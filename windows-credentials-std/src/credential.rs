//! # Windows Credentials
//!
//! Module dedicated to the Windows Credentials.
//!
//! This is where you have most of the calls to the Windows
//! API. [`Credential`] is a lighter version of the one from
//! [hwchen/keyring-rs]: it only manages String secrets. If you need
//! to manage binary secrets or attributes, please consider using
//! keyring-rs instead.
//!
//! [hwchen/keyring-rs]: https://github.com/hwchen/keyring-rs/blob/master/src/windows.rs

use std::{iter::once, mem::MaybeUninit, ptr, slice, str};

use byteorder::{ByteOrder, LittleEndian};
use secrecy::{ExposeSecret, SecretString};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, ERROR_BAD_USERNAME, ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER,
        ERROR_NOT_FOUND, ERROR_NO_SUCH_LOGON_SESSION, FILETIME,
    },
    Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CREDENTIAL_ATTRIBUTEW,
        CRED_FLAGS, CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_MAX_GENERIC_TARGET_NAME_LENGTH,
        CRED_MAX_STRING_LENGTH, CRED_MAX_USERNAME_LENGTH, CRED_PERSIST_ENTERPRISE,
        CRED_TYPE_GENERIC,
    },
};

use crate::{Error, Result};

// Windows API type mappings:
//
// DWORD is u32
// LPCWSTR is *const u16
// BOOL is i32 (false = 0, true = 1)
// PCREDENTIALW = *mut CREDENTIALW

/// The representation of a Windows Generic credential.
///
/// See the module header for the meanings of these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub username: String,
    pub target_name: String,
    pub target_alias: String,
    pub comment: String,
}

impl Credential {
    /// Creates and validates a new credential from the given service
    /// name and username.
    pub fn try_new(service: impl ToString, username: impl ToString) -> Result<Credential> {
        let username = username.to_string();

        if username.len() > CRED_MAX_USERNAME_LENGTH as usize {
            return Err(Error::UsernameTooLongError);
        }

        let service = service.to_string();
        let target_name = format!("{service}.{username}");

        if target_name.is_empty() {
            return Err(Error::TargetNameEmptyError);
        }

        if target_name.len() > CRED_MAX_GENERIC_TARGET_NAME_LENGTH as usize {
            return Err(Error::TargetNameTooLongError);
        }

        let comment = format!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

        if comment.len() > CRED_MAX_STRING_LENGTH as usize {
            return Err(Error::CommentTooLongError);
        }

        Ok(Self {
            username,
            target_name,
            target_alias: String::new(),
            comment,
        })
    }

    pub fn get_secret_string(&self) -> Result<SecretString> {
        let mut p_credential = MaybeUninit::uninit();
        // at this point, p_credential is just a pointer to nowhere.
        // The allocation happens in the `CredReadW` call below.
        let result = {
            let cred_type = CRED_TYPE_GENERIC;
            let target_name = to_wstr(&self.target_name);
            unsafe {
                CredReadW(
                    target_name.as_ptr(),
                    cred_type,
                    0,
                    p_credential.as_mut_ptr(),
                )
            }
        };
        match result {
            0 => {
                // `CredReadW` failed, so no allocation has been done, so no free needs to be done
                Err(match unsafe { GetLastError() } {
                    ERROR_NOT_FOUND => Error::WriteCredentialNotFoundError,
                    ERROR_NO_SUCH_LOGON_SESSION => Error::WriteCredentialSessionError,
                    ERROR_BAD_USERNAME => Error::WriteCredentialBadUsernameError,
                    ERROR_INVALID_FLAGS => Error::WriteCredentialInvalidFlagsError,
                    ERROR_INVALID_PARAMETER => Error::WriteCredentialInvalidParameterError,
                    code => Error::WriteCredentialError(code),
                })
            }
            _ => {
                // `CredReadW` succeeded, so p_credential points at an allocated credential.
                // To do anything with it, we need to cast it to the right type.  That takes two steps:
                // first we remove the "uninitialized" guard around it, then we reinterpret it as a
                // pointer to the right structure type.
                let p_credential = unsafe { p_credential.assume_init() };
                let w_credential: CREDENTIALW = unsafe { *p_credential };
                // Now we can apply the passed extractor function to the credential.
                let result = extract_secret_string(&w_credential);
                // Finally, we free the allocated credential.
                unsafe { CredFree(p_credential as *mut _) };
                result
            }
        }
    }

    pub fn set_secret_string(&self, secret: impl Into<SecretString>) -> Result<()> {
        let secret = secret.into();

        let secret_utf16_len = secret.expose_secret().encode_utf16().count() * 2;
        if secret_utf16_len > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
            return Err(Error::SecretTooLongError);
        }

        // Password strings are converted to UTF-16, because that's the native
        // charset for Windows strings.  This allows interoperability with native
        // Windows credential APIs.  But the storage for the credential is actually
        // a little-endian blob, because Windows credentials can contain anything.
        let blob_u16 = to_wstr_no_null(secret.expose_secret());
        let mut blob = vec![0; blob_u16.len() * 2];
        LittleEndian::write_u16_into(&blob_u16, &mut blob);

        let mut username = to_wstr(&self.username);
        let mut target_name = to_wstr(&self.target_name);
        let mut target_alias = to_wstr(&self.target_alias);
        let mut comment = to_wstr(&self.comment);
        let blob_len = blob.len() as u32;
        let flags = CRED_FLAGS::default();
        let cred_type = CRED_TYPE_GENERIC;
        let persist = CRED_PERSIST_ENTERPRISE;

        // Ignored by CredWriteW
        let last_written = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };

        let attribute_count = 0;
        let attributes: *mut CREDENTIAL_ATTRIBUTEW = ptr::null_mut();
        let mut credential = CREDENTIALW {
            Flags: flags,
            Type: cred_type,
            TargetName: target_name.as_mut_ptr(),
            Comment: comment.as_mut_ptr(),
            LastWritten: last_written,
            CredentialBlobSize: blob_len,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: persist,
            AttributeCount: attribute_count,
            Attributes: attributes,
            TargetAlias: target_alias.as_mut_ptr(),
            UserName: username.as_mut_ptr(),
        };

        // raw pointer to credential, is coerced from &mut
        let p_credential: *const CREDENTIALW = &mut credential;

        // Call windows API
        let code = unsafe { CredWriteW(p_credential, 0) };
        if code != 0 {
            return Ok(());
        }

        Err(match unsafe { GetLastError() } {
            ERROR_NOT_FOUND => Error::WriteCredentialNotFoundError,
            ERROR_NO_SUCH_LOGON_SESSION => Error::WriteCredentialSessionError,
            ERROR_BAD_USERNAME => Error::WriteCredentialBadUsernameError,
            ERROR_INVALID_FLAGS => Error::WriteCredentialInvalidFlagsError,
            ERROR_INVALID_PARAMETER => Error::WriteCredentialInvalidParameterError,
            code => Error::WriteCredentialError(code),
        })
    }

    /// Delete the underlying generic credential for this entry, if
    /// any.
    ///
    /// Returns a [NoEntry](ErrorCode::NoEntry) error if there is no
    /// credential in the store.
    pub fn delete_entry(&self) -> Result<()> {
        let target_name = to_wstr(&self.target_name);
        let cred_type = CRED_TYPE_GENERIC;
        let code = unsafe { CredDeleteW(target_name.as_ptr(), cred_type, 0) };

        if code != 0 {
            return Ok(());
        }

        Err(match unsafe { GetLastError() } {
            ERROR_NOT_FOUND => Error::DeleteEntryNotFoundError,
            ERROR_NO_SUCH_LOGON_SESSION => Error::DeleteEntrySessionError,
            ERROR_BAD_USERNAME => Error::DeleteEntryBadUsernameError,
            code => Error::DeleteEntryError(code),
        })
    }
}

fn extract_secret_string(credential: &CREDENTIALW) -> Result<SecretString> {
    let blob_pointer: *const u8 = credential.CredentialBlob;
    let blob_len = credential.CredentialBlobSize as usize;

    if blob_len == 0 {
        return Ok(SecretString::default());
    }

    let blob = unsafe { slice::from_raw_parts(blob_pointer, blob_len) };

    // 3rd parties may write credential data with an odd number of bytes,
    // so we make sure that we don't try to decode those as utf16
    if blob.len() % 2 != 0 {
        return Err(Error::ParseUtf16OddLengthError);
    }
    // Now we know this _can_ be a UTF-16 string, so convert it to
    // as UTF-16 vector and then try to decode it.
    let mut blob_u16 = vec![0; blob.len() / 2];
    LittleEndian::read_u16_into(&blob, &mut blob_u16);
    let secret = String::from_utf16(&blob_u16).map_err(Error::ParseUtf16EncodingError)?;
    Ok(secret.into())
}

fn to_wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(once(0)).collect()
}

fn to_wstr_no_null(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
