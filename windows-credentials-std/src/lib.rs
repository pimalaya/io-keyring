use std::{collections::HashMap, iter::once, mem::MaybeUninit, str, string::FromUtf16Error};

use byteorder::{ByteOrder, LittleEndian};
use keyring_lib::{Io, State};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use thiserror::Error;
use tracing::instrument;
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

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot write undefined secret to Windows Credentials")]
    WriteUndefinedSecretError,
    #[error("secret length cannot exceed {CRED_MAX_CREDENTIAL_BLOB_SIZE}")]
    SecretTooLongError,
    #[error("secret length cannot exceed {CRED_MAX_USERNAME_LENGTH}")]
    UsernameTooLongError,
    #[error("target name cannot be empty")]
    TargetNameEmptyError,
    #[error("target name cannot exceed {CRED_MAX_GENERIC_TARGET_NAME_LENGTH}")]
    TargetNameTooLongError,
    #[error("comment cannot exceed {CRED_MAX_STRING_LENGTH}")]
    CommentTooLongError,

    #[error("cannot parse secret from Windows Credentials Manager: UTF-16 length not even")]
    ParseUtf16OddLengthError,
    #[error("cannot parse secret from Windows Credentials Manager")]
    ParseUtf16EncodingError(#[source] FromUtf16Error),
    #[error("cannot delete entry from Windows Credentials Manager: entry not found")]
    DeleteEntryNotFoundError,
    #[error("cannot delete entry from Windows Credentials Manager: session issue")]
    DeleteEntrySessionError,
    #[error("cannot delete entry from Windows Credentials Manager: bad username")]
    DeleteEntryBadUsernameError,
    #[error("cannot delete entry from Windows Credentials Manager: generic code {0}")]
    DeleteEntryError(u32),
    #[error("cannot write credential into Windows Credentials Manager: credential not found")]
    WriteCredentialNotFoundError,
    #[error("cannot write credential into Windows Credentials Manager: session issue")]
    WriteCredentialSessionError,
    #[error("cannot write credential into Windows Credentials Manager: bad username")]
    WriteCredentialBadUsernameError,
    #[error("cannot write credential into Windows Credentials Manager: flags issue")]
    WriteCredentialInvalidFlagsError,
    #[error("cannot write credential into Windows Credentials Manager: parameter issue")]
    WriteCredentialInvalidParameterError,
    #[error("cannot write credential into Windows Credentials Manager: generic code {0}")]
    WriteCredentialError(u32),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub struct Connector {
    service: String,
}

impl Connector {
    #[instrument(skip_all)]
    pub fn new(service: impl ToString) -> Self {
        Self {
            service: service.to_string(),
        }
    }

    /// Executes the given `io` for the given `flow`.
    #[instrument(skip_all)]
    pub fn execute<F: AsMut<State>>(&self, flow: &mut F, io: Io) -> Result<()> {
        let state = flow.as_mut();

        match io {
            Io::Read => self.read(state),
            Io::Write => self.write(state),
            Io::Delete => self.delete(state),
        }
    }

    #[instrument(skip_all)]
    pub fn read(&self, state: &mut State) -> Result<()> {
        let key = state.get_key_ref();
        let secret = WinCredential::try_new(&self.service, key)?.get_secret_string()?;
        state.set_secret(secret);
        Ok(())
    }

    #[instrument(skip_all)]
    pub fn write(&self, state: &mut State) -> Result<()> {
        let secret = state.take_secret();
        let secret = secret.ok_or(Error::WriteUndefinedSecretError)?;
        let secret = secret.expose_secret();
        let key = state.get_key_ref();
        WinCredential::try_new(&self.service, key)?.set_secret_string(secret)?;
        Ok(())
    }

    #[instrument(skip_all)]
    pub fn delete(&self, state: &mut State) -> Result<()> {
        let key = state.get_key_ref();
        WinCredential::try_new(&self.service, key)?.delete_entry()?;
        Ok(())
    }
}

/// The representation of a Windows Generic credential.
///
/// See the module header for the meanings of these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinCredential {
    pub username: String,
    pub target_name: String,
    pub target_alias: String,
    pub comment: String,
}

// Windows API type mappings:
// DWORD is u32
// LPCWSTR is *const u16
// BOOL is i32 (false = 0, true = 1)
// PCREDENTIALW = *mut CREDENTIALW

impl WinCredential {
    pub fn try_new(service: impl ToString, username: impl ToString) -> Result<WinCredential> {
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
            target_alias: Default::default(),
            comment,
        })
    }

    pub fn get_secret_string(&self) -> Result<SecretString> {
        self.extract_from_platform(extract_secret_string)
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
        self.set_secret_bytes(blob)
    }

    pub fn get_secret_bytes(&self) -> Result<SecretSlice<u8>> {
        self.extract_from_platform(extract_secret_bytes)
    }

    pub fn set_secret_bytes(&self, secret: impl Into<SecretSlice<u8>>) -> Result<()> {
        let secret = secret.into();

        if secret.expose_secret().len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
            return Err(Error::SecretTooLongError);
        }

        self.save_credential(secret)
    }

    /// Get the attributes from the credential for this entry, if it exists.
    ///
    /// Returns a [NoEntry](ErrorCode::NoEntry) error if there is no
    /// credential in the store.
    pub fn get_attributes(&self) -> Result<HashMap<String, String>> {
        let cred = self.extract_from_platform(Self::extract_credential)?;
        let mut attributes: HashMap<String, String> = HashMap::new();
        attributes.insert("comment".to_string(), cred.comment.clone());
        attributes.insert("target_alias".to_string(), cred.target_alias.clone());
        attributes.insert("username".to_string(), cred.username.clone());
        Ok(attributes)
    }

    /// Update the attributes on the credential for this entry, if it exists.
    ///
    /// Returns a [NoEntry](ErrorCode::NoEntry) error if there is no
    /// credential in the store.
    pub fn update_attributes(&self, attributes: &HashMap<&str, &str>) -> Result<()> {
        let secret = self.extract_from_platform(extract_secret_bytes)?;
        let mut cred = self.extract_from_platform(Self::extract_credential)?;

        if let Some(comment) = attributes.get(&"comment") {
            cred.comment = comment.to_string();
        }

        if let Some(target_alias) = attributes.get(&"target_alias") {
            cred.target_alias = target_alias.to_string();
        }

        if let Some(username) = attributes.get(&"username") {
            cred.username = username.to_string();
        }

        cred.save_credential(secret)
    }

    /// Delete the underlying generic credential for this entry, if any.
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

    /// Write this credential into the underlying store as a Generic credential
    ///
    /// You must always have validated attributes before you call this!
    fn save_credential(&self, secret: impl Into<SecretSlice<u8>>) -> Result<()> {
        let secret = secret.into();
        let mut username = to_wstr(&self.username);
        let mut target_name = to_wstr(&self.target_name);
        let mut target_alias = to_wstr(&self.target_alias);
        let mut comment = to_wstr(&self.comment);
        let mut blob = secret.expose_secret().to_vec();
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
        let attributes: *mut CREDENTIAL_ATTRIBUTEW = std::ptr::null_mut();
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

    /// Construct a credential from this credential's underlying Generic credential.
    ///
    /// This can be useful for seeing modifications made by a third party.
    pub fn get_credential(&self) -> Result<Self> {
        self.extract_from_platform(Self::extract_credential)
    }

    fn extract_from_platform<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&CREDENTIALW) -> Result<T>,
    {
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
                let result = f(&w_credential);
                // Finally, we free the allocated credential.
                unsafe { CredFree(p_credential as *mut _) };
                result
            }
        }
    }

    fn extract_credential(w_credential: &CREDENTIALW) -> Result<Self> {
        Ok(Self {
            username: unsafe { from_wstr(w_credential.UserName) },
            target_name: unsafe { from_wstr(w_credential.TargetName) },
            target_alias: unsafe { from_wstr(w_credential.TargetAlias) },
            comment: unsafe { from_wstr(w_credential.Comment) },
        })
    }
}

fn extract_secret_string(credential: &CREDENTIALW) -> Result<SecretString> {
    let blob = extract_secret_bytes(credential)?;
    let blob = blob.expose_secret();
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

fn extract_secret_bytes(credential: &CREDENTIALW) -> Result<SecretSlice<u8>> {
    let blob_pointer: *const u8 = credential.CredentialBlob;
    let blob_len: usize = credential.CredentialBlobSize as usize;
    if blob_len == 0 {
        return Ok(SecretSlice::default());
    }
    let blob = unsafe { std::slice::from_raw_parts(blob_pointer, blob_len) };
    Ok(blob.to_vec().into())
}

fn to_wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(once(0)).collect()
}

fn to_wstr_no_null(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

unsafe fn from_wstr(ws: *const u16) -> String {
    // null pointer case, return empty string
    if ws.is_null() {
        return String::new();
    }
    // this code from https://stackoverflow.com/a/48587463/558006
    let len = (0..).take_while(|&i| *ws.offset(i) != 0).count();
    if len == 0 {
        return String::new();
    }
    let slice = std::slice::from_raw_parts(ws, len);
    String::from_utf16_lossy(slice)
}
