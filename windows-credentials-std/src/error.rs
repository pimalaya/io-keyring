//! # Error
//!
//! Module dedicated to Windows Credentials errors.
//!
//! It is mostly composed of an [`Error`] enum and a [`Result`] type
//! alias.

use std::string::FromUtf16Error;

use thiserror::Error;
use windows_sys::Win32::Security::Credentials::{
    CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_MAX_GENERIC_TARGET_NAME_LENGTH, CRED_MAX_STRING_LENGTH,
    CRED_MAX_USERNAME_LENGTH,
};

/// The global [`Error`] enum of this library.
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

/// The global [`Result`] type of this library.
pub type Result<T> = std::result::Result<T, Error>;
