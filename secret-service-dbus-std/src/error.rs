//! # Error
//!
//! Module dedicated to D-Bus Secret Service errors.
//!
//! It is mostly composed of an [`Error`] enum and a [`Result`] type
//! alias.

use thiserror::Error;

/// The global [`Error`] enum of this library.
#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot create Secret Service connection using D-Bus")]
    CreateSessionError(#[source] dbus::Error),
    #[error("cannot open Secret Service session using D-Bus")]
    OpenSessionError(#[source] dbus::Error),
    #[error("cannot parse Secret Service session output using D-Bus")]
    ParseSessionOutputError,

    #[error("cannot get default secret service collection")]
    GetDefaultCollectionError(#[source] dbus::Error),
    #[error("cannot get session secret service collection")]
    GetSessionCollectionError(#[source] dbus::Error),
    #[error("cannot get secret service collections")]
    GetCollectionsError(#[source] dbus::Error),
    #[error("cannot create default secret service collection")]
    CreateDefaultCollectionError(#[source] dbus::Error),
    #[error("cannot create secret service collection item")]
    CreateItemError(#[source] dbus::Error),
    #[error("cannot search items from Secret Service using D-Bus")]
    SearchItemsError(#[source] dbus::Error),
    #[error("cannot get item matching {0}:{1} in Secret Service using D-Bus")]
    GetItemNotFoundError(String, String),
    #[error("cannot get secret from Secret Service using D-Bus")]
    GetSecretError(#[source] dbus::Error),
    #[error("cannot delete item from Secret Service using D-Bus")]
    DeleteItemError(#[source] dbus::Error),
    #[error("cannot cast server public key to bytes")]
    CastServerPublicKeyToBytesError,
    #[error("cannot write empty secret into Secret Service entry using D-Bus")]
    WriteEmptySecretError,

    #[error("cannot prompt using D-Bus")]
    PromptError(#[source] dbus::Error),
    #[error("cannot prompt using D-Bus: match signal error")]
    PromptMatchSignalError(#[source] dbus::Error),
    #[error("cannot prompt using D-Bus: match stop error")]
    PromptMatchStopError(#[source] dbus::Error),
    #[error("cannot prompt using D-Bus: request timed out")]
    PromptTimeoutError,
    #[error("cannot prompt using D-Bus: prompt dismissed")]
    PromptDismissedError,
    #[error("cannot prompt using D-Bus: invalid prompt signal path")]
    ParsePromptPathError,
    #[error("cannot prompt using D-Bus: invalid prompt signal")]
    ParsePromptSignalError,
}

/// The global [`Result`] type of this library.
pub type Result<T> = std::result::Result<T, Error>;
