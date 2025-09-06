//! Keyring I/O requests and responses.

use secrecy::SecretString;

use crate::entry::KeyringEntry;

/// The keyring I/O request enum, emitted by [coroutines] and
/// processed by [runtimes].
///
/// Represents all the possible I/O requests that a stream coroutine
/// can emit. Runtimes should be able to handle all variants.
///
/// [coroutines]: crate::coroutines
/// [runtimes]: crate::runtimes
#[derive(Clone, Debug)]
pub enum KeyringIo {
    /// I/O for reading a secret from a keyring entry.
    ///
    /// Input: keyring entry
    ///
    /// Output: secret string
    Read(Result<SecretString, KeyringEntry>),

    /// I/O for saving a keyring entry secret.
    ///
    /// Input: keyring entry with secret string
    ///
    /// Output: none
    Write(Result<(), (KeyringEntry, SecretString)>),

    /// I/O for deleting a keyring entry.
    ///
    /// Input: keyring entry
    ///
    /// Output: none
    Delete(Result<(), KeyringEntry>),
}
