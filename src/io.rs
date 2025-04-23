use std::fmt;

use secrecy::SecretString;

use crate::Entry;

/// The keyring I/O request enum, emitted by [coroutines] and
/// processed by [runtimes].
///
/// Represents all the possible I/O requests that a stream coroutine
/// can emit. Runtimes should be able to handle all variants.
///
/// [coroutines]: crate::coroutines
/// [runtimes]: crate::runtimes
#[derive(Clone, Debug)]
pub enum Io {
    /// Generic error related to coroutine progression.
    Error(String),

    /// I/O for reading a secret from a keyring entry.
    Read(Result<SecretString, Entry>),

    /// I/O for saving a keyring entry secret.
    Write(Result<(), (Entry, SecretString)>),

    /// I/O for deleting a keyring entry.
    Delete(Result<(), Entry>),
}

impl Io {
    pub fn err(msg: impl fmt::Display) -> Io {
        let msg = format!("Keyring error: {msg}");
        Io::Error(msg)
    }
}
