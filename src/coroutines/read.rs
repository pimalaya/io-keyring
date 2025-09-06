//! I/O-free coroutine for reading a secret from a keyring entry.

use log::trace;
use secrecy::SecretString;
use thiserror::Error;

use crate::{entry::KeyringEntry, io::KeyringIo};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ReadSecretError {
    /// The coroutine received an invalid argument.
    ///
    /// Occurs when the coroutine receives an I/O response from
    /// another coroutine, which should not happen if the runtime maps
    /// correctly the arguments.
    #[error("Invalid argument: expected {0}, got {1:?}")]
    InvalidArgument(&'static str, KeyringIo),

    /// The entry was not ready.
    #[error("Entry not ready")]
    NotReady,
}

/// Output emitted after a coroutine finishes its progression.
#[derive(Clone, Debug)]
pub enum ReadSecretResult {
    /// The coroutine has successfully terminated its progression.
    Ok(SecretString),

    /// A keyring I/O needs to be performed to make the coroutine progress.
    Io(KeyringIo),

    /// An error occurred during the coroutine progression.
    Err(ReadSecretError),
}

/// I/O-free coroutine for reading a secret from a keyring entry.
#[derive(Clone, Debug)]
pub struct ReadSecret {
    entry: Option<KeyringEntry>,
}

impl ReadSecret {
    /// Creates a new coroutine for the given entry.
    pub fn new(entry: KeyringEntry) -> Self {
        Self { entry: Some(entry) }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<KeyringIo>) -> ReadSecretResult {
        let Some(arg) = arg else {
            let Some(entry) = self.entry.take() else {
                return ReadSecretResult::Err(ReadSecretError::NotReady);
            };

            trace!("need I/O to read secret from keyring entry");
            return ReadSecretResult::Io(KeyringIo::Read(Err(entry)));
        };

        let KeyringIo::Read(io) = arg else {
            return ReadSecretResult::Err(ReadSecretError::InvalidArgument("read output", arg));
        };

        let secret = match io {
            Ok(secret) => secret,
            Err(entry) => return ReadSecretResult::Io(KeyringIo::Read(Err(entry))),
        };

        trace!("resume after reading keyring entry");
        ReadSecretResult::Ok(secret)
    }
}
