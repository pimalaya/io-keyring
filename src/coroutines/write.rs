//! I/O-free coroutine for saving a keyring entry secret.

use log::trace;
use secrecy::SecretString;
use thiserror::Error;

use crate::{entry::KeyringEntry, io::KeyringIo};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum WriteSecretError {
    /// The coroutine received an invalid argument.
    #[error("Invalid argument: expected {0}, got {1:?}")]
    InvalidArgument(&'static str, KeyringIo),

    /// The entry and secret were not ready.
    #[error("Entry and secret not ready")]
    NotReady,
}

/// Output emitted after a coroutine finishes its progression.
#[derive(Clone, Debug)]
pub enum WriteSecretResult {
    /// The coroutine has successfully terminated its progression.
    Ok(()),

    /// A keyring I/O needs to be performed to make the coroutine progress.
    Io(KeyringIo),

    /// An error occurred during the coroutine progression.
    Err(WriteSecretError),
}

/// I/O-free coroutine for saving a keyring entry secret.
#[derive(Clone, Debug)]
pub struct WriteSecret {
    secret: Option<(KeyringEntry, SecretString)>,
}

impl WriteSecret {
    /// Creates a new coroutine for the given entry and secret.
    pub fn new(entry: KeyringEntry, secret: impl Into<SecretString>) -> Self {
        let secret = Some((entry, secret.into()));
        Self { secret }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<KeyringIo>) -> WriteSecretResult {
        let Some(arg) = arg else {
            let Some(secret) = self.secret.take() else {
                return WriteSecretResult::Err(WriteSecretError::NotReady);
            };

            trace!("need I/O to write secret into keyring entry");
            return WriteSecretResult::Io(KeyringIo::Write(Err(secret)));
        };

        let KeyringIo::Write(io) = arg else {
            let err = WriteSecretError::InvalidArgument("write output", arg);
            return WriteSecretResult::Err(err);
        };

        if let Err((entry, secret)) = io {
            return WriteSecretResult::Io(KeyringIo::Write(Err((entry, secret))));
        }

        trace!("resume after writing secret into keyring entry");
        WriteSecretResult::Ok(())
    }
}
