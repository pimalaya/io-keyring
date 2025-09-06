//! I/O-free coroutine for deleting a keyring entry.

use log::trace;
use thiserror::Error;

use crate::{entry::KeyringEntry, io::KeyringIo};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum DeleteSecretError {
    /// The coroutine received an invalid argument.
    #[error("Invalid argument: expected {0}, got {1:?}")]
    InvalidArgument(&'static str, KeyringIo),

    /// The entry was not ready.
    #[error("Entry not ready")]
    NotReady,
}

/// Output emitted after a coroutine finishes its progression.
#[derive(Clone, Debug)]
pub enum DeleteSecretResult {
    /// The coroutine has successfully terminated its progression.
    Ok(()),

    /// A keyring I/O needs to be performed to make the coroutine progress.
    Io(KeyringIo),

    /// An error occurred during the coroutine progression.
    Err(DeleteSecretError),
}

/// I/O-free coroutine for deleting a keyring entry.
#[derive(Clone, Debug)]
pub struct DeleteSecret {
    entry: Option<KeyringEntry>,
}

impl DeleteSecret {
    /// Creates a new coroutine for the given entry.
    pub fn new(entry: KeyringEntry) -> Self {
        Self { entry: Some(entry) }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<KeyringIo>) -> DeleteSecretResult {
        let Some(arg) = arg else {
            let Some(entry) = self.entry.take() else {
                return DeleteSecretResult::Err(DeleteSecretError::NotReady);
            };

            trace!("break: need I/O to delete secret from keyring entry");
            return DeleteSecretResult::Io(KeyringIo::Delete(Err(entry)));
        };

        let KeyringIo::Delete(io) = arg else {
            let err = DeleteSecretError::InvalidArgument("delete output", arg);
            return DeleteSecretResult::Err(err);
        };

        if let Err(entry) = io {
            return DeleteSecretResult::Io(KeyringIo::Delete(Err(entry)));
        }

        trace!("resume after deleting secret from keyring entry");
        DeleteSecretResult::Ok(())
    }
}
