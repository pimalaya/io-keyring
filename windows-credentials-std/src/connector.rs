//! # I/O Connector
//!
//! Module dedicated to the Windows Credentials I/O connector.

use keyring_lib::{Io, State};
use secrecy::ExposeSecret;
use tracing::instrument;

use crate::{credential::Credential, Error, Result};

/// The standard, blocking Windows Credentials I/O connector.
///
/// This connector makes use of the blocking Windows API to read,
/// write and delete secrets from the Windows Credentials.
#[derive(Clone, Debug)]
pub struct Connector {
    service: String,
}

impl Connector {
    /// Creates a new connector from the given service name.
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
        let key = state.get_key();
        let cred = Credential::try_new(&self.service, key)?;
        let secret = cred.get_secret_string()?;
        state.set_secret(secret);
        Ok(())
    }

    #[instrument(skip_all)]
    pub fn write(&self, state: &mut State) -> Result<()> {
        let secret = state.take_secret();
        let secret = secret.ok_or(Error::WriteUndefinedSecretError)?;
        let secret = secret.expose_secret();
        let key = state.get_key();
        let cred = Credential::try_new(&self.service, key)?;
        cred.set_secret_string(secret)
    }

    #[instrument(skip_all)]
    pub fn delete(&self, state: &mut State) -> Result<()> {
        let key = state.get_key();
        let cred = Credential::try_new(&self.service, key)?;
        cred.delete_entry()?;
        state.set_delete_done();
        Ok(())
    }
}
