use std::string::FromUtf8Error;

use keyring_lib::{Io, State};
use secrecy::ExposeSecret;
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use thiserror::Error;
use tracing::instrument;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot read secret from Apple Keychain")]
    ReadSecretError(#[source] security_framework::base::Error),
    #[error("cannot read secret from Apple Keychain")]
    ConvertSecretAsUtf8Error(#[source] FromUtf8Error),
    #[error("cannot write undefined secret to Apple Keychain")]
    WriteUndefinedSecretError,
    #[error("cannot write secret to Apple Keychain")]
    WriteSecretError(#[source] security_framework::base::Error),
    #[error("cannot delete secret from Apple Keychain")]
    DeleteSecretError(#[source] security_framework::base::Error),
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
        let secret = get_generic_password(&self.service, key).map_err(Error::ReadSecretError)?;
        let secret = String::from_utf8(secret).map_err(Error::ConvertSecretAsUtf8Error)?;
        state.set_secret(secret);
        Ok(())
    }

    #[instrument(skip_all)]
    pub fn write(&self, state: &mut State) -> Result<()> {
        let secret = state.take_secret();
        let secret = secret.ok_or(Error::WriteUndefinedSecretError)?;
        let secret = secret.expose_secret().as_bytes();
        set_generic_password(&self.service, state.get_key_ref(), secret)
            .map_err(Error::WriteSecretError)
    }

    #[instrument(skip_all)]
    pub fn delete(&self, state: &mut State) -> Result<()> {
        let key = state.get_key_ref();
        delete_generic_password(&self.service, key).map_err(Error::DeleteSecretError)
    }
}
