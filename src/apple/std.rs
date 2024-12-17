use secrecy::ExposeSecret;
use security_framework::{
    base::Error as SecurityFrameworkError,
    passwords::{get_generic_password, set_generic_password},
};
use thiserror::Error;

use super::Flow;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot read secret from OSX keychain")]
    ReadSecretError(#[source] SecurityFrameworkError),
    #[error("cannot write undefined secret to OSX keychain")]
    WriteUndefinedSecretError,
    #[error("cannot write secret to OSX keychain")]
    WriteSecretError(#[source] SecurityFrameworkError),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Default)]
pub struct IoConnector;

impl IoConnector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn read(&self, flow: &mut impl Flow) -> Result<()> {
        let service = flow.get_service();
        let account = flow.get_account();
        let secret = get_generic_password(service, account).map_err(Error::ReadSecretError)?;

        flow.put_secret(secret.into());
        Ok(())
    }

    pub fn write(&self, flow: &mut impl Flow) -> Result<()> {
        let secret = flow.take_secret().ok_or(Error::WriteUndefinedSecretError)?;
        let service = flow.get_service();
        let account = flow.get_account();
        let secret = secret.expose_secret();

        set_generic_password(service, account, secret).map_err(Error::WriteSecretError)?;
        Ok(())
    }
}
