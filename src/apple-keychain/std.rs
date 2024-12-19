use secrecy::ExposeSecret;
use security_framework::{
    base::Error as SecurityFrameworkError,
    passwords::{delete_generic_password, get_generic_password, set_generic_password},
};
use thiserror::Error;

use crate::sans_io::{GetKey, PutSecret, TakeSecret};

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot read secret from OSX keychain")]
    ReadSecretError(#[source] SecurityFrameworkError),
    #[error("cannot write undefined secret to OSX keychain")]
    WriteUndefinedSecretError,
    #[error("cannot write secret to OSX keychain")]
    WriteSecretError(#[source] SecurityFrameworkError),
    #[error("cannot delete secret from OSX keychain")]
    DeleteSecretError(#[source] SecurityFrameworkError),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub struct IoConnector {
    service: String,
}

impl IoConnector {
    pub fn new(service: impl ToString) -> Self {
        Self {
            service: service.to_string(),
        }
    }

    pub fn read<F: GetKey + PutSecret>(&self, flow: &mut F) -> Result<()> {
        let secret =
            get_generic_password(&self.service, flow.get_key()).map_err(Error::ReadSecretError)?;
        flow.put_secret(secret.into());
        Ok(())
    }

    pub fn write<F: GetKey + TakeSecret>(&self, flow: &mut F) -> Result<()> {
        let secret = flow.take_secret().ok_or(Error::WriteUndefinedSecretError)?;
        let secret = secret.expose_secret();
        set_generic_password(&self.service, flow.get_key(), secret)
            .map_err(Error::WriteSecretError)?;
        Ok(())
    }

    pub fn delete<F: GetKey>(&self, flow: &mut F) -> Result<()> {
        delete_generic_password(&self.service, flow.get_key()).map_err(Error::DeleteSecretError)?;
        Ok(())
    }
}
