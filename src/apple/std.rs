use secrecy::ExposeSecret;
use security_framework::{
    base::Error as SecurityFrameworkError,
    passwords::{delete_generic_password, get_generic_password, set_generic_password},
};
use thiserror::Error;

use crate::{Flow, PutSecret, TakeSecret};

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

    pub fn read(&self, flow: &mut impl PutSecret) -> Result<()> {
        let secret =
            get_generic_password(&self.service, flow.key()).map_err(Error::ReadSecretError)?;
        flow.put_secret(secret.into());
        Ok(())
    }

    pub fn write(&self, flow: &mut impl TakeSecret) -> Result<()> {
        let secret = flow.take_secret().ok_or(Error::WriteUndefinedSecretError)?;
        let secret = secret.expose_secret();
        set_generic_password(&self.service, flow.key(), secret).map_err(Error::WriteSecretError)?;
        Ok(())
    }

    pub fn delete(&self, flow: &mut impl Flow) -> Result<()> {
        delete_generic_password(&self.service, flow.key()).map_err(Error::DeleteSecretError)?;
        Ok(())
    }
}
