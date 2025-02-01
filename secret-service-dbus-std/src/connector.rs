#[cfg(not(feature = "encryption"))]
use keyring_lib::Io;
use keyring_lib::State;
use keyring_secret_service_lib::crypto::Algorithm;
#[cfg(feature = "encryption")]
use keyring_secret_service_lib::{crypto, Io};
use tracing::instrument;

use crate::{service::SecretService, Result, Session};

#[derive(Debug)]
pub struct Connector {
    service: String,
    dbus: SecretService,
}

impl Connector {
    pub fn new(service: impl ToString, encryption: Algorithm) -> Result<Self> {
        Ok(Self {
            service: service.to_string(),
            dbus: SecretService::connect(encryption)?,
        })
    }

    pub fn session(&mut self) -> &mut Session {
        &mut self.dbus.session
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

    fn read(&self, state: &mut State) -> Result<()> {
        let (_, _, secret, _) = self
            .dbus
            .get_default_collection()?
            .get_item(&self.service, state.get_key())?
            .get_secret()?;

        let secret = String::from_utf8(secret).unwrap();
        state.set_secret(secret);
        Ok(())
    }

    fn write(&self, state: &mut State) -> Result<()> {
        use crate::Error;

        let secret = state.take_secret().ok_or(Error::WriteEmptySecretError)?;

        self.dbus.get_default_collection()?.create_item(
            &self.service,
            state.get_key(),
            secret,
            vec![],
        )?;

        Ok(())
    }

    fn delete(&self, state: &mut State) -> Result<()> {
        self.dbus
            .get_default_collection()?
            .get_item(&self.service, state.get_key())?
            .delete()?;

        Ok(())
    }
}

#[cfg(feature = "encryption")]
impl Connector {
    /// Executes the given `io` for the given `flow`.
    #[instrument(skip_all)]
    pub fn execute<F>(&self, flow: &mut F, io: Io) -> Result<()>
    where
        F: AsMut<State> + AsMut<crypto::State>,
    {
        let state = flow.as_mut();

        match io {
            Io::Keyring(keyring_lib::Io::Read) => self.read(state),
            Io::Keyring(keyring_lib::Io::Write) => self.write(state),
            Io::Keyring(keyring_lib::Io::Delete) => self.delete(state),
            Io::Crypto(crypto::Io::Encrypt) => self.encrypt(state),
            Io::Crypto(crypto::Io::Decrypt) => self.decrypt(state),
        }
    }
}
