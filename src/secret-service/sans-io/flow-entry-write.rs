use secrecy::SecretSlice;

#[cfg(feature = "secret-service-crypto")]
use crate::secret_service::crypto::sans_io::{Io as CryptoIo, PutSalt, TakeSalt};
use crate::{
    sans_io::{Flow, GetKey, Io as EntryIo, PutSecret, TakeSecret},
    secret_service::crypto::sans_io::Algorithm,
};

use super::Io;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteEntryState {
    Write,
    #[cfg(feature = "secret-service-crypto")]
    Encrypt,
}

#[derive(Clone, Debug)]
pub struct WriteEntryFlow {
    inner: crate::sans_io::WriteEntryFlow,
    state: Option<WriteEntryState>,
    #[cfg(feature = "secret-service-crypto")]
    salt: Option<Vec<u8>>,
}

impl WriteEntryFlow {
    pub fn new(
        key: impl ToString,
        secret: impl Into<SecretSlice<u8>>,
        encryption: Algorithm,
    ) -> Self {
        let state = match encryption {
            Algorithm::Plain => WriteEntryState::Write,
            #[cfg(feature = "secret-service-crypto")]
            Algorithm::Dh(_) => WriteEntryState::Encrypt,
        };

        Self {
            inner: crate::sans_io::WriteEntryFlow::new(key.to_string(), secret),
            state: Some(state),
            #[cfg(feature = "secret-service-crypto")]
            salt: None,
        }
    }
}

impl Iterator for WriteEntryFlow {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state.take()? {
            #[cfg(feature = "secret-service-crypto")]
            WriteEntryState::Encrypt => {
                self.state.replace(WriteEntryState::Write);
                Some(Io::Crypto(CryptoIo::Encrypt))
            }
            WriteEntryState::Write => Some(Io::Entry(EntryIo::Write)),
        }
    }
}

impl Flow for WriteEntryFlow {}

impl GetKey for WriteEntryFlow {
    fn get_key(&self) -> &str {
        self.inner.get_key()
    }
}

impl TakeSecret for WriteEntryFlow {
    fn take_secret(&mut self) -> Option<SecretSlice<u8>> {
        self.inner.take_secret()
    }
}

impl PutSecret for WriteEntryFlow {
    fn put_secret(&mut self, secret: SecretSlice<u8>) {
        self.inner.put_secret(secret);
    }
}

#[cfg(feature = "secret-service-crypto")]
impl TakeSalt for WriteEntryFlow {
    fn take_salt(&mut self) -> Option<Vec<u8>> {
        self.salt.take()
    }
}

#[cfg(feature = "secret-service-crypto")]
impl PutSalt for WriteEntryFlow {
    fn put_salt(&mut self, salt: Vec<u8>) {
        self.salt.replace(salt);
    }
}
