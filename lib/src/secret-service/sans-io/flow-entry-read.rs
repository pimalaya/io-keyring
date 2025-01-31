use secrecy::SecretSlice;

#[cfg(feature = "secret-service-crypto")]
use crate::secret_service::crypto::sans_io::{Io as CryptoIo, PutSalt, TakeSalt};
use crate::{
    sans_io::{Flow, GetKey, Io as EntryIo, PutSecret, TakeSecret},
    secret_service::crypto::sans_io::Algorithm,
};

use super::Io;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadEntryState {
    Read,
    #[cfg(feature = "secret-service-crypto")]
    Decrypt,
}

#[derive(Clone, Debug)]
pub struct ReadEntryFlow {
    inner: crate::sans_io::ReadEntryFlow,
    encryption: Algorithm,
    state: Option<ReadEntryState>,
    #[cfg(feature = "secret-service-crypto")]
    salt: Option<Vec<u8>>,
}

impl ReadEntryFlow {
    pub fn new(key: impl ToString, encryption: Algorithm) -> Self {
        Self {
            inner: crate::sans_io::ReadEntryFlow::new(key.to_string()),
            encryption,
            state: Some(ReadEntryState::Read),
            #[cfg(feature = "secret-service-crypto")]
            salt: None,
        }
    }
}

impl Iterator for ReadEntryFlow {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state.take()? {
            ReadEntryState::Read => {
                match self.encryption {
                    Algorithm::Plain => (),
                    #[cfg(feature = "secret-service-crypto")]
                    Algorithm::Dh(_) => {
                        self.state.replace(ReadEntryState::Decrypt);
                    }
                }
                Some(Io::Entry(EntryIo::Read))
            }
            #[cfg(feature = "secret-service-crypto")]
            ReadEntryState::Decrypt => Some(Io::Crypto(CryptoIo::Decrypt)),
        }
    }
}

impl Flow for ReadEntryFlow {}

impl GetKey for ReadEntryFlow {
    fn get_key(&self) -> &str {
        self.inner.get_key()
    }
}

impl TakeSecret for ReadEntryFlow {
    fn take_secret(&mut self) -> Option<SecretSlice<u8>> {
        self.inner.take_secret()
    }
}

impl PutSecret for ReadEntryFlow {
    fn put_secret(&mut self, secret: SecretSlice<u8>) {
        self.inner.put_secret(secret)
    }
}

#[cfg(feature = "secret-service-crypto")]
impl TakeSalt for ReadEntryFlow {
    fn take_salt(&mut self) -> Option<Vec<u8>> {
        self.salt.take()
    }
}

#[cfg(feature = "secret-service-crypto")]
impl PutSalt for ReadEntryFlow {
    fn put_salt(&mut self, salt: Vec<u8>) {
        self.salt.replace(salt);
    }
}
