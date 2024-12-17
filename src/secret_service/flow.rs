use secrecy::SecretSlice;

use crate::{
    secret_service::crypto::{self, Algorithm},
    Flow, PutSecret, TakeSecret,
};

use super::Io;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadEntryState {
    Read,
    Decrypt,
}

#[derive(Clone, Debug)]
pub struct ReadEntryFlow {
    key: String,
    encryption: Algorithm,
    state: Option<ReadEntryState>,
    secret: Option<SecretSlice<u8>>,
    salt: Option<Vec<u8>>,
}

impl ReadEntryFlow {
    pub fn new(key: impl ToString, encryption: Algorithm) -> Self {
        Self {
            key: key.to_string(),
            encryption,
            state: Some(ReadEntryState::Read),
            secret: None,
            salt: None,
        }
    }
}

impl Iterator for ReadEntryFlow {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state.take()? {
            ReadEntryState::Read => {
                if let Algorithm::Dh = self.encryption {
                    self.state.replace(ReadEntryState::Decrypt);
                }
                Some(Io::Entry(crate::Io::Read))
            }
            ReadEntryState::Decrypt => Some(Io::Crypto(crypto::Io::Decrypt)),
        }
    }
}

impl Flow for ReadEntryFlow {
    fn key(&self) -> &str {
        self.key.as_str()
    }
}

impl TakeSecret for ReadEntryFlow {
    fn take_secret(&mut self) -> Option<SecretSlice<u8>> {
        self.secret.take()
    }
}

impl PutSecret for ReadEntryFlow {
    fn put_secret(&mut self, secret: SecretSlice<u8>) {
        self.secret.replace(secret);
    }
}

impl crypto::TakeSalt for ReadEntryFlow {
    fn take_salt(&mut self) -> Option<Vec<u8>> {
        self.salt.take()
    }
}

impl crypto::PutSalt for ReadEntryFlow {
    fn put_salt(&mut self, salt: Vec<u8>) {
        self.salt.replace(salt);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteEntryState {
    Encrypt,
    Write,
}

#[derive(Clone, Debug)]
pub struct WriteEntryFlow {
    key: String,
    state: Option<WriteEntryState>,
    secret: Option<SecretSlice<u8>>,
    salt: Option<Vec<u8>>,
}

impl WriteEntryFlow {
    pub fn new(
        key: impl ToString,
        secret: impl Into<SecretSlice<u8>>,
        encryption: Algorithm,
    ) -> Self {
        Self {
            key: key.to_string(),
            state: Some(match encryption {
                Algorithm::Plain => WriteEntryState::Write,
                Algorithm::Dh => WriteEntryState::Encrypt,
            }),
            secret: Some(secret.into()),
            salt: None,
        }
    }
}

impl Iterator for WriteEntryFlow {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state.take()? {
            WriteEntryState::Encrypt => {
                self.state.replace(WriteEntryState::Write);
                Some(Io::Crypto(crypto::Io::Encrypt))
            }
            WriteEntryState::Write => Some(Io::Entry(crate::Io::Write)),
        }
    }
}

impl Flow for WriteEntryFlow {
    fn key(&self) -> &str {
        self.key.as_str()
    }
}

impl TakeSecret for WriteEntryFlow {
    fn take_secret(&mut self) -> Option<SecretSlice<u8>> {
        self.secret.take()
    }
}

impl PutSecret for WriteEntryFlow {
    fn put_secret(&mut self, secret: SecretSlice<u8>) {
        self.secret.replace(secret);
    }
}

impl crypto::TakeSalt for WriteEntryFlow {
    fn take_salt(&mut self) -> Option<Vec<u8>> {
        self.salt.take()
    }
}

impl crypto::PutSalt for WriteEntryFlow {
    fn put_salt(&mut self, salt: Vec<u8>) {
        self.salt.replace(salt);
    }
}

#[derive(Clone, Debug)]
pub struct DeleteEntryFlow {
    key: String,
    deleted: bool,
}

impl DeleteEntryFlow {
    pub fn new(key: impl ToString) -> Self {
        Self {
            key: key.to_string(),
            deleted: false,
        }
    }
}

impl Iterator for DeleteEntryFlow {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        if self.deleted {
            None
        } else {
            self.deleted = true;
            Some(Io::Entry(crate::Io::Delete))
        }
    }
}

impl Flow for DeleteEntryFlow {
    fn key(&self) -> &str {
        self.key.as_str()
    }
}
