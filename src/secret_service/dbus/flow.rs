use secrecy::SecretSlice;

use crate::secret_service::dbus::crypto;

use super::{crypto::Algorithm, Io};

pub trait Flow {
    fn take_secret(&mut self) -> Option<SecretSlice<u8>>;
    fn take_salt(&mut self) -> Option<Vec<u8>>;

    fn give_secret(&mut self, secret: SecretSlice<u8>);
    fn give_salt(&mut self, salt: Vec<u8>);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadEntryState {
    Read,
    Decrypt,
}

#[derive(Clone, Debug)]
pub struct ReadEntryFlow {
    encryption: Algorithm,
    state: Option<ReadEntryState>,
    pub secret: Option<SecretSlice<u8>>,
    pub salt: Option<Vec<u8>>,
}

impl ReadEntryFlow {
    pub fn new(encryption: Algorithm) -> Self {
        Self {
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
    fn take_secret(&mut self) -> Option<SecretSlice<u8>> {
        self.secret.take()
    }

    fn take_salt(&mut self) -> Option<Vec<u8>> {
        self.salt.take()
    }

    fn give_secret(&mut self, secret: SecretSlice<u8>) {
        self.secret.replace(secret);
    }

    fn give_salt(&mut self, salt: Vec<u8>) {
        self.salt.replace(salt);
    }
}

impl crypto::Flow for ReadEntryFlow {
    fn take_secret(&mut self) -> Option<SecretSlice<u8>> {
        self.secret.take()
    }

    fn take_salt(&mut self) -> Option<Vec<u8>> {
        self.salt.take()
    }

    fn give_secret(&mut self, secret: SecretSlice<u8>) {
        self.secret.replace(secret);
    }

    fn give_salt(&mut self, salt: Vec<u8>) {
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
    state: Option<WriteEntryState>,
    pub secret: Option<SecretSlice<u8>>,
    pub salt: Option<Vec<u8>>,
}

impl WriteEntryFlow {
    pub fn new(secret: impl Into<SecretSlice<u8>>, encryption: Algorithm) -> Self {
        Self {
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
    fn take_secret(&mut self) -> Option<SecretSlice<u8>> {
        self.secret.take()
    }

    fn take_salt(&mut self) -> Option<Vec<u8>> {
        self.salt.take()
    }

    fn give_secret(&mut self, secret: SecretSlice<u8>) {
        self.secret.replace(secret);
    }

    fn give_salt(&mut self, salt: Vec<u8>) {
        self.salt.replace(salt);
    }
}

impl crypto::Flow for WriteEntryFlow {
    fn take_secret(&mut self) -> Option<SecretSlice<u8>> {
        self.secret.take()
    }

    fn take_salt(&mut self) -> Option<Vec<u8>> {
        self.salt.take()
    }

    fn give_secret(&mut self, secret: SecretSlice<u8>) {
        self.secret.replace(secret);
    }

    fn give_salt(&mut self, salt: Vec<u8>) {
        self.salt.replace(salt);
    }
}

// #[derive(Clone, Debug)]
// pub struct DeleteEntryFlow {
//     delete: Option<EntryIo>,
// }

// impl Default for DeleteEntryFlow {
//     fn default() -> Self {
//         Self {
//             delete: Some(EntryIo::Delete),
//         }
//     }
// }

// impl Iterator for DeleteEntryFlow {
//     type Item = Io;

//     fn next(&mut self) -> Option<Self::Item> {
//         Some(Io::Entry(self.delete.take()?))
//     }
// }
