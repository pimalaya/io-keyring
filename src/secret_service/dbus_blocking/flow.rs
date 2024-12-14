use secrecy::SecretString;

use super::io::SecretServiceIo;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadEntryState {
    Read,
    Decrypt,
}

#[derive(Clone, Debug)]
pub struct ReadEntryFlow {
    state: Option<ReadEntryState>,
    pub secret: Option<SecretString>,
}

impl ReadEntryFlow {
    pub fn new() -> Self {
        Self {
            state: Some(ReadEntryState::Read),
            secret: None,
        }
    }
}

impl Iterator for ReadEntryFlow {
    type Item = SecretServiceIo;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state.take()? {
            ReadEntryState::Read => {
                self.state.replace(ReadEntryState::Decrypt);
                Some(SecretServiceIo::Read)
            }
            ReadEntryState::Decrypt => Some(SecretServiceIo::Decrypt),
        }
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
    pub secret: Option<SecretString>,
}

impl WriteEntryFlow {
    pub fn new(secret: impl Into<SecretString>) -> Self {
        Self {
            state: Some(WriteEntryState::Encrypt),
            secret: Some(secret.into()),
        }
    }
}

impl Iterator for WriteEntryFlow {
    type Item = SecretServiceIo;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state.take()? {
            WriteEntryState::Encrypt => {
                self.state.replace(WriteEntryState::Write);
                Some(SecretServiceIo::Encrypt)
            }
            WriteEntryState::Write => Some(SecretServiceIo::Write),
        }
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
//     type Item = SecretServiceIo;

//     fn next(&mut self) -> Option<Self::Item> {
//         Some(SecretServiceIo::Entry(self.delete.take()?))
//     }
// }
