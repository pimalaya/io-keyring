use secrecy::SecretSlice;

use crate::Io;

pub trait Flow {
    fn key(&self) -> &str;
}

pub trait TakeSecret: Flow {
    fn take_secret(&mut self) -> Option<SecretSlice<u8>>;
}

pub trait PutSecret: Flow {
    fn put_secret(&mut self, secret: SecretSlice<u8>);
}

#[derive(Clone, Debug)]
pub struct ReadEntryFlow {
    key: String,
    secret: Option<SecretSlice<u8>>,
}

impl ReadEntryFlow {
    pub fn new(key: impl ToString) -> Self {
        Self {
            key: key.to_string(),
            secret: None,
        }
    }
}

impl Iterator for ReadEntryFlow {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        if self.secret.is_none() {
            Some(Io::Read)
        } else {
            None
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

#[derive(Clone, Debug)]
pub struct WriteEntryFlow {
    key: String,
    secret: Option<SecretSlice<u8>>,
}

impl WriteEntryFlow {
    pub fn new(key: impl ToString, secret: impl Into<SecretSlice<u8>>) -> Self {
        Self {
            key: key.to_string(),
            secret: Some(secret.into()),
        }
    }
}

impl Iterator for WriteEntryFlow {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        if self.secret.is_some() {
            Some(Io::Write)
        } else {
            None
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
            Some(Io::Delete)
        }
    }
}

impl Flow for DeleteEntryFlow {
    fn key(&self) -> &str {
        self.key.as_str()
    }
}
