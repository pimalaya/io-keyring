use secrecy::SecretSlice;

use crate::Io;

pub trait Flow {
    fn get_service(&self) -> &str;
    fn get_username(&self) -> &str;

    fn take_secret(&mut self) -> Option<SecretSlice<u8>>;
    fn put_secret(&mut self, secret: SecretSlice<u8>);
}

#[derive(Clone, Debug)]
pub struct ReadEntryFlow {
    service: String,
    username: String,
    secret: Option<SecretSlice<u8>>,
}

impl ReadEntryFlow {
    pub fn new(service: impl ToString, username: impl ToString) -> Self {
        Self {
            service: service.to_string(),
            username: username.to_string(),
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
    fn get_service(&self) -> &str {
        self.service.as_str()
    }

    fn get_username(&self) -> &str {
        self.username.as_str()
    }

    fn take_secret(&mut self) -> Option<SecretSlice<u8>> {
        self.secret.take()
    }

    fn put_secret(&mut self, secret: SecretSlice<u8>) {
        self.secret.replace(secret);
    }
}

#[derive(Clone, Debug)]
pub struct WriteEntryFlow {
    service: String,
    username: String,
    secret: Option<SecretSlice<u8>>,
}

impl WriteEntryFlow {
    pub fn new(
        service: impl ToString,
        username: impl ToString,
        secret: impl Into<SecretSlice<u8>>,
    ) -> Self {
        Self {
            service: service.to_string(),
            username: username.to_string(),
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
    fn get_service(&self) -> &str {
        self.service.as_str()
    }

    fn get_username(&self) -> &str {
        self.username.as_str()
    }

    fn take_secret(&mut self) -> Option<SecretSlice<u8>> {
        self.secret.take()
    }

    fn put_secret(&mut self, secret: SecretSlice<u8>) {
        self.secret.replace(secret);
    }
}
