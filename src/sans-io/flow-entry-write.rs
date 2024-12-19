use secrecy::SecretSlice;

use super::{Flow, GetKey, Io, PutSecret, TakeSecret};

/// [`Flow`] for writing a secret into a keyring entry.
#[derive(Clone, Debug)]
pub struct WriteEntryFlow {
    key: String,
    secret: Option<SecretSlice<u8>>,
}

impl WriteEntryFlow {
    /// Creates a new [`WriteEntryFlow`] from the given keyring entry
    /// key and the given secret.
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

impl Flow for WriteEntryFlow {}

impl GetKey for WriteEntryFlow {
    fn get_key(&self) -> &str {
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
