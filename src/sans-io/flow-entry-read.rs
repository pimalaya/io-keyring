use secrecy::SecretSlice;

use super::{Flow, GetKey, Io, PutSecret, TakeSecret};

/// [`Flow`] for reading a secret from a keyring entry.
#[derive(Clone, Debug)]
pub struct ReadEntryFlow {
    key: String,
    secret: Option<SecretSlice<u8>>,
}

impl ReadEntryFlow {
    /// Creates a new [`ReadEntryFlow`] from the given keyring entry
    /// key.
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

impl Flow for ReadEntryFlow {}

impl GetKey for ReadEntryFlow {
    fn get_key(&self) -> &str {
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
