use log::trace;
use secrecy::SecretString;

use crate::{Entry, Io};

/// I/O-free coroutine for reading a secret from a keyring entry.
#[derive(Clone, Debug)]
pub struct Read {
    entry: Option<Entry>,
}

impl Read {
    pub fn new(entry: Entry) -> Self {
        Self { entry: Some(entry) }
    }

    pub fn resume(&mut self, arg: Option<Io>) -> Result<SecretString, Io> {
        let Some(arg) = arg else {
            let Some(entry) = self.entry.take() else {
                return Err(Io::err("Entry not ready"));
            };

            trace!("break: need I/O to read secret from keyring entry");
            return Err(Io::Read(Err(entry)));
        };

        let Io::Read(Ok(secret)) = arg else {
            let err = format!("Expected read output, got {arg:?}");
            return Err(Io::err(err));
        };

        trace!("resume after reading keyring entry");
        Ok(secret)
    }
}
