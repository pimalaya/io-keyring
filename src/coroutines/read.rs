//! Module dedicated to the [`Read`] entry I/O-free coroutine.

use log::debug;
use secrecy::SecretString;

use crate::{Entry, Io};

/// I/O-free coroutine for reading a secret from a keyring entry.
#[derive(Clone, Debug)]
pub struct Read {
    input: Option<Entry>,
}

impl Read {
    pub fn new(input: Entry) -> Self {
        Self { input: Some(input) }
    }

    pub fn resume(&mut self, input: Option<Io>) -> Result<SecretString, Io> {
        let Some(input) = input else {
            let Some(input) = self.input.take() else {
                return Err(Io::UnavailableInput);
            };

            debug!("break: need I/O to read secret from keyring entry");
            return Err(Io::Read(Err(input)));
        };

        let Io::Read(Ok(secret)) = input else {
            return Err(Io::UnexpectedInput(Box::new(input)));
        };

        debug!("resume after reading keyring entry");
        Ok(secret)
    }
}
