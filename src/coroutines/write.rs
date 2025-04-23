//! Module dedicated to the [`Write`] entry I/O-free coroutine.

use log::debug;
use secrecy::SecretString;

use crate::{Entry, Io};

/// The I/O-free coroutine for saving a keyring entry secret.
#[derive(Clone, Debug)]
pub struct Write {
    input: Option<(Entry, SecretString)>,
}

impl Write {
    /// Creates a new coroutine from the given keyring entry key.
    pub fn new(entry: Entry, secret: impl Into<SecretString>) -> Self {
        let input = Some((entry, secret.into()));
        Self { input }
    }

    pub fn resume(&mut self, input: Option<Io>) -> Result<(), Io> {
        let Some(input) = input else {
            let Some(input) = self.input.take() else {
                return Err(Io::UnavailableInput);
            };

            debug!("break: need I/O to write secret into keyring entry");
            return Err(Io::Write(Err(input)));
        };

        let Io::Write(Ok(())) = input else {
            return Err(Io::UnexpectedInput(Box::new(input)));
        };

        debug!("resume after writing secret into keyring entry");
        Ok(())
    }
}
