//! Module dedicated to the [`Delete`] entry I/O-free coroutine.

use log::debug;

use crate::{Entry, Io};

/// The I/O-free coroutine for saving a keyring entry secret.
#[derive(Clone, Debug)]
pub struct Delete {
    input: Option<Entry>,
}

impl Delete {
    /// Creates a new coroutine from the given keyring entry key.
    pub fn new(input: Entry) -> Self {
        Self { input: Some(input) }
    }

    pub fn resume(&mut self, input: Option<Io>) -> Result<(), Io> {
        let Some(input) = input else {
            let Some(input) = self.input.take() else {
                return Err(Io::UnavailableInput);
            };

            debug!("break: need I/O to delete secret from keyring entry");
            return Err(Io::Delete(Err(input)));
        };

        let Io::Delete(Ok(())) = input else {
            return Err(Io::UnexpectedInput(Box::new(input)));
        };

        debug!("resume after deleting secret from keyring entry");
        Ok(())
    }
}
