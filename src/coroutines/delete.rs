use log::trace;

use crate::{Entry, Io};

/// The I/O-free coroutine for deleting a keyring entry.
#[derive(Clone, Debug)]
pub struct Delete {
    entry: Option<Entry>,
}

impl Delete {
    pub fn new(entry: Entry) -> Self {
        Self { entry: Some(entry) }
    }

    pub fn resume(&mut self, arg: Option<Io>) -> Result<(), Io> {
        let Some(arg) = arg else {
            let Some(entry) = self.entry.take() else {
                return Err(Io::err("Entry not ready"));
            };

            trace!("break: need I/O to delete secret from keyring entry");
            return Err(Io::Delete(Err(entry)));
        };

        let Io::Delete(Ok(())) = arg else {
            let err = format!("Expected delete output, got {arg:?}");
            return Err(Io::err(err));
        };

        trace!("resume after deleting secret from keyring entry");
        Ok(())
    }
}
