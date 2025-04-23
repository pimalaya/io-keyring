use log::trace;
use secrecy::SecretString;

use crate::{Entry, Io};

/// The I/O-free coroutine for saving a keyring entry secret.
#[derive(Clone, Debug)]
pub struct Write {
    secret: Option<(Entry, SecretString)>,
}

impl Write {
    pub fn new(entry: Entry, secret: impl Into<SecretString>) -> Self {
        let secret = Some((entry, secret.into()));
        Self { secret }
    }

    pub fn resume(&mut self, arg: Option<Io>) -> Result<(), Io> {
        let Some(arg) = arg else {
            let Some(secret) = self.secret.take() else {
                return Err(Io::err("Entry and secret not ready"));
            };

            trace!("break: need I/O to write secret into keyring entry");
            return Err(Io::Write(Err(secret)));
        };

        let Io::Write(Ok(())) = arg else {
            let err = format!("Expected write output, got {arg:?}");
            return Err(Io::err(err));
        };

        trace!("resume after writing secret into keyring entry");
        Ok(())
    }
}
