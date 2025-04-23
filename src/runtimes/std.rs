//! Module dedicated to the standard, blocking stream I/O handler.

use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{Entry, Io};

#[derive(Error, Debug)]
pub enum Error {
    #[error("keyring coroutine's input is missing or has already been used")]
    UnavailableInputError,
    #[error("unexpected keyring coroutine's input: {0:?}")]
    UnexpectedInputError(Box<Io>),
    #[error(transparent)]
    Keyring(#[from] keyring::Error),
}

/// The standard, blocking stream I/O handler.
///
/// Processes the [`Io`] request for the given coroutine, onto the
/// given stream.
pub fn handle(io: Io) -> Result<Io, Error> {
    match io {
        Io::UnavailableInput => Err(Error::UnavailableInputError),
        Io::UnexpectedInput(io) => Err(Error::UnexpectedInputError(io)),
        Io::Read(io) => read(io),
        Io::Write(io) => write(io),
        Io::Delete(io) => delete(io),
    }
}

pub fn read(input: Result<SecretString, Entry>) -> Result<Io, Error> {
    let entry = match input {
        Ok(output) => return Ok(Io::Read(Ok(output))),
        Err(entry) => keyring::Entry::try_from(entry)?,
    };

    let secret = entry.get_password()?;
    let secret = SecretString::from(secret);

    Ok(Io::Read(Ok(secret)))
}

pub fn write(input: Result<(), (Entry, SecretString)>) -> Result<Io, Error> {
    let (entry, secret) = match input {
        Ok(()) => return Ok(Io::Write(Ok(()))),
        Err((entry, secret)) => (keyring::Entry::try_from(entry)?, secret),
    };

    let secret = secret.expose_secret();
    entry.set_password(secret)?;

    Ok(Io::Write(Ok(())))
}

pub fn delete(input: Result<(), Entry>) -> Result<Io, Error> {
    let entry = match input {
        Ok(output) => return Ok(Io::Delete(Ok(output))),
        Err(entry) => keyring::Entry::try_from(entry)?,
    };

    entry.delete_credential()?;

    Ok(Io::Delete(Ok(())))
}
