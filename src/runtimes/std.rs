//! The standard, blocking keyring runtime.

use keyring::{Entry, Error};
use secrecy::{ExposeSecret, SecretString};

use crate::{entry::KeyringEntry, io::KeyringIo};

/// The standard, blocking keyring runtime handler.
///
/// This handler makes use of [`keyring`] module to process
/// [`KeyringIo`].
pub fn handle(io: KeyringIo) -> Result<KeyringIo, Error> {
    match io {
        KeyringIo::Read(io) => read(io),
        KeyringIo::Write(io) => write(io),
        KeyringIo::Delete(io) => delete(io),
    }
}

pub fn read(input: Result<SecretString, KeyringEntry>) -> Result<KeyringIo, Error> {
    let entry = match input {
        Ok(output) => return Ok(KeyringIo::Read(Ok(output))),
        Err(entry) => Entry::try_from(entry)?,
    };

    let secret = entry.get_password()?;
    let secret = SecretString::from(secret);

    Ok(KeyringIo::Read(Ok(secret)))
}

pub fn write(input: Result<(), (KeyringEntry, SecretString)>) -> Result<KeyringIo, Error> {
    let (entry, secret) = match input {
        Ok(()) => return Ok(KeyringIo::Write(Ok(()))),
        Err((entry, secret)) => (Entry::try_from(entry)?, secret),
    };

    let secret = secret.expose_secret();
    entry.set_password(secret)?;

    Ok(KeyringIo::Write(Ok(())))
}

pub fn delete(input: Result<(), KeyringEntry>) -> Result<KeyringIo, Error> {
    let entry = match input {
        Ok(output) => return Ok(KeyringIo::Delete(Ok(output))),
        Err(entry) => Entry::try_from(entry)?,
    };

    entry.delete_credential()?;

    Ok(KeyringIo::Delete(Ok(())))
}
