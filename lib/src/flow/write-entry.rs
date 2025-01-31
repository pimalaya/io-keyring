//! # Write entry flow
//!
//! Module dedicated to the I/O-free [`WriteEntry`] flow.

use secrecy::SecretString;

use crate::{Io, State};

/// The I/O-free flow for writing a secret into a keyring entry.
#[derive(Clone, Debug)]
pub struct WriteEntry {
    state: State,
}

impl WriteEntry {
    /// Creates a new flow from the given keyring entry key.
    pub fn new(key: impl ToString, secret: impl Into<SecretString>) -> Self {
        Self {
            state: State {
                key: key.to_string(),
                secret: Some(secret.into()),
                deleted: None,
            },
        }
    }
}

impl AsMut<State> for WriteEntry {
    fn as_mut(&mut self) -> &mut State {
        &mut self.state
    }
}

impl Iterator for WriteEntry {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        if self.state.secret.is_some() {
            Some(Io::Write)
        } else {
            None
        }
    }
}
