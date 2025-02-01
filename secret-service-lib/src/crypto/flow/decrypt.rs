//! # Decrypt
//!
//! Module dedicated to the I/O-free [`Decrypt`] flow.

use tracing::debug;

use crate::crypto::{Io, State};

/// The I/O-free flow for decrypting a secret.
#[derive(Clone, Debug)]
pub struct Decrypt {
    state: State,
}

impl Decrypt {
    pub fn new() -> Self {
        Self {
            state: State::decrypt(),
        }
    }
}

impl AsMut<State> for Decrypt {
    fn as_mut(&mut self) -> &mut State {
        &mut self.state
    }
}

impl Iterator for Decrypt {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        let State::Decrypt {
            secret,
            salt,
            cypher,
        } = &self.state
        else {
            debug!(state = ?self.state, "invalid state for decrypt flow");
            return None;
        };

        if cypher.is_pending() {
            return None;
        }

        if salt.is_pending() {
            return None;
        }

        if secret.is_ready() {
            return None;
        }

        Some(Io::Decrypt)
    }
}
