//! # Encrypt
//!
//! Module dedicated to the I/O-free [`Encrypt`] flow.

use tracing::debug;

use crate::crypto::{Io, State};

/// The I/O-free flow for encrypting a secret.
#[derive(Clone, Debug)]
pub struct Encrypt {
    state: State,
}

impl Encrypt {
    pub fn new() -> Self {
        Self {
            state: State::encrypt(),
        }
    }
}

impl AsMut<State> for Encrypt {
    fn as_mut(&mut self) -> &mut State {
        &mut self.state
    }
}

impl Iterator for Encrypt {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        let State::Encrypt {
            secret,
            salt,
            cypher,
        } = &self.state
        else {
            debug!(state = ?self.state, "invalid state for encrypt flow");
            return None;
        };

        if secret.is_pending() {
            return None;
        }

        if salt.is_pending() {
            return None;
        }

        if cypher.is_ready() {
            return None;
        }

        Some(Io::Encrypt)
    }
}
