//! # Delete entry flow
//!
//! Module dedicated to the I/O-free [`DeleteEntry`] flow.

use crate::{Io, State};

/// [`Flow`] for deleting a secret from a keyring entry.
#[derive(Clone, Debug)]
pub struct DeleteEntry {
    state: State,
}

impl DeleteEntry {
    pub fn new(key: impl ToString) -> Self {
        Self {
            state: State::delete(key),
        }
    }

    /// Takes the deleted flag away from the inner I/O state.
    pub fn is_deleted(&self) -> bool {
        self.state.is_deleted()
    }
}

impl AsMut<State> for DeleteEntry {
    fn as_mut(&mut self) -> &mut State {
        &mut self.state
    }
}

impl Iterator for DeleteEntry {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        if self.state.is_deleted() {
            None
        } else {
            Some(Io::Delete)
        }
    }
}
