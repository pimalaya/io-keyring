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
            state: State {
                key: key.to_string(),
                secret: None,
                deleted: None,
            },
        }
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
        if let None = self.state.deleted {
            Some(Io::Delete)
        } else {
            None
        }
    }
}
