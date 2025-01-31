use crate::sans_io::{Flow, GetKey, Io as EntryIo};

use super::Io;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteEntryFlow {
    key: String,
    deleted: bool,
}

impl DeleteEntryFlow {
    pub fn new(key: impl ToString) -> Self {
        Self {
            key: key.to_string(),
            deleted: false,
        }
    }
}

impl Iterator for DeleteEntryFlow {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        if self.deleted {
            None
        } else {
            self.deleted = true;
            Some(Io::Entry(EntryIo::Delete))
        }
    }
}

impl Flow for DeleteEntryFlow {}

impl GetKey for DeleteEntryFlow {
    fn get_key(&self) -> &str {
        self.key.as_str()
    }
}
