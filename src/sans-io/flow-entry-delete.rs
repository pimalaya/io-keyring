use super::{Flow, GetKey, Io};

/// [`Flow`] for deleting a secret from a keyring entry.
#[derive(Clone, Debug)]
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
            Some(Io::Delete)
        }
    }
}

impl Flow for DeleteEntryFlow {}

impl GetKey for DeleteEntryFlow {
    fn get_key(&self) -> &str {
        self.key.as_str()
    }
}
