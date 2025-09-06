//! Module dedicated to the keyring entry.

use keyring::{Entry, Error, Result};

/// The keyring entry structure.
///
/// Represents an entry inside a keyring. An entry is mostly composed
/// of a keyring entry name and a keyring service name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyringEntry {
    pub name: String,
    pub service: String,
}

impl KeyringEntry {
    /// Creates a new keyring entry from the given name.
    ///
    /// The service name is set to the cargo crate name by default.
    pub fn new(name: impl ToString) -> Self {
        Self {
            name: name.to_string(),
            service: env!("CARGO_CRATE_NAME").to_string(),
        }
    }

    /// Changes the keyring service name using the builder pattern.
    pub fn with_service(mut self, service: impl ToString) -> Self {
        self.service = service.to_string();
        self
    }
}

impl TryFrom<KeyringEntry> for Entry {
    type Error = Error;

    fn try_from(entry: KeyringEntry) -> Result<Self> {
        Entry::new(&entry.service, &entry.name)
    }
}
