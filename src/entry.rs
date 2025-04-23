#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub name: String,
    pub service: String,
}

impl Entry {
    pub fn new(name: impl ToString) -> Self {
        Self {
            name: name.to_string(),
            service: env!("CARGO_CRATE_NAME").to_string(),
        }
    }

    pub fn service(mut self, service: impl ToString) -> Self {
        self.service = service.to_string();
        self
    }
}

impl TryFrom<Entry> for keyring::Entry {
    type Error = keyring::Error;

    fn try_from(entry: Entry) -> keyring::Result<Self> {
        keyring::Entry::new(&entry.service, &entry.name)
    }
}
