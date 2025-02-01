use secrecy::SecretString;

/// The I/O state.
///
/// This struct represents the I/O state used by I/O connectors to
/// take and set data. It is usually held by flows themselves, and
/// serve as communication bridge between flows and I/O connectors.
#[derive(Clone, Debug)]
pub struct State {
    /// The entry key input.
    pub(crate) key: String,

    /// The secret output.
    pub(crate) secret: Option<SecretString>,

    /// The deleted flag output.
    pub(crate) deleted: bool,
}

impl State {
    pub fn read(key: impl ToString) -> Self {
        Self {
            key: key.to_string(),
            secret: None,
            deleted: false,
        }
    }

    pub fn write(key: impl ToString, secret: impl Into<SecretString>) -> Self {
        Self {
            key: key.to_string(),
            secret: Some(secret.into()),
            deleted: false,
        }
    }

    pub fn delete(key: impl ToString) -> Self {
        Self {
            key: key.to_string(),
            secret: None,
            deleted: false,
        }
    }

    /// Returns a reference to the inner key.
    pub fn get_key(&self) -> &str {
        self.key.as_str()
    }

    /// Takes the secret away from the inner I/O state.
    pub fn take_secret(&mut self) -> Option<SecretString> {
        self.secret.take()
    }

    /// Puts the given secret into the inner I/O state.
    pub fn set_secret(&mut self, secret: impl Into<SecretString>) {
        self.secret = Some(secret.into());
    }

    /// Takes the deleted flag away from the inner I/O state.
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// Marks the current secret as deleted.
    pub fn set_delete_done(&mut self) {
        self.deleted = true;
    }
}
