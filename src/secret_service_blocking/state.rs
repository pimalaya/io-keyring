use super::encryption::EncryptionAlgorithm;

#[derive(Clone, Debug, Default)]
pub enum SecretServiceEntryStateKind {
    #[default]
    Idle,
    Read,
    Write,
    Decrypt,
    Encrypt,
}

#[derive(Clone, Debug, Default)]
pub struct SecretServiceEntryState {
    pub service: String,
    pub account: String,
    pub kind: SecretServiceEntryStateKind,
    pub algorithm: EncryptionAlgorithm,
}
