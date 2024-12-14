#[derive(Clone, Debug)]
pub enum SecretServiceIo {
    Read,
    Write,
    Delete,
    Encrypt,
    Decrypt,
}
