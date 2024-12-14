use secrecy::SecretString;

#[derive(Clone, Debug)]
pub enum EntryIo {
    Read,
    Write(SecretString),
    Delete,
}
