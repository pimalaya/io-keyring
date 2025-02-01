use crate::crypto;

#[derive(Clone, Debug)]
pub enum Io {
    Keyring(keyring_lib::Io),
    Crypto(crypto::Io),
}
