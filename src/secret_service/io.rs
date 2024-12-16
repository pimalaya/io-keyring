use crate::secret_service::crypto;

#[derive(Clone, Debug)]
pub enum Io {
    Entry(crate::Io),
    Crypto(crypto::Io),
}
