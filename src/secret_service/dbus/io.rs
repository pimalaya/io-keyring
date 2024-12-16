use crate::secret_service::dbus::crypto;

#[derive(Clone, Debug)]
pub enum Io {
    Entry(crate::Io),
    Crypto(crypto::Io),
}
