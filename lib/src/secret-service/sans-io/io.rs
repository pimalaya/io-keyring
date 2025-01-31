use crate::sans_io::Io as EntryIo;
#[cfg(feature = "secret-service-crypto")]
use crate::secret_service::crypto::sans_io::Io as CryptoIo;

#[derive(Clone, Debug)]
pub enum Io {
    Entry(EntryIo),
    #[cfg(feature = "secret-service-crypto")]
    Crypto(CryptoIo),
}
