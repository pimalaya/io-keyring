use std::fmt;

#[cfg(feature = "secret-service-crypto")]
use crate::secret_service::crypto::sans_io::dh;
use crate::secret_service::crypto::sans_io::Algorithm;

pub struct Session<P> {
    pub path: P,
    pub encryption: Algorithm,
    pub output: Option<Vec<u8>>,
}

impl<P> Session<P> {
    pub fn new_plain(path: P) -> Self {
        Self {
            path,
            encryption: Algorithm::Plain,
            output: None,
        }
    }

    #[cfg(feature = "secret-service-crypto")]
    pub fn new_dh(path: P, keypair: dh::Keypair, output: Vec<u8>) -> Self {
        Self {
            path,
            encryption: Algorithm::Dh(keypair),
            output: Some(output),
        }
    }
}

impl<P: fmt::Debug> fmt::Debug for Session<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("path", &self.path)
            .field("encryption", &self.encryption)
            .field("output", &self.output.is_some())
            .finish()
    }
}
