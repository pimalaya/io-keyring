use std::fmt;

use num::BigUint;

use crate::secret_service::crypto::{common::Keypair, Algorithm};

pub struct Session<P> {
    encryption: Algorithm,
    keypair: Option<Keypair>,
    output: Option<Vec<u8>>,
    pub path: P,
}

impl<P> Session<P> {
    pub fn new_plain(path: P) -> Self {
        Self {
            encryption: Algorithm::Plain,
            keypair: None,
            output: None,
            path,
        }
    }

    pub fn new_dh(path: P, keypair: Keypair, output: Vec<u8>) -> Self {
        Self {
            encryption: Algorithm::Dh,
            keypair: Some(keypair),
            output: Some(output),
            path,
        }
    }

    pub fn encryption(&self) -> &Algorithm {
        &self.encryption
    }

    pub fn privkey(&self) -> Option<&BigUint> {
        Some(&self.keypair.as_ref()?.private)
    }

    pub fn take_output(&mut self) -> Option<Vec<u8>> {
        self.output.take()
    }
}

impl<P: fmt::Debug> fmt::Debug for Session<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("encryption", &self.encryption)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}
