use std::fmt;

use dbus::{arg::RefArg, Path};
use num::BigUint;

use super::crypto::{common::Keypair, Algorithm};

pub struct Session {
    encryption: Algorithm,
    keypair: Option<Keypair>,
    output: Box<dyn RefArg + 'static>,
    pub path: Path<'static>,
}

impl Session {
    pub fn new_plain(path: Path<'static>) -> Self {
        Self {
            encryption: Algorithm::Plain,
            keypair: None,
            output: Box::new(String::new()),
            path,
        }
    }

    pub fn new_dh(
        keypair: Keypair,
        output: Box<dyn RefArg + 'static>,
        path: Path<'static>,
    ) -> Self {
        Self {
            encryption: Algorithm::Dh,
            keypair: Some(keypair),
            output,
            path,
        }
    }

    pub fn encryption(&self) -> &Algorithm {
        &self.encryption
    }

    pub fn privkey(&self) -> Option<&BigUint> {
        Some(&self.keypair.as_ref()?.private)
    }

    pub fn output(&self) -> &Box<dyn RefArg + 'static> {
        &self.output
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("encryption", &self.encryption)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}
