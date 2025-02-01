use std::fmt;

#[cfg(feature = "encryption")]
use super::dh;

pub const ALGORITHM_PLAIN: &'static str = "plain";
#[cfg(feature = "encryption")]
pub const ALGORITHM_DH: &'static str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

#[derive(Clone, Default)]
pub enum Algorithm {
    #[default]
    Plain,
    #[cfg(feature = "encryption")]
    Dh(dh::Keypair),
}

impl Algorithm {
    #[cfg(feature = "encryption")]
    pub fn dh() -> Self {
        Self::Dh(dh::Keypair::generate())
    }
}

impl fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain => f.write_str("Algorithm::Plain"),
            #[cfg(feature = "encryption")]
            Self::Dh(_) => f.write_str("Algorithm::Dh"),
        }
    }
}

impl Eq for Algorithm {}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(feature = "encryption")]
        if matches!(self, Algorithm::Dh(_)) && matches!(other, Algorithm::Dh(_)) {
            return true;
        }

        matches!(self, Algorithm::Plain) && matches!(other, Algorithm::Plain)
    }
}
