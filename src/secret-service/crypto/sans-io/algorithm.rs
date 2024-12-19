use std::fmt;

#[cfg(feature = "secret-service-crypto")]
use super::dh;

pub const ALGORITHM_PLAIN: &str = "plain";
#[cfg(feature = "secret-service-crypto")]
pub const ALGORITHM_DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

#[derive(Clone, Default)]
pub enum Algorithm {
    #[default]
    Plain,
    #[cfg(feature = "secret-service-crypto")]
    Dh(dh::Keypair),
}

impl Algorithm {
    #[cfg(feature = "secret-service-crypto")]
    pub fn dh() -> Self {
        Self::Dh(dh::Keypair::generate())
    }
}

impl fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain => f.write_str("Algorithm::Plain"),
            #[cfg(feature = "secret-service-crypto")]
            Self::Dh(_) => f.write_str("Algorithm::Dh"),
        }
    }
}

impl Eq for Algorithm {}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(feature = "secret-service-crypto")]
        if matches!(self, Algorithm::Dh(_)) && matches!(other, Algorithm::Dh(_)) {
            return true;
        }

        matches!(self, Algorithm::Plain) && matches!(other, Algorithm::Plain)
    }
}
