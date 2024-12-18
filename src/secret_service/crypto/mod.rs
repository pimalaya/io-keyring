pub mod algorithm;
pub mod common;
pub mod error;
pub mod flow;
pub mod io;
#[cfg(feature = "secret-service-openssl-std")]
pub mod openssl;
#[cfg(feature = "secret-service-rust-crypto-std")]
pub mod rust_crypto;

pub use self::{
    algorithm::Algorithm,
    error::{Error, Result},
    flow::{PutSalt, TakeSalt},
    io::Io,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Provider {
    #[default]
    None,
    #[cfg(feature = "secret-service-openssl-std")]
    Openssl(Algorithm),
    #[cfg(feature = "secret-service-rust-crypto-std")]
    RustCrypto(Algorithm),
}

impl Provider {
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::None => Algorithm::Plain,
            #[cfg(feature = "secret-service-openssl-std")]
            Self::Openssl(algorithm) => algorithm.clone(),
            #[cfg(feature = "secret-service-rust-crypto-std")]
            Self::RustCrypto(algorithm) => algorithm.clone(),
        }
    }
}
