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
