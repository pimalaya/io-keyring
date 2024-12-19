#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Crypto {
    #[default]
    None,
    #[cfg(feature = "secret-service-openssl-std")]
    Openssl(super::sans_io::Algorithm),
    #[cfg(feature = "secret-service-rust-crypto-std")]
    RustCrypto(super::sans_io::Algorithm),
}
