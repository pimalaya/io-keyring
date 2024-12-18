use secrecy::SecretSlice;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot read secret: missing keyring provider")]
    ReadMissingKeyringProviderError,
    #[error("cannot write secret: missing keyring provider")]
    WriteMissingKeyringProviderError,
    #[error("cannot delete entry: missing keyring provider")]
    DeleteMissingKeyringProviderError,

    #[error("cannot encrypt: missing crypto provider")]
    EncryptMissingCryptoProviderError,
    #[error("cannot decrypt: missing crypto provider")]
    DecryptMissingCryptoProviderError,

    #[cfg(feature = "apple-keychain-std")]
    #[error(transparent)]
    AppleKeychainError(#[from] crate::apple::std::Error),
    #[cfg(feature = "windows-credentials-std")]
    #[error(transparent)]
    WindowsCredentialsError(#[from] crate::windows::std::Error),
    #[cfg(feature = "secret-service-dbus-std")]
    #[error(transparent)]
    SecretServiceDbusError(#[from] crate::secret_service::dbus::blocking::std::Error),
    #[cfg(feature = "secret-service-zbus-std")]
    #[error(transparent)]
    SecretServiceZbusError(#[from] crate::secret_service::zbus::std::Error),
    #[cfg(any(
        feature = "secret-service-openssl-std",
        feature = "secret-service-rust-crypto-std",
    ))]
    #[error(transparent)]
    SecretServiceCryptoError(#[from] crate::secret_service::crypto::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "secret-service")]
pub enum Crypto<P> {
    Undefined(std::marker::PhantomData<P>),
    #[cfg(feature = "secret-service-openssl-std")]
    Openssl(
        crate::secret_service::crypto::openssl::std::IoConnector<P>,
        crate::secret_service::crypto::Algorithm,
    ),
    #[cfg(feature = "secret-service-rust-crypto-std")]
    RustCrypto(
        crate::secret_service::crypto::rust_crypto::std::IoConnector<P>,
        crate::secret_service::crypto::Algorithm,
    ),
}

#[cfg(feature = "secret-service")]
impl<P> Default for Crypto<P> {
    fn default() -> Self {
        Self::Undefined(Default::default())
    }
}

#[cfg(feature = "secret-service")]
impl<P> Crypto<P> {
    pub fn decrypt<F>(&mut self, flow: &mut F) -> Result<()>
    where
        F: crate::TakeSecret + crate::PutSecret + crate::secret_service::crypto::TakeSalt,
    {
        match self {
            Self::Undefined(_) => Err(Error::DecryptMissingCryptoProviderError),
            #[cfg(feature = "secret-service-openssl-std")]
            Self::Openssl(crypto, _) => Ok(crypto.decrypt(flow)?),
            #[cfg(feature = "secret-service-rust-crypto-std")]
            Self::RustCrypto(crypto, _) => Ok(crypto.decrypt(flow)?),
        }
    }

    pub fn encrypt<F>(&mut self, flow: &mut F) -> Result<()>
    where
        F: crate::TakeSecret + crate::PutSecret + crate::secret_service::crypto::PutSalt,
    {
        match self {
            Self::Undefined(_) => Err(Error::EncryptMissingCryptoProviderError),
            #[cfg(feature = "secret-service-openssl-std")]
            Self::Openssl(crypto, _) => Ok(crypto.encrypt(flow)?),
            #[cfg(feature = "secret-service-rust-crypto-std")]
            Self::RustCrypto(crypto, _) => Ok(crypto.encrypt(flow)?),
        }
    }

    pub fn algorithm(&self) -> crate::secret_service::crypto::Algorithm {
        match self {
            Self::Undefined(_) => crate::secret_service::crypto::Algorithm::Plain,
            #[cfg(feature = "secret-service-openssl-std")]
            Self::Openssl(_, algorithm) => algorithm.clone(),
            #[cfg(feature = "secret-service-rust-crypto-std")]
            Self::RustCrypto(_, algorithm) => algorithm.clone(),
        }
    }
}

pub enum Keyring {
    Undefined,
    #[cfg(feature = "apple-keychain-std")]
    AppleKeychain(crate::apple::std::IoConnector),
    #[cfg(feature = "windows-credentials-std")]
    WindowsCredentials(crate::windows::std::IoConnector),
    #[cfg(feature = "secret-service-dbus-std")]
    DbusSecretService(
        crate::secret_service::dbus::blocking::std::IoConnector,
        Crypto<dbus::Path<'static>>,
    ),
    #[cfg(feature = "secret-service-zbus-std")]
    ZbusSecretService(
        crate::secret_service::zbus::std::IoConnector,
        Crypto<zbus::zvariant::OwnedObjectPath>,
    ),
}

impl Keyring {
    #[cfg(feature = "apple-keychain-std")]
    pub fn apple_keychain(service: impl ToString) -> Self {
        use crate::apple::std::IoConnector;
        Self::AppleKeychain(IoConnector::new(service))
    }

    #[cfg(feature = "windows-credentials-std")]
    pub fn windows_credentials(service: impl ToString) -> Self {
        use crate::windows::std::IoConnector;
        Self::WindowsCredentials(IoConnector::new(service))
    }

    #[cfg(feature = "secret-service-dbus-std")]
    pub fn dbus_secret_service(
        service: impl ToString,
        crypto: crate::secret_service::crypto::Provider,
    ) -> crate::secret_service::dbus::blocking::std::Result<Self> {
        use crate::secret_service::{crypto::Provider, dbus::blocking::std::IoConnector};
        let algorithm = crypto.algorithm();
        let mut dbus = IoConnector::new(service, algorithm.clone())?;
        match crypto {
            Provider::None => panic!(),
            #[cfg(feature = "secret-service-openssl-std")]
            Provider::Openssl(_) => {
                use crate::secret_service::crypto::openssl;
                let crypto = openssl::std::IoConnector::new(dbus.session())?;
                let crypto = Crypto::Openssl(crypto, algorithm);
                Ok(Self::DbusSecretService(dbus, crypto))
            }
            #[cfg(feature = "secret-service-rust-crypto-std")]
            Provider::RustCrypto(_) => {
                use crate::secret_service::crypto::rust_crypto;
                let crypto = rust_crypto::std::IoConnector::new(dbus.session())?;
                let crypto = Crypto::RustCrypto(crypto, algorithm);
                Ok(Self::DbusSecretService(dbus, crypto))
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[cfg(feature = "secret-service-zbus-std")]
    pub fn zbus_secret_service(
        service: impl ToString,
        crypto: crate::secret_service::crypto::Provider,
    ) -> Result<Self> {
        use crate::secret_service::{crypto::Provider, zbus::std::IoConnector};
        let algorithm = crypto.algorithm();
        let mut zbus = IoConnector::new(service, algorithm.clone())?;
        match crypto {
            Provider::None => panic!(),
            #[cfg(feature = "secret-service-openssl-std")]
            Provider::Openssl(_) => {
                use crate::secret_service::crypto::openssl;
                let crypto = openssl::std::IoConnector::new(zbus.session())?;
                let crypto = Crypto::Openssl(crypto, algorithm);
                Ok(Self::ZbusSecretService(zbus, crypto))
            }
            #[cfg(feature = "secret-service-rust-crypto-std")]
            Provider::RustCrypto(_) => {
                use crate::secret_service::crypto::rust_crypto;
                let crypto = rust_crypto::std::IoConnector::new(zbus.session())?;
                let crypto = Crypto::RustCrypto(crypto, algorithm);
                Ok(Self::ZbusSecretService(zbus, crypto))
            }
        }
    }

    pub fn read(&mut self, key: impl AsRef<str>) -> Result<SecretSlice<u8>> {
        match self {
            Self::Undefined => Err(Error::ReadMissingKeyringProviderError),
            #[cfg(feature = "apple-keychain-std")]
            Self::AppleKeychain(keychain) => {
                use crate::{Io, ReadEntryFlow, TakeSecret};

                let mut flow = ReadEntryFlow::new(key.as_ref());

                while let Some(io) = flow.next() {
                    match io {
                        Io::Read => {
                            keychain.read(&mut flow)?;
                        }
                        _ => (),
                    }
                }

                Ok(flow.take_secret().unwrap())
            }
            #[cfg(feature = "windows-credentials-std")]
            Self::WindowsCredentials(creds) => {
                use crate::{Io, ReadEntryFlow, TakeSecret};

                let mut flow = ReadEntryFlow::new(key.as_ref());

                while let Some(io) = flow.next() {
                    match io {
                        Io::Read => {
                            creds.read(&mut flow)?;
                        }
                        _ => (),
                    }
                }

                Ok(flow.take_secret().unwrap())
            }
            #[cfg(feature = "secret-service-dbus-std")]
            Self::DbusSecretService(dbus, crypto) => {
                use crate::{
                    secret_service::{self, crypto, flow::ReadEntryFlow},
                    Io, TakeSecret,
                };

                let mut flow = ReadEntryFlow::new(key.as_ref(), crypto.algorithm());

                while let Some(io) = flow.next() {
                    match io {
                        secret_service::Io::Entry(Io::Read) => {
                            dbus.read(&mut flow)?;
                        }
                        secret_service::Io::Crypto(crypto::Io::Decrypt) => {
                            crypto.decrypt(&mut flow)?;
                        }
                        _ => (),
                    }
                }

                Ok(flow.take_secret().unwrap())
            }
            #[cfg(feature = "secret-service-zbus-std")]
            Self::ZbusSecretService(zbus, crypto) => {
                use crate::{
                    secret_service::{self, crypto, flow::ReadEntryFlow},
                    Io, TakeSecret,
                };

                let mut flow = ReadEntryFlow::new(key.as_ref(), crypto.algorithm());

                while let Some(io) = flow.next() {
                    match io {
                        secret_service::Io::Entry(Io::Read) => {
                            zbus.read(&mut flow)?;
                        }
                        secret_service::Io::Crypto(crypto::Io::Decrypt) => {
                            crypto.decrypt(&mut flow)?;
                        }
                        _ => (),
                    }
                }

                Ok(flow.take_secret().unwrap())
            }
        }
    }

    pub fn write(
        &mut self,
        key: impl AsRef<str>,
        secret: impl Into<SecretSlice<u8>>,
    ) -> Result<()> {
        match self {
            Self::Undefined => Err(Error::WriteMissingKeyringProviderError),
            #[cfg(feature = "apple-keychain-std")]
            Self::AppleKeychain(keychain) => {
                use crate::{Io, WriteEntryFlow};

                let mut flow = WriteEntryFlow::new(key.as_ref(), secret);

                while let Some(io) = flow.next() {
                    match io {
                        Io::Write => {
                            keychain.write(&mut flow)?;
                        }
                        _ => (),
                    }
                }

                Ok(())
            }
            #[cfg(feature = "windows-credentials-std")]
            Self::WindowsCredentials(creds) => {
                use crate::{Io, WriteEntryFlow};

                let mut flow = WriteEntryFlow::new(key.as_ref(), secret);

                while let Some(io) = flow.next() {
                    match io {
                        Io::Write => {
                            creds.write(&mut flow)?;
                        }
                        _ => (),
                    }
                }

                Ok(())
            }
            #[cfg(feature = "secret-service-dbus-std")]
            Self::DbusSecretService(dbus, crypto) => {
                use crate::{
                    secret_service::{self, crypto, flow::WriteEntryFlow},
                    Io,
                };

                let mut flow = WriteEntryFlow::new(key.as_ref(), secret, crypto.algorithm());

                while let Some(io) = flow.next() {
                    match io {
                        secret_service::Io::Crypto(crypto::Io::Encrypt) => {
                            crypto.encrypt(&mut flow)?;
                        }
                        secret_service::Io::Entry(Io::Write) => {
                            dbus.write(&mut flow)?;
                        }
                        _ => (),
                    }
                }

                Ok(())
            }
            #[cfg(feature = "secret-service-zbus-std")]
            Self::ZbusSecretService(zbus, crypto) => {
                use crate::{
                    secret_service::{self, crypto, flow::WriteEntryFlow},
                    Io,
                };

                let mut flow = WriteEntryFlow::new(key.as_ref(), secret, crypto.algorithm());

                while let Some(io) = flow.next() {
                    match io {
                        secret_service::Io::Crypto(crypto::Io::Encrypt) => {
                            crypto.encrypt(&mut flow)?;
                        }
                        secret_service::Io::Entry(Io::Write) => {
                            zbus.write(&mut flow)?;
                        }
                        _ => (),
                    }
                }

                Ok(())
            }
        }
    }

    pub fn delete(&mut self, key: impl AsRef<str>) -> Result<()> {
        match self {
            Self::Undefined => Err(Error::DeleteMissingKeyringProviderError),
            #[cfg(feature = "apple-keychain-std")]
            Self::AppleKeychain(keychain) => {
                use crate::{DeleteEntryFlow, Io};

                let mut flow = DeleteEntryFlow::new(key.as_ref());

                while let Some(io) = flow.next() {
                    match io {
                        Io::Delete => {
                            keychain.delete(&mut flow)?;
                        }
                        _ => (),
                    }
                }

                Ok(())
            }
            #[cfg(feature = "windows-credentials-std")]
            Self::WindowsCredentials(creds) => {
                use crate::{DeleteEntryFlow, Io};

                let mut flow = DeleteEntryFlow::new(key.as_ref());

                while let Some(io) = flow.next() {
                    match io {
                        Io::Delete => {
                            creds.delete(&mut flow)?;
                        }
                        _ => (),
                    }
                }

                Ok(())
            }
            #[cfg(feature = "secret-service-dbus-std")]
            Self::DbusSecretService(dbus, _) => {
                use crate::{
                    secret_service::{self, flow::DeleteEntryFlow},
                    Io,
                };

                let mut flow = DeleteEntryFlow::new(key.as_ref());

                while let Some(io) = flow.next() {
                    match io {
                        secret_service::Io::Entry(Io::Delete) => {
                            dbus.delete(&mut flow)?;
                        }
                        _ => (),
                    }
                }

                Ok(())
            }
            #[cfg(feature = "secret-service-zbus-std")]
            Self::ZbusSecretService(zbus, _) => {
                use crate::{
                    secret_service::{self, flow::DeleteEntryFlow},
                    Io,
                };

                let mut flow = DeleteEntryFlow::new(key.as_ref());

                while let Some(io) = flow.next() {
                    match io {
                        secret_service::Io::Entry(Io::Delete) => {
                            zbus.delete(&mut flow)?;
                        }
                        _ => (),
                    }
                }

                Ok(())
            }
        }
    }
}

impl Default for Keyring {
    fn default() -> Self {
        Self::Undefined
    }
}
