use std::marker::PhantomData;

use secrecy::SecretSlice;
use thiserror::Error;

#[cfg(feature = "apple-keychain-std")]
use crate::apple_keychain::std as apple_keychain;
use crate::sans_io::*;
#[cfg(feature = "secret-service-crypto")]
use crate::secret_service::crypto::sans_io::{PutSalt, TakeSalt};
#[cfg(feature = "secret-service-crypto")]
use crate::secret_service::crypto::{self, sans_io::Algorithm};
#[cfg(feature = "secret-service-dbus-std")]
use crate::secret_service::dbus::blocking::std as dbus_secret_service;
#[cfg(feature = "secret-service-zbus-std")]
use crate::secret_service::zbus::std as zbus_secret_service;
#[cfg(feature = "windows-credentials-std")]
use crate::windows_credentials::std as windows_credentials;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot read secret: missing keyring provider")]
    ReadMissingKeyringProviderError,
    #[error("cannot write secret: missing keyring provider")]
    WriteMissingKeyringProviderError,
    #[error("cannot delete entry: missing keyring provider")]
    DeleteMissingKeyringProviderError,

    #[cfg(feature = "secret-service-crypto")]
    #[error("cannot encrypt: missing crypto provider")]
    EncryptMissingCryptoProviderError,
    #[cfg(feature = "secret-service-crypto")]
    #[error("cannot decrypt: missing crypto provider")]
    DecryptMissingCryptoProviderError,

    #[cfg(feature = "apple-keychain-std")]
    #[error(transparent)]
    AppleKeychainError(#[from] apple_keychain::Error),
    #[cfg(feature = "windows-credentials-std")]
    #[error(transparent)]
    WindowsCredentialsError(#[from] windows_credentials::Error),
    #[cfg(feature = "secret-service-dbus-std")]
    #[error(transparent)]
    SecretServiceDbusError(#[from] dbus_secret_service::Error),
    #[cfg(feature = "secret-service-zbus-std")]
    #[error(transparent)]
    SecretServiceZbusError(#[from] zbus_secret_service::Error),
    #[cfg(feature = "secret-service-openssl-std")]
    #[error(transparent)]
    OpensslError(#[from] crypto::openssl::std::Error),
    #[cfg(feature = "secret-service-rust-crypto-std")]
    #[error(transparent)]
    RustCryptoError(#[from] crypto::rust_crypto::std::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub enum Crypto<P> {
    Undefined(PhantomData<P>),
    #[cfg(feature = "secret-service-openssl-std")]
    Openssl(crypto::openssl::std::IoConnector<P>, Algorithm),
    #[cfg(feature = "secret-service-rust-crypto-std")]
    RustCrypto(crypto::rust_crypto::std::IoConnector<P>, Algorithm),
}

impl<P> Crypto<P> {
    #[cfg(feature = "secret-service-crypto")]
    pub fn decrypt<F: TakeSecret + PutSecret + TakeSalt>(&mut self, flow: &mut F) -> Result<()> {
        match self {
            Self::Undefined(_) => Err(Error::DecryptMissingCryptoProviderError),
            #[cfg(feature = "secret-service-openssl-std")]
            Self::Openssl(crypto, _) => Ok(crypto.decrypt(flow)?),
            #[cfg(feature = "secret-service-rust-crypto-std")]
            Self::RustCrypto(crypto, _) => Ok(crypto.decrypt(flow)?),
        }
    }

    #[cfg(feature = "secret-service-crypto")]
    pub fn encrypt<F: TakeSecret + PutSecret + PutSalt>(&mut self, flow: &mut F) -> Result<()> {
        match self {
            Self::Undefined(_) => Err(Error::EncryptMissingCryptoProviderError),
            #[cfg(feature = "secret-service-openssl-std")]
            Self::Openssl(crypto, _) => Ok(crypto.encrypt(flow)?),
            #[cfg(feature = "secret-service-rust-crypto-std")]
            Self::RustCrypto(crypto, _) => Ok(crypto.encrypt(flow)?),
        }
    }

    #[cfg(feature = "secret-service-crypto")]
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Undefined(_) => Algorithm::Plain,
            #[cfg(feature = "secret-service-openssl-std")]
            Self::Openssl(_, algorithm) => algorithm.clone(),
            #[cfg(feature = "secret-service-rust-crypto-std")]
            Self::RustCrypto(_, algorithm) => algorithm.clone(),
        }
    }
}

impl<P> Default for Crypto<P> {
    fn default() -> Self {
        Self::Undefined(Default::default())
    }
}

pub enum Keyring {
    Undefined,
    #[cfg(feature = "apple-keychain-std")]
    AppleKeychain(apple_keychain::IoConnector),
    #[cfg(feature = "windows-credentials-std")]
    WindowsCredentials(windows_credentials::IoConnector),
    #[cfg(feature = "secret-service-dbus-std")]
    DbusSecretService(
        dbus_secret_service::IoConnector,
        Crypto<dbus::Path<'static>>,
    ),
    #[cfg(feature = "secret-service-zbus-std")]
    ZbusSecretService(
        zbus_secret_service::IoConnector,
        Crypto<zbus::zvariant::OwnedObjectPath>,
    ),
}

impl Keyring {
    #[cfg(feature = "apple-keychain-std")]
    pub fn apple_keychain(service: impl ToString) -> Self {
        Self::AppleKeychain(apple_keychain::IoConnector::new(service))
    }

    #[cfg(feature = "windows-credentials-std")]
    pub fn windows_credentials(service: impl ToString) -> Self {
        use windows_credentials::IoConnector;
        Self::WindowsCredentials(IoConnector::new(service))
    }

    #[cfg(feature = "secret-service-dbus-std")]
    pub fn dbus_secret_service(
        service: impl ToString,
        crypto: crypto::std::Crypto,
    ) -> dbus_secret_service::Result<Self> {
        match crypto {
            crypto::std::Crypto::None => {
                let dbus = dbus_secret_service::IoConnector::new(service, Algorithm::Plain)?;
                let crypto = Crypto::Undefined(Default::default());
                Ok(Self::DbusSecretService(dbus, crypto))
            }
            #[cfg(feature = "secret-service-openssl-std")]
            crypto::std::Crypto::Openssl(algorithm) => {
                let mut dbus = dbus_secret_service::IoConnector::new(service, algorithm.clone())?;
                let crypto = crypto::openssl::std::IoConnector::new(dbus.session())?;
                let crypto = Crypto::Openssl(crypto, algorithm);
                Ok(Self::DbusSecretService(dbus, crypto))
            }
            #[cfg(feature = "secret-service-rust-crypto-std")]
            crypto::std::Crypto::RustCrypto(algorithm) => {
                let mut dbus = dbus_secret_service::IoConnector::new(service, algorithm.clone())?;
                let crypto = crypto::rust_crypto::std::IoConnector::new(dbus.session())?;
                let crypto = Crypto::RustCrypto(crypto, algorithm);
                Ok(Self::DbusSecretService(dbus, crypto))
            }
        }
    }

    #[cfg(feature = "secret-service-zbus-std")]
    pub fn zbus_secret_service(
        service: impl ToString,
        crypto: crypto::std::Crypto,
    ) -> zbus_secret_service::Result<Self> {
        match crypto {
            crypto::std::Crypto::None => {
                let zbus = zbus_secret_service::IoConnector::new(service, Algorithm::Plain)?;
                let crypto = Crypto::Undefined(Default::default());
                Ok(Self::ZbusSecretService(zbus, crypto))
            }
            #[cfg(feature = "secret-service-openssl-std")]
            crypto::std::Crypto::Openssl(algorithm) => {
                let mut zbus = zbus_secret_service::IoConnector::new(service, algorithm.clone())?;
                let crypto = crypto::openssl::std::IoConnector::new(zbus.session())?;
                let crypto = Crypto::Openssl(crypto, algorithm);
                Ok(Self::ZbusSecretService(zbus, crypto))
            }
            #[cfg(feature = "secret-service-rust-crypto-std")]
            crypto::std::Crypto::RustCrypto(algorithm) => {
                let mut zbus = zbus_secret_service::IoConnector::new(service, algorithm.clone())?;
                let crypto = crypto::rust_crypto::std::IoConnector::new(zbus.session())?;
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
                    sans_io::Io as EntryIo,
                    secret_service::{
                        crypto::sans_io::Io as CryptoIo,
                        sans_io::{Io, ReadEntryFlow},
                    },
                };

                let mut flow = ReadEntryFlow::new(key.as_ref(), crypto.algorithm());

                while let Some(io) = flow.next() {
                    match io {
                        Io::Entry(EntryIo::Read) => {
                            dbus.read(&mut flow)?;
                        }
                        #[cfg(feature = "secret-service-crypto")]
                        Io::Crypto(CryptoIo::Decrypt) => {
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
                    sans_io::Io as EntryIo,
                    secret_service::{
                        crypto::sans_io::Io as CryptoIo,
                        sans_io::{Io, ReadEntryFlow},
                    },
                };

                let mut flow = ReadEntryFlow::new(key.as_ref(), crypto.algorithm());

                while let Some(io) = flow.next() {
                    match io {
                        Io::Entry(EntryIo::Read) => {
                            zbus.read(&mut flow)?;
                        }
                        #[cfg(feature = "secret-service-crypto")]
                        Io::Crypto(CryptoIo::Decrypt) => {
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
                    sans_io::Io as EntryIo,
                    secret_service::{
                        crypto::sans_io::Io as CryptoIo,
                        sans_io::{Io, WriteEntryFlow},
                    },
                };

                let mut flow = WriteEntryFlow::new(key.as_ref(), secret, crypto.algorithm());

                while let Some(io) = flow.next() {
                    match io {
                        #[cfg(feature = "secret-service-crypto")]
                        Io::Crypto(CryptoIo::Encrypt) => {
                            crypto.encrypt(&mut flow)?;
                        }
                        Io::Entry(EntryIo::Write) => {
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
                    sans_io::Io as EntryIo,
                    secret_service::{
                        crypto::sans_io::Io as CryptoIo,
                        sans_io::{Io, WriteEntryFlow},
                    },
                };

                let mut flow = WriteEntryFlow::new(key.as_ref(), secret, crypto.algorithm());

                while let Some(io) = flow.next() {
                    match io {
                        #[cfg(feature = "secret-service-crypto")]
                        Io::Crypto(CryptoIo::Encrypt) => {
                            crypto.encrypt(&mut flow)?;
                        }
                        Io::Entry(EntryIo::Write) => {
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
                    sans_io::Io as EntryIo,
                    secret_service::sans_io::{DeleteEntryFlow, Io},
                };

                let mut flow = DeleteEntryFlow::new(key.as_ref());

                while let Some(io) = flow.next() {
                    match io {
                        Io::Entry(EntryIo::Delete) => {
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
                    sans_io::Io as EntryIo,
                    secret_service::sans_io::{DeleteEntryFlow, Io},
                };

                let mut flow = DeleteEntryFlow::new(key.as_ref());

                while let Some(io) = flow.next() {
                    match io {
                        Io::Entry(EntryIo::Delete) => {
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
