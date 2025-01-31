use std::{collections::HashMap, fmt};

use async_std::task::{spawn, JoinHandle};
use secrecy::{ExposeSecret, SecretSlice};
use thiserror::Error;
use tracing::error;
use zbus::{
    connection,
    proxy::CacheProperties,
    zvariant::{OwnedObjectPath, Value},
    Connection,
};

#[cfg(feature = "secret-service-crypto")]
use crate::secret_service::crypto::{
    self,
    sans_io::{PutSalt, TakeSalt, ALGORITHM_DH},
};
use crate::{
    sans_io::{GetKey, PutSecret, TakeSecret},
    secret_service::{
        crypto::sans_io::{Algorithm, ALGORITHM_PLAIN},
        sans_io::{DBUS_DEST, DBUS_PATH, ITEM_ATTRIBUTES, ITEM_LABEL},
    },
};

use super::{
    api::{
        CreateCollectionResult, CreateItemResult, OrgFreedesktopSecretCollectionProxy,
        OrgFreedesktopSecretItemProxy, OrgFreedesktopSecretServiceProxy, SecretStruct,
    },
    Session,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot create Secret Service connection using Z-Bus")]
    CreateSessionError(#[source] zbus::Error),
    #[error("cannot open Secret Service session using Z-Bus")]
    OpenSessionError(#[source] zbus::Error),
    #[error("cannot parse Secret Service session output using Z-Bus")]
    ParseSessionOutputError(#[source] zbus::zvariant::Error),

    #[error("cannot build Secret Service service proxy using Z-Bus")]
    BuildServiceProxyError(#[source] zbus::Error),
    #[error("cannot build Secret Service service proxy using Z-Bus: invalid destination")]
    BuildServiceProxyDestinationError(#[source] zbus::Error),
    #[error("cannot build Secret Service service proxy using Z-Bus: invalid path")]
    BuildServiceProxyPathError(#[source] zbus::Error),

    #[error("cannot build Secret Service collection proxy using Z-Bus")]
    BuildCollectionProxyError(#[source] zbus::Error),
    #[error("cannot build Secret Service collection proxy using Z-Bus: invalid destination")]
    BuildCollectionProxyDestinationError(#[source] zbus::Error),
    #[error("cannot build Secret Service collection proxy using Z-Bus: invalid path")]
    BuildCollectionProxyPathError(#[source] zbus::Error),
    #[error("cannot get default Secret Service collection using Z-Bus")]
    GetDefaultCollectionError(#[source] zbus::Error),
    #[error("cannot get session Secret Service collection using Z-Bus")]
    GetSessionCollectionError(#[source] zbus::Error),
    #[error("cannot get Secret Service collections using Z-Bus")]
    GetCollectionsError(#[source] zbus::fdo::Error),
    #[error("cannot create default Secret Service collection using Z-Bus")]
    CreateDefaultCollectionError(#[source] zbus::Error),

    #[error("cannot build Secret Service item proxy using Z-Bus")]
    BuildItemProxyError(#[source] zbus::Error),
    #[error("cannot build Secret Service item proxy using Z-Bus: invalid destination")]
    BuildItemProxyDestinationError(#[source] zbus::Error),
    #[error("cannot build Secret Service item proxy using Z-Bus: invalid path")]
    BuildItemProxyPathError(#[source] zbus::Error),
    #[error("cannot search Secret Service items using Z-Bus")]
    SearchItemsError(#[source] zbus::Error),
    #[error("cannot get Secret Service item matching {0}:{1} using Z-Bus")]
    GetItemNotFoundError(String, String),
    #[error("cannot create Secret Service item using Z-Bus")]
    CreateItemError(#[source] zbus::Error),
    #[error("cannot get Secret Service secret using Z-Bus")]
    GetSecretError(#[source] zbus::Error),
    #[error("cannot delete Secret Service item using Z-Bus")]
    DeleteItemError(#[source] zbus::Error),

    #[error("cannot write empty secret into Secret Service entry using Z-Bus")]
    WriteEmptySecretError,

    #[cfg(feature = "secret-service-openssl-std")]
    #[error(transparent)]
    OpensslError(#[from] crypto::openssl::std::Error),
    #[cfg(feature = "secret-service-rust-crypto-std")]
    #[error(transparent)]
    RustCryptoError(#[from] crypto::rust_crypto::std::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct SecretService {
    connection: Connection,
    session: Session,
    handle: JoinHandle<()>,
}

impl fmt::Debug for SecretService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretService")
            .field("connection", &self.connection.unique_name())
            .field("session", &self.session)
            .finish()
    }
}

impl SecretService {
    async fn proxy(connection: &Connection) -> Result<OrgFreedesktopSecretServiceProxy> {
        OrgFreedesktopSecretServiceProxy::builder(connection)
            .destination(DBUS_DEST)
            .map_err(Error::BuildServiceProxyDestinationError)?
            .path(DBUS_PATH)
            .map_err(Error::BuildServiceProxyPathError)?
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(Error::BuildServiceProxyError)
    }

    pub async fn connect(encryption: Algorithm) -> Result<Self> {
        let connection = connection::Builder::session()
            .map_err(Error::CreateSessionError)?
            .internal_executor(false)
            .build()
            .await
            .map_err(Error::CreateSessionError)?;

        let connection_clone = connection.clone();
        let handle = spawn(async move {
            loop {
                connection_clone.executor().tick().await;
            }
        });

        let proxy = Self::proxy(&connection).await?;

        let session = match encryption {
            Algorithm::Plain => {
                let session = proxy
                    .open_session(ALGORITHM_PLAIN, "".into())
                    .await
                    .map_err(Error::OpenSessionError)?;
                Session::new_plain(session.result)
            }
            #[cfg(feature = "secret-service-crypto")]
            Algorithm::Dh(keypair) => {
                let session = proxy
                    .open_session(ALGORITHM_DH, keypair.public.to_bytes_be().into())
                    .await
                    .map_err(Error::OpenSessionError)?;
                let output =
                    Vec::try_from(session.output).map_err(Error::ParseSessionOutputError)?;
                Session::new_dh(session.result, keypair, output)
            }
        };

        Ok(SecretService {
            connection,
            session,
            handle,
        })
    }

    pub async fn get_default_collection(&self) -> Result<Collection<'_>> {
        let proxy = Self::proxy(&self.connection).await?;
        let empty_path = OwnedObjectPath::default();

        let collection_path = proxy
            .read_alias("default")
            .await
            .map_err(Error::GetDefaultCollectionError)?;

        if collection_path != empty_path {
            return Ok(Collection::new(self, collection_path).await?);
        }

        let collection_path = proxy
            .read_alias("session")
            .await
            .map_err(Error::GetSessionCollectionError)?;

        if collection_path != empty_path {
            return Ok(Collection::new(self, collection_path).await?);
        }

        let collections_path = proxy
            .collections()
            .await
            .map_err(Error::GetCollectionsError)?;

        match collections_path.into_iter().next() {
            Some(collection_path) => Ok(Collection::new(self, collection_path.into()).await?),
            None => {
                let props: HashMap<&str, Value> =
                    HashMap::from_iter(Some((ITEM_LABEL, "default".into())));

                let CreateCollectionResult {
                    collection: collection_path,
                    prompt: _prompt,
                } = proxy
                    .create_collection(props, "default")
                    .await
                    .map_err(Error::CreateDefaultCollectionError)?;

                let collection_path = if collection_path == empty_path {
                    // no creation path, so prompt
                    todo!()
                } else {
                    collection_path
                };

                Ok(Collection::new(self, collection_path).await?)
            }
        }
    }

    pub async fn disconnect(self) {
        self.handle.cancel().await;
    }
}

#[derive(Debug)]
pub struct Collection<'a> {
    service: &'a SecretService,
    proxy: OrgFreedesktopSecretCollectionProxy<'a>,
}

impl<'a> Collection<'a> {
    pub async fn new(service: &'a SecretService, path: OwnedObjectPath) -> Result<Self> {
        let proxy = OrgFreedesktopSecretCollectionProxy::builder(&service.connection)
            .destination(DBUS_DEST)
            .map_err(Error::BuildCollectionProxyDestinationError)?
            .path(path)
            .map_err(Error::BuildCollectionProxyPathError)?
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(Error::BuildCollectionProxyError)?;

        Ok(Self { service, proxy })
    }

    pub async fn find_item(
        &self,
        service: impl AsRef<str>,
        account: impl AsRef<str>,
    ) -> Result<Option<Item>> {
        let attrs: HashMap<&str, &str> =
            HashMap::from_iter([("service", service.as_ref()), ("account", account.as_ref())]);

        let items_path = self
            .proxy
            .search_items(attrs)
            .await
            .map_err(Error::SearchItemsError)?;

        match items_path.into_iter().next() {
            Some(path) => Ok(Some(Item::new(&self.service, path).await?)),
            None => Ok(None),
        }
    }

    pub async fn get_item(
        &self,
        service: impl AsRef<str>,
        account: impl AsRef<str>,
    ) -> Result<Item> {
        let service = service.as_ref();
        let account = account.as_ref();

        match self.find_item(service, account).await? {
            Some(item) => Ok(item),
            None => {
                let service = service.to_owned();
                let account = account.to_owned();
                Err(Error::GetItemNotFoundError(service, account))
            }
        }
    }

    pub async fn create_item(
        &self,
        service: impl AsRef<str>,
        account: impl AsRef<str>,
        secret: impl Into<SecretSlice<u8>>,
        salt: Vec<u8>,
    ) -> Result<Item<'_>> {
        let label = service.as_ref().to_owned() + ":" + account.as_ref();

        let mut attrs: HashMap<&str, &str> = HashMap::new();
        attrs.insert("service", service.as_ref());
        attrs.insert("account", account.as_ref());

        let mut props: HashMap<&str, Value> = HashMap::new();
        props.insert(ITEM_LABEL, label.into());
        props.insert(ITEM_ATTRIBUTES, attrs.into());

        let secret = secret.into().expose_secret().to_vec();
        let secret = SecretStruct {
            session: self.service.session.path.clone(),
            parameters: salt,
            value: secret,
            content_type: "text/plain".into(),
        };

        let CreateItemResult {
            item: item_path,
            prompt: _prompt,
        } = self
            .proxy
            .create_item(props, secret, true)
            .await
            .map_err(Error::CreateItemError)?;

        let item_path = if item_path == OwnedObjectPath::default() {
            // no creation path, so prompt
            todo!()
        } else {
            item_path
        };

        Ok(Item::new(&self.service, item_path).await?)
    }

    pub async fn delete_item(
        &self,
        service: impl AsRef<str>,
        account: impl AsRef<str>,
    ) -> Result<()> {
        self.get_item(service, account).await?.delete().await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Item<'a> {
    service: &'a SecretService,
    proxy: OrgFreedesktopSecretItemProxy<'a>,
}

impl<'a> Item<'a> {
    pub async fn new(service: &'a SecretService, path: OwnedObjectPath) -> Result<Self> {
        let proxy = OrgFreedesktopSecretItemProxy::builder(&service.connection)
            .destination(DBUS_DEST)
            .map_err(Error::BuildItemProxyDestinationError)?
            .path(path)
            .map_err(Error::BuildItemProxyPathError)?
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(Error::BuildItemProxyError)?;

        Ok(Self { service, proxy })
    }

    pub async fn get_secret(&self) -> Result<SecretStruct> {
        self.proxy
            .get_secret(&self.service.session.path.as_ref())
            .await
            .map_err(Error::GetSecretError)
    }

    pub async fn delete(&self) -> Result<OwnedObjectPath> {
        self.proxy.delete().await.map_err(Error::DeleteItemError)
    }
}

pub struct IoConnector {
    service_name: String,
    service: SecretService,
}

impl IoConnector {
    pub async fn new(service: impl ToString, encryption: Algorithm) -> Result<Self> {
        Ok(Self {
            service_name: service.to_string(),
            service: SecretService::connect(encryption).await?,
        })
    }

    pub fn session(&mut self) -> &mut Session {
        &mut self.service.session
    }

    #[cfg(feature = "secret-service-crypto")]
    pub async fn read<F: GetKey + PutSecret + PutSalt>(&mut self, flow: &mut F) -> Result<()> {
        let SecretStruct {
            parameters: salt,
            value: secret,
            ..
        } = self
            .service
            .get_default_collection()
            .await?
            .get_item(&self.service_name, flow.get_key())
            .await?
            .get_secret()
            .await?;

        flow.put_secret(secret.into());
        flow.put_salt(salt);

        Ok(())
    }

    #[cfg(not(feature = "secret-service-crypto"))]
    pub async fn read<F: GetKey + PutSecret>(&mut self, flow: &mut F) -> Result<()> {
        let SecretStruct { value: secret, .. } = self
            .service
            .get_default_collection()
            .await?
            .get_item(&self.service_name, flow.get_key())
            .await?
            .get_secret()
            .await?;

        flow.put_secret(secret.into());

        Ok(())
    }

    #[cfg(feature = "secret-service-crypto")]
    pub async fn write<F: GetKey + TakeSecret + TakeSalt>(&mut self, flow: &mut F) -> Result<()> {
        let secret = flow.take_secret().ok_or(Error::WriteEmptySecretError)?;
        let salt = flow.take_salt().unwrap_or_default();

        self.service
            .get_default_collection()
            .await?
            .create_item(&self.service_name, flow.get_key(), secret, salt)
            .await?;

        Ok(())
    }

    #[cfg(not(feature = "secret-service-crypto"))]
    pub async fn write<F: GetKey + TakeSecret>(&mut self, flow: &mut F) -> Result<()> {
        let secret = flow.take_secret().ok_or(Error::WriteEmptySecretError)?;

        self.service
            .get_default_collection()
            .await?
            .create_item(&self.service_name, flow.get_key(), secret, vec![])
            .await?;

        Ok(())
    }

    pub async fn delete<F: GetKey>(&mut self, flow: &mut F) -> Result<()> {
        self.service
            .get_default_collection()
            .await?
            .get_item(&self.service_name, flow.get_key())
            .await?
            .delete()
            .await?;

        Ok(())
    }

    pub async fn disconnect(self) {
        self.service.disconnect().await;
    }
}
