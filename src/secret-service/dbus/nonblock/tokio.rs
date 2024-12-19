use std::{collections::HashMap, fmt, sync::Arc};

use dbus::{
    arg::{PropMap, RefArg, Variant},
    nonblock::{Proxy, SyncConnection},
    Path,
};
use dbus_tokio::connection::{new_session_sync, IOResourceError};
use secrecy::{ExposeSecret, SecretSlice};
use thiserror::Error;
use tokio::task::{JoinError, JoinHandle};
use tracing::error;

#[cfg(feature = "secret-service-crypto")]
use crate::secret_service::crypto::{
    self,
    sans_io::{PutSalt, TakeSalt, ALGORITHM_DH},
};
use crate::{
    sans_io::{GetKey, PutSecret, TakeSecret},
    secret_service::{
        crypto::sans_io::{Algorithm, ALGORITHM_PLAIN},
        dbus::Session,
        sans_io::{DBUS_DEST, DBUS_PATH, DEFAULT_TIMEOUT, ITEM_ATTRIBUTES, ITEM_LABEL},
    },
};

use super::api::{
    OrgFreedesktopSecretCollection, OrgFreedesktopSecretItem, OrgFreedesktopSecretService,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot create Secret Service connection using D-Bus")]
    CreateSessionError(#[source] dbus::Error),
    #[error("cannot open Secret Service session using D-Bus")]
    OpenSessionError(#[source] dbus::Error),
    #[error("cannot parse Secret Service session output using D-Bus")]
    ParseSessionOutputError,

    #[error("cannot get default secret service collection")]
    GetDefaultCollectionError(#[source] dbus::Error),
    #[error("cannot get session secret service collection")]
    GetSessionCollectionError(#[source] dbus::Error),
    #[error("cannot get secret service collections")]
    GetCollectionsError(#[source] dbus::Error),
    #[error("cannot create default secret service collection")]
    CreateDefaultCollectionError(#[source] dbus::Error),
    #[error("cannot create secret service collection item")]
    CreateItemError(#[source] dbus::Error),
    #[error("cannot search items from Secret Service using D-Bus")]
    SearchItemsError(#[source] dbus::Error),
    #[error("cannot get item matching {0}:{1} in Secret Service using D-Bus")]
    GetItemNotFoundError(String, String),
    #[error("cannot get secret from Secret Service using D-Bus")]
    GetSecretError(#[source] dbus::Error),
    #[error("cannot delete item from Secret Service using D-Bus")]
    DeleteItemError(#[source] dbus::Error),
    #[error("cannot cast server public key to bytes")]
    CastServerPublicKeyToBytesError,
    #[error("cannot write empty secret into Secret Service entry using D-Bus")]
    WriteEmptySecretError,

    #[error("lost connection to D-Bus")]
    ConnectionLostError(#[source] IOResourceError),

    #[cfg(feature = "secret-service-openssl-std")]
    #[error(transparent)]
    OpensslError(#[from] crypto::openssl::std::Error),
    #[cfg(feature = "secret-service-rust-crypto-std")]
    #[error(transparent)]
    RustCryptoError(#[from] crypto::rust_crypto::std::Error),

    #[error(transparent)]
    JoinError(#[from] JoinError),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct SecretService {
    connection: Arc<SyncConnection>,
    session: Session,
    handle: JoinHandle<()>,
}

impl fmt::Debug for SecretService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretService")
            .field("connection", &self.connection.unique_name())
            .field("session", &self.session)
            .field("handle", &self.handle)
            .finish()
    }
}

impl SecretService {
    pub async fn connect(encryption: Algorithm) -> Result<Self> {
        let new_session = tokio::task::spawn_blocking(new_session_sync);
        let (resource, connection) = new_session.await?.map_err(Error::CreateSessionError)?;

        let handle = tokio::spawn(async move {
            let err = resource.await;
            error!("lost connection to D-Bus: {err}");
        });

        let proxy = Proxy::new(DBUS_DEST, DBUS_PATH, DEFAULT_TIMEOUT, connection.clone());
        let session = match encryption {
            Algorithm::Plain => {
                let input = Variant(Box::new(String::new()) as Box<dyn RefArg>);
                let (_, session_path) = proxy
                    .open_session(ALGORITHM_PLAIN, input)
                    .await
                    .map_err(Error::OpenSessionError)?;
                Session::new_plain(session_path)
            }
            #[cfg(feature = "secret-service-crypto")]
            Algorithm::Dh(keypair) => {
                let input = Variant(Box::new(keypair.public.to_bytes_be()) as Box<dyn RefArg>);
                let (output, session_path) = proxy
                    .open_session(ALGORITHM_DH, input)
                    .await
                    .map_err(Error::OpenSessionError)?;
                let output =
                    dbus::arg::cast::<Vec<u8>>(&output.0).ok_or(Error::ParseSessionOutputError)?;
                Session::new_dh(session_path, keypair, output.clone())
            }
        };

        Ok(Self {
            connection,
            session,
            handle,
        })
    }

    pub async fn get_default_collection(&self) -> Result<Collection<'_>> {
        let proxy = Proxy::new(
            DBUS_DEST,
            DBUS_PATH,
            DEFAULT_TIMEOUT,
            self.connection.clone(),
        );
        let empty_path = Path::default();

        let collection_path = proxy
            .read_alias("default")
            .await
            .map_err(Error::GetDefaultCollectionError)?;

        if collection_path != empty_path {
            return Ok(Collection::new(self, collection_path));
        }

        let collection_path = proxy
            .read_alias("session")
            .await
            .map_err(Error::GetSessionCollectionError)?;

        if collection_path != empty_path {
            return Ok(Collection::new(self, collection_path));
        }

        let collections_path = proxy
            .collections()
            .await
            .map_err(Error::GetCollectionsError)?;

        match collections_path.into_iter().next() {
            Some(collection_path) => Ok(Collection::new(self, collection_path)),
            None => {
                let props: PropMap = HashMap::from_iter(Some((
                    "org.freedesktop.Secret.Collection.Label".into(),
                    Variant(Box::new(String::from("default")) as Box<dyn RefArg>),
                )));

                let (collection_path, _prompt_path) = proxy
                    .create_collection(props, "default")
                    .await
                    .map_err(Error::CreateDefaultCollectionError)?;

                let collection_path = if collection_path == empty_path {
                    // no creation path, so prompt
                    todo!()
                } else {
                    collection_path
                };

                Ok(Collection::new(self, collection_path))
            }
        }
    }

    pub async fn disconnect(self) -> Result<()> {
        self.handle.abort();
        let _ = self.handle.await;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Collection<'a> {
    service: &'a SecretService,
    path: Path<'a>,
}

impl<'a> Collection<'a> {
    pub fn new(service: &'a SecretService, path: Path<'a>) -> Self {
        Self { service, path }
    }

    pub fn proxy(&self) -> Proxy<'_, &'a SyncConnection> {
        let conn = self.service.connection.as_ref();
        Proxy::new(DBUS_DEST, &self.path, DEFAULT_TIMEOUT, conn)
    }

    pub async fn find_item(
        &self,
        service: impl AsRef<str>,
        account: impl AsRef<str>,
    ) -> Result<Option<Item>> {
        let proxy = self.proxy();
        let attrs: HashMap<&str, &str> =
            HashMap::from_iter([("service", service.as_ref()), ("account", account.as_ref())]);

        let items_path = OrgFreedesktopSecretCollection::search_items(&proxy, attrs)
            .await
            .map_err(Error::SearchItemsError)?;

        match items_path.into_iter().next() {
            Some(path) => Ok(Some(Item::new(&self.service, path))),
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
        service: impl ToString,
        account: impl ToString,
        secret: impl Into<SecretSlice<u8>>,
        salt: Vec<u8>,
    ) -> Result<Item<'_>> {
        let secret = secret.into().expose_secret().to_vec();
        let label = Box::new(service.to_string() + ":" + &account.to_string());
        let attrs: Box<HashMap<String, String>> = Box::new(HashMap::from_iter([
            (String::from("service"), service.to_string()),
            (String::from("account"), account.to_string()),
        ]));

        let mut props: PropMap = PropMap::new();
        props.insert(ITEM_LABEL.into(), Variant(label));
        props.insert(ITEM_ATTRIBUTES.into(), Variant(attrs));

        let session = self.service.session.path.clone();
        let secret = (session, salt, secret, "text/plain");
        let (item_path, _prompt_path) = self
            .proxy()
            .create_item(props, secret, true)
            .await
            .map_err(Error::CreateItemError)?;

        let item_path = if item_path == Path::default() {
            // no creation path, so prompt
            todo!()
        } else {
            item_path
        };

        Ok(Item::new(&self.service, item_path))
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
    pub path: Path<'a>,
}

impl<'a> Item<'a> {
    pub fn new(service: &'a SecretService, path: Path<'a>) -> Self {
        Self { service, path }
    }

    pub fn proxy(&self) -> Proxy<'_, &'a SyncConnection> {
        let conn = self.service.connection.as_ref();
        Proxy::new(DBUS_DEST, &self.path, DEFAULT_TIMEOUT, conn)
    }

    pub async fn get_secret(&self) -> Result<(Path<'static>, Vec<u8>, Vec<u8>, String)> {
        let proxy = &self.proxy();
        let session = self.service.session.path.clone();
        OrgFreedesktopSecretItem::get_secret(proxy, session)
            .await
            .map_err(Error::GetSecretError)
    }

    pub async fn delete(&self) -> Result<Path> {
        let proxy = &self.proxy();
        OrgFreedesktopSecretItem::delete(proxy)
            .await
            .map_err(Error::DeleteItemError)
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
        let (_, salt, secret, _) = self
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
        let (_, _, secret, _) = self
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

    pub async fn disconnect(self) -> Result<()> {
        self.service.disconnect().await
    }
}
