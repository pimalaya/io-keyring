use std::{collections::HashMap, fmt};

use dbus::{
    arg::{PropMap, RefArg, Variant},
    blocking::{Connection, Proxy},
    Path,
};
use secrecy::{ExposeSecret, SecretSlice};
use thiserror::Error;

use super::{
    api::{OrgFreedesktopSecretCollection, OrgFreedesktopSecretItem, OrgFreedesktopSecretService},
    DBUS_DEST, DBUS_PATH, ITEM_ATTRIBUTES, ITEM_LABEL, TIMEOUT,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot create D-Bus connection")]
    CreateSessionError(#[source] dbus::Error),
    #[error("cannot open D-Bus session")]
    OpenSessionError(#[source] dbus::Error),
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
    #[error("cannot cast server public key to bytes using OpenSSL")]
    CastServerPublicKeyToBytesError,
    #[error("cannot derive shared key using OpenSSL")]
    DeriveSharedKeyError(#[source] openssl::error::ErrorStack),
    #[error("cannot encrypt secret using OpenSSL")]
    EncryptSecretError(#[source] openssl::error::ErrorStack),
    #[error("cannot encrypt empty secret using OpenSSL")]
    EncryptSecretEmptyError,
    #[error("cannot decrypt secret using OpenSSL")]
    DecryptSecretError(#[source] openssl::error::ErrorStack),
    #[error("cannot decrypt empty secret using OpenSSL")]
    DecryptSecretEmptyError,
    #[error("cannot write empty secret into Secret Service entry using D-Bus")]
    WriteEmptySecretError,
}

pub type Result<T> = ::std::result::Result<T, Error>;

pub struct SecretServiceStd {
    connection: Connection,
}

impl fmt::Debug for SecretServiceStd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretServiceStd")
            .field("connection", &self.connection.unique_name())
            .finish()
    }
}

impl SecretServiceStd {
    pub fn connect() -> Result<Self> {
        let connection = Connection::new_session().map_err(Error::CreateSessionError)?;
        Ok(Self { connection })
    }

    pub fn get_default_collection(&self) -> Result<Collection<'_>> {
        let proxy = self.connection.with_proxy(DBUS_DEST, DBUS_PATH, TIMEOUT);
        let empty_path = Path::default();

        let collection_path = proxy
            .read_alias("default")
            .map_err(Error::GetDefaultCollectionError)?;

        if collection_path != empty_path {
            return Ok(Collection::new(self, collection_path));
        }

        let collection_path = proxy
            .read_alias("session")
            .map_err(Error::GetSessionCollectionError)?;

        if collection_path != empty_path {
            return Ok(Collection::new(self, collection_path));
        }

        let collections_path = proxy.collections().map_err(Error::GetCollectionsError)?;

        match collections_path.into_iter().next() {
            Some(collection_path) => Ok(Collection::new(self, collection_path)),
            None => {
                let props: PropMap = HashMap::from_iter(Some((
                    "org.freedesktop.Secret.Collection.Label".into(),
                    Variant(Box::new(String::from("default")) as Box<dyn RefArg>),
                )));

                let (collection_path, _prompt_path) = proxy
                    .create_collection(props, "default")
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
}

// #[derive(Debug)]
// pub struct Session {
//     path: Path<'static>,
//     algorithm: Algorithm,
// }

#[derive(Debug)]
pub struct Collection<'a> {
    service: &'a SecretServiceStd,
    path: Path<'a>,
}

impl<'a> Collection<'a> {
    pub fn new(service: &'a SecretServiceStd, path: Path<'a>) -> Self {
        Self { service, path }
    }

    pub fn proxy(&self) -> Proxy<'_, &'a Connection> {
        self.service
            .connection
            .with_proxy(DBUS_DEST, &self.path, TIMEOUT)
    }

    pub fn find_item(
        &self,
        service: impl AsRef<str>,
        account: impl AsRef<str>,
    ) -> Result<Option<Item>> {
        let proxy = self.proxy();
        let attrs: HashMap<&str, &str> =
            HashMap::from_iter([("service", service.as_ref()), ("account", account.as_ref())]);

        let items_path = OrgFreedesktopSecretCollection::search_items(&proxy, attrs)
            .map_err(Error::SearchItemsError)?;

        match items_path.into_iter().next() {
            Some(path) => Ok(Some(Item::new(&self.service, path))),
            None => Ok(None),
        }
    }

    pub fn get_item(&self, service: impl AsRef<str>, account: impl AsRef<str>) -> Result<Item> {
        let service = service.as_ref();
        let account = account.as_ref();

        match self.find_item(service, account)? {
            Some(item) => Ok(item),
            None => {
                let service = service.to_owned();
                let account = account.to_owned();
                Err(Error::GetItemNotFoundError(service, account))
            }
        }
    }

    pub fn create_item(
        &self,
        service: impl ToString,
        account: impl ToString,
        secret: impl Into<SecretSlice<u8>>,
        salt: Vec<u8>,
        session_path: Path<'static>,
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

        let secret = (session_path, salt, secret, "text/plain");
        let (item_path, _prompt_path) = self
            .proxy()
            .create_item(props, secret, true)
            .map_err(Error::CreateItemError)?;

        let item_path = if item_path == Path::default() {
            // no creation path, so prompt
            todo!()
        } else {
            item_path
        };

        Ok(Item::new(&self.service, item_path))
    }

    pub fn delete_item(&self, service: impl AsRef<str>, account: impl AsRef<str>) -> Result<()> {
        self.get_item(service, account)?.delete()?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Item<'a> {
    service: &'a SecretServiceStd,
    pub path: Path<'a>,
}

impl<'a> Item<'a> {
    pub fn new(service: &'a SecretServiceStd, path: Path<'a>) -> Self {
        Self { service, path }
    }

    pub fn proxy(&self) -> Proxy<'_, &'a Connection> {
        self.service
            .connection
            .with_proxy(DBUS_DEST, &self.path, TIMEOUT)
    }

    pub fn get_secret(
        &self,
        session_path: Path<'static>,
    ) -> Result<(Path<'static>, Vec<u8>, Vec<u8>, String)> {
        let proxy = &self.proxy();
        OrgFreedesktopSecretItem::get_secret(proxy, session_path).map_err(Error::GetSecretError)
    }

    pub fn delete(&self) -> Result<Path> {
        let proxy = &self.proxy();
        OrgFreedesktopSecretItem::delete(proxy).map_err(Error::DeleteItemError)
    }
}

pub struct SecretServiceDbusStdProcessor {
    service: String,
    account: String,
    dbus: SecretServiceStd,
    pub secret: Option<(SecretSlice<u8>, Vec<u8>)>,
}

impl SecretServiceDbusStdProcessor {
    pub fn try_new(service: impl ToString, account: impl ToString) -> Result<Self> {
        Ok(Self {
            service: service.to_string(),
            account: account.to_string(),
            dbus: SecretServiceStd::connect()?,
            secret: None,
        })
    }

    pub fn connection(&self) -> &Connection {
        &self.dbus.connection
    }

    pub fn save(&mut self, session_path: Path<'static>) -> Result<()> {
        let Some((secret, salt)) = self.secret.take() else {
            return Err(Error::WriteEmptySecretError);
        };

        self.dbus.get_default_collection()?.create_item(
            self.service.clone(),
            self.account.clone(),
            secret,
            salt,
            session_path,
        )?;

        Ok(())
    }

    pub fn read(&mut self, session_path: Path<'static>) -> Result<(SecretSlice<u8>, Vec<u8>)> {
        let (_, salt, secret, _) = self
            .dbus
            .get_default_collection()?
            .get_item(self.service.clone(), self.account.clone())?
            .get_secret(session_path)?;

        Ok((secret.into(), salt))
    }
}
