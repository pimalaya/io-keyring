use dbus::{
    blocking::{Connection, Proxy},
    Path,
};
use keyring_secret_service_lib::{
    generated::blocking::OrgFreedesktopSecretItem, DBUS_DEST, DEFAULT_TIMEOUT,
};

use crate::{service::SecretService, Error, Result};

#[derive(Debug)]
pub struct Item<'a> {
    service: &'a SecretService,
    pub path: Path<'a>,
}

impl<'a> Item<'a> {
    pub fn new(service: &'a SecretService, path: Path<'a>) -> Self {
        Self { service, path }
    }

    pub fn proxy(&self) -> Proxy<'_, &'a Connection> {
        self.service
            .connection
            .with_proxy(DBUS_DEST, &self.path, DEFAULT_TIMEOUT)
    }

    pub fn get_secret(&self) -> Result<(Path<'static>, Vec<u8>, Vec<u8>, String)> {
        let proxy = &self.proxy();
        let session = self.service.session.path.clone();
        OrgFreedesktopSecretItem::get_secret(proxy, session).map_err(Error::GetSecretError)
    }

    pub fn delete(&self) -> Result<Path> {
        let proxy = &self.proxy();
        OrgFreedesktopSecretItem::delete(proxy).map_err(Error::DeleteItemError)
    }
}
