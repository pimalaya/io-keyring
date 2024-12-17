use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Type, Value};

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Service",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets"
)]
pub trait OrgFreedesktopSecretService {
    fn open_session(&self, algorithm: &str, input: Value<'_>) -> zbus::Result<OpenSessionResult>;
    fn create_collection(
        &self,
        properties: HashMap<&str, Value<'_>>,
        alias: &str,
    ) -> zbus::Result<CreateCollectionResult>;
    fn search_items(&self, attributes: HashMap<&str, &str>) -> zbus::Result<SearchItemsResult>;
    fn unlock(&self, objects: Vec<&ObjectPath<'_>>) -> zbus::Result<LockActionResult>;
    fn lock(&self, objects: Vec<&ObjectPath<'_>>) -> zbus::Result<LockActionResult>;
    fn get_secrets(
        &self,
        objects: Vec<ObjectPath<'_>>,
    ) -> zbus::Result<HashMap<OwnedObjectPath, SecretStruct>>;
    fn read_alias(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    fn set_alias(&self, name: &str, collection: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(property)]
    fn collections(&self) -> zbus::fdo::Result<Vec<ObjectPath<'_>>>;
}

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Collection",
    default_service = "org.freedesktop.Secret.Collection"
)]
pub trait OrgFreedesktopSecretCollection {
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;
    fn search_items(&self, attributes: HashMap<&str, &str>) -> zbus::Result<Vec<OwnedObjectPath>>;
    fn create_item(
        &self,
        properties: HashMap<&str, Value<'_>>,
        secret: SecretStruct,
        replace: bool,
    ) -> zbus::Result<CreateItemResult>;

    #[zbus(property)]
    fn items(&self) -> zbus::fdo::Result<Vec<ObjectPath<'_>>>;
    #[zbus(property)]
    fn label(&self) -> zbus::fdo::Result<String>;
    #[zbus(property)]
    fn set_label(&self, new_label: &str) -> zbus::fdo::Result<()>;
    #[zbus(property)]
    fn locked(&self) -> zbus::fdo::Result<bool>;
    #[zbus(property)]
    fn created(&self) -> zbus::fdo::Result<u64>;
    #[zbus(property)]
    fn modified(&self) -> zbus::fdo::Result<u64>;
}

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Item",
    default_service = "org.freedesktop.Secret.Item"
)]
pub trait OrgFreedesktopSecretItem {
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;
    fn get_secret(&self, session: &ObjectPath<'_>) -> zbus::Result<SecretStruct>;
    fn set_secret(&self, secret: SecretStruct) -> zbus::Result<()>;

    #[zbus(property)]
    fn locked(&self) -> zbus::fdo::Result<bool>;
    #[zbus(property)]
    fn attributes(&self) -> zbus::fdo::Result<HashMap<String, String>>;
    #[zbus(property)]
    fn set_attributes(&self, attributes: HashMap<&str, &str>) -> zbus::fdo::Result<()>;
    #[zbus(property)]
    fn label(&self) -> zbus::fdo::Result<String>;
    #[zbus(property)]
    fn set_label(&self, new_label: &str) -> zbus::fdo::Result<()>;
    #[zbus(property)]
    fn created(&self) -> zbus::fdo::Result<u64>;
    #[zbus(property)]
    fn modified(&self) -> zbus::fdo::Result<u64>;
}

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Prompt",
    default_service = "org.freedesktop.Secret.Prompt"
)]
pub trait OrgFreedesktopSecretPrompt {
    fn prompt(&self, window_id: &str) -> zbus::Result<()>;
    fn dismiss(&self) -> zbus::Result<()>;

    #[zbus(signal)]
    fn completed(&self, dismissed: bool, result: Value<'_>) -> zbus::Result<()>;
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct SecretStruct {
    pub session: OwnedObjectPath,
    pub parameters: Vec<u8>,
    pub value: Vec<u8>,
    pub content_type: String,
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct OpenSessionResult {
    pub output: OwnedValue,
    pub result: OwnedObjectPath,
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct CreateCollectionResult {
    pub collection: OwnedObjectPath,
    pub prompt: OwnedObjectPath,
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct SearchItemsResult {
    pub unlocked: Vec<OwnedObjectPath>,
    pub locked: Vec<OwnedObjectPath>,
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct LockActionResult {
    pub object_paths: Vec<OwnedObjectPath>,
    pub prompt: OwnedObjectPath,
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct CreateItemResult {
    pub item: OwnedObjectPath,
    pub prompt: OwnedObjectPath,
}
