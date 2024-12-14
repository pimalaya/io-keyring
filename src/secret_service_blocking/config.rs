use std::time::Duration;

pub static TIMEOUT: Duration = Duration::from_secs(2);

pub static DBUS_DEST: &str = "org.freedesktop.secrets";
pub static DBUS_PATH: &str = "/org/freedesktop/secrets";

pub static COLLECTION_LABEL: &str = "org.freedesktop.Secret.Collection.Label";

pub static ITEM_LABEL: &str = "org.freedesktop.Secret.Item.Label";
pub static ITEM_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";
