use ::std::time::Duration;

pub mod api;
pub mod crypto;
pub mod flow;
pub mod io;
#[cfg(feature = "ss-dbus-std")]
pub mod std;

pub use self::{flow::Flow, io::Io};

pub const TIMEOUT: Duration = Duration::from_secs(2);

pub const DBUS_DEST: &str = "org.freedesktop.secrets";
pub const DBUS_PATH: &str = "/org/freedesktop/secrets";

pub const COLLECTION_LABEL: &str = "org.freedesktop.Secret.Collection.Label";

pub const ITEM_LABEL: &str = "org.freedesktop.Secret.Item.Label";
pub const ITEM_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";
