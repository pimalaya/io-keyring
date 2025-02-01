use dbus::Path;

pub type Session = keyring_secret_service_lib::Session<Path<'static>>;
