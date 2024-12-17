use dbus::Path;

pub type Session = crate::secret_service::Session<Path<'static>>;
