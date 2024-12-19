use dbus::Path;

use crate::secret_service::sans_io;

pub type Session = sans_io::Session<Path<'static>>;
