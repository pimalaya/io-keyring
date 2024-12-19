use zbus::zvariant::OwnedObjectPath;

pub type Session = crate::secret_service::sans_io::Session<OwnedObjectPath>;
