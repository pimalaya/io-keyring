use zbus::zvariant::OwnedObjectPath;

pub type Session = crate::secret_service::Session<OwnedObjectPath>;
