use std::{
    collections::HashMap,
    fmt,
    sync::mpsc::{channel, TryRecvError},
    time::Duration,
};

use dbus::{
    arg::{cast, PropMap, RefArg, Variant},
    blocking::Connection,
    Message, Path,
};
#[cfg(feature = "encryption")]
use keyring_secret_service_lib::crypto::ALGORITHM_DH;
use keyring_secret_service_lib::{
    crypto::{Algorithm, ALGORITHM_PLAIN},
    generated::blocking::{
        OrgFreedesktopSecretPrompt, OrgFreedesktopSecretPromptCompleted,
        OrgFreedesktopSecretService,
    },
    DBUS_DEST, DBUS_PATH, DEFAULT_TIMEOUT,
};
use tracing::warn;

use crate::{collection::Collection, Error, Result, Session};

pub struct SecretService {
    pub(crate) connection: Connection,
    pub(crate) session: Session,
}

impl fmt::Debug for SecretService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretService")
            .field("connection", &self.connection.unique_name())
            .field("session", &self.session)
            .finish()
    }
}

impl SecretService {
    pub fn connect(encryption: Algorithm) -> Result<Self> {
        let connection = Connection::new_session().map_err(Error::CreateSessionError)?;
        let proxy = connection.with_proxy(DBUS_DEST, DBUS_PATH, DEFAULT_TIMEOUT);
        let session = match encryption {
            Algorithm::Plain => {
                let input = Variant(Box::new(String::new()) as Box<dyn RefArg>);
                let (_, session_path) = proxy
                    .open_session(ALGORITHM_PLAIN, input)
                    .map_err(Error::OpenSessionError)?;
                Session::new_plain(session_path)
            }
            #[cfg(feature = "encryption")]
            Algorithm::Dh(keypair) => {
                let input = Variant(Box::new(keypair.public.to_bytes_be()) as Box<dyn RefArg>);
                let (output, session_path) = proxy
                    .open_session(ALGORITHM_DH, input)
                    .map_err(Error::OpenSessionError)?;
                let output = cast::<Vec<u8>>(&output.0).ok_or(Error::ParseSessionOutputError)?;
                Session::new_dh(session_path, keypair, output.clone())
            }
        };

        Ok(Self {
            connection,
            session,
        })
    }

    pub fn get_default_collection(&self) -> Result<Collection<'_>> {
        let proxy = self
            .connection
            .with_proxy(DBUS_DEST, DBUS_PATH, DEFAULT_TIMEOUT);
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

                let (collection_path, prompt_path) = proxy
                    .create_collection(props, "default")
                    .map_err(Error::CreateDefaultCollectionError)?;

                let collection_path = if collection_path == empty_path {
                    // no creation path, so prompt
                    self.prompt(&prompt_path)?
                } else {
                    collection_path
                };

                Ok(Collection::new(self, collection_path))
            }
        }
    }

    pub(crate) fn prompt(&self, path: &Path) -> Result<Path<'static>> {
        let timeout = 5 * 60 * 60; // 5 min
        let proxy = self.connection.with_proxy(DBUS_DEST, path, DEFAULT_TIMEOUT);
        let (tx, rx) = channel::<Result<Path<'static>>>();

        let token = proxy
            .match_signal(
                move |signal: OrgFreedesktopSecretPromptCompleted, _: &Connection, _: &Message| {
                    let result = if signal.dismissed {
                        Err(Error::PromptDismissedError)
                    } else if let Some(first) = signal.result.as_static_inner(0) {
                        match cast::<Path<'_>>(first) {
                            Some(path) => Ok(path.clone().into_static()),
                            None => Err(Error::ParsePromptPathError),
                        }
                    } else {
                        Err(Error::ParsePromptSignalError)
                    };

                    if let Err(err) = tx.send(result) {
                        warn!(?err, "cannot send prompt result, exiting anyway")
                    }

                    false
                },
            )
            .map_err(Error::PromptMatchSignalError)?;

        proxy.prompt("").map_err(Error::PromptError)?;

        let mut result = Err(Error::PromptTimeoutError);

        for _ in 0..timeout {
            match self.connection.process(Duration::from_secs(1)) {
                Ok(false) => continue,
                Ok(true) => match rx.try_recv() {
                    Ok(res) => {
                        result = res;
                        break;
                    }
                    Err(TryRecvError::Empty) => continue,
                    Err(TryRecvError::Disconnected) => break,
                },
                _ => break,
            }
        }

        proxy
            .match_stop(token, true)
            .map_err(Error::PromptMatchStopError)?;

        result
    }
}
