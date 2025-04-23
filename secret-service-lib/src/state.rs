use crate::crypto::{self, Algorithm};

#[derive(Clone, Debug)]
pub struct State {
    pub(crate) keyring: keyring_lib::State,
    pub(crate) crypto: crypto::State,
}

impl State {
    pub fn read(key: impl ToString, encryption: Algorithm) -> Self {
        Self {
            keyring: keyring_lib::State::read(key),
            crypto: match encryption {
                Algorithm::Plain => crypto::State::None,
                Algorithm::Dh(_) => crypto::State::decrypt(),
            },
        }
    }
}

impl AsMut<keyring_lib::State> for State {
    fn as_mut(&mut self) -> &mut keyring_lib::State {
        &mut self.keyring
    }
}

impl AsMut<crypto::State> for State {
    fn as_mut(&mut self) -> &mut crypto::State {
        &mut self.crypto
    }
}
