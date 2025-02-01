use std::{
    mem,
    task::{ready, Poll},
};

use secrecy::SecretString;

use super::dh::AesKey;

#[derive(Clone, Debug)]
pub enum State {
    None,
    Encrypt {
        /// The secret to encrypt, as input
        secret: Poll<SecretString>,
        /// The shared key used for encryption, as input
        shared_key: Poll<AesKey>,
        /// The encrypted secret, as output
        cypher: Poll<Vec<u8>>,
    },
    Decrypt {
        /// The encrypted secret to decrypt, as input
        cypher: Poll<Vec<u8>>,
        /// The shared key used for decryption, as input
        shared_key: Poll<AesKey>,
        /// The secret to encrypt, as output
        secret: Poll<SecretString>,
    },
}

impl State {
    pub fn encrypt() -> Self {
        Self::Encrypt {
            secret: Poll::Pending,
            shared_key: Poll::Pending,
            cypher: Poll::Pending,
        }
    }

    pub fn decrypt() -> Self {
        Self::Decrypt {
            cypher: Poll::Pending,
            shared_key: Poll::Pending,
            secret: Poll::Pending,
        }
    }

    pub fn get_shared_key(&self) -> Poll<&AesKey> {
        let key = ready!(match self {
            Self::None => return Poll::Pending,
            Self::Encrypt { shared_key, .. } => shared_key,
            Self::Decrypt { shared_key, .. } => shared_key,
        });

        Poll::Ready(key)
    }

    pub fn set_shared_key(&mut self, key: AesKey) {
        match self {
            Self::None => (),
            Self::Encrypt { shared_key, .. } => *shared_key = Poll::Ready(key),
            Self::Decrypt { shared_key, .. } => *shared_key = Poll::Ready(key),
        }
    }
}
