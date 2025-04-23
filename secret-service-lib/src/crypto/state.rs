use std::task::Poll;

use secrecy::SecretString;

use super::dh::AesKey;

#[derive(Clone, Debug)]
pub enum State {
    None,
    Encrypt {
        /// The shared key used for encryption
        shared_key: AesKey,
        /// The secret to encrypt, as input
        secret: Poll<SecretString>,
        /// The encrypted secret, as output
        cypher: Poll<Vec<u8>>,
    },
    Decrypt {
        /// The shared key used for decryption
        shared_key: AesKey,
        /// The encrypted secret to decrypt, as input
        cypher: Poll<Vec<u8>>,
        /// The secret to encrypt, as output
        secret: Poll<SecretString>,
    },
}

impl State {
    pub fn encrypt(shared_key: AesKey) -> Self {
        Self::Encrypt {
            shared_key,
            secret: Poll::Pending,
            cypher: Poll::Pending,
        }
    }

    pub fn decript(shared_key: AesKey) -> Self {
        Self::Decrypt {
            shared_key,
            cypher: Poll::Pending,
            secret: Poll::Pending,
        }
    }
}
