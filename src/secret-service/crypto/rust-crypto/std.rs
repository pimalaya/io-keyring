use aes::cipher::{
    block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use block_padding::UnpadError;
use cbc::{Decryptor, Encryptor};
use hkdf::{Hkdf, InvalidLength};
use num::BigUint;
use rand::{rngs::OsRng, Rng};
use secrecy::ExposeSecret;
use sha2::Sha256;
use thiserror::Error;

use crate::{
    sans_io::{PutSecret, TakeSecret},
    secret_service::{
        crypto::sans_io::{
            dh::{prepare_derive_shared, AesKey},
            Algorithm, PutSalt, TakeSalt,
        },
        sans_io::Session,
    },
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot find public key for Secret Service encrypted session using Rust Crypto")]
    FindPubkeyError,
    #[error("cannot derive shared key for Secret Service encrypted session using Rust Crypto")]
    DeriveSharedKeyError(#[source] hkdf::InvalidLength),

    #[error("cannot find key to encrypt secret using Rust Crypto")]
    EncryptSecretMissingKeyError,
    #[error("cannot find secret to encrypt using Rust Crypto")]
    EncryptSecretMissingSecretError,

    #[error("cannot decrypt secret using Rust Crypto")]
    DecryptSecretError(#[source] block_padding::UnpadError),
    #[error("cannot find key to decrypt secret using Rust Crypto")]
    DecryptSecretMissingKeyError,
    #[error("cannot find salt to decrypt secret using Rust Crypto")]
    DecryptSecretMissingSaltError,
    #[error("cannot find secret to decrypt using Rust Crypto")]
    DecryptSecretMissingSecretError,
}

#[derive(Clone, Debug)]
pub struct IoConnector<P> {
    session_path: P,
    shared_key: Option<AesKey>,
}

impl<P> Default for IoConnector<P>
where
    P: Default,
{
    fn default() -> Self {
        Self {
            session_path: Default::default(),
            shared_key: None,
        }
    }
}

impl<P> IoConnector<P> {
    pub fn new(session: &mut Session<P>) -> Result<Self, Error>
    where
        P: Default + Clone,
    {
        let mut connector = Self::default();
        connector.session_path = session.path.clone();

        if let Algorithm::Dh(keypair) = &session.encryption {
            let privkey = &keypair.private;
            let pubkey = session.output.take().ok_or(Error::FindPubkeyError)?;
            let shared_key =
                derive_shared(privkey, &pubkey).map_err(Error::DeriveSharedKeyError)?;

            connector.shared_key.replace(shared_key);
        };

        Ok(connector)
    }

    pub fn encrypt<F>(&mut self, flow: &mut F) -> Result<(), Error>
    where
        F: TakeSecret + PutSecret + PutSalt,
    {
        let secret = flow
            .take_secret()
            .ok_or(Error::EncryptSecretMissingSecretError)?;
        let secret = secret.expose_secret();
        let key = self.shared_key.ok_or(Error::EncryptSecretMissingKeyError)?;

        let (secret, salt) = encrypt(secret, &key);
        flow.put_secret(secret.into());
        flow.put_salt(salt);

        Ok(())
    }

    pub fn decrypt<F>(&mut self, flow: &mut F) -> Result<(), Error>
    where
        F: TakeSecret + PutSecret + TakeSalt,
    {
        let secret = flow
            .take_secret()
            .ok_or(Error::DecryptSecretMissingSecretError)?;
        let secret = secret.expose_secret();
        let key = self.shared_key.ok_or(Error::DecryptSecretMissingKeyError)?;
        let salt = flow
            .take_salt()
            .ok_or(Error::DecryptSecretMissingSaltError)?;

        let secret = decrypt(secret, &key, &salt).map_err(Error::DecryptSecretError)?;
        flow.put_secret(secret.into());

        Ok(())
    }
}

fn encrypt(data: &[u8], key: &AesKey) -> (Vec<u8>, Vec<u8>) {
    // create the salt for the encryption
    let mut aes_iv = [0; 16];
    OsRng.fill(&mut aes_iv);
    let salt = aes_iv.to_vec();

    // convert key and salt to input parameter form
    let key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(&aes_iv);
    let encryptor = Encryptor::<aes::Aes128>::new(key, iv);
    let encrypted_data = encryptor.encrypt_padded_vec_mut::<Pkcs7>(data);

    (encrypted_data, salt)
}

fn decrypt(encrypted_data: &[u8], key: &AesKey, iv: &[u8]) -> Result<Vec<u8>, UnpadError> {
    let key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(iv);
    let decryptor: Decryptor<aes::Aes128> = Decryptor::new(key, iv);
    decryptor.decrypt_padded_vec_mut::<Pkcs7>(encrypted_data)
}

fn hkdf(ikm: Vec<u8>, salt: Option<&[u8]>, okm: &mut [u8]) -> Result<(), InvalidLength> {
    let (_, hk) = Hkdf::<Sha256>::extract(salt, &ikm);
    hk.expand(&[], okm)
}

fn derive_shared(privkey: &BigUint, pubkey: &[u8]) -> Result<AesKey, InvalidLength> {
    let (ikm, mut okm) = prepare_derive_shared(privkey, pubkey);
    hkdf(ikm, None, &mut okm)?;
    Ok(okm)
}
