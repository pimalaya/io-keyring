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

use crate::{
    secret_service::{
        crypto::{
            common::{prepare_derive_shared, AesKey},
            Algorithm, Error, PutSalt, TakeSalt,
        },
        Session,
    },
    PutSecret, TakeSecret,
};

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

        if let Algorithm::Dh = session.encryption() {
            let pubkey = session.take_output().ok_or(Error::FindPubkeyError)?;
            let privkey = session.privkey().ok_or(Error::FindPrivkeyError)?;
            let shared_key =
                derive_shared(privkey, &pubkey).map_err(Error::DeriveSharedKeyRustCryptoError)?;

            connector.shared_key.replace(shared_key);
        };

        Ok(connector)
    }

    pub fn encrypt<F: TakeSecret + PutSecret + PutSalt>(
        &mut self,
        flow: &mut F,
    ) -> Result<(), Error> {
        let secret = flow
            .take_secret()
            .ok_or(Error::EncryptUndefinedSecretError)?;
        let secret = secret.expose_secret();
        let key = self.shared_key.ok_or(Error::EncryptSecretMissingKeyError)?;

        let (secret, salt) = encrypt(secret, &key);
        flow.put_secret(secret.into());
        flow.put_salt(salt);

        Ok(())
    }

    pub fn decrypt<F: TakeSecret + PutSecret + TakeSalt>(
        &mut self,
        flow: &mut F,
    ) -> Result<(), Error> {
        let secret = flow
            .take_secret()
            .ok_or(Error::DecryptUndefinedSecretError)?;
        let secret = secret.expose_secret();
        let key = self.shared_key.ok_or(Error::DecryptSecretMissingKeyError)?;
        let salt = flow.take_salt().unwrap_or_default();

        let secret = decrypt(secret, &key, &salt).map_err(Error::DecryptSecretRustCryptoError)?;
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
