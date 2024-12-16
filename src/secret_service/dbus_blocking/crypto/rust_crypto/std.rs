use aes::cipher::{
    block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use block_padding::UnpadError;
use cbc::{Decryptor, Encryptor};
use dbus::{
    arg::{cast, RefArg, Variant},
    blocking::Connection,
    Path,
};
use hkdf::{Hkdf, InvalidLength};
use rand::{rngs::OsRng, Rng};
use secrecy::ExposeSecret;
use sha2::Sha256;

use crate::secret_service::dbus_blocking::{
    self,
    api::OrgFreedesktopSecretService,
    crypto::{
        algorithm::Algorithm,
        common::{prepare_derive_shared, AesKey, Keypair},
        Error, Flow,
    },
    DBUS_DEST, DBUS_PATH, TIMEOUT,
};

pub struct IoConnector {
    pub encryption: Algorithm,
    pub session_path: Path<'static>,
    shared_key: Option<AesKey>,
}

impl IoConnector {
    pub fn new(connection: &Connection, encryption: Algorithm) -> dbus_blocking::std::Result<Self> {
        let proxy = connection.with_proxy(DBUS_DEST, DBUS_PATH, TIMEOUT);
        let processor = match encryption {
            Algorithm::Plain => {
                let (_, session_path) = proxy
                    .open_session(encryption.as_ref(), Variant(Box::new(String::new())))
                    .map_err(dbus_blocking::std::Error::OpenSessionError)?;

                Self {
                    encryption,
                    session_path,
                    shared_key: None,
                }
            }
            Algorithm::Dh => {
                let keypair = Keypair::generate();

                // send our public key with algorithm to service
                let public_bytes = keypair.public.to_bytes_be();
                let bytes_arg = Variant(Box::new(public_bytes) as Box<dyn RefArg>);
                let (out, session_path) = proxy
                    .open_session(encryption.as_ref(), bytes_arg)
                    .map_err(dbus_blocking::std::Error::OpenSessionError)?;

                let Some(server_public_key_bytes) = cast::<Vec<u8>>(&out.0) else {
                    return Err(dbus_blocking::std::Error::CastServerPublicKeyToBytesError);
                };

                let shared_key = derive_shared(&keypair, server_public_key_bytes)
                    .map_err(Error::DeriveSharedKeyRustCryptoError)?;

                Self {
                    encryption,
                    session_path,
                    shared_key: Some(shared_key),
                }
            }
        };

        Ok(processor)
    }

    pub fn encrypt(&mut self, flow: &mut impl Flow) -> Result<(), Error> {
        let secret = flow
            .take_secret()
            .ok_or(Error::EncryptUndefinedSecretError)?;
        let secret = secret.expose_secret();
        let key = self.shared_key.ok_or(Error::EncryptSecretMissingKeyError)?;

        let (secret, salt) = encrypt(secret, &key);
        flow.give_secret(secret.into());
        flow.give_salt(salt);

        Ok(())
    }

    pub fn decrypt(&mut self, flow: &mut impl Flow) -> Result<(), Error> {
        let secret = flow
            .take_secret()
            .ok_or(Error::DecryptUndefinedSecretError)?;
        let secret = secret.expose_secret();
        let key = self.shared_key.ok_or(Error::DecryptSecretMissingKeyError)?;
        let salt = flow.take_salt().unwrap_or_default();

        let secret = decrypt(secret, &key, &salt).map_err(Error::DecryptSecretRustCryptoError)?;
        flow.give_secret(secret.into());

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

fn derive_shared(
    keypair: &Keypair,
    server_public_key_bytes: &[u8],
) -> Result<AesKey, InvalidLength> {
    let (ikm, mut okm) = prepare_derive_shared(keypair, server_public_key_bytes);
    hkdf(ikm, None, &mut okm)?;
    Ok(okm)
}
