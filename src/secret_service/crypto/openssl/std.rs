use num::BigUint;
use openssl::{
    cipher::Cipher, cipher_ctx::CipherCtx, error::ErrorStack, md::Md, pkey::Id, pkey_ctx::PkeyCtx,
};
use rand::{rngs::OsRng, Rng};
use secrecy::ExposeSecret;

use crate::secret_service::{
    crypto::{
        algorithm::Algorithm,
        common::{prepare_derive_shared, AesKey},
        Error, Flow,
    },
    Session,
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
                derive_shared(privkey, &pubkey).map_err(Error::DeriveSharedKeyOpensslError)?;

            connector.shared_key.replace(shared_key);
        };

        Ok(connector)
    }

    pub fn encrypt(&mut self, flow: &mut impl Flow) -> Result<(), Error> {
        let secret = flow
            .take_secret()
            .ok_or(Error::EncryptUndefinedSecretError)?;
        let secret = secret.expose_secret();
        let key = &self.shared_key.unwrap();

        let (secret, salt) = encrypt(secret, key).map_err(Error::EncryptSecretOpensslError)?;
        flow.give_secret(secret.into());
        flow.give_salt(salt);

        Ok(())
    }

    pub fn decrypt(&mut self, flow: &mut impl Flow) -> Result<(), Error> {
        let secret = flow
            .take_secret()
            .ok_or(Error::DecryptUndefinedSecretError)?;
        let secret = secret.expose_secret();
        let salt = flow.take_salt().unwrap_or_default();
        let key = &self.shared_key.unwrap();

        let secret = decrypt(secret, key, &salt).map_err(Error::DecryptSecretOpensslError)?;
        flow.give_secret(secret.into());

        Ok(())
    }
}

fn encrypt(data: &[u8], key: &AesKey) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
    // create the salt for the encryption
    let mut aes_iv = [0u8; 16];
    OsRng.fill(&mut aes_iv);

    let mut ctx = CipherCtx::new()?;
    ctx.encrypt_init(Some(Cipher::aes_128_cbc()), Some(key), Some(&aes_iv))?;

    let mut output = vec![];
    ctx.cipher_update_vec(data, &mut output)?;
    ctx.cipher_final_vec(&mut output)?;

    Ok((output, aes_iv.to_vec()))
}

fn decrypt(encrypted_data: &[u8], key: &AesKey, iv: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let mut ctx = CipherCtx::new()?;
    ctx.decrypt_init(Some(Cipher::aes_128_cbc()), Some(key), Some(iv))?;

    let mut output = vec![];
    ctx.cipher_update_vec(encrypted_data, &mut output)?;
    ctx.cipher_final_vec(&mut output)?;
    Ok(output)
}

fn hkdf(ikm: Vec<u8>, salt: Option<&[u8]>, okm: &mut [u8]) -> Result<(), ErrorStack> {
    let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_md(Md::sha256())?;
    ctx.set_hkdf_key(&ikm)?;

    if let Some(salt) = salt {
        ctx.set_hkdf_salt(salt)?;
    }

    ctx.add_hkdf_info(&[]).unwrap();
    ctx.derive(Some(okm))?;

    Ok(())
}

fn derive_shared(privkey: &BigUint, pubkey: &[u8]) -> Result<AesKey, ErrorStack> {
    let (ikm, mut okm) = prepare_derive_shared(privkey, pubkey);
    hkdf(ikm, None, &mut okm)?;
    Ok(okm)
}
