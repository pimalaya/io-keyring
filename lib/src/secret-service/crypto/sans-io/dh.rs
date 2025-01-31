use std::ops::{Mul, Rem, Shr};

use num::{
    integer::Integer,
    traits::{One, Zero},
    BigUint, FromPrimitive,
};
use once_cell::sync::Lazy;
use rand::{rngs::OsRng, Rng};

static DH_GENERATOR: Lazy<BigUint> = Lazy::new(|| BigUint::from_u64(0x2).unwrap());
static DH_PRIME: Lazy<BigUint> = Lazy::new(|| {
    BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2,
        0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67,
        0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E,
        0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5,
        0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF,
        0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE,
        0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ])
});

pub type AesKey = [u8; 16];

#[derive(Clone)]
pub struct Keypair {
    pub private: BigUint,
    pub public: BigUint,
}

impl Keypair {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut privkey = [0; 128];
        rng.fill(&mut privkey);

        let privkey = BigUint::from_bytes_be(&privkey);
        let pubkey = pow_base_exp_mod(&DH_GENERATOR, &privkey, &DH_PRIME);

        Self {
            private: privkey,
            public: pubkey,
        }
    }
}

pub fn prepare_derive_shared(privkey: &BigUint, pubkey: &[u8]) -> (Vec<u8>, [u8; 16]) {
    // Derive the shared secret the server and us.
    let pubkey = BigUint::from_bytes_be(pubkey);
    let common_secret = pow_base_exp_mod(&pubkey, privkey, &DH_PRIME);

    let common_secret_bytes = common_secret.to_bytes_be();
    let mut common_secret_padded = vec![0; 128 - common_secret_bytes.len()];
    common_secret_padded.extend(common_secret_bytes);

    // keyring material ready for HKDF
    (common_secret_padded, [0; 16])
}

/// From <https://github.com/plietar/librespot/blob/master/core/src/util/mod.rs>
pub fn pow_base_exp_mod(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    let mut base = base.clone();
    let mut exp = exp.clone();
    let mut result: BigUint = One::one();

    while !exp.is_zero() {
        if exp.is_odd() {
            result = result.mul(&base).rem(modulus);
        }
        exp = exp.shr(1);
        base = (&base).mul(&base).rem(modulus);
    }

    result
}
