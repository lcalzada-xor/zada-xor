use super::cipher_data::*;
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

pub struct Identity {
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
}

impl Identity {
    pub fn new() -> Self {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }
}

pub struct SymetricKey {
    pub key: [u8; 32],
}

impl SymetricKey {
    pub fn from_key_exchange(my_secret: EphemeralSecret, their_public: &PublicKey) -> Self {
        let shared_secret = my_secret.diffie_hellman(their_public);

        Self {
            key: shared_secret.to_bytes(),
        }
    }
    pub fn cipher(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let cipher_data = CipherData {
            data,
            key: self.key,
        };
        cipher_data.cipher()
    }
    pub fn decipher(&self, ciphered_data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let cipher_data = CipherData {
            data: ciphered_data,
            key: self.key,
        };
        cipher_data.decipher()
    }
}
