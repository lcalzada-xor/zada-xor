use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit,
    aead::{Aead, AeadCore},
};
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
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|_| "Encryption failed: auth tag generation error")?;

        let mut final_payload = nonce.to_vec();
        final_payload.extend_from_slice(&ciphertext);

        Ok(final_payload)
    }
    pub fn decipher(&self, ciphered_data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphered_data.len() < 12 {
            //almenos validar si el nonce esta
            return Err("Decryption failed: payload is too short to contain a valid nonce");
        }

        let (nonce_bytes, ciphertext) = ciphered_data.split_at(12); //separar nonce

        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes); //castear a el tipo Nonce

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key)); //creamos el tipo con la clave de descifrado asociada

        let plaintext = cipher //desciframos con los respectivos tipos
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed: data corruption, wrong key, or tampered payload")?;

        Ok(plaintext)
    }
}
