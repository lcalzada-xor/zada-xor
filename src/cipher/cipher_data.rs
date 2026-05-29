// implemento cifrado y descifrado con chacha20 de payloads por salirme un poco del tipico xor

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::OsRng;

pub struct CipherData<'a> {
    pub data: &'a [u8], // se mete 'a por que va a ser el dato que se devuelve (colision de return)
    pub key: [u8; 32],
}

impl<'a> CipherData<'a> {
    pub fn cipher(self) -> Result<Vec<u8>, &'static str> {
        // el paquete CipherData se consume al cifrar
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, self.data)
            .map_err(|_| "Encryption failed: auth tag generation error")?;

        let mut ciphered_payload = Vec::with_capacity(nonce.len() + ciphertext.len());
        ciphered_payload.extend_from_slice(&nonce);
        ciphered_payload.extend_from_slice(&ciphertext);

        Ok(ciphered_payload)
    }

    pub fn decipher(self) -> Result<Vec<u8>, &'static str> {
        //el paquete CipherData se consume al descifrar
        if self.data.len() < 12 {
            return Err("Decryption failed: payload is too short to contain a valid nonce");
        }

        let (nonce_bytes, ciphertext) = self.data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed: data corruption, wrong key, or tampered payload")?;

        Ok(plaintext)
    }
}
