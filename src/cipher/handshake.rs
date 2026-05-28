use super::keys::SymetricKey;
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

//el cliente sabe pub key del server pero el server no sabe la pub key del cliente, por lo tanto el cliente debe enviar su pub key temporal junto a su pub key real cifrada
pub struct SecureClientHandshakePacket {
    // este tipo de paquete esta hecho para ser enviado a traves de la red
    pub client_ephemeral_public_key: [u8; 32],
    pub client_ciphered_pub_key: Vec<u8>, //el server utilizara la ephemeral_pub_key para descifrar la pub_key del cliente de forma segura
}

impl SecureClientHandshakePacket {
    pub fn new(server_pub_key: [u8; 32], client_pub_key: [u8; 32]) -> (Self, SymetricKey) {
        let server_public = PublicKey::from(server_pub_key);

        let client_ephemeral_secret = EphemeralSecret::random_from_rng(OsRng); // generamos una identidad temporal al cliente
        let client_ephemeral_public = PublicKey::from(&client_ephemeral_secret);

        let symmetric_key = SymetricKey::from_key_exchange(client_ephemeral_secret, &server_public); //generamos un secreto compartido (key final)

        let ciphered_client_pub = symmetric_key // ciframos la llave publica real del cliente (identidad real no temp) para ser compartida de manera segura
            .cipher(&client_pub_key)
            .expect("Error al cifrar la identidad del cliente");

        (
            Self {
                client_ephemeral_public_key: client_ephemeral_public.to_bytes(),
                client_ciphered_pub_key: ciphered_client_pub,
            },
            symmetric_key,
        )
    }
    pub fn process_packet(
        //logica de procesado del secureclienthandshakepacket por el servidor
        &self,
        server_priv_key: &StaticSecret,
    ) -> Result<(SymetricKey, PublicKey), String> {
        let client_ephemeral_public = PublicKey::from(self.client_ephemeral_public_key); //casteamos la llave publica efimera del cliente para poder operar con ella

        let shared_secret = server_priv_key.diffie_hellman(&client_ephemeral_public);

        let symmetric_key = SymetricKey {
            key: shared_secret.to_bytes(),
        };

        // se usa la clave simetrica temporal generada para descifrar la llave publica real del cliente (identidad real no temp)
        let decrypted_client_pub_bytes = symmetric_key
            .decipher(&self.client_ciphered_pub_key)
            .map_err(|e| format!("Handshake decryption failed: {}", e))?;

        //casteamos los bytes descifrados de la llave publica a un array estatico de 32 bytes
        let client_real_pub_key_bytes: [u8; 32] =
            decrypted_client_pub_bytes.try_into().map_err(|_| {
                "Invalid payload: decrypted client public key is not exactly 32 bytes".to_string()
            })?;

        let client_real_pub_key = PublicKey::from(client_real_pub_key_bytes);

        // se retorna la llave publica real del cliente y la llave simetrica para cifrar y descifrar la comunicacion entre cliente y servidor
        Ok((symmetric_key, client_real_pub_key))
    }
}
