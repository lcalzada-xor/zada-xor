use crate::cipher::keys::SymetricKey;

pub struct SecureDataPacket {
    // (Nonce 12 bytes + datos cifrados + tag de autenticación 16 bytes)
    pub payload: Vec<u8>,
}
impl SecureDataPacket {
    pub fn cipher(data: &[u8], key: &SymetricKey) -> Self {
        let payload = key.cipher(data).expect("Encryption failed");
        Self { payload }
    }
    pub fn decipher(payload: &[u8], key: &SymetricKey) -> Result<Vec<u8>, String> {
        let data = key.decipher(payload).map_err(|e| e.to_string())?;
        Ok(data)
    }
}
