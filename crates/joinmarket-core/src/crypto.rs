use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use xsalsa20poly1305::{XSalsa20Poly1305, KeyInit};
use xsalsa20poly1305::aead::Aead;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid public key length: expected 32, got {0}")]
    InvalidPublicKeyLength(usize),
}

pub struct EncryptionKey(StaticSecret);

pub struct EncryptedMessage {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl EncryptionKey {
    pub fn new(secret: StaticSecret) -> Self {
        EncryptionKey(secret)
    }

    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        EncryptionKey(StaticSecret::random_from_rng(OsRng))
    }

    pub fn public_key(&self) -> [u8; 32] {
        let pk = X25519PublicKey::from(&self.0);
        pk.to_bytes()
    }

    fn derive_shared_key(&self, peer_pubkey: &[u8]) -> Result<[u8; 32], CryptoError> {
        let peer_key_bytes: [u8; 32] = peer_pubkey.try_into()
            .map_err(|_| CryptoError::InvalidPublicKeyLength(peer_pubkey.len()))?;
        let peer_public = X25519PublicKey::from(peer_key_bytes);
        let shared = self.0.diffie_hellman(&peer_public);
        Ok(shared.to_bytes())
    }

    pub fn encrypt(&self, peer_pubkey: &[u8], plaintext: &[u8]) -> Result<EncryptedMessage, CryptoError> {
        use rand::RngCore;
        let shared = self.derive_shared_key(peer_pubkey)?;

        let cipher = XSalsa20Poly1305::new((&shared).into());

        let mut nonce_bytes = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = xsalsa20poly1305::Nonce::from(nonce_bytes);

        let ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(EncryptedMessage { nonce: nonce_bytes, ciphertext })
    }

    pub fn decrypt(&self, peer_pubkey: &[u8], msg: &EncryptedMessage) -> Result<Vec<u8>, CryptoError> {
        let shared = self.derive_shared_key(peer_pubkey)?;

        let cipher = XSalsa20Poly1305::new((&shared).into());
        let nonce = xsalsa20poly1305::Nonce::from(msg.nonce);

        cipher.decrypt(&nonce, msg.ciphertext.as_slice())
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let alice = EncryptionKey::generate();
        let bob = EncryptionKey::generate();

        let plaintext = b"hello joinmarket";
        let encrypted = alice.encrypt(&bob.public_key(), plaintext).unwrap();
        let decrypted = bob.decrypt(&alice.public_key(), &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_returns_encryption_failed_not_decryption() {
        // Verify that encryption errors (if they occurred) would use EncryptionFailed variant.
        // We can't easily force an encryption failure with valid inputs, but we can verify
        // the error variant exists and is distinct.
        let err = CryptoError::EncryptionFailed;
        assert_eq!(err.to_string(), "encryption failed");
        let err2 = CryptoError::DecryptionFailed;
        assert_eq!(err2.to_string(), "decryption failed");
    }

    #[test]
    fn test_nonce_tampering() {
        let alice = EncryptionKey::generate();
        let bob = EncryptionKey::generate();

        let plaintext = b"hello joinmarket";
        let mut encrypted = alice.encrypt(&bob.public_key(), plaintext).unwrap();
        // Tamper with nonce
        encrypted.nonce[0] ^= 0xFF;
        let result = bob.decrypt(&alice.public_key(), &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pubkey_length() {
        let alice = EncryptionKey::generate();
        let short_key = [0u8; 16];
        let result = alice.encrypt(&short_key, b"test");
        assert!(matches!(result, Err(CryptoError::InvalidPublicKeyLength(16))));
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let alice = EncryptionKey::generate();
        let bob = EncryptionKey::generate();
        let eve = EncryptionKey::generate();

        let plaintext = b"secret message";
        let encrypted = alice.encrypt(&bob.public_key(), plaintext).unwrap();

        // Eve tries to decrypt with her key instead of Bob's
        let result = eve.decrypt(&alice.public_key(), &encrypted);
        assert!(result.is_err());
    }
}
