// ─────────────────────────────────────────────────────────────
// General-purpose encryption helpers
// ─────────────────────────────────────────────────────────────

use anyhow::Result;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::rngs::OsRng;

/// Encrypt data with a 32-byte key, returning (ciphertext, nonce)
pub fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 24])> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 24];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt data with a 32-byte key
pub fn decrypt_with_key(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8; 24]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(xnonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

    Ok(plaintext)
}

/// Hash a password for authentication (not for key derivation)
pub fn hash_password(password: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ZeroSum_PasswordHash_");
    hasher.update(password.as_bytes());
    hasher.finalize().to_vec()
}
