// ─────────────────────────────────────────────────────────────
// Identity key management — generation, encryption, storage
// ─────────────────────────────────────────────────────────────

use anyhow::{Context, Result};
use argon2::{Argon2, password_hash::SaltString};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroize;

/// Full identity bundle for a user
#[derive(Serialize, Deserialize, Clone)]
pub struct Identity {
    /// Ed25519 signing key (identity key)
    pub signing_key_bytes: Vec<u8>,
    /// X25519 static secret for signed prekey
    pub signed_prekey_secret: Vec<u8>,
    /// One-time prekey secrets
    pub one_time_prekey_secrets: Vec<Vec<u8>>,
    /// Next OTP key index
    pub next_otpk_index: u32,
}

impl Identity {
    /// Generate a fresh identity with N one-time prekeys
    pub fn generate(num_otpks: u32) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);

        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);

        let mut otpk_secrets = Vec::with_capacity(num_otpks as usize);
        for _ in 0..num_otpks {
            let secret = StaticSecret::random_from_rng(&mut OsRng);
            otpk_secrets.push(secret.to_bytes().to_vec());
        }

        Identity {
            signing_key_bytes: signing_key.to_bytes().to_vec(),
            signed_prekey_secret: spk_secret.to_bytes().to_vec(),
            one_time_prekey_secrets: otpk_secrets,
            next_otpk_index: num_otpks,
        }
    }

    /// Get the Ed25519 signing key
    pub fn signing_key(&self) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.signing_key_bytes);
        SigningKey::from_bytes(&bytes)
    }

    /// Get the Ed25519 verifying (public identity) key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key().verifying_key()
    }

    /// Get the identity public key bytes
    pub fn identity_public_key(&self) -> Vec<u8> {
        self.verifying_key().to_bytes().to_vec()
    }

    /// Get X25519 signed prekey secret
    pub fn spk_secret(&self) -> StaticSecret {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.signed_prekey_secret);
        StaticSecret::from(bytes)
    }

    /// Get X25519 signed prekey public
    pub fn spk_public(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.spk_secret())
    }

    /// Sign the signed prekey with the identity key
    pub fn sign_spk(&self) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let sig = self.signing_key().sign(self.spk_public().as_bytes());
        sig.to_bytes().to_vec()
    }

    /// Get all one-time prekey public keys
    pub fn otpk_publics(&self) -> Vec<Vec<u8>> {
        self.one_time_prekey_secrets
            .iter()
            .map(|s| {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(s);
                let secret = StaticSecret::from(bytes);
                let public = X25519PublicKey::from(&secret);
                public.as_bytes().to_vec()
            })
            .collect()
    }

    /// Generate more one-time prekeys
    pub fn generate_more_otpks(&mut self, count: u32) -> Vec<Vec<u8>> {
        let mut new_publics = Vec::new();
        for _ in 0..count {
            let secret = StaticSecret::random_from_rng(&mut OsRng);
            new_publics.push(X25519PublicKey::from(&secret).as_bytes().to_vec());
            self.one_time_prekey_secrets.push(secret.to_bytes().to_vec());
            self.next_otpk_index += 1;
        }
        new_publics
    }

    /// Get the OTP secret at a given index
    pub fn otpk_secret_at(&self, index: u32) -> Option<StaticSecret> {
        let idx = index as usize;
        if idx < self.one_time_prekey_secrets.len() {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&self.one_time_prekey_secrets[idx]);
            Some(StaticSecret::from(bytes))
        } else {
            None
        }
    }

    /// Encrypt identity to disk using password-derived key
    pub fn encrypt_to_bytes(&self, password: &str) -> Result<Vec<u8>> {
        let plaintext = bincode::serialize(self).context("serialize identity")?;
        let encrypted = encrypt_blob(password, &plaintext)?;
        Ok(encrypted)
    }

    /// Decrypt identity from disk
    pub fn decrypt_from_bytes(password: &str, data: &[u8]) -> Result<Self> {
        let plaintext = decrypt_blob(password, data)?;
        let identity: Identity = bincode::deserialize(&plaintext).context("deserialize identity")?;
        Ok(identity)
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.signing_key_bytes.zeroize();
        self.signed_prekey_secret.zeroize();
        for s in &mut self.one_time_prekey_secrets {
            s.zeroize();
        }
    }
}

/// Derive an encryption key from a password using Argon2id
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let argon2 = Argon2::default();
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 error: {}", e))?;
    Ok(key)
}

/// Encrypt a blob: [salt: 16][nonce: 24][ciphertext...]
pub fn encrypt_blob(password: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let salt = SaltString::generate(&mut OsRng);
    let salt_bytes = salt.as_str().as_bytes();

    // Use first 16 bytes of salt string
    let mut salt16 = [0u8; 16];
    let copy_len = salt_bytes.len().min(16);
    salt16[..copy_len].copy_from_slice(&salt_bytes[..copy_len]);

    let key = derive_key(password, &salt16)?;
    let cipher = XChaCha20Poly1305::new((&key).into());

    let mut nonce_bytes = [0u8; 24];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let mut output = Vec::with_capacity(16 + 24 + ciphertext.len());
    output.extend_from_slice(&salt16);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt a blob produced by encrypt_blob
pub fn decrypt_blob(password: &str, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 40 {
        anyhow::bail!("Encrypted data too short");
    }

    let salt = &data[..16];
    let nonce_bytes = &data[16..40];
    let ciphertext = &data[40..];

    let key = derive_key(password, salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce = XNonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed — wrong password or corrupt data"))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_roundtrip() {
        let id = Identity::generate(10);
        let enc = id.encrypt_to_bytes("testpass").unwrap();
        let dec = Identity::decrypt_from_bytes("testpass", &enc).unwrap();
        assert_eq!(id.identity_public_key(), dec.identity_public_key());
    }

    #[test]
    fn test_wrong_password() {
        let id = Identity::generate(5);
        let enc = id.encrypt_to_bytes("correct").unwrap();
        assert!(Identity::decrypt_from_bytes("wrong", &enc).is_err());
    }

    #[test]
    fn test_blob_encrypt_decrypt() {
        let data = b"sensitive data here";
        let enc = encrypt_blob("password123", data).unwrap();
        let dec = decrypt_blob("password123", &enc).unwrap();
        assert_eq!(dec, data);
    }
}
