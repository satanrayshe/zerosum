// ─────────────────────────────────────────────────────────────
// Identity management + encrypted identity persistence
// ─────────────────────────────────────────────────────────────

use anyhow::{Result, bail};
use argon2::Argon2;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

#[derive(Serialize, Deserialize, Clone)]
pub struct Identity {
    pub signing_key_bytes: Vec<u8>,
    spk_secret_bytes: [u8; 32],
    otpk_secret_bytes: Vec<[u8; 32]>,
}

impl Identity {
    pub fn generate(otpk_count: usize) -> Self {
        let signing = SigningKey::generate(&mut OsRng);

        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let mut spk_secret_bytes = [0u8; 32];
        spk_secret_bytes.copy_from_slice(spk_secret.as_bytes());

        let mut otpk_secret_bytes = Vec::with_capacity(otpk_count);
        for _ in 0..otpk_count {
            let secret = StaticSecret::random_from_rng(&mut OsRng);
            otpk_secret_bytes.push(*secret.as_bytes());
        }

        Self {
            signing_key_bytes: signing.to_bytes().to_vec(),
            spk_secret_bytes,
            otpk_secret_bytes,
        }
    }

    pub fn identity_public_key(&self) -> Vec<u8> {
        self.signing_key()
            .verifying_key()
            .to_bytes()
            .to_vec()
    }

    pub fn spk_secret(&self) -> StaticSecret {
        StaticSecret::from(self.spk_secret_bytes)
    }

    pub fn spk_public(&self) -> PublicKey {
        PublicKey::from(&self.spk_secret())
    }

    pub fn sign_spk(&self) -> Vec<u8> {
        self.signing_key()
            .sign(self.spk_public().as_bytes())
            .to_bytes()
            .to_vec()
    }

    pub fn otpk_publics(&self) -> Vec<Vec<u8>> {
        self.otpk_secret_bytes
            .iter()
            .map(|secret| {
                let secret = StaticSecret::from(*secret);
                PublicKey::from(&secret).as_bytes().to_vec()
            })
            .collect()
    }

    pub fn otpk_secret_at(&self, index: u32) -> Option<StaticSecret> {
        self.otpk_secret_bytes
            .get(index as usize)
            .map(|secret| StaticSecret::from(*secret))
    }

    pub fn encrypt_to_bytes(&self, password: &str) -> Result<Vec<u8>> {
        let serialized = bincode::serialize(self)?;
        encrypt_blob(password, &serialized)
    }

    pub fn decrypt_from_bytes(password: &str, data: &[u8]) -> Result<Self> {
        let decrypted = decrypt_blob(password, data)?;
        Ok(bincode::deserialize(&decrypted)?)
    }

    fn signing_key(&self) -> SigningKey {
        let signing_key_bytes: [u8; 32] = self
            .signing_key_bytes
            .as_slice()
            .try_into()
            .expect("stored identity signing key must be 32 bytes");
        SigningKey::from_bytes(&signing_key_bytes)
    }
}

pub fn encrypt_blob(password: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut salt: [u8; SALT_LEN] = rand::random();
    rand::RngCore::fill_bytes(&mut OsRng, &mut salt);
    let key = derive_key(password, &salt)?;

    let mut nonce: [u8; NONCE_LEN] = rand::random();
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce);

    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_blob(password: &str, encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < SALT_LEN + NONCE_LEN {
        bail!("Encrypted blob too short");
    }

    let (salt, rest) = encrypted.split_at(SALT_LEN);
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    let key = derive_key(password, salt)?;

    let cipher = XChaCha20Poly1305::new((&key).into());
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed"))
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {e}"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_encrypt_decrypt_roundtrip() {
        let identity = Identity::generate(8);
        let password = {
            let random_bytes: [u8; 32] = rand::random();
            String::from_utf8_lossy(&random_bytes).to_string()
        };
        let encrypted = identity.encrypt_to_bytes(&password).unwrap();
        let decrypted = Identity::decrypt_from_bytes(&password, &encrypted).unwrap();

        assert_eq!(identity.identity_public_key(), decrypted.identity_public_key());
        assert_eq!(identity.sign_spk(), decrypted.sign_spk());
        assert_eq!(identity.otpk_publics(), decrypted.otpk_publics());
    }
}
