// ─────────────────────────────────────────────────────────────
// Double Ratchet — simplified Signal-style message ratchet
// ─────────────────────────────────────────────────────────────
// Provides forward secrecy per-message.

use anyhow::Result;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[allow(dead_code)]
const RATCHET_INFO: &[u8] = b"ZeroSum_Ratchet";

/// A symmetric ratchet state for one direction of communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetState {
    /// Current chain key (32 bytes)
    chain_key: Vec<u8>,
    /// Message counter
    pub counter: u32,
}

impl RatchetState {
    /// Initialize from a shared secret
    pub fn from_shared_secret(secret: &[u8; 32], is_initiator: bool) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, secret);
        let info = if is_initiator {
            b"ZeroSum_SendChain"
        } else {
            b"ZeroSum_RecvChain"
        };
        let mut chain_key = vec![0u8; 32];
        hkdf.expand(info.as_slice(), &mut chain_key)
            .expect("HKDF expand failed");
        RatchetState {
            chain_key,
            counter: 0,
        }
    }

    /// Derive the next message key and advance the chain
    pub fn next_message_key(&mut self) -> Result<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(None, &self.chain_key);

        // Derive message key
        let mut message_key = [0u8; 32];
        hkdf.expand(b"ZeroSum_MsgKey", &mut message_key)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed for message key"))?;

        // Advance chain key
        let mut new_chain_key = vec![0u8; 32];
        hkdf.expand(b"ZeroSum_ChainKey", &mut new_chain_key)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed for chain key"))?;

        self.chain_key = new_chain_key;
        self.counter += 1;

        Ok(message_key)
    }
}

/// Session ratchet combining send and receive chains
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRatchet {
    pub send_chain: RatchetState,
    pub recv_chain: RatchetState,
    pub established: bool,
}

impl SessionRatchet {
    /// Create a new session from an X3DH shared secret
    pub fn new(shared_secret: &[u8; 32], is_initiator: bool) -> Self {
        SessionRatchet {
            send_chain: RatchetState::from_shared_secret(shared_secret, is_initiator),
            recv_chain: RatchetState::from_shared_secret(shared_secret, !is_initiator),
            established: true,
        }
    }

    /// Encrypt a message using the send ratchet
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let message_key = self.send_chain.next_message_key()?;
        let cipher = XChaCha20Poly1305::new((&message_key).into());

        let mut nonce_bytes = [0u8; 24];
        rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| anyhow::anyhow!("Ratchet encryption failed"))?;

        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    /// Decrypt a message using the receive ratchet
    pub fn decrypt(&mut self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        let message_key = self.recv_chain.next_message_key()?;
        let cipher = XChaCha20Poly1305::new((&message_key).into());

        if nonce.len() != 24 {
            anyhow::bail!("Invalid nonce length");
        }
        let xnonce = XNonce::from_slice(nonce);

        let plaintext = cipher
            .decrypt(xnonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("Ratchet decryption failed — session may be out of sync"))?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_encrypt_decrypt() {
        let shared_secret = [42u8; 32];

        let mut alice = SessionRatchet::new(&shared_secret, true);
        let mut bob = SessionRatchet::new(&shared_secret, false);

        let message = b"hello from alice";
        let (ct, nonce) = alice.encrypt(message).unwrap();
        let pt = bob.decrypt(&ct, &nonce).unwrap();
        assert_eq!(pt, message);

        let message2 = b"hello from bob";
        let (ct2, nonce2) = bob.encrypt(message2).unwrap();
        let pt2 = alice.decrypt(&ct2, &nonce2).unwrap();
        assert_eq!(pt2, message2);
    }

    #[test]
    fn test_ratchet_forward_secrecy() {
        let shared_secret = [42u8; 32];
        let mut alice = SessionRatchet::new(&shared_secret, true);
        let mut bob = SessionRatchet::new(&shared_secret, false);

        // Send multiple messages, each with unique key
        let (ct1, n1) = alice.encrypt(b"msg1").unwrap();
        let (ct2, n2) = alice.encrypt(b"msg2").unwrap();

        let p1 = bob.decrypt(&ct1, &n1).unwrap();
        let p2 = bob.decrypt(&ct2, &n2).unwrap();

        assert_eq!(p1, b"msg1");
        assert_eq!(p2, b"msg2");
    }
}
