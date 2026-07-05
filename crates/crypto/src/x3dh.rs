// ─────────────────────────────────────────────────────────────
// X3DH Key Agreement — Extended Triple Diffie-Hellman
// ─────────────────────────────────────────────────────────────
// Implements X3DH as specified by Signal for initial key exchange.

use anyhow::Result;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Info string for X3DH HKDF
const X3DH_INFO: &[u8] = b"ZeroSum_X3DH_SharedSecret";

/// Result of X3DH from the initiator's side
pub struct X3dhInitResult {
    /// The shared secret derived from X3DH
    pub shared_secret: [u8; 32],
    /// Ephemeral public key to send to the responder
    pub ephemeral_public: [u8; 32],
}

/// Initiator performs X3DH:
///   DH1 = DH(IK_A, SPK_B)       — identity to signed prekey
///   DH2 = DH(EK_A, IK_B)        — ephemeral to identity
///   DH3 = DH(EK_A, SPK_B)       — ephemeral to signed prekey
///   DH4 = DH(EK_A, OPK_B)       — ephemeral to one-time prekey (optional)
pub fn x3dh_initiate(
    our_identity_secret: &StaticSecret,
    their_identity_public: &[u8; 32],
    their_signed_prekey: &[u8; 32],
    their_one_time_prekey: Option<&[u8; 32]>,
) -> Result<X3dhInitResult> {
    let their_ik = PublicKey::from(*their_identity_public);
    let their_spk = PublicKey::from(*their_signed_prekey);

    // Generate ephemeral key pair
    let ephemeral_secret = StaticSecret::random_from_rng(&mut OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // DH1: our identity × their signed prekey
    let dh1 = our_identity_secret.diffie_hellman(&their_spk);
    // DH2: our ephemeral × their identity
    let dh2 = ephemeral_secret.diffie_hellman(&their_ik);
    // DH3: our ephemeral × their signed prekey
    let dh3 = ephemeral_secret.diffie_hellman(&their_spk);

    let mut ikm = Vec::with_capacity(128);
    // Prepend 32 bytes of 0xFF as per Signal spec
    ikm.extend_from_slice(&[0xFF; 32]);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    // DH4: optional one-time prekey
    if let Some(otpk) = their_one_time_prekey {
        let their_otpk = PublicKey::from(*otpk);
        let dh4 = ephemeral_secret.diffie_hellman(&their_otpk);
        ikm.extend_from_slice(dh4.as_bytes());
    }

    // KDF
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut shared_secret = [0u8; 32];
    hkdf.expand(X3DH_INFO, &mut shared_secret)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    Ok(X3dhInitResult {
        shared_secret,
        ephemeral_public: *ephemeral_public.as_bytes(),
    })
}

/// Responder performs X3DH:
///   DH1 = DH(SPK_B, IK_A)       — signed prekey to identity
///   DH2 = DH(IK_B, EK_A)        — identity to ephemeral
///   DH3 = DH(SPK_B, EK_A)       — signed prekey to ephemeral
///   DH4 = DH(OPK_B, EK_A)       — one-time prekey to ephemeral (optional)
pub fn x3dh_respond(
    our_identity_secret: &StaticSecret,
    our_signed_prekey_secret: &StaticSecret,
    our_one_time_prekey_secret: Option<&StaticSecret>,
    their_identity_public: &[u8; 32],
    their_ephemeral_public: &[u8; 32],
) -> Result<[u8; 32]> {
    let their_ik = PublicKey::from(*their_identity_public);
    let their_ek = PublicKey::from(*their_ephemeral_public);

    // DH1: our signed prekey × their identity
    let dh1 = our_signed_prekey_secret.diffie_hellman(&their_ik);
    // DH2: our identity × their ephemeral
    let dh2 = our_identity_secret.diffie_hellman(&their_ek);
    // DH3: our signed prekey × their ephemeral
    let dh3 = our_signed_prekey_secret.diffie_hellman(&their_ek);

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(&[0xFF; 32]);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    // DH4: optional one-time prekey
    if let Some(otpk_secret) = our_one_time_prekey_secret {
        let dh4 = otpk_secret.diffie_hellman(&their_ek);
        ikm.extend_from_slice(dh4.as_bytes());
    }

    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut shared_secret = [0u8; 32];
    hkdf.expand(X3DH_INFO, &mut shared_secret)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    Ok(shared_secret)
}

/// Convert an Ed25519 public key to an X25519 public key for DH
/// (used because identity keys are Ed25519 but X3DH needs X25519)
pub fn ed25519_pub_to_x25519(ed_pub: &[u8; 32]) -> [u8; 32] {
    // Use the Montgomery form conversion
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let compressed = CompressedEdwardsY(*ed_pub);
    if let Some(point) = compressed.decompress() {
        point.to_montgomery().to_bytes()
    } else {
        // Fallback: return zeros (should not happen with valid keys)
        [0u8; 32]
    }
}

/// Convert an Ed25519 secret key to an X25519 secret for DH
pub fn ed25519_secret_to_x25519(ed_secret: &[u8; 32]) -> StaticSecret {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(ed_secret);
    let hash = hasher.finalize();
    let mut x_secret = [0u8; 32];
    x_secret.copy_from_slice(&hash[..32]);
    // Clamp
    x_secret[0] &= 248;
    x_secret[31] &= 127;
    x_secret[31] |= 64;
    StaticSecret::from(x_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn test_x3dh_roundtrip() {
        let alice = Identity::generate(5);
        let bob = Identity::generate(5);

        // Convert Ed25519 identity keys to X25519 for X3DH
        let alice_x_secret = ed25519_secret_to_x25519(
            &alice.signing_key_bytes.as_slice().try_into().unwrap(),
        );
        let bob_ik_pub_bytes: [u8; 32] = bob.identity_public_key().try_into().unwrap();
        let bob_x_pub = ed25519_pub_to_x25519(&bob_ik_pub_bytes);
        let bob_spk_pub: [u8; 32] = bob.spk_public().as_bytes().clone();
        let bob_otpk_pub: [u8; 32] = bob.otpk_publics()[0].clone().try_into().unwrap();

        let init_result = x3dh_initiate(
            &alice_x_secret,
            &bob_x_pub,
            &bob_spk_pub,
            Some(&bob_otpk_pub),
        )
        .unwrap();

        // Bob responds
        let alice_ik_pub_bytes: [u8; 32] = alice.identity_public_key().try_into().unwrap();
        let alice_x_pub = ed25519_pub_to_x25519(&alice_ik_pub_bytes);
        let bob_x_secret = ed25519_secret_to_x25519(
            &bob.signing_key_bytes.as_slice().try_into().unwrap(),
        );
        let bob_otpk_secret = bob.otpk_secret_at(0).unwrap();

        let shared_secret = x3dh_respond(
            &bob_x_secret,
            &bob.spk_secret(),
            Some(&bob_otpk_secret),
            &alice_x_pub,
            &init_result.ephemeral_public,
        )
        .unwrap();

        assert_eq!(init_result.shared_secret, shared_secret);
    }
}
