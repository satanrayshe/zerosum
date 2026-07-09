// ─────────────────────────────────────────────────────────────
// Safety Number / Key Fingerprint Verification
// ─────────────────────────────────────────────────────────────
// Fixes the missing MITM detection from the original.
// Matches Signal's safety number format: 12 groups of 5 digits.

use sha2::{Digest, Sha256};

/// Generate a safety number for a pair of identity keys.
/// Format: 12 groups of 5 digits (60 digits total), matching Signal.
pub fn safety_number(our_identity_key: &[u8], their_identity_key: &[u8]) -> String {
    // Canonical ordering: lower key first
    let (first, second) = if our_identity_key < their_identity_key {
        (our_identity_key, their_identity_key)
    } else {
        (their_identity_key, our_identity_key)
    };

    let mut hasher = Sha256::new();
    hasher.update(b"ZeroSum_SafetyNumber_v1_");
    hasher.update(first);
    hasher.update(second);
    let hash = hasher.finalize();

    // Convert hash bytes to 60 decimal digits (12 groups × 5 digits)
    // We iterate through pairs of bytes, converting each pair to a 5-digit number
    let mut digits = String::with_capacity(72); // 60 digits + 11 spaces
    for (i, chunk) in hash.chunks(2).enumerate().take(12) {
        if i > 0 {
            digits.push(' ');
        }
        // 2 bytes → 0..65535, mod 100000 to get 5 digits
        let val = if chunk.len() == 2 {
            ((chunk[0] as u32) << 8 | chunk[1] as u32) % 100000
        } else {
            (chunk[0] as u32) % 100000
        };
        digits.push_str(&format!("{:05}", val));
    }

    // Pad to 12 groups if needed (SHA256 = 32 bytes = 16 pairs, we take 12)
    digits
}

/// Format a public key as a hex fingerprint for display
pub fn hex_fingerprint(key: &[u8]) -> String {
    key.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| c.join(""))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_number_symmetric() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];

        let sn1 = safety_number(&key_a, &key_b);
        let sn2 = safety_number(&key_b, &key_a);

        // Must be identical regardless of order
        assert_eq!(sn1, sn2);

        // Must be 12 groups of 5 digits
        let groups: Vec<&str> = sn1.split(' ').collect();
        assert_eq!(groups.len(), 12);
        for g in groups {
            assert_eq!(g.len(), 5);
            assert!(g.chars().all(|c| c.is_ascii_digit()));
        }
    }
}
