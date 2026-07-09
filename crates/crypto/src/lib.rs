// ─────────────────────────────────────────────────────────────
// zerosum-crypto — all cryptographic operations
// ─────────────────────────────────────────────────────────────
// Pure Rust. No C FFI. No libsignal-protocol-c.
// Implements X3DH key agreement + Double Ratchet (simplified Signal).

pub mod identity;
pub mod x3dh;
pub mod ratchet;
pub mod store;
pub mod encrypt;
pub mod fingerprint;

pub use identity::*;
pub use encrypt::*;
pub use fingerprint::*;
