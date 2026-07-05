// ─────────────────────────────────────────────────────────────
// zerosum-tor — embedded Tor runtime (no external tor process)
// ─────────────────────────────────────────────────────────────
// Uses Arti (Tor's official Rust implementation) to:
//   1. Run an onion hidden service for the server
//   2. Connect as a SOCKS client for the client
// No separate `tor` binary needed. No ngrok. Single binary.

pub mod embedded;
pub mod client;

pub use embedded::*;
pub use client::*;
