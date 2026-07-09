// ─────────────────────────────────────────────────────────────
// zerosum-protocol — the single canonical wire format
// ─────────────────────────────────────────────────────────────
// There is ONE protocol module. No duplicates. No drift.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Wire protocol version — bump on breaking changes
pub const PROTOCOL_VERSION: u8 = 3;

/// Fixed message padding block size (traffic analysis resistance)
pub const PAD_BLOCK_SIZE: usize = 512;

#[derive(Error, Debug)]
pub enum ProtoError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] bincode::Error),
    #[error("Protocol version mismatch: got {got}, expected {expected}")]
    VersionMismatch { got: u8, expected: u8 },
    #[error("Frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: u32, max: u32 },
    #[error("Connection closed")]
    ConnectionClosed,
}

/// Maximum frame payload size: 1 MiB (for file chunks)
pub const MAX_FRAME_SIZE: u32 = 1 << 20;

// ── Message Types ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMessage {
    Hello { version: u8 },

    Register {
        username: String,
        password_hash: Vec<u8>,
        identity_public_key: Vec<u8>,
        signed_prekey: Vec<u8>,
        signed_prekey_signature: Vec<u8>,
        one_time_prekeys: Vec<Vec<u8>>,
    },

    Login {
        username: String,
        password_hash: Vec<u8>,
    },

    Heartbeat,

    /// Send a chat request to another user
    ChatRequest {
        to: String,
        /// Sender's identity public key
        identity_public_key: Vec<u8>,
        /// Sender's X3DH ephemeral public key
        ephemeral_pub: Vec<u8>,
        /// Which of the recipient's OTPs was used
        otpk_index: Option<u32>,
    },

    /// Accept a chat request — includes responder's confirmation
    ChatAccept {
        to: String,
    },

    /// Reject a chat request
    ChatReject {
        to: String,
    },

    /// Send an encrypted message (session must be established)
    SendMessage {
        to: String,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
    },

    /// Upload a file chunk
    SendFile {
        to: String,
        filename: String,
        chunk_index: u32,
        total_chunks: u32,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
    },

    /// Fetch another user's prekey bundle (used internally for chat request)
    FetchBundle { target_username: String },

    /// Replenish one-time prekeys
    RefillPrekeys {
        one_time_prekeys: Vec<Vec<u8>>,
    },

    Goodbye,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    HelloAck { version: u8, ok: bool },
    RegisterAck { ok: bool, error: Option<String> },
    LoginAck { ok: bool, error: Option<String> },

    HeartbeatAck { pending_messages: u32 },

    /// Prekey bundle response
    Bundle {
        username: String,
        identity_public_key: Vec<u8>,
        signed_prekey: Vec<u8>,
        signed_prekey_signature: Vec<u8>,
        one_time_prekey: Option<Vec<u8>>,
        otpk_index: Option<u32>,
    },
    BundleError { username: String, error: String },

    /// Incoming chat request from another user
    IncomingChatRequest {
        from: String,
        identity_public_key: Vec<u8>,
        ephemeral_pub: Vec<u8>,
        otpk_index: Option<u32>,
    },

    /// Chat request was accepted by the other side
    ChatRequestAccepted {
        from: String,
        /// Responder's identity public key so initiator can verify
        identity_public_key: Vec<u8>,
    },

    /// Chat request was rejected
    ChatRequestRejected {
        from: String,
    },

    /// Ack for chat request / accept / reject sends
    ChatAck { ok: bool, error: Option<String> },

    SendAck { ok: bool, error: Option<String> },

    /// Incoming message (delivered immediately if online, or from queue)
    IncomingMessage {
        from: String,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        server_timestamp: u64,
    },

    IncomingFile {
        from: String,
        filename: String,
        chunk_index: u32,
        total_chunks: u32,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        server_timestamp: u64,
    },

    RefillAck { ok: bool, count: u32 },
    PresenceUpdate { username: String, online: bool },
    Error { message: String },
    GoodbyeAck,
}

// ── Frame I/O ──────────────────────────────────────────────

pub async fn write_frame<W: AsyncWriteExt + Unpin, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> Result<(), ProtoError> {
    let payload = bincode::serialize(msg)?;
    let len = payload.len() as u32;
    if len > MAX_FRAME_SIZE {
        return Err(ProtoError::FrameTooLarge { size: len, max: MAX_FRAME_SIZE });
    }
    writer.write_u8(PROTOCOL_VERSION).await?;
    writer.write_u32(len).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncReadExt + Unpin, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
) -> Result<T, ProtoError> {
    let version = reader.read_u8().await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ProtoError::ConnectionClosed
        } else {
            ProtoError::Io(e)
        }
    })?;
    if version != PROTOCOL_VERSION {
        return Err(ProtoError::VersionMismatch { got: version, expected: PROTOCOL_VERSION });
    }
    let len = reader.read_u32().await?;
    if len > MAX_FRAME_SIZE {
        return Err(ProtoError::FrameTooLarge { size: len, max: MAX_FRAME_SIZE });
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    let msg = bincode::deserialize(&buf)?;
    Ok(msg)
}

pub fn pad_payload(data: &[u8]) -> Vec<u8> {
    let padded_len = ((data.len() / PAD_BLOCK_SIZE) + 1) * PAD_BLOCK_SIZE;
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(&(data.len() as u32).to_le_bytes());
    padded.extend_from_slice(data);
    padded.resize(padded_len, 0);
    padded
}

pub fn unpad_payload(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 4 { return None; }
    let len = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if len + 4 > padded.len() { return None; }
    Some(padded[4..4 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pad_unpad() {
        let data = b"hello world";
        let padded = pad_payload(data);
        assert_eq!(padded.len() % PAD_BLOCK_SIZE, 0);
        let recovered = unpad_payload(&padded).unwrap();
        assert_eq!(recovered, data);
    }
}
