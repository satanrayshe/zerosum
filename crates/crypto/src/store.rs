// ─────────────────────────────────────────────────────────────
// Encrypted session store — persists ratchet state to disk
// ─────────────────────────────────────────────────────────────
// Fixes the original's in-memory-only store that lost all
// forward secrecy state on crash.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::identity::{encrypt_blob, decrypt_blob};
use crate::ratchet::SessionRatchet;

/// Persistent encrypted session store
#[derive(Serialize, Deserialize, Default)]
pub struct SessionStore {
    /// Map of peer username → session ratchet state
    sessions: HashMap<String, SessionRatchet>,
    /// Store version for migration support
    version: u32,
}

impl SessionStore {
    pub fn new() -> Self {
        SessionStore {
            sessions: HashMap::new(),
            version: 1,
        }
    }

    /// Get a mutable reference to a session
    pub fn get_session_mut(&mut self, peer: &str) -> Option<&mut SessionRatchet> {
        self.sessions.get_mut(peer)
    }

    /// Get an immutable reference
    pub fn get_session(&self, peer: &str) -> Option<&SessionRatchet> {
        self.sessions.get(peer)
    }

    /// Insert or replace a session
    pub fn put_session(&mut self, peer: String, session: SessionRatchet) {
        self.sessions.insert(peer, session);
    }

    /// Remove a session
    pub fn remove_session(&mut self, peer: &str) -> Option<SessionRatchet> {
        self.sessions.remove(peer)
    }

    /// Check if a session exists
    pub fn has_session(&self, peer: &str) -> bool {
        self.sessions.contains_key(peer)
    }

    /// List all peers with sessions
    pub fn peers(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }

    /// Save encrypted to disk
    pub fn save(&self, path: &Path, password: &str) -> Result<()> {
        let data = bincode::serialize(self)?;
        let encrypted = encrypt_blob(password, &data)?;
        std::fs::write(path, encrypted)?;
        Ok(())
    }

    /// Load from encrypted file
    pub fn load(path: &Path, password: &str) -> Result<Self> {
        let encrypted = std::fs::read(path)?;
        let data = decrypt_blob(password, &encrypted)?;
        let store: SessionStore = bincode::deserialize(&data)?;
        Ok(store)
    }

    /// Load or create new
    pub fn load_or_new(path: &Path, password: &str) -> Self {
        if path.exists() {
            Self::load(path, password).unwrap_or_else(|_| {
                // Corrupt store — start fresh (log warning)
                eprintln!("[WARN] Session store corrupt or wrong password, starting fresh");
                Self::new()
            })
        } else {
            Self::new()
        }
    }

    /// Purge all sessions (panic mode)
    pub fn purge(&mut self) {
        self.sessions.clear();
    }

    /// Get the store file path for a given data directory
    pub fn default_path(data_dir: &Path) -> PathBuf {
        data_dir.join("sessions.enc")
    }
}
