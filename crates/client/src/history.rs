// ─────────────────────────────────────────────────────────────
// Encrypted local history — opt-in, encrypted, purgeable
// ─────────────────────────────────────────────────────────────
// History is DISABLED by default. User must opt in.
// When enabled, messages are encrypted with XChaCha20-Poly1305
// and stored in an append-only local file.

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use zerosum_crypto::identity::{encrypt_blob, decrypt_blob};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub timestamp: i64,
    pub peer: String,
    pub direction: Direction,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Direction {
    Sent,
    Received,
}

/// Local encrypted chat history store
pub struct HistoryStore {
    entries: Vec<HistoryEntry>,
    path: PathBuf,
    password: String,
    enabled: bool,
    dirty: bool,
}

impl HistoryStore {
    /// Create a new history store
    pub fn new(path: PathBuf, password: String, enabled: bool) -> Self {
        let mut store = HistoryStore {
            entries: Vec::new(),
            path,
            password,
            enabled,
            dirty: false,
        };

        if enabled && store.path.exists() {
            match store.load() {
                Ok(entries) => store.entries = entries,
                Err(_) => {
                    // Corrupt or wrong password — start fresh
                    store.entries = Vec::new();
                }
            }
        }

        store
    }

    /// Check if history is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable history
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable history (does NOT purge existing)
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Add a message to history
    pub fn add(&mut self, peer: &str, direction: Direction, content: &str) {
        if !self.enabled {
            return;
        }

        self.entries.push(HistoryEntry {
            timestamp: Utc::now().timestamp(),
            peer: peer.to_string(),
            direction,
            content: content.to_string(),
        });
        self.dirty = true;
    }

    /// Get history for a specific peer
    pub fn get_peer_history(&self, peer: &str) -> Vec<&HistoryEntry> {
        self.entries
            .iter()
            .filter(|e| e.peer == peer)
            .collect()
    }

    /// Get all history
    pub fn all(&self) -> &[HistoryEntry] {
        &self.entries
    }

    /// Save history to disk (encrypted)
    pub fn save(&mut self) -> Result<()> {
        if !self.enabled || !self.dirty {
            return Ok(());
        }

        let data = bincode::serialize(&self.entries)?;
        let encrypted = encrypt_blob(&self.password, &data)?;
        std::fs::write(&self.path, encrypted)?;
        self.dirty = false;
        Ok(())
    }

    /// Load history from disk
    fn load(&self) -> Result<Vec<HistoryEntry>> {
        let encrypted = std::fs::read(&self.path)?;
        let data = decrypt_blob(&self.password, &encrypted)?;
        let entries: Vec<HistoryEntry> = bincode::deserialize(&data)?;
        Ok(entries)
    }

    /// PURGE — irrecoverably destroy all history
    pub fn purge(&mut self) -> Result<()> {
        self.entries.clear();
        self.dirty = false;

        // Overwrite file with random data before deleting
        if self.path.exists() {
            let file_len = std::fs::metadata(&self.path)?.len() as usize;
            let mut random_data = vec![0u8; file_len];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random_data);
            std::fs::write(&self.path, &random_data)?;
            // Second pass with zeros
            std::fs::write(&self.path, vec![0u8; file_len])?;
            // Delete
            std::fs::remove_file(&self.path)?;
        }

        Ok(())
    }

    /// Get the default history file path
    pub fn default_path(data_dir: &Path) -> PathBuf {
        data_dir.join("history.enc")
    }
}

impl Drop for HistoryStore {
    fn drop(&mut self) {
        // Best-effort save on drop
        if self.enabled && self.dirty {
            let _ = self.save();
        }
    }
}
