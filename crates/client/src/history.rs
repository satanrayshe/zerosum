use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zerosum_crypto::identity::{decrypt_blob, encrypt_blob};

#[derive(Clone, Serialize, Deserialize)]
pub enum Direction {
    Sent,
    Received,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub peer: String,
    pub direction: Direction,
    pub text: String,
    pub timestamp: i64,
}

#[derive(Serialize, Deserialize)]
struct HistoryFile {
    enabled: bool,
    entries: Vec<HistoryEntry>,
}

pub struct HistoryStore {
    path: PathBuf,
    password: String,
    enabled: bool,
    entries: Vec<HistoryEntry>,
}

impl HistoryStore {
    pub fn new(path: PathBuf, password: String, enabled: bool) -> Self {
        if path.exists() {
            if let Ok(existing) = Self::load_from_file(&path, &password) {
                return Self {
                    path,
                    password,
                    enabled: existing.enabled,
                    entries: existing.entries,
                };
            }
        }

        Self {
            path,
            password,
            enabled,
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, peer: &str, direction: Direction, text: &str) {
        if !self.enabled {
            return;
        }
        self.entries.push(HistoryEntry {
            peer: peer.to_string(),
            direction,
            text: text.to_string(),
            timestamp: Utc::now().timestamp(),
        });
    }

    pub fn save(&self) -> Result<()> {
        let blob = HistoryFile {
            enabled: self.enabled,
            entries: self.entries.clone(),
        };
        let data = bincode::serialize(&blob)?;
        let encrypted = encrypt_blob(&self.password, &data)?;
        std::fs::write(&self.path, encrypted)?;
        Ok(())
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }

    pub fn purge(&mut self) -> Result<()> {
        self.entries.clear();
        self.save()
    }

    pub fn default_path(data_dir: &Path) -> PathBuf {
        data_dir.join("history.enc")
    }

    fn load_from_file(path: &Path, password: &str) -> Result<HistoryFile> {
        let encrypted = std::fs::read(path)?;
        let data = decrypt_blob(password, &encrypted)?;
        Ok(bincode::deserialize(&data)?)
    }
}
