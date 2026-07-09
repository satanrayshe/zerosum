// ─────────────────────────────────────────────────────────────
// Encrypted contacts — NO plaintext social graph on disk
// ─────────────────────────────────────────────────────────────
// Fixes the original's plaintext contacts.txt vulnerability.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use zerosum_crypto::identity::{encrypt_blob, decrypt_blob};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub username: String,
    /// Their identity public key (for fingerprint verification)
    pub identity_key: Option<Vec<u8>>,
    /// Whether we've verified their safety number out-of-band
    pub verified: bool,
    /// Optional display name / alias
    pub alias: Option<String>,
}

/// Encrypted contact store
#[derive(Serialize, Deserialize, Default)]
pub struct ContactStore {
    contacts: HashMap<String, Contact>,
}

impl ContactStore {
    pub fn new() -> Self {
        ContactStore {
            contacts: HashMap::new(),
        }
    }

    /// Add a contact
    pub fn add(&mut self, username: &str) {
        if !self.contacts.contains_key(username) {
            self.contacts.insert(
                username.to_string(),
                Contact {
                    username: username.to_string(),
                    identity_key: None,
                    verified: false,
                    alias: None,
                },
            );
        }
    }

    /// Remove a contact
    pub fn remove(&mut self, username: &str) -> bool {
        self.contacts.remove(username).is_some()
    }

    /// Get a contact
    pub fn get(&self, username: &str) -> Option<&Contact> {
        self.contacts.get(username)
    }

    /// Get a mutable contact
    pub fn get_mut(&mut self, username: &str) -> Option<&mut Contact> {
        self.contacts.get_mut(username)
    }

    /// Set a contact's identity key (from bundle fetch)
    pub fn set_identity_key(&mut self, username: &str, key: Vec<u8>) {
        if let Some(contact) = self.contacts.get_mut(username) {
            // Check if key changed (potential MITM)
            if let Some(ref old_key) = contact.identity_key {
                if *old_key != key {
                    // Key changed! Reset verification
                    contact.verified = false;
                }
            }
            contact.identity_key = Some(key);
        }
    }

    /// Mark a contact as verified
    pub fn verify(&mut self, username: &str) -> bool {
        if let Some(contact) = self.contacts.get_mut(username) {
            contact.verified = true;
            true
        } else {
            false
        }
    }

    /// Set an alias for a contact
    pub fn set_alias(&mut self, username: &str, alias: &str) {
        if let Some(contact) = self.contacts.get_mut(username) {
            contact.alias = Some(alias.to_string());
        }
    }

    /// List all contacts
    pub fn list(&self) -> Vec<&Contact> {
        self.contacts.values().collect()
    }

    /// List contact usernames
    pub fn usernames(&self) -> Vec<String> {
        self.contacts.keys().cloned().collect()
    }

    /// Check if a contact exists
    pub fn has(&self, username: &str) -> bool {
        self.contacts.contains_key(username)
    }

    /// Get display name (alias or username)
    pub fn display_name(&self, username: &str) -> String {
        if let Some(contact) = self.contacts.get(username) {
            contact
                .alias
                .as_ref()
                .cloned()
                .unwrap_or_else(|| contact.username.clone())
        } else {
            username.to_string()
        }
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
        let store: ContactStore = bincode::deserialize(&data)?;
        Ok(store)
    }

    /// Load or create new
    pub fn load_or_new(path: &Path, password: &str) -> Self {
        if path.exists() {
            Self::load(path, password).unwrap_or_else(|_| Self::new())
        } else {
            Self::new()
        }
    }

    /// Default path
    pub fn default_path(data_dir: &Path) -> PathBuf {
        data_dir.join("contacts.enc")
    }
}
