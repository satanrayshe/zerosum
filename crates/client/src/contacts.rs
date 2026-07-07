use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zerosum_crypto::identity::{decrypt_blob, encrypt_blob};

#[derive(Clone, Serialize, Deserialize)]
pub struct Contact {
    pub username: String,
    pub alias: Option<String>,
    pub verified: bool,
    pub identity_key: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct ContactStore {
    contacts: HashMap<String, Contact>,
    version: u32,
}

impl ContactStore {
    pub fn new() -> Self {
        Self {
            contacts: HashMap::new(),
            version: 1,
        }
    }

    pub fn load(path: &Path, password: &str) -> Result<Self> {
        let encrypted = std::fs::read(path)?;
        let data = decrypt_blob(password, &encrypted)?;
        Ok(bincode::deserialize(&data)?)
    }

    pub fn load_or_new(path: &Path, password: &str) -> Self {
        if path.exists() {
            Self::load(path, password).unwrap_or_else(|_| Self::new())
        } else {
            Self::new()
        }
    }

    pub fn save(&self, path: &Path, password: &str) -> Result<()> {
        let data = bincode::serialize(self)?;
        let encrypted = encrypt_blob(password, &data)?;
        std::fs::write(path, encrypted)?;
        Ok(())
    }

    pub fn default_path(data_dir: &Path) -> PathBuf {
        data_dir.join("contacts.enc")
    }

    pub fn list(&self) -> Vec<Contact> {
        self.contacts.values().cloned().collect()
    }

    pub fn get(&self, username: &str) -> Option<&Contact> {
        self.contacts.get(username)
    }

    pub fn has(&self, username: &str) -> bool {
        self.contacts.contains_key(username)
    }

    pub fn add(&mut self, username: &str) {
        self.contacts.entry(username.to_string()).or_insert(Contact {
            username: username.to_string(),
            alias: None,
            verified: false,
            identity_key: None,
        });
    }

    pub fn set_alias(&mut self, username: &str, alias: &str) {
        self.add(username);
        if let Some(contact) = self.contacts.get_mut(username) {
            contact.alias = Some(alias.to_string());
        }
    }

    pub fn set_identity_key(&mut self, username: &str, identity_key: Vec<u8>) {
        self.add(username);
        if let Some(contact) = self.contacts.get_mut(username) {
            contact.identity_key = Some(identity_key);
        }
    }

    pub fn verify(&mut self, username: &str) {
        self.add(username);
        if let Some(contact) = self.contacts.get_mut(username) {
            contact.verified = true;
        }
    }
}
