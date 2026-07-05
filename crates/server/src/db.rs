// ─────────────────────────────────────────────────────────────
// Server database — SQLite user directory, message queue, control queue
// ─────────────────────────────────────────────────────────────

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).context("Failed to open database")?;
        conn.execute_batch("
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash BLOB NOT NULL,
                identity_public_key BLOB NOT NULL,
                signed_prekey BLOB NOT NULL,
                signed_prekey_signature BLOB NOT NULL,
                online INTEGER DEFAULT 0,
                last_seen INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS one_time_prekeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                key_index INTEGER NOT NULL,
                public_key BLOB NOT NULL,
                used INTEGER DEFAULT 0,
                FOREIGN KEY (username) REFERENCES users(username)
            );

            CREATE TABLE IF NOT EXISTS message_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT NOT NULL,
                sender TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                timestamp INTEGER NOT NULL,
                msg_type TEXT DEFAULT 'message',
                filename TEXT,
                chunk_index INTEGER,
                total_chunks INTEGER,
                FOREIGN KEY (recipient) REFERENCES users(username)
            );

            CREATE TABLE IF NOT EXISTS control_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT NOT NULL,
                sender TEXT NOT NULL,
                msg_type TEXT NOT NULL,
                data BLOB NOT NULL,
                timestamp INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_queue_recipient ON message_queue(recipient);
            CREATE INDEX IF NOT EXISTS idx_control_recipient ON control_queue(recipient);
            CREATE INDEX IF NOT EXISTS idx_otpk_username ON one_time_prekeys(username, used);
        ").context("Failed to initialize database")?;

        Ok(Database { conn: Mutex::new(conn) })
    }

    pub fn register_user(&self, username: &str, password_hash: &[u8],
        identity_public_key: &[u8], signed_prekey: &[u8],
        signed_prekey_signature: &[u8], one_time_prekeys: &[Vec<u8>],
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let exists: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM users WHERE username = ?1",
            params![username], |row| row.get(0),
        ).unwrap_or(false);
        if exists { anyhow::bail!("Username already taken"); }

        conn.execute(
            "INSERT INTO users (username, password_hash, identity_public_key, signed_prekey, signed_prekey_signature)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![username, password_hash, identity_public_key, signed_prekey, signed_prekey_signature],
        )?;

        for (i, pk) in one_time_prekeys.iter().enumerate() {
            conn.execute(
                "INSERT INTO one_time_prekeys (username, key_index, public_key) VALUES (?1, ?2, ?3)",
                params![username, i as i64, pk],
            )?;
        }
        Ok(())
    }

    pub fn authenticate(&self, username: &str, password_hash: &[u8]) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let stored: Vec<u8> = conn.query_row(
            "SELECT password_hash FROM users WHERE username = ?1",
            params![username], |row| row.get(0),
        ).context("User not found")?;
        Ok(stored == password_hash)
    }

    pub fn set_online(&self, username: &str, online: bool) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute("UPDATE users SET online = ?1, last_seen = ?2 WHERE username = ?3",
            params![online as i64, now, username])?;
        Ok(())
    }

    pub fn user_exists(&self, username: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) > 0 FROM users WHERE username = ?1",
            params![username], |row| row.get::<_, bool>(0),
        ).unwrap_or(false)
    }

    pub fn get_identity_key(&self, username: &str) -> Result<Vec<u8>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT identity_public_key FROM users WHERE username = ?1",
            params![username], |row| row.get(0),
        ).context("User not found")
    }

    pub fn fetch_bundle(&self, username: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<u32>)> {
        let conn = self.conn.lock().unwrap();
        let (ik, spk, spk_sig): (Vec<u8>, Vec<u8>, Vec<u8>) = conn.query_row(
            "SELECT identity_public_key, signed_prekey, signed_prekey_signature FROM users WHERE username = ?1",
            params![username], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).context("User not found")?;

        let otpk_result: Option<(i64, Vec<u8>, i64)> = conn.query_row(
            "SELECT id, public_key, key_index FROM one_time_prekeys WHERE username = ?1 AND used = 0 LIMIT 1",
            params![username], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).ok();

        let (otpk, otpk_index) = if let Some((id, key, index)) = otpk_result {
            conn.execute("UPDATE one_time_prekeys SET used = 1 WHERE id = ?1", params![id])?;
            (Some(key), Some(index as u32))
        } else {
            (None, None)
        };

        Ok((ik, spk, spk_sig, otpk, otpk_index))
    }

    pub fn add_prekeys(&self, username: &str, prekeys: &[Vec<u8>]) -> Result<u32> {
        let conn = self.conn.lock().unwrap();
        let max_index: i64 = conn.query_row(
            "SELECT COALESCE(MAX(key_index), -1) FROM one_time_prekeys WHERE username = ?1",
            params![username], |row| row.get(0),
        ).unwrap_or(-1);

        for (i, pk) in prekeys.iter().enumerate() {
            conn.execute(
                "INSERT INTO one_time_prekeys (username, key_index, public_key) VALUES (?1, ?2, ?3)",
                params![username, max_index + 1 + i as i64, pk],
            )?;
        }

        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM one_time_prekeys WHERE username = ?1 AND used = 0",
            params![username], |row| row.get(0),
        ).unwrap_or(0);
        Ok(count)
    }

    // ── Message queue ───────────────────────────────────────

    pub fn queue_message(&self, recipient: &str, sender: &str,
        ciphertext: &[u8], nonce: &[u8], timestamp: u64) -> Result<()>
    {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO message_queue (recipient, sender, ciphertext, nonce, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![recipient, sender, ciphertext, nonce, timestamp as i64],
        )?;
        Ok(())
    }

    pub fn queue_file(&self, recipient: &str, sender: &str, filename: &str,
        chunk_index: u32, total_chunks: u32, ciphertext: &[u8], nonce: &[u8]) -> Result<()>
    {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO message_queue (recipient, sender, ciphertext, nonce, timestamp, msg_type, filename, chunk_index, total_chunks)
             VALUES (?1, ?2, ?3, ?4, ?5, 'file', ?6, ?7, ?8)",
            params![recipient, sender, ciphertext, nonce, now, filename, chunk_index as i64, total_chunks as i64],
        )?;
        Ok(())
    }

    pub fn drain_queue(&self, username: &str) -> Result<Vec<QueuedMessage>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, sender, ciphertext, nonce, timestamp, msg_type, filename, chunk_index, total_chunks
             FROM message_queue WHERE recipient = ?1 ORDER BY id")?;

        let messages: Vec<QueuedMessage> = stmt.query_map(params![username], |row| {
            Ok(QueuedMessage {
                id: row.get(0)?, sender: row.get(1)?,
                ciphertext: row.get(2)?, nonce: row.get(3)?,
                timestamp: row.get::<_, i64>(4)? as u64,
                msg_type: row.get(5)?,
                filename: row.get(6)?, chunk_index: row.get::<_, Option<i64>>(7)?.map(|i| i as u32),
                total_chunks: row.get::<_, Option<i64>>(8)?.map(|i| i as u32),
            })
        })?.collect::<std::result::Result<Vec<_>, _>>()?;

        conn.execute("DELETE FROM message_queue WHERE recipient = ?1", params![username])?;
        Ok(messages)
    }

    pub fn pending_count(&self, username: &str) -> u32 {
        let conn = self.conn.lock().unwrap();
        let msg_count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM message_queue WHERE recipient = ?1",
            params![username], |row| row.get(0),
        ).unwrap_or(0);
        let ctrl_count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM control_queue WHERE recipient = ?1",
            params![username], |row| row.get(0),
        ).unwrap_or(0);
        msg_count + ctrl_count
    }

    // ── Control message queue (chat requests, accepts, rejects) ──

    pub fn queue_control(&self, recipient: &str, sender: &str, msg_type: &str, data: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO control_queue (recipient, sender, msg_type, data, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![recipient, sender, msg_type, data, now],
        )?;
        Ok(())
    }

    pub fn drain_control_queue(&self, username: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, msg_type, data FROM control_queue WHERE recipient = ?1 ORDER BY id")?;

        let items: Vec<(i64, String, Vec<u8>)> = stmt.query_map(params![username], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?.collect::<std::result::Result<Vec<_>, _>>()?;

        conn.execute("DELETE FROM control_queue WHERE recipient = ?1", params![username])?;
        Ok(items.into_iter().map(|(_, t, d)| (t, d)).collect())
    }

    pub fn otpk_remaining(&self, username: &str) -> u32 {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM one_time_prekeys WHERE username = ?1 AND used = 0",
            params![username], |row| row.get(0),
        ).unwrap_or(0)
    }
}

pub struct QueuedMessage {
    pub id: i64,
    pub sender: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub timestamp: u64,
    pub msg_type: String,
    pub filename: Option<String>,
    pub chunk_index: Option<u32>,
    pub total_chunks: Option<u32>,
}
