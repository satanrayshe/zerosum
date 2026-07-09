// ─────────────────────────────────────────────────────────────
// PANIC — emergency purge of all local data
// ─────────────────────────────────────────────────────────────
// !panic command: securely wipes ALL local state:
//   - Encrypted identity
//   - Session store
//   - Contact store
//   - Chat history
//   - Tor state
//   - Any other files in the data directory

use anyhow::Result;
use std::path::Path;
use tracing::info;

/// Securely overwrite a file with random data, then zeros, then delete.
fn secure_delete(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if path.is_dir() {
        // Recursively delete directory contents
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            secure_delete(&entry.path())?;
        }
        std::fs::remove_dir(path)?;
        return Ok(());
    }

    let file_len = std::fs::metadata(path)?.len() as usize;
    if file_len > 0 {
        // Pass 1: random data
        let mut random_data = vec![0u8; file_len];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random_data);
        std::fs::write(path, &random_data)?;

        // Pass 2: zeros
        std::fs::write(path, vec![0u8; file_len])?;

        // Pass 3: ones
        std::fs::write(path, vec![0xFF; file_len])?;
    }

    // Delete
    std::fs::remove_file(path)?;
    info!("Securely deleted: {}", path.display());

    Ok(())
}

/// Execute the panic purge: destroy everything in the data directory.
pub fn execute_panic(data_dir: &Path) -> Result<()> {
    info!("!!! PANIC PURGE INITIATED !!!");

    // List of known sensitive files
    let sensitive_files = [
        "identity.enc",
        "sessions.enc",
        "contacts.enc",
        "history.enc",
        "onion_address.txt",
    ];

    // Delete known files first (fastest path to safety)
    for f in &sensitive_files {
        let path = data_dir.join(f);
        if path.exists() {
            secure_delete(&path)?;
        }
    }

    // Delete Tor state directories
    for dir_name in &["tor_state", "tor_cache", "tor_client_state", "tor_client_cache"] {
        let dir_path = data_dir.join(dir_name);
        if dir_path.exists() {
            secure_delete(&dir_path)?;
        }
    }

    // Delete everything else in data dir
    if data_dir.exists() {
        for entry in std::fs::read_dir(data_dir)? {
            let entry = entry?;
            secure_delete(&entry.path())?;
        }
    }

    info!("!!! PANIC PURGE COMPLETE !!!");
    Ok(())
}

/// Quick purge — just history (less destructive)
pub fn purge_history(data_dir: &Path) -> Result<()> {
    let history_path = data_dir.join("history.enc");
    if history_path.exists() {
        secure_delete(&history_path)?;
    }
    Ok(())
}
