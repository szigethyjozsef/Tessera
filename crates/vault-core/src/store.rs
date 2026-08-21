use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::path::{Path, PathBuf};
use std::fs;

use crate::aead::{open, seal, Sealed, NONCE_LEN};
use crate::error::{Result, VaultError};
use crate::manifest::FORMAT_VERSION;
use crate::Entry;
use crate::SecretKey;
use crate::EntryType;

fn entry_aad(vault_id: Uuid, entry_id: Uuid, format_version: u32) -> Vec<u8> {
    format!("{}|{}|{}", vault_id, entry_id, format_version).into_bytes()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryRecord {
    pub id: Uuid,
    pub format_version: u32,
    #[serde(with = "crate::b64::b64_array")]
    pub nonce: [u8; NONCE_LEN],
    #[serde(with = "crate::b64::b64_vec")]
    pub ciphertext: Vec<u8>,
}

fn seal_entry(dek: &SecretKey, vault_id: Uuid, entry: &Entry) -> Result<EntryRecord> {
    let json = serde_json::to_string(entry).map_err(|_| VaultError::Malformed)?;
    let aad = entry_aad(vault_id, entry.id, FORMAT_VERSION);
    let sealed = seal(dek, &aad, json.as_bytes())?;
    Ok(EntryRecord {
        id: entry.id,
        format_version: FORMAT_VERSION,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext
    })
}

fn open_entry(dek: &SecretKey, vault_id: Uuid, record: &EntryRecord) -> Result<Entry> {
    let sealed = Sealed {
        nonce: record.nonce,
        ciphertext: record.ciphertext.clone(),
    };
    let aad = entry_aad(vault_id, record.id, record.format_version);
    let plaintext = open(dek, &aad, &sealed)?;
    serde_json::from_slice(&plaintext).map_err(|_| VaultError::Malformed)
}

fn entry_path(entries_dir: &Path, id: Uuid) -> PathBuf {
    entries_dir.join(format!("{id}.json"))
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub(crate) fn write_entry(
    entries_dir: &Path,
    dek: &SecretKey,
    vault_id: Uuid,
    entry: &Entry,
) -> Result<()> {
    let record = seal_entry(dek, vault_id, entry)?;
    let json = serde_json::to_string_pretty(&record).map_err(|_| VaultError::Malformed)?;
    write_atomic(&entry_path(entries_dir, entry.id), json.as_bytes())
}

pub(crate) fn read_entry(
    entries_dir: &Path,
    dek: &SecretKey,
    vault_id: Uuid,
    id: Uuid,
) -> Result<Entry> {
    let json = fs::read_to_string(entry_path(entries_dir, id))?;
    let record: EntryRecord = serde_json::from_str(&json).map_err(|_| VaultError::Malformed)?;
    open_entry(dek, vault_id, &record)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a login entry with one field, for use as test input.
    fn sample_entry() -> Entry {
        let mut entry = Entry::new(EntryType::Login, "test-device");
        entry.set_field("password", "hunter2", "test-device");
        entry
    }

    #[test]
    fn sealed_entry_can_be_opened_again() {
        let dek = SecretKey::generate();
        let vault_id = Uuid::now_v7();
        let original = sample_entry();

        let record = seal_entry(&dek, vault_id, &original).unwrap();
        let recovered = open_entry(&dek, vault_id, &record).unwrap();

        assert_eq!(recovered.id, original.id);
        assert_eq!(recovered.version, original.version);
        assert_eq!(recovered.get_field("password"), Some("hunter2"));
    }

    #[test]
    fn opening_with_the_wrong_vault_id_fails() {
        let dek = SecretKey::generate();
        let vault_id = Uuid::now_v7();
        let other_vault_id = Uuid::now_v7();

        let record = seal_entry(&dek, vault_id, &sample_entry()).unwrap();

        assert!(open_entry(&dek, other_vault_id, &record).is_err());
    }
}