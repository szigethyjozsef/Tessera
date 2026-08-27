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

pub(crate) fn list_entries(
    entries_dir: &Path,
    dek: &SecretKey,
    vault_id: Uuid,
) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();

    for dir_entry in fs::read_dir(entries_dir)? {
        let path = dir_entry?.path();

        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }

        let Some(id) = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| Uuid::parse_str(stem).ok())
        else {
            continue;
        };

        if let Ok(entry) = read_entry(entries_dir, dek, vault_id, id) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

pub(crate) fn delete_entry(
    entries_dir: &Path,
    dek: &SecretKey,
    vault_id: Uuid,
    id: Uuid,
    device_id: &str,
) -> Result<()> {
    let mut entry = read_entry(entries_dir, dek, vault_id, id)?;

    if entry.deleted_at.is_some() {
        return Ok(());
    }

    entry.mark_deleted();
    entry.last_modified_by = device_id.to_owned();

    write_entry(entries_dir, dek, vault_id, &entry)
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

        fn temp_dir(tag: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join(format!("tessera-store-{tag}-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn entry_written_to_disk_can_be_read_back() {
        let dir = temp_dir("roundtrip");
        let dek = SecretKey::generate();
        let vault_id = Uuid::now_v7();
        let entry = sample_entry();

        write_entry(&dir, &dek, vault_id, &entry).unwrap();
        let recovered = read_entry(&dir, &dek, vault_id, entry.id).unwrap();

        assert_eq!(recovered.id, entry.id);
        assert_eq!(recovered.get_field("password"), Some("hunter2"));
    }

    #[test]
    fn entry_file_does_not_contain_the_plaintext_password() {
        let dir = temp_dir("no-leak");
        let dek = SecretKey::generate();
        let vault_id = Uuid::now_v7();
        let entry = sample_entry();

        write_entry(&dir, &dek, vault_id, &entry).unwrap();

        let raw = fs::read_to_string(entry_path(&dir, entry.id)).unwrap();
        assert!(!raw.contains("hunter2"));
        assert!(!raw.contains("password"));
    }

        #[test]
    fn listing_returns_every_written_entry() {
        let dir = temp_dir("list");
        let dek = SecretKey::generate();
        let vault_id = Uuid::now_v7();

        let first = sample_entry();
        let second = sample_entry();
        write_entry(&dir, &dek, vault_id, &first).unwrap();
        write_entry(&dir, &dek, vault_id, &second).unwrap();

        let listed = list_entries(&dir, &dek, vault_id).unwrap();

        assert_eq!(listed.len(), 2);
    }

    #[test]
    fn deleting_keeps_the_record_as_a_tombstone() {
        let dir = temp_dir("delete");
        let dek = SecretKey::generate();
        let vault_id = Uuid::now_v7();
        let entry = sample_entry();

        write_entry(&dir, &dek, vault_id, &entry).unwrap();
        delete_entry(&dir, &dek, vault_id, entry.id, "test-device").unwrap();

        let tombstone = read_entry(&dir, &dek, vault_id, entry.id).unwrap();

        assert!(tombstone.deleted_at.is_some());
        assert!(tombstone.fields.is_empty());
        assert_eq!(tombstone.version, entry.version + 1);
        assert!(entry_path(&dir, entry.id).exists());
    }

    #[test]
    fn deleting_twice_does_not_bump_the_version_again() {
        let dir = temp_dir("delete-twice");
        let dek = SecretKey::generate();
        let vault_id = Uuid::now_v7();
        let entry = sample_entry();

        write_entry(&dir, &dek, vault_id, &entry).unwrap();
        delete_entry(&dir, &dek, vault_id, entry.id, "test-device").unwrap();
        let after_first = read_entry(&dir, &dek, vault_id, entry.id).unwrap();

        delete_entry(&dir, &dek, vault_id, entry.id, "test-device").unwrap();
        let after_second = read_entry(&dir, &dek, vault_id, entry.id).unwrap();

        assert_eq!(after_first.version, after_second.version);
    }
}