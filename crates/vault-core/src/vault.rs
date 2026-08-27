use std::fs;
use std::path::{Path, PathBuf};

use crate::aead::{unwrap_dek, wrap_dek};
use crate::error::{Result, VaultError};
use crate::kdf::{derive_kek, generate_salt, KdfParams};
use crate::key::SecretKey;
use crate::manifest::Manifest;
use crate::entry::{Entry, EntryType};
use uuid::Uuid;

const MANIFEST_FILE: &str = "vault.json";
const ENTRIES_DIR: &str = "entries";

/// An unlocked vault.
///
/// Holding this value means the data-encryption key is live in memory. Drop it
/// to lock: the DEK is zeroised automatically.
pub struct Vault {
    root: PathBuf,
    manifest: Manifest,
    dek: SecretKey,
}

impl Vault {
    /// Creates a new vault at `root` and returns it unlocked.
    ///
    /// Fails if a manifest already exists there, so an existing vault can never
    /// be silently overwritten.
    pub fn create(root: &Path, password: &[u8], params: KdfParams) -> Result<Self> {
        let manifest_path = root.join(MANIFEST_FILE);
        if manifest_path.exists() {
            return Err(VaultError::AlreadyExists);
        }

        fs::create_dir_all(root.join(ENTRIES_DIR))?;

        let salt = generate_salt();
        let kek = derive_kek(password, &salt, params)?;
        let dek = SecretKey::generate();

        // The vault id is generated inside the manifest, so build it with a
        // placeholder AAD first, then seal against its real identity.
        let mut manifest = Manifest::new(
            params,
            salt,
            &crate::aead::Sealed {
                nonce: [0u8; crate::aead::NONCE_LEN],
                ciphertext: Vec::new(),
            },
        );

        let sealed = wrap_dek(&kek, &manifest.dek_aad(), &dek)?;
        manifest.wrapped_dek.nonce = sealed.nonce;
        manifest.wrapped_dek.ciphertext = sealed.ciphertext;

        crate::store::write_atomic(&manifest_path, manifest.to_json()?.as_bytes())?;

        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            dek,
        })
    }

    /// Opens an existing vault.
    ///
    /// A wrong password and a corrupted manifest are indistinguishable by
    /// design: both surface as [`VaultError::AuthenticationFailed`].
    pub fn unlock(root: &Path, password: &[u8]) -> Result<Self> {
        let json = fs::read_to_string(root.join(MANIFEST_FILE))?;
        let manifest = Manifest::from_json(&json)?;

        let kek = derive_kek(password, &manifest.kdf.salt, manifest.kdf_params())?;
        let dek = unwrap_dek(&kek, &manifest.dek_aad(), &manifest.wrapped_dek())?;

        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            dek,
        })
    }

    /// Re-wraps the data-encryption key under a new master password.
    ///
    /// Entry records are untouched: this is O(1), not O(number of entries).
    pub fn change_master_password(&mut self, new_password: &[u8]) -> Result<()> {
        let params = KdfParams::CURRENT;
        let salt = generate_salt();
        let kek = derive_kek(new_password, &salt, params)?;
        let sealed = wrap_dek(&kek, &self.manifest.dek_aad(), &self.dek)?;

        self.manifest.kdf.memory_kib = params.memory_kib;
        self.manifest.kdf.iterations = params.iterations;
        self.manifest.kdf.parallelism = params.parallelism;
        self.manifest.kdf.salt = salt;
        self.manifest.wrapped_dek.nonce = sealed.nonce;
        self.manifest.wrapped_dek.ciphertext = sealed.ciphertext;

        crate::store::write_atomic(
            &self.root.join(MANIFEST_FILE),
            self.manifest.to_json()?.as_bytes(),
        )
    }

    /// True if this vault was created with weaker parameters than the current baseline.
    pub fn needs_kdf_upgrade(&self) -> bool {
        self.manifest.kdf_params().memory_kib < KdfParams::CURRENT.memory_kib
    }

        /// Creates a new entry and writes it to disk.
    pub fn create_entry(&self, entry_type: EntryType, device_id: &str) -> Result<Entry> {
        let entry = Entry::new(entry_type, device_id);
        self.save_entry(&entry)?;
        Ok(entry)
    }

    /// Writes an entry, overwriting any existing record with the same id.
    pub fn save_entry(&self, entry: &Entry) -> Result<()> {
        crate::store::write_entry(
            &self.entries_dir(),
            &self.dek,
            self.manifest.vault_id,
            entry,
        )
    }

    /// Reads a single entry by id, including tombstones.
    pub fn get_entry(&self, id: Uuid) -> Result<Entry> {
        crate::store::read_entry(
            &self.entries_dir(),
            &self.dek,
            self.manifest.vault_id,
            id,
        )
    }

    /// Lists all live entries, hiding tombstones.
    pub fn list_entries(&self) -> Result<Vec<Entry>> {
        let mut entries = self.list_all_entries()?;
        entries.retain(|entry| entry.deleted_at.is_none());
        Ok(entries)
    }

    /// Lists every record, tombstones included.
    ///
    /// Sync needs to see deletions; the user interface does not.
    pub fn list_all_entries(&self) -> Result<Vec<Entry>> {
        crate::store::list_entries(
            &self.entries_dir(),
            &self.dek,
            self.manifest.vault_id,
        )
    }

    /// Turns an entry into a tombstone.
    pub fn delete_entry(&self, id: Uuid, device_id: &str) -> Result<()> {
        crate::store::delete_entry(
            &self.entries_dir(),
            &self.dek,
            self.manifest.vault_id,
            id,
            device_id,
        )
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub(crate) fn dek(&self) -> &SecretKey {
        &self.dek
    }

    pub(crate) fn entries_dir(&self) -> PathBuf {
        self.root.join(ENTRIES_DIR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PARAMS: KdfParams = KdfParams {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    };

    fn temp_root(tag: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("tessera-test-{tag}-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn created_vault_can_be_unlocked() {
        let root = temp_root("unlock");
        let created = Vault::create(&root, b"correct horse", TEST_PARAMS).unwrap();
        let expected = *created.dek().expose();
        drop(created);

        let opened = Vault::unlock(&root, b"correct horse").unwrap();
        assert_eq!(opened.dek().expose(), &expected);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let root = temp_root("wrong-pw");
        Vault::create(&root, b"correct horse", TEST_PARAMS).unwrap();

        assert!(matches!(
            Vault::unlock(&root, b"incorrect horse"),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn creating_over_an_existing_vault_is_refused() {
        let root = temp_root("exists");
        Vault::create(&root, b"first", TEST_PARAMS).unwrap();

        assert!(matches!(
            Vault::create(&root, b"second", TEST_PARAMS),
            Err(VaultError::AlreadyExists)
        ));
    }

    #[test]
    fn changing_the_password_preserves_the_dek() {
        let root = temp_root("change-pw");
        let mut vault = Vault::create(&root, b"old password", TEST_PARAMS).unwrap();
        let dek_before = *vault.dek().expose();

        vault.change_master_password(b"new password").unwrap();
        drop(vault);

        let reopened = Vault::unlock(&root, b"new password").unwrap();
        assert_eq!(reopened.dek().expose(), &dek_before);
        assert!(Vault::unlock(&root, b"old password").is_err());
    }

    #[test]
    fn manifest_on_disk_contains_no_plaintext_key() {
        let root = temp_root("no-leak");
        let vault = Vault::create(&root, b"correct horse", TEST_PARAMS).unwrap();
        let dek = *vault.dek().expose();

        let json = fs::read(root.join(MANIFEST_FILE)).unwrap();
        assert!(
            !json.windows(dek.len()).any(|w| w == dek),
            "raw DEK bytes found in the manifest"
        );
    }

    #[test]
    fn tampering_with_the_wrapped_dek_is_detected() {
        let root = temp_root("tamper");
        Vault::create(&root, b"correct horse", TEST_PARAMS).unwrap();

        let path = root.join(MANIFEST_FILE);
        let json = fs::read_to_string(&path).unwrap();
        let mut manifest = Manifest::from_json(&json).unwrap();
        manifest.wrapped_dek.ciphertext[0] ^= 0x01;
        fs::write(&path, manifest.to_json().unwrap()).unwrap();

        assert!(Vault::unlock(&root, b"correct horse").is_err());
    }
}
