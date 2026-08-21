use serde::{Deserialize, Serialize};
use uuid::Uuid;
use uuid::timestamp::UUID_TICKS_BETWEEN_EPOCHS;

use crate::aead::NONCE_LEN;
use crate::error::{Result, VaultError};
use crate::manifest::FORMAT_VERSION;
use crate::seal;
use crate::Entry;
use crate::SecretKey;

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
