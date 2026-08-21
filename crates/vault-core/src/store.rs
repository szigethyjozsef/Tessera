use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::aead::NONCE_LEN;

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