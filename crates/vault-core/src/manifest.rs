use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::aead::{Sealed, NONCE_LEN};
use crate::error::{Result, VaultError};
use crate::kdf::{KdfParams, SALT_LEN};

/// Identifies the file as a Tessera vault manifest.
pub const MAGIC: &str = "TESSERA-VAULT";

/// Highest format version this build can read.
pub const FORMAT_VERSION: u32 = 1;

/// Argon2 version 1.3, as recorded on disk.
const ARGON_VERSION: u32 = 19;

/// The plaintext vault manifest.
///
/// Contains no secrets: only the parameters required to *attempt* a key
/// derivation, and the wrapped data-encryption key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub magic: String,
    pub format_version: u32,
    pub vault_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub kdf: KdfSection,
    pub wrapped_dek: SealedSection,
    #[serde(with = "time::serde::rfc3339::option")]
    pub kdf_upgraded_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfSection {
    pub algorithm: String,
    pub argon_version: u32,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    #[serde(with = "b64_array")]
    pub salt: [u8; SALT_LEN],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedSection {
    pub algorithm: String,
    #[serde(with = "b64_array")]
    pub nonce: [u8; NONCE_LEN],
    #[serde(with = "b64_vec")]
    pub ciphertext: Vec<u8>,
}

impl Manifest {
    /// Builds a manifest for a freshly created vault.
    pub fn new(params: KdfParams, salt: [u8; SALT_LEN], wrapped_dek: &Sealed) -> Self {
        Self {
            magic: MAGIC.to_owned(),
            format_version: FORMAT_VERSION,
            vault_id: Uuid::now_v7(),
            created_at: OffsetDateTime::now_utc(),
            kdf: KdfSection {
                algorithm: "argon2id".to_owned(),
                argon_version: ARGON_VERSION,
                memory_kib: params.memory_kib,
                iterations: params.iterations,
                parallelism: params.parallelism,
                salt,
            },
            wrapped_dek: SealedSection {
                algorithm: "xchacha20poly1305".to_owned(),
                nonce: wrapped_dek.nonce,
                ciphertext: wrapped_dek.ciphertext.clone(),
            },
            kdf_upgraded_at: None,
        }
    }

    /// The KDF parameters this vault was created with.
    ///
    /// Always derived from the file, never from the current baseline, so that
    /// older vaults stay openable after the recommended cost is raised.
    pub fn kdf_params(&self) -> KdfParams {
        KdfParams {
            memory_kib: self.kdf.memory_kib,
            iterations: self.kdf.iterations,
            parallelism: self.kdf.parallelism,
        }
    }

    pub fn wrapped_dek(&self) -> Sealed {
        Sealed {
            nonce: self.wrapped_dek.nonce,
            ciphertext: self.wrapped_dek.ciphertext.clone(),
        }
    }

    /// Associated data binding the wrapped DEK to this specific vault.
    pub fn dek_aad(&self) -> Vec<u8> {
        format!("{}|{}", self.vault_id, self.format_version).into_bytes()
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|_| VaultError::Malformed)
    }

    /// Parses and validates a manifest.
    pub fn from_json(json: &str) -> Result<Self> {
        let manifest: Self = serde_json::from_str(json).map_err(|_| VaultError::Malformed)?;

        if manifest.magic != MAGIC {
            return Err(VaultError::Malformed);
        }

        if manifest.format_version > FORMAT_VERSION {
            return Err(VaultError::UnsupportedFormatVersion {
                found: manifest.format_version,
                supported: FORMAT_VERSION,
            });
        }

        Ok(manifest)
    }
}

mod b64_array {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D, const N: usize>(d: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(d)?;
        let decoded = STANDARD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)?;
        decoded
            .try_into()
            .map_err(|_| serde::de::Error::custom("unexpected byte length"))
    }
}

mod b64_vec {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(d)?;
        STANDARD.decode(&encoded).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::TAG_LEN;
    use crate::key::KEY_LEN;

    fn sample() -> Manifest {
        let sealed = Sealed {
            nonce: [0x07; NONCE_LEN],
            ciphertext: vec![0x5A; KEY_LEN + TAG_LEN],
        };
        Manifest::new(KdfParams::CURRENT, [0x42; SALT_LEN], &sealed)
    }

    #[test]
    fn json_roundtrip_preserves_every_field() {
        let original = sample();
        let parsed = Manifest::from_json(&original.to_json().unwrap()).unwrap();

        assert_eq!(parsed.vault_id, original.vault_id);
        assert_eq!(parsed.kdf.salt, original.kdf.salt);
        assert_eq!(parsed.wrapped_dek.nonce, original.wrapped_dek.nonce);
        assert_eq!(parsed.wrapped_dek.ciphertext, original.wrapped_dek.ciphertext);
        assert_eq!(parsed.kdf_params(), original.kdf_params());
    }

    #[test]
    fn fields_are_camel_case_on_disk() {
        let json = sample().to_json().unwrap();
        assert!(json.contains("\"formatVersion\""));
        assert!(json.contains("\"wrappedDek\""));
        assert!(json.contains("\"memoryKib\""));
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let json = sample().to_json().unwrap().replace(MAGIC, "SOMETHING-ELSE");
        assert!(Manifest::from_json(&json).is_err());
    }

    #[test]
    fn future_format_version_is_rejected() {
        let json = sample()
            .to_json()
            .unwrap()
            .replace("\"formatVersion\": 1", "\"formatVersion\": 99");

        match Manifest::from_json(&json) {
            Err(VaultError::UnsupportedFormatVersion { found, supported }) => {
                assert_eq!(found, 99);
                assert_eq!(supported, FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedFormatVersion, got {other:?}"),
        }
    }

    #[test]
    fn each_vault_gets_a_distinct_id() {
        assert_ne!(sample().vault_id, sample().vault_id);
    }
}