//! Cryptographic core and vault format for Tessera.

#![forbid(unsafe_code)]

mod aead;
mod error;
mod kdf;
mod key;
mod manifest;
mod vault;
mod entry;

pub use aead::{open, seal, unwrap_dek, wrap_dek, Sealed, NONCE_LEN, TAG_LEN};
pub use error::{Result, VaultError};
pub use kdf::{derive_kek, generate_salt, KdfParams, SALT_LEN};
pub use key::{SecretKey, KEY_LEN};
pub use manifest::{Manifest, FORMAT_VERSION, MAGIC};
pub use vault::Vault;
pub use entry::{Entry, EntryType, FieldValue};