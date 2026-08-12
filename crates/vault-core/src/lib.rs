//! Cryptographic core and vault format for Tessera.

#![forbid(unsafe_code)]

mod error;
mod kdf;
mod key;

pub use error::{Result, VaultError};
pub use kdf::{derive_kek, generate_salt, KdfParams, SALT_LEN};
pub use key::{SecretKey, KEY_LEN};