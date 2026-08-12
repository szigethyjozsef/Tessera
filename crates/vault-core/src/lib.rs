//! Cryptographic core and vault format for Tessera.

#![forbid(unsafe_code)]

mod error;
mod key;

pub use error::{Result, VaultError};
pub use key::{SecretKey, KEY_LEN};