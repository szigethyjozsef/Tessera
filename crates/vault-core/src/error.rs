use thiserror::Error;

/// Errors returned by the vault core.
///
/// Messages must never contain key material, passwords, or decrypted
/// entry contents: errors end up in logs and bug reports.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("incorrect master password or corrupted vault")]
    AuthenticationFailed,

    #[error("key derivation failed")]
    KeyDerivation,

    #[error("unsupported vault format version {found}, this build supports up to {supported}")]
    UnsupportedFormatVersion { found: u32, supported: u32 },

    #[error("vault data is malformed")]
    Malformed,

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;