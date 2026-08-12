use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};

use crate::error::{Result, VaultError};
use crate::key::{SecretKey, KEY_LEN};

/// Length of the KDF salt, in bytes.
pub const SALT_LEN: usize = 16;

/// Argon2id parameters recorded in a vault manifest.
///
/// These are stored per-vault rather than hardcoded, so that the recommended
/// cost can be raised over time without making older vaults unopenable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// The current baseline: m=64 MiB, t=3, p=4. See ADR-0002.
    pub const CURRENT: Self = Self {
        memory_kib: 65536,
        iterations: 3,
        parallelism: 4,
    };
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::CURRENT
    }
}

/// Generates a fresh random salt.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derives the key-encryption key from a master password.
///
/// The password is borrowed and never copied into an owned `String` here;
/// the caller owns its lifetime and is responsible for zeroising it.
pub fn derive_kek(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<SecretKey> {
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| VaultError::KeyDerivation)?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut output = [0u8; KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut output)
        .map_err(|_| VaultError::KeyDerivation)?;

    Ok(SecretKey::from_bytes(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters so the test suite stays fast. Never use these for real vaults.
    const TEST_PARAMS: KdfParams = KdfParams {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    };

    #[test]
    fn derivation_is_deterministic() {
        let salt = [0x42u8; SALT_LEN];
        let a = derive_kek(b"correct horse", &salt, TEST_PARAMS).unwrap();
        let b = derive_kek(b"correct horse", &salt, TEST_PARAMS).unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn different_passwords_give_different_keys() {
        let salt = [0x42u8; SALT_LEN];
        let a = derive_kek(b"correct horse", &salt, TEST_PARAMS).unwrap();
        let b = derive_kek(b"correct horsf", &salt, TEST_PARAMS).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn different_salts_give_different_keys() {
        let a = derive_kek(b"same password", &[0x01; SALT_LEN], TEST_PARAMS).unwrap();
        let b = derive_kek(b"same password", &[0x02; SALT_LEN], TEST_PARAMS).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn salts_are_not_repeated() {
        assert_ne!(generate_salt(), generate_salt());
    }
}