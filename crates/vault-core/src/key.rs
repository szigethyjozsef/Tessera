use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of all symmetric keys in this crate, in bytes.
pub const KEY_LEN: usize = 32;

/// A 256-bit symmetric key.
///
/// The backing bytes are overwritten with zeroes when the value is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; KEY_LEN],
}

impl SecretKey {
    /// Wraps existing key bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// Generates a new key from the operating system CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Borrows the raw key material.
    ///
    /// Deliberately named `expose` so that every call site reads as a
    /// conscious decision rather than an accessor.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_key_material() {
        let key = SecretKey::from_bytes([0xAB; KEY_LEN]);
        assert_eq!(format!("{:?}", key), "SecretKey(***)");
    }

    #[test]
    fn generate_produces_distinct_keys() {
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        assert_ne!(a.expose(), b.expose());
    }
}
