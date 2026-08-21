use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::{Result, VaultError};
use crate::key::{SecretKey, KEY_LEN};

/// XChaCha20 nonce length, in bytes.
pub const NONCE_LEN: usize = 24;

/// Poly1305 authentication tag length, in bytes.
pub const TAG_LEN: usize = 16;

/// A ciphertext together with the nonce it was produced with.
///
/// The tag is appended to `ciphertext` by the AEAD implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

fn cipher_for(key: &SecretKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.expose().into())
}

/// Encrypts `plaintext`, binding it to `aad`.
///
/// A fresh random nonce is generated on every call. With a 192-bit nonce the
/// probability of a collision is negligible, so no counter state is needed.
pub fn seal(key: &SecretKey, aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher_for(key)
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::Malformed)?;

    Ok(Sealed { nonce, ciphertext })
}

/// Decrypts and authenticates a sealed value.
///
/// Returns [`VaultError::AuthenticationFailed`] if the key, the associated data,
/// or the ciphertext do not match. The three cases are deliberately
/// indistinguishable to the caller.
pub fn open(key: &SecretKey, aad: &[u8], sealed: &Sealed) -> Result<Vec<u8>> {
    cipher_for(key)
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)
}

/// Encrypts a data-encryption key under the key-encryption key.
pub fn wrap_dek(kek: &SecretKey, aad: &[u8], dek: &SecretKey) -> Result<Sealed> {
    seal(kek, aad, dek.expose())
}

/// Recovers a data-encryption key.
///
/// This is also how a master password is verified: if the tag validates, the
/// password was correct. No password hash is stored anywhere.
pub fn unwrap_dek(kek: &SecretKey, aad: &[u8], sealed: &Sealed) -> Result<SecretKey> {
    let mut plaintext = open(kek, aad, sealed)?;

    if plaintext.len() != KEY_LEN {
        plaintext.zeroize();
        return Err(VaultError::Malformed);
    }

    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(&plaintext);
    plaintext.zeroize();

    Ok(SecretKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecretKey {
        SecretKey::from_bytes([0x11; KEY_LEN])
    }

    #[test]
    fn roundtrip_returns_original_plaintext() {
        let sealed = seal(&key(), b"vault|entry", b"hunter2").unwrap();
        assert_eq!(open(&key(), b"vault|entry", &sealed).unwrap(), b"hunter2");
    }

    #[test]
    fn ciphertext_is_longer_than_plaintext_by_the_tag() {
        let sealed = seal(&key(), b"", b"hunter2").unwrap();
        assert_eq!(sealed.ciphertext.len(), b"hunter2".len() + TAG_LEN);
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&key(), b"aad", b"secret").unwrap();
        let other = SecretKey::from_bytes([0x22; KEY_LEN]);
        assert!(open(&other, b"aad", &sealed).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let sealed = seal(&key(), b"entry-a", b"secret").unwrap();
        assert!(open(&key(), b"entry-b", &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut sealed = seal(&key(), b"aad", b"secret").unwrap();
        sealed.ciphertext[0] ^= 0x01;
        assert!(open(&key(), b"aad", &sealed).is_err());
    }

    #[test]
    fn nonces_are_not_repeated() {
        let a = seal(&key(), b"aad", b"secret").unwrap();
        let b = seal(&key(), b"aad", b"secret").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn dek_survives_wrap_and_unwrap() {
        let dek = SecretKey::generate();
        let wrapped = wrap_dek(&key(), b"vault-id", &dek).unwrap();
        let recovered = unwrap_dek(&key(), b"vault-id", &wrapped).unwrap();
        assert_eq!(recovered.expose(), dek.expose());
    }

    #[test]
    fn unwrapping_with_wrong_kek_fails() {
        let dek = SecretKey::generate();
        let wrapped = wrap_dek(&key(), b"vault-id", &dek).unwrap();
        let wrong = SecretKey::from_bytes([0x99; KEY_LEN]);
        assert!(unwrap_dek(&wrong, b"vault-id", &wrapped).is_err());
    }
}
