//! Data Encapsulation Mechanism: XChaCha20-Poly1305 with HKDF-SHA256 key derivation.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use curve25519_dalek::edwards::EdwardsPoint;
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Error, Result};

const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Derive a 32-byte DEM key from a shared Edwards point and domain separation context.
pub fn kdf_from_point(shared: &EdwardsPoint, context: &[u8]) -> [u8; KEY_LEN] {
    let ikm = shared.compress().to_bytes();
    let hk = Hkdf::<Sha256>::new(Some(b"StellarRecrypt-PRE-v1"), &ikm);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(context, &mut okm)
        .expect("HKDF expand 32 bytes never fails");
    okm
}

/// Encrypt plaintext; returns `nonce || ciphertext||tag`.
pub fn seal<R: CryptoRng + RngCore>(
    rng: &mut R,
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("AEAD encrypt failed".into()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt `nonce || ciphertext||tag`.
pub fn open(key: &[u8; KEY_LEN], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + 16 {
        return Err(Error::DecryptionFailed);
    }
    let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct,
                aad,
            },
        )
        .map_err(|_| Error::DecryptionFailed)
}

/// Zeroizing wrapper helper.
pub fn zeroize_key(key: &mut [u8; KEY_LEN]) {
    key.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn seal_open_roundtrip() {
        let mut key = [7u8; 32];
        let pt = b"hello stellar pre";
        let aad = b"capsule-aad";
        let sealed = seal(&mut OsRng, &key, pt, aad).unwrap();
        let opened = open(&key, &sealed, aad).unwrap();
        assert_eq!(opened, pt);
        assert!(open(&key, &sealed, b"bad").is_err());
        zeroize_key(&mut key);
    }
}
