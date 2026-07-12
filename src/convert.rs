//! Ed25519 ↔ X25519 / Curve25519 conversions (libsodium-compatible).
//!
//! Pipeline used by this crate:
//! - Stellar `S...` seed → SHA-512 → clamp → X25519 private scalar
//! - Stellar `G...` Ed25519 public → birational map → X25519 public (Montgomery u)
//!
//! These match libsodium:
//! - `crypto_sign_ed25519_sk_to_curve25519`
//! - `crypto_sign_ed25519_pk_to_curve25519`
//!
//! And RFC 8032 / RFC 7748.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Derive the Ed25519/X25519 clamped scalar bytes from a 32-byte Ed25519 seed.
///
/// Same clamping as X25519 / libsodium `crypto_sign_ed25519_sk_to_curve25519`
/// (using only the seed half of the 64-byte expanded secret).
pub fn ed25519_seed_to_scalar_bytes(seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::digest(seed);
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&h[..32]);
    // X25519 clamp
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    h.zeroize();
    sk
}

/// Ed25519 seed → X25519 private key bytes (clamped).
pub fn ed25519_seed_to_x25519_private(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_seed_to_scalar_bytes(seed)
}

/// Ed25519 seed → `curve25519_dalek::Scalar` for group operations.
pub fn ed25519_seed_to_scalar(seed: &[u8; 32]) -> Scalar {
    let mut bytes = ed25519_seed_to_scalar_bytes(seed);
    // Clamped value is already a valid scalar representative; construct without reduction
    // of high bits beyond what clamp ensures. Use from_bytes_mod_order for safety.
    let s = Scalar::from_bytes_mod_order(bytes);
    bytes.zeroize();
    s
}

/// Ed25519 public key (32-byte compressed Edwards Y) → X25519 public (Montgomery u).
pub fn ed25519_public_to_x25519_public(ed_pub: &[u8; 32]) -> Result<[u8; 32]> {
    let compressed = CompressedEdwardsY(*ed_pub);
    let edwards = compressed
        .decompress()
        .ok_or(Error::InvalidPublicKey)?;
    let mont: MontgomeryPoint = edwards.to_montgomery();
    Ok(mont.0)
}

/// Compute Ed25519 public key bytes from a 32-byte seed (RFC 8032).
pub fn ed25519_public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    use ed25519_dalek::{SigningKey, VerifyingKey};
    let signing = SigningKey::from_bytes(seed);
    let verifying: VerifyingKey = signing.verifying_key();
    verifying.to_bytes()
}

/// Consistency check: X25519 public from private path equals public conversion path.
#[cfg(test)]
pub fn x25519_public_from_private(x_priv: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*x_priv);
    let public = PublicKey::from(&secret);
    public.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn ed25519_x25519_priv_pub_consistent() {
        for _ in 0..16 {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);

            let ed_pub = ed25519_public_from_seed(&seed);
            let x_priv = ed25519_seed_to_x25519_private(&seed);
            let x_pub_from_priv = x25519_public_from_private(&x_priv);
            let x_pub_from_pub = ed25519_public_to_x25519_public(&ed_pub).unwrap();

            assert_eq!(
                x_pub_from_priv, x_pub_from_pub,
                "X25519 pub from priv must equal X25519 pub from Ed25519 pub"
            );
        }
    }

    #[test]
    fn rfc8032_vector1_public() {
        // RFC 8032 test vector 1
        let seed = hex::decode(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )
        .unwrap();
        let mut s = [0u8; 32];
        s.copy_from_slice(&seed);
        let expected = hex::decode(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .unwrap();
        let pubk = ed25519_public_from_seed(&s);
        assert_eq!(pubk.as_slice(), expected.as_slice());
    }
}
