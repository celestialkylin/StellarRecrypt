//! Domain-separated key derivation for PRE isolation.
//!
//! Alice's PRE scalar is derived via HKDF from the Stellar seed so that it is
//! computationally independent of the Ed25519 signing scalar.

use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// HKDF salt (library / version domain).
const SALT: &[u8] = b"StellarRecrypt-v1";

/// HKDF info for the PRE encryption scalar.
const INFO_PRE_SCALAR: &[u8] = b"pre-encryption-scalar";

/// Derive the Alice-side PRE scalar from a 32-byte Stellar Ed25519 seed.
///
/// ```text
/// HKDF-SHA256(ikm=seed, salt="StellarRecrypt-v1", info="pre-encryption-scalar", L=64)
///   → Scalar::from_bytes_mod_order_wide
/// ```
///
/// This value is intentionally **not** the Ed25519/X25519 signing scalar.
pub fn derive_pre_scalar(seed: &[u8; 32]) -> Scalar {
    let hk = Hkdf::<Sha256>::new(Some(SALT), seed);
    let mut okm = [0u8; 64];
    hk.expand(INFO_PRE_SCALAR, &mut okm)
        .expect("HKDF expand 64 bytes never fails");
    let s = Scalar::from_bytes_mod_order_wide(&okm);
    okm.zeroize();
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::ed25519_seed_to_scalar;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn deterministic() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        assert_eq!(derive_pre_scalar(&seed), derive_pre_scalar(&seed));
    }

    #[test]
    fn differs_from_signing_scalar() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let pre = derive_pre_scalar(&seed);
        let signing = ed25519_seed_to_scalar(&seed);
        assert_ne!(pre, signing);
        assert_ne!(pre, Scalar::ZERO);
    }

    #[test]
    fn different_seeds_different_scalars() {
        let mut a = [1u8; 32];
        let mut b = [2u8; 32];
        OsRng.fill_bytes(&mut a);
        OsRng.fill_bytes(&mut b);
        if a != b {
            assert_ne!(derive_pre_scalar(&a), derive_pre_scalar(&b));
        }
    }
}
