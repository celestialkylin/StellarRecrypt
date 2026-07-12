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

/// HKDF info for the default PRE encryption scalar (private; not part of public API).
const INFO_PRE_SCALAR: &[u8] = b"pre-encryption-scalar";

/// Derive the Alice-side PRE scalar from a 32-byte Stellar Ed25519 seed using
/// the library default HKDF info.
///
/// ```text
/// HKDF-SHA256(ikm=seed, salt="StellarRecrypt-v1", info="pre-encryption-scalar", L=64)
///   → Scalar::from_bytes_mod_order_wide
/// ```
///
/// This value is intentionally **not** the Ed25519/X25519 signing scalar.
pub(crate) fn derive_pre_scalar(seed: &[u8; 32]) -> Scalar {
    derive_pre_scalar_with_info(seed, INFO_PRE_SCALAR)
}

/// Derive the Alice-side PRE scalar with an explicit HKDF `info` context string.
///
/// Same salt and output length as the default path; only `info` differs.
/// No length or content checks are applied to `info` (HKDF allows any length,
/// including empty). Use [`info_for_peer`] for per-recipient isolation.
///
/// ```text
/// HKDF-SHA256(ikm=seed, salt="StellarRecrypt-v1", info=info, L=64)
///   → Scalar::from_bytes_mod_order_wide
/// ```
pub(crate) fn derive_pre_scalar_with_info(seed: &[u8; 32], info: &[u8]) -> Scalar {
    let hk = Hkdf::<Sha256>::new(Some(SALT), seed);
    let mut okm = [0u8; 64];
    hk.expand(info, &mut okm)
        .expect("HKDF expand 64 bytes never fails");
    let s = Scalar::from_bytes_mod_order_wide(&okm);
    okm.zeroize();
    s
}

/// Build structured HKDF info for a peer-specific PRE scalar.
///
/// Format:
/// ```text
/// "pre-encryption-scalar" || 0x00 || peer_ed25519_pk (32 bytes)
/// ```
///
/// Pass to `from_*(..., Some(&info))` so that Alice's `pre_sk` / `pre_pk` are
/// isolated per counterparty. The encryption `pre_pk` and decryption/rekey
/// `pre_sk` must use the same info.
pub fn info_for_peer(peer_ed25519: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::with_capacity(INFO_PRE_SCALAR.len() + 1 + 32);
    info.extend_from_slice(INFO_PRE_SCALAR);
    info.push(0);
    info.extend_from_slice(peer_ed25519);
    info
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

    #[test]
    fn default_matches_explicit_default_info() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        assert_eq!(
            derive_pre_scalar(&seed),
            derive_pre_scalar_with_info(&seed, INFO_PRE_SCALAR)
        );
    }

    #[test]
    fn different_info_different_scalars() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let a = derive_pre_scalar_with_info(&seed, b"context-a");
        let b = derive_pre_scalar_with_info(&seed, b"context-b");
        assert_ne!(a, b);
        assert_ne!(a, derive_pre_scalar(&seed));
    }

    #[test]
    fn info_for_peer_differs_by_peer() {
        let mut seed = [0u8; 32];
        let mut pk_a = [3u8; 32];
        let mut pk_b = [4u8; 32];
        OsRng.fill_bytes(&mut seed);
        OsRng.fill_bytes(&mut pk_a);
        OsRng.fill_bytes(&mut pk_b);
        if pk_a == pk_b {
            pk_b[0] ^= 1;
        }
        let sa = derive_pre_scalar_with_info(&seed, &info_for_peer(&pk_a));
        let sb = derive_pre_scalar_with_info(&seed, &info_for_peer(&pk_b));
        assert_ne!(sa, sb);
        assert_ne!(sa, derive_pre_scalar(&seed));
    }

    #[test]
    fn info_for_peer_format() {
        let pk = [0xABu8; 32];
        let info = info_for_peer(&pk);
        assert_eq!(&info[..INFO_PRE_SCALAR.len()], INFO_PRE_SCALAR);
        assert_eq!(info[INFO_PRE_SCALAR.len()], 0);
        assert_eq!(&info[INFO_PRE_SCALAR.len() + 1..], &pk);
        assert_eq!(info.len(), INFO_PRE_SCALAR.len() + 1 + 32);
    }
}
