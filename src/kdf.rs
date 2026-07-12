//! Domain-separated key derivation for PRE isolation.
//!
//! Alice's PRE scalar is derived via HKDF from the Stellar seed so that it is
//! computationally independent of the Ed25519 signing scalar.
//!
//! Callers **must** supply an explicit HKDF `info` when constructing Alice keys.
//! Use [`structured_info`] to compose purpose/peer domain strings.

use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// HKDF salt (library / version domain).
const SALT: &[u8] = b"StellarRecrypt-v1";

/// Prefix for [`structured_info`] outputs (not a default key-derivation info).
const INFO_PREFIX: &[u8] = b"pre-encryption-scalar";

/// Single-byte pad between structured info fields.
const INFO_PAD: u8 = 0;

/// Derive the Alice-side PRE scalar with an explicit HKDF `info` context string.
///
/// No length or content checks are applied to `info` (HKDF allows any length,
/// including empty). Prefer [`structured_info`] for purpose / peer isolation.
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

/// True if `arg` looks like a prior [`structured_info`] output
/// (`PREFIX || PAD || …`).
fn is_structured(arg: &[u8]) -> bool {
    arg.len() >= INFO_PREFIX.len() + 1
        && arg.starts_with(INFO_PREFIX)
        && arg[INFO_PREFIX.len()] == INFO_PAD
}

/// One-layer unwrap: `PREFIX || PAD || (x || PAD || y)` → `x || PAD || y`.
fn unwrap_structured(arg: &[u8]) -> &[u8] {
    if is_structured(arg) {
        &arg[INFO_PREFIX.len() + 1..]
    } else {
        arg
    }
}

/// Build structured HKDF info for domain separation.
///
/// Format:
/// ```text
/// "pre-encryption-scalar" || 0x00 || arg_a' || 0x00 || arg_b'
/// ```
///
/// If an argument is itself a previous output of this function (starts with
/// `PREFIX || PAD`), it is **unwrapped one layer** first: for
/// `structured_info(x, y)` that yields `PREFIX || PAD || x || PAD || y`, the
/// restored payload is exactly `x || PAD || y` (when `x` and `y` were not
/// structured).
///
/// Both arguments may be empty:
/// ```text
/// structured_info(&[], &[]) → PREFIX || PAD || PAD
/// ```
///
/// # Examples
///
/// Per-recipient isolation:
/// ```
/// use stellar_recrypt::structured_info;
/// let info = structured_info(b"rekey", &[0u8; 32]);
/// ```
pub fn structured_info(arg_a: &[u8], arg_b: &[u8]) -> Vec<u8> {
    let a = unwrap_structured(arg_a);
    let b = unwrap_structured(arg_b);
    let mut out = Vec::with_capacity(INFO_PREFIX.len() + 2 + a.len() + b.len());
    out.extend_from_slice(INFO_PREFIX);
    out.push(INFO_PAD);
    out.extend_from_slice(a);
    out.push(INFO_PAD);
    out.extend_from_slice(b);
    out
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
        let info = structured_info(b"test", &[]);
        assert_eq!(
            derive_pre_scalar_with_info(&seed, &info),
            derive_pre_scalar_with_info(&seed, &info)
        );
    }

    #[test]
    fn differs_from_signing_scalar() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let pre = derive_pre_scalar_with_info(&seed, &structured_info(b"pre", &[]));
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
        let info = structured_info(b"ctx", &[]);
        if a != b {
            assert_ne!(
                derive_pre_scalar_with_info(&a, &info),
                derive_pre_scalar_with_info(&b, &info)
            );
        }
    }

    #[test]
    fn different_info_different_scalars() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let a = derive_pre_scalar_with_info(&seed, b"context-a");
        let b = derive_pre_scalar_with_info(&seed, b"context-b");
        assert_ne!(a, b);
    }

    #[test]
    fn structured_info_both_empty() {
        let info = structured_info(&[], &[]);
        let mut expected = INFO_PREFIX.to_vec();
        expected.push(INFO_PAD);
        expected.push(INFO_PAD);
        assert_eq!(info, expected);
        assert_eq!(info.len(), INFO_PREFIX.len() + 2);
    }

    #[test]
    fn structured_info_format_raw_args() {
        let a = b"purpose";
        let b = [0xABu8; 32];
        let info = structured_info(a, &b);
        assert_eq!(&info[..INFO_PREFIX.len()], INFO_PREFIX);
        assert_eq!(info[INFO_PREFIX.len()], INFO_PAD);
        let rest = &info[INFO_PREFIX.len() + 1..];
        assert_eq!(&rest[..a.len()], a);
        assert_eq!(rest[a.len()], INFO_PAD);
        assert_eq!(&rest[a.len() + 1..], &b);
    }

    #[test]
    fn unwrap_structured_info_is_x_pad_y() {
        let x = b"x-val";
        let y = b"y-val";
        let built = structured_info(x, y);
        let restored = unwrap_structured(&built);
        let mut expected = Vec::new();
        expected.extend_from_slice(x);
        expected.push(INFO_PAD);
        expected.extend_from_slice(y);
        assert_eq!(restored, expected.as_slice());
    }

    #[test]
    fn nested_structured_info() {
        let x = b"x";
        let y = b"y";
        let z = b"z";
        let inner = structured_info(x, y);
        let outer = structured_info(&inner, z);

        // PREFIX || PAD || (x||PAD||y) || PAD || z
        let mut expected = INFO_PREFIX.to_vec();
        expected.push(INFO_PAD);
        expected.extend_from_slice(x);
        expected.push(INFO_PAD);
        expected.extend_from_slice(y);
        expected.push(INFO_PAD);
        expected.extend_from_slice(z);
        assert_eq!(outer, expected);
    }

    #[test]
    fn structured_info_differs_by_peer() {
        let mut seed = [0u8; 32];
        let mut pk_a = [3u8; 32];
        let mut pk_b = [4u8; 32];
        OsRng.fill_bytes(&mut seed);
        OsRng.fill_bytes(&mut pk_a);
        OsRng.fill_bytes(&mut pk_b);
        if pk_a == pk_b {
            pk_b[0] ^= 1;
        }
        let sa = derive_pre_scalar_with_info(&seed, &structured_info(b"rekey", &pk_a));
        let sb = derive_pre_scalar_with_info(&seed, &structured_info(b"rekey", &pk_b));
        assert_ne!(sa, sb);
    }
}
