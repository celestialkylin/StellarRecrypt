//! Key types for asymmetric PRE isolation.
//!
//! - **Alice (delegator)**: `pre_sk` / `pre_pk` derived via HKDF from `S...` seed.
//! - **Bob (delegatee)**: Stellar `G...` public + signing scalar from `S...` (no HKDF).

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::convert::{
    ed25519_public_from_seed, ed25519_public_to_x25519_public, ed25519_seed_to_scalar,
    ed25519_seed_to_x25519_private,
};
use crate::error::{Error, Result};
use crate::kdf::derive_pre_scalar;
use crate::strkey;

/// Alice-side PRE public key: `pre_pk = pre_sk · B`.
///
/// This is **not** a Stellar `G...` account key. Publish these 32 bytes so others
/// can encrypt to Alice without learning her signing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrePublicKey {
    bytes: [u8; 32],
    point: EdwardsPoint,
}

impl PrePublicKey {
    /// Build from a compressed Edwards Y point (32 bytes).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let point = CompressedEdwardsY(*bytes)
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;
        if bool::from(point.is_identity()) || !bool::from(point.is_torsion_free()) {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Self {
            bytes: *bytes,
            point,
        })
    }

    /// Derive PRE public key from a Stellar secret seed (`S...` payload).
    /// Only the seed holder can produce this; encryptors should use a published copy.
    pub fn from_stellar_seed(seed: &[u8; 32]) -> Result<Self> {
        let pre_sk = derive_pre_scalar(seed);
        if pre_sk == Scalar::ZERO {
            return Err(Error::InvalidPrivateKey);
        }
        let point = pre_sk * ED25519_BASEPOINT_POINT;
        let bytes = point.compress().to_bytes();
        Ok(Self { bytes, point })
    }

    /// Derive from a Stellar secret strkey `S...`.
    pub fn from_stellar_secret_strkey(s: &str) -> Result<Self> {
        let seed = strkey::decode_seed(s)?;
        Self::from_stellar_seed(&seed)
    }

    /// Compressed Edwards Y encoding (32 bytes).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Raw compressed bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub(crate) fn point(&self) -> &EdwardsPoint {
        &self.point
    }
}

/// Stellar account public key (`G...`).
///
/// Used as **Bob's** re-encryption target (delegatee public key). Not used as
/// Alice's encryption target under the isolation model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StellarPublicKey {
    /// Raw Ed25519 public key (32 bytes, compressed Edwards Y).
    ed25519: [u8; 32],
    /// Decompressed Edwards point.
    point: EdwardsPoint,
    /// X25519 / Montgomery public key (helper / interop).
    x25519: [u8; 32],
}

impl StellarPublicKey {
    /// Parse a Stellar strkey `G...`.
    pub fn from_strkey(g: &str) -> Result<Self> {
        let ed25519 = strkey::decode_public(g)?;
        Self::from_ed25519_bytes(&ed25519)
    }

    /// Build from raw 32-byte Ed25519 public key.
    pub fn from_ed25519_bytes(ed25519: &[u8; 32]) -> Result<Self> {
        let point = CompressedEdwardsY(*ed25519)
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;
        if bool::from(point.is_identity()) || !bool::from(point.is_torsion_free()) {
            return Err(Error::InvalidPublicKey);
        }
        let x25519 = ed25519_public_to_x25519_public(ed25519)?;
        Ok(Self {
            ed25519: *ed25519,
            point,
            x25519,
        })
    }

    /// Stellar `G...` encoding.
    pub fn to_strkey(&self) -> String {
        strkey::encode_public(&self.ed25519)
    }

    /// Raw Ed25519 public key bytes.
    pub fn as_ed25519_bytes(&self) -> &[u8; 32] {
        &self.ed25519
    }

    /// X25519 public key bytes (Montgomery u).
    pub fn as_x25519_bytes(&self) -> &[u8; 32] {
        &self.x25519
    }

    pub(crate) fn point(&self) -> &EdwardsPoint {
        &self.point
    }
}

/// Stellar secret seed (`S...`) with both PRE and signing scalars.
///
/// - [`Self::pre_scalar`] — HKDF-derived; Alice encrypt / decrypt / rekey
/// - [`Self::signing_scalar`] — Ed25519/X25519 clamp; Bob re-encrypted decrypt; matches `G...`
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StellarSecretKey {
    seed: [u8; 32],
    pre_sk: Scalar,
    signing_scalar: Scalar,
    x25519_private: [u8; 32],
}

impl std::fmt::Debug for StellarSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StellarSecretKey([REDACTED])")
    }
}

impl StellarSecretKey {
    /// Parse a Stellar strkey `S...`.
    pub fn from_strkey(s: &str) -> Result<Self> {
        let seed = strkey::decode_seed(s)?;
        Self::from_seed(&seed)
    }

    /// Build from raw 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let pre_sk = derive_pre_scalar(seed);
        let signing_scalar = ed25519_seed_to_scalar(seed);
        if pre_sk == Scalar::ZERO || signing_scalar == Scalar::ZERO {
            return Err(Error::InvalidPrivateKey);
        }
        let x25519_private = ed25519_seed_to_x25519_private(seed);
        Ok(Self {
            seed: *seed,
            pre_sk,
            signing_scalar,
            x25519_private,
        })
    }

    /// Generate a fresh random Stellar secret key.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed).expect("random seed is valid")
    }

    /// Stellar `S...` encoding.
    pub fn to_strkey(&self) -> String {
        strkey::encode_seed(&self.seed)
    }

    /// Stellar account public key `G...` (signing identity).
    pub fn stellar_public_key(&self) -> StellarPublicKey {
        let ed = ed25519_public_from_seed(&self.seed);
        StellarPublicKey::from_ed25519_bytes(&ed).expect("derived public key is valid")
    }

    /// Alice-side PRE public key (publish this for encryption).
    pub fn pre_public_key(&self) -> PrePublicKey {
        let point = self.pre_sk * ED25519_BASEPOINT_POINT;
        let bytes = point.compress().to_bytes();
        PrePublicKey { bytes, point }
    }

    /// Raw Ed25519 seed bytes.
    pub fn as_seed_bytes(&self) -> &[u8; 32] {
        &self.seed
    }

    /// X25519 private key bytes (signing-path clamp; interop helper).
    pub fn as_x25519_private_bytes(&self) -> &[u8; 32] {
        &self.x25519_private
    }

    /// HKDF PRE scalar (Alice).
    pub(crate) fn pre_scalar(&self) -> &Scalar {
        &self.pre_sk
    }

    /// Ed25519/X25519 signing scalar (Bob decrypt_reencrypted; matches `G...`).
    pub(crate) fn signing_scalar(&self) -> &Scalar {
        &self.signing_scalar
    }
}

/// Convenience keypair: Stellar account + derived PRE keys.
#[derive(Clone)]
pub struct StellarKeyPair {
    /// Secret seed (`S...`) with pre + signing scalars.
    pub secret: StellarSecretKey,
    /// Stellar account public key (`G...`).
    pub stellar_public: StellarPublicKey,
    /// PRE public key for encryption (publish for Alice role).
    pub pre_public: PrePublicKey,
}

impl StellarKeyPair {
    /// Generate a fresh random keypair.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let secret = StellarSecretKey::generate(rng);
        Self::from_secret(secret)
    }

    /// Build from an existing secret.
    pub fn from_secret(secret: StellarSecretKey) -> Self {
        let stellar_public = secret.stellar_public_key();
        let pre_public = secret.pre_public_key();
        Self {
            secret,
            stellar_public,
            pre_public,
        }
    }

    /// Build from a Stellar secret strkey `S...`.
    pub fn from_secret_strkey(s: &str) -> Result<Self> {
        let secret = StellarSecretKey::from_strkey(s)?;
        Ok(Self::from_secret(secret))
    }

    /// `pre_pk` matches `pre_sk · B`.
    pub fn validate_pre_consistency(&self) -> bool {
        let derived = self.secret.pre_scalar() * ED25519_BASEPOINT_POINT;
        derived.compress().to_bytes() == *self.pre_public.as_bytes()
    }

    /// `G...` matches signing scalar · B.
    pub fn validate_stellar_consistency(&self) -> bool {
        let derived = self.secret.signing_scalar() * ED25519_BASEPOINT_POINT;
        derived.compress().to_bytes() == *self.stellar_public.as_ed25519_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn keypair_roundtrip_strkey() {
        let kp = StellarKeyPair::generate(&mut OsRng);
        let s = kp.secret.to_strkey();
        assert!(s.starts_with('S'));
        assert!(kp.stellar_public.to_strkey().starts_with('G'));

        let kp2 = StellarKeyPair::from_secret_strkey(&s).unwrap();
        assert_eq!(kp2.stellar_public.to_strkey(), kp.stellar_public.to_strkey());
        assert_eq!(kp2.pre_public.to_bytes(), kp.pre_public.to_bytes());
        assert!(kp2.validate_pre_consistency());
        assert!(kp2.validate_stellar_consistency());
    }

    #[test]
    fn pre_sk_ne_signing_sk() {
        let kp = StellarKeyPair::generate(&mut OsRng);
        assert_ne!(kp.secret.pre_scalar(), kp.secret.signing_scalar());
        assert_ne!(
            kp.pre_public.as_bytes(),
            kp.stellar_public.as_ed25519_bytes()
        );
    }

    #[test]
    fn pre_public_from_secret_strkey() {
        let kp = StellarKeyPair::generate(&mut OsRng);
        let s = kp.secret.to_strkey();
        let pk = PrePublicKey::from_stellar_secret_strkey(&s).unwrap();
        assert_eq!(pk.to_bytes(), kp.pre_public.to_bytes());
    }

    #[test]
    fn pre_public_bytes_roundtrip() {
        let kp = StellarKeyPair::generate(&mut OsRng);
        let pk2 = PrePublicKey::from_bytes(&kp.pre_public.to_bytes()).unwrap();
        assert_eq!(pk2, kp.pre_public);
    }
}
