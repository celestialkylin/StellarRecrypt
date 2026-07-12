//! Proxy Re-Encryption (PRE) — asymmetric key isolation.
//!
//! # Roles
//!
//! - **Alice (delegator)**: encrypt / self-decrypt / rekey with HKDF `pre_sk` / `pre_pk`
//! - **Bob (delegatee)**: rekey target is Stellar `G...`; decrypt re-encrypted with signing scalar
//!
//! # Scheme
//!
//! ## Encrypt (to Alice's `pre_pk`)
//! ```text
//! r, u ← Z_L
//! E = r·B,  V = u·B
//! s = u + r·H(E,V)
//! shared = (r+u)·pre_pk_A
//! K = KDF(shared);  C = AEAD_K(plaintext)
//! ```
//!
//! ## Decrypt original (Alice `pre_sk`)
//! ```text
//! shared = pre_sk_A · (E+V)
//! ```
//!
//! ## ReKeyGen (`pre_sk_A`, Bob `G_B`)
//! ```text
//! x ← Z_L;  X = x·B
//! d = H(X, G_B, x·G_B)
//! rk = pre_sk_A · d⁻¹
//! ```
//!
//! ## ReEncrypt
//! ```text
//! E' = rk·E,  V' = rk·V
//! ```
//!
//! ## Decrypt re-encrypted (Bob signing scalar)
//! ```text
//! d = H(X, G_B, sk_B·X)
//! shared = d · (E'+V')   // = pre_sk_A · (E+V)
//! ```

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::dem;
use crate::error::{Error, Result};
use crate::keys::{PrePublicKey, StellarPublicKey, StellarSecretKey};

const CAPSULE_SIZE: usize = 32 + 32 + 32; // E || V || s
const REENCRYPTED_SIZE: usize = 32 + 32 + 32 + CAPSULE_SIZE;

/// Capsule: KEM ciphertext binding the ephemeral shared secret to Alice's `pre_pk`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capsule {
    pub(crate) point_e: EdwardsPoint,
    pub(crate) point_v: EdwardsPoint,
    pub(crate) signature: Scalar,
}

impl Capsule {
    /// Serialize: compressed E (32) || compressed V (32) || s (32) = 96 bytes.
    pub fn to_bytes(&self) -> [u8; CAPSULE_SIZE] {
        let mut out = [0u8; CAPSULE_SIZE];
        out[..32].copy_from_slice(&self.point_e.compress().to_bytes());
        out[32..64].copy_from_slice(&self.point_v.compress().to_bytes());
        out[64..].copy_from_slice(&self.signature.to_bytes());
        out
    }

    /// Deserialize and verify capsule integrity proof.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CAPSULE_SIZE {
            return Err(Error::Encoding(format!(
                "capsule must be {CAPSULE_SIZE} bytes"
            )));
        }
        let point_e = decompress_point(&bytes[..32])?;
        let point_v = decompress_point(&bytes[32..64])?;
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&bytes[64..96]);
        let signature = Scalar::from_canonical_bytes(s_bytes)
            .into_option()
            .ok_or_else(|| Error::Encoding("invalid capsule scalar".into()))?;

        let capsule = Self {
            point_e,
            point_v,
            signature,
        };
        if !capsule.verify() {
            return Err(Error::CapsuleValidationFailed);
        }
        Ok(capsule)
    }

    fn verify(&self) -> bool {
        let h = hash_capsule_points(&self.point_e, &self.point_v);
        let lhs = self.signature * ED25519_BASEPOINT_POINT;
        let rhs = self.point_v + (h * self.point_e);
        lhs == rhs
    }
}

/// Full ciphertext: capsule + AEAD payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    /// KEM capsule binding the ephemeral shared secret.
    pub capsule: Capsule,
    /// `nonce || ciphertext || tag` from XChaCha20-Poly1305.
    pub payload: Vec<u8>,
}

impl Ciphertext {
    /// Serialize: capsule (96) || payload_len_le (4) || payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CAPSULE_SIZE + 4 + self.payload.len());
        out.extend_from_slice(&self.capsule.to_bytes());
        let len = self.payload.len() as u32;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Deserialize a ciphertext produced by [`Ciphertext::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < CAPSULE_SIZE + 4 {
            return Err(Error::Encoding("ciphertext too short".into()));
        }
        let capsule = Capsule::from_bytes(&bytes[..CAPSULE_SIZE])?;
        let len = u32::from_le_bytes(bytes[CAPSULE_SIZE..CAPSULE_SIZE + 4].try_into().unwrap())
            as usize;
        let payload_start = CAPSULE_SIZE + 4;
        if bytes.len() != payload_start + len {
            return Err(Error::Encoding("ciphertext length mismatch".into()));
        }
        Ok(Self {
            capsule,
            payload: bytes[payload_start..].to_vec(),
        })
    }
}

/// Re-encryption key Alice → Bob (proxy may hold this; cannot decrypt).
///
/// Binds Alice's **`pre_pk`** and Bob's Stellar **`G...`** (Ed25519) public key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ReencryptionKey {
    /// Scalar rk = pre_sk_A · d⁻¹
    pub(crate) rk: Scalar,
    /// Precursor X = x·B (public)
    pub(crate) precursor: EdwardsPoint,
    /// Bob's Ed25519 / `G...` public key bytes
    pub(crate) bob_ed25519: [u8; 32],
    /// Alice's PRE public key compressed bytes (not `G...`)
    pub(crate) alice_pre_pk: [u8; 32],
}

impl std::fmt::Debug for ReencryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReencryptionKey")
            .field("precursor", &self.precursor.compress().to_bytes())
            .field("alice_pre_pk", &self.alice_pre_pk)
            .field("bob_ed25519", &self.bob_ed25519)
            .finish_non_exhaustive()
    }
}

impl ReencryptionKey {
    /// Serialize: rk(32) || precursor(32) || alice_pre_pk(32) || bob_ed(32) = 128 bytes.
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[..32].copy_from_slice(&self.rk.to_bytes());
        out[32..64].copy_from_slice(&self.precursor.compress().to_bytes());
        out[64..96].copy_from_slice(&self.alice_pre_pk);
        out[96..128].copy_from_slice(&self.bob_ed25519);
        out
    }

    /// Deserialize a re-encryption key produced by [`ReencryptionKey::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 128 {
            return Err(Error::Encoding(
                "re-encryption key must be 128 bytes".into(),
            ));
        }
        let mut rk_bytes = [0u8; 32];
        rk_bytes.copy_from_slice(&bytes[..32]);
        let rk = Scalar::from_canonical_bytes(rk_bytes)
            .into_option()
            .ok_or(Error::InvalidReencryptionKey)?;
        if rk == Scalar::ZERO {
            return Err(Error::InvalidReencryptionKey);
        }
        let precursor = decompress_point(&bytes[32..64])?;
        let mut alice_pre_pk = [0u8; 32];
        alice_pre_pk.copy_from_slice(&bytes[64..96]);
        let mut bob_ed25519 = [0u8; 32];
        bob_ed25519.copy_from_slice(&bytes[96..128]);
        // Validate bound public keys decode
        let _ = PrePublicKey::from_bytes(&alice_pre_pk)?;
        let _ = StellarPublicKey::from_ed25519_bytes(&bob_ed25519)?;
        Ok(Self {
            rk,
            precursor,
            bob_ed25519,
            alice_pre_pk,
        })
    }

    /// Alice's PRE public key bound into this re-key.
    pub fn alice_pre_public(&self) -> Result<PrePublicKey> {
        PrePublicKey::from_bytes(&self.alice_pre_pk)
    }

    /// Bob's Stellar public key (`G...`) this re-key targets.
    pub fn bob_stellar_public(&self) -> Result<StellarPublicKey> {
        StellarPublicKey::from_ed25519_bytes(&self.bob_ed25519)
    }
}

/// Ciphertext re-encrypted for Bob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReencryptedCiphertext {
    /// Re-encrypted capsule component `E' = rk · E`.
    pub point_e_prime: EdwardsPoint,
    /// Re-encrypted capsule component `V' = rk · V`.
    pub point_v_prime: EdwardsPoint,
    /// Precursor point `X = x · B` from re-key generation.
    pub precursor: EdwardsPoint,
    /// Original capsule (needed for AEAD AAD + validation).
    pub original_capsule: Capsule,
    /// Original AEAD payload (unchanged by re-encryption).
    pub payload: Vec<u8>,
    /// Alice's PRE public key compressed bytes.
    pub alice_pre_pk: [u8; 32],
    /// Bob's Ed25519 / `G...` public key bytes.
    pub bob_ed25519: [u8; 32],
}

impl ReencryptedCiphertext {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REENCRYPTED_SIZE + 4 + self.payload.len() + 64);
        out.extend_from_slice(&self.point_e_prime.compress().to_bytes());
        out.extend_from_slice(&self.point_v_prime.compress().to_bytes());
        out.extend_from_slice(&self.precursor.compress().to_bytes());
        out.extend_from_slice(&self.original_capsule.to_bytes());
        out.extend_from_slice(&self.alice_pre_pk);
        out.extend_from_slice(&self.bob_ed25519);
        let len = self.payload.len() as u32;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Deserialize a re-encrypted ciphertext produced by [`ReencryptedCiphertext::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // E'(32) V'(32) prec(32) capsule(96) alice_pre(32) bob(32) len(4) payload
        let header = 32 + 32 + 32 + CAPSULE_SIZE + 32 + 32;
        if bytes.len() < header + 4 {
            return Err(Error::Encoding("reencrypted ciphertext too short".into()));
        }
        let point_e_prime = decompress_point(&bytes[0..32])?;
        let point_v_prime = decompress_point(&bytes[32..64])?;
        let precursor = decompress_point(&bytes[64..96])?;
        let original_capsule = Capsule::from_bytes(&bytes[96..96 + CAPSULE_SIZE])?;
        let mut alice_pre_pk = [0u8; 32];
        alice_pre_pk.copy_from_slice(&bytes[96 + CAPSULE_SIZE..96 + CAPSULE_SIZE + 32]);
        let mut bob_ed25519 = [0u8; 32];
        bob_ed25519
            .copy_from_slice(&bytes[96 + CAPSULE_SIZE + 32..96 + CAPSULE_SIZE + 64]);
        let len_off = header;
        let len = u32::from_le_bytes(bytes[len_off..len_off + 4].try_into().unwrap()) as usize;
        if bytes.len() != len_off + 4 + len {
            return Err(Error::Encoding(
                "reencrypted ciphertext length mismatch".into(),
            ));
        }
        Ok(Self {
            point_e_prime,
            point_v_prime,
            precursor,
            original_capsule,
            payload: bytes[len_off + 4..].to_vec(),
            alice_pre_pk,
            bob_ed25519,
        })
    }
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

fn decompress_point(bytes: &[u8]) -> Result<EdwardsPoint> {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    CompressedEdwardsY(arr)
        .decompress()
        .ok_or(Error::InvalidPublicKey)
}

fn hash_capsule_points(e: &EdwardsPoint, v: &EdwardsPoint) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"StellarRecrypt/capsule");
    hasher.update(e.compress().as_bytes());
    hasher.update(v.compress().as_bytes());
    let dig = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&dig);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// d = H(precursor, pk_B, dh_point) — non-interactive shared scalar for re-encryption.
fn hash_to_d(precursor: &EdwardsPoint, bob_pk: &EdwardsPoint, dh: &EdwardsPoint) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"StellarRecrypt/rekey-d");
    hasher.update(precursor.compress().as_bytes());
    hasher.update(bob_pk.compress().as_bytes());
    hasher.update(dh.compress().as_bytes());
    let dig = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&dig);
    let mut s = Scalar::from_bytes_mod_order_wide(&wide);
    if s == Scalar::ZERO {
        s = Scalar::ONE;
    }
    s
}

fn random_nonzero_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Scalar {
    loop {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let s = Scalar::from_bytes_mod_order_wide(&bytes);
        if s != Scalar::ZERO {
            return s;
        }
    }
}

// ---------------------------------------------------------------------------
// Public PRE API
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` to Alice's PRE public key (`pre_pk`).
///
/// Encryptors must obtain `pre_pk` from Alice (published). It is not a Stellar `G...`.
pub fn encrypt<R: CryptoRng + RngCore>(
    rng: &mut R,
    recipient_pre_pk: &PrePublicKey,
    plaintext: &[u8],
) -> Result<Ciphertext> {
    let r = random_nonzero_scalar(rng);
    let u = random_nonzero_scalar(rng);

    let point_e = r * ED25519_BASEPOINT_POINT;
    let point_v = u * ED25519_BASEPOINT_POINT;
    let h = hash_capsule_points(&point_e, &point_v);
    let signature = u + r * h;

    // shared = (r+u) * pre_pk_A
    let shared = (r + u) * recipient_pre_pk.point();
    let capsule = Capsule {
        point_e,
        point_v,
        signature,
    };

    let aad = capsule.to_bytes();
    let mut key = dem::kdf_from_point(&shared, b"encrypt");
    let payload = dem::seal(rng, &key, plaintext, &aad)?;
    dem::zeroize_key(&mut key);

    Ok(Ciphertext { capsule, payload })
}

/// Decrypt a ciphertext with Alice's Stellar secret (`pre_sk` via HKDF).
pub fn decrypt(alice_sk: &StellarSecretKey, ct: &Ciphertext) -> Result<Vec<u8>> {
    if !ct.capsule.verify() {
        return Err(Error::CapsuleValidationFailed);
    }
    // shared = pre_sk * (E+V)
    let shared = alice_sk.pre_scalar() * (ct.capsule.point_e + ct.capsule.point_v);
    let aad = ct.capsule.to_bytes();
    let mut key = dem::kdf_from_point(&shared, b"encrypt");
    let pt = dem::open(&key, &ct.payload, &aad);
    dem::zeroize_key(&mut key);
    pt
}

/// Generate a re-encryption key from Alice to Bob.
///
/// - `alice_sk`: Alice's `S...` (uses **pre_sk** only)
/// - `bob_pk`: Bob's Stellar **`G...`** (not a PRE key)
pub fn rekey_gen<R: CryptoRng + RngCore>(
    rng: &mut R,
    alice_sk: &StellarSecretKey,
    bob_pk: &StellarPublicKey,
) -> Result<ReencryptionKey> {
    let alice_pre_pk = alice_sk.pre_public_key();
    let x = random_nonzero_scalar(rng);
    let precursor = x * ED25519_BASEPOINT_POINT;
    let dh = x * bob_pk.point();
    let d = hash_to_d(&precursor, bob_pk.point(), &dh);
    let d_inv = d.invert();
    let rk = alice_sk.pre_scalar() * d_inv;

    Ok(ReencryptionKey {
        rk,
        precursor,
        bob_ed25519: *bob_pk.as_ed25519_bytes(),
        alice_pre_pk: alice_pre_pk.to_bytes(),
    })
}

/// Re-encrypt Alice ciphertext for Bob. Proxy learns nothing about the plaintext.
pub fn reencrypt(rekey: &ReencryptionKey, ct: &Ciphertext) -> Result<ReencryptedCiphertext> {
    if !ct.capsule.verify() {
        return Err(Error::CapsuleValidationFailed);
    }
    let e_prime = rekey.rk * ct.capsule.point_e;
    let v_prime = rekey.rk * ct.capsule.point_v;

    Ok(ReencryptedCiphertext {
        point_e_prime: e_prime,
        point_v_prime: v_prime,
        precursor: rekey.precursor,
        original_capsule: ct.capsule.clone(),
        payload: ct.payload.clone(),
        alice_pre_pk: rekey.alice_pre_pk,
        bob_ed25519: rekey.bob_ed25519,
    })
}

/// Decrypt a re-encrypted ciphertext with Bob's Stellar secret (`S...` signing scalar).
pub fn decrypt_reencrypted(
    bob_sk: &StellarSecretKey,
    reenc: &ReencryptedCiphertext,
) -> Result<Vec<u8>> {
    let bob_pk = bob_sk.stellar_public_key();
    if bob_pk.as_ed25519_bytes() != &reenc.bob_ed25519 {
        return Err(Error::DecryptionFailed);
    }

    // dh = signing_sk_B * precursor
    let dh = bob_sk.signing_scalar() * reenc.precursor;
    let d = hash_to_d(&reenc.precursor, bob_pk.point(), &dh);

    // shared = d * (E' + V') = pre_sk_A * (E + V)
    let shared = d * (reenc.point_e_prime + reenc.point_v_prime);

    // Consistency check against Alice's pre_pk
    let alice_pre_pk = PrePublicKey::from_bytes(&reenc.alice_pre_pk)?;
    let h = hash_capsule_points(
        &reenc.original_capsule.point_e,
        &reenc.original_capsule.point_v,
    );
    let d_inv = d.invert();
    let lhs = (reenc.original_capsule.signature * d_inv) * alice_pre_pk.point();
    let rhs = (h * reenc.point_e_prime) + reenc.point_v_prime;
    if lhs != rhs {
        return Err(Error::CapsuleValidationFailed);
    }

    let aad = reenc.original_capsule.to_bytes();
    let mut key = dem::kdf_from_point(&shared, b"encrypt");
    let pt = dem::open(&key, &reenc.payload, &aad);
    dem::zeroize_key(&mut key);
    pt
}

// ---------------------------------------------------------------------------
// Strkey convenience (only the paths that still make sense)
// ---------------------------------------------------------------------------

/// Decrypt with Alice's Stellar `S...` and the same HKDF `info` used at encrypt time.
pub fn decrypt_with_strkey(alice_s: &str, info: &[u8], ct: &Ciphertext) -> Result<Vec<u8>> {
    let sk = StellarSecretKey::from_strkey(alice_s, info)?;
    decrypt(&sk, ct)
}

/// Generate re-encryption key from Alice's `S...` and Bob's `G...`.
///
/// `info` must match the HKDF context used to derive Alice's `pre_sk` / `pre_pk`
/// for this ciphertext. Prefer [`crate::structured_info`] for per-purpose /
/// per-recipient isolation.
pub fn rekey_gen_strkey<R: CryptoRng + RngCore>(
    rng: &mut R,
    alice_s: &str,
    info: &[u8],
    bob_g: &str,
) -> Result<ReencryptionKey> {
    let alice = StellarSecretKey::from_strkey(alice_s, info)?;
    let bob = StellarPublicKey::from_strkey(bob_g)?;
    rekey_gen(rng, &alice, &bob)
}

/// Decrypt re-encrypted ciphertext with Bob's `S...` (signing scalar).
///
/// Only the signing scalar is used; HKDF `info` is irrelevant. A placeholder
/// is supplied when constructing [`StellarSecretKey`] internally.
pub fn decrypt_reencrypted_with_strkey(
    bob_s: &str,
    reenc: &ReencryptedCiphertext,
) -> Result<Vec<u8>> {
    // pre_sk is unused for re-encrypted decrypt; any explicit info is fine.
    let bob = StellarSecretKey::from_strkey(bob_s, b"")?;
    decrypt_reencrypted(&bob, reenc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::structured_info;
    use crate::keys::StellarKeyPair;
    use rand_core::OsRng;

    fn demo_info() -> Vec<u8> {
        structured_info(b"test", &[])
    }

    #[test]
    fn encrypt_decrypt_alice_pre() {
        let alice = StellarKeyPair::generate(&mut OsRng, &demo_info());
        let msg = b"stellar succession secret";
        let ct = encrypt(&mut OsRng, &alice.pre_public, msg).unwrap();
        let pt = decrypt(&alice.secret, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn full_pre_alice_pre_to_bob_g() {
        let info = demo_info();
        let alice = StellarKeyPair::generate(&mut OsRng, &info);
        let bob = StellarKeyPair::generate(&mut OsRng, &info);
        let msg = b"delegate this payload to bob";

        let ct = encrypt(&mut OsRng, &alice.pre_public, msg).unwrap();
        assert_eq!(decrypt(&alice.secret, &ct).unwrap(), msg);

        // rekey: Alice pre_sk + Bob G...
        let rk = rekey_gen(&mut OsRng, &alice.secret, &bob.stellar_public).unwrap();
        assert_eq!(
            rk.alice_pre_public().unwrap().to_bytes(),
            alice.pre_public.to_bytes()
        );
        assert_eq!(
            rk.bob_stellar_public().unwrap().to_strkey(),
            bob.stellar_public.to_strkey()
        );

        let reenc = reencrypt(&rk, &ct).unwrap();
        let pt = decrypt_reencrypted(&bob.secret, &reenc).unwrap();
        assert_eq!(pt, msg);

        let carol = StellarKeyPair::generate(&mut OsRng, &info);
        assert!(decrypt_reencrypted(&carol.secret, &reenc).is_err());
        // Bob cannot open original (needs pre_sk_A)
        assert!(decrypt(&bob.secret, &ct).is_err());
    }

    #[test]
    fn strkey_api() {
        let info = demo_info();
        let alice = StellarKeyPair::generate(&mut OsRng, &info);
        let bob = StellarKeyPair::generate(&mut OsRng, &info);
        let msg = b"via strkey API";

        let alice_s = alice.secret.to_strkey();
        let bob_g = bob.stellar_public.to_strkey();
        let bob_s = bob.secret.to_strkey();

        let pre_pk = PrePublicKey::from_stellar_secret_strkey(&alice_s, &info).unwrap();
        let ct = encrypt(&mut OsRng, &pre_pk, msg).unwrap();
        assert_eq!(decrypt_with_strkey(&alice_s, &info, &ct).unwrap(), msg);

        let rk = rekey_gen_strkey(&mut OsRng, &alice_s, &info, &bob_g).unwrap();
        let reenc = reencrypt(&rk, &ct).unwrap();
        assert_eq!(
            decrypt_reencrypted_with_strkey(&bob_s, &reenc).unwrap(),
            msg
        );
    }

    #[test]
    fn peer_info_pre_roundtrip() {
        use crate::keys::StellarSecretKey;

        let other_info = structured_info(b"other", &[]);
        let alice_kp = StellarKeyPair::generate(&mut OsRng, &other_info);
        let bob = StellarKeyPair::generate(&mut OsRng, &other_info);
        let seed = *alice_kp.secret.as_seed_bytes();
        let info = structured_info(b"rekey", bob.stellar_public.as_ed25519_bytes());

        let alice = StellarSecretKey::from_seed(&seed, &info).unwrap();
        let pre_pk = PrePublicKey::from_stellar_seed(&seed, &info).unwrap();
        let msg = b"peer-isolated payload";

        let ct = encrypt(&mut OsRng, &pre_pk, msg).unwrap();
        assert_eq!(decrypt(&alice, &ct).unwrap(), msg);

        // Different-info Alice key cannot open peer-isolated ciphertext.
        assert!(decrypt(&alice_kp.secret, &ct).is_err());

        let rk = rekey_gen(&mut OsRng, &alice, &bob.stellar_public).unwrap();
        let reenc = reencrypt(&rk, &ct).unwrap();
        assert_eq!(decrypt_reencrypted(&bob.secret, &reenc).unwrap(), msg);
    }

    #[test]
    fn serialization_roundtrip() {
        let info = demo_info();
        let alice = StellarKeyPair::generate(&mut OsRng, &info);
        let bob = StellarKeyPair::generate(&mut OsRng, &info);
        let msg = b"serde";
        let ct = encrypt(&mut OsRng, &alice.pre_public, msg).unwrap();
        let ct2 = Ciphertext::from_bytes(&ct.to_bytes()).unwrap();
        assert_eq!(decrypt(&alice.secret, &ct2).unwrap(), msg);

        let rk = rekey_gen(&mut OsRng, &alice.secret, &bob.stellar_public).unwrap();
        let rk2 = ReencryptionKey::from_bytes(&rk.to_bytes()).unwrap();
        let reenc = reencrypt(&rk2, &ct).unwrap();
        let reenc2 = ReencryptedCiphertext::from_bytes(&reenc.to_bytes()).unwrap();
        assert_eq!(decrypt_reencrypted(&bob.secret, &reenc2).unwrap(), msg);
    }

    #[test]
    fn wrong_key_fails() {
        let info = demo_info();
        let alice = StellarKeyPair::generate(&mut OsRng, &info);
        let eve = StellarKeyPair::generate(&mut OsRng, &info);
        let ct = encrypt(&mut OsRng, &alice.pre_public, b"secret").unwrap();
        assert!(decrypt(&eve.secret, &ct).is_err());
    }

    #[test]
    fn rekey_binds_pre_pk_not_stellar_g() {
        let info = demo_info();
        let alice = StellarKeyPair::generate(&mut OsRng, &info);
        let bob = StellarKeyPair::generate(&mut OsRng, &info);
        let rk = rekey_gen(&mut OsRng, &alice.secret, &bob.stellar_public).unwrap();
        // Alice binding is pre_pk, distinct from G...
        assert_ne!(
            rk.alice_pre_pk.as_slice(),
            alice.stellar_public.as_ed25519_bytes().as_slice()
        );
        assert_eq!(
            rk.alice_pre_pk.as_slice(),
            alice.pre_public.as_bytes().as_slice()
        );
    }
}
