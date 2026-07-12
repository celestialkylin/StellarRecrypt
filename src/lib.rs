//! # StellarRecrypt
//!
//! Stellar-oriented **Proxy Re-Encryption (PRE)** with **asymmetric key isolation**:
//!
//! - **Alice (delegator)**: `S...` seed → HKDF → `pre_sk` / `pre_pk` for encrypt, decrypt, rekey
//! - **Bob (delegatee)**: rekey uses his Stellar **`G...`**; decrypt re-encrypted with signing scalar from **`S...`**
//!
//! ## Capabilities
//!
//! 1. **Encrypt** to Alice's published `pre_pk` (not bare `G...`)
//! 2. **Decrypt** with Alice's `S...` (`pre_sk`)
//! 3. **ReKeyGen**: Alice `S...` + Bob `G...` → re-encryption key
//! 4. **ReEncrypt**: proxy transforms ciphertext without learning plaintext
//! 5. **Decrypt re-encrypted** with Bob's `S...` (signing scalar)
//!
//! ## Quick example
//!
//! ```
//! use stellar_recrypt::{
//!     decrypt, decrypt_reencrypted, encrypt, reencrypt, rekey_gen, StellarKeyPair,
//! };
//! use rand_core::OsRng;
//!
//! let alice = StellarKeyPair::generate(&mut OsRng);
//! let bob = StellarKeyPair::generate(&mut OsRng);
//!
//! // Encrypt to Alice's PRE public key (publish alice.pre_public)
//! let ct = encrypt(&mut OsRng, &alice.pre_public, b"hello").unwrap();
//! assert_eq!(decrypt(&alice.secret, &ct).unwrap(), b"hello");
//!
//! // Alice delegates to Bob's G...
//! let rk = rekey_gen(&mut OsRng, &alice.secret, &bob.stellar_public).unwrap();
//! let reenc = reencrypt(&rk, &ct).unwrap();
//! assert_eq!(decrypt_reencrypted(&bob.secret, &reenc).unwrap(), b"hello");
//! ```
//!
//! ## Strkey helpers
//!
//! ```
//! use stellar_recrypt::{
//!     decrypt_reencrypted_with_strkey, decrypt_with_strkey, encrypt, reencrypt,
//!     rekey_gen_strkey, PrePublicKey, StellarKeyPair,
//! };
//! use rand_core::OsRng;
//!
//! let alice = StellarKeyPair::generate(&mut OsRng);
//! let bob = StellarKeyPair::generate(&mut OsRng);
//! let msg = b"via strkeys";
//!
//! let pre_pk = PrePublicKey::from_stellar_secret_strkey(&alice.secret.to_strkey()).unwrap();
//! let ct = encrypt(&mut OsRng, &pre_pk, msg).unwrap();
//! assert_eq!(decrypt_with_strkey(&alice.secret.to_strkey(), &ct).unwrap(), msg);
//!
//! let rk = rekey_gen_strkey(
//!     &mut OsRng,
//!     &alice.secret.to_strkey(),
//!     &bob.stellar_public.to_strkey(),
//! )
//! .unwrap();
//! let reenc = reencrypt(&rk, &ct).unwrap();
//! assert_eq!(
//!     decrypt_reencrypted_with_strkey(&bob.secret.to_strkey(), &reenc).unwrap(),
//!     msg
//! );
//! ```

#![deny(missing_docs)]

mod convert;
mod dem;
mod error;
mod kdf;
mod keys;
mod pre;
mod strkey;

pub use error::{Error, Result};
pub use keys::{PrePublicKey, StellarKeyPair, StellarPublicKey, StellarSecretKey};
pub use pre::{
    decrypt, decrypt_reencrypted, decrypt_reencrypted_with_strkey, decrypt_with_strkey, encrypt,
    reencrypt, rekey_gen, rekey_gen_strkey, Capsule, Ciphertext, ReencryptedCiphertext,
    ReencryptionKey,
};
pub use strkey::{decode_public, decode_seed, encode_public, encode_seed};

/// Low-level Ed25519 ↔ X25519 conversion helpers (interop; not the PRE primary path).
pub mod x25519 {
    pub use crate::convert::{
        ed25519_public_from_seed, ed25519_public_to_x25519_public, ed25519_seed_to_x25519_private,
    };
}
