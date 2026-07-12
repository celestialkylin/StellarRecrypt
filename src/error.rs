//! Error types for StellarRecrypt.

use thiserror::Error;

/// Library-wide error type.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid Stellar strkey (wrong prefix, length, or checksum).
    #[error("invalid stellar strkey: {0}")]
    InvalidStrkey(String),

    /// Invalid Ed25519 / Curve25519 public key encoding.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Invalid private key / seed.
    #[error("invalid private key")]
    InvalidPrivateKey,

    /// Ciphertext authentication failed or is malformed.
    #[error("decryption failed: authentication error or malformed ciphertext")]
    DecryptionFailed,

    /// Capsule or re-encrypted capsule failed integrity check.
    #[error("capsule validation failed")]
    CapsuleValidationFailed,

    /// Re-encryption key is invalid or mismatched.
    #[error("invalid re-encryption key")]
    InvalidReencryptionKey,

    /// Serialization / deserialization error.
    #[error("encoding error: {0}")]
    Encoding(String),

    /// Internal cryptographic failure.
    #[error("cryptographic error: {0}")]
    Crypto(String),
}

/// Convenient result alias.
pub type Result<T> = std::result::Result<T, Error>;
