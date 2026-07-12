# StellarRecrypt

A Stellar-oriented **Proxy Re-Encryption (PRE)** library in Rust with **asymmetric key isolation**:

| Role | Keys | Use |
|------|------|-----|
| **Alice** (delegator) | `S...` → **HKDF** → `pre_sk` / `pre_pk` | Encryption target, self-decrypt, re-encryption key generation |
| **Bob** (delegatee) | Public **`G...`**; signing scalar from **`S...`** | Rekey target; decrypt re-encrypted ciphertexts |

Bob does **not** run HKDF. Rekey only needs his public `G...`. His `S...` is used only locally for decryption and is never sent as part of rekey generation.

## Features

1. Encrypt to Alice’s published **`pre_pk`** (not bare `G...`)
2. Alice decrypts with `S...` (internal `pre_sk`)
3. `rekey_gen(Alice_S, Bob_G)` produces a re-encryption key
4. Proxy re-encrypts without learning the plaintext
5. Bob decrypts re-encrypted data with `S...` (signing scalar)

## Quick start

```rust
use stellar_recrypt::{
    decrypt, decrypt_reencrypted, encrypt, reencrypt, rekey_gen, StellarKeyPair,
};
use rand_core::OsRng;

fn main() {
    let alice = StellarKeyPair::generate(&mut OsRng);
    let bob = StellarKeyPair::generate(&mut OsRng);

    // Encryptors use Alice's published pre_pk
    let ct = encrypt(&mut OsRng, &alice.pre_public, b"succession secret").unwrap();
    assert_eq!(decrypt(&alice.secret, &ct).unwrap(), b"succession secret");

    // Alice: pre_sk + Bob's G...
    let rk = rekey_gen(&mut OsRng, &alice.secret, &bob.stellar_public).unwrap();
    let reenc = reencrypt(&rk, &ct).unwrap();

    // Bob decrypts locally with S...
    assert_eq!(
        decrypt_reencrypted(&bob.secret, &reenc).unwrap(),
        b"succession secret"
    );
}
```

```bash
cargo test
cargo run --example basic
```

## Key model

```text
Alice S... seed
  ├─ Ed25519 ──► G_A          // account identity only
  └─ HKDF ────► pre_sk_A
                 pre_pk_A     // published encryption target

Bob
  G_B  ── rekey target (public)
  S_B  ── local signing scalar to decrypt re-encrypted ciphertext
```

HKDF parameters:

```text
HKDF-SHA256(
  ikm  = stellar_seed,
  salt = "StellarRecrypt-v1",
  info = "pre-encryption-scalar",
  L    = 64
) → pre_sk
```

## Security notes

| Threat | Outcome |
|--------|---------|
| Bob colludes with a proxy holding `rk` | Can recover `pre_sk_A`, **not** Alice’s signing seed / funds |
| Proxy alone | Cannot learn plaintext or private keys |
| Rekey with `G_B` | Does **not** leak `S_B` |
| Bob’s decryption key | Same lineage as signing; compromise of Bob’s secret affects his account |

This is a simplified single-hop, non-threshold PRE. It does **not** provide cryptographic collusion-safety in the pairing/AFGH sense. Assess independently before production use.

## API overview

| Type / function | Description |
|-----------------|-------------|
| `PrePublicKey` | Alice’s encryption public key (32-byte compressed point) |
| `StellarPublicKey` | Bob’s `G...` |
| `StellarSecretKey` | `S...`; holds `pre_sk` + signing scalar |
| `StellarKeyPair` | `secret` + `stellar_public` + `pre_public` |
| `encrypt(rng, &pre_pk, msg)` | Encrypt to Alice |
| `decrypt(&alice_sk, &ct)` | Alice decrypt |
| `rekey_gen(rng, &alice_sk, &bob_g)` | Generate `rk` |
| `reencrypt(&rk, &ct)` | Proxy re-encrypt |
| `decrypt_reencrypted(&bob_sk, &reenc)` | Bob decrypt |
| `rekey_gen_strkey` / `decrypt_*_with_strkey` | Strkey convenience helpers |

## License

MIT OR Apache-2.0
