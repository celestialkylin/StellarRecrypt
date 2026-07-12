# StellarRecrypt

A Stellar-oriented **Proxy Re-Encryption (PRE)** library in Rust with **asymmetric key isolation**:

| Role | Keys | Use |
|------|------|-----|
| **Alice** (delegator) | `S...` → **HKDF(`info`)** → `pre_sk` / `pre_pk` | Encryption target, self-decrypt, re-encryption key generation |
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
    decrypt, decrypt_reencrypted, encrypt, reencrypt, rekey_gen, structured_info,
    StellarKeyPair,
};
use rand_core::OsRng;

fn main() {
    // Required HKDF domain separation — pick a distinct info per purpose / recipient.
    let info = structured_info(b"demo-succession-v1", &[]);
    let alice = StellarKeyPair::generate(&mut OsRng, &info);
    let bob = StellarKeyPair::generate(&mut OsRng, &info);

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
  └─ HKDF(info) ► pre_sk_A
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
  info = <caller-provided, required>,
  L    = 64
) → pre_sk
```

There is **no library default** for `info`. Callers must pass it explicitly when
constructing Alice keys (`from_seed`, `from_strkey`, `generate`, `PrePublicKey::from_*`).

Use `structured_info` to compose purpose and peer fields safely:

```text
structured_info(arg_a, arg_b)
  → "pre-encryption-scalar" || 0x00 || arg_a' || 0x00 || arg_b'
```

If an argument is itself a prior `structured_info` output, it is unwrapped one layer
first (`PREFIX || PAD || x || PAD || y` restores to `x || PAD || y`). Both arguments may
be empty: `structured_info(&[], &[])` → `PREFIX || PAD || PAD`.

```rust
use stellar_recrypt::{
    decrypt, decrypt_reencrypted, encrypt, reencrypt, rekey_gen, structured_info,
    PrePublicKey, StellarKeyPair, StellarSecretKey,
};
use rand_core::OsRng;

let alice_seed = *StellarKeyPair::generate(&mut OsRng, &structured_info(b"seed-gen", &[]))
    .secret
    .as_seed_bytes();
let bob = StellarKeyPair::generate(&mut OsRng, &structured_info(b"bob-gen", &[]));

// Purpose + Bob's Ed25519 pubkey → isolated pre_sk / pre_pk for this pair
let info = structured_info(b"rekey", bob.stellar_public.as_ed25519_bytes());
let alice = StellarSecretKey::from_seed(&alice_seed, &info).unwrap();
let pre_pk = PrePublicKey::from_stellar_seed(&alice_seed, &info).unwrap();

let ct = encrypt(&mut OsRng, &pre_pk, b"only for this pair path").unwrap();
assert_eq!(decrypt(&alice, &ct).unwrap(), b"only for this pair path");

let rk = rekey_gen(&mut OsRng, &alice, &bob.stellar_public).unwrap();
let reenc = reencrypt(&rk, &ct).unwrap();
assert_eq!(decrypt_reencrypted(&bob.secret, &reenc).unwrap(), b"only for this pair path");
```

Use the **same** `info` when deriving `pre_sk` and `pre_pk`. Bob still does not run HKDF;
he decrypts re-encrypted data with his signing scalar from `S...`.

## Security notes

| Threat | Outcome |
|--------|---------|
| Bob colludes with a proxy holding `rk` | Can recover `pre_sk_A`, **not** Alice’s signing seed / funds |
| Proxy alone | Cannot learn plaintext or private keys |
| Rekey with `G_B` | Does **not** leak `S_B` |
| Bob’s decryption key | Same lineage as signing; compromise of Bob’s secret affects his account |

This is a simplified single-hop, non-threshold PRE. It does **not** provide cryptographic collusion-safety in the pairing/AFGH sense. Assess independently before production use.

### Domain separation (`info`) — required

HKDF `info` is **mandatory** (no `Option`, no library default). This is intentional:

1. **Why force callers to pass `info`?**  
   If a shared default existed, most applications would use it and Alice would have a
   **single global** `pre_sk` / `pre_pk`. Collusion that recovers that scalar (Bob + proxy
   with `rk`) would then decrypt **all** ciphertexts under the default `pre_pk`, across
   every unrelated purpose or recipient. Requiring an explicit `info` nudges callers to
   choose **different contexts**, limiting blast radius.

2. **What collusion still does**  
   Domain separation does **not** prevent collusion. Bob + proxy can still recover the
   `pre_sk` for the **same `info`** used to build that rekey. Isolation is per-`info`,
   not collusion-proof.

3. **Caller guidance**
   - Prefer **different `info` per purpose and/or per recipient**  
     (e.g. `structured_info(b"succession-v1", bob_pk)`).
   - Always use the **same `info`** when deriving matching `pre_sk` and `pre_pk`.
   - **Do not** reuse one global string across unrelated apps, tenants, or recipients.
   - Empty or constant `info` reintroduces cross-context blast radius.
   - Bob’s re-encrypted decrypt uses only the signing scalar; `decrypt_reencrypted_with_strkey`
     does not take `info`. If you build Bob’s key with `from_strkey` yourself, any explicit
     placeholder is fine.

## API overview

| Type / function | Description |
|-----------------|-------------|
| `PrePublicKey` | Alice’s encryption public key (32-byte compressed point) |
| `StellarPublicKey` | Bob’s `G...` |
| `StellarSecretKey` | `S...`; holds `pre_sk` + signing scalar; `from_seed(seed, info)` |
| `StellarKeyPair` | `secret` + `stellar_public` + `pre_public`; `generate(rng, info)` |
| `structured_info(a, b)` | Structured HKDF info: `PREFIX \|\| 0x00 \|\| a \|\| 0x00 \|\| b` |
| `encrypt(rng, &pre_pk, msg)` | Encrypt to Alice |
| `decrypt(&alice_sk, &ct)` | Alice decrypt |
| `rekey_gen(rng, &alice_sk, &bob_g)` | Generate `rk` |
| `reencrypt(&rk, &ct)` | Proxy re-encrypt |
| `decrypt_reencrypted(&bob_sk, &reenc)` | Bob decrypt |
| `decrypt_with_strkey(alice_s, info, ct)` | Alice decrypt via strkey |
| `rekey_gen_strkey(rng, alice_s, info, bob_g)` | Rekey via strkeys |
| `decrypt_reencrypted_with_strkey(bob_s, reenc)` | Bob decrypt via strkey (no `info`) |

## License

Licensed under either of:

- [MIT License](LICENSE-MIT) ([MIT](https://opensource.org/licenses/MIT))
- [Apache License, Version 2.0](LICENSE-APACHE) ([Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0))

at your option.

Copyright (c) 2026 Cele.Kln
