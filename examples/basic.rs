//! Asymmetric isolation demo: Alice pre_pk encrypt → Bob G... rekey → Bob S... decrypt.
//!
//! Run: `cargo run --example basic`

use rand_core::OsRng;
use stellar_recrypt::{
    decrypt, decrypt_reencrypted, encrypt, reencrypt, rekey_gen, StellarKeyPair,
};

fn main() {
    let alice = StellarKeyPair::generate(&mut OsRng);
    let bob = StellarKeyPair::generate(&mut OsRng);

    println!("Alice S: {}", alice.secret.to_strkey());
    println!("Alice G (account only): {}", alice.stellar_public.to_strkey());
    println!(
        "Alice pre_pk (publish for encrypt): {}",
        hex::encode(alice.pre_public.as_bytes())
    );
    println!("Bob   G (rekey target): {}", bob.stellar_public.to_strkey());
    println!("Bob   S (local decrypt only): {}", bob.secret.to_strkey());
    println!();

    let plaintext = b"Stellar succession account secret payload";
    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));

    // 1) Encrypt to Alice's pre_pk
    let ct = encrypt(&mut OsRng, &alice.pre_public, plaintext).expect("encrypt");
    println!("Ciphertext size: {} bytes", ct.to_bytes().len());

    let pt_alice = decrypt(&alice.secret, &ct).expect("alice decrypt");
    assert_eq!(pt_alice, plaintext);
    println!("Alice decrypt (pre_sk): OK");

    // 2) Rekey: Alice pre_sk + Bob G...
    let rk = rekey_gen(&mut OsRng, &alice.secret, &bob.stellar_public).expect("rekey");
    println!("Re-encryption key size: {} bytes", rk.to_bytes().len());

    // 3) Proxy re-encrypt
    let reenc = reencrypt(&rk, &ct).expect("reencrypt");
    println!(
        "Re-encrypted ciphertext size: {} bytes",
        reenc.to_bytes().len()
    );

    // 4) Bob decrypts with S... (signing scalar)
    let pt_bob = decrypt_reencrypted(&bob.secret, &reenc).expect("bob decrypt");
    assert_eq!(pt_bob, plaintext);
    println!("Bob decrypt after re-encryption: OK");
    println!();
    println!("All steps succeeded.");
}
