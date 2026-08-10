// One-shot generator for the RSA PKCS#1 v1.5 verify KAT vector embedded in
// src/crypto/self_test.rs. Run with the escape feature so the private-key
// operation is permitted:
//   cargo run --release --example gen_rsa_kat --features insecure-rustcrypto-rsa-private-ops
use craton_hsm::crypto::{keygen, sign};

fn hex_rust(name: &str, bytes: &[u8]) {
    println!("const {}: &[u8] = &[", name);
    for chunk in bytes.chunks(12) {
        let line: Vec<String> = chunk.iter().map(|b| format!("0x{:02x}", b)).collect();
        println!("    {},", line.join(", "));
    }
    println!("];");
}

fn main() {
    let (priv_key, modulus, pub_exp) = keygen::generate_rsa_key_pair(2048, false).unwrap();
    let message: &[u8] = b"FIPS POST RSA PKCS#1 v1.5 self-test";
    let sig = sign::rsa_pkcs1v15_sign(priv_key.as_bytes(), message, Some(sign::HashAlg::Sha256))
        .expect("signing must be permitted; run with insecure-rustcrypto-rsa-private-ops");
    let ok = sign::rsa_pkcs1v15_verify(
        &modulus,
        &pub_exp,
        message,
        &sig,
        Some(sign::HashAlg::Sha256),
    )
    .unwrap();
    assert!(ok, "generated vector must verify");
    println!(
        "// modulus {} bytes, exponent {} bytes, signature {} bytes",
        modulus.len(),
        pub_exp.len(),
        sig.len()
    );
    hex_rust("RSA_KAT_MODULUS", &modulus);
    hex_rust("RSA_KAT_PUBLIC_EXPONENT", &pub_exp);
    hex_rust("RSA_KAT_SIGNATURE", &sig);
}
