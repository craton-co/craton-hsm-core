// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::pqc::*;
use craton_hsm::crypto::{digest, encrypt, keygen, sign};
use craton_hsm::pkcs11_abi::constants::*;

// ============================================================================
// RSA Benchmarks
// ============================================================================

fn bench_rsa_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("rsa_sign");
    for bits in [2048u32, 4096] {
        let (priv_key, _modulus, _pub_exp) = keygen::generate_rsa_key_pair(bits, false).unwrap();
        let data = vec![0u8; 32]; // SHA-256 sized input
        group.bench_with_input(BenchmarkId::from_parameter(bits), &bits, |b, _| {
            b.iter(|| {
                black_box(
                    sign::rsa_pkcs1v15_sign(
                        black_box(priv_key.as_bytes()),
                        black_box(&data),
                        Some(sign::HashAlg::Sha256),
                    )
                    .unwrap(),
                )
            })
        });
    }
    group.finish();
}

fn bench_rsa_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("rsa_verify");
    for bits in [2048u32, 4096] {
        let (priv_key, modulus, pub_exp) = keygen::generate_rsa_key_pair(bits, false).unwrap();
        let data = vec![0u8; 32];
        let signature =
            sign::rsa_pkcs1v15_sign(priv_key.as_bytes(), &data, Some(sign::HashAlg::Sha256))
                .unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(bits), &bits, |b, _| {
            b.iter(|| {
                black_box(
                    sign::rsa_pkcs1v15_verify(
                        black_box(&modulus),
                        black_box(&pub_exp),
                        black_box(&data),
                        black_box(&signature),
                        Some(sign::HashAlg::Sha256),
                    )
                    .unwrap(),
                )
            })
        });
    }
    group.finish();
}

// ============================================================================
// ECDSA Benchmarks
// ============================================================================

fn bench_ecdsa_p256_sign(c: &mut Criterion) {
    let (priv_key, _pub_key) = keygen::generate_ec_p256_key_pair().unwrap();
    let data = vec![0u8; 32];
    c.bench_function("ecdsa_p256_sign", |b| {
        b.iter(|| {
            black_box(
                sign::ecdsa_p256_sign(black_box(priv_key.as_bytes()), black_box(&data)).unwrap(),
            )
        })
    });
}

fn bench_ecdsa_p256_verify(c: &mut Criterion) {
    let (priv_key, pub_key) = keygen::generate_ec_p256_key_pair().unwrap();
    let data = vec![0u8; 32];
    let signature = sign::ecdsa_p256_sign(priv_key.as_bytes(), &data).unwrap();
    c.bench_function("ecdsa_p256_verify", |b| {
        b.iter(|| {
            black_box(
                sign::ecdsa_p256_verify(
                    black_box(&pub_key),
                    black_box(&data),
                    black_box(&signature),
                )
                .unwrap(),
            )
        })
    });
}

// ============================================================================
// Ed25519 Benchmarks
// ============================================================================

fn bench_ed25519_sign(c: &mut Criterion) {
    let (priv_key, _pub_key) = keygen::generate_ed25519_key_pair().unwrap();
    let data = vec![0u8; 64];
    c.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            black_box(sign::ed25519_sign(black_box(priv_key.as_bytes()), black_box(&data)).unwrap())
        })
    });
}

fn bench_ed25519_verify(c: &mut Criterion) {
    let (priv_key, pub_key) = keygen::generate_ed25519_key_pair().unwrap();
    let data = vec![0u8; 64];
    let signature = sign::ed25519_sign(priv_key.as_bytes(), &data).unwrap();
    c.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            black_box(
                sign::ed25519_verify(black_box(&pub_key), black_box(&data), black_box(&signature))
                    .unwrap(),
            )
        })
    });
}

// ============================================================================
// AES-GCM Benchmarks
// ============================================================================

fn bench_aes_gcm_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_encrypt");
    let key = keygen::generate_aes_key(32, false).unwrap();
    for size in [256usize, 4096, 65536] {
        let plaintext = vec![0u8; size];
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}B", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(
                        encrypt::aes_256_gcm_encrypt(
                            black_box(key.as_bytes()),
                            black_box(&plaintext),
                        )
                        .unwrap(),
                    )
                })
            },
        );
    }
    group.finish();
}

fn bench_aes_gcm_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_decrypt");
    let key = keygen::generate_aes_key(32, false).unwrap();
    for size in [256usize, 4096, 65536] {
        let plaintext = vec![0u8; size];
        let ciphertext = encrypt::aes_256_gcm_encrypt(key.as_bytes(), &plaintext).unwrap();
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}B", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(
                        encrypt::aes_256_gcm_decrypt(
                            black_box(key.as_bytes()),
                            black_box(&ciphertext),
                        )
                        .unwrap(),
                    )
                })
            },
        );
    }
    group.finish();
}

// ============================================================================
// SHA Digest Benchmarks
// ============================================================================

fn bench_sha256(c: &mut Criterion) {
    let data = vec![0u8; 4096];
    c.bench_function("sha256_4KB", |b| {
        b.iter(|| black_box(digest::compute_digest(CKM_SHA256, black_box(&data)).unwrap()))
    });
}

fn bench_sha512(c: &mut Criterion) {
    let data = vec![0u8; 4096];
    c.bench_function("sha512_4KB", |b| {
        b.iter(|| black_box(digest::compute_digest(CKM_SHA512, black_box(&data)).unwrap()))
    });
}

// ============================================================================
// ML-DSA (PQC) Benchmarks
// ============================================================================

fn bench_ml_dsa_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_sign");
    let message = vec![0u8; 64];

    let (sk44, _vk44) = ml_dsa_keygen(MlDsaVariant::MlDsa44).unwrap();
    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| {
            black_box(
                ml_dsa_sign(
                    black_box(sk44.as_bytes()),
                    black_box(&message),
                    MlDsaVariant::MlDsa44,
                )
                .unwrap(),
            )
        })
    });

    let (sk65, _vk65) = ml_dsa_keygen(MlDsaVariant::MlDsa65).unwrap();
    group.bench_function("ML-DSA-65", |b| {
        b.iter(|| {
            black_box(
                ml_dsa_sign(
                    black_box(sk65.as_bytes()),
                    black_box(&message),
                    MlDsaVariant::MlDsa65,
                )
                .unwrap(),
            )
        })
    });

    group.finish();
}

fn bench_ml_dsa_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_verify");
    let message = vec![0u8; 64];

    let (sk44, vk44) = ml_dsa_keygen(MlDsaVariant::MlDsa44).unwrap();
    let sig44 = ml_dsa_sign(sk44.as_bytes(), &message, MlDsaVariant::MlDsa44).unwrap();
    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| {
            black_box(
                ml_dsa_verify(
                    black_box(&vk44),
                    black_box(&message),
                    black_box(&sig44),
                    MlDsaVariant::MlDsa44,
                )
                .unwrap(),
            )
        })
    });

    let (sk65, vk65) = ml_dsa_keygen(MlDsaVariant::MlDsa65).unwrap();
    let sig65 = ml_dsa_sign(sk65.as_bytes(), &message, MlDsaVariant::MlDsa65).unwrap();
    group.bench_function("ML-DSA-65", |b| {
        b.iter(|| {
            black_box(
                ml_dsa_verify(
                    black_box(&vk65),
                    black_box(&message),
                    black_box(&sig65),
                    MlDsaVariant::MlDsa65,
                )
                .unwrap(),
            )
        })
    });

    group.finish();
}

// ============================================================================
// ML-KEM (PQC) Benchmarks
// ============================================================================

fn bench_ml_kem_encap(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_kem_encap");

    let (_dk512, ek512) = ml_kem_keygen(MlKemVariant::MlKem512).unwrap();
    group.bench_function("ML-KEM-512", |b| {
        b.iter(|| black_box(ml_kem_encapsulate(black_box(&ek512), MlKemVariant::MlKem512).unwrap()))
    });

    let (_dk768, ek768) = ml_kem_keygen(MlKemVariant::MlKem768).unwrap();
    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| black_box(ml_kem_encapsulate(black_box(&ek768), MlKemVariant::MlKem768).unwrap()))
    });

    group.finish();
}

fn bench_ml_kem_decap(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_kem_decap");

    let (dk512, ek512) = ml_kem_keygen(MlKemVariant::MlKem512).unwrap();
    let (ct512, _ss512) = ml_kem_encapsulate(&ek512, MlKemVariant::MlKem512).unwrap();
    group.bench_function("ML-KEM-512", |b| {
        b.iter(|| {
            black_box(
                ml_kem_decapsulate(
                    black_box(dk512.as_bytes()),
                    black_box(&ct512),
                    MlKemVariant::MlKem512,
                )
                .unwrap(),
            )
        })
    });

    let (dk768, ek768) = ml_kem_keygen(MlKemVariant::MlKem768).unwrap();
    let (ct768, _ss768) = ml_kem_encapsulate(&ek768, MlKemVariant::MlKem768).unwrap();
    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| {
            black_box(
                ml_kem_decapsulate(
                    black_box(dk768.as_bytes()),
                    black_box(&ct768),
                    MlKemVariant::MlKem768,
                )
                .unwrap(),
            )
        })
    });

    group.finish();
}

// ============================================================================
// Backend Comparative Benchmarks
// ============================================================================
//
// These benchmarks run identical operations through the CryptoBackend trait.
// The aws-lc-rs backend has moved to the craton_hsm-awslc crate (enterprise).
// To compare backends, add craton_hsm-awslc as a dev-dependency and push
// its AwsLcBackend into the backends vec below.

fn get_backends() -> Vec<(&'static str, Arc<dyn CryptoBackend>)> {
    let mut backends: Vec<(&'static str, Arc<dyn CryptoBackend>)> = Vec::new();

    #[cfg(feature = "rustcrypto-backend")]
    {
        use craton_hsm::crypto::rustcrypto_backend::RustCryptoBackend;
        backends.push(("RustCrypto", Arc::new(RustCryptoBackend)));
    }

    {
        use craton_hsm_awslc::AwsLcBackend;
        backends.push(("AwsLc", Arc::new(AwsLcBackend)));
    }

    backends
}

fn bench_backend_rsa_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend_rsa_sign_2048");
    for (name, backend) in get_backends() {
        let (priv_key, _modulus, _pub_exp) = backend.generate_rsa_key_pair(2048, false).unwrap();
        let data = vec![0u8; 32];
        group.bench_function(name, |b| {
            b.iter(|| {
                black_box(
                    backend
                        .rsa_pkcs1v15_sign(
                            black_box(priv_key.as_bytes()),
                            black_box(&data),
                            Some(sign::HashAlg::Sha256),
                        )
                        .unwrap(),
                )
            })
        });
    }
    group.finish();
}

fn bench_backend_rsa_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend_rsa_verify_2048");
    for (name, backend) in get_backends() {
        let (priv_key, modulus, pub_exp) = backend.generate_rsa_key_pair(2048, false).unwrap();
        let data = vec![0u8; 32];
        let signature = backend
            .rsa_pkcs1v15_sign(priv_key.as_bytes(), &data, Some(sign::HashAlg::Sha256))
            .unwrap();
        group.bench_function(name, |b| {
            b.iter(|| {
                black_box(
                    backend
                        .rsa_pkcs1v15_verify(
                            black_box(&modulus),
                            black_box(&pub_exp),
                            black_box(&data),
                            black_box(&signature),
                            Some(sign::HashAlg::Sha256),
                        )
                        .unwrap(),
                )
            })
        });
    }
    group.finish();
}

fn bench_backend_ecdsa_p256_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend_ecdsa_p256_sign");
    for (name, backend) in get_backends() {
        let (priv_key, _pub_key) = backend.generate_ec_p256_key_pair().unwrap();
        let data = vec![0u8; 32];
        group.bench_function(name, |b| {
            b.iter(|| {
                black_box(
                    backend
                        .ecdsa_p256_sign(black_box(priv_key.as_bytes()), black_box(&data))
                        .unwrap(),
                )
            })
        });
    }
    group.finish();
}

fn bench_backend_ecdsa_p256_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend_ecdsa_p256_verify");
    for (name, backend) in get_backends() {
        let (priv_key, pub_key) = backend.generate_ec_p256_key_pair().unwrap();
        let data = vec![0u8; 32];
        let signature = backend.ecdsa_p256_sign(priv_key.as_bytes(), &data).unwrap();
        group.bench_function(name, |b| {
            b.iter(|| {
                black_box(
                    backend
                        .ecdsa_p256_verify(
                            black_box(&pub_key),
                            black_box(&data),
                            black_box(&signature),
                        )
                        .unwrap(),
                )
            })
        });
    }
    group.finish();
}

fn bench_backend_aes_gcm_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend_aes_gcm_encrypt");
    for (name, backend) in get_backends() {
        let key = backend.generate_aes_key(32, false).unwrap();
        let plaintext = vec![0u8; 4096];
        group.bench_function(format!("{}/4KB", name), |b| {
            b.iter(|| {
                black_box(
                    backend
                        .aes_256_gcm_encrypt(black_box(key.as_bytes()), black_box(&plaintext))
                        .unwrap(),
                )
            })
        });
    }
    group.finish();
}

fn bench_backend_aes_gcm_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend_aes_gcm_decrypt");
    for (name, backend) in get_backends() {
        let key = backend.generate_aes_key(32, false).unwrap();
        let plaintext = vec![0u8; 4096];
        let ciphertext = backend
            .aes_256_gcm_encrypt(key.as_bytes(), &plaintext)
            .unwrap();
        group.bench_function(format!("{}/4KB", name), |b| {
            b.iter(|| {
                black_box(
                    backend
                        .aes_256_gcm_decrypt(black_box(key.as_bytes()), black_box(&ciphertext))
                        .unwrap(),
                )
            })
        });
    }
    group.finish();
}

fn bench_backend_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend_sha256");
    for (name, backend) in get_backends() {
        let data = vec![0u8; 4096];
        group.bench_function(format!("{}/4KB", name), |b| {
            b.iter(|| {
                black_box(
                    backend
                        .compute_digest(CKM_SHA256, black_box(&data))
                        .unwrap(),
                )
            })
        });
    }
    group.finish();
}

fn bench_backend_sha512(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend_sha512");
    for (name, backend) in get_backends() {
        let data = vec![0u8; 4096];
        group.bench_function(format!("{}/4KB", name), |b| {
            b.iter(|| {
                black_box(
                    backend
                        .compute_digest(CKM_SHA512, black_box(&data))
                        .unwrap(),
                )
            })
        });
    }
    group.finish();
}

fn bench_backend_keygen_rsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend_keygen_rsa_2048");
    group.sample_size(10); // RSA keygen is slow
    for (name, backend) in get_backends() {
        group.bench_function(name, |b| {
            b.iter(|| {
                black_box(
                    backend
                        .generate_rsa_key_pair(black_box(2048), false)
                        .unwrap(),
                )
            })
        });
    }
    group.finish();
}

fn bench_backend_keygen_ec_p256(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend_keygen_ec_p256");
    for (name, backend) in get_backends() {
        group.bench_function(name, |b| {
            b.iter(|| black_box(backend.generate_ec_p256_key_pair().unwrap()))
        });
    }
    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(rsa_benches, bench_rsa_sign, bench_rsa_verify,);

criterion_group!(
    ecdsa_benches,
    bench_ecdsa_p256_sign,
    bench_ecdsa_p256_verify,
);

criterion_group!(ed25519_benches, bench_ed25519_sign, bench_ed25519_verify,);

criterion_group!(aes_benches, bench_aes_gcm_encrypt, bench_aes_gcm_decrypt,);

criterion_group!(digest_benches, bench_sha256, bench_sha512,);

criterion_group!(
    pqc_benches,
    bench_ml_dsa_sign,
    bench_ml_dsa_verify,
    bench_ml_kem_encap,
    bench_ml_kem_decap,
);

criterion_group!(
    backend_comparison,
    bench_backend_rsa_sign,
    bench_backend_rsa_verify,
    bench_backend_ecdsa_p256_sign,
    bench_backend_ecdsa_p256_verify,
    bench_backend_aes_gcm_encrypt,
    bench_backend_aes_gcm_decrypt,
    bench_backend_sha256,
    bench_backend_sha512,
    bench_backend_keygen_rsa,
    bench_backend_keygen_ec_p256,
);

criterion_main!(
    rsa_benches,
    ecdsa_benches,
    ed25519_benches,
    aes_benches,
    digest_benches,
    pqc_benches,
    backend_comparison,
);
