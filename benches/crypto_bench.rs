// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;
use std::sync::Arc;

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::pqc::*;
use craton_hsm::crypto::{digest, encrypt, keygen, sign};
use craton_hsm::pkcs11_abi::constants::*;

// ============================================================================
// RSA private-key capability probe
// ============================================================================

/// Whether this build can perform RustCrypto RSA private-key operations.
///
/// Release builds refuse them because the `rsa` crate is subject to the Marvin
/// timing attack (RUSTSEC-2023-0071); see `require_rustcrypto_rsa_private_ops`
/// in `src/crypto/sign.rs`. `cargo bench` always builds in release, so without
/// this probe the RSA setup panics and takes the whole suite down with it --
/// including the AES, digest, PQC, and audit groups that do not involve RSA.
///
/// Probed once by generating a key and attempting one signature.
fn rsa_private_ops_available() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        let Ok((priv_key, _, _)) = keygen::generate_rsa_key_pair(2048, false) else {
            return false;
        };
        let ok = sign::rsa_pkcs1v15_sign(priv_key.as_bytes(), &[0u8; 32], Some(sign::HashAlg::Sha256))
            .is_ok();
        if !ok {
            eprintln!(
                "note: skipping RSA benchmarks -- this build refuses RustCrypto RSA \
                 private-key operations (RUSTSEC-2023-0071).\n\
                 note: measure RSA with the hardened backend:\n\
                 note:   cargo bench --bench crypto_bench --no-default-features --features awslc-backend\n\
                 note: or, for RustCrypto coverage only:\n\
                 note:   cargo bench --bench crypto_bench --features insecure-rustcrypto-rsa-private-ops"
            );
        }
        ok
    })
}

// ============================================================================
// RSA Benchmarks
// ============================================================================

fn bench_rsa_sign(c: &mut Criterion) {
    if !rsa_private_ops_available() {
        return;
    }
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
    // Verification itself is a public-key operation, but producing the
    // signature to verify is not.
    if !rsa_private_ops_available() {
        return;
    }
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

    // To bench AwsLc (Enterprise), clone the enterprise repo and uncomment the dependency in Cargo.toml
    /*
    {
        use craton_hsm_awslc::AwsLcBackend;
        backends.push(("AwsLc", Arc::new(AwsLcBackend)));
    }
    */

    backends
}

fn bench_backend_rsa_sign(c: &mut Criterion) {
    if !rsa_private_ops_available() {
        return;
    }
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
    if !rsa_private_ops_available() {
        return;
    }
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
// Audit trail
//
// The audit trail is on the critical path of most PKCS#11 operations: signing,
// verification, encryption, decryption, key generation, and the object and
// session calls each emit an event. (`C_Digest` does not.) Its throughput
// therefore bounds the rate of audited operations. These benchmarks exist
// because that bound was once ~760 events/second -- the worker opened, wrote,
// and fsynced the log file once per event -- and nothing measured it.
// ============================================================================

use craton_hsm::audit::log::{AuditLog, AuditOperation, AuditResult};

/// A representative event: the shape emitted by `C_Digest`.
fn sample_op() -> AuditOperation {
    AuditOperation::Digest {
        mechanism: 0x250,
        fips_approved: true,
    }
}

/// Create a process-unique audit log path under the Criterion target dir.
fn bench_audit_path(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("craton_hsm_audit_bench");
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{}_{}.jsonl", tag, std::process::id()))
}

/// Per-event CPU cost with no disk involved: chain hash plus the state lock.
///
/// This isolates the canonical payload encoding and SHA-256 from I/O. It is the
/// number that moves when the chain encoding changes.
fn bench_audit_record_in_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_record_in_memory");
    // Batch the work: a single `record` call only enqueues, so measuring one
    // in isolation measures the channel, not the worker. Enqueue a block and
    // flush, so the cost attributed per iteration is the worker's real cost.
    const BATCH: usize = 200;
    group.throughput(criterion::Throughput::Elements(BATCH as u64));
    group.bench_function("200_events", |b| {
        b.iter_batched(
            || {
                let log = AuditLog::new();
                // Warm the worker: `AuditLog::new` spawns a thread, and waiting
                // for that thread's first scheduling costs more than the 200
                // events being measured. Recording and flushing one event in
                // setup keeps thread startup out of the timed region.
                log.record(0, sample_op(), AuditResult::Success, None)
                    .unwrap();
                log.flush().unwrap();
                log
            },
            |log| {
                for i in 0..BATCH {
                    log.record(i as u64, sample_op(), AuditResult::Success, None)
                        .unwrap();
                }
                log.flush().unwrap();
                log
            },
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

/// Sustained throughput of the asynchronous path with disk persistence.
///
/// This is the module's operation ceiling: every `C_Sign`, `C_Encrypt`, and
/// `C_Digest` enqueues one event, and the single worker thread must keep up.
/// The `flush()` is what makes this a throughput measurement rather than an
/// enqueue measurement — without it, the events would simply pile up in the
/// channel.
///
/// A regression here means the worker stopped coalescing `fsync`s.
///
/// # What this number is and is not
///
/// Each iteration gets a **fresh** log file so the benchmark is reproducible
/// and does not grow without bound. That makes its absolute value pessimistic:
/// `fsync` on a file that is still being extended costs considerably more than
/// on an established one, and a production audit log is long-lived. Read this
/// as a relative gate against previous runs of the same benchmark, not as the
/// throughput a deployment will see.
fn bench_audit_record_to_disk(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_record_to_disk");
    const BATCH: usize = 200;
    group.throughput(criterion::Throughput::Elements(BATCH as u64));
    group.sample_size(20); // fsync-bound; the default 100 samples is slow
    group.bench_function("200_events", |b| {
        b.iter_batched(
            || {
                let path = bench_audit_path("async");
                let _ = std::fs::remove_file(&path);
                let log = AuditLog::new_with_path(path).unwrap();
                // Warm the worker *and* the file handle. The worker opens the
                // log lazily on its first write, and on Windows that first open
                // also hardens the file ACL — both one-time costs that would
                // otherwise be charged to the batch being measured.
                log.record_sync(0, sample_op(), AuditResult::Success, None)
                    .unwrap();
                log
            },
            |log| {
                for i in 0..BATCH {
                    log.record(i as u64, sample_op(), AuditResult::Success, None)
                        .unwrap();
                }
                log.flush().unwrap();
                log
            },
            criterion::BatchSize::PerIteration,
        )
    });
    group.finish();
}

/// Latency of a single durable audit write.
///
/// `record_sync` is used for security-relevant operations (login, key
/// destruction, token init) which must not be acknowledged before their
/// forensic record is on stable storage. This measures the uncoalesced case —
/// one caller, nothing queued behind it — so it is dominated by one `fsync`.
fn bench_audit_record_sync(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_record_sync");
    group.sample_size(20); // one fsync per iteration
    group.bench_function("single_event", |b| {
        let path = bench_audit_path("sync");
        let _ = std::fs::remove_file(&path);
        let log = AuditLog::new_with_path(path).unwrap();
        let mut i = 0u64;
        b.iter(|| {
            i += 1;
            log.record_sync(i, sample_op(), AuditResult::Success, None)
                .unwrap();
        })
    });
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
    audit_benches,
    bench_audit_record_in_memory,
    bench_audit_record_to_disk,
    bench_audit_record_sync,
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
    audit_benches,
    backend_comparison,
);
