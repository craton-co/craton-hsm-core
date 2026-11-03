// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

//! Comprehensive AVX-512 Performance & Frequency Probe for Software HSM.
//!
//! Measures latency, throughput, downclocking behavior, and speedup factors
//! for all vectorized HSM crypto algorithms on the host CPU.

use std::hint::black_box;
use std::time::Instant;
use craton_hsm::crypto::vector_accel::{
    active_config, avx512_aes_cbc_decrypt, avx512_aes_ctr_crypt, detect_vector_capabilities,
    set_config,
};

mod benchmark_kernels {

    pub mod pqc_mlkem {
        pub const MLKEM_Q: i16 = 3329;
        pub const MLKEM_N: usize = 256;

        pub fn poly_add_scalar(a: &mut [i16; MLKEM_N], b: &[i16; MLKEM_N]) {
            for i in 0..MLKEM_N {
                a[i] = (a[i] + b[i]) % MLKEM_Q;
            }
        }

        pub fn poly_add_vector(a: &mut [i16; MLKEM_N], b: &[i16; MLKEM_N]) {
            #[cfg(target_arch = "x86_64")]
            if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512bw") {
                unsafe { poly_add_avx512(a, b) };
                return;
            }
            poly_add_scalar(a, b);
        }

        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx512f,avx512bw")]
        unsafe fn poly_add_avx512(a: &mut [i16; MLKEM_N], b: &[i16; MLKEM_N]) {
            use std::arch::x86_64::*;
            let v_q = _mm512_set1_epi16(MLKEM_Q);
            for i in 0..8 {
                let offset = i * 32;
                let va = _mm512_loadu_si512(a.as_ptr().add(offset) as *const __m512i);
                let vb = _mm512_loadu_si512(b.as_ptr().add(offset) as *const __m512i);
                let mut sum = _mm512_add_epi16(va, vb);
                let mask = _mm512_cmpge_epi16_mask(sum, v_q);
                sum = _mm512_mask_sub_epi16(sum, mask, sum, v_q);
                _mm512_storeu_si512(a.as_mut_ptr().add(offset) as *mut __m512i, sum);
            }
        }

        pub fn poly_mul_montgomery_scalar(out: &mut [i16; MLKEM_N], a: &[i16; MLKEM_N], b: &[i16; MLKEM_N]) {
            for i in 0..MLKEM_N {
                let prod = (a[i] as i32) * (b[i] as i32);
                let t = (prod as i16).wrapping_mul(-3327) as i32;
                let res = (prod - t * (MLKEM_Q as i32)) >> 16;
                out[i] = res as i16;
            }
        }

        pub fn poly_mul_montgomery_vector(out: &mut [i16; MLKEM_N], a: &[i16; MLKEM_N], b: &[i16; MLKEM_N]) {
            #[cfg(target_arch = "x86_64")]
            if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512bw") {
                unsafe { poly_mul_montgomery_avx512(out, a, b) };
                return;
            }
            poly_mul_montgomery_scalar(out, a, b);
        }

        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx512f,avx512bw")]
        unsafe fn poly_mul_montgomery_avx512(out: &mut [i16; MLKEM_N], a: &[i16; MLKEM_N], b: &[i16; MLKEM_N]) {
            use std::arch::x86_64::*;
            let v_q = _mm512_set1_epi16(MLKEM_Q);
            let v_qinv = _mm512_set1_epi16(-3327);
            for i in 0..8 {
                let offset = i * 32;
                let va = _mm512_loadu_si512(a.as_ptr().add(offset) as *const __m512i);
                let vb = _mm512_loadu_si512(b.as_ptr().add(offset) as *const __m512i);
                let prod_lo = _mm512_mullo_epi16(va, vb);
                let prod_hi = _mm512_mulhi_epi16(va, vb);
                let t = _mm512_mullo_epi16(prod_lo, v_qinv);
                let t_q_hi = _mm512_mulhi_epi16(t, v_q);
                let res = _mm512_sub_epi16(prod_hi, t_q_hi);
                _mm512_storeu_si512(out.as_mut_ptr().add(offset) as *mut __m512i, res);
            }
        }
    }

    pub mod pqc_mldsa {
        pub const MLDSA_Q: i32 = 8380417;
        pub const MLDSA_N: usize = 256;

        pub fn poly_add_scalar(a: &mut [i32; MLDSA_N], b: &[i32; MLDSA_N]) {
            for i in 0..MLDSA_N {
                let mut s = a[i] + b[i];
                if s >= MLDSA_Q {
                    s -= MLDSA_Q;
                }
                a[i] = s;
            }
        }

        pub fn poly_add_vector(a: &mut [i32; MLDSA_N], b: &[i32; MLDSA_N]) {
            #[cfg(target_arch = "x86_64")]
            if is_x86_feature_detected!("avx512f") {
                unsafe { poly_add_avx512(a, b) };
                return;
            }
            poly_add_scalar(a, b);
        }

        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx512f")]
        unsafe fn poly_add_avx512(a: &mut [i32; MLDSA_N], b: &[i32; MLDSA_N]) {
            use std::arch::x86_64::*;
            let v_q = _mm512_set1_epi32(MLDSA_Q);
            for i in 0..16 {
                let offset = i * 16;
                let va = _mm512_loadu_si512(a.as_ptr().add(offset) as *const __m512i);
                let vb = _mm512_loadu_si512(b.as_ptr().add(offset) as *const __m512i);
                let mut sum = _mm512_add_epi32(va, vb);
                let mask = _mm512_cmpge_epi32_mask(sum, v_q);
                sum = _mm512_mask_sub_epi32(sum, mask, sum, v_q);
                _mm512_storeu_si512(a.as_mut_ptr().add(offset) as *mut __m512i, sum);
            }
        }
    }

    pub mod sha3_keccak {
        pub fn keccak_f1600(state: &mut [u64; 25]) {
            const ROUND_CONSTANTS: [u64; 24] = [
                0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
                0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
                0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
                0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
                0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
                0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
            ];
            const RHO_ROTATIONS: [u32; 25] = [
                0,  1, 62, 28, 27,
                36, 44,  6, 55, 20,
                3, 10, 43, 25, 39,
                41, 45, 15, 21,  8,
                18,  2, 61, 56, 14,
            ];
            const PI_INDEX: [usize; 25] = [
                0, 10, 20, 5, 15,
                16, 1, 11, 21, 6,
                7, 17, 2, 12, 22,
                23, 8, 18, 3, 13,
                14, 24, 9, 19, 4,
            ];
            for &rc in &ROUND_CONSTANTS {
                let mut c = [0u64; 5];
                for x in 0..5 {
                    c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
                }
                let mut d = [0u64; 5];
                for x in 0..5 {
                    d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
                }
                for x in 0..5 {
                    for y in 0..5 {
                        state[x + y * 5] ^= d[x];
                    }
                }
                let mut b = [0u64; 25];
                for i in 0..25 {
                    b[PI_INDEX[i]] = state[i].rotate_left(RHO_ROTATIONS[i]);
                }
                for y in 0..5 {
                    let row = y * 5;
                    state[row + 0] = b[row + 0] ^ ((!b[row + 1]) & b[row + 2]);
                    state[row + 1] = b[row + 1] ^ ((!b[row + 2]) & b[row + 3]);
                    state[row + 2] = b[row + 2] ^ ((!b[row + 3]) & b[row + 4]);
                    state[row + 3] = b[row + 3] ^ ((!b[row + 4]) & b[row + 0]);
                    state[row + 4] = b[row + 4] ^ ((!b[row + 0]) & b[row + 1]);
                }
                state[0] ^= rc;
            }
        }
    }

    pub mod rsa_ifma {
        pub fn montgomery_mul_2048(
            out: &mut [u64; 32],
            a: &[u64; 32],
            b: &[u64; 32],
            n: &[u64; 32],
            n_prime: u64,
        ) {
            let mut t = [0u64; 65];
            for i in 0..32 {
                let mut carry: u128 = 0;
                for j in 0..32 {
                    let sum = (t[i + j] as u128) + (a[j] as u128) * (b[i] as u128) + carry;
                    t[i + j] = sum as u64;
                    carry = sum >> 64;
                }
                t[i + 32] = (t[i + 32] as u128 + carry) as u64;

                let m = t[i].wrapping_mul(n_prime);
                let mut carry_m: u128 = 0;
                for j in 0..32 {
                    let sum = (t[i + j] as u128) + (n[j] as u128) * (m as u128) + carry_m;
                    t[i + j] = sum as u64;
                    carry_m = sum >> 64;
                }
                t[i + 32] = (t[i + 32] as u128 + carry_m) as u64;
            }
            out.copy_from_slice(&t[32..64]);
        }
    }
}

use benchmark_kernels::*;

fn main() {
    println!("================================================================================");
    println!("CRATON SOFTWARE HSM — AVX-512 VECTOR ACCELERATION EMPIRICAL BENCHMARK");
    println!("================================================================================");

    // 1. Detect capabilities & confidential computing state
    let caps = detect_vector_capabilities();
    println!("CPU Vector Capabilities:");
    println!("  AVX-512F (Foundation):        {}", if caps.avx512f { "YES" } else { "NO" });
    println!("  AVX-512BW (Byte/Word):         {}", if caps.avx512bw { "YES" } else { "NO" });
    println!("  AVX-512DQ (Dword/Qword):       {}", if caps.avx512dq { "YES" } else { "NO" });
    println!("  AVX-512VL (Vector Length):     {}", if caps.avx512vl { "YES" } else { "NO" });
    println!("  AVX-512IFMA (52-bit BigInt):   {}", if caps.avx512ifma { "YES" } else { "NO" });
    println!("  VAES (Vector AES 512-bit):     {}", if caps.vaes { "YES" } else { "NO" });
    println!("  VPCLMULQDQ (Carryless Mul):    {}", if caps.vpclmulqdq { "YES" } else { "NO" });
    println!("  Confidential Enclave Support:  {}", if caps.enclave_xcr0_valid { "YES (XSAVE/XCR0 opmask + ZMM valid)" } else { "NO" });

    // 2. Frequency penalty check
    println!("\nTesting Frequency Penalty (Zen 4/5 Turin / Sapphire Rapids No-Downclocking Guarantee)...");
    let freq_before = read_cpu_freq_mhz();
    let stress_start = Instant::now();
    let mut stress_poly = [1234i16; 256];
    let stress_add = [5678i16; 256];
    while stress_start.elapsed().as_millis() < 500 {
        for _ in 0..10_000 {
            pqc_mlkem::poly_add_vector(black_box(&mut stress_poly), black_box(&stress_add));
        }
    }
    let freq_during = read_cpu_freq_mhz();
    match (freq_before, freq_during) {
        (Some(before), Some(during)) if before > 0.0 => {
            println!("  Frequency before AVX-512 stress: {:.2} MHz", before);
            println!("  Frequency during AVX-512 stress: {:.2} MHz", during);
            if during >= before * 0.95 {
                println!("  STATUS: CONFIRMED — Zero downclocking penalty detected under sustained AVX-512 load.");
            } else {
                println!("  STATUS: WARNING — Clock downclocking observed.");
            }
        }
        _ => {
            println!("  STATUS: CPU frequency scaling interface not available in current environment (OK on VM).");
        }
    }

    let mut results = Vec::new();

    // ------------------------------------------------------------------------
    // Benchmark 1: AES-256-CTR Throughput (64 KB Payload)
    // ------------------------------------------------------------------------
    {
        let key = [0x5au8; 32];
        let iv = [0x1fu8; 16];
        let data_64k = vec![0xa5u8; 64 * 1024];

        let iters = 20_000;
        // Scalar
        let mut cfg = active_config();
        cfg.aes_ctr_enabled = false;
        set_config(cfg);

        use ctr::cipher::{KeyIvInit, StreamCipher};
        type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

        let t0 = Instant::now();
        for _ in 0..iters {
            let mut buf = data_64k.clone();
            let mut cipher = Aes256Ctr::new_from_slices(&key, &iv).unwrap();
            cipher.apply_keystream(&mut buf);
            black_box(buf);
        }
        let elapsed_scalar = t0.elapsed();
        let scalar_mb_s = (64.0 * iters as f64) / elapsed_scalar.as_secs_f64() / 1024.0;

        // Vector
        cfg.aes_ctr_enabled = true;
        set_config(cfg);

        let t1 = Instant::now();
        for _ in 0..iters {
            let out = avx512_aes_ctr_crypt(black_box(&key), black_box(&iv), black_box(&data_64k)).unwrap();
            black_box(out);
        }
        let elapsed_vector = t1.elapsed();
        let vector_mb_s = (64.0 * iters as f64) / elapsed_vector.as_secs_f64() / 1024.0;

        results.push(BenchResult {
            algorithm: "AES-256 CTR (64 KB)".to_string(),
            scalar_metric: format!("{:.1} MB/s", scalar_mb_s),
            vector_metric: format!("{:.1} MB/s", vector_mb_s),
            speedup: vector_mb_s / scalar_mb_s,
            recommend_default: vector_mb_s > scalar_mb_s,
        });
    }

    // ------------------------------------------------------------------------
    // Benchmark 2: AES-256-CBC Decrypt Throughput (64 KB Payload)
    // ------------------------------------------------------------------------
    {
        let key = [0x7eu8; 32];
        let iv = [0x33u8; 16];
        let plaintext_64k = vec![0x11u8; 64 * 1024];

        use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        let enc = Aes256CbcEnc::new_from_slices(&key, &iv).unwrap();
        let ciphertext = enc.encrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(&plaintext_64k);

        let iters = 20_000;
        // Scalar
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
        let t0 = Instant::now();
        for _ in 0..iters {
            let dec = Aes256CbcDec::new_from_slices(&key, &iv).unwrap();
            let pt = dec.decrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(&ciphertext).unwrap();
            black_box(pt);
        }
        let elapsed_scalar = t0.elapsed();
        let scalar_mb_s = (64.0 * iters as f64) / elapsed_scalar.as_secs_f64() / 1024.0;

        // Vector
        let t1 = Instant::now();
        for _ in 0..iters {
            let pt = avx512_aes_cbc_decrypt(black_box(&key), black_box(&iv), black_box(&ciphertext)).unwrap();
            black_box(pt);
        }
        let elapsed_vector = t1.elapsed();
        let vector_mb_s = (64.0 * iters as f64) / elapsed_vector.as_secs_f64() / 1024.0;

        results.push(BenchResult {
            algorithm: "AES-256 CBC Decrypt (64 KB)".to_string(),
            scalar_metric: format!("{:.1} MB/s", scalar_mb_s),
            vector_metric: format!("{:.1} MB/s", vector_mb_s),
            speedup: vector_mb_s / scalar_mb_s,
            recommend_default: vector_mb_s > scalar_mb_s,
        });
    }

    // ------------------------------------------------------------------------
    // Benchmark 3: ML-KEM Polynomial Addition mod 3329 (256 coeffs)
    // ------------------------------------------------------------------------
    {
        let mut a = [1234i16; 256];
        let b = [2345i16; 256];

        let iters = 1_000_000;
        let t0 = Instant::now();
        for _ in 0..iters {
            pqc_mlkem::poly_add_scalar(black_box(&mut a), black_box(&b));
        }
        let elapsed_scalar = t0.elapsed();
        let scalar_ns = elapsed_scalar.as_nanos() as f64 / iters as f64;

        let t1 = Instant::now();
        for _ in 0..iters {
            pqc_mlkem::poly_add_vector(black_box(&mut a), black_box(&b));
        }
        let elapsed_vector = t1.elapsed();
        let vector_ns = elapsed_vector.as_nanos() as f64 / iters as f64;

        results.push(BenchResult {
            algorithm: "ML-KEM Poly Add mod 3329 (256 coeffs)".to_string(),
            scalar_metric: format!("{:.1} ns/op", scalar_ns),
            vector_metric: format!("{:.1} ns/op", vector_ns),
            speedup: scalar_ns / vector_ns,
            recommend_default: vector_ns < scalar_ns,
        });
    }

    // ------------------------------------------------------------------------
    // Benchmark 4: ML-KEM Montgomery Multiplication mod 3329 (256 coeffs)
    // ------------------------------------------------------------------------
    {
        let a = [1234i16; 256];
        let b = [2345i16; 256];
        let mut out = [0i16; 256];

        let iters = 500_000;
        let t0 = Instant::now();
        for _ in 0..iters {
            pqc_mlkem::poly_mul_montgomery_scalar(black_box(&mut out), black_box(&a), black_box(&b));
        }
        let elapsed_scalar = t0.elapsed();
        let scalar_ns = elapsed_scalar.as_nanos() as f64 / iters as f64;

        let t1 = Instant::now();
        for _ in 0..iters {
            pqc_mlkem::poly_mul_montgomery_vector(black_box(&mut out), black_box(&a), black_box(&b));
        }
        let elapsed_vector = t1.elapsed();
        let vector_ns = elapsed_vector.as_nanos() as f64 / iters as f64;

        results.push(BenchResult {
            algorithm: "ML-KEM Poly Montgomery Mul (256 coeffs)".to_string(),
            scalar_metric: format!("{:.1} ns/op", scalar_ns),
            vector_metric: format!("{:.1} ns/op", vector_ns),
            speedup: scalar_ns / vector_ns,
            recommend_default: vector_ns < scalar_ns,
        });
    }

    // ------------------------------------------------------------------------
    // Benchmark 5: ML-DSA Polynomial Addition mod 8380417 (256 coeffs)
    // ------------------------------------------------------------------------
    {
        let mut a = [1234567i32; 256];
        let b = [2345678i32; 256];

        let iters = 1_000_000;
        let t0 = Instant::now();
        for _ in 0..iters {
            pqc_mldsa::poly_add_scalar(black_box(&mut a), black_box(&b));
        }
        let elapsed_scalar = t0.elapsed();
        let scalar_ns = elapsed_scalar.as_nanos() as f64 / iters as f64;

        let t1 = Instant::now();
        for _ in 0..iters {
            pqc_mldsa::poly_add_vector(black_box(&mut a), black_box(&b));
        }
        let elapsed_vector = t1.elapsed();
        let vector_ns = elapsed_vector.as_nanos() as f64 / iters as f64;

        results.push(BenchResult {
            algorithm: "ML-DSA Poly Add mod 8380417 (256 coeffs)".to_string(),
            scalar_metric: format!("{:.1} ns/op", scalar_ns),
            vector_metric: format!("{:.1} ns/op", vector_ns),
            speedup: scalar_ns / vector_ns,
            recommend_default: vector_ns < scalar_ns,
        });
    }

    // ------------------------------------------------------------------------
    // Benchmark 6: Keccak-p[1600] / SHA-3 Permutation (24 rounds)
    // ------------------------------------------------------------------------
    {
        let mut s = [0x0123456789abcdefu64; 25];

        let iters = 200_000;
        let t0 = Instant::now();
        for _ in 0..iters {
            sha3_keccak::keccak_f1600(black_box(&mut s));
        }
        let elapsed_scalar = t0.elapsed();
        let scalar_ns = elapsed_scalar.as_nanos() as f64 / iters as f64;

        results.push(BenchResult {
            algorithm: "Keccak-p[1600] (24 rounds)".to_string(),
            scalar_metric: format!("{:.1} ns/op", scalar_ns),
            vector_metric: "N/A (Scalar preferred)".to_string(),
            speedup: 1.0,
            recommend_default: false,
        });
    }

    // ------------------------------------------------------------------------
    // Benchmark 7: RSA 2048-bit Montgomery Multiplication
    // ------------------------------------------------------------------------
    {
        let a = [0x5555555555555555u64; 32];
        let b = [0xaaaaaaaaaaaaaaaau64; 32];
        let n = [0xffffffffffffffffu64; 32];
        let n_prime = 0x1234567890abcdefu64;
        let mut out = [0u64; 32];

        let iters = 20_000;
        let t0 = Instant::now();
        for _ in 0..iters {
            rsa_ifma::montgomery_mul_2048(black_box(&mut out), black_box(&a), black_box(&b), black_box(&n), n_prime);
        }
        let elapsed_scalar = t0.elapsed();
        let scalar_ns = elapsed_scalar.as_nanos() as f64 / iters as f64;

        results.push(BenchResult {
            algorithm: "RSA-2048 Montgomery Mul".to_string(),
            scalar_metric: format!("{:.1} ns/op", scalar_ns),
            vector_metric: "N/A (IFMA disabled)".to_string(),
            speedup: 1.0,
            recommend_default: false,
        });
    }

    // ------------------------------------------------------------------------
    // Print Summary Table
    // ------------------------------------------------------------------------
    println!("\n| Cryptographic Algorithm | Scalar Baseline | AVX-512 Vector | Speedup | Empirically Enabled by Default? |");
    println!("|:------------------------|:----------------|:---------------|:--------|:--------------------------------|");
    for r in &results {
        println!(
            "| {:<24} | {:<15} | {:<14} | {:>6.2}x | {:<31} |",
            r.algorithm,
            r.scalar_metric,
            r.vector_metric,
            r.speedup,
            if r.recommend_default { "YES (default = true)" } else { "NO (default = false)" }
        );
    }
    println!("================================================================================");
}

struct BenchResult {
    algorithm: String,
    scalar_metric: String,
    vector_metric: String,
    speedup: f64,
    recommend_default: bool,
}

fn read_cpu_freq_mhz() -> Option<f64> {
    if let Ok(content) = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq") {
        if let Ok(khz) = content.trim().parse::<f64>() {
            return Some(khz / 1000.0);
        }
    }
    if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in content.lines() {
            if line.starts_with("cpu MHz") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Ok(mhz) = val.trim().parse::<f64>() {
                        return Some(mhz);
                    }
                }
            }
        }
    }
    None
}
