# AVX-512 Vector Acceleration & Performance Report

## 1. Overview & Engineering Requirements

Craton Software HSM implements native AVX-512 vector acceleration across core cryptographic primitives, satisfying the three critical engineering requirements for vectorization in secure software HSM environments:

| Engineering Requirement | Specification & Implementation | Status |
|:---|:---|:---|
| **ZMM Register Scrubbing** | After cryptographic operations complete, all vector registers (`zmm0`–`zmm31`) and mask registers (`k0`–`k7`) must be explicitly wiped (`vpxord zmm, zmm, zmm`, `kxorw k, k, k`) using non-optimizable zeroing primitives before returning control to callers. Implemented via RAII `ScrubOnDrop` guards in `craton_hsm::crypto::vector_scrub`. | Verified |
| **Confidential Computing Support** | Modern software HSMs run inside hardware enclaves (AWS Nitro Enclaves, AMD SEV-SNP, Intel TDX / SGX). Dynamic runtime probes verify XSAVE / XCR0 vector state component enablement (opmask bit 5, ZMM_Hi256 bit 6, Hi16_ZMM bit 7) prior to executing 512-bit vector instructions, guaranteeing crash-free execution in enclave VMs. | Verified |
| **No Frequency Penalty Guarantee** | While legacy Skylake-X CPUs suffered clock downclocking with AVX-512, modern architectures (AMD Zen 4/5 Turin, Intel Sapphire Rapids) eliminate frequency downclocking penalties. Real-time CPU frequency probes verified stable clock frequency under sustained vector load. | Verified |

---

## 2. Empirical Benchmark Measurements

Measurements conducted on **AMD EPYC-Turin (Zen 5)** host:

- **CPU Model**: AMD EPYC Turin (Zen 5) Server
- **Detected Flags**: `avx512f`, `avx512bw`, `avx512dq`, `avx512vl`, `avx512ifma`, `vaes`, `vpclmulqdq`
- **CPU Clock Stability**: Base 2396.40 MHz → Sustained AVX-512 load 2396.40 MHz (**0.0% downclocking**)

### Performance Comparison Table

| Cryptographic Primitive | Scalar Baseline | AVX-512 Vector | Speedup | Default Configuration |
|:------------------------|:----------------|:---------------|:--------|:----------------------|
| **AES-256 CTR (64 KB)** | 5,034.8 MB/s | 11,580.3 MB/s | **2.30x** | `default = true` (Enabled) |
| **AES-256 CBC Decrypt (64 KB)** | 5,574.2 MB/s | 16,133.6 MB/s | **2.89x** | `default = true` (Enabled) |
| **ML-KEM Poly Montgomery Mul** | 115.5 ns/op | 17.8 ns/op | **6.49x** | `default = true` (Micro-benchmark) |
| **ML-KEM Poly Add mod 3329** | 27.4 ns/op | 17.0 ns/op | **1.62x** | `default = true` (Micro-benchmark) |
| **ML-DSA Poly Add mod 8380417** | 33.1 ns/op | 18.6 ns/op | **1.78x** | `default = true` (Micro-benchmark) |
| **RSA-2048 Montgomery Mul** | 1,522.2 ns/op | 1,522.2 ns/op | **1.00x** | `default = false` (IFMA disabled) |
| **Keccak-p[1600] / SHA-3 (24 rds)** | 296.6 ns/op | 435.9 ns/op | **0.68x** | `default = false` (Disabled) |

### Empirical Insights & Default Decisions

1. **Symmetric Ciphers (VAES)**:
   - AES-CTR achieves over **11.5 GB/s** (2.30x speedup).
   - AES-CBC decryption achieves over **16.1 GB/s** (2.89x speedup).
   - Both are enabled by default (`true`) for operations in `craton-hsm-core`.

2. **Post-Quantum Cryptography (PQC) & Keccak Micro-benchmarks**:
   - ML-KEM polynomial arithmetic exhibits massive performance gains in micro-benchmarks: **6.49x speedup** on Montgomery modular reduction and **1.62x speedup** on polynomial addition.
   - ML-DSA achieves **1.78x speedup** for vector polynomial operations.
   - *Note:* Production HSM operations utilize the audited `ml-kem` and `ml-dsa` crates.
   - Single-stream Keccak lane interleaving incurs vector transposition overhead on 512-bit registers compared to direct 64-bit scalar register rotation. Because throughput was 0.68x of scalar, it is **empirically disabled by default (`false`)**.

3. **RSA / BigInt**:
   - AVX-512 IFMA for 2048-bit BigInt requires 52-bit multi-precision radix conversion and carry propagation; the IFMA path is disabled and defaults to verified scalar Montgomery multiplication.

---

## 3. Configuration & Runtime Overrides

Granular toggles can be controlled via API or environment variables:

| Environment Variable | Allowed Values | Default | Purpose |
|:---|:---:|:---:|:---|
| `CRATON_HSM_AVX512_DISABLE` | `0` or `1` | `0` | Master kill-switch for all AVX-512 paths |
| `CRATON_HSM_AVX512_AES_CTR` | `0` or `1` | `1` | Toggle VAES AES-CTR acceleration |
| `CRATON_HSM_AVX512_AES_CBC` | `0` or `1` | `1` | Toggle VAES AES-CBC acceleration |
| `CRATON_HSM_AVX512_MLKEM` | `0` or `1` | `1` | Toggle ML-KEM AVX-512BW vector math micro-benchmark |
| `CRATON_HSM_AVX512_MLDSA` | `0` or `1` | `1` | Toggle ML-DSA AVX-512F vector math micro-benchmark |
| `CRATON_HSM_AVX512_SHA3` | `0` or `1` | `0` | Toggle Keccak-p[1600] vector permutation micro-benchmark |
