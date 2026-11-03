// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! SIMD register scrubbing after cryptographic operations.
//!
//! AES-NI, SHA-NI and AVX2/AVX-512 code paths in the crypto backends leave
//! key-derived data in vector registers. `zeroize` only reaches memory, so the
//! PKCS#11 crypto entry points wipe the registers before control returns to the
//! caller: zmm0–31 and k0–k7 on AVX-512 hosts, ymm0–15 on AVX hosts, xmm0–15
//! otherwise. Inline `asm!` is volatile, so the compiler cannot elide the wipe.
//!
//! Windows x64 note: the low 128 bits of xmm6–15 are callee-saved, so the
//! compiler restores the *caller's* values there on return; everything the
//! crypto operation itself left behind (including the upper zmm6–15 bits) is
//! still cleared.

/// Zero all SIMD vector (and AVX-512 mask) registers the CPU supports.
/// No-op on non-x86_64 targets.
#[inline]
pub fn scrub_vector_registers() {
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    x86_64::scrub();
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Scrubs vector registers when dropped, including during panic unwinding.
/// Bind it first in a crypto entry point: `let _scrub = ScrubOnDrop;`
#[derive(Debug, Default)]
pub struct ScrubOnDrop;

impl ScrubOnDrop {
    /// Create a new scrub-on-drop guard.
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

impl Drop for ScrubOnDrop {
    #[inline]
    fn drop(&mut self) {
        scrub_vector_registers();
    }
}

#[cfg(all(target_arch = "x86_64", not(miri)))]
mod x86_64 {
    use std::arch::asm;

    pub(super) fn scrub() {
        // `is_x86_feature_detected!` caches CPUID, so this is a load + branch.
        if is_x86_feature_detected!("avx512f") {
            // SAFETY: AVX-512F support was verified at runtime just above.
            unsafe { scrub_avx512() }
        } else if is_x86_feature_detected!("avx") {
            // SAFETY: AVX support was verified at runtime just above.
            unsafe { scrub_avx() }
        } else {
            scrub_sse()
        }
    }

    #[inline(never)]
    #[target_feature(enable = "avx512f")]
    unsafe fn scrub_avx512() {
        // SAFETY: only zeroes registers, all declared as clobbers; no memory or
        // stack access. kxorw zero-extends to the full mask register width.
        // On Windows x64, xmm6–15 are callee-saved; declaring them as clobbers
        // causes the compiler to spill them to the stack and restore them,
        // leaking secrets and defeating the scrub. We zero all volatile ZMM
        // registers (0–5, 16–31), mask registers (k0–7), and use vzeroupper to
        // clear the upper bits of zmm6–15 without touching callee-saved xmm6–15.
        #[cfg(target_os = "windows")]
        unsafe {
            asm!(
                "vpxord zmm0, zmm0, zmm0",    "vpxord zmm1, zmm1, zmm1",
                "vpxord zmm2, zmm2, zmm2",    "vpxord zmm3, zmm3, zmm3",
                "vpxord zmm4, zmm4, zmm4",    "vpxord zmm5, zmm5, zmm5",
                "vpxord zmm16, zmm16, zmm16", "vpxord zmm17, zmm17, zmm17",
                "vpxord zmm18, zmm18, zmm18", "vpxord zmm19, zmm19, zmm19",
                "vpxord zmm20, zmm20, zmm20", "vpxord zmm21, zmm21, zmm21",
                "vpxord zmm22, zmm22, zmm22", "vpxord zmm23, zmm23, zmm23",
                "vpxord zmm24, zmm24, zmm24", "vpxord zmm25, zmm25, zmm25",
                "vpxord zmm26, zmm26, zmm26", "vpxord zmm27, zmm27, zmm27",
                "vpxord zmm28, zmm28, zmm28", "vpxord zmm29, zmm29, zmm29",
                "vpxord zmm30, zmm30, zmm30", "vpxord zmm31, zmm31, zmm31",
                "kxorw k0, k0, k0", "kxorw k1, k1, k1",
                "kxorw k2, k2, k2", "kxorw k3, k3, k3",
                "kxorw k4, k4, k4", "kxorw k5, k5, k5",
                "kxorw k6, k6, k6", "kxorw k7, k7, k7",
                "vzeroupper",
                out("zmm0") _, out("zmm1") _, out("zmm2") _, out("zmm3") _,
                out("zmm4") _, out("zmm5") _,
                out("zmm16") _, out("zmm17") _, out("zmm18") _, out("zmm19") _,
                out("zmm20") _, out("zmm21") _, out("zmm22") _, out("zmm23") _,
                out("zmm24") _, out("zmm25") _, out("zmm26") _, out("zmm27") _,
                out("zmm28") _, out("zmm29") _, out("zmm30") _, out("zmm31") _,
                out("k0") _, out("k1") _, out("k2") _, out("k3") _,
                out("k4") _, out("k5") _, out("k6") _, out("k7") _,
                options(nomem, nostack, preserves_flags),
            );
        }
        #[cfg(not(target_os = "windows"))]
        unsafe {
            asm!(
                "vpxord zmm0, zmm0, zmm0",    "vpxord zmm1, zmm1, zmm1",
                "vpxord zmm2, zmm2, zmm2",    "vpxord zmm3, zmm3, zmm3",
                "vpxord zmm4, zmm4, zmm4",    "vpxord zmm5, zmm5, zmm5",
                "vpxord zmm6, zmm6, zmm6",    "vpxord zmm7, zmm7, zmm7",
                "vpxord zmm8, zmm8, zmm8",    "vpxord zmm9, zmm9, zmm9",
                "vpxord zmm10, zmm10, zmm10", "vpxord zmm11, zmm11, zmm11",
                "vpxord zmm12, zmm12, zmm12", "vpxord zmm13, zmm13, zmm13",
                "vpxord zmm14, zmm14, zmm14", "vpxord zmm15, zmm15, zmm15",
                "vpxord zmm16, zmm16, zmm16", "vpxord zmm17, zmm17, zmm17",
                "vpxord zmm18, zmm18, zmm18", "vpxord zmm19, zmm19, zmm19",
                "vpxord zmm20, zmm20, zmm20", "vpxord zmm21, zmm21, zmm21",
                "vpxord zmm22, zmm22, zmm22", "vpxord zmm23, zmm23, zmm23",
                "vpxord zmm24, zmm24, zmm24", "vpxord zmm25, zmm25, zmm25",
                "vpxord zmm26, zmm26, zmm26", "vpxord zmm27, zmm27, zmm27",
                "vpxord zmm28, zmm28, zmm28", "vpxord zmm29, zmm29, zmm29",
                "vpxord zmm30, zmm30, zmm30", "vpxord zmm31, zmm31, zmm31",
                "kxorw k0, k0, k0", "kxorw k1, k1, k1",
                "kxorw k2, k2, k2", "kxorw k3, k3, k3",
                "kxorw k4, k4, k4", "kxorw k5, k5, k5",
                "kxorw k6, k6, k6", "kxorw k7, k7, k7",
                out("zmm0") _, out("zmm1") _, out("zmm2") _, out("zmm3") _,
                out("zmm4") _, out("zmm5") _, out("zmm6") _, out("zmm7") _,
                out("zmm8") _, out("zmm9") _, out("zmm10") _, out("zmm11") _,
                out("zmm12") _, out("zmm13") _, out("zmm14") _, out("zmm15") _,
                out("zmm16") _, out("zmm17") _, out("zmm18") _, out("zmm19") _,
                out("zmm20") _, out("zmm21") _, out("zmm22") _, out("zmm23") _,
                out("zmm24") _, out("zmm25") _, out("zmm26") _, out("zmm27") _,
                out("zmm28") _, out("zmm29") _, out("zmm30") _, out("zmm31") _,
                out("k0") _, out("k1") _, out("k2") _, out("k3") _,
                out("k4") _, out("k5") _, out("k6") _, out("k7") _,
                options(nomem, nostack, preserves_flags),
            );
        }
    }

    #[inline(never)]
    #[target_feature(enable = "avx")]
    unsafe fn scrub_avx() {
        // SAFETY: On SysV x64, vzeroall zeroes ymm0–15 without spilling.
        // On Windows x64, ymm6–15 have callee-saved lower 128 bits. We zero
        // volatile ymm0–5 and issue vzeroupper to clear the upper halves of all
        // YMM registers without spilling xmm6–15.
        #[cfg(target_os = "windows")]
        unsafe {
            asm!(
                "vpxor ymm0, ymm0, ymm0", "vpxor ymm1, ymm1, ymm1",
                "vpxor ymm2, ymm2, ymm2", "vpxor ymm3, ymm3, ymm3",
                "vpxor ymm4, ymm4, ymm4", "vpxor ymm5, ymm5, ymm5",
                "vzeroupper",
                out("ymm0") _, out("ymm1") _, out("ymm2") _,
                out("ymm3") _, out("ymm4") _, out("ymm5") _,
                options(nomem, nostack, preserves_flags),
            );
        }
        #[cfg(not(target_os = "windows"))]
        unsafe {
            asm!(
                "vzeroall",
                out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
                out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
                out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
                out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
                options(nomem, nostack, preserves_flags),
            );
        }
    }

    #[inline(never)]
    fn scrub_sse() {
        // SAFETY: On SysV x64, all XMM are volatile. On Windows x64, xmm0–5
        // are volatile while xmm6–15 are callee-saved and preserved by the caller.
        #[cfg(target_os = "windows")]
        unsafe {
            asm!(
                "pxor xmm0, xmm0", "pxor xmm1, xmm1", "pxor xmm2, xmm2",
                "pxor xmm3, xmm3", "pxor xmm4, xmm4", "pxor xmm5, xmm5",
                out("xmm0") _, out("xmm1") _, out("xmm2") _,
                out("xmm3") _, out("xmm4") _, out("xmm5") _,
                options(nomem, nostack, preserves_flags),
            );
        }
        #[cfg(not(target_os = "windows"))]
        unsafe {
            asm!(
                "pxor xmm0, xmm0",   "pxor xmm1, xmm1",   "pxor xmm2, xmm2",
                "pxor xmm3, xmm3",   "pxor xmm4, xmm4",   "pxor xmm5, xmm5",
                "pxor xmm6, xmm6",   "pxor xmm7, xmm7",   "pxor xmm8, xmm8",
                "pxor xmm9, xmm9",   "pxor xmm10, xmm10", "pxor xmm11, xmm11",
                "pxor xmm12, xmm12", "pxor xmm13, xmm13", "pxor xmm14, xmm14",
                "pxor xmm15, xmm15",
                out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
                out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
                options(nomem, nostack, preserves_flags),
            );
        }
    }

    #[cfg(test)]
    mod tests {
        use std::arch::asm;

        extern "C" fn scrub_c() {
            super::super::scrub_vector_registers();
        }

        /// Load a non-zero pattern into xmm1 (volatile on every x86_64 ABI),
        /// call the scrubber, and read xmm1 back.
        #[test]
        fn scrub_clears_xmm1() {
            let mut buf = [0xA5u8; 16];
            // SAFETY: r12 is callee-saved on SysV and Win64, so `buf`'s pointer
            // survives the call. The 32-byte reservation is the Win64 shadow
            // space and keeps the 16-byte alignment Rust guarantees on entry.
            unsafe {
                asm!(
                    "movdqu xmm1, [r12]",
                    "sub rsp, 32",
                    "call {f}",
                    "add rsp, 32",
                    "movdqu [r12], xmm1",
                    f = sym scrub_c,
                    in("r12") buf.as_mut_ptr(),
                    clobber_abi("C"),
                );
            }
            assert_eq!(buf, [0u8; 16]);
        }

        /// Same check for an AVX-512-only register (zmm31) and mask k7.
        #[test]
        fn scrub_clears_zmm31_and_k7() {
            if !is_x86_feature_detected!("avx512f") {
                eprintln!("skipping: host lacks AVX-512F");
                return;
            }
            let mut buf = [0xA5u8; 64];
            let mut mask: u16 = 0xFFFF;
            // SAFETY: AVX-512F verified above; same call discipline as above.
            unsafe { load_call_store_avx512(buf.as_mut_ptr(), &mut mask) };
            assert_eq!(buf, [0u8; 64]);
            assert_eq!(mask, 0);
        }

        #[target_feature(enable = "avx512f")]
        unsafe fn load_call_store_avx512(buf: *mut u8, mask: *mut u16) {
            // SAFETY: caller guarantees AVX-512F; buf is 64 bytes, mask is 2.
            unsafe {
                asm!(
                    "vmovdqu64 zmm31, [r12]",
                    "kmovw k7, word ptr [r13]",
                    "sub rsp, 32",
                    "call {f}",
                    "add rsp, 32",
                    "vmovdqu64 [r12], zmm31",
                    "kmovw word ptr [r13], k7",
                    f = sym scrub_c,
                    in("r12") buf,
                    in("r13") mask,
                    clobber_abi("C"),
                );
            }
        }
    }
}
