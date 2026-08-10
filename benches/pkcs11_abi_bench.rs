// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! PKCS#11 C ABI Benchmark Harness — Craton HSM vs SoftHSMv2
//!
//! Loads PKCS#11 shared libraries via `libloading`, calls `C_GetFunctionList`,
//! and benchmarks cryptographic operations through the C ABI boundary.
//!
//! This measures real-world performance including FFI overhead, `catch_unwind`,
//! and pointer marshalling — exactly what PKCS#11 consumers experience.
//!
//! ## Usage
//!
//! ```bash
//! # Craton HSM only (cargo bench builds --release automatically)
//! cargo bench --bench pkcs11_abi_bench
//!
//! # Head-to-head comparison with SoftHSMv2
//! SOFTHSM2_LIB=/usr/lib/softhsm/libsofthsm2.so cargo bench --bench pkcs11_abi_bench
//!
//! # Override Craton HSM library path
//! CRATON_HSM_LIB=path/to/libcraton_hsm.so cargo bench --bench pkcs11_abi_bench
//! ```

#![allow(non_snake_case)]

use criterion::measurement::WallTime;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion};
use libloading::{Library, Symbol};
use std::ptr;

// Re-use PKCS#11 type definitions from our crate (compile-time only; all runtime
// calls go through the dynamically-loaded library's function pointers).
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::types::*;

// ---------------------------------------------------------------------------
// Test-only credentials — NEVER use these for real HSM tokens.
// ---------------------------------------------------------------------------
/// Security Officer PIN used exclusively for benchmark token initialization.
const BENCH_SO_PIN: &[u8] = b"SoPin123";
/// User PIN used exclusively for benchmark session login.
const BENCH_USER_PIN: &[u8] = b"UserPin1";

// ===========================================================================
// Benchmark configuration
// ===========================================================================

/// Point Craton HSM at a scratch configuration under `target/`.
///
/// Without this the library falls back to its defaults, which put the audit
/// trail at `craton_hsm_audit.jsonl` **relative to the working directory** —
/// the repository root under `cargo bench`. That has two consequences worth
/// avoiding:
///
/// * it litters the repository, and a full benchmark run writes hundreds of
///   megabytes (the log rotates at 100 MB, keeping five generations);
/// * it perturbs the measurements. Every benchmarked operation appends to that
///   one growing file, so later groups run against a larger file than earlier
///   ones, and a 100 MB rotation landing mid-group shows up as a large outlier.
///
/// Redirecting to `target/bench-tokens/` keeps runs reproducible and the tree
/// clean. Audit logging stays **enabled** on purpose: it is part of the cost of
/// every PKCS#11 call and disabling it would flatter the numbers.
fn configure_bench_environment() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let dir = std::env::current_dir()
            .expect("Failed to get current directory")
            .join("target/bench-tokens");
        std::fs::create_dir_all(&dir).expect("Failed to create benchmark scratch directory");

        // TOML needs forward slashes (or escaped backslashes) on Windows.
        let dir_str = dir.to_string_lossy().replace('\\', "/");
        let conf_path = dir.join("craton_hsm.toml");
        let conf = format!(
            "# Craton HSM benchmark configuration (auto-generated; do not edit)\n\
             [audit]\n\
             enabled = true\n\
             log_path = \"{dir}/craton_hsm_audit.jsonl\"\n\
             log_level = \"all\"\n",
            dir = dir_str,
        );
        std::fs::write(&conf_path, conf).expect("Failed to write benchmark configuration");

        // Start each run from a clean audit trail so file growth from a previous
        // run does not carry into this one.
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("craton_hsm_audit.jsonl") {
                let _ = std::fs::remove_file(entry.path());
            }
        }

        std::env::set_var("CRATON_HSM_CONFIG", &conf_path);
    });
}

// ===========================================================================
// Library loading
// ===========================================================================

type GetFunctionListFn = unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV;

/// A loaded PKCS#11 shared library with a cached function-list pointer.
///
/// # Safety invariants
/// - `_lib` keeps the shared library loaded for the lifetime of this struct.
/// - `fn_list` is a pointer into the library's static data, valid as long as
///   `_lib` is alive. It is set once by `C_GetFunctionList` and never mutated.
/// - `fn_list` is stored as a raw pointer wrapper (`FnListPtr`) that implements
///   `Send` + `Sync` because `CK_FUNCTION_LIST` contains only immutable function
///   pointers — no mutable state, no thread-local data.
///
/// # Drop order
/// `_lib` MUST be declared before `fn_list` so the library handle outlives the
/// pointer derived from it (Rust drops fields in declaration order).
struct Pkcs11Lib {
    _lib: Library,
    fn_list: FnListPtr,
}

/// Newtype wrapper for `*mut CK_FUNCTION_LIST` to implement Send + Sync.
///
/// SAFETY: CK_FUNCTION_LIST contains only function pointers which are inherently
/// thread-safe (they point to code, not mutable data). The pointer is obtained
/// once from C_GetFunctionList and never written to again. The underlying Library
/// handle is kept alive by the owning Pkcs11Lib struct.
///
/// The compile-time assertion below ensures `CK_FUNCTION_LIST` is exactly the
/// size we expect (a struct of function pointers). If someone adds non-pointer
/// fields the assertion will fail, alerting us to re-audit Send/Sync safety.
#[derive(Clone, Copy)]
struct FnListPtr(*mut CK_FUNCTION_LIST);

// Compile-time guard: CK_FUNCTION_LIST contains a CK_VERSION (2 bytes) followed by
// function pointers. On Windows, PKCS#11 structs use #[repr(C, packed)] per the spec
// (#pragma pack(1)), so the struct size is 2 + N*ptr_size (not aligned).
// On other platforms, CK_VERSION is padded to pointer alignment.
// Either way, the struct is composed of immutable function pointers — Send+Sync is safe.
const _: () = {
    let size = std::mem::size_of::<CK_FUNCTION_LIST>();
    let ptr_size = std::mem::size_of::<usize>();
    let version_size = std::mem::size_of::<CK_VERSION>(); // 2 bytes
                                                          // On packed (Windows): size = 2 + N*ptr_size
                                                          // On non-packed: size = ptr_size + N*ptr_size (version padded to ptr alignment)
    let fn_ptrs_size = size
        - if cfg!(target_os = "windows") {
            version_size
        } else {
            ptr_size
        };
    assert!(
        fn_ptrs_size % ptr_size == 0,
        "CK_FUNCTION_LIST has unexpected non-pointer fields — re-audit Send/Sync"
    );
};

impl FnListPtr {
    /// Borrow the function list.
    ///
    /// # Safety
    ///
    /// The caller must ensure the owning `Pkcs11Lib` is still alive. In the
    /// concurrency benchmarks that is guaranteed by `std::thread::scope`,
    /// which joins every worker before the `BenchState` can be dropped.
    ///
    /// This is a method rather than a direct `&*ptr.0` at the use site so that
    /// a closure capturing it captures the whole `FnListPtr` (which is `Send`)
    /// rather than disjointly capturing the inner raw pointer (which is not).
    unsafe fn fns(&self) -> &CK_FUNCTION_LIST {
        &*self.0
    }
}

// SAFETY: See FnListPtr doc comment. Function pointers are Send+Sync.
// The compile-time assertion above guards against layout changes.
unsafe impl Send for FnListPtr {}
unsafe impl Sync for FnListPtr {}

impl Pkcs11Lib {
    fn load(path: &str) -> Self {
        // Validate the library path before loading to prevent loading from
        // unexpected locations (e.g., attacker-controlled env vars on shared CI).
        //
        // Canonicalize first to resolve symlinks and `..' components, then load
        // the resolved path. This eliminates TOCTOU between check and load since
        // we hand the canonical path directly to Library::new.
        let lib_path = std::path::Path::new(path);
        let canonical = lib_path.canonicalize().unwrap_or_else(|e| {
            panic!(
                "PKCS#11 library not found or not resolvable at '{}': {}",
                path, e
            )
        });
        assert!(
            canonical.is_file(),
            "PKCS#11 library path '{}' (resolved to '{}') is not a regular file",
            path,
            canonical.display()
        );

        // Verify the library has the expected file extension for the platform.
        let ext = canonical.extension().and_then(|e| e.to_str()).unwrap_or("");
        let valid_ext = if cfg!(target_os = "windows") {
            ext.eq_ignore_ascii_case("dll")
        } else if cfg!(target_os = "macos") {
            ext == "dylib"
        } else {
            ext == "so"
        };
        assert!(
            valid_ext,
            "PKCS#11 library '{}' has unexpected extension '.{}' — expected a shared library",
            canonical.display(),
            ext
        );

        eprintln!("Loading PKCS#11 library: {}", canonical.display());

        let lib = unsafe { Library::new(&canonical) }.unwrap_or_else(|e| {
            panic!(
                "Failed to load PKCS#11 library '{}': {}",
                canonical.display(),
                e
            )
        });

        let get_fn: Symbol<GetFunctionListFn> = unsafe { lib.get(b"C_GetFunctionList") }
            .unwrap_or_else(|e| panic!("C_GetFunctionList not found in '{}': {}", path, e));

        let mut fn_list: *mut CK_FUNCTION_LIST = ptr::null_mut();
        let rv = unsafe { get_fn(&mut fn_list) };
        assert_eq!(rv, CKR_OK, "C_GetFunctionList returned 0x{:08X}", rv);
        assert!(
            !fn_list.is_null(),
            "C_GetFunctionList returned null pointer"
        );

        Pkcs11Lib {
            _lib: lib,
            fn_list: FnListPtr(fn_list),
        }
    }

    /// Access the function list.
    ///
    /// SAFETY: The returned reference is valid for the lifetime of `&self` because
    /// `_lib` (which keeps the library loaded) is owned by the same struct.
    /// The function list is immutable after `C_GetFunctionList` — no synchronization
    /// is needed for read-only access to function pointers.
    fn fns(&self) -> &CK_FUNCTION_LIST {
        unsafe { &*self.fn_list.0 }
    }

    /// The raw function-list pointer, for handing to worker threads.
    ///
    /// `fns()` returns a reference borrowed from `&self`, which cannot cross a
    /// thread boundary in a scoped thread that also needs `&self` elsewhere.
    /// `FnListPtr` is `Send + Sync` (see its doc comment), so the concurrency
    /// benchmarks copy the pointer instead and re-borrow it inside each thread.
    fn fn_list_ptr(&self) -> FnListPtr {
        self.fn_list
    }
}

/// Determine the default path to Craton HSM's shared library.
///
/// Search order:
/// 1. `CRATON_HSM_LIB` environment variable (explicit override)
/// 2. `target/release/` (standard `cargo build --release` output)
/// 3. `target/release/deps/` (fallback — some cargo workflows place the
///    cdylib here when building benchmarks)
fn craton_hsm_library_path() -> String {
    if let Ok(path) = std::env::var("CRATON_HSM_LIB") {
        return path;
    }

    let (primary, fallback) = if cfg!(target_os = "windows") {
        (
            "target/release/craton_hsm.dll",
            "target/release/deps/craton_hsm.dll",
        )
    } else if cfg!(target_os = "macos") {
        (
            "target/release/libcraton_hsm.dylib",
            "target/release/deps/libcraton_hsm.dylib",
        )
    } else {
        (
            "target/release/libcraton_hsm.so",
            "target/release/deps/libcraton_hsm.so",
        )
    };

    if std::path::Path::new(primary).exists() {
        primary.to_string()
    } else if std::path::Path::new(fallback).exists() {
        fallback.to_string()
    } else {
        panic!(
            "Craton HSM shared library not found at '{}' or '{}'.\n\
             Build it first: cargo build --release --lib",
            primary, fallback
        );
    }
}

/// Prepare the environment for SoftHSMv2.
///
/// Creates the token directory and sets `SOFTHSM2_CONF` to point to a
/// generated config file with absolute paths.  Must be called **before**
/// loading SoftHSMv2.
///
/// Uses `std::sync::Once` to guarantee the environment mutation happens
/// exactly once, even if called from multiple threads.
fn setup_softhsm2_env() {
    use std::sync::Once;
    static SOFTHSM_ENV_INIT: Once = Once::new();

    SOFTHSM_ENV_INIT.call_once(|| {
        let abs_token_dir = std::env::current_dir()
            .expect("Failed to get current directory")
            .join("target/bench-tokens");
        std::fs::create_dir_all(&abs_token_dir)
            .expect("Failed to create SoftHSMv2 token directory");

        // Always generate the config with absolute paths so it works regardless
        // of the working directory. This overwrites any shipped config that may
        // contain relative paths.
        let conf_path = std::env::current_dir()
            .expect("Failed to get current directory")
            .join("benches/softhsm2.conf");
        let conf = format!(
            "# SoftHSMv2 configuration for benchmarks (auto-generated)\n\
             directories.tokendir = {}\n\
             objectstore.backend = file\n\
             log.level = ERROR\n",
            abs_token_dir.display()
        );
        std::fs::write(&conf_path, conf).expect("Failed to write softhsm2.conf");

        // SAFETY: `Once::call_once` guarantees this executes exactly once and
        // synchronizes-with all subsequent `call_once` calls. Criterion has not
        // yet spawned benchmark worker threads at this point — only the main
        // thread is running during library setup.
        unsafe {
            std::env::set_var("SOFTHSM2_CONF", &conf_path);
        }
    });
}

// ===========================================================================
// Benchmark state — one-time setup shared across all benchmark groups
// ===========================================================================

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

/// Pre-initialized PKCS#11 context: library loaded, token initialised,
/// session open, user logged in, keys generated, artifacts pre-computed.
struct BenchState {
    name: String,
    lib: Pkcs11Lib,
    session: CK_SESSION_HANDLE,
    /// Slot the benchmark token lives on, so additional sessions can be opened
    /// for the concurrency benchmarks.
    slot: CK_SLOT_ID,
    /// `None` when the library provides no RSA private-key capability, in
    /// which case every RSA group skips itself. See `try_gen_rsa_2048`.
    rsa_pub_key: Option<CK_OBJECT_HANDLE>,
    rsa_priv_key: Option<CK_OBJECT_HANDLE>,
    ec_pub_key: CK_OBJECT_HANDLE,
    ec_priv_key: CK_OBJECT_HANDLE,
    /// Pre-computed RSA signature over 32 zero-bytes (for verify benchmarks).
    /// `None` when the library refuses RSA private-key operations.
    rsa_signature: Option<Vec<u8>>,
    /// Pre-computed ECDSA signature over 32 zero-bytes (for verify benchmarks).
    ec_signature: Vec<u8>,
    /// AES-256 key handle — only set when AES-GCM with null params is supported.
    aes_key: Option<CK_OBJECT_HANDLE>,
    /// Pre-computed AES-GCM ciphertext of 4 KB plaintext (for decrypt benchmarks).
    aes_ciphertext: Option<Vec<u8>>,
}

impl BenchState {
    /// Create a benchmark context for a PKCS#11 library.
    ///
    /// `with_aes_gcm_null_params`: set `true` for Craton HSM (which uses auto-nonce
    /// GCM with null mechanism parameters).  Set `false` for SoftHSMv2 (which
    /// requires `CK_GCM_PARAMS` — a different ABI not directly comparable).
    fn create(name: &str, lib_path: &str, with_aes_gcm_null_params: bool) -> Self {
        let lib = Pkcs11Lib::load(lib_path);
        let f = lib.fns();

        // --- Initialize library (accept already-initialized for re-entrant runs) ---
        let rv = (f.C_Initialize)(ptr::null_mut());
        assert!(
            rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
            "{}: C_Initialize returned 0x{:08X}",
            name,
            rv
        );

        // --- Validate slot 0 exists and is a software token ---
        // This prevents accidentally reinitializing a real hardware HSM slot.
        let mut slot_count: CK_ULONG = 0;
        let rv = (f.C_GetSlotList)(CK_FALSE, ptr::null_mut(), &mut slot_count);
        assert_eq!(
            rv, CKR_OK,
            "{}: C_GetSlotList(count) returned 0x{:08X}",
            name, rv
        );
        assert!(
            slot_count > 0,
            "{}: No slots available — is the library configured?",
            name
        );

        let mut slots = vec![0 as CK_SLOT_ID; slot_count as usize];
        let rv = (f.C_GetSlotList)(CK_FALSE, slots.as_mut_ptr(), &mut slot_count);
        assert_eq!(rv, CKR_OK, "{}: C_GetSlotList returned 0x{:08X}", name, rv);

        let bench_slot = slots[0];

        // --- Init token (resets all objects & PINs) ---
        let mut label = [b' '; 32];
        label[..9].copy_from_slice(b"BenchTest");
        let rv = (f.C_InitToken)(
            bench_slot,
            BENCH_SO_PIN.as_ptr() as *mut _,
            BENCH_SO_PIN.len() as CK_ULONG,
            label.as_ptr() as *mut _,
        );
        assert_eq!(rv, CKR_OK, "{}: C_InitToken returned 0x{:08X}", name, rv);

        // --- Open RW session ---
        let mut session: CK_SESSION_HANDLE = 0;
        let rv = (f.C_OpenSession)(
            bench_slot,
            CKF_RW_SESSION | CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut session,
        );
        assert_eq!(rv, CKR_OK, "{}: C_OpenSession returned 0x{:08X}", name, rv);

        // --- Login as SO → init user PIN → logout → login as user ---
        let rv = (f.C_Login)(
            session,
            CKU_SO,
            BENCH_SO_PIN.as_ptr() as *mut _,
            BENCH_SO_PIN.len() as CK_ULONG,
        );
        assert_eq!(rv, CKR_OK, "{}: C_Login(SO) returned 0x{:08X}", name, rv);

        let rv = (f.C_InitPIN)(
            session,
            BENCH_USER_PIN.as_ptr() as *mut _,
            BENCH_USER_PIN.len() as CK_ULONG,
        );
        assert_eq!(rv, CKR_OK, "{}: C_InitPIN returned 0x{:08X}", name, rv);

        let rv = (f.C_Logout)(session);
        assert_eq!(rv, CKR_OK, "{}: C_Logout returned 0x{:08X}", name, rv);

        let rv = (f.C_Login)(
            session,
            CKU_USER,
            BENCH_USER_PIN.as_ptr() as *mut _,
            BENCH_USER_PIN.len() as CK_ULONG,
        );
        assert_eq!(rv, CKR_OK, "{}: C_Login(User) returned 0x{:08X}", name, rv);

        // --- Generate keys ---
        let rsa_keys = Self::try_gen_rsa_2048(f, session);
        if rsa_keys.is_none() {
            eprintln!(
                "note: {}: skipping RSA benchmarks -- the library refused RSA key-pair \
                 generation. Release builds refuse RustCrypto RSA private-key operations \
                 (RUSTSEC-2023-0071), and key-pair generation runs a pairwise consistency \
                 test that signs.\n\
                 note: measure RSA with the hardened backend:\n\
                 note:   cargo bench --bench pkcs11_abi_bench --no-default-features --features awslc-backend",
                name,
            );
        }
        let (rsa_pub_key, rsa_priv_key) = match rsa_keys {
            Some((pubk, privk)) => (Some(pubk), Some(privk)),
            None => (None, None),
        };
        let (ec_pub_key, ec_priv_key) = Self::gen_ec_p256(f, session);

        // --- Pre-compute artifacts for verify benchmarks ---
        let data_32 = [0u8; 32];
        // `None` when the library refuses RSA private-key operations; the RSA
        // groups skip themselves in that case rather than aborting the suite.
        let rsa_signature =
            rsa_priv_key.and_then(|k| Self::try_sign(f, session, CKM_SHA256_RSA_PKCS, k, &data_32));
        let ec_signature = Self::sign(f, session, CKM_ECDSA, ec_priv_key, &data_32);

        // --- AES-GCM (only for libraries supporting null-params GCM) ---
        let (aes_key, aes_ciphertext) = if with_aes_gcm_null_params {
            let key = Self::gen_aes_256(f, session);
            let plaintext_4kb = [0u8; 4096];
            let ct = Self::encrypt_aes_gcm(f, session, key, &plaintext_4kb);
            (Some(key), Some(ct))
        } else {
            (None, None)
        };

        // Populate the token with labelled objects for the C_FindObjects
        // benchmarks. Done once here so object creation (which persists and
        // fsyncs when the token is persistent) is not inside a measured loop.
        populate_find_objects(f, session);

        BenchState {
            name: name.to_string(),
            lib,
            session,
            slot: bench_slot,
            rsa_pub_key,
            rsa_priv_key,
            ec_pub_key,
            ec_priv_key,
            rsa_signature,
            ec_signature,
            aes_key,
            aes_ciphertext,
        }
    }

    fn fns(&self) -> &CK_FUNCTION_LIST {
        self.lib.fns()
    }

    /// Open an additional session on the benchmark token.
    ///
    /// PKCS#11 login state is a property of the token, not of the session, so
    /// a session opened after `C_Login` is already authenticated. `C_Login` is
    /// still attempted and `CKR_USER_ALREADY_LOGGED_IN` accepted, so this also
    /// works if the login ordering ever changes.
    fn open_logged_in_session(&self) -> CK_SESSION_HANDLE {
        let f = self.fns();
        let mut session: CK_SESSION_HANDLE = 0;
        let rv = (f.C_OpenSession)(
            self.slot,
            CKF_RW_SESSION | CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut session,
        );
        assert_eq!(rv, CKR_OK, "C_OpenSession returned 0x{:08X}", rv);

        let rv = (f.C_Login)(
            session,
            CKU_USER,
            BENCH_USER_PIN.as_ptr() as *mut _,
            BENCH_USER_PIN.len() as CK_ULONG,
        );
        assert!(
            rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN,
            "C_Login(User) on extra session returned 0x{:08X}",
            rv
        );
        session
    }

    // --- Key generation helpers ---

    /// Generate an RSA-2048 key pair, returning `None` if the library refuses.
    ///
    /// Wraps `gen_rsa_2048` so setup can degrade instead of aborting the suite.
    fn try_gen_rsa_2048(
        f: &CK_FUNCTION_LIST,
        session: CK_SESSION_HANDLE,
    ) -> Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
            p_parameter: ptr::null_mut(),
            parameter_len: 0,
        };
        let modulus_bits = ck_ulong_bytes(2048);
        let bool_true: CK_BBOOL = CK_TRUE;
        let mut pub_template = vec![
            CK_ATTRIBUTE {
                attr_type: CKA_MODULUS_BITS,
                p_value: modulus_bits.as_ptr() as CK_VOID_PTR,
                value_len: modulus_bits.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                attr_type: CKA_VERIFY,
                p_value: &bool_true as *const _ as CK_VOID_PTR,
                value_len: 1,
            },
        ];
        let mut priv_template = vec![CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &bool_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        }];
        let mut pub_key: CK_OBJECT_HANDLE = 0;
        let mut priv_key: CK_OBJECT_HANDLE = 0;
        let rv = (f.C_GenerateKeyPair)(
            session,
            &mut mechanism,
            pub_template.as_mut_ptr(),
            pub_template.len() as CK_ULONG,
            priv_template.as_mut_ptr(),
            priv_template.len() as CK_ULONG,
            &mut pub_key,
            &mut priv_key,
        );
        if rv == CKR_OK {
            Some((pub_key, priv_key))
        } else {
            None
        }
    }

    fn gen_rsa_2048(
        f: &CK_FUNCTION_LIST,
        session: CK_SESSION_HANDLE,
    ) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
            p_parameter: ptr::null_mut(),
            parameter_len: 0,
        };
        let modulus_bits = ck_ulong_bytes(2048);
        let bool_true: CK_BBOOL = CK_TRUE;

        let mut pub_template = vec![
            CK_ATTRIBUTE {
                attr_type: CKA_MODULUS_BITS,
                p_value: modulus_bits.as_ptr() as CK_VOID_PTR,
                value_len: modulus_bits.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                attr_type: CKA_VERIFY,
                p_value: &bool_true as *const _ as CK_VOID_PTR,
                value_len: 1,
            },
            CK_ATTRIBUTE {
                attr_type: CKA_ENCRYPT,
                p_value: &bool_true as *const _ as CK_VOID_PTR,
                value_len: 1,
            },
        ];
        let mut priv_template = vec![
            CK_ATTRIBUTE {
                attr_type: CKA_SIGN,
                p_value: &bool_true as *const _ as CK_VOID_PTR,
                value_len: 1,
            },
            CK_ATTRIBUTE {
                attr_type: CKA_DECRYPT,
                p_value: &bool_true as *const _ as CK_VOID_PTR,
                value_len: 1,
            },
        ];

        let mut pub_key: CK_OBJECT_HANDLE = 0;
        let mut priv_key: CK_OBJECT_HANDLE = 0;
        let rv = (f.C_GenerateKeyPair)(
            session,
            &mut mechanism,
            pub_template.as_mut_ptr(),
            pub_template.len() as CK_ULONG,
            priv_template.as_mut_ptr(),
            priv_template.len() as CK_ULONG,
            &mut pub_key,
            &mut priv_key,
        );
        assert_eq!(rv, CKR_OK, "RSA-2048 keygen returned 0x{:08X}", rv);
        (pub_key, priv_key)
    }

    fn gen_ec_p256(
        f: &CK_FUNCTION_LIST,
        session: CK_SESSION_HANDLE,
    ) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_EC_KEY_PAIR_GEN,
            p_parameter: ptr::null_mut(),
            parameter_len: 0,
        };
        // P-256 OID: 1.2.840.10045.3.1.7
        let ec_params: Vec<u8> = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        let bool_true: CK_BBOOL = CK_TRUE;

        let mut pub_template = vec![
            CK_ATTRIBUTE {
                attr_type: CKA_EC_PARAMS,
                p_value: ec_params.as_ptr() as CK_VOID_PTR,
                value_len: ec_params.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                attr_type: CKA_VERIFY,
                p_value: &bool_true as *const _ as CK_VOID_PTR,
                value_len: 1,
            },
        ];
        let mut priv_template = vec![CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &bool_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        }];

        let mut pub_key: CK_OBJECT_HANDLE = 0;
        let mut priv_key: CK_OBJECT_HANDLE = 0;
        let rv = (f.C_GenerateKeyPair)(
            session,
            &mut mechanism,
            pub_template.as_mut_ptr(),
            pub_template.len() as CK_ULONG,
            priv_template.as_mut_ptr(),
            priv_template.len() as CK_ULONG,
            &mut pub_key,
            &mut priv_key,
        );
        assert_eq!(rv, CKR_OK, "EC P-256 keygen returned 0x{:08X}", rv);
        (pub_key, priv_key)
    }

    fn gen_aes_256(f: &CK_FUNCTION_LIST, session: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_KEY_GEN,
            p_parameter: ptr::null_mut(),
            parameter_len: 0,
        };
        let value_len = ck_ulong_bytes(32);
        let bool_true: CK_BBOOL = CK_TRUE;

        let mut template = vec![
            CK_ATTRIBUTE {
                attr_type: CKA_VALUE_LEN,
                p_value: value_len.as_ptr() as CK_VOID_PTR,
                value_len: value_len.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                attr_type: CKA_ENCRYPT,
                p_value: &bool_true as *const _ as CK_VOID_PTR,
                value_len: 1,
            },
            CK_ATTRIBUTE {
                attr_type: CKA_DECRYPT,
                p_value: &bool_true as *const _ as CK_VOID_PTR,
                value_len: 1,
            },
        ];

        let mut key: CK_OBJECT_HANDLE = 0;
        let rv = (f.C_GenerateKey)(
            session,
            &mut mechanism,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut key,
        );
        assert_eq!(rv, CKR_OK, "AES-256 keygen returned 0x{:08X}", rv);
        key
    }

    // --- Crypto operation helpers ---

    /// Sign, returning `None` instead of panicking if the library refuses the
    /// mechanism.
    ///
    /// Release builds refuse RustCrypto RSA private-key operations because the
    /// `rsa` crate is subject to the Marvin timing attack (RUSTSEC-2023-0071),
    /// and `cargo bench` always builds in release. Without this, precomputing
    /// the RSA signature during setup panicked and took the entire suite down
    /// with it -- including every group unrelated to RSA.
    fn try_sign(
        f: &CK_FUNCTION_LIST,
        session: CK_SESSION_HANDLE,
        mech_type: CK_MECHANISM_TYPE,
        key: CK_OBJECT_HANDLE,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        let mut mech = CK_MECHANISM {
            mechanism: mech_type,
            p_parameter: ptr::null_mut(),
            parameter_len: 0,
        };
        if (f.C_SignInit)(session, &mut mech, key) != CKR_OK {
            return None;
        }
        let mut sig = vec![0u8; 512];
        let mut sig_len: CK_ULONG = sig.len() as CK_ULONG;
        if (f.C_Sign)(
            session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            sig.as_mut_ptr(),
            &mut sig_len,
        ) != CKR_OK
        {
            return None;
        }
        if (sig_len as usize) > sig.len() {
            return None;
        }
        sig.truncate(sig_len as usize);
        Some(sig)
    }

    fn sign(
        f: &CK_FUNCTION_LIST,
        session: CK_SESSION_HANDLE,
        mech_type: CK_MECHANISM_TYPE,
        key: CK_OBJECT_HANDLE,
        data: &[u8],
    ) -> Vec<u8> {
        let mut mech = CK_MECHANISM {
            mechanism: mech_type,
            p_parameter: ptr::null_mut(),
            parameter_len: 0,
        };
        let rv = (f.C_SignInit)(session, &mut mech, key);
        assert_eq!(
            rv, CKR_OK,
            "C_SignInit(0x{:08X}) returned 0x{:08X}",
            mech_type, rv
        );

        let mut sig = vec![0u8; 512];
        let mut sig_len: CK_ULONG = sig.len() as CK_ULONG;
        let rv = (f.C_Sign)(
            session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            sig.as_mut_ptr(),
            &mut sig_len,
        );
        assert_eq!(
            rv, CKR_OK,
            "C_Sign(0x{:08X}) returned 0x{:08X}",
            mech_type, rv
        );
        assert!(
            (sig_len as usize) <= sig.len(),
            "C_Sign returned sig_len {} exceeding buffer size {}",
            sig_len,
            sig.len()
        );
        sig.truncate(sig_len as usize);
        sig
    }

    fn encrypt_aes_gcm(
        f: &CK_FUNCTION_LIST,
        session: CK_SESSION_HANDLE,
        key: CK_OBJECT_HANDLE,
        data: &[u8],
    ) -> Vec<u8> {
        let mut mech = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            p_parameter: ptr::null_mut(),
            parameter_len: 0,
        };
        let rv = (f.C_EncryptInit)(session, &mut mech, key);
        assert_eq!(rv, CKR_OK, "C_EncryptInit(AES-GCM) returned 0x{:08X}", rv);

        // Output buffer: nonce(12) + ciphertext(len) + tag(16)
        let mut out = vec![0u8; data.len() + 256];
        let mut out_len: CK_ULONG = out.len() as CK_ULONG;
        let rv = (f.C_Encrypt)(
            session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut out_len,
        );
        assert_eq!(rv, CKR_OK, "C_Encrypt(AES-GCM) returned 0x{:08X}", rv);
        assert!(
            (out_len as usize) <= out.len(),
            "C_Encrypt returned out_len {} exceeding buffer size {}",
            out_len,
            out.len()
        );
        out.truncate(out_len as usize);
        out
    }
}

impl Drop for BenchState {
    fn drop(&mut self) {
        let f = self.lib.fns();
        // Destroy key objects explicitly before closing the session.
        // C_Finalize would clean up anyway, but explicit cleanup is safer if
        // an earlier step panics or the library doesn't fully clean up on finalize.
        if let Some(k) = self.rsa_pub_key {
            let _ = (f.C_DestroyObject)(self.session, k);
        }
        if let Some(k) = self.rsa_priv_key {
            let _ = (f.C_DestroyObject)(self.session, k);
        }
        let _ = (f.C_DestroyObject)(self.session, self.ec_pub_key);
        let _ = (f.C_DestroyObject)(self.session, self.ec_priv_key);
        if let Some(aes_key) = self.aes_key {
            let _ = (f.C_DestroyObject)(self.session, aes_key);
        }
        let _ = (f.C_Logout)(self.session);
        let _ = (f.C_CloseSession)(self.session);
        let _ = (f.C_Finalize)(ptr::null_mut());
    }
}

// ===========================================================================
// Per-operation benchmark helpers
// ===========================================================================

fn bench_rsa_sign(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let Some(rsa_priv_key) = state.rsa_priv_key else {
        return;
    };
    let f = state.fns();
    let session = state.session;
    let data = [0u8; 32];
    group.bench_function(&state.name, |b| {
        b.iter(|| {
            let mut mech = CK_MECHANISM {
                mechanism: CKM_SHA256_RSA_PKCS,
                p_parameter: ptr::null_mut(),
                parameter_len: 0,
            };
            let rv = (f.C_SignInit)(session, &mut mech, rsa_priv_key);
            assert_eq!(rv, CKR_OK);
            let mut sig = [0u8; 512];
            let mut sig_len: CK_ULONG = 512;
            let rv = (f.C_Sign)(
                session,
                data.as_ptr() as CK_BYTE_PTR,
                32,
                sig.as_mut_ptr(),
                &mut sig_len,
            );
            assert_eq!(rv, CKR_OK);
        })
    });
}

fn bench_rsa_verify(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let (Some(rsa_signature), Some(rsa_pub_key)) =
        (state.rsa_signature.as_ref(), state.rsa_pub_key)
    else {
        return;
    };
    let f = state.fns();
    let session = state.session;
    let data = [0u8; 32];
    group.bench_function(&state.name, |b| {
        b.iter(|| {
            let mut mech = CK_MECHANISM {
                mechanism: CKM_SHA256_RSA_PKCS,
                p_parameter: ptr::null_mut(),
                parameter_len: 0,
            };
            let rv = (f.C_VerifyInit)(session, &mut mech, rsa_pub_key);
            assert_eq!(rv, CKR_OK);
            let rv = (f.C_Verify)(
                session,
                data.as_ptr() as CK_BYTE_PTR,
                32,
                rsa_signature.as_ptr() as CK_BYTE_PTR,
                rsa_signature.len() as CK_ULONG,
            );
            assert_eq!(rv, CKR_OK);
        })
    });
}

fn bench_ecdsa_sign(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let f = state.fns();
    let session = state.session;
    let data = [0u8; 32];
    group.bench_function(&state.name, |b| {
        b.iter(|| {
            let mut mech = CK_MECHANISM {
                mechanism: CKM_ECDSA,
                p_parameter: ptr::null_mut(),
                parameter_len: 0,
            };
            let rv = (f.C_SignInit)(session, &mut mech, state.ec_priv_key);
            assert_eq!(rv, CKR_OK);
            let mut sig = [0u8; 128];
            let mut sig_len: CK_ULONG = 128;
            let rv = (f.C_Sign)(
                session,
                data.as_ptr() as CK_BYTE_PTR,
                32,
                sig.as_mut_ptr(),
                &mut sig_len,
            );
            assert_eq!(rv, CKR_OK);
        })
    });
}

fn bench_ecdsa_verify(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let f = state.fns();
    let session = state.session;
    let data = [0u8; 32];
    group.bench_function(&state.name, |b| {
        b.iter(|| {
            let mut mech = CK_MECHANISM {
                mechanism: CKM_ECDSA,
                p_parameter: ptr::null_mut(),
                parameter_len: 0,
            };
            let rv = (f.C_VerifyInit)(session, &mut mech, state.ec_pub_key);
            assert_eq!(rv, CKR_OK);
            let rv = (f.C_Verify)(
                session,
                data.as_ptr() as CK_BYTE_PTR,
                32,
                state.ec_signature.as_ptr() as CK_BYTE_PTR,
                state.ec_signature.len() as CK_ULONG,
            );
            assert_eq!(rv, CKR_OK);
        })
    });
}

fn bench_aes_gcm_encrypt(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let aes_key = match state.aes_key {
        Some(k) => k,
        None => return, // Skip — library doesn't support null-params GCM
    };
    let f = state.fns();
    let session = state.session;
    let data = [0u8; 4096];
    group.bench_function(&state.name, |b| {
        b.iter(|| {
            let mut mech = CK_MECHANISM {
                mechanism: CKM_AES_GCM,
                p_parameter: ptr::null_mut(),
                parameter_len: 0,
            };
            let rv = (f.C_EncryptInit)(session, &mut mech, aes_key);
            assert_eq!(rv, CKR_OK);
            let mut out = [0u8; 4096 + 256];
            let mut out_len: CK_ULONG = out.len() as CK_ULONG;
            let rv = (f.C_Encrypt)(
                session,
                data.as_ptr() as CK_BYTE_PTR,
                4096,
                out.as_mut_ptr(),
                &mut out_len,
            );
            assert_eq!(rv, CKR_OK);
        })
    });
}

fn bench_aes_gcm_decrypt(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let (aes_key, ct) = match (&state.aes_key, &state.aes_ciphertext) {
        (Some(k), Some(ct)) => (*k, ct),
        _ => return, // Skip — library doesn't support null-params GCM
    };
    let f = state.fns();
    let session = state.session;
    group.bench_function(&state.name, |b| {
        b.iter(|| {
            let mut mech = CK_MECHANISM {
                mechanism: CKM_AES_GCM,
                p_parameter: ptr::null_mut(),
                parameter_len: 0,
            };
            let rv = (f.C_DecryptInit)(session, &mut mech, aes_key);
            assert_eq!(rv, CKR_OK);
            let mut out = [0u8; 4096 + 256];
            let mut out_len: CK_ULONG = out.len() as CK_ULONG;
            let rv = (f.C_Decrypt)(
                session,
                ct.as_ptr() as CK_BYTE_PTR,
                ct.len() as CK_ULONG,
                out.as_mut_ptr(),
                &mut out_len,
            );
            assert_eq!(rv, CKR_OK);
        })
    });
}

fn bench_sha256_digest(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let f = state.fns();
    let session = state.session;
    let data = [0u8; 4096];
    group.bench_function(&state.name, |b| {
        b.iter(|| {
            let mut mech = CK_MECHANISM {
                mechanism: CKM_SHA256,
                p_parameter: ptr::null_mut(),
                parameter_len: 0,
            };
            let rv = (f.C_DigestInit)(session, &mut mech);
            assert_eq!(rv, CKR_OK);
            let mut digest = [0u8; 32];
            let mut digest_len: CK_ULONG = 32;
            let rv = (f.C_Digest)(
                session,
                data.as_ptr() as CK_BYTE_PTR,
                4096,
                digest.as_mut_ptr(),
                &mut digest_len,
            );
            assert_eq!(rv, CKR_OK);
        })
    });
}

fn bench_keygen_rsa(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    if state.rsa_priv_key.is_none() {
        return;
    }
    let f = state.fns();
    let session = state.session;
    group.bench_function(&state.name, |b| {
        b.iter(|| {
            let (pub_key, priv_key) = BenchState::gen_rsa_2048(f, session);
            let _ = (f.C_DestroyObject)(session, pub_key);
            let _ = (f.C_DestroyObject)(session, priv_key);
        })
    });
}

fn bench_keygen_ec(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let f = state.fns();
    let session = state.session;
    group.bench_function(&state.name, |b| {
        b.iter(|| {
            let (pub_key, priv_key) = BenchState::gen_ec_p256(f, session);
            let _ = (f.C_DestroyObject)(session, pub_key);
            let _ = (f.C_DestroyObject)(session, priv_key);
        })
    });
}

fn bench_keygen_aes(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let f = state.fns();
    let session = state.session;
    group.bench_function(&state.name, |b| {
        b.iter(|| {
            let key = BenchState::gen_aes_256(f, session);
            let _ = (f.C_DestroyObject)(session, key);
        })
    });
}

// ===========================================================================
// Object lookup (C_FindObjects)
// ===========================================================================

/// Number of filler AES keys created before the `C_FindObjects` benchmarks so
/// the store is not trivially small. `find_objects` scans every object by
/// design (see `ObjectStore::find_objects_for_slot`), so the store population
/// is the independent variable that matters for this measurement.
const FIND_FILLER_OBJECTS: usize = 256;

/// Distinct label given to exactly one object, used by the selective search.
const FIND_TARGET_LABEL: &[u8] = b"craton-bench-find-target";

/// Populate the token with labelled AES keys and return their handles.
///
/// The last key created carries [`FIND_TARGET_LABEL`]; every other key gets a
/// unique `craton-bench-filler-N` label so that a search for the target label
/// matches exactly one object.
fn populate_find_objects(
    f: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
) -> Vec<CK_OBJECT_HANDLE> {
    let mut handles = Vec::with_capacity(FIND_FILLER_OBJECTS + 1);
    for i in 0..FIND_FILLER_OBJECTS {
        let label = format!("craton-bench-filler-{}", i).into_bytes();
        handles.push(gen_labelled_aes_key(f, session, &label));
    }
    handles.push(gen_labelled_aes_key(f, session, FIND_TARGET_LABEL));
    handles
}

/// Generate an AES-256 session key carrying `label` as CKA_LABEL.
fn gen_labelled_aes_key(
    f: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    label: &[u8],
) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let value_len = ck_ulong_bytes(32);
    let bool_true: CK_BBOOL = CK_TRUE;

    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: value_len.as_ptr() as CK_VOID_PTR,
            value_len: value_len.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_LABEL,
            p_value: label.as_ptr() as CK_VOID_PTR,
            value_len: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &bool_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];

    let mut key: CK_OBJECT_HANDLE = 0;
    let rv = (f.C_GenerateKey)(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key,
    );
    assert_eq!(rv, CKR_OK, "labelled AES-256 keygen returned 0x{:08X}", rv);
    key
}

/// Run one full `C_FindObjectsInit` + `C_FindObjects` + `C_FindObjectsFinal`
/// cycle against `template`, returning the number of handles found.
fn run_find(
    f: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    template: &mut [CK_ATTRIBUTE],
) -> usize {
    let rv = (f.C_FindObjectsInit)(session, template.as_mut_ptr(), template.len() as CK_ULONG);
    assert_eq!(rv, CKR_OK, "C_FindObjectsInit returned 0x{:08X}", rv);

    let mut found = [0 as CK_OBJECT_HANDLE; 512];
    let mut count: CK_ULONG = 0;
    let rv = (f.C_FindObjects)(
        session,
        found.as_mut_ptr(),
        found.len() as CK_ULONG,
        &mut count,
    );
    assert_eq!(rv, CKR_OK, "C_FindObjects returned 0x{:08X}", rv);

    let rv = (f.C_FindObjectsFinal)(session);
    assert_eq!(rv, CKR_OK, "C_FindObjectsFinal returned 0x{:08X}", rv);
    count as usize
}

/// Selective search: a CKA_LABEL template matching exactly one object.
///
/// This is the shape a real consumer uses to resolve a named key before
/// signing, and the one the optimisation notes claimed could be served in
/// O(1) from an attribute index. It is deliberately measured against a store
/// of [`FIND_FILLER_OBJECTS`] objects so that a scan-versus-index difference
/// would be visible.
fn bench_find_objects_selective(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let f = state.fns();
    let session = state.session;
    group.bench_function(&state.name, |b| {
        b.iter(|| {
            let mut template = [CK_ATTRIBUTE {
                attr_type: CKA_LABEL,
                p_value: FIND_TARGET_LABEL.as_ptr() as CK_VOID_PTR,
                value_len: FIND_TARGET_LABEL.len() as CK_ULONG,
            }];
            let n = run_find(f, session, &mut template);
            assert_eq!(n, 1, "selective find should match exactly one object");
        })
    });
}

/// Broad search: every secret key on the token.
///
/// Complements the selective case — here the result set is large, so the cost
/// of materialising and returning handles is included rather than just the
/// scan.
fn bench_find_objects_by_class(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let f = state.fns();
    let session = state.session;
    group.bench_function(&state.name, |b| {
        b.iter(|| {
            let class = ck_ulong_bytes(CKO_SECRET_KEY);
            let mut template = [CK_ATTRIBUTE {
                attr_type: CKA_CLASS,
                p_value: class.as_ptr() as CK_VOID_PTR,
                value_len: class.len() as CK_ULONG,
            }];
            let n = run_find(f, session, &mut template);
            assert!(
                n >= FIND_FILLER_OBJECTS,
                "broad find should match the filler keys"
            );
        })
    });
}

// ===========================================================================
// Payload scaling
// ===========================================================================

/// Payload sizes for the AES-GCM scaling benchmarks.
///
/// The fixed-size 4 KB benchmarks above measure the per-call overhead that
/// dominates small operations. These sizes extend the curve far enough that
/// bulk throughput dominates instead, which is what separates a per-call
/// regression from a per-byte one.
const PAYLOAD_SIZES: &[usize] = &[256, 4096, 65536, 1_048_576];

fn bench_aes_gcm_encrypt_sizes(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let Some(key) = state.aes_key else { return };
    let f = state.fns();
    let session = state.session;

    for &size in PAYLOAD_SIZES {
        let plaintext = vec![0u8; size];
        // Ciphertext buffer: plaintext + 12-byte nonce + 16-byte tag, with
        // headroom so C_Encrypt never fails on a short buffer.
        let mut ciphertext = vec![0u8; size + 64];
        group.throughput(criterion::Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new(&state.name, human_size(size)), |b| {
            b.iter(|| {
                let mut mech = CK_MECHANISM {
                    mechanism: CKM_AES_GCM,
                    p_parameter: ptr::null_mut(),
                    parameter_len: 0,
                };
                let rv = (f.C_EncryptInit)(session, &mut mech, key);
                assert_eq!(rv, CKR_OK);
                let mut out_len: CK_ULONG = ciphertext.len() as CK_ULONG;
                let rv = (f.C_Encrypt)(
                    session,
                    plaintext.as_ptr() as CK_BYTE_PTR,
                    plaintext.len() as CK_ULONG,
                    ciphertext.as_mut_ptr(),
                    &mut out_len,
                );
                assert_eq!(rv, CKR_OK);
            })
        });
    }
}

fn bench_sha256_digest_sizes(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let f = state.fns();
    let session = state.session;

    for &size in PAYLOAD_SIZES {
        let data = vec![0u8; size];
        group.throughput(criterion::Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new(&state.name, human_size(size)), |b| {
            b.iter(|| {
                let mut mech = CK_MECHANISM {
                    mechanism: CKM_SHA256,
                    p_parameter: ptr::null_mut(),
                    parameter_len: 0,
                };
                let rv = (f.C_DigestInit)(session, &mut mech);
                assert_eq!(rv, CKR_OK);
                let mut digest = [0u8; 32];
                let mut digest_len: CK_ULONG = 32;
                let rv = (f.C_Digest)(
                    session,
                    data.as_ptr() as CK_BYTE_PTR,
                    data.len() as CK_ULONG,
                    digest.as_mut_ptr(),
                    &mut digest_len,
                );
                assert_eq!(rv, CKR_OK);
            })
        });
    }
}

/// Render a byte count as a short benchmark-id suffix (`256B`, `4KB`, `1MB`).
fn human_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{}MB", bytes / (1024 * 1024))
    } else if bytes >= 1024 {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{}B", bytes)
    }
}

// ===========================================================================
// Concurrency
// ===========================================================================

/// Thread counts for the concurrent-session benchmarks.
const CONCURRENCY_LEVELS: &[usize] = &[1, 2, 4, 8];

/// Number of operations each thread performs per Criterion iteration.
///
/// Kept small so a single iteration stays in the tens of milliseconds even at
/// the highest thread count, but large enough that thread spawn cost is not
/// what is being measured.
const OPS_PER_THREAD: usize = 8;

/// Concurrent AES-GCM encryption across independent sessions.
///
/// PKCS#11 permits concurrent access when the library is initialised with OS
/// locking, and Craton HSM's session map, object store, and audit trail are all
/// designed for it. Every other benchmark in this file is single-threaded, so
/// this is the only one that can catch a *scalability* regression — a new lock
/// on a shared path, or a serialising bottleneck such as the single audit
/// worker thread, shows up here as a flat or inverted curve while leaving the
/// single-threaded numbers untouched.
///
/// AES-GCM is used rather than RSA because it is fast enough that shared-state
/// contention, not the arithmetic, is what the measurement is dominated by.
fn bench_concurrent_encrypt(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let Some(key) = state.aes_key else { return };
    let f_ptr = state.lib.fn_list_ptr();

    for &threads in CONCURRENCY_LEVELS {
        // One session per thread, opened up front so session creation is not
        // inside the measured region.
        let sessions: Vec<CK_SESSION_HANDLE> = (0..threads)
            .map(|_| state.open_logged_in_session())
            .collect();

        group.throughput(criterion::Throughput::Elements(
            (threads * OPS_PER_THREAD) as u64,
        ));
        group.bench_function(
            BenchmarkId::new(&state.name, format!("{}t", threads)),
            |b| {
                b.iter(|| {
                    std::thread::scope(|scope| {
                        for &session in &sessions {
                            scope.spawn(move || {
                                // SAFETY: `f_ptr` points into the loaded
                                // library's static function list, which
                                // outlives this scope and is never mutated.
                                let f: &CK_FUNCTION_LIST = unsafe { f_ptr.fns() };
                                let plaintext = [0u8; 4096];
                                let mut ciphertext = [0u8; 4096 + 64];
                                for _ in 0..OPS_PER_THREAD {
                                    let mut mech = CK_MECHANISM {
                                        mechanism: CKM_AES_GCM,
                                        p_parameter: ptr::null_mut(),
                                        parameter_len: 0,
                                    };
                                    let rv = (f.C_EncryptInit)(session, &mut mech, key);
                                    assert_eq!(rv, CKR_OK);
                                    let mut out_len: CK_ULONG = ciphertext.len() as CK_ULONG;
                                    let rv = (f.C_Encrypt)(
                                        session,
                                        plaintext.as_ptr() as CK_BYTE_PTR,
                                        plaintext.len() as CK_ULONG,
                                        ciphertext.as_mut_ptr(),
                                        &mut out_len,
                                    );
                                    assert_eq!(rv, CKR_OK);
                                }
                            });
                        }
                    });
                })
            },
        );

        for session in sessions {
            let _ = (state.fns().C_CloseSession)(session);
        }
    }
}

/// Concurrent ECDSA P-256 signing across independent sessions.
///
/// The signing counterpart to [`bench_concurrent_encrypt`]: private-key
/// operations take a read lock on the key object and go through the signing
/// key cache, so this exercises a different set of shared structures.
fn bench_concurrent_sign(group: &mut BenchmarkGroup<WallTime>, state: &BenchState) {
    let f_ptr = state.lib.fn_list_ptr();
    let priv_key = state.ec_priv_key;

    for &threads in CONCURRENCY_LEVELS {
        let sessions: Vec<CK_SESSION_HANDLE> = (0..threads)
            .map(|_| state.open_logged_in_session())
            .collect();

        group.throughput(criterion::Throughput::Elements(
            (threads * OPS_PER_THREAD) as u64,
        ));
        group.bench_function(
            BenchmarkId::new(&state.name, format!("{}t", threads)),
            |b| {
                b.iter(|| {
                    std::thread::scope(|scope| {
                        for &session in &sessions {
                            scope.spawn(move || {
                                // SAFETY: see `bench_concurrent_encrypt`.
                                let f: &CK_FUNCTION_LIST = unsafe { f_ptr.fns() };
                                let data = [0u8; 32];
                                let mut sig = [0u8; 128];
                                for _ in 0..OPS_PER_THREAD {
                                    let mut mech = CK_MECHANISM {
                                        mechanism: CKM_ECDSA,
                                        p_parameter: ptr::null_mut(),
                                        parameter_len: 0,
                                    };
                                    let rv = (f.C_SignInit)(session, &mut mech, priv_key);
                                    assert_eq!(rv, CKR_OK);
                                    let mut sig_len: CK_ULONG = sig.len() as CK_ULONG;
                                    let rv = (f.C_Sign)(
                                        session,
                                        data.as_ptr() as CK_BYTE_PTR,
                                        data.len() as CK_ULONG,
                                        sig.as_mut_ptr(),
                                        &mut sig_len,
                                    );
                                    assert_eq!(rv, CKR_OK);
                                }
                            });
                        }
                    });
                })
            },
        );

        for session in sessions {
            let _ = (state.fns().C_CloseSession)(session);
        }
    }
}

// ===========================================================================
// Main benchmark function
// ===========================================================================

fn pkcs11_abi_benchmarks(c: &mut Criterion) {
    // --- Load PKCS#11 libraries ---
    let mut libraries: Vec<BenchState> = Vec::new();

    // Redirect the audit trail into target/ before the library initialises.
    configure_bench_environment();

    // Craton HSM (always loaded)
    libraries.push(BenchState::create(
        "craton_hsm",
        &craton_hsm_library_path(),
        true, // supports null-params AES-GCM
    ));

    // SoftHSMv2 (optional — set SOFTHSM2_LIB to enable)
    if let Ok(softhsm_path) = std::env::var("SOFTHSM2_LIB") {
        setup_softhsm2_env();
        eprintln!("SoftHSMv2 comparison enabled: loading '{}'", softhsm_path);
        libraries.push(BenchState::create(
            "softhsm2",
            &softhsm_path,
            false, // SoftHSMv2 requires CK_GCM_PARAMS for AES-GCM
        ));
    }

    // --- RSA-2048 Sign (CKM_SHA256_RSA_PKCS) ---
    {
        let mut group = c.benchmark_group("pkcs11_rsa_sign_2048");
        for state in &libraries {
            bench_rsa_sign(&mut group, state);
        }
        group.finish();
    }

    // --- RSA-2048 Verify (CKM_SHA256_RSA_PKCS) ---
    {
        let mut group = c.benchmark_group("pkcs11_rsa_verify_2048");
        for state in &libraries {
            bench_rsa_verify(&mut group, state);
        }
        group.finish();
    }

    // --- ECDSA P-256 Sign (CKM_ECDSA — raw hash input) ---
    {
        let mut group = c.benchmark_group("pkcs11_ecdsa_p256_sign");
        for state in &libraries {
            bench_ecdsa_sign(&mut group, state);
        }
        group.finish();
    }

    // --- ECDSA P-256 Verify (CKM_ECDSA — raw hash input) ---
    {
        let mut group = c.benchmark_group("pkcs11_ecdsa_p256_verify");
        for state in &libraries {
            bench_ecdsa_verify(&mut group, state);
        }
        group.finish();
    }

    // --- AES-256-GCM Encrypt 4 KB (Craton HSM only — null-params GCM) ---
    {
        let mut group = c.benchmark_group("pkcs11_aes_gcm_encrypt_4kb");
        for state in &libraries {
            bench_aes_gcm_encrypt(&mut group, state);
        }
        group.finish();
    }

    // --- AES-256-GCM Decrypt 4 KB (Craton HSM only — null-params GCM) ---
    {
        let mut group = c.benchmark_group("pkcs11_aes_gcm_decrypt_4kb");
        for state in &libraries {
            bench_aes_gcm_decrypt(&mut group, state);
        }
        group.finish();
    }

    // --- SHA-256 Digest 4 KB ---
    {
        let mut group = c.benchmark_group("pkcs11_sha256_digest_4kb");
        for state in &libraries {
            bench_sha256_digest(&mut group, state);
        }
        group.finish();
    }

    // --- Key Generation: RSA-2048 ---
    {
        let mut group = c.benchmark_group("pkcs11_keygen_rsa_2048");
        group.sample_size(10); // RSA keygen is slow — set once before iterating libraries
        for state in &libraries {
            bench_keygen_rsa(&mut group, state);
        }
        group.finish();
    }

    // --- Key Generation: EC P-256 ---
    {
        let mut group = c.benchmark_group("pkcs11_keygen_ec_p256");
        for state in &libraries {
            bench_keygen_ec(&mut group, state);
        }
        group.finish();
    }

    // --- Key Generation: AES-256 ---
    {
        let mut group = c.benchmark_group("pkcs11_keygen_aes_256");
        for state in &libraries {
            bench_keygen_aes(&mut group, state);
        }
        group.finish();
    }

    // --- Object lookup: selective (CKA_LABEL matching one object) ---
    {
        let mut group = c.benchmark_group("pkcs11_find_objects_selective");
        for state in &libraries {
            bench_find_objects_selective(&mut group, state);
        }
        group.finish();
    }

    // --- Object lookup: broad (all secret keys) ---
    {
        let mut group = c.benchmark_group("pkcs11_find_objects_by_class");
        for state in &libraries {
            bench_find_objects_by_class(&mut group, state);
        }
        group.finish();
    }

    // --- Payload scaling: AES-256-GCM encrypt, 256B .. 1MB ---
    {
        let mut group = c.benchmark_group("pkcs11_aes_gcm_encrypt_sizes");
        for state in &libraries {
            bench_aes_gcm_encrypt_sizes(&mut group, state);
        }
        group.finish();
    }

    // --- Payload scaling: SHA-256 digest, 256B .. 1MB ---
    {
        let mut group = c.benchmark_group("pkcs11_sha256_digest_sizes");
        for state in &libraries {
            bench_sha256_digest_sizes(&mut group, state);
        }
        group.finish();
    }

    // --- Concurrency: AES-256-GCM encrypt across 1..8 sessions ---
    {
        let mut group = c.benchmark_group("pkcs11_concurrent_encrypt");
        for state in &libraries {
            bench_concurrent_encrypt(&mut group, state);
        }
        group.finish();
    }

    // --- Concurrency: ECDSA P-256 sign across 1..8 sessions ---
    {
        let mut group = c.benchmark_group("pkcs11_concurrent_sign");
        for state in &libraries {
            bench_concurrent_sign(&mut group, state);
        }
        group.finish();
    }
}

// ===========================================================================
// Criterion harness
// ===========================================================================

criterion_group!(pkcs11_abi, pkcs11_abi_benchmarks);
criterion_main!(pkcs11_abi);
