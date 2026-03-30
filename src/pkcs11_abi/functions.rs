// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
#![deny(unsafe_op_in_unsafe_fn)]
// PKCS#11 C ABI exports — all exported functions with #[no_mangle].
// Every function uses catch_unwind at the FFI boundary to prevent panics
// from crossing into C code (undefined behavior).
//
// # Safety — Unsafe Code in This Module
//
// All unsafe code in this module falls into a small number of patterns,
// all at the PKCS#11 C ABI boundary. No unsafe exists in crypto paths.
//
// **Pattern 1 — Dereferencing caller-provided output pointers:**
//   `unsafe { *p_info = info; }` or `unsafe { *pul_count = n; }`
//   SAFETY: The PKCS#11 spec requires the caller to provide valid, aligned,
//   writable pointers for output parameters. Null checks are performed where
//   specified by the spec. The function signature guarantees size/alignment.
//
// **Pattern 2 — Constructing slices from (pointer, length) pairs:**
//   `unsafe { slice::from_raw_parts(ptr, len) }` / `from_raw_parts_mut`
//   SAFETY: The PKCS#11 caller is required to provide a valid buffer of at
//   least `len` bytes. Null pointer checks are done before slice construction.
//   The resulting slice borrows for the duration of the function call only.
//
// **Pattern 3 — Reading CK_MECHANISM through a raw pointer:**
//   `unsafe { (*p_mechanism).mechanism }`
//   SAFETY: p_mechanism is checked for null before dereferencing. The caller
//   must provide a valid, aligned CK_MECHANISM struct per PKCS#11 spec.
//
// **Pattern 4 — Casting CK_C_INITIALIZE_ARGS pointer:**
//   `unsafe { &*(p_init_args as *const CK_C_INITIALIZE_ARGS) }`
//   SAFETY: Only performed after null check. The caller must pass a valid
//   CK_C_INITIALIZE_ARGS struct or NULL per PKCS#11 §5.10.
//
// **Pattern 5 — Multi-field struct dereference in extract_mechanism_param:**
//   `unsafe { let mech = &*p_mechanism; ... slice::from_raw_parts(...) }`
//   SAFETY: p_mechanism validity ensured by Pattern 3 guard. The p_parameter
//   field and parameter_len are checked before slice construction.
//
// **Pattern 6 — Dual output pointer dereference in C_GenerateKeyPair:**
//   `unsafe { *ph_public_key = pub_handle; *ph_private_key = priv_handle; }`
//   SAFETY: Both output pointers are checked for null at function entry.
//   The caller must provide valid, aligned, writable CK_OBJECT_HANDLE pointers.
//
// Total: 43 unsafe blocks (41 in this file, 2 in mlock.rs).

use std::cell::RefCell;
use std::panic::catch_unwind;
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::audit::log::{AuditOperation, AuditResult};
use crate::core::HsmCore;
use crate::crypto::backend::CryptoBackend;
use crate::crypto::{mechanisms, pairwise_test, pqc, sign};
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::*;
use crate::session::session::{ActiveOperation, FindContext};
use crate::store::key_material::RawKeyMaterial;
use crate::store::object::StoredObject;
use zeroize::Zeroizing;

/// Global singleton — PKCS#11 §5.10 requires exactly one `C_Initialize` / `C_Finalize`
/// pair per process. Uses `Mutex<Option<...>>` so `C_Finalize` can reset the state,
/// allowing a subsequent `C_Initialize` to succeed (required by PKCS#11 spec).
///
/// Uses `parking_lot::Mutex` for lower uncontended overhead (spin-then-park
/// instead of immediate syscall). No poisoning — panics are caught by `catch_unwind`.
static HSM: parking_lot::Mutex<Option<Arc<HsmCore>>> = parking_lot::Mutex::new(None);
static POST_FAILED: AtomicBool = AtomicBool::new(false);

/// Generation counter — bumped on every C_Initialize / C_Finalize to invalidate
/// thread-local caches of the HSM reference.
static HSM_GENERATION: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Thread-local cache of the HSM Arc to avoid mutex lock on every C_* call.
    /// Stores (Arc<HsmCore>, generation) — invalidated when generation changes.
    static CACHED_HSM: RefCell<Option<(Arc<HsmCore>, u64)>> = const { RefCell::new(None) };
}
/// Maximum bytes that multi-part Update functions may accumulate before
/// returning CKR_DATA_LEN_RANGE.  64 MiB is generous for any realistic
/// HSM workload while still bounding memory consumption.
const MAX_MULTIPART_ACCUMULATION: usize = 64 * 1024 * 1024;
/// Maximum PIN length in bytes. Defense-in-depth bound to prevent
/// `slice::from_raw_parts` with a caller-supplied length that exceeds
/// the actual allocation. 256 bytes is far above any realistic PIN.
const MAX_PIN_BYTES: usize = 256;
/// Maximum single-shot data buffer (encrypt/decrypt/sign/verify input).
/// Same as multi-part bound — 64 MiB.
const MAX_SINGLE_BUFFER: usize = 64 * 1024 * 1024;
/// Maximum number of attributes in a template. Defense-in-depth bound
/// to prevent `slice::from_raw_parts` with a caller-supplied count that
/// exceeds the actual allocation. 256 attributes is far above any
/// realistic PKCS#11 template.
const MAX_TEMPLATE_ATTRS: usize = 256;
/// Maximum size of a single attribute value in bytes. Defense-in-depth
/// bound to prevent `slice::from_raw_parts` with a bogus `value_len`
/// that exceeds the actual allocation. 64 KiB is far above any
/// realistic PKCS#11 attribute (RSA-4096 modulus is 512 bytes, PQC
/// keys are a few KiB).
const MAX_ATTR_VALUE_LEN: usize = 64 * 1024;
/// Operation type tags for C_GetOperationState / C_SetOperationState serialization.
const OP_TYPE_ENCRYPT: u8 = 0;
const OP_TYPE_DECRYPT: u8 = 1;
const OP_TYPE_SIGN: u8 = 2;
const OP_TYPE_VERIFY: u8 = 3;
const OP_TYPE_DIGEST: u8 = 4;
/// PID recorded at C_Initialize time; used for fork detection on Unix.
static INIT_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Get the current process ID (portable).
fn current_pid() -> u32 {
    #[cfg(unix)]
    {
        (unsafe { libc::getpid() }) as u32
    }
    #[cfg(windows)]
    {
        unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() }
    }
    #[cfg(not(any(unix, windows)))]
    {
        // Fork detection unavailable on this platform (e.g., WASM).
        // PID 0 disables the init_pid != current_pid() check in get_hsm().
        use std::sync::Once;
        static WARN_ONCE: Once = Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!("Fork detection unavailable: unsupported platform (not unix/windows)");
        });
        0
    }
}

/// Check if FIPS POST (or conditional self-test) has failed.
/// Used by integration tests to verify error state behavior.
pub fn is_post_failed() -> bool {
    POST_FAILED.load(Ordering::Acquire)
}

fn get_hsm() -> Result<Arc<HsmCore>, CK_RV> {
    if POST_FAILED.load(Ordering::Acquire) {
        return Err(CKR_GENERAL_ERROR);
    }

    // Fork detection: if the current PID differs from the PID at init time,
    // this process is a fork child that inherited stale state.
    // PKCS#11 §5.10: the child must call C_Initialize before using the library.
    let init_pid = INIT_PID.load(Ordering::Acquire);
    if init_pid != 0 && init_pid != current_pid() {
        CACHED_HSM.with(|c| *c.borrow_mut() = None);
        tracing::error!(
            "Fork detected: initialized in PID {} but running in PID {}. \
             The child process must call C_Initialize.",
            init_pid,
            current_pid()
        );
        return Err(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    // Fast path: check thread-local cache (avoids mutex lock on every C_* call).
    let current_gen = HSM_GENERATION.load(Ordering::Acquire);
    let cached = CACHED_HSM.with(|c| {
        let borrow = c.borrow();
        if let Some((ref arc, gen)) = *borrow {
            if gen == current_gen {
                return Some(arc.clone());
            }
        }
        None
    });
    if let Some(hsm) = cached {
        return Ok(hsm);
    }

    // Slow path: lock mutex, clone Arc, cache in TLS.
    let guard = HSM.lock();
    let hsm = guard
        .as_ref()
        .cloned()
        .ok_or(CKR_CRYPTOKI_NOT_INITIALIZED)?;
    CACHED_HSM.with(|c| {
        *c.borrow_mut() = Some((hsm.clone(), current_gen));
    });
    Ok(hsm)
}

/// Helper: convert HsmError to CK_RV
fn err_to_rv(e: HsmError) -> CK_RV {
    e.into()
}

/// Parse OAEP hash algorithm from CK_RSA_PKCS_OAEP_PARAMS mechanism parameter bytes.
/// The first CK_ULONG in the struct is hashAlg. Returns error for unrecognized or missing hash.
fn parse_oaep_hash(mech_param: &[u8]) -> Result<crate::crypto::sign::OaepHash, CK_RV> {
    use crate::crypto::sign::OaepHash;
    if mech_param.len() >= std::mem::size_of::<CK_ULONG>() {
        let hash_mech = CK_ULONG::from_ne_bytes(
            match mech_param[..std::mem::size_of::<CK_ULONG>()].try_into() {
                Ok(b) => b,
                Err(_) => return Err(CKR_MECHANISM_PARAM_INVALID),
            },
        );
        match hash_mech {
            CKM_SHA_1 => {
                tracing::error!("RSA-OAEP with SHA-1 is rejected — use SHA-256 or stronger");
                Err(CKR_MECHANISM_PARAM_INVALID)
            }
            CKM_SHA256 => Ok(OaepHash::Sha256),
            CKM_SHA384 => Ok(OaepHash::Sha384),
            CKM_SHA512 => Ok(OaepHash::Sha512),
            _ => Err(CKR_MECHANISM_PARAM_INVALID),
        }
    } else {
        Err(CKR_MECHANISM_PARAM_INVALID)
    }
}

// ============================================================================
// Core library functions
// ============================================================================

#[no_mangle]
pub extern "C" fn C_Initialize(p_init_args: CK_VOID_PTR) -> CK_RV {
    catch_unwind(|| {
        let mut guard = HSM.lock();

        if guard.is_some() {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }

        // Validate init args if provided
        if !p_init_args.is_null() {
            // SAFETY: p_init_args is non-null (checked above). Caller must provide a valid
            // CK_C_INITIALIZE_ARGS per PKCS#11 §5.10. (Pattern 4)
            let _args = unsafe { &*(p_init_args as *const CK_C_INITIALIZE_ARGS) };
            // We always support OS locking — accept CKF_OS_LOCKING_OK
            // If mutex callbacks provided without OS_LOCKING_OK, that's fine too (we ignore them)
        }

        // Reset per-key GCM encryption counters so re-initialization starts fresh
        crate::crypto::encrypt::reset_gcm_counters();

        // Reset POST failure flag so re-initialization after C_Finalize gets a fresh chance.
        // If POST fails again below, POST_FAILED will be set back to true.
        POST_FAILED.store(false, Ordering::Release);

        // Run FIPS 140-3 Power-On Self-Tests before any crypto service is available
        if let Err(_) = crate::crypto::self_test::run_post() {
            POST_FAILED.store(true, Ordering::Release);
            return CKR_GENERAL_ERROR;
        }

        let config = match crate::config::config::HsmConfig::load() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Configuration loading/validation failed: {}", e);
                return CKR_GENERAL_ERROR;
            }
        };
        let core = Arc::new(HsmCore::new(&config));

        // Record the PID for fork detection
        INIT_PID.store(current_pid(), Ordering::Release);
        let _ = core
            .audit_log
            .record(0, AuditOperation::Initialize, AuditResult::Success, None);
        *guard = Some(core);
        // Bump generation so any stale TLS caches from a prior init/finalize
        // cycle are invalidated.
        HSM_GENERATION.fetch_add(1, Ordering::Release);
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_Finalize(p_reserved: CK_VOID_PTR) -> CK_RV {
    catch_unwind(|| {
        if !p_reserved.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let mut guard = HSM.lock();

        let hsm = match guard.as_ref() {
            Some(h) => h.clone(),
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };

        let _ = hsm
            .audit_log
            .record(0, AuditOperation::Finalize, AuditResult::Success, None);
        hsm.audit_log.flush();

        // Reset state so a subsequent C_Initialize can succeed (PKCS#11 spec compliant)
        *guard = None;
        INIT_PID.store(0, Ordering::Release);
        // Invalidate all thread-local HSM caches.
        HSM_GENERATION.fetch_add(1, Ordering::Release);
        CACHED_HSM.with(|c| *c.borrow_mut() = None);
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_GetInfo(p_info: CK_INFO_PTR) -> CK_RV {
    catch_unwind(|| {
        if get_hsm().is_err() {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        if p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let mut info = CK_INFO {
            cryptoki_version: CK_VERSION { major: 3, minor: 0 },
            manufacturer_id: [b' '; 32],
            flags: 0,
            library_description: [b' '; 32],
            library_version: CK_VERSION { major: 0, minor: 1 },
        };
        pad_string(&mut info.manufacturer_id, "Craton HSM Project");
        pad_string(&mut info.library_description, "Craton HSM Software HSM");

        // SAFETY: p_info non-null (checked above), caller provides aligned writable CK_INFO. (Pattern 1)
        unsafe {
            *p_info = info;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_GetFunctionList(pp_function_list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    catch_unwind(|| {
        if pp_function_list.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        unsafe {
            *pp_function_list = &FUNCTION_LIST as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ============================================================================
// Slot and Token management
// ============================================================================

#[no_mangle]
pub extern "C" fn C_GetSlotList(
    token_present: CK_BBOOL,
    p_slot_list: CK_SLOT_ID_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pul_count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        // In this software HSM, all slots always have a token present.
        // When token_present is CK_TRUE, we filter to only slots with tokens —
        // which is all of them. The parameter is accepted for spec compliance.
        let _ = token_present;
        let slots = hsm.slot_manager.get_slot_ids();

        if p_slot_list.is_null() {
            unsafe {
                *pul_count = slots.len() as CK_ULONG;
            }
            return CKR_OK;
        }

        let count = unsafe { *pul_count } as usize;
        if count < slots.len() {
            unsafe {
                *pul_count = slots.len() as CK_ULONG;
            }
            return CKR_BUFFER_TOO_SMALL;
        }

        let slot_slice = unsafe { slice::from_raw_parts_mut(p_slot_list, slots.len()) };
        for (i, &slot_id) in slots.iter().enumerate() {
            slot_slice[i] = slot_id;
        }
        unsafe {
            *pul_count = slots.len() as CK_ULONG;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_GetSlotInfo(slot_id: CK_SLOT_ID, p_info: CK_SLOT_INFO_PTR) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if let Err(e) = hsm.slot_manager.validate_slot(slot_id) {
            return err_to_rv(e);
        }

        let mut info = CK_SLOT_INFO {
            slot_description: [b' '; 64],
            manufacturer_id: [b' '; 32],
            flags: CKF_SLOT_TOKEN_PRESENT,
            hardware_version: CK_VERSION { major: 0, minor: 1 },
            firmware_version: CK_VERSION { major: 0, minor: 1 },
        };
        pad_string(&mut info.slot_description, "Craton HSM Virtual Slot");
        pad_string(&mut info.manufacturer_id, "Craton HSM Project");

        unsafe {
            *p_info = info;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_GetTokenInfo(slot_id: CK_SLOT_ID, p_info: CK_TOKEN_INFO_PTR) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let token = match hsm.slot_manager.get_token(slot_id) {
            Ok(t) => t,
            Err(e) => return err_to_rv(e),
        };

        let mut info = CK_TOKEN_INFO {
            label: *token.label.read(),
            manufacturer_id: [b' '; 32],
            model: [b' '; 16],
            serial_number: hsm.serial_number,
            flags: token.flags(),
            max_session_count: token.max_sessions() as CK_ULONG,
            session_count: token.session_count() as CK_ULONG,
            max_rw_session_count: token.max_rw_sessions() as CK_ULONG,
            rw_session_count: token.rw_session_count() as CK_ULONG,
            max_pin_len: token.pin_max_len(),
            min_pin_len: token.pin_min_len(),
            total_public_memory: CK_UNAVAILABLE_INFORMATION,
            free_public_memory: CK_UNAVAILABLE_INFORMATION,
            total_private_memory: CK_UNAVAILABLE_INFORMATION,
            free_private_memory: CK_UNAVAILABLE_INFORMATION,
            hardware_version: CK_VERSION { major: 0, minor: 1 },
            firmware_version: CK_VERSION { major: 0, minor: 1 },
            utc_time: [b' '; 16],
        };
        pad_string(&mut info.manufacturer_id, "Craton HSM Project");
        pad_string(&mut info.model, "Craton HSM");

        unsafe {
            *p_info = info;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_InitToken(
    slot_id: CK_SLOT_ID,
    p_pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
    p_label: CK_UTF8CHAR_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_pin.is_null() || p_label.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let token = match hsm.slot_manager.get_token(slot_id) {
            Ok(t) => t,
            Err(e) => return err_to_rv(e),
        };

        if (pin_len as usize) > MAX_PIN_BYTES {
            return CKR_PIN_LEN_RANGE;
        }
        // SAFETY: p_pin non-null (checked above), caller must provide pin_len valid bytes. (Pattern 2)
        let pin = unsafe { slice::from_raw_parts(p_pin, pin_len as usize) };
        // SAFETY: p_label non-null (checked above), PKCS#11 labels are always 32 bytes. (Pattern 2)
        let label_bytes = unsafe { slice::from_raw_parts(p_label, 32) };
        let mut label = [b' '; 32];
        label.copy_from_slice(label_bytes);

        // Close all sessions for this slot first
        hsm.session_manager.close_all_sessions(slot_id, &token);

        // Per PKCS#11 spec: C_InitToken destroys all objects on the token
        hsm.object_store.clear();
        // All keys are destroyed — safe to reset all GCM/IV counters
        crate::crypto::encrypt::force_reset_all_counters();

        match token.init_token(pin, &label) {
            Ok(()) => CKR_OK,
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_InitPIN(
    session: CK_SESSION_HANDLE,
    p_pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_pin.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let sess = sess.read();
        let token = match hsm.slot_manager.get_token(sess.slot_id) {
            Ok(t) => t,
            Err(e) => return err_to_rv(e),
        };

        // PKCS#11: C_InitPIN requires SO role
        if !sess.state.is_so() {
            return CKR_USER_NOT_LOGGED_IN;
        }
        if (pin_len as usize) > MAX_PIN_BYTES {
            return CKR_PIN_LEN_RANGE;
        }
        let pin = unsafe { slice::from_raw_parts(p_pin, pin_len as usize) };
        match token.init_pin(pin) {
            Ok(()) => CKR_OK,
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_SetPIN(
    session: CK_SESSION_HANDLE,
    p_old_pin: CK_UTF8CHAR_PTR,
    old_len: CK_ULONG,
    p_new_pin: CK_UTF8CHAR_PTR,
    new_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_old_pin.is_null() || p_new_pin.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let sess = sess.read();
        let token = match hsm.slot_manager.get_token(sess.slot_id) {
            Ok(t) => t,
            Err(e) => return err_to_rv(e),
        };

        if (old_len as usize) > MAX_PIN_BYTES || (new_len as usize) > MAX_PIN_BYTES {
            return CKR_PIN_LEN_RANGE;
        }
        let old_pin = unsafe { slice::from_raw_parts(p_old_pin, old_len as usize) };
        let new_pin = unsafe { slice::from_raw_parts(p_new_pin, new_len as usize) };
        match token.set_pin(old_pin, new_pin) {
            Ok(()) => CKR_OK,
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_GetMechanismList(
    slot_id: CK_SLOT_ID,
    p_mechanism_list: CK_MECHANISM_TYPE_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pul_count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if let Err(e) = hsm.slot_manager.validate_slot(slot_id) {
            return err_to_rv(e);
        }

        // Filter mechanisms by algorithm policy (FIPS mode, PQC enable, etc.)
        let mechs = mechanisms::supported_mechanisms_filtered(&hsm.algorithm_config);

        if p_mechanism_list.is_null() {
            unsafe {
                *pul_count = mechs.len() as CK_ULONG;
            }
            return CKR_OK;
        }

        let count = unsafe { *pul_count } as usize;
        if count < mechs.len() {
            unsafe {
                *pul_count = mechs.len() as CK_ULONG;
            }
            return CKR_BUFFER_TOO_SMALL;
        }

        let out = unsafe { slice::from_raw_parts_mut(p_mechanism_list, mechs.len()) };
        for (i, &m) in mechs.iter().enumerate() {
            out[i] = m;
        }
        unsafe {
            *pul_count = mechs.len() as CK_ULONG;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_GetMechanismInfo(
    slot_id: CK_SLOT_ID,
    mechanism_type: CK_MECHANISM_TYPE,
    p_info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if let Err(e) = hsm.slot_manager.validate_slot(slot_id) {
            return err_to_rv(e);
        }

        let info = match mechanism_type {
            CKM_RSA_PKCS_KEY_PAIR_GEN => CK_MECHANISM_INFO {
                min_key_size: 2048 as CK_ULONG,
                max_key_size: 4096 as CK_ULONG,
                flags: CKF_GENERATE_KEY_PAIR_FLAG,
            },
            CKM_RSA_PKCS | CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS => {
                CK_MECHANISM_INFO {
                    min_key_size: 2048 as CK_ULONG,
                    max_key_size: 4096 as CK_ULONG,
                    flags: CKF_SIGN_FLAG | CKF_VERIFY_FLAG,
                }
            }
            CKM_RSA_PKCS_PSS
            | CKM_SHA256_RSA_PKCS_PSS
            | CKM_SHA384_RSA_PKCS_PSS
            | CKM_SHA512_RSA_PKCS_PSS => CK_MECHANISM_INFO {
                min_key_size: 2048 as CK_ULONG,
                max_key_size: 4096 as CK_ULONG,
                flags: CKF_SIGN_FLAG | CKF_VERIFY_FLAG,
            },
            CKM_RSA_PKCS_OAEP => CK_MECHANISM_INFO {
                min_key_size: 2048 as CK_ULONG,
                max_key_size: 4096 as CK_ULONG,
                flags: CKF_ENCRYPT_FLAG | CKF_DECRYPT_FLAG,
            },
            CKM_EC_KEY_PAIR_GEN => CK_MECHANISM_INFO {
                min_key_size: 256 as CK_ULONG,
                max_key_size: 384 as CK_ULONG,
                flags: CKF_GENERATE_KEY_PAIR_FLAG,
            },
            CKM_ECDSA | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512 => {
                CK_MECHANISM_INFO {
                    min_key_size: 256 as CK_ULONG,
                    max_key_size: 384 as CK_ULONG,
                    flags: CKF_SIGN_FLAG | CKF_VERIFY_FLAG,
                }
            }
            CKM_ECDH1_DERIVE | CKM_ECDH1_COFACTOR_DERIVE => CK_MECHANISM_INFO {
                min_key_size: 256 as CK_ULONG,
                max_key_size: 384 as CK_ULONG,
                flags: CKF_DERIVE_FLAG,
            },
            CKM_EDDSA => CK_MECHANISM_INFO {
                min_key_size: 256 as CK_ULONG,
                max_key_size: 256 as CK_ULONG,
                flags: CKF_SIGN_FLAG | CKF_VERIFY_FLAG | CKF_GENERATE_KEY_PAIR_FLAG,
            },
            CKM_AES_KEY_GEN => CK_MECHANISM_INFO {
                min_key_size: 16 as CK_ULONG,
                max_key_size: 32 as CK_ULONG,
                flags: CKF_GENERATE_FLAG,
            },
            CKM_AES_GCM | CKM_AES_CBC | CKM_AES_CBC_PAD | CKM_AES_CTR => CK_MECHANISM_INFO {
                min_key_size: 16 as CK_ULONG,
                max_key_size: 32 as CK_ULONG,
                flags: CKF_ENCRYPT_FLAG | CKF_DECRYPT_FLAG,
            },
            CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => CK_MECHANISM_INFO {
                min_key_size: 16 as CK_ULONG,
                max_key_size: 32 as CK_ULONG,
                flags: CKF_WRAP_FLAG | CKF_UNWRAP_FLAG,
            },
            CKM_SHA_1 | CKM_SHA256 | CKM_SHA384 | CKM_SHA512 | CKM_SHA3_256 | CKM_SHA3_384
            | CKM_SHA3_512 => CK_MECHANISM_INFO {
                min_key_size: 0 as CK_ULONG,
                max_key_size: 0 as CK_ULONG,
                flags: CKF_DIGEST_FLAG,
            },
            // Post-Quantum: ML-KEM (Key Encapsulation)
            CKM_ML_KEM_512 | CKM_ML_KEM_768 | CKM_ML_KEM_1024 => CK_MECHANISM_INFO {
                min_key_size: 512 as CK_ULONG,
                max_key_size: 1024 as CK_ULONG,
                flags: CKF_GENERATE_KEY_PAIR_FLAG | CKF_DERIVE_FLAG,
            },
            // Post-Quantum: ML-DSA (Digital Signatures)
            CKM_ML_DSA_44 | CKM_ML_DSA_65 | CKM_ML_DSA_87 => CK_MECHANISM_INFO {
                min_key_size: 44 as CK_ULONG,
                max_key_size: 87 as CK_ULONG,
                flags: CKF_GENERATE_KEY_PAIR_FLAG | CKF_SIGN_FLAG | CKF_VERIFY_FLAG,
            },
            // Post-Quantum: SLH-DSA (Hash-Based Signatures)
            CKM_SLH_DSA_SHA2_128S | CKM_SLH_DSA_SHA2_256S => CK_MECHANISM_INFO {
                min_key_size: 128 as CK_ULONG,
                max_key_size: 256 as CK_ULONG,
                flags: CKF_GENERATE_KEY_PAIR_FLAG | CKF_SIGN_FLAG | CKF_VERIFY_FLAG,
            },
            // Hybrid ML-DSA + ECDSA
            CKM_HYBRID_ML_DSA_ECDSA => CK_MECHANISM_INFO {
                min_key_size: 256 as CK_ULONG,
                max_key_size: 256 as CK_ULONG,
                flags: CKF_SIGN_FLAG | CKF_VERIFY_FLAG,
            },
            _ => return CKR_MECHANISM_INVALID,
        };

        unsafe {
            *p_info = info;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ============================================================================
// Session management
// ============================================================================

#[no_mangle]
pub extern "C" fn C_OpenSession(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _p_application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    ph_session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if ph_session.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let token = match hsm.slot_manager.get_token(slot_id) {
            Ok(t) => t,
            Err(e) => return err_to_rv(e),
        };

        match hsm.session_manager.open_session(slot_id, flags, &token) {
            Ok(handle) => {
                unsafe {
                    *ph_session = handle;
                }
                CKR_OK
            }
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_CloseSession(session: CK_SESSION_HANDLE) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };

        // Need to get the slot_id from the session first
        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let slot_id = sess.read().slot_id;
        let token = match hsm.slot_manager.get_token(slot_id) {
            Ok(t) => t,
            Err(e) => return err_to_rv(e),
        };

        match hsm.session_manager.close_session(session, &token) {
            Ok(()) => CKR_OK,
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_CloseAllSessions(slot_id: CK_SLOT_ID) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        let token = match hsm.slot_manager.get_token(slot_id) {
            Ok(t) => t,
            Err(e) => return err_to_rv(e),
        };

        hsm.session_manager.close_all_sessions(slot_id, &token);
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_GetSessionInfo(
    session: CK_SESSION_HANDLE,
    p_info: CK_SESSION_INFO_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };

        unsafe {
            *p_info = sess.read().get_info();
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_Login(
    session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    p_pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let slot_id = sess.read().slot_id;
        let token = match hsm.slot_manager.get_token(slot_id) {
            Ok(t) => t,
            Err(e) => return err_to_rv(e),
        };

        // SO login not allowed if there are RO sessions
        if user_type == CKU_SO && hsm.session_manager.has_ro_sessions(slot_id) {
            return CKR_SESSION_READ_ONLY_EXISTS;
        }

        if !p_pin.is_null() && (pin_len as usize) > MAX_PIN_BYTES {
            return CKR_PIN_LEN_RANGE;
        }
        let pin = if p_pin.is_null() {
            &[]
        } else {
            unsafe { slice::from_raw_parts(p_pin, pin_len as usize) }
        };

        match token.login(user_type, pin) {
            Ok(()) => {
                // Update all sessions for this slot
                let _ = hsm.session_manager.login_all(slot_id, user_type);
                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Login {
                        user_type: user_type as u64,
                    },
                    AuditResult::Success,
                    None,
                );
                CKR_OK
            }
            Err(e) => {
                let rv = err_to_rv(e);
                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Login {
                        user_type: user_type as u64,
                    },
                    AuditResult::Failure(rv as u64),
                    None,
                );
                rv
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_Logout(session: CK_SESSION_HANDLE) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let slot_id = sess.read().slot_id;
        let token = match hsm.slot_manager.get_token(slot_id) {
            Ok(t) => t,
            Err(e) => return err_to_rv(e),
        };

        match token.logout() {
            Ok(()) => {
                let _ = hsm.session_manager.logout_all(slot_id);
                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Logout,
                    AuditResult::Success,
                    None,
                );
                CKR_OK
            }
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ============================================================================
// Object management
// ============================================================================

#[no_mangle]
pub extern "C" fn C_CreateObject(
    session: CK_SESSION_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    ph_object: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_template.is_null() || ph_object.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        // Check session is valid and RW
        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let sess_read = sess.read();
        if !sess_read.is_rw() {
            return CKR_SESSION_READ_ONLY;
        }

        let template = match parse_template(p_template, count) {
            Ok(t) => t,
            Err(rv) => return rv,
        };

        // PKCS#11 §5.7.1: Creating private/secret key objects requires login.
        let is_key_object = template.iter().any(|(attr_type, value)| {
            *attr_type == CKA_CLASS && value.len() >= std::mem::size_of::<CK_ULONG>() && {
                let class = CK_ULONG::from_ne_bytes(
                    value[..std::mem::size_of::<CK_ULONG>()]
                        .try_into()
                        .unwrap_or([0; std::mem::size_of::<CK_ULONG>()]),
                );
                class == CKO_PRIVATE_KEY || class == CKO_SECRET_KEY
            }
        });
        if is_key_object && !sess_read.state.is_logged_in() {
            return CKR_USER_NOT_LOGGED_IN;
        }
        drop(sess_read);

        match hsm.object_store.create_object(&template) {
            Ok(handle) => {
                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::CreateObject,
                    AuditResult::Success,
                    None,
                );
                unsafe {
                    *ph_object = handle;
                }
                CKR_OK
            }
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_DestroyObject(session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        if !sess.read().is_rw() {
            return CKR_SESSION_READ_ONLY;
        }

        // PKCS#11: check CKA_DESTROYABLE before destroying
        let obj = match hsm.object_store.get_object(object) {
            Ok(o) => o,
            Err(e) => return err_to_rv(e),
        };
        let obj_read = obj.read();
        if !obj_read.destroyable {
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        // Capture key material reference for GCM counter cleanup
        let key_bytes: Option<Vec<u8>> = obj_read
            .key_material
            .as_ref()
            .map(|km| km.as_bytes().to_vec());
        drop(obj_read);
        drop(obj);

        match hsm.object_store.destroy_object(object) {
            Ok(()) => {
                // Clean up per-key GCM/IV counters now that the key is destroyed
                if let Some(ref kb) = key_bytes {
                    crate::crypto::encrypt::remove_gcm_counter(kb);
                }
                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::DestroyObject,
                    AuditResult::Success,
                    None,
                );
                CKR_OK
            }
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_GetObjectSize(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    pul_size: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pul_size.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };

        // PKCS#11 §4.4: Private objects must not be accessible without login.
        let obj_ref = match hsm.object_store.get_object(object) {
            Ok(o) => o,
            Err(e) => return err_to_rv(e),
        };
        if obj_ref.read().private && !sess.read().state.is_logged_in() {
            return CKR_USER_NOT_LOGGED_IN;
        }

        match hsm.object_store.get_object_size(object) {
            Ok(size) => {
                unsafe {
                    *pul_size = size;
                }
                CKR_OK
            }
            Err(e) => err_to_rv(e),
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_GetAttributeValue(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_template.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };

        let obj = match hsm.object_store.get_object(object) {
            Ok(o) => o,
            Err(e) => return err_to_rv(e),
        };
        let obj = obj.read();

        // PKCS#11 §4.4: Private objects must not be accessible without login.
        if obj.private && !sess.read().state.is_logged_in() {
            return CKR_USER_NOT_LOGGED_IN;
        }

        // SAFETY: p_template non-null (checked above), caller provides count valid CK_ATTRIBUTEs.
        // We write back value_len and optionally copy data into p_value buffers. (Pattern 2)
        let attrs = unsafe { slice::from_raw_parts_mut(p_template, count as usize) };
        let mut rv = CKR_OK;

        for attr in attrs.iter_mut() {
            match crate::store::attributes::read_attribute(&obj, attr.attr_type) {
                Ok(Some(value)) => {
                    if attr.p_value.is_null() {
                        attr.value_len = value.len() as CK_ULONG;
                    } else if (attr.value_len as usize) < value.len() {
                        attr.value_len = value.len() as CK_ULONG;
                        rv = CKR_BUFFER_TOO_SMALL;
                    } else {
                        // SAFETY: p_value non-null, buffer size verified >= value.len() above.
                        let dest = unsafe {
                            slice::from_raw_parts_mut(attr.p_value as *mut u8, value.len())
                        };
                        dest.copy_from_slice(&value);
                        attr.value_len = value.len() as CK_ULONG;
                    }
                }
                Ok(None) => {
                    attr.value_len = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                }
                Err(HsmError::AttributeSensitive) => {
                    attr.value_len = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_ATTRIBUTE_SENSITIVE;
                }
                Err(_) => {
                    attr.value_len = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_GENERAL_ERROR;
                }
            }
        }
        rv
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_SetAttributeValue(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_template.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        {
            let sess_read = sess.read();
            if !sess_read.is_rw() {
                return CKR_SESSION_READ_ONLY;
            }
        }

        let obj = match hsm.object_store.get_object(object) {
            Ok(o) => o,
            Err(e) => return err_to_rv(e),
        };
        let mut obj = obj.write();

        // PKCS#11 §4.4: Private objects must not be accessible without login.
        if obj.private && !sess.read().state.is_logged_in() {
            return CKR_USER_NOT_LOGGED_IN;
        }

        if !obj.modifiable {
            return CKR_ATTRIBUTE_READ_ONLY;
        }

        let template = match parse_template(p_template, count) {
            Ok(t) => t,
            Err(rv) => return rv,
        };
        for (attr_type, value) in &template {
            match *attr_type {
                // PKCS#11 §4.1.2: Only CKA_LABEL and CKA_ID are modifiable
                // after object creation. All other attributes (especially
                // CKA_CLASS, CKA_KEY_TYPE, CKA_SENSITIVE, CKA_EXTRACTABLE,
                // CKA_PRIVATE, permission flags, key material, etc.) are
                // read-only once the object exists.
                CKA_LABEL => obj.label = value.clone(),
                CKA_ID => obj.id = value.clone(),
                // Reject all other attributes as read-only
                _ => {
                    return CKR_ATTRIBUTE_READ_ONLY;
                }
            }
        }

        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_FindObjectsInit(
    session: CK_SESSION_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        if sess.find_context.is_some() {
            return CKR_OPERATION_ACTIVE;
        }

        let template = if p_template.is_null() || count == 0 {
            vec![]
        } else {
            match parse_template(p_template, count) {
                Ok(t) => t,
                Err(rv) => return rv,
            }
        };

        let is_logged_in = sess.state.is_logged_in();
        let results = hsm.object_store.find_objects(&template, is_logged_in);

        sess.find_context = Some(FindContext {
            results,
            position: 0,
        });

        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_FindObjects(
    session: CK_SESSION_HANDLE,
    ph_object: CK_OBJECT_HANDLE_PTR,
    max_count: CK_ULONG,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if ph_object.is_null() || pul_count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        let ctx = match sess.find_context.as_mut() {
            Some(c) => c,
            None => return CKR_OPERATION_NOT_INITIALIZED,
        };

        let remaining = ctx.results.len() - ctx.position;
        let to_return = remaining.min(max_count as usize);
        let out = unsafe { slice::from_raw_parts_mut(ph_object, to_return) };

        for i in 0..to_return {
            out[i] = ctx.results[ctx.position + i];
        }
        ctx.position += to_return;

        unsafe {
            *pul_count = to_return as CK_ULONG;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_FindObjectsFinal(session: CK_SESSION_HANDLE) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        if sess.find_context.is_none() {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        sess.find_context = None;
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ============================================================================
// Crypto operations
// ============================================================================

#[no_mangle]
pub extern "C" fn C_EncryptInit(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        if sess.active_operation.is_some() {
            return CKR_OPERATION_ACTIVE;
        }

        // SAFETY: p_mechanism non-null (checked above), caller provides valid CK_MECHANISM. (Pattern 3)
        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_encrypt_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }

        // Verify key exists and has CKA_ENCRYPT
        let obj = match hsm.object_store.get_object(key) {
            Ok(o) => o,
            Err(_) => return CKR_KEY_HANDLE_INVALID,
        };
        {
            let obj_read = obj.read();
            // Private keys require login before use
            if obj_read.private && !sess.state.is_logged_in() {
                return CKR_USER_NOT_LOGGED_IN;
            }
            if !obj_read.can_encrypt {
                return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
            // SP 800-57 lifecycle check
            if let Err(_) = obj_read.check_lifecycle("encrypt") {
                return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
        }

        let mech_param = extract_mechanism_param(p_mechanism);

        // Early validation: reject all-zero IV/nonce for CBC and CTR modes.
        // An all-zero IV indicates an initialization error or IV reuse risk.
        // Note: AES-GCM nonces are generated internally by the backend (not
        // caller-supplied), so no zero-check is needed for GCM.
        match mechanism {
            CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if mech_param.len() == 16 && mech_param.iter().all(|&b| b == 0) {
                    tracing::error!("C_EncryptInit: all-zero IV rejected for AES-CBC");
                    return CKR_MECHANISM_PARAM_INVALID;
                }
            }
            CKM_AES_CTR => {
                if mech_param.len() >= 16 && mech_param[..16].iter().all(|&b| b == 0) {
                    tracing::error!("C_EncryptInit: all-zero IV rejected for AES-CTR");
                    return CKR_MECHANISM_PARAM_INVALID;
                }
            }
            _ => {}
        }

        sess.active_operation = Some(ActiveOperation::Encrypt {
            mechanism,
            key_handle: key,
            mechanism_param: Zeroizing::new(mech_param),
            data: Zeroizing::new(Vec::new()),
            cached_object: Some(obj.clone()),
        });
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// Helper to extract mechanism parameter bytes.
/// SAFETY: Caller must ensure p_mechanism is a valid, non-null pointer to CK_MECHANISM.
/// The p_parameter field is checked for null before constructing a slice.
fn extract_mechanism_param(p_mechanism: CK_MECHANISM_PTR) -> Vec<u8> {
    unsafe {
        let mech = &*p_mechanism;
        if mech.p_parameter.is_null() || mech.parameter_len == 0 {
            return Vec::new();
        }
        let len = mech.parameter_len as usize;
        // Defense-in-depth: reject absurdly large parameter lengths to prevent
        // out-of-bounds reads from a malicious or buggy C caller.
        // No PKCS#11 mechanism parameter should approach 64 MiB.
        if len > MAX_SINGLE_BUFFER {
            return Vec::new();
        }
        slice::from_raw_parts(mech.p_parameter as *const u8, len).to_vec()
    }
}

#[no_mangle]
pub extern "C" fn C_Encrypt(
    session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    p_encrypted_data: CK_BYTE_PTR,
    pul_encrypted_data_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_data.is_null() || pul_encrypted_data_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        let (mechanism, key_handle, mech_param) = match &sess.active_operation {
            Some(ActiveOperation::Encrypt {
                mechanism,
                key_handle,
                mechanism_param,
                ..
            }) => (*mechanism, *key_handle, mechanism_param.clone()),
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };

        if (data_len as usize) > MAX_SINGLE_BUFFER {
            sess.active_operation = None;
            return CKR_DATA_LEN_RANGE;
        }
        let data = unsafe { slice::from_raw_parts(p_data, data_len as usize) };

        // Get key material
        let obj = match hsm.object_store.get_object(key_handle) {
            Ok(o) => o,
            Err(e) => {
                sess.active_operation = None;
                return err_to_rv(e);
            }
        };
        let obj = obj.read();
        let key_bytes = match &obj.key_material {
            Some(km) => km.as_bytes(),
            None => {
                sess.active_operation = None;
                return CKR_KEY_HANDLE_INVALID;
            }
        };

        // Length query: estimate output size WITHOUT performing the actual
        // encryption, preserving the operation state for the real call.
        // This avoids consuming AES-GCM nonces and keeps the two-call idiom sound.
        if p_encrypted_data.is_null() {
            let estimated = match mechanism {
                CKM_AES_GCM => {
                    // GCM output = nonce (12) + ciphertext (= plaintext len) + tag (16)
                    data.len() + 12 + 16
                }
                CKM_AES_CBC | CKM_AES_CBC_PAD => {
                    // CBC-PAD may add up to one block; plain CBC output = input len
                    data.len() + 16
                }
                CKM_AES_CTR => data.len(),
                CKM_RSA_PKCS_OAEP => {
                    // RSA-OAEP output = modulus size in bytes
                    match &obj.modulus {
                        Some(m) => m.len(),
                        None => {
                            sess.active_operation = None;
                            return CKR_KEY_HANDLE_INVALID;
                        }
                    }
                }
                _ => {
                    sess.active_operation = None;
                    return CKR_MECHANISM_INVALID;
                }
            };
            unsafe {
                *pul_encrypted_data_len = estimated as CK_ULONG;
            }
            return CKR_OK;
        }

        let result = match mechanism {
            CKM_AES_GCM => hsm.crypto_backend.aes_256_gcm_encrypt(key_bytes, data),
            CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if mech_param.is_empty() {
                    Err(HsmError::MechanismParamInvalid)
                } else {
                    hsm.crypto_backend
                        .aes_cbc_encrypt(key_bytes, &mech_param, data)
                }
            }
            CKM_AES_CTR => {
                if mech_param.is_empty() {
                    Err(HsmError::MechanismParamInvalid)
                } else {
                    hsm.crypto_backend
                        .aes_ctr_encrypt(key_bytes, &mech_param, data)
                }
            }
            CKM_RSA_PKCS_OAEP => {
                let modulus = match &obj.modulus {
                    Some(m) => m.as_slice(),
                    None => {
                        sess.active_operation = None;
                        return CKR_KEY_HANDLE_INVALID;
                    }
                };
                let pub_exp = match &obj.public_exponent {
                    Some(e) => e.as_slice(),
                    None => {
                        sess.active_operation = None;
                        return CKR_KEY_HANDLE_INVALID;
                    }
                };
                let oaep_hash = match parse_oaep_hash(&mech_param) {
                    Ok(h) => h,
                    Err(rv) => {
                        sess.active_operation = None;
                        return rv;
                    }
                };
                hsm.crypto_backend
                    .rsa_oaep_encrypt(modulus, pub_exp, data, oaep_hash)
            }
            _ => {
                sess.active_operation = None;
                return CKR_MECHANISM_INVALID;
            }
        };

        match result {
            Ok(encrypted) => {
                let buf_len = unsafe { *pul_encrypted_data_len } as usize;
                if buf_len < encrypted.len() {
                    unsafe {
                        *pul_encrypted_data_len = encrypted.len() as CK_ULONG;
                    }
                    return CKR_BUFFER_TOO_SMALL;
                }

                let out = unsafe { slice::from_raw_parts_mut(p_encrypted_data, encrypted.len()) };
                out.copy_from_slice(&encrypted);
                unsafe {
                    *pul_encrypted_data_len = encrypted.len() as CK_ULONG;
                }

                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Encrypt {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Success,
                    None,
                );

                sess.active_operation = None;
                CKR_OK
            }
            Err(e) => {
                let rv = err_to_rv(e);
                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Encrypt {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Failure(rv as u64),
                    None,
                );
                sess.active_operation = None;
                rv
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_DecryptInit(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        if sess.active_operation.is_some() {
            return CKR_OPERATION_ACTIVE;
        }

        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_encrypt_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }

        let obj = match hsm.object_store.get_object(key) {
            Ok(o) => o,
            Err(_) => return CKR_KEY_HANDLE_INVALID,
        };
        {
            let obj_read = obj.read();
            // Private keys require login before use
            if obj_read.private && !sess.state.is_logged_in() {
                return CKR_USER_NOT_LOGGED_IN;
            }
            if !obj_read.can_decrypt {
                return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
            // SP 800-57 lifecycle check
            if let Err(_) = obj_read.check_lifecycle("decrypt") {
                return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
        }

        let mech_param = extract_mechanism_param(p_mechanism);
        sess.active_operation = Some(ActiveOperation::Decrypt {
            mechanism,
            key_handle: key,
            mechanism_param: Zeroizing::new(mech_param),
            data: Zeroizing::new(Vec::new()),
            cached_object: Some(obj.clone()),
        });
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_Decrypt(
    session: CK_SESSION_HANDLE,
    p_encrypted_data: CK_BYTE_PTR,
    encrypted_data_len: CK_ULONG,
    p_data: CK_BYTE_PTR,
    pul_data_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_encrypted_data.is_null() || pul_data_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        let (mechanism, key_handle, mech_param) = match &sess.active_operation {
            Some(ActiveOperation::Decrypt {
                mechanism,
                key_handle,
                mechanism_param,
                ..
            }) => (*mechanism, *key_handle, mechanism_param.clone()),
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };

        if (encrypted_data_len as usize) > MAX_SINGLE_BUFFER {
            sess.active_operation = None;
            return CKR_DATA_LEN_RANGE;
        }
        let data = unsafe { slice::from_raw_parts(p_encrypted_data, encrypted_data_len as usize) };

        let obj = match hsm.object_store.get_object(key_handle) {
            Ok(o) => o,
            Err(e) => {
                sess.active_operation = None;
                return err_to_rv(e);
            }
        };
        let obj = obj.read();
        let key_bytes = match &obj.key_material {
            Some(km) => km.as_bytes(),
            None => {
                sess.active_operation = None;
                return CKR_KEY_HANDLE_INVALID;
            }
        };

        // Length query: estimate output size WITHOUT performing the actual
        // decryption, preserving the operation state for the real call.
        if p_data.is_null() {
            let estimated = match mechanism {
                CKM_AES_GCM => {
                    // GCM plaintext = ciphertext - nonce (12) - tag (16)
                    data.len().saturating_sub(28)
                }
                CKM_AES_CBC | CKM_AES_CBC_PAD => data.len(),
                CKM_AES_CTR => data.len(),
                CKM_RSA_PKCS_OAEP => {
                    // RSA-OAEP plaintext is at most modulus size
                    data.len()
                }
                _ => {
                    sess.active_operation = None;
                    return CKR_MECHANISM_INVALID;
                }
            };
            unsafe {
                *pul_data_len = estimated as CK_ULONG;
            }
            return CKR_OK;
        }

        let result = match mechanism {
            CKM_AES_GCM => hsm.crypto_backend.aes_256_gcm_decrypt(key_bytes, data),
            CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if mech_param.is_empty() {
                    Err(HsmError::MechanismParamInvalid)
                } else {
                    hsm.crypto_backend
                        .aes_cbc_decrypt(key_bytes, &mech_param, data)
                }
            }
            CKM_AES_CTR => {
                if mech_param.is_empty() {
                    Err(HsmError::MechanismParamInvalid)
                } else {
                    hsm.crypto_backend
                        .aes_ctr_decrypt(key_bytes, &mech_param, data)
                }
            }
            CKM_RSA_PKCS_OAEP => {
                let oaep_hash = match parse_oaep_hash(&mech_param) {
                    Ok(h) => h,
                    Err(rv) => {
                        sess.active_operation = None;
                        return rv;
                    }
                };
                hsm.crypto_backend
                    .rsa_oaep_decrypt(key_bytes, data, oaep_hash)
            }
            _ => {
                sess.active_operation = None;
                return CKR_MECHANISM_INVALID;
            }
        };

        match result {
            Ok(decrypted) => {
                let buf_len = unsafe { *pul_data_len } as usize;
                if buf_len < decrypted.len() {
                    unsafe {
                        *pul_data_len = decrypted.len() as CK_ULONG;
                    }
                    return CKR_BUFFER_TOO_SMALL;
                }

                let out = unsafe { slice::from_raw_parts_mut(p_data, decrypted.len()) };
                out.copy_from_slice(&decrypted);
                unsafe {
                    *pul_data_len = decrypted.len() as CK_ULONG;
                }

                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Decrypt {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Success,
                    None,
                );

                sess.active_operation = None;
                CKR_OK
            }
            Err(e) => {
                let rv = err_to_rv(e);
                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Decrypt {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Failure(rv as u64),
                    None,
                );
                sess.active_operation = None;
                rv
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_SignInit(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        if !sess.state.is_logged_in() {
            return CKR_USER_NOT_LOGGED_IN;
        }
        if sess.active_operation.is_some() {
            return CKR_OPERATION_ACTIVE;
        }

        let mechanism = unsafe { (*p_mechanism).mechanism };

        // Explicit SHA-1 rejection: CKM_SHA1_RSA_PKCS is deprecated per
        // NIST SP 800-131A Rev.2.  Block it at the ABI boundary regardless
        // of what the mechanisms module says, as defense-in-depth.
        if mechanism == CKM_SHA1_RSA_PKCS {
            tracing::error!(
                "C_SignInit: SHA-1 based RSA signing (CKM_SHA1_RSA_PKCS) is prohibited"
            );
            return CKR_MECHANISM_INVALID;
        }

        if !mechanisms::is_sign_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check (signing context)
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, true)
        {
            return rv;
        }

        let obj = match hsm.object_store.get_object(key) {
            Ok(o) => o,
            Err(_) => return CKR_KEY_HANDLE_INVALID,
        };
        {
            let obj_read = obj.read();
            if !obj_read.can_sign {
                return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
            // SP 800-57 lifecycle check
            if let Err(_) = obj_read.check_lifecycle("sign") {
                return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
        }

        // Create a hasher if the mechanism has a built-in hash (for multi-part support)
        let hasher = sign::sign_mechanism_to_digest_mechanism(mechanism)
            .and_then(|digest_mech| hsm.crypto_backend.create_hasher(digest_mech).ok());

        sess.active_operation = Some(ActiveOperation::Sign {
            mechanism,
            key_handle: key,
            data: Zeroizing::new(Vec::new()),
            hasher,
            cached_object: Some(obj.clone()),
        });
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_Sign(
    session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_data.is_null() || pul_signature_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        let (mechanism, key_handle) = match &sess.active_operation {
            Some(ActiveOperation::Sign {
                mechanism,
                key_handle,
                ..
            }) => (*mechanism, *key_handle),
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };

        if (data_len as usize) > MAX_SINGLE_BUFFER {
            sess.active_operation = None;
            return CKR_DATA_LEN_RANGE;
        }
        let data = unsafe { slice::from_raw_parts(p_data, data_len as usize) };

        let obj = match hsm.object_store.get_object(key_handle) {
            Ok(o) => o,
            Err(e) => {
                sess.active_operation = None;
                return err_to_rv(e);
            }
        };
        let obj = obj.read();
        let key_bytes = match &obj.key_material {
            Some(km) => km.as_bytes(),
            None => {
                sess.active_operation = None;
                return CKR_KEY_HANDLE_INVALID;
            }
        };

        // Length query: estimate output size WITHOUT performing the actual
        // signature, preserving the operation state and avoiding RNG waste
        // (important for ECDSA which consumes a random nonce per signature).
        if p_signature.is_null() {
            let est = match estimated_signature_len(mechanism, &obj) {
                Some(n) => n,
                None => {
                    sess.active_operation = None;
                    return CKR_MECHANISM_INVALID;
                }
            };
            unsafe {
                *pul_signature_len = est as CK_ULONG;
            }
            return CKR_OK;
        }

        let result = sign_single_shot(&*hsm.crypto_backend, mechanism, key_bytes, data, &obj);

        match result {
            Ok(signature) => {
                let buf_len = unsafe { *pul_signature_len } as usize;
                if buf_len < signature.len() {
                    unsafe {
                        *pul_signature_len = signature.len() as CK_ULONG;
                    }
                    return CKR_BUFFER_TOO_SMALL;
                }

                let out = unsafe { slice::from_raw_parts_mut(p_signature, signature.len()) };
                out.copy_from_slice(&signature);
                unsafe {
                    *pul_signature_len = signature.len() as CK_ULONG;
                }

                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Sign {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Success,
                    None,
                );

                sess.active_operation = None;
                CKR_OK
            }
            Err(e) => {
                let rv = err_to_rv(e);
                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Sign {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Failure(rv as u64),
                    None,
                );
                sess.active_operation = None;
                rv
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// Helper to check if EC params correspond to P-384
fn is_p384_params(ec_params: &[u8]) -> bool {
    // OID for secp384r1: 1.3.132.0.34 = 06 05 2B 81 04 00 22
    const P384_OID: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
    ec_params == P384_OID || ec_params.windows(P384_OID.len()).any(|w| w == P384_OID)
}

/// Single-shot sign: hash + sign in one step (used by C_Sign and C_SignFinal for non-hashed mechanisms)
fn sign_single_shot(
    backend: &dyn CryptoBackend,
    mechanism: CK_MECHANISM_TYPE,
    key_bytes: &[u8],
    data: &[u8],
    obj: &crate::store::object::StoredObject,
) -> HsmResult<Vec<u8>> {
    if sign::is_pss_mechanism(mechanism) {
        let hash = sign::pss_mechanism_to_hash(mechanism)?;
        backend.rsa_pss_sign(key_bytes, data, hash)
    } else if sign::is_ecdsa_mechanism(mechanism) {
        let key_type = obj.key_type.unwrap_or(0);
        match key_type {
            CKK_EC => {
                let ec_params = obj.ec_params.as_deref().unwrap_or(&[]);
                if is_p384_params(ec_params) {
                    backend.ecdsa_p384_sign(key_bytes, data)
                } else {
                    backend.ecdsa_p256_sign(key_bytes, data)
                }
            }
            _ => Err(HsmError::KeyTypeInconsistent),
        }
    } else if sign::is_eddsa_mechanism(mechanism) {
        backend.ed25519_sign(key_bytes, data)
    } else if pqc::is_ml_dsa_mechanism(mechanism) {
        let variant = pqc::mechanism_to_ml_dsa_variant(mechanism).unwrap();
        backend.ml_dsa_sign(key_bytes, data, variant)
    } else if pqc::is_slh_dsa_mechanism(mechanism) {
        let variant = pqc::mechanism_to_slh_dsa_variant(mechanism).unwrap();
        backend.slh_dsa_sign(key_bytes, data, variant)
    } else if pqc::is_hybrid_mechanism(mechanism) {
        let ecdsa_key = obj
            .extra_attributes
            .get(&CKA_EC_POINT)
            .or(obj.ec_point.as_ref())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        backend.hybrid_sign(key_bytes, ecdsa_key, data)
    } else {
        // RSA PKCS#1 v1.5
        let hash_alg = sign::mechanism_to_hash(mechanism);
        backend.rsa_pkcs1v15_sign(key_bytes, data, hash_alg)
    }
}

/// Prehashed sign: used by C_SignFinal when data was hashed via multi-part C_SignUpdate.
/// The `digest` is the finalized hash output.
fn sign_prehashed(
    backend: &dyn CryptoBackend,
    mechanism: CK_MECHANISM_TYPE,
    key_bytes: &[u8],
    digest: &[u8],
    obj: &crate::store::object::StoredObject,
) -> HsmResult<Vec<u8>> {
    if sign::is_pss_mechanism(mechanism) {
        let hash = sign::pss_mechanism_to_hash(mechanism)?;
        backend.rsa_pss_sign_prehashed(key_bytes, digest, hash)
    } else if sign::is_ecdsa_mechanism(mechanism) {
        let key_type = obj.key_type.unwrap_or(0);
        match key_type {
            CKK_EC => {
                let ec_params = obj.ec_params.as_deref().unwrap_or(&[]);
                if is_p384_params(ec_params) {
                    backend.ecdsa_p384_sign_prehashed(key_bytes, digest)
                } else {
                    backend.ecdsa_p256_sign_prehashed(key_bytes, digest)
                }
            }
            _ => Err(HsmError::KeyTypeInconsistent),
        }
    } else {
        // RSA PKCS#1 v1.5 prehashed
        let hash_alg = sign::mechanism_to_hash(mechanism).ok_or(HsmError::MechanismInvalid)?;
        backend.rsa_pkcs1v15_sign_prehashed(key_bytes, digest, hash_alg)
    }
}

/// Single-shot verify: hash + verify in one step (used by C_Verify and C_VerifyFinal for non-hashed mechanisms)
fn verify_single_shot(
    backend: &dyn CryptoBackend,
    mechanism: CK_MECHANISM_TYPE,
    data: &[u8],
    signature: &[u8],
    obj: &crate::store::object::StoredObject,
) -> HsmResult<bool> {
    if sign::is_pss_mechanism(mechanism) {
        let modulus = obj.modulus.as_deref().ok_or(HsmError::KeyHandleInvalid)?;
        let pub_exp = obj
            .public_exponent
            .as_deref()
            .ok_or(HsmError::KeyHandleInvalid)?;
        let hash = sign::pss_mechanism_to_hash(mechanism)?;
        backend.rsa_pss_verify(modulus, pub_exp, data, signature, hash)
    } else if sign::is_ecdsa_mechanism(mechanism) {
        let ec_point = obj.ec_point.as_deref().ok_or(HsmError::KeyHandleInvalid)?;
        let ec_params = obj.ec_params.as_deref().unwrap_or(&[]);
        if is_p384_params(ec_params) {
            backend.ecdsa_p384_verify(ec_point, data, signature)
        } else {
            backend.ecdsa_p256_verify(ec_point, data, signature)
        }
    } else if sign::is_eddsa_mechanism(mechanism) {
        let pub_key = obj
            .public_key_data
            .as_deref()
            .or(obj.ec_point.as_deref())
            .ok_or(HsmError::KeyHandleInvalid)?;
        backend.ed25519_verify(pub_key, data, signature)
    } else if pqc::is_ml_dsa_mechanism(mechanism) {
        let pub_key = obj
            .public_key_data
            .as_deref()
            .ok_or(HsmError::KeyHandleInvalid)?;
        let variant = pqc::mechanism_to_ml_dsa_variant(mechanism).unwrap();
        backend.ml_dsa_verify(pub_key, data, signature, variant)
    } else if pqc::is_slh_dsa_mechanism(mechanism) {
        let pub_key = obj
            .public_key_data
            .as_deref()
            .ok_or(HsmError::KeyHandleInvalid)?;
        let variant = pqc::mechanism_to_slh_dsa_variant(mechanism).unwrap();
        backend.slh_dsa_verify(pub_key, data, signature, variant)
    } else if pqc::is_hybrid_mechanism(mechanism) {
        let ml_dsa_vk = obj
            .public_key_data
            .as_deref()
            .ok_or(HsmError::KeyHandleInvalid)?;
        let ecdsa_pk = obj
            .extra_attributes
            .get(&CKA_EC_POINT)
            .or(obj.ec_point.as_ref())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        backend.hybrid_verify(ml_dsa_vk, ecdsa_pk, data, signature)
    } else {
        // RSA PKCS#1 v1.5
        let modulus = obj.modulus.as_deref().ok_or(HsmError::KeyHandleInvalid)?;
        let pub_exp = obj
            .public_exponent
            .as_deref()
            .ok_or(HsmError::KeyHandleInvalid)?;
        let hash_alg = sign::mechanism_to_hash(mechanism);
        backend.rsa_pkcs1v15_verify(modulus, pub_exp, data, signature, hash_alg)
    }
}

/// Prehashed verify: used by C_VerifyFinal when data was hashed via multi-part C_VerifyUpdate.
/// The `digest` is the finalized hash output.
fn verify_prehashed(
    backend: &dyn CryptoBackend,
    mechanism: CK_MECHANISM_TYPE,
    digest: &[u8],
    signature: &[u8],
    obj: &crate::store::object::StoredObject,
) -> HsmResult<bool> {
    if sign::is_pss_mechanism(mechanism) {
        let modulus = obj.modulus.as_deref().ok_or(HsmError::KeyHandleInvalid)?;
        let pub_exp = obj
            .public_exponent
            .as_deref()
            .ok_or(HsmError::KeyHandleInvalid)?;
        let hash = sign::pss_mechanism_to_hash(mechanism)?;
        backend.rsa_pss_verify_prehashed(modulus, pub_exp, digest, signature, hash)
    } else if sign::is_ecdsa_mechanism(mechanism) {
        let ec_point = obj.ec_point.as_deref().ok_or(HsmError::KeyHandleInvalid)?;
        let ec_params = obj.ec_params.as_deref().unwrap_or(&[]);
        if is_p384_params(ec_params) {
            backend.ecdsa_p384_verify_prehashed(ec_point, digest, signature)
        } else {
            backend.ecdsa_p256_verify_prehashed(ec_point, digest, signature)
        }
    } else {
        // RSA PKCS#1 v1.5 prehashed
        let modulus = obj.modulus.as_deref().ok_or(HsmError::KeyHandleInvalid)?;
        let pub_exp = obj
            .public_exponent
            .as_deref()
            .ok_or(HsmError::KeyHandleInvalid)?;
        let hash_alg = sign::mechanism_to_hash(mechanism).ok_or(HsmError::MechanismInvalid)?;
        backend.rsa_pkcs1v15_verify_prehashed(modulus, pub_exp, digest, signature, hash_alg)
    }
}

#[no_mangle]
pub extern "C" fn C_VerifyInit(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        if sess.active_operation.is_some() {
            return CKR_OPERATION_ACTIVE;
        }

        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_sign_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check (verify is not a signing context)
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }

        let obj = match hsm.object_store.get_object(key) {
            Ok(o) => o,
            Err(_) => return CKR_KEY_HANDLE_INVALID,
        };
        {
            let obj_read = obj.read();
            // Private keys require login before use
            if obj_read.private && !sess.state.is_logged_in() {
                return CKR_USER_NOT_LOGGED_IN;
            }
            if !obj_read.can_verify {
                return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
            // SP 800-57 lifecycle check
            if let Err(_) = obj_read.check_lifecycle("verify") {
                return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
        }

        // Create a hasher if the mechanism has a built-in hash (for multi-part support)
        let hasher = sign::sign_mechanism_to_digest_mechanism(mechanism)
            .and_then(|digest_mech| hsm.crypto_backend.create_hasher(digest_mech).ok());

        sess.active_operation = Some(ActiveOperation::Verify {
            mechanism,
            key_handle: key,
            data: Zeroizing::new(Vec::new()),
            hasher,
            cached_object: Some(obj.clone()),
        });
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_Verify(
    session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    signature_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_data.is_null() || p_signature.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        let (mechanism, key_handle) = match &sess.active_operation {
            Some(ActiveOperation::Verify {
                mechanism,
                key_handle,
                ..
            }) => (*mechanism, *key_handle),
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };

        if (data_len as usize) > MAX_SINGLE_BUFFER || (signature_len as usize) > MAX_SINGLE_BUFFER {
            sess.active_operation = None;
            return CKR_DATA_LEN_RANGE;
        }
        let data = unsafe { slice::from_raw_parts(p_data, data_len as usize) };
        let signature = unsafe { slice::from_raw_parts(p_signature, signature_len as usize) };

        let obj = match hsm.object_store.get_object(key_handle) {
            Ok(o) => o,
            Err(e) => {
                sess.active_operation = None;
                return err_to_rv(e);
            }
        };
        let obj = obj.read();

        let result = verify_single_shot(&*hsm.crypto_backend, mechanism, data, signature, &obj);

        sess.active_operation = None;

        match result {
            Ok(true) => {
                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Verify {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Success,
                    None,
                );
                CKR_OK
            }
            Ok(false) => {
                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Verify {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Failure(CKR_SIGNATURE_INVALID as u64),
                    None,
                );
                CKR_SIGNATURE_INVALID
            }
            Err(e) => {
                let rv = err_to_rv(e);
                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Verify {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Failure(rv as u64),
                    None,
                );
                rv
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ============================================================================
// Key generation
// ============================================================================

#[no_mangle]
pub extern "C" fn C_GenerateKey(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    p_template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    ph_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() || ph_key.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        if !sess.read().is_rw() {
            return CKR_SESSION_READ_ONLY;
        }

        let mechanism = unsafe { (*p_mechanism).mechanism };
        if mechanism != CKM_AES_KEY_GEN {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }

        let template = if p_template.is_null() {
            vec![]
        } else {
            match parse_template(p_template, count) {
                Ok(t) => t,
                Err(rv) => return rv,
            }
        };

        // Get value_len from template (default 32 for AES-256)
        let key_len = template
            .iter()
            .find(|(t, _)| *t == CKA_VALUE_LEN)
            .and_then(|(_, v)| {
                if v.len() >= std::mem::size_of::<CK_ULONG>() {
                    let mut buf = [0u8; std::mem::size_of::<CK_ULONG>()];
                    buf.copy_from_slice(&v[..std::mem::size_of::<CK_ULONG>()]);
                    Some(CK_ULONG::from_ne_bytes(buf) as usize)
                } else {
                    None
                }
            })
            .unwrap_or(32);

        let key_material = match hsm
            .crypto_backend
            .generate_aes_key(key_len, hsm.algorithm_config.fips_approved_only)
        {
            Ok(k) => k,
            Err(e) => return err_to_rv(e),
        };

        let handle = match hsm.object_store.next_handle() {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };
        let mut obj = StoredObject::new(handle, CKO_SECRET_KEY);
        obj.key_type = Some(CKK_AES);
        obj.key_material = Some(key_material);
        obj.value_len = Some(key_len as CK_ULONG);
        obj.can_encrypt = true;
        obj.can_decrypt = true;
        obj.sensitive = true;
        obj.extractable = false;
        obj.private = true;

        // Apply template overrides
        for (attr_type, value) in &template {
            match *attr_type {
                CKA_LABEL => obj.label = value.clone(),
                CKA_ID => obj.id = value.clone(),
                CKA_TOKEN => {
                    obj.token_object = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    }
                }
                CKA_PRIVATE => {
                    obj.private = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    }
                }
                CKA_SENSITIVE => {
                    obj.sensitive = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    }
                }
                CKA_EXTRACTABLE => {
                    obj.extractable = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    }
                }
                CKA_ENCRYPT => {
                    obj.can_encrypt = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    }
                }
                CKA_DECRYPT => {
                    obj.can_decrypt = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    }
                }
                CKA_WRAP => {
                    obj.can_wrap = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    }
                }
                CKA_UNWRAP => {
                    obj.can_unwrap = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    }
                }
                CKA_START_DATE => {
                    if value.len() == 8 {
                        let mut date = [0u8; 8];
                        date.copy_from_slice(value);
                        obj.start_date = Some(date);
                    } else if value.is_empty() {
                        obj.start_date = None;
                    }
                }
                CKA_END_DATE => {
                    if value.len() == 8 {
                        let mut date = [0u8; 8];
                        date.copy_from_slice(value);
                        obj.end_date = Some(date);
                    } else if value.is_empty() {
                        obj.end_date = None;
                    }
                }
                _ => {}
            }
        }

        if let Err(e) = hsm.object_store.insert_object(obj) {
            return err_to_rv(e);
        }

        let _ = hsm.audit_log.record(
            session as u64,
            AuditOperation::GenerateKey {
                mechanism: mechanism as u64,
                key_length: key_len as u32,
                fips_approved: mechanisms::is_fips_approved(mechanism),
            },
            AuditResult::Success,
            None,
        );

        unsafe {
            *ph_key = handle;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_GenerateKeyPair(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    p_public_key_template: CK_ATTRIBUTE_PTR,
    public_key_attr_count: CK_ULONG,
    p_private_key_template: CK_ATTRIBUTE_PTR,
    private_key_attr_count: CK_ULONG,
    ph_public_key: CK_OBJECT_HANDLE_PTR,
    ph_private_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() || ph_public_key.is_null() || ph_private_key.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        if !sess.read().is_rw() {
            return CKR_SESSION_READ_ONLY;
        }

        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_keypair_gen_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }

        let pub_template = if p_public_key_template.is_null() {
            vec![]
        } else {
            match parse_template(p_public_key_template, public_key_attr_count) {
                Ok(t) => t,
                Err(rv) => return rv,
            }
        };
        let priv_template = if p_private_key_template.is_null() {
            vec![]
        } else {
            match parse_template(p_private_key_template, private_key_attr_count) {
                Ok(t) => t,
                Err(rv) => return rv,
            }
        };

        let result = match mechanism {
            CKM_RSA_PKCS_KEY_PAIR_GEN => generate_rsa_keypair(&hsm, &pub_template, &priv_template),
            CKM_EC_KEY_PAIR_GEN => generate_ec_keypair(&hsm, &pub_template, &priv_template),
            CKM_EDDSA => generate_ed25519_keypair(&hsm, &pub_template, &priv_template),
            m if pqc::is_ml_kem_mechanism(m)
                || pqc::is_ml_dsa_mechanism(m)
                || pqc::is_slh_dsa_mechanism(m) =>
            {
                generate_pqc_keypair(&hsm, mechanism, &pub_template, &priv_template)
            }
            _ => return CKR_MECHANISM_INVALID,
        };
        let (pub_handle, priv_handle, key_length) = match result {
            Ok(r) => r,
            Err(rv) => return rv,
        };

        let _ = hsm.audit_log.record(
            session as u64,
            AuditOperation::GenerateKeyPair {
                mechanism: mechanism as u64,
                key_length,
                fips_approved: mechanisms::is_fips_approved(mechanism),
            },
            AuditResult::Success,
            None,
        );

        unsafe {
            *ph_public_key = pub_handle;
            *ph_private_key = priv_handle;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// RSA key pair generation helper
fn generate_rsa_keypair(
    hsm: &HsmCore,
    pub_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    priv_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, u32), CK_RV> {
    let modulus_bits = read_ulong_attr(pub_template, CKA_MODULUS_BITS).unwrap_or(2048) as u32;

    let (private_key_der, modulus, pub_exp) = hsm
        .crypto_backend
        .generate_rsa_key_pair(modulus_bits, hsm.algorithm_config.fips_approved_only)
        .map_err(err_to_rv)?;

    // FIPS 140-3 §9.6: Pairwise consistency test
    if let Err(_) = pairwise_test::rsa_pairwise_test(
        hsm.crypto_backend.as_ref(),
        &private_key_der,
        &modulus,
        &pub_exp,
    ) {
        tracing::error!("RSA pairwise consistency test failed — entering error state");
        POST_FAILED.store(true, Ordering::Release);
        return Err(CKR_GENERAL_ERROR);
    }

    let pub_handle = hsm.object_store.next_handle().map_err(err_to_rv)?;
    let mut pub_obj = StoredObject::new(pub_handle, CKO_PUBLIC_KEY);
    pub_obj.key_type = Some(CKK_RSA);
    pub_obj.modulus = Some(modulus.clone());
    pub_obj.modulus_bits = Some(modulus_bits as CK_ULONG);
    pub_obj.public_exponent = Some(pub_exp.clone());
    pub_obj.can_verify = true;
    pub_obj.can_encrypt = true;
    pub_obj.private = false;
    pub_obj.sensitive = false;
    let rv = apply_pub_template(&mut pub_obj, pub_template);
    if rv != CKR_OK {
        return Err(rv);
    }

    let priv_handle = hsm.object_store.next_handle().map_err(err_to_rv)?;
    let mut priv_obj = StoredObject::new(priv_handle, CKO_PRIVATE_KEY);
    priv_obj.key_type = Some(CKK_RSA);
    priv_obj.key_material = Some(private_key_der);
    priv_obj.modulus = Some(modulus);
    priv_obj.modulus_bits = Some(modulus_bits as CK_ULONG);
    priv_obj.public_exponent = Some(pub_exp);
    priv_obj.can_sign = true;
    priv_obj.can_decrypt = true;
    priv_obj.sensitive = true;
    priv_obj.extractable = false;
    priv_obj.private = true;
    let rv = apply_priv_template(&mut priv_obj, priv_template);
    if rv != CKR_OK {
        return Err(rv);
    }

    hsm.object_store
        .insert_object(pub_obj)
        .map_err(|e| err_to_rv(e))?;
    hsm.object_store
        .insert_object(priv_obj)
        .map_err(|e| err_to_rv(e))?;
    Ok((pub_handle, priv_handle, modulus_bits))
}

/// EC key pair generation helper (P-256 / P-384)
fn generate_ec_keypair(
    hsm: &HsmCore,
    pub_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    priv_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, u32), CK_RV> {
    // Determine curve from CKA_EC_PARAMS in the public template
    let ec_params = pub_template
        .iter()
        .find(|(t, _)| *t == CKA_EC_PARAMS)
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    let is_p384 = is_p384_params(&ec_params);
    let (private_key, public_key, key_bits) = if is_p384 {
        let (priv_key, pub_key) = hsm
            .crypto_backend
            .generate_ec_p384_key_pair()
            .map_err(err_to_rv)?;
        (priv_key, pub_key, 384u32)
    } else {
        let (priv_key, pub_key) = hsm
            .crypto_backend
            .generate_ec_p256_key_pair()
            .map_err(err_to_rv)?;
        (priv_key, pub_key, 256u32)
    };

    // FIPS 140-3 §9.6: Pairwise consistency test
    let pairwise_result = if is_p384 {
        pairwise_test::ecdsa_p384_pairwise_test(
            hsm.crypto_backend.as_ref(),
            &private_key,
            &public_key,
        )
    } else {
        pairwise_test::ecdsa_p256_pairwise_test(
            hsm.crypto_backend.as_ref(),
            &private_key,
            &public_key,
        )
    };
    if pairwise_result.is_err() {
        tracing::error!("ECDSA pairwise consistency test failed — entering error state");
        POST_FAILED.store(true, Ordering::Release);
        return Err(CKR_GENERAL_ERROR);
    }

    let pub_handle = hsm.object_store.next_handle().map_err(err_to_rv)?;
    let mut pub_obj = StoredObject::new(pub_handle, CKO_PUBLIC_KEY);
    pub_obj.key_type = Some(CKK_EC);
    pub_obj.ec_params = Some(ec_params.clone());
    pub_obj.ec_point = Some(public_key.clone());
    pub_obj.can_verify = true;
    pub_obj.private = false;
    pub_obj.sensitive = false;
    let rv = apply_pub_template(&mut pub_obj, pub_template);
    if rv != CKR_OK {
        return Err(rv);
    }

    let priv_handle = hsm.object_store.next_handle().map_err(err_to_rv)?;
    let mut priv_obj = StoredObject::new(priv_handle, CKO_PRIVATE_KEY);
    priv_obj.key_type = Some(CKK_EC);
    priv_obj.key_material = Some(private_key);
    priv_obj.ec_params = Some(ec_params);
    priv_obj.ec_point = Some(public_key);
    priv_obj.can_sign = true;
    priv_obj.can_derive = true;
    priv_obj.sensitive = true;
    priv_obj.extractable = false;
    priv_obj.private = true;
    let rv = apply_priv_template(&mut priv_obj, priv_template);
    if rv != CKR_OK {
        return Err(rv);
    }

    hsm.object_store
        .insert_object(pub_obj)
        .map_err(|e| err_to_rv(e))?;
    hsm.object_store
        .insert_object(priv_obj)
        .map_err(|e| err_to_rv(e))?;
    Ok((pub_handle, priv_handle, key_bits))
}

/// Ed25519 key pair generation helper
fn generate_ed25519_keypair(
    hsm: &HsmCore,
    pub_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    priv_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, u32), CK_RV> {
    let (private_key, public_key) = hsm
        .crypto_backend
        .generate_ed25519_key_pair()
        .map_err(err_to_rv)?;

    // FIPS 140-3 §9.6: Pairwise consistency test
    if let Err(_) =
        pairwise_test::ed25519_pairwise_test(hsm.crypto_backend.as_ref(), &private_key, &public_key)
    {
        tracing::error!("Ed25519 pairwise consistency test failed — entering error state");
        POST_FAILED.store(true, Ordering::Release);
        return Err(CKR_GENERAL_ERROR);
    }

    let pub_handle = hsm.object_store.next_handle().map_err(err_to_rv)?;
    let mut pub_obj = StoredObject::new(pub_handle, CKO_PUBLIC_KEY);
    pub_obj.key_type = Some(CKK_EC_EDWARDS);
    pub_obj.public_key_data = Some(public_key.clone());
    pub_obj.ec_point = Some(public_key.clone());
    pub_obj.can_verify = true;
    pub_obj.private = false;
    pub_obj.sensitive = false;
    let rv = apply_pub_template(&mut pub_obj, pub_template);
    if rv != CKR_OK {
        return Err(rv);
    }

    let priv_handle = hsm.object_store.next_handle().map_err(err_to_rv)?;
    let mut priv_obj = StoredObject::new(priv_handle, CKO_PRIVATE_KEY);
    priv_obj.key_type = Some(CKK_EC_EDWARDS);
    priv_obj.key_material = Some(private_key);
    priv_obj.public_key_data = Some(public_key.clone());
    priv_obj.ec_point = Some(public_key);
    priv_obj.can_sign = true;
    priv_obj.sensitive = true;
    priv_obj.extractable = false;
    priv_obj.private = true;
    let rv = apply_priv_template(&mut priv_obj, priv_template);
    if rv != CKR_OK {
        return Err(rv);
    }

    hsm.object_store
        .insert_object(pub_obj)
        .map_err(|e| err_to_rv(e))?;
    hsm.object_store
        .insert_object(priv_obj)
        .map_err(|e| err_to_rv(e))?;
    Ok((pub_handle, priv_handle, 256))
}

/// PQC key pair generation helper (ML-KEM, ML-DSA, SLH-DSA)
fn generate_pqc_keypair(
    hsm: &HsmCore,
    mechanism: CK_MECHANISM_TYPE,
    pub_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    priv_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, u32), CK_RV> {
    let (private_key, public_key, key_type, key_bits) =
        if let Some(variant) = pqc::mechanism_to_ml_kem_variant(mechanism) {
            let (dk_seed, ek_bytes) = hsm
                .crypto_backend
                .ml_kem_keygen(variant)
                .map_err(err_to_rv)?;
            let bits = match variant {
                pqc::MlKemVariant::MlKem512 => 512u32,
                pqc::MlKemVariant::MlKem768 => 768,
                pqc::MlKemVariant::MlKem1024 => 1024,
            };
            (dk_seed, ek_bytes, CKK_ML_KEM, bits)
        } else if let Some(variant) = pqc::mechanism_to_ml_dsa_variant(mechanism) {
            let (sk_seed, vk_bytes) = hsm
                .crypto_backend
                .ml_dsa_keygen(variant)
                .map_err(err_to_rv)?;
            let bits = match variant {
                pqc::MlDsaVariant::MlDsa44 => 44u32,
                pqc::MlDsaVariant::MlDsa65 => 65,
                pqc::MlDsaVariant::MlDsa87 => 87,
            };
            (sk_seed, vk_bytes, CKK_ML_DSA, bits)
        } else if let Some(variant) = pqc::mechanism_to_slh_dsa_variant(mechanism) {
            let (sk_bytes, vk_bytes) = hsm
                .crypto_backend
                .slh_dsa_keygen(variant)
                .map_err(err_to_rv)?;
            let bits = match variant {
                pqc::SlhDsaVariant::Sha2_128s => 128u32,
                pqc::SlhDsaVariant::Sha2_256s => 256,
            };
            (sk_bytes, vk_bytes, CKK_SLH_DSA, bits)
        } else {
            return Err(CKR_MECHANISM_INVALID);
        };

    // FIPS 140-3 §9.6: Pairwise consistency test for PQC key pairs
    let pairwise_result = if key_type == CKK_ML_KEM {
        let variant_name = match pqc::mechanism_to_ml_kem_variant(mechanism).unwrap() {
            pqc::MlKemVariant::MlKem512 => "ML-KEM-512",
            pqc::MlKemVariant::MlKem768 => "ML-KEM-768",
            pqc::MlKemVariant::MlKem1024 => "ML-KEM-1024",
        };
        pairwise_test::ml_kem_pairwise_test(
            hsm.crypto_backend.as_ref(),
            &private_key,
            &public_key,
            variant_name,
        )
    } else if key_type == CKK_ML_DSA {
        let variant_name = match pqc::mechanism_to_ml_dsa_variant(mechanism).unwrap() {
            pqc::MlDsaVariant::MlDsa44 => "ML-DSA-44",
            pqc::MlDsaVariant::MlDsa65 => "ML-DSA-65",
            pqc::MlDsaVariant::MlDsa87 => "ML-DSA-87",
        };
        pairwise_test::ml_dsa_pairwise_test(
            hsm.crypto_backend.as_ref(),
            &private_key,
            &public_key,
            variant_name,
        )
    } else if key_type == CKK_SLH_DSA {
        let variant_name = match pqc::mechanism_to_slh_dsa_variant(mechanism).unwrap() {
            pqc::SlhDsaVariant::Sha2_128s => "SLH-DSA-SHA2-128s",
            pqc::SlhDsaVariant::Sha2_256s => "SLH-DSA-SHA2-256s",
        };
        pairwise_test::slh_dsa_pairwise_test(
            hsm.crypto_backend.as_ref(),
            &private_key,
            &public_key,
            variant_name,
        )
    } else {
        Ok(())
    };
    if pairwise_result.is_err() {
        tracing::error!("PQC pairwise consistency test failed — entering error state");
        POST_FAILED.store(true, Ordering::Release);
        return Err(CKR_GENERAL_ERROR);
    }

    let pub_handle = hsm.object_store.next_handle().map_err(err_to_rv)?;
    let mut pub_obj = StoredObject::new(pub_handle, CKO_PUBLIC_KEY);
    pub_obj.key_type = Some(key_type);
    pub_obj.public_key_data = Some(public_key.clone());
    pub_obj.can_verify = key_type != CKK_ML_KEM;
    pub_obj.can_derive = key_type == CKK_ML_KEM; // KEM uses derive for encapsulate
    pub_obj.private = false;
    pub_obj.sensitive = false;
    let rv = apply_pub_template(&mut pub_obj, pub_template);
    if rv != CKR_OK {
        return Err(rv);
    }

    let priv_handle = hsm.object_store.next_handle().map_err(err_to_rv)?;
    let mut priv_obj = StoredObject::new(priv_handle, CKO_PRIVATE_KEY);
    priv_obj.key_type = Some(key_type);
    priv_obj.key_material = Some(private_key);
    priv_obj.public_key_data = Some(public_key);
    priv_obj.can_sign = key_type != CKK_ML_KEM;
    priv_obj.can_derive = key_type == CKK_ML_KEM; // KEM uses derive for decapsulate
    priv_obj.sensitive = true;
    priv_obj.extractable = false;
    priv_obj.private = true;
    let rv = apply_priv_template(&mut priv_obj, priv_template);
    if rv != CKR_OK {
        return Err(rv);
    }

    hsm.object_store
        .insert_object(pub_obj)
        .map_err(|e| err_to_rv(e))?;
    hsm.object_store
        .insert_object(priv_obj)
        .map_err(|e| err_to_rv(e))?;
    Ok((pub_handle, priv_handle, key_bits))
}

fn read_ulong_attr(
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    attr: CK_ATTRIBUTE_TYPE,
) -> Option<CK_ULONG> {
    template
        .iter()
        .find(|(t, _)| *t == attr)
        .and_then(|(_, v)| {
            if v.len() >= std::mem::size_of::<CK_ULONG>() {
                let mut buf = [0u8; std::mem::size_of::<CK_ULONG>()];
                buf.copy_from_slice(&v[..std::mem::size_of::<CK_ULONG>()]);
                Some(CK_ULONG::from_ne_bytes(buf))
            } else {
                None
            }
        })
}

fn apply_pub_template(obj: &mut StoredObject, template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> CK_RV {
    for (attr_type, value) in template {
        match *attr_type {
            CKA_LABEL => obj.label = value.clone(),
            CKA_ID => obj.id = value.clone(),
            CKA_TOKEN => {
                obj.token_object = match parse_ck_bbool(value) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            }
            CKA_VERIFY => {
                obj.can_verify = match parse_ck_bbool(value) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            }
            CKA_ENCRYPT => {
                obj.can_encrypt = match parse_ck_bbool(value) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            }
            CKA_WRAP => {
                obj.can_wrap = match parse_ck_bbool(value) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            }
            CKA_START_DATE => {
                if value.len() == 8 {
                    let mut date = [0u8; 8];
                    date.copy_from_slice(value);
                    obj.start_date = Some(date);
                } else if value.is_empty() {
                    obj.start_date = None;
                }
            }
            CKA_END_DATE => {
                if value.len() == 8 {
                    let mut date = [0u8; 8];
                    date.copy_from_slice(value);
                    obj.end_date = Some(date);
                } else if value.is_empty() {
                    obj.end_date = None;
                }
            }
            _ => {}
        }
    }
    CKR_OK
}

fn apply_priv_template(obj: &mut StoredObject, template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> CK_RV {
    for (attr_type, value) in template {
        match *attr_type {
            CKA_LABEL => obj.label = value.clone(),
            CKA_ID => obj.id = value.clone(),
            CKA_TOKEN => {
                obj.token_object = match parse_ck_bbool(value) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            }
            CKA_SENSITIVE => {
                obj.sensitive = match parse_ck_bbool(value) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            }
            CKA_EXTRACTABLE => {
                obj.extractable = match parse_ck_bbool(value) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            }
            CKA_SIGN => {
                obj.can_sign = match parse_ck_bbool(value) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            }
            CKA_DECRYPT => {
                obj.can_decrypt = match parse_ck_bbool(value) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            }
            CKA_UNWRAP => {
                obj.can_unwrap = match parse_ck_bbool(value) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            }
            CKA_DERIVE => {
                obj.can_derive = match parse_ck_bbool(value) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            }
            CKA_START_DATE => {
                if value.len() == 8 {
                    let mut date = [0u8; 8];
                    date.copy_from_slice(value);
                    obj.start_date = Some(date);
                } else if value.is_empty() {
                    obj.start_date = None;
                }
            }
            CKA_END_DATE => {
                if value.len() == 8 {
                    let mut date = [0u8; 8];
                    date.copy_from_slice(value);
                    obj.end_date = Some(date);
                } else if value.is_empty() {
                    obj.end_date = None;
                }
            }
            _ => {}
        }
    }
    CKR_OK
}

// ============================================================================
// Random generation
// ============================================================================

#[no_mangle]
pub extern "C" fn C_SeedRandom(
    session: CK_SESSION_HANDLE,
    _p_seed: CK_BYTE_PTR,
    _seed_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        let _ = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        // We use OsRng — seeding is not supported/needed
        CKR_RANDOM_SEED_NOT_SUPPORTED
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_GenerateRandom(
    session: CK_SESSION_HANDLE,
    p_random_data: CK_BYTE_PTR,
    random_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_random_data.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if (random_len as usize) > MAX_SINGLE_BUFFER {
            return CKR_DATA_LEN_RANGE;
        }
        let _ = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };

        use rand::rngs::OsRng;
        use rand::RngCore;

        let data = unsafe { slice::from_raw_parts_mut(p_random_data, random_len as usize) };
        OsRng.fill_bytes(data);

        let _ = hsm.audit_log.record(
            session as u64,
            AuditOperation::GenerateRandom {
                length: random_len as u32,
            },
            AuditResult::Success,
            None,
        );

        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ============================================================================
// Stubs for unimplemented functions (return CKR_FUNCTION_NOT_SUPPORTED)
// ============================================================================

fn not_supported() -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// C_GetOperationState saves the cryptographic operation state of a session.
/// Supports the two-call idiom: if pOperationState is NULL, only the length is returned.
#[no_mangle]
pub extern "C" fn C_GetOperationState(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    pulOperationStateLen: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pulOperationStateLen.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(hSession) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let sess = sess.read();

        let op = match &sess.active_operation {
            Some(op) => op,
            None => return CKR_OPERATION_NOT_INITIALIZED,
        };

        // Encrypt/Decrypt operations with key material are not saveable
        // (would require saving key handle binding which is session-specific)
        match op {
            ActiveOperation::Digest { .. } => {}
            ActiveOperation::Sign { .. } | ActiveOperation::Verify { .. } => {}
            ActiveOperation::Encrypt { .. } | ActiveOperation::Decrypt { .. } => {
                return CKR_STATE_UNSAVEABLE;
            }
        }

        let state_blob = match op.serialize_state(&hsm.state_hmac_key) {
            Ok(v) => v,
            Err(_) => return CKR_STATE_UNSAVEABLE,
        };

        if pOperationState.is_null() {
            // Length-only query
            unsafe {
                *pulOperationStateLen = state_blob.len() as CK_ULONG;
            }
            return CKR_OK;
        }

        let buf_len = unsafe { *pulOperationStateLen } as usize;
        if buf_len < state_blob.len() {
            unsafe {
                *pulOperationStateLen = state_blob.len() as CK_ULONG;
            }
            return CKR_BUFFER_TOO_SMALL;
        }

        let out = unsafe { slice::from_raw_parts_mut(pOperationState, state_blob.len()) };
        out.copy_from_slice(&state_blob);
        unsafe {
            *pulOperationStateLen = state_blob.len() as CK_ULONG;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// C_SetOperationState restores the cryptographic operation state of a session.
/// hEncryptionKey and hAuthenticationKey are used to supply key handles for
/// encrypt/decrypt and sign/verify operations respectively.
#[no_mangle]
pub extern "C" fn C_SetOperationState(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    ulOperationStateLen: CK_ULONG,
    _hEncryptionKey: CK_OBJECT_HANDLE,
    hAuthenticationKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pOperationState.is_null() || ulOperationStateLen == 0 {
            return CKR_ARGUMENTS_BAD;
        }

        let blob = unsafe { slice::from_raw_parts(pOperationState, ulOperationStateLen as usize) };

        let (op_type, mechanism, key_handle, _mechanism_param, data) =
            match ActiveOperation::deserialize_state(blob, &hsm.state_hmac_key) {
                Ok(v) => v,
                Err(_) => return CKR_SAVED_STATE_INVALID,
            };

        // Reconstruct the ActiveOperation based on type
        let active_op = match op_type {
            // Digest: reconstruct hasher and re-feed accumulated data
            OP_TYPE_DIGEST => {
                let hasher = match hsm.crypto_backend.create_hasher(mechanism) {
                    Ok(mut h) => {
                        // Re-feed accumulated data to restore hasher state
                        if !data.is_empty() {
                            h.update(&data);
                        }
                        h
                    }
                    Err(_) => return CKR_SAVED_STATE_INVALID,
                };
                ActiveOperation::Digest {
                    mechanism,
                    hasher: Some(hasher),
                    accumulated_input: data,
                }
            }
            // Sign: reconstruct hasher (if hash-then-sign mechanism) and restore
            OP_TYPE_SIGN => {
                let resolved_key = if hAuthenticationKey != 0 {
                    hAuthenticationKey
                } else {
                    key_handle
                };
                // Validate the key handle exists
                if hsm.object_store.get_object(resolved_key).is_err() {
                    return CKR_KEY_HANDLE_INVALID;
                }
                // Try to create a hasher for hash-then-sign mechanisms
                let hasher = hsm
                    .crypto_backend
                    .create_hasher(mechanism)
                    .ok()
                    .map(|mut h| {
                        if !data.is_empty() {
                            h.update(&data);
                        }
                        h
                    });
                ActiveOperation::Sign {
                    mechanism,
                    key_handle: resolved_key,
                    data,
                    hasher,
                    cached_object: None,
                }
            }
            // Verify: same as sign but uses hAuthenticationKey
            OP_TYPE_VERIFY => {
                let resolved_key = if hAuthenticationKey != 0 {
                    hAuthenticationKey
                } else {
                    key_handle
                };
                if hsm.object_store.get_object(resolved_key).is_err() {
                    return CKR_KEY_HANDLE_INVALID;
                }
                let hasher = hsm
                    .crypto_backend
                    .create_hasher(mechanism)
                    .ok()
                    .map(|mut h| {
                        if !data.is_empty() {
                            h.update(&data);
                        }
                        h
                    });
                ActiveOperation::Verify {
                    mechanism,
                    key_handle: resolved_key,
                    data,
                    hasher,
                    cached_object: None,
                }
            }
            // Encrypt/Decrypt: not restorable
            OP_TYPE_ENCRYPT | OP_TYPE_DECRYPT => return CKR_SAVED_STATE_INVALID,
            _ => return CKR_SAVED_STATE_INVALID,
        };

        let sess = match hsm.session_manager.get_session(hSession) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();
        sess.active_operation = Some(active_op);
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// C_CopyObject creates a deep copy of an existing object with optional
/// attribute modifications from the template.
///
/// PKCS#11 rules enforced:
/// - CKA_SENSITIVE can only be set to CK_TRUE (cannot decrease sensitivity)
/// - CKA_EXTRACTABLE can only be set to CK_FALSE (cannot increase extractability)
/// - CKA_CLASS and CKA_KEY_TYPE cannot be changed in the copy
/// - Session must be logged in for private objects
#[no_mangle]
pub extern "C" fn C_CopyObject(
    session: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    ph_new_object: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if ph_new_object.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        // Verify session is valid
        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let sess = sess.read();
        if !sess.is_rw() {
            return CKR_SESSION_READ_ONLY;
        }

        // Get source object
        let src_arc = match hsm.object_store.get_object(h_object) {
            Ok(o) => o,
            Err(_) => return CKR_OBJECT_HANDLE_INVALID,
        };
        let src_obj = src_arc.read();

        // Private objects require login
        if src_obj.private && !sess.state.is_logged_in() {
            return CKR_USER_NOT_LOGGED_IN;
        }

        // PKCS#11: CKA_COPYABLE check — reject if object is not copyable
        if !src_obj.copyable {
            return CKR_ATTRIBUTE_READ_ONLY;
        }

        // Deep clone the source object
        let mut new_obj = src_obj.clone();
        drop(src_obj); // Release read lock

        // Assign a new handle
        let new_handle = match hsm.object_store.next_handle() {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };
        new_obj.handle = new_handle;

        // Parse and apply template modifications
        if !p_template.is_null() && count > 0 {
            // Defense-in-depth: clamp count to MAX_TEMPLATE_ATTRS to prevent
            // out-of-bounds reads from a malicious or bogus caller value,
            // matching the same limit used in parse_template().
            let clamped = (count as usize).min(MAX_TEMPLATE_ATTRS);
            let template = unsafe { slice::from_raw_parts(p_template, clamped) };

            for attr in template {
                let attr_type = attr.attr_type;
                let value = if attr.p_value.is_null() || attr.value_len == 0 {
                    &[] as &[u8]
                } else {
                    // Defense-in-depth: reject absurdly large attribute values
                    let len = attr.value_len as usize;
                    if len > MAX_ATTR_VALUE_LEN {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    unsafe { slice::from_raw_parts(attr.p_value as *const u8, len) }
                };

                // Enforce PKCS#11 copy rules
                match attr_type {
                    // Cannot change object class
                    CKA_CLASS => {
                        let requested_class = if value.len() >= std::mem::size_of::<CK_ULONG>() {
                            CK_ULONG::from_ne_bytes(
                                value[..std::mem::size_of::<CK_ULONG>()]
                                    .try_into()
                                    .unwrap_or_default(),
                            )
                        } else {
                            return CKR_TEMPLATE_INCONSISTENT;
                        };
                        if requested_class != new_obj.class {
                            return CKR_TEMPLATE_INCONSISTENT;
                        }
                    }
                    // Cannot change key type
                    CKA_KEY_TYPE => {
                        if let Some(kt) = new_obj.key_type {
                            let requested_kt = if value.len() >= std::mem::size_of::<CK_ULONG>() {
                                CK_ULONG::from_ne_bytes(
                                    value[..std::mem::size_of::<CK_ULONG>()]
                                        .try_into()
                                        .unwrap_or_default(),
                                )
                            } else {
                                return CKR_TEMPLATE_INCONSISTENT;
                            };
                            if requested_kt != kt {
                                return CKR_TEMPLATE_INCONSISTENT;
                            }
                        }
                    }
                    // CKA_SENSITIVE can only increase (false → true OK, true → false ERROR)
                    CKA_SENSITIVE => {
                        let requested = match parse_ck_bbool(value) {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                        if new_obj.sensitive && !requested {
                            // Cannot decrease sensitivity
                            return CKR_TEMPLATE_INCONSISTENT;
                        }
                        new_obj.sensitive = requested;
                    }
                    // CKA_EXTRACTABLE can only decrease (true → false OK, false → true ERROR)
                    CKA_EXTRACTABLE => {
                        let requested = match parse_ck_bbool(value) {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                        if !new_obj.extractable && requested {
                            // Cannot increase extractability
                            return CKR_TEMPLATE_INCONSISTENT;
                        }
                        new_obj.extractable = requested;
                    }
                    // Other modifiable boolean attributes — validate CK_BBOOL length
                    CKA_LABEL => {
                        new_obj.label = value.to_vec();
                    }
                    CKA_ID => {
                        new_obj.id = value.to_vec();
                    }
                    CKA_TOKEN => {
                        new_obj.token_object = match parse_ck_bbool(value) {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                    }
                    CKA_PRIVATE => {
                        new_obj.private = match parse_ck_bbool(value) {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                    }
                    CKA_MODIFIABLE => {
                        new_obj.modifiable = match parse_ck_bbool(value) {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                    }
                    CKA_DESTROYABLE => {
                        new_obj.destroyable = match parse_ck_bbool(value) {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                    }
                    CKA_ENCRYPT => {
                        new_obj.can_encrypt = match parse_ck_bbool(value) {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                    }
                    CKA_DECRYPT => {
                        new_obj.can_decrypt = match parse_ck_bbool(value) {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                    }
                    CKA_SIGN => {
                        new_obj.can_sign = match parse_ck_bbool(value) {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                    }
                    CKA_VERIFY => {
                        new_obj.can_verify = match parse_ck_bbool(value) {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                    }
                    CKA_WRAP => {
                        new_obj.can_wrap = match parse_ck_bbool(value) {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                    }
                    CKA_UNWRAP => {
                        new_obj.can_unwrap = match parse_ck_bbool(value) {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                    }
                    CKA_DERIVE => {
                        new_obj.can_derive = match parse_ck_bbool(value) {
                            Ok(v) => v,
                            Err(rv) => return rv,
                        };
                    }
                    // Reject security-relevant attributes that could be
                    // used to inject key material or bypass access controls
                    CKA_VALUE | CKA_PRIVATE_EXPONENT | CKA_PRIME_1 | CKA_PRIME_2
                    | CKA_EXPONENT_1 | CKA_EXPONENT_2 | CKA_COEFFICIENT => {
                        return CKR_ATTRIBUTE_READ_ONLY;
                    }
                    // Store other attributes as extra
                    _ => {
                        new_obj.extra_attributes.insert(attr_type, value.to_vec());
                    }
                }
            }
        }

        // Insert the new object
        let result_handle = match hsm.object_store.insert_object(new_obj) {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };

        unsafe {
            *ph_new_object = result_handle;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// Check if an encrypt/decrypt mechanism supports multi-part operations.
/// AES-GCM and RSA-OAEP are single-shot only.
/// Estimate the maximum signature length for a given mechanism and key object.
/// Used by C_SignFinal size queries so we can report an upper-bound without
/// consuming the hasher or accumulated data.
fn estimated_signature_len(mechanism: CK_MECHANISM_TYPE, obj: &StoredObject) -> Option<usize> {
    if sign::is_pss_mechanism(mechanism)
        || mechanism == CKM_RSA_PKCS
        || mechanism == CKM_SHA256_RSA_PKCS
        || mechanism == CKM_SHA384_RSA_PKCS
        || mechanism == CKM_SHA512_RSA_PKCS
    {
        // RSA: signature length = modulus size in bytes
        if let Some(bits) = obj.modulus_bits {
            return Some((bits as usize + 7) / 8);
        }
        if let Some(ref m) = obj.modulus {
            return Some(m.len());
        }
        // Fallback: derive from private key DER (conservative)
        obj.key_material.as_ref().map(|km| km.as_bytes().len())
    } else if sign::is_ecdsa_mechanism(mechanism) {
        let ec_params = obj.ec_params.as_deref().unwrap_or(&[]);
        if is_p384_params(ec_params) {
            Some(104) // DER-encoded P-384 ECDSA: up to ~104 bytes
        } else {
            Some(72) // DER-encoded P-256 ECDSA: up to ~72 bytes
        }
    } else if sign::is_eddsa_mechanism(mechanism) {
        Some(64) // Ed25519
    } else if pqc::is_ml_dsa_mechanism(mechanism) {
        // ML-DSA signatures vary by variant; use generous upper bound
        Some(4672) // ML-DSA-87 max
    } else if pqc::is_slh_dsa_mechanism(mechanism) {
        Some(49_856) // SLH-DSA-SHA2-256f max
    } else if pqc::is_hybrid_mechanism(mechanism) {
        Some(49_856 + 104) // hybrid: PQC + ECDSA
    } else {
        None
    }
}

fn encrypt_mechanism_supports_multipart(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(mechanism, CKM_AES_CBC | CKM_AES_CBC_PAD | CKM_AES_CTR)
}

#[no_mangle]
pub extern "C" fn C_EncryptUpdate(
    session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    _p_encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_part.is_null() || pul_encrypted_part_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        match &mut sess.active_operation {
            Some(ActiveOperation::Encrypt {
                mechanism, data, ..
            }) => {
                if !encrypt_mechanism_supports_multipart(*mechanism) {
                    sess.active_operation = None;
                    return CKR_MECHANISM_INVALID;
                }

                let part_data = unsafe { slice::from_raw_parts(p_part, part_len as usize) };
                if data.len().saturating_add(part_data.len()) > MAX_MULTIPART_ACCUMULATION {
                    sess.active_operation = None;
                    return CKR_DATA_LEN_RANGE;
                }
                data.extend_from_slice(part_data);

                // Accumulation mode: output 0 bytes in Update, all output in Final
                unsafe {
                    *pul_encrypted_part_len = 0;
                }
                CKR_OK
            }
            _ => CKR_OPERATION_NOT_INITIALIZED,
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_EncryptFinal(
    session: CK_SESSION_HANDLE,
    p_last_encrypted_part: CK_BYTE_PTR,
    pul_last_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pul_last_encrypted_part_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        // Length query: report a conservative upper-bound WITHOUT
        // consuming the operation state so subsequent Final call works.
        if p_last_encrypted_part.is_null() {
            let estimated_len = match &sess.active_operation {
                Some(ActiveOperation::Encrypt {
                    mechanism, data, ..
                }) => {
                    if !encrypt_mechanism_supports_multipart(*mechanism) {
                        sess.active_operation = None;
                        return CKR_MECHANISM_INVALID;
                    }
                    // AES-CBC_PAD may add up to one block (16 bytes); others output same length
                    data.len() + 16
                }
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            };
            unsafe {
                *pul_last_encrypted_part_len = estimated_len as CK_ULONG;
            }
            return CKR_OK;
        }

        // Pre-check: verify the caller's buffer can hold the conservative
        // estimate BEFORE consuming accumulated data, so the operation is
        // preserved on CKR_BUFFER_TOO_SMALL (PKCS#11 spec compliant).
        {
            let (mech, data_ref) = match &sess.active_operation {
                Some(ActiveOperation::Encrypt {
                    mechanism, data, ..
                }) => (*mechanism, data),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            };
            if !encrypt_mechanism_supports_multipart(mech) {
                sess.active_operation = None;
                return CKR_MECHANISM_INVALID;
            }
            let estimated = data_ref.len() + 16; // CBC-PAD may add one block
            let buf_len = unsafe { *pul_last_encrypted_part_len } as usize;
            if buf_len < estimated {
                unsafe {
                    *pul_last_encrypted_part_len = estimated as CK_ULONG;
                }
                // Operation preserved — caller can retry with a larger buffer
                return CKR_BUFFER_TOO_SMALL;
            }
        }

        let (mechanism, key_handle, mech_param, data, cached_object) =
            match &mut sess.active_operation {
                Some(ActiveOperation::Encrypt {
                    mechanism,
                    key_handle,
                    mechanism_param,
                    data,
                    cached_object,
                }) => (
                    *mechanism,
                    *key_handle,
                    mechanism_param.clone(),
                    std::mem::take(data),
                    cached_object.take(),
                ),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            };

        let obj = if let Some(cached) = cached_object {
            cached
        } else {
            match hsm.object_store.get_object(key_handle) {
                Ok(o) => o,
                Err(e) => {
                    sess.active_operation = None;
                    return err_to_rv(e);
                }
            }
        };
        let obj = obj.read();
        let key_bytes = match &obj.key_material {
            Some(km) => km.as_bytes(),
            None => {
                sess.active_operation = None;
                return CKR_KEY_HANDLE_INVALID;
            }
        };

        let result = match mechanism {
            CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if mech_param.is_empty() {
                    Err(HsmError::MechanismParamInvalid)
                } else {
                    hsm.crypto_backend
                        .aes_cbc_encrypt(key_bytes, &mech_param, &data)
                }
            }
            CKM_AES_CTR => {
                if mech_param.is_empty() {
                    Err(HsmError::MechanismParamInvalid)
                } else {
                    hsm.crypto_backend
                        .aes_ctr_encrypt(key_bytes, &mech_param, &data)
                }
            }
            _ => {
                sess.active_operation = None;
                return CKR_MECHANISM_INVALID;
            }
        };

        match result {
            Ok(encrypted) => {
                let out =
                    unsafe { slice::from_raw_parts_mut(p_last_encrypted_part, encrypted.len()) };
                out.copy_from_slice(&encrypted);
                unsafe {
                    *pul_last_encrypted_part_len = encrypted.len() as CK_ULONG;
                }

                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Encrypt {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Success,
                    None,
                );

                sess.active_operation = None;
                CKR_OK
            }
            Err(e) => {
                sess.active_operation = None;
                err_to_rv(e)
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_DecryptUpdate(
    session: CK_SESSION_HANDLE,
    p_encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    _p_part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_encrypted_part.is_null() || pul_part_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        match &mut sess.active_operation {
            Some(ActiveOperation::Decrypt {
                mechanism, data, ..
            }) => {
                if !encrypt_mechanism_supports_multipart(*mechanism) {
                    sess.active_operation = None;
                    return CKR_MECHANISM_INVALID;
                }

                let part_data =
                    unsafe { slice::from_raw_parts(p_encrypted_part, encrypted_part_len as usize) };
                if data.len().saturating_add(part_data.len()) > MAX_MULTIPART_ACCUMULATION {
                    sess.active_operation = None;
                    return CKR_DATA_LEN_RANGE;
                }
                data.extend_from_slice(part_data);

                // Accumulation mode: output 0 bytes in Update, all output in Final
                unsafe {
                    *pul_part_len = 0;
                }
                CKR_OK
            }
            _ => CKR_OPERATION_NOT_INITIALIZED,
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_DecryptFinal(
    session: CK_SESSION_HANDLE,
    p_last_part: CK_BYTE_PTR,
    pul_last_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pul_last_part_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        // Length query: report a conservative upper-bound WITHOUT
        // consuming the operation state so subsequent Final call works.
        if p_last_part.is_null() {
            let estimated_len = match &sess.active_operation {
                Some(ActiveOperation::Decrypt {
                    mechanism, data, ..
                }) => {
                    if !encrypt_mechanism_supports_multipart(*mechanism) {
                        sess.active_operation = None;
                        return CKR_MECHANISM_INVALID;
                    }
                    // Decrypted output is at most the ciphertext length
                    data.len()
                }
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            };
            unsafe {
                *pul_last_part_len = estimated_len as CK_ULONG;
            }
            return CKR_OK;
        }

        // Pre-check: verify the caller's buffer can hold the conservative
        // estimate BEFORE consuming accumulated data, so the operation is
        // preserved on CKR_BUFFER_TOO_SMALL (PKCS#11 spec compliant).
        {
            let (mech, data_ref) = match &sess.active_operation {
                Some(ActiveOperation::Decrypt {
                    mechanism, data, ..
                }) => (*mechanism, data),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            };
            if !encrypt_mechanism_supports_multipart(mech) {
                sess.active_operation = None;
                return CKR_MECHANISM_INVALID;
            }
            // Decrypted output is at most the ciphertext length
            let estimated = data_ref.len();
            let buf_len = unsafe { *pul_last_part_len } as usize;
            if buf_len < estimated {
                unsafe {
                    *pul_last_part_len = estimated as CK_ULONG;
                }
                // Operation preserved — caller can retry with a larger buffer
                return CKR_BUFFER_TOO_SMALL;
            }
        }

        let (mechanism, key_handle, mech_param, data, cached_object) =
            match &mut sess.active_operation {
                Some(ActiveOperation::Decrypt {
                    mechanism,
                    key_handle,
                    mechanism_param,
                    data,
                    cached_object,
                }) => (
                    *mechanism,
                    *key_handle,
                    mechanism_param.clone(),
                    std::mem::take(data),
                    cached_object.take(),
                ),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            };

        let obj = if let Some(cached) = cached_object {
            cached
        } else {
            match hsm.object_store.get_object(key_handle) {
                Ok(o) => o,
                Err(e) => {
                    sess.active_operation = None;
                    return err_to_rv(e);
                }
            }
        };
        let obj = obj.read();
        let key_bytes = match &obj.key_material {
            Some(km) => km.as_bytes(),
            None => {
                sess.active_operation = None;
                return CKR_KEY_HANDLE_INVALID;
            }
        };

        let result = match mechanism {
            CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if mech_param.is_empty() {
                    Err(HsmError::MechanismParamInvalid)
                } else {
                    hsm.crypto_backend
                        .aes_cbc_decrypt(key_bytes, &mech_param, &data)
                }
            }
            CKM_AES_CTR => {
                if mech_param.is_empty() {
                    Err(HsmError::MechanismParamInvalid)
                } else {
                    hsm.crypto_backend
                        .aes_ctr_decrypt(key_bytes, &mech_param, &data)
                }
            }
            _ => {
                sess.active_operation = None;
                return CKR_MECHANISM_INVALID;
            }
        };

        match result {
            Ok(decrypted) => {
                let out = unsafe { slice::from_raw_parts_mut(p_last_part, decrypted.len()) };
                out.copy_from_slice(&decrypted);
                unsafe {
                    *pul_last_part_len = decrypted.len() as CK_ULONG;
                }

                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Decrypt {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Success,
                    None,
                );

                sess.active_operation = None;
                CKR_OK
            }
            Err(e) => {
                sess.active_operation = None;
                err_to_rv(e)
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_DigestInit(session: CK_SESSION_HANDLE, p_mechanism: CK_MECHANISM_PTR) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        if sess.active_operation.is_some() {
            return CKR_OPERATION_ACTIVE;
        }

        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_digest_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check (digest is not a signing context)
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }

        let hasher = match hsm.crypto_backend.create_hasher(mechanism) {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };

        sess.active_operation = Some(ActiveOperation::Digest {
            mechanism,
            hasher: Some(hasher),
            accumulated_input: Zeroizing::new(Vec::new()),
        });
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_Digest(
    session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    p_digest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_data.is_null() || pul_digest_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        let mechanism = match &sess.active_operation {
            Some(ActiveOperation::Digest {
                accumulated_input,
                mechanism,
                ..
            }) => {
                // PKCS#11: C_Digest is single-shot; reject if DigestUpdate was already called
                if !accumulated_input.is_empty() {
                    sess.active_operation = None;
                    return CKR_OPERATION_ACTIVE;
                }
                *mechanism
            }
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };

        if (data_len as usize) > MAX_SINGLE_BUFFER {
            sess.active_operation = None;
            return CKR_DATA_LEN_RANGE;
        }
        let data = unsafe { slice::from_raw_parts(p_data, data_len as usize) };
        let result = hsm.crypto_backend.compute_digest(mechanism, data);

        match result {
            Ok(digest_out) => {
                if p_digest.is_null() {
                    unsafe {
                        *pul_digest_len = digest_out.len() as CK_ULONG;
                    }
                    return CKR_OK;
                }

                let buf_len = unsafe { *pul_digest_len } as usize;
                if buf_len < digest_out.len() {
                    unsafe {
                        *pul_digest_len = digest_out.len() as CK_ULONG;
                    }
                    return CKR_BUFFER_TOO_SMALL;
                }

                let out = unsafe { slice::from_raw_parts_mut(p_digest, digest_out.len()) };
                out.copy_from_slice(&digest_out);
                unsafe {
                    *pul_digest_len = digest_out.len() as CK_ULONG;
                }

                sess.active_operation = None;
                CKR_OK
            }
            Err(e) => {
                sess.active_operation = None;
                err_to_rv(e)
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_DigestUpdate(
    session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_part.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        match &mut sess.active_operation {
            Some(ActiveOperation::Digest {
                hasher,
                accumulated_input,
                ..
            }) => {
                let data = unsafe { slice::from_raw_parts(p_part, part_len as usize) };
                if accumulated_input.len().saturating_add(data.len()) > MAX_MULTIPART_ACCUMULATION {
                    sess.active_operation = None;
                    return CKR_DATA_LEN_RANGE;
                }
                if let Some(h) = hasher.as_mut() {
                    h.update(data);
                }
                accumulated_input.extend_from_slice(data);
                CKR_OK
            }
            _ => CKR_OPERATION_NOT_INITIALIZED,
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// C_DigestKey feeds the value of a secret key into an active digest
/// operation, as if C_DigestUpdate had been called with the key's value.
///
/// Only works for secret keys (CKO_SECRET_KEY). Asymmetric keys return
/// CKR_KEY_INDIGESTIBLE. The key must not be sensitive and non-extractable,
/// since we need to read the raw bytes.
#[no_mangle]
pub extern "C" fn C_DigestKey(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };

        // Check active digest operation FIRST (per PKCS#11 spec)
        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        {
            let sess_read = sess.read();
            match &sess_read.active_operation {
                Some(ActiveOperation::Digest { .. }) => { /* OK, operation is active */ }
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            }
        }

        // Look up the key object
        let key_arc = match hsm.object_store.get_object(key) {
            Ok(o) => o,
            Err(_) => return CKR_KEY_HANDLE_INVALID,
        };
        let key_obj = key_arc.read();

        // Only secret keys can be digested
        if key_obj.class != CKO_SECRET_KEY {
            return CKR_KEY_INDIGESTIBLE;
        }

        // Sensitive keys must not be digested — feeding raw key bytes into a
        // hash leaks the key material through the digest output.
        if key_obj.sensitive {
            return CKR_KEY_INDIGESTIBLE;
        }

        // Get key material bytes
        let key_bytes = match &key_obj.key_material {
            Some(km) => km.as_bytes().to_vec(),
            None => return CKR_KEY_INDIGESTIBLE,
        };
        drop(key_obj); // Release read lock

        // Feed key bytes into active digest operation
        let mut sess = sess.write();

        match &mut sess.active_operation {
            Some(ActiveOperation::Digest {
                hasher,
                accumulated_input,
                ..
            }) => {
                if let Some(h) = hasher.as_mut() {
                    h.update(&key_bytes);
                }
                // Track digested key bytes so C_GetOperationState /
                // C_SetOperationState can reconstruct the hasher state.
                accumulated_input.extend_from_slice(&key_bytes);
                CKR_OK
            }
            _ => CKR_OPERATION_NOT_INITIALIZED,
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_DigestFinal(
    session: CK_SESSION_HANDLE,
    p_digest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pul_digest_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        // For a NULL-pointer (length) query, report the output size
        // WITHOUT consuming the hasher so the operation remains intact.
        if p_digest.is_null() {
            let out_len = match &sess.active_operation {
                Some(ActiveOperation::Digest {
                    hasher: Some(h), ..
                }) => h.output_len(),
                Some(ActiveOperation::Digest { hasher: None, .. }) => {
                    sess.active_operation = None;
                    return CKR_OPERATION_NOT_INITIALIZED;
                }
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            };
            unsafe {
                *pul_digest_len = out_len as CK_ULONG;
            }
            return CKR_OK;
        }

        // Real finalization: consume the hasher and produce output.
        let (_mechanism, hasher, _acc_input) = match &mut sess.active_operation {
            Some(ActiveOperation::Digest {
                mechanism,
                hasher,
                accumulated_input,
            }) => (*mechanism, hasher.take(), accumulated_input.clone()),
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };

        let hasher = match hasher {
            Some(h) => h,
            None => {
                sess.active_operation = None;
                return CKR_OPERATION_NOT_INITIALIZED;
            }
        };

        let output_len = hasher.output_len();

        let buf_len = unsafe { *pul_digest_len } as usize;
        if buf_len < output_len {
            unsafe {
                *pul_digest_len = output_len as CK_ULONG;
            }
            // Operation is terminated per PKCS#11 spec on buffer too small
            sess.active_operation = None;
            return CKR_BUFFER_TOO_SMALL;
        }

        let digest_out = hasher.finalize();
        let out = unsafe { slice::from_raw_parts_mut(p_digest, digest_out.len()) };
        out.copy_from_slice(&digest_out);
        unsafe {
            *pul_digest_len = digest_out.len() as CK_ULONG;
        }

        sess.active_operation = None;
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_SignUpdate(
    session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_part.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        match &mut sess.active_operation {
            Some(ActiveOperation::Sign {
                mechanism,
                hasher,
                data,
                ..
            }) => {
                let part_data = unsafe { slice::from_raw_parts(p_part, part_len as usize) };

                if data.len().saturating_add(part_data.len()) > MAX_MULTIPART_ACCUMULATION {
                    sess.active_operation = None;
                    return CKR_DATA_LEN_RANGE;
                }

                if let Some(h) = hasher.as_mut() {
                    // Multi-part with built-in hash: feed data to the hasher
                    h.update(part_data);
                } else if sign::sign_mechanism_supports_multipart(*mechanism) {
                    // Mechanism supports multi-part but hasher creation failed
                    sess.active_operation = None;
                    return CKR_GENERAL_ERROR;
                } else {
                    // Mechanism without built-in hash (e.g., CKM_RSA_PKCS):
                    // accumulate raw data for final sign
                    data.extend_from_slice(part_data);
                }
                CKR_OK
            }
            _ => CKR_OPERATION_NOT_INITIALIZED,
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_SignFinal(
    session: CK_SESSION_HANDLE,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if pul_signature_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        // Length query: estimate signature size WITHOUT consuming
        // the hasher or accumulated data so the operation stays intact.
        if p_signature.is_null() {
            let (mech, kh) = match &sess.active_operation {
                Some(ActiveOperation::Sign {
                    mechanism,
                    key_handle,
                    ..
                }) => (*mechanism, *key_handle),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            };
            let obj = match hsm.object_store.get_object(kh) {
                Ok(o) => o,
                Err(e) => {
                    sess.active_operation = None;
                    return err_to_rv(e);
                }
            };
            let obj = obj.read();
            let est = match estimated_signature_len(mech, &obj) {
                Some(n) => n,
                None => {
                    sess.active_operation = None;
                    return CKR_MECHANISM_INVALID;
                }
            };
            unsafe {
                *pul_signature_len = est as CK_ULONG;
            }
            return CKR_OK;
        }

        let (mechanism, key_handle, hasher, data, cached_object) = match &mut sess.active_operation
        {
            Some(ActiveOperation::Sign {
                mechanism,
                key_handle,
                hasher,
                data,
                cached_object,
            }) => (
                *mechanism,
                *key_handle,
                hasher.take(),
                std::mem::take(data),
                cached_object.take(),
            ),
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };

        let obj = if let Some(cached) = cached_object {
            cached
        } else {
            match hsm.object_store.get_object(key_handle) {
                Ok(o) => o,
                Err(e) => {
                    sess.active_operation = None;
                    return err_to_rv(e);
                }
            }
        };
        let obj = obj.read();
        let key_bytes = match &obj.key_material {
            Some(km) => km.as_bytes(),
            None => {
                sess.active_operation = None;
                return CKR_KEY_HANDLE_INVALID;
            }
        };

        let result = if let Some(h) = hasher {
            // Multi-part with built-in hash: finalize hash, then prehash sign
            let digest = h.finalize();
            sign_prehashed(&*hsm.crypto_backend, mechanism, key_bytes, &digest, &obj)
        } else {
            // Accumulated raw data: sign directly (same as C_Sign)
            sign_single_shot(&*hsm.crypto_backend, mechanism, key_bytes, &data, &obj)
        };

        match result {
            Ok(signature) => {
                let buf_len = unsafe { *pul_signature_len } as usize;
                if buf_len < signature.len() {
                    unsafe {
                        *pul_signature_len = signature.len() as CK_ULONG;
                    }
                    sess.active_operation = None;
                    return CKR_BUFFER_TOO_SMALL;
                }

                let out = unsafe { slice::from_raw_parts_mut(p_signature, signature.len()) };
                out.copy_from_slice(&signature);
                unsafe {
                    *pul_signature_len = signature.len() as CK_ULONG;
                }

                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Sign {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Success,
                    None,
                );

                sess.active_operation = None;
                CKR_OK
            }
            Err(e) => {
                sess.active_operation = None;
                err_to_rv(e)
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_SignRecoverInit(
    _s: CK_SESSION_HANDLE,
    _m: CK_MECHANISM_PTR,
    _k: CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported()
}

#[no_mangle]
pub extern "C" fn C_SignRecover(
    _s: CK_SESSION_HANDLE,
    _d: CK_BYTE_PTR,
    _dl: CK_ULONG,
    _sig: CK_BYTE_PTR,
    _sl: CK_ULONG_PTR,
) -> CK_RV {
    not_supported()
}

#[no_mangle]
pub extern "C" fn C_VerifyUpdate(
    session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_part.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        match &mut sess.active_operation {
            Some(ActiveOperation::Verify {
                mechanism,
                hasher,
                data,
                ..
            }) => {
                let part_data = unsafe { slice::from_raw_parts(p_part, part_len as usize) };

                if data.len().saturating_add(part_data.len()) > MAX_MULTIPART_ACCUMULATION {
                    sess.active_operation = None;
                    return CKR_DATA_LEN_RANGE;
                }

                if let Some(h) = hasher.as_mut() {
                    // Multi-part with built-in hash: feed data to the hasher
                    h.update(part_data);
                } else if sign::sign_mechanism_supports_multipart(*mechanism) {
                    // Mechanism supports multi-part but hasher creation failed
                    sess.active_operation = None;
                    return CKR_GENERAL_ERROR;
                } else {
                    // Mechanism without built-in hash (e.g., CKM_RSA_PKCS):
                    // accumulate raw data for final verify
                    data.extend_from_slice(part_data);
                }
                CKR_OK
            }
            _ => CKR_OPERATION_NOT_INITIALIZED,
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_VerifyFinal(
    session: CK_SESSION_HANDLE,
    p_signature: CK_BYTE_PTR,
    signature_len: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_signature.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let mut sess = sess.write();

        let (mechanism, key_handle, hasher, data, cached_object) = match &mut sess.active_operation
        {
            Some(ActiveOperation::Verify {
                mechanism,
                key_handle,
                hasher,
                data,
                cached_object,
            }) => (
                *mechanism,
                *key_handle,
                hasher.take(),
                std::mem::take(data),
                cached_object.take(),
            ),
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };

        let signature = unsafe { slice::from_raw_parts(p_signature, signature_len as usize) };

        let obj = if let Some(cached) = cached_object {
            cached
        } else {
            match hsm.object_store.get_object(key_handle) {
                Ok(o) => o,
                Err(e) => {
                    sess.active_operation = None;
                    return err_to_rv(e);
                }
            }
        };
        let obj = obj.read();

        let result = if let Some(h) = hasher {
            // Multi-part with built-in hash: finalize hash, then prehash verify
            let digest = h.finalize();
            verify_prehashed(&*hsm.crypto_backend, mechanism, &digest, signature, &obj)
        } else {
            // Accumulated raw data: verify directly (same as C_Verify)
            verify_single_shot(&*hsm.crypto_backend, mechanism, &data, signature, &obj)
        };

        sess.active_operation = None;

        match result {
            Ok(true) => {
                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Verify {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Success,
                    None,
                );
                CKR_OK
            }
            Ok(false) => {
                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Verify {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Failure(CKR_SIGNATURE_INVALID as u64),
                    None,
                );
                CKR_SIGNATURE_INVALID
            }
            Err(e) => {
                let rv = err_to_rv(e);
                let _ = hsm.audit_log.record(
                    session as u64,
                    AuditOperation::Verify {
                        mechanism: mechanism as u64,
                        fips_approved: mechanisms::is_fips_approved(mechanism),
                    },
                    AuditResult::Failure(rv as u64),
                    None,
                );
                rv
            }
        }
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_VerifyRecoverInit(
    _s: CK_SESSION_HANDLE,
    _m: CK_MECHANISM_PTR,
    _k: CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported()
}

#[no_mangle]
pub extern "C" fn C_VerifyRecover(
    _s: CK_SESSION_HANDLE,
    _sig: CK_BYTE_PTR,
    _sl: CK_ULONG,
    _d: CK_BYTE_PTR,
    _dl: CK_ULONG_PTR,
) -> CK_RV {
    not_supported()
}

#[no_mangle]
pub extern "C" fn C_DigestEncryptUpdate(
    _s: CK_SESSION_HANDLE,
    _p: CK_BYTE_PTR,
    _pl: CK_ULONG,
    _e: CK_BYTE_PTR,
    _el: CK_ULONG_PTR,
) -> CK_RV {
    not_supported()
}

#[no_mangle]
pub extern "C" fn C_DecryptDigestUpdate(
    _s: CK_SESSION_HANDLE,
    _e: CK_BYTE_PTR,
    _el: CK_ULONG,
    _d: CK_BYTE_PTR,
    _dl: CK_ULONG_PTR,
) -> CK_RV {
    not_supported()
}

#[no_mangle]
pub extern "C" fn C_SignEncryptUpdate(
    _s: CK_SESSION_HANDLE,
    _p: CK_BYTE_PTR,
    _pl: CK_ULONG,
    _e: CK_BYTE_PTR,
    _el: CK_ULONG_PTR,
) -> CK_RV {
    not_supported()
}

#[no_mangle]
pub extern "C" fn C_DecryptVerifyUpdate(
    _s: CK_SESSION_HANDLE,
    _e: CK_BYTE_PTR,
    _el: CK_ULONG,
    _d: CK_BYTE_PTR,
    _dl: CK_ULONG_PTR,
) -> CK_RV {
    not_supported()
}

#[no_mangle]
pub extern "C" fn C_WrapKey(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    wrapping_key: CK_OBJECT_HANDLE,
    key: CK_OBJECT_HANDLE,
    p_wrapped_key: CK_BYTE_PTR,
    pul_wrapped_key_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() || pul_wrapped_key_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        // Capture login state once under lock to avoid TOCTOU races
        let is_logged_in = sess.read().state.is_logged_in();

        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_wrap_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }

        // Get wrapping key material
        let wk_obj = match hsm.object_store.get_object(wrapping_key) {
            Ok(o) => o,
            Err(e) => return err_to_rv(e),
        };
        let wk_obj = wk_obj.read();
        // Private wrapping keys require login
        if wk_obj.private && !is_logged_in {
            return CKR_USER_NOT_LOGGED_IN;
        }
        if !wk_obj.can_wrap {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        // Check if wrapping key is trusted (for CKA_WRAP_WITH_TRUSTED enforcement)
        let wk_is_trusted = wk_obj
            .extra_attributes
            .get(&CKA_TRUSTED)
            .map(|v| v.first().copied().unwrap_or(0) != 0)
            .unwrap_or(false);
        let wk_bytes = match &wk_obj.key_material {
            Some(km) => km.as_bytes().to_vec(),
            None => return CKR_KEY_HANDLE_INVALID,
        };
        drop(wk_obj);

        // Get key to wrap
        let key_obj = match hsm.object_store.get_object(key) {
            Ok(o) => o,
            Err(e) => return err_to_rv(e),
        };
        let key_obj = key_obj.read();
        if !key_obj.extractable {
            return err_to_rv(HsmError::KeyFunctionNotPermitted);
        }
        // PKCS#11: CKA_WRAP_WITH_TRUSTED — key requires a trusted wrapping key
        let requires_trusted = key_obj
            .extra_attributes
            .get(&CKA_WRAP_WITH_TRUSTED)
            .map(|v| v.first().copied().unwrap_or(0) != 0)
            .unwrap_or(false);
        if requires_trusted && !wk_is_trusted {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        let key_bytes = match &key_obj.key_material {
            Some(km) => km.as_bytes().to_vec(),
            None => return CKR_KEY_HANDLE_INVALID,
        };
        drop(key_obj);

        let wrapped = match hsm.crypto_backend.aes_key_wrap(
            &wk_bytes,
            &key_bytes,
            hsm.algorithm_config.fips_approved_only,
        ) {
            Ok(w) => w,
            Err(e) => return err_to_rv(e),
        };

        if p_wrapped_key.is_null() {
            unsafe {
                *pul_wrapped_key_len = wrapped.len() as CK_ULONG;
            }
            return CKR_OK;
        }

        let buf_len = unsafe { *pul_wrapped_key_len } as usize;
        if buf_len < wrapped.len() {
            unsafe {
                *pul_wrapped_key_len = wrapped.len() as CK_ULONG;
            }
            return CKR_BUFFER_TOO_SMALL;
        }

        let out = unsafe { slice::from_raw_parts_mut(p_wrapped_key, wrapped.len()) };
        out.copy_from_slice(&wrapped);
        unsafe {
            *pul_wrapped_key_len = wrapped.len() as CK_ULONG;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_UnwrapKey(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    unwrapping_key: CK_OBJECT_HANDLE,
    p_wrapped_key: CK_BYTE_PTR,
    wrapped_key_len: CK_ULONG,
    p_template: CK_ATTRIBUTE_PTR,
    attr_count: CK_ULONG,
    ph_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() || p_wrapped_key.is_null() || ph_key.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        let sess_read = sess.read();
        if !sess_read.is_rw() {
            return CKR_SESSION_READ_ONLY;
        }
        // Capture login state once under lock to avoid TOCTOU races
        let is_logged_in = sess_read.state.is_logged_in();
        drop(sess_read);

        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_wrap_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }

        // Get unwrapping key
        let uk_obj = match hsm.object_store.get_object(unwrapping_key) {
            Ok(o) => o,
            Err(e) => return err_to_rv(e),
        };
        let uk_obj = uk_obj.read();
        // Private unwrapping keys require login
        if uk_obj.private && !is_logged_in {
            return CKR_USER_NOT_LOGGED_IN;
        }
        if !uk_obj.can_unwrap {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        let uk_bytes = match &uk_obj.key_material {
            Some(km) => km.as_bytes().to_vec(),
            None => return CKR_KEY_HANDLE_INVALID,
        };
        let uk_sensitive = uk_obj.sensitive;
        drop(uk_obj);

        // Defense-in-depth: bound wrapped_key_len before slice construction
        if (wrapped_key_len as usize) > MAX_SINGLE_BUFFER {
            return CKR_WRAPPED_KEY_LEN_RANGE;
        }
        let wrapped_data =
            unsafe { slice::from_raw_parts(p_wrapped_key, wrapped_key_len as usize) };

        let unwrapped = match hsm.crypto_backend.aes_key_unwrap(
            &uk_bytes,
            wrapped_data,
            hsm.algorithm_config.fips_approved_only,
        ) {
            Ok(u) => u,
            Err(e) => return err_to_rv(e),
        };

        let template = if p_template.is_null() {
            vec![]
        } else {
            match parse_template(p_template, attr_count) {
                Ok(t) => t,
                Err(rv) => return rv,
            }
        };

        let handle = match hsm.object_store.next_handle() {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };
        let mut obj = StoredObject::new(handle, CKO_SECRET_KEY);
        obj.key_type = Some(CKK_AES);
        obj.key_material = Some(RawKeyMaterial::new(unwrapped.clone()));
        obj.value_len = Some(unwrapped.len() as CK_ULONG);
        obj.sensitive = true;
        obj.extractable = false; // secure default: unwrapped keys are non-extractable
        obj.can_encrypt = true;
        obj.can_decrypt = true;

        for (attr_type, value) in &template {
            match *attr_type {
                CKA_LABEL => obj.label = value.clone(),
                CKA_ID => obj.id = value.clone(),
                CKA_TOKEN => {
                    obj.token_object = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    }
                }
                CKA_SENSITIVE => {
                    let requested = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    };
                    // PKCS#11: sensitivity can only increase, never decrease.
                    // If the unwrapping key is sensitive, the unwrapped key
                    // must also be sensitive (inherited constraint).
                    if uk_sensitive && !requested {
                        return CKR_TEMPLATE_INCONSISTENT;
                    }
                    obj.sensitive = requested;
                }
                CKA_EXTRACTABLE => {
                    let requested = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    };
                    // PKCS#11: extractability can only decrease, never increase.
                    if !obj.extractable && requested {
                        return CKR_TEMPLATE_INCONSISTENT;
                    }
                    obj.extractable = requested;
                }
                CKA_ENCRYPT => {
                    obj.can_encrypt = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    }
                }
                CKA_DECRYPT => {
                    obj.can_decrypt = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    }
                }
                _ => {}
            }
        }

        if let Err(e) = hsm.object_store.insert_object(obj) {
            return err_to_rv(e);
        }
        unsafe {
            *ph_key = handle;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_DeriveKey(
    session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    base_key: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    attr_count: CK_ULONG,
    ph_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_unwind(|| {
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        if p_mechanism.is_null() || ph_key.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let sess = match hsm.session_manager.get_session(session) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };
        if !sess.read().is_rw() {
            return CKR_SESSION_READ_ONLY;
        }

        let mechanism = unsafe { (*p_mechanism).mechanism };
        if !mechanisms::is_derive_mechanism(mechanism) && !mechanisms::is_kem_mechanism(mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        // FIPS algorithm policy check
        if let Err(rv) =
            mechanisms::validate_mechanism_for_policy(mechanism, &hsm.algorithm_config, false)
        {
            return rv;
        }

        // Get base key
        let bk_obj = match hsm.object_store.get_object(base_key) {
            Ok(o) => o,
            Err(e) => return err_to_rv(e),
        };
        let bk_obj = bk_obj.read();
        if !bk_obj.can_derive {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        let bk_bytes = match &bk_obj.key_material {
            Some(km) => km.as_bytes().to_vec(),
            None => return CKR_KEY_HANDLE_INVALID,
        };
        let ec_params = bk_obj.ec_params.as_deref().unwrap_or(&[]).to_vec();
        let bk_sensitive = bk_obj.sensitive;
        drop(bk_obj);

        // The mechanism parameter contains the peer public key (ECDH) or ciphertext (KEM)
        let mech_param = extract_mechanism_param(p_mechanism);
        if mech_param.is_empty() {
            return CKR_MECHANISM_PARAM_INVALID;
        }

        let template = if p_template.is_null() {
            vec![]
        } else {
            match parse_template(p_template, attr_count) {
                Ok(t) => t,
                Err(rv) => return rv,
            }
        };

        // Parse CKA_VALUE_LEN early so ECDH can derive exactly the right length
        // via HKDF, avoiding unnecessary truncation of the derived secret.
        let requested_len = read_ulong_attr(&template, CKA_VALUE_LEN).map(|v| v as usize);

        // Validate requested length is a valid AES key size
        if let Some(req_len) = requested_len {
            if req_len != 16 && req_len != 24 && req_len != 32 {
                return CKR_KEY_SIZE_RANGE;
            }
        }

        let shared_secret = if let Some(variant) = pqc::mechanism_to_ml_kem_variant(mechanism) {
            // ML-KEM decapsulation: base key is dk seed, param is ciphertext
            match hsm
                .crypto_backend
                .ml_kem_decapsulate(&bk_bytes, &mech_param, variant)
            {
                Ok(ss) => RawKeyMaterial::new(ss),
                Err(e) => return err_to_rv(e),
            }
        } else if is_p384_params(&ec_params) {
            match hsm
                .crypto_backend
                .ecdh_p384(&bk_bytes, &mech_param, requested_len)
            {
                Ok(s) => s,
                Err(e) => return err_to_rv(e),
            }
        } else {
            match hsm
                .crypto_backend
                .ecdh_p256(&bk_bytes, &mech_param, requested_len)
            {
                Ok(s) => s,
                Err(e) => return err_to_rv(e),
            }
        };

        // Validate the derived secret is a valid AES key size
        let shared_secret = {
            let slen = shared_secret.len();
            if slen != 16 && slen != 24 && slen != 32 {
                return CKR_KEY_SIZE_RANGE;
            }
            shared_secret
        };

        let handle = match hsm.object_store.next_handle() {
            Ok(h) => h,
            Err(e) => return err_to_rv(e),
        };
        let secret_len = shared_secret.len();
        let mut obj = StoredObject::new(handle, CKO_SECRET_KEY);
        obj.key_type = Some(CKK_AES);
        obj.key_material = Some(shared_secret);
        obj.value_len = Some(secret_len as CK_ULONG);
        obj.sensitive = true;
        obj.extractable = false;
        obj.can_encrypt = true;
        obj.can_decrypt = true;

        for (attr_type, value) in &template {
            match *attr_type {
                CKA_LABEL => obj.label = value.clone(),
                CKA_ID => obj.id = value.clone(),
                CKA_TOKEN => {
                    obj.token_object = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    }
                }
                CKA_SENSITIVE => {
                    let requested = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    };
                    // PKCS#11: if the base key is sensitive, the derived key
                    // must also be sensitive (inherited constraint).
                    if bk_sensitive && !requested {
                        return CKR_TEMPLATE_INCONSISTENT;
                    }
                    obj.sensitive = requested;
                }
                CKA_EXTRACTABLE => {
                    let requested = match parse_ck_bbool(value) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    };
                    if !obj.extractable && requested {
                        return CKR_TEMPLATE_INCONSISTENT;
                    }
                    obj.extractable = requested;
                }
                _ => {}
            }
        }

        if let Err(e) = hsm.object_store.insert_object(obj) {
            return err_to_rv(e);
        }
        unsafe {
            *ph_key = handle;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub extern "C" fn C_GetFunctionStatus(_s: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_PARALLEL
}

#[no_mangle]
pub extern "C" fn C_CancelFunction(_s: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_PARALLEL
}

#[no_mangle]
pub extern "C" fn C_WaitForSlotEvent(
    _flags: CK_FLAGS,
    _slot: CK_SLOT_ID_PTR,
    _reserved: CK_VOID_PTR,
) -> CK_RV {
    not_supported()
}

// ============================================================================
// Static function list
// ============================================================================

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 3, minor: 0 },
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPIN,
    C_SetPIN,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    C_GetOperationState,
    C_SetOperationState,
    C_Login,
    C_Logout,
    C_CreateObject,
    C_CopyObject,
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    C_DigestKey,
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    C_SignRecoverInit,
    C_SignRecover,
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    C_VerifyRecoverInit,
    C_VerifyRecover,
    C_DigestEncryptUpdate,
    C_DecryptDigestUpdate,
    C_SignEncryptUpdate,
    C_DecryptVerifyUpdate,
    C_GenerateKey,
    C_GenerateKeyPair,
    C_WrapKey,
    C_UnwrapKey,
    C_DeriveKey,
    C_SeedRandom,
    C_GenerateRandom,
    C_GetFunctionStatus,
    C_CancelFunction,
    C_WaitForSlotEvent,
};

// ============================================================================
// Helpers
// ============================================================================

/// Returns `true` if `attr_type` is a CK_BBOOL attribute per PKCS#11.
#[allow(dead_code)]
fn is_bool_attribute(attr_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attr_type,
        CKA_TOKEN
            | CKA_PRIVATE
            | CKA_SENSITIVE
            | CKA_EXTRACTABLE
            | CKA_ENCRYPT
            | CKA_DECRYPT
            | CKA_SIGN
            | CKA_VERIFY
            | CKA_WRAP
            | CKA_UNWRAP
            | CKA_DERIVE
            | CKA_MODIFIABLE
            | CKA_DESTROYABLE
            | CKA_COPYABLE
            | CKA_TRUSTED
            | CKA_LOCAL
            | CKA_ALWAYS_SENSITIVE
            | CKA_NEVER_EXTRACTABLE
            | CKA_WRAP_WITH_TRUSTED
    )
}

/// Parse a CK_BBOOL value from attribute bytes.
/// Returns `CKR_ATTRIBUTE_VALUE_INVALID` if `value.len()` is not exactly
/// `std::mem::size_of::<CK_BBOOL>()` (1 byte), per PKCS#11 spec.
fn parse_ck_bbool(value: &[u8]) -> Result<bool, CK_RV> {
    if value.len() != std::mem::size_of::<CK_BBOOL>() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    Ok(value[0] != 0)
}

/// Parse a PKCS#11 attribute template from C pointers into safe Rust types.
///
/// Returns `Err(CKR_ATTRIBUTE_VALUE_INVALID)` if any attribute value exceeds
/// `MAX_ATTR_VALUE_LEN`, or if `count` exceeds `MAX_TEMPLATE_ATTRS`.
/// PKCS#11 requires atomic template validation — partial templates must not
/// be silently accepted.
///
/// SAFETY: Caller must ensure p_template points to `count` valid CK_ATTRIBUTE structs.
/// Each attribute's p_value must point to value_len valid bytes (or be null).
fn parse_template(
    p_template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>, CK_RV> {
    let count_usize = count as usize;

    // Reject template counts exceeding the safety limit rather than silently
    // clamping — the caller must know their template was not fully processed.
    if count_usize > MAX_TEMPLATE_ATTRS {
        tracing::error!(
            "parse_template: count {} exceeds MAX_TEMPLATE_ATTRS ({})",
            count_usize,
            MAX_TEMPLATE_ATTRS
        );
        return Err(CKR_ARGUMENTS_BAD);
    }

    // SAFETY: p_template validated by caller, count matches array length. (Pattern 2)
    let attrs = unsafe { slice::from_raw_parts(p_template, count_usize) };
    let mut result = Vec::with_capacity(count_usize);
    for attr in attrs {
        let value = if attr.p_value.is_null() || attr.value_len == 0 {
            vec![]
        } else {
            // Reject absurdly large attribute values to prevent out-of-bounds
            // reads from a malicious or buggy C caller.
            let len = attr.value_len as usize;
            if len > MAX_ATTR_VALUE_LEN {
                let atype = { attr.attr_type };
                tracing::error!(
                    "parse_template: attribute 0x{:08X} value_len {} exceeds MAX_ATTR_VALUE_LEN",
                    atype,
                    len
                );
                return Err(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            unsafe { slice::from_raw_parts(attr.p_value as *const u8, len) }.to_vec()
        };
        result.push((attr.attr_type, value));
    }
    Ok(result)
}
