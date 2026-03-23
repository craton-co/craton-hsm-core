// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! PKCS#11 Spy Wrapper — intercepts and logs all PKCS#11 function calls.
//!
//! Usage:
//!   Set `PKCS11_SPY_TARGET` to the path of the real PKCS#11 library.
//!   Set `PKCS11_SPY_LOG` to the desired log file path (default: stderr).
//!   Load this library as the PKCS#11 provider in your application.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

mod loader;
mod logger;

use std::ffi::c_void;
use std::time::Instant;

// ── Minimal PKCS#11 type aliases (standalone — no dependency on craton_hsm) ─────
// NOTE: CK_ULONG is defined as `unsigned long` in the PKCS#11 spec, which maps
// to c_ulong. This is intentionally platform-dependent to match the ABI of the
// target PKCS#11 library. The spy MUST be compiled for the same target as the
// library it wraps (same architecture and OS).
type CK_ULONG = std::ffi::c_ulong;
type CK_RV = CK_ULONG;
type CK_BYTE = u8;
type CK_BBOOL = u8;
type CK_VOID_PTR = *mut c_void;
type CK_BYTE_PTR = *mut CK_BYTE;
type CK_ULONG_PTR = *mut CK_ULONG;
type CK_FLAGS = CK_ULONG;
type CK_SLOT_ID = CK_ULONG;
type CK_SESSION_HANDLE = CK_ULONG;
type CK_OBJECT_HANDLE = CK_ULONG;
type CK_MECHANISM_TYPE = CK_ULONG;
type CK_USER_TYPE = CK_ULONG;
type CK_UTF8CHAR_PTR = *mut u8;
type CK_SLOT_ID_PTR = *mut CK_SLOT_ID;
type CK_SESSION_HANDLE_PTR = *mut CK_SESSION_HANDLE;
type CK_OBJECT_HANDLE_PTR = *mut CK_OBJECT_HANDLE;
type CK_MECHANISM_TYPE_PTR = *mut CK_MECHANISM_TYPE;
type CK_NOTIFY = Option<extern "C" fn(CK_SESSION_HANDLE, CK_ULONG, CK_VOID_PTR) -> CK_RV>;

// Opaque struct pointers — we just forward them, never inspect them.
type CK_INFO_PTR = CK_VOID_PTR;
type CK_SLOT_INFO_PTR = CK_VOID_PTR;
type CK_TOKEN_INFO_PTR = CK_VOID_PTR;
type CK_SESSION_INFO_PTR = CK_VOID_PTR;
type CK_MECHANISM_PTR = CK_VOID_PTR;
type CK_MECHANISM_INFO_PTR = CK_VOID_PTR;
type CK_ATTRIBUTE_PTR = CK_VOID_PTR;
type CK_FUNCTION_LIST_PTR_PTR = *mut CK_VOID_PTR;

// ── Spy dispatch macro ───────────────────────────────────────────────────────
/// Generate a `#[no_mangle] pub extern "C"` function that:
///   1. Logs the call
///   2. Resolves and calls the real function
///   3. Logs the return value
///   4. Returns the result
macro_rules! spy_fn {
    (
        $name:ident ( $($pname:ident : $pty:ty),* ) => $($args_fmt:tt)*
    ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name( $($pname : $pty),* ) -> CK_RV {
            let fname = stringify!($name);
            let args_str = format!($($args_fmt)*);
            logger::log_call(fname, &args_str);
            let start = Instant::now();

            type FnSig = unsafe extern "C" fn( $($pty),* ) -> CK_RV;
            let symbol_name = concat!(stringify!($name), "\0");
            let rv = match unsafe { loader::resolve::<FnSig>(symbol_name.as_bytes()) } {
                Some(f) => unsafe { f( $($pname),* ) },
                None => loader::CKR_FUNCTION_NOT_SUPPORTED,
            };

            let elapsed = start.elapsed().as_micros() as u64;
            logger::log_return(fname, rv as u64, elapsed);
            rv
        }
    };
}

/// Variant for functions with pointer parameters that should be null-checked
/// before forwarding. If any checked pointer is null, returns CKR_ARGUMENTS_BAD.
macro_rules! spy_fn_checked {
    (
        $name:ident ( $($pname:ident : $pty:ty),* )
        check ( $($check_ptr:ident),+ )
        => $($args_fmt:tt)*
    ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name( $($pname : $pty),* ) -> CK_RV {
            let fname = stringify!($name);

            // Null-check required output pointers
            $(
                if ($check_ptr as *const ()).is_null() {
                    logger::log_call(fname, "\"<null pointer rejected>\"");
                    logger::log_return(fname, 0x07, 0); // CKR_ARGUMENTS_BAD
                    return 0x07 as CK_RV;
                }
            )+

            let args_str = format!($($args_fmt)*);
            logger::log_call(fname, &args_str);
            let start = Instant::now();

            type FnSig = unsafe extern "C" fn( $($pty),* ) -> CK_RV;
            let symbol_name = concat!(stringify!($name), "\0");
            let rv = match unsafe { loader::resolve::<FnSig>(symbol_name.as_bytes()) } {
                Some(f) => unsafe { f( $($pname),* ) },
                None => loader::CKR_FUNCTION_NOT_SUPPORTED,
            };

            let elapsed = start.elapsed().as_micros() as u64;
            logger::log_return(fname, rv as u64, elapsed);
            rv
        }
    };
}

// ── Exported functions ───────────────────────────────────────────────────────

// Initialization & Info
spy_fn!(C_Initialize(pInitArgs: CK_VOID_PTR) => "{{}}");
spy_fn!(C_Finalize(pReserved: CK_VOID_PTR) => "{{}}");
spy_fn_checked!(C_GetInfo(pInfo: CK_INFO_PTR)
    check(pInfo)
    => "{{}}");
spy_fn_checked!(C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR)
    check(ppFunctionList)
    => "{{}}");

// Slot & Token Management
spy_fn!(C_GetSlotList(tokenPresent: CK_BBOOL, pSlotList: CK_SLOT_ID_PTR, pulCount: CK_ULONG_PTR)
    => "{{\"token_present\":{}}}", tokenPresent);
spy_fn!(C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR)
    => "{{\"slot\":{}}}", slotID);
spy_fn!(C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR)
    => "{{\"slot\":{}}}", slotID);
// SECURITY: PIN length is redacted from logs to prevent brute-force narrowing
spy_fn!(C_InitToken(slotID: CK_SLOT_ID, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG, pLabel: CK_UTF8CHAR_PTR)
    => "{{\"slot\":{},\"pin_len\":\"<redacted>\"}}", slotID);
spy_fn!(C_GetMechanismList(slotID: CK_SLOT_ID, pMechList: CK_MECHANISM_TYPE_PTR, pulCount: CK_ULONG_PTR)
    => "{{\"slot\":{}}}", slotID);
spy_fn!(C_GetMechanismInfo(slotID: CK_SLOT_ID, mechType: CK_MECHANISM_TYPE, pInfo: CK_MECHANISM_INFO_PTR)
    => "{{\"slot\":{},\"mechanism\":\"0x{:08x}\"}}", slotID, mechType);

// Session Management
spy_fn!(C_OpenSession(slotID: CK_SLOT_ID, flags: CK_FLAGS, pApp: CK_VOID_PTR, notify: CK_NOTIFY, phSession: CK_SESSION_HANDLE_PTR)
    => "{{\"slot\":{},\"flags\":\"0x{:x}\"}}", slotID, flags);
spy_fn!(C_CloseSession(hSession: CK_SESSION_HANDLE)
    => "{{\"session\":{}}}", hSession);
spy_fn!(C_CloseAllSessions(slotID: CK_SLOT_ID)
    => "{{\"slot\":{}}}", slotID);
spy_fn!(C_GetSessionInfo(hSession: CK_SESSION_HANDLE, pInfo: CK_SESSION_INFO_PTR)
    => "{{\"session\":{}}}", hSession);
// SECURITY: PIN length and user_type redacted — prevents PIN oracle and user enumeration
spy_fn!(C_Login(hSession: CK_SESSION_HANDLE, userType: CK_USER_TYPE, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG)
    => "{{\"session\":{}}}", hSession);
spy_fn!(C_Logout(hSession: CK_SESSION_HANDLE)
    => "{{\"session\":{}}}", hSession);

// PIN Management — all PIN lengths redacted
spy_fn!(C_InitPIN(hSession: CK_SESSION_HANDLE, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG)
    => "{{\"session\":{}}}", hSession);
spy_fn!(C_SetPIN(hSession: CK_SESSION_HANDLE, pOldPin: CK_UTF8CHAR_PTR, ulOldLen: CK_ULONG, pNewPin: CK_UTF8CHAR_PTR, ulNewLen: CK_ULONG)
    => "{{\"session\":{}}}", hSession);

// Object Management
spy_fn!(C_CreateObject(hSession: CK_SESSION_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phObject: CK_OBJECT_HANDLE_PTR)
    => "{{\"session\":{},\"attr_count\":{}}}", hSession, ulCount);
spy_fn!(C_DestroyObject(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"object\":{}}}", hSession, hObject);
spy_fn!(C_GetObjectSize(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pulSize: CK_ULONG_PTR)
    => "{{\"session\":{},\"object\":{}}}", hSession, hObject);
spy_fn!(C_GetAttributeValue(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG)
    => "{{\"session\":{},\"object\":{},\"attr_count\":{}}}", hSession, hObject, ulCount);
spy_fn!(C_SetAttributeValue(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG)
    => "{{\"session\":{},\"object\":{},\"attr_count\":{}}}", hSession, hObject, ulCount);
spy_fn!(C_FindObjectsInit(hSession: CK_SESSION_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG)
    => "{{\"session\":{},\"attr_count\":{}}}", hSession, ulCount);
spy_fn!(C_FindObjects(hSession: CK_SESSION_HANDLE, phObject: CK_OBJECT_HANDLE_PTR, ulMaxCount: CK_ULONG, pulCount: CK_ULONG_PTR)
    => "{{\"session\":{},\"max_count\":{}}}", hSession, ulMaxCount);
spy_fn!(C_FindObjectsFinal(hSession: CK_SESSION_HANDLE)
    => "{{\"session\":{}}}", hSession);
spy_fn!(C_CopyObject(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phNewObject: CK_OBJECT_HANDLE_PTR)
    => "{{\"session\":{},\"object\":{},\"attr_count\":{}}}", hSession, hObject, ulCount);

// Encryption
spy_fn!(C_EncryptInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"key\":{}}}", hSession, hKey);
spy_fn!(C_Encrypt(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pEncData: CK_BYTE_PTR, pulEncDataLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"data_len\":{}}}", hSession, ulDataLen);
spy_fn!(C_EncryptUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncPart: CK_BYTE_PTR, pulEncPartLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"part_len\":{}}}", hSession, ulPartLen);
spy_fn!(C_EncryptFinal(hSession: CK_SESSION_HANDLE, pLastEncPart: CK_BYTE_PTR, pulLastEncPartLen: CK_ULONG_PTR)
    => "{{\"session\":{}}}", hSession);

// Decryption
spy_fn!(C_DecryptInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"key\":{}}}", hSession, hKey);
spy_fn!(C_Decrypt(hSession: CK_SESSION_HANDLE, pEncData: CK_BYTE_PTR, ulEncDataLen: CK_ULONG, pData: CK_BYTE_PTR, pulDataLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"enc_data_len\":{}}}", hSession, ulEncDataLen);
spy_fn!(C_DecryptUpdate(hSession: CK_SESSION_HANDLE, pEncPart: CK_BYTE_PTR, ulEncPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"enc_part_len\":{}}}", hSession, ulEncPartLen);
spy_fn!(C_DecryptFinal(hSession: CK_SESSION_HANDLE, pLastPart: CK_BYTE_PTR, pulLastPartLen: CK_ULONG_PTR)
    => "{{\"session\":{}}}", hSession);

// Signing
spy_fn!(C_SignInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"key\":{}}}", hSession, hKey);
spy_fn!(C_Sign(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"data_len\":{}}}", hSession, ulDataLen);
spy_fn!(C_SignUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG)
    => "{{\"session\":{},\"part_len\":{}}}", hSession, ulPartLen);
spy_fn!(C_SignFinal(hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR)
    => "{{\"session\":{}}}", hSession);
spy_fn!(C_SignRecoverInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"key\":{}}}", hSession, hKey);
spy_fn!(C_SignRecover(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"data_len\":{}}}", hSession, ulDataLen);

// Verification
spy_fn!(C_VerifyInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"key\":{}}}", hSession, hKey);
spy_fn!(C_Verify(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG)
    => "{{\"session\":{},\"data_len\":{},\"sig_len\":{}}}", hSession, ulDataLen, ulSignatureLen);
spy_fn!(C_VerifyUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG)
    => "{{\"session\":{},\"part_len\":{}}}", hSession, ulPartLen);
spy_fn!(C_VerifyFinal(hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG)
    => "{{\"session\":{},\"sig_len\":{}}}", hSession, ulSignatureLen);
spy_fn!(C_VerifyRecoverInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"key\":{}}}", hSession, hKey);
spy_fn!(C_VerifyRecover(hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG, pData: CK_BYTE_PTR, pulDataLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"sig_len\":{}}}", hSession, ulSignatureLen);

// Digest
spy_fn!(C_DigestInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR)
    => "{{\"session\":{}}}", hSession);
spy_fn!(C_Digest(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pDigest: CK_BYTE_PTR, pulDigestLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"data_len\":{}}}", hSession, ulDataLen);
spy_fn!(C_DigestUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG)
    => "{{\"session\":{},\"part_len\":{}}}", hSession, ulPartLen);
spy_fn!(C_DigestKey(hSession: CK_SESSION_HANDLE, hKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"key\":{}}}", hSession, hKey);
spy_fn!(C_DigestFinal(hSession: CK_SESSION_HANDLE, pDigest: CK_BYTE_PTR, pulDigestLen: CK_ULONG_PTR)
    => "{{\"session\":{}}}", hSession);

// Combined operations
spy_fn!(C_DigestEncryptUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncPart: CK_BYTE_PTR, pulEncPartLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"part_len\":{}}}", hSession, ulPartLen);
spy_fn!(C_DecryptDigestUpdate(hSession: CK_SESSION_HANDLE, pEncPart: CK_BYTE_PTR, ulEncPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"enc_part_len\":{}}}", hSession, ulEncPartLen);
spy_fn!(C_SignEncryptUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncPart: CK_BYTE_PTR, pulEncPartLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"part_len\":{}}}", hSession, ulPartLen);
spy_fn!(C_DecryptVerifyUpdate(hSession: CK_SESSION_HANDLE, pEncPart: CK_BYTE_PTR, ulEncPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"enc_part_len\":{}}}", hSession, ulEncPartLen);

// Key generation
spy_fn!(C_GenerateKey(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR)
    => "{{\"session\":{},\"attr_count\":{}}}", hSession, ulCount);
spy_fn!(C_GenerateKeyPair(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, pPubTemplate: CK_ATTRIBUTE_PTR, ulPubCount: CK_ULONG, pPrivTemplate: CK_ATTRIBUTE_PTR, ulPrivCount: CK_ULONG, phPubKey: CK_OBJECT_HANDLE_PTR, phPrivKey: CK_OBJECT_HANDLE_PTR)
    => "{{\"session\":{},\"pub_attrs\":{},\"priv_attrs\":{}}}", hSession, ulPubCount, ulPrivCount);
spy_fn!(C_WrapKey(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hWrappingKey: CK_OBJECT_HANDLE, hKey: CK_OBJECT_HANDLE, pWrappedKey: CK_BYTE_PTR, pulWrappedKeyLen: CK_ULONG_PTR)
    => "{{\"session\":{},\"wrapping_key\":{},\"key\":{}}}", hSession, hWrappingKey, hKey);
spy_fn!(C_UnwrapKey(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hUnwrappingKey: CK_OBJECT_HANDLE, pWrappedKey: CK_BYTE_PTR, ulWrappedKeyLen: CK_ULONG, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR)
    => "{{\"session\":{},\"unwrapping_key\":{},\"wrapped_len\":{}}}", hSession, hUnwrappingKey, ulWrappedKeyLen);
spy_fn!(C_DeriveKey(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hBaseKey: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR)
    => "{{\"session\":{},\"base_key\":{},\"attr_count\":{}}}", hSession, hBaseKey, ulCount);

// Random
spy_fn!(C_SeedRandom(hSession: CK_SESSION_HANDLE, pSeed: CK_BYTE_PTR, ulSeedLen: CK_ULONG)
    => "{{\"session\":{},\"seed_len\":{}}}", hSession, ulSeedLen);
spy_fn!(C_GenerateRandom(hSession: CK_SESSION_HANDLE, pRandomData: CK_BYTE_PTR, ulRandomLen: CK_ULONG)
    => "{{\"session\":{},\"random_len\":{}}}", hSession, ulRandomLen);

// State management
spy_fn!(C_GetOperationState(hSession: CK_SESSION_HANDLE, pOpState: CK_BYTE_PTR, pulOpStateLen: CK_ULONG_PTR)
    => "{{\"session\":{}}}", hSession);
spy_fn!(C_SetOperationState(hSession: CK_SESSION_HANDLE, pOpState: CK_BYTE_PTR, ulOpStateLen: CK_ULONG, hEncKey: CK_OBJECT_HANDLE, hAuthKey: CK_OBJECT_HANDLE)
    => "{{\"session\":{},\"state_len\":{}}}", hSession, ulOpStateLen);

// Parallel function management (legacy)
spy_fn!(C_GetFunctionStatus(hSession: CK_SESSION_HANDLE)
    => "{{\"session\":{}}}", hSession);
spy_fn!(C_CancelFunction(hSession: CK_SESSION_HANDLE)
    => "{{\"session\":{}}}", hSession);
spy_fn!(C_WaitForSlotEvent(flags: CK_FLAGS, pSlot: CK_SLOT_ID_PTR, pReserved: CK_VOID_PTR)
    => "{{\"flags\":\"0x{:x}\"}}", flags);
