// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// PKCS#11 v3.0 type definitions
// All types follow the OASIS PKCS#11 specification for C ABI compatibility.
//
// Per the PKCS#11 specification (Section 2), all Cryptoki structures must be
// packed with 1-byte alignment on Windows (#pragma pack(push, cryptoki, 1)).
// On Unix/Linux, the default alignment is used.

use std::ffi::c_void;

// --- Primitive type aliases ---

pub type CK_BYTE = u8;
pub type CK_CHAR = u8;
pub type CK_UTF8CHAR = u8;
pub type CK_BBOOL = u8;
pub type CK_ULONG = std::ffi::c_ulong;
pub type CK_LONG = std::ffi::c_long;
pub type CK_FLAGS = CK_ULONG;
pub type CK_VOID_PTR = *mut c_void;
pub type CK_BYTE_PTR = *mut CK_BYTE;
pub type CK_CHAR_PTR = *mut CK_CHAR;
pub type CK_UTF8CHAR_PTR = *mut CK_UTF8CHAR;
pub type CK_ULONG_PTR = *mut CK_ULONG;

// --- Handle types ---

pub type CK_SESSION_HANDLE = CK_ULONG;
pub type CK_OBJECT_HANDLE = CK_ULONG;
pub type CK_SLOT_ID = CK_ULONG;
pub type CK_MECHANISM_TYPE = CK_ULONG;
pub type CK_RV = CK_ULONG;
pub type CK_OBJECT_CLASS = CK_ULONG;
pub type CK_KEY_TYPE = CK_ULONG;
pub type CK_ATTRIBUTE_TYPE = CK_ULONG;
pub type CK_USER_TYPE = CK_ULONG;
pub type CK_STATE = CK_ULONG;
pub type CK_NOTIFICATION = CK_ULONG;
pub type CK_CERTIFICATE_TYPE = CK_ULONG;
pub type CK_MECHANISM_TYPE_PTR = *mut CK_MECHANISM_TYPE;
pub type CK_SESSION_HANDLE_PTR = *mut CK_SESSION_HANDLE;
pub type CK_OBJECT_HANDLE_PTR = *mut CK_OBJECT_HANDLE;
pub type CK_SLOT_ID_PTR = *mut CK_SLOT_ID;

// --- Boolean values ---

pub const CK_FALSE: CK_BBOOL = 0;
pub const CK_TRUE: CK_BBOOL = 1;

// --- Invalid handle sentinel ---

pub const CK_INVALID_HANDLE: CK_ULONG = 0;

// --- Pointer sentinels ---

pub const NULL_PTR: CK_VOID_PTR = std::ptr::null_mut();

// --- CK_VERSION ---

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Debug, Clone, Copy, Default)]
pub struct CK_VERSION {
    pub major: CK_BYTE,
    pub minor: CK_BYTE,
}

// --- CK_INFO ---

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Debug, Clone, Copy)]
pub struct CK_INFO {
    pub cryptoki_version: CK_VERSION,
    pub manufacturer_id: [CK_UTF8CHAR; 32],
    pub flags: CK_FLAGS,
    pub library_description: [CK_UTF8CHAR; 32],
    pub library_version: CK_VERSION,
}
pub type CK_INFO_PTR = *mut CK_INFO;

// --- CK_SLOT_INFO ---

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Debug, Clone, Copy)]
pub struct CK_SLOT_INFO {
    pub slot_description: [CK_UTF8CHAR; 64],
    pub manufacturer_id: [CK_UTF8CHAR; 32],
    pub flags: CK_FLAGS,
    pub hardware_version: CK_VERSION,
    pub firmware_version: CK_VERSION,
}
pub type CK_SLOT_INFO_PTR = *mut CK_SLOT_INFO;

// --- CK_TOKEN_INFO ---

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Debug, Clone, Copy)]
pub struct CK_TOKEN_INFO {
    pub label: [CK_UTF8CHAR; 32],
    pub manufacturer_id: [CK_UTF8CHAR; 32],
    pub model: [CK_UTF8CHAR; 16],
    pub serial_number: [CK_CHAR; 16],
    pub flags: CK_FLAGS,
    pub max_session_count: CK_ULONG,
    pub session_count: CK_ULONG,
    pub max_rw_session_count: CK_ULONG,
    pub rw_session_count: CK_ULONG,
    pub max_pin_len: CK_ULONG,
    pub min_pin_len: CK_ULONG,
    pub total_public_memory: CK_ULONG,
    pub free_public_memory: CK_ULONG,
    pub total_private_memory: CK_ULONG,
    pub free_private_memory: CK_ULONG,
    pub hardware_version: CK_VERSION,
    pub firmware_version: CK_VERSION,
    pub utc_time: [CK_CHAR; 16],
}
pub type CK_TOKEN_INFO_PTR = *mut CK_TOKEN_INFO;

// --- CK_SESSION_INFO ---

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Debug, Clone, Copy)]
pub struct CK_SESSION_INFO {
    pub slot_id: CK_SLOT_ID,
    pub state: CK_STATE,
    pub flags: CK_FLAGS,
    pub device_error: CK_ULONG,
}
pub type CK_SESSION_INFO_PTR = *mut CK_SESSION_INFO;

// --- CK_ATTRIBUTE ---

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Debug, Clone, Copy)]
pub struct CK_ATTRIBUTE {
    pub attr_type: CK_ATTRIBUTE_TYPE,
    pub p_value: CK_VOID_PTR,
    pub value_len: CK_ULONG,
}
pub type CK_ATTRIBUTE_PTR = *mut CK_ATTRIBUTE;

// --- CK_MECHANISM ---

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Debug, Clone, Copy)]
pub struct CK_MECHANISM {
    pub mechanism: CK_MECHANISM_TYPE,
    pub p_parameter: CK_VOID_PTR,
    pub parameter_len: CK_ULONG,
}
pub type CK_MECHANISM_PTR = *mut CK_MECHANISM;

// --- CK_MECHANISM_INFO ---

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Debug, Clone, Copy)]
pub struct CK_MECHANISM_INFO {
    pub min_key_size: CK_ULONG,
    pub max_key_size: CK_ULONG,
    pub flags: CK_FLAGS,
}
pub type CK_MECHANISM_INFO_PTR = *mut CK_MECHANISM_INFO;

// --- CK_C_INITIALIZE_ARGS ---

pub type CK_CREATEMUTEX = Option<extern "C" fn(pp_mutex: *mut CK_VOID_PTR) -> CK_RV>;
pub type CK_DESTROYMUTEX = Option<extern "C" fn(p_mutex: CK_VOID_PTR) -> CK_RV>;
pub type CK_LOCKMUTEX = Option<extern "C" fn(p_mutex: CK_VOID_PTR) -> CK_RV>;
pub type CK_UNLOCKMUTEX = Option<extern "C" fn(p_mutex: CK_VOID_PTR) -> CK_RV>;

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
#[derive(Debug, Clone, Copy)]
pub struct CK_C_INITIALIZE_ARGS {
    pub create_mutex: CK_CREATEMUTEX,
    pub destroy_mutex: CK_DESTROYMUTEX,
    pub lock_mutex: CK_LOCKMUTEX,
    pub unlock_mutex: CK_UNLOCKMUTEX,
    pub flags: CK_FLAGS,
    pub p_reserved: CK_VOID_PTR,
}
pub type CK_C_INITIALIZE_ARGS_PTR = *mut CK_C_INITIALIZE_ARGS;

// --- CK_NOTIFY callback ---

pub type CK_NOTIFY = Option<
    extern "C" fn(
        session: CK_SESSION_HANDLE,
        event: CK_NOTIFICATION,
        p_application: CK_VOID_PTR,
    ) -> CK_RV,
>;

// --- CK_FUNCTION_LIST ---
// This struct contains pointers to all PKCS#11 functions.
// C_GetFunctionList returns a pointer to a static instance of this struct.

pub type CK_C_Initialize = extern "C" fn(CK_VOID_PTR) -> CK_RV;
pub type CK_C_Finalize = extern "C" fn(CK_VOID_PTR) -> CK_RV;
pub type CK_C_GetInfo = extern "C" fn(CK_INFO_PTR) -> CK_RV;
pub type CK_C_GetSlotList = extern "C" fn(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_GetSlotInfo = extern "C" fn(CK_SLOT_ID, CK_SLOT_INFO_PTR) -> CK_RV;
pub type CK_C_GetTokenInfo = extern "C" fn(CK_SLOT_ID, CK_TOKEN_INFO_PTR) -> CK_RV;
pub type CK_C_GetMechanismList =
    extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_GetMechanismInfo =
    extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR) -> CK_RV;
pub type CK_C_InitToken =
    extern "C" fn(CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR) -> CK_RV;
pub type CK_C_InitPIN = extern "C" fn(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV;
pub type CK_C_SetPIN =
    extern "C" fn(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV;
pub type CK_C_OpenSession =
    extern "C" fn(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR) -> CK_RV;
pub type CK_C_CloseSession = extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_CloseAllSessions = extern "C" fn(CK_SLOT_ID) -> CK_RV;
pub type CK_C_GetSessionInfo = extern "C" fn(CK_SESSION_HANDLE, CK_SESSION_INFO_PTR) -> CK_RV;
pub type CK_C_Login =
    extern "C" fn(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV;
pub type CK_C_Logout = extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_CreateObject =
    extern "C" fn(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV;
pub type CK_C_DestroyObject = extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_GetObjectSize =
    extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_GetAttributeValue =
    extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV;
pub type CK_C_SetAttributeValue =
    extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV;
pub type CK_C_FindObjectsInit =
    extern "C" fn(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV;
pub type CK_C_FindObjects =
    extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_FindObjectsFinal = extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_EncryptInit =
    extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_Encrypt =
    extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_EncryptUpdate =
    extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_EncryptFinal = extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_DecryptInit =
    extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_Decrypt =
    extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_DecryptUpdate =
    extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_DecryptFinal = extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_DigestInit = extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR) -> CK_RV;
pub type CK_C_Digest =
    extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_DigestUpdate = extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV;
pub type CK_C_DigestFinal = extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_DigestKey = extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_SignInit =
    extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_Sign =
    extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_SignUpdate = extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV;
pub type CK_C_SignFinal = extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_SignRecoverInit =
    extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_SignRecover =
    extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_VerifyInit =
    extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_Verify =
    extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV;
pub type CK_C_VerifyUpdate = extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV;
pub type CK_C_VerifyFinal = extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV;
pub type CK_C_VerifyRecoverInit =
    extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_VerifyRecover =
    extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_GenerateKey = extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
pub type CK_C_GenerateKeyPair = extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
pub type CK_C_WrapKey = extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_UnwrapKey = extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
pub type CK_C_DeriveKey = extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
pub type CK_C_SeedRandom = extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV;
pub type CK_C_GenerateRandom = extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV;
pub type CK_C_GetOperationState =
    extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_SetOperationState = extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_CopyObject = extern "C" fn(
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
pub type CK_C_DigestEncryptUpdate =
    extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_DecryptDigestUpdate =
    extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_SignEncryptUpdate =
    extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_DecryptVerifyUpdate =
    extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type CK_C_WaitForSlotEvent = extern "C" fn(CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR) -> CK_RV;
pub type CK_C_GetFunctionList = extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV;

#[cfg_attr(target_os = "windows", repr(C, packed))]
#[cfg_attr(not(target_os = "windows"), repr(C))]
pub struct CK_FUNCTION_LIST {
    pub version: CK_VERSION,
    pub C_Initialize: CK_C_Initialize,
    pub C_Finalize: CK_C_Finalize,
    pub C_GetInfo: CK_C_GetInfo,
    pub C_GetFunctionList: CK_C_GetFunctionList,
    pub C_GetSlotList: CK_C_GetSlotList,
    pub C_GetSlotInfo: CK_C_GetSlotInfo,
    pub C_GetTokenInfo: CK_C_GetTokenInfo,
    pub C_GetMechanismList: CK_C_GetMechanismList,
    pub C_GetMechanismInfo: CK_C_GetMechanismInfo,
    pub C_InitToken: CK_C_InitToken,
    pub C_InitPIN: CK_C_InitPIN,
    pub C_SetPIN: CK_C_SetPIN,
    pub C_OpenSession: CK_C_OpenSession,
    pub C_CloseSession: CK_C_CloseSession,
    pub C_CloseAllSessions: CK_C_CloseAllSessions,
    pub C_GetSessionInfo: CK_C_GetSessionInfo,
    pub C_GetOperationState: CK_C_GetOperationState,
    pub C_SetOperationState: CK_C_SetOperationState,
    pub C_Login: CK_C_Login,
    pub C_Logout: CK_C_Logout,
    pub C_CreateObject: CK_C_CreateObject,
    pub C_CopyObject: CK_C_CopyObject,
    pub C_DestroyObject: CK_C_DestroyObject,
    pub C_GetObjectSize: CK_C_GetObjectSize,
    pub C_GetAttributeValue: CK_C_GetAttributeValue,
    pub C_SetAttributeValue: CK_C_SetAttributeValue,
    pub C_FindObjectsInit: CK_C_FindObjectsInit,
    pub C_FindObjects: CK_C_FindObjects,
    pub C_FindObjectsFinal: CK_C_FindObjectsFinal,
    pub C_EncryptInit: CK_C_EncryptInit,
    pub C_Encrypt: CK_C_Encrypt,
    pub C_EncryptUpdate: CK_C_EncryptUpdate,
    pub C_EncryptFinal: CK_C_EncryptFinal,
    pub C_DecryptInit: CK_C_DecryptInit,
    pub C_Decrypt: CK_C_Decrypt,
    pub C_DecryptUpdate: CK_C_DecryptUpdate,
    pub C_DecryptFinal: CK_C_DecryptFinal,
    pub C_DigestInit: CK_C_DigestInit,
    pub C_Digest: CK_C_Digest,
    pub C_DigestUpdate: CK_C_DigestUpdate,
    pub C_DigestKey: CK_C_DigestKey,
    pub C_DigestFinal: CK_C_DigestFinal,
    pub C_SignInit: CK_C_SignInit,
    pub C_Sign: CK_C_Sign,
    pub C_SignUpdate: CK_C_SignUpdate,
    pub C_SignFinal: CK_C_SignFinal,
    pub C_SignRecoverInit: CK_C_SignRecoverInit,
    pub C_SignRecover: CK_C_SignRecover,
    pub C_VerifyInit: CK_C_VerifyInit,
    pub C_Verify: CK_C_Verify,
    pub C_VerifyUpdate: CK_C_VerifyUpdate,
    pub C_VerifyFinal: CK_C_VerifyFinal,
    pub C_VerifyRecoverInit: CK_C_VerifyRecoverInit,
    pub C_VerifyRecover: CK_C_VerifyRecover,
    pub C_DigestEncryptUpdate: CK_C_DigestEncryptUpdate,
    pub C_DecryptDigestUpdate: CK_C_DecryptDigestUpdate,
    pub C_SignEncryptUpdate: CK_C_SignEncryptUpdate,
    pub C_DecryptVerifyUpdate: CK_C_DecryptVerifyUpdate,
    pub C_GenerateKey: CK_C_GenerateKey,
    pub C_GenerateKeyPair: CK_C_GenerateKeyPair,
    pub C_WrapKey: CK_C_WrapKey,
    pub C_UnwrapKey: CK_C_UnwrapKey,
    pub C_DeriveKey: CK_C_DeriveKey,
    pub C_SeedRandom: CK_C_SeedRandom,
    pub C_GenerateRandom: CK_C_GenerateRandom,
    pub C_GetFunctionStatus: extern "C" fn(CK_SESSION_HANDLE) -> CK_RV,
    pub C_CancelFunction: extern "C" fn(CK_SESSION_HANDLE) -> CK_RV,
    pub C_WaitForSlotEvent: CK_C_WaitForSlotEvent,
}
pub type CK_FUNCTION_LIST_PTR = *mut CK_FUNCTION_LIST;
pub type CK_FUNCTION_LIST_PTR_PTR = *mut CK_FUNCTION_LIST_PTR;

// --- Utility: pad a string to a fixed-width space-padded PKCS#11 buffer ---

pub fn pad_string(dest: &mut [CK_UTF8CHAR], src: &str) {
    let bytes = src.as_bytes();
    let copy_len = bytes.len().min(dest.len());
    dest[..copy_len].copy_from_slice(&bytes[..copy_len]);
    for b in dest[copy_len..].iter_mut() {
        *b = b' ';
    }
}
