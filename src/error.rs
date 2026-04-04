// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::CK_RV;

// NOTE: HsmError intentionally does NOT derive Copy. All variants are currently
// unit variants (zero-sized), but omitting Copy avoids a semver-breaking change
// if a variant with heap-allocated data is added in the future.
#[derive(Debug, Clone, thiserror::Error)]
#[must_use]
pub enum HsmError {
    #[error("cryptoki not initialized")]
    NotInitialized,
    #[error("already initialized")]
    AlreadyInitialized,
    #[error("bad arguments")]
    ArgumentsBad,
    #[error("slot ID invalid")]
    SlotIdInvalid,
    #[error("token not present")]
    TokenNotPresent,
    #[error("token not initialized")]
    TokenNotInitialized,
    #[error("session handle invalid")]
    SessionHandleInvalid,
    #[error("session count exceeded")]
    SessionCount,
    #[error("session read-only")]
    SessionReadOnly,
    #[error("session parallel not supported")]
    SessionParallelNotSupported,
    #[error("session exists")]
    SessionExists,
    #[error("session read-only exists")]
    SessionReadOnlyExists,
    #[error("session read-write SO exists")]
    SessionReadWriteSoExists,
    #[error("user already logged in")]
    UserAlreadyLoggedIn,
    #[error("user not logged in")]
    UserNotLoggedIn,
    #[error("user type invalid")]
    UserTypeInvalid,
    #[error("user another already logged in")]
    UserAnotherAlreadyLoggedIn,
    #[error("user PIN not initialized")]
    UserPinNotInitialized,
    #[error("PIN incorrect")]
    PinIncorrect,
    #[error("PIN invalid")]
    PinInvalid,
    #[error("PIN length out of range")]
    PinLenRange,
    #[error("PIN locked")]
    PinLocked,
    #[error("PIN rate-limited (too many recent attempts)")]
    PinRateLimited,
    #[error("object handle invalid")]
    ObjectHandleInvalid,
    #[error("attribute type invalid")]
    AttributeTypeInvalid,
    #[error("attribute value invalid")]
    AttributeValueInvalid,
    #[error("attribute read-only")]
    AttributeReadOnly,
    #[error("attribute sensitive")]
    AttributeSensitive,
    #[error("template incomplete")]
    TemplateIncomplete,
    #[error("template inconsistent")]
    TemplateInconsistent,
    #[error("mechanism invalid")]
    MechanismInvalid,
    #[error("mechanism parameter invalid")]
    MechanismParamInvalid,
    #[error("key handle invalid")]
    KeyHandleInvalid,
    #[error("key type inconsistent")]
    KeyTypeInconsistent,
    #[error("key size out of range")]
    KeySizeRange,
    #[error("key function not permitted")]
    KeyFunctionNotPermitted,
    #[error("operation active")]
    OperationActive,
    #[error("operation not initialized")]
    OperationNotInitialized,
    #[error("data invalid")]
    DataInvalid,
    #[error("data length out of range")]
    DataLenRange,
    #[error("encrypted data invalid")]
    EncryptedDataInvalid,
    #[error("encrypted data length out of range")]
    EncryptedDataLenRange,
    #[error("signature invalid")]
    SignatureInvalid,
    #[error("signature length out of range")]
    SignatureLenRange,
    #[error("buffer too small")]
    BufferTooSmall,
    #[error("function not supported")]
    FunctionNotSupported,
    #[error("general error")]
    GeneralError,
    #[error("host memory")]
    HostMemory,
    #[error("device memory")]
    DeviceMemory,
    #[error("token write-protected")]
    TokenWriteProtected,
    #[error("random seed not supported")]
    RandomSeedNotSupported,
    #[error("configuration error: {0}")]
    ConfigError(String),
    #[error("audit chain integrity broken: {0}")]
    AuditChainBroken(String),
    #[error("session closed")]
    SessionClosed,
}

impl From<HsmError> for CK_RV {
    fn from(e: HsmError) -> CK_RV {
        match e {
            HsmError::NotInitialized => CKR_CRYPTOKI_NOT_INITIALIZED,
            HsmError::AlreadyInitialized => CKR_CRYPTOKI_ALREADY_INITIALIZED,
            HsmError::ArgumentsBad => CKR_ARGUMENTS_BAD,
            HsmError::SlotIdInvalid => CKR_SLOT_ID_INVALID,
            HsmError::TokenNotPresent => CKR_TOKEN_NOT_PRESENT,
            // CKR_TOKEN_NOT_RECOGNIZED is correct per PKCS#11 spec for a software
            // token that has not yet been initialized via C_InitToken.
            HsmError::TokenNotInitialized => CKR_TOKEN_NOT_RECOGNIZED,
            HsmError::SessionHandleInvalid => CKR_SESSION_HANDLE_INVALID,
            HsmError::SessionCount => CKR_SESSION_COUNT,
            HsmError::SessionReadOnly => CKR_SESSION_READ_ONLY,
            HsmError::SessionParallelNotSupported => CKR_SESSION_PARALLEL_NOT_SUPPORTED,
            HsmError::SessionExists => CKR_SESSION_EXISTS,
            HsmError::SessionReadOnlyExists => CKR_SESSION_READ_ONLY_EXISTS,
            HsmError::SessionReadWriteSoExists => CKR_SESSION_READ_WRITE_SO_EXISTS,
            HsmError::UserAlreadyLoggedIn => CKR_USER_ALREADY_LOGGED_IN,
            HsmError::UserNotLoggedIn => CKR_USER_NOT_LOGGED_IN,
            HsmError::UserTypeInvalid => CKR_USER_TYPE_INVALID,
            HsmError::UserAnotherAlreadyLoggedIn => CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
            HsmError::UserPinNotInitialized => CKR_USER_PIN_NOT_INITIALIZED,
            HsmError::PinIncorrect => CKR_PIN_INCORRECT,
            HsmError::PinInvalid => CKR_PIN_INVALID,
            HsmError::PinLenRange => CKR_PIN_LEN_RANGE,
            HsmError::PinLocked => CKR_PIN_LOCKED,
            HsmError::PinRateLimited => CKR_FUNCTION_FAILED,
            HsmError::ObjectHandleInvalid => CKR_OBJECT_HANDLE_INVALID,
            HsmError::AttributeTypeInvalid => CKR_ATTRIBUTE_TYPE_INVALID,
            HsmError::AttributeValueInvalid => CKR_ATTRIBUTE_VALUE_INVALID,
            HsmError::AttributeReadOnly => CKR_ATTRIBUTE_READ_ONLY,
            HsmError::AttributeSensitive => CKR_ATTRIBUTE_SENSITIVE,
            HsmError::TemplateIncomplete => CKR_TEMPLATE_INCOMPLETE,
            HsmError::TemplateInconsistent => CKR_TEMPLATE_INCONSISTENT,
            HsmError::MechanismInvalid => CKR_MECHANISM_INVALID,
            HsmError::MechanismParamInvalid => CKR_MECHANISM_PARAM_INVALID,
            HsmError::KeyHandleInvalid => CKR_KEY_HANDLE_INVALID,
            HsmError::KeyTypeInconsistent => CKR_KEY_TYPE_INCONSISTENT,
            HsmError::KeySizeRange => CKR_KEY_SIZE_RANGE,
            HsmError::KeyFunctionNotPermitted => CKR_KEY_FUNCTION_NOT_PERMITTED,
            HsmError::OperationActive => CKR_OPERATION_ACTIVE,
            HsmError::OperationNotInitialized => CKR_OPERATION_NOT_INITIALIZED,
            HsmError::DataInvalid => CKR_DATA_INVALID,
            HsmError::DataLenRange => CKR_DATA_LEN_RANGE,
            HsmError::EncryptedDataInvalid => CKR_ENCRYPTED_DATA_INVALID,
            HsmError::EncryptedDataLenRange => CKR_ENCRYPTED_DATA_LEN_RANGE,
            HsmError::SignatureInvalid => CKR_SIGNATURE_INVALID,
            HsmError::SignatureLenRange => CKR_SIGNATURE_LEN_RANGE,
            HsmError::BufferTooSmall => CKR_BUFFER_TOO_SMALL,
            HsmError::FunctionNotSupported => CKR_FUNCTION_NOT_SUPPORTED,
            HsmError::GeneralError => CKR_GENERAL_ERROR,
            HsmError::HostMemory => CKR_HOST_MEMORY,
            HsmError::DeviceMemory => CKR_DEVICE_MEMORY,
            HsmError::TokenWriteProtected => CKR_TOKEN_WRITE_PROTECTED,
            HsmError::RandomSeedNotSupported => CKR_RANDOM_SEED_NOT_SUPPORTED,
            HsmError::ConfigError(_) => CKR_GENERAL_ERROR,
            HsmError::AuditChainBroken(_) => CKR_GENERAL_ERROR,
            HsmError::SessionClosed => CKR_SESSION_CLOSED,
        }
    }
}

/// Convenience alias for Results using `HsmError`.
pub type HsmResult<T> = Result<T, HsmError>;
