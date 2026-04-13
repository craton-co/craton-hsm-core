// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::*;
use crate::store::object::StoredObject;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    RoPublic,
    RoUser,
    RwPublic,
    RwUser,
    RwSO,
}

impl SessionState {
    pub fn to_ck_state(&self) -> CK_STATE {
        match self {
            SessionState::RoPublic => CKS_RO_PUBLIC_SESSION,
            SessionState::RoUser => CKS_RO_USER_FUNCTIONS,
            SessionState::RwPublic => CKS_RW_PUBLIC_SESSION,
            SessionState::RwUser => CKS_RW_USER_FUNCTIONS,
            SessionState::RwSO => CKS_RW_SO_FUNCTIONS,
        }
    }

    pub fn is_rw(&self) -> bool {
        matches!(
            self,
            SessionState::RwPublic | SessionState::RwUser | SessionState::RwSO
        )
    }

    pub fn is_logged_in(&self) -> bool {
        matches!(
            self,
            SessionState::RoUser | SessionState::RwUser | SessionState::RwSO
        )
    }

    pub fn is_so(&self) -> bool {
        matches!(self, SessionState::RwSO)
    }
}

/// Active cryptographic operation state.
/// All data fields use `Zeroizing<Vec<u8>>` to ensure intermediate plaintext
/// and key material is zeroized when the operation completes or the session closes
/// (FIPS 140-3 §7.7 — zeroization of intermediate CSPs).
pub enum ActiveOperation {
    Encrypt {
        /// Mechanism type (e.g., `CKM_AES_GCM`).
        mechanism: CK_MECHANISM_TYPE,
        /// Handle to the key used for encryption.
        key_handle: CK_OBJECT_HANDLE,
        /// Mechanism parameter (e.g., IV for CBC/CTR) — zeroized on drop.
        mechanism_param: Zeroizing<Vec<u8>>,
        /// Accumulated data for multi-part — zeroized on drop.
        data: Zeroizing<Vec<u8>>,
        /// Cached object reference from C_EncryptInit to avoid re-fetching from ObjectStore.
        cached_object: Option<Arc<parking_lot::RwLock<StoredObject>>>,
    },
    /// Symmetric decryption operation.
    Decrypt {
        /// Mechanism type.
        mechanism: CK_MECHANISM_TYPE,
        /// Handle to the key used for decryption.
        key_handle: CK_OBJECT_HANDLE,
        /// Mechanism parameter — zeroized on drop.
        mechanism_param: Zeroizing<Vec<u8>>,
        /// Accumulated data for multi-part — zeroized on drop.
        data: Zeroizing<Vec<u8>>,
        /// Cached object reference from C_DecryptInit.
        cached_object: Option<Arc<parking_lot::RwLock<StoredObject>>>,
    },
    /// Digital signature operation (RSA, ECDSA, EdDSA, PQC).
    Sign {
        /// Mechanism type.
        mechanism: CK_MECHANISM_TYPE,
        /// Handle to the key used for signing.
        key_handle: CK_OBJECT_HANDLE,
        /// Accumulated data for single-shot or multi-part sign — zeroized on drop.
        data: Zeroizing<Vec<u8>>,
        /// Hasher for multi-part sign operations (CKM_SHA*_RSA_PKCS, CKM_ECDSA_SHA*, etc.).
        hasher: Option<Box<dyn crate::crypto::digest::DigestAccumulator>>,
        /// Cached object reference from C_SignInit.
        cached_object: Option<Arc<parking_lot::RwLock<StoredObject>>>,
    },
    /// Signature verification operation.
    Verify {
        /// Mechanism type.
        mechanism: CK_MECHANISM_TYPE,
        /// Handle to the key used for verification.
        key_handle: CK_OBJECT_HANDLE,
        /// Accumulated data for single-shot or multi-part verify — zeroized on drop.
        data: Zeroizing<Vec<u8>>,
        /// Hasher for multi-part verify operations.
        hasher: Option<Box<dyn crate::crypto::digest::DigestAccumulator>>,
        /// Cached object reference from C_VerifyInit.
        cached_object: Option<Arc<parking_lot::RwLock<StoredObject>>>,
    },
    /// Message digest (hashing) operation.
    Digest {
        /// Mechanism type.
        mechanism: CK_MECHANISM_TYPE,
        /// Hasher for multi-part digest operations.
        hasher: Option<Box<dyn crate::crypto::digest::DigestAccumulator>>,
        /// Accumulated raw input for operation state save/restore.
        /// When C_GetOperationState is called, we serialize this data
        /// and can reconstruct the hasher by re-feeding it.
        accumulated_input: Zeroizing<Vec<u8>>,
    },
}

// ── Operation state serialization constants ──
const OP_TYPE_ENCRYPT: u8 = 0;
const OP_TYPE_DECRYPT: u8 = 1;
const OP_TYPE_SIGN: u8 = 2;
const OP_TYPE_VERIFY: u8 = 3;
const OP_TYPE_DIGEST: u8 = 4;

/// HMAC-SHA256 tag length appended to operation state blobs.
const OP_STATE_HMAC_LEN: usize = 32;

/// Maximum allowed mechanism parameter size in deserialized operation state (64 KB).
const OP_STATE_MAX_PARAM_LEN: usize = 64 * 1024;

/// Maximum allowed data size in deserialized operation state (4 MB).
const OP_STATE_MAX_DATA_LEN: usize = 4 * 1024 * 1024;

impl ActiveOperation {
    /// Serialize the operation state into a portable blob.
    /// Format: \[1:type\]\[8:mechanism\]\[8:key_handle\]\[4:param_len\]\[N:param\]\[4:data_len\]\[M:data\]\[32:hmac\]
    ///
    /// Returns `Err` if param or data lengths exceed the deserialization
    /// limits (`OP_STATE_MAX_PARAM_LEN` / `OP_STATE_MAX_DATA_LEN`),
    /// preventing silent `u32` truncation on the serialize side.
    ///
    /// The buffer is `Zeroizing` from the start so intermediate CSPs
    /// are zeroized even if an early return or panic occurs
    /// (FIPS 140-3 §7.7).
    pub fn serialize_state(&self, state_hmac_key: &[u8; 32]) -> HsmResult<Zeroizing<Vec<u8>>> {
        // Use Zeroizing from the start so CSPs are zeroized on panic/drop.
        let mut buf = Zeroizing::new(Vec::new());

        /// Validate and write a length-prefixed field, returning
        /// `HsmError::DataLenRange` if the length exceeds `max`.
        fn write_field(buf: &mut Vec<u8>, field: &[u8], max: usize) -> HsmResult<()> {
            if field.len() > max {
                return Err(HsmError::DataLenRange);
            }
            buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
            buf.extend_from_slice(field);
            Ok(())
        }

        match self {
            ActiveOperation::Encrypt {
                mechanism,
                key_handle,
                mechanism_param,
                data,
                ..
            } => {
                buf.push(OP_TYPE_ENCRYPT);
                buf.extend_from_slice(&(*mechanism as u64).to_le_bytes());
                buf.extend_from_slice(&(*key_handle as u64).to_le_bytes());
                write_field(&mut buf, mechanism_param, OP_STATE_MAX_PARAM_LEN)?;
                write_field(&mut buf, data, OP_STATE_MAX_DATA_LEN)?;
            }
            ActiveOperation::Decrypt {
                mechanism,
                key_handle,
                mechanism_param,
                data,
                ..
            } => {
                buf.push(OP_TYPE_DECRYPT);
                buf.extend_from_slice(&(*mechanism as u64).to_le_bytes());
                buf.extend_from_slice(&(*key_handle as u64).to_le_bytes());
                write_field(&mut buf, mechanism_param, OP_STATE_MAX_PARAM_LEN)?;
                write_field(&mut buf, data, OP_STATE_MAX_DATA_LEN)?;
            }
            ActiveOperation::Sign {
                mechanism,
                key_handle,
                data,
                ..
            } => {
                buf.push(OP_TYPE_SIGN);
                buf.extend_from_slice(&(*mechanism as u64).to_le_bytes());
                buf.extend_from_slice(&(*key_handle as u64).to_le_bytes());
                buf.extend_from_slice(&0u32.to_le_bytes()); // no mechanism_param
                write_field(&mut buf, data, OP_STATE_MAX_DATA_LEN)?;
            }
            ActiveOperation::Verify {
                mechanism,
                key_handle,
                data,
                ..
            } => {
                buf.push(OP_TYPE_VERIFY);
                buf.extend_from_slice(&(*mechanism as u64).to_le_bytes());
                buf.extend_from_slice(&(*key_handle as u64).to_le_bytes());
                buf.extend_from_slice(&0u32.to_le_bytes()); // no mechanism_param
                write_field(&mut buf, data, OP_STATE_MAX_DATA_LEN)?;
            }
            ActiveOperation::Digest {
                mechanism,
                accumulated_input,
                ..
            } => {
                buf.push(OP_TYPE_DIGEST);
                buf.extend_from_slice(&(*mechanism as u64).to_le_bytes());
                buf.extend_from_slice(&0u64.to_le_bytes()); // key_handle = 0
                buf.extend_from_slice(&0u32.to_le_bytes()); // no mechanism_param
                write_field(&mut buf, accumulated_input, OP_STATE_MAX_DATA_LEN)?;
            }
        }

        // Append HMAC-SHA256 tag to detect tampering
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(state_hmac_key).expect("HMAC key length is always valid");
        mac.update(&buf[..]);
        let tag = mac.finalize().into_bytes();
        buf.extend_from_slice(&tag);

        Ok(buf)
    }

    /// Deserialize an operation state blob into its components.
    /// Verifies the HMAC-SHA256 tag to detect tampering before parsing.
    /// Validates `op_type` against known operation constants.
    /// Returns (op_type, mechanism, key_handle, mechanism_param, data) with
    /// `Zeroizing` wrappers on param/data to ensure CSPs are zeroized on drop
    /// (FIPS 140-3 §7.7).
    ///
    /// Header format: \[1:type\]\[8:mechanism\]\[8:key_handle\]\[4:param_len\]...
    pub fn deserialize_state(
        blob: &[u8],
        state_hmac_key: &[u8; 32],
    ) -> HsmResult<(
        u8,
        CK_MECHANISM_TYPE,
        CK_OBJECT_HANDLE,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    )> {
        // Minimum: 21 bytes header (1+8+8+4) + 32 bytes HMAC
        const HEADER_LEN: usize = 1 + 8 + 8 + 4; // 21
        if blob.len() < HEADER_LEN + OP_STATE_HMAC_LEN {
            return Err(HsmError::DataInvalid);
        }

        // Verify HMAC tag (last 32 bytes)
        let payload = &blob[..blob.len() - OP_STATE_HMAC_LEN];
        let provided_tag = &blob[blob.len() - OP_STATE_HMAC_LEN..];

        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(state_hmac_key).expect("HMAC key length is always valid");
        mac.update(payload);
        mac.verify_slice(provided_tag)
            .map_err(|_| HsmError::DataInvalid)?;

        // Parse the verified payload — u64 for mechanism and key_handle
        let op_type = payload[0];

        // Validate op_type against known operation constants
        match op_type {
            OP_TYPE_ENCRYPT | OP_TYPE_DECRYPT | OP_TYPE_SIGN | OP_TYPE_VERIFY | OP_TYPE_DIGEST => {}
            _ => return Err(HsmError::DataInvalid),
        }

        let mechanism = u64::from_le_bytes(
            payload[1..9]
                .try_into()
                .map_err(|_| HsmError::DataInvalid)?,
        ) as CK_MECHANISM_TYPE;
        let key_handle = u64::from_le_bytes(
            payload[9..17]
                .try_into()
                .map_err(|_| HsmError::DataInvalid)?,
        ) as CK_OBJECT_HANDLE;
        let param_len = u32::from_le_bytes(
            payload[17..21]
                .try_into()
                .map_err(|_| HsmError::DataInvalid)?,
        ) as usize;

        if param_len > OP_STATE_MAX_PARAM_LEN {
            return Err(HsmError::DataInvalid);
        }
        if payload.len() < HEADER_LEN + param_len + 4 {
            return Err(HsmError::DataInvalid);
        }
        let mechanism_param = Zeroizing::new(payload[HEADER_LEN..HEADER_LEN + param_len].to_vec());
        let data_offset = HEADER_LEN + param_len;
        let data_len = u32::from_le_bytes(
            payload[data_offset..data_offset + 4]
                .try_into()
                .map_err(|_| HsmError::DataInvalid)?,
        ) as usize;

        if data_len > OP_STATE_MAX_DATA_LEN {
            return Err(HsmError::DataInvalid);
        }
        if payload.len() < data_offset + 4 + data_len {
            return Err(HsmError::DataInvalid);
        }
        let data = Zeroizing::new(payload[data_offset + 4..data_offset + 4 + data_len].to_vec());

        Ok((op_type, mechanism, key_handle, mechanism_param, data))
    }
}

impl std::fmt::Debug for ActiveOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActiveOperation::Encrypt {
                mechanism,
                key_handle,
                ..
            } => f
                .debug_struct("Encrypt")
                .field("mechanism", mechanism)
                .field("key_handle", key_handle)
                .finish(),
            ActiveOperation::Decrypt {
                mechanism,
                key_handle,
                ..
            } => f
                .debug_struct("Decrypt")
                .field("mechanism", mechanism)
                .field("key_handle", key_handle)
                .finish(),
            ActiveOperation::Sign {
                mechanism,
                key_handle,
                ..
            } => f
                .debug_struct("Sign")
                .field("mechanism", mechanism)
                .field("key_handle", key_handle)
                .finish(),
            ActiveOperation::Verify {
                mechanism,
                key_handle,
                ..
            } => f
                .debug_struct("Verify")
                .field("mechanism", mechanism)
                .field("key_handle", key_handle)
                .finish(),
            ActiveOperation::Digest { mechanism, .. } => f
                .debug_struct("Digest")
                .field("mechanism", mechanism)
                .finish(),
        }
    }
}

/// Find context for active FindObjects operations
#[derive(Debug)]
pub struct FindContext {
    pub results: Vec<CK_OBJECT_HANDLE>,
    pub position: usize,
}

pub struct Session {
    pub handle: CK_SESSION_HANDLE,
    pub slot_id: CK_SLOT_ID,
    pub flags: CK_FLAGS,
    pub state: SessionState,
    pub active_operation: Option<ActiveOperation>,
    pub find_context: Option<FindContext>,
    /// FIPS 140-3 IG 2.4.C: Algorithm indicator for the last completed operation.
    /// `Some(true)` = approved, `Some(false)` = non-approved, `None` = no operation yet.
    pub last_operation_fips_approved: Option<bool>,
    /// Monotonic timestamp of the last activity on this session, used for
    /// idle-timeout cleanup. Updated by `touch()`.
    pub last_activity: Instant,
    /// Set to `true` when this session has been logically closed. Any thread
    /// that still holds an `Arc<RwLock<Session>>` after the DashMap removal
    /// can check this flag to detect a use-after-close condition.
    pub closed: bool,
}

impl Drop for Session {
    fn drop(&mut self) {
        // Explicitly clear crypto state to trigger Zeroizing drop on any
        // intermediate CSPs held in ActiveOperation fields.
        self.active_operation = None;
        self.find_context = None;
    }
}

impl Session {
    pub fn new(handle: CK_SESSION_HANDLE, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Self {
        let is_rw = (flags & CKF_RW_SESSION) != 0;
        let state = if is_rw {
            SessionState::RwPublic
        } else {
            SessionState::RoPublic
        };

        Self {
            handle,
            slot_id,
            flags,
            state,
            active_operation: None,
            find_context: None,
            last_operation_fips_approved: None,
            last_activity: Instant::now(),
            closed: false,
        }
    }

    /// Update the last-activity timestamp to now. Call this on every
    /// operation that constitutes "activity" (crypto ops, find, login, etc.)
    /// to prevent the session from being reaped by idle-timeout cleanup.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Return how long this session has been idle (time since last `touch()`
    /// or creation). Uses `Instant` so it is monotonic and not affected by
    /// wall-clock adjustments.
    pub fn idle_duration(&self) -> Duration {
        self.last_activity.elapsed()
    }

    pub fn is_rw(&self) -> bool {
        self.state.is_rw()
    }

    /// Transition session state on user login
    pub fn on_user_login(&mut self) -> HsmResult<()> {
        self.state = match self.state {
            SessionState::RoPublic => SessionState::RoUser,
            SessionState::RwPublic => SessionState::RwUser,
            ref s if s.is_logged_in() => return Err(HsmError::UserAlreadyLoggedIn),
            _ => return Err(HsmError::GeneralError),
        };
        Ok(())
    }

    /// Transition session state on SO login
    pub fn on_so_login(&mut self) -> HsmResult<()> {
        self.state = match self.state {
            SessionState::RwPublic => SessionState::RwSO,
            SessionState::RoPublic => return Err(HsmError::SessionReadOnly),
            ref s if s.is_logged_in() => return Err(HsmError::UserAlreadyLoggedIn),
            _ => return Err(HsmError::GeneralError),
        };
        Ok(())
    }

    /// Transition session state on logout
    pub fn on_logout(&mut self) -> HsmResult<()> {
        self.state = match self.state {
            SessionState::RoUser => SessionState::RoPublic,
            SessionState::RwUser => SessionState::RwPublic,
            SessionState::RwSO => SessionState::RwPublic,
            _ => return Err(HsmError::UserNotLoggedIn),
        };
        // Clear active operations on logout
        self.active_operation = None;
        self.find_context = None;
        Ok(())
    }

    pub fn get_info(&self) -> CK_SESSION_INFO {
        CK_SESSION_INFO {
            slot_id: self.slot_id,
            state: self.state.to_ck_state(),
            flags: self.flags,
            device_error: 0,
        }
    }
}
