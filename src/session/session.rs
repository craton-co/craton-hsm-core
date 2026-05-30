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

/// Magic / format-version prefix for operation state blobs.
///
/// `OPS1` = "Operation State, version 1". Format v1 binds the serialized
/// blob to the originating `session_handle` and `slot_id` via the
/// authenticated payload, preventing a `C_GetOperationState` blob from
/// session A being replayed into session B (potentially across user
/// boundaries in a multi-tenant process).
///
/// Any pre-v1 blob would have started with `op_type` in `0..=4`, so it
/// will fail this magic check and be rejected by `deserialize_state`.
const OP_STATE_MAGIC: [u8; 4] = *b"OPS1";

impl ActiveOperation {
    /// Serialize the operation state into a portable blob.
    ///
    /// Format (v1):
    /// `[4:magic "OPS1"][8:session_handle][8:slot_id][1:type][8:mechanism][8:key_handle][4:param_len][N:param][4:data_len][M:data][32:hmac]`
    ///
    /// `session_handle` and `slot_id` are included in the MAC'd payload to
    /// bind the saved state to the originating session — `deserialize_state`
    /// will reject a blob whose binding fields do not match the caller's
    /// session/slot. Without this binding, an attacker who can call
    /// `C_GetOperationState` on session A could replay the blob into
    /// `C_SetOperationState` on session B in the same process (potentially
    /// crossing user boundaries in a multi-tenant deployment).
    ///
    /// Returns `Err` if param or data lengths exceed the deserialization
    /// limits (`OP_STATE_MAX_PARAM_LEN` / `OP_STATE_MAX_DATA_LEN`),
    /// preventing silent `u32` truncation on the serialize side.
    ///
    /// The buffer is `Zeroizing` from the start so intermediate CSPs
    /// are zeroized even if an early return or panic occurs
    /// (FIPS 140-3 §7.7).
    pub fn serialize_state(
        &self,
        state_hmac_key: &[u8; 32],
        session_handle: CK_SESSION_HANDLE,
        slot_id: CK_SLOT_ID,
    ) -> HsmResult<Zeroizing<Vec<u8>>> {
        // Use Zeroizing from the start so CSPs are zeroized on panic/drop.
        let mut buf = Zeroizing::new(Vec::new());

        // Magic / format-version prefix (must be authenticated, so write
        // before the rest of the payload and MAC over the whole thing).
        buf.extend_from_slice(&OP_STATE_MAGIC);

        // Session/slot binding fields. Stored as u64 LE regardless of the
        // platform width of CK_ULONG (32-bit on Windows, 64-bit on Linux)
        // so blobs are deterministically sized and the MAC covers a
        // canonical representation of the binding.
        buf.extend_from_slice(&(session_handle as u64).to_le_bytes());
        buf.extend_from_slice(&(slot_id as u64).to_le_bytes());

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
    ///
    /// Verifies the HMAC-SHA256 tag to detect tampering before parsing,
    /// rejects blobs whose 4-byte magic does not match the current
    /// format version (`OPS1`), and rejects blobs whose embedded
    /// `session_handle` / `slot_id` do not match the caller-supplied
    /// `expected_session` / `expected_slot`. This binding prevents an
    /// attacker from replaying a `C_GetOperationState` blob from
    /// session A into `C_SetOperationState` on session B.
    ///
    /// Returns `(op_type, mechanism, key_handle, mechanism_param, data)`
    /// with `Zeroizing` wrappers on param/data so CSPs are zeroized on
    /// drop (FIPS 140-3 §7.7).
    ///
    /// Header format (v1):
    /// `[4:magic "OPS1"][8:session_handle][8:slot_id][1:type][8:mechanism][8:key_handle][4:param_len]...`
    pub fn deserialize_state(
        blob: &[u8],
        state_hmac_key: &[u8; 32],
        expected_session: CK_SESSION_HANDLE,
        expected_slot: CK_SLOT_ID,
    ) -> HsmResult<(
        u8,
        CK_MECHANISM_TYPE,
        CK_OBJECT_HANDLE,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    )> {
        // Header layout (pre-payload):
        //   [4: magic][8: session_handle][8: slot_id]
        //   [1: type][8: mechanism][8: key_handle][4: param_len]
        const BIND_LEN: usize = 4 + 8 + 8; // magic + session + slot = 20
        const INNER_HEADER_LEN: usize = 1 + 8 + 8 + 4; // type+mech+key+param_len = 21
        const HEADER_LEN: usize = BIND_LEN + INNER_HEADER_LEN; // 41

        if blob.len() < HEADER_LEN + OP_STATE_HMAC_LEN {
            return Err(HsmError::DataInvalid);
        }

        // Verify HMAC tag (last 32 bytes) over the entire preceding payload,
        // which includes the magic and the session/slot binding.
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

        // Reject anything that isn't the current format version. Legacy
        // (pre-binding) blobs had op_type in 0..=4 as their first byte,
        // which cannot collide with "OPS1" = [0x4F, 0x50, 0x53, 0x31].
        if payload[..4] != OP_STATE_MAGIC {
            return Err(HsmError::DataInvalid);
        }

        // Authenticated session/slot binding. After the HMAC check, both
        // values are known to be exactly what `serialize_state` wrote, so
        // any mismatch with the caller's session/slot indicates an attempted
        // cross-session replay and must be rejected.
        let blob_session = u64::from_le_bytes(
            payload[4..12]
                .try_into()
                .map_err(|_| HsmError::DataInvalid)?,
        );
        let blob_slot = u64::from_le_bytes(
            payload[12..20]
                .try_into()
                .map_err(|_| HsmError::DataInvalid)?,
        );
        if blob_session != expected_session as u64 || blob_slot != expected_slot as u64 {
            return Err(HsmError::DataInvalid);
        }

        // Parse the verified payload — u64 for mechanism and key_handle
        let op_type = payload[BIND_LEN];

        // Validate op_type against known operation constants
        match op_type {
            OP_TYPE_ENCRYPT | OP_TYPE_DECRYPT | OP_TYPE_SIGN | OP_TYPE_VERIFY | OP_TYPE_DIGEST => {}
            _ => return Err(HsmError::DataInvalid),
        }

        let mechanism = u64::from_le_bytes(
            payload[BIND_LEN + 1..BIND_LEN + 9]
                .try_into()
                .map_err(|_| HsmError::DataInvalid)?,
        ) as CK_MECHANISM_TYPE;
        let key_handle = u64::from_le_bytes(
            payload[BIND_LEN + 9..BIND_LEN + 17]
                .try_into()
                .map_err(|_| HsmError::DataInvalid)?,
        ) as CK_OBJECT_HANDLE;
        let param_len = u32::from_le_bytes(
            payload[BIND_LEN + 17..BIND_LEN + 21]
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

#[cfg(test)]
mod tests {
    //! Tests for the `ActiveOperation` state serialization, focusing on the
    //! session/slot binding added in format version 1. These tests use a
    //! `Digest` operation because it does not carry a key handle that has
    //! to exist in the object store, which keeps them independent of any
    //! HsmCore setup.
    use super::*;

    fn fixed_key() -> [u8; 32] {
        // Deterministic test key — not used for any real CSP.
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    fn sample_digest_op() -> ActiveOperation {
        ActiveOperation::Digest {
            mechanism: CKM_SHA256,
            hasher: None,
            accumulated_input: Zeroizing::new(b"hello world".to_vec()),
        }
    }

    #[test]
    fn roundtrip_matching_session_and_slot_ok() {
        let key = fixed_key();
        let op = sample_digest_op();
        let blob = op
            .serialize_state(&key, 1, 2)
            .expect("serialize_state should succeed");

        let (op_type, mechanism, key_handle, param, data) =
            ActiveOperation::deserialize_state(&blob, &key, 1, 2)
                .expect("matching session/slot must deserialize cleanly");

        assert_eq!(op_type, OP_TYPE_DIGEST);
        assert_eq!(mechanism, CKM_SHA256);
        assert_eq!(key_handle, 0);
        assert!(param.is_empty());
        assert_eq!(&data[..], b"hello world");
    }

    #[test]
    fn mismatched_session_handle_is_rejected() {
        let key = fixed_key();
        let op = sample_digest_op();
        let blob = op.serialize_state(&key, 1, 2).unwrap();

        // Same slot, different session handle — must reject to prevent
        // cross-session replay within the same slot/process.
        let err = ActiveOperation::deserialize_state(&blob, &key, 3, 2)
            .expect_err("mismatched session_handle must be rejected");
        assert!(matches!(err, HsmError::DataInvalid));
    }

    #[test]
    fn mismatched_slot_id_is_rejected() {
        let key = fixed_key();
        let op = sample_digest_op();
        let blob = op.serialize_state(&key, 1, 2).unwrap();

        // Same session handle, different slot — must reject to prevent
        // cross-slot replay (e.g. across tokens in a multi-tenant process).
        let err = ActiveOperation::deserialize_state(&blob, &key, 1, 5)
            .expect_err("mismatched slot_id must be rejected");
        assert!(matches!(err, HsmError::DataInvalid));
    }

    #[test]
    fn legacy_pre_binding_blob_is_rejected() {
        // Synthesize a pre-v1 blob (no magic prefix, just the old header
        // starting with op_type) MAC'd with the right key, and confirm the
        // new deserializer rejects it. This locks in the format-version
        // bump: legacy callers cannot silently downgrade past the binding.
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let key = fixed_key();
        let mut legacy = Vec::new();
        legacy.push(OP_TYPE_DIGEST);
        legacy.extend_from_slice(&(CKM_SHA256 as u64).to_le_bytes());
        legacy.extend_from_slice(&0u64.to_le_bytes()); // key_handle
        legacy.extend_from_slice(&0u32.to_le_bytes()); // param_len
        legacy.extend_from_slice(&0u32.to_le_bytes()); // data_len

        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&legacy);
        let tag = mac.finalize().into_bytes();
        legacy.extend_from_slice(&tag);

        let err = ActiveOperation::deserialize_state(&legacy, &key, 1, 2)
            .expect_err("legacy blob without magic must be rejected");
        assert!(matches!(err, HsmError::DataInvalid));
    }

    #[test]
    fn tampered_binding_fails_hmac() {
        // Flipping the embedded session_handle inside an otherwise valid
        // blob must fail the HMAC check (caught before the binding check
        // even runs). This guards against an attacker who notices the
        // binding fields and tries to overwrite them without re-MACing.
        let key = fixed_key();
        let op = sample_digest_op();
        let mut blob = op.serialize_state(&key, 1, 2).unwrap().to_vec();

        // Magic occupies bytes 0..4; session_handle is bytes 4..12.
        blob[4] ^= 0xFF;

        let err = ActiveOperation::deserialize_state(&blob, &key, 1, 2)
            .expect_err("HMAC must catch in-blob tampering of the binding");
        assert!(matches!(err, HsmError::DataInvalid));
    }
}
