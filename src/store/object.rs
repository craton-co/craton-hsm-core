// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::*;
use crate::store::key_material::RawKeyMaterial;

/// Key lifecycle state per SP 800-57 Part 1.
///
/// Controls which cryptographic operations are permitted on a key:
/// - **PreActivation**: Key created but not yet at its `start_date`. No operations permitted.
/// - **Active**: Normal use — all permitted operations allowed.
/// - **Deactivated**: Past `end_date` — can verify/decrypt but cannot sign/encrypt.
/// - **Compromised**: Manually marked — blocked from all operations.
/// - **Destroyed**: Pending physical deletion — handle is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyLifecycleState {
    PreActivation,
    Active,
    Deactivated,
    Compromised,
    Destroyed,
}

impl Default for KeyLifecycleState {
    fn default() -> Self {
        KeyLifecycleState::Active
    }
}

/// Serde default helper for boolean fields that default to true.
fn default_true() -> bool {
    true
}

/// Internal representation of a PKCS#11 object stored in the token.
/// Serializable for persistence to the encrypted store.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredObject {
    pub handle: CK_OBJECT_HANDLE,
    /// Slot that owns this object. Used for slot-scoped isolation in multi-slot
    /// deployments — objects created on one slot are not visible from another.
    #[serde(default)]
    pub slot_id: CK_ULONG,
    pub class: CK_OBJECT_CLASS,
    pub key_type: Option<CK_KEY_TYPE>,
    pub label: Vec<u8>,
    pub id: Vec<u8>,
    pub token_object: bool,
    pub private: bool,
    pub sensitive: bool,
    pub extractable: bool,
    pub modifiable: bool,
    pub destroyable: bool,
    /// PKCS#11 CKA_COPYABLE: whether C_CopyObject is allowed on this object
    #[serde(default = "default_true")]
    pub copyable: bool,
    /// Permission attributes
    pub can_encrypt: bool,
    pub can_decrypt: bool,
    pub can_sign: bool,
    pub can_verify: bool,
    pub can_wrap: bool,
    pub can_unwrap: bool,
    pub can_derive: bool,
    /// Key material (only for key objects)
    pub key_material: Option<RawKeyMaterial>,
    /// Public key data (for asymmetric keys)
    pub public_key_data: Option<Vec<u8>>,
    /// RSA specific
    pub modulus: Option<Vec<u8>>,
    pub modulus_bits: Option<CK_ULONG>,
    pub public_exponent: Option<Vec<u8>>,
    /// EC specific
    pub ec_params: Option<Vec<u8>>,
    pub ec_point: Option<Vec<u8>>,
    /// AES specific
    pub value_len: Option<CK_ULONG>,
    /// Arbitrary additional attributes
    pub extra_attributes: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,

    // ========================================================================
    // Key lifecycle fields (SP 800-57)
    // ========================================================================
    /// CKA_START_DATE: PKCS#11 CK_DATE format (YYYYMMDD, 8 ASCII bytes)
    /// Key is pre-activation before this date.
    #[serde(default)]
    pub start_date: Option<[u8; 8]>,

    /// CKA_END_DATE: PKCS#11 CK_DATE format (YYYYMMDD, 8 ASCII bytes)
    /// Key is deactivated after this date.
    #[serde(default)]
    pub end_date: Option<[u8; 8]>,

    /// SP 800-57 lifecycle state
    #[serde(default)]
    pub lifecycle_state: KeyLifecycleState,

    /// Creation time (Unix epoch seconds)
    #[serde(default)]
    pub creation_time: u64,
}

impl StoredObject {
    pub fn new(handle: CK_OBJECT_HANDLE, class: CK_OBJECT_CLASS) -> Self {
        Self {
            handle,
            slot_id: 0,
            class,
            key_type: None,
            label: Vec::new(),
            id: Vec::new(),
            token_object: false,
            private: true,
            sensitive: true,
            extractable: false,
            modifiable: true,
            destroyable: true,
            copyable: true,
            can_encrypt: false,
            can_decrypt: false,
            can_sign: false,
            can_verify: false,
            can_wrap: false,
            can_unwrap: false,
            can_derive: false,
            key_material: None,
            public_key_data: None,
            modulus: None,
            modulus_bits: None,
            public_exponent: None,
            ec_params: None,
            ec_point: None,
            value_len: None,
            extra_attributes: HashMap::new(),
            start_date: None,
            end_date: None,
            lifecycle_state: KeyLifecycleState::Active,
            creation_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Check if a template matches this object (partial template matching per PKCS#11).
    ///
    /// Uses a bitwise u8 accumulator instead of early returns or boolean
    /// short-circuit to avoid leaking information about which attribute
    /// caused a mismatch via timing side-channels. All template attributes
    /// are always evaluated regardless of whether earlier attributes already
    /// failed to match. Variable-length comparisons (labels, IDs) use
    /// constant-time equality from the `subtle` crate.
    pub fn matches_template(&self, template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        // Use u8 accumulator with bitwise AND to prevent boolean short-circuit
        let mut matched: u8 = 1;
        for (attr_type, value) in template {
            let attr_match: u8 = match *attr_type {
                CKA_CLASS => match read_ck_ulong(value) {
                    Some(class) => (class == self.class) as u8,
                    None => 0,
                },
                CKA_KEY_TYPE => match (self.key_type, read_ck_ulong(value)) {
                    (Some(kt), Some(v)) => (v == kt) as u8,
                    (None, _) => 0,
                    (_, None) => 0,
                },
                CKA_LABEL => ct_bytes_eq(value, &self.label),
                CKA_ID => ct_bytes_eq(value, &self.id),
                CKA_TOKEN => {
                    if !value.is_empty() {
                        ((value[0] != 0) == self.token_object) as u8
                    } else {
                        1
                    }
                }
                CKA_PRIVATE => {
                    if !value.is_empty() {
                        ((value[0] != 0) == self.private) as u8
                    } else {
                        1
                    }
                }
                CKA_SENSITIVE => {
                    if !value.is_empty() {
                        ((value[0] != 0) == self.sensitive) as u8
                    } else {
                        1
                    }
                }
                CKA_SIGN => {
                    if !value.is_empty() {
                        ((value[0] != 0) == self.can_sign) as u8
                    } else {
                        1
                    }
                }
                CKA_VERIFY => {
                    if !value.is_empty() {
                        ((value[0] != 0) == self.can_verify) as u8
                    } else {
                        1
                    }
                }
                CKA_ENCRYPT => {
                    if !value.is_empty() {
                        ((value[0] != 0) == self.can_encrypt) as u8
                    } else {
                        1
                    }
                }
                CKA_DECRYPT => {
                    if !value.is_empty() {
                        ((value[0] != 0) == self.can_decrypt) as u8
                    } else {
                        1
                    }
                }
                _ => {
                    if let Some(stored) = self.extra_attributes.get(attr_type) {
                        ct_bytes_eq(stored, value)
                    } else {
                        0
                    }
                }
            };
            // Bitwise AND avoids boolean short-circuit optimization
            matched &= attr_match;
        }
        matched == 1
    }

    /// Get the approximate size of this object in bytes.
    /// Saturates to `CK_ULONG::MAX` on overflow instead of truncating.
    pub fn approximate_size(&self) -> CK_ULONG {
        let mut size: usize = std::mem::size_of::<StoredObject>();
        if let Some(ref km) = self.key_material {
            size = size.saturating_add(km.len());
        }
        if let Some(ref pk) = self.public_key_data {
            size = size.saturating_add(pk.len());
        }
        if let Some(ref m) = self.modulus {
            size = size.saturating_add(m.len());
        }
        size = size.saturating_add(self.label.len());
        size = size.saturating_add(self.id.len());
        CK_ULONG::try_from(size).unwrap_or(CK_ULONG::MAX)
    }
}

/// Custom Debug: never log key material
impl fmt::Debug for StoredObject {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("StoredObject")
            .field("handle", &self.handle)
            .field("class", &self.class)
            .field("key_type", &self.key_type)
            .field("label_len", &self.label.len())
            .field("sensitive", &self.sensitive)
            .field("extractable", &self.extractable)
            .field("lifecycle_state", &self.lifecycle_state)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl StoredObject {
    /// Check whether the given operation type is permitted by this key's
    /// lifecycle state (SP 800-57).
    ///
    /// Returns `Ok(())` if the operation is allowed, or an appropriate error.
    ///
    /// Rules:
    /// - **Active**: all operations permitted
    /// - **PreActivation**: no operations permitted
    /// - **Deactivated**: verify/decrypt/unwrap allowed; sign/encrypt/wrap blocked
    /// - **Compromised**: all operations blocked
    /// - **Destroyed**: key handle is invalid
    pub fn check_lifecycle(&self, operation: &str) -> Result<(), crate::error::HsmError> {
        use crate::error::HsmError;

        // Also check date-based lifecycle transitions
        let effective_state = self.effective_lifecycle_state();

        match effective_state {
            KeyLifecycleState::Active => Ok(()),
            KeyLifecycleState::PreActivation => {
                Err(HsmError::GeneralError) // CKR_KEY_FUNCTION_NOT_PERMITTED mapped to GeneralError
            }
            KeyLifecycleState::Deactivated => {
                // Allow verify, decrypt, unwrap (processing existing data)
                // Block sign, encrypt, wrap (creating new protected data)
                match operation {
                    "verify" | "decrypt" | "unwrap" => Ok(()),
                    _ => Err(HsmError::GeneralError),
                }
            }
            KeyLifecycleState::Compromised => Err(HsmError::GeneralError),
            KeyLifecycleState::Destroyed => Err(HsmError::ObjectHandleInvalid),
        }
    }

    /// Compute the effective lifecycle state, taking date fields into account.
    ///
    /// If the explicit lifecycle_state is Active, check dates:
    /// - If start_date is set and in the future → PreActivation
    /// - If end_date is set and in the past → Deactivated
    /// Otherwise returns the explicit lifecycle_state.
    pub fn effective_lifecycle_state(&self) -> KeyLifecycleState {
        if self.lifecycle_state != KeyLifecycleState::Active {
            return self.lifecycle_state;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check start_date (YYYYMMDD ASCII)
        if let Some(start) = &self.start_date {
            if let Some(start_epoch) = ck_date_to_epoch(start) {
                if now < start_epoch {
                    return KeyLifecycleState::PreActivation;
                }
            }
        }

        // Check end_date (YYYYMMDD ASCII)
        if let Some(end) = &self.end_date {
            if let Some(end_epoch) = ck_date_to_epoch(end) {
                if now > end_epoch {
                    return KeyLifecycleState::Deactivated;
                }
            }
        }

        KeyLifecycleState::Active
    }
}

/// Convert a CK_DATE (YYYYMMDD, 8 ASCII bytes) to a Unix epoch timestamp.
/// Returns the epoch for midnight UTC of the given date.
///
/// Uses a constant-time formula (no loops) to compute days since epoch.
fn ck_date_to_epoch(date: &[u8; 8]) -> Option<u64> {
    let s = std::str::from_utf8(date).ok()?;
    let year: u64 = s[0..4].parse().ok()?;
    let month: u64 = s[4..6].parse().ok()?;
    let day: u64 = s[6..8].parse().ok()?;

    if year < 1970 || year > 2200 || month < 1 || month > 12 || day < 1 || day > 31 {
        return None;
    }

    // Count leap years from 1970 to year-1 using closed-form formula
    let leap_years_before = |y: u64| -> u64 {
        if y == 0 {
            return 0;
        }
        let y = y - 1;
        y / 4 - y / 100 + y / 400
    };
    let leaps = leap_years_before(year) - leap_years_before(1970);
    let years_elapsed = year - 1970;
    let mut days = years_elapsed * 365 + leaps;

    // Cumulative days before each month (non-leap year)
    const CUMULATIVE_DAYS: [u64; 13] = [0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    days += CUMULATIVE_DAYS[month as usize];
    // Add leap day if past February in a leap year
    if month > 2 && is_leap_year(year) {
        days += 1;
    }
    days += day - 1;

    Some(days * 86400)
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Enum for higher-level crypto object types (used by crypto engine)
#[derive(Debug)]
pub enum CryptoObject {
    RsaPrivateKey {
        der: RawKeyMaterial,
    },
    RsaPublicKey {
        modulus: Vec<u8>,
        public_exponent: Vec<u8>,
    },
    AesKey {
        key: RawKeyMaterial,
    },
}

/// Constant-time byte slice equality comparison.
/// Returns 1 if equal, 0 if not. If lengths differ, returns 0 immediately
/// (length difference is not considered secret in PKCS#11 template matching).
fn ct_bytes_eq(a: &[u8], b: &[u8]) -> u8 {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return 0;
    }
    a.ct_eq(b).unwrap_u8()
}

/// Parse a `CK_ULONG` from raw bytes. Returns `None` if the input length
/// doesn't match exactly, instead of silently ignoring trailing bytes or
/// returning 0 (which is a valid value for some attribute types like
/// `CKO_DATA` and could cause false matches).
fn read_ck_ulong(bytes: &[u8]) -> Option<CK_ULONG> {
    let size = std::mem::size_of::<CK_ULONG>();
    if bytes.len() != size {
        return None;
    }
    let mut buf = [0u8; 8];
    buf[..size].copy_from_slice(&bytes[..size]);
    Some(CK_ULONG::from_ne_bytes(buf[..size].try_into().ok()?))
}
