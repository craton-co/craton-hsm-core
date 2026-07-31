// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Bounded binary persistence codec for secret-bearing token objects.
//!
//! This intentionally replaces generic serde deserialization: key bytes are
//! copied straight from authenticated plaintext into `RawKeyMaterial`, avoiding
//! parser-owned temporary allocations that cannot be zeroized by the HSM.

use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::types::CK_ULONG;
use crate::store::key_material::RawKeyMaterial;
use crate::store::object::{KeyLifecycleState, StoredObject};

const MAGIC: &[u8; 4] = b"RHSO";
const VERSION: u8 = 1;
const MAX_OBJECT_BYTES: usize = 1 << 20;
const MAX_FIELD_BYTES: usize = 64 << 10;
const MAX_ATTRIBUTES: usize = 64;

// `CK_ULONG` is `std::ffi::c_ulong`: 32 bits on Windows (LLP64) but 64 bits
// on Linux/macOS (LP64). Object handles in particular are Feistel-scrambled
// over the full native width for opacity, so on a 64-bit target they
// routinely exceed `u32::MAX`. The wire format is therefore a fixed 64-bit
// little-endian value on every platform: infallible to widen on encode,
// and only fallible to narrow on decode when CK_ULONG itself is 32 bits
// (which never actually fails for values this codec itself produced).
fn ulong_to_u64(value: CK_ULONG) -> u64 {
    u64::from(value)
}
fn u64_to_ulong(value: u64) -> HsmResult<CK_ULONG> {
    CK_ULONG::try_from(value).map_err(|_| HsmError::DataLenRange)
}
fn opt_ulong_to_u64(value: Option<CK_ULONG>) -> Option<u64> {
    value.map(ulong_to_u64)
}
fn opt_u64_to_ulong(value: Option<u64>) -> HsmResult<Option<CK_ULONG>> {
    value.map(u64_to_ulong).transpose()
}

pub(crate) fn encode(obj: &StoredObject) -> HsmResult<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(512));
    out.extend_from_slice(MAGIC);
    put_u8(&mut out, VERSION);
    put_u64(&mut out, ulong_to_u64(obj.handle));
    put_u64(&mut out, ulong_to_u64(obj.slot_id));
    put_u64(&mut out, ulong_to_u64(obj.class));
    put_opt_u64(&mut out, opt_ulong_to_u64(obj.key_type));
    put_bytes(&mut out, &obj.label)?;
    put_bytes(&mut out, &obj.id)?;
    for value in [
        obj.token_object,
        obj.private,
        obj.sensitive,
        obj.extractable,
        obj.modifiable,
        obj.destroyable,
        obj.copyable,
        obj.can_encrypt,
        obj.can_decrypt,
        obj.can_sign,
        obj.can_verify,
        obj.can_wrap,
        obj.can_unwrap,
        obj.can_derive,
    ] {
        put_bool(&mut out, value);
    }
    put_opt_key_material(&mut out, obj.key_material.as_ref())?;
    put_opt_bytes(&mut out, obj.public_key_data.as_deref())?;
    put_opt_bytes(&mut out, obj.modulus.as_deref())?;
    put_opt_u64(&mut out, opt_ulong_to_u64(obj.modulus_bits));
    put_opt_bytes(&mut out, obj.public_exponent.as_deref())?;
    put_opt_bytes(&mut out, obj.ec_params.as_deref())?;
    put_opt_bytes(&mut out, obj.ec_point.as_deref())?;
    put_opt_u64(&mut out, opt_ulong_to_u64(obj.value_len));
    if obj.extra_attributes.len() > MAX_ATTRIBUTES {
        return Err(HsmError::DataLenRange);
    }
    let mut attributes: Vec<_> = obj.extra_attributes.iter().collect();
    attributes.sort_unstable_by_key(|(key, _)| **key);
    put_u32(&mut out, attributes.len() as u32);
    for (key, value) in attributes {
        put_u64(&mut out, ulong_to_u64(*key));
        put_bytes(&mut out, value)?;
    }
    put_opt_date(&mut out, obj.start_date);
    put_opt_date(&mut out, obj.end_date);
    put_u8(
        &mut out,
        match obj.lifecycle_state {
            KeyLifecycleState::PreActivation => 0,
            KeyLifecycleState::Active => 1,
            KeyLifecycleState::Deactivated => 2,
            KeyLifecycleState::Compromised => 3,
            KeyLifecycleState::Destroyed => 4,
        },
    );
    put_u64(&mut out, obj.creation_time);
    if out.len() > MAX_OBJECT_BYTES {
        return Err(HsmError::DataLenRange);
    }
    Ok(out)
}

pub(crate) fn decode(data: &[u8]) -> HsmResult<StoredObject> {
    if data.len() > MAX_OBJECT_BYTES {
        return Err(HsmError::DataLenRange);
    }
    let mut reader = Reader::new(data);
    if reader.take_exact(4)? != MAGIC || reader.take_u8()? != VERSION {
        return Err(HsmError::DataInvalid);
    }
    let handle = u64_to_ulong(reader.take_u64()?)?;
    let slot_id = u64_to_ulong(reader.take_u64()?)?;
    let class = u64_to_ulong(reader.take_u64()?)?;
    let key_type = opt_u64_to_ulong(reader.take_opt_u64()?)?;
    let label = reader.take_vec()?;
    let id = reader.take_vec()?;
    let token_object = reader.take_bool()?;
    let private = reader.take_bool()?;
    let sensitive = reader.take_bool()?;
    let extractable = reader.take_bool()?;
    let modifiable = reader.take_bool()?;
    let destroyable = reader.take_bool()?;
    let copyable = reader.take_bool()?;
    let can_encrypt = reader.take_bool()?;
    let can_decrypt = reader.take_bool()?;
    let can_sign = reader.take_bool()?;
    let can_verify = reader.take_bool()?;
    let can_wrap = reader.take_bool()?;
    let can_unwrap = reader.take_bool()?;
    let can_derive = reader.take_bool()?;
    let key_material = reader.take_opt_key_material()?;
    let public_key_data = reader.take_opt_vec()?;
    let modulus = reader.take_opt_vec()?;
    let modulus_bits = opt_u64_to_ulong(reader.take_opt_u64()?)?;
    let public_exponent = reader.take_opt_vec()?;
    let ec_params = reader.take_opt_vec()?;
    let ec_point = reader.take_opt_vec()?;
    let value_len = opt_u64_to_ulong(reader.take_opt_u64()?)?;
    let attribute_count = reader.take_u32()? as usize;
    if attribute_count > MAX_ATTRIBUTES {
        return Err(HsmError::DataLenRange);
    }
    let mut extra_attributes = HashMap::with_capacity(attribute_count);
    for _ in 0..attribute_count {
        let key = u64_to_ulong(reader.take_u64()?)?;
        let value = reader.take_vec()?;
        if extra_attributes.insert(key, value).is_some() {
            return Err(HsmError::DataInvalid);
        }
    }
    let start_date = reader.take_opt_date()?;
    let end_date = reader.take_opt_date()?;
    let lifecycle_state = match reader.take_u8()? {
        0 => KeyLifecycleState::PreActivation,
        1 => KeyLifecycleState::Active,
        2 => KeyLifecycleState::Deactivated,
        3 => KeyLifecycleState::Compromised,
        4 => KeyLifecycleState::Destroyed,
        _ => return Err(HsmError::DataInvalid),
    };
    let creation_time = reader.take_u64()?;
    if !reader.is_empty() {
        return Err(HsmError::DataInvalid);
    }
    Ok(StoredObject {
        handle,
        slot_id,
        class,
        key_type,
        label,
        id,
        token_object,
        private,
        sensitive,
        extractable,
        modifiable,
        destroyable,
        copyable,
        can_encrypt,
        can_decrypt,
        can_sign,
        can_verify,
        can_wrap,
        can_unwrap,
        can_derive,
        key_material,
        public_key_data,
        modulus,
        modulus_bits,
        public_exponent,
        ec_params,
        ec_point,
        value_len,
        extra_attributes,
        start_date,
        end_date,
        lifecycle_state,
        creation_time,
    })
}

fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}
fn put_bool(out: &mut Vec<u8>, value: bool) {
    put_u8(out, u8::from(value));
}
fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_opt_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(v) => {
            put_u8(out, 1);
            put_u64(out, v);
        }
        None => put_u8(out, 0),
    }
}
fn put_bytes(out: &mut Vec<u8>, value: &[u8]) -> HsmResult<()> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(HsmError::DataLenRange);
    }
    put_u32(out, value.len() as u32);
    out.extend_from_slice(value);
    Ok(())
}
fn put_opt_bytes(out: &mut Vec<u8>, value: Option<&[u8]>) -> HsmResult<()> {
    match value {
        Some(v) => {
            put_u8(out, 1);
            put_bytes(out, v)
        }
        None => {
            put_u8(out, 0);
            Ok(())
        }
    }
}
fn put_opt_key_material(out: &mut Vec<u8>, value: Option<&RawKeyMaterial>) -> HsmResult<()> {
    put_opt_bytes(out, value.map(RawKeyMaterial::as_bytes))
}
fn put_opt_date(out: &mut Vec<u8>, value: Option<[u8; 8]>) {
    match value {
        Some(v) => {
            put_u8(out, 1);
            out.extend_from_slice(&v);
        }
        None => put_u8(out, 0),
    }
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }
    fn is_empty(&self) -> bool {
        self.offset == self.input.len()
    }
    fn take_exact(&mut self, length: usize) -> HsmResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(HsmError::DataInvalid)?;
        let result = self
            .input
            .get(self.offset..end)
            .ok_or(HsmError::DataInvalid)?;
        self.offset = end;
        Ok(result)
    }
    fn take_u8(&mut self) -> HsmResult<u8> {
        Ok(self.take_exact(1)?[0])
    }
    fn take_bool(&mut self) -> HsmResult<bool> {
        match self.take_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(HsmError::DataInvalid),
        }
    }
    fn take_u32(&mut self) -> HsmResult<u32> {
        Ok(u32::from_le_bytes(
            self.take_exact(4)?
                .try_into()
                .map_err(|_| HsmError::DataInvalid)?,
        ))
    }
    fn take_u64(&mut self) -> HsmResult<u64> {
        Ok(u64::from_le_bytes(
            self.take_exact(8)?
                .try_into()
                .map_err(|_| HsmError::DataInvalid)?,
        ))
    }
    fn take_opt_u64(&mut self) -> HsmResult<Option<u64>> {
        match self.take_u8()? {
            0 => Ok(None),
            1 => self.take_u64().map(Some),
            _ => Err(HsmError::DataInvalid),
        }
    }
    fn take_vec(&mut self) -> HsmResult<Vec<u8>> {
        let length = self.take_u32()? as usize;
        if length > MAX_FIELD_BYTES {
            return Err(HsmError::DataLenRange);
        }
        let bytes = self.take_exact(length)?;
        let mut result = Vec::with_capacity(length);
        result.extend_from_slice(bytes);
        Ok(result)
    }
    fn take_opt_vec(&mut self) -> HsmResult<Option<Vec<u8>>> {
        match self.take_u8()? {
            0 => Ok(None),
            1 => self.take_vec().map(Some),
            _ => Err(HsmError::DataInvalid),
        }
    }
    fn take_opt_key_material(&mut self) -> HsmResult<Option<RawKeyMaterial>> {
        match self.take_u8()? {
            0 => Ok(None),
            1 => self
                .take_vec()
                .map(|bytes| Some(RawKeyMaterial::new(bytes))),
            _ => Err(HsmError::DataInvalid),
        }
    }
    fn take_opt_date(&mut self) -> HsmResult<Option<[u8; 8]>> {
        match self.take_u8()? {
            0 => Ok(None),
            1 => self
                .take_exact(8)
                .map(|bytes| Some(bytes.try_into().expect("fixed length"))),
            _ => Err(HsmError::DataInvalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs11_abi::constants::CKO_SECRET_KEY;

    #[test]
    fn round_trip_preserves_secret_object() {
        let mut object = StoredObject::new(7, CKO_SECRET_KEY);
        object.key_material = Some(RawKeyMaterial::new(vec![0xA5; 32]));
        object.extra_attributes.insert(42, vec![1, 2, 3]);
        let encoded = encode(&object).expect("encode");
        let decoded = decode(&encoded).expect("decode");
        assert_eq!(decoded.handle, object.handle);
        assert_eq!(
            decoded.key_material.as_ref().unwrap().as_bytes(),
            &[0xA5; 32]
        );
        assert_eq!(decoded.extra_attributes.get(&42), Some(&vec![1, 2, 3]));
    }

    #[test]
    fn round_trip_preserves_max_width_handle() {
        // Object handles are Feistel-scrambled over the full native CK_ULONG
        // width for opacity, so on 64-bit targets they routinely exceed
        // `u32::MAX`. Exercise the largest possible native value to guard
        // against a codec that silently clamps to 32 bits on encode.
        let object = StoredObject::new(CK_ULONG::MAX, CKO_SECRET_KEY);
        let encoded = encode(&object).expect("encode");
        let decoded = decode(&encoded).expect("decode");
        assert_eq!(decoded.handle, CK_ULONG::MAX);
    }

    #[test]
    fn rejects_trailing_data() {
        let object = StoredObject::new(7, CKO_SECRET_KEY);
        let mut encoded = encode(&object).expect("encode");
        encoded.push(0);
        assert!(decode(&encoded).is_err());
    }
}
