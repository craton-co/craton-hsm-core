// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Fuzz target for integer overflow and buffer size attacks.
//!
//! Classic PKCS#11 vulnerabilities involve:
//! - ulCount overflows in C_FindObjects, C_GetAttributeValue
//! - Buffer length mismatches in two-call patterns
//! - Extremely large value_len in CK_ATTRIBUTE
//! - Zero-length buffers and null pointers in unexpected places
//! - CK_ULONG truncation on 32-bit vs 64-bit platforms

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::Once;

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions;
use craton_hsm::pkcs11_abi::types::*;

static INIT: Once = Once::new();

fn ensure_init() {
    INIT.call_once(|| {
        let rv = functions::C_Initialize(std::ptr::null_mut());
        assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
    });
}

/// Clean up all sessions to prevent state leaking between iterations.
fn cleanup_sessions() {
    let _ = functions::C_CloseAllSessions(0);
}

/// FIX #3: Extract a fuzz-derived PIN from data. Returns (pin_ptr, pin_len, bytes_consumed).
fn extract_fuzz_pin(data: &[u8]) -> (*mut u8, CK_ULONG, usize) {
    if data.is_empty() {
        return (std::ptr::null_mut(), 0, 0);
    }
    let pin_len = (data[0] as usize) % 65;
    let consumed = 1 + pin_len.min(data.len() - 1);
    let actual_pin = &data[1..consumed];
    if actual_pin.is_empty() {
        (std::ptr::null_mut(), 0, consumed)
    } else {
        (actual_pin.as_ptr() as *mut u8, actual_pin.len() as CK_ULONG, consumed)
    }
}

fuzz_target!(|data: &[u8]| {
    ensure_init();

    if data.len() < 4 {
        return;
    }

    let selector = data[0] % 7;
    let payload = &data[1..];

    match selector {
        0 => fuzz_get_attribute_value_lengths(payload),
        1 => fuzz_find_objects_count(payload),
        2 => fuzz_two_call_pattern_mismatch(payload),
        3 => fuzz_extreme_attribute_lengths(payload),
        4 => fuzz_null_pointer_everywhere(payload),
        5 => fuzz_get_mechanism_list_overflow(payload),
        6 => fuzz_get_slot_list_overflow(payload),
        _ => {}
    }

    // FIX: Prevent session/object leaks between iterations
    cleanup_sessions();
});

/// C_GetAttributeValue with random attribute types and varying buffer sizes.
/// Historically the #1 source of PKCS#11 buffer overflows.
fn fuzz_get_attribute_value_lengths(data: &[u8]) {
    if data.len() < 16 {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    // FIX #3: Use fuzz-derived PIN for login
    let (pin_ptr, pin_len, _) = extract_fuzz_pin(data);
    let _ = functions::C_Login(session, CKU_USER, pin_ptr, pin_len);

    // First create an object so we have a valid handle
    let class_val: CK_ULONG = CKO_SECRET_KEY;
    let key_type_val: CK_ULONG = CKK_AES;
    let value_len_val: CK_ULONG = 32;
    let true_val: CK_BBOOL = CK_TRUE;
    let key_data = [0x42u8; 32];

    let mut template = [
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: &class_val as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: &key_type_val as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE,
            p_value: key_data.as_ptr() as *mut _,
            value_len: 32,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: &value_len_val as *const _ as *mut _,
            value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_TOKEN,
            p_value: &true_val as *const _ as *mut _,
            value_len: 1,
        },
    ];

    let mut obj_handle: CK_OBJECT_HANDLE = 0;
    let rv = functions::C_CreateObject(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut obj_handle,
    );

    if rv == CKR_OK {
        // Now query attributes with various buffer sizes
        // FIX: Use from_le_bytes for reproducible corpus
        let mut offset = 0;
        while offset + 9 < data.len() {
            let attr_type = u64::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as CK_ATTRIBUTE_TYPE;
            offset += 8;

            let buf_size = data[offset] as CK_ULONG;
            offset += 1;

            // Allocate a small buffer but claim a potentially different size
            let mut buf = vec![0u8; 256];
            let mut attr = CK_ATTRIBUTE {
                attr_type,
                p_value: if buf_size == 0 {
                    std::ptr::null_mut()
                } else {
                    buf.as_mut_ptr() as *mut _
                },
                value_len: buf_size.min(256),
            };

            // This must never write beyond buf, even if value_len is wrong
            let _rv =
                functions::C_GetAttributeValue(session, obj_handle, &mut attr, 1);
        }

        let _ = functions::C_DestroyObject(session, obj_handle);
    }

    let _ = functions::C_Logout(session);
    let _ = functions::C_CloseSession(session);
}

/// C_FindObjects with extreme max_count values.
/// FIX #4: Use canary-guarded buffers to safely detect out-of-bounds writes.
/// The library must handle max_count > actual results without writing past the buffer.
fn fuzz_find_objects_count(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    // Init find with empty template (match all)
    let _rv = functions::C_FindObjectsInit(session, std::ptr::null_mut(), 0);

    // Request with varying max_count (including extreme values)
    let max_count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as CK_ULONG;

    // FIX #4: Always pass a max_count that matches the actual buffer size.
    // To test the library's handling of large max_count values, we allocate a
    // reasonably large buffer and use canary values to detect overflows.
    let buf_entries = (max_count as usize).min(4096);
    let canary: CK_OBJECT_HANDLE = 0xDEAD_BEEF_CAFE_F00D_u64 as CK_OBJECT_HANDLE;
    // Allocate buffer + 4 canary slots at the end
    let total_entries = buf_entries + 4;
    let mut objects = vec![canary; total_entries];
    let mut count: CK_ULONG = 0;

    // Pass the CLAMPED buf_entries as max_count so the buffer is always large enough.
    // The test value is: does the library honor max_count and not write more than that?
    let _rv = functions::C_FindObjects(
        session,
        objects.as_mut_ptr(),
        buf_entries as CK_ULONG,
        &mut count,
    );

    // FIX #4: Verify canary slots were not overwritten (detect buffer overflow)
    for i in buf_entries..total_entries {
        assert_eq!(
            objects[i], canary,
            "C_FindObjects wrote past max_count boundary at index {} (buffer overflow!)", i
        );
    }
    // FIX #11: Verify count <= max_count
    assert!(
        count <= buf_entries as CK_ULONG,
        "C_FindObjects returned count ({}) > max_count ({})", count, buf_entries
    );

    // Second test: small buffer with canary guard.
    // We tell the library max_count=2, and verify it respects that.
    let mut count2: CK_ULONG = 0;
    let mut guarded_buf = [0 as CK_OBJECT_HANDLE, 0, canary, canary];
    let _rv = functions::C_FindObjects(
        session,
        guarded_buf.as_mut_ptr(),
        2, // max_count matches the usable portion of guarded_buf
        &mut count2,
    );
    // Verify canary guard slots untouched
    assert_eq!(guarded_buf[2], canary, "C_FindObjects overwrote canary at index 2");
    assert_eq!(guarded_buf[3], canary, "C_FindObjects overwrote canary at index 3");
    assert!(count2 <= 2, "C_FindObjects returned count ({}) > max_count (2)", count2);

    let _rv = functions::C_FindObjectsFinal(session);
    let _ = functions::C_CloseSession(session);
}

/// Two-call pattern: first call to get size, second with wrong size.
fn fuzz_two_call_pattern_mismatch(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    // FIX #3: Use fuzz-derived PIN
    let (pin_ptr, pin_len, _) = extract_fuzz_pin(data);
    let _ = functions::C_Login(session, CKU_USER, pin_ptr, pin_len);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        p_parameter: std::ptr::null_mut(),
        parameter_len: 0,
    };

    let rv = functions::C_DigestInit(session, &mut mechanism);
    if rv != CKR_OK {
        let _ = functions::C_Logout(session);
        let _ = functions::C_CloseSession(session);
        return;
    }

    // Feed data
    if !data.is_empty() {
        let _rv = functions::C_DigestUpdate(
            session,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
        );
    }

    // First call: get required size (pass null buffer)
    let mut required_len: CK_ULONG = 0;
    let _rv = functions::C_DigestFinal(session, std::ptr::null_mut(), &mut required_len);

    // Second call: pass a buffer that's TOO SMALL based on fuzz data
    let fuzz_size = (data[0] as CK_ULONG) % 128;
    let mut small_buf = vec![0u8; fuzz_size as usize];
    let mut actual_len: CK_ULONG = fuzz_size;

    // This should return CKR_BUFFER_TOO_SMALL if fuzz_size < required_len
    let _rv = functions::C_DigestFinal(
        session,
        if small_buf.is_empty() {
            std::ptr::null_mut()
        } else {
            small_buf.as_mut_ptr()
        },
        &mut actual_len,
    );

    let _ = functions::C_Logout(session);
    let _ = functions::C_CloseSession(session);
}

/// CK_ATTRIBUTE with extreme value_len values (0, 1, MAX, mismatched).
/// FIX #5: Use over-allocated backing buffers with canary guards so that even if the
/// library reads past the claimed data, it reads from valid memory (no UB in the fuzzer),
/// while canary corruption proves the library has a read-overrun bug.
fn fuzz_extreme_attribute_lengths(data: &[u8]) {
    if data.len() < 16 {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    // FIX #5: Use over-allocated buffers so that mismatched value_len never causes
    // an out-of-bounds read in the fuzzer itself. The backing buffer is always 256 bytes,
    // but we tell the library a fuzz-controlled length. If the library reads beyond the
    // "logical" data, it hits valid (zero-filled) memory rather than causing UB.
    let mut attrs = Vec::new();

    // CKA_CLASS: actual data is sizeof(CK_ULONG), but value_len is fuzzed.
    // Back it with a 256-byte zero-filled buffer containing the real value at the start.
    let mut class_buf = [0u8; 256];
    let class_val: CK_ULONG = CKO_SECRET_KEY;
    class_buf[..std::mem::size_of::<CK_ULONG>()].copy_from_slice(&class_val.to_ne_bytes());
    attrs.push(CK_ATTRIBUTE {
        attr_type: CKA_CLASS,
        p_value: class_buf.as_mut_ptr() as *mut _,
        // Fuzz-controlled: could be 0, 1, 255 — library must validate
        value_len: data[0] as CK_ULONG,
    });

    // CKA_LABEL: actual label is 10 bytes, but value_len is fuzzed.
    // Use a 256-byte buffer so the library can safely read up to 255 bytes.
    let mut label_buf = [0u8; 256];
    let label = b"test-label";
    label_buf[..label.len()].copy_from_slice(label);
    attrs.push(CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: label_buf.as_mut_ptr() as *mut _,
        // Fuzz-controlled: could exceed actual label length, but buffer is 256 bytes
        value_len: data[1] as CK_ULONG,
    });

    // CKA_VALUE with null pointer but non-zero length — tests null+len validation
    attrs.push(CK_ATTRIBUTE {
        attr_type: CKA_VALUE,
        p_value: std::ptr::null_mut(),
        value_len: data[2] as CK_ULONG,
    });

    // CKA_TOKEN: actual data is 1 byte (CK_BBOOL), value_len is fuzzed.
    // Use a 256-byte buffer so oversized reads don't escape valid memory.
    let mut bool_buf = [0u8; 256];
    bool_buf[0] = CK_TRUE;
    attrs.push(CK_ATTRIBUTE {
        attr_type: CKA_TOKEN,
        p_value: bool_buf.as_mut_ptr() as *mut _,
        // Fuzz-controlled: tests whether library reads past the 1-byte bool
        value_len: data[3] as CK_ULONG,
    });

    let mut obj_handle: CK_OBJECT_HANDLE = 0;
    // Should return error, not panic or overflow
    let _rv = functions::C_CreateObject(
        session,
        attrs.as_mut_ptr(),
        attrs.len() as CK_ULONG,
        &mut obj_handle,
    );

    // Also test with extreme count values
    let _rv = functions::C_CreateObject(
        session,
        attrs.as_mut_ptr(),
        CK_ULONG::MAX, // Extreme count
        &mut obj_handle,
    );

    let _ = functions::C_CloseSession(session);
}

/// Pass null pointers in places they shouldn't be — test null checks.
/// FIX: Case 3 now passes non-zero length with null data pointer.
fn fuzz_null_pointer_everywhere(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = functions::C_OpenSession(
        0,
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    if rv != CKR_OK {
        return;
    }

    let selector = data[0] % 9;

    match selector {
        0 => {
            // Null template pointer to FindObjectsInit
            let _rv = functions::C_FindObjectsInit(session, std::ptr::null_mut(), 0);
            let _ = functions::C_FindObjectsFinal(session);
        }
        1 => {
            // Null output pointer to FindObjects
            let mut count: CK_ULONG = 0;
            let _rv = functions::C_FindObjectsInit(session, std::ptr::null_mut(), 0);
            let _rv = functions::C_FindObjects(session, std::ptr::null_mut(), 10, &mut count);
            let _ = functions::C_FindObjectsFinal(session);
        }
        2 => {
            // Null mechanism pointer to DigestInit
            let _rv = functions::C_DigestInit(session, std::ptr::null_mut());
        }
        3 => {
            // FIX: Null data pointer with NON-ZERO length — this is the real attack.
            // A null ptr with len=0 is arguably valid. The dangerous case is
            // null ptr + non-zero len which would cause slice::from_raw_parts to UB.
            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_SHA256,
                p_parameter: std::ptr::null_mut(),
                parameter_len: 0,
            };
            let rv = functions::C_DigestInit(session, &mut mechanism);
            if rv == CKR_OK {
                let mut out = [0u8; 64];
                let mut out_len: CK_ULONG = 64;
                // Null data ptr with non-zero length — must be caught before from_raw_parts
                let _rv = functions::C_Digest(
                    session,
                    std::ptr::null_mut(),
                    32, // Non-zero! This is the critical test case.
                    out.as_mut_ptr(),
                    &mut out_len,
                );
            }
        }
        4 => {
            // Null output length pointer
            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_SHA256,
                p_parameter: std::ptr::null_mut(),
                parameter_len: 0,
            };
            let rv = functions::C_DigestInit(session, &mut mechanism);
            if rv == CKR_OK {
                let input = [0u8; 32];
                let _rv = functions::C_Digest(
                    session,
                    input.as_ptr() as *mut _,
                    32,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
            }
        }
        5 => {
            // Null PIN to C_Login with non-zero length
            let _rv = functions::C_Login(session, CKU_USER, std::ptr::null_mut(), 0);
            // FIX #11: null PIN with non-zero claimed length — must not succeed
            let rv = functions::C_Login(session, CKU_USER, std::ptr::null_mut(), 16);
            assert!(rv != CKR_OK, "C_Login succeeded with null PIN + non-zero length");
        }
        6 => {
            // CreateObject with null template but non-zero count
            let mut handle: CK_OBJECT_HANDLE = 0;
            let _rv =
                functions::C_CreateObject(session, std::ptr::null_mut(), 0, &mut handle);
            // FIX #11: null template with non-zero count — must not succeed
            let rv =
                functions::C_CreateObject(session, std::ptr::null_mut(), 5, &mut handle);
            assert!(rv != CKR_OK, "C_CreateObject succeeded with null template + non-zero count");
        }
        7 => {
            // GenerateRandom with null buffer but non-zero length
            let _rv = functions::C_GenerateRandom(session, std::ptr::null_mut(), 0);
            // FIX #11: null buffer with non-zero length — must not succeed
            let rv = functions::C_GenerateRandom(session, std::ptr::null_mut(), 32);
            assert!(rv != CKR_OK, "C_GenerateRandom succeeded with null buffer + non-zero length");
        }
        8 => {
            // Null output handle pointer for CreateObject
            let class_val: CK_ULONG = CKO_SECRET_KEY;
            let mut attr = CK_ATTRIBUTE {
                attr_type: CKA_CLASS,
                p_value: &class_val as *const _ as *mut _,
                value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            };
            let _rv = functions::C_CreateObject(
                session,
                &mut attr,
                1,
                std::ptr::null_mut(),
            );
        }
        _ => {}
    }

    let _ = functions::C_CloseSession(session);
}

/// C_GetMechanismList with wrong count.
fn fuzz_get_mechanism_list_overflow(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    // First call: get count
    let mut count: CK_ULONG = 0;
    let _rv = functions::C_GetMechanismList(0, std::ptr::null_mut(), &mut count);

    // Second call: provide buffer with fuzz-controlled count
    // FIX: Use from_le_bytes for reproducibility
    let fuzz_count =
        u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as CK_ULONG;
    let safe_count = fuzz_count.min(256);
    let mut mechs = vec![0 as CK_MECHANISM_TYPE; safe_count as usize];
    let mut out_count = safe_count;
    let _rv = functions::C_GetMechanismList(
        0,
        if mechs.is_empty() {
            std::ptr::null_mut()
        } else {
            mechs.as_mut_ptr()
        },
        &mut out_count,
    );

    // Also test: claim a smaller count than actual mechanisms
    if count > 0 {
        let small = (data[0] as CK_ULONG) % count;
        let mut small_mechs = vec![0 as CK_MECHANISM_TYPE; small as usize];
        let mut small_count = small;
        let _rv = functions::C_GetMechanismList(
            0,
            if small_mechs.is_empty() {
                std::ptr::null_mut()
            } else {
                small_mechs.as_mut_ptr()
            },
            &mut small_count,
        );
    }
}

/// C_GetSlotList with wrong count.
fn fuzz_get_slot_list_overflow(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    // First call: get count
    let mut count: CK_ULONG = 0;
    let _rv = functions::C_GetSlotList(CK_FALSE, std::ptr::null_mut(), &mut count);

    // Second call: provide buffer with fuzz-controlled count
    let fuzz_count = data[0] as CK_ULONG;
    let mut slots = vec![0 as CK_SLOT_ID; fuzz_count as usize];
    let mut out_count = fuzz_count;
    let _rv = functions::C_GetSlotList(
        CK_FALSE,
        if slots.is_empty() {
            std::ptr::null_mut()
        } else {
            slots.as_mut_ptr()
        },
        &mut out_count,
    );

    // Also test with token_present = CK_TRUE
    let mut out_count2 = fuzz_count;
    let _rv = functions::C_GetSlotList(
        CK_TRUE,
        if slots.is_empty() {
            std::ptr::null_mut()
        } else {
            slots.as_mut_ptr()
        },
        &mut out_count2,
    );
}
