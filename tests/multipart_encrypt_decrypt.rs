// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Multi-part encrypt/decrypt integration tests — exercises C_EncryptUpdate/C_EncryptFinal
// and C_DecryptUpdate/C_DecryptFinal via the C ABI layer.
//
// Tests cover:
// - AES-CBC-PAD: multi-part encrypt + single-shot decrypt (and vice versa)
// - AES-CTR: multi-part encrypt + single-shot decrypt (and vice versa)
// - AES-GCM: multi-part correctly returns CKR_MECHANISM_INVALID
// - Cross-validation: multi-part result == single-shot result
// - Edge cases: empty data, exact block size, large data
//
// Must run with --test-threads=1 due to global OnceLock state.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

/// Initialize PKCS#11, open an RW session, and log in as user.
fn setup_session() -> CK_SESSION_HANDLE {
    let rv = C_Initialize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..9].copy_from_slice(b"TestToken");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK);

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(rv, CKR_OK);

    let rv = C_Login(
        session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    let user_pin = b"userpin1234";
    let rv = C_InitPIN(
        session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    let rv = C_Logout(session);
    assert_eq!(rv, CKR_OK);
    let rv = C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    session
}

/// Generate an AES-256 key. Returns the key handle.
fn generate_aes_key(session: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let key_len = ck_ulong_bytes(32); // AES-256
    let encrypt_true: CK_BBOOL = CK_TRUE;
    let decrypt_true: CK_BBOOL = CK_TRUE;
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type = ck_ulong_bytes(CKK_AES);

    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class.as_ptr() as CK_VOID_PTR,
            value_len: class.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: key_type.as_ptr() as CK_VOID_PTR,
            value_len: key_type.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: key_len.as_ptr() as CK_VOID_PTR,
            value_len: key_len.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &encrypt_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &decrypt_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];

    let mut key_handle: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key_handle,
    );
    assert_eq!(rv, CKR_OK);
    key_handle
}

/// Single-shot encrypt
fn single_shot_encrypt(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    key: CK_OBJECT_HANDLE,
    iv: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let iv_copy = iv.to_vec();
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: if iv_copy.is_empty() {
            ptr::null_mut()
        } else {
            iv_copy.as_ptr() as CK_VOID_PTR
        },
        parameter_len: iv_copy.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK, "C_EncryptInit failed");

    let mut out_buf = vec![0u8; data.len() + 32]; // Extra for padding/nonce
    let mut out_len: CK_ULONG = out_buf.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        out_buf.as_mut_ptr(),
        &mut out_len,
    );
    assert_eq!(rv, CKR_OK, "C_Encrypt failed");
    out_buf.truncate(out_len as usize);
    out_buf
}

/// Single-shot decrypt
fn single_shot_decrypt(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    key: CK_OBJECT_HANDLE,
    iv: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let iv_copy = iv.to_vec();
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: if iv_copy.is_empty() {
            ptr::null_mut()
        } else {
            iv_copy.as_ptr() as CK_VOID_PTR
        },
        parameter_len: iv_copy.len() as CK_ULONG,
    };
    let rv = C_DecryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK, "C_DecryptInit failed");

    let mut out_buf = vec![0u8; ciphertext.len() + 32];
    let mut out_len: CK_ULONG = out_buf.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        ciphertext.as_ptr() as CK_BYTE_PTR,
        ciphertext.len() as CK_ULONG,
        out_buf.as_mut_ptr(),
        &mut out_len,
    );
    assert_eq!(rv, CKR_OK, "C_Decrypt failed");
    out_buf.truncate(out_len as usize);
    out_buf
}

/// Multi-part encrypt: C_EncryptInit + C_EncryptUpdate*N + C_EncryptFinal
fn multi_part_encrypt(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    key: CK_OBJECT_HANDLE,
    iv: &[u8],
    chunks: &[&[u8]],
) -> Vec<u8> {
    let iv_copy = iv.to_vec();
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: if iv_copy.is_empty() {
            ptr::null_mut()
        } else {
            iv_copy.as_ptr() as CK_VOID_PTR
        },
        parameter_len: iv_copy.len() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK, "C_EncryptInit failed for multi-part");

    for chunk in chunks {
        let mut out_len: CK_ULONG = 0;
        let rv = C_EncryptUpdate(
            session,
            chunk.as_ptr() as CK_BYTE_PTR,
            chunk.len() as CK_ULONG,
            ptr::null_mut(), // accumulation mode: no output from Update
            &mut out_len,
        );
        assert_eq!(rv, CKR_OK, "C_EncryptUpdate failed");
        assert_eq!(
            out_len, 0,
            "EncryptUpdate should output 0 bytes in accumulation mode"
        );
    }

    // Calculate total data length for buffer allocation
    let total_len: usize = chunks.iter().map(|c| c.len()).sum();
    let mut out_buf = vec![0u8; total_len + 32]; // Extra for padding
    let mut out_len: CK_ULONG = out_buf.len() as CK_ULONG;
    let rv = C_EncryptFinal(session, out_buf.as_mut_ptr(), &mut out_len);
    assert_eq!(rv, CKR_OK, "C_EncryptFinal failed");
    out_buf.truncate(out_len as usize);
    out_buf
}

/// Multi-part decrypt: C_DecryptInit + C_DecryptUpdate*N + C_DecryptFinal
fn multi_part_decrypt(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    key: CK_OBJECT_HANDLE,
    iv: &[u8],
    chunks: &[&[u8]],
) -> Vec<u8> {
    let iv_copy = iv.to_vec();
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: if iv_copy.is_empty() {
            ptr::null_mut()
        } else {
            iv_copy.as_ptr() as CK_VOID_PTR
        },
        parameter_len: iv_copy.len() as CK_ULONG,
    };
    let rv = C_DecryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_OK, "C_DecryptInit failed for multi-part");

    for chunk in chunks {
        let mut out_len: CK_ULONG = 0;
        let rv = C_DecryptUpdate(
            session,
            chunk.as_ptr() as CK_BYTE_PTR,
            chunk.len() as CK_ULONG,
            ptr::null_mut(),
            &mut out_len,
        );
        assert_eq!(rv, CKR_OK, "C_DecryptUpdate failed");
        assert_eq!(
            out_len, 0,
            "DecryptUpdate should output 0 bytes in accumulation mode"
        );
    }

    let total_len: usize = chunks.iter().map(|c| c.len()).sum();
    let mut out_buf = vec![0u8; total_len + 32];
    let mut out_len: CK_ULONG = out_buf.len() as CK_ULONG;
    let rv = C_DecryptFinal(session, out_buf.as_mut_ptr(), &mut out_len);
    assert_eq!(rv, CKR_OK, "C_DecryptFinal failed");
    out_buf.truncate(out_len as usize);
    out_buf
}

#[test]
fn test_multipart_encrypt_decrypt() {
    let session = setup_session();
    let aes_key = generate_aes_key(session);

    let iv: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    let plaintext = b"The quick brown fox jumps over the lazy dog. This is test data for multi-part encryption.";
    let chunk1 = &plaintext[..20];
    let chunk2 = &plaintext[20..50];
    let chunk3 = &plaintext[50..];
    let chunks: Vec<&[u8]> = vec![chunk1, chunk2, chunk3];

    // ========================================================================
    // 1. AES-CBC-PAD: multi-part encrypt → single-shot decrypt
    // ========================================================================
    println!("Test 1: AES-CBC-PAD multi-part encrypt → single-shot decrypt");
    let ciphertext = multi_part_encrypt(session, CKM_AES_CBC_PAD, aes_key, &iv, &chunks);
    assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
    let decrypted = single_shot_decrypt(session, CKM_AES_CBC_PAD, aes_key, &iv, &ciphertext);
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "CBC-PAD: decrypted != original"
    );

    // ========================================================================
    // 2. AES-CBC-PAD: single-shot encrypt → multi-part decrypt
    // ========================================================================
    println!("Test 2: AES-CBC-PAD single-shot encrypt → multi-part decrypt");
    let ciphertext = single_shot_encrypt(session, CKM_AES_CBC_PAD, aes_key, &iv, plaintext);
    let ct_chunk1 = &ciphertext[..16];
    let ct_chunk2 = &ciphertext[16..];
    let ct_chunks: Vec<&[u8]> = vec![ct_chunk1, ct_chunk2];
    let decrypted = multi_part_decrypt(session, CKM_AES_CBC_PAD, aes_key, &iv, &ct_chunks);
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "CBC-PAD: multi-part decrypt != original"
    );

    // ========================================================================
    // 3. AES-CBC-PAD: cross-validation (multi-part == single-shot)
    // ========================================================================
    println!("Test 3: AES-CBC-PAD cross-validation");
    let ct_single = single_shot_encrypt(session, CKM_AES_CBC_PAD, aes_key, &iv, plaintext);
    let ct_multi = multi_part_encrypt(session, CKM_AES_CBC_PAD, aes_key, &iv, &chunks);
    assert_eq!(
        ct_single, ct_multi,
        "CBC-PAD: single-shot and multi-part ciphertexts should be identical"
    );

    // ========================================================================
    // 4. AES-CTR: multi-part encrypt → single-shot decrypt
    // ========================================================================
    println!("Test 4: AES-CTR multi-part encrypt → single-shot decrypt");
    let ciphertext = multi_part_encrypt(session, CKM_AES_CTR, aes_key, &iv, &chunks);
    assert_eq!(
        ciphertext.len(),
        plaintext.len(),
        "CTR ciphertext should be same length"
    );
    let decrypted = single_shot_decrypt(session, CKM_AES_CTR, aes_key, &iv, &ciphertext);
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "CTR: decrypted != original"
    );

    // ========================================================================
    // 5. AES-CTR: single-shot encrypt → multi-part decrypt
    // ========================================================================
    println!("Test 5: AES-CTR single-shot encrypt → multi-part decrypt");
    let ciphertext = single_shot_encrypt(session, CKM_AES_CTR, aes_key, &iv, plaintext);
    let ct_chunks: Vec<&[u8]> = vec![&ciphertext[..30], &ciphertext[30..]];
    let decrypted = multi_part_decrypt(session, CKM_AES_CTR, aes_key, &iv, &ct_chunks);
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "CTR: multi-part decrypt != original"
    );

    // ========================================================================
    // 6. AES-CTR: cross-validation
    // ========================================================================
    println!("Test 6: AES-CTR cross-validation");
    let ct_single = single_shot_encrypt(session, CKM_AES_CTR, aes_key, &iv, plaintext);
    let ct_multi = multi_part_encrypt(session, CKM_AES_CTR, aes_key, &iv, &chunks);
    assert_eq!(
        ct_single, ct_multi,
        "CTR: single-shot and multi-part should be identical"
    );

    // ========================================================================
    // 7. AES-GCM: multi-part should return CKR_MECHANISM_INVALID
    // ========================================================================
    println!("Test 7: AES-GCM multi-part should fail");
    {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            p_parameter: ptr::null_mut(),
            parameter_len: 0,
        };
        let rv = C_EncryptInit(session, &mut mechanism, aes_key);
        assert_eq!(rv, CKR_OK, "GCM EncryptInit should succeed");

        let mut out_len: CK_ULONG = 0;
        let rv = C_EncryptUpdate(
            session,
            plaintext.as_ptr() as CK_BYTE_PTR,
            plaintext.len() as CK_ULONG,
            ptr::null_mut(),
            &mut out_len,
        );
        assert_eq!(
            rv, CKR_MECHANISM_INVALID,
            "GCM EncryptUpdate should return MECHANISM_INVALID"
        );
    }

    // ========================================================================
    // 8. AES-GCM decrypt multi-part should also fail
    // ========================================================================
    println!("Test 8: AES-GCM decrypt multi-part should fail");
    {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            p_parameter: ptr::null_mut(),
            parameter_len: 0,
        };
        let rv = C_DecryptInit(session, &mut mechanism, aes_key);
        assert_eq!(rv, CKR_OK, "GCM DecryptInit should succeed");

        let dummy = [0u8; 32];
        let mut out_len: CK_ULONG = 0;
        let rv = C_DecryptUpdate(
            session,
            dummy.as_ptr() as CK_BYTE_PTR,
            dummy.len() as CK_ULONG,
            ptr::null_mut(),
            &mut out_len,
        );
        assert_eq!(
            rv, CKR_MECHANISM_INVALID,
            "GCM DecryptUpdate should return MECHANISM_INVALID"
        );
    }

    // ========================================================================
    // 9. Edge case: exact block-size data (48 bytes = 3 blocks)
    // ========================================================================
    println!("Test 9: AES-CBC-PAD exact block-size data");
    let block_data = [0xABu8; 48]; // 3 * 16 = exact block alignment
    let bd_chunks: Vec<&[u8]> = vec![&block_data[..16], &block_data[16..32], &block_data[32..]];
    let ct = multi_part_encrypt(session, CKM_AES_CBC_PAD, aes_key, &iv, &bd_chunks);
    // CBC-PAD adds a full padding block when input is block-aligned → 64 bytes
    assert_eq!(
        ct.len(),
        64,
        "CBC-PAD of 48 bytes should produce 64 bytes (extra padding block)"
    );
    let dec = single_shot_decrypt(session, CKM_AES_CBC_PAD, aes_key, &iv, &ct);
    assert_eq!(dec.as_slice(), block_data.as_slice());

    // ========================================================================
    // 10. Edge case: empty data
    // ========================================================================
    println!("Test 10: AES-CBC-PAD empty data");
    let empty_chunks: Vec<&[u8]> = vec![b""];
    let ct = multi_part_encrypt(session, CKM_AES_CBC_PAD, aes_key, &iv, &empty_chunks);
    // CBC-PAD of empty data → one block of padding (16 bytes)
    assert_eq!(
        ct.len(),
        16,
        "CBC-PAD of empty data should produce 16 bytes"
    );
    let dec = single_shot_decrypt(session, CKM_AES_CBC_PAD, aes_key, &iv, &ct);
    assert!(dec.is_empty(), "Decrypted empty data should be empty");

    // ========================================================================
    // 11. Large data: 64KB in 4KB chunks with AES-CBC-PAD
    // ========================================================================
    println!("Test 11: AES-CBC-PAD large data (64KB in 4KB chunks)");
    let large_data: Vec<u8> = (0..65536u32).map(|i| (i % 256) as u8).collect();
    let large_chunks: Vec<&[u8]> = large_data.chunks(4096).collect();
    let ct = multi_part_encrypt(session, CKM_AES_CBC_PAD, aes_key, &iv, &large_chunks);
    let dec = single_shot_decrypt(session, CKM_AES_CBC_PAD, aes_key, &iv, &ct);
    assert_eq!(dec, large_data, "Large data CBC-PAD roundtrip failed");

    // ========================================================================
    // 12. Large data with AES-CTR
    // ========================================================================
    println!("Test 12: AES-CTR large data (64KB in 4KB chunks)");
    let ct = multi_part_encrypt(session, CKM_AES_CTR, aes_key, &iv, &large_chunks);
    assert_eq!(
        ct.len(),
        large_data.len(),
        "CTR ciphertext length should match"
    );
    let dec = single_shot_decrypt(session, CKM_AES_CTR, aes_key, &iv, &ct);
    assert_eq!(dec, large_data, "Large data CTR roundtrip failed");

    // ========================================================================
    // 13. Error: C_EncryptUpdate without C_EncryptInit
    // ========================================================================
    println!("Test 13: C_EncryptUpdate without Init");
    let mut out_len: CK_ULONG = 0;
    let rv = C_EncryptUpdate(
        session,
        plaintext.as_ptr() as CK_BYTE_PTR,
        plaintext.len() as CK_ULONG,
        ptr::null_mut(),
        &mut out_len,
    );
    assert_eq!(rv, CKR_OPERATION_NOT_INITIALIZED);

    // ========================================================================
    // 14. Error: C_DecryptUpdate without C_DecryptInit
    // ========================================================================
    println!("Test 14: C_DecryptUpdate without Init");
    let rv = C_DecryptUpdate(
        session,
        plaintext.as_ptr() as CK_BYTE_PTR,
        plaintext.len() as CK_ULONG,
        ptr::null_mut(),
        &mut out_len,
    );
    assert_eq!(rv, CKR_OPERATION_NOT_INITIALIZED);

    // ========================================================================
    // 15. Non-aligned data with AES-CBC-PAD (17 bytes, not block-aligned)
    // ========================================================================
    println!("Test 15: AES-CBC-PAD non-aligned data (17 bytes)");
    let odd_data = [0x42u8; 17];
    let odd_chunks: Vec<&[u8]> = vec![&odd_data[..5], &odd_data[5..12], &odd_data[12..]];
    let ct = multi_part_encrypt(session, CKM_AES_CBC_PAD, aes_key, &iv, &odd_chunks);
    assert_eq!(ct.len(), 32, "CBC-PAD of 17 bytes should be 32 bytes");
    let dec = single_shot_decrypt(session, CKM_AES_CBC_PAD, aes_key, &iv, &ct);
    assert_eq!(dec.as_slice(), odd_data.as_slice());

    // Cleanup
    let rv = C_Logout(session);
    assert!(rv == CKR_OK || rv == CKR_USER_NOT_LOGGED_IN);
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);

    println!("All 15 multi-part encrypt/decrypt tests passed!");
}
