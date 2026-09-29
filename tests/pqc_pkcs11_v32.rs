// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// PKCS#11 v3.2 representation of post-quantum keys and mechanisms.
//
// Regression tests for OpenSSL pkcs11-provider, which imports an ML-DSA key
// by reading CKA_CLASS, CKA_KEY_TYPE (expecting CKK_ML_DSA), CKA_PARAMETER_SET
// and, for the public key, CKA_VALUE, and then signs with CKM_ML_DSA. Craton
// used vendor-defined key types and had no CKA_PARAMETER_SET, so the provider
// rejected the key ("Unsupported key type (2147483650)").
//
// Must run with --test-threads=1 due to global OnceLock state.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

mod common;

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

fn setup_user_session() -> CK_SESSION_HANDLE {
    let rv = C_Initialize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..7].copy_from_slice(b"PQCv3.2");
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
    let user_pin = b"userpin1";
    let rv = C_InitPIN(
        session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(C_Logout(session), CKR_OK);
    let rv = C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    session
}

/// Generate a key pair. `parameter_set`, if given, goes in the public key
/// template as CKA_PARAMETER_SET.
fn generate_keypair(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    parameter_set: Option<CK_ULONG>,
) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), CK_RV> {
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let ck_true: CK_BBOOL = CK_TRUE;
    let ps = parameter_set.map(ck_ulong_bytes);
    let mut pub_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_VERIFY,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: 1,
    }];
    if let Some(ps) = &ps {
        pub_template.push(CK_ATTRIBUTE {
            attr_type: CKA_PARAMETER_SET,
            p_value: ps.as_ptr() as CK_VOID_PTR,
            value_len: ps.len() as CK_ULONG,
        });
    }
    let mut priv_template = vec![CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &ck_true as *const _ as CK_VOID_PTR,
        value_len: 1,
    }];
    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKeyPair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        priv_template.as_mut_ptr(),
        priv_template.len() as CK_ULONG,
        &mut pub_key,
        &mut priv_key,
    );
    if rv != CKR_OK {
        return Err(rv);
    }
    Ok((pub_key, priv_key))
}

fn read_attribute(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    attr_type: CK_ATTRIBUTE_TYPE,
) -> Result<Vec<u8>, CK_RV> {
    let mut template = [CK_ATTRIBUTE {
        attr_type,
        p_value: ptr::null_mut(),
        value_len: 0,
    }];
    let rv = C_GetAttributeValue(session, object, template.as_mut_ptr(), 1);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut buf = vec![0u8; template[0].value_len as usize];
    template[0].p_value = buf.as_mut_ptr() as CK_VOID_PTR;
    let rv = C_GetAttributeValue(session, object, template.as_mut_ptr(), 1);
    if rv != CKR_OK {
        return Err(rv);
    }
    Ok(buf)
}

fn read_ulong(session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, attr: CK_ULONG) -> CK_ULONG {
    let bytes = read_attribute(session, object, attr).expect("attribute");
    CK_ULONG::from_ne_bytes(bytes.as_slice().try_into().unwrap())
}

fn sign(
    session: CK_SESSION_HANDLE,
    mechanism: &mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    let rv = C_SignInit(session, mechanism, key);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut sig = vec![0u8; 32768];
    let mut sig_len = sig.len() as CK_ULONG;
    let rv = C_Sign(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        sig.as_mut_ptr(),
        &mut sig_len,
    );
    if rv != CKR_OK {
        return Err(rv);
    }
    sig.truncate(sig_len as usize);
    Ok(sig)
}

fn verify(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
    signature: &[u8],
) -> CK_RV {
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let rv = C_VerifyInit(session, &mut mechanism, key);
    if rv != CKR_OK {
        return rv;
    }
    C_Verify(
        session,
        data.as_ptr() as CK_BYTE_PTR,
        data.len() as CK_ULONG,
        signature.as_ptr() as CK_BYTE_PTR,
        signature.len() as CK_ULONG,
    )
}

fn null_mechanism(mechanism: CK_MECHANISM_TYPE) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    }
}

fn find_objects(session: CK_SESSION_HANDLE, template: &[(CK_ULONG, Vec<u8>)]) -> Vec<CK_ULONG> {
    let mut attrs: Vec<CK_ATTRIBUTE> = template
        .iter()
        .map(|(t, v)| CK_ATTRIBUTE {
            attr_type: *t,
            p_value: v.as_ptr() as CK_VOID_PTR,
            value_len: v.len() as CK_ULONG,
        })
        .collect();
    assert_eq!(
        C_FindObjectsInit(session, attrs.as_mut_ptr(), attrs.len() as CK_ULONG),
        CKR_OK
    );
    let mut handles = [0 as CK_OBJECT_HANDLE; 64];
    let mut count: CK_ULONG = 0;
    assert_eq!(
        C_FindObjects(session, handles.as_mut_ptr(), 64, &mut count),
        CKR_OK
    );
    assert_eq!(C_FindObjectsFinal(session), CKR_OK);
    handles[..count as usize].to_vec()
}

#[test]
fn test_ml_dsa_87_pkcs11_provider_flow() {
    let session = setup_user_session();
    let (pub_key, priv_key) =
        generate_keypair(session, CKM_ML_DSA_KEY_PAIR_GEN, Some(CKP_ML_DSA_87)).unwrap();

    // p11prov_obj_from_handle(): CKA_CLASS, CKA_KEY_TYPE, CKA_COPYABLE,
    // CKA_TOKEN, CKA_PARAMETER_SET.
    for (key, class) in [(priv_key, CKO_PRIVATE_KEY), (pub_key, CKO_PUBLIC_KEY)] {
        assert_eq!(read_ulong(session, key, CKA_CLASS), class);
        assert_eq!(read_ulong(session, key, CKA_KEY_TYPE), CKK_ML_DSA);
        assert_eq!(CKK_ML_DSA, 0x4A);
        assert_eq!(read_ulong(session, key, CKA_PARAMETER_SET), CKP_ML_DSA_87);
        read_attribute(session, key, CKA_COPYABLE).unwrap();
        read_attribute(session, key, CKA_TOKEN).unwrap();
    }

    // fetch_mldsa_key(): the public key's CKA_VALUE is the FIPS 204 encoding.
    let public_key = read_attribute(session, pub_key, CKA_VALUE).unwrap();
    assert_eq!(public_key.len(), 2592);

    // Pure ML-DSA via CKM_ML_DSA with no parameter, as pkcs11-provider signs.
    let message = b"pkcs11-provider ML-DSA-87 interop";
    let mut mech = null_mechanism(CKM_ML_DSA);
    let signature = sign(session, &mut mech, priv_key, message).unwrap();
    assert_eq!(signature.len(), 4627);

    assert_eq!(
        verify(session, CKM_ML_DSA, pub_key, message, &signature),
        CKR_OK
    );
    // The vendor mechanism naming the same parameter set is equivalent.
    assert_eq!(
        verify(session, CKM_ML_DSA_87, pub_key, message, &signature),
        CKR_OK
    );

    // Independently verifiable from CKA_VALUE alone (what OpenSSL does once
    // it has exported the public key).
    use ml_dsa::signature::Verifier;
    let vk_enc: ml_dsa::EncodedVerifyingKey<ml_dsa::MlDsa87> =
        public_key.as_slice().try_into().unwrap();
    let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa87>::decode(&vk_enc);
    let sig = ml_dsa::Signature::<ml_dsa::MlDsa87>::try_from(signature.as_slice()).unwrap();
    assert!(vk.verify(message, &sig).is_ok());
}

#[test]
fn test_ml_dsa_find_by_standard_and_legacy_key_type() {
    let session = setup_user_session();
    let (pub_key, priv_key) =
        generate_keypair(session, CKM_ML_DSA_KEY_PAIR_GEN, Some(CKP_ML_DSA_44)).unwrap();

    let found = find_objects(session, &[(CKA_KEY_TYPE, ck_ulong_bytes(CKK_ML_DSA))]);
    assert!(found.contains(&pub_key) && found.contains(&priv_key));

    // Templates written against the old vendor-defined value still match.
    let found = find_objects(
        session,
        &[(CKA_KEY_TYPE, ck_ulong_bytes(CKK_VENDOR_ML_DSA_LEGACY))],
    );
    assert!(found.contains(&pub_key) && found.contains(&priv_key));

    let found = find_objects(
        session,
        &[
            (CKA_CLASS, ck_ulong_bytes(CKO_PUBLIC_KEY)),
            (CKA_PARAMETER_SET, ck_ulong_bytes(CKP_ML_DSA_44)),
        ],
    );
    assert_eq!(found, vec![pub_key]);
    let found = find_objects(
        session,
        &[(CKA_PARAMETER_SET, ck_ulong_bytes(CKP_ML_DSA_65))],
    );
    assert!(found.is_empty());
}

#[test]
fn test_vendor_mechanism_keys_expose_v32_attributes() {
    let session = setup_user_session();
    let (pub_key, priv_key) = generate_keypair(session, CKM_ML_DSA_65, None).unwrap();
    assert_eq!(read_ulong(session, priv_key, CKA_KEY_TYPE), CKK_ML_DSA);
    assert_eq!(
        read_ulong(session, priv_key, CKA_PARAMETER_SET),
        CKP_ML_DSA_65
    );

    // And they sign with the parameter-set-agnostic mechanism.
    let mut mech = null_mechanism(CKM_ML_DSA);
    let signature = sign(session, &mut mech, priv_key, b"legacy key").unwrap();
    assert_eq!(signature.len(), 3309);
    assert_eq!(
        verify(session, CKM_ML_DSA_65, pub_key, b"legacy key", &signature),
        CKR_OK
    );

    let (_, kem_priv) = generate_keypair(session, CKM_ML_KEM_768, None).unwrap();
    assert_eq!(read_ulong(session, kem_priv, CKA_KEY_TYPE), CKK_ML_KEM);
    assert_eq!(
        read_ulong(session, kem_priv, CKA_PARAMETER_SET),
        CKP_ML_KEM_768
    );
}

#[test]
fn test_ml_kem_and_slh_dsa_v32_keygen() {
    let session = setup_user_session();
    let (kem_pub, _) =
        generate_keypair(session, CKM_ML_KEM_KEY_PAIR_GEN, Some(CKP_ML_KEM_1024)).unwrap();
    assert_eq!(read_ulong(session, kem_pub, CKA_KEY_TYPE), CKK_ML_KEM);
    assert_eq!(
        read_ulong(session, kem_pub, CKA_PARAMETER_SET),
        CKP_ML_KEM_1024
    );
    assert_eq!(
        read_attribute(session, kem_pub, CKA_VALUE).unwrap().len(),
        1568
    );

    let (slh_pub, slh_priv) = generate_keypair(
        session,
        CKM_SLH_DSA_KEY_PAIR_GEN,
        Some(CKP_SLH_DSA_SHA2_128S),
    )
    .unwrap();
    assert_eq!(read_ulong(session, slh_priv, CKA_KEY_TYPE), CKK_SLH_DSA);
    assert_eq!(
        read_ulong(session, slh_priv, CKA_PARAMETER_SET),
        CKP_SLH_DSA_SHA2_128S
    );
    let mut mech = null_mechanism(CKM_SLH_DSA);
    let signature = sign(session, &mut mech, slh_priv, b"slh-dsa").unwrap();
    assert_eq!(
        verify(session, CKM_SLH_DSA, slh_pub, b"slh-dsa", &signature),
        CKR_OK
    );
}

#[test]
fn test_v32_keygen_parameter_set_errors() {
    let session = setup_user_session();
    assert_eq!(
        generate_keypair(session, CKM_ML_DSA_KEY_PAIR_GEN, None),
        Err(CKR_TEMPLATE_INCOMPLETE)
    );
    assert_eq!(
        generate_keypair(session, CKM_ML_DSA_KEY_PAIR_GEN, Some(7)),
        Err(CKR_ATTRIBUTE_VALUE_INVALID)
    );
    // SHAKE parameter sets are not implemented.
    assert_eq!(
        generate_keypair(session, CKM_SLH_DSA_KEY_PAIR_GEN, Some(2)),
        Err(CKR_ATTRIBUTE_VALUE_INVALID)
    );
}

#[test]
fn test_ml_dsa_sign_additional_context() {
    let session = setup_user_session();
    let (_, priv_key) =
        generate_keypair(session, CKM_ML_DSA_KEY_PAIR_GEN, Some(CKP_ML_DSA_44)).unwrap();

    let sign_init = |ctx: &mut CK_SIGN_ADDITIONAL_CONTEXT| {
        let mut mech = CK_MECHANISM {
            mechanism: CKM_ML_DSA,
            p_parameter: ctx as *mut _ as CK_VOID_PTR,
            parameter_len: std::mem::size_of::<CK_SIGN_ADDITIONAL_CONTEXT>() as CK_ULONG,
        };
        C_SignInit(session, &mut mech, priv_key)
    };

    let mut ctx = CK_SIGN_ADDITIONAL_CONTEXT {
        hedge_variant: CKH_DETERMINISTIC_REQUIRED,
        p_context: ptr::null_mut(),
        context_len: 0,
    };
    assert_eq!(sign_init(&mut ctx), CKR_OK);
    let mut sig = vec![0u8; 4096];
    let mut sig_len = sig.len() as CK_ULONG;
    let msg = b"msg";
    let rv = C_Sign(
        session,
        msg.as_ptr() as CK_BYTE_PTR,
        msg.len() as CK_ULONG,
        sig.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(sig_len, 2420);

    // Hedged signing and context strings are not supported: refuse rather
    // than silently produce a different signature.
    let mut ctx = CK_SIGN_ADDITIONAL_CONTEXT {
        hedge_variant: CKH_HEDGE_REQUIRED,
        p_context: ptr::null_mut(),
        context_len: 0,
    };
    assert_eq!(sign_init(&mut ctx), CKR_MECHANISM_PARAM_INVALID);
    let context = *b"app";
    let mut ctx = CK_SIGN_ADDITIONAL_CONTEXT {
        hedge_variant: CKH_HEDGE_PREFERRED,
        p_context: context.as_ptr() as CK_BYTE_PTR,
        context_len: context.len() as CK_ULONG,
    };
    assert_eq!(sign_init(&mut ctx), CKR_MECHANISM_PARAM_INVALID);
}

#[test]
fn test_ml_dsa_mechanism_rejects_other_key_types() {
    let session = setup_user_session();
    let (_, slh_priv) = generate_keypair(session, CKM_SLH_DSA_SHA2_128S, None).unwrap();
    let mut mech = null_mechanism(CKM_ML_DSA);
    assert_eq!(
        C_SignInit(session, &mut mech, slh_priv),
        CKR_KEY_TYPE_INCONSISTENT
    );
}

#[test]
fn test_v32_mechanisms_advertised() {
    let _session = setup_user_session();
    let mut count: CK_ULONG = 0;
    assert_eq!(C_GetMechanismList(0, ptr::null_mut(), &mut count), CKR_OK);
    let mut list = vec![0 as CK_MECHANISM_TYPE; count as usize];
    assert_eq!(C_GetMechanismList(0, list.as_mut_ptr(), &mut count), CKR_OK);
    for mech in [
        CKM_ML_DSA_KEY_PAIR_GEN,
        CKM_ML_DSA,
        CKM_ML_KEM_KEY_PAIR_GEN,
        CKM_SLH_DSA_KEY_PAIR_GEN,
        CKM_SLH_DSA,
    ] {
        assert!(list.contains(&mech), "mechanism 0x{mech:X} not listed");
        let mut info = CK_MECHANISM_INFO {
            min_key_size: 0,
            max_key_size: 0,
            flags: 0,
        };
        assert_eq!(C_GetMechanismInfo(0, mech, &mut info), CKR_OK);
    }
}

#[test]
fn test_function_list_reports_v2_40_layout() {
    let mut list: *mut CK_FUNCTION_LIST = ptr::null_mut();
    assert_eq!(C_GetFunctionList(&mut list), CKR_OK);
    // The table has the v2.40 layout; reporting 3.x would make callers read
    // C_GetInterface past its end.
    let version = unsafe { (*list).version };
    assert_eq!((version.major, version.minor), (2, 40));
}
