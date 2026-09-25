// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use p256::ecdh::diffie_hellman as p256_dh;
use p256::PublicKey as P256PublicKey;
use p256::SecretKey as P256SecretKey;
use p384::ecdh::diffie_hellman as p384_dh;
use p384::PublicKey as P384PublicKey;
use p384::SecretKey as P384SecretKey;
use zeroize::Zeroizing;

use crate::config::config::AlgorithmConfig;
use crate::crypto::backend::CryptoBackend;
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::{CK_ATTRIBUTE_TYPE, CK_EC_KDF_TYPE, CK_KEY_TYPE};
use crate::store::attributes::read_ck_ulong;
use crate::store::key_material::RawKeyMaterial;

/// Maximum HKDF-SHA256 output length (255 * 32 = 8160 bytes per RFC 5869).
/// We cap at a practical limit well below this.
const MAX_OKM_LEN: usize = 64;

/// ECDH key derivation for P-256.
///
/// `okm_len` specifies the desired derived key length in bytes. If `None`,
/// defaults to 32 (matching P-256's security level). Common values:
/// - 16 for AES-128
/// - 24 for AES-192
/// - 32 for AES-256
pub fn ecdh_p256(
    private_key_bytes: &[u8],
    peer_public_key_sec1: &[u8],
    okm_len: Option<usize>,
) -> HsmResult<RawKeyMaterial> {
    let derived_len = okm_len.unwrap_or(32);
    validate_okm_len(derived_len)?;

    let secret_key =
        P256SecretKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let peer_public =
        P256PublicKey::from_sec1_bytes(peer_public_key_sec1).map_err(|_| HsmError::ArgumentsBad)?;

    let shared_secret = p256_dh(secret_key.to_nonzero_scalar(), peer_public.as_affine());

    // Copy raw bytes into a Zeroizing wrapper so the shared secret is scrubbed
    // from memory promptly after HKDF extraction, regardless of compiler optimizations.
    let raw_bytes = Zeroizing::new(shared_secret.raw_secret_bytes().to_vec());

    // Build context-enriched HKDF info for domain separation (SP 800-56C §4.1).
    //
    // Uses the P-256 OID (1.2.840.10045.3.1.7) as the algorithm identifier per
    // NIST SP 800-56C Rev 2 §4.1, which recommends OID-based identifiers for
    // interoperability. The info string also includes output length and both
    // public keys so that:
    //  - Different curves produce different keys (OID)
    //  - Different requested lengths produce different keys (okm_len)
    //  - Different key pairs between the same parties produce different keys (public keys)
    //
    // NOTE: Changing this info string is a BREAKING CHANGE — existing derived
    // keys will not reproduce. Version the salt (HKDF_SALT) if migration is needed.
    let our_public = secret_key.public_key();
    let our_pk_bytes = elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&our_public, false);
    // OID 1.2.840.10045.3.1.7 (P-256 / prime256v1) DER-encoded
    const P256_OID: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let mut info =
        Vec::with_capacity(P256_OID.len() + 4 + our_pk_bytes.len() + peer_public_key_sec1.len());
    info.extend_from_slice(P256_OID);
    info.extend_from_slice(&(derived_len as u32).to_be_bytes());
    info.extend_from_slice(our_pk_bytes.as_bytes());
    info.extend_from_slice(peer_public_key_sec1);

    // Apply HKDF-SHA256 per NIST SP 800-56C — raw shared secret must not be used directly
    let okm = apply_hkdf(&raw_bytes, &info, derived_len)?;
    Ok(RawKeyMaterial::new(okm))
}

/// ECDH key derivation for P-384.
///
/// `okm_len` specifies the desired derived key length in bytes. If `None`,
/// defaults to 48 (matching P-384's security level). Common values:
/// - 16 for AES-128
/// - 24 for AES-192
/// - 32 for AES-256
/// - 48 for full P-384 shared secret length
pub fn ecdh_p384(
    private_key_bytes: &[u8],
    peer_public_key_sec1: &[u8],
    okm_len: Option<usize>,
) -> HsmResult<RawKeyMaterial> {
    let derived_len = okm_len.unwrap_or(48);
    validate_okm_len(derived_len)?;

    let secret_key =
        P384SecretKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let peer_public =
        P384PublicKey::from_sec1_bytes(peer_public_key_sec1).map_err(|_| HsmError::ArgumentsBad)?;

    let shared_secret = p384_dh(secret_key.to_nonzero_scalar(), peer_public.as_affine());

    // Copy raw bytes into a Zeroizing wrapper so the shared secret is scrubbed
    // from memory promptly after HKDF extraction.
    let raw_bytes = Zeroizing::new(shared_secret.raw_secret_bytes().to_vec());

    // Build context-enriched HKDF info for domain separation (SP 800-56C §4.1).
    // Uses the P-384 OID (1.3.132.0.34) as the algorithm identifier per NIST
    // SP 800-56C Rev 2 §4.1 for interoperability.
    let our_public = secret_key.public_key();
    let our_pk_bytes = elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&our_public, false);
    // OID 1.3.132.0.34 (P-384 / secp384r1) DER-encoded
    const P384_OID: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
    let mut info =
        Vec::with_capacity(P384_OID.len() + 4 + our_pk_bytes.len() + peer_public_key_sec1.len());
    info.extend_from_slice(P384_OID);
    info.extend_from_slice(&(derived_len as u32).to_be_bytes());
    info.extend_from_slice(our_pk_bytes.as_bytes());
    info.extend_from_slice(peer_public_key_sec1);

    // Apply HKDF-SHA256 per NIST SP 800-56C — raw shared secret must not be used directly
    let okm = apply_hkdf(&raw_bytes, &info, derived_len)?;
    Ok(RawKeyMaterial::new(okm))
}

/// Raw ECDH shared secret `Z` for P-256 (32 bytes), with no KDF applied.
pub fn ecdh_p256_shared_secret(
    private_key_bytes: &[u8],
    peer_public_key_sec1: &[u8],
) -> HsmResult<RawKeyMaterial> {
    let secret_key =
        P256SecretKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let peer_public =
        P256PublicKey::from_sec1_bytes(peer_public_key_sec1).map_err(|_| HsmError::ArgumentsBad)?;
    let shared_secret = p256_dh(secret_key.to_nonzero_scalar(), peer_public.as_affine());
    Ok(RawKeyMaterial::new(
        shared_secret.raw_secret_bytes().to_vec(),
    ))
}

/// Raw ECDH shared secret `Z` for P-384 (48 bytes), with no KDF applied.
pub fn ecdh_p384_shared_secret(
    private_key_bytes: &[u8],
    peer_public_key_sec1: &[u8],
) -> HsmResult<RawKeyMaterial> {
    let secret_key =
        P384SecretKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let peer_public =
        P384PublicKey::from_sec1_bytes(peer_public_key_sec1).map_err(|_| HsmError::ArgumentsBad)?;
    let shared_secret = p384_dh(secret_key.to_nonzero_scalar(), peer_public.as_affine());
    Ok(RawKeyMaterial::new(
        shared_secret.raw_secret_bytes().to_vec(),
    ))
}

/// Apply a PKCS#11 EC KDF (`CK_ECDH1_DERIVE_PARAMS.kdf`) to the raw ECDH
/// shared secret `z`.
///
/// - `CKD_NULL`: the key is `z` itself, truncated to `key_len` by keeping
///   the rightmost bytes (as SoftHSM does). Refused in FIPS-approved mode,
///   where SP 800-56C forbids using `Z` as a key directly.
/// - `CKD_SHA256_KDF` / `CKD_SHA384_KDF` / `CKD_SHA512_KDF`: the ANSI X9.63
///   KDF, `Hash(Z || counter || SharedInfo)` with a 32-bit big-endian
///   counter starting at 1.
///
/// `CKD_SHA1_KDF` is refused (SHA-1 is not offered for new key material),
/// as is `CKD_SHA224_KDF` (no SHA-224 digest is implemented).
pub fn apply_ec_kdf(
    backend: &dyn CryptoBackend,
    kdf: CK_EC_KDF_TYPE,
    z: &RawKeyMaterial,
    shared_data: &[u8],
    key_len: usize,
    fips_mode: bool,
) -> HsmResult<RawKeyMaterial> {
    if key_len == 0 {
        return Err(HsmError::KeySizeRange);
    }
    let hash_mech = match kdf {
        CKD_NULL => {
            if fips_mode {
                tracing::error!(
                    "ECDH with CKD_NULL is not permitted in FIPS-approved mode; use a SHA-2 KDF"
                );
                return Err(HsmError::MechanismParamInvalid);
            }
            if !shared_data.is_empty() {
                return Err(HsmError::MechanismParamInvalid);
            }
            let z = z.as_bytes();
            if key_len > z.len() {
                return Err(HsmError::KeySizeRange);
            }
            return Ok(RawKeyMaterial::new(z[z.len() - key_len..].to_vec()));
        }
        CKD_SHA256_KDF => CKM_SHA256,
        CKD_SHA384_KDF => CKM_SHA384,
        CKD_SHA512_KDF => CKM_SHA512,
        _ => return Err(HsmError::MechanismParamInvalid),
    };

    let mut okm = Zeroizing::new(Vec::with_capacity(key_len + 64));
    let mut counter: u32 = 1;
    while okm.len() < key_len {
        let mut input = Zeroizing::new(Vec::with_capacity(z.len() + 4 + shared_data.len()));
        input.extend_from_slice(z.as_bytes());
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(shared_data);
        let block = Zeroizing::new(backend.compute_digest(hash_mech, &input)?);
        okm.extend_from_slice(&block);
        counter += 1;
    }
    okm.truncate(key_len);
    Ok(RawKeyMaterial::new(std::mem::take(&mut *okm)))
}

/// Largest `CKK_GENERIC_SECRET` a derivation may produce, in bytes.
pub const MAX_DERIVED_GENERIC_SECRET_LEN: usize = 64;

/// Type, length and protection of a derived secret key, resolved from the
/// caller's derivation template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedKeyTemplate {
    /// `CKK_AES` or `CKK_GENERIC_SECRET`.
    pub key_type: CK_KEY_TYPE,
    /// `CKA_VALUE_LEN` in bytes, if the template gave one.
    pub value_len: Option<usize>,
    pub sensitive: bool,
    pub extractable: bool,
}

impl DerivedKeyTemplate {
    /// Resolve the derived-key attributes from a derivation template.
    ///
    /// - `CKA_KEY_TYPE` may be `CKK_AES` or `CKK_GENERIC_SECRET`; when absent
    ///   `default_key_type` is used.
    /// - `CKA_VALUE_LEN`, when present, must be 16/24/32 for AES and
    ///   1..=[`MAX_DERIVED_GENERIC_SECRET_LEN`] for a generic secret.
    /// - `CKA_SENSITIVE` / `CKA_EXTRACTABLE` are taken from the template as
    ///   PKCS#11 allows; the base key's sensitivity does not constrain them.
    ///   When unset they default per
    ///   [`AlgorithmConfig::derived_keys_default_extractable`].
    pub fn resolve(
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
        default_key_type: CK_KEY_TYPE,
        config: &AlgorithmConfig,
    ) -> HsmResult<Self> {
        let default_extractable = config.derived_keys_default_extractable();
        let mut resolved = Self {
            key_type: default_key_type,
            value_len: None,
            sensitive: !default_extractable,
            extractable: default_extractable,
        };
        for (attr_type, value) in template {
            match *attr_type {
                CKA_KEY_TYPE => {
                    resolved.key_type =
                        read_ck_ulong(value).ok_or(HsmError::AttributeValueInvalid)?;
                }
                CKA_VALUE_LEN => {
                    let len = read_ck_ulong(value).ok_or(HsmError::AttributeValueInvalid)?;
                    resolved.value_len =
                        Some(usize::try_from(len).map_err(|_| HsmError::KeySizeRange)?);
                }
                CKA_SENSITIVE => resolved.sensitive = parse_bbool(value)?,
                CKA_EXTRACTABLE => resolved.extractable = parse_bbool(value)?,
                _ => {}
            }
        }
        if !matches!(resolved.key_type, CKK_AES | CKK_GENERIC_SECRET) {
            return Err(HsmError::TemplateInconsistent);
        }
        if let Some(len) = resolved.value_len {
            resolved.check_len(len)?;
        }
        Ok(resolved)
    }

    /// Check a derived secret's length against the key type.
    pub fn check_len(&self, len: usize) -> HsmResult<()> {
        let ok = match self.key_type {
            CKK_AES => matches!(len, 16 | 24 | 32),
            _ => (1..=MAX_DERIVED_GENERIC_SECRET_LEN).contains(&len),
        };
        if ok {
            Ok(())
        } else {
            Err(HsmError::KeySizeRange)
        }
    }
}

fn parse_bbool(value: &[u8]) -> HsmResult<bool> {
    match value {
        [b] => Ok(*b != 0),
        _ => Err(HsmError::AttributeValueInvalid),
    }
}

/// Validate the requested output key material length.
fn validate_okm_len(len: usize) -> HsmResult<()> {
    if len == 0 || len > MAX_OKM_LEN {
        tracing::error!(
            "ECDH: requested OKM length {} is out of range (1..={})",
            len,
            MAX_OKM_LEN
        );
        return Err(HsmError::KeySizeRange);
    }
    Ok(())
}

/// Fixed salt for HKDF extraction per NIST SP 800-56C Rev 2.
/// Using a non-null salt improves extraction randomness compared to
/// the default all-zero salt. This value is a fixed public constant
/// and does not need to be secret.
const HKDF_SALT: &[u8] = b"CratonHSM-ECDH-HKDF-Salt-v1";

/// Apply HKDF-SHA256 to raw ECDH shared secret (NIST SP 800-56C).
/// Uses a fixed salt for extraction and a context-enriched info string
/// that includes the curve label, output key length, and public keys
/// of both parties for domain separation per NIST SP 800-56C Rev 2 §4.1.
/// `okm_len` specifies the output length.
fn apply_hkdf(ikm: &[u8], info: &[u8], okm_len: usize) -> HsmResult<Vec<u8>> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm);
    let mut okm = vec![0u8; okm_len];
    hk.expand(info, &mut okm).map_err(|e| {
        // Zeroize the output buffer on error before returning
        use zeroize::Zeroize;
        okm.zeroize();
        tracing::error!("HKDF expand failed: {}", e);
        HsmError::GeneralError
    })?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rustcrypto_backend::RustCryptoBackend;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn kdf(kdf: CK_EC_KDF_TYPE, z: &str, shared: &str, len: usize) -> HsmResult<Vec<u8>> {
        let z = RawKeyMaterial::new(hex(z));
        apply_ec_kdf(&RustCryptoBackend, kdf, &z, &hex(shared), len, false)
            .map(|k| k.as_bytes().to_vec())
    }

    // NIST CAVS ANSI X9.63 KDF (ansx963_2001.rsp), SHA-256, no SharedInfo.
    #[test]
    fn x963_sha256_known_answer() {
        let out = kdf(
            CKD_SHA256_KDF,
            "96c05619d56c328ab95fe84b18264b08725b85e33fd34f08",
            "",
            16,
        )
        .unwrap();
        assert_eq!(out, hex("443024c3dae66b95e6f5670601558f71"));
    }

    // NIST CAVS ANSI X9.63 KDF, SHA-256 with SharedInfo, multi-block output.
    #[test]
    fn x963_sha256_shared_info_multi_block() {
        let out = kdf(
            CKD_SHA256_KDF,
            "22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d",
            "75eef81aa3041e33b80971203d2c0c52",
            128,
        )
        .unwrap();
        assert_eq!(
            out,
            hex(concat!(
                "c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e",
                "52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485",
                "500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269",
                "142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21",
            ))
        );
    }

    #[test]
    fn ckd_null_keeps_rightmost_bytes() {
        let z = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert_eq!(
            kdf(CKD_NULL, z, "", 16).unwrap(),
            hex("101112131415161718191a1b1c1d1e1f")
        );
        assert_eq!(kdf(CKD_NULL, z, "", 32).unwrap(), hex(z));
        assert!(matches!(
            kdf(CKD_NULL, z, "", 33),
            Err(HsmError::KeySizeRange)
        ));
    }

    #[test]
    fn ckd_null_rejects_shared_data() {
        assert!(matches!(
            kdf(CKD_NULL, "00112233", "aa", 4),
            Err(HsmError::MechanismParamInvalid)
        ));
    }

    #[test]
    fn ckd_null_refused_in_fips_mode() {
        let z = RawKeyMaterial::new(vec![7u8; 32]);
        assert!(matches!(
            apply_ec_kdf(&RustCryptoBackend, CKD_NULL, &z, &[], 32, true),
            Err(HsmError::MechanismParamInvalid)
        ));
        assert!(apply_ec_kdf(&RustCryptoBackend, CKD_SHA256_KDF, &z, &[], 32, true).is_ok());
    }

    #[test]
    fn unsupported_kdfs_rejected() {
        for k in [CKD_SHA1_KDF, CKD_SHA224_KDF, 0, 0xdead] {
            assert!(
                matches!(
                    kdf(k, "00112233", "", 4),
                    Err(HsmError::MechanismParamInvalid)
                ),
                "kdf {k:#x}"
            );
        }
    }

    fn ulong(v: CK_KEY_TYPE) -> Vec<u8> {
        v.to_ne_bytes().to_vec()
    }

    #[test]
    fn derived_template_defaults_are_secure() {
        let t = DerivedKeyTemplate::resolve(&[], CKK_AES, &AlgorithmConfig::default()).unwrap();
        assert_eq!(
            t,
            DerivedKeyTemplate {
                key_type: CKK_AES,
                value_len: None,
                sensitive: true,
                extractable: false,
            }
        );
    }

    #[test]
    fn derived_template_config_flag_flips_defaults() {
        let config = AlgorithmConfig {
            derived_keys_extractable_by_default: true,
            ..AlgorithmConfig::default()
        };
        let t = DerivedKeyTemplate::resolve(&[], CKK_GENERIC_SECRET, &config).unwrap();
        assert!(!t.sensitive && t.extractable);

        // Explicit template values still win.
        let tpl = vec![(CKA_SENSITIVE, vec![1]), (CKA_EXTRACTABLE, vec![0])];
        let t = DerivedKeyTemplate::resolve(&tpl, CKK_GENERIC_SECRET, &config).unwrap();
        assert!(t.sensitive && !t.extractable);

        // Forced off in FIPS-approved mode.
        let fips = AlgorithmConfig {
            fips_approved_only: true,
            ..config
        };
        let t = DerivedKeyTemplate::resolve(&[], CKK_GENERIC_SECRET, &fips).unwrap();
        assert!(t.sensitive && !t.extractable);
    }

    #[test]
    fn derived_template_allows_non_sensitive_extractable() {
        let tpl = vec![(CKA_SENSITIVE, vec![0]), (CKA_EXTRACTABLE, vec![1])];
        let t = DerivedKeyTemplate::resolve(&tpl, CKK_AES, &AlgorithmConfig::default()).unwrap();
        assert!(!t.sensitive && t.extractable);
    }

    #[test]
    fn derived_template_key_type_and_length() {
        let config = AlgorithmConfig::default();
        let generic48 = vec![
            (CKA_KEY_TYPE, ulong(CKK_GENERIC_SECRET)),
            (CKA_VALUE_LEN, ulong(48)),
        ];
        let t = DerivedKeyTemplate::resolve(&generic48, CKK_AES, &config).unwrap();
        assert_eq!((t.key_type, t.value_len), (CKK_GENERIC_SECRET, Some(48)));

        let aes48 = vec![(CKA_KEY_TYPE, ulong(CKK_AES)), (CKA_VALUE_LEN, ulong(48))];
        assert!(matches!(
            DerivedKeyTemplate::resolve(&aes48, CKK_AES, &config),
            Err(HsmError::KeySizeRange)
        ));

        let rsa = vec![(CKA_KEY_TYPE, ulong(CKK_RSA))];
        assert!(matches!(
            DerivedKeyTemplate::resolve(&rsa, CKK_AES, &config),
            Err(HsmError::TemplateInconsistent)
        ));

        let bad_bool = vec![(CKA_SENSITIVE, vec![0, 0])];
        assert!(matches!(
            DerivedKeyTemplate::resolve(&bad_bool, CKK_AES, &config),
            Err(HsmError::AttributeValueInvalid)
        ));
    }
}
