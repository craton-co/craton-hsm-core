// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Parse RSA and EC key files (PEM or DER) into a PKCS#11 attribute template.
//!
//! The original `key import` implementation hard-coded `CKO_PRIVATE_KEY` for
//! both `--type RSA` and `--type EC` and copied the raw file bytes into
//! `CKA_VALUE`. Importing a public PEM as `--type RSA` therefore silently
//! produced a malformed "private key" object that had neither `CKA_MODULUS`
//! nor `CKA_PUBLIC_EXPONENT`, occupied a sensitive handle, and could not be
//! used for any operation.
//!
//! This module parses the input first, infers the object class from the
//! structure (PKCS#8 ⇒ private, SPKI ⇒ public, etc.), and constructs the
//! correct CKA_* attribute set per PKCS#11 §2.1.x.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::types::{CK_ATTRIBUTE_TYPE, CK_ULONG};

use const_oid::ObjectIdentifier;
use pkcs8::der::{Decode, Encode};
use pkcs8::{AlgorithmIdentifierRef, PrivateKeyInfo, SubjectPublicKeyInfoRef};
use rsa::pkcs1::{
    DecodeRsaPrivateKey, DecodeRsaPublicKey, RsaPrivateKey as Pkcs1RsaPrivateKey,
    RsaPublicKey as Pkcs1RsaPublicKey,
};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::BigUint;
use rsa::{RsaPrivateKey, RsaPublicKey};

use std::fmt;

/// `rsaEncryption` per RFC 8017 / PKCS#1.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// `id-ecPublicKey` per RFC 5480 / SEC1.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// NIST P-256 / `secp256r1`.
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// NIST P-384 / `secp384r1`.
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// Supported named curves. Other RustCrypto-supported curves can be added
/// here once we wire up the corresponding crates in `Cargo.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

impl Curve {
    fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        if *oid == OID_P256 {
            Some(Curve::P256)
        } else if *oid == OID_P384 {
            Some(Curve::P384)
        } else {
            None
        }
    }

    fn name(self) -> &'static str {
        match self {
            Curve::P256 => "P-256",
            Curve::P384 => "P-384",
        }
    }

    /// SEC1 uncompressed point length: `1 + 2 * field-bytes`.
    fn uncompressed_point_len(self) -> usize {
        match self {
            Curve::P256 => 1 + 2 * 32,
            Curve::P384 => 1 + 2 * 48,
        }
    }

    /// `CKA_EC_PARAMS` is the DER encoding of the named-curve OID
    /// (an `ECParameters` `CHOICE` selecting `namedCurve`).
    fn ec_params_der(self) -> Vec<u8> {
        let oid = match self {
            Curve::P256 => OID_P256,
            Curve::P384 => OID_P384,
        };
        // `ObjectIdentifier: Encode` produces the full DER (tag + length + value),
        // which is exactly what CKA_EC_PARAMS expects per PKCS#11 §2.3.3.
        oid.to_der().expect("encoding a known OID never fails")
    }
}

/// Parsed RSA private key components, ready to populate a PKCS#11 template.
///
/// Each `BigUint` is converted to the minimal big-endian byte representation
/// PKCS#11 expects for CKA_MODULUS / CKA_PRIVATE_EXPONENT / etc.
#[derive(Debug)]
pub struct ParsedRsaPrivate {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
    pub private_exponent: Vec<u8>,
    pub prime_1: Vec<u8>,
    pub prime_2: Vec<u8>,
    pub exponent_1: Vec<u8>,
    pub exponent_2: Vec<u8>,
    pub coefficient: Vec<u8>,
}

#[derive(Debug)]
pub struct ParsedRsaPublic {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
}

#[derive(Debug)]
pub struct ParsedEcPrivate {
    pub curve: Curve,
    /// Big-endian scalar `d`, padded to the field byte length.
    pub private_scalar: Vec<u8>,
    /// SEC1 uncompressed public point `04 || X || Y`, if the input contained one.
    /// PKCS#11 stores it under CKA_EC_POINT as a DER OCTET STRING wrapping
    /// these bytes; we build that wrapper in `into_template`.
    pub public_point: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct ParsedEcPublic {
    pub curve: Curve,
    /// SEC1 uncompressed point `04 || X || Y`.
    pub public_point: Vec<u8>,
}

#[derive(Debug)]
pub enum ParsedKey {
    RsaPrivate(ParsedRsaPrivate),
    RsaPublic(ParsedRsaPublic),
    EcPrivate(ParsedEcPrivate),
    EcPublic(ParsedEcPublic),
}

/// Errors surfaced from parsing. Kept stringy so the CLI can print them
/// without dragging error-handling crates into the admin tool.
#[derive(Debug)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for ParseError {}

impl From<&str> for ParseError {
    fn from(s: &str) -> Self {
        ParseError(s.to_string())
    }
}

impl From<String> for ParseError {
    fn from(s: String) -> Self {
        ParseError(s)
    }
}

impl ParsedKey {
    /// Detect format from leading bytes / PEM header and parse.
    pub fn from_bytes(data: &[u8]) -> Result<ParsedKey, ParseError> {
        // Try PEM first — if the input looks like PEM, we want a clear error
        // when the body is corrupted rather than re-parsing it as DER and
        // returning a misleading "DER error".
        if looks_like_pem(data) {
            return parse_pem(data);
        }
        parse_der(data)
    }

    pub fn key_type_name(&self) -> &'static str {
        match self {
            ParsedKey::RsaPrivate(_) | ParsedKey::RsaPublic(_) => "RSA",
            ParsedKey::EcPrivate(_) | ParsedKey::EcPublic(_) => "EC",
        }
    }

    pub fn inferred_class_name(&self) -> &'static str {
        match self {
            ParsedKey::RsaPrivate(_) | ParsedKey::EcPrivate(_) => "private",
            ParsedKey::RsaPublic(_) | ParsedKey::EcPublic(_) => "public",
        }
    }

    /// Confirm the user-supplied `--class` matches what the parser inferred.
    ///
    /// `None` means "trust the parser" and is always accepted. `Some` must
    /// match (case-insensitively) one of "public" / "private"; anything
    /// else — including a typo or a deliberate mismatch — is rejected so we
    /// never import a key under the wrong class.
    pub fn confirm_class(&self, requested: Option<&str>) -> Result<(), ParseError> {
        let inferred = self.inferred_class_name();
        match requested {
            None => Ok(()),
            Some(r) if r.eq_ignore_ascii_case(inferred) => Ok(()),
            Some(r) => Err(ParseError(format!(
                "--class {} disagrees with parsed key class ({}). \
                 Refusing to import to avoid creating a malformed object.",
                r, inferred
            ))),
        }
    }

    /// One-line human summary printed before the confirmation prompt.
    pub fn display_summary(&self) -> String {
        match self {
            ParsedKey::RsaPrivate(p) => {
                // CKA_MODULUS is unpadded big-endian, so the bit-length is
                // `bytes * 8` minus leading-zero bits of the first byte.
                let bits = modulus_bit_len(&p.modulus);
                format!("Type: RSA (private, {} bits)", bits)
            }
            ParsedKey::RsaPublic(p) => {
                let bits = modulus_bit_len(&p.modulus);
                format!("Type: RSA (public, {} bits)", bits)
            }
            ParsedKey::EcPrivate(p) => format!("Type: EC (private, {})", p.curve.name()),
            ParsedKey::EcPublic(p) => format!("Type: EC (public, {})", p.curve.name()),
        }
    }

    /// Build the full PKCS#11 attribute template. The caller is responsible
    /// for zeroizing the returned `Vec<u8>` values after `create_object`
    /// consumes them.
    pub fn into_template(self, label: &str) -> Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> {
        // Note: we use ck_ulong_bytes here (native-endian, sized to CK_ULONG)
        // because that's what the store's `read_ck_ulong` expects.
        match self {
            ParsedKey::RsaPrivate(p) => vec![
                (CKA_CLASS, ck_ulong_bytes(CKO_PRIVATE_KEY)),
                (CKA_KEY_TYPE, ck_ulong_bytes(CKK_RSA)),
                (CKA_LABEL, label.as_bytes().to_vec()),
                (CKA_TOKEN, vec![1u8]),
                (CKA_PRIVATE, vec![1u8]),
                (CKA_SENSITIVE, vec![1u8]),
                // CKA_EXTRACTABLE defaults to false in our store, but be
                // explicit to make the import behaviour obvious to operators
                // who later try to wrap-export the key.
                (CKA_EXTRACTABLE, vec![0u8]),
                (CKA_MODULUS, p.modulus),
                (CKA_PUBLIC_EXPONENT, p.public_exponent),
                (CKA_PRIVATE_EXPONENT, p.private_exponent),
                (CKA_PRIME_1, p.prime_1),
                (CKA_PRIME_2, p.prime_2),
                (CKA_EXPONENT_1, p.exponent_1),
                (CKA_EXPONENT_2, p.exponent_2),
                (CKA_COEFFICIENT, p.coefficient),
            ],
            ParsedKey::RsaPublic(p) => vec![
                (CKA_CLASS, ck_ulong_bytes(CKO_PUBLIC_KEY)),
                (CKA_KEY_TYPE, ck_ulong_bytes(CKK_RSA)),
                (CKA_LABEL, label.as_bytes().to_vec()),
                (CKA_TOKEN, vec![1u8]),
                // Public keys must be readable by anyone with access to the
                // token, so CKA_PRIVATE = false and CKA_SENSITIVE = false.
                (CKA_PRIVATE, vec![0u8]),
                (CKA_SENSITIVE, vec![0u8]),
                (CKA_MODULUS, p.modulus),
                (CKA_PUBLIC_EXPONENT, p.public_exponent),
            ],
            ParsedKey::EcPrivate(p) => {
                let mut tpl = vec![
                    (CKA_CLASS, ck_ulong_bytes(CKO_PRIVATE_KEY)),
                    (CKA_KEY_TYPE, ck_ulong_bytes(CKK_EC)),
                    (CKA_LABEL, label.as_bytes().to_vec()),
                    (CKA_TOKEN, vec![1u8]),
                    (CKA_PRIVATE, vec![1u8]),
                    (CKA_SENSITIVE, vec![1u8]),
                    (CKA_EXTRACTABLE, vec![0u8]),
                    (CKA_EC_PARAMS, p.curve.ec_params_der()),
                    // PKCS#11 §2.3.3: the private scalar lives in CKA_VALUE
                    // as a big-endian integer padded to the field size.
                    (CKA_VALUE, p.private_scalar),
                ];
                if let Some(point) = p.public_point {
                    tpl.push((CKA_EC_POINT, wrap_octet_string(&point)));
                }
                tpl
            }
            ParsedKey::EcPublic(p) => vec![
                (CKA_CLASS, ck_ulong_bytes(CKO_PUBLIC_KEY)),
                (CKA_KEY_TYPE, ck_ulong_bytes(CKK_EC)),
                (CKA_LABEL, label.as_bytes().to_vec()),
                (CKA_TOKEN, vec![1u8]),
                (CKA_PRIVATE, vec![0u8]),
                (CKA_SENSITIVE, vec![0u8]),
                (CKA_EC_PARAMS, p.curve.ec_params_der()),
                (CKA_EC_POINT, wrap_octet_string(&p.public_point)),
            ],
        }
    }
}

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

fn looks_like_pem(data: &[u8]) -> bool {
    // PEM is ASCII; bail quickly if not. We check the literal "-----BEGIN"
    // prefix (possibly preceded by whitespace) so we don't get fooled by
    // DER that happens to start with text-like bytes.
    let prefix = data
        .iter()
        .copied()
        .skip_while(|b| matches!(*b, b' ' | b'\t' | b'\r' | b'\n'))
        .take(10)
        .collect::<Vec<_>>();
    prefix.starts_with(b"-----BEGIN")
}

/// Wrap raw bytes in a DER OCTET STRING (tag 0x04). CKA_EC_POINT is defined
/// as "DER-encoding of an `ECPoint` value" per PKCS#11 §2.3.3, which is the
/// `OCTET STRING` wrapper around the SEC1 uncompressed point.
fn wrap_octet_string(inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + inner.len() + 4);
    out.push(0x04);
    encode_der_length(&mut out, inner.len());
    out.extend_from_slice(inner);
    out
}

fn encode_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        // Long-form: 0x80 | n, followed by n bytes of big-endian length.
        let mut tmp = Vec::with_capacity(8);
        let mut l = len;
        while l > 0 {
            tmp.push((l & 0xff) as u8);
            l >>= 8;
        }
        tmp.reverse();
        out.push(0x80 | tmp.len() as u8);
        out.extend_from_slice(&tmp);
    }
}

fn modulus_bit_len(modulus: &[u8]) -> usize {
    // Strip leading zeros (PKCS#11 stores the unsigned big-endian integer
    // with no leading-zero padding; defense-in-depth in case a caller adds
    // padding anyway).
    let trimmed = modulus.iter().position(|&b| b != 0).unwrap_or(modulus.len());
    let stripped = &modulus[trimmed..];
    if stripped.is_empty() {
        return 0;
    }
    let leading = stripped[0].leading_zeros() as usize;
    stripped.len() * 8 - leading
}

// -----------------------------------------------------------------------------
// PEM dispatch
// -----------------------------------------------------------------------------

fn parse_pem(data: &[u8]) -> Result<ParsedKey, ParseError> {
    // `pkcs8::der::pem::decode_vec` returns `(label: &str, der: Vec<u8>)`.
    // We accept any PEM label here and dispatch downstream.
    let (label, der) = pkcs8::der::pem::decode_vec(data)
        .map_err(|e| ParseError(format!("malformed PEM: {}", e)))?;

    match label {
        "PRIVATE KEY" => parse_pkcs8_private(&der),
        "PUBLIC KEY" => parse_spki_public(&der),
        "RSA PRIVATE KEY" => parse_pkcs1_rsa_private(&der),
        "RSA PUBLIC KEY" => parse_pkcs1_rsa_public(&der),
        "EC PRIVATE KEY" => parse_sec1_ec_private(&der, None),
        other => Err(ParseError(format!(
            "unsupported PEM label: '{}'. Expected one of: PRIVATE KEY, \
             PUBLIC KEY, RSA PRIVATE KEY, RSA PUBLIC KEY, EC PRIVATE KEY.",
            other
        ))),
    }
}

// -----------------------------------------------------------------------------
// DER dispatch — try the structures in order of preference and report only
// the most useful error.
// -----------------------------------------------------------------------------

fn parse_der(data: &[u8]) -> Result<ParsedKey, ParseError> {
    if let Ok(out) = parse_pkcs8_private(data) {
        return Ok(out);
    }
    if let Ok(out) = parse_spki_public(data) {
        return Ok(out);
    }
    if let Ok(out) = parse_pkcs1_rsa_private(data) {
        return Ok(out);
    }
    if let Ok(out) = parse_pkcs1_rsa_public(data) {
        return Ok(out);
    }
    Err(ParseError(
        "input did not parse as PKCS#8, SPKI, or PKCS#1 DER".to_string(),
    ))
}

// -----------------------------------------------------------------------------
// PKCS#8 PrivateKeyInfo: dispatch by algorithm OID.
// -----------------------------------------------------------------------------

fn parse_pkcs8_private(der: &[u8]) -> Result<ParsedKey, ParseError> {
    let info = PrivateKeyInfo::try_from(der)
        .map_err(|e| ParseError(format!("PKCS#8 decode failed: {}", e)))?;
    dispatch_private_key_info(&info)
}

fn dispatch_private_key_info(info: &PrivateKeyInfo<'_>) -> Result<ParsedKey, ParseError> {
    let alg_oid = info.algorithm.oid;
    if alg_oid == OID_RSA_ENCRYPTION {
        // RFC 5208 §5: PKCS#8's privateKey OCTET STRING contains the
        // PKCS#1 RSAPrivateKey DER for RSA.
        let pk1 = Pkcs1RsaPrivateKey::from_der(info.private_key)
            .map_err(|e| ParseError(format!("inner PKCS#1 RSAPrivateKey decode failed: {}", e)))?;
        parsed_rsa_private_from_pkcs1(&pk1)
    } else if alg_oid == OID_EC_PUBLIC_KEY {
        let curve = pkcs8_ec_curve(&info.algorithm)?;
        parse_sec1_ec_private(info.private_key, Some(curve))
    } else {
        Err(ParseError(format!(
            "unsupported PKCS#8 algorithm OID {} (only rsaEncryption and id-ecPublicKey are supported)",
            alg_oid
        )))
    }
}

fn pkcs8_ec_curve(alg: &AlgorithmIdentifierRef<'_>) -> Result<Curve, ParseError> {
    // For id-ecPublicKey, `parameters` carries the named-curve OID as an
    // ASN.1 OBJECT IDENTIFIER. We decode the ANY value into an OID and
    // map to our `Curve` enum.
    let params = alg
        .parameters
        .ok_or_else(|| ParseError("EC PKCS#8 missing curve parameters".to_string()))?;
    let oid: ObjectIdentifier = params
        .decode_as()
        .map_err(|e| ParseError(format!("EC curve parameters are not an OID: {}", e)))?;
    Curve::from_oid(&oid).ok_or_else(|| {
        ParseError(format!(
            "unsupported EC named curve OID {} (supported: P-256, P-384)",
            oid
        ))
    })
}

// -----------------------------------------------------------------------------
// SPKI SubjectPublicKeyInfo: dispatch by algorithm OID.
// -----------------------------------------------------------------------------

fn parse_spki_public(der: &[u8]) -> Result<ParsedKey, ParseError> {
    let spki = SubjectPublicKeyInfoRef::try_from(der)
        .map_err(|e| ParseError(format!("SPKI decode failed: {}", e)))?;
    let alg_oid = spki.algorithm.oid;
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| ParseError("SPKI BIT STRING has non-byte-aligned length".to_string()))?;

    if alg_oid == OID_RSA_ENCRYPTION {
        let pk1 = Pkcs1RsaPublicKey::from_der(key_bytes)
            .map_err(|e| ParseError(format!("inner PKCS#1 RSAPublicKey decode failed: {}", e)))?;
        parsed_rsa_public_from_pkcs1(&pk1)
    } else if alg_oid == OID_EC_PUBLIC_KEY {
        let curve = pkcs8_ec_curve(&spki.algorithm)?;
        // The SPKI BIT STRING already IS the SEC1 uncompressed point
        // (`04 || X || Y`) — no inner OCTET STRING wrapper.
        validate_ec_point(curve, key_bytes)?;
        Ok(ParsedKey::EcPublic(ParsedEcPublic {
            curve,
            public_point: key_bytes.to_vec(),
        }))
    } else {
        Err(ParseError(format!(
            "unsupported SPKI algorithm OID {} (only rsaEncryption and id-ecPublicKey are supported)",
            alg_oid
        )))
    }
}

// -----------------------------------------------------------------------------
// PKCS#1 RSAPrivateKey / RSAPublicKey (legacy traditional PEM).
// -----------------------------------------------------------------------------

fn parse_pkcs1_rsa_private(der: &[u8]) -> Result<ParsedKey, ParseError> {
    let pk1 = Pkcs1RsaPrivateKey::from_der(der)
        .map_err(|e| ParseError(format!("PKCS#1 RSAPrivateKey decode failed: {}", e)))?;
    parsed_rsa_private_from_pkcs1(&pk1)
}

fn parse_pkcs1_rsa_public(der: &[u8]) -> Result<ParsedKey, ParseError> {
    let pk1 = Pkcs1RsaPublicKey::from_der(der)
        .map_err(|e| ParseError(format!("PKCS#1 RSAPublicKey decode failed: {}", e)))?;
    parsed_rsa_public_from_pkcs1(&pk1)
}

/// Promote a `pkcs1::RsaPrivateKey<'_>` to a parsed-component struct.
///
/// We reparse through `rsa::RsaPrivateKey::from_pkcs1_der` so the resulting
/// key is *validated* (consistent modulus / exponent / primes) before we
/// accept it. A malformed inner RSA structure is exactly the kind of thing
/// that would have silently slipped past the old importer.
fn parsed_rsa_private_from_pkcs1(pk1: &Pkcs1RsaPrivateKey<'_>) -> Result<ParsedKey, ParseError> {
    let der = pk1
        .to_der()
        .map_err(|e| ParseError(format!("RSA reserialize failed: {}", e)))?;
    let key = RsaPrivateKey::from_pkcs1_der(&der)
        .map_err(|e| ParseError(format!("RSA key validation failed: {}", e)))?;
    key.validate()
        .map_err(|e| ParseError(format!("RSA key inconsistent: {}", e)))?;

    let n = key.n().to_bytes_be();
    let e = key.e().to_bytes_be();
    let d = key.d().to_bytes_be();
    let primes = key.primes();
    if primes.len() < 2 {
        return Err(ParseError(format!(
            "RSA key has {} prime(s); PKCS#11 requires multi-prime via separate attrs",
            primes.len()
        )));
    }
    let p_be = primes[0].to_bytes_be();
    let q_be = primes[1].to_bytes_be();

    // CRT components. `rsa::RsaPrivateKey::from_pkcs1_der` populates `dp`/`dq`
    // eagerly, but the trait still hands them back as `Option`s; recompute
    // when absent to be defensive against future API changes in the crate.
    let dp: Vec<u8> = match PrivateKeyParts::dp(&key) {
        Some(v) => v.to_bytes_be(),
        None => compute_d_mod_pm1(&key, 0)?,
    };
    let dq: Vec<u8> = match PrivateKeyParts::dq(&key) {
        Some(v) => v.to_bytes_be(),
        None => compute_d_mod_pm1(&key, 1)?,
    };
    let qinv = key
        .crt_coefficient()
        .ok_or_else(|| ParseError("could not compute CRT coefficient q^-1 mod p".to_string()))?
        .to_bytes_be();

    Ok(ParsedKey::RsaPrivate(ParsedRsaPrivate {
        modulus: n,
        public_exponent: e,
        private_exponent: d,
        prime_1: p_be,
        prime_2: q_be,
        exponent_1: dp,
        exponent_2: dq,
        coefficient: qinv,
    }))
}

fn parsed_rsa_public_from_pkcs1(pk1: &Pkcs1RsaPublicKey<'_>) -> Result<ParsedKey, ParseError> {
    let der = pk1
        .to_der()
        .map_err(|e| ParseError(format!("RSA pubkey reserialize failed: {}", e)))?;
    let key = RsaPublicKey::from_pkcs1_der(&der)
        .map_err(|e| ParseError(format!("RSA public key validation failed: {}", e)))?;
    Ok(ParsedKey::RsaPublic(ParsedRsaPublic {
        modulus: key.n().to_bytes_be(),
        public_exponent: key.e().to_bytes_be(),
    }))
}

/// Compute `d mod (p_i - 1)` using the `rsa` crate's re-exported `BigUint`.
fn compute_d_mod_pm1(key: &RsaPrivateKey, prime_idx: usize) -> Result<Vec<u8>, ParseError> {
    let primes = key.primes();
    let p: &BigUint = primes
        .get(prime_idx)
        .ok_or_else(|| ParseError("missing prime for CRT exponent".to_string()))?;
    let one = BigUint::from(1u32);
    let p_minus_one = p - &one;
    let dpx = key.d() % &p_minus_one;
    Ok(dpx.to_bytes_be())
}

// -----------------------------------------------------------------------------
// SEC1 EcPrivateKey (used directly for "EC PRIVATE KEY" PEMs and from inside
// PKCS#8 when the algorithm is id-ecPublicKey).
// -----------------------------------------------------------------------------

fn parse_sec1_ec_private(
    der: &[u8],
    known_curve: Option<Curve>,
) -> Result<ParsedKey, ParseError> {
    let pk = sec1::EcPrivateKey::from_der(der)
        .map_err(|e| ParseError(format!("SEC1 EcPrivateKey decode failed: {}", e)))?;

    // Resolve the curve. If known (from PKCS#8 wrapping), trust it; otherwise
    // require the parameters field to be present (PEM "EC PRIVATE KEY"
    // traditional encoding includes it explicitly).
    let curve = match known_curve {
        Some(c) => c,
        None => {
            let oid = pk
                .parameters
                .as_ref()
                .ok_or_else(|| {
                    ParseError("EC PRIVATE KEY missing named-curve parameters".to_string())
                })?
                .named_curve()
                .ok_or_else(|| {
                    ParseError("EC PRIVATE KEY parameters are not a named curve".to_string())
                })?;
            Curve::from_oid(&oid).ok_or_else(|| {
                ParseError(format!(
                    "unsupported EC named curve OID {} (supported: P-256, P-384)",
                    oid
                ))
            })?
        }
    };

    let scalar_len = curve.uncompressed_point_len() / 2; // = field-bytes
    if pk.private_key.len() > scalar_len {
        return Err(ParseError(format!(
            "EC private scalar length {} exceeds field size {}",
            pk.private_key.len(),
            scalar_len
        )));
    }
    // Left-pad to the field size — PKCS#11 expects fixed-width scalars.
    let mut padded = vec![0u8; scalar_len];
    let start = scalar_len - pk.private_key.len();
    padded[start..].copy_from_slice(pk.private_key);

    // Public point is optional in SEC1; preserve it when present so the
    // imported object exposes both halves of the keypair.
    let public_point = match pk.public_key {
        Some(p) => {
            validate_ec_point(curve, p)?;
            Some(p.to_vec())
        }
        None => None,
    };

    Ok(ParsedKey::EcPrivate(ParsedEcPrivate {
        curve,
        private_scalar: padded,
        public_point,
    }))
}

fn validate_ec_point(curve: Curve, point: &[u8]) -> Result<(), ParseError> {
    if point.is_empty() {
        return Err(ParseError("EC point is empty".to_string()));
    }
    let expected = curve.uncompressed_point_len();
    // We require uncompressed (0x04 prefix) form: it's what PKCS#11
    // implementations interoperate on and what the rest of craton-hsm
    // emits. Compressed (0x02/0x03) and hybrid (0x06/0x07) are rejected.
    if point[0] != 0x04 {
        return Err(ParseError(format!(
            "EC point must be uncompressed (0x04 prefix); got {:#x}",
            point[0]
        )));
    }
    if point.len() != expected {
        return Err(ParseError(format!(
            "EC point length {} does not match {} field size ({} expected)",
            point.len(),
            curve.name(),
            expected
        )));
    }
    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

    /// Deterministic small RSA key for fast tests. 1024 bits is below modern
    /// recommendations but is intentional — we are validating the parser /
    /// attribute construction, not the strength of the test key.
    fn test_rsa_key() -> RsaPrivateKey {
        use rand::rngs::StdRng;
        use rand::SeedableRng;
        // Fixed seed so failures are reproducible. Underscore groups of 4
        // hex digits keep clippy's `unusual_byte_groupings` lint happy.
        let mut rng = StdRng::seed_from_u64(0xC0FF_EECA_FE00_0001);
        RsaPrivateKey::new(&mut rng, 1024).expect("RSA keygen")
    }

    #[test]
    fn rsa_private_pkcs8_pem_round_trips() {
        let key = test_rsa_key();
        let pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode pkcs8 pem");
        let parsed = ParsedKey::from_bytes(pem.as_bytes()).expect("parse");
        match parsed {
            ParsedKey::RsaPrivate(p) => {
                assert_eq!(p.modulus, key.n().to_bytes_be());
                assert_eq!(p.public_exponent, key.e().to_bytes_be());
                assert_eq!(p.private_exponent, key.d().to_bytes_be());
                assert_eq!(p.prime_1, key.primes()[0].to_bytes_be());
                assert_eq!(p.prime_2, key.primes()[1].to_bytes_be());
                assert!(!p.exponent_1.is_empty(), "dp should be populated");
                assert!(!p.exponent_2.is_empty(), "dq should be populated");
                assert!(!p.coefficient.is_empty(), "qinv should be populated");
            }
            other => panic!("expected RsaPrivate, got {:?}", other),
        }
    }

    #[test]
    fn rsa_private_template_has_all_required_attributes() {
        let key = test_rsa_key();
        let pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode pkcs8 pem");
        let parsed = ParsedKey::from_bytes(pem.as_bytes()).expect("parse");
        let tpl = parsed.into_template("test-rsa-priv");

        // Find every attribute PKCS#11 requires for an RSA private key.
        let attrs: std::collections::HashMap<_, _> = tpl.iter().map(|(a, v)| (*a, v.clone())).collect();
        for required in [
            CKA_CLASS,
            CKA_KEY_TYPE,
            CKA_LABEL,
            CKA_MODULUS,
            CKA_PUBLIC_EXPONENT,
            CKA_PRIVATE_EXPONENT,
            CKA_PRIME_1,
            CKA_PRIME_2,
            CKA_EXPONENT_1,
            CKA_EXPONENT_2,
            CKA_COEFFICIENT,
        ] {
            assert!(attrs.contains_key(&required), "missing CKA 0x{:x}", required);
        }
        // Class must be CKO_PRIVATE_KEY, not the historical raw CKA_VALUE blob.
        let class_bytes = &attrs[&CKA_CLASS];
        assert_eq!(
            class_bytes,
            &ck_ulong_bytes(CKO_PRIVATE_KEY),
            "CKA_CLASS must be CKO_PRIVATE_KEY"
        );
        // Importantly: CKA_VALUE must NOT be present on an RSA private key
        // imported via the new path. The old bug stuffed the raw file bytes
        // into CKA_VALUE; this test guards against regression.
        assert!(
            !attrs.contains_key(&CKA_VALUE),
            "CKA_VALUE must not be set on an RSA private key — that was the bug"
        );
    }

    #[test]
    fn rsa_public_spki_pem_parses_as_public() {
        let key = test_rsa_key();
        let pem = key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode spki pem");
        let parsed = ParsedKey::from_bytes(pem.as_bytes()).expect("parse");
        assert_eq!(parsed.key_type_name(), "RSA");
        assert_eq!(parsed.inferred_class_name(), "public");
        match parsed {
            ParsedKey::RsaPublic(p) => {
                assert_eq!(p.modulus, key.n().to_bytes_be());
                assert_eq!(p.public_exponent, key.e().to_bytes_be());
            }
            other => panic!("expected RsaPublic, got {:?}", other),
        }
    }

    #[test]
    fn rsa_public_template_has_correct_class_and_no_private_attrs() {
        let key = test_rsa_key();
        let pem = key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode spki pem");
        let parsed = ParsedKey::from_bytes(pem.as_bytes()).expect("parse");
        let tpl = parsed.into_template("test-rsa-pub");
        let attrs: std::collections::HashMap<_, _> = tpl.iter().map(|(a, v)| (*a, v.clone())).collect();

        assert_eq!(attrs[&CKA_CLASS], ck_ulong_bytes(CKO_PUBLIC_KEY));
        assert!(attrs.contains_key(&CKA_MODULUS));
        assert!(attrs.contains_key(&CKA_PUBLIC_EXPONENT));
        // Private-only attributes must be absent.
        for forbidden in [
            CKA_PRIVATE_EXPONENT,
            CKA_PRIME_1,
            CKA_PRIME_2,
            CKA_EXPONENT_1,
            CKA_EXPONENT_2,
            CKA_COEFFICIENT,
        ] {
            assert!(
                !attrs.contains_key(&forbidden),
                "CKA 0x{:x} must not be set on a public RSA key",
                forbidden
            );
        }
        // Sensitive must be false for a public key.
        assert_eq!(attrs[&CKA_SENSITIVE], vec![0u8]);
    }

    #[test]
    fn rsa_pkcs1_traditional_pem_private() {
        // Build a traditional "RSA PRIVATE KEY" PEM and verify we accept it.
        use rsa::pkcs1::EncodeRsaPrivateKey;
        let key = test_rsa_key();
        let pem = key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("encode pkcs1 pem");
        let parsed = ParsedKey::from_bytes(pem.as_bytes()).expect("parse");
        assert_eq!(parsed.key_type_name(), "RSA");
        assert_eq!(parsed.inferred_class_name(), "private");
    }

    #[test]
    fn rsa_pkcs1_traditional_pem_public() {
        let key = test_rsa_key();
        let pem = key
            .to_public_key()
            .to_pkcs1_pem(LineEnding::LF)
            .expect("encode pkcs1 pub pem");
        let parsed = ParsedKey::from_bytes(pem.as_bytes()).expect("parse");
        assert_eq!(parsed.key_type_name(), "RSA");
        assert_eq!(parsed.inferred_class_name(), "public");
    }

    #[test]
    fn malformed_input_is_rejected_with_clear_error() {
        let err = ParsedKey::from_bytes(b"not a key").unwrap_err();
        let msg = err.to_string();
        // Either DER dispatch ("did not parse as PKCS#8 ...") or PEM error
        // — both are acceptable; we only require a useful message.
        assert!(
            msg.contains("PKCS#8") || msg.contains("PEM") || msg.contains("DER"),
            "error must mention what we tried: {}",
            msg
        );
    }

    #[test]
    fn malformed_pem_body_is_rejected() {
        let pem = b"-----BEGIN PRIVATE KEY-----\nnot-base64!@#\n-----END PRIVATE KEY-----\n";
        let err = ParsedKey::from_bytes(pem).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("pem")
                || msg.to_lowercase().contains("base64")
                || msg.to_lowercase().contains("decode"),
            "error must mention PEM/base64/decode: {}",
            msg
        );
    }

    #[test]
    fn ec_p256_private_pkcs8_pem() {
        use p256::pkcs8::EncodePrivateKey;
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let pem = secret
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode p256 pkcs8");
        let parsed = ParsedKey::from_bytes(pem.as_bytes()).expect("parse");
        match parsed {
            ParsedKey::EcPrivate(ec) => {
                assert_eq!(ec.curve, Curve::P256);
                assert_eq!(ec.private_scalar.len(), 32);
            }
            other => panic!("expected EcPrivate(P-256), got {:?}", other),
        }
    }

    #[test]
    fn ec_p256_public_spki_pem() {
        use p256::pkcs8::EncodePublicKey;
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let public = secret.public_key();
        let pem = public.to_public_key_pem(LineEnding::LF).expect("encode");
        let parsed = ParsedKey::from_bytes(pem.as_bytes()).expect("parse");
        match parsed {
            ParsedKey::EcPublic(ec) => {
                assert_eq!(ec.curve, Curve::P256);
                assert_eq!(ec.public_point.len(), 1 + 64);
                assert_eq!(ec.public_point[0], 0x04);
            }
            other => panic!("expected EcPublic(P-256), got {:?}", other),
        }
    }

    #[test]
    fn ec_p256_public_template_has_ec_params_and_point() {
        use p256::pkcs8::EncodePublicKey;
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let pem = secret
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode");
        let parsed = ParsedKey::from_bytes(pem.as_bytes()).expect("parse");
        let tpl = parsed.into_template("test-ec-pub");
        let attrs: std::collections::HashMap<_, _> = tpl.iter().map(|(a, v)| (*a, v.clone())).collect();
        assert_eq!(attrs[&CKA_CLASS], ck_ulong_bytes(CKO_PUBLIC_KEY));
        assert_eq!(attrs[&CKA_KEY_TYPE], ck_ulong_bytes(CKK_EC));
        assert!(attrs.contains_key(&CKA_EC_PARAMS));
        let ec_point = attrs.get(&CKA_EC_POINT).expect("CKA_EC_POINT set");
        // OCTET STRING wrapper: tag 0x04, length, then 65-byte uncompressed point.
        assert_eq!(ec_point[0], 0x04, "outer DER tag must be OCTET STRING");
        // For length=65 (0x41), short-form length applies.
        assert_eq!(ec_point[1], 0x41);
        assert_eq!(ec_point[2], 0x04, "inner SEC1 prefix must be 0x04");
    }

    #[test]
    fn class_disagreement_logic_caught_by_caller() {
        // This is the property the CLI layer uses: parsed class is the
        // ground truth, and `--class` is only a confirmation. Exercising
        // that here keeps the contract under test even if the CLI loop
        // ever gets refactored.
        let key = test_rsa_key();
        let pem = key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode");
        let parsed = ParsedKey::from_bytes(pem.as_bytes()).expect("parse");
        assert_eq!(parsed.inferred_class_name(), "public");

        let priv_pem = key.to_pkcs8_pem(LineEnding::LF).expect("encode");
        let priv_parsed = ParsedKey::from_bytes(priv_pem.as_bytes()).expect("parse");
        assert_eq!(priv_parsed.inferred_class_name(), "private");
    }

    #[test]
    fn confirm_class_accepts_matching_and_none() {
        let key = test_rsa_key();
        let pem = key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode");
        let parsed = ParsedKey::from_bytes(pem.as_bytes()).expect("parse");
        // Both omitted and matching `--class` succeed.
        parsed.confirm_class(None).expect("None is always accepted");
        parsed
            .confirm_class(Some("public"))
            .expect("matching class accepted");
        parsed
            .confirm_class(Some("PUBLIC"))
            .expect("case-insensitive match accepted");
    }

    #[test]
    fn confirm_class_rejects_public_pem_imported_as_private() {
        // This is the exact scenario the original bug created silently.
        let key = test_rsa_key();
        let pem = key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode");
        let parsed = ParsedKey::from_bytes(pem.as_bytes()).expect("parse");
        let err = parsed
            .confirm_class(Some("private"))
            .expect_err("must reject private for a public-key PEM");
        let msg = err.to_string();
        assert!(
            msg.contains("disagrees"),
            "error must explain the disagreement: {}",
            msg
        );
        assert!(
            msg.contains("public"),
            "error must mention the inferred class: {}",
            msg
        );
    }

    #[test]
    fn confirm_class_rejects_private_pem_imported_as_public() {
        // Symmetric case — private parsed, but `--class public` requested.
        let key = test_rsa_key();
        let pem = key.to_pkcs8_pem(LineEnding::LF).expect("encode");
        let parsed = ParsedKey::from_bytes(pem.as_bytes()).expect("parse");
        let err = parsed
            .confirm_class(Some("public"))
            .expect_err("must reject public for a private-key PEM");
        assert!(err.to_string().contains("disagrees"));
    }

    #[test]
    fn round_trip_rsa_private_via_temp_pem_file() {
        // End-to-end: generate, write to disk, read back, parse, build template.
        // This is the closest unit-test analogue to "the user runs key import
        // against a real file" without spinning up a full HsmCore instance.
        use std::io::Write;
        let key = test_rsa_key();
        let pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode pkcs8 pem");

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rsa-priv.pem");
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(pem.as_bytes()).expect("write");
        drop(f);

        let data = std::fs::read(&path).expect("read back");
        let parsed = ParsedKey::from_bytes(&data).expect("parse from file bytes");
        assert_eq!(parsed.key_type_name(), "RSA");
        assert_eq!(parsed.inferred_class_name(), "private");
        let tpl = parsed.into_template("round-trip");
        let attrs: std::collections::HashMap<_, _> =
            tpl.iter().map(|(a, v)| (*a, v.clone())).collect();
        assert_eq!(attrs[&CKA_CLASS], ck_ulong_bytes(CKO_PRIVATE_KEY));
        assert_eq!(attrs[&CKA_KEY_TYPE], ck_ulong_bytes(CKK_RSA));
        assert_eq!(attrs[&CKA_MODULUS], key.n().to_bytes_be());
        assert_eq!(attrs[&CKA_PUBLIC_EXPONENT], key.e().to_bytes_be());
    }

    #[test]
    fn confirm_class_rejects_unknown_class_string() {
        // A typo like `--class secret` should also be rejected for asymmetric
        // keys, because it can never match.
        let key = test_rsa_key();
        let pem = key.to_pkcs8_pem(LineEnding::LF).expect("encode");
        let parsed = ParsedKey::from_bytes(pem.as_bytes()).expect("parse");
        let err = parsed
            .confirm_class(Some("secret"))
            .expect_err("must reject unknown class");
        assert!(err.to_string().contains("disagrees"));
    }

    #[test]
    fn unsupported_pem_label_rejected() {
        // A "DSA PRIVATE KEY" PEM is well-formed but unsupported.
        let pem = b"-----BEGIN DSA PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END DSA PRIVATE KEY-----\n";
        let err = ParsedKey::from_bytes(pem).unwrap_err();
        assert!(
            err.to_string().contains("unsupported PEM label"),
            "expected unsupported-label message, got: {}",
            err
        );
    }

    #[test]
    fn modulus_bit_len_matches_known_2048_bit_key() {
        // Build a 2048-bit modulus made of all 0xff bytes — the trim-and-count
        // implementation must return 2048 exactly.
        let modulus = vec![0xff_u8; 256];
        assert_eq!(modulus_bit_len(&modulus), 2048);
        // With leading zero bytes, the bit length drops accordingly.
        let mut padded = vec![0u8; 4];
        padded.extend_from_slice(&modulus);
        assert_eq!(modulus_bit_len(&padded), 2048);
    }
}
