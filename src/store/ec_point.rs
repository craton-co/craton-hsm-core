// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! `CKA_EC_POINT` encoding.
//!
//! PKCS#11 defines `CKA_EC_POINT` as the DER encoding of an ANSI X9.62
//! `ECPoint`, i.e. an `OCTET STRING` wrapping the SEC1 point
//! (`04 || X || Y` for an uncompressed point). For Edwards keys it is the
//! same `OCTET STRING` wrapper around the RFC 8032 public key bytes.
//!
//! Internally, `StoredObject::ec_point` keeps the *raw* point, because that
//! is what the crypto backends consume. The DER wrapper is added when the
//! attribute is read through the PKCS#11 ABI and stripped when a value is
//! supplied by the caller. Callers may supply either form: raw points are
//! still accepted for compatibility with applications (and earlier versions
//! of this token) that pass the bare point.

/// Raw public-key lengths accepted inside a DER `OCTET STRING` wrapper.
///
/// Restricting unwrapping to these exact lengths makes raw/DER detection
/// unambiguous: none of the raw encodings (33/49/65/97/133-byte SEC1 points,
/// 32/57-byte Edwards keys) also parses as a complete DER `OCTET STRING`
/// whose content has one of these lengths.
const RAW_POINT_LENGTHS: &[usize] = &[
    32,  // Ed25519
    33,  // P-256 compressed
    49,  // P-384 compressed
    57,  // Ed448
    65,  // P-256 uncompressed
    67,  // P-521 compressed
    97,  // P-384 uncompressed
    133, // P-521 uncompressed
];

const DER_OCTET_STRING: u8 = 0x04;

/// Wrap a raw point in a DER `OCTET STRING`, producing the PKCS#11
/// `CKA_EC_POINT` value.
pub fn encode_der(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 4);
    out.push(DER_OCTET_STRING);
    let len = raw.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        // Points never exceed 64 KiB; two length octets are always enough.
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(raw);
    out
}

/// Return the raw point carried by a `CKA_EC_POINT` value supplied by a
/// caller, accepting both the PKCS#11 DER form and a bare point.
pub fn decode(value: &[u8]) -> &[u8] {
    match unwrap_der(value) {
        Some(inner) if RAW_POINT_LENGTHS.contains(&inner.len()) => inner,
        _ => value,
    }
}

/// Parse `value` as exactly one DER `OCTET STRING` and return its content.
fn unwrap_der(value: &[u8]) -> Option<&[u8]> {
    let (&tag, rest) = value.split_first()?;
    if tag != DER_OCTET_STRING {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0x00..=0x7f => (first as usize, rest),
        0x81 => {
            let (&l, rest) = rest.split_first()?;
            // DER requires the short form for lengths below 0x80.
            if l < 0x80 {
                return None;
            }
            (l as usize, rest)
        }
        0x82 => {
            if rest.len() < 2 {
                return None;
            }
            let l = ((rest[0] as usize) << 8) | rest[1] as usize;
            if l <= 0xff {
                return None;
            }
            (l, &rest[2..])
        }
        _ => return None,
    };
    (rest.len() == len).then_some(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uncompressed(len: usize, fill: u8) -> Vec<u8> {
        let mut p = vec![fill; len];
        p[0] = 0x04;
        p
    }

    #[test]
    fn encode_p256_uses_short_form() {
        let raw = uncompressed(65, 0xab);
        let der = encode_der(&raw);
        assert_eq!(&der[..3], &[0x04, 0x41, 0x04]);
        assert_eq!(der.len(), 67);
    }

    #[test]
    fn encode_p384_uses_short_form() {
        let raw = uncompressed(97, 0xe7);
        let der = encode_der(&raw);
        assert_eq!(&der[..3], &[0x04, 0x61, 0x04]);
        assert_eq!(der.len(), 99);
    }

    #[test]
    fn encode_p521_uses_long_form() {
        let raw = uncompressed(133, 0x01);
        let der = encode_der(&raw);
        assert_eq!(&der[..4], &[0x04, 0x81, 0x85, 0x04]);
        assert_eq!(der.len(), 136);
    }

    #[test]
    fn decode_round_trips_all_supported_lengths() {
        for &len in RAW_POINT_LENGTHS {
            let raw = uncompressed(len, 0x5a);
            assert_eq!(decode(&encode_der(&raw)), raw.as_slice(), "len {len}");
        }
    }

    #[test]
    fn decode_passes_raw_points_through() {
        for &len in RAW_POINT_LENGTHS {
            let raw = uncompressed(len, 0x5a);
            assert_eq!(decode(&raw), raw.as_slice(), "len {len}");
        }
    }

    #[test]
    fn decode_does_not_misread_raw_point_that_looks_like_der_header() {
        // Raw P-256 point whose X starts with 0x3f: `04 3f ...` is a
        // well-formed 63-byte OCTET STRING, but 63 is not a point length.
        let mut raw = uncompressed(65, 0x11);
        raw[1] = 0x3f;
        assert_eq!(decode(&raw), raw.as_slice());

        // Raw Ed25519 key that happens to begin `04 1e`.
        let mut ed = vec![0x22; 32];
        ed[0] = 0x04;
        ed[1] = 0x1e;
        assert_eq!(decode(&ed), ed.as_slice());
    }

    #[test]
    fn decode_rejects_non_minimal_length() {
        // 0x81 0x41 is a non-DER (BER long-form) encoding of length 65.
        let raw = uncompressed(65, 0x33);
        let mut ber = vec![0x04, 0x81, 0x41];
        ber.extend_from_slice(&raw);
        assert_eq!(decode(&ber), ber.as_slice());
    }
}
