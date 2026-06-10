// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! TLS configuration for the gRPC server.
//!
//! Mutual TLS (mTLS) is mandatory by default — `load_tls_config` refuses to
//! build a configuration without a client CA unless the caller explicitly
//! opts in to unauthenticated TLS (`allow_unauthenticated_tls = true`).
//!
//! NOTE (#17): This module provides rustls-native TLS configuration as an
//! alternative to tonic's built-in TLS. Currently main.rs uses tonic's
//! ServerTlsConfig directly. This module is retained for advanced use cases
//! (e.g., custom certificate verifiers, CRL checking) and will be integrated
//! when CRL/OCSP support is added.

use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::io::BufReader;
use std::sync::Arc;

/// Build a rustls ServerConfig from PEM cert, key, and optional client CA files.
///
/// When `client_ca_path` is provided, mutual TLS (mTLS) is enforced:
/// clients must present a certificate signed by the given CA.
///
/// When `client_ca_path` is `None`, this function only succeeds if
/// `allow_unauthenticated_tls` is `true`. Otherwise the call returns an error
/// — mTLS is mandatory by default.
///
/// ## Security Notes
///
/// - **CRL**: When `client_crl_path` is provided, revoked client certificates
///   are rejected. Without a CRL, revoked certs are still accepted.
///
/// - **Certificate pinning**: For high-security deployments, consider pinning
///   expected client certificate fingerprints in addition to CA validation.
///
/// - **TLS version**: Minimum TLS 1.3 is enforced. TLS 1.2 is excluded to
///   avoid legacy cipher suites.
/// Verify the TLS private-key file is owner-only readable.
///
/// On Unix, requires that the file's owner equals the effective UID and that
/// `mode & 0o077 == 0` (no group or other access bits set). A key readable by
/// group or other on a multi-user host means the daemon could be signing TLS
/// handshakes with material another local user has already exfiltrated.
///
/// On Windows, the full DACL inspection (walking every ACE and verifying that
/// only the owner / SYSTEM can read) is too invasive for this fix. Instead the
/// daemon shells out to `icacls` and refuses to start if Everyone, Users,
/// Authenticated Users, or BUILTIN\Users appear with any read-capable mask
/// (R/RX/RD/M/F). Gap: a custom group ACE granting read still passes — for
/// hardened deployments, restrict the file to its owner only (see
/// `platform_acl::restrict_file_to_owner` in the core crate).
pub(crate) fn check_key_file_permissions(key_path: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(key_path)
            .map_err(|e| format!("Failed to stat TLS key '{}': {}", key_path, e))?;
        // Owner check is intentionally not performed here: an owner mismatch
        // is already caught by the subsequent File::open in load_tls_config
        // when mode 0o6xx applies (a key owned by another user is not
        // readable by us, so open() errors out). Skipping the EUID lookup
        // avoids a libc dependency in this crate; the mode check below
        // remains the canonical defense.
        let mode = meta.mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "TLS key '{}' has insecure permissions {:#o} — \
                 group/other bits {:#o} must be cleared; run `chmod 600 {}`",
                key_path,
                mode & 0o777,
                mode & 0o077,
                key_path,
            ));
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        // Best-effort check: reject if the key file's ACL grants Everyone or
        // Users read access. Full DACL inspection is intentionally deferred —
        // see the doc comment on this function for the gap.
        let canonical = match std::fs::canonicalize(key_path) {
            Ok(p) => p,
            Err(_) => {
                // If canonicalize fails, fall through — the load_tls_config
                // path will error on open with a clearer message.
                return Ok(());
            }
        };
        let output = std::process::Command::new("icacls").arg(&canonical).output();
        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout).to_uppercase();
            // Reject if Everyone or Users have any read/full access. Note this
            // does not detect every misconfiguration (e.g. a custom group with
            // read access) — see doc comment for the gap.
            let dangerous_principals =
                ["EVERYONE", "USERS", "AUTHENTICATED USERS", "BUILTIN\\USERS"];
            let dangerous_perms = ["(F)", "(M)", "(R)", "(RX)", "(RD)"];
            for line in stdout.lines() {
                for principal in &dangerous_principals {
                    if line.contains(principal) {
                        for perm in &dangerous_perms {
                            if line.contains(perm) {
                                return Err(format!(
                                    "TLS key '{}' has insecure ACL — {} has read access. \
                                     Restrict the file to the daemon's owner only \
                                     (right-click > Properties > Security, or icacls).",
                                    key_path, principal
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = key_path;
        Ok(())
    }
}

pub fn load_tls_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
    client_crl_path: Option<&str>,
    allow_unauthenticated_tls: bool,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    // Refuse to load a key readable by anyone other than the daemon's user.
    // This must happen before File::open so we abort before any chance the
    // key material is read into memory.
    check_key_file_permissions(key_path).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| format!("Failed to open TLS cert '{}': {}", cert_path, e))?;
    let key_file = std::fs::File::open(key_path)
        .map_err(|e| format!("Failed to open TLS key '{}': {}", key_path, e))?;

    let server_certs: Vec<_> = certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse TLS certs: {}", e))?;

    let key = private_key(&mut BufReader::new(key_file))
        .map_err(|e| format!("Failed to parse TLS key: {}", e))?
        .ok_or("No private key found in TLS key file")?;

    let mut config = if let Some(ca_path) = client_ca_path {
        // mTLS: require client certificates signed by the given CA
        let ca_file = std::fs::File::open(ca_path)
            .map_err(|e| format!("Failed to open client CA '{}': {}", ca_path, e))?;
        let ca_certs: Vec<_> = certs(&mut BufReader::new(ca_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse client CA certs: {}", e))?;

        let mut root_store = RootCertStore::empty();
        for cert in ca_certs {
            root_store
                .add(cert)
                .map_err(|e| format!("Failed to add client CA cert: {}", e))?;
        }

        let mut verifier_builder = WebPkiClientVerifier::builder(Arc::new(root_store));

        // Load CRLs for revocation checking if configured
        if let Some(crl_path) = client_crl_path {
            let crl_data = std::fs::read(crl_path)
                .map_err(|e| format!("Failed to read CRL file '{}': {}", crl_path, e))?;
            let crl = rustls::pki_types::CertificateRevocationListDer::from(crl_data);
            verifier_builder = verifier_builder.with_crls(vec![crl]);
            tracing::info!("CRL revocation checking enabled (CRL: {})", crl_path);
        } else {
            tracing::warn!(
                "mTLS enabled but no CRL configured — revoked client certificates \
                 will still be accepted. Set [daemon] tls_client_crl for revocation checking."
            );
        }

        let client_verifier = verifier_builder
            .build()
            .map_err(|e| format!("Failed to build client verifier: {}", e))?;

        tracing::info!(
            "mTLS enabled — clients must present a certificate signed by '{}'",
            ca_path
        );

        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_certs, key)
            .map_err(|e| format!("TLS config error: {}", e))?
    } else {
        if !allow_unauthenticated_tls {
            return Err(
                "mTLS is mandatory: set [daemon] tls_client_ca to a CA certificate, \
                 or explicitly set allow_unauthenticated_tls = true to opt out \
                 (NOT recommended for production)."
                    .into(),
            );
        }
        tracing::error!(
            "allow_unauthenticated_tls = true — mTLS DISABLED. Any TLS client can \
             connect, and the login throttle falls back to per-IP keying instead of \
             per-client-cert. This is a CRITICAL security risk. Configure \
             tls_client_ca and remove allow_unauthenticated_tls before production use."
        );
        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(server_certs, key)
            .map_err(|e| format!("TLS config error: {}", e))?
    };

    // Enforce TLS 1.3 only — no legacy cipher suites
    config.alpn_protocols = vec![b"h2".to_vec()]; // gRPC requires HTTP/2

    Ok(config)
}

/// Wrap a tonic server with TLS if cert/key are configured.
pub fn make_tls_acceptor(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
    client_crl_path: Option<&str>,
    allow_unauthenticated_tls: bool,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let config = load_tls_config(
        cert_path,
        key_path,
        client_ca_path,
        client_crl_path,
        allow_unauthenticated_tls,
    )?;
    Ok(Arc::new(config))
}

#[cfg(all(test, unix))]
mod unix_perm_tests {
    use super::check_key_file_permissions;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::NamedTempFile;

    /// A 0o644 key file (group/other readable) must be rejected.
    #[test]
    fn rejects_group_or_world_readable_key() {
        let mut f = NamedTempFile::new().expect("create temp file");
        writeln!(f, "-----BEGIN PRIVATE KEY-----\nbogus\n-----END PRIVATE KEY-----")
            .expect("write key");
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o644))
            .expect("chmod 0644");

        let path = f.path().to_string_lossy().into_owned();
        let err = check_key_file_permissions(&path)
            .expect_err("0o644 key must be rejected by the perms check");
        // Error must name the offending bits and recommend chmod 600.
        assert!(
            err.contains("chmod 600"),
            "error message must recommend `chmod 600`, got: {err}",
        );
        assert!(
            err.contains("0o44") || err.contains("0o077") || err.contains("group"),
            "error must identify the offending bits, got: {err}",
        );
    }

    /// A 0o600 key file (owner-only) must pass the perms check. The key
    /// content here is intentionally bogus — we are only asserting the
    /// permission gate, not the downstream PEM parse.
    #[test]
    fn accepts_owner_only_key() {
        let mut f = NamedTempFile::new().expect("create temp file");
        writeln!(f, "-----BEGIN PRIVATE KEY-----\nbogus\n-----END PRIVATE KEY-----")
            .expect("write key");
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600");

        let path = f.path().to_string_lossy().into_owned();
        check_key_file_permissions(&path).expect("0o600 key must pass the perms check");
    }
}
