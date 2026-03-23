// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! TLS configuration for the gRPC server.
//!
//! Supports mutual TLS (mTLS) when a client CA is configured.
//! Without mTLS, any TLS client can connect — a warning is logged.
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
pub fn load_tls_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
    client_crl_path: Option<&str>,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
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
        tracing::warn!(
            "No client CA configured — mTLS disabled. Any TLS client can connect. \
             Set [daemon] tls_client_ca to enforce mutual TLS."
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
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let config = load_tls_config(cert_path, key_path, client_ca_path, client_crl_path)?;
    Ok(Arc::new(config))
}
