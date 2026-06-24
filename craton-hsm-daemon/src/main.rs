// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Craton HSM Network Daemon — gRPC over TLS for remote HSM access.

mod config;
mod server;
mod tls;

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tonic::transport::Server;
use tower::limit::ConcurrencyLimitLayer;

pub mod proto {
    tonic::include_proto!("craton_hsm");
}

use proto::hsm_service_server::HsmServiceServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install the default rustls CryptoProvider before any TLS operations.
    // Both `ring` and `aws-lc-rs` features are enabled; we must choose one explicitly.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls CryptoProvider");

    // Initialize tracing
    tracing_subscriber::fmt().with_target(false).init();

    // (#10-fix) Canonicalize config path to prevent symlink attacks and
    // provide clear error messages with absolute paths.
    let raw_config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "craton_hsm.toml".to_string());

    let config_path = match std::fs::canonicalize(&raw_config_path) {
        Ok(canonical) => {
            // Warn if the path is a symlink (potential substitution attack)
            if std::fs::symlink_metadata(&raw_config_path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                tracing::warn!(
                    "Config path '{}' is a symlink — resolved to '{}'. \
                     Verify this is the intended config file.",
                    raw_config_path,
                    canonical.display()
                );
            }
            canonical.to_string_lossy().to_string()
        }
        Err(_) => {
            // File doesn't exist yet — use as-is (FullConfig::load will produce
            // a clear error for missing files).
            raw_config_path
        }
    };

    let full_config = config::FullConfig::load(&config_path).unwrap_or_else(|e| {
        tracing::error!("{}", e);
        std::process::exit(1);
    });
    let hsm_config = HsmConfig::load_from_path(&config_path).unwrap_or_else(|e| {
        tracing::error!("HSM config loading/validation failed: {}", e);
        std::process::exit(1);
    });
    if let Err(e) = hsm_config.validate() {
        tracing::error!("HSM config validation failed: {}", e);
        std::process::exit(1);
    }

    // Run FIPS POST
    if let Err(e) = craton_hsm::crypto::self_test::run_post() {
        tracing::error!("FIPS POST self-tests failed: {:?}", e);
        std::process::exit(1);
    }
    tracing::info!("FIPS POST self-tests passed");

    // Initialize HsmCore
    let hsm = Arc::new(HsmCore::new(&hsm_config));

    let service = server::HsmServiceImpl::new(
        hsm,
        full_config.daemon.max_random_length,
        full_config.daemon.max_digest_length,
        full_config.daemon.max_login_attempts,
        full_config.daemon.login_cooldown_secs,
    );
    let addr = full_config.daemon.bind.parse()?;

    tracing::info!("Craton HSM daemon listening on {}", addr);

    // gRPC message size limits (#12) — 4 MiB inbound, 16 MiB outbound
    let svc = HsmServiceServer::new(service)
        .max_decoding_message_size(4 * 1024 * 1024)
        .max_encoding_message_size(16 * 1024 * 1024);

    // (#15) Connection limits and request timeout
    let request_timeout = Duration::from_secs(full_config.daemon.request_timeout_secs);
    let max_connections = full_config.daemon.max_connections as usize;
    let mut server = Server::builder()
        .timeout(request_timeout)
        .concurrency_limit_per_connection(64)
        // (#22) Enforce max_connections — previously configured but never applied.
        // This layer limits the total number of concurrent in-flight requests
        // across all connections, preventing connection exhaustion DoS.
        .layer(ConcurrencyLimitLayer::new(max_connections));

    // Configure TLS — mandatory for production security
    if let (Some(cert), Some(key)) = (&full_config.daemon.tls_cert, &full_config.daemon.tls_key) {
        // (#2-fix) Build the rustls ServerConfig directly via tls module, which
        // enforces TLS 1.3 minimum, mTLS with client CA, and CRL revocation
        // checking. Previously, a validated config was built but discarded, and
        // tonic's built-in ServerTlsConfig was used instead — which does NOT
        // enforce TLS 1.3 or apply CRL checking.
        let rustls_config = tls::load_tls_config(
            cert,
            key,
            full_config.daemon.tls_client_ca.as_deref(),
            full_config.daemon.tls_client_crl.as_deref(),
        )?;

        // Wrap the ServerConfig in an ArcSwap so SIGHUP and the CRL refresh
        // timer can atomically replace it. New TLS handshakes use the latest
        // config; already-established connections keep their original TLS
        // state (rustls clones the Arc into each ClientConnection on accept).
        let config_swap: Arc<ArcSwap<ServerConfig>> =
            Arc::new(ArcSwap::from(Arc::new(rustls_config)));

        // (#11) Do NOT log the TLS key path — it reveals filesystem layout
        tracing::info!("TLS enabled (cert: {}, TLS 1.3 enforced)", cert);

        // Spawn the SIGHUP reload task (Unix only — Windows has no SIGHUP).
        // On signal, re-read cert/key/CA/CRL and swap the active config. A
        // reload failure logs an error and keeps the old config in place so
        // the daemon stays up across operator mistakes.
        spawn_sighup_reload(
            config_swap.clone(),
            cert.clone(),
            key.clone(),
            full_config.daemon.tls_client_ca.clone(),
            full_config.daemon.tls_client_crl.clone(),
        );

        // Spawn the CRL refresh timer when a CRL is configured and refresh
        // is enabled. Without it, a freshly revoked client cert is only
        // honored after the next SIGHUP / restart.
        if full_config.daemon.tls_client_crl.is_some() && full_config.daemon.crl_refresh_secs > 0 {
            spawn_crl_refresh(
                config_swap.clone(),
                cert.clone(),
                key.clone(),
                full_config.daemon.tls_client_ca.clone(),
                full_config.daemon.tls_client_crl.clone(),
                Duration::from_secs(full_config.daemon.crl_refresh_secs),
            );
        }

        // Bind a TCP listener and wrap accepted connections with TLS using
        // the *current* swapped config. The resulting stream of TLS
        // connections is passed to tonic's serve_with_incoming_shutdown.
        let listener = TcpListener::bind(addr).await?;
        let accept_swap = config_swap.clone();

        let incoming = async_stream::stream! {
            loop {
                match listener.accept().await {
                    Ok((tcp, remote_addr)) => {
                        // Fetch the current config per-connection so reloads
                        // take effect for new handshakes without disturbing
                        // already-established sessions.
                        let acceptor = TlsAcceptor::from(accept_swap.load_full());
                        match acceptor.accept(tcp).await {
                            Ok(tls_stream) => yield Ok(tls_stream),
                            Err(e) => {
                                tracing::debug!(
                                    remote_addr = %remote_addr,
                                    error = %e,
                                    "TLS handshake failed"
                                );
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "TCP accept failed");
                        yield Err(e);
                    }
                }
            }
        };
        tokio::pin!(incoming);

        server
            .add_service(svc)
            .serve_with_incoming_shutdown(incoming, shutdown_signal())
            .await?;
    } else if full_config.daemon.allow_insecure {
        // (#10) Refuse insecure mode on non-loopback addresses
        if !full_config.daemon.is_loopback_bind() {
            tracing::error!(
                "allow_insecure = true is only permitted on loopback addresses \
                 (127.0.0.1 / [::1]). Bind address '{}' is not loopback. \
                 Either bind to a loopback address or configure TLS.",
                full_config.daemon.bind
            );
            std::process::exit(1);
        }

        // (#1) Only allow plaintext if explicitly opted in
        tracing::error!(
            "TLS disabled — the daemon is running WITHOUT encryption or authentication. \
             This is a CRITICAL security risk. Set allow_insecure = false and configure \
             tls_cert / tls_key in [daemon] for production."
        );

        server
            .add_service(svc)
            .serve_with_shutdown(addr, shutdown_signal())
            .await?;
    } else {
        // (#1) Refuse to start without TLS
        tracing::error!(
            "TLS not configured and allow_insecure is false. \
             Configure tls_cert and tls_key in [daemon], or set \
             allow_insecure = true for development only."
        );
        std::process::exit(1);
    }

    Ok(())
}

/// Graceful shutdown on SIGINT (Ctrl-C) on all platforms and SIGTERM on Unix.
///
/// systemd sends SIGTERM by default for `systemctl stop`; without an explicit
/// handler tokio's runtime would let the process exit immediately and drop
/// in-flight RPCs. Wiring SIGTERM into the same shutdown future as Ctrl-C
/// makes `serve_with_incoming_shutdown` drain connections gracefully.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to install SIGTERM handler — falling back to Ctrl-C only"
                );
                let _ = tokio::signal::ctrl_c().await;
                tracing::info!("Shutdown signal received, draining connections...");
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("SIGINT received, draining connections...");
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received, draining connections...");
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Shutdown signal received, draining connections...");
    }
}

/// Spawn the SIGHUP reload task on Unix. On Windows this is a no-op — the
/// platform has no SIGHUP, and operators can restart the service to pick up
/// rotated certificates.
#[cfg(unix)]
fn spawn_sighup_reload(
    config_swap: Arc<ArcSwap<ServerConfig>>,
    cert: String,
    key: String,
    client_ca: Option<String>,
    client_crl: Option<String>,
) {
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "Failed to install SIGHUP handler");
                return;
            }
        };
        while sighup.recv().await.is_some() {
            tracing::info!("SIGHUP received — reloading TLS material");
            match tls::load_tls_config(&cert, &key, client_ca.as_deref(), client_crl.as_deref()) {
                Ok(new_config) => {
                    config_swap.store(Arc::new(new_config));
                    tracing::info!("TLS config reloaded successfully");
                }
                Err(e) => {
                    // Keep the previous config — a half-reloaded daemon
                    // would refuse all new clients if we cleared it.
                    tracing::error!(
                        error = %e,
                        "TLS reload failed — keeping previous config"
                    );
                }
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup_reload(
    _config_swap: Arc<ArcSwap<ServerConfig>>,
    _cert: String,
    _key: String,
    _client_ca: Option<String>,
    _client_crl: Option<String>,
) {
    // SIGHUP does not exist on Windows. Operators rotate TLS material by
    // restarting the service (the Windows Service Control Manager
    // delivers a stop event which we honor via ctrl_c).
}

/// Spawn the periodic CRL refresh task. Re-reads the CRL file at the
/// configured interval and rebuilds the full `ServerConfig` (CRL data is
/// baked into the `WebPkiClientVerifier`, so a partial update is not
/// possible). On read or parse failure the previous config is retained.
fn spawn_crl_refresh(
    config_swap: Arc<ArcSwap<ServerConfig>>,
    cert: String,
    key: String,
    client_ca: Option<String>,
    client_crl: Option<String>,
    interval: Duration,
) {
    tracing::info!("CRL refresh enabled (every {}s)", interval.as_secs());
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip the immediate tick — the initial config was just loaded.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match tls::load_tls_config(&cert, &key, client_ca.as_deref(), client_crl.as_deref()) {
                Ok(new_config) => {
                    config_swap.store(Arc::new(new_config));
                    tracing::debug!("CRL refresh: TLS config reloaded");
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "CRL refresh failed — keeping previous config"
                    );
                }
            }
        }
    });
}
