// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Craton HSM Network Daemon — gRPC over TLS for remote HSM access.

mod config;
mod server;
mod tls;

use std::sync::Arc;
use std::time::Duration;

use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;
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
    let addr: std::net::SocketAddr = full_config.daemon.bind.parse()?;

    // Per-listener startup log lives in each branch below — TCP+TLS logs the
    // bound address, and the UDS path (when allow_insecure=true on Unix) logs
    // the socket path. We avoid logging `addr` here because in UDS mode it is
    // a parsed-but-unused fallback.

    // gRPC message size limits (#12) — 4 MiB inbound, 16 MiB outbound
    let svc = HsmServiceServer::new(service)
        .max_decoding_message_size(4 * 1024 * 1024)
        .max_encoding_message_size(16 * 1024 * 1024);

    // (#15) Connection limits and request timeout
    let request_timeout = Duration::from_secs(full_config.daemon.request_timeout_secs);
    let max_connections = full_config.daemon.max_connections as usize;
    let h2_keepalive_interval =
        Duration::from_secs(full_config.daemon.http2_keepalive_interval_secs);
    let h2_keepalive_timeout = Duration::from_secs(full_config.daemon.http2_keepalive_timeout_secs);
    let tcp_keepalive = Duration::from_secs(full_config.daemon.tcp_keepalive_secs);
    let max_concurrent_streams = full_config.daemon.max_concurrent_streams;
    let mut server = Server::builder()
        .timeout(request_timeout)
        .concurrency_limit_per_connection(64)
        // (#22) Enforce max_connections — previously configured but never applied.
        // This layer limits the total number of concurrent in-flight requests
        // across all connections, preventing connection exhaustion DoS.
        .layer(ConcurrencyLimitLayer::new(max_connections))
        // Slowloris / HTTP/2 RAPID-RESET defenses: keepalive pings detect
        // dead peers, TCP keepalive trips OS-level abandoned-socket cleanup,
        // and the stream cap bounds per-connection RAPID-RESET amplification.
        .http2_keepalive_interval(Some(h2_keepalive_interval))
        .http2_keepalive_timeout(Some(h2_keepalive_timeout))
        .tcp_keepalive(Some(tcp_keepalive))
        .max_concurrent_streams(Some(max_concurrent_streams));

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
            full_config.daemon.allow_unauthenticated_tls,
        )?;

        let tls_acceptor = TlsAcceptor::from(Arc::new(rustls_config));

        // (#11) Do NOT log the TLS key path — it reveals filesystem layout
        tracing::info!(
            "TLS enabled — daemon listening on {} (cert: {}, TLS 1.3 enforced)",
            addr,
            cert
        );

        // Bind a TCP listener and wrap accepted connections with TLS using our
        // validated rustls config (TLS 1.3, mTLS, CRL). Each TLS handshake is
        // performed inside its own tokio task with a timeout, so a slow / stuck
        // client cannot block the accept loop for everyone else and cannot tie
        // up an accept slot indefinitely. Completed TLS streams are funneled
        // back to the accept stream via an mpsc channel.
        let listener = TcpListener::bind(addr).await?;
        let handshake_timeout = Duration::from_secs(full_config.daemon.tls_handshake_timeout_secs);

        type AcceptItem =
            Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, std::io::Error>;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<AcceptItem>(max_connections);

        // Spawn the accept loop in its own task. It only does cheap work
        // (accept + spawn) and never awaits a handshake itself.
        {
            let tls_acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((tcp, remote_addr)) => {
                            let tls_acceptor = tls_acceptor.clone();
                            let tx = tx.clone();
                            tokio::spawn(async move {
                                match tokio::time::timeout(
                                    handshake_timeout,
                                    tls_acceptor.accept(tcp),
                                )
                                .await
                                {
                                    Ok(Ok(tls_stream)) => {
                                        // Send may fail if the server is shutting
                                        // down; that's fine — the stream is dropped.
                                        let _ = tx.send(Ok(tls_stream)).await;
                                    }
                                    Ok(Err(e)) => {
                                        tracing::info!(
                                            remote_addr = %remote_addr,
                                            error = %e,
                                            "TLS handshake failed"
                                        );
                                    }
                                    Err(_) => {
                                        tracing::info!(
                                            remote_addr = %remote_addr,
                                            timeout_secs = handshake_timeout.as_secs(),
                                            "TLS handshake timed out"
                                        );
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "TCP accept failed");
                            // Backoff briefly to avoid a tight spin on a
                            // persistent accept error (e.g. EMFILE).
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            });
        }

        let incoming = async_stream::stream! {
            while let Some(item) = rx.recv().await {
                yield item;
            }
        };
        tokio::pin!(incoming);

        server
            .add_service(svc)
            .serve_with_incoming_shutdown(incoming, shutdown_signal())
            .await?;
    } else if full_config.daemon.allow_insecure {
        // (#sec-uds) Plaintext loopback TCP is NOT safe: any local user with
        // CAP_NET_RAW (or any local process at all) can read PINs by sniffing
        // `lo` or by simply connecting to the loopback port. Authenticate the
        // caller via the filesystem instead.
        //
        // - Unix: bind a UDS at mode 0600 so only the daemon's UID can connect.
        // - Windows: there is no SO_PEERCRED equivalent for loopback TCP, and
        //   named-pipe ACLs would still leave the loopback TCP listener wide
        //   open. Refuse `allow_insecure` outright and require TLS.
        #[cfg(windows)]
        {
            tracing::error!(
                "allow_insecure = true is not supported on Windows: there is no \
                 equivalent of SO_PEERCRED for loopback TCP, so the listener \
                 cannot authenticate the calling user. Configure tls_cert and \
                 tls_key in [daemon] (TLS is the only safe option on Windows)."
            );
            std::process::exit(1);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            use tokio::net::UnixListener;

            let sock_path = full_config.daemon.resolved_unix_socket_path();

            // (1) Clean up a stale socket from a previous run, but ONLY if the
            // existing path is actually a socket. Refusing to clobber regular
            // files prevents the daemon from accidentally truncating an
            // arbitrary file if `bind_unix` is misconfigured.
            if let Ok(meta) = std::fs::symlink_metadata(&sock_path) {
                use std::os::unix::fs::FileTypeExt;
                if meta.file_type().is_socket() {
                    if let Err(e) = std::fs::remove_file(&sock_path) {
                        tracing::error!(
                            path = %sock_path.display(),
                            error = %e,
                            "Failed to remove stale UDS socket file"
                        );
                        std::process::exit(1);
                    }
                } else {
                    tracing::error!(
                        path = %sock_path.display(),
                        "bind_unix path exists and is NOT a socket — refusing to overwrite. \
                         Remove the file manually or point bind_unix at a clean path."
                    );
                    std::process::exit(1);
                }
            }

            // (2) Atomically create the socket with mode 0600 by setting
            // umask=0o177 before bind(2). Doing chmod *after* bind would
            // leave a window where another local user could connect with
            // the default permissive mode.
            // SAFETY: umask is process-global; we restore it immediately
            // after bind.
            let prev_umask = unsafe { libc::umask(0o177) };
            let listener_result = UnixListener::bind(&sock_path);
            unsafe {
                libc::umask(prev_umask);
            }
            let listener = listener_result.map_err(|e| {
                format!(
                    "Failed to bind UDS '{}': {}. Ensure the parent directory \
                     exists and is writable by the daemon's UID.",
                    sock_path.display(),
                    e
                )
            })?;

            // (3) Defense in depth: verify the resulting file mode. If
            // something defeated the umask (unusual filesystem, ACL),
            // refuse to expose secrets and chmod down to 0600.
            match std::fs::metadata(&sock_path) {
                Ok(meta) => {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode != 0o600 {
                        tracing::warn!(
                            path = %sock_path.display(),
                            actual_mode = format!("{:o}", mode),
                            "UDS socket mode is not 0600 after bind — chmod'ing down"
                        );
                        let perms = std::fs::Permissions::from_mode(0o600);
                        if let Err(e) = std::fs::set_permissions(&sock_path, perms) {
                            tracing::error!(
                                path = %sock_path.display(),
                                error = %e,
                                "Failed to chmod UDS to 0600 — refusing to expose plaintext socket"
                            );
                            let _ = std::fs::remove_file(&sock_path);
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        path = %sock_path.display(),
                        error = %e,
                        "Failed to stat UDS after bind — refusing to expose plaintext socket"
                    );
                    let _ = std::fs::remove_file(&sock_path);
                    std::process::exit(1);
                }
            }

            tracing::warn!(
                "TLS disabled — daemon is serving plaintext gRPC on UDS '{}' \
                 (mode 0600). Only the daemon's UID can connect. For production \
                 deployments configure tls_cert / tls_key in [daemon] and serve \
                 over TCP+TLS instead.",
                sock_path.display()
            );

            // (4) Adapt the listener into a stream of accepted UnixStreams.
            // Tonic implements `Connected` for `tokio::net::UnixStream`
            // directly, so no wrapper type is needed.
            let incoming = async_stream::stream! {
                loop {
                    match listener.accept().await {
                        Ok((stream, _addr)) => yield Ok::<_, std::io::Error>(stream),
                        Err(e) => {
                            tracing::error!(error = %e, "UDS accept failed");
                            yield Err(e);
                        }
                    }
                }
            };
            tokio::pin!(incoming);

            let sock_path_for_cleanup = sock_path.clone();
            let result = server
                .add_service(svc)
                .serve_with_incoming_shutdown(incoming, shutdown_signal())
                .await;

            // Best-effort cleanup of the socket file on shutdown. If this
            // fails, the next start-up will detect+remove it via the
            // stale-socket check above.
            let _ = std::fs::remove_file(&sock_path_for_cleanup);

            result?;
        }
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

/// Graceful shutdown on SIGTERM/SIGINT.
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("Shutdown signal received, draining connections...");
}

