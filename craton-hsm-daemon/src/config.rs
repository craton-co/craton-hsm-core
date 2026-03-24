// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Daemon configuration.

use serde::Deserialize;
use std::net::SocketAddr;

/// Configuration for the daemon, loaded from [daemon] section of craton_hsm.toml.
#[derive(Debug, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// Path to a PEM file containing the CA certificate(s) used to verify
    /// client certificates (mutual TLS). When set, clients must present a
    /// certificate signed by this CA. Strongly recommended for production.
    pub tls_client_ca: Option<String>,
    /// Path to a PEM/DER file containing Certificate Revocation Lists (CRLs)
    /// for client certificate validation. Only effective when tls_client_ca is set.
    pub tls_client_crl: Option<String>,
    /// Maximum allowed length for GenerateRandom requests (bytes).
    /// Prevents denial-of-service via unbounded allocation. Default: 1 MiB.
    #[serde(default = "default_max_random_length")]
    pub max_random_length: u32,
    /// Maximum allowed data length for Digest requests (bytes).
    /// Prevents CPU exhaustion via large hash payloads. Default: 16 MiB.
    #[serde(default = "default_max_digest_length")]
    pub max_digest_length: u32,
    /// Allow running without TLS. Must be explicitly set to true.
    /// Default: false (TLS is mandatory).
    #[serde(default)]
    pub allow_insecure: bool,
    /// Maximum failed login attempts before the daemon imposes a cooldown.
    /// Default: 5. Set to 0 to disable daemon-level lockout (relies on token).
    ///
    /// **IMPORTANT:** This throttle is in-memory only and resets on daemon restart.
    /// An attacker who can restart the daemon (e.g., by crashing it) bypasses
    /// this limit. Token-level PIN retry counters provide persistent lockout
    /// that survives restarts. For RAM-only token deployments (no persistent
    /// storage), configure an external rate limiter or OS-level restart
    /// throttling (e.g., systemd `RestartSec=30`, `StartLimitBurst=3`).
    #[serde(default = "default_max_login_attempts")]
    pub max_login_attempts: u32,
    /// Cooldown duration in seconds after max_login_attempts is exceeded.
    /// Default: 60 seconds.
    #[serde(default = "default_login_cooldown_secs")]
    pub login_cooldown_secs: u64,
    /// Maximum concurrent connections. Default: 256.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Per-request timeout in seconds. Default: 30.
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
}

fn default_bind() -> String {
    "127.0.0.1:5696".to_string()
}

fn default_max_random_length() -> u32 {
    1_048_576 // 1 MiB
}

fn default_max_digest_length() -> u32 {
    16_777_216 // 16 MiB
}

fn default_max_login_attempts() -> u32 {
    5
}

fn default_login_cooldown_secs() -> u64 {
    60
}

fn default_max_connections() -> u32 {
    256
}

fn default_request_timeout_secs() -> u64 {
    30
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            tls_cert: None,
            tls_key: None,
            tls_client_ca: None,
            tls_client_crl: None,
            max_random_length: default_max_random_length(),
            max_digest_length: default_max_digest_length(),
            allow_insecure: false,
            max_login_attempts: default_max_login_attempts(),
            login_cooldown_secs: default_login_cooldown_secs(),
            max_connections: default_max_connections(),
            request_timeout_secs: default_request_timeout_secs(),
        }
    }
}

impl DaemonConfig {
    /// (#23) Returns true if the bind address is a loopback address.
    /// (#6-fix) Only trusts parsed IP addresses, never hostnames. The string
    /// "localhost" can resolve to a non-loopback address on systems with a
    /// poisoned /etc/hosts or misconfigured DNS. Requiring an explicit IP
    /// (127.0.0.1 or [::1]) eliminates this risk entirely.
    pub fn is_loopback_bind(&self) -> bool {
        match self.bind.parse::<SocketAddr>() {
            Ok(addr) => addr.ip().is_loopback(),
            Err(_) => {
                // (#6-fix) Reject hostnames — only IP-based SocketAddr is trusted.
                // "localhost" could resolve to a non-loopback address on misconfigured
                // systems. Callers must use 127.0.0.1:port or [::1]:port.
                tracing::warn!(
                    "Bind address '{}' is not a valid IP:port — cannot verify loopback. \
                     Use 127.0.0.1:port or [::1]:port for insecure mode.",
                    self.bind
                );
                false
            }
        }
    }
}

/// Full config file structure (extends craton_hsm.toml with [daemon] section).
#[derive(Debug, Deserialize)]
pub struct FullConfig {
    #[serde(default)]
    pub daemon: DaemonConfig,
}

impl FullConfig {
    /// Load config from a TOML file path.
    /// Returns an error if the file exists but cannot be parsed (fail-closed).
    pub fn load(path: &str) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents).map_err(|e| {
                format!(
                    "Failed to parse config '{}': {}. \
                     Refusing to start with potentially incorrect settings.",
                    path, e
                )
            }),
            // (#12-fix) Missing config is a fatal error. The daemon cannot operate
            // securely without explicit TLS configuration, and silently falling back
            // to defaults masks deployment errors.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(format!(
                "Config file '{}' not found. Create an explicit config file with \
                     TLS settings (tls_cert, tls_key) in the [daemon] section.",
                path
            )),
            Err(e) => Err(format!("Failed to read config '{}': {}", path, e)),
        }
    }
}
