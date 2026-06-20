// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Daemon configuration.

use serde::Deserialize;

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
    ///
    /// **SECURITY:** On Unix, `allow_insecure = true` now binds a Unix domain
    /// socket (UDS) at `bind_unix` with mode 0600 instead of plaintext TCP.
    /// This authenticates the calling user via filesystem permissions, so any
    /// local user/process other than the daemon's owner is refused at the
    /// socket layer. On Windows, `allow_insecure` is refused outright — there
    /// is no equivalent of SO_PEERCRED, so TLS is the only safe option.
    #[serde(default)]
    pub allow_insecure: bool,
    /// Unix domain socket path used when `allow_insecure = true` on Unix.
    /// The socket file is created with mode 0600 (owner read/write only),
    /// ensuring only the daemon's UID can connect. If unset, defaults to
    /// `$XDG_RUNTIME_DIR/craton-hsm.sock` (or `/tmp/craton-hsm-<uid>.sock`
    /// when `XDG_RUNTIME_DIR` is not set).
    ///
    /// Ignored when TLS is configured, when `allow_insecure = false`, and
    /// on Windows (where insecure mode is refused outright).
    // Read by `resolved_unix_socket_path` (cfg(unix) only); on Windows the
    // value is still parsed and silently ignored so deployers can share a
    // single TOML across platforms.
    #[cfg_attr(not(unix), allow(dead_code))]
    #[serde(default)]
    pub bind_unix: Option<String>,
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
    /// CRL refresh interval in seconds. When `tls_client_crl` is set, a
    /// background task re-reads the CRL file at this interval and atomically
    /// swaps the TLS `ServerConfig` so revoked clients are rejected without
    /// a daemon restart. Default: 300 (5 minutes). Set to 0 to disable
    /// automatic CRL refresh (operators must SIGHUP after rotating the CRL).
    #[serde(default = "default_crl_refresh_secs")]
    pub crl_refresh_secs: u64,
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

fn default_crl_refresh_secs() -> u64 {
    300
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
            bind_unix: None,
            max_login_attempts: default_max_login_attempts(),
            login_cooldown_secs: default_login_cooldown_secs(),
            max_connections: default_max_connections(),
            request_timeout_secs: default_request_timeout_secs(),
            crl_refresh_secs: default_crl_refresh_secs(),
        }
    }
}

impl DaemonConfig {
    /// (#23) Returns true if the bind address is a loopback address.
    /// (#6-fix) Only trusts parsed IP addresses, never hostnames. The string
    /// "localhost" can resolve to a non-loopback address on systems with a
    /// poisoned /etc/hosts or misconfigured DNS. Requiring an explicit IP
    /// (127.0.0.1 or [::1]) eliminates this risk entirely.
    /// Resolve the effective Unix domain socket path used for insecure mode.
    ///
    /// Resolution order:
    /// 1. `bind_unix` from config, if set.
    /// 2. `$XDG_RUNTIME_DIR/craton-hsm.sock`, if `XDG_RUNTIME_DIR` is set.
    /// 3. `/tmp/craton-hsm-<uid>.sock` as a last-resort fallback (the
    ///    `<uid>` suffix prevents collisions between users on shared hosts).
    ///
    /// Only meaningful on Unix; on Windows we refuse `allow_insecure` before
    /// this is consulted.
    #[cfg(unix)]
    pub fn resolved_unix_socket_path(&self) -> std::path::PathBuf {
        if let Some(path) = &self.bind_unix {
            return std::path::PathBuf::from(path);
        }
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            if !runtime_dir.is_empty() {
                return std::path::PathBuf::from(runtime_dir).join("craton-hsm.sock");
            }
        }
        // Last-resort fallback. Tag with the daemon's UID so per-user instances
        // do not collide on shared hosts. SAFETY: getuid is async-signal-safe
        // and always succeeds on POSIX.
        let uid = unsafe { libc::getuid() };
        std::path::PathBuf::from(format!("/tmp/craton-hsm-{}.sock", uid))
    }

    // NOTE: `is_loopback_bind` previously guarded the deprecated insecure
    // loopback-TCP path. With `allow_insecure = true` now binding a UDS
    // (Unix) or being refused outright (Windows), there is no remaining
    // caller, so the helper was removed. If a future feature needs to
    // detect loopback bind addresses, restore from git history.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `bind_unix` parses from TOML on every platform — only the *use* of the
    /// value is Unix-gated. This lets deployers share a single config file.
    #[test]
    fn bind_unix_parses_from_toml() {
        let toml = r#"
            [daemon]
            bind = "127.0.0.1:5696"
            bind_unix = "/var/run/craton-hsm.sock"
            allow_insecure = true
        "#;
        let cfg: FullConfig = toml::from_str(toml).expect("parse");
        assert_eq!(
            cfg.daemon.bind_unix.as_deref(),
            Some("/var/run/craton-hsm.sock")
        );
        assert!(cfg.daemon.allow_insecure);
    }

    #[test]
    fn bind_unix_defaults_to_none() {
        let toml = r#"
            [daemon]
            bind = "127.0.0.1:5696"
        "#;
        let cfg: FullConfig = toml::from_str(toml).expect("parse");
        assert!(cfg.daemon.bind_unix.is_none());
    }

    /// When `bind_unix` is explicitly set, `resolved_unix_socket_path` returns
    /// it verbatim — XDG_RUNTIME_DIR and the /tmp fallback must not be
    /// consulted. This is the contract callers rely on for predictable paths.
    #[cfg(unix)]
    #[test]
    fn resolved_path_honors_explicit_bind_unix() {
        let cfg = DaemonConfig {
            bind_unix: Some("/run/my-custom.sock".to_string()),
            ..DaemonConfig::default()
        };
        // Set XDG_RUNTIME_DIR to verify explicit bind_unix still wins.
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1234");
        assert_eq!(
            cfg.resolved_unix_socket_path(),
            std::path::PathBuf::from("/run/my-custom.sock")
        );
    }

    /// Without an explicit `bind_unix`, fall back to `$XDG_RUNTIME_DIR`.
    /// systemd sets XDG_RUNTIME_DIR to a per-user 0700 dir, which is the
    /// idiomatic location for short-lived service sockets.
    #[cfg(unix)]
    #[test]
    fn resolved_path_uses_xdg_runtime_dir_when_unset() {
        let cfg = DaemonConfig {
            bind_unix: None,
            ..DaemonConfig::default()
        };
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/9999");
        assert_eq!(
            cfg.resolved_unix_socket_path(),
            std::path::PathBuf::from("/run/user/9999/craton-hsm.sock")
        );
    }

    /// When neither `bind_unix` nor `XDG_RUNTIME_DIR` is available, fall
    /// back to /tmp with the UID suffixed so different users on a shared
    /// host don't collide on the same path. The suffix also means an
    /// attacker can't pre-create the path under their UID to confuse us
    /// (their /tmp/craton-hsm-<their-uid>.sock is a different path).
    #[cfg(unix)]
    #[test]
    fn resolved_path_falls_back_to_uid_tagged_tmp() {
        let cfg = DaemonConfig {
            bind_unix: None,
            ..DaemonConfig::default()
        };
        std::env::remove_var("XDG_RUNTIME_DIR");
        let path = cfg.resolved_unix_socket_path();
        let s = path.to_string_lossy();
        assert!(s.starts_with("/tmp/craton-hsm-"), "got {}", s);
        assert!(s.ends_with(".sock"), "got {}", s);
    }
}
