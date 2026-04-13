// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Core HSM state — the central struct shared by C ABI, daemon, and admin CLI.

use std::sync::Arc;

use crate::audit::log::AuditLog;
use crate::config::{AlgorithmConfig, HsmConfig};
use crate::crypto::backend::CryptoBackend;
use crate::crypto::drbg::HmacDrbg;
#[cfg(feature = "rustcrypto-backend")]
use crate::crypto::rustcrypto_backend::RustCryptoBackend;
use crate::session::manager::SessionManager;
use crate::store::attributes::ObjectStore;
use crate::token::slot::SlotManager;
use zeroize::Zeroizing;

/// The global HSM state. Holds all managers needed for PKCS#11 operations.
pub struct HsmCore {
    pub(crate) slot_manager: SlotManager,
    pub(crate) session_manager: SessionManager,
    pub(crate) object_store: ObjectStore,
    pub(crate) audit_log: Arc<AuditLog>,
    pub(crate) crypto_backend: Arc<dyn CryptoBackend>,
    /// SP 800-90A HMAC_DRBG instance for FIPS-compliant random number generation.
    pub(crate) drbg: parking_lot::Mutex<HmacDrbg>,
    /// Algorithm policy configuration (FIPS approved mode, PQC enable, weak RSA, etc.).
    /// Stored at runtime so crypto operations can enforce policy checks.
    pub(crate) algorithm_config: AlgorithmConfig,
    /// Token serial number (configurable, 16-char space-padded).
    pub(crate) serial_number: [u8; 16],
    /// Per-instance HMAC key for authenticating serialized operation state blobs
    /// (C_GetOperationState / C_SetOperationState). Generated randomly at init
    /// time to prevent callers from tampering with saved state (e.g., swapping
    /// key handles or mechanisms).
    pub(crate) state_hmac_key: Zeroizing<[u8; 32]>,
}

impl HsmCore {
    /// Build a 16-byte space-padded serial number from config string.
    fn make_serial(config: &HsmConfig) -> [u8; 16] {
        let mut serial = [b' '; 16];
        let s = config.token.serial_number.as_bytes();
        let len = s.len().min(16);
        serial[..len].copy_from_slice(&s[..len]);
        serial
    }

    /// Select the crypto backend based on config + compiled features.
    ///
    /// The built-in RustCrypto backend is the default. External backends
    /// (e.g., the FIPS-validated aws-lc-rs backend in `craton_hsm-awslc`)
    /// can be injected via [`HsmCore::new_with_backend`].
    fn select_crypto_backend(config: &HsmConfig) -> Arc<dyn CryptoBackend> {
        let requested = config.algorithms.crypto_backend.as_str();

        match requested {
            #[cfg(feature = "awslc-backend")]
            "awslc" => return Arc::new(crate::crypto::awslc_backend::AwsLcBackend),

            #[cfg(not(feature = "awslc-backend"))]
            "awslc" => {
                tracing::warn!(
                    "Config requests 'awslc' backend but awslc-backend feature not compiled. \
                     Use HsmCore::new_with_backend() to inject it. \
                     Falling back to rustcrypto."
                );
            }

            #[cfg(feature = "rustcrypto-backend")]
            "rustcrypto" => return Arc::new(RustCryptoBackend),

            #[cfg(not(feature = "rustcrypto-backend"))]
            "rustcrypto" => {
                tracing::warn!(
                    "Config requests 'rustcrypto' backend but rustcrypto-backend feature not compiled; falling back"
                );
            }

            other => {
                tracing::warn!(
                    "Unknown crypto_backend '{}' in config; using default",
                    other
                );
            }
        }

        // Fallback: prefer awslc-backend if compiled, else rustcrypto
        #[cfg(feature = "awslc-backend")]
        {
            return Arc::new(crate::crypto::awslc_backend::AwsLcBackend);
        }

        #[cfg(all(feature = "rustcrypto-backend", not(feature = "awslc-backend")))]
        {
            return Arc::new(RustCryptoBackend);
        }

        #[cfg(not(any(feature = "rustcrypto-backend", feature = "awslc-backend")))]
        {
            compile_error!(
                "No crypto backend available. Enable the `rustcrypto-backend` or \
                          `awslc-backend` feature, or inject a custom backend via \
                          HsmCore::new_with_backend()."
            );
        }
    }

    /// Create a new HsmCore from a loaded configuration.
    ///
    /// # Panics
    ///
    /// Panics if the HMAC_DRBG cannot be instantiated (OS entropy unavailable).
    /// Use [`HsmCore::try_new`] for a fallible alternative.
    pub fn new(config: &HsmConfig) -> Self {
        Self::try_new(config).expect("DRBG instantiation must succeed (requires OS entropy)")
    }

    /// Generate a random 32-byte key for HMAC-binding operation state blobs.
    fn generate_state_hmac_key() -> Zeroizing<[u8; 32]> {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *key);
        key
    }

    /// Fallible constructor — returns an error if the HMAC_DRBG cannot be
    /// seeded (e.g., OS entropy source unavailable).
    pub fn try_new(config: &HsmConfig) -> Result<Self, crate::error::HsmError> {
        let drbg = HmacDrbg::new().map_err(|_| crate::error::HsmError::GeneralError)?;
        Ok(Self {
            slot_manager: SlotManager::new_with_config(config),
            session_manager: SessionManager::new(),
            object_store: ObjectStore::new(),
            audit_log: {
                let log = if config.audit.enabled {
                    AuditLog::new_with_path(config.audit.log_path.clone())?
                } else {
                    AuditLog::new()
                };
                let log = Arc::new(log);
                log.register_global_logger();
                log
            },
            crypto_backend: Self::select_crypto_backend(config),
            drbg: parking_lot::Mutex::new(drbg),
            algorithm_config: config.algorithms.clone(),
            serial_number: Self::make_serial(config),
            state_hmac_key: Self::generate_state_hmac_key(),
        })
    }

    /// Create a new HsmCore with an externally-provided crypto backend.
    ///
    /// Use this to inject the FIPS-validated `AwsLcBackend` from
    /// the `craton_hsm-awslc` crate (enterprise), or any custom backend.
    ///
    /// # Panics
    ///
    /// Panics if the HMAC_DRBG cannot be instantiated (OS entropy unavailable).
    /// Use [`HsmCore::try_new_with_backend`] for a fallible alternative.
    pub fn new_with_backend(config: &HsmConfig, backend: Arc<dyn CryptoBackend>) -> Self {
        Self::try_new_with_backend(config, backend)
            .expect("DRBG instantiation must succeed (requires OS entropy)")
    }

    /// Fallible constructor with an externally-provided crypto backend.
    pub fn try_new_with_backend(
        config: &HsmConfig,
        backend: Arc<dyn CryptoBackend>,
    ) -> Result<Self, crate::error::HsmError> {
        let drbg = HmacDrbg::new().map_err(|_| crate::error::HsmError::GeneralError)?;
        Ok(Self {
            slot_manager: SlotManager::new_with_config(config),
            session_manager: SessionManager::new(),
            object_store: ObjectStore::new(),
            audit_log: {
                let log = if config.audit.enabled {
                    AuditLog::new_with_path(config.audit.log_path.clone())?
                } else {
                    AuditLog::new()
                };
                let log = Arc::new(log);
                log.register_global_logger();
                log
            },
            crypto_backend: backend,
            drbg: parking_lot::Mutex::new(drbg),
            algorithm_config: config.algorithms.clone(),
            serial_number: Self::make_serial(config),
            state_hmac_key: Self::generate_state_hmac_key(),
        })
    }

    /// Create with default configuration.
    ///
    /// Returns an error if the config file is present but malformed, or if
    /// any security parameter fails validation.
    pub fn new_default() -> Result<Self, crate::error::HsmError> {
        let config = HsmConfig::load()?;
        Self::try_new(&config)
    }

    // ========================================================================
    // Public accessors for external workspace crates (daemon, admin CLI).
    // Internal code (pkcs11_abi) uses pub(crate) field access directly.
    // ========================================================================

    /// Returns a reference to the slot manager.
    pub fn slot_manager(&self) -> &SlotManager {
        &self.slot_manager
    }

    /// Returns a reference to the session manager.
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    /// Returns a reference to the object store.
    pub fn object_store(&self) -> &ObjectStore {
        &self.object_store
    }

    /// Returns a reference to the audit log.
    pub fn audit_log(&self) -> &Arc<AuditLog> {
        &self.audit_log
    }

    /// Returns a reference to the active crypto backend.
    pub fn crypto_backend(&self) -> &Arc<dyn CryptoBackend> {
        &self.crypto_backend
    }

    /// Returns a reference to the algorithm configuration.
    pub fn algorithm_config(&self) -> &AlgorithmConfig {
        &self.algorithm_config
    }

    /// Returns a reference to the HMAC_DRBG instance (SP 800-90A).
    pub fn drbg(&self) -> &parking_lot::Mutex<HmacDrbg> {
        &self.drbg
    }
}
