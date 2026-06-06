// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
pub mod audit;
pub mod backup;
pub mod import_parse;
pub mod key;
pub mod pin;
pub mod token;

use craton_hsm::core::HsmCore;
use craton_hsm::pkcs11_abi::constants::CKU_SO;
use craton_hsm::pkcs11_abi::types::CK_SLOT_ID;
use zeroize::Zeroizing;

/// Maximum SO authentication attempts before the CLI refuses further tries.
const MAX_SO_AUTH_ATTEMPTS: u32 = 3;

/// Authenticate as Security Officer (SO) before performing privileged
/// administrative operations (e.g. PIN reset, backup restore, key import).
///
/// This helper is the canonical SO-only authentication gate for admin
/// commands. Compared to the role-prompting `key::authenticate_user`, this
/// helper:
///
/// * Refuses to authenticate as the User role — backup restore and PIN
///   reset are SO-only operations and a USER login must not satisfy the
///   gate.
/// * Applies exponential backoff between failed attempts as defence in
///   depth against scripted brute-force, even when the token enforces its
///   own lockout.
///
/// On success the caller holds an SO session against the slot's token; the
/// caller is responsible for calling `token.logout()` once the privileged
/// operation completes (or fails).
pub(crate) fn authenticate_so(
    hsm: &HsmCore,
    slot_id: CK_SLOT_ID,
) -> Result<(), Box<dyn std::error::Error>> {
    let token = hsm
        .slot_manager()
        .get_token(slot_id)
        .map_err(|_| "Failed to access token.")?;

    if !token.is_initialized() {
        return Err("Token is not initialized. Run 'token init' first.".into());
    }

    for attempt in 1..=MAX_SO_AUTH_ATTEMPTS {
        let pin = Zeroizing::new(rpassword::prompt_password("Enter SO PIN: ")?);

        match token.login(CKU_SO, pin.as_bytes()) {
            Ok(_) => return Ok(()),
            Err(_) => {
                let remaining = MAX_SO_AUTH_ATTEMPTS - attempt;
                if remaining == 0 {
                    // Enforce a final delay to slow down scripted retry loops
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    return Err("SO authentication failed. Maximum attempts reached. \
                        Note: too many failed attempts may lock the SO PIN."
                        .into());
                }
                // Linear backoff: 1s, 2s between retries
                let delay = std::time::Duration::from_secs(attempt as u64);
                eprintln!(
                    "SO authentication failed. {} attempt(s) remaining. Retrying in {}s...",
                    remaining,
                    delay.as_secs()
                );
                std::thread::sleep(delay);
            }
        }
    }

    Err("SO authentication failed.".into())
}

/// Log out of the token associated with the given slot, swallowing errors.
///
/// Intended for use in the `Drop`-style logout that admin commands perform
/// after a privileged operation — failure to log out is non-fatal because
/// the process is about to exit anyway.
pub(crate) fn logout(hsm: &HsmCore, slot_id: CK_SLOT_ID) {
    if let Ok(token) = hsm.slot_manager().get_token(slot_id) {
        token.logout().ok();
    }
}
