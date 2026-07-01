// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use craton_hsm::audit::log::{
    load_entries_from_file, verify_chain_entries, AuditEvent, AuditOperation, AuditResult,
};
use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// Dump on-disk audit log entries.
///
/// Reads the NDJSON file at the configured `audit.log_path`, applies the
/// `--last N` window, prints either raw JSON lines (`--json`) or a
/// human-readable table (default), and runs `verify_chain_entries` at the end
/// so the operator sees whether the loaded chain is intact.
///
/// Exits with status 1 (via `Err`) if the audit log file does not exist; this
/// distinguishes "no log to dump" from "empty log".
pub fn dump(config_path: &str, last: usize, json: bool) -> CliResult {
    let config = load_config(config_path)?;
    let log_path = &config.audit.log_path;

    if !log_path.exists() {
        return Err(format!("no audit log at {}", log_path.display()).into());
    }

    let entries = load_entries_from_file(log_path)
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

    let total = entries.len();
    let chain_status = verify_chain_entries(&entries);

    // Apply the `--last N` window. `0` is treated as "no limit" so scripts can
    // request the whole log without first counting; the default `50` from the
    // CLI still applies when the user did not pass `--last`.
    let window: &[AuditEvent] = if last == 0 || last >= entries.len() {
        &entries[..]
    } else {
        &entries[entries.len() - last..]
    };

    if json {
        // Raw NDJSON-style output: one JSON object per line, matching the
        // on-disk format. Easy to pipe into `jq` or a SIEM.
        for event in window {
            println!("{}", serde_json::to_string(event)?);
        }
        // Trailing chain-status object so consumers can detect tamper without
        // re-running `verify-chain`.
        let status = match chain_status {
            Ok(count) => serde_json::json!({
                "chain_status": "valid",
                "entries_verified": count,
                "total_entries": total,
                "shown": window.len(),
            }),
            Err(index) => serde_json::json!({
                "chain_status": "broken",
                "broken_at_index": index,
                "total_entries": total,
                "shown": window.len(),
            }),
        };
        println!("{}", serde_json::to_string(&status)?);
    } else {
        println!("Audit Log: {}", log_path.display());
        println!("=================================");
        println!("  Total entries:    {}", total);
        println!("  Showing:          {} (last {})", window.len(), last);
        println!();
        for (idx, event) in window.iter().enumerate() {
            let global_idx = total - window.len() + idx;
            println!(
                "  [{:>5}] ts={} session={} op={} key={} result={}",
                global_idx,
                event.timestamp,
                event.session_handle,
                format_operation_name(&event.operation),
                event.key_id.as_deref().unwrap_or("-"),
                format_result(&event.result),
            );
        }
        println!();
        match chain_status {
            Ok(count) => {
                println!("  Chain status:     VALID ({} entries verified)", count);
            }
            Err(index) => {
                println!("  Chain status:     BROKEN at entry index {}", index);
            }
        }
    }

    // Surface a non-zero exit code when the chain is broken so the operator
    // notices in automation, but only after printing the entries the user
    // explicitly asked for.
    if chain_status.is_err() {
        std::process::exit(1);
    }

    Ok(())
}

/// Export audit log as a JSON array (pretty-printed).
pub fn export_json(config_path: &str) -> CliResult {
    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);
    println!("{}", hsm.audit_log().export_json());
    Ok(())
}

/// Export audit log as newline-delimited JSON (NDJSON/JSON Lines).
/// Each line is a single JSON object — ideal for log aggregators and SIEM ingestion.
pub fn export_ndjson(config_path: &str) -> CliResult {
    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);
    let ndjson = hsm.audit_log().export_ndjson();
    if !ndjson.is_empty() {
        println!("{}", ndjson);
    }
    Ok(())
}

/// Export audit log in syslog RFC 5424 format.
pub fn export_syslog(config_path: &str) -> CliResult {
    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);
    for line in hsm.audit_log().export_syslog() {
        println!("{}", line);
    }
    Ok(())
}

/// Verify integrity of the audit log hash chain.
pub fn verify_chain(config_path: &str, json: bool) -> CliResult {
    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);
    match hsm.audit_log().verify_chain() {
        Ok(count) => {
            if json {
                let value = serde_json::json!({
                    "status": "valid",
                    "entries_verified": count,
                });
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                println!("Audit Chain Verification: VALID");
                println!("  Entries verified: {}", count);
            }
        }
        Err(index) => {
            if json {
                let value = serde_json::json!({
                    "status": "broken",
                    "broken_at_index": index,
                });
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                eprintln!("Audit Chain Verification: BROKEN");
                eprintln!("  Chain broken at entry index: {}", index);
            }
            std::process::exit(1);
        }
    }
    Ok(())
}

fn load_config(path: &str) -> Result<HsmConfig, Box<dyn std::error::Error>> {
    let config = HsmConfig::load_from_path(path)?;
    config
        .validate()
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    Ok(config)
}

/// Short stable label for an [`AuditOperation`] variant. Kept in sync with the
/// `format_operation_name` table inside `craton_hsm::audit::log` so the dump
/// output matches the syslog export.
fn format_operation_name(op: &AuditOperation) -> &'static str {
    match op {
        AuditOperation::Initialize => "Initialize",
        AuditOperation::Finalize => "Finalize",
        AuditOperation::OpenSession { .. } => "OpenSession",
        AuditOperation::CloseSession => "CloseSession",
        AuditOperation::Login { .. } => "Login",
        AuditOperation::Logout => "Logout",
        AuditOperation::InitToken { .. } => "InitToken",
        AuditOperation::InitPIN { .. } => "InitPIN",
        AuditOperation::SetPIN => "SetPIN",
        AuditOperation::GenerateKey { .. } => "GenerateKey",
        AuditOperation::GenerateKeyPair { .. } => "GenerateKeyPair",
        AuditOperation::Sign { .. } => "Sign",
        AuditOperation::Verify { .. } => "Verify",
        AuditOperation::Encrypt { .. } => "Encrypt",
        AuditOperation::Decrypt { .. } => "Decrypt",
        AuditOperation::Digest { .. } => "Digest",
        AuditOperation::CreateObject => "CreateObject",
        AuditOperation::DestroyObject => "DestroyObject",
        AuditOperation::GenerateRandom { .. } => "GenerateRandom",
        AuditOperation::WrapKey { .. } => "WrapKey",
        AuditOperation::UnwrapKey { .. } => "UnwrapKey",
        AuditOperation::DeriveKey { .. } => "DeriveKey",
        AuditOperation::FindObjects { .. } => "FindObjects",
        AuditOperation::GetAttributeValue => "GetAttributeValue",
        AuditOperation::Zeroize { .. } => "Zeroize",
    }
}

fn format_result(r: &AuditResult) -> String {
    match r {
        AuditResult::Success => "SUCCESS".to_string(),
        AuditResult::Failure(rv) => format!("FAILURE(0x{:08X})", rv),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use craton_hsm::audit::log::AuditLog;
    use std::io::Write;
    use tempfile::tempdir;

    /// Build a small NDJSON audit log on disk, then assert `dump` in JSON mode
    /// emits the most recent `last` entries and a trailing chain-status line.
    /// The test drives the loader/verifier directly because `dump` writes to
    /// `stdout` via `println!`; the behaviour we care about is which entries
    /// the dump selects and what status it reports.
    #[test]
    fn dump_filters_last_n_and_verifies_chain() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        // Produce a real on-disk chain by going through `AuditLog::record`,
        // which gives us correct `previous_hash` linkage that
        // `verify_chain_entries` will accept.
        {
            let log = AuditLog::new_with_path(path.clone()).unwrap();
            for i in 0..5 {
                log.record(
                    100 + i as u64,
                    AuditOperation::GenerateRandom { length: 16 },
                    AuditResult::Success,
                    Some(format!("k{}", i)),
                )
                .unwrap();
            }
            log.flush();
        }

        // Load it back through the public loader.
        let entries = load_entries_from_file(&path).unwrap();
        assert_eq!(entries.len(), 5, "expected 5 events written");

        // Chain over the loaded entries must verify.
        let chain = verify_chain_entries(&entries);
        assert!(chain.is_ok(), "chain should verify: {:?}", chain);
        assert_eq!(chain.unwrap(), 5);

        // Apply the same `--last N` window logic the dump uses and assert we
        // get the last 3 entries with the right session handles.
        let last = 3usize;
        let window: &[AuditEvent] = if last >= entries.len() {
            &entries[..]
        } else {
            &entries[entries.len() - last..]
        };
        assert_eq!(window.len(), 3);
        assert_eq!(window[0].session_handle, 102);
        assert_eq!(window[1].session_handle, 103);
        assert_eq!(window[2].session_handle, 104);

        // Each window event should round-trip through serde_json::to_string,
        // which is what the JSON dump path emits.
        for ev in window {
            let line = serde_json::to_string(ev).unwrap();
            let round: AuditEvent = serde_json::from_str(&line).unwrap();
            assert_eq!(round.session_handle, ev.session_handle);
            assert_eq!(round.key_id, ev.key_id);
        }
    }

    /// `load_entries_from_file` must reject a tampered NDJSON file: if we
    /// hand-edit a `previous_hash` so it no longer matches, the loader still
    /// returns the entries (parsing succeeded) but the chain verifier flags
    /// the broken link. This is the contract `dump` relies on to surface a
    /// non-zero exit code.
    #[test]
    fn verify_chain_detects_tampered_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        {
            let log = AuditLog::new_with_path(path.clone()).unwrap();
            for i in 0..3 {
                log.record(
                    1 + i as u64,
                    AuditOperation::Sign {
                        mechanism: 1,
                        fips_approved: true,
                    },
                    AuditResult::Success,
                    None,
                )
                .unwrap();
            }
            log.flush();
        }

        // Tamper with line 2 by zeroing its previous_hash.
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = raw.lines().map(String::from).collect();
        let mut tampered: AuditEvent = serde_json::from_str(&lines[1]).unwrap();
        tampered.previous_hash = [0u8; 32];
        lines[1] = serde_json::to_string(&tampered).unwrap();
        let mut f = std::fs::File::create(&path).unwrap();
        for l in &lines {
            writeln!(f, "{}", l).unwrap();
        }
        drop(f);

        let entries = load_entries_from_file(&path).unwrap();
        assert_eq!(entries.len(), 3);
        let chain = verify_chain_entries(&entries);
        assert!(matches!(chain, Err(1)), "expected broken at index 1, got {:?}", chain);
    }
}
