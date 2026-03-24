// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// Dump recent audit log entries.
pub fn dump(config_path: &str, last: usize, json: bool) -> CliResult {
    let config = load_config(config_path)?;
    let hsm = HsmCore::new(&config);

    let count = hsm.audit_log().entry_count();

    if json {
        let value = serde_json::json!({
            "total_entries": count,
            "note": "Audit log entries are recorded during runtime. This shows in-memory log state."
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Audit Log");
        println!("=========");
        println!("  Total entries: {}", count);
        println!("  Requested:     last {}", last);
        if count == 0 {
            println!("\n  (no audit entries — log is populated during HSM operations)");
        }
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
