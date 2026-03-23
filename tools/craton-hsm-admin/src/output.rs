// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Output formatting helpers for the admin CLI.

use std::fmt;

/// Print a key-value table to stdout.
pub fn print_table(rows: &[(&str, String)]) {
    let max_key = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (key, value) in rows {
        println!("  {:<width$}  {}", key, value, width = max_key);
    }
}

/// Wrapper for JSON-or-table output.
pub fn print_json_or_table(json: bool, json_value: &serde_json::Value, rows: &[(&str, String)]) {
    if json {
        println!("{}", serde_json::to_string_pretty(json_value).unwrap());
    } else {
        print_table(rows);
    }
}

/// Format a byte slice as hex string.
pub fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Format CK_OBJECT_CLASS as human-readable string.
pub fn object_class_name(class: u64) -> &'static str {
    match class {
        0 => "Data",
        1 => "Certificate",
        2 => "PublicKey",
        3 => "PrivateKey",
        4 => "SecretKey",
        _ => "Unknown",
    }
}

/// Format CK_KEY_TYPE as human-readable string.
pub fn key_type_name(kt: u64) -> &'static str {
    match kt {
        0x00 => "RSA",
        0x03 => "EC",
        0x1F => "AES",
        0x04 => "GENERIC_SECRET",
        0x80000001 => "ED25519",
        0x80000010 => "ML-DSA",
        0x80000011 => "ML-KEM",
        0x80000012 => "SLH-DSA",
        _ => "Unknown",
    }
}

/// Simple columnar table printer for object listings.
pub struct ObjectTable {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl ObjectTable {
    pub fn new(headers: Vec<&str>) -> Self {
        Self {
            headers: headers.into_iter().map(String::from).collect(),
            rows: Vec::new(),
        }
    }

    pub fn add_row(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

impl fmt::Display for ObjectTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.rows.is_empty() {
            return writeln!(f, "  (no entries)");
        }

        // Calculate column widths
        let col_count = self.headers.len();
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.len()).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < col_count {
                    widths[i] = widths[i].max(cell.len());
                }
            }
        }

        // Print header
        for (i, header) in self.headers.iter().enumerate() {
            if i > 0 {
                write!(f, "  ")?;
            }
            write!(f, "{:<width$}", header, width = widths[i])?;
        }
        writeln!(f)?;

        // Print separator
        for (i, w) in widths.iter().enumerate() {
            if i > 0 {
                write!(f, "  ")?;
            }
            write!(f, "{}", "-".repeat(*w))?;
        }
        writeln!(f)?;

        // Print rows
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i > 0 {
                    write!(f, "  ")?;
                }
                if i < col_count {
                    write!(f, "{:<width$}", cell, width = widths[i])?;
                }
            }
            writeln!(f)?;
        }

        Ok(())
    }
}
