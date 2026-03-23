// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
fn main() {
    // Future: generate PKCS#11 header bindings if needed
    // For now, we define types manually for full control over the C ABI layout.
    println!("cargo:rerun-if-changed=build.rs");
}
