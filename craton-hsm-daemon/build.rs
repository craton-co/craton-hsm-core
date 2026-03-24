// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::compile_protos("proto/craton_hsm.proto")?;
    Ok(())
}
