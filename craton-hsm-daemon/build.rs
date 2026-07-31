// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Keep daemon builds hermetic: CI and source users do not need a system
    // protobuf compiler merely to compile the generated gRPC bindings.
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    unsafe { std::env::set_var("PROTOC", protoc) };
    tonic_prost_build::compile_protos("proto/craton_hsm.proto")?;
    Ok(())
}
