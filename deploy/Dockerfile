# ============================================================================
# Craton HSM — Multi-stage Production Dockerfile
#
# Builds the gRPC daemon (craton-hsm-daemon) and admin CLI (craton-hsm-admin)
# into a minimal distroless container. The PKCS#11 shared library
# (libcraton_hsm.so) is also included for in-container use.
#
# Build:   docker build -t craton_hsm:latest -f deploy/Dockerfile .
# Run:     docker run -p 5696:5696 -v ./craton_hsm.toml:/etc/craton_hsm/craton_hsm.toml craton_hsm:latest
# ============================================================================

# ── Stage 1: Build ──────────────────────────────────────────────────────────
# Base images pinned to SHA256 digests to prevent tag-mutation attacks.
# To update: docker pull <image>:<tag> && docker inspect --format='{{index .RepoDigests 0}}' <image>:<tag>
#   Or: crane digest <image>:<tag>
FROM rust:1.83-bookworm@sha256:62100541815d5e4262785ee7a645c4ef5cdb7cc13930fadca8282f2e2f450da0 AS builder

# Install protoc (required by tonic-build for gRPC proto compilation)
RUN apt-get update && \
    apt-get install -y --no-install-recommends protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Dependency caching layer ────────────────────────────────────────────────
# Copy only Cargo manifests + lockfile so dependencies are cached
# independently of source code changes.
COPY Cargo.toml Cargo.lock ./
COPY craton-hsm-daemon/Cargo.toml craton-hsm-daemon/Cargo.toml
COPY tools/craton-hsm-admin/Cargo.toml tools/craton-hsm-admin/Cargo.toml
COPY tools/pkcs11-spy/Cargo.toml tools/pkcs11-spy/Cargo.toml

# Create minimal stub source files so `cargo build` can resolve the
# dependency graph and download/compile all third-party crates.
RUN mkdir -p src && echo "pub fn _stub() {}" > src/lib.rs && \
    mkdir -p craton-hsm-daemon/src && echo "fn main() {}" > craton-hsm-daemon/src/main.rs && \
    echo "fn main() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }" > craton-hsm-daemon/build.rs && \
    mkdir -p craton-hsm-daemon/proto && echo 'syntax = "proto3";' > craton-hsm-daemon/proto/craton_hsm.proto && \
    mkdir -p tools/craton-hsm-admin/src && echo "fn main() {}" > tools/craton-hsm-admin/src/main.rs && \
    mkdir -p tools/pkcs11-spy/src && echo "" > tools/pkcs11-spy/src/lib.rs

# Download dependencies first — this MUST succeed (supply chain integrity).
# Separated from compilation so a compromised/missing crate causes a hard failure
# rather than being swallowed by the stub-compilation tolerance below.
RUN cargo fetch --locked

# Dependency-priming build — stubs won't link, but dependency compilation
# must succeed. We build individual crates (lib-only) to cache deps without
# requiring full linkage.
RUN cargo build --release --workspace --lib --locked 2>&1 \
    || echo "WARN: dep-priming partial compile failure (expected for stub binaries)"

# ── Full source build ───────────────────────────────────────────────────────
# Copy only the source directories needed — avoids accidentally pulling in
# secrets, credentials, or other sensitive files that slip past .dockerignore.
COPY src/ src/
COPY craton-hsm-daemon/ craton-hsm-daemon/
COPY tools/ tools/
COPY craton_hsm.toml craton_hsm.toml

# Invalidate the build cache for our own crates
RUN touch src/lib.rs craton-hsm-daemon/src/main.rs craton-hsm-daemon/build.rs \
          tools/craton-hsm-admin/src/main.rs tools/pkcs11-spy/src/lib.rs

# Build all workspace members in release mode (--locked enforces Cargo.lock integrity)
RUN cargo build --release --workspace --locked

# Verify POST self-tests pass during build
RUN cargo test --release -p craton_hsm -- crypto::self_test

# Download grpc-health-probe for Docker HEALTHCHECK (not needed in K8s which has native gRPC probes)
# Integrity is verified against the release checksums.txt published alongside the binary.
ARG GRPC_HEALTH_PROBE_VERSION=v0.4.28
RUN ARCH=$(dpkg --print-architecture) && \
    BINARY="grpc_health_probe-linux-${ARCH}" && \
    curl -fsSL -o /usr/local/bin/grpc_health_probe \
      "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/${BINARY}" && \
    curl -fsSL -o /tmp/checksums.txt \
      "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/checksums.txt" && \
    EXPECTED=$(grep "${BINARY}" /tmp/checksums.txt | awk '{print $1}') && \
    ACTUAL=$(sha256sum /usr/local/bin/grpc_health_probe | awk '{print $1}') && \
    if [ "$EXPECTED" != "$ACTUAL" ]; then \
      echo "FATAL: grpc_health_probe checksum mismatch (expected ${EXPECTED}, got ${ACTUAL})" >&2; exit 1; \
    fi && \
    rm -f /tmp/checksums.txt && \
    chmod +x /usr/local/bin/grpc_health_probe

# ── Stage 2: Runtime ────────────────────────────────────────────────────────
# Distroless: no shell, no package manager, minimal attack surface.
# "cc" variant includes libgcc/libstdc++ needed by Rust binaries.
# ":nonroot" tag runs as UID 65534 by default.
# Update digest: crane digest gcr.io/distroless/cc-debian12:nonroot
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:acf6c2ff1cfd0e2e6e1df529e918c0af9e21b1ae29f9db40e3a4ee6c076864a2

LABEL org.opencontainers.image.title="Craton HSM" \
      org.opencontainers.image.description="PKCS#11 v3.0 Software HSM with post-quantum support" \
      org.opencontainers.image.version="0.9.1" \
      org.opencontainers.image.vendor="Craton HSM" \
      org.opencontainers.image.licenses="Apache-2.0"

# Copy binaries from builder
COPY --from=builder /build/target/release/craton-hsm-daemon /usr/local/bin/
COPY --from=builder /build/target/release/craton-hsm-admin  /usr/local/bin/

# Copy the shared library (useful if a sidecar app needs PKCS#11 via dlopen)
COPY --from=builder /build/target/release/libcraton_hsm.so /usr/local/lib/

# Default config location (overridden by volume mount in production)
COPY --from=builder /build/craton_hsm.toml /etc/craton_hsm/craton_hsm.toml

# Copy grpc-health-probe for Docker HEALTHCHECK
COPY --from=builder /usr/local/bin/grpc_health_probe /usr/local/bin/

# gRPC listen port
EXPOSE 5696

# Docker HEALTHCHECK for standalone (non-K8s) deployments.
# In K8s, native gRPC probes in the Deployment spec take precedence.
HEALTHCHECK --interval=20s --timeout=3s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/grpc_health_probe", "-addr=:5696"]

# Run as non-root (UID 65534 from distroless:nonroot)
USER nonroot

ENTRYPOINT ["/usr/local/bin/craton-hsm-daemon"]
CMD ["/etc/craton_hsm/craton_hsm.toml"]
