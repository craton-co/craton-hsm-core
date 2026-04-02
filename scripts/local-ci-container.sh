#!/usr/bin/env bash
# ============================================================================
# local-ci-container.sh — Run full CI pipeline in Docker
# ============================================================================
#
# Mirrors .github/workflows/ci.yml in a controlled container.
# Ensures consistency and provides tools like Miri and Tarpaulin without
# local installation.
#
# Usage:
#   ./scripts/local-ci-container.sh              # Run all jobs
#   ./scripts/local-ci-container.sh quick        # fmt + test + clippy
#   ./scripts/local-ci-container.sh miri         # Run Miri
#   ./scripts/local-ci-container.sh coverage     # Run Tarpaulin
# ============================================================================

set -euo pipefail

# 1. Colors and Logging
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

log() {
    echo -e "${BLUE}${BOLD}==>${NC} ${BOLD}$1${NC}"
}

# 2. Prerequisites
if ! command -v docker &>/dev/null; then
    echo "Error: docker is not installed or not in PATH."
    exit 1
fi

# 3. Path setup
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

# 4. Build/Update the CI image
log "Ensuring CI Docker image is built..."
docker build -t craton_hsm_ci:latest -f deploy/Dockerfile.ci .

# 5. Run the container
# - --privileged: Required for cargo-tarpaulin (ptrace)
# - Volumes: Cache cargo data and build artifacts outside the host source tree
#   to avoid permissions issues and cross-OS build conflicts.
log "Starting CI container..."
docker run --rm -it \
    --privileged \
    -v "$REPO_ROOT":/app \
    -v craton-cargo-registry:/usr/local/cargo/registry \
    -v craton-cargo-git:/usr/local/cargo/git \
    -v craton-ci-target:/app/target \
    craton_hsm_ci:latest "$@"
