#!/bin/bash
set -e

# ==============================================================================
# IOI Kernel: TypeScript Client Generator
# ==============================================================================
# This script bridges the gap between the Rust backend (source of truth schemas)
# and the TypeScript/Tauri frontend (Autopilot UI).
#
# It compiles the shared .proto definitions into strict TypeScript interfaces
# and gRPC clients.
# ==============================================================================

# 1. Configuration
# ----------------
REPO_ROOT="$(git rev-parse --show-toplevel)"
PROTO_SRC="${REPO_ROOT}/crates/ipc/proto"
# Default to a standard sibling directory structure, can be overridden env var
UI_OUT_DIR="${UI_PATH:-${REPO_ROOT}/../autopilot-ui/src/generated}"

# 2. Dependency Check
# -------------------
if ! command -v protoc &> /dev/null; then
    echo "❌ Error: 'protoc' is not installed."
    echo "   Please install Protocol Buffers compiler (e.g., 'brew install protobuf')."
    exit 1
fi

# We look for the plugin in the local node_modules of the UI project if possible
PLUGIN_PATH="./node_modules/.bin/protoc-gen-ts"
if [ ! -f "$PLUGIN_PATH" ]; then
    # Fallback: check if it's globally installed or in path
    if command -v protoc-gen-ts &> /dev/null; then
        PLUGIN_PATH=$(command -v protoc-gen-ts)
    else
        echo "❌ Error: 'protoc-gen-ts' not found."
        echo "   Please run 'npm install ts-proto' or 'npm install -g ts-proto'."
        exit 1
    fi
fi

# 3. Generation
# -------------
echo "🚀 Generating TypeScript definitions..."
echo "   Source: ${PROTO_SRC}"
echo "   Target: ${UI_OUT_DIR}"

mkdir -p "$UI_OUT_DIR"

protoc \
    --plugin="protoc-gen-ts=${PLUGIN_PATH}" \
    --ts_out="${UI_OUT_DIR}" \
    --ts_opt=esModuleInterop=true \
    --ts_opt=outputServices=grpc-js \
    --ts_opt=env=browser \
    -I "${PROTO_SRC}" \
    "${PROTO_SRC}/public.proto" \
    "${PROTO_SRC}/blockchain.proto"

echo "✅ Done. Frontend client is in sync with Kernel schema."