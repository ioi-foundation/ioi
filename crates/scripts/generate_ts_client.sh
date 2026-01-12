#!/bin/bash
set -e

# ==============================================================================
# IOI Kernel: TypeScript Client Generator
# ==============================================================================

# 1. Configuration
# ----------------
# Resolve the absolute path to the repo root (../../ from this script)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Define source and target paths
PROTO_SRC="${REPO_ROOT}/crates/ipc/proto"
UI_OUT_DIR="${REPO_ROOT}/apps/autopilot/src/generated"

# 2. Dependency Check
# -------------------
if ! command -v protoc &> /dev/null; then
    echo "❌ Error: 'protoc' is not installed."
    echo "   Please install Protocol Buffers compiler (e.g., 'sudo apt install protobuf-compiler')."
    exit 1
fi

# The binary created by 'npm install ts-proto' is named 'protoc-gen-ts_proto' (underscore)
PLUGIN_PATH="${REPO_ROOT}/apps/autopilot/node_modules/.bin/protoc-gen-ts_proto"

if [ ! -f "$PLUGIN_PATH" ]; then
    echo "❌ Error: 'protoc-gen-ts_proto' not found at:"
    echo "   $PLUGIN_PATH"
    echo ""
    echo "   Please run:"
    echo "   cd apps/autopilot && npm install --save-dev ts-proto"
    exit 1
fi

# 3. Generation
# -------------
echo "🚀 Generating TypeScript definitions..."
echo "   Source: ${PROTO_SRC}"
echo "   Target: ${UI_OUT_DIR}"
echo "   Plugin: ${PLUGIN_PATH}"

# Create output dir if it doesn't exist
mkdir -p "$UI_OUT_DIR"

# We use --plugin=protoc-gen-ts=... to map the 'ts' output flag to the 'ts_proto' binary
protoc \
    --plugin="protoc-gen-ts=${PLUGIN_PATH}" \
    --ts_out="${UI_OUT_DIR}" \
    --ts_opt=esModuleInterop=true \
    --ts_opt=outputServices=grpc-js \
    --ts_opt=env=browser \
    --proto_path="${PROTO_SRC}" \
    "${PROTO_SRC}/public.proto" \
    "${PROTO_SRC}/blockchain.proto" \
    "${PROTO_SRC}/control.proto"

echo "✅ Done. Frontend client is in sync with Kernel schema."