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

# The binary created by 'npm install ts-proto' is named 'protoc-gen-ts_proto' (underscore).
# In workspace installs, npm may hoist it to the repo-root node_modules/.bin.
PLUGIN_PATHS=(
    "${REPO_ROOT}/apps/autopilot/node_modules/.bin/protoc-gen-ts_proto"
    "${REPO_ROOT}/node_modules/.bin/protoc-gen-ts_proto"
)
PLUGIN_PATH=""
for candidate in "${PLUGIN_PATHS[@]}"; do
    if [ -f "$candidate" ]; then
        PLUGIN_PATH="$candidate"
        break
    fi
done

if [ -z "$PLUGIN_PATH" ]; then
    echo "❌ Error: 'protoc-gen-ts_proto' not found in expected paths:"
    for candidate in "${PLUGIN_PATHS[@]}"; do
        echo "   $candidate"
    done
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

# Remove legacy flat outputs if they exist. Canonical output is versioned
# (e.g., public/v1/public.ts) under src/generated.
LEGACY_TS_FILES=(
    "${UI_OUT_DIR}/public.ts"
    "${UI_OUT_DIR}/control.ts"
    "${UI_OUT_DIR}/blockchain.ts"
)
for legacy in "${LEGACY_TS_FILES[@]}"; do
    if [ -f "$legacy" ]; then
        rm -f "$legacy"
        echo "🧹 Removed legacy generated file: $legacy"
    fi
done

# We use --plugin=protoc-gen-ts=... to map the 'ts' output flag to the 'ts_proto' binary
protoc \
    --plugin="protoc-gen-ts=${PLUGIN_PATH}" \
    --ts_out="${UI_OUT_DIR}" \
    --ts_opt=esModuleInterop=true \
    --ts_opt=outputServices=grpc-js \
    --ts_opt=env=browser \
    --proto_path="${PROTO_SRC}" \
    "${PROTO_SRC}/public/v1/public.proto" \
    "${PROTO_SRC}/blockchain/v1/blockchain.proto" \
    "${PROTO_SRC}/control/v1/control.proto"

echo "✅ Done. Frontend client is in sync with Kernel schema."
