#!/bin/bash
# Script to create a markdown snapshot of specific architecture/security context files.

set -euo pipefail

OUTPUT_FILE="context.md"

SNAPSHOT_FILES=(
    "crates/drivers/src/gui/lenses/mod.rs"
    "crates/drivers/src/gui/lenses/auto.rs"
    "crates/drivers/src/gui/som.rs"
    "crates/drivers/src/gui/operator.rs"
    "crates/drivers/src/gui/README.md"
    "crates/services/src/agentic/desktop/service/step/perception.rs"
    "crates/services/src/agentic/desktop/service/actions/resume/visual.rs"
    "crates/drivers/src/browser/mod.rs"
    "crates/drivers/src/browser/driver_core.rs"
    "crates/drivers/src/browser/page_ops.rs"
    "crates/drivers/src/browser/dom_ops/accessibility.rs"
    "crates/drivers/src/browser/README.md"
    "crates/services/src/agentic/desktop/execution/browser/selector_click.rs"
    "crates/services/src/agentic/desktop/execution/browser/element_click.rs"
    "crates/services/src/agentic/desktop/execution/browser/handler.rs"
    "crates/services/src/agentic/policy/conditions.rs"
    "crates/types/src/app/action.rs"
    "crates/types/src/app/wallet_network/secret_injection.rs"
    "crates/drivers/src/mcp/README.md"
)

function print_usage() {
    echo "Usage: $0 [OPTIONS] [TARGET_DIR]"
    echo "Creates a markdown snapshot for selected context files."
    echo ""
    echo "Options:"
    echo "  -o, --output FILE    Output file (default: ${OUTPUT_FILE})"
    echo "  -h, --help           Display this help message"
    echo ""
    echo "Examples:"
    echo "  $0"
    echo "  $0 -o context.md"
    echo "  $0 /path/to/repo"
    exit 0
}

TARGET_PATH="."
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            ;;
        *)
            TARGET_PATH="$1"
            shift
            ;;
    esac
done

if [ ! -e "$TARGET_PATH" ]; then
    echo "Error: Target path does not exist: $TARGET_PATH" >&2
    exit 1
fi

TARGET_PATH="$(realpath "$TARGET_PATH")"

function lang_for_file() {
    local file="$1"
    local ext="${file##*.}"
    case "$ext" in
        rs) echo "rust" ;;
        ts|tsx) echo "typescript" ;;
        js|jsx) echo "javascript" ;;
        py) echo "python" ;;
        sh) echo "bash" ;;
        md) echo "markdown" ;;
        json) echo "json" ;;
        toml) echo "toml" ;;
        yml|yaml) echo "yaml" ;;
        *) echo "" ;;
    esac
}

function process_file() {
    local rel="$1"
    local full="$TARGET_PATH/$rel"

    echo "### File: $rel" >> "$OUTPUT_FILE"

    if [ ! -f "$full" ]; then
        echo "*Missing on disk: $full*" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        return
    fi

    local size lines file_type lang
    size="$(du -h "$full" | cut -f1)"
    lines="$(wc -l < "$full" 2>/dev/null || echo "0")"
    file_type="$(file -b "$full" 2>/dev/null || echo "unknown")"
    lang="$(lang_for_file "$full")"

    echo "*Size: $size, Lines: $lines, Type: $file_type*" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    echo '```'"$lang" >> "$OUTPUT_FILE"
    cat "$full" >> "$OUTPUT_FILE"
    echo '```' >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
}

{
    echo "# Context Snapshot"
    echo "Created: $(date)"
    echo "Target: $TARGET_PATH"
    echo ""
    echo "## Included Files"
    echo '```'
    printf "%s\n" "${SNAPSHOT_FILES[@]}"
    echo '```'
    echo ""
} > "$OUTPUT_FILE"

for rel in "${SNAPSHOT_FILES[@]}"; do
    process_file "$rel"
done

echo "Snapshot created at: $OUTPUT_FILE"
