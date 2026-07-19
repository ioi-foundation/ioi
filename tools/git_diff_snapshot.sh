#!/bin/bash
# Script to create a snapshot of all modified files based on a git diff.

# Default settings
OUTPUT_FILE="diff_snapshot.md"

function print_usage() {
    echo "Usage: $0 [OPTIONS] [GIT_DIFF_ARGS...]"
    echo "Creates a snapshot of all modified files based on a git diff."
    echo ""
    echo "This script pipes arguments directly to 'git diff'. It then finds all unique files"
    echo "that were added or modified in that diff and outputs their full contents into"
    echo "a single markdown file."
    echo ""
    echo "Options:"
    echo "  -o, --output FILE    Output file (default: ${OUTPUT_FILE})"
    echo "  -h, --help           Display this help message"
    echo ""
    echo "Examples:"
    echo "  # Snapshot changes against the 'main' branch"
    echo "  $0 main"
    echo ""
    echo "  # Snapshot staged changes, output to a specific file"
    echo "  $0 --output my_staged_changes.md --staged"
    echo ""
    echo "  # Snapshot changes in the last 3 commits"
    echo "  $0 HEAD~3 HEAD"
    exit 1
}

# --- Argument Parsing ---
GIT_DIFF_ARGS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            if [ -n "$2" ]; then
                OUTPUT_FILE="$2"
                shift 2
            else
                echo "Error: --output requires a file name."
                exit 1
            fi
            ;;
        -h|--help)
            print_usage
            ;;
        *)
            GIT_DIFF_ARGS+=("$1")
            shift
            ;;
    esac
done

# --- Git Repository Check ---
if ! git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    echo "Error: Not inside a git repository."
    exit 1
fi

GIT_ROOT=$(git rev-parse --show-toplevel)

# --- Find Modified Files ---
# A: Added, C: Copied, M: Modified, R: Renamed
# We get a list of unique file paths relative to the git root.
# Using 'git diff' with '--name-only' and '--diff-filter=ACMR' is the most reliable way.
MODIFIED_FILES=$(git diff --name-only --diff-filter=ACMR "${GIT_DIFF_ARGS[@]}" | sort -u)

if [ -z "$MODIFIED_FILES" ]; then
    echo "No added or modified files found for the given diff."
    exit 0
fi

# --- Create Snapshot ---
# Initialize the output file
echo "# Git Diff Snapshot" > "$OUTPUT_FILE"
echo "Created: $(date)" >> "$OUTPUT_FILE"
echo "Git Diff Command: \`git diff ${GIT_DIFF_ARGS[*]}\`" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "## Modified Files Included:" >> "$OUTPUT_FILE"
echo '```' >> "$OUTPUT_FILE"
echo "$MODIFIED_FILES" >> "$OUTPUT_FILE"
echo '```' >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Process each modified file
while IFS= read -r file_path; do
    # Ensure the file exists (it might have been deleted in a subsequent commit)
    if [ -f "$GIT_ROOT/$file_path" ]; then
        echo "---" >> "$OUTPUT_FILE"
        echo "### File: \`$file_path\`" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"

        # Determine the language for syntax highlighting
        ext="${file_path##*.}"
        lang=""
        case "$ext" in
            rs)         lang="rust";;
            js)         lang="javascript";;
            ts)         lang="typescript";;
            py)         lang="python";;
            rb)         lang="ruby";;
            c|h)        lang="c";;
            cpp|hpp)    lang="cpp";;
            sh)         lang="bash";;
            java)       lang="java";;
            php)        lang="php";;
            html)       lang="html";;
            css)        lang="css";;
            json)       lang="json";;
            md)         lang="markdown";;
            xml)        lang="xml";;
            yml|yaml)   lang="yaml";;
            toml)       lang="toml";;
            go)         lang="go";;
            swift)      lang="swift";;
            kt|kts)     lang="kotlin";;
            *)          lang="";;
        esac
        
        # Include file content
        echo '```'"$lang" >> "$OUTPUT_FILE"
        cat "$GIT_ROOT/$file_path" >> "$OUTPUT_FILE"
        echo '```' >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    else
        echo "---" >> "$OUTPUT_FILE"
        echo "### File: \`$file_path\` (Note: File not found on disk, may have been deleted/renamed later)" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi
done <<< "$MODIFIED_FILES"

echo "Snapshot of modified files created at: $OUTPUT_FILE"