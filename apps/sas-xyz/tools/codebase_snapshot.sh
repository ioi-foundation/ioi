#!/bin/bash
# Script to create a flattened snapshot of a codebase

# Default settings
LINE_THRESHOLD=1500
OUTPUT_FILE="codebase_snapshot.md"
LARGE_DIRS=("pqclean" "node_modules" ".git" "target" "build" "dist" "Cargo.lock" "tree.md")
IGNORED_EXTS=("jpg" "jpeg" "png" "gif" "mp4" "mov" "zip" "tar" "gz" "class" "o" "so" "dylib" "a" "exe" "dll")

function print_usage() {
    echo "Usage: $0 [OPTIONS] <path>"
    echo "Creates a flattened snapshot of a codebase."
    echo ""
    echo "Options:"
    echo "  -o, --output FILE    Output file (default: ${OUTPUT_FILE})"
    echo "  -l, --lines NUM      Line threshold for small files (default: ${LINE_THRESHOLD})"
    echo "  -h, --help           Display this help message"
    echo ""
    echo "Examples:"
    echo "  $0 ."
    echo "  $0 --lines 2000 --output my_project_snapshot.md ~/projects/my-project"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -l|--lines)
            LINE_THRESHOLD="$2"
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

# Check if target path is provided
if [ -z "$TARGET_PATH" ]; then
    echo "Error: No target path provided."
    print_usage
fi

# Verify target path exists
if [ ! -e "$TARGET_PATH" ]; then
    echo "Error: Target path does not exist: $TARGET_PATH"
    exit 1
fi

# Resolve to absolute path
TARGET_PATH=$(realpath "$TARGET_PATH")

# Function to check if a file should be ignored based on extension
function should_ignore_file() {
    local file="$1"
    local ext="${file##*.}"
    
    # Convert to lowercase
    ext=$(echo "$ext" | tr '[:upper:]' '[:lower:]')
    
    for ignored_ext in "${IGNORED_EXTS[@]}"; do
        if [ "$ext" = "$ignored_ext" ]; then
            return 0  # Should ignore
        fi
    done
    
    return 1  # Should not ignore
}

# Function to check if a directory is considered "large"
function is_large_dir() {
    local dir="$1"
    local dirname=$(basename "$dir")
    
    for large_dir in "${LARGE_DIRS[@]}"; do
        if [ "$dirname" = "$large_dir" ]; then
            return 0  # Is large
        fi
    done
    
    return 1  # Is not large
}

# Initialize the output file
echo "# Codebase Snapshot: $(basename "$TARGET_PATH")" > "$OUTPUT_FILE"
echo "Created: $(date)" >> "$OUTPUT_FILE"
echo "Target: $TARGET_PATH" >> "$OUTPUT_FILE"
echo "Line threshold for included files: $LINE_THRESHOLD" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Function to process a directory
function process_directory() {
    local dir="$1"
    local indent="$2"
    local base_dir="$3"
    local relative_path="${dir#$base_dir/}"
    
    # Skip hidden directories
    if [[ $(basename "$dir") == .* && "$dir" != "$TARGET_PATH" ]]; then
        return
    fi
    
    # Check if this is a large directory
    if is_large_dir "$(basename "$dir")"; then
        echo "${indent}## Directory: $relative_path (Large - showing tree only)" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        echo "${indent}Tree structure:" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        echo '```' >> "$OUTPUT_FILE"
        tree -L 3 --dirsfirst "$dir" >> "$OUTPUT_FILE"
        echo '```' >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        return
    fi
    
    echo "${indent}## Directory: $relative_path" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    local entries=()
    while IFS= read -r -d $'\0' entry; do
        entries+=("$entry")
    done < <(find "$dir" -mindepth 1 -maxdepth 1 -print0 | sort -z)
    
    # Process directories first
    for entry in "${entries[@]}"; do
        if [ -d "$entry" ]; then
            process_directory "$entry" "${indent}#" "$base_dir"
        fi
    done
    
    # Then process files
    for entry in "${entries[@]}"; do
        if [ -f "$entry" ]; then
            process_file "$entry" "$indent" "$base_dir"
        fi
    done
}

# Function to process a file
function process_file() {
    local file="$1"
    local indent="$2"
    local base_dir="$3"
    local relative_path="${file#$base_dir/}"
    
    # Skip hidden files
    if [[ $(basename "$file") == .* ]]; then
        return
    fi
    
    # Skip files with ignored extensions
    if should_ignore_file "$file"; then
        return
    fi
    
    # Get file size and line count
    local size=$(du -h "$file" | cut -f1)
    local lines=$(wc -l < "$file" 2>/dev/null || echo "0")
    local file_type=$(file -b "$file")
    
    echo "${indent}### File: $relative_path" >> "$OUTPUT_FILE"
    echo "${indent}*Size: $size, Lines: $lines, Type: $file_type*" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    # Check if this is a small text file
    if [ "$lines" -le "$LINE_THRESHOLD" ] && [[ "$file_type" == *text* || "$file_type" == *script* || "$file_type" == *source* ]]; then
        # Determine the language for syntax highlighting
        local ext="${file##*.}"
        local lang=""
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
        cat "$file" >> "$OUTPUT_FILE"
        echo '```' >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    else
        echo "${indent}*File content not included (exceeds threshold or non-text file)*" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi
}

# Start processing
if [ -d "$TARGET_PATH" ]; then
    # Collect statistics
    total_files=$(find "$TARGET_PATH" -type f | wc -l)
    total_dirs=$(find "$TARGET_PATH" -type d | wc -l)
    
    echo "## Summary Statistics" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    echo "* Total files: $total_files" >> "$OUTPUT_FILE"
    echo "* Total directories: $total_dirs" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    # Process the target directory
    process_directory "$TARGET_PATH" "#" "$TARGET_PATH"
else
    # It's a single file
    process_file "$TARGET_PATH" "#" "$(dirname "$TARGET_PATH")"
fi

echo "Snapshot created at: $OUTPUT_FILE"