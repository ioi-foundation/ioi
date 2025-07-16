#!/bin/bash
# This script flattens all files in a specified directory,
# outputting the relative path and file content to output.txt.
# It ignores .ico files and excludes specified directories.
# Cancels operation if output file exceeds ~6MB.

# Check if a directory argument is provided.
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <directory>"
    exit 1
fi

# Convert the directory argument to an absolute path
dir="$(realpath "$1")"
parent_dir=$(dirname "$dir")  # Added to get the parent directory
output="codebase.txt"
max_size=6000000  # Approximately 6MB in bytes

# Remove any existing output file.
[ -f "$output" ] && rm "$output"

# Use 'find' to get all files under the directory,
# excluding the output file, any .ico files, and the specified directories.
find "$dir" -type f \
    ! -name "$(basename "$output")" \
    ! -iname "*.ico" | while IFS= read -r file; do
    
    # Compute the file's relative path relative to the parent directory.
    rel="${file#$parent_dir/}"  # Modified to use parent_dir instead of dir

    # Write the relative path to the output file.
    echo "$rel" >> "$output"
    
    # Append the file's contents to the output file.
    cat "$file" >> "$output"
    
    # Optionally, add an extra newline between files for readability.
    echo "" >> "$output"

    # Check file size
    if [ -f "$output" ]; then
        size=$(stat -f%z "$output" 2>/dev/null || stat -c%s "$output" 2>/dev/null)
        if [ "$size" -gt "$max_size" ]; then
            echo "Error: Output file exceeded 6MB limit. Operation cancelled."
            rm "$output"
            exit 1
        fi
    fi
done

# Check if the operation completed successfully
if [ $? -eq 0 ]; then
    echo "Operation completed successfully."
else
    echo "Operation failed."
fi