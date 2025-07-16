#!/bin/bash
#
# Usage: ./tree.sh <directory>
#
# Creates a tree-style Markdown listing of <directory>,
# excluding:
#   - any subpaths under 'sandbox'
#   - any subpaths under 'tools'
#   - all .ico files
#   - the output file itself (tree.md)
#
# The result is written to tree.md in the current directory.

# 1) Validate arguments
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <directory>"
  exit 1
fi

# 2) Convert the directory argument to an absolute path
dir="$(realpath "$1")"

# 3) Our exclusions
exclude_dir1="$dir/sandbox"
exclude_dir2="$dir/tools"

# 4) Output file name
output="tree.md"

# 5) Remove any existing output file
[ -f "$output" ] && rm "$output"

###############################################################################
# print_tree: Recursively prints a directory in Markdown-style tree format.
#   - $1: Current directory path
#   - $2: Indentation prefix (e.g., "  " or "    ")
###############################################################################
print_tree() {
  local current_dir="$1"
  local prefix="$2"

  # List items (including hidden ones except "." and "..") sorted alphabetically
  # 2>/dev/null to avoid permission warnings
  local items
  items="$(ls -A "$current_dir" 2>/dev/null | sort)"

  for item in $items; do
    local full_path="$current_dir/$item"

    # -------------------------------------------------------------------------
    # Exclusions
    # -------------------------------------------------------------------------
    # 1) Skip anything under the sandbox or tools folders
    if [[ "$full_path" == "$exclude_dir1"* ]] || [[ "$full_path" == "$exclude_dir2"* ]]; then
      continue
    fi
    # 2) Skip .ico files
    if [[ "$item" == *.ico ]]; then
      continue
    fi
    # 3) Skip the output file itself
    if [[ "$item" == "$(basename "$output")" ]]; then
      continue
    fi
    # -------------------------------------------------------------------------

    if [ -d "$full_path" ]; then
      # It's a directory
      echo "${prefix}- $item/" >> "$output"
      # Recursively descend into the directory, adding indentation
      print_tree "$full_path" "  $prefix"
    elif [ -f "$full_path" ]; then
      # It's a file
      echo "${prefix}- $item" >> "$output"
    fi
  done
}

# 6) Write a top-level entry for the directory itself, then recurse
echo "- $(basename "$dir")/" >> "$output"
print_tree "$dir" "  "

echo "Markdown tree created in $output"
