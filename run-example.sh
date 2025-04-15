#!/bin/bash

# Run a specific example from the DePIN SDK examples

set -e  # Exit on error

if [ $# -lt 1 ]; then
    echo "Usage: $0 <example_name>"
    echo "Available examples:"
    ls -1 examples
    exit 1
fi

EXAMPLE=$1

if [ ! -d "examples/$EXAMPLE" ]; then
    echo "Error: Example '$EXAMPLE' not found."
    echo "Available examples:"
    ls -1 examples
    exit 1
fi

echo "Building and running example: $EXAMPLE"

cargo run --manifest-path examples/$EXAMPLE/Cargo.toml

echo "Example run completed."
