#!/bin/bash

# quick-start.sh - Quick start script for running the DePIN SDK example

set -e  # Exit on error

echo "Quick Start for DePIN SDK..."

# Build the simple chain example
echo "Building simple chain example..."
cargo build --manifest-path examples/simple_chain/Cargo.toml

# Run the example
echo "Running simple chain example..."
cargo run --manifest-path examples/simple_chain/Cargo.toml

echo "Example completed successfully!"
echo ""
echo "To explore more examples, check the 'examples/' directory."
echo "To learn more about the architecture, see the documentation in 'docs/'."
