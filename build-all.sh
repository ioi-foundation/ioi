#!/bin/bash

# Build all DePIN SDK crates in the correct order

set -e  # Exit on error

echo "Building all DePIN SDK crates..."

# Step 1: Build core traits
echo "Building core traits..."
cargo build --package depin-sdk-core

# Step 2: Build cryptography implementations
echo "Building cryptography implementations..."
cargo build --package depin-sdk-crypto

# Step 3: Build commitment schemes
echo "Building commitment schemes..."
cargo build --package depin-sdk-commitment-schemes

# Step 4: Build state trees
echo "Building state trees..."
cargo build --package depin-sdk-state-trees

# Step 5: Build transaction models
echo "Building transaction models..."
cargo build --package depin-sdk-transaction-models

# Step 6: Build homomorphic operations
echo "Building homomorphic operations..."
cargo build --package depin-sdk-homomorphic

# Step 7: Build IBC implementation
echo "Building IBC implementation..."
cargo build --package depin-sdk-ibc

# Step 8: Build validator implementation
echo "Building validator implementation..."
cargo build --package depin-sdk-validator

# Step 9: Build test utilities
echo "Building test utilities..."
cargo build --package depin-sdk-test-utils

# Step 10: Build examples
echo "Building examples..."
for example in examples/*; do
    if [ -d "$example" ]; then
        echo "Building example: $example"
        cargo build --manifest-path $example/Cargo.toml
    fi
done

echo "All DePIN SDK crates built successfully!"
