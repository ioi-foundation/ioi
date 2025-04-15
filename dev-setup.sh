#!/bin/bash

# dev-setup.sh - Setup development environment for DePIN SDK

set -e  # Exit on error

echo "Setting up DePIN SDK development environment..."

# Check if Rust is installed
if ! command -v rustc &> /dev/null; then
    echo "Rust is not installed. Installing now..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "Rust is already installed."
fi

# Add necessary components
rustup component add rustfmt clippy

# Check if Docker is installed (for development containers)
if ! command -v docker &> /dev/null; then
    echo "WARNING: Docker is not installed. It is recommended for use with dev containers."
    echo "Please install Docker manually to use the container-based development environment."
else
    echo "Docker is installed."
fi

# Install additional dependencies
echo "Installing additional dependencies..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt-get update
    sudo apt-get install -y build-essential pkg-config libssl-dev
elif [[ "$OSTYPE" == "darwin"* ]]; then
    brew install openssl pkg-config
fi

# Initialize Git repository if not already initialized
if [ ! -d .git ]; then
    git init
    git add .
    git commit -m "Initial commit of DePIN SDK"
fi

# Create initial build
echo "Building DePIN SDK..."
cargo build

echo "Development environment setup completed successfully!"
echo "To start development with VSCode dev containers:"
echo "1. Open the project in VSCode"
echo "2. Install the 'Remote - Containers' extension"
echo "3. Click 'Reopen in Container' when prompted, or run the command manually"
echo ""
echo "To build the project:"
echo "cargo build"
echo ""
echo "To run tests:"
echo "cargo test"
