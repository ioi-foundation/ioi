# DePIN SDK

A Rust-based, modular framework for building sovereign app chains with post-quantum cryptography, customizable consensus mechanisms, and a flexible container-based validator architecture.

## Core Features

- **Polymorphic Trait-Based Modularity**: Components are designed as fully interchangeable plugins
- **Homomorphic Commitment Schemes**: Support for operations directly on commitments
- **Commitment Scheme Agility**: Runtime selection of different commitment schemes
- **Post-Quantum Security**: First-class support for PQC algorithms
- **Container Isolation**: Strong security boundaries between components
- **Flexible Transaction Models**: Support for UTXO, account-based, and hybrid models
- **Cross-Chain Interoperability**: Proof translation between different commitment schemes

## Getting Started

### Prerequisites

- Rust (stable channel)
- Docker (for container-based development and validators)
- VS Code with Remote Containers extension (optional but recommended)

### Quick Setup

1. Clone this repository
2. Run the setup script:

```bash
./dev-setup.sh
```

3. Run the quick start example:

```bash
./quick-start.sh
```

### Development with VS Code Dev Containers

This project is configured for development using VS Code's Remote Containers feature:

1. Open the project in VS Code
2. When prompted, click "Reopen in Container"
3. VS Code will build the dev container with all required dependencies

## Project Structure

The DePIN SDK follows a "bottom-up" architecture:

- `crates/core/`: Core traits and interfaces
- `crates/commitment_schemes/`: Commitment scheme implementations
- `crates/state_trees/`: State tree implementations
- `crates/transaction_models/`: Transaction model implementations
- `crates/validator/`: Validator implementation with container architecture
- `crates/ibc/`: Inter-Blockchain Communication implementation
- `crates/crypto/`: Cryptographic implementations including post-quantum
- `crates/homomorphic/`: Homomorphic operations implementation
- `crates/chain/`: Chain implementation components
- `crates/test_utils/`: Utilities for testing the SDK components

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- Architecture overview: `docs/architecture/overview.md`
- Getting started guides: `docs/guides/`
- API documentation: `docs/api/`
- Security documentation: `docs/security/`

## License

This project is licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
