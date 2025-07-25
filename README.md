# DePIN SDK

**The first Web4 blockchain framework enabling "read-write-own-understand" through fully decentralized AI.** Build sovereign app chains with natural language smart contracts, privacy-preserving semantic understanding, and cross-chain interoperability—all without external dependencies.

## Key Features:
- **Truly Decentralized AI**: LLMs run directly on validator nodes with deterministic, sharded, or consensus execution modes
- **Compile-Time Sovereignty**: Inherit shared knowledge at compilation, then operate independently forever
- **Universal Interoperability**: Poly-homomorphic commitment schemes with intelligent proof translation between heterogeneous chains
- **Post-Quantum Security**: Comprehensive PQC suite with algorithm agility and migration paths
- **Multi-VM Support**: WASM (default), EVM compatibility, or custom VMs with privileged plugin architecture
- **No External Dependencies**: Eliminates oracle networks through validator-based data fetching
- **Privacy-First Design**: FHE, differential privacy, and ZK proofs for sensitive applications
- **Flexible Everything**: Choose your consensus, governance, cryptography, state model, and execution environment

## Built for:
Enterprise blockchains • DeFi protocols • Gaming infrastructure • IoT networks • Privacy-sensitive healthcare • Autonomous DAOs • Creative platforms • Cross-chain applications

**From simple tokens to complex multi-agent systems, DePIN SDK is the foundation for Web4 innovation.**

## Getting Started

### Prerequisites

- Rust (stable channel)
- Docker (for container-based development and validators)
- VS Code with Remote Containers extension (optional but recommended)

### Quick Setup


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
- `crates/services/`:  
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
