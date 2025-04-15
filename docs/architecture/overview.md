# DePIN SDK Architecture Overview

## Core Architecture

DePIN SDK is a Rust-based, modular framework for building sovereign app chains with post-quantum cryptography, customizable consensus mechanisms, and a flexible container-based validator architecture. 

## Building from the Bottom Up

The DePIN SDK follows a "bottom-up" architecture where each layer builds upon the foundations established by lower layers:

1. **Core Traits and Interfaces**: Foundational traits like `CommitmentScheme` and `StateTree` that define the abstractions used throughout the SDK.

2. **Cryptographic Primitives**: Implementations of both traditional and post-quantum cryptographic algorithms.

3. **Commitment Schemes**: Various implementations of commitment schemes (Merkle, Pedersen, KZG, lattice-based).

4. **State Tree Implementations**: Different state tree structures built on top of commitment schemes.

5. **Transaction Models**: UTXO, account-based, and hybrid transaction models.

6. **Homomorphic Operations**: Support for operations on encrypted data.

7. **IBC Translation Layers**: Cross-chain interoperability mechanisms.

8. **Validator Architecture**: Container-based validator implementations.

9. **App Chain Implementation**: Complete sovereign app chain implementations.

## Polymorphic Design

The SDK uses Rust's trait system to provide a polymorphic architecture that allows components to be swapped out or upgraded without affecting dependent layers. For example, an app chain can change its underlying commitment scheme without modifying its transaction logic.

## Container Security

The validator architecture uses a multi-container approach to create strong security boundaries between components:

- Standard Validator: 3 containers (Guardian, Orchestration, Workload)
- Hybrid Validator: 5 containers (adds Interface and API containers)

## Post-Quantum Security

The SDK provides first-class support for post-quantum cryptographic algorithms:

- Kyber for key encapsulation
- Dilithium, Falcon, and SPHINCS+ for signatures
- Lattice-based vector commitments for Verkle trees

## Getting Started

See the [Getting Started Guide](../guides/getting_started.md) for instructions on setting up your development environment and creating your first app chain with DePIN SDK.
