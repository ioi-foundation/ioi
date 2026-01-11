# IOI Kernel Crypto Module

Quantum-resistant cryptographic primitives for the IOI Kernel, built on top of the [dcrypt](https://github.com/dcrypt-rs/dcrypt) library.

## Features

- **Post-Quantum Signatures**: Dilithium (ML-DSA) implementation with multiple security levels
- **Type-Safe API**: Strong typing ensures correct usage of keys and signatures
- **No-std Support**: Can be used in embedded environments
- **Zeroization**: Automatic secure memory cleanup for sensitive data
- **Comprehensive Testing**: Full test coverage with test vectors
- **Performance**: Optimized implementations with optional SIMD support

## Usage

### Basic Example

```rust
use ioi_crypto::prelude::*;

// Create a Dilithium signature scheme
let scheme = DilithiumScheme::new(SecurityLevel::Level2);

// Generate a key pair
let keypair = scheme.generate_keypair();

// Sign a message
let message = b"Hello, quantum world!";
let signature = keypair.sign(message);

// Verify the signature
assert!(keypair.public_key().verify(message, &signature));
```

### Key Serialization

```rust
// Export keys for storage
let public_key_bytes = keypair.public_key().to_bytes();
let private_key_bytes = keypair.private_key().to_bytes();

// Import keys from storage
let public_key = DilithiumPublicKey::from_bytes(&public_key_bytes)?;
let private_key = DilithiumPrivateKey::from_bytes(&private_key_bytes)?;
```

### Security Levels

The library supports three NIST security levels for Dilithium:

- `SecurityLevel::Level2` - 128-bit quantum security (Dilithium2)
- `SecurityLevel::Level3` - 192-bit quantum security (Dilithium3)
- `SecurityLevel::Level5` - 256-bit quantum security (Dilithium5)

## Performance

Run benchmarks with:

```bash
cargo bench --features benchmarks
```

Typical performance on modern hardware:

| Operation | Level 2 | Level 3 | Level 5 |
|-----------|---------|---------|---------|
| Key Gen   | ~0.1ms  | ~0.2ms  | ~0.3ms  |
| Sign      | ~0.3ms  | ~0.5ms  | ~0.7ms  |
| Verify    | ~0.1ms  | ~0.2ms  | ~0.3ms  |

## Feature Flags

- `std` (default): Enable standard library support
- `no-std`: Disable standard library for embedded use
- `dilithium` (default): Enable Dilithium signatures
- `serde`: Enable serialization support
- `zeroize`: Enable secure memory wiping
- `parallel`: Enable parallel processing
- `simd`: Enable SIMD optimizations

## Security Considerations

1. **Key Storage**: Always store private keys securely. Consider using hardware security modules (HSMs) or secure enclaves when available.

2. **Random Number Generation**: The library uses `rand::rngs::OsRng` by default, which provides cryptographically secure randomness from the operating system.

3. **Side-Channel Resistance**: The dcrypt implementation includes countermeasures against timing attacks, but physical side-channel attacks may still be possible in some environments.

4. **Post-Quantum Security**: While Dilithium is believed to be secure against quantum attacks, the field of post-quantum cryptography is still evolving. Stay updated with NIST recommendations.


## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) first.

## License