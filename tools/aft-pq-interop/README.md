# AFT ML-DSA interoperability oracle

This isolated executable checks FIPS 204 and FIPS 205 byte-level
interoperability. It pairs production `dcrypt` ML-DSA-44 with independently
maintained RustCrypto `ml-dsa` 0.1.1, and production RustCrypto
`slh-dsa` 0.2.0-rc.5 with IntegrityChain `fips205` 0.4.1. ML-DSA version 0.1.1
includes the canonical-hint fix released after GHSA-5x2r-hc65-25f9.

It is excluded from the root workspace because RustCrypto requires Rust 1.85+
while the IOI workspace declares Rust 1.78. Run it with:

```sh
cargo +stable run --locked --manifest-path tools/aft-pq-interop/Cargo.toml
```

Success proves that each implementation pair agrees on deterministic key and
signature encodings and accepts the other implementation's signatures for the
same pure-signing context. This is interoperability evidence, not an
independent security audit.
