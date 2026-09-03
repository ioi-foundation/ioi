# AFT assurance clean-room verifier

This verifier uses Python's standard library and the separately compiled
RustCrypto ML-DSA oracle in `tools/aft-pq-interop`. It imports no IOI crate and
does not contact an IOI node. It independently reproduces the canonical/hash,
runtime-certificate, full-mesh channel, rooted terminal-seal,
manifest/consequence, collateral-floor, transformation and policy checks for
the closed v1 receipt profile. The oracle verifies ML-DSA with RustCrypto and
SLH-DSA with `fips205`, rather than the production dcrypt/`slh-dsa` paths.

Run the committed golden vectors:

```sh
python3 tools/aft-assurance-cleanroom/verify.py
```

Verify a complete canonical receipt after building the independent oracle:

```sh
cargo build --manifest-path tools/aft-pq-interop/Cargo.toml
python3 tools/aft-assurance-cleanroom/verify.py \
  --receipt RECEIPT.json \
  --negative-dir VALIDLY_REENVELOPED_NEGATIVE_RECEIPTS \
  --pq-oracle tools/aft-pq-interop/target/debug/aft-pq-interop
```

The release harness generates the complete receipt and its validly
re-enveloped inner-mutation corpus into a temporary directory before invoking
this command. Randomized PQ signatures and KEM transcripts therefore remain
fresh while representation-level canonical/economic golden vectors remain
committed and stable.
