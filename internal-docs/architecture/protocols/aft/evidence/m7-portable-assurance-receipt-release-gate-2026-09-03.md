# M7 portable assurance receipt release-gate evidence — 2026-09-03

## Result

The source-neutral verifier library and `ioi-receipt-proof-verify` CLI accept a
complete canonical receipt only against a separately provisioned canonical
trust policy, without an IOI node or network. The success report
contains the achieved `GuaranteeVectorV1`, policy result, verified constituents
and exact verified transformations. Refusals are typed and machine-readable.

## Bound constituents

- effect manifest and exact policy;
- configuration and active-key snapshot roots;
- embedded runtime-v3 ordering, availability and finality evidence;
- complete, payload-bound PQ channel graph for the rooted finality membership;
- unanimous configuration votes over the terminal-key manifest and one
  SLH-DSA terminal share per member;
- achieved guarantee vector and T12/T1/T10/T11 transform trace;
- accountability evidence, bond snapshot and distinctness proof;
- intent, execution, outcome and reconciliation roots;
- atomic resource record and adapter profile;
- resource-profile-rooted ML-DSA endpoint evidence;
- requested anchor reference/hash pairs;
- schema and verifier profile;
- canonical receipt hash and ML-DSA-44 signature.
- external network, configuration, epoch, terminal-key-root, receipt-signer,
  anchor and relying-party guarantee pins that are not learned from the
  receipt.

## Negative corpus

The tests reject unknown receipt versions, verifier profiles, signature
algorithms and transformations; noncanonical bytes; manifest/policy drift;
mutations of intent, self-nominated configuration/signer/anchors,
configuration/key enrollment votes, missing or altered PQ
channel edges, terminal shares/domain, endpoint evidence, outcome, collateral
amount, achieved PQ coordinates, anchors, and embedded finality signatures;
stale, duplicate, shared, encumbered and unpriceable economic evidence through
M6. Seven inner forgeries, including a withheld unanimous share, are validly
re-enveloped so failure cannot be credited to the outer receipt signature.

## Independent reproduction

- Production signs/verifies the envelope through dcrypt ML-DSA-44.
- The unit gate imports that signature into RustCrypto `ml-dsa` and verifies
  the exact domain-separated receipt message.
- `tools/aft-assurance-cleanroom/verify.py` imports no IOI crate and reproduces
  runtime-certificate hashes/signature, the six-edge channel graph, four
  enrollment votes, four terminal shares, endpoint evidence, canonical/hash,
  manifest/resource, collateral, transform and policy checks.
- `tools/aft-pq-interop` exposes generic independent RustCrypto ML-DSA and
  `fips205` SLH-DSA verification modes.
- Committed canonical and arbitrary-precision economic golden vectors pass the
  clean-room verifier.

## Reproduction

```text
cargo test -p ioi-finality --features portable-assurance portable_assurance --lib
cargo test -p ioi-finality --features portable-assurance --lib
cargo check -p ioi-finality --features portable-assurance --bin ioi-receipt-proof-verify
python3 tools/aft-assurance-cleanroom/verify.py
cargo build --manifest-path tools/aft-pq-interop/Cargo.toml
RECEIPT_DIR="$(mktemp -d)"
AFT_PORTABLE_RECEIPT_OUTPUT="${RECEIPT_DIR}/complete-v1.json" \
  AFT_PORTABLE_TRUST_OUTPUT="${RECEIPT_DIR}/external-trust-v1.json" \
  AFT_PORTABLE_NEGATIVE_OUTPUT_DIR="${RECEIPT_DIR}/negative" \
  cargo test -p ioi-finality --features portable-assurance portable_assurance --lib
python3 tools/aft-assurance-cleanroom/verify.py \
  --receipt "${RECEIPT_DIR}/complete-v1.json" \
  --trust "${RECEIPT_DIR}/external-trust-v1.json" \
  --negative-dir "${RECEIPT_DIR}/negative" \
  --pq-oracle tools/aft-pq-interop/target/debug/aft-pq-interop
cargo fmt --all -- --check
git diff --check
```

Authoritative complete-path rerun: 4 / 4 production tests passed in 165.97
seconds; the clean-room verifier accepted the generated 1.08 MB receipt and
rejected all seven validly re-enveloped inner mutations.

## Boundary

M7 proves portable verification and, for the ADR 0047 profile, independently
reconstructs a payload-scoped end-to-end PQ decision. It does not erase weaker
constituents, establish adaptive security, or replace the required independent
cryptographic/custody/channel review. M8 owns integrated production emission.
