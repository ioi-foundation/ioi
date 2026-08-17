# aft-proofs — the AFT-CB real recursive-backend workspace (P2.5)

Status: AFT-CB program crate; its own Cargo workspace, **excluded from the
root workspace** — `cargo build --locked` at the repository root never
touches it. It builds with the succinct toolchain in its own nightly CI
lane (`.github/workflows/aft-proofs-nightly.yml`) and locally with the
recipe below.

## What is proven, labeled exactly

The guest (`program/`) proves ONE step of the collapse-continuity
relation: a previous step commitment (or genesis) is bound; a Unanimous
Boundary Close over `(boundary_root, batch_root)` is **signature-verified
in-guest** — every ring member's real ed25519 signature over the
domain-separated tuple, n-of-n, no smaller quorum exists in the program;
the canonical-order relation binds `order_root` to the closed boundary;
and the step commits the tuple the next step binds.

**Chain shape (honest label):** each step is an independent SP1 CORE
proof; the harness verifies every step proof and the hash chain links the
steps' committed public values. In-guest recursive verification —
compressing the chain into one succinct proof — is the R4c follow-up and
is **not** claimed here. `HashPcdV1` remains the estate's labeled
non-succinct reference profile; the release-profile `SuccinctSp1V1`
reservation (P0.3) flips only at R4c.

## The governed verifying-key pin

`vkey.json` pins the guest's verifying key (`vkey_bytes32`). The harness
**refuses** to run against any other key. `UNPINNED` is a refusal state,
never a fallback. Changing the pin is a protocol-parameter change: it
lands only through a reviewed PR that names the guest change forcing it.

## Running

```sh
# toolchain (once): sp1up → cargo-prove + the succinct rustc
curl -sL https://sp1up.succinct.xyz -o /tmp/sp1up.sh && bash /tmp/sp1up.sh && ~/.sp1/bin/sp1up
# native deps for the gnark FFI build: Go >= 1.22 and libclang
# (CI: apt-get install -y libclang-dev golang-go; no-sudo recipe in the
# AFT-CB ledger, P2.5 block — LLVM 17 ubuntu-22.04 tarball + BINDGEN_EXTRA_CLANG_ARGS)

cd crates/aft-proofs
cargo run --release --bin chain    # 3-step e2e: prove+verify each step, hash chain checked
cargo run --release --bin drills   # corrupt-byte + foreign-vkey refusal drills
```

Measured cost (P4.3 input): ~26.5s per step proof, CPU-only, 24-core
desktop-class machine; 79.2s for the 3-step chain.

## Licensing

`crates/**` is classed by `LICENSE-MANIFEST.json` (first-match, bbsl_1_1)
— no manifest change was needed for this path. External dependencies
(sp1-sdk, sp1-zkvm, sp1-build, ed25519-dalek, sha2 and the sp1-patches
forks) are MIT/Apache-2.0-class, compatible as dependencies per ADR 0033.
