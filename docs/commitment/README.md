# Commitment Tree References

Status: reference index over commitment-tree implementation notes.
Canonical owner: none for doctrine; the implementations under `crates/state` are the source of truth, and this index only routes readers
Document class: `canonical-index`
Doctrine status: reference
Implementation status: built (IAVL state backend live under `crates/state`; the mHNSW certifying retrieval product path is retired)
Implementation refs:
  - crates/state
Last implementation audit: 2026-07-26

## Contents

- [`tree/iavl/README.md`](./tree/iavl/README.md) — production IAVL state
  backend reference.
- [`tree/mhnsw/README.md`](./tree/mhnsw/README.md) — historical notes on the
  retired mHNSW certifying retrieval path.

Architecture doctrine for state commitment lives under
[`docs/architecture/`](../architecture/README.md); these files are low-level
reference and history only.
