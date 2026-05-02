# Asymptote Fault Tolerance Protocol Corpus

Status: canonical protocol corpus index.
Canonical owner: this file for AFT protocol documentation location and navigation.
Supersedes: `docs/architecture/consensus/aft/` and `docs/consensus/aft/` as standalone documentation roots.
Superseded by: none.
Last alignment pass: 2026-05-02.

This directory holds Asymptote Fault Tolerance protocol material that is large
enough to remain as its own corpus. The formal source and specs stay in
architecture because they define protocol authority. Generated traces, TLC state
dumps, and compiled paper outputs live under [`docs/formal-artifacts/aft`](../../../formal-artifacts/aft/).

- [`specs/`](./specs/) — protocol specs, theorem surfaces, and yellow paper source.
- [`formal/`](./formal/) — TLA+ source, configs, proof source, and formal-model READMEs.
- [`RUNBOOKS.md`](./RUNBOOKS.md) — operational runbooks.
- [`OPERATIONAL_POLICY.md`](./OPERATIONAL_POLICY.md) — operational policy.
