# Asymptote Fault Tolerance Protocol Corpus

Status: internal protocol corpus index.
Authority: `docs/architecture/` and accepted ADRs are canonical; this file is private protocol corpus navigation only.
Migrated from: `docs/architecture/consensus/aft/` and `docs/consensus/aft/` standalone documentation roots.
Superseded by: canonical architecture docs or ADRs when conflicts arise.
Last alignment pass: 2026-05-02.

This directory holds Asymptote Fault Tolerance protocol material that is large
enough to remain as its own private corpus. The formal source and specs are
supporting protocol context; durable architecture conclusions must be promoted
to `docs/architecture/` or accepted ADRs before they become canonical. Generated
traces, TLC state dumps, and compiled paper outputs live under
[`internal-docs/formal/aft`](../../../formal/aft/).

- [`specs/`](./specs/) — protocol specs, theorem surfaces, and yellow paper source.
- [`formal/`](./formal/) — TLA+ source, configs, proof source, and formal-model READMEs.
- [`RUNBOOKS.md`](./RUNBOOKS.md) — operational runbooks.
- [`OPERATIONAL_POLICY.md`](./OPERATIONAL_POLICY.md) — operational policy.
