# Close The Parity Gap With Artifacts

The retained artifact-parity execution surface in this repo now lives in:

- `docs/evidence/studio-artifact-surface/README.md`
- `docs/evidence/studio-artifact-surface/benchmark-suite.catalog.json`
- `docs/evidence/studio-artifact-surface/release-gates.json`
- `docs/evidence/studio-artifact-surface/parity-loop/ledger.json`
- `docs/evidence/studio-artifact-surface/distillation/ledger.json`

Operational rule:

- treat those retained evidence files and their generators as the current
  artifact-parity plan of record
- preserve CIRC and CEC invariants
- keep promotion benchmark-first, conformance-backed, and receipt-backed

Execution hooks:

- `node scripts/generate-studio-artifact-corpus-summary.mjs`
- `node scripts/generate-studio-artifact-arena.mjs`
- `node scripts/run-studio-artifact-release-gates.mjs`
- `node scripts/run-studio-artifact-parity-loop.mjs`
