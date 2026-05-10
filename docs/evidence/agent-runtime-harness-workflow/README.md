# Agent Runtime Harness Workflow Evidence

This folder names the canonical latest green evidence bundle for the
agent-runtime-harness-as-workflow master guide.

## Latest Green

- Machine-readable index:
  `docs/evidence/agent-runtime-harness-workflow/latest-green.json`
- Full retained GUI harness result:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-10T15-53-13-199Z/result.json`
- Runtime P3 dashboard:
  `docs/evidence/agent-runtime-p3-validation/2026-05-10T16-00-53-223Z/dashboard-index.json`

## What It Proves

- The default harness is the live workflow-backed runtime substrate for the
  retained path.
- P0 runtime components are workflow-addressable and backed by TS/Rust
  contracts.
- Live turns expose node timeline, inspector, receipts, replay status, and
  live-vs-shadow comparison.
- Package import activation apply is green.
- Invalid fork activation is blocked, while valid package/import activation can
  mint an activation id.
- Reviewed fork mutation canary identity is bound into the package snapshot.
- Worker attach, resume, and rollback lifecycle is accepted.
- Active runtime rollback proof, dry-run, apply execution, and negative apply
  cases are green.
- Runtime P3 has zero incomplete items with required GUI evidence.

## Historical Runs

Older timestamped bundles in
`docs/evidence/autopilot-gui-harness-validation/` and
`docs/evidence/agent-runtime-p3-validation/` are retained as historical run
records. They are useful for archaeology and regression comparison, but this
index is the canonical pointer for the current green checkpoint until a newer
index replaces it.
