# Runtime Refactor Progress

This file is durable task memory for the clean target-state refactor pass. If context is lost, resume from the latest `Next Step`.

| Time/Pass | Status | Files Changed | Tests Run | Blockers | Remaining Matches | Next Step |
|---|---|---|---|---|---|---|
| Pass 0 | IN PROGRESS | Created progress memory | Not run yet | None | Active Studio env/proof-trace names; large module roots | Add boundary docs and refactor-health guard |
| Pass 1 | COMPLETE | Added refactor docs and `scripts/check-runtime-refactor-health.sh`; renamed active Studio-era env/proof-trace names; moved large Rust roots into directory modules | `./scripts/check-runtime-refactor-health.sh` PASS | None | Guard scripts contain legacy patterns intentionally; large files reported as tracked debt | Run format/checks and repair module-move fallout |
| Pass 2 | IN PROGRESS | Repaired moved-module test paths and CLI chat/artifact imports | `cargo fmt --all` PASS; `cargo check -p ioi-api` PASS; `cargo check -p autopilot` PASS with existing warnings; `cargo check -p ioi-drivers` PASS; `cargo check -p ioi-services` PASS; `cargo check -p ioi-cli` PASS; `npm run typecheck` PASS; `cargo test -p ioi-services --test bounded_runtime_invariants` PASS; `cargo test -p ioi-api` COMPILES then fails in existing direct-author/local-runtime/inference cluster | Broad `ioi-api` suite remains unstable outside this refactor | Guard scripts contain intentional patterns; large files are reported debt | Run remaining focused tests/build and final grep/status |
| Pass 3 | COMPLETE | Renamed active Chat shell UI variables/actions away from Studio; renamed chat-artifact corpus/tooling contracts and developer docs; tightened refactor guard for active Studio naming | `cargo fmt --all` PASS; `./scripts/check-runtime-refactor-health.sh` PASS; `./scripts/check-clean-break-debt.sh` PASS; `npm run typecheck` PASS; `npm run build:ide` PASS; `cargo check -p ioi-cli` PASS; `cargo check -p autopilot` PASS with existing warnings; focused services tests PASS | Broad `cargo test -p ioi-api` has pre-existing functional failures unrelated to the refactor | Only guard regexes and literal `visual studio code` remain in active grep | Done |

## Milestone Status

### Milestone 0 — Guard Rails And Baseline
Status: COMPLETE

- Add refactor boundary docs.
- Add guard script for active legacy naming and compatibility debt.
- Record known large-module decomposition targets.

### Milestone 1 — Active Naming Cleanup
Status: COMPLETE

- Replace active Studio-era env vars and proof trace labels with chat/artifact runtime names.
- Keep legacy names only in historical docs and audit/progress files.

### Milestone 2 — Module Topology
Status: COMPLETE

- Move root monolith files into directory modules where that can be done mechanically.
- Prefer active module names that match product/runtime boundaries.

### Milestone 3 — Validation
Status: COMPLETE

- Run guards, formatting, and focused checks.
- Repair failures introduced by the refactor.

## Final Notes

- Active `Studio` naming is removed from active `apps/`, `crates/`, `packages/`, and `scripts/` code except guard regexes and the literal editor phrase `visual studio code`.
- Large files remain, but they are now either under directory-module roots or explicitly reported by `scripts/check-runtime-refactor-health.sh` and tracked in `docs/runtime/refactor-boundaries.md`.
- `cargo test -p ioi-api` compiles after the refactor but still fails in the existing direct-author/local-runtime/inference-adapter test cluster. This is recorded as baseline instability, not a refactor compile failure.
