# Determinism Audit — Admission Cores (Session 1, 2026-07-05)

Scope: `crates/services/src/agentic/runtime/kernel/` (the deterministic
`plan_*`/`project_*` admission cores) against the doctrine determinism rule
(docs/architecture/components/agentgres/doctrine.md, Substrate Contract
Doctrine): no wall clock, no randomness, no thread nondeterminism inside
admission logic; nondeterminism enters only as recorded operation inputs.

## Findings

**Randomness: CLEAN.** Zero uses of `rand::`, `thread_rng`, `fastrand`,
`Uuid::new_v4`, or `nanoid` anywhere in the kernel. No confinement work
needed.

**Wall clock: 33 uses across 8 kernel files** (the violation surface):

- `runtime_lifecycle.rs`
- `deadline.rs`
- `runtime_memory_control.rs`
- `workspace_restore.rs`
- `agentgres_admission.rs` (1 use, line ~4639 — a nanos-derived helper)
- `skill_hook_registry.rs`
- `policy/workspace_trust.rs`
- `coding_tool_event.rs`

Classification: most are timestamp stamping (`recorded_at`-style fields) and
deadline arithmetic, not state-content derivation — i.e., confinement is a
mechanical refactor (accept `now_ms: u64` as a parameter from the route/hail
layer), not a redesign. `deadline.rs` is the only file where clock reads are
load-bearing logic; its confinement needs a `DeadlineClock` input trait.

**HashMap iteration order: LOW RISK.** 5 `HashMap` uses in the kernel; none
feed hash/root computation (state roots are carried strings, not computed
from map iteration). New substrate code uses `BTreeMap` exclusively.

## Confinement rule for new code (binding now)

`crates/agentgres` is `#![forbid(unsafe_code)]`, has zero clock
and zero randomness inside the engine (`recorded_at_ms` is an operation
input; the bench harness reads clocks, the engine never does), and uses
`BTreeMap` for all rooted state. This is the reference posture; kernel files
migrate to it as they are touched (same-change rule as the status axis).

## Migration backlog (tracked, not done)

1. Thread `now_ms` parameters into the 8 kernel files' public entry points,
   sourcing from the route layer (one mechanical pass; ~33 sites).
2. `deadline.rs`: introduce a clock-input trait so deadline logic is
   simulation-testable.
3. Add a conformance grep (deny `SystemTime::now`/`Utc::now` under
   `kernel/`) once 1–2 land, so the surface cannot regrow.
