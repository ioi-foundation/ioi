# NOW

Generated. Do not edit. `node internal-docs/implementation/tools/generate-now.mjs --write`

This file is a projection. It owns no sequence and no status. Sequence lives in
[`program/sequence.v1.json`](./program/sequence.v1.json); status lives in the work-item record named below.

## Open stages

| Stage | State | Records | Exit gate |
| --- | --- | --- | --- |
| [M0](./stages/m0.md) — Program Control And Claim Lock | evidence_ready — **exit gate held by osh-0025** | verified_historical_with_open_successor 8, verified 3, proposed 3 | `m0-program-control-selected-profile-exit-proof` |
| [M3](./stages/m3.md) — Generic Pursuit And Result Seam | evidence_ready — **exit gate held by osh-0079** | verified 8, verified_historical_with_open_successor 3 | `m3-direct-path-and-exit-proof` |
| [M5](./stages/m5.md) — Participants, Local Agents, And Shared Frontier | pending | verified 1, proposed 11 | `m5-selected-profile-exit-proof` |

## Earliest open stage

**M0 — Program Control And Claim Lock** (evidence_ready)

- why it is current: exact sequence exit gate is verified_historical_with_open_successor under osh-0025
- depends on: (nothing)
- stage module: [`stages/m0.md`](./stages/m0.md)
- records: 14 (verified_historical_with_open_successor 8, verified 3, proposed 3)
- exit gate: `m0-program-control-selected-profile-exit-proof`

## Next cut

**`m5-goalrun-thread-orchestration-seam`** — proposed

Bind every executing GoalRun and harness-to-harness delegation to the daemon-owned thread event, thread fork, managed session, session launch recipe, and harness session binding primitives.

- record: [`work-items/proposed/m5-goalrun-thread-orchestration-seam.v1.json`](./work-items/proposed/m5-goalrun-thread-orchestration-seam.v1.json)
- status authority: `private_record` → `internal-docs/implementation/work-items/proposed/m5-goalrun-thread-orchestration-seam.v1.json`
- dependencies satisfied: yes
- canon owners:
  - `docs/architecture/_meta/implementation-matrix.md`
  - `docs/architecture/components/daemon-runtime/doctrine.md`
  - `docs/architecture/components/hypervisor/core-clients-surfaces.md`
  - `docs/architecture/domains/ioi-ai/control-plane.md`
  - `docs/architecture/foundations/objects/goal-run-execution.md`
  - `docs/decisions/0031-goalrun-execution-composes-thread-orchestration.md`
- in scope:
  - M5.0 and ADR 0031's exact five-owner GoalRun execution composition
  - One primary harness requesting one bounded delegated harness only through daemon-owned fork/session/launch contracts
  - Exact GoalRun refs to kernel event, fork, managed-session, launch-recipe, harness-binding, receipt, and replay truth
  - Positive, denial, stale-state, substitution, restart, replay, fault, and retained-evidence proof for the seam
- out of scope:
  - M4 room admission, CAS, lineage, replay, projection, or literals
  - M5 pairing, participant admission, frontier, claim, Attempt, Finding, VerifierChallenge, acceptance, export, or settlement lifecycles
  - General durable pub/sub, dynamic subscription creation, durable subscriber checkpoints, and accepted-event losslessness; those belong to m5-agentgres-durable-event-subscription-successor.
  - General untrusted-workload isolation or a strong-sandbox claim; those remain in M9.
  - Deleting GoalRun, requiring a Session for a non-executing GoalRun, or granting authority through a thread, fork, Session, or harness binding
  - Creating this proposed record does not implement behavior, close its literal, or change M4 status.

## Permitted differential lanes

These lanes are derived from structured exceptions in `program/sequence.v1.json`. They do not change stage state or satisfy a stage dependency.

None currently permitted.

## Open successor holds

Source of truth: [`./_archive/holds/open-successor-holds.v1.json`](./_archive/holds/open-successor-holds.v1.json). A hold opens when a review dispositions a change `successor_required`, or when a
verification is withdrawn. While it is open every predecessor closure it names projects as
`verified_historical_with_open_successor` — proven against the revision it was proven against, with a
successor owed and unwritten. It is never projected as unqualified `verified`.

| Hold | Subject | Source | Required successor | Predecessors projected as qualified |
| --- | --- | --- | --- | --- |
| `osh-0019` | `docs/architecture/components/daemon-runtime/doctrine.md` | canon_acceptance_disposition (acceptance 3) | `m9-hypervisor-app-primary-attach-binding-and-retirement` | 2 |
| `osh-0020` | `docs/architecture/components/hypervisor/core-clients-surfaces.md` | canon_acceptance_disposition (acceptance 3) | `m9-hypervisor-app-primary-attach-binding-and-retirement` | 6 |
| `osh-0025` | `docs/decisions/README.md` | canon_acceptance_disposition (acceptance 3) | `m9-hypervisor-app-primary-attach-binding-and-retirement` | 9 |
| `osh-0077` | `docs/architecture/_meta/canon-to-code-delta.md` | canon_acceptance_disposition (acceptance 20) | `m5-goalrun-thread-orchestration-seam` | 0 |
| `osh-0078` | `docs/architecture/_meta/implementation-matrix.md` | canon_acceptance_disposition (acceptance 20) | `m5-goalrun-thread-orchestration-seam` | 0 |
| `osh-0079` | `docs/architecture/components/daemon-runtime/doctrine.md` | canon_acceptance_disposition (acceptance 20) | `m5-goalrun-thread-orchestration-seam` | 3 |
| `osh-0080` | `docs/architecture/components/hypervisor/core-clients-surfaces.md` | canon_acceptance_disposition (acceptance 20) | `m5-goalrun-thread-orchestration-seam` | 2 |
| `osh-0081` | `docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md` | canon_acceptance_disposition (acceptance 20) | `m5-goalrun-thread-orchestration-seam` | 0 |
| `osh-0082` | `docs/architecture/domains/ioi-ai/control-plane.md` | canon_acceptance_disposition (acceptance 20) | `m5-goalrun-thread-orchestration-seam` | 0 |
| `osh-0083` | `docs/architecture/foundations/objects/goal-run-execution.md` | canon_acceptance_disposition (acceptance 20) | `m5-goalrun-thread-orchestration-seam` | 2 |
| `osh-0084` | `docs/decisions/0031-goalrun-execution-composes-thread-orchestration.md` | canon_acceptance_disposition (acceptance 20) | `m5-goalrun-thread-orchestration-seam` | 0 |

18 verified record(s) project as `verified_historical_with_open_successor`:

- `m0-adjacent-canon-doc-class-and-placement-disposition` — held by osh-0025
- `m0-canon-owner-coverage-and-orphan-verifier` — held by osh-0025
- `m0-literal-exit-evidence-contract` — held by osh-0025
- `m0-program-control-selected-profile-exit-proof` — held by osh-0025
- `m0-route-final-invoker-pg-census-maintenance` — held by osh-0019, osh-0020
- `m0-selected-profile-baseline-and-claim-lock-successor` — held by osh-0025
- `m0-selected-profile-baseline-evidence-and-claim-lock` — held by osh-0025
- `m0-source-disposition-and-single-sequencer-successor` — held by osh-0025
- `m0-source-disposition-and-single-sequencer-verifier` — held by osh-0025
- `m0-work-item-contract-completeness-and-owner-lint` — held by osh-0025
- `m1-dual-genesis-and-read-projection` — held by osh-0020
- `m1-system-genesis-product-journey` — held by osh-0020
- `m2-agentgres-replay-recovery-and-product-topology` — held by osh-0020
- `m3-direct-path-and-exit-proof` — held by osh-0079
- `m3-goal-kernel-context-and-runtime-truth-spine` — held by osh-0079, osh-0080, osh-0083
- `m3-work-session-automation-product-journey` — held by osh-0079, osh-0080, osh-0083
- `project-discovery-startup-and-session-chain` — held by osh-0019, osh-0020
- `scm-publication-effect-and-route-rebuild` — held by osh-0020

## Filed, not gating

Real work that is deliberately not on the critical path, so it is never nominated as the next cut. Excluded from nomination, never from view.

| Work item | Stage | Status | Why it does not gate |
| --- | --- | --- | --- |
| `m0-declared-relationship-enforcement-successor` | M0 | proposed | `post_exit_successor` |
| `m0-gate-input-closure-successor` | M0 | proposed | `deliberately_non_gating` |
| `m0-review-epoch-partial-attestation-successor` | M0 | proposed | `deliberately_non_gating` |
| `m2-authority-ref-shape-unification-successor` | M2 | proposed | `post_exit_successor` |
| `m4-exact-projection-assertion-nondeterminism-successor` | M4 | proposed | `deliberately_non_gating` |
| `m5-p0-readiness-verifier` | M5 | proposed | `consumes_stage_exit_cannot_gate_it` |
| `m5-qm-reference-shell-executable-rebind` | M5 | proposed | `deliberately_non_gating` |
| `m5-thread-event-legacy-stream-migration-successor` | M5 | proposed | `deliberately_non_gating` |

## What to run

```text
while developing   node internal-docs/implementation/tools/check-fast.mjs
at stage exit      node internal-docs/implementation/tools/certify-stage.mjs M0
at a release gate  node internal-docs/implementation/tools/check-program.mjs
```

## What blocks advancement

- 6 canon subject(s) exist only on this branch and carry no classification; they grant no coverage until they land
- 14 canon subject digest(s) changed since the reviewed baseline; affected stages: FUTURE, M0, M10, M11, M14, M2, M3, M4, M6, M7, M9
- open successor hold `osh-0019` on `docs/architecture/components/daemon-runtime/doctrine.md`: successor `m9-hypervisor-app-primary-attach-binding-and-retirement`; 2 predecessor closure(s) project as `verified_historical_with_open_successor`
- open successor hold `osh-0020` on `docs/architecture/components/hypervisor/core-clients-surfaces.md`: successor `m9-hypervisor-app-primary-attach-binding-and-retirement`; 6 predecessor closure(s) project as `verified_historical_with_open_successor`
- open successor hold `osh-0025` on `docs/decisions/README.md`: successor `m9-hypervisor-app-primary-attach-binding-and-retirement`; 9 predecessor closure(s) project as `verified_historical_with_open_successor`
- open successor hold `osh-0077` on `docs/architecture/_meta/canon-to-code-delta.md`: successor `m5-goalrun-thread-orchestration-seam`; 0 predecessor closure(s) project as `verified_historical_with_open_successor`
- open successor hold `osh-0078` on `docs/architecture/_meta/implementation-matrix.md`: successor `m5-goalrun-thread-orchestration-seam`; 0 predecessor closure(s) project as `verified_historical_with_open_successor`
- open successor hold `osh-0079` on `docs/architecture/components/daemon-runtime/doctrine.md`: successor `m5-goalrun-thread-orchestration-seam`; 3 predecessor closure(s) project as `verified_historical_with_open_successor`
- open successor hold `osh-0080` on `docs/architecture/components/hypervisor/core-clients-surfaces.md`: successor `m5-goalrun-thread-orchestration-seam`; 2 predecessor closure(s) project as `verified_historical_with_open_successor`
- open successor hold `osh-0081` on `docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md`: successor `m5-goalrun-thread-orchestration-seam`; 0 predecessor closure(s) project as `verified_historical_with_open_successor`
- open successor hold `osh-0082` on `docs/architecture/domains/ioi-ai/control-plane.md`: successor `m5-goalrun-thread-orchestration-seam`; 0 predecessor closure(s) project as `verified_historical_with_open_successor`
- open successor hold `osh-0083` on `docs/architecture/foundations/objects/goal-run-execution.md`: successor `m5-goalrun-thread-orchestration-seam`; 2 predecessor closure(s) project as `verified_historical_with_open_successor`
- open successor hold `osh-0084` on `docs/decisions/0031-goalrun-execution-composes-thread-orchestration.md`: successor `m5-goalrun-thread-orchestration-seam`; 0 predecessor closure(s) project as `verified_historical_with_open_successor`
- stage exit requires the aggregate record `m0-program-control-selected-profile-exit-proof` to reach `verified` on proof

## Provenance

```text
orientation inputs  94af2b1e3e405b712fcd5a97ec6958025d5c9a02dbddc97fec2bc0b722572bdb
sequence            bce04cda8eade7634e22ac8555eb47559336af8fa17d3a2c34fe83758e89b075
```

Route presence, an HTTP 200, a screenshot, a plan, or a process exit code is not proof. See [`program/rules.md`](./program/rules.md) §6.
