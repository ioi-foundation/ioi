# Clean-Slate Convergence Pass — 2026-07-25

Status: evidence artifact (pass record). Never authority; ADR 0022 and the
owner docs are the authority.
Branch: `integrate/canon-reconciliation` (PR #107), converging the
maximal-ceiling architecture pass, the ADR 0022 owner rulings, and the
estate-wide compatibility purge into one merge to master — the clean baseline
M2 starts from.

## What this pass executed

1. **Convergence.** The maximal-ceiling pass commit was restacked onto the
   concurrent session's final head as `055321e64` (cherry-pick; no history
   rewritten; the temporary `arch/maximal-ceiling-pass` worktree branch is
   deleted after merge).
2. **ADR 0022 accepted** (`29f0a4c51`): Decision 1 — the goal/room family
   (GoalRunProfile, GoalRun, GoalRunActivation, OutcomeRoom, and the room
   object planes) consists of domain objects of the openly packaged ioi.ai
   orchestration application; Hypervisor keeps session vocabulary and the
   generic WorkResult/OutcomeDelta seam; protocol grammar is AIIP + package
   contracts. Decision 2 — with zero downstream users, live compatibility
   machinery is deleted, not aliased, estate-wide; history and runtime-state
   contracts are excluded.
3. **Layering applied to canon** (`ac73220c5`): three-layer table in
   term-boundaries; README stack and decision register; the GoalRun admission
   contract relocated from daemon doctrine (which keeps the INV-37
   admission-evidence discipline) to the application's object family in
   `objects/goal-run-execution.md`; ownership map, vocabulary, horizons,
   conformance inputs, and delta rows aligned.
4. **Compatibility purge — canon + gates** (`9714089a3`): deleted
   `HypervisorRouteAliasRegistration` and `HypervisorLegacyWorkSubjectAlias`
   object families; `/v1/missions` wire contracts and the route-alias sample
   registrations in api.md; the route-ledger alias column and `/sessions` +
   `/missions` alias routing; retired schemes `mission://`, `recipe://`,
   `facility_system://` (registry rows, prose clauses, and the
   `facility_system` alias key); Workbench / Work Ledger / Missions
   compatibility-alias language across defaults, start-here, map, vocabulary,
   matrix, delta, and the whitepaper; and the migration-receipt requirements
   in the product-taxonomy gate. Gate pins were updated in lockstep and
   **strengthened**: the deleted alias machinery is now forbidden vocabulary
   in the corpus scan. Kept deliberately: the snake→kebab ref-scheme
   normalization register (mid-migration machinery; m11 retires it by
   deletion), the `HypervisorSurfaceAlias` naming dictionary (name mappings
   only, no machinery), and the providers-and-environments v1 record-field
   compatibility clause (describes current persisted records honestly).
5. **Compatibility purge — TypeScript** (`7c3ebf574`): deprecated
   `AssistantNotification*` aliases, the 15 optional `Assistant*`
   session-runtime interface members, `AgentSession*` type aliases, the
   17-entry const alias block, all feature-detect forks, and the
   `HypervisorClientRuntime` twin methods deleted — canonical spellings are
   the only exports; `work-graph-compat.ts` (retired swarm wire keys) deleted
   with its mapping path.
6. **Route re-home** (`e520f5092`): 13 route families moved from
   `/v1/hypervisor/*` to `/v1/goal-orchestration/*` with the old routes
   deleted, not aliased — goal-runs, ioi-agent, outcome-rooms,
   room-participation-requests, room-participant-leases, work-frontier-items,
   work-claim-leases, resource-offers, capability-offers,
   work-eligibility-matches, attempts, findings, verifier-challenges.
   WorkResult and OutcomeDelta remain `/v1/hypervisor/*` (substrate seam).
   Loopback callers, the serve layer, the missions surface reads, the
   operational-depth atlas, the m0 program-control effect identities, and
   every plane verifier script updated in the same cut. The unreachable
   `legacy_implicit_creation` quarantine lane deleted. Marketplace
   `IntelligenceAsset`/`AssetType` `Swarm` variants renamed `WorkGraph`
   (SCALE index-stable).
7. **M0 program-control refresh**: review epoch 14 over the changed
   identities, canon-basis re-hash, anchor entry
   (`self_declared_unsigned`, reviewer label
   `claude-fable-5-clean-slate-convergence`), `--attest-review`, `--write`,
   `--check`.
8. **internal-docs consistency**: canon-impact baseline re-accepted; program
   state regenerated; work items
   `m6-systems-work-projection-and-mission-alias-migration` and
   `m11-canonical-contract-registry-and-legacy-ref-migration` annotated with
   ADR 0022 rescope notes (alias/migration halves are void; deletion-based
   retirement); gap dispositions recorded
   (`program/canon-gap-dispositions.v1.json`): gap 24 (the product crossing)
   and gap 22 (missing `prim:` vocabulary) resolved in canon.

## Named deferrals (each justified, none silent)

- **`/__ioi/missions` and `/__ioi/workbench` surface slugs/labels** keep
  their current names in the live serve layer this pass: they are pinned by
  the operational-depth atlas and the pixel/parity evidence chain, and under
  ADR 0022 sub-ruling 4 those surfaces are reassigned to the orchestration
  application via the product-surface registration family — the rename rides
  that leg. Canon no longer describes them as aliases; they are current
  implementation evidence with retired labels.
- **Snake→kebab ref-scheme normalization** (109-entry register) — retired by
  deletion in the m11 leg, per its ADR 0022 rescope note.
- **`AssistantWorkbench*` / `AssistantSessionRuntime` type-name family** —
  live canonical TS types; renaming them is the term-boundaries
  `ContextualWorkbench*` disposition's own leg, not compat machinery.
- **`/v1/hypervisor/work-ledger` route name** — wire name for the Provenance
  projection, pinned by 13+ verifier suites; retirement belongs to the
  Provenance surface leg. Canon calls the surface Provenance everywhere.

## Verification (literal)

| Check | Result |
| --- | --- |
| `npm run check:pre-next-leg` (full 12-gate runner) | **exit 0** — includes m0-program-control 60/60, architecture-docs pass, architecture-contract bar (18 rust-lifecycle tests ok), system-genesis compiler, conformance-docs 7/7, work-items 7 records, readiness 9/9, workflow-compositor, runtime layout |
| `npm run check:m0-program-control` | exit 0, 60/60 (epoch-14 refresh: `--attest-review` 0, `--write` 0, `--check` 0) |
| `npm run check:architecture-docs` | pass, exit 0 |
| `npm run check:conformance-docs` | 7 tests / 0 fail, exit 0 |
| `npm run check:architecture-contracts` | 171 fixtures, exit 0 |
| `npm run check:generated-contract-owners` | OK — 88 contracts, 17 Rust-owned, 71 quarantined (named gap, unchanged) |
| `npm run check:work-items` | pass, exit 0 |
| `npm run test:workflow-compositor-dogfood` | 9 tests / 0 fail |
| `cargo check` (ioi-node, ioi-types, ioi-services) | exit 0 |
| `cargo test -p ioi-node --bin hypervisor-daemon` | 341 passed / 0 failed |
| `cargo test -p ioi-api` | 344 passed / 0 failed (+282 in second suite) |
| `npx tsc --noEmit` (app + hypervisor-workbench package) | exit 0 both |
| `verify-hypervisor-outcome-room-plane` (live, isolated daemon + real wallet) | 140/140, exit 0 |
| `verify-hypervisor-work-frontier-claim-plane` | 56/56 (incl. 200/200 replay check), exit 0 |
| `verify-hypervisor-attempt-finding-plane` | 19/19, exit 0 |
| `verify-hypervisor-verifier-challenge-plane` | 25/25, exit 0 |
| `verify-hypervisor-resource-capability-offer-plane` | 20/20, exit 0 |
| `verify-hypervisor-resource-capability-offer-eligibility-regressions` | 3/3, exit 0 |
| `verify-hypervisor-work-result-plane` | 63/63, exit 0 |
| `verify-hypervisor-room-participation-plane` | **exit 1 — INHERITED failure, not introduced by this pass.** The crash-replay probe ("governed admission did not converge through real wallet.network", verifier line 286) fails because the fault-injected admit intent is persisted without `authority_resolved_at_ms` and the post-readiness completer's re-resolution (`governed_authority.rs` `reauthorize_sealed_receipt_with_context`) refuses it, retrying every boot ("QUARANTINED for bounded post-readiness authority re-resolution" → "retained (the governed intent lacks authority_resolved_at_ms)"). **Bisect proof:** reproduced bit-identically at the pre-pass base `fc80d2e73` in a clean worktree with a base-built daemon (`BASE_EXIT=1`, same message, same line). The seven sibling plane suites, including their own crash/replay and receipt-fault probes, pass on the converged branch. Fix belongs to the participation-plane owner as its own cut: either seal the resolution tuple before intent persistence under the dirsync-unconfirmed fault, or make post-readiness re-resolution perform a full fresh authority resolution for intents that legitimately lack the sealed tuple — a governed-authority semantics decision, deliberately not hot-patched inside this convergence pass. |

The inherited participation failure is the only red result in the estate at
merge time, it predates this pass, and it is recorded here with its exact
signature so the owning cut can start from evidence rather than rediscovery.

## Relationship to the maximal-ceiling pass record

`docs/evidence/canon-maximal-ceiling-pass/2026-07-25-maximal-ceiling-pass.md`
records the architecture pass this convergence builds on; its addendum
records the ADR 0022 rulings. This record supersedes nothing there.

## Addendum (2026-07-26) — required CI check, root cause, and fix

PR #107's required CI check went red after the convergence push. Owner
diagnosis, verified locally: CI restores a cached `target/debug/
hypervisor-daemon`, and `scripts/lib/rust-hypervisor-daemon.mjs` returned any
existing binary without building — so the workflow-edit contract ran against
a stale pre-re-home daemon. After an explicit rebuild the focused
workflow-edit contract passes 9/9. This was an infrastructure fault, not a
product regression, and it is the same defect class INV-37 names: existence
is not evidence of currentness. Fix (this branch): the existsSync shortcut is
deleted — the resolver now always runs `cargo build` and lets cargo's
fingerprinting make the fresh case a sub-second no-op;
`IOI_HYPERVISOR_DAEMON_BIN` remains the explicit prebuilt override.
