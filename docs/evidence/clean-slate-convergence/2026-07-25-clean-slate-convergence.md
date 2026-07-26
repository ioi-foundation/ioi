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

## Verification (literal; final numbers at pass end)

See the final section of this file after the gate sweep:

<!-- VERIFICATION_RESULTS -->

## Relationship to the maximal-ceiling pass record

`docs/evidence/canon-maximal-ceiling-pass/2026-07-25-maximal-ceiling-pass.md`
records the architecture pass this convergence builds on; its addendum
records the ADR 0022 rulings. This record supersedes nothing there.
