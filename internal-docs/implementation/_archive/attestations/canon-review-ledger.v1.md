# Canon review ledger v1 — the review that did not happen at the time

Machine-readable form: [`canon-review-ledger.v1.json`](./canon-review-ledger.v1.json). That file is the record; this one is the reading.

## Read this first

- THIS LEDGER IS A RECONSTRUCTION PERFORMED AFTER THE FACT. It was not produced at the moment of review, because no review happened at that moment.
- A refreshed canon_snapshot stamp is NOT evidence of review. tools/refresh-canon-snapshots.mjs --write rewrites captured_at, captured_at_commit, aggregate_sha256, and every owner digest in place. It records that bytes were re-read; it records nothing about whether a human or an agent considered what those bytes now say.
- The prior stored digests of the rewritten records are UNRECOVERABLE. internal-docs/implementation/ is untracked (.gitignore line 117, untracked at commit ccb7fbec2), so the pre-rewrite record content exists in no history. The old digests reported here are recovered from the canon side — the git blob of each cited canon file at the immediate pre-delta revision — and are labelled as such. They are not the values the records previously carried.
- canon-impact --accept was run as a mechanical step to make a bar green, against the tool's own instruction to review the named stages, modules, and work items first. No automated gate broke at the time. This ledger exists because a green bar is not a review.

**Reviewer.** Claude Opus 5 (1M context), Claude Code agent session, acting under owner direction.

Every disposition below and its written justification. Where a fact could not be established, this reviewer recorded `blocked` or `unrecoverable` rather than an assumption.

Review method: Read the git diff of every drifted canon subject; read each affected record's objective, falsifiable_claim, in_scope, remaining_nonclaims, and contract_families; probed each record's full text for terms reaching the changed material; ran every estate verifier, including the nine that tools/check-program.mjs does not run as a bar — six of which currently fail.

Review commit: `360853b78de09d23ba51291851f599048547cb7a`.

## The standing rule

> **Never rewrite a verified closure to absorb a semantic change. Create a successor record instead.**

A verified record is a statement about a bounded claim at a bounded revision. If canon moves under it, the record does not move with it. Editing a closure so it agrees with the new canon destroys the only evidence that the old claim was ever tested, and leaves nothing that says the new claim has not been.

- A baseline advance is not a review. tools/canon-impact.mjs --accept records that someone said the drift was considered; from 2026-07-29 it additionally requires a content-bound review manifest naming every pending subject with its digest and an accountable reviewer_ref, so that accepting drift nobody enumerated is impossible.
- A canon_snapshot is provenance, not proof, and its captured_at_commit is not self-verifying. Four records on disk carry digests that do not match the commit they name.
- `unaffected` must be argued from what actually changed. An unargued `unaffected` is the same failure as a mechanical --accept, one record at a time.

## Disposition vocabulary

| Disposition | Meaning |
| --- | --- |
| `unaffected` | The record's claims demonstrably do not depend on anything that changed. The justification must name the specific delta and say why it does not reach this record's claim, scope, or contract families. |
| `successor_required` | The change is load-bearing for this record. For a VERIFIED record this means strictly a successor record: the closure is never rewritten. For a PROPOSED record it means the record cannot silently absorb the change — a distinct successor or amendment must carry the new obligation, and this ledger names what it has to prove. |
| `blocked` | The drift cannot be honestly dispositioned from the record and the canon diff alone. Something must land first: an owner ruling, a repair of the record's declared canon owners, or a repair of its retained evidence. `blocked` is never a soft `unaffected`. |

## What actually changed

Reviewed delta: `decf9ffc2784` (pre) → `106e2ac797d0` (the revision every affected `canon_snapshot` names). Head at review: `360853b78de0`.

PR #127 landed AFTER the reviewed baseline and changed components/connectors-tools/contracts.md again. That is why 18 records are still stale against the tree at review time; they are marked stale_against_tree_now.

### `docs/architecture/_meta/canon-to-code-delta.md`

- old `cd8fd1982c0b` → new `eb37948582fe`
- landed in: `a5c0f0a59750`

The EnforcementCoverageDeclaration row was rewritten from "nothing is on current master (corrected 2026-07-26)" to "the substrate is on current master (corrected 2026-07-28)": registry entry, v1 schema, invariants, 21 fixtures, both generated projections, and crates/services/src/agentic/runtime/enforcement_coverage.rs are present and verified. What is absent is narrowed to the route producer and daemon admission wiring — no route writes a declaration into hypervisoros-node-evidence and EnforcementCoverageRegistry has zero callers, so nothing is produced at runtime. Two gaps are newly recorded: the registered invariants enforce evidence only for `receipted` and `uncovered`, so a `mediated` positive claim is satisfied by the global evidence bag; and node attestation admits a node with an empty `enforcement_coverage_declaration_refs` list, satisfying the binding rule vacuously.

**Reach.** Records whose claims quantify over enforcement-coverage residency, production, or the node-attestation binding of coverage declarations.

### `docs/architecture/components/daemon-runtime/hypervisoros.md`

- old `a54419f5d213` → new `c139f77385bc`
- landed in: `a5c0f0a59750`

One hunk inside the Node Enforcement Profile section (lines ~448-473). The self-contradicting "registration, files, projections and the runtime lifecycle module are all absent from current master" claim was replaced with "present on current master", the absence narrowed to the route producer and daemon admission wiring, and a new explicit "Known gap (recorded, not claimed)" paragraph added stating that the registered invariants enforce evidence only for `receipted` and `uncovered`, so a `mediated` claim is admitted against the global evidence bag. No rule elsewhere in the file changed.

**Reach.** Records whose claims quantify over enforcement-coverage residency, production, or the node-attestation/admission binding of coverage declarations.

### `docs/architecture/components/hypervisor/core-clients-surfaces.md`

- old `971ac013517b` → new `11636564cbc7`
- landed in: `8b51847461c9`

A single +10/-1 hunk at line 1545, inside the Systems-surface paragraph that promises a direct Session, Project, AutomationSpec, or standalone GoalRun never requires System genesis. The promise is extended to governed change: an upgrade proposal binds an owner-qualified `target_owner_ref` and leaves `system_id` null for a non-System owner; a System remains required by change class and target kind. The paragraph explicitly delegates the field-level rules to foundations/objects/interop-and-collaboration-terms.md and restates none of them. No surface, workspace, taxonomy, registration record, contract, or implementation-status line elsewhere in the file changed.

**Reach.** Records whose claims concern upgrade proposals or whether a System must exist before governed change.

### `docs/architecture/foundations/objects/interop-and-collaboration-terms.md`

- old `06500434c328` → new `78f0414fc635`
- landed in: `8b51847461c9`

Front matter (implementation status, alignment date) plus four hunks all inside the UpgradeProposalEnvelope block (lines ~956-1056). The unconditional `system_id: system://...` was replaced by an owner-qualified `target_owner_ref` admitting user://, org://, project://, system://, domain://; `system_id` became nullable and non-null exactly when the target owner is a System; `originating_work_subject: TypedWorkSubjectBinding | null` was added as non-owning provenance; ~59 lines of admission rules were added, and protected-target routing now branches on whether the target owner is a System. The file's other three owned families — AIIP bounded-execution-domain identity and standards bindings, the dispute rail object family, and conditional-cooperation collaboration terms — are byte-identical.

**Reach.** Records whose claims concern upgrade proposals or governed-change ownership. Explicitly NOT records citing this file for AIIP, dispute-rail, or conditional-cooperation shapes.

### `docs/architecture/_meta/execution-horizons.md`

- old `8ebe90865485` → new `360c68f0d83a`
- landed in: `f665adf61b06`

Three things. (1) The undeniable-product proof gate's arrow flow was re-expressed as twenty-two ordered, individually checkable product/operator states; the commit states, and the diff confirms, that the steps themselves are unchanged — this is an equivalent restatement that makes a single step citable and failable. (2) A new 'continuous maintenance lane' paragraph declares a second activation mode (product signal -> AutomationRun -> typed HypervisorWorkItem -> optional GoalRun escalation through the ordinary GoalRunActivation crossing) converging on the same spine, bound to the selected external design-partner profile and explicitly leaving that rung's generic claim text unchanged (ADR 0024). (3) A new 'External-surface integrity rule' binds every surface reachable during a claimed journey to compile from IOI's canonical catalogs, use IOI-owned taxonomy and examples, carry no externally derived implementation as a fallback, and mark unsupported entries honestly; externally derived surfaces retire atomically once their replacement is Hypervisor-bound under a six-point operational bar, and visual parity is never evidence of binding.

**Reach.** Records that claim the terminal/undeniable journey, or that assert anything about the provenance or integrity of externally reachable product surfaces.

### `docs/decisions/0024-two-mode-flagship-composition.md`

- old `(absent)` → new `0ef57dfcf07a`
- landed in: `c1008b3bef57`

New ADR (162 lines). Records the flagship institution as two activation modes over one spine — the goal-initiated terminal journey that closes the internal product-proof rung, and the continuous maintenance lane that is the selected external design-partner profile's differentiator only. The ADR states that the generic claim text of that rung is unchanged, no object is re-placed, no claim-ladder or dependency edge moves, and no new primitive, plane, rail, runtime, or bare noun is created. Classified in program/canon-map.v1.json as non_build_doctrine with no owning stage or work item.

**Reach.** Records that claim the terminal journey or the external design-partner profile's composition.

### `docs/decisions/README.md`

- old `1b236c04405c` → new `b5a017a068d9`
- landed in: `c1008b3bef57`

One appended list item linking ADR 0024. No prose, rule, status, ownership, or ordering statement changed.

**Reach.** None. An index line carries no obligation and no claim; nothing can depend on it that does not already depend on the ADR it links.

### `docs/architecture/_meta/schemas/architecture-contract-registry.v1.json`

- old `3dab8e328129` → new `29f91b62f209`
- landed in: `568d2b9770f7`

Purely additive: one new registry entry, schema://ioi/components/connectors-tools/scm-publication-effect/v1 (ScmPublicationEffect), 85 -> 86 registered contracts, with canonical_owner_ref into components/connectors-tools/contracts.md, one cross-field invariant file, generated Rust/TypeScript projection targets, and 16 fixtures (5 positive, 11 negative). Registered at maturity `target`, stability `provisional`, compatibility `initial`. No existing registry entry was modified or removed.

**Reach.** Records whose claims quantify over the registered contract set as a closed census, or that own the ScmPublicationEffect family.

### `docs/architecture/components/connectors-tools/contracts.md`

- old `42f78271a77c` → new `2dd0ec137e27` → tree now `f0ec4d69aecf`
- landed in: `568d2b9770f7`, `b39b7619a (p`, `9cdf8aaee (p`

Inside the reviewed delta (568d2b977): additive — a new 'Source-Control Publication' section defining ScmPublicationEffect as the only shape in which the estate may mutate a remote repository through a connector (expected-head compare-and-swap, proposal-bound file set, admitted-connector destination, separately receipted publication and review-request sub-effects, recomputed idempotency), plus front-matter canonical-owner and implementation-status updates recording it as a target contract that no runtime path satisfies. AFTER the reviewed baseline, PR #127 (b39b7619a, 9cdf8aaee) changed the same file again: the implementation status flipped from 'planned / target contract' to 'implemented (single-node estate)', the defective handle_scm_publish route in lifecycle_routes.rs was recorded as REMOVED and replaced by scm_publication_routes.rs, and a new refusal rule was added — a source identity naming more than one revision refuses by name (ambiguous_destination_binding_ref, ambiguous_proposal_ref) under INV-37, with no caller-supplied revision selector.

**Reach.** Records that claim a closed route/final-invoker census, that own source-control publication, or that quantify over connector/tool contract coverage.

## Population

| Measure | Value |
| --- | --- |
| records on disk | 135 |
| carrying the leg-a stamp | 95 |
| rewritten by `refresh-canon-snapshots --write` in one batch | 91 |
| of those, pre-existing | 88 |
| of those, session-authored | 3 |
| authored after the batch, stamped at authoring | 4 |
| verified records affected | 16 of 29 verified on disk |
| still stale against the tree at review time | 18 |

**Counting reconciliation.** The brief states 94 records (6 new + 88 pre-existing) and 18 of 29 verified. Measured on disk: 88 pre-existing records were rewritten by the tool — an exact match — alongside 4 session-authored records, for a rewrite batch of 92 (identical mtime 2026-07-29T08:40:43Z). Two further session-authored records were written two minutes later and a seventh two hours later, all three stamped at the same commit, giving 95 records carrying the leg-a stamp today and 94 at the time the brief was written. The verified count does NOT reconcile: 16 verified records carry the leg-a stamp, not 18. Every verified record on disk was enumerated and its snapshot commit read; no mechanism was found by which two further verified records could have been stamped and then unstamped. This reviewer reports 16 and does not adopt 18.

## Dispositions

`unaffected` 79 · `successor_required` 12 · `blocked` 4

### Every record that is not `unaffected`

#### `m0-program-control-selected-profile-exit-proof` — blocked — verified, certified, M0

Drifted canon owners: `docs/architecture/_meta/schemas/architecture-contract-registry.v1.json`, `docs/decisions/README.md`

VERIFIED and certified aggregate exit for M0. The canon delta it drifted on (contract-registry addition, ADR index line) is inert for its claim. It is nonetheless not dispositionable as `unaffected`, because its own retained evidence no longer re-derives: tools/check-literal-exit-contract.mjs reports `evidence/M0/m0-program-control-selected-profile-exit-proof.exit.v1.txt: stale: artifact digest mismatch for docs/evidence/m0-program-control/m0-exit-report.json: declared b626e80656ba78dafe161395ba6c6e2986cb16cfd8cfa3c9944ce07004dae6ac, actual c8fff04a7b73cabe7324867d8357b8a362d3a598e62d582795e5231caa0639cc`. The evidence file was regenerated inside the same leg-a range by ec50272f1 (`chore(census): locator-rebind re-entry for the proof-infrastructure cuts (anchor seq 22)`). An aggregate exit whose retained log binds a digest the tree no longer carries cannot be asserted intact, and the repair is an owner decision — re-attest the retained log against the regenerated evidence, or open a successor exit proof — not a disposition this reconstruction may make.

#### `m0-route-final-invoker-pg-census-maintenance` — successor_required — verified, certified, M0

Drifted canon owners: `docs/architecture/components/connectors-tools/contracts.md`, `docs/architecture/components/hypervisor/core-clients-surfaces.md` — and still stale against the tree now

VERIFIED and certified. Its closure is a CLOSED route/final-invoker census. The retained census evidence docs/evidence/m0-program-control/effect-census.json and reviewed-entry-lock.json still name `crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs#handle_scm_publish:12907` as a final invoker, and contain zero references to scm_publication_routes.rs. PR #127 — the same change that produced this record's still-pending contracts.md drift — DELETED handle_scm_publish from lifecycle_routes.rs and moved publication to crates/node/src/bin/hypervisor_daemon_routes/scm_publication_routes.rs. The certified census is therefore factually stale about the current tree: it asserts a final invoker at a locator that no longer exists and omits a route family that does. tools/check-route-census-maintenance.mjs currently exits non-zero with `scripts/m0-program-control.mjs --check FAILED; census, lock, and anchors do not cohere`. This is the single clearest refutation of the claim that no certified claim was invalidated.

**The successor must prove.** A successor record — never an edit to this closure — must re-derive the closed route and final-invoker census over current master, show handle_scm_publish retired through the bypass/retirement diff rather than silently dropped, admit scm_publication_routes.rs with its final invokers and PG-id joins, re-establish census/lock/anchor coherence so tools/check-route-census-maintenance.mjs exits 0, and carry its own literal exit under the retained-log contract. It must also state which census entries changed only by line-number rebind and which changed by route identity, because a locator rebind and a route deletion are not the same fact.

#### `m0-selected-profile-baseline-evidence-and-claim-lock` — blocked — verified, certified, M0

Drifted canon owners: `docs/architecture/_meta/schemas/architecture-contract-registry.v1.json`, `docs/decisions/README.md`

VERIFIED and certified. The canon delta it drifted on (contract-registry addition, ADR index line) is inert for its claim. It is nonetheless not dispositionable as `unaffected`, because the frozen bundle it certified no longer re-derives: tools/check-claim-lock.mjs reports `lock source digest stale` for docs/evidence/m0-program-control/current-baselines.json, selected-profile.json, and release-ladder.json — the three sources of the claim lock this record froze — all regenerated inside the reviewed range by ec50272f1. The lock failing closed is the certified behaviour working; the frozen bundle no longer binding is a separate fact, and which of the two the owner accepts is an owner decision, not a disposition this reconstruction may make.

#### `m2-membership-readiness-plane` — successor_required — verified, certified, M2

Drifted canon owners: `docs/architecture/components/daemon-runtime/hypervisoros.md`

VERIFIED and certified. It is the only verified record that DECLARES the EnforcementCoverageDeclaration contract family, binding contract id schema://ioi/components/daemon-runtime/enforcement-coverage-declaration/v1 to canonical_owner_ref canon://docs/architecture/components/daemon-runtime/hypervisoros.md#node-enforcement-profile — the exact section the delta rewrote. Canon's position on that family reversed (absent from master -> registered and present, with runtime production still absent and zero registry callers), and a vacuously satisfiable admission binding was newly recorded. The record's claim is that desired deployment never fabricates observed admission or readiness truth; a coverage binding that is satisfiable by an empty list, over a registry that is never populated at runtime, is a fabricated-admission surface inside its declared contract family.

**The successor must prove.** That membership admission and readiness derive no posture from an EnforcementCoverageDeclaration that was never produced, that a registry-resident contract with zero callers cannot be read as coverage, and that the declared contract family binding in this record resolves to producible runtime truth or is re-declared as substrate-only with a named nonclaim.

#### `m2-node-attestation-identity-secret-readiness` — successor_required — verified, certified, M2

Drifted canon owners: `docs/architecture/components/daemon-runtime/hypervisoros.md`

VERIFIED and certified. Its declared in_scope is `node identity/attestation, secret custody, readiness, temporal-floor families` and its falsifiable claim fails on `ready-before-proof`. The delta added, to the very canon owner it cites, a newly recorded gap stating that node attestation admits a node with an EMPTY `enforcement_coverage_declaration_refs` list, satisfying the binding rule vacuously. That is an admission/readiness mechanism that can be satisfied without proof — precisely the failure shape this record's claim asserts cannot occur — and the record's remaining_nonclaims do not exclude it. The closure must not be edited to absorb this.

**The successor must prove.** That node attestation either refuses admission when `enforcement_coverage_declaration_refs` is empty, or that an empty list is admitted under an explicitly named and owner-ratified nonclaim that no readiness or coverage posture is derived from it. It must exercise the empty-list case adversarially, not merely assert it, and must state whether any readiness projection currently reads the field.

#### `hypervisoros-ctee-task-capsule-attestation` — successor_required — proposed, M9

Drifted canon owners: `docs/architecture/components/daemon-runtime/hypervisoros.md`

Load-bearing, not incidental. In `docs/architecture/components/daemon-runtime/hypervisoros.md` (`a54419f5d213` -> `c139f77385bc`): One hunk inside the Node Enforcement Profile section (lines ~448-473). The record's own text quantifies over exactly that material (probe ECD_STATUS_CORRECTION matches), so what changed is inside what this record undertakes to prove. A refreshed canon_snapshot did not carry that obligation and could not have.

**The successor must prove.** That the EnforcementCoverageDeclaration family it relies on is actually produced at runtime — a route writes a declaration, EnforcementCoverageRegistry acquires callers, and the declaration resolves as verified_current — or that its own claim is re-bounded with a named nonclaim stating that registry residency is not coverage. It must additionally address the two gaps canon now records: per-claim evidence for a `mediated` positive claim, and node attestation admitting an empty `enforcement_coverage_declaration_refs` list.

#### `m10-attestation-temporal-floor-and-revocation-continuity` — successor_required — proposed, M10

Drifted canon owners: `docs/architecture/components/daemon-runtime/hypervisoros.md`

Load-bearing, not incidental. In `docs/architecture/components/daemon-runtime/hypervisoros.md` (`a54419f5d213` -> `c139f77385bc`): One hunk inside the Node Enforcement Profile section (lines ~448-473). The record's own text quantifies over exactly that material (probe ECD_STATUS_CORRECTION matches), so what changed is inside what this record undertakes to prove. A refreshed canon_snapshot did not carry that obligation and could not have.

**The successor must prove.** That the EnforcementCoverageDeclaration family it relies on is actually produced at runtime — a route writes a declaration, EnforcementCoverageRegistry acquires callers, and the declaration resolves as verified_current — or that its own claim is re-bounded with a named nonclaim stating that registry residency is not coverage. It must additionally address the two gaps canon now records: per-claim evidence for a `mediated` positive claim, and node attestation admitting an empty `enforcement_coverage_declaration_refs` list.

#### `m14-cross-plane-correlated-failure-injection` — successor_required — proposed, FUTURE

Drifted canon owners: `docs/architecture/components/connectors-tools/contracts.md`, `docs/architecture/components/daemon-runtime/hypervisoros.md`, `docs/architecture/foundations/objects/interop-and-collaboration-terms.md` — and still stale against the tree now

Load-bearing, not incidental. In `docs/architecture/components/daemon-runtime/hypervisoros.md` (`a54419f5d213` -> `c139f77385bc`): One hunk inside the Node Enforcement Profile section (lines ~448-473). The record's own text quantifies over exactly that material (probe ECD_STATUS_CORRECTION matches), so what changed is inside what this record undertakes to prove. A refreshed canon_snapshot did not carry that obligation and could not have. Its other drifted owners — `docs/architecture/components/connectors-tools/contracts.md`, `docs/architecture/foundations/objects/interop-and-collaboration-terms.md` — do not reach it and are not the reason for this disposition.

**The successor must prove.** That the EnforcementCoverageDeclaration family it relies on is actually produced at runtime — a route writes a declaration, EnforcementCoverageRegistry acquires callers, and the declaration resolves as verified_current — or that its own claim is re-bounded with a named nonclaim stating that registry residency is not coverage. It must additionally address the two gaps canon now records: per-claim evidence for a `mediated` positive claim, and node attestation admitting an empty `enforcement_coverage_declaration_refs` list.

#### `m8-improvement-operational-journey` — successor_required — proposed, M8

Drifted canon owners: `docs/architecture/components/hypervisor/core-clients-surfaces.md`

Load-bearing, not incidental. In `docs/architecture/components/hypervisor/core-clients-surfaces.md` (`971ac013517b` -> `11636564cbc7`): A single +10/-1 hunk at line 1545, inside the Systems-surface paragraph that promises a direct Session, Project, AutomationSpec, or standalone GoalRun never requires System genesis. The record's own text quantifies over exactly that material (probe UPGRADE_PROPOSAL_OWNER_QUALIFICATION matches), so what changed is inside what this record undertakes to prove. A refreshed canon_snapshot did not carry that obligation and could not have.

**The successor must prove.** That its upgrade-proposal path binds the owner-qualified `target_owner_ref` shape — `system_id` non-null exactly when the target owner is a System, `originating_work_subject` carried as non-owning provenance, an unlisted owner scheme refused — and that a non-System owner reaches no constitutional-amendment path. Because canon records this as a shape change with no registered contract, projection, or runtime route behind it, the successor must also state that a registered contract revision lands before any wire consumer relies on the new shape.

#### `m8-learning-boundary-provider-exit` — successor_required — proposed, M8

Drifted canon owners: `docs/architecture/foundations/objects/interop-and-collaboration-terms.md`

Load-bearing, not incidental. In `docs/architecture/foundations/objects/interop-and-collaboration-terms.md` (`06500434c328` -> `78f0414fc635`): Front matter (implementation status, alignment date) plus four hunks all inside the UpgradeProposalEnvelope block (lines ~956-1056). The record's own text quantifies over exactly that material (probe UPGRADE_PROPOSAL_OWNER_QUALIFICATION matches), so what changed is inside what this record undertakes to prove. A refreshed canon_snapshot did not carry that obligation and could not have.

**The successor must prove.** That its upgrade-proposal path binds the owner-qualified `target_owner_ref` shape — `system_id` non-null exactly when the target owner is a System, `originating_work_subject` carried as non-owning provenance, an unlisted owner scheme refused — and that a non-System owner reaches no constitutional-amendment path. Because canon records this as a shape change with no registered contract, projection, or runtime route behind it, the successor must also state that a registered contract revision lands before any wire consumer relies on the new shape.

#### `m8-model-supply-route-substitution-and-selected-exit` — successor_required — proposed, M8

Drifted canon owners: `docs/architecture/foundations/objects/interop-and-collaboration-terms.md`

Load-bearing, not incidental. In `docs/architecture/foundations/objects/interop-and-collaboration-terms.md` (`06500434c328` -> `78f0414fc635`): Front matter (implementation status, alignment date) plus four hunks all inside the UpgradeProposalEnvelope block (lines ~956-1056). The record's own text quantifies over exactly that material (probe UPGRADE_PROPOSAL_OWNER_QUALIFICATION matches), so what changed is inside what this record undertakes to prove. A refreshed canon_snapshot did not carry that obligation and could not have.

**The successor must prove.** That its upgrade-proposal path binds the owner-qualified `target_owner_ref` shape — `system_id` non-null exactly when the target owner is a System, `originating_work_subject` carried as non-owning provenance, an unlisted owner scheme refused — and that a non-System owner reaches no constitutional-amendment path. Because canon records this as a shape change with no registered contract, projection, or runtime route behind it, the successor must also state that a registered contract revision lands before any wire consumer relies on the new shape.

#### `m8-order-zero-improvement-and-direct-path` — successor_required — proposed, M8

Drifted canon owners: `docs/architecture/foundations/objects/interop-and-collaboration-terms.md`

Load-bearing, not incidental. In `docs/architecture/foundations/objects/interop-and-collaboration-terms.md` (`06500434c328` -> `78f0414fc635`): Front matter (implementation status, alignment date) plus four hunks all inside the UpgradeProposalEnvelope block (lines ~956-1056). The record's own text quantifies over exactly that material (probe UPGRADE_PROPOSAL_OWNER_QUALIFICATION matches), so what changed is inside what this record undertakes to prove. A refreshed canon_snapshot did not carry that obligation and could not have.

**The successor must prove.** That its upgrade-proposal path binds the owner-qualified `target_owner_ref` shape — `system_id` non-null exactly when the target owner is a System, `originating_work_subject` carried as non-owning provenance, an unlisted owner scheme refused — and that a non-System owner reaches no constitutional-amendment path. Because canon records this as a shape change with no registered contract, projection, or runtime route behind it, the successor must also state that a registered contract revision lands before any wire consumer relies on the new shape.

#### `m9-authority-gateway-equivalence-and-coverage` — successor_required — proposed, M9

Drifted canon owners: `docs/architecture/components/connectors-tools/contracts.md`, `docs/architecture/components/daemon-runtime/hypervisoros.md`, `docs/architecture/components/hypervisor/core-clients-surfaces.md` — and still stale against the tree now

Load-bearing, not incidental. In `docs/architecture/components/daemon-runtime/hypervisoros.md` (`a54419f5d213` -> `c139f77385bc`): One hunk inside the Node Enforcement Profile section (lines ~448-473). The record's own text quantifies over exactly that material (probe ECD_STATUS_CORRECTION matches), so what changed is inside what this record undertakes to prove. A refreshed canon_snapshot did not carry that obligation and could not have. Its other drifted owners — `docs/architecture/components/connectors-tools/contracts.md`, `docs/architecture/components/hypervisor/core-clients-surfaces.md` — do not reach it and are not the reason for this disposition.

**The successor must prove.** That the EnforcementCoverageDeclaration family it relies on is actually produced at runtime — a route writes a declaration, EnforcementCoverageRegistry acquires callers, and the declaration resolves as verified_current — or that its own claim is re-bounded with a named nonclaim stating that registry residency is not coverage. It must additionally address the two gaps canon now records: per-claim evidence for a `mediated` positive claim, and node attestation admitting an empty `enforcement_coverage_declaration_refs` list.

#### `m9-environments-operational-journey` — successor_required — proposed, M9

Drifted canon owners: `docs/architecture/components/daemon-runtime/hypervisoros.md`, `docs/architecture/components/hypervisor/core-clients-surfaces.md`

Load-bearing, not incidental. In `docs/architecture/components/daemon-runtime/hypervisoros.md` (`a54419f5d213` -> `c139f77385bc`): One hunk inside the Node Enforcement Profile section (lines ~448-473). The record's own text quantifies over exactly that material (probe ECD_STATUS_CORRECTION matches), so what changed is inside what this record undertakes to prove. A refreshed canon_snapshot did not carry that obligation and could not have. Its other drifted owners — `docs/architecture/components/hypervisor/core-clients-surfaces.md` — do not reach it and are not the reason for this disposition.

**The successor must prove.** That the EnforcementCoverageDeclaration family it relies on is actually produced at runtime — a route writes a declaration, EnforcementCoverageRegistry acquires callers, and the declaration resolves as verified_current — or that its own claim is re-bounded with a named nonclaim stating that registry residency is not coverage. It must additionally address the two gaps canon now records: per-claim evidence for a `mediated` positive claim, and node attestation admitting an empty `enforcement_coverage_declaration_refs` list.

#### `m9-sovereign-local-terminal-journey` — blocked — proposed, M9

Drifted canon owners: `docs/architecture/components/hypervisor/core-clients-surfaces.md`

This is the record for the sovereign-local terminal journey, and docs/architecture/_meta/execution-horizons.md is the canonical owner of the undeniable-product proof gate that journey instantiates. The record does NOT cite execution-horizons.md among its nineteen canon_owners. The delta that most concerns it — the twenty-two-step enumeration and the new external-surface integrity rule binding every surface reachable during a claimed journey — therefore lands in a canon owner it never declared, so its canon_snapshot could not drift for it and no digest in this ledger measures it. Its drift disposition cannot be computed from its own declaration. Repair the canon_owners set first; only then can this record be dispositioned.

#### `scm-publication-effect-and-route-rebuild` — blocked — proposed, M9

Drifted canon owners: `docs/architecture/components/connectors-tools/contracts.md`, `docs/architecture/components/hypervisor/core-clients-surfaces.md` — and still stale against the tree now

Session-authored record owning the ScmPublicationEffect rebuild. Two facts block disposition. First, its canon_snapshot anchors components/connectors-tools/contracts.md at revision 106e2ac79, which PREDATES the rebuild the record describes: PR #127 then rewrote that section's implementation status from `planned`/`target contract` to `implemented (single-node estate)` and added the ambiguous-identity refusal rules, so the record's own anchor contradicts the state it narrates and it sits in the currently pending drift set. Second, the record carries an explicit unresolved blocker in its own nonclaims — an OPEN CONTRACT-SEMANTICS QUESTION requiring an owner ruling before it may claim operational idempotency — and program/canon-map.v1.json records the same thing for the registered schema ("an owner ruling requires a v2 revision for observation-independent retry semantics"). Disposition requires that ruling.

### The priority set — every verified record affected

| Work item | Stage | Certified | Disposition | Drifted canon owners | Stale now |
| --- | --- | --- | --- | --- | --- |
| `m0-adjacent-canon-doc-class-and-placement-disposition` | M0 | yes | `unaffected` | decisions/README.md | — |
| `m0-canon-owner-coverage-and-orphan-verifier` | M0 | yes | `unaffected` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md | — |
| `m0-literal-exit-evidence-contract` | M0 | yes | `unaffected` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md | — |
| `m0-program-control-selected-profile-exit-proof` | M0 | yes | `blocked` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md | — |
| `m0-route-final-invoker-pg-census-maintenance` | M0 | yes | `successor_required` | components/connectors-tools/contracts.md<br>components/hypervisor/core-clients-surfaces.md | yes |
| `m0-selected-profile-baseline-evidence-and-claim-lock` | M0 | yes | `blocked` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md | — |
| `m0-source-disposition-and-single-sequencer-verifier` | M0 | yes | `unaffected` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md | — |
| `m0-work-item-contract-completeness-and-owner-lint` | M0 | yes | `unaffected` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md | — |
| `m1-dual-genesis-and-read-projection` | M1 | yes | `unaffected` | components/hypervisor/core-clients-surfaces.md | — |
| `m1-system-genesis-product-journey` | M1 | yes | `unaffected` | components/hypervisor/core-clients-surfaces.md | — |
| `m2-agentgres-replay-recovery-and-product-topology` | M2 | yes | `unaffected` | components/hypervisor/core-clients-surfaces.md | — |
| `m2-membership-readiness-plane` | M2 | yes | `successor_required` | components/daemon-runtime/hypervisoros.md | — |
| `m2-node-attestation-identity-secret-readiness` | M2 | yes | `successor_required` | components/daemon-runtime/hypervisoros.md | — |
| `m2-route-restore-activation-cleanup` | M2 | yes | `unaffected` | components/daemon-runtime/hypervisoros.md | — |
| `m2-writer-fence-and-lost-suffix` | M2 | yes | `unaffected` | components/daemon-runtime/hypervisoros.md | — |
| `project-discovery-startup-and-session-chain` | M2 | yes | `unaffected` | components/hypervisor/core-clients-surfaces.md | — |

### Every affected record

| Work item | Status | Disposition | Drifted canon owners |
| --- | --- | --- | --- |
| `m0-adjacent-canon-doc-class-and-placement-disposition` | verified | `unaffected` | decisions/README.md |
| `m0-canon-owner-coverage-and-orphan-verifier` | verified | `unaffected` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md |
| `m0-literal-exit-evidence-contract` | verified | `unaffected` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md |
| `m0-program-control-selected-profile-exit-proof` | verified | `blocked` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md |
| `m0-route-final-invoker-pg-census-maintenance` | verified | `successor_required` | components/connectors-tools/contracts.md<br>components/hypervisor/core-clients-surfaces.md |
| `m0-selected-profile-baseline-evidence-and-claim-lock` | verified | `blocked` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md |
| `m0-source-disposition-and-single-sequencer-verifier` | verified | `unaffected` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md |
| `m0-work-item-contract-completeness-and-owner-lint` | verified | `unaffected` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md |
| `m1-dual-genesis-and-read-projection` | verified | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m1-system-genesis-product-journey` | verified | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m2-agentgres-replay-recovery-and-product-topology` | verified | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m2-membership-readiness-plane` | verified | `successor_required` | components/daemon-runtime/hypervisoros.md |
| `m2-node-attestation-identity-secret-readiness` | verified | `successor_required` | components/daemon-runtime/hypervisoros.md |
| `m2-route-restore-activation-cleanup` | verified | `unaffected` | components/daemon-runtime/hypervisoros.md |
| `m2-writer-fence-and-lost-suffix` | verified | `unaffected` | components/daemon-runtime/hypervisoros.md |
| `project-discovery-startup-and-session-chain` | verified | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `connected-worker-capability-supply-and-hiring` | proposed | `unaffected` | foundations/objects/interop-and-collaboration-terms.md |
| `dispute-adjudication-remedy-kernel` | proposed | `unaffected` | foundations/objects/interop-and-collaboration-terms.md |
| `ecosystem-assurance-and-public-claim-estate` | proposed | `unaffected` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md |
| `enforcement-coverage-evidence-and-binding` | proposed | `unaffected` | components/daemon-runtime/hypervisoros.md<br>_meta/canon-to-code-delta.md |
| `governance-decision-truth-repairs` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `hypervisoros-ctee-task-capsule-attestation` | proposed | `successor_required` | components/daemon-runtime/hypervisoros.md |
| `m10-attestation-temporal-floor-and-revocation-continuity` | proposed | `successor_required` | components/daemon-runtime/hypervisoros.md |
| `m10-operations-operational-journey` | proposed | `unaffected` | components/daemon-runtime/hypervisoros.md<br>components/hypervisor/core-clients-surfaces.md |
| `m10-topology-chaos-and-operator-product-proof` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m11-canonical-embodied-contract-alignment` | proposed | `unaffected` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md |
| `m11-embodied-systems-nonlive-operational-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m11-foundry-promotion-safety-case-and-product-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m12-federated-admission-portable-exit-and-bindings` | proposed | `unaffected` | foundations/objects/interop-and-collaboration-terms.md |
| `m12-federation-product-and-operator-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md<br>foundations/objects/interop-and-collaboration-terms.md |
| `m12-ifc-disclosure-receipt-and-settlement-binding` | proposed | `unaffected` | foundations/objects/interop-and-collaboration-terms.md |
| `m12-terms-discovery-semantic-negotiation` | proposed | `unaffected` | foundations/objects/interop-and-collaboration-terms.md |
| `m13-independent-operation-and-external-worker-product-proof` | proposed | `unaffected` | foundations/objects/interop-and-collaboration-terms.md |
| `m13-sovereignty-trial-preregistration` | proposed | `unaffected` | foundations/objects/interop-and-collaboration-terms.md |
| `m13-two-sovereign-surplus-and-decline-proof` | proposed | `unaffected` | foundations/objects/interop-and-collaboration-terms.md |
| `m14-cross-plane-correlated-failure-injection` | proposed | `successor_required` | components/connectors-tools/contracts.md<br>components/daemon-runtime/hypervisoros.md<br>foundations/objects/interop-and-collaboration-terms.md |
| `m14-demand-security-economics` | proposed | `unaffected` | foundations/objects/interop-and-collaboration-terms.md |
| `m14-network-service-devnet` | proposed | `unaffected` | foundations/objects/interop-and-collaboration-terms.md |
| `m14-service-family-owner-contract-and-product-surfaces` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md<br>foundations/objects/interop-and-collaboration-terms.md |
| `m3-goal-kernel-context-and-runtime-truth-spine` | proposed | `unaffected` | components/connectors-tools/contracts.md<br>components/hypervisor/core-clients-surfaces.md |
| `m3-pursuit-definition-resolution` | proposed | `unaffected` | components/connectors-tools/contracts.md<br>components/hypervisor/core-clients-surfaces.md |
| `m3-result-lifecycle-negative-retention` | proposed | `unaffected` | components/connectors-tools/contracts.md |
| `m3-work-session-automation-product-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m4-room-graph-truth-and-product-projection` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m5-attribution-acceptance-and-challenge-boundary` | proposed | `unaffected` | foundations/objects/interop-and-collaboration-terms.md |
| `m5-local-agent-pairing` | proposed | `unaffected` | components/connectors-tools/contracts.md |
| `m5-pairing-identity-and-gateway-scope` | proposed | `unaffected` | components/connectors-tools/contracts.md |
| `m5-participant-frontier-result-closeout` | proposed | `unaffected` | components/connectors-tools/contracts.md |
| `m5-portable-exit-independent-clients` | proposed | `unaffected` | components/connectors-tools/contracts.md |
| `m6-applications-workspace-operational-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m6-automations-operational-journey` | proposed | `unaffected` | components/connectors-tools/contracts.md<br>components/hypervisor/core-clients-surfaces.md |
| `m6-catalog-route-alias-migration-accessibility` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m6-consequential-action-authority-receipt-unification` | proposed | `unaffected` | components/connectors-tools/contracts.md<br>components/hypervisor/core-clients-surfaces.md |
| `m6-developer-workspace-operational-journey` | proposed | `unaffected` | components/connectors-tools/contracts.md<br>components/hypervisor/core-clients-surfaces.md |
| `m6-home-workspace-operational-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m6-owner-application-registration-and-shell-state-coverage` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m6-packages-operational-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m6-product-surface-and-typed-workspaces` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m6-production-truth-fallback-retirement` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m6-projects-workspace-operational-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m6-reference-shell-disposition-and-depth-ledger` | proposed | `unaffected` | _meta/schemas/architecture-contract-registry.v1.json<br>components/hypervisor/core-clients-surfaces.md<br>decisions/README.md |
| `m6-surface-compiler-and-source-convergence` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m6-systems-work-projection-and-mission-alias-migration` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m6-systems-workspace-operational-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m6-work-workspace-operational-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m7-data-operational-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m7-data-transformation-provenance-replay` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m7-ontology-action-final-invoker-and-product-proof` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m7-ontology-operational-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m7-studio-operational-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m8-evaluations-operational-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m8-foundry-operational-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m8-improvement-operational-journey` | proposed | `successor_required` | components/hypervisor/core-clients-surfaces.md |
| `m8-learning-boundary-provider-exit` | proposed | `successor_required` | foundations/objects/interop-and-collaboration-terms.md |
| `m8-learning-custody-memory-and-provider-rights` | proposed | `unaffected` | components/daemon-runtime/hypervisoros.md |
| `m8-model-supply-route-substitution-and-selected-exit` | proposed | `successor_required` | foundations/objects/interop-and-collaboration-terms.md |
| `m8-order-zero-improvement-and-direct-path` | proposed | `successor_required` | foundations/objects/interop-and-collaboration-terms.md |
| `m9-authority-gateway-equivalence-and-coverage` | proposed | `successor_required` | components/connectors-tools/contracts.md<br>components/daemon-runtime/hypervisoros.md<br>components/hypervisor/core-clients-surfaces.md |
| `m9-developer-console-operational-journey` | proposed | `unaffected` | components/connectors-tools/contracts.md<br>components/hypervisor/core-clients-surfaces.md |
| `m9-environments-operational-journey` | proposed | `successor_required` | components/daemon-runtime/hypervisoros.md<br>components/hypervisor/core-clients-surfaces.md |
| `m9-governance-operational-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m9-lifecycle-evidence-operator-proof` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m9-managed-optionality-overlay` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m9-provenance-operational-journey` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `m9-selected-profile-aggregate-exit-and-claim-publication` | proposed | `unaffected` | _meta/schemas/architecture-contract-registry.v1.json<br>decisions/README.md |
| `m9-sovereign-local-terminal-journey` | proposed | `blocked` | components/hypervisor/core-clients-surfaces.md |
| `m9-terminal-product-state-and-release-supply-chain` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `mcp-receipt-effect-truth-pre-wiring` | proposed | `unaffected` | components/connectors-tools/contracts.md |
| `p2-external-surface-integrity-gate` | proposed | `unaffected` | _meta/execution-horizons.md<br>components/hypervisor/core-clients-surfaces.md<br>decisions/0024-two-mode-flagship-composition.md |
| `p2-launcher-catalog-availability-check` | proposed | `unaffected` | _meta/execution-horizons.md<br>components/hypervisor/core-clients-surfaces.md |
| `p2-surface-provenance-integrity-check` | proposed | `unaffected` | _meta/execution-horizons.md<br>components/hypervisor/core-clients-surfaces.md |
| `platform-operability-observability-and-incidents` | proposed | `unaffected` | components/hypervisor/core-clients-surfaces.md |
| `production-information-flow-and-declassification` | proposed | `unaffected` | components/connectors-tools/contracts.md |
| `scm-publication-effect-and-route-rebuild` | proposed | `blocked` | components/connectors-tools/contracts.md<br>components/hypervisor/core-clients-surfaces.md |
| `sdk-cli-adk-odk-builder-journey` | proposed | `unaffected` | _meta/schemas/architecture-contract-registry.v1.json<br>components/connectors-tools/contracts.md<br>components/hypervisor/core-clients-surfaces.md<br>decisions/README.md |

Per-owner digests — recorded, pre-delta, post-delta, and current-tree — are in the JSON under `records[].canon_owners`. Each `unaffected` disposition carries its own written argument there; none is asserted by default.

## What could not be recovered

### prior canon_snapshot digests of the 92 rewritten records

**Why.** internal-docs/implementation/ is untracked (.gitignore line 117; untracked at commit ccb7fbec2). tools/refresh-canon-snapshots.mjs --write replaces canon_snapshot in place with no prior-value retention and no ledger. There is no copy in _archive/, in the nested worktree under worktrees/hypervisor-assistant-boundary (a much older estate carrying 7 active records), or in docs/architecture/_meta/work-items/ (7 tracked records, none of which carry a canon_snapshot at all).

**Reported instead.** The canon-side digest at the immediate pre-delta revision decf9ffc2, labelled old_sha256 with old_sha256_source on every row. This is what the canon file digested to before the change; it is NOT proof of what the record previously stored.

### the exact prior captured_at_commit of each rewritten record

**Why.** Same. It cannot be inferred from the surviving population either: the hypothesis that a full-population refresh ran at decf9ffc2 was tested and REFUTED — four records still carry a 7139292b1 stamp while holding digests that match the current tree rather than that commit (finding F4), so the stamp history is not reconstructible by consistency argument.

**Reported instead.** None. Reported as unrecoverable rather than inferred. What IS established is that every one of the 95 affected records cites at least one canon owner that changed in the reviewed delta, so the delta fully explains the drift with no residue.

## Adjacent integrity findings

These are not dispositions. They are what the review found while looking, and they bear directly on whether "no certified claim was invalidated" can be asserted. It cannot yet.

| # | Severity | From this delta | Finding |
| --- | --- | --- | --- |
| F1 | high | yes | The gate that would have caught this drift is not run by the program bar. tools/check-canon-owner-coverage.mjs currently FAILS with 18 stale-digest errors, every one of them naming docs/architecture/components/connectors-tools/contracts.md. It is not a member of the BARS list in tools/check-program.mjs, so check-program.mjs reports PASS (0 errors) while canon-owner staleness is live. |
| F2 | high | yes | Two retained M0 exit logs no longer re-derive. tools/check-literal-exit-contract.mjs FAILS on evidence/M0/m0-program-control-selected-profile-exit-proof.exit.v1.txt and evidence/M0/m0-unsigned-review-anchor.exit.v1.txt, both binding digests of docs/evidence/m0-program-control/ files that were regenerated inside the reviewed range by ec50272f1. Both records are VERIFIED. This tool is also not in check-program.mjs's BARS. |
| F3 | high | yes | tools/check-claim-lock.mjs FAILS with 4 stale lock-source digests and tools/check-route-census-maintenance.mjs FAILS with `census, lock, and anchors do not cohere`, both over the same docs/evidence/m0-program-control/ set regenerated by ec50272f1 inside the reviewed range. Neither is in check-program.mjs's BARS. |
| F4 | medium | no | canon_snapshot.captured_at_commit is not self-verifying and is demonstrably wrong for four records. tools/refresh-canon-snapshots.mjs digests the WORKING TREE but stamps `git rev-parse HEAD` with no cleanliness check, so the named commit and the recorded digests can disagree. Measured across all 134 records: 129 consistent, 1 with no commit, 4 inconsistent — m0-invariant-registry-census (verified, 2 of 3 owner digests do not match commit 7139292b1), m0-canonical-enum-member-set-binding-and-legacy-string-census (verified, 1 of 3), m12-aiip-channel-envelope-profile (1 of 8), m8-product-memory-runtime-successor-and-scs-retirement (1 of 8). |
| F5 | medium | no | canon_snapshot.captured_at is derived from the mtime of program/sequence.v1.json, not from the capture. It is not a capture date and must not be read as one. |
| F6 | low | yes | ADR 0024 is Accepted but classified non_build_doctrine in program/canon-map.v1.json, producing an unactioned canon-impact WARN (`accepted ADR classified non_build_doctrine`). ADR 0021 carries the same unactioned warning. check-program.mjs surfaces both as warnings and still reports PASS. |
| F7 | medium | no | Two further estate verifiers fail for reasons NOT attributable to this canon delta, and are recorded here only so they are not mistaken for it. tools/enum-member-census.mjs FAILS (census does not reproduce byte-for-byte); it derives from docs/architecture/foundations/canonical-enums.md, which did not change in the reviewed range. tools/check-source-dispositions.mjs FAILS (ledger does not reproduce); it derives from program/guide-registry.v1.json and the _archive tree, not from the architecture contract registry. |
| F8 | high | yes | The estate's own remedy for a stale canon anchor is a mechanical rewrite. check-canon-owner-coverage.mjs says `re-anchor before admission`; the only re-anchoring tool is refresh-canon-snapshots.mjs --write, which rewrites the anchor and produces no review artifact of any kind. The instruction and the tool together make the mechanical path the path of least resistance. This ledger and the hardened --accept contract are the counterweight. |

## The new required flow for `canon-impact --accept`

`--accept` can no longer assert review by itself. As of this ledger the tool requires a content-bound review manifest and an accountable reviewer, and it refuses anything that does not match the pending drift exactly.

```text
# 1. see what is pending — read-only, no manifest, never writes
node internal-docs/implementation/tools/canon-impact.mjs
node internal-docs/implementation/tools/canon-impact.mjs --check

# 2. emit a manifest skeleton of the exact pending drift set
node internal-docs/implementation/tools/canon-impact.mjs \
  --emit-review-manifest <manifest.json>

# 3. REVIEW. Name the reviewer. For every subject write a disposition
#    (unaffected | successor_required | blocked) and a review_note that
#    argues it from what actually changed. An empty note is refused, and
#    an `unaffected` that argues nothing is the same failure as a
#    mechanical accept, one subject at a time.

# 4. accept against the manifest
node internal-docs/implementation/tools/canon-impact.mjs --accept \
  --review-manifest <manifest.json> \
  --reviewer-ref 'agent://claude-opus-5 (session 2026-07-29, owner-directed)'
```

Refusal surface, each independent and each reported by name:

| Refusal | When |
| --- | --- |
| `accept-no-manifest` | `--accept` with no `--review-manifest` |
| `accept-no-reviewer` / `reviewer-placeholder` / `reviewer-mismatch` | no `--reviewer-ref`, a placeholder one, or one disagreeing with the manifest |
| `manifest-extra-subject` | the manifest names a subject that is not pending |
| `manifest-missing-subject` | a pending subject the manifest does not name |
| `manifest-stale-digest` | a recorded baseline or tree digest no longer matches |
| `manifest-disposition` / `manifest-review-note` | a subject with no disposition, or with no written reasoning |
| `accept-nothing-pending` | nothing is pending; there is no drift to review |
| `manifest-format` / `manifest-claim` / `manifest-set-digest` | wrong evidence format, a claim beyond `canon_drift_reviewed_only`, or a self-inconsistent manifest |

Every refusal leaves the baseline exactly as it was, which is the honest state. Every acceptance appends one entry to `_archive/attestations/canon-acceptances.v1.json` — append-only, dense sequence, in the same house style as `_archive/attestations/record-reattestations.v1.json`. The entry binds the manifest by digest and copies every subject and disposition into itself, so the manifest is an INPUT and the ledger is the retained record; the manifest file does not have to live in the estate.

## Non-claims of this ledger

- This ledger reviews drift. It does not re-verify any implementation, re-run any proof bar, or restore any closure.
- An `unaffected` disposition asserts only that the reviewed delta does not reach the record's claim. It asserts nothing about whether that claim is true.
- The counts here are measured from the records on disk at the review commit. Where they disagree with the brief, the measurement and the method are given and the disagreement is left standing, not reconciled away.
