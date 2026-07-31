# Architecture-to-Implementation Coverage Audit

Document class: private point-in-time audit and work record; not architecture canon, not
program status, and not a sequencer.

Audit date: 2026-07-22.

Audit checkout: `feat/estate-camera-pipeline` at `a894b250` (the current dirty
working tree was inspected without altering its pre-existing tracked changes).

Authority: architecture meaning remains in `docs/architecture/` and accepted
ADRs. Program order remains solely in
[`ioi-target-end-state-master-implementation-guide.md`](../ioi-target-end-state-master-implementation-guide.md).
Cut status remains solely in the private `ioi.program.work_item.v1` records and
their derived [`program-state.json`](../program-state.json) projection.

## Executive verdict

No. `internal-docs/implementation/` does **not** yet completely cover building
the current IOI architecture A–Z.

It substantially covers the selected M0–M14 contract-first proof spine. The 43
private records name every stage, the stronger slices usually name useful
contract families and adversarial exits, and M2, M5, M10–M14 are much less
implicit than they were before the prior reconciliation. That is meaningful
coverage of the selected proof program.

It is not an executable A–Z implementation estate for three independent
reasons:

1. **Record depth is below the master guide's own admission bar.** None of the
   43 records contains the complete §4.1 planning shape. In particular, none
   has an explicit product journey/state model, implementation-action list,
   consequential final-invoker map, frozen metrics, compatibility/migration
   plan, evidence index, or rollback/stop rule.
2. **The sequenced proof spine is narrower than the complete target canon.**
   Estate-wide information flow, production receipt cryptography, environment
   construction, lawful model supply, billing/disputes, Foundry/Evaluations,
   worker and service marketplaces, assurance, private/measured substrate,
   live embodied execution, Agentgres production breadth, and public claim
   surfaces have no complete mechanism-owning implementation slices.
3. **The product plan covers taxonomy more strongly than operational depth.**
   M6 has one umbrella record for the shell, catalog, workspaces, packages,
   aliases, and every application. The running estate exposes many useful
   projections and several governed actions, but it also exposes transitional
   navigation, harvested shells, read-only surfaces, disabled controls, and
   dormant reference lanes that have no per-surface implementation journey in
   the private plan.

The honest conclusion is therefore:

> The directory is a partially executable plan for the selected proof spine,
> not a complete build specification for the architecture estate.

This conclusion closes no stage and does not downgrade any record. Where a
record reports a status, this audit reports that record's assertion; it does
not independently promote or regress it.

## Scope, method, and evidence limits

### Inspected sources

The pass inspected:

- all 71 files then present under `internal-docs/implementation/`, including
  every top-level guide, projection, audit, evidence file, reconciliation
  artifact, and all 43 work-item records;
- the complete master guide and its M0–M14, work-package, proof-gate, release,
  scorecard, evidence, and source-disposition sections;
- the current owner map, reader entry point, execution horizons,
  implementation matrix, canon-to-code delta, current architecture owner
  documents, registered machine-contract inventory, and accepted ADRs;
- current conformance contracts under `docs/conformance/` as proof-definition
  inputs, without treating them as architecture owners;
- Hypervisor's catalog, surface registry, operational-depth atlas, parity
  inventory, bound surface modules, augmentation shell, dormant UX seeds,
  route handlers, and React entry point;
- the already-running Hypervisor UI at `http://127.0.0.1:4173` and daemon at
  `http://127.0.0.1:8765` through read-only HTTP requests.

An initial live HTTP pass requested 35 representative shell, workspace,
owner-app, substrate, proof, and dormant-shell routes; all returned HTTP 200.
The final safe-GET pass requested 74 routes: 70 returned 200 and four reference
routes returned 307 redirects. An initial normalized source pass found 143
distinct `__ioi`/`__apps` literals; the broadened IOI/reference pass retained
202 route-like strings, and separate manifests enumerate the captured SPA
pages, wildcard/proxy seams and all 103 inspected Connect RPC adapter
operations. Tests, assets, fragments, callbacks, actions and known-invalid
probes remain visible. A route string, redirect or HTTP 200 is reachability
evidence only, never proof that its workflow or backing contract is complete.

### Visual evidence limitation

The supported in-app browser was unavailable in this session. Consequently,
this pass did not perform a genuine visual desktop/narrow interaction walk or
produce fresh screenshots. It instead inspected the served HTML, visible
labels and affordances, source-defined actions and disabled reasons, and
responsive CSS. Any claim that requires layout, focus order, keyboard
operation, screen-reader behavior, pointer behavior, or viewport-specific
visual confirmation remains unverified by this audit.

This matters: only the Missions and Pipeline bound modules contain explicit
viewport media rules; the other bound surfaces and the augmentation modules
have no comparable media-query coverage. That is a source-level risk signal,
not a rendered mobile-failure verdict.

### Validation/provenance limitation

The private projection targets master commit `695921491...`, while this
checkout is at `a894b250...`. This estate branch predates
`scripts/generate-program-state.mjs`, `scripts/check-work-items.mjs`, and their
package scripts. Running
`node internal-docs/implementation/check-program-state.mjs` fails while
importing the absent generator. Several committed anchors referenced by
non-proposed records are also absent from this checkout.

These are checkout/provenance blockers. They are not evidence that a stage
closed, regressed, or lost proof.

A pre-authoring SHA-256 manifest froze the 71-file private estate. During this
audit, a separate concurrent process changed
`internal-docs/implementation/work-item-m1-5c-amendment-execution.md`. This
audit did not edit or revert that file. The two requested deliverables are the
only files added by this cut, but an exact "only two workspace files changed"
claim cannot be certified against the shared working directory while that
unrelated edit is present.

## What A–Z coverage means

A canonical target is implementation-covered only when the private estate can
follow this chain without guessing:

```text
canonical target and exact owner
  -> master stage and one owning work-item slice
  -> exact contract/schema/event/profile families
  -> implementation actions and legal mutation boundaries
  -> consequential effects and final invokers
  -> code/storage/projection anchors
  -> honest product journey, including empty/denied/degraded/recovery states
  -> positive + adversarial + fault proof and literal retained exit
  -> compatibility, migration, rollback/stop, metrics, and evidence index
```

Adjacent code, a schema, a route, an attractive UI, a process exit code, or a
historical verifier does not fill a missing link. A UI projection cannot own
runtime truth. A private workflow evidence chain cannot become product
authority. Product authority remains wallet grants, sealed intents,
final-invoker checks, and receipts; delegated review remains an unsigned hash
chain with honest nonclaims.

Coverage classifications used below:

| Classification | Meaning |
| --- | --- |
| `complete_plan_coverage` | One named slice has the complete planning chain for its bounded claim. |
| `partial_plan_coverage` | A stage/record names the subject, but one or more required owner, mechanism, product-state, or proof links are missing. |
| `pointer_only` | The estate points at canon or another plan but provides no executable slice. |
| `conflicting_plan_coverage` | Two current-looking directions overlap or disagree about owner, contract, source, sequence, or exit. |
| `missing_plan_coverage` | No mechanism-owning slice was found. |
| `canon_unresolved` | Canon has not yet resolved enough target/owner detail to admit a bounded implementation slice. |

`gated` is a qualifier, not a coverage classification: it means canon defers
activation or claims behind a later proof/demand gate. `non-build` identifies
orientation/history/nonclaims that are not canonical build obligations and
therefore are excluded from the coverage denominator.

Under that definition, no current stage is fully covered at the plan-record
level because every record omits required §4.1 fields. This is a planning
assessment, not a stage-status assertion.

## Estate census and structural findings

| Evidence | Observed fact | Coverage consequence |
| --- | --- | --- |
| Private directory | 71 files, about 2.1 MB; 22 authored/projection files at the root before these deliverables | The top level mixes authority, generated state, audits, obsolete plans, work logs, and transactional patches. |
| Work items | 43 records: M0 2; M1 7; M2 4; M3 3; M4 1; M5 5; M6 1; M7 1; M8 2; M9 4; M10 1; M11 3; M12 4; M13 2; M14 3 | Every stage has a record label, but label coverage is not complete executable planning. |
| Proposed records | 36 records name nonempty contract families, dependencies, exits, adversarial prose, and a literal success line | This is a sound minimum convention, but it is materially weaker than master §4.1/§4.3. |
| Rich planning fields | All 43 omit `selected_profile`, `in_scope`, `out_of_scope`, `implementation_actions`, `consequential_effects_and_final_invokers`, `applicable_pg_ids`, `positive_proof`, `product_journey_and_states`, `metrics_and_frozen_thresholds`, `compatibility_and_migration`, `evidence_index`, and `rollback_or_stop_rule` | The records cannot by themselves drive A–Z implementation, UX, or closure. |
| Dependency graph | Dependencies mix work-item IDs with prose such as “Real M1-M5 read models” and “Legal, assurance, and commercial gates” | The plan graph is not machine-closed; several aggregate exits have no owner record. |
| Machine contracts | Registry covers 27 revisions, 27 invariant profiles, and 117 positive/adversarial fixtures | Contract shape is unusually strong, but emitter, verifier, admission, storage, effect, export, and product paths remain separate work. |
| Hypervisor registry | 14 registered app surfaces; one declares `workflow_complete`, three `act`, one `inspect`, eight `browse`, and one `read_only_by_contract` in the UI atlas/registry vocabulary | These are bounded UI evidence labels, not program status. M6 does not plan every owner application's path from its current depth to target depth. |
| Hypervisor route estate | Transitional product shell plus native `__ioi` views, bound ported surfaces, `__apps` reference proxies, and dormant UX seeds coexist | Source ownership, route migration, shell retirement, responsive behavior, and surface-specific contracts need explicit slices. |

## Complete canon-owner inventory

The inventory below names every current architecture owner family inspected.
Schema fixtures and generated projections are represented by the registered
contract row rather than repeated one-by-one. Archived implementation logs are
not current owners.

### Meta, entry, status-index, and synthesis owners

| Role | Files | Implementation coverage finding |
| --- | --- | --- |
| Reader entry and estate navigation | `docs/architecture/README.md`; `docs/architecture/START_HERE.md`; `_meta/start-here.md` | `non-build`, except the runnable builder/product journey they describe needs WP-DOCS and M6/M9 slices. |
| Ownership and defaults | `_meta/source-of-truth-map.md`; `_meta/current-canon-defaults.md`; `_meta/vocabulary.md`; `_meta/doc-classes.md` | `partial_plan_coverage`: M0 has no recurring owner-digest/impact/orphan check tied to work-item admission. |
| Canonical order and implementation indexes | `_meta/execution-horizons.md`; `_meta/implementation-matrix.md`; `_meta/canon-to-code-delta.md` | `partial_plan_coverage`: mapped by the master, but the private records do not prove closed coverage against these changing indexes. |
| Public claim estate | `_meta/public-web-estate.md` | `missing_plan_coverage`: no complete private implementation/claim-gate slice. |
| Readability/refactor evidence | `_meta/canon-readability-audit.md`; `_meta/refactor-baseline.md` | `non-build`/historical inputs. |
| Registered contract compiler | `_meta/schemas/architecture-contract-registry.v1.json` and its schemas, invariants, fixtures, aliases, and generated targets | `partial_plan_coverage`: compiler substrate is planned by PG gates; production consumers are unevenly planned. |
| Long-form synthesis | `whitepaper.tex` | `non-build`; it cannot substitute for owner contracts. |
| Terminal/archived meta records | `_meta/hypervisor-kernel-substrate-migration-matrix.md`; `_meta/hypervisor-kernel-substrate-unification-master-guide.md`; `_meta/wallet-protocol-sdk-packaging-plan.md` | Current canon labels these non-actionable/archived, while the private master still calls the first two active authorities. This conflict requires a user-approved sequencer amendment. |

### Foundation owners

| Owner family | Files | Coverage |
| --- | --- | --- |
| Stack and bounded systems | `web4-and-ioi-stack.md`; `governed-autonomous-systems.md`; `domain-kernels.md`; `common-objects-and-envelopes.md`; `canonical-enums.md`; `invariants.md` | `partial_plan_coverage` across M1–M14; the selected System spine is represented, broader lifecycle/finality/recovery and full shared-object breadth are not. |
| Bounded agency and security | `verifiable-bounded-agency.md`; `security-privacy-policy-invariants.md` | `partial_plan_coverage`: bounded execution appears throughout, but estate-wide IFC/declassification and temporal enforcement have no end-to-end slice. |
| Semantic plane | `domain-ontologies-and-data-recipes.md` | `partial_plan_coverage` in M7; one umbrella record does not cover full ODK, transformation, projection, action, dispute, and federation breadth. |
| Learning and improvement | `institutional-learning-boundary.md`; `bounded-recursive-improvement.md` | `partial_plan_coverage` in M8; custody, route rights, real Foundry/Evaluations, portability, and campaign runtime/product work remain incomplete. |
| Worker supply | `mixture-of-workers.md`; `worker-training-lifecycle.md` | `missing_plan_coverage` as mechanism-owning implementation work. |
| Economics | `economic-flywheel-and-pricing-boundaries.md` | `partial_plan_coverage` for M13/M14 proof criteria and `missing_plan_coverage` for managed billing, Work Credits, reconciliation, and dispute mechanisms. |
| Assurance | `ecosystem-assurance-certification-liability.md` | `missing_plan_coverage` beyond references and later-stage gates. |
| Physical safety | `physical-action-safety.md` | `partial_plan_coverage`: M11 explicitly stops before live promotion; live effect/safety proof has `missing_plan_coverage` and needs a later owned slice. |
| Sovereign interop | `aiip.md` | `partial_plan_coverage` in M12–M13; core protocol/proof slices exist, production cross-cut bindings are incomplete. |
| Public trust/economics | `ioi-l1-mainnet.md`; `ioi-l1-contract-interfaces.md` | `partial_plan_coverage`, correctly `gated` in M14; this is not an A–Z implementation plan for the speculative contract estate. |

### Component owners

| Component | Files | Coverage |
| --- | --- | --- |
| Agentgres | `agentgres/doctrine.md`; `api-object-model.md`; `artifact-ref-plane.md`; `postgres-bridge-and-readiness-contract.md`; `projection-system-reference.md` | `partial_plan_coverage`: many stages cite truth/replay abstractly; Postgres readiness, checkpoint/proof export, branch/staged effects, and owner integration lack complete slices. |
| Daemon/runtime | `daemon-runtime/doctrine.md`; `api.md`; `default-harness-profile.md`; `events-receipts-delivery-bundles.md`; `platform-operability.md`; `improvement-governance-gates.md`; `portable-memory-vault.md`; `runtime-nodes-tee-depin.md`; `task-capsule-protocol.md`; `private-workspace-ctee.md`; `hypervisoros.md`; `embodied-runtime.md` | `partial_plan_coverage`: the runtime rail is pervasive, but receipt crypto, platform observers/recovery, cTEE/HypervisorOS/task-capsule production, and native embodied runtime are not completely planned. |
| Hypervisor product/substrate | `hypervisor/core-clients-surfaces.md`; `providers-and-environments.md`; `byo-provider-plane.md`; `identity-access-and-metering.md`; `foundry.md`; `evaluations.md`; `improvement.md` | `partial_plan_coverage`: M6 covers taxonomy, not operational depth; project discovery/startup, full provider lifecycle, identity/metering, training/eval, and improvement product paths remain incomplete. |
| Connectors/tools | `connectors-tools/doctrine.md`; `contracts.md` | `partial_plan_coverage`: RuntimeToolContract substrate exists; complete MCP normalization, gateway equivalence, IFC, and every egress/final-invoker path do not. |
| Model router | `model-router/doctrine.md`; `api-byok-mounting.md` | `missing_plan_coverage` as a complete rights/supply/BYOK/BYOA/fallback implementation lane. |
| Wallet | `wallet-network/doctrine.md`; `api-authority-scopes.md`; `product-exchange-risk.md` | `partial_plan_coverage`: selected authority proof and managed overlay are planned; portable crypto verification, account/recovery product breadth, and financial authority surfaces remain incomplete. |
| Storage | `storage-backends/doctrine.md`; `filecoin-cas.md` | `partial_plan_coverage`: current local/CAS/Filecoin precedents do not amount to an A–Z storage/profile/repair/availability plan. |

### Domain owners

| Domain | Files | Coverage |
| --- | --- | --- |
| ioi.ai | `ioi-ai/control-plane.md`; `ioi-ai/collaborative-outcome-pattern.md` | `partial_plan_coverage` in M4–M5 and M12–M13; Goal Space product, managed attachment, full room acceptance/dispute/economics, and open challenge operation are not fully planned. |
| aiagent.xyz | `aiagent/digital-worker-ontology.md`; `vertical-ontology-packs.md`; `integration-surface-taxonomy.md`; `managed-worker-instance-lifecycle.md`; `managed-agent-console-contract.md`; `worker-endpoints.md`; `worker-marketplace.md` | `missing_plan_coverage` as an end-to-end worker registry, hiring, managed-instance, console, integration, and public-marketplace implementation program. |
| sas.xyz | `sas/service-endpoints.md`; `sas/service-marketplace.md` | `missing_plan_coverage` as an end-to-end service order, fulfillment, evidence, acceptance, dispute, and settlement program. |
| decentralized.* | `decentralized/README.md`; `cloud.md`; `exchange.md`; `trade.md` | `missing_plan_coverage` as product implementation slices; wallet/route/provider boundaries appear only incidentally. |
| Marketplace neutrality | `marketplace-neutrality.md` | `partial_plan_coverage` in contribution/proof language; routing neutrality, allocation, accounting, dispute, and settlement mechanisms lack a full slice. |

### Accepted decision controls

The pass inspected accepted ADRs 0001–0006, 0008, 0010, and 0013–0018.
ADRs 0007, 0009, 0011, and 0012 are retained superseded history. The most
implementation-significant current controls are ADR 0013 (Core/clients/
surfaces/adapters), 0014 (IDE/session estate), 0015 (bounded distributed
autonomous systems and enrollment), 0016 (Systems and Work spine), 0017
(pursuit/workflow/skill/harness/tool separation), and 0018 (bounded campaigns
without an RSI engine).

## Canonical target-to-plan trace

This is the A–Z coverage view. Code evidence and UI observations are deliberately
separate. The grade is an audit inference from canon, private plans, code, and
UI; none of those observations declares a stage or target family complete.

| Architecture family | Canonical target | Current plan owner | Code evidence | UI observation | Missing plan-level links | Audit inference |
| --- | --- | --- | --- | --- | --- | --- |
| Program and claim control | One owner per fact, exact current evidence, literal exits, honest nonclaims | M0 records; master §§4–5, 13–16 | Private checker and literal M0 wrapper exist, but this branch lacks generator/check scripts | Not applicable; UI cannot establish program truth | Full §4.1 schema, closed dependencies, canon digest, owner/orphan lint, route/final-invoker/PG census | `partial_plan_coverage` |
| Bounded System core | Package/release, profiles, genesis, sequence zero, constitution, activation, protected transitions | Seven M1 records | Registered package/genesis/profile contracts and compiler precedents | Governance/System-like projections expose only selected transitions | M1.5d migration/succession/dissolution/enrollment; complete M1 aggregate; product journey/states | `partial_plan_coverage` |
| Deployment and continuity substrate | Desired/observed deployment, membership, readiness, epochs, fences, recovery, routes, backups, restore, cleanup | Four M2 records | Placement/failover records and partial environment/backup precursors | Environments/Operations show bounded projections, not membership/fencing proof | Node attestation, temporal floors, secrets/custody, Agentgres recovery, exact invokers, product states | `partial_plan_coverage` |
| Pursuit/runtime spine | GoalRunProfile, WorkflowTemplate, skills, harness/tool resolution, GoalRun/Context/Session/Work lifecycle and generic results | Three M3 records | GoalRun precursor, harness registry, Step/Module Rust boundary, owner-specific lifecycle implementations | Sessions/Automations/timeline views cover selected lifecycle reads | Goal Kernel/context/runtime truth slice; full MCP normalization; shared lifecycle owner integrations; UX journey | `partial_plan_coverage` |
| Flagship OutcomeRoom System | Reusable room package, one System per durable room, admitted graph children, hosted admission, export | One M4 umbrella record | Hosted room/participant/frontier code precedents exist | Missions is a read-oriented compatibility projection, not the target room journey | Exact graph/room contracts, acceptance/verdict, receipts/replay, decomposition, Goal Space/Work/Governance/Provenance states | `partial_plan_coverage` |
| Participants and frontier | Pairing, participation, offers, claims, attempts, findings, challenges, results, portable exit, P0 readiness | Five M5 records | Hosted-plane participant/frontier precedents exist | Missions exposes only a bounded read projection | Identity owner crossing, gateway narrowing, allocation/spend/reassignment, acceptance/dispute, per-surface journey | `partial_plan_coverage` |
| Product surface system | Policy-filtered compiler, normalized registrations, five workspaces, owner/substrate apps, packages, routes/aliases | One M6 record plus taxonomy specialist plan | Fourteen-surface registry and selected governed handlers exist | Applications/native/ported views are broad; Systems and Work are absent from the canonical root spine | Exact canonical family names, compiler implementation, Systems/Work shell migration, every owner app's operational path, responsive/a11y/deep-link proof | `partial_plan_coverage` |
| Semantic/data plane | Ontology versions/overlays/crosswalks, mappings, assertions, recipes, transformations, action contracts, oracle policy | One M7 record | ODK and mutable mapping/data-pipeline precedents exist | Ontology/Data projections expose browse and selected bounded actions | Immutable definition/run split, Agentgres/replay, action final invokers, IFC, disputes, generated apps, full product journey | `partial_plan_coverage` |
| Enterprise learning | Fail-closed learning compiler, source/route rights, custody, eligibility, egress, export/import, provider exit | `m8-learning-boundary-provider-exit` | Adjacent memory, route, policy, and data precedents only | Studio/Foundry/Evaluations expose fragments, not a custody/rights journey | cTEE/vault/storage, bidirectional rights, scope inheritance, real egress enforcement, portability and model-swap runner | `partial_plan_coverage` |
| Bounded improvement | Direct proposals plus optional campaigns, frozen epochs, exposure, independent judgment, owner promotion | `m8-order-zero-improvement-and-direct-path`; campaign specialist plan | Narrow proposal/simulation handlers exist | Improvement/Studio show proposal-like states, not the complete campaign/promotion loop | Complete campaign objects/runtime, Foundry/Evaluations, metrics, product states, target-owner promotion and rollback proof | `partial_plan_coverage` |
| Authority and authentication | Local identity separate from authority; portable grants, review/ceremony, revocation, daemon-derived effect, receipts | M9 sovereign and managed-overlay records; WP-WALLET | v1/v2 contract substrate, principal-authority resolution, and selected guarded handlers exist | Login/review/account fragments do not cover portable verification or every final invoker | Portable verifier, v3 path, account/factor/recovery estate, receipt profiles, estate-wide final-invoker equality | `partial_plan_coverage` |
| Information flow and privacy | Labels and declassification propagate through every guarded seam before egress/effect | Mentioned across PG and records, no owning slice | Registered label/declassification schema substrate only | No estate-wide denied/degraded/declassification journey was found | Shared evaluator, propagation kernel, enumerated PEP suite, connector/MCP/model/browser/memory/room coverage, degraded/refusal UX | `missing_plan_coverage` |
| Receipt integrity and portable proof | JCS hashing, accumulator, signed checkpoints, inclusion/consistency proof, Agentgres export, offline verifier | WP-PROOF and M9 selected offline proof | Registered receipt/checkpoint/proof schemas and fixtures | Provenance/timeline views do not demonstrate independent offline verification | Production emitters, checkpoint writer, key discovery, proof export/CLI, transparency and split-view defenses | `missing_plan_coverage` |
| Environment construction and product lifecycle | Project discovery → accepted candidate → recipe/resolution → StartupPlan → launch/spawn/readiness/terminal; routes, backup/restore, cleanup | M2 route/restore record only partially; M9 lifecycle proof | Generic recipe/resolution, independent spawn, ports and legacy backup precedents | Projects/Environments expose only parts of the predecessor/recovery chain | ProjectDiscovery, StartupPlan, complete predecessor chain, persistent cleanup, installer/updater/doctor owner slices | `missing_plan_coverage` |
| Model/provider supply | Lawful provider rights, BYOK/BYOA, local/open routes, fallback rules, custody, pricing, supplier reconciliation | WP-SUPPLY prose; no mechanism record | Model route/admin and provider precedents exist | Model Catalog/Foundry cards do not establish rights, substitution, or reconciliation | Full rights contract enforcement, credential principal, unattended/downstream rights, substitution, learning rights, supplier statements | `missing_plan_coverage` |
| Managed economics and disputes | Quote/hold/usage/debit/adjustment, Work Credits, fees, service/marketplace settlement, adjudication/remedies | M13/M14 proof criteria; no production mechanism slices | Registered billing/dispute bundle schemas only | Billing/listing views do not expose a complete acceptance/dispute/remedy journey | Persistence, authority/effect paths, reconciliation, product APIs, escrow/bonds/remedies, cross-rail receipt closure | `missing_plan_coverage` |
| Foundry and Evaluations | Training/tuning/eval jobs, frozen epochs, scorecards, artifacts, independent judgment, promotion bundles | M8/M11 references | No complete execution loop was found | Foundry labels plans; Evaluations labels suites inert | Real job execution, evaluator integrity, exposure ledger, artifact lifecycle, promotion/rollback, operator journey | `missing_plan_coverage` |
| Workers, services, and marketplaces | MoW routing/training; private/public workers; managed instances; service orders/delivery; contribution accounting | Incidental M5/M13/M14 references | Current worker/provider and browse-projection precedents exist | Marketplace/listings are browse-heavy and do not complete hiring/order/delivery/settlement | End-to-end aiagent/sas lifecycles, independent supply, consoles, hiring/orders, delivery/acceptance, payments/disputes | `missing_plan_coverage` |
| Platform operability | Per-operation plane/temporal decisions, recovery, mixed versions, key epochs, SLOs, observability, capacity, incidents | Cross-cut prose and selected M9/M10 proofs | Fault-matrix contract and scattered readiness/operations precedents exist | Operations/Incidents do not show a complete observer/controller/recovery path | Production observer/evaluator, outside-domain floors, recovery controller, privacy-safe telemetry, capacity/backpressure/support bundles | `missing_plan_coverage` |
| Private/measured substrate | HypervisorOS, runtime nodes, cTEE, task capsules, attestation, leases/re-attestation | Mentioned in M2/M9/M10, not mechanism-owned | Contract/projection and generic startup precedents exist | No complete measured-boot/attestation/custody operator journey was found | Images/boot/update, measurement/attestation drivers, custody proof, task-capsule runtime, product/operator flows | `missing_plan_coverage` |
| Same-System distribution | Membership, continuity, RuntimeAssignment, work allocation, partitions, reassignment, no duplicate effects | M10 and M11 records | Placement/failover substrate exists; no retained stage proof in this checkout | Work/Systems/Operations do not expose the complete partition/reassignment/recovery journey | Exact assignments/leases/watermarks, Agentgres coordination, chaos runner, operator states, dynamic/automated profiles when later claimed | `partial_plan_coverage` |
| Embodied and physical | Native graph/profiles/streams/supervisor/controllers, transactional activation, fleet allocation, staged promotion, live safety | M11 non-live record and aggregate | Limited intent/schema precedents only | No complete Embodied Systems journey or live-action proof was observed | Canon-name alignment, compiler/executor/supervisor, Foundry SIL/HIL/shadow, live final invoker, physical receipts, certification/promotion | non-live `partial_plan_coverage`; live `missing_plan_coverage` |
| AIIP federation | Channels/envelopes, exact-root terms, semantic/action negotiation, standards bindings, federated admission, portable exit | Four M12 records | Target contracts and selected hosted precedents only | No sovereign federation/operator journey was observed | IFC/disclosure, keys/revocation, retries/reconciliation, dispute/settlement, third-party conformance and full operator journey | `partial_plan_coverage` |
| Two-sovereign proof | Independent systems, external worker/verifier, positive participant surplus, safe decline and exit | Two M13 records | No two-sovereign proof artifact was found | No UI observation is admissible as proof; no proof claim is made | Aggregate exit, independent-operation acquisition, frozen metrics, product/dispute/exit journey and evidence export | `partial_plan_coverage`; proof `gated` |
| Connected/secured services and L1 | Explicit enrollment/services, demand/security economics, valid no-L1 branch, optional selected public commitments | Three M14 records | Enrollment/billing/dispute schemas are only contract substrate | No connected-service devnet or L1 operator proof was observed | Exact service owners, product surfaces, aggregate exit, legal/commercial/assurance thresholds, devnet operator proof | `partial_plan_coverage`; L1 `gated` |
| Ecosystem assurance and public claims | Conformance, certification, jurisdiction, quarantine, liability, commercial audit, honest public estate | Later gates only | No general production mechanism was found | No complete certification/liability/publication withdrawal journey was observed | Full implementation slices and publication gates | `missing_plan_coverage` |

### Obligation-level trace ledger

The family table above is the compact verdict; the rows below are the
implementation-sized obligations used to reach it. “Owner location” is the
exact canonical file plus the owning subject/section (line numbers are avoided
because this audit is intended to survive canon edits). Registry revisions,
fixtures, ADRs, and every inspected path are enumerated in the appendix.
Code evidence and UI observation are separate from each other and from the
canonical requirement. Neither supplies a missing plan owner.

#### Exact canonical source locators

Each ledger target resolves here to one or more
`repo-path#exact-GitHub-heading-anchor` locators. Every anchor was checked
against a unique literal heading in this checkout; this is the stable exact
location used by the corresponding row below. The contract registry is JSON,
so its locator uses an RFC 6901 JSON Pointer instead of inventing a Markdown
heading. Supporting owner files remain named in the ledger rows even when the
minimum authoritative heading set below is smaller.

| Ledger target | Exact canonical heading locator(s) |
| --- | --- |
| Canon owner/change intake | `docs/architecture/_meta/source-of-truth-map.md#subject-ownership`; `docs/architecture/_meta/source-of-truth-map.md#edit-rules`; `docs/architecture/_meta/current-canon-defaults.md#current-defaults`; `docs/architecture/_meta/schemas/architecture-contract-registry.v1.json#/contracts`; `docs/decisions/README.md#accepted-adrs` |
| Public claim boundary | `docs/architecture/_meta/public-web-estate.md#status-axis-and-claim-rules`; `docs/architecture/_meta/public-web-estate.md#gates` |
| System package/release/profile | `docs/architecture/foundations/governed-autonomous-systems.md#the-bounded-system-contract`; `docs/architecture/foundations/objects/bounded-system-genesis.md#package-release-and-live-system-genesis`; `docs/architecture/foundations/objects/bounded-system-genesis.md#autonomoussystemdeploymentprofileenvelope` |
| Genesis/sequence zero/activation | `docs/architecture/foundations/objects/bounded-system-genesis.md#autonomoussystemgenesisenvelope`; `docs/architecture/foundations/objects/bounded-system-genesis.md#autonomoussystemsequencezeromaterializationenvelope`; `docs/architecture/foundations/governed-autonomous-systems.md#lifecycle-is-part-of-correctness` |
| Protected transitions | `docs/architecture/foundations/governed-autonomous-systems.md#lifecycle-is-part-of-correctness`; `docs/architecture/foundations/verifiable-bounded-agency.md#proposal-mediated-autonomous-system-upgrades`; `docs/architecture/foundations/objects/bounded-system-genesis.md#lifecycletransitionenvelope` |
| Agentgres operation truth | `docs/architecture/components/agentgres/doctrine.md#substrate-contract-doctrine`; `docs/architecture/components/agentgres/api-object-model.md#operation-shape`; `docs/architecture/components/agentgres/projection-system-reference.md#4-core-properties-of-a-csps` |
| Agentgres persistence/branches/checkpoints | `docs/architecture/components/agentgres/api-object-model.md#agent-execution-branches`; `docs/architecture/components/agentgres/postgres-bridge-and-readiness-contract.md#commit-log-and-durability`; `docs/architecture/components/agentgres/postgres-bridge-and-readiness-contract.md#recovery-and-pitr-roadmap` |
| Deployment membership/readiness | `docs/architecture/components/hypervisor/providers-and-environments.md#autonomous-system-node-addition-and-failover-boundary`; `docs/architecture/components/daemon-runtime/runtime-nodes-tee-depin.md#attestation-assurance-and-tee-flow`; `docs/architecture/foundations/objects/bounded-system-genesis.md#autonomoussystemnodemembershipenvelope` |
| Writer fencing/reconciliation | `docs/architecture/foundations/governed-autonomous-systems.md#multi-node-deployment-continuity-and-useful-work`; `docs/architecture/components/daemon-runtime/doctrine.md#logical-system-control-boundary`; `docs/architecture/foundations/objects/bounded-system-genesis.md#autonomoussystemwriterepochtransitionenvelope` |
| Environment discovery/startup | `docs/architecture/components/hypervisor/providers-and-environments.md#evidenced-project-discovery`; `docs/architecture/components/hypervisor/providers-and-environments.md#autonomous-readiness-and-setup-automation`; `docs/architecture/components/hypervisor/byo-provider-plane.md#product-placement-abstraction` |
| Backup/restore/route/cleanup | `docs/architecture/components/hypervisor/providers-and-environments.md#lifecycle`; `docs/architecture/components/daemon-runtime/platform-operability.md#checkpoint-backup-restore-migration-and-compaction`; `docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md#environment-backup-restore-route-binding-and-cleanup-receipts` |
| Goal/harness/tool resolution | `docs/architecture/components/daemon-runtime/default-harness-profile.md#step-resolution-broker-boundary`; `docs/architecture/components/connectors-tools/contracts.md#mcp-normalization-boundary`; `docs/decisions/0017-goal-pursuit-workflow-skill-and-harness-taxonomy.md#decision` |
| Context/session/work/result lifecycle | `docs/architecture/components/daemon-runtime/doctrine.md#shared-lifecycle-mechanics-distinct-owners`; `docs/architecture/foundations/objects/work-results-and-lifecycle.md#worklifecyclerecordenvelope`; `docs/architecture/components/daemon-runtime/api.md#workeragent-and-run-lifecycle` |
| Platform operation decisions | `docs/architecture/components/daemon-runtime/platform-operability.md#canonical-definition`; `docs/architecture/components/daemon-runtime/platform-operability.md#plane-sli-and-slo-contract`; `docs/architecture/components/daemon-runtime/platform-operability.md#incident-evidence-and-recovery` |
| Measured/private substrate | `docs/architecture/components/daemon-runtime/hypervisoros.md#node-measurement-doctrine`; `docs/architecture/components/daemon-runtime/runtime-nodes-tee-depin.md#attestation-assurance-and-tee-flow`; `docs/architecture/components/daemon-runtime/private-workspace-ctee.md#canonical-definition`; `docs/architecture/components/daemon-runtime/task-capsule-protocol.md#taskcapsule` |
| Room/System graph | `docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md#collaborative-work-graph-and-shared-state-admission`; `docs/architecture/foundations/objects/collaborative-pursuit.md#outcomeroomenvelope`; `docs/architecture/domains/ioi-ai/control-plane.md#ioiai-goal-chat-and-goal-space-boundary` |
| Participant/frontier/result lifecycle | `docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md#canonical-flow`; `docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md#cross-domain-discovery-admission-and-portable-exit`; `docs/architecture/domains/marketplace-neutrality.md#contribution-objects` |
| P0 readiness | `internal-docs/implementation/ioi-target-end-state-master-implementation-guide.md#m5--participants-local-agents-and-shared-frontier`; `docs/architecture/components/daemon-runtime/default-harness-profile.md#verification-and-completion`; `docs/architecture/components/connectors-tools/doctrine.md#readiness-and-escalation-states` |
| Product-surface compiler/topology | `docs/architecture/components/hypervisor/core-clients-surfaces.md#top-level-product-ia`; `docs/architecture/components/hypervisor/core-clients-surfaces.md#product-surface-compiler`; `docs/decisions/0016-hypervisor-systems-work-and-application-taxonomy.md#decision` |
| Owner-application operational depth | `docs/architecture/components/hypervisor/core-clients-surfaces.md#the-autonomous-systems-owner-applications`; `docs/architecture/components/hypervisor/core-clients-surfaces.md#application-surface-registration-contract` |
| Production UI truth/source | `docs/architecture/components/hypervisor/core-clients-surfaces.md#first-class-clients`; `docs/architecture/components/daemon-runtime/api.md#hypervisor-client-projections`; `docs/architecture/components/daemon-runtime/doctrine.md#public-runtime-api` |
| Consequential UI actions | `docs/architecture/components/wallet-network/doctrine.md#canonical-embedded-sign-in-to-effect-journey`; `docs/architecture/components/daemon-runtime/api.md#action-mediation--authority-gateway-api`; `docs/architecture/components/wallet-network/api-authority-scopes.md#target-context-bound-authority-grant` |
| Ontology definitions/actions | `docs/architecture/foundations/domain-ontologies-and-data-recipes.md#first-class-concepts`; `docs/architecture/foundations/domain-ontologies-and-data-recipes.md#lifecycle`; `docs/architecture/foundations/domain-ontologies-and-data-recipes.md#authority-boundary` |
| Data recipes/transformations/provenance | `docs/architecture/foundations/domain-ontologies-and-data-recipes.md#lifecycle`; `docs/architecture/foundations/domain-ontologies-and-data-recipes.md#agentgres-boundary`; `docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md#ontology-assertion-admission-receipt` |
| Information-flow/declassification | `docs/architecture/foundations/security-privacy-policy-invariants.md#information-flow-invariants`; `docs/architecture/foundations/security-privacy-policy-invariants.md#target-information-flow-boundary-matrix` |
| Receipt integrity/offline proof | `docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md#receipt-checkpoints-and-offline-proofs`; `docs/architecture/components/agentgres/doctrine.md#state-and-payload-boundary`; `docs/architecture/components/storage-backends/doctrine.md#lifecycle` |
| Identity/access/metering | `docs/architecture/components/hypervisor/identity-access-and-metering.md#canonical-definition`; `docs/architecture/components/hypervisor/identity-access-and-metering.md#metering--cost`; `docs/architecture/components/wallet-network/doctrine.md#portable-principal-to-authority-binding` |
| Wallet grants/receipts/exchange risk | `docs/architecture/components/wallet-network/doctrine.md#canonical-embedded-sign-in-to-effect-journey`; `docs/architecture/components/wallet-network/api-authority-scopes.md#target-context-bound-authority-grant`; `docs/architecture/components/wallet-network/product-exchange-risk.md#canonical-exchange-flow` |
| Institutional learning/custody | `docs/architecture/foundations/institutional-learning-boundary.md#canonical-definition`; `docs/architecture/foundations/institutional-learning-boundary.md#portability-and-model-independence`; `docs/architecture/components/daemon-runtime/private-workspace-ctee.md#custody-types-and-proof-carrying-workspace` |
| Bounded improvement | `docs/architecture/foundations/bounded-recursive-improvement.md#lightweight-and-campaign-paths`; `docs/architecture/foundations/bounded-recursive-improvement.md#promotion-and-effect-recovery`; `docs/architecture/components/daemon-runtime/improvement-governance-gates.md#campaign-grade-gate-extension-planned` |
| Model/provider rights/supply | `docs/architecture/components/model-router/doctrine.md#supply-portfolio-and-route-rights`; `docs/architecture/components/model-router/api-byok-mounting.md#byok-rule`; `docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md#open-supply-and-foundation-model-procurement` |
| Storage profiles/repair | `docs/architecture/components/storage-backends/doctrine.md#lifecycle`; `docs/architecture/components/storage-backends/doctrine.md#artifact-availability-incidents`; `docs/architecture/components/storage-backends/filecoin-cas.md#availability-incidents-and-repair` |
| Same-System continuity | `docs/architecture/foundations/governed-autonomous-systems.md#multi-node-deployment-continuity-and-useful-work`; `docs/architecture/foundations/objects/bounded-system-genesis.md#autonomoussystemdeploymentprofileenvelope`; `docs/architecture/foundations/objects/bounded-system-genesis.md#autonomoussystemwriterepochtransitionenvelope`; `docs/architecture/components/agentgres/postgres-bridge-and-readiness-contract.md#replication-and-deployment-profiles`; `docs/architecture/components/agentgres/postgres-bridge-and-readiness-contract.md#recovery-and-pitr-roadmap` |
| Useful distribution | `docs/architecture/foundations/governed-autonomous-systems.md#multi-node-deployment-continuity-and-useful-work`; `docs/architecture/foundations/objects/work-execution.md#runtimeassignmentenvelope`; `docs/architecture/foundations/objects/collaborative-pursuit.md#workclaimleaseenvelope`; `docs/decisions/0015-bounded-distributed-autonomous-systems-and-network-enrollment.md#three-coordination-planes` |
| Non-live embodied graph | `docs/architecture/components/daemon-runtime/embodied-runtime.md#compiled-runtime-graph-and-component-abi`; `docs/architecture/foundations/objects/embodied-systems.md#embodiedgraphactivationtransaction`; `docs/architecture/components/daemon-runtime/embodied-runtime.md#sim-to-real-promotion-gates`; `docs/architecture/foundations/physical-action-safety.md#physical-assurance-evidence-levels` |
| Live physical promotion | `docs/architecture/foundations/physical-action-safety.md#hard-local-safety-invariants`; `docs/architecture/foundations/physical-action-safety.md#final-invoker-and-receipt-chain-invariant`; `docs/architecture/components/daemon-runtime/embodied-runtime.md#local-control-supervisor-compatibility-bridge-heartbeat-and-failsafe`; `docs/architecture/components/daemon-runtime/embodied-runtime.md#deployment-bound-assurance` |
| AIIP channel/envelope/profile | `docs/architecture/foundations/aiip.md#aiip-envelope`; `docs/architecture/foundations/objects/interop-and-collaboration-terms.md#aiip-and-bounded-execution-domain-envelopes`; `docs/architecture/foundations/aiip.md#protocol-profiles` |
| AIIP discovery/terms/semantic/action negotiation | `docs/architecture/foundations/aiip.md#packet-classes`; `docs/architecture/foundations/aiip.md#standards-bindings-not-replacements`; `docs/architecture/foundations/domain-ontologies-and-data-recipes.md#local-semantic-world-planes-and-optional-federation`; `docs/architecture/components/connectors-tools/contracts.md#mcp-normalization-boundary` |
| Federated admission/portable exit | `docs/architecture/foundations/aiip.md#outcomeroom-and-collaborativeworkgraph-handoffs`; `docs/architecture/foundations/governed-autonomous-systems.md#conditional-cooperation-between-sovereign-systems`; `docs/architecture/components/wallet-network/doctrine.md#multi-party-authority-boundary`; `docs/architecture/components/storage-backends/doctrine.md#lifecycle` |
| Two-sovereign trial/surplus | `docs/architecture/foundations/aiip.md#conditional-cooperation-thesis`; `docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md#conditional-cooperation-and-participant-rationality`; `docs/architecture/foundations/mixture-of-workers.md#contribution-assurance-and-settlement` |
| Worker ontology/training/marketplace | `docs/architecture/domains/aiagent/digital-worker-ontology.md#lifecycle`; `docs/architecture/foundations/worker-training-lifecycle.md#canonical-stages`; `docs/architecture/domains/aiagent/integration-surface-taxonomy.md#integration-classes`; `docs/architecture/domains/aiagent/managed-worker-instance-lifecycle.md#lifecycle`; `docs/architecture/domains/aiagent/worker-marketplace.md#hire-and-configure-flow`; `docs/architecture/domains/aiagent/worker-endpoints.md#task-execution-api` |
| Service order/marketplace | `docs/architecture/domains/sas/service-marketplace.md#service-order-lifecycle`; `docs/architecture/domains/sas/service-endpoints.md#order-api`; `docs/architecture/domains/sas/service-endpoints.md#delivery-api`; `docs/architecture/domains/sas/service-endpoints.md#settlement--escrow-mirror-api`; `docs/architecture/domains/sas/service-endpoints.md#dispute-api` |
| Billing/Work Credits/reconciliation | `docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md#work-credits`; `docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md#managed-work-billing-chain`; `docs/architecture/components/hypervisor/identity-access-and-metering.md#metering--cost` |
| Dispute/adjudication/remedy | `docs/architecture/foundations/objects/interop-and-collaboration-terms.md#dispute-rail-object-family`; `docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md#dispute-rail-economics`; `docs/architecture/foundations/aiip.md#aiip-dispute-rail`; `docs/architecture/domains/marketplace-neutrality.md#marketplace-dispute-rail`; `docs/architecture/domains/sas/service-endpoints.md#dispute-api` |
| Marketplace neutrality/contribution | `docs/architecture/domains/marketplace-neutrality.md#neutral-routing-doctrine`; `docs/architecture/domains/marketplace-neutrality.md#contribution-objects`; `docs/architecture/domains/marketplace-neutrality.md#marketplace-dispute-rail` |
| Ecosystem assurance/liability | `docs/architecture/foundations/ecosystem-assurance-certification-liability.md#assurance-object-families`; `docs/architecture/foundations/ecosystem-assurance-certification-liability.md#jurisdiction-and-compliance-packs`; `docs/architecture/foundations/ecosystem-assurance-certification-liability.md#insurance-liability-and-claims`; `docs/architecture/foundations/ecosystem-assurance-certification-liability.md#abuse-threat-and-quarantine`; `docs/architecture/foundations/ecosystem-assurance-certification-liability.md#commercial-assurance` |
| Connected/secured services | `internal-docs/implementation/ioi-target-end-state-master-implementation-guide.md#m14--connectedsecured-services-and-demand-gated-l1`; `docs/architecture/foundations/governed-autonomous-systems.md#ioi-network-enrollment`; `docs/architecture/domains/sas/service-marketplace.md#optional-ioi-network-services-and-settlement-profile`; `docs/architecture/foundations/ecosystem-assurance-certification-liability.md#ioi-network-enrollment-and-assurance-mapping`; `docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md#commercial-activation-gates`; `docs/architecture/domains/aiagent/worker-endpoints.md#marketplace-admission-endpoints` |
| L1/no-L1 decision | `docs/architecture/foundations/ioi-l1-mainnet.md#local-and-optional-public-settlement`; `docs/architecture/foundations/ioi-l1-mainnet.md#bootstrap-and-native-asset-gate`; `docs/architecture/foundations/ioi-l1-contract-interfaces.md#contract-set` |
| SDK/CLI/ADK/ODK/public builder path | `docs/architecture/_meta/start-here.md#reader-paths`; `docs/architecture/components/daemon-runtime/doctrine.md#cli-operator-surface`; `docs/architecture/components/daemon-runtime/doctrine.md#public-runtime-api`; `docs/architecture/components/hypervisor/core-clients-surfaces.md#first-class-clients`; `docs/architecture/components/hypervisor/core-clients-surfaces.md#builder-surfaces`; `docs/architecture/components/connectors-tools/contracts.md#hypervisor-mcp-gateway-api`; `docs/architecture/foundations/domain-ontologies-and-data-recipes.md#product-and-domain-roles` |
| Decentralized cloud/exchange/trade profiles | `docs/architecture/domains/decentralized/README.md#boundary-rule`; `docs/architecture/domains/decentralized/cloud.md#lifecycle`; `docs/architecture/domains/decentralized/exchange.md#lifecycle`; `docs/architecture/domains/decentralized/trade.md#lifecycle` |

#### Program, System, truth, runtime, and environment obligations

| Target and exact owner location | Required contract/behavior | Runtime/application owner and journey | Required proof | Stage/private slice | Code evidence | UI observation | Classification | Missing plan material |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Canon owner/change intake — `_meta/source-of-truth-map.md`, `_meta/current-canon-defaults.md`, `_meta/schemas/architecture-contract-registry.v1.json`, `../decisions/README.md` | One owner per fact; current owner/contract digest; no archive as current owner | Private admission tooling; contributor changes canon then receives impact report | Duplicate/zero-owner, stale digest, superseded ADR and orphan rejection | M0; no complete record | Owner map, contract compiler and fixtures exist | Not applicable; UI is not program truth | `partial_plan_coverage` | Full record schema, deterministic coverage projection, current digest and owner/orphan verifier |
| Public claim boundary — `_meta/public-web-estate.md` | Every public property/copy claim bound to proved release scope and nonclaims | Docs/public-property publication and withdrawal journey | Stale/overbroad claim, missing evidence, rollback and removal proof | Later WP-DOCS only | No general claim-gate mechanism inspected | No complete publication/withdrawal journey inspected | `missing_plan_coverage` | Named owner slice, property census, evidence binding, expiry/withdrawal exit |
| System package/release/profile — `foundations/governed-autonomous-systems.md` “package/release/profile” and `foundations/common-objects-and-envelopes.md` | Immutable package/release/profile, selected compact/advanced form and identical object/hash semantics | Daemon compiler; Studio/Packages/System proposal and inspect journey | Invalid digest/dependency/profile, compact/advanced parity, two-System isolation | M1 records; M9 parity record missing | Registered package/profile/genesis schemas and compiler precedents | Studio/Governance projections do not cover the complete package journey | `partial_plan_coverage` | Exact contracts/actions, product states, M9.1 owner and evidence index |
| Genesis/sequence zero/activation — `foundations/governed-autonomous-systems.md` “genesis/sequence zero/lifecycle” and `foundations/common-objects-and-envelopes.md` | Deterministic proposal→validation/simulation→approval→genesis→sequence zero→initialize→activate | Daemon/Agentgres; Studio/Governance/System detail | Wrong approver/profile/System, crash/restart, no activation before admitted genesis | Existing M1.1–M1.4/initialize records | Several record assertions target an older master; their anchors are absent here | Governance/System-like views expose selected transitions only | `partial_plan_coverage` | Full §4.1 fields, current anchors, journey, final invokers and aggregate |
| Protected transitions — `foundations/governed-autonomous-systems.md` “amendment/migration/succession/suspension/dissolution/enrollment” and `foundations/verifiable-bounded-agency.md` | Authorized, ordered, replayable transitions with residual disposition | Daemon/Agentgres/wallet; Governance/System lifecycle | Stale/replayed approval, concurrent conflict, crash, orphan residual, unauthorized enrollment | M1.5 parent/5b/5c | Private records/logs cover selected transition mechanisms | Governance exposes selected approvals, not dissolution/migration/recovery breadth | `partial_plan_coverage` | Explicit M1.5d, parent/child graph, dissolution/migration product/recovery proof |
| Agentgres operation truth — `components/agentgres/doctrine.md`; `components/agentgres/api-object-model.md`; `components/agentgres/projection-system-reference.md` | Per-System operation log, heads/roots, deterministic replay and read projections | Agentgres writer/projection; Systems/Provenance/Operations | Lost/duplicate/reordered suffix, projection mismatch, wrong-System write, restart | Mentioned M2–M4/M7; no complete production record | Operation/projection precedents and contract docs exist | Provenance/Operations show projections, not production writer/replay proof | `partial_plan_coverage` | Exact writer/invoker, replay/recovery runner, per-System integration and product states |
| Agentgres persistence/branches/checkpoints — `components/agentgres/artifact-ref-plane.md`; `components/agentgres/api-object-model.md`; `components/agentgres/postgres-bridge-and-readiness-contract.md` | Durable Postgres bridge, artifacts, branches/staged effects, checkpoint/proof writer | Agentgres/storage; operator restore/branch/merge journey | Corruption, branch effect before merge, invalid artifact bytes, restore mismatch | No assigned mechanism record | Partial adapters and legacy backup precedents | No complete branch/merge/checkpoint operator journey found | `missing_plan_coverage` | Stage assignment, production readiness, branch/effect and proof-export slices |
| Deployment membership/readiness — `foundations/governed-autonomous-systems.md`; `components/daemon-runtime/runtime-nodes-tee-depin.md`; `components/hypervisor/providers-and-environments.md` | Desired/observed deployment, node identity/admission/readiness, bounded membership/epochs | Daemon/HypervisorOS/provider plane; Environments/Systems/Operations | Forged/stale candidate, ready-before-catch-up, wrong role, expired lease | `m2-membership-readiness-plane` | Placement/failover/provider read models exist | Environments/Operations expose bounded topology reads | `partial_plan_coverage` | Attestation/identity/secrets/temporal owners, exact actions and journey |
| Writer fencing/reconciliation — `foundations/governed-autonomous-systems.md`; `components/agentgres/doctrine.md`; `components/agentgres/api-object-model.md`; `components/daemon-runtime/doctrine.md` | Single admitted writer per epoch; fence stale writers; reconcile lost suffix without duplicate effects | Daemon final invoker/Agentgres; Operations topology/recovery | Split brain, stale epoch, lost suffix, rejoin race, zero unguarded effectors | `m2-writer-fence-and-lost-suffix` + M2 aggregate | Placement/failover mechanisms are adjacent evidence | No full fence/rejoin/lost-suffix operator path found | `partial_plan_coverage` | Heads/roots/temporal floors/exact invokers and retained chaos proof |
| Environment discovery/startup — `components/hypervisor/providers-and-environments.md`; `components/hypervisor/byo-provider-plane.md`; `components/daemon-runtime/default-harness-profile.md` | ProjectDiscovery→candidate acceptance→recipe/resolution→StartupPlan→launch/spawn/readiness/terminal | Provider/daemon/harness; Projects/Environments/Sessions | Missing predecessor, failed spawn, port collision, fabricated readiness, cleanup after failure | M2 route/restore record only | Generic recipe/resolution, spawn and port precedents exist | Projects/Environments/Sessions expose only portions of the chain | `missing_plan_coverage` | Complete predecessor contracts, stage owner, product/recovery/cleanup exit |
| Backup/restore/route/cleanup — `components/hypervisor/providers-and-environments.md`; `components/agentgres/artifact-ref-plane.md`; `components/storage-backends/doctrine.md`; `components/daemon-runtime/platform-operability.md` | Content-bound backups/artifacts, verified restore, route activation and persistent cleanup obligations | Provider/Agentgres/storage; Environments/Operations | Corrupt bytes, stale route, partial activation, live-ref deletion, failed rollback | `m2-route-restore-activation-cleanup` | Legacy backup/restore and provider adapters exist | Environments/Operations do not cover every corrupt/rollback/cleanup state | `partial_plan_coverage` | Exact `Hypervisor*` owners/contracts, artifact verification and operator states |
| Goal/harness/tool resolution — `components/daemon-runtime/default-harness-profile.md`; `components/connectors-tools/doctrine.md`; `components/connectors-tools/contracts.md`; `../decisions/0017-goal-pursuit-workflow-skill-and-harness-taxonomy.md` | GoalRunProfile/WorkflowTemplate/skills/grounding/harness/tools resolve before execution | Daemon registries/Authority Gateway; Work/Sessions/Automations/Developer Workspace | Unknown/incompatible dependency, MCP bypass, stale resolution, direct-path regression | `m3-pursuit-definition-resolution` | GoalRun precursor, harness registry and Rust Step/Module boundaries exist | Sessions/Automations/Workbench expose fragments, not complete resolution states | `partial_plan_coverage` | Exact GoalRun/Kernel/context/runtime truth, MCP normalization, UX states |
| Context/session/work/result lifecycle — `components/daemon-runtime/doctrine.md`; `components/daemon-runtime/api.md`; `components/daemon-runtime/events-receipts-delivery-bundles.md`; `foundations/common-objects-and-envelopes.md` | Context lease/handoff, Session/WorkRun/invocation/result, cancel/archive/replay and retained negatives | Daemon/Agentgres; Work/Sessions/Automations/Provenance | Stale context, duplicate invocation/effect, cancel race, archive loss, replay divergence | Existing M3 lifecycle/direct-path records | Owner-specific lifecycle code exists | Timeline/Sessions/Automations expose selected lifecycle reads | `partial_plan_coverage` | Shared truth record, owner integrations, final invokers, complete journey/recovery exit |
| Platform operation decisions — `components/daemon-runtime/platform-operability.md` | Per-operation plane/temporal inputs, SLI/SLO, capacity/backpressure, incident/recovery and mixed-version behavior | Daemon observers/controllers; Operations/Incidents | False healthy state, stale temporal input, telemetry leak, recovery/no-recovery distinction | Broad M9/M10 prose only | Fault schema and scattered readiness projections exist | Operations/Incidents lack a complete controller/recovery journey | `missing_plan_coverage` | Assigned mechanism record, privacy-safe telemetry, controller and operator proof |
| Measured/private substrate — `components/daemon-runtime/hypervisoros.md`; `components/daemon-runtime/private-workspace-ctee.md`; `components/daemon-runtime/task-capsule-protocol.md`; `components/daemon-runtime/runtime-nodes-tee-depin.md` | Image/boot/update measurement, attestation/custody, task capsule, leases/re-attestation | HypervisorOS/cTEE/runtime node; Environments/Operations | Forged measurement, rollback image, custody escape, expired lease/capsule replay | Mentioned M2/M9/M10 only | Contract and generic startup precedents exist | No complete measured-substrate operator journey found | `missing_plan_coverage` | Stage assignment, mechanism/final invokers, release integration and product/operator journey |

#### Product, authority, semantic, learning, and supply obligations

| Target and exact owner location | Required contract/behavior | Runtime/application owner and journey | Required proof | Stage/private slice | Code evidence | UI observation | Classification | Missing plan material |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Room/System graph — `domains/ioi-ai/collaborative-outcome-pattern.md`; `domains/ioi-ai/control-plane.md`; `foundations/governed-autonomous-systems.md`; `foundations/common-objects-and-envelopes.md` | One reusable OutcomeRoom package, one System per durable room, admitted graph children and export | Daemon/Agentgres; Goal Space/Work/Rooms/Systems/Governance/Provenance | Direct-write refusal, wrong-System child, replay, acceptance/verdict and export filtering | `m4-outcome-room-system-spine` | Hosted room/frontier/claim precedents exist | Missions exposes a read-oriented compatibility projection | `partial_plan_coverage` | Exact graph/room families, decomposition, receipts/replay, product/recovery states |
| Participant/frontier/result lifecycle — `domains/ioi-ai/collaborative-outcome-pattern.md`; `domains/ioi-ai/control-plane.md`; `domains/marketplace-neutrality.md` | Pairing, participation leases, offers/frontier, claims/attempts/findings/challenges/results, allocation/acceptance | Hosted room runtime; Work/Rooms/Governance/Evaluations | Expiry/replay/reassignment, attribution≠acceptance, challenge blocks settlement, portable exit | M5 five-record set | Strong hosted participant/frontier precedents exist | Missions is read-only for this audit and lacks the full journey | `partial_plan_coverage` | Identity/gateway owner crossing, allocation/economics, acceptance/dispute and per-surface journey |
| P0 readiness — `ioi-target-end-state-master-implementation-guide.md` M5/P0; `components/daemon-runtime/default-harness-profile.md`; `components/connectors-tools/doctrine.md`; `domains/ioi-ai/collaborative-outcome-pattern.md`; `domains/ioi-ai/control-plane.md` | Verified M3–M5, direct-path preservation and controlled-boundary verifier before product pull | Private verifier; no product authority | Literal child exits, direct-path differential, no uncontrolled final invoker | `m5-p0-readiness-verifier` | Record exists; this checkout cannot validate its target artifacts | UI cannot prove P0 readiness | `partial_plan_coverage` | Full §4.1 fields/current provenance and machine-closed child/evidence graph |
| Product-surface compiler/topology — `components/hypervisor/core-clients-surfaces.md`; `../decisions/0013-hypervisor-core-clients-surfaces-and-adapters.md`; `../decisions/0016-hypervisor-systems-work-and-application-taxonomy.md` | Policy-filtered canonical registrations; five workspaces; owner/substrate apps; one Open Application; aliases | Daemon compiler + Hypervisor shell; Home/Systems/Projects/Applications/Work | Unknown/hard-coded membership, tenant/context leakage, alias/deep-link and unavailable-state proof | One M6 umbrella + specialist plan | Registry/catalog and fourteen surface handlers exist | Native/ported routes are broad; Systems/Work are absent from the canonical root spine | `partial_plan_coverage` | Exact families/compiler/source migration, Systems/Work, normalized membership and complete state proof |
| Owner-application operational depth — `components/hypervisor/core-clients-surfaces.md`; each owner named in its application-family row in that file | Every admitted owner app has contracts, actions, backend truth, routes and honest states | Twelve owner apps, two substrate apps, conditional Embodied Systems | Empty/denied/degraded/recovery, action/receipt, accessibility, narrow/embed, route migration | No per-owner M6 children | Atlas reports 390 implemented and 173 unimplemented reference controls; 39 seed registrations exist | Shell reachability is broad but operational depth varies and is often inert | `missing_plan_coverage` | One child per admitted owner, depth generator and implement/defer/merge/reject ledger |
| Production UI truth/source — `components/hypervisor/core-clients-surfaces.md`; `components/daemon-runtime/api.md`; `components/daemon-runtime/doctrine.md` | One truthful source/serve path; production routes fail closed; references isolated | Hypervisor launcher/adapter/shell | Daemon outage cannot yield fixture truth; compatibility and captured-bundle retirement | M6/WP-UX/WP-RUNTIME prose only | AGENTS/README/Vite contradict active 4173 harvested serve path; 55 unique fixture endpoints are mirrored in two trees | Rendered shell does not reveal whether returned data is daemon truth or fixture fallback | `conflicting_plan_coverage` | Explicit source convergence/fallback retirement slices and launcher/document alignment |
| Consequential UI actions — `foundations/verifiable-bounded-agency.md`; `components/wallet-network/doctrine.md`; `components/wallet-network/api-authority-scopes.md`; `components/daemon-runtime/api.md`; `components/hypervisor/core-clients-surfaces.md` | Action descriptor→sealed intent/grant→final-invoker revalidation→durable receipt | Daemon/owner services; every mutating surface | Deny/revoke/stale/duplicate/no-receipt and zero client-derived authority | No route-complete M6 slice | Six extracted surfaces exist; four contain bounded actions while flat handlers remain | Clickable/mutating controls do not uniformly expose authority and receipt states | `partial_plan_coverage` | Complete action census, one runtime migration, receipt presentation and bypass proof |
| Ontology definitions/actions — `foundations/domain-ontologies-and-data-recipes.md` | Versioned ontologies/overlays/crosswalks/interfaces/actions/oracle policy | Ontology/Studio/ODK/daemon/Agentgres | Version conflict, uncertain mapping, oracle dispute, denied final invoker | One M7 umbrella | Operational metadata/type-upsert handlers exist | Ontology/ODK provide browse and selected editing projections | `partial_plan_coverage` | Immutable/version/migration/action decomposition, final invokers and full owner journey |
| Data recipes/transformations/provenance — `foundations/domain-ontologies-and-data-recipes.md`; `components/agentgres/doctrine.md`; `components/daemon-runtime/events-receipts-delivery-bundles.md` | Source→recipe→mapping→TransformationRun→assertion/provenance/replay | Data/Pipeline/Provenance | Stale recipe, contradiction/dispute, restart/replay, egress denial | Same M7 umbrella | One bounded Pipeline ladder and source-declaration handler exist | Data/Pipeline/Provenance do not expose the complete transform/replay/recovery journey | `partial_plan_coverage` | Full source/sync/transform/test/output contracts, Agentgres truth and recovery/product proof |
| Information-flow/declassification — `foundations/security-privacy-policy-invariants.md` | Labels propagate across every PEP; declassification/refusal/disclosure receipts before egress/effect | Daemon, connector/MCP/model/browser/memory/room paths; denied/degraded UI | Missing/stripped label, implicit release, client-only check, stale decision | No mechanism owner | Registered label/declassification schemas exist | No estate-wide denial/declassification/degraded-state journey found | `missing_plan_coverage` | Shared evaluator/propagation kernel, enumerated PEP suite, stage/aggregate and product states |
| Receipt integrity/offline proof — `components/daemon-runtime/events-receipts-delivery-bundles.md`; `components/wallet-network/doctrine.md`; `components/agentgres/doctrine.md`; `components/storage-backends/doctrine.md` | JCS hashing, accumulator, signed checkpoints, inclusion/consistency proofs, key discovery/export | Daemon/Agentgres/wallet/storage; Provenance/CLI offline verifier | Tamper/omission/split view/stale key/producer independence | WP-PROOF and M9 prose only | Registered receipt/checkpoint/proof schemas and fixtures exist | Timeline/Provenance do not demonstrate independent offline verification | `missing_plan_coverage` | Emitters/writer/export/CLI/key discovery/transparency defenses and literal aggregate |
| Identity/access/metering — `components/hypervisor/identity-access-and-metering.md`; `components/wallet-network/doctrine.md`; `components/wallet-network/api-authority-scopes.md` | Local identity distinct from effect authority; pairing/session/recovery/metering scoped and revocable | Identity provider/wallet/daemon; login/pairing/review/account journeys | Origin/principal mismatch, expiry/replay/revoke, recovery abuse, meter/effect mismatch | M5 pairing + M9 managed overlay partial | Principal resolution and SSO/OIDC/token/secrets adapters exist | Login/settings/account routes expose fragments, not the complete authority/recovery journey | `partial_plan_coverage` | Complete owner crossing, product states, financial authority/metering and portable verification |
| Wallet grants/receipts/exchange risk — `components/wallet-network/doctrine.md`; `components/wallet-network/api-authority-scopes.md`; `components/wallet-network/product-exchange-risk.md` | Portable grants/sealed intents, scopes/limits/revocation, review ceremony, final-invoker equality and receipts | Wallet/daemon; review/sign/revoke/recover/verify | Wrong invoker/scope, replay/revoke/risk limit, offline verification and effect-receipt match | M9 selected/managed records | v1/v2 substrate and selected guarded routes exist | No complete review/sign/revoke/recover/offline-verify path found | `partial_plan_coverage` | Portable/v3 verifier, account/factor/recovery breadth, estate-wide invoker and receipt proof |
| Institutional learning/custody — `foundations/institutional-learning-boundary.md`; `components/daemon-runtime/private-workspace-ctee.md`; `components/daemon-runtime/portable-memory-vault.md`; `components/storage-backends/doctrine.md` | Rights compiler, source/route scope, custody, eligibility, egress, export/import/provider exit | Learning runtime/cTEE; Foundry/Evaluations/Improvement/Provenance | Unauthorized source/route/use, custody/egress leak, scope inheritance, provider substitution/exit | `m8-learning-boundary-provider-exit` | Adjacent route/memory/policy precedents exist | Foundry/Evaluations/Improvement expose fragments, not a custody/provider-exit journey | `partial_plan_coverage` | cTEE/vault/MemorySpace/storage, real enforcement, complete inheritance and portability runner |
| Bounded improvement — `foundations/bounded-recursive-improvement.md`; `components/daemon-runtime/improvement-governance-gates.md`; `../decisions/0018-bounded-recursive-improvement-campaign-taxonomy.md` | Direct proposal plus optional bounded campaign with frozen epoch/exposure/judgment/owner promotion | Improvement/Foundry/Evaluations/Governance | Self-promotion, mutable epoch, evaluator leakage, canary/rollback/recall and stop rule | M8 direct record + specialist campaign plan | Narrow proposal/simulation handlers exist | Change/Improvement views do not expose the complete campaign/promotion loop | `partial_plan_coverage` | Complete campaign runtime/objects, real evaluation, metrics/product states and owner promotion |
| Model/provider rights/supply — `components/model-router/doctrine.md`; `components/model-router/api-byok-mounting.md`; `foundations/institutional-learning-boundary.md`; `foundations/economic-flywheel-and-pricing-boundaries.md` | BYOK/BYOA/local/open routes, lawful automation/downstream/learning rights, fallback and supplier reconciliation | Model router/Foundry; Models/Developer Console | Credential leak, unauthorized use, silent substitution, provider exit and invoice mismatch | WP-SUPPLY prose only | Model-route/admin precedents exist | Model Catalog/Foundry cards do not expose rights/substitution/reconciliation proof | `missing_plan_coverage` | Mechanism record, credential principal, rights evaluator, model-swap/fallback and supplier proof |
| Storage profiles/repair — `components/storage-backends/doctrine.md`; `components/storage-backends/filecoin-cas.md` | Local/object/CAS profiles, retention/holds, repair/availability, verified restore and cleanup | Storage/Agentgres/provider; Environments/Operations/Provenance | Corruption/loss, retention violation, unverified restore, cleanup of live reference | Incidentally M2/M9 | Local/CAS/Filecoin/backup precedents exist | Environments/Operations/Provenance lack the complete repair/hold/restore journey | `partial_plan_coverage` | S3/object breadth, repair/controller, incident/operator and portability exit |

#### Distribution, embodied, federation, economics, and ecosystem obligations

| Target and exact owner location | Required contract/behavior | Runtime/application owner and journey | Required proof | Stage/private slice | Code evidence | UI observation | Classification | Missing plan material |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Same-System continuity — `foundations/governed-autonomous-systems.md`; `components/daemon-runtime/doctrine.md`; `components/daemon-runtime/runtime-nodes-tee-depin.md`; `components/agentgres/doctrine.md`; `components/agentgres/postgres-bridge-and-readiness-contract.md` | Two failure domains, admitted membership, promotion/fence/rejoin, temporal/key floors, no duplicate effects | Daemon/Agentgres; Systems/Environments/Operations/Provenance | Promotion/fence/rejoin chaos, lost suffix, split brain, RPO/RTO and degraded recovery | One broad M10 record | Placement/failover substrate exists | No complete topology/degraded/recovery journey found | `partial_plan_coverage` | Attestation/floors/keys/checkpoints, exact invokers, chaos aggregate and operator states |
| Useful distribution — `foundations/governed-autonomous-systems.md`; `components/daemon-runtime/doctrine.md`; `components/agentgres/doctrine.md`; `../decisions/0015-bounded-distributed-autonomous-systems-and-network-enrollment.md` | RuntimeAssignment/lease/watermark, partition/reassignment, useful work without duplicate effect | Scheduler/daemon/Agentgres; Work/Systems/Operations | Partition/stale lease/reassignment, duplicate effect, restart/reconcile | `m11-useful-same-system-distribution` | Selected placement/workflow controls exist | Work/Systems/Operations lack the complete partition/reassignment path | `partial_plan_coverage` | Exact assignments/watermarks, coordination/final invokers, product/metric proof |
| Non-live embodied graph — `components/daemon-runtime/embodied-runtime.md`; `foundations/physical-action-safety.md`; `components/hypervisor/core-clients-surfaces.md`; `foundations/bounded-recursive-improvement.md` | Native profile/graph/streams/supervisor/controllers, transactional activation, fleet/spacetime leases, safety case through non-live proof | Embodied runtime/Foundry; Embodied Systems/Operations | Compiler/simulation/SIL/HIL/shadow, stale lease, missing supervisor, no actuator invocation | M11 embodied + aggregate records | Limited schema/intent precedents exist | No complete Embodied Systems/Foundry non-live journey was observed | `partial_plan_coverage` | Canon-name alignment, mechanisms, safety/promotion journey and exact non-live exits |
| Live physical promotion — `components/daemon-runtime/embodied-runtime.md`; `foundations/physical-action-safety.md`; `foundations/ecosystem-assurance-certification-liability.md` | Native final invoker, physical receipts, certification and E1+ staged promotion | Local supervisor/controllers; operator emergency/recovery journey | Hardware-independent verifier, stop/fence/fail-safe, incident/rollback/recall | Explicitly outside M11; no owner | No sufficient implementation evidence found | No live control journey observed; no live claim made | `missing_plan_coverage`, `gated` | Conditional later stage/activation, live mechanism/contracts and assurance proof |
| AIIP channel/envelope/profile — `foundations/aiip.md` protocol sections | Bilateral channels/envelopes, identity/keys/revocation, ordering/retry and selected profile | AIIP adapters/daemon; Developer Console/Provenance | Replay/reorder/stale key, duplicate packet, disconnect/reconciliation | `m12-aiip-channel-envelope-profile` | Target contracts and hosted precedents only | No sovereign channel/operator journey observed | `partial_plan_coverage` | Exact registered names, key/receipt/IFC owners, third-party conformance and operator states |
| AIIP discovery/terms/semantic/action negotiation — `foundations/aiip.md`; `foundations/domain-ontologies-and-data-recipes.md`; `foundations/verifiable-bounded-agency.md`; `components/connectors-tools/contracts.md` | Exact-root terms, counter/decline, semantic mapping, action negotiation, HTTP/RPC/MCP/directory/settlement bindings | AIIP/ontology/connectors; Goal Space/Rooms/Governance/Ontology/Console | Mismatch/safe decline, mapping dispute, restricted disclosure, unsupported adapter | `m12-terms-discovery-semantic-negotiation` | No sovereign interop proof found | No discovery/terms/counter/decline product journey observed | `partial_plan_coverage` | Full adapter breadth, IFC/dispute/receipt owners and product journey |
| Federated admission/portable exit — `foundations/aiip.md`; `foundations/governed-autonomous-systems.md`; `components/agentgres/doctrine.md`; `components/wallet-network/doctrine.md`; `components/storage-backends/doctrine.md` | Admit remote terms into bounded local truth; disconnect/exit/export/import without authority leakage | Daemon/Agentgres/wallet; Rooms/Governance/Provenance | Wrong root/System, stale authority, disconnect/retry, disputed exit and custody | M12 admission + aggregate records | Hosted-only precedents exist | No sovereign admission/disconnect/portable-exit journey observed | `partial_plan_coverage`, `gated` | Cross-cut bindings, portable verifier, full states and retained M13 nonclaim |
| Two-sovereign trial/surplus — `foundations/aiip.md`; `foundations/economic-flywheel-and-pricing-boundaries.md`; `foundations/mixture-of-workers.md`; `domains/aiagent/digital-worker-ontology.md` | Independently administered systems/provider/verifier, preregistered baselines, repeated positive surplus and safe decline | Two deployments; invited/open Goal Space, external-worker and evidence-export journeys | Independence, subsidy disclosure, baseline/valuation freeze, verifier conflict, safe local continuation | Two M13 records | No proof artifact found | UI is not admissible proof; no proof claim is made | `partial_plan_coverage`, `gated` | Aggregate, evidence acquisition/custody, complete product/dispute/exit and frozen metrics |
| Worker ontology/training/marketplace — `foundations/mixture-of-workers.md`; `foundations/worker-training-lifecycle.md`; `domains/aiagent/digital-worker-ontology.md`; `domains/aiagent/vertical-ontology-packs.md`; `domains/aiagent/integration-surface-taxonomy.md`; `domains/aiagent/managed-worker-instance-lifecycle.md`; `domains/aiagent/managed-agent-console-contract.md`; `domains/aiagent/worker-endpoints.md`; `domains/aiagent/worker-marketplace.md` | Worker identity/capabilities/training, managed instances/consoles/integrations, registry/hiring/fulfillment | Worker runtime/aiagent; Marketplace/Console/Rooms | Fake capability, unsafe delegation, rights/custody, acceptance/dispute/portable exit | Incidental M5/M13/M14 only | Worker/provider precedents exist | Marketplace/Console are browse/projection-heavy and lack the end-to-end lifecycle | `missing_plan_coverage` | End-to-end mechanism/product/supply/settlement records and stage assignment |
| Service order/marketplace — `domains/sas/service-endpoints.md`; `domains/sas/service-marketplace.md` | Service listing/order/delivery/evidence/acceptance/dispute/settlement and exit | sas service runtime; Packages/Marketplace/Governance/Provenance | Non-delivery, unsafe/invalid evidence, disputed acceptance, payment/exit | M14 proof criteria only | Listing/projection precedents exist | No complete service order/delivery/acceptance/dispute journey observed | `missing_plan_coverage` | Exact service owner/families, implementation journey and devnet/negative exit |
| Billing/Work Credits/reconciliation — `foundations/economic-flywheel-and-pricing-boundaries.md`; `components/hypervisor/identity-access-and-metering.md`; `components/wallet-network/doctrine.md` | Quote/hold/usage/debit/adjustment, allowances/Work Credits, supplier statements and reconciliation | Billing/ledger/wallet; account/project/service product APIs | Double charge, stale quote, unmetered effect, refund/adjustment and supplier mismatch | M13/M14 criteria only | Billing bundle schemas exist | Settings/billing views do not show complete effect/reconciliation proof | `missing_plan_coverage` | Persistence/authority/effect paths, stage owner, APIs and reconciliation proof |
| Dispute/adjudication/remedy — `foundations/economic-flywheel-and-pricing-boundaries.md`; `components/wallet-network/doctrine.md`; `foundations/aiip.md`; `domains/marketplace-neutrality.md`; `domains/sas/service-marketplace.md`; `foundations/ecosystem-assurance-certification-liability.md` | Evidence/appeal, escrow/bond, adjudication/remedy, cross-rail receipts | Governance/wallet/settlement; dispute/operator journey | Self-adjudication, evidence loss, premature settlement, appeal/remedy failure | M12–M14 references only | Dispute bundle schemas exist | Governance/listing views do not expose full appeal/remedy/finality states | `missing_plan_coverage` | One kernel owner, persistence/finality, product states and cross-rail binding |
| Marketplace neutrality/contribution — `domains/marketplace-neutrality.md` | Neutral routing/allocation, transparent contribution accounting, challenge/dispute/settlement | Marketplace/worker/service routers; contributor inspect/challenge/exit | Preferential routing, attribution theft, opaque allocation, disputed settlement | Incidental M5/M13/M14 | Hosted attribution and routing precedents exist | Marketplace listings do not demonstrate neutral allocation/accounting | `partial_plan_coverage` | Mechanism owner, allocation/accounting contracts and portable evidence exit |
| Ecosystem assurance/liability — `foundations/ecosystem-assurance-certification-liability.md` | Conformance/certification, jurisdiction packs, quarantine, liability/insurance/claims and commercial audit | Assurance/governance; operator/customer/auditor journeys | Self-certification, jurisdiction bypass, revoked cert, uninsured/unrouted claim | Later gates only | Conformance documents exist; no general production mechanism found | No complete certification/liability/claim journey observed | `missing_plan_coverage` | Stage/activation, assurance objects, authority/product journeys and claim-safe exits |
| Connected/secured services — `ioi-target-end-state-master-implementation-guide.md` M14; `domains/sas/service-endpoints.md`; `domains/sas/service-marketplace.md`; `domains/aiagent/worker-endpoints.md`; `foundations/economic-flywheel-and-pricing-boundaries.md`; `foundations/ecosystem-assurance-certification-liability.md` | Explicit enrollment, selected services/postures, demand/security economics, suspension/dispute/exit | Network/service operators; enrollment/payment/Governance/Provenance | Implicit enrollment, insufficient supply/security, attack budget, dispute and safe exit | Three M14 records | Contract substrate exists; no service proof found | No connected-service enrollment/operator journey observed | `partial_plan_coverage`, `gated` | Exact service selection/owners, aggregate, frozen sustained thresholds and operator proof |
| L1/no-L1 decision — `foundations/ioi-l1-mainnet.md`; `foundations/ioi-l1-contract-interfaces.md` | Valid default no-L1 branch; optional selected public commitments only after demand/security/legal gates | Network contracts/operator UI only if selected | Threshold persistence, safety margin, rollback/stop, legal/assurance and explicit no-L1 proof | `m14-l1-authorization-decision`; no aggregate | Planning/schema targets only; no selected implementation proof | No L1 operator journey observed | `partial_plan_coverage`, `gated` | Complete M14 aggregate and, only if selected, bounded devnet/contracts/operator evidence |
| SDK/CLI/ADK/ODK/public builder path — `_meta/start-here.md`; `components/hypervisor/core-clients-surfaces.md`; `components/daemon-runtime/api.md`; `components/connectors-tools/contracts.md`; `foundations/domain-ontologies-and-data-recipes.md` | Supported App/Web/CLI/headless/SDK/toolkit journeys with versioned maturity labels | CLI/SDK/Developer Workspace/Console/Studio/Ontology | Runnable examples, parity/compatibility, stale-doc rejection, no client authority | WP-DOCS/M6/M9 prose | Several tools and APIs exist | Developer Workspace/Console/Studio/Ontology do not form one runnable parity journey | `missing_plan_coverage` | Assigned stage, interface matrix, runnable conformance and release documentation gate |
| Decentralized cloud/exchange/trade profiles — `domains/decentralized/README.md`; `domains/decentralized/cloud.md`; `domains/decentralized/exchange.md`; `domains/decentralized/trade.md` | Conditional provider/exchange/trade products under wallet, identity, route, economic and risk controls | Provider/router/wallet; conditional product journeys | Enrollment/rights/risk/settlement/exit and honest unavailable profile | No named private slices | Adjacent provider/wallet precedents only | No selected decentralized product journey observed | `missing_plan_coverage`, `gated` | Canon-pull decision, stage/owner, contracts, nonclaims and demand-gated exits |

## M0–M14 plan audit

The table keeps sequencer demand, canon specification, private-plan coverage,
code evidence, UI observation, and audit inference distinct. Bounded evidence
does not replace a retained literal stage-exit log.

| Stage | Master demand | Canon specification | Private plan/records | Code evidence | UI observation | Missing plan material / audit inference |
| --- | --- | --- | --- | --- | --- | --- |
| M0 | One program truth system, claim lock, inventories, gates and retained literal exits | Owner map, contract registry and accepted-ADR boundary define the inputs; workflow evidence is non-product evidence | Two records; private projection/checker and runtime-trust audit | Literal M0 wrapper exists; required generator/check scripts are absent in this checkout | Not applicable to status or proof | Full M0.1–M0.9 set, §4.1 validation, owner/canon digest, closed route/PEP/final-invoker/PG census and private-workflow classification; `partial_plan_coverage` |
| M1 | Package → genesis → sequence zero → initialize/activate → protected transitions | Governed-System and common-envelope owners specify packages, profiles, genesis, lifecycle and protected transition invariants | Seven records | Registered package/genesis/profile schemas and compiler/transition precedents | Governance/System-like projections cover selected lifecycle views only | M1.5d, closed parent/child graph, selected-profile aggregate, journey and recovery states; `partial_plan_coverage` |
| M2 | Membership/readiness, catch-up/root, writer epoch/fence, recovery, routes/backup/restore/cleanup | System, daemon, Agentgres, provider/environment and storage owners specify admission, persistence and recovery | Four records | Placement/failover, environment, backup and restore precursors | Environments/Operations lack the complete admitted topology/fence/recovery journey | Attestation/identity/secrets/custody/temporal floors, heads/replay, exact invokers, canonical names and product states; `partial_plan_coverage` |
| M3 | Immutable pursuit/workflow/skill/harness/tool resolution, generic result, shared lifecycle and direct path | Daemon, harness, connector/tool and envelope owners specify resolution and lifecycle boundaries | Three records | GoalRun precursor, harness registry and Rust Step/Module boundary exist | Sessions/Automations/timeline expose selected reads, not the full Work journey | Goal Kernel/Context/Session/WorkRun truth, MCP normalization, owner integrations and product/recovery journey; `partial_plan_coverage` |
| M4 | Reusable OutcomeRoom package as one bounded System with admitted child graph/export | IOI.AI room/control-plane and governed-System owners define room graph, admission and result semantics | One umbrella record | Hosted room/frontier precedents exist | Missions is read-oriented and compatibility-labeled | Decompose obligations; exact graph/room/receipt/Agentgres owners; acceptance/verdict and Goal Space/Work/Governance/Provenance states; `partial_plan_coverage` |
| M5 | Pairing, participation, frontier/result lifecycle, portable exit and P0 verifier | IOI.AI, identity/access, neutrality, wallet and bounded-agency owners define participation and authority crossings | Five records | Hosted-plane participant/frontier precedents exist | Missions exposes a bounded projection, not a complete participant journey | Identity/gateway crossings, allocation/spend/reassignment, acceptance/dispute, exact families and per-surface states; `partial_plan_coverage` |
| M6 | One policy-filtered compiler, five workspaces, owner/substrate apps, packages/extensions, aliases and UX proof | Hypervisor surface owner and ADRs 0013/0016 define normalized topology and application ownership | One aggregate record plus taxonomy specialist plan | Fourteen-surface registry, extracted handlers and broad route estate exist | Applications/native/ported shells are broad; Systems/Work and full narrow/a11y journeys are absent | Compiler/source convergence, exact families, every app journey/state/action, aliases, responsive/a11y and Embodied/Packages disposition; `partial_plan_coverage` |
| M7 | Immutable semantics, mappings, transformations, provenance, action contracts and oracle/evidence | Ontology/data-recipe, Agentgres, receipt and bounded-agency owners define versioned semantics and consequence boundaries | One umbrella record | ODK, mapping, pipeline and selected bounded-action precedents exist | Ontology/Data/Studio/Provenance cover only fragments | Decomposition, immutable definition/run split, Agentgres/replay, final invokers, IFC/disputes and complete product journey; `partial_plan_coverage` |
| M8 | Institutional-learning/provider-exit boundary plus bounded direct/campaign improvement | Learning, improvement, model-router, storage and measured-substrate owners define rights, custody and owner promotion | Two records plus specialist campaign plan | Direct proposal/simulation and adjacent memory/data/policy precedents exist | Foundry/Evaluations/Improvement do not expose the complete job/evaluation/promotion loop | BYOK/rights, cTEE/vault/storage, scope inheritance, frozen metrics, product journeys and aggregate exit; `partial_plan_coverage` |
| M9 | Compact/advanced parity, sovereign-local terminal journey, optional managed authority, Gateway equivalence and offline proof | System, daemon, wallet, storage, identity and assurance owners define selected-profile behavior | Four records | Partial authority/runtime/release ingredients exist; no end-to-end SLC runner | Login/account/review/runtime fragments do not cover the 21-state journey | M9.1 owner, release supply chain, cohorts/thresholds, Gateway correction, full aggregate and publication gate; `partial_plan_coverage` |
| M10 | One logical System across two failure domains, controlled promotion/fencing and no dual effects | System, daemon, Agentgres and measured-node owners define membership, epochs, roots and continuity | One record | Placement/failover substrate exists | Systems/Environments/Operations do not expose complete degraded/recovery/RPO/RTO states | Attestation/floors/keys/checkpoints, exact invokers, chaos runner, operator journey and aggregate; `partial_plan_coverage` |
| M11 | Useful same-System work plus non-live native embodied graph proof; safety remains local | Distribution ADR, embodied runtime and physical-safety owners define leases, native graph and non-live promotion boundary | Three records | Selected placement/workflow and limited schema/intent precedents exist | No complete Embodied Systems / Foundry SIL-HIL-shadow journey | Canon-name reconciliation, mechanism owners, receipt/certification bindings, non-live product proof; live promotion remains separate; `partial_plan_coverage` |
| M12 | AIIP channel/profile, exact-root terms, discovery/semantic/action negotiation, admission and portable exit | AIIP, semantic, authority, Agentgres, IFC, connector and storage owners define federation boundaries | Four records | Target contracts and hosted precedents only | No sovereign federation/operator journey is present | IFC/disclosure receipts, key/revocation, Agentgres, dispute/settlement, adapters and complete pulled-surface journey; `partial_plan_coverage`, federation `gated` |
| M13 | Pre-registered independent trial, repeated surplus, external worker, safe decline/local continuation | AIIP, worker and economic owners define independence, baselines, worker lifecycle and surplus semantics | Two records | No two-sovereign proof artifact was found | No UI can establish independent administration or surplus proof | Aggregate, evidence acquisition/custody, frozen metrics, verifier conflict, dispute/exit and portable export; `partial_plan_coverage`, proof `gated` |
| M14 | Selected service devnet, sustained demand/security/economics and explicit L1/no-L1 decision | sas/aiagent, economics, assurance and L1 owners define service, enrollment, settlement and optional commitment boundaries | Three records | Enrollment/billing/dispute schema substrate only | No connected-service devnet or L1 operator proof was observed | Exact families/owners, full product journey, sustained thresholds, aggregate, assurance/legal/commercial crossings; `partial_plan_coverage`, L1 `gated` |

## Hypervisor product and shell audit

### Canonical target

The current target shell is:

```text
+ New: System | Session | Goal | Project | Automation
Core: Home | Systems | Projects | Applications | Work
Shell placement: Automations
One slot: Open Application

Owner applications:
  Studio | Automations | Ontology | Data | Governance | Provenance
  Evaluations | Improvement | Foundry | Packages
  Developer Workspace | Developer Console

Substrate applications:
  Environments | Operations

Conditional:
  Embodied Systems (planned registration until its contracts pull it)
```

Systems and Work are policy-filtered core workspaces, not truth owners.
Automations is an owner application with shell placement, not a sixth core
workspace registration. Workbench is a compatibility label for Developer
Workspace. Marketplace is a mode over Packages, not package/install truth.
Mission may be presentation over exactly one GoalRun or OutcomeRoom, not a
generic canonical object.

### Current reachable estate

The current root shell still visibly presents `New Session`, `Home`,
`Projects`, `Automations`, `Insights`, and `Sessions`. A native
`/__ioi/applications` route exists, but Systems and Work are not the permanent
root-spine destinations described by current canon. `Missions` remains a
prominent compatibility surface; `Provenance` is served at the legacy
`/__ioi/work-ledger` route; and `Workbench` remains the product label.

Current route/surface evidence is best read in four layers:

| Layer | Current examples | Honest interpretation |
| --- | --- | --- |
| Transitional shell/core views | `/`, `/__ioi/home`, `/__ioi/sessions`, `/__ioi/applications`, `/__ioi/workbench`, `/__ioi/automations` | Useful product projections, but not the canonical five-workspace shell or typed Work/System migration. |
| Native owner/substrate views | `/__ioi/agent-studio`, `/__ioi/connections`, `/__ioi/foundry`, `/__ioi/governance`, `/__ioi/evaluations`, `/__ioi/odk`, `/__ioi/environments`, `/__ioi/operations`, `/__ioi/domain-apps`, `/__ioi/marketplace`, `/__ioi/work-ledger` | Broad surface reachability. Many views honestly state their missing mutation/execution planes. |
| Registered ported applications | Missions, Pipeline Builder, Data Connection, Ontology Manager, Object Explorer, Approvals, Issues, Model Catalog, Marketplace, Solution Designer, Machinery, Automate, Upgrade Assistant, AIP Evals | UI atlas/registry depth ranges from browse to selected governed actions. Pixel parity and route reachability grant no product membership or owner truth. |
| Executable parity/reference estate | 39 registered `__apps` seed entries: 13 `daemon_wired`, 3 `substrate_bound`, and 23 `reference_capture` | The 16 bound entries are still bounded by their declared workflow. The 23 captures are interaction/design evidence only, not implemented app workflows. |
| Unregistered dormant lanes | Workspaces, Widgets, and Lineage UX seeds plus the archived 45-application capability crosswalk | Useful breadth evidence that requires implement/defer/merge/reject disposition. Dormant or archived evidence grants no product membership. |

The current route families resolve to the following product map. This is a
source and HTTP inventory, not a claim that every nested action is operational:

| Current family | Audit class | Representative routes | Target disposition gap |
| --- | --- | --- | --- |
| Shell/core | `partially_operable`; Systems/Work are `canon_target_not_present` | `/`, `/ai`, `/ai#new-session`, `/projects`, `/projects/:projectId`, `/details/:environmentId`, `/__ioi/home`, `/__ioi/sessions`, `/__ioi/applications`, `/__ioi/search` | Replace duplicated captured/augmentation navigation with the canonical five workspaces and typed `+ New`; preserve loading/empty/denied/unavailable/degraded/deep-link behavior while source ownership converges. No live `/workspaces/:environment` page exists; Workspaces appears only in reference/dormant material. |
| Studio | `partially_operable` | `/__ioi/agent-studio`, `/__ioi/studio/designer`, `/__ioi/studio/machinery` | One owner home and complete governed design/build handoff. |
| Automations | `partially_operable` | `/__ioi/automations` plus create/detail/run/pause/resume/patch/delete and `/__ioi/automations/monitors` | Reconcile the richer native route with the registered monitor port and one canonical execution chain. |
| Ontology | `partially_operable` | `/__ioi/ontology/manager`, `/__ioi/ontology/explorer`, `/__ioi/odk` | Separate Ontology owner truth from ODK/tooling modes and complete instance/action paths. |
| Data | `partially_operable` | `/__ioi/data/sources`, `/__ioi/pipeline`, ODK data-plane routes | Complete credentials, extraction, ingestion, sync, transforms, recovery, and egress. |
| Governance | `partially_operable` | `/__ioi/governance`, `/__ioi/governance/approvals` | Unify review ceremony, authority, effect receipt, assignment, appeal, and audit export. |
| Missions/Work | Missions is `noncanonical_or_stale`; Work is `canon_target_not_present` | `/__ioi/missions`, `/__ioi/missions/incidents`; the Applications tile currently opens `/__ioi/sessions` | Retire Missions as a peer family into typed Work/Rooms; implement the canonical Work workspace and correct the route. |
| Provenance | `partially_operable`; Work Ledger label is `noncanonical_or_stale` | `/__ioi/work-ledger`, `/__ioi/lineage`, `/__ioi/vertex` | Migrate the legacy Work Ledger route and bind lineage/offline-proof views to current truth. |
| Evaluations | `partially_operable` shell with an inoperable execution path | `/__ioi/evaluations`, `/__ioi/feedback`, `/__ioi/evaluations/evalsuites` | Make Evaluations the owner home and implement EvalRun, judgment, scoring, challenge, and promotion evidence. |
| Improvement | `partially_operable` with split ownership | Agent Studio improvement sections and `/__ioi/improvement/changes` | Establish one owner route for proposal, simulate, approve, apply, canary, rollback, and recall. |
| Foundry | `partially_operable` shell with inoperable training/deployment paths | `/__ioi/foundry`, spec/run-plan routes, `/__ioi/foundry/models` | Implement model registration/training/evaluation/deployment with rights and safety evidence. |
| Packages/Marketplace | Marketplace-as-owner is `noncanonical_or_stale`; Packages is `canon_target_not_present` | `/__ioi/marketplace` plus listings/candidates/reviews/offers | Make Packages the owner and Marketplace a mode; implement admission/install/publish/hire/settle/dispute. |
| Developer Workspace | `partially_operable`; Workbench label is `noncanonical_or_stale` | `/__ioi/workbench`, `/__ioi/code`, captured workspaces | Migrate the Workbench label and make editor/repository/session context authoritative. |
| Developer Console | `partially_operable` | `/__ioi/connections` plus connector/MCP/OAuth/GitHub/Slack setup routes | Define supported integration lifecycle, credential custody, test/revoke/recover, and failure states. |
| Substrate | `partially_operable` | `/__ioi/environments`, `/__ioi/operations` | Complete provider/environment construction, readiness, incidents, spend, recovery, and portable exit. |
| Generated/support | `partially_operable`; unmatched seeds are `dormant_or_unreachable` or `inoperable_shell` | `/__ioi/domain-apps`, `/__ioi/domain-app-runtime/:id`, timeline/replay, editor-open, auth/callback routes | Classify each route as owner app, generated app, support flow, compatibility alias, or retirement target; map every consequential endpoint to an authority boundary. |

The captured product shell also contains the following source-defined page
families. They were inspected statically and through representative safe GETs;
they are not silently promoted into the canonical application taxonomy:

| Captured page family | Routes inspected | Current class and visible purpose | Dependencies, authority/failure requirements, and plan mapping |
| --- | --- | --- | --- |
| Project and creation | `/projects`, `/projects/:projectId`, project settings/secrets/prebuilds, `/create` | `partially_operable`; project selection, configuration and environment creation | Project/provider/secret/runner adapters; mutations require owner-side authority and receipts, with denied/stale/cleanup states. M2 construction + M6 Projects journey are partial. |
| Environment detail | `/details/:environmentId` with logs, service logs, tasks, task runs and code changes | `partially_operable`; operate one environment | Environment/runner/log/event/supervisor adapters; tenant isolation, token expiry, stop/delete authority, degraded stream and cleanup/recovery are required. M2/M3/M6/M9 coverage is partial. |
| Captured automations | `/automations`, webhooks, create/detail/edit, executions and execution-action detail | `partially_operable`; define and inspect captured workflows | Workflow/secret/webhook/event dependencies; sealed authority, replay/idempotence, pause/cancel/recover and receipt presentation required. M3/M6 coverage is partial and overlaps the native IOI route. |
| Personal settings | `/settings/profile`, preferences, secrets, Git authentication, personal tokens, integrations, activity and experiments | `partially_operable`; identity, preference and credential administration | User/Secret/Integration services; credential custody, revoke/rotate/recovery, origin/principal checks and honest unavailable states. M6/M9 owner journey is incomplete. |
| Organization administration | `/settings/manage-organization`, announcements, terms, members/groups/teams/service accounts, runners, environments, org secrets, agents/policies/skills/integrations/policies/login/SCIM/OIDC/billing/credit usage | `partially_operable`; managed-organization administration | Organization/identity/runner/billing/policy services; role-scoped final invokers, audit receipts, recovery, stale-role and billing-dispute states. M9 managed overlay and M14 economics are partial/gated; UI presence proves neither. |
| Authentication and onboarding | `/onboarding/ioi/*`, `/create-organization`, `/join-organization/:inviteId?`, `/login*`, `/magiclink`, `/confirm/signin`, `/account-deleted` | `partially_operable`; sign-in, invitation and guided setup | Identity/organization/integration/project services; expiry/replay/origin/recovery and no implicit authority or enrollment. M5/M6/M9 coverage is partial. |
| Integration and support callbacks | `/integrations/connect/:integrationId`, `/integrations/connected/:integrationId`, `/runner/scm-success`, `/port-denied`, `/experiments/:name`, wildcard fallthrough | `partially_operable` or `noncanonical_or_stale` by route | OAuth/SCM/runner/feature-flag dependencies; state/nonce, callback replay, denied-port and unavailable handling required. Developer Console/M6 and identity/M9 coverage is partial. |

The root Vite source separately exposes `/workspace-preview`; it is
`noncanonical_or_stale` as a served-elsewhere diagnostic, not a captured SPA
workspace. The dormant proposal `/__ioi/workbench/workspaces` remains
`dormant_or_unreachable` and is not evidence for a live Workspaces route.

### Executable seed-by-seed trace

All 39 parity entries were joined individually below. Three repeated evidence
profiles keep their requirements explicit:

- `D` (`daemon_wired`): the candidate reads a daemon/owner projection. Any
  consequence needs a wallet grant or sealed intent, final-invoker
  revalidation and durable receipt; deny, stale, duplicate, unavailable and
  recovery behavior must fail closed.
- `S` (`substrate_bound`): the candidate is a bounded projection/adapter, not a
  truth or authority owner. Tenant/System mismatch, stale data, replay,
  degraded dependency and recovery must remain visible.
- `R` (`reference_capture`): the route is fixture/capture evidence only. It has
  no product authority, backend truth or success claim; proxy failure must be
  honest, and it needs an implement/defer/merge/reject disposition.

Code abbreviations resolve to exact paths: `PARITY` is
`apps/hypervisor/harvest-app-parity-matrix.json`; `SERVE` is
`apps/hypervisor/scripts/serve-product-ui.mjs`; `PIPELINE`, `SOURCES`,
`SCHEMA`, `EXPLORER`, `APPROVALS`, and `MISSIONS` are respectively
`apps/hypervisor/surfaces/pipeline/index.mjs`,
`apps/hypervisor/surfaces/sources/index.mjs`,
`apps/hypervisor/surfaces/ontology-manager/index.mjs`,
`apps/hypervisor/surfaces/object-explorer/index.mjs`,
`apps/hypervisor/surfaces/approvals/index.mjs`, and
`apps/hypervisor/surfaces/missions/index.mjs`. `PARITY+SERVE` means the
reference proxy is owned by both sources; it does not make the capture an IOI
truth owner.

| Seed and route | Purpose / canonical disposition | Current class and dependency/authority/failure profile | Code owner | Stage and private-plan coverage |
| --- | --- | --- | --- | --- |
| `designer` — `/__apps/designer` → `/__ioi/studio/designer` | Studio solution design; retain only through Studio | `inoperable_shell`; `D`; real composition reads, authoring disabled | `PARITY+SERVE` | M6 + M1/M7; `partial_plan_coverage`, Studio child absent |
| `machinery` — `/__apps/machinery` → `/__ioi/studio/machinery` | Studio governed state-machine design/execution | `inoperable_shell`; `D`; projection lacks complete author/execute path | `PARITY+SERVE` | M6 + M3/M7; `partial_plan_coverage`, Studio child absent |
| `workshop` — `/__apps/workshop` | Studio builder reference; merge or reject | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M1/M7; `pointer_only`, no owner slice |
| `module` — `/__apps/module` | Studio/module-composition reference; merge or reject | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M3/M7; `pointer_only`, no owner slice |
| `monitors` — `/__apps/monitors` → `/__ioi/automations/monitors` | Automation monitoring/run inspection | `partially_operable`; `D`; browse port beside richer native handlers | `PARITY+SERVE` | M6 + M3; `partial_plan_coverage`, Automations child absent |
| `scheduler` — `/__apps/scheduler` | Scheduling reference; merge into Automations or reject | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M3; `pointer_only`, no owner slice |
| `lineage` — `/__apps/lineage` → `/__ioi/lineage` | Provenance lineage projection; migrate under Provenance | `partially_operable`; `S`; no replay/offline-proof claim | `PARITY+SERVE` | M6 + M3/M7/M9; `partial_plan_coverage`, Provenance child absent |
| `ingest` — `/__apps/ingest` | Data ingestion reference; merge or reject | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M7; `pointer_only`, no owner slice |
| `sources` — `/__apps/sources` → `/__ioi/data/sources` | Data source declaration/connection | `partially_operable`; `D`; bounded declaration, incomplete extraction/sync/recovery | `PARITY+SOURCES` | M6 + M7; `partial_plan_coverage`, Data child absent |
| `pipeline` — `/__apps/pipeline` → `/__ioi/pipeline` | Data transformation/materialization | `partially_operable`; `D`; bounded ladder, broad authoring disabled | `PARITY+PIPELINE` | M6 + M7; `partial_plan_coverage`, Data child absent |
| `dataset` — `/__apps/dataset` | Dataset/materialization reference | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M7; `pointer_only`, no owner slice |
| `schema` — `/__apps/schema` → `/__ioi/ontology/manager` | Ontology definition/action-type authoring | `partially_operable`; `D`; selected bounded upserts | `PARITY+SCHEMA` | M6 + M7; `partial_plan_coverage`, Ontology child absent |
| `explorer` — `/__apps/explorer` → `/__ioi/ontology/explorer` | Ontology object search/inspect | `partially_operable`; `D`; inspect exists, materialization/actions incomplete | `PARITY+EXPLORER` | M6 + M7; `partial_plan_coverage`, Ontology child absent |
| `objectview` — `/__apps/objectview` | Object-detail reference; merge into Explorer or reject | `inoperable_shell`; `R`; safe crawl redirected | `PARITY+SERVE` | M6 + M7; `pointer_only`, no owner slice |
| `objecteditor` — `/__apps/objecteditor` | Object-edit reference; requires action/final-invoker owner | `inoperable_shell`; `R`; safe crawl redirected | `PARITY+SERVE` | M6 + M7; `pointer_only`, no owner slice |
| `evalsuites` — `/__apps/evalsuites` → `/__ioi/evaluations/evalsuites` | Evaluation suite/evidence input | `inoperable_shell`; `D`; explicitly does not execute or score | `PARITY+SERVE` | M6 + M8; `partial_plan_coverage`, Evaluations child absent |
| `analysis` — `/__apps/analysis` | Evaluation-analysis reference | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M8; `pointer_only`, no owner slice |
| `quiver` — `/__apps/quiver` | Evaluation metric/visual-analysis reference | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M8; `pointer_only`, no owner slice |
| `models` — `/__apps/models` → `/__ioi/foundry/models` | Foundry model catalog/posture | `inoperable_shell`; `D`; no training/deployment/rights loop | `PARITY+SERVE` | M6 + M8; `partial_plan_coverage`, Foundry child absent |
| `modelstudio` — `/__apps/modelstudio` | Model author/train reference | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M8; `pointer_only`, no owner slice |
| `inference` — `/__apps/inference` | Inference/playground reference | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M8; `pointer_only`, no owner slice |
| `listings` — `/__apps/listings` → `/__ioi/marketplace/listings` | Package/worker/service listings; Marketplace is a Packages mode | `noncanonical_or_stale`; `D`; owner split unresolved | `PARITY+SERVE` | M6 + M5/M8/M14; `conflicting_plan_coverage`, Packages child absent |
| `registry` — `/__apps/registry` | Resolve Package versus worker/service registry owner | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + selected owner stage; `canon_unresolved` |
| `devconsole` — `/__apps/devconsole` | Developer Console integration/diagnostic reference | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M3/M12; `pointer_only`, no owner slice |
| `widgets` — `/__apps/widgets` | Developer Console widget reference; merge/reject | `inoperable_shell`; `R` | `PARITY+SERVE` | M6; `pointer_only`, no owner slice |
| `developer` — `/__apps/developer` | Developer Console/API-tooling reference | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M3/M7/M12; `pointer_only`, no owner slice |
| `workspaces` — `/__apps/workspaces` | Developer Workspace reference; not a live `/workspaces/:environment` page | `inoperable_shell`; `R`; safe crawl redirected | `PARITY+SERVE` | M6 + M3; `pointer_only`, Developer Workspace child absent |
| `repositories` — `/__apps/repositories` | Developer Workspace repository reference | `inoperable_shell`; `R`; safe crawl redirected | `PARITY+SERVE` | M6 + M3; `pointer_only`, no owner slice |
| `notepad` — `/__apps/notepad` | Developer Workspace editing/note reference | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M3; `pointer_only`, no owner slice |
| `vertex` — `/__apps/vertex` → `/__ioi/vertex` | Provenance graph/detail projection | `partially_operable`; `S`; no truth/replay proof | `PARITY+SERVE` | M6 + M3/M7/M9; `partial_plan_coverage`, Provenance child absent |
| `map` — `/__apps/map` | Environments topology/map reference | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M2/M9; `pointer_only`, Environments child absent |
| `slate` — `/__apps/slate` | Generated/domain-app shell; membership needs compiled descriptor | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M7; `pointer_only`, disposition absent |
| `logic` — `/__apps/logic` | Generated/domain-app logic shell; membership needs compiled descriptor | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M7; `pointer_only`, disposition absent |
| `contour` — `/__apps/contour` | Generated/domain-app analysis shell; membership needs compiled descriptor | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M7; `pointer_only`, disposition absent |
| `fusion` — `/__apps/fusion` | Generated/domain-app composite shell; membership needs compiled descriptor | `inoperable_shell`; `R` | `PARITY+SERVE` | M6 + M7; `pointer_only`, disposition absent |
| `jobs` — `/__apps/jobs` → `/__ioi/missions` | Migrate Mission jobs to typed Work/GoalRun/OutcomeRoom | `noncanonical_or_stale`; `S`; read projection only | `PARITY+MISSIONS` | M6 + M4/M5; `conflicting_plan_coverage`, Work child absent |
| `incidents` — `/__apps/incidents` → `/__ioi/missions/incidents` | Incident/blocker projection; resolve Work versus Operations owner | `inoperable_shell`; `D`; broad controls inert | `PARITY+SERVE` | M6 + M3/M9; `canon_unresolved`, child absent |
| `approvals` — `/__apps/approvals` → `/__ioi/governance/approvals` | Governance approval review/transitions | `partially_operable`; `D`; bounded approve/reject/revoke transitions | `PARITY+APPROVALS` | M6 + M1/M5/M9; `partial_plan_coverage`, Governance child absent |
| `changes` — `/__apps/changes` → `/__ioi/improvement/changes` | Improvement proposal/change review | `partially_operable`; `D`; campaign/promotion incomplete | `PARITY+SERVE` | M6 + M8; `partial_plan_coverage`, Improvement child absent |

This accounts for every parity entry but does not make all 39 intended product
applications. Canonical membership comes from the surface compiler and owner
contracts; captures remain evidence until each row has a reviewed disposition.

### Registered application depth and missing breadth

The point-in-time operational-depth atlas counts 390 implemented reference
controls and 173 unimplemented controls across the 14 registered surfaces.
Those numbers are useful audit evidence, not current program truth: the atlas
is based on `19d732ff2 (#67)`, and some recommendations lag current source
(for example, Sources is already classified `act`). Its verifier validates
taxonomy/state normalization but does not recompute every control flag or
recommendation from source. A green atlas check can therefore coexist with
stale gap prose. M6 needs either immutable-snapshot semantics or a
current-source surface-depth generator.

| Surface | Surface audit class | Declared depth | Atlas controls | What the HTTP/source crawl shows | Missing target implementation plan |
| --- | --- | --- | ---: | --- | --- |
| Missions | `noncanonical_or_stale` | `read_only_by_contract` | 6/10 | Browses/filters/selects/inspects room graph and proof; no mutation | Migration to typed Work/Rooms and optional Mission profile; acceptance/dispute/exit states; route retirement |
| Pipeline Builder | `partially_operable` | `workflow_complete` for its bounded ladder | 75/84 | Real materializing-run ladder and proof, while freeform authoring, transforms, scheduling, deploy, tests, and many canvas controls are visibly disabled | Distinguish the proven bounded workflow from full Data/Transformation/Automation product target; plan each disabled owner contract |
| Data Connection | `partially_operable` | `act` | 26/31 | Can declare a source; extraction/live connection, edit/delete, tests, upload, synthesis, sync/listener/agent lanes remain disabled/not wired | Complete source/credential/ingestion/sync lifecycle, identity and edit lineage, recovery and egress policy |
| Ontology Manager | `partially_operable` | `act` | 41/60 | Real ontology/COM authoring and proof-oriented views | Immutable version/overlay/crosswalk/action contracts, migration, disputes, generated surfaces, responsive states |
| Object Explorer | `partially_operable` | `inspect` | 32/35 | Search/filter/select/inspect; materialization/action breadth absent | Policy-bound data views, materialization, object action contracts, denied/degraded/large-data states |
| Approvals | `partially_operable` | `act` | 35/40 | Governed transitions over approval queue | Unified wallet review/ceremony/effect receipts, authenticated assignment/delegation, comments/SLA/export, origin/session context, mobile/CLI parity, recovery states |
| Issues | `inoperable_shell` | `browse` | 32/42 | Incident/blocker projection; many inert controls | Canonical IncidentRecord/remediation owner, assignment/severity/comments/actions, reconciliation, dispute and Work/Operations integration |
| Model Catalog | `inoperable_shell` | `browse` | 20/39 | Route/model cards and some native Foundry model posture | Detail/compare/playground, registration/training/deployment, rights, BYOK/BYOA, supplier pricing/learning/custody evidence |
| Marketplace | `noncanonical_or_stale` | `browse` | 16/33 | Store/listing projections; install/publish/hire/settle absent | Packages truth split, admission/install, worker/service/product lifecycles, payments/disputes |
| Solution Designer | `inoperable_shell` | `browse` | 7/51 | Real concept/component/resource projection; authoring mostly seed-like | Durable design graph, edge/layout authoring, Studio/ADK writes, package/genesis handoff, validation/simulation, undo/migration |
| Machinery | `inoperable_shell` | `browse` | 17/30 | Real state-machine projection; full governed authoring not mounted in this surface | Definition lifecycle, execution binding, scheduler, simulation, action authority, tests, versioning, promotion and rollback |
| Automate | `partially_operable` | `browse` in registered port | 20/29 | Main `/__ioi/automations` has richer spec/canvas/run behavior; ported monitor surface remains mostly browse | Reconcile two presentations; canonical WorkflowTemplate/AutomationSpec/Binding/Run chain, richer trigger/effect library and recovery states |
| Upgrade Assistant | `partially_operable` | `browse` | 39/47 | Proposal-like projection without complete campaign/promotion mechanism; richer actions live elsewhere | One owner path; direct/campaign distinction, evaluation epoch/exposure, owner approval, canary/rollback/recall |
| AIP Evals | `inoperable_shell` | `browse` | 24/32 | Suite declaration and candidate/evidence inputs; UI explicitly says it does not execute or score | Real EvalRun/judgment/scorecard/exposure/challenge/auto-mining/promotion path |

Cross-surface state coverage is also incomplete:

| State/interaction family | Current evidence | Plan finding |
| --- | --- | --- |
| Loading and honest empty | Present in selected extracted modules and native views, but not governed by one target-state contract | M6 needs required state matrices per admitted application. |
| Denied/expired/revoked | Extracted actions can fail closed; many flat handlers do not share that path | Consequential-action record must prove deny-before-effect and no success copy without receipt. |
| Daemon unavailable/degraded | Some native modules surface errors; selected adapter paths can substitute fixtures | Fixture-retirement record must prove typed unavailable state and no fabricated truth. |
| Validation/conflict/stale write | Bounded action modules expose selected errors; broad authoring shells are inconsistent or disabled | Each owner child needs stale/conflict/retry/reconciliation paths. |
| In-flight/cancel/recover | Strongest in the bounded Pipeline ladder; sparse across other intended workflows | Per-owner journeys need cancellation, restart, terminal and recovery proof. |
| Receipt/completed | Verified in selected bounded actions; post-and-redirect handlers may ignore result bodies | One receipt presentation/verification rule is required across consequential actions. |
| Modal/panel/embed | Applications modal and one iframe-backed Open Application slot exist; many drawers/tables assume desktop | Shell record must prove focus return, context isolation, deep links, narrow layout and embedded mode. |
| Disabled/placeholder | Atlas names 173 unimplemented controls; 23 seeds are reference captures | Every item needs an implement/defer/merge/reject disposition without converting UI evidence into target authority. |

Unregistered but important product breadth also needs owners: Home's governed
readout, Projects and discovery, Sessions and the full launch chain,
Applications/generated apps, Developer Workspace/editor targets, Developer
Console/MCP, Environments/provider lifecycle, Operations/readiness/incident
operations, Provenance/offline proof, Packages, Systems, Work, and Embodied
Systems.

### Source-of-product conflict

The branch's `apps/hypervisor/AGENTS.md` says the product is a source-owned
React app with surfaces under `src/surfaces/*`, no seed bundle, and no `/api`
adapter. The current `src/main.tsx` only mounts `/workspace-preview` and a
served-elsewhere notice. `npm run dev:hypervisor-app` starts that Vite shell on
port 1420, while the README's `npm run serve:app` command does not exist.
`apps/hypervisor/package.json` does provide the executable
`npm run serve:product-ui --workspace=@ioi/hypervisor-app` command (and the
identical `serve:reference` alias), both invoking
`node scripts/serve-product-ui.mjs`. That package-supported command matches the
active product process, whose script header describes a transitional,
gitignored harvested `product-ui` bundle, an IOI adapter, remaining mocks, and
injected augmentation/surface modules. Contrary to that header, 768 files
under `product-ui` are tracked in this checkout. The serving script is about
10,000 lines and eight of the registered surfaces still use flat handlers
rather than extracted bounded modules.

That contradiction is not merely documentation cleanup. It leaves the
implementation plan without a settled source-ownership migration, target
serving path, removal proof for the harvested dependency, or compatibility
plan for current routes. M6/WP-UX must own an explicit product-source
convergence slice before the directory can claim A–Z Hypervisor coverage.

### Authority/receipt consistency and fixture fallback

The extracted Pipeline, Ontology Manager, Sources, and Approvals actions use a
bounded runtime that fails closed and requires authority plus receipts for
their declared consequential mutations. Missions and Object Explorer are
deliberately read-only. Other owner pages expose mutations for Automations,
Feedback/Evaluations, Studio, Foundry, ODK, domain apps, Governance, and
Marketplace without uniformly traversing the same action descriptor,
final-invoker, and durable-receipt path. Some handlers post and redirect
without consuming a receipt. The plan needs a route-complete consequential
action census and one bounded migration/negative-proof cut; it must not infer
authority from a clickable control.

The adapter implements 103 inspected RPC operations (98 literal paths plus
five dynamically dispatched ProjectService operations), but the captured product
bundle still includes 55 unique fixture API endpoints mirrored across 110
files in its owned/source trees. Some EnvironmentService and
AgentService failures return `null`; the serve layer can then fall back to
captured fixtures, and unported `/api` calls may proxy to mocks. A daemon
outage can therefore present plausible reference data rather than an honest
unavailable/empty state. WP-RUNTIME states the fail-closed doctrine, but no
named M6 slice owns production fallback removal, a development-only reference
profile, per-endpoint fixture retirement, and negative proof that lost daemon
truth cannot fabricate product truth.

### Responsive and accessibility risk

The live visual pass was unavailable. Static evidence nonetheless shows:

- all 13 pixel-certification records cover desktop viewports only (1440×900
  and 1920×1080); none proves a 390×844 or equivalent narrow journey;
- Missions has explicit breakpoints at 980px and 640px and reduced-motion
  handling;
- Pipeline has limited width-specific rules, mainly for its dense toolbar;
- the shared surface rail remains fixed at 230px and the Open Application
  iframe always consumes the remaining width;
- other bound surfaces use many fixed widths, sticky drawers, wide grids,
  nowrap cells, and ported desktop chrome without comparable viewport rules;
- augmentation modals cap width with viewport units, but the augmentation
  modules do not contain a complete responsive shell policy;
- keyboard labels exist in the harvested shell, but no private record owns a
  full keyboard/focus/screen-reader/touch proof across the target topology.

M6's single phrase “frozen usability bar” is insufficient. The plan needs
explicit desktop/narrow journeys, focus order, keyboard launch, accessible
names/status, reduced motion, table/graph overflow, and no-hidden-authority
proofs for each pulled surface family.

## Orphan and conflict inventory

### Canon targets without a mechanism-owning slice

Highest-confidence orphans are:

1. Estate-wide information-flow/declassification propagation and PEP coverage.
2. Production receipt hashing, checkpoint emission, proof export, offline CLI,
   key discovery, and split-view defense.
3. Project discovery, candidate acceptance, StartupPlan, and the complete
   harness-session launch chain.
4. Provider/model commercial rights, sealed BYOK/BYOA, fallback substitution,
   and supplier reconciliation.
5. Managed billing, Work Credits, Goal Space allowances, and payment
   reconciliation.
6. Dispute admission, evidence adjudication, remedies, escrow/bonds, and
   cross-rail receipts.
7. Real Foundry training and independent Evaluations execution.
8. Mixture-of-Workers, worker training, aiagent managed workers, sas service
   fulfillment, and marketplace contribution settlement.
9. Ecosystem assurance, certification, jurisdiction packs, quarantine,
   liability, insurance/claims, and commercial audit export.
10. HypervisorOS, cTEE, task-capsule, and production attestation mechanisms.
11. Live native embodied and physical-action execution/promotion.
12. Agentgres Postgres readiness, checkpoint/proof writer, branches/staged
    effects, and complete per-System writer integration.
13. Per-owner-application operational depth behind the M6 taxonomy.
14. Public web-property claim gates and publication maintenance.
15. Storage profiles/repair/availability beyond current local/CAS/Filecoin
    precedents.

### Implementation/UI breadth without private plan ownership

Current code and verifier families expose additional orphaned implementation
breadth: multiple cloud/GPU/DePIN provider adapters; provider spend and
failover; OIDC/SSO/SCIM/GitHub/SCM/auth/token/secrets flows; portable memory;
model routing; connector execution; editor targets; workload and workflow
controls; storage custody; ontology/data pipelines; notifications; and broad
operator diagnostics. Existing implementation may be valuable, but the private
estate does not consistently map these families to a current record, selected
profile, migration rule, product journey, or retained exit. This makes future
canon changes hard to impact-analyze and makes code retirement risky.

The Hypervisor-specific orphan set includes the 39-seed parity estate, three
unregistered UX seeds, the broader archived 45-application capability
crosswalk, 55 unique captured fixture endpoints, duplicated hard-coded catalog/route
membership, eight flat registered handlers, and the atlas's 173 named
unimplemented controls. Each needs an explicit implement/defer/merge/reject
disposition; none is automatically a target merely because it exists.

### Plan artifacts that no longer match current owners

- The master calls the two kernel migration documents active authorities;
  current canon calls them archived terminal records.
- `m9-authority-gateway-equivalence-and-coverage` says enforcement-coverage
  ownership is unresolved; current canon assigns the Gateway to daemon doctrine
  and `EnforcementCoverageDeclaration` to the HypervisorOS/daemon boundary.
- M2, M3, M6, and M11 records use several generic or stale contract names
  instead of current canonical names.
- The M1.5 umbrella, M1.5b, and M1.5c overlap without a machine-readable
  parent/child aggregation rule; their own prose reserves a missing M1.5d.
- The M9 sovereign journey and Gateway record overlap M9.4 without a declared
  boundary.
- M14 demand economics presents itself as exit evidence but cannot aggregate
  the network-service and L1/no-L1 decision obligations.
- Private proof protocols and canonical product contract names share one
  undifferentiated `contract_families` array in the records.
- All proposed records retain one prior audit commit as provenance but no
  current-canon digest or change-impact trigger.

The plan-bearing file disposition at audit time is:

| Current file/family | Current canonical/program basis | Audit finding |
| --- | --- | --- |
| `ioi-target-end-state-master-implementation-guide.md` | Sole M0–M14 sequencer | Current program owner, but contains the stale kernel/PG references isolated in the companion plan's SA-1/SA-5 diffs. |
| `README.md` | Private navigation contract | Valid entry role; reconciliation residue makes its current reader path too expensive. |
| `ioi-undeniable-product-proof-implementation-guide.md` | Former proof sequencer | `conflicting_plan_coverage` if read actively; preserve/archive and point to sole master. |
| `refine-architecture.md` | Former master | `conflicting_plan_coverage` if read actively; no current sequencing authority. |
| `low-level-implementation-milestones.md` | Compatibility pointer | `pointer_only`, correctly inert. |
| `hypervisor-bounded-das-application-taxonomy-winning-state-plan.md` | M6 detail plus dated census | Useful module/audit material, but its phases overlap M6 and cannot remain an active-looking plan. |
| `canon-mechanism-hardening-action-plan.md` | PG definitions plus closure/status ledger | Useful proof-gate definitions; live status and cut order conflict with the Status Truth Rule. |
| `bounded-recursive-improvement-campaign-discovery-plan.md` | M8 experiment method plus dated research | Useful module/audit material; its phases overlap M8 and WP-IMPROVE. |
| `runtime-kernel-service-trust-boundary-audit.md` | M0 method plus dated 198-method census | Useful module/audit material; census is not current runtime status. |
| `runtime-module-map.md`; `runtime-package-boundaries.md` | Old runtime structure/checklist | Stale/superseded by current runtime canon and code; archive bodies and retain pointers. |
| `ioi-design-system-portable-package-plan.md` | Old portable design-system plan | No current independent sequence; current surface owner/M6 must pull any reusable detail. |
| Hypervisor migration pair | Completed historical migration plus one compatibility pointer | Evidence/pointer only; not a current build queue. |
| Reconciliation plan/review/patch/manifest | Point-in-time transaction evidence | No current direction; move behind the audit/history reader path. |
| `m0-m14-plan-gap-audit.md`; `canon-sota-improvement-review.md` | Point-in-time audits | Evidence only; superseded as current gap voice by this audit after acceptance. |
| M1.5 human work logs | Per-cut narrative evidence | Work-record role only; live status must resolve to JSON/program state. |
| Runtime JSON mirrors/residuals and `program-state.json` | Generated/projection roles | Valid only with explicit inputs/generator/check command; never hand-owned status or canon. |
| 43 `work-items/*.v1.json` records | Private per-cut plan/status layer | Correct location and role; incomplete §4.1 depth, stale names/owners and open dependency graph require enrichment, not relocation into canon. |

## Prioritized plan gaps

### P0 — make the existing plan executable

1. Enforce master §4.1 for every new/updated record and provide an explicit
   migration for older records.
2. Add machine-closed work-item dependencies, parent/child aggregation, exact
   owner refs, exact canonical contract-name validation, and classification of
   private proof artifacts versus product contracts.
3. Generate an architecture-owner coverage map that refuses unassigned build
   obligations and records the current canon digest.
4. Restore and run the work-item/program-state/stateless-guide validators in
   the authoritative estate checkout.
5. Own the route/PEP/final-invoker/PG census and refuse newly reachable,
   unclassified consequential routes.
6. Add the missing selected-profile work: the M0 aggregate; M1.5d and the M1
   aggregate; M9.1 and the M9 aggregate; the M13 aggregate; and the M14
   aggregate.
7. Replace M6's single umbrella with a surface compiler slice, a shell/alias/
   accessibility slice, a source/serve and fixture-retirement slice, an
   all-consequential-action authority/receipt slice, a current-source depth
   ledger, and owner-application depth slices pulled by real contracts.

### P1 — close selected sovereign-product proof gaps

1. Complete environment discovery/StartupPlan/session-launch ownership.
2. Complete authority review/effect receipts and portable verification.
3. Define production receipt/checkpoint/offline-proof mechanics.
4. Define platform temporal/operability inputs and recovery.
5. Add the full 21-step terminal product journey with honest state matrices,
   release supply chain, cohorts, thresholds, rollback, and stop rules.
6. Close model-route rights, custody, provider exit, and managed attach/detach
   dependencies needed by M8–M9.

### P2 — cover the remaining target architecture without pulling claims forward

Create explicitly stage-owned, demand/pull-gated slices for information flow,
managed economics/disputes, Foundry/Evaluations, worker/service supply,
assurance, private/measured substrate, Agentgres production breadth, storage,
live embodied promotion, public properties, and later network services. Their
records may remain `proposed`; having a complete plan does not license M9–M14
claims or bypass predecessor exits.

## Required disposition

The implementation directory should not be declared A–Z complete. It should be
refactored around one private master sequencer, subordinate stage/cross-cut
detail modules, machine-checked work-item records, generated projections,
evidence, and dated audits. The companion
[`implementation-directory-unification-action-plan.md`](../implementation-directory-unification-action-plan.md)
defines that refactor and the gap-closing work-item recommendations without
moving files, changing canon, changing runtime behavior, amending the
sequencer, or closing a stage in this audit cut.


## Appendix — inspection manifest

This appendix separates the inspection set from the owner/coverage synthesis
above. Paths in the first two manifests were enumerated mechanically; inclusion
does not make an archived file current authority. The implementation manifest
contains the 71-file pre-cut estate plus these two deliverables.

### Commands and live-crawl result

The principal read-only commands were:

```text
node internal-docs/implementation/check-program-state.mjs
npm run check:work-items
npm run check:stateless-master-guide
rg --files docs/architecture | sort
find internal-docs/implementation -type f | sort
ps/ss inspection for ports 4173, 8765, and 9301
rg/JSON source inspection across Hypervisor routes, registries, atlas, parity,
  seeds, bound actions, fixtures, launchers, documentation, and CSS
HTTP GET http://127.0.0.1:4173<route> for the route manifest below
```

The supported in-app browser bootstrap failed because the in-app browser was
unavailable. The already-running product server on port 4173 and daemon on
port 8765 were therefore inspected by safe HTTP GET plus source. The observed
product command was
`node apps/hypervisor/scripts/serve-product-ui.mjs`; it was not restarted or
duplicated. Its package-supported equivalent is
`npm run serve:product-ui --workspace=@ioi/hypervisor-app` (with
`serve:reference` currently an identical alias). Static startup inspection
found that `npm run dev:hypervisor-app` would launch only the Vite
served-elsewhere shell on port 1420, while the README's `npm run serve:app`
command is absent. An initial
35-route pass returned 35 HTTP 200 responses. The final manifest pass exercised
74 routes: 70 returned HTTP 200 and four reference routes
(`/__apps/objecteditor`, `/__apps/objectview`,
`/__apps/repositories`, and `/__apps/workshop`) returned HTTP 307 redirects.
No mutation was submitted. HTTP success or redirect is reachability evidence
only.

The three required private validators were run after authoring. Both npm
commands failed because this estate branch has no corresponding package
scripts. `check-program-state.mjs` failed with `ERR_MODULE_NOT_FOUND` for the
absent `scripts/generate-program-state.mjs`. These are checkout/provenance
blockers, not passing checks or status evidence; the exact limitation is also
recorded near the start of this audit.

The deliverable-only checks succeeded: both files have balanced fences,
consistent table widths, no trailing whitespace, and no unresolved local
Markdown file or heading link. The 50 obligation rows map one-to-one to 50
exact-locator rows; all 173 Markdown heading references and the registry JSON
Pointer resolve. The 272-path canon manifest and 73-path private manifest
match the current filesystem exactly; the 39 seed rows and 14 registered
surface rows are complete. `git check-ignore -v` resolves both deliverables to
`.gitignore` line 109, while `git ls-files --error-unmatch` rejects both as
untracked and `git diff --check` reports no tracked-diff whitespace error.

The pre-authoring hash comparison reports exactly the two requested additions,
no deletion, and the separately disclosed concurrent modification to
`work-item-m1-5c-amendment-execution.md`. It therefore proves this cut's two
additions while preserving the shared-worktree nonclaim.

### Canon file manifest (272 paths)

```text
docs/architecture/README.md
docs/architecture/START_HERE.md
docs/architecture/_archive/README.md
docs/architecture/_archive/change-ledgers/hypervisor-kernel-substrate-migration-cut-log.md
docs/architecture/_archive/change-ledgers/hypervisor-kernel-substrate-slice-ledger.md
docs/architecture/_archive/change-ledgers/implementation-matrix-sprint-lane-log.md
docs/architecture/_archive/implementation-logs/byo-provider-plane-adapter-build-log.md
docs/architecture/_archive/implementation-logs/decentralized-cloud-implemented-contract-log.md
docs/architecture/_archive/specs/agentgres-v2-reference.md
docs/architecture/_archive/specs/aiagent-worker-marketplace-product-context.md
docs/architecture/_archive/specs/ioi-cli-v1-1-product-spec.md
docs/architecture/_archive/specs/sas-service-marketplace-product-context.md
docs/architecture/_archive/specs/wallet-network-product-context-v3-2.md
docs/architecture/_archive/specs/wallet-protocol-sdk-packaging-plan.md
docs/architecture/_meta/canon-readability-audit.md
docs/architecture/_meta/canon-to-code-delta.md
docs/architecture/_meta/current-canon-defaults.md
docs/architecture/_meta/doc-classes.md
docs/architecture/_meta/execution-horizons.md
docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
docs/architecture/_meta/hypervisor-kernel-substrate-unification-master-guide.md
docs/architecture/_meta/implementation-matrix.md
docs/architecture/_meta/public-web-estate.md
docs/architecture/_meta/refactor-baseline.md
docs/architecture/_meta/schemas/architecture-contract-registry.v1.json
docs/architecture/_meta/schemas/authority-grant-envelope.v1.schema.json
docs/architecture/_meta/schemas/authority-grant-envelope.v2.schema.json
docs/architecture/_meta/schemas/authority-key-set.v1.schema.json
docs/architecture/_meta/schemas/authority-revocation-snapshot.v1.schema.json
docs/architecture/_meta/schemas/autonomous-system-constitution-amendment.v1.schema.json
docs/architecture/_meta/schemas/autonomous-system-constitution.v1.schema.json
docs/architecture/_meta/schemas/autonomous-system-genesis.v1.schema.json
docs/architecture/_meta/schemas/autonomous-system-initial-profile-bundle.v1.schema.json
docs/architecture/_meta/schemas/autonomous-system-manifest.v1.schema.json
docs/architecture/_meta/schemas/autonomous-system-sequence-zero-materialization-receipt.v1.schema.json
docs/architecture/_meta/schemas/autonomous-system-sequence-zero-materialization-receipt.v2.schema.json
docs/architecture/_meta/schemas/autonomous-system-sequence-zero-materialization.v1.schema.json
docs/architecture/_meta/schemas/declassification-approval.v1.schema.json
docs/architecture/_meta/schemas/dispute-rail-bundle.v1.schema.json
docs/architecture/_meta/schemas/enforcement-coverage-declaration.v1.schema.json
docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v1/negative-empty-capabilities.json
docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v1/negative-legacy-alias-write.json
docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v1/negative-status.json
docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v1/negative-unknown-constraint.json
docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v1/positive-active.json
docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v1/positive-revoked.json
docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v2/negative-empty-capabilities.json
docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v2/negative-padded-signature.json
docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v2/negative-signature-key-mismatch.json
docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v2/negative-stale-schema-hash.json
docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v2/positive-attenuated-child.json
docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v2/positive-root.json
docs/architecture/_meta/schemas/fixtures/authority-key-set-v1/negative-empty-validity-window.json
docs/architecture/_meta/schemas/fixtures/authority-key-set-v1/negative-padded-public-key.json
docs/architecture/_meta/schemas/fixtures/authority-key-set-v1/positive-active.json
docs/architecture/_meta/schemas/fixtures/authority-key-set-v1/positive-delegator.json
docs/architecture/_meta/schemas/fixtures/authority-revocation-snapshot-v1/negative-wrong-domain.json
docs/architecture/_meta/schemas/fixtures/authority-revocation-snapshot-v1/positive-current.json
docs/architecture/_meta/schemas/fixtures/authority-revocation-snapshot-v1/positive-delegator-current.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-constitution-amendment-v1/negative-committed-status.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-constitution-amendment-v1/positive-proposed.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-constitution-v1/negative-self-authorize.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-constitution-v1/positive-draft.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-genesis-v1/negative-nonzero-sequence.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-genesis-v1/positive-proposed.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-initial-profile-bundle-v1/negative-foreign-oracle-system.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-initial-profile-bundle-v1/negative-hollow-profile-bodies.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-initial-profile-bundle-v1/negative-missing-enrollment-slot.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-initial-profile-bundle-v1/positive-closed.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-manifest-v1/negative-live-system-identity.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-manifest-v1/positive-reusable-release.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v1/negative-activation-claim.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v1/negative-authority-binding-unknown-field.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v1/negative-detached-subject.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v1/negative-incompatible-artifact-ref.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v1/negative-legacy-receipt-type.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v1/negative-missing-public-commitment-ref.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v1/negative-output-hash-binding.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v1/negative-receipt-identity-binding.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v1/positive-materialized-pending-activation.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/negative-activation-claim.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/negative-authority-binding-unknown-field.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/negative-detached-subject.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/negative-incompatible-artifact-ref.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/negative-legacy-receipt-type.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/negative-missing-public-commitment-ref.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/negative-output-hash-binding.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/negative-receipt-identity-binding.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-v1/negative-activation-claim.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-v1/negative-component-count-binding.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-v1/negative-component-identity-duplicate.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-v1/negative-component-kind-ref-substitution.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-v1/negative-component-registry-binding.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-v1/negative-deployment-profile-root-binding.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-v1/negative-materialization-id-binding.json
docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-v1/positive-materialized-pending-activation.json
docs/architecture/_meta/schemas/fixtures/declassification-approval-v1/negative-missing-reviewed-representation-hash.json
docs/architecture/_meta/schemas/fixtures/declassification-approval-v1/positive-exact-binding.json
docs/architecture/_meta/schemas/fixtures/dispute-rail-bundle-v1/negative-value-unit-substitution.json
docs/architecture/_meta/schemas/fixtures/dispute-rail-bundle-v1/positive-marketplace-resolution.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-attributable-unobservable.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-audit-only-mediated.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-audit-only-preventable.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-custom-kernel-dependency-unbound.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-mediated-unknown-decision-source.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-mediated-unknown-final-invoker.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-passive-observation-mediated.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-positive-claim-missing-mechanism-role.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-preventable-unmediated.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-receipt-ingestion-mediated.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-receipted-missing-contract.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-receipted-missing-evidence.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-receipted-none-scope.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-uncovered-missing-gap.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-uncovered-mode-without-uncovered-claim.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-uncovered-positive-claim.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/negative-verified-stale-evidence.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/positive-active-enforcement.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/positive-audit-only.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/positive-scoped-custom-kernel-dependency.json
docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/positive-uncovered.json
docs/architecture/_meta/schemas/fixtures/information-flow-label-v1/negative-missing-instruction-authority.json
docs/architecture/_meta/schemas/fixtures/information-flow-label-v1/positive-private-untrusted.json
docs/architecture/_meta/schemas/fixtures/information-flow-label-v1/positive-public-verified.json
docs/architecture/_meta/schemas/fixtures/ioi-network-enrollment-v1/negative-compatible-selected-service.json
docs/architecture/_meta/schemas/fixtures/ioi-network-enrollment-v1/positive-local-only.json
docs/architecture/_meta/schemas/fixtures/lifecycle-continuity-profile-v1/negative-enabled-without-trigger.json
docs/architecture/_meta/schemas/fixtures/lifecycle-continuity-profile-v1/positive-successor-governed.json
docs/architecture/_meta/schemas/fixtures/lifecycle-transition-v1/negative-pause-carries-genesis.json
docs/architecture/_meta/schemas/fixtures/lifecycle-transition-v1/positive-initialize-proposal.json
docs/architecture/_meta/schemas/fixtures/managed-work-billing-ledger-bundle-v1/negative-floating-credit-units.json
docs/architecture/_meta/schemas/fixtures/managed-work-billing-ledger-bundle-v1/positive-complete.json
docs/architecture/_meta/schemas/fixtures/oracle-evidence-profile-v1/negative-escalation-without-adjudicator.json
docs/architecture/_meta/schemas/fixtures/oracle-evidence-profile-v1/positive-fail-closed.json
docs/architecture/_meta/schemas/fixtures/ordering-admission-finality-profile-v1/negative-threshold-exceeds-eligible.json
docs/architecture/_meta/schemas/fixtures/ordering-admission-finality-profile-v1/positive-single-authority.json
docs/architecture/_meta/schemas/fixtures/physical-action-execution-receipt-v1/negative-committed-missing-dispatch-evidence.json
docs/architecture/_meta/schemas/fixtures/physical-action-execution-receipt-v1/negative-envelope-input-hash-mismatch.json
docs/architecture/_meta/schemas/fixtures/physical-action-execution-receipt-v1/negative-flat-unbundled.json
docs/architecture/_meta/schemas/fixtures/physical-action-execution-receipt-v1/positive-committed.json
docs/architecture/_meta/schemas/fixtures/receipt-checkpoint-v1/negative-signature-key-mismatch.json
docs/architecture/_meta/schemas/fixtures/receipt-checkpoint-v1/negative-stale-schema-hash.json
docs/architecture/_meta/schemas/fixtures/receipt-checkpoint-v1/negative-wrong-domain.json
docs/architecture/_meta/schemas/fixtures/receipt-checkpoint-v1/positive-current.json
docs/architecture/_meta/schemas/fixtures/receipt-checkpoint-v1/positive-previous.json
docs/architecture/_meta/schemas/fixtures/receipt-envelope-v1/negative-bad-profile-ref.json
docs/architecture/_meta/schemas/fixtures/receipt-envelope-v1/negative-empty-boundary-facts.json
docs/architecture/_meta/schemas/fixtures/receipt-envelope-v1/negative-unknown-field.json
docs/architecture/_meta/schemas/fixtures/receipt-envelope-v1/positive-assured.json
docs/architecture/_meta/schemas/fixtures/receipt-envelope-v1/positive-minimal.json
docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v1/negative-leaf-index-mismatch.json
docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v1/negative-stale-schema-hash.json
docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v1/negative-wrong-domain.json
docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v1/positive-offline.json
docs/architecture/_meta/schemas/fixtures/runtime-tool-contract-v1/negative-missing-destination-declaration.json
docs/architecture/_meta/schemas/fixtures/runtime-tool-contract-v1/positive-declared-egress.json
docs/architecture/_meta/schemas/fixtures/system-genesis-compiler-v1/adversarial-cases.json
docs/architecture/_meta/schemas/information-flow-label.v1.schema.json
docs/architecture/_meta/schemas/invariants/authority-grant-envelope.v1.invariants.json
docs/architecture/_meta/schemas/invariants/authority-grant-envelope.v2.invariants.json
docs/architecture/_meta/schemas/invariants/authority-key-set.v1.invariants.json
docs/architecture/_meta/schemas/invariants/authority-revocation-snapshot.v1.invariants.json
docs/architecture/_meta/schemas/invariants/autonomous-system-constitution-amendment.v1.invariants.json
docs/architecture/_meta/schemas/invariants/autonomous-system-constitution.v1.invariants.json
docs/architecture/_meta/schemas/invariants/autonomous-system-genesis.v1.invariants.json
docs/architecture/_meta/schemas/invariants/autonomous-system-initial-profile-bundle.v1.invariants.json
docs/architecture/_meta/schemas/invariants/autonomous-system-manifest.v1.invariants.json
docs/architecture/_meta/schemas/invariants/autonomous-system-sequence-zero-materialization-receipt.v1.invariants.json
docs/architecture/_meta/schemas/invariants/autonomous-system-sequence-zero-materialization-receipt.v2.invariants.json
docs/architecture/_meta/schemas/invariants/autonomous-system-sequence-zero-materialization.v1.invariants.json
docs/architecture/_meta/schemas/invariants/declassification-approval.v1.invariants.json
docs/architecture/_meta/schemas/invariants/dispute-rail-bundle.v1.invariants.json
docs/architecture/_meta/schemas/invariants/enforcement-coverage-declaration.v1.invariants.json
docs/architecture/_meta/schemas/invariants/information-flow-label.v1.invariants.json
docs/architecture/_meta/schemas/invariants/ioi-network-enrollment.v1.invariants.json
docs/architecture/_meta/schemas/invariants/lifecycle-continuity-profile.v1.invariants.json
docs/architecture/_meta/schemas/invariants/lifecycle-transition.v1.invariants.json
docs/architecture/_meta/schemas/invariants/managed-work-billing-ledger-bundle.v1.invariants.json
docs/architecture/_meta/schemas/invariants/oracle-evidence-profile.v1.invariants.json
docs/architecture/_meta/schemas/invariants/ordering-admission-finality-profile.v1.invariants.json
docs/architecture/_meta/schemas/invariants/physical-action-execution-receipt.v1.invariants.json
docs/architecture/_meta/schemas/invariants/receipt-checkpoint.v1.invariants.json
docs/architecture/_meta/schemas/invariants/receipt-envelope.v1.invariants.json
docs/architecture/_meta/schemas/invariants/receipt-proof-bundle.v1.invariants.json
docs/architecture/_meta/schemas/invariants/runtime-tool-contract.v1.invariants.json
docs/architecture/_meta/schemas/ioi-network-enrollment.v1.schema.json
docs/architecture/_meta/schemas/legacy-ref-scheme-aliases.json
docs/architecture/_meta/schemas/lifecycle-continuity-profile.v1.schema.json
docs/architecture/_meta/schemas/lifecycle-transition.v1.schema.json
docs/architecture/_meta/schemas/managed-work-billing-ledger-bundle.v1.schema.json
docs/architecture/_meta/schemas/oracle-evidence-profile.v1.schema.json
docs/architecture/_meta/schemas/ordering-admission-finality-profile.v1.schema.json
docs/architecture/_meta/schemas/physical-action-execution-receipt.v1.schema.json
docs/architecture/_meta/schemas/receipt-checkpoint.v1.schema.json
docs/architecture/_meta/schemas/receipt-envelope.v1.schema.json
docs/architecture/_meta/schemas/receipt-proof-bundle.v1.schema.json
docs/architecture/_meta/schemas/runtime-action-schema.json
docs/architecture/_meta/schemas/runtime-tool-contract.v1.schema.json
docs/architecture/_meta/source-of-truth-map.md
docs/architecture/_meta/start-here.md
docs/architecture/_meta/vocabulary.md
docs/architecture/_meta/wallet-protocol-sdk-packaging-plan.md
docs/architecture/components/agentgres/api-object-model.md
docs/architecture/components/agentgres/artifact-ref-plane.md
docs/architecture/components/agentgres/doctrine.md
docs/architecture/components/agentgres/postgres-bridge-and-readiness-contract.md
docs/architecture/components/agentgres/projection-system-reference.md
docs/architecture/components/connectors-tools/contracts.md
docs/architecture/components/connectors-tools/doctrine.md
docs/architecture/components/daemon-runtime/api.md
docs/architecture/components/daemon-runtime/default-harness-profile.md
docs/architecture/components/daemon-runtime/doctrine.md
docs/architecture/components/daemon-runtime/embodied-runtime.md
docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md
docs/architecture/components/daemon-runtime/hypervisoros.md
docs/architecture/components/daemon-runtime/improvement-governance-gates.md
docs/architecture/components/daemon-runtime/platform-operability.md
docs/architecture/components/daemon-runtime/portable-memory-vault.md
docs/architecture/components/daemon-runtime/private-workspace-ctee.md
docs/architecture/components/daemon-runtime/runtime-nodes-tee-depin.md
docs/architecture/components/daemon-runtime/task-capsule-protocol.md
docs/architecture/components/hypervisor/byo-provider-plane.md
docs/architecture/components/hypervisor/core-clients-surfaces.md
docs/architecture/components/hypervisor/evaluations.md
docs/architecture/components/hypervisor/foundry.md
docs/architecture/components/hypervisor/identity-access-and-metering.md
docs/architecture/components/hypervisor/improvement.md
docs/architecture/components/hypervisor/providers-and-environments.md
docs/architecture/components/model-router/api-byok-mounting.md
docs/architecture/components/model-router/doctrine.md
docs/architecture/components/storage-backends/doctrine.md
docs/architecture/components/storage-backends/filecoin-cas.md
docs/architecture/components/wallet-network/api-authority-scopes.md
docs/architecture/components/wallet-network/doctrine.md
docs/architecture/components/wallet-network/product-exchange-risk.md
docs/architecture/domains/aiagent/digital-worker-ontology.md
docs/architecture/domains/aiagent/integration-surface-taxonomy.md
docs/architecture/domains/aiagent/managed-agent-console-contract.md
docs/architecture/domains/aiagent/managed-worker-instance-lifecycle.md
docs/architecture/domains/aiagent/vertical-ontology-packs.md
docs/architecture/domains/aiagent/worker-endpoints.md
docs/architecture/domains/aiagent/worker-marketplace.md
docs/architecture/domains/decentralized/README.md
docs/architecture/domains/decentralized/cloud.md
docs/architecture/domains/decentralized/exchange.md
docs/architecture/domains/decentralized/trade.md
docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md
docs/architecture/domains/ioi-ai/control-plane.md
docs/architecture/domains/marketplace-neutrality.md
docs/architecture/domains/sas/service-endpoints.md
docs/architecture/domains/sas/service-marketplace.md
docs/architecture/foundations/aiip.md
docs/architecture/foundations/bounded-recursive-improvement.md
docs/architecture/foundations/canonical-enums.md
docs/architecture/foundations/common-objects-and-envelopes.md
docs/architecture/foundations/domain-kernels.md
docs/architecture/foundations/domain-ontologies-and-data-recipes.md
docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md
docs/architecture/foundations/ecosystem-assurance-certification-liability.md
docs/architecture/foundations/governed-autonomous-systems.md
docs/architecture/foundations/institutional-learning-boundary.md
docs/architecture/foundations/invariants.md
docs/architecture/foundations/ioi-l1-contract-interfaces.md
docs/architecture/foundations/ioi-l1-mainnet.md
docs/architecture/foundations/mixture-of-workers.md
docs/architecture/foundations/physical-action-safety.md
docs/architecture/foundations/security-privacy-policy-invariants.md
docs/architecture/foundations/verifiable-bounded-agency.md
docs/architecture/foundations/web4-and-ioi-stack.md
docs/architecture/foundations/worker-training-lifecycle.md
docs/architecture/whitepaper.tex
```

### Decision-record manifest (19 inspected paths)

The decision index and all retained records were inspected. Current accepted
controls are 0001–0006, 0008, 0010, and 0013–0018; 0007, 0009, 0011, and 0012
are superseded history and were not treated as current owners.

```text
docs/decisions/0001-scs-deprecation-and-memory-runtime-successor.md
docs/decisions/0002-execution-authority-and-client-boundaries.md
docs/decisions/0003-agentgres-operation-backed-domain-truth.md
docs/decisions/0004-worker-mow-and-training-doctrine.md
docs/decisions/0005-domain-ontologies-and-data-recipes.md
docs/decisions/0006-capability-authority-and-work-graph-vocabulary.md
docs/decisions/0007-autopilot-ide-first-two-substrate-architecture.md
docs/decisions/0008-ioi-authority-gateway-sidecar-adoption-wedge.md
docs/decisions/0009-switch-autopilot-ide-shell-from-tauri-to-electron-vscode-fork.md
docs/decisions/0010-verifiable-bounded-agency-and-execution-boundary-alignment.md
docs/decisions/0011-hypervisor-nodes-and-governed-autonomous-system-chains.md
docs/decisions/0012-ioi-autonomous-system-settlement-and-aiip.md
docs/decisions/0013-hypervisor-core-clients-surfaces-and-adapters.md
docs/decisions/0014-hypervisor-ide-of-ides-and-session-estate.md
docs/decisions/0015-bounded-distributed-autonomous-systems-and-network-enrollment.md
docs/decisions/0016-hypervisor-systems-work-and-application-taxonomy.md
docs/decisions/0017-goal-pursuit-workflow-skill-and-harness-taxonomy.md
docs/decisions/0018-bounded-recursive-improvement-campaign-taxonomy.md
docs/decisions/README.md
```

### Private implementation file manifest (73 paths after this cut)

```text
internal-docs/implementation/README.md
internal-docs/implementation/architecture-to-implementation-coverage-audit.md
internal-docs/implementation/bounded-recursive-improvement-campaign-discovery-plan.md
internal-docs/implementation/canon-mechanism-hardening-action-plan.md
internal-docs/implementation/canon-sota-improvement-review.md
internal-docs/implementation/check-program-state.mjs
internal-docs/implementation/evidence/m0-exit.v1.txt
internal-docs/implementation/hypervisor-bounded-das-application-taxonomy-winning-state-plan.md
internal-docs/implementation/hypervisor-model-mount-rust-consolidation-and-deadcode-retirement.md
internal-docs/implementation/hypervisor-unified-rust-daemon-lifecycle-migration.md
internal-docs/implementation/implementation-directory-unification-action-plan.md
internal-docs/implementation/implementation-plan-estate-reconciliation.md
internal-docs/implementation/implementation-plan-reconciliation-review.md
internal-docs/implementation/ioi-design-system-portable-package-plan.md
internal-docs/implementation/ioi-target-end-state-master-implementation-guide.md
internal-docs/implementation/ioi-undeniable-product-proof-implementation-guide.md
internal-docs/implementation/low-level-implementation-milestones.md
internal-docs/implementation/m0-m14-plan-gap-audit.md
internal-docs/implementation/program-state.json
internal-docs/implementation/reconciliation/stateless-master-guide.v1.json
internal-docs/implementation/reconciliation/stateless-master-guide.v1.patch
internal-docs/implementation/refine-architecture.md
internal-docs/implementation/runtime-action-schema.json
internal-docs/implementation/runtime-kernel-namespace-residual.v1.json
internal-docs/implementation/runtime-kernel-service-trust-boundary-audit.md
internal-docs/implementation/runtime-module-map.md
internal-docs/implementation/runtime-package-boundaries.md
internal-docs/implementation/work-item-m1-5-protected-transitions.md
internal-docs/implementation/work-item-m1-5c-amendment-execution.md
internal-docs/implementation/work-items/README.md
internal-docs/implementation/work-items/m0-literal-exit-evidence-contract.v1.json
internal-docs/implementation/work-items/m0-unsigned-review-anchor.v1.json
internal-docs/implementation/work-items/m1-5-protected-transitions.v1.json
internal-docs/implementation/work-items/m1-5b-generic-protected-transitions.v1.json
internal-docs/implementation/work-items/m1-5c-amendment-execution.v1.json
internal-docs/implementation/work-items/m1-dual-genesis-and-read-projection.v1.json
internal-docs/implementation/work-items/m1-genesis-admission.v1.json
internal-docs/implementation/work-items/m1-governed-initialize-activate.v1.json
internal-docs/implementation/work-items/m1-sequence-zero-materialization.v1.json
internal-docs/implementation/work-items/m10-two-failure-domain-continuity.v1.json
internal-docs/implementation/work-items/m11-embodied-nonlive-graph-proof.v1.json
internal-docs/implementation/work-items/m11-selected-profile-exit-proof.v1.json
internal-docs/implementation/work-items/m11-useful-same-system-distribution.v1.json
internal-docs/implementation/work-items/m12-aiip-channel-envelope-profile.v1.json
internal-docs/implementation/work-items/m12-federated-admission-portable-exit-and-bindings.v1.json
internal-docs/implementation/work-items/m12-selected-profile-exit-proof.v1.json
internal-docs/implementation/work-items/m12-terms-discovery-semantic-negotiation.v1.json
internal-docs/implementation/work-items/m13-sovereignty-trial-preregistration.v1.json
internal-docs/implementation/work-items/m13-two-sovereign-surplus-and-decline-proof.v1.json
internal-docs/implementation/work-items/m14-demand-security-economics.v1.json
internal-docs/implementation/work-items/m14-l1-authorization-decision.v1.json
internal-docs/implementation/work-items/m14-network-service-devnet.v1.json
internal-docs/implementation/work-items/m2-membership-readiness-plane.v1.json
internal-docs/implementation/work-items/m2-route-restore-activation-cleanup.v1.json
internal-docs/implementation/work-items/m2-selected-profile-exit-proof.v1.json
internal-docs/implementation/work-items/m2-writer-fence-and-lost-suffix.v1.json
internal-docs/implementation/work-items/m3-direct-path-and-exit-proof.v1.json
internal-docs/implementation/work-items/m3-pursuit-definition-resolution.v1.json
internal-docs/implementation/work-items/m3-result-lifecycle-negative-retention.v1.json
internal-docs/implementation/work-items/m4-outcome-room-system-spine.v1.json
internal-docs/implementation/work-items/m5-local-agent-pairing.v1.json
internal-docs/implementation/work-items/m5-p0-readiness-verifier.v1.json
internal-docs/implementation/work-items/m5-participant-frontier-result-closeout.v1.json
internal-docs/implementation/work-items/m5-portable-exit-independent-clients.v1.json
internal-docs/implementation/work-items/m5-selected-profile-exit-proof.v1.json
internal-docs/implementation/work-items/m6-product-surface-and-typed-workspaces.v1.json
internal-docs/implementation/work-items/m7-semantic-definition-action-plane.v1.json
internal-docs/implementation/work-items/m8-learning-boundary-provider-exit.v1.json
internal-docs/implementation/work-items/m8-order-zero-improvement-and-direct-path.v1.json
internal-docs/implementation/work-items/m9-authority-gateway-equivalence-and-coverage.v1.json
internal-docs/implementation/work-items/m9-lifecycle-evidence-operator-proof.v1.json
internal-docs/implementation/work-items/m9-managed-optionality-overlay.v1.json
internal-docs/implementation/work-items/m9-sovereign-local-terminal-journey.v1.json
```

### Hypervisor surface identities inspected

- Canonical core workspaces: Home; Systems; Projects; Applications; Work.
- Canonical shell placement: Automations.
- Canonical owner applications: Studio; Automations; Ontology; Data; Governance; Provenance; Evaluations; Improvement; Foundry; Packages; Developer Workspace; Developer Console.
- Canonical substrate applications: Environments; Operations.
- Conditional canonical application: Embodied Systems.
- Registered surfaces: Missions; Pipeline Builder; Data Connection; Ontology Manager; Object Explorer; Approvals; Issues; Model Catalog; Marketplace; Solution Designer; Machinery; Automate; Upgrade Assistant; AIP Evals.
- Dormant unregistered seeds: Workspaces; Widgets; Lineage.
- Executable seed surfaces: analysis; approvals; changes; contour; dataset; designer; devconsole; developer; evalsuites; explorer; fusion; incidents; inference; ingest; jobs; lineage; listings; logic; machinery; map; models; modelstudio; module; monitors; notepad; objecteditor; objectview; pipeline; quiver; registry; repositories; scheduler; schema; slate; sources; vertex; widgets; workshop; workspaces.

### HTTP route manifest (74 safe GETs)

```text
/ai
/projects
/__ioi/home
/__ioi/sessions
/__ioi/applications
/__ioi/search
/__ioi/code
/__ioi/run-timeline
/__ioi/run-replay
/__ioi/agent-studio
/__ioi/studio/designer
/__ioi/studio/machinery
/__ioi/automations
/__ioi/automations/monitors
/__ioi/ontology/manager
/__ioi/ontology/explorer
/__ioi/odk
/__ioi/data/sources
/__ioi/pipeline
/__ioi/governance
/__ioi/governance/approvals
/__ioi/missions
/__ioi/missions/incidents
/__ioi/work-ledger
/__ioi/evaluations
/__ioi/evaluations/evalsuites
/__ioi/improvement/changes
/__ioi/foundry
/__ioi/foundry/models
/__ioi/marketplace
/__ioi/connections
/__ioi/environments
/__ioi/operations
/__ioi/domain-apps
/__ioi/workbench
/__apps/analysis
/__apps/approvals
/__apps/changes
/__apps/contour
/__apps/dataset
/__apps/designer
/__apps/devconsole
/__apps/developer
/__apps/evalsuites
/__apps/explorer
/__apps/fusion
/__apps/incidents
/__apps/inference
/__apps/ingest
/__apps/jobs
/__apps/lineage
/__apps/listings
/__apps/logic
/__apps/machinery
/__apps/map
/__apps/models
/__apps/modelstudio
/__apps/module
/__apps/monitors
/__apps/notepad
/__apps/objecteditor
/__apps/objectview
/__apps/pipeline
/__apps/quiver
/__apps/registry
/__apps/repositories
/__apps/scheduler
/__apps/schema
/__apps/slate
/__apps/sources
/__apps/vertex
/__apps/widgets
/__apps/workshop
/__apps/workspaces
```

In addition to these concrete GETs, static inspection covered nested
create/detail/action/callback routes, dynamic parameter forms, disabled
controls, test-only literals, asset URLs, and generated application activation
paths. Those source strings were classified in the route-family table rather
than treated as safe, independently operable pages.

### Captured-SPA source page manifest

These are the page paths extracted from the captured SPA router. Child paths
have been joined to their parents. `#new-session` is client state, not a server
pathname. Redirects and the wildcard remain listed because they were inspected
as routing behavior. There is no `/workspaces/:environment` registration.

```text
/
/projects
/projects/:projectId
/projects/:projectId/settings
/projects/:projectId/secrets
/projects/:projectId/prebuilds
/ai
/ai#new-session
/insights
/automations
/automations/webhooks
/automations/webhooks/:webhookId
/automations/new
/automations/:workflowId
/automations/:workflowId/edit
/automations/executions/:workflowExecutionId
/automations/executions/:workflowExecutionId/actions/:workflowExecutionActionId
/create
/details/:environmentId
/details/:environmentId/logs
/details/:environmentId/services/:serviceId/logs
/details/:environmentId/tasks
/details/:environmentId/task/:taskId
/details/:environmentId/task/:taskId/run/:runId
/details/:environmentId/code-changes
/settings
/settings/profile
/settings/preferences
/settings/secrets
/settings/git-authentications
/settings/personal-access-tokens
/settings/user-integrations
/settings/activities
/settings/experiments
/settings/manage-organization
/settings/announcements
/settings/terms-of-service
/settings/members
/settings/members/invite
/settings/members/group/:groupId
/settings/members/team/:teamId
/settings/members/service-account/:serviceAccountId
/settings/runners
/settings/runners/:runnerId
/settings/environments
/settings/organization-secrets
/settings/agents
/settings/agent-policies
/settings/agent-skills
/settings/org-integrations
/settings/policies
/settings/login
/settings/scim
/settings/security/oidc
/settings/billing
/settings/credit-usage
/onboarding/ioi
/onboarding/ioi/connect-to-github
/onboarding/ioi/create-a-project
/onboarding/ioi/write-your-first-prompt
/onboarding/ioi/select-your-repository
/onboarding/ioi/get-started-with-tasks
/create-organization
/integrations/connect/:integrationId
/integrations/connected/:integrationId
/experiments/:name
/join-organization/:inviteId?
/login
/login/ioi
/login/ioi/new
/magiclink
/confirm/signin
/account-deleted
/runner/scm-success
/port-denied
*
```

The root source-owned Vite shell additionally defines `/workspace-preview`.
Dormant, non-registered proposals are `/__ioi/workbench/workspaces`,
`/__ioi/developer-console/widgets`, and `/__ioi/provenance/lineage`.


### Static route-like string manifest (202 inspected strings)

This is the broad source inventory behind the route audit. It intentionally
retains non-reachable test probes, asset paths, action endpoints, callbacks,
trailing-slash variants and parameter fragments so static evidence is not
silently omitted. The 74-entry table above is the safe GET subset.

```text
/__apps/analysis
/__apps/approvals
/__apps/changes
/__apps/contour
/__apps/dataset
/__apps/definitely-not-a-seed
/__apps/designer
/__apps/devconsole
/__apps/developer
/__apps/evalsuites
/__apps/explorer
/__apps/fusion
/__apps/incidents
/__apps/inference
/__apps/ingest
/__apps/jobs
/__apps/lineage
/__apps/listings
/__apps/logic
/__apps/machinery
/__apps/map
/__apps/models
/__apps/modelstudio
/__apps/module
/__apps/monitors
/__apps/nonesuch
/__apps/notepad
/__apps/objecteditor
/__apps/objectview
/__apps/pipeline
/__apps/quiver
/__apps/registry
/__apps/repositories
/__apps/scheduler
/__apps/schema
/__apps/slate
/__apps/sources
/__apps/vertex
/__apps/widgets
/__apps/workshop
/__apps/workspaces
/__ioi/.../actions/upsert-object-type
/__ioi/__test/action-surface
/__ioi/__test/action-surface/x/transition
/__ioi/__test/boom
/__ioi/__unproven-read-only
/__ioi/a
/__ioi/agent-runs/
/__ioi/agent-runs/:id/timeline
/__ioi/agent-studio
/__ioi/agent-studio/governance/approvals/
/__ioi/agent-studio/governance/releases/
/__ioi/agent-studio/harness-profiles/
/__ioi/agent-studio/improvements/
/__ioi/agent-studio/improvements/propose
/__ioi/agent-studio/intel/
/__ioi/agent-studio/intel/affinities
/__ioi/agent-studio/intel/graph
/__ioi/agent-studio/intel/memory
/__ioi/agent-studio/intel/memory/
/__ioi/agent-studio/intel/skills
/__ioi/agent-studio/launch-policies
/__ioi/agent-studio/launch-policies/
/__ioi/agent-studio/model-routes/
/__ioi/agent-studio/model-routes/:id/
/__ioi/agent-studio/model-routes/mrt_local_default/
/__ioi/agent-studio/proposals/
/__ioi/agent-studio/vault/export
/__ioi/agent-studio/vault/import
/__ioi/api/applications
/__ioi/api/ioi-agent/launch
/__ioi/api/ioi-agent/preview
/__ioi/api/new-session/context
/__ioi/api/new-session/launch
/__ioi/api/placement/venue-policy
/__ioi/applications
/__ioi/automations
/__ioi/automations.json
/__ioi/automations/
/__ioi/automations/cron-preview
/__ioi/automations/monitors
/__ioi/automations/new
/__ioi/code
/__ioi/connections
/__ioi/connections/add
/__ioi/data/sources
/__ioi/data/sources/actions/declare
/__ioi/developer-console/widgets
/__ioi/domain-app-runtime
/__ioi/domain-app-runtime/
/__ioi/domain-apps
/__ioi/domain-apps/
/__ioi/domain-apps/new
/__ioi/editor/open
/__ioi/env-latest-run/
/__ioi/environments
/__ioi/evaluations
/__ioi/evaluations/
/__ioi/evaluations/evalsuites
/__ioi/fallthrough
/__ioi/fallthrough/reset
/__ioi/feedback
/__ioi/feedback/
/__ioi/fonts/
/__ioi/fonts/source-sans-pro-400.woff2
/__ioi/fonts/source-sans-pro-600.woff2
/__ioi/fonts/source-sans-pro-700.woff2
/__ioi/foundry
/__ioi/foundry/
/__ioi/foundry/models
/__ioi/foundry/run-plans
/__ioi/foundry/run-plans/
/__ioi/foundry/run-plans/new
/__ioi/foundry/specs
/__ioi/foundry/specs/
/__ioi/foundry/specs/new
/__ioi/github-app/callback
/__ioi/github-app/installed
/__ioi/github-app/start
/__ioi/governance
/__ioi/governance/
/__ioi/governance/approvals
/__ioi/governance/approvals/
/__ioi/governance/approvals/:id/transition
/__ioi/governance/approvals/appr_x/nonsense
/__ioi/governance/approvals/appr_x/transition
/__ioi/governance/cohorts
/__ioi/governance/kill-switches/
/__ioi/home
/__ioi/improvement/changes
/__ioi/integrations/connect/
/__ioi/integrations/oauth/callback
/__ioi/intelligence/projections/
/__ioi/intelligence/simulations/
/__ioi/invite/
/__ioi/invite/:id
/__ioi/lineage
/__ioi/login
/__ioi/login/sso/
/__ioi/login/sso/callback
/__ioi/logout
/__ioi/marketplace
/__ioi/marketplace/candidates/
/__ioi/marketplace/listings
/__ioi/marketplace/listings/
/__ioi/marketplace/listings/:id
/__ioi/marketplace/listings/new
/__ioi/marketplace/offers/
/__ioi/marketplace/reviews/
/__ioi/missions
/__ioi/missions/incidents
/__ioi/missions/room/transition
/__ioi/odk
/__ioi/odk/
/__ioi/odk/data-recipes
/__ioi/odk/data-recipes/
/__ioi/odk/manifests
/__ioi/odk/manifests/
/__ioi/odk/ontologies
/__ioi/odk/ontologies/
/__ioi/odk/ontologies/new
/__ioi/odk/surface-descriptors
/__ioi/odk/surface-descriptors/
/__ioi/odk/surface-descriptors/new
/__ioi/ontology
/__ioi/ontology/
/__ioi/ontology/explorer
/__ioi/ontology/manager
/__ioi/ontology/manager/actions/
/__ioi/ontology/manager/actions/create-ontology
/__ioi/operations
/__ioi/pipeline
/__ioi/pipeline/
/__ioi/provenance/lineage
/__ioi/run-publish/
/__ioi/run-replay
/__ioi/run-timeline
/__ioi/run-timeline/
/__ioi/run-timeline/../governance
/__ioi/run-timeline/:id
/__ioi/run-timeline/:runId
/__ioi/run-timeline/aex_
/__ioi/run-timeline/does-not-exist-xyz
/__ioi/run-timeline/env/
/__ioi/run-timeline/exec_safe
/__ioi/run-timeline/goal-run/
/__ioi/run-timeline/goal-run/:id
/__ioi/run-timeline/goal-run/goal-run-49
/__ioi/run-timeline/goal-run/goal-run-50
/__ioi/run-timeline/goal-run/gr_deadbeef
/__ioi/run-timeline/gr_deadbeef
/__ioi/run-timeline/r
/__ioi/search
/__ioi/sessions
/__ioi/slack/setup
/__ioi/studio/designer
/__ioi/studio/machinery
/__ioi/vertex
/__ioi/work-ledger
/__ioi/workbench
/__ioi/workbench/workspaces
/__ioi/x
```

Normalized dynamic IOI-owned page/action templates inspected in the serving
script and extracted surface modules (including methods where consequence
matters) were:

```text
GET|POST /__ioi/login
GET /__ioi/login/sso/:configId
GET /__ioi/login/sso/callback
GET|POST /__ioi/invite/:inviteId
GET /__ioi/logout
POST /__ioi/run-publish/:runId
GET /__ioi/github-app/start
GET /__ioi/github-app/callback
GET /__ioi/github-app/installed
GET /__ioi/integrations/connect/:connectorId
GET /__ioi/integrations/oauth/callback
GET|POST /__ioi/slack/setup
GET /__ioi/connections
GET|POST /__ioi/connections/add
GET /__ioi/editor/open
GET /__ioi/run-timeline/:runId
GET /__ioi/run-timeline/goal-run/:goalRunId
GET /__ioi/run-timeline/env/:environmentId
GET /__ioi/run-timeline/draft/:draftId
GET /__ioi/env-latest-run/:environmentId
GET /__ioi/agent-runs/:runId/timeline
GET /__ioi/agent-runs/:runId/conversation
GET /__ioi/agent-runs/:runId/conversation/history
GET /__ioi/agent-runs/:runId/conversation/live
POST /__ioi/api/new-session/launch
POST /__ioi/api/ioi-agent/preview
POST /__ioi/api/ioi-agent/launch
GET|PUT|POST /__ioi/api/placement/venue-policy
GET|POST /__ioi/automations
GET /__ioi/automations/:automationId
POST /__ioi/automations/:automationId/run
POST /__ioi/automations/:automationId/pause
POST /__ioi/automations/:automationId/resume
POST /__ioi/automations/:automationId/patch
POST /__ioi/automations/:automationId/webhook-rotate
POST /__ioi/automations/:automationId/delete
GET|POST /__ioi/feedback
POST /__ioi/feedback/:feedbackId/transition
GET|POST /__ioi/evaluations
POST /__ioi/evaluations/:suiteId/delete
POST /__ioi/agent-studio/intel/:kind
POST /__ioi/agent-studio/intel/:kind/:id/:transition
POST /__ioi/agent-studio/improvements/:id/simulate
POST /__ioi/agent-studio/improvements/propose
POST /__ioi/agent-studio/improvements/:id/:decision
POST /__ioi/agent-studio/improvements/:id/governance/:action
POST /__ioi/agent-studio/governance/:kind/:id/:transition
POST /__ioi/agent-studio/proposals/:id/:decision
POST /__ioi/agent-studio/launch-policies
POST /__ioi/agent-studio/launch-policies/:id/:action
POST /__ioi/agent-studio/launch-policies/:id/rollout/:action
POST /__ioi/agent-studio/model-routes/:id/:action
POST /__ioi/agent-studio/harness-profiles/:id/:action
GET /__ioi/intelligence/simulations/:id
GET /__ioi/intelligence/projections/:id/explain
GET /__ioi/agent-studio/vault/export
POST /__ioi/agent-studio/vault/import
GET /__ioi/foundry/specs/:id
GET /__ioi/foundry/specs/:id/edit
POST /__ioi/foundry/specs/:id/patch
POST /__ioi/foundry/specs/:id/delete
GET /__ioi/foundry/run-plans/:id
POST /__ioi/foundry/run-plans/:id/delete
GET /__ioi/odk/:kind/new
POST /__ioi/odk/:kind
GET /__ioi/odk/:kind/:id
GET /__ioi/odk/:kind/:id/edit
POST /__ioi/odk/:kind/:id/patch
POST /__ioi/odk/:kind/:id/delete
GET|POST /__ioi/domain-apps
GET /__ioi/domain-apps/:id
GET /__ioi/domain-apps/:id/edit
POST /__ioi/domain-apps/:id/:action
GET /__ioi/domain-app-runtime/:runtimeId
POST /__ioi/governance/:kind
POST /__ioi/governance/:kind/:id/transition
POST /__ioi/governance/:kind/:id/delete
POST /__ioi/governance/kill-switches/:id/enforce
GET|POST /__ioi/marketplace/listings
GET /__ioi/marketplace/listings/:id
GET /__ioi/marketplace/listings/:id/edit
POST /__ioi/marketplace/listings/:id/:action
POST /__ioi/marketplace/candidates/:id/:action
POST /__ioi/marketplace/reviews/:id
POST /__ioi/marketplace/offers/:id
POST /__ioi/pipeline/actions/admit-run
POST /__ioi/pipeline/:id/submit-lease-grant
POST /__ioi/pipeline/:id/cancel-run
POST /__ioi/pipeline/:id/release-lease
POST /__ioi/pipeline/:id/admit-session
POST /__ioi/pipeline/:id/submit-session-grant
POST /__ioi/pipeline/:id/release-session
POST /__ioi/pipeline/:id/execute
POST /__ioi/data/sources/actions/declare
POST /__ioi/ontology/manager/actions/create-ontology
POST /__ioi/ontology/manager/actions/update-metadata
POST /__ioi/ontology/manager/actions/upsert-value-type
POST /__ioi/ontology/manager/actions/upsert-object-type
POST /__ioi/ontology/manager/actions/upsert-property
POST /__ioi/ontology/manager/actions/upsert-link-type
POST /__ioi/ontology/manager/actions/upsert-action-type
POST /__ioi/governance/approvals/:id/transition
```

For finite template domains, `:kind`, `:transition`, and `:action` are
normalized audit notation over the enumerated handlers, not open-ended route
authority. Test-only routes (`/__ioi/__test/boom` and the action-surface
transition family) remain in the 202-string manifest and are not product
surfaces.

### Proxy, passthrough, and adapter route manifest

Static inspection also covered these wildcard families; the suffix is part of
the inspected route contract, not an assertion that every possible suffix was
called:

```text
/multipass/*
/graphql-gateway/*
/compass/*
/documentation/*
/aip-assist/*
/monocle/*
/approvals/*
/workspace/api/*
/log-receiver/*
/interventions/*
/ontology-metadata/*
/magritte-coordinator/*
/issues/*
/foundry-search/*
/marketplace/*
/object-set-service/*
/phonograph2/*
/language-model-service/*
/foundry-ml/*
/artifacts/*
/foundry-catalog/*
/models/*
/build2/*
/foundry-stemma/*
/third-party-applications/*
/developer-console/*
/assets/content-addressable-storage/*
/v1/*
/scim/*
/supervisor/*
/supervisor/:environmentId/supervisor.v1.EnvironmentOpsService/:method
/supervisor.v1.EnvironmentOpsService/* (websocket family)
/segment/*
/sentry*
/sentry-tunnel
/api/*
```

The product server's two exact local asset routes were also inspected in
source. They were not added to the 74 safe-GET count:

```text
GET /ioi-augmentation.js
ANY /static/assets/Terminal-CAzwFiqq.js
```

Special locally intercepted mirror paths inspected were:

```text
/interventions/api/interventions/v2/list
/interventions/api/interventions/ri.interventions.main.intervention.:kind/stats/search
/interventions/api/interventions/ri.interventions.main.intervention.:kind/compass/stats/search
/interventions/api/record/visit
/graphql-gateway/api/graphql*
/marketplace/api/block-set-transport/permissions/user-upload-quota
/issues/api/search/issues/v2/search
/issues/api/search/issues/v2/batch
/approvals/api/search/task-requests
/approvals/api/search/task-requests/counts
```

The following 103 Connect RPC adapter operations were inspected. The first 98
are literal strings; the five ProjectService entries are dynamically
dispatched and are retained here explicitly:

```text
/api/ioi.v1.AccountService/GetAccount
/api/ioi.v1.AccountService/GetChatIdentityToken
/api/ioi.v1.AgentService/CreateAgentExecution
/api/ioi.v1.AgentService/CreateAgentExecutionConversationToken
/api/ioi.v1.AgentService/CreateAgentSession
/api/ioi.v1.AgentService/DeleteAgentExecution
/api/ioi.v1.AgentService/GetAgentExecution
/api/ioi.v1.AgentService/ListAgentExecutions
/api/ioi.v1.AgentService/ListPrompts
/api/ioi.v1.AgentService/SendToAgentExecution
/api/ioi.v1.AgentService/StartAgent
/api/ioi.v1.AgentService/StopAgentExecution
/api/ioi.v1.BillingService/GetAutoTopupSettings
/api/ioi.v1.BillingService/GetBillingInfo
/api/ioi.v1.BillingService/GetCreditConsumptionTimeSeries
/api/ioi.v1.BillingService/ListSubscriptions
/api/ioi.v1.BillingService/ReconcileBilling
/api/ioi.v1.EditorService/ListEditors
/api/ioi.v1.EnvironmentAutomationService/ListServices
/api/ioi.v1.EnvironmentAutomationService/ListTaskExecutions
/api/ioi.v1.EnvironmentAutomationService/ListTasks
/api/ioi.v1.EnvironmentService/ArchiveEnvironment
/api/ioi.v1.EnvironmentService/CreateEnvironment
/api/ioi.v1.EnvironmentService/CreateEnvironmentAccessToken
/api/ioi.v1.EnvironmentService/CreateEnvironmentFromProject
/api/ioi.v1.EnvironmentService/CreateEnvironmentLogsToken
/api/ioi.v1.EnvironmentService/DeleteEnvironment
/api/ioi.v1.EnvironmentService/GetEnvironment
/api/ioi.v1.EnvironmentService/ListEnvironmentClasses
/api/ioi.v1.EnvironmentService/ListEnvironments
/api/ioi.v1.EnvironmentService/MarkEnvironmentActive
/api/ioi.v1.EnvironmentService/StartEnvironment
/api/ioi.v1.EnvironmentService/StopEnvironment
/api/ioi.v1.EnvironmentService/UnarchiveEnvironment
/api/ioi.v1.EnvironmentService/UpdateEnvironment
/api/ioi.v1.EventService/WatchEvents
/api/ioi.v1.GroupService/GetGroup
/api/ioi.v1.GroupService/ListGroups
/api/ioi.v1.GroupService/ListRoleAssignments
/api/ioi.v1.IntegrationService/CreateIntegration
/api/ioi.v1.IntegrationService/ListIntegrationDefinitions
/api/ioi.v1.IntegrationService/ListIntegrations
/api/ioi.v1.IntegrationService/ValidateIntegration
/api/ioi.v1.OrganizationService/CreateDomainVerification
/api/ioi.v1.OrganizationService/CreateOrganizationInvite
/api/ioi.v1.OrganizationService/CreateSCIMConfiguration
/api/ioi.v1.OrganizationService/CreateSSOConfiguration
/api/ioi.v1.OrganizationService/DeleteCustomDomain
/api/ioi.v1.OrganizationService/DeleteDomainVerification
/api/ioi.v1.OrganizationService/DeleteSCIMConfiguration
/api/ioi.v1.OrganizationService/DeleteSSOConfiguration
/api/ioi.v1.OrganizationService/GetAnnouncementBanner
/api/ioi.v1.OrganizationService/GetCustomDomain
/api/ioi.v1.OrganizationService/GetOIDCConfig
/api/ioi.v1.OrganizationService/GetOrganization
/api/ioi.v1.OrganizationService/GetOrganizationInvite
/api/ioi.v1.OrganizationService/GetOrganizationPolicies
/api/ioi.v1.OrganizationService/GetTermsOfService
/api/ioi.v1.OrganizationService/JoinOrganization
/api/ioi.v1.OrganizationService/ListDomainVerifications
/api/ioi.v1.OrganizationService/ListMembers
/api/ioi.v1.OrganizationService/ListSCIMConfigurations
/api/ioi.v1.OrganizationService/ListSSOConfigurations
/api/ioi.v1.OrganizationService/ResetOrganizationInvite
/api/ioi.v1.OrganizationService/SetCustomDomain
/api/ioi.v1.OrganizationService/UpdateCustomDomain
/api/ioi.v1.OrganizationService/UpdateOIDCConfig
/api/ioi.v1.OrganizationService/UpdateSCIMConfiguration
/api/ioi.v1.OrganizationService/VerifyDomainVerification
/api/ioi.v1.PrebuildService/ListPrebuilds
/api/ioi.v1.PrebuildService/ListWarmPools
/api/ioi.v1.ProjectService/ListProjects
/api/ioi.v1.ProjectService/GetProject
/api/ioi.v1.ProjectService/CreateProject
/api/ioi.v1.ProjectService/DeleteProject
/api/ioi.v1.ProjectService/ListProjectEnvironmentClasses
/api/ioi.v1.RunnerConfigurationService/CreateHostAuthenticationToken
/api/ioi.v1.RunnerConfigurationService/DeleteHostAuthenticationToken
/api/ioi.v1.RunnerConfigurationService/ListHostAuthenticationTokens
/api/ioi.v1.RunnerConfigurationService/ListSCMIntegrations
/api/ioi.v1.RunnerManagerService/ListAvailableRunnerManagers
/api/ioi.v1.RunnerService/CheckAuthenticationForHost
/api/ioi.v1.RunnerService/CreateRunner
/api/ioi.v1.RunnerService/CreateRunnerLogsToken
/api/ioi.v1.RunnerService/GetRunner
/api/ioi.v1.RunnerService/ListRunners
/api/ioi.v1.RunnerService/ParseContextURL
/api/ioi.v1.SecretService/CreateSecret
/api/ioi.v1.SecretService/DeleteSecret
/api/ioi.v1.SecretService/ListSecrets
/api/ioi.v1.SecretService/UpdateSecretValue
/api/ioi.v1.ServiceAccountService/ListServiceAccounts
/api/ioi.v1.UserService/CreatePersonalAccessToken
/api/ioi.v1.UserService/DeletePersonalAccessToken
/api/ioi.v1.UserService/GetAuthenticatedUser
/api/ioi.v1.UserService/GetDotfilesConfiguration
/api/ioi.v1.UserService/GetPreference
/api/ioi.v1.UserService/ListPersonalAccessTokens
/api/ioi.v1.UserService/ListPreferences
/api/ioi.v1.UserService/SetPreference
/api/ioi.v1.WorkflowService/GetWorkflowExecutionSummary
/api/ioi.v1.WorkflowService/ListWorkflowExecutions
/api/ioi.v1.WorkflowService/ListWorkflows
```

These adapter and proxy paths are dependencies/fallback seams, not product
membership. Mutating operations require the same owner authority,
final-invoker and receipt rules as native routes; mirror/mock success is not
runtime proof.


### Important Hypervisor code and evidence anchors

```text
apps/hypervisor/AGENTS.md
apps/hypervisor/README.md
apps/hypervisor/package.json
apps/hypervisor/vite.config.ts
apps/hypervisor/src/main.tsx
apps/hypervisor/src/styles/global.css
apps/hypervisor/scripts/serve-product-ui.mjs
apps/hypervisor/scripts/ioi-api-adapter.mjs
apps/hypervisor/scripts/ioi-projection.mjs
apps/hypervisor/scripts/surface-registry.mjs
apps/hypervisor/scripts/app-catalog.mjs
apps/hypervisor/scripts/augmentation/00-core.js
apps/hypervisor/scripts/augmentation/35-app-catalog.js
apps/hypervisor/scripts/augmentation/90-mount.js
apps/hypervisor/application-operational-depth.json
apps/hypervisor/harvest-app-parity-matrix.json
apps/hypervisor/harvest-starting-points.json
apps/hypervisor/reference-clean-sweep.json
apps/hypervisor/pixel-certifications/README.md
apps/hypervisor/pixel-certifications/approvals.json
apps/hypervisor/pixel-certifications/changes.json
apps/hypervisor/pixel-certifications/designer.json
apps/hypervisor/pixel-certifications/evalsuites.json
apps/hypervisor/pixel-certifications/explorer.json
apps/hypervisor/pixel-certifications/incidents.json
apps/hypervisor/pixel-certifications/listings.json
apps/hypervisor/pixel-certifications/machinery.json
apps/hypervisor/pixel-certifications/models.json
apps/hypervisor/pixel-certifications/monitors.json
apps/hypervisor/pixel-certifications/pipeline.json
apps/hypervisor/pixel-certifications/schema.json
apps/hypervisor/pixel-certifications/sources.json
apps/hypervisor/surfaces/approvals/index.mjs
apps/hypervisor/surfaces/missions/index.mjs
apps/hypervisor/surfaces/object-explorer/index.mjs
apps/hypervisor/surfaces/ontology-manager/index.mjs
apps/hypervisor/surfaces/pipeline/index.mjs
apps/hypervisor/surfaces/sources/index.mjs
apps/hypervisor/surfaces/chrome.mjs
apps/hypervisor/surfaces/kit.mjs
apps/hypervisor/surfaces/ontology-context.mjs
apps/hypervisor/surfaces/plane-read.mjs
apps/hypervisor/ux-seeds/workspaces/surface.mjs
apps/hypervisor/ux-seeds/widgets/surface.mjs
apps/hypervisor/ux-seeds/lineage/surface.mjs
apps/hypervisor/product-ui/
apps/hypervisor/product-ui/public/static/assets/main-DLKYFe1Y.js
apps/hypervisor/product-ui/public/static/assets/SegmentProvider-CXCNBY9U.js
apps/hypervisor/docs/product-ui-api-integration.md
internal-docs/reverse-engineering/palantir/local-composition-application-crosswalk.md
package.json
```

The six extracted bound modules and all eight flat registered handlers were
read through their registry/serve-script ownership, along with all 13 desktop
pixel-certification records and all 39 parity seed entries. The appendix is an
inspection manifest, not an implementation or status ledger.
