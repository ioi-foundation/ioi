# Canon-to-Code Delta

Status: canonical implementation index.
Canonical owner: this file for the object-level delta between the collaborative-pursuit / federated-ontology canon and what the code durably implements today, and for the deferred application-UX backlog that replaced the former surface-by-surface implementation queue.
Supersedes: the PR68 operational-depth queue as an implementation SEQUENCE (its audit evidence remains valid and referenced); ad hoc "what do we build next" lists in plans.
Superseded by: none.
Last alignment pass: 2026-07-12.
Doctrine status: canonical
Implementation status: mixed (each row carries its own state; most target objects are not started — that is the point of this file)
Last implementation audit: 2026-07-12

## Why this file exists

The estate reached an audited application plane (the operational-depth atlas,
`apps/hypervisor/application-operational-depth.json`) whose remaining queue
ranked SURFACE work. The canon's next leg is not surface work: it is the
collaborative-pursuit and federated-ontology object plane. This file records,
object by object, what the canon requires, what the code holds today, and what
crossing turns the delta into durable truth — so application UX resumes only
when an implemented contract pulls it.

Reading rules:

- **Implementation state** is honest: `not started` means the object's
  durable form does not exist in code — even when an adjacent substrate is
  named as an explicitly labeled *implementation precedent* (a precedent is
  never a partial instance). `partial` is reserved for rows where a real
  slice of the object itself persists. Nothing planned is described as
  shipped.
- **Next authority crossing** is the first daemon/Agentgres/wallet boundary the
  object must cross to exist as governed truth (not a UI milestone).
- **Owning application projection** names the product surface that will RENDER
  the object. Projections never own the truth; the daemon/Agentgres contracts
  in the row do.

## The delta table

| Canonical object | Canonical owner | Durable form (target) | Current code anchor | Implementation state | Next authority crossing | Conformance proof | Owning application projection |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `WorkResult` | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | canonical object: generic typed result envelope (kind, payload profile, evidence refs, verification state) beyond software patches | generic admission plane implemented in the held stack (build step 1, not yet merged to master): `crates/node/src/bin/hypervisor_daemon_routes/work_result_routes.rs` — `POST/GET /v1/hypervisor/work-results` admits all nine canonical profiles fail-closed with atomic record-first/receipt-second receipts; the `implementation_result` payload (schema `ioi.hypervisor.implementation-result.v1`, in `runtime_goal_run_admission.rs` + `goalrun_routes.rs`) remains the software profile via `result_profile: software_implementation` + `result_payload_ref` | partial (admission plane + LIVE room binding in the held stack — `outcome_room_ref` must resolve to an open hosted room; acceptance/verification/challenge transitions pending build step 3) | room-scoped admission under the OutcomeRoom aggregate (build step 2); acceptance/challenge authority (build step 3) | held stack: `work_result_tests` (cargo) + `verify-hypervisor-work-result-plane.mjs` (isolated, 63 checks); planned: room-scoped admission proofs (build step 2) | Missions (result detail); Provenance (evidence chain) |
| `OutcomeDelta` | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | canonical object: declared before/after outcome statement bound to results and acceptance | admission plane implemented in the held stack (build step 1, not yet merged to master): `work_result_routes.rs` — `POST/GET /v1/hypervisor/outcome-deltas`; the delta-binds-result invariant is fail-closed at write (`proposed_by_ref` must resolve to an admitted work-result; attempt/finding/participant-lease proposers refuse as named gaps); status is plane-owned at `proposed` | partial (admission plane + LIVE room binding in the held stack — a delta's room must exactly equal its bound result's room; evaluation/admission/rollback transitions pending build step 3 authority) | evaluation/admission transitions under room/acceptance authority (build steps 2-3) | held stack: delta-binds-result invariant in `work_result_tests` + `verify-hypervisor-work-result-plane.mjs`; planned: transition authority proofs (build steps 2-3) | Missions (outcome view) |
| `OutcomeRoom` | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | canonical object: hosted room aggregate above bounded GoalRuns with declared admission mode | hosted aggregate implemented in the held stack (build step 2, not yet merged to master): `crates/node/src/bin/hypervisor_daemon_routes/outcome_room_routes.rs` — `POST/GET /v1/hypervisor/outcome-rooms` (+`/:id/transition`, `/:id/attach-goal-run`); every shared-state transition admitted + receipted with required `expected_revision`; hosted_admission only with a REQUIRED host_domain_ref authority binding (federated = named gap, AIIP leg); GoalRun membership is SINGULAR and reciprocal (canonical goal:// identity; the GoalRun.outcome_room_ref stamp lands atomically with the member list; a run belongs to at most one room) | partial (hosted lifecycle + singular reciprocal membership in the held stack; participant/frontier/attempt/finding lists are plane-owned empties pending build step 3; federated admission pending steps 7-8) | participant leases + frontier + claim authority under the room (build step 3) | held stack: `outcome_room_tests` (cargo) + `verify-hypervisor-outcome-room-plane.mjs` (isolated, 104 checks incl. same-revision concurrency storm, close-vs-admission race, goal-run lifecycle fail-closed + duplicate-reconcile reservation, declaration-first staged-output failure lanes with a real wallet crossing, output-containment (traversal/absolute/symlink/alias) refusals, bounded intake (FIFO/oversize/count) refusals, live staged-manifest binding into the recovery authority hash (mutate-after-challenge defeated), visibility-fault lanes (visible-unconfirmed stamp goes forward with reciprocal equality; visible receipt keeps a resolving attempt record + backlink), SIGKILL crash-durability + governed restart recovery with attempt-bound receipts, a recovery-intent kill point completed forward by a seal-validating boot completer that resolves dangling attempt refs, append-only attempt evidence, authority-gated lifecycle recovery, exact-shape rollback, and substrate soak-parity lanes); planned: single-node collaborative-pursuit proof (build step 6) | Missions (room = Mission detail); ioi.ai Goal Space |
| `CollaborativeWorkGraph` | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | canonical object graph: admitted participant/frontier/claim/attempt/finding/evaluation graph of one room | nearest substrate: per-run `adaptive_work_graph` execution strategy (`crates/types/src/app/chat.rs`) — a DIFFERENT, run-internal object | not started (run-internal graph exists; shared room graph absent) | graph heads admitted in Agentgres under the room aggregate; no direct client writes | planned: graph-transition receipt tests (build step 3) | Missions (workstream board); boards/digests are projections |
| `OutcomeRoomDiscovery` | [`aiip.md`](../foundations/aiip.md) | policy-bound discovery projection an external worker can query for eligible rooms | none | not started | policy-bound read projection with visibility policy enforcement at the daemon boundary | planned: AIIP discovery conformance (build step 7) | Missions (discovery lens); Developer Console (federation config) |
| `RoomParticipationRequest` | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | canonical object: typed admission request (identity, affiliation, eligibility evidence, requested scopes) | none | not started | typed admission decision producing a receipt + (on accept) a `RoomParticipantLease` | planned: admission accept/refuse receipt tests (build step 3) | Missions (participant admission queue) |
| `ParticipantStateBundle` | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | canonical object: portable exit bundle of permitted claim/contribution/result/finding/receipt refs with recorded exclusions | none | not started | export crossing: bundle assembly is policy-filtered and receipted; usable without the hosted room DB | planned: portable-exit proof (build step 7) | Missions (participant detail → export) |
| `RoomParticipantLease` | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | canonical object: bounded leased participation (TTL, heartbeat, budget/authority leases, lifecycle) | nearest pattern: the CapabilityLease gateway (`crates/node/src/bin/hypervisor_daemon_routes/capability_lease_plan_routes.rs` + daemon lease gateway) — authority-crossing precedent, not the room lease | not started (lease-gateway pattern proven elsewhere) | lease issue/renew/expire/revoke transitions receipted under the room aggregate | planned: lease lifecycle tests incl. revocation releases claims (build step 3) | Missions (participants panel) |
| `ResourceOffer` | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | canonical object: typed offer of compute/runtime/data/verification capacity to a room; a profile over existing resource inventory | nearest substrate: provider/candidate planes (`crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs`, candidate sources) | not started (inventory substrate exists; offer object absent) | offer admission bound to real inventory refs; acceptance creates allocation with spend visibility | planned: offer-accept-allocate receipt chain test (build step 3) | Missions (offers board); Operations (backing inventory) |
| `CapabilityOffer` | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | canonical object: typed advertisement of a Worker/service/specialist capability to a room | nearest substrate: marketplace listing plane (`crates/node/src/bin/hypervisor_daemon_routes/marketplace_routes.rs`) | not started | offer admission with eligibility evidence; matching to frontier items receipted | planned: capability-match receipt test (build step 3) | Missions (offers board); Marketplace (listing origin) |
| `WorkFrontierItem` | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | canonical object: claimable unit of room work with readiness/dependency state | none | not started | frontier transitions (open→claimed→resolved/returned) admitted under the room aggregate | planned: frontier state-machine tests + backpressure proof (build step 3) | Missions (frontier board) |
| `WorkClaimLease` | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | canonical object: bounded pull-based claim on a frontier item (TTL, renewal, release-on-exit) | nearest pattern: CapabilityLease gateway (same precedent as `RoomParticipantLease`) | not started | claim issue/expiry/release transitions receipted; exit/revocation MUST release claims | planned: claim-release-on-revocation test (build step 3) | Missions (claims view) |
| `Attempt` | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | canonical object: one bounded, isolated execution against a claim, run as a GoalRun | implementation precedent (not a partial Attempt): bounded GoalRun records + agent-run transcripts (`goalrun_routes.rs`; `/v1/hypervisor/agent-run-transcripts`) — the bounded-execution substrate an Attempt will run on | not started (no Attempt object; no attempt-to-claim binding) | attempt record binding claim ref + GoalRun ref at admission | planned: attempt-binds-claim invariant test (build step 3) | Missions (attempt timeline); Provenance (replay) |
| `Finding` | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | canonical object: positive or negative typed discovery bound to attempts/evidence, valuable independent of success | implementation precedent only: the eval-suite library plane (`crates/node/src/bin/hypervisor_daemon_routes/eval_suite_routes.rs`) is DECLARATION-ONLY by its own contract — no run/execute endpoint, no scoring, no verdict — a precedent for declared assessment gates, not a findings or verdict plane | not started (no verdict or finding plane exists anywhere) | finding admission with evidence refs; negative findings first-class | planned: negative-finding lineage test (build step 3) | Missions (findings feed); Evaluations (verdict lineage) |
| `VerifierChallenge` | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | canonical object: typed challenge against a result/finding with resolution lifecycle | nearest substrate: improvement governance gates (`crates/node/src/bin/hypervisor_daemon_routes/*` improvement/governance planes) | not started | challenge admission + resolution transition receipted; unresolved challenges block acceptance | planned: challenge-blocks-acceptance test (build step 3) | Evaluations (challenge queue); Missions (room detail) |
| `OntologyVersion` | [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md) | canonical object: immutable `DomainOntologyEnvelope` with `ontology_record_profile: ontology_version` (compatibility/deprecation contract per namespace) | implementation precedent (not a partial OntologyVersion): ODK's MUTABLE single-domain revision counter + `expected_revision` optimistic concurrency + revision history (`crates/node/src/bin/hypervisor_daemon_routes/odk_routes.rs`) — concurrency discipline the immutable version object will reuse | not started (no immutable version object, no cross-namespace identity) | version publication as immutable admitted record with cross-namespace identity | precedent evidence: `odk_tests` (revision conflict = typed, zero mutation); planned: federated version lineage tests (build step 5) | Ontology (Manager history) |
| `OntologyOverlay` | [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md) | canonical object: `DomainOntologyEnvelope` with `ontology_record_profile: ontology_overlay` + explicit base-version refs | none | not started | overlay admission bound to a base `OntologyVersion` ref | planned: overlay-resolves-against-base test (build step 5) | Ontology (Manager overlays) |
| `OntologyCrosswalk` | [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md) | canonical object: `OntologyMappingEnvelope` with `mapping_record_profile: ontology_crosswalk` (declared loss, ambiguity, scope, verifier requirements) | nearest substrate: single-domain `ConnectorMapping` (`crates/node/src/bin/hypervisor_daemon_routes/connector_mapping_routes.rs`) — provider→domain, not domain→domain | not started (in-domain mapping exists; cross-domain crosswalk absent) | crosswalk admission binding two version refs; used at AIIP profile negotiation | planned: two-domain profile negotiation proof (build steps 5+8) | Ontology (crosswalk view); Developer Console (federation) |
| `SemanticMappingDecision` | [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md) | canonical object: applied `OntologyMappingEnvelope` with `mapping_record_profile: semantic_mapping_decision` — challengeable, receipted application of a crosswalk to a concrete handoff | implementation precedent (not a partial decision object): `ConnectorMapping` create/update receipts (`connector_mapping_routes.rs`) — receipted mapping mutations without decision identity | not started (no decision-as-object, no reviewer lineage) | decision admission with reviewer identity + receipt | planned: mapping-decision lineage test (build step 5) | Ontology (mapping review) |
| `ProvenanceAssertion` | [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md) | canonical object: `OntologyAssertionEnvelope` with `assertion_profile: provenance_assertion` — time/source/confidence/evidence/dispute-bearing claim; admission records it without making it universally true | implementation precedent (not a partial assertion object): the receipt families + proof stream (`/v1/hypervisor/work-ledger` route in `crates/node/src/bin/hypervisor-daemon.rs` — route name is API compatibility; the product surface is Provenance) — evidence substrate an assertion will bind | not started (no assertion-as-object) | assertion admission binding receipt refs; challenge path shared with `VerifierChallenge` | planned: assertion-binds-receipts test (build step 5) | Provenance (assertion graph) |
| `OntologyActionContract` | [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md) | canonical object: executable semantic action binding target object + typed IO to pre/postconditions, capabilities, authority, risk, idempotency, compensation, verifier, evidence, and receipt obligations | nearest substrate: ODK COM `action_types` (`odk_routes.rs`) + `RuntimeToolContract` split tiers (`crates/types/src/app/runtime_contracts.rs`) | not started (typed action definitions + tool contracts exist separately; the binding contract absent) | contract admission binding action type ref → tool contract ref → `authority_scope_requirements`; execution stays behind wallet/policy | planned: action-contract execution refusal/receipt tests (build step 5) | Ontology (action contracts); Studio (composition wiring) |

## The build sequence this table pulls

The ordered, contract-first sequence lives in
[`execution-horizons.md`](./execution-horizons.md#the-build-sequence-contract-first).
Rows above name which step implements them. Closure is the working proof —
no step is bound to a PR number.

## Deferred application-UX backlog (replaces the PR68 queue)

The operational-depth atlas
(`apps/hypervisor/application-operational-depth.json`, verified by
`apps/hypervisor/scripts/verify-hypervisor-operational-depth.mjs`) remains
valid AUDIT EVIDENCE: its per-surface censuses, daemon cross-checks, and
security notes are the record of what each surface can honestly do today.
What this file retires is its RANKED QUEUE as the primary implementation
sequence. Surface operationalization is now PULLED by contracts — each row
below is deferred and resumes only when pulled by an implemented contract:

| Surface | Status | Resumes when |
| --- | --- | --- |
| Changes (Upgrade Assistant) | deferred | pulled by an implemented improvement/challenge contract (`VerifierChallenge`, governance transitions) |
| Monitors (Automate) | deferred | pulled by automation authority the room/frontier plane exposes |
| Models (Model Catalog) | deferred | pulled by route-binding/metering contracts (Horizon 0 model-route work) |
| Designer (Solution Designer) | deferred | pulled by a real composition-write contract (Studio-owned) |
| Incidents (Issues) | deferred | pulled by an incident/finding contract (`Finding` admission) |
| Machinery | deferred | pulled by state-machine execution authority |
| Evalsuites (AIP Evals) | deferred | pulled by `Finding`/`VerifierChallenge` admission (build step 3) |
| Explorer (Object Explorer) | deferred | pulled by federated ontology versions/overlays (build step 5) |
| Marketplace (Listings) | deferred | pulled by `CapabilityOffer`/settlement contracts |

Surfaces implemented in the held stack (Approvals, Ontology Manager,
Pipeline Builder, Sources — PRs #61–#69, open and held for review, NOT yet
merged to master) keep their implementations and verifiers; nothing in this
reclassification discards them. They land per their own review gates; this
backlog governs NEW surface work only.

## Related Canon

- [`implementation-matrix.md`](./implementation-matrix.md) — per-concept durable-form index (the wider matrix).
- [`execution-horizons.md`](./execution-horizons.md) — horizon framing + the contract-first build sequence.
- [`source-of-truth-map.md`](./source-of-truth-map.md) — subject-to-owner map.
- [`../domains/ioi-ai/collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) — the room/pursuit behavior owner.
- [`../foundations/domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md) — the federated ontology / assertions / mappings / action-contracts owner.
- [`../foundations/aiip.md`](../foundations/aiip.md) — the inter-domain protocol owner.
