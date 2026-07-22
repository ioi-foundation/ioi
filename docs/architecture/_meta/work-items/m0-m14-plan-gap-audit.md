# M0-M14 Plan-Level Gap Audit

Classification: `WORK-RECORD`.
Status: non-authoritative point-in-time plan audit.
Doctrine status: reference
Implementation status: built (this audit artifact only; no product, cut, or
stage status)

This dated audit is neither architecture canon, an implementation-status
owner, nor a sequencer. It does not amend or reorder the M0-M14 program.

Sequencer read for this audit:
`internal-docs/implementation/ioi-target-end-state-master-implementation-guide.md`
from the main checkout, reconciled in this worktree on 2026-07-22. Repository
snapshot:
`origin/master` at `61eba1802992c01efa7d3188184ff315ad9d2ba0` on
2026-07-22.

Authority remains with the subject owners in
[`source-of-truth-map.md`](../source-of-truth-map.md), the contract-dependency
and claim horizons in [`execution-horizons.md`](../execution-horizons.md), the
sole internal M0-M14 sequencer above, and machine-checked status in
`ioi.program.work_item.v1` records plus
`internal-docs/implementation/program-state.json`. Observations below are
evidence at the named snapshot, not durable status claims.

## Reading rules

- **Guide demands** paraphrases the sole sequencer. It does not create a new
  sequence.
- **Canon specifies** names the owner documents and contract families already
  present in canon. A target schema or prose contract is not runtime proof.
- **Code proves** is deliberately narrow. An anchor is credited only for the
  behavior visible in that file or in a machine-checked work-item record; an
  adjacent implementation precedent is labeled as such.
- **Plan-level missing** means that the current estate lacks a machine-checked
  owner slice, a required contract-family mapping, or a cut-level exit proof.
  It does not mean the stage is activated, and it does not authorize runtime
  implementation before the sequencer's prerequisites.
- Program logs, P0 manifests, review anchors, and work-item records are
  development-workflow evidence. They are unsigned or self-declared unless an
  owner contract says otherwise. They do not grant product authority. Product
  authority remains the wallet/domain-policy path: grants, sealed intents,
  final-invoker revalidation, and receipts.
- Every proposed cut below requires a retained log containing one unambiguous
  literal `<CUT>_EXIT=<declared-success-value>`. The checker must parse that
  literal; a process exit code alone cannot close the bar.

There is one vocabulary conflict to resolve explicitly. The request calls the
new records `pending`, but `ioi.program.work_item.v1` and master-guide section
4.1 do not permit `pending`; their pre-admission value is `proposed`. The record
specifications below therefore use `status: proposed` while remaining pending
work in ordinary prose. Adding a new status value would require a user-approved
sequencer and checker change.

## Stage audit

### M0 - Program Control And Claim Lock

- **Guide demands:** one owner map and accepted-ADR snapshot; canonical delta;
  complete externally reachable route/final-invoker census; selected profile
  and nonclaims; source-plan disposition; all 58 `PG-*` mappings; evidence,
  release, blocker, and baseline records; and the complete
  `RuntimeKernelService` trust-boundary inventory.
- **Canon specifies:** documentation ownership in
  [`source-of-truth-map.md`](../source-of-truth-map.md), contract-dependency and
  claim horizons in [`execution-horizons.md`](../execution-horizons.md), and
  runtime convergence in the current daemon owners, with retired migration
  ledgers retained only as terminal provenance. These sources keep a route
  census separate from policy or authority and do not sequence M0-M14 work.
- **Code proves:** `scripts/m0-program-control.mjs` and
  `scripts/lib/m0-program-control-model.mjs` rebuild/check the committed M0
  evidence bundle. `docs/evidence/m0-program-control/m0-exit-report.json`
  contains `"m0_exit_state": "verified"` for the supplied snapshot and
  explicitly denies architecture or production-capability closure.
  [`m0-exit.v1.txt`](../../../evidence/implementation-plan-reconciliation/m0-exit.v1.txt)
  contains exactly one literal `M0_EXIT=0`, content-bound by SHA-256 to that
  committed M0 exit report; `check-work-items.mjs` and the local
  `check-program-state.mjs` validate the binding and literal rather than relying
  on process status.
  `m0-unsigned-review-anchor.v1.json` machine-records that the review chain is
  unsigned workflow evidence, not wallet authority.
- **Plan-level missing:** the M0-specific retained literal is now present and
  checked, but the generic cross-cut rule for declaring, content-binding, and
  machine-checking every future `*_EXIT=` value still lacks an admitted owner
  slice. `m0-literal-exit-evidence-contract` remains proposed for that broader
  rule. No new M0 capability or additional stage closure follows.

### M1 - Bounded-System Constitutional Core

- **Guide demands:** registered package/genesis/constitution/profile/lifecycle
  families; pure genesis compilation; wallet/daemon/Agentgres admission;
  sequence-zero roots; protected transitions; two isolated Systems from one
  package; and honest pre/post-genesis projections.
- **Canon specifies:**
  [`governed-autonomous-systems.md`](../../foundations/governed-autonomous-systems.md)
  and
  [`common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md)
  own `AutonomousSystemManifest`, genesis, sequence-zero materialization,
  constitution/amendment, active profiles, chain/operation log, lifecycle,
  oracle/evidence, finality, and enrollment families.
- **Code proves:** machine records `m1-genesis-admission`,
  `m1-sequence-zero-materialization`, and
  `m1-governed-initialize-activate` point at exact merged schemas and
  `system_genesis_routes.rs`, `system_sequence_zero_routes.rs`, and
  `system_activation_routes.rs`. They prove only their recorded cuts.
  `m1-5-protected-transitions` scopes later M1.5 work. The activation route
  explicitly emits no membership, runtime, or network effect.
- **Plan-level missing:** no work-item record owns M1.6's distinct-System
  isolation proof or M1.7's compact/advanced/read-projection proof, and neither
  has a cut-level literal exit definition. Proposed slice:
  `m1-dual-genesis-and-read-projection`.

### M2 - Deployment, Membership, Fencing, And Transition Truth

- **Guide demands:** desired deployment/failure-domain/node-role profiles
  separated from observed membership; admitted membership/role/readiness and
  catch-up records; one active-writer epoch; daemon-derived fences; final-
  invoker membership/epoch/resource/grant/effect checks; lost-suffix custody;
  rebuildable topology; route-binding lifecycle; manifest-complete backup and
  staged restore; forward-only activation; and persistent cleanup duties.
- **Canon specifies:**
  [`domain-kernels.md`](../../foundations/domain-kernels.md),
  [`governed-autonomous-systems.md`](../../foundations/governed-autonomous-systems.md),
  and the common-object owner define `AutonomousSystemDeploymentProfile`,
  `AutonomousSystemNodeMembership`, `AutonomousSystemFailoverProfile`,
  `AutonomousSystemWriterEpochTransition`, `LostSuffixRecord`,
  `ConsequentialEffectFenceContext`, `OrderingFinalityRecovery`, route-binding,
  backup, change-plan, and cleanup-obligation families. Desired and observed
  topology are distinct facts; node placement grants neither authority nor
  finality.
- **Code proves:** the registered deployment-profile-revision schema is a
  candidate contract input. `crates/agentgres/src/mux.rs` (`promote`) and
  `crates/agentgres/src/replica.rs` (`AGRS2`) prove storage-writer replication,
  catch-up, and epoch-fencing precedents only. `placement_failover_routes.rs`
  proves a cross-provider workload/provider recovery lane, not System
  membership or continuity. `environment_routes.rs` has legacy backup/snapshot
  handlers, not the canonical manifest/ChangePlan/cleanup plane. The canonical
  matrix explicitly records no public System membership/control route,
  per-System effect validator, active-fence projection, continuity witness, or
  lost-suffix mechanism.
- **Plan-level missing:** the guide's ten requirements have no machine-checked
  M2 slices or aggregate exit verifier. Proposed slices:
  `m2-membership-readiness-plane`, `m2-writer-fence-and-lost-suffix`,
  `m2-route-restore-activation-cleanup`, and
  `m2-selected-profile-exit-proof`.

### M3 - Generic Pursuit And Result Seam

- **Guide demands:** immutable `GoalRunProfile` and `WorkflowTemplate`
  releases; exact component-resolution snapshots; distinct Skill definition,
  installation, and active-set records; loop-native GoalKernel grounding;
  harness/tool resolution; generic `WorkResult`/`OutcomeDelta`; typed lifecycle,
  cancellation, archive/replay; and retained negative/inconclusive outputs.
- **Canon specifies:** the common-object owner, Hypervisor surface owner,
  default-harness owner, connector/tool owner, and daemon/Agentgres owners
  define `GoalRunProfile`, `WorkflowTemplate`, `SkillManifest`/`SkillEntry`/
  `ActiveSkillSetSnapshot`, `HarnessProfile`, `RuntimeToolContract`,
  `WorkLifecycle*`, `WorkResult`, and `OutcomeDelta`. Canon also requires simple
  work to collapse to a direct path; plurality must earn its cost.
- **Code proves:** `goalrun_routes.rs` and
  `runtime_goal_run_admission.rs` implement a narrow software-oriented GoalRun
  and RoleTopology precedent; `verify-hypervisor-goalrun-multi-harness.mjs`
  tests that bounded lane. `work_result_routes.rs` plus
  `verify-hypervisor-work-result-plane.mjs` prove generic result/delta
  admission and selected hosted-room backlinks. They do not prove immutable
  profile release/resolution, the three-way Skill split, shared lifecycle,
  archive-only replay, or a canonical direct-profile closeout.
- **Plan-level missing:** no records own the definition/resolution family, the
  result/lifecycle closeout, or an explicit direct-path preservation and M3
  exit bar. Proposed slices: `m3-pursuit-definition-resolution`,
  `m3-result-lifecycle-negative-retention`, and
  `m3-direct-path-and-exit-proof`.

### M4 - OutcomeRoom As The Flagship Bounded DAS

- **Guide demands:** compile the reusable room package through genesis into a
  stable System; bind constitution/deployment/admission/oracle/lifecycle roots;
  require `RoomAdmittedObjectBase` on children; commit and receipt every shared
  transition; keep reciprocal GoalRun membership; and expose rebuildable
  lifecycle/head/blocker/authority/cost/evidence views.
- **Canon specifies:**
  [`collaborative-outcome-pattern.md`](../../domains/ioi-ai/collaborative-outcome-pattern.md),
  the common-object owner, and the governed-System owner define OutcomeRoom as
  a package-instantiated bounded DAS above GoalRuns, with hosted admission as
  the first explicit ordering topology.
- **Code proves:** `outcome_room_routes.rs` and
  `verify-hypervisor-outcome-room-plane.mjs` prove a hosted aggregate with
  expected-revision lifecycle, reciprocal backlinks, close interlocks, and a
  typed refusal of `federated_admission`. They do not bind the room to a
  canonical package/genesis/System/constitution root set and do not prove the
  exported package-to-room-child lineage required for the M4 claim.
- **Plan-level missing:** no machine record owns the package-to-genesis room
  spine, complete child-base migration, exported lineage proof, and M4 exit.
  Proposed slice: `m4-outcome-room-system-spine`.

### M5 - Participants, Local Agents, And Shared Frontier

- **Guide demands:** challenge/key/origin/target-bound local-agent pairing;
  governed participation and leases; inventory-backed offers; pull frontier and
  claims with TTL/heartbeat/backpressure/renew/release/revoke; claim-bound
  attempts; typed findings and verifier challenges; participant/lease/root-
  bound results; portable exit; and two independently implemented clients.
- **Canon specifies:** the common-object, collaborative-pursuit, and aiagent
  endpoint owners define `LocalAgentPairingSession`,
  `RoomParticipationRequest`, `RoomParticipantLease`, resource/capability
  offers, frontier/claim leases, `Attempt`, `Finding`, `VerifierChallenge`,
  `ParticipantStateBundle`, and the room-scoped result spine. Pairing creates
  no membership, context, budget, tools, reputation, payout, or authority.
- **Code proves:** `room_participation_routes.rs`,
  `resource_capability_offer_routes.rs`, `work_frontier_claim_routes.rs`,
  `attempt_finding_routes.rs`, and `verifier_challenge_routes.rs`, with their
  named `verify-hypervisor-*.mjs` verifiers, prove bounded pieces of the hosted
  participant/frontier graph. Current code deliberately refuses non-null
  participant TTL, reassignment, federated admission, acceptance/verdict, and
  portable export where those owners are absent. `outcome_room_routes.rs`
  literally labels `ParticipantStateBundle` a later build step. There is no
  `LocalAgentPairingSession` runtime anchor and no two-independent-client exit
  harness.
- **Plan-level missing:** no record owns pairing; time/renewal/reassignment and
  the exact participant-to-result spine; portable exit/two-client proof; or an
  aggregate M5 exit. P0 is only a release-ladder row: the guide does not name
  the required verified-M3-through-M5 prerequisites, direct-path regression,
  manifest, or readiness verifier. Proposed slices: `m5-local-agent-pairing`,
  `m5-participant-frontier-result-closeout`,
  `m5-portable-exit-independent-clients`, `m5-selected-profile-exit-proof`,
  and `m5-p0-readiness-verifier`.

### M6 - Honest Product Workspaces And Application Catalog

- **Guide demands:** normalized surface definition/release/installation/
  System-interface/serving records; daemon-admitted request/tenant/policy-
  filtered catalog; honest Systems and typed Work views; Mission alias
  retirement; owner-correct Governance/Operations/Provenance/Packages; direct
  non-System creation; `UX-00`; context-safe route migration; and replaceable
  generated applications.
- **Canon specifies:**
  [`core-clients-surfaces.md`](../../components/hypervisor/core-clients-surfaces.md),
  canonical enums, ADR 0016, and each rendered object's owner define the five
  workspaces and normalized surface-record family. The compiler is a
  policy-filtered projection and cannot confer product membership or truth.
- **Code proves:** `apps/hypervisor/scripts/app-catalog.mjs` and
  `surface-registry.mjs` implement a static evidence-gated catalog precedent.
  The latter still registers `owner: "Missions"` and `/__ioi/missions`;
  `verify-hypervisor-app-parity-missions.mjs` proves that compatibility view,
  not the canonical Work/Systems migration. No daemon-admitted normalized
  binding family or request-scoped compiler exists.
- **Plan-level missing:** no work record groups the normalized compiler,
  Systems/Work truth projections, alias receipts, package/extension lifecycle,
  `UX-00`, and usability exit into a reviewable M6 cut family. Proposed slice:
  `m6-product-surface-and-typed-workspaces`.

### M7 - Local Ontology And Action Semantics

- **Guide demands:** immutable ontology versions/overlays; explicit
  challengeable crosswalk decisions; time/source/confidence/dispute-bearing
  assertions; immutable recipe/mapping versus run execution; exact semantic
  snapshots; ontology action contracts; oracle evidence at admission/effect;
  and honest uncertainty/dispute views.
- **Canon specifies:**
  [`domain-ontologies-and-data-recipes.md`](../../foundations/domain-ontologies-and-data-recipes.md),
  the common-object owner, and oracle/evidence owners define
  `OntologyVersion`, `OntologyOverlay`, `OntologyCrosswalk`,
  `SemanticMappingDecision`, `ProvenanceAssertion`, `DataRecipe`, immutable
  `ConnectorMapping`, `TransformationRun`, `OntologyActionContract`, and
  `OracleEvidenceProfile`.
- **Code proves:** `odk_routes.rs` implements mutable draft ontology/recipe
  precedents with expected-revision checks and explicitly says no real
  ontology-bound object plane is built. `connector_mapping_routes.rs`
  implements a mutable single-domain connector mapping precedent. Neither is
  the immutable/versioned cross-domain or action/oracle family.
- **Plan-level missing:** no record owns the exact semantic release/mapping/
  assertion family plus its action/runtime/oracle crossing and stage exit.
  Proposed slice: `m7-semantic-definition-action-plane`.

### M8 - Enterprise Learning And Bounded Improvement

- **Guide demands:** an admitted institutional-learning boundary and snapshots;
  pre-egress enforcement/receipts; rights-eligible export/import; provider
  removal against frozen floors; source-revocation impact; immutable
  improvement governance/Agenda/finite Campaign/frozen epoch/exposure/cutoff;
  separated Search/Judgment/Authority; target-owner proposal handoff; and a
  preserved one-shot path.
- **Canon specifies:**
  [`institutional-learning-boundary.md`](../../foundations/institutional-learning-boundary.md),
  [`bounded-recursive-improvement.md`](../../foundations/bounded-recursive-improvement.md),
  Improvement, Evaluations, Foundry, Governance, and the common-object owner
  define the learning/export/model-swap family and the optional Campaign
  family. Campaigns coordinate bounded search; they never judge, authorize, or
  mutate production.
- **Code proves:** `ioi_intelligence_routes.rs` implements a narrow direct
  improvement-proposal/simulation precedent, including freshness checks
  against proposal content and record-shaped approval/release gates.
  `verify-hypervisor-improvement-*.mjs` tests that precedent. No
  `InstitutionalLearningBoundaryProfile` runtime, general learning eligibility,
  egress receipt, provider-exit bundle, Campaign, frozen epoch, exposure
  ledger, cutoff, or evidence-claim lifecycle exists.
- **Plan-level missing:** no records own the end-to-end provider-exit demo or
  the order-zero Campaign proof and one-shot regression. Proposed slices:
  `m8-learning-boundary-provider-exit` and
  `m8-order-zero-improvement-and-direct-path`.

### M9 - Single-Node Undeniable Product Proof

- **Guide demands:** verified M1-M8 and terminal selected routes; compact and
  advanced inputs producing identical hashes; distinct sovereign-local and
  managed-optionality authority lanes; one coding-agent plus one MCP attach;
  exact result/effect path; restart/substitution/revocation/rollback/retry
  faults; immutable offline evidence; first-operator study; signed lifecycle
  and recovery; and claim publication bounded to evidence.
- **Canon specifies:** the sovereign-local completeness profile, Hypervisor
  product/operator owners, wallet authority owners, Platform Operability,
  daemon/Agentgres proof owners, and runtime/tool/MCP owners. Authentication is
  not authority. The local lane may use locally permitted nonportable
  exact-effect authority; portable delegated authority and passkey review are
  additional managed-overlay obligations.
- **Code proves:**
  `docs/conformance/hypervisor-core/sovereign-local-completeness-matrix.v1.json`
  and `scripts/lib/sovereign-local-completeness-matrix.mjs` machine-check a
  target matrix, not an end-to-end runner. On the audited master,
  `lifecycle_routes.rs` calls workflow-edit approval a "lighter,
  proposal-scoped decision" and mutates after that record decision; it does not
  implement the guide's claimed exact-action grant -> final invoker ->
  WorkResult -> OutcomeDelta chain. No `EnforcementCoverageDeclaration` occurs
  in tracked canon or code at this snapshot. The narrower workflow-edit tests
  prove proposal approval/idempotency only.
- **Plan-level missing:** no records own either terminal authority lane, the
  declared native/MCP equivalence and coverage proof, or the complete lifecycle/
  evidence/operator exit. In addition, `EnforcementCoverageDeclaration` has no
  canonical owner, contrary to the guide stop rule for ownerless contracts.
  Proposed slices: `m9-sovereign-local-terminal-journey`,
  `m9-managed-optionality-overlay`,
  `m9-authority-gateway-equivalence-and-coverage`, and
  `m9-lifecycle-evidence-operator-proof`. Owner resolution is a sequencer
  amendment candidate below; no M9 claim may be inferred from the existing
  workflow-edit precedent.

### M10 - Two-Failure-Domain Continuity

- **Guide demands:** attest/admit a candidate node; restore/catch up and verify
  roots, watermarks, temporal/key/revocation floors and readiness; inject
  writer/node/link/storage/witness/restart faults; reconcile work; policy-
  controlled promotion and new epoch; fence the old writer; drain/remove; prove
  RPO/RTO and lost-suffix behavior; and render honest topology/recovery
  evidence.
- **Canon specifies:** the governed-System and domain-kernel continuity gate
  over the M2 deployment/membership/failover/writer/lost-suffix/fence families.
  One `system_id`, constitution, authority boundary, and truth path must survive;
  replication is neither consensus nor useful-distribution proof.
- **Code proves:** Agentgres static replication/catch-up and storage-writer
  promotion/fencing are implementation precedents in `crates/agentgres/`.
  `placement_failover_routes.rs` is a provider/workload failover lane. Neither
  proves admitted System membership, two failure domains, unchanged authority,
  external continuity floors, active-work reconciliation, or zero dual
  accepted effects.
- **Plan-level missing:** no M10 work record binds the M2 contracts to a
  two-failure-domain fixture, declared fault model, RPO/RTO thresholds,
  outside-rollback-domain floors, product projection, and literal exit. Proposed
  slice: `m10-two-failure-domain-continuity`.

### M11 - Useful Same-System Distributed Work And Embodied Pre-Live Proof

- **Guide demands:** bind GoalRun/roles/work/offers/assignments to admitted
  membership; allocation leases, watermarks, epochs, backpressure,
  reassignment/rebalance/rejoin; distributed fault and ambiguous-effect
  handling; freeze the embodied contract family; compile one graph across
  `micro`/`edge`/`site`; transactional prepare/activate; simulation/SIL/HIL/
  shadow; local veto/e-stop; fenced fleet allocation/reservation; and the full
  timing/partition/takeover fault matrix.
- **Canon specifies:** `RuntimeAssignment`, GoalRun/RoleTopology/claim/resource
  leases, and the native Embodied Runtime owner define same-System work.
  [`embodied-runtime.md`](../../components/daemon-runtime/embodied-runtime.md)
  owns graph/profile/stream/action/supervisor/activation/unit/group/fleet/
  reservation contracts; Physical Action Safety owns safety; Foundry owns
  experiment execution. Placement never grants authority, and AIIP is not used
  inside one `system_id`.
- **Code proves:** the narrow GoalRun route can select a RoleTopology, but no
  canonical `RuntimeAssignment` admission/reconcile plane exists.
  `runtime_physical_action_intent_admission.rs` is a pure validation precedent
  with no mounted physical-execution route, owner resolution, supervisor,
  hardware adapter, or durable effect state. No graph compiler,
  `LocalControlSupervisor`, fleet-allocation/reservation, or same-System
  multi-node proof exists.
- **Plan-level missing:** no records own useful distributed-work assignment and
  reconciliation, the embodied graph/compiler plus staged non-live proof, or
  one aggregate selected-profile verifier for the guide's M11 exit proof.
  Proposed slices: `m11-useful-same-system-distribution`,
  `m11-embodied-nonlive-graph-proof`, and
  `m11-selected-profile-exit-proof`.

### M12 - AIIP Federation Contract

- **Guide demands:** policy-bound discovery; exact-root CollaborationTerms;
  accept/counter/decline/expiry/non-retroactive amendment; semantic/action
  profile negotiation; signed/sequenced/idempotent restricted refs; external
  standards bindings; explicit hosted/federated ordering/conflict/failover;
  independent challenge/acceptance/contribution/dispute/revocation/exit.
- **Canon specifies:** [`aiip.md`](../../foundations/aiip.md), the common-object
  owner, collaborative-pursuit owner, semantic owner, authority/proof/dispute/
  settlement owners define `AIIPEnvelope`, bilateral `AIIPChannel`, external
  protocol bindings, CollaborationTerms proposal/response payloads,
  `OutcomeRoomDiscovery`, participation/lease/frontier/result packets,
  `ParticipantStateBundle`, and federated admission. AIIP is only between
  distinct independently governed Systems; each admits its own truth and can
  decline.
- **Code proves:** no `AIIPEnvelope`, `AIIPChannel`, CollaborationTerms, or
  external-binding runtime type/route exists in `crates/`. Hosted room and
  participation routes explicitly return `outcome_room_federated_unavailable`,
  `room_participation_federated_unavailable`, and discovery/signature/
  portable-state unavailable results. Architecture-document checks protect the
  sovereignty wording; they are not a channel/router or federation proof.
- **Plan-level missing:** no records own channel enrollment/version/profile
  negotiation and per-profile root/receipt conformance; terms/discovery/
  semantic negotiation; federated room ordering, portable exit, standards
  adapters, and recovery; or the aggregate M12 exit proof consumed by M13.
  Proposed slices: `m12-aiip-channel-envelope-profile`,
  `m12-terms-discovery-semantic-negotiation`,
  `m12-federated-admission-portable-exit-and-bindings`, and
  `m12-selected-profile-exit-proof`. The guide does not name the
  channel/version/conformance slice explicitly; see the sequencer amendment
  candidate.

### M13 - Two-Sovereign Internet-Of-Intelligence Proof

- **Guide demands:** independently operate a customer/data-owner System and a
  coordinator/worker System, then add an independent provider or verifier;
  freeze outside options, private valuation method, cost/risk/rights/benefit;
  repeat useful cross-boundary work; preserve verification, acceptance,
  attribution, dispute, and exit; disclose subsidy and compare direct/local
  baselines; and run a safe negative-surplus decline.
- **Canon specifies:** AIIP, the governed-System conditional-cooperation owner,
  and
  [`economic-flywheel-and-pricing-boundaries.md`](../../foundations/economic-flywheel-and-pricing-boundaries.md)
  require exact-root accepted terms and positive expected surplus for every
  required party over its best permitted outside option and incremental risk/
  coordination costs. Raw valuations may remain private. Attribution is not
  allocation; traffic, node count, and receipts do not prove network value.
- **Code proves:** no two-System conformance runner, independence assessor,
  CollaborationTerms runtime, cross-domain participant-state export, surplus
  evidence bundle, or negative-control harness exists. The M0 release ladder
  and architecture-document checker contain criteria/wording only.
- **Plan-level missing:** the stage has no machine record for preregistering the
  trial, independence and outside-option eligibility, a provider-or-verifier
  criterion that is independent of both sovereign System administrations,
  privacy-preserving participant attestations, subsidy/risk accounting, or for
  executing the positive trial plus safe-decline control and portable exit.
  Both proposed proofs retain a negative fixture that substitutes a provider
  or verifier controlled by either System administration and must be rejected.
  Proposed slices:
  `m13-sovereignty-trial-preregistration` and
  `m13-two-sovereign-surplus-and-decline-proof`.

### M14 - Connected/Secured Services And Demand-Gated L1

- **Guide demands:** prove registry/rights/reputation/security/escrow/bond/
  dispute/adjudication/settlement/enrollment/exit contracts on devnet or a
  mature compatible environment; keep compatible/connected/secured exact;
  measure unrelated recurring demand, willingness to pay/bear risk, independent
  supply, attack/security budget, regulation, and alternatives; remove token
  appreciation; authorize a sovereign L1 only if it beats the compatible
  alternative; and keep credits/tokens/cash/payouts/bonds/native assets
  distinct.
- **Canon specifies:**
  [`ioi-l1-mainnet.md`](../../foundations/ioi-l1-mainnet.md),
  [`ioi-l1-contract-interfaces.md`](../../foundations/ioi-l1-contract-interfaces.md),
  enrollment, assurance, dispute, settlement, and economic owners define
  `IOINetworkEnrollment`, `NetworkServiceInvocation`, `SettlementEnvelope`,
  registry/service/bond/agreement interfaces, Standard DAS profiles, selected
  service assurance, and the native-asset gate. Compatible L0 and ordinary
  AIIP owe no fee, enrollment, L1 transaction, or token.
- **Code proves:** the registered `ioi-network-enrollment.v1` schema, fixtures,
  invariants, and generated Rust/TypeScript projections prove machine-contract
  shape only. There is no enrollment authority/persistence/transition,
  `NetworkServiceInvocation` runtime, Standard DAS/shared-security service,
  devnet service proof, demand cohort, security-economics verifier, or L1
  authorization decision. Existing consensus/networking/settlement code does
  not establish demand for these selected IOI services.
- **Plan-level missing:** no records own the devnet/compatible-environment
  service family, the preregistered unrelated-demand/security-economics proof,
  or the final compare-and-authorize decision with a default no-L1 branch.
  Proposed slices: `m14-network-service-devnet`,
  `m14-demand-security-economics`, and `m14-l1-authorization-decision`.

## Proposed `ioi.program.work_item.v1` record specifications

All records in this section are proposals only (`status: proposed`), do not
activate a stage, and remain inert until their dependencies and selected
profiles are admitted. They are materialized as individual `.v1.json` planning
records so those dependencies and proof obligations are machine checked.
Each table ID maps to `<work_item_id>.v1.json` in this directory.
`contract families` below names required owner resolution; it is not a schema
registry change. Each exit also requires the literal retained-log value
described in the reading rules.

| Proposed `work_item_id` | Stage / guide slice | Contract families and owner refs | Cut-level exit criteria | Dependencies and remaining nonclaims |
| --- | --- | --- | --- | --- |
| `m0-literal-exit-evidence-contract` | M0 / all proof bars | Work-item/evidence-index/checker workflow records; no product contract | Beyond the checked M0-specific `M0_EXIT=0`, generic enforcement rejects missing, duplicate, malformed, stale, or non-success future `*_EXIT=` literals and ignores process status; each retained log is content-bound into its evidence index | Existing checked M0 literal and evidence; broader rule remains proposed; unsigned workflow hash-chain only; grants no authority and reopens no M0 capability claim |
| `m1-dual-genesis-and-read-projection` | M1.6-M1.7 | Manifest/genesis/chain/profile roots; policy-filtered System projection | Same package produces two distinct `system_id`s with no shared live identity/lease/credential/state; compact and advanced inputs resolve identically; restart rebuilds blocker and post-genesis views | M1.1-M1.5 owner cuts; no membership, consensus, permanent Systems rail, or network claim |
| `m2-membership-readiness-plane` | M2.1-M2.2, M2.7 | DeploymentProfile, NodeMembership, FailoverProfile, role lease, readiness/catch-up/watermark/root, desired/observed projections | Admission, catch-up, drain, remove, restart/rebuild, stale-root, foreign-node, and degraded fixtures prove desired topology never fabricates observed readiness | M1 exit; no promotion, automatic failover, consensus, or useful-work distribution |
| `m2-writer-fence-and-lost-suffix` | M2.3-M2.6 | WriterEpochTransition, ConsequentialEffectFenceContext, OrderingFinalityRecovery, LostSuffixRecord, final-invoker PEP bindings | Caller-authored/stale/foreign/deposed/mismatched membership, epoch, resource, grant, root, or effect reaches zero invokers; crash/timeout retains ambiguous/lost suffix and reconciliation duty | Membership/readiness plane; no two-node continuity or automated leader election |
| `m2-route-restore-activation-cleanup` | M2.8-M2.10 | Providers and Environments owner: EnvironmentRouteBinding, HypervisorChangePlan, EnvironmentBackup manifest/artifact family, activation head, ResourceCleanupObligation | Route/TLS/owner drift fails closed; every restored byte and secret disposition verifies before apply; stale/superseded activation cannot advance; parent deletion/provider loss cannot erase cleanup duty | M2 fence plane plus artifact/secret/provider owners; no outcome recovery inferred from environment recovery |
| `m2-selected-profile-exit-proof` | M2 aggregate exit | Evidence index over all M2 families and selected final invokers | Full stale/foreign/deposed/caller-authored matrix has zero effectors; projections reconstruct with fork/gap/tamper visible; backup/activation/cleanup negatives remain visible | Prior three M2 records; single-node selected profile only; no M10 continuity claim |
| `m3-pursuit-definition-resolution` | M3.1-M3.5 | GoalRunProfile, WorkflowTemplate, SkillManifest/SkillEntry/ActiveSkillSetSnapshot, GoalGroundingLoop, HarnessProfile/Adapter, RuntimeToolContract | Two runs reuse immutable definitions without shared live state; exact component resolution freezes; replacement preserves GoalRun identity; definitions/instructions cannot execute or grant authority | Verified M2 for System-bound work; direct non-System profile preserved; no room/collective claim |
| `m3-result-lifecycle-negative-retention` | M3.6-M3.8 | WorkResult, OutcomeDelta, WorkLifecycleRecord/Projection, cancellation fanout, archive/snapshot | Non-software result passes; cancellation drains/fences/reconciles by owner; restart and archive-only replay reconstruct; invalid/negative/inconclusive/challenged output remains inspectable | Pursuit definition slice; no acceptance authority or collective pursuit |
| `m3-direct-path-and-exit-proof` | M3 exit + P0 prerequisite | Canonical degenerate/direct pursuit profile or owner-approved equivalent projection; M3 evidence index | Simple eligible work completes one direct path without forced room, plurality, Campaign, or System genesis; hard-work fan-out remains opt-in; all M3 exit clauses and direct-path regressions emit literal exit | Other M3 slices; no P0, M4 room, independent party, or production claim |
| `m4-outcome-room-system-spine` | M4.1-M4.6 | Reusable room package/release, System genesis/constitution/profile roots, RoomAdmittedObjectBase, room/GoalRun membership, transition/root/receipt spine | Export verifies package -> genesis -> System -> room -> every child; stale/wrong-System/unbound/direct-client mutation refuses; hosted aggregate cannot bypass constitution or Agentgres | M3 exit and M1/M2 System truth; hosted admission only; no external participant or federation claim |
| `m5-local-agent-pairing` | M5.1 | LocalAgentPairingSession plus adapter/profile resolution and post-pairing proposal boundary | Create/inspect/claim/complete/cancel/expire/revoke passes two client implementations; replay, origin/target/key/attempt/expiry mismatch fails; zero membership/context/budget/tool/authority granted | M4 exit and selected identity rail; pre-AIIP, proposal-only, no publication/reputation/payout |
| `m5-participant-frontier-result-closeout` | M5.2-M5.8 | Participation/lease, offers/match, frontier/claim, Attempt/Finding/Challenge, WorkResult/OutcomeDelta and authenticated time | TTL/heartbeat/renew/release/revoke/backpressure and required reassignment cases close; each result binds exact participant/claim/predecessor/root; every revoked/expired path has zero unauthorized effect/admission | Pairing where selected and M4; hosted only; acceptance/verdict/settlement remain separate owners |
| `m5-portable-exit-independent-clients` | M5.9 + exit | ParticipantStateBundle, policy-filtered export receipt, claim-release lineage, independent-client conformance | Two independently implemented clients complete pairing/admission/claim/contribution/revoke-or-retire/export; bundle verifies without hosted DB and records exclusions; all live claims release | M5 participant closeout; portability is permitted state only, not federation or payout |
| `m5-selected-profile-exit-proof` | M5 aggregate exit | M5 evidence index and adversarial matrix | Pairing never escalates; guest cannot self-admit; replay/origin/target/attempt/lease/revocation all fail closed; attribution and negative evidence survive | All M5 owner slices; no public marketplace, correctness, payout, or M9 cohort claim |
| `m5-p0-readiness-verifier` | P0 after M3-M5 | Non-authoritative P0 comparison protocol, manifest, evidence index, readiness checker | Checker consumes literal M3, M4, and M5 exits; proves direct-path regression and one controlled owner-boundary fixture; emits a hash-bound P0 manifest and literal P0 exit | Verified M3-M5 plus `m3-direct-path-and-exit-proof`; no production, claim-bearing cohort, multi-node, federation, or matched-performance claim; claim-bearing qualification remains M9-gated |
| `m6-product-surface-and-typed-workspaces` | M6.1-M6.11 | Surface definition/release/install/System-interface/serving/alias/projection, Systems/Work views, package/extension lifecycle | One registered source feeds shell/catalog/palette/context/API; policy/tenant/context negatives fail; typed aliases preserve deep context; direct subjects remain creatable; `UX-00` and frozen usability bar pass | Real M1-M5 read models; no screenshot/parity membership and no operational-depth claim for unbuilt owners |
| `m7-semantic-definition-action-plane` | M7.1-M7.8 | Ontology version/overlay/crosswalk/mapping decision/assertion, DataRecipe/ConnectorMapping/TransformationRun, OntologyActionContract, OracleEvidenceProfile | Immutable successor and exact semantic tuple tests pass; loss/uncertainty/contradiction remain visible; semantic mapping grants no authority; effect crosses tool/policy/authority/oracle PEP and receipts | M6 and System-bound M1-M5 truth; no global ontology or cross-System cooperation |
| `m8-learning-boundary-provider-exit` | M8.1-M8.6 | LearningSourceRightsClaim, InstitutionalLearningBoundaryProfile/snapshots, LearningEvidenceEligibility, LearningEgressReceipt, export bundle, ModelSwapContinuityReport | Forbidden canary stops before egress; eligible lineage exports/imports; incumbent removal meets frozen floors; seller/cross-tenant denied; source revocation triggers declared impact path | M7 and provider/data/Foundry/evaluation/rights owners; no hidden provider non-learning, equivalent quality, or weight forgetting |
| `m8-order-zero-improvement-and-direct-path` | M8.7-M8.9 | ImprovementGovernanceProfile, Agenda, Campaign, EvaluationEpoch/ExposureLedger, cutoff, evidence claim, target-owner UpgradeProposal | Fixed budgets/epoch/evaluator survive branches and restart; negative evidence retained; selection reproduces; Campaign cannot self-judge/promote/mutate; one-shot proposal path remains valid | Learning-boundary slice and owner evaluation contracts; order zero only; no recursive-seat or ignition claim |
| `m9-sovereign-local-terminal-journey` | M9 minimum lane | Local identity/session, locally permitted nonportable exact-effect authority, TemporalVerificationProfile/Evaluation, effect admission receipt, selected M1-M8 contracts | Independent operator completes package-to-effect-to-export journey; substitution/revocation/stale fence/rollback/retry has zero unauthorized or duplicate final invocations; offline reconstruction passes | Literal M1-M8 selected-profile exits, terminal selected routes and gates; no portable delegation, managed lane, multi-node, federation, physical action, or public settlement |
| `m9-managed-optionality-overlay` | M9 ordered overlay | Wallet account/session/factor/guardian/WebAuthn, request/review/presentation/ceremony/typed subject, AuthorityReviewReceipt, v3 grant/effect receipt | Principal/session/origin/request/representation/ceremony/subject/grant substitutions all refuse; recovery preserves no grant; same System completes attach and detach without hidden dependency | Sovereign-local terminal exit first; portable authority claimed only for this overlay; no blanket passkey-understanding claim |
| `m9-authority-gateway-equivalence-and-coverage` | M9.3-M9.4 | Owner-resolved coverage declaration/evidence schema, RuntimeToolContract, MCP gateway requirement/profile, local authority/grant, effect/result/delta spine | Declared coding agent and MCP server converge on same PEP/final invoker; allow once and every selected refusal reaches zero calls; coverage facts and uncovered seams are mechanism-bound and exported | Canon owner resolution for coverage artifact; selected M3-M5 contracts; no universal interception, opaque-runtime, or endpoint-wide claim |
| `m9-lifecycle-evidence-operator-proof` | M9.5-M9.9 | Evidence index, receipt checkpoint/proof bundle, installer/updater, backup/restore/change plan, cleanup obligation, retirement, usability protocol | Restart/provider removal/signed update/rollback/restore/cleanup/archive/uninstall/retire and first-operator metrics pass; integrity, valid-as-of, and currentness remain distinct | Other M9 slices and applicable `PG-*`; no production SLA beyond actually closed gates |
| `m10-two-failure-domain-continuity` | M10.1-M10.7 | M2 deployment/membership/failover/writer/lost-suffix/fence families, checkpoints/log/root/watermark/floor, continuity receipts | Two declared failure domains preserve one System identity/constitution/owners/finality profile; injected faults produce no dual accepted effects; RPO/RTO/lost suffix are measured; drain/remove/restart reconstruct | M9 and M2 exits; operator-controlled promotion unless separately proven; no useful distribution, consensus, authority expansion, or federation |
| `m11-useful-same-system-distribution` | M11.1-M11.4 | Common Objects, Domain Kernels, and Governed Autonomous Systems owners: RuntimeAssignment, RoleTopology, work/resource/capability/claim leases, watermarks/coordination epochs, reconciliation receipts | Complementary roles complete across admitted nodes; placement grants no authority; worker/coordinator/node/link/partition faults yield declared continue/pause/reassign/fail-closed states with no duplicate effect | M10; one `system_id` only; no AIIP, independent-party, or physical-live claim |
| `m11-embodied-nonlive-graph-proof` | M11.5-M11.10 | Embodied units/groups, native profiles, graph/stream/action/supervisor/activation, fleet allocation, spacetime reservation, assurance case and physical receipts | One exact graph compiles across micro/edge/site; prepare/commit-or-abort and restart-unarmed hold; sim/SIL/HIL/shadow fault matrix proves one writer, local veto/e-stop, fenced takeover and rejoin | Relevant frozen safety/embodied contracts plus M10; evidence stays labeled non-live; no generic certification, live mission, remote final veto, or federation |
| `m11-selected-profile-exit-proof` | M11 aggregate exit | M11 evidence index plus distributed-work and embodied non-live adversarial matrices | Useful complementary work holds under unchanged authority; non-live one-writer/local-veto/fenced-takeover/rejoin clauses hold; stale, cross-System, authority-widening, duplicate-effect, mislabeled-stage, and remote-final-veto evidence is rejected | Prior two M11 slices; no live physical mission, generic certification, M12 verification, federation, or stage closure claim |
| `m12-aiip-channel-envelope-profile` | M12 channel prerequisite | AIIPChannel, AIIPEnvelope/packet payloads, version/profile/schema negotiation/governance, mandatory per-profile roots/receipts | Two distinct independently governed System endpoints enroll exact profiles; equal identities, missing endpoint decisions, version/root/signature/sequence/idempotency substitution fail; disconnect preserves local operation | `m11-selected-profile-exit-proof` and M5/M7 contracts; transport/socket/node does not establish sovereignty; no useful-value claim |
| `m12-terms-discovery-semantic-negotiation` | M12.1-M12.6 | OutcomeRoomDiscovery, CollaborationTerms proposal/response/receipt, ontology/action profiles/mapping decisions, external binding profiles | Accept/counter/decline/expiry/non-retroactive amendment and mapping-risk cases pass; discovery grants nothing; A2A/MCP/HTTP/directory completion never becomes IOI authority/verification/acceptance | AIIP channel slice; no raw private context, shared DB, settlement, or positive-surplus claim |
| `m12-federated-admission-portable-exit-and-bindings` | M12.7-M12.8 | Federated admission policy, packetized participation/frontier/result/challenge/contribution/dispute refs, ParticipantStateBundle, recovery/idempotency | Hosted/federated modes declare ordering/merge/conflict/adjudication/failover; neither peer mutates the other's truth; disconnect/decline preserves local completeness; portable exit works without host trust | Prior M12 slices; no foreign physical-control stream, economic value, network effect, or M13 claim |
| `m12-selected-profile-exit-proof` | M12 aggregate exit | M12 evidence index plus channel, terms/semantic, federated-admission, recovery, disconnect, and portable-exit conformance matrices | Each System remains locally complete; peer truth/authority mutation and foreign physical control reject; permitted participant state exits without host trust; protocol completion grants no downstream claim; retained log contains exactly one `M12_EXIT=0` | All three M12 slices; no verification, acceptance, settlement, correctness, positive-surplus, M13, or stage-closure claim |
| `m13-sovereignty-trial-preregistration` | M13.1-M13.2 | Non-product trial protocol, independent-operation and independent-provider-or-verifier evidence, exact terms roots, private-valuation attestations, outside-option/cost/risk/rights/benefit and subsidy ledger | Identities/control dependencies freeze before work, including a provider or verifier independent of both sovereign System administrations; every participant's method/outside option plus comparator/stop rules freeze; a provider/verifier controlled by either administration is a rejecting negative fixture | `m12-selected-profile-exit-proof`, independently operated Systems, and independently administered provider/verifier; protocol is workflow evidence, not authority or a cooperation claim |
| `m13-two-sovereign-surplus-and-decline-proof` | M13.3-M13.6 | AIIP work/participation/claim/result/verification/acceptance/dispute/exit families, independent-provider-or-verifier evidence, surplus report, and portable bundle | Repeated useful work crosses sovereignty without shared runtime/DB/admin and uses a provider or verifier independent of both System administrations; every required party/sponsor clears its frozen baseline; external Worker completes the lifecycle; both controlled-provider/verifier and negative-surplus fixtures reject safely | Preregistered trial and M12; disclose subsidy; no broad network effect, marketplace economics, or L1 demand claim |
| `m14-network-service-devnet` | M14.1-M14.2 | Governed Autonomous Systems, Domain Kernels, Common Objects, and IOI L1 owners: enrollment, NetworkServiceInvocation/Receipt, SettlementEnvelope, registries, rights/reputation, escrow/bond/dispute/adjudication, Standard DAS/shared-security agreements | At least selected public service families pass positive, failure, dispute, renewal/suspension/exit on devnet or compatible settlement; posture and assurance remain service-specific | Repeated M13 evidence and legal/assurance/commercial gates; no mainnet/native asset or generic safety/correctness claim |
| `m14-demand-security-economics` | M14.3-M14.4 + exit evidence | Frozen unrelated-organization cohort, demand/payment-or-risk ledger, provider/guardian/verifier supply, attack/security budget, regulatory/alternative model, zero-appreciation counterfactual | At least three unrelated organizations across two service families meet the predeclared sustained period; fees/bonds cover frozen margin; independent supply exists; result survives zero appreciation and subsidy disclosure | Network-service proof; internal traffic, L0 adoption, system/receipt count, or token speculation never qualifies as demand |
| `m14-l1-authorization-decision` | M14.5-M14.6 | Governed compare/decision record over compatible alternative, sovereignty/order/security/performance/governance/economics, asset-ledger separation and exit | Default no-L1 branch remains valid; authorization occurs only if frozen comparison passes and exit/dispute/failure already work; credits/provider tokens/cash/payouts/bonds/native asset remain disjoint | Demand/security proof and all applicable gates; no compulsory settlement, token-demand inference, or token-per-worker/run/room/node/System claim |

## SEQUENCER AMENDMENTS - explicit user approval required

None of the following text is applied by this work record. These are the only
guide-silent or guide-conflicting changes found that require editing the sole
sequencer itself. Ordinary cut decomposition above does not require a guide
change.

### SA-1 - literal exit values, not task exit codes

Reason: guide section 13.2 says a green command proves only its scope, but does
not require a retained literal `*_EXIT=` value. The current M0 artifact uses a
JSON state field rather than such a log literal.

```diff
@@ section 13.2, after "A green command proves only its actual scope."
+Every proof bar declares one literal `<BAR>_EXIT=<success-value>` contract.
+The retained log must contain exactly one unambiguous value for that bar, and
+the evidence checker must parse and content-bind it. Process exit status,
+task-runner success, or a green aggregate command never substitutes for the
+literal exit value.
```

### SA-2 - make P0 readiness an explicit M3-M5 slice

Reason: the release ladder names P0, while `program-state.json` says a readiness
verifier and manifest activate after M3-M5. The guide itself does not name
those prerequisites, direct-path preservation, artifacts, or claim ceiling.

```diff
@@ after the M5 exit proof
+#### P0 readiness activation
+
+P0 activates only after literal verified exits for the selected M3, M4, and
+M5 profiles. A dedicated readiness verifier must bind those exits, preserve a
+passing simple direct-path regression, and produce one content-bound manifest
+for a controlled owner-boundary fixture. The manifest and its unsigned
+workflow evidence grant no authority. P0 means walking skeleton only: it does
+not authorize a claim-bearing cohort, production readiness, multi-node work,
+federation, positive-surplus cooperation, or comparative performance. Any
+claim-bearing matched qualification remains gated by M9 and later stages.
```

### SA-3 - resolve `EnforcementCoverageDeclaration` ownership before M9.3

Reason: M9 treats this as schema-valid, exported evidence, but no canonical
owner or tracked contract exists at the audited snapshot. Master-guide section
13.4 requires stopping when a contract has no clear canonical owner. The owner
must be established in canon first; the guide cannot crown it.

```diff
@@ M9 Authority Gateway attach proof, before the selected proof journey
+Admission prerequisite: canon must classify and assign an owner to
+`EnforcementCoverageDeclaration`, or explicitly classify the declaration as a
+non-canonical program-evidence schema. Until that owner decision and its
+machine contract/checker land, declaration-shaped output is non-authoritative
+workflow evidence and cannot satisfy M9.3 or support prevention/coverage
+claims.
```

### SA-4 - add the missing AIIP channel/profile conformance slice

Reason: M12 requires signed/sequenced exchange and standards bindings, but it
does not explicitly schedule the bilaterally admitted channel, distinct-System
identity proof, version/profile/schema negotiation, or mandatory per-profile
root/receipt manifest that canon's AIIP open workstreams require.

```diff
@@ M12 Required work, before M12.1
+- `M12.0` admit a bilateral `AIIPChannel` only between distinct independently
+  governed System identities; negotiate exact protocol, schema, and profile
+  versions; freeze the mandatory roots and receipt obligations for each
+  selected profile; and prove signature, sequence, nonce, idempotency,
+  retry/recovery, version-substitution, and equal-identity refusals before any
+  discovery, terms, participation, or work packet is accepted;
```

### SA-5 - permit archive moves without losing stable pointers

Reason: the reconciliation request requires superseded plans to move under the
existing archive convention, while the guide currently forbids every move.
The guide wins, so this cut keeps ignored source plans in place. Approval would
allow the requested move only when history and backlinks remain recoverable.

```diff
@@ top-level Preservation rule
-Preservation rule: no source plan is deleted, moved, or stripped of detail.
+Preservation rule: no source plan is deleted or stripped of detail. A source
+classified SUPERSEDED may move under the existing `_archive/` convention only
+when its original path becomes a one-line tombstone to the owner and archive,
+all backlinks remain valid, and the preserved body is explicitly non-operative.
```

### SA-6 - make the sequencer/horizon split explicit

Reason: the guide calls itself the sole implementation sequencer but ranks
`execution-horizons.md` as owner of canonical build order. The current
non-overlapping reading is usable, but it should be made explicit before either
document is edited as if it could activate work.

```diff
@@ section 2.1, execution-horizons authority
-for canonical build order and claim horizons.
+for canonical contract dependencies and claim horizons only. It cannot
+activate, reorder, or close an implementation cut; this guide is the sole
+M0-M14 implementation sequencer.
```

### SA-7 - reconcile retired kernel migration authorities

Reason: guide section 2.3 calls the kernel unification guide and migration
matrix active canonical implementation authorities, while the tracked source
map and document-class checks classify them as archived terminal records. The
tracked canonical owners and current code already win by the guide's own
precedence; the guide should stop routing future work to retired ledgers.

```diff
@@ section 2.3 Active specialist authorities
-The first two are canonical implementation authorities.
+The first two are archived terminal provenance and cannot direct current work.
+Current daemon subject owners, checked code, the stateless implementation
+matrix, and the canon-to-code crossing index carry the live pointers.
```

### SA-8 - complete the source-disposition ledger

Reason: the guide's source ledger predates the runtime residual, the M1.5
human work log, `program-state.json`, and its checker/generator. The estate
inventory classifies them, but only the guide may add them to its disposition
ledger.

```diff
@@ section 14 source-coverage ledger
+| `runtime-kernel-namespace-residual.v1.json` | derived runtime-trust projection; regenerate and validate with its trust-audit owner |
+| `work-item-m1-5-protected-transitions.md` | preserved human work log; machine JSON record alone owns cut status |
+| `program-state.json` | ignored derived session projection; regenerate with `npm run generate:program-state` |
+| `check-program-state.mjs` / `scripts/generate-program-state.mjs` | projection validator/generator; own no stage fact |
```

### SA-9 - decide whether the PG ledger remains the one status exception

Reason: the guide assigns the hardening plan a specialized `PG-*` gate-closure
ledger, while the requested strict Status Truth Rule says all status lives in
work-item records and `program-state.json`. This cut preserves the guide's
narrow exception rather than silently deleting it. Approval would make the
rule literal and require each gate-closing cut to own a machine record.

```diff
@@ sections 2.3, 13.3, and 14.1
-`canon-mechanism-hardening-action-plan.md` owns PG gate closure status.
+`canon-mechanism-hardening-action-plan.md` owns PG definitions and required
+evidence only. The matching work-item record owns gate-closing cut status and
+points to the retained literal exit; the PG ledger is a non-status proof index.
```

### SA-10 - bound canon-to-code observations as path facts, not status

Reason: the reconciled delta checker retains only exact repository paths,
their declared `implementation | precedent` roles, and `none | partial`
anchor coverage. The guide's Status Truth Rule should explicitly distinguish
that stable crossing index from cut, object-completeness, proof, and stage
status so the delta cannot grow a live delivery narrative again.

```diff
@@ Status Truth Rule
+A machine-checked canon-to-code crossing index may state only whether an exact
+repository path exists and whether the path is an implementation anchor or an
+adjacent precedent. Its `none | partial` anchor coverage is not completeness,
+proof, cut status, stage status, priority, or activation. It must carry no
+merged, live, held, blocked, verified, dated-delivery, or next-work narrative;
+all such facts route to the owning work-item record and program-state
+projection.
```

## Evidence conflicts and uncertainties retained

1. The guide is read from the gitignored main checkout while canon/code are at
   `origin/master`. Its dated M9 implementation paragraph appears to include
   work that `program-state.json` attributes to held web-estate branch tip
   `a894b2505`, not master. This audit credits only master and leaves the guide
   discrepancy unresolved for the stateless-guide reconciliation.
2. Existing work-item records are the status owner even where their evidence
   arrays are empty. This audit did not reinterpret their status from prose or
   task exit codes.
3. Absence claims were checked against tracked Rust/JavaScript/schema paths at
   the named commit. They do not predict untracked local work or held branches.
4. The M13 surplus and M14 demand artifacts are deliberately proposed as
   workflow/evaluation evidence unless canon later promotes a durable product
   contract. They cannot become wallet authority, settlement, or public truth
   by being signed or hashed.
5. Multi-node, federated, two-sovereign, connected, secured, and L1 language in
   this record describes gated target proofs only. No such claim is made for
   the audited checkout.
