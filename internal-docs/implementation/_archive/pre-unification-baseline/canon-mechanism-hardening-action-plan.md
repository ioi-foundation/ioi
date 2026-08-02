# IOI Canon Mechanism Hardening — Action Plan

> **Execution routing (2026-07-17): active specialist ledger.** This file
> remains the sole detailed definition and closure ledger for its 58 `PG-*`
> gates. Stage activation and dependency order are owned by the
> [target-end-state master guide](./ioi-target-end-state-master-implementation-guide.md).

Status: implementation plan and audited execution ledger; non-canonical  
Date: 2026-07-16  
Scope: contract compilation, cryptographic proof, information-flow security,
distributed correctness, work lifecycle, embodied assurance, commercial
mechanics, attestation, and canon operability

Canonical authority remains `docs/architecture/`, especially
[`source-of-truth-map.md`](../../docs/architecture/_meta/source-of-truth-map.md)
and the subject owners named below. This plan is execution scaffolding. It does
not amend doctrine, create canonical objects, rename products, or make an
implementation claim by itself.

Primary advisory input:
[`canon-sota-improvement-review.md`](./canon-sota-improvement-review.md).
That review is evidence, not an owner or an instruction to absorb every finding.

## 1. Executive directive

Preserve IOI's current target architecture. Convert its strongest doctrine into
machine-checkable contracts, independently verifiable proofs, deterministic
distributed-system semantics, and adversarial conformance.

The next program should move from adding nouns to compiling, enforcing, and
proving the contracts already carrying the product thesis:

```text
close immediate fail-open and canon-integrity defects
  -> establish one contract registry and compiler
  -> establish canonical hashing, signing, key, and export verification
  -> carry information provenance through context into effect admission
  -> finish distributed timing, fencing, recovery, and work lifecycle physics
  -> refine existing embodied-safety owners without adding a parallel runtime
  -> finish billing, dispute, attestation, and deployment-policy mechanisms
  -> prove cross-plane failure behavior and platform operability
```

This program does not change these foundations:

- bounded autonomous systems remain the core deployment unit;
- Agentgres remains local operational truth;
- local/domain policy and applicable authority providers authorize effects;
- Hypervisor admits, enforces, executes, and receipts them;
- candidates never become authority merely by being intelligent or popular;
- same-system distributed work remains native L0;
- AIIP begins at independently governed system boundaries;
- detailed target canon may remain canonical while implementation is planned;
- Embodied Runtime remains native-first and adapter-tolerant;
- settlement and public trust remain demand-gated rather than prerequisites for
  local utility.

## 2. Success definition

The program is complete only when:

1. Implemented and consequential IOI contracts have resolvable,
   machine-validated schemas rather than independent YAML-in-Markdown copies.
2. Rust, TypeScript, SDK, CLI, and exported bundles reproduce the same object
   hashes and verify the same signed proof material.
3. Authority grants and portable assurance claims can be verified without
   trusting the process that presents them.
4. Untrusted content cannot silently compose legitimate private-context access
   and legitimate egress authority into an exfiltration path.
5. A deposed writer cannot produce a consequential accepted effect through
   Agentgres, wallet, connectors, storage, settlement, or physical actuation.
6. GoalRun and subordinate work survive retry, cancellation, crash, replay,
   compaction, and executor substitution without ambiguous state.
7. Embodied activation proves timing, assured-input, ODD, teleoperation,
   writer-fence, and safe-switch obligations at the deployment boundary.
8. Managed work has a typed quote, hold, usage, adjustment, and final-cost
   chain; adversarial value-bearing disputes have explicit incentive and
   evidence-availability mechanisms.
9. Assurance claims identify the enforcement context that produced them and
   automatically narrow when stronger attestation is unavailable.
10. Canon status, owner precedence, schema evolution, and implementation anchors
    fail visibly in CI rather than remaining prose conventions.

## 3. Review disposition

### Adopt

- machine-readable contracts and generated references;
- canonical encoding, domain-separated hashing, and portable verification;
- signed and attenuable authority grants with bounded revocation staleness;
- provenance-aware information flow and egress admission;
- distributed time, epoch, fencing, read-consistency, and lost-suffix rules;
- legal lifecycle transitions, idempotency, cancellation, and append-only loop
  history;
- focused embodied timing, sensing, ODD, teleoperation, and conformance work;
- billing and rail-scoped dispute mechanics;
- owner precedence, status registries, code-anchor checking, and schema
  evolution.

### Adapt rather than copy literally

| Review proposal | Refined IOI action |
| --- | --- |
| Sign every consequential receipt individually | Individually sign authority-bearing and portable cross-boundary objects. Protect ordinary local receipts through Agentgres commitments and signed checkpoints; exports carry inclusion and consistency material. |
| Add `RuntimeAssuranceSwitchContract` | Extend the existing `SafetyEnvelope` with monitor-period, recoverable-region/margin, and switch-test evidence. |
| Add a runtime-assurance kernel | Keep `LocalControlSupervisor` as the logical boundary and make the independently isolated safety decision module explicit inside or beneath it. |
| Require RATS/hardware identity everywhere | Make attestation assurance-profile and deployment-posture dependent. Software-only and trusted-operator postures remain valid but cannot claim hardware-rooted assurance. |
| Add one universal challenge game | Share a base challenge shape only where useful; bonds, windows, appeals, and remedies remain rail-, value-, and jurisdiction-specific. |
| Downgrade detailed future objects | Add per-object maturity, stability, and claimable conformance levels without retracting target architecture. |
| Mandate one dual-LLM implementation | Canonize the separation and information-flow property while allowing multiple conforming implementations. |

### Reject as program work

- an estate-wide mass rename;
- `GoalKernel -> GoalConductor`;
- `IOI L1 -> IOI Settlement Layer` without a separate scope ADR;
- demotion of the defined intelligent-blockchain category;
- retirement of physical `Mission` terminology used in robotics and fleet work;
- a bridge-first Embodied Runtime target;
- mandatory public transparency or public-chain anchoring for local receipts;
- mandatory hardware attestation for every valid deployment;
- bonds or arbitration around ordinary internal enterprise verification;
- splitting every large owner file before machine ownership and generation exist;
- treating any review score or named comparison as implementation evidence.

### ADR-only queue

The following may be worthwhile but are separate decisions:

- replace Type-1/Type-2/Type-3 enum slugs with explicit substrate postures;
- replace or qualify `cTEE` so software custody is not read as hardware TEE
  assurance;
- choose the long-term public form of Foundry/Capability Foundry;
- choose whether Web4 is the primary category label or a positioning layer;
- correct the AIIP expansion while preserving protocol identity;
- adopt shared naming, suffix, acronym, and collision-review rules;
- migrate invalid underscore URI schemes to canonical hyphenated schemes using
  read-side aliases and no new writes under legacy spelling.

Only the URI/ref grammar blocks the contract compiler.

## 4. Execution laws

1. **Owner first.** Amend the canonical subject owner or land an ADR before code
   treats a new rule as doctrine.
2. **One semantic source.** A schema, enum, state machine, receipt profile, or
   invariant has one machine-readable source and generated projections.
3. **Built seams first.** Formalize implemented and consequential boundaries
   before exhaustively compiling speculative families.
4. **Fail closed by risk.** Unknown impact, stale authority, unverifiable proof,
   ambiguous writer state, and missing safety evidence block at the relevant
   boundary.
5. **Local-first proof.** Local correctness never depends on public settlement.
6. **No candidate authority.** Model, worker, tool, mapping, route, improvement,
   and physical-action outputs remain proposals until their owner admits them.
7. **No parallel owner.** Extend `ReceiptEnvelope`, `AuthorityGrantEnvelope`,
   `SafetyEnvelope`, `GoalRun`, and `PhysicalStreamContract` before minting
   another family.
8. **Cross-runtime reproducibility.** Rust and TypeScript golden vectors agree
   before a hash, signature, or schema is portable.
9. **Negative proof required.** Every positive path ships with tamper, replay,
   stale, revoked, unauthorized, ambiguous, and unavailable cases.
10. **Status follows implementation.** Owner status, implementation matrix,
    code anchors, and conformance hooks change with the implementation cut.

## 5. Dependency graph

```text
Cut 0 — Immediate correctness and canon integrity
  |
  v
Cut 1 — Contract registry and compiler
  |\
  | +-----------------------------+
  v                               v
Cut 2 — Proof and authority       Cut 3 — Information-flow security
  |                               |
  +---------------+---------------+
                  v
Cut 4 — Distributed physics and work lifecycle
                  |
                  v
Cut 5 — Embodied assurance refinement
                  |
                  v
Cut 6 — Billing, dispute, attestation, deployment profiles
                  |
                  v
Cut 7 — Cross-plane failure and platform operability
```

Cut 0 can begin immediately. Cut 1 supplies the common machine form. Cuts 2 and
3 may proceed in parallel once the pilot stabilizes. Cut 5 depends on Cut 4's
timing and fencing vocabulary. Cut 6 reuses proof and transition semantics.

## 6. Cut 0 — Immediate correctness and canon integrity

### Objective

Close current fail-open and rot-green cases before building more machinery.

### Work

- Change unsimulated improvement proposals from implicit `no_simulation` allow
  to `simulation_required` outside `local_development`, unless the active
  governance profile names an exact, receipted per-kind waiver.
- Bind the simulation fingerprint to the exact target base root/revision.
- Replace the magnitude-only impact constant with a versioned policy that sees
  authority, privacy, physical, financial, security, and constitutional deltas.
- Add an anti-decomposition trigger so repeated one-shot proposals against one
  target family can require an `ImprovementCampaign`.
- Replace “newer aligned direction wins” with mapped owner, then explicit
  `Supersedes`, otherwise ADR-required conflict resolution.
- Validate architecture status values against a closed vocabulary.
- Fail on live code anchors that do not exist; move historical anchors to an
  archive/evidence field.
- Detect duplicate object, receipt, enum, and URI/ref declarations.
- Collapse the conflicting `RoutingDecisionReceipt` sketches to one owner.
- Add RFC-compatible URI-scheme grammar checks and an explicit legacy-alias
  registry before migration begins.

Primary surfaces:

- [`ioi_intelligence_routes.rs`](../../crates/node/src/bin/hypervisor_daemon_routes/ioi_intelligence_routes.rs)
- [`improvement-governance-gates.md`](../../docs/architecture/components/daemon-runtime/improvement-governance-gates.md)
- [`bounded-recursive-improvement.md`](../../docs/architecture/foundations/bounded-recursive-improvement.md)
- [`source-of-truth-map.md`](../../docs/architecture/_meta/source-of-truth-map.md)
- [`implementation-matrix.md`](../../docs/architecture/_meta/implementation-matrix.md)
- [`events-receipts-delivery-bundles.md`](../../docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md)
- [`check-architecture-docs.mjs`](../../scripts/check-architecture-docs.mjs)

### Exit gates

- An unsimulated non-waived proposal returns `simulation_required` outside local
  development.
- A report produced against target root A cannot authorize target root B.
- A forged, stale, too-broad, or wrong-kind waiver fails.
- Architecture checks fail on an invalid URI/ref, duplicate receipt, invalid
  status member, missing live anchor, or unresolved owner conflict.
- No live matrix row uses deleted `packages/runtime-daemon/**` paths as current
  anchors.

### Validation floor

```text
cargo test -p ioi-node improvement_gate_tests
node apps/hypervisor/scripts/verify-hypervisor-improvement-governance-gates.mjs
npm run check:architecture-docs
npm run hypervisor-conformance:docs
git diff --check
```

## 7. Cut 1 — Contract registry and canon compiler

### Objective

Create one resolvable machine source for contracts used by current
implementations and portable proof.

### Source form

- JSON Schema 2020-12 for JSON wire shape;
- a registry manifest for identity, owner, status, version, encoding,
  compatibility aliases, generated targets, and code anchors;
- CEL or an equivalently portable expression layer for cross-field invariants;
- generated Markdown reference blocks and Rust/TypeScript fixtures;
- checked-in positive and negative golden instances.

Initial home: `docs/architecture/_meta/schemas/`, as assigned by
[`doc-classes.md`](../../docs/architecture/_meta/doc-classes.md). Move to a
package only after multiple runtime consumers justify it.

### Pilot contracts

1. `ReceiptEnvelope` and selected receipt profiles;
2. `AuthorityGrantEnvelope`, leases, and revocation state;
3. `GoalRunProfile`, `GoalRun`, and GoalGroundingLoop transitions;
4. `RuntimeAssignment` and `HarnessInvocation`;
5. `RuntimeToolContract`, tool results, and connector-event admission;
6. `PhysicalActionIntent`, `SafetyEnvelope`, physical mission binding,
   `EmbodiedActionChunk`, and `ActuatorCommandReceipt`;
7. the quote/hold/debit family introduced in Cut 6.

Do not compile every speculative envelope in the first slice.

### Minimum registry metadata

```yaml
contract_id: schema://ioi/<family>/<name>/v1
canonical_name: PascalCaseName
canonical_owner_ref: canon://...
schema_version: ioi.<family>.<name>.v1
maturity: implemented | partial | target | research | reserved
stability: experimental | provisional | stable | deprecated
wire_format: json
canonical_encoding_profile_ref: encoding-profile://ioi/jcs-json/v1 | null
cross_field_invariant_refs: [invariant://...]
compatibility_aliases: []
generated_targets: [markdown_ref, rust_fixture, typescript_fixture]
```

The exact registry fields become canon only after the pilot proves them.

### Evolution and generation rules

- Stable schema identity is immutable; breaking changes mint successors.
- Every successor records compatibility, migration, and hash impact.
- Read-side aliases never permit new writes under retired names.
- Durable admitted objects are never silently rewritten to a successor.
- Registry/schema owns field presence, versions, and enum members; owner prose
  retains meaning and boundary rationale.
- Generated blocks are marked and never hand-edited.
- CI regenerates to a temporary directory and fails on diff.

### Exit gates

- Rust and TypeScript accept every positive fixture and reject every negative
  fixture identically.
- Generated Markdown matches checked-in reference blocks.
- Invalid enum, ref grammar, version, condition, or invariant fails predictably.
- A successor version has a tested compatibility matrix.
- The architecture checker delegates contract truth to the registry instead of
  checking hundreds of prose fragments.

## 8. Cut 2 — Cryptographic proof and authority

### Objective

Make proof and delegated authority independently reproducible across runtimes
and organizations.

### Work

- Select an initial portable JSON encoding profile based on RFC 8785 JCS.
- Define domain separation and exact signature/hash coverage per schema version.
- Publish cross-runtime vectors for numbers, Unicode, arrays, optional fields,
  extensions, and field ordering.
- Distinguish receipt body hashes from checkpoint/accumulator roots.
- Extend `AuthorityGrantEnvelope` with issuer and holder keys, audience,
  issued/not-before/expiry, parent proof, attenuating caveats, risk/resource
  restrictions, revocation epoch, schema version, body hash, and signature.
- Define signer/key discovery, rotation, revocation, and bounded-staleness rules.
- Bind consequential proof to daemon/runtime build, policy revision, workload
  identity, runtime posture, and appraisal result when required.

### Receipt protection classes

| Class | Required protection |
| --- | --- |
| Ordinary local receipt | admitted Agentgres operation and chained state root; integrity inherited through the enclosing checkpoint profile |
| Consequential local effect | body hash, exact authority/policy/writer refs, inclusion in a signed checkpoint within the declared interval |
| Portable authority or certification | individual typed signature plus issuer/key/revocation discovery |
| AIIP/cross-domain packet | object/transport signature, peer identity/version negotiation, replay protection |
| Exported bundle | signed manifest, object hashes, checkpoint inclusion/consistency material, verification instructions |
| Public transparency profile | selected public-log proofs only when active policy requires them |

### Exit gates

- Rust and TypeScript reproduce every golden hash and signature.
- Type, version, domain, payload, key, or audience substitution fails.
- Child grants narrow and never widen parents.
- Expired, revoked, wrong-holder, wrong-audience, stale, and unknown-key grants
  fail closed.
- An exported bundle verifies offline without the producer's mutable database.
- Inconsistent-checkpoint and split-view fixtures are detected.

Primary owners: common objects, events/receipts, wallet authority, Agentgres,
AIIP, and their existing conformance surfaces.

## 9. Cut 3 — Context provenance and information-flow security

### Objective

Prevent injected content from composing valid context access and valid effect
authority into an unauthorized information flow.

### Label model

Track independent axes rather than one boolean taint:

```yaml
origin: operator | admitted_artifact | connector | web | room | model | tool | external
integrity: untrusted | schema_validated | policy_admitted | independently_verified
confidentiality: public | internal | private | regulated | secret
instruction_authority: none | suggestion | operator_instruction | admitted_policy
egress_policy_ref: policy://...
purpose_and_retention_refs: []
derivation_parent_refs: []
```

Exact fields belong to the existing owners and the schema pilot.

### Work

- Propagate labels through `ContextCell`, tools, connectors, MCP, browser/web,
  rooms, memory import/export, summaries, and derived proposals.
- Add destination/data-class allowlists to `RuntimeToolContract`.
- Verify inbound webhooks, timestamps, replay windows, and idempotency before
  they can propose an event.
- Evaluate complete derivation closure before outbound messages, files,
  network, spend, deployment, or actuation.
- Block private-context + untrusted-content + egress by default unless an exact,
  receipted declassification or step-up rule admits it.
- Bind approval to the exact effect bytes and exact reviewed representation.
- Require high-risk profiles to separate untrusted semantic interpretation
  from trusted exact-effect assembly without mandating one research design.

### Exit gates

- Injection in email, web content, issue text, tool output, or room content
  cannot exfiltrate private data through an otherwise allowed connector.
- Schema-valid untrusted content does not acquire instruction authority.
- Changing approved bytes or the reviewed presentation invalidates approval.
- Governed tools without destination declarations cannot use ambient egress.
- Labels survive summarization, model substitution, memory import, and
  multi-step derivation.

Primary owners: security/privacy invariants, verifiable agency, default harness,
connector/tool contracts, portable memory, and institutional learning boundary.

## 10. Cut 4 — Distributed physics and work lifecycle

### Objective

Make failover, leases, consequential reads, retries, and cancellations obey one
explicit model across truth, authority, effects, and work state.

### Distributed physics

- Implement the canonical `TemporalVerificationProfile` and recomputable
  `TemporalValidityEvaluation`: qualify deployment-bound sources/trust roots
  and failure domains; distinguish absolute intervals, challenge freshness,
  same-boot elapsed continuity, owner epochs, status-as-of, and per-namespace
  floors; declare skew/uncertainty, heartbeat, lease TTL, renewal margin,
  revocation/holdover exposure, suspend/pause/reboot behavior, rollback domain,
  re-anchor, and wait-out assumptions. Feed the evaluation into the existing
  Platform Operability decision and final PEP; do not create a time authority
  or admit from a scalar timestamp.
- Name the durable membership/writer-epoch compare-and-swap home.
- Bind promotion to exact membership/epoch roots and require monotonic epochs.
- Verify writer/authority epochs at the resource realizing each Agentgres,
  wallet, connector, storage, deployment, settlement, and actuator effect.
- Define a small read-consistency vocabulary; consequential admission requires
  the declared current-writer posture.
- Record orphaned/lost suffixes after weaker recovery. Rejoin is re-admission
  and reconciliation, never implicit state merge.

### Work lifecycle

For `GoalRun`, GoalGroundingLoop, WorkRun, AutomationRun, HarnessInvocation,
ContextCell, and external handles:

- publish legal transition and transition-authority tables;
- make active loop phase a projection over append-only transition records;
- define uniform idempotency scope, retention, replay, and conflict behavior;
- define cancellation propagation, drain, fence, timeout, compensation, and
  ambiguous-effect treatment;
- replace unbounded mutable ref arrays with append-only children and rebuildable
  heads/projections;
- define snapshot/compaction without losing receipt lineage.

### Exit gates

- A partitioned former writer is rejected by every representative effect
  resource after promotion.
- Clock skew, delayed revocation, missing witness, and stale-read fixtures fail
  as declared.
- Two implementations agree on every legal and illegal transition.
- Same idempotency key and body returns the same result; changed body fails.
- GoalRun cancellation reaches cells, invocations, leases, provider handles,
  and effect reconciliation deterministically.
- Crash/replay reconstructs the same active phase and object head.

Primary owners: governed systems, domain kernels, Agentgres, wallet authority,
common objects, daemon doctrine/API, and effect-specific owners.

## 11. Cut 5 — Embodied assurance refinement

### Objective

Close the remaining safety-mechanism gaps while preserving current owner
boundaries and the native-first target.

### Work

- Extend `SafetyEnvelope` with monitor period/jitter, total
  observation-to-switch bound, recoverable-region/margin evidence, switch-test
  receipts, ODD-exit response, proof-test cadence, and operator takeover budget.
- Add sensor/stream assurance posture: safety-rated, independently assured,
  unassured/learned, or advisory-only.
- State explicitly that `LocalControlSupervisor` is the logical enforcement
  boundary while its monitor, switch, watchdog, recovery, and e-stop components
  retain independent isolation and may live on a safety MCU, PLC, certified
  controller, or other assured local boundary.
- Add graph-scoped timing chains for sensor-to-actuator,
  violation-to-minimum-risk, teleoperation, and remote revocation.
- Require analytic evidence for hard-real-time/safety partitions and declared
  tail-latency evidence for bounded-soft-realtime autonomy.
- Define measurable ODD attributes, monitors, exits, and degrade/stop behavior.
- Define teleoperation link class, latency/loss budget, authentication, deadman,
  arbitration, command stream, and automatic safe degradation.
- Move `PhysicalActionKind` to one shared enum; object-local lists are subsets.
- Define behavior tick/trigger, priority, preemption, halt, contingency,
  action-chunk expiry, recovery ordering, and operator insertion semantics.

### Claimable conformance

| Level | Claimable capability |
| --- | --- |
| E0 governed integration | External backend executes; IOI owns admitted identity, policy, authority binding, evidence, replay, and local supervisor contract. |
| E1 native assurance | Native or separately assured monitor/switch/recovery boundary passes timing and fault tests. |
| E2 native deterministic motion | Native deterministic execution and writer/resource fencing pass representative realtime profiles. |
| E3 native composed runtime | Micro/edge/site composition, fleet allocation, partition/rejoin, heterogeneous proof matrix, and sim-to-live lifecycle pass. |

These are evidence claims, not separate architectures. E0 remains subordinate
compatibility and does not redefine the native target.

### Exit gates

- Unassured learned sensing cannot silently become the only safety input.
- Monitor/switch/recovery remains inside derived safe margins under load/fault.
- ODD exit, teleoperation loss, stale chunks, supervisor loss, writer conflict,
  and partition produce declared safe behavior.
- Restart remains inactive and unarmed; exactly one writer reaches each actuator.
- A lower conformance level cannot imply a higher level.

Primary owners: Physical Action Safety, Embodied Runtime, common objects,
events/receipts, Foundry, and ecosystem assurance.

## 12. Cut 6 — Billing, dispute, attestation, and deployment profiles

### Managed-work billing

Implement:

```text
versioned RateCard / Plan
  -> WorkQuote
  -> CreditHold or payment authorization
  -> metered UsageRecord entries
  -> overrun decision or additional hold
  -> FinalDebit
  -> Adjustment / Refund / Writeoff
```

Quotes bind component selections, assumptions, budget owner, rate-card version,
expiry, and overrun policy. Holds are finite and idempotent. Retries do not
double-charge. Provider cost, IOI margin, verifier funding, and participant
allocation remain distinguishable. Work Credits remain product budget units,
not transferable protocol tokens.

### Verification funding and disputes

- `CollaborationTerms` names ordinary verification funding.
- Value-bearing challenges may require profile-sized bonds.
- Define challenger, respondent, evidence/response windows, timeout default,
  escalation, appeal, remedy, and bond distribution.
- Bind evidence retention/availability to the dispute window.
- Separate internal review, marketplace escrow, AIIP dispute, and public
  settlement profiles.
- Remove “deterministic arbitration” where no mechanism is named.

### Attestation profiles

- Separate Attester, Verifier/appraisal, and Relying Party roles.
- Bind nonce freshness, workload identity, endorsements/reference values,
  daemon/policy build, appraisal policy/result, and re-attestation cadence.
- Support CPU, TEE, GPU, secure-element, measured-boot, software-only, and
  trusted-operator postures without conflating them.
- Couple persistent appraisal to lease/revocation state and narrow claims when
  appraisal expires or disappears.
- `policy_declared` may support trusted-operator posture but never renders as
  measured or hardware-attested execution.

### Deployment/regulatory profiles

- Keep obligations in versioned jurisdiction/deployment packs rather than one
  global compliance claim.
- Add incident deadlines, responsible role, evidence projection, and reporting
  state where a profile requires them.
- Add crypto-shredding/erasure evidence for protected data retained in immutable
  logs or content-addressed storage.
- Never let a generated projection claim legal conformity without an authorized
  accountable issuer.

### Exit gates

- Quote, hold, debit, adjustment, and refund replay without double charge.
- Cost overrun blocks or follows the exact admitted policy.
- Challenge outcomes distribute value as their rail profile declares.
- Unavailable evidence prevents the stronger claim or triggers the declared
  default.
- Replayed nonce, changed build, stale appraisal, wrong workload, or untrusted
  endorsement fails.
- Losing hardware evidence narrows assurance rather than destroying valid local
  trusted-operator operation.

Primary owners: economics, metering, Goal Space, marketplace rails, ecosystem
assurance, runtime nodes, HypervisorOS, common objects, and events/receipts.

## 13. Cut 7 — Cross-plane failure and platform operability

### Fault matrix

Exercise correlated failure across daemon, Agentgres, authority, storage,
clock, provider, network/fleet, attestation, billing, and public settlement.
For each combination name:

- safe/available operations;
- fail-closed operations;
- usable cached state and maximum staleness;
- delayed receipts/evidence obligations;
- recovery, reconciliation, compensation, or manual admission;
- assurance claims that must narrow.

### Platform SRE contract

Define plane-specific SLIs/SLOs, dependency/failure domains, readiness and
degraded states, checkpoint/backup/restore/compaction, key rotation/revocation,
schema rollout/mixed-version behavior, proof/billing reconciliation, incident
evidence, capacity/backpressure, and privacy-safe observability.

### Exit gates

- A scheduled fault matrix has deterministic expected states.
- Correlated failure cannot widen authority or convert unknown effects to
  success.
- Checkpoint recovery reproduces admitted state and proof roots.
- Mixed versions interoperate through declared rules or fail with typed upgrade
  requirements.
- Observability does not become ungoverned learning exhaust or secret egress.

## 14. Audited execution and disposition ledger

Audit date: 2026-07-22. This ledger records the current Cuts 0–7 worktree
state. It is an implementation disposition, not an amendment to owner canon and
not a release-readiness declaration.

Disposition terms are exact:

| Disposition | Meaning |
| --- | --- |
| `reference_mechanism_complete` | The bounded contract, evaluator, kernel, adapter, or verifier named here exists and has focused positive/adversarial proof. The disposition does not imply estate-wide mounting, production persistence, authentic external evidence, or live value/effect execution. |
| `production_integration_deferred` | The gate is required before the named product, deployment, assurance, safety, billing, settlement, or recovery claim may be made. Until it closes, guarded paths must fail closed, remain typed-unavailable, or retain the narrower status documented by their owner. |
| `intentionally_out_of_scope` | The item is not a completion gate for this program or profile. Adding it requires a separate owner decision, ADR, or explicitly selected deployment profile; its absence cannot be used to weaken a completed reference mechanism. |

### 14.1 Cut execution status

| Cut | Current disposition | Completed bounded mechanism | Primary proof anchors |
| --- | --- | --- | --- |
| 0A — improvement admission | `reference_mechanism_complete` for the direct-proposal lane | Non-local unsimulated work fails closed absent an exact approved and receipted per-kind waiver; reports bind the current target base; impact is versioned and multi-axis; repeated same-family proposals trigger Campaign pressure; apply receipts retain the admitted chain. | `ioi_intelligence_routes.rs`, `improvement-governance-gates.md`, `verify-hypervisor-improvement-governance-gates.mjs` |
| 0B — canon integrity | `reference_mechanism_complete` for the checked document corpus | Closed status metadata, live implementation-ref validation, owner-map consistency, duplicate object/receipt/enum/schema checks, RFC-compatible new-write schemes, and a read-only legacy alias registry fail visibly. | `scripts/lib/architecture-docs-integrity.mjs`, `scripts/check-architecture-docs.mjs`, `scripts/fixtures/architecture-docs-checker/` |
| 1 — contract registry/compiler | `reference_mechanism_complete` for registered contracts; registry expansion remains incremental | One registry drives strict JSON Schema, portable cross-field invariants, positive/negative fixtures, and generated Rust/TypeScript projections. Registered billing, dispute, information-flow, tool, declassification, authority, receipt/proof, and physical-execution slices use this path. | `docs/architecture/_meta/schemas/`, `scripts/generate-architecture-contracts.mjs`, `scripts/check-architecture-contracts.mjs`, `scripts/test-architecture-contract-projections.mjs` |
| 2 — proof and authority | `reference_mechanism_complete` for the portable authority and receipt-proof verticals | JCS/Ed25519 authority verification, attenuation, key/revocation inputs, receipt/checkpoint/export proof, offline verification, and cross-runtime golden vectors are built. | `crates/validator/src/portable_authority.rs`, `crates/validator/src/portable_receipt_proof.rs`, `verify-authority-grant.rs`, `verify-receipt-proof.rs`, `hypervisor-conformance:proofs` |
| 3 — information flow | `reference_mechanism_complete` for the enumerated guarded seams | Labels, derivation closure, exact-effect declassification, and destination-aware tool contracts are enforced at selected connector, MCP tool, hosted-model, browser, memory, webhook, WorkResult, and OutcomeDelta seams with zero-invoker denials. | `information_flow.rs`, `information-flow-propagation.md`, `hypervisor-conformance:ifc` |
| 4A — distributed fencing | `reference_mechanism_complete` with representative live PEPs | Per-System writer-transition validation, immutable transition and active-fence projection, startup replay/repair, owner-derived fence context, and representative Agentgres/connector PEPs are built. | `distributed_fencing.rs` in services and daemon routes; `hypervisor-conformance:fencing` covers the service kernel, daemon transition/store, system-owner PEPs, Agentgres stale-primary promotion fence, and architecture docs |
| 4B — work lifecycle | `production_integration_deferred`; target contract only on this frozen base | Owner canon and target conformance specify kind-specific tables, exact-head/idempotency, typed child facts, ancestor-bound admission, disjoint reservations, cancellation, replay, and archive/snapshot lineage. The current base has no shared kernel, durable reference store, daemon route, status projection, or dedicated verifier. | `common-objects-and-envelopes.md`, `work-lifecycle.md`, `canon-to-code-delta.md`, `implementation-matrix.md` |
| 5 — embodied assurance | `reference_mechanism_complete` for admission and reference execution | Physical admission freezes the exact pre-state root and expanded unit/controller/sensor/actuator/zone/e-stop resource closure. The unmounted execution core rechecks fresh admission and typed controller identity, persists a prepared state before dispatch, freezes ambiguous crash recovery for reconciliation, distinguishes observed dispatch from proved non-dispatch, proves zero-call denial and exact replay, and emits the closed domain-separated physical-execution receipt contract. | `runtime_physical_action_intent_admission.rs`, `physical_action_execution.rs`, registered physical-execution receipt contract, `hypervisor-conformance:physical` |
| 6A — managed-work billing | `reference_mechanism_complete` as an internal accounting contract and process-local durable reference | Exact RateCard/Plan/quote/hold/usage/overrun/debit/adjustment chains, fixed-point arithmetic, owner-evidence requirements, cost separation, replay/conflict, and durable JSONL reconstruction are built. | `managed_work_billing.rs`, registered billing bundle, `hypervisor-conformance:billing` |
| 6B — dispute rails | `reference_mechanism_complete` as deterministic admission/allocation | Four distinct rail profiles bind one exact value unit, case head, evidence windows/defaults, remedy, conserved bond allocation, replay, and admission-only bundle. | `dispute_rail.rs`, registered dispute bundle, `hypervisor-conformance:disputes` |
| 6C — attestation assurance | `reference_mechanism_complete` for evaluator/startup-gate integration | RATS-role/evidence evaluation and deterministic assurance narrowing are consumed by the existing startup gate when structured input exists. | `attestation_assurance.rs`, `profile.rs`, `hypervisor-conformance:attestation` |
| 6D — deployment-policy obligations | `reference_mechanism_complete` for pure obligation projection | Versioned jurisdiction and incident inputs project clocks, reporting state, accountable roles, retention/erasure posture, and unresolved obligations without legal-conformity overclaim or external effect execution. | `deployment_policy_obligations.rs`, `hypervisor-conformance:attestation` |
| 7 — cross-plane operability | `reference_mechanism_complete` for deterministic policy, replay, version, key, and observability evaluation | The machine fault matrix produces stable availability/fail-closed decisions; companion kernels verify checkpoint/suffix replay, mixed-version refusal, single-signer key rotation, and protected observability projection. | `platform_operability.rs`, `platform_recovery.rs`, `platform-fault-matrix.v1.json`, `hypervisor-conformance:operability` |

### 14.2 Deferred production-integration gates

Every row below remains `production_integration_deferred`. Closing one row does
not close another row, and none may be inferred from a passing reference suite.
The audit records 58 open production gates: 3 in Cut 0, 3 in Cut 1, 6 in
Cut 2, 6 in Cut 3, 12 in Cut 4, 5 in Cut 5, 15 in Cut 6, and 8 in Cut 7.

#### Cuts 0–2

| Gate | Required production integration | Closure evidence |
| --- | --- | --- |
| PG-0.1 | Build the full `ImprovementCampaign` vertical: immutable governance/profile roots, Agenda/Campaign/Epoch/Exposure/Cutoff/Claim state, finite budgets, candidate/evaluator separation, negative-result retention, learning eligibility, OutcomeRoom/Foundry handoff, and target-owner proposal admission. | One target-order-0 campaign replayed from durable owner records, including adversarial exposure, evaluator, budget, and activation-separation proof. |
| PG-0.2 | Add route-level proof for anti-decomposition threshold, persisted impact assessment, exact waiver freshness, and the complete application-chain receipt. | Focused daemon verifier covers success, threshold crossing, stale base, forged/wrong-kind waiver, and receipt reconstruction. |
| PG-0.3 | Migrate persisted legacy underscore-scheme refs through explicit read aliases and canonical new writes. | Inventory reaches zero new legacy writes; each migrated family has read-old/write-new and collision fixtures. |
| PG-1.1 | Register remaining consequential pilot families, especially GoalRunProfile/GoalRun/GroundingLoop, RuntimeAssignment/HarnessInvocation, and the remaining physical-action envelope set. | Owner-approved schemas/invariants, positive/adversarial fixtures, generated projections, and runtime consumers for each promoted family. |
| PG-1.2 | Generate or mechanically verify owner-document reference blocks and adopt generated projections in additional SDK/CLI consumers where those consumers claim the contract. | Temporary regeneration produces no diff; owner prose links rather than redeclares wire fields; consumer parity tests pass. |
| PG-1.3 | Prove successor rollout, compatibility, migration, and hash impact for the first production breaking schema transition. | Mixed-version fixtures and deployed-reader/writer matrix reject undeclared downgrade or mutation. |
| PG-2.1 | Connect portable grants to real issuance, holder/audience identity, trust-root acquisition, key rotation, and bounded-staleness revocation discovery under the selected `TemporalVerificationProfile`. | Independent issuer and verifier processes pass rotation, stale/unknown key, revocation, audience, holder, uncertainty-overlap, reboot/restore, and outage probes without accepting caller-authored currentness. |
| PG-2.2 | Mount grant verification at every consequential production PEP rather than accepting copied authority fields. | Representative Agentgres, wallet, connector, storage, deployment, settlement, and actuator effects prove denial before invocation for invalid authority. |
| PG-2.3 | Emit ordinary and consequential receipts through Agentgres-owned append, scheduled signed checkpoints, and durable inclusion/consistency material. | Crash/restart and concurrent append preserve the exact checkpoint root and offline export verifies from production-emitted data. |
| PG-2.4 | Connect export verification to real signer/key/revocation discovery and bounded temporal verification windows, separating integrity, valid-as-of posture, and currentness. | Offline consumer starts without producer database access, resolves only declared immutable/trusted inputs, preserves authentic historical proof, and cannot turn an old checkpoint into current authority. |
| PG-2.5 | Add AIIP object/transport signatures, peer identity/version negotiation, and replay protection when the cross-domain transport is implemented. | Two independently governed systems exchange, reject replay/substitution, and verify the same portable proof. |
| PG-2.6 | Where a deployment explicitly selects a transparency profile, add witness/gossip or equivalent split-view detection and the selected public-log proof. | Conflicting checkpoints presented to independent observers are detected under that profile. |

#### Cut 3

| Gate | Required production integration | Closure evidence |
| --- | --- | --- |
| PG-3.1 | Carry exact labels and derivation closure estate-wide through ContextCells, summaries, model substitution, memory import/export, and every derived proposal/effect. | Cross-step fixtures cannot drop or weaken a restrictive parent and production owners supply labels instead of ambient defaults. |
| PG-3.2 | Normalize and guard MCP resources, prompts, elicitation, Tasks, and Apps; current coverage is limited to tool/list execution seams. | Each primitive has an owner mapping, untrusted-input posture, lease/authority behavior, and positive/zero-invoker negative tests. |
| PG-3.3 | Supply canonical browser IFC context from the production execution owner and enforce redirect, ambient request, response/download bytes, active/history/target-tab destinations, pointer-coordinate resolution, and general computer-use effects. | Browser/network canaries prove actual destination and returned bytes remain bound across redirects and alternate action paths. |
| PG-3.4 | Apply signed/replay-safe inbound and destination-aware outbound admission to connector families beyond the automation-webhook and current non-MCP HTTP seams. | Each promoted connector proves signature/time/nonce/idempotency plus denial immediately before its real driver. |
| PG-3.5 | Bind OutcomeRoom discussion, artifact-byte resolution, and durable label lookup/persistence without introducing a second truth owner. | Room/artifact/memory replay reconstructs the same label closure and cannot cite an unresolved or substituted label. |
| PG-3.6 | Build the institutional-learning-boundary conformance adapter and run its complete contract grade, then deployment grade for any product claim. | Deployed runner proves policy intersection, prohibited-provider/cross-tenant denial, Foundry lineage, export/import, revocation impact, and model-independence threshold. |

#### Cut 4

| Gate | Required production integration | Closure evidence |
| --- | --- | --- |
| PG-4A.1 | Build public System membership, writer-transition, failover, and promotion control APIs over owner-authorized records. | Authenticated control-plane tests cover admission, removal, promotion, stale requests, and restart. |
| PG-4A.2 | Connect automatic failure detection to an external continuity CAS/witness and the declared temporal profile, interval/uncertainty, lease, revocation, rollback-domain, and re-anchor rules; detection/evaluation must not mint promotion authority. | Partition, skew, delayed-revocation, reboot, and whole-state rollback tests show one admitted successor, a non-regressing outside-domain floor or fail-closed result, and no automatic-authority shortcut. |
| PG-4A.3 | Independently verify the active transition grant's signature, scope, expiry, revocation epoch, and issuer rather than comparing refs only. | Foreign, stale, revoked, widened, and copied-ref grants fail before transition or effect. |
| PG-4A.4 | Emit and reconcile `LostSuffixRecord` data, excluded-suffix custody, and rejoin readmission instead of implicit state merge. | Weaker recovery and rejoin fixtures preserve excluded facts and never silently accept a missing suffix. |
| PG-4A.5 | Mount owner-derived fence verification at every consequential Agentgres, wallet, connector, storage, deployment, settlement, and actuator PEP. | Estate matrix proves a deposed writer reaches zero real invokers after promotion. |
| PG-4A.6 | Deploy across independent failure domains and prove multi-node no-dual-writer behavior under partition, skew, restart, and witness loss. | Scheduled fault suite plus resource-side receipts demonstrates one effective writer or fail-closed state. |
| PG-4B.1 | Bind every GoalRun, GoalGroundingLoop, WorkRun, AutomationRun, HarnessInvocation, ContextCell, and external-handle owner write path to the shared lifecycle mechanism. Every work-owning create/attach/reattach/resume/rearm/replacement/reassignment/bound-change path must atomically validate exact ancestor and allocation heads, reject cycles and widened bounds, protect policy-required recovery/integration capacity, and commit per-dimension disjoint child reservations. | `live_owner_route_bindings` names each real adapter; route tests reconstruct the same phase/head and prove simultaneous siblings cannot inherit one remainder, stale rearm cannot reset ancestor bounds, live reassignment revalidates both ancestor chains and transfers rather than frees/duplicates responsibility and reservations, and non-authorizing dependency/evidence links confer no admission or authority. |
| PG-4B.2 | Verify owner authority/grant scope, expiry, and revocation immediately before lifecycle admission. | Wrong-owner, widened, stale, revoked, and copied-ref requests leave no transition record. |
| PG-4B.3 | Implement Agentgres-owned append and cross-process exact-head concurrency; do not introduce a daemon-local filesystem reference on this base. | Concurrent writers, crash/restart, and duplicate delivery converge without fork or lost accepted record. |
| PG-4B.4 | Emit owner events and completion receipts after durable commit, and execute cancellation drain/fence/lease-revoke/timeout/rollback/compensation/reconciliation plans with receipts. Preserve the affected authority and resource reservation until terminal/fenced proof or explicit ambiguity with funded reconciliation. | Cancellation and executor-loss fault matrices show every target terminal, fenced, or explicitly ambiguous with a funded reconciliation obligation; local process disappearance never releases the reservation or advances parent success. |
| PG-4B.5 | Automate archive selection, retention, pruning, and archive-only resume with fsync/rename/archive/snapshot/restore fault injection. | Pruned hot logs restore the identical object head, child index, idempotency map, and receipt lineage. |
| PG-4B.6 | Add mixed-version legal-table rollout/downgrade refusal and privacy filtering for future inspection APIs. | Old/new nodes agree or return typed upgrade-required; unauthorized subjects cannot enumerate private objects. |

#### Cut 5

| Gate | Required production integration | Closure evidence |
| --- | --- | --- |
| PG-5.1 | Resolve and cryptographically verify referenced deployment, stream, timing, ODD, proof-test, authority, writer, and sensor evidence rather than validating supplied bindings only. | Independent evidence-store and revocation tests reject substituted, stale, unavailable, or unsigned evidence. |
| PG-5.2 | Implement the native graph scheduler and isolated `LocalControlSupervisor` monitor/switch/watchdog/recovery/e-stop boundary with live timing, assured-input, ODD-exit, and teleoperation behavior. | SIL/HIL or deployment evidence meets declared margins and produces safe responses under load, loss, and fault. |
| PG-5.3 | Mount the execution core immediately before real native or separately assured controller adapters, including redirect, bridge, standby, restart, alternate-controller, resource-group, and controller-identity paths. | CPAS-9 bypass probes prove every denial has zero actuator calls and every accepted call uses the exact fenced controller. |
| PG-5.4 | Persist physical idempotency, predecessor heads, and the full switch/proof-test/ODD/teleop/restart/handoff/command/segment/exception/e-stop/incident receipt family through Agentgres. | Restart/crash replay cannot reinvoke a completed command or lose an unknown effect; receipts verify offline. |
| PG-5.5 | Prove claimable E1–E3 levels across representative hardware, realtime profiles, fleet partition/rejoin, and sim-to-live promotion. | Deployment-specific conformance report prevents lower-level evidence from rendering a stronger claim. |

#### Cut 6

| Gate | Required production integration | Closure evidence |
| --- | --- | --- |
| PG-6A.1 | Resolve runtime receipt identities/quantities, signed provider price schedules, supplier statements, and every route-attempt/fallback invoice line. | Invoice reconciliation ties each charged unit to owner evidence and authentic supplier statements. |
| PG-6A.2 | Move billing append authority into Agentgres transactions and add public entitlement, purchase/top-up, processor, tax, and cash-ledger integration. | Cross-process concurrency and payment-processor fixtures prevent double hold/debit and distinguish accounting from money movement. |
| PG-6A.3 | Execute participant, verifier, broker, and supplier payouts plus refunds, chargebacks, and dispute-linked corrections. | Settlement receipts and processor reconciliation prove actual value movement without rewriting usage truth. |
| PG-6A.4 | Emit daemon billing events, signed checkpoints, offline audit export, and crash/compaction/backup/restore/mixed-version/reconciliation-outage tests. | Production ledger restores exact heads and exports a verifier-independent audit chain. |
| PG-6B.1 | Persist dispute case/resolution heads in Agentgres with cross-process exact-head concurrency and stale-adjudication refusal. | Concurrent adjudicators yield one admitted head; stale/foreign decisions leave no accepted record. |
| PG-6B.2 | Independently resolve evidence availability and adjudicator authority, implement appeal/supersession, and enforce legal-hold/retention/crypto-shredding windows. | Missing/stale evidence and unauthorized adjudicators trigger the declared default or denial; appeals preserve prior lineage. |
| PG-6B.3 | Hold and release/slash real challenger/respondent bonds and execute marketplace escrow refund/payout/remedy reconciliation. | Wallet/processor receipts conserve the exact bound asset-unit and reconcile both parties. |
| PG-6B.4 | Exchange bilateral AIIP dispute packets/receipts and, only for enrolled profiles, prove public-settlement inclusion/finality. | Independent peers verify the same case; local rails remain available when public settlement is not selected. |
| PG-6B.5 | Emit required dispute, bond-distribution, remedy, and escalation receipts plus offline proof export. | Receipt bundle distinguishes admitted allocation from executed value movement and verifies independently. |
| PG-6C.1 | Add real CPU/TEE/TPM/DICE/secure-element/GPU quote drivers, atomic nonce consumption, signature/certificate verification, endorsement/reference-value resolution, and live revocation. | Vendor-backed and negative quote suites bind exact workload/build/policy and reject replay, substitution, and stale evidence. |
| PG-6C.2 | Mint/revoke attestation-bound leases, schedule re-attestation, and supply structured evidence to actual `ioi-agent` startup/degraded-operation paths. | Evidence expiry or loss narrows/stops the exact workload according to policy without inheriting a stronger label. |
| PG-6C.3 | Run deployment fault injection for quote service, endorsement, revocation, lease, clock, and hardware-evidence loss. | Startup and ongoing operation remain deterministic under correlated assurance failures. |
| PG-6D.1 | Resolve authentic jurisdiction-pack, incident-clock, reporting, erasure, retention, legal-hold, and exception inputs. | Accountable-issuer signatures and receipts prove the exact version and source of each projection input. |
| PG-6D.2 | Connect regulator-notification/reporting clients, erasure/key-destruction effectors, replica/backup scope discovery, and legal-hold enforcement. | External acknowledgements and destructive verification receipts match the projected deadlines and scope. |
| PG-6D.3 | If a product needs a legal-conformity assertion, integrate a separately authorized accountable issuer; the generated evaluator remains `not_determined`. | Issuer-specific signed claim cites the projection and applicable legal review without changing evaluator output. |

#### Cut 7

| Gate | Required production integration | Closure evidence |
| --- | --- | --- |
| PG-7.1 | Produce authenticated, owner-rooted plane observations and temporal evaluations, then mount the existing operability admission immediately before real scheduler/effect invokers. | Missing/stale/forged evidence, indeterminate expiry overlap, lost continuity floor, or imported evaluation yields zero invoker calls for each affected operation class. |
| PG-7.2 | Schedule correlated failure injection across shared daemon, Agentgres, authority, storage, clock, provider, fleet, attestation, billing, and settlement failure domains. | Actual states and obligations match the checked fault matrix. |
| PG-7.3 | Restore checkpoints/backups through each plane's real persistence engine, reconcile retained/lost suffixes, and preserve or freshly re-establish every required owner-scoped temporal/key/revocation/checkpoint floor outside the restored rollback domain. | Restored state and proof roots match the declared checkpoint; a pre-revocation whole-VM restore reaches zero consequential invokers until fresh/outside-domain currentness is established, otherwise fails with explicit loss/unavailable records. |
| PG-7.4 | Distribute and revoke signing-key epochs across real signer/verifier processes. | Rotation has one active signer, preserves the verification window, and rejects stale/revoked epochs. |
| PG-7.5 | Exercise deployed mixed-version rollout, rollback, and typed upgrade requirements. | Consequential unknown fields are never guessed or lost through downgrade. |
| PG-7.6 | Reconcile production quote/usage/debit/refund with receipt/checkpoint truth after outage and replay. | Accounting, supplier, and proof heads converge or remain explicitly disputed. |
| PG-7.7 | Define and test capacity, saturation, backpressure, and load-shed behavior for every plane, including recursive child admission, reservation shrink/expiry/transfer, and protected verification/integration/recovery capacity. | Overload narrows availability without widening authority, oversubscribing one ancestor balance, starving required recovery, or converting unknown effects to success. |
| PG-7.8 | Run end-to-end observability canaries against telemetry and learning sinks. | Protected raw content never crosses a disallowed sink; allowed projections contain only governed refs/hashes. |

### 14.3 Intentional exclusions

| Item | Disposition and consequence |
| --- | --- |
| Mandatory public-chain anchoring or public transparency for local correctness | `intentionally_out_of_scope`. A selected transparency/public-settlement profile creates its own PG-2.6 or PG-6B.4 gate; local proof does not depend on it. |
| Individual signatures on every ordinary local receipt | `intentionally_out_of_scope`. Ordinary receipts inherit integrity through Agentgres commitments and signed checkpoints; portable authority/certification remains individually signed. |
| Mandatory hardware attestation for every valid deployment | `intentionally_out_of_scope`. Software-only and trusted-operator postures remain valid when policy permits and may never render a hardware claim. |
| One universal challenge/bond/arbitration game, including ordinary internal verification | `intentionally_out_of_scope`. Rails keep distinct incentives, assets, windows, remedies, and jurisdiction; internal review remains non-bonded. |
| A bridge-first Embodied Runtime or using the reference executor as proof of a live actuator path | `intentionally_out_of_scope`. E0 compatibility is subordinate; native assurance remains the target and PG-5.2 through PG-5.5 govern production claims. |
| A stronger Merkle/RFC 6962 accumulator as a prerequisite for receipt-proof v1 | `intentionally_out_of_scope`. V1 honestly uses a linear append-only checkpoint profile; a successor requires its own ADR/schema/evolution proof. |
| Generated legal-conformity decisions | `intentionally_out_of_scope`. Projection code remains `not_determined`; only a separately accountable issuer may make the conditional PG-6D.3 claim. |
| Exhaustively compiling speculative envelopes or moving the registry into a package before consumers require it | `intentionally_out_of_scope`. Consequential built seams are compiled incrementally under their semantic owners. |
| Estate-wide renaming, `GoalKernel -> GoalConductor`, automatic `IOI L1` relabeling, demoting intelligent blockchains, or retiring physical Mission terminology | `intentionally_out_of_scope`. These require separate owner/ADR decisions and do not close a mechanism gate. |
| Type-1/2/3 slug replacement, `cTEE` qualification, Foundry public naming, Web4 positioning, AIIP expansion correction, and shared naming/collision rules | `intentionally_out_of_scope` for this implementation program and retained on the ADR-only queue. URI/ref migration is the exception already tracked by PG-0.3. |
| Parallel truth, authority, evaluator, safety, lifecycle, health, or evidence owners; mass splitting of owner files | `intentionally_out_of_scope`. Cuts extend existing owners and may refactor presentation only after machine ownership exists. |
| Treating a review score, named comparison, UI badge, provider promise, or successful model response as implementation evidence | `intentionally_out_of_scope`. Only typed mechanism and deployment proof can close a gate. |

### 14.4 Completion interpretation

The bounded reference-mechanism phase for Cuts 0–7 is complete only in the
scopes listed in Section 14.1. The program is **not production-complete** while
any applicable `PG-*` row remains open. A deployment may defer an inapplicable
conditional gate only by recording the selected profile and maintaining the
narrower nonclaim; it may not mark the underlying capability built.

Future work updates this ledger by:

1. retaining the gate ID;
2. changing its disposition only with code, owner integration, adversarial
   proof, and implementation-status evidence;
3. linking the exact closure artifact;
4. recording conditional/profile applicability; and
5. never converting an intentional exclusion into an implicit requirement
   without an owner decision or ADR.

## 15. Ownership map

| Workstream | Canonical owner families | Initial implementation/conformance surfaces |
| --- | --- | --- |
| Improvement gate | bounded improvement + daemon gates | Rust intelligence routes, Hypervisor improvement verifier |
| Contract compiler | common objects, canonical enums, doc classes, subject owners | `_meta/schemas`, architecture checker, generated Rust/TS fixtures |
| Encoding/receipts | common objects, events/receipts, Agentgres | wallet protocol, receipt conformance, SDK/CLI verifier |
| Authority | wallet.network authority owners | wallet protocol/SDK, daemon PEPs, wallet conformance |
| Information flow | security invariants, harness, connectors, learning boundary | context/tool/connector/memory gates, negative conformance |
| Distributed physics | governed systems, Agentgres, wallet, effect owners | Rust admission and provider/connector/storage/actuator PEP tests |
| Work lifecycle | common objects + daemon doctrine/API | GoalRun/WorkRun/Automation replay and cancellation tests |
| Embodied | physical safety + Embodied Runtime | activation, supervisor, Foundry SIL/HIL/fault injection |
| Billing/dispute | economics, metering, marketplace/settlement rails | billing ledger, dispute fixtures, receipt exports |
| Attestation | runtime nodes, HypervisorOS, assurance | attester/verifier fixtures, workload identity, downgrade tests |
| Operability | explicitly assigned platform-operations owner | fault matrix, restore/rotation/reconciliation tests |

No workstream creates a second truth, authority, evaluator, safety, campaign, or
lifecycle owner.

## 16. Adversarial validation matrix

| Boundary | Positive proof | Required negative proof |
| --- | --- | --- |
| Schema | all runtimes accept one golden object | missing condition, wrong enum, invalid ref, incompatible version |
| Canonical hash | Rust/TS/CLI reproduce digest | type, version, domain, number, Unicode, or payload alteration |
| Authority | valid narrowed grant admits | widened child, wrong audience/holder, expired/revoked/stale grant |
| Receipt export | offline manifest/inclusion verifies | tamper, absent inclusion, inconsistent checkpoint, unknown signer |
| Information flow | admitted public input reaches allowed destination | untrusted content exfiltrates private context or gains instruction authority |
| Failover | successor serves after valid promotion | old-writer effect, stale read, missing CAS, skew violation |
| Work lifecycle | retry/cancel/replay converges | duplicate side effect, illegal transition, orphaned invocation/lease |
| Embodied | admitted graph stays inside safety bounds | unassured safety input, late switch, ignored ODD exit, teleop loss, two writers |
| Billing | quote/hold/final cost reconcile | double debit, stale rate card, unapproved overrun, lost refund |
| Attestation | fresh appraisal binds workload | replayed nonce, changed build, stale result, self-declared hardware |
| Recovery | checkpoint restores exact state/root | missing suffix silently accepted or mixed schema guessed |

## 17. Canon and whitepaper discipline

Every accepted architectural change lands in this order:

```text
subject owner
  -> shared schema or enum
  -> events/receipts and API reference
  -> implementation matrix and execution horizon
  -> ADR when durable tradeoff history is needed
  -> code and conformance
  -> cross-owner digest/map if navigation changed
  -> whitepaper synthesis after owner canon stabilizes
```

Never update the whitepaper first and use it to override an owner. Never copy
this plan into canon wholesale. Each owner absorbs only the rule it owns.

## 18. Original first slices — audited disposition

### Slice A — Stop fail-open and rot-green behavior

Disposition: the bounded direct-proposal and architecture-integrity mechanisms
are complete. Full Campaign execution, route-level gate proof, and persisted
legacy-ref migration remain PG-0.1 through PG-0.3.

- invert unsimulated improvement admission;
- bind simulation to target base root;
- replace recency conflict resolution with owner/ADR precedence;
- reject invalid new URI/ref spellings and duplicate receipt definitions;
- fail live missing code anchors;
- land focused tests and docs conformance.

### Slice B — Contract compiler pilot

Disposition: the registry/compiler pilot and generated Rust/TypeScript fixture
path are complete for registered contracts. Remaining family promotion,
owner-reference generation, and successor rollout are PG-1.1 through PG-1.3.

- establish registry/schema metadata;
- formalize `ReceiptEnvelope` and `AuthorityGrantEnvelope` first;
- generate Rust/TypeScript projections and shared positive/adversarial fixtures;
- add schema and cross-runtime parity checks;
- normalize one small legacy URI/ref family through read aliases.

### Slice C — Portable proof vertical

Disposition: the portable authority and offline receipt-proof reference
verticals are complete. Production issuance/PEPs, Agentgres checkpoint
emission, discovery, AIIP, and selected transparency integration remain PG-2.1
through PG-2.6.

- define JCS/domain-separated body hashing;
- sign and verify `AuthorityGrantEnvelope`;
- generate one deterministic signed checkpoint fixture and authenticated proof
  artifact without claiming production Agentgres emission;
- export one receipt plus inclusion proof;
- verify through Rust, TypeScript, and CLI/offline paths;
- demonstrate tamper, revocation, wrong-audience, and inconsistent-checkpoint
  failures.

The registry may now expand one consequential owner-approved contract at a
time. A passing reference vertical does not waive the PG-1.* or PG-2.*
production gates.

## 19. Delivery and completion gate

Each slice contains:

1. one bounded objective;
2. exact owner amendment or accepted ADR;
3. schema/invariant change;
4. implementation change;
5. positive and adversarial fixtures;
6. conformance update;
7. implementation status and live-anchor update;
8. migration/compatibility disposition;
9. no unrelated rename sweep;
10. explicit remaining non-claims.

The reference-mechanism hardening phase is disposition-complete when every
completed scope has owner/schema/code/conformance evidence and every remaining
gate has a stable Section 14 disposition. Production completion is stricter:
all applicable `PG-*` rows must close with their named evidence. The current
ledger records explicit deferral; it does not claim that production condition.

## 20. Validation floor

```text
git diff --check
npm run check:architecture-docs
npm run check:runtime-layout
npm run check:wallet-protocol
npm run test:wallet-protocol
npm run hypervisor-conformance:docs
npm run hypervisor-conformance:contracts
npm run hypervisor-conformance:proofs
npm run hypervisor-conformance:ifc
npm run hypervisor-conformance:fencing
npm run hypervisor-conformance:work-lifecycle
npm run hypervisor-conformance:physical
npm run hypervisor-conformance:billing
npm run hypervisor-conformance:disputes
npm run hypervisor-conformance:attestation
npm run hypervisor-conformance:operability
npm run hypervisor-conformance:receipts
npm run hypervisor-conformance:wallet
npm run hypervisor-conformance:negative
```

Focused Rust, TypeScript, SDK, CLI, embodied simulation, billing, and fault
tests remain mandatory for their respective cuts. This list is a floor.

## 21. Reference index

Routing and status:

- [`doc-classes.md`](../../docs/architecture/_meta/doc-classes.md)
- [`source-of-truth-map.md`](../../docs/architecture/_meta/source-of-truth-map.md)
- [`implementation-matrix.md`](../../docs/architecture/_meta/implementation-matrix.md)
- [`execution-horizons.md`](../../docs/architecture/_meta/execution-horizons.md)

Core mechanisms:

- [`common-objects-and-envelopes.md`](../../docs/architecture/foundations/common-objects-and-envelopes.md)
- [`security-privacy-policy-invariants.md`](../../docs/architecture/foundations/security-privacy-policy-invariants.md)
- [`verifiable-bounded-agency.md`](../../docs/architecture/foundations/verifiable-bounded-agency.md)
- [`governed-autonomous-systems.md`](../../docs/architecture/foundations/governed-autonomous-systems.md)
- [`events-receipts-delivery-bundles.md`](../../docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md)
- [`agentgres/doctrine.md`](../../docs/architecture/components/agentgres/doctrine.md)
- [`wallet-network/doctrine.md`](../../docs/architecture/components/wallet-network/doctrine.md)

Embodied and improvement:

- [`physical-action-safety.md`](../../docs/architecture/foundations/physical-action-safety.md)
- [`embodied-runtime.md`](../../docs/architecture/components/daemon-runtime/embodied-runtime.md)
- [`bounded-recursive-improvement.md`](../../docs/architecture/foundations/bounded-recursive-improvement.md)
- [`improvement-governance-gates.md`](../../docs/architecture/components/daemon-runtime/improvement-governance-gates.md)

Commercial and assurance:

- [`economic-flywheel-and-pricing-boundaries.md`](../../docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md)
- [`ecosystem-assurance-certification-liability.md`](../../docs/architecture/foundations/ecosystem-assurance-certification-liability.md)
- [`runtime-nodes-tee-depin.md`](../../docs/architecture/components/daemon-runtime/runtime-nodes-tee-depin.md)

Standards anchors:

- [RFC 3986 — URI Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986.html)
- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/info/rfc8785/)
- [DSSE — Dead Simple Signing Envelope](https://github.com/secure-systems-lab/dsse)
- [RFC 9334 — RATS Architecture](https://www.rfc-editor.org/rfc/rfc9334.html)
- [OWASP LLM01 — Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
