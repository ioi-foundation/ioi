# Platform Operability and Cross-Plane Failure Contract

Status: canonical architecture authority.
Canonical owner: this file for cross-plane operability, degraded-mode, recovery, and platform SRE doctrine.
Supersedes: implicit or component-local assumptions that a healthy daemon implies a healthy platform.
Superseded by: none.
Last alignment pass: 2026-07-16.
Doctrine status: canonical
Implementation status: partial (deterministic decision kernel and canonical fault matrix built; plane observers, scheduler, recovery controllers, and estate-wide probes remain planned)
Last implementation audit: 2026-07-16

## Canonical Definition

IOI operability is the ability to name, enforce, and prove which operation
classes remain safe under the current joint state of the daemon, Agentgres,
authority, storage, clock, provider, network/fleet, attestation, billing, and
public-settlement planes.

Operability is not one aggregate health boolean. A platform may remain useful
while a non-required plane is unavailable, but no failure may widen authority,
upgrade assurance, invent cost or truth, erase an unknown effect, or silently
turn bounded stale state into current state.

This owner defines the cross-plane decision contract. It does not replace any
plane's own health, truth, authority, receipt, billing, recovery, or incident
owner. Plane observations must be produced by those owners and bound to their
source head, observation time, validity window, and evidence refs. The
operability evaluator consumes those facts; it does not self-certify them.

## Plane Model

| Plane | Owns | Representative failure signals |
| --- | --- | --- |
| `daemon` | admission, mediation, execution, local control projection | process unavailable, queue saturation, dependency gate unavailable |
| `agentgres` | admitted operational truth, object heads, state roots, replay | quorum/read loss, stale head, suspected split brain, replay gap |
| `authority` | grants, revocation, delegation, policy-authority resolution | issuer unavailable, revocation freshness lost, grant verifier failure |
| `storage` | artifact and payload custody behind governed refs | object unavailable, invalid hash, restore failure, capacity exhaustion |
| `clock` | trusted time evidence for leases, expiry, ordering, and latency claims | skew outside bound, stale source, monotonicity failure |
| `provider` | selected external compute/model/service venue | endpoint unavailable, throttling, placement loss, ambiguous provider effect |
| `network_fleet` | node reachability, membership transport, coordination, and partition evidence | partition, lost quorum/peer, delayed membership state, route isolation |
| `attestation` | workload/platform evidence and appraisal freshness | stale appraisal, endorsement loss, measurement mismatch, verifier unavailable |
| `billing` | quote, hold, usage, debit, adjustment, refund, and reconciliation facts | rate-card loss, hold failure, usage-head conflict, ledger unavailable |
| `public_settlement` | optional shared-trust commitment and settlement publication | chain/finality outage, relayer failure, inclusion delay |

Canonical plane states are:

- `healthy`: the declared SLI window and evidence requirements are met;
- `degraded`: the plane remains usable only under an explicitly narrower
  contract that identifies the exact allowed operation classes and emits
  degraded-operation evidence;
- `stale`: the last observation or its bound source head is outside its
  validity window;
- `unavailable`: the owner cannot currently serve the required contract; and
- `split_brain_suspected`: mutually incompatible heads, writers, leases, or
  observations exist or cannot be ruled out.

`unknown`, missing, or malformed plane evidence is never normalized to
`healthy`. For an operation that requires the plane, it is fail-closed.

## Operation Classes

The evaluator reasons over explicit operation classes rather than product
screens or route names.

| Operation class | Minimum required planes | Canonical degraded behavior |
| --- | --- | --- |
| `proposal_only` | daemon | may continue without public settlement; the result remains a local proposal and carries no effect or settlement claim |
| `cached_read` | no live plane by definition | allowed only inside a declared maximum staleness bound and with cache age plus source head exposed |
| `consistent_read` | daemon, Agentgres, clock | stale, missing, unavailable, or split-brain truth/clock evidence fails closed |
| `truth_mutation` | daemon, Agentgres, authority, clock | required-plane degradation is explicit; stale, unavailable, or split-brain state fails closed |
| `external_effect` | daemon, Agentgres, authority, clock, network/fleet | unknown effect, authority uncertainty, stale clock, or coordination ambiguity fails closed pending reconciliation |
| `physical_bounded_continuation` | clock plus the admitted local supervisor | may continue through remote-plane loss only inside the already admitted local safety envelope; no new mission, authority, ODD, or assurance claim is admitted |
| `paid_work_start` | daemon, Agentgres, authority, clock, billing | billing loss blocks new paid work; the runtime may not invent a price, hold, or free fallback |
| `billing_finalize` | daemon, Agentgres, billing | unavailable or conflicting usage/ledger heads fail closed into reconciliation |
| `portable_assurance_export` | daemon, Agentgres, storage, clock, attestation | stale or unavailable attestation blocks the stronger portable claim |
| `public_settlement` | daemon, Agentgres, authority, clock, network/fleet, public settlement | local commitments may remain pending, but public inclusion/finality is not claimed |

Provider, storage, or cross-node planes become required whenever the concrete
operation declares them. This keeps a local proposal independent of an unused
provider while preventing a provider-backed effect from pretending the
provider was irrelevant.

## Decision Invariants

1. **Failure only narrows.** A fallback assurance posture cannot be stronger
   than the asserted posture. Missing attestation narrows the claim or blocks a
   portable assurance export.
2. **Required-plane ambiguity fails closed.** `stale`, `unavailable`,
   `split_brain_suspected`, missing evidence, or an invalid observation blocks
   the operation unless this owner explicitly defines a bounded alternative.
   `degraded` is usable only when the observation carries a nonempty degraded
   contract reference and that contract explicitly allows the requested
   operation class; generic degradation never implies generic permission.
3. **Unknown effects remain unknown.** A timeout or recovery event after an
   effect may have occurred requires preservation of attempt/effect evidence
   and reconciliation before retry, compensation, or success.
4. **Cache use is visible and bounded.** Cached state is usable only for an
   operation classified as `cached_read`, within a declared staleness maximum,
   and with cache age and source head recorded.
5. **Local physical continuation is not remote autonomy.** It requires the
   admitted `LocalControlSupervisor` and remains inside the active
   `SafetyEnvelope`, ODD, writer fence, and minimum-risk response. Remote
   control-plane loss cannot authorize new physical behavior.
6. **Billing outage cannot create free execution.** New paid work stops unless
   an already admitted offline-spend or prepaid policy explicitly owns a
   bounded reservation. Missing usage truth never becomes zero usage.
7. **Public settlement is optional but claims are exact.** A public-settlement
   outage need not stop unrelated local work. It does stop claims of public
   inclusion, finality, or settlement.
8. **A degraded result carries duties.** Every degraded or denied decision
   returns stable reason codes and the evidence, recovery, reconciliation, or
   safe-state obligations that remain outstanding.
9. **Caller claims do not become plane facts.** Requests may state requirements
   but cannot author their own health, writer, authority, attestation, billing,
   or settlement observations.

## Deterministic Decision Boundary

The built pure kernel is
[`platform_operability.rs`](../../../../crates/services/src/agentic/runtime/kernel/platform_operability.rs).
It accepts owner-produced observations and returns:

```text
available | degraded | fail_closed
  + stable reason codes
  + evidence/recovery obligations
  + effective assurance posture
  + bounded-cache usability
```

Its result is an admission input or operational projection, not a durable
source of plane truth. A caller cannot use an `available` result after any
bound observation expires, its source head changes, or a dependency required
by the concrete action becomes newly relevant.

## Plane SLI and SLO Contract

Each production plane profile must publish, at minimum:

```yaml
PlatformPlaneServiceProfile:
  plane: agentgres
  service_profile_ref: service-profile://...
  producer_ref: service://...
  failure_domain_refs: [failure-domain://...]
  dependency_plane_refs: [daemon, storage, clock]
  sli_windows:
    availability: {window: 5m, target: 0.999}
    latency: {percentile: p99, maximum_ms: 250}
    freshness: {maximum_age_ms: 1000}
    correctness: {metric_ref: metric://state-root-agreement, target: 1.0}
  saturation_thresholds:
    queue_depth: 1000
    storage_headroom_ratio: 0.20
  degraded_contract_ref: policy://platform/agentgres-degraded
  recovery_objective:
    rto_ms: 300000
    rpo_ms: 0
  observation_validity_ms: 5000
  observability_policy_ref: policy://privacy-safe-observability
```

Values are deployment-profile inputs, not universal constants. A profile must
name the measurement source, aggregation window, validity, failure domains,
and consequence of breach. A service can meet availability while failing
freshness or correctness; readiness therefore evaluates every required SLI,
not uptime alone.

## Readiness and Degraded States

Production surfaces expose at least four distinct projections:

- **process liveness**: the component can answer a minimal local probe;
- **plane readiness**: the component can satisfy its declared plane contract;
- **operation readiness**: the exact operation's required planes and evidence
  are currently eligible; and
- **system posture**: the bounded system's allowed local, cross-node,
  physical, paid, and public-settlement behaviors after policy evaluation.

A liveness probe must never be used as operation readiness. The UI and API must
render typed reasons and consequences such as `read_only`, `cached_read_only`,
`proposal_only`, `local_supervisor_only`, `no_new_paid_work`,
`reconciliation_required`, or `public_settlement_deferred`.

## Dependency and Failure-Domain Rules

- Every plane profile declares direct dependencies and independent failure
  domains. Shared region, process, datastore, KMS, identity issuer, clock
  source, network path, or operator control invalidates an independence claim.
- Correlated-failure tests target actual shared dependencies, not only one
  process at a time.
- Active/standby or multi-node service is not redundant until promotion,
  fencing, catch-up/root verification, and stale-writer refusal are proven.
- A local safety supervisor is a separate physical-action failure boundary; a
  remote daemon, model, wallet, chain, or human round trip cannot be the final
  fast-path veto.
- Provider diversity is not failure-domain diversity when routes share the
  same account, network, region, aggregator, secret issuer, or billing rail.

## Checkpoint, Backup, Restore, and Compaction

Every state-bearing plane declares:

- checkpoint cadence and exact state/head/root coverage;
- backup custody, encryption, retention, and restore authority;
- recovery-point and recovery-time objectives;
- suffix-log or journal handling after the checkpoint;
- compaction rules that preserve required proof, lineage, revocation, dispute,
  and incident evidence; and
- a restore validation procedure that recomputes the admitted state/root before
  the plane becomes ready.

A blob's existence is not restore validity. Missing or unverified suffix state
is recorded as a `LostSuffixRecord` or the owner-equivalent incident; it is not
silently accepted. Restored environment bytes do not prove reconciliation of
external, financial, physical, or provider effects.

## Key Rotation and Revocation

Key-bearing planes must support overlapping verification windows without
overlapping signing authority:

1. publish the successor key/issuer set and activation epoch;
2. prove distribution to required verifiers;
3. activate exactly one signing epoch under the owner transition rule;
4. retain old verification material for the declared receipt/proof lifetime;
5. propagate revocation snapshots and freshness bounds; and
6. fail closed when the verifier cannot establish the applicable key epoch.

Emergency revocation may narrow or stop service immediately. Recovery may not
resurrect revoked authority from a checkpoint, cache, copied receipt field, or
stale verifier process.

## Schema Rollout and Mixed Versions

Every durable contract declares `schema_version`, compatibility range, and
unknown-field/unknown-enum behavior. Rollout follows:

```text
read-old/write-old
  -> read-old-and-new/write-old
  -> read-old-and-new/write-new behind admission gate
  -> mixed-version soak with golden replay and rollback evidence
  -> stop old writes
  -> retire old reads only after retained-state migration or explicit archive support
```

Consequential paths fail with a typed upgrade requirement when peers cannot
agree on a compatible contract. They do not guess, discard unknown authority
or policy fields, or reinterpret an old enum by position. Fencing epochs,
authority bindings, information-flow labels, proof hashes, billing heads, and
safety contracts are never down-converted in a way that widens behavior.

## Proof and Billing Reconciliation

Proof reconciliation compares receipt body hash, inclusion/checkpoint proof,
signer/key epoch, state root, and revocation/appraisal freshness. A valid
signature without the required inclusion or current authority is insufficient.

Billing reconciliation compares the exact rate-card and plan versions, quote,
hold, usage head, overrun decision, final debit, and any adjustment/refund or
writeoff. Duplicate delivery with the same idempotency body is replay; the same
key with a changed body is conflict. An unavailable billing plane can preserve
already admitted local facts but cannot mint a new quote, usage record, debit,
or refund.

Reconciliation outcomes are admitted by their existing proof, billing,
Agentgres, or settlement owner. The platform-operations layer reports the duty
and readiness impact; it does not rewrite those ledgers.

## Incident Evidence and Recovery

An operability incident preserves:

- affected system, operation, plane, service profile, failure domains, and
  dependency graph;
- last known good heads/roots, plane observations, and clock evidence;
- admission, attempt, effect, authority, writer epoch, quote/hold, and receipt
  refs applicable to the failure;
- exact ambiguity: not attempted, attempted, effect known, effect unknown,
  compensated, reconciled, or irrecoverable;
- containment, fencing, safe-state, rollback, restore, replay, and manual
  admission actions;
- responsible operator/role and required deadlines; and
- closure evidence plus residual lost-suffix, disputed-effect, assurance, or
  customer-notification state.

Automatic retry is allowed only for an owner-declared replay-safe operation
with a stable idempotency binding. Unknown or consequential effects first enter
reconciliation. Physical recovery remains subject to Physical Action Safety.

## Capacity, Backpressure, and Load Shedding

- Every queue or resource pool declares capacity, reservation, saturation, and
  backpressure behavior.
- Admission rejects work before resource exhaustion invalidates latency,
  durability, safety, or cost bounds.
- Load shedding prioritizes safety, authority/revocation, receipt durability,
  incident capture, cancellation, and reconciliation over speculative or
  background work.
- Backpressure is propagated to the originating GoalRun, AutomationRun,
  WorkRun, connector, provider route, or fleet allocator as typed state; it is
  not hidden behind unbounded buffering.
- Priority cannot bypass authority, information-flow, budget, writer-fence, or
  physical-safety gates.

## Privacy-Safe Observability

Observability is evidence, not a second learning-exhaust channel. Logs, traces,
metrics, profiles, crash dumps, and incident exports must:

- carry tenant/system scope and applicable `InformationFlowLabel`;
- use allowlisted fields and bounded cardinality;
- redact or tokenize secrets, prompts, proprietary context, payload bytes,
  model outputs, memory, corrections, eval answers, and physical imagery unless
  explicitly admitted;
- bind retention, access, export, and deletion/crypto-shredding policy;
- keep operator access and declassification receipted; and
- preserve enough hashes, refs, timing, decision codes, and state heads to
  diagnose and replay without copying protected content into a global log.

Telemetry sampled for product improvement remains subject to the
`InstitutionalLearningBoundaryProfile`; operational necessity does not grant
training, distillation, cross-tenant, or provider-learning rights.

## Conformance

The canonical scheduled matrix is
[`platform-fault-matrix.v1.json`](../../../conformance/hypervisor-core/platform-fault-matrix.v1.json).
It must cover at least:

- authority loss before an external effect;
- Agentgres split-brain suspicion before truth mutation;
- bounded and expired cache reads;
- local physical continuation with and without the admitted supervisor;
- billing loss before paid work;
- public-settlement loss during unrelated local work;
- stale attestation and clock evidence;
- provider loss for provider-required work; and
- an unknown effect that cannot become success.

The conformance profile is
[`platform-operability.md`](../../../conformance/hypervisor-core/platform-operability.md).

## Current Implementation Posture and Nonclaims

Built:

- a pure Rust operation/plane decision kernel;
- stable reason and obligation codes;
- assurance narrowing, bounded-cache, unknown-effect, billing, settlement, and
  local-physical-continuation rules; and
- a canonical JSON fault matrix consumed by focused tests;
- deterministic checkpoint plus ordered-suffix replay that recomputes every
  JCS/SHA-256 state root and rejects gaps, reorder, and tamper;
- mixed-version negotiation that selects the highest compatible version or
  returns a typed upgrade/lossy-downgrade refusal;
- key-epoch transition validation requiring one active signer, successor
  distribution evidence, retained verification windows, and current
  revocation state; and
- an information-flow-label-preserving observability projection that refuses
  protected raw values and retains only allowlisted hashes or governed refs.

Not yet built or claimed:

- authoritative producers for every plane observation;
- a daemon API or scheduler-wide operation-admission choke point;
- scheduled correlated-failure injection across a deployed estate;
- integration of the reference checkpoint replay with every plane's real
  backup/restore path;
- live key distribution/activation/revocation across verifier processes;
- deployed mixed-version rollouts, billing/proof reconciliation controllers,
  or telemetry-sink canary probes;
- platform-wide SLO values for any production deployment; or
- evidence that the pure decision result alone repaired, fenced, restored, or
  reconciled a plane.

Until those seams exist, this cut proves the deterministic policy and reference
recovery/compatibility/projection mechanisms, not full production operability.

## Invariants

- **PO-1:** no failed, stale, missing, or ambiguous plane may widen authority,
  assurance, data egress, spend, physical action, or settlement claims.
- **PO-2:** every consequential operation resolves current owner-produced
  observations for its exact required planes immediately before the effect.
- **PO-3:** unknown effects remain reconciliation-required across retry,
  restart, restore, reassignment, and failover.
- **PO-4:** cached state exposes age and source head and never serves outside its
  declared operation and staleness bounds.
- **PO-5:** local physical continuation cannot exceed its already admitted
  safety envelope or create new remote authority.
- **PO-6:** recovery, compaction, mixed-version operation, and observability
  preserve the proof, privacy, authority, billing, and incident facts required
  by their canonical owners.
