# Platform Operability and Cross-Plane Failure Contract

Status: canonical architecture authority.
Canonical owner: this file for cross-plane operability, degraded-mode, recovery, and platform SRE doctrine.
Supersedes: implicit or component-local assumptions that a healthy daemon implies a healthy platform.
Superseded by: none.
Last alignment pass: 2026-07-19.
Doctrine status: canonical
Implementation status: planned (the canonical fault matrix is machine-readable target fixture data; the deterministic evaluator, plane observers, scheduler, recovery controllers, and estate-wide probes are not implemented on current master)
Last implementation audit: 2026-07-19

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

Temporal validity is likewise not one clock reading or health flag. The clock
plane qualifies time-related evidence, while authority owners still own grant,
key, revocation, and policy state; System-continuity owners still own writer
generations; proof owners still own checkpoints; and the resource-side PEP
still owns the final fence. Platform Operability may evaluate whether the
required temporal propositions are established under an admitted profile. It
cannot create current authority, promote a writer, make a checkpoint latest, or
invoke an effect.

## Plane Model

| Plane | Owns | Representative failure signals |
| --- | --- | --- |
| `daemon` | admission, mediation, execution, local control projection | process unavailable, queue saturation, dependency gate unavailable |
| `agentgres` | admitted operational truth, object heads, state roots, replay | quorum/read loss, stale head, suspected split brain, replay gap |
| `authority` | grants, revocation, delegation, policy-authority resolution | issuer unavailable, revocation freshness lost, grant verifier failure |
| `storage` | artifact and payload custody behind governed refs | object unavailable, invalid hash, restore failure, capacity exhaustion |
| `clock` | source-qualified temporal evidence for absolute bounds, elapsed duration, freshness, leases, expiry, ordering, and latency claims | uncertainty outside profile, stale or divergent source, boot/monotonicity discontinuity, rollback anchor unavailable |
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
10. **Temporal propositions remain typed.** Absolute-time bounds, response
    freshness, same-boot elapsed duration, owner epochs, status-as-of,
    non-regression floors, and resource fences are different claims. One valid
    claim never implies another.
11. **Currentness is conditional.** A signature, point timestamp, local
    high-water mark, or `clock: healthy` flag cannot establish latest or
    rollback-resistant currentness. The exact required claim must be
    established under an admitted profile immediately before use.

## Deterministic Decision Boundary

The target deterministic evaluator accepts owner-produced observations and
returns:

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

The decision embeds or references one typed `TemporalValidityEvaluation` when
the operation requires temporal claims. That evaluation reports which claims
are `established`, `indeterminate`, `failed`, or `unavailable`; it does not
itself return `admit`, `wait`, `attenuate`, or `refuse`. Platform Operability
maps the temporal results together with the other required plane observations
to `available | degraded | fail_closed`. The final authority/resource PEP
consumes that decision, rechecks its owner facts and fence, and separately owns
effect admission and invocation.

## Temporal Verification Contract

### One profile, several orthogonal claims

`TemporalVerificationProfile` is the immutable, versioned policy that declares
which temporal propositions one operation class must establish, which evidence
and failure domains are admissible, the maximum uncertainty and holdover
bounds, and the behavior required after discontinuity, restore, or
disconnection. It is a policy/profile, not a clock, time oracle, authority
grant, continuity database, or executable.

The semantic minimum is:

```yaml
TemporalVerificationProfile:
  profile_ref: policy://...
  profile_version: integer
  profile_hash: sha256:...
  applicable_operation_classes: [external_effect]
  required_claims:
    - absolute_time_interval
    - challenge_freshness
    - status_as_of
    - continuity_floor
  evidence_policy:
    admitted_source_profile_refs: [policy://...]
    required_failure_domain_separation: object
    maximum_uncertainty_ms: integer | null
    maximum_evidence_age_ms: integer | null
  continuity_policy:
    protected_namespace_floor_kinds:
      - authority_key_set
      - authority_revocation
      - receipt_checkpoint
      - owner_generation
    rollback_domain_ref: failure-domain://...
    accepted_outside_domain_anchor_classes: [string]
    reanchor_after_boot_or_restore: required | policy_bounded
  disconnected_policy:
    allowed_operation_classes: [physical_bounded_continuation]
    maximum_holdover_ms: integer | null
    maximum_revocation_exposure_ms: integer | null
    call_or_effect_budget_ref: policy://... | null
    reconnect_action: revalidate_and_reconcile | quarantine | fail_closed
  required_effect_fence_profile_ref: policy://... | null
```

This block is the canonical semantic target, not a registered wire schema.
Future portable use requires a new registered contract revision, invariants,
positive/adversarial fixtures, generated projections, and compatibility rules.
Registered authority, revocation, checkpoint, and proof-bundle v1 contracts
remain immutable.

Platform Operability owns this shared observation interface and qualification
semantics. It does not operate the underlying sources. OS/host clocks,
authenticated network-time clients, hardware counters, witness services,
ledger/finality adapters, and operator anchors are deployment- or
owner-specific producers with explicit trust roots, failure domains, and
revocation/update lifecycles. The evaluator may not produce the observation it
then treats as independent evidence.

An evaluation binds the exact profile, subject, operation, requested claims,
and owner-produced evidence:

```yaml
TemporalValidityEvaluation:
  profile_ref: policy://...
  profile_hash: sha256:...
  subject_ref: <owner-defined canonical subject reference>
  subject_hash: sha256:...
  operation_class: external_effect
  evidence_refs: [evidence://..., receipt://...]
  source_failure_domain_refs: [failure-domain://...]
  claims:
    - kind: absolute_time_interval
      status: established | indeterminate | failed | unavailable
      earliest: timestamp | null
      latest: timestamp | null
      uncertainty_ms: integer | null
      reason_codes: [string]
    - kind: challenge_freshness
      status: established | indeterminate | failed | unavailable
      challenge_ref: challenge://... | null
      maximum_age_ms: integer | null
      reason_codes: [string]
    - kind: elapsed_duration
      status: established | indeterminate | failed | unavailable
      boot_or_incarnation_ref: evidence://... | null
      lower_bound_ms: integer | null
      upper_bound_ms: integer | null
      reason_codes: [string]
    - kind: owner_epoch
      status: established | indeterminate | failed | unavailable
      namespace_ref: <owner-defined canonical namespace reference>
      epoch_kind: string
      observed_version_or_epoch: integer | null
      required_minimum_version_or_epoch: integer | null
      observed_head_hash: sha256:... | null
      reason_codes: [string]
    - kind: status_as_of
      status: established | indeterminate | failed | unavailable
      status_subject_ref: <owner-defined canonical subject reference>
      status_kind: string
      status_value_hash: sha256:... | null
      as_of: timestamp | null
      maximum_age_ms: integer | null
      reason_codes: [string]
    - kind: continuity_floor
      status: established | indeterminate | failed | unavailable
      namespace_ref: <owner-defined canonical namespace reference> | null
      floor_kind: string | null
      accepted_version_or_epoch: integer | null
      accepted_head_hash: sha256:... | null
      outside_rollback_domain_evidence_refs: [evidence://...]
      reason_codes: [string]
  temporal_posture:
    online_fresh | bounded_offline | historical_only | insufficient
  evidence_horizon:
    valid_from: timestamp | null
    valid_until: timestamp | null
  invalidation_triggers: [string]
  obligations: [string]
  evaluation_hash: sha256:...
```

The exact wire shape may group or normalize repeated claim fields, but it must
preserve their meanings and claim-specific results. A generic
`trusted_time_observed_at` field or `verified` boolean is insufficient.
The four claim results mean:

- `established`: the bound evidence satisfies that exact requested proposition
  under the selected profile and current evidence horizon;
- `indeterminate`: admitted evidence exists, but uncertainty, competing
  observations, or a boundary overlap prevents the proposition from being
  established or disproved;
- `failed`: admitted evidence establishes that the requested proposition is
  false or violates its profile; and
- `unavailable`: the required admissible evidence, source, continuity basis,
  or outside-domain anchor cannot currently be obtained.

The result is per claim. One `established` claim never fills a missing or
indeterminate sibling claim.

### Claim semantics and conservative boundaries

- **Absolute interval:** evidence yields a lower and upper bound, not a
  favorable point estimate. To establish `now >= not_before`, the lower bound
  must satisfy the owner's exact boundary rule. To establish
  `now < expires_at`, the upper bound must satisfy it. An interval overlapping
  the boundary is `indeterminate`; the PEP may refresh, wait out uncertainty,
  narrow the operation, or fail closed according to policy, but never round
  toward admission.
- **Challenge freshness:** a nonce can establish that a response followed a
  challenge within a verifier-owned window. It does not prove the underlying
  source fact was newly created or that no later revocation exists.
- **Elapsed duration:** a monotonic source establishes deltas only across the
  boot/incarnation, suspend, VM-pause, steering, drift, and reset semantics it
  names. A replayable boot identifier is not rollback evidence. Reboot,
  counter reset, replacement, or continuity loss requires re-anchoring before
  the stronger claim resumes.
- **Owner epoch:** a key-set version, revocation epoch, writer generation,
  checkpoint size, or finality height states owner-defined order. It is never
  wall time, and no global IOI epoch is created.
- **Status-as-of:** a signed key, revocation, appraisal, or provider status is
  current only through its admitted evidence horizon and refresh policy.
  Signature validity alone establishes neither freshness nor latest state.
- **Continuity floor:** non-regression is scoped to an owner namespace, kind,
  version/epoch, and exact head/hash. The floor establishes rollback resistance
  only when it survives outside the declared rollback domain or fresh
  independent evidence rebinds it after restore.
- **Effect fence:** time and continuity evidence do not replace the existing
  owner-specific `ConsequentialEffectFenceContext` or equivalent
  resource-side generation check. A former writer with otherwise valid local
  time and lease evidence still reaches zero invokers after the resource has
  accepted a higher fence.

### Rollback, restore, and disconnected operation

A verifier restored together with its clock, revocation snapshot, and local
high-water marks cannot distinguish the original past from a later rollback
using those bytes alone. Hardware counters, independently administered
services, retained remote/quorum state, selected ledger finality, witness logs,
or operator-controlled anchors may satisfy an admitted profile. None is a
universal dependency.

If the required floor is not outside the rollback domain and no fresh
independent evidence is available, the corresponding claim is
`indeterminate` or `unavailable`. Consequential current-authority operations
fail closed. Historical inspection, proposal-only work, and already admitted
physical minimum-risk continuation may remain available under their own
policies and exact nonclaims.

Disconnected operation never proves that no later revocation occurred. It may
continue only under a pre-admitted profile binding:

- an established elapsed-duration/boot-continuity basis;
- a conservative maximum holdover and revocation-exposure bound;
- exact allowed operation classes and call/effect budget;
- replay, idempotency, writer-fence, and local-safety posture; and
- mandatory revalidation and reconciliation, quarantine, or fail-closed
  behavior on reconnect, reboot, restore, or bound exhaustion.

Loss of temporal evidence cannot admit a new mission, grant, writer,
deployment, ODD, or assurance claim.

### Historical validity versus current authority

Portable verification reports at least three conclusions separately:

1. cryptographic and structural integrity;
2. validity as of a declared evidence/checkpoint horizon, when established; and
3. current key, revocation, authority, or latest-head posture.

An old receipt or checkpoint may remain authentic and historically valid while
currentness is unknown. Missing currentness must not erase valid history, and
valid history must not become current effect authority.

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

Restore and migration also hand off every required per-namespace temporal,
key-set, revocation, checkpoint, and owner-generation floor. Imported
`healthy`, `verified`, `current`, or evaluation outputs are evidence inputs,
not target-side truth. The target re-resolves the exact profile, trust roots,
authority status, temporal sources, outside-domain floors, and resource fence
before readiness. A floor that cannot be retained or freshly re-established
narrows the posture or fails closed; restore never lowers it silently.

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

Key-set and revocation epochs are owner-specific non-regression inputs, not
clocks. Their signatures prove issuer attribution and integrity. Currentness
also requires the admitted temporal evidence horizon and, when rollback is in
scope, a namespace floor outside the restored failure domain or fresh
independent revalidation.

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
Its result separately records integrity, valid-as-of horizon, and currentness;
an authentic historical proof is not rejected merely because currentness is
unknown, and it is never reused as current effect authority.

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
- the exact temporal profile/evaluation, source failure domains, uncertainty,
  boot/incarnation, evidence horizon, and retained or lost namespace floors;
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

A standalone deployment has no required telemetry, crash-reporting, support,
license-heartbeat, or update-discovery egress. Each outbound diagnostic,
profile, crash export, update check, or support bundle is separately declared
and governed by information-flow and institutional-learning policy. Its
absence cannot disable unrelated local work. An air-gapped deployment may
import signed release material through the ordinary Change Plane; imported
bytes still require the applicable verification, authority, admission,
rollback, and receipt path before activation.

The standalone startup, blocked-diagnostic, attach/detach, and dependency-
closure consequences are specified by
[`sovereign-local-completeness.md`](../../../conformance/hypervisor-core/sovereign-local-completeness.md).

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
- uncertainty spanning a grant/lease expiry;
- reboot or restore without a required temporal re-anchor;
- whole-VM rollback to a pre-revocation snapshot with and without an
  outside-domain namespace floor;
- bounded disconnected continuation and holdover exhaustion;
- an authentic historical checkpoint whose currentness is unknown;
- provider loss for provider-required work; and
- an unknown effect that cannot become success.

The conformance profile is
[`platform-operability.md`](../../../conformance/hypervisor-core/platform-operability.md).

## Current Implementation Posture and Nonclaims

This cut defines the owner contract and a canonical JSON fault matrix as
machine-readable target fixture data. Current master does not contain the
proposed cross-plane decision evaluator, checkpoint/suffix recovery kernel,
mixed-version negotiator, key-epoch transition validator, or
information-flow-preserving observability projector. The matrix therefore
specifies expected dispositions and refusal cases; it is not evidence that a
runtime policy or recovery mechanism executed them.

Also not built or claimed:

- authoritative producers for every plane observation;
- a daemon API or scheduler-wide operation-admission choke point;
- a registered `TemporalVerificationProfile` or portable
  `TemporalValidityEvaluation` contract, producer, evaluator, or verifier;
- rollback-resistant per-namespace floor storage or fresh re-anchoring across
  restore;
- scheduled correlated-failure injection across a deployed estate;
- integration with every plane's real backup/restore path;
- live key distribution/activation/revocation across verifier processes;
- deployed mixed-version rollouts, billing/proof reconciliation controllers,
  or telemetry-sink canary probes;
- platform-wide SLO values for any production deployment; or
- evidence that a modeled decision repaired, fenced, restored, or reconciled a
  plane.

Until those seams exist, this document and its fixture define the planned
contract only, not production operability or a reference implementation.

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
- **PO-7:** every required temporal proposition is evaluated separately under
  the exact immutable `TemporalVerificationProfile`; a point timestamp,
  signature, owner epoch, or clock-health flag cannot stand in for another
  claim.
- **PO-8:** rollback resistance is claimed only relative to a named rollback
  domain and a namespace floor retained outside it or freshly re-established
  by admitted independent evidence.
- **PO-9:** a `TemporalValidityEvaluation` supplies typed evidence to an
  existing PEP; it never creates authority, current truth, writer state,
  fencing, or effect permission.
