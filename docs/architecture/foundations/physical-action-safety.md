# Physical Action Safety

Status: canonical architecture authority.
Canonical owner: this file for physical-action safety envelopes, embodied-system actuator authority, the two-speed mission/local-control boundary, independent local runtime-assurance requirements, safe-set and recovery semantics, human supervision, emergency stop, sensor evidence, segment and actuator receipts, incident handling, and physical-action anti-patterns.
Supersedes: plan prose that treats `physical_action` as only a loose runtime risk class.
Superseded by: none.
Last alignment pass: 2026-07-16.
Doctrine status: canonical
Implementation status: partial (the Rust-owned `POST /v1/hypervisor/physical-action-intent-admissions` planner rejects live, hard-real-time, and E1+ requests without exact deployment, resource-group, command/controller, ODD, timing, assured-input, safe-switch, restart/writer, and teleoperation evidence; a separate reference `PhysicalActionExecutionCore` proves fresh preflight immediately before one typed invoker, exact state-root and adapter-identity checks, zero-call denial, coordinator-side same-body replay, serializable `Prepared`/`Completed` recovery posture, dispatch-proof normalization, and the registered nested execution-receipt contract. That core is not yet mounted to a native controller, persisted durably through Agentgres, or operating a `LocalControlSupervisor`; it does not prove cryptographic controller identity or controller-side idempotency. Estate-wide CPAS coverage and live timing/incident claims therefore remain open — `crates/services/src/agentic/runtime/kernel/runtime_physical_action_intent_admission.rs`, `crates/services/src/agentic/runtime/kernel/physical_action_execution.rs`)
Last implementation audit: 2026-07-16

## Canonical Definition

**Physical action is any autonomous or semi-autonomous effect that can
materially change the physical world.**

Examples include robot movement, vehicle-adjacent actions, drone flight,
facility control, appliance or machine control, tool use, physical access,
sensor override, and any actuator command that can affect people, property,
facilities, safety systems, or regulated environments.

Physical action is not ordinary tool invocation. A worker, model, harness, or
adapter may propose an embodied action, but the Hypervisor Daemon must classify
the proposal as `physical_action`, bind it to a safety envelope, pass authority
and policy gates, produce evidence and receipts, and keep the action
emergency-stoppable.

Short form:

> **No actuator command is a generic tool call.**

Physical Action Safety must be independently enforceable from the ML policy,
planner, VLA, runtime adapter, or teacher model that proposes motion. It may be
implemented by the native `LocalControlSupervisor`, a separately assured safety
controller, or a facility safety system, but it is not merely a library linked
into the policy process. A verified adapter may project such a boundary into
IOI contracts; the adapter does not manufacture its assurance. A policy,
classical planner, behavior graph, or human teleoperator can propose action; an
independently enforceable local monitor, command switch, and recovery path can
deny, clip, replace, stop, or require handoff.

## Owns

This document owns the canonical meaning and minimal object model for:

- `PhysicalActionIntent`
- `PhysicalActionPolicy`
- `SafetyEnvelope`
- `EmergencyStopAuthority`
- `HumanSupervisionPolicy`
- `SensorEvidenceReceipt`
- `ActuatorCommandReceipt`
- `PhysicalActionSegmentCommitmentReceipt`
- `PhysicalActionExecutionReceipt`
- `PhysicalActionIncident`
- safe-set, command-switch, and recovery-controller requirements carried by a
  `SafetyEnvelope`
- independence and worst-case response requirements for the local
  runtime-assurance path
- physical-action incident, dispute, and liability hooks
- safety semantics for robot fleets, humanoid systems, drones, vehicles,
  facility systems, IoT actuators, and other embodied workers

## Does Not Own

This document does not own:

- robot firmware, hardware certification, or mechanical safety design;
- venue, facility, or platform operating rules;
- embodied runtime domains, robot/fleet identity, controller bindings, embodied
  resource groups, sensor and actuator registries, world models, telemetry
  streams, runtime graphs, component scheduling, local-control-supervisor
  implementation, physical replay, command queues, or fleet runtime policy;
- wallet.network authority scopes, approvals, leases, or secret brokerage;
- Agentgres admitted operational truth, state roots, or artifact refs;
- storage backend payload bytes;
- IOI L1 settlement defaults;
- ordinary digital-only action policy.

Physical Action Safety defines the required safety objects and receipts.
wallet.network authorizes power. The Hypervisor Daemon gates execution.
Agentgres records admitted truth. IOI L1 settles only when public, economic,
rights, dispute, or cross-domain commitments require it **and** the system's
declared enrollment and settlement profiles select that service.

wallet.network belongs to mission admission, authority, spend, scope, and
revocation. It should not sit in the millisecond actuator loop. A cached
authority result may permit the run to proceed, but local Physical Action
Safety retains the final real-time veto for motion.

## Two-Speed Boundary And Local Assurance Strata

Embodied autonomy retains two system-level control speeds with different
owners. The fast local side is not one undifferentiated or uniformly certified
process: it contains distinct assurance strata so complex perception or learned
policy inference cannot silently become the safety controller.

| System plane or local stratum | Timescale and responsibility | Canonical boundary |
| --- | --- | --- |
| Governance and intelligence plane | Goal grounding, mission planning, ontology/action semantics, simulation, risk classification, budget, authority, supervision, envelope issue, course correction, pause/revoke, incident response | Goal Kernel, Hypervisor Daemon admission, local/domain governance, wallet.network where portable delegated or high-risk authority is required, Agentgres receipts plus admitted GoalRun/work-subject and physical-envelope truth |
| On-unit autonomy stratum | Perception, state estimation, world-model updates, reactive planning, VLA or policy inference, behavior execution, and teleoperation assistance | Potentially complex or unassured candidate generators operating under declared deadlines; their output is a non-authoritative proposal |
| Deterministic motion stratum | Multi-rate read/compute/write, trajectory execution, kinematics, whole-body or vehicle allocation, exact actuator ownership, interpolation, and controller lifecycle | Admitted deterministic execution profile and exact resource fence; it cannot bypass the safety switch |
| Independent runtime-assurance and safety stratum | Safe-set monitoring, independent inputs, command deny/clip/replace, watchdog/interlock, recovery controller, local e-stop, minimum-risk behavior, and immediate exception capture | `LocalControlSupervisor` or separately assured local safety boundary operating only inside the admitted mission and `SafetyEnvelope` |

The slow plane authorizes an embodied-owned `PhysicalMissionControlEnvelope`
that binds this document's `PhysicalActionPolicy`, `SafetyEnvelope`,
supervision, e-stop, and evidence requirements. For distributed fleet work it
also binds the owning `system_id`, deployment and observed memberships,
mission-coordination epoch, allocation leases, and minimum shared-world-state
watermark. The local strata execute commands inside it without a daemon, wallet,
AIIP, model-provider, or L1 round trip per motor update. Local safety may always
deny, clip, stop, or hand control to an operator even when a remote grant
remains valid. Remote revocation must propagate within the declared maximum
latency, but no loss of network connectivity may remove the local veto or
safe-stop behavior.

In this safety contract, *mission* is physical-domain language for one bounded
slow-plane control scope. It does not name or depend on a generic
`HypervisorMission` object. The envelope, any fleet coordination/allocation
records, and their receipts carry one common `TypedWorkSubjectBinding`; that
binding normally names a GoalRun and may name another admitted work kind only
when its owner contract permits direct physical work.

Goal Kernel operates at mission, subgoal, evaluation, and course-correction
timescales. It must not become the motor-control loop. Hypervising embodied
agency means governing identity, mission envelope, controller binding,
authority, resource use, evidence, incidents, and recovery—not scheduling every
servo command through a general-purpose work protocol.

The local runtime may aggregate high-frequency commands and observations into
segment commitments while emitting immediate exception, stop, violation, and
incident receipts. Aggregation must preserve enough sensor/command refs,
controller and policy version, time bounds, state roots, and exception detail
for replay and investigation; it must not hide safety-critical events behind a
single success hash.

## Lifecycle

The physical-action lifecycle is:

```text
worker / GoalRun / typed work subject proposes PhysicalActionIntent or bounded physical mission
  -> Hypervisor Daemon classifies risk_class = physical_action
  -> ontology action, local policy, and wallet.network scopes/leases/step-up are resolved
  -> PhysicalActionPolicy, SafetyEnvelope, supervision, controller binding,
     runtime graph, deterministic execution profile, LocalControlSupervisor,
     heartbeat/failsafe, and EmergencyStopAuthority are validated
  -> current sensor/world evidence and sim-to-real eligibility are checked
  -> daemon admits PhysicalMissionControlEnvelope with expiry and revoke semantics
  -> mission coordinator leases bounded work to admitted node/unit bindings
  -> admitted policy/planner/human sources emit bounded candidate actions or chunks
  -> deterministic motion runtime allocates exact resources and executes accepted work
  -> independent local supervisor denies, clips, replaces, stops, or requests handoff
  -> segment commitments plus immediate command/exception/e-stop receipts are emitted
  -> daemon reconciles mission outcome, ambiguous effects, incidents, and recovery
  -> Agentgres admits receipts, refs, state roots, replay, and incident state
  -> an explicitly selected service such as IOI L1 anchors settlement,
     dispute, or public commitments when the system's profile requires it
```

Perception, simulation, planning, and reporting may be lower-risk actions when
they do not affect actuators. Any command that moves, actuates, unlocks,
controls, disables, overrides, dispenses, or physically manipulates must follow
the physical-action lifecycle. A mission envelope amortizes governance; it does
not declassify the commands inside it or authorize work outside its zone,
controller, action, time, force/speed, supervision, or stop bounds.

## Minimal Implementation Objects

```yaml
PhysicalActionIntent:
  intent_id: intent:...
  actor_id: worker:... | service_engine:... | runtime:...
  task_id: task:...
  domain_ref: domain://...
  target_system_ref: robot://... | facility://... | vehicle://... | device://...
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
      unit_refs:
        - robot://... | drone://... | device://... | facility-system://...
      controller_binding_refs: [controller-binding://...]
      sensor_refs: [sensor://...]
      actuator_refs: [actuator://...]
      physical_zone_refs: [zone://...]
      emergency_stop_authority_refs: [estop://...]
  command_schema_ref: action-schema://... | null
  command_payload_hash: sha256:... | null
  controller_binding_ref: controller-binding://... | null
  controller_idempotency_key: string | null
  preflight_receipt_refs:
    - receipt://...
  segment_commitment_receipt_refs:
    - receipt://...
  action_kind:
    navigation | manipulation | vehicle_adjacent | drone_flight |
    facility_control | tool_use | access_control | sensor_override |
    emergency_stop_test | other
  risk_class: physical_action
  requested_primitives:
    - prim:physical.actuate
  requested_scopes:
    - scope:physical.actuate
  physical_action_policy_ref: policy:...
  safety_envelope_ref: safety:...
  human_supervision_policy_ref: supervision:... | null
  emergency_stop_authority_ref: estop:...
  expected_sensor_evidence:
    - sensor_ref:...
  expected_actuator_receipt_schema: schema:...
  rollback_or_compensation_policy_ref: policy:... | null
  incident_policy_ref: policy:...
  authority_ref: grant:... | null
```

The command/controller fields may remain null while an intent is only proposed.
They become mandatory for live preflight and must match the exact payload,
controller binding, resource-group closure, and idempotency key presented at
the final invoker boundary. A caller cannot submit an old admitted record as a
substitute for fresh admission.

```yaml
PhysicalActionPolicy:
  policy_id: policy:...
  owner_ref: wallet://... | org://... | domain://...
  allowed_action_kinds: []
  forbidden_action_kinds: []
  required_scopes:
    - scope:...
  required_supervision_mode:
    autonomous | monitored | human_on_loop | human_in_loop |
    manual_confirm_each_action
  required_sensor_evidence: []
  required_emergency_stop: true
  max_risk_class: physical_action
  policy_hash: hash
```

```yaml
SafetyEnvelope:
  safety_envelope_id: safety:...
  asserted_assurance_evidence_level: E0 | E1 | E2 | E3
  deployment_assurance:
    assurance_evidence_bundle_ref: assurance-evidence://...
    assurance_evidence_bundle_hash: sha256:...
    supported_evidence_level: E0 | E1 | E2 | E3
    target_system_ref: robot://... | facility://... | vehicle://... | device://...
    safety_envelope_hash: sha256:...
    runtime_graph_manifest_ref: embodied-runtime-graph-manifest://...
    runtime_graph_manifest_hash: sha256:...
    hardware_configuration_ref: artifact://...
    hardware_configuration_hash: sha256:...
    controller_firmware_ref: artifact://...
    controller_firmware_hash: sha256:...
  operational_design_domain:
    operational_design_domain_ref: policy://... | artifact://...
    operational_design_domain_hash: sha256:...
    measurable_attributes:
      - attribute: string
        unit: string
        permitted_min: number
        permitted_max: number
        monitor_ref: module://... | controller://...
        measurement_receipt_ref: receipt://...
    monitor_refs: [module://... | controller://... | artifact://...]
    state: inside | exiting | outside | unknown
    exit_response:
      deny_new_commands | switch_to_recovery | safe_stop |
      emergency_stop | operator_handoff
    exit_response_deadline_ms: positive_integer
    operator_takeover_budget_ms: positive_integer
    current_compliance_receipt_ref: receipt://...
  physical_zone_ref: zone://...
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
      unit_refs:
        - robot://... | drone://... | device://...
      controller_binding_refs: [controller-binding://...]
      sensor_refs: [sensor://...]
      actuator_refs: [actuator://...]
      physical_zone_refs: [zone://...]
      emergency_stop_authority_refs: [estop://...]
  allowed_actions: []
  forbidden_actions: []
  speed_force_distance_limits: {}
  geofence: {}
  proximity_policy: {}
  sensor_requirements: []
  safety_input_bindings:
    - stream_contract_ref: physical-stream-contract://...
      stream_contract_hash: sha256:...
      producer_ref: sensor://... | controller://...
      source_kind: learned | deterministic | hardware_interlock | fused
      assurance_posture:
        unassured_supplemental | assured_independent | assured_diverse
      failure_domain_ref: failure-domain://...
      current_evidence_receipt_ref: receipt://...
      assurance_evidence_ref:
        artifact://... | evidence://... | assurance-evidence://... | null
      assurance_evidence_hash: sha256:... | null
  preflight_checks: []
  stop_conditions: []
  safe_set_invariant_refs:
    - invariant://...
  safety_monitor_ref: module://... | controller://... | artifact://...
  command_switch_ref: module://... | controller://... | artifact://...
  recovery_controller_ref: module://... | controller://... | artifact://...
  runtime_assurance_profile_ref: assurance_profile://...
  runtime_assurance_timing:
    monitor_period_us: positive_integer
    monitor_jitter_us: nonnegative_integer
    total_observation_to_switch_bound_us: positive_integer
    demonstrated_observation_to_switch_bound_us: positive_integer
    graph_timing_chain_ref: artifact://...
    graph_timing_chain_hash: sha256:...
    evidence_mode: hard_realtime_analytic | bounded_soft_tail
    analytic_schedulability_evidence_ref: artifact://... | evidence://... | null
    analytic_schedulability_evidence_hash: sha256:... | null
    tail_latency_evidence_ref: artifact://... | evidence://... | null
    tail_latency_evidence_hash: sha256:... | null
    tail_percentile: string | null
    tail_sample_count: positive_integer | null
  recoverable_region:
    evidence_ref: artifact://... | evidence://... | assurance-evidence://...
    evidence_hash: sha256:...
    margin_unit: string
    minimum_margin: nonnegative_number
    current_margin: nonnegative_number
  switch_and_recovery_proof:
    switch_proof_test_receipt_ref: receipt://...
    switch_proof_test_age_ms: nonnegative_integer
    switch_proof_test_max_age_ms: positive_integer
    safe_switch_receipt_ref: receipt://...
    recovery_entry_test_receipt_ref: receipt://...
  allowed_runtime_graph_bindings:
    - runtime_graph_manifest_ref: embodied-runtime-graph-manifest://...
      runtime_graph_manifest_hash: hash
  safety_critical_graph_mutation_policy:
    while_armed: immutable
    noncritical_change_requires_readmission: true
  response_time_bounds:
    detection_wcet_ms: integer
    switch_wcet_ms: integer
    recovery_entry_deadline_ms: integer
  failure_independence_requirements:
    planner_failure_cannot_disable_monitor: true
    inference_failure_cannot_disable_recovery: true
    network_failure_cannot_disable_estop: true
  writer_and_restart_assurance:
    restart_posture:
      no_restart_since_admission |
      restarted_inactive_unarmed_and_readmitted
    restart_unarmed_receipt_ref: receipt://...
    active_writer_state: exclusive_active
    active_writer_lease_ref: resource-lease://...
    active_writer_fencing_epoch: nonnegative_integer
    active_writer_fencing_token_hash: sha256:...
    standby_writer_posture: absent | fenced_inactive | safe_takeover_tested
    standby_writer_refs: [local_control_supervisor://...]
    standby_safe_takeover_receipt_ref: receipt://... | null
  teleoperation_requirements:
    link_contract_ref: physical-stream-contract://... | null
    link_contract_hash: sha256:... | null
    operator_authority_required: true
    authentication_receipt_required: true
    deadman_contract_ref: policy://... | artifact://... | null
    arbitration_policy_ref: policy://... | null
    max_round_trip_ms: positive_integer | null
    operator_takeover_budget_ms: positive_integer | null
    on_link_loss:
      hold_position | switch_to_recovery | safe_stop | emergency_stop
  heartbeat_failsafe_policy_ref: policy://...
  segment_commitment_policy_ref: policy://...
  max_remote_revocation_latency_ms: integer
  operator_contact_ref: user://... | org://...
  policy_hash: hash
```

An assurance profile or evidence bundle does not make arbitrary software
certified. The active `SafetyEnvelope` binds one deployment and operating
domain to exact hardware, firmware, runtime-graph, monitor, switch, recovery,
timing, fault, and test evidence. Domain standards and independent assessment
may impose stricter requirements. A changed binary, graph, calibration,
controller, operating domain, or safety assumption requires the amendment or
readmission path named by that assurance profile.

These fields extend the existing `SafetyEnvelope`; they do not create a second
runtime-assurance kernel, a generic `Safety` contract, or a parallel deployment
case. `EmbodiedDeploymentAssuranceCase` remains the deployment evidence member
of the existing `AssuranceEvidenceBundle`, and Embodied Runtime remains the
enforcement owner for graph, stream, supervisor, and controller machinery.

### Physical assurance evidence levels

The `E0..E3` ladder is a claim about evidence bound to one exact physical
deployment, not a safety-integrity level, authority grant, certification badge,
or permission to reuse evidence on another graph, body, site, ODD, firmware, or
envelope:

| Level | Minimum meaning |
|---|---|
| `E0` | Declared design assumptions and refs only. Eligible for proposal, simulation, or shadow planning; insufficient by itself for live physical admission. |
| `E1` | Measurements and proof-test receipts from the exact deployment binding, including current ODD, assured safety input, monitor/switch/recovery path, writer fence, and end-to-end response bound. |
| `E2` | E1 plus target-relevant SIL/HIL, fault injection, ODD-exit, recovery, restart, standby-takeover, and bounded limited-live evidence. |
| `E3` | E2 plus independent assessment and sustained operational evidence under the declared standards, evidence window, amendment, and residual-risk posture. |

An admission may assert only the highest level supported by the bound bundle.
Any `E1+` assertion fails closed when the exact bundle/hash or deployment
bindings are absent or support only a lower level. Hard-real-time evidence is an
orthogonal timing claim: it always requires graph-scoped analytic WCET,
blocking/interference, release-jitter, scheduling, transport, monitor, switch,
and actuator-response evidence. A bounded-soft-real-time claim instead requires
a declared tail percentile, sample count, workload/fault envelope, and measured
tail evidence. Average latency, one component's WCET, or an aggregate p99 cannot
be substituted for the total observation-to-safe-switch chain.

The total bound includes worst admitted observation age, stream/transport delay,
monitor release period and jitter, monitor computation, arbitration, command
switch, controller/actuator acceptance, and proof that recovery begins while the
state remains inside its evidenced recoverable region. The current margin must
remain at or above the envelope minimum. Switch and recovery proof-test receipts
expire at the envelope cadence; a stale receipt is equivalent to missing
evidence.

Unassured learned sensing may enrich autonomy or provide a supplemental safety
signal, but it cannot be the sole input to the monitor, switch, or emergency
path. At least one current, independently assured, non-learned input must remain
available in a distinct declared failure domain. Stream discovery, successful
inference, or a fresh model timestamp does not establish this posture.

## Hard Local Safety Invariants

Every conforming physical runtime enforces these invariants:

1. No fresh authority lease, exact resource fence, and admitted mission and
   safety envelope means no physical actuation.
2. Exactly one active command writer owns an exclusive actuator or physical
   resource at a time.
3. Every candidate action, including a learned action chunk, crosses the
   independent local safety switch before realization.
4. The safety monitor, recovery controller, and emergency stop use locally
   available inputs and require no network, model, wallet, ledger, or remote
   approval round trip.
5. Planner, inference, GPU, communications, or general runtime failure cannot
   disable the independently enforceable safety path.
6. Loss of heartbeat, time integrity, required stream guarantees,
   localization confidence, or world-state freshness invokes the declared
   degrade-or-safe-state transition.
7. Restart returns the unit inactive and unarmed. Restart is not permission to
   resume effects.
8. Physical effects are not assumed exactly once; unknown effects enter
   observation and reconciliation before retry or compensation.
9. Safety-critical graph partitions are immutable while armed. A hot reload,
   policy swap, or controller takeover requires the governed handoff and new
   fencing epoch declared by the envelope.
10. A spacetime reservation or fleet allocation never overrides the local
    collision, safe-set, interlock, or emergency-stop decision.
11. ODD attributes are measured by named monitors. `exiting`, `outside`,
    `unknown`, or an out-of-range attribute invokes the declared exit response
    inside its deadline; it never becomes a warning while motion continues.
12. Teleoperation is an admitted proposal/control source with a bound link,
    operator authentication and authority, deadman, arbitration, latency, and
    loss response. Link, authentication, or deadman loss cannot leave the prior
    remote command writer active.

```yaml
EmergencyStopAuthority:
  authority_id: estop:...
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
      unit_refs:
        - robot://... | drone://... | device://...
      controller_binding_refs: [controller-binding://...]
      sensor_refs: [sensor://...]
      actuator_refs: [actuator://...]
      physical_zone_refs: [zone://...]
      emergency_stop_authority_refs: [estop://...]
  holders:
    - controller://... | user://... | org://... | daemon://...
  trigger_channels:
    - local_button | app | web | voice_supervisor | facility_system | api
  max_latency_ms: integer
  last_tested_at: timestamp
  revocation_epoch: integer
```

```yaml
HumanSupervisionPolicy:
  policy_id: supervision:...
  mode:
    autonomous | monitored | human_on_loop | human_in_loop |
    manual_confirm_each_action
  supervisor_refs:
    - user://... | org://...
  step_up_required_for: []
  escalation_policy_ref: policy:...
```

Every resource-group binding above names one admitted immutable
`EmbodiedResourceGroup` revision, its exact `membership_closure_hash`, and the
expanded `unit_refs`, `controller_binding_refs`, `sensor_refs`, `actuator_refs`,
`physical_zone_refs`, and `emergency_stop_authority_refs`. Bindings never
substitute a mutable group name for resolved leaves. Intent admission retains
that exact closure; safety is the intersection of every leaf, group, and mission
restriction; and emergency-stop scope resolves to those same leaves. The target
must be one of the bound units or actuators, and the selected controller and
emergency-stop authority must occur in the same admitted closure. A group may
add or narrow requirements but cannot grant authority, relax a member
constraint, mask an unavailable required leaf, or turn a multi-controller
action into an atomic hardware transaction. A later group revision or changed
leaf set requires a new intent and envelope admission.

Every new fixed-system unit binding uses `facility-system://`. The historical
`facility_system://` spelling is a read-only compatibility alias only; it
cannot cross physical admission or appear in an execution receipt. Alias
normalization, where an implementation deliberately provides it, occurs before
admission and carries no authority or safety evidence of its own.

Physical safety owns when `SensorEvidenceReceipt`, `ActuatorCommandReceipt`,
`PhysicalActionSegmentCommitmentReceipt`, and
`PhysicalActionExecutionReceipt` are required and the safety facts they must
bind. Their single field-level schemas live in
[`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md#embodied-runtime-receipts).

High-frequency execution may aggregate routine commands into a
`PhysicalActionSegmentCommitmentReceipt` only while immediate exception,
emergency-stop, incident, and ambiguous-effect reporting remains available.
The segment receipt must bind the local controller interval, controller/version,
authority, policy and safety envelope, command/sensor sequence roots, initial
and final state refs, immediate exception/e-stop receipt refs, and declared
result. It does not replace mission-level reconciliation or acceptance.

```yaml
PhysicalActionIncident:
  incident_id: incident:...
  severity: low | medium | high | critical
  trigger:
    safety_envelope_violation | emergency_stop | sensor_disagreement |
    actuator_failure | supervision_failure | policy_violation |
    disputed_outcome | other
  involved_intent_refs:
    - intent://...
  involved_receipt_refs:
    - receipt://...
  emergency_stop_ref: estop:... | null
  dispute_ref: dispute://... | null
  remediation_policy_ref: policy:...
  status: open | contained | remediated | disputed | closed
```

## Admission / Settlement Boundary

The Hypervisor Daemon owns the deterministic execution gate for physical
actions. The model does not directly actuate. A connector, robot controller,
AIIP handoff, or external harness may only carry a physical-action proposal or
approved command envelope.

After mission admission, the deterministic motion runtime may own
high-frequency command issue, while the independent `LocalControlSupervisor`
or separately assured safety controller owns the final safety veto inside the
envelope. This is delegated
execution, not delegated authority creation: it cannot widen zone, duration,
action class, force/speed, actuator set, supervision, budget, or stop policy.
The daemon owns later reconciliation and may pause execution, quarantine,
require operator handoff, or deny admission of the next segment; it is not in
the servo loop and does not itself revoke authority.

wallet.network owns authority scopes, leases, step-up, emergency revoke, and
payment authorization. Physical-action scopes must stay explicit, such as
`scope:physical.actuate`, `scope:robot.navigate`, or
`scope:facility.control`.

Agentgres records admitted physical-action intents, policies, safety envelope
refs, receipts, incident state, artifact refs, and state roots. Storage
backends hold payload bytes such as videos, sensor logs, maps, and raw traces.

IOI L1 is not the safety controller. It may anchor settlement, rights,
insurance, marketplace, dispute, reputation, or public accountability
commitments when required.

Environment recovery and outcome recovery are separate. Restarting a robot
runtime, controller bridge, VM, or network session does not establish whether a
physical effect committed before failure. Every physical action or mission
segment must declare a recovery class such as `replayable`, `checkpointable`,
`compensatable`, `reconciliation_required`, or `non_retryable`. Unknown or
ambiguous external effects fail into reconciliation/operator policy; they are
never blindly replayed. Compensation is a new governed action with its own
safety and authority checks, not a rollback fiction.

### Final invoker and receipt-chain invariant

The command path has one final choke point:

```text
canonical command payload + exact expected hash
  -> same-body idempotency and exact receipt-head check
  -> fresh physical preflight admission
  -> exact state-root, resource-closure, and typed-adapter identity checks
  -> Prepared persisted before one controller invocation
  -> dispatch evidence + effect normalized without erasing ambiguity
  -> exact ReceiptEnvelope + physical body bundle verified
  -> Completed persisted only after bundle verification
```

The fresh admission binds the command schema and payload hash, controller
binding, controller idempotency key, exact embodied-resource-group revisions
and expanded leaf closures, emergency-stop authority, SafetyEnvelope, runtime
graph, assurance bundle, writer lease/epoch/token, timing chain, preflight and
sensor receipts, and the state root before execution. The request's
`state_root_before` must exactly equal the state root returned by that fresh
admission. The invoker's typed `controller_binding_ref` must exactly equal the
admitted binding before the core can enter `Prepared` or invoke it. That typed
identity prevents accidental adapter substitution; it is not cryptographic
hardware or controller identity proof.

The reference ledger records `Prepared { request_hash, prepared_at }`
immediately before the sole invocation and records
`Completed { request_hash, result }` only after outcome normalization and
receipt-bundle verification. Same key plus the same canonical body replays a
`Completed` result without another call. A changed body, stale predecessor head,
substituted command, state root, closure leaf, adapter identity, or denied fresh
admission produces zero controller calls. If a serialized/restored ledger
contains `Prepared`, the same request returns
`physical_action_execution_reconciliation_required`, other work on that chain
also fails closed, and neither path reinvokes. This is the required recovery
posture for an interrupted call whose external effect may be unknown; production
still requires a durable Agentgres-owned ledger.

Controller outcomes carry one dispatch posture:
`not_dispatched_proven`, `dispatched_observed`, or `dispatch_ambiguous`, plus
dispatch-evidence receipt refs. `committed` requires observed dispatch,
non-empty dispatch and controller evidence, and a known after-state root.
`rejected` requires proof of no dispatch, dispatch evidence, and no after-state
root. A timeout, transport failure, contradictory proof, or malformed or
incomplete post-invocation result normalizes to `unknown` with
`dispatch_ambiguous` and explicit normalization errors. It never becomes a
pre-effect denial, success, or permission to retry.

The resulting `PhysicalActionExecutionReceipt` is exactly the registered
`schema://ioi/foundations/physical-action-execution-receipt/v1` bundle:
`{ schema_version, receipt_envelope, body, body_hash, receipt_hash }`.
`receipt_envelope.input_hash` equals the execution request hash,
`receipt_envelope.output_hash` equals the JCS SHA-256 of the physical body, and
`receipt_envelope.policy_hash` equals the safety-envelope hash. `body_hash`
binds the exact `{ receipt_envelope, body }` pair, and `receipt_hash` is the
domain-separated hash over the schema version and that same canonical bundle.
The body additionally binds the controller effect ref, dispatch posture and
evidence, controller receipts, state root after execution when known, effect
status, predecessor receipt hash, and execution time.

The built Rust core is a reference mechanism for this invariant. Until a native
or separately assured controller adapter mounts it at the real effect boundary
and persists its ledger and receipts through the runtime/Agentgres owners, it
does not prove that every deployed actuator path is covered. The adapter
contract requires propagation of the controller idempotency key, but the
reference core cannot prove controller-side deduplication. Native mounting,
durable Agentgres persistence, cryptographic hardware/controller identity,
controller-side idempotency, and estate-wide CPAS conformance remain open.

## Events and Receipts

Physical-action work should emit:

- `PhysicalActionIntentProposed`
- `PhysicalActionGateResult`
- `PhysicalActionPreflightReceipt`
- `SensorEvidenceReceipt`
- `ActuatorCommandReceipt`
- `PhysicalActionSegmentCommitmentReceipt`
- `EmergencyStopReceipt`
- `PhysicalActionExecutionReceipt`
- `PhysicalActionIncident`
- `PhysicalActionRemediationReceipt`

Digital-only simulation receipts are not actuator receipts. A successful
simulation may support a gate decision, but it does not prove that the physical
command was safe, issued, stopped, or completed.

## Conformance Checks

Executable and evidence-facing criteria are identified as `CPAS-*` in
[`physical-action-safety.md`](../../conformance/hypervisor-core/physical-action-safety.md).
The list below remains the owner-level summary; it does not turn planned local
runtime behavior into a built claim.

A conforming implementation must ensure:

- every `physical_action` proposal carries `PhysicalActionPolicy` and
  `SafetyEnvelope` refs;
- every admitted embodied mission identifies the local controller,
  controller version, runtime-graph manifest and hash, deterministic execution
  profile, local supervisor, mission bounds, expiry, revocation latency,
  heartbeat/failsafe policy, segment-commitment policy, and local e-stop;
- every active safety envelope binds independent safety inputs, safe-set
  invariants, safety monitor, command switch, recovery controller, monitor
  period/jitter, total observation-to-safe-switch bound, recoverable-region
  margin, proof-test cadence and receipts, failure-independence requirements,
  exact allowed runtime-graph ref and hash, and deployment-bound assurance
  evidence;
- live, hard-real-time, or asserted E1+ admission fails closed unless the exact
  evidence bundle/hash binds the target, safety-envelope hash, runtime graph,
  hardware, firmware, ODD, monitor, switch, recovery controller, timing chain,
  current proof tests, writer fence, and restart posture;
- the asserted `E0..E3` level never exceeds the level supported by the bound
  deployment evidence; evidence from a different graph, target, ODD, firmware,
  or safety-envelope revision is ineligible;
- hard-real-time chains carry analytic graph-scoped WCET/schedulability evidence;
  bounded-soft chains carry explicit tail percentile, sample count, workload,
  and fault-envelope evidence; both cover the total observation-to-safe-switch
  path rather than only one component;
- current ODD attributes, monitors, compliance receipt, exit response/deadline,
  and operator-takeover budget are bound, and an ODD exit or unknown state denies
  continued admission;
- an unassured learned stream is never the sole safety input; each assured input
  pins its stream contract/hash, producer, failure domain, evidence, and receipt;
- every distributed embodied mission binds its owning system, deployment,
  admitted node/unit assignments, coordination epoch, allocation-lease expiry,
  world-state freshness, and partition/rejoin policy without treating a unit as
  a system node by implication;
- every group-scoped intent, safety envelope, and emergency-stop authority binds
  an admitted `group_revision_ref` plus its exact `membership_closure_hash`,
  resolves within the same system and embodied domain, and retains the expanded
  sensor, actuator, controller, unit, zone, and stop-channel refs needed for
  enforcement and replay;
- resource-group constraints compose by intersection with all leaf, controller,
  unit, zone, mission, and local-safety constraints; group membership or health
  cannot grant authority, widen a safety envelope, or hide a blocked required
  leaf;
- a multi-controller or multi-unit group does not imply atomic execution or
  replace per-unit assignments, allocation leases, local safety boundaries, or
  effect reconciliation;
- actuator-affecting actions cannot execute through generic `tool.invoke`,
  `shell.exec`, `connector.call`, or AIIP packets without physical-action
  classification;
- emergency stop is available, scoped, and testable for embodied domains where
  harm can propagate;
- required human supervision mode is enforced before command issue;
- current sensor evidence is captured before and after high-risk actuator
  commands;
- high-frequency commands remain inside the admitted envelope and can be
  denied, clipped, stopped, or handed off locally without a remote round trip;
- learned, classical, behavior-graph, or human-produced action chunks remain
  non-authoritative proposals, bind exact observation/world-state watermarks,
  policy and embodiment revisions, expiry, resource leaves, and fencing, and
  record proposed-versus-executed lineage;
- an armed safety-critical graph cannot be hot-reloaded, and restart or
  component activation never implies actuator authority; restart-unarmed,
  exclusive active-writer fencing, standby posture, and any safe-takeover proof
  remain explicit in the admission record;
- active teleoperation binds the exact link contract/hash, current operator
  authority and authentication receipt, deadman contract/receipt, arbitration,
  round-trip bound, takeover budget, and fail-closed link-loss response;
- partition, rejoin, and rebalance cannot widen mission authority or replay an
  unknown physical effect; the previous allocation is fenced and effects are
  reconciled before reassignment;
- aggregated segments retain command/sensor roots and emit immediate exception,
  violation, unknown-effect, and emergency-stop receipts;
- `ActuatorCommandReceipt` binds the exact actuator leaf, command hash,
  authority ref, safety envelope ref, sensor evidence receipt refs, and, when a
  group was used, the exact group revision and membership-closure hash;
- incident state is admitted through Agentgres rather than hidden in local logs;
- cTEE, TEE, sandboxing, or model safety claims are not treated as physical
  safety envelopes;
- an `ImprovementCampaign` for perception, planning, allocation, action-policy,
  controller, or embodied-runtime targets freezes the incumbent and candidate
  roots and passes target-appropriate simulation, hardware-in-the-loop, shadow,
  transfer, operator, and limited-live gates before any target-owner activation;
- campaign success, an `ImprovementEvidenceClaim`, or an `UpgradeProposal`
  cannot weaken the protected independently enforceable local safety path,
  become actuator authority, or hot-swap the
  servo/interlock/emergency-stop path; protected controller and safety targets
  use their protected assurance-amendment or, where applicable,
  recertification path;
- runtime/environment restart is not treated as outcome recovery, and ambiguous
  physical effects are reconciled according to the declared recovery class
  before retry or compensation.

## Anti-Patterns

- Treating a robot fleet or actuator API as an ordinary connector.
- Letting raw model output control an actuator.
- Treating SMS, chat, or email text as physical-action authority.
- Calling a simulation result an execution receipt.
- Treating a Foundry embodied package, runtime candidate, VLM, VLA, or action
  policy as an actuator authority grant.
- Embedding the only safety decision inside the same policy process that emits
  motor actions.
- Treating a hardware TEE or cTEE private workspace as physical safety.
- Using IOI L1 settlement as a substitute for local emergency stop.
- Putting wallet.network, AIIP, the model provider, IOI L1, or a general daemon
  request/response inside each motor-control update.
- Letting Goal Kernel or an OutcomeRoom become the servo loop rather than the
  mission/course-correction layer.
- Treating AIIP acceptance, fleet membership, node membership, or a scheduler
  assignment as direct actuator authority.
- Treating an embodied resource-group name, health projection, or later
  revision as actuator authority, a replacement for exact leaf refs, or proof
  of cross-controller physical atomicity.
- Treating a remote grant as authority to bypass the local safety veto or
  continue after heartbeat/failsafe loss.
- Treating an active component lifecycle state, runtime-graph activation,
  transport discovery, successful inference, or matching tensor dimensions as
  permission to actuate.
- Letting the same failure domain host the only candidate generator, safety
  monitor, command switch, and recovery controller where the assurance profile
  requires independence.
- Executing the unexpired suffix of a remote action chunk after its observation
  watermark, fencing epoch, controller state, or safety assumptions have gone
  stale.
- Claiming E1, E2, or E3 from declarations, simulation-only results, a different
  deployment, or evidence whose supported level is lower than the display claim.
- Calling a component deadline or average/p99 latency the observation-to-switch
  bound while omitting stream age, monitor release jitter, arbitration, switch,
  actuator acceptance, or recoverable-region margin.
- Allowing an unassured learned perception stream to be the only safety input.
- Continuing teleoperation after link degradation, authentication expiry,
  deadman release, arbitration loss, or takeover-budget exhaustion.
- Hiding command exceptions or e-stop events inside an aggregate segment hash.
- Blindly replaying a physical command after environment recovery when the
  external effect is unknown, compensatable, reconciliation-required, or
  non-retryable.
- Storing sensor video or actuator logs as raw blobs without Agentgres refs and
  receipts.
- Hiding a physical-action incident in provider logs instead of admitting it as
  incident state.

## Related Canon

- [`aiip.md`](./aiip.md) for bounded execution domains and handoffs.
- [`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md) for
  bounded execution domain envelopes.
- [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md)
  for action proposals and loop-native step resolution.
- [`api-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md)
  for wallet authority scopes.
- [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
  for receipt, trace, replay, and delivery patterns.
- [`embodied-runtime.md`](../components/daemon-runtime/embodied-runtime.md) for
  robot/fleet identity, controller binding, physical telemetry, physical replay,
  command queues, sim-to-real gates, and embodied runtime recovery.
- [`verifiable-bounded-agency.md`](./verifiable-bounded-agency.md) for the
  execution-boundary alignment thesis.
