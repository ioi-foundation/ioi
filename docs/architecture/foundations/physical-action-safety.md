# Physical Action Safety

Status: canonical architecture authority.
Canonical owner: this file for physical-action safety envelopes, embodied-system actuator authority, two-speed mission/local-control safety, human supervision, emergency stop, sensor evidence, segment and actuator receipts, incident handling, and physical-action anti-patterns.
Supersedes: plan prose that treats `physical_action` as only a loose runtime risk class.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: speculative beyond package admission (worker-package install admission currently requires vertical-pack, physical-action-policy, safety-envelope, and emergency-stop refs for `physical_action`; two-speed mission execution, certified local enforcement, segment commitments, live receipts, and incidents are not implemented — `crates/services/src/agentic/runtime/kernel/runtime_worker_package_install_admission.rs`)
Last implementation audit: 2026-07-11

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
implemented beside a local control bridge, safety controller, verified adapter,
or facility safety system, but it is not merely a library linked into the policy
process. The policy can suggest action; the safety layer can deny, clip, stop,
or require handoff.

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
- physical-action incident, dispute, and liability hooks
- safety semantics for robot fleets, humanoid systems, drones, vehicles,
  facility systems, IoT actuators, and other embodied workers

## Does Not Own

This document does not own:

- robot firmware, hardware certification, or mechanical safety design;
- venue, facility, or platform operating rules;
- embodied runtime domains, robot/fleet identity, controller bindings, sensor
  and actuator registries, world models, telemetry streams, physical replay,
  command queues, or fleet runtime policy;
- wallet.network authority scopes, approvals, leases, or secret brokerage;
- Agentgres admitted operational truth, state roots, or artifact refs;
- storage backend payload bytes;
- IOI L1 settlement defaults;
- ordinary digital-only action policy.

Physical Action Safety defines the required safety objects and receipts.
wallet.network authorizes power. The Hypervisor Daemon gates execution.
Agentgres records admitted truth. IOI L1 settles only when public, economic,
rights, dispute, or cross-domain commitments require it.

wallet.network belongs to mission admission, authority, spend, scope, and
revocation. It should not sit in the millisecond actuator loop. A cached
authority result may permit the run to proceed, but local Physical Action
Safety retains the final real-time veto for motion.

## Two-Speed Safety Architecture

Embodied autonomy has two control speeds with different owners:

| Plane | Timescale and responsibility | Canonical boundary |
| --- | --- | --- |
| Governance and intelligence plane | Goal grounding, mission planning, ontology/action semantics, simulation, risk classification, budget, authority, supervision, envelope issue, course correction, pause/revoke, incident response | Goal Kernel, Hypervisor Daemon admission, local/domain governance, wallet.network where portable delegated or high-risk authority is required, Agentgres receipts and mission truth |
| Certified local control and safety plane | High-frequency perception/control, controller-local invariants, watchdog/heartbeat, command clipping/denial, local e-stop, safe stop, exception capture | Independently enforceable local safety controller/bridge operating only inside the admitted mission and `SafetyEnvelope` |

The slow plane authorizes an embodied-owned `PhysicalMissionControlEnvelope`
that binds this document's `PhysicalActionPolicy`, `SafetyEnvelope`,
supervision, e-stop, and evidence requirements. The fast plane
executes commands inside it without a daemon, wallet, AIIP, model-provider, or
L1 round trip per motor update. Local safety may always deny, clip, stop, or
hand control to an operator even when a remote grant remains valid. Remote
revocation must propagate within the declared maximum latency, but no loss of
network connectivity may remove the local veto or safe-stop behavior.

Goal Kernel operates at mission, subgoal, evaluation, and course-correction
timescales. It must not become the motor-control loop. Hypervising embodied
agency means governing identity, mission envelope, controller binding,
authority, resource use, evidence, incidents, and recovery—not scheduling every
servo command through a general-purpose work protocol.

The local plane may aggregate high-frequency commands and observations into
segment commitments while emitting immediate exception, stop, violation, and
incident receipts. Aggregation must preserve enough sensor/command refs,
controller and policy version, time bounds, state roots, and exception detail
for replay and investigation; it must not hide safety-critical events behind a
single success hash.

## Lifecycle

The physical-action lifecycle is:

```text
worker / GoalRun / mission proposes PhysicalActionIntent or bounded mission
  -> Hypervisor Daemon classifies risk_class = physical_action
  -> ontology action, local policy, and wallet.network scopes/leases/step-up are resolved
  -> PhysicalActionPolicy, SafetyEnvelope, supervision, controller binding,
     heartbeat/failsafe, and EmergencyStopAuthority are validated
  -> current sensor/world evidence and sim-to-real eligibility are checked
  -> daemon admits PhysicalMissionControlEnvelope with expiry and revoke semantics
  -> certified local control-and-safety plane executes high-frequency commands inside it
  -> local plane independently denies, clips, stops, or requests operator handoff
  -> segment commitments plus immediate command/exception/e-stop receipts are emitted
  -> daemon reconciles mission outcome, ambiguous effects, incidents, and recovery
  -> Agentgres admits receipts, refs, state roots, replay, and incident state
  -> IOI L1 anchors only selected settlement, dispute, or public commitments
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
  physical_zone_ref: zone://...
  allowed_actions: []
  forbidden_actions: []
  speed_force_distance_limits: {}
  geofence: {}
  proximity_policy: {}
  sensor_requirements: []
  preflight_checks: []
  stop_conditions: []
  heartbeat_failsafe_policy_ref: policy://...
  segment_commitment_policy_ref: policy://...
  max_remote_revocation_latency_ms: integer
  operator_contact_ref: user://... | org://...
  policy_hash: hash
```

```yaml
EmergencyStopAuthority:
  authority_id: estop:...
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

After mission admission, the certified local controller owns high-frequency
command issue and the final safety veto inside the envelope. This is delegated
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

A conforming implementation must ensure:

- every `physical_action` proposal carries `PhysicalActionPolicy` and
  `SafetyEnvelope` refs;
- every admitted embodied mission identifies the certified local controller,
  controller version, mission bounds, expiry, revocation latency,
  heartbeat/failsafe policy, segment-commitment policy, and local e-stop;
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
- aggregated segments retain command/sensor roots and emit immediate exception,
  violation, unknown-effect, and emergency-stop receipts;
- `ActuatorCommandReceipt` binds command hash, authority ref, safety envelope
  ref, and sensor evidence receipt refs;
- incident state is admitted through Agentgres rather than hidden in local logs;
- cTEE, TEE, sandboxing, or model safety claims are not treated as physical
  safety envelopes.
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
- Treating a remote grant as authority to bypass the local safety veto or
  continue after heartbeat/failsafe loss.
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
