# Embodied Runtime, Robot Fleet Runtime, and Physical Telemetry

Status: canonical architecture authority.
Canonical owner: this file for embodied runtime domains, robot/fleet identity,
controller bindings, sensor and actuator registries, versioned embodied
resource groups, native runtime profiles and execution strata, embodied
runtime graph manifests, component and physical-stream contracts,
deployment-bound assurance cases, local control supervisors and
compatibility bridges, heartbeat/failsafe posture, two-speed mission/control
execution, world representations, physical telemetry, physical replay, command
queues, spacetime reservations, fleet policy, recovery, and operator handoff.
Supersedes: plan prose that treats robot fleets, actuator APIs, sensor streams,
or physical telemetry as ordinary connector/tool details.
Superseded by: none.
Last alignment pass: 2026-07-19.
Doctrine status: canonical
Implementation status: partial admission precursor only (current master retains the older Rust physical-action-intent admission path; the stricter deployment-assurance, graph-timing, ODD, assured-input, restart/writer, and teleoperation checks described here are target contract. Native graph compiler, mixed-criticality executor, physical stream runtime, local supervisor, actuator execution, and the Embodied Systems surface are not implemented.)
Last implementation audit: 2026-07-16

## Canonical Definition

**Embodied Runtime is the native, deployment-neutral IOI operating environment
for defining, compiling, operating, governing, verifying, and improving bounded
autonomous systems that observe or affect the physical world.**

It covers robot fleets, humanoid systems, drones, vehicles or vehicle-adjacent
systems, facility systems, IoT actuators, field-service devices, and other
physical domains where workers, models, controllers, sensors, actuators, and
humans must coordinate under safety, evidence, and emergency-stop constraints.
The reference runtime must be able to commission and operate a conforming
physical system without making any external robot framework, simulator,
accelerator stack, vendor cloud, or controller plane the semantic or safety
center. Existing controller stacks, simulators, transports, device drivers,
autopilots, and accelerator libraries remain valuable optional adapters and
backends. HypervisorOS is one optional Type 1 placement, not an adoption
prerequisite; a robot, drone, facility, PLC, or controller does not have to
replace its operating system or certified firmware to join an IOI system.

Short form:

```text
Foundry trains and evaluates embodied capability.
Physical Action Safety defines the safety gate.
Embodied Runtime operates the live physical domain.
```

Embodied Runtime is not:

- robot firmware;
- hardware certification;
- mechanical safety design;
- a generic connector;
- a partner-runtime wrapper presented as an embodied operating environment;
- a direct model-to-actuator path;
- a requirement to rebuild every device driver, autopilot, physics engine,
  safety PLC, or OEM controller;
- a substitute for Physical Action Safety;
- a simulation result presented as live execution;
- IOI L1 as a safety controller.

The competitive boundary is therefore precise: IOI owns the portable execution
semantics, graph admission, component lifecycle, physical stream contracts,
resource arbitration, model/policy binding, runtime assurance, fleet work,
spacetime coordination, evidence, and promotion loop. A backend may implement a
binding, but it does not redefine those semantics or become the owner of live
authority.

## Ownership Boundaries

Embodied Runtime owns runtime representation and control-plane contracts for:

- robot/fleet identity and controller binding;
- sensor and actuator registries;
- immutable compiled embodied-runtime graphs, component contracts, physical
  stream contracts, lifecycle, placement, and activation transactions;
- composable native `micro`, `edge`, and `site` runtime footprints under one
  `NativeEmbodiedRuntimeProfile` family;
- immutable, versioned resource groups for named sensor suites, actuator
  assemblies, kinematic chains, drivetrains, workcells, facility subsystems,
  and mixed safety domains;
- embodied capability package binding to a physical domain;
- embodiment adapters, calibration registries, and time-synchronization
  contracts;
- native local control supervision, optional external-runtime compatibility
  bridges, and heartbeat/failsafe protocol;
- slow mission/governance plane separation from on-unit autonomy,
  deterministic motion, and independently isolated runtime-assurance/safety
  execution domains;
- model-neutral embodied policy binding and latency-bounded physical
  action-chunk proposal semantics;
- world model, maps, zones, calibration, and environment state;
- latency, degraded-network, offline, and emergency-stop runtime guarantees;
- sim-to-real promotion gates for deployment into physical domains;
- telemetry streams and physical replay;
- physical command queue semantics for movement, manipulation, and facility
  control;
- incident, liability, recovery, and operator handoff projections;
- fleet-level policy across many robots, devices, controllers, zones, and
  human supervisors;
- same-system mission coordination across admitted nodes and embodied units,
  including allocation leases, shared-world-state watermarks, coordination
  epochs, partition behavior, rejoin/rebalance, and duplicate-effect
  prevention;
- expiring, fenced spacetime reservations for shared physical corridors,
  volumes, zones, tools, workcells, charging resources, and cooperative work.

It does not own:

- `PhysicalActionPolicy`, `SafetyEnvelope`, `EmergencyStopAuthority`,
  `HumanSupervisionPolicy`, `SensorEvidenceReceipt`, `ActuatorCommandReceipt`,
  or physical-action incident semantics; those belong to
  [`physical-action-safety.md`](../../foundations/physical-action-safety.md);
- wallet.network authority, leases, step-up, emergency revoke, or payment;
- Agentgres admitted truth, state roots, artifact refs, or replay truth;
- storage backend payload bytes such as videos, point clouds, telemetry logs,
  maps, or controller traces;
- Foundry simulation, robotics training, perception/action dataset construction,
  model tuning, or sim-to-real scorecards;
- robot OEM firmware, facility safety systems, or venue operating rules.

## Runtime Shape

```text
Embodied domain
  -> Owning bounded DAS, deployment profile, and admitted node memberships
  -> Linked embodiment/resource, execution, behavior, and world/evidence graphs
  -> Composable native micro / edge / site runtime footprints
  -> RobotFleetRecord
  -> Robot / device identities
  -> Controller bindings
  -> Sensor registry
  -> Actuator registry
  -> Embodied resource groups (versioned, exact leaf expansion)
  -> Embodied capability package binding
  -> Embodiment adapter / policy / calibration / time-sync contract
  -> Immutable EmbodiedRuntimeGraphManifest and activation transaction
  -> Layered world model / representations / maps / zones / calibration
  -> Native LocalControlSupervisor
  -> Optional LocalControlBridge compatibility bindings
  -> Heartbeat and failsafe protocol
  -> Physical command queue
  -> Fleet mission coordination / allocation and spacetime leases
  -> Telemetry stream and physical replay
  -> Operator handoff / incident / recovery views
```

The Hypervisor Daemon remains the governing admission gate at system, graph,
mission, and course-correction boundaries; the `LocalControlSupervisor`
enforces the frozen admitted snapshot locally. A model, worker, harness, MCP
gateway, connector, AIIP handoff, or external agent may propose embodied work,
but actuator-affecting execution must route through:

```text
proposal
  -> PhysicalActionIntent
  -> EmbodiedCapabilityPackage / runtime candidate lookup
  -> EmbodiedRuntimeDomain and RobotFleetRecord lookup
  -> immutable runtime graph, embodiment/policy adapter, controller,
     resource-group revision, exact sensor and actuator leaves, world-state,
     calibration, time-sync, placement, and latency readiness
  -> optional EmbodiedActionChunk proposal and candidate selection
  -> current world/sensor/lease compatibility checks
  -> Physical Action Safety gate
  -> wallet.network authority
  -> physical command queue admission
  -> native local control supervisor
  -> native controller binding or optional compatibility bridge
  -> telemetry observation
  -> receipts, replay, incident/recovery state
  -> Agentgres admission
```

This flow admits a bounded mission/action envelope and safety policy; it does
not require a remote daemon, wallet, model, Agentgres, AIIP, or chain round trip
for every servo or motor-control tick.

## Linked Runtime Graphs

One generic module graph must not silently own the whole physical system.
Embodied Runtime compiles and relates four explicitly bounded graph views:

| Graph | Sole question answered | Runtime role |
|---|---|---|
| Embodiment/resource graph | What bodies, joints, sensors, actuators, tools, controllers, frames, energy stores, zones, and exact resource groups exist? | Supplies physical identity, topology, limits, calibration, and claimable leaves. |
| Execution graph | Which components execute where, with which rates, deadlines, memory, accelerator, transport, isolation, lifecycle, and failure behavior? | Compiles into an immutable `EmbodiedRuntimeGraphManifest`. |
| Behavior graph | Which admitted goals, skills, policies, planners, contingencies, recovery paths, and human interventions direct work? | References GoalRun, workflow, skill, policy, and supervision owners without taking over their state. |
| World/evidence graph | What does the system believe, at what time and uncertainty, and what observations, proposals, commands, interventions, and effects occurred? | Projects layered world state and evidence through their canonical owners. |

The views may share stable refs, but they do not collapse ownership. An
execution edge does not grant authority; a behavior edge is not a physical
connection; a world-state assertion is not evidence that an effect occurred;
and an embodiment edge is not an allocation lease. Authoring tools may present
one joined canvas, but admission resolves each view independently and freezes
the exact cross-graph bindings used by a live deployment.

## Native Runtime Profiles and Execution Strata

`NativeEmbodiedRuntimeProfile` is a composable deployment-footprint family, not
three products, sovereign systems, or assurance grades:

| Footprint | Typical placement | Mandatory posture |
|---|---|---|
| `micro` | MCU, PLC, safety controller, flight controller, or RTOS | Bounded control/safety subset, watchdog and local-stop paths, bounded memory, declared timing, and reduced/no-network operation. |
| `edge` | Robot, drone, vehicle-adjacent, or workcell compute | On-unit perception and estimation, local inference/planning, deterministic motion, supervisor, replay capture, and offline-safe operation. |
| `site` | Facility, vessel, warehouse, field site, or fleet edge | Multi-unit world-state projections, work allocation, spacetime reservations, site policy, heavier inference, replay indexes, and partition/rejoin coordination. |

A deployment may compose one, two, or all three footprints. A single edge
computer may host several when isolation and timing admission prove the
placement; a tiny controller may implement only `micro`. Hypervisor's control
plane, Goal Kernel, Foundry, Governance, and Agentgres remain outside this enum
even when colocated. They direct, evaluate, admit, and record work; they are not
secretly another servo-loop profile.

All footprints share identifiers, immutable manifests, schemas, units, frames,
clock semantics, leases, lifecycle, evidence, and failure vocabulary. They need
not share one language, scheduler, transport, kernel, binary, or hardware
architecture. External stacks conform only through an admitted adapter that
preserves these contracts.

`EmbodiedRuntimeExecutionStratum` identifies one locally isolated execution
class beneath the slower mission/governance plane:

| Stratum | Owns | Required isolation posture |
|---|---|---|
| `autonomy` | perception, estimation, planning, learned inference, selection, and proposals | May be nondeterministic and accelerator-backed; failure cannot disable motion fencing or runtime assurance. |
| `deterministic_motion` | feasibility, trajectories, kinematics, allocation, interpolation, exclusive actuator writing, and bounded control | Declared schedule, resource ownership, deadline behavior, and failover handoff. |
| `runtime_assurance_safety` | monitors, command switch, clipping/veto, watchdogs, recovery/minimum-risk control, interlocks, and final local veto | Independent failure containment and availability appropriate to the deployment-bound assurance case. |

Strata declare their scheduling, memory, restart, and fault-containment
properties separately. Colocation is permitted only when the deployment case
proves the required isolation; a process, GPU, network, or model failure may
not remove the runtime-assurance stratum's final local veto.

## Compiled Runtime Graph and Component ABI

`EmbodiedRuntimeGraphManifest` is the immutable, content-addressed,
admission-ready result of compiling an authored embodied execution graph. Its
canonical wire shape, including nested `EmbodiedComponentContract` and
`PhysicalStreamContract`, is defined in
[`common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md#embodiedruntimegraphmanifestenvelope).
The authored canvas, blueprint, or source graph remains editable source, not
live runtime truth.

Every manifest freezes exact component implementations and hashes, ports,
profiles, execution strata, schedules, lifecycle dependencies, placement and
isolation, controller/resource leaves, frames, clocks, calibration, world
representation, action-policy/supervisor bindings, deployment requirements,
assurance refs, and resolved backend bindings. It owns no live state,
authority, actuator command, safety approval, or certification claim.

Every nested component contract declares component kind, implementation,
profile, stratum/criticality, determinism posture, inputs and outputs, trigger,
rate/deadline/WCET and missed-deadline behavior, compute/memory/accelerator and
exclusive physical resources, effect class, health, lifecycle, restart, and
safe-state behavior.

`PhysicalStreamContract` describes meaning before transport: schema, direction,
producer and permitted-consumer identity, authentication, integrity,
anti-replay and confidentiality policy, source and receive clock domains,
timestamp uncertainty, frame, units, rate, deadline, jitter, ordering,
reliability, history, durability, freshness, liveliness, priority,
backpressure, criticality, replay, and the required degrade/fail/stop action.
The compiler may then resolve shared
memory, accelerator buffers, an RTOS channel, fieldbus, DDS, Zenoh, or another
binding. Matching topic names, tensor shapes, or successful transport
negotiation does not prove contract compatibility, and a binding may never
silently change semantic, timing, evidence, or authority behavior.

Safety-relevant streams also declare an assurance posture:
`unassured_supplemental`, `assured_independent`, or `assured_diverse`, together
with their exact contract/hash, producer, failure domain, current evidence
receipt, and deployment evidence. Learned sensing may remain an autonomy input
or supplemental monitor input, but an unassured learned stream cannot be the
only source for safe-set, switch, recovery, interlock, or e-stop decisions.
Transport discovery, publisher liveliness, model confidence, or a recent
timestamp does not upgrade a stream's assurance posture.

### Graph-scoped timing chains

A safety timing claim binds one exact path through the admitted runtime graph,
not a bag of component deadlines. The chain starts at the oldest admissible
physical observation and includes source timestamp uncertainty and age,
transport/queue delay, clock conversion, monitor release period and jitter,
monitor WCET, arbitration, command-switch WCET, controller/fieldbus acceptance,
actuator response, and recovery-entry margin. Its artifact ref/hash pins every
component, stream, scheduler, priority, placement, and interference assumption
used by the calculation or measurement.

`hard_realtime` requires analytic evidence for WCET, blocking, preemption,
release jitter, scheduling, transport, clock error, and the complete path under
the declared fault assumptions. Measurement may corroborate that proof but may
not replace it. `bounded_soft_realtime` requires a named tail percentile, sample
count, workload/ODD distribution, injected faults, dropped/degraded samples, and
measured worst demonstrated observation-to-switch result. Average latency or a
component-only p99 is not an end-to-end safety bound. In both modes, a result
later than the `SafetyEnvelope.total_observation_to_switch_bound_us` is a safety
violation and invokes the envelope's ODD/degrade response.

### Transactional Activation and Lifecycle

`EmbodiedGraphActivationTransaction`, whose wire contract is defined beside the
graph envelope in
[`common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md),
prepares one exact graph against one exact local placement:

```text
resolve hashes and dependencies
  -> validate schemas, frames, units, clocks, QoS, schedules, and WCET budgets
  -> reserve compute, memory, accelerator, controller, and resource leaves
  -> validate supervisor, Physical Action Safety, and deployment-assurance refs
  -> configure and health-check every component while inactive and unarmed
  -> commit at one admitted supervisor/hardware boundary, or abort completely
```

Activation does not arm controllers, mint authority, enqueue commands, or prove
that the current world is safe. Arming is a separate transition requiring a
current mission envelope, authority, safety decision, leases, sensor/world
readiness, and supervisor admission. Atomic activation may be claimed only
inside one admitted supervisor/hardware boundary; distributed launch uses
fenced coordination epochs and explicit readiness rather than fictitious global
physical atomicity.

The reference lifecycle is `unresolved -> resolved -> staged -> configured ->
ready -> active_unarmed`. Mission admission may then produce `armed ->
executing`; stop, expiry, recall, or replacement proceeds through `quiescing ->
safe_stopped -> inactive`. `degraded`, `failed`, `revoked`, and recovery branches
must name their permitted successor and physical safe state. Component health
may degrade a graph, but it may not bypass the graph or supervisor transition.

Restart always returns an actuator-bearing graph inactive and unarmed and never
resumes a physical effect implicitly. Safety-related or hard-real-time
partitions are immutable while armed. Replacement requires a newly admitted
manifest, drained command/effect boundary, new leases, predecessor fencing,
readiness proof, and rollback or minimum-risk posture. Noncritical components
may be replaced more freely only when declared isolation proves that no
authority, timing, resource, safety, or evidence contract widens.

## Robot and Fleet Identity

Embodied systems need stable identity separate from worker identity. A marketplace
worker may operate several robot bodies over time; one robot body may run several
workers or policies over its lifetime.

```yaml
EmbodiedRuntimeDomain:
  domain_id: embodied_domain://...
  system_id: system://...
  deployment_profile_ref: deployment-profile://...
  operating_node_membership_refs:
    - node-membership://...
  admitted_runtime_graph_manifest_refs:
    - embodied-runtime-graph-manifest://...
  active_graph_activation_refs:
    - graph-activation-transaction://...
  local_control_supervisor_refs:
    - local_control_supervisor://...
  owner_ref: wallet://... | org://...
  physical_domain_ref: site://... | facility://... | field_area://...
  domain_kind:
    robot_fleet | humanoid_fleet | drone_fleet | facility_system |
    vehicle_adjacent | field_service | iot_actuator_domain | mixed
  fleet_refs:
    - robot_fleet://...
  world_model_ref: world_model://...
  fleet_policy_ref: fleet_policy://...
  default_safety_envelope_refs:
    - safety://...
  default_supervision_policy_ref: supervision://...
  emergency_stop_authority_refs:
    - estop://...
  telemetry_stream_refs:
    - telemetry_stream://...
  resource_group_refs:
    - embodied-resource-group://...
  status:
    planned | commissioning | active | degraded | suspended |
    emergency_stopped | decommissioned
```

```yaml
RobotFleetRecord:
  fleet_id: robot_fleet://...
  system_id: system://...
  deployment_profile_ref: deployment-profile://...
  embodied_domain_ref: embodied_domain://...
  display_name: string
  unit_refs:
    - robot://... | drone://... | device://... | facility-system://...
  controller_binding_refs:
    - controller-binding://...
  operating_node_membership_refs:
    - node-membership://...
  mission_coordination_policy_ref: policy://...
  operator_group_refs:
    - org_group://...
  fleet_policy_ref: fleet_policy://...
  maintenance_policy_ref: policy://...
  emergency_stop_authority_refs:
    - estop://...
  liability_policy_ref: policy://...
  status:
    active | degraded | partially_offline | emergency_stopped |
    maintenance | suspended | retired
```

`RobotFleetRecord.unit_refs` has cardinality `1..N`. A fleet of one is a
valid fleet and does not require a `FleetMissionCoordinationRecord` merely to
represent, commission, inventory, or operate that unit. Mission coordination
becomes mandatory only when one mission distributes or reconciles work across
multiple units or execution-node memberships.

```yaml
EmbodiedUnitIdentity:
  unit_id: robot://... | drone://... | device://... | facility-system://...
  system_id: system://...
  fleet_ref: robot_fleet://...
  hardware_identity_ref: hardware://... | null
  manufacturer_ref: org://... | null
  model_ref: device_model://... | null
  serial_or_attestation_ref: attestation://... | null
  controller_binding_ref: controller-binding://...
  runtime_assignment_ref: runtime-assignment://... | null
  runtime_assignment_history_refs:
    - runtime-assignment://...
  attached_node_membership_ref: node-membership://... | null
  allowed_zone_refs:
    - zone://...
  allowed_action_kinds:
    - navigation | manipulation | facility_control | access_control |
      sensor_capture | inspection | emergency_stop_test
  maintenance_state:
    ready | due_soon | due_now | locked_out | unknown
  status:
    commissioning | ready | active | idle | detached | degraded | offline |
    faulted | emergency_stopped | maintenance | retired
```

Identity records do not authorize actuation. They bind the physical body,
controller, policy, domain, and evidence paths that later gates must verify.
New `EmbodiedUnitIdentity` and resource-group writes use the RFC-compatible
`facility-system://` scheme. `facility_system://` is a read-only migration
alias: an explicit compatibility reader may normalize it before admission, but
no canonical identity, admission, receipt, or derived write may emit it.

`runtime_assignment_ref` is only the unit's current admitted execution
placement and may be `null` while the unit is commissioning, idle without a
placement, detached, held as inventory, under maintenance, or retired.
`runtime_assignment_history_refs` is a derived, rebuildable projection of the
unit's separately admitted runtime assignments, ordered through their
`predecessor_runtime_assignment_ref` lineage. It preserves prior and superseded
assignment refs across detachment and reassignment and may be empty for a
never-assigned unit, but it is not independently mutable truth and never
confers current placement, membership, or actuator authority.

An embodied unit and an autonomous-system node are different identities. A
robot or drone may host an admitted Hypervisor Node, may attach through a local
bridge hosted by another admitted node, or may remain a controller-addressed
unit with no node membership of its own. One node may operate several units,
and one unit may be rebound to a replacement node after a governed transition.
Neither physical presence nor controller reachability creates system
membership, and admitting a node does not authorize its attached actuators.

## Controller Binding

Robot and device controllers are privileged physical interfaces. They are not
ordinary connectors even when the transport looks like an API.

```yaml
RobotControllerBinding:
  binding_id: controller-binding://...
  system_id: system://...
  deployment_profile_ref: deployment-profile://...
  unit_ref: robot://... | drone://... | device://... | facility-system://...
  controller_ref: controller://...
  runtime_node_ref: runtime://...
  node_membership_ref: node-membership://...
  local_control_supervisor_ref: local_control_supervisor://...
  compatibility_bridge_ref: local_control_bridge://... | null
  runtime_graph_manifest_ref: embodied-runtime-graph-manifest://...
  runtime_graph_manifest_hash: hash
  native_runtime_profile: micro | edge
  embodiment_adapter_ref: embodiment_adapter://...
  embodiment_adapter_hash: hash
  protocol_profile:
    native_ioi | ros_like | industrial_control | drone_control |
    vehicle_adjacent | facility_control | proprietary | other
  command_topics_or_endpoints:
    - ref: endpoint://...
      action_kind: navigation | manipulation | facility_control | other
      physical_stream_contract_ref: physical-stream-contract://...
  telemetry_topics_or_endpoints:
    - stream_ref: telemetry_stream://...
      physical_stream_contract_ref: physical-stream-contract://...
  heartbeat_and_failsafe_policy_ref: heartbeat_policy://...
  command_queue_ref: physical_command_queue://...
  sensor_refs:
    - sensor://...
  actuator_refs:
    - actuator://...
  authority_scope_refs:
    - scope:robot.navigate
  status:
    unbound | validating | bound | degraded | disconnected |
    emergency_stopped | revoked
```

Controller binding must prove:

- which admitted system membership, runtime node, and local supervisor can send
  commands, and whether an external compatibility bridge is involved;
- which command surfaces are available;
- which sensors provide evidence;
- which actuators can move or affect the world;
- which heartbeat and fail-closed behavior apply;
- which authority scopes are required;
- where receipts and telemetry are emitted.

A `native_ioi` binding connects the supervisor directly to a controller driver
or native `micro` executor. Other protocol profiles may use a
`LocalControlBridge`, but the bridge remains a compatibility binding beneath
the supervisor. It cannot become a parallel source of authority, resource
ownership, safety state, or command admission.

## Sensor and Actuator Registries

Sensors and actuators are registered separately. A camera stream may be safe to
read while the gripper beside it is unsafe to actuate.

```yaml
SensorRegistryEntry:
  sensor_ref: sensor://...
  system_id: system://...
  embodied_domain_ref: embodied_domain://...
  unit_ref:
    robot://... | drone://... | device://... | facility-system://... | null
  controller_binding_ref: controller-binding://... | null
  source_node_membership_ref: node-membership://... | null
  physical_zone_refs:
    - zone://...
  sensor_kind:
    camera | depth | lidar | radar | imu | gps | encoder |
    force_torque | proximity | audio | thermal | chemical |
    system_state | human_presence | other
  data_class:
    public | internal | private | regulated | safety_critical
  stream_ref: telemetry_stream://...
  calibration_ref: calibration://...
  freshness_requirement_ms: integer
  confidence_policy_ref: policy://...
  redaction_policy_ref: policy://... | null
  required_for_action_kinds:
    - navigation | manipulation | facility_control | access_control
  status:
    active | stale | degraded | blocked | offline | untrusted
```

```yaml
ActuatorRegistryEntry:
  actuator_ref: actuator://...
  system_id: system://...
  embodied_domain_ref: embodied_domain://...
  unit_ref: robot://... | drone://... | device://... | facility-system://...
  controller_binding_ref: controller-binding://...
  actuator_kind:
    base_motion | arm_joint | gripper | tool | door_lock |
    dispenser | switch | valve | drone_motor | other
  physical_zone_refs:
    - zone://...
  allowed_action_kinds:
    - navigation | manipulation | facility_control | access_control
  max_limits:
    speed: number | null
    force: number | null
    torque: number | null
    range: object | null
  required_sensor_refs:
    - sensor://...
  safety_envelope_refs:
    - safety://...
  stop_condition_refs:
    - stop_condition://...
  status:
    enabled | disabled | degraded | locked_out | faulted |
    emergency_stopped
```

An active sensor must resolve to its owning system and embodied domain through
an admitted controller binding or source-node membership. `unit_ref` may remain
`null` for a fixed environmental or facility sensor; this must not be papered
over with a fictitious robot identity. An actuator always binds a unit and an
admitted controller. It must not be admitted for command execution if its
required sensor evidence is stale, missing, untrusted, or blocked by policy.

## Embodied Resource Groups

`EmbodiedResourceGroup` gives one bounded DAS a reusable name for an exact set
of sensors and actuators: for example a camera array, left-arm kinematic chain,
drive train, end effector, safety interlock, process cell, or multi-unit
workcell. It is a versioned resource-composition object, not a unit, fleet,
runtime placement, system node, Worker, authority grant, or sovereign system.

```yaml
EmbodiedResourceGroup:
  group_id: embodied-resource-group://...
  group_revision_id: embodied-resource-group-revision://...
  revision: nonnegative_integer
  predecessor_group_revision_ref:
    embodied-resource-group-revision://... | null
  system_id: system://...
  deployment_profile_ref: deployment-profile://...
  embodied_domain_ref: embodied_domain://...
  display_name: string
  group_kind:
    kinematic_chain | drivetrain | end_effector | sensor_array |
    safety_interlock | workcell | facility_zone | process_cell |
    mission_subset | mixed | other
  direct_members:
    sensor_refs:
      - sensor://...
    actuator_refs:
      - actuator://...
    child_group_revision_refs:
      - embodied-resource-group-revision://...
  resolved_membership:
    unit_refs:
      - robot://... | drone://... | device://... | facility-system://...
    controller_binding_refs:
      - controller-binding://...
    node_membership_refs:
      - node-membership://...
    sensor_refs:
      - sensor://...
    actuator_refs:
      - actuator://...
  membership_closure_hash: hash
  physical_zone_refs:
    - zone://...
  targeting_mode:
    observe_only | exact_member_expansion | certified_local_atomic_segment
  local_control_boundary_ref:
    controller-binding://... | controller://... | null
  allowed_action_kinds:
    - navigation | manipulation | facility_control | access_control |
      sensor_capture | inspection | emergency_stop_test
  sensor_evidence_policy_ref: policy://...
  concurrency_policy_ref: policy://...
  partial_availability_policy_ref: policy://...
  time_sync_contract_ref: time_sync://... | null
  stricter_group_safety_envelope_refs:
    - safety://...
  emergency_stop_authority_refs:
    - estop://...
  health_aggregation_policy_ref: policy://...
  health_projection_ref: projection://... | null
  status:
    proposed | validating | active | degraded | blocked |
    emergency_stopped | retired
  admission_receipt_ref: receipt://...
```

Every admitted group revision is an immutable membership snapshot. It must
contain at least one direct sensor, actuator, or child-group revision; nested
groups form an acyclic graph; and recursive expansion must terminate in exact
leaf `sensor://` and `actuator://` refs whose registry records bind the same
`system_id` and `embodied_domain_ref`. Every non-null unit, controller, and
source-node path must resolve inside that system and active deployment profile.
Dynamic selectors may propose a new revision, but cannot remain late-bound in
an active envelope or command. A unit ref never means "this unit and whatever
hardware it may contain later."

An `observe_only` revision has no actuator leaves. Its resolved unit and
controller lists may be empty only when every sensor is a fixed or environmental
sensor with an explicit admitted source-node membership. This supports a
facility sensor array without inventing a robot, controller, or actuator
identity. Every actuator-bearing revision resolves each actuator through an
embodied unit and admitted controller binding.

Resources may appear in more than one group. Overlap never permits conflicting
commands: queue admission still compares the exact expanded actuator, zone,
safety-envelope, and controller identities. Group safety is the conjunction of
member, unit, controller, zone, and stricter group restrictions; incompatible
requirements fail closed. Group status and health are derived from admitted
member state under the named aggregation policy and cannot hide a blocked,
faulted, stale, untrusted, or emergency-stopped required leaf.

`observe_only` groups carry no actuator target. `exact_member_expansion` expands
into explicit controller-local commands and makes no cross-controller atomicity
claim. `certified_local_atomic_segment` is valid only when all affected leaves
resolve to one independently enforceable local control-and-safety boundary,
which may be a certified interlock spanning controllers. A group that spans
controllers, units, or node memberships otherwise remains mission-level
composition and cannot promise hardware-transaction atomicity.

Group membership never grants read, actuation, node membership, runtime
placement, allocation, or authority. Every admitted assignment, mission
envelope, safety envelope, command, and receipt that uses a group binds the
exact `group_revision_id` and `membership_closure_hash` and retains the expanded
leaf refs. A later group revision cannot widen an already admitted act.

Creating or observing a group does not require fleet coordination. A
single-unit limb, drivetrain, or sensor array on one execution membership needs
no `FleetMissionCoordinationRecord`. If mission work is actually distributed or
reconciled across multiple units or execution-node memberships, the existing
coordination record and one current allocation lease per affected assignment
remain mandatory. No group may cross a sovereign `system_id`; cross-system
cooperation uses AIIP and each system's independently admitted local groups.

## Embodied Capability Package Binding

Foundry produces embodied capability packages, but a package is not runnable on
a physical domain until Embodied Runtime binds it to a specific fleet, robot,
controller set, sensor set, calibration set, world contract, supervision policy,
and safety envelope.

```yaml
EmbodiedCapabilityBinding:
  binding_id: package_binding://...
  embodied_capability_package_ref: package://...
  embodied_runtime_candidate_ref: embodied_candidate://... | null
  embodied_runtime_graph_manifest_ref:
    embodied-runtime-graph-manifest://...
  capability_spec_ref: capability_spec://...
  domain_ref: embodied_domain://...
  fleet_ref: robot_fleet://...
  unit_refs:
    - robot://... | drone://... | device://... | facility-system://...
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
  embodiment_adapter_refs:
    - embodiment_adapter://...
  controller_binding_refs:
    - controller-binding://...
  sensor_contract_ref: sensor_contract://...
  action_schema_ref: action_schema://...
  embodied_action_policy_contract_refs:
    - embodied-action-policy-contract://...
  world_contract_ref: world_contract://...
  calibration_refs:
    - calibration://...
  time_sync_contract_ref: time_sync://...
  embodied_deployment_assurance_case_ref: assurance_evidence://...
  safety_envelope_ref: safety://...
  supervision_policy_ref: supervision://...
  required_success_detector_refs:
    - success_detector://...
  allowed_runtime_mode:
    observe_only | shadow | supervised_low_risk | human_in_loop |
    canary | production
  status:
    proposed | validating | bound | shadowing | canary | active |
    paused | rolled_back | recalled | revoked
```

Binding must prove that the package's declared observation/action assumptions
match the actual robot, controller, calibration, sensor freshness, world model,
and safety envelope. If any required contract is stale or incompatible, the
package may run only in simulation or shadow mode, or not at all.

### Embodiment and Model-Neutral Action Contracts

The canonical wire shapes are defined in the
[`EmbodimentAdapter`](../../foundations/common-objects-and-envelopes.md#embodimentadapter)
and
[`EmbodiedActionPolicyContract`](../../foundations/common-objects-and-envelopes.md#embodiedactionpolicycontract)
sections of the common-object owner.
The adapter maps one device, controller family, ROS graph, flight stack, or
external runtime into IOI identities, frames, streams, actions, lifecycle,
health, and receipt semantics. It is an adoption and portability surface, not
an authority grant, assurance equivalence, or alternate control plane. A live
graph pins its exact adapter hash, units, joint/tool order, resource closure,
calibration, clock, controller mode, and supervisor compatibility.

`EmbodiedActionPolicyContract` maps an ontology-level permitted action class to
bounded target-specific action semantics. It applies equally to a learned
policy, VLA, classical planner, behavior graph, optimizer, or teleoperator
source and binds pre/postconditions, observation/action schemas, frames,
resources, freshness, rate, horizon, inference deadline, state/reset,
uncertainty/OOD, interruption, fallback, verification, safety compatibility,
receipts, and promotion/recall lineage.

Hardware-neutral is not semantics-neutral. Matching tensor dimensions, model
names, or controller endpoints never proves that a policy can bind a new body.
A direct torque or joint-space policy is eligible only when its exact artifact,
embodiment adapter, controller chain, resource closure, timing profile, and
deployment-bound assurance case have been admitted.

Every deliberative source produces a finite, expiring, uncertainty-bearing
`EmbodiedActionChunk` (`embodied-action-chunk://...`): a waypoint set,
trajectory segment, setpoint sequence,
grasp, locomotion phase, or coordinated subtask bound to the current mission
envelope, action-policy revision, observation/world watermark, frames,
resources, leases, provenance, interruption boundaries, and expected
observations. The canonical wire object is defined with the other embodied
envelopes in
[`common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md#embodiedactionchunk).
It is always a proposal, never an actuator command, safety approval, authority
grant, or exactly-once effect.

Selection means only that a candidate may proceed to current world/sensor
checks, Physical Action Safety, authority, queue admission, deterministic
motion, and the independent local supervisor. The supervisor may deny, clip,
replace, interrupt, or expire it. A late result, stale observation, lost lease,
mismatched hash, or missed inference deadline invokes the declared local
fallback instead of execution.

## World Model, Maps, Zones, Calibration, and Environment State

Embodied runtime needs an explicit physical-state plane. It cannot rely on a
prompt, screenshot, or local controller memory as the only representation of the
world. The runtime keeps four linked layers distinct:

1. structural assets and digital-twin geometry;
2. coordinate frames, kinematics, calibration, and time state;
3. live probabilistic occupancy, objects, humans, hazards, and uncertainty;
4. semantic ontology, affordances, task state, and operating constraints.

`WorldRepresentationManifest` pins the representations and transformations used
by one runtime graph. It may project OpenUSD, meshes, maps, splats, neural
scenes, occupancy, collision proxies, or simulator assets, but none of those
formats becomes live world truth or actuator authority.
Its canonical layered wire shape is defined in
[`common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md#worldrepresentationmanifest).
The manifest is a versioned declaration and provenance root. `WorldModel` is
the domain's current policy-bound projection; `EnvironmentState` is time-indexed
live state. A simulator or authoring tool may consume or produce compatible
representations without being able to assert operational truth.

```yaml
WorldModel:
  world_model_id: world_model://...
  embodied_domain_ref: embodied_domain://...
  map_refs:
    - physical_map://...
  zone_refs:
    - zone://...
  calibration_refs:
    - calibration://...
  environment_state_ref: environment_state://...
  object_model_refs:
    - object_model://...
  world_representation_manifest_refs:
    - world-representation-manifest://...
  semantic_scene_graph_refs:
    - artifact://...
  affordance_map_refs:
    - artifact://...
  collision_proxy_refs:
    - artifact://...
  physics_proxy_refs:
    - artifact://...
  task_state_ref: task://... | null
  action_history_refs:
    - physical_command://...
  dynamic_obstacle_policy_ref: policy://...
  human_presence_policy_ref: policy://...
  freshness_status:
    current | stale | partial | unknown
```

```yaml
PhysicalMap:
  map_id: physical_map://...
  source_refs:
    - artifact://... | telemetry_stream://... | simulator://...
  map_kind:
    floorplan | occupancy_grid | point_cloud | semantic_map |
    route_graph | facility_model | geofence | mesh | gaussian_splat |
    neural_scene | collision_proxy | physics_proxy | other
  coordinate_frame_ref: frame://...
  version: string
  valid_zone_refs:
    - zone://...
  created_from:
    manual | sensor_scan | simulation | import | fused
  receipt_refs:
    - receipt://...
```

```yaml
PhysicalZone:
  zone_ref: zone://...
  domain_ref: embodied_domain://...
  zone_kind:
    public_area | restricted_area | human_dense | equipment_area |
    vehicle_area | no_go | staging | charging | maintenance
  geometry_ref: artifact://...
  allowed_unit_refs:
    - robot://... | drone://... | device://... | facility-system://...
  allowed_action_kinds:
    - navigation | inspection
  supervision_requirement:
    autonomous | monitored | human_on_loop | human_in_loop |
    manual_confirm_each_action
  emergency_stop_refs:
    - estop://...
```

```yaml
CalibrationRecord:
  calibration_ref: calibration://...
  unit_or_sensor_ref:
    robot://... | drone://... | device://... | facility-system://... |
    sensor://... | actuator://...
  coordinate_frame_ref: frame://...
  calibration_kind:
    camera_intrinsics | sensor_extrinsics | arm_kinematics |
    base_frame | tool_center_point | map_alignment | other
  valid_from: timestamp
  valid_until: timestamp | null
  quality_status:
    valid | stale | failed | unknown
  receipt_refs:
    - receipt://...
```

```yaml
EnvironmentState:
  state_ref: environment_state://...
  domain_ref: embodied_domain://...
  observed_at: timestamp
  source_stream_refs:
    - telemetry_stream://...
  occupancy_refs:
    - artifact://...
  human_presence_refs:
    - observation://...
  hazard_refs:
    - hazard://...
  weather_or_site_condition_ref: artifact://... | null
  freshness_ms: integer
  confidence: number | null
  status:
    current | stale | partial | degraded | unknown
```

### Embodied Context And State Binding

The runtime bottleneck is embodied state binding, not raw prompt or model context
length. Embodied Runtime should bind the compact state required for safe action:

```text
world representation
  maps, splats, meshes, occupancy, point clouds, semantic scene graphs,
  object identity, affordances, collision proxies, and physics proxies

robot state
  joint state, gripper/tool state, controller mode, battery, health,
  force/torque, calibration, latency, supervisor, and compatibility-bridge posture

task state
  goal, subgoal, preconditions, progress, blocked conditions, undo or
  compensation posture, and prior action history

evidence memory
  demonstrations, failures, receipts, eval traces, human labels, sensor
  evidence, actuator receipts, and physical replay refs

policy-bound retrieval
  only eligible, relevant, authority-permitted context enters a model route,
  worker, verifier, or action-policy call

runtime action context
  short-horizon observation/action window for VLA, visuomotor policy,
  action expert, controller adapter, or deterministic controller

safety context
  independent constraints for zone, collision, speed, force, human proximity,
  emergency stop, supervision, authority, and receipts
```

The live runtime should not stuff unbounded frames, logs, or hidden controller
state into a model and call that context. It should use explicit refs, freshness
requirements, policy-bound views, and receipts so perception, planning, action,
and safety can be audited and replayed independently.

## Two-Speed Mission And Control Contract

Embodied execution preserves the two-speed system doctrine: governed
intelligence admits bounded physical work, while all deadline-sensitive
execution and safety remain local. The local side is not one undifferentiated
"fast plane," however. It contains three separately scheduled and isolated
domains:

```text
slow governance / intelligence plane
  Goal Kernel, mission planning, ontology actions, policy, authority, budget,
  route selection, approvals, verifier paths, operator handoff, course
  correction, and admission of a bounded mission/action envelope

local execution side
  on-unit autonomy domain
    perception, state estimation, local planning, learned-policy/VLA inference,
    candidate selection, and latency-bounded action-chunk proposals

  deterministic motion domain
    feasibility checks, kinematics, trajectories, whole-body/control
    allocation, interpolation, resource arbitration, and high-frequency control

  independent runtime-assurance / safety domain
    safe-set and operating-envelope monitor, command switch, clipping/veto,
    watchdogs, recovery or minimum-risk controller, interlocks, and e-stop
```

On-unit autonomy normally executes as `bounded_soft_realtime`; it may be
powerful, learned, and local without being treated as deterministic or
safety-certified. Deterministic motion owns admitted trajectory/control
execution and exact resource arbitration. The runtime-assurance/safety domain
must be able to reject both domains, remain available when a model, planner,
accelerator, network, or general runtime fails, and invoke the admitted recovery
or minimum-risk behavior.

Physical Action Safety owns safety policy, envelope, supervision, emergency
authority, evidence, and incident semantics. This document owns how a native
runtime isolates and enforces those referenced constraints. A particular
deployment may use OEM-certified controllers or safety PLCs inside the local
domain; no generic runtime component inherits certification merely because it
implements this architecture.

The slow plane issues a `PhysicalMissionControlEnvelope` that binds the target
fleet/units, allowed action classes, zones, limits, start/expiry, supervisor and
e-stop posture, local controller/capability versions, required evidence,
exception policy, and revocation epoch. The three local domains may execute only
inside that envelope and the independent supervisor's stricter local veto. They
emit bounded segment
commitments and exception/incident receipts rather than one globally settled
record for every control tick.

```yaml
PhysicalMissionControlEnvelope:
  envelope_id: physical_mission_envelope://...
  system_id: system://...
  deployment_profile_ref: deployment-profile://...
  work_subject:
    kind:
      goal_run | automation_run | work_item | work_claim |
      service_order | physical_action_intent
    ref:
      goal://... | automation-run://... | work_item://... | work-claim://... |
      order://... | intent://...
  embodied_domain_ref: embodied_domain://...
  runtime_graph_manifest_ref: embodied-runtime-graph-manifest://...
  runtime_graph_manifest_hash: hash
  graph_activation_transaction_ref: graph-activation-transaction://...
  local_control_supervisor_refs: [local_control_supervisor://...]
  assurance_evidence_bundle_ref: assurance_evidence://...
  fleet_mission_coordination_ref: fleet-mission-coordination://... | null
  coordination_epoch: nonnegative_integer | null
  coordination_node_membership_refs: [node-membership://...]
  unit_refs:
    - robot://... | drone://... | device://... | facility-system://...
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
  allocation_lease_refs: [fleet-mission-allocation-lease://...]
  spacetime_reservation_lease_refs: [spacetime-reservation-lease://...]
  shared_world_state_ref: environment_state://... | state://... | null
  minimum_world_state_watermark: string | null
  allowed_action_kinds: [string]
  zone_refs: [zone://...]
  motion_force_speed_energy_limits_ref: policy://...
  valid_from: timestamp
  expires_at: timestamp
  authority_ref: grant://...
  safety_envelope_ref: safety://...
  local_controller_version_refs: [controller://...]
  supervisor_and_estop_refs: [supervision://... | estop://...]
  required_evidence_policy_ref: policy://...
  exception_policy_ref: policy://...
  revocation_epoch: integer
  status:
    proposed | admitted | active | paused | expired | revoked |
    completed | incident
```

`work_subject` is the common `TypedWorkSubjectBinding`; its discriminator and
ref must agree. The usual parent is a GoalRun. A direct automation, work item,
claim, service order, or physical-action intent is valid only when that owner's
contract independently admits the physical work. The domain term *mission* in
this envelope names the slow-plane physical safety/control scope, not a generic
`HypervisorMission` record.

`LocalControlSegment` is the embodied-runtime record for one bounded interval
of local controller execution. It is not the safety/evidence commitment itself:
Physical Action Safety owns when a `PhysicalActionSegmentCommitmentReceipt` and
immediate exception, e-stop, and incident receipts are required; the events and
receipts owner defines their field-level schemas.

```yaml
LocalControlSegment:
  segment_ref: control-segment://...
  mission_control_envelope_ref: physical_mission_envelope://...
  local_control_supervisor_ref: local_control_supervisor://...
  compatibility_bridge_ref: local_control_bridge://... | null
  controller_binding_ref: controller-binding://...
  unit_refs:
    - robot://... | drone://... | device://... | facility-system://...
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
  command_refs: [physical_command://...]
  started_at: timestamp
  ended_at: timestamp | null
  telemetry_range_refs: [telemetry_range://...]
  physical_action_segment_commitment_receipt_ref: receipt://... | null
  exception_receipt_refs: [receipt://...]
  incident_refs: [embodied_incident://...]
  status:
    proposed | active | completed | clipped | stopped | failed | ambiguous
```

Goal Kernel operates at mission, checkpoint, exception, and course-correction
timescales. It may never be placed inside a hard real-time actuator loop.
Network loss cannot broaden the envelope; local control either continues only
under an explicitly admitted offline policy or transitions to a safe state.

## Intra-System Fleet Mission Coordination

A fleet or swarm belonging to one bounded DAS is primarily a **same-system
distributed-work topology**, not a federation of sovereign systems. Its nodes
and units share one `system_id`, constitution, ordering/finality contract, and
mission authority boundary. Native L0 and Embodied Runtime contracts assign and
reconcile useful work across those members; AIIP is neither required nor the
semantic boundary. Same-system members do not negotiate
`CollaborationTermsEnvelope` with their own system, and coordination does not
turn each robot into an independent chain.

When a mission distributes or reconciles work across multiple units or
execution-node memberships, the mission plane must make that distribution
explicit. A singleton fleet operating through one execution membership does
not need this record:

```yaml
FleetMissionCoordinationRecord:
  coordination_id: fleet-mission-coordination://...
  system_id: system://...
  deployment_profile_ref: deployment-profile://...
  embodied_domain_ref: embodied_domain://...
  work_subject:
    kind:
      goal_run | automation_run | work_item | work_claim |
      service_order | physical_action_intent
    ref:
      goal://... | automation-run://... | work_item://... | work-claim://... |
      order://... | intent://...
  mission_control_envelope_ref: physical_mission_envelope://...
  fleet_refs: [robot_fleet://...]
  coordination_mode:
    assigned_coordinator | replicated_coordinator | partitioned_peer_policy
  coordination_node_membership_refs: [node-membership://...]
  active_coordination_epoch: nonnegative_integer
  shared_world_state_ref: environment_state://... | state://...
  shared_world_state_watermark: string
  world_state_merge_policy_ref: policy://...
  allocation_policy_ref: policy://...
  allocation_lease_refs: [fleet-mission-allocation-lease://...]
  coordination_cell_refs: [coordination-cell://...]
  spacetime_reservation_lease_refs: [spacetime-reservation-lease://...]
  partition_and_degraded_mode_policy_ref: policy://...
  rejoin_and_rebalance_policy_ref: policy://...
  effect_deduplication_and_reconciliation_policy_ref: policy://...
  checkpoint_ref: checkpoint://... | null
  status:
    proposed | admitted | active | degraded | partitioned | rebalancing |
    paused | completed | revoked | incident
```

```yaml
FleetMissionAllocationLease:
  allocation_lease_id: fleet-mission-allocation-lease://...
  system_id: system://...
  coordination_ref: fleet-mission-coordination://...
  work_subject:
    kind:
      goal_run | automation_run | work_item | work_claim |
      service_order | physical_action_intent
    ref:
      goal://... | automation-run://... | work_item://... | work-claim://... |
      order://... | intent://...
  coordination_epoch: nonnegative_integer
  allocated_work_ref: work_item://... | goal://... | intent://...
  unit_ref: robot://... | drone://... | device://... | facility-system://...
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
  controller_binding_ref: controller-binding://...
  execution_node_membership_ref: node-membership://...
  minimum_world_state_watermark: string
  coordination_cell_refs: [coordination-cell://...]
  spacetime_reservation_lease_refs: [spacetime-reservation-lease://...]
  authorized_effect_id_refs: [effect://...]
  valid_from: timestamp
  expires_at: timestamp
  supersedes_lease_ref: fleet-mission-allocation-lease://... | null
  status: proposed | active | completed | expired | fenced | revoked | ambiguous
```

Allocation answers **who owns which work**. It does not answer **where and when
that unit may occupy or affect shared physical space**. The latter requires an
expiring, epoch-fenced `SpacetimeReservationLease`. Its canonical wire shape is
defined in
[`common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md#spacetimereservationlease)
and binds the work/allocation, unit and exact group closure, geometry and frame,
valid interval, uncertainty/clearance margin, capacity/exclusivity, priority,
preemption, observed world watermark, partition posture, supervisor, admission,
fencing, and receipts.

A reservation permits an admitted attempt under bounded coordination
assumptions; it never proves that the physical world is clear and never
overrides local perception, collision avoidance, human-presence rules, the
supervisor, or emergency stop. Cooperative manipulation or formation flight
may use `cooperative` capacity only when all participating allocations,
resource leaves, controller boundaries, timing tolerances, and local failure
responses are explicit. A reservation with an ambiguous physical effect must
be observed and reconciled before retry or reassignment.

`coordination-cell://...` refs identify derived operational partitions of a
site, airspace, workcell, or peer neighborhood for scaling coordination. A cell
is not a new sovereign system, node membership, authority domain, or safety
boundary. Cells may split, merge, or migrate only at admitted coordination
boundaries, and every change increments or binds a fencing epoch. Local units
retain the prior cell's safe, time-bounded posture until the new cell state is
admitted; reachability to a new coordinator cannot transfer work or space.

The coordination record, every allocation lease, and the referenced
`PhysicalMissionControlEnvelope` must carry the same typed parent work subject.
`allocated_work_ref` narrows one allocation within that pursuit; it cannot silently
replace or mutate the parent subject. Neither record creates an independent
Mission lifecycle, authority, budget, acceptance, or evidence plane.

These contracts apply the following semantics:

- Allocation is leased, epoch-bound, and scope-bound. Reassignment first
  expires, revokes, or fences the previous lease; scheduler reachability alone
  never creates authority to perform the work.
- Shared world state is versioned and freshness-bounded. A unit may use local
  perception inside its safety envelope, but it may not claim globally
  conflicting work from an inadmissibly stale coordination watermark.
- Allocation and spacetime are separate leases. A unit needs both whenever
  allocated work consumes a reserved corridor, volume, workcell, tool, shared
  object, or capacity; holding one cannot imply the other.
- A coordination epoch fences superseded coordinators and allocations. It is a
  mission-level fence, not a silent change to the DAS writer epoch,
  membership, or ordering/finality profile.
- Partition behavior is declared before the mission. A partition may permit
  completion of an already leased safe segment, a safe return, observe-only
  operation, local-policy-limited peer coordination, or safe stop; it may never
  widen zones, effects, budgets, authority, or lease duration.
- A disconnected coordination cell may continue only with its last admitted
  cell membership, world watermark, allocation leases, spacetime reservations,
  and local safety posture. It cannot renew or invent leases from elapsed wall
  time, and potentially conflicting cells fail closed or enter predeclared
  nonoverlapping degraded modes.
- Rejoining units report their last accepted epoch, world-state watermark,
  completed segments, effect identifiers, actuator receipts, and ambiguous
  effects before new allocation. Rebalance occurs at mission/segment
  boundaries and never migrates a servo loop through a distributed workgraph.
- Effect identifiers and idempotency keys suppress a provably duplicate
  admission. An unknown physical effect is reconciled under its recovery class
  before retry; deduplication metadata is not evidence that an effect did or
  did not occur.

This coordination record may project generic GoalRun, frontier, claim-lease,
runtime-assignment, and receipt objects into an embodied mission, but it does
not replace their owner contracts. Conversely, an OutcomeRoom or generic agent
swarm may help plan, verify, or course-correct the mission; it may not become
the actuator control loop. Different node operators, sites, or failure domains
do not alone create multiple sovereign systems. If a participant requires its
own constitution, operational truth, admission authority, and independent exit,
it is a separate DAS and the relationship crosses the AIIP boundary below.

### Cross-System Embodied Cooperation

AIIP begins only at an independently governed system boundary. When such fleets
cooperate, each DAS retains its own
`system_id`, node memberships, coordination epoch, mission envelope, world-state
truth, controller bindings, and local safety veto. AIIP may exchange an
accepted collaboration root plus typed mission offers, bounded work claims,
restricted world-state views, handoff checkpoints, evidence, and receipts.
It does not merge the fleets into one implicit membership set or make a foreign
packet direct actuator authority. Cross-system work is admitted into a local
coordination record and local mission envelope before execution; either system
may decline, pause, revoke, or exit according to the accepted terms without
disabling the other's independent safe operation.

## Local Control Supervisor, Compatibility Bridge, Heartbeat, and Failsafe

`LocalControlSupervisor` is the native local enforcement owner between admitted
mission work, autonomy components, deterministic motion, independent runtime
assurance, and physical controllers. It must execute close enough to the body or
workcell to preserve watchdog, veto, recovery, and fail-closed behavior when a
cloud, model, accelerator, site coordinator, operator link, or general-purpose
runtime degrades.

It is a logical local trust boundary, not permission to collapse every duty
into one process or failure domain. Its runtime-assurance monitor, command
switch, recovery path, and emergency-stop integration must retain the isolation
and availability required by the active `SafetyEnvelope` and deployment
assurance case even when autonomy or deterministic-motion components fail.

```yaml
LocalControlSupervisor:
  supervisor_id: local_control_supervisor://...
  system_id: system://...
  deployment_profile_ref: deployment-profile://...
  embodied_domain_ref: embodied_domain://...
  runtime_node_ref: runtime://...
  node_membership_ref: node-membership://...
  runtime_profile: micro | edge
  active_graph_manifest_ref:
    embodied-runtime-graph-manifest://... | null
  graph_activation_transaction_ref: graph-activation-transaction://... | null
  controller_binding_refs: [controller-binding://...]
  compatibility_bridge_refs: [local_control_bridge://...]
  assured_safety_input_contract_refs: [physical-stream-contract://...]
  runtime_assurance_timing_chain_ref: artifact://...
  runtime_assurance_timing_chain_hash: sha256:...
  monitor_period_us: positive_integer
  monitor_jitter_us: nonnegative_integer
  total_observation_to_switch_bound_us: positive_integer
  active_odd_compliance_receipt_ref: receipt://...
  switch_proof_test_receipt_ref: receipt://...
  switch_proof_test_due_at: timestamp
  safe_switch_receipt_ref: receipt://...
  restart_posture:
    no_restart_since_admission |
    restarted_inactive_unarmed_and_readmitted
  restart_unarmed_receipt_ref: receipt://...
  exclusive_actuator_writer_lease_ref: resource-lease://... | null
  exclusive_actuator_writer_fencing_epoch: nonnegative_integer | null
  exclusive_actuator_writer_fencing_token_hash: hash | null
  standby_supervisor_refs: [local_control_supervisor://...]
  safe_takeover_policy_ref: policy://...
  standby_safe_takeover_receipt_ref: receipt://... | null
  active_teleoperation_handoff_ref: operator_handoff://... | null
  command_queue_refs: [physical_command_queue://...]
  heartbeat_and_failsafe_policy_ref: heartbeat_policy://...
  runtime_assurance_component_keys: [string]
  recovery_or_minimum_risk_controller_refs: [controller://...]
  active_mission_envelope_ref: physical_mission_envelope://... | null
  local_control_segment_ref: control-segment://... | null
  telemetry_stream_refs: [telemetry_stream://...]
  isolation_and_availability_evidence_ref: artifact://...
  status:
    inactive | starting | ready_unarmed | armed | active | degraded | partitioned |
    quiescing | safe_stopped | fail_closed | emergency_stopped
```

The supervisor validates graph, physical streams, schedules, mission envelope,
lease, exact resources, world-state, clocks, heartbeat, and revocation
compatibility before admitting a local control segment. It owns active graph
scheduling, stream/time-health enforcement, exclusive actuator-writer fencing,
command arbitration, recovery-controller switching, watchdogs, and the final
local veto. It may admit, clip, delay, interrupt, reject, or transfer to an
admitted recovery/minimum-risk controller, but it cannot create or widen
authority. It rejects an expired switch proof test, an ODD exit or unknown
state, a late observation-to-switch path, loss of every assured independent
safety input, or a stale recoverable-region margin. Standby takeover requires a
new fence, restart-unarmed evidence, and a locally proven safe-switch/handoff
receipt; two supervisors never write the same actuator concurrently. The
field-level safety policy and evidence objects remain owned by Physical Action
Safety.

`LocalControlBridge` is only the compatibility binding between the supervisor's
native contracts and an external controller stack, robotics middleware,
autopilot, fieldbus gateway, or vendor runtime. A native IOI controller path
does not require one.

```yaml
LocalControlBridge:
  bridge_id: local_control_bridge://...
  system_id: system://...
  deployment_profile_ref: deployment-profile://...
  embodied_domain_ref: embodied_domain://...
  local_control_supervisor_ref: local_control_supervisor://...
  runtime_node_ref: runtime://...
  node_membership_ref: node-membership://...
  controller_binding_refs:
    - controller-binding://...
  network_profile_ref: network_profile://...
  external_runtime_kind:
    ros_like | industrial_control | drone_autopilot | vehicle_adjacent |
    facility_control | proprietary | other
  external_runtime_version_ref: artifact://...
  component_mapping_ref: artifact://...
  stream_mapping_ref: artifact://...
  action_mapping_ref: artifact://...
  mapping_hash: hash
  telemetry_stream_refs:
    - telemetry_stream://...
  status:
    proposed | validating | active | degraded | incompatible |
    disconnected | revoked
```

```yaml
HeartbeatFailsafePolicy:
  policy_id: heartbeat_policy://...
  max_controller_heartbeat_gap_ms: integer
  max_daemon_heartbeat_gap_ms: integer
  max_supervisor_heartbeat_gap_ms: integer | null
  on_controller_gap:
    hold_position | slow_stop | safe_stop | power_cut | operator_handoff
  on_daemon_gap:
    pause_queue | drain_safe_commands | safe_stop | local_supervisor_only
  on_supervisor_gap:
    continue_under_separately_assured_boundary | safe_stop | emergency_stop
  fail_closed_required: boolean
  last_tested_at: timestamp
  receipt_refs:
    - receipt://...
```

The supervisor and bridge must never treat a live model stream as a heartbeat.
Heartbeat proves control-channel health, not reasoning quality. A bridge cannot
issue authority, renew leases, arm a graph, weaken a supervisor decision, or
substitute external dashboard state for IOI evidence. Loss or incompatibility
of a required bridge causes the supervisor's declared degradation or safe
state; it never causes a fallback around the supervisor.

`continue_under_separately_assured_boundary` is valid only when the active
mission and deployment assurance case bind another locally available safety
controller that retains the monitor, switch, recovery, and emergency-stop
guarantees after supervisor loss. Otherwise a lost supervisor fails to the
declared safe or emergency-stop state.

## Latency, Degraded Networking, Offline, and Emergency Stop

Embodied domains need explicit runtime guarantees for timing and degraded
operation.

```yaml
EmbodiedRuntimeGuarantee:
  guarantee_id: runtime_guarantee://...
  domain_ref: embodied_domain://...
  max_command_latency_ms: integer
  max_observation_latency_ms: integer
  monitor_period_us: positive_integer
  monitor_jitter_us: nonnegative_integer
  total_observation_to_switch_bound_us: positive_integer
  graph_timing_chain_ref: artifact://...
  graph_timing_chain_hash: sha256:...
  timing_evidence_mode: hard_realtime_analytic | bounded_soft_tail
  timing_evidence_ref: artifact://... | evidence://...
  timing_evidence_hash: sha256:...
  max_estop_latency_ms: integer
  control_loop_owner:
    local_control_supervisor | separately_assured_local_controller
  remote_round_trip_in_control_loop: false
  max_mission_envelope_age_ms: integer
  control_segment_commit_interval_ms: integer
  offline_mode:
    disabled | observe_only | local_manual_only | safe_return |
    local_policy_limited
  degraded_network_policy:
    pause_new_commands | allow_low_risk_only | safe_stop |
    operator_handoff
  stale_sensor_policy:
    block_action | degrade_speed | require_supervisor | safe_stop
  odd_exit_response:
    deny_new_commands | switch_to_recovery | safe_stop |
    emergency_stop | operator_handoff
  odd_exit_response_deadline_ms: positive_integer
  operator_takeover_budget_ms: positive_integer
  clock_sync_requirement_ms: integer | null
  receipt_refs:
    - receipt://...
```

Emergency stop must remain local and testable. wallet.network may authorize who
can issue emergency revoke or e-stop commands, but IOI L1, settlement, cloud
availability, or a remote model response cannot be the live safety path.

The guarantee separates mission-plane latency from controller-loop latency.
Remote daemon/model/wallet/Agentgres/AIIP latency may delay a new mission,
course correction, or envelope renewal, but it may not become part of the
deterministic high-frequency or runtime-assurance loop. Envelope expiry or loss of required heartbeat
causes the admitted local fallback, pause, handoff, or safe stop.

## Command Queue Semantics

Movement and manipulation commands are stateful physical operations. They should
not be modeled as one-shot function calls without queue, preflight, interrupt,
and result semantics.

```yaml
PhysicalCommandQueue:
  queue_id: physical_command_queue://...
  controller_binding_ref: controller-binding://...
  embodied_domain_ref: embodied_domain://...
  queue_policy_ref: policy://...
  active_command_ref: physical_command://... | null
  pending_command_refs:
    - physical_command://...
  interrupt_policy_ref: policy://...
  max_queue_depth: integer
  concurrency_policy:
    exclusive | actuator_scoped | zone_scoped | safe_parallel
  status:
    accepting | paused | draining | blocked | handoff_requested |
    emergency_stopped | offline
```

```yaml
PhysicalCommand:
  command_id: physical_command://...
  intent_ref: intent://...
  queue_ref: physical_command_queue://...
  unit_ref: robot://... | drone://... | device://... | facility-system://...
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
  actuator_refs:
    - actuator://...
  command_kind:
    navigate_to | follow_path | manipulate_object | use_tool |
    open_close | dispense | inspect | hold | pause | cancel | retry |
    request_handoff | emergency_stop | stop | other
  command_payload_ref: artifact://...
  preflight_check_refs:
    - preflight://...
  required_sensor_evidence_refs:
    - sensor://...
  safety_envelope_ref: safety://...
  mission_control_envelope_ref: physical_mission_envelope://...
  local_control_segment_ref: control-segment://... | null
  authority_ref: grant://...
  idempotency_key: string
  interruptible: boolean
  compensation_policy_ref: policy://... | null
  status:
    proposed | preflight | queued | active | paused | completed |
    cancelled | retrying | handoff_requested | stopped | failed |
    rejected | superseded | incident
```

A group-targeted command never follows a mutable "latest group" pointer. The
bound group revision and closure hash are provenance and constraint inputs;
`actuator_refs` and `required_sensor_evidence_refs` remain the exact expanded
leaves actually admitted for this command. Any group change while work is
queued requires re-admission. A mixed group containing even one actuator
remains `physical_action`; sensor membership cannot declassify it.

Queue admission must check command conflicts. For example, two commands that
share an actuator, zone, or safety envelope cannot run concurrently unless a
domain-specific safe-parallel policy explicitly permits it.

A queued command is mission-level intent, not a servo stream. The local
supervisor, using a native binding or compatibility bridge,
may expand it into controller-native setpoints only inside the admitted mission
envelope. Normal control ticks remain local; the supervisor emits segment
commitments, completion evidence, material deviation, envelope exhaustion,
ambiguous effect, safety intervention, and incident receipts at policy-defined
boundaries.

## Telemetry Streams and Physical Replay

Physical replay is the work-first inspection path for embodied runs. It is not a
raw video folder, raw controller log, or chain explorer.

Embodied runtime must preserve two related but distinct data forms:

```text
raw synchronized robot log
  robotics-native multimodal capture for replay, audit, incident review,
  calibration checks, and future dataset reconstruction

normalized episode dataset
  training/eval-ready sequential decision records with episode and step
  semantics, modality schemas, labels, rewards, success/failure annotations,
  and split manifests
```

The raw log is evidence. The normalized episode dataset is a derived training or
eval object and must pass training evidence eligibility before reuse.

```yaml
TimeSyncContract:
  time_sync_ref: time_sync://...
  domain_ref: embodied_domain://...
  clock_sources:
    - controller://... | sensor://... | bridge://...
  max_skew_ms: integer
  required_frame_refs:
    - frame://...
  sequence_policy:
    strict | allow_dropped_frames | event_time_with_watermark
  synchronization_status:
    valid | degraded | failed | unknown
  receipt_refs:
    - receipt://...
```

`TimeSyncContract` remains the embodied data-plane contract for correlating
sensor, controller, command, and frame time. It does not establish current
authority, lease validity, revocation freshness, rollback resistance, or a
global clock. When graph activation, allocation, action-chunk expiry, or
disconnected continuation depends on those propositions, the responsible PEP
also resolves the exact Platform Operability `TemporalVerificationProfile` and
`TemporalValidityEvaluation`. The two contracts may cite the same underlying
clock evidence while retaining distinct owners and claim scopes.

```yaml
RawRobotLog:
  robot_log_ref: robot_log://...
  domain_ref: embodied_domain://...
  run_ref: run://...
  time_sync_contract_ref: time_sync://...
  telemetry_stream_refs:
    - telemetry_stream://...
  command_refs:
    - physical_command://...
  operator_event_refs:
    - artifact://... | receipt://...
  log_container_ref: artifact://...
  normalized_episode_dataset_refs:
    - episode_dataset://... | dataset_snapshot://...
  retention_policy_ref: policy://...
  receipt_root: hash
  status:
    capturing | sealed | redacted | retained | deprecated | revoked
```

```yaml
NormalizedEpisodeDataset:
  episode_dataset_ref: episode_dataset://...
  source_robot_log_refs:
    - robot_log://...
  capability_spec_ref: capability_spec://...
  sensor_contract_refs:
    - sensor_contract://...
  action_schema_ref: action_schema://...
  episode_manifest_ref: artifact://...
  step_schema_ref: schema://...
  label_refs:
    - teacher_label_set://... | artifact://...
  split_manifest_ref: artifact://...
  training_evidence_eligibility_ref: eligibility://... | null
  status:
    draft | materialized | eligible | retained | deprecated | revoked
```

```yaml
PhysicalTelemetryStream:
  stream_id: telemetry_stream://...
  embodied_domain_ref: embodied_domain://...
  source_ref:
    sensor://... | controller://... | robot://... | drone://... |
    device://... | facility-system://... | embodied-resource-group-revision://... |
    bridge://...
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
  stream_kind:
    camera | depth | lidar | imu | joint_state | odometry |
    force_torque | command_status | system_health | human_presence |
    estop_state | controller_log | other
  retention_policy_ref: policy://...
  privacy_class: public | internal | confidential | restricted | regulated | safety_critical
  sampling_profile:
    rate_hz: number | null
    event_driven: boolean
  artifact_sink_ref: storage://... | null
  agentgres_projection_ref: projection://...
  status:
    active | degraded | stale | offline | blocked
```

```yaml
PhysicalTelemetryFrame:
  frame_id: telemetry_frame://...
  stream_ref: telemetry_stream://...
  captured_at: timestamp
  monotonic_time_ref: time://... | null
  sequence: integer
  observation_hash: hash
  artifact_ref: artifact://... | null
  redaction_status:
    none | redacted | private_ref_only
  quality:
    valid | dropped | delayed | partial | suspect
```

```yaml
PhysicalReplayBundle:
  replay_bundle_id: physical_replay://...
  run_ref: run://...
  domain_ref: embodied_domain://...
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
  command_refs:
    - physical_command://...
  telemetry_stream_refs:
    - telemetry_stream://...
  sensor_evidence_receipt_refs:
    - receipt://...
  actuator_command_receipt_refs:
    - receipt://...
  incident_refs:
    - incident://...
  timeline_segments:
    - segment://...
  proof_links:
    - receipt://... | state_root://... | settlement://...
  redacted_export_ref: artifact://... | null
```

Physical replay should support:

- timeline view by run, command, zone, robot, and incident;
- synchronized command, sensor, actuator, human-supervision, and e-stop state;
- map/zone overlay where available;
- pre/post sensor evidence comparison;
- receipt and proof drilldowns;
- redacted export for privacy-sensitive environments.

Raw telemetry may be large and non-public. Agentgres records refs, hashes,
projections, receipts, and replay indexes; storage backends hold payload bytes.

## Sim-To-Real Promotion Gates

Foundry may produce embodied workers, policies, and simulation-trained models,
but live physical deployment needs a promotion gate before any actuator command.

```yaml
SimToRealPromotionGate:
  gate_id: sim_to_real_gate://...
  foundry_job_ref: foundry_job://...
  embodied_capability_package_ref: package://... | null
  embodied_runtime_candidate_ref: embodied_candidate://... | null
  worker_or_model_ref: worker://... | model://...
  target_domain_ref: embodied_domain://...
  target_fleet_ref: robot_fleet://...
  target_resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
  sensor_contract_ref: sensor_contract://...
  action_schema_ref: action_schema://...
  simulator_world_refs:
    - simulator://...
  world_representation_manifest_refs:
    - world-representation-manifest://...
  eval_suite_refs:
    - eval_suite://...
  assurance_evidence_bundle_ref: assurance_evidence://...
  required_shadow_run_refs:
    - run://...
  required_human_review_refs:
    - approval://...
  allowed_initial_mode:
    observe_only | supervised_low_risk | human_in_loop |
    manual_confirm_each_action
  promotion_status:
    draft | simulation_passed | shadowing | limited_live |
    rejected | promoted | rolled_back
  rollback_policy_ref: policy://...
  receipt_refs:
    - receipt://...
```

Sim-to-real gates should distinguish:

- offline evaluation and deterministic replay;
- randomized simulation and software-in-the-loop validation;
- hardware-in-the-loop validation;
- shadow-mode observation in the target environment;
- limited live operation under strict supervision;
- full operational promotion;
- rollback or quarantine.

A simulation result can support the gate, but it is not live physical evidence.

## Deployment-Bound Assurance

`EmbodiedDeploymentAssuranceCase` is the typed
`AssuranceEvidenceBundle.deployment_assurance` member for one exact deployment.
Its stable identity is the owning `assurance_evidence://...` bundle; it does not
create a second case registry, evidence store, certification object, or Physical
Action Safety owner. The canonical wire shape is defined in
[`common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md#embodieddeploymentassurancecase).

The exact graph, binaries, toolchain, hardware, controller/firmware,
operational design domain, hazards, timing/fault assumptions, monitor and
recovery implementations, fault-injection results, applicable standards,
assessment, residual risk, and amendment lineage all participate. Changing any
assumption that the case relies on requires an admitted amendment or successor
`AssuranceEvidenceBundle`, linked through its predecessor and revalidation refs.

For live physical work, the case must bind the exact target, `SafetyEnvelope`
hash, graph ref/hash, hardware configuration, controller firmware, ODD ref/hash,
safety-input stream contracts, monitor, command switch, recovery controller,
recoverable-region model and margin, graph timing-chain artifact, proof-test
receipts/cadence, restart-unarmed evidence, and active/standby writer fencing.
An evidence level asserted by admission may not exceed the level supported by
that exact bundle. The `E0..E3` meaning and fail-closed admission rule are owned
by Physical Action Safety; Embodied Runtime supplies and enforces the exact
deployment bindings rather than minting another assurance ladder.

ODD evidence is operational, not a prose label. Each safety-relevant attribute
has a unit, permitted range or set, named monitor, measurement receipt,
freshness/timing contract, and exit response. `exiting`, `outside`, `unknown`, or
an out-of-range measurement triggers the bound response within its deadline.
The case also proves the recoverable region and minimum margin within which the
switch/recovery chain can still reach the declared safe state; a zero, stale, or
negative current margin blocks continued actuation.

The case references `AssuranceEvidenceBundle`, receipts, Physical Action Safety,
and ecosystem assurance/certification owners rather than redefining their field
schemas. Possessing a case proves neither present safety nor certification for
another graph, body, site, environment, or operating envelope. Standards and
independent assessments are deployment-specific claims whose acceptance and
display remain governed by
[`ecosystem-assurance-certification-liability.md`](../../foundations/ecosystem-assurance-certification-liability.md).

## Incidents, Liability, Recovery, and Operator Handoff

Embodied incidents must become admitted operational state. They must not be
hidden in provider logs, robot dashboards, chat transcripts, or video folders.

```yaml
EmbodiedIncident:
  incident_id: incident://...
  domain_ref: embodied_domain://...
  fleet_ref: robot_fleet://...
  unit_refs:
    - robot://... | drone://... | device://... | facility-system://...
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
  command_refs:
    - physical_command://...
  physical_action_incident_ref: incident://... | null
  severity: low | medium | high | critical
  trigger:
    safety_envelope_violation | emergency_stop | sensor_disagreement |
    actuator_failure | controller_fault | latency_violation |
    supervision_failure | human_near_miss | property_damage |
    policy_violation | disputed_outcome | other
  telemetry_refs:
    - telemetry_stream://...
  physical_replay_refs:
    - physical_replay://...
  operator_handoff_refs:
    - operator_handoff://...
  authority_refs:
    - grant://...
  map_refs:
    - physical_map://...
  zone_refs:
    - zone://...
  receipt_refs:
    - receipt://...
  liability_policy_ref: policy://...
  liability_claim_route_ref: liability_claim_route://... | null
  insurance_or_claim_ref: claim://... | null
  status:
    open | contained | under_review | remediating |
    disputed | closed
```

```yaml
OperatorHandoff:
  handoff_id: operator_handoff://...
  domain_ref: embodied_domain://...
  unit_ref:
    robot://... | drone://... | device://... | facility-system://... | null
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
  reason:
    degraded_network | stale_sensor | high_risk_action |
    incident | supervisor_requested | policy_required | other
  from_actor_ref: worker://... | runtime://... | daemon://...
  to_operator_ref: user://... | org_group://...
  required_context_refs:
    - physical_replay://...
    - receipt://...
    - map://...
  allowed_operator_actions:
    - observe | pause | safe_stop | manual_control |
      approve_low_risk | reject | recover | dispatch_maintenance
  teleoperation_contract:
    active: boolean
    link_contract_ref: physical-stream-contract://... | null
    link_contract_hash: sha256:... | null
    operator_authority_ref: grant://... | approval://... | null
    authentication_receipt_ref: receipt://... | null
    deadman_contract_ref: policy://... | artifact://... | null
    deadman_receipt_ref: receipt://... | null
    arbitration_policy_ref: policy://... | null
    control_writer_fencing_epoch: nonnegative_integer | null
    observed_round_trip_ms: nonnegative_integer | null
    max_round_trip_ms: positive_integer | null
    operator_takeover_budget_ms: positive_integer | null
    on_link_loss:
      hold_position | switch_to_recovery | safe_stop | emergency_stop
    link_state: healthy | degraded | lost | unknown
    authentication_state: verified | expired | revoked | unknown
    deadman_state: asserted | released | stale | unknown
  status:
    requested | accepted | declined | timed_out | completed |
    escalated
```

Teleoperation never creates a second actuator path around the local supervisor.
Remote commands remain proposals or one explicitly fenced command source under
the same `SafetyEnvelope`, ODD, switch, queue, and receipt rules. The link
contract binds endpoint identity, mutual authentication, integrity/anti-replay,
clock and sequence semantics, rate, latency/jitter, freshness, confidentiality,
and loss detection. The deadman is independently fresh and cannot be inferred
from packet arrival. Arbitration names which local autonomy, recovery, or human
source wins each conflict and fences the prior writer before transfer.

Loss, degradation beyond the admitted round-trip bound, authentication expiry
or revocation, deadman release/staleness, arbitration ambiguity, or exhaustion
of the operator-takeover budget invokes the declared local hold/recovery/stop
response. A remote UI reconnect, process restart, or restored video stream does
not resume manual control; it requires fresh authentication, deadman, current
ODD/safety evidence, and a new writer-fencing transition.

```yaml
RecoveryPlan:
  recovery_plan_id: recovery://...
  incident_ref: incident://...
  domain_ref: embodied_domain://...
  unit_refs:
    - robot://... | drone://... | device://... | facility-system://...
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
  recovery_mode:
    safe_stop | return_to_base | manual_extract | maintenance_lockout |
    recalibrate | replace_sensor | policy_update | other
  preconditions:
    - condition://...
  operator_refs:
    - user://...
  verification_refs:
    - receipt://...
  status:
    proposed | approved | active | completed | failed | abandoned
```

## Fleet-Level Policy

Fleet policy coordinates many robots, devices, controllers, zones, and humans in
one physical domain.

```yaml
FleetPolicy:
  policy_id: fleet_policy://...
  domain_ref: embodied_domain://...
  applies_to:
    fleet_refs:
      - robot_fleet://...
    zone_refs:
      - zone://...
    unit_refs:
      - robot://... | drone://... | device://... | facility-system://...
    resource_group_revision_refs:
      - embodied-resource-group-revision://...
  concurrency_limits:
    max_active_units_per_zone: integer | null
    max_high_risk_commands: integer | null
    mutually_exclusive_action_kinds:
      - [navigation, facility_control]
  supervision_policy_ref: supervision://...
  emergency_stop_authority_refs:
    - estop://...
  maintenance_lockout_policy_ref: policy://...
  telemetry_retention_policy_ref: policy://...
  degraded_mode_policy_ref: policy://...
  incident_escalation_policy_ref: policy://...
  liability_policy_ref: policy://...
  allowed_worker_refs:
    - worker://...
  forbidden_action_kinds:
    - sensor_override
  policy_hash: hash
```

Fleet policy is where the product prevents local correctness from becoming
global danger. A single robot command may be safe by itself while unsafe in a
crowded zone, during maintenance, during a network partition, or when another
robot is already acting.

## Native Reference Runtime and Component Library

A portable ABI without useful first-party components is not a competitive
embodied platform. The target must therefore ship a native reference runtime
and a curated, conformance-tested component library across these jobs:

| Library family | Minimum first-party scope |
|---|---|
| Commission and bind | device discovery, hardware identity, controller binding, calibration, time sync, frame validation, health checks, and resource-group resolution |
| Observe and estimate | sensor ingest, transforms, synchronization, odometry/state estimation, occupancy, object/human tracking, uncertainty, and world-state projection |
| Reason and propose | classical planning, behavior/policy adapters, local model inference, candidate comparison, teleoperation, success/progress detection, and action-chunk proposal |
| Move and control | kinematics, trajectories, whole-body/control allocation, interpolation, actuator arbitration, common mobile/manipulator/drone command adapters, and controller lifecycle |
| Assure and recover | operating-envelope monitors, watchdogs, command switch, clipping/veto, collision and zone monitors, recovery/minimum-risk controllers, and e-stop integration |
| Coordinate | work allocation, cell coordination, spacetime reservations, traffic/conflict resolution, cooperative-task barriers, partition behavior, and rejoin reconciliation |
| Prove and improve | synchronized raw logging, deterministic replay, incident capture, episode materialization, shadow comparison, evaluation, promotion, recall, and rollback |

First-party does not mean IOI rewrites every OEM driver, autopilot, physics
engine, or accelerator kernel. It means a developer can build and operate a
meaningful native reference system from IOI contracts and components, while
vendor and ecosystem components enter through the same ABI, admission,
evidence, and conformance gates. Native components receive no privileged path
around authority or safety.

## Product Surfaces

Embodied Runtime may appear through:

```text
Applications catalog
  conditional Embodied Systems planned registration, shown or recommended in
  embodied contexts but nonlaunchable until its route and implementation are
  built (the Open Application surfaces below are target-state design)

Studio
  compose the four linked graph views; author component and stream contracts;
  inspect exact resources, frames, timing, placement, policy compatibility,
  compile manifests, and resolve admission errors

Embodied Systems in the singular Open Application slot
  Commission: bodies, controllers, devices, calibration, frames, clocks
  Compose: joined graph inspection and deployment topology
  Operate: fleet/unit/world view, allocation, reservations, command queues
  Intervene: supervision, teleoperation, pause, safe stop, recovery, incidents
  Observe: health, timing, uncertainty, telemetry, replay, receipt drilldowns
  Deploy: activation transactions, versions, canaries, recall, rollback

Foundry
  simulator worlds, embodied datasets, policy training, evals, hardware-in-loop,
  shadow comparison, sim-to-real gates, and bounded-improvement campaigns

Sessions
  live embodied runs, command timelines, telemetry, receipts, e-stop state

Governance
  physical scopes, e-stop authority, supervision policy, deployment-bound
  assurance posture, release gates, liability policy

Provenance
  physical replay bundles, sensor evidence, actuator receipts, incidents
```

The surface is deployment-neutral. Existing robot, vehicle, industrial, and
device controllers may integrate through an admitted compatibility bridge
without running HypervisorOS; HypervisorOS remains one optional Type 1
substrate. Embodied Systems is the owner application for live physical-domain
operations, not a collection of separate fleet, robot, drone, safety, or replay
applications. Studio, Foundry, Governance, Sessions, and Provenance retain their
existing owner jobs and project contextually into that application.

## Reference Proof Matrix

The architecture is not state of the art because its schemas are complete. A
native implementation may claim the target only after the same contract family
passes all of the following reference systems with published evidence:

| Reference system | Required proof |
|---|---|
| Contact-rich workcell or manipulation arm | deterministic motion/resource arbitration, human-presence intervention, force/contact bounds, replayable success evidence, and safe recovery |
| Autonomous drone | local flight-control binding, geofence and airspace reservation, link loss, localization degradation, energy reserve, safe return/land, and no remote control-loop dependency |
| Humanoid | locomotion plus bimanual work, whole-body allocation, many resource groups, learned action chunks, fall/contact recovery, and independent command switching |
| Heterogeneous multi-unit site | work allocation plus spacetime reservations, coordination cells, failover, partitions, fenced reassignment, deadlock/conflict recovery, and ambiguous-effect reconciliation |
| Lightweight MCU/RTOS system | native `micro` footprint, bounded memory, deterministic sensor/servo timing, watchdog/e-stop behavior, and evidence handoff without a full daemon or GPU |

Each reference must also pass the cross-cutting graph compile/admission and
restart-unarmed suite; stream schema/frame/clock/QoS/freshness/liveliness/
backpressure failures; bounded scheduling and fault containment; supervisor
deny/clip/switch/recovery/e-stop independence; one-writer fencing and safe
standby takeover; native-versus-adapter semantic equivalence; and exact
simulation, SIL, HIL, shadow, limited-live, promotion, recall, and deployment-
assurance lineage.

Every demonstration reports at least p50/p99/p999 latency and jitter where
applicable, missed deadlines, queue/backpressure behavior, fault-containment and
safe-state time, intervention/violation rates, replay fidelity, resource and
spacetime conflicts, partition/rejoin outcomes, and promotion/rollback results.
Simulation is necessary but insufficient: relevant software-in-loop,
hardware-in-loop, shadow, bounded live, fault-injection, and recovery evidence
must be included. Passing only one robot body, one vendor stack, one simulator,
or one network topology does not satisfy the proof matrix.

## Conformance Checks

A conforming embodied runtime implementation must ensure:

- a complete reference deployment can commission and operate without making an
  external robotics runtime, simulator, or vendor cloud the semantic, authority,
  evidence, or safety owner;
- the embodiment/resource, execution, behavior, and world/evidence graph views
  retain their distinct owners and freeze exact cross-graph bindings for live
  work;
- every active execution graph resolves to an immutable admitted
  `EmbodiedRuntimeGraphManifest` with exact component implementations,
  stream contracts, placement, schedules, resource leaves, frames, clocks,
  calibration, world representations, deployment-assurance ref, and hashes;
- every component declares native runtime profile, execution stratum,
  criticality,
  lifecycle, IO streams, resource budget, effect class, deadline/failure
  behavior, replay posture, and isolation requirement;
- every physical stream binds schema, semantic role, endpoint identity,
  authentication, integrity/anti-replay, confidentiality, units, frame, clock,
  uncertainty, timing, freshness, delivery/backpressure, transport
  requirements, replay posture, assurance posture, producer/failure domain,
  exact contract hash, and current evidence before transport is selected;
- an unassured learned stream is supplemental and never the sole input to the
  safe-set monitor, command switch, recovery controller, interlock, or e-stop;
- every safety timing bound pins one graph-scoped observation-to-switch chain;
  hard-real-time claims provide analytic WCET/schedulability evidence and
  bounded-soft claims provide explicit tail percentile/sample/workload/fault
  evidence, with monitor period/jitter and all stream/scheduler/switch/actuator
  contributions included;
- an actuator-bearing graph activates only through a local
  `EmbodiedGraphActivationTransaction` that prepares, validates, commits, or
  aborts the exact graph while unarmed; a separate current authority, safety,
  lease, world-readiness, and supervisor decision is required to arm; restart
  is inactive and unarmed, and safety-related or hard-real-time partitions do
  not hot-swap while armed;
- `micro`, `edge`, and `site` footprints share one contract
  family without requiring one binary, operating system, transport, language,
  or hardware architecture;
- every embodied domain has an `EmbodiedRuntimeDomain` and explicit fleet,
  controller, sensor, actuator, world-state, telemetry, and policy refs before
  actuator-affecting work is admitted;
- every `RobotFleetRecord` contains `1..N` unit refs; each ref identifies a
  robot, drone, device, or facility system; a singleton fleet is
  valid and does not require mission-coordination state solely because it is
  represented as a fleet;
- every admitted `EmbodiedResourceGroup` is non-empty after recursive leaf
  expansion, binds one system/domain, uses acyclic revision-pinned nesting, and
  carries a reproducible membership-closure hash;
- every active group sensor resolves through an admitted controller or
  source-node membership; every actuator resolves through an embodied unit and
  controller; and an `observe_only` revision contains no actuator leaves;
- every group-targeted assignment, envelope, command, segment, and receipt
  binds the exact admitted group revision/hash and retains its explicit leaf
  sensor/actuator refs; a later group revision never widens admitted work;
- resource-group constraints intersect with all applicable member, unit,
  controller, zone, authority, and safety constraints; incompatibility fails
  closed, and a degraded aggregate never hides an unsafe required leaf;
- overlapping group names do not hide actuator, zone, or safety-envelope
  conflicts, and cross-controller groups do not claim atomic physical execution
  unless one independently enforceable deployment-assured local boundary proves
  it;
- an embodied unit's current runtime assignment may be absent during
  commissioning, unplaced idle, detached inventory, maintenance, or retirement;
  its assignment-history refs are rebuilt from predecessor-linked admitted
  assignments, are not independently mutable truth, and never confer current
  authority;
- every domain, fleet, controller binding, local supervisor, compatibility
  bridge, and mission envelope binds the owning `system_id`, deployment profile,
  and relevant observed node memberships; a runtime node or embodied unit is
  not presumed to be a member;
- embodied capability packages require a package binding before they can affect
  a physical domain;
- package binding must validate capability spec, embodiment adapter,
  sensor/action/world contracts, calibration refs, time-sync contract,
  runtime graph, policy contract, supervision policy, safety envelope, and
  success-detector refs;
- every policy/planner/teleoperator source binds exact observation/action,
  embodiment, normalization, timing, state/reset, uncertainty, interruption,
  fallback, evaluation, and promotion semantics, and emits only expiring
  non-authoritative `EmbodiedActionChunk` proposals;
- active teleoperation additionally binds the exact link contract/hash, operator
  authority and authentication receipt, independent deadman, arbitration,
  writer fence, latency, takeover budget, and local degrade/stop response; link,
  auth, deadman, or arbitration loss cannot preserve remote writer authority;
- robot and controller identities do not authorize actuation by themselves;
- controller bindings declare heartbeat, failsafe, command queue, telemetry, and
  authority requirements;
- stale or untrusted required sensor evidence blocks or degrades physical
  commands according to policy;
- current measurable ODD attributes and monitor receipts remain inside their
  admitted bounds; `exiting`, `outside`, `unknown`, or out-of-range state invokes
  the declared response before its deadline;
- emergency stop is local, testable, and not dependent on cloud, chain, model, or
  marketplace availability;
- every actuator-bearing mission separates slow governance/intelligence from
  on-unit autonomy, deterministic motion, and independently isolated runtime
  assurance/safety through an admitted `PhysicalMissionControlEnvelope`;
- same-system mission work distributed across multiple units or execution-node
  memberships uses epoch-bound allocation leases, shared-world-state
  watermarks, declared partition/rejoin behavior, fenced reassignment, and
  duplicate/ambiguous-effect reconciliation;
- allocation and spacetime remain separate leases; use of shared corridors,
  volumes, workcells, tools, objects, exclusion zones, or capacity binds an
  expiring `SpacetimeReservationLease`, while local perception, avoidance, and
  supervisor veto always take precedence;
- disconnected coordination cells cannot invent or extend work, authority,
  reservations, or epochs and must remain within predeclared nonconflicting
  degraded behavior until reconciled;
- cross-system fleet work preserves separate system identities, memberships,
  world-state truth, mission admission, and local safety; AIIP carries proposals
  and accepted handoffs rather than direct foreign actuator authority;
- Goal Kernel, remote model calls, wallet round trips, Agentgres admission,
  AIIP, and settlement do not sit inside the high-frequency actuator loop;
- the native local supervisor continuously enforces graph, envelope, lease,
  resource, world-state, clock, revocation, heartbeat/failsafe, and stricter
  local safety compatibility, fences one exclusive active actuator writer,
  remains able to select recovery/minimum-risk control independently of
  autonomy/network failure, and emits bounded segment commitments and
  exception/incident receipts;
- the supervisor rejects stale switch proof tests, insufficient recoverable
  margin, late observation-to-switch results, missing assured safety inputs, or
  missing restart-unarmed/one-writer/standby-takeover evidence;
- a compatibility bridge only maps native component, stream, action, and
  controller contracts to an external stack; it cannot arm a graph, grant
  authority, renew leases, bypass the supervisor, or own safety/evidence truth;
- degraded/offline operation cannot widen an envelope and must follow an
  explicit local fallback, handoff, pause, or safe-stop policy;
- movement/manipulation/facility commands pass through `PhysicalCommandQueue`
  semantics rather than generic tool calls;
- telemetry streams emit refs, hashes, and replay projections rather than only
  raw provider logs;
- raw synchronized robot logs and normalized episode datasets remain distinct:
  logs support replay/audit; episode datasets support training/eval only after
  eligibility gates;
- physical replay can reconstruct the command, sensor, actuator, supervision,
  e-stop, incident, and receipt timeline for a run;
- sim-to-real promotion gates separate offline eval, software-in-the-loop,
  hardware-in-the-loop, shadow mode, canary task batteries, limited live
  operation, and full promotion;
- every live deployment's `AssuranceEvidenceBundle` carries an
  `EmbodiedDeploymentAssuranceCase` for the exact graph, binaries/toolchain,
  hardware/firmware, operational design domain, hazards, timing/fault
  assumptions, monitor/recovery implementations, evidence, applicable
  assessments, residual risk, and amendment lineage; the case creates no second
  registry and is neither generic certification nor present actuation authority;
- a live, hard-real-time, or E1+ admission binds that exact bundle and its hashes
  to the target, SafetyEnvelope, graph, hardware, firmware, ODD, monitor, switch,
  recovery, timing chain, inputs, proof tests, and writer posture; an asserted
  evidence level higher than the bundle supports fails closed;
- Foundry embodied packages and runtime candidates remain build/eval artifacts
  until Governance release controls, daemon admission, Embodied Runtime
  readiness, Physical Action Safety, authority, and receipts admit them for a
  target physical domain;
- embodied context is bound through world, robot, task, evidence, action, and
  safety refs rather than hidden prompt context or raw model memory;
- structural assets, frame/kinematic/calibration/time state, live probabilistic
  environment state, and semantic ontology/affordances remain explicit layers;
- incidents, liability hooks, recovery plans, and operator handoffs are admitted
  state, not ad hoc chat messages;
- fleet policy can block a locally valid command when the broader physical
  domain is unsafe.

## Anti-Patterns

- Treating robot fleets as ordinary connectors because they expose an API.
- Calling an external runtime or vendor cloud the IOI Embodied Runtime while it
  still owns graph semantics, command admission, safety state, or evidence.
- Forcing HypervisorOS or a full daemon onto every controller, servo, sensor, or
  robot as the price of participating in an IOI system.
- Collapsing embodiment/resource, execution, behavior, and world/evidence into
  one late-bound module graph whose edges silently imply authority or truth.
- Treating topic names, tensor shapes, or successful transport negotiation as
  proof that units, frames, clocks, freshness, uncertainty, actions, and failure
  semantics are compatible.
- Activating an editable source graph directly, hot-swapping an armed
  safety-related partition, or resuming actuator effects automatically after a
  process restart.
- Rejecting a fleet of one, or fabricating distributed coordination state for a
  singleton fleet that has no distributed mission work.
- Treating each robot as a sovereign DAS, or as an admitted system node, merely
  because it is physically distinct or network-addressable.
- Treating an `EmbodiedResourceGroup` as a unit, fleet, node, Worker, authority
  grant, allocation, sovereign DAS, or mutable late-bound selector.
- Fabricating a robot or controller identity for a fixed observation-only
  sensor array instead of binding its admitted source-node path.
- Authorizing a group name without pinning its revision/closure hash and exact
  sensor/actuator leaves, or letting a later membership edit widen queued work.
- Claiming multi-controller or multi-unit transactional actuation because the
  resources share a group name.
- Treating a historical runtime assignment as a current placement, membership,
  or actuator-authority grant.
- Letting an external agent, MCP gateway, or model stream send actuator commands
  directly to a controller.
- Treating a learned policy, VLA, local inference component, or selected action
  chunk as deterministic motion, local safety approval, or actuator authority.
- Treating an unassured learned sensor or fused model output as the only input to
  the monitor, command switch, recovery controller, interlock, or e-stop.
- Claiming hard-real-time behavior from measurements alone, or bounded-soft
  behavior from average latency without an explicit tail/sample/fault envelope.
- Treating a healthy video feed or packet heartbeat as teleoperation authority,
  deadman state, arbitration, or permission to preserve the prior writer after
  link/authentication loss.
- Placing learned perception/planning in the same failure domain as the only
  watchdog, command switch, recovery controller, or e-stop path.
- Letting an external compatibility bridge arm a graph, grant authority, renew
  a lease, weaken a supervisor decision, or own operational truth.
- Treating a controller heartbeat as proof that the world is safe.
- Treating a model response as heartbeat.
- Treating simulation success as live deployment authority.
- Running multiple physical commands without queue, interrupt, and conflict
  semantics.
- Storing telemetry only as raw video/log files without Agentgres refs, hashes,
  replay indexes, receipts, and retention policy.
- Hiding incidents inside vendor dashboards.
- Relying on IOI L1 settlement or remote cloud availability for emergency stop.
- Placing Goal Kernel, a foundation-model stream, wallet approval, Agentgres
  admission, AIIP, or a network round trip inside a servo/motor-control loop.
- Treating mission-level authority as permission for arbitrary local setpoints
  outside an expiring, revocable action envelope.
- Emitting one public/settlement receipt per motor tick instead of bounded local
  segment commitments and material exception receipts.
- Allowing a fleet-level unsafe state because each single robot command looked
  locally valid.
- Treating work allocation as a reservation of airspace, floor space, a
  workcell, tool, shared object, energy, or other physically contended capacity.
- Treating a spacetime reservation as proof that the sensed world is clear or
  as permission to override local collision avoidance and human safety.
- Letting a disconnected coordination cell mint, extend, or transfer leases or
  rejoin without fencing and reconciling its world watermark and effects.
- Reallocating partitioned fleet work without fencing the old lease and
  reconciling completed, duplicated, or ambiguous physical effects.
- Using a digital twin, OpenUSD stage, simulator state, map, or scene graph as
  unquestioned live world truth or actuator authority.
- Claiming embodied-runtime maturity from one simulator, one vendor body, one
  happy-path demo, or aggregate latency without tail, fault, intervention,
  partition, recovery, replay, and rollback evidence.

## Related Canon

- [`physical-action-safety.md`](../../foundations/physical-action-safety.md) for
  physical-action safety envelopes, supervision, emergency stop, receipts, and
  incidents.
- [`foundry.md`](../hypervisor/foundry.md) for embodied simulation, robotics
  training, evals, and sim-to-real build artifacts.
- [`runtime-nodes-tee-depin.md`](./runtime-nodes-tee-depin.md) for runtime-node
  placement and execution-privacy profiles.
- [`ecosystem-assurance-certification-liability.md`](../../foundations/ecosystem-assurance-certification-liability.md)
  for assurance evidence, certification-claim, assessment, and liability
  boundaries.
- [`events-receipts-delivery-bundles.md`](./events-receipts-delivery-bundles.md)
  for events, receipts, trace bundles, replay, and proof drilldowns.
- [`common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md)
  for the canonical embodied graph, world representation, embodiment adapter,
  policy, action-chunk, activation, spacetime-lease, and package wire shapes.
- [`aiip.md`](../../foundations/aiip.md) for cross-system handoffs.
