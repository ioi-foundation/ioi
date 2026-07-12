# Embodied Runtime, Robot Fleet Runtime, and Physical Telemetry

Status: canonical architecture authority.
Canonical owner: this file for embodied runtime domains, robot/fleet identity,
controller bindings, sensor and actuator registries, local control bridges,
heartbeat/failsafe posture, two-speed mission/control execution, world models,
physical telemetry, physical replay, command queues, fleet policy, recovery,
and operator handoff.
Supersedes: plan prose that treats robot fleets, actuator APIs, sensor streams,
or physical telemetry as ordinary connector/tool details.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: speculative (robot-fleet runtime design; no embodied implementation)
Last implementation audit: 2026-07-05

## Canonical Definition

**Embodied Runtime is the Hypervisor runtime profile for autonomous systems that
observe or affect the physical world.**

It covers robot fleets, humanoid systems, drones, vehicles or vehicle-adjacent
systems, facility systems, IoT actuators, field-service devices, and other
physical domains where workers, models, controllers, sensors, actuators, and
humans must coordinate under safety, evidence, and emergency-stop constraints.

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
- a direct model-to-actuator path;
- a substitute for Physical Action Safety;
- a simulation result presented as live execution;
- IOI L1 as a safety controller.

## Ownership Boundaries

Embodied Runtime owns runtime representation and control-plane contracts for:

- robot/fleet identity and controller binding;
- sensor and actuator registries;
- embodied capability package binding to a physical domain;
- embodiment adapters, calibration registries, and time-synchronization
  contracts;
- local control bridge and heartbeat/failsafe protocol;
- slow mission/governance plane and certified local real-time control plane
  separation;
- world model, maps, zones, calibration, and environment state;
- latency, degraded-network, offline, and emergency-stop runtime guarantees;
- sim-to-real promotion gates for deployment into physical domains;
- telemetry streams and physical replay;
- physical command queue semantics for movement, manipulation, and facility
  control;
- incident, liability, recovery, and operator handoff projections;
- fleet-level policy across many robots, devices, controllers, zones, and
  human supervisors.

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
  -> RobotFleetRecord
  -> Robot / device identities
  -> Controller bindings
  -> Sensor registry
  -> Actuator registry
  -> Embodied capability package binding
  -> Embodiment adapter / calibration / time-sync contract
  -> World model / maps / zones / calibration
  -> Local control bridge
  -> Heartbeat and failsafe protocol
  -> Physical command queue
  -> Telemetry stream and physical replay
  -> Operator handoff / incident / recovery views
```

The Hypervisor Daemon remains the runtime gate. A model, worker, harness, MCP
gateway, connector, AIIP handoff, or external agent may propose embodied work,
but actuator-affecting execution must route through:

```text
proposal
  -> PhysicalActionIntent
  -> EmbodiedCapabilityPackage / runtime candidate lookup
  -> EmbodiedRuntimeDomain and RobotFleetRecord lookup
  -> embodiment adapter, controller, sensor, actuator, world-state,
     calibration, time-sync, and latency readiness
  -> Physical Action Safety gate
  -> wallet.network authority
  -> physical command queue admission
  -> local control bridge
  -> telemetry observation
  -> receipts, replay, incident/recovery state
  -> Agentgres admission
```

This flow admits a bounded mission/action envelope and safety policy; it does
not require a remote daemon, wallet, model, Agentgres, AIIP, or chain round trip
for every servo or motor-control tick.

## Robot and Fleet Identity

Embodied systems need stable identity separate from worker identity. A marketplace
worker may operate several robot bodies over time; one robot body may run several
workers or policies over its lifetime.

```yaml
EmbodiedRuntimeDomain:
  domain_id: embodied_domain://...
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
  status:
    planned | commissioning | active | degraded | suspended |
    emergency_stopped | decommissioned
```

```yaml
RobotFleetRecord:
  fleet_id: robot_fleet://...
  embodied_domain_ref: embodied_domain://...
  display_name: string
  robot_refs:
    - robot://...
  controller_binding_refs:
    - controller-binding://...
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

```yaml
EmbodiedUnitIdentity:
  unit_id: robot://... | drone://... | device://... | facility_system://...
  fleet_ref: robot_fleet://...
  hardware_identity_ref: hardware://... | null
  manufacturer_ref: org://... | null
  model_ref: device_model://... | null
  serial_or_attestation_ref: attestation://... | null
  controller_binding_ref: controller-binding://...
  runtime_assignment_ref: runtime_assignment://...
  allowed_zone_refs:
    - zone://...
  allowed_action_kinds:
    - navigation | manipulation | facility_control | access_control |
      sensor_capture | inspection | emergency_stop_test
  maintenance_state:
    ready | due_soon | due_now | locked_out | unknown
  status:
    ready | active | idle | degraded | offline | faulted |
    emergency_stopped | maintenance | retired
```

Identity records do not authorize actuation. They bind the physical body,
controller, policy, domain, and evidence paths that later gates must verify.

## Controller Binding

Robot and device controllers are privileged physical interfaces. They are not
ordinary connectors even when the transport looks like an API.

```yaml
RobotControllerBinding:
  binding_id: controller-binding://...
  unit_ref: robot://... | device://... | facility_system://...
  controller_ref: controller://...
  runtime_node_ref: runtime_node://...
  bridge_ref: local_control_bridge://...
  protocol_profile:
    ros_like | industrial_control | drone_control | vehicle_adjacent |
    facility_control | proprietary | other
  command_topics_or_endpoints:
    - ref: controller_endpoint://...
      action_kind: navigation | manipulation | facility_control | other
  telemetry_topics_or_endpoints:
    - telemetry_stream://...
  heartbeat_policy_ref: heartbeat_policy://...
  failsafe_policy_ref: failsafe_policy://...
  command_queue_ref: physical_command_queue://...
  sensor_registry_refs:
    - sensor_registry://...
  actuator_registry_refs:
    - actuator_registry://...
  authority_scope_refs:
    - scope:robot.navigate
  status:
    unbound | validating | bound | degraded | disconnected |
    emergency_stopped | revoked
```

Controller binding must prove:

- which runtime node or local bridge can send commands;
- which command surfaces are available;
- which sensors provide evidence;
- which actuators can move or affect the world;
- which heartbeat and fail-closed behavior apply;
- which authority scopes are required;
- where receipts and telemetry are emitted.

## Sensor and Actuator Registries

Sensors and actuators are registered separately. A camera stream may be safe to
read while the gripper beside it is unsafe to actuate.

```yaml
SensorRegistryEntry:
  sensor_ref: sensor://...
  unit_ref: robot://... | facility://... | zone://...
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
  unit_ref: robot://... | device://... | facility_system://...
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

An actuator must not be admitted for command execution if its required sensor
evidence is stale, missing, untrusted, or blocked by policy.

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
  capability_spec_ref: capability_spec://...
  domain_ref: embodied_domain://...
  fleet_ref: robot_fleet://...
  unit_refs:
    - robot://...
  embodiment_adapter_refs:
    - embodiment_adapter://...
  controller_binding_refs:
    - controller-binding://...
  sensor_contract_ref: sensor_contract://...
  action_schema_ref: action_schema://...
  world_contract_ref: world_contract://...
  calibration_refs:
    - calibration://...
  time_sync_contract_ref: time_sync://...
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

## World Model, Maps, Zones, Calibration, and Environment State

Embodied runtime needs an explicit physical-state plane. It cannot rely on a
prompt, screenshot, or local controller memory as the only representation of the
world.

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
  world_representation_refs:
    - world_representation://... | artifact://...
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
    - robot://...
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
  unit_or_sensor_ref: robot://... | sensor://... | actuator://...
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
  force/torque, calibration, latency, and local bridge posture

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

Embodied execution has two explicitly separated timescales:

```text
slow governance / intelligence plane
  Goal Kernel, mission planning, ontology actions, policy, authority, budget,
  route selection, approvals, verifier paths, operator handoff, course
  correction, and admission of a bounded mission/action envelope

fast certified local control-and-safety plane
  deterministic or certified controller, short-horizon perception/action,
  collision and zone enforcement, heartbeat, failsafe, e-stop, command
  interpolation, and high-frequency actuator control inside that envelope
```

The slow plane issues a `PhysicalMissionControlEnvelope` that binds the target
fleet/units, allowed action classes, zones, limits, start/expiry, supervisor and
e-stop posture, local controller/capability versions, required evidence,
exception policy, and revocation epoch. The local plane may execute only inside
that envelope and its stricter local safety veto. It emits bounded segment
commitments and exception/incident receipts rather than one globally settled
record for every control tick.

```yaml
PhysicalMissionControlEnvelope:
  envelope_id: physical_mission_envelope://...
  mission_ref: mission:...
  embodied_domain_ref: embodied_domain://...
  unit_refs: [robot://...]
  allowed_action_kinds: [string]
  zone_refs: [physical_zone://...]
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

`LocalControlSegment` is the embodied-runtime record for one bounded interval
of local controller execution. It is not the safety/evidence commitment itself:
Physical Action Safety owns when a `PhysicalActionSegmentCommitmentReceipt` and
immediate exception, e-stop, and incident receipts are required; the events and
receipts owner defines their field-level schemas.

```yaml
LocalControlSegment:
  segment_ref: control-segment://...
  mission_control_envelope_ref: physical_mission_envelope://...
  local_control_bridge_ref: local_control_bridge://...
  controller_binding_ref: controller-binding://...
  unit_refs: [robot://...]
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

## Local Control Bridge, Heartbeat, and Failsafe

The local control bridge is the runtime component that mediates between the
Hypervisor Daemon and physical controllers. It should be close enough to the
device to enforce heartbeat and fail-closed behavior even when cloud, model, or
operator links degrade.

```yaml
LocalControlBridge:
  bridge_id: local_control_bridge://...
  embodied_domain_ref: embodied_domain://...
  runtime_node_ref: runtime_node://...
  controller_binding_refs:
    - controller-binding://...
  network_profile_ref: network_profile://...
  heartbeat_policy_ref: heartbeat_policy://...
  failsafe_policy_ref: failsafe_policy://...
  local_estop_channel_refs:
    - estop://...
  command_queue_refs:
    - physical_command_queue://...
  active_mission_envelope_ref: physical_mission_envelope://... | null
  local_control_segment_ref: control-segment://... | null
  telemetry_stream_refs:
    - telemetry_stream://...
  status:
    starting | active | degraded | partitioned | offline |
    fail_closed | emergency_stopped
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
    continue_low_risk | pause_high_risk | safe_stop
  fail_closed_required: boolean
  last_tested_at: timestamp
  receipt_refs:
    - receipt://...
```

The bridge must never treat a live model stream as a heartbeat. Heartbeat proves
control-channel health, not reasoning quality.

The bridge is the enforcement boundary between the two speeds. It validates the
mission envelope and revocation epoch before admitting a local control segment,
enforces limits continuously, preserves the local e-stop and safety veto, and
summarizes each segment with evidence/commitment refs. It fails closed on an
expired, revoked, incompatible, or unverifiable envelope.

## Latency, Degraded Networking, Offline, and Emergency Stop

Embodied domains need explicit runtime guarantees for timing and degraded
operation.

```yaml
EmbodiedRuntimeGuarantee:
  guarantee_id: runtime_guarantee://...
  domain_ref: embodied_domain://...
  max_command_latency_ms: integer
  max_observation_latency_ms: integer
  max_estop_latency_ms: integer
  control_loop_owner:
    certified_local_controller | deterministic_local_controller
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
certified high-frequency loop. Envelope expiry or loss of required heartbeat
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
  unit_ref: robot://...
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

Queue admission must check command conflicts. For example, two commands that
share an actuator, zone, or safety envelope cannot run concurrently unless a
domain-specific safe-parallel policy explicitly permits it.

A queued command is mission-level intent, not a servo stream. The local bridge
may expand it into controller-native setpoints only inside the admitted mission
envelope. Normal control ticks remain local; the bridge emits segment
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
  source_ref: sensor://... | controller://... | robot://... | bridge://...
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
  sensor_contract_ref: sensor_contract://...
  action_schema_ref: action_schema://...
  simulator_world_refs:
    - simulator://...
  world_representation_refs:
    - world_representation://... | artifact://...
  eval_suite_refs:
    - eval_suite://...
  safety_case_ref: safety_case://...
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

- simulation success;
- hardware-in-the-loop validation;
- shadow-mode observation in the target environment;
- limited live operation under strict supervision;
- full operational promotion;
- rollback or quarantine.

A simulation result can support the gate, but it is not live physical evidence.

## Incidents, Liability, Recovery, and Operator Handoff

Embodied incidents must become admitted operational state. They must not be
hidden in provider logs, robot dashboards, chat transcripts, or video folders.

```yaml
EmbodiedIncident:
  incident_id: incident://...
  domain_ref: embodied_domain://...
  fleet_ref: robot_fleet://...
  unit_refs:
    - robot://...
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
  unit_ref: robot://... | null
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
  status:
    requested | accepted | declined | timed_out | completed |
    escalated
```

```yaml
RecoveryPlan:
  recovery_plan_id: recovery://...
  incident_ref: incident://...
  domain_ref: embodied_domain://...
  unit_refs:
    - robot://...
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
      - robot://...
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

## Product Surfaces

Embodied Runtime may appear through:

```text
Applications catalog
  the named HypervisorOS horizon entry (embodied systems lane; named only
  today — the Open Application surfaces below are target-state design)

Open Application
  fleet overview, controller health, map/zone view, telemetry, command queue,
  supervision inbox, incidents, recovery, and replay

Foundry
  simulator worlds, embodied datasets, policy training, evals, sim-to-real gates

Sessions
  live embodied runs, command timelines, telemetry, receipts, e-stop state

Governance
  physical scopes, e-stop authority, supervision policy, liability policy

Provenance
  physical replay bundles, sensor evidence, actuator receipts, incidents
```

This surface is optional until the product supports embodied domains, but the
runtime objects are part of the architecture so robot/fleet integrations do not
arrive as one-off connectors.

## Conformance Checks

A conforming embodied runtime implementation must ensure:

- every embodied domain has an `EmbodiedRuntimeDomain` and explicit fleet,
  controller, sensor, actuator, world-state, telemetry, and policy refs before
  actuator-affecting work is admitted;
- embodied capability packages require a package binding before they can affect
  a physical domain;
- package binding must validate capability spec, embodiment adapter,
  sensor/action/world contracts, calibration refs, time-sync contract,
  supervision policy, safety envelope, and success-detector refs;
- robot and controller identities do not authorize actuation by themselves;
- controller bindings declare heartbeat, failsafe, command queue, telemetry, and
  authority requirements;
- stale or untrusted required sensor evidence blocks or degrades physical
  commands according to policy;
- emergency stop is local, testable, and not dependent on cloud, chain, model, or
  marketplace availability;
- every actuator-bearing mission separates slow governance/intelligence from
  certified local real-time control through an admitted
  `PhysicalMissionControlEnvelope`;
- Goal Kernel, remote model calls, wallet round trips, Agentgres admission,
  AIIP, and settlement do not sit inside the high-frequency actuator loop;
- the local bridge continuously enforces envelope limits, revocation epoch,
  heartbeat/failsafe, and stricter local safety vetoes, then emits bounded
  segment commitments and exception/incident receipts;
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
- Foundry embodied packages and runtime candidates remain build/eval artifacts
  until Governance release controls, daemon admission, Embodied Runtime
  readiness, Physical Action Safety, authority, and receipts admit them for a
  target physical domain;
- embodied context is bound through world, robot, task, evidence, action, and
  safety refs rather than hidden prompt context or raw model memory;
- incidents, liability hooks, recovery plans, and operator handoffs are admitted
  state, not ad hoc chat messages;
- fleet policy can block a locally valid command when the broader physical
  domain is unsafe.

## Anti-Patterns

- Treating robot fleets as ordinary connectors because they expose an API.
- Letting an external agent, MCP gateway, or model stream send actuator commands
  directly to a controller.
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

## Related Canon

- [`physical-action-safety.md`](../../foundations/physical-action-safety.md) for
  physical-action safety envelopes, supervision, emergency stop, receipts, and
  incidents.
- [`foundry.md`](../hypervisor/foundry.md) for embodied simulation, robotics
  training, evals, and sim-to-real build artifacts.
- [`runtime-nodes-tee-depin.md`](./runtime-nodes-tee-depin.md) for runtime-node
  placement and execution-privacy profiles.
- [`events-receipts-delivery-bundles.md`](./events-receipts-delivery-bundles.md)
  for events, receipts, trace bundles, replay, and proof drilldowns.
- [`common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md)
  for bounded execution domain envelopes.
- [`aiip.md`](../../foundations/aiip.md) for cross-system handoffs.
