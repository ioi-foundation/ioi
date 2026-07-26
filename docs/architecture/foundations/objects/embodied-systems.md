# Embodied and Physical-Action Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of physical mission segments, embodied capability specs and packages, embodied training-data contracts, world representation manifests, native embodied runtime profiles, embodiment adapters, embodied action policy contracts, embodied runtime graph manifests and activation transactions, embodied action chunks, spacetime reservation leases, embodied deployment assurance cases, and Foundry embodied runtime candidates.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: partial admission precursor only (`PhysicalActionExecutionReceipt` v1 has a registered schema, invariants, fixtures, and generated projections; physical execution and the embodied object plane remain planned)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../../components/daemon-runtime/embodied-runtime.md`](../../components/daemon-runtime/embodied-runtime.md);
this module does not restate them.

## Physical Mission Segment Envelopes

`PhysicalMissionControlEnvelope` registers the slow-plane mission envelope that
binds fleet/units, allowed actions, zones/limits, validity, authority,
safety/e-stop, controller versions, evidence, exceptions, and revocation.
`LocalControlSegmentEnvelope` registers the embodied-runtime record for one
bounded interval of native `LocalControlSupervisor` or separately assured
local-controller execution at
`control-segment://...`. The corresponding
`PhysicalActionSegmentCommitmentReceipt` binds that interval to mission intent,
controller/version, policy, safety envelope, command and sensor roots, state
refs, exception/e-stop receipts, and the declared result. It is a receipt type,
not a second common envelope. Mission and local-segment records are owned by
[`embodied-runtime.md`](../../components/daemon-runtime/embodied-runtime.md),
physical-action obligations are owned by
[`physical-action-safety.md`](../physical-action-safety.md), and the sole receipt
schema is owned by
[`events-receipts-delivery-bundles.md`](../../components/daemon-runtime/events-receipts-delivery-bundles.md).

Here, *mission* is physical-domain language for the bounded slow-plane control
contract, not a `HypervisorMission` identity. Every
`PhysicalMissionControlEnvelope`, fleet-coordination record, allocation lease,
and physical receipt binds the same `TypedWorkSubjectBinding` (normally a
GoalRun; another listed kind is valid only when its owner contract permits
direct physical work). The physical envelope adds safety and controller bounds;
it never becomes the work subject's lifecycle or truth owner.

These objects implement the two-speed boundary: Goal Kernel and remote
governance operate at mission/checkpoint/exception/course-correction
timescales, while the native `LocalControlSupervisor` or a separately assured
local controller owns the independently enforceable high-frequency loop, local
e-stop, and fail-safe behavior inside a bounded mission envelope.

## EmbodiedCapabilitySpecEnvelope

Embodied capability work starts with the task and physical contract, not a model
choice. The spec names the task family, command interface, allowed workspace,
success criteria, and safety category before Foundry trains or packages
anything.

```yaml
EmbodiedCapabilitySpecEnvelope:
  capability_spec_id: capability_spec://...
  task_family: string
  command_interface_ref: action_schema://...
  allowed_workspace_refs:
    - zone://... | world_contract://...
  success_criteria_ref: gate://... | eval_report://... | artifact://...
  safety_category:
    observe_only | low_risk_motion | supervised_manipulation |
    high_value_physical_action | human_proximity | custom
  required_sensor_contract_refs:
    - sensor_contract://...
  required_world_contract_ref: world_contract://...
  required_supervision_policy_ref: supervision://...
  receipt_refs:
    - receipt://...
  status: draft | ready | superseded | archived
```

## EmbodiedTrainingDataContractEnvelope

Embodied datasets should preserve both raw synchronized logs and normalized
episode views. Raw logs are the replay/audit substrate; episode datasets are
the training/eval substrate.

```yaml
EmbodiedTrainingDataContractEnvelope:
  data_contract_id: dataset_snapshot://... | artifact://...
  capability_spec_ref: capability_spec://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  raw_robot_log_refs:
    - robot_log://... | artifact://...
  normalized_episode_dataset_refs:
    - episode_dataset://... | dataset_snapshot://...
  time_sync_contract_ref: time_sync://...
  sensor_contract_refs:
    - sensor_contract://...
  calibration_refs:
    - calibration://...
  modality_channels:
    - rgb
    - rgbd
    - lidar
    - imu
    - force_torque
    - tactile
    - proprioception
    - command_status
    - estop_state
    - operator_event
  split_manifest_ref: artifact://...
  retention_policy_ref: policy://...
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
  receipt_refs:
    - receipt://...
  status: draft | materialized | retained | deprecated | revoked
```

## WorldRepresentationManifest

`WorldRepresentationManifest` freezes the schemas, frames, assumptions, and
projection bindings through which an embodied graph interprets physical state.
It does not freeze a live world snapshot and is not an actuator-authority
object. The live `WorldModel` and `EnvironmentState` remain runtime projections
owned by Embodied Runtime; OpenUSD, occupancy maps, scene graphs, and vendor
formats are representations behind this contract, never runtime truth by
themselves.

```yaml
WorldRepresentationManifest:
  schema_version: ioi.world-representation-manifest.v1
  manifest_ref: world-representation-manifest://...
  revision: semver_or_hash
  content_hash: hash
  system_id: system://...
  embodied_domain_ref: embodied_domain://...
  layers:
    structural:
      asset_and_geometry_refs:
        - world_representation://... | artifact://...
      kinematic_and_collision_model_refs:
        - world_representation://... | artifact://... | schema://...
      immutable_site_or_body_topology_root: hash
    calibration_and_time:
      frame_graph_contract_ref: world_representation://... | schema://... | artifact://...
      calibration_refs:
        - calibration://...
      time_sync_contract_ref: time_sync://...
      unit_and_coordinate_convention_ref: schema://...
    live_probabilistic:
      world_model_schema_refs:
        - schema://...
      uncertainty_contract_ref: schema://... | policy://...
      freshness_and_validity_policy_ref: policy://...
      live_state_is_external_projection: true
    semantic:
      ontology_and_affordance_refs:
        - ontology://... | ontology-assertion://... | artifact://...
      operating_constraint_refs:
        - spatial_policy://... | policy://...
      object_identity_and_resolution_policy_ref: policy://...
  projection_bindings:
    - projection_kind:
        openusd | occupancy_grid | scene_graph | physics_proxy |
        vendor_native | custom
      representation_ref: world_representation://... | artifact://...
      binding_schema_ref: schema://...
      binding_hash: hash
  provenance_refs:
    - provenance://... | receipt://... | artifact://...
  signature: required
```

Every graph activation binds the exact manifest revision and hash. Calibration,
frame, time, or structural-topology changes produce a successor manifest or an
explicitly versioned calibration record admitted by its policy; they never
silently reinterpret an armed graph. A `live_probabilistic` layer declares how
live state is represented and aged, but its manifest must not masquerade as the
current occupancy, human location, collision state, or success evidence.

## NativeEmbodiedRuntimeProfile

`NativeEmbodiedRuntimeProfile` is the composable deployment-footprint family
for the first-party runtime. It is an enum and conformance shape, not a new
sovereign system, authority tier, safety rating, product, or required operating
system:

```yaml
NativeEmbodiedRuntimeProfile:
  footprint: micro | edge | site
  required_execution_strata:
    - autonomy | deterministic_motion | runtime_assurance_safety
  scheduler_memory_isolation_and_fault_contract_refs:
    - conformance_profile://... | policy://... | schema://...
  supported_component_contract_refs:
    - schema://... | artifact://...
  supported_physical_stream_contract_refs:
    - schema://... | artifact://...
  hardware_and_accelerator_requirement_refs:
    - resource://... | capacity://... | policy://...
  conformance_evidence_refs:
    - receipt://... | evidence://... | assurance_evidence://...
```

`micro` targets bounded MCU/RTOS control and safety partitions; `edge` targets
on-unit perception, state estimation, planning, motion, and local coordination;
`site` targets multi-unit world state, fleet coordination, evidence, and
operations. One graph may compose all three. They share manifests, schemas,
frames, clocks, leases, lifecycle, and evidence semantics while using different
languages, schedulers, transports, kernels, or hardware.

## EmbodimentAdapter

`EmbodimentAdapter` is the immutable semantic mapping between canonical
observation/action contracts and one compatible body/controller family. It
prevents a policy whose tensors happen to have the right dimensions from being
treated as compatible with a different joint order, frame convention, unit
system, controller mode, or safety envelope.

```yaml
EmbodimentAdapter:
  schema_version: ioi.embodiment-adapter.v1
  adapter_ref: embodiment_adapter://...
  revision: semver_or_hash
  content_hash: hash
  compatibility_source:
    kind:
      device | vendor_controller | ros_graph | flight_stack |
      industrial_runtime | external_embodied_runtime | custom
    source_profile_ref: schema://... | artifact://... | connector://...
    source_profile_hash: hash
  embodiment_refs:
    - embodiment://...
  compatible_controller_profile_refs:
    - controller://... | schema://... | conformance_profile://...
  observation_mapping:
    source_sensor_contract_refs:
      - sensor_contract://...
    canonical_observation_schema_refs:
      - schema://...
    field_order_units_frames_and_masks_ref: artifact://... | schema://...
    normalization_ref: artifact://... | schema://...
  action_mapping:
    canonical_action_schema_ref: action_schema://...
    controller_command_schema_refs:
      - action_schema://... | schema://...
    joint_actuator_and_end_effector_order_ref: artifact://... | schema://...
    units_frames_limits_and_saturation_ref: artifact://... | schema://...
    kinematic_and_control_allocation_ref: artifact://... | schema://...
  required_resource_topology_ref:
    embodied-resource-group-revision://... | schema://...
  required_calibration_contract_refs:
    - calibration://... | schema://...
  required_time_sync_contract_ref: time_sync://...
  lifecycle_health_and_receipt_mapping:
    lifecycle_mapping_ref: schema://... | artifact://...
    health_and_fault_mapping_ref: schema://... | artifact://...
    external_to_ioi_receipt_mapping_ref: schema://... | artifact://...
    external_completion_is_accepted_truth: false
  compatible_local_control_supervisor_profiles:
    - conformance_profile://... | policy://...
  validation_and_evaluation_refs:
    - eval_report://... | gate://... | receipt://...
  provenance_refs:
    - provenance://... | artifact://...
  signature: required
```

The reusable adapter may describe a body/controller family. A compiled graph
must additionally bind the exact adapter hash to exact unit, controller,
resource-group closure, calibration, and time-sync revisions. The adapter
translates semantics; it does not grant authority, select work, bypass the
`LocalControlSupervisor`, or prove that current physical state is safe.

## EmbodiedActionPolicyContract

`EmbodiedActionPolicyContract` is the model-neutral runtime contract for a
learned policy, classical planner, behavior graph, optimizer, or other producer
of candidate physical action chunks. The policy artifact and the contract are
distinct: changing observation/action semantics, embodiment binding, timing,
state/reset behavior, or fallback posture requires a new contract revision even
when the underlying artifact is unchanged.

```yaml
EmbodiedActionPolicyContract:
  schema_version: ioi.embodied-action-policy-contract.v1
  action_policy_contract_ref: embodied-action-policy-contract://...
  revision: semver_or_hash
  content_hash: hash
  policy_artifact_refs:
    - model://... | worker://... | controller://... | user://... | artifact://...
  permitted_action_semantics:
    ontology_action_contract_ref: ontology-action://... | null
    permitted_action_class_ref: schema://... | policy://...
    precondition_refs:
      - policy://... | schema://...
    postcondition_and_success_refs:
      - policy://... | schema://... | success_detector://...
    required_resource_contract_refs:
      - embodied-resource-group-revision://... | schema://...
  observation_contract:
    sensor_contract_refs:
      - sensor_contract://...
    observation_schema_refs:
      - schema://...
    world_representation_manifest_ref: world-representation-manifest://...
    world_representation_manifest_hash: hash
    required_freshness_and_uncertainty_policy_ref: policy://...
  action_contract:
    action_schema_ref: action_schema://...
    representation:
      pose_target | velocity_target | trajectory | action_chunk |
      task_space_command | joint_space_command | custom
    output_semantics: candidate_action_chunk_only
    direct_actuator_execution: forbidden
  embodiment_adapter_ref: embodiment_adapter://...
  embodiment_adapter_hash: hash
  timing:
    nominal_control_frequency_hz: positive_number
    action_horizon_ms: positive_integer
    maximum_inference_latency_ms: positive_integer
    maximum_jitter_ms: nonnegative_integer
    late_result_behavior: discard | hold_safe | fallback
  state_and_reset:
    stateful: boolean
    state_schema_ref: schema://... | null
    reset_and_recovery_policy_ref: policy://...
  runtime_eligibility:
    native_profiles:
      - micro | edge | site
    accelerator_and_memory_requirement_refs:
      - resource://... | capacity://... | policy://...
    remote_inference: prohibited | shadow_only | bounded_by_policy
  uncertainty_and_out_of_distribution:
    output_schema_ref: schema://...
    threshold_policy_ref: policy://...
    failure_behavior: reject | request_supervision | fallback | safe_stop
  fallback_and_interruption_policy_ref: policy://...
  verification_and_receipt_obligation_refs:
    - verifier_path://... | schema://... | policy://...
  physical_action_safety_compatibility_refs:
    - safety://... | policy://... | conformance_profile://...
  evaluation_promotion_and_recall_refs:
    - eval_report://... | gate://... | promotion_record://... | regression://...
  provenance_refs:
    - provenance://... | artifact://... | receipt://...
  signature: required
```

No action-policy contract is actuator authority. Its only physical output is a
`EmbodiedActionChunk`, which remains subject to selection, current
world/sensor checks, Physical Action Safety, wallet authority where required,
spacetime/resource leases, queue admission, and independent local enforcement.

## EmbodiedRuntimeGraphManifestEnvelope

`EmbodiedRuntimeGraphManifestEnvelope` is an immutable, compiled specification
for an ongoing reactive embodied execution graph. It is not a
`WorkflowTemplate`, which declares finite directed work, and not a
`GoalRunProfile`, which declares how one goal class should converge. A GoalRun
or workflow may request work through an already-admitted graph; neither owns or
replaces the graph's component lifecycle, stream semantics, schedule, physical
bindings, or local safety boundary.

The graph contains two nested contract shapes. They are content-hashed members
of the graph and do not create parallel registries or independent authority.

```yaml
EmbodiedComponentContract:
  component_key: stable_graph_local_string
  component_contract_ref: schema://... | artifact://...
  component_contract_hash: hash
  component_kind:
    sensor_source | actuator_sink | transform | state_estimator | perception |
    world_model | planner | action_policy | selector | motion_controller |
    control_allocator | safety_monitor | recovery_controller | command_switch |
    evidence_recorder | fleet_coordinator | compatibility_adapter | custom
  implementation_ref: package_artifact://... | artifact://... | module://...
  implementation_hash: hash
  runtime_profile:
    micro | edge | site
  execution_stratum:
    autonomy | deterministic_motion | runtime_assurance_safety
  criticality:
    independent_safety | deterministic_hard_realtime |
    bounded_soft_realtime | best_effort | offline_only
  determinism_posture: deterministic | bounded_nondeterministic | nondeterministic
  input_port_keys: []
  output_port_keys: []
  scheduling:
    trigger: periodic | stream_driven | event_driven | on_demand
    period_or_minimum_interval_ms: positive_number | null
    deadline_ms: positive_number | null
    worst_case_execution_time_ms: positive_number | null
    priority_class: integer | null
    missed_deadline_behavior: reject | degrade | fallback | safe_stop
  resource_requirements:
    cpu_memory_and_accelerator_refs:
      - resource://... | capacity://... | policy://...
    exclusive_physical_resource_keys: []
  authority_and_effects:
    authority_scope_refs:
      - authority://... | policy://...
    effect_class:
      observe_only | propose_physical_action | admit_physical_command |
      enforce_safety | record_evidence
  lifecycle:
    configure_policy_ref: policy://...
    health_contract_ref: schema://... | policy://...
    failure_and_restart_policy_ref: policy://...
    declared_safe_state_ref: safety://... | policy://... | null

PhysicalStreamContract:
  schema_version: ioi.physical-stream-contract.v1
  stream_contract_ref: physical-stream-contract://...
  content_hash: hash
  stream_key: stable_graph_local_string
  producer_component_and_port: string
  consumer_component_and_port_refs: []
  payload_schema_ref: schema://...
  payload_schema_hash: hash
  semantic_class:
    observation_latest | observation_ordered | evidence_lossless |
    command_bounded | safety_signal | state_replication
  direction:
    observation | proposal | command | safety | evidence | coordination
  units_and_frame:
    unit_schema_ref: schema://... | null
    coordinate_frame_ref: world-representation-manifest://... | schema://... | null
    transform_policy_ref: policy://... | null
  time:
    source_clock_domain_ref: time_sync://...
    receive_clock_domain_ref: time_sync://...
    timestamp_and_sequence_contract_ref: schema://...
    timestamp_uncertainty_contract_ref: schema://... | policy://...
  security:
    producer_identity_ref: module://... | controller://... | runtime://...
    allowed_consumer_identity_refs:
      - module://... | controller://... | runtime://...
    authentication_policy_ref: policy://...
    integrity_and_anti_replay_policy_ref: policy://...
    confidentiality_policy_ref: policy://...
  qos:
    nominal_rate_hz: positive_number | null
    deadline_ms: positive_number | null
    maximum_jitter_ms: nonnegative_number | null
    maximum_freshness_age_ms: positive_number | null
    queue_depth: positive_integer
    reliability: best_effort | reliable | fail_closed
    history: keep_latest | keep_last_n | keep_all_bounded
    durability: volatile | transient_local | durable
    liveliness_and_lease_policy_ref: policy://...
    priority: integer
    criticality:
      safety_related | mission_critical | operational | noncritical
    backpressure: block | drop_oldest | drop_newest | coalesce | fail_closed
    loss_posture: latest_value | ordered_bounded_loss | lossless
    missed_contract_behavior: discard | degrade | fallback | safe_stop
  resolved_transport:
    allowed_kinds:
      - shared_memory | accelerator_buffer | dds | zenoh | can_fd | ethercat |
        tsn | rtos_local | durable_log | compatibility_binding | custom
    kind:
      shared_memory | accelerator_buffer | dds | zenoh | can_fd | ethercat |
      tsn | rtos_local | durable_log | compatibility_binding | custom
    binding_ref: schema://... | artifact://... | connector://...
    binding_hash: hash
  replay_and_evidence:
    record_policy_ref: policy://...
    evidence_obligation_refs:
      - schema://... | policy://...
```

`PhysicalStreamContract` owns semantic and timing requirements. Its resolved
transport is an implementation binding and may not change units, frames,
ordering, loss, freshness, evidence, or authority semantics. A compiler may
choose zero-copy shared memory or accelerator buffers, DDS/Zenoh, an industrial
bus, or another admitted transport only after satisfying the same contract.

```yaml
EmbodiedRuntimeGraphManifestEnvelope:
  schema_version: ioi.embodied-runtime-graph-manifest.v1
  runtime_graph_manifest_ref: embodied-runtime-graph-manifest://...
  revision: semver_or_hash
  graph_hash: hash
  system_id: system://...
  embodied_domain_ref: embodied_domain://...
  capability_spec_ref: capability_spec://...
  graph_kind:
    continuous_reactive | episodic_reactive | local_control |
    fleet_coordination | mixed
  supported_native_runtime_profiles:
    - micro | edge | site
  component_contracts:
    - EmbodiedComponentContract
  physical_stream_contracts:
    - PhysicalStreamContract
  placement_partitions:
    - partition_key: string
      runtime_profile:
        micro | edge | site
      component_keys: []
      required_locality_and_isolation_refs:
        - policy://... | failure-domain://... | custody://...
      external_execution_adapter_ref:
        connector://... | artifact://... | null
      external_execution_adapter_hash: hash | null
  exact_physical_bindings:
    controller_binding_refs:
      - controller-binding://...
    resource_group_bindings:
      - group_revision_ref: embodied-resource-group-revision://...
        membership_closure_hash: hash
    embodiment_adapter_bindings:
      - adapter_ref: embodiment_adapter://...
        adapter_hash: hash
    action_policy_bindings:
      - action_policy_contract_ref: embodied-action-policy-contract://...
        action_policy_contract_hash: hash
    local_control_supervisor_refs:
      - local_control_supervisor://...
  world_representation_manifest_ref: world-representation-manifest://...
  world_representation_manifest_hash: hash
  calibration_refs:
    - calibration://...
  time_sync_contract_ref: time_sync://...
  safety_and_assurance:
    physical_action_safety_policy_refs:
      - safety://... | policy://...
    assurance_profile_refs:
      - assurance_profile://...
    assurance_evidence_bundle_refs:
      - assurance_evidence://... | evidence://...
    embodied_deployment_assurance_case_refs:
      - assurance_evidence://...
    certification_claim_refs:
      - certification_claim://...
    local_control_supervisor_conformance_refs:
      - conformance_profile://... | receipt://...
  compilation:
    source_graph_ref: artifact://...
    source_graph_hash: hash
    compiler_and_version_ref: artifact://... | module://...
    compiler_and_version_hash: hash
    resolution_receipt_ref: receipt://...
    static_analysis_and_schedule_evidence_refs:
      - evidence://... | gate://... | receipt://...
  activation_policy_ref: policy://...
  rollback_graph_manifest_ref: embodied-runtime-graph-manifest://... | null
  rollback_graph_manifest_hash: hash | null
  provenance_refs:
    - provenance://... | artifact://... | receipt://...
  signature: required
```

Every physical ref, implementation, contract, adapter, policy, representation,
and stream/partition member that may affect execution is resolved into
`graph_hash`. Runtime discovery may select among already-declared eligible
bindings, but it may not late-bind a different actuator, policy, component,
schema, frame, unit, authority scope, or criticality class. Any such change
requires a successor graph and a fresh activation transaction.

The graph does not hash its enclosing package. The package binds graph refs and
hashes, while activation binds both exact package and graph hashes; hashing the
package into a graph that the same package hashes would create a circular
content-addressing dependency.

## EmbodiedGraphActivationTransaction

`EmbodiedGraphActivationTransaction` stages, validates, commits, deactivates,
or rolls back one exact graph revision. It is the local lifecycle and atomicity
boundary for native embodied execution, not a replacement for a
RuntimeAssignment, controller binding, Physical Action Safety decision,
physical-mission arming decision, or authority grant.

```yaml
EmbodiedGraphActivationTransaction:
  schema_version: ioi.embodied-graph-activation-transaction.v1
  graph_activation_ref: graph-activation-transaction://...
  activation_epoch: nonnegative_integer
  predecessor_graph_activation_ref: graph-activation-transaction://... | null
  transaction_kind: activate | deactivate | rollback | recover
  runtime_graph_manifest_ref: embodied-runtime-graph-manifest://...
  runtime_graph_manifest_hash: hash
  capability_package_ref: package://...
  capability_package_hash: hash
  system_id: system://...
  embodied_domain_ref: embodied_domain://...
  partition_activations:
    - partition_key: string
      runtime_assignment_ref: runtime-assignment://...
      runtime_node_ref: runtime://...
      node_membership_ref: node-membership://...
      runtime_profile:
        micro | edge | site
      commit_at_local_time: timestamp
      activation_clock_domain_ref: time_sync://...
      runtime_resource_lease_refs:
        - resource-lease://...
      local_control_supervisor_refs:
        - local_control_supervisor://...
      controller_binding_refs:
        - controller-binding://...
      resolved_partition_hash: hash
      local_prepare_receipt_ref: receipt://...
      local_activation_receipt_ref: receipt://... | null
  admission_snapshot:
    resource_group_bindings:
      - group_revision_ref: embodied-resource-group-revision://...
        membership_closure_hash: hash
    embodiment_adapter_bindings:
      - adapter_ref: embodiment_adapter://...
        adapter_hash: hash
    action_policy_bindings:
      - action_policy_contract_ref: embodied-action-policy-contract://...
        action_policy_contract_hash: hash
    world_representation_manifest_ref: world-representation-manifest://...
    world_representation_manifest_hash: hash
    calibration_refs:
      - calibration://...
    time_sync_contract_ref: time_sync://...
    authority_grant_refs:
      - grant://...
    safety_and_assurance_evidence_refs:
      - safety://... | assurance_evidence://... | certification_claim://... |
        conformance_profile://... | evidence://... | receipt://...
  predecessor_control:
    drain_required: boolean
    predecessor_fencing_epoch: nonnegative_integer | null
    drain_fence_and_reconciliation_receipt_refs:
      - receipt://... | evidence://...
  transaction_state:
    proposed | staging | validated | committed | aborted | rolled_back |
    failed_closed
  resulting_graph_state:
    inactive_unarmed | active_unarmed | deactivated | failed_closed
  physical_arming: not_performed_by_transaction
  transition_receipt_refs:
    - receipt://...
  activation_root: hash
  signature: required
```

Prepare validates exact hashes, schedules, resources, stream contracts,
controllers, calibration/time readiness, safety/assurance evidence, and
predecessor fencing before any partition commits. Commit may start graph
scheduling only in `active_unarmed`; it never arms a physical mission or grants
actuation authority. Restart returns a graph to `inactive_unarmed`; it never
resumes physical effects implicitly. A safety-critical partition is immutable
while a later mission is armed. Hot replacement requires a successor graph,
drain/fence or declared safe handoff,
fresh admission, and rollback evidence.

Each controller or runtime profile performs its own fail-closed local
activation. A transaction spanning several nodes records coordinated prepare
and commit receipts, but does not claim impossible atomicity across
controllers or physical effects. If a required partition fails to activate,
already-prepared partitions remain inactive and unarmed, or enter their
declared safe state, and the aggregate transaction fails closed.

## EmbodiedActionChunk

`EmbodiedActionChunk` is a time-bounded, non-authoritative proposal for a
trajectory, waypoint set, setpoint sequence, grasp, locomotion phase,
coordinated subtask, or other short-horizon physical behavior. It
can be produced by a learned policy, classical planner, behavior graph,
optimizer, operator, or replay evaluator. Source does not change its authority
posture.

```yaml
EmbodiedActionChunk:
  schema_version: ioi.embodied-action-chunk.v1
  action_chunk_ref: embodied-action-chunk://...
  action_chunk_hash: hash
  work_binding: TypedWorkSubjectBinding
  physical_mission_envelope_ref: physical_mission_envelope://...
  graph_activation_ref: graph-activation-transaction://...
  action_policy_contract_ref: embodied-action-policy-contract://...
  action_policy_contract_hash: hash
  source:
    source_kind:
      learned_policy | classical_planner | behavior_graph | optimizer |
      operator | replay
    source_ref:
      embodied-action-policy-contract://... | worker://... | module://... |
      user://... | artifact://...
    source_hash: hash
  target:
    unit_ref: robot://... | drone://... | device://... | facility-system://...
    controller_binding_ref: controller-binding://...
    observed_actuator_writer_fence:
      exclusive_actuator_writer_lease_ref: resource-lease://... | null
      fencing_epoch: nonnegative_integer | null
      fencing_token_hash: hash | null
    resource_group_bindings:
      - group_revision_ref: embodied-resource-group-revision://...
        membership_closure_hash: hash
    fleet_mission_allocation_lease_ref:
      fleet-mission-allocation-lease://... | null
    spacetime_reservation_lease_refs:
      - spacetime-reservation-lease://...
  input_basis:
    observation_root: hash
    world_state_ref: world_model://... | state://...
    world_state_watermark_ref: state://... | commitment://...
    calibration_refs:
      - calibration://...
    time_sync_contract_ref: time_sync://...
  proposed_action:
    action_schema_ref: action_schema://...
    action_chunk_payload_ref: artifact://... | state://...
    action_chunk_payload_hash: hash
    begins_at: timestamp
    expires_at: timestamp
    horizon_ms: positive_integer
    interruption_boundary_offsets_ms: []
    expected_observation_and_postcondition_refs:
      - schema://... | policy://... | success_detector://...
  confidence_and_uncertainty_ref: artifact://... | evidence://...
  provenance_refs:
    - provenance://... | trace://... | receipt://...
  authority_posture: non_authoritative_proposal
  direct_execution: forbidden
  selection_and_admission:
    selection_decision_ref: decision://... | null
    physical_safety_decision_ref: decision://... | null
    queue_admission_receipt_ref: receipt://... | null
    physical_command_queue_ref: physical_command_queue://... | null
    resulting_control_segment_ref: control-segment://... | null
  status:
    proposed | selected | rejected | expired | superseded |
    admitted_to_queue | executed_under_segment
  receipt_refs:
    - receipt://...
  signature: required
```

`selected` means only that the selector chose this candidate. Conversion into
one or more `PhysicalCommand` records requires a fresh Physical Action Safety
decision, current authority and leases, current sensor/world evidence, and
admission to the existing `PhysicalCommandQueue`. Only the native
`LocalControlSupervisor` may release admitted commands to a controller under a
bounded `LocalControlSegmentEnvelope`; it may deny, clip, replace, delay,
interrupt, or switch the proposal to an admitted recovery controller. A
`LocalControlBridge` may carry those
commands to an external controller but remains a compatibility binding; it is
not the enforcement owner. Expiry, stale observations, revoked authority,
reservation loss, supervisor veto, or mismatched hashes fails closed.

A simulation- or replay-only chunk may carry a null observed writer fence. Live
queue admission requires a non-null writer lease, epoch, and token hash matching
the supervisor's current exclusive-actuator-writer fence; a stale or absent
fence can be evaluated but cannot produce a physical command.

## SpacetimeReservationLease

`SpacetimeReservationLease` answers **where and when** one embodied unit may
attempt occupancy. `RuntimeAssignmentEnvelope` answers execution placement,
and `FleetMissionAllocationLease` answers **which unit owns which work**. These
contracts remain separate because assigning work neither clears physical space
nor proves that a route, workcell, air corridor, human-exclusion volume, or
cooperative manipulation region is currently safe.

```yaml
SpacetimeReservationLease:
  schema_version: ioi.spacetime-reservation-lease.v1
  reservation_lease_ref: spacetime-reservation-lease://...
  system_id: system://...
  embodied_domain_ref: embodied_domain://...
  work_binding: TypedWorkSubjectBinding
  holder:
    unit_ref: robot://... | drone://... | device://... | facility-system://...
    controller_binding_ref: controller-binding://...
    runtime_assignment_ref: runtime-assignment://...
    resource_group_bindings:
      - group_revision_ref: embodied-resource-group-revision://...
        membership_closure_hash: hash
    fleet_mission_allocation_lease_ref:
      fleet-mission-allocation-lease://... | null
  occupancy:
    geometry_ref: world-representation-manifest://... | world_representation://... | artifact://...
    geometry_hash: hash
    reserved_resource_or_capacity_ref: resource://... | capacity://... | null
    coordinate_frame_ref: world-representation-manifest://... | schema://...
    valid_from: timestamp
    expires_at: timestamp
    uncertainty_and_clearance_margin_ref: policy://... | artifact://...
    occupancy_kind:
      point | path | corridor | volume | workcell | shared_object_region |
      human_exclusion_zone | custom
    capacity: positive_integer
    exclusivity: exclusive | capacity_bounded | cooperative
  coordination:
    reservation_epoch: nonnegative_integer
    fencing_token_hash: hash
    priority: integer
    conflict_and_preemption_policy_ref: policy://...
    related_reservation_refs:
      - spacetime-reservation-lease://...
    observed_world_state_watermark_ref: state://... | commitment://...
  local_safety:
    local_collision_avoidance_overrides_reservation: true
    reservation_is_clearance_proof: false
    local_control_supervisor_ref: local_control_supervisor://...
  issued_by_ref: system://... | policy://... | controller://...
  admission_decision_ref: decision://...
  receipt_refs:
    - receipt://...
  status:
    proposed | active | consumed | expired | preempted | revoked |
    released | failed_closed
  signature: required
```

Reservations expire and fence stale holders. Overlap is valid only when the
declared capacity/cooperative policy admits it. A reservation permits an
attempt inside declared bounds; it does not authorize an actuator, replace
local sensing or collision avoidance, guarantee occupancy is clear, or make a
physical effect exactly once. Partitioned operation may retain only leases
whose issuer, epoch, expiry, world-state freshness, and local partition policy
remain valid.

## EmbodiedDeploymentAssuranceCase

`EmbodiedDeploymentAssuranceCase` is the deployment-bound claim-and-evidence
shape carried by the existing `AssuranceEvidenceBundle.deployment_assurance`
member. It does not create a second assurance registry, evidence store,
certification object, or physical-safety owner. Its stable ref is the owning
`assurance_evidence://...` bundle, whose profiles, receipts, redaction,
validity, and certification-claim relationships remain owned by ecosystem
assurance canon.

```yaml
EmbodiedDeploymentAssuranceCase:
  schema_version: ioi.embodied-deployment-assurance-case.v1
  assurance_evidence_bundle_ref: assurance_evidence://...
  subject:
    runtime_graph_manifest_ref: embodied-runtime-graph-manifest://...
    runtime_graph_manifest_hash: hash
    capability_package_ref: package://...
    capability_package_hash: hash
    target_system_id: system://...
    embodied_domain_ref: embodied_domain://...
  deployment_baseline:
    hardware_firmware_and_controller_refs:
      - artifact://... | controller-binding://...
    binary_toolchain_and_build_refs:
      - artifact://... | package_artifact://... | provenance://...
    native_runtime_profile_set:
      - micro | edge | site
    local_control_supervisor_refs:
      - local_control_supervisor://...
    world_representation_manifest_ref: world-representation-manifest://...
    world_representation_manifest_hash: hash
    calibration_and_time_sync_refs:
      - calibration://... | time_sync://...
  safety_argument:
    physical_action_safety_case_ref: safety://...
    operational_design_domain_ref: artifact://... | policy://...
    hazard_and_safety_requirement_refs:
      - artifact://... | schema://... | policy://...
    timing_and_fault_assumption_refs:
      - artifact://... | policy://...
    monitor_recovery_and_minimum_risk_implementation_refs:
      - artifact://... | controller://... | local_control_supervisor://...
    residual_risk_ref: artifact://...
  verification_evidence:
    simulation_sil_hil_shadow_and_limited_live_refs:
      - eval_report://... | run://... | gate://... | receipt://...
    schedule_fault_injection_and_containment_refs:
      - evidence://... | eval_report://... | receipt://...
    applicable_standard_and_assessment_refs:
      - assurance_profile://... | artifact://... | attestation://...
  certification_claim_refs:
    - certification_claim://...
  predecessor_assurance_evidence_bundle_ref: assurance_evidence://... | null
  amendment_and_revalidation_refs:
    - assurance_evidence://... | decision://... | receipt://...
  validity: valid | incomplete | stale | disputed | revoked
```

The case binds one exact graph and deployment baseline. It cannot be reused as
proof for different hardware, binaries, toolchain, body/controller mappings,
operational design domain, calibration, safety monitor, or recovery path
without an admitted successor case and applicable revalidation. Its presence
is neither actuator authority nor certification; only an independently issued
`CertificationClaim` may state certification, and even that claim does not arm
or activate the system.

## EmbodiedCapabilityPackageEnvelope

The embodied capability package is the center of the embodied architecture.
Foundry builds and evaluates it, the native Embodied Runtime executes its exact
compiled graphs, Physical Action Safety constrains it, wallet.network
authorizes mission scope where delegated power is required, and Agentgres
records state, receipts, and replay. External runtimes, simulators, and replay
engines are optional targets behind declared bindings; none is the package's
semantic or safety owner.

```yaml
EmbodiedCapabilityPackageEnvelope:
  schema_version: ioi.embodied-capability-package.v2
  package_ref: package://...
  revision: semver_or_hash
  package_hash: hash
  foundry_job_ref: foundry_job://...
  capability_spec_ref: capability_spec://...
  embodiment_refs:
    - embodiment://...
  supported_native_runtime_profiles:
    - micro | edge | site
  runtime_graph_manifests:
    - runtime_graph_manifest_ref: embodied-runtime-graph-manifest://...
      runtime_graph_manifest_hash: hash
  embodiment_adapter_bindings:
    - adapter_ref: embodiment_adapter://...
      adapter_hash: hash
  sensor_contract_bindings:
    - sensor_contract_ref: sensor_contract://...
      sensor_contract_hash: hash
  action_schema_bindings:
    - action_schema_ref: action_schema://...
      action_schema_hash: hash
  world_contract_ref: world_contract://...
  world_contract_hash: hash
  world_representation_manifests:
    - world_representation_manifest_ref: world-representation-manifest://...
      world_representation_manifest_hash: hash
  action_policy_contract_bindings:
    - action_policy_contract_ref: embodied-action-policy-contract://...
      action_policy_contract_hash: hash
  success_detector_bindings:
    - success_detector_ref: success_detector://... | model://... | worker://...
      success_detector_hash: hash
  local_control:
    local_control_supervisor_requirement_refs:
      - conformance_profile://... | policy://...
    external_compatibility_adapter_bindings:
      - adapter_ref: connector://... | artifact://...
        adapter_hash: hash
  raw_robot_log_refs:
    - robot_log://... | artifact://...
  episode_dataset_refs:
    - episode_dataset://... | dataset_snapshot://...
  teacher_label_set_refs:
    - teacher_label_set://...
  perception_model_refs:
    - model://...
  calibration_refs:
    - calibration://...
  time_sync_contract_ref: time_sync://...
  safety_and_assurance:
    physical_action_safety_policy_refs:
      - policy://... | safety://...
    embodied_deployment_assurance_case_refs:
      - assurance_evidence://...
    assurance_profile_refs:
      - assurance_profile://...
    assurance_evidence_bundle_refs:
      - assurance_evidence://... | evidence://...
    certification_claim_refs:
      - certification_claim://...
  human_supervision_policy_ref: supervision://...
  emergency_stop_authority_ref: estop://...
  eval_report_refs:
    - eval_report://... | artifact://... | gate://...
  sim_to_real_report_ref: eval_report://... | artifact://...
  promotion_record_refs:
    - promotion_record://...
  receipt_root: hash
  signature: required
  status: draft | evaluated | packaged | proposed | promoted | recalled | revoked
```

Every executable graph, adapter, stream/schema contract, world representation,
policy contract, success detector, and compatibility adapter is bound by exact
ref and hash. The package may contain several graphs or eligible native
profiles, but activation selects one exact graph revision and exact placed
partitions. `safety_and_assurance` reuses the ecosystem assurance family:
deployment-bound safety cases and evidence bundles support admission but never
turn a package, certification claim, or Foundry promotion into live actuator
authority.

## FoundryEmbodiedRuntimeCandidateEnvelope

An embodied runtime candidate is a proposal to bind an embodied capability
package to a target runtime and physical domain. It is not live actuator
authority and cannot activate a graph.

```yaml
FoundryEmbodiedRuntimeCandidateEnvelope:
  schema_version: ioi.foundry-embodied-runtime-candidate.v2
  candidate_id: embodied_candidate://...
  source_training_pipeline_ref: trainpipe://...
  embodied_capability_package_ref: package://...
  embodied_capability_package_hash: hash
  runtime_graph_manifest_ref: embodied-runtime-graph-manifest://...
  runtime_graph_manifest_hash: hash
  intended_runtime: native | external | simulator | replay
  native_runtime_profiles:
    - micro | edge | site
  execution_binding:
    native_local_control_supervisor_profile_refs:
      - conformance_profile://... | policy://...
    external_runtime_adapter_ref:
      connector://... | artifact://... | null
    external_runtime_adapter_hash: hash | null
    simulator_adapter_ref: sim_world_adapter://... | artifact://... | null
    simulator_adapter_hash: hash | null
    replay_input_ref: physical_replay://... | replay://... | null
    replay_input_hash: hash | null
  target:
    embodied_domain_ref: embodied_domain://... | null
    fleet_ref: robot_fleet://... | null
    unit_refs:
      - robot://... | drone://... | device://... | facility-system://...
    controller_binding_refs:
      - controller-binding://...
    resource_group_bindings:
      - group_revision_ref: embodied-resource-group-revision://...
        membership_closure_hash: hash
  exact_contract_bindings:
    embodiment_adapter_bindings:
      - adapter_ref: embodiment_adapter://...
        adapter_hash: hash
    action_policy_contract_bindings:
      - action_policy_contract_ref: embodied-action-policy-contract://...
        action_policy_contract_hash: hash
    world_representation_manifest_ref: world-representation-manifest://...
    world_representation_manifest_hash: hash
    calibration_refs:
      - calibration://...
    time_sync_contract_ref: time_sync://...
  safety_and_assurance_refs:
    - safety://... | assurance_profile://... | assurance_evidence://... |
      certification_claim://... | conformance_profile://...
  required_stage_refs:
    offline_eval: eval_report://...
    software_in_loop: eval_report://...
    hardware_in_loop: eval_report://...
    shadow: run://...
    canary: sim_to_real_gate://... | gate://...
  promotion_status:
    draft | eval | shadow | canary | gated | proposed | rejected | promoted |
    rolled_back | recalled
```

Exactly one execution-binding branch matches `intended_runtime`.
`native_runtime_profiles` is non-empty only for `native`; an external target
requires an exact external adapter; a simulator target requires an exact
simulator adapter; and a replay target requires an immutable replay input.
Simulation and replay candidates cannot be promoted directly into physical
activation. A native candidate may span several profile partitions of the same
graph. Promotion registers the package/graph as eligible for a later
`EmbodiedGraphActivationTransaction`; it does not arm controllers, enqueue commands,
or carry forward evaluation-time authority.
