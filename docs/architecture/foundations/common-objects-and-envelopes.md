# Common Objects and Envelopes

Status: canonical low-level reference.
Canonical owner: this file for shared envelope names, ID namespaces, primitive capability tiers, authority grants, and receipt/run/event envelope fields.
Supersedes: older flattened capability-tier examples in plans/specs.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: mixed (core runtime envelopes/IDs built or partial in the daemon; AIIP transport and collaborative-pursuit, federated ontology/action, NetworkGoalBudget, physical-segment, embodied, cTEE, and prediction families planned or speculative)
Last implementation audit: 2026-07-05

## Purpose

This file defines the shared low-level objects that every IOI/Web4 component
must understand. The goal is to prevent split-brain API design between
`@ioi/agent-sdk`, IOI ADK, IOI ODK, IOI CLI/headless, optional TUI, Hypervisor
Workbench, Workflow Compositor, Hypervisor, Hypervisor Daemon, Agentgres,
wallet.network, aiagent.xyz, sas.xyz, harness profiles, benchmarks,
hosted/self-hosted workers, and IOI L1 contracts.

## Canonical Envelope Types

```text
ManifestEnvelope
AutonomousSystemManifestEnvelope
AutonomousSystemChainEnvelope
HypervisorNodeEnvelope
BoundedExecutionDomainEnvelope
ServiceModuleManifestEnvelope
ModuleInvocationEnvelope
UpgradeProposalEnvelope
UpgradeDecisionEnvelope
LocalSettlementEnvelope
AIIPChannelEnvelope
AIIPEnvelope
MultiPartyCollaborationEnvelope
CapabilityDescriptorEnvelope
TaskOfferEnvelope
TaskAcceptanceEnvelope
HandoffEnvelope
ReceiptCommitmentEnvelope
DeliveryUpdateEnvelope
AcceptanceDecisionEnvelope
SettlementIntentEnvelope
DisputeResolutionEnvelope
ReputationEventEnvelope
AuthorityScopeRequestEnvelope
AuthorityGrantEnvelope
AccessPointBindingEnvelope
StepUpChallengeEnvelope
TaskEnvelope
RunEnvelope
ResourceAllocationDecisionEnvelope
WorkerInstanceEnvelope
RuntimeSubscriptionEnvelope
RuntimeAssignmentEnvelope
ComputeSessionEnvelope
HypervisorOSNodeEnvelope
HypervisorOSBootProfileEnvelope
HypervisorOSBootReceiptEnvelope
NodeMeasurementReceiptEnvelope
PrivateWorkspaceNodeEnvelope
PrivateWorkspaceCapsuleEnvelope
PlaintextFreeModelMountEnvelope
ModelMountViewEnvelope
AlphaSealEnvelope
AutonomyLeaseEnvelope
DeterrenceDetectionProfileEnvelope
RuntimeEventEnvelope
ReceiptEnvelope
ArtifactEnvelope
SealedStateArchiveEnvelope
DeliveryEnvelope
SettlementEnvelope
ContributionEnvelope
NetworkGoalBudgetEnvelope
QualityEnvelope
DisputeEnvelope
AgentWikiEnvelope
DomainOntologyEnvelope
OntologyAssertionEnvelope
OntologyMappingEnvelope
OntologyActionContractEnvelope
CanonicalObjectModelEnvelope
DataRecipeEnvelope
ConnectorMappingEnvelope
PolicyBoundDataViewEnvelope
TransformationRunEnvelope
DistilledOntologyDatasetEnvelope
EvaluationDatasetEnvelope
TrainingEvidenceEligibilityEnvelope
OntologyProjectionEnvelope
OntologyToWorkerPlanEnvelope
OntologyDevelopmentKitManifestEnvelope
OntologySurfaceDescriptorEnvelope
ModelCapacityProfileEnvelope
ModelDeploymentProfileEnvelope
FoundrySpecEnvelope
DatasetSnapshotEnvelope
FoundryRunPlanEnvelope
FoundryTrialEnvelope
FoundryCheckpointArtifactEnvelope
FoundryModelAndPackageArtifactEnvelope
FoundryRegistryVersionAndRouteBindingEnvelope
EmbodiedCapabilitySpecEnvelope
EmbodiedTrainingDataContractEnvelope
EmbodiedCapabilityPackageEnvelope
FoundryEmbodiedRuntimeCandidateEnvelope
PhysicalMissionControlEnvelope
LocalControlSegmentEnvelope
TrainingBatchPlanEnvelope
GenerationBatchEnvelope
TeacherSessionEnvelope
CandidateTrainingSignalEnvelope
RawBatchArchiveEnvelope
QualityGateReportEnvelope
TrainingCostLedgerEnvelope
WorkerTrainingEnvelope
DatasetFactoryRunEnvelope
TrainingPipelineRunEnvelope
ExperimentOptimizationCycleEnvelope
ArtifactConversionRunEnvelope
ConductorAdvisorCandidateEnvelope
PostTrainingCycleEnvelope
ContextMutationEnvelope
FoundryPromotionBundleEnvelope
PromotionDecisionEnvelope
CapabilityRegressionRecordEnvelope
OrchestrationConstraintEnvelope
OrchestrationPlanEnvelope
OrchestrationPolicyEnvelope
OutcomeRoomEnvelope
OutcomeRoomDiscoveryEnvelope
RoomParticipationRequestEnvelope
RoomParticipantLeaseEnvelope
ParticipantStateBundleEnvelope
ResourceOfferEnvelope
CapabilityOfferEnvelope
WorkFrontierItemEnvelope
WorkClaimLeaseEnvelope
AttemptEnvelope
FindingEnvelope
VerifierChallengeEnvelope
WorkResultEnvelope
OutcomeDeltaEnvelope
GoalRunEnvelope
GoalGroundingLoopEnvelope
RoleTopologyEnvelope
ContextCellEnvelope
ContextLeaseEnvelope
ContextHandoffEnvelope
TaskBriefPayloadEnvelope
HarnessInvocationEnvelope
HarnessAdapterEventEnvelope
ImplementationResultPayloadEnvelope
VerifierPathEnvelope
BenchmarkEnvelope
RoutingDecisionEnvelope
```

## Common ID Conventions

```text
ai://...                global intelligence/app/worker/service namespace
system://...            Autonomous System Package namespace
domain://...            bounded execution domain, application domain, or sovereign domain namespace
org://...               organization, enterprise, DAO, regulator, auditor, provider, or institutional party identity
user://...              human user, operator, sponsor, or accountable individual identity
project://...           governed project or workspace-project identity
policy://...            versioned policy, admission rule, obligation set, or governance profile identity
schema://...            versioned data, event, payload, receipt-profile, or interface schema identity
event://...             durable or referenced event identity
intent://...            declared user, service, autonomous-work, or physical-action intent identity
node://...              Hypervisor Node or runtime node namespace
module://...            governed service-module namespace
invocation://...        module invocation namespace
proposal://...          upgrade, policy, module, workflow, or settlement proposal namespace
transition://...        accepted local state-transition namespace
state://...             referenced operational, environment, world, or domain state identity
agentgres://...         Agentgres domain, operation, object, projection, or state-root ref
provenance://...        source, derivation, observation, attribution, or lineage record identity
prompt://...            policy-governed prompt/template artifact identity; never raw secret transport
surface://...           registered product, application, operator, or generated surface identity
route://...             generic non-model route, path, or routing-candidate identity
verifier://...          verifier identity when a Worker, organization, or gate ref is not the subject
decision://...          policy, admission, acceptance, routing, merge, or adjudication decision identity
acceptance://...        explicit delivery, result, service, or outcome acceptance identity
dispute://...           challenge and dispute lifecycle identity
effect://...            declared external, business, digital, or physical effect identity
aiip://channel/...      AIIP channel namespace
packet://...            AIIP packet namespace
collaboration://...     multi-party collaboration context, shared-proof, or party-view identity
outcome-room://...      shared collaborative-pursuit room identity
participant-lease://... room participant lifecycle and bounded participation lease
frontier://...          claimable collaborative work-frontier item
work-claim://...        leased claim over one bounded frontier item
attempt://...           durable positive, negative, inconclusive, or invalid attempt
finding://...           provenance-bearing claim, hypothesis, or finding
verifier-challenge://... challenge to evidence, evaluation, eligibility, or verifier rules
work-result://...       generic result returned by bounded work
outcome-delta://...     proposed change to outcome, frontier, knowledge, or domain state
room-discovery://...    policy-bound public/permissioned OutcomeRoom discovery projection identity
participation-request://... typed request by an external party to join a discoverable OutcomeRoom
participant-state://... policy-bound portable state bundle issued for an active or exiting room participant
resource-offer://...    room-scoped offer of compute, capacity, data access, or another allocatable resource
capability-offer://...  room-scoped offer of a worker, service, tool, verifier, or other capability
capability://...        reusable declared capability descriptor identity
resource://...          allocatable compute, data, storage, tool, or service resource identity
capacity://...          availability and quantity profile for an allocatable resource identity
region://...            provider, data-residency, execution, or physical locality identity
custody://...           declared data, key, model, artifact, or execution custody posture identity
context-profile://...   versioned context eligibility, projection, and disclosure profile identity
goal-budget://...       separately funded Network/Open goal budget for independent labor, verification, services, challenge, and settlement
work-credit://...       non-transferable managed-work credit or included/top-up allowance unit
ontology-assertion://... provenance-bearing semantic assertion or relationship
ontology-mapping://... explicit cross-ontology mapping and compatibility decision
ontology-action://...  executable semantic action contract
control-segment://...  bounded certified local real-time control interval
physical_mission_envelope://... bounded slow-plane embodied mission authority envelope
settlement-intent://... AIIP settlement intent namespace
delivery://...          service delivery, delivery update, or cross-domain outcome delivery identity
evidence://...          evidence bundle, proof bundle, or admitted evidence identity
redacted_summary://...  redacted summary identity for shareable context without raw payload
revocation://...        authority, party, client, connector, view, or collaboration revocation identity
ioi://publisher/...     publisher identity
agent://...             product-facing agent instance or compatibility worker instance
worker://...            worker package or worker type
install://...           worker install/license binding
package://...           worker, model, service, autonomous-system, or embodied capability package identity
subscription://...      runtime or managed-instance subscription/entitlement
service://...           sas.xyz service definition
order://...             sas.xyz service order or cross-domain outcome order
run://...               runtime run identity
task://...              task identity
goal://...              ioi.ai or coordinator goal identity
outcome-plan://...      ioi.ai Goal Space outcome and orchestration plan identity
attempt-summary://...   product projection summarizing one admitted or proposed attempt
outcome-graph://...     cross-session Goal Space outcome graph projection identity
connector-escalation://... typed connector connection, scope, or approval escalation identity
mission://...           Hypervisor Mission or durable collaborative mission identity
automation://...        Hypervisor Automation specification or run identity
capability-request://... request for bounded executable capability or authority evaluation
approval-request://...  typed request for human, policy, wallet, or governance approval
goal_loop://...         goal grounding loop identity for conductor orientation and continuation
role_topology://...     selected role topology for a goal, session, automation, or managed instance
context_cell://...      independent role context for conductor, implementer, reviewer, verifier, operator, or specialist work
context_lease://...     scoped context/tool/memory/authority/budget lease issued to a context cell or harness invocation
handoff://...           typed context handoff between context cells
task_brief://...        normalized task brief payload for bounded implementation or specialist work
harness_invocation://... daemon-mediated invocation of a selected HarnessProfile or Agent Harness Adapter
harness_event://...     normalized event emitted by a harness adapter during invocation
implementation_result://... normalized implementation result payload returned from a harness invocation
constraint://...        orchestration, workflow, policy, or object constraint identity
orchestration_policy://... versioned outcome-conductor plan-selection policy identity
orchestration_plan://... candidate or selected orchestration plan identity
verifier_path://...     configured verification path for a run, plan, worker, route, or package
runtime://...           Hypervisor Daemon runtime-node identity
compute://...           compute session identity
boot_profile://...      HypervisorOS boot profile identity
measurement_policy://... HypervisorOS node measurement policy identity
artifact://...          Agentgres artifact ref
receipt://...           receipt identity
benchmark://...         benchmark profile or benchmark run identity
rubric://...            evaluation rubric identity
ontology://...          domain ontology identity
semantic-profile://... versioned negotiated semantic compatibility profile identity
object-model://...      canonical object model identity
recipe://...            data recipe identity
mapping://...           connector mapping identity
view://...              policy-bound data view identity
dataset://...           evaluation or training dataset identity
dataset_snapshot://...  immutable dataset materialization, split, manifest, and lineage identity
eligibility://...       training evidence eligibility or exclusion identity
teacher_session://...   Foundry teacher, critic, judge, debate, or correction session identity
candidate_data://...    quarantined or accepted candidate training-signal record identity
training_stack://...    source-neutral Foundry training-stack blueprint identity
trainer_backend://...   trainer, evaluator, converter, or distributed-backend profile identity
verifier_set://...      verifier, reward, environment-feedback, or task-set bundle identity
reasoning_policy://...  thinking, non-thinking, budget, and trace-disclosure training policy identity
foundry_spec://...      declarative Foundry training, eval, packaging, or promotion spec identity
run_plan://...          typed Foundry stage graph and executor-binding plan identity
trial://...             optimizer, sweep, training, or evaluation trial identity
checkpoint://...        resumable training, optimizer, or execution checkpoint identity
model_artifact://...    frozen training-native model, adapter, or checkpoint-derived artifact identity
package_artifact://...  deployable runtime package, converted model, image, or endpoint package identity
registry_version://...  registered model, worker, package, or routeable artifact version identity
promotion_record://...  auditable route binding, traffic split, alias change, or promotion decision identity
promotion_bundle://...  immutable Foundry promotion bundle identity
package_binding://...   runtime binding between a capability package and a target domain or route identity
projection://...        ontology-aware or Agentgres projection identity
trace://...             replayable operation/effect trace identity
replay://...            replay bundle, replay report, or replay-plan identity
transform://...         transformation run identity
plan://...              ontology-to-worker plan identity
profile://...           training/model capacity profile identity
batch://...             training batch plan or generation batch identity
gate://...              quality gate report or promotion gate identity
ledger://...            usage, token, cost, or contribution ledger identity
resource_pool://...     capacity pool, provider pool, quota pool, or runtime capacity identity
allocation://...        resource allocation request or decision identity
resource-lease://...    bounded lease over compute, data, capacity, or another allocated resource
budget://...            managed-work, spend, quota, token, runtime, GPU, or rate-limit budget identity
spend://...             reserved, admitted, reconciled, refunded, or settled spend record identity
quote://...             bounded provider, worker, service, or resource quote identity
rate-card://...         versioned pricing and charging rule identity
escrow://...            escrow account, reservation, or conditional release identity
price-schedule://...    versioned route, provider, service, or resource price schedule identity
terms://...             versioned provider, model, service, license, or commercial terms identity
cost://...              attributable estimated, reserved, admitted, reconciled, or settled cost identity
fee://...               explicit platform, coordination, marketplace, service, or settlement fee identity
fee-basis://...         versioned rule and evidence basis used to calculate a fee
quota://...             provider, project, org, connector, or model quota identity
rate_limit://...        rate-limit policy or observed throttle identity
schedule://...          schedule, trigger, or catch-up policy identity
audit_export://...      compliance, customer, regulator, SLA, tax, or internal audit export bundle identity
assurance_evidence://... assurance evidence bundle identity
assurance_profile://... ecosystem assurance profile identity
conformance_profile://... interface, runtime, gateway, wallet-client, or service conformance profile identity
certification_claim://... certification claim identity over a subject and assurance profile
jurisdiction_policy_pack://... jurisdiction, compliance, retention, or regulated-action policy pack identity
liability_claim_route://... liability, insurance, incident, or dispute claim-route identity
abuse_signal://... abuse, threat, vulnerability, policy-violation, or quarantine signal identity
commercial_export://... commercial assurance, billing, SLA, tax, or customer export identity
retention_lock://...    retention hold, deletion hold, or legal/audit lock identity
restricted_view://...   restricted/redacted/export-safe view identity
invoice://...           invoice identity
cost_center://...       cost center identity
sla://...               SLA report or service-level objective identity
tax://...               tax profile or tax export identity
procurement://...       purchase order, procurement profile, or vendor review identity
foundry_job://...       Foundry job identity
trainpipe://...         Foundry training pipeline run identity
optcycle://...          Foundry experiment optimization cycle identity
conversion://...        Foundry artifact conversion run identity
conductor://...         conductor advisor or coordinator candidate identity
embodied_candidate://... Foundry embodied runtime candidate identity
regression://...        capability regression, canary regression, or post-promotion regression record identity
model://...             model artifact, registered model, or model-family identity
model_route://...       model routing profile, endpoint candidate, or serving policy identity
model-route-contract://... versioned rights, privacy, pricing, availability, and fallback contract for a model route
route-attempt://...     one admitted attempt through a provider/model/runtime route
route-chain://...       ordered primary, cascade, fallback, or hedged route plan identity
routing-decision://...  neutral routing decision over a committed candidate and affiliation set
routing-prior://...     versioned routing prior or learned routing-policy signal identity
interactive_world://... Foundry interactive game, simulator, browser, domain-app, robotics-sim, or synthetic world identity
gameplay://...          normalized gameplay or interactive-world trajectory dataset identity
scenario_curriculum://... scenario curriculum, perturbation set, difficulty ladder, and holdout identity
spatial_policy://...    spatial-temporal policy, route policy, or action-policy candidate identity
sim_world_adapter://... simulator/game/browser/domain-world adapter identity
world_transfer_gate://... world-to-runtime transfer gate identity
capability_spec://...   embodied or autonomous capability task, success, command, and safety spec identity
embodied_domain://...   physical-domain runtime identity for a site, facility, field area, or fleet domain
robot_fleet://...       fleet identity for robots, drones, humanoids, devices, or facility systems
robot://...             robot, drone, device, or embodied unit identity
controller://...        controller identity for robot, facility, actuator, or bridge control
controller-binding://... versioned binding between an embodied domain/unit and its admitted local controller
heartbeat://...         participant, worker, controller, lease, or runtime liveness observation identity
sensor://...            physical sensor identity
actuator://...          physical actuator identity
embodiment://...        robot embodiment, body, kinematic family, or actuator/sensor form identity
embodiment_adapter://... mapping between canonical action semantics and a specific robot/controller identity
sensor_contract://...   required sensor schema, modality, calibration, freshness, and evidence contract identity
action_schema://...     embodied action space, action chunk, trajectory, or command-target schema identity
world_contract://...    scene, geometry, coordinate-frame, simulation, and collision/physics assumptions identity
world_model://...       live or candidate physical world model identity
world_representation://... visual, geometric, semantic, or physics-proxy world representation identity
robot_log://...         raw synchronized multimodal robot log, bag, or robotics-native capture identity
episode_dataset://...   normalized sequential decision episode dataset identity
teacher_label_set://... teacher-generated embodied labels, rewards, subgoals, or success annotations identity
success_detector://...  embodied success/failure detector, evaluator, or validation policy identity
eval_report://...       embodied, model, package, route, or capability evaluation report identity
safety://...            physical safety envelope or safety-case identity
supervision://...       human supervision, handoff, or operator policy identity
estop://...             emergency-stop authority, channel, or control identity
calibration://...       physical calibration record identity
time_sync://...         clock, timestamp, frame, and stream synchronization contract identity
local_control_bridge://... local control bridge identity for embodied domains
heartbeat_policy://...  heartbeat and fail-closed policy identity
physical_command_queue://... physical command queue identity
physical_command://...  movement, manipulation, facility, stop, or handoff command identity
telemetry_stream://...  physical telemetry stream identity
physical_replay://...   physical replay bundle identity
sim_to_real_gate://...  sim-to-real promotion gate identity
wiki://...              Agent Wiki or durable semantic-memory surface identity
memory://...            context-memory record or local memory-plane identity
memory_profile://...    declared memory retention, portability, privacy, projection, and archive profile identity
memory_archive://...    encrypted restorable memory archive identity
memory_projection://... harness-, model-, worker-, or surface-specific memory projection identity
cid://...               content-addressed payload ref, commonly Filecoin/CAS/IPFS
wallet://...            wallet.network account or authority provider ref
authority://...         portable delegated authority, approval, consent, or provider-specific authority object ref
auth_factor://...       wallet.network authentication factor identity
access_point://...      low-assurance access-point binding ref
challenge://...         short-lived wallet.network step-up challenge pointer
credential://...        provider credential binding or secret metadata ref
key_shard://...         MPC, threshold, hardware-backed, or org key-share ref
wallet_client://...     wallet.network CLI/MCP/mobile/web/embedded client session
origin://...            authority-client origin binding identity
device://...            authority-client, guardian, or enrolled device identity
key://...               public key, signing key, or key material metadata ref
lease://...             capability lease or short-lived authority lease ref
mcp_gateway://...       Hypervisor MCP Gateway profile identity
connector://...         connector or external-system adapter identity
tool://...              typed tool or tool contract identity
mcp://...               MCP server, tool surface, or gateway-exposed MCP capability identity
session://...           Hypervisor session identity
work_run://...          WorkRun identity
worktree://...          workspace/worktree projection identity for diff, status, and file-scope evidence
message://...           bounded message or summary artifact identity
diff://...              diff or patch evidence identity
test://...              test run, test case, verifier script result, or check identity
script://...            verifier, build, migration, or harness script identity
blocker://...           blocker or unresolved-decision identity
screenshot://...        screenshot or visual evidence identity
endpoint://...          API, route, or service endpoint identity
incident://...          provider, runtime, storage, authority, safety, or ecosystem incident identity
recovery://...          environment, WorkRun, artifact, physical, or service recovery attempt identity
quarantine_advisory://... quarantine advisory identity
shielded_capsule://...  private workspace capsule identity; legacy name kept for compatibility
model_mount://...       plaintext-free model mount identity
model_mount_view://...  per-inference plaintext-free model mount view identity
environment://...       Hypervisor environment identity
provider://...          environment, compute, storage, model, connector, or service provider identity
observation://...       lifecycle, runtime, support, or provider evidence observation identity
snapshot://...          environment/workspace point-in-time material identity
backup://...            environment/workspace durability material identity
archive://...           policy-bound restore-chain material identity
patch_branch://...      Agentgres patch-branch coordination identity
execution_branch://...  branchable Agentgres run state over trace, workspace, memory, authority, and receipts
staged_effect://...     pre-settlement effect intent/outcome or staged mutation identity
branch_checkpoint://... checkpoint of execution-branch state and object heads
branch_merge://...      branch comparison, merge, admission, or discard plan identity
work_item://...         Work item identity inside a queue, recovery, automation, or WorkRun
custody_proof://...     cTEE proof-carrying workspace custody proof identity
privacy_posture://...   cTEE execution privacy posture identity
coverage://...          cTEE candidate coverage / redundancy profile identity
crypto_op_policy://...  cTEE cryptographic/private operator policy identity
counterfactual_lattice://... cTEE committed counterfactual candidate lattice identity
alpha_seal://...        sealed private strategy capsule identity
autonomy_lease://...    wallet-bounded offline autonomy lease identity
guardian://...          high-assurance wallet/cTEE guardian or threshold authority participant
leakage://...           declared leakage profile for Private Workspace/private work
deterrence://...        cTEE deterrence/detection profile identity
commitment://...        private output, state, or witness commitment
capability_exit://...   bounded external action exit from protected work
license://...           artifact, dataset, model, worker, contribution, or output license identity
method://...            declared research, implementation, verification, or execution method identity
state-delta://...       typed proposed or admitted state change payload identity
tool-lease://...        bounded lease over a tool or connector capability
prim:*                  primitive execution capability ref
scope:*                 wallet.network authority scope ref
grant://...             authority grant or lease ref
```

The table above is exhaustive for URI schemes that this shared-object canon
owns and promotes across components. A component may still own opaque local
refs and show them in component-local examples, but those refs remain governed
by their named component owner and do not become protocol-global merely by
appearing in a schema. Promoting a local ref into this shared canon requires
registering its scheme here first.

All IDs must be globally unique within their declared namespace. IDs that
become public must be stable. Runtime-local IDs may be temporary but must map to
stable Agentgres IDs when settled.

## Capability and Authority Tiers

IOI uses two separate tiers that must not be collapsed into a single generic capability field:

```text
Primitive execution capabilities:
  prim:fs.read
  prim:fs.write
  prim:sys.exec
  prim:ui.interact
  prim:net.request
  prim:model.invoke

Authority scopes and leases:
  scope:gmail.read
  scope:gmail.send
  scope:calendar.create
  scope:repo.write
  scope:commerce.order_submit
```

Primitive capabilities are runtime feasibility and isolation primitives. They describe the low-level action classes a runtime/tool requires.

Authority scopes are wallet.network policy grants over resources, providers,
identities, budgets, approvals, and expiry. They describe what a delegated
subject is allowed to do outside ordinary local product governance.

Application-local permissions, project settings, dataset eligibility,
workflow draft permissions, ontology proposal state, and surface-local review
state are policy/admission/governance objects until they require a portable
authority lease, secret, spend, decryption, declassification, external
connector access, provider-trust acceptance, cross-domain reuse, or autonomous
agent execution.

Provider names, fixture names, tool availability, and authority scopes must never alter semantic intent ranking. They may affect admission, policy, routing feasibility, and verification requirements only after the intent has been understood.

## ManifestEnvelope

```yaml
ManifestEnvelope:
  manifest_id: ai://...
  manifest_type: app | autonomous_system | autonomous_system_chain | bounded_execution_domain | service_module | worker | service | runtime | domain | tool | connector
  version: semver_or_hash
  publisher_id: ioi://publisher/...
  manifest_root: hash
  body_ref: cid://... | https://... | agentgres://...
  signature:
    scheme: ed25519 | secp256k1 | ml-dsa | hybrid
    public_key_ref: ...
    signature: base64
  l1_commitment:
    chain_id: ioi-mainnet
    contract: ManifestRootRegistry
    tx_hash: optional
  status: draft | active | deprecated | revoked
  interaction_surfaces:
    - chat
    - form
    - api
    - workflow_node
    - scheduler
    - background_service
  runtime_profiles:
    - local
    - hosted
    - provider
    - depin
    - tee
    - customer_vpc
  persistence_profiles:
    - ephemeral
    - session
    - zero_to_idle
    - persistent
  subscription_profiles:
    - per_invocation
    - warm_runtime
    - managed_monthly
  mow:
    sparse_worker_category: optional
    benchmark_profile_refs: []
    evaluation_rubric_ref: optional
    routing_eligibility_status: draft | submitted | benchmarking | eligible | suspended | revoked
    contribution_policy_ref: optional
    training_lineage_ref: optional
  worker_profile:
    architecture_profile: optional
    active_context_strategy: optional
    context_mutability: none | external_context_only | adapter_promoted | package_revision
    post_training_policy_ref: optional
  semantic_data:
    ontology_refs: []
    canonical_object_model_refs: []
    data_recipe_refs: []
    connector_mapping_refs: []
    distilled_dataset_refs: []
    evaluation_dataset_refs: []
  model_deployment:
    profile_ref: optional
    mount_mode: bundled_weights | local_file | local_server | external_api | hosted_pool | tee_session | depin_session | customer_vpc | none
    model_artifact_refs: []
    endpoint_refs: []
```

## Autonomous System Package Lifecycle

Hypervisor's primary build artifact is an Autonomous System Package.

An Autonomous System Package is the developer-facing skeletal unit for
autonomous-system work. It is not an agent, connector, workflow, daemon
process, or policy bundle. It binds worker responsibility, workflow or harness
topology, model and tool capabilities, authority, memory/state/artifacts, evals,
deployment profiles, and receipts into one packageable object.

Implementation may represent the package as a strict `ManifestEnvelope` profile,
as `AutonomousSystemManifestEnvelope`, or as both. That implementation choice
must not make the package concept invisible in product, SDK, ADK, CLI/headless,
workflow, or documentation surfaces.

The canonical lifecycle loop is:

```text
compose -> bind -> simulate -> authorize -> run -> verify -> inspect receipts
-> package -> deploy -> promote -> improve
```

Short product form:

```text
build -> bind authority -> test -> run -> inspect receipts -> package
-> promote
```

Lifecycle readiness must not collapse into one vague ready state. IOI clients
should distinguish:

| Readiness | Meaning | Blocking Scope |
| --- | --- | --- |
| Run readiness | The graph can execute now in the selected runtime profile. | Blocks Run. |
| Authority readiness | Required grants, approvals, and secret leases are available. | Blocks live effects. |
| Package readiness | The graph can become a complete Autonomous System Package. | Blocks package/publish. |
| Evaluation readiness | Eval cases, scorecards, replay expectations, and quality gates exist. | Blocks promotion. |
| Deployment readiness | The target runtime/deployment profile can run the package. | Blocks deploy. |
| Promotion readiness | The package is safe and qualified for reuse, marketplace, service, or Foundry feedback loops. | Blocks promotion. |

### Terminology Boundary Table

| Term | Canonical Meaning | Must Not Mean |
| --- | --- | --- |
| Autonomous System Package | The primary developer-facing build artifact binding worker responsibility, topology, capabilities, authority, memory/state/artifacts, evals, deployment profiles, and receipts. | A raw workflow file, a connector config, or a daemon process. |
| AutonomousSystemManifest | The manifest/profile contract that makes an Autonomous System Package deterministic, portable, evaluable, and receipted. | A second runtime or React Flow truth store. |
| Worker | Durable protocol actor, responsibility boundary, package identity, routing target, and event/receipt subject. | Merely a UI label for a chat agent. |
| Agent | Product-facing instance or compatibility alias that may be worker-backed. | The canonical low-level actor when Worker is required. |
| Workflow | Deterministic executable composition manifest. | Hidden product state or the React Flow canvas itself. |
| Harness | Reusable workflow topology for a behavior class such as coding loop, browser/computer-use loop, evaluation loop, or proposal-first mutation loop. | A provider-owned action runtime. |
| Capability | Primitive/model/tool feasibility and contract reference. | Authority, secret possession, or policy permission. |
| Authority | wallet.network grant or lease over resource, provider, identity, budget, approval, secret, and expiry for delegated machine power. | A capability flag, UI readiness badge, or every app-local permission. |
| Policy | Admission and behavior rules over authority, risk, approval, privacy, retention, evidence, and execution posture. | Tracing, telemetry, or run history. |
| Tool | Executable capability with schema, risk, primitive capability requirements, authority scopes, approval requirements, and receipt behavior. | Ambient connector access. |
| Connector | External system adapter exposing tools. | Runtime truth, authority owner, or untyped API access. |
| Skill | Instruction/resource/procedure package that can influence context. | Authority grant or executable tool by itself. |
| Session | Current interaction or run context. | Long-term memory or package identity. |
| State | Scoped serializable working data. | Canonical domain truth unless settled through Agentgres/contracts. |
| Memory | Governed long-term recall or retrieval surface. | Unbounded hidden context. |
| Artifact | Materialized output, evidence, or deliverable. | A receipt by itself. |
| Event | Observation that something happened. | Durable proof of correctness. |
| Trace | Ordered diagnostic/observability path through runtime behavior. | Policy decision or authority grant. |
| Receipt | Durable proof of an action, decision, verification, artifact, authority use, or promotion outcome. | A log line or UI-only status. |
| Runtime | Daemon/runtime execution contract and event/receipt producer. | React Flow, a provider SDK, or a model-owned loop. |

### AutonomousSystemManifestEnvelope

```yaml
AutonomousSystemManifestEnvelope:
  schema_version: ioi.autonomous-system-manifest.v1
  system_id: system://...
  manifest_id: ai://...
  display_name: string
  description: string
  version: semver_or_hash
  status: draft | runnable | package_ready | deployable | promoted | revoked
  worker:
    worker_ref: worker://... | agent://...
    responsibility: string
    owner_ref: ioi://publisher/...
  workflow:
    workflow_manifest_ref: artifact://... | cid://... | inline_ref
    harness_ref: optional
    topology_hash: string
  source_project:
    project_ref: optional
    repository_refs: []
    default_branch_or_ref: optional
    development_environment_recipe_ref: optional
    issue_tracker_refs: []
    code_owner_refs: []
  interfaces:
    operator_console_ref: optional
    generated_domain_app_ref: optional
    api_endpoint_refs: []
    mcp_profile_refs: []
    aiip_channel_refs: []
    preview_or_public_endpoint_refs: []
  capabilities:
    model_capability_refs: []
    model_deployment_profile_refs: []
    tool_capability_refs: []
    connector_refs: []
    primitive_capabilities_required: []
  authority:
    authority_scope_requirements: []
    grant_requirements: []
    approval_profile_ref: optional
    policy_profile_ref: optional
    revocation_posture: fail_closed | pause | degrade_read_only
  runtime_profiles:
    - profile_id: profile://...
      kind: local_daemon | task_browser | local_container | hosted_daemon | cloud_vm | tee | depin | customer_vpc
      readiness: ready | degraded | missing | external
      cleanup_policy_ref: optional
  session_state_memory_artifacts:
    session_profile_ref: optional
    state_profile_ref: optional
    memory_profile_ref: optional
    artifact_retention_profile_ref: optional
    observation_retention_mode: summary_only | local_redacted | local_raw | encrypted_local_raw | no_persistence
  evaluation:
    eval_profile_refs: []
    benchmark_refs: []
    quality_gate_refs: []
    replay_profile_ref: optional
  promotion:
    promotion_profile_ref: optional
    release_target_refs: []
    rollout_policy_ref: optional
    rollback_policy_ref: optional
    recall_policy_ref: optional
    kill_switch_ref: optional
    marketplace_exposure_eligibility: none | internal | review_required | eligible
    foundry_lineage_refs: []
    worker_card_preview_ref: optional
  receipts:
    package_readiness_receipt_ref: optional
    latest_run_receipt_refs: []
    latest_eval_receipt_refs: []
```

The envelope is a package/readiness and portability contract. It must compile
to daemon/runtime, wallet.network, Agentgres, workflow, connector/tool, and
receipt contracts; it must not bypass them.

## Governed Autonomous-System Chain Envelopes

Governed autonomous-system chains are local stateful execution objects. They
are not necessarily standalone public blockchains or IOI L1s. Their accepted
operations and receipts live in Agentgres/domain state, while IOI L1 anchors
only selected roots when public trust or economic settlement requires it.

```yaml
AutonomousSystemChainEnvelope:
  chain_id: system://...
  owning_hypervisor_node_id: node://...
  manifest_ref: ai://...
  worker_instance_refs: []
  workflow_refs: []
  policy_root: hash
  module_registry_root: hash
  proposal_queue_root: hash
  operation_log_ref: agentgres://...
  latest_state_root: hash
  latest_receipt_root: hash
  latest_transition_id: transition://...
  upgrade_policy_ref: policy://...
  l1_anchor_policy:
    anchor_identity: boolean
    anchor_policy_roots: boolean
    anchor_upgrade_roots: boolean
    anchor_receipt_roots: on_dispute | on_settlement | periodic | never
  status: draft | active | paused | archived | revoked
```

```yaml
HypervisorNodeEnvelope:
  node_id: node://...
  owner_id: wallet://... | org://... | project://...
  hypervisor_ide_ref: optional
  daemon_runtime_ref: runtime://...
  agentgres_domain_ref: agentgres://domain/...
  wallet_authority_ref: wallet://...
  local_registry_refs:
    workers: []
    modules: []
    workflows: []
    manifests: []
  autonomous_system_chain_refs: []
  receipt_store_ref: agentgres://...
  replay_store_ref: agentgres://...
  l1_anchor_policy_ref: optional
  status: local | hosted | hybrid | enterprise | archived
```

```yaml
HypervisorOSNodeEnvelope:
  node_id: runtime://...
  profile: hypervisoros_bare_metal
  owner_ref: wallet://... | provider://...
  daemon_ref: runtime://...
  boot_profile_ref: boot_profile://...
  measurement_policy_ref: measurement_policy://...
  ctee_policy_ref: policy://...
  agentgres_domain_ref: agentgres://domain/...
  supported_worker_substrates:
    - microvm
    - container
    - wasm
    - model_server
  forbidden_bypasses:
    - direct_plaintext_private_mount
    - unreceipted_tool_execution
    - raw_secret_env_injection
    - daemonless_model_server
    - unscoped_network_egress
  receipts_required:
    - HypervisorOSBootReceipt
    - NodeMeasurementReceipt
    - ModelMountReceipt
    - CapabilityExitReceipt
```

## AIIP and Bounded Execution Domain Envelopes

AIIP is the shared semantic protocol for local microharness routing and
external autonomous-system handoffs. Transports and settlement depth may vary,
but consequential work packets must compile into typed envelopes with policy,
authority, receipt, and settlement semantics.

This file owns the canonical field-level `AIIPChannelEnvelope` and
`AIIPEnvelope` schemas because they are shared boundary objects. The AIIP owner,
[`aiip.md`](./aiip.md), owns packet semantics, processing rules, protocol
profiles, conformance, and evolution. Other documents reference these schemas;
they must not publish a competing reduced envelope.

```yaml
BoundedExecutionDomainEnvelope:
  domain_id: domain://...
  owner_ref: wallet://... | org://... | project://... | ioi://publisher/...
  domain_kind: local_microharness | installed_worker | marketplace_worker | outcome_provider | enterprise_runtime | robot_fleet | dao_operator | autonomous_system | as_l1 | appchain | sovereign_domain
  manifest_ref: ai://...
  capabilities: []
  policies:
    policy_root: hash
    dispute_policy_ref: optional
    privacy_policy_ref: optional
  authority_requirements:
    authority_scope_requirements: []
    grant_requirements: []
  receipt_schema_refs: []
  state_boundary:
    state_root: optional_hash
    state_ref: optional agentgres://... | cid://...
    public_commitment_mode: local_only | optional_anchor | mainnet_required | dispute_only | reputation_only
  runtime_profile:
    kind: local_daemon | in_process | local_http | grpc | json_rpc | nats | hosted_daemon | cloud_vm | tee | depin | customer_vpc | robot_controller | external_api
    endpoint_ref: optional
  settlement_behavior:
    settlement_account_ref: optional
    default_mode: local_only | optional_anchor | mainnet_required | dispute_only | reputation_only
    escrow_supported: boolean
  aiip_profiles_supported: []
  status: draft | active | suspended | revoked | archived
```

Robot fleets, robot controllers, drones, vehicles, facility systems, IoT
actuators, and other embodied domains are allowed bounded execution domains,
but they must not treat actuator effects as ordinary tool traffic. When a
domain can perform `physical_action`, its envelope should bind physical-action
safety posture explicitly:

```yaml
physical_action_safety:
  physical_action_policy_refs:
    - policy:...
  safety_envelope_refs:
    - safety:...
  emergency_stop_authority_ref: estop:...
  human_supervision_policy_ref: supervision:... | null
  incident_policy_ref: policy:...
  required_receipt_schema_refs:
    - schema:SensorEvidenceReceipt
    - schema:ActuatorCommandReceipt
```

The canonical owner for these objects is
[`physical-action-safety.md`](./physical-action-safety.md). AIIP may carry
handoffs and command envelopes, but actuator-affecting actions still require
safety envelope semantics, wallet.network authority, daemon gating, evidence,
and receipts.

```yaml
AIIPChannelEnvelope:
  channel_id: aiip://channel/...
  system_id_from: system://... | domain://...
  system_id_to: system://... | domain://...
  profile: local | installed_worker | marketplace_worker | outcome_service | autonomous_system | collaborative_pursuit | enterprise
  transport: in_process | daemon_ipc | unix_socket | local_http | grpc | json_rpc | nats | https | queue | chain_relay
  schema_version: semver_or_hash
  relay_policy_ref: optional
  authority_policy_ref: optional
  privacy_mode: public | private | encrypted | redacted | permissioned_evidence
  settlement_mode: local_only | optional_anchor | mainnet_required | dispute_only | reputation_only
  sequence_root: optional_hash
  status: opening | active | paused | closing | closed | disputed
```

```yaml
AIIPEnvelope:
  packet_id: packet://...
  message_type: capability_discovery | task_offer | task_acceptance | handoff |
    semantic_profile_negotiation | room_discovery | room_participation |
    frontier_update |
    work_claim | attempt_finding | verifier_challenge | room_admission |
    authority_query | authority_grant | receipt_commitment | delivery_update |
    acceptance_decision | settlement_intent | dispute | dispute_resolution |
    reputation_query
  system_id_from: system://... | domain://...
  system_id_to: system://... | domain://...
  channel_id: aiip://channel/...
  sequence_or_nonce: string
  idempotency_key: string
  causation_ref: packet://... | event://... | receipt://... | null
  correlation_ref:
    goal://... | task://... | outcome-room://... | collaboration://... | null
  timestamp_or_slot: string
  profile: local | installed_worker | marketplace_worker | outcome_service |
    autonomous_system | collaborative_pursuit | enterprise
  policy_hash: hash
  authority_ref: optional grant://...
  collaboration_envelope_ref: collaboration://... | null
  outcome_room_ref: outcome-room://... | null
  ontology_profile_refs:
    - ontology://... | semantic-profile://... | ontology-mapping://...
  action_schema_profile_refs:
    - ontology-action://... | action_schema://... | schema://...
  restricted_view_refs:
    - restricted_view://... | view://...
  verifier_challenge_refs:
    - verifier-challenge://...
  payload_hash: hash
  payload_ref: optional artifact://... | cid://... | encrypted_ref
  receipt_obligations: []
  verifier_and_acceptor_refs: []
  assurance_stage: optional attested | evidenced | verified | accepted |
    adjudicated | settled
  effect_recovery_class: optional replayable | checkpointable | compensatable |
    reconciliation_required | non_retryable
  settlement_terms:
    mode: local_only | optional_anchor | mainnet_required | dispute_only | reputation_only
    settlement_account_ref: optional
    escrow_ref: optional
    dispute_window: optional
  signature:
    scheme: ed25519 | secp256k1 | ml-dsa | hybrid
    public_key_ref: string
    signature: base64
```

```yaml
CapabilityDescriptorEnvelope:
  descriptor_id: artifact://... | ai://...
  domain_id: domain://... | system://... | worker://...
  capabilities: []
  sparse_worker_category_refs: []
  receipt_schema_refs: []
  authority_scope_requirements: []
  runtime_profile_refs: []
  pricing_ref: optional
  reputation_context_refs: []
  signature: optional
```

```yaml
TaskOfferEnvelope:
  offer_id: packet://...
  task_id: task://...
  offered_by: system://... | domain://...
  offered_to: system://... | domain://... | worker://... | service://...
  task_payload_hash: hash
  constraints_ref: optional
  authority_requirements: []
  receipt_obligations: []
  settlement_terms_ref: optional
  expires_at: timestamp
```

```yaml
TaskAcceptanceEnvelope:
  acceptance_id: packet://...
  offer_id: packet://...
  accepted_by: system://... | domain://... | worker://... | service://...
  price_quote_ref: optional
  sla_ref: optional
  authority_requirements: []
  receipt_obligations: []
  settlement_terms_ref: optional
  status: accepted | rejected | counteroffered | expired
```

```yaml
HandoffEnvelope:
  handoff_id: packet://...
  task_id: task://...
  from_domain: system://... | domain://...
  to_domain: system://... | domain://...
  predecessor_receipt_root: optional_hash
  authority_ref: optional grant://...
  handoff_policy_hash: hash
  settlement_intent_ref: optional settlement-intent://...
  status: proposed | accepted | in_progress | completed | rejected | disputed
```

```yaml
ReceiptCommitmentEnvelope:
  receipt_commitment_id: packet://...
  task_id: task://...
  domain_id: system://... | domain://... | worker://...
  receipt_root: hash
  inclusion_proof_ref: optional
  artifact_commitment_refs: []
  policy_hash: hash
  authority_ref: optional grant://...
  disclosure_mode: public_root | private_body | encrypted_body | dispute_gated
```

```yaml
DeliveryUpdateEnvelope:
  delivery_update_id: packet://...
  task_id: task://...
  service_order_ref: optional service://... | order://...
  buyer_domain_ref: system://... | domain://... | wallet://...
  provider_domain_ref: system://... | domain://... | service://...
  delivery_refs: []
  milestone_ref: optional
  status: draft | partial | submitted | accepted | rejected | revision_requested | disputed | cancelled
  artifact_refs: []
  evidence_refs: []
  local_receipt_root: optional_hash
  remote_receipt_root: optional_hash
  disclosure_mode: public_root | private_body | encrypted_body | dispute_gated
  settlement_intent_ref: optional settlement-intent://...
  created_at: timestamp
```

```yaml
AcceptanceDecisionEnvelope:
  acceptance_decision_id: packet://...
  delivery_update_ref: packet://... | delivery_...
  decider_ref: wallet://... | org://... | policy://... | domain://...
  decision: accept | accept_partial | reject | request_revision | open_dispute
  acceptance_criteria_refs: []
  quality_refs: []
  evidence_refs: []
  settlement_intent_ref: optional settlement-intent://...
  dispute_ref: optional dispute://...
  status: drafted | submitted | admitted | challenged | final
```

```yaml
SettlementIntentEnvelope:
  settlement_intent_id: settlement-intent://...
  task_id: task://...
  claimant_ref: system://... | domain://... | worker://... | service://... | wallet://...
  settlement_account_ref: optional
  receipt_condition_refs: []
  payment_terms_ref: optional
  reputation_event_refs: []
  dispute_window: optional
  l1_anchor_policy: local_only | optional_anchor | mainnet_required | dispute_only | reputation_only
  status: drafted | submitted | accepted | challenged | settled | rejected | expired
```

```yaml
DisputeResolutionEnvelope:
  dispute_resolution_id: packet://...
  dispute_ref: dispute://...
  service_order_ref: optional service://... | order://...
  delivery_update_refs: []
  evidence_refs: []
  decision: refund | partial_refund | payout | partial_payout | slash | retry | revise | escalate | no_fault
  settlement_intent_ref: optional settlement-intent://...
  l1_anchor_policy: local_only | optional_anchor | mainnet_required | dispute_only | reputation_only
  status: proposed | accepted | rejected | executed | escalated
```

```yaml
ReputationEventEnvelope:
  reputation_event_id: receipt://...
  subject_ref: system://... | domain://... | worker://... | service://...
  context_ref: benchmark://... | rubric://... | service://... | sparse_category | custom
  event_type: delivery_accepted | delivery_rejected | dispute_opened | dispute_resolved | slash | refund | benchmark_result | reliability_update | routing_quality
  score_commitment: optional_hash
  receipt_ref: receipt://...
  policy_hash: hash
  l1_anchor_ref: optional
```

AIIP envelopes may reference private or encrypted payload bodies. IOI L1 should
anchor only the roots or commitments needed for shared trust, settlement,
reputation, or disputes.

```yaml
MultiPartyCollaborationEnvelope:
  collaboration_id: collaboration://...
  goal_ref: goal://... | task://... | order://... | service://...
  outcome_room_ref: outcome-room://... | null
  coordinator_ref: domain://... | system://... | agent://... | org://...
  coordination_topology:
    hosted_admission | federated_admission
  coordination_and_ordering_policy_ref: policy://...
  shared_state_admission_owner_ref: domain://... | policy://...
  conflict_failover_and_adjudication_policy_refs:
    - policy://...
  party_refs:
    - party_ref: org://... | wallet://... | domain://... | service://... | provider://...
      role: data_owner | worker_provider | compute_provider | coordinator | customer | auditor | regulator | insurer | verifier | settlement_counterparty
      domain_ref: domain://... | system://... | agentgres://domain/... | null
      operator_and_affiliation_refs:
        - org://... | provider://... | wallet://...
      model_runtime_and_infrastructure_dependency_refs:
        - model_route://... | runtime://... | node://... | provider://...
      authority_provider_refs:
        - authority://... | wallet://... | policy://...
      revocation_ref: revocation://... | null
      status: invited | active | suspended | removed | revoked | observer_only
  allowed_shared_refs:
    - artifact://... | receipt://... | evidence://... | view://... |
      restricted_view://... | redacted_summary://... | aiip://channel/... |
      delivery://... | audit_export://...
  blocked_context_classes:
    - raw_secret
    - protected_plaintext
    - unauthorized_connector_payload
    - unrelated_private_memory
    - non_opted_in_training_trace
  policy_bound_data_view_refs:
    - view://...
  restricted_view_refs:
    - restricted_view://...
  aiip_channel_refs:
    - aiip://channel/...
  handoff_refs:
    - packet://...
  authority_refs_by_party:
    - party_ref: org://... | wallet://... | domain://...
      authority_refs:
        - grant://... | authority://... | policy://...
  evidence_bundle_refs:
    - evidence://... | assurance_evidence://...
  delivery_bundle_refs:
    - delivery://...
  contribution_refs:
    - contrib_... | receipt://...
  settlement_intent_refs:
    - settlement-intent://... | settle_...
  audit_export_profile_refs:
    - audit_export://... | policy://...
  l1_anchor_policy:
    local_only | optional_anchor | dispute_only | reputation_only |
    settlement_required | required_public_root
  history_policy:
    party_removal_effect: no_new_access | revoke_live_access | tombstone_view |
      rotate_views
    historical_receipts: immutable | sealed | export_limited
  status:
    proposed | active | blocked | delivery_submitted | accepted |
    revision_requested | disputed | settled | revoked | archived
```

`MultiPartyCollaborationEnvelope` is the policy and proof context for multiple
organizations, domains, workers, providers, auditors, or regulators
collaborating on one autonomous outcome without collapsing ownership,
authority, or privacy boundaries. It is not a shared raw chat context and not a
new global database. It is an admitted context over refs, views, authorities,
AIIP handoffs, delivery state, contribution state, export profiles, and
immutable proof.

Multiplicity is not sufficient for this boundary. Several model routes,
workers, runtime nodes, clouds, or keys controlled by one operator remain one
party when one principal controls authority, revocation, operational truth,
risk, verification, and settlement. A model or cloud provider is normally a
disclosed dependency or subprocessor, not a room party, unless its owning
principal accepts room-level rights, obligations, challenge, evidence, or
settlement roles. `party_refs` and affiliation/dependency refs must make those
relationships visible.

Collaboration history is not rewritten when a party is removed. Revocation
stops future access, rotates or tombstones live views when policy requires it,
and preserves historical receipt roots, contribution refs, and dispute/audit
evidence under the relevant restricted-view and export policies.

```yaml
ServiceModuleManifestEnvelope:
  module_id: module://...
  manifest_ref: ai://...
  module_type: classifier | planner | router | policy | authority | execution_adapter | mutation | verifier | observer | evidence | settlement | projection | upgrade_proposal | other
  version: semver_or_hash
  publisher_id: ioi://publisher/...
  input_schema_ref: cid://... | artifact://...
  output_schema_ref: cid://... | artifact://...
  primitive_capabilities_required: []
  authority_scopes_required: []
  policy_profile_ref: optional
  receipt_obligations: []
  benchmark_profile_refs: []
  upgrade_policy_ref: optional
  status: draft | active | deprecated | revoked
```

```yaml
ModuleInvocationEnvelope:
  invocation_id: invocation://...
  module_id: module://...
  module_version: semver_or_hash
  autonomous_system_chain_id: system://...
  hypervisor_node_id: node://...
  input_hash: hash
  predecessor_state_root: hash
  resulting_state_root: optional_hash
  policy_hash: hash
  authority_grant_refs: []
  receipt_refs: []
  transition_id: optional transition://...
  status: proposed | admitted | executed | verified | committed | rejected | failed
```

```yaml
UpgradeProposalEnvelope:
  proposal_id: proposal://...
  autonomous_system_chain_id: system://...
  target_kind: policy_module | service_module | workflow_graph | contract | tool_binding | model_route | memory_schema | projection_schema | settlement_rule | dispute_rule | authority_envelope
  target_ref: string
  proposed_by: agent://... | worker://... | wallet://... | org://...
  diff_ref: artifact://... | cid://...
  expected_effects_ref: optional
  simulation_receipt_refs: []
  benchmark_receipt_refs: []
  policy_hash: hash
  status: drafted | submitted | approved | rejected | escalated | committed | rolled_back
```

```yaml
UpgradeDecisionEnvelope:
  decision_id: receipt://...
  proposal_id: proposal://...
  decision: approve | reject | escalate | rollback
  decided_by: wallet://... | org://... | policy://... | governance://...
  approval_grant_ref: optional
  policy_hash: hash
  receipt_refs: []
  l1_commitment: optional
```

```yaml
LocalSettlementEnvelope:
  local_settlement_id: transition://...
  hypervisor_node_id: node://...
  autonomous_system_chain_id: optional system://...
  settlement_kind: module_invocation | workflow_transition | authority_outcome | task_handoff | upgrade_decision | receipt_root | dispute_escalation
  operation_ref: agentgres://...
  predecessor_state_root: optional_hash
  resulting_state_root: hash
  receipt_root: hash
  l1_anchor_ref: optional
```

## WorkerInstanceEnvelope

```yaml
WorkerInstanceEnvelope:
  worker_instance_id: agent://...
  worker_id: worker://...
  worker_manifest_ref: ai://...
  install_id: install://...
  owner_id: wallet://... | org://... | project://...
  runtime_assignment_id: optional
  runtime_id: optional
  execution_profile: local | hosted | provider | depin_mutual_blind | tee_enterprise | customer_vpc
  persistence_profile: ephemeral | session | zero_to_idle | persistent
  interaction_surfaces:
    - chat
    - task
    - api
    - workflow_node
    - scheduler
  status: starting | running | idle | recovering | suspended | archived | failed
  memory_policy:
    mode: none | session | agentgres_refs | sealed_archive
    archive_on_idle: boolean
  authority_grant_refs:
    - grant://...
  subscription_ref: optional
  latest_run_id: optional
  latest_state_root: optional
  archive_ref: optional
  created_at: timestamp
  updated_at: timestamp
```

## RuntimeSubscriptionEnvelope

```yaml
RuntimeSubscriptionEnvelope:
  subscription_id: subscription://...
  owner_id: wallet://... | org://...
  worker_instance_id: optional
  runtime_assignment_id: optional
  mode: per_invocation | warm_runtime | managed_monthly
  compute_profile: hosted | provider | depin | tee | customer_vpc | local
  budget_policy_ref: optional
  entitlement_ref: optional
  billing_ref: optional
  status: trial | active | past_due | paused | cancelled
  renews_at: optional
  expires_at: optional
```

## AuthorityScopeRequestEnvelope

```yaml
AuthorityScopeRequestEnvelope:
  authority_request_id: authreq_...
  subject_id: agent://... | worker://... | runtime://...
  issuer_id: wallet://... | org://... | policy://...
  primitive_capabilities_required:
    - prim:model.invoke
    - prim:fs.read
  authority_scopes_requested:
    - scope:gmail.read
    - scope:repo.write
  resource_scope:
    resources:
      - agentgres://project/hypervisor/*
      - file://workspace/src/**
    constraints:
      max_budget_usd: 10
      expiry: 2026-05-01T00:00:00Z
      approval_required_for:
        - external_message
        - commerce
  policy_hash: hash
  request_hash: hash
  authority_grant_id: optional
  status: requested | granted | denied | expired | revoked
```

## AuthorityGrantEnvelope

```yaml
AuthorityGrantEnvelope:
  authority_grant_id: grant_...
  request_id: authreq_...
  issuer_id: wallet://... | org://... | policy://...
  subject_id: agent://... | worker://... | runtime://...
  authority_scopes:
    - scope:gmail.read
    - scope:repo.write
  primitive_capability_constraints:
    - prim:fs.read
    - prim:fs.write
  resources:
    - agentgres://project/hypervisor/*
    - file://workspace/src/**
  constraints:
    max_budget_usd: 10
    expires_at: 2026-05-01T00:00:00Z
    max_calls: optional
    approval_required_for:
      - external_message
      - commerce
  revocation_epoch: integer
  status: active | expired | revoked
```

## AuthorityClientEnvelope

```yaml
AuthorityClientEnvelope:
  authority_client_id: wallet_client://...
  client_kind:
    wallet_web | wallet_mobile | wallet_desktop | hypervisor_panel |
    cli_signer | mcp_server | sdk | enterprise_authority_service |
    browser_origin | local_signer
  owner_ref: wallet://... | org://...
  subject_ref: agent://... | worker://... | runtime://... | service://... | null
  origin_binding:
    origin_ref: origin://... | null
    device_ref: device://... | null
    public_key_ref: key://... | null
    attestation_ref: attestation://... | null
  allowed_operations:
    - request_authority
    - approve_challenge
    - inspect_grants
    - revoke_lease
    - list_receipts
  authority_scope_refs:
    - scope:...
  active_grant_refs:
    - grant://...
  active_lease_refs:
    - lease://...
  gateway_profile_refs:
    - mcp_gateway://...
  connector_refs:
    - connector://...
  session_refs:
    - session://...
  work_run_refs:
    - work_run://...
  risk_ceiling:
    read | draft | low_local_write | external_message | deploy |
    funds | secret_export | policy_widening
  expires_at: timestamp
  last_use_at: timestamp | null
  last_use_ref: event://... | null
  revocation_epoch: integer
  anomaly_state:
    clean | watch | origin_mismatch | expired_use | scope_excess |
    suspicious_frequency | policy_denied | leaked | compromised
  quarantine_advisory_refs:
    - quarantine_advisory://...
  replacement_client_ref: wallet_client://... | null
  status:
    active | expired | suspended | quarantined | rotating | rotated | revoked
```

Authority clients are surfaces and sessions that may request, inspect, approve,
or broker scoped authority. They are not raw secret custodians and cannot widen
authority without a new wallet.network grant. Origin mismatch, expired use,
scope excess, leaked key material, or quarantine must fail closed before any
effectful provider mutation.

## AccessPointBindingEnvelope

```yaml
AccessPointBindingEnvelope:
  binding_id: access_point://...
  owner_ref: wallet://...
  kind: sms | email | chat_app | voice | webhook | browser_session | local_app
  channel_hash: sha256:...
  display_label: optional
  agent_refs:
    - agent://...
  allowed_intents:
    - notify
    - status
    - pause
    - resume
    - request_summary
    - run_preapproved_workflow
    - request_step_up
  risk_ceiling: read | draft | low_local_write
  can_decrypt: false
  can_declassify: false
  can_hold_grant: false
  can_release_secret: false
  step_up_required_for:
    - external_message
    - commerce
    - funds
    - deploy
    - secret_export
    - policy_widening
    - private_workspace_view
    - private_workspace_declassification
  challenge_policy:
    single_use: true
    ttl_seconds: 300
    requires_surface:
      - wallet_network_web
      - hypervisor_app
      - enrolled_guardian_device
      - passkey
      - enterprise_idp
      - local_cli_signer
  expires_at: optional
  revocation_epoch: integer
  status: active | disabled | expired | revoked
```

## StepUpChallengeEnvelope

```yaml
StepUpChallengeEnvelope:
  challenge_id: challenge://...
  binding_id: access_point://...
  owner_ref: wallet://...
  request_hash: sha256:...
  policy_hash: sha256:...
  risk_class: read | draft | local_write | write_reversible |
    external_message | commerce | funds | credential_access |
    policy_widening | secret_export | identity_change |
    system_destructive | physical_action
  action_summary: string
  challenge_url_ref: optional
  single_use: true
  expires_at: timestamp
  status: issued | approved | denied | expired | consumed
  resulting_grant_ref: grant://... | null
  receipt_ref: receipt://... | null
```

Low-assurance access points can carry a `challenge://...` pointer but must not
carry a `grant://...`, decryption key, credential, private workspace payload, or
durable secret.

## TaskEnvelope

```yaml
TaskEnvelope:
  task_id: task_...
  requester_id: wallet://... | agent://... | service://...
  outcome_room_ref: outcome-room://... | null
  frontier_item_ref: frontier://... | null
  work_claim_ref: work-claim://... | null
  objective: string
  task_class: coding | research | workflow | commerce | render | connector | service_delivery | managed_agent | other
  privacy_class: public | internal | confidential | restricted | regulated | safety_critical
  execution_profile: local | hosted | provider | depin_mutual_blind | tee_enterprise | customer_vpc
  input_refs:
    - artifact://...
    - agentgres://object/...
  output_contract:
    type:
      report | patch | artifact | work_result | outcome_delta | finding |
      delivery_bundle | service_result | worker_result
    required_receipts:
      - execution
      - validation
  constraints:
    deadline: optional
    max_budget: optional
    human_approval: optional
  training_spec_ref: optional
  domain_ontology_ref: optional
  data_recipe_refs: []
  policy_bound_data_view_refs: []
  evaluation_dataset_refs: []
  benchmark_profile_ref: optional
  sparse_worker_category: optional
  evaluation_rubric_ref: optional
  contribution_policy_ref: optional
  primitive_capabilities_required:
    - prim:model.invoke
  authority_scopes_required:
    - scope:model.invoke.external
  created_at: timestamp
```

## RunEnvelope

```yaml
RunEnvelope:
  run_id: run_...
  task_id: task_...
  goal_ref: goal://... | null
  outcome_room_ref: outcome-room://... | null
  participant_lease_ref: participant-lease://... | null
  attempt_ref: attempt://... | null
  runtime_id: runtime://...
  worker_id: optional
  worker_instance_id: optional
  service_id: optional
  subscription_ref: optional
  state: queued | assigned | starting | running | sleeping | waiting | throttled | degraded | preempted | awaiting_approval | paused | quarantined | completed | failed | cancelled
  assignment:
    node_id: node://...
    placement_reason: string
    privacy_mode: mutual_blind | enterprise_secure | local | hosted
  event_stream: /v1/runs/{run_id}/events
  artifacts_endpoint: /v1/runs/{run_id}/artifacts
  receipts_endpoint: /v1/runs/{run_id}/receipts
  trace_endpoint: /v1/runs/{run_id}/trace
  inspect_endpoint: /v1/runs/{run_id}/inspect
  scorecard_endpoint: /v1/runs/{run_id}/scorecard
  stop_condition: optional
  resource_allocation_refs:
    - allocation://...
  budget_refs:
    - budget://...
  task_state_ref: optional
  agentgres_projection_watermark: optional
```

## ResourceAllocationDecisionEnvelope

```yaml
ResourceAllocationDecisionEnvelope:
  allocation_decision_id: allocation://...
  allocation_request_ref: allocation://...
  workload_kind:
    session | work_run | automation | scheduled_job | training_pipeline |
    eval | managed_worker | model_route | outcome_room | frontier_claim |
    verification | replication | release_job | connector_job
  workload_refs:
    - session://... | work_run://... | trainpipe://... | worker://... |
      outcome-room://... | frontier://... | work-claim://... | attempt://...
  resource_offer_refs:
    - resource-offer://... | capability-offer://...
  resource_pool_refs:
    - resource_pool://...
  budget_refs:
    - budget://...
  quota_refs:
    - quota://...
  fairness_and_backpressure_policy_refs:
    - policy://...
  priority_class:
    safety_critical | user_blocking | deadline | interactive |
    production | standard | background | speculative
  decision:
    admit | queue | throttle | degrade | preempt | pause | defer |
    cancel | shift_provider | request_budget | fail_closed
  reason_code:
    capacity_available | capacity_exhausted | budget_warning |
    budget_exhausted | quota_exhausted | rate_limited |
    deadline_priority | safety_priority | policy_denied |
    privacy_or_residency_block | provider_unhealthy |
    verified_work_low_value | duplicate_catchup | unfair_share |
    verification_bottleneck | marginal_value_stop
  affected_workload_refs:
    - work_run://... | trainpipe://... | worker://...
  preempted_workload_refs:
    - work_run://...
  preserved_checkpoint_refs:
    - artifact://... | receipt://...
  lost_or_discarded_refs:
    - artifact://...
  retry_or_resume_policy_ref: optional policy://...
  catchup_policy_ref: optional schedule://...
  authority_requirement_refs:
    - authority://... | policy://...
  authority_grant_refs:
    - grant://... | lease://... | authority://...
  cost_delta_ref: optional ledger://...
  expected_verified_work_delta_ref: optional artifact://... | receipt://...
  receipt_refs:
    - receipt://...
  status: proposed | admitted | blocked | executed | superseded | failed
```

## RuntimeEventEnvelope

```yaml
RuntimeEventEnvelope:
  event_id: evt_...
  parent_event_id: optional
  run_id: run_...
  task_id: task_...
  turn_id: optional
  kind: session.started | model.requested | model.completed | tool.proposed | policy.decided | approval.requested | tool.started | tool.completed | artifact.created | ontology.bound | data_recipe.run_started | data_recipe.run_completed | transformation.receipt_emitted | distilled_dataset.bound | evaluation_dataset.bound | ontology_projection.updated | environment.failure_detected | environment.recovery_planned | environment.recovery_started | environment.recovery_completed | environment.recovery_failed | workrun.recovery_reconciled | resource.allocation_requested | resource.allocation_decided | resource.budget_warning | resource.budget_exhausted | resource.preemption_decided | resource.degradation_applied | scheduler.catchup_planned | scheduler.catchup_executed | assurance.policy_pack.applied | assurance.policy_pack.blocked | assurance.audit_export.requested | assurance.audit_export.generated | assurance.audit_export.delivered | assurance.audit_export.revoked | collaboration.context_created | collaboration.party_joined | collaboration.party_removed | collaboration.view_granted | collaboration.view_revoked | collaboration.proof_bundle_generated | orchestration.decision_recorded | training.foundry_spec_admitted | training.dataset_snapshot_materialized | training.run_plan_admitted | training.evidence_eligibility_recorded | training.dataset_factory_started | training.dataset_factory_completed | training.batch_planned | training.generation_batch_archived | training.teacher_session_started | training.teacher_session_completed | training.candidate_data_quarantined | training.on_policy_correction_recorded | training.quality_gates_reported | training.cost_ledger_updated | training.pipeline_started | training.pipeline_stage_advanced | training.pipeline_suspended | training.pipeline_resumed | training.pipeline_completed | training.pipeline_failed | training.trial_started | training.trial_pruned | training.trial_completed | training.checkpoint_created | training.experiment_trial_started | training.experiment_trial_completed | training.experiment_trial_accepted | training.experiment_trial_rejected | training.artifact_conversion_started | training.artifact_conversion_validated | training.model_artifact_frozen | training.package_artifact_validated | training.model_registered | training.registry_version_created | training.route_binding_proposed | training.route_binding_activated | training.promotion_bundle_frozen | training.conductor_advisor_candidate_created | training.conductor_advisor_shadow_started | training.conductor_advisor_promoted | capability.regression_detected | capability.regression_adjudicated | authority_client.* | mcp_gateway.* | revocation.* | embodied.* | sim_to_real.* | assurance.* | capability.* | job.* | receipt.emitted | run.completed | run.failed
  timestamp: timestamp
  actor_id: agent://... | runtime://... | wallet://...
  privacy_class: public | internal | confidential | restricted | regulated | safety_critical
  redaction_status: full | redacted | hash_only
  payload: object
  receipt_ref: optional
  cursor: integer
  terminal: boolean
```

The `kind` line above is a compatibility sample, not the exhaustive event
registry. `outcome_room.*` covers room lifecycle, participant, frontier,
claim, resource, attempt, finding, verifier-challenge, re-verification,
OutcomeDelta, and course-correction events. The exhaustive names and receipt
bindings are owned by
[`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md).

## ReceiptEnvelope

```yaml
ReceiptEnvelope:
  receipt_id: receipt://...
  receipt_type: registered receipt type
  receipt_profile_ref: schema://...
  attested_boundary_fact_refs: []
  claim_scope_ref: schema://... | policy://... | null
  run_id: optional
  task_id: optional
  actor_id: string
  input_hash: optional
  output_hash: optional
  policy_hash: optional
  authority_grant_id: optional
  primitive_capabilities: []
  authority_scopes: []
  artifact_refs: []
  evidence_bundle_refs: []
  verification_ref: verifier_path://... | null
  acceptance_ref: acceptance://... | null
  adjudication_ref: decision://... | dispute://... | null
  settlement_ref: settlement://... | null
  timestamp: timestamp
  signature: optional
  l1_commitment: optional
```

The exhaustive `receipt_type` registry and cross-component field-level schemas
live in the events/receipts owner. This file owns only the portable base
envelope shared by every registered profile. A receipt proves only
its declared bound facts;
the evidence, verification, acceptance, adjudication, and settlement refs above
must not be inferred merely because a receipt exists.

## ArtifactEnvelope

```yaml
ArtifactEnvelope:
  artifact_id: artifact_...
  cid: bafy...
  sha256: hash
  size_bytes: integer
  media_type: string
  privacy_class: public | internal | confidential | restricted | regulated | safety_critical
  encryption:
    mode: none | envelope | threshold | tee_sealed
    key_ref: optional
  provenance:
    run_id: optional
    worker_id: optional
    operation_id: optional
    receipt_id: optional
    ontology_ref: optional
    data_recipe_ref: optional
    transformation_run_id: optional
  access_policy_ref: optional
```

## DeliveryEnvelope

```yaml
DeliveryEnvelope:
  delivery_id: delivery_...
  service_order_id: optional
  buyer_domain_ref: optional system://... | domain://... | wallet://...
  provider_domain_ref: optional system://... | domain://... | service://...
  worker_invocation_id: optional
  run_id: run_...
  delivery_update_refs: []
  output_artifacts: []
  evidence_bundle: []
  local_receipt_root: optional_hash
  remote_receipt_root: optional_hash
  dispute_refs: []
  settlement_intent_refs: []
  disclosure_mode: public_root | private_body | encrypted_body | dispute_gated
  quality_summary: object
  policy_summary: object
  settlement_status: pending | partial | accepted | rejected | revision_requested | disputed | settled | paid | refunded | slashed
  acceptance_deadline: optional
```

## SettlementEnvelope

```yaml
SettlementEnvelope:
  settlement_id: settle_...
  chain_id: ioi-mainnet
  contract: string
  action: escrow_lock | payout_release | partial_payout | refund | partial_refund | slash | service_acceptance | service_revision | license_mint | dispute_open | dispute_resolve | reputation_root_update | handoff_finality
  amount: optional
  token: IOI | stablecoin | credit
  related_delivery_id: optional
  related_settlement_intent_id: optional
  related_dispute_id: optional
  related_receipt_root: optional
  receipt_condition_refs: []
  status: drafted | submitted | pending | settled | disputed | reversed | failed
  tx_hash: optional
```

## ContributionEnvelope

```yaml
ContributionEnvelope:
  contribution_id: contrib_...
  contributor_ref:
    worker://... | service://... | publisher://... | tool://... |
    org://... | domain://...
  contributor_role:
    worker | service | publisher | tool | verifier | reviewer |
    resource_provider | semantic_mapper | organization
  operator_ref: user://... | wallet://... | org://... | domain://... | null
  affiliation_refs: []
  consumer_id: wallet://... | service://... | agent://...
  task_ref: task://... | null
  run_ref: run://... | null
  outcome_room_ref: outcome-room://... | null
  attempt_finding_and_result_refs:
    - attempt://... | finding://... | work-result://... | outcome-delta://...
  contribution_kind:
    planning | execution | generation | worker_invocation | service_delivery |
    tool_use | model_use | dataset_use | workflow_use | resource_provision |
    debugging | review | verification | replication | negative_result |
    integrity_report | semantic_mapping | verifier_hardening | curation |
    synthesis | training_data | distilled_training_data | training_service |
    benchmark_submission | routing_selection | verifier_signal
  usage_hash: hash
  sparse_worker_category: optional
  benchmark_profile_ref: optional
  routing_decision_ref: optional
  attributed_model_and_route_refs:
    - model://... | model_route://... | registry_version://...
  downstream_outcome_ref: optional
  derivation_refs:
    - contrib_... | attempt://... | artifact://... | finding://...
  assurance_stage:
    attested | evidenced | verified | accepted |
    adjudicated | settled
  dispute_status: none | pending | upheld | rejected | no_fault
  quality_delta: optional
  reward_claim: optional
  license_ref: optional
  receipt_ref: receipt://...
```

A model or model route may be attributed as a cognition dependency and
`model_use` contribution kind, but it is not the accountable protocol or
economic actor by itself. `contributor_ref` therefore names the Worker,
service, publisher, tool, organization, or domain boundary that accepted the
contribution obligations; model and route identity remains in
`attributed_model_and_route_refs`.

## DomainOntologyEnvelope

The ontology object family uses one wire/storage base with explicit profiles;
the first-class semantic names are not parallel schemas:

| Semantic object | Canonical envelope profile |
| --- | --- |
| `DomainOntology` | Aggregate lineage addressed by `ontology_family_ref`. |
| `OntologyVersion` | `DomainOntologyEnvelope` with `ontology_record_profile: ontology_version`; every version is immutable after admission. |
| `OntologyOverlay` | `DomainOntologyEnvelope` with `ontology_record_profile: ontology_overlay` and explicit base-version refs. |
| `ProvenanceAssertion` | `OntologyAssertionEnvelope` with `assertion_profile: provenance_assertion`. |
| `OntologyCrosswalk` | `OntologyMappingEnvelope` with `mapping_record_profile: ontology_crosswalk`. |
| `SemanticMappingDecision` | `OntologyMappingEnvelope` with `mapping_record_profile: semantic_mapping_decision`, an applied crosswalk/adapter target, and a decision receipt. |

Agentgres registers the semantic object/profile names while persisting the
corresponding base envelope. Implementations must not create separate,
incompatible `OntologyVersion`, `OntologyOverlay`, `OntologyCrosswalk`,
`SemanticMappingDecision`, or `ProvenanceAssertion` schemas.

```yaml
DomainOntologyEnvelope:
  ontology_id: ontology://...
  ontology_family_ref: ontology://...
  ontology_record_profile: ontology_version | ontology_overlay
  namespace: uri_or_domain_scoped_name
  name: string
  domain_ref: agentgres://domain/... | service://... | org://...
  version: semver_or_hash
  predecessor_version_ref: ontology://... | null
  base_ontology_version_refs:
    - ontology://...
  local_canonicality_scope_ref: domain://... | org://... | project://...
  extension_and_overlay_refs:
    - ontology://... | policy://...
  compatibility_profile_ref: compatibility://... | null
  deprecation_policy_ref: policy://... | null
  entity_types: []
  relationship_types: []
  event_types: []
  action_types: []
  state_machines: []
  invariant_refs: []
  owner_id: wallet://... | org://... | service://...
  policy_hash: hash
  status: draft | active | deprecated | revoked
```

No Domain Ontology is presumed globally canonical. A domain may make one
version locally canonical while other domains retain independent definitions,
extensions, overlays, and policy-bound views. Cross-domain work must negotiate
versioned profiles and explicit mappings rather than silently flattening them
into one enterprise or network graph.

## OntologyAssertionEnvelope

Operational truth and semantic belief are distinct. Agentgres may canonically
record that a domain admitted an assertion or decision; that admission does not
make the proposition universally true. Ontology-bound properties and
relationships therefore carry time, source, uncertainty, evidence,
applicability, supersession, and dispute state.

```yaml
OntologyAssertionEnvelope:
  assertion_id: ontology-assertion://...
  assertion_profile: provenance_assertion
  ontology_ref: ontology://...
  subject_ref: object://... | ontology-assertion://...
  predicate_ref: ontology://...#property_or_relationship
  object_or_value_ref: object://... | scalar | artifact://...
  valid_time: interval | null
  transaction_time: timestamp
  source_and_observation_context_refs:
    - source://... | observation://... | attempt://... | domain://...
  confidence_or_uncertainty: number | null
  supporting_evidence_refs:
    - evidence://... | receipt://... | artifact://...
  contradicting_assertion_refs:
    - ontology-assertion://... | finding://...
  applicability_scope_ref: policy://... | domain://... | null
  causal_or_counterfactual_context_ref: artifact://... | finding://... | null
  supersedes_ref: ontology-assertion://... | null
  dispute_ref: dispute://... | null
  admission_receipt_ref: receipt://... | null
  status: proposed | admitted | contradicted | superseded | disputed | rejected
```

## OntologyMappingEnvelope

```yaml
OntologyMappingEnvelope:
  ontology_mapping_id: ontology-mapping://...
  mapping_record_profile: ontology_crosswalk | semantic_mapping_decision
  source_ontology_ref: ontology://...
  target_ontology_ref: ontology://...
  source_and_target_version_refs:
    - ontology://...
  mapping_profile_ref: artifact://... | mapping://...
  applied_crosswalk_ref: ontology-mapping://... | null
  application_target_refs:
    - packet://... | handoff://... | object://... | query://... |
      ontology-action://... | artifact://...
  mapped_object_relationship_event_and_action_refs:
    - object-model://... | ontology-action://... | schema://...
  compatibility_result:
    exact | compatible | lossy | requires_adapter | incompatible
  policy_bound_view_refs:
    - view://... | restricted_view://...
  validation_and_challenge_refs:
    - test://... | verifier-challenge://... | evidence://...
  decided_by_ref: worker://... | org://... | domain://... | policy://... | null
  decision_timestamp: timestamp | null
  mapping_decision_receipt_ref: receipt://... | null
  deprecation_and_migration_policy_ref: policy://... | null
  status: proposed | validated | active | challenged | deprecated | revoked
```

## OntologyActionContractEnvelope

An ontology action becomes executable only through a contract that binds
semantic meaning to capability, runtime, authority, effects, compensation,
evidence, and verification. An action name or connector method alone is not an
execution contract.

```yaml
OntologyActionContractEnvelope:
  ontology_action_id: ontology-action://...
  ontology_ref: ontology://...
  action_type_ref: ontology://...#action
  target_object_model_refs:
    - object-model://...
  typed_input_schema_ref: schema://... | artifact://...
  typed_output_schema_ref: schema://... | artifact://...
  precondition_refs:
    - policy://... | invariant://... | state://...
  postcondition_and_invariant_refs:
    - policy://... | invariant://... | state://...
  expected_state_transition_ref: transition://... | state-delta://...
  capability_runtime_tool_and_automation_refs:
    - prim:... | runtime://... | tool://... | automation://...
  risk_class: read | draft | local_write | write_reversible |
    external_message | commerce | funds | credential_access |
    policy_widening | secret_export | identity_change |
    system_destructive | physical_action
  local_policy_and_authority_scope_refs:
    - policy://... | scope:... | grant://...
  approval_and_revocation_refs:
    - approval-policy://... | revocation://...
  preview_and_dry_run_profile_ref: policy://... | null
  idempotency_and_retry_profile_ref: policy://...
  ambiguous_effect_and_reconciliation_profile_ref: policy://...
  compensation_profile_ref: policy://... | null
  verifier_and_evidence_refs:
    - verifier_path://... | evidence://... | schema://...
  physical_safety_profile_ref: safety://... | null
  status: draft | validating | active | deprecated | revoked
```

## CanonicalObjectModelEnvelope

```yaml
CanonicalObjectModelEnvelope:
  object_model_id: object-model://...
  ontology_ref: ontology://...
  object_type: string
  id_strategy: deterministic | assigned | provider_mapped
  schema_ref: artifact://... | cid://... | inline
  lifecycle_states: []
  constraints:
    - constraint://...
  privacy_class: public | internal | confidential | restricted | regulated | safety_critical
  authority_scopes_required: []
  projection_hints: []
  status: draft | active | deprecated
```

## DataRecipeEnvelope

```yaml
DataRecipeEnvelope:
  data_recipe_id: recipe://...
  ontology_refs:
    - ontology://...
  input_source_types:
    - connector
    - document
    - trace
    - dataset
    - artifact
  connector_mapping_refs:
    - mapping://...
  output_object_model_refs:
    - object-model://...
  output_dataset_refs:
    - dataset://...
  output_distilled_dataset_refs:
    - dataset://...
  transformation_steps:
    - extract
    - redact
    - normalize
    - dedupe
    - validate
    - map
    - link
    - export
  policy_bound_data_view_refs:
    - view://...
  receipt_obligations:
    - data_recipe_run
    - transformation
  status: draft | active | deprecated
```

## ConnectorMappingEnvelope

```yaml
ConnectorMappingEnvelope:
  connector_mapping_id: mapping://...
  connector_id: connector://...
  ontology_ref: ontology://...
  source_schema_ref: artifact://... | cid://... | provider_schema
  target_object_model_refs:
    - object-model://...
  field_mappings: []
  action_mappings: []
  authority_scopes_required: []
  redaction_policy_ref: optional
  evidence_required: []
  status: draft | active | deprecated
```

## PolicyBoundDataViewEnvelope

```yaml
PolicyBoundDataViewEnvelope:
  view_id: view://...
  domain_id: agentgres://domain/...
  ontology_refs:
    - ontology://...
  object_model_refs:
    - object-model://...
  source_refs: []
  allowed_uses:
    - read
    - transform
    - distill
    - train
    - evaluate
    - export
    - publish
    - route
  authority_grant_refs:
    - grant://...
  retention_policy_ref: optional
  privacy_class: public | internal | confidential | restricted | regulated | safety_critical
  policy_hash: hash
  expires_at: optional
```

## TransformationRunEnvelope

```yaml
TransformationRunEnvelope:
  transformation_run_id: transform://...
  data_recipe_ref: recipe://...
  ontology_refs:
    - ontology://...
  input_refs:
    - artifact://...
    - connector://...
    - agentgres://object/...
  output_object_refs:
    - agentgres://object/...
  output_dataset_refs:
    - dataset://...
  output_distilled_dataset_refs:
    - dataset://...
  output_artifact_refs:
    - artifact://...
  policy_bound_data_view_refs:
    - view://...
  authority_grant_refs:
    - grant://...
  receipt_refs:
    - receipt://...
  status: queued | running | completed | failed | rejected
```

## DistilledOntologyDatasetEnvelope

```yaml
DistilledOntologyDatasetEnvelope:
  distilled_dataset_id: dataset://...
  ontology_refs:
    - ontology://...
  data_recipe_refs:
    - recipe://...
  source_commitments:
    - hash
  policy_bound_data_view_refs:
    - view://...
  transformation_receipt_refs:
    - receipt://...
  distillation_methods:
    - teacher_distillation
    - verifier_filtering
    - rubric_judgment
    - tool_trace_extraction
    - counterexample_generation
    - failure_regression
    - schema_canonicalization
  teacher_refs:
    - worker://...
  verifier_refs:
    - worker://...
  output_artifact_refs:
    - artifact://...
  evaluation_dataset_refs:
    - dataset://...
  benchmark_profile_refs:
    - benchmark://...
  receipt_root: hash
  status: draft | active | deprecated | revoked
```

## EvaluationDatasetEnvelope

```yaml
EvaluationDatasetEnvelope:
  evaluation_dataset_id: dataset://...
  ontology_refs:
    - ontology://...
  data_recipe_refs:
    - recipe://...
  dataset_type: golden | holdout | adversarial | regression | benchmark | synthetic | distilled
  rubric_ref: rubric://...
  benchmark_profile_ref: optional
  source_commitment: hash
  privacy_policy_ref: optional
  artifact_refs:
    - artifact://...
  receipt_root: hash
  status: draft | active | deprecated | revoked
```

## TrainingEvidenceEligibilityEnvelope

Training evidence eligibility is the pre-training local governance,
admission, consent, and privacy classification record. It is where sensitive
traces, connector outputs, enterprise documents, feedback, receipts, or
artifacts are explicitly admitted or excluded before Foundry can produce
datasets, evals, model candidates, or conductor-advisor candidates.

This is not a wallet.network object by default. Hypervisor, Foundry, Data /
Knowledge, Ontology, domain apps, or org governance surfaces may propose the
eligibility decision; Agentgres records the admitted decision and receipts;
wallet.network supplies authority refs only when the decision requires
delegated machine power such as decryption, connector access, model-provider
keys, GPU spend, provider-trust acceptance, publication, export, or
cross-domain reuse.

```yaml
TrainingEvidenceEligibilityEnvelope:
  eligibility_id: eligibility://...
  governance_owner_ref: org://... | project://... | agentgres://domain/... | foundry_job://...
  subject_refs:
    - artifact://... | receipt://... | dataset://... | view://... | connector://...
  requester_ref: wallet://... | org://... | foundry_job://... | goal://...
  intended_use:
    conductor_training | worker_training | eval_generation |
    dataset_distillation | benchmark | simulation | analytics_only
  training_data_posture:
    never_train | synthetic_only | redacted_opt_in | full_private_opt_in | org_policy
  policy_bound_data_view_refs:
    - view://...
  data_recipe_refs:
    - recipe://...
  local_policy_refs:
    - policy://...
  consent_refs:
    - grant://... | policy://... | authority://...
  wallet_authority_refs:
    - grant://... | lease://... | authority://...
  authority_requirement_kinds:
    - decryption | connector_access | model_provider_key | gpu_spend |
      provider_trust | publication | export | cross_domain_reuse | none
  declassification_refs:
    - receipt://... | policy://...
  provider_trust_posture:
    no_provider_plaintext | redacted_api | provider_trust_accepted |
    private_compute_required | blocked
  retention_policy_ref: policy://...
  exclusion_reason:
    optional never_train_default | revoked | expired | regulated_block |
    connector_scope_denied | no_provider_trust | data_subject_request |
    missing_policy_bound_view | incident_hold
  receipt_root: hash
  admitted_by_ref: optional agentgres://operation/... | policy://...
  status: proposed | eligible | excluded | revoked | expired | superseded
```

## OntologyProjectionEnvelope

```yaml
OntologyProjectionEnvelope:
  ontology_projection_id: projection://...
  agentgres_projection_id: projection://...
  ontology_refs:
    - ontology://...
  object_model_refs:
    - object-model://...
  data_recipe_refs:
    - recipe://...
  policy_bound_data_view_ref: optional
  freshness_watermark: domain_seq:...
  checkpoint_ref: optional
  status: building | active | stale | rebuilding | deprecated
```

## OntologyToWorkerPlanEnvelope

```yaml
OntologyToWorkerPlanEnvelope:
  plan_id: plan://...
  ontology_refs:
    - ontology://...
  canonical_object_model_refs:
    - object-model://...
  data_recipe_refs:
    - recipe://...
  workflow_schema_refs: []
  policy_bound_data_view_refs:
    - view://...
  evaluation_dataset_refs:
    - dataset://...
  distilled_dataset_refs:
    - dataset://...
  benchmark_profile_refs:
    - benchmark://...
  proposed_worker_manifest_ref: optional
  worker_training_ref: optional
  status: draft | proposed | training | evaluated | bound | rejected
```

## OntologyDevelopmentKitManifestEnvelope

An Ontology Development Kit manifest packages the semantic contracts and builder
expectations needed to generate or validate object-aware surfaces, domain apps,
eval packs, worker packages, and marketplace-ready ontology packs. It is a
builder/conformance object, not semantic truth, runtime truth, permission truth,
or marketplace truth.

```yaml
OntologyDevelopmentKitManifestEnvelope:
  odk_manifest_id: odk://...
  name: string
  version: semver_or_hash
  ontology_refs:
    - ontology://...
  canonical_object_model_refs:
    - object-model://...
  data_recipe_refs:
    - recipe://...
  connector_mapping_refs:
    - mapping://...
  policy_bound_data_view_refs:
    - view://...
  ontology_projection_refs:
    - projection://...
  surface_descriptor_refs:
    - surface-descriptor://...
  workflow_schema_refs: []
  evaluation_dataset_refs:
    - dataset://...
  benchmark_profile_refs:
    - benchmark://...
  worker_plan_refs:
    - plan://...
  operator_contract_refs:
    - contract://...
  mcp_contract_refs:
    - mcp-profile://...
  conformance_profile_refs:
    - profile://...
  package_refs:
    - artifact://...
  receipt_obligations:
    - validation
    - artifact
    - data_recipe_run
    - transformation
    - evaluation_verdict
  status: draft | active | deprecated | revoked
```

## OntologySurfaceDescriptorEnvelope

An ontology surface descriptor declares how a UI, domain app, operator console,
or generated surface binds to ontology objects, projections, daemon contracts,
policy-bound views, and receipts. It can be authored by humans, generated by the
ODK, or emitted by an application builder, but it remains a descriptor over the
owning domains.

```yaml
OntologySurfaceDescriptorEnvelope:
  surface_descriptor_id: surface-descriptor://...
  surface_ref: surface://...
  display_name: string
  ontology_refs:
    - ontology://...
  canonical_object_model_refs:
    - object-model://...
  data_recipe_refs:
    - recipe://...
  connector_mapping_refs:
    - mapping://...
  policy_bound_data_view_refs:
    - view://...
  ontology_projection_refs:
    - projection://...
  composition_pattern:
    list_detail | object_view | object_editor | graph |
    wizard | review_inbox | monitoring_console | dashboard |
    data_recipe_builder | connector_mapping_editor | domain_app
  allowed_action_refs:
    - action://...
  daemon_api_refs:
    - api://...
  operator_contract_refs:
    - contract://...
  mcp_contract_refs:
    - mcp-profile://...
  authority_requirement_refs:
    - scope:* | policy://... | grant://...
  receipt_obligations:
    - receipt://...
  conformance_profile_refs:
    - profile://...
  generated_artifact_refs:
    - artifact://...
  status: draft | active | deprecated | revoked
```

## ModelCapacityProfileEnvelope

```yaml
ModelCapacityProfileEnvelope:
  model_capacity_profile_id: profile://...
  training_id: optional
  target_worker_id: optional
  target_class: small_local | balanced_local | specialist_local | hosted_frontier | hybrid_worker | deterministic_worker | custom
  parameter_range: optional
  context_budget_tokens: optional
  system_prompt_budget_tokens: optional
  tool_batch_limit: optional
  row_structure: freeform | structured | ontology_bound | tool_trace | mixed
  label_space_ref: optional
  latency_target: optional
  cost_target: optional
  privacy_posture: local | hosted | private_runtime | regulated
  recommendations:
    - structured_rows
    - shorter_system_prompt
    - tighter_label_set
    - smaller_tool_batches
    - stronger_gold_reasons
    - more_eval_coverage
  status: draft | active | superseded
```

## ModelDeploymentProfileEnvelope

Model deployment profiles describe how cognition backends are supplied to a
node or runtime. The router and invocation contract live in the node/runtime;
model weights and endpoints are profile resources.

```yaml
ModelDeploymentProfileEnvelope:
  model_deployment_profile_id: profile://...
  owner_id: wallet://... | org://... | project://...
  mount_mode: bundled_weights | local_file | local_server | external_api | hosted_pool | tee_session | depin_session | customer_vpc
  weight_custody_profile_id: model_weight_custody://...
  model_artifact_refs:
    - cid://... | artifact://... | file://...
  endpoint_refs:
    - endpoint://...
  provider_refs: []
  authority_scope_requirements:
    - scope:model.invoke.external
  execution_privacy_posture: local | external_api | tenant_private | tee_private | regulated
  run_to_idle_policy_ref: optional
  receipt_mode: hash_only | full_redacted | full_private
  status: draft | active | unavailable | revoked
```

Bundled local weights are valid for offline, demo, small sovereign, or
deployment-specific profiles. They are not the architecture default.

## ModelWeightCustodyProfileEnvelope

Model weight custody is tracked separately from workspace privacy. This avoids
the common mistake of treating cTEE/private-workspace custody as protection for
proprietary weights mounted on a root-owned rented GPU.

```yaml
ModelWeightCustodyProfileEnvelope:
  profile_id: model_weight_custody://...
  weight_class: public_open_weight | user_local_private_weight | remote_api_private_weight | provider_trust_remote_mount | tee_or_customer_cloud_mount | forbidden_plaintext_mount
  weight_owner: user | org | provider | public | marketplace_package
  mount_target: local_device | user_owned_node | rented_gpu | customer_cloud | provider_api | tee_session | none
  remote_provider_can_read_weights: true | false
  required_controls:
    - wallet_authorized_api_capability
    - local_only
    - customer_account_boundary
    - tee_attestation
    - no_remote_plaintext_mount
    - explicit_provider_trust_acceptance
  receipt_refs:
    - receipt://...
  status: proposed | accepted | blocked | revoked
```

## FoundrySpecEnvelope

The Foundry spec is the declarative source of truth for a durable training,
evaluation, packaging, or route-promotion lifecycle. Notebooks, chats, and code
workspaces may author it, but they are not the system of record.

```yaml
FoundrySpecEnvelope:
  foundry_spec_id: foundry_spec://...
  foundry_job_ref: optional foundry_job://...
  objective: string
  task_family: string
  base_model_refs:
    - model://...
  training_mode:
    sft | adapter | full_finetune | distillation |
    preference_optimization | on_policy_correction | eval_only |
    packaging_only | route_policy_training | conductor_advisor_training
  training_stack_ref: optional training_stack://...
  trainer_backend_profile_refs:
    - trainer_backend://...
  reasoning_mode_policy_ref: optional reasoning_policy://...
  verifier_environment_set_refs:
    - verifier_set://... | interactive_world://... | gate://...
  dataset_snapshot_refs:
    - dataset_snapshot://... | dataset://...
  search_space_ref: optional artifact://... | policy://...
  packaging_targets:
    - adapter_merge | quantization | gguf | mlx | onnx | tensorrt |
      runtime_image | endpoint_package | model_card | custom
  budget_policy_ref: budget://... | policy://...
  eval_policy_ref: gate://... | policy://...
  target_route_ref: optional model_route://...
  version: integer
  created_by_ref: wallet://... | org://... | service://...
  status: draft | ready | superseded | archived
```

## DatasetSnapshotEnvelope

Dataset factories define how data is produced; dataset snapshots are immutable
materializations used for training, evaluation, regression, and promotion
replay.

```yaml
DatasetSnapshotEnvelope:
  dataset_snapshot_id: dataset_snapshot://...
  dataset_factory_ref: foundry_job://... | recipe://...
  dataset_refs:
    - dataset://...
  content_manifest_ref: artifact://...
  split_manifest_ref: artifact://...
  source_version_refs:
    - artifact://... | connector://... | view://... | receipt://...
  slice_definitions_ref: optional artifact://...
  filtering_rules_ref: optional policy://... | artifact://...
  retention_policy_ref: policy://...
  lineage_refs:
    - receipt://... | transform://...
  snapshot_hash: hash
  status: materialized | retained | deprecated | revoked
```

## FoundryRunPlanEnvelope

Run plans turn a spec and snapshots into a typed stage graph with explicit
executor bindings, artifact contracts, retry policy, and checkpoint policy.

```yaml
FoundryRunPlanEnvelope:
  run_plan_id: run_plan://...
  foundry_spec_ref: foundry_spec://...
  stage_graph_ref: artifact://...
  stages:
    - data_prep
    - dataset_factory
    - teacher_distillation
    - training
    - reasoning_mode_fusion
    - environment_feedback_rl
    - checkpointing
    - eval
    - packaging
    - artifact_conversion
    - registration
    - route_promotion
  executor_bindings:
    - runtime://... | compute://... | service://...
  retry_policy_ref: policy://...
  checkpoint_policy_ref: policy://...
  timeout_policy_ref: policy://...
  artifact_contract_refs:
    - schema://...
  status: draft | admitted | running | completed | superseded
```

## FoundryTrialEnvelope

Trials are the unit of search, pruning, early stopping, comparison, and
optimizer attribution.

```yaml
FoundryTrialEnvelope:
  trial_id: trial://...
  run_plan_ref: run_plan://...
  training_pipeline_ref: optional trainpipe://...
  optimization_cycle_ref: optional optcycle://...
  parameter_values_ref: artifact://...
  objective_metric_refs:
    - gate://... | artifact://...
  scheduler_state_ref: optional artifact://...
  checkpoint_refs:
    - checkpoint://... | artifact://...
  cost_ledger_ref: ledger://...
  status: queued | running | pruned | completed | failed | selected | rejected
```

## FoundryCheckpointArtifactEnvelope

Checkpoints are resumable state, not just files.

```yaml
FoundryCheckpointArtifactEnvelope:
  checkpoint_id: checkpoint://...
  trial_ref: optional trial://...
  training_pipeline_ref: trainpipe://...
  checkpoint_artifact_ref: artifact://...
  global_step: optional integer
  token_count: optional integer
  optimizer_state_ref: optional artifact://...
  resume_compatibility_ref: optional schema://... | artifact://...
  status: created | retained | resume_candidate | deprecated | revoked
```

## FoundryModelAndPackageArtifactEnvelope

Training-native model artifacts and deployable package artifacts are distinct
lineage nodes. Packaging may merge adapters, quantize, export, build runtime
images, or create endpoint packages, but it must not overwrite the source
artifact.

```yaml
FoundryModelArtifactEnvelope:
  model_artifact_id: model_artifact://...
  source_checkpoint_ref: checkpoint://... | artifact://...
  artifact_ref: artifact://...
  artifact_kind:
    checkpoint | adapter | merged_model | safetensors | pytorch |
    trainer_native | verifier_model | route_policy | conductor_advisor
  architecture_ref: optional profile://... | artifact://...
  precision: optional string
  signature_ref: optional schema://...
  metrics_ref: optional gate://... | artifact://...
  status: frozen | evaluated | deprecated | revoked

FoundryPackageArtifactEnvelope:
  package_artifact_id: package_artifact://...
  source_model_artifact_ref: model_artifact://... | artifact://...
  target_runtime:
    local_model_mount | hosted_endpoint | ctee_mount | mobile |
    browser | robot_runtime | batch_inference | custom
  format:
    adapter_merge | quantization | gguf | mlx | onnx | tensorrt |
    runtime_image | endpoint_package | model_card | custom
  output_artifact_refs:
    - artifact://...
  build_log_ref: artifact://...
  compatibility_ref: optional schema://... | conformance_profile://...
  validation_refs:
    - gate://... | receipt://...
  status: built | validated | registered | failed | revoked
```

## FoundryRegistryVersionAndRouteBindingEnvelope

Promotion updates route indirection. It does not mutate old artifacts in place.

```yaml
FoundryRegistryVersionEnvelope:
  registry_version_id: registry_version://...
  registry_model_ref: model://... | worker://... | package://...
  artifact_ref: model_artifact://... | package_artifact://... | artifact://...
  scorecard_ref: gate://... | artifact://...
  lineage_refs:
    - foundry_spec://... | dataset_snapshot://... | trainpipe://... |
      receipt://...
  aliases:
    - champion
    - candidate
    - shadow
    - canary
  approval_status:
    draft | pending | approved | rejected | deprecated | revoked
  model_card_ref: optional artifact://...

FoundryRouteBindingEnvelope:
  route_binding_id: promotion_record://...
  route_ref: model_route://...
  registry_version_ref: registry_version://...
  alias: champion | candidate | shadow | canary | rollback
  traffic_split: optional object
  canary_policy_ref: optional policy://...
  rollback_target_ref: registry_version://... | model://... | package://...
  decision_evidence_refs:
    - gate://... | artifact://... | receipt://...
  status: proposed | active | paused | rolled_back | recalled | superseded
```

## Physical Mission Segment Envelopes

`PhysicalMissionControlEnvelope` registers the slow-plane mission envelope that
binds fleet/units, allowed actions, zones/limits, validity, authority,
safety/e-stop, controller versions, evidence, exceptions, and revocation.
`LocalControlSegmentEnvelope` registers the embodied-runtime record for one
bounded interval of certified local controller execution at
`control-segment://...`. The corresponding
`PhysicalActionSegmentCommitmentReceipt` binds that interval to mission intent,
controller/version, policy, safety envelope, command and sensor roots, state
refs, exception/e-stop receipts, and the declared result. It is a receipt type,
not a second common envelope. Mission and local-segment records are owned by
[`embodied-runtime.md`](../components/daemon-runtime/embodied-runtime.md),
physical-action obligations are owned by
[`physical-action-safety.md`](./physical-action-safety.md), and the sole receipt
schema is owned by
[`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md).

These objects implement the two-speed boundary: Goal Kernel and remote
governance operate at mission/checkpoint/exception/course-correction
timescales, while the certified local controller owns the high-frequency loop,
local e-stop, and fail-safe behavior inside a bounded mission envelope.

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
  receipt_refs:
    - receipt://...
  status: draft | materialized | retained | deprecated | revoked
```

## EmbodiedCapabilityPackageEnvelope

The embodied capability package is the center of the embodied architecture.
Foundry builds it, Hypervisor Daemon executes it, Physical Action Safety
constrains it, wallet.network authorizes mission scope where delegated power is
required, and Agentgres records state, receipts, and replay.

```yaml
EmbodiedCapabilityPackageEnvelope:
  package_ref: package://...
  foundry_job_ref: foundry_job://...
  capability_spec_ref: capability_spec://...
  robot_embodiment_refs:
    - embodiment://...
  embodiment_adapter_refs:
    - embodiment_adapter://...
  sensor_contract_ref: sensor_contract://...
  action_schema_ref: action_schema://...
  world_contract_ref: world_contract://...
  world_representation_refs:
    - world_representation://... | artifact://...
  raw_robot_log_refs:
    - robot_log://... | artifact://...
  episode_dataset_refs:
    - episode_dataset://... | dataset_snapshot://...
  teacher_label_set_refs:
    - teacher_label_set://...
  perception_model_refs:
    - model://...
  action_policy_refs:
    - model://... | worker://... | artifact://...
  success_detector_refs:
    - success_detector://... | model://... | worker://...
  runtime_adapter_ref: worker://...
  calibration_refs:
    - calibration://...
  time_sync_contract_ref: time_sync://...
  physical_action_safety_envelope_ref: policy://... | safety://...
  human_supervision_policy_ref: supervision://...
  emergency_stop_authority_ref: estop://...
  eval_report_refs:
    - eval_report://... | artifact://... | gate://...
  sim_to_real_report_ref: eval_report://... | artifact://...
  promotion_record_refs:
    - promotion_record://...
  receipt_root: hash
  status: draft | evaluated | packaged | proposed | promoted | recalled | revoked
```

## FoundryEmbodiedRuntimeCandidateEnvelope

An embodied runtime candidate is a proposal to bind an embodied capability
package to a target runtime and physical domain. It is not live actuator
authority.

```yaml
FoundryEmbodiedRuntimeCandidateEnvelope:
  candidate_id: embodied_candidate://...
  source_training_pipeline_ref: trainpipe://...
  embodied_capability_package_ref: package://...
  intended_runtime:
    hypervisor_daemon | partner_robot_runtime | simulator_only
  target_domain_ref: embodied_domain://...
  target_fleet_ref: robot_fleet://...
  sensor_contract_ref: sensor_contract://...
  action_schema_ref: action_schema://...
  world_contract_ref: world_contract://...
  runtime_adapter_ref: worker://...
  safety_envelope_ref: safety://...
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

## TrainingBatchPlanEnvelope

```yaml
TrainingBatchPlanEnvelope:
  batch_plan_id: batch://...
  training_id: train_...
  orchestrator_ref: worker://... | runtime://... | agent://...
  target_scope: string
  target_family: optional
  label_boundary_ref: optional
  hard_eval_pattern_ref: optional
  quota:
    target_rows: integer
    target_tokens: optional
    max_cost: optional
  split_policy:
    train: percentage
    holdout: percentage
    golden: percentage
    adversarial: percentage
    regression: percentage
  model_capacity_profile_ref: optional
  teacher_session_refs:
    - teacher_session://...
  candidate_data_quarantine_policy_ref: optional policy://...
  executor_worker_refs:
    - worker://...
  prompt_artifact_refs:
    - artifact://...
  acceptance_thresholds: object
  receipt_refs:
    - receipt://...
  status: draft | running | completed | rejected | superseded
```

## GenerationBatchEnvelope

```yaml
GenerationBatchEnvelope:
  generation_batch_id: batch://...
  batch_plan_ref: batch://...
  training_id: train_...
  executor_ref: worker://... | model://... | runtime://...
  provider_model_ref: optional
  input_prompt_ref: artifact://... | cid://...
  raw_batch_archive_ref: artifact://...
  row_count: integer
  token_count: optional
  provider_call_count: optional
  cost_estimate: optional
  started_at: timestamp
  completed_at: optional
  status: queued | running | archived | gated | rejected | failed
```

## TeacherSessionEnvelope

Teacher sessions record foundation-model, worker, verifier, or human-review
interactions used to generate candidate supervision. They produce candidate
training signal, not accepted truth.

```yaml
TeacherSessionEnvelope:
  teacher_session_id: teacher_session://...
  foundry_job_ref: foundry_job://...
  task_contract_ref: schema://... | artifact://...
  session_mode:
    generate | critique | debate | revise | label | judge |
    student_rollout_correction | route_policy_supervision
  teacher_refs:
    - model://... | worker://... | agent://...
  student_candidate_ref: optional model://... | worker://... | conductor://...
  prompt_artifact_refs:
    - artifact://...
  tool_contract_refs:
    - tool://... | mcp://...
  evidence_refs:
    - artifact://... | receipt://... | view://...
  output_candidate_data_refs:
    - candidate_data://...
  privacy_policy_ref: policy://...
  cost_ledger_ref: ledger://...
  receipt_refs:
    - receipt://...
  status:
    planned | running | completed | quarantined | rejected | superseded
```

## CandidateTrainingSignalEnvelope

Candidate training signal is quarantined by default. It may become an accepted
dataset row only after privacy, provenance, quality, and truth gates pass.

```yaml
CandidateTrainingSignalEnvelope:
  candidate_data_id: candidate_data://...
  teacher_session_ref: teacher_session://...
  training_id: optional train_...
  record_family:
    instruction | demonstration | chosen_rejected_preference |
    binary_preference | critique_revision | tool_trace |
    agent_trajectory | verifier_label | process_label |
    route_orchestration_trace | on_policy_correction
  source_teacher_refs:
    - model://... | worker://... | agent://...
  prompt_template_ref: optional artifact://...
  environment_ref: optional runtime://... | compute://...
  evidence_refs:
    - artifact://... | receipt://... | view://...
  verifier_refs:
    - worker://... | model://... | gate://...
  privacy_status_ref: eligibility://... | policy://...
  quality_gate_refs:
    - gate://...
  accepted_dataset_refs:
    - dataset://...
  status:
    quarantined | eligible | accepted | rejected | held_for_review |
    redacted | superseded
```

## RawBatchArchiveEnvelope

```yaml
RawBatchArchiveEnvelope:
  raw_batch_archive_id: artifact://...
  training_id: train_...
  generation_batch_refs:
    - batch://...
  raw_artifact_refs:
    - artifact://...
  candidate_data_refs:
    - candidate_data://...
  cache_artifact_refs:
    - artifact://...
  provider_metadata_hash: optional
  prompt_hash: optional
  token_count: optional
  cost_estimate: optional
  policy_hash: hash
  status: archived | redacted | rejected | promoted_to_curation
```

## QualityGateReportEnvelope

```yaml
QualityGateReportEnvelope:
  gate_report_id: gate://...
  training_id: train_...
  batch_plan_ref: optional
  generation_batch_ref: optional
  gate_policy_hash: hash
  gate_results:
    schema_validity: pass | fail | skipped
    role_order: pass | fail | skipped
    final_user_turn: pass | fail | skipped
    allowed_labels: pass | fail | skipped
    canonical_order: pass | fail | skipped
    duplicate_prompt: pass | fail | skipped
    placeholder_or_meta_text: pass | fail | skipped
    target_scope_signal: pass | fail | skipped
    helper_scope_policy: pass | fail | skipped
    unsupported_primary_policy: pass | fail | skipped
    split_intent: pass | fail | skipped
    leakage_risk: pass | fail | skipped
    source_teacher_provenance: pass | fail | skipped
    candidate_data_quarantine: pass | fail | skipped
    execution_truth_gate: pass | fail | skipped
    retrieval_evidence_support: pass | fail | skipped
    verifier_agreement: pass | fail | skipped
    low_quality_or_synthetic_pattern: pass | fail | skipped
    gold_reason_quality: pass | fail | skipped
    rubric_fit: pass | fail | skipped
  accepted_count: integer
  rejected_count: integer
  rejection_reason_counts: object
  accepted_dataset_refs:
    - dataset://...
  receipt_refs:
    - receipt://...
  status: draft | completed | disputed | superseded
```

## TrainingCostLedgerEnvelope

```yaml
TrainingCostLedgerEnvelope:
  training_cost_ledger_id: ledger://...
  training_id: train_...
  batch_plan_refs:
    - batch://...
  provider_call_count: integer
  token_count: integer
  runtime_seconds: optional
  spend_estimate: optional
  accepted_row_count: integer
  rejected_row_count: integer
  cost_per_accepted_row: optional
  dataset_yield_summary_ref: optional
  quality_lift_summary_ref: optional
  status: open | closed | disputed
```

## WorkerTrainingEnvelope

```yaml
WorkerTrainingEnvelope:
  training_id: train_...
  target_worker_id: worker://...
  requester_id: wallet://... | service://... | org://...
  provider_id: worker://... | service://... | publisher://...
  training_objective: string
  training_profile: dense_transformer | moe | subquadratic | hybrid_attention_state | retrieval_augmented | mutable_context | adapter_trained | distillation_trained | deterministic_verifier | custom
  training_methods:
    - prompt_optimization
    - workflow_trace
    - retrieval_curation
    - context_update
    - route_policy_training
    - adapter_training
    - verifier_tuning
    - eval_generation
    - model_finetune
    - distillation
    - policy_hardening
  dataset_commitment: hash
  domain_ontology_ref: optional
  canonical_object_model_refs: []
  data_recipe_refs: []
  policy_bound_data_view_refs: []
  distilled_dataset_refs: []
  evaluation_dataset_refs: []
  model_capacity_profile_ref: optional
  training_batch_plan_refs: []
  raw_batch_archive_refs: []
  quality_gate_report_refs: []
  training_cost_ledger_ref: optional
  ontology_to_worker_plan_ref: optional
  privacy_policy_ref: optional
  evaluation_rubric_ref: rubric://...
  post_training_policy_ref: optional
  context_graph_ref: optional
  promotion_gate_ref: optional
  output_manifest_ref: ai://...
  receipt_root: hash
  status: proposed | running | evaluated | accepted | rejected | disputed
```

## DatasetFactoryRunEnvelope

```yaml
DatasetFactoryRunEnvelope:
  dataset_factory_run_id: run://... | foundry_job://...
  foundry_job_ref: foundry_job://...
  foundry_spec_ref: optional foundry_spec://...
  objective: string
  source_refs:
    - artifact://... | connector://... | view://... | receipt://...
  data_recipe_refs:
    - recipe://...
  ontology_refs:
    - ontology://...
  policy_bound_data_view_refs:
    - view://...
  stages:
    - define
    - research
    - ground
    - generate
    - audit
    - export
    - runbook
  stage: define | research | ground | generate | audit | export | runbook
  output_dataset_refs:
    - dataset://...
  dataset_snapshot_refs:
    - dataset_snapshot://...
  holdout_dataset_refs:
    - dataset://...
  adversarial_dataset_refs:
    - dataset://...
  quality_gate_refs:
    - gate://...
  cost_ledger_ref: ledger://...
  receipt_root: hash
  status: draft | running | gated | exported | failed | rejected
```

## TrainingPipelineRunEnvelope

```yaml
TrainingPipelineRunEnvelope:
  training_pipeline_run_id: trainpipe://...
  foundry_job_ref: foundry_job://...
  foundry_spec_ref: foundry_spec://...
  run_plan_ref: optional run_plan://...
  objective: string
  stage:
    idea | data_binding | dataset_factory | notebook_prep | training |
    eval | validation | conversion | registration | endpoint_candidate |
    promotion_review | completed | failed
  workspace_ref: code_workspace://... | notebook://... | runtime://...
  compute_session_refs:
    - compute://...
  checkpoint_refs:
    - checkpoint://... | artifact://... | receipt://...
  resume_ref: optional artifact://... | receipt://...
  last_heartbeat_ref: optional receipt://...
  authority_grant_refs:
    - grant://...
  training_evidence_eligibility_refs:
    - eligibility://...
  training_data_posture:
    synthetic_only | redacted_opt_in | full_private_opt_in | org_policy
  model_base_refs:
    - model://... | model_mount://...
  input_dataset_refs:
    - dataset://...
  dataset_snapshot_refs:
    - dataset_snapshot://...
  training_config_ref: artifact://...
  training_batch_plan_refs:
    - batch://...
  trial_refs:
    - trial://...
  teacher_session_refs:
    - teacher_session://...
  candidate_data_refs:
    - candidate_data://...
  eval_suite_refs:
    - benchmark://... | gate://...
  validation_report_refs:
    - artifact://...
  optimization_cycle_refs:
    - optcycle://...
  artifact_conversion_refs:
    - conversion://...
  model_artifact_refs:
    - model_artifact://...
  package_artifact_refs:
    - package_artifact://...
  registered_model_candidate_ref: model://... | registry_version://...
  endpoint_candidate_ref: model_route://...
  route_binding_candidate_ref: optional promotion_record://...
  conductor_advisor_candidate_ref: optional conductor://...
  scorecard_ref: gate://... | artifact://...
  promotion_bundle_ref: optional promotion_bundle://...
  spend_forecast_ref: optional ledger://...
  current_burn_ref: optional ledger://...
  continuation_policy_ref: optional policy://...
  stop_resume_policy_ref: optional policy://...
  cost_ledger_ref: ledger://...
  promotion_proposal_ref: proposal://...
  receipt_root: hash
  status: planned | running | suspended | resuming | gated | registered | promoted | rejected | failed
```

## ExperimentOptimizationCycleEnvelope

```yaml
ExperimentOptimizationCycleEnvelope:
  optimization_cycle_id: optcycle://...
  target_training_pipeline_ref: trainpipe://...
  optimizer_ref: worker://... | conductor://... | runtime://...
  objective_metric:
    name: string
    direction: minimize | maximize
  baseline_recipe_ref: artifact://...
  best_candidate_ref: artifact://...
  trial_refs:
    - trial://... | run://... | artifact://...
  accepted_change_refs:
    - artifact://...
  rejected_change_refs:
    - artifact://...
  seed_policy_ref: policy://...
  budget_policy_ref: policy://...
  stop_policy_ref: policy://...
  receipt_root: hash
  status: planned | running | stopped | promoted_to_review | failed | rejected
```

## ArtifactConversionRunEnvelope

```yaml
ArtifactConversionRunEnvelope:
  conversion_run_id: conversion://...
  training_pipeline_ref: trainpipe://...
  source_model_artifact_ref: model_artifact://... | artifact://... | model://...
  conversion_targets:
    - adapter_merge
    - quantization
    - gguf
    - mlx
    - onnx
    - tensorrt
    - model_card
    - endpoint_package
    - custom
  output_artifact_refs:
    - package_artifact://... | artifact://...
  validation_refs:
    - gate://... | receipt://... | benchmark://...
  registered_model_candidate_ref: model://... | registry_version://...
  receipt_root: hash
  status: planned | running | validated | registered | failed | rejected
```

## ConductorAdvisorCandidateEnvelope

```yaml
ConductorAdvisorCandidateEnvelope:
  conductor_advisor_candidate_id: conductor://...
  foundry_job_ref: foundry_job://...
  intended_consumer: ioi_ai | hypervisor_operator_plane | custom_coordinator
  training_data_posture:
    synthetic_only | redacted_opt_in | full_private_opt_in | org_policy
  training_consent_refs:
    - grant://... | policy://...
  training_evidence_eligibility_refs:
    - eligibility://...
  input_refs:
    - artifact://... | receipt://... | dataset://...
  teacher_session_refs:
    - teacher_session://...
  candidate_data_refs:
    - candidate_data://...
  eval_suite_refs:
    - benchmark://... | gate://...
  scorecard_refs:
    - gate://... | artifact://...
  shadow_mode_refs:
    - run://...
  shadow_mode_receipt_refs:
    - receipt://...
  shadow_mode_summary:
    quality_delta: optional
    cost_delta: optional
    latency_delta: optional
    privacy_incidents: integer
    policy_denials: integer
    authority_escalations: integer
  promotion_status:
    draft | training | shadow | gated | promoted | rejected | paused |
    rolled_back | recalled
  rollback_ref: optional
  promotion_bundle_ref: optional promotion_bundle://...
```

## PostTrainingCycleEnvelope

```yaml
PostTrainingCycleEnvelope:
  cycle_id: ptc_...
  worker_id: worker://...
  trigger: user_correction | failed_eval | benchmark_submission | teacher_distillation | scheduled_retrain | service_delivery_feedback
  allowed_training_methods:
    - context_update
    - adapter_training
    - route_policy_training
    - distillation
    - eval_generation
    - package_revision
  source_trace_refs: []
  privacy_policy_ref: policy://...
  teacher_worker_refs: []
  candidate_artifact_ref: cid://... | artifact://...
  eval_profile_ref: benchmark://...
  promotion_gate_ref: gate://...
  rollback_required: true
  status: proposed | training | evaluating | promoted | rejected | rolled_back
```

## AgentWikiEnvelope

Agent Wiki is the user-facing and agent-facing semantic memory surface for
preferences, procedures, doctrine, route notes, failure lessons, source-backed
claims, and project knowledge. It is backed by the `ioi-memory` context plane
for product memory and retrieval. It is not itself Agentgres canonical truth.

Agent Wiki and `ioi-memory` form the portable agent-memory substrate. Harnesses
may keep local caches, summaries, embeddings, hidden scratchpads, or run-native
"brain" files, but those are adapters over admitted memory. They are not the
durable owner of user, org, project, worker, or managed-instance knowledge.

Agentgres admits authoritative wiki changes through operations such as
`ContextMutationEnvelope`, stores provenance and policy refs, and serves
rebuildable projections over accepted wiki state.

```yaml
AgentWikiEnvelope:
  wiki_id: wiki://...
  owner_ref: wallet://... | org://... | project://... | worker://...
  agentgres_domain_ref: agentgres://domain/...
  memory_plane_ref: memory://... | optional
  memory_profile_ref: memory_profile://... | optional
  scope: user | org | project | worker | service | domain
  visibility: private | shared | org | public
  policy_ref: policy://...
  default_retention_policy_ref: policy://...
  encryption_policy_ref: policy://... | optional
  restore_authority_ref: authority://... | policy://... | optional
  page_index_ref: projection://... | optional
  retrieval_projection_refs:
    - memory_projection://...
  latest_context_mutation_ref: ctxmut_... | optional
  archive_ref: memory_archive://... | cid://... | artifact://... | optional
  status: active | archived | restoring | deprecated
```

## Portable Agent Memory

Portable agent memory is user-, org-, project-, worker-, service-, or
domain-bound context that can survive harness swaps, model-route swaps,
runtime migration, node failure, payment lapse, or managed-instance restore when
policy allows. It is the durable layer beneath agent "personality," preferences,
procedures, route notes, game lessons, project conventions, tool affordances,
and failure memory.

The package declares what memory it can use. The instance owns the concrete
memory. Harnesses receive policy-filtered projections.

```text
WorkerPackage declares MemoryProfile compatibility
  -> install / managed instance binds an owner-scoped AgentWiki
  -> runs propose ContextMutationEnvelope changes
  -> Agentgres admits accepted memory refs and receipts
  -> storage backend holds encrypted payload/archive bytes
  -> authority provider releases restore/decryption when required
  -> harness/model receives a MemoryProjection, not raw private memory by default
```

The anti-pattern this prevents is:

```text
selected harness writes the agent's durable brain by itself
```

The correct shape is:

```text
harness-local memory is cache;
Agent Wiki / ioi-memory is durable knowledge;
Agentgres admits memory truth;
encrypted archives preserve restorable bytes;
authority providers gate restore, export, decryption, and revocation
```

```yaml
MemoryProfileEnvelope:
  memory_profile_id: memory_profile://...
  owner_scope:
    user | org | project | worker | managed_instance | service | domain
  package_ref: optional package://...
  managed_instance_ref: optional agent://...
  allowed_memory_kinds:
    - preference
    - fact
    - procedure
    - doctrine
    - route
    - tool_affordance
    - failure
    - eval
    - game_lesson
    - project_convention
    - connector_observation
  portability:
    any_compatible_harness | package_family_only |
    instance_private | no_portability
  persistence:
    ephemeral | session | grace_archive | zero_to_idle | persistent | exportable
  default_retention_policy_ref: policy://...
  archive_policy_ref: policy://...
  projection_policy_ref: policy://...
  redaction_policy_ref: policy://...
  training_use_policy_ref: optional policy://...
  restore_authority_requirement:
    local_policy | authority_step_up | wallet_step_up | org_quorum |
    admin_policy | unavailable
  delete_or_forget_policy_ref: policy://...
  status:
    draft | active | suspended | archived | revoked

MemoryArchiveEnvelope:
  memory_archive_id: memory_archive://...
  wiki_ref: wiki://...
  memory_profile_ref: memory_profile://...
  managed_instance_ref: optional agent://...
  archive_payload_ref: cid://... | artifact://... | encrypted_ref
  payload_hash: hash
  encryption_policy_ref: policy://...
  retention_policy_ref: policy://...
  restore_policy_ref: policy://...
  authority_refs:
    - authority://... | grant://... | lease://...
  created_from_state_root_ref: state_root://...
  receipt_refs:
    - receipt://...
  status:
    retained | restoring | restored | expired | deleted | revoked

MemoryProjectionEnvelope:
  projection_id: memory_projection://...
  wiki_ref: wiki://...
  memory_profile_ref: memory_profile://...
  target_ref:
    harness://... | model_route://... | worker://... | service://... |
    surface://... | agent://...
  projection_kind:
    prompt_context | retrieval_index | skill_bundle | route_notes |
    policy_filtered_summary | tool_affordance_map | eval_memory
  allowed_memory_kinds:
    - preference | fact | procedure | doctrine | route |
      tool_affordance | failure | eval | game_lesson |
      project_convention | connector_observation
  redaction_policy_ref: policy://...
  privacy_posture_ref: policy://...
  freshness:
    realtime | run_start_snapshot | scheduled_refresh | manual_refresh
  source_context_mutation_refs:
    - ctxmut_...
  receipt_ref: receipt://...
  status:
    active | stale | revoked | superseded
```

## ContextMutationEnvelope

```yaml
ContextMutationEnvelope:
  mutation_id: ctxmut_...
  wiki_ref: wiki://... | optional
  worker_id: worker://...
  package_ref: optional package://...
  managed_instance_ref: optional agent://...
  memory_profile_ref: optional memory_profile://...
  project_ref: agentgres://project/... | optional
  mutation_type:
    fact | preference | doctrine | route | procedure | eval | failure |
    tool_affordance | game_lesson | project_convention | connector_observation
  operation: add | supersede | contradict | deprecate | activate | archive | forget
  scope: user | org | project | worker | service | domain | optional
  visibility: private | shared | org | public | optional
  validity_window: optional
  retention_policy_ref: optional policy://...
  projection_policy_ref: optional policy://...
  claim_ref: artifact://... | hash://... | optional
  prior_claim_refs: []
  evidence_refs: []
  source_authority: user | worker | verifier | benchmark | service_delivery | admin
  policy_hash: hash
  receipt_ref: receipt://...
```

## PromotionDecisionEnvelope

Foundry promotion bundles freeze the evidence package that Governance may use
for rollout, rollback, recall, or placement decisions. A bundle is not itself
deployment permission.

```yaml
FoundryPromotionBundleEnvelope:
  promotion_bundle_id: promotion_bundle://...
  foundry_job_ref: foundry_job://...
  candidate_ref: model://... | worker://... | model_route://... | conductor://... | package://...
  parent_artifact_ref: optional artifact://... | model://... | worker://...
  dataset_digest_refs:
    - dataset://... | hash
  teacher_session_refs:
    - teacher_session://...
  verifier_version_refs:
    - worker://... | model://... | gate://...
  scorecard_ref: gate://... | artifact://...
  gating_threshold_ref: policy://...
  authority_or_signoff_refs:
    - grant://... | policy://... | receipt://...
  monitoring_policy_ref: policy://...
  deployment_tier: local | shadow | canary | production | marketplace
  rollback_target_ref: artifact://... | model://... | worker://... | package://...
  receipt_root: hash
  status:
    draft | frozen | proposed | approved | rejected | rolled_back | recalled
```

```yaml
PromotionDecisionEnvelope:
  promotion_id: promote_...
  cycle_id: ptc_...
  candidate_ref: cid://... | artifact://...
  baseline_version: worker://...@semver
  candidate_version: worker://...@semver-candidate
  eval_profile_ref: benchmark://...
  baseline_score_commitment: hash
  candidate_score_commitment: hash
  regression_receipt_refs: []
  decision: promoted | rejected | rolled_back
  reason_ref: artifact://... | hash://...
  rollback_ref: optional
  receipt_ref: receipt://...
```

## CapabilityRegressionRecordEnvelope

```yaml
CapabilityRegressionRecordEnvelope:
  regression_id: regression://...
  capability_ref: worker://... | model_route://... | tool://... | mcp://... | automation://... | service://... | package://... | domain_app://...
  capability_kind: worker | model_route | agent_harness | tool | mcp_server | connector | automation | service | environment_image | package | domain_app | fleet_policy
  baseline_version_ref: optional
  candidate_or_active_version_ref: string
  detected_in:
    phase: offline_eval | shadow | canary | rollout | production | recall_review
    run_refs: []
    release_target_refs: []
  regression_class:
    quality | safety | privacy | cost | latency | authority | reliability |
    policy | security | compliance | marketplace_reputation
  severity: info | warning | blocking | critical
  evidence_refs:
    - receipt://... | artifact://... | gate://... | benchmark://...
  scorecard_refs: []
  affected_scope_refs: []
  recommended_action:
    reject | hold | shadow_more | pause | rollback | recall | constrain |
    patch_and_retry | require_human_review
  adjudication_ref: receipt://... | optional
  training_evidence_eligibility_ref: eligibility://... | optional
  future_eval_candidate_refs: []
  status:
    detected | adjudicating | blocked | rejected | shadowing | paused |
    rolled_back | recalled | constrained | converted_to_eval | closed
```

A regression record is evidence and lifecycle posture, not training consent. It
may become a future holdout, eval case, or Foundry job only after the owning
governance surface records `TrainingEvidenceEligibility` or an equivalent
policy decision.

## OrchestrationConstraintEnvelope

Captures the constraints that bind an outcome-conductor plan before a model,
harness, worker, or session receives private context or scoped tool access.
This is a plan-selection input, not an authority grant.

```yaml
OrchestrationConstraintEnvelope:
  constraint_id: constraint://...
  goal_ref: goal://... | task://...
  requester_ref: wallet://... | org://... | system://... | agent://...
  privacy_posture_ref: policy://... | privacy_posture://... | null
  authority_posture_refs:
    - authority://... | grant://... | policy://...
  provider_trust_posture:
    local_only | redacted_remote | provider_allowed |
    customer_boundary | tee_required | no_provider_trust
  budget_refs:
    - budget://...
  latency_target: interactive | batch | background | deadline_bound
  quality_target_ref: benchmark://... | rubric://... | gate://... | null
  verification_strength:
    none | lightweight | standard | independent | adversarial |
    regulated | physical_safety
  data_use_eligibility_refs:
    - eligibility://... | policy://...
  allowed_route_classes:
    - local_model | provider_api | marketplace_worker | installed_worker |
      managed_agent | deterministic_tool | foundry_job
  disallowed_context_classes:
    - raw_secret
    - protected_plaintext
    - unauthorized_connector_payload
    - non_opted_in_training_trace
  user_or_org_preference_refs:
    - policy://... | profile://...
  status: draft | active | superseded | revoked
```

## OrchestrationPolicyEnvelope

Versioned policy for choosing among candidate plan shapes. It may use
deterministic rules, benchmark priors, contextual bandit updates, online
quality evidence, user/org preferences, or Foundry-produced conductor advisors.
It does not execute work or grant authority.

```yaml
OrchestrationPolicyEnvelope:
  policy_id: orchestration_policy://...
  owner_ref: org://... | system://... | domain://... | null
  policy_version: semver_or_hash
  applicable_goal_classes:
    - research | code | computer_use | connector_action | operations |
      foundry_build | marketplace_handoff | physical_action | custom
  supported_materializations:
    - single_path
    - verifier_backed_single_path
    - multi_model_answer
    - multi_harness_attempt
    - cross_session_branch_and_merge
    - collaborative_frontier
    - independent_replication
    - dynamic_specialist_mesh
    - open_challenge
    - marketplace_worker_delegation
    - foundry_job
  goal_execution_policy: auto | pinned | compare
  selection_source: user | org_policy | conductor_policy | fallback_policy
  topology_policy:
    fixed | conductor_mutable | frontier_driven | participant_proposed |
    market_allocated | governed_federation
  routing_signal_refs:
    - benchmark://... | receipt://... | ledger://... | gate://...
  conductor_advisor_refs:
    - conductor://...
  hard_policy_refs:
    - policy://...
  fallback_policy:
    ask_user | local_default | safest_private_route | cheapest_route |
    fail_closed
  collaboration_policy_refs:
    - policy://...
  marginal_value_stop_policy_ref: policy://... | null
  update_mode:
    static | operator_managed | bandit_assisted | foundry_promoted
  status: draft | active | shadow | deprecated | revoked
```

## OrchestrationPlanEnvelope

Candidate or selected plan shape for an outcome conductor. A plan may reference
model routes, harnesses, workers, verifier paths, sessions, and handoffs, but it
does not execute until Hypervisor/daemon admission accepts the relevant work.

```yaml
OrchestrationPlanEnvelope:
  plan_id: orchestration_plan://...
  goal_ref: goal://... | task://...
  constraint_envelope_ref: constraint://...
  materialization:
    single_path | verifier_backed_single_path | multi_model_answer |
    multi_harness_attempt | cross_session_branch_and_merge |
    collaborative_frontier | independent_replication |
    dynamic_specialist_mesh | open_challenge |
    marketplace_worker_delegation | foundry_job
  goal_execution_policy: auto | pinned | compare
  selection_source: user | org_policy | conductor_policy | fallback_policy
  proposed_model_route_refs:
    - model_route://...
  proposed_harness_refs:
    - harness_profile:... | agent_harness_adapter:...
  proposed_worker_refs:
    - worker://... | agent://...
  proposed_verifier_path_refs:
    - verifier_path://...
  proposed_session_topology:
    single_session | isolated_parallel_sessions | branch_and_merge |
    collaborative_frontier | federated_room | handoff_only | no_execution
  outcome_room_ref: outcome-room://... | null
  proposed_coordination_topology:
    none | hosted_admission | federated_admission
  expected_cost_ref: budget://... | null
  expected_latency_class: interactive | batch | background | deadline_bound
  evidence_basis_refs:
    - benchmark://... | receipt://... | ledger://... | gate://...
  status: candidate | selected | rejected | superseded | admitted
```

## NetworkGoalBudgetEnvelope

`NetworkGoalBudgetEnvelope` is the explicit spend boundary for independent
Network/Open workers, verifiers, services, resource providers, challenges, and
settlement. It is separately funded and visible; it is not the ordinary Goal
Space Work Credit allowance, a pooled provider seat, a transferable credit, or
permission to spend without the declared authority and admission path. A
`ServiceOrder` may carry its own equivalent budget contract, but an OutcomeRoom
must reference which contract governs external spend.

```yaml
NetworkGoalBudgetEnvelope:
  network_goal_budget_id: goal-budget://...
  goal_ref: goal://... | task://...
  outcome_room_ref: outcome-room://... | null
  sponsor_ref: user://... | org://... | project://... | service://...
  funding_mode: prepaid_cap | bounty | procurement_cap | service_order
  funding_source_ref:
    wallet://... | escrow://... | procurement://... | order://...
  denomination: string
  authorized_amount: decimal
  reserved_amount: decimal
  admitted_spend_amount: decimal
  remaining_amount: decimal
  quote_rate_card_and_cap_refs:
    - quote://... | rate-card://... | policy://...
  eligible_contributor_and_work_refs:
    - worker://... | service://... | participant-lease://... |
      frontier://... | verifier_path://... | resource-offer://...
  spend_authority_ref: grant://...
  allocation_and_reservation_refs:
    - allocation://... | receipt://... | ledger://...
  contribution_delivery_and_settlement_refs:
    - contrib_... | delivery://... | settlement-intent://... | receipt://...
  adjustment_refund_and_dispute_policy_refs:
    - policy://... | dispute://...
  ordinary_work_credit_substitution: prohibited
  expires_at: timestamp | null
  status:
    draft | funded | active | exhausted | paused | disputed |
    settling | settled | refunded | expired | revoked
```

## OutcomeRoomDiscoveryEnvelope and RoomParticipationRequestEnvelope

Cross-domain and Network/Open participation begins with a policy-bound
discovery projection, not access to the room database. An independently
operated Worker can discover the public objective/category and declared
requirements, then submit a typed participation request through AIIP. Neither
object carries raw room context, private memory, secrets, protected connector
payloads, or non-public operational state.

The contract is topology-neutral. Under `hosted_admission`,
`admission_owner_ref` names the host domain. Under `federated_admission`, it
names the versioned federation policy/adjudicator path. The same request,
eligibility, visibility, privacy, quote, verifier, settlement, receipt, and
lease semantics apply in both cases; only ordering/admission ownership differs.

```yaml
OutcomeRoomDiscoveryEnvelope:
  room_discovery_id: room-discovery://...
  outcome_room_ref: outcome-room://...
  publication_version: semver_or_hash
  published_by_ref: domain://... | org://... | service://...
  public_goal_ref: goal://... | task://... | service://...
  public_objective: string
  public_category_refs:
    - ontology://... | benchmark://... | capability://... | service://...
  coordination_topology: hosted_admission | federated_admission
  admission_owner_ref: domain://... | policy://...
  participation_channel_ref: aiip://channel/...
  semantic_and_action_profile_refs:
    - ontology://... | semantic-profile://... | ontology-mapping://... |
      ontology-action://... | action_schema://...
  required_capability_and_worker_profile_refs:
    - capability://... | worker://... | package://... | verifier_path://...
  eligibility_and_affiliation_policy_refs:
    - policy://... | conformance_profile://... | certification_claim://...
  visibility_and_privacy_policy_refs:
    - policy://... | privacy_posture://... | restricted_view://...
  public_frontier_and_context_projection_refs:
    - projection://... | frontier://... | restricted_view://... |
      redacted_summary://...
  budget_quote_and_capacity_refs:
    - goal-budget://... | order://... | quote://... | resource-offer://...
  verifier_and_acceptance_posture_refs:
    - verifier_path://... | rubric://... | gate://... | policy://...
  settlement_dispute_and_contribution_policy_refs:
    - policy://... | settlement-intent://... | dispute://...
  license_retention_and_export_policy_refs:
    - license://... | policy://...
  excluded_context_classes:
    - raw_secret
    - protected_plaintext
    - unauthorized_connector_payload
    - unrelated_private_memory
    - private_room_database_state
    - non_opted_in_training_trace
  private_context_included: false
  published_at: timestamp
  updated_at: timestamp | null
  valid_until: timestamp | null
  discovery_state_root: hash
  signature: required
  status: draft | discoverable | paused | filled | expired | withdrawn | revoked
```

```yaml
RoomParticipationRequestEnvelope:
  participation_request_id: participation-request://...
  room_discovery_ref: room-discovery://...
  outcome_room_ref: outcome-room://...
  requested_by_ref: worker://... | service://... | org://... | domain://...
  operator_and_home_domain_refs:
    - user://... | wallet://... | org://... | domain://... | system://...
  worker_composition_and_dependency_refs:
    - package://... | worker://... | model_route://... |
      harness_profile:... | runtime://... | provider://...
  capability_offer_refs:
    - capability-offer://... | ai://... | package://...
  affiliation_and_independent_operation_evidence_refs:
    - evidence://... | receipt://... | org://... | certification_claim://...
  supported_semantic_and_action_profile_refs:
    - ontology://... | semantic-profile://... | ontology-mapping://... |
      ontology-action://... | action_schema://...
  eligibility_evidence_refs:
    - evidence://... | receipt://... | benchmark://... |
      conformance_profile://... | certification_claim://...
  requested_role_frontier_and_visibility_refs:
    - frontier://... | policy://... | restricted_view://...
  privacy_custody_and_context_policy_refs:
    - privacy_posture://... | custody://... | policy://...
  proposed_quote_and_budget_refs:
    - quote://... | goal-budget://... | order://...
  accepted_verifier_settlement_dispute_and_contribution_policy_refs:
    - verifier_path://... | policy://... | settlement-intent://... |
      dispute://...
  requested_participant_state_export_policy_ref: policy://...
  coordination_topology: hosted_admission | federated_admission
  admission_owner_ref: domain://... | policy://...
  private_context_included: false
  request_hash: hash
  signature: required
  admission_decision_ref: decision://... | receipt://... | null
  participant_lease_ref: participant-lease://... | null
  status: draft | submitted | evaluating | admitted | rejected | withdrawn | expired
```

## OutcomeRoomEnvelope

`OutcomeRoomEnvelope` is the shared collaborative-pursuit profile above one or
more GoalRuns. It binds a durable objective to a work frontier, participants,
attempts, findings, verification, contribution lineage, budget, and replay. It
does not create a second runtime, authority system, marketplace, or globally
mutable Agentgres graph.

The same room may appear as a Goal Space in ioi.ai and Mission detail in
Hypervisor. A direct question, one-shot run, ordinary automation, or single
session does not require an OutcomeRoom. The room is used only when persistent
collective pursuit creates enough value to justify participation and admission
machinery.

Every room declares who orders and admits its shared state:

- `hosted_admission`: one named governed domain orders and admits room-level
  frontier, attempt, finding, evaluation, and decision updates;
- `federated_admission`: a versioned policy names participating domains,
  ordering/merge rules, quorum or adjudicator requirements, conflict behavior,
  failover, and dispute handling.

Each party retains its local operational truth and private context in either
topology. AIIP carries signed, sequenced, idempotent permitted updates and refs;
`MultiPartyCollaborationEnvelope` remains the cross-party policy and proof
context. A room board, chat, inbox, digest, leaderboard, and replay are
projections over admitted objects, never operational truth by themselves.

```yaml
OutcomeRoomEnvelope:
  outcome_room_id: outcome-room://...
  owner_or_sponsor_ref:
    user://... | org://... | project://... | domain://... | service://...
  objective_ref: goal://... | task://... | service://...
  objective: string
  constraint_refs:
    - constraint://... | policy://... | budget://...
  acceptance_criteria_refs:
    - rubric://... | gate://... | policy://...
  stop_policy_ref: policy://...
  room_mode:
    private_goal | permissioned_team | cross_org | open_challenge
  visibility_policy_ref: policy://...
  participation_policy_ref: policy://...
  privacy_policy_ref: policy://...
  contribution_policy_ref: policy://...
  discovery_and_external_admission_policy_refs:
    - policy://... | room-discovery://... | aiip://channel/...
  artifact_license_rights_retention_and_export_policy_refs:
    - policy://... | license://...
  coordination_topology:
    hosted_admission | federated_admission
  coordination_policy_ref: policy://...
  host_domain_ref: domain://... | null
  ordering_and_merge_policy_ref: policy://...
  conflict_and_failover_policy_ref: policy://...
  multi_party_collaboration_ref: collaboration://... | null
  ontology_profile_refs:
    - ontology://... | semantic-profile://... | ontology-mapping://...
  scorecard_and_guardrail_refs:
    - benchmark://... | rubric://... | gate://... | policy://...
  verifier_path_refs:
    - verifier_path://...
  resource_and_budget_refs:
    - resource_pool://... | budget://... | goal-budget://... | order://...
  settlement_policy_ref: policy://... | null
  participant_lease_refs:
    - participant-lease://...
  participation_request_refs:
    - participation-request://...
  resource_offer_refs:
    - resource-offer://...
  capability_offer_refs:
    - capability-offer://...
  frontier_item_refs:
    - frontier://...
  attempt_refs:
    - attempt://...
  finding_refs:
    - finding://...
  verifier_challenge_refs:
    - verifier-challenge://...
  discussion_projection_refs:
    - projection://... | message://...
  admission_and_replay_refs:
    - receipt://... | replay://... | agentgres://...
  contribution_refs:
    - contrib_... | receipt://...
  participant_state_bundle_refs:
    - participant-state://...
  status:
    proposed | open | active | paused | blocked | verifying |
    accepted | disputed | settled | closed | revoked | archived
```

## RoomParticipantLeaseEnvelope

Room participation is a lease, not ambient membership. It composes existing
identity, context, authority, runtime, resource, and budget leases rather than
creating a second credential system.

```yaml
RoomParticipantLeaseEnvelope:
  participant_lease_id: participant-lease://...
  outcome_room_ref: outcome-room://...
  participant_ref:
    agent://... | worker://... | service://... | org://... | domain://...
  admitted_role:
    conductor | implementer | reviewer | verifier | operator |
    researcher | specialist | synthesizer | resource_provider |
    integrity_challenger | memory_curator
  operator_ref: user://... | org://... | wallet://... | domain://...
  home_domain_ref: domain://... | system://... | agentgres://domain/...
  worker_and_runtime_refs:
    - worker://... | harness_profile:... | agent_harness_adapter:... |
      model_route://... | runtime://... | node://...
  capability_advertisement_refs:
    - capability-offer://... | ai://... | package://...
  tool_connector_and_capability_dependency_refs:
    - tool://... | connector://... | capability://... | prim:*
  join_request_ref: participation-request://... | proposal://... | null
  identity_and_eligibility_evidence_refs:
    - evidence://... | receipt://... | certification_claim://...
  admission_decision_ref: receipt://... | decision://...
  visibility_scope_ref: policy://... | restricted_view://...
  context_and_authority_lease_refs:
    - context_lease://... | grant://... | authority://...
  runtime_resource_and_budget_lease_refs:
    - lease://... | resource-lease://... | budget://...
  current_claim_ref: work-claim://... | null
  heartbeat_ref: receipt://... | heartbeat://... | null
  next_wake_condition_ref: policy://... | event://... | null
  quiet_hours_or_backoff_ref: policy://... | null
  last_contribution_ref: contrib_... | receipt://... | null
  exit_and_claim_release_refs:
    - decision://... | work-claim://... | receipt://...
  portable_participant_state_bundle_ref: participant-state://... | null
  future_access_revocation_refs:
    - revocation://... | receipt://...
  ttl_seconds: integer | null
  status:
    invited | joining | active | sleeping | waiting | suspended |
    quarantined | retiring | retired | revoked
```

## ParticipantStateBundleEnvelope

Retirement or revocation ends future participation and releases or reassigns
live claims; it does not erase permitted contribution lineage, receipts,
acceptance, settlement, or dispute evidence. The participant's home domain may
retain a signed, policy-bound portable bundle and continue without room-database
access. A hosted room cannot make portability depend on continued trust in or
access to its database; a federated room applies the same export contract at the
declared federation watermark.

Bundle revocation is append-only. It may end future room access, revoke keys or
live restricted views, or supersede an erroneous export. It cannot erase
already permitted contribution, receipt, acceptance, settlement, or dispute
lineage; historical proof cannot depend on later host availability.

```yaml
ParticipantStateBundleEnvelope:
  participant_state_bundle_id: participant-state://...
  outcome_room_ref: outcome-room://...
  participant_lease_ref: participant-lease://...
  participant_and_home_domain_refs:
    - worker://... | service://... | org://... | domain://... | system://...
  coordination_topology: hosted_admission | federated_admission
  bundle_reason: checkpoint | voluntary_retirement | lease_expiry | revocation | quarantine | room_close
  source_admission_watermark_ref: receipt://... | agentgres://... | hash
  released_or_reassigned_claim_refs:
    - work-claim://... | decision://... | receipt://...
  preserved_contribution_attempt_finding_and_result_refs:
    - contrib_... | attempt://... | finding://... | work-result://... |
      outcome-delta://...
  preserved_receipt_acceptance_settlement_and_dispute_refs:
    - receipt://... | acceptance://... | settlement-intent://... |
      dispute://... | decision://...
  portable_artifact_and_view_refs:
    - artifact://... | restricted_view://... | redacted_summary://... |
      evidence://... | replay://...
  lineage_and_supersession_refs:
    - contrib_... | attempt://... | finding://... | work-result://...
  export_license_retention_and_recall_policy_refs:
    - policy://... | license://... | revocation://...
  excluded_context_classes:
    - raw_secret
    - protected_plaintext
    - unauthorized_connector_payload
    - unrelated_private_memory
    - private_room_database_state
    - revoked_restricted_view
    - non_opted_in_training_trace
  released_future_access_refs:
    - revocation://... | context_lease://... | grant://... | receipt://...
  revocation_or_supersession_refs:
    - revocation://... | participant-state://... | decision://... | receipt://...
  revocation_effect:
    none | future_access_only | restricted_view_keys_revoked |
    erroneous_export_superseded
  bundle_artifact_ref: artifact://... | cid://... | encrypted_ref
  bundle_root: hash
  room_database_access_required: false
  issued_at: timestamp
  signature: required
  status: prepared | exported | acknowledged | superseded | revoked
```

## ResourceOfferEnvelope and CapabilityOfferEnvelope

Participants may offer compute, runtime capacity, data access, verification,
specialist work, tools, or other capabilities to a room. Offers are typed
profiles over existing provider inventory, worker manifests, capability
discovery, and resource-allocation objects; they are not a second marketplace.

```yaml
ResourceOfferEnvelope:
  resource_offer_id: resource-offer://...
  outcome_room_ref: outcome-room://...
  provider_or_participant_ref:
    participant-lease://... | provider://... | org://... | domain://...
  resource_profile_ref: resource://... | runtime://... | node://...
  capacity_and_availability_ref: capacity://... | schedule://...
  locality_and_custody_refs:
    - region://... | custody://... | privacy_posture://...
  trust_and_assurance_refs:
    - evidence://... | certification_claim://... | receipt://...
  cost_ref: quote://... | budget://... | null
  eligible_work_classes:
    - string
  policy_constraint_refs:
    - policy://...
  allocation_policy_ref: policy://...
  queue_preemption_and_fairness_policy_ref: policy://...
  expires_at: timestamp | null
  allocation_decision_refs:
    - allocation://... | receipt://...
  spend_and_contribution_refs:
    - spend://... | contrib_... | receipt://...
  usage_and_consumption_refs:
    - ledger://... | receipt://... | work-credit://...
  status: offered | queued | allocated | exhausted | withdrawn | expired | revoked
```

```yaml
CapabilityOfferEnvelope:
  capability_offer_id: capability-offer://...
  outcome_room_ref: outcome-room://...
  participant_ref: participant-lease://... | worker://... | service://...
  capability_descriptor_refs:
    - ai://... | package://... | capability://...
  eligible_frontier_classes:
    - string
  model_harness_tool_and_connector_refs:
    - model_route://... | harness_profile:... | tool://... | connector://...
  authority_and_context_requirements:
    - scope:* | policy://... | context-profile://...
  privacy_cost_quality_and_latency_refs:
    - privacy_posture://... | quote://... | benchmark://... | sla://...
  availability_ref: schedule://... | null
  status: offered | eligible | allocated | suspended | withdrawn | revoked
```

When a participant advertises an `ai://...` or `package://...` descriptor but a
frontier needs a generic capability coordinate, the hosted matcher may derive
the reversible alias `capability://advertised/<scheme>/<tail>`. The alias is
valid only while the underlying participant advertisement remains admitted; it
is not a new credential or a trust-on-first-use capability.

Eligibility matching is evidence admission, not allocation or execution
authority. The receipt freezes every input coordinate a later claim must
revalidate. Offer-side requirements are constraints that require independent
proof; they never count as evidence of their own satisfaction. Until the owner
plane can resolve a `scope:*`, `context-profile://...`, `policy://...`, or other
offer prerequisite, matching refuses typed-unavailable. Claim admission
recomputes the exact prerequisite coverage and rechecks resource-offer expiry
against freshly committed wallet.network `resolved_at_ms` immediately before
linearization:

```yaml
WorkEligibilityMatchReceipt:
  receipt_ref: receipt://...
  outcome_room_ref: outcome-room://...
  frontier_item_ref: frontier://...
  frontier_revision: integer
  frontier_control_hash: hash
  participant_ref: participant-lease://...
  participant_revision: integer
  participant_control_hash: hash
  resource_offers:
    - offer_ref: resource-offer://...
      revision: integer
      control_hash: hash
  capability_offers:
    - offer_ref: capability-offer://...
      revision: integer
      control_hash: hash
  context_lease_refs:
    - context_lease://...
  authority_resource_compute_data_budget_and_tool_lease_refs:
    - grant://... | resource-lease://... | compute://... |
      view://... | budget://... | tool-lease://...
  requirement_coverage:
    - requirement_ref: canonical ref
      matched_exactly: true
  offer_prerequisite_coverage:
    - offer_ref: resource-offer://... | capability-offer://...
      prerequisite_refs:
        - scope:* | policy://... | context-profile://... | canonical ref
      proof_refs:
        - grant://... | context-lease://... | receipt://... | canonical ref
  allocation_created: false
  execution_authority_granted: false
  claim_created: false
  authority_grant_id: grant://...
  principal_authority_binding: required
  effect_hash: hash
  output_hash: hash
```

## WorkFrontierItemEnvelope

The work frontier is the room's claimable graph of questions, problems,
hypotheses, tasks, reviews, verification needs, and resource needs. It supports
conductor assignment, pull-based claims, independent replication, and dynamic
taskforces under one contract.

```yaml
WorkFrontierItemEnvelope:
  frontier_item_id: frontier://...
  outcome_room_ref: outcome-room://...
  item_kind:
    question | problem | hypothesis | task | review_need |
    verification_need | resource_need | synthesis_need
  objective: string
  dependency_refs:
    - frontier://... | attempt://... | finding://...
  related_attempt_and_finding_refs:
    - attempt://... | finding://...
  required_capability_refs:
    - capability://... | worker://... | tool://...
  required_context_resource_authority_and_evidence_refs:
    - context-profile://... | resource://... | scope:* | evidence://...
  expected_value: number | null
  uncertainty: number | null
  priority: number | null
  duplication_policy:
    exclusive | allowed | encouraged | independent_replication_required
  claimability:
    open | invited_only | assigned | paused | closed
  max_concurrency: integer | null
  expires_at: timestamp | null
  stop_condition_ref: policy://... | null
  status:
    open | claimed | blocked | replicating | verifying |
    accepted | rejected | superseded | closed
```

## WorkClaimLeaseEnvelope

```yaml
WorkClaimLeaseEnvelope:
  work_claim_id: work-claim://...
  outcome_room_ref: outcome-room://...
  frontier_item_ref: frontier://...
  claimant_ref: participant-lease://... | worker://... | agent://... | org://...
  eligibility_match_receipt_ref: receipt://... | null
  bounded_scope_ref: task://... | task_brief://... | policy://...
  context_lease_refs:
    - context_lease://...
  authority_resource_compute_data_budget_and_tool_lease_refs:
    - grant://... | resource-lease://... | compute://... | view://... |
      budget://... | tool-lease://...
  duplicate_work_policy:
    exclusive | allowed | independent_replication | adversarial_replication
  issued_at: timestamp
  expires_at: timestamp
  heartbeat_ref: heartbeat://... | receipt://... | null
  renewal_count: integer
  release_or_reassignment_reason: string | null
  status:
    proposed | active | waiting | released | expired | reassigned |
    completed | quarantined | revoked
```

## AttemptEnvelope

Attempts preserve positive, negative, inconclusive, invalid, exploit-finding,
and superseded work. A non-winning attempt remains durable when it contributes
information, reproduction evidence, debugging, integrity findings, resources,
review, or synthesis.

Hosted Attempt admission freezes the exact room-control, frontier, active claim,
participant-lease, and GoalRun coordinates that authorized the declaration. The
record hashes and revisions are historical evidence, not a requirement that
mutable claim, participant, or frontier state remain byte-identical forever.
Attempt creation and participant-governed work transitions still re-resolve the
same identities and require the exact claim to be active/current; later host
admission, supersession, Finding admission, and Finding lifecycle may use the
immutable historical identities after claim completion or release. Submitted
OutcomeDelta refs must be exact plane-owned backlinks of the submitted
WorkResult and must independently resolve to that same result, room, and goal.
The Attempt record is provenance over an already admitted GoalRun; creating or
transitioning it does not launch work or grant execution authority.

```yaml
AttemptEnvelope:
  attempt_id: attempt://...
  outcome_room_ref: outcome-room://... | null
  goal_run_ref: goal://...
  frontier_item_ref: frontier://... | null
  work_claim_ref: work-claim://... | null
  participant_ref: participant-lease://... | worker://... | agent://...
  bound_coordinates:
    outcome_room: { record_ref: outcome-room://..., host_domain_ref: domain://..., control_hash: hash }
    frontier_item: { record_ref: frontier://..., outcome_room_ref: outcome-room://..., revision: integer, record_hash: hash }
    work_claim: { record_ref: work-claim://..., outcome_room_ref: outcome-room://..., frontier_item_ref: frontier://..., claimant_ref: participant-lease://..., revision: integer, record_hash: hash }
    participant_lease: { record_ref: participant-lease://..., outcome_room_ref: outcome-room://..., principal_ref: worker://... | agent://..., revision: integer, record_hash: hash }
    goal_run: { record_ref: goal://..., outcome_room_ref: outcome-room://..., updated_at: timestamp | null, record_hash: hash }
  declared_method_and_hypothesis_refs:
    - method://... | finding://... | artifact://...
  parent_and_derivation_refs:
    - attempt://... | artifact://... | finding://...
  input_state_and_environment_refs:
    - state://... | environment://... | worktree://... | dataset://...
  worker_model_harness_tool_and_runtime_versions:
    - worker://... | model_route://... | harness_profile:... |
      tool://... | runtime://...
  authority_and_policy_refs:
    - grant://... | policy://...
  resource_and_cost_refs:
    - resource-lease://... | spend://... | ledger://...
  outcome_class:
    positive | negative | inconclusive | invalid | exploit_found | superseded
  work_result_ref: work-result://... | implementation_result://... | null
  outcome_delta_refs:
    - outcome-delta://...
  artifact_evidence_and_receipt_refs:
    - artifact://... | evidence://... | receipt://... | ledger://...
  verifier_refs:
    - verifier_path://... | verifier-challenge://...
  reproduction_state:
    unreviewed | reproducible | not_reproduced | contradicted | invalidated
  artifact_license_ip_retention_and_export_refs:
    - license://... | policy://...
  contribution_refs:
    - contrib_... | receipt://...
  status: draft | running | submitted | admitted | challenged | accepted | rejected | superseded
```

## FindingEnvelope

Operational admission of a finding proves that the domain admitted a
provenance-bearing assertion; it does not make the proposition universally
true. Findings therefore preserve uncertainty, applicability, contradiction,
time, and dispute state.

A hosted Finding freezes its exact admitted Attempt, WorkResult, historical
participant identity, and optional same-room predecessor Finding coordinates
together with evidence and proof refs. Fresh Finding creation requires that exact
participant lease to be active at authorization and commit, but does not require
an active/current claim. Once admitted, host-governed Finding lifecycle uses the
historical identity coordinates after participant retirement, revocation, or
other inactivity; mutable participant records need not remain byte-identical.
`supersedes_ref` must strictly resolve to a Finding in the same room; a merely
syntactic or cross-room predecessor never establishes lineage. `admitted` is
still an admission state, not acceptance or a verifier verdict.

```yaml
FindingEnvelope:
  finding_id: finding://...
  outcome_room_ref: outcome-room://... | null
  attempt_ref: attempt://...
  work_result_ref: work-result://...
  participant_ref: participant-lease://...
  bound_coordinates:
    attempt: { record_ref: attempt://..., outcome_room_ref: outcome-room://..., participant_ref: participant-lease://..., work_result_ref: work-result://..., revision: integer, record_hash: hash }
    work_result: { record_ref: work-result://..., outcome_room_ref: outcome-room://..., goal_run_ref: goal://..., goal_ref: goal://..., updated_at: timestamp | null, record_hash: hash }
    participant_lease: { record_ref: participant-lease://..., outcome_room_ref: outcome-room://..., principal_ref: worker://... | agent://..., revision: integer, record_hash: hash }
    supersedes_finding: { record_ref: finding://..., outcome_room_ref: outcome-room://..., revision: integer, record_hash: hash } | null
  proposition: string
  finding_kind:
    hypothesis | observation | claim | negative_result | integrity_incident |
    mapping_claim | causal_claim | counterexample | synthesis
  confidence_or_uncertainty: number | null
  valid_time: interval | null
  transaction_time: timestamp
  source_and_observation_context_refs:
    - attempt://... | observation://... | participant-lease://... | domain://...
  supporting_evidence_refs:
    - evidence://... | artifact://... | receipt://...
  proof_refs:
    - evidence://... | artifact://... | receipt://...
  contradicting_evidence_refs:
    - evidence://... | artifact://... | finding://...
  applicability_and_counterexample_refs:
    - policy://... | finding://... | ontology://...
  provenance_ontology_and_mapping_refs:
    - provenance://... | ontology://... | ontology-mapping://...
  proposed_effect_refs:
    - frontier://... | routing-prior://... | policy://... | capability://...
  supersedes_ref: finding://... | null
  dispute_ref: dispute://... | null
  status:
    branch_local | proposed | admitted | contradicted | superseded |
    disputed | rejected | archived
```

## VerifierChallengeEnvelope

```yaml
VerifierChallengeEnvelope:
  verifier_challenge_id: verifier-challenge://...
  outcome_room_ref: outcome-room://... | null
  challenger_ref: participant-lease://... | worker://... | org://... | user://...
  challenged_ref:
    attempt://... | finding://... | verifier_path://... | benchmark://... |
    rubric://... | evidence://... | eligibility://... | decision://...
  challenge_kind:
    metric | rule | verifier | evidence | eligibility | result |
    exploit | independence | collusion | mapping
  challenge_evidence_refs:
    - evidence://... | artifact://... | receipt://...
  adjudicator_policy_ref: policy://...
  prior_rule_version_ref: rubric://... | verifier_path://... | null
  proposed_rule_version_ref: rubric://... | verifier_path://... | null
  affected_attempt_refs:
    - attempt://...
  reverification_required: boolean
  adjudication_ref: decision://... | dispute://... | null
  status:
    proposed | admitted | investigating | upheld | rejected |
    rule_changed | reverifying | resolved | withdrawn
```

## WorkResultEnvelope and OutcomeDeltaEnvelope

`WorkResultEnvelope` is the generic bounded result seam returned by a GoalRun,
claim, worker, harness, service, research attempt, ontology operation, incident
response, or embodied mission. `ImplementationResultPayloadEnvelope` is its
software-specific profile; it no longer defines the general pursuit model.

Profile-specific fields remain behind `result_profile_ref` and
`result_payload_ref`; research, ontology, incident, service, physical-mission,
review, and evaluation results are not forced through software file/diff/test
fields. The cross-domain invariants below are optional when irrelevant, but a
profile must preserve the applicable identities, method/lineage, claims and
uncertainty, evidence, cost/authority/verifier posture, rights, reproduction,
acceptance, challenge, and supersession state whenever the result crosses a
run, room, domain, contribution, dispute, or replay boundary.

```yaml
WorkResultEnvelope:
  work_result_id: work-result://...
  goal_ref: goal://...
  goal_run_ref: goal://... | null
  outcome_room_ref: outcome-room://... | null
  work_claim_ref: work-claim://... | null
  attempt_ref: attempt://... | null
  invocation_or_run_ref:
    harness_invocation://... | run://... | service://... | mission://... | null
  result_profile:
    software_implementation | research | ontology_mutation |
    incident_resolution | service_delivery | physical_mission |
    review | evaluation | custom
  result_profile_ref: schema://... | profile://... | null
  result_payload_ref: artifact://... | cid://... | encrypted_ref | null
  worker_harness_model_runtime_version_refs:
    - worker://... | harness_profile:... | agent_harness_adapter:... |
      model://... | model_route://... | runtime://... | registry_version://...
  declared_method_and_lineage_refs:
    - method://... | attempt://... | finding://... | work-result://... |
      artifact://... | trace://...
  outcome_class:
    positive | negative | inconclusive | invalid | exploit_found | superseded
  status: completed | failed | blocked | partial | challenged | superseded
  outcome_delta_refs:
    - outcome-delta://...
  finding_refs:
    - finding://...
  claim_refs:
    - finding://... | ontology-assertion://... | evidence://...
  uncertainty: number | string | object | null
  supporting_evidence_refs:
    - artifact://... | evidence://... | receipt://... | ledger://...
  contradicting_evidence_refs:
    - finding://... | ontology-assertion://... | evidence://... | artifact://...
  artifact_receipt_and_trace_refs:
    - artifact://... | receipt://... | ledger://... | trace://...
  resource_and_cost_refs:
    - resource-lease://... | cost://... | quote://... | budget://... |
      ledger://... | receipt://...
  authority_and_policy_refs:
    - grant://... | scope:* | policy://... | receipt://...
  blocker_and_decision_request_refs:
    - blocker://... | handoff://... | proposal://...
  verifier_refs:
    - verifier_path://... | worker://... | gate://... | receipt://...
  license_disclosure_retention_and_export_refs:
    - license://... | policy://... | restricted_view://... | receipt://...
  reproduction_state:
    unreviewed | reproducible | not_reproduced | contradicted | invalidated | null
  reproduction_refs:
    - attempt://... | work-result://... | evidence://... | receipt://...
  acceptance_ref: acceptance://... | decision://... | receipt://... | null
  challenge_refs:
    - verifier-challenge://... | dispute://... | evidence://...
  supersedes_work_result_ref: work-result://... | null
  superseded_by_ref: work-result://... | outcome-delta://... | null
  summary_ref: message://... | artifact://... | null
  next_action:
    none | repair | review | verify | replicate | synthesize |
    ask_user | escalate | update_frontier
```

```yaml
OutcomeDeltaEnvelope:
  outcome_delta_id: outcome-delta://...
  goal_ref: goal://...
  outcome_room_ref: outcome-room://... | null
  proposed_by_ref:
    work-result://... | attempt://... | finding://... | participant-lease://...
  target_ref:
    frontier://... | finding://... | ontology://... | state://... |
    capability://... | policy://... | routing-prior://... | service://...
  delta_kind:
    create | update | supersede | reject | merge | promote |
    rollback | course_correct | close
  payload_ref: artifact://... | patch://... | mapping://... | state-delta://...
  precondition_and_invariant_refs:
    - policy://... | gate://... | state://...
  expected_effect_ref: effect://... | null
  verifier_and_acceptance_refs:
    - verifier_path://... | rubric://... | gate://...
  admission_receipt_ref: receipt://... | null
  status: proposed | evaluating | admitted | rejected | superseded | rolled_back
```

## GoalRunEnvelope

Durable state for goal-shaped work. `ioi.ai` and Hypervisor Sessions may expose
different product surfaces, but they should converge on the same GoalRun
primitive when intent must survive compaction, delegation, verification, or
long-session continuation.

The GoalRun is not a chat transcript and not a harness-specific memory file. It
is the bounded coordination record for one participant or subteam's Goal Kernel
loop: intent, constraints, role topology, context cells, leases, handoffs,
attempts, generic results, verifier path, receipts, and continuation state. A
GoalRun may stand alone or participate in an `OutcomeRoomEnvelope`; it does not
own the shared room frontier or cross-party admission policy.

```yaml
GoalRunEnvelope:
  goal_run_id: goal://...
  owner_ref: user://... | org://... | project://... | domain://...
  origin_surface:
    ioi_goal_chat | hypervisor_new_session | hypervisor_session |
    automation | marketplace_instance | api
  user_intent_ref: intent://... | prompt://...
  normalized_goal: string
  outcome_room_ref: outcome-room://... | null
  room_participant_lease_ref: participant-lease://... | null
  frontier_item_refs:
    - frontier://...
  work_claim_refs:
    - work-claim://...
  constraint_refs:
    - constraint://... | policy://... | budget://...
  role_topology_ref: role_topology://...
  grounding_loop_ref: goal_loop://... | null
  active_loop_phase:
    receive_intent | classify_goal | gather_grounding | inspect_state |
    derive_constraints | observe_frontier | form_hypotheses |
    select_or_adapt_topology | claim_allocate_or_delegate | lease_context |
    open_context_cells | execute_attempt | monitor_progress |
    publish_result | verify_compare_or_challenge | repair_or_escalate |
    reconcile | update_frontier_and_memory | continue_or_close | null
  context_cell_refs:
    - context_cell://...
  context_lease_refs:
    - context_lease://... | lease://... | memory_projection://...
  orchestration_plan_refs:
    - orchestration_plan://...
  selected_plan_ref: orchestration_plan://... | null
  topology_revision_refs:
    - role_topology://... | decision://...
  attempt_refs:
    - attempt://...
  work_result_refs:
    - work-result://... | implementation_result://...
  finding_refs:
    - finding://...
  verifier_path_ref: verifier_path://... | null
  verifier_challenge_refs:
    - verifier-challenge://...
  receipt_refs:
    - receipt://... | ledger://...
  continuation_state:
    open | waiting_on_user | waiting_on_frontier | sleeping | delegated |
    verifying | course_correcting | complete | blocked | superseded
  status: draft | active | paused | complete | superseded | revoked
```

## GoalGroundingLoopEnvelope

Low-level orientation and course-correction loop for bounded goal-shaped work.
This is the concrete loop behind the Goal Kernel: it prevents "goal mode" from
becoming unbounded chat, and prevents multi-worker orchestration from becoming
token-maxing. The loop may run in one harness, across multiple Context Cells,
or as one participant in an OutcomeRoom, but every phase has a purpose, an
admission boundary, and an exit condition.

```yaml
GoalGroundingLoopEnvelope:
  goal_loop_id: goal_loop://...
  goal_ref: goal://...
  conductor_context_cell_ref: context_cell://...
  loop_iteration: integer
  phase:
    receive_intent | classify_goal | gather_grounding | inspect_state |
    derive_constraints | observe_frontier | form_hypotheses |
    select_or_adapt_topology | claim_allocate_or_delegate | lease_context |
    open_context_cells | execute_attempt | monitor_progress |
    publish_result | verify_compare_or_challenge | repair_or_escalate |
    reconcile | update_frontier_and_memory | continue_or_close
  outcome_room_ref: outcome-room://... | null
  frontier_and_claim_refs:
    - frontier://... | work-claim://...
  grounding_source_refs:
    - canon://... | doc://... | route://... | runtime://... |
      project://... | receipt://... | ledger://... | memory_projection://...
  state_inspection_refs:
    - environment://... | session://... | run://... | artifact://... |
      worktree://... | surface://... | endpoint://...
  decision_refs:
    - orchestration_decision://... | routing-decision://... |
      approval-request://... | release-control://...
  context_cell_refs:
    - context_cell://...
  handoff_refs:
    - handoff://...
  attempt_result_and_finding_refs:
    - attempt://... | work-result://... | implementation_result://... |
      finding://... | outcome-delta://...
  verifier_path_ref: verifier_path://... | null
  evidence_refs:
    - receipt://... | test://... | artifact://... | screenshot://... |
      ledger://...
  productivity_budget_ref: budget://... | null
  topology_participant_and_verifier_change_refs:
    - role_topology://... | participant-lease://... |
      verifier_path://... | decision://...
  marginal_value_stop_policy_ref: policy://... | null
  escalation_state:
    none | ask_user | open_implementer_cell | open_reviewer_cell |
    require_independent_verifier | require_governance_control |
    stop_blocked
  exit_condition:
    continue | delegated | waiting_on_frontier | verified_complete |
    accepted | risk_stop | budget_stop | deadline_stop |
    marginal_value_stop | blocked | superseded |
    user_input_required | governance_required
  status: active | waiting | satisfied | blocked | superseded | revoked
```

Canonical conductor loop:

```text
receive intent
  -> classify goal shape and risk
  -> gather canon, project, runtime, memory, and surface grounding
  -> inspect current state instead of relying on prose
  -> derive constraints, acceptance, and verification path
  -> observe uncertainty, opportunity, and any shared work frontier
  -> form hypotheses, candidate plans, or frontier items
  -> select or adapt topology; claim, allocate, or delegate bounded work
  -> lease context, tools, memory, resources, budget, and authority
  -> execute isolated or cooperative attempts
  -> publish positive, negative, inconclusive, and integrity results
  -> evaluate, falsify, reproduce, compare, merge, reject, or challenge
  -> reconcile receipts, findings, contribution lineage, and memory
  -> update the shared frontier and routing priors when admitted
  -> adapt topology, participants, budget, and verifier paths
  -> continue until acceptance, risk, budget, deadline, or marginal-value stop
```

The conductor may be the verifier for ordinary work. Independent verifier cells
are policy-triggered escalation paths, not the default. A "sea of agents" is a
participation and allocation policy over this loop and the OutcomeRoom frontier,
not a separate runtime or hard-coded topology.

## RoleTopologyEnvelope

Selected role shape for a GoalRun. The topology is provider-neutral: a role may
be resolved by any eligible harness, model route, worker package, browser
agent, CI agent, service, human, or future runtime. The durable contract is the
role, handoff shape, verifier path, and authority posture, not the vendor. A
topology may be fixed for a small run or revised under policy as the frontier,
participants, evidence, risk, or resource bottlenecks change.

```yaml
RoleTopologyEnvelope:
  topology_id: role_topology://...
  applies_to: goal://... | automation://... | managed_instance://...
  outcome_room_ref: outcome-room://... | null
  topology_version: integer | semver_or_hash
  topology_kind:
    direct | goal_conductor | delegated_build | governed_release |
    multi_context_review | specialist_mesh | leaderless_blackboard |
    market_allocated | independent_replication | federated_pursuit
  mutation_policy:
    fixed | conductor_mutable | participant_proposed |
    frontier_driven | governance_required
  conductor_ref: harness_profile:... | agent://... | worker://...
  implementer_refs:
    - harness_profile:... | agent://... | worker://...
  reviewer_refs:
    - harness_profile:... | worker://... | org://...
  participant_lease_refs:
    - participant-lease://...
  resource_offer_refs:
    - resource-offer://... | capability-offer://...
  verifier_path_ref: verifier_path://... | null
  conductor_verifies_by_default: boolean
  escalation_triggers:
    - publish | runtime_mount | external_connector_action | spend |
      secret_access | unsafe_plaintext | marketplace_admission |
      release_control | production_mutation | physical_action |
      compliance_review
  predecessor_topology_ref: role_topology://... | null
  mutation_decision_ref: decision://... | receipt://... | null
  status: draft | active | adapting | satisfied | superseded | revoked
```

## ContextCellEnvelope

Independent working context for one role. Context cells exist to protect
long-horizon intent from implementation-token churn, to keep implementation
details out of high-level state until summarized, and to allow review with a
fresh bounded context. Agent-to-agent conversation is allowed only when it is a
typed handoff between cells.

```yaml
ContextCellEnvelope:
  context_cell_id: context_cell://...
  goal_ref: goal://...
  outcome_room_ref: outcome-room://... | null
  participant_lease_ref: participant-lease://... | null
  role:
    conductor | implementer | reviewer | verifier | operator |
    researcher | specialist | synthesizer | resource_provider |
    integrity_challenger | memory_curator
  harness_ref: harness_profile:... | agent_harness_adapter:... | null
  model_route_ref: model_route://... | null
  memory_projection_refs:
    - memory_projection://... | wiki://...
  context_lease_refs:
    - context_lease://... | lease://...
  authority_scope_refs:
    - authority://... | policy://...
  compression_policy_ref: policy://... | null
  current_claim_ref: work-claim://... | null
  next_wake_condition_ref: policy://... | event://... | null
  status:
    open | active | sleeping | waiting | handed_off | summarized |
    quarantined | closed | revoked
```

## ContextLeaseEnvelope

Scoped lease that lets a Context Cell or harness invocation use only the context,
tools, memory, files, runtime, authority, and budget required for its bounded
role. Context leases make context a governed resource instead of dumping the
entire conversation, wiki, repo, connector estate, or authority envelope into
every harness.

```yaml
ContextLeaseEnvelope:
  context_lease_id: context_lease://...
  goal_ref: goal://...
  context_cell_ref: context_cell://...
  issued_to:
    harness_profile:... | agent_harness_adapter:... | worker://... |
    agent://... | service://...
  lease_kind:
    canon | repo_slice | worktree | memory_projection | tool |
    connector | runtime | authority | budget | surface | receipt_view |
    mixed
  allowed_ref_patterns:
    - docs/architecture/... | apps/... | crate://... | memory_projection://... |
      tool://... | connector://... | authority://... | receipt://...
  denied_ref_patterns:
    - secret://... | unrelated_path://... | unsafe_plaintext://...
  authority_scope_refs:
    - authority://... | policy://...
  budget_ref: budget://... | null
  ttl_seconds: integer | null
  receipt_required: boolean
  status: draft | active | expired | revoked | consumed
```

## ContextHandoffEnvelope

Typed packet between context cells. Handoffs are the durable substrate for
conductor/implementer/reviewer workflows; they should contain enough state for
the receiving cell to act without inheriting the sender's entire context window.

```yaml
ContextHandoffEnvelope:
  handoff_id: handoff://...
  goal_ref: goal://...
  from_context_cell_ref: context_cell://...
  to_context_cell_ref: context_cell://...
  handoff_kind:
    task_brief | implementation_result | blocker | diff_summary |
    test_result | review_request | verification_result |
    attempt_result | finding | resource_request | capability_offer |
    frontier_update | verifier_challenge | decision_request |
    continuation_summary
  payload_ref:
    task_brief://... | implementation_result://... | artifact://... |
    work-result://... | finding://... | resource-offer://... |
    capability-offer://... | verifier-challenge://... | message://... | null
  context_lease_refs:
    - context_lease://...
  acceptance_refs:
    - rubric://... | gate://... | test://...
  receipt_refs:
    - receipt://... | ledger://...
  status: draft | sent | accepted | rejected | superseded
```

## TaskBriefPayloadEnvelope

Normalized payload for bounded implementation, research, review, repair,
specialist, resource, synthesis, or verification work. The conductor may
render this as a prompt for a specific harness, but the durable contract is
this task brief, not the rendered prompt. Software-specific fields are one
output profile rather than the generic result contract.

```yaml
TaskBriefPayloadEnvelope:
  task_brief_id: task_brief://...
  goal_ref: goal://...
  handoff_ref: handoff://...
  objective: string
  objective_class:
    implement | repair | review | verify | inspect | research |
    reproduce | synthesize | curate | challenge | provide_resource |
    ontology_change | incident_response | service_delivery |
    physical_mission | refactor | ui_check | release_check | custom
  scope_refs:
    - project://... | file://... | route://... | surface://... |
      artifact://... | receipt://...
  canon_refs:
    - canon://... | doc://...
  constraints:
    - string
  do_not_touch_refs:
    - file://... | module://... | policy://...
  acceptance_refs:
    - rubric://... | test://... | gate://...
  verification_plan_refs:
    - verifier_path://... | test://... | script://...
  context_lease_refs:
    - context_lease://...
  output_contract:
    result_profile:
      software_implementation | research | ontology_mutation |
      incident_resolution | service_delivery | physical_mission |
      review | evaluation | custom
    work_result_required: boolean
    outcome_delta_required: boolean
    finding_refs_required: boolean
    changed_files_required: boolean
    diff_summary_required: boolean
    tests_required: boolean
    blocker_report_required: boolean
    receipt_refs_required: boolean
  status: draft | issued | superseded | revoked
```

## HarnessInvocationEnvelope

Daemon-mediated invocation of a selected HarnessProfile or Agent Harness
Adapter. This is the object that removes the human copy-paste relay: a
ContextHandoff becomes a HarnessInvocation, the adapter renders the harness
native prompt or command privately, and the daemon records normalized events,
artifacts, receipts, and final result.

```yaml
HarnessInvocationEnvelope:
  harness_invocation_id: harness_invocation://...
  goal_ref: goal://...
  handoff_ref: handoff://...
  context_cell_ref: context_cell://...
  task_brief_ref: task_brief://...
  harness_ref: harness_profile:... | agent_harness_adapter:...
  model_route_ref: model_route://... | null
  runtime_ref: runtime://... | environment://... | session://... | null
  context_lease_refs:
    - context_lease://...
  adapter_rendering_ref: artifact://... | null
  event_refs:
    - harness_event://...
  result_ref: work-result://... | implementation_result://... | null
  receipt_refs:
    - receipt://... | ledger://...
  status:
    queued | running | waiting_on_harness | waiting_on_conductor |
    completed | failed | cancelled | superseded
```

## HarnessAdapterEventEnvelope

Normalized event emitted by a harness adapter during a HarnessInvocation.
Harnesses may stream text, tool calls, terminal output, file writes, browser
events, or provider-specific state; the adapter must translate them into common
events before they become durable coordination evidence.

```yaml
HarnessAdapterEventEnvelope:
  harness_event_id: harness_event://...
  harness_invocation_ref: harness_invocation://...
  goal_ref: goal://...
  event_kind:
    started | stdout | stderr | thought_summary | tool_proposed |
    tool_started | tool_completed | file_changed | patch_created |
    test_started | test_completed | blocker | decision_request |
    artifact_created | attempt_updated | finding_proposed |
    outcome_delta_proposed | verifier_challenge_proposed |
    resource_requested | frontier_update_proposed |
    receipt_emitted | completed | failed
  payload_ref: artifact://... | message://... | null
  normalized_observation_ref: observation://... | null
  receipt_refs:
    - receipt://...
  redaction_policy_ref: policy://... | null
  timestamp: iso8601
```

## ImplementationResultPayloadEnvelope

Software-implementation profile of `WorkResultEnvelope` returned from a
HarnessInvocation. The conductor consumes this object, not a copied chat
response. It is intentionally bounded: enough evidence to verify, repair,
continue, or close; not the implementer's full context. Research, ontology,
incident, service, physical-mission, review, and evaluation results use the
generic WorkResult/OutcomeDelta seam rather than overloading changed files.

```yaml
ImplementationResultPayloadEnvelope:
  implementation_result_id: implementation_result://...
  goal_ref: goal://...
  harness_invocation_ref: harness_invocation://...
  handoff_ref: handoff://...
  work_result_ref: work-result://... | null
  attempt_ref: attempt://... | null
  status: completed | failed | blocked | partial | superseded
  changed_file_refs:
    - file://... | artifact://...
  patch_refs:
    - artifact://... | diff://...
  test_result_refs:
    - test://... | receipt://...
  blocker_refs:
    - blocker://... | handoff://...
  decision_request_refs:
    - handoff://...
  artifact_refs:
    - artifact://...
  receipt_refs:
    - receipt://... | ledger://...
  summary_ref: message://... | artifact://... | null
  next_recommended_handoff_kind:
    none | repair | review | verify | ask_user | escalate
```

## VerifierPathEnvelope

Defines the selected verification shape for a plan, run, worker, route, or
package. Verifier paths are evidence contracts; model judges are allowed, but
they are not truth by themselves.

The default verifier path for ordinary goal work may be conductor-run
deterministic verification: tests, diffs, browser evidence, source checks,
receipt inspection, and acceptance-criteria reconciliation. Independent verifier
harnesses are escalation paths, not the default requirement.

```yaml
VerifierPathEnvelope:
  verifier_path_id: verifier_path://...
  owner_ref: org://... | system://... | domain://... | null
  applies_to:
    - goal://... | run://... | worker://... | model_route://... |
      package://... | orchestration_plan://... | outcome-room://... |
      attempt://... | finding://...
  verifier_rule_version_ref: rubric://... | policy://... | gate://...
  verification_kind:
    deterministic | test | static_analysis | browser_evidence |
    model_judge | verifier_worker | human_review | benchmark |
    regulated_review | physical_safety | hybrid
  required_evidence_refs:
    - artifact://... | receipt://... | gate://... | benchmark://...
  verifier_refs:
    - worker://... | model://... | gate://... | org://...
  acceptance_threshold_ref: rubric://... | gate://... | policy://...
  independence_requirement:
    none | different_model | different_harness | different_worker |
    human | regulated_party
  replay_required: boolean
  challenge_refs:
    - verifier-challenge://...
  status:
    draft | active | challenged | reverifying | satisfied |
    failed | superseded | revoked
```

## Orchestration Decision Receipt Registration

The shared object canon owns `OrchestrationConstraintEnvelope`,
`OrchestrationPolicyEnvelope`, and `OrchestrationPlanEnvelope`. The canonical
`OrchestrationDecisionReceipt` field schema and receipt-type registration are
owned solely by
[`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md).
That receipt records why a coordinator selected a plan under declared
constraints, policy, candidates, evidence, fallback, and verifier posture. It
is distinct from `RoutingDecisionEnvelope`, which records Worker/domain/route
selection, and it does not prove that either decision was globally optimal or
correct.

## BenchmarkEnvelope

```yaml
BenchmarkEnvelope:
  benchmark_run_id: bench_...
  worker_id: worker://...
  worker_composition_ref: package://... | ai://... | null
  model_route_ref: model_route://... | null
  harness_ref: harness_profile:... | agent_harness_adapter:... | null
  runtime_profile_ref: runtime://... | profile://... | null
  privacy_posture_ref: privacy_posture://... | policy://... | null
  verifier_path_ref: verifier_path://... | null
  sparse_worker_category: string
  benchmark_profile_ref: benchmark://...
  environment_hash: hash
  manifest_hash: hash
  policy_hash: hash
  score_commitment: hash
  evaluator_id: worker://... | verifier://...
  evaluation_receipt_root: hash
  routing_eligibility_result: eligible | ineligible | suspended
```

## RoutingDecisionEnvelope

`RoutingDecisionEnvelope` is the neutral, replayable selection record. It
commits not only to the candidate set but also to affiliations, first-party or
subsidized seed supply, the selected Worker composition and its mounted
dependencies, every admitted route attempt, fallback/escalation, and verifier
posture. A selection receipt can attest this decision boundary; it cannot prove
that the chosen route was globally optimal or independent without the declared
evidence.

```yaml
RoutingDecisionEnvelope:
  routing_decision_id: routing-decision://...
  task_id: task://...
  goal_and_room_refs:
    - goal://... | outcome-room://...
  router_id: worker://... | runtime://... | system://... | domain://...
  intent_hash: hash
  candidate_set_commitment: hash
  candidate_affiliation_commitment: hash
  candidate_affiliation_and_ownership_evidence_refs:
    - evidence://... | receipt://... | org://... | provider://...
  routing_policy_hash: hash
  selected_domain_or_worker: system://... | domain://... | worker://... | service://... | runtime://...
  selected_worker_composition_ref: package://... | ai://... | worker://... | null
  selected_model_provider_runtime_refs:
    - model://... | model_route://... | provider://... | runtime://... |
      node://... | model-route-contract://...
  attempted_route_refs:
    - route-attempt://... | route-chain://...
  actual_attempt_refs:
    - route-attempt://... | attempt://... | work-result://... | receipt://...
  authority_scope: []
  cost_bound_ref: cost://... | budget://... | quote://... | null
  reason_codes:
    - quality | cost | privacy | latency | locality | installed_status |
      benchmark_result | authority_fit | user_preference | safety |
      independence | affiliation | seed_supply | fallback_availability
  fallback_policy_ref: policy://... | null
  fallback_or_escalation_refs:
    - route-chain://... | route-attempt://... | decision://... | receipt://...
  verifier_escalation_refs:
    - verifier_path://... | verifier-challenge://... | worker://... |
      decision://... | receipt://...
  contributor_scope: my_workers | organization | network_open
  contribution_policy_ref: policy://...
  seed_supply_and_independence_evidence_refs:
    - evidence://... | receipt://... | benchmark://... | certification_claim://...
  receipt_obligations: []
  routing_decision_receipt_ref: receipt://... | null
  signature: optional
```
