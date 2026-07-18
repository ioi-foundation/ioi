# Common Objects and Envelopes

Status: canonical low-level reference.
Canonical owner: this file for shared envelope and contract names, ID namespaces, principal refs, primitive capability tiers, authority grants, reusable GoalRun-profile, workflow-template, and skill-manifest contracts, bounded-autonomous-system package/genesis/constitution/deployment/membership/finality/recovery/oracle/lifecycle/enrollment/transition/service/settlement fields, dispute rail profile/value-unit/case/resolution fields, bounded-improvement governance/agenda/campaign/evaluation/exposure/evidence/cutoff fields, conditional-cooperation terms and participation fields, room admission fields, AIIP standards bindings, pre-AIIP local-agent pairing fields, native embodied graph/profile/component/stream/adapter/policy/world/action/activation/reservation/deployment-assurance fields, and receipt/run/event envelope fields.
Supersedes: older flattened capability-tier examples in plans/specs.
Superseded by: none.
Last alignment pass: 2026-07-17.
Doctrine status: canonical
Implementation status: mixed (the registered architecture-contract substrate supplies schemas, invariants, adversarial fixtures, and generated Rust/TypeScript projections for `ReceiptEnvelope` v1, `ReceiptCheckpoint` v1, `ReceiptProofBundle` v1, `AuthorityGrantEnvelope` v1/v2, `AuthorityKeySet` v1, `AuthorityRevocationSnapshot` v1, `InformationFlowLabel` v1, `DeclassificationApproval` v1, `ManagedWorkBillingLedgerBundle` v1, `DisputeRailBundle` v1, and `PhysicalActionExecutionReceipt` v1; production portable-authority and receipt-proof cryptographic verifiers/CLIs, information-flow enforcement, managed-work billing and dispute kernels, shared work-lifecycle persistence/routes, physical execution, daemon/Agentgres checkpoint emission, network key discovery, and public transparency remain planned; other core runtime envelopes and IDs are built or partial only where their owner routes exist; bounded-autonomous-system profile/control families, bounded-improvement Agenda/Campaign/Epoch/exposure/claim spine, conditional-cooperation terms, local-agent pairing, AIIP transport/bindings and collaborative-pursuit, optional federated ontology/action, Institutional Learning Boundary, NetworkGoalBudget, physical-segment, embodied, cTEE, and prediction families remain planned or speculative)
Last implementation audit: 2026-07-18

## Purpose

This file defines the shared low-level objects that every IOI/Web4 component
must understand. The goal is to prevent split-brain API design between
`@ioi/agent-sdk`, IOI ADK, IOI ODK, IOI CLI/headless, optional TUI, Hypervisor
Developer Workspace, Workflow Compositor, Hypervisor, Hypervisor Daemon, Agentgres,
wallet.network, aiagent.xyz, sas.xyz, harness profiles, benchmarks,
hosted/self-hosted workers, and IOI L1 contracts.

## Canonical Envelope and Shared Contract Types

```text
ManifestEnvelope
WorkflowTemplateEnvelope
SkillManifestEnvelope
SkillEntryEnvelope
ActiveSkillSetSnapshotEnvelope
AutonomousSystemManifestEnvelope
AutonomousSystemGenesisEnvelope
AutonomousSystemConstitutionEnvelope
ImprovementGovernanceProfileEnvelope
AutonomousSystemDeploymentProfileEnvelope
AutonomousSystemNodeMembershipEnvelope
AutonomousSystemFailoverProfileEnvelope
OrderingFinalityRecoveryEnvelope
OrderingAdmissionFinalityProfileEnvelope
OracleEvidenceProfileEnvelope
LifecycleContinuityProfileEnvelope
LifecycleTransitionEnvelope
IOINetworkEnrollmentEnvelope
AutonomousSystemChainEnvelope
HypervisorNodeEnvelope
BoundedExecutionDomainEnvelope
ServiceModuleManifestEnvelope
ModuleInvocationEnvelope
UpgradeProposalEnvelope
UpgradeDecisionEnvelope
ImprovementAgendaEnvelope
ImprovementCampaignEnvelope
EvaluationEpochEnvelope
EvaluationExposureLedgerEnvelope
ImprovementEvidenceClaimEnvelope
ImprovementOrderCutoffReceiptEnvelope
StateTransitionCommitmentEnvelope
LocalAgentPairingSessionEnvelope
AIIPChannelEnvelope
AIIPEnvelope
AIIPExternalProtocolBindingEnvelope
CollaborationTermsEnvelope
MultiPartyCollaborationEnvelope
CapabilityDescriptorEnvelope
TaskOfferEnvelope
TaskAcceptanceEnvelope
HandoffEnvelope
ReceiptCommitmentEnvelope
DeliveryUpdateEnvelope
AcceptanceDecisionEnvelope
SettlementIntentEnvelope
DisputeValueUnitBinding
DisputeRailProfileEnvelope
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
NetworkServiceInvocationEnvelope
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
LearningSourceRightsClaimEnvelope
InstitutionalLearningBoundaryProfileEnvelope
PolicyBoundDataViewEnvelope
TransformationRunEnvelope
DistilledOntologyDatasetEnvelope
EvaluationDatasetEnvelope
LearningEvidenceEligibilityEnvelope
InstitutionalIntelligenceExportBundleEnvelope
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
WorldRepresentationManifest
NativeEmbodiedRuntimeProfile
EmbodimentAdapter
EmbodiedActionPolicyContract
EmbodiedComponentContract
PhysicalStreamContract
EmbodiedRuntimeGraphManifestEnvelope
EmbodiedGraphActivationTransaction
EmbodiedActionChunk
SpacetimeReservationLease
EmbodiedDeploymentAssuranceCase
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
GoalRunProfileEnvelope
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
WorkLifecycleRecordEnvelope
WorkLifecycleArchiveSegmentEnvelope
WorkLifecycleSnapshotEnvelope
CancellationFanoutPlanEnvelope
GoalRunEnvelope
GoalGroundingLoopEnvelope
RoleTopologyEnvelope
ContextCellEnvelope
ContextLeaseEnvelope
ContextHandoffEnvelope
TaskBriefPayloadEnvelope
HarnessInvocationEnvelope
AgentHarnessAdapterEnvelope
HarnessAdapterEventEnvelope
ImplementationResultPayloadEnvelope
VerifierPathEnvelope
BenchmarkEnvelope
RoutingDecisionEnvelope
```

## Common ID Conventions

```text
ai://...                global intelligence/app/worker/service namespace
system://...            stable bounded logical autonomous-system identity across package releases and member nodes
package://...           reusable Autonomous System Package identity and immutable release-manifest identity
genesis://...           one logical system's constitution/profile binding and initial transition identity
domain://...            bounded execution domain, application domain, or sovereign domain namespace
org://...               organization, enterprise, DAO, regulator, auditor, provider, or institutional party identity
user://...              human user, operator, sponsor, or accountable individual identity
project://...           governed project or workspace-project identity
object-set://...        governed ontology object-set identity or saved typed object scope
policy://...            versioned policy, admission rule, obligation set, or governance profile identity
invariant://...         versioned machine-checkable invariant or safe-set requirement identity
schema://...            versioned data, event, payload, receipt-profile, or interface schema identity
event://...             durable or referenced event identity
intent://...            declared user, service, autonomous-work, or physical-action intent identity
node://...              Hypervisor Node or runtime node namespace
module://...            governed service-module namespace
invocation://...        module invocation namespace
proposal://...          upgrade, policy, module, workflow, or settlement proposal namespace
authority-request://... explicit portable authority-scope request identity
transition://...        accepted local state-transition namespace
state://...             referenced operational, environment, world, or domain state identity
constitution://...      autonomous-system constitutional boundary and amendment lineage
improvement-governance-profile://... immutable bounded-improvement admission and promotion policy profile
deployment-profile://... desired autonomous-system topology and continuity profile
node-membership://...   observed governed node membership in one logical system
failover-profile://...  writer-fencing, promotion, and continuity target identity
ordering-recovery://... profile-native threshold, BFT, membership, or external-finality recovery transition
ordering-profile://...  ordering, admission, and finality profile identity
oracle-evidence-profile://... external-fact and evidence policy identity
lifecycle-profile://... continuity, succession, migration, and dissolution policy identity
lifecycle-transition://... receipted lifecycle transition identity
work-lifecycle://...    append-only phase-transition or child-reference fact for one owned work object
work-lifecycle-archive://... immutable compacted work-lifecycle record segment
work-lifecycle-snapshot://... rebuildable work-lifecycle projection and replay checkpoint
network-enrollment://... explicit IOI Network enrollment identity
network://...           chain, settlement, or shared-security network identity
chain://...             external or IOI chain identity when distinct from a network service
contract://...          deployed or versioned settlement, rights, escrow, or application contract identity
account://...           declared payment, custody, provider, or settlement account identity
tx://...                external ledger or chain transaction identity
commitment://...        content, state-root, registry, rights, reputation, governance, or public anchor commitment identity
network-service-invocation://... selected registry, rights, reputation, or finality service invocation identity
contribution://...      attributable work, resource, verification, or knowledge contribution identity
failure-domain://...    independent host, rack, zone, region, provider, operator, or correlated-failure domain identity
worker-registration://... private, organization, or public Worker registration identity
agentgres://...         Agentgres domain, operation, object, projection, or state-root ref
provenance://...        source, derivation, observation, attribution, or lineage record identity
prompt://...            policy-governed prompt/template artifact identity; never raw secret transport
surface://...           registered product, application, operator, or generated surface identity
hypervisor-workspace://... stable Hypervisor core-workspace registration identity; distinct from code or private workspaces
route-alias://...       typed route-alias registration with one owner and a static target or fail-closed resolver
ui-primitive://...      reusable source-neutral Hypervisor UX primitive identity; never a product registration by itself
surface-descriptor://... ontology-bound surface descriptor identity; never launchability or product-membership authority by itself
surface-serving://...   serving route/runtime binding for one admitted surface installation or System interface
route://...             generic non-model route, path, or routing-candidate identity
verifier://...          verifier identity when a Worker, organization, or gate ref is not the subject
decision://...          policy, admission, acceptance, routing, merge, or adjudication decision identity
acceptance://...        explicit delivery, result, service, or outcome acceptance identity
dispute://...           challenge and dispute lifecycle identity
effect://...            declared external, business, digital, or physical effect identity
aiip://channel/...      AIIP channel namespace
packet://...            AIIP packet namespace
aiip-binding://...      versioned external-protocol-to-AIIP binding identity
local-agent-pairing://... short-lived pre-AIIP pairing session for an already-running user-owned local agent or harness
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
composition://...       exact versioned WorkerComposition identity binding model, harness, tools, runtime, policy, and dependency posture
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
control-segment://...  bounded independently enforced local real-time control interval
physical_mission_envelope://... bounded slow-plane embodied mission authority envelope
settlement-intent://... AIIP settlement intent namespace
settlement://...        concrete local, bilateral, invoice, escrow, external-chain, or IOI L1 settlement record
delivery://...          service delivery, delivery update, or cross-domain outcome delivery identity
evidence://...          evidence bundle, proof bundle, or admitted evidence identity
redacted_summary://...  redacted summary identity for shareable context without raw payload
revocation://...        authority, party, client, connector, view, or collaboration revocation identity
ioi://publisher/...     publisher identity
agent://...             product-facing agent instance or compatibility worker instance
worker://...            worker package or worker type
install://...           worker, service, package, application-surface, or System-interface install/license binding
package://...           worker, model, service, autonomous-system, or embodied capability package identity
subscription://...      runtime or managed-instance subscription/entitlement
runtime-assignment://... governed placement decision for one bounded unit of work
service://...           sas.xyz service definition
order://...             sas.xyz service order or cross-domain outcome order
run://...               runtime run identity
task://...              task identity
goal://...              ioi.ai or coordinator goal identity
goal-run-profile://...  reusable immutable pursuit-profile family or content-addressed revision
improvement-agenda://... immutable governed improvement-portfolio family or revision
improvement-campaign://... optional multi-epoch improvement domain lifecycle
evaluation-epoch://...  frozen utility, verifier, holdout, and statistical contract for one campaign epoch
evaluation-exposure://... append-only adaptive-evaluation exposure ledger
improvement-evidence://... immutable bounded-improvement evidence claim
outcome-plan://...      ioi.ai read-projection identity over one exact OrchestrationPlan revision
attempt-summary://...   product projection summarizing one admitted or proposed attempt
outcome-graph://...     cross-session Goal Space outcome graph projection identity
connector-escalation://... typed connector connection, scope, or approval escalation identity
mission://...           legacy presentation alias resolving to exactly one goal://... or outcome-room://... subject; never canonical truth
automation://...        Hypervisor AutomationSpec identity
automation-run://...    one Hypervisor AutomationRun activation identity
capability-request://... request for bounded executable capability or authority evaluation
approval-request://...  typed request for human, policy, wallet, or governance approval
goal_loop://...         goal grounding loop identity for conductor orientation and continuation
workflow-template://... reusable immutable directed-work template family or revision
workflow://...          admitted or proposed directed-work graph identity
skill://...             immutable reusable skill family or content-addressed revision
skill-entry://...       successor-versioned owner-scoped binding to one skill revision; registry lifecycle is mutable
active-skill-set://...  exact run-scoped daemon-admitted active skill snapshot
harness-profile://...   immutable content-addressed scoped-step resolver profile identity
agent-harness-adapter://... immutable content-addressed external agent-harness bridge identity
role_topology://...     immutable selected role topology revision for one admitted work subject
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
training://...          worker/model training lifecycle or run identity
post-training-cycle://... post-training evaluation, promotion, rollback, or recall cycle identity
context-mutation://...  versioned context/skill/memory mutation identity
promotion://...         governed capability/package/route promotion decision identity
rubric://...            evaluation rubric identity
ontology://...          domain ontology identity
semantic-profile://... versioned negotiated semantic compatibility profile identity
object-model://...      canonical object model identity
data-recipe://...       immutable DataRecipe family or content-addressed revision
recipe://...            legacy typed DataRecipe compatibility alias; never a generic RecipeEnvelope
development-environment-recipe://... Hypervisor development-environment construction recipe identity
session-launch-recipe://... Hypervisor session-launch composition recipe identity
mapping://...           connector mapping identity
view://...              policy-bound data view identity
dataset://...           evaluation or training dataset identity
dataset_snapshot://...  immutable dataset materialization, split, manifest, and lineage identity
eligibility://...       learning-evidence eligibility or exclusion identity, including training
learning-source-rights://... evidence-backed source-rights assertion used by institutional-learning policy
learning-boundary://... versioned Institutional Learning Boundary profile and immutable run snapshot identity
institutional-intelligence-export://... governed institutional-intelligence portability bundle identity
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
terms://...             versioned collaboration, provider, model, service, license, or commercial terms identity
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
embodied-resource-group://... stable logical identity for a named same-system sensor/actuator composition
embodied-resource-group-revision://... immutable admitted membership revision of an embodied resource group
embodied-runtime-graph-manifest://... immutable compiled native embodied reactive-execution graph identity
graph-activation-transaction://... local transactional activation identity for one exact embodied graph revision
physical-stream-contract://... immutable semantic, timing, security, and delivery contract for one physical stream
embodied-action-policy-contract://... immutable physical action-policy interface and runtime contract identity
embodied-action-chunk://... non-authoritative finite candidate physical-action chunk identity
spacetime-reservation-lease://... expiring lease over bounded physical occupancy in a declared frame and interval
fleet-mission-coordination://... same-system distributed embodied-work coordination identity
fleet-mission-allocation-lease://... epoch- and expiry-bound embodied work allocation identity
coordination-cell://... derived fenced same-system embodied coordination partition identity
robot://...             robot or humanoid embodied-unit identity
drone://...             aerial, marine, or other drone embodied-unit identity
facility-system://...   canonical facility, workcell, or fixed embodied-system unit identity
facility_system://...   read-only legacy alias for facility-system://...; never emitted by new writes
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
physical_map://...      admitted physical map identity
zone://...              admitted physical zone, geofence, or operating region identity
frame://...             physical coordinate-frame identity
environment_state://... freshness-bounded live embodied environment-state identity
world_representation://... visual, geometric, semantic, or physics-proxy world representation identity
world-representation-manifest://... immutable layered world-representation contract identity
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
local_control_supervisor://... native independent local physical-command enforcement identity
heartbeat_policy://...  heartbeat and fail-closed policy identity
runtime_guarantee://... admitted embodied timing, degraded-network, and offline guarantee identity
physical_command_queue://... physical command queue identity
physical_command://...  movement, manipulation, facility, stop, or handoff command identity
telemetry_stream://...  physical telemetry stream identity
telemetry_frame://...   one time- and sequence-bound physical telemetry frame identity
telemetry_range://...   bounded time/sequence range within a physical telemetry stream
physical_replay://...   physical replay bundle identity
sim_to_real_gate://...  sim-to-real promotion gate identity
embodied_incident://... embodied-runtime incident identity
operator_handoff://... physical operator-handoff identity
fleet_policy://...      fleet-level physical coordination and safety policy identity
wiki://...              Agent Wiki or durable semantic-memory surface identity
memory://...            context-memory record or local memory-plane identity
memory-space://...      governed durable memory-space identity
memory-entry://...      one portable memory-entry identity within a memory space
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
mcp-gateway-requirement://... immutable gateway capability and exposure requirement identity
connector://...         connector or external-system adapter identity
tool://...              typed tool or tool contract identity
mcp://...               MCP server, tool surface, or gateway-exposed MCP capability identity
session://...           Hypervisor session identity
work_queue://...        Hypervisor work-queue identity
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

New canonical documents and v2 APIs emit the URI-like `harness-profile://...`
and `agent-harness-adapter://...` forms. The historical
`harness_profile:...`, `harness-profile:...`, `agent_harness_adapter:...`,
`agent-harness-adapter:...`, and generic `harness://...` spellings are
compatibility inputs only. Boundary adapters may normalize them to the
canonical identity after validating object kind and exact revision; canonical
state and new receipts must not emit those aliases.

Canonical actor fields use the narrowest subset of this reusable principal
union and include `system://` whenever a bounded DAS may itself act:

```text
ProtocolPrincipalRef = system://... | user://... | wallet://... | org://... |
  project://... | domain://... | worker://... | agent://... | service://... |
  provider://... | policy://... | governance://...
```

`system://` names the accountable logical institution; `domain://` or
`agentgres://domain/...` names an admission/storage domain; worker, service,
agent, and provider refs name acting components or dependencies. One ref must
not be substituted for another to hide accountability, affiliation, or
admission.

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
  public_commitment: null | object
    service_kind: registry
    service_ref: service://...
    network_service_invocation_ref: network-service-invocation://...
    network_enrollment_ref: network-enrollment://... | null
    public_commitment_policy_ref: policy://...
    network_or_chain_ref: network://... | chain://...
    contract_ref: contract://... | null
    commitment_ref: commitment://...
    transaction_ref: tx://... | null
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

## Package Release And Live-System Genesis

Hypervisor's primary build artifact is an Autonomous System Package.

An Autonomous System Package is the reusable developer-facing skeletal unit for
autonomous-system work. It is not an agent, connector, workflow, daemon
process, policy bundle, live system identity, or node membership. It binds
worker responsibility, GoalRunProfile and WorkflowTemplate composition,
compatible step-resolution profiles, model and tool capabilities, authority
requirements, memory/state/artifact contracts,
evaluations, profile templates and constraints, and receipt obligations into
one packageable release.

Implementation may represent the package as a strict `ManifestEnvelope` profile,
as `AutonomousSystemManifestEnvelope`, or as both. That implementation choice
must not make the package concept invisible in product, SDK, ADK, CLI/headless,
workflow, or documentation surfaces.

Package/release lifecycle and live-system lifecycle are deliberately separate:

```text
package: compose -> bind requirements -> simulate/evaluate -> package -> sign
         -> release -> promote -> deprecate or revoke

system:  instantiate/genesis -> authorize -> activate -> run -> improve
         -> recover, migrate, fork, adopt, succeed, dissolve, retire,
            archive, or decommission
```

Evaluation runs may instantiate disposable development or test systems and bind
their receipts back to a package release. The package itself never becomes
`active`, owns operational state, joins a network, fails over, succeeds, or
dissolves. `AutonomousSystemGenesisEnvelope` is the only object that binds one
selected release to a new stable `system_id`, active constitution, initial
profiles, initial state/receipt roots, and activation authority. An existing
system adopts another release through a governed upgrade; it does not create a
second genesis or change `system_id`.

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
| Autonomous System Package | The reusable developer-facing build artifact binding worker responsibility, topology, capabilities, authority requirements, memory/state/artifact contracts, evals, profile templates/constraints, and receipt obligations. | A raw workflow file, connector config, daemon process, live system identity, or node membership. |
| AutonomousSystemManifest | The immutable release-manifest contract that makes an Autonomous System Package deterministic, portable, evaluable, and receipted. | A live system, second runtime, or React Flow truth store. |
| AutonomousSystemGenesis | The one-time binding of a selected package release to a new `system_id`, constitution, initial active profiles, authority decision, and cryptographic initial state. | A package publication, ordinary upgrade, node join, or network enrollment. |
| Worker | Durable protocol actor, responsibility boundary, package identity, routing target, and event/receipt subject. | Merely a UI label for a chat agent. |
| Agent | Product-facing instance or compatibility alias that may be worker-backed. | The canonical low-level actor when Worker is required. |
| WorkflowTemplate | Immutable, versioned Workflow-Compositor definition of directed graph shape, typed steps, dependencies, review points, acceptance, and delivery. | A trigger-bearing AutomationSpec, a live run, adaptive pursuit state, a harness loop, or React Flow canvas state. |
| Workflow | Proposed or admitted executable graph materialized from a WorkflowTemplate or authored directly under the same compositor contracts. | Hidden product state, a standing activation, or the React Flow canvas itself. |
| GoalRunProfile | Immutable, content-addressed composition describing how a class of adaptive goals should converge. | A GoalRun, orchestration super-object, executable, authority grant, workflow graph, campaign database, or domain-state owner. |
| HarnessProfile | Daemon-executed or daemon-mediated resolver for one scoped assigned step. | High-level workflow topology, reusable goal pursuit, a peer runtime, or persistent memory owner. |
| Capability | Primitive/model/tool feasibility and contract reference. | Authority, secret possession, or policy permission. |
| Authority | wallet.network grant or lease over resource, provider, identity, budget, approval, secret, and expiry for delegated machine power. | A capability flag, UI readiness badge, or every app-local permission. |
| Policy | Admission and behavior rules over authority, risk, approval, privacy, retention, evidence, and execution posture. | Tracing, telemetry, or run history. |
| Tool | Executable capability with schema, risk, primitive capability requirements, authority scopes, approval requirements, and receipt behavior. | Ambient connector access. |
| Connector | External system adapter exposing tools. | Runtime truth, authority owner, or untyped API access. |
| SkillManifest | Immutable, versioned instruction/resource/procedure and support-asset package that can influence context and reference admitted tools. | Authority grant, secret, executable tool by itself, marketplace listing, mutable installation, or active run snapshot. |
| Recipe | Product-facing or package-facing label for an owner-qualified reusable composition. | A generic canonical `RecipeEnvelope`, untyped `run-recipe:` identity, or excuse to erase DataRecipe, environment, session-launch, workflow, automation, or GoalRun-profile ownership. |
| Session | Current interaction or run context. | Long-term memory or package identity. |
| State | Scoped serializable working data. | Canonical domain truth unless settled through Agentgres/contracts. |
| Memory | Governed long-term recall or retrieval surface. | Unbounded hidden context. |
| Artifact | Materialized output, evidence, or deliverable. | A receipt by itself. |
| Event | Observation that something happened. | Durable proof of correctness. |
| Trace | Ordered diagnostic/observability path through runtime behavior. | Policy decision or authority grant. |
| Receipt | Durable proof of an action, decision, verification, artifact, authority use, or promotion outcome. | A log line or UI-only status. |
| Runtime | Daemon/runtime execution contract and event/receipt producer. | React Flow, a provider SDK, or a model-owned loop. |

### WorkflowTemplateEnvelope

`WorkflowTemplateEnvelope` is the Workflow Compositor's reusable directed-work
definition. A released revision is immutable and content-addressed. It may be
referenced by an `AutomationSpec`, a `GoalRunProfile`, a Package, or a typed
one-off `GoalRun`, `AutomationRun`, `WorkRun`, or Foundry job owner, but the
template never runs itself and owns no trigger, schedule, activation history,
live lease, or execution truth.

```yaml
WorkflowTemplateEnvelope:
  schema_version: ioi.workflow-template.v1
  workflow_template_id: workflow-template://...
  revision_ref: workflow-template://.../revision/...
  version: semver_or_hash
  predecessor_revision_ref: workflow-template://.../revision/... | null
  content_hash: hash
  owner_ref: org://... | project://... | system://... | user://... | domain://... | ioi://publisher/...
  display_name: string
  description: string
  graph_ref: workflow://... | artifact://... | cid://...
  graph_hash: hash
  parameter_schema_ref: schema://... | null
  input_contract_refs: []
  output_contract_refs: []
  step_contract_refs: []
  dependency_and_handoff_refs: []
  acceptance_and_review_contract_refs: []
  delivery_contract_ref: schema://... | policy://... | null
  selection_hint_refs:
    harness_profile_revision_refs: []
    model_route_refs: []
    worker_refs: []
    provider_refs: []
    verifier_path_refs: []
  runtime_tool_contract_requirement_refs: []
  required_primitive_capabilities: []
  authority_scope_requirement_refs: []
  resource_and_budget_requirement_refs: []
  receipt_policy_ref: policy://... | null
  allowed_override_schema_ref: schema://... | null
  provenance_refs: []
  evaluation_refs: []
  registry_lifecycle_ref: agentgres://object/... | package://.../release/... | null
  registry_status: draft | evaluable | released | deprecated | revoked
```

`selection_hint_refs` are constraints or reproducibility pins, not live
assignments. Daemon admission still resolves eligible workers, harnesses,
models, tools, authority, context, budget, and runtime placement. A patch to a
released template creates a successor revision; it never mutates an active
revision.

Capability, authority, resource, budget, and receipt fields are requirements
or ceilings only. A WorkflowTemplate never contains a concrete authority
grant, capability/context/resource lease, RuntimeAssignment, selected route,
trigger, or run state.

The revision body and `content_hash` are immutable. `registry_status` and
`registry_lifecycle_ref` are registry projections excluded from that content
hash; deprecation, recall, or revocation changes eligibility without rewriting
the released definition.

### SkillManifestEnvelope

`SkillManifestEnvelope` is the immutable reusable definition of a skill. It
supplies procedure and support material to a model, worker, or harness; it may
reference `RuntimeToolContract` capabilities but cannot execute them, carry
their credentials, or grant their authority.

```yaml
SkillManifestEnvelope:
  schema_version: ioi.skill-manifest.v1
  skill_id: skill://...
  revision_ref: skill://.../revision/...
  version: semver_or_hash
  predecessor_revision_ref: skill://.../revision/... | null
  content_hash: hash
  owner_ref: org://... | project://... | system://... | user://... | ioi://publisher/...
  display_name: string
  description: string
  instruction_entrypoint_ref: artifact://... | cid://...
  procedure_and_reference_refs: []
  example_refs: []
  support_asset_refs: []
  dependency_skill_revision_refs: []
  runtime_tool_contract_requirement_refs: []
  capability_requirement_refs: []
  input_and_output_contract_refs: []
  context_requirement_profile_refs: []
  compatible_goal_run_profile_revision_refs: []
  compatible_harness_profile_revision_refs: []
  compatible_runtime_and_kernel_refs: []
  provenance_refs: []
  source_rights_and_license_refs: []
  evaluation_and_benchmark_refs: []
  promotion_policy_ref: policy://... | null
  revocation_and_recall_policy_ref: policy://... | null
  registry_lifecycle_ref: agentgres://object/... | package://.../release/... | null
  registry_status: draft | evaluable | released | deprecated | revoked
```

Helper scripts may be support assets. Only an agent-callable capability that
crosses an execution/admission boundary requires a `RuntimeToolContract`;
internal helper files do not each become tools merely because a skill invokes
them behind one admitted capability.

The revision body and `content_hash` are immutable. `registry_status` and
`registry_lifecycle_ref` are registry projections excluded from that content
hash.

Commercial discovery is not another skill owner. A Packages/Marketplace
listing or room-scoped `CapabilityOffer` references the exact
`skill_revision_ref` and owns price, license offer, ranking, availability, and
commercial terms. Those fields do not enter `SkillManifest`.

### SkillEntryEnvelope

Each `SkillEntry` is an immutable successor-versioned installation/admission
binding for one organization, Project, workspace, System, or user scope. It
declares the binding's intended enablement posture; the registry projection
owns mutable current lifecycle status. The manifest remains immutable.

```yaml
SkillEntryEnvelope:
  schema_version: ioi.skill-entry.v1
  skill_entry_id: skill-entry://...
  binding_revision_ref: skill-entry://.../revision/...
  predecessor_binding_revision_ref: skill-entry://.../revision/... | null
  binding_hash: hash
  skill_revision_ref: skill://.../revision/...
  skill_manifest_content_hash: hash
  owner_scope_ref: org://... | project://... | system://... | user://...
  memory_space_ref: memory-space://... | null
  compatibility_decision_ref: decision://... | receipt://...
  configuration_ref: artifact://... | policy://... | null
  allowed_goal_run_profile_revision_refs: []
  policy_refs: []
  admitted_by_ref: user://... | org://... | system://...
  admission_receipt_ref: receipt://...
  revocation_ref: revocation://... | null
  registry_lifecycle_ref: agentgres://object/... | null
  registry_status: proposed | active | suspended | archived | revoked
```

`SkillEntry` contains no copied procedure body. Each binding revision is
immutable and `binding_hash` commits the exact manifest pin, owner scope,
effective configuration, policy, permitted profile set, and admitting actor.
Changing any of them creates a successor binding revision. Compatibility and
admission decision/receipt refs, revocation, and registry lifecycle/status are
excluded from the hash; they bind the already-computed binding hash and may
suspend or revoke use without rewriting the historical binding. The binding
revision owns the admitted local configuration and enablement declaration; the
registry projection owns mutable lifecycle status. Procedure, provenance,
dependencies, evaluation, promotion, and release recall remain on the manifest
and its referenced owner records.

### ActiveSkillSetSnapshotEnvelope

One admitted run receives an exact, reproducible snapshot of selected skill
revisions and installation bindings. This is live resolution state, not a
portable skill or marketplace asset.

```yaml
ActiveSkillSetSnapshotEnvelope:
  schema_version: ioi.active-skill-set-snapshot.v1
  active_skill_set_snapshot_id: active-skill-set://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  selected_skills:
    - skill_entry_ref: skill-entry://...
      skill_entry_binding_revision_ref: skill-entry://.../revision/...
      skill_entry_binding_hash: hash
      skill_revision_ref: skill://.../revision/...
      manifest_content_hash: hash
      inclusion_basis_refs: []
  excluded_candidates:
    - candidate_ref: skill://... | skill-entry://...
      reason_code: incompatible | policy_blocked | revoked | superseded | not_required | budget_blocked | other
      decision_ref: decision://... | receipt://...
  compatibility_and_evaluation_result_refs: []
  active_set_hash: hash
  resolved_runtime_tool_contracts:
    - revision_ref: tool://.../revision/...
      content_hash: hash
  context_lease_refs: []
  resolution_receipt_ref: receipt://...
  registry_lifecycle_ref: agentgres://object/... | null
  registry_status: admitted | active | superseded | revoked
```

Runtime hooks remain separately typed executable/admission machinery. A
combined implementation projection such as an active skill-and-hook manifest
must preserve that distinction and normalize to this active-skill-set object
plus separately owned hook bindings.

`active_set_hash` commits each exact SkillEntry binding revision/hash and
SkillManifest revision/hash, the excluded candidates, compatibility results,
resolved tool revisions/hashes, and ContextLease refs. The immutable
`resolution_receipt_ref` links that committed set to admission but is excluded
from the set hash so the receipt may include the snapshot ref/hash without a
self-referential commitment. `registry_lifecycle_ref` and `registry_status` are
also excluded projections; supersession or revocation changes eligibility/use
without rewriting what the run originally resolved.

`work_subject_ref` is mandatory. A snapshot with no exact admitted work binding
fails closed.

### AutonomousSystemManifestEnvelope

```yaml
AutonomousSystemManifestEnvelope:
  schema_version: ioi.autonomous-system-manifest.v1
  package_id: package://...
  manifest_id: package://.../release/...
  display_name: string
  description: string
  version: semver_or_hash
  predecessor_manifest_ref: package://.../release/... | null
  release_root: hash
  registry_status: draft | evaluable | package_ready | released | promoted | deprecated | revoked
  constitution_template_ref: artifact://... | cid://...
  required_profile_templates:
    deployment_template_ref: artifact://... | cid://...
    ordering_admission_finality_template_ref: artifact://... | cid://...
    oracle_evidence_template_refs: []
    lifecycle_continuity_template_ref: artifact://... | cid://...
    network_enrollment_constraint_ref: policy://...
  system_binding:
    allowed_use: instantiate_new | upgrade_existing | either
    compatible_constitution_constraint_ref: policy://...
    compatible_predecessor_release_roots: []
  worker:
    worker_revision_ref: worker://.../revision/...
    worker_content_hash: hash
    responsibility: string
    owner_ref: ioi://publisher/...
  typed_components:
    component_set_snapshot_ref: artifact://...
    component_set_hash: hash
    goal_run_profiles:
      - revision_ref: goal-run-profile://.../revision/...
        content_hash: hash
    workflow_templates:
      - revision_ref: workflow-template://.../revision/...
        content_hash: hash
    automation_specs:
      - revision_ref: automation://.../revision/...
        content_hash: hash
    harness_profiles:
      - revision_ref: harness-profile://.../revision/...
        content_hash: hash
    agent_harness_adapters:
      - revision_ref: agent-harness-adapter://.../revision/...
        content_hash: hash
    skill_manifests:
      - revision_ref: skill://.../revision/...
        content_hash: hash
    data_recipes:
      - revision_ref: data-recipe://.../revision/...
        content_hash: hash
    runtime_tool_contracts:
      - revision_ref: tool://.../revision/...
        content_hash: hash
    mcp_gateway_requirements:
      - revision_ref: mcp-gateway-requirement://.../revision/...
        content_hash: hash
  workflow_compatibility:
    default_workflow_template_revision_ref: workflow-template://.../revision/... | null
    default_workflow_template_content_hash: hash | null
    compatible_harness_profile_revision_refs: []
    topology_hash: string | null
  source_project:
    project_ref: optional
    repository_refs: []
    default_branch_or_ref: optional
    development_environment_recipe_ref: development-environment-recipe://.../revision/... | null
    development_environment_recipe_content_hash: hash | null
    issue_tracker_refs: []
    code_owner_refs: []
  interfaces:
    operator_console_descriptor_ref: optional
    generated_domain_app_descriptor_ref: optional
    api_contract_refs: []
    aiip_binding_requirement_refs: []
    publication_endpoint_contract_refs: []
  capabilities:
    model_capability_requirement_refs: []
    model_deployment_profile_refs: []
    capability_descriptor_refs: []
    connector_requirement_refs: []
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
      compatibility_requirement_ref: policy://... | profile://...
      cleanup_policy_ref: policy://... | null
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
    release_evaluation_receipt_refs: []
  release:
    publisher_signature_ref: receipt://... | evidence://...
    registry_published_at: timestamp | null
```

The envelope is a package/readiness and portability contract. It must compile
to daemon/runtime, wallet.network, Agentgres, workflow, connector/tool, and
receipt contracts; it must not bypass them.

Typed component tuples preserve each component's owner and exact immutable
revision/content hash. `release_root` commits the component-set snapshot and
hash; admission rejects any tuple or snapshot mismatch. A Package distributes
immutable definitions, templates, requirements, and compatibility pins; it
does not contain a concrete MCP gateway instance, ContextLease, authority
grant, RuntimeAssignment, ActiveSkillSetSnapshot, or other admission-bound
live object. The `mcp_gateway_requirements` tuples name exact immutable
requirements that constrain later resolution. Only an admitted GoalRun, Session,
AutomationRun, worker invocation, or live System binding may reference the
resulting `mcp_gateway://...` profile. Capability descriptors and connector
requirements are semantic or dependency constraints; they are not admitted
RuntimeToolContracts, connector account bindings, credentials, or provider
invocation permission.

The release body and `release_root` are immutable. `registry_status`,
`registry_published_at`, `publisher_signature_ref`,
`package_readiness_receipt_ref`, and any registry lifecycle projection are
excluded from that root; the signature and readiness receipt bind the
already-computed root. Fixed pre-release evaluation receipts may remain
committed only when they bind the exact component-set snapshot. The manifest carries interface descriptors and contracts,
runtime compatibility requirements, and fixed release-evaluation evidence—not
live endpoints, current readiness, installation enablement, or rolling
"latest" run/evaluation receipts. Those mutable facts belong to admitted
installations or System bindings, runtime/readiness projections, catalogs, and
their individual runs and receipts.

`runtime_profiles` describe compatible execution venues for modules and
workers. They do not describe the system's member-node topology, ordering,
failover, authority distribution, or finality; those belong to the deployment
and ordering templates above and become live only through genesis or a governed
upgrade.

### AutonomousSystemGenesisEnvelope

```yaml
AutonomousSystemGenesisEnvelope:
  schema_version: ioi.autonomous-system-genesis.v1
  genesis_id: genesis://...
  system_id: system://...
  package_id: package://...
  manifest_ref: package://.../release/...
  admitted_manifest_root: hash
  constitution_ref: constitution://...
  initial_profile_refs:
    deployment_profile_ref: deployment-profile://...
    ordering_admission_finality_profile_ref: ordering-profile://...
    oracle_evidence_profile_refs: []
    lifecycle_continuity_profile_ref: lifecycle-profile://...
    network_enrollment_ref: network-enrollment://... | null
  initial_component_bindings:
    admitted_component_set_snapshot_ref: artifact://...
    admitted_component_set_hash: hash
    goal_run_profiles:
      - revision_ref: goal-run-profile://.../revision/...
        content_hash: hash
    workflow_templates:
      - revision_ref: workflow-template://.../revision/...
        content_hash: hash
    automation_specs:
      - revision_ref: automation://.../revision/...
        content_hash: hash
    automation_installations:
      - binding_revision_ref: install://automation/.../revision/...
        binding_hash: hash
        admission_receipt_ref: receipt://...
    harness_profiles:
      - revision_ref: harness-profile://.../revision/...
        content_hash: hash
    agent_harness_adapters:
      - revision_ref: agent-harness-adapter://.../revision/...
        content_hash: hash
    skill_entries:
      - binding_revision_ref: skill-entry://.../revision/...
        binding_hash: hash
        skill_manifest_revision_ref: skill://.../revision/...
        skill_manifest_content_hash: hash
    data_recipes:
      - revision_ref: data-recipe://.../revision/...
        content_hash: hash
    runtime_tool_contracts:
      - revision_ref: tool://.../revision/...
        content_hash: hash
    mcp_gateway_profiles:
      - profile_revision_ref: mcp_gateway://.../revision/...
        profile_content_hash: hash
  instantiation:
    proposed_by: system://... | wallet://... | org://... | project://...
    decision_ref: decision://...
    authority_grant_refs: []
    conformance_receipt_refs: []
  cryptographic_origin:
    sequence: 0
    predecessor_commitment_ref: null
    genesis_operation_commitment: hash
    genesis_transition_commitment_ref: commitment://...
    initial_state_root: hash
    initial_receipt_root: hash
    admission_proof_ref: evidence://... | receipt://...
  activation_receipt_ref: receipt://... | null
  lifecycle_transition_refs: []
  status_source_receipt_refs: []
  created_at: timestamp
  status: proposed | authorized | activated | rejected | revoked
```

The genesis decision creates one logical system; it does not grant a node
ambient authority or activate optional network services. All live profile refs
must satisfy the new constitution's protected constraints. An enrollment ref is
valid only when its own service-selection and activation conditions pass.
Genesis `status` is a projection, not an independently mutable lifecycle. The
`initialize` and `activate` lifecycle transitions below are authoritative and
must bind this `genesis_ref`; their admitted genesis/activation receipts drive
the projected authorized/activated state.

The package may supply goal, workflow, skill, and gateway requirements, but
genesis records only definitions and bindings admitted for this System. A live
MCP gateway ref must name a separately admitted, subject- and scope-bound
profile; genesis cannot manufacture one by copying a package template.
`admitted_component_set_hash` commits every initial ref/hash tuple and must
match the admitted snapshot and activation receipt; package inclusion alone
does not activate a component. Each initially enabled AutomationSpec also
requires an exact System/owner-scoped AutomationInstallationBinding
revision/hash and its admission receipt in this set; the package remains
definition-only.

## Governed Autonomous-System Chain Envelopes

Governed autonomous-system chains are system-local, logically scoped stateful
execution objects, not necessarily single-node objects. They are not
necessarily standalone public blockchains or IOI L1s. Their accepted
operations and receipts live in Agentgres/domain state, while IOI L1 anchors
only roots selected by an explicit enrollment and settlement profile.

The logical system is constitution-bound and may span one or many admitted
nodes. Desired topology, observed membership, ordering/finality, external-fact
policy, lifecycle continuity, and optional IOI Network enrollment are separate
objects so node count cannot silently change authority or assurance.

### AutonomousSystemConstitutionEnvelope

```yaml
AutonomousSystemConstitutionEnvelope:
  schema_version: ioi.autonomous-system-constitution.v1
  constitution_id: constitution://...
  system_id: system://...
  version: semver_or_hash
  predecessor_constitution_ref: constitution://... | null
  constitution_root: hash
  declared_purpose:
    statement: string
    ontology_refs: []
    beneficiary_or_stakeholder_refs: []
    acceptance_policy_refs: []
  normative_constraints:
    invariant_refs: []
    permitted_objective_policy_refs: []
    prohibited_objective_policy_refs: []
    permitted_ontology_action_contract_refs: []
    prohibited_effect_policy_refs: []
  agency_boundary:
    authority_ceiling_scope_refs: []
    delegable_scope_refs: []
    non_delegable_scope_refs: []
    resource_and_budget_ceiling_policy_refs: []
    time_and_duration_ceiling_policy_refs: []
    data_and_privacy_ceiling_policy_refs: []
    effect_and_externality_ceiling_policy_refs: []
    egress_policy_ref: policy://...
    node_expansion: governed_membership_only
    code_propagation: admitted_deployment_only
    self_authority_widening: forbidden
  governance:
    governance_owner_refs: []
    accountable_principal_refs: []
    affected_party_policy_ref: policy://...
    ordinary_upgrade_policy_ref: policy://...
    amendment_mode: immutable | external_governance_only
    amendment_decision_profile_ref: policy://... | null
    protected_clause_refs: []
    agent_may_propose_amendment: boolean
    agent_may_commit_amendment: false
    emergency_pause_authority_refs: []
    revocation_authority_refs: []
  protected_profile_governance:
    improvement_governance_profile_ref:
      improvement-governance-profile://.../revision/... | null
    improvement_governance_profile_change_decision_profile_ref: policy://... | null
    deployment_constraint_ref: policy://...
    deployment_change_decision_profile_ref: policy://...
    ordering_admission_finality_constraint_ref: policy://...
    ordering_profile_change_decision_profile_ref: policy://...
    oracle_evidence_constraint_ref: policy://...
    oracle_profile_change_decision_profile_ref: policy://...
    lifecycle_continuity_constraint_ref: policy://...
    lifecycle_profile_change_decision_profile_ref: policy://...
    network_enrollment_constraint_ref: policy://...
    network_enrollment_change_decision_profile_ref: policy://...
  shutdown:
    kill_switch_ref: optional
    decommission_policy_ref: policy://...
    minimum_archive_policy_ref: policy://...
  activation_receipt_ref: receipt://... | null
  public_commitment_ref: commitment://... | settlement://... | tx://... | null
  status: draft | active | superseded | revoked
```

Purpose prose is explanatory; the referenced invariants, policies, ontology
action contracts, scopes, ceilings, and decision rules are normative. Ordinary
upgrades cannot amend protected purpose, authority ceilings, amendment gates,
improvement governance, ordering/finality, oracle, lifecycle, or shutdown
boundaries. A bounded system
can still pursue a harmful purpose: the constitution makes its declared and
enforceable bounds auditable; it does not prove benevolence.

The constitution protects constraints and decision paths, not one forever-
current mutable profile ID. Its improvement-governance profile constrains
campaign admission and promotion but does not grant a campaign authority or
declare its evidence valid. Package templates are deployment candidates;
genesis `initial_profile_refs` remain candidates while genesis is proposed or
authorized and become the first admitted live refs only when activation commits.
The live
`AutonomousSystemChainEnvelope` fields are the currently
admitted refs. Activation or later profile change must prove that each live ref
satisfies the constitutional constraint and was admitted through the matching
decision profile. Changing a live ref does not amend the constitution; changing
its constraint or decision path does.

A null improvement-governance profile disables ImprovementCampaign admission
and unattended target-generation for that System; it does not disable ordinary
owner-governed one-shot UpgradeProposals. Enabling the profile follows the
constitution's protected amendment/change path rather than an implicit default.

### ImprovementGovernanceProfileEnvelope

An accountable owner binds one immutable, owner-qualified policy profile for
bounded improvement. For a System, its constitution protects the selected
profile and change path. A user, project, or organization may bind the same
profile family for a non-System research Campaign, but that does not create a
System, constitution, or bounded-DAS conformance claim. The profile controls
whether the owner scope may admit Campaign work; it is not a campaign,
evaluator, authority grant, or promotion decision.

```yaml
ImprovementGovernanceProfileEnvelope:
  schema_version: ioi.improvement-governance-profile.v1
  improvement_governance_profile_id: improvement-governance-profile://...
  revision_ref: improvement-governance-profile://.../revision/...
  version: semver_or_hash
  predecessor_revision_ref:
    improvement-governance-profile://.../revision/... | null
  content_hash: hash
  owner_ref: user://... | org://... | project://... | system://...
  system_id: system://... | null
  mutable_target_allowlist_refs: []
  protected_target_refs: []
  protected_target_change_decision_profile_refs: []
  max_target_improvement_order: nonnegative_integer
  max_active_nested_campaign_depth: positive_integer
  max_unattended_target_generations: nonnegative_integer
  ancestor_reservation_policy_refs:
    resource_budget: policy://...
    statistical_risk_budget: policy://...
    evaluation_exposure_budget: policy://...
  campaign_admission_policy_ref: policy://...
  campaign_stop_policy_ref: policy://...
  evaluator_firewall_policy_ref: policy://...
  evaluator_independence_policy_ref: policy://...
  promotion_authority_policy_ref: policy://...
  irreversible_effect_recovery_policy_ref: policy://...
  registry_lifecycle_ref: agentgres://object/... | decision://... | null
  registry_status: draft | active | superseded | revoked
```

The revision body and `content_hash` are immutable; registry lifecycle and
status are projections outside that hash. Descendants reserve disjoint
resource, statistical-risk, and evaluation-exposure allowances from their
ancestors. Naming a higher target order or creating another GoalRun never
duplicates or resets those allowances. For a System-scoped profile,
replacement follows the constitution's protected change path; otherwise it
follows the owner scope's declared governance path. Either applies only to
newly admitted work unless an explicit pause, quarantine, or migration decision
says otherwise.

### AutonomousSystemDeploymentProfileEnvelope

```yaml
AutonomousSystemDeploymentProfileEnvelope:
  schema_version: ioi.autonomous-system-deployment-profile.v1
  deployment_profile_id: deployment-profile://...
  system_id: system://...
  constitution_ref: constitution://...
  manifest_ref: package://.../release/...
  version: semver_or_hash
  environment_class: development | test | staging | production | recovery
  environment_and_custody_profile_ref: policy://...
  ordering_admission_finality_profile_ref: ordering-profile://...
  role_requirements:
    - role: autonomous_system_node_role
      minimum_ready_nodes: nonnegative_integer
      maximum_active_nodes: positive_integer | null
      placement_policy_ref: policy://...
      failure_independence_policy_ref: policy://... | null
      colocation_allowed: boolean
  state_distribution:
    operation_log_replication_factor: positive_integer
    projection_replication_factor: positive_integer
    artifact_replication_factor: positive_integer
    minimum_ack_durability: buffered | device_flush | replicated_same_host | quorum_replicated
    consistency_and_read_watermark_policy_ref: policy://...
    checkpoint_policy_ref: policy://...
    catchup_policy_ref: policy://...
  scaling:
    mode: manual | policy_automated
    scaling_policy_ref: policy://...
    eligible_automatic_roles:
      - projection_replica
      - execution_worker
      - artifact_replica
    authority_role_changes: governed_only
    rebalance_policy_ref: policy://...
  membership_policy_ref: policy://...
  failover_profile_ref: failover-profile://...
  partition_and_degraded_mode_policy_ref: policy://...
  restore_policy_ref: policy://...
  rollout_policy_ref: policy://...
  rollback_policy_ref: policy://...
  drain_and_removal_policy_ref: policy://...
  receipt_obligations: []
  status: draft | active | superseded | revoked
```

This is desired topology. Live node state is carried only by observed
membership records. Authority-bearing roles are never automatically scaled.

### AutonomousSystemNodeMembershipEnvelope

```yaml
AutonomousSystemNodeMembershipEnvelope:
  schema_version: ioi.autonomous-system-node-membership.v1
  node_membership_id: node-membership://...
  system_id: system://...
  deployment_profile_ref: deployment-profile://...
  node_id: node://...
  node_owner_ref: wallet://... | org://... | project://...
  membership_epoch: nonnegative_integer
  membership_lease_ref: lease://...
  role_assignments:
    - role: autonomous_system_node_role
      role_scope_refs: []
      authority_grant_refs: []
      role_lease_ref: lease://... | null
      admitted_epoch: nonnegative_integer
      valid_from: timestamp
      expires_at: timestamp | null
  failure_domain_refs: []
  failure_independence_evidence_refs: []
  node_attestation_refs: []
  conformance_profile_refs: []
  admission:
    proposal_ref: proposal://...
    decision_ref: decision://...
    admitted_constitution_root: hash
    admitted_manifest_root: hash
    admitted_deployment_profile_root: hash
  synchronization:
    checkpoint_ref: checkpoint://... | null
    operation_offset: nonnegative_integer
    verified_state_root: hash | null
    catchup_receipt_ref: receipt://... | null
    verified_at: timestamp | null
  writer_fencing:
    writer_epoch: nonnegative_integer | null
    writer_epoch_transition_ref: writer-transition://... | null
    writer_epoch_transition_hash: hash | null
    writer_lease_ref: lease://... | null
    promotion_receipt_ref: receipt://... | null
  observation:
    readiness: unknown | syncing | ready | degraded | unreachable | failed_closed
    health_observation_ref: agentgres://... | event://... | null
    heartbeat_ref: event://... | receipt://... | null
    readiness_evidence_refs: []
    last_heartbeat_at: timestamp | null
    last_observed_at: timestamp
    observation_expires_at: timestamp
  status: candidate | attesting | admitted | active | draining | suspended | revoked | left | failed_closed
```

Joining authenticates and admits a node; it does not inherently assign an
authority-bearing role. `hot_standby` cannot admit writes until a governed
epoch promotion fences the previous writer.

Membership lifecycle and observed readiness are separate. An unexpired
membership or role lease does not prove a healthy node; stale heartbeat,
readiness, or root evidence makes the observation `unknown`, `degraded`, or
`unreachable` under policy and cannot satisfy promotion or availability claims.

### AutonomousSystemFailoverProfileEnvelope

```yaml
AutonomousSystemFailoverProfileEnvelope:
  schema_version: ioi.autonomous-system-failover-profile.v1
  failover_profile_id: failover-profile://...
  system_id: system://...
  version: semver_or_hash
  response_authorization_mode: manual_governance | preauthorized_policy | protocol_native
  recovery_mechanism: unavailable_fail_closed | single_writer_restore | single_writer_promotion | ordering_profile_native
  failure_condition_policy_refs: []
  failure_detection_policy_ref: policy://...
  minimum_independent_witnesses: nonnegative_integer
  evidence_freshness_policy_ref: policy://...
  ambiguous_partition_response: fail_closed
  deployment_timing_assumptions:
    evidence_mode: bounded_clock_partial_synchrony | external_witness
    clock_or_witness_profile_ref: policy://... | witness-profile://...
    maximum_clock_skew_or_uncertainty_ms: nonnegative_integer
    heartbeat_interval_ms: positive_integer
    heartbeat_evidence_expires_after_ms: positive_integer
    writer_lease_ttl_ms: positive_integer
    writer_lease_renewal_margin_ms: positive_integer
    maximum_effect_lease_ttl_ms: positive_integer
    maximum_revocation_propagation_ms: nonnegative_integer
    promotion_waitout_policy_ref: policy://...
  durable_continuity_cas:
    mechanism: witness_quorum_cas | wallet_epoch_authority | external_coordination_service
    substrate_ref: agentgres://... | wallet://... | service://...
    head_namespace: string
    cas_proof_schema_ref: schema://...
    minimum_independent_witnesses: nonnegative_integer
    unavailable_or_ambiguous_response: fail_closed
  single_writer_restore: object | null
    recovery_target: same_admitted_node | governed_replacement
    restore_policy_ref: policy://...
    required_checkpoint_and_log_proof_schema_ref: schema://...
    require_verified_resulting_state_root: true
    require_writer_epoch_increment: boolean
    require_displaced_writer_fencing: boolean
    required_authority_refs: []
  single_writer_promotion: object | null
    candidate_role: hot_standby
    required_authority_refs: []
    minimum_durability: buffered | device_flush | replicated_same_host | quorum_replicated
    require_latest_verified_state_root: true
    require_catchup_receipt: true
    require_writer_epoch_increment: true
    require_old_writer_fencing: true
    promotion_policy_ref: policy://...
  ordering_profile_recovery: object | null
    recovery_policy_ref: policy://... | null
    view_or_round_change_rule_ref: policy://... | null
    membership_transition_rule_ref: policy://... | null
    external_finality_recovery_rule_ref: policy://... | null
    recovery_proof_schema_ref: schema://...
    resulting_finality_proof_schema_ref: schema://...
  continuity_targets:
    target_recovery_point_ref: policy://...
    target_recovery_time_ref: policy://...
    work_lease_reconciliation_policy_ref: policy://...
    rebalance_policy_ref: policy://...
  receipt_obligations: []
  status: draft | active | superseded | revoked
```

`response_authorization_mode` answers who or what may initiate/authorize the
response; `recovery_mechanism` answers how the active ordering profile recovers.
They are independent axes. A `single_authority` system may select
`unavailable_fail_closed`, receipted `single_writer_restore`, or
`single_writer_promotion`; the first requires every recovery object to be null,
the second requires only its restore object, and the third requires only its
promotion object. A `replicated_single_authority` system normally selects
restore or promotion. Replacement restore and promotion require a new writer
epoch and fencing; a same-admitted-node restart follows the active restore
policy and must prove checkpoint/log continuity and its resulting state root.
Policy automation may automate detection, proposal, and pre-authorized
recovery; it never creates authority silently. For threshold, BFT, or external-finality profiles,
the mechanism is `ordering_profile_native`, the single-writer object is null,
and recovery binds the applicable threshold, round/view, membership, or
external-finality proof rather than inventing a hot-standby writer epoch.
`protocol_native` authorization is valid only when the active ordering profile
defines it. An ambiguous partition fails closed. This system writer/state
object is distinct from provider-placement `FailoverPlan` in
decentralized.cloud.

Timing is a declared deployment assumption, not a generic clock service. The
renewal margin must be shorter than the writer-lease TTL, heartbeat evidence
must expire after its declared interval, and a preauthorized promotion requires
either bounded-clock partial-synchrony evidence or the named external witness.
The successor writer cannot emit consequential effects until every affected
resource fence has advanced, or until the declared wait-out covers the latest
possible displaced-writer/effect lease, revocation propagation, and clock
uncertainty. Incrementing an integer without a successful durable continuity
CAS does not create a writer fence.

### AutonomousSystemWriterEpochTransitionEnvelope

One immutable transition advances a single System's active writer. This is a
logical-System authority and continuity object. It is distinct from the
Agentgres mux/storage-writer epoch used to fence replicas of one storage log.

```yaml
AutonomousSystemWriterEpochTransitionEnvelope:
  schema_version: ioi.autonomous-system-writer-epoch-transition.v1
  writer_epoch_transition_id: writer-transition://...
  writer_epoch_transition_hash: hash
  transition_kind: genesis | same_node_restore | replacement_restore | promotion
  system_id: system://...
  deployment_profile_ref: deployment-profile://...
  deployment_profile_root: hash
  failover_profile_ref: failover-profile://...
  failover_profile_root: hash
  ordering_profile_ref: ordering-profile://...
  ordering_profile_root: hash
  predecessor_transition_ref: writer-transition://... | null
  predecessor_transition_hash: hash | null
  expected_membership_root: hash | null
  resulting_membership_root: hash
  prior_writer:
    node_membership_ref: node-membership://... | null
    node_id: node://... | null
    membership_epoch: nonnegative_integer | null
    writer_epoch: nonnegative_integer
  successor_writer:
    node_membership_ref: node-membership://...
    node_id: node://...
    membership_epoch: nonnegative_integer
    writer_epoch: positive_integer
    writer_lease_ref: lease://...
  continuity:
    verified_state_root: hash
    checkpoint_ref: checkpoint://... | null
    operation_offset: nonnegative_integer
    catchup_receipt_ref: receipt://...
    state_root_verification_ref: verification://...
  continuity_cas:
    mechanism: witness_quorum_cas | wallet_epoch_authority | external_coordination_service
    substrate_ref: agentgres://... | wallet://... | service://...
    expected_head: hash | null
    resulting_head: hash
    proof_ref: evidence://... | receipt://...
  authority:
    authority_grant_refs: []
    authority_revocation_snapshot_ref: revocation-snapshot://...
    authority_revocation_epoch: nonnegative_integer
  displaced_writer_fencing:
    writer_fence_receipt_refs: []
    effect_lease_fence_receipt_refs: []
    effects_admissible_not_before: timestamp
  timing_evidence:
    observed_at: timestamp
    expires_at: timestamp
    displaced_writer_leases_expire_at: timestamp
    revocation_propagation_complete_at: timestamp
    maximum_clock_skew_or_uncertainty_ms: nonnegative_integer
    witness_evidence_refs: []
  resource_fences:
    - resource_id: string
      allowed_effect_kinds: []
      minimum_read_consistency:
        cached_projection | projection_consistent | snapshot_consistent |
        state_root_consistent | linearized_domain | serializable_domain
      read_watermark: string
  lost_suffix_record_ref: lost-suffix://... | null
  admission_receipt_ref: receipt://...
  committed_at: timestamp
```

Except at genesis, the new writer epoch is exactly the active epoch plus one;
predecessor ref/hash, profile refs/roots, membership roots, prior writer, and
CAS expected head must equal durable active truth. Catch-up, verified state
root, a nonempty unique set of active authority-grant refs, revocation evidence,
displaced-writer fencing or safe wait-out, and every declared resource fence
are admission requirements. Timing evidence must satisfy
`observed_at <= committed_at <= expires_at`; effect activation must cover the
maximum displaced lease, revocation propagation, and declared clock/witness
uncertainty without exceeding evidence expiry. The CAS
resulting head binds the exact immutable transition: the content commitment is
computed over every field except `writer_epoch_transition_hash` and
`continuity_cas.resulting_head`, and both excluded fields must then equal that
commitment. A stale, skipped, foreign, or merely caller-asserted epoch cannot
advance the active projection.

Immutable transition truth is persisted before the rebuildable active-fence
projection. Startup and authoritative loads replay each System chain at every
transition's commit-time validation horizon, reject duplicate genesis roots,
forks, gaps, predecessor/hash mismatches, commit-time regression, tampered
content commitments, and orphan active files, then atomically restore the exact
latest projection. Authority-record filenames derive from a collision-resistant
commitment to the full canonical ref; lossy sanitized refs are not identity.

### LostSuffixRecordEnvelope

Recovery records what the new authoritative history excludes. It never hides
or silently merges an old writer's suffix on rejoin.

```yaml
LostSuffixRecordEnvelope:
  schema_version: ioi.lost-suffix-record.v1
  lost_suffix_record_id: lost-suffix://...
  system_id: system://...
  writer_epoch_transition_ref: writer-transition://...
  prior_writer_epoch: nonnegative_integer
  last_common:
    operation_offset: nonnegative_integer
    state_root: hash
  authoritative_head:
    operation_offset: nonnegative_integer
    state_root: hash
  excluded_suffix:
    first_offset: nonnegative_integer
    last_offset: nonnegative_integer
    commitment_refs: []
    custody_artifact_refs: []
  classification:
    lost_unacknowledged | orphaned_acknowledged_below_required_durability | ambiguous
  reconciliation_policy_ref: policy://...
  disposition: retained_for_forensics | compensating_transition_required | adjudication_required | destroyed_under_policy
  disposition_receipt_refs: []
  status: open | reconciled | adjudicated | closed
  recorded_at: timestamp
```

### ConsequentialEffectFenceContext

`ConsequentialEffectFenceContext` is generated and embedded at a policy
enforcement point. It is not a grant, lease, top-level runtime object, or source
of owner identity:

```yaml
ConsequentialEffectFenceContext:
  schema_version: ioi.consequential-effect-fence-context.v1
  system_id: system://...
  executing_node_id: node://...
  resource_id: string
  effect_kind: string
  exact_payload_hash: hash
  deployment_profile_root: hash
  node_membership_epoch: nonnegative_integer
  node_membership_root: hash
  writer_epoch_transition_ref: writer-transition://...
  writer_epoch_transition_hash: hash
  writer_epoch: positive_integer
  writer_lease_expires_at: timestamp
  authority_grant_ref: grant://...
  authority_revocation_snapshot_ref: revocation-snapshot://...
  authority_revocation_epoch: nonnegative_integer
  read_consistency:
    cached_projection | projection_consistent | snapshot_consistent |
    state_root_consistent | linearized_domain | serializable_domain
  read_watermark: string
  read_state_root: hash
  idempotency_key: string
  evaluated_at: timestamp
  expires_at: timestamp
```

The effect owner record supplies `system_id`; trusted daemon startup/config
supplies `executing_node_id`; and the PEP supplies its own exact resource and
effect identities and hashes the exact effect payload. Caller-authored fence
contexts are refused. The PEP then requires the executing node to equal the
active writer and requires the current tuple `(system_id, writer_epoch_transition_hash,
authority_revocation_epoch)`, exact membership/deployment roots, an unexpired
writer/timing posture, and the resource's declared read consistency,
watermark, and state root. Caller omission never converts a System-scoped
effect into an unscoped effect. Any stale or mismatched field refuses before
the consequential invoker is called.
Observed read evidence supplies the context's consistency, watermark, and state
root; a PEP may not copy the resource fence's required values and present them
as observations. If the executing path cannot derive those facts from durable
owner/projection state, the System-scoped effect is unavailable.

### OrderingFinalityRecoveryEnvelope

The failover profile contains immutable recovery rules and proof schemas. A
specific threshold, BFT, membership-reconfiguration, or external-finality
recovery is a separate admitted transition:

```yaml
OrderingFinalityRecoveryEnvelope:
  schema_version: ioi.ordering-finality-recovery.v1
  ordering_recovery_id: ordering-recovery://...
  system_id: system://...
  failover_profile_ref: failover-profile://...
  ordering_admission_finality_profile_ref: ordering-profile://...
  recovery_class: threshold_view_or_round | bft_view_or_round | membership_reconfiguration | external_finality_rebind
  predecessor:
    sequence: nonnegative_integer
    transition_commitment_ref: commitment://...
    state_root: hash
    membership_root: hash
    view_or_round: nonnegative_integer | null
    external_finality_ref: evidence://... | null
  trigger_evidence_refs: []
  governing_decision_ref: decision://... | null
  authority_grant_refs: []
  transition:
    proposed_view_or_round: nonnegative_integer | null
    membership_transition_ref: transition://... | decision://... | null
    expected_membership_root: hash
    resulting_membership_root: hash
    threshold_or_consensus_proof_refs: []
    external_finality_recovery_ref: evidence://... | null
    recovery_proof_ref: evidence://...
  result:
    sequence: nonnegative_integer
    transition_commitment_ref: commitment://...
    state_root: hash
    finality_proof_ref: evidence://...
    receipt_ref: receipt://... | null
  status: proposed | evidence_pending | authorized | admitted | committed | rejected | failed_closed
```

This object never invents authority. Its predecessor fields are compare-and-
swap inputs; its proof must satisfy the active profile and its resulting
commitment must preserve the cryptographic chain. Single-writer promotion uses
the writer-promotion/fencing contract instead of this envelope.

### OrderingAdmissionFinalityProfileEnvelope

```yaml
OrderingAdmissionFinalityProfileEnvelope:
  schema_version: ioi.ordering-admission-finality-profile.v1
  ordering_profile_id: ordering-profile://...
  system_id: system://...
  constitution_ref: constitution://...
  version: semver_or_hash
  profile: single_authority | replicated_single_authority | threshold_authority | bft_consensus | external_chain_finality
  authority_distribution:
    posture: single_principal | declared_multi_principal | external_network
    principal_refs: []
    independence_evidence_refs: []
  ordering:
    rule_ref: policy://...
    member_node_membership_refs: []
    writer_epoch_required: boolean
    fencing_required: boolean
    leader_or_sequencer_selection_ref: policy://... | null
    conflict_rule_ref: policy://...
  admission:
    deterministic_transition_function_ref: artifact://... | cid://...
    schema_root: hash
    policy_root: hash
    authority_rule_ref: policy://...
    threshold:
      required: nonnegative_integer
      eligible: nonnegative_integer
    require_expected_predecessor_root: true
    receipt_obligations: []
  cryptographic_continuity:
    hash_and_signature_suite_ref: schema://...
    sequence_rule_ref: policy://...
    require_monotonic_sequence: true
    require_expected_predecessor_commitment: true
    operation_or_batch_commitment_schema_ref: schema://...
    admission_proof_schema_ref: schema://...
    require_resulting_state_root: true
    require_receipt_root: true
    checkpoint_and_compaction_policy_ref: policy://...
  finality:
    scope: local_operational | cross_domain | public_economic
    rule_ref: policy://...
    proof_schema_ref: schema://...
    rollback_posture: recoverable_before_final | compensation_only_after_final | irreversible_after_final
    external_network_ref: network://... | chain://... | domain://sovereign-settlement/... | null
    external_contract_ref: optional
    external_confirmation_policy_ref: policy://... | null
  fault_model_ref: policy://...
  liveness_policy_ref: policy://...
  membership_and_profile_change_policy_ref: policy://...
  conformance_receipt_refs: []
  status: draft | active | superseded | revoked
```

`single_authority` and `replicated_single_authority` have exactly one active
`admission_writer`. Replication, node count, and durability quorum never upgrade
authority distribution or public-finality claims. `threshold_authority` is
k-of-n admission, not BFT consensus unless a named protocol also solves
ordering and its declared fault model. `bft_consensus` names the protocol,
membership rule, fault assumptions, and finality proof.
`external_chain_finality` names the external network, contract, proof, and
confirmation rule. Local operational finality must never be marketed as public
or economic finality.

An `external_network_ref` uses `network://` or `chain://` by default. A
`domain://sovereign-settlement/...` ref is valid only when the external finality
source is explicitly modeled as a sovereign settlement domain; an ordinary
application domain is not a chain-finality proof.

The `cryptographic_continuity` block is the minimum for the **intelligent
blockchain** classification under every ordering profile, including
single-authority/PoA-1. Each admitted operation or batch binds a monotonic
sequence, expected predecessor commitment, operation/batch commitment,
admission signature or proof, resulting state root, and receipt root. A bounded
DAS without that verifiable root/commitment chain is a bounded autonomous
application or institution, not an intelligent blockchain. Consensus and a
token remain optional.

### OracleEvidenceProfileEnvelope

```yaml
OracleEvidenceProfileEnvelope:
  schema_version: ioi.oracle-evidence-profile.v1
  oracle_evidence_profile_id: oracle-evidence-profile://...
  system_id: system://...
  version: semver_or_hash
  fact_class_refs: []
  source_requirements:
    - source_class: official_record | institutional_attestation | signed_sensor | contractual_notice | human_attestation | network_commitment | other
      source_refs: []
      evidence_schema_ref: schema://...
      signer_or_principal_refs: []
      freshness_and_finality_policy_ref: policy://...
      independence_group_ref: optional
      required: boolean
  aggregation:
    rule: single_source | threshold | weighted | adjudicated
    minimum_sources: positive_integer
    minimum_independent_principals: positive_integer
    threshold_policy_ref: policy://... | null
    correlated_failure_policy_ref: policy://...
    uncertainty_policy_ref: policy://...
  contradiction:
    policy: fail_closed | hold_pending | escalate
    adjudicator_refs: []
    dispute_policy_ref: policy://...
  challenge:
    challenge_window_ref: policy://...
    verifier_refs: []
    appeal_policy_ref: policy://...
  admission:
    decision_semantics: qualified_scope_bound_operational_determination
    ontology_assertion_schema_refs: []
    required_verifier_path_refs: []
    ontology_action_contract_refs: []
    permitted_applicability_scope_refs: []
    permitted_consequence_scope_refs: []
    maximum_assertion_validity_policy_ref: policy://...
    required_authority_refs: []
    policy_ref: policy://...
    receipt_obligations:
      - oracle_evidence_admission
  missing_or_stale_evidence_mode: unknown | read_only | pause | escalate
  source_replacement_policy_ref: policy://...
  privacy_policy_ref: policy://...
  retention_policy_ref: policy://...
  status: draft | active | superseded | revoked
```

Actual observations remain evidence or `OntologyAssertionEnvelope` records.
The profile governs whether attributed, freshness-bounded, contradictory, and
challengeable evidence may support a scoped transition; it does not turn an
external proposition into universal truth. Silence, source loss, creator
absence, or stale data is not positive evidence unless an explicit lawful rule
says so.

The selected profile may compose several mechanisms into a qualified
operational determination only when it binds the fact class, evidence and
dependency roots, independence posture, verifier path, freshness and
uncertainty assessment, contradiction/challenge state, applicability,
permitted-consequence scope, validity window, policy, and required authority.
The resulting `OracleEvidenceAdmissionReceipt` is owned by the receipt registry.
It proves that the named admission boundary reached its declared decision under
those inputs; it does not prove the external proposition and it conveys no
authority by itself.

### LifecycleContinuityProfileEnvelope

```yaml
LifecycleContinuityProfileEnvelope:
  schema_version: ioi.lifecycle-continuity-profile.v1
  lifecycle_profile_id: lifecycle-profile://...
  system_id: system://...
  constitution_ref: constitution://...
  version: semver_or_hash
  continuity_class: operator_bound | successor_governed | durable_purpose | finite_term
  continuity:
    operating_budget_policy_ref: policy://...
    dependency_replacement_policy_ref: policy://...
    minimum_archive_policy_ref: policy://...
    degraded_mode: pause | read_only | bounded_continuation
  recovery_and_suspension:
    recovery_policy_ref: policy://...
    pause_and_resume_policy_ref: policy://...
    suspension_and_reinstatement_policy_ref: policy://...
    quarantine_and_release_policy_ref: policy://...
    retirement_policy_ref: policy://...
  succession:
    enabled: boolean
    trigger_classes: [creator_death, creator_incapacity, organization_dissolution, authority_loss, governance_deadlock, term_expiry]
    oracle_evidence_profile_refs: []
    successor_candidate_refs: []
    selection_policy_ref: policy://...
    required_legal_or_governance_authority_refs: []
    challenge_window_ref: policy://...
    authority_handoff: rotate_and_reissue
    constitution_must_be_preserved: true
  dissolution:
    trigger_policy_refs: []
    approval_policy_ref: policy://...
    active_work_disposition_policy_ref: policy://...
    asset_disposition_contract_refs: []
    outstanding_obligation_policy_ref: policy://...
    authority_revocation_policy_ref: policy://...
    worker_and_node_shutdown_policy_ref: policy://...
    data_export_retention_and_erasure_policy_ref: policy://...
    network_exit_policy_ref: policy://...
    tombstone_policy_ref: policy://...
  migration:
    allowed: boolean
    migration_policy_ref: policy://...
    identity_continuity_required: true
    state_root_verification_required: true
  fork:
    allowed: boolean
    fork_policy_ref: policy://...
    new_system_id_required: true
    source_identity_inheritance: forbidden
    state_root_and_lineage_proof_required: true
  adoption:
    allowed: boolean
    adoption_policy_ref: policy://...
    identity_continuity_decision_profile_ref: policy://...
    explicit_identity_decision_required: true
    state_root_and_lineage_proof_required: true
  status: draft | active | superseded | revoked
```

Succession transfers governed responsibility, not existing raw keys;
wallet.network rotates or reissues authority inside the constitution. Creator
absence never widens purpose. Migration, fork, or adoption does not silently
inherit identity, assurance, reputation, escrow, or enrollment.

### LifecycleTransitionEnvelope

```yaml
LifecycleTransitionEnvelope:
  schema_version: ioi.lifecycle-transition.v1
  lifecycle_transition_id: lifecycle-transition://...
  system_id: system://...
  resulting_or_related_system_id: system://... | null
  lifecycle_profile_ref: lifecycle-profile://...
  transition_kind: initialize | activate | pause | resume | suspend | reinstate | enter_dormancy | wake | begin_recovery | complete_recovery | quarantine | release_quarantine | initiate_succession | complete_succession | initiate_dissolution | complete_dissolution | migrate | fork | adopt | retire | archive | revoke | decommission
  genesis_ref: genesis://... | null
  manifest_ref: package://.../release/... | null
  admitted_manifest_root: hash | null
  previous_state: draft | initialized | active | degraded | paused | suspended | dormant | recovering | quarantined | succession_pending | successor_governed | dissolution_pending | dissolving | dissolved | retired | archived | decommissioned | revoked
  proposed_state: same_enum
  trigger_evidence_refs: []
  oracle_evidence_profile_refs: []
  proposal_ref: proposal://...
  decision_ref: decision://... | null
  authority_grant_refs: []
  challenge_opened_at: timestamp | null
  challenge_closes_at: timestamp | null
  predecessor_state_root: hash
  resulting_state_root: hash | null
  state_transition_commitment_ref: transition://... | null
  lineage_ref: provenance://... | null
  identity_continuity_decision_ref: decision://... | null
  disposition_receipt_refs: []
  receipt_refs: []
  public_commitment_ref: commitment://... | settlement://... | tx://... | null
  status: proposed | evidence_pending | challenge_open | approved | executing | committed | rejected | rolled_back | failed_closed
```

`initialize` and `activate` require `genesis_ref`, manifest/release binding, and
the applicable genesis or activation receipt. Every other transition requires
those fields to be null and operates against the already active system chain.
The genesis object and lifecycle projection may not disagree: only an admitted
lifecycle transition changes whether the system is initialized or active.

Migration preserves `system_id` and therefore sets
`resulting_or_related_system_id` to the same identity. A fork mints a different
system ID and binds lineage without inheriting enrollment, assurance,
reputation, escrow, or authority. Adoption binds the abandoned/source system
and the governed continuity decision; it preserves identity only when the
constitution and adoption decision explicitly authorize that result.

### IOINetworkEnrollmentEnvelope

```yaml
IOINetworkEnrollmentEnvelope:
  schema_version: ioi.network-enrollment.v1
  network_enrollment_id: network-enrollment://...
  system_id: system://...
  constitution_ref: constitution://...
  manifest_ref: package://.../release/...
  version: semver_or_hash
  predecessor_enrollment_ref: network-enrollment://... | null
  profile: ioi_compatible | ioi_connected | ioi_secured
  governing_decision_ref: decision://...
  authority_grant_refs: []
  effective_at: timestamp
  expires_at: timestamp | null
  renewal_policy_ref: policy://...
  conformance:
    kernel_release_root: hash
    conformance_profile_refs: []
    conformance_receipt_refs: []
    ecosystem_assurance_profile_refs: []
  connection:
    network_ref: network://ioi-l1 | null
    system_registration_ref: optional
    constitution_commitment_ref: optional
    release_commitment_ref: optional
    endpoint_commitment_refs: []
    aiip_profile_refs: []
    aiip_channel_refs: []
  selected_network_services:
    - service_kind: registry | rights | reputation | escrow | dispute | settlement | validator | verifier | guardian | availability | relayer | arbitrator | ordering | finality
      service_ref: service://...
      terms_ref: terms://...
      fee_basis_ref: fee-basis://... | null
      bond_or_stake_ref: optional
      slashing_or_claim_policy_ref: policy://... | null
      assurance_profile_ref: assurance_profile://... | null
  assurance_claim: none | connected_services_only | secured_profile
  standard_das_conformance_profile_ref: conformance_profile://... | null
  exit:
    exit_policy_ref: policy://...
    outstanding_obligation_refs: []
    dispute_refs: []
    final_commitment_ref: optional
  suspension_reason_code: string | null
  transition_receipt_refs: []
  status: local_only | pending | active | suspended | exiting | exited | revoked
```

`ioi_compatible` requires `local_only`, no L1 dependency, no selected network
service, and no assurance claim. `ioi_connected` pays only for named services
and may claim only their guarantees. `ioi_secured` requires Standard DAS
conformance, named security/assurance services, and any declared bonds or
service consideration. Enrollment never taxes local transitions or implicitly
changes constitution, authority, ordering, or finality. Exit preserves open
disputes, outstanding obligations, and required commitments.

The profile conditions fail closed. `ioi_connected` cannot become `active`
without a network ref and at least one complete selected-service record.
`ioi_secured` additionally requires a current Standard DAS conformance ref and
at least one named shared-security/assurance service with service terms,
coverage/fault-model evidence, and any required bond or claim policy. Missing,
expired, suspended, or contradictory prerequisites keep the enrollment pending
or suspended and prohibit the corresponding assurance claim.

```yaml
AutonomousSystemChainEnvelope:
  schema_version: ioi.autonomous-system-chain.v1
  system_id: system://...
  home_domain_ref: domain://...
  governance_owner_refs: []
  genesis_ref: genesis://...
  package_id: package://...
  manifest_ref: package://.../release/...
  constitution_ref: constitution://...
  deployment_profile_ref: deployment-profile://...
  ordering_admission_finality_profile_ref: ordering-profile://...
  oracle_evidence_profile_refs: []
  lifecycle_continuity_profile_ref: lifecycle-profile://...
  network_enrollment_ref: network-enrollment://... | null
  node_membership_refs: []
  node_membership_root: hash
  active_writer_epoch: nonnegative_integer | null
  latest_sequence: nonnegative_integer
  latest_transition_commitment_ref: commitment://...
  worker_instance_refs: []
  workflow_refs: []
  active_component_registry_ref: agentgres://object-set/... | null
  active_component_registry_root: hash
  policy_root: hash
  module_registry_root: hash
  proposal_queue_root: hash
  operation_log_ref: agentgres://...
  latest_state_root: hash
  latest_receipt_root: hash
  latest_transition_id: transition://...
  upgrade_policy_ref: policy://...
  settlement_policy_ref: policy://...
  default_settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
  allowed_settlement_modes: []
  settlement_profile_refs: []
  public_commitment_policy_ref: policy://... | null
  status: draft | initialized | active | degraded | paused | suspended | dormant | recovering | quarantined | succession_pending | successor_governed | dissolution_pending | dissolving | dissolved | retired | archived | decommissioned | revoked
```

`system_id` remains stable across package releases, node replacement, failover,
migration, and legal/governance succession. Member nodes act for the system only
within their scoped membership and current epoch; no physical node owns the
logical identity.

The deployment, ordering/finality, oracle, lifecycle, and enrollment refs above
are the active admitted refs. They need not remain equal to the package templates
or genesis bindings, but every supersession binds predecessor/proposed roots,
the constitution's protected decision profile, authority, evidence, and
receipts. A chain may not point at an unadmitted profile merely because a
manifest or client requests it.

The active component registry is the live System binding for admitted
GoalRunProfile, WorkflowTemplate, AutomationSpec,
AutomationInstallationBinding, DataRecipe, SkillEntry, RuntimeToolContract,
HarnessProfile, and AgentHarnessAdapter revisions, plus any independently
admitted System-scoped MCP gateway-profile revisions. It is not a copy of
package contents. Every entry binds an exact immutable revision and content or
binding hash. Its root changes only through a governed operation with
predecessor, policy, authority, compatibility, and receipt evidence.
Per-invocation ActiveSkillSetSnapshots, ContextLeases, RuntimeAssignments, and
gateway profiles scoped to one Session or run remain below the System registry.

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
  supported_autonomous_system_node_roles: []
  autonomous_system_membership_refs: []
  node_attestation_refs: []
  failure_domain_refs: []
  receipt_store_ref: agentgres://...
  replay_store_ref: agentgres://...
  settlement_adapter_refs: []
  hosting_posture: local | hosted | hybrid | enterprise
  status: candidate | active | draining | suspended | archived | revoked
```

A Hypervisor Node may participate in several logical systems under separate
membership, role, authority, settlement, and fencing records. A node may expose
settlement adapters, but the logical system's profile selects whether to use
one. `hosting_posture` describes placement/administration; `status` describes
observed node lifecycle.

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

## LocalAgentPairingSessionEnvelope

`LocalAgentPairingSessionEnvelope` is the short-lived, pre-AIIP bootstrap
contract for connecting an already-running, user-owned local agent or harness
to an IOI product surface. It binds one product-initiated pairing challenge to
one local client key and origin so the client can submit typed proposals
without receiving ambient product, room, runtime, or authority access.

Pairing has three target kinds:

- `room_guest` creates a room-scoped, unpublished Worker composition proposal
  and a typed request to participate in one discoverable OutcomeRoom;
- `private_worker` proposes a reusable Worker composition visible only to the
  initiating user until separately admitted or published;
- `organization_worker` proposes a reusable Worker composition to an
  organization-controlled admission path. Pairing does not prove that the
  agent represents the organization and does not bypass organization policy.

The pairing transport may be a loopback exchange, a device-code flow, or a
copyable bootstrap command. Those are transport choices, not protocol identity
or authority. Raw one-time factors, access tokens, private keys, prompts, and
secrets must not be persisted in this envelope.

```yaml
LocalAgentPairingSessionEnvelope:
  pairing_session_id: local-agent-pairing://...
  schema_version: ioi.local-agent-pairing-session.v1
  initiated_by_ref: user://... | org://...
  initiating_surface_ref: surface://...
  target_kind: room_guest | private_worker | organization_worker
  target_scope_ref:
    outcome-room://... | user://... | org://...
  room_discovery_ref: room-discovery://... | null
  claimed_local_agent:
    display_name: string
    resolver_kind: harness_profile | agent_harness_adapter | none
    resolver_revision_ref:
      harness-profile://.../revision/... |
      agent-harness-adapter://.../revision/... | null
    resolver_content_hash: hash | null
    semantic_harness_profile_revision_ref:
      harness-profile://.../revision/... | null
    semantic_harness_profile_content_hash: hash | null
    execution_posture: instrumented_adapter | prompt_only
  pairing_transport: loopback | device_code | copy_command
  challenge: null | object
    challenge_hash: hash
    authentication_factor_kind:
      one_time_challenge | device_code | signed_nonce
    issued_at: timestamp
    expires_at: timestamp
    single_use: true
  client_binding: null | object
    agent_public_key_ref: key://...
    proof_of_possession_hash: hash
    origin_kind: loopback_endpoint | device_client | bootstrap_client
    origin_binding_hash: hash
    bound_at: timestamp | null
  claim_attempt_policy:
    failed_attempt_limit: positive_integer
    failed_attempt_count: nonnegative_integer
    rate_limit_policy_ref: policy://...
  allowed_bootstrap_actions:
    - read_discovery
    - submit_worker_composition
    - submit_room_participation_request
  bootstrap_non_grants:
    authority: none
    room_membership: none
    room_database_access: none
    private_context_access: none
    connector_or_secret_access: none
    budget_or_spend: none
    effect_execution: none
  submission_refs:
    worker_composition_ref: composition://... | null
    room_participation_request_ref: participation-request://... | null
    first_aiip_packet_ref: packet://... | null
  contribution_lane: instrumented_candidate | proposal_only
  assurance_posture:
    pairing_proves: client_key_and_origin_binding_only
    prompt_only_ceiling: attested
  failure_reason_code:
    null | challenge_expired | challenge_replayed | invalid_proof |
    key_mismatch | origin_mismatch | attempt_exhausted | rate_limited |
    scope_escalation | malformed_submission | policy_denied |
    target_unavailable
  created_at: timestamp
  updated_at: timestamp
  completed_at: timestamp | null
  status:
    created | challenge_issued | agent_proof_received | bootstrap_bound |
    composition_submitted | participation_submitted | completed | expired |
    rejected | cancelled | revoked | failed_closed
```

The subobjects are phase-qualified. `challenge` is null until
`challenge_issued`; after that successful transition, later active states retain
the non-secret challenge commitment and timestamps. `client_binding` is null
until candidate proof is received. In `agent_proof_received`, the candidate
key, proof-of-possession hash, and observed origin binding may be recorded while
`bound_at` remains null; `bootstrap_bound` and later successful states require
all binding fields and a non-null `bound_at`. A terminal transition retains only
the partial subobjects reached before failure: for example, cancellation from
`created` may retain null challenge and binding, while rejection after proof
retains the challenge and observed unbound proof. Terminal states never
synthesize unobserved fields. Failed claims increment `failed_attempt_count`
atomically, and reaching the limit produces `attempt_exhausted` plus
`failed_closed`. Prompt-only clients still bind a bootstrap-client `key://...`
and origin; their limitation is absent runtime instrumentation, not absent
pairing identity.

The `allowed_bootstrap_actions` list is a closed enum and a target-specific
subset, never an extensible capability bag. `read_discovery` exposes only the
signed public or permissioned discovery projection already eligible for the
initiating product session. `submit_worker_composition` and
`submit_room_participation_request` submit tainted proposals for schema and
policy admission. They do not install, invoke, publish, list, admit, allocate,
fund, or authorize the proposed Worker.

`resolver_kind` discriminates the exact resolver revision/hash. `none`
requires both resolver fields to be null. When the local agent uses an
AgentHarnessAdapter, the optional semantic HarnessProfile pair declares the
exact scoped-step contract the adapter realizes; the concrete bridge never
masquerades as that profile. When `resolver_kind: harness_profile`, the
semantic pair equals the resolver pair. `prompt_only` does not imply an
instrumented adapter or verifiable local execution.

The canonical lifecycle is:

```text
created
  -> challenge_issued
  -> agent_proof_received
  -> bootstrap_bound
       -> composition_submitted
            -> completed                         private_worker | organization_worker
            -> participation_submitted
                 -> completed                    room_guest

any non-terminal state
  -> expired | rejected | cancelled | failed_closed

bootstrap_bound | composition_submitted | participation_submitted
  -> revoked
```

For `room_guest`, `participation_submitted` is valid only after a composition
ref exists and the bound client submits the typed
`RoomParticipationRequestEnvelope`. That submission is carried as the first
`room_participation` AIIP packet; the pairing exchange itself is not AIIP and
is not an `authority_grant`. For `private_worker` and `organization_worker`, a
composition proposal is sufficient to complete pairing. Joining a room later
requires a room-specific participation request and the applicable AIIP flow.
`target_scope_ref` must be an `outcome-room://...`, `user://...`, or `org://...`
ref for `room_guest`, `private_worker`, or `organization_worker` respectively;
`room_discovery_ref` is required for `room_guest` and null for the reusable
Worker targets. A mismatch fails closed.

A challenge is short-lived and single-use. Its successful proof is consumed
atomically with binding to the declared client key and origin. A retry may be
idempotent only for the same session, key, origin, target, and submission hash.
Replay, expiry, key or origin drift, target mutation, malformed typed objects,
or a request for any action outside the closed bootstrap set fails closed and
creates no partial grant. Revocation stops future bootstrap use but does not
erase an already admitted composition, participation request, contribution,
or required audit history; those objects follow their own lifecycle owners.

`prompt_only` means the product can authenticate the bootstrap client but
cannot attest which model, harness loop, tools, environment, or private
reasoning produced a proposal. It therefore forces the `proposal_only`
contribution lane and the `attested` prompt-only ceiling. A later named verifier
may advance a specific result through evidence, verification, and acceptance;
that does not retroactively attest the hidden agent runtime.

Pairing completion records bootstrap submission only. Later admission,
rejection, suspension, or revocation of the Worker composition or room
participation request stays on those downstream objects and does not rewrite
pairing history.

No new pairing receipt type is introduced. The session object, its bound
submission refs, and the existing Worker, participation, evidence,
verification, acceptance, and runtime event/receipt owners carry the relevant
state and assurance claims.

## AIIP and Bounded Execution Domain Envelopes

AIIP is the interoperation protocol for handoffs between independently governed
autonomous systems. Local GoalRun/HarnessInvocation, member-node, and
embodied-unit routing uses native L0 GoalRun, RuntimeAssignment, lease,
state/evidence, and Embodied
Runtime contracts rather than AIIP. Internal and external paths may reuse common
typed work, authority, idempotency, evidence, and receipt conventions without
collapsing their sovereignty boundary. Consequential AIIP packets must compile
into typed envelopes with policy, authority, receipt, recovery, and declared
settlement semantics.

This file owns the canonical field-level `AIIPChannelEnvelope` and
`AIIPEnvelope` schemas because they are shared boundary objects. The AIIP owner,
[`aiip.md`](./aiip.md), owns packet semantics, processing rules, protocol
profiles, conformance, and evolution. Other documents reference these schemas;
they must not publish a competing reduced envelope.

```yaml
AIIPExternalProtocolBindingEnvelope:
  schema_version: ioi.aiip-external-protocol-binding.v1
  binding_id: aiip-binding://...
  aiip_profile_ref: profile://...
  protocol_kind: native_aiip | a2a | mcp | http_json_rpc | grpc | oasf_directory | erc_8004 | erc_8183 | other
  protocol_name: string
  protocol_version_or_commitment: string
  specification_ref: https://... | artifact://... | cid://...
  identity_mapping_ref: schema://...
  lifecycle_and_status_mapping_ref: schema://... | null
  message_and_artifact_mapping_ref: schema://... | null
  error_and_retry_mapping_ref: schema://... | null
  extension_profile_refs: []
  required_runtime_tool_contract_refs: []
  required_authority_scope_refs: []
  assurance_non_equivalences: []
  conformance_profile_refs: []
  compatibility_range: string
  status: draft | active | deprecated | revoked
```

The binding preserves protocol-version drift and explicitly records what does
not map. A remote task completion, tool response, registry entry, reputation
record, or evaluator decision never silently becomes an IOI verification,
acceptance, authority grant, adjudication, or settlement state.

### Shared Settlement Selection Contract

Every concrete settlement intent, obligation, resolution, or mirror uses the
same settlement-selection fields:

```yaml
settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
settlement_profile_ref: policy://...
network_enrollment_ref: network-enrollment://... | null
public_commitment_policy_ref: policy://... | null
```

The `settlement_mode` member set is owned by
[`canonical-enums.md`](./canonical-enums.md#settlement-modes-settlement_mode).

The profile owns settlement triggers such as an explicit request, accepted
delivery, adjudicated remedy, or contract condition; those triggers are not
alternate rails. Registry, rights, license, reputation, and handoff-finality
operations use the network-service contract below and are not settlement
actions merely because they may have a fee. `local_domain` is the default and requires a null
enrollment ref. `ioi_l1` requires an active connected or secured enrollment
that selected the named service. Missing, expired, suspended, or mismatched
enrollment fails closed. Consequentiality, a signature, a receipt, or an AIIP
handoff never silently selects a public rail.

Long-lived containers such as domains, channels, systems, and collaborations do
not select one rail for every future counterparty. They declare a default,
allowed modes, and profile refs; each `SettlementIntentEnvelope` or
`SettlementEnvelope` selects the concrete mode, rail, and applicable party
enrollment. Party-specific enrollments never become one ambiguous shared
enrollment.

```yaml
BoundedExecutionDomainEnvelope:
  domain_id: domain://...
  owner_ref: wallet://... | org://... | project://... | ioi://publisher/...
  domain_kind: local_runtime | installed_worker | marketplace_worker | outcome_provider | enterprise_runtime | robot_fleet | dao_operator | autonomous_system | as_l1 | appchain | sovereign_domain
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
    public_commitment_policy_ref: policy://... | null
  runtime_profile:
    kind: local_daemon | in_process | local_http | grpc | json_rpc | nats | hosted_daemon | cloud_vm | tee | depin | customer_vpc | robot_controller | external_api
    endpoint_ref: optional
  settlement_behavior:
    settlement_account_ref: optional
    default_settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
    allowed_settlement_modes: []
    settlement_profile_refs: []
    network_enrollment_refs: []
    public_commitment_policy_ref: policy://... | null
    escrow_supported: boolean
  aiip_profiles_supported: []
  status: draft | active | suspended | revoked | archived
```

The retired `local_microharness` discriminator may be accepted only by an
explicit compatibility adapter and must normalize to `local_runtime` before
admission. A GoalRunProfile or HarnessProfile is not itself an execution
domain; the admitted local runtime/domain executing its invocations is.

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
  external_protocol_binding_ref: aiip-binding://... | null
  schema_version: ioi.aiip-channel.v1
  relay_policy_ref: optional
  authority_policy_ref: optional
  privacy_mode: public | private | encrypted | redacted | permissioned_evidence
  default_settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
  allowed_settlement_modes: []
  settlement_profile_refs: []
  party_network_enrollment_refs:
    - party_ref: system://... | domain://...
      network_enrollment_ref: network-enrollment://... | null
  public_commitment_policy_ref: policy://... | null
  sequence_root: optional_hash
  status: opening | active | paused | closing | closed | disputed
```

```yaml
AIIPEnvelope:
  schema_version: ioi.aiip-envelope.v1
  packet_id: packet://...
  message_type: capability_discovery | task_offer | task_acceptance | handoff |
    semantic_profile_negotiation | collaboration_terms_proposal |
    collaboration_terms_response | room_discovery | room_participation |
    frontier_update |
    work_claim | attempt_finding | verifier_challenge | room_admission |
    authority_query | authority_grant | receipt_commitment | delivery_update |
    acceptance_decision | settlement_intent | dispute | dispute_resolution |
    reputation_query
  system_id_from: system://... | domain://...
  system_id_to: system://... | domain://...
  channel_id: aiip://channel/...
  external_protocol_binding_ref: aiip-binding://... | null
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
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: hash | null
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
    settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
    settlement_profile_ref: policy://...
    network_enrollment_ref: network-enrollment://... | null
    public_commitment_policy_ref: policy://... | null
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
  offered_to: system://... | domain://... | worker://... | service://... | null
  collaboration_ref: collaboration://... | null
  outcome_room_ref: outcome-room://... | null
  frontier_item_ref: frontier://... | null
  solicitation_mode: directed | invited | open
  discovery_ref: room-discovery://... | null
  collaboration_terms_ref: terms://...
  collaboration_terms_root: hash
  task_payload_hash: hash
  constraints_ref: optional
  authority_requirements: []
  receipt_obligations: []
  quote_required: boolean
  counteroffer_allowed: boolean
  budget_and_funding_refs:
    - goal-budget://... | budget://... | escrow://... |
      procurement://... | order://...
  candidate_eligibility_policy_refs:
    - policy://... | conformance_profile://... | certification_claim://...
  selection_policy_ref: policy://...
  verifier_and_acceptance_refs:
    - verifier_path://... | rubric://... | gate://... | policy://...
  settlement_terms_ref: policy://... | terms://... | null
  expires_at: timestamp
  status: draft | open | withdrawn | expired | superseded
```

```yaml
TaskAcceptanceEnvelope:
  acceptance_id: packet://...
  offer_id: packet://...
  accepted_by: system://... | domain://... | worker://... | service://...
  collaboration_terms_ref: terms://...
  collaboration_terms_root: hash
  terms_response: accept | counteroffer | decline
  counterterms_ref: terms://... | null
  price_quote_ref: quote://... | null
  sla_ref: sla://... | null
  proposed_method_and_delivery_refs:
    - method://... | schedule://... | sla://... | artifact://...
  requested_scope_or_term_change_refs:
    - policy://... | terms://...
  authority_requirements: []
  receipt_obligations: []
  settlement_terms_ref: policy://... | terms://... | null
  valid_until: timestamp
  response_hash: hash
  signature: required
  status: accepted | rejected | counteroffered | expired
```

The response fields are conditional and fail closed on contradiction:

- `terms_response: accept` requires `status: accepted` until `valid_until` (and
  may become `expired` afterward), a null `counterterms_ref`, and the exact
  terms root advertised by the offer;
- `terms_response: counteroffer` requires `status: counteroffered` until
  `valid_until` (and may become `expired` afterward), a non-null
  `counterterms_ref` naming a new terms root, and
  `counteroffer_allowed: true` on the offer;
- `terms_response: decline` requires `status: rejected` and a null
  `counterterms_ref`;
- `quote_required: true` on the offer requires a non-null `price_quote_ref` on
  any accepted or counteroffered response; and
- `response_hash` binds the offer, responding party, response kind, original
  terms ref/root, counterterms ref when present, quote, SLA, method/delivery,
  requested changes, receipt obligations, settlement terms, and validity. The
  signature binds that response hash.

An open solicitation may receive many responses. A response is not selected
or executable merely because it is signed or accepted by its author.

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
  delivery_update_ref: packet://... | delivery://...
  decider_ref: system://... | wallet://... | org://... | policy://... | domain://...
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
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: hash | null
  work_claim_ref: work-claim://... | null
  contribution_refs:
    - contribution://... | receipt://...
  acceptance_decision_refs:
    - acceptance://... | packet://... | decision://...
  budget_reservation_ref: budget://... | spend://... | escrow://... | null
  settlement_account_ref: optional
  receipt_condition_refs: []
  payment_terms_ref: optional
  reputation_event_refs: []
  dispute_window: optional
  settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
  settlement_profile_ref: policy://...
  network_enrollment_ref: network-enrollment://... | null
  public_commitment_policy_ref: policy://... | null
  status: drafted | submitted | accepted | challenged | settled | rejected | expired
```

## Dispute Rail Object Family

The dispute family keeps the policy, one owner-produced case snapshot, and one
admitted resolution distinct:

```text
versioned DisputeRailProfileEnvelope
  -> append-only DisputeEnvelope head
  -> DisputeResolutionEnvelope
  -> owner-executed remedy / bond distribution / receipts
```

V1 has one deliberately strict denomination rule. `disputed_value_units`,
`remedy_units`, both bond holds, the total bond pool, and every bond-allocation
leg use the same exact `DisputeValueUnitBinding`. There is no implicit
conversion, price oracle, decimal reinterpretation, or substitution between
money, Work Credits, tokens, points, or differently deployed forms of an
asset. A case needing separately denominated bonds or remedies requires a
future explicit conversion contract with version, rate source, rounding,
freshness, slippage, and authority rules; it cannot overload v1.

```yaml
DisputeValueUnitBinding:
  asset_ref: asset://...
  unit_ref: denomination://...
  unit_version: positive_integer
  unit_body_hash: sha256:...
  atomic_unit_code: string
  decimals: nonnegative_integer

DisputeRailProfileEnvelope:
  dispute_rail_profile_ref: policy://dispute/...
  profile_version: positive_integer
  profile_body_hash: sha256:JCS(profile body without this field)
  rail_kind:
    internal_review | marketplace_escrow | aiip_dispute | public_settlement
  value_unit: DisputeValueUnitBinding
  ordinary_verification_funding_ref: budget://... | null
  challenger_bond_units: nonnegative_integer
  respondent_bond_units: nonnegative_integer
  evidence_window_ms: positive_integer
  response_window_ms: positive_integer
  appeal_window_ms: positive_integer
  evidence_unavailable_default:
    challenger_upheld | respondent_upheld | partial | no_fault | escalated
  respondent_timeout_default:
    challenger_upheld | respondent_upheld | partial | no_fault | escalated
  allowed_remedies:
    - none | refund | partial_refund | payout | partial_payout | slash |
      retry | revise | escalate
  outcome_rules:
    - outcome:
        challenger_upheld | respondent_upheld | partial | no_fault | escalated
      remedy:
        none | refund | partial_refund | payout | partial_payout | slash |
        retry | revise | escalate
      maximum_remedy_bps_of_disputed_value: 0..10000
      bond_distribution:
        challenger_return_bps: 0..10000
        respondent_return_bps: 0..10000
        challenger_award_bps: 0..10000
        respondent_award_bps: 0..10000
        verifier_funding_bps: 0..10000
        treasury_bps: 0..10000
        burn_bps: 0..10000
        rounding_recipient:
          challenger_return | respondent_return | challenger_award |
          respondent_award | verifier_funding | treasury | burn

DisputeEnvelope:
  dispute_ref: dispute://...
  dispute_rail_profile_ref: policy://dispute/...
  dispute_rail_profile_version: positive_integer
  dispute_rail_profile_body_hash: sha256:...
  value_unit: DisputeValueUnitBinding
  challenged_ref: typed_ref
  challenger_ref: typed_ref
  respondent_ref: typed_ref
  opened_at_ms: integer
  evidence_retained_until_ms: integer
  disputed_value_units: nonnegative_integer
  challenger_bond_hold_ref: hold://... | null
  challenger_bond_held_units: nonnegative_integer
  respondent_bond_hold_ref: hold://... | null
  respondent_bond_held_units: nonnegative_integer
  escrow_ref: escrow://... | null
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: sha256:... | null
  settlement_profile_ref: policy://... | null
  network_enrollment_ref: network-enrollment://... | null
  case_head_hash: sha256:...

DisputeResolutionEnvelope:
  dispute_resolution_ref: dispute-resolution://...
  dispute_ref: dispute://...
  dispute_rail_profile_ref: policy://dispute/...
  dispute_rail_profile_version: positive_integer
  dispute_rail_profile_body_hash: sha256:...
  rail_kind:
    internal_review | marketplace_escrow | aiip_dispute | public_settlement
  value_unit: DisputeValueUnitBinding
  case_head_hash: sha256:...
  request_hash: sha256:JCS(exact resolution request)
  idempotency_key: string
  adjudicator_ref: typed_ref
  decided_at_ms: integer
  evidence_refs: []
  response_refs: []
  appeal_of_resolution_ref: dispute-resolution://... | null
  outcome:
    challenger_upheld | respondent_upheld | partial | no_fault | escalated
  remedy:
    none | refund | partial_refund | payout | partial_payout | slash |
    retry | revise | escalate
  remedy_units: nonnegative_integer
  bond_pool_units: nonnegative_integer
  bond_allocation:
    challenger_return_units: nonnegative_integer
    respondent_return_units: nonnegative_integer
    challenger_award_units: nonnegative_integer
    respondent_award_units: nonnegative_integer
    verifier_funding_units: nonnegative_integer
    treasury_units: nonnegative_integer
    burn_units: nonnegative_integer
  used_evidence_unavailable_default: boolean
  used_respondent_timeout_default: boolean
  appeal_deadline_ms: integer
  required_receipt_kinds:
    - dispute_resolution
    - bond_distribution
    - dispute_remedy_execution | dispute_escalation
  resolution_state:
    proposed | admitted | appealed | superseded | execution_pending |
    executed | execution_failed
```

Invariants:

- The case and resolution bind the exact profile ref, version, and canonical
  body hash. They also repeat the exact value-unit binding; any asset, unit ref,
  unit version, body hash, code, or decimal substitution fails closed.
- Portable numeric fields are fixed-point integers no greater than
  `9,007,199,254,740,991`. Floating-point bond, value, remedy, or allocation
  amounts are invalid.
- `internal_review` has zero bonds and no bond-hold refs.
  `marketplace_escrow` binds its escrow. `aiip_dispute` binds exact
  CollaborationTerms and ordinary verification funding.
  `public_settlement` binds its settlement profile and active network
  enrollment.
- Each required default names an outcome rule. Each rule's bond distribution
  totals exactly 10,000 basis points. Integer allocation assigns the remainder
  to the declared rounding recipient, and all allocation legs sum exactly to
  the held pool.
- Non-value remedies (`none`, `retry`, `revise`, `escalate`) have zero value
  cap and zero `remedy_units`. A selected value remedy cannot exceed its
  profile cap over `disputed_value_units`.
- Evidence retention covers the evidence, response, and actual resolution
  appeal windows. Unavailable-evidence and respondent-timeout defaults cannot
  run before their respective deadlines.
- Same idempotency key plus the same exact request hash replays the prior
  decision. Changed bytes conflict. A replay decision must still bind the same
  dispute, profile, value unit, rail, and case head.
- A resolution admits a decision and allocation plan only. It does not prove
  evidence truth, escrow custody, remedy execution, value movement, receipt
  emission, appeal finality, or public settlement inclusion.

The registered
`schema://ioi/foundations/dispute-rail-bundle/v1` contract carries one exact
profile/case/resolution projection without creating a second dispute owner.

```yaml
ReputationEventEnvelope:
  reputation_event_id: receipt://...
  subject_ref: system://... | domain://... | worker://... | service://...
  context_ref: benchmark://... | rubric://... | service://... | sparse_category | custom
  event_type: delivery_accepted | delivery_rejected | dispute_opened | dispute_resolved | slash | refund | benchmark_result | reliability_update | routing_quality
  score_commitment: optional_hash
  receipt_ref: receipt://...
  policy_hash: hash
  public_commitment_ref: commitment://... | settlement://... | tx://... | null
```

AIIP envelopes may reference private or encrypted payload bodies. IOI L1 may
receive only commitments selected by an active enrollment and settlement
profile; private bodies remain off-chain.

## CollaborationTermsEnvelope

`CollaborationTermsEnvelope` is the exact ex-ante bargain for voluntary
cross-party work. It makes the objective, required parties, bounded work,
rights, disclosure, contribution eligibility, consideration, risk, exit, and
settlement conditions inspectable without requiring a party to reveal its raw
private valuation or outside option. Discovery, a shared goal, or a compatible
AIIP channel creates no duty to accept these terms.

```yaml
CollaborationTermsEnvelope:
  schema_version: ioi.collaboration-terms.v1
  collaboration_terms_id: terms://...
  version: semver_or_hash
  predecessor_terms_ref: terms://... | null
  terms_body_hash_profile: ioi.collaboration-terms-body.v1
  terms_body_root: hash
  scope:
    collaboration_ref: collaboration://... | null
    outcome_room_ref: outcome-room://... | null
    task_refs:
      - task://... | frontier://...
    order_or_service_refs:
      - order://... | service://...
    aiip_channel_refs:
      - aiip://channel/...
  proposed_by_ref:
    system://... | domain://... | org://... | service://... |
    participant-lease://...
  party_roles:
    - party_ref:
        system://... | domain://... | org://... | wallet://... |
        service://... | provider://...
      role:
        data_owner | worker_provider | compute_provider | coordinator |
        customer | auditor | regulator | insurer | verifier |
        settlement_counterparty
      acceptance_required: boolean
  activation:
    rule: bilateral | unanimous_required_parties | required_roles | threshold
    threshold:
      required: nonnegative_integer
      eligible: nonnegative_integer
    required_role_set: []
    activation_policy_ref: policy://...
    activation_decision_ref: decision://... | null
    acceptance_receipt_refs:
      - receipt://...
  cooperation_conditions:
    eligibility_policy_refs:
      - policy://... | conformance_profile://... | certification_claim://...
    required_evidence_refs:
      - evidence://... | receipt://...
    active_participant_lease_required: boolean
    required_context_and_view_policy_refs:
      - context-profile://... | restricted_view://... | policy://...
    authority_requirement_refs:
      - scope:* | policy://...
    deliverable_and_acceptance_refs:
      - schema://... | rubric://... | gate://... | policy://...
    verifier_and_independence_policy_refs:
      - verifier_path://... | policy://...
  rights_and_obligations:
    allowed_work_scope_refs:
      - task://... | frontier://... | policy://...
    artifact_license_and_ip_refs:
      - license://... | policy://...
    confidentiality_privacy_retention_and_export_refs:
      - policy://... | privacy_posture://... | restricted_view://...
    attribution_and_audit_policy_refs:
      - policy://... | audit_export://...
    challenge_dispute_and_remedy_policy_refs:
      - policy://... | dispute://...
    exit_and_outstanding_obligation_policy_refs:
      - policy://...
  contribution_terms:
    contribution_policy_ref: policy://...
    eligible_contribution_kinds: []
    negative_and_inconclusive_result_eligibility:
      excluded | attribution_only | reward_eligible_when_accepted
    attribution_and_derivation_policy_ref: policy://...
    minimum_reward_assurance_stage:
      evidenced | verified | accepted | adjudicated | settled
    reward_basis_ref: policy://... | rate-card://... | quote://... | null
    self_report_creates_payout_right: false
  economics:
    funding_and_budget_refs:
      - goal-budget://... | budget://... | escrow://... |
        procurement://... | order://...
    consideration_kinds:
      - payment | outcome_right | reciprocal_access | license | royalty |
        portable_reputation | reusable_learning | shared_risk_reduction |
        strategic_benefit
    quote_required: boolean
    allowed_settlement_modes: []
    settlement_profile_refs:
      - policy://...
    payout_condition_refs:
      - acceptance://... | receipt://... | policy://...
    ordinary_work_credit_substitution: prohibited
  participant_rationality:
    each_required_party_accepts_expected_net_benefit: true
    participation_decision_refs:
      - decision://... | receipt://...
    raw_private_valuation_disclosure: prohibited_by_default | optional
  term:
    effective_at: timestamp | null
    expires_at: timestamp | null
    renewal_policy_ref: policy://...
    suspension_policy_ref: policy://...
    termination_policy_ref: policy://...
  amendment:
    amendment_policy_ref: policy://...
    requires_new_terms_root: true
    existing_acceptance_carries_forward: false
    retroactive_rewrite: forbidden
  proposer_signature: required
  status:
    draft | proposed | active | suspended | superseded |
    expired | terminated | revoked
```

At least one scope ref must be non-null. `active` requires the declared
activation rule, exact-root acceptance by every required party or role, and
domain admission. Acceptance attests that the party's own governed decision
found participation permissible and worthwhile under its private policy; it
does not prove objective surplus, disclose a reservation price, grant
authority, award work, or create a payout. A new terms root requires new
acceptance and never rewrites already admitted contribution or reward bases.

`terms_body_root` uses the canonical
`ioi.collaboration-terms-body.v1` projection. It hashes the immutable normative
body: schema version, terms identity/version/predecessor, scope, proposer
identity, party roles,
activation rule/threshold/required roles/policy, cooperation conditions,
rights and obligations, contribution terms, economics, rationality rule, term,
and amendment rule. It excludes `terms_body_root` itself,
`activation.activation_decision_ref`,
`activation.acceptance_receipt_refs`,
`participant_rationality.participation_decision_refs`, `proposer_signature`,
and lifecycle `status`. The proposer signature signs the resulting root and
the proposer identity. Activation decisions, acceptance receipts, and status
transitions bind that root but never alter it.

Activation rules have one interpretation across implementations:

- `bilateral` requires exactly two distinct required parties and both accepted;
- `unanimous_required_parties` requires every distinct party with
  `acceptance_required: true`;
- `required_roles` requires at least one accepted distinct party for each
  `required_role_set` member, in addition to every explicitly required party;
- `threshold` requires `1 <= required <= eligible`, counts distinct parties
  rather than roles or keys, and never bypasses a party marked
  `acceptance_required: true`.

One principal may occupy several roles but counts once toward a distinct-party
threshold or independence rule. An invalid or zero threshold cannot activate
terms.

```yaml
MultiPartyCollaborationEnvelope:
  collaboration_id: collaboration://...
  goal_ref: goal://... | task://... | order://... | service://...
  outcome_room_ref: outcome-room://... | null
  coordinator_ref: domain://... | system://... | agent://... | org://...
  active_collaboration_terms_ref: terms://... | null
  active_collaboration_terms_root: hash | null
  party_terms_acceptances:
    - party_ref:
        system://... | domain://... | org://... | wallet://... |
        service://... | provider://...
      collaboration_terms_ref: terms://...
      accepted_terms_root: hash
      acceptance_ref: receipt://...
      accepted_at: timestamp
      status: accepted | withdrawn | superseded | revoked
  terms_amendment_refs:
    - terms://... | proposal://... | decision://...
  coordination_topology:
    hosted_admission | federated_admission
  coordination_and_ordering_policy_ref: policy://...
  shared_state_admission_owner_ref: system://... | domain://... | policy://...
  conflict_failover_and_adjudication_policy_refs:
    - policy://...
  party_refs:
    - party_ref: system://... | org://... | wallet://... | domain://... | service://... | provider://...
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
    - party_ref: system://... | org://... | wallet://... | domain://...
      authority_refs:
        - grant://... | authority://... | policy://...
  evidence_bundle_refs:
    - evidence://... | assurance_evidence://...
  delivery_bundle_refs:
    - delivery://...
  contribution_refs:
    - contribution://... | receipt://...
  settlement_intent_refs:
    - settlement-intent://... | settlement://...
  audit_export_profile_refs:
    - audit_export://... | policy://...
  settlement_policy:
    default_settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
    allowed_settlement_modes: []
    settlement_profile_refs: []
    party_network_enrollment_refs:
      - party_ref: system://... | org://... | wallet://... | domain://...
        network_enrollment_ref: network-enrollment://... | null
    public_commitment_policy_ref: policy://... | null
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

The collaboration may become `active` only when the referenced terms activation
rule is satisfied. A new terms version never carries forward party acceptance
silently. Party discovery, invitation, messaging, or presence in `party_refs`
creates no work obligation, context or authority right, award, contribution
eligibility, or payout.

Every `party_terms_acceptances[].acceptance_ref` resolves to an admitted
`CollaborationTermsAcceptanceReceipt` whose party, role, terms ref/root, scope,
and current acceptance status match the collaboration. A signed packet or bare
decision may be its cause but is not the admitted proof.

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
  system_id: system://...
  hypervisor_node_id: node://...
  acting_node_membership_ref: node-membership://... | null
  ordering_admission_finality_profile_ref: ordering-profile://...
  writer_epoch: nonnegative_integer | null
  ordering_or_finality_proof_ref: evidence://... | null
  sequence: nonnegative_integer | null
  expected_predecessor_commitment_ref: commitment://... | null
  operation_or_batch_commitment: hash | null
  resulting_transition_commitment_ref: commitment://... | null
  admission_proof_ref: evidence://... | receipt://... | null
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
  system_id: system://...
  proposal_profile: standard | improvement_promotion | improvement_agenda_patch
  change_class: release_upgrade | ordinary_upgrade | constitutional_amendment | deployment_change | membership_change | lifecycle_transition | network_enrollment_change
  target_kind: package_release | policy_module | service_module | workflow_graph | goal_run_profile | workflow_template | harness_profile | skill_manifest | runtime_tool_contract | evaluator | improvement_agenda | improvement_governance_profile | contract | tool_binding | model_route | memory_schema | projection_schema | settlement_rule | dispute_rule | authority_envelope | constitution | deployment_profile | node_membership | failover_profile | ordering_admission_finality_profile | oracle_evidence_profile | lifecycle_continuity_profile | network_enrollment
  target_ref: string
  current_manifest_ref: package://.../release/... | null
  proposed_manifest_ref: package://.../release/... | null
  proposed_by: system://... | agent://... | worker://... | wallet://... | org://...
  diff_ref: artifact://... | cid://...
  predecessor_target_root: hash
  proposed_target_root: hash
  required_decision_profile_ref: policy://...
  expected_effects_ref: optional
  simulation_receipt_refs: []
  benchmark_receipt_refs: []
  improvement_promotion:
    campaign_ref: improvement-campaign://... | null
    agenda_revision_and_item_refs: []
    candidate_attempt_or_artifact_ref: attempt://... | artifact://... | null
    evaluation_epoch_ref: evaluation-epoch://... | null
    improvement_evidence_claim_refs: []
    improvement_order_cutoff_receipt_refs: []
    statistical_selection_decision_ref: decision://... | artifact://... | null
    selection_policy_and_observation_refs: []
    complexity_maintainability_and_monitorability_refs: []
    independent_reproduction_refs: []
    activation_mode: direct | shadow | canary | cohort | target_owner_defined | null
    activation_policy_ref: policy://... | null
    rollback_recall_containment_compensation_and_reconciliation_refs: []
    irreversible_effect_recovery_ref: policy://... | artifact://... | null
  policy_hash: hash
  status: drafted | submitted | approved | rejected | escalated | committed | rolled_back
```

Protected target kinds route through the decision path declared by the active
constitution. Ordinary upgrade approval is insufficient. Agents may propose a
constitutional amendment only when the constitution permits it; they never
self-commit one.

`improvement_promotion` is non-null only when `proposal_profile` is
`improvement_promotion`; otherwise every nested field is null or empty. It
freezes the campaign/epoch evidence used to propose one target-owner change but
does not create another promotion decision. The proposal's
`predecessor_target_root` remains the optimistic-concurrency base. A stale base
fails admission: rebase, conflict resolution, or atomic composition creates a
new candidate lineage and requires fresh applicable evaluation rather than a
clerical update to an approved proposal. `improvement_agenda_patch` always
targets an immutable successor Agenda revision and can affect only future
campaign admissions.

```yaml
UpgradeDecisionEnvelope:
  decision_id: decision://...
  proposal_id: proposal://...
  decision: approve | reject | escalate | rollback
  decided_by: system://... | wallet://... | org://... | policy://... | governance://...
  approval_grant_ref: optional
  policy_hash: hash
  receipt_refs: []
  public_commitment_ref: commitment://... | settlement://... | tx://... | null
```

```yaml
StateTransitionCommitmentEnvelope:
  state_transition_commitment_id: transition://...
  system_id: system://...
  hypervisor_node_id: node://...
  acting_node_membership_ref: node-membership://...
  ordering_admission_finality_profile_ref: ordering-profile://...
  writer_epoch: nonnegative_integer | null
  ordering_or_finality_proof_ref: evidence://... | null
  sequence: nonnegative_integer
  expected_predecessor_commitment_ref: commitment://...
  operation_or_batch_commitment: hash
  resulting_transition_commitment_ref: commitment://...
  admission_proof_ref: evidence://... | receipt://...
  transition_kind: module_invocation | workflow_transition | authority_outcome | task_handoff | upgrade_decision | receipt_root | dispute_escalation
  operation_ref: agentgres://...
  predecessor_state_root: optional_hash
  resulting_state_root: hash
  receipt_root: hash
  external_settlement_ref: settlement://... | null
```

`writer_epoch` is required only when the active ordering profile declares
`writer_epoch_required: true`. Threshold/BFT/external-finality transitions bind
their declared ordering or finality proof instead; a null writer epoch never
means an untracked writer.

`system_id` is the only canonical logical-system field name. Legacy
`autonomous_system_id` and `autonomous_system_chain_id` keys may be accepted
only by a versioned migration adapter, must normalize to `system_id` before
admission, and must not be emitted by canonical v1+ envelopes or projections.

A proposed module invocation may leave acting membership and ordering proof
null before admission. An admitted or committed invocation must bind the acting
membership plus either the required writer epoch or the active profile's
ordering/finality proof; it cannot rely on the later transition commitment to repair
missing admission identity.

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

## TypedWorkSubjectBinding

`TypedWorkSubjectBinding` is a non-owning discriminated value used when a
domain contract must point at the work that authorized or contextualized an
effect without inventing a universal work wrapper. `kind` and `ref` must agree,
and the referenced owner remains authoritative for lifecycle, budget,
acceptance, evidence, and status:

```yaml
TypedWorkSubjectBinding:
  kind:
    goal_run | automation_run | work_item | work_claim |
    service_order | physical_action_intent
  ref:
    goal://... | automation-run://... | work_item://... | work-claim://... |
    order://... | intent://...
```

The legacy `mission://...` namespace may survive only as a compatibility alias
that resolves to exactly one `goal://...` or `outcome-room://...` backing
subject. It cannot be written as canonical identity or carry independent
authority, budget, lifecycle, evidence, receipts, or status.
An `automation_run` binding always uses `automation-run://...`; the reusable
AutomationSpec remains `automation://...`. A discriminator may not rescue an
intrinsically ambiguous identity namespace.

## RuntimeAssignmentEnvelope

`RuntimeAssignmentEnvelope` is the governed bridge from logical work to an
actual execution placement. It binds a GoalRun, claimed work, role, Context
Cell, or embodied unit to one runtime and, when the work executes for a bounded
DAS, to one currently admitted node membership of that same `system_id`. It is
a placement and reconciliation decision, not a node-membership record,
authority grant, actuator-authority grant, or cross-system delegation packet.

```yaml
RuntimeAssignmentEnvelope:
  schema_version: ioi.runtime-assignment.v1
  runtime_assignment_id: runtime-assignment://...
  assignment_epoch: nonnegative_integer
  predecessor_runtime_assignment_ref: runtime-assignment://... | null
  work_binding:
    goal_run_ref: goal://... | null
    task_ref: task://... | null
    run_ref: run://... | null
    frontier_item_ref: frontier://... | null
    work_claim_ref: work-claim://... | null
    role_topology_ref: role_topology://... | null
    role_name: string | null
    context_cell_ref: context_cell://... | null
    harness_invocation_ref: harness_invocation://... | null
    worker_instance_ref: agent://... | null
    embodied_unit_ref:
      robot://... | drone://... | device://... | facility-system://... | null
    controller_binding_ref: controller-binding://... | null
    fleet_mission_allocation_lease_ref:
      fleet-mission-allocation-lease://... | null
    resource_group_bindings:
      - group_revision_ref: embodied-resource-group-revision://...
        membership_closure_hash: hash
  system_id: system://... | null
  system_placement:
    deployment_profile_ref: deployment-profile://... | null
    node_membership_ref: node-membership://... | null
    node_id: node://... | null
    node_membership_epoch: nonnegative_integer | null
    node_role: autonomous_system_node_role | null
    node_role_lease_ref: lease://... | null
    writer_epoch_transition_ref: writer-transition://... | null
    writer_epoch_transition_hash: hash | null
    writer_epoch: nonnegative_integer | null
  runtime_placement:
    runtime_node_ref: runtime://...
    daemon_profile_ref: profile://...
    compute_session_ref: compute://... | null
    placement_policy_ref: policy://...
    required_locality_refs:
      - region://... | failure-domain://... | custody://... | policy://...
    prohibited_locality_refs:
      - region://... | failure-domain://... | custody://... | policy://...
  embodied_runtime_binding:
    execution_target: native | external | null
    native_runtime_profile:
      micro | edge | site | null
    runtime_graph_manifest_ref: embodied-runtime-graph-manifest://... | null
    runtime_graph_manifest_hash: hash | null
    graph_partition_bindings:
      - partition_key: string
        resolved_partition_hash: hash
    graph_activation_ref: graph-activation-transaction://... | null
  state_and_partition:
    required_state_watermark_ref:
      agentgres://... | checkpoint://... | commitment://... | state://... | null
    minimum_operation_offset: nonnegative_integer | null
    required_state_root: hash | null
    minimum_read_consistency:
      cached_projection | projection_consistent | snapshot_consistent |
      state_root_consistent | linearized_domain | serializable_domain
    required_read_watermark: string | null
    state_freshness_policy_ref: policy://...
    state_sync_before_start: required | policy_conditional | not_required
    partition_mode:
      fail_closed | read_only | bounded_local_execution | disconnected_autonomy
    partition_and_degraded_mode_policy_ref: policy://...
    rejoin_and_state_merge_policy_ref: policy://...
  lease_and_reassignment:
    assignment_lease_ref: lease://...
    valid_from: timestamp
    expires_at: timestamp | null
    reassignment_policy_ref: policy://...
    predecessor_drain_or_fencing_receipt_ref: receipt://... | null
    handoff_checkpoint_ref: checkpoint://... | artifact://... | null
  duplicate_effect_control:
    effect_recovery_class:
      replayable | checkpointable | compensatable |
      reconciliation_required | non_retryable | null
    idempotency_key: string | null
    idempotency_scope_ref: policy://... | state://... | null
    duplicate_effect_prevention_policy_ref: policy://...
    ambiguous_effect_reconciliation_policy_ref: policy://...
    compensation_policy_ref: policy://... | null
  reconciliation:
    required_before_activation: boolean
    predecessor_outcome_state:
      not_applicable | known_not_committed | known_committed | ambiguous
    reconciliation_policy_ref: policy://...
    unresolved_effect_refs:
      - effect://... | invocation://... | receipt://...
    reconciliation_receipt_ref: receipt://... | null
    status: not_required | pending | satisfied | failed_closed
  authority_and_assurance:
    assigned_by_ref: system://... | domain://... | policy://... | worker://...
    assignment_decision_ref: decision://... | routing-decision://...
    authority_grant_refs:
      - grant://...
    authority_scope_refs:
      - authority://... | policy://...
    verification_profile_refs:
      - verifier_path://... | policy://... | schema://...
    admission_evidence_refs:
      - evidence://... | receipt://... | attestation://...
    receipt_obligations: []
  economics:
    subscription_ref: subscription://... | null
    quote_ref: quote://... | null
    budget_reservation_ref: budget://... | allocation://... | null
  assignment_hash: hash
  signature: required
  admission_receipt_ref: receipt://... | null
  execution_receipt_refs:
    - receipt://...
  status:
    proposed | admitted | active | draining | completed | superseded |
    revoked | failed_closed
```

At least one of `goal_run_ref`, `task_ref`, `run_ref`, `work_claim_ref`,
`harness_invocation_ref`, or `embodied_unit_ref` is required. An embodied unit
may therefore be the required work subject for placement. A Context Cell, role,
controller binding, fleet-allocation binding, or exact embodied-resource-group
revision narrows that work subject; it cannot create work, room participation,
node membership, actuator authority, or any other authority by itself.

When a system-owned GoalRun is the work subject, assignment `system_id` must
match the GoalRun owner. For room-scoped participant work, it must resolve
through the GoalRun's current participant lease and work claim; the room's own
system identity does not silently become the participant's execution identity.

When `embodied_unit_ref` is non-null, assignment `system_id` is required and
must match the unit's owning `system_id`. An admitted or active embodied
assignment must bind `controller_binding_ref`; that controller binding must name
the same unit and `system_id`, and its admitted execution-node membership must
match `system_placement.node_membership_ref`. When
`fleet_mission_allocation_lease_ref` is present, the lease must name the same
unit, controller binding, `system_id`, and execution-node membership as the
assignment.

Every `resource_group_bindings` entry must name one admitted immutable group
revision and its exact `membership_closure_hash`. The group must resolve to the
same `system_id` and `system_placement.deployment_profile_ref` as the assignment
and to one embodied domain admitted by that system. It is never sufficient as
the only work subject. When `embodied_unit_ref` or `controller_binding_ref` is
present, the group's resolved closure must contain that unit or controller plus
at least one sensor or actuator reachable through the bound controller; the
binding then narrows placement to that assignment's slice of the group.

An actuator-bearing assignment requires non-null `embodied_unit_ref` and
`controller_binding_ref`, and every actuator in its effective group slice must
be reachable through that controller. An `observe_only` group containing only
passive work may instead narrow a GoalRun, task, run, work claim, or harness
invocation without fabricating an embodied unit, provided every selected sensor
resolves through the assignment's admitted source-node membership or another
explicitly admitted read/evidence route. This exception never admits
actuation. One assignment never stands in for every unit or controller in a
multi-unit group, and a changed revision or closure hash requires a new
assignment admission rather than late-bound expansion.

A physical work subject that distributes or reconciles work across multiple
embodied units or execution-node memberships requires a distinct, current
`FleetMissionAllocationLease` for each affected assignment. A
`RobotFleetRecord` with one unit does not require a coordination record or fleet
allocation lease merely because it is represented as a fleet; those contracts
become required only when the physical work actually crosses unit or execution-member
boundaries. Naming a multi-unit resource group does not collapse those
assignments, allocation leases, controller boundaries, or reconciliation
obligations into one placement.

An admitted embodied execution assignment binds one exact
`EmbodiedRuntimeGraphManifestEnvelope` revision and hash plus the exact hashes
of graph partitions placed by that assignment. `native_runtime_profile` is required
exactly when `execution_target` is `native`; it selects the `micro`, `edge`, or
`site` deployment footprint
without implying that all three profiles share one binary or operating system.
An active assignment also binds the current successful
`EmbodiedGraphActivationTransaction`. A proposed or admitted-but-not-active assignment
may leave `graph_activation_ref` null. The activation must name the same graph
hash, assignment, partitions, controller/resource bindings, runtime node, and
system membership; otherwise activation fails closed. External compatibility
execution still binds the compiled graph, but leaves `native_runtime_profile`
null and resolves the admitted external adapter through that graph.

No `SpacetimeReservationLease` is embedded in the assignment. Assignment and
`FleetMissionAllocationLease` determine placement and who owns which work;
spacetime reservations separately constrain where and when a unit may attempt
physical occupancy. Neither object expands the other's scope or authorizes an
actuator.

An embodied unit may have no current assignment while it is inventory-only,
commissioning, unplaced idle, detached, under maintenance, offline, retired, or
otherwise outside an admitted execution placement. Historical and superseded
assignment refs remain lineage only. Neither an embodied identity,
resource-group binding, controller binding, fleet allocation lease, nor
`RuntimeAssignmentEnvelope` authorizes actuation; Physical Action Safety and
the admitted physical-mission/action authority envelopes remain mandatory.

For an ordinary non-system local assignment, `system_id` and every
`system_placement` field may be null. Once `system_id` is non-null, an admitted
or active assignment must bind the system's active deployment profile, the
selected node's current membership and membership epoch, and the declared node
role. `node_id` must match that membership. A role lease is additionally
required whenever the selected membership or deployment policy requires one.
Membership, role, and assignment leases must all remain current before an
effect is admitted. The assignment never widens the authority already carried
by those records and grants.

`required_state_watermark_ref`, `required_state_root`, assignment epoch, and
predecessor drain/fencing evidence prevent a replacement or partitioned worker
from proceeding on silently stale state. `bounded_local_execution` and
`disconnected_autonomy` are valid only under the referenced system partition
policy; they do not permit undeclared external effects or override the
independently enforceable local safety boundary. An ambiguous predecessor
effect requires satisfied reconciliation
before activation. A `non_retryable` or `reconciliation_required` effect cannot
be reassigned as a fresh attempt merely because its runtime disappeared.

One logical GoalRun may therefore have several assignments for parallel roles,
independent replication, failover, or fleet/swarm execution while remaining
inside one system's constitution and operational truth. Same-system placement
and coordination are native L0 operations and do not use AIIP semantics.
Cross-system work does not share this placement object: each sovereign
participant admits its own local `RuntimeAssignmentEnvelope`, and AIIP carries
the accepted handoff, terms, permitted evidence, and result between those
systems. No AIIP packet, remote GoalRun, or foreign role topology grants
placement or node authority inside another system.

## AuthorityScopeRequestEnvelope

```yaml
AuthorityScopeRequestEnvelope:
  authority_request_id: authority-request://...
  principal_ref: principal://... | wallet://... | org://...
  product_session_ref: session://... | null
  origin_binding_ref: origin-binding://... | origin://... | null
  subject_id: system://... | agent://... | worker://... | runtime://...
  issuer_id: system://... | wallet://... | org://... | policy://...
  requesting_runtime_ref: runtime://... | null
  purpose: string
  auth_factor_refs:
    - auth_factor://...
  guardian_surface_ref: guardian://... | null
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
  destination_refs: []
  risk_classes: []
  policy_hash: hash
  request_hash: sha256:...
  authority_grant_id: grant://... | null
  status: requested | granted | denied | expired | revoked
```

`product_session_ref` identifies a session owned by the product or deployment
identity plane; wallet.network binds it into the request but does not own that
session's lifecycle. `request_hash` commits the canonical RFC 8785 JCS encoding
of every immutable request field above except `request_hash`,
`authority_grant_id`, and `status`. It therefore binds the principal, product
session, origin, acting subject/runtime, purpose, factors/guardian posture, exact
capabilities/scopes/resources/destinations, budget/expiry constraints, risk,
and policy. Review, grant issuance, and effect admission resolve the same body
and reject any field substitution.

## AuthorityGrantEnvelope

The canonical v1 and portable v2 JSON wire shapes, cross-field invariant
profiles, and golden fixtures are registered by
[`architecture-contract-registry.v1.json`](../_meta/schemas/architecture-contract-registry.v1.json).
That machine form owns field presence and validation for those versions; this
section retains semantic ownership. The `grant_id` spelling is a read-side
v1 compatibility-adapter alias only and is rejected on canonical writes.

```yaml
AuthorityGrantEnvelope:
  authority_grant_id: grant://...
  request_id: authority-request://...
  issuer_id: system://... | wallet://... | org://... | policy://...
  subject_id: system://... | agent://... | worker://... | runtime://...
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

Portable v2 is the registered signed-wire successor for authority that must
cross a process, runtime, or sovereign-system boundary. It binds the exact holder identity and
holder key, audience, issuer key-set identity/version, validity interval,
revocation epoch, resources, primitive capabilities, authority scopes, caveats,
risk restrictions, parent proof, registered schema hash, and canonical body
hash. Its canonical encoding is RFC 8785 JCS. The Ed25519 signature preimage is
domain separated as `IOI-AUTHORITY-GRANT-ENVELOPE-V2\0` followed by the JCS
encoding of `body_hash`, `schema_hash`, and `signature_domain`.

`AuthorityKeySet` v1 and signed `AuthorityRevocationSnapshot` v1 are verification
inputs, not new authority owners. Verification fails closed on an untrusted or
mismatched key set, inactive key or grant, wrong audience/holder, stale or
invalid revocation snapshot, revoked grant/key, body/schema/signature mismatch,
missing parent proof, parent-link mismatch, delegation cycle, or widened child.
A delegated child must be issued by the parent holder key and may only narrow
scopes, primitive capabilities, resources, risk classes, budget, calls, and
validity while retaining or adding caveats and approval requirements.

A conforming verifier operates over a caller-supplied locally trusted key set
and bounded-freshness signed revocation snapshot. Current master registers the
wire contract, invariants, fixtures, and generated projections but does not
contain the portable Ed25519/JCS verifier or an offline CLI. Network key
discovery, trust-root acquisition, transparency infrastructure, and universal
revocation distribution remain separate planned work.

Portable v3 is the target successor required before the embedded
sign-in-to-effect product proof. It retains the v2 portability and attenuation
contract and additionally signs:

```yaml
request_commitment:
  authority_request_id: authority-request://...
  authority_request_body_hash: sha256:...
  principal_ref: principal://... | wallet://... | org://...
  product_session_ref: session://... | null
  origin_binding_ref: origin-binding://... | origin://... | null
  auth_factor_refs:
    - auth_factor://...
  guardian_surface_ref: guardian://... | null
  authority_review_receipt_ref: receipt://...
  approval_evidence_root: sha256:...
```

The signed v3 grant is independently verifiable against the exact
`AuthorityScopeRequestEnvelope` body and review receipt. A subject, session,
origin, request, factor, guardian, resource, destination, budget, policy, or
risk substitution invalidates the commitment. A null session or origin is
permitted only when the selected non-browser/non-product policy explicitly
declares that posture; it is never inferred by omission. V1 and v2 remain
immutable compatibility contracts. V3 requires a new registered schema,
fixtures, generated Rust/TypeScript projections, and verifier support rather
than silently changing either registered version.

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
  task_id: task://...
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
  run_id: run://...
  task_id: task://...
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  effective_learning_policy_hash: hash | null
  goal_ref: goal://... | null
  outcome_room_ref: outcome-room://... | null
  participant_lease_ref: participant-lease://... | null
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: hash | null
  task_offer_and_acceptance_refs:
    - packet://...
  work_claim_ref: work-claim://... | null
  room_admission: RoomAdmittedObjectBase | null
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
  event_id: event://...
  parent_event_id: event://... | null
  run_id: run://...
  task_id: task://...
  turn_id: optional
  kind: session.started | model.requested | model.completed | tool.proposed | policy.decided | approval.requested | tool.started | tool.completed | artifact.created | ontology.bound | data_recipe.run_started | data_recipe.run_completed | transformation.receipt_emitted | distilled_dataset.bound | evaluation_dataset.bound | ontology_projection.updated | environment.failure_detected | environment.recovery_planned | environment.recovery_started | environment.recovery_completed | environment.recovery_failed | workrun.recovery_reconciled | resource.allocation_requested | resource.allocation_decided | resource.budget_warning | resource.budget_exhausted | resource.preemption_decided | resource.degradation_applied | scheduler.catchup_planned | scheduler.catchup_executed | assurance.policy_pack.applied | assurance.policy_pack.blocked | assurance.audit_export.requested | assurance.audit_export.generated | assurance.audit_export.delivered | assurance.audit_export.revoked | collaboration.context_created | collaboration.party_joined | collaboration.party_removed | collaboration.view_granted | collaboration.view_revoked | collaboration.proof_bundle_generated | orchestration.decision_recorded | training.foundry_spec_admitted | training.dataset_snapshot_materialized | training.run_plan_admitted | training.evidence_eligibility_recorded | training.dataset_factory_started | training.dataset_factory_completed | training.batch_planned | training.generation_batch_archived | training.teacher_session_started | training.teacher_session_completed | training.candidate_data_quarantined | training.on_policy_correction_recorded | training.quality_gates_reported | training.cost_ledger_updated | training.pipeline_started | training.pipeline_stage_advanced | training.pipeline_suspended | training.pipeline_resumed | training.pipeline_completed | training.pipeline_failed | training.trial_started | training.trial_pruned | training.trial_completed | training.checkpoint_created | training.experiment_trial_started | training.experiment_trial_completed | training.experiment_trial_accepted | training.experiment_trial_rejected | training.artifact_conversion_started | training.artifact_conversion_validated | training.model_artifact_frozen | training.package_artifact_validated | training.model_registered | training.registry_version_created | training.route_binding_proposed | training.route_binding_activated | training.promotion_bundle_frozen | training.conductor_advisor_candidate_created | training.conductor_advisor_shadow_started | training.conductor_advisor_promoted | capability.regression_detected | capability.regression_adjudicated | authority_client.* | mcp_gateway.* | revocation.* | embodied.* | sim_to_real.* | assurance.* | capability.* | job.* | receipt.emitted | run.completed | run.failed
  timestamp: timestamp
  actor_id: system://... | participant-lease://... | agent://... | worker://... | service://... | runtime://... | wallet://...
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

The canonical v1 JSON wire shape, boundary-fact invariant, and golden fixtures
are registered by
[`architecture-contract-registry.v1.json`](../_meta/schemas/architecture-contract-registry.v1.json).
That machine form owns field presence and ref validation for v1; this section
and the receipt registry retain semantic and profile ownership. The encoding
profile remains deliberately null and the optional signature remains opaque in
this pilot; portable signing is a separate successor contract, not an implied
property of v1.

```yaml
ReceiptEnvelope:
  receipt_id: receipt://...
  receipt_type: registered receipt type
  receipt_profile_ref: schema://...
  attested_boundary_fact_refs: []
  claim_scope_ref: schema://... | policy://... | null
  run_id: run://... | null
  task_id: task://... | null
  actor_id: ProtocolPrincipalRef | runtime://...
  input_hash: optional
  output_hash: optional
  policy_hash: optional
  authority_grant_id: grant://... | null
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
  public_commitment_ref: commitment://... | settlement://... | tx://... | null
```

The exhaustive `receipt_type` registry and cross-component field-level schemas
live in the events/receipts owner. This file owns only the portable base
envelope shared by every registered profile. A receipt proves only
its declared bound facts;
the evidence, verification, acceptance, adjudication, and settlement refs above
must not be inferred merely because a receipt exists.

For the registered target portable proof profile,
`ioi.receipt-envelope-jcs-sha256.v1` means SHA-256 over the RFC 8785 JCS bytes
of the exact closed v1
`ReceiptEnvelope`. Every present v1 field—including its legacy opaque
`signature`, when present—is inside that hash. The hash is then bound into a
domain-separated, indexed accumulator leaf. The signed checkpoint, inclusion
witness, consistency witness, and export-manifest rules are owned by
[`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md#receipt-checkpoints-and-offline-proofs).

## ArtifactEnvelope

```yaml
ArtifactEnvelope:
  artifact_id: artifact://...
  cid: bafy...
  sha256: hash
  lineage_commitment: hash
  size_bytes: integer
  media_type: string
  artifact_role:
    immutable_source_snapshot | derived_export | evidence | deliverable |
    runtime_intermediate | package_payload | other
  source_lineage:
    editable_domain_object_ref:
      agentgres://object/... | project://... | ontology://... | workflow://... |
      goal://... | system://... | null
    editable_domain_object_revision_ref:
      agentgres://state-root/... | commitment://... | artifact://... | null
    source_snapshot_artifact_ref: artifact://... | null
    parent_artifact_refs: []
    derivation_kind:
      none | deterministic_export | receipted_transformation |
      compilation | rendering | conversion | aggregation | other
    derivation_run_ref: run://... | transform://... | conversion://... | null
    derivation_contract_ref: tool://... | workflow-template://.../revision/... | schema://... | null
    derivation_receipt_ref: receipt://... | null
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
    data_recipe_revision_ref: data-recipe://.../revision/... | null
    data_recipe_content_hash: hash | null
    transformation_run_id: optional
  access_policy_ref: optional
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  derivative_policy_ref: policy://... | null
  impact_graph_ref: agentgres://projection/... | null
```

Editable canvas, document, design, ontology, source-tree, campaign, and other
domain state remains owned by its domain object. `ArtifactEnvelope` captures an
immutable snapshot or materialization of that state. A `derived_export` must
name the exact `source_snapshot_artifact_ref` and the tool, workflow revision,
or transformation contract plus its run and receipt; it may never point only
at a mutable editor object. Exporting therefore uses deterministic or
receipted tool/workflow machinery and explicit source -> snapshot -> derived
lineage. It does not create an `ExportHarness` or transfer artifact ownership
to a HarnessProfile.

`lineage_commitment` binds the payload `sha256`, `artifact_role`, and complete
`source_lineage` object so metadata cannot be rewritten while retaining the
same artifact commitment. For `immutable_source_snapshot`, the editable object
and exact editable revision are required, `source_snapshot_artifact_ref` is
null, and `derivation_kind` is `none`. For `derived_export`, the source snapshot
ref, derivation contract, run, and receipt are all required; the source ref must
resolve to an `immutable_source_snapshot`. The derivation receipt must bind the
output payload hash, output lineage commitment, source-snapshot ref and payload
hash, derivation contract, and derivation run. Any missing or inconsistent
conditional field fails admission.

## DeliveryEnvelope

```yaml
DeliveryEnvelope:
  delivery_id: delivery://...
  service_order_id: order://... | null
  buyer_domain_ref: optional system://... | domain://... | wallet://...
  provider_domain_ref: optional system://... | domain://... | service://...
  worker_invocation_id: invocation://... | null
  run_id: run://...
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
  delivery_status: draft | partial | submitted | cancelled
  acceptance_status: pending | accepted | accepted_partial | rejected | revision_requested
  adjudication_status: none | disputed | adjudicating | resolved
  settlement_status: not_requested | intent_created | pending | settled | paid | refunded | slashed | failed
  acceptance_deadline: optional
```

## Managed Work Billing Object Family

Managed-work billing is one immutable, append-only product-budget chain:

```text
versioned RateCard + versioned Plan
  -> immutable WorkQuote
  -> finite CreditHold
  -> append-only UsageRecord entries
  -> typed OverrunDecision -> exact additional CreditHold or block
  -> one FinalDebit
  -> append-only BillingAdjustment records (refund or writeoff)
```

All money uses integer currency-minor units. Work Credits use integer
`micro_work_credit` units. Floating-point amounts, ambiguous decimal strings,
and implicit unit conversion are invalid. Money, Work Credits, and coarse OCU
telemetry are different dimensions and never share an amount field.

```yaml
WorkCreditAmount:
  unit: micro_work_credit
  units: nonnegative_safe_integer

ManagedWorkCostBreakdown:
  currency_code: ISO-4217-code
  provider_cost_minor: nonnegative_safe_integer
  broker_fee_minor: nonnegative_safe_integer
  participant_cost_minor: nonnegative_safe_integer
  verifier_cost_minor: nonnegative_safe_integer
  ioi_fee_minor: nonnegative_safe_integer
  excluded_customer_borne_provider_cost_minor: nonnegative_safe_integer
  supplier_reconciliation_state:
    not_applicable | estimated | supplier_statement_reconciled
```

`provider_cost_minor` records managed supplier cost only.
`broker_fee_minor`, `participant_cost_minor`, `verifier_cost_minor`, and
`ioi_fee_minor` remain separately attributable. BYOK, BYOA, customer-cloud,
self-hosted, and local execution put customer-borne provider cost only in
`excluded_customer_borne_provider_cost_minor`; that excluded amount cannot
enter the Work Credit debit. The Work Credit charge comes from the quoted
RateCard, not by adding these money fields.

```yaml
RateCard:
  rate_card_ref: rate-card://...
  version: positive_integer
  body_hash: canonical_exact_body_hash
  currency_code: ISO-4217-code
  meter_rates:
    - meter_class: string
      work_credit_micro_units_per_meter_unit: nonnegative_safe_integer
      charge_component:
        managed_model | managed_runtime | broker | participant | verifier |
        ioi_managed_service | non_billable_telemetry
  ioi_fee_policy_ref: fee-basis://...
  issued_at_ms: integer
  expires_at_ms: integer

Plan:
  plan_ref: plan://...
  version: positive_integer
  body_hash: canonical_exact_body_hash
  rate_card_ref: rate-card://...
  rate_card_body_hash: hash
  included_work_credits: WorkCreditAmount
  reset_policy:
    non_resetting | monthly_expiring | contract_term_expiring
  issued_at_ms: integer
  expires_at_ms: integer

WorkQuote:
  quote_ref: quote://...
  body_hash: canonical_exact_body_hash
  rate_card_ref: rate-card://...
  rate_card_body_hash: hash
  plan_ref: plan://...
  plan_body_hash: hash
  estimated_work_credits: WorkCreditAmount
  required_hold: WorkCreditAmount
  overrun_policy: block | exact_additional_hold
  max_attempt_count: positive_integer
  allowed_commercial_postures:
    - managed | customer_byok | customer_byoa | customer_cloud |
      self_hosted | local
  issued_at_ms: integer
  expires_at_ms: integer
```

A RateCard or Plan is a versioned immutable revision. A quote freezes their
exact refs and body hashes, its own finite expiry, permitted commercial
postures, route-attempt ceiling, hold amount, and exact overrun policy.
Quote admission fails when the RateCard or Plan is expired, the quote outlives
either input, or any referenced body hash differs. Reusing a quote ref with
different canonical bytes is a conflict, never an update.

```yaml
CreditHold:
  hold_ref: credit-hold://...
  body_hash: canonical_exact_body_hash
  quote_ref: quote://...
  idempotency_key: string
  hold_kind: initial | exact_additional
  overrun_decision_ref: overrun-decision://... | null
  amount: WorkCreditAmount
  created_at_ms: integer
  expires_at_ms: integer
  status: active | consumed | released

UsageRecord:
  usage_ref: usage://...
  body_hash: canonical_exact_body_hash
  quote_ref: quote://...
  sequence: positive_integer
  previous_usage_hash: hash | null
  runtime_receipt_refs: [receipt://...]
  supplier_statement_refs: [supplier-statement://...]
  meter_class: string
  quantity_units: nonnegative_safe_integer
  rate_work_credit_micro_units_per_meter_unit: nonnegative_safe_integer
  charged_work_credits: WorkCreditAmount
  commercial_posture:
    managed | customer_byok | customer_byoa | customer_cloud |
    self_hosted | local
  cost_breakdown: ManagedWorkCostBreakdown
  coarse_ocu_projection: boolean
  occurred_at_ms: integer
```

The first hold is positive, finite, no larger than the quote's required hold,
and no later than the quote expiry. An additional hold requires the exact
unconsumed `OverrunDecision`, amount, usage head, and quote. Same
idempotency-key plus same canonical command bytes replays the existing result;
same key plus different bytes is a conflict.

Every UsageRecord binds one or more owner-derived runtime receipts. Sequence
and `previous_usage_hash` form an unbroken append-only usage chain. A conforming
future kernel must re-resolve the frozen rate and compute
`quantity_units * work_credit_micro_units_per_meter_unit` with checked integer
arithmetic; a caller-supplied charge or stale usage head is invalid. Managed
provider cost can claim `supplier_statement_reconciled` only with matching
supplier-statement evidence. Customer-borne postures require
`provider_cost_minor: 0`. A coarse OCU projection is always
`non_billable_telemetry` and cannot mint invoice-grade usage or a Work Credit
debit.

```yaml
OverrunDecision:
  overrun_decision_ref: overrun-decision://...
  body_hash: canonical_exact_body_hash
  quote_ref: quote://...
  usage_head_hash: hash | null
  held_work_credits: WorkCreditAmount
  projected_work_credits: WorkCreditAmount
  exact_overage_work_credits: WorkCreditAmount
  decision: block | exact_additional_hold
  additional_hold_amount: WorkCreditAmount
  created_at_ms: integer

FinalDebit:
  final_debit_ref: final-debit://...
  body_hash: canonical_exact_body_hash
  quote_ref: quote://...
  usage_head_hash: hash | null
  usage_record_refs: [usage://...]
  hold_refs: [credit-hold://...]
  debited_work_credits: WorkCreditAmount
  finalized_at_ms: integer

BillingAdjustment:
  adjustment_ref: billing-adjustment://...
  body_hash: canonical_exact_body_hash
  final_debit_ref: final-debit://...
  previous_adjustment_hash: hash | null
  adjustment_kind: refund | writeoff
  amount: WorkCreditAmount
  reason_code: string
  evidence_refs: [receipt://... | supplier-statement://... | decision://...]
  created_at_ms: integer
```

An overrun decision binds the current usage head, current active held amount,
and exact projected total. `block` requires zero additional amount.
`exact_additional_hold` is valid only when selected by the quote and requires
an additional hold equal to the checked projected-total-minus-held-total
overage. Usage cannot cross the active held amount before that hold is durably
appended.

FinalDebit is unique per quote, binds the current usage head and complete usage
and hold sets, and equals the checked sum of chargeable UsageRecords. Finalizing
twice, appending usage after finalization, or debiting more than active held
Work Credits fails closed. A BillingAdjustment is append-only and downward-only
in v1: refund and writeoff remain distinct reasons, bind the FinalDebit and
prior adjustment head, and their cumulative amount cannot exceed the one debit.
This record does not itself transfer money, replenish a credit balance, settle
a supplier invoice, or execute a refund rail.

```yaml
ManagedWorkBillingLedgerBundle:
  schema_version: ioi.foundations.managed-work-billing-ledger-bundle.v1
  bundle_ref: billing-bundle://...
  billing_account_ref: billing-account://...
  work_ref: goal://... | goal-run://... | automation-run://... |
    work-run://... | invocation://... | order://...
  rate_card: RateCard
  plan: Plan
  quote: WorkQuote
  holds: [CreditHold]
  usage_records: [UsageRecord]
  overrun_decisions: [OverrunDecision]
  final_debit: FinalDebit | null
  adjustments: [BillingAdjustment]
  ledger_head_hash: hash
  exported_at_ms: integer
  assurance_status:
    internal_event_log | supplier_partially_reconciled | supplier_reconciled
```

The bundle is a portable projection of the append-only ledger, not a mutable
invoice. Its `ledger_head_hash` commits the ordered entry chain. A conforming
future store must admit only owner-derived runtime, billing-account, and
supplier evidence; no public caller-authored supplier-usage mint is defined.
Supplier reconciliation is claimable only when the corresponding statement
refs have been resolved and verified by their owner. The registered v1 contract
is
[`managed-work-billing-ledger-bundle.v1.schema.json`](../_meta/schemas/managed-work-billing-ledger-bundle.v1.schema.json).

## SettlementEnvelope

```yaml
SettlementEnvelope:
  schema_version: ioi.settlement.v2
  settlement_id: settlement://...
  system_id: system://... | null
  settlement_domain_ref: domain://...
  subject_ref: system://... | order://... | delivery://... | task://... | worker://... | service://... | package://... | license://... | contract://... | account://... | contribution://... | settlement-intent://... | network-service-invocation://...
  settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
  settlement_profile_ref: policy://...
  network_enrollment_ref: network-enrollment://... | null
  public_commitment_policy_ref: policy://... | null
  rail:
    network_or_ledger_ref: agentgres://... | network://... | chain://... | invoice://... | null
    contract_ref: contract://... | null
    payer_account_ref: wallet://... | account://... | null
    payee_account_ref: wallet://... | account://... | null
    asset_kind: none | fiat | stablecoin | native_asset | service_credit
    asset_identifier: string | null
    amount: decimal_string | null
  product_budget_ref: budget://... | null
  work_credit_debit_ref: receipt://... | null
  action: obligation_create | obligation_update | payment_request | payment_record | payment_acknowledge | adjustment | escrow_lock | payout_release | partial_payout | refund | partial_refund | slash | bond_lock | bond_release
  related_delivery_ref: delivery://... | null
  related_acceptance_decision_ref: acceptance://... | decision://... | null
  related_adjudication_ref: decision://... | dispute://... | null
  related_settlement_intent_ref: settlement-intent://... | null
  related_receipt_root: hash | null
  receipt_condition_refs: []
  settlement_receipt_refs: []
  status: drafted | submitted | pending | settled | disputed | reversed | failed
  ledger_or_transaction_ref: optional
```

`local_domain` is the default. `ioi_l1` is valid only when an active
`IOINetworkEnrollmentEnvelope` selects the matching service; no other mode
silently upgrades to it. Work Credits remain non-transferable product budget
units: `work_credit_debit_ref` may prove an IOI product-budget charge or refund,
but Work Credits are not the provider payout asset, protocol token, or generic
settlement rail. External money and chain rails declare their actual asset,
network, contract, accounts, authority, and receipt lineage.

Action availability is profile-conditional. Local-domain, bilateral, and
invoice modes use obligation, request, record, acknowledgement, and adjustment
actions without pretending an escrow payout occurred. Escrow, external-chain,
and IOI-L1 modes may additionally use lock, release, refund, bond, and slash
actions only when their declared contract and authority path support them.

Acceptance and adjudication are prerequisites/conditions, not settlement
actions. `SettlementEnvelope` references their decisions and may release or
reverse value, bonds, or contractually due consideration only after the declared conditions pass; it cannot create
acceptance or resolve a dispute by relabeling a settlement action.

## NetworkServiceInvocationEnvelope

Selected registry, rights, license, reputation, and handoff-finality services
are orthogonal to the rail used to pay for them. They use this profile-neutral
contract rather than overloading `SettlementEnvelope`:

```yaml
NetworkServiceInvocationEnvelope:
  schema_version: ioi.network-service-invocation.v1
  network_service_invocation_id: network-service-invocation://...
  system_id: system://... | null
  subject_ref: system://... | domain://... | worker://... | service://... | package://... | license://... | delivery://... | contribution://... | commitment://...
  service_kind: registry | rights | reputation | finality
  service_subprofile: worker_license | artifact_license | dataset_license | handoff_finality | null
  operation: register | publish | commit | issue | transfer | revoke | finalize | challenge
  service_ref: service://...
  terms_ref: terms://...
  network_or_domain_ref: network://... | domain://...
  network_enrollment_ref: network-enrollment://... | null
  public_commitment_policy_ref: policy://... | null
  expected_predecessor_commitment_ref: commitment://... | null
  request_root: hash
  governing_decision_ref: decision://... | null
  authority_grant_refs: []
  resulting_commitment_ref: commitment://... | tx://... | null
  service_receipt_refs: []
  status: proposed | authorized | submitted | committed | challenged | rejected | failed
```

An IOI Network service invocation requires an active connected or secured
enrollment that selected the matching `service_kind`; a local or external
service names its own domain/network and leaves that enrollment null. The
service's selection and public-commitment policy govern the operation. Its fee
may settle through any allowed settlement mode, so `ioi_l1` settlement is
required only when IOI L1 is itself the selected economic rail.

## ContributionEnvelope

```yaml
ContributionEnvelope:
  contribution_id: contribution://...
  contributor_ref:
    system://... | participant-lease://... | worker://... | service://... | ioi://publisher/... | tool://... |
    org://... | domain://...
  contributor_role:
    autonomous_system | worker | service | publisher | tool | verifier | reviewer |
    resource_provider | semantic_mapper | organization
  operator_ref: user://... | wallet://... | org://... | domain://... | null
  affiliation_refs: []
  consumer_id: system://... | wallet://... | service://... | agent://...
  task_ref: task://... | null
  run_ref: run://... | null
  outcome_room_ref: outcome-room://... | null
  participant_lease_ref: participant-lease://... | null
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: hash | null
  task_offer_and_acceptance_refs:
    - packet://...
  work_claim_ref: work-claim://... | null
  room_admission: RoomAdmittedObjectBase | null
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
  routing_decision_ref: routing-decision://... | null
  reward_basis_ref:
    policy://... | rate-card://... | quote://... | order://... |
    budget://... | null
  attributed_model_and_route_refs:
    - model://... | model_route://... | registry_version://...
  downstream_outcome_ref: optional
  derivation_refs:
    - contribution://... | attempt://... | artifact://... | finding://...
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
system, service, publisher, tool, organization, or domain boundary that accepted the
contribution obligations; model and route identity remains in
`attributed_model_and_route_refs`.

When `outcome_room_ref` is non-null, `participant_lease_ref` and
`room_admission` are required and must bind that same room; `contributor_ref`
must resolve through the lease. A raw system, worker, service, organization, or
domain ref cannot claim a room contribution outside admitted participation or
the room's compare-and-swap commitment spine.

When external or multi-party terms apply, the contribution binds the exact
terms root, selected response, routing decision, claim, and reward basis in
force when work was awarded. Later amendments cannot retroactively change its
attribution, eligibility, license, or reward basis. A contribution or receipt
establishes attributable work under declared terms; it is not itself an
allocation, acceptance, or payout decision.

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
  admission_domain_ref: agentgres://domain/... | domain://...
  version: semver_or_hash
  predecessor_version_ref: ontology://... | null
  base_ontology_version_refs:
    - ontology://...
  governing_scope_ref: system://... | domain://... | org://... | project://... | service://...
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
  owner_id: system://... | wallet://... | org://... | service://...
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
  fact_class_ref: ontology://...#fact-class | null
  subject_ref: object://... | ontology-assertion://...
  predicate_ref: ontology://...#property_or_relationship
  object_or_value_ref: object://... | scalar | artifact://...
  valid_time: interval | null
  transaction_time: timestamp
  source_and_observation_context_refs:
    - source://... | observation://... | attempt://... | system://... | domain://...
  confidence_or_uncertainty: number | null
  supporting_evidence_refs:
    - evidence://... | receipt://... | artifact://...
  contradicting_assertion_refs:
    - ontology-assertion://... | finding://...
  oracle_evidence_profile_ref: oracle-evidence-profile://... | null
  oracle_evidence_admission_receipt_ref: receipt://... | null
  ontology_assertion_admission_receipt_ref: receipt://... | null
  applicability_scope_ref: policy://... | system://... | domain://... | null
  permitted_consequence_scope_refs:
    - policy://...
  causal_or_counterfactual_context_ref: artifact://... | finding://... | null
  supersedes_ref: ontology-assertion://... | null
  dispute_ref: dispute://... | null
  status:
    proposed | evidence_pending | held_unknown | admitted | contradicted |
    superseded | disputed | rejected
```

`oracle_evidence_admission_receipt_ref` identifies the evaluator's qualified
determination under the selected oracle/evidence profile.
`ontology_assertion_admission_receipt_ref` identifies the separate
`OntologyAssertionAdmissionReceipt` through which Agentgres/the domain admits
the assertion as operational truth. When an oracle/evidence profile governs an
assertion, `status: admitted` requires both receipts. Both bind the same
assertion commitment, fact class, profile revision, applicability scope, and
permitted consequence-scope set; the selected scopes must be permitted by the
active profile. Neither receipt can be substituted for the other.

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
  decided_by_ref: system://... | worker://... | org://... | domain://... | policy://... | null
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
  data_recipe_id: data-recipe://...
  revision_ref: data-recipe://.../revision/...
  predecessor_revision_ref: data-recipe://.../revision/... | null
  content_hash: hash
  owner_ref: org://... | project://... | system://... | domain://... | ioi://publisher/...
  semantic_component_set_snapshot_ref: artifact://...
  semantic_component_set_hash: hash
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
  output_dataset_contract_refs:
    - schema://... | object-model://...
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
  registry_lifecycle_ref: agentgres://object/... | package://.../release/... | null
  registry_status: draft | active | deprecated | revoked
```

Each released DataRecipe revision is immutable and content-addressed. It
declares transformations and output contracts but contains no concrete dataset,
distilled output, artifact, authority grant, run, or receipt. Those belong to
`TransformationRunEnvelope` and the resulting dataset/artifact objects.
`semantic_component_set_snapshot_ref` enumerates the exact revision ref and
content hash for every ontology version, ConnectorMapping, object model,
schema/contract, and policy-bound view named by the readable family-ref fields.
`content_hash` commits that snapshot ref and set hash, so a released recipe
cannot silently resolve a newer mapping or semantic head. Registry
lifecycle/status are excluded projections. `recipe://` is a typed legacy
DataRecipe alias only; it never identifies a generic recipe family.

## ConnectorMappingEnvelope

```yaml
ConnectorMappingEnvelope:
  connector_mapping_id: mapping://...
  revision_ref: mapping://.../revision/...
  predecessor_revision_ref: mapping://.../revision/... | null
  content_hash: hash
  semantic_component_set_snapshot_ref: artifact://...
  semantic_component_set_hash: hash
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
  registry_lifecycle_ref: agentgres://object/... | package://.../release/... | null
  registry_status: draft | active | deprecated | revoked
```

Each ConnectorMapping revision is immutable. Its semantic-component snapshot
commits the exact connector contract/schema, ontology version, target object
models, policy, and evidence-contract revisions/hashes represented by the
readable family refs. `content_hash` commits the snapshot ref and hash;
registry lifecycle/status remain excluded projections. Any field, action,
schema, ontology, object-model, or policy change creates a successor mapping
revision.

## LearningSourceRightsClaimEnvelope

A learning-source-rights claim records the evidence-backed rights posture that
policy uses to admit or reject inference, evaluation, improvement, derivative,
or export uses. It is an auditable assertion, not proof of legal title or an
automatic grant of authority.

```yaml
LearningSourceRightsClaimEnvelope:
  source_rights_claim_id: learning-source-rights://...
  subject_refs:
    - artifact://... | receipt://... | dataset://... | view://... |
      connector://... | memory://... | trace://... | model://... |
      worker://... | package://...
  source_class:
    employee | contractor | customer | patient | partner | vendor |
    licensed | purchased | public | synthetic | provider_output |
    machine_generated | mixed | unknown
  asserted_by_ref: user://... | org://... | system://... | project://...
  asserted_rights_holder_refs:
    - user://... | org://... | system://... | project://... | provider://...
  rights_basis_refs:
    - contract://... | terms://... | policy://... | grant://... |
      authority://... | license://... | evidence://...
  provider_or_model_route_contract_refs:
    - model-route-contract://...
  permitted_uses:
    - operational_inference
    - retain
    - replay
    - internal_evaluation
    - internal_analytics
    - memory_or_context_improvement
    - dataset_generation
    - fine_tune
    - distill
    - competing_model_training
    - worker_or_package_improvement
    - commercialize_derivative
    - export
    - publish
    - cross_tenant_aggregate_learning
  prohibited_uses: []
  derivative_disposition:
    inherit_intersection | internal_only | transferable_with_claims |
    noncommercial_only | no_derivatives | policy_defined
  beneficiary_scope_refs:
    - user://... | org://... | project://... | system://... | worker://...
  jurisdiction_and_region_refs: []
  retention_policy_ref: policy://...
  deletion_or_forget_policy_ref: policy://...
  validity:
    valid_from: timestamp
    valid_until: timestamp | null
  evidence_refs:
    - evidence://... | receipt://... | artifact://...
  claim_commitment: hash
  supersedes_ref: learning-source-rights://... | null
  status: asserted | admitted | disputed | expired | superseded | revoked | rejected
```

Unknown, expired, disputed, conflicting, or unsupported claims fail closed for
training, distillation, publication, cross-tenant learning, and export. A
separate policy may admit operational inference when its own access and use
rights are established.

## InstitutionalLearningBoundaryProfileEnvelope

The Institutional Learning Boundary is a composition profile over existing
authority, truth, runtime, custody, routing, data, and Foundry owners. Its
canonical doctrine and narrowing semantics are owned by
[`institutional-learning-boundary.md`](./institutional-learning-boundary.md).

```yaml
InstitutionalLearningBoundaryProfileEnvelope:
  schema_version: ioi.institutional-learning-boundary.v1
  boundary_profile_id: learning-boundary://...
  revision: semver_or_hash
  scope_level:
    organization | project | system | session | run |
    model_invocation | transformation | foundry_job
  scope_owner_ref:
    org://... | project://... | system://... | session://... | goal://... |
    run://... | invocation://... | transform://... | foundry_job://...
  applies_to_refs:
    - org://... | project://... | system://... | domain://... |
      session://... | goal://... | run://... | invocation://... |
      transform://... | foundry_job://... | worker://...
  governance_owner_ref: org://... | project://... | system://...
  parent_profile_refs:
    - learning-boundary://...
  system_binding:
    system_ref: system://... | null
    constitution_ref: constitution://... | null
    deployment_profile_ref: deployment-profile://... | null
    upgrade_required_for_widening: true
  protected_material_classes:
    - source_data
    - prompts_and_completions
    - connector_and_tool_io
    - work_graphs_traces_and_receipts
    - corrections_and_reviewer_judgments
    - evaluations_rubrics_holdouts_and_canaries
    - memory_context_procedures_workflows_and_skills
    - datasets_embeddings_and_indexes
    - adapters_checkpoints_weights_and_packages
    - router_verifier_authority_and_governance_policy
    - analytics_crash_support_and_security_telemetry
    - embodied_sensor_actuator_mission_and_operator_telemetry
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  enterprise_permitted_uses:
    - operational_inference
    - retain
    - replay
    - internal_evaluation
    - internal_analytics
    - memory_or_context_improvement
    - dataset_generation
    - fine_tune
    - distill
    - competing_model_training
    - worker_or_package_improvement
    - commercialize_derivative
    - export
    - publish
  enterprise_prohibited_uses: []
  external_recipient_permissions:
    transient_inference: allow | deny | policy_qualified
    service_logging: allow | deny | policy_qualified
    abuse_or_security_review: allow | deny | policy_qualified
    human_support_review: allow | deny | policy_qualified
    retention: allow | deny | policy_qualified
    service_improvement: allow | deny | policy_qualified
    provider_model_training: allow | deny | policy_qualified
    cross_customer_aggregation: allow | deny | policy_qualified
    publication: allow | deny | policy_qualified
  cross_tenant_learning:
    default: deny
    permitted_cohort_refs: []
    aggregation_policy_ref: policy://... | null
    contribution_and_benefit_terms_ref: terms://... | null
  route_and_custody:
    product_mode: standard | private
    runtime_operator: ioi_managed | customer_managed | local | hybrid
    permitted_provider_trust_postures: []
    permitted_custody_postures: []
    model_route_contract_refs:
      - model-route-contract://...
    private_claim_requires_current_proof: true
  data_and_improvement_policy_refs:
    - view://... | data-recipe://.../revision/... | eligibility://... | policy://... | gate://...
  retention_policy_ref: policy://...
  deletion_or_forget_policy_ref: policy://...
  legal_or_audit_hold_policy_ref: policy://... | null
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
  export_policy_ref: policy://...
  revocation_policy_ref: policy://...
  declassification_policy_ref: policy://... | null
  receipt_obligations:
    - boundary_compilation
    - model_route_decision
    - learning_egress_decision
    - learning_evidence_eligibility
    - transformation
    - foundry_lineage
    - promotion_or_recall
    - export_or_denial
  compiled_policy_hash: hash
  effective_from: timestamp
  expires_at: timestamp | null
  supersedes_ref: learning-boundary://... | null
  status: draft | active | suspended | superseded | revoked
```

`enterprise_permitted_uses` never overrides a missing source right. Effective
policy is the most-restrictive deterministic intersection of applicable active
profiles, source-rights claims, data views, route contracts, custody rules,
retention rules, and authority decisions. Session, run, model-invocation,
transformation, and Foundry-job profiles are immutable snapshots. An active
system profile is pinned by system governance; a new organization or project
revision does not mutate it by implication.

## PolicyBoundDataViewEnvelope

```yaml
PolicyBoundDataViewEnvelope:
  view_id: view://...
  domain_id: agentgres://domain/...
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  learning_source_rights_claim_refs:
    - learning-source-rights://...
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
  data_recipe_revision_ref: data-recipe://.../revision/...
  data_recipe_content_hash: hash
  resolved_semantic_component_set_snapshot_ref: artifact://...
  resolved_semantic_component_set_hash: hash
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  effective_learning_policy_hash: hash | null
  learning_source_rights_claim_refs:
    - learning-source-rights://...
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
  derivative_policy_ref: policy://... | null
  impact_graph_ref: agentgres://projection/... | null
  receipt_refs:
    - receipt://...
  status: queued | running | completed | failed | rejected
```

The resolved semantic-component tuple must exactly equal the tuple committed by
the admitted DataRecipe revision. A run may not replace an ontology, mapping,
object model, schema, or policy-bound view with a current registry head. A
different semantic dependency set requires a successor recipe revision and a
new admission receipt.

## DistilledOntologyDatasetEnvelope

```yaml
DistilledOntologyDatasetEnvelope:
  distilled_dataset_id: dataset://...
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  ontology_refs:
    - ontology://...
  data_recipe_refs:
    - data-recipe://.../revision/...
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
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
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
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  ontology_refs:
    - ontology://...
  data_recipe_refs:
    - data-recipe://.../revision/...
  dataset_type: golden | holdout | adversarial | regression | benchmark | synthetic | distilled
  rubric_ref: rubric://...
  benchmark_profile_ref: optional
  source_commitment: hash
  privacy_policy_ref: optional
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
  artifact_refs:
    - artifact://...
  receipt_root: hash
  status: draft | active | deprecated | revoked
```

## LearningEvidenceEligibilityEnvelope

Learning evidence eligibility is the local governance, admission, consent,
rights, and privacy classification record for reusing evidence to improve a
model, worker, pursuit method, workflow, policy, evaluator, agenda, memory, or
other governed component. It is where sensitive traces, Findings, connector
outputs, enterprise documents, feedback, receipts, or artifacts are explicitly
admitted or excluded before they cross from operational evidence into a
learning or improvement loop.

This is not a wallet.network object by default. Hypervisor, Foundry, Data /
Knowledge, Ontology, domain apps, or org governance surfaces may propose the
eligibility decision; Agentgres records the admitted decision and receipts;
wallet.network supplies authority refs only when the decision requires
delegated machine power such as decryption, connector access, model-provider
keys, GPU spend, provider-trust acceptance, publication, export, or
cross-domain reuse.

```yaml
LearningEvidenceEligibilityEnvelope:
  schema_version: ioi.learning-evidence-eligibility.v1
  eligibility_id: eligibility://...
  eligibility_profile: general_learning | training_compatibility
  governance_owner_ref: org://... | project://... | system://... | agentgres://domain/... | foundry_job://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  subject_refs:
    - artifact://... | receipt://... | dataset://... | view://... |
      connector://... | finding://... | outcome-delta://... |
      work-result://... | attempt://... | trace://... | memory://...
  requester_ref:
    wallet://... | org://... | system://... | foundry_job://... | goal://... |
    improvement-campaign://...
  intended_use:
    conductor_training | worker_training | eval_generation |
    dataset_distillation | benchmark | simulation | analytics_only |
    pursuit_method_improvement | workflow_or_policy_improvement |
    evaluator_improvement | improvement_agenda_revision |
    memory_or_context_improvement | package_or_tool_improvement
  learning_use_posture:
    operational_only | evaluation_only | synthetic_only | redacted_opt_in |
    full_private_opt_in | org_policy
  applicable_evaluation_epoch_refs:
    - evaluation-epoch://...
  allowed_improvement_target_refs: []
  owner_and_tenant_scope_refs: []
  contamination_posture:
    clean | evaluation_aware | exposed | quarantined | unknown
  policy_bound_data_view_refs:
    - view://...
  data_recipe_refs:
    - data-recipe://.../revision/...
  local_policy_refs:
    - policy://...
  consent_refs:
    - grant://... | policy://... | authority://...
  wallet_authority_refs:
    - grant://... | lease://... | authority://...
  authority_requirement_kinds:
    - decryption | connector_access | model_provider_key | gpu_spend |
      provider_trust | sealed_evaluation_access | learning_egress |
      publication | export | cross_domain_reuse | none
  declassification_refs:
    - receipt://... | policy://...
  learning_egress_receipt_refs:
    - receipt://...
  provider_trust_posture:
    no_provider_plaintext | redacted_api | provider_trust_accepted |
    private_compute_required | blocked
  retention_policy_ref: policy://...
  derivative_policy_ref: policy://...
  lineage_root: hash
  exclusion_reason:
    optional operational_only_default | never_train_default |
    sealed_evaluation_material | revoked | expired | regulated_block |
    connector_scope_denied | no_provider_trust | data_subject_request |
    missing_policy_bound_view | incident_hold
  receipt_root: hash
  admitted_by_ref: optional agentgres://operation/... | policy://...
  status: proposed | eligible | excluded | revoked | expired | superseded
```

Live sealed holdout cases, labels, evaluator internals, and protected outputs
are ineligible learning evidence for the campaign they judge and for dependent
claims until their rotation/declassification policy explicitly releases them.
Recording an access receipt does not declassify its protected payload.

### TrainingEvidenceEligibilityEnvelope compatibility

`TrainingEvidenceEligibilityEnvelope` is the model/worker-training compatibility
profile of this same object, not a second eligibility decision. A compatibility
adapter accepts that envelope label and the legacy wire key
`training_evidence_eligibility_refs` only when `intended_use` is one of the
training, dataset, evaluation, or benchmark uses above; it normalizes them to
the same `eligibility_id` and emits `LearningEvidenceEligibilityEnvelope` with
`eligibility_profile: training_compatibility` and
`learning_evidence_eligibility_refs`.
The legacy `training_data_posture` field maps to `learning_use_posture`, with
`never_train` mapping to `operational_only`; conflicting old and new values fail
admission.
Training pipelines may still declare a separate `training_data_posture`; that
run configuration cannot widen the canonical learning-evidence decision.

## InstitutionalIntelligenceExportBundleEnvelope

The institutional-intelligence export bundle is a governed portability
manifest over rights-eligible state and artifacts. It records inclusions,
omissions, lineage, destination, residual obligations, and authority; it is not
a raw Agentgres dump, legal title certificate, or promise that every
provider-specific capability can move.

```yaml
InstitutionalIntelligenceExportBundleEnvelope:
  export_bundle_id: institutional-intelligence-export://...
  owner_scope_ref: user://... | org://... | project://... | system://...
  requested_by_ref: user://... | wallet://... | org://... | system://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  export_policy_ref: policy://...
  authority_refs:
    - grant://... | authority://... | policy://...
  recipient_ref: user://... | org://... | system://... | provider://... | endpoint://...
  destination_custody_posture_ref: policy://... | custody_proof://...
  included_manifest:
    ontology_and_object_model_refs: []
    data_recipe_mapping_and_view_refs: []
    wiki_memory_and_context_refs: []
    evaluation_rubric_canary_and_dataset_refs: []
    worker_workflow_skill_tool_and_package_refs: []
    adapter_checkpoint_weight_and_model_refs: []
    route_verifier_governance_and_retention_policy_refs: []
    lineage_receipt_and_state_root_refs: []
  excluded_entries:
    - subject_ref: artifact://... | dataset://... | memory://... | model://... | worker://...
      reason:
        missing_right | source_restricted | provider_restricted |
        privacy_block | retention_or_hold | revoked | incompatible |
        provider_native_unavailable | policy_defined
  payload_manifest_ref: artifact://... | cid://...
  payload_commitment: hash
  encryption_policy_ref: policy://...
  integrity_and_signature_refs:
    - receipt://... | evidence://... | artifact://...
  lineage_root: hash
  receipt_root: hash
  model_independence_report_ref: benchmark://... | gate://... | artifact://... | null
  retention_policy_ref: policy://...
  revocation_and_residual_obligation_ref: policy://... | artifact://...
  declassification_refs:
    - receipt://... | policy://...
  export_receipt_ref: receipt://... | null
  status:
    proposed | denied | assembling | ready | exported | partially_exported |
    expired | revoked
```

Export does not sever inherited restrictions. The receiver gets only the rights
and material that the bundle and its source claims admit. Revocation after an
irreversible export records future-use restrictions and residual exposure; it
must not rewrite history or claim remote deletion without evidence.

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
    - data-recipe://.../revision/...
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
    - data-recipe://.../revision/...
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
    - data-recipe://.../revision/...
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
    - data-recipe://.../revision/...
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
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  learning_source_rights_claim_refs:
    - learning-source-rights://...
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
  institutional_learning_boundary_profile_ref: learning-boundary://...
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  dataset_factory_ref: foundry_job://... | data-recipe://.../revision/...
  dataset_refs:
    - dataset://...
  content_manifest_ref: artifact://...
  split_manifest_ref: artifact://...
  source_version_refs:
    - artifact://... | connector://... | view://... | receipt://...
  slice_definitions_ref: optional artifact://...
  filtering_rules_ref: optional policy://... | artifact://...
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
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
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
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
  institutional_learning_boundary_profile_ref: learning-boundary://...
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
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
  institutional_learning_boundary_profile_ref: learning-boundary://...
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
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
  institutional_learning_boundary_profile_ref: learning-boundary://...
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
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
  institutional_learning_boundary_profile_ref: learning-boundary://...
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
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
bounded interval of native `LocalControlSupervisor` or separately assured
local-controller execution at
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

## TrainingBatchPlanEnvelope

```yaml
TrainingBatchPlanEnvelope:
  batch_plan_id: batch://...
  training_id: training://...
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
  training_id: training://...
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
  training_id: optional training://...
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
  training_id: training://...
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
  training_id: training://...
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
  training_id: training://...
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
  training_id: training://...
  target_worker_id: worker://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  requester_id: wallet://... | service://... | org://...
  provider_id: worker://... | service://... | ioi://publisher/...
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
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  foundry_spec_ref: optional foundry_spec://...
  objective: string
  source_refs:
    - artifact://... | connector://... | view://... | receipt://...
  data_recipe_refs:
    - data-recipe://.../revision/...
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
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  learning_source_rights_claim_refs:
    - learning-source-rights://...
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
  learning_evidence_eligibility_refs:
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
  foundry_job_ref: foundry_job://...
  improvement_campaign_ref: improvement-campaign://... | null
  evaluation_epoch_ref: evaluation-epoch://... | null
  coordinating_goal_run_ref: goal://... | null
  target_ref: string
  target_class:
    training_pipeline | foundry_spec | run_plan | model | worker |
    goal_run_profile | workflow_template | harness_profile | skill_manifest |
    runtime_tool_contract_binding | model_route | evaluator_asset |
    other_admitted_component
  target_owner_ref: string
  baseline_target_ref: string
  baseline_target_root: hash
  resolved_component_snapshot_ref: artifact://...
  optimizer_ref: worker://... | conductor://... | runtime://...
  search_policy_ref: policy://...
  objective_and_guardrail_policy_ref: policy://...
  randomness_and_repetition_policy_ref: policy://...
  resource_normalization_ref: policy://... | budget://...
  best_candidate_ref: artifact://... | null
  candidate_archive_projection_ref: artifact://... | null
  trial_refs:
    - trial://...
  accepted_change_refs:
    - artifact://...
  rejected_change_refs:
    - artifact://...
  inconclusive_change_refs:
    - artifact://...
  exploit_or_invalid_change_refs:
    - artifact://...
  evaluation_result_refs:
    - finding://... | gate://... | artifact://... | receipt://...
  typed_patch_candidate_ref: artifact://... | proposal://... | null
  promotion_bundle_candidate_ref: promotion_bundle://... | null
  budget_policy_ref: policy://...
  stop_policy_ref: policy://...
  receipt_root: hash
  status: planned | running | stopped | proposed_for_review | failed | rejected
```

This remains a Foundry-owned execution cycle, not the Campaign itself. A cycle
may run without an ImprovementCampaign for ordinary bounded optimization; when
campaign/epoch refs are present they must name the frozen contract that admitted
the cycle and its evaluation. The deprecated `target_training_pipeline_ref`
wire key may be accepted only by a versioned adapter that normalizes it to
`target_ref` with `target_class: training_pipeline`; canonical state does not
emit both. `best_candidate_ref` is an experiment-local selection under the
declared policies, not Campaign nomination, evaluation truth, or release
authority. No universal scalar `fitness` or mandatory Pareto/bandit algorithm
is canonical.
Foundry documentation may use the owner-qualified label
`FoundryExperimentOptimizationCycle`; the shared wire envelope and Agentgres
object class remain `ExperimentOptimizationCycle`.

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
  learning_evidence_eligibility_refs:
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
  cycle_id: post-training-cycle://...
  worker_id: worker://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  learning_source_rights_claim_refs:
    - learning-source-rights://...
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
  latest_context_mutation_ref: context-mutation://... | optional
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
adapter- and HarnessInvocation-local memory is cache;
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
    harness-profile://... | agent-harness-adapter://... |
    model_route://... | worker://... | service://... |
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
    - context-mutation://...
  receipt_ref: receipt://...
  status:
    active | stale | revoked | superseded
```

## ContextMutationEnvelope

```yaml
ContextMutationEnvelope:
  mutation_id: context-mutation://...
  wiki_ref: wiki://... | optional
  institutional_learning_boundary_profile_ref: learning-boundary://... | optional
  learning_source_rights_claim_refs:
    - learning-source-rights://...
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
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
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
  promotion_id: promotion://...
  cycle_id: post-training-cycle://...
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
  capability_ref:
    worker://... | model_route://... | goal-run-profile://.../revision/... |
    workflow-template://.../revision/... | harness-profile://.../revision/... |
    skill://.../revision/... | tool://... | mcp://... | automation://... |
    service://... | package://... | policy://... | artifact://... | domain_app://...
  capability_kind:
    worker | model_route | goal_run_profile | workflow_template |
    harness_profile | agent_harness | skill_manifest | runtime_tool_contract |
    evaluator | policy | tool | mcp_server | connector | automation | service |
    environment_image | package | domain_app | fleet_policy
  baseline_version_ref: optional
  candidate_or_active_version_ref: string
  improvement_campaign_ref: improvement-campaign://... | null
  evaluation_epoch_ref: evaluation-epoch://... | null
  upgrade_proposal_ref: proposal://... | null
  detected_in:
    phase: offline_eval | shadow | canary | rollout | production | recall_review
    run_refs: []
    release_target_refs: []
  regression_class:
    quality | safety | privacy | cost | latency | authority | reliability |
    policy | security | compliance | maintainability | complexity |
    steerability | product_compatibility | monitorability |
    workgraph_integrity | irreversible_effect | marketplace_reputation
  severity: info | warning | blocking | critical
  evidence_refs:
    - receipt://... | artifact://... | gate://... | benchmark://...
  scorecard_refs: []
  maintainability_complexity_and_compatibility_refs: []
  monitorability_trace_quality_and_debuggability_refs: []
  aggregate_workgraph_effect_refs: []
  effect_recovery_posture:
    reversible_state_rollback_refs: []
    containment_refs: []
    compensation_refs: []
    reconciliation_refs: []
    irreversible_effect_refs: []
    residual_unrecoverable_effect_refs: []
  affected_scope_refs: []
  recommended_action:
    reject | hold | shadow_more | pause | rollback | recall | constrain |
    patch_and_retry | require_human_review
  adjudication_ref: receipt://... | optional
  learning_evidence_eligibility_ref: eligibility://... | optional
  future_eval_candidate_refs: []
  status:
    detected | adjudicating | blocked | rejected | shadowing | paused |
    rolled_back | recalled | constrained | converted_to_eval | closed
```

A regression record is evidence and lifecycle posture, not learning consent. It
may become a future holdout, eval case, or Foundry job only after the owning
governance surface records `LearningEvidenceEligibility`; the
training-compatibility profile never creates a parallel decision.

## Bounded Improvement Campaign Envelopes

These objects add the optional multi-epoch state missing between bounded
pursuit and target-owner promotion. They do not add an RSI engine, runtime,
authority plane, evaluator, or product application. A direct one-shot change
may still proceed through `UpgradeProposalEnvelope` without a Campaign.

### ImprovementAgendaEnvelope

An Agenda is an immutable-by-revision governed portfolio of questions worth
investigating. It requests targets and evidence; it is not executable and
cannot choose current-epoch truth or authorize target mutation.

```yaml
ImprovementAgendaEnvelope:
  schema_version: ioi.improvement-agenda.v1
  improvement_agenda_id: improvement-agenda://...
  revision_ref: improvement-agenda://.../revision/...
  revision: positive_integer
  predecessor_revision_ref: improvement-agenda://.../revision/... | null
  content_hash: hash
  owner_ref: org://... | project://... | system://... | user://...
  system_id: system://... | null
  constitution_and_policy_refs: []
  governance_policy_refs: []
  release_decision_ref: decision://... | null
  target_graph_ref: artifact://...
  portfolio_allocation_policy_ref: policy://...
  items:
    - agenda_item_id: string
      target_ref: string
      target_class: string
      requested_target_improvement_order: nonnegative_integer
      requested_target_order_path_ref: artifact://...
      mechanism_hypothesis_ref: artifact://...
      causal_prediction_and_falsifier_ref: artifact://...
      minimum_decisive_test_ref: policy://... | artifact://...
      evidence_gap_and_uncertainty_ref: artifact://...
      transfer_and_reproduction_requirement_refs: []
      hard_constraint_and_risk_refs: []
      protected_exclusion_refs: []
      dependency_and_readiness_refs: []
      requested_budget_ref: budget://...
      effect_recovery_policy_ref: policy://...
  registry_lifecycle_ref: agentgres://object/... | decision://... | null
  registry_status: draft | evaluable | released | superseded | retired
```

Lifecycle/status fields are registry projections excluded from `content_hash`.
Only a released revision is campaign-admission eligible. The requested order
and budget are hypotheses; Governance resolves the effective target path,
order, authority, and ceilings at admission. An `improvement_agenda_patch`
UpgradeProposal creates a successor revision and affects only future campaign
admissions.

### ImprovementCampaignEnvelope

A Campaign owns the optional multi-epoch candidate, evaluation,
synchronization, and promotion lineage for one mutable target or exceptional
same-owner atomic bundle. GoalRuns coordinate its work; the Campaign is not a
second goal, pursuit profile, execution identity, evaluator, or authority.

```yaml
ImprovementCampaignEnvelope:
  schema_version: ioi.improvement-campaign.v1
  improvement_campaign_id: improvement-campaign://...
  campaign_contract_revision_ref: improvement-campaign://.../revision/...
  campaign_contract_revision: positive_integer
  predecessor_contract_revision_ref:
    improvement-campaign://.../revision/... | null
  campaign_contract_root: hash
  owner_ref: org://... | project://... | system://... | user://...
  system_id: system://... | null
  improvement_governance_profile_revision_ref:
    improvement-governance-profile://.../revision/...
  effective_governance_snapshot_ref: artifact://...
  campaign_admission_decision_ref: decision://...
  campaign_admission_receipt_ref: receipt://...
  admission_authority_and_constitution_snapshot_refs: []
  coordinating_goal_run_ref: goal://...
  child_goal_run_refs: []
  goal_run_profile_revision_ref: goal-run-profile://.../revision/...
  goal_run_profile_resolution_receipt_ref: receipt://...
  resolved_component_snapshot_ref: artifact://...
  outcome_room_ref: outcome-room://... | null
  agenda_revision_ref: improvement-agenda://.../revision/...
  agenda_item_refs: []
  campaign_mode:
    optimization | recursive_seat_test | transfer_test |
    independent_reproduction | evaluator_campaign
  target_class: string
  mutable_target_ref: string | null
  atomic_target_bundle_ref: artifact://... | null
  target_base_root: hash
  protected_boundary_refs: []
  target_improvement_order: nonnegative_integer
  pursuit_method_order: positive_integer
  target_to_pursuit_method_edge_ref: artifact://... | receipt://...
  target_order_path_ref: artifact://...
  target_order_assignment_receipt_ref: receipt://...
  base_target_generation_index: nonnegative_integer
  effective_target_order_ceiling: nonnegative_integer
  effective_target_order_ceiling_ref: policy://... | decision://...
  max_active_nested_campaign_depth: positive_integer
  parent_execution_campaign_ref: improvement-campaign://... | null
  predecessor_target_generation_campaign_ref: improvement-campaign://... | null
  source_lower_order_campaign_refs: []
  deployment_incumbent_ref: string
  deployment_incumbent_root: hash
  candidate_archive_ref: artifact://... | null
  candidate_resolved_component_snapshot_refs: []
  active_evaluation_epoch_ref: evaluation-epoch://... | null
  historical_evaluation_epoch_refs: []
  search_and_candidate_archive_policy_refs: []
  synchronization_policy_ref: policy://...
  improvement_order_cutoff_receipt_refs: []
  ancestor_resource_budget_ledger_ref: ledger://...
  resource_reservation_refs: []
  ancestor_statistical_risk_budget_ledger_ref: ledger://...
  statistical_risk_reservation_refs: []
  inherited_evaluation_exposure_ledger_refs: []
  evaluation_exposure_reservation_refs: []
  learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  stop_policy_ref: policy://...
  rollback_recall_containment_compensation_and_reconciliation_policy_refs: []
  operation_head_sequence: nonnegative_integer
  operation_head_root: hash
  derived_state_projection_ref: agentgres://projection/...
```

Exactly one of `mutable_target_ref` or `atomic_target_bundle_ref` is present.
Every atomic-bundle member must share one admitted target order, activation
owner, evaluator, conflict set, and recovery path; otherwise use separate
Campaigns with explicit dependencies. Contract fields are frozen by
`campaign_contract_root`; candidates, epochs, reservations, cutoffs, and state
advance through append-only Agentgres operations and rebuildable projections.
The child-run list, candidate/archive refs, active and historical Epoch refs,
cutoff refs, reservation refs, operation head, and derived-state ref are
operation projections excluded from that contract root. A governed successor
contract revision applies only to future operations/Epochs and never
reinterprets evidence already frozen under a predecessor root.
Parallel descendants reserve disjoint ancestor resource, statistical-risk, and
exposure allowances. Creating a child or relabeling order never copies or
resets an allowance.
Target order is path-relative and revision-bound, never an intrinsic property
of a component. `pursuit_method_order` is recorded only with the frozen target-
to-method edge and is normally the target order plus one; generation indexes,
active nesting depth, transfer tier, and evidence claim class remain orthogonal.

### EvaluationEpochEnvelope

An Evaluation Epoch freezes one Campaign utility, verifier, holdout,
statistical, and acceptance contract. Changing any frozen evaluator or metric
creates a successor epoch and cannot select a candidate against the old epoch.

```yaml
EvaluationEpochEnvelope:
  schema_version: ioi.evaluation-epoch.v1
  evaluation_epoch_id: evaluation-epoch://...
  campaign_ref: improvement-campaign://...
  campaign_contract_revision_ref: improvement-campaign://.../revision/...
  campaign_contract_root: hash
  predecessor_epoch_ref: evaluation-epoch://... | null
  pursuit_goal_run_profile_revision_ref: goal-run-profile://.../revision/...
  pursuit_profile_resolution_and_component_snapshot_refs: []
  target_improvement_order: nonnegative_integer
  pursuit_method_order: positive_integer
  base_target_generation_index: nonnegative_integer
  target_graph_and_order_path_roots: []
  deployment_incumbent_ref: string
  deployment_incumbent_root: hash
  synchronization_cutoff_receipt_ref: receipt://... | null
  visible_eval_refs: []
  sealed_holdout_commitment_refs: []
  transfer_ood_and_adversarial_eval_refs: []
  recursive_seat_and_metaproductivity_metric_refs: []
  cross_play_and_causal_ablation_policy_ref: policy://...
  transfer_non_regression_and_hard_constraint_gate_refs: []
  metric_and_selection_policy_ref: policy://...
  cost_normalization_ref: policy://...
  confirmatory_estimand_and_minimum_effect_refs: []
  statistical_test_and_winner_adjustment_refs: []
  risk_wealth_allocation_ref: policy://...
  power_and_inconclusive_stop_policy_ref: policy://...
  campaign_false_promotion_budget_ref: policy://...
  ancestor_statistical_risk_budget_ledger_ref: ledger://...
  inherited_evaluation_exposure_ledger_refs: []
  sealed_feedback_release_and_exposure_spend_policy_refs: []
  evaluator_version_and_affiliation_refs: []
  holdout_custodian_refs: []
  external_reality_anchor_refs: []
  operational_acceptance_owner_refs: []
  leakage_rotation_and_challenge_policy_refs: []
  frozen_root: hash
  lifecycle_ref: agentgres://object/... | decision://... | null
  lifecycle_status: draft | frozen | active | challenged | closed | invalidated
```

Lifecycle state is a projection excluded from `frozen_root`. A challenge or
invalidation appends linked evidence rather than rewriting the epoch. The
deployment incumbent root is the frozen comparison baseline, not ownership of
the live Systems/ReleaseControl incumbent projection.

### EvaluationExposureLedgerEnvelope

```yaml
EvaluationExposureLedgerEnvelope:
  schema_version: ioi.evaluation-exposure-ledger.v1
  evaluation_exposure_ledger_id: evaluation-exposure://...
  evaluation_epoch_ref: evaluation-epoch://...
  ancestor_exposure_ledger_refs: []
  steward_refs: []
  sealed_suite_and_world_commitment_refs: []
  exposure_budget_ref: policy://...
  admitted_entry_refs: []
  ledger_head_sequence: nonnegative_integer
  ledger_head_root: hash
  derived_exposure_and_contamination_projection_ref: agentgres://projection/...
  lifecycle_decision_refs: []
```

Each immutable entry binds the candidate/family/ancestry commitments, selected
case commitments, information-return class, evaluator versions, execution and
access receipts, contamination flags, charged exposure, and previous root.
Reservation, spend, return, contamination, rotation, and invalidation are
append-only entry kinds. Remaining exposure and contamination posture are
derived from the admitted head; child Campaigns inherit effective ancestor
spend and cannot reset it by changing identity or order.

### ImprovementEvidenceClaimEnvelope

This immutable artifact states only the bounded evidence actually established.
It is not an authority object, promotion decision, or promise of open-ended
recursive improvement.
Its `claim_class` uses the cross-component member set owned by
[`canonical-enums.md`](./canonical-enums.md#improvement-evidence-claim-classes-claim_class).

```yaml
ImprovementEvidenceClaimEnvelope:
  schema_version: ioi.improvement-evidence-claim.v1
  improvement_evidence_claim_id: improvement-evidence://...
  evidence_revision: positive_integer
  predecessor_evidence_claim_ref: improvement-evidence://... | null
  campaign_refs: []
  target_chain_refs: []
  target_improvement_order: nonnegative_integer
  pursuit_method_order: positive_integer
  target_generation_range: string
  transfer_tiers_claimed: []
  claim_class:
    bounded_optimization | self_targeted_improvement |
    net_positive_recursive_improvement | ignition_evidence |
    inflection_evidence
  claim_methodology_ref: policy://...
  baseline_incumbent_and_candidate_snapshot_refs: []
  fixed_budget_environment_and_cost_refs: []
  visible_sealed_transfer_and_production_eval_refs: []
  synchronization_cutoff_and_downstream_lineage_refs: []
  descendant_campaign_archive_and_distribution_refs: []
  transfer_matrix_ref: artifact://...
  causal_ablation_falsifier_and_statistical_analysis_refs: []
  recursive_seat_test_ref: improvement-campaign://... | null
  independent_reproduction_refs: []
  complexity_operability_monitorability_and_workgraph_refs: []
  evaluator_change_and_challenge_refs: []
  outer_release_and_effect_recovery_refs: []
  limitations_ref: artifact://...
  evidence_root: hash
  claim_lifecycle_ref: agentgres://object/... | decision://... | null
```

Support, dispute, supersession, withdrawal, evaluator invalidation, and claim
downgrade append lifecycle or successor records. They never mutate the claim
body or let a later looser methodology inflate an earlier claim.

### ImprovementOrderCutoffReceiptEnvelope

This receipt is a typed evidence/learning cutoff between adjacent target
orders. It is neither a live synchronization object nor later promotion proof.

```yaml
ImprovementOrderCutoffReceiptEnvelope:
  receipt_id: receipt://...
  receipt_profile: improvement_order_cutoff
  receipt_profile_ref: schema://ioi/improvement-order-cutoff-receipt/v1
  synchronization_wave_ref: artifact://...
  source_campaign_epoch_and_archive_roots: []
  source_target_improvement_order: nonnegative_integer
  source_target_generation_cutoff: nonnegative_integer
  intended_destination_target_order: nonnegative_integer
  per_order_source_version_and_cutoff_vector_ref: artifact://...
  destination_base_root: hash
  agenda_and_task_distribution_roots: []
  eligible_finding_and_outcome_refs: []
  learning_evidence_eligibility_refs: []
  learning_egress_receipt_refs: []
  boundary_enforcement_access_and_custody_receipt_refs: []
  effective_learning_policy_hash: hash
  denied_or_quarantined_information_class_refs: []
  source_incumbent_resolved_component_snapshot_ref: artifact://...
  inherited_budget_risk_and_exposure_reservation_roots: []
  dependency_and_statistical_assumption_delta_ref: artifact://...
  signal_bundle_ref: artifact://... | null
  terminal_disposition: evidence_ready | no_change | blocked
  previous_cutoff_receipt_root: hash | null
  receipt_root: hash
```

The destination order must equal the source order plus one; skipped edges need
their own later cutoff. Same-boundary use may have no learning-egress receipt,
but still requires learning eligibility and applicable access/custody evidence.
Fresh cross-play/ablation, UpgradeDecision, activation, monitoring, and effect
recovery remain with their existing owners.

## GoalRunProfileEnvelope

`GoalRunProfileEnvelope` is the reusable pursuit specification missing between
product-facing Recipes/Packages and one durable `GoalRun`. It declares how a
class of adaptive goals should converge by composing existing owner-qualified
contracts. It is not a workflow graph, executable, authority holder, campaign
database, evaluator, or live state machine.

Each released revision is immutable and content-addressed. Hypervisor Core and
the daemon admit one selected revision plus run-specific constraints and only
those overrides permitted by its declared schema. The Goal Kernel interprets
that frozen resolution to form and revise `OrchestrationPlan` objects and to
operate the bounded pursue--verify--course-correct loop. Authoritative GoalRun
creation, mutation, and effect admission remain daemon-owned.

```yaml
GoalRunProfileEnvelope:
  schema_version: ioi.goal-run-profile.v1
  goal_run_profile_id: goal-run-profile://...
  revision_ref: goal-run-profile://.../revision/...
  version: semver_or_hash
  predecessor_revision_ref: goal-run-profile://.../revision/... | null
  content_hash: hash
  owner_ref: org://... | project://... | system://... | user://... | domain://... | ioi://publisher/...
  display_name: string
  description: string
  applicable_goal_class_refs:
    - schema://... | ontology://... | profile://...
  compatible_domain_object_schema_refs:
    - schema://... | ontology://...
  orchestration_policy_ref: orchestration_policy://...
  constraint_derivation_policy_refs: []
  workflow_template_revision_refs: []
  role_topology_requirement_refs: []
  harness_requirement_refs: []
  pinned_harness_profile_revision_refs: []
  skill_requirement_refs: []
  pinned_skill_manifest_revision_refs: []
  worker_requirement_refs: []
  model_route_requirement_refs: []
  service_requirement_refs: []
  runtime_tool_contract_requirement_refs: []
  primitive_capability_requirements: []
  context_requirement_profile_refs: []
  input_contract_ref: schema://... | policy://...
  output_contract_ref: schema://... | policy://...
  acceptance_contract_refs: []
  verifier_requirement_refs: []
  budget_time_and_resource_ceiling_refs: []
  stop_policy_ref: policy://...
  recovery_policy_ref: policy://...
  escalation_policy_ref: policy://...
  learning_boundary_requirement_ref: policy://... | null
  pinned_learning_boundary_profile_ref: learning-boundary://... | null
  allowed_override_schema_ref: schema://... | null
  compatibility_refs: []
  provenance_refs: []
  evaluation_and_benchmark_refs: []
  promotion_policy_ref: policy://... | null
  revocation_and_recall_policy_ref: policy://... | null
  registry_lifecycle_ref: agentgres://object/... | package://.../release/... | null
  registry_status: draft | evaluable | released | deprecated | revoked
```

Requirement refs allow admission to choose an eligible implementation.
`pinned_*` refs are reserved for reproducibility, certification, compatibility,
or explicit policy; ordinary profiles should not freeze one provider, model,
worker, or harness unnecessarily. The profile references
`OrchestrationPolicy`, constraint-derivation policy, `WorkflowTemplate`, topology,
skills, tools, verifiers, and output contracts without redefining their fields
or taking over their lifecycle.

The resolution receipt commits the exact admission-time dependency closure:
the selected profile revision and content hash, admitted overrides, effective
constraint envelope and hash, orchestration policy, optional workflow revision,
initial topology decision when one exists, skill revisions and active-set
snapshot, resolved tool contracts, learning boundary, all compatibility/policy
decisions, and every still-unresolved late-binding predicate expressly
permitted by the profile. Later worker/model/service/verifier/runtime choices
are not falsely called resolved; their owning plans, invocations, leases, and
receipts freeze them when selected. A top-level profile hash without this
resolved-component commitment is insufficient for replay.

`GoalRunProfilePatch` always proposes a successor revision. It cannot mutate a
released or in-use profile. A product may label a profile or package
composition a **Recipe**, but there is no generic canonical `RecipeEnvelope`.

The revision body and `content_hash` are immutable. `registry_status` and
`registry_lifecycle_ref` are registry projections excluded from that content
hash. A revoked profile remains replayable by its exact hash even when it is no
longer eligible for new admission.

## OrchestrationConstraintEnvelope

Captures the constraints that bind an outcome-conductor plan before a model,
harness, worker, or session receives private context or scoped tool access.
This is a plan-selection input, not an authority grant.

```yaml
OrchestrationConstraintEnvelope:
  constraint_id: constraint://...
  goal_ref: goal://... | task://...
  requester_ref: wallet://... | org://... | system://... | agent://...
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  effective_learning_policy_hash: hash | null
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
  revision_ref: orchestration_plan://.../revision/...
  predecessor_revision_ref: orchestration_plan://.../revision/... | null
  content_hash: hash
  goal_ref: goal://... | task://...
  goal_run_profile_revision_ref: goal-run-profile://.../revision/...
  workflow_template_revision_refs: []
  constraint_envelope_ref: constraint://...
  materialization:
    single_path | verifier_backed_single_path | multi_model_answer |
    multi_harness_attempt | cross_session_branch_and_merge |
    collaborative_frontier | independent_replication |
    dynamic_specialist_mesh | open_challenge |
    marketplace_worker_delegation | foundry_job
  goal_execution_policy: auto | pinned | compare
  selection_source: user | org_policy | conductor_policy | fallback_policy
  model_route_requirement_refs: []
  resolver_requirement_refs: []
  worker_requirement_refs: []
  verifier_requirement_refs: []
  role_topology_requirement_refs: []
  selected_role_topology_revision_ref: role_topology://.../revision/... | null
  selected_role_topology_content_hash: hash | null
  routing_decision_refs: []
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
  selection_decision_receipt_ref: receipt://... | null
  registry_lifecycle_ref: agentgres://object/... | null
  registry_status: candidate | selected | rejected | superseded | admitted
```

Each plan revision is immutable and content-addressed. Course correction,
selection, or topology change creates or selects a revision and binds the
decision receipt; that receipt and registry lifecycle/status are excluded from
`content_hash` and the receipt binds the already-computed hash. Requirement
refs are nonbinding candidate constraints. A selected/admitted plan may bind an
exact RoleTopology revision/hash plus routing decisions; that topology owns the
role-to-actor/resolver mapping, and each HarnessInvocation owns the resolver
actually invoked. The plan never restates either mapping as parallel arrays. Product
surfaces may render the selected revision but cannot restate its selections as
a second truth owner.

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
  room_admission: RoomAdmittedObjectBase | null
  sponsor_ref: system://... | user://... | org://... | project://... | service://...
  collaboration_terms_refs:
    - terms://...
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
    - contribution://... | delivery://... | settlement-intent://... | receipt://...
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
  room_admission: RoomAdmittedObjectBase
  publication_version: semver_or_hash
  published_by_ref: system://... | domain://... | org://... | service://...
  public_goal_ref: goal://... | task://... | service://...
  public_objective: string
  public_category_refs:
    - ontology://... | benchmark://... | capability://... | service://...
  coordination_topology: hosted_admission | federated_admission
  admission_owner_ref: system://... | domain://... | policy://...
  participation_channel_ref: aiip://channel/...
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: hash | null
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
  requested_by_ref: system://... | worker://... | service://... | org://... | domain://...
  collaboration_terms_ref: terms://...
  collaboration_terms_root: hash
  terms_response: accept | counteroffer | decline
  counterterms_ref: terms://... | null
  terms_acceptance_signature: required_when_accept
  operator_and_home_domain_refs:
    - user://... | wallet://... | org://... | domain://... | system://...
  worker_composition_and_dependency_refs:
    - package://... | worker://... | model_route://... |
      harness-profile://... | runtime://... | provider://...
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
  admission_owner_ref: system://... | domain://... | policy://...
  private_context_included: false
  request_hash: hash
  signature: required
  admission_decision_ref: decision://... | receipt://... | null
  participant_lease_ref: participant-lease://... | null
  status: draft | submitted | evaluating | admitted | rejected | withdrawn | expired
```

Discovery advertises an exact public terms ref/root but remains an invitation.
The participation `request_hash` binds the same root and an explicit accept,
counteroffer, or decline. A counteroffer remains a proposal; neither discovery
nor response creates membership, authority, work, contribution eligibility, or
payout. Admission may issue a participant lease only after exact-root terms
acceptance and the ordinary eligibility, privacy, and policy checks.

## OutcomeRoomEnvelope

`OutcomeRoomEnvelope` is the shared collaborative-pursuit profile above one or
more GoalRuns. It binds a durable objective to a work frontier, participants,
attempts, findings, verification, contribution lineage, budget, and replay. It
does not create a second runtime, authority system, marketplace, or globally
mutable Agentgres graph.

Every durable OutcomeRoom is an instance of the reference bounded-DAS package,
with its own stable `system_id`, genesis, constitution, active manifest and
profiles, and cryptographically continuous admitted room state. The hosted
ioi.ai service may operate many such systems; the service account or host domain
is not a substitute for a room's logical identity. A draft may await genesis,
but a room cannot enter `open` or `active`, or be called an intelligent
blockchain, until the complete binding below is admitted. A chat room or
temporary coordination aggregate without that binding is an application
session, not the flagship reference DAS.

The same room may appear as a Goal Space in ioi.ai and Work / Rooms in
Hypervisor, optionally with a non-authoritative Mission presentation label. A
direct question, one-shot run, ordinary automation, or single
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
  system_id: system://...
  genesis_ref: genesis://... | null
  package_id: package://...
  manifest_ref: package://.../release/...
  constitution_ref: constitution://...
  active_profile_refs:
    deployment_profile_ref: deployment-profile://...
    ordering_admission_finality_profile_ref: ordering-profile://...
    oracle_evidence_profile_refs: []
    lifecycle_continuity_profile_ref: lifecycle-profile://...
    network_enrollment_ref: network-enrollment://... | null
  autonomous_system_state_ref: agentgres://...
  owner_or_sponsor_ref:
    system://... | user://... | org://... | project://... | domain://... | service://...
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
  cooperation_surplus_policy_ref: policy://...
  collaboration_terms_refs:
    - terms://...
  discovery_and_external_admission_policy_refs:
    - policy://... | room-discovery://... | aiip://channel/...
  artifact_license_rights_retention_and_export_policy_refs:
    - policy://... | license://...
  coordination_topology:
    hosted_admission | federated_admission
  coordination_policy_ref: policy://...
  host_domain_ref: system://... | domain://... | null
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
    - contribution://... | receipt://...
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
  room_admission: RoomAdmittedObjectBase
  participant_ref:
    system://... | agent://... | worker://... | service://... | org://... | domain://...
  admitted_role:
    conductor | implementer | reviewer | verifier | operator |
    researcher | specialist | synthesizer | resource_provider |
    integrity_challenger | memory_curator
  operator_ref: system://... | user://... | org://... | wallet://... | domain://...
  home_domain_ref: domain://... | system://... | agentgres://domain/...
  worker_and_runtime_refs:
    - worker://... | harness-profile://... | agent-harness-adapter://... |
      model_route://... | runtime://... | node://...
  capability_advertisement_refs:
    - capability-offer://... | ai://... | package://...
  tool_connector_and_capability_dependency_refs:
    - tool://... | connector://... | capability://... | prim:*
  join_request_ref: participation-request://... | proposal://... | null
  collaboration_terms_ref: terms://...
  accepted_terms_root: hash
  terms_acceptance_ref: receipt://...
  identity_and_eligibility_evidence_refs:
    - evidence://... | receipt://... | certification_claim://...
  admission_decision_ref: receipt://... | decision://...
  visibility_scope_ref: policy://... | restricted_view://...
  context_and_authority_lease_refs:
    - context_lease://... | grant://... | authority://...
  runtime_resource_and_budget_lease_refs:
    - lease://... | resource-lease://... | budget://...
  current_claim_ref: work-claim://... | null
  lease_epoch: nonnegative_integer
  issued_at: timestamp
  effective_at: timestamp
  expires_at: timestamp | null
  renew_after: timestamp | null
  renewal_policy_ref: policy://...
  unbounded_term_exception_decision_ref: decision://... | null
  heartbeat_policy_ref: policy://...
  heartbeat_ref: receipt://... | heartbeat://... | null
  last_heartbeat_at: timestamp | null
  heartbeat_valid_until: timestamp | null
  revocation_epoch: nonnegative_integer
  next_wake_condition_ref: policy://... | event://... | null
  quiet_hours_or_backoff_ref: policy://... | null
  last_contribution_ref: contribution://... | receipt://... | null
  exit_and_claim_release_refs:
    - decision://... | work-claim://... | receipt://...
  portable_participant_state_bundle_ref: participant-state://... | null
  future_access_revocation_refs:
    - revocation://... | receipt://...
  ttl_seconds: positive_integer | null
  status:
    invited | joining | active | sleeping | waiting | suspended |
    quarantined | retiring | retired | revoked
```

The default lease is time-bounded: `expires_at` and `ttl_seconds` are required.
A null term is allowed only when the room constitution and participation policy
explicitly permit continuing membership and
`unbounded_term_exception_decision_ref` proves the governed exception. It still
requires heartbeat freshness, monotonic lease/revocation epochs, and an
effective revocation path; it is never ambient irrevocable membership. An
expired heartbeat cannot satisfy active-capacity or work-claim admission.
The lease cannot outlive its accepted collaboration terms unless their renewal
policy explicitly permits that continuation. Terms acceptance alone grants no
context, authority, resource, budget, claim, or payout right.
`terms_acceptance_ref` resolves to a current admitted
`CollaborationTermsAcceptanceReceipt` matching the participant, role, room,
terms ref/root, and lease term; a packet or bare decision is not sufficient.

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
  room_admission: RoomAdmittedObjectBase
  participant_lease_ref: participant-lease://...
  participant_and_home_domain_refs:
    - worker://... | service://... | org://... | domain://... | system://...
  coordination_topology: hosted_admission | federated_admission
  bundle_reason: checkpoint | voluntary_retirement | lease_expiry | revocation | quarantine | room_close
  source_admission_watermark_ref: receipt://... | agentgres://... | hash
  released_or_reassigned_claim_refs:
    - work-claim://... | decision://... | receipt://...
  preserved_contribution_attempt_finding_and_result_refs:
    - contribution://... | attempt://... | finding://... | work-result://... |
      outcome-delta://...
  preserved_receipt_acceptance_settlement_and_dispute_refs:
    - receipt://... | acceptance://... | settlement-intent://... |
      dispute://... | decision://...
  portable_artifact_and_view_refs:
    - artifact://... | restricted_view://... | redacted_summary://... |
      evidence://... | replay://...
  lineage_and_supersession_refs:
    - contribution://... | attempt://... | finding://... | work-result://...
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

Every mutable child of a room uses one admission spine:

```yaml
RoomAdmittedObjectBase:
  room_system_id: system://...
  outcome_room_ref: outcome-room://...
  proposed_or_issued_by_ref: participant-lease://... | system://...
  expected_room_revision: nonnegative_integer
  expected_predecessor_commitment_ref: commitment://...
  payload_root: hash
  admission_policy_ref: policy://...
  admission_decision_ref: decision://... | null
  admission_receipt_ref: receipt://... | null
  admitted_sequence: nonnegative_integer | null
  resulting_room_revision: nonnegative_integer | null
  resulting_transition_commitment_ref: commitment://... | null
  resulting_room_state_root: hash | null
  resulting_receipt_root: hash | null
  created_at: timestamp
  updated_at: timestamp | null
  admission_status: proposed | evaluating | admitted | rejected | superseded | revoked
```

An external agent, Worker, service, organization, or sovereign system acts in a
room only through a current `participant-lease://` ref. `system://` is valid as
issuer only for a room-system-authored scheduling, expiry, or policy transition.
Expected revision and predecessor commitment are compare-and-swap inputs. A
payload becomes shared room truth only when the declared policy/decision emits
an admission receipt and resulting commitment; proposal/workgraph structure
therefore makes untrusted local-agent work useful without treating it as trusted
runtime truth.

```yaml
ResourceOfferEnvelope:
  resource_offer_id: resource-offer://...
  room_admission: RoomAdmittedObjectBase
  provider_participant_lease_ref: participant-lease://...
  backing_provider_ref: provider://... | org://... | domain://... | system://...
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
    - spend://... | contribution://... | receipt://...
  usage_and_consumption_refs:
    - ledger://... | receipt://... | work-credit://...
  status: offered | queued | allocated | exhausted | withdrawn | expired | revoked
```

```yaml
CapabilityOfferEnvelope:
  capability_offer_id: capability-offer://...
  room_admission: RoomAdmittedObjectBase
  participant_lease_ref: participant-lease://...
  backing_worker_or_service_ref: worker://... | service://... | system://...
  capability_descriptor_refs:
    - ai://... | package://... | capability://...
  eligible_frontier_classes:
    - string
  model_harness_tool_and_connector_refs:
    - model_route://... | harness-profile://... | tool://... | connector://...
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
  room_admission: RoomAdmittedObjectBase
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
  outcome_room_ref: outcome-room://... | null
  room_admission: RoomAdmittedObjectBase | null
  frontier_item_ref: frontier://... | null
  claimant_ref:
    participant-lease://... | system://... | domain://... |
    worker://... | service://... | agent://... | org://...
  claimant_participant_lease_ref: participant-lease://... | null
  eligibility_match_receipt_ref: receipt://... | null
  task_offer_ref: packet://... | null
  task_acceptance_ref: packet://... | null
  routing_decision_ref: routing-decision://... | null
  collaboration_terms_ref: terms://...
  collaboration_terms_root: hash
  terms_acceptance_ref: receipt://...
  contribution_policy_ref: policy://...
  quote_ref: quote://... | null
  budget_reservation_ref: budget://... | spend://... | allocation://... | null
  settlement_profile_ref: policy://...
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

`active` is the executable award. It requires the exact accepted terms root,
an admitted `CollaborationTermsAcceptanceReceipt`, any selected task response
and routing decision, the required context/resource/tool/budget leases,
applicable authority, and a room/domain admission receipt.
Room-scoped claims additionally require a current participant lease and
non-null room admission bound to the same room/frontier; its terms-acceptance
receipt must be the one bound by that participant lease. Direct bilateral AIIP
work leaves those room fields null but requires a claimant-bound terms-
acceptance receipt and receiving-domain admission. Discovery, terms acceptance,
or selection alone cannot activate work.

The terms-acceptance receipt must have current `acceptance_status: accepted`
and remain inside `effective_until`; a withdrawn, superseded, revoked, or
time-expired acceptance cannot activate or renew a claim.

For an external solicitation, the selected response must be a member of the
routing decision's candidate response set, have `status: accepted`, name the
same `accepted_by` principal as the routing selection and claim, and bind the
same terms root as the offer, routing decision, acceptance receipt, and claim.
The claim's quote and budget reservation must match the selected response and
routing decision. Counteroffers must first become a newly accepted terms root;
they cannot be selected under the superseded offer root.

An active claim's `expires_at` must not exceed the terms expiry or terms-
acceptance `effective_until`. Continuation beyond either bound requires the
already accepted renewal or outstanding-obligation policy and a new admitted
lease/receipt; it is never inferred from work already being in progress.

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
  room_admission: RoomAdmittedObjectBase | null
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://...
  goal_run_ref: goal://... | null
  frontier_item_ref: frontier://... | null
  work_claim_ref: work-claim://... | null
  participant_ref:
    participant-lease://... | system://... | worker://... | agent://...
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
  worker_model_resolver_tool_and_runtime_version_refs:
    - worker://... | model_route://... | harness-profile://.../revision/... |
      agent-harness-adapter://.../revision/... | tool://.../revision/... |
      runtime://...
  authority_and_policy_refs:
    - grant://... | policy://...
  resource_and_cost_refs:
    - resource-lease://... | spend://... | ledger://...
  outcome_class:
    positive | negative | inconclusive | invalid | exploit_found | superseded
  work_result_ref: work-result://... | null
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
    - contribution://... | receipt://...
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
  room_admission: RoomAdmittedObjectBase | null
  attempt_ref: attempt://...
  work_result_ref: work-result://...
  participant_ref: participant-lease://...
  proposed_by_ref:
    participant-lease://... | system://... | worker://... |
    service://... | org://... | domain://...
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
  room_admission: RoomAdmittedObjectBase | null
  challenger_ref: participant-lease://... | system://... | worker://... | org://... | user://...
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
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  goal_run_ref: goal://... | null
  outcome_room_ref: outcome-room://... | null
  room_admission: RoomAdmittedObjectBase | null
  produced_by_ref: system://... | participant-lease://... | worker://... | service://... | org://... | domain://...
  submitted_by_ref: system://... | participant-lease://... | worker://... | service://... | org://... | domain://...
  operator_and_affiliation_refs: []
  work_claim_ref: work-claim://... | null
  attempt_ref: attempt://... | null
  invocation_or_run_ref:
    harness_invocation://... | run://... | work_run://... | automation-run://... |
    service://... | null
  result_profile:
    software_implementation | research | ontology_mutation |
    incident_resolution | service_delivery | physical_mission |
    review | evaluation | custom
  result_profile_ref: schema://... | profile://... | null
  result_payload_ref:
    implementation_result://... | artifact://... | cid://... | encrypted_ref | null
  producer_component_resolution:
    resolved_component_set_snapshot_ref: artifact://... | null
    resolved_component_set_hash: hash | null
    component_resolution_receipt_ref: receipt://... | null
    resolver_kind: harness_profile | agent_harness_adapter | none
    resolver_revision_ref:
      harness-profile://.../revision/... |
      agent-harness-adapter://.../revision/... | null
    resolver_content_hash: hash | null
  declared_method_and_lineage_refs:
    - method://... | attempt://... | finding://... | work-result://... |
      artifact://... | trace://...
  information_flow_label_refs:
    - ifc-label://...
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

The producer component snapshot/receipt and resolver pair are null, with
`resolver_kind: none`, only for work whose declared profile has no executable
component resolution, such as an admitted direct human assertion. Any
WorkResult emitted by a HarnessInvocation, AutomationRun,
WorkRun, worker, service, model route, or RuntimeAssignment requires the exact
resolved-component snapshot/hash and its admission receipt. The snapshot
commits the exact worker, resolver, model-route, tool, skill, runtime, and other
applicable component revisions/hashes. `resolver_kind` independently
discriminates the exact resolver pair for projection and replay; family refs or
current registry heads are invalid provenance.

```yaml
OutcomeDeltaEnvelope:
  outcome_delta_id: outcome-delta://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  outcome_room_ref: outcome-room://... | null
  room_admission: RoomAdmittedObjectBase | null
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
  information_flow_label_refs:
    - ifc-label://...
  status: proposed | evaluating | admitted | rejected | superseded | rolled_back
```

Information-flow labels are part of result lineage, not an assertion that the
result is true or authoritative. A room-scoped result preserves every label
that can influence its payload, summary, claims, or proposed delta. An
`OutcomeDelta` inherits the complete label set of the `WorkResult` or other
admitted proposer it derives from and may only add labels; it cannot drop,
replace, or weaken inherited labels. Summarization, verifier review, schema
validation, room admission, and agreement do not declassify content or upgrade
instruction authority. The label objects remain owned by their originating
artifact, context, receipt, or runtime boundary; these fields carry exact refs
so downstream effect admission can resolve and join them.

For `Attempt`, `Finding`, `VerifierChallenge`, `WorkResult`, and `OutcomeDelta`,
`outcome_room_ref != null` requires a non-null `room_admission` whose
`proposed_or_issued_by_ref` is the current room participant lease (or the room
system for a system-authored transition). Direct actor refs are permitted only
for non-room work subjects. Room-scoped `WorkResult.produced_by_ref` and
`submitted_by_ref` must resolve through that same participant lease, preserving
the accountable operator/affiliation lineage.

## WorkLifecycleRecordEnvelope

`WorkLifecycleRecordEnvelope` is the shared append-only mechanics layer for
bounded work. It does not own GoalRun, GoalGroundingLoop, WorkRun,
AutomationRun, HarnessInvocation, ContextCell, or external-protocol state and
does not flatten their phases into a universal business lifecycle. Each kind
keeps its own legal transition and transition-authority table; the target
shared kernel would supply content commitment, exact-head compare-and-swap,
object-scoped idempotency, append-only child references, replay, cancellation
planning, and snapshot/archive continuity. Current master does not implement
this shared kernel or its persistence/routes.

```yaml
WorkLifecycleRecordEnvelope:
  schema_version: ioi.work-lifecycle-record.v1
  record_id: work-lifecycle://...
  record_hash: hash
  record_type: phase_transition | child_reference
  object_kind:
    goal_run | goal_grounding_loop | work_run | automation_run |
    harness_invocation | context_cell | external_handle
  object_ref:
    goal://... | goal_loop://... | work_run://... | automation-run://... |
    harness_invocation://... | context_cell://... | opaque_external_handle_ref
  owner_ref: system://... | user://... | org://... | project://... | domain://...
  expected_head: hash | null
  resulting_head: hash
  idempotency_key: string
  authority_class:
    owner | goal_kernel | conductor | verifier | daemon | operator |
    reviewer | automation_controller | harness_adapter |
    external_protocol_adapter | reconciler | governance
  authority_ref: authority://... | actor://... | policy://...
  authority_grant_refs: [grant://...]
  decision_receipt_ref: receipt://... | null
  evidence_refs: [evidence://... | artifact://... | trace://...]
  receipt_refs: [receipt://...]
  phase_transition:
    from_phase: string | null
    to_phase: string
    cancellation_intent:
      requested_by_ref: actor://...
      reason: string
      drain_deadline_ms: integer_timestamp_ms
      compensation_policy_ref: policy://... | null
      ambiguous_effect_policy_ref: policy://... | null
    # null unless this transition initiates cancellation/revocation
  child_reference:
    operation: attach | detach
    relation_kind:
      context_cell | context_lease | runtime_assignment |
      harness_invocation | external_handle | child_goal_run |
      work_run | automation_run | work_result | receipt
    child_ref: typed_ref
    effect_recovery_class:
      none | reversible | compensatable | irreversible | ambiguous
  occurred_at_ms: integer_timestamp_ms
```

Exactly one of `phase_transition` and `child_reference` is non-null and must
match `record_type`. The content commitment covers every field except
`record_hash` and `resulting_head`; both excluded fields then equal that exact
commitment. Genesis has `expected_head: null` and one kind-specific initial
phase. Every successor binds the current head and may not regress
`occurred_at_ms`. Reusing the same object-scoped
idempotency key with identical bytes returns the original result; changed bytes
fail. A log containing duplicate genesis records, a fork, gap, orphan, invalid
hash, illegal transition, foreign owner, or unauthorized authority class fails
closed before its active-phase projection changes.

The kind-specific phase owners remain:

| Kind | Canonical phase family | Ordinary transition authority |
|---|---|---|
| GoalRun | `draft`, `active`, `paused`, `complete`, `superseded`, `revoked` | Goal Kernel; owner on declared pause/resume/revoke edges; governance on declared pause/revoke/supersede edges |
| GoalGroundingLoop | the canonical receive → ground → inspect → constrain → allocate → execute → verify → repair/reconcile → continue loop phases | Goal Kernel/conductor; verifier only on declared verify/challenge edges |
| WorkRun | `pending`, `running`, `waiting_for_input`, `ready_for_review`, `stopped`, `completed`, `failed`, `canceled` | daemon/operator; reviewer only on declared review exits |
| AutomationRun | `queued`, `running`, `waiting_for_approval`, `blocked`, `succeeded`, `failed`, `canceled`, `archived` | Automation controller/daemon; governance on declared cancellation edges |
| HarnessInvocation | `queued`, `running`, `waiting_on_harness`, `waiting_on_conductor`, `completed`, `failed`, `cancelled`, `superseded` | daemon, selected adapter, or conductor on the declared edge |
| ContextCell | `open`, `active`, `sleeping`, `waiting`, `handed_off`, `summarized`, `quarantined`, `closed`, `revoked` | conductor/daemon; governance on declared revocation edges |
| external handle | `requested`, `acknowledged`, `running`, `waiting`, `succeeded`, `failed`, `cancelled`, `expired`, `ambiguous`, `reconciled` | exact external-protocol adapter/daemon; reconciler on ambiguous settlement |

These rows name phase families, not permission to jump between arbitrary
members. The versioned legal-edge table is normative. Reference mutations have
their own kind-specific authority table and never mutate the child object; they
only append or retire the owning object's typed index entry. Thus a GoalRun's
ContextCell refs, a WorkRun's HarnessInvocation refs, and an invocation's
external handles are reconstructable without moving lifecycle ownership into
the shared kernel.

Cancellation/revocation is not a terminal string assignment. An admitted
`cancellation_intent` deterministically derives a `CancellationFanoutPlan` over
active typed children:

```yaml
CancellationFanoutPlanEnvelope:
  schema_version: ioi.cancellation-fanout-plan.v1
  object_ref: typed_ref
  source_head: hash
  requested_by_ref: actor://...
  reason: string
  compensation_policy_ref: policy://... | null
  effect_reconciliation_policy_ref: policy://... | null
  targets:
    - relation_kind: same_enum_as_above
      target_ref: typed_ref
      actions:
        - request_cancel | drain | fence | revoke_lease | close_context |
          wait_until_timeout | rollback | compensate |
          reconcile_ambiguous_effect | reconcile_irreversible_effect |
          preserve_receipt_lineage
      timeout_at_ms: integer_timestamp_ms | null
  requires_completion_receipt: true
```

The cancellation edge is refused when a compensatable active child has no
compensation policy or an ambiguous/irreversible active child has no effect-
reconciliation policy. Cancellation metadata is invalid on non-cancel edges.
The plan cannot claim child completion. Each child owner executes and receipts
its cancellation, drain, lease revocation, provider fence, timeout,
compensation, or ambiguous/irreversible-effect reconciliation. Unknown external
completion becomes `ambiguous`; it never becomes success merely because the
local wait ended.

## WorkLifecycleArchiveSegmentEnvelope and WorkLifecycleSnapshotEnvelope

```yaml
WorkLifecycleArchiveSegmentEnvelope:
  schema_version: ioi.work-lifecycle-archive-segment.v1
  archive_ref: work-lifecycle-archive://...
  object_kind: same_enum_as_record
  object_ref: typed_ref
  through_head: hash
  archive_root: hash
  records: [WorkLifecycleRecordEnvelope]
  receipt_lineage_refs: [receipt://...]
  created_at_ms: integer_timestamp_ms

WorkLifecycleSnapshotEnvelope:
  schema_version: ioi.work-lifecycle-snapshot.v1
  snapshot_ref: work-lifecycle-snapshot://...
  archive_ref: work-lifecycle-archive://...
  archive_root: hash
  through_head: hash
  resume_state:
    projection:
      schema_version: ioi.work-lifecycle-projection.v1
      object_kind: same_enum_as_record
      object_ref: typed_ref
      owner_ref: typed_ref
      active_phase: kind_specific_phase
      head: hash
      last_record_ref: work-lifecycle://...
      last_occurred_at_ms: integer_timestamp_ms
      record_count: integer
      active_children: typed_relation_index
      cancellation_intent: object | null
      receipt_lineage_refs: [receipt://...]
    idempotency_record_hashes: object
  receipt_lineage_refs: [receipt://...]
  created_at_ms: integer_timestamp_ms
```

Compaction first writes an immutable archive segment, then a snapshot bound to
that archive root and head. Resume plus an append-only tail must reconstruct the
same phase, child index, idempotency decisions, and object head as full replay.
Receipt lineage is retained even when individual hot-log records later leave
the active segment. Snapshot files are projections/checkpoints, never a license
to discard the immutable archive or owner-domain truth.

## GoalRunEnvelope

Durable state for goal-shaped work. `ioi.ai` and Hypervisor Sessions may expose
different product surfaces, but they should converge on the same GoalRun
primitive when intent must survive compaction, delegation, verification, or
long-session continuation.

The GoalRun is not a chat transcript and not a harness-specific memory file. It
is the bounded coordination record for one participant or subteam's Goal Kernel
loop: intent, constraints, role topology, context cells, leases, handoffs,
runtime assignments, attempts, generic results, verifier path, receipts, and
continuation state. A
GoalRun may stand alone or participate in an `OutcomeRoomEnvelope`; it does not
own the shared room frontier or cross-party admission policy.

```yaml
GoalRunEnvelope:
  goal_run_id: goal://...
  owner_ref: system://... | user://... | org://... | project://... | domain://...
  goal_run_profile_revision_ref: goal-run-profile://.../revision/...
  goal_run_profile_content_hash: hash
  admitted_override_set_ref: artifact://... | null
  admitted_override_set_hash: hash | null
  resolved_component_set_snapshot_ref: artifact://...
  resolved_component_set_hash: hash
  active_skill_set_snapshot_ref: active-skill-set://...
  active_skill_set_hash: hash
  goal_run_profile_resolution_receipt_ref: receipt://...
  initial_role_topology_revision_ref: role_topology://.../revision/... | null
  initial_role_topology_content_hash: hash | null
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  effective_learning_policy_hash: hash | null
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
  role_topology_ref: role_topology://.../revision/... | null
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
  runtime_assignment_refs:
    - runtime-assignment://...
  orchestration_plan_revision_refs:
    - orchestration_plan://.../revision/...
  selected_orchestration_plan_revision_ref: orchestration_plan://.../revision/... | null
  selected_orchestration_plan_content_hash: hash | null
  orchestration_decision_receipt_ref: receipt://... | null
  topology_revision_refs:
    - role_topology://.../revision/...
  attempt_refs:
    - attempt://...
  work_result_refs:
    - work-result://...
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

When `outcome_room_ref` is non-null, `room_participant_lease_ref` is required,
must name a current lease for that same room, and every `work_claim_ref` must be
issued to that lease. A GoalRun cannot attach itself to shared room state by
setting a room ref alone.

Every newly admitted GoalRun binds exactly one profile revision. Direct ad hoc
work uses the versioned generic-adaptive profile plus explicit run constraints;
null profile fields are accepted only by a versioned legacy migration adapter
and must be resolved before activation. The resolved-component snapshot,
hash, and resolution receipt are required before the GoalRun becomes `active`.
When an override set is present, both its ref and hash are required; when it is
absent, both are null. The receipt binds the admitted override set and the
transitive versions/hashes actually resolved for this run. Profile revocation
or recall follows its declared policy and may pause, quarantine, migrate, or
allow bounded completion; it never silently rewrites an active run to a newer
revision.

The `initial_role_topology_*` tuple is the immutable admission-time selection
bound by the profile-resolution receipt; both fields are null or both are
non-null. `role_topology_ref` is the current topology pointer and
`topology_revision_refs` preserves its immutable evolution. Initial selection
after grounding and every later adaptation require their own decision/receipt;
they never rewrite the admission tuple.

The selected OrchestrationPlan revision ref/hash and decision receipt are all
null before selection or all non-null after selection. Course correction appends
a successor revision and decision receipt; it never mutates the selected plan
body or makes a product `outcome-plan://` projection authoritative.

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
    - attempt://... | work-result://... |
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

Selected role shape for one admitted work subject. The topology is provider-
neutral but never actor-neutral: every role names an accountable actor or
participant separately from its step resolver, model route, and runtime
placement. The durable contract is the role, handoff shape, verifier path, and
authority posture, not a vendor or reusable resolver definition. A topology
may be fixed for a small run or revised under policy as the frontier,
participants, evidence, risk, or resource bottlenecks change.

```yaml
RoleTopologyEnvelope:
  topology_id: role_topology://...
  revision_ref: role_topology://.../revision/...
  content_hash: hash
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  outcome_room_ref: outcome-room://... | null
  topology_version: integer | semver_or_hash
  topology_kind:
    direct | goal_conductor | delegated_build | governed_release |
    multi_context_review | specialist_mesh | leaderless_blackboard |
    market_allocated | independent_replication | federated_pursuit
  mutation_policy:
    fixed | conductor_mutable | participant_proposed |
    frontier_driven | governance_required
  conductor_role_id: string
  role_bindings:
    - role_id: string
      role_kind:
        conductor | implementer | reviewer | verifier | operator |
        researcher | specialist | synthesizer | resource_provider |
        integrity_challenger | memory_curator
      accountable_actor_ref:
        participant-lease://... | system://... | worker://... | agent://... |
        service://... | org://... | user://... | domain://...
      resolver_requirement_ref: schema://... | capability://... | null
      selected_resolver_kind: harness_profile | agent_harness_adapter | none
      selected_resolver_revision_ref:
        harness-profile://.../revision/... |
        agent-harness-adapter://.../revision/... | null
      selected_resolver_content_hash: hash | null
      model_route_requirement_ref: schema://... | capability://... | null
      selected_model_route_ref: model_route://... | null
      runtime_assignment_ref: runtime-assignment://... | null
      context_cell_ref: context_cell://... | null
  resource_offer_refs:
    - resource-offer://... | capability-offer://...
  verifier_path_ref: verifier_path://... | null
  conductor_verifies_by_default: boolean
  escalation_triggers:
    - publish | runtime_mount | external_connector_action | spend |
      secret_access | unsafe_plaintext | marketplace_admission |
      release_control | production_mutation | physical_action |
      compliance_review
  predecessor_revision_ref: role_topology://.../revision/... | null
  mutation_decision_ref: decision://... | receipt://... | null
  registry_lifecycle_ref: agentgres://object/... | null
  registry_status: draft | active | adapting | satisfied | superseded | revoked
```

Each topology revision is immutable and content-addressed. Adapting topology
creates a successor revision whose `content_hash` commits the topology body and
predecessor. `mutation_decision_ref` and registry lifecycle/status are excluded;
the decision/receipt binds the already-computed revision/hash and lifecycle may
change eligibility without rewriting a revision. A GoalRun may be admitted
with `role_topology_ref: null` when its profile permits topology to be selected
after grounding. The first selection and every successor are receipted plan/run
updates, never an unversioned in-place graph mutation.

`selected_resolver_kind` discriminates the resolver ref/hash pair; `none`
requires both null. A HarnessProfile, AgentHarnessAdapter, model route, or
RuntimeAssignment can never occupy `accountable_actor_ref`. Room roles use the
current `participant-lease://` as their accountable actor; non-room roles name
the Worker, agent, service, System, organization, user, or domain that remains
responsible for the work and receipts.

## InformationFlowLabel and DeclassificationApproval

`InformationFlowLabel` is the versioned, multi-axis information-flow contract
carried by context, connector/tool outputs, memory imports, model outputs, and
their derivatives. Its registered v1 wire shape owns origin, integrity,
confidentiality, instruction authority, destination/data-class egress policy,
purpose, retention, and the transitive derivation-parent closure. Missing or
`unknown` axes fail closed at consequential-effect admission. Summarization,
model substitution, memory import, and tool-output transformation create a new
label by deterministic restrictive join; they never erase or weaken a parent
label.

Boundary production also cannot mint trust. Raw model-provider results are
`model_output + untrusted + none`; browser observations are
`external_untrusted + untrusted + none`; live MCP results are
`tool_output + untrusted + none`; and durable imported/summarized memory is
content-only while preserving the worst parent integrity and authority. A
separately admitted verifier may later create a successor label; the producing
boundary cannot do so implicitly.

`DeclassificationApproval` is the separate wallet/policy authority object for
one protected egress. It binds the exact RuntimeToolContract revision, label ref
and content hash, canonical effect hash, canonical request hash, exact reviewed-
representation hash, destination, purpose, declassification target, expiry,
grant, and approval receipt. Changing effect bytes, request content, destination,
reviewed representation, label, tool revision, purpose, status, or expiry makes
the approval unusable. Declassification changes neither provenance nor
instruction authority; it cannot make an untrusted instruction authoritative.

The canonical JSON Schema 2020-12 wire contracts, invariant profiles, and
cross-language fixtures are registered in
[`architecture-contract-registry.v1.json`](../_meta/schemas/architecture-contract-registry.v1.json).
The Hypervisor Daemon owns pre-effect evaluation. `ContextCell`, memory,
connector/tool, and model owners carry refs to these labels rather than defining
parallel taint or privacy objects.

## ContextCellEnvelope

Independent working context for one role. Context cells exist to protect
long-horizon intent from implementation-token churn, to keep implementation
details out of high-level state until summarized, and to allow review with a
fresh bounded context. Agent-to-agent conversation is allowed only when it is a
typed handoff between cells.

```yaml
ContextCellEnvelope:
  context_cell_id: context_cell://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  outcome_room_ref: outcome-room://... | null
  participant_lease_ref: participant-lease://... | null
  role_topology_revision_ref: role_topology://.../revision/... | null
  role_binding_id: string
  accountable_actor_ref:
    participant-lease://... | system://... | worker://... | agent://... |
    service://... | org://... | user://... | domain://...
  role:
    conductor | implementer | reviewer | verifier | operator |
    researcher | specialist | synthesizer | resource_provider |
    integrity_challenger | memory_curator
  resolver_revision_ref:
    harness-profile://.../revision/... |
    agent-harness-adapter://.../revision/... | null
  resolver_content_hash: hash | null
  model_route_ref: model_route://... | null
  memory_projection_refs:
    - memory_projection://... | wiki://...
  context_lease_refs:
    - context_lease://... | lease://...
  information_flow_label_refs:
    - ifc-label://...
  active_runtime_assignment_ref: runtime-assignment://... | null
  authority_scope_refs:
    - authority://... | policy://...
  compression_policy_ref: policy://... | null
  current_claim_ref: work-claim://... | null
  next_wake_condition_ref: policy://... | event://... | null
  status:
    open | active | sleeping | waiting | handed_off | summarized |
    quarantined | closed | revoked
```

The runtime-assignment refs above are projections of separately admitted
placement decisions. A RoleTopology declares logical responsibility and a
Context Cell owns bounded working context; neither object may infer node
membership, locality, authority, or cross-system participation from a worker or
harness ref. Reassignment creates a new assignment epoch and preserves the
predecessor and reconciliation lineage.

When `role_topology_revision_ref` is non-null, `role_binding_id`, accountable
actor, resolver ref/hash, model route, runtime assignment, and participant
lease must equal that exact topology role. Changing any of those role-binding
axes requires a successor RoleTopology revision plus the owning routing,
placement, or admission decision/receipt and an updated cell pointer. They are
convenience projections, not independent selection truth.
A topology-less direct-work cell leaves the topology ref null and must still
name its standalone accountable actor; HarnessInvocation owns the resolver
actually invoked.

## ContextLeaseEnvelope

Scoped lease that lets a Context Cell or harness invocation use only the context,
tools, memory, files, runtime, authority, and budget required for its bounded
role. Context leases make context a governed resource instead of dumping the
entire conversation, wiki, repo, connector estate, or authority envelope into
every harness.

```yaml
ContextLeaseEnvelope:
  context_lease_id: context_lease://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  context_cell_ref: context_cell://... | null
  issued_to_ref: context_cell://... | harness_invocation://...
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

`issued_to_ref` names only a concrete ContextCell or HarnessInvocation. A
reusable HarnessProfile, AgentHarnessAdapter, Worker definition, or service
definition is never a lease subject. The lease and its subject must bind the
same `work_subject_ref`; when a cell ref is present it must be that subject or
the cell that owns the invocation.

## ContextHandoffEnvelope

Typed packet between context cells. Handoffs are the durable substrate for
conductor/implementer/reviewer workflows; they should contain enough state for
the receiving cell to act without inheriting the sender's entire context window.

```yaml
ContextHandoffEnvelope:
  handoff_id: handoff://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
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
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  handoff_ref: handoff://... | null
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
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  goal_run_ref: goal://... | null
  accountable_actor_ref:
    participant-lease://... | system://... | worker://... | agent://... |
    service://... | org://... | user://... | domain://...
  handoff_ref: handoff://... | null
  context_cell_ref: context_cell://... | null
  task_brief_ref: task_brief://...
  resolver_kind: harness_profile | agent_harness_adapter
  resolver_revision_ref:
    harness-profile://.../revision/... |
    agent-harness-adapter://.../revision/...
  resolver_content_hash: hash
  model_route_ref: model_route://... | null
  runtime_ref: runtime://... | environment://... | session://... | null
  external_invocation_bindings:
    - external_protocol_binding_ref: aiip-binding://... | mcp://... | schema://...
      protocol_version_or_extension_ref: string
      opaque_handle_commitment: hash
      encrypted_or_redacted_handle_ref: artifact://... | null
      status_projection_ref: event://... | artifact://... | null
  context_lease_refs:
    - context_lease://...
  adapter_rendering_ref: artifact://... | null
  event_refs:
    - harness_event://...
  work_result_ref: work-result://... | null
  profile_result_ref: implementation_result://... | artifact://... | null
  receipt_refs:
    - receipt://... | ledger://...
  status:
    queued | running | waiting_on_harness | waiting_on_conductor |
    completed | failed | cancelled | superseded
```

An MCP Task or another protocol-native asynchronous task remains an opaque
external invocation handle bound to this invocation and its exact
protocol/version adapter. IOI records its commitment and protected handle
reference; it does not mint an IOI identity that pretends to own the external
task. The handle never becomes the `GoalRun` identity or authoritative GoalRun
status. Completion is normalized into `WorkResult` / `OutcomeDelta` and remains
subject to the conductor's `VerifierPath`.

`resolver_kind` discriminates the exact resolver revision/hash. The invocation
also binds the accountable actor that owns the work and receipts; neither a
HarnessProfile, adapter, model route, nor runtime can stand in for that actor.
GoalRun/context-cell execution binds `goal_run_ref`, `handoff_ref`, and
`context_cell_ref` as applicable. A direct AutomationRun, WorkRun, module run,
claim, or attempt invocation may leave those goal-specific refs null, but still
requires an exact `work_subject_ref`, accountable actor, TaskBrief, resolver,
leases, and result/receipt path. Every event and result emitted by the
invocation must carry the same work subject.

A completed invocation requires `work_result_ref`. `profile_result_ref` is an
optional domain/profile payload and cannot replace the canonical WorkResult.
For software work it names an `ImplementationResultPayloadEnvelope`, which
must point back to the same WorkResult and be the WorkResult's
`result_payload_ref` (or its content-addressed payload). Failed or cancelled
invocations may leave both result refs null only when their terminal receipt
and failure/blocker evidence are present.

## HarnessAdapterEventEnvelope

Normalized event emitted by a harness adapter during a HarnessInvocation.
Harnesses may stream text, tool calls, terminal output, file writes, browser
events, or provider-specific state; the adapter must translate them into common
events before they become durable coordination evidence.

```yaml
HarnessAdapterEventEnvelope:
  harness_event_id: harness_event://...
  harness_invocation_ref: harness_invocation://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
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
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  harness_invocation_ref: harness_invocation://...
  handoff_ref: handoff://... | null
  work_result_ref: work-result://...
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
      attempt://... | finding://... | ontology-assertion://... |
      evidence://...
  verifier_rule_version_ref: rubric://... | policy://... | gate://...
  verification_kind:
    deterministic | test | static_analysis | browser_evidence |
    model_judge | verifier_worker | human_review | benchmark |
    regulated_review | physical_safety | hybrid
  required_evidence_refs:
    - artifact://... | receipt://... | gate://... | benchmark://...
  verifier_refs:
    - principal://... | worker://... | model://... | gate://... | org://... |
      system://... | domain://...
  acceptance_threshold_ref: rubric://... | gate://... | policy://...
  independence:
    minimum_independent_principals: nonnegative_integer
    subject_owner_may_self_verify: boolean
    required_distinct_independence_groups: nonnegative_integer
    affiliation_and_dependency_evidence_refs:
      - evidence://... | artifact://... | receipt://...
    correlated_failure_policy_ref: policy://... | null
  replay_required: boolean
  challenge_refs:
    - verifier-challenge://...
  status:
    draft | active | challenged | reverifying | satisfied |
    failed | superseded | revoked
```

For an independence requirement greater than zero, a verifier counts only when
its accountable principal, affiliations, upstream evidence dependencies, and
declared independence group satisfy the selected correlation policy. Missing
affiliation or dependency evidence is unknown and never counts as independence.

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
  benchmark_run_id: benchmark://...
  worker_id: worker://...
  worker_composition_ref: package://... | ai://... | null
  model_route_ref: model_route://... | null
  resolver_kind: harness_profile | agent_harness_adapter | none
  resolver_revision_ref:
    harness-profile://.../revision/... |
    agent-harness-adapter://.../revision/... | null
  resolver_content_hash: hash | null
  semantic_harness_profile_revision_ref:
    harness-profile://.../revision/... | null
  semantic_harness_profile_content_hash: hash | null
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

The benchmark resolver discriminator follows the pairing rule above. An
adapter benchmark may additionally bind the exact HarnessProfile it realizes;
the score never treats an adapter family ref or semantic profile as proof of
the other. `none` requires all resolver/profile fields to be null unless the
benchmark profile explicitly names a non-harness deterministic path.

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
  task_offer_ref: packet://... | null
  task_acceptance_refs:
    - packet://...
  selected_task_acceptance_ref: packet://... | null
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: hash | null
  budget_reservation_ref: budget://... | spend://... | allocation://... | null
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

For an external solicitation, the decision binds every admitted response and
the selected response under one terms root. It explains selection but is not
an authority grant, executable award, accepted result, contribution allocation,
or payout right. The corresponding `WorkClaimLeaseEnvelope` is the bounded
award that must still satisfy participant, context, resource, budget, and
authority admission.

The `selected_task_acceptance_ref` must be a member of
`task_acceptance_refs`. For an external solicitation it is non-null, has
`status: accepted`, names `selected_domain_or_worker` as its accountable
responder, and binds the same collaboration terms root. The selected quote and
budget reservation must match the routing decision. Internal local routing may
leave offer/response refs null, but it cannot claim an external award.
