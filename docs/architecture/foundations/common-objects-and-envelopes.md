# Common Objects and Envelopes

Status: canonical low-level reference and shared-object family index.
Canonical owner: this file for the envelope base types every shared object reuses, the bounded `Common ID Conventions` ref-scheme registry, the primitive-capability and authority tiers, `ManifestEnvelope`, and the index of the shared-object modules under [`objects/`](./objects/). Each module under `objects/` is the single canonical owner of the object shapes it lists; this file does not restate them.
Supersedes: the single-file form of this document, which carried every shared object shape in one 11,000-line file.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: mixed (the envelope base types, ID registry, and capability/authority tiers are shared contract substrate; per-object implementation status is declared by each owning module under `objects/`)
Last implementation audit: 2026-07-25

## Purpose

This file defines the shared low-level objects that every IOI/Web4 component
must understand. The goal is to prevent split-brain API design between
`@ioi/agent-sdk`, IOI ADK, IOI ODK, IOI CLI/headless, optional TUI, Hypervisor
Developer Workspace, Workflow Compositor, Hypervisor, Hypervisor Daemon, Agentgres,
wallet.network, aiagent.xyz, sas.xyz, harness profiles, benchmarks,
hosted/self-hosted workers, and IOI L1 contracts.

## Shared-Object Modules

Every shared object shape is owned by exactly one module below. Load the
module you need; you do not need the rest of the family. Doctrine and
lifecycle semantics stay with the subject owner named in each row.

| Module | Owns the object shapes for | Doctrine owner |
| --- | --- | --- |
| [`reusable-work-definitions.md`](./objects/reusable-work-definitions.md) | WorkflowTemplate, SkillManifest, SkillEntry, ActiveSkillSetSnapshot | [`components/hypervisor/core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md) |
| [`bounded-system-genesis.md`](./objects/bounded-system-genesis.md) | Package Release And Live-System Genesis, Governed Autonomous-System Chain Envelopes, LocalAgentPairingSessionEnvelope | [`foundations/governed-autonomous-systems.md`](../foundations/governed-autonomous-systems.md) |
| [`interop-and-collaboration-terms.md`](./objects/interop-and-collaboration-terms.md) | AIIP and Bounded Execution Domain Envelopes, Dispute Rail Object Family, CollaborationTermsEnvelope | [`foundations/aiip.md`](../foundations/aiip.md) |
| [`authority-and-access.md`](./objects/authority-and-access.md) | AuthorityScopeRequestEnvelope, ApprovalCeremonyContextEnvelope, AuthorityGrantEnvelope, AuthorityClientEnvelope, +2 more | [`components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md) |
| [`work-execution.md`](./objects/work-execution.md) | WorkerInstanceEnvelope, RuntimeSubscriptionEnvelope, TypedWorkSubjectBinding, RuntimeAssignmentEnvelope, +3 more | [`components/daemon-runtime/doctrine.md`](../components/daemon-runtime/doctrine.md) |
| [`evidence-and-delivery.md`](./objects/evidence-and-delivery.md) | RuntimeEventEnvelope, ReceiptEnvelope, ArtifactEnvelope, DeliveryEnvelope | [`components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) |
| [`economics-and-settlement.md`](./objects/economics-and-settlement.md) | Managed Work Billing Object Family, SettlementEnvelope, NetworkServiceInvocationEnvelope, ContributionEnvelope | [`foundations/economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md) |
| [`semantic-plane.md`](./objects/semantic-plane.md) | DomainOntologyEnvelope, OntologyAssertionEnvelope, OntologyMappingEnvelope, OntologyActionContractEnvelope, +7 more | [`foundations/domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md) |
| [`institutional-learning.md`](./objects/institutional-learning.md) | LearningSourceRightsClaimEnvelope, InstitutionalLearningBoundaryProfileEnvelope, PolicyBoundDataViewEnvelope, TransformationRunEnvelope, +4 more | [`foundations/institutional-learning-boundary.md`](../foundations/institutional-learning-boundary.md) |
| [`model-foundry-and-training.md`](./objects/model-foundry-and-training.md) | ModelCapacityProfileEnvelope, ModelDeploymentProfileEnvelope, ModelWeightCustodyProfileEnvelope, FoundrySpecEnvelope, +20 more | [`components/hypervisor/foundry.md`](../components/hypervisor/foundry.md) |
| [`embodied-systems.md`](./objects/embodied-systems.md) | Physical Mission Segment Envelopes, EmbodiedCapabilitySpecEnvelope, EmbodiedTrainingDataContractEnvelope, WorldRepresentationManifest, +10 more | [`components/daemon-runtime/embodied-runtime.md`](../components/daemon-runtime/embodied-runtime.md) |
| [`memory-and-promotion.md`](./objects/memory-and-promotion.md) | AgentWikiEnvelope, Portable Agent Memory, ContextMutationEnvelope, PromotionDecisionEnvelope, +1 more | [`components/daemon-runtime/portable-memory-vault.md`](../components/daemon-runtime/portable-memory-vault.md) |
| [`bounded-improvement.md`](./objects/bounded-improvement.md) | Bounded Improvement Campaign Envelopes | [`foundations/bounded-recursive-improvement.md`](../foundations/bounded-recursive-improvement.md) |
| [`goal-pursuit.md`](./objects/goal-pursuit.md) | GoalRunProfileEnvelope, OrchestrationConstraintEnvelope, OrchestrationPolicyEnvelope, OrchestrationPlanEnvelope, +1 more | [`domains/ioi-ai/control-plane.md`](../domains/ioi-ai/control-plane.md) |
| [`collaborative-pursuit.md`](./objects/collaborative-pursuit.md) | OutcomeRoomDiscoveryEnvelope and RoomParticipationRequestEnvelope, OutcomeRoomEnvelope, RoomParticipantLeaseEnvelope, ParticipantStateBundleEnvelope, +6 more | [`domains/ioi-ai/collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) |
| [`work-results-and-lifecycle.md`](./objects/work-results-and-lifecycle.md) | WorkResultEnvelope and OutcomeDeltaEnvelope, WorkLifecycleRecordEnvelope, WorkLifecycleArchiveSegmentEnvelope and WorkLifecycleSnapshotEnvelope | [`components/daemon-runtime/doctrine.md`](../components/daemon-runtime/doctrine.md) |
| [`goal-run-execution.md`](./objects/goal-run-execution.md) | GoalRunEnvelope, GoalGroundingLoopEnvelope, RoleTopologyEnvelope, InformationFlowLabel and DeclassificationApproval, +11 more | [`components/daemon-runtime/default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) |

Anything not listed above is owned by this file: the envelope base types,
the `Common ID Conventions` ref-scheme registry, the primitive-capability and
authority tiers, and `ManifestEnvelope`.

What a name *means* — and what it must not mean — is owned by
[`term-boundaries.md`](./term-boundaries.md), not by any module here. Exact
enumerated member sets are owned by
[`canonical-enums.md`](./canonical-enums.md).

## Canonical Envelope and Shared Contract Types

```text
ManifestEnvelope
WorkflowTemplateEnvelope
SkillManifestEnvelope
SkillEntryEnvelope
ActiveSkillSetSnapshotEnvelope
AutonomousSystemManifestEnvelope
AutonomousSystemGenesisEnvelope
AutonomousSystemSequenceZeroMaterializationEnvelope
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
ApprovalCeremonyContextEnvelope
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
approval-ceremony-context://... immutable single-use approval ceremony context identity
review://...            authority, delivery, or policy review identity
transition://...        accepted local state-transition namespace
state://...             referenced operational, environment, world, or domain state identity
constitution://...      autonomous-system constitutional boundary and amendment lineage
constitution-amendment://... immutable constitutional amendment proposal identity
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
wallet-client://...     wallet.network CLI/MCP/mobile/web/embedded client session
wallet_client://...     read-only legacy alias for wallet-client://...; never emitted by new writes
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
