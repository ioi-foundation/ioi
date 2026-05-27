# Common Objects and Envelopes

Status: canonical low-level reference.
Canonical owner: this file for shared envelope names, ID namespaces, primitive capability tiers, authority grants, and receipt/run/event envelope fields.
Supersedes: older flattened capability-tier examples in plans/specs.
Superseded by: none.
Last alignment pass: 2026-05-25.

## Purpose

This file defines the shared low-level objects that every IOI/Web4 component must understand. The goal is to prevent split-brain API design between `@ioi/agent-sdk`, IOI ADK, IOI CLI/TUI, agent-ide, Autopilot, IOI daemon, Agentgres, wallet.network, aiagent.xyz, sas.xyz, workflow compositor, harnesses, benchmarks, hosted/self-hosted workers, and IOI L1 contracts.

## Canonical Envelope Types

```text
ManifestEnvelope
AutonomousSystemManifestEnvelope
AutonomousSystemChainEnvelope
AutopilotNodeEnvelope
BoundedExecutionDomainEnvelope
ServiceModuleManifestEnvelope
ModuleInvocationEnvelope
UpgradeProposalEnvelope
UpgradeDecisionEnvelope
LocalSettlementEnvelope
AIIPChannelEnvelope
AIIPEnvelope
CapabilityDescriptorEnvelope
TaskOfferEnvelope
TaskAcceptanceEnvelope
HandoffEnvelope
ReceiptCommitmentEnvelope
SettlementIntentEnvelope
ReputationEventEnvelope
AuthorityScopeRequestEnvelope
AuthorityGrantEnvelope
TaskEnvelope
RunEnvelope
WorkerInstanceEnvelope
RuntimeSubscriptionEnvelope
RuntimeAssignmentEnvelope
ComputeSessionEnvelope
RuntimeEventEnvelope
ReceiptEnvelope
ArtifactEnvelope
SealedStateArchiveEnvelope
DeliveryEnvelope
SettlementEnvelope
ContributionEnvelope
QualityEnvelope
DisputeEnvelope
DomainOntologyEnvelope
CanonicalObjectModelEnvelope
DataRecipeEnvelope
ConnectorMappingEnvelope
PolicyBoundDataViewEnvelope
TransformationRunEnvelope
DistilledOntologyDatasetEnvelope
EvaluationDatasetEnvelope
OntologyProjectionEnvelope
OntologyToWorkerPlanEnvelope
ModelCapacityProfileEnvelope
ModelDeploymentProfileEnvelope
TrainingBatchPlanEnvelope
GenerationBatchEnvelope
RawBatchArchiveEnvelope
QualityGateReportEnvelope
TrainingCostLedgerEnvelope
WorkerTrainingEnvelope
PostTrainingCycleEnvelope
ContextMutationEnvelope
PromotionDecisionEnvelope
BenchmarkEnvelope
RoutingDecisionEnvelope
```

## Common ID Conventions

```text
ai://...                global intelligence/app/worker/service namespace
system://...            Autonomous System Package namespace
domain://...            bounded execution domain, application domain, or sovereign domain namespace
node://...              Autopilot node or runtime node namespace
module://...            governed service-module namespace
invocation://...        module invocation namespace
proposal://...          upgrade, policy, module, workflow, or settlement proposal namespace
transition://...        accepted local state-transition namespace
aiip://channel/...      AIIP channel namespace
packet://...            AIIP packet namespace
settlement-intent://... AIIP settlement intent namespace
ioi://publisher/...     publisher identity
agent://...             product-facing agent instance or compatibility worker instance
worker://...            worker package or worker type
install://...           worker install/license binding
subscription://...      runtime or managed-instance subscription/entitlement
service://...           sas.xyz service definition
run://...               runtime run identity
task://...              task identity
runtime://...           IOI daemon/runtime-node identity
compute://...           compute session identity
artifact://...          Agentgres artifact ref
receipt://...           receipt identity
benchmark://...         benchmark profile or benchmark run identity
rubric://...            evaluation rubric identity
ontology://...          domain ontology identity
object-model://...      canonical object model identity
recipe://...            data recipe identity
mapping://...           connector mapping identity
view://...              policy-bound data view identity
dataset://...           evaluation or training dataset identity
projection://...        ontology-aware or Agentgres projection identity
transform://...         transformation run identity
plan://...              ontology-to-worker plan identity
profile://...           training/model capacity profile identity
batch://...             training batch plan or generation batch identity
gate://...              quality gate report or promotion gate identity
ledger://...            usage, token, cost, or contribution ledger identity
cid://...               Filecoin/CAS content ref
wallet://...            wallet.network account or authority ref
prim://...              primitive execution capability ref
scope://...             wallet.network authority scope ref
grant://...             authority grant or lease ref
```

All IDs must be globally unique within their declared namespace. IDs that become public must be stable. Runtime-local IDs may be temporary but must map to stable Agentgres IDs when settled.

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

Authority scopes are wallet.network policy grants over resources, providers, identities, budgets, approvals, and expiry. They describe what a subject is allowed to do.

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

Autopilot's primary build artifact is an Autonomous System Package.

An Autonomous System Package is the developer-facing skeletal unit for
autonomous-system work. It is not an agent, connector, workflow, daemon
process, or policy bundle. It binds worker responsibility, workflow or harness
topology, model and tool capabilities, authority, memory/state/artifacts, evals,
deployment profiles, and receipts into one packageable object.

Implementation may represent the package as a strict `ManifestEnvelope` profile,
as `AutonomousSystemManifestEnvelope`, or as both. That implementation choice
must not make the package concept invisible in product, SDK, ADK, CLI/TUI,
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
| Authority | wallet.network grant or lease over resource, provider, identity, budget, approval, secret, and expiry. | A capability flag or UI readiness badge. |
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
  owning_autopilot_node_id: node://...
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
AutopilotNodeEnvelope:
  node_id: node://...
  owner_id: wallet://... | org://... | project://...
  workbench_ref: optional
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

## AIIP and Bounded Execution Domain Envelopes

AIIP is the shared semantic protocol for local microharness routing and
external autonomous-system handoffs. Transports and settlement depth may vary,
but consequential work packets must compile into typed envelopes with policy,
authority, receipt, and settlement semantics.

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

```yaml
AIIPChannelEnvelope:
  channel_id: aiip://channel/...
  system_id_from: system://... | domain://...
  system_id_to: system://... | domain://...
  profile: local | installed_worker | marketplace_worker | outcome_service | autonomous_system | enterprise
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
  message_type: capability_discovery | task_offer | task_acceptance | handoff | authority_query | authority_grant | receipt_commitment | settlement_intent | dispute | reputation_query
  system_id_from: system://... | domain://...
  system_id_to: system://... | domain://...
  channel_id: aiip://channel/...
  sequence_or_nonce: string
  timestamp_or_slot: string
  profile: local | installed_worker | marketplace_worker | outcome_service | autonomous_system | enterprise
  policy_hash: hash
  authority_ref: optional grant://...
  payload_hash: hash
  payload_ref: optional artifact://... | cid://... | encrypted_ref
  receipt_obligations: []
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
  autopilot_node_id: node://...
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
  autopilot_node_id: node://...
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
  status: starting | running | idle | suspended | archived | failed
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
      - agentgres://project/autopilot/*
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
    - agentgres://project/autopilot/*
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

## TaskEnvelope

```yaml
TaskEnvelope:
  task_id: task_...
  requester_id: wallet://... | agent://... | service://...
  objective: string
  task_class: coding | research | workflow | commerce | render | connector | service_delivery | managed_agent | other
  privacy_class: public | internal | confidential | regulated
  execution_profile: local | hosted | provider | depin_mutual_blind | tee_enterprise | customer_vpc
  input_refs:
    - artifact://...
    - agentgres://object/...
  output_contract:
    type: report | patch | artifact | delivery_bundle | service_result | worker_result
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
  runtime_id: runtime://...
  worker_id: optional
  worker_instance_id: optional
  service_id: optional
  subscription_ref: optional
  state: queued | assigned | starting | running | awaiting_approval | paused | completed | failed | cancelled
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
  task_state_ref: optional
  agentgres_projection_watermark: optional
```

## RuntimeEventEnvelope

```yaml
RuntimeEventEnvelope:
  event_id: evt_...
  parent_event_id: optional
  run_id: run_...
  task_id: task_...
  turn_id: optional
  kind: session.started | model.requested | model.completed | tool.proposed | policy.decided | approval.requested | tool.started | tool.completed | artifact.created | ontology.bound | data_recipe.run_started | data_recipe.run_completed | transformation.receipt_emitted | distilled_dataset.bound | evaluation_dataset.bound | ontology_projection.updated | training.batch_planned | training.generation_batch_archived | training.quality_gates_reported | training.cost_ledger_updated | receipt.emitted | run.completed | run.failed
  timestamp: timestamp
  actor_id: agent://... | runtime://... | wallet://...
  privacy_class: public | internal | private | secret
  redaction_status: full | redacted | hash_only
  payload: object
  receipt_ref: optional
  cursor: integer
  terminal: boolean
```

## ReceiptEnvelope

```yaml
ReceiptEnvelope:
  receipt_id: receipt_...
  receipt_type: policy | approval | model_invocation | tool_execution | module_invocation | artifact | validation | delivery | settlement | local_settlement | contribution | quality | data_recipe_run | transformation | dataset_distillation | ontology_projection | upgrade_proposal | upgrade_decision | training_batch_plan | generation_batch | quality_gate_report | training_cost_ledger | training_trace | dataset_curation | context_mutation | post_training_cycle | promotion_decision | benchmark_run | evaluation_verdict | routing_decision
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
  timestamp: timestamp
  signature: optional
  l1_commitment: optional
```

## ArtifactEnvelope

```yaml
ArtifactEnvelope:
  artifact_id: artifact_...
  cid: bafy...
  sha256: hash
  size_bytes: integer
  media_type: string
  privacy_class: public | internal | private | encrypted
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
  worker_invocation_id: optional
  run_id: run_...
  output_artifacts: []
  evidence_bundle: []
  quality_summary: object
  policy_summary: object
  settlement_status: pending | accepted | disputed | paid | refunded
  acceptance_deadline: optional
```

## SettlementEnvelope

```yaml
SettlementEnvelope:
  settlement_id: settle_...
  chain_id: ioi-mainnet
  contract: string
  action: escrow_lock | payout_release | license_mint | dispute_open | dispute_resolve | reputation_root_update
  amount: optional
  token: IOI | stablecoin | credit
  related_delivery_id: optional
  related_receipt_root: optional
  tx_hash: optional
```

## ContributionEnvelope

```yaml
ContributionEnvelope:
  contribution_id: contrib_...
  contributor_id: worker://... | service://... | publisher://... | tool://... | model://...
  consumer_id: wallet://... | service://... | agent://...
  task_id: task_...
  contribution_type: worker_invocation | service_delivery | tool_use | model_use | dataset_use | workflow_use | verification | training_data | distilled_training_data | training_service | benchmark_submission | routing_selection | verifier_signal
  usage_hash: hash
  sparse_worker_category: optional
  benchmark_profile_ref: optional
  routing_decision_ref: optional
  downstream_outcome_ref: optional
  dispute_status: none | pending | upheld | rejected | no_fault
  quality_delta: optional
  reward_claim: optional
  license_ref: optional
  receipt_ref: receipt://...
```

## DomainOntologyEnvelope

```yaml
DomainOntologyEnvelope:
  ontology_id: ontology://...
  name: string
  domain_ref: agentgres://domain/... | service://... | org://...
  version: semver_or_hash
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
  privacy_class: public | internal | confidential | regulated
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
  privacy_class: public | internal | confidential | regulated
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
  model_artifact_refs:
    - cid://... | artifact://... | file://...
  endpoint_refs:
    - model_endpoint://...
  provider_refs: []
  authority_scope_requirements:
    - scope:model.invoke.external
  privacy_class: local | external_api | tenant_private | tee_private | regulated
  run_to_idle_policy_ref: optional
  receipt_mode: hash_only | full_redacted | full_private
  status: draft | active | unavailable | revoked
```

Bundled local weights are valid for offline, demo, small sovereign, or
deployment-specific profiles. They are not the architecture default.

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

## RawBatchArchiveEnvelope

```yaml
RawBatchArchiveEnvelope:
  raw_batch_archive_id: artifact://...
  training_id: train_...
  generation_batch_refs:
    - batch://...
  raw_artifact_refs:
    - artifact://...
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

## ContextMutationEnvelope

```yaml
ContextMutationEnvelope:
  mutation_id: ctxmut_...
  worker_id: worker://...
  project_ref: agentgres://project/... | optional
  mutation_type: fact | preference | doctrine | route | procedure | eval | failure
  operation: add | supersede | contradict | deprecate | activate | archive
  claim_ref: artifact://... | hash://... | optional
  prior_claim_refs: []
  evidence_refs: []
  source_authority: user | worker | verifier | benchmark | service_delivery | admin
  policy_hash: hash
  receipt_ref: receipt://...
```

## PromotionDecisionEnvelope

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

## BenchmarkEnvelope

```yaml
BenchmarkEnvelope:
  benchmark_run_id: bench_...
  worker_id: worker://...
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

```yaml
RoutingDecisionEnvelope:
  routing_decision_id: route_...
  task_id: task://...
  router_id: worker://... | runtime://... | system://... | domain://...
  intent_hash: hash
  candidate_set_commitment: hash
  routing_policy_hash: hash
  selected_domain_or_worker: system://... | domain://... | worker://... | service://... | runtime://...
  authority_scope: []
  cost_bound: optional
  reason_code: string
  fallback_policy: optional
  contribution_policy_ref: optional
  receipt_obligations: []
  signature: optional
```
