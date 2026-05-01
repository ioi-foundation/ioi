// packages/agent-ide/src/types/graph.ts

// ============================================
// Node Configuration Schemas
// ============================================

export interface WorkflowTestAssertion {
  kind: "node_exists" | "schema_matches" | "output_contains" | "custom";
  expected?: unknown;
  expression?: string;
}

export interface WorkflowNodeViewMacro {
  macroId: string;
  macroLabel: string;
  role: "input" | "model" | "memory" | "tool" | "parser" | "decision" | "gate" | "output";
  expandedFrom: "agent_loop_macro" | string;
}

export interface WorkflowFieldMapping {
  source: string;
  path: string;
  type?: string;
}

export interface NodeLogic {
  // --- Source / output ---
  payload?: unknown;
  sourceKind?: "manual" | "file" | "media" | "dataset" | "api_payload";
  sourcePath?: string;
  fileExtension?: string;
  mediaKind?: "image" | "audio" | "video" | "document";
  sanitizeInput?: boolean;
  stripMetadata?: boolean;
  validateMime?: boolean;
  format?: string;
  path?: string;
  rendererRef?: WorkflowRendererRef;
  materialization?: WorkflowMaterializationConfig;
  deliveryTarget?: WorkflowDeliveryTarget;
  retentionPolicy?: WorkflowOutputRetentionPolicy;
  versioning?: WorkflowOutputVersioning;

  // --- Model Nodes ---
  modelRef?: string;
  provider?: string;
  model?: string;
  modelId?: string;
  modelHash?: string;
  temperature?: number;
  systemPrompt?: string;
  prompt?: string;
  text?: string;
  modelBinding?: WorkflowModelBinding;
  toolUseMode?: "none" | "explicit" | "auto";
  parserRef?: string;
  parserBinding?: WorkflowParserBinding;
  memoryKey?: string;
  validateStructuredOutput?: boolean;
  jsonMode?: boolean;
  maxTokens?: number;
  stream?: boolean;

  // --- Tool Nodes ---
  endpoint?: string;
  method?: "GET" | "POST" | "PUT" | "DELETE";
  headers?: Record<string, string>;
  bodyTemplate?: string;
  timeoutMs?: number;

  // --- Dynamic MCP Tools ---
  tool_name?: string;
  arguments?: Record<string, unknown>;
  toolBinding?: WorkflowToolBinding;

  // --- Code / Function ---
  language?: string;
  code?: string;
  functionBinding?: WorkflowFunctionBinding;

  // --- Flow Control ---
  routes?: string[];
  defaultRoute?: string;
  routerInstruction?: string;
  durationMs?: number; // Wait block
  retry?: {
    maxAttempts?: number;
    backoffMs?: number;
  };

  // --- Context ---
  variables?: Record<string, string>;

  // --- Triggers ---
  triggerKind?: "manual" | "scheduled" | "event";
  runtimeReady?: boolean;
  rssUrl?: string;
  cronSchedule?: string;
  eventSourceRef?: string;
  dedupeKey?: string;

  // --- State ---
  stateKey?: string;
  stateOperation?: "read" | "write" | "append" | "merge";
  reducer?: "replace" | "append" | "merge";
  initialValue?: unknown;
  
  // --- Retrieval ---
  query?: string;
  limit?: number;
  url?: string;
  max_chars?: number;
  topK?: number;
  candidatesText?: string;

  // --- Media ---
  mimeType?: string;
  audioPath?: string;
  imagePath?: string;
  maskImagePath?: string;
  audioLanguage?: string;
  voice?: string;

  // --- Logic ---
  conditionScript?: string;
  loopCondition?: string;
  maxIterations?: number;
  barrierStrategy?: "all" | "any";
  subgraphRef?: WorkflowSubgraphRef;
  proposalAction?: WorkflowProposalAction;
  assertion?: WorkflowTestAssertion;
  assertionKind?: WorkflowTestAssertion["kind"];
  expected?: unknown;
  expression?: string;

  // --- Connector / adapter binding ---
  connectorBinding?: WorkflowConnectorBinding;

  // --- Runtime validation ---
  schema?: WorkflowJsonSchema;
  inputMapping?: Record<string, string>;
  fieldMappings?: Record<string, WorkflowFieldMapping>;
  inputSchema?: WorkflowJsonSchema;
  outputSchema?: WorkflowJsonSchema;
  testInput?: unknown;
  mockBinding?: boolean;

  // --- View-only composition helpers ---
  viewMacro?: WorkflowNodeViewMacro;
}

export interface FirewallPolicy {
  budgetCap?: number;
  networkAllowlist?: string[];
  requireHumanGate?: boolean;
  privilegedActions?: string[];
  privacyLevel?: "none" | "masked" | "zero-knowledge";
  retryPolicy?: {
    maxAttempts: number;
    backoffMs: number;
  };
  sandboxPolicy?: WorkflowSandboxPolicy;
}

export type WorkflowSideEffectClass =
  | "none"
  | "read"
  | "write"
  | "external_write"
  | "financial_write"
  | "admin";

export interface WorkflowJsonSchema {
  type?: string;
  required?: string[];
  properties?: Record<string, unknown>;
  additionalProperties?: boolean;
}

export interface WorkflowSandboxPolicy {
  timeoutMs?: number;
  memoryMb?: number;
  outputLimitBytes?: number;
  permissions?: Array<"filesystem" | "network" | "process">;
}

export interface WorkflowFunctionBinding {
  language: "javascript" | "typescript" | "python";
  code: string;
  functionRef?: WorkflowFunctionRef;
  inputSchema?: WorkflowJsonSchema;
  outputSchema?: WorkflowJsonSchema;
  sandboxPolicy?: WorkflowSandboxPolicy;
  testInput?: unknown;
}

export type WorkflowToolBindingKind = "plugin_tool" | "mcp_tool" | "workflow_tool";

export interface WorkflowToolBinding {
  toolRef: string;
  bindingKind?: WorkflowToolBindingKind;
  mockBinding: boolean;
  credentialReady?: boolean;
  capabilityScope: string[];
  sideEffectClass: WorkflowSideEffectClass;
  requiresApproval: boolean;
  arguments?: Record<string, unknown>;
  workflowTool?: {
    workflowPath: string;
    argumentSchema?: WorkflowJsonSchema;
    resultSchema?: WorkflowJsonSchema;
    timeoutMs?: number;
    maxAttempts?: number;
  };
}

export interface WorkflowConnectorBinding {
  connectorRef: string;
  mockBinding: boolean;
  credentialReady?: boolean;
  capabilityScope: string[];
  sideEffectClass: WorkflowSideEffectClass;
  requiresApproval: boolean;
  operation?: string;
}

export interface WorkflowNodeExecutor {
  nodeType: WorkflowNodeKind | string;
  executorId: string;
  sandboxed: boolean;
  supportsDryRun: boolean;
}

export interface WorkflowVerificationEvidence {
  nodeId: string;
  evidenceType: "execution" | "schema_validation" | "approval" | "output" | "materialized_asset" | "test";
  status: "passed" | "failed" | "blocked";
  summary: string;
  createdAtMs: number;
}

export interface WorkflowCompletionRequirement {
  id: string;
  nodeId?: string;
  requirementType: "execution" | "verification" | "approval" | "output_created" | "asset_materialized" | "test";
  status: "satisfied" | "missing" | "failed";
  summary: string;
}

export type WorkflowOutputFormat =
  | "markdown"
  | "json"
  | "svg"
  | "image"
  | "chart"
  | "diff"
  | "patch"
  | "dataset"
  | "message"
  | "report";

export interface WorkflowRendererRef {
  rendererId: string;
  displayMode: "inline" | "canvas_preview" | "table" | "json" | "media" | "diff" | "report" | "artifact_panel";
  dependencies?: string[];
}

export interface WorkflowMaterializationConfig {
  enabled: boolean;
  assetPath?: string;
  assetKind?: "file" | "blob" | "report" | "svg" | "chart" | "patch" | "dataset";
}

export interface WorkflowDeliveryTarget {
  targetKind: "none" | "chat_inline" | "local_file" | "repo_patch" | "ticket_draft" | "message_draft" | "connector_write" | "deploy";
  targetRef?: string;
  requiresApproval?: boolean;
}

export interface WorkflowOutputRetentionPolicy {
  retentionKind: "ephemeral" | "run_scoped" | "workflow_scoped" | "versioned";
  ttlMs?: number;
}

export interface WorkflowOutputVersioning {
  enabled: boolean;
  versionRef?: string;
  hash?: string;
}

export interface WorkflowOutputNodeConfig {
  format: WorkflowOutputFormat;
  schema?: WorkflowJsonSchema;
  rendererRef?: WorkflowRendererRef;
  materialization?: WorkflowMaterializationConfig;
  deliveryTarget?: WorkflowDeliveryTarget;
  retentionPolicy?: WorkflowOutputRetentionPolicy;
  versioning?: WorkflowOutputVersioning;
  sideEffectClass?: WorkflowSideEffectClass;
}

export interface WorkflowMaterializedAsset {
  id: string;
  nodeId: string;
  assetKind: NonNullable<WorkflowMaterializationConfig["assetKind"]>;
  path?: string;
  hash?: string;
  createdAtMs: number;
}

export interface WorkflowOutputBundle {
  id: string;
  nodeId: string;
  format: WorkflowOutputFormat | string;
  value: unknown;
  rendererRef?: WorkflowRendererRef;
  materializedAssets?: WorkflowMaterializedAsset[];
  deliveryTarget?: WorkflowDeliveryTarget;
  dependencyRefs?: string[];
  evidenceRefs?: string[];
  version?: WorkflowOutputVersioning;
  createdAtMs: number;
}

export interface WorkflowFunctionRef {
  runtime: "javascript" | "typescript";
  entrypoint: string;
  sourcePath: string;
  codeHash?: string;
  dependencyManifest?: Record<string, unknown>;
  inputSchema?: WorkflowJsonSchema;
  outputSchema?: WorkflowJsonSchema;
  fixtureSet?: unknown[];
  sandboxPolicy?: WorkflowSandboxPolicy;
}

export interface WorkflowModelBinding {
  modelRef: string;
  mockBinding: boolean;
  capabilityScope: string[];
  argumentSchema?: WorkflowJsonSchema;
  resultSchema?: WorkflowJsonSchema;
  sideEffectClass: WorkflowSideEffectClass;
  requiresApproval: boolean;
  credentialReady?: boolean;
  toolUseMode?: "none" | "explicit" | "auto";
}

export interface WorkflowParserBinding {
  parserRef: string;
  parserKind: "json_schema" | "structured_output" | "text";
  resultSchema?: WorkflowJsonSchema;
  mockBinding?: boolean;
}

export interface WorkflowTriggerConfig {
  triggerKind: "manual" | "scheduled" | "event";
  schedule?: string;
  eventSourceRef?: string;
  dedupeKey?: string;
}

export interface WorkflowStateOperation {
  key: string;
  operation: "read" | "write" | "append" | "merge";
  reducer: "replace" | "append" | "merge";
  initialValue?: unknown;
}

export interface WorkflowSubgraphRef {
  workflowPath: string;
  inputMapping?: Record<string, string>;
  outputMapping?: Record<string, string>;
}

export interface WorkflowProposalAction {
  actionKind: "create" | "preview" | "apply";
  boundedTargets: string[];
  requiresApproval: boolean;
}

export type WorkflowPortDataType =
  | "none"
  | "payload"
  | "prompt"
  | "message"
  | "request"
  | "response"
  | "args"
  | "result"
  | "branch"
  | "decision"
  | "approval"
  | "state"
  | "run"
  | "output_bundle"
  | "test_result"
  | "proposal";

export type WorkflowConnectionClass =
  | "control"
  | "data"
  | "model"
  | "memory"
  | "tool"
  | "parser"
  | "state"
  | "approval"
  | "error"
  | "retry"
  | "delivery"
  | "subgraph";

export interface WorkflowPortDefinition {
  id: string;
  label: string;
  direction: "input" | "output";
  dataType: WorkflowPortDataType;
  connectionClass: WorkflowConnectionClass;
  cardinality: "one" | "many";
  required: boolean;
  semanticRole:
    | "input"
    | "context"
    | "output"
    | "error"
    | "retry"
    | "branch"
    | "approval"
    | "delivery"
    | "model"
    | "tool"
    | "parser"
    | "state"
    | "proposal"
    | "memory"
    | "subgraph"
    | "trigger";
  connectableNodeKinds?: WorkflowNodeKind[];
}

export type WorkflowNodeFamily =
  | "sources"
  | "triggers"
  | "functions"
  | "models"
  | "tools"
  | "connectors"
  | "state"
  | "flow_control"
  | "gates"
  | "outputs"
  | "tests"
  | "proposals"
  | "subgraphs";

export interface WorkflowPolicyProfile {
  sideEffectClass: WorkflowSideEffectClass;
  requiresApproval: boolean;
  sandboxed: boolean;
  privilegedBoundary?: boolean;
}

export interface WorkflowEvidenceProfile {
  requiredEvidence: Array<WorkflowVerificationEvidence["evidenceType"]>;
  completionRequirements: Array<WorkflowCompletionRequirement["requirementType"]>;
}

export interface WorkflowNodeConfigBase<TKind extends WorkflowNodeKind, TLogic extends NodeLogic = NodeLogic> {
  kind?: TKind;
  logic: TLogic;
  law: FirewallPolicy;
}

export type WorkflowNodeConfig =
  | WorkflowNodeConfigBase<"source">
  | WorkflowNodeConfigBase<"trigger">
  | WorkflowNodeConfigBase<"task_state">
  | WorkflowNodeConfigBase<"uncertainty_gate">
  | WorkflowNodeConfigBase<"probe">
  | WorkflowNodeConfigBase<"budget_gate">
  | WorkflowNodeConfigBase<"capability_sequence">
  | WorkflowNodeConfigBase<"function">
  | WorkflowNodeConfigBase<"model_binding">
  | WorkflowNodeConfigBase<"model_call">
  | WorkflowNodeConfigBase<"parser">
  | WorkflowNodeConfigBase<"adapter">
  | WorkflowNodeConfigBase<"plugin_tool">
  | WorkflowNodeConfigBase<"dry_run">
  | WorkflowNodeConfigBase<"state">
  | WorkflowNodeConfigBase<"decision">
  | WorkflowNodeConfigBase<"loop">
  | WorkflowNodeConfigBase<"barrier">
  | WorkflowNodeConfigBase<"subgraph">
  | WorkflowNodeConfigBase<"human_gate">
  | WorkflowNodeConfigBase<"semantic_impact">
  | WorkflowNodeConfigBase<"postcondition_synthesis">
  | WorkflowNodeConfigBase<"verifier">
  | WorkflowNodeConfigBase<"drift_detector">
  | WorkflowNodeConfigBase<"quality_ledger">
  | WorkflowNodeConfigBase<"handoff">
  | WorkflowNodeConfigBase<"gui_harness_validation">
  | WorkflowNodeConfigBase<"output">
  | WorkflowNodeConfigBase<"test_assertion">
  | WorkflowNodeConfigBase<"proposal">;

export interface WorkflowNodeDefinitionContract {
  type: WorkflowNodeKind;
  family: WorkflowNodeFamily;
  label: string;
  ports: WorkflowPortDefinition[];
  configSchema: WorkflowJsonSchema;
  policyProfile: WorkflowPolicyProfile;
  evidenceProfile: WorkflowEvidenceProfile;
  executor: WorkflowNodeExecutor;
}

export interface WorkflowScaffoldDefinition {
  scaffoldId: string;
  nodeType: WorkflowNodeKind;
  family: WorkflowNodeFamily;
  label: string;
  description: string;
  defaultName: string;
  connectionClasses?: WorkflowConnectionClass[];
  relatedNodeTypes?: WorkflowNodeKind[];
  keywords?: string[];
}

export interface WorkflowNodeActionDefinition {
  actionId: string;
  nodeType: WorkflowNodeKind;
  family: WorkflowNodeFamily;
  label: string;
  description: string;
  category: string;
  requiredBinding?: "model" | "function" | "connector" | "tool" | "parser" | "subgraph" | "proposal";
  bindingMode: "none" | "optional" | "required";
  supportsMockBinding: boolean;
  sideEffectClass: WorkflowSideEffectClass;
  requiresApproval: boolean;
  sandboxed: boolean;
  supportsDryRun: boolean;
  schemaRequired: boolean;
  connectionClasses: WorkflowConnectionClass[];
  compatibleNodeTypes: WorkflowNodeKind[];
  keywords: string[];
}

// ============================================
// Graph Topology
// ============================================

export interface Node extends Record<string, unknown> {
  id: string;
  type: string;
  name: string;
  x: number;
  y: number;

  config?: WorkflowNodeConfig;

  schema?: string; // JSON Schema for dynamic tools

  // Execution State (Visual feedback)
  status?: "idle" | "running" | "success" | "error" | "blocked";
  metrics?: { records: number; time: string };
  metricLabel?: string;
  metricValue?: string;
  
  inputs?: string[];
  outputs?: string[];
  ports?: WorkflowPortDefinition[];
  ioTypes?: { in: string; out: string };
  runtimeBinding?: WorkflowHarnessNodeBinding;
  
  isGhost?: boolean;
  attested?: boolean;
}

export interface Edge {
  id: string;
  from: string;
  to: string;
  fromPort: string;
  toPort: string;
  type: "data" | "control";
  connectionClass?: WorkflowConnectionClass;
  label?: string;
  active?: boolean;
  volume?: number;
  data?: Record<string, unknown>;
}

// ============================================
// File Format
// ============================================

export type GraphCapabilityId =
  | "reasoning"
  | "vision"
  | "embedding"
  | "image"
  | "speech"
  | "video";

export interface GraphCapabilityRequirement {
  required?: boolean;
  bindingKey?: string;
  notes?: string;
}

export interface GraphGlobalConfig {
  env: string;
  environmentProfile?: GraphEnvironmentProfile;
  modelBindings: Record<string, GraphModelBinding>;
  requiredCapabilities: Record<string, GraphCapabilityRequirement>;
  policy: {
    maxBudget: number;
    maxSteps: number;
    timeoutMs: number;
  };
  contract: {
    developerBond: number;
    adjudicationRubric: string;
    validationSchema?: string;
  };
  meta: {
    name: string;
    description: string;
  };
  production?: GraphProductionProfile;
}

export type GraphEnvironmentTarget = "local" | "sandbox" | "staging" | "production";

export type GraphMockBindingPolicy = "allow" | "warn" | "block";

export interface GraphEnvironmentProfile {
  target: GraphEnvironmentTarget;
  credentialScope?: string;
  mockBindingPolicy?: GraphMockBindingPolicy;
}

export type WorkflowBindingCheckStatus = "passed" | "blocked" | "warning";

export interface WorkflowBindingCheckResult {
  id: string;
  rowId: string;
  nodeId: string;
  bindingKind: string;
  reference: string;
  mode: "mock" | "live" | "local";
  status: WorkflowBindingCheckStatus;
  summary: string;
  detail: string;
  createdAtMs: number;
}

export interface WorkflowBindingManifestEntry {
  id: string;
  nodeId: string;
  nodeName: string;
  nodeType: WorkflowNodeKind | string;
  bindingKind: string;
  reference: string;
  mode: "mock" | "live" | "local";
  credentialReady: boolean;
  mockBinding: boolean;
  sideEffectClass: string;
  requiresApproval: boolean;
  capabilityScope: string[];
  status: WorkflowBindingCheckStatus;
  statusReason: string;
}

export interface WorkflowBindingManifestSummary {
  total: number;
  live: number;
  mock: number;
  local: number;
  ready: number;
  blocked: number;
  approvalRequired: number;
}

export interface WorkflowBindingManifest {
  schemaVersion: "workflow.bindings.v1" | string;
  workflowId: string;
  workflowSlug: string;
  generatedAtMs: number;
  environmentProfile: GraphEnvironmentProfile;
  bindings: WorkflowBindingManifestEntry[];
  summary: WorkflowBindingManifestSummary;
}

export interface GraphModelBinding {
  modelId: string;
  modelHash?: string;
  required?: boolean;
}

export interface GraphProductionProfile {
  errorWorkflowPath?: string;
  evaluationSetPath?: string;
  expectedTimeSavedMinutes?: number;
  mcpAccessReviewed?: boolean;
  requireReplayFixtures?: boolean;
}

export interface ProjectFile {
  version: string;
  nodes: Node[];
  edges: Edge[];
  global_config: GraphGlobalConfig;
  metadata?: WorkflowProjectMetadata;
  tests?: WorkflowTestCase[];
  proposals?: WorkflowProposal[];
  runs?: WorkflowRunSummary[];
}

export interface AgentConfiguration {
  name: string;
  description: string;
  instructions: string;
  model: string;
  temperature: number;
  tools: { id: string; name: string; desc: string; icon: string }[];
}

export type WorkflowKind =
  | "agent_workflow"
  | "scheduled_workflow"
  | "event_workflow"
  | "evaluation_workflow";

export type WorkflowExecutionMode = "local" | "external_adapter" | "hybrid";

export type WorkflowHarnessComponentKind =
  | "planner"
  | "task_state"
  | "uncertainty_gate"
  | "probe_runner"
  | "budget_gate"
  | "capability_sequencer"
  | "model_router"
  | "model_call"
  | "tool_router"
  | "tool_call"
  | "dry_run_simulator"
  | "mcp_provider"
  | "mcp_tool_call"
  | "connector_call"
  | "policy_gate"
  | "approval_gate"
  | "wallet_capability"
  | "memory_read"
  | "memory_write"
  | "verifier"
  | "semantic_impact_analyzer"
  | "postcondition_synthesizer"
  | "drift_detector"
  | "quality_ledger"
  | "handoff_bridge"
  | "gui_harness_validator"
  | "output_writer"
  | "receipt_writer"
  | "retry_policy"
  | "repair_loop"
  | "merge_judge"
  | "completion_gate";

export type WorkflowHarnessSlotKind =
  | "model_policy"
  | "tool_grant_policy"
  | "state_policy"
  | "budget_policy"
  | "dry_run_policy"
  | "verifier_policy"
  | "approval_policy"
  | "output_policy"
  | "memory_policy"
  | "quality_ledger_policy"
  | "handoff_policy"
  | "retry_repair_policy";

export interface WorkflowHarnessRetryBehavior {
  maxAttempts: number;
  backoffMs: number;
  retryableErrors: string[];
}

export interface WorkflowHarnessTimeoutBehavior {
  timeoutMs: number;
  cancellation: "cooperative" | "hard" | "none";
}

export interface WorkflowHarnessApprovalSemantics {
  required: boolean;
  mode: "none" | "policy_gate" | "human_gate" | "wallet_capability";
  reason: string;
}

export interface WorkflowHarnessComponentSpec {
  componentId: string;
  version: string;
  kind: WorkflowHarnessComponentKind;
  label: string;
  description: string;
  kernelRef: string;
  inputSchema: unknown;
  outputSchema: unknown;
  errorSchema: unknown;
  timeout: WorkflowHarnessTimeoutBehavior;
  retry: WorkflowHarnessRetryBehavior;
  requiredCapabilityScope: string[];
  approval: WorkflowHarnessApprovalSemantics;
  emittedEvents: string[];
  evidence: string[];
  ui: {
    icon: string;
    group: string;
    summary: string;
  };
}

export interface WorkflowHarnessSlotSpec {
  slotId: string;
  kind: WorkflowHarnessSlotKind;
  label: string;
  description: string;
  required: boolean;
  allowedComponentKinds: WorkflowHarnessComponentKind[];
  defaultComponentId?: string;
  validation: {
    blocksActivation: boolean;
    reason: string;
  };
}

export interface WorkflowHarnessNodeBinding {
  componentId: string;
  componentVersion: string;
  componentKind: WorkflowHarnessComponentKind;
  kernelRef: string;
  slotIds?: string[];
  evidenceEventKinds: string[];
  receiptKinds: string[];
  replay: {
    deterministicEnvelope: boolean;
    capturesInput: boolean;
    capturesOutput: boolean;
    capturesPolicyDecision: boolean;
  };
}

export interface WorkflowHarnessMetadata {
  schemaVersion: "workflow.harness.v1" | string;
  harnessWorkflowId: string;
  harnessVersion: string;
  harnessHash: string;
  templateName: string;
  blessed: boolean;
  forkable: boolean;
  forkedFrom?: {
    harnessWorkflowId: string;
    harnessVersion: string;
    harnessHash: string;
  };
  packageName?: string;
  activationId?: string;
  activationState?: "read_only" | "draft" | "blocked" | "validated" | "active";
  validationGates: string[];
  aiMutationMode: "proposal_only";
  componentIds: string[];
  slotIds: string[];
}

export interface WorkflowHarnessWorkerBinding {
  harnessWorkflowId: string;
  harnessActivationId?: string;
  harnessHash: string;
  source: "default" | "fork" | "legacy";
}

export type WorkflowNodeKind =
  | "source"
  | "trigger"
  | "task_state"
  | "uncertainty_gate"
  | "probe"
  | "budget_gate"
  | "capability_sequence"
  | "function"
  | "model_binding"
  | "model_call"
  | "parser"
  | "adapter"
  | "plugin_tool"
  | "dry_run"
  | "state"
  | "decision"
  | "loop"
  | "barrier"
  | "subgraph"
  | "human_gate"
  | "semantic_impact"
  | "postcondition_synthesis"
  | "verifier"
  | "drift_detector"
  | "quality_ledger"
  | "handoff"
  | "gui_harness_validation"
  | "output"
  | "test_assertion"
  | "proposal";

export type WorkflowWorkbenchTab = "graph" | "proposals" | "executions";

export type WorkflowRightPanel =
  | "outputs"
  | "unit_tests"
  | "sources"
  | "search"
  | "changes"
  | "runs"
  | "readiness"
  | "schedules"
  | "files"
  | "settings";

export type WorkflowBottomPanel =
  | "selection"
  | "data"
  | "suggestions"
  | "warnings"
  | "fixtures"
  | "checkpoints"
  | "proposal_diff"
  | "test_output"
  | "run_output";

export interface WorkflowProjectMetadata {
  id: string;
  name: string;
  slug: string;
  workflowKind: WorkflowKind;
  executionMode: WorkflowExecutionMode;
  gitLocation?: string;
  branch?: string;
  dirty?: boolean;
  readOnly?: boolean;
  harness?: WorkflowHarnessMetadata;
  workerHarnessBinding?: WorkflowHarnessWorkerBinding;
  createdAtMs?: number;
  updatedAtMs?: number;
}

export interface WorkflowProject extends ProjectFile {
  metadata: WorkflowProjectMetadata;
}

export interface WorkflowNode extends Node {
  type: WorkflowNodeKind;
}

export type WorkflowEdge = Edge;

export type WorkflowTestStatus = "idle" | "passed" | "failed" | "blocked" | "skipped";

export interface WorkflowTestCase {
  id: string;
  name: string;
  targetNodeIds: string[];
  targetSubgraphId?: string;
  assertion: WorkflowTestAssertion;
  status?: WorkflowTestStatus;
  lastMessage?: string;
}

export interface WorkflowNodeFixture {
  id: string;
  nodeId: string;
  name: string;
  input?: unknown;
  output?: unknown;
  schemaHash?: string;
  nodeConfigHash?: string;
  sourceRunId?: string;
  pinned?: boolean;
  stale?: boolean;
  validationStatus?: "passed" | "failed" | "not_declared" | "stale";
  validationMessage?: string;
  createdAtMs: number;
}

export interface WorkflowTestRunResult {
  runId: string;
  status: WorkflowTestStatus;
  startedAtMs: number;
  finishedAtMs: number;
  passed: number;
  failed: number;
  blocked: number;
  skipped: number;
  results: Array<{
    testId: string;
    status: WorkflowTestStatus;
    message: string;
    coveredNodeIds: string[];
  }>;
}

export interface WorkflowProposal {
  id: string;
  title: string;
  summary: string;
  status: "open" | "applied" | "rejected";
  createdAtMs: number;
  boundedTargets: string[];
  graphDiff?: {
    addedNodeIds?: string[];
    removedNodeIds?: string[];
    changedNodeIds?: string[];
  };
  configDiff?: {
    changedNodeIds?: string[];
    changedGlobalKeys?: string[];
    changedMetadataKeys?: string[];
  };
  sidecarDiff?: {
    testsChanged?: boolean;
    fixturesChanged?: boolean;
    functionsChanged?: boolean;
    bindingsChanged?: boolean;
    proposalsChanged?: boolean;
    changedRoles?: string[];
  };
  codeDiff?: string;
  workflowPatch?: WorkflowProject;
}

export type WorkflowRunStatus =
  | "queued"
  | "running"
  | "passed"
  | "failed"
  | "blocked"
  | "interrupted";

export interface WorkflowRunSummary {
  id: string;
  threadId?: string;
  status: WorkflowRunStatus;
  startedAtMs: number;
  finishedAtMs?: number;
  nodeCount: number;
  testCount?: number;
  checkpointCount?: number;
  interruptId?: string;
  summary: string;
  evidencePath?: string;
}

export interface WorkflowThread {
  id: string;
  workflowPath: string;
  status: WorkflowRunStatus;
  createdAtMs: number;
  latestCheckpointId?: string;
  input?: unknown;
}

export interface WorkflowStateUpdate {
  nodeId: string;
  key: string;
  value: unknown;
  reducer: "replace" | "append" | "merge";
}

export interface WorkflowStateSnapshot {
  threadId: string;
  checkpointId: string;
  runId: string;
  stepIndex: number;
  values: Record<string, unknown>;
  nodeOutputs: Record<string, unknown>;
  completedNodeIds: string[];
  blockedNodeIds: string[];
  interruptedNodeIds: string[];
  activeNodeIds: string[];
  branchDecisions: Record<string, string>;
  pendingWrites: WorkflowStateUpdate[];
}

export interface WorkflowCheckpoint {
  id: string;
  threadId: string;
  runId: string;
  createdAtMs: number;
  stepIndex: number;
  nodeId?: string;
  status: WorkflowRunStatus;
  summary: string;
}

export interface WorkflowNodeRun {
  nodeId: string;
  nodeType: WorkflowNodeKind | string;
  status: "queued" | "running" | "success" | "error" | "blocked" | "interrupted";
  startedAtMs: number;
  finishedAtMs?: number;
  attempt: number;
  input?: unknown;
  output?: unknown;
  error?: string;
  checkpointId?: string;
  lifecycle?: string[];
}

export interface WorkflowInterrupt {
  id: string;
  runId: string;
  threadId: string;
  nodeId: string;
  status: "pending" | "approved" | "rejected" | "edited";
  createdAtMs: number;
  resolvedAtMs?: number;
  prompt: string;
  allowedOutcomes: Array<"approve" | "reject" | "edit">;
  response?: unknown;
}

export interface WorkflowStreamEvent {
  id: string;
  runId: string;
  threadId: string;
  sequence: number;
  kind:
    | "run_started"
    | "node_started"
    | "node_succeeded"
    | "node_failed"
    | "node_blocked"
    | "node_interrupted"
    | "state_updated"
    | "output_created"
    | "asset_materialized"
    | "test_result"
    | "child_run_completed"
    | "run_completed";
  createdAtMs: number;
  nodeId?: string;
  status?: string;
  message?: string;
  stateDelta?: WorkflowStateUpdate[];
}

export interface WorkflowRunResult {
  summary: WorkflowRunSummary;
  thread: WorkflowThread;
  finalState: WorkflowStateSnapshot;
  nodeRuns: WorkflowNodeRun[];
  checkpoints: WorkflowCheckpoint[];
  events: WorkflowStreamEvent[];
  verificationEvidence: WorkflowVerificationEvidence[];
  completionRequirements: WorkflowCompletionRequirement[];
  interrupt?: WorkflowInterrupt;
}

export interface WorkflowRunNodeComparison {
  nodeId: string;
  baselineStatus?: string;
  targetStatus?: string;
  inputChanged: boolean;
  outputChanged: boolean;
  errorChanged: boolean;
}

export interface WorkflowRunStateComparison {
  key: string;
  change: "added" | "removed" | "changed" | string;
  baselineValue?: unknown;
  targetValue?: unknown;
}

export interface WorkflowRunComparison {
  baselineRunId: string;
  targetRunId: string;
  statusChanged: boolean;
  checkpointDelta: number;
  nodeChanges: WorkflowRunNodeComparison[];
  stateChanges: WorkflowRunStateComparison[];
}

export interface WorkflowResumeRequest {
  runId?: string;
  threadId: string;
  nodeId?: string;
  interruptId?: string;
  checkpointId?: string;
  outcome: "approve" | "reject" | "edit" | "retry" | "repair";
  editedState?: Record<string, unknown>;
}

export interface WorkflowCheckpointForkRequest {
  checkpointId: string;
  name?: string;
  input?: unknown;
}

export interface WorkflowProjectSummary {
  id: string;
  name: string;
  slug: string;
  workflowKind: WorkflowKind;
  executionMode: WorkflowExecutionMode;
  workflowPath: string;
  testsPath: string;
  proposalsDir: string;
  nodeCount: number;
  updatedAtMs?: number;
  branch?: string;
  dirty?: boolean;
}

export interface WorkflowWorkbenchBundle {
  workflowPath: string;
  testsPath: string;
  proposalsDir: string;
  workflow: WorkflowProject;
  tests: WorkflowTestCase[];
  proposals: WorkflowProposal[];
  runs: WorkflowRunSummary[];
}

export interface CreateWorkflowProjectRequest {
  projectRoot: string;
  name: string;
  workflowKind: WorkflowKind;
  executionMode: WorkflowExecutionMode;
  templateId?: string;
}

export interface CreateWorkflowFromTemplateRequest {
  projectRoot: string;
  templateId: string;
  name?: string;
}

export interface CreateWorkflowProposalRequest {
  title: string;
  summary: string;
  boundedTargets: string[];
  workflowPatch?: WorkflowProject;
  codeDiff?: string;
}

export interface WorkflowValidationIssue {
  nodeId?: string;
  code: string;
  message: string;
  repairActionId?: string;
  repairLabel?: string;
  configSection?: string;
  fieldPath?: string;
  suggestedCreatorId?: string;
}

export interface WorkflowValidationResult {
  status: "passed" | "failed" | "blocked";
  errors: WorkflowValidationIssue[];
  warnings: WorkflowValidationIssue[];
  blockedNodes: string[];
  missingConfig: WorkflowValidationIssue[];
  unsupportedRuntimeNodes: string[];
  policyRequiredNodes: string[];
  coverageByNodeId: Record<string, string[]>;
  connectorBindingIssues: WorkflowValidationIssue[];
  executionReadinessIssues?: WorkflowValidationIssue[];
  verificationIssues?: WorkflowValidationIssue[];
}

export interface WorkflowEvidenceSummary {
  id: string;
  kind:
    | "validation"
    | "readiness"
    | "test_run"
    | "run"
    | "proposal"
    | "bundle"
    | "fixture"
    | "package"
    | "binding_check"
    | "binding_manifest";
  createdAtMs: number;
  summary: string;
  path?: string;
}

export interface WorkflowPortablePackageFile {
  role: string;
  relativePath: string;
  bytes: number;
  sha256: string;
}

export interface WorkflowPortablePackageManifest {
  schemaVersion: "workflow.portable-package.v1" | string;
  exportedAtMs: number;
  workflowName: string;
  workflowSlug: string;
  sourceWorkflowPath: string;
  harness?: WorkflowHarnessMetadata;
  workerHarnessBinding?: WorkflowHarnessWorkerBinding;
  readinessStatus: WorkflowValidationResult["status"];
  portable: boolean;
  blockers: WorkflowValidationIssue[];
  files: WorkflowPortablePackageFile[];
}

export interface WorkflowPortablePackage {
  packagePath: string;
  manifestPath: string;
  manifest: WorkflowPortablePackageManifest;
  importedWorkflowPath?: string;
}

export interface ImportWorkflowPackageRequest {
  packagePath: string;
  projectRoot: string;
  name?: string;
}

export interface WorkflowTemplateMetadata {
  templateId: string;
  name: string;
  description: string;
  workflowKind: WorkflowKind;
  executionMode: WorkflowExecutionMode;
  requiredConnectors: string[];
  optionalConnectors: string[];
  guardrailProfile: string;
  seedNodes: WorkflowNode[];
  seedEdges: WorkflowEdge[];
  seedTests: WorkflowTestCase[];
}

export interface WorkflowDogfoodRun {
  id: string;
  suiteId: string;
  startedAtMs: number;
  finishedAtMs?: number;
  status: "passed" | "failed" | "blocked";
  outputDir: string;
  workflowPaths: string[];
  gapLedgerPath: string;
}

export interface WorkflowGapLedgerEntry {
  id: string;
  workflowId: string;
  severity: "info" | "warning" | "blocking";
  area: "gui" | "runtime" | "validation" | "sandbox" | "proposal";
  summary: string;
  status: "open" | "closed";
}
