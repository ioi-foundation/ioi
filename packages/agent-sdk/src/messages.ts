import type { StopReason } from "./options.js";

export type IOISDKMessageType =
  | "thread_forked"
  | "run_started"
  | "model_route_decision"
  | "memory_update"
  | "step"
  | "delta"
  | "tool_call"
  | "tool_result"
  | "task_state"
  | "uncertainty"
  | "probe"
  | "postcondition_synthesized"
  | "semantic_impact"
  | "stop_condition"
  | "quality_ledger"
  | "artifact"
  | "completed"
  | "canceled"
  | "interrupted"
  | "steered"
  | "context_compacted"
  | "error";

export interface IOISDKMessage {
  id: string;
  runId: string;
  agentId: string;
  type: IOISDKMessageType;
  cursor: string;
  createdAt: string;
  summary: string;
  data?: unknown;
}

export interface ConversationMessage {
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  eventId?: string;
  createdAt?: string;
}

export const RUNTIME_TTI_SCHEMA_VERSIONS = {
  thread: "ioi.runtime.thread.v1",
  turn: "ioi.runtime.turn.v1",
  item: "ioi.runtime.item.v1",
  event: "ioi.runtime.event.v1",
} as const;

export const RUNTIME_TTI_SCHEMA_VERSION_LITERALS = [
  RUNTIME_TTI_SCHEMA_VERSIONS.thread,
  RUNTIME_TTI_SCHEMA_VERSIONS.turn,
  RUNTIME_TTI_SCHEMA_VERSIONS.item,
  RUNTIME_TTI_SCHEMA_VERSIONS.event,
] as const;

export const RUNTIME_THREAD_MODES = ["plan", "agent", "yolo", "custom"] as const;
export const RUNTIME_APPROVAL_MODES = [
  "suggest",
  "auto_local",
  "never_prompt",
  "human_required",
  "policy_required",
] as const;
export const RUNTIME_THREAD_STATUSES = [
  "active",
  "idle",
  "waiting",
  "interrupted",
  "completed",
  "failed",
  "archived",
] as const;
export const RUNTIME_TURN_STATUSES = [
  "queued",
  "running",
  "waiting_for_approval",
  "waiting_for_input",
  "interrupted",
  "completed",
  "failed",
  "canceled",
] as const;
export const RUNTIME_ITEM_KINDS = [
  "user_message",
  "agent_message",
  "reasoning_delta",
  "tool_call",
  "tool_result",
  "file_change",
  "command_execution",
  "approval_required",
  "approval_decision",
  "context_compaction",
  "lsp_diagnostics",
  "memory_update",
  "subagent_event",
  "rollback_snapshot",
  "status",
  "error",
] as const;
export const RUNTIME_ITEM_STATUSES = [
  "pending",
  "running",
  "completed",
  "failed",
  "interrupted",
  "canceled",
  "blocked",
] as const;
export const RUNTIME_ITEM_ACTORS = [
  "user",
  "assistant",
  "tool",
  "runtime",
  "policy",
  "system",
] as const;
export const RUNTIME_EVENT_SOURCES = [
  "runtime_service",
  "daemon_bridge",
  "sdk_client",
  "cli_tui",
  "react_flow",
  "runtime_auto",
  "fixture",
] as const;

export type RuntimeThreadMode = (typeof RUNTIME_THREAD_MODES)[number];
export type RuntimeApprovalMode = (typeof RUNTIME_APPROVAL_MODES)[number];
export type RuntimeThreadStatus = (typeof RUNTIME_THREAD_STATUSES)[number];
export type RuntimeTurnStatus = (typeof RUNTIME_TURN_STATUSES)[number];
export type RuntimeItemKind = (typeof RUNTIME_ITEM_KINDS)[number];
export type RuntimeItemStatus = (typeof RUNTIME_ITEM_STATUSES)[number];
export type RuntimeItemActor = (typeof RUNTIME_ITEM_ACTORS)[number];
export type RuntimeEventSource = (typeof RUNTIME_EVENT_SOURCES)[number];

export const RUNTIME_THREAD_EVENT_TYPES = [
  "thread_started",
  "thread_forked",
  "turn_started",
  "turn_completed",
  "turn_failed",
  "turn_canceled",
  "turn_interrupted",
  "turn_steered",
  "context_compacted",
  "reasoning_delta",
  "tool_completed",
  "tool_failed",
  "approval_required",
  "policy_blocked",
  "receipt_emitted",
  "model_route_decision",
  "tool_route_decision",
  "runtime_step",
] as const;

export type RuntimeThreadEventType = (typeof RUNTIME_THREAD_EVENT_TYPES)[number];

export interface RuntimeUsageRecord {
  input_tokens: number;
  output_tokens: number;
  reasoning_tokens: number;
  cached_input_tokens: number;
  tool_result_tokens: number;
  compacted_tokens: number;
  estimated_cost_micros: number;
  provider: string;
  model: string;
  latency_ms: number;
}

export interface RuntimeThreadRecord {
  schema_version: typeof RUNTIME_TTI_SCHEMA_VERSIONS.thread;
  thread_id: string;
  session_id: string;
  agent_id: string;
  workspace_root: string;
  title: string;
  mode: RuntimeThreadMode;
  approval_mode: RuntimeApprovalMode;
  trust_profile: string;
  model_route: string;
  status: RuntimeThreadStatus;
  latest_turn_id: string | null;
  latest_seq: number;
  event_stream_id: string;
  workflow_graph_id: string | null;
  harness_binding_id: string | null;
  agentgres_projection_ref: string | null;
  created_at: string;
  updated_at: string;
  archived_at: string | null;
  fixture_profile: string | null;
  requested_model?: string | null;
  selected_model?: string | null;
  model_route_id?: string | null;
  model_route_receipt_id?: string | null;
  model_route_decision?: ModelRouteDecision | null;
  reasoning_effort?: string | null;
  runtime_controls?: RuntimeThreadControls | null;
}

export interface RuntimeThreadControls {
  schemaVersion?: string;
  schema_version?: string;
  mode: RuntimeThreadMode;
  approvalMode?: RuntimeApprovalMode;
  approval_mode?: RuntimeApprovalMode;
  model?: {
    id?: string | null;
    routeId?: string | null;
    route_id?: string | null;
    selectedModel?: string | null;
    selected_model?: string | null;
    endpointId?: string | null;
    providerId?: string | null;
    receiptId?: string | null;
    reasoningEffort?: string | null;
    reasoning_effort?: string | null;
    privacy?: string | null;
    maxCostUsd?: number | null;
    allowHostedFallback?: boolean | null;
    workflowGraphId?: string | null;
    workflowNodeId?: string | null;
    updatedAt?: string | null;
  };
  updatedAt?: string | null;
}

export interface RuntimeTurnRecord {
  schema_version: typeof RUNTIME_TTI_SCHEMA_VERSIONS.turn;
  turn_id: string;
  thread_id: string;
  parent_turn_id: string | null;
  request_id: string;
  status: RuntimeTurnStatus;
  input_item_ids: string[];
  output_item_ids: string[];
  seq_start: number | null;
  seq_end: number | null;
  started_at: string;
  completed_at: string | null;
  mode: RuntimeThreadMode;
  approval_mode: RuntimeApprovalMode;
  model_route_decision_id: string | null;
  usage: RuntimeUsageRecord | null;
  stop_reason: string | null;
  error: string | null;
  rollback_snapshot_id: string | null;
  quality_ledger_ref: string | null;
  workflow_execution_ref: string | null;
  fixture_profile: string | null;
}

export interface RuntimeItemRecord {
  schema_version: typeof RUNTIME_TTI_SCHEMA_VERSIONS.item;
  item_id: string;
  thread_id: string;
  turn_id: string;
  kind: RuntimeItemKind;
  status: RuntimeItemStatus;
  seq_start: number | null;
  seq_end: number | null;
  actor: RuntimeItemActor;
  summary: string;
  content_ref: string | null;
  tool_name: string | null;
  component_kind: string | null;
  workflow_node_id: string | null;
  receipt_refs: string[];
  artifact_refs: string[];
  approval_id: string | null;
  policy_decision_id: string | null;
  rollback_snapshot_id: string | null;
  redaction_profile: string;
  payload_schema_version: string;
}

export interface RuntimeEventEnvelope {
  schema_version: typeof RUNTIME_TTI_SCHEMA_VERSIONS.event;
  event_id: string;
  event_stream_id: string;
  thread_id: string;
  turn_id: string;
  item_id: string;
  seq: number;
  parent_seq: number | null;
  idempotency_key: string;
  source: RuntimeEventSource;
  source_event_kind: string;
  event_kind: string;
  status: string;
  actor: RuntimeItemActor;
  created_at: string;
  workspace_root: string;
  workflow_graph_id: string | null;
  workflow_node_id: string | null;
  component_kind: string | null;
  tool_call_id: string | null;
  approval_id: string | null;
  artifact_refs: string[];
  receipt_refs: string[];
  policy_decision_refs: string[];
  rollback_refs: string[];
  payload_schema_version: string;
  payload_ref: string | null;
  payload: Record<string, string>;
  redaction_profile: string;
  fixture_profile: string | null;
}

export interface RuntimeThreadEvent {
  id: string;
  cursor: string;
  seq: number;
  threadId: string;
  turnId: string | null;
  itemId: string | null;
  type: RuntimeThreadEventType;
  eventKind: string;
  source: RuntimeEventSource | string;
  sourceEventKind: string;
  status: string;
  actor: RuntimeItemActor | string;
  createdAt: string;
  componentKind: string | null;
  workflowNodeId: string | null;
  workflowGraphId: string | null;
  toolCallId: string | null;
  toolName: string | null;
  approvalId: string | null;
  agentStatus: string | null;
  stepIndex: number | null;
  payloadSchemaVersion: string;
  receiptRefs: string[];
  artifactRefs: string[];
  policyDecisionRefs: string[];
  rollbackRefs: string[];
  payload: Record<string, unknown>;
  envelope: RuntimeEventEnvelope;
}

export interface RuntimeTraceBundle {
  schemaVersion: "ioi.agent-sdk.trace.v1";
  traceBundleId: string;
  agentId: string;
  runId: string;
  eventStreamId: string;
  events: IOISDKMessage[];
  receipts: RuntimeReceipt[];
  taskState: TaskStateProjection;
  uncertainty: UncertaintyProjection;
  probes: ProbeProjection[];
  postconditions: PostconditionProjection;
  semanticImpact: SemanticImpactProjection;
  modelRouteDecision?: ModelRouteDecision | null;
  memoryPolicy?: AgentMemoryPolicy | null;
  memoryRecords?: AgentMemoryRecord[];
  memoryWrites?: AgentMemoryRecord[];
  subagentMemoryInheritance?: SubagentMemoryInheritanceProjection | null;
  stopCondition: StopConditionProjection;
  qualityLedger: AgentQualityLedgerProjection;
  scorecard: RuntimeScorecard;
}

export interface RuntimeAccountProfile {
  id: string;
  email?: string | null;
  authorityLevel: "local" | "operator" | "admin" | "hosted";
  privacyClass: "local_private" | "workspace" | "hosted" | "external";
  source: string;
}

export interface RuntimeNodeProfile {
  id: string;
  kind: "local" | "hosted" | "self_hosted" | "tee" | "depin";
  status: "available" | "unavailable" | "blocked";
  endpoint?: string;
  privacyClass: "local_private" | "workspace" | "hosted" | "external";
  evidenceRefs: string[];
}

export interface RuntimeToolCatalogEntry {
  schemaVersion?: string;
  stableToolId: string;
  displayName: string;
  pack?: string;
  primitiveCapabilities: string[];
  authorityScopeRequirements: string[];
  effectClass: string;
  riskDomain: string;
  inputSchema: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
  evidenceRequirements: string[];
  workflowNodeType?: string;
  workflowConfigFields?: string[];
}

export interface RuntimeMcpServerEntry {
  schema_version?: string;
  schemaVersion?: string;
  id: string;
  label?: string;
  name?: string;
  enabled?: boolean;
  status: string;
  transport: string;
  command?: string | null;
  args?: string[];
  server_url?: string | null;
  serverUrl?: string | null;
  source?: string;
  source_path?: string | null;
  sourcePath?: string | null;
  workspace_root?: string | null;
  workspaceRoot?: string | null;
  allowed_tools?: string[];
  allowedTools?: string[];
  tool_count?: number;
  toolCount?: number;
  resources?: RuntimeMcpResourceEntry[];
  resource_count?: number;
  resourceCount?: number;
  prompts?: RuntimeMcpPromptEntry[];
  prompt_count?: number;
  promptCount?: number;
  containment?: Record<string, unknown>;
  secret_refs?: Record<string, unknown>;
  secretRefs?: Record<string, unknown>;
  health?: Record<string, unknown>;
  evidence_refs?: string[];
  evidenceRefs?: string[];
}

export interface RuntimeMcpToolEntry extends RuntimeToolCatalogEntry {
  server_id?: string;
  serverId?: string;
  server_label?: string;
  serverLabel?: string;
  tool_name?: string;
  toolName?: string;
  status?: string;
  transport?: string;
  workflow_node_id?: string;
  workflowNodeId?: string;
}

export interface RuntimeMcpResourceEntry {
  schema_version?: string;
  schemaVersion?: string;
  stableResourceId?: string;
  stable_resource_id?: string;
  displayName?: string;
  display_name?: string;
  pack?: string;
  server_id?: string;
  serverId?: string;
  server_label?: string;
  serverLabel?: string;
  uri: string;
  name?: string;
  description?: string | null;
  mimeType?: string | null;
  mime_type?: string | null;
  status?: string;
  transport?: string;
  workflowNodeType?: string;
  workflow_node_id?: string;
  workflowNodeId?: string;
}

export interface RuntimeMcpPromptEntry {
  schema_version?: string;
  schemaVersion?: string;
  stablePromptId?: string;
  stable_prompt_id?: string;
  displayName?: string;
  display_name?: string;
  pack?: string;
  server_id?: string;
  serverId?: string;
  server_label?: string;
  serverLabel?: string;
  name: string;
  description?: string | null;
  arguments?: unknown[];
  prompt_arguments?: unknown[];
  promptArguments?: unknown[];
  status?: string;
  transport?: string;
  workflowNodeType?: string;
  workflow_node_id?: string;
  workflowNodeId?: string;
}

export interface RuntimeMcpValidationIssue {
  code: string;
  severity: "error" | "warning" | string;
  server_id?: string;
  serverId?: string;
  key?: string;
  message: string;
}

export interface RuntimeMcpValidationResult {
  schema_version?: string;
  schemaVersion?: string;
  object?: "ioi.runtime_mcp_manager_validation" | string;
  ok: boolean;
  status?: string;
  server_count?: number;
  serverCount?: number;
  tool_count?: number;
  toolCount?: number;
  resource_count?: number;
  resourceCount?: number;
  prompt_count?: number;
  promptCount?: number;
  issue_count?: number;
  issueCount?: number;
  warning_count?: number;
  warningCount?: number;
  issues: RuntimeMcpValidationIssue[];
  warnings: RuntimeMcpValidationIssue[];
  servers?: RuntimeMcpServerEntry[];
  tools?: RuntimeMcpToolEntry[];
  resources?: RuntimeMcpResourceEntry[];
  prompts?: RuntimeMcpPromptEntry[];
  event?: RuntimeEventEnvelope;
}

export interface RuntimeMcpInvocationRecord {
  schema_version?: string;
  schemaVersion?: string;
  object?: "ioi.runtime_mcp_tool_invocation" | string;
  tool_call_id: string;
  toolCallId?: string;
  thread_id?: string;
  threadId?: string;
  agent_id?: string;
  agentId?: string;
  server_id: string;
  serverId?: string;
  tool_name: string;
  toolName?: string;
  status: string;
  input_hash?: string;
  inputHash?: string;
  output_hash?: string;
  outputHash?: string;
  side_effect_class?: string;
  sideEffectClass?: string;
  requires_approval?: boolean;
  requiresApproval?: boolean;
  approval_mode?: string;
  approvalMode?: string;
  approved?: boolean;
  blockers?: string[];
  transport?: string;
  transport_execution?: Record<string, unknown> | null;
  transportExecution?: Record<string, unknown> | null;
  containment?: Record<string, unknown>;
  result?: Record<string, unknown> | null;
  evidence_refs?: string[];
  evidenceRefs?: string[];
}

export interface RuntimeMcpInvocationResult extends RuntimeMcpInvocationRecord {
  event_kind?: string;
  control_kind?: string;
  server?: RuntimeMcpServerEntry;
  servers?: RuntimeMcpServerEntry[];
  tool?: RuntimeMcpToolEntry;
  tools?: RuntimeMcpToolEntry[];
  invocation?: RuntimeMcpInvocationRecord;
  summary?: string;
  receipt_refs?: string[];
  receiptRefs?: string[];
  policy_decision_refs?: string[];
  policyDecisionRefs?: string[];
  event?: RuntimeEventEnvelope;
}

export interface RuntimeMcpStatus {
  schema_version?: string;
  schemaVersion?: string;
  object?: "ioi.runtime_mcp_manager_status" | string;
  status: string;
  server_count: number;
  serverCount?: number;
  tool_count: number;
  toolCount?: number;
  resource_count?: number;
  resourceCount?: number;
  prompt_count?: number;
  promptCount?: number;
  enabled_server_count?: number;
  enabledServerCount?: number;
  servers: RuntimeMcpServerEntry[];
  tools: RuntimeMcpToolEntry[];
  resources?: RuntimeMcpResourceEntry[];
  prompts?: RuntimeMcpPromptEntry[];
  validation?: RuntimeMcpValidationResult;
  routes?: Record<string, string>;
  event?: RuntimeEventEnvelope;
}

export interface RuntimeMemoryValidationIssue {
  code: string;
  severity: "error" | "warning" | string;
  message: string;
  memory_record_id?: string | null;
  memoryRecordId?: string | null;
  memory_scope?: string | null;
  memoryScope?: string | null;
  path?: string;
}

export interface RuntimeMemoryValidationResult {
  schema_version?: string;
  schemaVersion?: string;
  object?: "ioi.runtime_memory_manager_validation" | string;
  ok: boolean;
  status?: string;
  issue_count?: number;
  issueCount?: number;
  warning_count?: number;
  warningCount?: number;
  record_count?: number;
  recordCount?: number;
  thread_id?: string | null;
  threadId?: string | null;
  agent_id?: string | null;
  agentId?: string | null;
  workspace?: string | null;
  issues: RuntimeMemoryValidationIssue[];
  warnings: RuntimeMemoryValidationIssue[];
  policy?: AgentMemoryPolicy;
  paths?: unknown;
  filters?: unknown;
  records?: AgentMemoryRecord[];
  event?: RuntimeEventEnvelope;
}

export interface RuntimeMemoryStatus {
  schema_version?: string;
  schemaVersion?: string;
  object?: "ioi.runtime_memory_manager_status" | string;
  status: string;
  disabled?: boolean;
  injection_enabled?: boolean;
  injectionEnabled?: boolean;
  read_only?: boolean;
  readOnly?: boolean;
  write_requires_approval?: boolean;
  writeRequiresApproval?: boolean;
  write_blocked_reason?: string | null;
  writeBlockedReason?: string | null;
  record_count: number;
  recordCount?: number;
  scope_count?: number;
  scopeCount?: number;
  memory_key_count?: number;
  memoryKeyCount?: number;
  scopes?: string[];
  memory_keys?: string[];
  memoryKeys?: string[];
  thread_id?: string | null;
  threadId?: string | null;
  agent_id?: string | null;
  agentId?: string | null;
  workspace?: string | null;
  policy?: AgentMemoryPolicy;
  paths?: unknown;
  filters?: unknown;
  records: AgentMemoryRecord[];
  validation?: RuntimeMemoryValidationResult;
  routes?: Record<string, string>;
  rows?: Array<Record<string, unknown>>;
  event?: RuntimeEventEnvelope;
}

export interface RuntimeReceipt {
  id: string;
  kind: string;
  summary: string;
  redaction: "none" | "redacted";
  evidenceRefs: string[];
}

export interface ModelRouteDecision {
  schemaVersion: "ioi.model-route-decision.v1";
  object: "ioi.model_route_decision";
  eventKind: "ModelRouteDecision";
  decisionId: string;
  routeId: string | null;
  capability: string;
  requestedModel: string | null;
  requestedModelMode: "auto" | "explicit" | "route_default" | string;
  autoResolved: boolean;
  selectedModel: string | null;
  upstreamModel: string | null;
  neverSendAutoUpstream: boolean;
  endpointId: string | null;
  providerId: string | null;
  providerKind: string | null;
  providerLabel: string | null;
  reasoningEffort: string;
  localRemotePlacement: string;
  privacyPosture: string;
  costEstimateUsd: number;
  costEstimateSource: string;
  fallbackModel: string | null;
  fallbackEndpointId: string | null;
  fallbackAllowed: boolean;
  fallbackTriggered?: boolean;
  fallbackReason?: string | null;
  rationale: string;
  policyConstraints: Record<string, unknown>;
  evaluatedCandidateCount: number;
  rejectedCandidates: Array<{
    endpointId: string;
    providerId: string;
    reason: string | null;
  }>;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  workflowNodeType: string | null;
  responseId: string | null;
  previousResponseId: string | null;
  policyHash?: string;
  evidenceRefs: string[];
  receiptId?: string;
}

export interface AgentMemoryRecord {
  schemaVersion: "ioi.agent-runtime.memory.v1";
  id: string;
  object: "ioi.agent_memory_record";
  scope: "global" | "workspace" | "thread" | "workflow" | "subagent" | string;
  fact: string;
  factHash?: string;
  memoryKey?: string | null;
  agentId: string | null;
  threadId: string | null;
  workspace: string | null;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  workflowNodeType: string | null;
  source: string;
  redaction: "none" | "redacted";
  createdAt: string;
  updatedAt: string;
  evidenceRefs: string[];
}

export interface AgentMemoryPolicy {
  schemaVersion: "ioi.agent-runtime.memory-policy.v1";
  id: string;
  object: "ioi.agent_memory_policy";
  targetType: "agent" | "thread" | "workflow" | "subagent" | string;
  targetId: string;
  agentId: string | null;
  threadId: string | null;
  workspace: string | null;
  disabled: boolean;
  injectionEnabled: boolean;
  readOnly: boolean;
  writeRequiresApproval: boolean;
  retention: string;
  redaction: "none" | "redacted" | string;
  subagentInheritance: "none" | "explicit" | "read_only" | "full" | string;
  scope: "global" | "workspace" | "thread" | "workflow" | "subagent" | string;
  source: string;
  createdAt: string;
  updatedAt: string;
  evidenceRefs: string[];
  effective?: boolean;
  policyRefs?: string[];
}

export interface SubagentMemoryInheritanceProjection {
  schemaVersion: "ioi.agent-runtime.subagent-memory-inheritance.v1";
  object: "ioi.subagent_memory_inheritance";
  parentAgentId: string;
  subagentName: string | null;
  threadId: string | null;
  mode: "none" | "explicit" | "read_only" | "full" | string;
  requestedMode: string;
  parentPolicyId: string | null;
  effectivePolicyId: string;
  parentPolicy: AgentMemoryPolicy | null;
  effectivePolicy: AgentMemoryPolicy;
  filters: {
    threadId?: string;
    scope?: "global" | "workspace" | "thread" | "workflow" | "subagent" | string;
    memoryKey?: string;
    query?: string;
    q?: string;
    limit?: number;
    redaction?: "none" | "redacted" | string;
  };
  records: AgentMemoryRecord[];
  inheritedRecordIds: string[];
  writeAllowed: boolean;
  writeBlockReason: string | null;
  evidenceRefs: string[];
}

export interface TaskStateProjection {
  currentObjective: string;
  knownFacts: string[];
  uncertainFacts: string[];
  assumptions: string[];
  constraints: string[];
  blockers: string[];
  changedObjects: string[];
  evidenceRefs: string[];
}

export interface UncertaintyProjection {
  ambiguityLevel: "none" | "low" | "medium" | "high";
  selectedAction:
    | "ask_human"
    | "retrieve"
    | "probe"
    | "dry_run"
    | "execute"
    | "verify"
    | "escalate"
    | "stop";
  rationale: string;
  valueOfProbe: "none" | "low" | "medium" | "high";
}

export interface ProbeProjection {
  probeId: string;
  hypothesis: string;
  cheapestValidationAction: string;
  expectedObservation: string;
  result: "pending" | "confirmed" | "rejected" | "inconclusive" | "blocked";
  confidenceUpdate: string;
}

export interface PostconditionProjection {
  objective: string;
  taskFamily: string;
  riskClass: string;
  checks: Array<{
    checkId: string;
    description: string;
    status: "required" | "passed" | "failed" | "unknown" | "skipped";
  }>;
  minimumEvidence: string[];
}

export interface SemanticImpactProjection {
  changedSymbols: string[];
  changedApis: string[];
  changedSchemas: string[];
  changedPolicies: string[];
  affectedTests: string[];
  affectedDocs: string[];
  riskClass: string;
}

export interface StopConditionProjection {
  reason: StopReason;
  evidenceSufficient: boolean;
  rationale: string;
}

export interface AgentQualityLedgerProjection {
  ledgerId: string;
  taskFamily: string;
  selectedStrategy: string;
  toolSequence: string[];
  scorecardMetrics: Record<string, number>;
  failureOntologyLabels: string[];
}

export interface RuntimeScorecard {
  taskPassRate: number;
  recoverySuccess: number;
  memoryRelevance: number;
  toolQuality: number;
  strategyRoi: number;
  operatorInterventionRate: number;
  verifierIndependence: number;
}

export interface IOIRunResult {
  id: string;
  agentId: string;
  status: "queued" | "running" | "completed" | "canceled" | "failed" | "blocked";
  result: string;
  stopCondition: StopConditionProjection;
  routeDecision?: ModelRouteDecision | null;
  trace: RuntimeTraceBundle;
  scorecard: RuntimeScorecard;
  git?: {
    branches: Array<{ name: string; prUrl?: string }>;
  };
}
