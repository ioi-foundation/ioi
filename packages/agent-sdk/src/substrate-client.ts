import { IoiAgentError, type IoiAgentErrorCode } from "./errors.js";
import {
  evaluateComputerUseTrajectory,
  exportComputerUseBenchmarkCase,
  planComputerUseHarnessImprovement,
  type ComputerUseBenchmarkCaseExport,
  type ComputerUseHarnessImprovementPlan,
  type ComputerUseTrajectoryEvalProjection,
} from "./computer-use.js";
import {
  runtimeThreadEventFromEnvelope,
} from "./runtime-events.js";
import type {
  AgentOptions,
  DryRunOptions,
  HandoffOptions,
  LearnOptions,
  McpServerConfig,
  PlanOptions,
  RuntimeMode,
  SendOptions,
} from "./options.js";
import type {
  AgentMemoryPolicy,
  AgentMemoryRecord,
  ConversationMessage,
  IOIRunResult,
  IOISDKMessage,
  ModelRouteDecision,
  RuntimeReceipt,
  RuntimeAccountProfile,
  RuntimeEventEnvelope,
  RuntimeMcpInvocationResult,
  RuntimeMcpPromptEntry,
  RuntimeMcpResourceEntry,
  RuntimeMcpServerEntry,
  RuntimeMcpStatus,
  RuntimeMcpToolEntry,
  RuntimeMcpToolSearchResult,
  RuntimeMcpValidationResult,
  RuntimeMemoryStatus,
  RuntimeMemoryValidationResult,
  RuntimeNodeProfile,
  RuntimeScorecard,
  RuntimeThreadEvent,
  RuntimeThreadRecord,
  RuntimeToolCatalogEntry,
  RuntimeTraceBundle,
  RuntimeTurnRecord,
  SubagentMemoryInheritanceProjection,
} from "./messages.js";
import type { ModelCapabilityContract, RuntimeModelCatalogEntry } from "./model-mounts.js";

export { runtimeThreadEventFromEnvelope } from "./runtime-events.js";

export interface RuntimeArtifact {
  id: string;
  runId: string;
  name: string;
  mediaType: string;
  redaction: "none" | "redacted";
  receiptId: string;
  content: string;
}

export interface ConversationArtifactRef {
  ref: string;
  role: string;
  path?: string;
  fileName?: string;
  mediaType?: string;
}

export interface ConversationArtifactRevision {
  id: string;
  revision_id?: string;
  revisionId?: string;
  artifact_id?: string;
  artifactId?: string;
  status: string;
  summary?: string;
  source_refs?: ConversationArtifactRef[];
  sourceRefs?: ConversationArtifactRef[];
  original_refs?: ConversationArtifactRef[];
  originalRefs?: ConversationArtifactRef[];
  projection_refs?: ConversationArtifactRef[];
  projectionRefs?: ConversationArtifactRef[];
  preview_refs?: ConversationArtifactRef[];
  previewRefs?: ConversationArtifactRef[];
  log_refs?: ConversationArtifactRef[];
  logRefs?: ConversationArtifactRef[];
  created_at?: string;
  createdAt?: string;
}

export interface ConversationArtifactRecord {
  id: string;
  artifact_id?: string;
  artifactId?: string;
  thread_id?: string | null;
  threadId?: string | null;
  artifact_class?: string;
  artifactClass?: string;
  title: string;
  status: string;
  state_label?: string;
  stateLabel?: string;
  summary?: string;
  renderer?: Record<string, unknown>;
  source_refs?: ConversationArtifactRef[];
  sourceRefs?: ConversationArtifactRef[];
  original_refs?: ConversationArtifactRef[];
  originalRefs?: ConversationArtifactRef[];
  projection_refs?: ConversationArtifactRef[];
  projectionRefs?: ConversationArtifactRef[];
  preview_refs?: ConversationArtifactRef[];
  previewRefs?: ConversationArtifactRef[];
  trace_refs?: string[];
  traceRefs?: string[];
  policy_refs?: string[];
  policyRefs?: string[];
  receipt_refs?: string[];
  receiptRefs?: string[];
  actions?: string[];
  revisions?: ConversationArtifactRevision[];
  latest_revision_id?: string;
  latestRevisionId?: string;
  export_refs?: ConversationArtifactRef[];
  exportRefs?: ConversationArtifactRef[];
  promotion_refs?: Record<string, unknown>[];
  promotionRefs?: Record<string, unknown>[];
  created_at?: string;
  createdAt?: string;
  updated_at?: string;
  updatedAt?: string;
}

export interface ConversationArtifactActionResult {
  action: string;
  status: string;
  artifact: ConversationArtifactRecord;
  receipt?: RuntimeReceipt;
}

export interface RuntimeAgentRecord {
  id: string;
  status: "active" | "archived" | "closed";
  runtime: RuntimeMode;
  cwd: string;
  modelId: string;
  requestedModelId?: string;
  modelRouteId?: string;
  modelRouteEndpointId?: string | null;
  modelRouteProviderId?: string | null;
  modelRouteReceiptId?: string | null;
  modelRouteDecision?: ModelRouteDecision | null;
  runtimeControls?: RuntimeThreadRecord["runtime_controls"] | null;
  createdAt: string;
  updatedAt: string;
  options: AgentOptionsSummary;
}

export interface AgentOptionsSummary {
  localCwd?: string;
  cloudConfigured: boolean;
  selfHostedConfigured: boolean;
  mcpServerNames: string[];
  skillNames: string[];
  hookNames: string[];
  subagentNames: string[];
  sandboxProfile: string;
}

export interface RuntimeRunRecord {
  id: string;
  agentId: string;
  status: "queued" | "running" | "completed" | "canceled" | "failed" | "blocked";
  turnStatus?: RuntimeTurnRecord["status"];
  objective: string;
  mode: "send" | "plan" | "dry_run" | "handoff" | "learn";
  createdAt: string;
  updatedAt: string;
  events: IOISDKMessage[];
  conversation: ConversationMessage[];
  receipts: RuntimeReceipt[];
  artifacts: RuntimeArtifact[];
  trace: RuntimeTraceBundle;
  modelRouteDecision?: ModelRouteDecision | null;
  modelRouteReceiptId?: string | null;
  memoryPolicy?: AgentMemoryPolicy | null;
  memoryRecords?: AgentMemoryRecord[];
  memoryWriteReceipts?: RuntimeReceipt[];
  subagentMemoryInheritance?: SubagentMemoryInheritanceProjection | null;
  usage?: RuntimeUsageTelemetry | null;
  usage_telemetry?: RuntimeUsageTelemetry | null;
  usageTelemetry?: RuntimeUsageTelemetry | null;
  runtimeUsage?: RuntimeUsageTelemetry | null;
  result: string;
}

export interface RuntimeUsageTelemetry {
  schema_version?: "ioi.runtime.usage-telemetry.v1" | string;
  object?: "ioi.runtime_usage_telemetry" | string;
  scope: "run" | "thread" | "subagent" | "global" | string;
  thread_id?: string | null;
  turn_id?: string | null;
  run_id?: string | null;
  agent_id?: string | null;
  provider: string;
  model: string;
  route_id?: string | null;
  model_route_id?: string | null;
  input_tokens: number;
  output_tokens: number;
  reasoning_tokens: number;
  cached_input_tokens: number;
  tool_result_tokens: number;
  compacted_tokens: number;
  total_tokens: number;
  estimated_cost_micros: number;
  estimated_cost_usd?: number;
  currency?: string;
  context_window_tokens?: number;
  context_used_tokens?: number;
  context_pressure?: number;
  context_pressure_status?: "nominal" | "elevated" | "high" | string;
  latency_ms: number;
  estimated?: boolean;
  source_counts?: { runs?: number; subagents?: number; [key: string]: unknown };
  source_refs?: string[];
  generated_at?: string;
}

export interface RuntimeUsageListInput {
  group_by?: "run" | "thread" | string;
  agent_id?: string;
}

export interface RuntimeUsageListResult {
  schema_version?: "ioi.runtime.usage-telemetry.v1" | string;
  object?: "ioi.runtime_usage_list" | string;
  group_by?: string;
  count: number;
  usage: RuntimeUsageTelemetry[];
  generated_at?: string;
}

export interface RuntimeTaskRecord {
  schemaVersion: string;
  object: "ioi.runtime_task" | string;
  taskId: string;
  runId: string;
  agentId: string | null;
  threadId?: string | null;
  turnId?: string | null;
  status: "queued" | "running" | "completed" | "canceled" | "failed" | "blocked" | string;
  mode?: string;
  taskFamily?: string;
  selectedStrategy?: string;
  summary?: string;
  promptHash?: string;
  promptIncluded?: boolean;
  modelRouteDecisionId?: string | null;
  activeSkillHookManifestId?: string | null;
  durable?: boolean;
  replayable?: boolean;
  cancelable?: boolean;
  cancelEndpoint?: string;
  endpoints?: Record<string, string>;
  workflowNodeId?: string;
  createdAt: string;
  updatedAt: string;
  evidenceRefs?: string[];
  [key: string]: unknown;
}

export interface RuntimeTaskListOptions {
  agent_id?: string;
  status?: string;
}

export interface RuntimeTaskCreateOptions {
  agent_id?: string;
  prompt?: string;
  mode?: string;
  options?: Record<string, unknown>;
  agent?: Record<string, unknown>;
  agent_options?: Record<string, unknown>;
  model?: Record<string, unknown>;
  cwd?: string;
}

export interface RuntimeJobRecord {
  schemaVersion: string;
  object: "ioi.runtime_job" | string;
  jobId: string;
  taskId: string;
  runId: string;
  agentId: string | null;
  threadId?: string | null;
  turnId?: string | null;
  status: "queued" | "running" | "completed" | "canceled" | "failed" | "blocked" | string;
  lifecycle: string[];
  summary?: string;
  queueName?: string;
  runner?: string;
  jobType?: string;
  priority?: string;
  background?: boolean;
  durable?: boolean;
  replayable?: boolean;
  createdAt: string;
  updatedAt: string;
  queuedAt?: string | null;
  startedAt?: string | null;
  completedAt?: string | null;
  progress?: {
    completedSteps?: number;
    totalSteps?: number;
    percent?: number;
  };
  eventCount?: number | null;
  terminalEventCount?: number | null;
  artifactNames?: string[];
  receiptKinds?: string[];
  cancelable?: boolean;
  cancelEndpoint?: string;
  endpoints?: Record<string, string>;
  workflowNodeId?: string;
  evidenceRefs?: string[];
  [key: string]: unknown;
}

export interface RuntimeJobListOptions {
  agent_id?: string;
  status?: string;
}

export type RuntimeSubagentLifecycleStatus =
  | "queued"
  | "running"
  | "waiting_for_input"
  | "interrupted"
  | "blocked"
  | "completed"
  | "failed"
  | "canceled"
  | string;

export interface RuntimeSubagentOutputContractStatus {
  schema_version?: string;
  status?: string | null;
  required_sections?: string[];
  present_sections?: string[];
  missing_sections?: string[];
  validated_at?: string;
}

export interface RuntimeSubagentUsageTelemetry {
  schema_version?: string;
  object?: "ioi.runtime_subagent_usage_telemetry" | string;
  estimated?: boolean;
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
  cumulative_input_tokens?: number;
  cumulative_output_tokens?: number;
  cumulative_total_tokens?: number;
  cost_estimate_usd?: number;
  cumulative_cost_estimate_usd?: number;
  model_route_id?: string | null;
}

export interface RuntimeSubagentBudgetStatus {
  schema_version?: string;
  object?: "ioi.runtime_subagent_budget_status" | string;
  status?: "not_configured" | "within_budget" | "exceeded" | string;
  budget?: Record<string, unknown> | null;
  usage?: RuntimeSubagentUsageTelemetry | null;
  violations?: Record<string, unknown>[];
  policy_decision?: Record<string, unknown> | null;
  checked_at?: string;
}

export interface RuntimeSubagentRequestMetadataInput {
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  actor?: string;
  workflow_graph_id?: string;
  workflow_node_id?: string;
  receipt_refs?: string[];
  policy_decision_refs?: string[];
  idempotency_key?: string;
}

export interface RuntimeSubagentBudgetControlInput {
  budget?: Record<string, unknown>;
  budget_usage_telemetry?: RuntimeSubagentUsageTelemetry | null;
}

export interface RuntimeSubagentSpawnInput
  extends RuntimeSubagentRequestMetadataInput,
    RuntimeSubagentBudgetControlInput {
  prompt: string;
  role?: string;
  tool_pack?: string;
  model_route_id?: string;
  max_concurrency?: number;
  output_contract?: string[] | Record<string, unknown>;
  merge_policy?: string;
  cancellation_inheritance?: "propagate" | "isolated" | string;
  fork_context?: boolean;
  parent_turn_id?: string;
  turn_id?: string;
  context_pressure_action?: string;
  context_pressure?: number;
  pressure?: number;
  pressure_status?: string;
  alert_id?: string;
  source_event_id?: string;
  memory?: Record<string, unknown>;
  options?: Record<string, unknown>;
}

export interface RuntimeSubagentWaitInput extends RuntimeSubagentRequestMetadataInput {}

export interface RuntimeSubagentSendInput
  extends RuntimeSubagentRequestMetadataInput,
    RuntimeSubagentBudgetControlInput {
  input: string;
}

export interface RuntimeSubagentCancelInput
  extends RuntimeSubagentRequestMetadataInput,
    RuntimeSubagentBudgetControlInput {
  reason?: string;
  cancellation_reason?: string;
  inherited?: boolean;
  cancellation_inherited?: boolean;
  propagated_from_thread_id?: string;
}

export interface RuntimeSubagentResumeInput
  extends RuntimeSubagentRequestMetadataInput,
    RuntimeSubagentBudgetControlInput {
  prompt?: string;
  role?: string;
  model_route_id?: string;
  output_contract?: string[] | Record<string, unknown>;
  memory?: Record<string, unknown>;
  options?: Record<string, unknown>;
}

export interface RuntimeSubagentAssignInput extends RuntimeSubagentRequestMetadataInput {
  role?: string;
  tool_pack?: string;
  model_route_id?: string;
  merge_policy?: string;
  cancellation_inheritance?: "propagate" | "isolated" | string;
  target_agent_id?: string;
}

export interface RuntimeSubagentCancellationPropagationInput
  extends RuntimeSubagentRequestMetadataInput,
    RuntimeSubagentBudgetControlInput {
  reason?: string;
  cancellation_reason?: string;
}

export interface RuntimeSubagentListInput {
  role?: string;
  status?: string;
}

export interface RuntimeSubagentRecord {
  schema_version?: string;
  object?: "ioi.runtime_subagent" | string;
  subagent_id?: string;
  agent_id?: string;
  child_thread_id?: string;
  run_id?: string;
  parent_thread_id?: string;
  parent_agent_id?: string;
  parent_turn_id?: string | null;
  role?: string;
  tool_pack?: string | null;
  model_route_id?: string | null;
  workflow_graph_id?: string | null;
  workflow_node_id?: string | null;
  lifecycle_status?: RuntimeSubagentLifecycleStatus;
  status?: RuntimeSubagentLifecycleStatus;
  restart_status?: string | null;
  restart_count?: number;
  input_count?: number;
  assignment_count?: number;
  cancellation_inheritance?: string | null;
  cancellation_reason?: string | null;
  cancellation_inherited?: boolean | null;
  propagated_from_thread_id?: string | null;
  output_contract_status?: string | null;
  budget_status?: string | null;
  usage_telemetry?: RuntimeSubagentUsageTelemetry | null;
  cost_estimate_usd?: number | null;
  token_estimate?: number | null;
  result?: RuntimeSubagentResult | null;
  event?: RuntimeEventEnvelope | null;
  receipt_refs?: string[];
  evidence_refs?: string[];
  created_at?: string;
  updated_at?: string;
}

export interface RuntimeSubagentListResult {
  schema_version?: string;
  object: "ioi.runtime_subagent_list" | string;
  thread_id?: string;
  parent_agent_id?: string;
  status?: string;
  count: number;
  active_count?: number;
  subagents: RuntimeSubagentRecord[];
}

export interface RuntimeSubagentResult {
  schema_version?: string;
  object?: "ioi.runtime_subagent_result" | string;
  subagent_id?: string | null;
  agent_id?: string | null;
  run_id?: string | null;
  lifecycle_status?: RuntimeSubagentLifecycleStatus | null;
  status?: RuntimeSubagentLifecycleStatus | null;
  result?: string | null;
  output?: Record<string, unknown> | null;
  output_contract_status?: string | null;
  budget_status?: string | null;
  usage_telemetry?: RuntimeSubagentUsageTelemetry | null;
  cost_estimate_usd?: number | null;
  token_estimate?: number | null;
  receipt_refs?: string[];
  subagent?: RuntimeSubagentRecord;
  event?: RuntimeEventEnvelope | null;
  cancellation?: Record<string, unknown> | null;
  input?: Record<string, unknown> | null;
  resume?: Record<string, unknown> | null;
  assignment?: Record<string, unknown> | null;
}

export interface RuntimeSubagentCancellationPropagationResult {
  schema_version?: string;
  object: "ioi.runtime_subagent_cancellation_propagation" | string;
  thread_id?: string;
  parent_agent_id?: string;
  status: string;
  source?: string;
  reason?: string;
  propagation_policy?: string;
  candidate_count?: number;
  canceled_count?: number;
  skipped_count?: number;
  canceled_subagents?: RuntimeSubagentRecord[];
  skipped_subagents?: RuntimeSubagentRecord[];
  event_refs?: string[];
  receipt_refs?: string[];
}

export interface AgentMemoryProjection {
  schemaVersion: "ioi.agent-runtime.memory.v1";
  object: "ioi.agent_memory_projection";
  threadId: string | null;
  agentId: string | null;
  workspace: string | null;
  policy?: AgentMemoryPolicy;
  paths?: AgentMemoryPathProjection;
  filters?: MemoryListOptions;
  records: AgentMemoryRecord[];
  totalMatches?: number;
}

export interface MemoryListOptions {
  threadId?: string;
  scope?: "global" | "workspace" | "thread" | "workflow" | "subagent" | string;
  memoryKey?: string;
  query?: string;
  q?: string;
  limit?: number;
  redaction?: "none" | "redacted" | string;
}

export interface RememberMemoryInput {
  text: string;
  memoryKey?: string;
  scope?: "global" | "workspace" | "thread" | "workflow" | "subagent" | string;
  threadId?: string;
  workflowGraphId?: string;
  workflowNodeId?: string;
  workflowNodeType?: string;
  writeApproved?: boolean;
}

export interface RememberMemoryResult {
  record: AgentMemoryRecord;
  receipt: RuntimeReceipt;
}

export interface UpdateMemoryRecordInput {
  text: string;
  threadId?: string;
  writeApproved?: boolean;
}

export interface DeleteMemoryRecordInput {
  threadId?: string;
  writeApproved?: boolean;
}

export interface MemoryPolicyInput {
  threadId?: string;
  targetType?: "agent" | "thread" | "workflow" | "subagent" | string;
  targetId?: string;
  disabled?: boolean;
  injectionEnabled?: boolean;
  readOnly?: boolean;
  writeRequiresApproval?: boolean;
  retention?: string;
  redaction?: "none" | "redacted" | string;
  subagentInheritance?: "none" | "explicit" | "read_only" | "full" | string;
  scope?: "global" | "workspace" | "thread" | "workflow" | "subagent" | string;
}

export interface MemoryPolicyUpdateResult {
  policy: AgentMemoryPolicy;
  receipt: RuntimeReceipt;
}

export interface RuntimeToolListOptions {
  pack?: string;
}

export interface RuntimeThreadToolInvokeInput {
  input?: Record<string, unknown>;
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  turnId?: string;
  turn_id?: string;
  workflowGraphId?: string;
  workflow_graph_id?: string;
  workflowNodeId?: string;
  workflow_node_id?: string;
  toolCallId?: string;
  tool_call_id?: string;
  idempotencyKey?: string;
  idempotency_key?: string;
  [key: string]: unknown;
}

export interface RuntimeThreadToolInvocationResult {
  schema_version: string;
  object: "ioi.runtime_coding_tool_result" | string;
  tool_pack: string;
  tool_name: string;
  tool_call_id: string;
  thread_id: string;
  turn_id: string | null;
  status: string;
  workspace_root: string;
  workflow_graph_id: string | null;
  workflow_node_id: string | null;
  shell_fallback_used: boolean;
  receipt_refs: string[];
  artifact_refs: string[];
  rollback_refs?: string[];
  event?: RuntimeEventEnvelope;
  workspace_snapshot?: Record<string, unknown> | null;
  workspaceSnapshot?: Record<string, unknown> | null;
  workspace_snapshot_event?: RuntimeEventEnvelope | null;
  workspaceSnapshotEvent?: RuntimeEventEnvelope | null;
  result?: Record<string, unknown> | null;
  error?: Record<string, unknown> | null;
}

export interface RuntimeMcpListOptions {
  thread_id?: string;
  agent_id?: string;
  server_id?: string;
  mcp_config_source_mode?: string;
  config_source_mode?: string;
}

export interface RuntimeMcpToolSearchInput extends RuntimeMcpListOptions {
  query?: string;
  q?: string;
  search?: string;
  tool_id?: string;
  tool_name?: string;
  exact?: boolean;
  live_discovery?: boolean;
  catalog_preview_limit?: number;
  limit?: number;
}

export interface RuntimeMcpValidationInput {
  mcp_json?: Record<string, unknown>;
  servers?: unknown[] | Record<string, unknown>;
  cwd?: string;
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  workflow_graph_id?: string;
  workflow_node_id?: string;
  [key: string]: unknown;
}

export interface RuntimeMcpServerControlInput extends RuntimeMcpValidationInput {
  thread_id?: string;
  server_id?: string;
  enabled?: boolean;
}

export interface RuntimeMcpServerMutationInput extends RuntimeMcpServerControlInput {
  label?: string;
  name?: string;
  transport?: "stdio" | "http" | "sse" | string;
  url?: string;
  serverUrl?: string;
  server_url?: string;
  headers?: Record<string, string>;
  server?: Record<string, unknown>;
  config?: Record<string, unknown>;
  mcp_json?: Record<string, unknown>;
}

export interface RuntimeMcpToolInvokeInput extends RuntimeMcpValidationInput {
  thread_id?: string;
  server_id?: string;
  tool_id?: string;
  tool_name?: string;
  tool?: string;
  input?: Record<string, unknown>;
  arguments?: Record<string, unknown>;
  side_effect_class?: string;
  requires_approval?: boolean;
  approved?: boolean;
  live_transport?: boolean;
  execution_mode?: "live_stdio" | "live_http" | "live_sse" | "simulated_manager_receipt" | string;
  timeout_ms?: number;
}

export interface RuntimeThreadMcpInput extends RuntimeMcpServerControlInput {
  turn_id?: string;
  idempotency_key?: string;
}

export interface RuntimeMcpJsonRpcRequest {
  jsonrpc?: "2.0" | string;
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface RuntimeMcpJsonRpcResponse {
  jsonrpc: "2.0" | string;
  id?: string | number | null;
  result?: Record<string, unknown>;
  error?: {
    code: number;
    message: string;
    data?: Record<string, unknown>;
  };
  [key: string]: unknown;
}

export interface RuntimeMcpServeRpcInput extends RuntimeMcpListOptions {
  message: RuntimeMcpJsonRpcRequest | RuntimeMcpJsonRpcRequest[];
  allowedTools?: string[];
  allowed_tools?: string[];
  source?: "sdk_client" | "cli_tui" | "react_flow" | "mcp_serve" | string;
}

export interface RuntimeMemoryStatusOptions extends MemoryListOptions {
  threadId?: string;
  thread_id?: string;
  agentId?: string;
  agent_id?: string;
  [key: string]: unknown;
}

export interface RuntimeMemoryValidationInput extends RuntimeMemoryStatusOptions {
  projection?: AgentMemoryProjection;
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  workflowGraphId?: string;
  workflow_graph_id?: string;
  workflowNodeId?: string;
  workflow_node_id?: string;
  [key: string]: unknown;
}

export interface RuntimeThreadMemoryInput extends RuntimeMemoryValidationInput {
  turnId?: string;
  turn_id?: string;
  idempotencyKey?: string;
  idempotency_key?: string;
}

export interface RuntimeThreadMemoryWriteInput extends RememberMemoryInput, RuntimeThreadMemoryInput {}

export interface RuntimeThreadMemoryEditInput extends UpdateMemoryRecordInput, RuntimeThreadMemoryInput {}

export interface RuntimeThreadMemoryDeleteInput extends DeleteMemoryRecordInput, RuntimeThreadMemoryInput {}

export interface RuntimeWorkspaceSnapshotListResult {
  schemaVersion: string;
  object: "ioi.runtime_workspace_snapshot_list" | string;
  threadId: string;
  thread_id?: string;
  snapshotCount: number;
  snapshot_count?: number;
  snapshots: Array<Record<string, unknown>>;
}

export interface RuntimeWorkspaceRestorePreviewInput {
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  workflowGraphId?: string;
  workflow_graph_id?: string;
  workflowNodeId?: string;
  workflow_node_id?: string;
  [key: string]: unknown;
}

export interface RuntimeWorkspaceRestorePreviewResult {
  schemaVersion: string;
  schema_version?: string;
  object: "ioi.runtime_workspace_restore_preview" | string;
  threadId: string;
  thread_id?: string;
  snapshotId: string;
  snapshot_id?: string;
  previewStatus: string;
  preview_status?: string;
  previewSupported: boolean;
  preview_supported?: boolean;
  applySupported: boolean;
  apply_supported?: boolean;
  fileCount: number;
  file_count?: number;
  readyCount: number;
  ready_count?: number;
  noopCount: number;
  noop_count?: number;
  conflictCount: number;
  conflict_count?: number;
  blockedCount: number;
  blocked_count?: number;
  operations: Array<Record<string, unknown>>;
  receiptRefs: string[];
  receipt_refs?: string[];
  artifactRefs: string[];
  artifact_refs?: string[];
  rollbackRefs: string[];
  rollback_refs?: string[];
  event?: RuntimeEventEnvelope | null;
  restore_preview_event?: RuntimeEventEnvelope | null;
  restorePreviewEvent?: RuntimeEventEnvelope | null;
  summary?: string;
}

export interface RuntimeWorkspaceRestoreApplyInput extends RuntimeWorkspaceRestorePreviewInput {
  approvalGranted?: boolean;
  approval_granted?: boolean;
  confirm?: boolean;
  confirmed?: boolean;
  allowConflicts?: boolean;
  allow_conflicts?: boolean;
  overrideConflicts?: boolean;
  override_conflicts?: boolean;
  conflictPolicy?: string;
  conflict_policy?: string;
}

export interface RuntimeWorkspaceRestoreApplyResult {
  schemaVersion: string;
  schema_version?: string;
  object: "ioi.runtime_workspace_restore_apply" | string;
  threadId: string;
  thread_id?: string;
  snapshotId: string;
  snapshot_id?: string;
  previewStatus: string;
  preview_status?: string;
  applyStatus: string;
  apply_status?: string;
  applySupported: boolean;
  apply_supported?: boolean;
  approvalRequired: boolean;
  approval_required?: boolean;
  approvalSatisfied: boolean;
  approval_satisfied?: boolean;
  fileCount: number;
  file_count?: number;
  appliedCount: number;
  applied_count?: number;
  applyNoopCount: number;
  apply_noop_count?: number;
  applyBlockedCount: number;
  apply_blocked_count?: number;
  failedCount: number;
  failed_count?: number;
  operations: Array<Record<string, unknown>>;
  policyDecisionRefs: string[];
  policy_decision_refs?: string[];
  receiptRefs: string[];
  receipt_refs?: string[];
  artifactRefs: string[];
  artifact_refs?: string[];
  rollbackRefs: string[];
  rollback_refs?: string[];
  event?: RuntimeEventEnvelope | null;
  restore_apply_event?: RuntimeEventEnvelope | null;
  restoreApplyEvent?: RuntimeEventEnvelope | null;
  summary?: string;
}

export interface RuntimeDiagnosticsRepairRetryResult {
  schemaVersion: string;
  schema_version?: string;
  object: "ioi.runtime_diagnostics_repair_retry" | string;
  threadId: string;
  thread_id?: string;
  status: string;
  turnId?: string | null;
  turn_id?: string | null;
  requestId?: string | null;
  request_id?: string | null;
  repairTurn?: RuntimeTurnRecord | null;
  repair_turn?: RuntimeTurnRecord | null;
  event?: RuntimeEventEnvelope | null;
  repair_retry_event?: RuntimeEventEnvelope | null;
  receiptRefs: string[];
  receipt_refs?: string[];
  artifactRefs: string[];
  artifact_refs?: string[];
  policyDecisionRefs: string[];
  policy_decision_refs?: string[];
  rollbackRefs: string[];
  rollback_refs?: string[];
  summary?: string;
}

export interface RuntimeDiagnosticsOperatorOverrideResult {
  schemaVersion: string;
  schema_version?: string;
  object: "ioi.runtime_diagnostics_operator_override" | string;
  threadId: string;
  thread_id?: string;
  status: string;
  overrideStatus?: string;
  override_status?: string;
  gateEventId?: string | null;
  gate_event_id?: string | null;
  gateId?: string | null;
  gate_id?: string | null;
  targetTurnId?: string | null;
  target_turn_id?: string | null;
  targetRunId?: string | null;
  target_run_id?: string | null;
  approvalRequired?: boolean;
  approval_required?: boolean;
  approvalSatisfied?: boolean;
  approval_satisfied?: boolean;
  approvalSource?: string | null;
  approval_source?: string | null;
  continuationAllowed?: boolean;
  continuation_allowed?: boolean;
  event?: RuntimeEventEnvelope | null;
  operator_override_event?: RuntimeEventEnvelope | null;
  receiptRefs: string[];
  receipt_refs?: string[];
  artifactRefs: string[];
  artifact_refs?: string[];
  policyDecisionRefs: string[];
  policy_decision_refs?: string[];
  rollbackRefs: string[];
  rollback_refs?: string[];
  summary?: string;
}

export interface RuntimeDiagnosticsRepairDecisionExecuteInput {
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  action?: "repair_retry" | "restore_preview" | "restore_apply" | "operator_override" | string;
  gateId?: string;
  gate_id?: string;
  snapshotId?: string;
  snapshot_id?: string;
  actor?: string;
  workflowGraphId?: string;
  workflow_graph_id?: string;
  workflowNodeId?: string;
  workflow_node_id?: string;
  approvalGranted?: boolean;
  approval_granted?: boolean;
  confirm?: boolean;
  confirmed?: boolean;
  allowConflicts?: boolean;
  allow_conflicts?: boolean;
  overrideConflicts?: boolean;
  override_conflicts?: boolean;
  restoreConflictPolicy?: string;
  restore_conflict_policy?: string;
  idempotencyKey?: string;
  idempotency_key?: string;
  restorePreviewIdempotencyKey?: string;
  restore_preview_idempotency_key?: string;
  restoreApplyIdempotencyKey?: string;
  restore_apply_idempotency_key?: string;
  repairRetryIdempotencyKey?: string;
  repair_retry_idempotency_key?: string;
  operatorOverrideIdempotencyKey?: string;
  operator_override_idempotency_key?: string;
  repairPromptText?: string;
  repair_prompt_text?: string;
  [key: string]: unknown;
}

export interface RuntimeDiagnosticsRepairDecisionExecutionResult {
  schemaVersion: string;
  schema_version?: string;
  object: "ioi.runtime_diagnostics_repair_decision_execution" | string;
  threadId: string;
  thread_id?: string;
  decisionId: string;
  decision_id?: string;
  action: string;
  status: string;
  gateEventId?: string | null;
  gate_event_id?: string | null;
  policyId?: string | null;
  policy_id?: string | null;
  snapshotId?: string | null;
  snapshot_id?: string | null;
  workflowGraphId?: string | null;
  workflow_graph_id?: string | null;
  workflowNodeId?: string | null;
  workflow_node_id?: string | null;
  decision?: Record<string, unknown>;
  repairPolicy?: Record<string, unknown>;
  repair_policy?: Record<string, unknown>;
  repairRetry?: RuntimeDiagnosticsRepairRetryResult;
  repair_retry?: RuntimeDiagnosticsRepairRetryResult;
  repairTurn?: RuntimeTurnRecord | null;
  repair_turn?: RuntimeTurnRecord | null;
  repairRetryEvent?: RuntimeEventEnvelope | null;
  repair_retry_event?: RuntimeEventEnvelope | null;
  operatorOverride?: RuntimeDiagnosticsOperatorOverrideResult;
  operator_override?: RuntimeDiagnosticsOperatorOverrideResult;
  operatorOverrideEvent?: RuntimeEventEnvelope | null;
  operator_override_event?: RuntimeEventEnvelope | null;
  restorePreview?: RuntimeWorkspaceRestorePreviewResult;
  restore_preview?: RuntimeWorkspaceRestorePreviewResult;
  restoreApply?: RuntimeWorkspaceRestoreApplyResult;
  restore_apply?: RuntimeWorkspaceRestoreApplyResult;
  restorePreviewEvent?: RuntimeEventEnvelope | null;
  restore_preview_event?: RuntimeEventEnvelope | null;
  restoreApplyEvent?: RuntimeEventEnvelope | null;
  restore_apply_event?: RuntimeEventEnvelope | null;
  event?: RuntimeEventEnvelope | null;
  receiptRefs: string[];
  receipt_refs?: string[];
  artifactRefs: string[];
  artifact_refs?: string[];
  policyDecisionRefs: string[];
  policy_decision_refs?: string[];
  rollbackRefs: string[];
  rollback_refs?: string[];
  summary?: string;
}

export interface AgentMemoryPathProjection {
  schemaVersion: "ioi.agent-runtime.memory.v1";
  object: "ioi.agent_memory_path_projection";
  threadId: string | null;
  agentId: string | null;
  workspace: string | null;
  recordsPath: string;
  policiesPath: string;
  effectivePolicyId: string;
}

export interface RuntimeThreadCreateInput {
  options?: AgentOptions;
  runtime_profile?: string;
  goal?: string;
  max_steps?: number;
  [key: string]: unknown;
}

export interface RuntimeThreadForkInput {
  options?: AgentOptions;
  reason?: string;
  actor?: string;
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  workflowGraphId?: string;
  workflowNodeId?: string;
  [key: string]: unknown;
}

export interface RuntimeTurnCreateInput {
  prompt?: string;
  message?: string;
  input?: string;
  mode?: RuntimeRunRecord["mode"];
  options?: SendOptions | PlanOptions | DryRunOptions | HandoffOptions;
  memory?: SendOptions["memory"];
  remember?: string;
  [key: string]: unknown;
}

export interface RuntimeTurnInterruptInput {
  reason?: string;
  actor?: string;
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  workflowGraphId?: string;
  workflowNodeId?: string;
  [key: string]: unknown;
}

export interface RuntimeTurnSteerInput {
  guidance?: string;
  message?: string;
  input?: string;
  actor?: string;
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  workflowGraphId?: string;
  workflowNodeId?: string;
  [key: string]: unknown;
}

export interface RuntimeThreadCompactInput {
  reason?: string;
  scope?: "thread" | "turn" | string;
  actor?: string;
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  workflowGraphId?: string;
  workflowNodeId?: string;
  [key: string]: unknown;
}

export interface RuntimeThreadModeInput {
  mode: RuntimeThreadRecord["mode"] | string;
  approvalMode?: RuntimeThreadRecord["approval_mode"] | string;
  actor?: string;
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  workflowGraphId?: string;
  workflowNodeId?: string;
  [key: string]: unknown;
}

export interface RuntimeThreadModelInput {
  model?: string | {
    id?: string;
    modelId?: string;
    routeId?: string;
    reasoningEffort?: string;
    thinking?: string;
    privacy?: string;
    maxCostUsd?: number;
    allow_hosted_fallback?: boolean;
    workflowGraphId?: string;
    workflowNodeId?: string;
    [key: string]: unknown;
  };
  modelId?: string;
  routeId?: string;
  reasoningEffort?: string;
  actor?: string;
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  workflowGraphId?: string;
  workflowNodeId?: string;
  [key: string]: unknown;
}

export interface RuntimeThreadThinkingInput {
  reasoningEffort?: "low" | "medium" | "high" | "xhigh" | string;
  thinking?: "low" | "medium" | "high" | "xhigh" | string;
  actor?: string;
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  workflowGraphId?: string;
  workflowNodeId?: string;
  [key: string]: unknown;
}

export type RuntimeGovernedImprovementSurface =
  | "skill"
  | "module"
  | "workflow"
  | "route"
  | "schema"
  | "policy"
  | string;

export interface RuntimeGovernedImprovementProposal extends Record<string, unknown> {
  schema_version: "ioi.governed_runtime_improvement.v1" | string;
  proposal_id: string;
  target_ref: string;
  candidate_ref: string;
  surface: RuntimeGovernedImprovementSurface;
  source_trace_ref: string;
  eval_receipt_refs: string[];
  verifier_receipt_refs: string[];
  approval_ref: string;
  rollback_ref: string;
  agentgres_operation_ref: string;
  expected_heads: string[];
  state_root_before: string;
  state_root_after: string;
  resulting_head: string;
}

export interface RuntimeGovernedImprovementProposalAdmissionInput extends Record<string, unknown> {
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  actor?: string;
  workflowGraphId?: string;
  workflow_graph_id?: string;
  workflowNodeId?: string;
  workflow_node_id?: string;
  proposal: RuntimeGovernedImprovementProposal | Record<string, unknown>;
}

export interface RuntimeGovernedImprovementProposalAdmissionResult extends Record<string, unknown> {
  schema_version?: "ioi.runtime.governed_improvement_admission.v1" | string;
  object?: "ioi.runtime_governed_improvement_admission" | string;
  status: "admitted" | string;
  proposal_admitted?: boolean;
  mutation_executed?: boolean;
  thread_id?: string;
  agent_id?: string;
  proposal_id?: string | null;
  admission_hash?: string | null;
  agentgres_operation_ref?: string | null;
  state_root_before?: string | null;
  state_root_after?: string | null;
  resulting_head?: string | null;
  approval_ref?: string | null;
  rollback_ref?: string | null;
  admission?: Record<string, unknown>;
  record?: Record<string, unknown>;
}

export type RuntimeWorkerServicePackageKind =
  | "worker_package"
  | "service_package"
  | string;

export interface RuntimeWorkerServicePackageInvocation extends Record<string, unknown> {
  schema_version: "ioi.worker_service_package_invocation.v1" | string;
  package_kind: RuntimeWorkerServicePackageKind;
  package_ref: string;
  manifest_ref: string;
  invocation: Record<string, unknown>;
  result: Record<string, unknown>;
  expected_heads: string[];
}

export interface RuntimeWorkerServicePackageInvocationAdmissionInput extends Record<string, unknown> {
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  actor?: string;
  workflowGraphId?: string;
  workflow_graph_id?: string;
  workflowNodeId?: string;
  workflow_node_id?: string;
  invocation: RuntimeWorkerServicePackageInvocation | Record<string, unknown>;
}

export interface RuntimeWorkerServicePackageInvocationAdmissionResult extends Record<string, unknown> {
  schema_version?: "ioi.runtime.worker_service_package_admission.v1" | string;
  object?: "ioi.runtime_worker_service_package_admission" | string;
  status: "admitted" | string;
  invocation_admitted?: boolean;
  thread_id?: string;
  agent_id?: string;
  package_kind?: string | null;
  package_ref?: string | null;
  manifest_ref?: string | null;
  invocation_id?: string | null;
  router_admission?: Record<string, unknown> | null;
  receipt_binding?: Record<string, unknown> | null;
  accepted_receipt_append?: Record<string, unknown> | null;
  agentgres_admission?: Record<string, unknown> | null;
  projection_record?: Record<string, unknown> | null;
  receipt_refs?: string[];
  artifact_refs?: string[];
  payload_refs?: string[];
  authority_grant_refs?: string[];
  admission?: Record<string, unknown>;
  record?: Record<string, unknown>;
}

export interface RuntimeL1SettlementAttempt extends Record<string, unknown> {
  schema_version: "ioi.l1_settlement_admission.v1" | string;
  settlement_ref: string;
  domain_ref: string;
  state_root_ref: string;
  trigger_refs: string[];
  receipt_refs: string[];
}

export interface RuntimeL1SettlementAttemptAdmissionInput extends Record<string, unknown> {
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  actor?: string;
  workflowGraphId?: string;
  workflow_graph_id?: string;
  workflowNodeId?: string;
  workflow_node_id?: string;
  attempt: RuntimeL1SettlementAttempt | Record<string, unknown>;
}

export interface RuntimeL1SettlementAttemptAdmissionResult extends Record<string, unknown> {
  schema_version?: "ioi.runtime.l1_settlement_admission.v1" | string;
  object?: "ioi.runtime_l1_settlement_admission" | string;
  status: "admitted" | string;
  settlement_admitted?: boolean;
  thread_id?: string;
  agent_id?: string;
  settlement_ref?: string | null;
  domain_ref?: string | null;
  state_root_ref?: string | null;
  trigger_refs?: string[];
  receipt_refs?: string[];
  admission_hash?: string | number[] | null;
  admission?: Record<string, unknown>;
  record?: Record<string, unknown>;
}

export interface RuntimeCteePrivateWorkspaceNodeTrust extends Record<string, unknown> {
  runtime_node_ref: string;
  trusted_for_plaintext: boolean;
  attestation_ref?: string | null;
}

export interface RuntimeCteePrivateWorkspaceAction extends Record<string, unknown> {
  invocation: Record<string, unknown>;
  node_trust: RuntimeCteePrivateWorkspaceNodeTrust | Record<string, unknown>;
  expected_heads: string[];
}

export interface RuntimeCteePrivateWorkspaceActionInput extends Record<string, unknown> {
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  actor?: string;
  workflowGraphId?: string;
  workflow_graph_id?: string;
  workflowNodeId?: string;
  workflow_node_id?: string;
  action: RuntimeCteePrivateWorkspaceAction | Record<string, unknown>;
}

export interface RuntimeCteePrivateWorkspaceActionResult extends Record<string, unknown> {
  schema_version?: "ioi.runtime.ctee_private_workspace_admission.v1" | string;
  object?: "ioi.runtime_ctee_private_workspace_admission" | string;
  status: "admitted" | string;
  action_executed?: boolean;
  thread_id?: string;
  agent_id?: string;
  invocation_id?: string | null;
  receipt_ref?: string | null;
  receipt?: Record<string, unknown> | null;
  result?: Record<string, unknown> | null;
  receipt_binding?: Record<string, unknown> | null;
  accepted_receipt_append?: Record<string, unknown> | null;
  agentgres_admission?: Record<string, unknown> | null;
  projection_record?: Record<string, unknown> | null;
  receipt_refs?: string[];
  evidence_refs?: string[];
  admission?: Record<string, unknown>;
  record?: Record<string, unknown>;
}

export interface RuntimeEventStreamOptions {
  sinceSeq?: number;
  lastEventId?: string;
  signal?: AbortSignal;
}

export interface RuntimeComputerUseBrowserDiscoveryOptions {
  probe?: boolean;
  include_tabs?: boolean;
  includeTabs?: boolean;
  reveal_tab_titles?: boolean;
  revealTabTitles?: boolean;
}

export interface RuntimeComputerUseBrowserDiscoveryProcess {
  process_ref: string;
  pid: number;
  ppid: number;
  command: string;
  browser_family: string;
  is_browser_child_process: boolean;
  has_remote_debugging_port: boolean;
  remote_debugging_port: number | null;
  remote_debugging_address: string | null;
  user_data_dir_present: boolean;
  user_data_dir_hash: string | null;
  profile_directory_present: boolean;
  profile_directory_hash: string | null;
  profile_provenance: string;
  default_profile_cdp_refusal_risk: boolean;
  cdp_status: string;
  redacted_flags: Array<{ flag: string; value: string }>;
}

export interface RuntimeComputerUseBrowserDiscoveryEndpoint {
  endpoint_ref: string;
  process_ref: string;
  pid: number;
  browser_family: string;
  host: string;
  port: number;
  endpoint_url: string;
  source: string;
  status: string;
  browser: string | null;
  protocol_version: string | null;
  tab_count: number | null;
  tabs: Array<Record<string, unknown>>;
  error_class?: string;
  error_summary?: string;
}

export interface RuntimeComputerUseBrowserDiscoveryReport {
  schema_version: "ioi.computer-use.browser-discovery.v1" | string;
  object: "ioi.computer_use.browser_discovery_report" | string;
  receipt_ref: string;
  discovered_at: string;
  platform: string;
  process_count: number;
  browser_process_count: number;
  browser_processes: RuntimeComputerUseBrowserDiscoveryProcess[];
  cdp_endpoint_count: number;
  cdp_endpoints: RuntimeComputerUseBrowserDiscoveryEndpoint[];
  default_profile_remote_debugging_blockers: Array<Record<string, unknown>>;
  safety: {
    read_only: boolean;
    mutated_browser_state: boolean;
    copied_profiles: boolean;
    copied_credentials: boolean;
    raw_profile_paths_redacted: boolean;
    raw_command_lines_redacted: boolean;
    cdp_probe_enabled: boolean;
    cdp_probe_scope: string;
  };
  recommended_next_steps: string[];
}

export interface RuntimeComputerUseProviderRegistryEntry {
  provider_id: string;
  provider_kind: string;
  lane: string;
  status: string;
  implementation_status: string;
  thread_tool_name: string | null;
  supported_session_modes: string[];
  capabilities: string[];
  authority_scopes: string[];
  retention_modes: string[];
  cleanup_required: boolean;
  fixture: boolean;
  unavailable_reason?: string;
}

export interface RuntimeComputerUseProviderRegistryReport {
  schema_version: "ioi.computer-use.provider-registry.v1" | string;
  object: "ioi.computer_use.provider_registry_report" | string;
  providers: RuntimeComputerUseProviderRegistryEntry[];
  available_provider_ids: string[];
  unavailable_provider_ids: string[];
  fail_closed_when_unavailable: boolean;
}

export interface RuntimeSubstrateClient {
  createThread(input?: RuntimeThreadCreateInput): Promise<RuntimeThreadRecord>;
  listThreads(): Promise<RuntimeThreadRecord[]>;
  getThread(threadId: string): Promise<RuntimeThreadRecord>;
  getThreadUsage(threadId: string): Promise<RuntimeUsageTelemetry>;
  resumeThread(threadId: string): Promise<RuntimeThreadRecord>;
  forkThread(threadId: string, input?: RuntimeThreadForkInput): Promise<RuntimeThreadRecord>;
  compactThread(threadId: string, input?: RuntimeThreadCompactInput): Promise<RuntimeThreadRecord>;
  updateThreadMode(threadId: string, input: RuntimeThreadModeInput): Promise<RuntimeThreadRecord>;
  updateThreadModel(threadId: string, input: RuntimeThreadModelInput): Promise<RuntimeThreadRecord>;
  updateThreadThinking(threadId: string, input: RuntimeThreadThinkingInput): Promise<RuntimeThreadRecord>;
  admitGovernedImprovementProposal(
    threadId: string,
    input: RuntimeGovernedImprovementProposalAdmissionInput,
  ): Promise<RuntimeGovernedImprovementProposalAdmissionResult>;
  admitWorkerServicePackageInvocation(
    threadId: string,
    input: RuntimeWorkerServicePackageInvocationAdmissionInput,
  ): Promise<RuntimeWorkerServicePackageInvocationAdmissionResult>;
  admitL1SettlementAttempt(
    threadId: string,
    input: RuntimeL1SettlementAttemptAdmissionInput,
  ): Promise<RuntimeL1SettlementAttemptAdmissionResult>;
  executeCteePrivateWorkspaceAction(
    threadId: string,
    input: RuntimeCteePrivateWorkspaceActionInput,
  ): Promise<RuntimeCteePrivateWorkspaceActionResult>;
  submitTurn(threadId: string, input: RuntimeTurnCreateInput): Promise<RuntimeTurnRecord>;
  listTurns(threadId: string): Promise<RuntimeTurnRecord[]>;
  getTurn(threadId: string, turnId: string): Promise<RuntimeTurnRecord>;
  interruptTurn(threadId: string, turnId: string, input?: RuntimeTurnInterruptInput): Promise<RuntimeTurnRecord>;
  steerTurn(threadId: string, turnId: string, input?: RuntimeTurnSteerInput): Promise<RuntimeTurnRecord>;
  streamThreadEvents(threadId: string, options?: RuntimeEventStreamOptions): AsyncIterable<RuntimeThreadEvent>;
  listSubagents(threadId: string, input?: RuntimeSubagentListInput): Promise<RuntimeSubagentListResult>;
  spawnSubagent(threadId: string, input: RuntimeSubagentSpawnInput): Promise<RuntimeSubagentRecord>;
  waitSubagent(
    threadId: string,
    subagentId: string,
    input?: RuntimeSubagentWaitInput,
  ): Promise<RuntimeSubagentResult>;
  getSubagentResult(threadId: string, subagentId: string): Promise<RuntimeSubagentResult>;
  sendSubagentInput(
    threadId: string,
    subagentId: string,
    input: RuntimeSubagentSendInput,
  ): Promise<RuntimeSubagentRecord>;
  cancelSubagent(
    threadId: string,
    subagentId: string,
    input?: RuntimeSubagentCancelInput,
  ): Promise<RuntimeSubagentResult>;
  resumeSubagent(
    threadId: string,
    subagentId: string,
    input?: RuntimeSubagentResumeInput,
  ): Promise<RuntimeSubagentResult>;
  assignSubagent(
    threadId: string,
    subagentId: string,
    input?: RuntimeSubagentAssignInput,
  ): Promise<RuntimeSubagentRecord>;
  propagateSubagentCancellation(
    threadId: string,
    input?: RuntimeSubagentCancellationPropagationInput,
  ): Promise<RuntimeSubagentCancellationPropagationResult>;
  createAgent(options: AgentOptions): Promise<RuntimeAgentRecord>;
  resumeAgent(agentId: string): Promise<RuntimeAgentRecord>;
  closeAgent(agentId: string): Promise<void>;
  reloadAgent(agentId: string): Promise<RuntimeAgentRecord>;
  listAgents(): Promise<RuntimeAgentRecord[]>;
  getAgent(agentId: string): Promise<RuntimeAgentRecord>;
  archiveAgent(agentId: string): Promise<RuntimeAgentRecord>;
  unarchiveAgent(agentId: string): Promise<RuntimeAgentRecord>;
  deleteAgent(agentId: string): Promise<void>;
  send(agentId: string, prompt: string, options?: SendOptions): Promise<RuntimeRunRecord>;
  plan(agentId: string, prompt: string, options?: PlanOptions): Promise<RuntimeRunRecord>;
  dryRun(agentId: string, prompt: string, options?: DryRunOptions): Promise<RuntimeRunRecord>;
  handoff(agentId: string, prompt: string, options?: HandoffOptions): Promise<RuntimeRunRecord>;
  learn(agentId: string, options: LearnOptions): Promise<RuntimeRunRecord>;
  streamRun(runId: string, options?: { lastEventId?: string }): AsyncIterable<IOISDKMessage>;
  waitRun(runId: string): Promise<IOIRunResult>;
  cancelRun(runId: string): Promise<RuntimeRunRecord>;
  getRun(runId: string): Promise<RuntimeRunRecord>;
  getRunUsage(runId: string): Promise<RuntimeUsageTelemetry>;
  listRuns(agentId?: string): Promise<RuntimeRunRecord[]>;
  listUsage(input?: RuntimeUsageListInput): Promise<RuntimeUsageListResult>;
  createTask(options?: RuntimeTaskCreateOptions): Promise<RuntimeTaskRecord>;
  listTasks(options?: RuntimeTaskListOptions): Promise<RuntimeTaskRecord[]>;
  getTask(taskId: string): Promise<RuntimeTaskRecord>;
  cancelTask(taskId: string): Promise<RuntimeTaskRecord>;
  listJobs(options?: RuntimeJobListOptions): Promise<RuntimeJobRecord[]>;
  getJob(jobId: string): Promise<RuntimeJobRecord>;
  cancelJob(jobId: string): Promise<RuntimeJobRecord>;
  conversation(runId: string): Promise<ConversationMessage[]>;
  listArtifacts(runId: string): Promise<RuntimeArtifact[]>;
  downloadArtifact(runId: string, artifactId: string): Promise<RuntimeArtifact>;
  listConversationArtifacts(input?: { threadId?: string; thread_id?: string }): Promise<ConversationArtifactRecord[]>;
  createConversationArtifact(threadId: string, input: Record<string, unknown>): Promise<{
    artifact: ConversationArtifactRecord;
    receipt?: RuntimeReceipt;
  }>;
  getConversationArtifact(artifactId: string): Promise<ConversationArtifactRecord>;
  listConversationArtifactRevisions(artifactId: string): Promise<ConversationArtifactRevision[]>;
  performConversationArtifactAction(artifactId: string, input: Record<string, unknown>): Promise<ConversationArtifactActionResult>;
  exportTrace(runId: string): Promise<RuntimeTraceBundle>;
  replayTrace(runId: string): AsyncIterable<IOISDKMessage>;
  inspectRun(runId: string): Promise<RuntimeTraceBundle>;
  getRunComputerUseTrace(runId: string): Promise<RuntimeTraceBundle["computerUse"]>;
  getRunComputerUseTrajectory(runId: string): Promise<unknown>;
  getRunComputerUseTrajectoryEval(runId: string): Promise<ComputerUseTrajectoryEvalProjection>;
  getRunComputerUseHarnessImprovementPlan(runId: string): Promise<ComputerUseHarnessImprovementPlan>;
  getRunComputerUseBenchmarkCase(runId: string): Promise<ComputerUseBenchmarkCaseExport>;
  discoverComputerUseBrowsers(
    options?: RuntimeComputerUseBrowserDiscoveryOptions,
  ): Promise<RuntimeComputerUseBrowserDiscoveryReport>;
  discoverComputerUseProviders(): Promise<RuntimeComputerUseProviderRegistryReport>;
  scorecard(runId: string): Promise<RuntimeScorecard>;
  listModels(): Promise<RuntimeModelCatalogEntry[]>;
  listModelCapabilities(): Promise<ModelCapabilityContract[]>;
  listRepositories(): Promise<Array<{ url: string; source: string; status: string }>>;
  getAccount(): Promise<RuntimeAccountProfile>;
  listRuntimeNodes(): Promise<RuntimeNodeProfile[]>;
  listTools(options?: RuntimeToolListOptions): Promise<RuntimeToolCatalogEntry[]>;
  getMcpStatus(options?: RuntimeMcpListOptions): Promise<RuntimeMcpStatus>;
  listMcpServers(options?: RuntimeMcpListOptions): Promise<RuntimeMcpServerEntry[]>;
  listMcpTools(options?: RuntimeMcpListOptions): Promise<RuntimeMcpToolEntry[]>;
  searchMcpTools(input?: RuntimeMcpToolSearchInput): Promise<RuntimeMcpToolSearchResult>;
  getMcpTool(toolId: string, input?: RuntimeMcpToolSearchInput): Promise<RuntimeMcpToolSearchResult>;
  listMcpResources(options?: RuntimeMcpListOptions): Promise<RuntimeMcpResourceEntry[]>;
  listMcpPrompts(options?: RuntimeMcpListOptions): Promise<RuntimeMcpPromptEntry[]>;
  validateMcp(input?: RuntimeMcpValidationInput): Promise<RuntimeMcpValidationResult>;
  importMcp(input?: RuntimeMcpServerMutationInput): Promise<RuntimeMcpStatus>;
  addMcpServer(input?: RuntimeMcpServerMutationInput): Promise<RuntimeMcpStatus>;
  removeMcpServer(serverId: string, input?: RuntimeMcpServerMutationInput): Promise<RuntimeMcpStatus>;
  enableMcpServer(serverId: string, input?: RuntimeMcpServerControlInput): Promise<RuntimeMcpStatus>;
  disableMcpServer(serverId: string, input?: RuntimeMcpServerControlInput): Promise<RuntimeMcpStatus>;
  invokeMcpTool(input?: RuntimeMcpToolInvokeInput): Promise<RuntimeMcpInvocationResult>;
  serveMcpRpc(
    input: RuntimeMcpServeRpcInput,
  ): Promise<RuntimeMcpJsonRpcResponse | RuntimeMcpJsonRpcResponse[] | null>;
  threadMcpStatus(threadId: string, input?: RuntimeThreadMcpInput): Promise<RuntimeMcpStatus>;
  importThreadMcp(threadId: string, input?: RuntimeMcpServerMutationInput): Promise<RuntimeMcpStatus>;
  addThreadMcpServer(threadId: string, input?: RuntimeMcpServerMutationInput): Promise<RuntimeMcpStatus>;
  removeThreadMcpServer(
    threadId: string,
    serverId: string,
    input?: RuntimeMcpServerMutationInput,
  ): Promise<RuntimeMcpStatus>;
  validateThreadMcp(
    threadId: string,
    input?: RuntimeThreadMcpInput,
  ): Promise<RuntimeMcpValidationResult>;
  searchThreadMcpTools(
    threadId: string,
    input?: RuntimeMcpToolSearchInput,
  ): Promise<RuntimeMcpToolSearchResult>;
  getThreadMcpTool(
    threadId: string,
    toolId: string,
    input?: RuntimeMcpToolSearchInput,
  ): Promise<RuntimeMcpToolSearchResult>;
  enableThreadMcpServer(
    threadId: string,
    serverId: string,
    input?: RuntimeMcpServerControlInput,
  ): Promise<RuntimeMcpStatus>;
  disableThreadMcpServer(
    threadId: string,
    serverId: string,
    input?: RuntimeMcpServerControlInput,
  ): Promise<RuntimeMcpStatus>;
  invokeThreadMcpTool(
    threadId: string,
    input?: RuntimeMcpToolInvokeInput,
  ): Promise<RuntimeMcpInvocationResult>;
  threadMcpServeRpc(
    threadId: string,
    message: RuntimeMcpJsonRpcRequest | RuntimeMcpJsonRpcRequest[],
    options?: RuntimeMcpListOptions,
  ): Promise<RuntimeMcpJsonRpcResponse | RuntimeMcpJsonRpcResponse[] | null>;
  getMemoryStatus(options?: RuntimeMemoryStatusOptions): Promise<RuntimeMemoryStatus>;
  validateMemory(input?: RuntimeMemoryValidationInput): Promise<RuntimeMemoryValidationResult>;
  threadMemoryStatus(threadId: string, input?: RuntimeThreadMemoryInput): Promise<RuntimeMemoryStatus>;
  validateThreadMemory(
    threadId: string,
    input?: RuntimeThreadMemoryInput,
  ): Promise<RuntimeMemoryValidationResult>;
  rememberThreadMemory(threadId: string, input: RuntimeThreadMemoryWriteInput): Promise<RememberMemoryResult>;
  updateThreadMemory(
    threadId: string,
    memoryId: string,
    input: RuntimeThreadMemoryEditInput,
  ): Promise<RememberMemoryResult>;
  deleteThreadMemory(
    threadId: string,
    memoryId: string,
    input?: RuntimeThreadMemoryDeleteInput,
  ): Promise<RememberMemoryResult>;
  invokeThreadTool(
    threadId: string,
    toolId: string,
    input?: RuntimeThreadToolInvokeInput,
  ): Promise<RuntimeThreadToolInvocationResult>;
  listThreadWorkspaceSnapshots(threadId: string): Promise<RuntimeWorkspaceSnapshotListResult>;
  previewThreadWorkspaceRestore(
    threadId: string,
    snapshotId: string,
    input?: RuntimeWorkspaceRestorePreviewInput,
  ): Promise<RuntimeWorkspaceRestorePreviewResult>;
  applyThreadWorkspaceRestore(
    threadId: string,
    snapshotId: string,
    input?: RuntimeWorkspaceRestoreApplyInput,
  ): Promise<RuntimeWorkspaceRestoreApplyResult>;
  executeThreadDiagnosticsRepairDecision(
    threadId: string,
    decisionId: string,
    input?: RuntimeDiagnosticsRepairDecisionExecuteInput,
  ): Promise<RuntimeDiagnosticsRepairDecisionExecutionResult>;
  rememberMemory(agentId: string, input: RememberMemoryInput): Promise<RememberMemoryResult>;
  listMemory(agentId: string, options?: MemoryListOptions): Promise<AgentMemoryProjection>;
  updateMemory(agentId: string, memoryId: string, input: UpdateMemoryRecordInput): Promise<RememberMemoryResult>;
  deleteMemory(agentId: string, memoryId: string, input?: DeleteMemoryRecordInput): Promise<RememberMemoryResult>;
  getMemoryPolicy(agentId: string, options?: { threadId?: string }): Promise<AgentMemoryPolicy>;
  setMemoryPolicy(agentId: string, input: MemoryPolicyInput): Promise<MemoryPolicyUpdateResult>;
  memoryPath(agentId: string, options?: { threadId?: string }): Promise<AgentMemoryPathProjection>;
}

export interface RuntimeSubstrateClientOptions {
  cwd?: string;
  checkpointDir?: string;
  endpoint?: string;
  apiKey?: string;
  headers?: Record<string, string>;
}

export function createRuntimeSubstrateClient(
  options: RuntimeSubstrateClientOptions = {},
): RuntimeSubstrateClient {
  return new DaemonRuntimeSubstrateClient(options);
}


export class DaemonRuntimeSubstrateClient implements RuntimeSubstrateClient {
  private readonly endpoint?: string;
  private readonly apiKey?: string;
  private readonly headers: Record<string, string>;

  constructor(options: RuntimeSubstrateClientOptions = {}) {
    this.endpoint = options.endpoint ?? process.env.IOI_DAEMON_ENDPOINT;
    this.apiKey = options.apiKey ?? process.env.IOI_DAEMON_TOKEN;
    this.headers = options.headers ?? {};
  }

  async createThread(input: RuntimeThreadCreateInput = {}): Promise<RuntimeThreadRecord> {
    return this.request("createThread", "POST", "/v1/threads", input);
  }

  async listThreads(): Promise<RuntimeThreadRecord[]> {
    return this.request("listThreads", "GET", "/v1/threads");
  }

  async getThread(threadId: string): Promise<RuntimeThreadRecord> {
    return this.request("getThread", "GET", `/v1/threads/${encodePath(threadId)}`);
  }

  async getThreadUsage(threadId: string): Promise<RuntimeUsageTelemetry> {
    return this.request("getThreadUsage", "GET", `/v1/threads/${encodePath(threadId)}/usage`);
  }

  async resumeThread(threadId: string): Promise<RuntimeThreadRecord> {
    return this.request("resumeThread", "POST", `/v1/threads/${encodePath(threadId)}/resume`);
  }

  async forkThread(threadId: string, input: RuntimeThreadForkInput = {}): Promise<RuntimeThreadRecord> {
    return this.request("forkThread", "POST", `/v1/threads/${encodePath(threadId)}/fork`, {
      source: "sdk_client",
      ...input,
    });
  }

  async compactThread(
    threadId: string,
    input: RuntimeThreadCompactInput = {},
  ): Promise<RuntimeThreadRecord> {
    return this.request(
      "compactThread",
      "POST",
      `/v1/threads/${encodePath(threadId)}/compact`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async updateThreadMode(
    threadId: string,
    input: RuntimeThreadModeInput,
  ): Promise<RuntimeThreadRecord> {
    return this.request(
      "updateThreadMode",
      "POST",
      `/v1/threads/${encodePath(threadId)}/mode`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async updateThreadModel(
    threadId: string,
    input: RuntimeThreadModelInput,
  ): Promise<RuntimeThreadRecord> {
    return this.request(
      "updateThreadModel",
      "POST",
      `/v1/threads/${encodePath(threadId)}/model`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async updateThreadThinking(
    threadId: string,
    input: RuntimeThreadThinkingInput,
  ): Promise<RuntimeThreadRecord> {
    return this.request(
      "updateThreadThinking",
      "POST",
      `/v1/threads/${encodePath(threadId)}/thinking`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async admitGovernedImprovementProposal(
    threadId: string,
    input: RuntimeGovernedImprovementProposalAdmissionInput,
  ): Promise<RuntimeGovernedImprovementProposalAdmissionResult> {
    return this.request(
      "admitGovernedImprovementProposal",
      "POST",
      `/v1/threads/${encodePath(threadId)}/governed-improvement-proposals`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async admitWorkerServicePackageInvocation(
    threadId: string,
    input: RuntimeWorkerServicePackageInvocationAdmissionInput,
  ): Promise<RuntimeWorkerServicePackageInvocationAdmissionResult> {
    return this.request(
      "admitWorkerServicePackageInvocation",
      "POST",
      `/v1/threads/${encodePath(threadId)}/worker-service-package-invocations`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async admitL1SettlementAttempt(
    threadId: string,
    input: RuntimeL1SettlementAttemptAdmissionInput,
  ): Promise<RuntimeL1SettlementAttemptAdmissionResult> {
    return this.request(
      "admitL1SettlementAttempt",
      "POST",
      `/v1/threads/${encodePath(threadId)}/l1-settlement-attempts`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async executeCteePrivateWorkspaceAction(
    threadId: string,
    input: RuntimeCteePrivateWorkspaceActionInput,
  ): Promise<RuntimeCteePrivateWorkspaceActionResult> {
    return this.request(
      "executeCteePrivateWorkspaceAction",
      "POST",
      `/v1/threads/${encodePath(threadId)}/ctee-private-workspace-actions`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async submitTurn(threadId: string, input: RuntimeTurnCreateInput): Promise<RuntimeTurnRecord> {
    return this.request("submitTurn", "POST", `/v1/threads/${encodePath(threadId)}/turns`, input);
  }

  async listTurns(threadId: string): Promise<RuntimeTurnRecord[]> {
    return this.request("listTurns", "GET", `/v1/threads/${encodePath(threadId)}/turns`);
  }

  async getTurn(threadId: string, turnId: string): Promise<RuntimeTurnRecord> {
    return this.request(
      "getTurn",
      "GET",
      `/v1/threads/${encodePath(threadId)}/turns/${encodePath(turnId)}`,
    );
  }

  async interruptTurn(
    threadId: string,
    turnId: string,
    input: RuntimeTurnInterruptInput = {},
  ): Promise<RuntimeTurnRecord> {
    return this.request(
      "interruptTurn",
      "POST",
      `/v1/threads/${encodePath(threadId)}/turns/${encodePath(turnId)}/interrupt`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async steerTurn(
    threadId: string,
    turnId: string,
    input: RuntimeTurnSteerInput = {},
  ): Promise<RuntimeTurnRecord> {
    return this.request(
      "steerTurn",
      "POST",
      `/v1/threads/${encodePath(threadId)}/turns/${encodePath(turnId)}/steer`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async *streamThreadEvents(
    threadId: string,
    options: RuntimeEventStreamOptions = {},
  ): AsyncIterable<RuntimeThreadEvent> {
    const events = await this.requestRuntimeEvents(
      "streamThreadEvents",
      `/v1/threads/${encodePath(threadId)}/events${runtimeEventQuery(options)}`,
    );
    for (const event of events) {
      options.signal?.throwIfAborted();
      yield runtimeThreadEventFromEnvelope(event);
    }
  }

  async listSubagents(
    threadId: string,
    input: RuntimeSubagentListInput = {},
  ): Promise<RuntimeSubagentListResult> {
    return this.request(
      "listSubagents",
      "GET",
      `/v1/threads/${encodePath(threadId)}/subagents${subagentListQuery(input)}`,
    );
  }

  async spawnSubagent(
    threadId: string,
    input: RuntimeSubagentSpawnInput,
  ): Promise<RuntimeSubagentRecord> {
    return this.request(
      "spawnSubagent",
      "POST",
      `/v1/threads/${encodePath(threadId)}/subagents`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async waitSubagent(
    threadId: string,
    subagentId: string,
    input: RuntimeSubagentWaitInput = {},
  ): Promise<RuntimeSubagentResult> {
    return this.request(
      "waitSubagent",
      "POST",
      `/v1/threads/${encodePath(threadId)}/subagents/${encodePath(subagentId)}/wait`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async getSubagentResult(threadId: string, subagentId: string): Promise<RuntimeSubagentResult> {
    return this.request(
      "getSubagentResult",
      "GET",
      `/v1/threads/${encodePath(threadId)}/subagents/${encodePath(subagentId)}/result`,
    );
  }

  async sendSubagentInput(
    threadId: string,
    subagentId: string,
    input: RuntimeSubagentSendInput,
  ): Promise<RuntimeSubagentRecord> {
    return this.request(
      "sendSubagentInput",
      "POST",
      `/v1/threads/${encodePath(threadId)}/subagents/${encodePath(subagentId)}/input`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async cancelSubagent(
    threadId: string,
    subagentId: string,
    input: RuntimeSubagentCancelInput = {},
  ): Promise<RuntimeSubagentResult> {
    return this.request(
      "cancelSubagent",
      "POST",
      `/v1/threads/${encodePath(threadId)}/subagents/${encodePath(subagentId)}/cancel`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async resumeSubagent(
    threadId: string,
    subagentId: string,
    input: RuntimeSubagentResumeInput = {},
  ): Promise<RuntimeSubagentResult> {
    return this.request(
      "resumeSubagent",
      "POST",
      `/v1/threads/${encodePath(threadId)}/subagents/${encodePath(subagentId)}/resume`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async assignSubagent(
    threadId: string,
    subagentId: string,
    input: RuntimeSubagentAssignInput = {},
  ): Promise<RuntimeSubagentRecord> {
    return this.request(
      "assignSubagent",
      "POST",
      `/v1/threads/${encodePath(threadId)}/subagents/${encodePath(subagentId)}/assign`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async propagateSubagentCancellation(
    threadId: string,
    input: RuntimeSubagentCancellationPropagationInput = {},
  ): Promise<RuntimeSubagentCancellationPropagationResult> {
    return this.request(
      "propagateSubagentCancellation",
      "POST",
      `/v1/threads/${encodePath(threadId)}/subagents/cancel`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async createAgent(options: AgentOptions): Promise<RuntimeAgentRecord> {
    return this.request("createAgent", "POST", "/v1/agents", { options });
  }

  async resumeAgent(agentId: string): Promise<RuntimeAgentRecord> {
    return this.request("resumeAgent", "POST", `/v1/agents/${encodePath(agentId)}/resume`);
  }

  async closeAgent(agentId: string): Promise<void> {
    await this.request("closeAgent", "POST", `/v1/agents/${encodePath(agentId)}/close`);
  }

  async reloadAgent(agentId: string): Promise<RuntimeAgentRecord> {
    return this.request("reloadAgent", "POST", `/v1/agents/${encodePath(agentId)}/reload`);
  }

  async listAgents(): Promise<RuntimeAgentRecord[]> {
    return this.request("listAgents", "GET", "/v1/agents");
  }

  async getAgent(agentId: string): Promise<RuntimeAgentRecord> {
    return this.request("getAgent", "GET", `/v1/agents/${encodePath(agentId)}`);
  }

  async archiveAgent(agentId: string): Promise<RuntimeAgentRecord> {
    return this.request("archiveAgent", "POST", `/v1/agents/${encodePath(agentId)}/archive`);
  }

  async unarchiveAgent(agentId: string): Promise<RuntimeAgentRecord> {
    return this.request("unarchiveAgent", "POST", `/v1/agents/${encodePath(agentId)}/unarchive`);
  }

  async deleteAgent(agentId: string): Promise<void> {
    await this.request("deleteAgent", "DELETE", `/v1/agents/${encodePath(agentId)}`);
  }

  async send(agentId: string, prompt: string, options: SendOptions = {}): Promise<RuntimeRunRecord> {
    return this.createRun("send", agentId, prompt, options);
  }

  async plan(agentId: string, prompt: string, options: PlanOptions = {}): Promise<RuntimeRunRecord> {
    return this.createRun("plan", agentId, prompt, options);
  }

  async dryRun(agentId: string, prompt: string, options: DryRunOptions = {}): Promise<RuntimeRunRecord> {
    return this.createRun("dry_run", agentId, prompt, options);
  }

  async handoff(agentId: string, prompt: string, options: HandoffOptions = {}): Promise<RuntimeRunRecord> {
    return this.createRun("handoff", agentId, prompt, options);
  }

  async learn(agentId: string, options: LearnOptions): Promise<RuntimeRunRecord> {
    return this.request("learn", "POST", `/v1/agents/${encodePath(agentId)}/runs`, {
      mode: "learn",
      options,
    });
  }

  async *streamRun(runId: string, options: { lastEventId?: string } = {}): AsyncIterable<IOISDKMessage> {
    const query = options.lastEventId ? `?lastEventId=${encodeURIComponent(options.lastEventId)}` : "";
    const events = await this.requestEvents("streamRun", `/v1/runs/${encodePath(runId)}/events${query}`);
    for (const event of eventsFromResponse(events)) {
      yield event;
    }
  }

  async waitRun(runId: string): Promise<IOIRunResult> {
    return this.request("waitRun", "GET", `/v1/runs/${encodePath(runId)}/wait`);
  }

  async cancelRun(runId: string): Promise<RuntimeRunRecord> {
    return this.request("cancelRun", "POST", `/v1/runs/${encodePath(runId)}/cancel`);
  }

  async getRun(runId: string): Promise<RuntimeRunRecord> {
    return this.request("getRun", "GET", `/v1/runs/${encodePath(runId)}`);
  }

  async getRunUsage(runId: string): Promise<RuntimeUsageTelemetry> {
    return this.request("getRunUsage", "GET", `/v1/runs/${encodePath(runId)}/usage`);
  }

  async listRuns(agentId?: string): Promise<RuntimeRunRecord[]> {
    const query = agentId ? `?agentId=${encodeURIComponent(agentId)}` : "";
    return this.request("listRuns", "GET", `/v1/runs${query}`);
  }

  async listUsage(input: RuntimeUsageListInput = {}): Promise<RuntimeUsageListResult> {
    const query = runtimeUsageListQuery(input);
    return this.request("listUsage", "GET", `/v1/usage${query}`);
  }

  async createTask(options: RuntimeTaskCreateOptions = {}): Promise<RuntimeTaskRecord> {
    return this.request("createTask", "POST", "/v1/tasks", options);
  }

  async listTasks(options: RuntimeTaskListOptions = {}): Promise<RuntimeTaskRecord[]> {
    const params = new URLSearchParams();
    const agentId = options.agent_id;
    if (agentId) params.set("agent_id", agentId);
    if (options.status) params.set("status", options.status);
    const query = params.toString() ? `?${params}` : "";
    return this.request("listTasks", "GET", `/v1/tasks${query}`);
  }

  async getTask(taskId: string): Promise<RuntimeTaskRecord> {
    return this.request("getTask", "GET", `/v1/tasks/${encodePath(taskId)}`);
  }

  async cancelTask(taskId: string): Promise<RuntimeTaskRecord> {
    return this.request("cancelTask", "POST", `/v1/tasks/${encodePath(taskId)}/cancel`);
  }

  async listJobs(options: RuntimeJobListOptions = {}): Promise<RuntimeJobRecord[]> {
    const params = new URLSearchParams();
    const agentId = options.agent_id;
    if (agentId) params.set("agent_id", agentId);
    if (options.status) params.set("status", options.status);
    const query = params.toString() ? `?${params}` : "";
    return this.request("listJobs", "GET", `/v1/jobs${query}`);
  }

  async getJob(jobId: string): Promise<RuntimeJobRecord> {
    return this.request("getJob", "GET", `/v1/jobs/${encodePath(jobId)}`);
  }

  async cancelJob(jobId: string): Promise<RuntimeJobRecord> {
    return this.request("cancelJob", "POST", `/v1/jobs/${encodePath(jobId)}/cancel`);
  }

  async conversation(runId: string): Promise<ConversationMessage[]> {
    return this.request("conversation", "GET", `/v1/runs/${encodePath(runId)}/conversation`);
  }

  async listArtifacts(runId: string): Promise<RuntimeArtifact[]> {
    return this.request("listArtifacts", "GET", `/v1/runs/${encodePath(runId)}/artifacts`);
  }

  async downloadArtifact(runId: string, artifactId: string): Promise<RuntimeArtifact> {
    return this.request(
      "downloadArtifact",
      "GET",
      `/v1/runs/${encodePath(runId)}/artifacts/${encodePath(artifactId)}`,
    );
  }

  async listConversationArtifacts(input: { threadId?: string; thread_id?: string } = {}): Promise<ConversationArtifactRecord[]> {
    const threadId = input.threadId ?? input.thread_id;
    const query = threadId ? `?threadId=${encodeURIComponent(threadId)}` : "";
    return this.request("listConversationArtifacts", "GET", `/v1/conversation-artifacts${query}`);
  }

  async createConversationArtifact(threadId: string, input: Record<string, unknown>): Promise<{
    artifact: ConversationArtifactRecord;
    receipt?: RuntimeReceipt;
  }> {
    return this.request(
      "createConversationArtifact",
      "POST",
      `/v1/threads/${encodePath(threadId)}/artifacts`,
      input,
    );
  }

  async getConversationArtifact(artifactId: string): Promise<ConversationArtifactRecord> {
    return this.request("getConversationArtifact", "GET", `/v1/conversation-artifacts/${encodePath(artifactId)}`);
  }

  async listConversationArtifactRevisions(artifactId: string): Promise<ConversationArtifactRevision[]> {
    return this.request(
      "listConversationArtifactRevisions",
      "GET",
      `/v1/conversation-artifacts/${encodePath(artifactId)}/revisions`,
    );
  }

  async performConversationArtifactAction(
    artifactId: string,
    input: Record<string, unknown>,
  ): Promise<ConversationArtifactActionResult> {
    return this.request(
      "performConversationArtifactAction",
      "POST",
      `/v1/conversation-artifacts/${encodePath(artifactId)}/actions`,
      input,
    );
  }

  async exportTrace(runId: string): Promise<RuntimeTraceBundle> {
    return this.request("exportTrace", "GET", `/v1/runs/${encodePath(runId)}/trace`);
  }

  async *replayTrace(runId: string): AsyncIterable<IOISDKMessage> {
    const events = await this.requestEvents("replayTrace", `/v1/runs/${encodePath(runId)}/replay`);
    for (const event of eventsFromResponse(events)) {
      yield event;
    }
  }

  async inspectRun(runId: string): Promise<RuntimeTraceBundle> {
    return this.request("inspectRun", "GET", `/v1/runs/${encodePath(runId)}/inspect`);
  }

  async getRunComputerUseTrace(runId: string): Promise<RuntimeTraceBundle["computerUse"]> {
    return this.request(
      "getRunComputerUseTrace",
      "GET",
      `/v1/runs/${encodePath(runId)}/computer-use/trace`,
    );
  }

  async getRunComputerUseTrajectory(runId: string): Promise<unknown> {
    return this.request(
      "getRunComputerUseTrajectory",
      "GET",
      `/v1/runs/${encodePath(runId)}/computer-use/trajectory`,
    );
  }

  async getRunComputerUseTrajectoryEval(
    runId: string,
  ): Promise<ComputerUseTrajectoryEvalProjection> {
    const trace = await this.getRunComputerUseTrace(runId);
    return evaluateComputerUseTrajectory({ trace });
  }

  async getRunComputerUseHarnessImprovementPlan(
    runId: string,
  ): Promise<ComputerUseHarnessImprovementPlan> {
    const trace = await this.getRunComputerUseTrace(runId);
    const evalProjection = evaluateComputerUseTrajectory({ trace });
    return planComputerUseHarnessImprovement({ trace, eval: evalProjection });
  }

  async getRunComputerUseBenchmarkCase(
    runId: string,
  ): Promise<ComputerUseBenchmarkCaseExport> {
    const trace = await this.getRunComputerUseTrace(runId);
    const evalProjection = evaluateComputerUseTrajectory({ trace });
    const improvementPlan = planComputerUseHarnessImprovement({ trace, eval: evalProjection });
    return exportComputerUseBenchmarkCase({
      trace,
      eval: evalProjection,
      improvement_plan: improvementPlan,
    });
  }

  async discoverComputerUseBrowsers(
    options: RuntimeComputerUseBrowserDiscoveryOptions = {},
  ): Promise<RuntimeComputerUseBrowserDiscoveryReport> {
    return this.request(
      "discoverComputerUseBrowsers",
      "GET",
      `/v1/computer-use/browser-discovery${computerUseBrowserDiscoveryQuery(options)}`,
    );
  }

  async discoverComputerUseProviders(): Promise<RuntimeComputerUseProviderRegistryReport> {
    return this.request(
      "discoverComputerUseProviders",
      "GET",
      "/v1/computer-use/providers",
    );
  }

  async scorecard(runId: string): Promise<RuntimeScorecard> {
    return this.request("scorecard", "GET", `/v1/runs/${encodePath(runId)}/scorecard`);
  }

  async listModels(): Promise<RuntimeModelCatalogEntry[]> {
    return this.request("listModels", "GET", "/v1/models");
  }

  async listModelCapabilities(): Promise<ModelCapabilityContract[]> {
    return this.request("listModelCapabilities", "GET", "/v1/model-capabilities");
  }

  async listRepositories(): Promise<Array<{ url: string; source: string; status: string }>> {
    return this.request("listRepositories", "GET", "/v1/repositories");
  }

  async getAccount(): Promise<RuntimeAccountProfile> {
    return this.request("getAccount", "GET", "/v1/account");
  }

  async listRuntimeNodes(): Promise<RuntimeNodeProfile[]> {
    return this.request("listRuntimeNodes", "GET", "/v1/runtime/nodes");
  }

  async listTools(options: RuntimeToolListOptions = {}): Promise<RuntimeToolCatalogEntry[]> {
    return normalizeRuntimeToolCatalogEntries(
      await this.request("listTools", "GET", `/v1/tools${toolListQuery(options)}`),
    );
  }

  async getMcpStatus(options: RuntimeMcpListOptions = {}): Promise<RuntimeMcpStatus> {
    return this.request("getMcpStatus", "GET", `/v1/mcp${mcpListQuery(options)}`);
  }

  async listMcpServers(options: RuntimeMcpListOptions = {}): Promise<RuntimeMcpServerEntry[]> {
    return this.request("listMcpServers", "GET", `/v1/mcp/servers${mcpListQuery(options)}`);
  }

  async listMcpTools(options: RuntimeMcpListOptions = {}): Promise<RuntimeMcpToolEntry[]> {
    return this.request("listMcpTools", "GET", `/v1/mcp/tools${mcpListQuery(options)}`);
  }

  async searchMcpTools(input: RuntimeMcpToolSearchInput = {}): Promise<RuntimeMcpToolSearchResult> {
    return this.request("searchMcpTools", "GET", `/v1/mcp/tools/search${mcpListQuery(input)}`);
  }

  async getMcpTool(
    toolId: string,
    input: RuntimeMcpToolSearchInput = {},
  ): Promise<RuntimeMcpToolSearchResult> {
    return this.request("getMcpTool", "GET", `/v1/mcp/tools/${encodePath(toolId)}${mcpListQuery(input)}`);
  }

  async listMcpResources(options: RuntimeMcpListOptions = {}): Promise<RuntimeMcpResourceEntry[]> {
    return this.request("listMcpResources", "GET", `/v1/mcp/resources${mcpListQuery(options)}`);
  }

  async listMcpPrompts(options: RuntimeMcpListOptions = {}): Promise<RuntimeMcpPromptEntry[]> {
    return this.request("listMcpPrompts", "GET", `/v1/mcp/prompts${mcpListQuery(options)}`);
  }

  async validateMcp(input: RuntimeMcpValidationInput = {}): Promise<RuntimeMcpValidationResult> {
    return this.request("validateMcp", "POST", "/v1/mcp/validate", {
      source: "sdk_client",
      ...input,
    });
  }

  async importMcp(input: RuntimeMcpServerMutationInput = {}): Promise<RuntimeMcpStatus> {
    return this.request("importMcp", "POST", "/v1/mcp/import", {
      source: "sdk_client",
      ...input,
    });
  }

  async addMcpServer(input: RuntimeMcpServerMutationInput = {}): Promise<RuntimeMcpStatus> {
    return this.request("addMcpServer", "POST", "/v1/mcp/servers", {
      source: "sdk_client",
      ...input,
    });
  }

  async removeMcpServer(
    serverId: string,
    input: RuntimeMcpServerMutationInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.request(
      "removeMcpServer",
      "DELETE",
      `/v1/mcp/servers/${encodePath(serverId)}`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async enableMcpServer(
    serverId: string,
    input: RuntimeMcpServerControlInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.request(
      "enableMcpServer",
      "POST",
      `/v1/mcp/servers/${encodePath(serverId)}/enable`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async disableMcpServer(
    serverId: string,
    input: RuntimeMcpServerControlInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.request(
      "disableMcpServer",
      "POST",
      `/v1/mcp/servers/${encodePath(serverId)}/disable`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async invokeMcpTool(input: RuntimeMcpToolInvokeInput = {}): Promise<RuntimeMcpInvocationResult> {
    const toolId = input.tool_id ?? `${input.server_id ?? "mcp"}.${input.tool_name ?? input.tool ?? "tool"}`;
    return this.request(
      "invokeMcpTool",
      "POST",
      `/v1/mcp/tools/${encodePath(toolId)}/invoke`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async serveMcpRpc(
    input: RuntimeMcpServeRpcInput,
  ): Promise<RuntimeMcpJsonRpcResponse | RuntimeMcpJsonRpcResponse[] | null> {
    const { message, ...options } = input;
    return this.request("serveMcpRpc", "POST", `/v1/mcp/serve${mcpListQuery(options)}`, message);
  }

  async threadMcpStatus(
    threadId: string,
    input: RuntimeThreadMcpInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.request(
      "threadMcpStatus",
      "POST",
      `/v1/threads/${encodePath(threadId)}/mcp/status`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async importThreadMcp(
    threadId: string,
    input: RuntimeMcpServerMutationInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.request(
      "importThreadMcp",
      "POST",
      `/v1/threads/${encodePath(threadId)}/mcp/import`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async addThreadMcpServer(
    threadId: string,
    input: RuntimeMcpServerMutationInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.request(
      "addThreadMcpServer",
      "POST",
      `/v1/threads/${encodePath(threadId)}/mcp/servers`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async removeThreadMcpServer(
    threadId: string,
    serverId: string,
    input: RuntimeMcpServerMutationInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.request(
      "removeThreadMcpServer",
      "DELETE",
      `/v1/threads/${encodePath(threadId)}/mcp/servers/${encodePath(serverId)}`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async validateThreadMcp(
    threadId: string,
    input: RuntimeThreadMcpInput = {},
  ): Promise<RuntimeMcpValidationResult> {
    return this.request(
      "validateThreadMcp",
      "POST",
      `/v1/threads/${encodePath(threadId)}/mcp/validate`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async searchThreadMcpTools(
    threadId: string,
    input: RuntimeMcpToolSearchInput = {},
  ): Promise<RuntimeMcpToolSearchResult> {
    return this.request(
      "searchThreadMcpTools",
      "GET",
      `/v1/threads/${encodePath(threadId)}/mcp/tools/search${mcpListQuery(input)}`,
    );
  }

  async getThreadMcpTool(
    threadId: string,
    toolId: string,
    input: RuntimeMcpToolSearchInput = {},
  ): Promise<RuntimeMcpToolSearchResult> {
    return this.request(
      "getThreadMcpTool",
      "GET",
      `/v1/threads/${encodePath(threadId)}/mcp/tools/${encodePath(toolId)}${mcpListQuery(input)}`,
    );
  }

  async enableThreadMcpServer(
    threadId: string,
    serverId: string,
    input: RuntimeMcpServerControlInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.request(
      "enableThreadMcpServer",
      "POST",
      `/v1/threads/${encodePath(threadId)}/mcp/servers/${encodePath(serverId)}/enable`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async disableThreadMcpServer(
    threadId: string,
    serverId: string,
    input: RuntimeMcpServerControlInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.request(
      "disableThreadMcpServer",
      "POST",
      `/v1/threads/${encodePath(threadId)}/mcp/servers/${encodePath(serverId)}/disable`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async invokeThreadMcpTool(
    threadId: string,
    input: RuntimeMcpToolInvokeInput = {},
  ): Promise<RuntimeMcpInvocationResult> {
    const toolId = input.tool_id ?? `${input.server_id ?? "mcp"}.${input.tool_name ?? input.tool ?? "tool"}`;
    return this.request(
      "invokeThreadMcpTool",
      "POST",
      `/v1/threads/${encodePath(threadId)}/mcp/tools/${encodePath(toolId)}/invoke`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async threadMcpServeRpc(
    threadId: string,
    message: RuntimeMcpJsonRpcRequest | RuntimeMcpJsonRpcRequest[],
    options: RuntimeMcpListOptions = {},
  ): Promise<RuntimeMcpJsonRpcResponse | RuntimeMcpJsonRpcResponse[] | null> {
    return this.request(
      "threadMcpServeRpc",
      "POST",
      `/v1/threads/${encodePath(threadId)}/mcp/serve${mcpListQuery(options)}`,
      message,
    );
  }

  async getMemoryStatus(options: RuntimeMemoryStatusOptions = {}): Promise<RuntimeMemoryStatus> {
    return this.request("getMemoryStatus", "GET", `/v1/memory${memoryListQuery(options)}`);
  }

  async validateMemory(input: RuntimeMemoryValidationInput = {}): Promise<RuntimeMemoryValidationResult> {
    return this.request("validateMemory", "POST", "/v1/memory/validate", {
      source: "sdk_client",
      ...input,
    });
  }

  async threadMemoryStatus(
    threadId: string,
    input: RuntimeThreadMemoryInput = {},
  ): Promise<RuntimeMemoryStatus> {
    return this.request(
      "threadMemoryStatus",
      "POST",
      `/v1/threads/${encodePath(threadId)}/memory/status`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async validateThreadMemory(
    threadId: string,
    input: RuntimeThreadMemoryInput = {},
  ): Promise<RuntimeMemoryValidationResult> {
    return this.request(
      "validateThreadMemory",
      "POST",
      `/v1/threads/${encodePath(threadId)}/memory/validate`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async rememberThreadMemory(
    threadId: string,
    input: RuntimeThreadMemoryWriteInput,
  ): Promise<RememberMemoryResult> {
    return this.request(
      "rememberThreadMemory",
      "POST",
      `/v1/threads/${encodePath(threadId)}/memory`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async updateThreadMemory(
    threadId: string,
    memoryId: string,
    input: RuntimeThreadMemoryEditInput,
  ): Promise<RememberMemoryResult> {
    return this.request(
      "updateThreadMemory",
      "PATCH",
      `/v1/threads/${encodePath(threadId)}/memory/${encodePath(memoryId)}`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async deleteThreadMemory(
    threadId: string,
    memoryId: string,
    input: RuntimeThreadMemoryDeleteInput = {},
  ): Promise<RememberMemoryResult> {
    return this.request(
      "deleteThreadMemory",
      "DELETE",
      `/v1/threads/${encodePath(threadId)}/memory/${encodePath(memoryId)}`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async invokeThreadTool(
    threadId: string,
    toolId: string,
    input: RuntimeThreadToolInvokeInput = {},
  ): Promise<RuntimeThreadToolInvocationResult> {
    return this.request(
      "invokeThreadTool",
      "POST",
      `/v1/threads/${encodePath(threadId)}/tools/${encodePath(toolId)}/invoke`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async listThreadWorkspaceSnapshots(threadId: string): Promise<RuntimeWorkspaceSnapshotListResult> {
    return this.request(
      "listThreadWorkspaceSnapshots",
      "GET",
      `/v1/threads/${encodePath(threadId)}/snapshots`,
    );
  }

  async previewThreadWorkspaceRestore(
    threadId: string,
    snapshotId: string,
    input: RuntimeWorkspaceRestorePreviewInput = {},
  ): Promise<RuntimeWorkspaceRestorePreviewResult> {
    return this.request(
      "previewThreadWorkspaceRestore",
      "POST",
      `/v1/threads/${encodePath(threadId)}/snapshots/${encodePath(snapshotId)}/restore-preview`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async applyThreadWorkspaceRestore(
    threadId: string,
    snapshotId: string,
    input: RuntimeWorkspaceRestoreApplyInput = {},
  ): Promise<RuntimeWorkspaceRestoreApplyResult> {
    return this.request(
      "applyThreadWorkspaceRestore",
      "POST",
      `/v1/threads/${encodePath(threadId)}/snapshots/${encodePath(snapshotId)}/restore-apply`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async executeThreadDiagnosticsRepairDecision(
    threadId: string,
    decisionId: string,
    input: RuntimeDiagnosticsRepairDecisionExecuteInput = {},
  ): Promise<RuntimeDiagnosticsRepairDecisionExecutionResult> {
    return this.request(
      "executeThreadDiagnosticsRepairDecision",
      "POST",
      `/v1/threads/${encodePath(threadId)}/diagnostics/repair-decisions/${encodePath(decisionId)}/execute`,
      {
        source: "sdk_client",
        ...input,
      },
    );
  }

  async rememberMemory(agentId: string, input: RememberMemoryInput): Promise<RememberMemoryResult> {
    return this.request("rememberMemory", "POST", `/v1/agents/${encodePath(agentId)}/memory`, input);
  }

  async listMemory(agentId: string, options: MemoryListOptions = {}): Promise<AgentMemoryProjection> {
    const query = memoryListQuery(options);
    return this.request("listMemory", "GET", `/v1/agents/${encodePath(agentId)}/memory${query}`);
  }

  async updateMemory(agentId: string, memoryId: string, input: UpdateMemoryRecordInput): Promise<RememberMemoryResult> {
    return this.request("updateMemory", "PATCH", `/v1/agents/${encodePath(agentId)}/memory/${encodePath(memoryId)}`, input);
  }

  async deleteMemory(agentId: string, memoryId: string, input: DeleteMemoryRecordInput = {}): Promise<RememberMemoryResult> {
    return this.request("deleteMemory", "DELETE", `/v1/agents/${encodePath(agentId)}/memory/${encodePath(memoryId)}`, input);
  }

  async getMemoryPolicy(agentId: string, options: { threadId?: string } = {}): Promise<AgentMemoryPolicy> {
    const query = options.threadId ? `?threadId=${encodeURIComponent(options.threadId)}` : "";
    return this.request("getMemoryPolicy", "GET", `/v1/agents/${encodePath(agentId)}/memory/policy${query}`);
  }

  async setMemoryPolicy(agentId: string, input: MemoryPolicyInput): Promise<MemoryPolicyUpdateResult> {
    return this.request("setMemoryPolicy", "PATCH", `/v1/agents/${encodePath(agentId)}/memory/policy`, input);
  }

  async memoryPath(agentId: string, options: { threadId?: string } = {}): Promise<AgentMemoryPathProjection> {
    const query = options.threadId ? `?threadId=${encodeURIComponent(options.threadId)}` : "";
    return this.request("memoryPath", "GET", `/v1/agents/${encodePath(agentId)}/memory/path${query}`);
  }

  private createRun(
    mode: RuntimeRunRecord["mode"],
    agentId: string,
    prompt: string,
    options: SendOptions | PlanOptions | DryRunOptions | HandoffOptions,
  ): Promise<RuntimeRunRecord> {
    return this.request(mode, "POST", `/v1/agents/${encodePath(agentId)}/runs`, {
      mode,
      prompt,
      options,
    });
  }

  private async request<T>(
    sdkMethod: string,
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
    route: string,
    body?: unknown,
  ): Promise<T> {
    const endpoint = this.requireEndpoint(sdkMethod);
    const url = new URL(route.replace(/^\/+/, ""), endpoint);
    const headers: Record<string, string> = {
      accept: "application/json",
      ...this.headers,
    };
    if (body !== undefined) {
      headers["content-type"] = "application/json";
    }
    if (this.apiKey) {
      headers.authorization = `Bearer ${this.apiKey}`;
    }

    let response: Response;
    try {
      response = await fetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (error) {
      throw new IoiAgentError({
        code: "network",
        message: `IOI daemon request failed for ${sdkMethod}.`,
        cause: error,
        details: { method: sdkMethod, endpoint: this.endpoint, route },
      });
    }

    const requestId = response.headers.get("x-request-id") ?? undefined;
    const text = await response.text();
    const parsed = parseDaemonResponseBody(text);
    if (!response.ok) {
      throw errorFromDaemonResponse({
        sdkMethod,
        route,
        status: response.status,
        requestId,
        parsed,
      });
    }
    return parsed as T;
  }

  private async requestEvents(sdkMethod: string, route: string): Promise<IOISDKMessage[]> {
    const endpoint = this.requireEndpoint(sdkMethod);
    const url = new URL(route.replace(/^\/+/, ""), endpoint);
    const headers: Record<string, string> = {
      accept: "text/event-stream, application/json",
      ...this.headers,
    };
    if (this.apiKey) {
      headers.authorization = `Bearer ${this.apiKey}`;
    }

    let response: Response;
    try {
      response = await fetch(url, { method: "GET", headers });
    } catch (error) {
      throw new IoiAgentError({
        code: "network",
        message: `IOI daemon event stream failed for ${sdkMethod}.`,
        cause: error,
        details: { method: sdkMethod, endpoint: this.endpoint, route },
      });
    }

    const requestId = response.headers.get("x-request-id") ?? undefined;
    const text = await response.text();
    if (!response.ok) {
      throw errorFromDaemonResponse({
        sdkMethod,
        route,
        status: response.status,
        requestId,
        parsed: parseDaemonResponseBody(text),
      });
    }
    const contentType = response.headers.get("content-type") ?? "";
    return contentType.includes("text/event-stream")
      ? parseServerSentEvents(text)
      : eventsFromResponse(parseDaemonResponseBody(text) as IOISDKMessage[] | { events: IOISDKMessage[] });
  }

  private async requestRuntimeEvents(sdkMethod: string, route: string): Promise<RuntimeEventEnvelope[]> {
    const endpoint = this.requireEndpoint(sdkMethod);
    const url = new URL(route.replace(/^\/+/, ""), endpoint);
    const headers: Record<string, string> = {
      accept: "text/event-stream, application/json",
      ...this.headers,
    };
    if (this.apiKey) {
      headers.authorization = `Bearer ${this.apiKey}`;
    }

    let response: Response;
    try {
      response = await fetch(url, { method: "GET", headers });
    } catch (error) {
      throw new IoiAgentError({
        code: "network",
        message: `IOI daemon runtime event stream failed for ${sdkMethod}.`,
        cause: error,
        details: { method: sdkMethod, endpoint: this.endpoint, route },
      });
    }

    const requestId = response.headers.get("x-request-id") ?? undefined;
    const text = await response.text();
    if (!response.ok) {
      throw errorFromDaemonResponse({
        sdkMethod,
        route,
        status: response.status,
        requestId,
        parsed: parseDaemonResponseBody(text),
      });
    }
    const contentType = response.headers.get("content-type") ?? "";
    return contentType.includes("text/event-stream")
      ? parseServerSentRuntimeEvents(text)
      : runtimeEventsFromResponse(parseDaemonResponseBody(text));
  }

  private requireEndpoint(method: string): URL {
    if (!this.endpoint) {
      throw this.unavailableError(method);
    }
    try {
      return new URL(this.endpoint.endsWith("/") ? this.endpoint : `${this.endpoint}/`);
    } catch (error) {
      throw new IoiAgentError({
        code: "config",
        message: "IOI_DAEMON_ENDPOINT must be a valid URL.",
        cause: error,
        details: { endpoint: this.endpoint, method },
      });
    }
  }

  private unavailableError(method: string): IoiAgentError {
    return new IoiAgentError({
      code: "external_blocker",
      message:
        "The default IOI SDK client targets the daemon substrate and is fail-closed until the daemon transport is configured.",
      details: {
        method,
        endpointConfigured: Boolean(this.endpoint),
        requiredEnvironment: ["IOI_DAEMON_ENDPOINT"],
      },
    });
  }
}

function encodePath(value: string): string {
  return encodeURIComponent(value);
}

function runtimeUsageListQuery(input: RuntimeUsageListInput = {}): string {
  const params = new URLSearchParams();
  const grouping = input.group_by;
  const agentId = input.agent_id;
  if (grouping) params.set("group_by", grouping);
  if (agentId) params.set("agent_id", agentId);
  const query = params.toString();
  return query ? `?${query}` : "";
}

function memoryListQuery(options: MemoryListOptions = {}): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(options)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

function toolListQuery(options: RuntimeToolListOptions = {}): string {
  const params = new URLSearchParams();
  if (options.pack) params.set("pack", options.pack);
  const text = params.toString();
  return text ? `?${text}` : "";
}

function computerUseBrowserDiscoveryQuery(
  options: RuntimeComputerUseBrowserDiscoveryOptions = {},
): string {
  const params = new URLSearchParams();
  if (options.probe !== undefined) params.set("probe", String(options.probe));
  const includeTabs = options.includeTabs ?? options.include_tabs;
  if (includeTabs !== undefined) params.set("include_tabs", String(includeTabs));
  const revealTabTitles = options.revealTabTitles ?? options.reveal_tab_titles;
  if (revealTabTitles !== undefined) {
    params.set("reveal_tab_titles", String(revealTabTitles));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

function mcpListQuery(options: RuntimeMcpListOptions = {}): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(options)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

function normalizeRuntimeToolCatalogEntries(value: unknown): RuntimeToolCatalogEntry[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((tool): tool is RuntimeToolCatalogEntry => Boolean(tool && typeof tool === "object"))
    .map((tool) => normalizeRuntimeToolCatalogEntry(tool));
}

function normalizeRuntimeToolCatalogEntry(tool: RuntimeToolCatalogEntry): RuntimeToolCatalogEntry {
  const raw = tool as RuntimeToolCatalogEntry & Record<string, unknown>;
  const stableToolId = toolString(raw.stableToolId ?? raw.stable_tool_id) ?? "runtime.tool";
  const displayName = toolString(raw.displayName ?? raw.display_name) ?? stableToolId;
  const primitiveCapabilities = toolStringArray(
    raw.primitiveCapabilities ?? raw.primitive_capabilities,
  );
  const authorityScopeRequirements = toolStringArray(
    raw.authorityScopeRequirements ?? raw.authority_scope_requirements,
  );
  const evidenceRequirements = toolStringArray(raw.evidenceRequirements ?? raw.evidence_requirements);
  const effectClass = toolString(raw.effectClass ?? raw.effect_class) ?? "unknown";
  const riskDomain = toolString(raw.riskDomain ?? raw.risk_domain) ?? "runtime";
  const workflowNodeType = toolString(raw.workflowNodeType ?? raw.workflow_node_type);
  const workflowConfigFields = toolStringArray(raw.workflowConfigFields ?? raw.workflow_config_fields);
  const approvalRequired =
    toolBoolean(raw.approvalRequired ?? raw.approval_required) ??
    runtimeToolRequiresApproval(effectClass, authorityScopeRequirements);
  const credentialReadiness = normalizeRuntimeToolCredentialReadiness(
    raw.credentialReadiness ?? raw.credential_readiness,
    raw.credentialReady ?? raw.credential_ready,
    { stableToolId, riskDomain, effectClass },
  );
  const credentialReady = credentialReadiness.status === "ready" || credentialReadiness.status === "not_required";
  const receiptBehavior = normalizeRuntimeToolReceiptBehavior(
    raw.receiptBehavior ?? raw.receipt_behavior,
    evidenceRequirements,
  );
  const idempotencyBehavior = normalizeRuntimeToolIdempotencyBehavior(
    raw.idempotencyBehavior ?? raw.idempotency_behavior,
    effectClass,
    stableToolId,
  );
  const rateLimitProfile = normalizeRuntimeToolRateLimitProfile(
    raw.rateLimitProfile ?? raw.rate_limit_profile,
    effectClass,
    stableToolId,
  );
  const workflowAvailability = normalizeRuntimeToolAvailability(
    raw.workflowAvailability ?? raw.workflow_availability,
    Boolean(workflowNodeType),
    workflowNodeType ?? null,
    workflowConfigFields,
    workflowNodeType ? null : "No workflow node projection registered.",
  );
  const agentAvailability = normalizeRuntimeToolAvailability(
    raw.agentAvailability ?? raw.agent_availability,
    true,
    null,
    [],
    null,
  );
  const marketplaceExposure = normalizeRuntimeToolMarketplaceExposure(
    raw.marketplaceExposure ?? raw.marketplace_exposure,
    approvalRequired,
    credentialReadiness.status,
    effectClass,
  );

  return {
    ...tool,
    stableToolId,
    stable_tool_id: toolString(raw.stable_tool_id) ?? stableToolId,
    displayName,
    display_name: toolString(raw.display_name) ?? displayName,
    primitiveCapabilities,
    authorityScopeRequirements,
    effectClass,
    riskDomain,
    inputSchema: toolRecord(raw.inputSchema ?? raw.input_schema) ?? { type: "object" },
    outputSchema: toolRecord(raw.outputSchema ?? raw.output_schema) ?? { type: "object" },
    evidenceRequirements,
    credentialReady,
    credentialReadiness,
    approvalRequired,
    approval_required: approvalRequired,
    rateLimitProfile,
    idempotencyBehavior,
    receiptBehavior,
    workflowAvailability,
    agentAvailability,
    marketplaceExposure,
    workflowNodeType,
    workflowConfigFields,
  };
}

function normalizeRuntimeToolCredentialReadiness(
  value: unknown,
  credentialReadyValue: unknown,
  context: { stableToolId: string; riskDomain: string; effectClass: string },
): NonNullable<RuntimeToolCatalogEntry["credentialReadiness"]> {
  const record = toolRecord(value);
  const explicitStatus = toolString(record?.status);
  const explicitReady = toolBoolean(credentialReadyValue);
  let status = explicitStatus;
  if (!status && explicitReady === true) status = "ready";
  if (!status && explicitReady === false) status = "missing";
  if (!status) {
    status = runtimeToolLikelyRequiresCredential(context) ? "unknown" : "not_required";
  }
  return {
    status,
    checkedAt: toolString(record?.checkedAt ?? record?.checked_at) ?? null,
    evidenceRefs: toolStringArray(record?.evidenceRefs ?? record?.evidence_refs),
    reason: toolString(record?.reason) ?? null,
  };
}

function normalizeRuntimeToolRateLimitProfile(
  value: unknown,
  effectClass: string,
  stableToolId: string,
): NonNullable<RuntimeToolCatalogEntry["rateLimitProfile"]> {
  const record = toolRecord(value);
  const readOnly = runtimeToolIsReadOnly(effectClass);
  return {
    policy: toolString(record?.policy) ?? (readOnly ? "unlimited_local_read" : "runtime_governed"),
    scope: toolString(record?.scope) ?? stableToolId,
    maxCalls: toolNumberOrNull(record?.maxCalls ?? record?.max_calls),
    windowMs: toolNumberOrNull(record?.windowMs ?? record?.window_ms),
    burst: toolNumberOrNull(record?.burst),
    evidenceRefs: toolStringArray(record?.evidenceRefs ?? record?.evidence_refs),
  };
}

function normalizeRuntimeToolIdempotencyBehavior(
  value: unknown,
  effectClass: string,
  stableToolId: string,
): NonNullable<RuntimeToolCatalogEntry["idempotencyBehavior"]> {
  const record = toolRecord(value);
  const readOnly = runtimeToolIsReadOnly(effectClass);
  return {
    required: toolBoolean(record?.required) ?? !readOnly,
    strategy:
      toolString(record?.strategy) ??
      (readOnly ? "read_only" : runtimeToolIsExternalEffect(effectClass) ? "caller_or_runtime_key" : "runtime_key"),
    keyScope: toolString(record?.keyScope ?? record?.key_scope) ?? (readOnly ? null : stableToolId),
    evidenceRefs: toolStringArray(record?.evidenceRefs ?? record?.evidence_refs),
  };
}

function normalizeRuntimeToolReceiptBehavior(
  value: unknown,
  evidenceRequirements: string[],
): NonNullable<RuntimeToolCatalogEntry["receiptBehavior"]> {
  const record = toolRecord(value);
  return {
    emitsReceipt: toolBoolean(record?.emitsReceipt ?? record?.emits_receipt) ?? evidenceRequirements.length > 0,
    receiptRequired:
      toolBoolean(record?.receiptRequired ?? record?.receipt_required) ?? evidenceRequirements.length > 0,
    requiredReceiptTypes: toolStringArray(record?.requiredReceiptTypes ?? record?.required_receipt_types).length
      ? toolStringArray(record?.requiredReceiptTypes ?? record?.required_receipt_types)
      : evidenceRequirements,
    evidenceRequirements,
  };
}

function normalizeRuntimeToolAvailability(
  value: unknown,
  defaultAvailable: boolean,
  nodeType: string | null,
  configFields: string[],
  defaultReason: string | null,
): NonNullable<RuntimeToolCatalogEntry["workflowAvailability"]> {
  const record = toolRecord(value);
  return {
    available: toolBoolean(record?.available) ?? defaultAvailable,
    reason: toolString(record?.reason) ?? defaultReason,
    nodeType: toolString(record?.nodeType ?? record?.node_type) ?? nodeType,
    configFields: toolStringArray(record?.configFields ?? record?.config_fields).length
      ? toolStringArray(record?.configFields ?? record?.config_fields)
      : configFields,
    evidenceRefs: toolStringArray(record?.evidenceRefs ?? record?.evidence_refs),
  };
}

function normalizeRuntimeToolMarketplaceExposure(
  value: unknown,
  approvalRequired: boolean,
  credentialStatus: string,
  effectClass: string,
): NonNullable<RuntimeToolCatalogEntry["marketplaceExposure"]> {
  const record = toolRecord(value);
  const eligible = !approvalRequired && credentialStatus !== "missing" && runtimeToolIsReadOnly(effectClass);
  return {
    eligible: toolBoolean(record?.eligible) ?? eligible,
    reason:
      toolString(record?.reason) ??
      (eligible ? "Read-only tool is eligible for marketplace exposure." : "Requires authority review before exposure."),
    trustRequired: toolBoolean(record?.trustRequired ?? record?.trust_required) ?? approvalRequired,
    versionPinned: toolBoolean(record?.versionPinned ?? record?.version_pinned) ?? true,
    evidenceRefs: toolStringArray(record?.evidenceRefs ?? record?.evidence_refs),
  };
}

function runtimeToolRequiresApproval(effectClass: string, authorityScopes: string[]): boolean {
  return authorityScopes.length > 0 || !runtimeToolIsReadOnly(effectClass);
}

function runtimeToolIsReadOnly(effectClass: string): boolean {
  const normalized = effectClass.trim().toLowerCase();
  return normalized === "read" || normalized === "local_read" || normalized.endsWith("_read");
}

function runtimeToolIsExternalEffect(effectClass: string): boolean {
  const normalized = effectClass.trim().toLowerCase();
  return (
    normalized.includes("external") ||
    normalized.includes("connector") ||
    normalized.includes("destructive") ||
    normalized.includes("commerce")
  );
}

function runtimeToolLikelyRequiresCredential(context: {
  stableToolId: string;
  riskDomain: string;
  effectClass: string;
}): boolean {
  const haystack = `${context.stableToolId} ${context.riskDomain} ${context.effectClass}`.toLowerCase();
  return haystack.includes("connector") || haystack.includes("mcp") || haystack.includes("model") || haystack.includes("oauth");
}

function toolStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((item) => toolString(item)).filter((item): item is string => Boolean(item)))];
}

function toolString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

function toolBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  return undefined;
}

function toolNumberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function toolRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function subagentListQuery(options: RuntimeSubagentListInput = {}): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(options)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

function parseDaemonResponseBody(text: string): unknown {
  if (!text.trim()) {
    return undefined;
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new IoiAgentError({
      code: "runtime",
      message: "IOI daemon returned a non-JSON substrate response.",
      cause: error,
      details: { preview: text.slice(0, 240) },
    });
  }
}

function eventsFromResponse(value: unknown): IOISDKMessage[] {
  if (Array.isArray(value)) {
    return normalizeDaemonEvents(value);
  }
  if (value && typeof value === "object" && Array.isArray((value as { events?: unknown[] }).events)) {
    return normalizeDaemonEvents((value as { events: unknown[] }).events);
  }
  throw new IoiAgentError({
    code: "runtime",
    message: "IOI daemon event endpoint returned an invalid event stream projection.",
    details: { value },
  });
}

function parseServerSentEvents(text: string): IOISDKMessage[] {
  const events: unknown[] = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    const dataLines = block
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice("data:".length).trimStart());
    if (dataLines.length === 0) {
      continue;
    }
    const data = dataLines.join("\n").trim();
    if (!data || data === "[DONE]") {
      continue;
    }
    const parsed = parseDaemonResponseBody(data);
    events.push(parsed);
  }
  return normalizeDaemonEvents(events);
}

function parseServerSentRuntimeEvents(text: string): RuntimeEventEnvelope[] {
  const events: unknown[] = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    const dataLines = block
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice("data:".length).trimStart());
    if (dataLines.length === 0) {
      continue;
    }
    const data = dataLines.join("\n").trim();
    if (!data || data === "[DONE]") {
      continue;
    }
    events.push(parseDaemonResponseBody(data));
  }
  return runtimeEventsFromResponse(events);
}

function runtimeEventsFromResponse(value: unknown): RuntimeEventEnvelope[] {
  const values = Array.isArray(value)
    ? value
    : value && typeof value === "object" && Array.isArray((value as { events?: unknown[] }).events)
      ? (value as { events: unknown[] }).events
      : null;
  if (!values) {
    throw new IoiAgentError({
      code: "runtime",
      message: "IOI daemon runtime event endpoint returned an invalid event stream projection.",
      details: { value },
    });
  }
  return values.map((event) => {
    if (!isRuntimeEventEnvelope(event)) {
      throw new IoiAgentError({
        code: "runtime",
        message: "IOI daemon runtime event endpoint returned a non-TTI event envelope.",
        details: { event },
      });
    }
    return event;
  });
}

function runtimeEventQuery(options: RuntimeEventStreamOptions = {}): string {
  const params = new URLSearchParams();
  if (options.sinceSeq !== undefined) {
    params.set("since_seq", String(options.sinceSeq));
  } else if (options.lastEventId) {
    params.set("lastEventId", options.lastEventId);
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

function normalizeDaemonEvents(values: unknown[]): IOISDKMessage[] {
  const latestTerminalByRun = new Map<string, number>();
  for (const value of values) {
    if (!isRuntimeEventEnvelope(value) || !isRuntimeTerminalEvent(value)) continue;
    latestTerminalByRun.set(runtimeEventRunId(value), value.seq);
  }
  return values.map((value) => normalizeDaemonEvent(value, latestTerminalByRun));
}

function normalizeDaemonEvent(value: unknown, latestTerminalByRun = new Map<string, number>()): IOISDKMessage {
  if (isSdkMessage(value)) return value;
  if (isRuntimeEventEnvelope(value)) {
    const terminalSuperseded =
      isRuntimeTerminalEvent(value) && latestTerminalByRun.get(runtimeEventRunId(value)) !== value.seq;
    return sdkMessageFromRuntimeEvent(value, { terminalSuperseded });
  }
  throw new IoiAgentError({
    code: "runtime",
    message: "IOI daemon event endpoint returned an invalid event stream projection.",
    details: { value },
  });
}

function isSdkMessage(value: unknown): value is IOISDKMessage {
  return Boolean(
    value &&
      typeof value === "object" &&
      typeof (value as IOISDKMessage).id === "string" &&
      typeof (value as IOISDKMessage).runId === "string" &&
      typeof (value as IOISDKMessage).type === "string" &&
      typeof (value as IOISDKMessage).cursor === "string",
  );
}

function isRuntimeEventEnvelope(value: unknown): value is RuntimeEventEnvelope {
  return Boolean(
    value &&
      typeof value === "object" &&
      (value as RuntimeEventEnvelope).schema_version === "ioi.runtime.event.v1" &&
      typeof (value as RuntimeEventEnvelope).event_id === "string" &&
      typeof (value as RuntimeEventEnvelope).event_stream_id === "string" &&
      typeof (value as RuntimeEventEnvelope).seq === "number",
  );
}

function sdkMessageFromRuntimeEvent(
  event: RuntimeEventEnvelope,
  options: { terminalSuperseded?: boolean } = {},
): IOISDKMessage {
  const payload = event.payload ?? {};
  const type = options.terminalSuperseded ? "step" : sdkMessageTypeFromRuntimeEvent(event);
  return {
    id: event.event_id,
    runId: runtimeEventRunId(event),
    agentId: payload.agent_id ?? event.thread_id.replace(/^thread_/, "agent_"),
    type,
    cursor: `${event.event_stream_id}:${event.seq}`,
    createdAt: event.created_at,
    summary: payload.summary ?? event.event_kind,
    data: {
      ...payload,
      runtimeEventEnvelope: event,
    },
  };
}

function runtimeEventRunId(event: RuntimeEventEnvelope): string {
  return event.payload?.run_id ?? event.turn_id.replace(/^turn_/, "run_");
}

function isRuntimeTerminalEvent(event: RuntimeEventEnvelope): boolean {
  return ["turn.completed", "turn.canceled", "turn.failed"].includes(event.event_kind);
}

function sdkMessageTypeFromRuntimeEvent(event: RuntimeEventEnvelope): IOISDKMessage["type"] {
  if (event.event_kind.startsWith("computer_use.")) {
    const computerUseType = event.event_kind.replace(/\./g, "_");
    if (isSdkMessageType(computerUseType)) return computerUseType;
  }
  switch (event.event_kind) {
    case "thread.started":
    case "turn.started":
      return "run_started";
    case "answer.delta":
      return "answer_delta";
    case "reasoning.delta":
    case "item.delta":
      return "delta";
    case "tool.completed":
    case "tool.failed":
      return "tool_result";
    case "turn.completed":
      return "completed";
    case "turn.canceled":
      return "canceled";
    case "turn.failed":
      return "error";
    case "model.route_decision":
    case "tool.route_decision":
      return "model_route_decision";
    case "workspace.trust_warning":
      return "workspace_trust_warning";
    case "workspace.trust_acknowledged":
      return "workspace_trust_acknowledged";
    default:
      return "step";
  }
}

function isSdkMessageType(value: string): value is IOISDKMessage["type"] {
  return [
    "run_started",
    "model_route_decision",
    "memory_update",
    "computer_use_environment_selected",
    "computer_use_environment_unavailable",
    "computer_use_lease_acquired",
    "computer_use_run_state",
    "computer_use_observation",
    "computer_use_affordance_graph",
    "computer_use_browser_discovery",
    "computer_use_action_proposed",
    "computer_use_action_executed",
    "computer_use_verification",
    "computer_use_commit_gate",
    "computer_use_trajectory_written",
    "computer_use_cleanup",
    "computer_use_control",
    "step",
    "delta",
    "tool_call",
    "tool_result",
    "task_state",
    "uncertainty",
    "probe",
    "postcondition_synthesized",
    "semantic_impact",
    "usage_final",
    "stop_condition",
    "quality_ledger",
    "workspace_trust_warning",
    "workspace_trust_acknowledged",
    "artifact",
    "completed",
    "canceled",
    "error",
  ].includes(value);
}

function errorFromDaemonResponse({
  sdkMethod,
  route,
  status,
  requestId,
  parsed,
}: {
  sdkMethod: string;
  route: string;
  status: number;
  requestId?: string;
  parsed: unknown;
}): IoiAgentError {
  const record = parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  const nested = record.error && typeof record.error === "object"
    ? (record.error as Record<string, unknown>)
    : record;
  const code = normalizeDaemonErrorCode(nested.code, status);
  return new IoiAgentError({
    code,
    status,
    requestId: typeof nested.requestId === "string" ? nested.requestId : requestId,
    retryable: typeof nested.retryable === "boolean" ? nested.retryable : undefined,
    message:
      typeof nested.message === "string"
        ? nested.message
        : `IOI daemon request failed for ${sdkMethod}.`,
    details: {
      method: sdkMethod,
      route,
      daemon: nested.details && typeof nested.details === "object" ? nested.details : record,
    },
  });
}

function normalizeDaemonErrorCode(value: unknown, status: number): IoiAgentErrorCode {
  if (
    value === "auth" ||
    value === "config" ||
    value === "policy" ||
    value === "rate_limit" ||
    value === "network" ||
    value === "model" ||
    value === "tool" ||
    value === "verifier" ||
    value === "postcondition" ||
    value === "not_found" ||
    value === "external_blocker" ||
    value === "runtime"
  ) {
    return value;
  }
  if (status === 401) return "auth";
  if (status === 403) return "policy";
  if (status === 404) return "not_found";
  if (status === 429) return "rate_limit";
  if (status === 424) return "external_blocker";
  if (status >= 500) return "network";
  return "runtime";
}
export function summarizeOptions(cwd: string, options: AgentOptions): AgentOptionsSummary {
  const cursorConfig = loadCursorCompatibilityConfig(cwd);
  return {
    localCwd: options.local?.cwd,
    cloudConfigured: Boolean(options.cloud ?? options.hosted),
    selfHostedConfigured: Boolean(options.selfHosted),
    mcpServerNames: [
      ...new Set([
        ...Object.keys(options.mcpServers ?? {}),
        ...Object.keys(cursorConfig.mcpServers),
      ]),
    ],
    skillNames: cursorConfig.skillNames,
    hookNames: cursorConfig.hookNames,
    subagentNames: Object.keys(options.agents ?? {}),
    sandboxProfile: options.sandboxOptions?.profile ?? "development",
  };
}

function loadCursorCompatibilityConfig(_cwd: string): {
  mcpServers: Record<string, McpServerConfig>;
  skillNames: string[];
  hookNames: string[];
} {
  return { mcpServers: {}, hookNames: [], skillNames: [] };
}

// Conformance check I1 verification requirements:
// Agentgres non-authoritative checkpoint projection boundary
// agent-sdk-mock schemaVersion ioi.agentgres.runtime.v0
