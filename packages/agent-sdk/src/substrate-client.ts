import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { IoiAgentError, type IoiAgentErrorCode } from "./errors.js";
import {
  eventStreamIdForThread,
  mockRuntimeCursorSeq,
  mockRuntimeEnvelopeForSdkEvent,
  mockRuntimeEventEnvelope,
  runtimeThreadEventFromEnvelope,
  runtimeTurnStatusForRun,
  turnIdForRun,
} from "./runtime-events.js";
import type {
  AgentOptions,
  CloudAgentOptions,
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
  AgentQualityLedgerProjection,
  ConversationMessage,
  IOIRunResult,
  IOISDKMessage,
  ModelRouteDecision,
  PostconditionProjection,
  ProbeProjection,
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
  SemanticImpactProjection,
  StopConditionProjection,
  SubagentMemoryInheritanceProjection,
  TaskStateProjection,
  UncertaintyProjection,
} from "./messages.js";
import type { RuntimeModelCatalogEntry } from "./model-mounts.js";
import { mockComputerUseProjectionForRun } from "./computer-use-projection.js";

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
  schemaVersion?: "ioi.runtime.usage-telemetry.v1" | string;
  object?: "ioi.runtime_usage_telemetry" | string;
  scope: "run" | "thread" | "subagent" | "global" | string;
  thread_id?: string | null;
  threadId?: string | null;
  turn_id?: string | null;
  turnId?: string | null;
  run_id?: string | null;
  runId?: string | null;
  agent_id?: string | null;
  agentId?: string | null;
  provider: string;
  model: string;
  route_id?: string | null;
  routeId?: string | null;
  model_route_id?: string | null;
  modelRouteId?: string | null;
  input_tokens: number;
  inputTokens?: number;
  output_tokens: number;
  outputTokens?: number;
  reasoning_tokens: number;
  reasoningTokens?: number;
  cached_input_tokens: number;
  cachedInputTokens?: number;
  tool_result_tokens: number;
  toolResultTokens?: number;
  compacted_tokens: number;
  compactedTokens?: number;
  total_tokens: number;
  totalTokens?: number;
  estimated_cost_micros: number;
  estimatedCostMicros?: number;
  estimated_cost_usd?: number;
  estimatedCostUsd?: number;
  currency?: string;
  context_window_tokens?: number;
  contextWindowTokens?: number;
  context_used_tokens?: number;
  contextUsedTokens?: number;
  context_pressure?: number;
  contextPressure?: number;
  context_pressure_status?: "nominal" | "elevated" | "high" | string;
  contextPressureStatus?: "nominal" | "elevated" | "high" | string;
  latency_ms: number;
  latencyMs?: number;
  estimated?: boolean;
  source_counts?: { runs?: number; subagents?: number; [key: string]: unknown };
  sourceCounts?: { runs?: number; subagents?: number; [key: string]: unknown };
  source_refs?: string[];
  sourceRefs?: string[];
  generated_at?: string;
  generatedAt?: string;
  [key: string]: unknown;
}

export interface RuntimeUsageListInput {
  groupBy?: "run" | "thread" | string;
  group_by?: "run" | "thread" | string;
  agentId?: string;
  agent_id?: string;
}

export interface RuntimeUsageListResult {
  schema_version?: "ioi.runtime.usage-telemetry.v1" | string;
  schemaVersion?: "ioi.runtime.usage-telemetry.v1" | string;
  object?: "ioi.runtime_usage_list" | string;
  group_by?: string;
  groupBy?: string;
  count: number;
  usage: RuntimeUsageTelemetry[];
  generated_at?: string;
  generatedAt?: string;
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
  agentId?: string;
  agent_id?: string;
  status?: string;
}

export interface RuntimeTaskCreateOptions {
  agentId?: string;
  agent_id?: string;
  prompt?: string;
  objective?: string;
  goal?: string;
  mode?: string;
  options?: Record<string, unknown>;
  agent?: Record<string, unknown>;
  agentOptions?: Record<string, unknown>;
  agent_options?: Record<string, unknown>;
  model?: Record<string, unknown>;
  cwd?: string;
  workspace?: string;
  [key: string]: unknown;
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
  agentId?: string;
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
  schemaVersion?: string;
  status?: string | null;
  required_sections?: string[];
  requiredSections?: string[];
  present_sections?: string[];
  presentSections?: string[];
  missing_sections?: string[];
  missingSections?: string[];
  validated_at?: string;
  validatedAt?: string;
  [key: string]: unknown;
}

export interface RuntimeSubagentUsageTelemetry {
  schema_version?: string;
  schemaVersion?: string;
  object?: "ioi.runtime_subagent_usage_telemetry" | string;
  estimated?: boolean;
  input_tokens?: number;
  inputTokens?: number;
  output_tokens?: number;
  outputTokens?: number;
  total_tokens?: number;
  totalTokens?: number;
  cumulative_input_tokens?: number;
  cumulativeInputTokens?: number;
  cumulative_output_tokens?: number;
  cumulativeOutputTokens?: number;
  cumulative_total_tokens?: number;
  cumulativeTotalTokens?: number;
  cost_estimate_usd?: number;
  costEstimateUsd?: number;
  cumulative_cost_estimate_usd?: number;
  cumulativeCostEstimateUsd?: number;
  model_route_id?: string | null;
  modelRouteId?: string | null;
  [key: string]: unknown;
}

export interface RuntimeSubagentBudgetStatus {
  schema_version?: string;
  schemaVersion?: string;
  object?: "ioi.runtime_subagent_budget_status" | string;
  status?: "not_configured" | "within_budget" | "exceeded" | string;
  budget?: Record<string, unknown> | null;
  usage?: RuntimeSubagentUsageTelemetry | null;
  violations?: Record<string, unknown>[];
  policy_decision?: Record<string, unknown> | null;
  policyDecision?: Record<string, unknown> | null;
  checked_at?: string;
  checkedAt?: string;
  [key: string]: unknown;
}

export interface RuntimeSubagentControlInput {
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  actor?: string;
  prompt?: string;
  message?: string;
  input?: string;
  text?: string;
  role?: string;
  subagentRole?: string;
  subagent_role?: string;
  toolPack?: string;
  tool_pack?: string;
  subagentToolPack?: string;
  modelRouteId?: string;
  model_route_id?: string;
  subagentModelRoute?: string;
  maxConcurrency?: number;
  max_concurrency?: number;
  subagentMaxConcurrency?: number;
  budget?: Record<string, unknown>;
  subagentBudget?: Record<string, unknown>;
  outputContract?: string[] | Record<string, unknown>;
  output_contract?: string[] | Record<string, unknown>;
  subagentOutputContract?: string[] | Record<string, unknown>;
  mergePolicy?: string;
  merge_policy?: string;
  cancellationInheritance?: "propagate" | "isolated" | string;
  cancellation_inheritance?: "propagate" | "isolated" | string;
  cancellationReason?: string;
  cancellation_reason?: string;
  reason?: string;
  inherited?: boolean;
  cancellationInherited?: boolean;
  cancellation_inherited?: boolean;
  propagatedFromThreadId?: string;
  propagated_from_thread_id?: string;
  forkContext?: boolean;
  fork_context?: boolean;
  parentTurnId?: string;
  parent_turn_id?: string;
  turnId?: string;
  turn_id?: string;
  targetAgentId?: string;
  target_agent_id?: string;
  memory?: Record<string, unknown>;
  options?: Record<string, unknown>;
  workflowGraphId?: string;
  workflow_graph_id?: string;
  workflowNodeId?: string;
  workflow_node_id?: string;
  idempotencyKey?: string;
  idempotency_key?: string;
  [key: string]: unknown;
}

export interface RuntimeSubagentListInput {
  role?: string;
  subagentRole?: string;
  subagent_role?: string;
  status?: string;
  [key: string]: unknown;
}

export interface RuntimeSubagentRecord {
  schema_version?: string;
  schemaVersion?: string;
  object?: "ioi.runtime_subagent" | string;
  subagent_id?: string;
  subagentId?: string;
  agent_id?: string;
  agentId?: string;
  child_thread_id?: string;
  childThreadId?: string;
  run_id?: string;
  runId?: string;
  parent_thread_id?: string;
  parentThreadId?: string;
  parent_agent_id?: string;
  parentAgentId?: string;
  parent_turn_id?: string | null;
  parentTurnId?: string | null;
  role?: string;
  tool_pack?: string | null;
  toolPack?: string | null;
  model_route_id?: string | null;
  modelRouteId?: string | null;
  workflow_graph_id?: string | null;
  workflowGraphId?: string | null;
  workflow_node_id?: string | null;
  workflowNodeId?: string | null;
  lifecycle_status?: RuntimeSubagentLifecycleStatus;
  lifecycleStatus?: RuntimeSubagentLifecycleStatus;
  status?: RuntimeSubagentLifecycleStatus;
  restart_status?: string | null;
  restartStatus?: string | null;
  restart_count?: number;
  restartCount?: number;
  input_count?: number;
  inputCount?: number;
  assignment_count?: number;
  assignmentCount?: number;
  cancellation_inheritance?: string | null;
  cancellationInheritance?: string | null;
  cancellation_reason?: string | null;
  cancellationReason?: string | null;
  cancellation_inherited?: boolean | null;
  cancellationInherited?: boolean | null;
  propagated_from_thread_id?: string | null;
  propagatedFromThreadId?: string | null;
  output_contract_status?: string | null;
  outputContractStatus?: RuntimeSubagentOutputContractStatus | string | null;
  budget_status?: string | null;
  budgetStatus?: RuntimeSubagentBudgetStatus | string | null;
  usage_telemetry?: RuntimeSubagentUsageTelemetry | null;
  usageTelemetry?: RuntimeSubagentUsageTelemetry | null;
  cost_estimate_usd?: number | null;
  costEstimateUsd?: number | null;
  token_estimate?: number | null;
  tokenEstimate?: number | null;
  result?: RuntimeSubagentResult | null;
  event?: RuntimeEventEnvelope | null;
  receipt_refs?: string[];
  receiptRefs?: string[];
  evidence_refs?: string[];
  evidenceRefs?: string[];
  created_at?: string;
  createdAt?: string;
  updated_at?: string;
  updatedAt?: string;
  [key: string]: unknown;
}

export interface RuntimeSubagentListResult {
  schema_version?: string;
  schemaVersion?: string;
  object: "ioi.runtime_subagent_list" | string;
  thread_id?: string;
  threadId?: string;
  parent_agent_id?: string;
  parentAgentId?: string;
  status?: string;
  count: number;
  active_count?: number;
  activeCount?: number;
  subagents: RuntimeSubagentRecord[];
  [key: string]: unknown;
}

export interface RuntimeSubagentResult {
  schema_version?: string;
  schemaVersion?: string;
  object?: "ioi.runtime_subagent_result" | string;
  subagent_id?: string | null;
  subagentId?: string | null;
  agent_id?: string | null;
  agentId?: string | null;
  run_id?: string | null;
  runId?: string | null;
  lifecycle_status?: RuntimeSubagentLifecycleStatus | null;
  lifecycleStatus?: RuntimeSubagentLifecycleStatus | null;
  status?: RuntimeSubagentLifecycleStatus | null;
  result?: string | null;
  output?: Record<string, unknown> | null;
  output_contract_status?: string | null;
  outputContractStatus?: RuntimeSubagentOutputContractStatus | string | null;
  budget_status?: string | null;
  budgetStatus?: RuntimeSubagentBudgetStatus | string | null;
  usage_telemetry?: RuntimeSubagentUsageTelemetry | null;
  usageTelemetry?: RuntimeSubagentUsageTelemetry | null;
  cost_estimate_usd?: number | null;
  costEstimateUsd?: number | null;
  token_estimate?: number | null;
  tokenEstimate?: number | null;
  receipt_refs?: string[];
  receiptRefs?: string[];
  subagent?: RuntimeSubagentRecord;
  event?: RuntimeEventEnvelope | null;
  cancellation?: Record<string, unknown> | null;
  input?: Record<string, unknown> | null;
  resume?: Record<string, unknown> | null;
  assignment?: Record<string, unknown> | null;
  [key: string]: unknown;
}

export interface RuntimeSubagentCancellationPropagationResult {
  schema_version?: string;
  schemaVersion?: string;
  object: "ioi.runtime_subagent_cancellation_propagation" | string;
  thread_id?: string;
  threadId?: string;
  parent_agent_id?: string;
  parentAgentId?: string;
  status: string;
  source?: string;
  reason?: string;
  propagation_policy?: string;
  propagationPolicy?: string;
  candidate_count?: number;
  candidateCount?: number;
  canceled_count?: number;
  canceledCount?: number;
  skipped_count?: number;
  skippedCount?: number;
  canceled_subagents?: RuntimeSubagentRecord[];
  canceledSubagents?: RuntimeSubagentRecord[];
  skipped_subagents?: RuntimeSubagentRecord[];
  skippedSubagents?: RuntimeSubagentRecord[];
  event_refs?: string[];
  eventRefs?: string[];
  receipt_refs?: string[];
  receiptRefs?: string[];
  [key: string]: unknown;
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
  threadId?: string;
  thread_id?: string;
  agentId?: string;
  agent_id?: string;
  serverId?: string;
  server_id?: string;
  [key: string]: unknown;
}

export interface RuntimeMcpToolSearchInput extends RuntimeMcpListOptions {
  query?: string;
  q?: string;
  search?: string;
  toolId?: string;
  tool_id?: string;
  toolName?: string;
  tool_name?: string;
  exact?: boolean;
  liveDiscovery?: boolean;
  live_discovery?: boolean;
  catalogPreviewLimit?: number;
  catalog_preview_limit?: number;
  limit?: number;
}

export interface RuntimeMcpValidationInput {
  mcpJson?: Record<string, unknown>;
  mcp_json?: Record<string, unknown>;
  mcpServers?: Record<string, unknown>;
  servers?: unknown[] | Record<string, unknown>;
  cwd?: string;
  source?: "sdk_client" | "cli_tui" | "react_flow" | string;
  workflowGraphId?: string;
  workflow_graph_id?: string;
  workflowNodeId?: string;
  workflow_node_id?: string;
  [key: string]: unknown;
}

export interface RuntimeMcpServerControlInput extends RuntimeMcpValidationInput {
  threadId?: string;
  thread_id?: string;
  serverId?: string;
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
  mcpServer?: Record<string, unknown>;
  mcpServers?: Record<string, unknown>;
  mcp_json?: Record<string, unknown>;
  mcpJson?: Record<string, unknown>;
}

export interface RuntimeMcpToolInvokeInput extends RuntimeMcpValidationInput {
  threadId?: string;
  thread_id?: string;
  serverId?: string;
  server_id?: string;
  toolId?: string;
  tool_id?: string;
  toolName?: string;
  tool_name?: string;
  tool?: string;
  input?: Record<string, unknown>;
  arguments?: Record<string, unknown>;
  sideEffectClass?: string;
  side_effect_class?: string;
  requiresApproval?: boolean;
  requires_approval?: boolean;
  approved?: boolean;
  liveTransport?: boolean;
  live_transport?: boolean;
  executionMode?: "live_stdio" | "live_http" | "live_sse" | "simulated_manager_receipt" | string;
  execution_mode?: "live_stdio" | "live_http" | "live_sse" | "simulated_manager_receipt" | string;
  timeoutMs?: number;
  timeout_ms?: number;
}

export interface RuntimeThreadMcpInput extends RuntimeMcpServerControlInput {
  turnId?: string;
  turn_id?: string;
  idempotencyKey?: string;
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
    allowHostedFallback?: boolean;
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
  submitTurn(threadId: string, input: RuntimeTurnCreateInput): Promise<RuntimeTurnRecord>;
  listTurns(threadId: string): Promise<RuntimeTurnRecord[]>;
  getTurn(threadId: string, turnId: string): Promise<RuntimeTurnRecord>;
  interruptTurn(threadId: string, turnId: string, input?: RuntimeTurnInterruptInput): Promise<RuntimeTurnRecord>;
  steerTurn(threadId: string, turnId: string, input?: RuntimeTurnSteerInput): Promise<RuntimeTurnRecord>;
  streamThreadEvents(threadId: string, options?: RuntimeEventStreamOptions): AsyncIterable<RuntimeThreadEvent>;
  listSubagents(threadId: string, input?: RuntimeSubagentListInput): Promise<RuntimeSubagentListResult>;
  spawnSubagent(threadId: string, input: RuntimeSubagentControlInput): Promise<RuntimeSubagentRecord>;
  waitSubagent(
    threadId: string,
    subagentId: string,
    input?: RuntimeSubagentControlInput,
  ): Promise<RuntimeSubagentResult>;
  getSubagentResult(threadId: string, subagentId: string): Promise<RuntimeSubagentResult>;
  sendSubagentInput(
    threadId: string,
    subagentId: string,
    input: RuntimeSubagentControlInput,
  ): Promise<RuntimeSubagentRecord>;
  cancelSubagent(
    threadId: string,
    subagentId: string,
    input?: RuntimeSubagentControlInput,
  ): Promise<RuntimeSubagentResult>;
  resumeSubagent(
    threadId: string,
    subagentId: string,
    input?: RuntimeSubagentControlInput,
  ): Promise<RuntimeSubagentResult>;
  assignSubagent(
    threadId: string,
    subagentId: string,
    input?: RuntimeSubagentControlInput,
  ): Promise<RuntimeSubagentRecord>;
  propagateSubagentCancellation(
    threadId: string,
    input?: RuntimeSubagentControlInput,
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
  exportTrace(runId: string): Promise<RuntimeTraceBundle>;
  replayTrace(runId: string): AsyncIterable<IOISDKMessage>;
  inspectRun(runId: string): Promise<RuntimeTraceBundle>;
  getRunComputerUseTrace(runId: string): Promise<RuntimeTraceBundle["computerUse"]>;
  getRunComputerUseTrajectory(runId: string): Promise<unknown>;
  discoverComputerUseBrowsers(
    options?: RuntimeComputerUseBrowserDiscoveryOptions,
  ): Promise<RuntimeComputerUseBrowserDiscoveryReport>;
  scorecard(runId: string): Promise<RuntimeScorecard>;
  listModels(): Promise<RuntimeModelCatalogEntry[]>;
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

export function createMockRuntimeSubstrateClient(
  options: RuntimeSubstrateClientOptions = {},
): RuntimeSubstrateClient {
  return new MockRuntimeSubstrateClient(options);
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
    input: RuntimeSubagentControlInput,
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
    input: RuntimeSubagentControlInput = {},
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
    input: RuntimeSubagentControlInput,
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
    input: RuntimeSubagentControlInput = {},
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
    input: RuntimeSubagentControlInput = {},
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
    input: RuntimeSubagentControlInput = {},
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
    input: RuntimeSubagentControlInput = {},
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
    const agentId = options.agentId ?? options.agent_id;
    if (agentId) params.set("agentId", agentId);
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
    const agentId = options.agentId ?? options.agent_id;
    if (agentId) params.set("agentId", agentId);
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

  async discoverComputerUseBrowsers(
    options: RuntimeComputerUseBrowserDiscoveryOptions = {},
  ): Promise<RuntimeComputerUseBrowserDiscoveryReport> {
    return this.request(
      "discoverComputerUseBrowsers",
      "GET",
      `/v1/computer-use/browser-discovery${computerUseBrowserDiscoveryQuery(options)}`,
    );
  }

  async scorecard(runId: string): Promise<RuntimeScorecard> {
    return this.request("scorecard", "GET", `/v1/runs/${encodePath(runId)}/scorecard`);
  }

  async listModels(): Promise<RuntimeModelCatalogEntry[]> {
    return this.request("listModels", "GET", "/v1/models");
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
    return this.request("listTools", "GET", `/v1/tools${toolListQuery(options)}`);
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
    const toolId = input.toolId ?? input.tool_id ?? `${input.serverId ?? input.server_id ?? "mcp"}.${input.toolName ?? input.tool_name ?? input.tool ?? "tool"}`;
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
    const toolId = input.toolId ?? input.tool_id ?? `${input.serverId ?? input.server_id ?? "mcp"}.${input.toolName ?? input.tool_name ?? input.tool ?? "tool"}`;
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
        explicitMockFactory: "@ioi/agent-sdk/testing#createMockRuntimeSubstrateClient",
      },
    });
  }
}

function encodePath(value: string): string {
  return encodeURIComponent(value);
}

function runtimeUsageListQuery(input: RuntimeUsageListInput = {}): string {
  const params = new URLSearchParams();
  const groupBy = input.groupBy ?? input.group_by;
  const agentId = input.agentId ?? input.agent_id;
  if (groupBy) params.set("group_by", groupBy);
  if (agentId) params.set("agentId", agentId);
  const query = params.toString();
  return query ? `?${query}` : "";
}

function mockUsageForRun(run: RuntimeRunRecord): RuntimeUsageTelemetry {
  const existing = run.usageTelemetry ?? run.usage_telemetry ?? run.runtimeUsage ?? run.usage;
  if (existing) return existing;
  const inputTokens = estimatedTokenCount(run.objective);
  const outputTokens = estimatedTokenCount(run.result);
  const totalTokens = inputTokens + outputTokens;
  const costUsd = roundUsageUsd(totalTokens * 0.000001);
  const contextWindowTokens = 128000;
  const contextUsedTokens = totalTokens;
  const contextPressure = roundUsageRatio(contextUsedTokens / contextWindowTokens);
  return {
    schema_version: "ioi.runtime.usage-telemetry.v1",
    schemaVersion: "ioi.runtime.usage-telemetry.v1",
    object: "ioi.runtime_usage_telemetry",
    scope: "run",
    thread_id: threadIdForAgent(run.agentId),
    threadId: threadIdForAgent(run.agentId),
    turn_id: turnIdForRun(run.id),
    turnId: turnIdForRun(run.id),
    run_id: run.id,
    runId: run.id,
    agent_id: run.agentId,
    agentId: run.agentId,
    provider: run.modelRouteDecision?.providerId ?? "local",
    model: run.modelRouteDecision?.selectedModel ?? "local:auto",
    route_id: run.modelRouteDecision?.routeId ?? null,
    routeId: run.modelRouteDecision?.routeId ?? null,
    model_route_id: run.modelRouteDecision?.routeId ?? null,
    modelRouteId: run.modelRouteDecision?.routeId ?? null,
    input_tokens: inputTokens,
    inputTokens,
    output_tokens: outputTokens,
    outputTokens,
    reasoning_tokens: 0,
    reasoningTokens: 0,
    cached_input_tokens: 0,
    cachedInputTokens: 0,
    tool_result_tokens: 0,
    toolResultTokens: 0,
    compacted_tokens: 0,
    compactedTokens: 0,
    total_tokens: totalTokens,
    totalTokens,
    estimated_cost_micros: Math.round(costUsd * 1_000_000),
    estimatedCostMicros: Math.round(costUsd * 1_000_000),
    estimated_cost_usd: costUsd,
    estimatedCostUsd: costUsd,
    currency: "USD",
    context_window_tokens: contextWindowTokens,
    contextWindowTokens,
    context_used_tokens: contextUsedTokens,
    contextUsedTokens,
    context_pressure: contextPressure,
    contextPressure,
    context_pressure_status: contextPressureStatus(contextPressure),
    contextPressureStatus: contextPressureStatus(contextPressure),
    latency_ms: 0,
    latencyMs: 0,
    estimated: true,
    source_counts: { runs: 1, subagents: 0 },
    sourceCounts: { runs: 1, subagents: 0 },
    source_refs: [run.id],
    sourceRefs: [run.id],
    generated_at: new Date().toISOString(),
    generatedAt: new Date().toISOString(),
  };
}

function mockUsageForThread({
  threadId,
  agent,
  runs,
  subagents,
}: {
  threadId: string;
  agent: RuntimeAgentRecord;
  runs: RuntimeRunRecord[];
  subagents: RuntimeSubagentRecord[];
}): RuntimeUsageTelemetry {
  const records = [
    ...runs.map((run) => run.usageTelemetry ?? run.usage_telemetry ?? run.runtimeUsage ?? run.usage ?? mockUsageForRun(run)),
    ...subagents.map(mockUsageForSubagent).filter((record): record is RuntimeUsageTelemetry => Boolean(record)),
  ];
  const inputTokens = usageSum(records, "input_tokens", "inputTokens");
  const outputTokens = usageSum(records, "output_tokens", "outputTokens");
  const reasoningTokens = usageSum(records, "reasoning_tokens", "reasoningTokens");
  const cachedInputTokens = usageSum(records, "cached_input_tokens", "cachedInputTokens");
  const toolResultTokens = usageSum(records, "tool_result_tokens", "toolResultTokens");
  const compactedTokens = usageSum(records, "compacted_tokens", "compactedTokens");
  const totalTokens = usageSum(records, "total_tokens", "totalTokens");
  const estimatedCostUsd = roundUsageUsd(
    records.reduce((sum, record) => sum + usageNumber(record.estimated_cost_usd ?? record.estimatedCostUsd), 0),
  );
  const estimatedCostMicros =
    records.reduce((sum, record) => sum + usageNumber(record.estimated_cost_micros ?? record.estimatedCostMicros), 0) ||
    Math.round(estimatedCostUsd * 1_000_000);
  const contextWindowTokens = Math.max(
    128000,
    ...records.map((record) => usageNumber(record.context_window_tokens ?? record.contextWindowTokens)),
  );
  const contextUsedTokens = records.reduce(
    (sum, record) => sum + usageNumber(record.context_used_tokens ?? record.contextUsedTokens),
    0,
  );
  const contextPressure = contextWindowTokens > 0
    ? roundUsageRatio(contextUsedTokens / contextWindowTokens)
    : 0;
  return {
    schema_version: "ioi.runtime.usage-telemetry.v1",
    schemaVersion: "ioi.runtime.usage-telemetry.v1",
    object: "ioi.runtime_usage_telemetry",
    scope: "thread",
    thread_id: threadId,
    threadId,
    agent_id: agent.id,
    agentId: agent.id,
    provider: "aggregate",
    model: "aggregate",
    route_id: null,
    routeId: null,
    model_route_id: null,
    modelRouteId: null,
    input_tokens: inputTokens,
    inputTokens,
    output_tokens: outputTokens,
    outputTokens,
    reasoning_tokens: reasoningTokens,
    reasoningTokens,
    cached_input_tokens: cachedInputTokens,
    cachedInputTokens,
    tool_result_tokens: toolResultTokens,
    toolResultTokens,
    compacted_tokens: compactedTokens,
    compactedTokens,
    total_tokens: totalTokens,
    totalTokens,
    estimated_cost_micros: estimatedCostMicros,
    estimatedCostMicros: estimatedCostMicros,
    estimated_cost_usd: estimatedCostUsd,
    estimatedCostUsd: estimatedCostUsd,
    currency: "USD",
    context_window_tokens: contextWindowTokens,
    contextWindowTokens,
    context_used_tokens: contextUsedTokens,
    contextUsedTokens,
    context_pressure: contextPressure,
    contextPressure,
    context_pressure_status: contextPressureStatus(contextPressure),
    contextPressureStatus: contextPressureStatus(contextPressure),
    latency_ms: usageSum(records, "latency_ms", "latencyMs"),
    latencyMs: usageSum(records, "latency_ms", "latencyMs"),
    estimated: true,
    source_counts: { runs: runs.length, subagents: subagents.length },
    sourceCounts: { runs: runs.length, subagents: subagents.length },
    source_refs: records.flatMap((record) => record.source_refs ?? record.sourceRefs ?? []).filter(Boolean),
    sourceRefs: records.flatMap((record) => record.sourceRefs ?? record.source_refs ?? []).filter(Boolean),
    generated_at: new Date().toISOString(),
    generatedAt: new Date().toISOString(),
  };
}

function mockUsageForSubagent(record: RuntimeSubagentRecord): RuntimeUsageTelemetry | null {
  const usage = record.usageTelemetry ?? record.usage_telemetry;
  if (!usage) return null;
  const totalTokens = usageNumber(usage.cumulative_total_tokens ?? usage.cumulativeTotalTokens ?? usage.total_tokens ?? usage.totalTokens);
  const inputTokens = usageNumber(usage.cumulative_input_tokens ?? usage.cumulativeInputTokens ?? usage.input_tokens ?? usage.inputTokens);
  const outputTokens = usageNumber(usage.cumulative_output_tokens ?? usage.cumulativeOutputTokens ?? usage.output_tokens ?? usage.outputTokens);
  const estimatedCostUsd = roundUsageUsd(
    usageNumber(usage.cumulative_cost_estimate_usd ?? usage.cumulativeCostEstimateUsd ?? usage.cost_estimate_usd ?? usage.costEstimateUsd) ||
      totalTokens * 0.000001,
  );
  const contextPressure = roundUsageRatio(totalTokens / 128000);
  return {
    schema_version: "ioi.runtime.usage-telemetry.v1",
    schemaVersion: "ioi.runtime.usage-telemetry.v1",
    object: "ioi.runtime_usage_telemetry",
    scope: "subagent",
    thread_id: record.parent_thread_id ?? record.parentThreadId ?? null,
    threadId: record.parentThreadId ?? record.parent_thread_id ?? null,
    turn_id: record.parent_turn_id ?? record.parentTurnId ?? null,
    turnId: record.parentTurnId ?? record.parent_turn_id ?? null,
    run_id: record.run_id ?? record.runId ?? null,
    runId: record.runId ?? record.run_id ?? null,
    agent_id: record.agent_id ?? record.agentId ?? null,
    agentId: record.agentId ?? record.agent_id ?? null,
    provider: "subagent",
    model: "subagent",
    route_id: record.model_route_id ?? record.modelRouteId ?? null,
    routeId: record.modelRouteId ?? record.model_route_id ?? null,
    model_route_id: record.model_route_id ?? record.modelRouteId ?? null,
    modelRouteId: record.modelRouteId ?? record.model_route_id ?? null,
    input_tokens: inputTokens,
    inputTokens,
    output_tokens: outputTokens,
    outputTokens,
    reasoning_tokens: 0,
    reasoningTokens: 0,
    cached_input_tokens: 0,
    cachedInputTokens: 0,
    tool_result_tokens: 0,
    toolResultTokens: 0,
    compacted_tokens: 0,
    compactedTokens: 0,
    total_tokens: totalTokens,
    totalTokens,
    estimated_cost_micros: Math.round(estimatedCostUsd * 1_000_000),
    estimatedCostMicros: Math.round(estimatedCostUsd * 1_000_000),
    estimated_cost_usd: estimatedCostUsd,
    estimatedCostUsd: estimatedCostUsd,
    currency: "USD",
    context_window_tokens: 128000,
    contextWindowTokens: 128000,
    context_used_tokens: totalTokens,
    contextUsedTokens: totalTokens,
    context_pressure: contextPressure,
    contextPressure,
    context_pressure_status: contextPressureStatus(contextPressure),
    contextPressureStatus: contextPressureStatus(contextPressure),
    latency_ms: 0,
    latencyMs: 0,
    estimated: true,
    source_counts: { runs: 0, subagents: 1 },
    sourceCounts: { runs: 0, subagents: 1 },
    source_refs: [record.subagent_id ?? record.subagentId, record.run_id ?? record.runId].filter(Boolean) as string[],
    sourceRefs: [record.subagentId ?? record.subagent_id, record.runId ?? record.run_id].filter(Boolean) as string[],
    generated_at: new Date().toISOString(),
    generatedAt: new Date().toISOString(),
  };
}

function mockUsageListEnvelope(groupBy: string, usage: RuntimeUsageTelemetry[]): RuntimeUsageListResult {
  return {
    schema_version: "ioi.runtime.usage-telemetry.v1",
    schemaVersion: "ioi.runtime.usage-telemetry.v1",
    object: "ioi.runtime_usage_list",
    group_by: groupBy,
    groupBy,
    count: usage.length,
    usage,
    generated_at: new Date().toISOString(),
    generatedAt: new Date().toISOString(),
  };
}

function usageSum(records: RuntimeUsageTelemetry[], snakeKey: string, camelKey: string): number {
  return records.reduce((sum, record) => sum + usageNumber(record[snakeKey] ?? record[camelKey]), 0);
}

function usageNumber(value: unknown): number {
  const number = Number(value ?? 0);
  return Number.isFinite(number) && number >= 0 ? number : 0;
}

function estimatedTokenCount(value: unknown): number {
  const text = String(value ?? "");
  return text ? Math.max(1, Math.ceil(text.length / 4)) : 0;
}

function contextPressureStatus(value: number): "nominal" | "elevated" | "high" {
  if (value >= 0.85) return "high";
  if (value >= 0.6) return "elevated";
  return "nominal";
}

function roundUsageUsd(value: number): number {
  return Math.round((Number(value) || 0) * 1_000_000) / 1_000_000;
}

function roundUsageRatio(value: number): number {
  return Math.round((Number(value) || 0) * 10000) / 10000;
}

function runtimeJobRecordForSdkRun(run: RuntimeRunRecord): RuntimeJobRecord {
  const terminal = ["completed", "failed", "canceled", "blocked"].includes(run.status);
  const jobId = `job_${run.id}`;
  return {
    schemaVersion: "ioi.agent-runtime.job-record.v1",
    object: "ioi.runtime_job",
    jobId,
    taskId: `task_${run.id}`,
    runId: run.id,
    agentId: run.agentId,
    threadId: threadIdForAgent(run.agentId),
    turnId: turnIdForRun(run.id),
    status: run.status,
    lifecycle: terminal ? ["queued", "started", run.status] : ["queued", "started"],
    summary: `Runtime job ${jobId} is ${run.status}.`,
    queueName: "local-agentgres",
    runner: "local-sdk-agentgres",
    jobType: "agent_run",
    priority: "normal",
    background: true,
    durable: true,
    replayable: true,
    createdAt: run.createdAt,
    updatedAt: run.updatedAt,
    queuedAt: run.createdAt,
    startedAt: run.createdAt,
    completedAt: terminal ? run.updatedAt : null,
    progress: {
      completedSteps: terminal ? 1 : 0,
      totalSteps: 1,
      percent: terminal ? 100 : run.status === "running" ? 50 : 0,
    },
    eventCount: run.events.length,
    terminalEventCount: run.events.filter((event) =>
      ["completed", "failed", "canceled", "blocked"].includes(event.type),
    ).length,
    artifactNames: run.artifacts.map((artifact) => artifact.name),
    receiptKinds: run.receipts.map((receipt) => receipt.kind),
    cancelable: run.status !== "canceled",
    cancelEndpoint: `/v1/jobs/${jobId}/cancel`,
    endpoints: {
      self: `/v1/jobs/${jobId}`,
      cancel: `/v1/jobs/${jobId}/cancel`,
      run: `/v1/runs/${run.id}`,
      events: `/v1/runs/${run.id}/events`,
      replay: `/v1/runs/${run.id}/replay`,
      trace: `/v1/runs/${run.id}/trace`,
      inspect: `/v1/runs/${run.id}/inspect`,
    },
    workflowNodeId: "runtime.runtime-job",
    evidenceRefs: ["runtime_job", `run:${run.id}`],
  };
}

function runtimeTaskRecordForSdkRun(run: RuntimeRunRecord): RuntimeTaskRecord {
  const taskId = `task_${run.id}`;
  const runWithTaskManifest = run as RuntimeRunRecord & {
    activeSkillHookManifest?: { manifestId?: string };
    trace?: RuntimeTraceBundle & { activeSkillHookManifest?: { manifestId?: string } };
  };
  return {
    schemaVersion: "ioi.agent-runtime.task-record.v1",
    object: "ioi.runtime_task",
    taskId,
    runId: run.id,
    agentId: run.agentId,
    threadId: threadIdForAgent(run.agentId),
    turnId: turnIdForRun(run.id),
    status: run.status,
    mode: run.mode,
    taskFamily: run.trace?.qualityLedger?.taskFamily ?? "coding_agent",
    selectedStrategy: run.trace?.qualityLedger?.selectedStrategy ?? "agent",
    summary: `Runtime task for ${run.mode} is ${run.status}.`,
    promptHash: crypto.createHash("sha256").update(run.objective ?? "").digest("hex"),
    promptIncluded: false,
    modelRouteDecisionId:
      run.modelRouteDecision?.decisionId ?? run.trace?.modelRouteDecision?.decisionId ?? null,
    activeSkillHookManifestId:
      runWithTaskManifest.activeSkillHookManifest?.manifestId ??
      runWithTaskManifest.trace?.activeSkillHookManifest?.manifestId ??
      null,
    durable: true,
    replayable: true,
    cancelable: run.status !== "canceled",
    cancelEndpoint: `/v1/tasks/${taskId}/cancel`,
    endpoints: {
      self: `/v1/tasks/${taskId}`,
      cancel: `/v1/tasks/${taskId}/cancel`,
      run: `/v1/runs/${run.id}`,
      job: `/v1/jobs/job_${run.id}`,
      events: `/v1/runs/${run.id}/events`,
      trace: `/v1/runs/${run.id}/trace`,
    },
    workflowNodeId: "runtime.runtime-task",
    createdAt: run.createdAt,
    updatedAt: run.updatedAt,
    evidenceRefs: ["runtime_task", "runtime.tasks.durable_projection", "RuntimeTaskNode", `run:${run.id}`],
  };
}

function runtimeSubagentStatusForRun(
  status: RuntimeRunRecord["status"] | RuntimeSubagentLifecycleStatus | undefined,
): RuntimeSubagentLifecycleStatus {
  switch (status) {
    case "queued":
      return "queued";
    case "running":
      return "running";
    case "canceled":
      return "canceled";
    case "failed":
      return "failed";
    case "blocked":
      return "blocked";
    case "completed":
    default:
      return status ?? "completed";
  }
}

function runtimeSubagentIsActive(record: RuntimeSubagentRecord): boolean {
  return ["queued", "running", "waiting_for_input", "interrupted"].includes(
    String(record.lifecycle_status ?? record.lifecycleStatus ?? record.status ?? ""),
  );
}

function runtimeSubagentText(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
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

function subagentListQuery(options: RuntimeSubagentListInput = {}): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(options)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

function mockCodingToolContracts(): RuntimeToolCatalogEntry[] {
  return [
    {
      schemaVersion: "ioi.runtime.coding-tool-pack.v1",
      stableToolId: "workspace.status",
      displayName: "Workspace status",
      pack: "coding",
      primitiveCapabilities: ["prim:workspace.status", "prim:git.status"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "workspace",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      evidenceRequirements: ["workspace_status_receipt", "coding_tool_receipt"],
      workflowNodeType: "CodingToolNode",
      workflowConfigFields: ["toolPack.coding.workspaceStatus", "toolPack.coding.gitEnabled"],
    },
    {
      schemaVersion: "ioi.runtime.coding-tool-pack.v1",
      stableToolId: "git.diff",
      displayName: "Git diff",
      pack: "coding",
      primitiveCapabilities: ["prim:git.diff"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "git",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      evidenceRequirements: ["git_diff_receipt", "coding_tool_receipt"],
      workflowNodeType: "GitToolNode",
      workflowConfigFields: ["toolPack.coding.gitEnabled", "toolPack.coding.allowedPaths"],
    },
    {
      schemaVersion: "ioi.runtime.coding-tool-pack.v1",
      stableToolId: "file.inspect",
      displayName: "Inspect file",
      pack: "coding",
      primitiveCapabilities: ["prim:fs.inspect"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "filesystem",
      inputSchema: { type: "object", required: ["path"] },
      outputSchema: { type: "object" },
      evidenceRequirements: ["file_inspect_receipt", "coding_tool_receipt"],
      workflowNodeType: "FilesystemToolNode",
      workflowConfigFields: ["toolPack.coding.filesystemEnabled", "toolPack.coding.allowedPaths"],
    },
    {
      schemaVersion: "ioi.runtime.coding-tool-pack.v1",
      stableToolId: "file.apply_patch",
      displayName: "Apply file patch",
      pack: "coding",
      primitiveCapabilities: ["prim:fs.apply_patch", "prim:fs.write"],
      authorityScopeRequirements: ["scope:workspace.write"],
      effectClass: "local_write",
      riskDomain: "filesystem",
      inputSchema: { type: "object", required: ["path"] },
      outputSchema: { type: "object" },
      evidenceRequirements: [
        "file_apply_patch_receipt",
        "workspace_mutation_receipt",
        "workspace_snapshot_receipt",
        "coding_tool_receipt",
      ],
      workflowNodeType: "FilesystemPatchNode",
      workflowConfigFields: [
        "toolPack.coding.filesystemEnabled",
        "toolPack.coding.writeEnabled",
        "toolPack.coding.allowedPaths",
        "toolPack.coding.dryRun",
        "toolPack.coding.diagnosticsMode",
        "toolPack.coding.defaultDiagnosticCommandId",
        "toolPack.coding.restorePolicy",
        "toolPack.coding.restoreConflictPolicy",
        "toolPack.coding.diagnosticsRepairDefault",
        "toolPack.coding.operatorOverrideRequiresApproval",
        "toolPack.coding.approvalMode",
        "toolPack.coding.trustProfile",
        "toolPack.coding.nodeApprovalOverride",
        "toolPack.coding.requiresApproval",
      ],
    },
    {
      schemaVersion: "ioi.runtime.coding-tool-pack.v1",
      stableToolId: "test.run",
      displayName: "Run tests",
      pack: "coding",
      primitiveCapabilities: ["prim:test.run", "prim:process.exec_file"],
      authorityScopeRequirements: ["scope:workspace.test"],
      effectClass: "local_command",
      riskDomain: "test",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      evidenceRequirements: ["test_run_receipt", "coding_tool_receipt"],
      workflowNodeType: "TestRunNode",
      workflowConfigFields: [
        "toolPack.coding.testEnabled",
        "toolPack.coding.allowedTestCommandIds",
        "toolPack.coding.allowedPaths",
        "toolPack.coding.timeoutMs",
        "toolPack.coding.approvalMode",
        "toolPack.coding.trustProfile",
        "toolPack.coding.nodeApprovalOverride",
        "toolPack.coding.requiresApproval",
      ],
    },
    {
      schemaVersion: "ioi.runtime.coding-tool-pack.v1",
      stableToolId: "lsp.diagnostics",
      displayName: "LSP diagnostics",
      pack: "coding",
      primitiveCapabilities: ["prim:lsp.diagnostics", "prim:process.exec_file"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "diagnostics",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      evidenceRequirements: ["lsp_diagnostics_receipt", "coding_tool_receipt"],
      workflowNodeType: "LspDiagnosticsNode",
      workflowConfigFields: [
        "toolPack.coding.diagnosticsEnabled",
        "toolPack.coding.allowedDiagnosticCommandIds",
        "toolPack.coding.diagnosticsMode",
        "toolPack.coding.defaultDiagnosticCommandId",
        "toolPack.coding.allowedPaths",
        "toolPack.coding.timeoutMs",
      ],
    },
    {
      schemaVersion: "ioi.runtime.coding-tool-pack.v1",
      stableToolId: "artifact.read",
      displayName: "Read artifact",
      pack: "coding",
      primitiveCapabilities: ["prim:artifact.read"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "artifact",
      inputSchema: { type: "object", required: ["artifactId"] },
      outputSchema: { type: "object" },
      evidenceRequirements: ["artifact_read_receipt", "coding_tool_receipt"],
      workflowNodeType: "ArtifactReadNode",
      workflowConfigFields: ["toolPack.coding.artifactEnabled", "toolPack.coding.resultRetrievalEnabled"],
    },
    {
      schemaVersion: "ioi.runtime.coding-tool-pack.v1",
      stableToolId: "tool.retrieve_result",
      displayName: "Retrieve tool result",
      pack: "coding",
      primitiveCapabilities: ["prim:tool.retrieve_result", "prim:artifact.read"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "artifact",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      evidenceRequirements: ["tool_result_retrieval_receipt", "artifact_read_receipt", "coding_tool_receipt"],
      workflowNodeType: "ToolResultRetrievalNode",
      workflowConfigFields: ["toolPack.coding.resultRetrievalEnabled", "toolPack.coding.artifactEnabled"],
    },
  ];
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
  const legacyType = event.payload?.legacy_event_type;
  if (typeof legacyType === "string" && isSdkMessageType(legacyType)) return legacyType;
  switch (event.event_kind) {
    case "thread.started":
    case "turn.started":
      return "run_started";
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

export class MockRuntimeSubstrateClient implements RuntimeSubstrateClient {
  private readonly cwd: string;
  private readonly checkpointDir: string;
  private readonly agents = new Map<string, RuntimeAgentRecord>();
  private readonly runs = new Map<string, RuntimeRunRecord>();
  private readonly memories = new Map<string, AgentMemoryRecord>();
  private readonly memoryPolicies = new Map<string, AgentMemoryPolicy>();
  private readonly subagents = new Map<string, RuntimeSubagentRecord>();

  constructor(options: RuntimeSubstrateClientOptions = {}) {
    this.cwd = path.resolve(options.cwd ?? process.cwd());
    this.checkpointDir = path.resolve(
      options.checkpointDir ?? path.join(this.cwd, ".ioi", "agent-sdk-mock"),
    );
    this.loadCheckpoints();
  }

  async createThread(input: RuntimeThreadCreateInput = {}): Promise<RuntimeThreadRecord> {
    const agent = await this.createAgent(input.options ?? (input as AgentOptions));
    return this.threadRecordForAgent(agent);
  }

  async listThreads(): Promise<RuntimeThreadRecord[]> {
    return (await this.listAgents()).map((agent) => this.threadRecordForAgent(agent));
  }

  async getThread(threadId: string): Promise<RuntimeThreadRecord> {
    return this.threadRecordForAgent(await this.agentForThread(threadId));
  }

  async getThreadUsage(threadId: string): Promise<RuntimeUsageTelemetry> {
    return this.usageForThread(threadId);
  }

  async resumeThread(threadId: string): Promise<RuntimeThreadRecord> {
    const agent = await this.agentForThread(threadId);
    return this.threadRecordForAgent(await this.resumeAgent(agent.id));
  }

  async forkThread(threadId: string, input: RuntimeThreadForkInput = {}): Promise<RuntimeThreadRecord> {
    const source = await this.getThread(threadId);
    const agent = await this.createAgent({
      ...(input.options ?? {}),
      local: input.options?.local ?? { cwd: source.workspace_root },
      model: input.options?.model ?? { id: source.model_route },
    });
    return {
      ...this.threadRecordForAgent(agent),
      agentgres_projection_ref: `forked_from:${source.thread_id}:${source.latest_seq}`,
    };
  }

  async compactThread(
    threadId: string,
    input: RuntimeThreadCompactInput = {},
  ): Promise<RuntimeThreadRecord> {
    const agent = await this.agentForThread(threadId);
    const reason = typeof input.reason === "string" && input.reason.trim()
      ? input.reason.trim()
      : "operator requested context compaction";
    const source = typeof input.source === "string" && input.source.trim()
      ? input.source.trim()
      : "sdk_client";
    const scope = typeof input.scope === "string" && input.scope.trim() ? input.scope.trim() : "thread";
    const runs = (await this.listRuns(agent.id)).sort((left, right) =>
      left.createdAt.localeCompare(right.createdAt),
    );
    const run = runs.at(-1);
    if (!run) return this.threadRecordForAgent(agent);
    const existingCompact = run.events.find(
      (event) =>
        event.type === "context_compacted" &&
        event.data &&
        typeof event.data === "object" &&
        !Array.isArray(event.data) &&
        (event.data as { reason?: unknown }).reason === reason,
    );
    if (existingCompact) return this.threadRecordForAgent(agent);
    const turnId = turnIdForRun(run.id);
    const compactedEvent = makeEvent(
      run.id,
      run.agentId,
      run.events.length,
      "context_compacted",
      "Context compacted",
      {
        eventKind: "OperatorControl.Compact",
        reason,
        source,
        scope,
        threadId,
        turnId,
        workflowNodeId: input.workflowNodeId ?? "runtime.context-compact",
      },
    );
    const compacted = {
      ...run,
      updatedAt: compactedEvent.createdAt,
      events: [...run.events, compactedEvent],
      trace: {
        ...run.trace,
        events: [...run.events, compactedEvent],
        operatorControls: [
          ...((run.trace as { operatorControls?: unknown[] }).operatorControls ?? []),
          {
            control: "compact",
            source,
            reason,
            scope,
            eventId: compactedEvent.id,
            createdAt: compactedEvent.createdAt,
          },
        ],
      },
    };
    this.persistRun(compacted);
    return this.threadRecordForAgent(agent);
  }

  async updateThreadMode(
    threadId: string,
    input: RuntimeThreadModeInput,
  ): Promise<RuntimeThreadRecord> {
    const agent = await this.agentForThread(threadId);
    const mode = String(input.mode ?? "agent").trim() || "agent";
    const approvalMode = String(
      input.approvalMode ??
        (mode === "yolo" ? "never_prompt" : mode === "plan" || mode === "review" ? "human_required" : "suggest"),
    );
    const updated = {
      ...agent,
      updatedAt: new Date().toISOString(),
      runtimeControls: {
        ...(agent as RuntimeAgentRecord & { runtimeControls?: Record<string, unknown> }).runtimeControls,
        mode,
        approvalMode,
        approval_mode: approvalMode,
      },
    } as RuntimeAgentRecord;
    this.persistAgent(updated);
    return this.threadRecordForAgent(updated);
  }

  async updateThreadModel(
    threadId: string,
    input: RuntimeThreadModelInput,
  ): Promise<RuntimeThreadRecord> {
    const agent = await this.agentForThread(threadId);
    const modelInput =
      input.model && typeof input.model === "object" && !Array.isArray(input.model)
        ? input.model
        : {};
    const requestedModel =
      (typeof input.model === "string" ? input.model : undefined) ??
      input.modelId ??
      modelInput.id ??
      modelInput.modelId ??
      agent.requestedModelId ??
      agent.modelId;
    const routeId = input.routeId ?? modelInput.routeId ?? agent.modelRouteId ?? "route.local-first";
    const reasoningEffort = input.reasoningEffort ?? modelInput.reasoningEffort;
    const updated = {
      ...agent,
      modelId: requestedModel,
      requestedModelId: requestedModel,
      modelRouteId: routeId,
      updatedAt: new Date().toISOString(),
      runtimeControls: {
        ...(agent as RuntimeAgentRecord & { runtimeControls?: Record<string, unknown> }).runtimeControls,
        model: {
          id: requestedModel,
          routeId,
          selectedModel: requestedModel,
          reasoningEffort,
          workflowNodeId: input.workflowNodeId ?? modelInput.workflowNodeId ?? "runtime.model-router",
        },
      },
    } as RuntimeAgentRecord;
    this.persistAgent(updated);
    return this.threadRecordForAgent(updated);
  }

  async updateThreadThinking(
    threadId: string,
    input: RuntimeThreadThinkingInput,
  ): Promise<RuntimeThreadRecord> {
    return this.updateThreadModel(threadId, {
      reasoningEffort: input.reasoningEffort ?? input.thinking,
      source: input.source,
      actor: input.actor,
      workflowGraphId: input.workflowGraphId,
      workflowNodeId: input.workflowNodeId,
    });
  }

  async submitTurn(threadId: string, input: RuntimeTurnCreateInput): Promise<RuntimeTurnRecord> {
    const agent = await this.agentForThread(threadId);
    const prompt = input.prompt ?? input.message ?? input.input ?? "";
    const options = {
      ...(input.options ?? {}),
      ...(input.memory ? { memory: input.memory } : {}),
      ...(input.remember ? { memory: { ...(input.options?.memory ?? {}), remember: input.remember } } : {}),
    } as SendOptions;
    const run = await this.createRun(agent.id, prompt, input.mode ?? "send", options);
    return this.turnRecordForRun(run);
  }

  async listTurns(threadId: string): Promise<RuntimeTurnRecord[]> {
    const agent = await this.agentForThread(threadId);
    return (await this.listRuns(agent.id)).map((run) => this.turnRecordForRun(run));
  }

  async getTurn(threadId: string, turnId: string): Promise<RuntimeTurnRecord> {
    const turn = (await this.listTurns(threadId)).find((candidate) => candidate.turn_id === turnId);
    if (!turn) {
      throw new IoiAgentError({ code: "not_found", message: `Turn not found: ${turnId}` });
    }
    return turn;
  }

  async interruptTurn(
    threadId: string,
    turnId: string,
    input: RuntimeTurnInterruptInput = {},
  ): Promise<RuntimeTurnRecord> {
    const turn = await this.getTurn(threadId, turnId);
    const run = await this.getRun(turn.request_id);
    const reason = typeof input.reason === "string" && input.reason.trim()
      ? input.reason.trim()
      : "operator requested interrupt";
    const source = typeof input.source === "string" && input.source.trim()
      ? input.source.trim()
      : "sdk_client";
    const events = run.events.filter((event) => event.type !== "interrupted");
    const interruptedEvent = makeEvent(
      run.id,
      run.agentId,
      events.length,
      "interrupted",
      "Turn interrupted",
      {
        eventKind: "OperatorControl.Interrupt",
        reason,
        source,
        threadId,
        turnId,
        workflowNodeId: input.workflowNodeId ?? "runtime.operator-interrupt",
      },
    );
    const stopCondition: StopConditionProjection = {
      reason: "operator_interrupt",
      evidenceSufficient: true,
      rationale: `Operator interrupt accepted from ${source}: ${reason}`,
    };
    const trace = {
      ...run.trace,
      events: [...events, interruptedEvent],
      stopCondition,
      qualityLedger: {
        ...run.trace.qualityLedger,
        failureOntologyLabels: [
          ...new Set([...run.trace.qualityLedger.failureOntologyLabels, "operator_interrupt"]),
        ],
      },
    };
    const interrupted = {
      ...run,
      status: ["queued", "running", "blocked"].includes(run.status) ? "canceled" as const : run.status,
      turnStatus: "interrupted" as const,
      updatedAt: interruptedEvent.createdAt,
      events: trace.events,
      trace,
      result: `Turn interrupted by operator: ${reason}`,
    };
    this.persistRun(interrupted);
    return this.turnRecordForRun(interrupted);
  }

  async steerTurn(
    threadId: string,
    turnId: string,
    input: RuntimeTurnSteerInput = {},
  ): Promise<RuntimeTurnRecord> {
    const turn = await this.getTurn(threadId, turnId);
    const run = await this.getRun(turn.request_id);
    const guidance = typeof input.guidance === "string" && input.guidance.trim()
      ? input.guidance.trim()
      : typeof input.message === "string" && input.message.trim()
        ? input.message.trim()
        : typeof input.input === "string" && input.input.trim()
          ? input.input.trim()
          : "operator provided steering guidance";
    const source = typeof input.source === "string" && input.source.trim()
      ? input.source.trim()
      : "sdk_client";
    const existingSteer = run.events.find(
      (event) =>
        event.type === "steered" &&
        event.data &&
        typeof event.data === "object" &&
        !Array.isArray(event.data) &&
        (event.data as { guidance?: unknown }).guidance === guidance,
    );
    if (existingSteer) return this.turnRecordForRun(run);
    const events = run.events;
    const steeredEvent = makeEvent(
      run.id,
      run.agentId,
      events.length,
      "steered",
      "Turn steered",
      {
        eventKind: "OperatorControl.Steer",
        guidance,
        source,
        threadId,
        turnId,
        workflowNodeId: input.workflowNodeId ?? "runtime.operator-steer",
      },
    );
    const steered = {
      ...run,
      updatedAt: steeredEvent.createdAt,
      events: [...events, steeredEvent],
      trace: {
        ...run.trace,
        events: [...events, steeredEvent],
        operatorControls: [
          ...((run.trace as { operatorControls?: unknown[] }).operatorControls ?? []),
          {
            control: "steer",
            source,
            guidance,
            eventId: steeredEvent.id,
            createdAt: steeredEvent.createdAt,
          },
        ],
      },
    };
    this.persistRun(steered);
    return this.turnRecordForRun(steered);
  }

  async *streamThreadEvents(
    threadId: string,
    options: RuntimeEventStreamOptions = {},
  ): AsyncIterable<RuntimeThreadEvent> {
    const agent = await this.agentForThread(threadId);
    const events = this.threadRuntimeEvents(agent);
    const cursorSeq = mockRuntimeCursorSeq(events, options);
    for (const event of events.filter((candidate) => candidate.seq > cursorSeq)) {
      options.signal?.throwIfAborted();
      yield runtimeThreadEventFromEnvelope(event);
    }
  }

  async listSubagents(
    threadId: string,
    input: RuntimeSubagentListInput = {},
  ): Promise<RuntimeSubagentListResult> {
    const parentAgent = await this.agentForThread(threadId);
    const role = runtimeSubagentText(input.role ?? input.subagentRole ?? input.subagent_role)?.toLowerCase();
    const subagents = [...this.subagents.values()]
      .filter((record) => (record.parent_thread_id ?? record.parentThreadId) === threadId)
      .filter((record) => !role || record.role === role)
      .sort((left, right) =>
        String(left.created_at ?? left.createdAt ?? "").localeCompare(
          String(right.created_at ?? right.createdAt ?? ""),
        ),
      );
    return {
      schema_version: "ioi.runtime.subagent-manager.v1",
      schemaVersion: "ioi.runtime.subagent-manager.v1",
      object: "ioi.runtime_subagent_list",
      thread_id: threadId,
      threadId,
      parent_agent_id: parentAgent.id,
      parentAgentId: parentAgent.id,
      status: "ready",
      count: subagents.length,
      active_count: subagents.filter(runtimeSubagentIsActive).length,
      activeCount: subagents.filter(runtimeSubagentIsActive).length,
      subagents,
    };
  }

  async spawnSubagent(
    threadId: string,
    input: RuntimeSubagentControlInput,
  ): Promise<RuntimeSubagentRecord> {
    const parentAgent = await this.agentForThread(threadId);
    const prompt = runtimeSubagentText(
      input.prompt ?? input.message ?? input.input ?? input.subagentPrompt ?? input.subagent_prompt,
    );
    if (!prompt) {
      throw new IoiAgentError({
        code: "runtime",
        message: "Subagent spawn requires a prompt.",
        details: { threadId },
      });
    }
    const role = runtimeSubagentText(input.role ?? input.subagentRole ?? input.subagent_role)?.toLowerCase() ?? "general";
    const maxConcurrency = Number(input.maxConcurrency ?? input.max_concurrency ?? input.subagentMaxConcurrency ?? 0);
    if (Number.isFinite(maxConcurrency) && maxConcurrency > 0) {
      const activeForRole = (await this.listSubagents(threadId, { role })).subagents.filter(runtimeSubagentIsActive).length;
      if (activeForRole >= maxConcurrency) {
        throw new IoiAgentError({
          code: "policy",
          message: "Subagent role concurrency limit reached.",
          details: { threadId, role, activeForRole, maxConcurrency },
        });
      }
    }
    const childAgent = await this.createAgent({
      local: { cwd: parentAgent.cwd },
      model: {
        id: parentAgent.requestedModelId ?? parentAgent.modelId ?? "local:auto",
        routeId: parentAgent.modelRouteId ?? "route.local-first",
      },
    });
    const run = await this.createRun(childAgent.id, prompt, "send", {
      metadata: { receiver: role, subagent: true },
    });
    const now = new Date().toISOString();
    const subagentId = childAgent.id;
    const outputContractStatus: RuntimeSubagentOutputContractStatus = {
      schema_version: "ioi.runtime.subagent-output-contract-status.v1",
      schemaVersion: "ioi.runtime.subagent-output-contract-status.v1",
      status: "passed",
      required_sections: ["SUMMARY"],
      requiredSections: ["SUMMARY"],
      present_sections: ["SUMMARY"],
      presentSections: ["SUMMARY"],
      missing_sections: [],
      missingSections: [],
      validated_at: now,
      validatedAt: now,
    };
    const record: RuntimeSubagentRecord = {
      schema_version: "ioi.runtime.subagent-manager.v1",
      schemaVersion: "ioi.runtime.subagent-manager.v1",
      object: "ioi.runtime_subagent",
      subagent_id: subagentId,
      subagentId,
      agent_id: childAgent.id,
      agentId: childAgent.id,
      child_thread_id: threadIdForAgent(childAgent.id),
      childThreadId: threadIdForAgent(childAgent.id),
      run_id: run.id,
      runId: run.id,
      parent_thread_id: threadId,
      parentThreadId: threadId,
      parent_agent_id: parentAgent.id,
      parentAgentId: parentAgent.id,
      role,
      tool_pack: runtimeSubagentText(input.toolPack ?? input.tool_pack ?? input.subagentToolPack) ?? null,
      toolPack: runtimeSubagentText(input.toolPack ?? input.tool_pack ?? input.subagentToolPack) ?? null,
      model_route_id:
        runtimeSubagentText(input.modelRouteId ?? input.model_route_id ?? input.subagentModelRoute) ??
        parentAgent.modelRouteId ??
        null,
      modelRouteId:
        runtimeSubagentText(input.modelRouteId ?? input.model_route_id ?? input.subagentModelRoute) ??
        parentAgent.modelRouteId ??
        null,
      workflow_graph_id: runtimeSubagentText(input.workflowGraphId ?? input.workflow_graph_id) ?? null,
      workflowGraphId: runtimeSubagentText(input.workflowGraphId ?? input.workflow_graph_id) ?? null,
      workflow_node_id:
        runtimeSubagentText(input.workflowNodeId ?? input.workflow_node_id) ??
        `runtime.subagent.spawn.${role}`,
      workflowNodeId:
        runtimeSubagentText(input.workflowNodeId ?? input.workflow_node_id) ??
        `runtime.subagent.spawn.${role}`,
      lifecycle_status: runtimeSubagentStatusForRun(run.status),
      lifecycleStatus: runtimeSubagentStatusForRun(run.status),
      status: runtimeSubagentStatusForRun(run.status),
      restart_status: "not_restarted",
      restartStatus: "not_restarted",
      restart_count: 0,
      restartCount: 0,
      input_count: 0,
      inputCount: 0,
      assignment_count: 0,
      assignmentCount: 0,
      merge_policy: runtimeSubagentText(input.mergePolicy ?? input.merge_policy) ?? "manual",
      mergePolicy: runtimeSubagentText(input.mergePolicy ?? input.merge_policy) ?? "manual",
      cancellation_inheritance:
        runtimeSubagentText(input.cancellationInheritance ?? input.cancellation_inheritance) ?? "propagate",
      cancellationInheritance:
        runtimeSubagentText(input.cancellationInheritance ?? input.cancellation_inheritance) ?? "propagate",
      output_contract_status: outputContractStatus.status ?? null,
      outputContractStatus,
      created_at: now,
      createdAt: now,
      updated_at: now,
      updatedAt: now,
      receipt_refs: run.receipts.map((receipt) => receipt.id),
      receiptRefs: run.receipts.map((receipt) => receipt.id),
      evidence_refs: ["runtime.subagent_manager", "runtime.subagent.spawn", run.id],
      evidenceRefs: ["runtime.subagent_manager", "runtime.subagent.spawn", run.id],
    };
    record.result = await this.mockSubagentResultForRecord(record);
    this.subagents.set(subagentId, record);
    return record;
  }

  async waitSubagent(
    threadId: string,
    subagentId: string,
    input: RuntimeSubagentControlInput = {},
  ): Promise<RuntimeSubagentResult> {
    const record = await this.mockSubagentForThread(threadId, subagentId);
    const result = await this.mockSubagentResultForRecord(record);
    return {
      ...result,
      event: await this.mockSubagentControlEvent(threadId, record, "wait", input),
    };
  }

  async getSubagentResult(threadId: string, subagentId: string): Promise<RuntimeSubagentResult> {
    return this.mockSubagentResultForRecord(await this.mockSubagentForThread(threadId, subagentId));
  }

  async sendSubagentInput(
    threadId: string,
    subagentId: string,
    input: RuntimeSubagentControlInput,
  ): Promise<RuntimeSubagentRecord> {
    const record = await this.mockSubagentForThread(threadId, subagentId);
    const message = runtimeSubagentText(input.input ?? input.message ?? input.prompt ?? input.text);
    if (!message) {
      throw new IoiAgentError({
        code: "runtime",
        message: "Subagent input requires a message.",
        details: { threadId, subagentId },
      });
    }
    const childAgentId = record.agent_id ?? record.agentId ?? subagentId;
    const previousRunId = record.run_id ?? record.runId ?? null;
    const run = await this.createRun(childAgentId, message, "send", {
      metadata: { receiver: record.role ?? "general", subagentInput: true },
    });
    const inputCount = Number(record.input_count ?? record.inputCount ?? 0) + 1;
    const now = new Date().toISOString();
    const inputId = `subagent_input_${crypto.randomUUID()}`;
    const updated: RuntimeSubagentRecord = {
      ...record,
      run_id: run.id,
      runId: run.id,
      previous_run_id: previousRunId,
      previousRunId: previousRunId,
      lifecycle_status: runtimeSubagentStatusForRun(run.status),
      lifecycleStatus: runtimeSubagentStatusForRun(run.status),
      status: runtimeSubagentStatusForRun(run.status),
      input_id: inputId,
      inputId,
      input_count: inputCount,
      inputCount,
      last_input: message,
      lastInput: message,
      last_input_at: now,
      lastInputAt: now,
      updated_at: now,
      updatedAt: now,
      event: await this.mockSubagentControlEvent(threadId, record, "send_input", input),
      receipt_refs: [...new Set([...(record.receipt_refs ?? []), ...run.receipts.map((receipt) => receipt.id)])],
      receiptRefs: [...new Set([...(record.receiptRefs ?? []), ...run.receipts.map((receipt) => receipt.id)])],
    };
    updated.result = await this.mockSubagentResultForRecord(updated);
    this.subagents.set(subagentId, updated);
    return updated;
  }

  async cancelSubagent(
    threadId: string,
    subagentId: string,
    input: RuntimeSubagentControlInput = {},
  ): Promise<RuntimeSubagentResult> {
    const record = await this.mockSubagentForThread(threadId, subagentId);
    const runId = record.run_id ?? record.runId;
    if (runId) {
      await this.cancelRun(runId);
    }
    const now = new Date().toISOString();
    const reason = runtimeSubagentText(input.reason ?? input.cancellationReason ?? input.cancellation_reason) ?? "operator_cancel";
    const cancellation = {
      reason,
      requestedBy: runtimeSubagentText(input.actor) ?? "operator",
      inherited: Boolean(input.inherited ?? input.cancellationInherited ?? input.cancellation_inherited),
      propagatedFromThreadId:
        runtimeSubagentText(input.propagatedFromThreadId ?? input.propagated_from_thread_id) ?? null,
      source: runtimeSubagentText(input.source) ?? "sdk_client",
    };
    const updated: RuntimeSubagentRecord = {
      ...record,
      lifecycle_status: "canceled",
      lifecycleStatus: "canceled",
      status: "canceled",
      canceled_at: now,
      canceledAt: now,
      cancellation_reason: reason,
      cancellationReason: reason,
      cancellation_inherited: cancellation.inherited,
      cancellationInherited: cancellation.inherited,
      propagated_from_thread_id: cancellation.propagatedFromThreadId,
      propagatedFromThreadId: cancellation.propagatedFromThreadId,
      cancellation,
      updated_at: now,
      updatedAt: now,
    };
    updated.result = await this.mockSubagentResultForRecord(updated);
    this.subagents.set(subagentId, updated);
    return {
      ...updated.result,
      subagent: updated,
      cancellation,
      event: await this.mockSubagentControlEvent(threadId, updated, "cancel", input),
    };
  }

  async resumeSubagent(
    threadId: string,
    subagentId: string,
    input: RuntimeSubagentControlInput = {},
  ): Promise<RuntimeSubagentResult> {
    const record = await this.mockSubagentForThread(threadId, subagentId);
    const childAgentId = record.agent_id ?? record.agentId ?? subagentId;
    const role = runtimeSubagentText(input.role ?? input.subagentRole ?? input.subagent_role) ?? record.role ?? "general";
    const prompt = runtimeSubagentText(input.prompt ?? input.message ?? input.input) ?? `Resume subagent ${role}.`;
    const run = await this.createRun(childAgentId, prompt, "send", {
      metadata: { receiver: role, subagentResume: true },
    });
    const now = new Date().toISOString();
    const restartCount = Number(record.restart_count ?? record.restartCount ?? 0) + 1;
    const resumeId = `subagent_resume_${crypto.randomUUID()}`;
    const resume = {
      schema_version: "ioi.runtime.subagent-resume.v1",
      schemaVersion: "ioi.runtime.subagent-resume.v1",
      resume_id: resumeId,
      resumeId,
      run_id: run.id,
      runId: run.id,
      prompt,
      role,
      restart_count: restartCount,
      restartCount,
      created_at: now,
      createdAt: now,
    };
    const updated: RuntimeSubagentRecord = {
      ...record,
      role,
      run_id: run.id,
      runId: run.id,
      lifecycle_status: runtimeSubagentStatusForRun(run.status),
      lifecycleStatus: runtimeSubagentStatusForRun(run.status),
      status: runtimeSubagentStatusForRun(run.status),
      restart_status: "restarted",
      restartStatus: "restarted",
      restart_count: restartCount,
      restartCount,
      resume,
      cancellation: null,
      cancellation_reason: null,
      cancellationReason: null,
      updated_at: now,
      updatedAt: now,
      receipt_refs: [...new Set([...(record.receipt_refs ?? []), ...run.receipts.map((receipt) => receipt.id)])],
      receiptRefs: [...new Set([...(record.receiptRefs ?? []), ...run.receipts.map((receipt) => receipt.id)])],
    };
    updated.result = await this.mockSubagentResultForRecord(updated);
    this.subagents.set(subagentId, updated);
    return {
      ...updated.result,
      subagent: updated,
      resume,
      event: await this.mockSubagentControlEvent(threadId, updated, "resume", input),
    };
  }

  async assignSubagent(
    threadId: string,
    subagentId: string,
    input: RuntimeSubagentControlInput = {},
  ): Promise<RuntimeSubagentRecord> {
    const record = await this.mockSubagentForThread(threadId, subagentId);
    const now = new Date().toISOString();
    const assignmentCount = Number(record.assignment_count ?? record.assignmentCount ?? 0) + 1;
    const assignmentId = `subagent_assignment_${crypto.randomUUID()}`;
    const assignment = {
      schema_version: "ioi.runtime.subagent-assignment.v1",
      schemaVersion: "ioi.runtime.subagent-assignment.v1",
      assignment_id: assignmentId,
      assignmentId,
      previous_role: record.role ?? "general",
      previousRole: record.role ?? "general",
      role: runtimeSubagentText(input.role ?? input.subagentRole ?? input.subagent_role) ?? record.role ?? "general",
      target_agent_id: runtimeSubagentText(input.targetAgentId ?? input.target_agent_id) ?? record.agent_id ?? record.agentId,
      targetAgentId: runtimeSubagentText(input.targetAgentId ?? input.target_agent_id) ?? record.agentId ?? record.agent_id,
      created_at: now,
      createdAt: now,
    };
    const updated: RuntimeSubagentRecord = {
      ...record,
      role: String(assignment.role),
      target_agent_id: assignment.target_agent_id,
      targetAgentId: assignment.targetAgentId,
      tool_pack: runtimeSubagentText(input.toolPack ?? input.tool_pack ?? input.subagentToolPack) ?? record.tool_pack ?? null,
      toolPack: runtimeSubagentText(input.toolPack ?? input.tool_pack ?? input.subagentToolPack) ?? record.toolPack ?? null,
      model_route_id:
        runtimeSubagentText(input.modelRouteId ?? input.model_route_id ?? input.subagentModelRoute) ??
        record.model_route_id ??
        null,
      modelRouteId:
        runtimeSubagentText(input.modelRouteId ?? input.model_route_id ?? input.subagentModelRoute) ??
        record.modelRouteId ??
        null,
      merge_policy: runtimeSubagentText(input.mergePolicy ?? input.merge_policy) ?? record.merge_policy ?? "manual",
      mergePolicy: runtimeSubagentText(input.mergePolicy ?? input.merge_policy) ?? record.mergePolicy ?? "manual",
      cancellation_inheritance:
        runtimeSubagentText(input.cancellationInheritance ?? input.cancellation_inheritance) ??
        record.cancellation_inheritance ??
        "propagate",
      cancellationInheritance:
        runtimeSubagentText(input.cancellationInheritance ?? input.cancellation_inheritance) ??
        record.cancellationInheritance ??
        "propagate",
      assignment,
      assignment_count: assignmentCount,
      assignmentCount,
      updated_at: now,
      updatedAt: now,
      event: await this.mockSubagentControlEvent(threadId, record, "assign", input),
    };
    updated.result = await this.mockSubagentResultForRecord(updated);
    this.subagents.set(subagentId, updated);
    return updated;
  }

  async propagateSubagentCancellation(
    threadId: string,
    input: RuntimeSubagentControlInput = {},
  ): Promise<RuntimeSubagentCancellationPropagationResult> {
    const parentAgent = await this.agentForThread(threadId);
    const candidates = (await this.listSubagents(threadId)).subagents;
    const canceled: RuntimeSubagentRecord[] = [];
    const skipped: RuntimeSubagentRecord[] = [];
    for (const record of candidates) {
      const inheritance = record.cancellation_inheritance ?? record.cancellationInheritance ?? "propagate";
      const status = record.lifecycle_status ?? record.lifecycleStatus ?? record.status;
      const targetId = record.subagent_id ?? record.subagentId ?? record.agent_id ?? record.agentId;
      if (inheritance !== "propagate" || status === "canceled" || !targetId) {
        skipped.push({
          ...record,
          skip_reason: inheritance !== "propagate" ? "cancellation_inheritance_not_propagate" : "already_canceled",
          skipReason: inheritance !== "propagate" ? "cancellation_inheritance_not_propagate" : "already_canceled",
        });
        continue;
      }
      const result = await this.cancelSubagent(threadId, targetId, {
        ...input,
        inherited: true,
        cancellationInherited: true,
        propagatedFromThreadId: threadId,
      });
      if (result.subagent) canceled.push(result.subagent);
    }
    return {
      schema_version: "ioi.runtime.subagent-manager.v1",
      schemaVersion: "ioi.runtime.subagent-manager.v1",
      object: "ioi.runtime_subagent_cancellation_propagation",
      thread_id: threadId,
      threadId,
      parent_agent_id: parentAgent.id,
      parentAgentId: parentAgent.id,
      status: "completed",
      source: runtimeSubagentText(input.source) ?? "sdk_client",
      reason: runtimeSubagentText(input.reason ?? input.cancellationReason ?? input.cancellation_reason) ?? "parent_cancel",
      propagation_policy: "cancellationInheritance=propagate",
      propagationPolicy: "cancellationInheritance=propagate",
      candidate_count: candidates.length,
      candidateCount: candidates.length,
      canceled_count: canceled.length,
      canceledCount: canceled.length,
      skipped_count: skipped.length,
      skippedCount: skipped.length,
      canceled_subagents: canceled,
      canceledSubagents: canceled,
      skipped_subagents: skipped,
      skippedSubagents: skipped,
      event_refs: [],
      eventRefs: [],
      receipt_refs: [...new Set(canceled.flatMap((record) => record.receipt_refs ?? []))],
      receiptRefs: [...new Set(canceled.flatMap((record) => record.receiptRefs ?? []))],
    };
  }

  private async mockSubagentForThread(
    threadId: string,
    subagentId: string,
  ): Promise<RuntimeSubagentRecord> {
    await this.agentForThread(threadId);
    const record = this.subagents.get(subagentId);
    if (!record || (record.parent_thread_id ?? record.parentThreadId) !== threadId) {
      throw new IoiAgentError({
        code: "not_found",
        message: `Subagent not found: ${subagentId}`,
        details: { threadId, subagentId },
      });
    }
    return record;
  }

  private async mockSubagentResultForRecord(record: RuntimeSubagentRecord): Promise<RuntimeSubagentResult> {
    const runId = record.run_id ?? record.runId ?? null;
    const run = runId ? await this.getRun(runId) : null;
    const status = record.status ?? runtimeSubagentStatusForRun(run?.status);
    const text = run?.result ?? "";
    const receiptRefs = [
      ...new Set([
        ...(record.receipt_refs ?? []),
        ...(record.receiptRefs ?? []),
        ...(run?.receipts.map((receipt) => receipt.id) ?? []),
      ]),
    ];
    const outputContractStatus =
      record.outputContractStatus && typeof record.outputContractStatus === "object"
        ? record.outputContractStatus
        : {
            schema_version: "ioi.runtime.subagent-output-contract-status.v1",
            schemaVersion: "ioi.runtime.subagent-output-contract-status.v1",
            status: record.output_contract_status ?? "passed",
          };
    return {
      schema_version: "ioi.runtime.subagent-result.v1",
      schemaVersion: "ioi.runtime.subagent-result.v1",
      object: "ioi.runtime_subagent_result",
      subagent_id: record.subagent_id ?? record.subagentId ?? null,
      subagentId: record.subagentId ?? record.subagent_id ?? null,
      agent_id: record.agent_id ?? record.agentId ?? null,
      agentId: record.agentId ?? record.agent_id ?? null,
      run_id: runId,
      runId,
      lifecycle_status: status,
      lifecycleStatus: status,
      status,
      result: text,
      output: {
        schema_version: "ioi.runtime.subagent-result.v1",
        schemaVersion: "ioi.runtime.subagent-result.v1",
        object: "ioi.runtime_subagent_output_contract",
        text,
        sections: { SUMMARY: text },
      },
      output_contract_status: outputContractStatus.status ?? null,
      outputContractStatus: outputContractStatus,
      budget_status:
        record.budget_status ??
        (typeof record.budgetStatus === "object" ? record.budgetStatus?.status : record.budgetStatus) ??
        null,
      budgetStatus: record.budgetStatus ?? record.budget_status ?? null,
      usage_telemetry: record.usage_telemetry ?? record.usageTelemetry ?? null,
      usageTelemetry: record.usageTelemetry ?? record.usage_telemetry ?? null,
      cost_estimate_usd: record.cost_estimate_usd ?? record.costEstimateUsd ?? null,
      costEstimateUsd: record.costEstimateUsd ?? record.cost_estimate_usd ?? null,
      token_estimate: record.token_estimate ?? record.tokenEstimate ?? null,
      tokenEstimate: record.tokenEstimate ?? record.token_estimate ?? null,
      receipt_refs: receiptRefs,
      receiptRefs,
      subagent: {
        ...record,
        lifecycle_status: status,
        lifecycleStatus: status,
        status,
      },
    };
  }

  private async mockSubagentControlEvent(
    threadId: string,
    record: RuntimeSubagentRecord,
    operation: string,
    input: RuntimeSubagentControlInput,
  ): Promise<RuntimeEventEnvelope> {
    const parentAgent = await this.agentForThread(threadId);
    const createdAt = new Date().toISOString();
    return mockRuntimeEventEnvelope({
      agent: parentAgent,
      threadId,
      streamId: eventStreamIdForThread(threadId),
      seq: 1,
      eventKind: `subagent.${operation}`,
      sourceEventKind: `Subagent.${operation}`,
      itemId: `${threadId}:subagent:${record.subagent_id ?? record.subagentId ?? "unknown"}:${operation}`,
      payload: {
        operation,
        source: runtimeSubagentText(input.source) ?? "sdk_client",
        subagent_id: record.subagent_id ?? record.subagentId ?? null,
        subagentId: record.subagentId ?? record.subagent_id ?? null,
      },
      createdAt,
      payloadSchemaVersion: "ioi.runtime.subagent-manager.v1",
      componentKind: "subagent_manager",
      workflowNodeId:
        runtimeSubagentText(input.workflowNodeId ?? input.workflow_node_id) ??
        record.workflow_node_id ??
        record.workflowNodeId ??
        `runtime.subagent.${operation}`,
      receiptRefs: [`receipt_subagent_${operation}_${record.subagent_id ?? record.subagentId ?? "unknown"}`],
    });
  }

  async createAgent(options: AgentOptions): Promise<RuntimeAgentRecord> {
    const runtime = runtimeModeForOptions(options);
    ensureProviderConfigured(runtime, options);
    const cwd = path.resolve(options.local?.cwd ?? this.cwd);
    const modelRouteDecision = mockModelRouteDecision(options.model, options.model?.id ?? "local:auto");
    const agent: RuntimeAgentRecord = {
      id: `agent_${crypto.randomUUID()}`,
      status: "active",
      runtime,
      cwd,
      modelId: modelRouteDecision.selectedModel ?? options.model?.id ?? "local:auto",
      requestedModelId: modelRouteDecision.requestedModel ?? options.model?.id ?? "local:auto",
      modelRouteId: modelRouteDecision.routeId ?? "route.local-first",
      modelRouteEndpointId: modelRouteDecision.endpointId,
      modelRouteProviderId: modelRouteDecision.providerId,
      modelRouteReceiptId: `receipt_agent_${crypto.randomUUID()}_model_route`,
      modelRouteDecision,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      options: summarizeOptions(cwd, options),
    };
    this.agents.set(agent.id, agent);
    this.persistAgent(agent);
    return agent;
  }

  async resumeAgent(agentId: string): Promise<RuntimeAgentRecord> {
    const agent = await this.getAgent(agentId);
    return { ...agent, status: agent.status === "closed" ? "active" : agent.status };
  }

  async closeAgent(agentId: string): Promise<void> {
    const agent = await this.getAgent(agentId);
    this.persistAgent({ ...agent, status: "closed", updatedAt: new Date().toISOString() });
  }

  async reloadAgent(agentId: string): Promise<RuntimeAgentRecord> {
    const agent = await this.getAgent(agentId);
    const reloaded = { ...agent, updatedAt: new Date().toISOString() };
    this.persistAgent(reloaded);
    return reloaded;
  }

  async listAgents(): Promise<RuntimeAgentRecord[]> {
    return [...this.agents.values()].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  async getAgent(agentId: string): Promise<RuntimeAgentRecord> {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new IoiAgentError({ code: "not_found", message: `Agent not found: ${agentId}` });
    }
    return agent;
  }

  async archiveAgent(agentId: string): Promise<RuntimeAgentRecord> {
    const agent = await this.getAgent(agentId);
    const archived = { ...agent, status: "archived" as const, updatedAt: new Date().toISOString() };
    this.persistAgent(archived);
    return archived;
  }

  async unarchiveAgent(agentId: string): Promise<RuntimeAgentRecord> {
    const agent = await this.getAgent(agentId);
    const active = { ...agent, status: "active" as const, updatedAt: new Date().toISOString() };
    this.persistAgent(active);
    return active;
  }

  async deleteAgent(agentId: string): Promise<void> {
    const agent = await this.getAgent(agentId);
    const runCount = [...this.runs.values()].filter((run) => run.agentId === agentId).length;
    if (runCount > 0) {
      throw new IoiAgentError({
        code: "policy",
        message:
          "Permanent agent deletion requires data-retention approval when runs exist; archive instead.",
        details: { agentId: agent.id, runCount },
      });
    }
    this.agents.delete(agentId);
    this.rmQuiet(path.join(this.checkpointDir, "agents", `${agentId}.json`));
  }

  async send(
    agentId: string,
    prompt: string,
    options: SendOptions = {},
  ): Promise<RuntimeRunRecord> {
    return this.createRun(agentId, prompt, "send", options);
  }

  async plan(
    agentId: string,
    prompt: string,
    options: PlanOptions = {},
  ): Promise<RuntimeRunRecord> {
    return this.createRun(agentId, prompt, "plan", options);
  }

  async dryRun(
    agentId: string,
    prompt: string,
    options: DryRunOptions = {},
  ): Promise<RuntimeRunRecord> {
    return this.createRun(agentId, prompt, "dry_run", options);
  }

  async handoff(
    agentId: string,
    prompt: string,
    options: HandoffOptions = {},
  ): Promise<RuntimeRunRecord> {
    return this.createRun(agentId, prompt, "handoff", options);
  }

  async learn(agentId: string, options: LearnOptions): Promise<RuntimeRunRecord> {
    return this.createRun(
      agentId,
      `Learn governed task-family updates for ${options.taskFamily}`,
      "learn",
      { metadata: { learn: options } },
    );
  }

  async *streamRun(
    runId: string,
    options: { lastEventId?: string } = {},
  ): AsyncIterable<IOISDKMessage> {
    const run = await this.getRun(runId);
    const start = options.lastEventId
      ? run.events.findIndex((event) => event.id === options.lastEventId) + 1
      : 0;
    for (const event of run.events.slice(Math.max(0, start))) {
      yield event;
    }
  }

  async waitRun(runId: string): Promise<IOIRunResult> {
    const run = await this.getRun(runId);
    return {
      id: run.id,
      agentId: run.agentId,
      status: run.status,
      result: run.result,
      stopCondition: run.trace.stopCondition,
      routeDecision: run.modelRouteDecision ?? run.trace.modelRouteDecision ?? null,
      usage: run.usageTelemetry ?? run.usage_telemetry ?? run.runtimeUsage ?? run.usage ?? mockUsageForRun(run),
      trace: run.trace,
      scorecard: run.trace.scorecard,
    };
  }

  async cancelRun(runId: string): Promise<RuntimeRunRecord> {
    const run = await this.getRun(runId);
    if (run.status === "completed") {
      const canceled = this.withTerminalReplacement(run, "canceled", {
        reason: "operator canceled after completion request",
      });
      this.persistRun(canceled);
      return canceled;
    }
    const canceled = this.withTerminalReplacement(run, "canceled", {
      reason: "operator canceled run",
    });
    this.persistRun(canceled);
    return canceled;
  }

  async getRun(runId: string): Promise<RuntimeRunRecord> {
    const run = this.runs.get(runId);
    if (!run) {
      throw new IoiAgentError({ code: "not_found", message: `Run not found: ${runId}` });
    }
    return run;
  }

  async getRunUsage(runId: string): Promise<RuntimeUsageTelemetry> {
    const run = await this.getRun(runId);
    return run.usageTelemetry ?? run.usage_telemetry ?? run.runtimeUsage ?? run.usage ?? mockUsageForRun(run);
  }

  async listRuns(agentId?: string): Promise<RuntimeRunRecord[]> {
    return [...this.runs.values()]
      .filter((run) => !agentId || run.agentId === agentId)
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  async listUsage(input: RuntimeUsageListInput = {}): Promise<RuntimeUsageListResult> {
    const groupBy = input.groupBy ?? input.group_by ?? "run";
    const agentId = input.agentId ?? input.agent_id;
    if (groupBy === "thread") {
      const threadIds = new Set(
        (await this.listRuns(agentId)).map((run) => threadIdForAgent(run.agentId)),
      );
      const usage = await Promise.all([...threadIds].map((threadId) => this.usageForThread(threadId)));
      return mockUsageListEnvelope(groupBy, usage);
    }
    return mockUsageListEnvelope(
      "run",
      (await this.listRuns(agentId)).map(
        (run) => run.usageTelemetry ?? run.usage_telemetry ?? run.runtimeUsage ?? run.usage ?? mockUsageForRun(run),
      ),
    );
  }

  async createTask(options: RuntimeTaskCreateOptions = {}): Promise<RuntimeTaskRecord> {
    const agentId = options.agentId ?? options.agent_id;
    const agent = agentId
      ? await this.getAgent(agentId)
      : await this.createAgent({
          ...(options.agent ?? options.agentOptions ?? options.agent_options ?? {}),
          local: {
            cwd: options.cwd ?? options.workspace ?? this.cwd,
            ...((options.agent ?? options.agentOptions ?? options.agent_options ?? {}).local ?? {}),
          },
          model: options.model,
        } as AgentOptions);
    const run = await this.send(agent.id, options.prompt ?? options.objective ?? options.goal ?? "", {
      mode: options.mode,
      options: options.options,
    } as SendOptions);
    return runtimeTaskRecordForSdkRun(run);
  }

  async listTasks(options: RuntimeTaskListOptions = {}): Promise<RuntimeTaskRecord[]> {
    const agentId = options.agentId ?? options.agent_id;
    return (await this.listRuns(agentId))
      .map((run) => runtimeTaskRecordForSdkRun(run))
      .filter((task) => !options.status || task.status === options.status);
  }

  async getTask(taskId: string): Promise<RuntimeTaskRecord> {
    const task = (await this.listTasks()).find(
      (candidate) => candidate.taskId === taskId || candidate.runId === taskId,
    );
    if (!task) {
      throw new IoiAgentError({ code: "not_found", message: `Task not found: ${taskId}` });
    }
    return task;
  }

  async cancelTask(taskId: string): Promise<RuntimeTaskRecord> {
    const task = await this.getTask(taskId);
    const run = await this.cancelRun(task.runId);
    return runtimeTaskRecordForSdkRun(run);
  }

  async listJobs(options: RuntimeJobListOptions = {}): Promise<RuntimeJobRecord[]> {
    const agentId = options.agentId ?? options.agent_id;
    return (await this.listRuns(agentId))
      .map((run) => runtimeJobRecordForSdkRun(run))
      .filter((job) => !options.status || job.status === options.status);
  }

  async getJob(jobId: string): Promise<RuntimeJobRecord> {
    const job = (await this.listJobs()).find(
      (candidate) => candidate.jobId === jobId || candidate.runId === jobId,
    );
    if (!job) {
      throw new IoiAgentError({ code: "not_found", message: `Job not found: ${jobId}` });
    }
    return job;
  }

  async cancelJob(jobId: string): Promise<RuntimeJobRecord> {
    const job = await this.getJob(jobId);
    const run = await this.cancelRun(job.runId);
    return runtimeJobRecordForSdkRun(run);
  }

  async conversation(runId: string): Promise<ConversationMessage[]> {
    return (await this.getRun(runId)).conversation;
  }

  async listArtifacts(runId: string): Promise<RuntimeArtifact[]> {
    return (await this.getRun(runId)).artifacts;
  }

  async downloadArtifact(runId: string, artifactId: string): Promise<RuntimeArtifact> {
    const artifact = (await this.listArtifacts(runId)).find((item) => item.id === artifactId);
    if (!artifact) {
      throw new IoiAgentError({
        code: "not_found",
        message: `Artifact not found: ${artifactId}`,
      });
    }
    return artifact;
  }

  async exportTrace(runId: string): Promise<RuntimeTraceBundle> {
    return (await this.getRun(runId)).trace;
  }

  async *replayTrace(runId: string): AsyncIterable<IOISDKMessage> {
    yield* this.streamRun(runId);
  }

  async inspectRun(runId: string): Promise<RuntimeTraceBundle> {
    return this.exportTrace(runId);
  }

  async getRunComputerUseTrace(runId: string): Promise<RuntimeTraceBundle["computerUse"]> {
    return (await this.getRun(runId)).trace.computerUse ?? null;
  }

  async getRunComputerUseTrajectory(runId: string): Promise<unknown> {
    return (await this.getRunComputerUseTrace(runId))?.trajectory ?? null;
  }

  async discoverComputerUseBrowsers(
    options: RuntimeComputerUseBrowserDiscoveryOptions = {},
  ): Promise<RuntimeComputerUseBrowserDiscoveryReport> {
    const now = new Date().toISOString();
    return {
      schema_version: "ioi.computer-use.browser-discovery.v1",
      object: "ioi.computer_use.browser_discovery_report",
      receipt_ref: "receipt_mock_computer_use_browser_discovery",
      discovered_at: now,
      platform: "mock",
      process_count: 0,
      browser_process_count: 0,
      browser_processes: [],
      cdp_endpoint_count: 0,
      cdp_endpoints: [],
      default_profile_remote_debugging_blockers: [],
      safety: {
        read_only: true,
        mutated_browser_state: false,
        copied_profiles: false,
        copied_credentials: false,
        raw_profile_paths_redacted: true,
        raw_command_lines_redacted: true,
        cdp_probe_enabled: options.probe !== false,
        cdp_probe_scope: "declared_remote_debugging_ports_only",
      },
      recommended_next_steps: [
        "No mock browser process was discovered.",
        "Use a daemon-backed client for host browser discovery.",
      ],
    };
  }

  async scorecard(runId: string): Promise<RuntimeScorecard> {
    return (await this.getRun(runId)).trace.scorecard;
  }

  async listModels(): Promise<RuntimeModelCatalogEntry[]> {
    return [
      { id: "local:auto", provider: "ioi-local", cost: "local", quality: "adaptive" },
      { id: "gpt-5.5", provider: "configured-provider", cost: "high", quality: "frontier" },
      { id: "gpt-5.4-mini", provider: "configured-provider", cost: "low", quality: "fast" },
    ];
  }

  async listRepositories(): Promise<Array<{ url: string; source: string; status: string }>> {
    return [{ url: this.cwd, source: "local", status: "available" }];
  }

  async getAccount(): Promise<RuntimeAccountProfile> {
    return {
      id: "local-operator",
      email: process.env.IOI_OPERATOR_EMAIL ?? null,
      authorityLevel: "local",
      privacyClass: "local_private",
      source: "explicit_mock_runtime_substrate_projection",
    };
  }

  async listRuntimeNodes(): Promise<RuntimeNodeProfile[]> {
    return [
      {
        id: "local-mock-projection",
        kind: "local",
        status: "available",
        privacyClass: "local_private",
        evidenceRefs: ["explicit_mock_runtime_substrate_projection"],
      },
      {
        id: "hosted-provider",
        kind: "hosted",
        status: process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT ? "available" : "blocked",
        endpoint: process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT,
        privacyClass: "hosted",
        evidenceRefs: ["IOI_AGENT_SDK_HOSTED_ENDPOINT"],
      },
      {
        id: "self-hosted-provider",
        kind: "self_hosted",
        status: process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT ? "available" : "blocked",
        endpoint: process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT,
        privacyClass: "workspace",
        evidenceRefs: ["IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT"],
      },
    ];
  }

  async listTools(options: RuntimeToolListOptions = {}): Promise<RuntimeToolCatalogEntry[]> {
    const tools: RuntimeToolCatalogEntry[] = [
      {
        stableToolId: "fs.read",
        displayName: "Read file",
        pack: "runtime",
        primitiveCapabilities: ["prim:fs.read"],
        authorityScopeRequirements: [],
        effectClass: "local_read",
        riskDomain: "filesystem",
        inputSchema: { type: "object", required: ["path"] },
        outputSchema: { type: "object", required: ["content"] },
        evidenceRequirements: ["file_read_receipt"],
      },
      {
        stableToolId: "sys.exec",
        displayName: "Shell command",
        pack: "runtime",
        primitiveCapabilities: ["prim:sys.exec"],
        authorityScopeRequirements: ["scope:host.controlled_execution"],
        effectClass: "local_command",
        riskDomain: "host",
        inputSchema: { type: "object", required: ["command"] },
        outputSchema: { type: "object", required: ["exitCode", "stdout", "stderr"] },
        evidenceRequirements: ["shell_receipt", "sandbox_profile"],
      },
      {
        stableToolId: "mcp.invoke",
        displayName: "MCP tool invocation",
        pack: "runtime",
        primitiveCapabilities: ["prim:connector.invoke"],
        authorityScopeRequirements: ["scope:mcp.invoke"],
        effectClass: "connector_call",
        riskDomain: "connector",
        inputSchema: { type: "object", required: ["server", "tool"] },
        outputSchema: { type: "object" },
        evidenceRequirements: ["mcp_containment_receipt"],
      },
      ...mockCodingToolContracts(),
    ];
    return options.pack ? tools.filter((tool) => tool.pack === options.pack) : tools;
  }

  async getMcpStatus(options: RuntimeMcpListOptions = {}): Promise<RuntimeMcpStatus> {
    const servers = await this.listMcpServers(options);
    const tools = await this.listMcpTools(options);
    const resources = await this.listMcpResources(options);
    const prompts = await this.listMcpPrompts(options);
    return {
      schema_version: "ioi.runtime.mcp-manager-status.v1",
      schemaVersion: "ioi.runtime.mcp-manager-status.v1",
      object: "ioi.runtime_mcp_manager_status",
      status: "ready",
      server_count: servers.length,
      serverCount: servers.length,
      tool_count: tools.length,
      toolCount: tools.length,
      resource_count: resources.length,
      resourceCount: resources.length,
      prompt_count: prompts.length,
      promptCount: prompts.length,
      servers,
      tools,
      resources,
      prompts,
      validation: {
        schema_version: "ioi.runtime.mcp-manager-validation.v1",
        schemaVersion: "ioi.runtime.mcp-manager-validation.v1",
        ok: true,
        status: "pass",
        issues: [],
        warnings: [],
        servers,
        tools,
        resources,
        prompts,
      },
    };
  }

  async listMcpServers(_options: RuntimeMcpListOptions = {}): Promise<RuntimeMcpServerEntry[]> {
    const names = new Set<string>();
    for (const agent of this.agents.values()) {
      for (const name of agent.options.mcpServerNames ?? []) names.add(name);
    }
    return [...names].sort().map((name) => ({
      schema_version: "ioi.runtime.mcp-manager-status.v1",
      schemaVersion: "ioi.runtime.mcp-manager-status.v1",
      id: `mcp.${name.replace(/[^a-zA-Z0-9_.-]+/g, "_")}`,
      label: name,
      name,
      enabled: true,
      status: "configured",
      transport: "stdio",
      command: null,
      args: [],
      allowed_tools: [],
      allowedTools: [],
      tool_count: 0,
      toolCount: 0,
      containment: { mode: "sandboxed", allow_network_egress: false, allow_child_processes: false },
      secret_refs: {},
      secretRefs: {},
      health: { status: "not_connected", live_probe: false },
      evidence_refs: ["explicit_mock_runtime_substrate_projection"],
      evidenceRefs: ["explicit_mock_runtime_substrate_projection"],
    }));
  }

  async listMcpTools(options: RuntimeMcpListOptions = {}): Promise<RuntimeMcpToolEntry[]> {
    const servers = await this.listMcpServers(options);
    return servers.flatMap((server) =>
      (server.allowedTools ?? server.allowed_tools ?? []).map((toolName) => ({
        stableToolId: `mcp.${server.label}.${toolName}`,
        displayName: `${server.label}.${toolName}`,
        pack: "mcp",
        primitiveCapabilities: ["prim:connector.invoke"],
        authorityScopeRequirements: ["scope:mcp.invoke"],
        effectClass: "connector_call",
        riskDomain: "connector",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        evidenceRequirements: ["mcp_containment_receipt"],
        server_id: server.id,
        serverId: server.id,
        tool_name: toolName,
        toolName,
        status: server.status,
      })),
    );
  }

  async searchMcpTools(input: RuntimeMcpToolSearchInput = {}): Promise<RuntimeMcpToolSearchResult> {
    const query = String(input.query ?? input.q ?? input.search ?? input.toolId ?? input.tool_id ?? "").toLowerCase();
    const tools = (await this.listMcpTools(input)).filter((tool) => {
      if (!query) return true;
      return [
        tool.stableToolId,
        tool.stable_tool_id,
        tool.displayName,
        tool.display_name,
        tool.serverId,
        tool.server_id,
        tool.toolName,
        tool.tool_name,
        tool.description,
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query));
    });
    const limit = Number(input.limit ?? 25);
    const returned = tools.slice(0, Number.isFinite(limit) && limit > 0 ? limit : 25);
    const serverCount = (await this.listMcpServers(input)).length;
    return {
      schema_version: "ioi.runtime.mcp-tool-search.v1",
      schemaVersion: "ioi.runtime.mcp-tool-search.v1",
      object: "ioi.runtime_mcp_tool_search",
      status: "completed",
      query,
      q: query,
      live_discovery: Boolean(input.liveDiscovery ?? input.live_discovery),
      liveDiscovery: Boolean(input.liveDiscovery ?? input.live_discovery),
      server_count: serverCount,
      serverCount,
      tool_count: tools.length,
      toolCount: tools.length,
      returned_count: returned.length,
      returnedCount: returned.length,
      limit: returned.length,
      deferred: tools.length > returned.length,
      tools: returned,
      catalog_summaries: [],
      catalogSummaries: [],
      failures: [],
    };
  }

  async getMcpTool(
    toolId: string,
    input: RuntimeMcpToolSearchInput = {},
  ): Promise<RuntimeMcpToolSearchResult> {
    const result = await this.searchMcpTools({ ...input, toolId, tool_id: toolId, exact: true, limit: 100 });
    const normalized = toolId.toLowerCase();
    const tool = result.tools.find((candidate) =>
      [
        candidate.stableToolId,
        candidate.stable_tool_id,
        candidate.displayName,
        candidate.display_name,
        candidate.toolName,
        candidate.tool_name,
      ]
        .filter(Boolean)
        .map((value) => String(value).toLowerCase())
        .includes(normalized),
    ) ?? result.tools[0];
    if (!tool) throw new IoiAgentError({ code: "not_found", message: `MCP tool not found: ${toolId}` });
    return {
      ...result,
      object: "ioi.runtime_mcp_tool_fetch",
      tool_id: toolId,
      toolId,
      tool,
      tools: [tool],
      returned_count: 1,
      returnedCount: 1,
    };
  }

  async listMcpResources(options: RuntimeMcpListOptions = {}): Promise<RuntimeMcpResourceEntry[]> {
    const servers = await this.listMcpServers(options);
    return servers.flatMap(
      (server) => ((server as RuntimeMcpServerEntry & { resources?: RuntimeMcpResourceEntry[] }).resources ?? []),
    );
  }

  async listMcpPrompts(options: RuntimeMcpListOptions = {}): Promise<RuntimeMcpPromptEntry[]> {
    const servers = await this.listMcpServers(options);
    return servers.flatMap(
      (server) => ((server as RuntimeMcpServerEntry & { prompts?: RuntimeMcpPromptEntry[] }).prompts ?? []),
    );
  }

  async validateMcp(input: RuntimeMcpValidationInput = {}): Promise<RuntimeMcpValidationResult> {
    const status = await this.getMcpStatus();
    return {
      schema_version: "ioi.runtime.mcp-manager-validation.v1",
      schemaVersion: "ioi.runtime.mcp-manager-validation.v1",
      object: "ioi.runtime_mcp_manager_validation",
      ok: true,
      status: "pass",
      server_count: status.server_count,
      serverCount: status.server_count,
      tool_count: status.tool_count,
      toolCount: status.tool_count,
      resource_count: status.resource_count ?? 0,
      resourceCount: status.resource_count ?? 0,
      prompt_count: status.prompt_count ?? 0,
      promptCount: status.prompt_count ?? 0,
      issue_count: 0,
      issueCount: 0,
      warning_count: input ? 0 : 0,
      warningCount: 0,
      issues: [],
      warnings: [],
      servers: status.servers,
      tools: status.tools,
      resources: status.resources,
      prompts: status.prompts,
    };
  }

  async importMcp(input: RuntimeMcpServerMutationInput = {}): Promise<RuntimeMcpStatus> {
    const threadId = input.threadId ?? input.thread_id ?? threadIdForAgent((await this.createAgent({})).id);
    return this.importThreadMcp(threadId, input);
  }

  async addMcpServer(input: RuntimeMcpServerMutationInput = {}): Promise<RuntimeMcpStatus> {
    const threadId = input.threadId ?? input.thread_id ?? threadIdForAgent((await this.createAgent({})).id);
    return this.addThreadMcpServer(threadId, input);
  }

  async removeMcpServer(
    serverId: string,
    input: RuntimeMcpServerMutationInput = {},
  ): Promise<RuntimeMcpStatus> {
    const threadId = input.threadId ?? input.thread_id ?? threadIdForAgent((await this.createAgent({})).id);
    return this.removeThreadMcpServer(threadId, serverId, input);
  }

  async enableMcpServer(
    serverId: string,
    input: RuntimeMcpServerControlInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.threadMcpStatus(input.threadId ?? input.thread_id ?? threadIdForAgent((await this.createAgent({})).id), {
      ...input,
      serverId,
      enabled: true,
    });
  }

  async disableMcpServer(
    serverId: string,
    input: RuntimeMcpServerControlInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.threadMcpStatus(input.threadId ?? input.thread_id ?? threadIdForAgent((await this.createAgent({})).id), {
      ...input,
      serverId,
      enabled: false,
    });
  }

  async invokeMcpTool(input: RuntimeMcpToolInvokeInput = {}): Promise<RuntimeMcpInvocationResult> {
    const threadId = input.threadId ?? input.thread_id ?? threadIdForAgent((await this.createAgent({})).id);
    return this.invokeThreadMcpTool(threadId, input);
  }

  async serveMcpRpc(
    input: RuntimeMcpServeRpcInput,
  ): Promise<RuntimeMcpJsonRpcResponse | RuntimeMcpJsonRpcResponse[] | null> {
    const threadId = input.threadId ?? input.thread_id ?? threadIdForAgent((await this.createAgent({})).id);
    return this.threadMcpServeRpc(threadId, input.message, input);
  }

  async threadMcpStatus(threadId: string, input: RuntimeThreadMcpInput = {}): Promise<RuntimeMcpStatus> {
    return {
      ...(await this.getMcpStatus({ threadId })),
      event: mockRuntimeEventEnvelope({
        agent: await this.getAgent(agentIdForThread(threadId)),
        threadId,
        streamId: eventStreamIdForThread(threadId),
        seq: this.threadRuntimeEvents(await this.getAgent(agentIdForThread(threadId))).length + 1,
        eventKind: "mcp.catalog_status",
        sourceEventKind: "OperatorControl.Mcp",
        itemId: `${threadId}:item:mcp-status`,
        payload: { event_kind: "McpCatalogStatus", source: input.source ?? "sdk_client" },
        createdAt: new Date().toISOString(),
        componentKind: "mcp_provider",
        workflowNodeId: "runtime.mcp-manager",
      }),
    };
  }

  async importThreadMcp(
    threadId: string,
    input: RuntimeMcpServerMutationInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.mockThreadMcpMutation(threadId, "McpServersImported", "mcp_import", input);
  }

  async addThreadMcpServer(
    threadId: string,
    input: RuntimeMcpServerMutationInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.mockThreadMcpMutation(threadId, "McpServerAdded", "mcp_add", input);
  }

  async removeThreadMcpServer(
    threadId: string,
    _serverId: string,
    input: RuntimeMcpServerMutationInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.mockThreadMcpMutation(threadId, "McpServerRemoved", "mcp_remove", input);
  }

  private async mockThreadMcpMutation(
    threadId: string,
    eventKind: string,
    controlKind: string,
    input: RuntimeMcpServerMutationInput,
  ): Promise<RuntimeMcpStatus> {
    const status = await this.threadMcpStatus(threadId, input);
    return {
      ...status,
      event_kind: eventKind,
      control_kind: controlKind,
      event: mockRuntimeEventEnvelope({
        agent: await this.getAgent(agentIdForThread(threadId)),
        threadId,
        streamId: eventStreamIdForThread(threadId),
        seq: this.threadRuntimeEvents(await this.getAgent(agentIdForThread(threadId))).length + 1,
        eventKind: controlKind.replace("_", "."),
        sourceEventKind: `OperatorControl.${eventKind.replace(/^Mcp/, "Mcp")}`,
        itemId: `${threadId}:item:${controlKind}`,
        payload: { event_kind: eventKind, source: input.source ?? "sdk_client" },
        createdAt: new Date().toISOString(),
        componentKind: "mcp_provider",
        workflowNodeId: "runtime.mcp-manager",
      }),
    };
  }

  async searchThreadMcpTools(
    _threadId: string,
    input: RuntimeMcpToolSearchInput = {},
  ): Promise<RuntimeMcpToolSearchResult> {
    return this.searchMcpTools(input);
  }

  async getThreadMcpTool(
    _threadId: string,
    toolId: string,
    input: RuntimeMcpToolSearchInput = {},
  ): Promise<RuntimeMcpToolSearchResult> {
    return this.getMcpTool(toolId, input);
  }

  async enableThreadMcpServer(
    threadId: string,
    serverId: string,
    input: RuntimeMcpServerControlInput = {},
  ): Promise<RuntimeMcpStatus> {
    return {
      ...(await this.threadMcpStatus(threadId, input)),
      status: "ready",
      servers: (await this.listMcpServers({ threadId })).map((server) =>
        server.id === serverId || server.label === serverId
          ? { ...server, enabled: true, status: "configured" }
          : server,
      ),
    };
  }

  async disableThreadMcpServer(
    threadId: string,
    serverId: string,
    input: RuntimeMcpServerControlInput = {},
  ): Promise<RuntimeMcpStatus> {
    return {
      ...(await this.threadMcpStatus(threadId, input)),
      servers: (await this.listMcpServers({ threadId })).map((server) =>
        server.id === serverId || server.label === serverId
          ? { ...server, enabled: false, status: "disabled" }
          : server,
      ),
    };
  }

  async invokeThreadMcpTool(
    threadId: string,
    input: RuntimeMcpToolInvokeInput = {},
  ): Promise<RuntimeMcpInvocationResult> {
    const serverId = input.serverId ?? input.server_id ?? "mcp.mock";
    const toolName = input.toolName ?? input.tool_name ?? input.tool ?? "query";
    const toolCallId = `mcp_call_${String(serverId).replace(/[^a-zA-Z0-9_.-]+/g, "_")}_${String(toolName).replace(/[^a-zA-Z0-9_.-]+/g, "_")}`;
    const agent = await this.getAgent(agentIdForThread(threadId));
    return {
      schema_version: "ioi.runtime.mcp-manager-invocation.v1",
      schemaVersion: "ioi.runtime.mcp-manager-invocation.v1",
      object: "ioi.runtime_mcp_tool_invocation",
      event_kind: "McpToolInvocation",
      control_kind: "mcp_invoke",
      tool_call_id: toolCallId,
      toolCallId,
      thread_id: threadId,
      threadId,
      agent_id: agent.id,
      agentId: agent.id,
      server_id: serverId,
      serverId,
      tool_name: toolName,
      toolName,
      status: input.requiresApproval && !input.approved ? "blocked" : "completed",
      input_hash: "mock-input",
      inputHash: "mock-input",
      output_hash: "mock-output",
      outputHash: "mock-output",
      side_effect_class: input.sideEffectClass ?? input.side_effect_class ?? "read",
      sideEffectClass: input.sideEffectClass ?? input.side_effect_class ?? "read",
      requires_approval: Boolean(input.requiresApproval ?? input.requires_approval),
      requiresApproval: Boolean(input.requiresApproval ?? input.requires_approval),
      approved: Boolean(input.approved),
      blockers: input.requiresApproval && !input.approved ? ["approval_required"] : [],
      transport: "mock",
      transport_execution: {
        ok: true,
        status: "completed",
        transport: "mock",
        execution_mode: "mock_client",
        executionMode: "mock_client",
      },
      transportExecution: {
        ok: true,
        status: "completed",
        transport: "mock",
        execution_mode: "mock_client",
        executionMode: "mock_client",
      },
      result: { ok: true, fixture: true, serverId, toolName },
      receipt_refs: [`receipt_${toolCallId}`],
      receiptRefs: [`receipt_${toolCallId}`],
      policy_decision_refs: [`policy_${toolCallId}`],
      policyDecisionRefs: [`policy_${toolCallId}`],
      event: mockRuntimeEventEnvelope({
        agent,
        threadId,
        streamId: eventStreamIdForThread(threadId),
        seq: this.threadRuntimeEvents(agent).length + 1,
        eventKind: "mcp.tool_invocation",
        sourceEventKind: "OperatorControl.McpInvoke",
        itemId: `${threadId}:item:mcp-invoke`,
        payload: { event_kind: "McpToolInvocation", source: input.source ?? "sdk_client" },
        createdAt: new Date().toISOString(),
        componentKind: "mcp_tool_call",
        workflowNodeId: `runtime.mcp-tool.${serverId}.${toolName}`,
      }),
    };
  }

  async threadMcpServeRpc(
    threadId: string,
    message: RuntimeMcpJsonRpcRequest | RuntimeMcpJsonRpcRequest[],
    options: RuntimeMcpListOptions = {},
  ): Promise<RuntimeMcpJsonRpcResponse | RuntimeMcpJsonRpcResponse[] | null> {
    const handle = async (entry: RuntimeMcpJsonRpcRequest): Promise<RuntimeMcpJsonRpcResponse | null> => {
      const id = entry.id ?? null;
      if (entry.method === "notifications/initialized") return null;
      if (entry.method === "initialize") {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: "2024-11-05",
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: "ioi-runtime-mock", version: "ioi.runtime.mcp-serve.v1" },
          },
        };
      }
      if (entry.method === "tools/list") {
        const requested = [
          ...((Array.isArray(options.allowedTools) ? options.allowedTools : []) as string[]),
          ...((Array.isArray(options.allowed_tools) ? options.allowed_tools : []) as string[]),
        ];
        const allowed = requested.length ? requested : ["workspace.status", "git.diff", "file.inspect"];
        const tools = (await this.listTools({ pack: "coding" }))
          .filter((tool) => allowed.includes(tool.stableToolId))
          .map((tool) => ({
            name: tool.stableToolId,
            title: tool.displayName,
            description: `${tool.displayName} through IOI's governed runtime.`,
            inputSchema: tool.inputSchema,
          }));
        return { jsonrpc: "2.0", id, result: { tools } };
      }
      if (entry.method === "tools/call") {
        const params = (entry.params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
        const toolName = params.name ?? "workspace.status";
        const invocation = await this.invokeThreadTool(threadId, toolName, {
          source: "mcp_serve",
          workflow_node_id: `runtime.mcp-serve.${toolName}`,
          input: params.arguments ?? {},
        });
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: `IOI runtime tool ${toolName} completed.` }],
            structuredContent: {
              schema_version: "ioi.runtime.mcp-serve.v1",
              status: invocation.status,
              tool_name: invocation.tool_name,
              tool_call_id: invocation.tool_call_id,
              receipt_refs: invocation.receipt_refs,
              result: invocation.result ?? null,
            },
            isError: invocation.status !== "completed",
          },
        };
      }
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `MCP method not found: ${entry.method}.` },
      };
    };
    if (Array.isArray(message)) {
      const responses = await Promise.all(message.map((entry) => handle(entry)));
      return responses.filter((entry): entry is RuntimeMcpJsonRpcResponse => Boolean(entry));
    }
    return handle(message);
  }

  async validateThreadMcp(threadId: string, input: RuntimeThreadMcpInput = {}): Promise<RuntimeMcpValidationResult> {
    return {
      ...(await this.validateMcp(input)),
      event: mockRuntimeEventEnvelope({
        agent: await this.getAgent(agentIdForThread(threadId)),
        threadId,
        streamId: eventStreamIdForThread(threadId),
        seq: this.threadRuntimeEvents(await this.getAgent(agentIdForThread(threadId))).length + 1,
        eventKind: "mcp.validation",
        sourceEventKind: "OperatorControl.McpValidate",
        itemId: `${threadId}:item:mcp-validate`,
        payload: { event_kind: "McpValidationReport", source: input.source ?? "sdk_client" },
        createdAt: new Date().toISOString(),
        componentKind: "mcp_validator",
        workflowNodeId: "runtime.mcp-manager.validate",
      }),
    };
  }

  async getMemoryStatus(options: RuntimeMemoryStatusOptions = {}): Promise<RuntimeMemoryStatus> {
    const threadId = options.threadId ?? options.thread_id;
    const agentId =
      options.agentId ??
      options.agent_id ??
      (threadId ? agentIdForThread(threadId) : this.agents.values().next().value?.id);
    if (!agentId) return mockMemoryStatusForProjection(mockEmptyMemoryProjection());
    const projection = await this.listMemory(agentId, {
      ...options,
      ...(threadId ? { threadId } : {}),
    });
    return mockMemoryStatusForProjection(projection);
  }

  async validateMemory(input: RuntimeMemoryValidationInput = {}): Promise<RuntimeMemoryValidationResult> {
    const projection = input.projection ?? (await this.getMemoryStatus(input));
    return mockMemoryValidationForProjection(projection);
  }

  async threadMemoryStatus(threadId: string, input: RuntimeThreadMemoryInput = {}): Promise<RuntimeMemoryStatus> {
    const agent = await this.getAgent(agentIdForThread(threadId));
    return {
      ...(await this.getMemoryStatus({ ...input, threadId })),
      event: mockRuntimeEventEnvelope({
        agent,
        threadId,
        streamId: eventStreamIdForThread(threadId),
        seq: this.threadRuntimeEvents(agent).length + 1,
        eventKind: "memory.status",
        sourceEventKind: "OperatorControl.Memory",
        itemId: `${threadId}:item:memory-status`,
        payload: { event_kind: "MemoryStatus", source: input.source ?? "sdk_client" },
        createdAt: new Date().toISOString(),
        componentKind: "memory_policy",
        workflowNodeId: "runtime.memory-manager",
      }),
    };
  }

  async validateThreadMemory(threadId: string, input: RuntimeThreadMemoryInput = {}): Promise<RuntimeMemoryValidationResult> {
    const agent = await this.getAgent(agentIdForThread(threadId));
    return {
      ...(await this.validateMemory({ ...input, threadId })),
      event: mockRuntimeEventEnvelope({
        agent,
        threadId,
        streamId: eventStreamIdForThread(threadId),
        seq: this.threadRuntimeEvents(agent).length + 1,
        eventKind: "memory.validation",
        sourceEventKind: "OperatorControl.MemoryValidate",
        itemId: `${threadId}:item:memory-validate`,
        payload: { event_kind: "MemoryValidationReport", source: input.source ?? "sdk_client" },
        createdAt: new Date().toISOString(),
        componentKind: "memory_policy",
        workflowNodeId: "runtime.memory-manager.validate",
      }),
    };
  }

  async rememberThreadMemory(
    threadId: string,
    input: RuntimeThreadMemoryWriteInput,
  ): Promise<RememberMemoryResult> {
    return this.rememberMemory(agentIdForThread(threadId), { ...input, threadId });
  }

  async updateThreadMemory(
    threadId: string,
    memoryId: string,
    input: RuntimeThreadMemoryEditInput,
  ): Promise<RememberMemoryResult> {
    return this.updateMemory(agentIdForThread(threadId), memoryId, { ...input, threadId });
  }

  async deleteThreadMemory(
    threadId: string,
    memoryId: string,
    input: RuntimeThreadMemoryDeleteInput = {},
  ): Promise<RememberMemoryResult> {
    return this.deleteMemory(agentIdForThread(threadId), memoryId, { ...input, threadId });
  }

  async invokeThreadTool(
    threadId: string,
    toolId: string,
    input: RuntimeThreadToolInvokeInput = {},
  ): Promise<RuntimeThreadToolInvocationResult> {
    const agent = await this.getAgent(agentIdForThread(threadId));
    const toolCallId = `mock_coding_tool_${crypto.randomUUID()}`;
    const mockWorkspaceSnapshot =
      toolId === "file.apply_patch"
        ? {
            schemaVersion: "ioi.runtime.workspace-snapshot.v1",
            snapshotId: `workspace_snapshot_${toolCallId}`,
            snapshotKind: "pre_post_touched_files",
            fileCount: 1,
            changedFileCount: 1,
            restore: { status: "content_captured", previewSupported: true, applySupported: true },
            receiptRefs: [`receipt_workspace_snapshot_${toolCallId}`],
            artifactRefs: [`artifact_workspace_snapshot_${toolCallId}`],
          }
        : null;
    const artifactRefs = [
      ...(toolId === "artifact.read" || toolId === "tool.retrieve_result"
        ? [`artifact_mock_${toolId.replaceAll(".", "_")}`]
        : []),
      ...(mockWorkspaceSnapshot?.artifactRefs ?? []),
    ];
    const rollbackRefs = [
      ...(mockWorkspaceSnapshot ? [String(mockWorkspaceSnapshot.snapshotId)] : []),
      ...((Array.isArray(input.rollbackRefs) ? input.rollbackRefs : []) as string[]),
      ...((Array.isArray(input.rollback_refs) ? input.rollback_refs : []) as string[]),
    ];
    const event = mockRuntimeEventEnvelope({
      agent,
      threadId,
      streamId: eventStreamIdForThread(threadId),
      seq: 1,
      eventKind: "tool.completed",
      sourceEventKind: mockCodingToolSourceEventKind(toolId),
      itemId: `${threadId}:item:${toolId}`,
      payload: {
        event_kind: "CodingToolResult",
        tool_pack: "coding",
        tool_name: toolId,
        tool_call_id: toolCallId,
        shell_fallback_used: false,
        rollback_refs: rollbackRefs,
        diagnostics_repair_context: input.diagnosticsRepairContext ?? input.diagnostics_repair_context ?? null,
      },
      createdAt: new Date().toISOString(),
      componentKind: "coding_tool",
      workflowNodeId: String(input.workflowNodeId ?? input.workflow_node_id ?? `runtime.coding-tool.${toolId}`),
      receiptRefs: [`receipt_mock_${toolId.replaceAll(".", "_")}`],
      artifactRefs,
      rollbackRefs,
    });
    return {
      schema_version: "ioi.runtime.coding-tool-result.v1",
      object: "ioi.runtime_coding_tool_result",
      tool_pack: "coding",
      tool_name: toolId,
      tool_call_id: toolCallId,
      thread_id: threadId,
      turn_id: null,
      status: "completed",
      workspace_root: agent.cwd,
      workflow_graph_id: null,
      workflow_node_id: event.workflow_node_id,
      shell_fallback_used: false,
      receipt_refs: event.receipt_refs,
      artifact_refs: artifactRefs,
      rollback_refs: rollbackRefs,
      event,
      workspace_snapshot: mockWorkspaceSnapshot,
      workspaceSnapshot: mockWorkspaceSnapshot,
      result: {
        input: input.input ?? input,
        ...(toolId === "file.apply_patch"
          ? {
              changedFiles: [
                {
                  path: String((input.input as { path?: unknown } | undefined)?.path ?? "mock-file.js"),
                  diagnosticsRecommended: true,
                },
              ],
              diagnosticsRecommended: true,
              workspaceSnapshot: mockWorkspaceSnapshot,
              workspace_snapshot: mockWorkspaceSnapshot,
            }
          : {}),
        ...(toolId === "lsp.diagnostics"
          ? {
              commandId: "auto",
              resolvedCommandId: "node.check",
              diagnosticStatus: "clean",
              diagnostics: [],
              diagnosticCount: 0,
              backend: "node.check",
              backendStatus: "available",
              fallbackUsed: false,
              shellFallbackUsed: false,
            }
          : {}),
        ...(artifactRefs.length
          ? { artifactRefs, content: "mock coding artifact content" }
          : {}),
      },
      error: null,
    };
  }

  async listThreadWorkspaceSnapshots(threadId: string): Promise<RuntimeWorkspaceSnapshotListResult> {
    return {
      schemaVersion: "ioi.runtime.workspace-snapshot.v1",
      object: "ioi.runtime_workspace_snapshot_list",
      threadId,
      thread_id: threadId,
      snapshotCount: 1,
      snapshot_count: 1,
      snapshots: [
        {
          schemaVersion: "ioi.runtime.workspace-snapshot.v1",
          snapshotId: `workspace_snapshot_mock_${threadId}`,
          snapshotKind: "pre_post_touched_files",
          restore: { status: "content_captured", previewSupported: true, applySupported: true },
          receiptRefs: [`receipt_workspace_snapshot_mock_${threadId}`],
          artifactRefs: [`artifact_workspace_snapshot_mock_${threadId}`],
        },
      ],
    };
  }

  async previewThreadWorkspaceRestore(
    threadId: string,
    snapshotId: string,
    input: RuntimeWorkspaceRestorePreviewInput = {},
  ): Promise<RuntimeWorkspaceRestorePreviewResult> {
    const agent = await this.getAgent(agentIdForThread(threadId));
    const event = mockRuntimeEventEnvelope({
      agent,
      threadId,
      streamId: eventStreamIdForThread(threadId),
      seq: 1,
      eventKind: "workspace.restore.previewed",
      sourceEventKind: "WorkspaceRestore.Previewed",
      itemId: `${threadId}:item:workspace-restore-preview:${snapshotId}`,
      payload: {
        event_kind: "WorkspaceRestorePreview",
        snapshot_id: snapshotId,
        preview_status: "ready",
        summary: `Restore preview ready for 1 file(s) from ${snapshotId}.`,
      },
      createdAt: new Date().toISOString(),
      componentKind: "restore_gate",
      workflowNodeId: String(input.workflowNodeId ?? input.workflow_node_id ?? "runtime.restore-gate"),
      receiptRefs: [`receipt_workspace_restore_preview_${snapshotId}`],
    });
    const previewEvent = {
      ...event,
      rollback_refs: [snapshotId],
      artifact_refs: [`artifact_workspace_restore_preview_${snapshotId}`],
    };
    return {
      schemaVersion: "ioi.runtime.workspace-restore-preview.v1",
      schema_version: "ioi.runtime.workspace-restore-preview.v1",
      object: "ioi.runtime_workspace_restore_preview",
      threadId,
      thread_id: threadId,
      snapshotId,
      snapshot_id: snapshotId,
      previewStatus: "ready",
      preview_status: "ready",
      previewSupported: true,
      preview_supported: true,
      applySupported: true,
      apply_supported: true,
      fileCount: 1,
      file_count: 1,
      readyCount: 1,
      ready_count: 1,
      noopCount: 0,
      noop_count: 0,
      conflictCount: 0,
      conflict_count: 0,
      blockedCount: 0,
      blocked_count: 0,
      operations: [{ path: "mock-file.js", operation: "replace", status: "ready" }],
      receiptRefs: event.receipt_refs,
      receipt_refs: event.receipt_refs,
      artifactRefs: [`artifact_workspace_restore_preview_${snapshotId}`],
      artifact_refs: [`artifact_workspace_restore_preview_${snapshotId}`],
      rollbackRefs: [snapshotId],
      rollback_refs: [snapshotId],
      event: previewEvent,
      restore_preview_event: previewEvent,
      restorePreviewEvent: previewEvent,
      summary: `Restore preview ready for 1 file(s) from ${snapshotId}.`,
    };
  }

  async applyThreadWorkspaceRestore(
    threadId: string,
    snapshotId: string,
    input: RuntimeWorkspaceRestoreApplyInput = {},
  ): Promise<RuntimeWorkspaceRestoreApplyResult> {
    const agent = await this.getAgent(agentIdForThread(threadId));
    const approved = Boolean(input.approvalGranted ?? input.approval_granted ?? input.confirm ?? input.confirmed);
    const applyStatus = approved ? "applied" : "blocked";
    const event = mockRuntimeEventEnvelope({
      agent,
      threadId,
      streamId: eventStreamIdForThread(threadId),
      seq: 1,
      eventKind: "workspace.restore.applied",
      sourceEventKind: "WorkspaceRestore.Applied",
      itemId: `${threadId}:item:workspace-restore-apply:${snapshotId}`,
      payload: {
        event_kind: "WorkspaceRestoreApply",
        snapshot_id: snapshotId,
        apply_status: applyStatus,
        summary: approved
          ? `Restore apply restored 1 file(s) from ${snapshotId}.`
          : `Restore apply blocked for ${snapshotId}: operator approval is required.`,
      },
      createdAt: new Date().toISOString(),
      componentKind: "restore_gate",
      workflowNodeId: String(input.workflowNodeId ?? input.workflow_node_id ?? "runtime.restore-gate"),
      receiptRefs: [`receipt_workspace_restore_apply_${snapshotId}`],
    });
    const applyEvent = {
      ...event,
      rollback_refs: [snapshotId],
      artifact_refs: [`artifact_workspace_restore_apply_${snapshotId}`],
      policy_decision_refs: [`policy_workspace_restore_apply_${snapshotId}_${approved ? "approval_satisfied" : "approval_required"}`],
    };
    return {
      schemaVersion: "ioi.runtime.workspace-restore-apply.v1",
      schema_version: "ioi.runtime.workspace-restore-apply.v1",
      object: "ioi.runtime_workspace_restore_apply",
      threadId,
      thread_id: threadId,
      snapshotId,
      snapshot_id: snapshotId,
      previewStatus: "ready",
      preview_status: "ready",
      applyStatus,
      apply_status: applyStatus,
      applySupported: approved,
      apply_supported: approved,
      approvalRequired: true,
      approval_required: true,
      approvalSatisfied: approved,
      approval_satisfied: approved,
      fileCount: 1,
      file_count: 1,
      appliedCount: approved ? 1 : 0,
      applied_count: approved ? 1 : 0,
      applyNoopCount: 0,
      apply_noop_count: 0,
      applyBlockedCount: approved ? 0 : 1,
      apply_blocked_count: approved ? 0 : 1,
      failedCount: 0,
      failed_count: 0,
      operations: [
        {
          path: "mock-file.js",
          operation: "replace",
          status: "ready",
          applyStatus,
          apply_status: applyStatus,
        },
      ],
      policyDecisionRefs: applyEvent.policy_decision_refs,
      policy_decision_refs: applyEvent.policy_decision_refs,
      receiptRefs: event.receipt_refs,
      receipt_refs: event.receipt_refs,
      artifactRefs: applyEvent.artifact_refs,
      artifact_refs: applyEvent.artifact_refs,
      rollbackRefs: [snapshotId],
      rollback_refs: [snapshotId],
      event: applyEvent,
      restore_apply_event: applyEvent,
      restoreApplyEvent: applyEvent,
      summary: String(applyEvent.payload?.summary ?? ""),
    };
  }

  async executeThreadDiagnosticsRepairDecision(
    threadId: string,
    decisionId: string,
    input: RuntimeDiagnosticsRepairDecisionExecuteInput = {},
  ): Promise<RuntimeDiagnosticsRepairDecisionExecutionResult> {
    const snapshotId = input.snapshotId ?? input.snapshot_id ?? `workspace_snapshot_mock_${threadId}`;
    const action = String(
      input.action ??
        (decisionId.includes("repair_retry")
          ? "repair_retry"
          : decisionId.includes("operator_override")
            ? "operator_override"
          : decisionId.includes("restore_apply")
            ? "restore_apply"
            : "restore_preview"),
    );
    const workflowNodeId = String(
      input.workflowNodeId ??
        input.workflow_node_id ??
        (action === "repair_retry"
          ? "runtime.lsp-diagnostics.repair.retry"
          : action === "operator_override"
          ? "runtime.lsp-diagnostics.repair.operator-override"
          : action === "restore_apply"
          ? "runtime.lsp-diagnostics.repair.restore-apply"
          : "runtime.lsp-diagnostics.repair.restore-preview"),
    );
    const agent = await this.getAgent(agentIdForThread(threadId));
    const repairRetry =
      action === "repair_retry"
        ? await this.mockDiagnosticsRepairRetry(threadId, decisionId, workflowNodeId, input, snapshotId)
        : undefined;
    const operatorOverride =
      action === "operator_override"
        ? await this.mockDiagnosticsOperatorOverride(threadId, decisionId, workflowNodeId, input, snapshotId)
        : undefined;
    const restorePreview =
      action === "restore_preview"
        ? await this.previewThreadWorkspaceRestore(threadId, snapshotId, {
            source: input.source ?? "sdk_client",
            workflowGraphId: input.workflowGraphId,
            workflow_graph_id: input.workflow_graph_id,
            workflowNodeId,
          })
        : undefined;
    const restoreApply =
      action === "restore_apply"
        ? await this.applyThreadWorkspaceRestore(threadId, snapshotId, {
            source: input.source ?? "sdk_client",
            workflowGraphId: input.workflowGraphId,
            workflow_graph_id: input.workflow_graph_id,
            workflowNodeId,
            approvalGranted: input.approvalGranted,
            approval_granted: input.approval_granted,
            confirm: input.confirm,
            confirmed: input.confirmed,
            allowConflicts: input.allowConflicts,
            allow_conflicts: input.allow_conflicts,
            overrideConflicts: input.overrideConflicts,
            override_conflicts: input.override_conflicts,
            conflictPolicy: input.restoreConflictPolicy,
            conflict_policy: input.restore_conflict_policy,
          })
        : undefined;
    const executionStatus =
      operatorOverride?.status === "blocked"
        ? "blocked"
        : operatorOverride?.status === "failed"
          ? "failed"
          : restoreApply?.applyStatus === "blocked"
            ? "blocked"
            : restoreApply?.applyStatus === "failed"
              ? "failed"
              : "completed";
    const event = mockRuntimeEventEnvelope({
      agent,
      threadId,
      streamId: eventStreamIdForThread(threadId),
      seq: 1,
      eventKind: "diagnostics.repair_decision.executed",
      sourceEventKind: "LspDiagnostics.RepairDecisionExecuted",
      itemId: `${threadId}:item:diagnostics-repair:${decisionId}`,
      payload: {
        event_kind: "LspDiagnosticsRepairDecisionExecuted",
        decision_id: decisionId,
        action,
        snapshot_id: snapshotId,
        repair_retry_event_id: repairRetry?.event?.event_id ?? null,
        repair_retry_turn_id: repairRetry?.repairTurn?.turn_id ?? null,
        repair_retry_request_id: repairRetry?.repairTurn?.request_id ?? null,
        operator_override_event_id: operatorOverride?.event?.event_id ?? null,
        operator_override_status: operatorOverride?.overrideStatus ?? operatorOverride?.status ?? null,
        operator_override_approval_required: operatorOverride?.approvalRequired ?? null,
        operator_override_approval_satisfied: operatorOverride?.approvalSatisfied ?? null,
        operator_override_continuation_allowed: operatorOverride?.continuationAllowed ?? null,
        restore_preview_event_id: restorePreview?.event?.event_id ?? null,
        restore_apply_event_id: restoreApply?.event?.event_id ?? null,
        restore_apply_status: restoreApply?.applyStatus ?? null,
        approval_satisfied: restoreApply?.approvalSatisfied ?? null,
      },
      createdAt: new Date().toISOString(),
      status: executionStatus,
      payloadSchemaVersion: "ioi.runtime.diagnostics-repair-decision-execution.v1",
      componentKind: "lsp_diagnostics_repair",
      workflowNodeId: `${workflowNodeId}.decision`,
      receiptRefs: [`receipt_lsp_diagnostics_repair_${decisionId}`],
      artifactRefs:
        repairRetry?.artifactRefs ?? operatorOverride?.artifactRefs ?? restoreApply?.artifactRefs ?? restorePreview?.artifactRefs ?? [],
      policyDecisionRefs: [
        decisionId,
        ...(repairRetry?.policyDecisionRefs ?? []),
        ...(operatorOverride?.policyDecisionRefs ?? []),
        ...(restoreApply?.policyDecisionRefs ?? []),
      ],
      rollbackRefs: [snapshotId, ...(repairRetry?.rollbackRefs ?? []), ...(operatorOverride?.rollbackRefs ?? [])],
    });
    return {
      schemaVersion: "ioi.runtime.diagnostics-repair-decision-execution.v1",
      schema_version: "ioi.runtime.diagnostics-repair-decision-execution.v1",
      object: "ioi.runtime_diagnostics_repair_decision_execution",
      threadId,
      thread_id: threadId,
      decisionId,
      decision_id: decisionId,
      action,
      status: executionStatus,
      snapshotId,
      snapshot_id: snapshotId,
      workflowGraphId: input.workflowGraphId ?? input.workflow_graph_id ?? null,
      workflow_graph_id: input.workflow_graph_id ?? input.workflowGraphId ?? null,
      workflowNodeId,
      workflow_node_id: workflowNodeId,
      repairRetry,
      repair_retry: repairRetry,
      repairTurn: repairRetry?.repairTurn ?? null,
      repair_turn: repairRetry?.repairTurn ?? null,
      repairRetryEvent: repairRetry?.event ?? null,
      repair_retry_event: repairRetry?.event ?? null,
      operatorOverride,
      operator_override: operatorOverride,
      operatorOverrideEvent: operatorOverride?.event ?? null,
      operator_override_event: operatorOverride?.event ?? null,
      restorePreview,
      restore_preview: restorePreview,
      restoreApply,
      restore_apply: restoreApply,
      restorePreviewEvent: restorePreview?.event ?? null,
      restore_preview_event: restorePreview?.event ?? null,
      restoreApplyEvent: restoreApply?.event ?? null,
      restore_apply_event: restoreApply?.event ?? null,
      event,
      receiptRefs: event.receipt_refs,
      receipt_refs: event.receipt_refs,
      artifactRefs: event.artifact_refs,
      artifact_refs: event.artifact_refs,
      policyDecisionRefs: event.policy_decision_refs,
      policy_decision_refs: event.policy_decision_refs,
      rollbackRefs: [snapshotId],
      rollback_refs: [snapshotId],
      summary: `Executed diagnostics repair decision ${action} for ${snapshotId}.`,
    };
  }

  private async mockDiagnosticsRepairRetry(
    threadId: string,
    decisionId: string,
    workflowNodeId: string,
    input: RuntimeDiagnosticsRepairDecisionExecuteInput,
    snapshotId: string,
  ): Promise<RuntimeDiagnosticsRepairRetryResult> {
    const agent = await this.getAgent(agentIdForThread(threadId));
    const run = await this.createRun(
      agent.id,
      String(input.prompt ?? input.message ?? "Repair the blocking post-edit diagnostics and retry the turn."),
      "send",
      {},
    );
    const repairTurn = this.turnRecordForRun(run);
    const event = mockRuntimeEventEnvelope({
      agent,
      threadId,
      streamId: eventStreamIdForThread(threadId),
      seq: 1,
      eventKind: "diagnostics.repair_retry.created",
      sourceEventKind: "LspDiagnostics.RepairRetryTurnCreated",
      itemId: `${repairTurn.turn_id}:item:diagnostics-repair-retry:${decisionId}`,
      payload: {
        event_kind: "LspDiagnosticsRepairRetryTurnCreated",
        decision_id: decisionId,
        action: "repair_retry",
        snapshot_id: snapshotId,
        retry_turn_id: repairTurn.turn_id,
        retry_request_id: repairTurn.request_id,
        repair_prompt_injected: true,
        summary: `Diagnostics repair retry created turn ${repairTurn.turn_id} for ${decisionId}.`,
      },
      createdAt: new Date().toISOString(),
      turnId: repairTurn.turn_id,
      payloadSchemaVersion: "ioi.runtime.diagnostics-repair-decision-execution.v1",
      componentKind: "lsp_diagnostics_repair_retry",
      workflowNodeId,
      receiptRefs: [`receipt_lsp_diagnostics_repair_retry_${decisionId}`],
      artifactRefs: run.artifacts.map((artifact) => artifact.id),
      policyDecisionRefs: [decisionId],
      rollbackRefs: [snapshotId],
    });
    return {
      schemaVersion: "ioi.runtime.diagnostics-repair-decision-execution.v1",
      schema_version: "ioi.runtime.diagnostics-repair-decision-execution.v1",
      object: "ioi.runtime_diagnostics_repair_retry",
      threadId,
      thread_id: threadId,
      status: "completed",
      turnId: repairTurn.turn_id,
      turn_id: repairTurn.turn_id,
      requestId: repairTurn.request_id,
      request_id: repairTurn.request_id,
      repairTurn,
      repair_turn: repairTurn,
      event,
      repair_retry_event: event,
      receiptRefs: event.receipt_refs,
      receipt_refs: event.receipt_refs,
      artifactRefs: event.artifact_refs,
      artifact_refs: event.artifact_refs,
      policyDecisionRefs: event.policy_decision_refs,
      policy_decision_refs: event.policy_decision_refs,
      rollbackRefs: event.rollback_refs,
      rollback_refs: event.rollback_refs,
      summary: String(event.payload?.summary ?? ""),
    };
  }

  private async mockDiagnosticsOperatorOverride(
    threadId: string,
    decisionId: string,
    workflowNodeId: string,
    input: RuntimeDiagnosticsRepairDecisionExecuteInput,
    snapshotId: string,
  ): Promise<RuntimeDiagnosticsOperatorOverrideResult> {
    const agent = await this.getAgent(agentIdForThread(threadId));
    const approvalRequired = Boolean(input.operatorOverrideRequiresApproval ?? input.operator_override_requires_approval ?? false);
    const approvalSatisfied =
      !approvalRequired ||
      Boolean(
        input.operatorOverrideApproved ??
          input.operator_override_approved ??
          input.overrideApproved ??
          input.override_approved ??
          input.approvalGranted ??
          input.approval_granted ??
          input.confirm ??
          input.confirmed ??
          input.approved,
      );
    const status = approvalRequired && !approvalSatisfied ? "blocked" : "completed";
    const event = mockRuntimeEventEnvelope({
      agent,
      threadId,
      streamId: eventStreamIdForThread(threadId),
      seq: 1,
      eventKind: "diagnostics.operator_override.executed",
      sourceEventKind: "LspDiagnostics.OperatorOverrideExecuted",
      itemId: `${threadId}:item:diagnostics-operator-override:${decisionId}`,
      payload: {
        event_kind: "LspDiagnosticsOperatorOverrideExecuted",
        decision_id: decisionId,
        action: "operator_override",
        status,
        snapshot_id: snapshotId,
        approval_required: approvalRequired,
        approval_satisfied: approvalSatisfied,
        approval_source: approvalSatisfied ? "boolean_confirmation" : "missing",
        continuation_allowed: status === "completed",
        summary:
          status === "completed"
            ? `Diagnostics operator override granted for ${decisionId}.`
            : `Diagnostics operator override blocked for ${decisionId}: approval is required.`,
      },
      createdAt: new Date().toISOString(),
      status,
      payloadSchemaVersion: "ioi.runtime.diagnostics-repair-decision-execution.v1",
      componentKind: "lsp_diagnostics_operator_override",
      workflowNodeId,
      receiptRefs: [`receipt_lsp_diagnostics_operator_override_${decisionId}`],
      artifactRefs: [],
      policyDecisionRefs: [
        decisionId,
        `policy_lsp_diagnostics_operator_override_${approvalSatisfied ? "approval_satisfied" : "approval_required"}`,
      ],
      rollbackRefs: [snapshotId],
    });
    return {
      schemaVersion: "ioi.runtime.diagnostics-repair-decision-execution.v1",
      schema_version: "ioi.runtime.diagnostics-repair-decision-execution.v1",
      object: "ioi.runtime_diagnostics_operator_override",
      threadId,
      thread_id: threadId,
      status,
      overrideStatus: status,
      override_status: status,
      approvalRequired,
      approval_required: approvalRequired,
      approvalSatisfied,
      approval_satisfied: approvalSatisfied,
      approvalSource: approvalSatisfied ? "boolean_confirmation" : "missing",
      approval_source: approvalSatisfied ? "boolean_confirmation" : "missing",
      continuationAllowed: status === "completed",
      continuation_allowed: status === "completed",
      event,
      operator_override_event: event,
      receiptRefs: event.receipt_refs,
      receipt_refs: event.receipt_refs,
      artifactRefs: event.artifact_refs,
      artifact_refs: event.artifact_refs,
      policyDecisionRefs: event.policy_decision_refs,
      policy_decision_refs: event.policy_decision_refs,
      rollbackRefs: event.rollback_refs,
      rollback_refs: event.rollback_refs,
      summary: String(event.payload?.summary ?? ""),
    };
  }

  async rememberMemory(agentId: string, input: RememberMemoryInput): Promise<RememberMemoryResult> {
    const agent = await this.getAgent(agentId);
    const threadId = input.threadId ?? threadIdForAgent(agent.id);
    const policy = this.memoryPolicyForAgent(agent, threadId, input);
    const blocked = mockMemoryWriteBlockReason(policy, input, true);
    if (blocked) {
      throw new IoiAgentError({
        code: "policy",
        message: "Memory write blocked by policy.",
        details: { agentId, threadId, reason: blocked, policy },
      });
    }
    const record = mockMemoryRecord(agent, input.text, {
      memoryKey: input.memoryKey,
      scope: input.scope ?? "thread",
      threadId,
      source: "sdk_memory_helper",
      workflowGraphId: input.workflowGraphId ?? null,
      workflowNodeId: input.workflowNodeId ?? "runtime.memory",
      workflowNodeType: input.workflowNodeType ?? "Memory",
    });
    this.memories.set(record.id, record);
    this.persistMemory(record);
    return {
      record,
      receipt: memoryReceipt(record),
    };
  }

  async listMemory(agentId: string, options: MemoryListOptions = {}): Promise<AgentMemoryProjection> {
    const agent = await this.getAgent(agentId);
    const threadId = options.threadId ?? threadIdForAgent(agent.id);
    const records = this.memoryForAgent(agent, threadId, options);
    return {
      schemaVersion: "ioi.agent-runtime.memory.v1",
      object: "ioi.agent_memory_projection",
      threadId,
      agentId: agent.id,
      workspace: agent.cwd,
      policy: this.memoryPolicyForAgent(agent, threadId),
      paths: mockMemoryPath(agent, threadId, this.checkpointDir),
      filters: memoryListFilters(options),
      records,
      totalMatches: records.length,
    };
  }

  async updateMemory(agentId: string, memoryId: string, input: UpdateMemoryRecordInput): Promise<RememberMemoryResult> {
    const agent = await this.getAgent(agentId);
    const threadId = input.threadId ?? threadIdForAgent(agent.id);
    const policy = this.memoryPolicyForAgent(agent, threadId, input);
    const blocked = mockMemoryWriteBlockReason(policy, input, true);
    if (blocked) {
      throw new IoiAgentError({
        code: "policy",
        message: "Memory edit blocked by policy.",
        details: { agentId, threadId, memoryId, reason: blocked, policy },
      });
    }
    const existing = this.memories.get(memoryId);
    if (!existing) {
      throw new IoiAgentError({
        code: "not_found",
        message: `Memory record not found: ${memoryId}`,
        details: { memoryId },
      });
    }
    const updated: AgentMemoryRecord = {
      ...existing,
      fact: input.text,
      updatedAt: new Date().toISOString(),
      source: "sdk_memory_edit",
      evidenceRefs: [...new Set([...existing.evidenceRefs, "memory.edit"])],
    };
    this.persistMemory(updated);
    return { record: updated, receipt: memoryReceipt(updated, "memory_edit", "edit") };
  }

  async deleteMemory(agentId: string, memoryId: string, input: DeleteMemoryRecordInput = {}): Promise<RememberMemoryResult> {
    const agent = await this.getAgent(agentId);
    const threadId = input.threadId ?? threadIdForAgent(agent.id);
    const policy = this.memoryPolicyForAgent(agent, threadId, input);
    const blocked = mockMemoryWriteBlockReason(policy, input, true);
    if (blocked) {
      throw new IoiAgentError({
        code: "policy",
        message: "Memory delete blocked by policy.",
        details: { agentId, threadId, memoryId, reason: blocked, policy },
      });
    }
    const existing = this.memories.get(memoryId);
    if (!existing) {
      throw new IoiAgentError({
        code: "not_found",
        message: `Memory record not found: ${memoryId}`,
        details: { memoryId },
      });
    }
    this.memories.delete(memoryId);
    this.rmQuiet(path.join(this.checkpointDir, "memory", `${memoryId}.json`));
    return { record: existing, receipt: memoryReceipt(existing, "memory_delete", "delete") };
  }

  async getMemoryPolicy(agentId: string, options: { threadId?: string } = {}): Promise<AgentMemoryPolicy> {
    const agent = await this.getAgent(agentId);
    return this.memoryPolicyForAgent(agent, options.threadId ?? threadIdForAgent(agent.id));
  }

  async setMemoryPolicy(agentId: string, input: MemoryPolicyInput): Promise<MemoryPolicyUpdateResult> {
    const agent = await this.getAgent(agentId);
    const threadId = input.threadId ?? threadIdForAgent(agent.id);
    const policy = mockMemoryPolicy(agent, {
      ...this.memoryPolicyForAgent(agent, threadId),
      ...input,
      threadId,
      targetType: input.targetType ?? "thread",
      targetId: input.targetId ?? threadId,
      source: "sdk_memory_policy",
    });
    this.persistMemoryPolicy(policy);
    return { policy, receipt: memoryPolicyReceipt(policy) };
  }

  async memoryPath(agentId: string, options: { threadId?: string } = {}): Promise<AgentMemoryPathProjection> {
    const agent = await this.getAgent(agentId);
    return mockMemoryPath(agent, options.threadId ?? threadIdForAgent(agent.id), this.checkpointDir);
  }

  private async createRun(
    agentId: string,
    prompt: string,
    mode: RuntimeRunRecord["mode"],
    options: SendOptions = {},
  ): Promise<RuntimeRunRecord> {
    const agent = await this.getAgent(agentId);
    if (agent.runtime !== "local") {
      throw new IoiAgentError({
        code: "external_blocker",
        message: `${agent.runtime} runtime provider is not configured for SDK execution.`,
        details: { runtime: agent.runtime, agentId },
      });
    }
    const memory = this.resolveRunMemory(agent, prompt, options, mode);
    const run = buildMockRun(agent, prompt, mode, options, memory);
    const usageTelemetry = mockUsageForRun(run);
    const runtimeRun = {
      ...run,
      usage: usageTelemetry,
      usage_telemetry: usageTelemetry,
      usageTelemetry,
      runtimeUsage: usageTelemetry,
      trace: {
        ...run.trace,
        usage: usageTelemetry,
        usage_telemetry: usageTelemetry,
        usageTelemetry,
        runtimeUsage: usageTelemetry,
      },
    };
    await emitCallbacks(runtimeRun, options);
    this.persistRun(runtimeRun);
    return runtimeRun;
  }

  private async usageForThread(threadId: string): Promise<RuntimeUsageTelemetry> {
    const agent = await this.agentForThread(threadId);
    const runs = await this.listRuns(agent.id);
    return mockUsageForThread({
      threadId,
      agent,
      runs,
      subagents: [...this.subagents.values()].filter(
        (record) => (record.parent_thread_id ?? record.parentThreadId) === threadId,
      ),
    });
  }

  private withTerminalReplacement(
    run: RuntimeRunRecord,
    status: RuntimeRunRecord["status"],
    data: Record<string, unknown>,
  ): RuntimeRunRecord {
    const events = run.events.filter(
      (event) => event.type !== "completed" && event.type !== "canceled",
    );
    const canceledEvent = makeEvent(run.id, run.agentId, events.length, "canceled", "Run canceled", data);
    const stopCondition: StopConditionProjection = {
      reason: "marginal_improvement_too_low",
      evidenceSufficient: true,
      rationale: "Run has an explicit cancellation terminal state and replay pointer.",
    };
    const trace = {
      ...run.trace,
      events: [...events, canceledEvent],
      stopCondition,
      qualityLedger: {
        ...run.trace.qualityLedger,
        failureOntologyLabels: ["operator_cancel"],
      },
    };
    return {
      ...run,
      status,
      updatedAt: new Date().toISOString(),
      events: trace.events,
      trace,
      result: "Run canceled with terminal event continuity preserved.",
    };
  }

  private loadCheckpoints(): void {
    for (const [kind, target] of [
      ["agents", this.agents],
      ["runs", this.runs],
      ["memory", this.memories],
      ["memory-policies", this.memoryPolicies],
    ] as const) {
      const dir = path.join(this.checkpointDir, kind);
      if (!fs.existsSync(dir)) {
        continue;
      }
      for (const file of fs.readdirSync(dir)) {
        if (!file.endsWith(".json")) {
          continue;
        }
        const parsed = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
        target.set(parsed.id, parsed);
      }
    }
  }

  private persistAgent(agent: RuntimeAgentRecord): void {
    this.agents.set(agent.id, agent);
    writeJson(path.join(this.checkpointDir, "agents", `${agent.id}.json`), agent);
  }

  private persistRun(run: RuntimeRunRecord): void {
    this.runs.set(run.id, run);
    writeJson(path.join(this.checkpointDir, "runs", `${run.id}.json`), run);
  }

  private persistMemory(record: AgentMemoryRecord): void {
    this.memories.set(record.id, record);
    writeJson(path.join(this.checkpointDir, "memory", `${record.id}.json`), record);
  }

  private persistMemoryPolicy(policy: AgentMemoryPolicy): void {
    this.memoryPolicies.set(policy.id, policy);
    writeJson(path.join(this.checkpointDir, "memory-policies", `${safeFileName(policy.id)}.json`), policy);
  }

  private memoryForAgent(agent: RuntimeAgentRecord, threadId = threadIdForAgent(agent.id), options: MemoryListOptions = {}): AgentMemoryRecord[] {
    const filters = memoryListFilters(options);
    const records = [...this.memories.values()]
      .filter(
        (record) =>
          record.scope === "global" ||
          record.threadId === threadId ||
          (record.agentId === agent.id && record.scope !== "thread") ||
          (record.workspace === agent.cwd && record.scope === "workspace"),
      )
      .filter((record) => !filters.scope || record.scope === filters.scope)
      .filter((record) => !filters.memoryKey || record.memoryKey === filters.memoryKey)
      .filter((record) => !filters.query || mockMemorySearchText(record).includes(filters.query))
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
    const limited = filters.limit ? records.slice(0, filters.limit) : records;
    return filters.redaction === "redacted" ? limited.map(redactMockMemoryRecord) : limited;
  }

  private memoryPolicyForAgent(
    agent: RuntimeAgentRecord,
    threadId = threadIdForAgent(agent.id),
    overrides: Partial<MemoryPolicyInput & RememberMemoryInput & UpdateMemoryRecordInput> = {},
  ): AgentMemoryPolicy {
    const stored =
      this.memoryPolicies.get(mockMemoryPolicyId("thread", threadId)) ??
      this.memoryPolicies.get(mockMemoryPolicyId("agent", agent.id));
    return mockMemoryPolicy(agent, {
      ...stored,
      ...mockPolicyFields(overrides),
      threadId,
      targetType: "thread",
      targetId: threadId,
      effective: true,
    });
  }

  private resolveRunMemory(
    agent: RuntimeAgentRecord,
    prompt: string,
    options: SendOptions,
    mode: RuntimeRunRecord["mode"] = "send",
  ): MockRunMemory {
    const threadId = options.memory?.threadId ?? threadIdForAgent(agent.id);
    const command = parseMockMemoryCommand(prompt);
    const policyUpdates: MemoryPolicyUpdateResult[] = [];
    const mutations: MockMemoryMutation[] = [];
    let policy = this.memoryPolicyForAgent(agent, threadId, options.memory ?? {});
    if (command.kind === "disable" || command.kind === "enable") {
      const nextPolicy = mockMemoryPolicy(agent, {
        ...policy,
        threadId,
        targetType: "thread",
        targetId: threadId,
        disabled: command.kind === "disable",
        injectionEnabled: command.kind !== "disable",
        source: `sdk_memory_${command.kind}`,
      });
      this.persistMemoryPolicy(nextPolicy);
      const update = { policy: nextPolicy, receipt: memoryPolicyReceipt(nextPolicy) };
      policyUpdates.push(update);
      mutations.push({ ...update, operation: "policy_update" });
      policy = this.memoryPolicyForAgent(agent, threadId, options.memory ?? {});
    }
    const subagentMemoryInheritance =
      mode === "handoff"
        ? this.resolveSubagentMemoryInheritance(agent, threadId, options, policy)
        : null;
    const effectivePolicy = subagentMemoryInheritance?.effectivePolicy ?? policy;
    const requestedRemember = options.memory?.remember;
    const requestedWrite =
      command.kind === "remember" ||
      command.kind === "edit" ||
      command.kind === "delete" ||
      Boolean(requestedRemember);
    const policyBlockReason = mockMemoryWriteBlockReason(effectivePolicy, options.memory ?? {}, requestedWrite);
    if (subagentMemoryInheritance) {
      subagentMemoryInheritance.writeBlockReason = policyBlockReason;
      subagentMemoryInheritance.writeAllowed = requestedWrite
        ? policyBlockReason === null
        : !effectivePolicy.disabled && !effectivePolicy.readOnly && !effectivePolicy.writeRequiresApproval;
    }
    if (effectivePolicy.disabled || effectivePolicy.injectionEnabled === false) {
      return {
        command: command.kind,
        records: [],
        writes: [],
        mutations,
        policy: effectivePolicy,
        policyUpdates,
        paths: mockMemoryPath(agent, threadId, this.checkpointDir),
        disabled: Boolean(effectivePolicy.disabled),
        policyBlockReason,
        subagentMemoryInheritance,
      };
    }
    const writes: RememberMemoryResult[] = [];
    if (!policyBlockReason && command.kind === "remember") {
      const record = mockMemoryRecord(agent, command.text, {
        memoryKey: options.memory?.memoryKey,
        scope: effectivePolicy.scope ?? "thread",
        threadId,
        source: "chat_hash_remember",
      });
      this.persistMemory(record);
      const write = { record, receipt: memoryReceipt(record) };
      writes.push(write);
      mutations.push({ ...write, operation: "write" });
    } else if (!policyBlockReason && command.kind === "edit") {
      const existing = this.memories.get(command.id);
      if (existing) {
        const record = {
          ...existing,
          fact: command.text,
          source: "sdk_memory_edit",
          updatedAt: new Date().toISOString(),
          evidenceRefs: [...new Set([...existing.evidenceRefs, "memory.edit"])],
        };
        this.persistMemory(record);
        mutations.push({ record, receipt: memoryReceipt(record, "memory_edit", "edit"), operation: "edit" });
      }
    } else if (!policyBlockReason && command.kind === "delete") {
      const record = this.memories.get(command.id);
      if (record) {
        this.memories.delete(record.id);
        this.rmQuiet(path.join(this.checkpointDir, "memory", `${record.id}.json`));
        mutations.push({ record, receipt: memoryReceipt(record, "memory_delete", "delete"), operation: "delete" });
      }
    } else if (!policyBlockReason && requestedRemember) {
      const record = mockMemoryRecord(agent, requestedRemember, {
        memoryKey: options.memory?.memoryKey,
        scope: effectivePolicy.scope ?? "thread",
        threadId,
        source: "sdk_send_memory_option",
      });
      this.persistMemory(record);
      const write = { record, receipt: memoryReceipt(record) };
      writes.push(write);
      mutations.push({ ...write, operation: "write" });
    }
    return {
      command: command.kind,
      records: subagentMemoryInheritance?.records ?? this.memoryForAgent(agent, threadId, options.memory ?? {}),
      writes,
      mutations,
      policy: effectivePolicy,
      policyUpdates,
      paths: mockMemoryPath(agent, threadId, this.checkpointDir),
      policyBlockReason,
      subagentMemoryInheritance,
    };
  }

  private resolveSubagentMemoryInheritance(
    agent: RuntimeAgentRecord,
    threadId: string,
    options: SendOptions,
    parentPolicy: AgentMemoryPolicy,
  ): SubagentMemoryInheritanceProjection {
    const memoryOptions = options.memory ?? {};
    const requestedMode = optionalMemoryString(memoryOptions.subagentInheritance) ?? parentPolicy.subagentInheritance ?? "explicit";
    const mode = normalizeSubagentInheritanceMode(requestedMode);
    const receiver = subagentReceiverName(options);
    const filters = memoryListFilters(memoryOptions);
    const parentAllowsInjection = !parentPolicy.disabled && parentPolicy.injectionEnabled !== false;
    const records =
      parentAllowsInjection && shouldInheritSubagentMemory(mode, memoryOptions)
        ? this.memoryForAgent(agent, threadId, {
            ...memoryOptions,
            redaction: memoryOptions.redaction ?? parentPolicy.redaction,
          })
        : [];
    const effectivePolicy = mockSubagentMemoryPolicy(agent, parentPolicy, {
      threadId,
      receiver,
      mode,
    });
    return {
      schemaVersion: "ioi.agent-runtime.subagent-memory-inheritance.v1",
      object: "ioi.subagent_memory_inheritance",
      parentAgentId: agent.id,
      subagentName: receiver,
      threadId,
      mode,
      requestedMode,
      parentPolicyId: parentPolicy.id ?? null,
      effectivePolicyId: effectivePolicy.id,
      parentPolicy,
      effectivePolicy,
      filters,
      records,
      inheritedRecordIds: records.map((record) => record.id),
      writeAllowed: !effectivePolicy.disabled && !effectivePolicy.readOnly && !effectivePolicy.writeRequiresApproval,
      writeBlockReason: null,
      evidenceRefs: [
        "subagent_memory_inheritance",
        "agent_memory_store",
        parentPolicy.id,
        effectivePolicy.id,
        ...records.map((record) => record.id),
      ].filter((value): value is string => Boolean(value)),
    };
  }

  private async agentForThread(threadId: string): Promise<RuntimeAgentRecord> {
    const agent = [...this.agents.values()].find((candidate) => threadIdForAgent(candidate.id) === threadId);
    if (!agent) {
      throw new IoiAgentError({ code: "not_found", message: `Thread not found: ${threadId}` });
    }
    return agent;
  }

  private threadRecordForAgent(agent: RuntimeAgentRecord): RuntimeThreadRecord {
    const runs = [...this.runs.values()]
      .filter((run) => run.agentId === agent.id)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
    const latestRun = runs.at(-1);
    const threadId = threadIdForAgent(agent.id);
    const events = this.threadRuntimeEvents(agent);
    const runtimeControls =
      (agent as RuntimeAgentRecord & { runtimeControls?: RuntimeThreadRecord["runtime_controls"] })
        .runtimeControls ?? null;
    const mode = runtimeControls?.mode ?? "agent";
    const approvalMode =
      runtimeControls?.approvalMode ?? runtimeControls?.approval_mode ?? "suggest";
    const modelControls = runtimeControls?.model;
    const usageTelemetry = mockUsageForThread({
      threadId,
      agent,
      runs,
      subagents: [...this.subagents.values()].filter(
        (record) => (record.parent_thread_id ?? record.parentThreadId) === threadId,
      ),
    });
    return {
      schema_version: "ioi.runtime.thread.v1",
      thread_id: threadId,
      session_id: `session_${agent.id}`,
      agent_id: agent.id,
      workspace_root: agent.cwd,
      title: latestRun?.objective ?? agent.cwd,
      mode,
      approval_mode: approvalMode,
      trust_profile: "local_private",
      model_route: agent.modelId,
      status: this.threadRecordStatus(agent),
      latest_turn_id: latestRun ? turnIdForRun(latestRun.id) : null,
      latest_seq: events.at(-1)?.seq ?? 0,
      event_stream_id: eventStreamIdForThread(threadId),
      workflow_graph_id: null,
      harness_binding_id: null,
      agentgres_projection_ref: `agents/${agent.id}.json`,
      created_at: agent.createdAt,
      updated_at: agent.updatedAt,
      archived_at: agent.status === "archived" ? agent.updatedAt : null,
      fixture_profile: "agent_sdk_mock",
      requested_model: agent.requestedModelId ?? agent.modelId,
      selected_model: agent.modelId,
      model_route_id: agent.modelRouteId ?? null,
      model_route_receipt_id: agent.modelRouteReceiptId ?? null,
      model_route_decision: agent.modelRouteDecision ?? null,
      reasoning_effort:
        agent.modelRouteDecision?.reasoningEffort ??
        modelControls?.reasoningEffort ??
        modelControls?.reasoning_effort ??
        null,
      runtime_controls: runtimeControls,
      usage: usageTelemetry,
      usage_telemetry: usageTelemetry,
      usageTelemetry,
      runtime_usage: usageTelemetry,
      runtimeUsage: usageTelemetry,
    };
  }

  private turnRecordForRun(run: RuntimeRunRecord): RuntimeTurnRecord {
    const turnId = turnIdForRun(run.id);
    const events = this.threadRuntimeEvents(this.agents.get(run.agentId)).filter(
      (event) => event.turn_id === turnId,
    );
    const status = run.turnStatus ?? runtimeTurnStatusForRun(run.status);
    return {
      schema_version: "ioi.runtime.turn.v1",
      turn_id: turnId,
      thread_id: threadIdForAgent(run.agentId),
      parent_turn_id: null,
      request_id: run.id,
      status,
      input_item_ids: events.filter((event) => event.event_kind === "turn.started").map((event) => event.item_id),
      output_item_ids: events.filter((event) => event.event_kind !== "turn.started").map((event) => event.item_id),
      seq_start: events.at(0)?.seq ?? null,
      seq_end: status === "running" || status === "queued" ? null : (events.at(-1)?.seq ?? null),
      started_at: run.createdAt,
      completed_at: run.status === "running" || run.status === "queued" ? null : run.updatedAt,
      mode: "agent",
      approval_mode: "suggest",
      model_route_decision_id: run.modelRouteDecision?.decisionId ?? null,
      usage: null,
      stop_reason: run.trace.stopCondition.reason,
      error: run.status === "failed" ? run.result : null,
      rollback_snapshot_id: null,
      quality_ledger_ref: run.trace.qualityLedger.ledgerId,
      workflow_execution_ref: null,
      fixture_profile: "agent_sdk_mock",
    };
  }

  private threadRuntimeEvents(agent?: RuntimeAgentRecord): RuntimeEventEnvelope[] {
    if (!agent) return [];
    const threadId = threadIdForAgent(agent.id);
    const streamId = eventStreamIdForThread(threadId);
    const events: RuntimeEventEnvelope[] = [
      mockRuntimeEventEnvelope({
        agent,
        threadId,
        streamId,
        seq: 1,
        eventKind: "thread.started",
        sourceEventKind: "agent.create",
        itemId: `${threadId}:item:thread-started`,
        payload: {
          event_kind: "ThreadStarted",
          agent_id: agent.id,
          thread_id: threadId,
          status: this.threadRecordStatus(agent),
        },
        createdAt: agent.createdAt,
        componentKind: "runtime_thread",
        workflowNodeId: "runtime.runtime-thread",
      }),
    ];
    const runs = [...this.runs.values()]
      .filter((run) => run.agentId === agent.id)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
    for (const run of runs) {
      const turnId = turnIdForRun(run.id);
      for (const event of run.events) {
        events.push(mockRuntimeEnvelopeForSdkEvent({
          agent,
          event,
          run,
          seq: events.length + 1,
          streamId,
          threadId,
          turnId,
        }));
      }
    }
    return events;
  }

  private threadRecordStatus(agent: RuntimeAgentRecord): RuntimeThreadRecord["status"] {
    return agent.status === "archived" ? "archived" : agent.status === "closed" ? "completed" : "active";
  }

  private rmQuiet(filePath: string): void {
    try {
      fs.rmSync(filePath, { force: true });
    } catch {
      // Best-effort cleanup; mock checkpoints are projections, not canonical runtime state.
    }
  }
}

function mockCodingToolSourceEventKind(toolId: string): string {
  return `CodingTool.${toolId
    .split(/[._-]/)
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join("")}`;
}

function runtimeModeForOptions(options: AgentOptions): RuntimeMode {
  if (options.cloud) return "cloud";
  if (options.hosted) return "hosted";
  if (options.selfHosted) return "selfHosted";
  return "local";
}

function ensureProviderConfigured(runtime: RuntimeMode, options: AgentOptions): void {
  if (runtime === "local") {
    return;
  }
  const providerEndpoint =
    endpointForCloud(options.cloud ?? options.hosted) ??
    options.selfHosted?.endpoint ??
    process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT ??
    process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT;
  if (!providerEndpoint) {
    throw new IoiAgentError({
      code: "external_blocker",
      message: `${runtime} runtime requested, but no IOI SDK provider endpoint is configured.`,
      details: {
        runtime,
        requiredEnvironment: [
          "IOI_AGENT_SDK_HOSTED_ENDPOINT",
          "IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT",
        ],
      },
    });
  }
}

function endpointForCloud(options?: CloudAgentOptions): string | undefined {
  return options?.endpoint;
}

function summarizeOptions(cwd: string, options: AgentOptions): AgentOptionsSummary {
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

function loadCursorCompatibilityConfig(cwd: string): {
  mcpServers: Record<string, McpServerConfig>;
  skillNames: string[];
  hookNames: string[];
} {
  const cursorDir = path.join(cwd, ".cursor");
  const mcpPath = path.join(cursorDir, "mcp.json");
  const hooksPath = path.join(cursorDir, "hooks.json");
  const skillsDir = path.join(cursorDir, "skills");
  const mcpServers = fs.existsSync(mcpPath) ? readJson(mcpPath).mcpServers ?? {} : {};
  const hookNames = fs.existsSync(hooksPath) ? Object.keys(readJson(hooksPath)) : [];
  const skillNames = fs.existsSync(skillsDir)
    ? fs.readdirSync(skillsDir).filter((entry) => !entry.startsWith("."))
    : [];
  return { mcpServers, hookNames, skillNames };
}

function mockModelRouteDecision(
  model: SendOptions["model"] | undefined,
  requestedModel: string,
  fallback?: ModelRouteDecision,
): ModelRouteDecision {
  if (!model && fallback) {
    return fallback;
  }
  const routeId = model?.routeId ?? model?.route ?? fallback?.routeId ?? "route.local-first";
  const autoResolved = requestedModel.trim().toLowerCase() === "auto";
  const selectedModel = autoResolved ? "local:auto" : requestedModel;
  const workflowNodeId = model?.workflowNodeId ?? fallback?.workflowNodeId ?? "runtime.model-router";
  const workflowNodeType = model?.workflowNodeType ?? fallback?.workflowNodeType ?? "Model Router";
  return {
    schemaVersion: "ioi.model-route-decision.v1",
    object: "ioi.model_route_decision",
    eventKind: "ModelRouteDecision",
    decisionId: mockStableHash({
      routeId,
      requestedModel,
      selectedModel,
      workflowNodeId,
      reasoningEffort: model?.reasoningEffort ?? model?.thinking,
    }),
    routeId,
    capability: model?.capability ?? fallback?.capability ?? "chat",
    requestedModel,
    requestedModelMode: autoResolved ? "auto" : requestedModel ? "explicit" : "route_default",
    autoResolved,
    selectedModel,
    upstreamModel: selectedModel,
    neverSendAutoUpstream: !autoResolved || selectedModel !== "auto",
    endpointId: selectedModel === "local:auto" ? "endpoint.local.auto" : `endpoint.mock.${selectedModel.replace(/[^a-z0-9]+/gi, "_")}`,
    providerId: "provider.local.folder",
    providerKind: "local_folder",
    providerLabel: "SDK mock local provider",
    reasoningEffort: model?.reasoningEffort ?? model?.thinking ?? fallback?.reasoningEffort ?? "provider_default",
    localRemotePlacement: "local",
    privacyPosture: model?.privacy ?? fallback?.privacyPosture ?? "local_private",
    costEstimateUsd: 0,
    costEstimateSource: "local_default",
    fallbackModel: null,
    fallbackEndpointId: "endpoint.local.auto",
    fallbackAllowed: true,
    fallbackTriggered: false,
    fallbackReason: null,
    rationale: autoResolved
      ? "model=auto resolved to local:auto through route.local-first before provider invocation."
      : `Explicit model ${requestedModel} resolved to ${selectedModel} on local_folder.`,
    policyConstraints: {
      routePrivacy: model?.privacy ?? "local_or_enterprise",
      requestedPrivacy: model?.privacy ?? null,
      providerEligibility: ["local_folder"],
      deniedProviders: ["openai", "anthropic", "gemini"],
      maxCostUsd: model?.maxCostUsd ?? 0,
      allowHostedFallback: Boolean(model?.allowHostedFallback),
      localOnly: model?.privacy === "local_only",
    },
    evaluatedCandidateCount: 1,
    rejectedCandidates: [],
    workflowGraphId: model?.workflowGraphId ?? fallback?.workflowGraphId ?? null,
    workflowNodeId,
    workflowNodeType,
    responseId: null,
    previousResponseId: null,
    policyHash: mockStableHash(model?.policy ?? {}),
    evidenceRefs: [
      "model_router",
      routeId,
      selectedModel === "local:auto" ? "endpoint.local.auto" : null,
      "provider.local.folder",
      autoResolved ? "model_auto_resolved_before_provider_invocation" : null,
    ].filter((value): value is string => Boolean(value)),
  };
}

function mockStableHash(value: unknown): string {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

interface MockRunMemory {
  command: MockMemoryCommand["kind"];
  records: AgentMemoryRecord[];
  writes: RememberMemoryResult[];
  mutations?: MockMemoryMutation[];
  policy?: AgentMemoryPolicy;
  policyUpdates?: MemoryPolicyUpdateResult[];
  paths?: AgentMemoryPathProjection;
  disabled?: boolean;
  policyBlockReason?: string | null;
  subagentMemoryInheritance?: SubagentMemoryInheritanceProjection | null;
}

type MockMemoryCommand =
  | { kind: "none" }
  | { kind: "show" }
  | { kind: "remember"; text: string }
  | { kind: "disable" }
  | { kind: "enable" }
  | { kind: "path" }
  | { kind: "edit"; id: string; text: string }
  | { kind: "delete"; id: string };

type MockMemoryMutation =
  | (RememberMemoryResult & { operation: "write" | "edit" | "delete" })
  | (MemoryPolicyUpdateResult & { operation: "policy_update" });

function parseMockMemoryCommand(prompt: string): MockMemoryCommand {
  const text = String(prompt ?? "").trim();
  const remember = text.match(/^#\s*remember\s+([\s\S]+)$/i);
  if (remember?.[1]?.trim()) return { kind: "remember", text: remember[1].trim() };
  if (/^\/memory(?:\s+show)?\s*$/i.test(text)) return { kind: "show" };
  if (/^\/memory\s+disable\s*$/i.test(text)) return { kind: "disable" };
  if (/^\/memory\s+enable\s*$/i.test(text)) return { kind: "enable" };
  if (/^\/memory\s+path\s*$/i.test(text)) return { kind: "path" };
  const edit = text.match(/^\/memory\s+edit\s+(\S+)\s+([\s\S]+)$/i);
  if (edit?.[1] && edit?.[2]?.trim()) return { kind: "edit", id: edit[1], text: edit[2].trim() };
  const deletion = text.match(/^\/memory\s+(?:delete|remove|forget)\s+(\S+)\s*$/i);
  if (deletion?.[1]) return { kind: "delete", id: deletion[1] };
  return { kind: "none" };
}

function mockMemoryRecord(
  agent: RuntimeAgentRecord,
  text: string,
  fields: {
    memoryKey?: string | null;
    scope: string;
    threadId: string;
    source: string;
    workflowGraphId?: string | null;
    workflowNodeId?: string | null;
    workflowNodeType?: string | null;
  },
): AgentMemoryRecord {
  const now = new Date().toISOString();
  return {
    schemaVersion: "ioi.agent-runtime.memory.v1",
    id: `memory_${crypto.randomUUID()}`,
    object: "ioi.agent_memory_record",
    scope: fields.scope,
    fact: String(text).trim(),
    memoryKey: fields.memoryKey ?? null,
    agentId: agent.id,
    threadId: fields.threadId,
    workspace: agent.cwd,
    workflowGraphId: fields.workflowGraphId ?? null,
    workflowNodeId: fields.workflowNodeId ?? "runtime.memory",
    workflowNodeType: fields.workflowNodeType ?? "Memory",
    source: fields.source,
    redaction: "none",
    createdAt: now,
    updatedAt: now,
    evidenceRefs: ["agent_memory_store", "memory.write", agent.id, fields.threadId],
  };
}

function memoryListFilters(options: MemoryListOptions = {}): MemoryListOptions {
  return {
    threadId: options.threadId,
    scope: optionalMemoryString(options.scope),
    memoryKey: optionalMemoryString(options.memoryKey),
    query: optionalMemoryString(options.query ?? options.q)?.toLowerCase(),
    limit: normalizeMemoryLimit(options.limit),
    redaction: options.redaction === "redacted" ? "redacted" : "none",
  };
}

function optionalMemoryString(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function normalizeMemoryLimit(value: unknown): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return undefined;
  return Math.min(Math.floor(parsed), 200);
}

function mockMemorySearchText(record: AgentMemoryRecord): string {
  return [
    record.fact,
    record.id,
    record.scope,
    record.memoryKey,
    record.workflowGraphId,
    record.workflowNodeId,
    record.workflowNodeType,
    record.source,
  ]
    .filter((value) => value !== undefined && value !== null)
    .map((value) => String(value).toLowerCase())
    .join("\n");
}

function redactMockMemoryRecord(record: AgentMemoryRecord): AgentMemoryRecord & { factHash: string } {
  return {
    ...record,
    fact: "[REDACTED]",
    factHash: crypto.createHash("sha256").update(record.fact).digest("hex"),
    redaction: "redacted",
  };
}

function memoryReceipt(
  record: AgentMemoryRecord,
  kind: "memory_write" | "memory_edit" | "memory_delete" = "memory_write",
  operation = "write",
): RuntimeReceipt {
  return {
    id: `receipt_${record.id}_${operation}`,
    kind,
    summary:
      kind === "memory_write"
        ? `Remembered ${record.scope} memory for ${record.threadId ?? record.agentId}.`
        : `${kind === "memory_edit" ? "Edited" : "Deleted"} memory record ${record.id}.`,
    redaction: "none",
    evidenceRefs: ["agent_memory_store", `memory.${operation}`, record.id],
  };
}

function mockMemoryPolicy(agent: RuntimeAgentRecord, fields: Partial<AgentMemoryPolicy> & { threadId?: string } = {}): AgentMemoryPolicy {
  const now = new Date().toISOString();
  const targetType = fields.targetType ?? "thread";
  const threadId = fields.threadId ?? threadIdForAgent(agent.id);
  const targetId = fields.targetId ?? threadId;
  return {
    schemaVersion: "ioi.agent-runtime.memory-policy.v1",
    id: mockMemoryPolicyId(targetType, targetId),
    object: "ioi.agent_memory_policy",
    targetType,
    targetId,
    agentId: agent.id,
    threadId,
    workspace: agent.cwd,
    disabled: false,
    injectionEnabled: true,
    readOnly: false,
    writeRequiresApproval: false,
    retention: "persistent",
    redaction: "none",
    subagentInheritance: "explicit",
    scope: "thread",
    source: "sdk_memory_policy_default",
    createdAt: fields.createdAt ?? now,
    updatedAt: now,
    evidenceRefs: ["agent_memory_store", "memory.policy"],
    ...mockPolicyFields(fields),
    effective: fields.effective,
    policyRefs: fields.policyRefs,
  };
}

function mockSubagentMemoryPolicy(
  agent: RuntimeAgentRecord,
  parentPolicy: AgentMemoryPolicy,
  fields: {
    threadId: string;
    receiver: string | null;
    mode: SubagentMemoryInheritanceProjection["mode"];
  },
): AgentMemoryPolicy {
  const targetId = `${fields.threadId}:${fields.receiver ?? "subagent"}`;
  const id = mockMemoryPolicyId("subagent", targetId);
  const disabled = parentPolicy.disabled || fields.mode === "none";
  const injectionEnabled = parentPolicy.injectionEnabled !== false && fields.mode !== "none";
  const readOnly = disabled || parentPolicy.readOnly || fields.mode === "read_only";
  const writeRequiresApproval =
    fields.mode === "explicit" ? true : Boolean(parentPolicy.writeRequiresApproval);
  const now = new Date().toISOString();
  return {
    ...parentPolicy,
    id,
    targetType: "subagent",
    targetId,
    agentId: agent.id,
    threadId: fields.threadId,
    workspace: agent.cwd,
    disabled,
    injectionEnabled,
    readOnly,
    writeRequiresApproval,
    source: "sdk_subagent_memory_inheritance",
    updatedAt: now,
    evidenceRefs: [
      ...new Set([
        ...parentPolicy.evidenceRefs,
        "subagent_memory_inheritance",
        "memory.policy.effective.subagent",
      ]),
    ],
    effective: true,
    policyRefs: [parentPolicy.id].filter(Boolean),
  };
}

function normalizeSubagentInheritanceMode(value: unknown): SubagentMemoryInheritanceProjection["mode"] {
  const mode = optionalMemoryString(value) ?? "explicit";
  return ["none", "explicit", "read_only", "full"].includes(mode) ? mode : "explicit";
}

function shouldInheritSubagentMemory(
  mode: SubagentMemoryInheritanceProjection["mode"],
  options: SendOptions["memory"] = {},
): boolean {
  if (mode === "none") return false;
  if (mode === "explicit") return hasExplicitSubagentMemorySelector(options);
  return true;
}

function hasExplicitSubagentMemorySelector(options: SendOptions["memory"] = {}): boolean {
  return Boolean(
    optionalMemoryString(options?.memoryKey) ??
      optionalMemoryString(options?.query ?? options?.q) ??
      optionalMemoryString(options?.scope),
  );
}

function subagentReceiverName(options: SendOptions): string | null {
  const receiver = (options as HandoffOptions).receiver;
  return optionalMemoryString(receiver) ?? null;
}

function mockPolicyFields(value: object = {}): Partial<AgentMemoryPolicy> {
  const fields: Partial<AgentMemoryPolicy> = {};
  const source = value as Record<string, unknown>;
  for (const key of [
    "disabled",
    "injectionEnabled",
    "readOnly",
    "writeRequiresApproval",
    "retention",
    "redaction",
    "subagentInheritance",
    "scope",
  ] as const) {
    if (source[key] !== undefined) {
      (fields as Record<string, unknown>)[key] = source[key];
    }
  }
  return fields;
}

function memoryPolicyReceipt(policy: AgentMemoryPolicy): RuntimeReceipt {
  return {
    id: `receipt_${policy.id}_${mockStableHash(policy.updatedAt).slice(0, 12)}`,
    kind: "memory_policy",
    summary: `Updated memory policy for ${policy.targetId}.`,
    redaction: "none",
    evidenceRefs: ["agent_memory_store", "memory.policy", policy.id],
  };
}

function subagentMemoryInheritanceReceiptForRun(
  runId: string,
  projection: SubagentMemoryInheritanceProjection,
): RuntimeReceipt {
  return {
    id: `receipt_${runId}_subagent_memory_inheritance`,
    kind: "subagent_memory_inheritance",
    summary: `Subagent memory inheritance ${projection.mode} for ${projection.subagentName ?? "handoff"} exposed ${projection.records.length} record(s).`,
    redaction: projection.effectivePolicy.redaction === "redacted" ? "redacted" : "none",
    evidenceRefs: projection.evidenceRefs,
  };
}

function mockMemoryWriteBlockReason(policy: AgentMemoryPolicy, options: object = {}, requestedWrite = false): string | null {
  if (!requestedWrite) return null;
  const source = options as { writeApproved?: unknown };
  if (policy.disabled) return "memory_disabled";
  if (policy.readOnly) return "memory_read_only";
  if (policy.writeRequiresApproval && !source.writeApproved) return "memory_write_requires_approval";
  return null;
}

function mockMemoryEventKind(operation: MockMemoryMutation["operation"]): string {
  switch (operation) {
    case "policy_update":
      return "MemoryPolicy";
    case "edit":
      return "MemoryEdit";
    case "delete":
      return "MemoryDelete";
    case "write":
    default:
      return "MemoryWrite";
  }
}

function mockMemoryEventSummary(operation: MockMemoryMutation["operation"]): string {
  switch (operation) {
    case "policy_update":
      return "Memory policy updated";
    case "edit":
      return "Memory record edited";
    case "delete":
      return "Memory record deleted";
    case "write":
    default:
      return "Memory write recorded";
  }
}

function mockMemoryPath(agent: RuntimeAgentRecord, threadId: string, checkpointDir: string): AgentMemoryPathProjection {
  return {
    schemaVersion: "ioi.agent-runtime.memory.v1",
    object: "ioi.agent_memory_path_projection",
    threadId,
    agentId: agent.id,
    workspace: agent.cwd,
    recordsPath: path.join(checkpointDir, "memory"),
    policiesPath: path.join(checkpointDir, "memory-policies"),
    effectivePolicyId: mockMemoryPolicyId("thread", threadId),
  };
}

function mockEmptyMemoryProjection(): AgentMemoryProjection {
  return {
    schemaVersion: "ioi.agent-runtime.memory.v1",
    object: "ioi.agent_memory_projection",
    threadId: null,
    agentId: null,
    workspace: null,
    records: [],
    totalMatches: 0,
  };
}

function mockMemoryStatusForProjection(projection: {
  threadId?: string | null;
  agentId?: string | null;
  workspace?: string | null;
  policy?: AgentMemoryPolicy;
  paths?: unknown;
  filters?: unknown;
  records?: AgentMemoryRecord[];
}): RuntimeMemoryStatus {
  const records = projection.records ?? [];
  const policy = projection.policy;
  const disabled = Boolean(policy?.disabled);
  const validation = mockMemoryValidationForProjection(projection);
  return {
    schema_version: "ioi.runtime.memory-manager-status.v1",
    schemaVersion: "ioi.runtime.memory-manager-status.v1",
    object: "ioi.runtime_memory_manager_status",
    status: validation.ok ? (disabled ? "disabled" : "ready") : "needs_review",
    disabled,
    injection_enabled: policy?.injectionEnabled !== false,
    injectionEnabled: policy?.injectionEnabled !== false,
    read_only: Boolean(policy?.readOnly),
    readOnly: Boolean(policy?.readOnly),
    write_requires_approval: Boolean(policy?.writeRequiresApproval),
    writeRequiresApproval: Boolean(policy?.writeRequiresApproval),
    write_blocked_reason: disabled
      ? "memory_disabled"
      : policy?.readOnly
        ? "memory_read_only"
        : policy?.writeRequiresApproval
          ? "memory_write_requires_approval"
          : null,
    record_count: records.length,
    recordCount: records.length,
    thread_id: projection.threadId ?? null,
    threadId: projection.threadId ?? null,
    agent_id: projection.agentId ?? null,
    agentId: projection.agentId ?? null,
    workspace: projection.workspace ?? null,
    policy,
    paths: projection.paths,
    filters: projection.filters,
    records,
    validation,
    routes: {
      records: "/v1/threads/{thread_id}/memory",
      status: "/v1/threads/{thread_id}/memory/status",
      validate: "/v1/threads/{thread_id}/memory/validate",
    },
  };
}

function mockMemoryValidationForProjection(projection: {
  threadId?: string | null;
  agentId?: string | null;
  workspace?: string | null;
  policy?: AgentMemoryPolicy;
  paths?: unknown;
  filters?: unknown;
  records?: AgentMemoryRecord[];
}): RuntimeMemoryValidationResult {
  const records = projection.records ?? [];
  const issues = records
    .filter((record) => !record.id || !record.fact)
    .map((record) => ({
      code: "memory_record_invalid",
      severity: "error" as const,
      message: "Memory record must have id and fact text.",
      memoryRecordId: record.id ?? null,
      memory_record_id: record.id ?? null,
    }));
  return {
    schema_version: "ioi.runtime.memory-manager-validation.v1",
    schemaVersion: "ioi.runtime.memory-manager-validation.v1",
    object: "ioi.runtime_memory_manager_validation",
    ok: issues.length === 0,
    status: issues.length === 0 ? "pass" : "blocked",
    issue_count: issues.length,
    issueCount: issues.length,
    warning_count: 0,
    warningCount: 0,
    record_count: records.length,
    recordCount: records.length,
    thread_id: projection.threadId ?? null,
    threadId: projection.threadId ?? null,
    agent_id: projection.agentId ?? null,
    agentId: projection.agentId ?? null,
    workspace: projection.workspace ?? null,
    issues,
    warnings: [],
    policy: projection.policy,
    paths: projection.paths,
    filters: projection.filters,
    records,
  };
}

function mockMemoryPolicyId(targetType: string, targetId: string): string {
  return `memory_policy_${targetType}_${safeFileName(targetId)}`;
}

function safeFileName(value: string): string {
  return String(value).replace(/[^a-zA-Z0-9_.-]+/g, "_");
}

function threadIdForAgent(agentId: string): string {
  return agentId.startsWith("agent_") ? `thread_${agentId.slice("agent_".length)}` : `thread_${agentId}`;
}

function agentIdForThread(threadId: string): string {
  return threadId.startsWith("thread_") ? `agent_${threadId.slice("thread_".length)}` : threadId;
}

function buildMockRun(
  agent: RuntimeAgentRecord,
  prompt: string,
  mode: RuntimeRunRecord["mode"],
  options: SendOptions,
  memory: MockRunMemory = { command: "none", records: [], writes: [] },
): RuntimeRunRecord {
  const runId = `run_${crypto.randomUUID()}`;
  const createdAt = new Date().toISOString();
  const taskFamily = taskFamilyForMode(mode);
  const selectedStrategy = strategyForMode(mode);
  const toolSequence = capabilitySequenceForMode(mode, agent);
  const modelRouteDecision = mockModelRouteDecision(
    options.model,
    options.model?.id ?? agent.requestedModelId ?? agent.modelId,
    agent.modelRouteDecision ?? undefined,
  );
  const modelRouteReceiptId = `receipt_${runId}_model_route`;
  const selectedModel = modelRouteDecision.selectedModel ?? options.model?.id ?? agent.modelId;
  const computerUseProjection = mockComputerUseProjectionForRun({
    cwd: agent.cwd,
    runId,
    prompt,
    mode,
    options,
    selectedModel,
  });
  if (computerUseProjection) {
    toolSequence.push("computer_use_harness");
  }
  const inlineMcpServerNames = Object.keys(options.mcpServers ?? {});
  const memoryRecords = memory.records;
  const memoryMutations = memory.mutations ?? memory.writes.map((write) => ({ ...write, operation: "write" as const }));
  const memoryWrites = memory.writes.map((write) => write.record);
  const memoryWriteReceipts = memoryMutations.map((write) => write.receipt);
  const memoryPolicy = memory.policy ?? null;
  const subagentMemoryInheritance =
    mode === "handoff" ? memory.subagentMemoryInheritance ?? null : null;
  const subagentMemoryReceipt = subagentMemoryInheritance
    ? subagentMemoryInheritanceReceiptForRun(runId, subagentMemoryInheritance)
    : null;
  const taskState: TaskStateProjection = {
    currentObjective: prompt,
    knownFacts: [
      "SDK run entered through the explicit mock RuntimeSubstrateClient",
      "Authority and trace export are required by the IOI runtime contract",
      `Selected model profile: ${selectedModel}`,
      ...(memoryPolicy
        ? [
            `Memory policy: disabled=${Boolean(memoryPolicy.disabled)}, injection=${memoryPolicy.injectionEnabled !== false}, readOnly=${Boolean(memoryPolicy.readOnly)}, writeRequiresApproval=${Boolean(memoryPolicy.writeRequiresApproval)}`,
          ]
        : []),
      ...(subagentMemoryInheritance
        ? [
            `Subagent memory inheritance: mode=${subagentMemoryInheritance.mode}, receiver=${subagentMemoryInheritance.subagentName ?? "handoff"}, records=${subagentMemoryInheritance.records.length}, writeAllowed=${subagentMemoryInheritance.writeAllowed}`,
          ]
        : []),
      ...(computerUseProjection
        ? [
            `Computer-use lane: ${computerUseProjection.environmentSelection.selected_lane}/${computerUseProjection.environmentSelection.selected_session_mode}`,
            `Computer-use observation: ${computerUseProjection.observation.observation_ref} with target index ${computerUseProjection.targetIndex.target_index_ref}`,
          ]
        : []),
      ...memoryRecords.map((record) => `Memory fact (${record.scope}:${record.id}): ${record.fact}`),
    ],
    uncertainFacts: mode === "dry_run" ? ["Side effects are previewed, not executed"] : [],
    assumptions: ["Mock SDK execution writes non-authoritative checkpoint projections"],
    constraints: ["No GUI internals", "No raw receipt dump", "No policy bypass"],
    blockers: [],
    changedObjects: mode === "send" ? [] : [`sdk:${mode}`],
    evidenceRefs: [
      "runtime_substrate_client",
      "agent_sdk_mock_checkpoint",
      ...inlineMcpServerNames,
      ...modelRouteDecision.evidenceRefs,
      modelRouteReceiptId,
      memoryPolicy?.id,
      ...memoryRecords.map((record) => record.id),
      ...memoryWriteReceipts.map((receipt) => receipt.id),
      subagentMemoryReceipt?.id,
      computerUseProjection?.receipt.id,
      computerUseProjection?.environmentSelection.receipt_ref,
      computerUseProjection?.observation.observation_ref,
      computerUseProjection?.actionProposal?.proposal_ref,
      computerUseProjection?.action?.action_ref,
      computerUseProjection?.actionReceipt?.receipt_ref,
      computerUseProjection?.trajectory?.trajectory_ref,
      computerUseProjection?.cleanup.cleanup_ref,
    ].filter((value): value is string => Boolean(value)),
  };
  const uncertainty: UncertaintyProjection = {
    ambiguityLevel: mode === "send" ? "low" : "medium",
    selectedAction:
      mode === "dry_run"
        ? "dry_run"
        : mode === "plan"
          ? "verify"
          : mode === "handoff"
            ? "execute"
            : "probe",
    rationale: "Explicit SDK mock runs choose a bounded substrate projection before terminal output.",
    valueOfProbe: mode === "send" ? "medium" : "high",
  };
  const probes: ProbeProjection[] = [
    {
      probeId: `${runId}:probe:substrate`,
      hypothesis: "The explicit SDK mock path can preserve substrate events, trace, receipts, and scorecard.",
      cheapestValidationAction: "Inspect generated local checkpoint and replay event cursor.",
      expectedObservation: "Monotonic event stream with terminal event and trace bundle.",
      result: "confirmed",
      confidenceUpdate: "SDK mock substrate projection is replayable for this run.",
    },
  ];
  const postconditions: PostconditionProjection = {
    objective: prompt,
    taskFamily,
    riskClass: mode === "dry_run" ? "side_effect_preview" : "bounded_local",
    checks: [
      {
        checkId: "event-stream-terminal",
        description: "Event stream contains exactly one terminal event.",
        status: "passed",
      },
      {
        checkId: "trace-export",
        description: "Trace bundle is exportable and replay-compatible.",
        status: "passed",
      },
      {
        checkId: "quality-ledger",
        description: "Quality ledger and stop condition are attached.",
        status: "passed",
      },
      ...(computerUseProjection
        ? [
            {
              checkId: "computer-use-lifecycle-trace",
              description: "Computer-use lease, proposal, action receipt, verification, trajectory, and cleanup are trace-visible.",
              status: "passed" as const,
            },
          ]
        : []),
    ],
    minimumEvidence: [
      "events",
      "receipts",
      "trace",
      ...(computerUseProjection ? ["computer_use_trace", "computer-use-trace.json"] : []),
      "scorecard",
    ],
  };
  const semanticImpact: SemanticImpactProjection = {
    changedSymbols: [],
    changedApis: mode === "learn" ? ["agent.learn"] : [],
    changedSchemas: [
      "IOISDKMessage",
      "RuntimeTraceBundle",
      "ModelRouteDecision",
      "AgentMemoryPolicy",
      "SubagentMemoryInheritanceProjection",
      ...(computerUseProjection
        ? [
            "ComputerUseRunState",
            "EnvironmentSelectionReceipt",
            "ComputerUseObservationBundle",
            "TargetIndex",
            "AffordanceGraph",
            "ActionProposal",
            "ComputerAction",
            "ActionReceipt",
            "ComputerUseVerificationReceipt",
            "ComputerUseTrajectoryBundle",
            "CleanupReceipt",
          ]
        : []),
    ],
    changedPolicies: [
      ...(mode === "dry_run" ? ["authority.preview_only"] : []),
      ...(memory.policyBlockReason ? [`memory.${memory.policyBlockReason}`] : []),
      ...(memory.policyUpdates?.map(() => "memory.policy") ?? []),
      ...(subagentMemoryInheritance
        ? [`memory.subagent_inheritance.${subagentMemoryInheritance.mode}`]
        : []),
      ...(computerUseProjection
        ? [
            "computer_use.native_browser.read_only",
            "computer_use.action_proposal_required",
            "computer_use.cleanup_required",
          ]
        : []),
    ],
    affectedTests: ["cursor-sdk-parity-contract"],
    affectedDocs: ["cursor-sdk-harness-parity-plus-master-guide.md"],
    riskClass: postconditions.riskClass,
  };
  const stopCondition: StopConditionProjection = {
    reason: "evidence_sufficient",
    evidenceSufficient: true,
    rationale: "Required SDK trace, replay, postcondition, and scorecard evidence were produced.",
  };
  const qualityLedger: AgentQualityLedgerProjection = {
    ledgerId: `quality_${runId}`,
    taskFamily,
    selectedStrategy,
    toolSequence,
    scorecardMetrics: {
      task_pass_rate: 100,
      recovery_success: 100,
      memory_relevance: mode === "learn" ? 100 : 90,
      tool_quality: 95,
      strategy_roi: 90,
      operator_interventions: 0,
      verifier_independence: 100,
    },
    failureOntologyLabels: [],
  };
  const scorecard: RuntimeScorecard = {
    taskPassRate: 1,
    recoverySuccess: 1,
    memoryRelevance: mode === "learn" ? 1 : 0.9,
    toolQuality: 0.95,
    strategyRoi: 0.9,
    operatorInterventionRate: 0,
    verifierIndependence: 1,
  };
  const receipts: RuntimeReceipt[] = [
    {
      id: modelRouteReceiptId,
      kind: "model_route_selection",
      summary: `Route ${modelRouteDecision.routeId} selected ${modelRouteDecision.selectedModel}.`,
      redaction: "none",
      evidenceRefs: modelRouteDecision.evidenceRefs,
    },
    ...(computerUseProjection ? [computerUseProjection.receipt] : []),
    ...(subagentMemoryReceipt ? [subagentMemoryReceipt] : []),
    ...memoryWriteReceipts,
    {
      id: `receipt_${runId}_authority`,
      kind: "authority_decision",
      summary: "SDK mock action used an explicit non-authoritative runtime substrate projection.",
      redaction: "none",
      evidenceRefs: ["RuntimeSubstratePortContract"],
    },
    {
      id: `receipt_${runId}_trace`,
      kind: "trace_export",
      summary: "Trace export was generated from the explicit SDK mock runtime projection.",
      redaction: "redacted",
      evidenceRefs: ["RuntimeTraceBundle"],
    },
  ];
  const result = resultForMode(mode, agent, prompt, memory);
  const events: IOISDKMessage[] = [];
  const addEvent = (type: IOISDKMessage["type"], summary: string, data?: unknown): IOISDKMessage => {
    const event = makeEvent(runId, agent.id, events.length, type, summary, data);
    events.push(event);
    return event;
  };
  const startedEvent = addEvent("run_started", "Run entered IOI SDK substrate", {
    taskFamily,
    selectedStrategy,
  });
  addEvent("model_route_decision", "Model route decision recorded", {
    ...modelRouteDecision,
    receiptId: modelRouteReceiptId,
  });
  if (computerUseProjection) {
    for (const event of computerUseProjection.events) {
      addEvent(event.type, event.summary, event.data);
    }
  }
  for (const mutation of memoryMutations) {
    addEvent("memory_update", mockMemoryEventSummary(mutation.operation), {
      ...(("record" in mutation ? mutation.record : mutation.policy) ?? {}),
      operation: mutation.operation,
      eventKind: mockMemoryEventKind(mutation.operation),
      receiptId: mutation.receipt.id,
    });
  }
  if (subagentMemoryInheritance) {
    addEvent("memory_update", "Subagent memory inheritance resolved", {
      ...subagentMemoryInheritance,
      operation: "subagent_inheritance",
      eventKind: "SubagentMemoryInheritance",
      receiptId: subagentMemoryReceipt?.id ?? null,
    });
  }
  addEvent("task_state", "Task state projected", taskState);
  addEvent("uncertainty", "Uncertainty assessed", uncertainty);
  addEvent("probe", "Probe completed", probes[0]);
  addEvent("postcondition_synthesized", "Postconditions synthesized", postconditions);
  addEvent("semantic_impact", "Semantic impact classified", semanticImpact);
  const deltaEvent = addEvent("delta", result, { text: result });
  const usagePreview = mockUsageForRun({
    id: runId,
    agentId: agent.id,
    status: "completed",
    objective: prompt,
    mode,
    createdAt,
    updatedAt: createdAt,
    events: [],
    conversation: [],
    receipts,
    artifacts: [],
    trace: {} as RuntimeTraceBundle,
    modelRouteDecision,
    modelRouteReceiptId,
    memoryPolicy,
    memoryRecords,
    memoryWriteReceipts,
    subagentMemoryInheritance,
    result,
  });
  addEvent("usage_final", "Usage telemetry recorded", usagePreview);
  addEvent("stop_condition", "Stop condition recorded", stopCondition);
  addEvent("quality_ledger", "Quality ledger recorded", qualityLedger);
  addEvent("completed", "Run completed", { stopReason: stopCondition.reason });
  const trace: RuntimeTraceBundle = {
    schemaVersion: "ioi.agent-sdk.trace.v1",
    traceBundleId: `trace_${runId}`,
    agentId: agent.id,
    runId,
    eventStreamId: `events_${runId}`,
    events,
    receipts,
    taskState,
    uncertainty,
    probes,
    postconditions,
    semanticImpact,
    modelRouteDecision,
    memoryPolicy,
    memoryRecords,
    memoryWrites,
    computerUse: computerUseProjection
      ? {
          environmentSelection: computerUseProjection.environmentSelection,
          lease: computerUseProjection.lease,
          runState: computerUseProjection.runState,
          observation: computerUseProjection.observation,
          targetIndex: computerUseProjection.targetIndex,
          affordanceGraph: computerUseProjection.affordanceGraph,
          actionProposal: computerUseProjection.actionProposal,
          action: computerUseProjection.action,
          actionReceipt: computerUseProjection.actionReceipt,
          verification: computerUseProjection.verification,
          outcomeContract: computerUseProjection.outcomeContract,
          commitGate: computerUseProjection.commitGate,
          trajectory: computerUseProjection.trajectory,
          cleanup: computerUseProjection.cleanup,
        }
      : null,
    subagentMemoryInheritance,
    stopCondition,
    qualityLedger,
    scorecard,
  };
  const artifacts: RuntimeArtifact[] = [
    {
      id: `artifact_${runId}_trace`,
      runId,
      name: "trace.json",
      mediaType: "application/json",
      redaction: "redacted",
      receiptId: receipts[receipts.length - 1]?.id ?? modelRouteReceiptId,
      content: JSON.stringify(trace, null, 2),
    },
    ...(computerUseProjection
      ? [
          {
            id: `artifact_${runId}_computer_use_trace`,
            runId,
            name: "computer-use-trace.json",
            mediaType: "application/json",
            redaction: "redacted" as const,
            receiptId: computerUseProjection.receipt.id,
            content: JSON.stringify(trace.computerUse, null, 2),
          },
        ]
      : []),
    {
      id: `artifact_${runId}_scorecard`,
      runId,
      name: "scorecard.json",
      mediaType: "application/json",
      redaction: "none",
      receiptId: receipts[receipts.length - 1]?.id ?? modelRouteReceiptId,
      content: JSON.stringify(scorecard, null, 2),
    },
  ];
  return {
    id: runId,
    agentId: agent.id,
    status: "completed",
    objective: prompt,
    mode,
    createdAt,
    updatedAt: createdAt,
    events,
    conversation: [
      { role: "user", content: prompt, eventId: startedEvent.id, createdAt },
      { role: "assistant", content: result, eventId: deltaEvent.id, createdAt },
    ],
    receipts,
    artifacts,
    trace,
    modelRouteDecision,
    modelRouteReceiptId,
    memoryPolicy,
    memoryRecords,
    memoryWriteReceipts,
    subagentMemoryInheritance,
    result,
  };
}

function resultForMode(
  mode: RuntimeRunRecord["mode"],
  agent: RuntimeAgentRecord,
  prompt: string,
  memory: MockRunMemory = { command: "none", records: [], writes: [] },
): string {
  if (memory.command === "disable") {
    return "Memory is disabled for this thread.";
  }
  if (memory.command === "enable") {
    return "Memory is enabled for this thread.";
  }
  if (memory.command === "path") {
    return `Memory records path: ${memory.paths?.recordsPath ?? "unknown"}\nMemory policy path: ${memory.paths?.policiesPath ?? "unknown"}`;
  }
  if (memory.policyBlockReason) {
    return `Memory write blocked by policy: ${memory.policyBlockReason}.`;
  }
  if (memory.command === "edit") {
    const edited = memory.mutations?.find((mutation) => mutation.operation === "edit" && "record" in mutation);
    return edited && "record" in edited ? `Edited memory: ${edited.record.id}` : "No memory was edited.";
  }
  if (memory.command === "delete") {
    const deleted = memory.mutations?.find((mutation) => mutation.operation === "delete" && "record" in mutation);
    return deleted && "record" in deleted ? `Deleted memory: ${deleted.record.id}` : "No memory was deleted.";
  }
  if (memory.disabled && (memory.command === "remember" || memory.command === "show")) {
    return "Memory is disabled for this run.";
  }
  if (memory.command === "remember") {
    return memory.writes.length > 0
      ? `Remembered: ${memory.writes.map((write) => write.record.fact).join("; ")}`
      : "No memory was written because the remember request was empty.";
  }
  if (memory.command === "show") {
    return memory.records.length > 0
      ? `Memory:\n${memory.records.map((record) => `- ${record.fact}`).join("\n")}`
      : "Memory is empty for this thread.";
  }
  switch (mode) {
    case "plan":
      return `Plan-only SDK run recorded objective, constraints, postconditions, and stop reason for: ${prompt}`;
    case "dry_run":
      return "Dry run completed. Side effects were previewed and no tool mutation was executed.";
    case "handoff":
      return "Handoff bundle is complete: objective, state, blockers, evidence, and next action are preserved.";
    case "learn":
      return "Governed learning record created behind memory quality and bounded self-improvement gates.";
    case "send":
      return `IOI SDK mock run completed for ${agent.cwd}. This is a non-authoritative projection; trace, receipts, task state, uncertainty, probe, postconditions, semantic impact, stop condition, and scorecard are available through run.inspect(), run.trace(), and run.scorecard().`;
  }
}

function taskFamilyForMode(mode: RuntimeRunRecord["mode"]): string {
  switch (mode) {
    case "plan":
      return "planning";
    case "dry_run":
      return "safety_preview";
    case "handoff":
      return "delegation";
    case "learn":
      return "learning";
    case "send":
      return "mock_sdk_projection";
  }
}

function strategyForMode(mode: RuntimeRunRecord["mode"]): string {
  switch (mode) {
    case "plan":
      return "plan_only_with_postconditions";
    case "dry_run":
      return "dry_run_before_effect";
    case "handoff":
      return "handoff_with_state_preservation";
    case "learn":
      return "bounded_learning_gate";
    case "send":
      return "explicit_mock_substrate_projection";
  }
}

function capabilitySequenceForMode(mode: RuntimeRunRecord["mode"], agent: RuntimeAgentRecord): string[] {
  const base = ["authority_check", "task_state_projection", "trace_export"];
  if (agent.options.mcpServerNames.length > 0) {
    base.push("mcp_containment");
  }
  if (agent.options.skillNames.length > 0) {
    base.push("skill_instruction_import");
  }
  if (agent.options.hookNames.length > 0) {
    base.push("runtime_event_hook");
  }
  if (mode === "dry_run") {
    base.push("side_effect_preview");
  }
  if (mode === "handoff") {
    base.push("handoff_quality");
  }
  if (mode === "learn") {
    base.push("memory_quality_gate");
  }
  return base;
}

function makeEvent(
  runId: string,
  agentId: string,
  index: number,
  type: IOISDKMessage["type"],
  summary: string,
  data?: unknown,
): IOISDKMessage {
  return {
    id: `${runId}:event:${String(index).padStart(3, "0")}:${type}`,
    runId,
    agentId,
    type,
    cursor: `${runId}:${index}`,
    createdAt: new Date().toISOString(),
    summary,
    data,
  };
}

async function emitCallbacks(run: RuntimeRunRecord, options: SendOptions): Promise<void> {
  for (const event of run.events) {
    if (event.type === "delta") {
      const text =
        event.data && typeof event.data === "object" && "text" in event.data
          ? String(event.data.text)
          : event.summary;
      await options.onDelta?.(text);
    }
    await options.onStep?.(event);
  }
}

function writeJson(filePath: string, value: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function readJson(filePath: string): any {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}
