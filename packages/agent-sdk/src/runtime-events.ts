import type { IOISDKMessage, RuntimeEventEnvelope, RuntimeThreadEvent, RuntimeTurnRecord } from "./messages.js";
import type { RuntimeAgentRecord, RuntimeEventStreamOptions, RuntimeRunRecord } from "./substrate-client.js";
import { COMPUTER_USE_CONTRACT_SCHEMA_VERSION } from "./computer-use.js";

export function runtimeThreadEventFromEnvelope(event: RuntimeEventEnvelope): RuntimeThreadEvent {
  const payload = runtimeEventPayload(event);
  return {
    id: event.event_id,
    cursor: `${event.event_stream_id}:${event.seq}`,
    seq: event.seq,
    threadId: event.thread_id,
    turnId: event.turn_id || null,
    itemId: event.item_id || null,
    type: runtimeThreadEventTypeFromKind(event.event_kind),
    eventKind: event.event_kind,
    source: event.source,
    sourceEventKind: event.source_event_kind,
    status: event.status,
    actor: event.actor,
    createdAt: event.created_at,
    componentKind: event.component_kind,
    workflowNodeId: event.workflow_node_id,
    workflowGraphId: event.workflow_graph_id,
    toolCallId: event.tool_call_id,
    toolName: optionalString(payload.tool_name),
    approvalId: event.approval_id || optionalString(payload.approval_id),
    agentStatus: optionalString(payload.agent_status),
    stepIndex: optionalNumber(payload.step_index),
    payloadSchemaVersion: event.payload_schema_version,
    receiptRefs: event.receipt_refs,
    artifactRefs: event.artifact_refs,
    policyDecisionRefs: event.policy_decision_refs,
    rollbackRefs: event.rollback_refs,
    payload,
    envelope: event,
  };
}

export function turnIdForRun(runId: string): string {
  return runId.startsWith("run_") ? `turn_${runId.slice("run_".length)}` : `turn_${runId}`;
}

export function eventStreamIdForThread(threadId: string): string {
  return `events_${threadId}`;
}

export function runtimeTurnStatusForRun(status: RuntimeRunRecord["status"]): RuntimeTurnRecord["status"] {
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
      return "waiting_for_input";
    case "completed":
      return "completed";
  }
}

export function mockRuntimeCursorSeq(
  events: RuntimeEventEnvelope[],
  options: RuntimeEventStreamOptions,
): number {
  if (options.sinceSeq !== undefined) {
    return Number(options.sinceSeq) || 0;
  }
  if (!options.lastEventId) {
    return 0;
  }
  const match = events.find(
    (event) => event.event_id === options.lastEventId || (event as { id?: string }).id === options.lastEventId,
  );
  return match?.seq ?? 0;
}

export function mockRuntimeEnvelopeForSdkEvent({
  agent,
  event,
  run,
  seq,
  streamId,
  threadId,
  turnId,
}: {
  agent: RuntimeAgentRecord;
  event: IOISDKMessage;
  run: RuntimeRunRecord;
  seq: number;
  streamId: string;
  threadId: string;
  turnId: string;
}): RuntimeEventEnvelope {
  const eventKind = runtimeEventKindForSdkMessage(event.type);
  return mockRuntimeEventEnvelope({
    agent,
    threadId,
    streamId,
    seq,
    turnId,
    itemId: `${turnId}:item:${String(seq).padStart(4, "0")}`,
    eventKind,
    sourceEventKind: sourceEventKindForSdkMessage(event.type),
    status: runtimeEventStatusForSdkMessage(event.type),
    payloadSchemaVersion: payloadSchemaVersionForSdkMessage(event.type),
    payload: {
      ...(event.data && typeof event.data === "object" && !Array.isArray(event.data) ? event.data : {}),
      event_kind: event.type,
      agent_id: agent.id,
      run_id: run.id,
      turn_id: turnId,
      summary: event.summary,
      legacy_event_type: event.type,
    },
    createdAt: event.createdAt,
    componentKind: componentKindForSdkMessage(event.type),
    workflowNodeId: workflowNodeIdForSdkMessage(event.type),
    receiptRefs: run.receipts.map((receipt) => receipt.id),
  });
}

export function mockRuntimeEventEnvelope({
  agent,
  threadId,
  streamId,
  seq,
  eventKind,
  sourceEventKind,
  itemId,
  payload,
  createdAt,
  turnId = "",
  status = "completed",
  payloadSchemaVersion = "ioi.agent-sdk.thread-event.v1",
  componentKind = null,
  workflowNodeId = null,
  receiptRefs = [],
  artifactRefs = [],
  policyDecisionRefs = [],
  rollbackRefs = [],
}: {
  agent: RuntimeAgentRecord;
  threadId: string;
  streamId: string;
  seq: number;
  eventKind: string;
  sourceEventKind: string;
  itemId: string;
  payload: Record<string, unknown>;
  createdAt: string;
  turnId?: string;
  status?: string;
  payloadSchemaVersion?: string;
  componentKind?: string | null;
  workflowNodeId?: string | null;
  receiptRefs?: string[];
  artifactRefs?: string[];
  policyDecisionRefs?: string[];
  rollbackRefs?: string[];
}): RuntimeEventEnvelope {
  return {
    schema_version: "ioi.runtime.event.v1",
    event_id: `${streamId}:seq:${String(seq).padStart(8, "0")}`,
    event_stream_id: streamId,
    thread_id: threadId,
    turn_id: turnId,
    item_id: itemId,
    seq,
    parent_seq: seq > 1 ? seq - 1 : null,
    idempotency_key: `${sourceEventKind}:${itemId}`,
    source: "sdk_client",
    source_event_kind: sourceEventKind,
    event_kind: eventKind,
    status,
    actor: "runtime",
    created_at: createdAt,
    workspace_root: agent.cwd,
    workflow_graph_id: null,
    workflow_node_id: workflowNodeId,
    component_kind: componentKind,
    tool_call_id: null,
    approval_id: null,
    artifact_refs: artifactRefs,
    receipt_refs: receiptRefs,
    policy_decision_refs: policyDecisionRefs,
    rollback_refs: rollbackRefs,
    payload_schema_version: payloadSchemaVersion,
    payload_ref: null,
    payload: runtimePayloadStringRecord(payload),
    redaction_profile: "internal",
    fixture_profile: "agent_sdk_mock",
  };
}

function runtimeEventPayload(event: RuntimeEventEnvelope): Record<string, unknown> {
  const payloadSummary = (event as { payload_summary?: unknown }).payload_summary;
  if (payloadSummary && typeof payloadSummary === "object" && !Array.isArray(payloadSummary)) {
    return payloadSummary as Record<string, unknown>;
  }
  return event.payload ?? {};
}

function runtimeThreadEventTypeFromKind(kind: string): RuntimeThreadEvent["type"] {
  switch (kind) {
    case "thread.started":
      return "thread_started";
    case "thread.forked":
      return "thread_forked";
    case "turn.started":
      return "turn_started";
    case "turn.completed":
      return "turn_completed";
    case "turn.failed":
      return "turn_failed";
    case "turn.canceled":
      return "turn_canceled";
    case "turn.interrupted":
      return "turn_interrupted";
    case "turn.steered":
      return "turn_steered";
    case "context.compacted":
      return "context_compacted";
    case "context_budget.evaluated":
      return "context_budget_evaluated";
    case "compaction_policy.evaluated":
      return "compaction_policy_evaluated";
    case "usage.delta":
      return "usage_delta";
    case "context.pressure_delta":
      return "context_pressure_delta";
    case "context.pressure_alert":
      return "context_pressure_alert";
    case "workspace.trust_warning":
      return "workspace_trust_warning";
    case "workspace.trust_acknowledged":
      return "workspace_trust_acknowledged";
    case "workflow.edit_proposed":
      return "workflow_edit_proposed";
    case "workflow.edit_applied":
      return "workflow_edit_applied";
    case "reasoning.delta":
    case "item.delta":
      return "reasoning_delta";
    case "tool.completed":
      return "tool_completed";
    case "tool.failed":
      return "tool_failed";
    case "approval.required":
      return "approval_required";
    case "approval.approved":
    case "approval.rejected":
      return "approval_decision";
    case "policy.blocked":
      return "policy_blocked";
    case "receipt.emitted":
      return "receipt_emitted";
    case "model.route_decision":
      return "model_route_decision";
    case "tool.route_decision":
      return "tool_route_decision";
    default:
      return "runtime_step";
  }
}

function runtimePayloadStringRecord(payload: Record<string, unknown>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(payload).map(([key, value]) => [
      key,
      typeof value === "string" ? value : value === undefined ? "" : JSON.stringify(value),
    ]),
  );
}

function runtimeEventKindForSdkMessage(type: IOISDKMessage["type"]): string {
  switch (type) {
    case "thread_forked":
      return "thread.forked";
    case "run_started":
      return "turn.started";
    case "delta":
      return "reasoning.delta";
    case "tool_result":
      return "tool.completed";
    case "model_route_decision":
      return "model.route_decision";
    case "computer_use_environment_selected":
      return "computer_use.environment_selected";
    case "computer_use_run_state":
      return "computer_use.run_state";
    case "computer_use_observation":
      return "computer_use.observation";
    case "computer_use_affordance_graph":
      return "computer_use.affordance_graph";
    case "computer_use_action_proposed":
      return "computer_use.action_proposed";
    case "computer_use_verification":
      return "computer_use.verification";
    case "completed":
      return "turn.completed";
    case "canceled":
      return "turn.canceled";
    case "interrupted":
      return "turn.interrupted";
    case "steered":
      return "turn.steered";
    case "context_compacted":
      return "context.compacted";
    case "context_budget_evaluated":
      return "context_budget.evaluated";
    case "compaction_policy_evaluated":
      return "compaction_policy.evaluated";
    case "usage_delta":
      return "usage.delta";
    case "context_pressure_delta":
      return "context.pressure_delta";
    case "context_pressure_alert":
      return "context.pressure_alert";
    case "workspace_trust_warning":
      return "workspace.trust_warning";
    case "workspace_trust_acknowledged":
      return "workspace.trust_acknowledged";
    case "workflow_edit_proposed":
      return "workflow.edit_proposed";
    case "workflow_edit_applied":
      return "workflow.edit_applied";
    case "error":
      return "turn.failed";
    default:
      return "runtime.step";
  }
}

function runtimeEventStatusForSdkMessage(type: IOISDKMessage["type"]): string {
  if (
    type === "run_started" ||
    type === "delta" ||
    type === "computer_use_environment_selected" ||
    type === "computer_use_run_state" ||
    type === "computer_use_observation" ||
    type === "computer_use_affordance_graph" ||
    type === "computer_use_action_proposed" ||
    type === "usage_delta" ||
    type === "context_pressure_delta" ||
    type === "context_pressure_alert"
  ) return "running";
  if (type === "workspace_trust_warning") return "warning";
  if (type === "workspace_trust_acknowledged") return "completed";
  if (type === "workflow_edit_proposed") return "waiting_for_approval";
  if (type === "workflow_edit_applied") return "completed";
  if (type === "canceled") return "canceled";
  if (type === "interrupted") return "interrupted";
  if (type === "error") return "failed";
  return "completed";
}

function componentKindForSdkMessage(type: IOISDKMessage["type"]): string {
  if (type === "thread_forked") return "thread_fork";
  if (type === "interrupted" || type === "steered") return "operator_control";
  if (type === "context_compacted") return "context_compaction";
  if (type === "context_budget_evaluated") return "context_budget";
  if (type === "compaction_policy_evaluated") return "compaction_policy";
  if (type === "usage_delta") return "usage_telemetry";
  if (type === "context_pressure_delta") return "context_pressure";
  if (type === "context_pressure_alert") return "context_pressure_alert";
  if (type === "workspace_trust_warning" || type === "workspace_trust_acknowledged") return "workspace_trust";
  if (type === "workflow_edit_proposed" || type === "workflow_edit_applied") return "workflow_edit_proposal";
  if (type === "approval_required" || type === "approval_decision") return "approval_gate";
  if (type === "model_route_decision") return "model_router";
  if (type.startsWith("computer_use_")) return "computer_use_harness";
  if (type === "tool_result") return "tool_result";
  if (type === "delta") return "reasoning_delta";
  return type;
}

function workflowNodeIdForSdkMessage(type: IOISDKMessage["type"]): string {
  if (type === "thread_forked") return "runtime.thread-fork";
  if (type === "interrupted") return "runtime.operator-interrupt";
  if (type === "steered") return "runtime.operator-steer";
  if (type === "context_compacted") return "runtime.context-compact";
  if (type === "context_budget_evaluated") return "runtime.context-budget";
  if (type === "compaction_policy_evaluated") return "runtime.compaction-policy";
  if (type === "usage_delta") return "runtime.usage-telemetry";
  if (type === "context_pressure_delta") return "runtime.context-budget";
  if (type === "context_pressure_alert") return "runtime.context-pressure-alert";
  if (type === "workspace_trust_warning" || type === "workspace_trust_acknowledged") return "runtime.workspace-trust";
  if (type === "workflow_edit_proposed" || type === "workflow_edit_applied") return "runtime.workflow-edit-proposal";
  if (type === "approval_decision") return "runtime.approval-decision";
  if (type === "model_route_decision") return "runtime.model-router";
  if (type === "computer_use_environment_selected") return "computer-use.select-environment";
  if (type === "computer_use_run_state") return "computer-use.run-state";
  if (type === "computer_use_observation") return "computer-use.observe";
  if (type === "computer_use_affordance_graph") return "computer-use.affordance-graph";
  if (type === "computer_use_action_proposed") return "computer-use.action-proposal";
  if (type === "computer_use_verification") return "computer-use.verify";
  if (type === "tool_result") return "runtime.tool-result";
  if (type === "delta") return "runtime.reasoning";
  return `runtime.${type.replaceAll("_", "-")}`;
}

function sourceEventKindForSdkMessage(type: IOISDKMessage["type"]): string {
  if (type === "thread_forked") return "OperatorControl.Fork";
  if (type === "interrupted") return "OperatorControl.Interrupt";
  if (type === "steered") return "OperatorControl.Steer";
  if (type === "context_compacted") return "OperatorControl.Compact";
  if (type === "context_budget_evaluated") return "RuntimeContextBudget.Evaluate";
  if (type === "compaction_policy_evaluated") return "RuntimeCompactionPolicy.Evaluate";
  if (type === "usage_delta") return "RuntimeUsageTelemetry.Delta";
  if (type === "context_pressure_delta") return "RuntimeContextPressure.Delta";
  if (type === "context_pressure_alert") return "RuntimeContextPressure.Alert";
  if (type === "workspace_trust_warning") return "WorkspaceTrust.Warning";
  if (type === "workspace_trust_acknowledged") return "WorkspaceTrust.Acknowledged";
  if (type === "workflow_edit_proposed") return "WorkflowEdit.Proposed";
  if (type === "workflow_edit_applied") return "WorkflowEdit.Applied";
  if (type === "approval_decision") return "OperatorApproval.Decision";
  if (type === "computer_use_environment_selected") return "ComputerUse.EnvironmentSelected";
  if (type === "computer_use_run_state") return "ComputerUse.RunState";
  if (type === "computer_use_observation") return "ComputerUse.Observation";
  if (type === "computer_use_affordance_graph") return "ComputerUse.AffordanceGraph";
  if (type === "computer_use_action_proposed") return "ComputerUse.ActionProposed";
  if (type === "computer_use_verification") return "ComputerUse.Verification";
  return `run.${type}`;
}

function payloadSchemaVersionForSdkMessage(type: IOISDKMessage["type"]): string {
  if (type === "thread_forked") return "ioi.runtime.thread-fork.v1";
  if (type === "interrupted" || type === "steered") return "ioi.runtime.operator-control.v1";
  if (type === "context_compacted") return "ioi.runtime.context-compaction.v1";
  if (type === "context_budget_evaluated") return "ioi.runtime.context-budget-policy.v1";
  if (type === "compaction_policy_evaluated") return "ioi.runtime.compaction-policy.v1";
  if (type === "usage_delta") return "ioi.runtime.usage-delta.v1";
  if (type === "context_pressure_delta") return "ioi.runtime.context-pressure-delta.v1";
  if (type === "context_pressure_alert") return "ioi.runtime.context-pressure-alert.v1";
  if (type === "workspace_trust_warning") return "ioi.runtime.workspace-trust-warning.v1";
  if (type === "workspace_trust_acknowledged") return "ioi.runtime.workspace-trust-acknowledgement.v1";
  if (type === "workflow_edit_proposed") return "ioi.runtime.workflow-edit-proposal.v1";
  if (type === "workflow_edit_applied") return "ioi.runtime.workflow-edit-apply.v1";
  if (type === "approval_decision") return "ioi.runtime.approval-decision.v1";
  if (type.startsWith("computer_use_")) return COMPUTER_USE_CONTRACT_SCHEMA_VERSION;
  return "ioi.agent-sdk.event.v1";
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function optionalNumber(value: unknown): number | null {
  const number = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  return Number.isFinite(number) ? number : null;
}
