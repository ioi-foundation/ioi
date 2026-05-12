import type { IOISDKMessage, RuntimeEventEnvelope, RuntimeThreadEvent, RuntimeTurnRecord } from "./messages.js";
import type { RuntimeAgentRecord, RuntimeEventStreamOptions, RuntimeRunRecord } from "./substrate-client.js";

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
    sourceEventKind: `run.${event.type}`,
    status: runtimeEventStatusForSdkMessage(event.type),
    payloadSchemaVersion: "ioi.agent-sdk.event.v1",
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
    artifact_refs: [],
    receipt_refs: receiptRefs,
    policy_decision_refs: [],
    rollback_refs: [],
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
    case "turn.started":
      return "turn_started";
    case "turn.completed":
      return "turn_completed";
    case "turn.failed":
      return "turn_failed";
    case "turn.canceled":
      return "turn_canceled";
    case "reasoning.delta":
    case "item.delta":
      return "reasoning_delta";
    case "tool.completed":
      return "tool_completed";
    case "tool.failed":
      return "tool_failed";
    case "approval.required":
      return "approval_required";
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
    case "run_started":
      return "turn.started";
    case "delta":
      return "reasoning.delta";
    case "tool_result":
      return "tool.completed";
    case "model_route_decision":
      return "model.route_decision";
    case "completed":
      return "turn.completed";
    case "canceled":
      return "turn.canceled";
    case "error":
      return "turn.failed";
    default:
      return "runtime.step";
  }
}

function runtimeEventStatusForSdkMessage(type: IOISDKMessage["type"]): string {
  if (type === "run_started" || type === "delta") return "running";
  if (type === "canceled") return "canceled";
  if (type === "error") return "failed";
  return "completed";
}

function componentKindForSdkMessage(type: IOISDKMessage["type"]): string {
  if (type === "model_route_decision") return "model_router";
  if (type === "tool_result") return "tool_result";
  if (type === "delta") return "reasoning_delta";
  return type;
}

function workflowNodeIdForSdkMessage(type: IOISDKMessage["type"]): string {
  if (type === "model_route_decision") return "runtime.model-router";
  if (type === "tool_result") return "runtime.tool-result";
  if (type === "delta") return "runtime.reasoning";
  return `runtime.${type.replaceAll("_", "-")}`;
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function optionalNumber(value: unknown): number | null {
  const number = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  return Number.isFinite(number) ? number : null;
}
