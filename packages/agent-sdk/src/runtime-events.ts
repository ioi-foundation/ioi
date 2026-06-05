import type { RuntimeEventEnvelope, RuntimeThreadEvent } from "./messages.js";

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

function runtimeEventPayload(event: RuntimeEventEnvelope): Record<string, unknown> {
  const payloadSummary = (event as { payload_summary?: unknown }).payload_summary;
  if (payloadSummary && typeof payloadSummary === "object" && !Array.isArray(payloadSummary)) {
    return payloadSummary as Record<string, unknown>;
  }
  return event.payload ?? {};
}

function runtimeThreadEventTypeFromKind(kind: string): RuntimeThreadEvent["type"] {
  if (kind.startsWith("computer_use.")) {
    return kind.replace(/\./g, "_") as RuntimeThreadEvent["type"];
  }
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
    case "answer.delta":
      return "answer_delta";
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

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function optionalNumber(value: unknown): number | null {
  const number = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  return Number.isFinite(number) ? number : null;
}
