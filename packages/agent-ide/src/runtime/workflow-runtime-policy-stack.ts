import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";

export const WORKFLOW_RUNTIME_POLICY_STACK_SCHEMA_VERSION =
  "ioi.workflow.runtime-policy-stack.v1" as const;

export type WorkflowRuntimePolicyStackStageKind =
  | "workspace_trust_warning"
  | "workspace_trust_acknowledgement"
  | "approval_requirement"
  | "approval_decision"
  | "approved_retry";

export type WorkflowRuntimePolicyStackStatus =
  | "not_required"
  | "waiting"
  | "blocked"
  | "completed";

export interface WorkflowRuntimePolicyStackStage {
  kind: WorkflowRuntimePolicyStackStageKind;
  status: WorkflowRuntimePolicyStackStatus;
  label: string;
  eventId: string | null;
  eventSeq: number | null;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  threadId: string | null;
  approvalId: string | null;
  warningId: string | null;
  toolCallId: string | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
}

export interface WorkflowRuntimePolicyStack {
  schemaVersion: typeof WORKFLOW_RUNTIME_POLICY_STACK_SCHEMA_VERSION;
  status: WorkflowRuntimePolicyStackStatus;
  threadIds: string[];
  workflowGraphIds: string[];
  eventIds: string[];
  workflowNodeIds: string[];
  approvalId: string | null;
  warningId: string | null;
  toolCallId: string | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
  stages: WorkflowRuntimePolicyStackStage[];
}

export interface WorkflowRuntimePolicyStackOptions {
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
}

export function workflowRuntimePolicyStackFromEvents(
  events: readonly WorkflowRuntimeThreadEventLike[],
  options: WorkflowRuntimePolicyStackOptions = {},
): WorkflowRuntimePolicyStack {
  const graphId = cleanString(options.workflowGraphId);
  const nodeId = cleanString(options.workflowNodeId);
  const sortedEvents = [...events]
    .filter((event) => (!graphId || !event.workflowGraphId || event.workflowGraphId === graphId))
    .filter((event) => (!nodeId || !event.workflowNodeId || event.workflowNodeId === nodeId))
    .sort((a, b) => a.seq - b.seq);

  const warningEvent = latestEvent(sortedEvents, isWorkspaceTrustWarning);
  const warningId = warningEvent ? warningIdForEvent(warningEvent) : null;
  const acknowledgementEvent = warningEvent
    ? latestEvent(sortedEvents, (event) =>
        isWorkspaceTrustAcknowledgement(event, warningEvent, warningId),
      )
    : null;
  const approvalRequirementEvent = latestEvent(sortedEvents, (event) =>
    isApprovalRequirement(event, acknowledgementEvent?.seq ?? warningEvent?.seq ?? 0),
  );
  const approvalId =
    stringField(approvalRequirementEvent, "approvalId", "approval_id") ??
    stringField(approvalRequirementEvent?.payload, "approvalId", "approval_id");
  const approvalDecisionEvent = approvalRequirementEvent
    ? latestEvent(sortedEvents, (event) =>
        isApprovalDecision(event, approvalRequirementEvent, approvalId),
      )
    : null;
  const approved = approvalDecisionEvent
    ? approvalDecisionEvent.eventKind === "approval.approved" ||
      approvalDecisionEvent.status.toLowerCase().includes("approved") ||
      stringField(approvalDecisionEvent.payload, "decision") === "approve"
    : false;
  const approvedRetryEvent = approved
    ? latestEvent(sortedEvents, (event) =>
        isApprovedRetry(event, approvalId, approvalDecisionEvent),
      )
    : null;

  const stages = [
    stageForEvent({
      kind: "workspace_trust_warning",
      label: "Workspace trust warning",
      event: warningEvent,
      fallbackStatus: warningEvent ? "completed" : "not_required",
      warningId,
      approvalId: null,
    }),
    stageForEvent({
      kind: "workspace_trust_acknowledgement",
      label: "Workspace trust acknowledgement",
      event: acknowledgementEvent,
      fallbackStatus: warningEvent ? "waiting" : "not_required",
      warningId,
      approvalId: null,
    }),
    stageForEvent({
      kind: "approval_requirement",
      label: "Approval requirement",
      event: approvalRequirementEvent,
      fallbackStatus: acknowledgementEvent ? "waiting" : "not_required",
      warningId,
      approvalId,
    }),
    stageForEvent({
      kind: "approval_decision",
      label: approvalDecisionEvent?.status.toLowerCase().includes("rejected")
        ? "Approval rejected"
        : "Approval decision",
      event: approvalDecisionEvent,
      fallbackStatus: approvalRequirementEvent ? "waiting" : "not_required",
      warningId,
      approvalId,
      statusOverride: approvalDecisionEvent
        ? approved
          ? "completed"
          : "blocked"
        : undefined,
    }),
    stageForEvent({
      kind: "approved_retry",
      label: "Approved retry",
      event: approvedRetryEvent,
      fallbackStatus: approved ? "waiting" : approvalDecisionEvent ? "blocked" : "not_required",
      warningId,
      approvalId,
      statusOverride: approvedRetryEvent ? "completed" : undefined,
    }),
  ] satisfies WorkflowRuntimePolicyStackStage[];

  const activeStages = stages.filter((stage) => stage.status !== "not_required");
  const status = stackStatus(activeStages);

  return {
    schemaVersion: WORKFLOW_RUNTIME_POLICY_STACK_SCHEMA_VERSION,
    status,
    threadIds: uniqueStrings(activeStages.map((stage) => stage.threadId)),
    workflowGraphIds: uniqueStrings(activeStages.map((stage) => stage.workflowGraphId)),
    eventIds: uniqueStrings(activeStages.map((stage) => stage.eventId)),
    workflowNodeIds: uniqueStrings(activeStages.map((stage) => stage.workflowNodeId)),
    approvalId,
    warningId,
    toolCallId: approvedRetryEvent?.toolCallId ?? null,
    receiptRefs: uniqueStrings(activeStages.flatMap((stage) => stage.receiptRefs)),
    policyDecisionRefs: uniqueStrings(
      activeStages.flatMap((stage) => stage.policyDecisionRefs),
    ),
    stages,
  };
}

function stageForEvent({
  kind,
  label,
  event,
  fallbackStatus,
  warningId,
  approvalId,
  statusOverride,
}: {
  kind: WorkflowRuntimePolicyStackStageKind;
  label: string;
  event: WorkflowRuntimeThreadEventLike | null;
  fallbackStatus: WorkflowRuntimePolicyStackStatus;
  warningId: string | null;
  approvalId: string | null;
  statusOverride?: WorkflowRuntimePolicyStackStatus;
}): WorkflowRuntimePolicyStackStage {
  return {
    kind,
    status: statusOverride ?? (event ? "completed" : fallbackStatus),
    label,
    eventId: event?.id ?? null,
    eventSeq: event?.seq ?? null,
    workflowGraphId: event?.workflowGraphId ?? null,
    workflowNodeId: event?.workflowNodeId ?? null,
    threadId: event?.threadId ?? null,
    approvalId:
      approvalId ??
      stringField(event, "approvalId", "approval_id") ??
      stringField(event?.payload, "approvalId", "approval_id"),
    warningId,
    toolCallId: event?.toolCallId ?? null,
    receiptRefs: event?.receiptRefs ?? [],
    policyDecisionRefs: event?.policyDecisionRefs ?? [],
  };
}

function isWorkspaceTrustWarning(event: WorkflowRuntimeThreadEventLike): boolean {
  return (
    event.type === "workspace_trust_warning" ||
    event.eventKind === "workspace.trust_warning" ||
    event.sourceEventKind === "WorkspaceTrust.Warning"
  );
}

function isWorkspaceTrustAcknowledgement(
  event: WorkflowRuntimeThreadEventLike,
  warningEvent: WorkflowRuntimeThreadEventLike,
  warningId: string | null,
): boolean {
  if (
    event.type !== "workspace_trust_acknowledged" &&
    event.eventKind !== "workspace.trust_acknowledged" &&
    event.sourceEventKind !== "WorkspaceTrust.Acknowledged"
  ) {
    return false;
  }
  return (
    stringField(event.payload, "warningId", "warning_id") === warningId ||
    stringField(event.payload, "sourceEventId", "source_event_id") === warningEvent.id
  );
}

function isApprovalRequirement(
  event: WorkflowRuntimeThreadEventLike,
  afterSeq: number,
): boolean {
  return (
    event.seq > afterSeq &&
    (event.type === "approval_required" || event.eventKind === "approval.required")
  );
}

function isApprovalDecision(
  event: WorkflowRuntimeThreadEventLike,
  requestEvent: WorkflowRuntimeThreadEventLike,
  approvalId: string | null,
): boolean {
  if (
    event.seq <= requestEvent.seq ||
    (event.type !== "approval_decision" &&
      event.eventKind !== "approval.approved" &&
      event.eventKind !== "approval.rejected")
  ) {
    return false;
  }
  const eventApprovalId =
    stringField(event, "approvalId", "approval_id") ??
    stringField(event.payload, "approvalId", "approval_id");
  return !approvalId || eventApprovalId === approvalId;
}

function isApprovedRetry(
  event: WorkflowRuntimeThreadEventLike,
  approvalId: string | null,
  decisionEvent: WorkflowRuntimeThreadEventLike | null,
): boolean {
  if (
    !decisionEvent ||
    event.seq <= decisionEvent.seq ||
    (event.type !== "tool_completed" &&
      event.eventKind !== "workflow.run.retry_completed" &&
      event.sourceEventKind !== "WorkflowRunCodingToolBudgetApprovedRetry")
  ) {
    return false;
  }
  const retryKind =
    event.eventKind === "workflow.run.retry_completed" ||
    event.sourceEventKind === "WorkflowRunCodingToolBudgetApprovedRetry";
  const payloadApprovalId = stringField(event.payload, "approvalId", "approval_id");
  const decisionEventId = stringField(
    event.payload,
    "approvalDecisionEventId",
    "approval_decision_event_id",
  );
  const approvalSatisfied =
    booleanField(event.payload, "approvalSatisfied", "approval_satisfied") ??
    retryKind;
  return (
    approvalSatisfied &&
    (!approvalId || payloadApprovalId === approvalId) &&
    (!decisionEventId || decisionEventId === decisionEvent.id)
  );
}

function latestEvent(
  events: readonly WorkflowRuntimeThreadEventLike[],
  predicate: (event: WorkflowRuntimeThreadEventLike) => boolean,
): WorkflowRuntimeThreadEventLike | null {
  return [...events].reverse().find(predicate) ?? null;
}

function stackStatus(
  stages: readonly WorkflowRuntimePolicyStackStage[],
): WorkflowRuntimePolicyStackStatus {
  if (stages.length === 0) return "not_required";
  if (stages.some((stage) => stage.status === "blocked")) return "blocked";
  if (stages.some((stage) => stage.status === "waiting")) return "waiting";
  return "completed";
}

function warningIdForEvent(event: WorkflowRuntimeThreadEventLike): string {
  return stringField(event.payload, "warningId", "warning_id") ?? event.id;
}

function stringField(value: unknown, ...keys: string[]): string | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  for (const key of keys) {
    const field = record[key];
    if (typeof field === "string" && field.trim()) return field.trim();
  }
  return null;
}

function booleanField(value: unknown, ...keys: string[]): boolean | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  for (const key of keys) {
    const field = record[key];
    if (typeof field === "boolean") return field;
  }
  return null;
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(values.filter((value): value is string => Boolean(value && value.trim()))),
  );
}
