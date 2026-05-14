import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";

export const WORKFLOW_RUNTIME_EDIT_PROPOSAL_POLICY_SCHEMA_VERSION =
  "ioi.workflow.runtime-edit-proposal-policy.v1" as const;

export type WorkflowRuntimeEditProposalStageKind =
  | "proposal_created"
  | "approval_requirement"
  | "approval_decision"
  | "proposal_apply";

export type WorkflowRuntimeEditProposalStatus =
  | "not_required"
  | "waiting"
  | "blocked"
  | "completed";

export interface WorkflowRuntimeEditProposalStage {
  kind: WorkflowRuntimeEditProposalStageKind;
  status: WorkflowRuntimeEditProposalStatus;
  label: string;
  eventId: string | null;
  eventSeq: number | null;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  threadId: string | null;
  proposalId: string | null;
  approvalId: string | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
}

export interface WorkflowRuntimeEditProposalPolicyStack {
  schemaVersion: typeof WORKFLOW_RUNTIME_EDIT_PROPOSAL_POLICY_SCHEMA_VERSION;
  status: WorkflowRuntimeEditProposalStatus;
  threadIds: string[];
  workflowGraphIds: string[];
  workflowNodeIds: string[];
  eventIds: string[];
  proposalId: string | null;
  approvalId: string | null;
  targetWorkflowNodeIds: string[];
  mutationExecuted: boolean;
  receiptRefs: string[];
  policyDecisionRefs: string[];
  stages: WorkflowRuntimeEditProposalStage[];
}

export interface WorkflowRuntimeEditProposalPolicyOptions {
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  proposalId?: string | null;
}

export function workflowRuntimeEditProposalPolicyStackFromEvents(
  events: readonly WorkflowRuntimeThreadEventLike[],
  options: WorkflowRuntimeEditProposalPolicyOptions = {},
): WorkflowRuntimeEditProposalPolicyStack {
  const graphId = cleanString(options.workflowGraphId);
  const nodeId = cleanString(options.workflowNodeId);
  const requestedProposalId = cleanString(options.proposalId);
  const sortedEvents = [...events]
    .filter((event) => (!graphId || !event.workflowGraphId || event.workflowGraphId === graphId))
    .filter((event) => (!nodeId || !event.workflowNodeId || event.workflowNodeId === nodeId))
    .sort((a, b) => a.seq - b.seq);
  const proposalEvent = latestEvent(sortedEvents, (event) => {
    if (!isWorkflowEditProposalEvent(event)) return false;
    return !requestedProposalId || proposalIdForEvent(event) === requestedProposalId;
  });
  const proposalId = proposalEvent ? proposalIdForEvent(proposalEvent) : requestedProposalId;
  const approvalId =
    stringField(proposalEvent, "approvalId", "approval_id") ??
    stringField(proposalEvent?.payload, "approvalId", "approval_id");
  const approvalRequirementEvent = proposalEvent
    ? latestEvent(sortedEvents, (event) =>
        isApprovalRequirement(event, proposalEvent, approvalId),
      )
    : null;
  const effectiveApprovalId =
    approvalId ??
    stringField(approvalRequirementEvent, "approvalId", "approval_id") ??
    stringField(approvalRequirementEvent?.payload, "approvalId", "approval_id");
  const approvalDecisionEvent = approvalRequirementEvent
    ? latestEvent(sortedEvents, (event) =>
        isApprovalDecision(event, approvalRequirementEvent, effectiveApprovalId),
      )
    : null;
  const approved = approvalDecisionEvent
    ? approvalDecisionEvent.eventKind === "approval.approved" ||
      approvalDecisionEvent.status.toLowerCase().includes("approved") ||
      stringField(approvalDecisionEvent.payload, "decision") === "approve"
    : false;
  const applyEvent =
    proposalEvent && approved
      ? latestEvent(sortedEvents, (event) =>
          isWorkflowEditApplyEvent(event, proposalEvent, proposalId, approvalDecisionEvent),
        )
      : null;
  const mutationExecuted =
    booleanField(applyEvent?.payload, "mutationExecuted", "mutation_executed") ?? false;
  const targetWorkflowNodeIds = uniqueStrings(
    [
      ...stringArrayField(proposalEvent?.payload, "targetWorkflowNodeIds", "target_workflow_node_ids"),
      ...stringArrayField(proposalEvent?.payload, "boundedTargets", "bounded_targets"),
    ],
  );

  const stages = [
    stageForEvent({
      kind: "proposal_created",
      label: "Workflow edit proposed",
      event: proposalEvent,
      fallbackStatus: proposalEvent ? "completed" : "not_required",
      proposalId,
      approvalId: effectiveApprovalId,
    }),
    stageForEvent({
      kind: "approval_requirement",
      label: "Proposal approval required",
      event: approvalRequirementEvent,
      fallbackStatus: proposalEvent ? "waiting" : "not_required",
      proposalId,
      approvalId: effectiveApprovalId,
    }),
    stageForEvent({
      kind: "approval_decision",
      label: approvalDecisionEvent?.status.toLowerCase().includes("rejected")
        ? "Proposal rejected"
        : "Proposal approval decision",
      event: approvalDecisionEvent,
      fallbackStatus: approvalRequirementEvent ? "waiting" : "not_required",
      proposalId,
      approvalId: effectiveApprovalId,
      statusOverride: approvalDecisionEvent
        ? approved
          ? "completed"
          : "blocked"
        : undefined,
    }),
    stageForEvent({
      kind: "proposal_apply",
      label: "Approved workflow edit apply",
      event: applyEvent,
      fallbackStatus: approved ? "waiting" : approvalDecisionEvent ? "blocked" : "not_required",
      proposalId,
      approvalId: effectiveApprovalId,
      statusOverride: applyEvent ? "completed" : undefined,
    }),
  ] satisfies WorkflowRuntimeEditProposalStage[];
  const activeStages = stages.filter((stage) => stage.status !== "not_required");

  return {
    schemaVersion: WORKFLOW_RUNTIME_EDIT_PROPOSAL_POLICY_SCHEMA_VERSION,
    status: stackStatus(activeStages),
    threadIds: uniqueStrings(activeStages.map((stage) => stage.threadId)),
    workflowGraphIds: uniqueStrings(activeStages.map((stage) => stage.workflowGraphId)),
    workflowNodeIds: uniqueStrings(activeStages.map((stage) => stage.workflowNodeId)),
    eventIds: uniqueStrings(activeStages.map((stage) => stage.eventId)),
    proposalId,
    approvalId: effectiveApprovalId,
    targetWorkflowNodeIds,
    mutationExecuted,
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
  proposalId,
  approvalId,
  statusOverride,
}: {
  kind: WorkflowRuntimeEditProposalStageKind;
  label: string;
  event: WorkflowRuntimeThreadEventLike | null;
  fallbackStatus: WorkflowRuntimeEditProposalStatus;
  proposalId: string | null;
  approvalId: string | null;
  statusOverride?: WorkflowRuntimeEditProposalStatus;
}): WorkflowRuntimeEditProposalStage {
  return {
    kind,
    status: statusOverride ?? (event ? "completed" : fallbackStatus),
    label,
    eventId: event?.id ?? null,
    eventSeq: event?.seq ?? null,
    workflowGraphId: event?.workflowGraphId ?? null,
    workflowNodeId: event?.workflowNodeId ?? null,
    threadId: event?.threadId ?? null,
    proposalId: proposalId ?? proposalIdForEvent(event),
    approvalId:
      approvalId ??
      stringField(event, "approvalId", "approval_id") ??
      stringField(event?.payload, "approvalId", "approval_id"),
    receiptRefs: event?.receiptRefs ?? [],
    policyDecisionRefs: event?.policyDecisionRefs ?? [],
  };
}

function isWorkflowEditProposalEvent(event: WorkflowRuntimeThreadEventLike): boolean {
  return (
    event.type === "workflow_edit_proposed" ||
    event.eventKind === "workflow.edit_proposed" ||
    event.sourceEventKind === "WorkflowEdit.Proposed"
  );
}

function isWorkflowEditApplyEvent(
  event: WorkflowRuntimeThreadEventLike,
  proposalEvent: WorkflowRuntimeThreadEventLike,
  proposalId: string | null,
  approvalDecisionEvent: WorkflowRuntimeThreadEventLike | null,
): boolean {
  if (!approvalDecisionEvent || event.seq <= approvalDecisionEvent.seq) return false;
  if (
    event.type !== "workflow_edit_applied" &&
    event.eventKind !== "workflow.edit_applied" &&
    event.sourceEventKind !== "WorkflowEdit.Applied"
  ) {
    return false;
  }
  const eventProposalId = proposalIdForEvent(event);
  const sourceEventId = stringField(event.payload, "proposalEventId", "proposal_event_id");
  return (
    (!proposalId || eventProposalId === proposalId) &&
    (!sourceEventId || sourceEventId === proposalEvent.id)
  );
}

function isApprovalRequirement(
  event: WorkflowRuntimeThreadEventLike,
  proposalEvent: WorkflowRuntimeThreadEventLike,
  approvalId: string | null,
): boolean {
  if (
    event.seq <= proposalEvent.seq ||
    (event.type !== "approval_required" && event.eventKind !== "approval.required")
  ) {
    return false;
  }
  const eventApprovalId =
    stringField(event, "approvalId", "approval_id") ??
    stringField(event.payload, "approvalId", "approval_id");
  return !approvalId || eventApprovalId === approvalId;
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

function latestEvent(
  events: readonly WorkflowRuntimeThreadEventLike[],
  predicate: (event: WorkflowRuntimeThreadEventLike) => boolean,
): WorkflowRuntimeThreadEventLike | null {
  return [...events].reverse().find(predicate) ?? null;
}

function stackStatus(
  stages: readonly WorkflowRuntimeEditProposalStage[],
): WorkflowRuntimeEditProposalStatus {
  if (stages.length === 0) return "not_required";
  if (stages.some((stage) => stage.status === "blocked")) return "blocked";
  if (stages.some((stage) => stage.status === "waiting")) return "waiting";
  return "completed";
}

function proposalIdForEvent(event: WorkflowRuntimeThreadEventLike | null | undefined): string | null {
  return (
    stringField(event, "proposalId", "proposal_id") ??
    stringField(event?.payload, "proposalId", "proposal_id")
  );
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

function stringArrayField(value: unknown, ...keys: string[]): string[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  const record = value as Record<string, unknown>;
  for (const key of keys) {
    const field = record[key];
    if (!Array.isArray(field)) continue;
    return field.filter(
      (item): item is string => typeof item === "string" && item.trim().length > 0,
    );
  }
  return [];
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(values.filter((value): value is string => Boolean(value && value.trim()))),
  );
}
