import type {
  Node,
  WorkflowEdge,
  WorkflowProject,
  WorkflowValidationIssue,
} from "../types/graph";
import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import { workflowRuntimeEventId } from "./workflow-runtime-event-identity";

export const RUNTIME_WORKSPACE_TRUST_GATE_NODE_TYPE =
  "runtime_workspace_trust_gate" as const;

export type WorkflowWorkspaceTrustGateRequirementStatus =
  | "not_required"
  | "blocked"
  | "passed";

export interface WorkflowWorkspaceTrustGateRequirement {
  modeNodeId: string;
  gateNodeId: string | null;
  threadId: string | null;
  mode: string;
  approvalMode: string;
  warningWorkflowNodeId: string;
  warningId: string | null;
  warningEventId: string | null;
  acknowledgementEventId: string | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
  status: WorkflowWorkspaceTrustGateRequirementStatus;
  blockerCode: string | null;
  message: string;
}

export interface WorkflowWorkspaceTrustGateReadiness {
  status: WorkflowWorkspaceTrustGateRequirementStatus;
  requirements: WorkflowWorkspaceTrustGateRequirement[];
  issues: WorkflowValidationIssue[];
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function booleanValue(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringField(
  value: unknown,
  ...keys: string[]
): string | null {
  const record = objectValue(value);
  if (!record) return null;
  for (const key of keys) {
    const fieldValue = cleanString(record[key]);
    if (fieldValue) return fieldValue;
  }
  return null;
}

function stringList(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      values.filter((value): value is string => Boolean(value && value.trim())),
    ),
  );
}

function eventId(event: WorkflowRuntimeThreadEventLike): string {
  return workflowRuntimeEventId(event) ?? "";
}

function eventWorkflowNodeId(event: WorkflowRuntimeThreadEventLike): string | null {
  return (
    cleanString(event.workflowNodeId) ??
    stringField(event.payload, "workflowNodeId", "workflow_node_id")
  );
}

function workflowGraphId(workflow: WorkflowProject): string | null {
  return cleanString(workflow.metadata.id) ?? cleanString(workflow.metadata.slug);
}

function modeNodeIsRisky(node: Node): boolean {
  const logic = node.config?.logic ?? {};
  const mode = cleanString(logic.runtimeThreadModeMode) ?? "review";
  const requestWarning =
    booleanValue(logic.runtimeThreadModeRequestWarningAcknowledgement) ?? true;
  return requestWarning && (mode === "review" || mode === "yolo");
}

function modeNodeWarningWorkflowNodeId(node: Node): string {
  const logic = node.config?.logic ?? {};
  return (
    cleanString(logic.runtimeThreadModeWorkspaceTrustWorkflowNodeId) ??
    `${cleanString(logic.runtimeThreadModeWorkflowNodeId) ?? "runtime.thread-mode"}.workspace-trust`
  );
}

function gateMatchesModeNode(gate: Node, modeNode: Node, edges: readonly WorkflowEdge[]): boolean {
  const logic = gate.config?.logic ?? {};
  const warningWorkflowNodeId = modeNodeWarningWorkflowNodeId(modeNode);
  const configuredWarningWorkflowNodeId = cleanString(
    logic.runtimeWorkspaceTrustGateWarningWorkflowNodeId,
  );
  const configuredModeNodeId = cleanString(logic.runtimeWorkspaceTrustGateModeNodeId);
  if (configuredWarningWorkflowNodeId === warningWorkflowNodeId) return true;
  if (configuredModeNodeId === modeNode.id) return true;
  return edges.some((edge) => edge.from === modeNode.id && edge.to === gate.id);
}

function trustWarningEvent(
  events: readonly WorkflowRuntimeThreadEventLike[],
  workflowNodeId: string,
  graphId: string | null,
): WorkflowRuntimeThreadEventLike | null {
  return (
    [...events].reverse().find((event) => {
      const eventKindMatches =
        event.type === "workspace_trust_warning" ||
        event.eventKind === "workspace.trust_warning" ||
        event.sourceEventKind === "WorkspaceTrust.Warning";
      if (!eventKindMatches) return false;
      const eventNodeId = eventWorkflowNodeId(event);
      if (eventNodeId && eventNodeId !== workflowNodeId) return false;
      if (!eventNodeId && workflowNodeId !== "runtime.workspace-trust") return false;
      return !graphId || !event.workflowGraphId || event.workflowGraphId === graphId;
    }) ?? null
  );
}

function trustAcknowledgementEvent(
  events: readonly WorkflowRuntimeThreadEventLike[],
  warningEvent: WorkflowRuntimeThreadEventLike,
  warningId: string,
): WorkflowRuntimeThreadEventLike | null {
  const sourceEventId = eventId(warningEvent);
  return (
    [...events].reverse().find((event) => {
      const eventKindMatches =
        event.type === "workspace_trust_acknowledged" ||
        event.eventKind === "workspace.trust_acknowledged" ||
        event.sourceEventKind === "WorkspaceTrust.Acknowledged";
      if (!eventKindMatches) return false;
      return (
        stringField(event.payload, "warningId", "warning_id") === warningId ||
        stringField(event.payload, "sourceEventId", "source_event_id") ===
          sourceEventId
      );
    }) ?? null
  );
}

export function workflowWorkspaceTrustGateReadiness(
  workflow: WorkflowProject,
  events: readonly WorkflowRuntimeThreadEventLike[] = [],
): WorkflowWorkspaceTrustGateReadiness {
  const graphId = workflowGraphId(workflow);
  const gateNodes = workflow.nodes.filter(
    (node) => node.type === RUNTIME_WORKSPACE_TRUST_GATE_NODE_TYPE,
  );
  const requirements = workflow.nodes
    .filter((node) => node.type === "runtime_thread_mode")
    .filter(modeNodeIsRisky)
    .map((modeNode): WorkflowWorkspaceTrustGateRequirement => {
      const logic = modeNode.config?.logic ?? {};
      const gateNode =
        gateNodes.find((candidate) =>
          gateMatchesModeNode(candidate, modeNode, workflow.edges),
        ) ?? null;
      const warningWorkflowNodeId = modeNodeWarningWorkflowNodeId(modeNode);
      if (!gateNode) {
        return {
          modeNodeId: modeNode.id,
          gateNodeId: null,
          threadId: null,
          mode: cleanString(logic.runtimeThreadModeMode) ?? "review",
          approvalMode:
            cleanString(logic.runtimeThreadModeApprovalMode) ?? "human_required",
          warningWorkflowNodeId,
          warningId: null,
          warningEventId: null,
          acknowledgementEventId: null,
          receiptRefs: [],
          policyDecisionRefs: [],
          status: "blocked",
          blockerCode: "missing_workspace_trust_gate",
          message:
            "Risky runtime thread modes need a WorkspaceTrustGateNode wired to daemon workspace-trust receipts.",
        };
      }
      const warningEvent = trustWarningEvent(events, warningWorkflowNodeId, graphId);
      if (!warningEvent) {
        return {
          modeNodeId: modeNode.id,
          gateNodeId: gateNode.id,
          threadId: null,
          mode: cleanString(logic.runtimeThreadModeMode) ?? "review",
          approvalMode:
            cleanString(logic.runtimeThreadModeApprovalMode) ?? "human_required",
          warningWorkflowNodeId,
          warningId: null,
          warningEventId: null,
          acknowledgementEventId: null,
          receiptRefs: [],
          policyDecisionRefs: [],
          status: "blocked",
          blockerCode: "workspace_trust_warning_not_emitted",
          message:
            "Run the runtime mode preflight so the daemon emits a workspace trust warning before execution.",
        };
      }
      const warningId =
        stringField(warningEvent.payload, "warningId", "warning_id") ??
        eventId(warningEvent);
      const acknowledgementEvent =
        trustAcknowledgementEvent(events, warningEvent, warningId) ?? null;
      if (!acknowledgementEvent) {
        return {
          modeNodeId: modeNode.id,
          gateNodeId: gateNode.id,
          threadId: warningEvent.threadId,
          mode: cleanString(logic.runtimeThreadModeMode) ?? "review",
          approvalMode:
            cleanString(logic.runtimeThreadModeApprovalMode) ?? "human_required",
          warningWorkflowNodeId,
          warningId,
          warningEventId: eventId(warningEvent),
          acknowledgementEventId: null,
          receiptRefs: stringList(warningEvent.receiptRefs),
          policyDecisionRefs: stringList(warningEvent.policyDecisionRefs),
          status: "blocked",
          blockerCode: "workspace_trust_acknowledgement_missing",
          message:
            "Acknowledge the daemon workspace trust warning before running this risky workflow.",
        };
      }
      return {
        modeNodeId: modeNode.id,
        gateNodeId: gateNode.id,
        threadId: acknowledgementEvent.threadId || warningEvent.threadId,
        mode: cleanString(logic.runtimeThreadModeMode) ?? "review",
        approvalMode:
          cleanString(logic.runtimeThreadModeApprovalMode) ?? "human_required",
        warningWorkflowNodeId,
        warningId,
        warningEventId: eventId(warningEvent),
        acknowledgementEventId: eventId(acknowledgementEvent),
        receiptRefs: stringList([
          ...warningEvent.receiptRefs,
          ...acknowledgementEvent.receiptRefs,
        ]),
        policyDecisionRefs: stringList([
          ...warningEvent.policyDecisionRefs,
          ...acknowledgementEvent.policyDecisionRefs,
        ]),
        status: "passed",
        blockerCode: null,
        message: "Workspace trust acknowledgement is present in daemon history.",
      };
    });
  const issues = requirements
    .filter((requirement) => requirement.status === "blocked")
    .map((requirement): WorkflowValidationIssue => ({
      nodeId: requirement.gateNodeId ?? requirement.modeNodeId,
      code: requirement.blockerCode ?? "workspace_trust_gate_blocked",
      message: requirement.message,
      repairActionId:
        requirement.blockerCode === "missing_workspace_trust_gate"
          ? "add-workspace-trust-gate"
          : "open-runtime-run-inspector",
      repairLabel:
        requirement.blockerCode === "missing_workspace_trust_gate"
          ? "Add WorkspaceTrustGateNode"
          : "Review workspace trust",
      suggestedCreatorId:
        requirement.blockerCode === "missing_workspace_trust_gate"
          ? RUNTIME_WORKSPACE_TRUST_GATE_NODE_TYPE
          : undefined,
    }));
  const hasBlocked = issues.length > 0;
  return {
    status:
      requirements.length === 0
        ? "not_required"
        : hasBlocked
          ? "blocked"
          : "passed",
    requirements,
    issues,
  };
}

export function workflowWorkspaceTrustGateIssues(
  workflow: WorkflowProject,
  events: readonly WorkflowRuntimeThreadEventLike[] = [],
): WorkflowValidationIssue[] {
  return workflowWorkspaceTrustGateReadiness(workflow, events).issues;
}
