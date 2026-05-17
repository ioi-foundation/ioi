import type { WorkflowProject } from "../types/graph";
import type { WorkflowCapabilityRepairAction } from "./workflow-run-capability-receipts";

export const WORKFLOW_CAPABILITY_GRANT_REQUEST_SCHEMA_VERSION =
  "ioi.workflow.capability-grant-request.v1";
export const WORKFLOW_CAPABILITY_GRANT_REQUEST_RESULT_SCHEMA_VERSION =
  "ioi.workflow.capability-grant-request-result.v1";

export type WorkflowCapabilityGrantRequest = {
  schemaVersion: typeof WORKFLOW_CAPABILITY_GRANT_REQUEST_SCHEMA_VERSION;
  sourceKind: "workflow_capability_repair_action";
  requestId: string;
  createdAtMs: number;
  workflowGraphId: string;
  workflowName: string;
  workflowNodeId: string;
  nodeName: string;
  bindingKind: WorkflowCapabilityRepairAction["bindingKind"];
  capabilityRef: string;
  routeId: string | null;
  authorityEndpoint: "/api/v1/authority";
  authorityScopes: string[];
  policyTarget: {
    kind:
      | "model_capability"
      | "tool_capability"
      | "connector_capability"
      | "workflow_tool_capability";
    ref: string;
    routeId: string | null;
  };
  receiptBehavior: {
    receiptRequired: true;
    requiredReceiptTypes: [
      "authority_grant_request",
      "policy_decision",
      "capability_grant_receipt",
    ];
  };
  readiness: {
    credential: string;
    grant: string;
    policy: string;
  };
  riskClass: string | null;
  sideEffectClass: string;
  requiresApproval: boolean;
  missingFields: string[];
  blockerReasons: string[];
  failClosedUntil: "grant_readiness_ready_and_policy_allowed";
  redaction: {
    containsSecretMaterial: false;
    credentialValuesIncluded: false;
  };
};

export type WorkflowCapabilityGrantRequestResultStatus =
  | "drafted"
  | "blocked"
  | "approved"
  | "denied";

export type WorkflowCapabilityGrantRequestResult = {
  schemaVersion: typeof WORKFLOW_CAPABILITY_GRANT_REQUEST_RESULT_SCHEMA_VERSION;
  requestId: string;
  status: WorkflowCapabilityGrantRequestResultStatus;
  capabilityRef: string;
  workflowNodeId: string;
  authorityScopes: string[];
  policyDecisionRefs: string[];
  receiptRefs: string[];
  evidenceRef: string | null;
  workflowRemainsFailClosed: boolean;
  secretMaterialPresent: false;
  message: string;
  issues: string[];
  request: WorkflowCapabilityGrantRequest;
};

export function workflowCapabilityGrantRequestFromRepairAction(
  workflow: WorkflowProject,
  action: WorkflowCapabilityRepairAction,
  options: { nowMs?: number; requestId?: string } = {},
): WorkflowCapabilityGrantRequest | null {
  if (action.kind !== "request_authority_grant") return null;
  const authorityScopes = uniqueStrings(action.authorityScopes);
  if (authorityScopes.length === 0) return null;
  const globalMeta = workflow.global_config?.meta as
    | { id?: string; name?: string }
    | undefined;
  const workflowGraphId =
    workflow.metadata?.id ??
    globalMeta?.id ??
    globalMeta?.name ??
    "workflow";
  const workflowName =
    workflow.metadata?.name ??
    globalMeta?.name ??
    workflowGraphId;
  const createdAtMs = options.nowMs ?? Date.now();
  const requestId =
    options.requestId ??
    `workflow-authority-grant-${safeId(workflowGraphId)}-${safeId(action.nodeId)}-${createdAtMs}`;
  return {
    schemaVersion: WORKFLOW_CAPABILITY_GRANT_REQUEST_SCHEMA_VERSION,
    sourceKind: "workflow_capability_repair_action",
    requestId,
    createdAtMs,
    workflowGraphId,
    workflowName,
    workflowNodeId: action.nodeId,
    nodeName: action.nodeName,
    bindingKind: action.bindingKind,
    capabilityRef: action.capabilityRef,
    routeId: action.routeId,
    authorityEndpoint: action.authorityEndpoint ?? "/api/v1/authority",
    authorityScopes,
    policyTarget: {
      kind: policyTargetKind(action.bindingKind),
      ref: action.capabilityRef,
      routeId: action.routeId,
    },
    receiptBehavior: {
      receiptRequired: true,
      requiredReceiptTypes: [
        "authority_grant_request",
        "policy_decision",
        "capability_grant_receipt",
      ],
    },
    readiness: {
      credential: action.readinessStatus,
      grant: action.grantStatus,
      policy: action.policyStatus,
    },
    riskClass: action.riskClass,
    sideEffectClass: action.sideEffectClass,
    requiresApproval: action.requiresApproval,
    missingFields: uniqueStrings(action.missingFields),
    blockerReasons: uniqueStrings(action.blockerReasons),
    failClosedUntil: "grant_readiness_ready_and_policy_allowed",
    redaction: {
      containsSecretMaterial: false,
      credentialValuesIncluded: false,
    },
  };
}

export function createBlockedWorkflowCapabilityGrantRequestResult(
  request: WorkflowCapabilityGrantRequest,
  issues: string[],
): WorkflowCapabilityGrantRequestResult {
  return {
    schemaVersion: WORKFLOW_CAPABILITY_GRANT_REQUEST_RESULT_SCHEMA_VERSION,
    requestId: request.requestId,
    status: "blocked",
    capabilityRef: request.capabilityRef,
    workflowNodeId: request.workflowNodeId,
    authorityScopes: request.authorityScopes,
    policyDecisionRefs: [],
    receiptRefs: [],
    evidenceRef: null,
    workflowRemainsFailClosed: true,
    secretMaterialPresent: false,
    message:
      "Authority grant request blocked before daemon submission. Review capability scopes and binding metadata.",
    issues,
    request,
  };
}

function policyTargetKind(
  bindingKind: WorkflowCapabilityRepairAction["bindingKind"],
): WorkflowCapabilityGrantRequest["policyTarget"]["kind"] {
  if (bindingKind === "Model") return "model_capability";
  if (bindingKind === "Connector") return "connector_capability";
  if (bindingKind === "Workflow tool") return "workflow_tool_capability";
  return "tool_capability";
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(
    new Set(values.map((value) => value.trim()).filter(Boolean)),
  );
}

function safeId(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "workflow"
  );
}
