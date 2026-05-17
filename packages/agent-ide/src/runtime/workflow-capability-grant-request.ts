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
  | "denied"
  | "expired";

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
  resolvedAtMs?: number | null;
  resolution?: WorkflowCapabilityGrantResolution | null;
  appliedAtMs?: number | null;
};

export type WorkflowCapabilityGrantResolutionDecision =
  | "approve"
  | "deny"
  | "expire";

export type WorkflowCapabilityGrantResolution = {
  decision: WorkflowCapabilityGrantResolutionDecision;
  reason: string | null;
  actor: "authority_center" | "daemon" | "test" | "unknown";
  resolvedAtMs: number;
};

export type WorkflowCapabilityGrantResolutionRequest = {
  requestId: string;
  decision: WorkflowCapabilityGrantResolutionDecision;
  reason?: string | null;
  actor?: WorkflowCapabilityGrantResolution["actor"];
};

export type WorkflowCapabilityGrantApplyRequest = {
  requestId: string;
};

type WorkflowCapabilityGrantBindingKey =
  | "modelBinding"
  | "toolBinding"
  | "connectorBinding";

export type WorkflowCapabilityGrantApplyResult = {
  status: "applied" | "blocked";
  workflow: WorkflowProject;
  issues: string[];
  nodeId: string | null;
  bindingKey: WorkflowCapabilityGrantBindingKey | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
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
    resolvedAtMs: null,
    resolution: null,
    appliedAtMs: null,
  };
}

export function applyApprovedWorkflowCapabilityGrantRequestToWorkflow(
  workflow: WorkflowProject,
  grant: WorkflowCapabilityGrantRequestResult,
): WorkflowCapabilityGrantApplyResult {
  if (grant.status !== "approved") {
    return blockedGrantApply(workflow, grant, [
      `grant_status_${grant.status}_is_not_approved`,
    ]);
  }
  if (grant.authorityScopes.length === 0) {
    return blockedGrantApply(workflow, grant, ["missing_authority_scope"]);
  }
  const bindingKey = bindingKeyForGrantRequest(grant.request);
  const workflowCopy = cloneWorkflow(workflow);
  const node = workflowCopy.nodes.find(
    (candidate) => candidate.id === grant.workflowNodeId,
  );
  if (!node) {
    return blockedGrantApply(workflow, grant, ["workflow_node_not_found"]);
  }
  const logic = {
    ...(node.config?.logic ?? {}),
  } as Record<string, any>;
  const existingBinding = {
    ...(logic[bindingKey] ?? {}),
  } as Record<string, any>;
  const receiptTypes = uniqueStrings([
    ...arrayOfStrings(existingBinding.receiptBehavior?.requiredReceiptTypes),
    ...grant.request.receiptBehavior.requiredReceiptTypes,
  ]);
  logic[bindingKey] = {
    ...existingBinding,
    ...bindingRefPatchForGrant(grant.request, bindingKey),
    authorityScopes: grant.authorityScopes,
    authorityScopeRequirements: grant.authorityScopes,
    grantReadiness: {
      status: "ready",
      reason: "Authority grant request approved and applied to this workflow binding.",
      evidenceRefs: grant.receiptRefs,
      requestId: grant.requestId,
    },
    policyPosture: {
      status: "allowed",
      policyTarget: grant.request.policyTarget.ref,
      source: "workflow_capability_grant_request",
      evidenceRefs: grant.policyDecisionRefs,
      requestId: grant.requestId,
    },
    receiptBehavior: {
      ...(existingBinding.receiptBehavior ?? {}),
      receiptRequired: true,
      requiredReceiptTypes: receiptTypes,
    },
    grantReceiptRefs: uniqueStrings([
      ...arrayOfStrings(existingBinding.grantReceiptRefs),
      ...grant.receiptRefs,
    ]),
    policyDecisionRefs: uniqueStrings([
      ...arrayOfStrings(existingBinding.policyDecisionRefs),
      ...grant.policyDecisionRefs,
    ]),
    lastAuthorityGrantRequestId: grant.requestId,
  };
  node.config = {
    ...(node.config as any),
    kind: (node.config as any)?.kind ?? node.type,
    logic,
  } as any;
  workflowCopy.metadata = {
    ...workflowCopy.metadata,
    dirty: true,
    updatedAtMs: Date.now(),
  };
  return {
    status: "applied",
    workflow: workflowCopy,
    issues: [],
    nodeId: grant.workflowNodeId,
    bindingKey,
    receiptRefs: grant.receiptRefs,
    policyDecisionRefs: grant.policyDecisionRefs,
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

function bindingKeyForGrantRequest(
  request: WorkflowCapabilityGrantRequest,
): WorkflowCapabilityGrantBindingKey {
  if (request.bindingKind === "Model") return "modelBinding";
  if (request.bindingKind === "Connector") return "connectorBinding";
  return "toolBinding";
}

function bindingRefPatchForGrant(
  request: WorkflowCapabilityGrantRequest,
  bindingKey: WorkflowCapabilityGrantBindingKey,
): Record<string, unknown> {
  if (bindingKey === "modelBinding") {
    return {
      modelCapabilityRef: request.capabilityRef,
      routeId: request.routeId,
    };
  }
  if (bindingKey === "connectorBinding") {
    return {
      connectorCapabilityRef: request.capabilityRef,
    };
  }
  return {
    toolCapabilityRef: request.capabilityRef,
  };
}

function blockedGrantApply(
  workflow: WorkflowProject,
  grant: WorkflowCapabilityGrantRequestResult,
  issues: string[],
): WorkflowCapabilityGrantApplyResult {
  return {
    status: "blocked",
    workflow,
    issues,
    nodeId: grant.workflowNodeId ?? null,
    bindingKey: bindingKeyForGrantRequest(grant.request),
    receiptRefs: grant.receiptRefs,
    policyDecisionRefs: grant.policyDecisionRefs,
  };
}

function cloneWorkflow(workflow: WorkflowProject): WorkflowProject {
  return JSON.parse(JSON.stringify(workflow)) as WorkflowProject;
}

function arrayOfStrings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter(Boolean);
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
