import type { Node, NodeLogic } from "../types/graph";

export const WORKFLOW_RUNTIME_COMPACTION_POLICY_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-compaction-policy-control.v1" as const;
export const RUNTIME_COMPACTION_POLICY_WORKFLOW_NODE_ID =
  "runtime.compaction-policy" as const;
export const RUNTIME_COMPACTION_POLICY_SOURCE = "react_flow" as const;
export const RUNTIME_COMPACTION_POLICY_SOURCE_EVENT_KIND =
  "RuntimeCompactionPolicy.Evaluate" as const;
export const RUNTIME_COMPACTION_POLICY_COMPONENT_KIND =
  "compaction_policy" as const;
export const RUNTIME_COMPACTION_POLICY_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.compaction-policy.v1" as const;
export const RUNTIME_COMPACTION_POLICY_CONTEXT_COMPACT_WORKFLOW_NODE_ID =
  "runtime.context-compact" as const;

export type RuntimeCompactionPolicyAction =
  | "noop"
  | "warn"
  | "compact"
  | "stop"
  | "approval_required";

export interface RuntimeCompactionPolicyControlRequestBody {
  schemaVersion: typeof WORKFLOW_RUNTIME_COMPACTION_POLICY_CONTROL_SCHEMA_VERSION;
  source: typeof RUNTIME_COMPACTION_POLICY_SOURCE;
  actor: string;
  eventKind: typeof RUNTIME_COMPACTION_POLICY_SOURCE_EVENT_KIND;
  event_kind: typeof RUNTIME_COMPACTION_POLICY_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_COMPACTION_POLICY_COMPONENT_KIND;
  component_kind: typeof RUNTIME_COMPACTION_POLICY_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_COMPACTION_POLICY_PAYLOAD_SCHEMA_VERSION;
  payload_schema_version: typeof RUNTIME_COMPACTION_POLICY_PAYLOAD_SCHEMA_VERSION;
  workflowGraphId: string | null;
  workflow_graph_id: string | null;
  workflowNodeId: string;
  workflow_node_id: string;
  threadId: string;
  thread_id: string;
  turnId: string | null;
  turn_id: string | null;
  contextBudget: unknown | null;
  context_budget: unknown | null;
  contextBudgetStatus: string | null;
  context_budget_status: string | null;
  policy: {
    okAction: RuntimeCompactionPolicyAction;
    ok_action: RuntimeCompactionPolicyAction;
    warnAction: RuntimeCompactionPolicyAction;
    warn_action: RuntimeCompactionPolicyAction;
    blockedAction: RuntimeCompactionPolicyAction;
    blocked_action: RuntimeCompactionPolicyAction;
    approvalRequired: boolean;
    approval_required: boolean;
    approvalGranted: boolean;
    approval_granted: boolean;
    executeCompaction: boolean;
    execute_compaction: boolean;
    compactReason: string;
    compact_reason: string;
    compactScope: string;
    compact_scope: string;
    compactWorkflowNodeId: string;
    compact_workflow_node_id: string;
  };
}

export interface RuntimeCompactionPolicyControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_COMPACTION_POLICY_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_compaction_policy";
  nodeId: string | null;
  threadId: string;
  turnId: string | null;
  endpoint: string;
  method: "POST";
  body: RuntimeCompactionPolicyControlRequestBody;
}

export interface RuntimeCompactionPolicyControlRequestInput {
  nodeId?: string | null;
  input?: unknown;
  threadId?: string | null;
  threadIdField?: string | null;
  turnId?: string | null;
  turnIdField?: string | null;
  endpoint?: string | null;
  contextBudget?: unknown;
  contextBudgetField?: string | null;
  contextBudgetStatus?: string | null;
  contextBudgetStatusField?: string | null;
  okAction?: string | null;
  okActionField?: string | null;
  warnAction?: string | null;
  warnActionField?: string | null;
  blockedAction?: string | null;
  blockedActionField?: string | null;
  approvalRequired?: boolean | null;
  approvalRequiredField?: string | null;
  approvalGranted?: boolean | null;
  approvalGrantedField?: string | null;
  executeCompaction?: boolean | null;
  executeCompactionField?: string | null;
  compactReason?: string | null;
  compactReasonField?: string | null;
  compactScope?: string | null;
  compactScopeField?: string | null;
  compactWorkflowNodeId?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeCompactionPolicyWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export function createRuntimeCompactionPolicyControlRequest(
  params: RuntimeCompactionPolicyControlRequestInput,
): RuntimeCompactionPolicyControlRequest {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error("runtime_compaction_policy nodes need a threadId input.");
  }
  const turnId =
    cleanString(params.turnId) ??
    stringAtPath(params.input, params.turnIdField ?? "turnId") ??
    stringAtPath(params.input, "turn_id") ??
    null;
  const contextBudget =
    valueAtPath(params.input, params.contextBudgetField ?? "runtimeContextBudget") ??
    valueAtPath(params.input, "contextBudget") ??
    valueAtPath(params.input, "context_budget") ??
    params.contextBudget ??
    null;
  const contextBudgetStatus =
    stringAtPath(
      params.input,
      params.contextBudgetStatusField ?? "runtimeContextBudget.status",
    ) ??
    stringAtPath(contextBudget, "status") ??
    stringAtPath(contextBudget, "policyDecision.status") ??
    stringAtPath(contextBudget, "policy_decision.status") ??
    cleanString(params.contextBudgetStatus);
  const workflowNodeId =
    cleanString(params.workflowNodeId) ??
    RUNTIME_COMPACTION_POLICY_WORKFLOW_NODE_ID;
  const workflowGraphId = cleanString(params.workflowGraphId);
  const okAction = runtimeCompactionPolicyAction(
    stringAtPath(params.input, params.okActionField ?? "") ??
      cleanString(params.okAction),
    "noop",
  );
  const warnAction = runtimeCompactionPolicyAction(
    stringAtPath(params.input, params.warnActionField ?? "") ??
      cleanString(params.warnAction),
    "warn",
  );
  const blockedAction = runtimeCompactionPolicyAction(
    stringAtPath(params.input, params.blockedActionField ?? "") ??
      cleanString(params.blockedAction),
    "compact",
  );
  const approvalRequired =
    booleanAtPath(params.input, params.approvalRequiredField ?? "") ??
    params.approvalRequired ??
    false;
  const approvalGranted =
    booleanAtPath(params.input, params.approvalGrantedField ?? "") ??
    params.approvalGranted ??
    false;
  const executeCompaction =
    booleanAtPath(params.input, params.executeCompactionField ?? "") ??
    params.executeCompaction ??
    false;
  const compactReason =
    stringAtPath(params.input, params.compactReasonField ?? "") ??
    cleanString(params.compactReason) ??
    "Compact thread context from React Flow compaction policy.";
  const compactScope =
    stringAtPath(params.input, params.compactScopeField ?? "") ??
    cleanString(params.compactScope) ??
    "thread";
  const compactWorkflowNodeId =
    cleanString(params.compactWorkflowNodeId) ??
    RUNTIME_COMPACTION_POLICY_CONTEXT_COMPACT_WORKFLOW_NODE_ID;
  const body: RuntimeCompactionPolicyControlRequestBody = {
    schemaVersion: WORKFLOW_RUNTIME_COMPACTION_POLICY_CONTROL_SCHEMA_VERSION,
    source: RUNTIME_COMPACTION_POLICY_SOURCE,
    actor: cleanString(params.actor) ?? "operator",
    eventKind: RUNTIME_COMPACTION_POLICY_SOURCE_EVENT_KIND,
    event_kind: RUNTIME_COMPACTION_POLICY_SOURCE_EVENT_KIND,
    componentKind: RUNTIME_COMPACTION_POLICY_COMPONENT_KIND,
    component_kind: RUNTIME_COMPACTION_POLICY_COMPONENT_KIND,
    payloadSchemaVersion: RUNTIME_COMPACTION_POLICY_PAYLOAD_SCHEMA_VERSION,
    payload_schema_version: RUNTIME_COMPACTION_POLICY_PAYLOAD_SCHEMA_VERSION,
    workflowGraphId,
    workflow_graph_id: workflowGraphId,
    workflowNodeId,
    workflow_node_id: workflowNodeId,
    threadId,
    thread_id: threadId,
    turnId,
    turn_id: turnId,
    contextBudget,
    context_budget: contextBudget,
    contextBudgetStatus,
    context_budget_status: contextBudgetStatus,
    policy: {
      okAction,
      ok_action: okAction,
      warnAction,
      warn_action: warnAction,
      blockedAction,
      blocked_action: blockedAction,
      approvalRequired,
      approval_required: approvalRequired,
      approvalGranted,
      approval_granted: approvalGranted,
      executeCompaction,
      execute_compaction: executeCompaction,
      compactReason,
      compact_reason: compactReason,
      compactScope,
      compact_scope: compactScope,
      compactWorkflowNodeId,
      compact_workflow_node_id: compactWorkflowNodeId,
    },
  };

  return {
    schemaVersion: WORKFLOW_RUNTIME_COMPACTION_POLICY_CONTROL_SCHEMA_VERSION,
    nodeType: "runtime_compaction_policy",
    nodeId: cleanString(params.nodeId),
    threadId,
    turnId,
    endpoint: endpointFromTemplate(
      cleanString(params.endpoint) ?? "/v1/threads/{threadId}/compaction-policy",
      { threadId },
    ),
    method: "POST",
    body,
  };
}

export function createRuntimeCompactionPolicyControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeCompactionPolicyWorkflowNodeOptions = {},
): RuntimeCompactionPolicyControlRequest {
  const logic = compactionPolicyWorkflowNodeLogic(node);
  return createRuntimeCompactionPolicyControlRequest({
    nodeId: node.id,
    input,
    threadId: cleanString(logic.runtimeCompactionPolicyThreadId),
    threadIdField:
      cleanString(logic.runtimeCompactionPolicyThreadIdField) ?? "threadId",
    turnId: cleanString(logic.runtimeCompactionPolicyTurnId),
    turnIdField: cleanString(logic.runtimeCompactionPolicyTurnIdField) ?? "turnId",
    endpoint: cleanString(logic.runtimeCompactionPolicyEndpoint),
    contextBudget: logic.runtimeCompactionPolicyContextBudget,
    contextBudgetField:
      cleanString(logic.runtimeCompactionPolicyContextBudgetField) ??
      "runtimeContextBudget",
    contextBudgetStatus: cleanString(logic.runtimeCompactionPolicyContextBudgetStatus),
    contextBudgetStatusField: cleanString(
      logic.runtimeCompactionPolicyContextBudgetStatusField,
    ),
    okAction: cleanString(logic.runtimeCompactionPolicyOkAction),
    okActionField: cleanString(logic.runtimeCompactionPolicyOkActionField),
    warnAction: cleanString(logic.runtimeCompactionPolicyWarnAction),
    warnActionField: cleanString(logic.runtimeCompactionPolicyWarnActionField),
    blockedAction: cleanString(logic.runtimeCompactionPolicyBlockedAction),
    blockedActionField: cleanString(
      logic.runtimeCompactionPolicyBlockedActionField,
    ),
    approvalRequired:
      typeof logic.runtimeCompactionPolicyApprovalRequired === "boolean"
        ? logic.runtimeCompactionPolicyApprovalRequired
        : null,
    approvalRequiredField: cleanString(
      logic.runtimeCompactionPolicyApprovalRequiredField,
    ),
    approvalGranted:
      typeof logic.runtimeCompactionPolicyApprovalGranted === "boolean"
        ? logic.runtimeCompactionPolicyApprovalGranted
        : null,
    approvalGrantedField: cleanString(
      logic.runtimeCompactionPolicyApprovalGrantedField,
    ),
    executeCompaction:
      typeof logic.runtimeCompactionPolicyExecuteCompaction === "boolean"
        ? logic.runtimeCompactionPolicyExecuteCompaction
        : null,
    executeCompactionField: cleanString(
      logic.runtimeCompactionPolicyExecuteCompactionField,
    ),
    compactReason: cleanString(logic.runtimeCompactionPolicyCompactReason),
    compactReasonField: cleanString(
      logic.runtimeCompactionPolicyCompactReasonField,
    ),
    compactScope: cleanString(logic.runtimeCompactionPolicyCompactScope),
    compactScopeField: cleanString(logic.runtimeCompactionPolicyCompactScopeField),
    compactWorkflowNodeId: cleanString(
      logic.runtimeCompactionPolicyCompactWorkflowNodeId,
    ),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeCompactionPolicyWorkflowNodeId) ??
      RUNTIME_COMPACTION_POLICY_WORKFLOW_NODE_ID,
    actor: cleanString(options.actor) ?? cleanString(logic.runtimeCompactionPolicyActor),
  });
}

function compactionPolicyWorkflowNodeLogic(
  node: Pick<Node, "type" | "config">,
): NodeLogic {
  if (node.type !== "runtime_compaction_policy") {
    throw new Error(`Expected runtime_compaction_policy node, received ${node.type}.`);
  }
  return node.config?.logic ?? {};
}

function runtimeCompactionPolicyAction(
  value: string | null,
  fallback: RuntimeCompactionPolicyAction,
): RuntimeCompactionPolicyAction {
  if (
    value === "noop" ||
    value === "warn" ||
    value === "compact" ||
    value === "stop" ||
    value === "approval_required"
  ) {
    return value;
  }
  return fallback;
}

function endpointFromTemplate(
  template: string,
  values: Record<string, string>,
): string {
  return Object.entries(values).reduce(
    (current, [key, value]) =>
      current.replace(new RegExp(`\\{${key}\\}`, "g"), encodeURIComponent(value)),
    template,
  );
}

function stringAtPath(input: unknown, path: string | null | undefined): string | null {
  const value = valueAtPath(input, path);
  return cleanString(value);
}

function booleanAtPath(input: unknown, path: string | null | undefined): boolean | null {
  const value = valueAtPath(input, path);
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const clean = value.trim().toLowerCase();
    if (clean === "true" || clean === "1" || clean === "yes") return true;
    if (clean === "false" || clean === "0" || clean === "no") return false;
  }
  return null;
}

function valueAtPath(input: unknown, path: string | null | undefined): unknown {
  const clean = cleanString(path);
  if (!clean || input === null || typeof input !== "object") return null;
  return clean.split(".").reduce<unknown>((current, segment) => {
    if (current === null || typeof current !== "object") return null;
    return (current as Record<string, unknown>)[segment];
  }, input);
}

function cleanString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const clean = value.trim();
  return clean ? clean : null;
}
