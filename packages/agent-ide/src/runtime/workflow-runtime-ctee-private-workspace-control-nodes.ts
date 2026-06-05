import type { Node, NodeLogic } from "../types/graph";

export const WORKFLOW_RUNTIME_CTEE_PRIVATE_WORKSPACE_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-ctee-private-workspace-control.v1" as const;
export const RUNTIME_CTEE_PRIVATE_WORKSPACE_SOURCE = "react_flow" as const;
export const RUNTIME_CTEE_PRIVATE_WORKSPACE_SOURCE_EVENT_KIND =
  "CteePrivateWorkspace.ActionAdmitted" as const;
export const RUNTIME_CTEE_PRIVATE_WORKSPACE_COMPONENT_KIND =
  "ctee_private_workspace_action" as const;
export const RUNTIME_CTEE_PRIVATE_WORKSPACE_WORKFLOW_NODE_ID =
  "runtime.ctee-private-workspace-action" as const;

export interface RuntimeCteePrivateWorkspaceNodeTrust extends Record<string, unknown> {
  runtime_node_ref: string;
  trusted_for_plaintext: boolean;
  attestation_ref?: string | null;
}

export interface RuntimeCteePrivateWorkspaceAction extends Record<string, unknown> {
  invocation: Record<string, unknown>;
  node_trust: RuntimeCteePrivateWorkspaceNodeTrust;
  expected_heads: string[];
}

export interface RuntimeCteePrivateWorkspaceControlRequestBody {
  source: typeof RUNTIME_CTEE_PRIVATE_WORKSPACE_SOURCE;
  actor: string;
  event_kind: typeof RUNTIME_CTEE_PRIVATE_WORKSPACE_SOURCE_EVENT_KIND;
  eventKind: typeof RUNTIME_CTEE_PRIVATE_WORKSPACE_SOURCE_EVENT_KIND;
  component_kind: typeof RUNTIME_CTEE_PRIVATE_WORKSPACE_COMPONENT_KIND;
  componentKind: typeof RUNTIME_CTEE_PRIVATE_WORKSPACE_COMPONENT_KIND;
  workflow_graph_id: string | null;
  workflowGraphId: string | null;
  workflow_node_id: string;
  workflowNodeId: string;
  invocation_id: string;
  invocationId: string;
  runtime_node_ref: string;
  runtimeNodeRef: string;
  trusted_for_plaintext: boolean;
  trustedForPlaintext: boolean;
  expected_heads: string[];
  expectedHeads: string[];
  admission_only: true;
  admissionOnly: true;
  direct_truth_write_allowed: false;
  directTruthWriteAllowed: false;
  plaintext_custody_checked_by_rust: true;
  plaintextCustodyCheckedByRust: true;
  action: RuntimeCteePrivateWorkspaceAction;
  ctee_action: RuntimeCteePrivateWorkspaceAction;
  cteeAction: RuntimeCteePrivateWorkspaceAction;
}

export interface RuntimeCteePrivateWorkspaceControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_CTEE_PRIVATE_WORKSPACE_CONTROL_SCHEMA_VERSION;
  nodeType: "ctee_private_workspace_action";
  nodeId: string | null;
  threadId: string;
  invocationId: string;
  endpoint: string;
  method: "POST";
  body: RuntimeCteePrivateWorkspaceControlRequestBody;
}

export interface RuntimeCteePrivateWorkspaceControlRequestInput {
  nodeId?: string | null;
  input?: unknown;
  threadId?: string | null;
  threadIdField?: string | null;
  action?: Partial<RuntimeCteePrivateWorkspaceAction> & Record<string, unknown>;
  actionField?: string | null;
  invocation?: Record<string, unknown> | null;
  nodeTrust?: Partial<RuntimeCteePrivateWorkspaceNodeTrust> & Record<string, unknown>;
  expectedHeads?: string[] | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeCteePrivateWorkspaceWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export function createRuntimeCteePrivateWorkspaceControlRequest(
  params: RuntimeCteePrivateWorkspaceControlRequestInput,
): RuntimeCteePrivateWorkspaceControlRequest {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error("cTEE private workspace controls need a threadId input before dispatch.");
  }

  const actionSeed =
    objectRecord(params.action) ??
    objectAtPath(params.input, params.actionField ?? "action") ??
    objectAtPath(params.input, "ctee_action") ??
    objectAtPath(params.input, "cteeAction") ??
    {};
  const invocation = requiredObject(
    params.invocation ??
      objectField(actionSeed, "invocation") ??
      objectAtPath(params.input, "invocation"),
    "invocation",
  );
  const nodeTrustSeed =
    objectRecord(params.nodeTrust) ??
    objectField(actionSeed, "node_trust") ??
    objectField(actionSeed, "nodeTrust") ??
    objectAtPath(params.input, "node_trust") ??
    objectAtPath(params.input, "nodeTrust");
  const runtimeNodeRef = requiredString(
    stringField(nodeTrustSeed, "runtime_node_ref", "runtimeNodeRef"),
    "node_trust.runtime_node_ref",
  );
  const trustedForPlaintext = booleanField(nodeTrustSeed, "trusted_for_plaintext", "trustedForPlaintext");
  if (trustedForPlaintext === null) {
    throw new Error("cTEE private workspace controls need node_trust.trusted_for_plaintext before dispatch.");
  }
  const expectedHeads = requiredStringArray(
    params.expectedHeads ??
      stringArrayField(actionSeed, "expected_heads", "expectedHeads") ??
      stringArrayAtPath(params.input, "expected_heads") ??
      stringArrayAtPath(params.input, "expectedHeads"),
    "expected_heads",
  );
  const invocationId = requiredString(
    stringField(invocation, "invocation_id", "invocationId"),
    "invocation.invocation_id",
  );
  const workflowGraphId = cleanString(params.workflowGraphId) ?? null;
  const workflowNodeId =
    cleanString(params.workflowNodeId) ??
    `${RUNTIME_CTEE_PRIVATE_WORKSPACE_WORKFLOW_NODE_ID}.${safeId(invocationId)}`;
  const nodeTrust: RuntimeCteePrivateWorkspaceNodeTrust = {
    ...(nodeTrustSeed ?? {}),
    runtime_node_ref: runtimeNodeRef,
    trusted_for_plaintext: trustedForPlaintext,
    attestation_ref:
      stringField(nodeTrustSeed, "attestation_ref", "attestationRef") ??
      null,
  };
  const action: RuntimeCteePrivateWorkspaceAction = {
    ...actionSeed,
    invocation,
    node_trust: nodeTrust,
    expected_heads: expectedHeads,
  };

  return {
    schemaVersion: WORKFLOW_RUNTIME_CTEE_PRIVATE_WORKSPACE_CONTROL_SCHEMA_VERSION,
    nodeType: "ctee_private_workspace_action",
    nodeId: params.nodeId ?? null,
    threadId,
    invocationId,
    endpoint: `/v1/threads/${encodeSegment(threadId)}/ctee-private-workspace-actions`,
    method: "POST",
    body: {
      source: RUNTIME_CTEE_PRIVATE_WORKSPACE_SOURCE,
      actor: cleanString(params.actor) ?? "workflow-author",
      event_kind: RUNTIME_CTEE_PRIVATE_WORKSPACE_SOURCE_EVENT_KIND,
      eventKind: RUNTIME_CTEE_PRIVATE_WORKSPACE_SOURCE_EVENT_KIND,
      component_kind: RUNTIME_CTEE_PRIVATE_WORKSPACE_COMPONENT_KIND,
      componentKind: RUNTIME_CTEE_PRIVATE_WORKSPACE_COMPONENT_KIND,
      workflow_graph_id: workflowGraphId,
      workflowGraphId,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      invocation_id: invocationId,
      invocationId,
      runtime_node_ref: runtimeNodeRef,
      runtimeNodeRef,
      trusted_for_plaintext: trustedForPlaintext,
      trustedForPlaintext,
      expected_heads: expectedHeads,
      expectedHeads,
      admission_only: true,
      admissionOnly: true,
      direct_truth_write_allowed: false,
      directTruthWriteAllowed: false,
      plaintext_custody_checked_by_rust: true,
      plaintextCustodyCheckedByRust: true,
      action,
      ctee_action: action,
      cteeAction: action,
    },
  };
}

export function createRuntimeCteePrivateWorkspaceControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeCteePrivateWorkspaceWorkflowNodeOptions = {},
): RuntimeCteePrivateWorkspaceControlRequest {
  const logic = workflowNodeLogic(node);
  const action =
    objectField(logic, "cteePrivateWorkspace") ??
    objectField(logic, "cteeAction") ??
    objectField(logic, "action") ??
    {};
  return createRuntimeCteePrivateWorkspaceControlRequest({
    nodeId: node.id,
    input,
    threadIdField: "threadId",
    action,
    workflowGraphId: options.workflowGraphId,
    workflowNodeId:
      stringField(logic, "workflowNodeId", "workflow_node_id") ??
      `${RUNTIME_CTEE_PRIVATE_WORKSPACE_WORKFLOW_NODE_ID}.${safeId(node.id)}`,
    actor: options.actor,
  });
}

function workflowNodeLogic(node: Pick<Node, "config">): NodeLogic {
  const logic = node.config?.logic;
  return logic && typeof logic === "object" ? (logic as NodeLogic) : {};
}

function requiredString(value: string | null, field: string): string {
  if (value) return value;
  throw new Error(`cTEE private workspace controls need ${field} before dispatch.`);
}

function requiredStringArray(values: string[] | null | undefined, field: string): string[] {
  const normalized = uniqueStrings(values ?? []);
  if (normalized.length > 0) return normalized;
  throw new Error(`cTEE private workspace controls need ${field} before dispatch.`);
}

function requiredObject(value: Record<string, unknown> | null | undefined, field: string): Record<string, unknown> {
  if (value && Object.keys(value).length > 0) return value;
  throw new Error(`cTEE private workspace controls need ${field} before dispatch.`);
}

function cleanString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function stringField(source: unknown, ...keys: string[]): string | null {
  if (!source || typeof source !== "object" || Array.isArray(source)) return null;
  for (const key of keys) {
    const value = cleanString((source as Record<string, unknown>)[key]);
    if (value) return value;
  }
  return null;
}

function booleanField(source: unknown, ...keys: string[]): boolean | null {
  if (!source || typeof source !== "object" || Array.isArray(source)) return null;
  for (const key of keys) {
    const value = (source as Record<string, unknown>)[key];
    if (typeof value === "boolean") return value;
  }
  return null;
}

function objectField(source: unknown, key: string): Record<string, unknown> | null {
  if (!source || typeof source !== "object" || Array.isArray(source)) return null;
  return objectRecord((source as Record<string, unknown>)[key]);
}

function objectRecord(source: unknown): Record<string, unknown> | null {
  return source && typeof source === "object" && !Array.isArray(source)
    ? (source as Record<string, unknown>)
    : null;
}

function stringArrayField(source: unknown, ...keys: string[]): string[] | null {
  if (!source || typeof source !== "object" || Array.isArray(source)) return null;
  for (const key of keys) {
    const value = stringArray((source as Record<string, unknown>)[key]);
    if (value) return value;
  }
  return null;
}

function stringAtPath(source: unknown, path: string): string | null {
  return cleanString(valueAtPath(source, path));
}

function stringArrayAtPath(source: unknown, path: string): string[] | null {
  return stringArray(valueAtPath(source, path));
}

function objectAtPath(source: unknown, path: string): Record<string, unknown> | null {
  return objectRecord(valueAtPath(source, path));
}

function stringArray(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  return uniqueStrings(value.map((item) => cleanString(item)).filter(Boolean) as string[]);
}

function valueAtPath(source: unknown, path: string): unknown {
  if (!source || typeof source !== "object" || Array.isArray(source)) return undefined;
  return path.split(".").reduce<unknown>((current, segment) => {
    if (!current || typeof current !== "object" || Array.isArray(current)) return undefined;
    return (current as Record<string, unknown>)[segment];
  }, source);
}

function uniqueStrings(values: readonly string[]): string[] {
  return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean)));
}

function encodeSegment(value: string): string {
  return encodeURIComponent(value);
}

function safeId(value: unknown): string {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}
