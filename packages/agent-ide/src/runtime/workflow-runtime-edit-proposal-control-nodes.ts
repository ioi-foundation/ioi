import type { Node, NodeLogic } from "../types/graph";

export const WORKFLOW_RUNTIME_EDIT_PROPOSAL_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-edit-proposal-control.v1" as const;
export const WORKFLOW_RUNTIME_EDIT_PROPOSAL_APPLY_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-edit-proposal-apply-control.v1" as const;
export const RUNTIME_WORKFLOW_EDIT_PROPOSAL_SOURCE = "react_flow" as const;
export const RUNTIME_WORKFLOW_EDIT_PROPOSAL_SOURCE_EVENT_KIND =
  "WorkflowEdit.Proposed" as const;
export const RUNTIME_WORKFLOW_EDIT_PROPOSAL_APPLY_SOURCE_EVENT_KIND =
  "WorkflowEdit.Apply" as const;
export const RUNTIME_WORKFLOW_EDIT_PROPOSAL_COMPONENT_KIND =
  "workflow_edit_proposal" as const;
export const RUNTIME_WORKFLOW_EDIT_PROPOSAL_WORKFLOW_NODE_ID =
  "runtime.workflow-edit-proposal" as const;
export const RUNTIME_WORKFLOW_EDIT_PROPOSAL_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.workflow-edit-proposal.v1" as const;
export const RUNTIME_WORKFLOW_EDIT_PROPOSAL_APPLY_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.workflow-edit-apply.v1" as const;

export interface RuntimeWorkflowEditProposalControlRequestBody {
  source: typeof RUNTIME_WORKFLOW_EDIT_PROPOSAL_SOURCE;
  actor: string;
  event_kind: typeof RUNTIME_WORKFLOW_EDIT_PROPOSAL_SOURCE_EVENT_KIND;
  eventKind: typeof RUNTIME_WORKFLOW_EDIT_PROPOSAL_SOURCE_EVENT_KIND;
  component_kind: typeof RUNTIME_WORKFLOW_EDIT_PROPOSAL_COMPONENT_KIND;
  componentKind: typeof RUNTIME_WORKFLOW_EDIT_PROPOSAL_COMPONENT_KIND;
  payload_schema_version: typeof RUNTIME_WORKFLOW_EDIT_PROPOSAL_PAYLOAD_SCHEMA_VERSION;
  payloadSchemaVersion: typeof RUNTIME_WORKFLOW_EDIT_PROPOSAL_PAYLOAD_SCHEMA_VERSION;
  workflow_graph_id: string | null;
  workflowGraphId: string | null;
  workflow_node_id: string;
  workflowNodeId: string;
  proposal_id: string | null;
  proposalId: string | null;
  title: string;
  summary: string;
  target_workflow_node_ids: string[];
  targetWorkflowNodeIds: string[];
  bounded_targets: string[];
  boundedTargets: string[];
  workflow_path: string | null;
  workflowPath: string | null;
  workflow_patch: unknown | null;
  workflowPatch: unknown | null;
  code_diff: string | null;
  codeDiff: string | null;
  approval_mode: "human_required";
  approvalMode: "human_required";
  proposal_only: true;
  proposalOnly: true;
  mutation_allowed: false;
  mutationAllowed: false;
  mutation_executed: false;
  mutationExecuted: false;
}

export interface RuntimeWorkflowEditProposalControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_EDIT_PROPOSAL_CONTROL_SCHEMA_VERSION;
  nodeType: "proposal";
  nodeId: string | null;
  threadId: string;
  endpoint: string;
  method: "POST";
  body: RuntimeWorkflowEditProposalControlRequestBody;
}

export interface RuntimeWorkflowEditProposalControlRequestInput {
  nodeId?: string | null;
  input?: unknown;
  threadId?: string | null;
  threadIdField?: string | null;
  proposalId?: string | null;
  proposalIdField?: string | null;
  title?: string | null;
  titleField?: string | null;
  summary?: string | null;
  summaryField?: string | null;
  targetWorkflowNodeIds?: string[] | null;
  targetWorkflowNodeIdsField?: string | null;
  workflowPath?: string | null;
  workflowPathField?: string | null;
  workflowPatch?: unknown | null;
  workflowPatchField?: string | null;
  codeDiff?: string | null;
  codeDiffField?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeWorkflowEditProposalApplyControlRequestBody {
  source: typeof RUNTIME_WORKFLOW_EDIT_PROPOSAL_SOURCE;
  actor: string;
  event_kind: typeof RUNTIME_WORKFLOW_EDIT_PROPOSAL_APPLY_SOURCE_EVENT_KIND;
  eventKind: typeof RUNTIME_WORKFLOW_EDIT_PROPOSAL_APPLY_SOURCE_EVENT_KIND;
  component_kind: typeof RUNTIME_WORKFLOW_EDIT_PROPOSAL_COMPONENT_KIND;
  componentKind: typeof RUNTIME_WORKFLOW_EDIT_PROPOSAL_COMPONENT_KIND;
  payload_schema_version: typeof RUNTIME_WORKFLOW_EDIT_PROPOSAL_APPLY_PAYLOAD_SCHEMA_VERSION;
  payloadSchemaVersion: typeof RUNTIME_WORKFLOW_EDIT_PROPOSAL_APPLY_PAYLOAD_SCHEMA_VERSION;
  workflow_graph_id: string | null;
  workflowGraphId: string | null;
  workflow_node_id: string;
  workflowNodeId: string;
  proposal_id: string;
  proposalId: string;
  approval_id: string | null;
  approvalId: string | null;
  proposal_only: true;
  proposalOnly: true;
}

export interface RuntimeWorkflowEditProposalApplyControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_EDIT_PROPOSAL_APPLY_CONTROL_SCHEMA_VERSION;
  nodeType: "proposal";
  nodeId: string | null;
  threadId: string;
  proposalId: string;
  endpoint: string;
  method: "POST";
  body: RuntimeWorkflowEditProposalApplyControlRequestBody;
}

export interface RuntimeWorkflowEditProposalApplyControlRequestInput {
  nodeId?: string | null;
  input?: unknown;
  threadId?: string | null;
  threadIdField?: string | null;
  proposalId?: string | null;
  proposalIdField?: string | null;
  approvalId?: string | null;
  approvalIdField?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeWorkflowEditProposalWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export function createRuntimeWorkflowEditProposalControlRequest(
  params: RuntimeWorkflowEditProposalControlRequestInput,
): RuntimeWorkflowEditProposalControlRequest {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error("proposal nodes need a threadId input before dispatch.");
  }

  const targetWorkflowNodeIds = uniqueStrings(
    params.targetWorkflowNodeIds ??
      stringArrayAtPath(
        params.input,
        params.targetWorkflowNodeIdsField ?? "targetWorkflowNodeIds",
      ) ??
      stringArrayAtPath(params.input, "target_workflow_node_ids") ??
      stringArrayAtPath(params.input, "boundedTargets") ??
      stringArrayAtPath(params.input, "bounded_targets") ??
      [],
  );
  const proposalId =
    cleanString(params.proposalId) ??
    stringAtPath(params.input, params.proposalIdField ?? "proposalId") ??
    stringAtPath(params.input, "proposal_id");
  const workflowGraphId = cleanString(params.workflowGraphId) ?? null;
  const workflowNodeId =
    cleanString(params.workflowNodeId) ??
    `${RUNTIME_WORKFLOW_EDIT_PROPOSAL_WORKFLOW_NODE_ID}.${safeId(
      proposalId ?? targetWorkflowNodeIds[0] ?? "draft",
    )}`;
  const title =
    cleanString(params.title) ??
    stringAtPath(params.input, params.titleField ?? "title") ??
    "Review workflow edit proposal";
  const summary =
    cleanString(params.summary) ??
    stringAtPath(params.input, params.summaryField ?? "summary") ??
    "Proposal-only workflow edit staged for daemon-owned approval.";
  const workflowPath =
    cleanString(params.workflowPath) ??
    stringAtPath(params.input, params.workflowPathField ?? "workflowPath") ??
    stringAtPath(params.input, "workflow_path");
  const workflowPatch =
    params.workflowPatch ??
    valueAtPath(params.input, params.workflowPatchField ?? "workflowPatch") ??
    valueAtPath(params.input, "workflow_patch") ??
    null;
  const codeDiff =
    cleanString(params.codeDiff) ??
    stringAtPath(params.input, params.codeDiffField ?? "codeDiff") ??
    stringAtPath(params.input, "code_diff");

  return {
    schemaVersion: WORKFLOW_RUNTIME_EDIT_PROPOSAL_CONTROL_SCHEMA_VERSION,
    nodeType: "proposal",
    nodeId: params.nodeId ?? null,
    threadId,
    endpoint: `/v1/threads/${encodeSegment(threadId)}/workflow-edit-proposals`,
    method: "POST",
    body: {
      source: RUNTIME_WORKFLOW_EDIT_PROPOSAL_SOURCE,
      actor: cleanString(params.actor) ?? "workflow-author",
      event_kind: RUNTIME_WORKFLOW_EDIT_PROPOSAL_SOURCE_EVENT_KIND,
      eventKind: RUNTIME_WORKFLOW_EDIT_PROPOSAL_SOURCE_EVENT_KIND,
      component_kind: RUNTIME_WORKFLOW_EDIT_PROPOSAL_COMPONENT_KIND,
      componentKind: RUNTIME_WORKFLOW_EDIT_PROPOSAL_COMPONENT_KIND,
      payload_schema_version: RUNTIME_WORKFLOW_EDIT_PROPOSAL_PAYLOAD_SCHEMA_VERSION,
      payloadSchemaVersion: RUNTIME_WORKFLOW_EDIT_PROPOSAL_PAYLOAD_SCHEMA_VERSION,
      workflow_graph_id: workflowGraphId,
      workflowGraphId,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      proposal_id: proposalId,
      proposalId,
      title,
      summary,
      target_workflow_node_ids: targetWorkflowNodeIds,
      targetWorkflowNodeIds,
      bounded_targets: targetWorkflowNodeIds,
      boundedTargets: targetWorkflowNodeIds,
      workflow_path: workflowPath,
      workflowPath,
      workflow_patch: workflowPatch,
      workflowPatch,
      code_diff: codeDiff,
      codeDiff,
      approval_mode: "human_required",
      approvalMode: "human_required",
      proposal_only: true,
      proposalOnly: true,
      mutation_allowed: false,
      mutationAllowed: false,
      mutation_executed: false,
      mutationExecuted: false,
    },
  };
}

export function createRuntimeWorkflowEditProposalApplyControlRequest(
  params: RuntimeWorkflowEditProposalApplyControlRequestInput,
): RuntimeWorkflowEditProposalApplyControlRequest {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error("proposal apply controls need a threadId input before dispatch.");
  }
  const proposalId =
    cleanString(params.proposalId) ??
    stringAtPath(params.input, params.proposalIdField ?? "proposalId") ??
    stringAtPath(params.input, "proposal_id");
  if (!proposalId) {
    throw new Error("proposal apply controls need a proposalId input before dispatch.");
  }
  const approvalId =
    cleanString(params.approvalId) ??
    stringAtPath(params.input, params.approvalIdField ?? "approvalId") ??
    stringAtPath(params.input, "approval_id");
  const workflowGraphId = cleanString(params.workflowGraphId) ?? null;
  const workflowNodeId =
    cleanString(params.workflowNodeId) ??
    `${RUNTIME_WORKFLOW_EDIT_PROPOSAL_WORKFLOW_NODE_ID}.${safeId(proposalId)}`;

  return {
    schemaVersion: WORKFLOW_RUNTIME_EDIT_PROPOSAL_APPLY_CONTROL_SCHEMA_VERSION,
    nodeType: "proposal",
    nodeId: params.nodeId ?? null,
    threadId,
    proposalId,
    endpoint: `/v1/threads/${encodeSegment(threadId)}/workflow-edit-proposals/${encodeSegment(
      proposalId,
    )}/apply`,
    method: "POST",
    body: {
      source: RUNTIME_WORKFLOW_EDIT_PROPOSAL_SOURCE,
      actor: cleanString(params.actor) ?? "workflow-author",
      event_kind: RUNTIME_WORKFLOW_EDIT_PROPOSAL_APPLY_SOURCE_EVENT_KIND,
      eventKind: RUNTIME_WORKFLOW_EDIT_PROPOSAL_APPLY_SOURCE_EVENT_KIND,
      component_kind: RUNTIME_WORKFLOW_EDIT_PROPOSAL_COMPONENT_KIND,
      componentKind: RUNTIME_WORKFLOW_EDIT_PROPOSAL_COMPONENT_KIND,
      payload_schema_version:
        RUNTIME_WORKFLOW_EDIT_PROPOSAL_APPLY_PAYLOAD_SCHEMA_VERSION,
      payloadSchemaVersion:
        RUNTIME_WORKFLOW_EDIT_PROPOSAL_APPLY_PAYLOAD_SCHEMA_VERSION,
      workflow_graph_id: workflowGraphId,
      workflowGraphId,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      proposal_id: proposalId,
      proposalId,
      approval_id: approvalId,
      approvalId,
      proposal_only: true,
      proposalOnly: true,
    },
  };
}

export function createRuntimeWorkflowEditProposalControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeWorkflowEditProposalWorkflowNodeOptions = {},
): RuntimeWorkflowEditProposalControlRequest {
  const logic = proposalWorkflowNodeLogic(node);
  const proposalAction = objectField(logic, "proposalAction") ?? {};
  return createRuntimeWorkflowEditProposalControlRequest({
    nodeId: node.id,
    input,
    threadIdField: "threadId",
    proposalId: stringField(logic, "proposalId", "proposal_id"),
    title: stringField(logic, "title"),
    summary: stringField(logic, "summary"),
    targetWorkflowNodeIds:
      stringArrayField(logic, "targetWorkflowNodeIds", "target_workflow_node_ids") ??
      stringArrayField(proposalAction, "boundedTargets", "bounded_targets"),
    workflowPath: stringField(logic, "workflowPath", "workflow_path"),
    workflowPatch: valueField(logic, "workflowPatch", "workflow_patch"),
    codeDiff: stringField(logic, "codeDiff", "code_diff"),
    workflowGraphId: options.workflowGraphId,
    workflowNodeId:
      stringField(logic, "workflowNodeId", "workflow_node_id") ??
      `${RUNTIME_WORKFLOW_EDIT_PROPOSAL_WORKFLOW_NODE_ID}.${safeId(node.id)}`,
    actor: options.actor,
  });
}

export function createRuntimeWorkflowEditProposalApplyControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeWorkflowEditProposalWorkflowNodeOptions = {},
): RuntimeWorkflowEditProposalApplyControlRequest {
  const logic = proposalWorkflowNodeLogic(node);
  return createRuntimeWorkflowEditProposalApplyControlRequest({
    nodeId: node.id,
    input,
    threadIdField: "threadId",
    proposalId: stringField(logic, "proposalId", "proposal_id"),
    approvalId: stringField(logic, "approvalId", "approval_id"),
    workflowGraphId: options.workflowGraphId,
    workflowNodeId:
      stringField(logic, "workflowNodeId", "workflow_node_id") ??
      `${RUNTIME_WORKFLOW_EDIT_PROPOSAL_WORKFLOW_NODE_ID}.${safeId(node.id)}`,
    actor: options.actor,
  });
}

function proposalWorkflowNodeLogic(node: Pick<Node, "config">): NodeLogic {
  const logic = node.config?.logic;
  return logic && typeof logic === "object" ? (logic as NodeLogic) : {};
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

function objectField(source: unknown, key: string): Record<string, unknown> | null {
  if (!source || typeof source !== "object" || Array.isArray(source)) return null;
  const value = (source as Record<string, unknown>)[key];
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function valueField(source: unknown, ...keys: string[]): unknown | null {
  if (!source || typeof source !== "object" || Array.isArray(source)) return null;
  for (const key of keys) {
    const record = source as Record<string, unknown>;
    if (Object.prototype.hasOwnProperty.call(record, key)) return record[key];
  }
  return null;
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
  return Array.from(new Set(values.filter((value) => value.trim())));
}

function encodeSegment(value: string): string {
  return encodeURIComponent(value);
}

function safeId(value: unknown): string {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}
