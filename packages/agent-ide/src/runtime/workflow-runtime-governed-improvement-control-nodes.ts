import type { Node, NodeLogic } from "../types/graph";

export const WORKFLOW_RUNTIME_GOVERNED_IMPROVEMENT_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-governed-improvement-control.v1" as const;
export const RUNTIME_GOVERNED_IMPROVEMENT_SOURCE = "react_flow" as const;
export const RUNTIME_GOVERNED_IMPROVEMENT_SOURCE_EVENT_KIND =
  "GovernedImprovement.Proposed" as const;
export const RUNTIME_GOVERNED_IMPROVEMENT_COMPONENT_KIND =
  "governed_improvement_proposal" as const;
export const RUNTIME_GOVERNED_IMPROVEMENT_PROPOSAL_SCHEMA_VERSION =
  "ioi.governed_runtime_improvement.v1" as const;
export const RUNTIME_GOVERNED_IMPROVEMENT_WORKFLOW_NODE_ID =
  "runtime.governed-improvement-proposal" as const;

export const RUNTIME_GOVERNED_IMPROVEMENT_SURFACES = [
  "skill",
  "module",
  "workflow",
  "route",
  "schema",
  "policy",
] as const;

export type RuntimeGovernedImprovementSurface =
  (typeof RUNTIME_GOVERNED_IMPROVEMENT_SURFACES)[number];

export interface RuntimeGovernedImprovementProposal extends Record<string, unknown> {
  schema_version: typeof RUNTIME_GOVERNED_IMPROVEMENT_PROPOSAL_SCHEMA_VERSION | string;
  proposal_id: string;
  target_ref: string;
  candidate_ref: string;
  surface: RuntimeGovernedImprovementSurface;
  source_trace_ref: string;
  eval_receipt_refs: string[];
  verifier_receipt_refs: string[];
  approval_ref: string;
  rollback_ref: string;
  agentgres_operation_ref: string;
  expected_heads: string[];
  state_root_before: string;
  state_root_after: string;
  resulting_head: string;
}

export interface RuntimeGovernedImprovementControlRequestBody {
  source: typeof RUNTIME_GOVERNED_IMPROVEMENT_SOURCE;
  actor: string;
  event_kind: typeof RUNTIME_GOVERNED_IMPROVEMENT_SOURCE_EVENT_KIND;
  eventKind: typeof RUNTIME_GOVERNED_IMPROVEMENT_SOURCE_EVENT_KIND;
  component_kind: typeof RUNTIME_GOVERNED_IMPROVEMENT_COMPONENT_KIND;
  componentKind: typeof RUNTIME_GOVERNED_IMPROVEMENT_COMPONENT_KIND;
  payload_schema_version: typeof RUNTIME_GOVERNED_IMPROVEMENT_PROPOSAL_SCHEMA_VERSION;
  payloadSchemaVersion: typeof RUNTIME_GOVERNED_IMPROVEMENT_PROPOSAL_SCHEMA_VERSION;
  workflow_graph_id: string | null;
  workflowGraphId: string | null;
  workflow_node_id: string;
  workflowNodeId: string;
  proposal_id: string;
  proposalId: string;
  target_ref: string;
  targetRef: string;
  candidate_ref: string;
  candidateRef: string;
  surface: RuntimeGovernedImprovementSurface;
  source_trace_ref: string;
  sourceTraceRef: string;
  eval_receipt_refs: string[];
  evalReceiptRefs: string[];
  verifier_receipt_refs: string[];
  verifierReceiptRefs: string[];
  approval_ref: string;
  approvalRef: string;
  rollback_ref: string;
  rollbackRef: string;
  agentgres_operation_ref: string;
  agentgresOperationRef: string;
  expected_heads: string[];
  expectedHeads: string[];
  state_root_before: string;
  stateRootBefore: string;
  state_root_after: string;
  stateRootAfter: string;
  resulting_head: string;
  resultingHead: string;
  approval_mode: "human_required";
  approvalMode: "human_required";
  proposal_only: true;
  proposalOnly: true;
  mutation_allowed: false;
  mutationAllowed: false;
  mutation_executed: false;
  mutationExecuted: false;
  proposal: RuntimeGovernedImprovementProposal;
  proposal_payload: RuntimeGovernedImprovementProposal;
  proposalPayload: RuntimeGovernedImprovementProposal;
}

export interface RuntimeGovernedImprovementControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_GOVERNED_IMPROVEMENT_CONTROL_SCHEMA_VERSION;
  nodeType: "governed_improvement_proposal";
  nodeId: string | null;
  threadId: string;
  proposalId: string;
  endpoint: string;
  method: "POST";
  body: RuntimeGovernedImprovementControlRequestBody;
}

export interface RuntimeGovernedImprovementControlRequestInput {
  nodeId?: string | null;
  input?: unknown;
  threadId?: string | null;
  threadIdField?: string | null;
  proposal?: Partial<RuntimeGovernedImprovementProposal> & Record<string, unknown>;
  proposalField?: string | null;
  proposalId?: string | null;
  targetRef?: string | null;
  candidateRef?: string | null;
  surface?: RuntimeGovernedImprovementSurface | string | null;
  sourceTraceRef?: string | null;
  evalReceiptRefs?: string[] | null;
  verifierReceiptRefs?: string[] | null;
  approvalRef?: string | null;
  rollbackRef?: string | null;
  agentgresOperationRef?: string | null;
  expectedHeads?: string[] | null;
  stateRootBefore?: string | null;
  stateRootAfter?: string | null;
  resultingHead?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeGovernedImprovementWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export function createRuntimeGovernedImprovementControlRequest(
  params: RuntimeGovernedImprovementControlRequestInput,
): RuntimeGovernedImprovementControlRequest {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error("governed improvement proposal controls need a threadId input before dispatch.");
  }

  const proposalSeed =
    objectRecord(params.proposal) ??
    objectAtPath(params.input, params.proposalField ?? "proposal") ??
    objectAtPath(params.input, "proposal_payload") ??
    objectAtPath(params.input, "proposalPayload") ??
    {};
  const schemaVersion =
    cleanString(proposalSeed.schema_version) ??
    cleanString(proposalSeed.schemaVersion) ??
    RUNTIME_GOVERNED_IMPROVEMENT_PROPOSAL_SCHEMA_VERSION;
  const proposalId = requiredString(
    cleanString(params.proposalId) ??
      stringField(proposalSeed, "proposal_id", "proposalId") ??
      stringAtPath(params.input, "proposal_id") ??
      stringAtPath(params.input, "proposalId"),
    "proposal_id",
  );
  const targetRef = requiredString(
    cleanString(params.targetRef) ??
      stringField(proposalSeed, "target_ref", "targetRef") ??
      stringAtPath(params.input, "target_ref") ??
      stringAtPath(params.input, "targetRef"),
    "target_ref",
  );
  const candidateRef = requiredString(
    cleanString(params.candidateRef) ??
      stringField(proposalSeed, "candidate_ref", "candidateRef") ??
      stringAtPath(params.input, "candidate_ref") ??
      stringAtPath(params.input, "candidateRef"),
    "candidate_ref",
  );
  const surface = requiredSurface(
    cleanString(params.surface) ??
      stringField(proposalSeed, "surface") ??
      stringAtPath(params.input, "surface"),
  );
  const sourceTraceRef = requiredString(
    cleanString(params.sourceTraceRef) ??
      stringField(proposalSeed, "source_trace_ref", "sourceTraceRef") ??
      stringAtPath(params.input, "source_trace_ref") ??
      stringAtPath(params.input, "sourceTraceRef"),
    "source_trace_ref",
  );
  const evalReceiptRefs = requiredStringArray(
    params.evalReceiptRefs ??
      stringArrayField(proposalSeed, "eval_receipt_refs", "evalReceiptRefs") ??
      stringArrayAtPath(params.input, "eval_receipt_refs") ??
      stringArrayAtPath(params.input, "evalReceiptRefs"),
    "eval_receipt_refs",
  );
  const verifierReceiptRefs = requiredStringArray(
    params.verifierReceiptRefs ??
      stringArrayField(proposalSeed, "verifier_receipt_refs", "verifierReceiptRefs") ??
      stringArrayAtPath(params.input, "verifier_receipt_refs") ??
      stringArrayAtPath(params.input, "verifierReceiptRefs"),
    "verifier_receipt_refs",
  );
  const approvalRef = requiredString(
    cleanString(params.approvalRef) ??
      stringField(proposalSeed, "approval_ref", "approvalRef") ??
      stringAtPath(params.input, "approval_ref") ??
      stringAtPath(params.input, "approvalRef"),
    "approval_ref",
  );
  const rollbackRef = requiredString(
    cleanString(params.rollbackRef) ??
      stringField(proposalSeed, "rollback_ref", "rollbackRef") ??
      stringAtPath(params.input, "rollback_ref") ??
      stringAtPath(params.input, "rollbackRef"),
    "rollback_ref",
  );
  const agentgresOperationRef = requiredString(
    cleanString(params.agentgresOperationRef) ??
      stringField(proposalSeed, "agentgres_operation_ref", "agentgresOperationRef") ??
      stringAtPath(params.input, "agentgres_operation_ref") ??
      stringAtPath(params.input, "agentgresOperationRef"),
    "agentgres_operation_ref",
  );
  const expectedHeads = requiredStringArray(
    params.expectedHeads ??
      stringArrayField(proposalSeed, "expected_heads", "expectedHeads") ??
      stringArrayAtPath(params.input, "expected_heads") ??
      stringArrayAtPath(params.input, "expectedHeads"),
    "expected_heads",
  );
  const stateRootBefore = requiredString(
    cleanString(params.stateRootBefore) ??
      stringField(proposalSeed, "state_root_before", "stateRootBefore") ??
      stringAtPath(params.input, "state_root_before") ??
      stringAtPath(params.input, "stateRootBefore"),
    "state_root_before",
  );
  const stateRootAfter = requiredString(
    cleanString(params.stateRootAfter) ??
      stringField(proposalSeed, "state_root_after", "stateRootAfter") ??
      stringAtPath(params.input, "state_root_after") ??
      stringAtPath(params.input, "stateRootAfter"),
    "state_root_after",
  );
  const resultingHead = requiredString(
    cleanString(params.resultingHead) ??
      stringField(proposalSeed, "resulting_head", "resultingHead") ??
      stringAtPath(params.input, "resulting_head") ??
      stringAtPath(params.input, "resultingHead"),
    "resulting_head",
  );
  const workflowGraphId = cleanString(params.workflowGraphId) ?? null;
  const workflowNodeId =
    cleanString(params.workflowNodeId) ??
    `${RUNTIME_GOVERNED_IMPROVEMENT_WORKFLOW_NODE_ID}.${safeId(proposalId)}`;
  const proposal: RuntimeGovernedImprovementProposal = {
    ...proposalSeed,
    schema_version: schemaVersion,
    proposal_id: proposalId,
    target_ref: targetRef,
    candidate_ref: candidateRef,
    surface,
    source_trace_ref: sourceTraceRef,
    eval_receipt_refs: evalReceiptRefs,
    verifier_receipt_refs: verifierReceiptRefs,
    approval_ref: approvalRef,
    rollback_ref: rollbackRef,
    agentgres_operation_ref: agentgresOperationRef,
    expected_heads: expectedHeads,
    state_root_before: stateRootBefore,
    state_root_after: stateRootAfter,
    resulting_head: resultingHead,
  };

  return {
    schemaVersion: WORKFLOW_RUNTIME_GOVERNED_IMPROVEMENT_CONTROL_SCHEMA_VERSION,
    nodeType: "governed_improvement_proposal",
    nodeId: params.nodeId ?? null,
    threadId,
    proposalId,
    endpoint: `/v1/threads/${encodeSegment(threadId)}/governed-improvement-proposals`,
    method: "POST",
    body: {
      source: RUNTIME_GOVERNED_IMPROVEMENT_SOURCE,
      actor: cleanString(params.actor) ?? "workflow-author",
      event_kind: RUNTIME_GOVERNED_IMPROVEMENT_SOURCE_EVENT_KIND,
      eventKind: RUNTIME_GOVERNED_IMPROVEMENT_SOURCE_EVENT_KIND,
      component_kind: RUNTIME_GOVERNED_IMPROVEMENT_COMPONENT_KIND,
      componentKind: RUNTIME_GOVERNED_IMPROVEMENT_COMPONENT_KIND,
      payload_schema_version: RUNTIME_GOVERNED_IMPROVEMENT_PROPOSAL_SCHEMA_VERSION,
      payloadSchemaVersion: RUNTIME_GOVERNED_IMPROVEMENT_PROPOSAL_SCHEMA_VERSION,
      workflow_graph_id: workflowGraphId,
      workflowGraphId,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      proposal_id: proposalId,
      proposalId,
      target_ref: targetRef,
      targetRef,
      candidate_ref: candidateRef,
      candidateRef,
      surface,
      source_trace_ref: sourceTraceRef,
      sourceTraceRef,
      eval_receipt_refs: evalReceiptRefs,
      evalReceiptRefs,
      verifier_receipt_refs: verifierReceiptRefs,
      verifierReceiptRefs,
      approval_ref: approvalRef,
      approvalRef,
      rollback_ref: rollbackRef,
      rollbackRef,
      agentgres_operation_ref: agentgresOperationRef,
      agentgresOperationRef,
      expected_heads: expectedHeads,
      expectedHeads,
      state_root_before: stateRootBefore,
      stateRootBefore,
      state_root_after: stateRootAfter,
      stateRootAfter,
      resulting_head: resultingHead,
      resultingHead,
      approval_mode: "human_required",
      approvalMode: "human_required",
      proposal_only: true,
      proposalOnly: true,
      mutation_allowed: false,
      mutationAllowed: false,
      mutation_executed: false,
      mutationExecuted: false,
      proposal,
      proposal_payload: proposal,
      proposalPayload: proposal,
    },
  };
}

export function createRuntimeGovernedImprovementControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeGovernedImprovementWorkflowNodeOptions = {},
): RuntimeGovernedImprovementControlRequest {
  const logic = workflowNodeLogic(node);
  const proposal =
    objectField(logic, "governedImprovement") ??
    objectField(logic, "runtimeImprovementProposal") ??
    objectField(logic, "proposal") ??
    {};
  return createRuntimeGovernedImprovementControlRequest({
    nodeId: node.id,
    input,
    threadIdField: "threadId",
    proposal,
    workflowGraphId: options.workflowGraphId,
    workflowNodeId:
      stringField(logic, "workflowNodeId", "workflow_node_id") ??
      `${RUNTIME_GOVERNED_IMPROVEMENT_WORKFLOW_NODE_ID}.${safeId(node.id)}`,
    actor: options.actor,
  });
}

function workflowNodeLogic(node: Pick<Node, "config">): NodeLogic {
  const logic = node.config?.logic;
  return logic && typeof logic === "object" ? (logic as NodeLogic) : {};
}

function requiredString(value: string | null, field: string): string {
  if (value) return value;
  throw new Error(`governed improvement proposal controls need ${field} before dispatch.`);
}

function requiredStringArray(values: string[] | null | undefined, field: string): string[] {
  const normalized = uniqueStrings(values ?? []);
  if (normalized.length > 0) return normalized;
  throw new Error(`governed improvement proposal controls need ${field} before dispatch.`);
}

function requiredSurface(value: string | null): RuntimeGovernedImprovementSurface {
  if (RUNTIME_GOVERNED_IMPROVEMENT_SURFACES.includes(value as RuntimeGovernedImprovementSurface)) {
    return value as RuntimeGovernedImprovementSurface;
  }
  throw new Error("governed improvement proposal controls need a canonical surface before dispatch.");
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
