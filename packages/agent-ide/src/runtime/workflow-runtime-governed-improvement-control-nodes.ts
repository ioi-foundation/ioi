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

const RETIRED_GOVERNED_IMPROVEMENT_PROPOSAL_INPUT_FIELDS = [
  "proposal_payload",
  "proposalPayload",
] as const;

const RETIRED_GOVERNED_IMPROVEMENT_PROPOSAL_PAYLOAD_FIELDS = [
  "schemaVersion",
  "proposalId",
  "targetRef",
  "candidateRef",
  "sourceTraceRef",
  "evalReceiptRefs",
  "verifierReceiptRefs",
  "approvalRef",
  "rollbackRef",
  "agentgresOperationRef",
  "expectedHeads",
  "stateRootBefore",
  "stateRootAfter",
  "resultingHead",
] as const;

const RETIRED_GOVERNED_IMPROVEMENT_PROPOSAL_TRUTH_FIELDS = [
  "agentgres_operation_ref",
  "expected_heads",
  "state_root_before",
  "state_root_after",
  "resulting_head",
] as const;

const RETIRED_GOVERNED_IMPROVEMENT_WORKFLOW_LOGIC_FIELDS = [
  "governedImprovement",
  "runtimeImprovementProposal",
  "workflowNodeId",
] as const;

const RETIRED_GOVERNED_IMPROVEMENT_CONTROL_INPUT_FIELDS = [
  "workflowGraphId",
  "workflowNodeId",
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
}

export interface RuntimeGovernedImprovementControlRequestBody {
  source: typeof RUNTIME_GOVERNED_IMPROVEMENT_SOURCE;
  actor: string;
  event_kind: typeof RUNTIME_GOVERNED_IMPROVEMENT_SOURCE_EVENT_KIND;
  component_kind: typeof RUNTIME_GOVERNED_IMPROVEMENT_COMPONENT_KIND;
  payload_schema_version: typeof RUNTIME_GOVERNED_IMPROVEMENT_PROPOSAL_SCHEMA_VERSION;
  workflow_graph_id: string | null;
  workflow_node_id: string;
  proposal_id: string;
  target_ref: string;
  candidate_ref: string;
  surface: RuntimeGovernedImprovementSurface;
  source_trace_ref: string;
  eval_receipt_refs: string[];
  verifier_receipt_refs: string[];
  approval_ref: string;
  rollback_ref: string;
  approval_mode: "human_required";
  proposal_only: true;
  mutation_allowed: false;
  mutation_executed: false;
  proposal: RuntimeGovernedImprovementProposal;
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
  workflow_graph_id?: string | null;
  workflow_node_id?: string | null;
  actor?: string | null;
}

export interface RuntimeGovernedImprovementWorkflowNodeOptions {
  workflow_graph_id?: string | null;
  actor?: string | null;
}

export function createRuntimeGovernedImprovementControlRequest(
  params: RuntimeGovernedImprovementControlRequestInput,
): RuntimeGovernedImprovementControlRequest {
  assertNoRetiredGovernedImprovementControlInputAliases(params);
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error("governed improvement proposal controls need a threadId input before dispatch.");
  }

  const proposalField = params.proposalField ?? "proposal";
  assertCanonicalGovernedImprovementProposalInputField(proposalField);
  const proposalSeed =
    objectRecord(params.proposal) ??
    objectAtPath(params.input, proposalField) ??
    {};
  assertCanonicalGovernedImprovementProposalPayload(proposalSeed);
  assertCanonicalGovernedImprovementProposalPayload(params.input);
  const schemaVersion =
    cleanString(proposalSeed.schema_version) ??
    RUNTIME_GOVERNED_IMPROVEMENT_PROPOSAL_SCHEMA_VERSION;
  const proposalId = requiredString(
    cleanString(params.proposalId) ??
      stringField(proposalSeed, "proposal_id") ??
      stringAtPath(params.input, "proposal_id"),
    "proposal_id",
  );
  const targetRef = requiredString(
    cleanString(params.targetRef) ??
      stringField(proposalSeed, "target_ref") ??
      stringAtPath(params.input, "target_ref"),
    "target_ref",
  );
  const candidateRef = requiredString(
    cleanString(params.candidateRef) ??
      stringField(proposalSeed, "candidate_ref") ??
      stringAtPath(params.input, "candidate_ref"),
    "candidate_ref",
  );
  const surface = requiredSurface(
    cleanString(params.surface) ??
      stringField(proposalSeed, "surface") ??
      stringAtPath(params.input, "surface"),
  );
  const sourceTraceRef = requiredString(
    cleanString(params.sourceTraceRef) ??
      stringField(proposalSeed, "source_trace_ref") ??
      stringAtPath(params.input, "source_trace_ref"),
    "source_trace_ref",
  );
  const evalReceiptRefs = requiredStringArray(
    params.evalReceiptRefs ??
      stringArrayField(proposalSeed, "eval_receipt_refs") ??
      stringArrayAtPath(params.input, "eval_receipt_refs"),
    "eval_receipt_refs",
  );
  const verifierReceiptRefs = requiredStringArray(
    params.verifierReceiptRefs ??
      stringArrayField(proposalSeed, "verifier_receipt_refs") ??
      stringArrayAtPath(params.input, "verifier_receipt_refs"),
    "verifier_receipt_refs",
  );
  const approvalRef = requiredString(
    cleanString(params.approvalRef) ??
      stringField(proposalSeed, "approval_ref") ??
      stringAtPath(params.input, "approval_ref"),
    "approval_ref",
  );
  const rollbackRef = requiredString(
    cleanString(params.rollbackRef) ??
      stringField(proposalSeed, "rollback_ref") ??
      stringAtPath(params.input, "rollback_ref"),
    "rollback_ref",
  );
  const workflowGraphId = cleanString(params.workflow_graph_id) ?? null;
  const workflowNodeId =
    cleanString(params.workflow_node_id) ??
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
      component_kind: RUNTIME_GOVERNED_IMPROVEMENT_COMPONENT_KIND,
      payload_schema_version: RUNTIME_GOVERNED_IMPROVEMENT_PROPOSAL_SCHEMA_VERSION,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      proposal_id: proposalId,
      target_ref: targetRef,
      candidate_ref: candidateRef,
      surface,
      source_trace_ref: sourceTraceRef,
      eval_receipt_refs: evalReceiptRefs,
      verifier_receipt_refs: verifierReceiptRefs,
      approval_ref: approvalRef,
      rollback_ref: rollbackRef,
      approval_mode: "human_required",
      proposal_only: true,
      mutation_allowed: false,
      mutation_executed: false,
      proposal,
    },
  };
}

export function createRuntimeGovernedImprovementControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeGovernedImprovementWorkflowNodeOptions = {},
): RuntimeGovernedImprovementControlRequest {
  assertNoRetiredGovernedImprovementWorkflowNodeOptionAliases(options);
  const logic = workflowNodeLogic(node);
  assertCanonicalGovernedImprovementWorkflowLogic(logic);
  const proposal = objectField(logic, "proposal") ?? {};
  return createRuntimeGovernedImprovementControlRequest({
    nodeId: node.id,
    input,
    threadIdField: "threadId",
    proposal,
    workflow_graph_id: options.workflow_graph_id,
    workflow_node_id:
      stringField(logic, "workflow_node_id") ??
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

function assertCanonicalGovernedImprovementProposalInputField(field: string): void {
  if (
    RETIRED_GOVERNED_IMPROVEMENT_PROPOSAL_INPUT_FIELDS.includes(
      field as (typeof RETIRED_GOVERNED_IMPROVEMENT_PROPOSAL_INPUT_FIELDS)[number],
    )
  ) {
    throw new Error(
      "governed improvement proposal controls no longer accept retired proposal input field aliases; use proposal.",
    );
  }
}

function assertCanonicalGovernedImprovementProposalPayload(source: unknown): void {
  const record = objectRecord(source);
  if (!record) return;
  const retiredAliases = RETIRED_GOVERNED_IMPROVEMENT_PROPOSAL_PAYLOAD_FIELDS.filter(
    (field) => Object.prototype.hasOwnProperty.call(record, field),
  );
  const retiredTruthFields = RETIRED_GOVERNED_IMPROVEMENT_PROPOSAL_TRUTH_FIELDS.filter(
    (field) => Object.prototype.hasOwnProperty.call(record, field),
  );
  const retiredFields = [...retiredAliases, ...retiredTruthFields];
  if (retiredFields.length === 0) return;
  throw new Error(
    `governed improvement proposal controls no longer accept retired proposal payload aliases: ${retiredFields.join(", ")}`,
  );
}

function assertCanonicalGovernedImprovementWorkflowLogic(logic: NodeLogic): void {
  const retiredAliases = RETIRED_GOVERNED_IMPROVEMENT_WORKFLOW_LOGIC_FIELDS.filter((field) =>
    Object.prototype.hasOwnProperty.call(logic, field),
  );
  if (retiredAliases.length === 0) return;
  throw new Error(
    `governed improvement workflow nodes no longer accept retired logic aliases: ${retiredAliases.join(", ")}`,
  );
}

function assertNoRetiredGovernedImprovementControlInputAliases(
  input: RuntimeGovernedImprovementControlRequestInput,
): void {
  const record = input as unknown as Record<string, unknown>;
  const retiredAliases = RETIRED_GOVERNED_IMPROVEMENT_CONTROL_INPUT_FIELDS.filter((field) =>
    Object.prototype.hasOwnProperty.call(record, field),
  );
  if (retiredAliases.length === 0) return;
  throw new Error(
    `governed improvement proposal controls no longer accept retired control input aliases: ${retiredAliases.join(", ")}`,
  );
}

function assertNoRetiredGovernedImprovementWorkflowNodeOptionAliases(
  options: RuntimeGovernedImprovementWorkflowNodeOptions,
): void {
  const record = options as unknown as Record<string, unknown>;
  const retiredAliases = RETIRED_GOVERNED_IMPROVEMENT_CONTROL_INPUT_FIELDS.filter((field) =>
    Object.prototype.hasOwnProperty.call(record, field),
  );
  if (retiredAliases.length === 0) return;
  throw new Error(
    `governed improvement workflow node options no longer accept retired control input aliases: ${retiredAliases.join(", ")}`,
  );
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
