import type { Node, NodeLogic } from "../types/graph";

export const WORKFLOW_RUNTIME_L1_SETTLEMENT_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-l1-settlement-control.v1" as const;
export const RUNTIME_L1_SETTLEMENT_SOURCE = "react_flow" as const;
export const RUNTIME_L1_SETTLEMENT_SOURCE_EVENT_KIND =
  "L1Settlement.AttemptAdmitted" as const;
export const RUNTIME_L1_SETTLEMENT_COMPONENT_KIND =
  "l1_settlement_attempt" as const;
export const RUNTIME_L1_SETTLEMENT_ATTEMPT_SCHEMA_VERSION =
  "ioi.l1_settlement_admission.v1" as const;
export const RUNTIME_L1_SETTLEMENT_WORKFLOW_NODE_ID =
  "runtime.l1-settlement-attempt" as const;

const RETIRED_L1_SETTLEMENT_CONTROL_INPUT_FIELDS = [
  "workflowGraphId",
  "workflowNodeId",
] as const;

export interface RuntimeL1SettlementAttempt extends Record<string, unknown> {
  schema_version: typeof RUNTIME_L1_SETTLEMENT_ATTEMPT_SCHEMA_VERSION | string;
  settlement_ref: string;
  domain_ref: string;
  state_root_ref: string;
  trigger_refs: string[];
  receipt_refs: string[];
}

export interface RuntimeL1SettlementControlRequestBody {
  source: typeof RUNTIME_L1_SETTLEMENT_SOURCE;
  actor: string;
  event_kind: typeof RUNTIME_L1_SETTLEMENT_SOURCE_EVENT_KIND;
  component_kind: typeof RUNTIME_L1_SETTLEMENT_COMPONENT_KIND;
  payload_schema_version: typeof RUNTIME_L1_SETTLEMENT_ATTEMPT_SCHEMA_VERSION;
  workflow_graph_id: string | null;
  workflow_node_id: string;
  settlement_ref: string;
  domain_ref: string;
  state_root_ref: string;
  trigger_refs: string[];
  receipt_refs: string[];
  admission_only: true;
  direct_truth_write_allowed: false;
  mutation_allowed: false;
  default_runtime_settlement_allowed: false;
  settlement_trigger_checked_by_rust: true;
  attempt: RuntimeL1SettlementAttempt;
}

export interface RuntimeL1SettlementControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_L1_SETTLEMENT_CONTROL_SCHEMA_VERSION;
  nodeType: "l1_settlement_attempt";
  nodeId: string | null;
  threadId: string;
  settlementRef: string;
  endpoint: string;
  method: "POST";
  body: RuntimeL1SettlementControlRequestBody;
}

export interface RuntimeL1SettlementControlRequestInput {
  nodeId?: string | null;
  input?: unknown;
  threadId?: string | null;
  threadIdField?: string | null;
  attempt?: Partial<RuntimeL1SettlementAttempt> & Record<string, unknown>;
  attemptField?: string | null;
  settlementRef?: string | null;
  domainRef?: string | null;
  stateRootRef?: string | null;
  triggerRefs?: string[] | null;
  receiptRefs?: string[] | null;
  workflow_graph_id?: string | null;
  workflow_node_id?: string | null;
  actor?: string | null;
}

export interface RuntimeL1SettlementWorkflowNodeOptions {
  workflow_graph_id?: string | null;
  actor?: string | null;
}

export function createRuntimeL1SettlementControlRequest(
  params: RuntimeL1SettlementControlRequestInput,
): RuntimeL1SettlementControlRequest {
  assertNoRetiredL1SettlementControlInputAliases(params);
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "thread_id") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error("L1 settlement controls need a threadId input before dispatch.");
  }

  const attemptSeed =
    objectRecord(params.attempt) ??
    objectAtPath(params.input, params.attemptField ?? "attempt") ??
    objectAtPath(params.input, "settlement_attempt") ??
    {};
  const schemaVersion =
    cleanString(attemptSeed.schema_version) ??
    RUNTIME_L1_SETTLEMENT_ATTEMPT_SCHEMA_VERSION;
  const settlementRef = requiredString(
    cleanString(params.settlementRef) ??
      stringField(attemptSeed, "settlement_ref") ??
      stringAtPath(params.input, "settlement_ref") ??
      null,
    "settlement_ref",
  );
  const domainRef = requiredString(
    cleanString(params.domainRef) ??
      stringField(attemptSeed, "domain_ref") ??
      stringAtPath(params.input, "domain_ref") ??
      null,
    "domain_ref",
  );
  const stateRootRef = requiredString(
    cleanString(params.stateRootRef) ??
      stringField(attemptSeed, "state_root_ref") ??
      stringAtPath(params.input, "state_root_ref") ??
      null,
    "state_root_ref",
  );
  const triggerRefs = requiredStringArray(
    params.triggerRefs ??
      stringArrayField(attemptSeed, "trigger_refs") ??
      stringArrayAtPath(params.input, "trigger_refs") ??
      null,
    "trigger_refs",
  );
  const receiptRefs = requiredStringArray(
    params.receiptRefs ??
      stringArrayField(attemptSeed, "receipt_refs") ??
      stringArrayAtPath(params.input, "receipt_refs") ??
      null,
    "receipt_refs",
  );
  const workflowGraphId = cleanString(params.workflow_graph_id) ?? null;
  const workflowNodeId =
    cleanString(params.workflow_node_id) ??
    `${RUNTIME_L1_SETTLEMENT_WORKFLOW_NODE_ID}.${safeId(settlementRef)}`;
  const attempt: RuntimeL1SettlementAttempt = {
    ...attemptSeed,
    schema_version: schemaVersion,
    settlement_ref: settlementRef,
    domain_ref: domainRef,
    state_root_ref: stateRootRef,
    trigger_refs: triggerRefs,
    receipt_refs: receiptRefs,
  };

  return {
    schemaVersion: WORKFLOW_RUNTIME_L1_SETTLEMENT_CONTROL_SCHEMA_VERSION,
    nodeType: "l1_settlement_attempt",
    nodeId: params.nodeId ?? null,
    threadId,
    settlementRef,
    endpoint: `/v1/threads/${encodeSegment(threadId)}/l1-settlement-attempts`,
    method: "POST",
    body: {
      source: RUNTIME_L1_SETTLEMENT_SOURCE,
      actor: cleanString(params.actor) ?? "workflow-author",
      event_kind: RUNTIME_L1_SETTLEMENT_SOURCE_EVENT_KIND,
      component_kind: RUNTIME_L1_SETTLEMENT_COMPONENT_KIND,
      payload_schema_version: RUNTIME_L1_SETTLEMENT_ATTEMPT_SCHEMA_VERSION,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      settlement_ref: settlementRef,
      domain_ref: domainRef,
      state_root_ref: stateRootRef,
      trigger_refs: triggerRefs,
      receipt_refs: receiptRefs,
      admission_only: true,
      direct_truth_write_allowed: false,
      mutation_allowed: false,
      default_runtime_settlement_allowed: false,
      settlement_trigger_checked_by_rust: true,
      attempt,
    },
  };
}

export function createRuntimeL1SettlementControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeL1SettlementWorkflowNodeOptions = {},
): RuntimeL1SettlementControlRequest {
  assertNoRetiredL1SettlementWorkflowNodeOptionAliases(options);
  const logic = workflowNodeLogic(node);
  const attempt =
    objectField(logic, "l1Settlement") ??
    objectField(logic, "settlement_attempt") ??
    objectField(logic, "attempt") ??
    {};
  return createRuntimeL1SettlementControlRequest({
    nodeId: node.id,
    input,
    threadIdField: "thread_id",
    attempt,
    workflow_graph_id: options.workflow_graph_id,
    workflow_node_id:
      stringField(logic, "workflow_node_id") ??
      `${RUNTIME_L1_SETTLEMENT_WORKFLOW_NODE_ID}.${safeId(node.id)}`,
    actor: options.actor,
  });
}

function workflowNodeLogic(node: Pick<Node, "config">): NodeLogic {
  const logic = node.config?.logic;
  return logic && typeof logic === "object" ? (logic as NodeLogic) : {};
}

function requiredString(value: string | null, field: string): string {
  if (value) return value;
  throw new Error(`L1 settlement controls need ${field} before dispatch.`);
}

function requiredStringArray(values: string[] | null | undefined, field: string): string[] {
  const normalized = uniqueStrings(values ?? []);
  if (normalized.length > 0) return normalized;
  throw new Error(`L1 settlement controls need ${field} before dispatch.`);
}

function assertNoRetiredL1SettlementControlInputAliases(
  input: RuntimeL1SettlementControlRequestInput,
): void {
  const record = input as unknown as Record<string, unknown>;
  const retiredAliases = RETIRED_L1_SETTLEMENT_CONTROL_INPUT_FIELDS.filter((field) =>
    Object.prototype.hasOwnProperty.call(record, field),
  );
  if (retiredAliases.length === 0) return;
  throw new Error(
    `L1 settlement controls no longer accept retired control input aliases: ${retiredAliases.join(", ")}`,
  );
}

function assertNoRetiredL1SettlementWorkflowNodeOptionAliases(
  options: RuntimeL1SettlementWorkflowNodeOptions,
): void {
  const record = options as unknown as Record<string, unknown>;
  const retiredAliases = RETIRED_L1_SETTLEMENT_CONTROL_INPUT_FIELDS.filter((field) =>
    Object.prototype.hasOwnProperty.call(record, field),
  );
  if (retiredAliases.length === 0) return;
  throw new Error(
    `L1 settlement workflow node options no longer accept retired control input aliases: ${retiredAliases.join(", ")}`,
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
