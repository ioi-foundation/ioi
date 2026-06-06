import type { Node, NodeLogic } from "../types/graph";

export const WORKFLOW_RUNTIME_WORKER_SERVICE_PACKAGE_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-worker-service-package-control.v1" as const;
export const RUNTIME_WORKER_SERVICE_PACKAGE_SOURCE = "react_flow" as const;
export const RUNTIME_WORKER_SERVICE_PACKAGE_SOURCE_EVENT_KIND =
  "WorkerServicePackage.InvocationAdmitted" as const;
export const RUNTIME_WORKER_SERVICE_PACKAGE_COMPONENT_KIND =
  "worker_service_package_invocation" as const;
export const RUNTIME_WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION =
  "ioi.worker_service_package_invocation.v1" as const;
export const RUNTIME_WORKER_SERVICE_PACKAGE_WORKFLOW_NODE_ID =
  "runtime.worker-service-package-invocation" as const;

export const RUNTIME_WORKER_SERVICE_PACKAGE_KINDS = [
  "worker_package",
  "service_package",
] as const;

export type RuntimeWorkerServicePackageKind =
  (typeof RUNTIME_WORKER_SERVICE_PACKAGE_KINDS)[number];

export interface RuntimeWorkerServicePackageInvocation extends Record<string, unknown> {
  schema_version: typeof RUNTIME_WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION | string;
  package_kind: RuntimeWorkerServicePackageKind;
  package_ref: string;
  manifest_ref: string;
  invocation: Record<string, unknown>;
  result: Record<string, unknown>;
  expected_heads: string[];
}

export interface RuntimeWorkerServicePackageControlRequestBody {
  source: typeof RUNTIME_WORKER_SERVICE_PACKAGE_SOURCE;
  actor: string;
  event_kind: typeof RUNTIME_WORKER_SERVICE_PACKAGE_SOURCE_EVENT_KIND;
  component_kind: typeof RUNTIME_WORKER_SERVICE_PACKAGE_COMPONENT_KIND;
  payload_schema_version: typeof RUNTIME_WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION;
  workflow_graph_id: string | null;
  workflow_node_id: string;
  package_kind: RuntimeWorkerServicePackageKind;
  package_ref: string;
  manifest_ref: string;
  invocation_id: string;
  expected_heads: string[];
  admission_only: true;
  direct_truth_write_allowed: false;
  mutation_allowed: false;
  invocation: RuntimeWorkerServicePackageInvocation;
}

export interface RuntimeWorkerServicePackageControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_WORKER_SERVICE_PACKAGE_CONTROL_SCHEMA_VERSION;
  nodeType: "worker_service_package_invocation";
  nodeId: string | null;
  threadId: string;
  invocationId: string;
  endpoint: string;
  method: "POST";
  body: RuntimeWorkerServicePackageControlRequestBody;
}

export interface RuntimeWorkerServicePackageControlRequestInput {
  nodeId?: string | null;
  input?: unknown;
  threadId?: string | null;
  threadIdField?: string | null;
  packageInvocation?: Partial<RuntimeWorkerServicePackageInvocation> & Record<string, unknown>;
  packageInvocationField?: string | null;
  packageKind?: RuntimeWorkerServicePackageKind | string | null;
  packageRef?: string | null;
  manifestRef?: string | null;
  stepModuleInvocation?: Record<string, unknown> | null;
  result?: Record<string, unknown> | null;
  expectedHeads?: string[] | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeWorkerServicePackageWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export function createRuntimeWorkerServicePackageControlRequest(
  params: RuntimeWorkerServicePackageControlRequestInput,
): RuntimeWorkerServicePackageControlRequest {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error("worker/service package controls need a threadId input before dispatch.");
  }

  const packageSeed =
    objectRecord(params.packageInvocation) ??
    objectAtPath(params.input, params.packageInvocationField ?? "invocation") ??
    objectAtPath(params.input, "package_invocation") ??
    objectAtPath(params.input, "packageInvocation") ??
    {};
  const schemaVersion =
    cleanString(packageSeed.schema_version) ??
    cleanString(packageSeed.schemaVersion) ??
    RUNTIME_WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION;
  const packageKind = requiredPackageKind(
    cleanString(params.packageKind) ??
      stringField(packageSeed, "package_kind", "packageKind") ??
      stringAtPath(params.input, "package_kind") ??
      stringAtPath(params.input, "packageKind"),
  );
  const packageRef = requiredString(
    cleanString(params.packageRef) ??
      stringField(packageSeed, "package_ref", "packageRef") ??
      stringAtPath(params.input, "package_ref") ??
      stringAtPath(params.input, "packageRef"),
    "package_ref",
  );
  const manifestRef = requiredString(
    cleanString(params.manifestRef) ??
      stringField(packageSeed, "manifest_ref", "manifestRef") ??
      stringAtPath(params.input, "manifest_ref") ??
      stringAtPath(params.input, "manifestRef"),
    "manifest_ref",
  );
  const stepModuleInvocation = requiredObject(
    params.stepModuleInvocation ??
      objectField(packageSeed, "invocation") ??
      objectField(packageSeed, "stepModuleInvocation") ??
      objectAtPath(params.input, "step_module_invocation") ??
      objectAtPath(params.input, "stepModuleInvocation"),
    "invocation",
  );
  const result = requiredObject(
    params.result ??
      objectField(packageSeed, "result") ??
      objectAtPath(params.input, "result"),
    "result",
  );
  const expectedHeads = requiredStringArray(
    params.expectedHeads ??
      stringArrayField(packageSeed, "expected_heads", "expectedHeads") ??
      stringArrayAtPath(params.input, "expected_heads") ??
      stringArrayAtPath(params.input, "expectedHeads"),
    "expected_heads",
  );
  const invocationId = requiredString(
    stringField(stepModuleInvocation, "invocation_id", "invocationId"),
    "invocation.invocation_id",
  );
  const workflowGraphId = cleanString(params.workflowGraphId) ?? null;
  const workflowNodeId =
    cleanString(params.workflowNodeId) ??
    `${RUNTIME_WORKER_SERVICE_PACKAGE_WORKFLOW_NODE_ID}.${safeId(invocationId)}`;
  const invocation: RuntimeWorkerServicePackageInvocation = {
    ...packageSeed,
    schema_version: schemaVersion,
    package_kind: packageKind,
    package_ref: packageRef,
    manifest_ref: manifestRef,
    invocation: stepModuleInvocation,
    result,
    expected_heads: expectedHeads,
  };

  return {
    schemaVersion: WORKFLOW_RUNTIME_WORKER_SERVICE_PACKAGE_CONTROL_SCHEMA_VERSION,
    nodeType: "worker_service_package_invocation",
    nodeId: params.nodeId ?? null,
    threadId,
    invocationId,
    endpoint: `/v1/threads/${encodeSegment(threadId)}/worker-service-package-invocations`,
    method: "POST",
    body: {
      source: RUNTIME_WORKER_SERVICE_PACKAGE_SOURCE,
      actor: cleanString(params.actor) ?? "workflow-author",
      event_kind: RUNTIME_WORKER_SERVICE_PACKAGE_SOURCE_EVENT_KIND,
      component_kind: RUNTIME_WORKER_SERVICE_PACKAGE_COMPONENT_KIND,
      payload_schema_version: RUNTIME_WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      package_kind: packageKind,
      package_ref: packageRef,
      manifest_ref: manifestRef,
      invocation_id: invocationId,
      expected_heads: expectedHeads,
      admission_only: true,
      direct_truth_write_allowed: false,
      mutation_allowed: false,
      invocation,
    },
  };
}

export function createRuntimeWorkerServicePackageControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeWorkerServicePackageWorkflowNodeOptions = {},
): RuntimeWorkerServicePackageControlRequest {
  const logic = workflowNodeLogic(node);
  const packageInvocation =
    objectField(logic, "workerServicePackage") ??
    objectField(logic, "packageInvocation") ??
    objectField(logic, "invocation") ??
    {};
  return createRuntimeWorkerServicePackageControlRequest({
    nodeId: node.id,
    input,
    threadIdField: "threadId",
    packageInvocation,
    workflowGraphId: options.workflowGraphId,
    workflowNodeId:
      stringField(logic, "workflowNodeId", "workflow_node_id") ??
      `${RUNTIME_WORKER_SERVICE_PACKAGE_WORKFLOW_NODE_ID}.${safeId(node.id)}`,
    actor: options.actor,
  });
}

function workflowNodeLogic(node: Pick<Node, "config">): NodeLogic {
  const logic = node.config?.logic;
  return logic && typeof logic === "object" ? (logic as NodeLogic) : {};
}

function requiredString(value: string | null, field: string): string {
  if (value) return value;
  throw new Error(`worker/service package controls need ${field} before dispatch.`);
}

function requiredStringArray(values: string[] | null | undefined, field: string): string[] {
  const normalized = uniqueStrings(values ?? []);
  if (normalized.length > 0) return normalized;
  throw new Error(`worker/service package controls need ${field} before dispatch.`);
}

function requiredPackageKind(value: string | null): RuntimeWorkerServicePackageKind {
  if (RUNTIME_WORKER_SERVICE_PACKAGE_KINDS.includes(value as RuntimeWorkerServicePackageKind)) {
    return value as RuntimeWorkerServicePackageKind;
  }
  throw new Error("worker/service package controls need package_kind before dispatch.");
}

function requiredObject(value: Record<string, unknown> | null | undefined, field: string): Record<string, unknown> {
  if (value && Object.keys(value).length > 0) return value;
  throw new Error(`worker/service package controls need ${field} before dispatch.`);
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
