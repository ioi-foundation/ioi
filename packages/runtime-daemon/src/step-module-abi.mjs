import crypto from "node:crypto";

export const STEP_MODULE_INVOCATION_SCHEMA_VERSION = "ioi.step_module_invocation.v1";
export const STEP_MODULE_RESULT_SCHEMA_VERSION = "ioi.step_module_result.v1";

const DEFAULT_RUN_ID = "run:projection";
const DEFAULT_TASK_ID = "task:projection";
const DEFAULT_WORKFLOW_GRAPH_ID = "workflow:projection";
const DEFAULT_RUNTIME_NODE_REF = "node://local";
const DEFAULT_ACTOR_ID = "runtime:hypervisor-daemon";
const DEFAULT_POLICY_HASH = "sha256:projection-policy";

export function stableStepModuleJson(value) {
  return JSON.stringify(sortJsonValue(value));
}

export function stepModuleHash(value) {
  return `sha256:${crypto.createHash("sha256").update(stableStepModuleJson(value)).digest("hex")}`;
}

export function createStepModuleInvocationForCodingTool({
  contract,
  toolId = contract?.stable_tool_id,
  input = {},
  run_id = DEFAULT_RUN_ID,
  task_id = DEFAULT_TASK_ID,
  thread_id = null,
  workflow_graph_id = DEFAULT_WORKFLOW_GRAPH_ID,
  workflow_node_id = `node:coding-tool:${toolId}`,
  context_chamber_ref = null,
  action_proposal_ref = `action:projection:${toolId}`,
  gate_result_ref = `gate:projection:${toolId}`,
  module_kind = "workload_job",
  execution_backend = "workload_grpc",
  manifest_ref = null,
  actor_id = DEFAULT_ACTOR_ID,
  runtime_node_ref = DEFAULT_RUNTIME_NODE_REF,
  policy_hash = DEFAULT_POLICY_HASH,
  authority_grant_refs = [],
  approval_ref = null,
  state_root_before = null,
  projection_watermark = null,
  idempotency_key = `step-module:${run_id}:${task_id}:${toolId}:${stepModuleHash(input).slice(7, 23)}`,
  deadline_ms = 60_000,
} = {}) {
  if (!contract || typeof contract !== "object") {
    throw new TypeError("createStepModuleInvocationForCodingTool requires a coding tool contract.");
  }
  if (!toolId || typeof toolId !== "string") {
    throw new TypeError("createStepModuleInvocationForCodingTool requires toolId.");
  }

  const invocation = {
    schema_version: STEP_MODULE_INVOCATION_SCHEMA_VERSION,
    invocation_id: `invocation://projection/${stepModuleHash({
      run_id,
      task_id,
      toolId,
      input,
    }).slice(7, 39)}`,
    run_id,
    task_id,
    thread_id,
    workflow_graph_id,
    workflow_node_id,
    context_chamber_ref,
    action_proposal_ref,
    gate_result_ref,
    module_ref: {
      kind: module_kind,
      id: toolId,
      version: contract.schema_version ?? "migration",
      manifest_ref,
    },
    actor: {
      actor_id,
      runtime_node_ref,
    },
    authority: {
      authority_grant_refs: normalizeStringArray(authority_grant_refs),
      policy_hash,
      primitive_capabilities: normalizeStringArray(contract.primitive_capabilities),
      authority_scopes: normalizeStringArray(contract.authority_scope_requirements),
      approval_ref,
    },
    input: {
      input_hash: stepModuleHash(input),
      expected_schema_ref: `schema://coding-tool/${toolId}/input`,
      context_refs: [],
      artifact_refs: [],
      payload_refs: [],
      state_root_before,
      projection_watermark,
      data_plane_handle: null,
    },
    custody: {
      privacy_profile: "internal",
      plaintext_policy: {
        node_plaintext_allowed: true,
        declassification_required: false,
      },
      custody_proof_ref: null,
      leakage_profile_ref: null,
    },
    execution: {
      backend: execution_backend,
      idempotency_key,
      deadline_ms,
      resource_lease_ref: null,
      retry_policy_ref: null,
    },
  };

  validateStepModuleInvocationShape(invocation);
  return invocation;
}

export function createStepModuleResultForCodingTool({
  invocation,
  contract,
  toolId = contract?.stable_tool_id ?? invocation?.module_ref?.id,
  result = {},
  status = "success",
  workflow_projection_status = "projected",
  execution_result_ref = null,
  normalized_observation_ref = null,
  receipt_refs = null,
  artifact_refs = [],
  payload_refs = [],
  agentgres_operation_refs = [],
  state_root_after = null,
  resulting_head = null,
  evidence_refs = [],
  model_reentry_required = false,
  verifier_required = false,
} = {}) {
  if (!invocation || typeof invocation !== "object") {
    throw new TypeError("createStepModuleResultForCodingTool requires invocation.");
  }
  if (!toolId || typeof toolId !== "string") {
    throw new TypeError("createStepModuleResultForCodingTool requires toolId.");
  }

  const resultHash = stepModuleHash({
    invocationId: invocation.invocation_id,
    status,
    result,
  });
  const normalizedReceiptRefs = receipt_refs ?? [`receipt://projection/${resultHash.slice(7, 39)}`];
  const stepResult = {
    schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION,
    invocation_id: invocation.invocation_id,
    status,
    execution_result_ref: execution_result_ref ?? `result://projection/${resultHash.slice(7, 39)}`,
    normalized_observation_ref:
      normalized_observation_ref ?? `observation://projection/${resultHash.slice(7, 39)}`,
    receipt_refs: normalizeStringArray(normalizedReceiptRefs),
    artifact_refs: normalizeStringArray(artifact_refs),
    payload_refs: normalizeStringArray(payload_refs),
    agentgres_operation_refs: normalizeStringArray(agentgres_operation_refs),
    state_root_after,
    resulting_head,
    workflow_projection: {
      workflow_graph_id: invocation.workflow_graph_id ?? DEFAULT_WORKFLOW_GRAPH_ID,
      workflow_node_id: invocation.workflow_node_id ?? `node:coding-tool:${toolId}`,
      component_kind: contract?.workflow_node_type ?? "CodingToolNode",
      status: workflow_projection_status,
      attempt_id: `attempt://projection/${resultHash.slice(7, 39)}`,
      evidence_refs: normalizeStringArray(evidence_refs),
      receipt_refs: normalizeStringArray(normalizedReceiptRefs),
    },
    next: {
      model_reentry_required: Boolean(model_reentry_required),
      verifier_required: Boolean(verifier_required),
    },
  };

  validateStepModuleResultShape(stepResult);
  return stepResult;
}

export function createCodingToolStepModuleProjection(options = {}) {
  const invocation = createStepModuleInvocationForCodingTool(options);
  const result = createStepModuleResultForCodingTool({
    ...options,
    invocation,
  });
  return { invocation, result };
}

export function createStepModuleInvocationForModelMount({
  invocation_ref,
  route_ref,
  provider_ref,
  endpoint_ref,
  model_ref,
  capability = "chat",
  invocation_kind = "chat",
  input_hash,
  policy_hash = DEFAULT_POLICY_HASH,
  route_decision_ref = null,
  route_receipt_ref = null,
  run_id = "run:model-mount",
  task_id = "task:model-mount",
  thread_id = null,
  workflow_graph_id = DEFAULT_WORKFLOW_GRAPH_ID,
  workflow_node_id = `node:model-mount:${safeRefSegment(invocation_ref)}`,
  action_proposal_ref = `action:model-mount:${safeRefSegment(invocation_ref)}`,
  gate_result_ref = `gate:model-mount:${safeRefSegment(invocation_ref)}`,
  manifest_ref = null,
  actor_id = DEFAULT_ACTOR_ID,
  runtime_node_ref = DEFAULT_RUNTIME_NODE_REF,
  authority_grant_refs = [],
  authority_scopes = [],
  approval_ref = null,
  privacy_profile = "internal",
  node_plaintext_allowed = false,
  declassification_required = false,
  custody_proof_ref = null,
  leakage_profile_ref = null,
  state_root_before = null,
  projection_watermark = null,
  idempotency_key = `step-module:${invocation_ref}`,
  deadline_ms = 300_000,
} = {}) {
  requireModelMountString("invocation_ref", invocation_ref);
  requireModelMountString("route_ref", route_ref);
  requireModelMountString("provider_ref", provider_ref);
  requireModelMountString("endpoint_ref", endpoint_ref);
  requireModelMountString("model_ref", model_ref);
  requireModelMountString("input_hash", input_hash);

  const invocation = {
    schema_version: STEP_MODULE_INVOCATION_SCHEMA_VERSION,
    invocation_id: invocation_ref,
    run_id,
    task_id,
    thread_id,
    workflow_graph_id,
    workflow_node_id,
    context_chamber_ref: null,
    action_proposal_ref,
    gate_result_ref,
    module_ref: {
      kind: "model_mount",
      id: `${capability}:${route_ref}:${endpoint_ref}`,
      version: "migration",
      manifest_ref,
    },
    actor: {
      actor_id,
      runtime_node_ref,
    },
    authority: {
      authority_grant_refs: normalizeStringArray(authority_grant_refs),
      policy_hash: normalizeSha256(policy_hash),
      primitive_capabilities: [`model:${capability}`, `model:${invocation_kind}`],
      authority_scopes: normalizeStringArray(authority_scopes),
      approval_ref,
    },
    input: {
      input_hash: normalizeSha256(input_hash),
      expected_schema_ref: `schema://model-mount/${invocation_kind}/input`,
      context_refs: normalizeStringArray([
        route_ref,
        provider_ref,
        endpoint_ref,
        model_ref,
        route_decision_ref,
        route_receipt_ref,
      ]),
      artifact_refs: [],
      payload_refs: [],
      state_root_before,
      projection_watermark,
      data_plane_handle: null,
    },
    custody: {
      privacy_profile: normalizeStepModulePrivacyProfile(privacy_profile),
      plaintext_policy: {
        node_plaintext_allowed: Boolean(node_plaintext_allowed),
        declassification_required: Boolean(declassification_required),
      },
      custody_proof_ref,
      leakage_profile_ref,
    },
    execution: {
      backend: "model_mount",
      idempotency_key,
      deadline_ms,
      resource_lease_ref: null,
      retry_policy_ref: null,
    },
  };

  validateStepModuleInvocationShape(invocation);
  return invocation;
}

export function createStepModuleResultForModelMount({
  invocation,
  receipt_ref,
  output_hash,
  status = "success",
  workflow_projection_status = "live",
  execution_result_ref = null,
  normalized_observation_ref = null,
  artifact_refs = [],
  payload_refs = [],
  agentgres_operation_refs = [],
  state_root_after = null,
  resulting_head = null,
  evidence_refs = [],
  model_reentry_required = false,
  verifier_required = false,
} = {}) {
  if (!invocation || typeof invocation !== "object") {
    throw new TypeError("createStepModuleResultForModelMount requires invocation.");
  }
  requireModelMountString("receipt_ref", receipt_ref);
  requireModelMountString("output_hash", output_hash);

  const resultHash = stepModuleHash({
    invocationId: invocation.invocation_id,
    receipt_ref,
    output_hash,
    status,
  });
  const stepResult = {
    schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION,
    invocation_id: invocation.invocation_id,
    status,
    execution_result_ref: execution_result_ref ?? `result://model-mount/${resultHash.slice(7, 39)}`,
    normalized_observation_ref:
      normalized_observation_ref ?? `observation://model-mount/${resultHash.slice(7, 39)}`,
    receipt_refs: [receipt_ref],
    artifact_refs: normalizeStringArray(artifact_refs),
    payload_refs: normalizeStringArray(payload_refs),
    agentgres_operation_refs: normalizeStringArray(agentgres_operation_refs),
    state_root_after,
    resulting_head,
    workflow_projection: {
      workflow_graph_id: invocation.workflow_graph_id ?? DEFAULT_WORKFLOW_GRAPH_ID,
      workflow_node_id: invocation.workflow_node_id ?? `node:model-mount:${safeRefSegment(invocation.invocation_id)}`,
      component_kind: "ModelInvocationNode",
      status: workflow_projection_status,
      attempt_id: `attempt://model-mount/${resultHash.slice(7, 39)}`,
      evidence_refs: normalizeStringArray(evidence_refs),
      receipt_refs: [receipt_ref],
    },
    next: {
      model_reentry_required: Boolean(model_reentry_required),
      verifier_required: Boolean(verifier_required),
    },
  };

  validateStepModuleResultShape(stepResult);
  return stepResult;
}

export function createModelMountStepModuleProjection(options = {}) {
  const invocation = createStepModuleInvocationForModelMount(options);
  const result = createStepModuleResultForModelMount({
    ...options,
    invocation,
  });
  return { invocation, result };
}

export function validateStepModuleInvocationShape(invocation) {
  const failures = [];
  requireEqual(
    failures,
    "schema_version",
    invocation?.schema_version,
    STEP_MODULE_INVOCATION_SCHEMA_VERSION,
  );
  requireString(failures, "invocation_id", invocation?.invocation_id);
  requireString(failures, "run_id", invocation?.run_id);
  requireString(failures, "task_id", invocation?.task_id);
  requireString(failures, "action_proposal_ref", invocation?.action_proposal_ref);
  requireString(failures, "gate_result_ref", invocation?.gate_result_ref);
  requireString(failures, "module_ref.id", invocation?.module_ref?.id);
  requireString(failures, "module_ref.version", invocation?.module_ref?.version);
  requireString(failures, "actor.actor_id", invocation?.actor?.actor_id);
  requireString(failures, "actor.runtime_node_ref", invocation?.actor?.runtime_node_ref);
  requireString(failures, "authority.policy_hash", invocation?.authority?.policy_hash);
  requireString(failures, "input.input_hash", invocation?.input?.input_hash);
  requireString(failures, "input.expected_schema_ref", invocation?.input?.expected_schema_ref);
  requireString(failures, "execution.idempotency_key", invocation?.execution?.idempotency_key);
  if (!Number.isFinite(invocation?.execution?.deadline_ms) || invocation.execution.deadline_ms <= 0) {
    failures.push("execution.deadline_ms must be positive.");
  }
  if (!backendAllowedForKind(invocation?.module_ref?.kind, invocation?.execution?.backend)) {
    failures.push(
      `execution backend ${invocation?.execution?.backend ?? "missing"} is not allowed for module kind ${invocation?.module_ref?.kind ?? "missing"}.`,
    );
  }
  if (
    invocation?.custody?.privacy_profile === "private_workspace_ctee" &&
    invocation?.custody?.plaintext_policy?.node_plaintext_allowed
  ) {
    failures.push(
      "cTEE private workspace invocations cannot allow node plaintext custody on untrusted runtime nodes.",
    );
  }
  if (failures.length > 0) {
    throw new TypeError(`Invalid StepModuleInvocation: ${failures.join(" ")}`);
  }
  return true;
}

export function validateStepModuleResultShape(result) {
  const failures = [];
  requireEqual(failures, "schema_version", result?.schema_version, STEP_MODULE_RESULT_SCHEMA_VERSION);
  requireString(failures, "invocation_id", result?.invocation_id);
  requireString(failures, "execution_result_ref", result?.execution_result_ref);
  requireString(failures, "normalized_observation_ref", result?.normalized_observation_ref);
  requireString(
    failures,
    "workflow_projection.workflow_graph_id",
    result?.workflow_projection?.workflow_graph_id,
  );
  requireString(
    failures,
    "workflow_projection.workflow_node_id",
    result?.workflow_projection?.workflow_node_id,
  );
  requireString(failures, "workflow_projection.attempt_id", result?.workflow_projection?.attempt_id);
  if ((result?.status === "success" || result?.status === "partial") && result?.receipt_refs?.length === 0) {
    failures.push("accepted StepModuleResult statuses require at least one receipt ref.");
  }
  if (
    Array.isArray(result?.agentgres_operation_refs) &&
    result.agentgres_operation_refs.length > 0 &&
    (!result.state_root_after || !result.resulting_head)
  ) {
    failures.push("Agentgres operation refs require state_root_after and resulting_head.");
  }
  if (failures.length > 0) {
    throw new TypeError(`Invalid StepModuleResult: ${failures.join(" ")}`);
  }
  return true;
}

function normalizeStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((entry) => typeof entry === "string" && entry.trim()).map((entry) => entry.trim());
}

function normalizeSha256(value) {
  const normalized = String(value ?? "").trim();
  return normalized.startsWith("sha256:") ? normalized : `sha256:${normalized}`;
}

function normalizeStepModulePrivacyProfile(value) {
  const normalized = String(value ?? "").trim();
  if (normalized === "private_workspace_ctee" || normalized === "tee_confidential" || normalized === "redacted" || normalized === "public") {
    return normalized;
  }
  return "internal";
}

function requireModelMountString(field, value) {
  if (typeof value !== "string" || !value.trim()) {
    throw new TypeError(`createStepModuleInvocationForModelMount requires ${field}.`);
  }
}

function safeRefSegment(value) {
  return String(value ?? "unknown")
    .replace(/^[a-z]+:\/\//i, "")
    .replace(/[^a-zA-Z0-9_.:-]+/g, "-")
    .slice(0, 96) || "unknown";
}

function backendAllowedForKind(kind, backend) {
  return (
    (kind === "daemon_native_tool" && backend === "rust_wasm") ||
    (kind === "rust_wasm_service_module" && backend === "rust_wasm") ||
    (kind === "workload_job" && backend === "workload_grpc") ||
    (kind === "model_mount" && backend === "model_mount") ||
    (kind === "private_workspace_ctee_action" && backend === "ctee_operator") ||
    (kind === "verifier" && (backend === "rust_wasm" || backend === "workload_grpc")) ||
    (kind === "aiip_capability_exit" && backend === "aiip")
  );
}

function requireEqual(failures, field, actual, expected) {
  if (actual !== expected) {
    failures.push(`${field} must be ${expected}.`);
  }
}

function requireString(failures, field, value) {
  if (typeof value !== "string" || !value.trim()) {
    failures.push(`${field} must be a non-empty string.`);
  }
}

function sortJsonValue(value) {
  if (Array.isArray(value)) return value.map(sortJsonValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => [key, sortJsonValue(entry)]),
  );
}
