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
  toolId = contract?.stableToolId,
  input = {},
  runId = DEFAULT_RUN_ID,
  taskId = DEFAULT_TASK_ID,
  threadId = null,
  workflowGraphId = DEFAULT_WORKFLOW_GRAPH_ID,
  workflowNodeId = `node:coding-tool:${toolId}`,
  contextChamberRef = null,
  actionProposalRef = `action:projection:${toolId}`,
  gateResultRef = `gate:projection:${toolId}`,
  moduleKind = "daemon_native_tool",
  executionBackend = "daemon_js",
  manifestRef = null,
  actorId = DEFAULT_ACTOR_ID,
  runtimeNodeRef = DEFAULT_RUNTIME_NODE_REF,
  policyHash = DEFAULT_POLICY_HASH,
  authorityGrantRefs = [],
  approvalRef = null,
  stateRootBefore = null,
  projectionWatermark = null,
  idempotencyKey = `step-module:${runId}:${taskId}:${toolId}:${stepModuleHash(input).slice(7, 23)}`,
  deadlineMs = 60_000,
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
      runId,
      taskId,
      toolId,
      input,
    }).slice(7, 39)}`,
    run_id: runId,
    task_id: taskId,
    thread_id: threadId,
    workflow_graph_id: workflowGraphId,
    workflow_node_id: workflowNodeId,
    context_chamber_ref: contextChamberRef,
    action_proposal_ref: actionProposalRef,
    gate_result_ref: gateResultRef,
    module_ref: {
      kind: moduleKind,
      id: toolId,
      version: contract.schemaVersion ?? "migration",
      manifest_ref: manifestRef,
    },
    actor: {
      actor_id: actorId,
      runtime_node_ref: runtimeNodeRef,
    },
    authority: {
      authority_grant_refs: normalizeStringArray(authorityGrantRefs),
      policy_hash: policyHash,
      primitive_capabilities: normalizeStringArray(contract.primitiveCapabilities),
      authority_scopes: normalizeStringArray(contract.authorityScopeRequirements),
      approval_ref: approvalRef,
    },
    input: {
      input_hash: stepModuleHash(input),
      expected_schema_ref: `schema://coding-tool/${toolId}/input`,
      context_refs: [],
      artifact_refs: [],
      payload_refs: [],
      state_root_before: stateRootBefore,
      projection_watermark: projectionWatermark,
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
      backend: executionBackend,
      idempotency_key: idempotencyKey,
      deadline_ms: deadlineMs,
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
  toolId = contract?.stableToolId ?? invocation?.module_ref?.id,
  result = {},
  status = "success",
  workflowProjectionStatus = "projected",
  executionResultRef = null,
  normalizedObservationRef = null,
  receiptRefs = null,
  artifactRefs = [],
  payloadRefs = [],
  agentgresOperationRefs = [],
  stateRootAfter = null,
  resultingHead = null,
  evidenceRefs = [],
  modelReentryRequired = false,
  verifierRequired = false,
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
  const normalizedReceiptRefs = receiptRefs ?? [`receipt://projection/${resultHash.slice(7, 39)}`];
  const stepResult = {
    schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION,
    invocation_id: invocation.invocation_id,
    status,
    execution_result_ref: executionResultRef ?? `result://projection/${resultHash.slice(7, 39)}`,
    normalized_observation_ref:
      normalizedObservationRef ?? `observation://projection/${resultHash.slice(7, 39)}`,
    receipt_refs: normalizeStringArray(normalizedReceiptRefs),
    artifact_refs: normalizeStringArray(artifactRefs),
    payload_refs: normalizeStringArray(payloadRefs),
    agentgres_operation_refs: normalizeStringArray(agentgresOperationRefs),
    state_root_after: stateRootAfter,
    resulting_head: resultingHead,
    workflow_projection: {
      workflow_graph_id: invocation.workflow_graph_id ?? DEFAULT_WORKFLOW_GRAPH_ID,
      workflow_node_id: invocation.workflow_node_id ?? `node:coding-tool:${toolId}`,
      component_kind: contract?.workflowNodeType ?? "CodingToolNode",
      status: workflowProjectionStatus,
      attempt_id: `attempt://projection/${resultHash.slice(7, 39)}`,
      evidence_refs: normalizeStringArray(evidenceRefs),
      receipt_refs: normalizeStringArray(normalizedReceiptRefs),
    },
    next: {
      model_reentry_required: Boolean(modelReentryRequired),
      verifier_required: Boolean(verifierRequired),
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
  invocationRef,
  routeRef,
  providerRef,
  endpointRef,
  modelRef,
  capability = "chat",
  invocationKind = "chat",
  inputHash,
  policyHash = DEFAULT_POLICY_HASH,
  routeDecisionRef = null,
  routeReceiptRef = null,
  runId = "run:model-mount",
  taskId = "task:model-mount",
  threadId = null,
  workflowGraphId = DEFAULT_WORKFLOW_GRAPH_ID,
  workflowNodeId = `node:model-mount:${safeRefSegment(invocationRef)}`,
  actionProposalRef = `action:model-mount:${safeRefSegment(invocationRef)}`,
  gateResultRef = `gate:model-mount:${safeRefSegment(invocationRef)}`,
  manifestRef = null,
  actorId = DEFAULT_ACTOR_ID,
  runtimeNodeRef = DEFAULT_RUNTIME_NODE_REF,
  authorityGrantRefs = [],
  authorityScopes = [],
  approvalRef = null,
  privacyProfile = "internal",
  nodePlaintextAllowed = false,
  declassificationRequired = false,
  custodyProofRef = null,
  leakageProfileRef = null,
  stateRootBefore = null,
  projectionWatermark = null,
  idempotencyKey = `step-module:${invocationRef}`,
  deadlineMs = 300_000,
} = {}) {
  requireModelMountString("invocationRef", invocationRef);
  requireModelMountString("routeRef", routeRef);
  requireModelMountString("providerRef", providerRef);
  requireModelMountString("endpointRef", endpointRef);
  requireModelMountString("modelRef", modelRef);
  requireModelMountString("inputHash", inputHash);

  const invocation = {
    schema_version: STEP_MODULE_INVOCATION_SCHEMA_VERSION,
    invocation_id: invocationRef,
    run_id: runId,
    task_id: taskId,
    thread_id: threadId,
    workflow_graph_id: workflowGraphId,
    workflow_node_id: workflowNodeId,
    context_chamber_ref: null,
    action_proposal_ref: actionProposalRef,
    gate_result_ref: gateResultRef,
    module_ref: {
      kind: "model_mount",
      id: `${capability}:${routeRef}:${endpointRef}`,
      version: "migration",
      manifest_ref: manifestRef,
    },
    actor: {
      actor_id: actorId,
      runtime_node_ref: runtimeNodeRef,
    },
    authority: {
      authority_grant_refs: normalizeStringArray(authorityGrantRefs),
      policy_hash: normalizeSha256(policyHash),
      primitive_capabilities: [`model:${capability}`, `model:${invocationKind}`],
      authority_scopes: normalizeStringArray(authorityScopes),
      approval_ref: approvalRef,
    },
    input: {
      input_hash: normalizeSha256(inputHash),
      expected_schema_ref: `schema://model-mount/${invocationKind}/input`,
      context_refs: normalizeStringArray([
        routeRef,
        providerRef,
        endpointRef,
        modelRef,
        routeDecisionRef,
        routeReceiptRef,
      ]),
      artifact_refs: [],
      payload_refs: [],
      state_root_before: stateRootBefore,
      projection_watermark: projectionWatermark,
      data_plane_handle: null,
    },
    custody: {
      privacy_profile: normalizeStepModulePrivacyProfile(privacyProfile),
      plaintext_policy: {
        node_plaintext_allowed: Boolean(nodePlaintextAllowed),
        declassification_required: Boolean(declassificationRequired),
      },
      custody_proof_ref: custodyProofRef,
      leakage_profile_ref: leakageProfileRef,
    },
    execution: {
      backend: "model_mount",
      idempotency_key: idempotencyKey,
      deadline_ms: deadlineMs,
      resource_lease_ref: null,
      retry_policy_ref: null,
    },
  };

  validateStepModuleInvocationShape(invocation);
  return invocation;
}

export function createStepModuleResultForModelMount({
  invocation,
  receiptRef,
  outputHash,
  status = "success",
  workflowProjectionStatus = "live",
  executionResultRef = null,
  normalizedObservationRef = null,
  artifactRefs = [],
  payloadRefs = [],
  agentgresOperationRefs = [],
  stateRootAfter = null,
  resultingHead = null,
  evidenceRefs = [],
  modelReentryRequired = false,
  verifierRequired = false,
} = {}) {
  if (!invocation || typeof invocation !== "object") {
    throw new TypeError("createStepModuleResultForModelMount requires invocation.");
  }
  requireModelMountString("receiptRef", receiptRef);
  requireModelMountString("outputHash", outputHash);

  const resultHash = stepModuleHash({
    invocationId: invocation.invocation_id,
    receiptRef,
    outputHash,
    status,
  });
  const stepResult = {
    schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION,
    invocation_id: invocation.invocation_id,
    status,
    execution_result_ref: executionResultRef ?? `result://model-mount/${resultHash.slice(7, 39)}`,
    normalized_observation_ref:
      normalizedObservationRef ?? `observation://model-mount/${resultHash.slice(7, 39)}`,
    receipt_refs: [receiptRef],
    artifact_refs: normalizeStringArray(artifactRefs),
    payload_refs: normalizeStringArray(payloadRefs),
    agentgres_operation_refs: normalizeStringArray(agentgresOperationRefs),
    state_root_after: stateRootAfter,
    resulting_head: resultingHead,
    workflow_projection: {
      workflow_graph_id: invocation.workflow_graph_id ?? DEFAULT_WORKFLOW_GRAPH_ID,
      workflow_node_id: invocation.workflow_node_id ?? `node:model-mount:${safeRefSegment(invocation.invocation_id)}`,
      component_kind: "ModelInvocationNode",
      status: workflowProjectionStatus,
      attempt_id: `attempt://model-mount/${resultHash.slice(7, 39)}`,
      evidence_refs: normalizeStringArray(evidenceRefs),
      receipt_refs: [receiptRef],
    },
    next: {
      model_reentry_required: Boolean(modelReentryRequired),
      verifier_required: Boolean(verifierRequired),
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
    (kind === "daemon_native_tool" && (backend === "daemon_js" || backend === "rust_wasm")) ||
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
