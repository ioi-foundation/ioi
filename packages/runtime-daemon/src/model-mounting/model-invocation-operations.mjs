import { stableHash } from "./io.mjs";
import {
  createModelMountStepModuleProjection,
} from "../step-module-abi.mjs";

const RETIRED_MODEL_INVOCATION_REQUEST_ALIASES = [
  "routeId",
  "modelPolicy",
  "responseId",
  "previousResponseId",
  "sendOptions",
  "authorityGrantRefs",
  "authorityReceiptRefs",
  "custodyRef",
  "privacyProfile",
  "nodePlaintextAllowed",
];

const RETIRED_MODEL_INVOCATION_HELPER_ALIASES = [
  "acceptedReceiptRecord",
  "apiFormat",
  "backendEvidenceRefs",
  "backendId",
  "backendProcess",
  "backendProcessId",
  "backendProcessPidHash",
  "compatTranslation",
  "custodyRef",
  "executionBackend",
  "evidenceRefs",
  "grantId",
  "loadPolicy",
  "modelId",
  "nodePlaintextAllowed",
  "outputText",
  "privacyClass",
  "providerAuthEvidenceRefs",
  "providerId",
  "providerResponse",
  "providerResponseKind",
  "routeControl",
  "routeDecision",
  "routeReceipt",
  "serverIds",
  "streamChunks",
  "streamFormat",
  "streamKind",
  "tokenCount",
  "toolReceiptIds",
];

export async function invokeModel(state, { authorization, requiredScope, kind, body = {} } = {}, deps = {}) {
  void authorization;
  assertCanonicalModelInvocationRequestBody(body);
  return executeModelInvocationThroughRustCore(state, {
    body,
    deps,
    kind,
    requiredScope,
    stream: false,
  });
}

export async function startModelStream(state, { authorization, requiredScope, kind, body = {} } = {}, deps = {}) {
  void authorization;
  assertCanonicalModelInvocationRequestBody(body);
  return executeModelInvocationThroughRustCore(state, {
    body,
    deps,
    kind,
    requiredScope,
    stream: true,
  });
}

export function modelMountInvocationAdmissionRequestForReceipt({
  body = {},
  capability = "chat",
  kind,
  receiptDetails = {},
  receiptId,
  receiptKind,
  routeReceipt,
  selection,
  streamStatus = null,
} = {}) {
  assertCanonicalModelInvocationRequestBody(body);
  assertCanonicalModelInvocationHelperInputs({ selection });
  const routeReceiptRef = receiptRef(requiredStringRef("routeReceipt.id", routeReceipt?.id));
  const invocationReceiptRef = receiptRef(requiredStringRef("receiptId", receiptId));
  const routeDecisionRef = requiredStringRef(
    "routeReceipt.details.model_mount_route_decision_ref",
    routeReceipt?.details?.model_mount_route_decision_ref,
  );
  const policy = body.model_policy ?? {};
  return {
    schema_version: "ioi.model_mount.invocation_admission.v1",
    invocation_ref: `model-invocation://${requiredStringRef("receiptId", receiptId)}`,
    route_decision_ref: routeDecisionRef,
    route_receipt_ref: routeReceiptRef,
    invocation_receipt_ref: invocationReceiptRef,
    route_ref: requiredStringRef("route.id", selection?.route?.id ?? receiptDetails.route_id),
    provider_ref: requiredStringRef("provider.id", selection?.provider?.id ?? receiptDetails.provider_id),
    endpoint_ref: requiredStringRef("endpoint.id", selection?.endpoint?.id ?? receiptDetails.endpoint_id),
    model_ref: requiredStringRef("endpoint.model_id", selection?.endpoint?.model_id ?? receiptDetails.selected_model),
    capability: requiredStringRef("capability", capability),
    invocation_kind: requiredStringRef("kind", kind),
    policy_hash: policyHashRef(receiptDetails.policy_hash),
    input_hash: hashRef(receiptDetails.input_hash, "input_hash"),
    output_hash: hashRef(receiptDetails.output_hash, "output_hash"),
    idempotency_key: `${receiptKind}:${receiptId}`,
    receipt_refs: uniqueRefs([
      routeReceiptRef,
      invocationReceiptRef,
      ...(Array.isArray(receiptDetails.tool_receipt_ids) ? receiptDetails.tool_receipt_ids.map(receiptRef) : []),
    ]),
    authority_grant_refs: uniqueRefs([
      optionalRef(receiptDetails.grant_id),
      ...(Array.isArray(body.authority_grant_refs) ? body.authority_grant_refs : []),
    ]),
    authority_receipt_refs: uniqueRefs([
      ...(Array.isArray(body.authority_receipt_refs) ? body.authority_receipt_refs : []),
    ]),
    provider_auth_evidence_refs: uniqueRefs(receiptDetails.provider_auth_evidence_refs ?? []),
    backend_evidence_refs: uniqueRefs(receiptDetails.backend_evidence_refs ?? []),
    tool_receipt_refs: uniqueRefs(receiptDetails.tool_receipt_ids ?? []),
    custody_ref: optionalRef(
      body.custody_ref ??
        selection?.endpoint?.custody_ref ??
        selection?.provider?.custody_ref,
    ),
    privacy_profile: optionalRef(
      body.privacy_profile ??
        policy.privacy_profile ??
        policy.privacy ??
        selection?.route?.privacy ??
        selection?.provider?.privacy_class,
    ),
    node_plaintext_allowed: Boolean(
      body.node_plaintext_allowed ??
        selection?.endpoint?.node_plaintext_allowed ??
        selection?.provider?.node_plaintext_allowed ??
        false,
    ),
    workflow_graph_ref: optionalRef(routeReceipt?.details?.workflow_graph_id),
    workflow_node_ref: optionalRef(routeReceipt?.details?.workflow_node_id),
    response_ref: optionalRef(receiptDetails.response_id),
    previous_response_ref: optionalRef(receiptDetails.previous_response_id),
    stream_status: optionalRef(streamStatus ?? receiptDetails.stream_status),
  };
}

export function modelMountProviderExecutionRequestForInvocation({
  body = {},
  capability = "chat",
  ephemeralMcp = {},
  hash = stableHash,
  input,
  instance = {},
  kind,
  previousResponseId = null,
  providerBody = {},
  responseId = null,
  routeReceipt,
  selection,
  streamStatus = null,
  token = {},
} = {}) {
  assertCanonicalModelInvocationRequestBody(body);
  assertCanonicalModelInvocationHelperInputs({ selection, instance, token });
  const routeReceiptRef = receiptRef(requiredStringRef("routeReceipt.id", routeReceipt?.id));
  const routeDecisionRef = requiredStringRef(
    "routeReceipt.details.model_mount_route_decision_ref",
    routeReceipt?.details?.model_mount_route_decision_ref,
  );
  const requestHash = hashRef(
    hash({
      endpointId: selection?.endpoint?.id ?? null,
      invocationKind: kind,
      providerBody,
      streamStatus,
    }),
    "request_hash",
  );
  const policy = body.model_policy ?? {};
  return {
    schema_version: "ioi.model_mount.provider_execution.v1",
    invocation_ref: `model-provider-execution://${requestHash.replace(/^sha256:/, "sha256/")}`,
    route_decision_ref: routeDecisionRef,
    route_receipt_ref: routeReceiptRef,
    route_ref: requiredStringRef("route.id", selection?.route?.id),
    provider_ref: requiredStringRef("provider.id", selection?.provider?.id),
    endpoint_ref: requiredStringRef("endpoint.id", selection?.endpoint?.id),
    model_ref: requiredStringRef("endpoint.model_id", selection?.endpoint?.model_id),
    capability: requiredStringRef("capability", capability),
    invocation_kind: requiredStringRef("kind", kind),
    policy_hash: policyHashRef(hash(policy)),
    input_hash: hashRef(hash(input ?? ""), "input_hash"),
    request_hash: requestHash,
    idempotency_key: `model_provider_execution:${routeReceiptRef}:${requestHash}`,
    receipt_refs: uniqueRefs([
      routeReceiptRef,
      ...(Array.isArray(ephemeralMcp.toolReceiptIds) ? ephemeralMcp.toolReceiptIds.map(receiptRef) : []),
    ]),
    authority_grant_refs: uniqueRefs([
      optionalRef(token.grant_ref),
      ...(Array.isArray(body.authority_grant_refs) ? body.authority_grant_refs : []),
    ]),
    authority_receipt_refs: uniqueRefs([
      ...(Array.isArray(body.authority_receipt_refs) ? body.authority_receipt_refs : []),
    ]),
    provider_auth_evidence_refs: hostedProviderAuthEvidenceRefs(selection, hash),
    backend_evidence_refs: uniqueRefs([
      instance.backend_id,
      selection?.endpoint?.backend_id,
    ]),
    tool_receipt_refs: uniqueRefs(ephemeralMcp.toolReceiptIds ?? []),
    custody_ref: optionalRef(
      body.custody_ref ??
        selection?.endpoint?.custody_ref ??
        selection?.provider?.custody_ref,
    ),
    privacy_profile: optionalRef(
      body.privacy_profile ??
        policy.privacy_profile ??
        policy.privacy ??
        selection?.route?.privacy ??
        selection?.provider?.privacy_class,
    ),
    node_plaintext_allowed: Boolean(
      body.node_plaintext_allowed ??
        selection?.endpoint?.node_plaintext_allowed ??
        selection?.provider?.node_plaintext_allowed ??
        false,
    ),
    workflow_graph_ref: optionalRef(routeReceipt?.details?.workflow_graph_id),
    workflow_node_ref: optionalRef(routeReceipt?.details?.workflow_node_id),
    response_ref: optionalRef(responseId),
    previous_response_ref: optionalRef(previousResponseId),
    stream_status: optionalRef(streamStatus),
  };
}

export function modelMountProviderInvocationRequestForExecution({
  input,
  instance = {},
  kind,
  modelMountProviderExecutionAdmission = {},
  selection,
} = {}) {
  assertCanonicalModelInvocationHelperInputs({ selection, instance });
  const record = modelMountProviderExecutionAdmission.record ?? {};
  const provider = selection?.provider ?? {};
  const endpoint = selection?.endpoint ?? {};
  return {
    schema_version: "ioi.model_mount.provider_invocation.v1",
    provider_execution_ref: requiredStringRef(
      "modelMountProviderExecutionAdmission.provider_execution_ref",
      modelMountProviderExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
    ),
    provider_execution_hash: requiredStringRef(
      "modelMountProviderExecutionAdmission.provider_execution_hash",
      modelMountProviderExecutionAdmission.provider_execution_hash ?? record.provider_execution_hash,
    ),
    route_decision_ref: requiredStringRef("providerExecution.route_decision_ref", record.route_decision_ref),
    route_receipt_ref: requiredStringRef("providerExecution.route_receipt_ref", record.route_receipt_ref),
    route_ref: requiredStringRef("providerExecution.route_ref", record.route_ref),
    provider_ref: requiredStringRef("providerExecution.provider_ref", record.provider_ref),
    provider_kind: requiredStringRef("provider.kind", provider.kind),
    endpoint_ref: requiredStringRef("providerExecution.endpoint_ref", record.endpoint_ref),
    model_ref: requiredStringRef("providerExecution.model_ref", record.model_ref),
    capability: requiredStringRef("providerExecution.capability", record.capability),
    invocation_kind: requiredStringRef("providerExecution.invocation_kind", record.invocation_kind ?? kind),
    input: String(input ?? ""),
    request_hash: requiredStringRef("providerExecution.request_hash", record.request_hash),
    execution_backend: modelMountProviderInvocationExecutionBackend(selection),
    api_format: optionalRef(endpoint.api_format ?? provider.api_format),
    driver: explicitProviderDriver(selection),
    backend_ref: optionalRef(instance.backend_id ?? endpoint.backend_id),
    stream_status: optionalRef(record.stream_status),
    receipt_refs: modelMountProviderExecutionAdmission.receipt_refs ?? record.receipt_refs ?? [],
    evidence_refs: uniqueRefs([
      modelMountProviderExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
      ...(modelMountProviderExecutionAdmission.evidence_refs ?? []),
    ]),
    admitted_provider_execution: record,
  };
}

export function modelMountProviderStreamInvocationRequestForExecution({
  input,
  instance = {},
  kind,
  modelMountProviderExecutionAdmission = {},
  selection,
} = {}) {
  assertCanonicalModelInvocationHelperInputs({ selection, instance });
  const record = modelMountProviderExecutionAdmission.record ?? {};
  const provider = selection?.provider ?? {};
  const endpoint = selection?.endpoint ?? {};
  return {
    schema_version: "ioi.model_mount.provider_invocation.v1",
    provider_execution_ref: requiredStringRef(
      "modelMountProviderExecutionAdmission.provider_execution_ref",
      modelMountProviderExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
    ),
    provider_execution_hash: requiredStringRef(
      "modelMountProviderExecutionAdmission.provider_execution_hash",
      modelMountProviderExecutionAdmission.provider_execution_hash ?? record.provider_execution_hash,
    ),
    route_decision_ref: requiredStringRef("providerExecution.route_decision_ref", record.route_decision_ref),
    route_receipt_ref: requiredStringRef("providerExecution.route_receipt_ref", record.route_receipt_ref),
    route_ref: requiredStringRef("providerExecution.route_ref", record.route_ref),
    provider_ref: requiredStringRef("providerExecution.provider_ref", record.provider_ref),
    provider_kind: requiredStringRef("provider.kind", provider.kind),
    endpoint_ref: requiredStringRef("providerExecution.endpoint_ref", record.endpoint_ref),
    model_ref: requiredStringRef("providerExecution.model_ref", record.model_ref),
    capability: requiredStringRef("providerExecution.capability", record.capability),
    invocation_kind: requiredStringRef("providerExecution.invocation_kind", record.invocation_kind ?? kind),
    input: String(input ?? ""),
    request_hash: requiredStringRef("providerExecution.request_hash", record.request_hash),
    execution_backend: modelMountProviderStreamInvocationExecutionBackend(selection),
    api_format: optionalRef(endpoint.api_format ?? provider.api_format),
    driver: explicitProviderDriver(selection),
    backend_ref: optionalRef(instance.backend_id ?? endpoint.backend_id),
    stream_status: optionalRef(record.stream_status) ?? "started",
    receipt_refs: modelMountProviderExecutionAdmission.receipt_refs ?? record.receipt_refs ?? [],
    evidence_refs: uniqueRefs([
      modelMountProviderExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
      ...(modelMountProviderExecutionAdmission.evidence_refs ?? []),
    ]),
    admitted_provider_execution: record,
  };
}

export function modelMountProviderResultAdmissionRequestForExecution({
  input,
  instance = {},
  kind,
  modelMountProviderExecutionAdmission = {},
  providerResult = {},
  selection,
} = {}) {
  assertCanonicalModelInvocationHelperInputs({ selection, instance, providerResult });
  const stream = Boolean(optionalRef(modelMountProviderExecutionAdmission.record?.stream_status));
  const expectedExecutionBackend = expectedProviderResultExecutionBackend(selection, { stream });
  const executionBackend = requiredStringRef(
    "providerResult.execution_backend",
    providerResult.execution_backend,
  );
  if (executionBackend !== expectedExecutionBackend) {
    throw providerResultRustBackendMismatch(selection, {
      actual: executionBackend,
      expected: expectedExecutionBackend,
      stream,
    });
  }
  const record = modelMountProviderExecutionAdmission.record ?? {};
  const provider = selection?.provider ?? {};
  const endpoint = selection?.endpoint ?? {};
  const output_text = String(providerResult.output_text ?? "");
  const token_count = requiredTokenCount(
    providerResult.token_count,
    "providerResult.token_count",
  );
  return {
    schema_version: "ioi.model_mount.provider_result.v1",
    provider_execution_ref: requiredStringRef(
      "modelMountProviderExecutionAdmission.provider_execution_ref",
      modelMountProviderExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
    ),
    provider_execution_hash: requiredStringRef(
      "modelMountProviderExecutionAdmission.provider_execution_hash",
      modelMountProviderExecutionAdmission.provider_execution_hash ?? record.provider_execution_hash,
    ),
    route_decision_ref: requiredStringRef("providerExecution.route_decision_ref", record.route_decision_ref),
    route_receipt_ref: requiredStringRef("providerExecution.route_receipt_ref", record.route_receipt_ref),
    route_ref: requiredStringRef("providerExecution.route_ref", record.route_ref),
    provider_ref: requiredStringRef("providerExecution.provider_ref", record.provider_ref),
    provider_kind: requiredStringRef("provider.kind", provider.kind),
    endpoint_ref: requiredStringRef("providerExecution.endpoint_ref", record.endpoint_ref),
    model_ref: requiredStringRef("providerExecution.model_ref", record.model_ref),
    capability: requiredStringRef("providerExecution.capability", record.capability),
    invocation_kind: requiredStringRef("providerExecution.invocation_kind", record.invocation_kind ?? kind),
    request_hash: requiredStringRef("providerExecution.request_hash", record.request_hash),
    output_text,
    output_hash: hashRef(stableHash(output_text), "output_hash"),
    token_count,
    provider_response_kind: optionalRef(providerResult.provider_response_kind),
    execution_backend: executionBackend,
    backend_ref: optionalRef(providerResult.backend_id ?? instance.backend_id ?? endpoint.backend_id),
    stream_status: optionalRef(record.stream_status),
    receipt_refs: modelMountProviderExecutionAdmission.receipt_refs ?? record.receipt_refs ?? [],
    provider_auth_evidence_refs: uniqueRefs(providerResult.provider_auth_evidence_refs ?? []),
    backend_evidence_refs: uniqueRefs(providerResult.backend_evidence_refs ?? []),
    evidence_refs: uniqueRefs([
      modelMountProviderExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
      ...(modelMountProviderExecutionAdmission.evidence_refs ?? []),
    ]),
    admitted_provider_execution: record,
  };
}

export function modelMountInvocationReceiptBindingRequestForReceipt({
  admission,
  admissionRequest,
  agentgresTransition = null,
  receiptDetails = {},
  receiptId,
} = {}) {
  const receiptRefValue = receiptRef(requiredStringRef("receiptId", receiptId));
  const { invocation, result } = createModelMountStepModuleProjection({
    invocation_ref: requiredStringRef("admissionRequest.invocation_ref", admissionRequest?.invocation_ref),
    route_ref: requiredStringRef("admissionRequest.route_ref", admissionRequest?.route_ref),
    provider_ref: requiredStringRef("admissionRequest.provider_ref", admissionRequest?.provider_ref),
    endpoint_ref: requiredStringRef("admissionRequest.endpoint_ref", admissionRequest?.endpoint_ref),
    model_ref: requiredStringRef("admissionRequest.model_ref", admissionRequest?.model_ref),
    capability: requiredStringRef("admissionRequest.capability", admissionRequest?.capability),
    invocation_kind: requiredStringRef("admissionRequest.invocation_kind", admissionRequest?.invocation_kind),
    input_hash: hashRef(admissionRequest?.input_hash, "admissionRequest.input_hash"),
    output_hash: hashRef(admissionRequest?.output_hash, "admissionRequest.output_hash"),
    policy_hash: policyHashRef(admissionRequest?.policy_hash),
    route_decision_ref: requiredStringRef("admissionRequest.route_decision_ref", admissionRequest?.route_decision_ref),
    route_receipt_ref: requiredStringRef("admissionRequest.route_receipt_ref", admissionRequest?.route_receipt_ref),
    receipt_ref: receiptRefValue,
    authority_grant_refs: admissionRequest?.authority_grant_refs ?? [],
    workflow_graph_id: optionalRef(admissionRequest?.workflow_graph_ref) ?? "workflow:model-mount",
    workflow_node_id:
      optionalRef(admissionRequest?.workflow_node_ref) ?? `node:model-mount:${requiredStringRef("receiptId", receiptId)}`,
    privacy_profile: admissionRequest?.privacy_profile ?? "internal",
    node_plaintext_allowed: Boolean(admissionRequest?.node_plaintext_allowed),
    custody_proof_ref: admissionRequest?.custody_ref ?? null,
    idempotency_key: admissionRequest?.idempotency_key ?? `model_invocation:${receiptId}`,
    state_root_before: requiredStringRef("agentgresTransition.state_root_before", agentgresTransition?.state_root_before),
    projection_watermark: requiredStringRef("agentgresTransition.projection_watermark", agentgresTransition?.projection_watermark),
    agentgres_operation_refs: [
      requiredStringRef("agentgresTransition.operation_ref", agentgresTransition?.operation_ref),
    ],
    state_root_after: requiredStringRef("agentgresTransition.state_root_after", agentgresTransition?.state_root_after),
    resulting_head: requiredStringRef("agentgresTransition.resulting_head", agentgresTransition?.resulting_head),
    evidence_refs: uniqueRefs([
      "rust_model_mount_core",
      admission?.invocation_admission_ref,
      ...(admission?.evidence_refs ?? []),
      ...(receiptDetails.provider_auth_evidence_refs ?? []),
      ...(receiptDetails.backend_evidence_refs ?? []),
    ]),
  });
  return {
    invocation,
    result,
    acceptedReceiptTransition: objectRecord(agentgresTransition?.acceptedReceiptTransition),
    receiptRef: receiptRefValue,
  };
}

export function modelMountInvocationAgentgresTransitionForReceipt(
  state,
  {
    admission,
    admissionRequest,
    receiptDetails = {},
    receiptId,
    receiptKind,
  } = {},
) {
  if (typeof state.planModelMountAcceptedReceiptTransition !== "function") {
    const error = new Error("Model invocation Agentgres admission requires Rust model-mount accepted receipt transition planning.");
    error.status = 500;
    error.code = "model_mount_accepted_receipt_transition_planner_required";
    throw error;
  }
  if (typeof state.agentgresModelMountingHead !== "function") {
    const error = new Error("Model invocation Agentgres admission requires a current model-mounting operation head.");
    error.status = 500;
    error.code = "model_mount_agentgres_head_required";
    throw error;
  }
  const currentHead = normalizeAgentgresHead(state.agentgresModelMountingHead());
  const transition = state.planModelMountAcceptedReceiptTransition({
    schema_version: "ioi.model_mount.accepted_receipt_transition.v1",
    current_sequence: currentHead.sequence,
    current_head_ref: currentHead.head_ref,
    current_state_root: currentHead.state_root,
    receipt_id: requiredStringRef("receiptId", receiptId),
    receipt_kind: requiredStringRef("receiptKind", receiptKind),
    route_decision_ref: admissionRequest?.route_decision_ref ?? null,
    invocation_admission_ref: admission?.invocation_admission_ref ?? null,
    invocation_admission_hash: admission?.invocation_admission_hash ?? null,
    input_hash: admissionRequest?.input_hash ?? receiptDetails.input_hash ?? null,
    output_hash: admissionRequest?.output_hash ?? receiptDetails.output_hash ?? null,
  });
  return {
    operation_id: requiredStringRef("transition.operation_id", transition?.operation_id),
    operation_ref: requiredStringRef("transition.operation_ref", transition?.operation_ref),
    expected_heads: uniqueRefs(transition?.expected_heads ?? []),
    state_root_before: requiredStringRef("transition.state_root_before", transition?.state_root_before),
    state_root_after: requiredStringRef("transition.state_root_after", transition?.state_root_after),
    resulting_head: requiredStringRef("transition.resulting_head", transition?.resulting_head),
    projection_watermark: requiredStringRef("transition.projection_watermark", transition?.projection_watermark),
    transition_hash: requiredStringRef("transition.transition_hash", transition?.transition_hash),
    evidence_refs: uniqueRefs(transition?.evidence_refs ?? []),
    acceptedReceiptTransition: objectRecord(transition?.transition),
  };
}

export function withModelMountInvocationAdmission(details, admission) {
  return {
    ...details,
    model_mount_invocation_admission_schema_version: "ioi.model_mount.invocation_admission.v1",
    model_mount_invocation_admission_ref: admission.invocation_admission_ref,
    model_mount_invocation_admission_hash: admission.invocation_admission_hash,
    model_mount_invocation_admission_source: admission.source,
    model_mount_invocation_admission_backend: admission.backend,
    model_mount_invocation_admission_receipt_refs: admission.receipt_refs ?? [],
    model_mount_invocation_admission: admission.record,
  };
}

export function withModelMountProviderExecutionAdmission(details, admission) {
  return {
    ...details,
    model_mount_provider_execution_schema_version: "ioi.model_mount.provider_execution.v1",
    model_mount_provider_execution_ref: admission.provider_execution_ref,
    model_mount_provider_execution_hash: admission.provider_execution_hash,
    model_mount_provider_execution_source: admission.source,
    model_mount_provider_execution_backend: admission.backend,
    model_mount_provider_execution_receipt_refs: admission.receipt_refs ?? [],
    model_mount_provider_execution: admission.record,
  };
}

export function withModelMountInvocationReceiptBinding(details, binding) {
  return {
    ...details,
    model_mount_receipt_binding_source: binding.source,
    model_mount_receipt_binding_backend: binding.backend,
    model_mount_receipt_binding_ref: binding.receipt_binding?.binding_hash ?? null,
    model_mount_receipt_binding: binding.receipt_binding ?? null,
    model_mount_accepted_receipt_append_hash: binding.accepted_receipt_append?.append_hash ?? null,
    model_mount_accepted_receipt_append: binding.accepted_receipt_append ?? null,
    model_mount_step_module_invocation: binding.invocation ?? null,
    model_mount_step_module_result: binding.result ?? null,
    model_mount_router_admission: binding.router_admission ?? null,
    model_mount_agentgres_admission: binding.agentgres_admission ?? null,
    model_mount_agentgres_admission_hash: binding.agentgres_admission?.admission_hash ?? null,
    model_mount_agentgres_operation_ref: binding.agentgres_admission?.operation_ref ?? null,
    model_mount_agentgres_expected_heads: binding.agentgres_admission?.expected_heads ?? [],
    model_mount_agentgres_state_root_before: binding.agentgres_admission?.state_root_before ?? null,
    model_mount_agentgres_state_root_after: binding.agentgres_admission?.state_root_after ?? null,
    model_mount_agentgres_resulting_head: binding.agentgres_admission?.resulting_head ?? null,
    model_mount_projection_record: binding.projection_record ?? null,
    model_mount_receipt_binding_receipt_refs: binding.receipt_refs ?? [],
  };
}

function withModelMountProviderResultAdmission(providerResult, admission) {
  return {
    ...providerResult,
    model_mount_provider_result_admission_schema_version: "ioi.model_mount.provider_result.v1",
    model_mount_provider_result_admission_ref: admission.provider_result_ref,
    model_mount_provider_result_admission_hash: admission.provider_result_hash,
    model_mount_provider_result_admission_source: admission.source,
    model_mount_provider_result_admission_backend: admission.backend,
    model_mount_provider_result_admission_receipt_refs: admission.receipt_refs ?? [],
    model_mount_provider_result_admission_evidence_refs: admission.evidence_refs ?? [],
    model_mount_provider_result_admission: admission.record,
    backend_evidence_refs: uniqueRefs([
      ...(providerResult.backend_evidence_refs ?? []),
      admission.provider_result_ref,
      ...(admission.evidence_refs ?? []),
    ]),
  };
}

async function executeModelInvocationThroughRustCore(
  state,
  {
    body = {},
    deps = {},
    kind,
    requiredScope = null,
    stream = false,
  } = {},
) {
  const {
    inputText = modelInvocationInputText,
    stableHash: hash = stableHash,
    supportsResponseState = modelInvocationSupportsResponseState,
  } = deps;
  const started = nowMs(state);
  const requestBody = objectRecord(body) ?? {};
  const input = inputText(requestBody);
  const statefulInvocation = supportsResponseState(kind);
  const previousResponseId = statefulInvocation ? optionalRef(requestBody.previous_response_id) : null;
  const previousState = previousResponseId ? state.conversationState(previousResponseId) : null;
  const responseId = statefulInvocation ? state.nextResponseId(requestBody.response_id) : null;
  const capability = capabilityForInvocationKind(kind);
  const rawSelection = state.selectRoute({
    modelId: requestBody.model ?? requestBody.model_id ?? null,
    routeId: requestBody.route_id ?? null,
    capability,
    policy: requestBody.model_policy ?? {},
    body: requestBody,
  });
  const selection = normalizeModelMountSelection(rawSelection);
  const routeReceipt = requiredRouteReceipt(selection);
  const continuationSafety = state.validateContinuationSafety({
    previousState,
    selection,
    body: requestBody,
  });
  const rawInstance = await state.ensureLoaded(rawSelection?.endpoint ?? selection.endpoint);
  const instance = normalizeModelMountInstance(rawInstance, selection);
  const ephemeralMcp = normalizeEphemeralMcp(
    state.compileEphemeralMcpIntegrations({ body: requestBody, input }),
  );
  const providerBody = requestBody;
  const token = normalizeInvocationToken(null);
  const providerExecutionAdmission = admitModelMountProviderExecution(
    state,
    modelMountProviderExecutionRequestForInvocation({
      body: requestBody,
      capability,
      ephemeralMcp,
      hash,
      input,
      instance,
      kind,
      previousResponseId,
      providerBody,
      responseId,
      routeReceipt,
      selection,
      streamStatus: stream ? "started" : null,
      token,
    }),
  );
  const providerInvocation = stream
    ? executeModelMountProviderStreamInvocation(
        state,
        modelMountProviderStreamInvocationRequestForExecution({
          input,
          instance,
          kind,
          modelMountProviderExecutionAdmission: providerExecutionAdmission,
          selection,
        }),
      )
    : executeModelMountProviderInvocation(
        state,
        modelMountProviderInvocationRequestForExecution({
          input,
          instance,
          kind,
          modelMountProviderExecutionAdmission: providerExecutionAdmission,
          selection,
        }),
      );
  const providerResultForAdmission = canonicalProviderResultForAdmission(providerInvocation);
  const providerResultAdmission = admitModelMountProviderResult(
    state,
    modelMountProviderResultAdmissionRequestForExecution({
      input,
      instance,
      kind,
      modelMountProviderExecutionAdmission: providerExecutionAdmission,
      providerResult: providerResultForAdmission,
      selection,
    }),
  );
  const providerResult = withModelMountProviderResultAdmission(
    providerResultForAdmission,
    providerResultAdmission,
  );
  const outputText = stream ? "" : providerResult.output_text;
  const tokenCount = providerResult.token_count;
  const latencyMs = Math.max(1, nowMs(state) - started);
  const receiptKind = "model_invocation";
  const receiptId = nextInvocationReceiptId(state, receiptKind);
  const receiptDetails = withModelMountProviderExecutionAdmission(
    invocationReceiptDetails({
      body: requestBody,
      continuationSafety,
      ephemeralMcp,
      hash,
      input,
      instance,
      latencyMs,
      outputText: providerResult.output_text,
      previousResponseId,
      providerResult,
      requiredScope,
      responseId,
      routeReceipt,
      selection,
      token,
      tokenCount,
      stream,
    }),
    providerExecutionAdmission,
  );
  const invocationAdmissionRequest = modelMountInvocationAdmissionRequestForReceipt({
    body: requestBody,
    capability,
    kind,
    receiptDetails,
    receiptId,
    receiptKind,
    routeReceipt,
    selection,
    streamStatus: stream ? "started" : null,
  });
  const invocationAdmission = admitModelMountInvocation(state, invocationAdmissionRequest);
  const agentgresTransition = modelMountInvocationAgentgresTransitionForReceipt(state, {
    admission: invocationAdmission,
    admissionRequest: invocationAdmissionRequest,
    receiptDetails,
    receiptId,
    receiptKind,
  });
  const receiptBinding = invokeRustModelMountReceiptBinding(
    state,
    modelMountInvocationReceiptBindingRequestForReceipt({
      admission: invocationAdmission,
      admissionRequest: invocationAdmissionRequest,
      agentgresTransition,
      receiptDetails,
      receiptId,
    }),
  );
  const receipt = persistModelInvocationReceipt(state, {
    details: withModelMountInvocationReceiptBinding(
      withModelMountInvocationAdmission(receiptDetails, invocationAdmission),
      receiptBinding,
    ),
    kind: receiptKind,
    receiptBinding,
    receiptId,
    routeReceipt,
    selection,
    stream,
  });
  const invocation = {
    kind,
    input,
    outputText,
    model: selection.endpoint.model_id,
    route: selection.route,
    endpoint: selection.endpoint,
    instance,
    receipt,
    routeReceipt,
    tokenCount,
    providerResponse: providerInvocation.provider_response ?? providerInvocation.result?.provider_response ?? null,
    providerResponseKind: providerResult.provider_response_kind ?? null,
    toolReceiptIds: ephemeralMcp.toolReceiptIds,
    responseId,
    previousResponseId,
    previousConversationState: previousState,
    continuationSafety,
  };
  if (!stream) return invocation;
  const streamHandle = readableStreamFromRustProviderChunks(
    providerInvocation.stream_chunks ?? providerInvocation.result?.stream_chunks ?? [],
  );
  return {
    native: true,
    invocation,
    providerStream: streamHandle.stream,
    abort: streamHandle.abort,
    providerResult: {
      ...providerInvocation,
      ...providerResult,
      streamFormat:
        providerInvocation.stream_format ?? providerInvocation.result?.stream_format ?? null,
      streamKind:
        providerInvocation.stream_kind ?? providerInvocation.result?.stream_kind ?? null,
    },
  };
}

function persistModelInvocationReceipt(
  state,
  {
    details,
    kind,
    receiptBinding = {},
    receiptId,
    routeReceipt,
    selection,
    stream = false,
  } = {},
) {
  const receipt = {
    id: receiptId,
    runId: null,
    kind,
    summary: stream
      ? `${details.invocation_kind ?? "model"} invocation stream started through ${selection.route.id} to ${selection.endpoint.model_id}.`
      : `${details.invocation_kind ?? "model"} invocation routed through ${selection.route.id} to ${selection.endpoint.model_id}.`,
    redaction: "redacted",
    evidenceRefs: uniqueRefs([
      "model_router",
      "rust_model_mount_core",
      "model_mount_invocation_positive_rust_path",
      "model_mount_invocation_js_facade_retired",
      "agentgres_model_invocation_truth_required",
      "rust_daemon_core_model_invocation_receipt",
      routeReceipt?.id,
      selection.route?.id,
      selection.endpoint?.id,
      selection.provider?.id,
      details.model_mount_provider_execution_ref,
      details.model_mount_provider_result_admission_ref,
      details.model_mount_invocation_admission_ref,
      receiptBinding.receipt_binding?.binding_hash,
      receiptBinding.accepted_receipt_append?.append_hash,
      ...(receiptBinding.evidence_refs ?? []),
    ]),
    createdAt: nowIsoForState(state),
    details: {
      ...details,
      rust_daemon_core_receipt_author: "daemonCoreModelMountApi.bindModelMountInvocationReceipt",
    },
    schemaVersion: "ioi.model-mounting.runtime.v1",
  };
  if (typeof state.persistRustAuthoredReceipt !== "function") {
    const error = new Error("Model invocation receipts require Rust-authored receipt persistence.");
    error.status = 500;
    error.code = "model_mount_invocation_receipt_persistence_required";
    error.details = { receipt_id: receiptId };
    throw error;
  }
  return state.persistRustAuthoredReceipt(receipt);
}

export function modelMountProviderInvocationRequiresRust(selection = {}, options = {}) {
  assertCanonicalModelInvocationHelperInputs({ selection });
  void options;
  return true;
}

export function modelMountProviderStreamInvocationRequiresRust(selection = {}) {
  assertCanonicalModelInvocationHelperInputs({ selection });
  return true;
}

function admitModelMountInvocation(state, request) {
  if (typeof state.admitModelMountInvocation !== "function") {
    const error = new Error("Model invocation requires Rust model_mount invocation admission.");
    error.status = 500;
    error.code = "model_mount_invocation_admission_required";
    throw error;
  }
  return state.admitModelMountInvocation(request);
}

function admitModelMountProviderExecution(state, request) {
  if (typeof state.admitModelMountProviderExecution !== "function") {
    const error = new Error("Model provider execution requires Rust model_mount provider execution admission.");
    error.status = 500;
    error.code = "model_mount_provider_execution_admission_required";
    throw error;
  }
  return state.admitModelMountProviderExecution(request);
}

function admitModelMountProviderResult(state, request) {
  if (typeof state.admitModelMountProviderResult !== "function") {
    const error = new Error("Model provider result requires Rust model_mount provider result admission.");
    error.status = 500;
    error.code = "model_mount_provider_result_admission_required";
    throw error;
  }
  return state.admitModelMountProviderResult(request);
}

function executeModelMountProviderInvocation(state, request) {
  if (typeof state.executeModelMountProviderInvocation !== "function") {
    const error = new Error("Migrated model provider execution requires Rust model_mount provider invocation execution.");
    error.status = 500;
    error.code = "model_mount_provider_invocation_rust_core_unavailable";
    throw error;
  }
  return state.executeModelMountProviderInvocation(request);
}

function executeModelMountProviderStreamInvocation(state, request) {
  if (typeof state.executeModelMountProviderStreamInvocation !== "function") {
    const error = new Error("Migrated native-local model stream execution requires Rust model_mount provider stream invocation execution.");
    error.status = 500;
    error.code = "model_mount_provider_stream_invocation_rust_core_unavailable";
    throw error;
  }
  return state.executeModelMountProviderStreamInvocation(request);
}

function invokeRustModelMountReceiptBinding(state, request) {
  if (typeof state.bindModelMountInvocationReceipt !== "function") {
    const error = new Error("Model invocation receipt persistence requires Rust receipt_binder binding.");
    error.status = 500;
    error.code = "model_mount_invocation_receipt_binding_required";
    throw error;
  }
  return state.bindModelMountInvocationReceipt(request);
}

function nextInvocationReceiptId(state, kind) {
  if (typeof state.nextReceiptId !== "function") {
    const error = new Error("Model invocation admission requires a precomputed receipt id before Rust admission.");
    error.status = 500;
    error.code = "model_mount_invocation_receipt_id_required";
    throw error;
  }
  return state.nextReceiptId(kind);
}

function normalizeModelMountSelection(selection = {}) {
  const endpoint = canonicalEndpointRecord(selection.endpoint);
  const provider = canonicalProviderRecord(selection.provider, endpoint);
  return {
    route: objectRecord(selection.route) ?? {},
    endpoint,
    provider,
    route_decision: objectRecord(selection.route_decision) ?? {},
    route_receipt: canonicalRouteReceiptRecord(selection.route_receipt),
    route_control: canonicalRouteControlRecord(selection.route_control),
    rust_core_boundary: optionalRef(selection.rust_core_boundary),
    evidence_refs: uniqueRefs(selection.evidence_refs ?? []),
  };
}

function canonicalEndpointRecord(endpoint = {}) {
  const record = objectRecord(endpoint) ?? {};
  return {
    id: optionalRef(record.id),
    model_id: optionalRef(record.model_id),
    provider_id: optionalRef(record.provider_id),
    api_format: optionalRef(record.api_format),
    driver: optionalRef(record.driver),
    backend_id: optionalRef(record.backend_id),
    custody_ref: optionalRef(record.custody_ref),
    node_plaintext_allowed: Boolean(record.node_plaintext_allowed ?? false),
    privacy_class: optionalRef(record.privacy_class),
    status: optionalRef(record.status),
    capabilities: arrayOfStrings(record.capabilities),
    load_policy: objectRecord(record.load_policy),
  };
}

function canonicalProviderRecord(provider = {}, endpoint = {}) {
  const record = objectRecord(provider) ?? {};
  return {
    id: optionalRef(record.id ?? endpoint.provider_id),
    kind: optionalRef(record.kind),
    api_format: optionalRef(record.api_format),
    driver: optionalRef(record.driver),
    secret_ref: optionalRef(record.secret_ref ?? record.secretRef),
    custody_ref: optionalRef(record.custody_ref),
    node_plaintext_allowed: Boolean(record.node_plaintext_allowed ?? false),
    privacy_class: optionalRef(record.privacy_class),
    status: optionalRef(record.status),
    capabilities: arrayOfStrings(record.capabilities),
  };
}

function canonicalRouteReceiptRecord(receipt = {}) {
  const record = objectRecord(receipt);
  if (!record) return null;
  return {
    id: optionalRef(record.id),
    kind: optionalRef(record.kind),
    details: objectRecord(record.details) ?? {},
  };
}

function canonicalRouteControlRecord(control = {}) {
  const record = objectRecord(control);
  if (!record) return null;
  const commit = objectRecord(record.commit) ?? {};
  const receiptCommit = objectRecord(record.receipt_commit) ?? {};
  return {
    record_dir: optionalRef(record.record_dir),
    record_id: optionalRef(record.record_id),
    control_hash: optionalRef(record.control_hash),
    commit_hash: optionalRef(commit.commit_hash),
    object_ref: optionalRef(commit.object_ref),
    receipt_commit_hash: optionalRef(receiptCommit.commit_hash),
    receipt_object_ref: optionalRef(receiptCommit.object_ref),
  };
}

function normalizeModelMountInstance(instance = {}, selection = {}) {
  const record = objectRecord(instance) ?? {};
  return {
    id: optionalRef(record.id),
    endpoint_id: optionalRef(record.endpoint_id ?? selection.endpoint?.id),
    provider_id: optionalRef(record.provider_id ?? selection.provider?.id),
    backend_id: optionalRef(record.backend_id ?? selection.endpoint?.backend_id),
    backend_process: objectRecord(record.backend_process),
    backend_process_id: optionalRef(record.backend_process_id),
    backend_process_pid_hash: optionalRef(record.backend_process_pid_hash),
  };
}

function normalizeEphemeralMcp(value = {}) {
  return {
    toolReceiptIds: uniqueRefs(value.tool_receipt_ids ?? []),
    serverIds: uniqueRefs(value.server_ids ?? []),
    evidenceRefs: uniqueRefs(value.evidence_refs ?? []),
  };
}

function normalizeInvocationToken(value = {}) {
  return {
    grant_ref: optionalRef(value?.grant_ref),
  };
}

function requiredRouteReceipt(selection = {}) {
  const routeReceipt = objectRecord(selection.route_receipt);
  if (!routeReceipt) {
    const error = new Error("Model invocation requires a Rust-authored route-selection receipt.");
    error.status = 500;
    error.code = "model_mount_route_selection_receipt_required";
    throw error;
  }
  return routeReceipt;
}

function canonicalProviderResultForAdmission(providerResult = {}) {
  const result = objectRecord(providerResult.result) ?? {};
  return {
    output_text: String(providerResult.output_text ?? result.output_text ?? ""),
    token_count:
      objectRecord(providerResult.token_count ?? result.token_count) ?? null,
    provider_response_kind: optionalRef(
      providerResult.provider_response_kind ??
        result.provider_response_kind,
    ),
    execution_backend: optionalRef(
      providerResult.execution_backend ??
        result.execution_backend,
    ),
    backend_id: optionalRef(providerResult.backend_id ?? result.backend_id),
    provider_auth_evidence_refs: uniqueRefs(
      providerResult.provider_auth_evidence_refs ??
        result.provider_auth_evidence_refs ??
        [],
    ),
    backend_evidence_refs: uniqueRefs(
      providerResult.backend_evidence_refs ??
        result.backend_evidence_refs ??
        result.evidence_refs ??
        providerResult.evidence_refs ??
        [],
    ),
    evidence_refs: uniqueRefs(providerResult.evidence_refs ?? result.evidence_refs ?? []),
  };
}

function invocationReceiptDetails({
  body = {},
  continuationSafety,
  ephemeralMcp,
  hash,
  input,
  instance,
  latencyMs,
  outputText,
  previousResponseId,
  providerResult,
  requiredScope,
  responseId,
  routeReceipt,
  selection,
  token,
  tokenCount,
  stream,
}) {
  const backendId = providerResult.backend_id ?? instance.backend_id ?? selection.endpoint.backend_id ?? null;
  const routeDecisionRef = requiredStringRef(
    "routeReceipt.details.model_mount_route_decision_ref",
    routeReceipt?.details?.model_mount_route_decision_ref ??
      selection.route_decision?.route_decision_ref,
  );
  return {
    route_id: requiredStringRef("route.id", selection.route?.id),
    route_receipt_id: requiredStringRef("routeReceipt.id", routeReceipt?.id),
    selected_model: requiredStringRef("endpoint.model_id", selection.endpoint?.model_id),
    endpoint_id: requiredStringRef("endpoint.id", selection.endpoint?.id),
    provider_id: requiredStringRef("provider.id", selection.provider?.id),
    instance_id: requiredStringRef("instance.id", instance?.id),
    backend: providerResult.execution_backend ?? selection.endpoint?.api_format ?? null,
    backend_id: backendId,
    selected_backend: backendId,
    policy_hash: hash(body.model_policy ?? {}),
    required_scope: requiredScope ?? null,
    grant_id: token.grant_ref,
    token_count: tokenCount,
    latency_ms: latencyMs,
    input_hash: hash(input),
    output_hash: hash(outputText),
    provider_response_kind: providerResult.provider_response_kind ?? null,
    backend_process: instance.backend_process ?? null,
    backend_process_id: instance.backend_process_id ?? null,
    backend_process_pid_hash: instance.backend_process_pid_hash ?? null,
    backend_evidence_refs: providerResult.backend_evidence_refs ?? [],
    provider_auth_evidence_refs: providerResult.provider_auth_evidence_refs ?? [],
    provider_auth_header_names: [],
    model_mount_route_decision_ref: routeDecisionRef,
    model_mount_provider_result_admission_schema_version:
      providerResult.model_mount_provider_result_admission_schema_version ?? null,
    model_mount_provider_result_admission_ref:
      providerResult.model_mount_provider_result_admission_ref ?? null,
    model_mount_provider_result_admission_hash:
      providerResult.model_mount_provider_result_admission_hash ?? null,
    model_mount_provider_result_admission_source:
      providerResult.model_mount_provider_result_admission_source ?? null,
    model_mount_provider_result_admission_backend:
      providerResult.model_mount_provider_result_admission_backend ?? null,
    model_mount_provider_result_admission_receipt_refs:
      providerResult.model_mount_provider_result_admission_receipt_refs ?? [],
    model_mount_provider_result_admission_evidence_refs:
      providerResult.model_mount_provider_result_admission_evidence_refs ?? [],
    model_mount_provider_result_admission:
      providerResult.model_mount_provider_result_admission ?? null,
    tool_receipt_ids: ephemeralMcp.toolReceiptIds,
    ephemeral_mcp_server_ids: ephemeralMcp.serverIds,
    response_id: responseId,
    previous_response_id: previousResponseId,
    continuation: continuationSafety,
    invocation_kind: stream ? "model_mount.invocation.stream_start" : "model_mount.invocation.invoke",
    stream_status: stream ? "started" : null,
    stream_source: stream ? "provider_native" : null,
    send_options: body.send_options ?? null,
    memory: body.memory ?? body.send_options?.memory ?? null,
  };
}

function modelInvocationInputText(body = {}) {
  if (typeof body.input === "string") return body.input;
  if (Array.isArray(body.input)) return body.input.map(inputPartToText).join("\n");
  if (typeof body.prompt === "string") return body.prompt;
  if (typeof body.query === "string") return body.query;
  if (Array.isArray(body.messages)) {
    return body.messages
      .map((message) => `${message?.role ?? "user"}: ${inputPartToText(message?.content ?? "")}`)
      .join("\n");
  }
  if (Array.isArray(body.documents)) {
    return [body.query, ...body.documents].map(inputPartToText).filter(Boolean).join("\n");
  }
  return JSON.stringify(body ?? {});
}

function inputPartToText(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(inputPartToText).join("\n");
  if (value && typeof value === "object") {
    if (typeof value.text === "string") return value.text;
    if (typeof value.content === "string") return value.content;
    if (typeof value.input_text === "string") return value.input_text;
    return JSON.stringify(value);
  }
  return String(value ?? "");
}

function modelInvocationSupportsResponseState(kind) {
  return ["chat", "chat.completions", "responses", "messages", "completions"].includes(kind);
}

function readableStreamFromRustProviderChunks(chunks = []) {
  const encoder = new TextEncoder();
  const encoded = (Array.isArray(chunks) ? chunks : []).map((chunk) => encoder.encode(String(chunk ?? "")));
  let controllerRef = null;
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    try {
      controllerRef?.close();
    } catch {
      // The stream may already be canceled by the protocol adapter.
    }
  };
  const abort = () => close();
  const stream = new ReadableStream({
    start(controller) {
      controllerRef = controller;
      for (const chunk of encoded) {
        if (closed) break;
        controller.enqueue(chunk);
      }
      close();
    },
    cancel() {
      abort();
    },
  });
  return { stream, abort };
}

function nowMs(state) {
  const value = typeof state?.now === "function" ? state.now() : new Date();
  if (typeof value?.getTime === "function") return value.getTime();
  return Date.now();
}

function nowIsoForState(state) {
  if (typeof state?.nowIso === "function") return state.nowIso();
  return new Date().toISOString();
}

function modelMountProviderInvocationExecutionBackend(selection = {}) {
  if (nativeLocalProviderInvocationSelected(selection)) {
    return "rust_model_mount_native_local";
  }
  if (fixtureProviderInvocationSelected(selection)) {
    return "rust_model_mount_fixture";
  }
  if (hostedProviderInvocationSelected(selection)) {
    return "rust_model_mount_hosted_provider";
  }
  throw unsupportedProviderInvocationRustBackend(selection, { stream: false });
}

function modelMountProviderStreamInvocationExecutionBackend(selection = {}) {
  if (nativeLocalProviderInvocationSelected(selection)) {
    return "rust_model_mount_native_local_stream";
  }
  if (hostedProviderInvocationSelected(selection)) {
    return "rust_model_mount_hosted_provider_stream";
  }
  throw unsupportedProviderInvocationRustBackend(selection, { stream: true });
}

function fixtureProviderInvocationSelected(selection = {}) {
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  const driver = explicitProviderDriver(selection);
  return provider.kind === "local_folder" || driver === "fixture" || endpoint.api_format === "ioi_fixture";
}

function nativeLocalProviderInvocationSelected(selection = {}) {
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  const driver = explicitProviderDriver(selection);
  return provider.kind === "ioi_native_local" || driver === "native_local" || endpoint.api_format === "ioi_native";
}

function hostedProviderInvocationSelected(selection = {}) {
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  const driver = explicitProviderDriver(selection);
  return [
    "openai",
    "anthropic",
    "gemini",
    "custom_http",
    "openai_compatible",
    "ollama",
    "vllm",
    "llama_cpp",
    "lm_studio",
    "depin_tee",
  ].includes(provider.kind) ||
    ["openai", "anthropic", "gemini", "custom", "openai_compatible", "ollama"].includes(endpoint.api_format ?? provider.api_format) ||
    ["openai_compatible", "hosted_provider"].includes(driver);
}

function hostedProviderAuthEvidenceRefs(selection = {}, hash = stableHash) {
  if (fixtureProviderInvocationSelected(selection) || nativeLocalProviderInvocationSelected(selection)) return [];
  if (!hostedProviderInvocationSelected(selection)) return [];
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  const secretRef = optionalRef(
    provider.secret_ref ??
      endpoint.secret_ref ??
      provider.auth_vault_ref ??
      endpoint.auth_vault_ref ??
      provider.api_key_vault_ref ??
      endpoint.api_key_vault_ref,
  );
  const refs = [
    "rust_model_mount_hosted_provider_auth_gate",
    "wallet_network_provider_transport_authority_bound",
    "ctee_hosted_provider_secret_not_exposed",
    "provider_env_secret_material_fallback_retired",
  ];
  if (secretRef?.startsWith("vault://")) {
    refs.push("wallet_network_provider_vault_ref_bound");
    refs.push("rust_provider_auth_materialization_bound");
    refs.push("hosted_provider_auth_header_materialized_by_rust");
    refs.push(`provider_vault_ref_hash:${hash(secretRef)}`);
  } else {
    refs.push("wallet_network_provider_vault_ref_required");
  }
  return uniqueRefs(refs);
}

function unsupportedProviderInvocationRustBackend(selection = {}, { stream = false } = {}) {
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  const driver = explicitProviderDriver(selection);
  const error = new Error("Provider invocation requires a Rust model_mount execution backend.");
  error.status = 501;
  error.code = "model_mount_provider_invocation_rust_backend_required";
  error.details = {
    provider_kind: provider.kind ?? null,
    provider_driver: driver ?? null,
    api_format: endpoint.api_format ?? provider.api_format ?? null,
    stream,
    rust_core_boundary: "model_mount.provider_invocation",
    evidence_refs: [
      "model_mount_provider_invocation_js_false_predicate_retired",
      "rust_daemon_core_provider_invocation_required",
      "agentgres_provider_invocation_truth_required",
    ],
  };
  return error;
}

function providerResultRustBackendMismatch(selection = {}, { actual, expected, stream = false } = {}) {
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  const driver = explicitProviderDriver(selection);
  const error = new Error("Provider result admission requires a Rust-owned provider invocation backend.");
  error.status = 501;
  error.code = "model_mount_provider_result_rust_backend_required";
  error.details = {
    provider_kind: provider.kind ?? null,
    provider_driver: driver ?? null,
    api_format: endpoint.api_format ?? provider.api_format ?? null,
    execution_backend: actual ?? null,
    expected_execution_backend: expected ?? null,
    stream,
    rust_core_boundary: "model_mount.provider_result",
    evidence_refs: [
      "model_mount_provider_result_js_observation_retired",
      "rust_daemon_core_provider_result_required",
      "agentgres_provider_result_truth_required",
    ],
  };
  return error;
}

function explicitProviderDriver(selection = {}) {
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  return optionalRef(endpoint.driver ?? provider.driver);
}

function expectedProviderResultExecutionBackend(selection = {}, { stream = false } = {}) {
  try {
    return stream
      ? modelMountProviderStreamInvocationExecutionBackend(selection)
      : modelMountProviderInvocationExecutionBackend(selection);
  } catch (error) {
    if (error?.code !== "model_mount_provider_invocation_rust_backend_required") throw error;
    throw providerResultRustBackendMismatch(selection, {
      actual: null,
      expected: null,
      stream,
    });
  }
}

function normalizeAgentgresHead(value) {
  const sequence = Number(value?.sequence);
  if (!Number.isInteger(sequence) || sequence < 0) {
    const error = new Error("Model invocation Agentgres admission requires a non-negative operation head sequence.");
    error.status = 500;
    error.code = "model_mount_agentgres_head_invalid";
    throw error;
  }
  return {
    sequence,
    head_ref: requiredStringRef("agentgresHead.head_ref", value?.head_ref),
    state_root: hashRef(value?.state_root, "agentgresHead.state_root"),
  };
}

function requiredStringRef(field, value) {
  const normalized = optionalRef(value);
  if (!normalized) {
    const error = new Error(`Model invocation admission missing ${field}.`);
    error.status = 500;
    error.code = "model_mount_invocation_ref_missing";
    error.details = { field };
    throw error;
  }
  return normalized;
}

function optionalRef(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function assertCanonicalModelInvocationRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_INVOCATION_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model invocation request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_mount_invocation_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: [
      "route_id",
      "model_policy",
      "response_id",
      "previous_response_id",
      "send_options",
      "authority_grant_refs",
      "authority_receipt_refs",
      "custody_ref",
      "privacy_profile",
      "node_plaintext_allowed",
    ],
  };
  throw error;
}

function assertCanonicalModelInvocationHelperInputs(values = {}) {
  const retiredAliases = [];
  collectRetiredModelInvocationHelperAliases(values, retiredAliases);
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model invocation migration helper aliases are retired; pass canonical snake_case Rust model_mount fields.",
  );
  error.status = 400;
  error.code = "model_mount_invocation_helper_aliases_retired";
  error.details = {
    retired_aliases: [...new Set(retiredAliases)],
    canonical_fields: [
      "api_format",
      "backend_evidence_refs",
      "backend_id",
      "custody_ref",
      "execution_backend",
      "grant_ref",
      "model_id",
      "node_plaintext_allowed",
      "output_text",
      "privacy_class",
      "provider_auth_evidence_refs",
      "provider_id",
      "provider_response_kind",
      "token_count",
    ],
  };
  throw error;
}

function collectRetiredModelInvocationHelperAliases(value, retiredAliases) {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) collectRetiredModelInvocationHelperAliases(item, retiredAliases);
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RETIRED_MODEL_INVOCATION_HELPER_ALIASES.includes(key)) {
      retiredAliases.push(key);
    }
    collectRetiredModelInvocationHelperAliases(nested, retiredAliases);
  }
}

function requiredTokenCount(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw providerResultTokenCountRequired(label);
  }
  const tokenCount = {
    prompt_tokens: requiredNonNegativeInteger(`${label}.prompt_tokens`, value.prompt_tokens),
    completion_tokens: requiredNonNegativeInteger(`${label}.completion_tokens`, value.completion_tokens),
    total_tokens: requiredNonNegativeInteger(`${label}.total_tokens`, value.total_tokens),
  };
  if (tokenCount.total_tokens !== tokenCount.prompt_tokens + tokenCount.completion_tokens) {
    const error = new Error(
      "Rust model_mount provider results must provide internally consistent token_count.",
    );
    error.status = 400;
    error.code = "model_mount_provider_result_token_count_mismatch";
    error.details = {
      field: label,
      token_count: tokenCount,
    };
    throw error;
  }
  return tokenCount;
}

function requiredNonNegativeInteger(label, value) {
  if (!Number.isInteger(value) || value < 0) {
    throw providerResultTokenCountRequired(label);
  }
  return value;
}

function providerResultTokenCountRequired(field) {
  const error = new Error(
    "Rust model_mount provider results must include token_count; JS token estimation fallback is retired.",
  );
  error.status = 400;
  error.code = "model_mount_provider_result_token_count_required";
  error.details = {
    field,
    rust_core_boundary: "model_mount.provider_result",
  };
  return error;
}

function policyHashRef(value) {
  const normalized = requiredStringRef("policy_hash", value);
  return normalized.startsWith("sha256:") ? normalized : `sha256:${normalized}`;
}

function hashRef(value, field) {
  const normalized = requiredStringRef(field, value);
  return normalized.startsWith("sha256:") ? normalized : `sha256:${normalized}`;
}

function receiptRef(value) {
  const normalized = requiredStringRef("receipt_ref", value);
  return normalized.startsWith("receipt://") ? normalized : `receipt://${normalized}`;
}

function uniqueRefs(values = []) {
  const refs = [];
  for (const value of values) {
    const ref = optionalRef(value);
    if (ref && !refs.includes(ref)) refs.push(ref);
  }
  return refs;
}

function arrayOfStrings(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((item) => typeof item === "string" && item.trim()).map((item) => item.trim());
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

export function capabilityForInvocationKind(kind) {
  if (kind === "embeddings") return "embeddings";
  if (kind === "rerank") return "rerank";
  if (kind === "responses") return "responses";
  return "chat";
}
