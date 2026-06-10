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
  "apiFormat",
  "backendEvidenceRefs",
  "backendId",
  "compatTranslation",
  "custodyRef",
  "executionBackend",
  "grantId",
  "modelId",
  "nodePlaintextAllowed",
  "outputText",
  "privacyClass",
  "providerAuthEvidenceRefs",
  "providerId",
  "providerResponseKind",
  "tokenCount",
];

const MODEL_INVOCATION_RUST_CORE_REQUIRED_EVIDENCE_REFS = [
  "model_mount_invocation_js_facade_retired",
  "rust_daemon_core_model_invocation_required",
  "agentgres_model_invocation_truth_required",
];

export async function invokeModel(state, { requiredScope, kind, body = {} } = {}) {
  assertCanonicalModelInvocationRequestBody(body);
  throwModelInvocationRustCoreRequired("model_mount.invocation.invoke", {
    kind,
    model_id: body.model ?? body.model_id ?? null,
    route_id: body.route_id ?? null,
    required_scope: requiredScope ?? null,
    stream: false,
  });
}

export async function startModelStream(state, { requiredScope, kind, body = {} } = {}) {
  assertCanonicalModelInvocationRequestBody(body);
  throwModelInvocationRustCoreRequired("model_mount.invocation.stream_start", {
    kind,
    model_id: body.model ?? body.model_id ?? null,
    route_id: body.route_id ?? null,
    required_scope: requiredScope ?? null,
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
    provider_auth_evidence_refs: [],
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

export function modelMountProviderInvocationRequiresRust(selection = {}, options = {}) {
  assertCanonicalModelInvocationHelperInputs({ selection });
  void options;
  return true;
}

export function modelMountProviderStreamInvocationRequiresRust(selection = {}) {
  assertCanonicalModelInvocationHelperInputs({ selection });
  return true;
}

function modelMountProviderInvocationExecutionBackend(selection = {}) {
  if (nativeLocalProviderInvocationSelected(selection)) {
    return "rust_model_mount_native_local";
  }
  if (fixtureProviderInvocationSelected(selection)) {
    return "rust_model_mount_fixture";
  }
  throw unsupportedProviderInvocationRustBackend(selection, { stream: false });
}

function modelMountProviderStreamInvocationExecutionBackend(selection = {}) {
  if (nativeLocalProviderInvocationSelected(selection)) {
    return "rust_model_mount_native_local_stream";
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

export function modelInvocationRustCoreRequiredError(operation_kind, details = {}) {
  const error = new Error("Model invocation execution requires Rust daemon-core ownership.");
  error.status = 501;
  error.code = "model_mount_invocation_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.invocation",
    operation_kind,
    ...details,
    evidence_refs: MODEL_INVOCATION_RUST_CORE_REQUIRED_EVIDENCE_REFS,
  };
  return error;
}

function throwModelInvocationRustCoreRequired(operation_kind, details = {}) {
  throw modelInvocationRustCoreRequiredError(operation_kind, details);
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

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

export function capabilityForInvocationKind(kind) {
  if (kind === "embeddings") return "embeddings";
  if (kind === "rerank") return "rerank";
  if (kind === "responses") return "responses";
  return "chat";
}
