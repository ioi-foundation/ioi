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
  const token = normalizeInvocationToken(null);
  const authorityBase = modelMountInvocationAuthorityBaseRequest({
    body: requestBody,
    capability,
    ephemeralMcp,
    input,
    instance,
    kind,
    previousResponseId,
    responseId,
    routeReceipt,
    selection,
    stream,
    streamStatus: stream ? "started" : null,
    token,
  });
  const providerExecutionAuthority = planModelMountInvocationAuthority(state, {
    ...authorityBase,
    operation: "provider_execution",
  }, "provider_execution_request");
  const providerExecutionAdmission = admitModelMountProviderExecution(
    state,
    providerExecutionAuthority.provider_execution_request,
  );
  const providerInvocationAuthority = planModelMountInvocationAuthority(state, {
    ...authorityBase,
    operation: stream ? "provider_stream_invocation" : "provider_invocation",
    provider_execution_admission: providerExecutionAdmission,
  }, "provider_invocation_request");
  const providerInvocation = stream
    ? executeModelMountProviderStreamInvocation(
        state,
        providerInvocationAuthority.provider_invocation_request,
      )
    : executeModelMountProviderInvocation(
        state,
        providerInvocationAuthority.provider_invocation_request,
      );
  const providerResultForAdmission = canonicalProviderResultForAdmission(providerInvocation);
  const providerResultAuthority = planModelMountInvocationAuthority(state, {
    ...authorityBase,
    operation: "provider_result_admission",
    provider_execution_admission: providerExecutionAdmission,
    provider_result: providerResultForAdmission,
  }, "provider_result_admission_request");
  const providerResultAdmission = admitModelMountProviderResult(
    state,
    providerResultAuthority.provider_result_admission_request,
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
  const invocationAuthority = planModelMountInvocationAuthority(state, {
    ...authorityBase,
    operation: "invocation_admission",
    continuation: continuationSafety,
    latency_ms: latencyMs,
    provider_execution_admission: providerExecutionAdmission,
    provider_result: providerResult,
    provider_result_admission: providerResultAdmission,
    receipt_id: receiptId,
    receipt_kind: receiptKind,
    required_scope: requiredScope ?? null,
  }, "invocation_admission_request");
  const receiptDetails = withModelMountProviderExecutionAdmission(
    invocationAuthority.receipt_details,
    providerExecutionAdmission,
  );
  const invocationAdmissionRequest = invocationAuthority.invocation_admission_request;
  const invocationAdmission = admitModelMountInvocation(state, invocationAdmissionRequest);
  const currentHead = normalizeAgentgresHeadForInvocationAuthority(state);
  const transitionAuthority = planModelMountInvocationAuthority(state, {
    ...authorityBase,
    operation: "accepted_receipt_transition",
    current_head: currentHead,
    invocation_admission: invocationAdmission,
    invocation_admission_request: invocationAdmissionRequest,
    receipt_details: receiptDetails,
    receipt_id: receiptId,
    receipt_kind: receiptKind,
  }, "accepted_receipt_transition_request");
  const agentgresTransition = planModelMountAcceptedReceiptTransitionForInvocation(
    state,
    transitionAuthority.accepted_receipt_transition_request,
  );
  const receiptBindingAuthority = planModelMountInvocationAuthority(state, {
    ...authorityBase,
    operation: "receipt_binding",
    agentgres_transition: agentgresTransition,
    invocation_admission: invocationAdmission,
    invocation_admission_request: invocationAdmissionRequest,
    receipt_details: receiptDetails,
    receipt_id: receiptId,
    receipt_kind: receiptKind,
  }, "receipt_binding_request");
  const receiptBinding = invokeRustModelMountReceiptBinding(
    state,
    receiptBindingAuthority.receipt_binding_request,
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

function modelMountInvocationAuthorityBaseRequest({
  body = {},
  capability,
  ephemeralMcp = {},
  input,
  instance = {},
  kind,
  previousResponseId = null,
  responseId = null,
  routeReceipt,
  selection,
  stream = false,
  streamStatus = null,
  token = {},
} = {}) {
  return {
    schema_version: "ioi.model_mount.invocation_authority.v1",
    body,
    selection,
    instance,
    route_receipt: routeReceipt,
    ephemeral_mcp: {
      tool_receipt_ids: ephemeralMcp.toolReceiptIds ?? [],
      server_ids: ephemeralMcp.serverIds ?? [],
      evidence_refs: ephemeralMcp.evidenceRefs ?? [],
    },
    token,
    input,
    kind,
    capability,
    response_id: responseId,
    previous_response_id: previousResponseId,
    stream,
    stream_status: streamStatus,
  };
}

function planModelMountInvocationAuthority(state, request, requiredField) {
  if (typeof state.planModelMountInvocationAuthority !== "function") {
    const error = new Error("Model invocation authority requires Rust daemon-core model_mount invocation authority planning.");
    error.status = 500;
    error.code = "model_mount_invocation_authority_planner_required";
    error.details = {
      rust_core_boundary: "model_mount.invocation_authority",
      required_field: requiredField,
    };
    throw error;
  }
  const plan = state.planModelMountInvocationAuthority(request);
  assertRustModelMountInvocationAuthorityPlan(plan, requiredField);
  return plan;
}

function assertRustModelMountInvocationAuthorityPlan(plan = {}, requiredField) {
  const evidenceRefs = Array.isArray(plan.evidence_refs) ? plan.evidence_refs : [];
  const missing = [];
  if (plan.rust_core_boundary !== "model_mount.invocation_authority") missing.push("rust_core_boundary");
  if (!evidenceRefs.includes("rust_daemon_core_model_mount_invocation_authority")) {
    missing.push("evidence_refs.rust_daemon_core_model_mount_invocation_authority");
  }
  if (!evidenceRefs.includes("model_mount_invocation_contract_js_authoring_retired")) {
    missing.push("evidence_refs.model_mount_invocation_contract_js_authoring_retired");
  }
  if (requiredField && !objectRecord(plan[requiredField])) missing.push(requiredField);
  if (missing.length === 0) return;
  const error = new Error("Model invocation authority requires a Rust-authored model_mount invocation authority plan.");
  error.status = 502;
  error.code = "model_mount_invocation_authority_plan_invalid";
  error.details = {
    missing,
    source: plan.source ?? null,
  };
  throw error;
}

function normalizeAgentgresHeadForInvocationAuthority(state) {
  if (typeof state.agentgresModelMountingHead !== "function") {
    const error = new Error("Model invocation authority requires a current model-mounting operation head.");
    error.status = 500;
    error.code = "model_mount_agentgres_head_required";
    throw error;
  }
  return normalizeAgentgresHead(state.agentgresModelMountingHead());
}

function planModelMountAcceptedReceiptTransitionForInvocation(state, transitionRequest) {
  if (typeof state.planModelMountAcceptedReceiptTransition !== "function") {
    const error = new Error("Model invocation Agentgres admission requires Rust model-mount accepted receipt transition planning.");
    error.status = 500;
    error.code = "model_mount_accepted_receipt_transition_planner_required";
    throw error;
  }
  const transition = state.planModelMountAcceptedReceiptTransition(transitionRequest);
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
  assertNoRetiredProviderVaultRecordAliases(record, "endpoint");
  return {
    id: optionalRef(record.id),
    model_id: optionalRef(record.model_id),
    provider_id: optionalRef(record.provider_id),
    api_format: optionalRef(record.api_format),
    driver: optionalRef(record.driver),
    backend_id: optionalRef(record.backend_id),
    base_url: optionalRef(record.base_url),
    secret_ref: optionalRef(record.secret_ref),
    auth_vault_ref: optionalRef(record.auth_vault_ref),
    api_key_vault_ref: optionalRef(record.api_key_vault_ref),
    provider_auth_materialization_ref: optionalRef(record.provider_auth_materialization_ref),
    outbound_header_binding_ref: optionalRef(record.outbound_header_binding_ref),
    auth_header_materialization_status: optionalRef(record.auth_header_materialization_status),
    ctee_egress_resolver_ref: optionalRef(record.ctee_egress_resolver_ref),
    ctee_egress_resolver_hash: optionalRef(record.ctee_egress_resolver_hash),
    ctee_egress_resolution_status: optionalRef(record.ctee_egress_resolution_status),
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
  assertNoRetiredProviderVaultRecordAliases(record, "provider");
  return {
    id: optionalRef(record.id ?? endpoint.provider_id),
    kind: optionalRef(record.kind),
    api_format: optionalRef(record.api_format),
    driver: optionalRef(record.driver),
    secret_ref: optionalRef(record.secret_ref),
    auth_vault_ref: optionalRef(record.auth_vault_ref),
    api_key_vault_ref: optionalRef(record.api_key_vault_ref),
    base_url: optionalRef(record.base_url),
    provider_auth_materialization_ref: optionalRef(record.provider_auth_materialization_ref),
    outbound_header_binding_ref: optionalRef(record.outbound_header_binding_ref),
    auth_header_materialization_status: optionalRef(record.auth_header_materialization_status),
    ctee_egress_resolver_ref: optionalRef(record.ctee_egress_resolver_ref),
    ctee_egress_resolver_hash: optionalRef(record.ctee_egress_resolver_hash),
    ctee_egress_resolution_status: optionalRef(record.ctee_egress_resolution_status),
    custody_ref: optionalRef(record.custody_ref),
    node_plaintext_allowed: Boolean(record.node_plaintext_allowed ?? false),
    privacy_class: optionalRef(record.privacy_class),
    status: optionalRef(record.status),
    capabilities: arrayOfStrings(record.capabilities),
  };
}

function assertNoRetiredProviderVaultRecordAliases(record = {}, subject) {
  const retiredAliases = ["secretRef", "authVaultRef", "apiKeyVaultRef"].filter((field) =>
    Object.hasOwn(record, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error("Model provider vault-ref record aliases are retired.");
  error.status = 400;
  error.code = "model_mount_provider_vault_record_aliases_retired";
  error.details = {
    subject,
    retired_aliases: retiredAliases,
    canonical_fields: ["secret_ref", "auth_vault_ref", "api_key_vault_ref"],
  };
  throw error;
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
    hosted_transport_request_ref: optionalRef(
      providerResult.hosted_transport_request_ref ??
        result.hosted_transport_request_ref,
    ),
    hosted_transport_request_hash: optionalRef(
      providerResult.hosted_transport_request_hash ??
        result.hosted_transport_request_hash,
    ),
    hosted_transport_response_hash: optionalRef(
      providerResult.hosted_transport_response_hash ??
        result.hosted_transport_response_hash,
    ),
    hosted_transport_status: optionalRef(
      providerResult.hosted_transport_status ??
        result.hosted_transport_status,
    ),
    ctee_egress_resolver_ref: optionalRef(
      providerResult.ctee_egress_resolver_ref ??
        result.ctee_egress_resolver_ref,
    ),
    ctee_egress_resolver_hash: optionalRef(
      providerResult.ctee_egress_resolver_hash ??
        result.ctee_egress_resolver_hash,
    ),
    ctee_egress_resolution_status: optionalRef(
      providerResult.ctee_egress_resolution_status ??
        result.ctee_egress_resolution_status,
    ),
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

function hashRef(value, field) {
  const normalized = requiredStringRef(field, value);
  return normalized.startsWith("sha256:") ? normalized : `sha256:${normalized}`;
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
