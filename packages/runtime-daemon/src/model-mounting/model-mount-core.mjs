export const RUST_MODEL_MOUNT_ADMISSION_BACKEND = "rust_model_mount_live";
export const RUST_MODEL_MOUNT_FIXTURE_BACKEND = "rust_model_mount_fixture";
export const RUST_MODEL_MOUNT_FIXTURE_INVENTORY_BACKEND = "rust_model_mount_fixture_inventory";
export const RUST_MODEL_MOUNT_FIXTURE_LIFECYCLE_BACKEND = "rust_model_mount_fixture_lifecycle";
export const RUST_MODEL_MOUNT_HOSTED_PROVIDER_INVENTORY_BACKEND = "rust_model_mount_hosted_provider_inventory";
export const RUST_MODEL_MOUNT_HOSTED_PROVIDER_LIFECYCLE_BACKEND = "rust_model_mount_hosted_provider_lifecycle";
export const RUST_MODEL_MOUNT_STORAGE_CONTROL_BACKEND = "rust_model_mount_storage_control";
export const RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND = "rust_model_mount_instance_lifecycle";
export const RUST_MODEL_MOUNT_NATIVE_LOCAL_BACKEND = "rust_model_mount_native_local";
export const RUST_MODEL_MOUNT_NATIVE_LOCAL_INVENTORY_BACKEND = "rust_model_mount_native_local_inventory";
export const RUST_MODEL_MOUNT_NATIVE_LOCAL_LIFECYCLE_BACKEND = "rust_model_mount_native_local_lifecycle";
export const MODEL_MOUNT_ROUTE_DECISION_API_METHOD = "admitModelMountRouteDecision";
export const MODEL_MOUNT_INVOCATION_AUTHORITY_API_METHOD = "planModelMountInvocationAuthority";
export const MODEL_MOUNT_INVOCATION_API_METHOD = "admitModelMountInvocation";
export const MODEL_MOUNT_PROVIDER_EXECUTION_API_METHOD = "admitModelMountProviderExecution";
export const MODEL_MOUNT_PROVIDER_INVOCATION_API_METHOD = "executeModelMountProviderInvocation";
export const MODEL_MOUNT_PROVIDER_STREAM_INVOCATION_API_METHOD = "executeModelMountProviderStreamInvocation";
export const MODEL_MOUNT_PROVIDER_LIFECYCLE_API_METHOD = "planModelMountProviderLifecycle";
export const MODEL_MOUNT_PROVIDER_INVENTORY_API_METHOD = "planModelMountProviderInventory";
export const MODEL_MOUNT_INSTANCE_LIFECYCLE_API_METHOD = "planModelMountInstanceLifecycle";
export const MODEL_MOUNT_PROVIDER_RESULT_API_METHOD = "admitModelMountProviderResult";
export const MODEL_MOUNT_BACKEND_PROCESS_API_METHOD = "planModelMountBackendProcess";
export const MODEL_MOUNT_BACKEND_PROCESS_MATERIALIZATION_API_METHOD =
  "planModelMountBackendProcessMaterialization";
export const MODEL_MOUNT_BACKEND_PROCESS_SUPERVISION_API_METHOD =
  "superviseModelMountBackendProcess";
export const MODEL_MOUNT_BACKEND_LIFECYCLE_API_METHOD = "planModelMountBackendLifecycle";
export const MODEL_MOUNT_ARTIFACT_ENDPOINT_API_METHOD = "planModelMountArtifactEndpoint";
export const MODEL_MOUNT_STORAGE_CONTROL_API_METHOD = "planModelMountStorageControl";
export const MODEL_MOUNT_MCP_WORKFLOW_API_METHOD = "planModelMountMcpWorkflow";
export const MODEL_MOUNT_SERVER_CONTROL_API_METHOD = "planModelMountServerControl";
export const MODEL_MOUNT_ROUTE_CONTROL_API_METHOD = "planModelMountRouteControl";
export const MODEL_MOUNT_RUNTIME_ENGINE_API_METHOD = "planModelMountRuntimeEngine";
export const MODEL_MOUNT_RUNTIME_SURVEY_API_METHOD = "planModelMountRuntimeSurvey";
export const MODEL_MOUNT_TOKENIZER_REQUIRED_API_METHOD = "planModelMountTokenizerRequired";
export const MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_API_METHOD = "planModelMountRouteControlRequired";
export const MODEL_MOUNT_TOKENIZER_API_METHOD = "planModelMountTokenizer";
export const MODEL_MOUNT_CONVERSATION_STATE_API_METHOD = "planModelMountConversationState";
export const MODEL_MOUNT_STREAM_COMPLETION_API_METHOD = "planModelMountStreamCompletion";
export const MODEL_MOUNT_STREAM_CANCEL_API_METHOD = "planModelMountStreamCancel";
export const MODEL_MOUNT_READ_PROJECTION_API_METHOD = "planModelMountReadProjection";
export const MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_API_METHOD = "planModelMountAcceptedReceiptHead";
export const MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_API_METHOD = "planModelMountAcceptedReceiptTransition";
export const MODEL_MOUNT_INVOCATION_RECEIPT_BINDING_API_METHOD = "bindModelMountInvocationReceipt";
export const MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_API_METHOD = "planModelMountCatalogProviderControl";
export const MODEL_MOUNT_PROVIDER_CONTROL_API_METHOD = "planModelMountProviderControl";
export const MODEL_MOUNT_PROVIDER_AUTH_MATERIALIZATION_API_METHOD = "planModelMountProviderAuthMaterialization";
export const MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_API_METHOD = "planModelMountCapabilityTokenControl";
export const MODEL_MOUNT_VAULT_CONTROL_API_METHOD = "planModelMountVaultControl";
export const MODEL_MOUNT_RECEIPT_GATE_API_METHOD = "planModelMountReceiptGate";

export function createModelMountCore(options = {}) {
  return new ModelMountCore(options);
}

export function assertNoRetiredModelMountCoreOption(field, value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new ModelMountCoreError(
    "Model-mount command compatibility options are retired; use daemonCoreModelMountApi for migrated Rust daemon-core model_mount APIs.",
    "model_mount_core_compatibility_option_retired",
    { retired_option: field, retired_value: value },
  );
}

export class ModelMountCore {
  constructor(options = {}) {
    assertNoRetiredModelMountCoreOption("command", options.command);
    assertNoRetiredModelMountCoreOption("args", options.args);
    assertNoRetiredModelMountCoreOption("env", options.env);
    assertNoRetiredModelMountCoreOption("daemonCoreApi", options.daemonCoreApi);
    assertNoRetiredModelMountCoreOption("daemonCoreInvoker", options.daemonCoreInvoker);
    this.daemonCoreModelMountApi = modelMountApi(options.daemonCoreModelMountApi);
  }

  admitRouteDecision(request) {
    return normalizeRouteDecisionApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_ROUTE_DECISION_API_METHOD, request),
    );
  }

  planInvocationAuthority(request) {
    return normalizeInvocationAuthorityApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_INVOCATION_AUTHORITY_API_METHOD, request),
    );
  }

  admitInvocation(request) {
    return normalizeInvocationApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_INVOCATION_API_METHOD, request),
    );
  }

  admitProviderExecution(request) {
    return normalizeProviderExecutionApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_PROVIDER_EXECUTION_API_METHOD, request),
    );
  }

  executeProviderInvocation(request) {
    return normalizeProviderInvocationApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_PROVIDER_INVOCATION_API_METHOD, request),
    );
  }

  executeProviderStreamInvocation(request) {
    return normalizeProviderStreamInvocationApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_PROVIDER_STREAM_INVOCATION_API_METHOD, request),
    );
  }

  planProviderLifecycle(request) {
    return normalizeProviderLifecycleApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_PROVIDER_LIFECYCLE_API_METHOD, request),
    );
  }

  planProviderInventory(request) {
    return normalizeProviderInventoryApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_PROVIDER_INVENTORY_API_METHOD, request),
    );
  }

  planInstanceLifecycle(request) {
    return normalizeInstanceLifecycleApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_INSTANCE_LIFECYCLE_API_METHOD, request),
    );
  }

  admitProviderResult(request) {
    return normalizeProviderResultApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_PROVIDER_RESULT_API_METHOD, request),
    );
  }

  planBackendProcess(request) {
    return normalizeBackendProcessPlanApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_BACKEND_PROCESS_API_METHOD, request),
    );
  }

  planBackendProcessMaterialization(request) {
    return normalizeBackendProcessMaterializationApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_BACKEND_PROCESS_MATERIALIZATION_API_METHOD, request),
    );
  }

  superviseBackendProcess(request) {
    return normalizeBackendProcessSupervisionApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_BACKEND_PROCESS_SUPERVISION_API_METHOD, request),
    );
  }

  planBackendLifecycle(request) {
    return normalizeBackendLifecycleApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_BACKEND_LIFECYCLE_API_METHOD, request),
    );
  }

  planArtifactEndpoint(request) {
    return normalizeArtifactEndpointApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_ARTIFACT_ENDPOINT_API_METHOD, request),
    );
  }

  planStorageControl(request) {
    return normalizeStorageControlApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_STORAGE_CONTROL_API_METHOD, request),
    );
  }

  planMcpWorkflow(request) {
    return normalizeMcpWorkflowApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_MCP_WORKFLOW_API_METHOD, request),
    );
  }

  planServerControl(request) {
    return normalizeServerControlApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_SERVER_CONTROL_API_METHOD, request),
    );
  }

  planRuntimeEngine(request) {
    return normalizeRuntimeEngineApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_RUNTIME_ENGINE_API_METHOD, request),
    );
  }

  planRuntimeSurvey(request) {
    return normalizeRuntimeSurveyApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_RUNTIME_SURVEY_API_METHOD, request),
    );
  }

  planTokenizerRequired(request) {
    return normalizeTokenizerRequiredApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_TOKENIZER_REQUIRED_API_METHOD, request),
    );
  }

  planTokenizer(request) {
    return normalizeTokenizerApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_TOKENIZER_API_METHOD, request),
    );
  }

  planConversationState(request) {
    return normalizeConversationStateApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_CONVERSATION_STATE_API_METHOD, request),
    );
  }

  planStreamCompletion(request) {
    return normalizeStreamCompletionApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_STREAM_COMPLETION_API_METHOD, request),
    );
  }

  planStreamCancel(request) {
    return normalizeStreamCancelApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_STREAM_CANCEL_API_METHOD, request),
    );
  }

  planRouteControlRequired(request) {
    return normalizeRouteControlRequiredApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_API_METHOD, request),
    );
  }

  planRouteControl(request) {
    return normalizeRouteControlApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_ROUTE_CONTROL_API_METHOD, request),
    );
  }

  planCatalogProviderControl(request) {
    return normalizeCatalogProviderControlApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_API_METHOD, request),
    );
  }

  planProviderControl(request) {
    return normalizeProviderControlApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_PROVIDER_CONTROL_API_METHOD, request),
    );
  }

  planProviderAuthMaterialization(request) {
    return normalizeProviderAuthMaterializationApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_PROVIDER_AUTH_MATERIALIZATION_API_METHOD, request),
    );
  }

  planCapabilityTokenControl(request) {
    return normalizeCapabilityTokenControlApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_API_METHOD, request),
    );
  }

  planVaultControl(request) {
    return normalizeVaultControlApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_VAULT_CONTROL_API_METHOD, request),
    );
  }

  planReceiptGate(request) {
    return normalizeReceiptGateApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_RECEIPT_GATE_API_METHOD, request),
    );
  }

  planAcceptedReceiptHead(request) {
    return normalizeAcceptedReceiptHeadApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_API_METHOD, request),
    );
  }

  planAcceptedReceiptTransition(request) {
    return normalizeAcceptedReceiptTransitionApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_API_METHOD, request),
    );
  }

  planReadProjection(request) {
    return normalizeReadProjectionApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_READ_PROJECTION_API_METHOD, request),
    );
  }

  bindInvocationReceipt(request = {}) {
    if (Object.hasOwn(request, "expectedHeads")) {
      throw new ModelMountCoreError(
        "Model mount invocation expected heads must come from the Rust accepted-receipt transition planner.",
        "model_mount_invocation_expected_heads_retired",
        { status: 400 },
      );
    }
    const {
      invocation,
      result,
      acceptedReceiptTransition = null,
      receiptRef = null,
    } = request;
    const bindingRequest = {
      invocation,
      result,
      accepted_receipt_transition: acceptedReceiptTransition,
      receipt_ref: receiptRef,
    };
    return normalizeInvocationReceiptBindingApiResult(
      this.invokeModelMountApi(MODEL_MOUNT_INVOCATION_RECEIPT_BINDING_API_METHOD, bindingRequest),
    );
  }

  invokeModelMountApi(method, request) {
    const invoke = this.daemonCoreModelMountApi?.[method];
    if (typeof invoke !== "function") {
      throw new ModelMountCoreError(
        `Model mount requires daemonCoreModelMountApi.${method} for direct Rust daemon-core model_mount APIs.`,
        "model_mount_core_direct_model_mount_api_unconfigured",
        { boundary: `daemonCoreModelMountApi.${method}` },
      );
    }
    const response = invoke.call(this.daemonCoreModelMountApi, request);
    const responseError = objectRecord(response?.error);
    if (response?.ok === false && responseError) {
      throw new ModelMountCoreError(
        responseError.message ?? "Rust model_mount core rejected the direct API request.",
        responseError.code ?? "model_mount_core_direct_model_mount_api_rejected",
        { error: responseError },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

export class ModelMountCoreError extends Error {
  constructor(message, code = "model_mount_core_error", details = {}) {
    super(message);
    this.name = "ModelMountCoreError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

function normalizeRouteDecisionApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  return {
    source: result.source ?? "rust_model_mount_api",
    backend: result.backend ?? RUST_MODEL_MOUNT_ADMISSION_BACKEND,
    record,
    route_decision_ref: result.route_decision_ref ?? record.route_decision_ref ?? null,
    route_decision_hash: result.route_decision_hash ?? record.route_decision_hash ?? null,
    receipt_refs: Array.isArray(result.receipt_refs)
      ? result.receipt_refs
      : Array.isArray(record.receipt_refs)
        ? record.receipt_refs
        : null,
    accepted_receipt_record: result.accepted_receipt_record ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

function normalizeInvocationAuthorityApiResult(value = {}) {
  const result = objectRecord(value.result) ?? objectRecord(value) ?? {};
  const evidenceRefs = arrayOfStrings(result.evidence_refs ?? result.evidenceRefs);
  const normalized = {
    ...result,
    source: result.source ?? "rust_daemon_core.model_mount.invocation_authority",
    rust_core_boundary: result.rust_core_boundary ?? "model_mount.invocation_authority",
    operation: result.operation ?? null,
    evidence_refs: evidenceRefs,
  };
  if (normalized.rust_core_boundary !== "model_mount.invocation_authority") {
    throw new ModelMountCoreError(
      "Rust model_mount invocation authority plan is incomplete.",
      "model_mount_invocation_authority_plan_invalid",
      { missing: ["rust_core_boundary"] },
    );
  }
  if (!normalized.evidence_refs.includes("model_mount_invocation_contract_js_authoring_retired")) {
    throw new ModelMountCoreError(
      "Rust model_mount invocation authority plan must retire JS contract authorship.",
      "model_mount_invocation_authority_plan_invalid",
      { missing: ["evidence_refs.model_mount_invocation_contract_js_authoring_retired"] },
    );
  }
  return normalized;
}

function normalizeInvocationApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : result;
  return {
    source: result.source ?? "rust_model_mount_invocation_api",
    backend: result.backend ?? RUST_MODEL_MOUNT_ADMISSION_BACKEND,
    record,
    invocation_admission_ref: result.invocation_admission_ref ?? record.invocation_admission_ref ?? null,
    invocation_admission_hash: result.invocation_admission_hash ?? record.invocation_admission_hash ?? null,
    receipt_refs: Array.isArray(result.receipt_refs)
      ? result.receipt_refs
      : Array.isArray(record.receipt_refs)
        ? record.receipt_refs
        : null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

function normalizeProviderExecutionApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : result;
  return {
    source: result.source ?? "rust_model_mount_provider_execution_api",
    backend: result.backend ?? RUST_MODEL_MOUNT_ADMISSION_BACKEND,
    record,
    provider_execution_ref: result.provider_execution_ref ?? record.provider_execution_ref ?? null,
    provider_execution_hash: result.provider_execution_hash ?? record.provider_execution_hash ?? null,
    receipt_refs: Array.isArray(result.receipt_refs)
      ? result.receipt_refs
      : Array.isArray(record.receipt_refs)
        ? record.receipt_refs
        : null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

function normalizeProviderInvocationApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : result;
  return {
    source: result.source ?? "rust_model_mount_provider_invocation_api",
    backend: result.backend ?? record.execution_backend ?? RUST_MODEL_MOUNT_FIXTURE_BACKEND,
    result: record,
    outputText: result.outputText ?? result.output_text ?? record.output_text ?? "",
    tokenCount: result.tokenCount ?? result.token_count ?? record.token_count ?? null,
    providerResponse: result.providerResponse ?? result.provider_response ?? null,
    providerResponseKind:
      result.providerResponseKind ?? result.provider_response_kind ?? record.provider_response_kind ?? null,
    executionBackend: result.execution_backend ?? record.execution_backend ?? null,
    backendId: result.backendId ?? result.backend_id ?? record.backend_id ?? null,
    provider_execution_ref: result.provider_execution_ref ?? record.provider_execution_ref ?? null,
    provider_execution_hash: result.provider_execution_hash ?? record.provider_execution_hash ?? null,
    invocation_hash: result.invocation_hash ?? record.invocation_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs
      : Array.isArray(record.evidence_refs)
        ? record.evidence_refs
        : null,
    backendEvidenceRefs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs
      : Array.isArray(record.evidence_refs)
        ? record.evidence_refs
        : null,
  };
}

function normalizeProviderStreamInvocationApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : result;
  const streamChunks = Array.isArray(result.streamChunks)
    ? result.streamChunks
    : Array.isArray(result.stream_chunks)
      ? result.stream_chunks
      : Array.isArray(record.stream_chunks)
        ? record.stream_chunks
        : [];
  return {
    source: result.source ?? "rust_model_mount_provider_stream_invocation_api",
    backend: result.backend ?? record.execution_backend ?? RUST_MODEL_MOUNT_NATIVE_LOCAL_BACKEND,
    result: record,
    outputText: result.outputText ?? result.output_text ?? record.output_text ?? "",
    tokenCount: result.tokenCount ?? result.token_count ?? record.token_count ?? null,
    providerResponse: result.providerResponse ?? result.provider_response ?? null,
    providerResponseKind:
      result.providerResponseKind ?? result.provider_response_kind ?? record.provider_response_kind ?? null,
    executionBackend: result.execution_backend ?? record.execution_backend ?? null,
    backendId: result.backendId ?? result.backend_id ?? record.backend_id ?? null,
    streamFormat: result.streamFormat ?? result.stream_format ?? record.stream_format ?? null,
    streamKind: result.streamKind ?? result.stream_kind ?? record.stream_kind ?? null,
    streamChunks,
    provider_execution_ref: result.provider_execution_ref ?? record.provider_execution_ref ?? null,
    provider_execution_hash: result.provider_execution_hash ?? record.provider_execution_hash ?? null,
    invocation_hash: result.invocation_hash ?? record.invocation_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs
      : Array.isArray(record.evidence_refs)
        ? record.evidence_refs
        : null,
    backendEvidenceRefs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs
      : Array.isArray(record.evidence_refs)
        ? record.evidence_refs
        : null,
  };
}

function normalizeProviderLifecycleApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : result;
  const lifecycleRecord = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : record.record && typeof record.record === "object" && !Array.isArray(record.record)
      ? record.record
      : null;
  return {
    source: result.source ?? "rust_model_mount_provider_lifecycle_api",
    backend: result.backend ?? record.execution_backend ?? RUST_MODEL_MOUNT_NATIVE_LOCAL_LIFECYCLE_BACKEND,
    result: record,
    status: result.status ?? record.status ?? null,
    backendId: result.backend_id ?? record.backend_id ?? null,
    providerBackend: result.provider_backend ?? record.backend ?? null,
    driver: result.driver ?? record.driver ?? null,
    executionBackend: result.execution_backend ?? record.execution_backend ?? null,
    lifecycle_hash: result.lifecycle_hash ?? record.lifecycle_hash ?? null,
    transport_contract: result.transport_contract ?? record.transport_contract ?? lifecycleRecord?.transport_contract ?? null,
    transport_execution_status:
      result.transport_execution_status ?? record.transport_execution_status ?? lifecycleRecord?.transport_execution_status ?? null,
    operation_kind: result.operation_kind ?? record.operation_kind ?? lifecycleRecord?.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? record.rust_core_boundary ?? lifecycleRecord?.rust_core_boundary ?? null,
    record_dir: result.record_dir ?? record.record_dir ?? lifecycleRecord?.record_dir ?? null,
    record_id: result.record_id ?? record.record_id ?? lifecycleRecord?.record_id ?? lifecycleRecord?.id ?? null,
    record: lifecycleRecord,
    public_response: result.public_response && typeof result.public_response === "object" && !Array.isArray(result.public_response)
      ? result.public_response
      : record.public_response && typeof record.public_response === "object" && !Array.isArray(record.public_response)
        ? record.public_response
        : null,
    receipt_refs: Array.isArray(result.receipt_refs)
      ? result.receipt_refs
      : Array.isArray(record.receipt_refs)
        ? record.receipt_refs
        : [],
    evidence_refs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs
      : Array.isArray(record.evidence_refs)
        ? record.evidence_refs
        : null,
    backendEvidenceRefs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs
      : Array.isArray(record.evidence_refs)
        ? record.evidence_refs
        : null,
  };
}

function normalizeProviderInventoryApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : result;
  const itemRefs = Array.isArray(result.item_refs)
      ? result.item_refs
      : Array.isArray(record.item_refs)
        ? record.item_refs
        : null;
  return {
    source: result.source ?? "rust_model_mount_provider_inventory_api",
    backend: result.backend ?? record.execution_backend ?? RUST_MODEL_MOUNT_NATIVE_LOCAL_INVENTORY_BACKEND,
    result: record,
    status: result.status ?? record.status ?? null,
    backendId: result.backend_id ?? record.backend_id ?? null,
    providerBackend: result.provider_backend ?? record.backend ?? null,
    driver: result.driver ?? record.driver ?? null,
    executionBackend: result.execution_backend ?? record.execution_backend ?? null,
    itemRefs,
    itemCount: result.item_count ?? record.item_count ?? null,
    inventory_hash: result.inventory_hash ?? record.inventory_hash ?? null,
    transport_contract:
      result.transport_contract ?? record.transport_contract ?? result.record?.transport_contract ?? record.record?.transport_contract ?? null,
    transport_execution_status:
      result.transport_execution_status ??
      record.transport_execution_status ??
      result.record?.transport_execution_status ??
      record.record?.transport_execution_status ??
      null,
    operation_kind: result.operation_kind ?? record.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? record.rust_core_boundary ?? null,
    record_dir: result.record_dir ?? record.record_dir ?? null,
    record_id: result.record_id ?? record.record_id ?? record.id ?? null,
    record: result.record && typeof result.record === "object" && !Array.isArray(result.record)
      ? result.record
      : record.record && typeof record.record === "object" && !Array.isArray(record.record)
        ? record.record
        : null,
    receipt_refs: Array.isArray(result.receipt_refs)
      ? result.receipt_refs
      : Array.isArray(record.receipt_refs)
        ? record.receipt_refs
        : [],
    evidence_refs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs
      : Array.isArray(record.evidence_refs)
        ? record.evidence_refs
        : null,
    backendEvidenceRefs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs
      : Array.isArray(record.evidence_refs)
        ? record.evidence_refs
        : null,
  };
}

function normalizeInstanceLifecycleApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : result;
  return {
    source: result.source ?? "rust_model_mount_instance_lifecycle_api",
    backend: result.backend ?? record.execution_backend ?? RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND,
    result: record,
    action: result.action ?? record.action ?? null,
    status: result.status ?? record.status ?? null,
    backendId: result.backendId ?? result.backend_id ?? record.backend_id ?? null,
    driver: result.driver ?? record.driver ?? null,
    executionBackend: result.execution_backend ?? record.execution_backend ?? null,
    provider_lifecycle_hash: result.provider_lifecycle_hash ?? record.provider_lifecycle_hash ?? null,
    backend_process_ref: result.backend_process_ref ?? record.backend_process_ref ?? null,
    backend_process_materialization_hash:
      result.backend_process_materialization_hash ??
      record.backend_process_materialization_hash ??
      null,
    backend_supervision_ref: result.backend_supervision_ref ?? record.backend_supervision_ref ?? null,
    backend_supervision_hash: result.backend_supervision_hash ?? record.backend_supervision_hash ?? null,
    backend_supervision_status: result.backend_supervision_status ?? record.backend_supervision_status ?? null,
    instance_lifecycle_hash: result.instance_lifecycle_hash ?? record.instance_lifecycle_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs
      : Array.isArray(record.evidence_refs)
        ? record.evidence_refs
        : null,
    backendEvidenceRefs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs
      : Array.isArray(record.evidence_refs)
        ? record.evidence_refs
        : null,
  };
}

function normalizeProviderResultApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : result;
  return {
    source: result.source ?? "rust_model_mount_provider_result_api",
    backend: result.backend ?? RUST_MODEL_MOUNT_ADMISSION_BACKEND,
    record,
    provider_result_ref:
      result.provider_result_ref ?? record.provider_result_ref ?? null,
    provider_result_hash:
      result.provider_result_hash ?? record.provider_result_hash ?? null,
    receipt_refs: Array.isArray(result.receipt_refs)
      ? result.receipt_refs
      : Array.isArray(record.receipt_refs)
        ? record.receipt_refs
        : null,
    evidence_refs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs
      : Array.isArray(record.evidence_refs)
        ? record.evidence_refs
        : null,
  };
}

function normalizeBackendProcessPlanApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : {};
  return {
    source: result.source ?? "rust_daemon_core.model_mount.backend_process",
    result: record,
    supports_supervision: result.supports_supervision ?? record.supports_supervision ?? null,
    supervisor_kind: result.supervisor_kind ?? record.supervisor_kind ?? null,
    public_args: Array.isArray(result.public_args)
      ? result.public_args
      : Array.isArray(record.public_args)
        ? record.public_args
        : null,
    spawn_args: Array.isArray(result.spawn_args)
      ? result.spawn_args
      : Array.isArray(record.spawn_args)
        ? record.spawn_args
        : null,
    spawn_required: result.spawn_required ?? record.spawn_required ?? null,
    spawn_status: result.spawn_status ?? record.spawn_status ?? null,
    plan_hash: result.plan_hash ?? record.plan_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs
      : Array.isArray(record.evidence_refs)
        ? record.evidence_refs
        : null,
  };
}

const RETIRED_BACKEND_PROCESS_FALLBACK_PROOF_FIELDS = [
  "retired_paths",
  "js_process_supervisor",
  "command_transport_spawn",
  "binary_bridge_spawn",
  "compatibility_spawn_fallback",
];

function assertRetiredBackendProcessFallbackProofFieldsAbsent(record, path, missing) {
  if (!record || typeof record !== "object" || Array.isArray(record)) return;
  for (const field of RETIRED_BACKEND_PROCESS_FALLBACK_PROOF_FIELDS) {
    if (Object.hasOwn(record, field)) missing.push(`${path}.${field}_retired`);
  }
}

function normalizeBackendProcessMaterializationApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const publicResponse = result.public_response ?? plan.public_response ?? record?.public_response ?? null;
  const normalized = {
    source: result.source ?? plan.source ?? "rust_daemon_core.model_mount.backend_process_materialization",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    public_response: publicResponse,
    process_plan: result.process_plan ?? plan.process_plan ?? record?.process_plan ?? null,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs) ?? [],
    authority_grant_refs: arrayOrNull(result.authority_grant_refs) ?? arrayOrNull(plan.authority_grant_refs) ?? [],
    authority_receipt_refs:
      arrayOrNull(result.authority_receipt_refs) ?? arrayOrNull(plan.authority_receipt_refs) ?? [],
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    materialization_hash: result.materialization_hash ?? plan.materialization_hash ?? null,
    authority_hash: result.authority_hash ?? plan.authority_hash ?? null,
    backend_process_ref:
      result.backend_process_ref ??
      plan.backend_process_ref ??
      record?.backend_process_ref ??
      publicResponse?.backend_process_ref ??
      null,
    backend_supervision_ref:
      result.backend_supervision_ref ??
      plan.backend_supervision_ref ??
      record?.backend_supervision_ref ??
      publicResponse?.backend_supervision_ref ??
      null,
    backend_supervision_hash:
      result.backend_supervision_hash ??
      plan.backend_supervision_hash ??
      record?.backend_supervision_hash ??
      publicResponse?.backend_supervision_hash ??
      null,
    backend_supervision_status:
      result.backend_supervision_status ??
      plan.backend_supervision_status ??
      record?.backend_supervision_status ??
      publicResponse?.backend_supervision_status ??
      null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation_kind", "materialization_hash", "authority_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.backend_process_materialization") {
    missing.push("rust_core_boundary");
  }
  for (const ref of [
    "rust_daemon_core_backend_process_materialization",
    "rust_backend_process_materialization_bound",
    "wallet_network_backend_process_authority_bound",
    "ctee_backend_process_custody_enforced",
    "agentgres_backend_process_materialization_truth_required",
    "rust_backend_process_supervision_bound",
    "js_backend_process_supervisor_retired",
    "command_transport_backend_process_spawn_retired",
    "binary_bridge_backend_process_spawn_retired",
  ]) {
    if (!Array.isArray(normalized.evidence_refs) || !normalized.evidence_refs.includes(ref)) {
      missing.push(`evidence_refs.${ref}`);
    }
  }
  if (record?.id !== normalized.record_id) missing.push("record.id");
  if (record?.process_materialization_status == null) {
    missing.push("record.process_materialization_status");
  }
  if (!normalized.backend_supervision_ref) {
    missing.push("backend_supervision_ref");
  }
  if (!normalized.backend_supervision_hash) {
    missing.push("backend_supervision_hash");
  }
  if (!normalized.backend_supervision_status) {
    missing.push("backend_supervision_status");
  }
  if (record?.process_supervision_owner !== "rust_daemon_core.model_mount.backend_process_supervisor") {
    missing.push("record.process_supervision_owner");
  }
  if (record?.supervision_contract?.process_supervision_owner !== "rust_daemon_core.model_mount.backend_process_supervisor") {
    missing.push("record.supervision_contract.process_supervision_owner");
  }
  if (!record?.supervision_contract?.backend_supervision_ref) {
    missing.push("record.supervision_contract.backend_supervision_ref");
  }
  if (!record?.supervision_contract?.backend_supervision_hash) {
    missing.push("record.supervision_contract.backend_supervision_hash");
  }
  if (!record?.supervision_contract?.backend_supervision_status) {
    missing.push("record.supervision_contract.backend_supervision_status");
  }
  if (record?.spawn_contract?.spawn_args_returned !== false) {
    missing.push("record.spawn_contract.spawn_args_returned_false");
  }
  if (record?.spawn_contract?.pid_returned !== false) {
    missing.push("record.spawn_contract.pid_returned_false");
  }
  assertRetiredBackendProcessFallbackProofFieldsAbsent(record, "record", missing);
  assertRetiredBackendProcessFallbackProofFieldsAbsent(record?.supervision_contract, "record.supervision_contract", missing);
  assertRetiredBackendProcessFallbackProofFieldsAbsent(publicResponse, "public_response", missing);
  if (publicResponse?.spawn_args_returned !== false) {
    missing.push("public_response.spawn_args_returned_false");
  }
  if (!publicResponse?.backend_supervision_ref) {
    missing.push("public_response.backend_supervision_ref");
  }
  if (!publicResponse?.backend_supervision_hash) {
    missing.push("public_response.backend_supervision_hash");
  }
  if (!publicResponse?.backend_supervision_status) {
    missing.push("public_response.backend_supervision_status");
  }
  if (publicResponse?.process_supervision_owner !== "rust_daemon_core.model_mount.backend_process_supervisor") {
    missing.push("public_response.process_supervision_owner");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount backend-process materialization plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_backend_process_materialization_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeBackendProcessSupervisionApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const publicResponse = result.public_response ?? plan.public_response ?? record?.public_response ?? null;
  const normalized = {
    source: result.source ?? plan.source ?? "rust_daemon_core.model_mount.backend_process_supervision",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    public_response: publicResponse,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? record?.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? record?.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs) ?? [],
    authority_grant_refs: arrayOrNull(result.authority_grant_refs) ?? arrayOrNull(plan.authority_grant_refs) ?? [],
    authority_receipt_refs:
      arrayOrNull(result.authority_receipt_refs) ?? arrayOrNull(plan.authority_receipt_refs) ?? [],
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs) ?? arrayOrNull(record?.evidence_refs),
    runtime_ref:
      result.runtime_ref ??
      plan.runtime_ref ??
      record?.backend_process_runtime_ref ??
      publicResponse?.backend_process_runtime_ref ??
      null,
    runtime_hash:
      result.runtime_hash ??
      plan.runtime_hash ??
      record?.backend_process_runtime_hash ??
      publicResponse?.backend_process_runtime_hash ??
      null,
    runtime_status:
      result.runtime_status ??
      plan.runtime_status ??
      record?.backend_process_runtime_status ??
      publicResponse?.backend_process_runtime_status ??
      null,
    authority_hash: result.authority_hash ?? plan.authority_hash ?? record?.authority_hash ?? null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation_kind", "runtime_ref", "runtime_hash", "runtime_status"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.record_dir !== "model-backend-process-supervisions") missing.push("record_dir.model-backend-process-supervisions");
  if (normalized.rust_core_boundary !== "model_mount.backend_process_supervision") {
    missing.push("rust_core_boundary");
  }
  if (record?.id !== normalized.record_id) missing.push("record.id");
  if (record?.process_execution_owner !== "rust_daemon_core.model_mount.backend_process_supervisor") {
    missing.push("record.process_execution_owner");
  }
  if (record?.process_supervision_owner !== "rust_daemon_core.model_mount.backend_process_supervisor") {
    missing.push("record.process_supervision_owner");
  }
  if (record?.spawn_contract?.spawn_args_returned !== false) {
    missing.push("record.spawn_contract.spawn_args_returned_false");
  }
  if (record?.spawn_contract?.executable_path_returned !== false) {
    missing.push("record.spawn_contract.executable_path_returned_false");
  }
  if (record?.spawn_contract?.pid_returned !== false) {
    missing.push("record.spawn_contract.pid_returned_false");
  }
  assertRetiredBackendProcessFallbackProofFieldsAbsent(record, "record", missing);
  assertRetiredBackendProcessFallbackProofFieldsAbsent(publicResponse, "public_response", missing);
  for (const ref of [
    "rust_daemon_core_backend_process_supervision",
    "rust_backend_process_live_supervision_owned",
    "wallet_network_backend_process_authority_bound",
    "ctee_backend_process_custody_enforced",
    "agentgres_backend_process_supervision_truth_required",
    "js_backend_process_supervisor_retired",
    "command_transport_backend_process_spawn_retired",
    "binary_bridge_backend_process_spawn_retired",
  ]) {
    if (!Array.isArray(normalized.evidence_refs) || !normalized.evidence_refs.includes(ref)) {
      missing.push(`evidence_refs.${ref}`);
    }
  }
  if (normalized.operation_kind === "model_mount.backend_process.start" &&
    !normalized.evidence_refs?.includes("rust_backend_process_live_start_executed")) {
    missing.push("evidence_refs.rust_backend_process_live_start_executed");
  }
  if (normalized.operation_kind === "model_mount.backend_process.stop" &&
    !normalized.evidence_refs?.includes("rust_backend_process_live_stop_executed")) {
    missing.push("evidence_refs.rust_backend_process_live_stop_executed");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount backend-process supervision result is incomplete.");
    error.status = 502;
    error.code = "model_mount_backend_process_supervision_result_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeBackendLifecycleApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const publicResponse = result.public_response ?? plan.public_response ?? null;
  const normalized = {
    source: result.source ?? "rust_daemon_core.model_mount.backend_lifecycle",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    public_response: publicResponse,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs) ?? [],
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    control_hash: result.control_hash ?? plan.control_hash ?? null,
    backend_process_ref: result.backend_process_ref ?? record?.backend_process_ref ?? publicResponse?.backend_process_ref ?? null,
    backend_process_materialization_hash:
      result.backend_process_materialization_hash ??
      record?.backend_process_materialization_hash ??
      publicResponse?.backend_process_materialization_hash ??
      null,
    backend_supervision_ref:
      result.backend_supervision_ref ?? record?.backend_supervision_ref ?? publicResponse?.backend_supervision_ref ?? null,
    backend_supervision_hash:
      result.backend_supervision_hash ?? record?.backend_supervision_hash ?? publicResponse?.backend_supervision_hash ?? null,
    backend_supervision_status:
      result.backend_supervision_status ??
      record?.backend_supervision_status ??
      publicResponse?.backend_supervision_status ??
      null,
    backend_process_runtime_ref:
      result.backend_process_runtime_ref ??
      record?.backend_process_runtime_ref ??
      publicResponse?.backend_process_runtime_ref ??
      null,
    backend_process_runtime_hash:
      result.backend_process_runtime_hash ??
      record?.backend_process_runtime_hash ??
      publicResponse?.backend_process_runtime_hash ??
      null,
    backend_process_runtime_status:
      result.backend_process_runtime_status ??
      record?.backend_process_runtime_status ??
      publicResponse?.backend_process_runtime_status ??
      null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation_kind", "control_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.backend_lifecycle") {
    missing.push("rust_core_boundary");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("rust_daemon_core_backend_lifecycle")
  ) {
    missing.push("evidence_refs.rust_daemon_core_backend_lifecycle");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("agentgres_backend_lifecycle_truth_required")
  ) {
    missing.push("evidence_refs.agentgres_backend_lifecycle_truth_required");
  }
  if (normalized.operation_kind === "model_mount.backend.start") {
    for (const field of [
      "backend_process_ref",
      "backend_process_materialization_hash",
      "backend_supervision_ref",
      "backend_supervision_hash",
      "backend_supervision_status",
      "backend_process_runtime_ref",
      "backend_process_runtime_hash",
      "backend_process_runtime_status",
    ]) {
      if (!normalized[field]) missing.push(field);
      if (!record?.[field]) missing.push(`record.${field}`);
      if (!publicResponse?.[field]) missing.push(`public_response.${field}`);
    }
    if (record?.process_supervision_owner !== "rust_daemon_core.model_mount.backend_process_supervisor") {
      missing.push("record.process_supervision_owner");
    }
    if (publicResponse?.process_supervision_owner !== "rust_daemon_core.model_mount.backend_process_supervisor") {
      missing.push("public_response.process_supervision_owner");
    }
    for (const ref of [
      "rust_backend_lifecycle_backend_process_materialization_bound",
      "rust_backend_lifecycle_backend_process_supervision_bound",
      "rust_backend_lifecycle_backend_process_live_start_bound",
      "backend_lifecycle_start_js_process_control_retired",
    ]) {
      if (!Array.isArray(normalized.evidence_refs) || !normalized.evidence_refs.includes(ref)) {
        missing.push(`evidence_refs.${ref}`);
      }
    }
  }
  if (normalized.operation_kind === "model_mount.backend.stop") {
    for (const field of [
      "backend_process_runtime_ref",
      "backend_process_runtime_hash",
      "backend_process_runtime_status",
    ]) {
      if (!normalized[field]) missing.push(field);
      if (!record?.[field]) missing.push(`record.${field}`);
      if (!publicResponse?.[field]) missing.push(`public_response.${field}`);
    }
    if (record?.process_supervision_owner !== "rust_daemon_core.model_mount.backend_process_supervisor") {
      missing.push("record.process_supervision_owner");
    }
    if (publicResponse?.process_supervision_owner !== "rust_daemon_core.model_mount.backend_process_supervisor") {
      missing.push("public_response.process_supervision_owner");
    }
    for (const ref of [
      "rust_backend_lifecycle_backend_process_live_stop_bound",
      "backend_lifecycle_stop_js_process_control_retired",
    ]) {
      if (!Array.isArray(normalized.evidence_refs) || !normalized.evidence_refs.includes(ref)) {
        missing.push(`evidence_refs.${ref}`);
      }
    }
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount backend-lifecycle plan is incomplete.");
    error.code = "model_mount_backend_lifecycle_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeArtifactEndpointApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : result;
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const normalized = {
    source: result.source ?? plan.source ?? "rust_daemon_core.model_mount.artifact_endpoint",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    public_response: result.public_response ?? plan.public_response ?? null,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs) ?? [],
    authority_grant_refs: arrayOrNull(result.authority_grant_refs) ?? arrayOrNull(plan.authority_grant_refs) ?? [],
    authority_receipt_refs:
      arrayOrNull(result.authority_receipt_refs) ?? arrayOrNull(plan.authority_receipt_refs) ?? [],
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    control_hash: result.control_hash ?? plan.control_hash ?? null,
    authority_hash: result.authority_hash ?? plan.authority_hash ?? null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation_kind", "control_hash", "authority_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.artifact_endpoint") {
    missing.push("rust_core_boundary");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("rust_daemon_core_artifact_endpoint")
  ) {
    missing.push("evidence_refs.rust_daemon_core_artifact_endpoint");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("agentgres_artifact_endpoint_truth_required")
  ) {
    missing.push("evidence_refs.agentgres_artifact_endpoint_truth_required");
  }
  if (record?.id !== normalized.record_id) {
    missing.push("record.id");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount artifact-endpoint plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_artifact_endpoint_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeStorageControlApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const normalized = {
    source: result.source ?? "rust_model_mount_storage_control_api",
    backend: result.backend ?? RUST_MODEL_MOUNT_STORAGE_CONTROL_BACKEND,
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    public_response: result.public_response ?? plan.public_response ?? null,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs) ?? [],
    authority_grant_refs: arrayOrNull(result.authority_grant_refs) ?? arrayOrNull(plan.authority_grant_refs) ?? [],
    authority_receipt_refs:
      arrayOrNull(result.authority_receipt_refs) ?? arrayOrNull(plan.authority_receipt_refs) ?? [],
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    control_hash: result.control_hash ?? plan.control_hash ?? null,
    authority_hash: result.authority_hash ?? plan.authority_hash ?? null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation_kind", "control_hash", "authority_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.storage_control") {
    missing.push("rust_core_boundary");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("rust_daemon_core_model_storage")
  ) {
    missing.push("evidence_refs.rust_daemon_core_model_storage");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("agentgres_model_storage_truth_required")
  ) {
    missing.push("evidence_refs.agentgres_model_storage_truth_required");
  }
  if (record?.id !== normalized.record_id) {
    missing.push("record.id");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount storage-control plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_storage_control_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      backend: normalized.backend,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function assertMcpWorkflowResultMaterialized(publicResponse, receipt, record, missing) {
  const resultPayload = publicResponse.result_payload;
  const resultPayloadHash = typeof publicResponse.result_payload_hash === "string"
    ? publicResponse.result_payload_hash.trim()
    : "";
  if (publicResponse.model_mount_mcp_result_materialized !== true) {
    missing.push("public_response.model_mount_mcp_result_materialized.rust_materialized");
  }
  if (publicResponse.model_mount_mcp_result_materialization_status === "rust_admitted_pending_transport_backend") {
    missing.push("public_response.model_mount_mcp_result_materialization_status.retired_pending_transport_backend");
  }
  if (publicResponse.model_mount_mcp_result_materialization_status !== "rust_materialized") {
    missing.push("public_response.model_mount_mcp_result_materialization_status.rust_materialized");
  }
  if (publicResponse.result_materialization_owner !== "rust_daemon_core.model_mount.mcp_workflow") {
    missing.push("public_response.result_materialization_owner");
  }
  if (!resultPayload || typeof resultPayload !== "object" || Array.isArray(resultPayload)) {
    missing.push("public_response.result_payload");
  } else {
    assertRetiredMcpWorkflowFieldsAbsent(resultPayload, "public_response.result_payload", [
      "js_result_synthesis",
      "command_transport_fallback",
      "binary_bridge_fallback",
      "compatibility_fallback",
    ], missing);
  }
  if (!resultPayloadHash) {
    missing.push("public_response.result_payload_hash");
  }
  if (record?.details?.model_mount_mcp_result_materialized !== true) {
    missing.push("record.details.model_mount_mcp_result_materialized.rust_materialized");
  }
  if (record?.details?.result_payload_hash !== publicResponse.result_payload_hash) {
    missing.push("record.details.result_payload_hash.public_response_match");
  }
  if (receipt?.details?.model_mount_mcp_result_materialized !== true) {
    missing.push("receipt.details.model_mount_mcp_result_materialized.rust_materialized");
  }
  if (receipt?.details?.model_mount_mcp_result_materialization_status === "rust_admitted_pending_transport_backend") {
    missing.push("receipt.details.model_mount_mcp_result_materialization_status.retired_pending_transport_backend");
  }
  if (receipt?.details?.model_mount_mcp_result_materialization_status !== "rust_materialized") {
    missing.push("receipt.details.model_mount_mcp_result_materialization_status.rust_materialized");
  }
  if (receipt?.details?.result_payload_hash !== publicResponse.result_payload_hash) {
    missing.push("receipt.details.result_payload_hash.public_response_match");
  }
  if (receipt?.details?.model_mount_step_module_result?.result_materialized !== true) {
    missing.push("receipt.details.model_mount_step_module_result.result_materialized_true");
  }
  if (receipt?.details?.model_mount_step_module_result?.result_payload_hash !== publicResponse.result_payload_hash) {
    missing.push("receipt.details.model_mount_step_module_result.result_payload_hash");
  }
  const receiptResultPayload = receipt?.details?.result_payload;
  if (receiptResultPayload && typeof receiptResultPayload === "object" && !Array.isArray(receiptResultPayload)) {
    assertRetiredMcpWorkflowFieldsAbsent(receiptResultPayload, "receipt.details.result_payload", [
      "js_result_synthesis",
      "command_transport_fallback",
      "binary_bridge_fallback",
      "compatibility_fallback",
    ], missing);
  }
}

function assertRetiredMcpWorkflowFieldsAbsent(record, path, fields, missing) {
  if (!record || typeof record !== "object" || Array.isArray(record)) return;
  for (const field of fields) {
    if (Object.hasOwn(record, field)) missing.push(`${path}.${field}_retired`);
  }
}

function normalizeMcpWorkflowApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result;
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : null;
  const normalized = {
    source: result.source ?? "rust_daemon_core.model_mount.mcp_workflow",
    plan,
    record_dir: result.record_dir ?? null,
    record_id: result.record_id ?? null,
    record,
    public_response: result.public_response ?? null,
    receipt: result.receipt ?? null,
    operation_kind: result.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? [],
    authority_grant_refs: arrayOrNull(result.authority_grant_refs) ?? [],
    authority_receipt_refs: arrayOrNull(result.authority_receipt_refs) ?? [],
    evidence_refs: arrayOrNull(result.evidence_refs),
    workflow_hash: result.workflow_hash ?? null,
    authority_hash: result.authority_hash ?? null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation_kind", "workflow_hash", "authority_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.mcp_workflow") {
    missing.push("rust_core_boundary");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("rust_daemon_core_model_mount_mcp_workflow")
  ) {
    missing.push("evidence_refs.rust_daemon_core_model_mount_mcp_workflow");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("agentgres_mcp_workflow_truth_required")
  ) {
    missing.push("evidence_refs.agentgres_mcp_workflow_truth_required");
  }
  if (record?.id !== normalized.record_id) {
    missing.push("record.id");
  }
  const publicResponse =
    normalized.public_response && typeof normalized.public_response === "object" && !Array.isArray(normalized.public_response)
      ? normalized.public_response
      : {};
  const receipt = normalized.receipt && typeof normalized.receipt === "object" && !Array.isArray(normalized.receipt)
    ? normalized.receipt
    : null;
  if (normalized.operation_kind === "model_mount.mcp_tool.invoke") {
    if (publicResponse.transport_execution_status === "rust_required") {
      missing.push("public_response.transport_execution_status.retired_rust_required");
    }
    if (publicResponse.transport_execution_status !== "rust_admitted") {
      missing.push("public_response.transport_execution_status.rust_admitted");
    }
    if (publicResponse.rust_transport_execution_admitted !== true) {
      missing.push("public_response.rust_transport_execution_admitted");
    }
    assertRetiredMcpWorkflowFieldsAbsent(publicResponse, "public_response", [
      "js_transport_invocation",
      "command_transport_fallback",
      "binary_bridge_fallback",
      "compatibility_fallback",
      "legacy_js_result_fallback",
    ], missing);
    assertRetiredMcpWorkflowFieldsAbsent(record?.details, "record.details", [
      "js_transport_invocation",
      "command_transport_fallback",
      "binary_bridge_fallback",
      "compatibility_fallback",
      "legacy_js_result_fallback",
    ], missing);
    for (const field of [
      "content_receipt_id",
      "result_receipt_id",
      "transport_execution_owner",
      "step_module_dispatch_owner",
    ]) {
      if (!publicResponse[field]) missing.push(`public_response.${field}`);
    }
    assertMcpWorkflowResultMaterialized(publicResponse, receipt, record, missing);
    if (!receipt) {
      missing.push("receipt");
    } else {
      if (receipt.kind !== "mcp_tool_invocation") missing.push("receipt.kind.mcp_tool_invocation");
      if (receipt.id !== publicResponse.content_receipt_id) missing.push("receipt.id.content_receipt_id");
      if (!receipt.evidenceRefs?.includes("model_mount_mcp_execution_content_receipt_rust_owned")) {
        missing.push("receipt.evidenceRefs.model_mount_mcp_execution_content_receipt_rust_owned");
      }
      if (receipt.details?.rust_daemon_core_receipt_author !== "model_mount.mcp_workflow") {
        missing.push("receipt.details.rust_daemon_core_receipt_author");
      }
      if (!receipt.details?.model_mount_mcp_content_hash) {
        missing.push("receipt.details.model_mount_mcp_content_hash");
      }
      if (!receipt.details?.model_mount_step_module_result?.state_root_after) {
        missing.push("receipt.details.model_mount_step_module_result.state_root_after");
      }
    }
  }
  if (normalized.operation_kind === "model_mount.workflow_node.execute") {
    if (publicResponse.execution_status === "rust_required") {
      missing.push("public_response.execution_status.retired_rust_required");
    }
    if (publicResponse.execution_status !== "rust_admitted") {
      missing.push("public_response.execution_status.rust_admitted");
    }
    if (publicResponse.rust_step_module_dispatch_admitted !== true) {
      missing.push("public_response.rust_step_module_dispatch_admitted");
    }
    assertRetiredMcpWorkflowFieldsAbsent(publicResponse, "public_response", [
      "js_route_test",
      "js_model_invocation",
      "js_mcp_tool_invocation",
      "command_transport_fallback",
      "binary_bridge_fallback",
      "compatibility_fallback",
      "legacy_js_result_fallback",
    ], missing);
    assertRetiredMcpWorkflowFieldsAbsent(record?.details, "record.details", [
      "js_route_test",
      "js_model_invocation",
      "js_mcp_tool_invocation",
      "command_transport_fallback",
      "binary_bridge_fallback",
      "compatibility_fallback",
      "legacy_js_result_fallback",
    ], missing);
    for (const field of [
      "content_receipt_id",
      "result_receipt_id",
      "workflow_execution_owner",
      "step_module_dispatch_owner",
    ]) {
      if (!publicResponse[field]) missing.push(`public_response.${field}`);
    }
    assertMcpWorkflowResultMaterialized(publicResponse, receipt, record, missing);
    if (!receipt) {
      missing.push("receipt");
    } else {
      if (receipt.kind !== "workflow_node_execution") missing.push("receipt.kind.workflow_node_execution");
      if (receipt.id !== publicResponse.content_receipt_id) missing.push("receipt.id.content_receipt_id");
      if (!receipt.evidenceRefs?.includes("model_mount_mcp_execution_content_receipt_rust_owned")) {
        missing.push("receipt.evidenceRefs.model_mount_mcp_execution_content_receipt_rust_owned");
      }
      if (receipt.details?.rust_daemon_core_receipt_author !== "model_mount.mcp_workflow") {
        missing.push("receipt.details.rust_daemon_core_receipt_author");
      }
      if (!receipt.details?.model_mount_mcp_content_hash) {
        missing.push("receipt.details.model_mount_mcp_content_hash");
      }
      if (!receipt.details?.model_mount_step_module_result?.state_root_after) {
        missing.push("receipt.details.model_mount_step_module_result.state_root_after");
      }
    }
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount MCP workflow plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_mcp_workflow_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeServerControlApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result;
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : null;
  const normalized = {
    source: result.source ?? "rust_daemon_core.model_mount.server_control",
    plan,
    record_dir: result.record_dir ?? null,
    record_id: result.record_id ?? null,
    record,
    public_response: result.public_response ?? null,
    operation_kind: result.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? [],
    evidence_refs: arrayOrNull(result.evidence_refs),
    control_hash: result.control_hash ?? null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation_kind", "control_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.server_control") {
    missing.push("rust_core_boundary");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("rust_daemon_core_server_control")
  ) {
    missing.push("evidence_refs.rust_daemon_core_server_control");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("agentgres_server_control_truth_required")
  ) {
    missing.push("evidence_refs.agentgres_server_control_truth_required");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount server-control plan is incomplete.");
    error.code = "model_mount_server_control_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeRuntimeEngineApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : result;
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const normalized = {
    source: result.source ?? plan.source ?? "rust_daemon_core.model_mount.runtime_engine",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    public_response: result.public_response ?? plan.public_response ?? null,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs) ?? [],
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    control_hash: result.control_hash ?? plan.control_hash ?? null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation_kind", "control_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.runtime_engine") {
    missing.push("rust_core_boundary");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("rust_daemon_core_runtime_engine")
  ) {
    missing.push("evidence_refs.rust_daemon_core_runtime_engine");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("agentgres_runtime_engine_truth_required")
  ) {
    missing.push("evidence_refs.agentgres_runtime_engine_truth_required");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount runtime-engine plan is incomplete.");
    error.code = "model_mount_runtime_engine_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeRuntimeSurveyApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : result;
  const receipt = result.receipt && typeof result.receipt === "object" && !Array.isArray(result.receipt)
    ? result.receipt
    : plan.receipt && typeof plan.receipt === "object" && !Array.isArray(plan.receipt)
      ? plan.receipt
      : null;
  const normalized = {
    source: result.source ?? plan.source ?? "rust_daemon_core.model_mount.runtime_survey",
    plan,
    receipt,
    public_response: result.public_response ?? plan.public_response ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs),
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    survey_hash: result.survey_hash ?? plan.survey_hash ?? receipt?.details?.runtime_survey_hash ?? null,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
  };
  const details = receipt?.details && typeof receipt.details === "object" && !Array.isArray(receipt.details)
    ? receipt.details
    : {};
  const missing = [];
  for (const field of ["receipt", "public_response", "receipt_refs", "evidence_refs", "survey_hash", "operation_kind"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.runtime_survey") {
    missing.push("rust_core_boundary");
  }
  if (receipt?.kind !== "runtime_survey") {
    missing.push("receipt.kind");
  }
  for (const field of ["checked_at", "engine_count", "selected_engines", "runtime_preference", "hardware", "lm_studio", "runtime_survey_hash"]) {
    if (!Object.hasOwn(details, field)) missing.push(`receipt.details.${field}`);
  }
  if (details.rust_daemon_core_receipt_author !== "model_mount.runtime_survey") {
    missing.push("receipt.details.rust_daemon_core_receipt_author");
  }
  if (details.js_hardware_probe_executed !== false) {
    missing.push("receipt.details.js_hardware_probe_executed_false");
  }
  if (details.js_runtime_engine_read_executed !== false) {
    missing.push("receipt.details.js_runtime_engine_read_executed_false");
  }
  if (details.js_lm_studio_probe_executed !== false) {
    missing.push("receipt.details.js_lm_studio_probe_executed_false");
  }
  if (!Array.isArray(normalized.evidence_refs)) {
    missing.push("evidence_refs");
  } else {
    for (const evidenceRef of [
      "model_mount_runtime_survey_js_facade_retired",
      "rust_daemon_core_runtime_survey",
      "agentgres_runtime_survey_truth_required",
      "rust_model_mount_core",
    ]) {
      if (!normalized.evidence_refs.includes(evidenceRef)) {
        missing.push(`evidence_refs.${evidenceRef}`);
      }
    }
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount runtime-survey plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_runtime_survey_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeTokenizerRequiredApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : {};
  const details = result.details && typeof result.details === "object" && !Array.isArray(result.details)
    ? result.details
    : record.details && typeof record.details === "object" && !Array.isArray(record.details)
      ? record.details
      : {};
  return {
    source: result.source ?? "rust_daemon_core.model_mount.tokenizer_required",
    record,
    status: result.status ?? record.status ?? "rust_core_required",
    status_code: result.status_code ?? record.status_code ?? 501,
    code: result.code ?? record.code ?? "model_mount_tokenizer_rust_core_required",
    message:
      result.message ??
      record.message ??
      "Model tokenization and context-fit utilities require direct Rust daemon-core admission and projection.",
    rust_core_boundary: result.rust_core_boundary ?? record.rust_core_boundary ?? "model_mount.tokenizer",
    operation: result.operation ?? record.operation ?? details.operation ?? null,
    details,
    evidence_refs: arrayOrNull(record.evidence_refs) ?? arrayOrNull(details.evidence_refs),
  };
}

function normalizeRouteControlRequiredApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : {};
  const details = result.details && typeof result.details === "object" && !Array.isArray(result.details)
    ? result.details
    : record.details && typeof record.details === "object" && !Array.isArray(record.details)
      ? record.details
      : {};
  return {
    source: result.source ?? "rust_daemon_core.model_mount.route_control_required",
    record,
    status: result.status ?? record.status ?? "rust_core_required",
    status_code: result.status_code ?? record.status_code ?? 501,
    code: result.code ?? record.code ?? "model_mount_route_control_rust_core_required",
    message: result.message ?? record.message ?? "Model route control requires Rust daemon-core ownership.",
    rust_core_boundary:
      result.rust_core_boundary ?? record.rust_core_boundary ?? "model_mount.route_control",
    operation: result.operation ?? record.operation ?? details.operation ?? null,
    operation_kind: result.operation_kind ?? record.operation_kind ?? details.operation_kind ?? null,
    details,
    evidence_refs: arrayOrNull(record.evidence_refs) ?? arrayOrNull(details.evidence_refs),
  };
}

function normalizeRouteControlApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : result;
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const normalized = {
    source: result.source ?? plan.source ?? "rust_daemon_core.model_mount.route_control",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs),
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    control_hash: result.control_hash ?? plan.control_hash ?? null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation_kind", "control_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.route_control") {
    missing.push("rust_core_boundary");
  }
  if (!Array.isArray(normalized.receipt_refs) || normalized.receipt_refs.length === 0) {
    missing.push("receipt_refs");
  }
  if (!Array.isArray(normalized.evidence_refs) || !normalized.evidence_refs.includes("model_mount_route_control_rust_owned")) {
    missing.push("evidence_refs.model_mount_route_control_rust_owned");
  }
  if (record?.id !== normalized.record_id) {
    missing.push("record.id");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount route-control plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_route_control_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeCatalogProviderControlApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const normalized = {
    source: result.source ?? "rust_daemon_core.model_mount.catalog_provider_control",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs) ?? [],
    authority_grant_refs: arrayOrNull(result.authority_grant_refs) ?? arrayOrNull(plan.authority_grant_refs) ?? [],
    authority_receipt_refs:
      arrayOrNull(result.authority_receipt_refs) ?? arrayOrNull(plan.authority_receipt_refs) ?? [],
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    control_hash: result.control_hash ?? plan.control_hash ?? null,
    authority_hash: result.authority_hash ?? plan.authority_hash ?? null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation_kind", "control_hash", "authority_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.catalog_provider_control") {
    missing.push("rust_core_boundary");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("rust_daemon_core_catalog_provider_control")
  ) {
    missing.push("evidence_refs.rust_daemon_core_catalog_provider_control");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("ctee_catalog_provider_custody_enforced")
  ) {
    missing.push("evidence_refs.ctee_catalog_provider_custody_enforced");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("agentgres_catalog_provider_control_truth_required")
  ) {
    missing.push("evidence_refs.agentgres_catalog_provider_control_truth_required");
  }
  if (record?.id !== normalized.record_id) {
    missing.push("record.id");
  }
  if (record?.plaintext_material_returned !== false) {
    missing.push("record.plaintext_material_returned_false");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount catalog-provider-control plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_catalog_provider_control_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeProviderControlApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const normalized = {
    source: result.source ?? "rust_daemon_core.model_mount.provider_control",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    public_response: result.public_response ?? plan.public_response ?? record?.public_response ?? null,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs) ?? [],
    authority_grant_refs: arrayOrNull(result.authority_grant_refs) ?? arrayOrNull(plan.authority_grant_refs) ?? [],
    authority_receipt_refs:
      arrayOrNull(result.authority_receipt_refs) ?? arrayOrNull(plan.authority_receipt_refs) ?? [],
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    control_hash: result.control_hash ?? plan.control_hash ?? null,
    authority_hash: result.authority_hash ?? plan.authority_hash ?? null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation_kind", "control_hash", "authority_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.provider_control") {
    missing.push("rust_core_boundary");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("rust_daemon_core_provider_control")
  ) {
    missing.push("evidence_refs.rust_daemon_core_provider_control");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("ctee_provider_custody_enforced")
  ) {
    missing.push("evidence_refs.ctee_provider_custody_enforced");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("agentgres_provider_control_truth_required")
  ) {
    missing.push("evidence_refs.agentgres_provider_control_truth_required");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("public_provider_control_js_facade_retired")
  ) {
    missing.push("evidence_refs.public_provider_control_js_facade_retired");
  }
  if (record?.id !== normalized.record_id) {
    missing.push("record.id");
  }
  if (record?.plaintext_material_returned !== false) {
    missing.push("record.plaintext_material_returned_false");
  }
  if (record?.public_response?.private_material_returned !== false) {
    missing.push("record.public_response.private_material_returned_false");
  }
  if (record?.public_response?.plaintext_material_persisted !== false) {
    missing.push("record.public_response.plaintext_material_persisted_false");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount provider-control plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_provider_control_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeProviderAuthMaterializationApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const publicResponse = result.public_response ?? plan.public_response ?? record?.public_response ?? null;
  const normalized = {
    source: result.source ?? "rust_daemon_core.model_mount.provider_auth_materialization",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    public_response: publicResponse,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs) ?? [],
    authority_grant_refs: arrayOrNull(result.authority_grant_refs) ?? arrayOrNull(plan.authority_grant_refs) ?? [],
    authority_receipt_refs:
      arrayOrNull(result.authority_receipt_refs) ?? arrayOrNull(plan.authority_receipt_refs) ?? [],
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    materialization_hash: result.materialization_hash ?? plan.materialization_hash ?? null,
    authority_hash: result.authority_hash ?? plan.authority_hash ?? null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation_kind", "materialization_hash", "authority_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.provider_auth_materialization") {
    missing.push("rust_core_boundary");
  }
  for (const ref of [
    "rust_daemon_core_provider_auth_materialization",
    "rust_provider_auth_materialization_bound",
    "wallet_network_provider_vault_ref_bound",
    "ctee_provider_auth_header_custody_enforced",
    "rust_ctee_egress_resolver_bound",
    "ctee_outbound_egress_resolver_depth_bound",
    "agentgres_provider_auth_materialization_truth_required",
    "public_provider_auth_header_js_facade_retired",
  ]) {
    if (!Array.isArray(normalized.evidence_refs) || !normalized.evidence_refs.includes(ref)) {
      missing.push(`evidence_refs.${ref}`);
    }
  }
  if (record?.id !== normalized.record_id) {
    missing.push("record.id");
  }
  if (record?.auth_header_materialization_status !== "rust_ctee_outbound_header_bound") {
    missing.push("record.auth_header_materialization_status");
  }
  if (record?.plaintext_secret_material_returned !== false) {
    missing.push("record.plaintext_secret_material_returned_false");
  }
  if (record?.auth_header_value_returned !== false) {
    missing.push("record.auth_header_value_returned_false");
  }
  if (record?.auth_header_value_persisted !== false) {
    missing.push("record.auth_header_value_persisted_false");
  }
  if (publicResponse?.auth_header_value_returned !== false) {
    missing.push("public_response.auth_header_value_returned_false");
  }
  if (!record?.outbound_header_binding_ref) {
    missing.push("record.outbound_header_binding_ref");
  }
  if (!record?.provider_auth_materialization_ref) {
    missing.push("record.provider_auth_materialization_ref");
  }
  if (!record?.ctee_egress_resolver_ref) {
    missing.push("record.ctee_egress_resolver_ref");
  }
  if (!record?.ctee_egress_resolver_hash) {
    missing.push("record.ctee_egress_resolver_hash");
  }
  if (record?.ctee_egress_resolution_status !== "rust_ctee_outbound_egress_resolved") {
    missing.push("record.ctee_egress_resolution_status");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount provider-auth materialization plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_provider_auth_materialization_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeCapabilityTokenControlApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const normalized = {
    source: result.source ?? "rust_daemon_core.model_mount.capability_token_control",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    public_response: result.public_response ?? plan.public_response ?? null,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs) ?? [],
    authority_grant_refs: arrayOrNull(result.authority_grant_refs) ?? arrayOrNull(plan.authority_grant_refs) ?? [],
    authority_receipt_refs:
      arrayOrNull(result.authority_receipt_refs) ?? arrayOrNull(plan.authority_receipt_refs) ?? [],
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    control_hash: result.control_hash ?? plan.control_hash ?? null,
    authority_hash: result.authority_hash ?? plan.authority_hash ?? null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation_kind", "control_hash", "authority_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.capability_token") {
    missing.push("rust_core_boundary");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("rust_daemon_core_capability_token_control")
  ) {
    missing.push("evidence_refs.rust_daemon_core_capability_token_control");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("wallet_network_capability_token_authority_required")
  ) {
    missing.push("evidence_refs.wallet_network_capability_token_authority_required");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("agentgres_capability_token_truth_required")
  ) {
    missing.push("evidence_refs.agentgres_capability_token_truth_required");
  }
  if (record?.id !== normalized.record_id) {
    missing.push("record.id");
  }
  if (record?.public_response?.token != null) {
    missing.push("record.public_response.token_absent");
  }
  if (record?.public_response?.plaintext_material_persisted !== false) {
    missing.push("record.public_response.plaintext_material_persisted_false");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount capability-token-control plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_capability_token_control_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeVaultControlApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const normalized = {
    source: result.source ?? "rust_daemon_core.model_mount.vault_control",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    public_response: result.public_response ?? plan.public_response ?? null,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs) ?? [],
    authority_grant_refs: arrayOrNull(result.authority_grant_refs) ?? arrayOrNull(plan.authority_grant_refs) ?? [],
    authority_receipt_refs:
      arrayOrNull(result.authority_receipt_refs) ?? arrayOrNull(plan.authority_receipt_refs) ?? [],
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    control_hash: result.control_hash ?? plan.control_hash ?? null,
    authority_hash: result.authority_hash ?? plan.authority_hash ?? null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation_kind", "control_hash", "authority_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.vault") {
    missing.push("rust_core_boundary");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("rust_daemon_core_vault_control")
  ) {
    missing.push("evidence_refs.rust_daemon_core_vault_control");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("wallet_network_vault_authority_required")
  ) {
    missing.push("evidence_refs.wallet_network_vault_authority_required");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("ctee_vault_custody_enforced")
  ) {
    missing.push("evidence_refs.ctee_vault_custody_enforced");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("agentgres_vault_truth_required")
  ) {
    missing.push("evidence_refs.agentgres_vault_truth_required");
  }
  if (record?.id !== normalized.record_id) {
    missing.push("record.id");
  }
  if (record?.public_response?.material != null) {
    missing.push("record.public_response.material_absent");
  }
  if (record?.ctee_custody?.plaintext_material_persisted !== false) {
    missing.push("record.ctee_custody.plaintext_material_persisted_false");
  }
  if (record?.ctee_custody?.plaintext_material_returned !== false) {
    missing.push("record.ctee_custody.plaintext_material_returned_false");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount vault-control plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_vault_control_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeTokenizerApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const normalized = {
    source: result.source ?? "rust_daemon_core.model_mount.tokenizer",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    operation: result.operation ?? plan.operation ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs),
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    control_hash: result.control_hash ?? plan.control_hash ?? null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation", "control_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.tokenizer") {
    missing.push("rust_core_boundary");
  }
  if (!Array.isArray(normalized.receipt_refs) || normalized.receipt_refs.length === 0) {
    missing.push("receipt_refs");
  }
  if (!Array.isArray(normalized.evidence_refs) || !normalized.evidence_refs.includes("model_mount_tokenizer_rust_owned")) {
    missing.push("evidence_refs.model_mount_tokenizer_rust_owned");
  }
  if (record?.id !== normalized.record_id) {
    missing.push("record.id");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount tokenizer plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_tokenizer_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      backend: normalized.backend,
      operation: normalized.operation,
    };
    throw error;
  }
  return normalized;
}

function normalizeConversationStateApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const normalized = {
    source: result.source ?? "rust_daemon_core.model_mount.conversation_state",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    operation: result.operation ?? plan.operation ?? null,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs),
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    conversation_hash: result.conversation_hash ?? plan.conversation_hash ?? null,
  };
  const missing = [];
  for (const field of ["record_dir", "record_id", "record", "operation", "operation_kind", "conversation_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.conversation") {
    missing.push("rust_core_boundary");
  }
  if (!Array.isArray(normalized.receipt_refs) || normalized.receipt_refs.length === 0) {
    missing.push("receipt_refs");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("model_mount_conversation_state_rust_owned")
  ) {
    missing.push("evidence_refs.model_mount_conversation_state_rust_owned");
  }
  if (record?.id !== normalized.record_id) {
    missing.push("record.id");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount conversation-state plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_conversation_state_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      backend: normalized.backend,
      operation: normalized.operation,
    };
    throw error;
  }
  return normalized;
}

function normalizeStreamCompletionApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const receipt = result.receipt && typeof result.receipt === "object" && !Array.isArray(result.receipt)
    ? result.receipt
    : plan.receipt && typeof plan.receipt === "object" && !Array.isArray(plan.receipt)
      ? plan.receipt
      : null;
  const normalized = {
    source: result.source ?? "rust_daemon_core.model_mount.stream_completion",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    receipt,
    operation: result.operation ?? plan.operation ?? null,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs),
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    stream_completion_hash: result.stream_completion_hash ?? plan.stream_completion_hash ?? null,
    conversation_hash: result.conversation_hash ?? plan.conversation_hash ?? null,
  };
  const missing = [];
  for (const field of [
    "record_dir",
    "record_id",
    "record",
    "receipt",
    "operation",
    "operation_kind",
    "stream_completion_hash",
    "conversation_hash",
  ]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.conversation") {
    missing.push("rust_core_boundary");
  }
  if (!Array.isArray(normalized.receipt_refs) || normalized.receipt_refs.length === 0) {
    missing.push("receipt_refs");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("model_mount_stream_completion_rust_owned")
  ) {
    missing.push("evidence_refs.model_mount_stream_completion_rust_owned");
  }
  if (record?.id !== normalized.record_id) {
    missing.push("record.id");
  }
  if (receipt?.kind !== "model_invocation_stream_completed") {
    missing.push("receipt.kind");
  }
  if (!receipt?.details?.model_mount_step_module_result?.agentgres_operation_refs) {
    missing.push("receipt.details.model_mount_step_module_result.agentgres_operation_refs");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount stream-completion plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_stream_completion_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      backend: normalized.backend,
      operation: normalized.operation,
    };
    throw error;
  }
  return normalized;
}

function normalizeStreamCancelApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : {};
  const record = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
      ? plan.record
      : null;
  const receipt = result.receipt && typeof result.receipt === "object" && !Array.isArray(result.receipt)
    ? result.receipt
    : plan.receipt && typeof plan.receipt === "object" && !Array.isArray(plan.receipt)
      ? plan.receipt
      : null;
  const normalized = {
    source: result.source ?? "rust_daemon_core.model_mount.stream_cancel",
    plan,
    record_dir: result.record_dir ?? plan.record_dir ?? null,
    record_id: result.record_id ?? plan.record_id ?? null,
    record,
    receipt,
    operation: result.operation ?? plan.operation ?? null,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs),
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
    stream_cancel_hash: result.stream_cancel_hash ?? plan.stream_cancel_hash ?? null,
    conversation_hash: result.conversation_hash ?? plan.conversation_hash ?? null,
  };
  const missing = [];
  for (const field of [
    "record_dir",
    "record_id",
    "record",
    "receipt",
    "operation",
    "operation_kind",
    "stream_cancel_hash",
    "conversation_hash",
  ]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.conversation") {
    missing.push("rust_core_boundary");
  }
  if (!Array.isArray(normalized.receipt_refs) || normalized.receipt_refs.length === 0) {
    missing.push("receipt_refs");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("model_mount_stream_cancel_rust_owned")
  ) {
    missing.push("evidence_refs.model_mount_stream_cancel_rust_owned");
  }
  if (
    !Array.isArray(normalized.evidence_refs) ||
    !normalized.evidence_refs.includes("agentgres_model_stream_cancel_truth_required")
  ) {
    missing.push("evidence_refs.agentgres_model_stream_cancel_truth_required");
  }
  if (record?.id !== normalized.record_id) {
    missing.push("record.id");
  }
  if (receipt?.kind !== "model_invocation_stream_canceled") {
    missing.push("receipt.kind");
  }
  if (!receipt?.details?.model_mount_step_module_result?.agentgres_operation_refs) {
    missing.push("receipt.details.model_mount_step_module_result.agentgres_operation_refs");
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount stream-cancel plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_stream_cancel_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      backend: normalized.backend,
      operation: normalized.operation,
    };
    throw error;
  }
  return normalized;
}

function normalizeReceiptGateApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const plan = result.plan && typeof result.plan === "object" && !Array.isArray(result.plan)
    ? result.plan
    : {};
  const receipt = result.receipt && typeof result.receipt === "object" && !Array.isArray(result.receipt)
    ? result.receipt
    : plan.receipt && typeof plan.receipt === "object" && !Array.isArray(plan.receipt)
      ? plan.receipt
      : null;
  const normalized = {
    source: result.source ?? "rust_daemon_core.model_mount.receipt_gate",
    plan,
    receipt,
    public_response: result.public_response ?? plan.public_response ?? null,
    operation_kind: result.operation_kind ?? plan.operation_kind ?? null,
    rust_core_boundary: result.rust_core_boundary ?? plan.rust_core_boundary ?? null,
    gate_hash: result.gate_hash ?? plan.gate_hash ?? null,
    receipt_refs: arrayOrNull(result.receipt_refs) ?? arrayOrNull(plan.receipt_refs) ?? [],
    evidence_refs: arrayOrNull(result.evidence_refs) ?? arrayOrNull(plan.evidence_refs),
  };
  const details = receipt?.details && typeof receipt.details === "object" && !Array.isArray(receipt.details)
    ? receipt.details
    : {};
  const missing = [];
  for (const field of ["receipt", "operation_kind", "gate_hash"]) {
    if (!normalized[field]) missing.push(field);
  }
  if (normalized.rust_core_boundary !== "model_mount.receipt_gate") {
    missing.push("rust_core_boundary");
  }
  if (!["workflow_receipt_gate", "workflow_receipt_gate_blocked"].includes(receipt?.kind)) {
    missing.push("receipt.kind");
  }
  if (!details.model_mount_receipt_gate_hash) {
    missing.push("receipt.details.model_mount_receipt_gate_hash");
  }
  if (!details.model_mount_receipt_binding_ref) {
    missing.push("receipt.details.model_mount_receipt_binding_ref");
  }
  if (!details.model_mount_agentgres_operation_ref) {
    missing.push("receipt.details.model_mount_agentgres_operation_ref");
  }
  if (!Array.isArray(normalized.evidence_refs)) {
    missing.push("evidence_refs");
  } else {
    for (const evidenceRef of [
      "model_mount_receipt_gate_rust_owned",
      "model_mount_receipt_gate_js_facade_retired",
      "rust_receipt_binder_core",
      "agentgres_model_receipt_gate_truth_required",
    ]) {
      if (!normalized.evidence_refs.includes(evidenceRef)) {
        missing.push(`evidence_refs.${evidenceRef}`);
      }
    }
  }
  if (missing.length > 0) {
    const error = new Error("Rust model_mount receipt-gate plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_receipt_gate_plan_invalid";
    error.details = {
      missing,
      source: normalized.source,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeAcceptedReceiptHeadApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const head = result.head && typeof result.head === "object" ? result.head : {};
  return {
    source: result.source ?? "rust_daemon_core.model_mount.accepted_receipt_head",
    head,
    sequence: result.sequence ?? head.sequence ?? null,
    head_ref: result.head_ref ?? head.head_ref ?? null,
    state_root: result.state_root ?? head.state_root ?? null,
    projection_watermark: result.projection_watermark ?? head.projection_watermark ?? null,
    head_hash: result.head_hash ?? head.head_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs
      : Array.isArray(head.evidence_refs)
        ? head.evidence_refs
        : null,
  };
}

function normalizeAcceptedReceiptTransitionApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const transition = result.transition && typeof result.transition === "object" ? result.transition : {};
  return {
    source: result.source ?? "rust_daemon_core.model_mount.accepted_receipt_transition",
    transition,
    operation_id: result.operation_id ?? transition.operation_id ?? null,
    operation_ref: result.operation_ref ?? transition.operation_ref ?? null,
    expected_heads: Array.isArray(result.expected_heads)
      ? result.expected_heads
      : Array.isArray(transition.expected_heads)
        ? transition.expected_heads
        : null,
    state_root_before: result.state_root_before ?? transition.state_root_before ?? null,
    state_root_after: result.state_root_after ?? transition.state_root_after ?? null,
    resulting_head: result.resulting_head ?? transition.resulting_head ?? null,
    projection_watermark: result.projection_watermark ?? transition.projection_watermark ?? null,
    transition_hash: result.transition_hash ?? transition.transition_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs
      : Array.isArray(transition.evidence_refs)
        ? transition.evidence_refs
        : null,
  };
}

function normalizeInvocationReceiptBindingApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    source: result.source ?? "rust_daemon_core.model_mount.invocation_receipt_binding",
    invocation: result.invocation ?? null,
    result: result.result ?? null,
    router_admission: result.router_admission ?? null,
    receipt_binding: result.receipt_binding ?? null,
    accepted_receipt_append: result.accepted_receipt_append ?? null,
    agentgres_admission: result.agentgres_admission ?? null,
    projection_record: result.projection_record ?? null,
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

function normalizeReadProjectionApiResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    source: result.source ?? "rust_daemon_core.model_mount.read_projection",
    projection_kind: result.projection_kind ?? result.projectionKind ?? null,
    projection: result.projection ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

function modelMountApi(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function arrayOrNull(value) {
  return Array.isArray(value) ? value : null;
}
