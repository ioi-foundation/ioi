export const MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUST_MODEL_MOUNT_ADMISSION_BACKEND = "rust_model_mount_live";
export const RUST_MODEL_MOUNT_FIXTURE_BACKEND = "rust_model_mount_fixture";
export const RUST_MODEL_MOUNT_FIXTURE_INVENTORY_BACKEND = "rust_model_mount_fixture_inventory";
export const RUST_MODEL_MOUNT_FIXTURE_LIFECYCLE_BACKEND = "rust_model_mount_fixture_lifecycle";
export const RUST_MODEL_MOUNT_HOSTED_PROVIDER_INVENTORY_BACKEND = "rust_model_mount_hosted_provider_inventory";
export const RUST_MODEL_MOUNT_BACKEND_PROCESS_BACKEND = "rust_model_mount_backend_process";
export const RUST_MODEL_MOUNT_BACKEND_LIFECYCLE_BACKEND = "rust_model_mount_backend_lifecycle";
export const RUST_MODEL_MOUNT_ARTIFACT_ENDPOINT_BACKEND = "rust_model_mount_artifact_endpoint";
export const RUST_MODEL_MOUNT_STORAGE_CONTROL_BACKEND = "rust_model_mount_storage_control";
export const RUST_MODEL_MOUNT_MCP_WORKFLOW_BACKEND = "rust_model_mount_mcp_workflow";
export const RUST_MODEL_MOUNT_SERVER_CONTROL_BACKEND = "rust_model_mount_server_control";
export const RUST_MODEL_MOUNT_RUNTIME_ENGINE_BACKEND = "rust_model_mount_runtime_engine";
export const RUST_MODEL_MOUNT_RUNTIME_SURVEY_BACKEND = "rust_model_mount_runtime_survey";
export const RUST_MODEL_MOUNT_TOKENIZER_REQUIRED_BACKEND = "rust_model_mount_tokenizer_required";
export const RUST_MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_BACKEND = "rust_model_mount_route_control_required";
export const RUST_MODEL_MOUNT_ROUTE_CONTROL_BACKEND = "rust_model_mount_route_control";
export const RUST_MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_BACKEND = "rust_model_mount_catalog_provider_control";
export const RUST_MODEL_MOUNT_PROVIDER_CONTROL_BACKEND = "rust_model_mount_provider_control";
export const RUST_MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_BACKEND = "rust_model_mount_capability_token_control";
export const RUST_MODEL_MOUNT_VAULT_CONTROL_BACKEND = "rust_model_mount_vault_control";
export const RUST_MODEL_MOUNT_RECEIPT_GATE_BACKEND = "rust_model_mount_receipt_gate";
export const RUST_MODEL_MOUNT_TOKENIZER_BACKEND = "rust_model_mount_tokenizer";
export const RUST_MODEL_MOUNT_CONVERSATION_STATE_BACKEND = "rust_model_mount_conversation_state";
export const RUST_MODEL_MOUNT_STREAM_COMPLETION_BACKEND = "rust_model_mount_stream_completion";
export const RUST_MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_BACKEND = "rust_model_mount_accepted_receipt_head";
export const RUST_MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_BACKEND = "rust_model_mount_accepted_receipt_transition";
export const RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND = "rust_model_mount_instance_lifecycle";
export const RUST_MODEL_MOUNT_NATIVE_LOCAL_BACKEND = "rust_model_mount_native_local";
export const RUST_MODEL_MOUNT_NATIVE_LOCAL_INVENTORY_BACKEND = "rust_model_mount_native_local_inventory";
export const RUST_MODEL_MOUNT_NATIVE_LOCAL_LIFECYCLE_BACKEND = "rust_model_mount_native_local_lifecycle";

export function createModelMountAdmissionRunnerFromEnv(env = process.env, options = {}) {
  assertNoModelMountAdmissionCommandArgs(
    options.args ??
      env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS ??
      env.IOI_MODEL_MOUNT_ADMISSION_COMMAND_ARGS,
  );
  assertNoModelMountAdmissionCommandSelection(
    options.command ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND ?? env.IOI_MODEL_MOUNT_ADMISSION_COMMAND,
  );
  return new RustModelMountAdmissionRunner({
    daemonCoreInvoker: options.daemonCoreInvoker,
  });
}

export function assertNoModelMountAdmissionCommandArgs(value) {
  if (value == null) return;
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  throw new ModelMountAdmissionRunnerError(
    "Model-mount admission command argument selection is retired; daemon-core command argv is fixed migration transport.",
    "model_mount_admission_command_args_retired",
    { retired_args: value },
  );
}

export function assertNoModelMountAdmissionCommandSelection(value) {
  if (value == null) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  throw new ModelMountAdmissionRunnerError(
    "Model-mount admission binary command selection is retired; use daemonCoreInvoker for direct Rust daemon-core model_mount admission.",
    "model_mount_admission_command_selection_retired",
    { retired_command: value },
  );
}

export class RustModelMountAdmissionRunner {
  constructor(options = {}) {
    assertNoModelMountAdmissionCommandArgs(options.args);
    assertNoModelMountAdmissionCommandSelection(options.command);
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  admitRouteDecision(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "admit_model_mount_route_decision",
      backend: RUST_MODEL_MOUNT_ADMISSION_BACKEND,
      request,
    };
    return normalizeRouteDecisionBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  admitInvocation(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "admit_model_mount_invocation",
      backend: RUST_MODEL_MOUNT_ADMISSION_BACKEND,
      request,
    };
    return normalizeInvocationBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  admitProviderExecution(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "admit_model_mount_provider_execution",
      backend: RUST_MODEL_MOUNT_ADMISSION_BACKEND,
      request,
    };
    return normalizeProviderExecutionBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  executeProviderInvocation(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "execute_model_mount_provider_invocation",
      backend: request?.execution_backend ?? RUST_MODEL_MOUNT_FIXTURE_BACKEND,
      request,
    };
    return normalizeProviderInvocationBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  executeProviderStreamInvocation(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "execute_model_mount_provider_stream_invocation",
      backend: request?.execution_backend ?? RUST_MODEL_MOUNT_NATIVE_LOCAL_BACKEND,
      request,
    };
    return normalizeProviderStreamInvocationBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planProviderLifecycle(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_provider_lifecycle",
      backend: request?.execution_backend ?? RUST_MODEL_MOUNT_NATIVE_LOCAL_LIFECYCLE_BACKEND,
      request,
    };
    return normalizeProviderLifecycleBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planProviderInventory(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_provider_inventory",
      backend: request?.execution_backend ?? RUST_MODEL_MOUNT_NATIVE_LOCAL_INVENTORY_BACKEND,
      request,
    };
    return normalizeProviderInventoryBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planInstanceLifecycle(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_instance_lifecycle",
      backend: request?.execution_backend ?? RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND,
      request,
    };
    return normalizeInstanceLifecycleBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  admitProviderResult(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "admit_model_mount_provider_result",
      backend: RUST_MODEL_MOUNT_ADMISSION_BACKEND,
      request,
    };
    return normalizeProviderResultBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planBackendProcess(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_backend_process",
      backend: RUST_MODEL_MOUNT_BACKEND_PROCESS_BACKEND,
      request,
    };
    return normalizeBackendProcessPlanBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planBackendLifecycle(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_backend_lifecycle",
      backend: RUST_MODEL_MOUNT_BACKEND_LIFECYCLE_BACKEND,
      request,
    };
    return normalizeBackendLifecycleBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planArtifactEndpoint(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_artifact_endpoint",
      backend: RUST_MODEL_MOUNT_ARTIFACT_ENDPOINT_BACKEND,
      request,
    };
    return normalizeArtifactEndpointBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planStorageControl(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_storage_control",
      backend: RUST_MODEL_MOUNT_STORAGE_CONTROL_BACKEND,
      request,
    };
    return normalizeStorageControlBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planMcpWorkflow(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_mcp_workflow",
      backend: RUST_MODEL_MOUNT_MCP_WORKFLOW_BACKEND,
      request,
    };
    return normalizeMcpWorkflowBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planServerControl(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_server_control",
      backend: RUST_MODEL_MOUNT_SERVER_CONTROL_BACKEND,
      request,
    };
    return normalizeServerControlBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planRuntimeEngine(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_runtime_engine",
      backend: RUST_MODEL_MOUNT_RUNTIME_ENGINE_BACKEND,
      request,
    };
    return normalizeRuntimeEngineBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planRuntimeSurvey(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_runtime_survey",
      backend: RUST_MODEL_MOUNT_RUNTIME_SURVEY_BACKEND,
      request,
    };
    return normalizeRuntimeSurveyBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planTokenizerRequired(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_tokenizer_required",
      backend: RUST_MODEL_MOUNT_TOKENIZER_REQUIRED_BACKEND,
      request,
    };
    return normalizeTokenizerRequiredBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planTokenizer(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_tokenizer",
      backend: RUST_MODEL_MOUNT_TOKENIZER_BACKEND,
      request,
    };
    return normalizeTokenizerBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planConversationState(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_conversation_state",
      backend: RUST_MODEL_MOUNT_CONVERSATION_STATE_BACKEND,
      request,
    };
    return normalizeConversationStateBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planStreamCompletion(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_stream_completion",
      backend: RUST_MODEL_MOUNT_STREAM_COMPLETION_BACKEND,
      request,
    };
    return normalizeStreamCompletionBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planRouteControlRequired(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_route_control_required",
      backend: RUST_MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_BACKEND,
      request,
    };
    return normalizeRouteControlRequiredBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planRouteControl(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_route_control",
      backend: RUST_MODEL_MOUNT_ROUTE_CONTROL_BACKEND,
      request,
    };
    return normalizeRouteControlBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planCatalogProviderControl(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_catalog_provider_control",
      backend: RUST_MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_BACKEND,
      request,
    };
    return normalizeCatalogProviderControlBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planProviderControl(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_provider_control",
      backend: RUST_MODEL_MOUNT_PROVIDER_CONTROL_BACKEND,
      request,
    };
    return normalizeProviderControlBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planCapabilityTokenControl(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_capability_token_control",
      backend: RUST_MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_BACKEND,
      request,
    };
    return normalizeCapabilityTokenControlBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planVaultControl(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_vault_control",
      backend: RUST_MODEL_MOUNT_VAULT_CONTROL_BACKEND,
      request,
    };
    return normalizeVaultControlBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planReceiptGate(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_receipt_gate",
      backend: RUST_MODEL_MOUNT_RECEIPT_GATE_BACKEND,
      request,
    };
    return normalizeReceiptGateBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planAcceptedReceiptHead(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_accepted_receipt_head",
      backend: RUST_MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_BACKEND,
      request,
    };
    return normalizeAcceptedReceiptHeadBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planAcceptedReceiptTransition(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_accepted_receipt_transition",
      backend: RUST_MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_BACKEND,
      request,
    };
    return normalizeAcceptedReceiptTransitionBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planReadProjection(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_read_projection",
      backend: "rust_model_mount_read_projection",
      request,
    };
    return normalizeReadProjectionBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  bindInvocationReceipt(request = {}) {
    if (Object.hasOwn(request, "expectedHeads")) {
      throw new ModelMountAdmissionRunnerError(
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
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "bind_model_mount_invocation_receipt",
      backend: RUST_MODEL_MOUNT_ADMISSION_BACKEND,
      invocation,
      result,
      accepted_receipt_transition: acceptedReceiptTransition,
      receipt_ref: receiptRef,
    };
    return normalizeInvocationReceiptBindingBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new ModelMountAdmissionRunnerError(
        "Model mount admission requires daemonCoreInvoker for direct Rust daemon-core model_mount admission.",
        "model_mount_admission_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    const responseError = objectRecord(response?.error);
    if (response?.ok === false && responseError) {
      throw new ModelMountAdmissionRunnerError(
        responseError.message ?? "Rust model_mount core rejected the admission request.",
        responseError.code ?? "model_mount_admission_direct_invoker_rejected",
        { error: responseError },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

export class ModelMountAdmissionRunnerError extends Error {
  constructor(message, code = "model_mount_admission_runner_error", details = {}) {
    super(message);
    this.name = "ModelMountAdmissionRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

function normalizeRouteDecisionBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  return {
    source: result.source ?? "rust_model_mount_command",
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

function normalizeInvocationBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  return {
    source: result.source ?? "rust_model_mount_invocation_command",
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

function normalizeProviderExecutionBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  return {
    source: result.source ?? "rust_model_mount_provider_execution_command",
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

function normalizeProviderInvocationBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : {};
  return {
    source: result.source ?? "rust_model_mount_provider_invocation_command",
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

function normalizeProviderStreamInvocationBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : {};
  const streamChunks = Array.isArray(result.streamChunks)
    ? result.streamChunks
    : Array.isArray(result.stream_chunks)
      ? result.stream_chunks
      : Array.isArray(record.stream_chunks)
        ? record.stream_chunks
        : [];
  return {
    source: result.source ?? "rust_model_mount_provider_stream_invocation_command",
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

function normalizeProviderLifecycleBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : {};
  const lifecycleRecord = result.record && typeof result.record === "object" && !Array.isArray(result.record)
    ? result.record
    : record.record && typeof record.record === "object" && !Array.isArray(record.record)
      ? record.record
      : null;
  return {
    source: result.source ?? "rust_model_mount_provider_lifecycle_command",
    backend: result.backend ?? record.execution_backend ?? RUST_MODEL_MOUNT_NATIVE_LOCAL_LIFECYCLE_BACKEND,
    result: record,
    status: result.status ?? record.status ?? null,
    backendId: result.backend_id ?? record.backend_id ?? null,
    providerBackend: result.provider_backend ?? record.backend ?? null,
    driver: result.driver ?? record.driver ?? null,
    executionBackend: result.execution_backend ?? record.execution_backend ?? null,
    lifecycle_hash: result.lifecycle_hash ?? record.lifecycle_hash ?? null,
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

function normalizeProviderInventoryBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : {};
  const itemRefs = Array.isArray(result.item_refs)
      ? result.item_refs
      : Array.isArray(record.item_refs)
        ? record.item_refs
        : null;
  return {
    source: result.source ?? "rust_model_mount_provider_inventory_command",
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

function normalizeInstanceLifecycleBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : {};
  return {
    source: result.source ?? "rust_model_mount_instance_lifecycle_command",
    backend: result.backend ?? record.execution_backend ?? RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND,
    result: record,
    action: result.action ?? record.action ?? null,
    status: result.status ?? record.status ?? null,
    backendId: result.backendId ?? result.backend_id ?? record.backend_id ?? null,
    driver: result.driver ?? record.driver ?? null,
    executionBackend: result.execution_backend ?? record.execution_backend ?? null,
    provider_lifecycle_hash: result.provider_lifecycle_hash ?? record.provider_lifecycle_hash ?? null,
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

function normalizeProviderResultBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.record && typeof result.record === "object" ? result.record : {};
  return {
    source: result.source ?? "rust_model_mount_provider_result_command",
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

function normalizeBackendProcessPlanBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : {};
  return {
    source: result.source ?? "rust_model_mount_backend_process_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_BACKEND_PROCESS_BACKEND,
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

function normalizeBackendLifecycleBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_backend_lifecycle_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_BACKEND_LIFECYCLE_BACKEND,
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
  if (missing.length > 0) {
    const error = new Error("Rust model_mount backend-lifecycle plan is incomplete.");
    error.code = "model_mount_backend_lifecycle_plan_invalid";
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

function normalizeArtifactEndpointBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_artifact_endpoint_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_ARTIFACT_ENDPOINT_BACKEND,
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
      backend: normalized.backend,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeStorageControlBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_storage_control_command",
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

function normalizeMcpWorkflowBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_mcp_workflow_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_MCP_WORKFLOW_BACKEND,
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
    workflow_hash: result.workflow_hash ?? plan.workflow_hash ?? null,
    authority_hash: result.authority_hash ?? plan.authority_hash ?? null,
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
  if (missing.length > 0) {
    const error = new Error("Rust model_mount MCP workflow plan is incomplete.");
    error.status = 502;
    error.code = "model_mount_mcp_workflow_plan_invalid";
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

function normalizeServerControlBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_server_control_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_SERVER_CONTROL_BACKEND,
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
      backend: normalized.backend,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeRuntimeEngineBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_runtime_engine_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_RUNTIME_ENGINE_BACKEND,
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
      backend: normalized.backend,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeRuntimeSurveyBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_runtime_survey_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_RUNTIME_SURVEY_BACKEND,
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
      backend: normalized.backend,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeTokenizerRequiredBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_tokenizer_required_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_TOKENIZER_REQUIRED_BACKEND,
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

function normalizeRouteControlRequiredBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_route_control_required_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_BACKEND,
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

function normalizeRouteControlBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_route_control_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_ROUTE_CONTROL_BACKEND,
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
      backend: normalized.backend,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeCatalogProviderControlBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_catalog_provider_control_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_BACKEND,
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
      backend: normalized.backend,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeProviderControlBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_provider_control_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_PROVIDER_CONTROL_BACKEND,
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
      backend: normalized.backend,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeCapabilityTokenControlBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_capability_token_control_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_BACKEND,
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
      backend: normalized.backend,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeVaultControlBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_vault_control_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_VAULT_CONTROL_BACKEND,
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
      backend: normalized.backend,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeTokenizerBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_tokenizer_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_TOKENIZER_BACKEND,
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

function normalizeConversationStateBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_conversation_state_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_CONVERSATION_STATE_BACKEND,
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

function normalizeStreamCompletionBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_stream_completion_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_STREAM_COMPLETION_BACKEND,
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

function normalizeReceiptGateBridgeResult(value = {}) {
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
    source: result.source ?? "rust_model_mount_receipt_gate_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_RECEIPT_GATE_BACKEND,
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
      backend: normalized.backend,
      operation_kind: normalized.operation_kind,
    };
    throw error;
  }
  return normalized;
}

function normalizeAcceptedReceiptHeadBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const head = result.head && typeof result.head === "object" ? result.head : {};
  return {
    source: result.source ?? "rust_model_mount_accepted_receipt_head_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_BACKEND,
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

function normalizeAcceptedReceiptTransitionBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const transition = result.transition && typeof result.transition === "object" ? result.transition : {};
  return {
    source: result.source ?? "rust_model_mount_accepted_receipt_transition_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_BACKEND,
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

function normalizeInvocationReceiptBindingBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    source: result.source ?? "rust_model_mount_receipt_binding_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_ADMISSION_BACKEND,
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

function normalizeReadProjectionBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    source: result.source ?? "rust_model_mount_read_projection_command",
    backend: result.backend ?? "rust_model_mount_read_projection",
    projection_kind: result.projection_kind ?? result.projectionKind ?? null,
    projection: result.projection ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : null,
  };
}

function optionalFunction(value) {
  return typeof value === "function" ? value : null;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function arrayOrNull(value) {
  return Array.isArray(value) ? value : null;
}
