import { spawnSync } from "node:child_process";

export const MODEL_MOUNT_ADMISSION_COMMAND_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND";
export const MODEL_MOUNT_ADMISSION_COMMAND_ARGS_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS";
export const MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUST_MODEL_MOUNT_ADMISSION_BACKEND = "rust_model_mount_live";
export const RUST_MODEL_MOUNT_FIXTURE_BACKEND = "rust_model_mount_fixture";
export const RUST_MODEL_MOUNT_FIXTURE_INVENTORY_BACKEND = "rust_model_mount_fixture_inventory";
export const RUST_MODEL_MOUNT_FIXTURE_LIFECYCLE_BACKEND = "rust_model_mount_fixture_lifecycle";
export const RUST_MODEL_MOUNT_BACKEND_PROCESS_BACKEND = "rust_model_mount_backend_process";
export const RUST_MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_BACKEND = "rust_model_mount_accepted_receipt_head";
export const RUST_MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_BACKEND = "rust_model_mount_accepted_receipt_transition";
export const RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND = "rust_model_mount_instance_lifecycle";
export const RUST_MODEL_MOUNT_NATIVE_LOCAL_BACKEND = "rust_model_mount_native_local";
export const RUST_MODEL_MOUNT_NATIVE_LOCAL_INVENTORY_BACKEND = "rust_model_mount_native_local_inventory";
export const RUST_MODEL_MOUNT_NATIVE_LOCAL_LIFECYCLE_BACKEND = "rust_model_mount_native_local_lifecycle";

export function createModelMountAdmissionRunnerFromEnv(env = process.env, options = {}) {
  return new RustModelMountAdmissionRunner({
    command: options.command ?? env[MODEL_MOUNT_ADMISSION_COMMAND_ENV] ?? null,
    args: options.args ?? parseCommandArgs(env[MODEL_MOUNT_ADMISSION_COMMAND_ARGS_ENV]),
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export class RustModelMountAdmissionRunner {
  constructor(options = {}) {
    this.command = optionalString(options.command);
    this.args = normalizeArgs(options.args);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
  }

  admitRouteDecision(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "admit_model_mount_route_decision",
      backend: RUST_MODEL_MOUNT_ADMISSION_BACKEND,
      request,
    };
    return normalizeRouteDecisionBridgeResult(this.invokeBridge(bridgeRequest));
  }

  admitInvocation(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "admit_model_mount_invocation",
      backend: RUST_MODEL_MOUNT_ADMISSION_BACKEND,
      request,
    };
    return normalizeInvocationBridgeResult(this.invokeBridge(bridgeRequest));
  }

  admitProviderExecution(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "admit_model_mount_provider_execution",
      backend: RUST_MODEL_MOUNT_ADMISSION_BACKEND,
      request,
    };
    return normalizeProviderExecutionBridgeResult(this.invokeBridge(bridgeRequest));
  }

  executeProviderInvocation(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "execute_model_mount_provider_invocation",
      backend: request?.execution_backend ?? RUST_MODEL_MOUNT_FIXTURE_BACKEND,
      request,
    };
    return normalizeProviderInvocationBridgeResult(this.invokeBridge(bridgeRequest));
  }

  executeProviderStreamInvocation(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "execute_model_mount_provider_stream_invocation",
      backend: request?.execution_backend ?? RUST_MODEL_MOUNT_NATIVE_LOCAL_BACKEND,
      request,
    };
    return normalizeProviderStreamInvocationBridgeResult(this.invokeBridge(bridgeRequest));
  }

  planProviderLifecycle(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_provider_lifecycle",
      backend: request?.execution_backend ?? RUST_MODEL_MOUNT_NATIVE_LOCAL_LIFECYCLE_BACKEND,
      request,
    };
    return normalizeProviderLifecycleBridgeResult(this.invokeBridge(bridgeRequest));
  }

  planProviderInventory(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_provider_inventory",
      backend: request?.execution_backend ?? RUST_MODEL_MOUNT_NATIVE_LOCAL_INVENTORY_BACKEND,
      request,
    };
    return normalizeProviderInventoryBridgeResult(this.invokeBridge(bridgeRequest));
  }

  planInstanceLifecycle(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_instance_lifecycle",
      backend: request?.execution_backend ?? RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND,
      request,
    };
    return normalizeInstanceLifecycleBridgeResult(this.invokeBridge(bridgeRequest));
  }

  admitProviderResult(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "admit_model_mount_provider_result",
      backend: RUST_MODEL_MOUNT_ADMISSION_BACKEND,
      request,
    };
    return normalizeProviderResultBridgeResult(this.invokeBridge(bridgeRequest));
  }

  planBackendProcess(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_backend_process",
      backend: RUST_MODEL_MOUNT_BACKEND_PROCESS_BACKEND,
      request,
    };
    return normalizeBackendProcessPlanBridgeResult(this.invokeBridge(bridgeRequest));
  }

  planAcceptedReceiptHead(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_accepted_receipt_head",
      backend: RUST_MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_BACKEND,
      request,
    };
    return normalizeAcceptedReceiptHeadBridgeResult(this.invokeBridge(bridgeRequest));
  }

  planAcceptedReceiptTransition(request) {
    const bridgeRequest = {
      schema_version: MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
      operation: "plan_model_mount_accepted_receipt_transition",
      backend: RUST_MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_BACKEND,
      request,
    };
    return normalizeAcceptedReceiptTransitionBridgeResult(this.invokeBridge(bridgeRequest));
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
    return normalizeInvocationReceiptBindingBridgeResult(this.invokeBridge(bridgeRequest));
  }

  invokeBridge(request) {
    if (this.mockResult) {
      const value = typeof this.mockResult === "function" ? this.mockResult(request) : this.mockResult;
      return {
        source: "rust_model_mount_mock",
        backend: RUST_MODEL_MOUNT_ADMISSION_BACKEND,
        ...value,
      };
    }
    if (!this.command) {
      throw new ModelMountAdmissionRunnerError(
        "Model mount admission requires IOI_RUNTIME_DAEMON_CORE_COMMAND for Rust daemon-core model_mount admission.",
        "model_mount_admission_bridge_unconfigured",
        {
          env: MODEL_MOUNT_ADMISSION_COMMAND_ENV,
          argsEnv: MODEL_MOUNT_ADMISSION_COMMAND_ARGS_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, this.args, {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new ModelMountAdmissionRunnerError(
        "Failed to spawn Rust model_mount admission bridge command.",
        "model_mount_admission_bridge_spawn_failed",
        { error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new ModelMountAdmissionRunnerError(
        "Rust model_mount admission bridge command failed.",
        "model_mount_admission_bridge_failed",
        {
          status: output.status,
          stderr: String(output.stderr ?? "").slice(0, 4096),
        },
      );
    }
    let parsed = null;
    try {
      parsed = JSON.parse(String(output.stdout ?? ""));
    } catch (error) {
      throw new ModelMountAdmissionRunnerError(
        "Rust model_mount admission bridge command returned invalid JSON.",
        "model_mount_admission_bridge_invalid_json",
        { error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new ModelMountAdmissionRunnerError(
        parsed.error?.message ?? "Rust model_mount core rejected the admission request.",
        parsed.error?.code ?? "model_mount_admission_bridge_rejected",
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
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
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : record.receipt_refs ?? [],
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
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
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : record.receipt_refs ?? [],
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
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
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : record.receipt_refs ?? [],
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
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
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : record.evidence_refs ?? [],
    backendEvidenceRefs: Array.isArray(result.evidence_refs) ? result.evidence_refs : record.evidence_refs ?? [],
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
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : record.evidence_refs ?? [],
    backendEvidenceRefs: Array.isArray(result.evidence_refs) ? result.evidence_refs : record.evidence_refs ?? [],
  };
}

function normalizeProviderLifecycleBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : {};
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
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : record.evidence_refs ?? [],
    backendEvidenceRefs: Array.isArray(result.evidence_refs) ? result.evidence_refs : record.evidence_refs ?? [],
  };
}

function normalizeProviderInventoryBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : {};
  const itemRefs = Array.isArray(result.item_refs)
      ? result.item_refs
      : Array.isArray(record.item_refs)
        ? record.item_refs
        : [];
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
    itemCount: result.item_count ?? record.item_count ?? itemRefs.length,
    inventory_hash: result.inventory_hash ?? record.inventory_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : record.evidence_refs ?? [],
    backendEvidenceRefs: Array.isArray(result.evidence_refs) ? result.evidence_refs : record.evidence_refs ?? [],
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
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : record.evidence_refs ?? [],
    backendEvidenceRefs: Array.isArray(result.evidence_refs) ? result.evidence_refs : record.evidence_refs ?? [],
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
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : record.receipt_refs ?? [],
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : record.evidence_refs ?? [],
  };
}

function normalizeBackendProcessPlanBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = result.result && typeof result.result === "object" ? result.result : {};
  return {
    source: result.source ?? "rust_model_mount_backend_process_command",
    backend: result.backend ?? RUST_MODEL_MOUNT_BACKEND_PROCESS_BACKEND,
    result: record,
    supports_supervision: Boolean(result.supports_supervision ?? record.supports_supervision),
    supervisor_kind: result.supervisor_kind ?? record.supervisor_kind ?? null,
    public_args: Array.isArray(result.public_args) ? result.public_args : record.public_args ?? [],
    spawn_args: Array.isArray(result.spawn_args) ? result.spawn_args : record.spawn_args ?? [],
    spawn_required: Boolean(result.spawn_required ?? record.spawn_required),
    spawn_status: result.spawn_status ?? record.spawn_status ?? null,
    plan_hash: result.plan_hash ?? record.plan_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : record.evidence_refs ?? [],
  };
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
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : head.evidence_refs ?? [],
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
    expected_heads: Array.isArray(result.expected_heads) ? result.expected_heads : transition.expected_heads ?? [],
    state_root_before: result.state_root_before ?? transition.state_root_before ?? null,
    state_root_after: result.state_root_after ?? transition.state_root_after ?? null,
    resulting_head: result.resulting_head ?? transition.resulting_head ?? null,
    projection_watermark: result.projection_watermark ?? transition.projection_watermark ?? null,
    transition_hash: result.transition_hash ?? transition.transition_hash ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : transition.evidence_refs ?? [],
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
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : [],
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
  };
}

function parseCommandArgs(value) {
  if (!value) return [];
  if (Array.isArray(value)) return normalizeArgs(value);
  return String(value)
    .split(/\s+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeArgs(value) {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => String(entry)).filter((entry) => entry.length > 0);
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}
