import {
  RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
  mcpRegistryForWorkspace,
} from "./mcp-manager.mjs";
import {
  RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";
import { agentIdForThread, eventStreamIdForThread } from "./runtime-identifiers.mjs";
import { runtimeError } from "./runtime-http-utils.mjs";
import {
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";
import {
  MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  MCP_LIVE_BACKEND_EXECUTION_REQUEST_SCHEMA_VERSION,
  MCP_LIVE_RESULT_REPLAY_REQUEST_SCHEMA_VERSION,
  createRuntimeContextPolicyCore,
} from "./runtime-context-policy-core.mjs";

const RUNTIME_RECEIPT_STATE_COMMIT_SCHEMA_VERSION = "ioi.runtime_receipt_state_commit.v1";
const RUNTIME_MCP_LIVE_RESULT_STATE_COMMIT_SCHEMA_VERSION =
  "ioi.runtime_mcp_live_result_state_commit.v1";
const RUNTIME_STATE_STORAGE_BACKEND_REF = "storage://runtime-agentgres/local-json";

export function createRuntimeMcpControlSurface({
  RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION: invocationSchemaVersion = RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION: statusSchemaVersion = RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION: validationSchemaVersion = RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
  mcpRegistryForWorkspace: mcpRegistryForWorkspaceDep = mcpRegistryForWorkspace,
  normalizeArray: normalizeArrayDep = normalizeArray,
  objectRecord: objectRecordDep = objectRecord,
  optionalString: optionalStringDep = optionalString,
  runtimeError: runtimeErrorDep = runtimeError,
  safeId: safeIdDep = safeId,
  contextPolicyCore = createRuntimeContextPolicyCore(),
  agentIdForThread: agentIdForThreadDep = agentIdForThread,
  eventStreamIdForThread: eventStreamIdForThreadDep = eventStreamIdForThread,
  mcpControlStateUpdateSchemaVersion = MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  nowIso = () => new Date().toISOString(),
} = {}) {
  return {
    importMcp(store, input = {}) {
      const threadId = requiredMcpThreadId(input, "MCP import");
      return this.importThreadMcp(store, threadId, input);
    },
    addMcpServer(store, input = {}) {
      const threadId = requiredMcpThreadId(input, "MCP server add");
      return this.addThreadMcpServer(store, threadId, input);
    },
    removeMcpServer(store, serverId, input = {}) {
      const threadId = requiredMcpThreadId(input, "MCP server removal", { server_id: serverId ?? null });
      return this.removeThreadMcpServer(store, threadId, serverId, input);
    },
    setMcpServerEnabled(store, serverId, enabled, request = {}) {
      const threadId = requiredMcpThreadId(request, "MCP server enable/disable controls", {
        server_id: serverId ?? null,
        enabled,
      });
      return this.setThreadMcpServerEnabled(store, threadId, serverId, enabled, request);
    },
    async invokeMcpTool(store, request = {}) {
      const threadId = requiredMcpThreadId(request, "MCP tool invocation", {
        tool_id: request.tool_id ?? null,
      });
      return this.invokeThreadMcpTool(store, threadId, request.tool_id, request);
    },
    mcpStatusForAgent(agent) {
      const registry = agent.mcpRegistry ?? mcpRegistryForWorkspaceDep(agent.cwd, {
        contextPolicyCore,
      });
      const servers = normalizeArrayDep(registry.servers);
      const catalog = contextPolicyCore.planMcpManagerCatalogProjection({ servers });
      const validation = contextPolicyCore.validateMcpServers({ servers });
      return contextPolicyCore.planMcpManagerStatusProjection({
        status_schema_version: statusSchemaVersion,
        validation,
        servers,
        tools: catalog.tools,
        enabled_tools: catalog.enabled_tools,
        resources: catalog.resources,
        prompts: catalog.prompts,
      });
    },
    importThreadMcp(store, threadId, request = {}) {
      return applyRustMcpControlStateUpdate(store, threadId, "mcp_import", "import_mcp", request, {
        servers: normalizeArrayDep(request.servers).map((server) => mcpControlServerPayload(server)),
      });
    },
    addThreadMcpServer(store, threadId, request = {}) {
      return applyRustMcpControlStateUpdate(store, threadId, "mcp_add", "add_mcp_server", request, {
        server: mcpControlServerPayload(request),
      });
    },
    removeThreadMcpServer(store, threadId, serverId, request = {}) {
      return applyRustMcpControlStateUpdate(store, threadId, "mcp_remove", "remove_mcp_server", request, {
        server_id: optionalStringDep(serverId) ?? optionalStringDep(request.server_id) ?? null,
      });
    },
    applyThreadMcpServerMutation(store, {
      thread_id,
      mutation_kind,
      server,
      server_id,
      request = {},
    } = {}) {
      const mutation = optionalStringDep(mutation_kind) ?? "mutation";
      const controlKind = mutation.startsWith("mcp_") ? mutation : `mcp_${mutation}`;
      return applyRustMcpControlStateUpdate(store, thread_id, controlKind, "apply_mcp_server_mutation", request, {
        mutation_kind: mutation,
        server_id: optionalStringDep(server_id) ?? null,
        ...(server ? { server: mcpControlServerPayload(server) } : {}),
      });
    },
    async mcpStatusWithLiveDiscovery(store, status = {}, request = {}) {
      const threadId = requiredMcpThreadId(request, "MCP live discovery");
      return applyRustMcpControlStateUpdate(store, threadId, "mcp_live_discovery", "mcp_live_discovery", request, {
        status: optionalStringDep(status?.status) ?? null,
        live_transport: optionalStringDep(request.live_transport) ?? null,
        execution_mode: optionalStringDep(request.execution_mode) ?? "discovery",
        timeout_ms: finitePositiveNumber(request.timeout_ms),
      });
    },
    setThreadMcpServerEnabled(store, threadId, serverId, enabled, request = {}) {
      return applyRustMcpControlStateUpdate(
        store,
        threadId,
        enabled ? "mcp_enable" : "mcp_disable",
        enabled ? "enable_mcp_server" : "disable_mcp_server",
        request,
        {
          server_id: optionalStringDep(serverId) ?? optionalStringDep(request.server_id) ?? null,
          enabled: Boolean(enabled),
        },
      );
    },
    async invokeThreadMcpTool(store, threadId, toolId, request = {}) {
      const requestedThreadId = optionalStringDep(threadId) ?? optionalStringDep(request.thread_id);
      const requestedToolId = optionalStringDep(toolId) ?? optionalStringDep(request.tool_id);
      return applyRustMcpControlStateUpdate(store, requestedThreadId, "mcp_invoke", "invoke_mcp_tool", request, {
        server_id: optionalStringDep(request.server_id) ?? null,
        tool_id: requestedToolId ?? null,
        tool_name: optionalStringDep(request.tool_name) ?? null,
        live_transport: optionalStringDep(request.live_transport) ?? null,
        execution_mode: optionalStringDep(request.execution_mode) ?? "live",
        timeout_ms: finitePositiveNumber(request.timeout_ms),
      });
    },
    recordThreadMcpStatus(store, threadId, request = {}) {
      return applyRustMcpControlStateUpdate(store, threadId, "mcp_status", "record_mcp_status", request, {
        status: optionalStringDep(request.status) ?? null,
      });
    },
    validateThreadMcp(store, threadId, request = {}) {
      return applyRustMcpControlStateUpdate(store, threadId, "mcp_validate", "validate_mcp", request, {
        validation: objectRecordDep(request.validation) ?? null,
      });
    },
    appendThreadMcpControlEvent(store, {
      thread_id,
      control_kind,
      request = {},
    } = {}) {
      const control = optionalStringDep(control_kind) ?? "mcp_control";
      return applyRustMcpControlStateUpdate(store, thread_id, control, "append_mcp_control_event", request, {
        control_kind: control,
      });
    },
  };

  function requiredMcpThreadId(input, label, details = {}) {
    const threadId = optionalStringDep(input.thread_id);
    if (!threadId) {
      throw runtimeErrorDep({
        status: 400,
        code: "mcp_thread_required",
        message: `${label} requires a thread_id so the Rust daemon core can own MCP control admission.`,
        details,
      });
    }
    return threadId;
  }

  function applyRustMcpControlStateUpdate(
    store,
    requestedThreadId,
    controlKind,
    operation,
    request = {},
    payload = {},
  ) {
    const threadId = optionalStringDep(requestedThreadId);
    if (!threadId) {
      throw runtimeErrorDep({
        status: 400,
        code: "mcp_thread_required",
        message: "MCP control requires a thread_id so the Rust daemon core can own MCP control admission.",
        details: {
          operation,
          operation_kind: `thread.${controlKind}`,
        },
      });
    }
    const operationKind = `thread.${controlKind}`;
    const planner = mcpControlStateUpdatePlanner(operation, operationKind, { thread_id: threadId });
    const writer = mcpControlAgentWriter(store, operation, operationKind, { thread_id: threadId });

    const now = optionalStringDep(request.updated_at) ?? optionalStringDep(request.created_at) ?? nowIso();
    const eventStreamId = eventStreamIdForThreadDep(threadId);
    const eventId =
      optionalStringDep(request.event_id) ??
      `mcp_control_${safeIdDep(threadId)}_${safeIdDep(controlKind)}_${safeIdDep(now)}`;
    const stateUpdate = planner({
      thread_id: threadId,
      agent_id: optionalStringDep(request.agent_id) ?? agentIdForThreadDep(threadId),
      state_dir: optionalStringDep(request.state_dir) ?? optionalStringDep(store?.stateDir) ?? null,
      control_kind: controlKind,
      event_id: eventId,
      created_at: now,
      request: mcpControlRequestPayload(request, payload),
    });
    const record = objectRecordDep(stateUpdate?.record) ?? objectRecordDep(stateUpdate) ?? {};
    const plannedAgent = objectRecordDep(record.agent);
    if (!plannedAgent) {
      throw runtimeErrorDep({
        status: 502,
        code: "mcp_control_rust_agent_update_missing",
        message: "Rust MCP control planner did not return an agent state projection.",
        details: {
          operation,
          operation_kind: record.operation_kind ?? operationKind,
          thread_id: threadId,
        },
      });
    }
    const plannedOperationKind = optionalStringDep(record.operation_kind) ?? operationKind;
    const backendExecutionState = executeRuntimeMcpLiveBackend(
      store,
      record,
      record.receipt ?? null,
      operation,
      plannedOperationKind,
      threadId,
      request,
    );
    const resultRecord = objectRecordDep(backendExecutionState?.record) ?? record;
    const receiptState = persistRuntimeMcpLiveReceipt(store, resultRecord, operation, plannedOperationKind, threadId);
    const resultState = persistRuntimeMcpLiveResult(
      store,
      resultRecord,
      receiptState?.receipt ?? resultRecord.receipt ?? null,
      operation,
      plannedOperationKind,
      threadId,
    );
    const resultReplay = projectRuntimeMcpLiveResult(
      store,
      resultRecord,
      receiptState?.receipt ?? resultRecord.receipt ?? null,
      resultState,
      operation,
      plannedOperationKind,
      threadId,
    );
    const commit = writer(plannedAgent, plannedOperationKind);
    return {
      ...resultRecord,
      commit,
      receipt: receiptState?.receipt ?? record.receipt ?? null,
      result: resultReplay?.result ?? null,
      live_backend_execution: backendExecutionState?.execution ?? null,
      receipt_commit: receiptState?.commit ?? null,
      receipt_state_commit: receiptState?.commit ?? null,
      result_commit: resultState?.commit ?? null,
      result_state_commit: resultState?.commit ?? null,
      result_replay: resultReplay?.projection ?? null,
      result_projection: resultReplay?.projection ?? null,
      result_state_replay: resultReplay?.projection ?? null,
      source: stateUpdate?.source ?? record.source ?? "rust_mcp_control_agent_state_update_api",
      backend: stateUpdate?.backend ?? record.backend ?? "rust_policy",
    };
  }

  function persistRuntimeMcpLiveReceipt(store, record, operation, operationKind, threadId) {
    const control = objectRecordDep(record.control) ?? {};
    if (!isRuntimeMcpLiveExit(control.control_kind ?? operationKind)) return null;
    const receipt = objectRecordDep(record.receipt);
    if (!receipt) {
      throw runtimeErrorDep({
        status: 502,
        code: "mcp_control_live_exit_receipt_required",
        message: "Rust MCP live exit planner did not return the required Rust-authored receipt.",
        details: {
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          boundary: "runtime.mcp_control",
          required_schema_version: "ioi.runtime.mcp-live-exit-receipt.v1",
        },
      });
    }
    assertRuntimeMcpLiveReceiptBound(receipt, control, { operation, operationKind, threadId });
    if (typeof store?.commitRuntimeReceiptState !== "function") {
      throw runtimeErrorDep({
        status: 501,
        code: "mcp_control_live_exit_receipt_state_commit_required",
        message: "Runtime MCP live exits require Rust Agentgres receipt-state commit before public truth returns.",
        details: {
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          boundary: "runtime.mcp_control",
          required_store_api: "commitRuntimeReceiptState",
          required_core: "rust_daemon_core",
          receipt_id: receipt.id ?? null,
        },
      });
    }
    const commit = store.commitRuntimeReceiptState({
      schema_version: RUNTIME_RECEIPT_STATE_COMMIT_SCHEMA_VERSION,
      receipt_id: receipt.id,
      operation_kind: "runtime.mcp_live_exit.receipt.write",
      storage_backend_ref: RUNTIME_STATE_STORAGE_BACKEND_REF,
      receipt,
      receipt_refs: [receipt.id],
    });
    if (!commit?.commit_hash) {
      throw runtimeErrorDep({
        status: 502,
        code: "mcp_control_live_exit_receipt_state_commit_invalid",
        message: "Rust Agentgres runtime MCP live-exit receipt-state commit returned without commit_hash.",
        details: {
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          receipt_id: receipt.id ?? null,
        },
      });
    }
    return { receipt, commit };
  }

  function executeRuntimeMcpLiveBackend(store, record, receipt, operation, operationKind, threadId, request = {}) {
    const control = objectRecordDep(record.control) ?? {};
    if (!isRuntimeMcpLiveExit(control.control_kind ?? operationKind)) return null;
    if (!objectRecordDep(receipt)) {
      throw runtimeErrorDep({
        status: 502,
        code: "mcp_control_live_exit_receipt_required",
        message: "Rust MCP live exit planner did not return the required Rust-authored receipt.",
        details: {
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          boundary: "runtime.mcp_control",
          required_schema_version: "ioi.runtime.mcp-live-exit-receipt.v1",
        },
      });
    }
    const plannedResult = objectRecordDep(record.result);
    if (!plannedResult) {
      throw runtimeErrorDep({
        status: 502,
        code: "mcp_control_live_exit_result_required",
        message: "Rust MCP live exit planner did not return the required Rust-authored live result record.",
        details: {
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          boundary: "runtime.mcp_control",
          required_schema_version: "ioi.runtime.mcp-live-result.v1",
        },
      });
    }
    const resultPayload = objectRecordDep(plannedResult.payload) ?? {};
    const executor = mcpLiveBackendExecutor(operation, operationKind, {
      thread_id: threadId,
      result_id: plannedResult.id ?? null,
    });
    const execution = executor({
      schema_version: MCP_LIVE_BACKEND_EXECUTION_REQUEST_SCHEMA_VERSION,
      state_dir: optionalStringDep(request.state_dir) ?? optionalStringDep(store?.stateDir) ?? null,
      thread_id: threadId,
      agent_id:
        optionalStringDep(record.agent_id) ??
        optionalStringDep((objectRecordDep(record.agent) ?? {}).id) ??
        null,
      control_kind: optionalStringDep(control.control_kind) ?? null,
      event_id: optionalStringDep(control.event_id) ?? null,
      server_id: optionalStringDep(control.server_id) ?? optionalStringDep(request.server_id) ?? null,
      tool_id: optionalStringDep(request.tool_id) ?? null,
      tool_name: optionalStringDep(request.tool_name) ?? null,
      tool_ref:
        optionalStringDep(resultPayload.backend_execution?.tool_ref) ??
        optionalStringDep(request.tool_id) ??
        optionalStringDep(request.tool_name) ??
        null,
      live_transport: optionalStringDep(control.live_transport) ?? optionalStringDep(request.live_transport) ?? null,
      execution_mode: optionalStringDep(control.execution_mode) ?? optionalStringDep(request.execution_mode) ?? null,
      timeout_ms: finitePositiveNumber(control.timeout_ms) ?? finitePositiveNumber(request.timeout_ms) ?? null,
      arguments: objectRecordDep(request.arguments) ?? objectRecordDep(request.input) ?? {},
      workload_spec: objectRecordDep(request.workload_spec) ?? null,
      authority_grant_refs: normalizeArrayDep(control.authority_grant_refs),
      authority_receipt_refs: normalizeArrayDep(control.authority_receipt_refs),
      custody_ref: optionalStringDep(control.custody_ref) ?? optionalStringDep(request.custody_ref) ?? null,
      containment_ref: optionalStringDep(control.containment_ref) ?? optionalStringDep(request.containment_ref) ?? null,
      backend_execution: objectRecordDep(resultPayload.backend_execution) ?? null,
      receipt,
      control,
      planned_result: plannedResult,
    });
    const executedResult =
      objectRecordDep(execution?.result) ??
      objectRecordDep(execution?.record?.result) ??
      objectRecordDep(execution?.live_result) ??
      null;
    const executionRecord = objectRecordDep(execution?.record) ?? objectRecordDep(execution) ?? {};
    const executedControl =
      objectRecordDep(execution?.control) ??
      objectRecordDep(executionRecord.control) ??
      control;
    const executedReceipt =
      objectRecordDep(execution?.receipt) ??
      objectRecordDep(executionRecord.receipt) ??
      receipt;
    assertRuntimeMcpLiveBackendExecuted(execution, executedResult, executedReceipt, executedControl, {
      operation,
      operationKind,
      threadId,
      result_id: plannedResult.id ?? null,
    });
    return {
      execution,
      record: {
        ...record,
        control: executedControl,
        receipt: executedReceipt,
        result: executedResult,
      },
    };
  }

  function persistRuntimeMcpLiveResult(store, record, receipt, operation, operationKind, threadId) {
    const control = objectRecordDep(record.control) ?? {};
    if (!isRuntimeMcpLiveExit(control.control_kind ?? operationKind)) return null;
    const result = objectRecordDep(record.result);
    if (!result) {
      throw runtimeErrorDep({
        status: 502,
        code: "mcp_control_live_exit_result_required",
        message: "Rust MCP live exit planner did not return the required Rust-authored live result record.",
        details: {
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          boundary: "runtime.mcp_control",
          required_schema_version: "ioi.runtime.mcp-live-result.v1",
        },
      });
    }
    assertRuntimeMcpLiveResultBound(result, receipt, control, { operation, operationKind, threadId });
    if (typeof store?.commitRuntimeMcpLiveResultState !== "function") {
      throw runtimeErrorDep({
        status: 501,
        code: "mcp_control_live_exit_result_state_commit_required",
        message: "Runtime MCP live exits require Rust Agentgres live-result state commit before public truth returns.",
        details: {
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          boundary: "runtime.mcp_control",
          required_store_api: "commitRuntimeMcpLiveResultState",
          required_core: "rust_daemon_core",
          result_id: result.id ?? null,
        },
      });
    }
    const commit = store.commitRuntimeMcpLiveResultState({
      schema_version: RUNTIME_MCP_LIVE_RESULT_STATE_COMMIT_SCHEMA_VERSION,
      result_id: result.id,
      operation_kind: "runtime.mcp_live_exit.result.write",
      storage_backend_ref: RUNTIME_STATE_STORAGE_BACKEND_REF,
      result,
      receipt_refs: [receipt?.id].filter(Boolean),
    });
    if (!commit?.commit_hash) {
      throw runtimeErrorDep({
        status: 502,
        code: "mcp_control_live_exit_result_state_commit_invalid",
        message: "Rust Agentgres runtime MCP live-exit result-state commit returned without commit_hash.",
        details: {
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          result_id: result.id ?? null,
        },
      });
    }
    return { result, commit };
  }

  function projectRuntimeMcpLiveResult(store, record, receipt, resultState, operation, operationKind, threadId) {
    const control = objectRecordDep(record.control) ?? {};
    if (!isRuntimeMcpLiveExit(control.control_kind ?? operationKind)) return null;
    const result = objectRecordDep(resultState?.result);
    if (!result) {
      throw runtimeErrorDep({
        status: 502,
        code: "mcp_control_live_exit_result_replay_input_required",
        message: "Runtime MCP live-result replay requires a committed Rust-authored live result.",
        details: {
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          boundary: "runtime.mcp_control",
          required_core: "rust_daemon_core",
        },
      });
    }
    const stateDir = optionalStringDep(store?.stateDir);
    if (!stateDir) {
      throw runtimeErrorDep({
        status: 501,
        code: "mcp_control_live_exit_result_replay_state_dir_required",
        message: "Runtime MCP live-result replay requires the Agentgres state directory before public truth returns.",
        details: {
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          boundary: "runtime.mcp_control",
          required_state_dir: true,
          required_core: "rust_daemon_core",
        },
      });
    }
    const projector = mcpLiveResultReplayProjector(operation, operationKind, {
      thread_id: threadId,
      result_id: result.id ?? null,
    });
    const projection = projector({
      schema_version: MCP_LIVE_RESULT_REPLAY_REQUEST_SCHEMA_VERSION,
      state_dir: stateDir,
      result_id: optionalStringDep(result.id) ?? null,
      receipt_id: optionalStringDep(receipt?.id) ?? optionalStringDep(result.receipt_id) ?? null,
      thread_id: threadId,
      agent_id:
        optionalStringDep(record.agent_id) ??
        optionalStringDep((objectRecordDep(record.agent) ?? {}).id) ??
        null,
      control_kind: optionalStringDep(control.control_kind) ?? null,
    });
    const projectedResult = objectRecordDep(projection?.latest_result);
    if (!projectedResult) {
      throw runtimeErrorDep({
        status: 502,
        code: "mcp_control_live_exit_result_replay_invalid",
        message: "Rust MCP live-result replay projection did not return a bound latest_result.",
        details: {
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          boundary: "runtime.mcp_control",
          result_id: result.id ?? null,
          replay_hash: projection?.replay_hash ?? null,
        },
      });
    }
    assertRuntimeMcpLiveResultBound(projectedResult, receipt, control, {
      operation,
      operationKind,
      threadId,
      replay_hash: projection?.replay_hash ?? null,
    });
    return { result: projectedResult, projection };
  }

  function assertRetiredMcpLiveTransportProofFieldsAbsent(record, path, missing) {
    if (!record || typeof record !== "object" || Array.isArray(record)) return;
    for (const field of [
      "js_backend_execution",
      "js_transport_invocation",
      "command_transport_fallback",
      "binary_bridge_fallback",
      "compatibility_fallback",
    ]) {
      if (Object.hasOwn(record, field)) missing.push(`${path}.${field}_retired`);
    }
  }

  function assertRuntimeMcpLiveReceiptBound(receipt, control, details = {}) {
    const receiptDetails = objectRecordDep(receipt.details) ?? {};
    const evidenceRefs = Array.isArray(receipt.evidence_refs) ? receipt.evidence_refs : [];
    const receiptId = optionalStringDep(receipt.id);
    const contentReceiptId = optionalStringDep(control.content_receipt_id);
    const resultReceiptId = optionalStringDep(control.result_receipt_id);
    const missing = [];
    if (receipt.schema_version !== "ioi.runtime.mcp-live-exit-receipt.v1") missing.push("schema_version");
    if (receipt.kind !== "runtime_mcp_live_exit") missing.push("kind");
    if (!receiptId) missing.push("id");
    if (receiptId !== contentReceiptId) missing.push("content_receipt_id");
    if (receiptId !== resultReceiptId) missing.push("result_receipt_id");
    if (receiptDetails.rust_daemon_core_receipt_author !== "runtime.mcp_control") {
      missing.push("rust_daemon_core_receipt_author");
    }
    for (const ref of [
      "runtime_mcp_live_exit_rust_receipt",
      "agentgres_runtime_mcp_live_receipt_truth_required",
      "runtime_mcp_backend_execution_rust_driver_bound",
      "receipt_state_root_binding_required",
    ]) {
      if (!evidenceRefs.includes(ref)) missing.push(ref);
    }
    if (!receiptDetails.runtime_mcp_agentgres_operation_ref) {
      missing.push("runtime_mcp_agentgres_operation_ref");
    }
    if (!receiptDetails.runtime_mcp_agent_state_root_before) {
      missing.push("runtime_mcp_agent_state_root_before");
    }
    if (!receiptDetails.runtime_mcp_agent_state_root_after) {
      missing.push("runtime_mcp_agent_state_root_after");
    }
    if (!receiptDetails.runtime_mcp_resulting_head) {
      missing.push("runtime_mcp_resulting_head");
    }
    if (receiptDetails.runtime_mcp_agentgres_operation_ref !== control.runtime_mcp_agentgres_operation_ref) {
      missing.push("control_operation_ref_binding");
    }
    if (receiptDetails.runtime_mcp_agent_state_root_after !== control.runtime_mcp_agent_state_root_after) {
      missing.push("control_state_root_after_binding");
    }
    if (receiptDetails.runtime_mcp_resulting_head !== control.runtime_mcp_resulting_head) {
      missing.push("control_resulting_head_binding");
    }
    if (receiptDetails.result_materialized !== true) missing.push("result_materialized_true");
    if (!optionalStringDep(receiptDetails.result_payload_hash)) missing.push("result_payload_hash");
    if (receiptDetails.runtime_mcp_backend_execution_status !== "rust_driver_contract_bound") {
      missing.push("runtime_mcp_backend_execution_status");
    }
    if (receiptDetails.runtime_mcp_backend_owner !== "ioi_drivers::mcp::McpManager") {
      missing.push("runtime_mcp_backend_owner");
    }
    if (receiptDetails.runtime_mcp_backend_transport_owner !== "ioi_drivers::mcp::transport::McpTransport") {
      missing.push("runtime_mcp_backend_transport_owner");
    }
    if (!optionalStringDep(receiptDetails.runtime_mcp_backend_method)) missing.push("runtime_mcp_backend_method");
    if (receiptDetails.runtime_mcp_backend_contract_required !== true) {
      missing.push("runtime_mcp_backend_contract_required");
    }
    assertRetiredMcpLiveTransportProofFieldsAbsent(receiptDetails, "details", missing);
    if (missing.length > 0) {
      throw runtimeErrorDep({
        status: 502,
        code: "mcp_control_live_exit_receipt_binding_invalid",
        message: "Rust MCP live-exit receipt is not bound to the Rust control admission and Agentgres state-root transition.",
        details: {
          ...details,
          receipt_id: receiptId ?? null,
          missing,
        },
      });
    }
  }

  function assertRuntimeMcpLiveResultBound(result, receipt, control, details = {}) {
    const resultDetails = objectRecordDep(result.details) ?? {};
    const payload = objectRecordDep(result.payload);
    const backendExecution = objectRecordDep(payload?.backend_execution);
    const evidenceRefs = Array.isArray(result.evidence_refs) ? result.evidence_refs : [];
    const resultId = optionalStringDep(result.id);
    const receiptId = optionalStringDep(receipt?.id);
    const resultRecordId = optionalStringDep(control.result_record_id);
    const detailsPayloadHash =
      optionalStringDep(resultDetails.payload_hash) ?? optionalStringDep(resultDetails.result_payload_hash);
    const payloadHash =
      optionalStringDep(payload?.payload_hash) ?? optionalStringDep(payload?.result_payload_hash);
    const receiptPayloadHash = optionalStringDep(receipt?.details?.result_payload_hash);
    const missing = [];
    if (result.schema_version !== "ioi.runtime.mcp-live-result.v1") missing.push("schema_version");
    if (result.kind !== "runtime_mcp_live_result") missing.push("kind");
    if (result.status === "admitted_pending_rust_transport") {
      missing.push("admitted_pending_rust_transport_retired");
    }
    if (result.status !== "rust_materialized") missing.push("status.rust_materialized");
    if (!resultId) missing.push("id");
    if (resultId !== resultRecordId) missing.push("result_record_id");
    if (!receiptId) missing.push("receipt_id");
    if (optionalStringDep(result.receipt_id) !== receiptId) missing.push("receipt_binding");
    if (resultDetails.rust_daemon_core_result_author !== "runtime.mcp_control") {
      missing.push("rust_daemon_core_result_author");
    }
    for (const ref of [
      "runtime_mcp_live_result_rust_projection",
      "agentgres_runtime_mcp_live_result_truth_required",
      "runtime_mcp_live_result_payload_rust_materialized",
      "runtime_mcp_no_js_transport_result",
      "runtime_mcp_backend_execution_rust_driver_bound",
      "runtime_mcp_live_backend_rust_driver_executed",
      "receipt_state_root_binding_required",
    ]) {
      if (!evidenceRefs.includes(ref)) missing.push(ref);
    }
    if (evidenceRefs.includes("runtime_mcp_transport_backend_pending")) {
      missing.push("runtime_mcp_transport_backend_pending_retired");
    }
    if (resultDetails.runtime_mcp_agentgres_operation_ref !== control.runtime_mcp_agentgres_operation_ref) {
      missing.push("control_operation_ref_binding");
    }
    if (resultDetails.runtime_mcp_agent_state_root_after !== control.runtime_mcp_agent_state_root_after) {
      missing.push("control_state_root_after_binding");
    }
    if (resultDetails.runtime_mcp_resulting_head !== control.runtime_mcp_resulting_head) {
      missing.push("control_resulting_head_binding");
    }
    if (resultDetails.result_materialized !== true) missing.push("result_materialized_true");
    if (resultDetails.backend_materialization_status !== "rust_driver_contract_bound") {
      missing.push("backend_materialization_status");
    }
    if (resultDetails.runtime_mcp_backend_execution_status !== "rust_driver_contract_bound") {
      missing.push("runtime_mcp_backend_execution_status");
    }
    if (resultDetails.runtime_mcp_backend_owner !== "ioi_drivers::mcp::McpManager") {
      missing.push("runtime_mcp_backend_owner");
    }
    if (resultDetails.runtime_mcp_backend_transport_owner !== "ioi_drivers::mcp::transport::McpTransport") {
      missing.push("runtime_mcp_backend_transport_owner");
    }
    if (!optionalStringDep(resultDetails.runtime_mcp_backend_method)) missing.push("runtime_mcp_backend_method");
    if (resultDetails.runtime_mcp_backend_contract_required !== true) {
      missing.push("runtime_mcp_backend_contract_required");
    }
    if (resultDetails.runtime_mcp_live_backend_execution_status !== "rust_driver_executed") {
      missing.push("runtime_mcp_live_backend_execution_status");
    }
    if (resultDetails.runtime_mcp_live_backend_execution_required !== true) {
      missing.push("runtime_mcp_live_backend_execution_required");
    }
    if (!backendExecution) missing.push("payload.backend_execution");
    if (backendExecution?.schema_version !== "ioi.runtime.mcp-backend-execution.v1") {
      missing.push("payload.backend_execution.schema_version");
    }
    if (backendExecution?.status !== "rust_driver_contract_bound") {
      missing.push("payload.backend_execution.status");
    }
    if (backendExecution?.owner !== "ioi_drivers::mcp::McpManager") {
      missing.push("payload.backend_execution.owner");
    }
    if (backendExecution?.transport_owner !== "ioi_drivers::mcp::transport::McpTransport") {
      missing.push("payload.backend_execution.transport_owner");
    }
    if (!optionalStringDep(backendExecution?.method)) missing.push("payload.backend_execution.method");
    if (!payload) missing.push("payload");
    if (!detailsPayloadHash) missing.push("payload_hash");
    if (!payloadHash) missing.push("payload.payload_hash");
    if (detailsPayloadHash && payloadHash && detailsPayloadHash !== payloadHash) {
      missing.push("payload_hash_binding");
    }
    if (receiptPayloadHash && detailsPayloadHash && receiptPayloadHash !== detailsPayloadHash) {
      missing.push("receipt_result_payload_hash_binding");
    }
    assertRetiredMcpLiveTransportProofFieldsAbsent(resultDetails, "details", missing);
    assertRetiredMcpLiveTransportProofFieldsAbsent(backendExecution, "payload.backend_execution", missing);
    if (missing.length > 0) {
      throw runtimeErrorDep({
        status: 502,
        code: "mcp_control_live_exit_result_binding_invalid",
        message: "Rust MCP live-exit result record is not bound to the Rust control admission, receipt, and Agentgres state-root transition.",
        details: {
          ...details,
          result_id: resultId ?? null,
          receipt_id: receiptId ?? null,
          missing,
        },
      });
    }
  }

  function assertRuntimeMcpLiveBackendExecuted(execution, result, receipt, control, details = {}) {
    const record = objectRecordDep(execution?.record) ?? objectRecordDep(execution) ?? {};
    const backendExecution =
      objectRecordDep(record.backend_execution) ??
      objectRecordDep(execution?.backend_execution) ??
      null;
    const evidenceRefs = Array.isArray(record.evidence_refs) ? record.evidence_refs : [];
    const resultDetails = objectRecordDep(result?.details) ?? {};
    const resultPayload = objectRecordDep(result?.payload) ?? {};
    const driverResultHash =
      optionalStringDep(record.driver_result_hash) ??
      optionalStringDep(backendExecution?.driver_result_hash) ??
      null;
    const missing = [];
    if (!record) missing.push("execution");
    if (record.source !== "rust_mcp_live_backend_execution_api") missing.push("source");
    if (record.status !== "rust_driver_executed") missing.push("status.rust_driver_executed");
    if (!evidenceRefs.includes("runtime_mcp_live_backend_rust_driver_executed")) {
      missing.push("runtime_mcp_live_backend_rust_driver_executed");
    }
    if (!backendExecution) missing.push("backend_execution");
    if (backendExecution?.schema_version !== "ioi.runtime.mcp-backend-execution.v1") {
      missing.push("backend_execution.schema_version");
    }
    if (backendExecution?.status !== "rust_driver_executed") {
      missing.push("backend_execution.status");
    }
    if (backendExecution?.owner !== "ioi_drivers::mcp::McpManager") {
      missing.push("backend_execution.owner");
    }
    if (backendExecution?.transport_owner !== "ioi_drivers::mcp::transport::McpTransport") {
      missing.push("backend_execution.transport_owner");
    }
    if (!optionalStringDep(backendExecution?.method)) missing.push("backend_execution.method");
    assertRetiredMcpLiveTransportProofFieldsAbsent(backendExecution, "backend_execution", missing);
    if (!result) missing.push("result");
    if (optionalStringDep(result?.id) !== optionalStringDep(control.result_record_id)) {
      missing.push("result_record_id");
    }
    if (optionalStringDep(result?.receipt_id) !== optionalStringDep(receipt?.id)) {
      missing.push("receipt_binding");
    }
    if (resultDetails.runtime_mcp_live_backend_execution_status !== "rust_driver_executed") {
      missing.push("result.runtime_mcp_live_backend_execution_status");
    }
    if (resultDetails.runtime_mcp_live_backend_execution_required !== true) {
      missing.push("result.runtime_mcp_live_backend_execution_required");
    }
    if (!driverResultHash) missing.push("driver_result_hash");
    if (
      driverResultHash &&
      resultDetails.runtime_mcp_live_backend_driver_result_hash !== driverResultHash
    ) {
      missing.push("result.runtime_mcp_live_backend_driver_result_hash");
    }
    if (driverResultHash && resultPayload.driver_result_hash !== driverResultHash) {
      missing.push("result.payload.driver_result_hash");
    }
    if (
      driverResultHash &&
      resultPayload.runtime_mcp_live_backend_driver_result_hash !== driverResultHash
    ) {
      missing.push("result.payload.runtime_mcp_live_backend_driver_result_hash");
    }
    assertRetiredMcpLiveTransportProofFieldsAbsent(resultDetails, "result.details", missing);
    if (missing.length > 0) {
      throw runtimeErrorDep({
        status: 502,
        code: "mcp_control_live_backend_execution_invalid",
        message: "Rust MCP live backend execution did not return a driver-executed result bound to the live-exit receipt.",
        details: {
          ...details,
          result_id: optionalStringDep(result?.id) ?? null,
          receipt_id: optionalStringDep(receipt?.id) ?? null,
          missing,
        },
      });
    }
  }

  function isRuntimeMcpLiveExit(controlKind) {
    return controlKind === "mcp_invoke" || controlKind === "mcp_live_discovery";
  }

  function mcpControlStateUpdatePlanner(operation, operationKind, details = {}) {
    if (typeof contextPolicyCore?.planMcpControlAgentStateUpdate === "function") {
      return contextPolicyCore.planMcpControlAgentStateUpdate.bind(contextPolicyCore);
    }
    throwMcpControlRustCoreRequired(operation, operationKind, details);
  }

  function mcpLiveResultReplayProjector(operation, operationKind, details = {}) {
    if (typeof contextPolicyCore?.projectMcpLiveResultReplay === "function") {
      return contextPolicyCore.projectMcpLiveResultReplay.bind(contextPolicyCore);
    }
    throw runtimeErrorDep({
      status: 501,
      code: "mcp_control_live_exit_result_replay_required",
      message: "Runtime MCP live exits require Rust daemon-core live-result replay before public truth returns.",
      details: {
        boundary: "runtime.mcp_control",
        operation,
        operation_kind: operationKind,
        required_core: "rust_daemon_core",
        required_policy_api: "projectMcpLiveResultReplay",
        schema_version: MCP_LIVE_RESULT_REPLAY_REQUEST_SCHEMA_VERSION,
        evidence_refs: [
          "runtime_mcp_live_result_rust_projection",
          "agentgres_runtime_mcp_live_result_truth_required",
        ],
        ...details,
      },
    });
  }

  function mcpLiveBackendExecutor(operation, operationKind, details = {}) {
    if (typeof contextPolicyCore?.executeRuntimeMcpLiveBackend === "function") {
      return contextPolicyCore.executeRuntimeMcpLiveBackend.bind(contextPolicyCore);
    }
    throw runtimeErrorDep({
      status: 501,
      code: "mcp_control_live_backend_execution_required",
      message: "Runtime MCP live exits require Rust daemon-core live backend execution before result-state commit.",
      details: {
        boundary: "runtime.mcp_control",
        operation,
        operation_kind: operationKind,
        required_core: "rust_daemon_core",
        required_policy_api: "executeRuntimeMcpLiveBackend",
        schema_version: MCP_LIVE_BACKEND_EXECUTION_REQUEST_SCHEMA_VERSION,
        evidence_refs: [
          "runtime_mcp_backend_execution_rust_driver_bound",
          "runtime_mcp_live_backend_rust_driver_executed",
        ],
        ...details,
      },
    });
  }

  function mcpControlAgentWriter(store, operation, operationKind, details = {}) {
    if (typeof store?.writeAgent === "function") {
      return store.writeAgent.bind(store);
    }
    throw runtimeErrorDep({
      status: 501,
      code: "mcp_control_agentgres_commit_required",
      message: "Runtime MCP control requires Agentgres-backed agent-state commit after Rust planning.",
      details: {
        boundary: "runtime.mcp_control",
        operation,
        operation_kind: operationKind,
        required_core: "rust_daemon_core",
        required_store_api: "writeAgent",
        schema_version: mcpControlStateUpdateSchemaVersion,
        evidence_refs: [
          "runtime_mcp_control_rust_owned",
          "agentgres_runtime_agent_state_truth_required",
        ],
        ...details,
      },
    });
  }

  function mcpControlRequestPayload(request = {}, overrides = {}) {
    const source = objectRecordDep(request) ?? {};
    const payload = {};
    for (const key of [
      "server_id",
      "tool_id",
      "tool_name",
      "workflow_node_id",
      "workflow_graph_id",
      "turn_id",
      "idempotency_key",
      "mutation_kind",
      "control_kind",
      "status",
      "validation",
      "live_transport",
      "execution_mode",
      "timeout_ms",
      "authority_grant_refs",
      "authority_receipt_refs",
      "custody_ref",
      "containment_ref",
      "source",
      "reason",
      "enabled",
    ]) {
      if (Object.hasOwn(source, key)) payload[key] = source[key];
    }
    if (objectRecordDep(source.server)) {
      payload.server = mcpControlServerPayload(source.server);
    }
    if (Array.isArray(source.servers)) {
      payload.servers = source.servers.map((server) => mcpControlServerPayload(server));
    }
    for (const [key, value] of Object.entries(overrides)) {
      if (value !== undefined) payload[key] = value;
    }
    return payload;
  }

  function mcpControlServerPayload(input = {}) {
    const source = objectRecordDep(input?.server) ?? objectRecordDep(input) ?? {};
    const server = {};
    for (const key of [
      "id",
      "label",
      "name",
      "enabled",
      "status",
      "transport",
      "command",
      "args",
      "env",
      "headers",
      "server_url",
      "url",
      "endpoint",
      "allowed_tools",
      "tools",
      "resources",
      "prompts",
      "source",
      "source_path",
      "source_scope",
      "config_compatibility",
      "workspace_root",
      "containment",
      "secret_refs",
      "vault_boundary",
    ]) {
      if (Object.hasOwn(source, key)) server[key] = source[key];
    }
    return server;
  }

  function throwMcpControlRustCoreRequired(operation, operationKind, details = {}) {
    throw runtimeErrorDep({
      status: 501,
      code: "mcp_control_rust_core_required",
      message:
        "Runtime MCP control mutations and live transport exits are retired from the JS facade; route this operation through the Rust daemon core MCP control API.",
      details: {
        boundary: "runtime.mcp_control",
        operation,
        operation_kind: operationKind,
        required_core: "rust_daemon_core",
        migration_transport_only: false,
        schema_version: mcpControlStateUpdateSchemaVersion,
        invocation_schema_version: invocationSchemaVersion,
        validation_schema_version: validationSchemaVersion,
        ...details,
      },
    });
  }

  function finitePositiveNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) && number > 0 ? number : undefined;
  }
}
