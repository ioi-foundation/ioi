import {
  RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
  mcpRegistryForWorkspace,
} from "./mcp-manager.mjs";
import {
  RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";
import { eventStreamIdForThread } from "./runtime-identifiers.mjs";
import { runtimeError } from "./runtime-http-utils.mjs";
import {
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";
import {
  MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  createContextPolicyRunnerFromEnv,
} from "./runtime-context-policy-runner.mjs";

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
  contextPolicyRunner = createContextPolicyRunnerFromEnv(),
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
      const registry = agent.mcpRegistry ?? mcpRegistryForWorkspaceDep(agent.cwd);
      const servers = normalizeArrayDep(registry.servers);
      const catalog = contextPolicyRunner.planMcpManagerCatalogProjection({ servers });
      const validation = contextPolicyRunner.validateMcpServers({ servers });
      return contextPolicyRunner.planMcpManagerStatusProjection({
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
    async mcpStatusWithLiveDiscovery(store, status = {}, agent, request = {}) {
      const threadId = requiredMcpThreadId(request, "MCP live discovery", {
        agent_id: agent?.id ?? null,
      });
      return applyRustMcpControlStateUpdate(store, threadId, "mcp_live_discovery", "mcp_live_discovery", request, {
        agent_id: optionalStringDep(agent?.id) ?? null,
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
    const agent = objectRecordDep(store.agentForThread?.(threadId));
    if (!agent) {
      throw runtimeErrorDep({
        status: 404,
        code: "mcp_control_agent_not_found",
        message: "MCP control requires a canonical agent projection.",
        details: { thread_id: threadId, operation, operation_kind: operationKind },
      });
    }

    const now = optionalStringDep(request.updated_at) ?? optionalStringDep(request.created_at) ?? nowIso();
    const eventStreamId = eventStreamIdForThreadDep(threadId);
    const latestSeq = typeof store.latestRuntimeEventSeq === "function"
      ? Number(store.latestRuntimeEventSeq(eventStreamId) ?? 0)
      : 0;
    const eventId =
      optionalStringDep(request.event_id) ??
      `mcp_control_${safeIdDep(threadId)}_${safeIdDep(controlKind)}_${safeIdDep(now)}`;
    const stateUpdate = planner({
      thread_id: threadId,
      agent,
      control_kind: controlKind,
      event_id: eventId,
      seq: Number.isFinite(latestSeq) ? latestSeq + 1 : 1,
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
    const commit = writer(plannedAgent, plannedOperationKind);
    return {
      ...record,
      commit,
      source: stateUpdate?.source ?? record.source ?? "rust_mcp_control_agent_state_update_command",
      backend: stateUpdate?.backend ?? record.backend ?? "rust_policy",
    };
  }

  function mcpControlStateUpdatePlanner(operation, operationKind, details = {}) {
    if (typeof contextPolicyRunner?.planMcpControlAgentStateUpdate === "function") {
      return contextPolicyRunner.planMcpControlAgentStateUpdate.bind(contextPolicyRunner);
    }
    throwMcpControlRustCoreRequired(operation, operationKind, details);
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
