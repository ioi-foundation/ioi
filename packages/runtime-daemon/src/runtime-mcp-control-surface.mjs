import {
  RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
  mcpRegistryForWorkspace,
  mcpToolsForServers,
  validateMcpServerRecords,
} from "./mcp-manager.mjs";
import {
  mcpPromptKey,
  mcpResourceKey,
} from "./runtime-mcp-helpers.mjs";
import { runtimeError } from "./runtime-http-utils.mjs";
import {
  normalizeArray,
  optionalString,
} from "./runtime-value-helpers.mjs";

export function createRuntimeMcpControlSurface({
  RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION: invocationSchemaVersion = RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION: statusSchemaVersion = RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION: validationSchemaVersion = RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
  mcpPromptKey: mcpPromptKeyDep = mcpPromptKey,
  mcpRegistryForWorkspace: mcpRegistryForWorkspaceDep = mcpRegistryForWorkspace,
  mcpResourceKey: mcpResourceKeyDep = mcpResourceKey,
  mcpToolsForServers: mcpToolsForServersDep = mcpToolsForServers,
  normalizeArray: normalizeArrayDep = normalizeArray,
  optionalString: optionalStringDep = optionalString,
  runtimeError: runtimeErrorDep = runtimeError,
  validateMcpServerRecords: validateMcpServerRecordsDep = validateMcpServerRecords,
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
      const tools = mcpToolsForServersDep(servers);
      const resourceRecords = servers.flatMap((server) =>
        normalizeArrayDep(server.resources).map((resource) => {
          const record = resource && typeof resource === "object" ? resource : { uri: String(resource) };
          return { server_id: server.id, ...record };
        }),
      );
      const promptRecords = servers.flatMap((server) =>
        normalizeArrayDep(server.prompts).map((prompt) => {
          const record = prompt && typeof prompt === "object" ? prompt : { name: String(prompt) };
          return { server_id: server.id, ...record };
        }),
      );
      const resources = resourceRecords.sort((left, right) =>
        mcpResourceKeyDep(left).localeCompare(mcpResourceKeyDep(right)),
      );
      const prompts = promptRecords.sort((left, right) =>
        mcpPromptKeyDep(left).localeCompare(mcpPromptKeyDep(right)),
      );
      const validation = validateMcpServerRecordsDep(servers);
      const enabledServers = servers.filter((server) => server.enabled !== false);
      const enabledTools = mcpToolsForServersDep(enabledServers);
      return {
        schema_version: statusSchemaVersion,
        object: "ioi.runtime_mcp_manager_status",
        status: validation.ok ? "ready" : "blocked",
        server_count: servers.length,
        enabled_server_count: enabledServers.length,
        tool_count: tools.length,
        enabled_tool_count: enabledTools.length,
        resource_count: resources.length,
        prompt_count: prompts.length,
        servers,
        tools,
        resources,
        prompts,
        validation,
      };
    },
    importThreadMcp(_store, threadId, _request = {}) {
      throwMcpControlRustCoreRequired("import_mcp", "thread.mcp_import", {
        thread_id: threadId,
      });
    },
    addThreadMcpServer(_store, threadId, _request = {}) {
      throwMcpControlRustCoreRequired("add_mcp_server", "thread.mcp_add", {
        thread_id: threadId,
      });
    },
    removeThreadMcpServer(_store, threadId, serverId, request = {}) {
      throwMcpControlRustCoreRequired("remove_mcp_server", "thread.mcp_remove", {
        thread_id: threadId,
        server_id: serverId ?? request.server_id ?? null,
      });
    },
    applyThreadMcpServerMutation(_store, {
      threadId,
      mutationKind,
    } = {}) {
      const controlKind = optionalStringDep(mutationKind) ?? "mutation";
      throwMcpControlRustCoreRequired("apply_mcp_server_mutation", `thread.mcp_${controlKind}`, {
        thread_id: threadId ?? null,
        mutation_kind: mutationKind ?? null,
      });
    },
    async mcpStatusWithLiveDiscovery(_store, _status, agent, request = {}) {
      throwMcpControlRustCoreRequired("mcp_live_discovery", "thread.mcp_status", {
        thread_id: request.thread_id ?? null,
        agent_id: agent?.id ?? null,
      });
    },
    setThreadMcpServerEnabled(_store, threadId, serverId, enabled, _request = {}) {
      throwMcpControlRustCoreRequired(
        enabled ? "enable_mcp_server" : "disable_mcp_server",
        enabled ? "thread.mcp_enable" : "thread.mcp_disable",
        {
          thread_id: threadId,
          server_id: serverId ?? null,
          enabled,
        },
      );
    },
    async invokeThreadMcpTool(_store, threadId, toolId, request = {}) {
      throwMcpControlRustCoreRequired("invoke_mcp_tool", "thread.mcp_invoke", {
        thread_id: threadId,
        tool_id: toolId ?? request.tool_id ?? null,
        server_id: request.server_id ?? null,
        tool_name: request.tool_name ?? null,
      });
    },
    async recordThreadMcpStatus(_store, threadId, _request = {}) {
      throwMcpControlRustCoreRequired("record_mcp_status", "thread.mcp_status", {
        thread_id: threadId,
      });
    },
    validateThreadMcp(_store, threadId, _request = {}) {
      throwMcpControlRustCoreRequired("validate_mcp", "thread.mcp_validate", {
        thread_id: threadId,
      });
    },
    appendThreadMcpControlEvent(_store, {
      threadId,
      controlKind,
    } = {}) {
      const control = optionalStringDep(controlKind) ?? "control";
      throwMcpControlRustCoreRequired("append_mcp_control_event", `thread.${control}`, {
        thread_id: threadId ?? null,
        control_kind: controlKind ?? null,
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
        invocation_schema_version: invocationSchemaVersion,
        validation_schema_version: validationSchemaVersion,
        ...details,
      },
    });
  }
}
