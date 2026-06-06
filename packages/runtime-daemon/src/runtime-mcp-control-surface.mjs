import {
  RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
  discoverMcpHttpCatalog,
  discoverMcpStdioCatalog,
  invokeMcpHttpTool,
  invokeMcpStdioTool,
  mcpRegistryForWorkspace,
  mcpToolsForServers,
  validateMcpServerRecords,
} from "./mcp-manager.mjs";
import {
  fixtureProfileForAgent,
  eventStreamIdForThread,
} from "./runtime-identifiers.mjs";
import { createContextPolicyRunnerFromEnv } from "./runtime-context-policy-runner.mjs";
import {
  mcpCatalogExposureForStatus,
  mcpCatalogFullRequested,
  mcpCatalogPreviewLimit,
  mcpLiveExecutionModeForServer,
  mcpPromptKey,
  mcpRegistryWithServers,
  mcpResourceKey,
  mcpServerRecordFromAddRequest,
  mcpServerRecordsFromMutationInput,
  mcpToolKey,
  mcpTransportEvidenceRef,
  mcpTransportSummary,
  resolveMcpServerRecord,
  resolveMcpToolRecord,
} from "./runtime-mcp-helpers.mjs";
import { notFound, runtimeError } from "./runtime-http-utils.mjs";
import {
  doctorHash,
  normalizeArray,
  operatorControlSource,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

export function createRuntimeMcpControlSurface({
  RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION: invocationSchemaVersion = RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION: statusSchemaVersion = RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION: validationSchemaVersion = RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
  contextPolicyRunner: contextPolicyRunnerDep = createContextPolicyRunnerFromEnv(),
  discoverMcpHttpCatalog: discoverMcpHttpCatalogDep = discoverMcpHttpCatalog,
  discoverMcpStdioCatalog: discoverMcpStdioCatalogDep = discoverMcpStdioCatalog,
  doctorHash: doctorHashDep = doctorHash,
  eventStreamIdForThread: eventStreamIdForThreadDep = eventStreamIdForThread,
  fixtureProfileForAgent: fixtureProfileForAgentDep = fixtureProfileForAgent,
  invokeMcpHttpTool: invokeMcpHttpToolDep = invokeMcpHttpTool,
  invokeMcpStdioTool: invokeMcpStdioToolDep = invokeMcpStdioTool,
  mcpCatalogExposureForStatus: mcpCatalogExposureForStatusDep = mcpCatalogExposureForStatus,
  mcpCatalogFullRequested: mcpCatalogFullRequestedDep = mcpCatalogFullRequested,
  mcpCatalogPreviewLimit: mcpCatalogPreviewLimitDep = mcpCatalogPreviewLimit,
  mcpLiveExecutionModeForServer: mcpLiveExecutionModeForServerDep = mcpLiveExecutionModeForServer,
  mcpPromptKey: mcpPromptKeyDep = mcpPromptKey,
  mcpRegistryForWorkspace: mcpRegistryForWorkspaceDep = mcpRegistryForWorkspace,
  mcpRegistryWithServers: mcpRegistryWithServersDep = mcpRegistryWithServers,
  mcpResourceKey: mcpResourceKeyDep = mcpResourceKey,
  mcpServerRecordFromAddRequest: mcpServerRecordFromAddRequestDep = mcpServerRecordFromAddRequest,
  mcpServerRecordsFromMutationInput: mcpServerRecordsFromMutationInputDep = mcpServerRecordsFromMutationInput,
  mcpToolKey: mcpToolKeyDep = mcpToolKey,
  mcpToolsForServers: mcpToolsForServersDep = mcpToolsForServers,
  mcpTransportEvidenceRef: mcpTransportEvidenceRefDep = mcpTransportEvidenceRef,
  mcpTransportSummary: mcpTransportSummaryDep = mcpTransportSummary,
  normalizeArray: normalizeArrayDep = normalizeArray,
  notFound: notFoundDep = notFound,
  operatorControlSource: operatorControlSourceDep = operatorControlSource,
  optionalString: optionalStringDep = optionalString,
  resolveMcpServerRecord: resolveMcpServerRecordDep = resolveMcpServerRecord,
  resolveMcpToolRecord: resolveMcpToolRecordDep = resolveMcpToolRecord,
  runtimeError: runtimeErrorDep = runtimeError,
  safeId: safeIdDep = safeId,
  uniqueStrings: uniqueStringsDep = uniqueStrings,
  validateMcpServerRecords: validateMcpServerRecordsDep = validateMcpServerRecords,
} = {}) {
  return {
    importMcp(store, input = {}) {
      const threadId = optionalStringDep(input.thread_id);
      if (!threadId) {
        throw runtimeErrorDep({
          status: 400,
          code: "mcp_thread_required",
          message: "MCP import requires a thread_id so the daemon can update the active runtime registry.",
        });
      }
      return this.importThreadMcp(store, threadId, input);
    },
    addMcpServer(store, input = {}) {
      const threadId = optionalStringDep(input.thread_id);
      if (!threadId) {
        throw runtimeErrorDep({
          status: 400,
          code: "mcp_thread_required",
          message: "MCP server add requires a thread_id so the daemon can update the active runtime registry.",
        });
      }
      return this.addThreadMcpServer(store, threadId, input);
    },
    mcpStatusForAgent(agent) {
      const registry = agent.mcpRegistry ?? mcpRegistryForWorkspaceDep(agent.cwd);
      const servers = normalizeArrayDep(registry.servers);
      const tools = mcpToolsForServersDep(servers);
      const resourceRecords = servers.flatMap((server) =>
        normalizeArrayDep(server.resources).map((resource) => {
          const record = resource && typeof resource === "object" ? resource : { uri: String(resource) };
          return { server_id: server.id, serverId: server.id, ...record };
        }),
      );
      const promptRecords = servers.flatMap((server) =>
        normalizeArrayDep(server.prompts).map((prompt) => {
          const record = prompt && typeof prompt === "object" ? prompt : { name: String(prompt) };
          return { server_id: server.id, serverId: server.id, ...record };
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
        schemaVersion: statusSchemaVersion,
        object: "ioi.runtime_mcp_manager_status",
        status: validation.ok ? "ready" : "blocked",
        server_count: servers.length,
        serverCount: servers.length,
        enabled_server_count: enabledServers.length,
        enabledServerCount: enabledServers.length,
        tool_count: tools.length,
        toolCount: tools.length,
        enabled_tool_count: enabledTools.length,
        enabledToolCount: enabledTools.length,
        resource_count: resources.length,
        resourceCount: resources.length,
        prompt_count: prompts.length,
        promptCount: prompts.length,
        servers,
        tools,
        resources,
        prompts,
        validation,
      };
    },
    removeMcpServer(store, serverId, input = {}) {
      const threadId = optionalStringDep(input.thread_id);
      if (!threadId) {
        throw runtimeErrorDep({
          status: 400,
          code: "mcp_thread_required",
          message: "MCP server removal requires a thread_id so the daemon can update the active runtime registry.",
          details: { serverId },
        });
      }
      return this.removeThreadMcpServer(store, threadId, serverId, input);
    },
    importThreadMcp(store, threadId, request = {}) {
      const agent = store.agentForThread(threadId);
      const importedServers = mcpServerRecordsFromMutationInputDep(
        request,
        agent.cwd,
        "runtime_mcp_import",
      );
      return this.applyThreadMcpServerMutation(store, {
        threadId,
        agent,
        request,
        mutationKind: "import",
        sourceEventKind: "OperatorControl.McpImport",
        eventKind: "mcp.servers_imported",
        workflowNodeId: "runtime.mcp-manager.import",
        serversToUpsert: importedServers,
      });
    },
    addThreadMcpServer(store, threadId, request = {}) {
      const agent = store.agentForThread(threadId);
      const server = mcpServerRecordFromAddRequestDep(request, agent.cwd);
      return this.applyThreadMcpServerMutation(store, {
        threadId,
        agent,
        request,
        mutationKind: "add",
        sourceEventKind: "OperatorControl.McpAdd",
        eventKind: "mcp.server_added",
        workflowNodeId:
          optionalStringDep(request.workflow_node_id) ??
          `runtime.mcp-server.${safeIdDep(server.id)}`,
        serversToUpsert: [server],
      });
    },
    removeThreadMcpServer(store, threadId, serverId, request = {}) {
      const agent = store.agentForThread(threadId);
      const registry = agent.mcpRegistry ?? mcpRegistryForWorkspaceDep(agent.cwd, { homeDir: store.homeDir });
      const server = resolveMcpServerRecordDep(registry.servers, serverId ?? request.server_id);
      if (!server) throw notFoundDep(`MCP server not found: ${serverId}`, { threadId, serverId });
      const remainingServers = normalizeArrayDep(registry.servers).filter((candidate) => candidate.id !== server.id);
      const updatedRegistry = mcpRegistryWithServersDep(registry, remainingServers);
      const updatedAgent = {
        ...agent,
        mcpRegistry: updatedRegistry,
        updatedAt: new Date().toISOString(),
      };
      const status = this.mcpStatusForAgent(updatedAgent);
      return this.appendThreadMcpControlEvent(store, {
        threadId,
        agent: updatedAgent,
        request,
        controlKind: "mcp_remove",
        sourceEventKind: "OperatorControl.McpRemove",
        eventKind: "mcp.server_removed",
        componentKind: "mcp_provider",
        workflowNodeId:
          optionalStringDep(request.workflow_node_id) ??
          `runtime.mcp-server.${safeIdDep(server.id)}`,
        payloadSchemaVersion: statusSchemaVersion,
        status: "completed",
        payload: {
          ...status,
          event_kind: "McpServerRemoved",
          control_kind: "mcp_remove",
          thread_id: threadId,
          agent_id: updatedAgent.id,
          server_id: server.id,
          serverId: server.id,
          server,
          removed: [server],
          removed_count: 1,
          removedCount: 1,
          policy_decision: "registry_write_allowed",
          summary: `MCP server ${server.id} removed from the active runtime registry.`,
        },
      });
    },
    applyThreadMcpServerMutation(store, {
      threadId,
      agent,
      request,
      mutationKind,
      sourceEventKind,
      eventKind,
      workflowNodeId,
      serversToUpsert,
    }) {
      const registry = agent.mcpRegistry ?? mcpRegistryForWorkspaceDep(agent.cwd, { homeDir: store.homeDir });
      const proposedServers = normalizeArrayDep(serversToUpsert);
      if (proposedServers.length === 0) {
        throw runtimeErrorDep({
          status: 400,
          code: "mcp_servers_required",
          message: `MCP ${mutationKind} requires at least one server definition.`,
          details: { threadId, mutationKind },
        });
      }
      const validation = validateMcpServerRecordsDep(proposedServers);
      if (!validation.ok) {
        const status = store.mcpStatus({ thread_id: threadId });
        return this.appendThreadMcpControlEvent(store, {
          threadId,
          agent,
          request,
          controlKind: `mcp_${mutationKind}`,
          sourceEventKind,
          eventKind,
          componentKind: "mcp_provider",
          workflowNodeId,
          payloadSchemaVersion: validationSchemaVersion,
          status: "blocked",
          payload: {
            ...status,
            event_kind: mutationKind === "import" ? "McpServersImportBlocked" : "McpServerAddBlocked",
            control_kind: `mcp_${mutationKind}`,
            thread_id: threadId,
            agent_id: agent.id,
            proposed_servers: proposedServers,
            proposedServers,
            validation,
            issues: validation.issues,
            warnings: validation.warnings,
            policy_decision: "registry_write_blocked",
            summary: `MCP ${mutationKind} blocked by ${validation.issues.length} validation issue(s).`,
          },
        });
      }
      const byId = new Map(normalizeArrayDep(registry.servers).map((server) => [server.id, server]));
      for (const server of proposedServers) {
        byId.set(server.id, {
          ...server,
          evidence_refs: uniqueStringsDep([
            ...(server.evidence_refs ?? server.evidenceRefs ?? []),
            mutationKind === "import" ? "mcp.manager.server.import" : "mcp.manager.server.add",
          ]),
          evidenceRefs: uniqueStringsDep([
            ...(server.evidence_refs ?? server.evidenceRefs ?? []),
            mutationKind === "import" ? "mcp.manager.server.import" : "mcp.manager.server.add",
          ]),
        });
      }
      const updatedRegistry = mcpRegistryWithServersDep(registry, [...byId.values()]);
      const updatedAgent = {
        ...agent,
        mcpRegistry: updatedRegistry,
        updatedAt: new Date().toISOString(),
      };
      const status = this.mcpStatusForAgent(updatedAgent);
      const eventLabel = mutationKind === "import" ? "McpServersImported" : "McpServerAdded";
      return this.appendThreadMcpControlEvent(store, {
        threadId,
        agent: updatedAgent,
        request,
        controlKind: `mcp_${mutationKind}`,
        sourceEventKind,
        eventKind,
        componentKind: "mcp_provider",
        workflowNodeId,
        payloadSchemaVersion: statusSchemaVersion,
        status: "completed",
        payload: {
          ...status,
          event_kind: eventLabel,
          control_kind: `mcp_${mutationKind}`,
          thread_id: threadId,
          agent_id: updatedAgent.id,
          servers: proposedServers,
          [mutationKind === "import" ? "imported" : "added"]: proposedServers,
          [`${mutationKind}_count`]: proposedServers.length,
          [`${mutationKind}Count`]: proposedServers.length,
          policy_decision: "registry_write_allowed",
          summary:
            mutationKind === "import"
              ? `Imported ${proposedServers.length} MCP server(s) into the active runtime registry.`
              : `MCP server ${proposedServers[0]?.id ?? "unknown"} added to the active runtime registry.`,
        },
      });
    },
    async mcpStatusWithLiveDiscovery(store, status, agent, request = {}) {
      const toolMap = new Map((status.tools ?? []).map((tool) => [mcpToolKeyDep(tool), tool]));
      const resourceMap = new Map(
        (status.resources ?? []).map((resource) => [mcpResourceKeyDep(resource), resource]),
      );
      const promptMap = new Map((status.prompts ?? []).map((prompt) => [mcpPromptKeyDep(prompt), prompt]));
      const catalogSummaries = [];
      const previewLimit = mcpCatalogPreviewLimitDep(request);
      const forceFullCatalog = mcpCatalogFullRequestedDep(request);
      const discoveries = [];
      for (const server of status.servers ?? []) {
        const liveMode = mcpLiveExecutionModeForServerDep(server, request);
        if (server.enabled === false || !liveMode) {
          continue;
        }
        try {
          const catalog =
            liveMode === "live_stdio"
              ? await discoverMcpStdioCatalogDep(server, {
                  cwd: agent.cwd,
                  timeoutMs: request.timeout_ms,
                })
              : await discoverMcpHttpCatalogDep(server, {
                  cwd: agent.cwd,
                  timeoutMs: request.timeout_ms,
                  vault: store.modelMounting.vault,
                });
          const exposure = mcpCatalogExposureForStatusDep(server, catalog, {
            previewLimit,
            forceFullCatalog,
          });
          catalogSummaries.push(exposure.summary);
          for (const tool of exposure.tools) {
            toolMap.set(mcpToolKeyDep(tool), tool);
          }
          for (const resource of exposure.resources) {
            resourceMap.set(mcpResourceKeyDep(resource), resource);
          }
          for (const prompt of exposure.prompts) {
            promptMap.set(mcpPromptKeyDep(prompt), prompt);
          }
          discoveries.push({
            server_id: server.id,
            serverId: server.id,
            status: "completed",
            transport: catalog.transport ?? server.transport ?? "stdio",
            execution_mode: catalog.execution_mode ?? catalog.executionMode ?? liveMode,
            executionMode: catalog.executionMode ?? catalog.execution_mode ?? liveMode,
            auth_boundary: catalog.auth_boundary ?? catalog.authBoundary ?? null,
            authBoundary: catalog.authBoundary ?? catalog.auth_boundary ?? null,
            tool_count: catalog.tool_count ?? 0,
            resource_count: catalog.resource_count ?? 0,
            prompt_count: catalog.prompt_count ?? 0,
            returned_tool_count: exposure.tools.length,
            returnedToolCount: exposure.tools.length,
            catalog_summary: exposure.summary,
            catalogSummary: exposure.summary,
            catalog_exposure: exposure.exposure,
            catalogExposure: exposure.exposure,
          });
        } catch (error) {
          discoveries.push({
            server_id: server.id,
            serverId: server.id,
            status: "failed",
            transport: server.transport ?? "stdio",
            execution_mode: liveMode,
            executionMode: liveMode,
            error_code: optionalStringDep(error?.code) ?? "mcp_live_discovery_failed",
            message: String(error?.message ?? error),
          });
        }
      }
      const tools = [...toolMap.values()].sort((left, right) =>
        mcpToolKeyDep(left).localeCompare(mcpToolKeyDep(right)),
      );
      const resources = [...resourceMap.values()].sort((left, right) =>
        mcpResourceKeyDep(left).localeCompare(mcpResourceKeyDep(right)),
      );
      const prompts = [...promptMap.values()].sort((left, right) =>
        mcpPromptKeyDep(left).localeCompare(mcpPromptKeyDep(right)),
      );
      return {
        ...status,
        tools,
        tool_count: tools.length,
        toolCount: tools.length,
        resources,
        resource_count: resources.length,
        resourceCount: resources.length,
        prompts,
        prompt_count: prompts.length,
        promptCount: prompts.length,
        catalog_summaries: catalogSummaries,
        catalogSummaries,
        catalog_tool_count: catalogSummaries.reduce((sum, entry) => sum + (entry.tool_count ?? 0), 0),
        catalogToolCount: catalogSummaries.reduce((sum, entry) => sum + (entry.tool_count ?? 0), 0),
        returned_tool_count: tools.length,
        returnedToolCount: tools.length,
        live_discovery: {
          status: discoveries.some((entry) => entry.status === "failed") ? "partial" : "completed",
          requested: true,
          servers: discoveries,
        },
        liveDiscovery: {
          status: discoveries.some((entry) => entry.status === "failed") ? "partial" : "completed",
          requested: true,
          servers: discoveries,
        },
      };
    },
    setMcpServerEnabled(store, serverId, enabled, request = {}) {
      const threadId = optionalStringDep(request.thread_id);
      if (!threadId) {
        throw runtimeErrorDep({
          status: 400,
          code: "mcp_thread_required",
          message: "MCP server enable/disable controls require a thread_id so the daemon can update the active runtime registry.",
          details: { serverId, enabled },
        });
      }
      return this.setThreadMcpServerEnabled(store, threadId, serverId, enabled, request);
    },
    setThreadMcpServerEnabled(store, threadId, serverId, enabled, request = {}) {
      const agent = store.agentForThread(threadId);
      const registry = agent.mcpRegistry ?? mcpRegistryForWorkspaceDep(agent.cwd, { homeDir: store.homeDir });
      const server = resolveMcpServerRecordDep(registry.servers, serverId);
      if (!server) throw notFoundDep(`MCP server not found: ${serverId}`, { threadId, serverId });
      const nextStatus = enabled
        ? (server.status === "disabled" ? "configured" : server.status ?? "configured")
        : "disabled";
      const updatedServer = {
        ...server,
        enabled,
        status: nextStatus,
        health: {
          ...(server.health ?? {}),
          status: enabled ? server.health?.status ?? "not_connected" : "disabled",
          live_probe: false,
          reason: enabled ? "operator_enabled" : "operator_disabled",
        },
        evidence_refs: uniqueStringsDep([
          ...(server.evidence_refs ?? server.evidenceRefs ?? []),
          enabled ? "mcp.manager.server.enable" : "mcp.manager.server.disable",
        ]),
        evidenceRefs: uniqueStringsDep([
          ...(server.evidence_refs ?? server.evidenceRefs ?? []),
          enabled ? "mcp.manager.server.enable" : "mcp.manager.server.disable",
        ]),
      };
      const servers = normalizeArrayDep(registry.servers).map((candidate) =>
        candidate.id === server.id ? updatedServer : candidate,
      );
      const updatedRegistry = mcpRegistryWithServersDep(registry, servers);
      const updatedAgent = {
        ...agent,
        mcpRegistry: updatedRegistry,
        updatedAt: new Date().toISOString(),
      };
      const status = this.mcpStatusForAgent(updatedAgent);
      const controlKind = enabled ? "mcp_enable" : "mcp_disable";
      return this.appendThreadMcpControlEvent(store, {
        threadId,
        agent: updatedAgent,
        request,
        controlKind,
        sourceEventKind: enabled ? "OperatorControl.McpEnable" : "OperatorControl.McpDisable",
        eventKind: enabled ? "mcp.server_enabled" : "mcp.server_disabled",
        componentKind: "mcp_provider",
        workflowNodeId:
          optionalStringDep(request.workflow_node_id) ??
          `runtime.mcp-server.${safeIdDep(updatedServer.id)}`,
        payloadSchemaVersion: statusSchemaVersion,
        status: "completed",
        payload: {
          ...status,
          event_kind: enabled ? "McpServerEnabled" : "McpServerDisabled",
          control_kind: controlKind,
          thread_id: threadId,
          agent_id: updatedAgent.id,
          server_id: updatedServer.id,
          serverId: updatedServer.id,
          enabled,
          server: updatedServer,
          servers: [updatedServer],
          tools: mcpToolsForServersDep([updatedServer]),
          summary: `MCP server ${updatedServer.id} ${enabled ? "enabled" : "disabled"}.`,
        },
      });
    },
    async invokeMcpTool(store, request = {}) {
      const threadId = optionalStringDep(request.thread_id);
      if (!threadId) {
        throw runtimeErrorDep({
          status: 400,
          code: "mcp_thread_required",
          message: "MCP tool invocation requires a thread_id so the daemon can apply the active MCP registry and approval policy.",
          details: { toolId: request.tool_id ?? null },
        });
      }
      return this.invokeThreadMcpTool(store, threadId, request.tool_id, request);
    },
    async invokeThreadMcpTool(store, threadId, toolId, request = {}) {
      const agent = store.agentForThread(threadId);
      const servers = store.listMcpServers({ thread_id: threadId });
      const target = resolveMcpToolRecordDep(servers, toolId, request);
      if (!target.server) {
        throw notFoundDep("MCP server not found for invocation.", {
          threadId,
          toolId,
          serverId: request.server_id ?? null,
        });
      }
      if (!target.toolName) {
        throw runtimeErrorDep({
          status: 400,
          code: "mcp_tool_required",
          message: "MCP invocation requires a tool name.",
          details: { threadId, serverId: target.server.id, toolId: toolId ?? null },
        });
      }
      const server = target.server;
      const toolName = target.toolName;
      const tools = mcpToolsForServersDep([server]);
      const toolEntry =
        tools.find((candidate) => candidate.toolName === toolName || candidate.tool_name === toolName) ??
        null;
      if (!toolEntry) {
        throw notFoundDep(`MCP tool not found: ${toolName}`, {
          threadId,
          serverId: server.id,
          toolName,
        });
      }
      const input = request.input ?? request.arguments ?? request.args ?? {};
      const sideEffectClass =
        optionalStringDep(request.side_effect_class) ??
        optionalStringDep(toolEntry.sideEffectClass) ??
        "read";
      const requiresApproval =
        request.requires_approval === true ||
        (sideEffectClass !== "none" && sideEffectClass !== "read");
      const approvalMode =
        optionalStringDep(agent.runtimeControls?.approval_mode ?? agent.runtimeControls?.approvalMode) ??
        "agent";
      const approved =
        request.approved === true ||
        request.approval_granted === true ||
        approvalMode === "yolo";
      const validation = validateMcpServerRecordsDep([server]);
      const blockers = [
        ...(server.enabled === false ? ["server_disabled"] : []),
        ...(!validation.ok ? validation.issues.map((issue) => issue.code) : []),
        ...(requiresApproval && !approved ? ["approval_required"] : []),
      ];
      const inputHash = doctorHashDep(JSON.stringify(input));
      let status = blockers.length > 0 ? "blocked" : "completed";
      let output = null;
      let transportExecution = null;
      if (status === "completed") {
        const liveMode = mcpLiveExecutionModeForServerDep(server, request);
        if (liveMode === "live_stdio") {
          try {
            transportExecution = await invokeMcpStdioToolDep(server, toolName, input, {
              cwd: agent.cwd,
              timeoutMs: request.timeout_ms,
              mcpMode: request.mcp_mode,
            });
            output = transportExecution.result ?? {};
          } catch (error) {
            status = "blocked";
            blockers.push("stdio_transport_failed");
            transportExecution = {
              ok: false,
              status: "failed",
              transport: "stdio",
              execution_mode: "live_stdio",
              executionMode: "live_stdio",
              error: {
                code: optionalStringDep(error?.code) ?? "mcp_stdio_transport_error",
                message: String(error?.message ?? error),
                details: error?.details ?? {},
              },
            };
          }
        } else if (liveMode === "live_http" || liveMode === "live_sse") {
          const transport = liveMode === "live_sse" ? "sse" : "http";
          try {
            transportExecution = await invokeMcpHttpToolDep(server, toolName, input, {
              cwd: agent.cwd,
              timeoutMs: request.timeout_ms,
              headers: request.headers,
              vault: store.modelMounting.vault,
            });
            output = transportExecution.result ?? {};
          } catch (error) {
            status = "blocked";
            blockers.push(`${transport}_transport_failed`);
            transportExecution = {
              ok: false,
              status: "failed",
              transport,
              execution_mode: liveMode,
              executionMode: liveMode,
              error: {
                code: optionalStringDep(error?.code) ?? `mcp_${transport}_transport_error`,
                message: String(error?.message ?? error),
                details: error?.details ?? {},
              },
            };
          }
        } else {
          output = { ok: true, fixture: true, serverId: server.id, toolName };
          transportExecution = {
            ok: true,
            status: "completed",
            transport: server.transport ?? "unknown",
            execution_mode: "simulated_manager_receipt",
            executionMode: "simulated_manager_receipt",
          };
        }
      }
      const outputHash = doctorHashDep(
        JSON.stringify(output ?? { blocked: blockers, transport_execution: transportExecution }),
      );
      const callHash = doctorHashDep(
        `${threadId}:${server.id}:${toolName}:${inputHash}:${Date.now()}`,
      ).slice(0, 16);
      const toolCallId = `mcp_call_${safeIdDep(server.id)}_${safeIdDep(toolName)}_${callHash}`;
      const invocation = {
        schema_version: invocationSchemaVersion,
        schemaVersion: invocationSchemaVersion,
        object: "ioi.runtime_mcp_tool_invocation",
        tool_call_id: toolCallId,
        toolCallId,
        thread_id: threadId,
        threadId,
        agent_id: agent.id,
        agentId: agent.id,
        server_id: server.id,
        serverId: server.id,
        tool_name: toolName,
        toolName,
        status,
        input_hash: inputHash,
        inputHash,
        output_hash: outputHash,
        outputHash,
        side_effect_class: sideEffectClass,
        sideEffectClass,
        requires_approval: requiresApproval,
        requiresApproval,
        approval_mode: approvalMode,
        approvalMode,
        approved,
        blockers,
        transport: server.transport ?? "stdio",
        transport_execution: transportExecution,
        transportExecution,
        containment: {
          ...(server.containment ?? {}),
          receiptRequired: true,
          executionMode: transportExecution?.executionMode ?? transportExecution?.execution_mode ?? "blocked",
          execution_mode: transportExecution?.execution_mode ?? transportExecution?.executionMode ?? "blocked",
        },
        result: output,
        evidence_refs: [
          "mcp.manager.tool.invoke",
          "mcp_containment_receipt",
          mcpTransportEvidenceRefDep(transportExecution),
          server.id,
          `tool:${toolName}`,
        ],
        evidenceRefs: [
          "mcp.manager.tool.invoke",
          "mcp_containment_receipt",
          mcpTransportEvidenceRefDep(transportExecution),
          server.id,
          `tool:${toolName}`,
        ],
      };
      return this.appendThreadMcpControlEvent(store, {
        threadId,
        agent,
        request,
        controlKind: "mcp_invoke",
        sourceEventKind: "OperatorControl.McpInvoke",
        eventKind: "mcp.tool_invocation",
        componentKind: "mcp_tool_call",
        workflowNodeId:
          optionalStringDep(request.workflow_node_id) ??
          toolEntry.workflowNodeId ??
          toolEntry.workflow_node_id ??
          `runtime.mcp-tool.${safeIdDep(server.id)}.${safeIdDep(toolName)}`,
        payloadSchemaVersion: invocationSchemaVersion,
        status,
        payload: {
          ...invocation,
          event_kind: "McpToolInvocation",
          control_kind: "mcp_invoke",
          server,
          servers: [server],
          tool: { ...toolEntry, status },
          tools: [{ ...toolEntry, status }],
          invocation,
          summary:
            status === "completed"
              ? `MCP tool ${server.id}.${toolName} invoked with ${mcpTransportSummaryDep(transportExecution)}.`
              : `MCP tool ${server.id}.${toolName} blocked: ${blockers.join(", ")}.`,
          policy_decision: status === "completed" ? "invoke_allowed" : "invoke_blocked",
          result: output,
        },
      });
    },
    async recordThreadMcpStatus(store, threadId, request = {}) {
      const agent = store.agentForThread(threadId);
      let status = store.mcpStatus({ ...request, thread_id: threadId });
      if (request.live_discovery === true || request.liveDiscovery === true) {
        status = await this.mcpStatusWithLiveDiscovery(store, status, agent, request);
      }
      return this.appendThreadMcpControlEvent(store, {
        threadId,
        agent,
        request,
        controlKind: "mcp_status",
        sourceEventKind: "OperatorControl.Mcp",
        eventKind: "mcp.catalog_status",
        componentKind: "mcp_provider",
        workflowNodeId: "runtime.mcp-manager",
        payloadSchemaVersion: statusSchemaVersion,
        status: status.status === "ready" ? "completed" : "blocked",
        payload: {
          ...status,
          event_kind: "McpCatalogStatus",
          control_kind: "mcp_status",
          thread_id: threadId,
          agent_id: agent.id,
          summary: `MCP catalog has ${status.server_count} server(s), ${status.tool_count} tool(s), ${status.resource_count ?? 0} resource(s), and ${status.prompt_count ?? 0} prompt(s).`,
        },
      });
    },
    validateThreadMcp(store, threadId, request = {}) {
      const agent = store.agentForThread(threadId);
      const validation = store.validateMcp(
        request.mcp_json || request.mcpJson || request.servers || request.mcpServers
          ? request
          : { servers: store.listMcpServers({ ...request, thread_id: threadId }) },
      );
      return this.appendThreadMcpControlEvent(store, {
        threadId,
        agent,
        request,
        controlKind: "mcp_validate",
        sourceEventKind: "OperatorControl.McpValidate",
        eventKind: "mcp.validation",
        componentKind: "mcp_validator",
        workflowNodeId: "runtime.mcp-manager.validate",
        payloadSchemaVersion: validationSchemaVersion,
        status: validation.ok ? "completed" : "blocked",
        payload: {
          ...validation,
          event_kind: "McpValidationReport",
          control_kind: "mcp_validate",
          thread_id: threadId,
          agent_id: agent.id,
          summary: validation.ok
            ? `MCP validation passed for ${validation.server_count} server(s).`
            : `MCP validation found ${validation.issue_count} issue(s).`,
        },
      });
    },
    appendThreadMcpControlEvent(store, {
      threadId,
      agent,
      request,
      controlKind,
      sourceEventKind,
      eventKind,
      componentKind,
      workflowNodeId,
      payloadSchemaVersion,
      status,
      payload,
    }) {
      const thread = store.threadForAgent(agent);
      const turnId =
        optionalStringDep(request.turn_id ?? request.turnId) ??
        optionalStringDep(thread.latest_turn_id) ??
        "";
      const source = operatorControlSourceDep(request.source);
      const graphId = optionalStringDep(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
      const nodeId =
        optionalStringDep(request.workflow_node_id) ??
        workflowNodeId;
      const eventHash = doctorHashDep(`${threadId}:${controlKind}:${JSON.stringify(payload)}:${Date.now()}`).slice(0, 12);
      const receiptId = `receipt_mcp_${safeIdDep(controlKind)}_${eventHash}`;
      const policyKind =
        optionalStringDep(payload.policy_decision ?? payload.policyDecision) ??
        (status === "blocked"
          ? "blocked"
          : controlKind === "mcp_invoke"
            ? "invoke_allowed"
            : "read");
      const policyId = `policy_mcp_${safeIdDep(controlKind)}_${safeIdDep(policyKind)}_${eventHash}`;
      const event = store.appendRuntimeEvent({
        event_stream_id: eventStreamIdForThreadDep(threadId),
        thread_id: threadId,
        turn_id: turnId,
        item_id: `${turnId || threadId}:item:mcp:${safeIdDep(controlKind)}:${eventHash}`,
        idempotency_key:
          optionalStringDep(request.idempotency_key ?? request.idempotencyKey) ??
          `thread:${threadId}:mcp:${controlKind}:${eventHash}`,
        source,
        source_event_kind: sourceEventKind,
        event_kind: eventKind,
        status,
        actor: "operator",
        workspace_root: agent.cwd,
        workflow_graph_id: graphId,
        workflow_node_id: nodeId,
        component_kind: componentKind,
        payload_schema_version: payloadSchemaVersion,
        payload_summary: payload,
        receipt_refs: [receiptId],
        policy_decision_refs: [policyId],
        artifact_refs: [],
        rollback_refs: [],
        redaction_profile: "internal",
        fixture_profile: fixtureProfileForAgentDep(agent),
      });
      const result = {
        ...payload,
        event,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
      };
      if (typeof contextPolicyRunnerDep?.planMcpControlAgentStateUpdate !== "function") {
        throw runtimeErrorDep({
          status: 500,
          code: "mcp_control_state_update_planner_unavailable",
          message: "MCP control updates require Rust policy state-update planning.",
          details: { threadId, controlKind },
        });
      }
      const stateUpdate = contextPolicyRunnerDep.planMcpControlAgentStateUpdate({
        thread_id: threadId,
        agent,
        control_kind: controlKind,
        event_id: event.event_id,
        seq: event.seq,
        created_at: event.created_at,
      });
      const updatedAgent = stateUpdate.agent;
      if (!updatedAgent?.id) {
        throw runtimeErrorDep({
          status: 502,
          code: "mcp_control_state_update_planner_invalid",
          message: "Rust policy state-update planning did not return an agent record.",
          details: { threadId, controlKind },
        });
      }
      const operationKind = requiredMcpControlOperationKind(stateUpdate, threadId, controlKind);
      store.agents.set(updatedAgent.id, updatedAgent);
      store.writeAgent(updatedAgent, operationKind);
      return result;
    },
  };

  function requiredMcpControlOperationKind(stateUpdate, threadId, controlKind) {
    const expectedOperationKind = `thread.${controlKind}`;
    const operationKind = optionalStringDep(stateUpdate.operation_kind);
    if (!operationKind) {
      throw runtimeErrorDep({
        status: 502,
        code: "mcp_control_state_update_operation_kind_missing",
        message: "Rust policy state-update planning did not return an operation kind.",
        details: { threadId, controlKind, operationKind: expectedOperationKind },
      });
    }
    if (operationKind !== expectedOperationKind) {
      throw runtimeErrorDep({
        status: 502,
        code: "mcp_control_state_update_operation_kind_mismatch",
        message: "Rust policy state-update planning returned an unexpected operation kind.",
        details: {
          threadId,
          controlKind,
          expectedOperationKind,
          operationKind,
        },
      });
    }
    return operationKind;
  }
}
