import path from "node:path";

import {
  MCP_LIVE_CATALOG_MAX_PREVIEW_LIMIT,
  RUNTIME_MCP_TOOL_SEARCH_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";
import {
  RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
  discoverMcpHttpCatalog,
  discoverMcpStdioCatalog,
  mcpRegistryForWorkspace,
  mcpServerRecordsFromValidationInput,
  normalizeMcpServerRecord,
} from "./mcp-manager.mjs";
import {
  mcpCatalogPreviewLimit,
  mcpConfigSourceModeForRequest,
  mcpLiveExecutionModeForServer,
  mcpServerMatchesConfigSourceMode,
  mcpToolIdentityMatches,
  mcpToolKey,
  mcpToolMatchesQuery,
  mcpToolSearchLimit,
  resolveMcpServerRecord,
} from "./runtime-mcp-helpers.mjs";
import { notFound } from "./runtime-http-utils.mjs";
import {
  normalizeArray,
  optionalString,
} from "./runtime-value-helpers.mjs";
import { agentIdForThread } from "./runtime-identifiers.mjs";
import { createContextPolicyRunnerFromEnv } from "./runtime-context-policy-runner.mjs";

export function createRuntimeMcpCatalogSurface({
  RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION: statusSchemaVersion = RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
  RUNTIME_MCP_TOOL_SEARCH_SCHEMA_VERSION: toolSearchSchemaVersion = RUNTIME_MCP_TOOL_SEARCH_SCHEMA_VERSION,
  MCP_LIVE_CATALOG_MAX_PREVIEW_LIMIT: maxLiveCatalogPreviewLimit = MCP_LIVE_CATALOG_MAX_PREVIEW_LIMIT,
  RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION: validationSchemaVersion = RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
  agentIdForThread: agentIdForThreadDep = agentIdForThread,
  discoverMcpHttpCatalog: discoverMcpHttpCatalogDep = discoverMcpHttpCatalog,
  discoverMcpStdioCatalog: discoverMcpStdioCatalogDep = discoverMcpStdioCatalog,
  mcpCatalogPreviewLimit: mcpCatalogPreviewLimitDep = mcpCatalogPreviewLimit,
  mcpConfigSourceModeForRequest: mcpConfigSourceModeForRequestDep = mcpConfigSourceModeForRequest,
  mcpLiveExecutionModeForServer: mcpLiveExecutionModeForServerDep = mcpLiveExecutionModeForServer,
  mcpRegistryForWorkspace: mcpRegistryForWorkspaceDep = mcpRegistryForWorkspace,
  mcpServerMatchesConfigSourceMode: mcpServerMatchesConfigSourceModeDep = mcpServerMatchesConfigSourceMode,
  mcpServerRecordsFromValidationInput: mcpServerRecordsFromValidationInputDep = mcpServerRecordsFromValidationInput,
  mcpToolIdentityMatches: mcpToolIdentityMatchesDep = mcpToolIdentityMatches,
  mcpToolKey: mcpToolKeyDep = mcpToolKey,
  mcpToolMatchesQuery: mcpToolMatchesQueryDep = mcpToolMatchesQuery,
  mcpToolSearchLimit: mcpToolSearchLimitDep = mcpToolSearchLimit,
  notFound: notFoundDep = notFound,
  normalizeArray: normalizeArrayDep = normalizeArray,
  normalizeMcpServerRecord: normalizeMcpServerRecordDep = normalizeMcpServerRecord,
  optionalString: optionalStringDep = optionalString,
  pathResolve = path.resolve,
  resolveMcpServerRecord: resolveMcpServerRecordDep = resolveMcpServerRecord,
  contextPolicyRunner = createContextPolicyRunnerFromEnv(),
} = {}) {
  return {
    listMcpServers(store, options = {}) {
      return this.mcpServersForContext(store, options);
    },
    listMcpTools(store, options = {}) {
      const servers = this.mcpServersForContext(store, options);
      const serverFilter = optionalStringDep(options.server_id);
      return this.mcpCatalogRowsForServers(
        serverFilter ? servers.filter((server) => server.id === serverFilter) : servers,
      ).tools;
    },
    async searchMcpTools(store, options = {}) {
      const threadId = optionalStringDep(options.thread_id);
      if (threadId) return this.searchThreadMcpTools(store, threadId, options);
      return this.searchMcpToolCatalog(store, {
        ...options,
        servers: this.mcpServersForContext(store, options),
        agent: { cwd: store.defaultCwd },
      });
    },
    async getMcpTool(store, toolId, options = {}) {
      const threadId = optionalStringDep(options.thread_id);
      if (threadId) return this.getThreadMcpTool(store, threadId, toolId, options);
      return this.getMcpToolFromCatalog(store, toolId, {
        ...options,
        servers: this.mcpServersForContext(store, options),
        agent: { cwd: store.defaultCwd },
      });
    },
    listMcpResources(store, options = {}) {
      const servers = this.mcpServersForContext(store, options);
      const serverFilter = optionalStringDep(options.server_id);
      return this.mcpCatalogRowsForServers(
        serverFilter ? servers.filter((server) => server.id === serverFilter) : servers,
      ).resources;
    },
    listMcpPrompts(store, options = {}) {
      const servers = this.mcpServersForContext(store, options);
      const serverFilter = optionalStringDep(options.server_id);
      return this.mcpCatalogRowsForServers(
        serverFilter ? servers.filter((server) => server.id === serverFilter) : servers,
      ).prompts;
    },
    mcpStatus(store, options = {}) {
      const servers = this.listMcpServers(store, options);
      const catalog = contextPolicyRunner.planMcpManagerCatalogProjection({ servers });
      const validation = contextPolicyRunner.validateMcpServers({ servers });
      const routes = {
        servers: "/v1/mcp/servers",
        tools: "/v1/mcp/tools",
        search_tools: "/v1/mcp/tools/search",
        get_tool: "/v1/mcp/tools/{tool_id}",
        resources: "/v1/mcp/resources",
        prompts: "/v1/mcp/prompts",
        validate: "/v1/mcp/validate",
        import_servers: "/v1/mcp/import",
        add_server: "/v1/mcp/servers",
        remove_server: "/v1/mcp/servers/{server_id}",
        enable_server: "/v1/mcp/servers/{server_id}/enable",
        disable_server: "/v1/mcp/servers/{server_id}/disable",
        invoke_tool: "/v1/mcp/tools/{tool_id}/invoke",
        serve: "/v1/mcp/serve",
        serve_for_thread: "/v1/threads/{thread_id}/mcp/serve",
      };
      return contextPolicyRunner.planMcpManagerStatusProjection({
        status_schema_version: statusSchemaVersion,
        validation,
        servers,
        tools: catalog.tools,
        resources: catalog.resources,
        prompts: catalog.prompts,
        enabled_tools: catalog.enabled_tools,
        routes,
      });
    },
    async searchThreadMcpTools(store, threadId, request = {}) {
      const agent = store.agentForThread(threadId);
      return this.searchMcpToolCatalog(store, {
        ...request,
        thread_id: threadId,
        threadId,
        servers: this.listMcpServers(store, { ...request, thread_id: threadId }),
        agent,
      });
    },
    async getThreadMcpTool(store, threadId, toolId, request = {}) {
      const agent = store.agentForThread(threadId);
      return this.getMcpToolFromCatalog(store, toolId, {
        ...request,
        thread_id: threadId,
        servers: this.listMcpServers(store, { ...request, thread_id: threadId }),
        agent,
      });
    },
    async getMcpToolFromCatalog(store, toolId, request = {}) {
      const result = await this.searchMcpToolCatalog(store, {
        ...request,
        tool_id: toolId,
        exact: true,
        limit: Math.max(Number(request.limit ?? 0), maxLiveCatalogPreviewLimit),
      });
      const requested = optionalStringDep(toolId ?? request.tool_id);
      const tool = result.tools.find((candidate) => mcpToolIdentityMatchesDep(candidate, requested)) ?? null;
      if (!tool) {
        throw notFoundDep("MCP tool not found.", {
          tool_id: requested ?? null,
          server_id: request.server_id ?? null,
        });
      }
      return {
        ...result,
        object: "ioi.runtime_mcp_tool_fetch",
        status: "completed",
        tool_id: requested ?? tool.stable_tool_id ?? null,
        server_id: tool.server_id ?? null,
        tool_name: tool.tool_name ?? null,
        tool,
        tools: [tool],
        returned_count: 1,
      };
    },
    async searchMcpToolCatalog(store, request = {}) {
      const query = optionalStringDep(request.q ?? request.query ?? request.search) ?? "";
      const requestedToolId = optionalStringDep(request.tool_id);
      const exact = request.exact === true || request.exact === "true";
      const serverFilter = optionalStringDep(request.server_id);
      const liveDiscovery = request.live_discovery !== false;
      const limit = mcpToolSearchLimitDep(request);
      const servers = normalizeArrayDep(request.servers).filter((server) =>
        serverFilter ? resolveMcpServerRecordDep([server], serverFilter) : true,
      );
      const agent = request.agent ?? { cwd: store.defaultCwd };
      const catalogSummaries = [];
      const failures = [];
      const candidateTools = [];
      for (const server of servers) {
        const declaredCatalog = this.mcpCatalogRowsForServers([server]);
        let tools = declaredCatalog.tools;
        let resources = declaredCatalog.resources;
        let prompts = declaredCatalog.prompts;
        const liveMode = liveDiscovery ? mcpLiveExecutionModeForServerDep(server, request) : null;
        if (server.enabled !== false && liveMode) {
          try {
            const catalog =
              liveMode === "live_stdio"
                ? await discoverMcpStdioCatalogDep(server, {
                    cwd: agent.cwd,
                    timeout_ms: request.timeout_ms,
                  })
                : await discoverMcpHttpCatalogDep(server, {
                    cwd: agent.cwd,
                    timeout_ms: request.timeout_ms,
                    vault: store.modelMounting.vault,
                  });
            const liveCatalog = this.mcpCatalogRowsForServers([{
              ...server,
              tools: normalizeArrayDep(catalog.tools ?? catalog.listed_tools),
              resources: normalizeArrayDep(catalog.resources ?? catalog.listed_resources),
              prompts: normalizeArrayDep(catalog.prompts ?? catalog.listed_prompts),
            }]);
            tools = liveCatalog.tools;
            resources = liveCatalog.resources;
            prompts = liveCatalog.prompts;
            catalogSummaries.push(this.mcpCatalogSummaryForRows(server, { tools, resources, prompts }, {
              live_mode: liveMode,
              deferred: tools.length > mcpCatalogPreviewLimitDep(request),
              preview_limit: mcpCatalogPreviewLimitDep(request),
            }));
          } catch (error) {
            failures.push({
              server_id: server.id,
              status: "failed",
              error_code: optionalStringDep(error?.code) ?? "mcp_tool_search_discovery_failed",
              message: String(error?.message ?? error),
            });
            catalogSummaries.push(this.mcpCatalogSummaryForRows(server, { tools, resources, prompts }, {
              live_mode: liveMode,
              status: "failed",
              error_code: optionalStringDep(error?.code) ?? "mcp_tool_search_discovery_failed",
            }));
          }
        } else {
          catalogSummaries.push(this.mcpCatalogSummaryForRows(server, { tools, resources, prompts }, {
            live_mode: liveMode ?? "declared_catalog",
            deferred: false,
            preview_limit: mcpCatalogPreviewLimitDep(request),
          }));
        }
        candidateTools.push(...tools);
      }
      const filtered = candidateTools
        .filter((tool) =>
          requestedToolId
            ? mcpToolIdentityMatchesDep(tool, requestedToolId) ||
              (!exact && mcpToolMatchesQueryDep(tool, requestedToolId))
            : mcpToolMatchesQueryDep(tool, query),
        )
        .sort((left, right) => mcpToolKeyDep(left).localeCompare(mcpToolKeyDep(right)));
      const returned = filtered.slice(0, limit);
      return {
        schema_version: toolSearchSchemaVersion,
        object: "ioi.runtime_mcp_tool_search",
        status: failures.length > 0 ? "partial" : "completed",
        query,
        q: query,
        exact,
        live_discovery: liveDiscovery,
        server_count: servers.length,
        tool_count: filtered.length,
        returned_count: returned.length,
        limit,
        deferred: filtered.length > returned.length,
        tools: returned,
        catalog_summaries: catalogSummaries,
        failures,
        routes: {
          search: "/v1/mcp/tools/search",
          get_tool: "/v1/mcp/tools/{tool_id}",
          invoke_tool: "/v1/mcp/tools/{tool_id}/invoke",
        },
      };
    },
    validateMcp(store, input = {}) {
      const workspaceRoot = pathResolve(
        input.cwd ?? input.workspace_root ?? store.defaultCwd,
      );
      const servers = mcpServerRecordsFromValidationInputDep(input, workspaceRoot, {
        contextPolicyRunner,
      });
      const validation = contextPolicyRunner.validateMcpServers({ servers });
      const catalog = contextPolicyRunner.planMcpManagerCatalogProjection({ servers });
      return contextPolicyRunner.planMcpManagerValidationProjection({
        validation_schema_version: validationSchemaVersion,
        validation,
        servers,
        tools: catalog.tools,
        resources: catalog.resources,
        prompts: catalog.prompts,
      });
    },
    mcpCatalogRowsForServers(servers = []) {
      const catalog = contextPolicyRunner.planMcpManagerCatalogProjection({ servers });
      return {
        ...catalog,
        tools: normalizeArrayDep(catalog.tools),
        resources: normalizeArrayDep(catalog.resources),
        prompts: normalizeArrayDep(catalog.prompts),
        enabled_tools: normalizeArrayDep(catalog.enabled_tools),
      };
    },
    mcpCatalogSummaryForRows(server, catalog = {}, options = {}) {
      return contextPolicyRunner.planMcpManagerCatalogSummaryProjection({
        server,
        tools: normalizeArrayDep(catalog.tools),
        resources: normalizeArrayDep(catalog.resources),
        prompts: normalizeArrayDep(catalog.prompts),
        live_mode: options.live_mode,
        status: options.status,
        error_code: options.error_code,
        preview_limit: options.preview_limit,
        deferred: options.deferred,
      });
    },
    mcpServersForContext(store, options = {}) {
      const threadId = optionalStringDep(options.thread_id);
      const agentId =
        optionalStringDep(options.agent_id) ??
        (threadId ? agentIdForThreadDep(threadId) : undefined);
      const sourceMode = mcpConfigSourceModeForRequestDep(options);
      const servers = [];
      if (agentId && store.agents.has(agentId)) {
        const agent = store.getAgent(agentId);
        servers.push(...normalizeArrayDep(agent.mcpRegistry?.servers));
      } else {
        servers.push(
          ...mcpRegistryForWorkspaceDep(store.defaultCwd, {
            ...options,
            homeDir: store.homeDir,
            mcp_config_source_mode: sourceMode,
          }).servers,
        );
        for (const agent of store.agents.values()) {
          servers.push(...normalizeArrayDep(agent.mcpRegistry?.servers));
        }
      }
      servers.push(
        ...store.modelMounting.listMcpServers().map((server) =>
          normalizeMcpServerRecordDep(server.label ?? server.id, server, {
            workspace_root: store.defaultCwd,
            source: server.source ?? "model_mounting",
            source_scope: "model_mounting",
            config_compatibility: "ioi_model_mounting",
            status: server.status ?? "registered",
          }),
        ),
      );
      const byId = new Map();
      for (const server of servers) {
        byId.set(server.id, server);
      }
      return [...byId.values()]
        .filter((server) => mcpServerMatchesConfigSourceModeDep(server, sourceMode))
        .sort((left, right) => left.id.localeCompare(right.id));
    },
  };
}
