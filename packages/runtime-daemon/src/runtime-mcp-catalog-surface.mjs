import path from "node:path";

import {
  MCP_LIVE_CATALOG_MAX_PREVIEW_LIMIT,
  RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
  RUNTIME_MCP_TOOL_SEARCH_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";
import {
  RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
  mcpRegistryForWorkspace,
  mcpServerRecordsFromValidationInput,
} from "./mcp-manager.mjs";
import {
  mcpCatalogPreviewLimit,
  mcpConfigSourceModeForRequest,
  mcpServerMatchesConfigSourceMode,
  mcpToolSearchLimit,
} from "./runtime-mcp-helpers.mjs";
import { notFound } from "./runtime-http-utils.mjs";
import {
  normalizeArray,
  optionalString,
} from "./runtime-value-helpers.mjs";
import { createRuntimeContextPolicyCore } from "./runtime-context-policy-core.mjs";

export function createRuntimeMcpCatalogSurface({
  RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION: statusSchemaVersion = RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
  RUNTIME_MCP_TOOL_SEARCH_SCHEMA_VERSION: toolSearchSchemaVersion = RUNTIME_MCP_TOOL_SEARCH_SCHEMA_VERSION,
  MCP_LIVE_CATALOG_MAX_PREVIEW_LIMIT: maxLiveCatalogPreviewLimit = MCP_LIVE_CATALOG_MAX_PREVIEW_LIMIT,
  RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION: validationSchemaVersion = RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
  mcpCatalogPreviewLimit: mcpCatalogPreviewLimitDep = mcpCatalogPreviewLimit,
  mcpConfigSourceModeForRequest: mcpConfigSourceModeForRequestDep = mcpConfigSourceModeForRequest,
  mcpRegistryForWorkspace: mcpRegistryForWorkspaceDep = mcpRegistryForWorkspace,
  mcpServerMatchesConfigSourceMode: mcpServerMatchesConfigSourceModeDep = mcpServerMatchesConfigSourceMode,
  mcpServerRecordsFromValidationInput: mcpServerRecordsFromValidationInputDep = mcpServerRecordsFromValidationInput,
  mcpToolSearchLimit: mcpToolSearchLimitDep = mcpToolSearchLimit,
  notFound: notFoundDep = notFound,
  normalizeArray: normalizeArrayDep = normalizeArray,
  optionalString: optionalStringDep = optionalString,
  pathResolve = path.resolve,
  contextPolicyCore = createRuntimeContextPolicyCore(),
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
      });
    },
    async getMcpTool(store, toolId, options = {}) {
      const threadId = optionalStringDep(options.thread_id);
      if (threadId) return this.getThreadMcpTool(store, threadId, toolId, options);
      return this.getMcpToolFromCatalog(store, toolId, {
        ...options,
        servers: this.mcpServersForContext(store, options),
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
      const catalog = contextPolicyCore.planMcpManagerCatalogProjection({ servers });
      const validation = contextPolicyCore.validateMcpServers({ servers });
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
      return contextPolicyCore.planMcpManagerStatusProjection({
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
      return this.searchMcpToolCatalog(store, {
        ...request,
        thread_id: threadId,
        threadId,
        servers: this.listMcpServers(store, { ...request, thread_id: threadId }),
      });
    },
    async getThreadMcpTool(store, threadId, toolId, request = {}) {
      return this.getMcpToolFromCatalog(store, toolId, {
        ...request,
        thread_id: threadId,
        servers: this.listMcpServers(store, { ...request, thread_id: threadId }),
      });
    },
    async getMcpToolFromCatalog(store, toolId, request = {}) {
      const requested = optionalStringDep(toolId ?? request.tool_id);
      const result = contextPolicyCore.projectMcpToolFetchProjection({
        status_schema_version: toolSearchSchemaVersion,
        state_dir: optionalStringDep(request.state_dir) ?? optionalStringDep(store?.stateDir) ?? null,
        thread_id: optionalStringDep(request.thread_id) ?? null,
        agent_id: optionalStringDep(request.agent_id) ?? null,
        server_id: optionalStringDep(request.server_id) ?? null,
        servers: normalizeArrayDep(request.servers),
        tool_id: requested ?? null,
        limit: Math.max(Number(request.limit ?? 0), maxLiveCatalogPreviewLimit),
        preview_limit: mcpCatalogPreviewLimitDep(request),
        live_discovery: request.live_discovery !== false,
      });
      if (result.status === "not_found" || !result.tool) {
        throw notFoundDep("MCP tool not found.", {
          tool_id: requested ?? null,
          server_id: request.server_id ?? null,
        });
      }
      return result;
    },
    async searchMcpToolCatalog(store, request = {}) {
      const query = optionalStringDep(request.q ?? request.query ?? request.search) ?? "";
      const requestedToolId = optionalStringDep(request.tool_id);
      const exact = request.exact === true || request.exact === "true";
      const liveDiscovery = request.live_discovery !== false;
      const limit = mcpToolSearchLimitDep(request);
      return contextPolicyCore.projectMcpToolSearchProjection({
        status_schema_version: toolSearchSchemaVersion,
        state_dir: optionalStringDep(request.state_dir) ?? optionalStringDep(store?.stateDir) ?? null,
        thread_id: optionalStringDep(request.thread_id) ?? null,
        agent_id: optionalStringDep(request.agent_id) ?? null,
        server_id: optionalStringDep(request.server_id) ?? null,
        servers: normalizeArrayDep(request.servers),
        query,
        tool_id: requestedToolId ?? null,
        exact,
        limit,
        preview_limit: mcpCatalogPreviewLimitDep(request),
        live_discovery: liveDiscovery,
      });
    },
    validateMcp(store, input = {}) {
      const workspaceRoot = pathResolve(
        input.cwd ?? input.workspace_root ?? store.defaultCwd,
      );
      const servers = mcpServerRecordsFromValidationInputDep(input, workspaceRoot, {
        contextPolicyCore,
      });
      const validation = contextPolicyCore.validateMcpServers({ servers });
      const catalog = contextPolicyCore.planMcpManagerCatalogProjection({ servers });
      return contextPolicyCore.planMcpManagerValidationProjection({
        validation_schema_version: validationSchemaVersion,
        validation,
        servers,
        tools: catalog.tools,
        resources: catalog.resources,
        prompts: catalog.prompts,
      });
    },
    mcpCatalogRowsForServers(servers = []) {
      const catalog = contextPolicyCore.planMcpManagerCatalogProjection({ servers });
      return {
        ...catalog,
        tools: normalizeArrayDep(catalog.tools),
        resources: normalizeArrayDep(catalog.resources),
        prompts: normalizeArrayDep(catalog.prompts),
        enabled_tools: normalizeArrayDep(catalog.enabled_tools),
      };
    },
    mcpCatalogSummaryForRows(server, catalog = {}, options = {}) {
      return contextPolicyCore.planMcpManagerCatalogSummaryProjection({
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
      const agentId = optionalStringDep(options.agent_id);
      const sourceMode = mcpConfigSourceModeForRequestDep(options);
      const stateDir = optionalStringDep(options.state_dir) ?? optionalStringDep(store?.stateDir);
      const workspaceServers = threadId || agentId
        ? []
        : mcpRegistryForWorkspaceDep(store.defaultCwd, {
            ...options,
            contextPolicyCore,
            homeDir: store.homeDir,
            mcp_config_source_mode: sourceMode,
          }).servers;
      const catalog = contextPolicyCore.planMcpManagerCatalogProjection({
        servers: normalizeArrayDep(workspaceServers),
        state_dir: stateDir ?? null,
        thread_id: threadId ?? null,
        agent_id: agentId ?? null,
      });
      const servers = normalizeArrayDep(catalog.servers);
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
