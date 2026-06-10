import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeMcpCatalogSurface } from "./runtime-mcp-catalog-surface.mjs";

function server(id, sourceScope = "workspace", extra = {}) {
  return {
    id,
    label: id,
    enabled: extra.enabled ?? true,
    sourceScope,
    tools: extra.tools ?? [{ name: "search" }],
    resources: extra.resources ?? [{ uri: `${id}://root` }],
    prompts: extra.prompts ?? [{ name: "ask" }],
    ...extra,
  };
}

function harness() {
  const calls = [];
  const workspaceServer = server("mcp.workspace.docs", "workspace");
  const agentServer = server("mcp.agent.git", "thread", { tools: [{ name: "diff" }] });
  const surface = createRuntimeMcpCatalogSurface({
    agentIdForThread(threadId) {
      return threadId.replace(/^thread-/, "");
    },
    mcpConfigSourceModeForRequest(options) {
      return options.config_source_mode ?? options.mcp_config_source_mode ?? "all";
    },
    discoverMcpStdioCatalog(server, options) {
      calls.push({ name: "discoverMcpStdioCatalog", server, options });
      return { tools: server.tools ?? [], resources: server.resources ?? [], prompts: server.prompts ?? [] };
    },
    mcpLiveExecutionModeForServer(server, request = {}) {
      return request.live_discovery === true || server.execution_mode === "live_stdio" ? "live_stdio" : null;
    },
    mcpRegistryForWorkspace(cwd, options) {
      calls.push({ name: "mcpRegistryForWorkspace", cwd, options });
      return { servers: [workspaceServer] };
    },
    mcpServerMatchesConfigSourceMode(item, sourceMode) {
      if (sourceMode === "workspace") return item.sourceScope === "workspace";
      if (sourceMode === "thread") return item.sourceScope === "thread";
      return true;
    },
    mcpServerRecordsFromValidationInput(input, workspaceRoot) {
      calls.push({ name: "mcpServerRecordsFromValidationInput", input, workspaceRoot });
      return input.servers ?? [];
    },
    contextPolicyRunner: {
      validateMcpServers(request) {
        calls.push({ name: "validateMcpServers", request });
        const issues = request.servers.some((item) => item.invalid)
          ? [{ code: "invalid", server_id: "mcp.invalid" }]
          : [];
        return {
          source: "rust_mcp_server_validation_command",
          backend: "rust_policy",
          ok: issues.length === 0,
          status: issues.length === 0 ? "pass" : "blocked",
          issue_count: issues.length,
          warning_count: 0,
          issues,
          warnings: [],
        };
      },
      planMcpManagerCatalogProjection(request) {
        calls.push({ name: "planMcpManagerCatalogProjection", request });
        const tools = request.servers.flatMap((item) =>
          (item.tools ?? []).map((tool) => ({
            server_id: item.id,
            tool_name: tool.name,
            stable_tool_id: `${item.id}.${tool.name}`,
          })),
        );
        const resources = request.servers.flatMap((item) => item.resources ?? []);
        const prompts = request.servers.flatMap((item) => item.prompts ?? []);
        return {
          source: "rust_mcp_manager_catalog_projection_command",
          backend: "rust_policy",
          status: "projected",
          server_count: request.servers.length,
          tool_count: tools.length,
          resource_count: resources.length,
          prompt_count: prompts.length,
          enabled_tool_count: tools.length,
          servers: request.servers,
          tools,
          resources,
          prompts,
          enabled_tools: tools,
        };
      },
      planMcpManagerCatalogSummaryProjection(request) {
        calls.push({ name: "planMcpManagerCatalogSummaryProjection", request });
        const toolNames = request.tools.map((tool) => tool.tool_name).filter(Boolean).sort();
        return {
          source: "rust_mcp_manager_catalog_summary_projection_command",
          backend: "rust_policy",
          schema_version: "ioi.runtime.mcp-manager-catalog-summary.v1",
          object: "ioi.runtime_mcp_catalog_summary",
          status: request.status ?? "completed",
          server_id: request.server.id,
          server_label: request.server.label ?? request.server.id,
          transport: request.server.transport ?? null,
          execution_mode: request.live_mode ?? null,
          catalog_hash: `summary:${request.server.id}:${request.tools.length}`,
          tool_count: request.tools.length,
          resource_count: request.resources.length,
          prompt_count: request.prompts.length,
          namespace_count: toolNames.length,
          namespaces: toolNames,
          preview_limit: request.preview_limit ?? 25,
          preview_tool_names: toolNames.slice(0, 20),
          deferred: request.deferred ?? false,
          full_catalog_included: !(request.deferred ?? false),
          error_code: request.error_code ?? null,
          search_route: "/v1/mcp/tools/search",
          fetch_route: "/v1/mcp/tools/{tool_id}",
        };
      },
      planMcpManagerValidationProjection(request) {
        calls.push({ name: "planMcpManagerValidationProjection", request });
        return {
          source: "rust_mcp_manager_validation_projection_command",
          backend: "rust_policy",
          schema_version: request.validation_schema_version,
          object: "ioi.runtime_mcp_manager_validation",
          ok: request.validation.ok,
          status: request.validation.ok ? "pass" : "blocked",
          server_count: request.servers.length,
          tool_count: request.tools.length,
          resource_count: request.resources.length,
          prompt_count: request.prompts.length,
          issue_count: request.validation.issues.length,
          warning_count: request.validation.warnings.length,
          issues: request.validation.issues,
          warnings: request.validation.warnings,
          servers: request.servers,
          tools: request.tools,
          resources: request.resources,
          prompts: request.prompts,
        };
      },
      planMcpManagerStatusProjection(request) {
        calls.push({ name: "planMcpManagerStatusProjection", request });
        const validation = {
          ...request.validation,
          server_count: request.servers.length,
          tool_count: request.tools.length,
          resource_count: request.resources.length,
          prompt_count: request.prompts.length,
          servers: request.servers,
          tools: request.tools,
          resources: request.resources,
          prompts: request.prompts,
        };
        return {
          source: "rust_mcp_manager_status_projection_command",
          backend: "rust_policy",
          schema_version: request.status_schema_version,
          object: "ioi.runtime_mcp_manager_status",
          status: validation.ok ? "ready" : "needs_review",
          server_count: request.servers.length,
          tool_count: request.tools.length,
          resource_count: request.resources.length,
          prompt_count: request.prompts.length,
          enabled_server_count: request.servers.filter((item) => item.enabled !== false).length,
          servers: request.servers,
          tools: request.tools,
          resources: request.resources,
          prompts: request.prompts,
          validation,
          routes: request.routes,
        };
      },
    },
    normalizeMcpServerRecord(label, input, context) {
      calls.push({ name: "normalizeMcpServerRecord", label, input, context });
      return {
        ...input,
        id: input.id ?? `mcp.${label}`,
        label,
        enabled: input.enabled !== false,
        sourceScope: context.sourceScope,
        tools: input.tools ?? [],
        resources: input.resources ?? [],
        prompts: input.prompts ?? [],
      };
    },
    pathResolve(value) {
      return `/resolved${value}`;
    },
  });
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/user",
    agents: new Map([
      ["agent-one", { id: "agent-one", mcpRegistry: { servers: [agentServer] } }],
    ]),
    getAgent(agentId) {
      calls.push({ name: "getAgent", agentId });
      return this.agents.get(agentId);
    },
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      return this.getAgent(threadId.replace(/^thread-/, ""));
    },
    modelMounting: {
      listMcpServers() {
        throw new Error("runtime MCP catalog must not read model-mounting MCP server maps");
      },
    },
  };
  return { agentServer, calls, store, surface, workspaceServer };
}

test("runtime MCP catalog surface lists context servers and filters catalog rows", () => {
  const { calls, store, surface } = harness();

  assert.deepEqual(surface.listMcpServers(store).map((item) => item.id), [
    "mcp.agent.git",
    "mcp.workspace.docs",
  ]);
  assert.deepEqual(
    surface
      .listMcpServers(store, {
        thread_id: "thread-agent-one",
        threadId: "thread-retired",
        agentId: "retired-agent",
      })
      .map((item) => item.id),
    ["mcp.agent.git"],
  );
  assert.deepEqual(
    surface
      .listMcpServers(store, {
        config_source_mode: "workspace",
        configSourceMode: "thread",
      })
      .map((item) => item.id),
    ["mcp.workspace.docs"],
  );
  assert.deepEqual(surface.listMcpTools(store, { server_id: "mcp.agent.git", serverId: "retired-server" }), [
    {
      server_id: "mcp.agent.git",
      stable_tool_id: "mcp.agent.git.diff",
      tool_name: "diff",
    },
  ]);
  assert.equal(surface.listMcpResources(store).length, 2);
  assert.equal(surface.listMcpPrompts(store).length, 2);
  assert.equal(calls.some((call) => call.name === "normalizeMcpServerRecord"), false);
});

test("runtime MCP catalog surface projects status and validation envelopes", () => {
  const { calls, store, surface } = harness();

  const status = surface.mcpStatus(store);
  assert.equal(status.schema_version, "ioi.runtime.mcp-manager-status.v1");
  assert.equal(status.status, "ready");
  assert.equal(status.server_count, 2);
  assert.equal(status.tool_count, 2);
  assert.equal(status.resource_count, 2);
  assert.equal(status.prompt_count, 2);
  assert.equal(status.enabled_server_count, 2);
  assert.equal(status.source, "rust_mcp_manager_status_projection_command");
  assert.equal(status.validation.source, "rust_mcp_server_validation_command");
  assert.equal(status.validation.server_count, 2);
  assert.equal(
    calls.find((call) => call.name === "planMcpManagerCatalogProjection")?.request.servers.length,
    2,
  );
  assert.equal(status.routes.search_tools, "/v1/mcp/tools/search");
  assert.equal(Object.hasOwn(status, "schemaVersion"), false);
  assert.equal(Object.hasOwn(status, "serverCount"), false);
  assert.equal(Object.hasOwn(status, "toolCount"), false);
  assert.equal(Object.hasOwn(status, "enabledServerCount"), false);
  assert.equal(Object.hasOwn(status.validation, "serverCount"), false);
  assert.equal(Object.hasOwn(status.validation, "toolCount"), false);
  assert.equal(Object.hasOwn(status.routes, "searchTools"), false);
  assert.equal(Object.hasOwn(status.routes, "serveForThread"), false);

  const validation = surface.validateMcp(store, {
    cwd: "/custom",
    workspaceRoot: "/retired",
    servers: [server("mcp.valid"), server("mcp.invalid", "workspace", { invalid: true })],
  });
  assert.equal(validation.schema_version, "ioi.runtime.mcp-manager-validation.v1");
  assert.equal(validation.ok, false);
  assert.equal(validation.status, "blocked");
  assert.equal(validation.server_count, 2);
  assert.equal(validation.issue_count, 1);
  assert.equal(validation.issues[0].server_id, "mcp.invalid");
  assert.equal(validation.tools.length, 2);
  assert.equal(validation.source, "rust_mcp_manager_validation_projection_command");
  assert.equal(Object.hasOwn(validation, "schemaVersion"), false);
  assert.equal(Object.hasOwn(validation, "serverCount"), false);
  assert.equal(Object.hasOwn(validation, "issueCount"), false);
  assert.equal(Object.hasOwn(validation, "warningCount"), false);
  assert.deepEqual(
    calls.find((call) => call.name === "mcpServerRecordsFromValidationInput")?.workspaceRoot,
    "/resolved/custom",
  );
  assert.equal(
    calls.find((call) => call.name === "planMcpManagerValidationProjection")?.request.tools.length,
    2,
  );
  assert.equal(
    calls.find((call) => call.name === "planMcpManagerValidationProjection")?.request.validation.issues[0].server_id,
    "mcp.invalid",
  );
  assert.deepEqual(
    calls.find((call) => call.name === "validateMcpServers")?.request.servers.map((item) => item.id),
    ["mcp.agent.git", "mcp.workspace.docs"],
  );
  assert.deepEqual(
    calls.find((call) => call.name === "planMcpManagerStatusProjection")?.request.servers.map((item) => item.id),
    ["mcp.agent.git", "mcp.workspace.docs"],
  );
  assert.equal(
    calls.find((call) => call.name === "planMcpManagerStatusProjection")?.request.tools[0].stable_tool_id,
    "mcp.agent.git.diff",
  );
  assert.equal(
    calls.find((call) => call.name === "planMcpManagerStatusProjection")?.request.routes.search_tools,
    "/v1/mcp/tools/search",
  );
  assert.deepEqual(
    calls.filter((call) => call.name === "validateMcpServers").at(-1)?.request.servers.map((item) => item.id),
    ["mcp.valid", "mcp.invalid"],
  );

  surface.validateMcp(store, {
    workspaceRoot: "/retired",
    servers: [server("mcp.valid")],
  });
  assert.deepEqual(
    calls.filter((call) => call.name === "mcpServerRecordsFromValidationInput").at(-1)?.workspaceRoot,
    "/resolved/workspace",
  );
});

test("runtime MCP catalog surface searches and fetches tools through global and thread contexts", async () => {
  const { calls, store, surface } = harness();

  const globalSearch = await surface.searchMcpTools(store, {
    query: "diff",
    live_discovery: false,
    liveDiscovery: true,
    toolId: "mcp.workspace.docs.search",
    serverId: "mcp.workspace.docs",
    catalogPreviewLimit: 1,
  });
  assert.equal(globalSearch.schema_version, "ioi.runtime.mcp-tool-search.v1");
  assert.equal(globalSearch.status, "completed");
  assert.equal(globalSearch.server_count, 2);
  assert.deepEqual(globalSearch.tools.map((tool) => tool.stable_tool_id), ["mcp.agent.git.diff"]);
  assert.equal(globalSearch.routes.get_tool, "/v1/mcp/tools/{tool_id}");
  assert.equal(
    globalSearch.catalog_summaries[0].source,
    "rust_mcp_manager_catalog_summary_projection_command",
  );
  assert.equal(Object.hasOwn(globalSearch, "schemaVersion"), false);
  assert.equal(Object.hasOwn(globalSearch, "liveDiscovery"), false);
  assert.equal(Object.hasOwn(globalSearch, "serverCount"), false);
  assert.equal(Object.hasOwn(globalSearch, "returnedCount"), false);
  assert.equal(Object.hasOwn(globalSearch, "catalogSummaries"), false);
  assert.equal(Object.hasOwn(globalSearch.routes, "getTool"), false);

  const threadSearch = await surface.searchMcpTools(store, {
    thread_id: "thread-agent-one",
    query: "diff",
    live_discovery: false,
    liveDiscovery: true,
  });
  assert.equal(threadSearch.server_count, 1);
  assert.deepEqual(threadSearch.tools.map((tool) => tool.stable_tool_id), ["mcp.agent.git.diff"]);
  assert.equal(calls.some((call) => call.name === "agentForThread"), true);
  assert.equal(
    calls.some((call) => call.name === "planMcpManagerCatalogSummaryProjection"),
    true,
  );

  const fetched = await surface.getMcpTool(store, "mcp.agent.git.diff", {
    thread_id: "thread-agent-one",
    threadId: "thread-retired",
    live_discovery: false,
    liveDiscovery: true,
    toolId: "mcp.workspace.docs.search",
  });
  assert.equal(fetched.object, "ioi.runtime_mcp_tool_fetch");
  assert.equal(fetched.status, "completed");
  assert.equal(fetched.tool_id, "mcp.agent.git.diff");
  assert.equal(fetched.server_id, "mcp.agent.git");
  assert.equal(fetched.tool_name, "diff");
  assert.equal(fetched.returned_count, 1);
  assert.equal(Object.hasOwn(fetched, "toolId"), false);
  assert.equal(Object.hasOwn(fetched, "serverId"), false);
  assert.equal(Object.hasOwn(fetched, "toolName"), false);
  assert.equal(Object.hasOwn(fetched, "returnedCount"), false);

  await assert.rejects(
    () => surface.getMcpTool(store, "mcp.missing.nope", { live_discovery: false }),
    (error) =>
      error.status === 404 &&
      error.code === "not_found" &&
      error.details.tool_id === "mcp.missing.nope" &&
      Object.hasOwn(error.details, "toolId") === false,
  );
});

test("runtime MCP catalog surface ignores retired timeoutMs request alias", async () => {
  const { calls, store, surface } = harness();

  await surface.searchMcpTools(store, {
    thread_id: "thread-agent-one",
    live_discovery: true,
    timeout_ms: 2345,
    timeoutMs: 9999,
  });
  const canonicalCall = calls.find((call) => call.name === "discoverMcpStdioCatalog");
  assert.equal(canonicalCall.options.timeout_ms, 2345);
  assert.equal(Object.hasOwn(canonicalCall.options, "timeoutMs"), false);

  calls.length = 0;
  await surface.searchMcpTools(store, {
    thread_id: "thread-agent-one",
    live_discovery: true,
    timeoutMs: 9999,
  });
  const aliasOnlyCall = calls.find((call) => call.name === "discoverMcpStdioCatalog");
  assert.equal(aliasOnlyCall.options.timeout_ms, undefined);
  assert.equal(Object.hasOwn(aliasOnlyCall.options, "timeoutMs"), false);
});
