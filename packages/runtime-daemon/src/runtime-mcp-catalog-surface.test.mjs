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
  const modelServer = server("mcp.model.search", "model_mounting", {
    id: "model-search",
    label: "Model Search",
    source: "model_mounting",
    tools: [{ name: "model_search" }],
  });
  const surface = createRuntimeMcpCatalogSurface({
    agentIdForThread(threadId) {
      return threadId.replace(/^thread-/, "");
    },
    mcpConfigSourceModeForRequest(options) {
      return options.config_source_mode ?? options.mcp_config_source_mode ?? "all";
    },
    mcpPromptsForServers(servers) {
      return servers.flatMap((item) => item.prompts ?? []);
    },
    mcpRegistryForWorkspace(cwd, options) {
      calls.push({ name: "mcpRegistryForWorkspace", cwd, options });
      return { servers: [workspaceServer] };
    },
    mcpResourcesForServers(servers) {
      return servers.flatMap((item) => item.resources ?? []);
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
    mcpToolsForServers(servers) {
      return servers.flatMap((item) =>
        (item.tools ?? []).map((tool) => ({
          serverId: item.id,
          toolName: tool.name,
          stableToolId: `${item.id}.${tool.name}`,
        })),
      );
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
    validateMcpServerRecords(servers) {
      const issues = servers.some((item) => item.invalid) ? [{ code: "invalid" }] : [];
      return { ok: issues.length === 0, issues, warnings: [] };
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
        calls.push({ name: "modelMounting.listMcpServers" });
        return [modelServer];
      },
    },
  };
  return { agentServer, calls, modelServer, store, surface, workspaceServer };
}

test("runtime MCP catalog surface lists context servers and filters catalog rows", () => {
  const { calls, store, surface } = harness();

  assert.deepEqual(surface.listMcpServers(store).map((item) => item.id), [
    "mcp.agent.git",
    "mcp.workspace.docs",
    "model-search",
  ]);
  assert.deepEqual(
    surface
      .listMcpServers(store, {
        thread_id: "thread-agent-one",
        threadId: "thread-retired",
        agentId: "retired-agent",
      })
      .map((item) => item.id),
    ["mcp.agent.git", "model-search"],
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
      serverId: "mcp.agent.git",
      stableToolId: "mcp.agent.git.diff",
      toolName: "diff",
    },
  ]);
  assert.equal(surface.listMcpResources(store).length, 3);
  assert.equal(surface.listMcpPrompts(store).length, 3);
  assert.equal(calls.some((call) => call.name === "normalizeMcpServerRecord"), true);
});

test("runtime MCP catalog surface projects status and validation envelopes", () => {
  const { store, surface } = harness();

  const status = surface.mcpStatus(store);
  assert.equal(status.schema_version, "ioi.runtime.mcp-manager-status.v1");
  assert.equal(status.status, "ready");
  assert.equal(status.server_count, 3);
  assert.equal(status.tool_count, 3);
  assert.equal(status.resource_count, 3);
  assert.equal(status.prompt_count, 3);
  assert.equal(status.enabled_server_count, 3);
  assert.equal(status.validation.server_count, 3);
  assert.equal(status.routes.searchTools, "/v1/mcp/tools/search");

  const validation = surface.validateMcp(store, {
    cwd: "/custom",
    servers: [server("mcp.valid"), server("mcp.invalid", "workspace", { invalid: true })],
  });
  assert.equal(validation.schema_version, "ioi.runtime.mcp-manager-validation.v1");
  assert.equal(validation.ok, false);
  assert.equal(validation.status, "blocked");
  assert.equal(validation.server_count, 2);
  assert.equal(validation.issue_count, 1);
  assert.equal(validation.tools.length, 2);
});

test("runtime MCP catalog surface searches and fetches tools through global and thread contexts", async () => {
  const { calls, store, surface } = harness();

  const globalSearch = await surface.searchMcpTools(store, {
    query: "diff",
    liveDiscovery: false,
  });
  assert.equal(globalSearch.schema_version, "ioi.runtime.mcp-tool-search.v1");
  assert.equal(globalSearch.status, "completed");
  assert.equal(globalSearch.server_count, 3);
  assert.deepEqual(globalSearch.tools.map((tool) => tool.stableToolId), ["mcp.agent.git.diff"]);
  assert.equal(globalSearch.routes.getTool, "/v1/mcp/tools/{tool_id}");

  const threadSearch = await surface.searchMcpTools(store, {
    thread_id: "thread-agent-one",
    query: "diff",
    liveDiscovery: false,
  });
  assert.equal(threadSearch.server_count, 2);
  assert.deepEqual(threadSearch.tools.map((tool) => tool.stableToolId), ["mcp.agent.git.diff"]);
  assert.equal(calls.some((call) => call.name === "agentForThread"), true);

  const fetched = await surface.getMcpTool(store, "mcp.agent.git.diff", {
    threadId: "thread-agent-one",
    liveDiscovery: false,
  });
  assert.equal(fetched.object, "ioi.runtime_mcp_tool_fetch");
  assert.equal(fetched.status, "completed");
  assert.equal(fetched.tool_id, "mcp.agent.git.diff");
  assert.equal(fetched.server_id, "mcp.agent.git");
  assert.equal(fetched.tool_name, "diff");
  assert.equal(fetched.returned_count, 1);

  await assert.rejects(
    () => surface.getMcpTool(store, "mcp.missing.nope", { liveDiscovery: false }),
    (error) => error.status === 404 && error.code === "not_found",
  );
});
