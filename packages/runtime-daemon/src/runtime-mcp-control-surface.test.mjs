import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeMcpControlSurface } from "./runtime-mcp-control-surface.mjs";

function server(id, tools = [{ name: "search" }], extra = {}) {
  return {
    id,
    label: id,
    enabled: extra.enabled ?? true,
    status: extra.status ?? "configured",
    transport: extra.transport ?? "stdio",
    tools,
    resources: extra.resources ?? [],
    prompts: extra.prompts ?? [],
    ...extra,
  };
}

function harness() {
  const events = [];
  const writes = [];
  const agent = {
    id: "agent-one",
    cwd: "/workspace",
    runtimeControls: { approval_mode: "agent" },
    mcpRegistry: {
      servers: [
        server("mcp.docs", [
          { name: "search", sideEffectClass: "read" },
          { name: "write", sideEffectClass: "write" },
        ]),
      ],
    },
  };
  const mcpToolsForServers = (servers) =>
    servers.flatMap((item) =>
      (item.tools ?? []).map((tool) => ({
        serverId: item.id,
        server_id: item.id,
        toolName: tool.name,
        tool_name: tool.name,
        stableToolId: `${item.id}.${tool.name}`,
        sideEffectClass: tool.sideEffectClass ?? "read",
        workflowNodeId: `runtime.mcp-tool.${item.id}.${tool.name}`,
      })),
    );
  const surface = createRuntimeMcpControlSurface({
    RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION: "invoke.schema",
    RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION: "status.schema",
    RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION: "validation.schema",
    doctorHash() {
      return "hash1234567890abcdef";
    },
    eventStreamIdForThread(threadId) {
      return `stream:${threadId}`;
    },
    fixtureProfileForAgent() {
      return "fixture.profile";
    },
    mcpRegistryWithServers(registry, servers) {
      return { ...registry, servers };
    },
    mcpServerRecordFromAddRequest(input) {
      return server(input.id ?? "mcp.added", input.tools ?? [{ name: "added" }], input);
    },
    mcpServerRecordsFromMutationInput(input) {
      return input.servers ?? [];
    },
    mcpToolsForServers,
    mcpTransportEvidenceRef() {
      return "mcp.transport.fixture";
    },
    mcpTransportSummary() {
      return "simulated manager receipt";
    },
    resolveMcpToolRecord(servers, toolId, request = {}) {
      const requestedTool = request.tool_name ?? request.toolName ?? request.name ?? String(toolId ?? "").split(".").at(-1);
      const requestedServer = request.server_id ?? request.serverId ?? String(toolId ?? "").split(".").slice(0, -1).join(".");
      const foundServer =
        servers.find((item) => item.id === requestedServer) ??
        servers.find((item) => (item.tools ?? []).some((tool) => tool.name === requestedTool));
      return { server: foundServer ?? null, toolName: requestedTool };
    },
    runtimeError({ status, code, message, details }) {
      const error = new Error(message);
      error.status = status;
      error.code = code;
      error.details = details;
      return error;
    },
    validateMcpServerRecords(servers) {
      const issues = servers.some((item) => item.invalid) ? [{ code: "invalid_server" }] : [];
      return { ok: issues.length === 0, issues, warnings: [] };
    },
  });
  const store = {
    agents: new Map([["agent-one", agent]]),
    homeDir: "/home/user",
    modelMounting: { vault: {} },
    agentForThread(threadId) {
      assert.equal(threadId, "thread-agent-one");
      return this.agents.get("agent-one");
    },
    appendRuntimeEvent(event) {
      const record = {
        ...event,
        event_id: `event-${events.length + 1}`,
        id: `event-${events.length + 1}`,
        seq: events.length + 1,
        created_at: "2026-06-04T12:00:00.000Z",
      };
      events.push(record);
      return record;
    },
    listMcpServers({ thread_id }) {
      assert.equal(thread_id, "thread-agent-one");
      return this.agents.get("agent-one").mcpRegistry.servers;
    },
    mcpStatus({ thread_id }) {
      const servers = this.listMcpServers({ thread_id });
      const tools = mcpToolsForServers(servers);
      return {
        schema_version: "status.schema",
        object: "ioi.runtime_mcp_manager_status",
        status: "ready",
        server_count: servers.length,
        tool_count: tools.length,
        resource_count: 0,
        prompt_count: 0,
        servers,
        tools,
        resources: [],
        prompts: [],
      };
    },
    threadForAgent() {
      return { thread_id: "thread-agent-one", latest_turn_id: "turn-one" };
    },
    validateMcp(input = {}) {
      const servers = input.servers ?? [];
      return {
        schema_version: "validation.schema",
        ok: !servers.some((item) => item.invalid),
        status: servers.some((item) => item.invalid) ? "blocked" : "pass",
        server_count: servers.length,
        issue_count: servers.some((item) => item.invalid) ? 1 : 0,
        issues: servers.some((item) => item.invalid) ? [{ code: "invalid_server" }] : [],
        warnings: [],
        servers,
      };
    },
    writeAgent(record, reason) {
      writes.push({ record, reason });
    },
  };
  return { events, store, surface, writes };
}

test("runtime MCP control surface applies add, remove, and blocked mutation envelopes", () => {
  const { events, store, surface } = harness();

  assert.throws(
    () => surface.importMcp(store, {}),
    (error) => error.status === 400 && error.code === "mcp_thread_required",
  );

  const added = surface.addMcpServer(store, {
    thread_id: "thread-agent-one",
    id: "mcp.extra",
    tools: [{ name: "extra" }],
  });
  assert.equal(added.event_kind, "McpServerAdded");
  assert.equal(added.add_count, 1);
  assert.equal(added.policy_decision, "registry_write_allowed");
  assert.equal(events.at(-1).payload_schema_version, "status.schema");
  assert.equal(store.agents.get("agent-one").mcpRegistry.servers.some((item) => item.id === "mcp.extra"), true);

  const removed = surface.removeThreadMcpServer(store, "thread-agent-one", "mcp.extra");
  assert.equal(removed.event_kind, "McpServerRemoved");
  assert.equal(removed.removed_count, 1);
  assert.equal(store.agents.get("agent-one").mcpRegistry.servers.some((item) => item.id === "mcp.extra"), false);

  const blocked = surface.applyThreadMcpServerMutation(store, {
    threadId: "thread-agent-one",
    agent: store.agents.get("agent-one"),
    request: {},
    mutationKind: "import",
    sourceEventKind: "OperatorControl.McpImport",
    eventKind: "mcp.servers_imported",
    workflowNodeId: "runtime.mcp-manager.import",
    serversToUpsert: [server("mcp.invalid", [], { invalid: true })],
  });
  assert.equal(blocked.event_kind, "McpServersImportBlocked");
  assert.equal(blocked.policy_decision, "registry_write_blocked");
  assert.equal(blocked.issues[0].code, "invalid_server");
  assert.equal(events.at(-1).payload_schema_version, "validation.schema");
});

test("runtime MCP control surface records enable, status, and validation controls", async () => {
  const { events, store, surface, writes } = harness();

  const disabled = surface.setThreadMcpServerEnabled(store, "thread-agent-one", "mcp.docs", false);
  assert.equal(disabled.event_kind, "McpServerDisabled");
  assert.equal(disabled.enabled, false);
  assert.equal(disabled.server.status, "disabled");
  assert.equal(events.at(-1).event_kind, "mcp.server_disabled");

  const status = await surface.recordThreadMcpStatus(store, "thread-agent-one");
  assert.equal(status.event_kind, "McpCatalogStatus");
  assert.match(status.summary, /MCP catalog has 1 server/);

  const validation = surface.validateThreadMcp(store, "thread-agent-one");
  assert.equal(validation.event_kind, "McpValidationReport");
  assert.equal(validation.status, "pass");
  assert.equal(writes.length >= 3, true);
});

test("runtime MCP control surface invokes tools with receipt-backed policy outcomes", async () => {
  const { events, store, surface } = harness();

  const completed = await surface.invokeThreadMcpTool(store, "thread-agent-one", "mcp.docs.search", {
    input: { q: "runtime" },
  });
  assert.equal(completed.event_kind, "McpToolInvocation");
  assert.equal(completed.status, "completed");
  assert.equal(completed.policy_decision, "invoke_allowed");
  assert.equal(completed.invocation.schema_version, "invoke.schema");
  assert.equal(completed.invocation.result.fixture, true);
  assert.deepEqual(completed.invocation.evidence_refs.slice(0, 3), [
    "mcp.manager.tool.invoke",
    "mcp_containment_receipt",
    "mcp.transport.fixture",
  ]);

  const blocked = await surface.invokeThreadMcpTool(store, "thread-agent-one", "mcp.docs.write", {
    input: { path: "README.md" },
  });
  assert.equal(blocked.status, "blocked");
  assert.equal(blocked.policy_decision, "invoke_blocked");
  assert.deepEqual(blocked.invocation.blockers, ["approval_required"]);
  assert.equal(events.at(-1).status, "blocked");
});
