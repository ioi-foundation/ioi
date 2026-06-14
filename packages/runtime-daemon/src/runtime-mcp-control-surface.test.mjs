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

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function failIfCalled(name) {
  return () => {
    throw new Error(`${name} must not be reached by the Rust-owned MCP control surface`);
  };
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function planMcpControlAgentStateUpdate(request) {
  const agent = cloneJson(request.agent);
  const payload = request.request ?? {};
  const registry = agent.mcpRegistry ?? { servers: [] };
  let servers = Array.isArray(registry.servers) ? registry.servers.map((item) => cloneJson(item)) : [];
  const serverId = payload.server_id ?? payload.server?.id ?? null;
  if (request.control_kind === "mcp_import") {
    servers = Array.isArray(payload.servers) ? payload.servers.map((item) => cloneJson(item)) : [];
  } else if (request.control_kind === "mcp_add" && payload.server) {
    const next = cloneJson(payload.server);
    const index = servers.findIndex((item) => item.id === next.id);
    if (index >= 0) servers[index] = next;
    else servers.push(next);
  } else if (request.control_kind === "mcp_remove" && serverId) {
    servers = servers.filter((item) => item.id !== serverId);
  } else if ((request.control_kind === "mcp_enable" || request.control_kind === "mcp_disable") && serverId) {
    servers = servers.map((item) =>
      item.id === serverId
        ? {
            ...item,
            enabled: request.control_kind === "mcp_enable",
            status: request.control_kind === "mcp_enable" ? "configured" : "disabled",
          }
        : item,
    );
  }
  agent.mcpRegistry = { servers };
  agent.updatedAt = request.created_at;
  return {
    source: "rust_mcp_control_agent_state_update_command",
    backend: "rust_policy",
    schema_version: "ioi.runtime.mcp-control-agent-state-update.v1",
    object: "ioi.runtime_mcp_control_agent_state_update",
    status: "planned",
    operation_kind: `thread.${request.control_kind}`,
    thread_id: request.thread_id,
    agent_id: agent.id,
    updated_at: request.created_at,
    control: {
      control_kind: request.control_kind,
      event_id: request.event_id,
      seq: request.seq,
      created_at: request.created_at,
      server_id: serverId,
      server_count: servers.length,
      enabled_server_count: servers.filter((item) => item.enabled !== false).length,
      registry_hash: `hash.${servers.map((item) => item.id).join(".")}`,
      mutation_applied: ["mcp_import", "mcp_add", "mcp_remove", "mcp_enable", "mcp_disable"].includes(
        request.control_kind,
      ),
    },
    agent,
  };
}

function harness(options = {}) {
  const calls = [];
  let agent = {
    id: "agent-one",
    cwd: "/workspace",
    runtimeControls: { approval_mode: "agent" },
    mcpRegistry: {
      servers: [
        server("mcp.docs", [
          { name: "search", side_effect_class: "read" },
          { name: "write", side_effect_class: "write" },
        ], {
          resources: [{ uri: "docs://index" }],
          prompts: [{ name: "summarize" }],
        }),
      ],
    },
  };
  const contextPolicyCore = options.contextPolicyCore ?? {
    validateMcpServers(request) {
      calls.push({ name: "validateMcpServers", request });
      const issues = request.servers.some((item) => item.invalid) ? [{ code: "invalid_server" }] : [];
      return {
        source: "rust_mcp_server_validation_command",
        ok: issues.length === 0,
        status: issues.length === 0 ? "pass" : "blocked",
        issues,
        warnings: [],
      };
    },
    planMcpManagerCatalogProjection(request) {
      calls.push({ name: "planMcpManagerCatalogProjection", request });
      const tools = request.servers.flatMap((item) =>
        (item.tools ?? item.allowed_tools ?? []).map((tool) => ({
          server_id: item.id,
          tool_name: tool.name ?? tool,
          stable_tool_id: `${item.id}.${tool.name ?? tool}`,
          side_effect_class: tool.side_effect_class ?? "read",
        })),
      );
      const resources = request.servers.flatMap((item) => item.resources ?? []);
      const prompts = request.servers.flatMap((item) => item.prompts ?? []);
      return {
        source: "rust_mcp_manager_catalog_projection_command",
        schema_version: "catalog.schema",
        object: "ioi.runtime_mcp_manager_catalog_projection",
        status: "projected",
        server_count: request.servers.length,
        tool_count: tools.length,
        enabled_tool_count: tools.length,
        resource_count: resources.length,
        prompt_count: prompts.length,
        servers: request.servers,
        tools,
        enabled_tools: tools,
        resources,
        prompts,
      };
    },
    planMcpManagerStatusProjection(request) {
      calls.push({ name: "planMcpManagerStatusProjection", request });
      return {
        source: "rust_mcp_manager_status_projection_command",
        schema_version: request.status_schema_version,
        object: "ioi.runtime_mcp_manager_status",
        status: request.validation.ok ? "ready" : "needs_review",
        server_count: request.servers.length,
        enabled_server_count: request.servers.filter((item) => item.enabled !== false).length,
        tool_count: request.tools.length,
        enabled_tool_count: request.enabled_tools.length,
        resource_count: request.resources.length,
        prompt_count: request.prompts.length,
        servers: request.servers,
        tools: request.tools,
        resources: request.resources,
        prompts: request.prompts,
        validation: {
          ...request.validation,
          server_count: request.servers.length,
          tool_count: request.tools.length,
          resource_count: request.resources.length,
          prompt_count: request.prompts.length,
        },
      };
    },
    planMcpControlAgentStateUpdate(request) {
      calls.push({ name: "planMcpControlAgentStateUpdate", request: cloneJson(request) });
      return planMcpControlAgentStateUpdate(request);
    },
  };
  const surface = createRuntimeMcpControlSurface({
    RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION: "invoke.schema",
    RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION: "status.schema",
    RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION: "validation.schema",
    runtimeError,
    contextPolicyCore,
    eventStreamIdForThread: (threadId) => `events_${threadId}`,
    nowIso: () => "2026-06-06T06:30:00.000Z",
  });
  const store = {
    agents: { set: failIfCalled("agents.set") },
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      return agent;
    },
    appendRuntimeEvent: failIfCalled("appendRuntimeEvent"),
    latestRuntimeEventSeq(eventStreamId) {
      calls.push({ name: "latestRuntimeEventSeq", eventStreamId });
      return 8;
    },
    listMcpServers: failIfCalled("listMcpServers"),
    mcpStatus: failIfCalled("mcpStatus"),
    threadForAgent: failIfCalled("threadForAgent"),
    validateMcp: failIfCalled("validateMcp"),
    writeAgent(record, operationKind) {
      calls.push({ name: "writeAgent", agent: cloneJson(record), operationKind });
      agent = cloneJson(record);
      return {
        agent_id: record.id,
        operation_kind: operationKind,
        commit_hash: `commit.${operationKind}`,
      };
    },
    ...options.store,
  };
  return { agent, calls, store, surface };
}

function assertNoRetiredDetailAliases(details) {
  for (const alias of [
    "threadId",
    "serverId",
    "toolId",
    "toolName",
    "controlKind",
    "operationKind",
    "expectedOperationKind",
    "requiredCore",
    "migrationTransportOnly",
  ]) {
    assert.equal(Object.hasOwn(details ?? {}, alias), false, `${alias} detail alias must be absent`);
  }
}

function assertRustCoreRequired(error, operation, operationKind) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "mcp_control_rust_core_required");
  assert.equal(error.details.boundary, "runtime.mcp_control");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.required_core, "rust_daemon_core");
  assert.equal(error.details.migration_transport_only, false);
  assertNoRetiredDetailAliases(error.details);
}

test("runtime MCP control surface keeps read-only status projection canonical", () => {
  const { agent, calls, surface } = harness();

  const status = surface.mcpStatusForAgent(agent);

  assert.equal(status.schema_version, "status.schema");
  assert.equal(status.object, "ioi.runtime_mcp_manager_status");
  assert.equal(status.status, "ready");
  assert.equal(status.server_count, 1);
  assert.equal(status.enabled_server_count, 1);
  assert.equal(status.tool_count, 2);
  assert.equal(status.enabled_tool_count, 2);
  assert.equal(status.resource_count, 1);
  assert.equal(status.prompt_count, 1);
  assert.equal(status.source, "rust_mcp_manager_status_projection_command");
  assert.equal(status.validation.source, "rust_mcp_server_validation_command");
  assert.equal(
    calls.find((call) => call.name === "planMcpManagerCatalogProjection")?.request.servers[0].id,
    "mcp.docs",
  );
  assert.deepEqual(status.tools.map((tool) => tool.stable_tool_id), [
    "mcp.docs.search",
    "mcp.docs.write",
  ]);
  assert.deepEqual(
    calls.find((call) => call.name === "validateMcpServers")?.request.servers.map((item) => item.id),
    ["mcp.docs"],
  );
  assert.equal(
    calls.find((call) => call.name === "planMcpManagerStatusProjection")?.request.enabled_tools.length,
    2,
  );
  assert.equal(Object.hasOwn(status.resources[0], "serverId"), false);
  assert.equal(Object.hasOwn(status, "schemaVersion"), false);
  assert.equal(Object.hasOwn(status, "serverCount"), false);
  assert.equal(Object.hasOwn(status, "enabledServerCount"), false);
});

test("runtime MCP control facade rejects retired threadId alias before JS lookup", async () => {
  const { store, surface } = harness();

  assert.throws(
    () => surface.importMcp(store, { threadId: "thread-agent-one", servers: [] }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "mcp_thread_required");
      assertNoRetiredDetailAliases(error.details);
      return true;
    },
  );
  assert.throws(
    () => surface.addMcpServer(store, { threadId: "thread-agent-one", id: "mcp.new" }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "mcp_thread_required");
      assertNoRetiredDetailAliases(error.details);
      return true;
    },
  );
  await assert.rejects(
    () => surface.invokeMcpTool(store, { threadId: "thread-retired", tool_id: "mcp.docs.search" }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "mcp_thread_required");
      assertNoRetiredDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime MCP control mutations plan in Rust and commit agent state without JS state mutation", () => {
  const { calls, store, surface } = harness();

  const imported = surface.importMcp(store, {
    thread_id: "thread-agent-one",
    servers: [server("mcp.imported", [{ name: "lookup" }], { serverId: "retired" })],
    mcpServers: [server("mcp.retired")],
  });
  const added = surface.addMcpServer(store, {
    thread_id: "thread-agent-one",
    id: "mcp.git",
    label: "Git",
    transport: "stdio",
    command: "npx",
    tools: [{ name: "diff" }],
    serverId: "mcp.retired",
  });
  const disabled = surface.setMcpServerEnabled(store, "mcp.git", false, {
    thread_id: "thread-agent-one",
  });
  const status = surface.recordThreadMcpStatus(store, "thread-agent-one", { status: "ready" });
  const validation = surface.validateThreadMcp(store, "thread-agent-one", {
    validation: { ok: true },
  });
  const appended = surface.appendThreadMcpControlEvent(store, {
    thread_id: "thread-agent-one",
    control_kind: "mcp_invoke",
  });
  const removed = surface.removeMcpServer(store, "mcp.git", { thread_id: "thread-agent-one" });

  assert.equal(imported.source, "rust_mcp_control_agent_state_update_command");
  assert.equal(added.operation_kind, "thread.mcp_add");
  assert.equal(disabled.control.enabled_server_count, 1);
  assert.equal(status.operation_kind, "thread.mcp_status");
  assert.equal(validation.operation_kind, "thread.mcp_validate");
  assert.equal(appended.operation_kind, "thread.mcp_invoke");
  assert.equal(removed.operation_kind, "thread.mcp_remove");
  assert.equal(added.commit.operation_kind, "thread.mcp_add");
  assert.equal(removed.commit.operation_kind, "thread.mcp_remove");

  const planCalls = calls.filter((call) => call.name === "planMcpControlAgentStateUpdate");
  assert.deepEqual(planCalls.map((call) => call.request.control_kind), [
    "mcp_import",
    "mcp_add",
    "mcp_disable",
    "mcp_status",
    "mcp_validate",
    "mcp_invoke",
    "mcp_remove",
  ]);
  assert.equal(planCalls[0].request.thread_id, "thread-agent-one");
  assert.equal(planCalls[0].request.request.servers[0].id, "mcp.imported");
  assert.equal(planCalls[1].request.request.server.id, "mcp.git");
  assert.equal(planCalls[2].request.request.server_id, "mcp.git");
  assert.equal(planCalls[0].request.seq, 9);
  assert.equal(planCalls[0].request.event_id, "mcp_control_thread-agent-one_mcp_import_2026-06-06T06_30_00.000Z");
  for (const call of planCalls) {
    const payload = JSON.stringify(call.request.request);
    assert.equal(payload.includes("threadId"), false);
    assert.equal(payload.includes("serverId"), false);
    assert.equal(payload.includes("mcpServers"), false);
    assert.equal(payload.includes("controlKind"), false);
  }
  assert.deepEqual(
    calls.filter((call) => call.name === "writeAgent").map((call) => call.operationKind),
    [
      "thread.mcp_import",
      "thread.mcp_add",
      "thread.mcp_disable",
      "thread.mcp_status",
      "thread.mcp_validate",
      "thread.mcp_invoke",
      "thread.mcp_remove",
    ],
  );
  assert.equal(calls.some((call) => call.name === "latestRuntimeEventSeq"), true);
});

test("runtime MCP control planner absence fails closed before JS state mutation", () => {
  const { store, surface } = harness({
    contextPolicyCore: {},
    store: {
      agentForThread: failIfCalled("agentForThread"),
      writeAgent: failIfCalled("writeAgent"),
    },
  });

  assert.throws(
    () => surface.addMcpServer(store, { thread_id: "thread-agent-one", id: "mcp.new" }),
    (error) => {
      assertRustCoreRequired(error, "add_mcp_server", "thread.mcp_add");
      return true;
    },
  );
});

test("runtime MCP live exits use Rust control admission before JS transport invocation", async () => {
  const { agent, calls, store, surface } = harness();

  const invoked = await surface.invokeMcpTool(store, {
    thread_id: "thread-agent-one",
    server_id: "mcp.docs",
    tool_id: "mcp.docs.search",
    tool_name: "search",
    live_transport: "stdio",
    execution_mode: "live",
    timeout_ms: 2500,
    timeoutMs: 999,
  });
  const discovered = await surface.mcpStatusWithLiveDiscovery(
    store,
    { status: "ready", servers: [] },
    agent,
    {
      thread_id: "thread-agent-one",
      server_id: "mcp.docs",
      live_transport: "stdio",
      execution_mode: "discovery",
      timeout_ms: 1500,
      liveDiscovery: true,
    },
  );

  assert.equal(invoked.operation_kind, "thread.mcp_invoke");
  assert.equal(invoked.control.control_kind, "mcp_invoke");
  assert.equal(invoked.commit.operation_kind, "thread.mcp_invoke");
  assert.equal(discovered.operation_kind, "thread.mcp_live_discovery");
  assert.equal(discovered.control.control_kind, "mcp_live_discovery");
  assert.equal(discovered.commit.operation_kind, "thread.mcp_live_discovery");

  const planCalls = calls.filter((call) => call.name === "planMcpControlAgentStateUpdate");
  assert.deepEqual(planCalls.map((call) => call.request.control_kind), ["mcp_invoke", "mcp_live_discovery"]);
  assert.deepEqual(planCalls.map((call) => call.request.request.timeout_ms), [2500, 1500]);
  assert.equal(planCalls[0].request.request.tool_id, "mcp.docs.search");
  assert.equal(planCalls[0].request.request.tool_name, "search");
  assert.equal(planCalls[0].request.request.server_id, "mcp.docs");
  assert.equal(planCalls[0].request.request.live_transport, "stdio");
  assert.equal(planCalls[0].request.request.execution_mode, "live");
  assert.equal(planCalls[1].request.request.execution_mode, "discovery");
  assert.equal(JSON.stringify(planCalls[0].request.request).includes("timeoutMs"), false);
  assert.equal(JSON.stringify(planCalls[1].request.request).includes("liveDiscovery"), false);
  assert.deepEqual(
    calls.filter((call) => call.name === "writeAgent").map((call) => call.operationKind),
    ["thread.mcp_invoke", "thread.mcp_live_discovery"],
  );
});

test("runtime MCP live exits fail closed when Rust control planner is missing", async () => {
  const { agent, store, surface } = harness({
    contextPolicyCore: {},
    store: {
      agentForThread: failIfCalled("agentForThread"),
      writeAgent: failIfCalled("writeAgent"),
    },
  });

  await assert.rejects(
    () =>
      surface.invokeMcpTool(store, {
        thread_id: "thread-agent-one",
        tool_id: "mcp.docs.search",
      }),
    (error) => {
      assertRustCoreRequired(error, "invoke_mcp_tool", "thread.mcp_invoke");
      assert.equal(error.details.thread_id, "thread-agent-one");
      return true;
    },
  );
  await assert.rejects(
    () =>
      surface.mcpStatusWithLiveDiscovery(
        store,
        { status: "ready", servers: [] },
        agent,
        { thread_id: "thread-agent-one", live_discovery: true },
      ),
    (error) => {
      assertRustCoreRequired(error, "mcp_live_discovery", "thread.mcp_live_discovery");
      assert.equal(error.details.thread_id, "thread-agent-one");
      return true;
    },
  );
});
