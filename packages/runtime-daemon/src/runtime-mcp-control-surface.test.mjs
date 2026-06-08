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
    throw new Error(`${name} must not be reached by the retired JS MCP control facade`);
  };
}

function harness() {
  const calls = [];
  const agent = {
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
  const surface = createRuntimeMcpControlSurface({
    RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION: "invoke.schema",
    RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION: "status.schema",
    RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION: "validation.schema",
    runtimeError,
    contextPolicyRunner: {
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
          (item.tools ?? []).map((tool) => ({
            server_id: item.id,
            tool_name: tool.name,
            stable_tool_id: `${item.id}.${tool.name}`,
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
    },
  });
  const store = {
    agents: { set: failIfCalled("agents.set") },
    agentForThread: failIfCalled("agentForThread"),
    appendRuntimeEvent: failIfCalled("appendRuntimeEvent"),
    listMcpServers: failIfCalled("listMcpServers"),
    mcpStatus: failIfCalled("mcpStatus"),
    threadForAgent: failIfCalled("threadForAgent"),
    validateMcp: failIfCalled("validateMcp"),
    writeAgent: failIfCalled("writeAgent"),
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

test("runtime MCP control mutations fail closed before JS state mutation", () => {
  const { store, surface } = harness();

  const cases = [
    {
      run: () => surface.importMcp(store, { thread_id: "thread-agent-one", servers: [] }),
      operation: "import_mcp",
      operationKind: "thread.mcp_import",
    },
    {
      run: () => surface.addMcpServer(store, { thread_id: "thread-agent-one", id: "mcp.new" }),
      operation: "add_mcp_server",
      operationKind: "thread.mcp_add",
    },
    {
      run: () => surface.removeMcpServer(store, "mcp.docs", { thread_id: "thread-agent-one" }),
      operation: "remove_mcp_server",
      operationKind: "thread.mcp_remove",
    },
    {
      run: () => surface.setMcpServerEnabled(store, "mcp.docs", false, { thread_id: "thread-agent-one" }),
      operation: "disable_mcp_server",
      operationKind: "thread.mcp_disable",
    },
    {
      run: () =>
        surface.applyThreadMcpServerMutation(store, {
          threadId: "thread-agent-one",
          mutationKind: "add",
        }),
      operation: "apply_mcp_server_mutation",
      operationKind: "thread.mcp_add",
    },
    {
      run: () =>
        surface.appendThreadMcpControlEvent(store, {
          threadId: "thread-agent-one",
          controlKind: "mcp_invoke",
        }),
      operation: "append_mcp_control_event",
      operationKind: "thread.mcp_invoke",
    },
  ];

  for (const item of cases) {
    assert.throws(item.run, (error) => {
      assertRustCoreRequired(error, item.operation, item.operationKind);
      return true;
    });
  }
});

test("runtime MCP live exits fail closed before JS transport invocation", async () => {
  const { agent, store, surface } = harness();

  await assert.rejects(
    () =>
      surface.invokeMcpTool(store, {
        thread_id: "thread-agent-one",
        tool_id: "mcp.docs.search",
      }),
    (error) => {
      assertRustCoreRequired(error, "invoke_mcp_tool", "thread.mcp_invoke");
      assert.equal(error.details.tool_id, "mcp.docs.search");
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
      assertRustCoreRequired(error, "mcp_live_discovery", "thread.mcp_status");
      assert.equal(error.details.agent_id, "agent-one");
      return true;
    },
  );
});
