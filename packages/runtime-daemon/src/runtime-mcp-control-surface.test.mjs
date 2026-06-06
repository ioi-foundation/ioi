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

function harness({ stateUpdateOverride = null } = {}) {
  const events = [];
  const statePlannerCalls = [];
  const transportCalls = [];
  const writes = [];
  const agent = {
    id: "agent-one",
    cwd: "/workspace",
    runtimeControls: { approval_mode: "agent" },
    mcpRegistry: {
      servers: [
        server("mcp.docs", [
          { name: "search", side_effect_class: "read" },
          { name: "write", side_effect_class: "write" },
        ]),
      ],
    },
  };
  const mcpToolsForServers = (servers) =>
    servers.flatMap((item) =>
      (item.tools ?? []).map((tool) => ({
        server_id: item.id,
        tool_name: tool.name,
        stable_tool_id: `${item.id}.${tool.name}`,
        side_effect_class: tool.side_effect_class ?? "read",
        workflow_node_id: `runtime.mcp-tool.${item.id}.${tool.name}`,
      })),
    );
  const surface = createRuntimeMcpControlSurface({
    RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION: "invoke.schema",
    RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION: "status.schema",
    RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION: "validation.schema",
    contextPolicyRunner: {
      planMcpControlAgentStateUpdate(request) {
        statePlannerCalls.push(request);
        return {
          status: "planned",
          operation_kind: `thread.${request.control_kind}`,
          updated_at: request.created_at,
          control: {
            controlKind: request.control_kind,
            eventId: request.event_id,
            seq: request.seq,
          },
          agent: {
            ...request.agent,
            updatedAt: request.created_at,
          },
          ...stateUpdateOverride,
        };
      },
    },
    doctorHash() {
      return "hash1234567890abcdef";
    },
    eventStreamIdForThread(threadId) {
      return `stream:${threadId}`;
    },
    fixtureProfileForAgent() {
      return "fixture.profile";
    },
    discoverMcpStdioCatalog(server, options) {
      transportCalls.push({ name: "discoverMcpStdioCatalog", server, options });
      return { tools: server.tools ?? [], resources: server.resources ?? [], prompts: server.prompts ?? [] };
    },
    invokeMcpStdioTool(server, toolName, input, options) {
      transportCalls.push({ name: "invokeMcpStdioTool", server, toolName, input, options });
      return {
        ok: true,
        status: "completed",
        transport: "stdio",
        execution_mode: "live_stdio",
        result: { ok: true },
      };
    },
    mcpLiveExecutionModeForServer(server, request = {}) {
      return request.live_transport === true || server.execution_mode === "live_stdio" ? "live_stdio" : null;
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
      const requestedTool = request.tool_name ?? request.name ?? String(toolId ?? "").split(".").at(-1);
      const requestedServer = request.server_id ?? String(toolId ?? "").split(".").slice(0, -1).join(".");
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
  return { events, statePlannerCalls, store, surface, transportCalls, writes };
}

test("runtime MCP control surface applies add, remove, and blocked mutation envelopes", () => {
  const { events, statePlannerCalls, store, surface } = harness();

  assert.throws(
    () => surface.importMcp(store, {}),
    (error) => error.status === 400 && error.code === "mcp_thread_required",
  );
  assert.throws(
    () => surface.importMcp(store, { threadId: "thread-agent-one", servers: [] }),
    (error) => error.status === 400 && error.code === "mcp_thread_required",
  );

  const added = surface.addMcpServer(store, {
    thread_id: "thread-agent-one",
    threadId: "thread-retired",
    workflow_node_id: "runtime.mcp-server.extra.canonical",
    workflowNodeId: "runtime.mcp-server.extra.retired",
    id: "mcp.extra",
    tools: [{ name: "extra" }],
  });
  assert.equal(added.event_kind, "McpServerAdded");
  assert.equal(added.add_count, 1);
  assert.equal(added.policy_decision, "registry_write_allowed");
  assert.equal(Object.hasOwn(added, "addCount"), false);
  assert.equal(Object.hasOwn(store.agents.get("agent-one").mcpRegistry.servers.at(-1), "evidenceRefs"), false);
  assert.equal(events.at(-1).payload_schema_version, "status.schema");
  assert.equal(events.at(-1).workflow_node_id, "runtime.mcp-server.extra.canonical");
  assert.equal(store.agents.get("agent-one").mcpRegistry.servers.some((item) => item.id === "mcp.extra"), true);
  assert.equal(statePlannerCalls.at(-1).control_kind, "mcp_add");
  assert.equal(statePlannerCalls.at(-1).agent.mcpRegistry.servers.some((item) => item.id === "mcp.extra"), true);

  assert.throws(
    () => surface.removeThreadMcpServer(store, "thread-agent-one", null, { serverId: "mcp.extra" }),
    (error) => error.status === 404 && error.code === "not_found",
  );

  const removed = surface.removeThreadMcpServer(store, "thread-agent-one", null, {
    server_id: "mcp.extra",
    serverId: "mcp.retired",
    workflow_node_id: "runtime.mcp-server.remove.canonical",
    workflowNodeId: "runtime.mcp-server.remove.retired",
  });
  assert.equal(removed.event_kind, "McpServerRemoved");
  assert.equal(removed.removed_count, 1);
  assert.equal(removed.server_id, "mcp.extra");
  assert.equal(Object.hasOwn(removed, "serverId"), false);
  assert.equal(Object.hasOwn(removed, "removedCount"), false);
  assert.equal(events.at(-1).workflow_node_id, "runtime.mcp-server.remove.canonical");
  assert.equal(store.agents.get("agent-one").mcpRegistry.servers.some((item) => item.id === "mcp.extra"), false);
  assert.equal(statePlannerCalls.at(-1).control_kind, "mcp_remove");

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
  assert.equal(Object.hasOwn(blocked, "proposedServers"), false);
  assert.equal(events.at(-1).payload_schema_version, "validation.schema");
  assert.equal(statePlannerCalls.at(-1).control_kind, "mcp_import");
  assert.deepEqual(statePlannerCalls.map((call) => call.control_kind), [
    "mcp_add",
    "mcp_remove",
    "mcp_import",
  ]);
});

test("runtime MCP control surface records enable, status, and validation controls", async () => {
  const { events, statePlannerCalls, store, surface, writes } = harness();

  const disabled = surface.setThreadMcpServerEnabled(store, "thread-agent-one", "mcp.docs", false);
  assert.equal(disabled.event_kind, "McpServerDisabled");
  assert.equal(disabled.enabled, false);
  assert.equal(disabled.server_id, "mcp.docs");
  assert.equal(disabled.server.status, "disabled");
  assert.equal(Object.hasOwn(disabled, "serverId"), false);
  assert.equal(Object.hasOwn(disabled.server, "evidenceRefs"), false);
  assert.equal(events.at(-1).event_kind, "mcp.server_disabled");

  const status = await surface.recordThreadMcpStatus(store, "thread-agent-one");
  assert.equal(status.event_kind, "McpCatalogStatus");
  assert.equal(status.schema_version, "status.schema");
  assert.equal(status.server_count, 1);
  assert.equal(status.tool_count, 2);
  assert.equal(Object.hasOwn(status, "schemaVersion"), false);
  assert.equal(Object.hasOwn(status, "serverCount"), false);
  assert.equal(Object.hasOwn(status, "toolCount"), false);
  assert.match(status.summary, /MCP catalog has 1 server/);

  const statusWithAssets = surface.mcpStatusForAgent({
    ...store.agents.get("agent-one"),
    mcpRegistry: {
      servers: [
        server("mcp.assets", [], {
          resources: [{ uri: "file:///workspace/README.md" }],
          prompts: [{ name: "summarize" }],
        }),
      ],
    },
  });
  assert.equal(statusWithAssets.resources[0].server_id, "mcp.assets");
  assert.equal(statusWithAssets.prompts[0].server_id, "mcp.assets");
  assert.equal(Object.hasOwn(statusWithAssets, "enabledToolCount"), false);
  assert.equal(Object.hasOwn(statusWithAssets.resources[0], "serverId"), false);
  assert.equal(Object.hasOwn(statusWithAssets.prompts[0], "serverId"), false);

  const validation = surface.validateThreadMcp(store, "thread-agent-one");
  assert.equal(validation.event_kind, "McpValidationReport");
  assert.equal(validation.status, "pass");

  const canonicalValidation = surface.validateThreadMcp(store, "thread-agent-one", {
    servers: [server("mcp.invalid", [], { invalid: true })],
    mcpServers: [server("mcp.retired", [], { invalid: false })],
  });
  assert.equal(canonicalValidation.status, "blocked");
  assert.equal(canonicalValidation.issue_count, 1);

  const retiredValidation = surface.validateThreadMcp(store, "thread-agent-one", {
    mcpServers: [server("mcp.invalid", [], { invalid: true })],
  });
  assert.equal(retiredValidation.status, "pass");

  assert.equal(writes.length >= 3, true);
  assert.deepEqual(statePlannerCalls.map((call) => call.control_kind), [
    "mcp_disable",
    "mcp_status",
    "mcp_validate",
    "mcp_validate",
    "mcp_validate",
  ]);
});

test("runtime MCP control surface fails closed without Rust-planned operation kind", () => {
  const { statePlannerCalls, store, surface, writes } = harness({
    stateUpdateOverride: {
      operation_kind: null,
    },
  });

  assert.throws(
    () =>
      surface.addMcpServer(store, {
        thread_id: "thread-agent-one",
        id: "mcp.extra",
        tools: [{ name: "extra" }],
      }),
    (error) => {
      assert.equal(error.code, "mcp_control_state_update_operation_kind_missing");
      assert.equal(error.details.operationKind, "thread.mcp_add");
      return true;
    },
  );
  assert.equal(writes.length, 0);
  assert.equal(statePlannerCalls.length, 1);
  assert.equal(store.agents.get("agent-one").mcpRegistry.servers.length, 1);
});

test("runtime MCP control surface invokes tools with receipt-backed policy outcomes", async () => {
  const { events, statePlannerCalls, store, surface } = harness();

  const completed = await surface.invokeThreadMcpTool(store, "thread-agent-one", "mcp.docs.search", {
    input: { q: "runtime" },
  });
  assert.equal(completed.event_kind, "McpToolInvocation");
  assert.equal(completed.status, "completed");
  assert.equal(completed.policy_decision, "invoke_allowed");
  assert.equal(completed.invocation.schema_version, "invoke.schema");
  assert.equal(completed.invocation.result.fixture, true);
  assert.equal(completed.invocation.result.server_id, "mcp.docs");
  assert.equal(completed.invocation.result.tool_name, "search");
  assert.equal(completed.invocation.containment.receipt_required, true);
  assert.equal(completed.invocation.containment.execution_mode, "simulated_manager_receipt");
  assert.deepEqual(completed.invocation.evidence_refs.slice(0, 3), [
    "mcp.manager.tool.invoke",
    "mcp_containment_receipt",
    "mcp.transport.fixture",
  ]);
  for (const field of [
    "schemaVersion",
    "toolCallId",
    "threadId",
    "agentId",
    "serverId",
    "toolName",
    "inputHash",
    "outputHash",
    "sideEffectClass",
    "requiresApproval",
    "approvalMode",
    "transportExecution",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(completed.invocation, field), false);
  }
  assert.equal(Object.hasOwn(completed.invocation.result, "serverId"), false);
  assert.equal(Object.hasOwn(completed.invocation.result, "toolName"), false);
  assert.equal(Object.hasOwn(completed.invocation.transport_execution, "executionMode"), false);
  assert.equal(Object.hasOwn(completed.invocation.containment, "receiptRequired"), false);
  assert.equal(Object.hasOwn(completed.invocation.containment, "executionMode"), false);

  const blocked = await surface.invokeThreadMcpTool(store, "thread-agent-one", "mcp.docs.write", {
    input: { path: "README.md" },
  });
  assert.equal(blocked.status, "blocked");
  assert.equal(blocked.policy_decision, "invoke_blocked");
  assert.deepEqual(blocked.invocation.blockers, ["approval_required"]);
  assert.equal(events.at(-1).status, "blocked");
  assert.deepEqual(statePlannerCalls.map((call) => call.control_kind), [
    "mcp_invoke",
    "mcp_invoke",
  ]);
});

test("runtime MCP control surface ignores retired threadId request alias", async () => {
  const { store, surface } = harness();

  assert.throws(
    () =>
      surface.addMcpServer(store, {
        threadId: "thread-agent-one",
        id: "mcp.retired",
        tools: [{ name: "retired" }],
      }),
    (error) => error.status === 400 && error.code === "mcp_thread_required",
  );
  assert.throws(
    () => surface.setMcpServerEnabled(store, "mcp.docs", false, { threadId: "thread-agent-one" }),
    (error) => error.status === 400 && error.code === "mcp_thread_required",
  );

  await assert.rejects(
    () =>
      surface.invokeMcpTool(store, {
        threadId: "thread-agent-one",
        tool_id: "mcp.docs.search",
      }),
    (error) => error.status === 400 && error.code === "mcp_thread_required",
  );

  const invoked = await surface.invokeMcpTool(store, {
    thread_id: "thread-agent-one",
    threadId: "thread-retired",
    tool_id: "mcp.docs.search",
    toolId: "mcp.retired.nope",
    serverId: "mcp.retired",
    toolName: "retired",
    input: { q: "canonical" },
  });
  assert.equal(invoked.status, "completed");
  assert.equal(invoked.thread_id, "thread-agent-one");
});

test("runtime MCP control surface ignores retired invoke identity aliases", async () => {
  const { store, surface } = harness();

  await assert.rejects(
    () =>
      surface.invokeMcpTool(store, {
        thread_id: "thread-agent-one",
        toolId: "mcp.docs.search",
      }),
    (error) => error.status === 404 && error.code === "not_found",
  );

  const invoked = await surface.invokeMcpTool(store, {
    thread_id: "thread-agent-one",
    server_id: "mcp.docs",
    tool_name: "search",
    toolId: "mcp.retired.nope",
    serverId: "mcp.retired",
    toolName: "retired",
    input: { q: "canonical identity" },
  });
  assert.equal(invoked.status, "completed");
  assert.equal(invoked.server_id, "mcp.docs");
  assert.equal(invoked.tool_name, "search");
});

test("runtime MCP control surface ignores retired timeoutMs request alias", async () => {
  const { store, surface, transportCalls } = harness();

  await surface.invokeMcpTool(store, {
    thread_id: "thread-agent-one",
    tool_id: "mcp.docs.search",
    live_transport: true,
    timeout_ms: 1234,
    timeoutMs: 9999,
  });
  assert.equal(transportCalls.at(-1).name, "invokeMcpStdioTool");
  assert.equal(transportCalls.at(-1).options.timeoutMs, 1234);

  await surface.invokeMcpTool(store, {
    thread_id: "thread-agent-one",
    tool_id: "mcp.docs.search",
    live_transport: true,
    timeoutMs: 9999,
  });
  assert.equal(transportCalls.at(-1).options.timeoutMs, undefined);
});

test("runtime MCP control surface ignores retired mcpMode request alias", async () => {
  const { store, surface, transportCalls } = harness();

  await surface.invokeMcpTool(store, {
    thread_id: "thread-agent-one",
    tool_id: "mcp.docs.search",
    live_transport: true,
    mcp_mode: "strict",
    mcpMode: "retired",
  });
  assert.equal(transportCalls.at(-1).name, "invokeMcpStdioTool");
  assert.equal(transportCalls.at(-1).options.mcpMode, "strict");

  await surface.invokeMcpTool(store, {
    thread_id: "thread-agent-one",
    tool_id: "mcp.docs.search",
    live_transport: true,
    mcpMode: "retired",
  });
  assert.equal(transportCalls.at(-1).options.mcpMode, undefined);
});

test("runtime MCP control surface ignores retired liveDiscovery request alias", async () => {
  const { store, surface, transportCalls } = harness();

  const liveStatus = await surface.recordThreadMcpStatus(store, "thread-agent-one", {
    live_discovery: true,
    liveDiscovery: false,
    live_transport: true,
  });
  assert.equal(transportCalls.at(-1).name, "discoverMcpStdioCatalog");
  assert.equal(liveStatus.live_discovery.status, "completed");
  assert.equal(liveStatus.catalog_summaries.length, 1);
  assert.equal(liveStatus.returned_tool_count, 3);
  assert.equal(liveStatus.live_discovery.servers[0].server_id, "mcp.docs");
  assert.equal(liveStatus.live_discovery.servers[0].returned_tool_count, 2);
  assert.equal(Object.hasOwn(liveStatus, "liveDiscovery"), false);
  assert.equal(Object.hasOwn(liveStatus, "catalogSummaries"), false);
  assert.equal(Object.hasOwn(liveStatus, "catalogToolCount"), false);
  assert.equal(Object.hasOwn(liveStatus, "returnedToolCount"), false);
  assert.equal(Object.hasOwn(liveStatus.live_discovery.servers[0], "serverId"), false);
  assert.equal(Object.hasOwn(liveStatus.live_discovery.servers[0], "executionMode"), false);
  assert.equal(Object.hasOwn(liveStatus.live_discovery.servers[0], "returnedToolCount"), false);
  assert.equal(Object.hasOwn(liveStatus.live_discovery.servers[0], "catalogSummary"), false);

  transportCalls.length = 0;
  await surface.recordThreadMcpStatus(store, "thread-agent-one", {
    liveDiscovery: true,
    live_transport: true,
  });
  assert.equal(transportCalls.length, 0);
});

test("runtime MCP control surface ignores retired event metadata request aliases", async () => {
  const { events, store, surface } = harness();

  await surface.recordThreadMcpStatus(store, "thread-agent-one", {
    turn_id: "turn-canonical",
    turnId: "turn-retired",
    workflow_graph_id: "graph-canonical",
    workflowGraphId: "graph-retired",
    idempotency_key: "idem-canonical",
    idempotencyKey: "idem-retired",
  });
  assert.equal(events.at(-1).turn_id, "turn-canonical");
  assert.equal(events.at(-1).workflow_graph_id, "graph-canonical");
  assert.equal(events.at(-1).idempotency_key, "idem-canonical");

  await surface.recordThreadMcpStatus(store, "thread-agent-one", {
    turnId: "turn-retired",
    workflowGraphId: "graph-retired",
    idempotencyKey: "idem-retired",
  });
  assert.equal(events.at(-1).turn_id, "turn-one");
  assert.equal(events.at(-1).workflow_graph_id, null);
  assert.match(events.at(-1).idempotency_key, /^thread:thread-agent-one:mcp:mcp_status:/);
});

test("runtime MCP control surface ignores retired invoke policy aliases", async () => {
  const { store, surface } = harness();

  const canonicalSideEffect = await surface.invokeMcpTool(store, {
    thread_id: "thread-agent-one",
    tool_id: "mcp.docs.search",
    side_effect_class: "write",
    sideEffectClass: "read",
  });
  assert.equal(canonicalSideEffect.status, "blocked");
  assert.deepEqual(canonicalSideEffect.invocation.blockers, ["approval_required"]);

  const retiredSideEffect = await surface.invokeMcpTool(store, {
    thread_id: "thread-agent-one",
    tool_id: "mcp.docs.search",
    sideEffectClass: "write",
  });
  assert.equal(retiredSideEffect.status, "completed");

  const canonicalRequiresApproval = await surface.invokeMcpTool(store, {
    thread_id: "thread-agent-one",
    tool_id: "mcp.docs.search",
    requires_approval: true,
    requiresApproval: false,
  });
  assert.equal(canonicalRequiresApproval.status, "blocked");
  assert.deepEqual(canonicalRequiresApproval.invocation.blockers, ["approval_required"]);

  const retiredRequiresApproval = await surface.invokeMcpTool(store, {
    thread_id: "thread-agent-one",
    tool_id: "mcp.docs.search",
    requiresApproval: true,
  });
  assert.equal(retiredRequiresApproval.status, "completed");

  const canonicalApproved = await surface.invokeMcpTool(store, {
    thread_id: "thread-agent-one",
    tool_id: "mcp.docs.write",
    approved: true,
    approvalGranted: false,
  });
  assert.equal(canonicalApproved.status, "completed");

  const retiredApprovalGranted = await surface.invokeMcpTool(store, {
    thread_id: "thread-agent-one",
    tool_id: "mcp.docs.write",
    approvalGranted: true,
  });
  assert.equal(retiredApprovalGranted.status, "blocked");
  assert.deepEqual(retiredApprovalGranted.invocation.blockers, ["approval_required"]);
});
