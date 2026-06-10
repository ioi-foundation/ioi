import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeMcpServeSurface } from "./runtime-mcp-serve-surface.mjs";

function harness() {
  const invocations = [];
  const tools = [
    { stable_tool_id: "workspace.status", display_name: "Workspace status", input_schema: { type: "object" } },
    { stable_tool_id: "git.diff", display_name: "Git diff", input_schema: { type: "object" } },
    { stable_tool_id: "test.run", display_name: "Run tests", input_schema: { type: "object" } },
  ];
  const allowedToolIds = (options = {}) =>
    options.onlyDiff === true ? ["git.diff"] : ["workspace.status", "git.diff"];
  const surface = createRuntimeMcpServeSurface({
    RUNTIME_MCP_SERVE_PROTOCOL_VERSION: "mcp.protocol.test",
    RUNTIME_MCP_SERVE_SCHEMA_VERSION: "ioi.runtime.mcp-serve.test",
    codingToolContracts() {
      return tools;
    },
    mcpServeAllowedToolIds: allowedToolIds,
    mcpServeToolCallResult(invocation) {
      return {
        content: [{ type: "text", text: `${invocation.tool_name} ${invocation.status}` }],
        structuredContent: invocation,
        isError: invocation.status !== "completed",
      };
    },
    mcpServeToolDescriptor(tool) {
      return {
        name: tool.stable_tool_id,
        title: tool.display_name,
        inputSchema: tool.input_schema,
        _meta: { stableToolId: tool.stable_tool_id },
      };
    },
    mcpServeToolIdForName(name, options = {}) {
      return allowedToolIds(options).includes(name) ? name : null;
    },
  });
  const store = {
    agentForThread() {
      throw new Error("MCP serve tool-call facade must not resolve thread agents in JS.");
    },
    async invokeThreadToolAsync(threadId, toolId, request) {
      invocations.push({ threadId, toolId, request });
      throw new Error("MCP serve tool-call facade must not invoke JS thread tools.");
    },
  };
  return { invocations, store, surface };
}

test("runtime MCP serve surface projects status and allowed tool catalog", () => {
  const { store, surface } = harness();

  const status = surface.mcpServeStatus(store, {
    thread_id: "thread-one",
    threadId: "thread-retired",
    onlyDiff: true,
  });

  assert.equal(status.schema_version, "ioi.runtime.mcp-serve.test");
  assert.equal(status.protocol_version, "mcp.protocol.test");
  assert.equal(status.thread_id, "thread-one");
  assert.equal(surface.mcpServeStatus(store, { threadId: "thread-retired" }).thread_id, null);
  assert.deepEqual(status.allowed_tool_ids, ["git.diff"]);
  assert.equal(status.tool_count, 1);
  assert.deepEqual(status.tools.map((tool) => tool.name), ["git.diff"]);
  assert.equal(status.routes.serve_for_thread, "/v1/threads/{thread_id}/mcp/serve");
  assert.deepEqual(status.evidence_refs, ["mcp.serve.http_jsonrpc", "coding_tool_receipt"]);
  assert.equal(Object.hasOwn(status, "schemaVersion"), false);
  assert.equal(Object.hasOwn(status, "protocolVersion"), false);
  assert.equal(Object.hasOwn(status, "allowedToolIds"), false);
  assert.equal(Object.hasOwn(status, "toolCount"), false);
  assert.equal(Object.hasOwn(status, "evidenceRefs"), false);
  assert.equal(Object.hasOwn(status.routes, "serveForThread"), false);
});

test("runtime MCP serve surface handles JSON-RPC lifecycle and batch notifications", async () => {
  const { invocations, store, surface } = harness();

  const initialize = await surface.handleMcpServeJsonRpc(
    store,
    "thread-one",
    { jsonrpc: "2.0", id: 1, method: "initialize" },
    { onlyDiff: true },
  );
  assert.equal(initialize.result.protocolVersion, "mcp.protocol.test");
  assert.equal(initialize.result.serverInfo.version, "ioi.runtime.mcp-serve.test");
  assert.equal(initialize.result._meta.thread_id, "thread-one");
  assert.deepEqual(initialize.result._meta.allowed_tool_ids, ["git.diff"]);

  const initializedNotification = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    { jsonrpc: "2.0", method: "notifications/initialized" },
  );
  assert.equal(initializedNotification, null);

  const initializedRequest = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    { jsonrpc: "2.0", id: 2, method: "notifications/initialized" },
  );
  assert.deepEqual(initializedRequest, { jsonrpc: "2.0", id: 2, result: {} });

  const batch = await surface.handleMcpServeJsonRpc(
    store,
    "thread-one",
    [
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 3, method: "ping" },
      { jsonrpc: "2.0", id: 4, method: "tools/list" },
    ],
  );
  assert.equal(batch.length, 2);
  assert.deepEqual(batch.map((response) => response.id), [3, 4]);
  assert.deepEqual(batch[1].result.tools.map((tool) => tool.name), ["workspace.status", "git.diff"]);
  assert.deepEqual(invocations, []);
});

test("runtime MCP serve surface fails closed for allowed tool calls and rejects malformed requests", async () => {
  const { invocations, store, surface } = harness();

  const invalid = await surface.handleSingleMcpServeJsonRpc(store, "thread-one", []);
  assert.equal(invalid.error.code, -32600);
  assert.equal(invalid.error.data.schema_version, "ioi.runtime.mcp-serve.test");

  const disallowed = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "workspace.status" } },
    { onlyDiff: true },
  );
  assert.equal(disallowed.error.code, -32602);
  assert.deepEqual(disallowed.error.data.allowed_tools, ["git.diff"]);
  assert.equal(Object.hasOwn(disallowed.error.data, "allowedTools"), false);

  const retiredToolName = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    { jsonrpc: "2.0", id: 9, method: "tools/call", params: { toolName: "git.diff" } },
    { onlyDiff: true },
  );
  assert.equal(retiredToolName.error.code, -32602);
  assert.match(retiredToolName.error.message, /missing/);
  assert.deepEqual(invocations, []);

  const unsupported = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    { jsonrpc: "2.0", id: 6, method: "resources/read" },
  );
  assert.equal(unsupported.error.code, -32601);
  assert.equal(unsupported.error.data.supported_methods.includes("tools/call"), true);
  assert.equal(Object.hasOwn(unsupported.error.data, "supportedMethods"), false);

  const response = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "git.diff", arguments: { includeStat: true } },
    },
    {
      onlyDiff: true,
      workflow_graph_id: "custom.graph",
      workflow_node_id: "custom.node",
      workflowGraphId: "retired.graph",
      workflowNodeId: "retired.node",
    },
  );
  assert.equal(response.id, 7);
  assert.equal(response.error.code, -32000);
  assert.equal(response.error.data.code, "runtime_mcp_serve_tool_call_rust_core_required");
  assert.equal(response.error.data.details.rust_core_boundary, "runtime.mcp_serve");
  assert.equal(response.error.data.details.operation_kind, "mcp.serve.tools.call");
  assert.equal(response.error.data.details.thread_id, "thread-one");
  assert.equal(response.error.data.details.tool_id, "git.diff");
  assert.equal(response.error.data.details.tool_name, "git.diff");
  assert.equal(
    response.error.data.details.evidence_refs.includes("runtime_mcp_serve_tool_call_js_facade_retired"),
    true,
  );

  const retiredOnlyResponse = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 8,
      method: "tools/call",
      params: { name: "git.diff", arguments: { summary: true } },
    },
    {
      onlyDiff: true,
      workflowGraphId: "retired.graph",
      workflowNodeId: "retired.node",
    },
  );
  assert.equal(retiredOnlyResponse.error.data.code, "runtime_mcp_serve_tool_call_rust_core_required");
  assert.equal(retiredOnlyResponse.error.data.details.thread_id, "thread-one");

  const retiredArgsResponse = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 10,
      method: "tools/call",
      params: { name: "git.diff", args: { includeStat: "retired" } },
    },
    { onlyDiff: true },
  );
  assert.equal(retiredArgsResponse.error.data.code, "runtime_mcp_serve_tool_call_rust_core_required");
  assert.deepEqual(invocations, []);
});
