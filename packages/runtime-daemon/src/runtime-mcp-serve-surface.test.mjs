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
    async invokeThreadTool() {
      throw new Error("MCP serve tool-call facade must not invoke JS thread tools.");
    },
    async invokeThreadToolAsync() {
      throw new Error("MCP serve tool-call facade must not invoke retired async JS thread tools.");
    },
    codingToolInvocationSurface: {
      invokeThreadTool(surfaceStore, threadId, toolId, request) {
        invocations.push({ surfaceStore, threadId, toolId, request });
        return {
          schema_version: "ioi.runtime.coding-tool-result.v1",
          object: "ioi.runtime_coding_tool_result",
          status: "completed",
          tool_name: toolId,
          tool_call_id: request.tool_call_id,
          thread_id: threadId,
          workflow_graph_id: request.workflow_graph_id,
          workflow_node_id: request.workflow_node_id,
          receipt_refs: ["receipt_mcp_serve_tool_call"],
          policy_decision_refs: ["policy_mcp_serve_tool_call"],
          artifact_refs: ["artifact_mcp_serve_tool_call"],
          event: {
            event_id: "event_mcp_serve_tool_call",
            payload_summary: { summary: `${toolId} completed through Rust coding-tool invocation.` },
          },
          result: { ok: true, input: request },
        };
      },
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

test("runtime MCP serve surface invokes Rust-owned coding-tool path for allowed tool calls", async () => {
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
  assert.equal(response.result.structuredContent.status, "completed");
  assert.equal(response.result.structuredContent.tool_name, "git.diff");
  assert.equal(response.result.structuredContent.event_id, "event_mcp_serve_tool_call");
  assert.deepEqual(response.result.structuredContent.receipt_refs, ["receipt_mcp_serve_tool_call"]);
  assert.equal(response.result.content[0].text, "git.diff completed through Rust coding-tool invocation.");
  assert.equal(invocations.length, 1);
  assert.equal(invocations[0].surfaceStore, store);
  assert.equal(invocations[0].threadId, "thread-one");
  assert.equal(invocations[0].toolId, "git.diff");
  assert.equal(invocations[0].request.includeStat, true);
  assert.equal(invocations[0].request.source, "mcp_serve");
  assert.equal(invocations[0].request.workflow_graph_id, "custom.graph");
  assert.equal(invocations[0].request.workflow_node_id, "custom.node");
  assert.equal(Object.hasOwn(invocations[0].request, "workflowGraphId"), false);
  assert.equal(Object.hasOwn(invocations[0].request, "workflowNodeId"), false);
  assert.equal(invocations[0].request.mcp_serve_request.method, "tools/call");
  assert.equal(invocations[0].request.mcp_serve_request.tool_id, "git.diff");
  assert.equal(Object.hasOwn(invocations[0].request.mcp_serve_request, "toolId"), false);

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
  assert.equal(retiredOnlyResponse.result.structuredContent.status, "completed");
  const retiredOnlyInvocation = invocations.at(-1);
  assert.equal(retiredOnlyInvocation.request.workflow_graph_id, "runtime.mcp_serve");
  assert.equal(retiredOnlyInvocation.request.workflow_node_id, "runtime.mcp_serve.git.diff");
  assert.equal(Object.hasOwn(retiredOnlyInvocation.request, "workflowGraphId"), false);
  assert.equal(Object.hasOwn(retiredOnlyInvocation.request, "workflowNodeId"), false);

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
  assert.equal(retiredArgsResponse.result.structuredContent.status, "completed");
  const retiredArgsInvocation = invocations.at(-1);
  assert.equal(Object.hasOwn(retiredArgsInvocation.request, "includeStat"), false);
  assert.equal(Object.hasOwn(retiredArgsInvocation.request, "args"), false);
});

test("runtime MCP serve tool calls fail closed without Rust-owned coding-tool invocation surface", async () => {
  const { store, surface } = harness();
  delete store.codingToolInvocationSurface;

  const response = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "git.diff", arguments: { includeStat: true } },
    },
    { onlyDiff: true },
  );

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
});
