import assert from "node:assert/strict";
import test from "node:test";
import { makeWorkflowNode } from "./workflow-node-registry";
import {
  RUNTIME_MCP_TOOL_COMPONENT_KIND,
  RUNTIME_MCP_TOOL_SOURCE,
  RUNTIME_MCP_TOOL_SOURCE_EVENT_KIND,
  WORKFLOW_RUNTIME_MCP_TOOL_CONTROL_SCHEMA_VERSION,
  createRuntimeMcpToolControlRequestFromWorkflowNode,
} from "./workflow-runtime-mcp-control-nodes";

test("MCP search state node builds a React Flow daemon catalog request", () => {
  const node = makeWorkflowNode("mcp-search", "state", "Search MCP", 100, 120, {
    stateKey: "mcp",
    stateOperation: "mcp_tool_search",
    reducer: "replace",
    mcpServerId: "mcp.search",
    mcpToolSearchQuery: "query",
    mcpConfigSourceMode: "workspace",
    mcpCatalogMode: "summary",
    mcpToolCatalogPreviewLimit: 2,
  });

  const request = createRuntimeMcpToolControlRequestFromWorkflowNode(
    node,
    { threadId: "thread react flow" },
    { workflowGraphId: "workflow.mcp.catalog" },
  );

  assert.equal(request.schemaVersion, WORKFLOW_RUNTIME_MCP_TOOL_CONTROL_SCHEMA_VERSION);
  assert.equal(request.nodeType, "runtime_mcp_tool");
  assert.equal(request.operation, "search");
  assert.equal(request.method, "GET");
  assert.equal(request.threadId, "thread react flow");
  assert.match(
    request.endpoint,
    /^\/v1\/threads\/thread%20react%20flow\/mcp\/tools\/search\?/,
  );
  assert.match(request.endpoint, /q=query/);
  assert.match(request.endpoint, /query=query/);
  assert.match(request.endpoint, /server_id=mcp\.search/);
  assert.match(request.endpoint, /mcp_config_source_mode=workspace/);
  assert.match(request.endpoint, /catalog_preview_limit=2/);
  assert.equal(request.body, null);
});

test("MCP fetch state node builds a stable tool fetch request", () => {
  const node = makeWorkflowNode("mcp-fetch", "state", "Fetch MCP", 100, 120, {
    stateKey: "mcp",
    stateOperation: "mcp_tool_fetch",
    reducer: "replace",
    mcpServerId: "mcp.search",
    mcpToolName: "query",
    mcpConfigSourceMode: "workspace_and_global",
  });

  const request = createRuntimeMcpToolControlRequestFromWorkflowNode(
    node,
    { threadId: "thread-mcp-fetch" },
  );

  assert.equal(request.operation, "fetch");
  assert.equal(request.method, "GET");
  assert.equal(request.toolId, "mcp.search.query");
  assert.match(
    request.endpoint,
    /^\/v1\/threads\/thread-mcp-fetch\/mcp\/tools\/mcp\.search\.query\?/,
  );
  assert.match(request.endpoint, /server_id=mcp\.search/);
  assert.match(request.endpoint, /source=react_flow/);
  assert.equal(request.body, null);
});

test("MCP invoke state node builds a governed invocation request", () => {
  const node = makeWorkflowNode("mcp-invoke", "state", "Invoke MCP", 100, 120, {
    stateKey: "mcp",
    stateOperation: "mcp_tool_invoke",
    reducer: "replace",
    mcpServerId: "mcp.search",
    mcpToolName: "query",
    mcpToolInputJson: "{\"q\":\"workflow-authored\"}",
    mcpConfigSourceMode: "workspace",
    mcpCatalogMode: "summary",
    mcpContainmentMode: "sandboxed",
    mcpAllowNetworkEgress: false,
    mcpVaultHeaderRefsJson: "{\"Authorization\":\"vault://mcp/search-token\"}",
  });

  const request = createRuntimeMcpToolControlRequestFromWorkflowNode(
    node,
    { threadId: "thread-mcp-invoke" },
    { workflowGraphId: "workflow.mcp.invoke", actor: "workflow-author" },
  );

  assert.equal(request.operation, "invoke");
  assert.equal(request.method, "POST");
  assert.equal(
    request.endpoint,
    "/v1/threads/thread-mcp-invoke/mcp/tools/mcp.search.query/invoke",
  );
  assert.equal(request.body?.source, RUNTIME_MCP_TOOL_SOURCE);
  assert.equal(request.body?.actor, "workflow-author");
  assert.equal(request.body?.eventKind, RUNTIME_MCP_TOOL_SOURCE_EVENT_KIND);
  assert.equal(request.body?.componentKind, RUNTIME_MCP_TOOL_COMPONENT_KIND);
  assert.equal(request.body?.workflowGraphId, "workflow.mcp.invoke");
  assert.equal(request.body?.workflowNodeId, "runtime.mcp-tool.mcp.search.query");
  assert.deepEqual(request.body?.input, { q: "workflow-authored" });
  assert.deepEqual(request.body?.arguments, { q: "workflow-authored" });
  assert.equal(request.body?.containmentMode, "sandboxed");
  assert.equal(request.body?.allowNetworkEgress, false);
  assert.deepEqual(request.body?.headers, {
    Authorization: "vault://mcp/search-token",
  });
});
