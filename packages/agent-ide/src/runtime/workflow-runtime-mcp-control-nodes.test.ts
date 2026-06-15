import assert from "node:assert/strict";
import test from "node:test";
import { makeWorkflowNode } from "./workflow-node-registry";
import {
  RUNTIME_MCP_SERVE_CLIENT_SCHEMA_VERSION,
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
  const body = request.body as unknown as Record<string, unknown>;
  assert.equal(body.source, RUNTIME_MCP_TOOL_SOURCE);
  assert.equal(body.actor, "workflow-author");
  assert.equal(body.event_kind, RUNTIME_MCP_TOOL_SOURCE_EVENT_KIND);
  assert.equal(body.component_kind, RUNTIME_MCP_TOOL_COMPONENT_KIND);
  assert.equal(body.workflow_graph_id, "workflow.mcp.invoke");
  assert.equal(body.workflow_node_id, "runtime.mcp-tool.mcp.search.query");
  assert.deepEqual(body.input, { q: "workflow-authored" });
  assert.deepEqual(body.arguments, { q: "workflow-authored" });
  assert.equal(body.containment_mode, "sandboxed");
  assert.equal(body.allow_network_egress, false);
  assert.deepEqual(body.headers, {
    Authorization: "vault://mcp/search-token",
  });
  for (const retired of [
    "eventKind",
    "componentKind",
    "payloadSchemaVersion",
    "workflowGraphId",
    "workflowNodeId",
    "serverId",
    "toolName",
    "sideEffectClass",
    "mcpConfigSourceMode",
    "catalogMode",
    "containmentMode",
    "allowNetworkEgress",
    "vaultHeaderRefs",
  ]) {
    assert.equal(Object.prototype.hasOwnProperty.call(body, retired), false);
  }
});

test("MCP serve state node builds a stable protocol admission request", () => {
  const node = makeWorkflowNode("mcp-serve", "state", "Serve MCP", 100, 120, {
    stateKey: "mcp",
    stateOperation: "mcp_serve",
    reducer: "replace",
    mcpServeAllowedToolsJson: "[\"workspace.status\",\"git.diff\"]",
    mcpServeAuthorityGrantRefsJson:
      "[\"wallet.network://grant/mcp-serve/{thread_id}/workspace.status\"]",
    mcpServeAuthorityReceiptRefsJson:
      "[\"receipt://wallet.network/mcp-serve/{thread_id}/workspace.status\"]",
    mcpServeCustodyRef: "ctee://workspace/{thread_id}",
    mcpServeContainmentRef: "containment://mcp-serve/{thread_id}/workspace.status",
  });

  const request = createRuntimeMcpToolControlRequestFromWorkflowNode(
    node,
    { threadId: "thread mcp serve" },
    { workflowGraphId: "workflow.mcp.serve", actor: "workflow-author" },
  );
  const body = request.body as unknown as Record<string, unknown>;

  assert.equal(request.operation, "serve");
  assert.equal(request.method, "POST");
  assert.equal(request.endpoint, "/v1/threads/thread%20mcp%20serve/mcp/serve");
  assert.equal(request.serverId, null);
  assert.equal(request.toolName, null);
  assert.equal(body.schema_version, RUNTIME_MCP_SERVE_CLIENT_SCHEMA_VERSION);
  assert.equal(body.source, RUNTIME_MCP_TOOL_SOURCE);
  assert.deepEqual(body.allowed_tools, ["workspace.status", "git.diff"]);
  assert.deepEqual(body.authority_grant_refs, [
    "wallet.network://grant/mcp-serve/thread mcp serve/workspace.status",
  ]);
  assert.deepEqual(body.authority_receipt_refs, [
    "receipt://wallet.network/mcp-serve/thread mcp serve/workspace.status",
  ]);
  assert.equal(body.custody_ref, "ctee://workspace/thread mcp serve");
  assert.equal(
    body.containment_ref,
    "containment://mcp-serve/thread mcp serve/workspace.status",
  );
  assert.deepEqual(body.message, {
    jsonrpc: "2.0",
    id: "workflow-mcp-serve-mcp-serve",
    method: "tools/list",
  });
  assert.equal(Object.prototype.hasOwnProperty.call(body, "endpoint"), false);
});
