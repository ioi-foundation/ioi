import assert from "node:assert/strict";
import test from "node:test";

import { RUNTIME_MCP_SERVE_DEFAULT_ALLOWED_TOOL_IDS } from "./runtime-contract-constants.mjs";
import {
  mcpCatalogFullRequested,
  mcpConfigSourceModeForRequest,
  mcpJsonRpcError,
  mcpJsonRpcErrorCodeFor,
  mcpJsonRpcResult,
  mcpLiveExecutionModeForServer,
  mcpTransportEvidenceRef,
  mcpTransportSummary,
  mcpServeAllowedToolIds,
  mcpServeToolDescriptor,
  mcpServeToolIdForName,
  mcpServerMatchesConfigSourceMode,
  mcpToolSearchLimit,
  mcpToolIdentityMatches,
  mcpToolMatchesQuery,
  resolveMcpServerRecord,
  resolveMcpToolRecord,
} from "./runtime-mcp-helpers.mjs";

test("runtime MCP helpers resolve servers and tools by stable identities", () => {
  const servers = [{
    id: "mcp.workspace.docs",
    label: "Docs",
    tools: [{
      name: "search",
      description: "Search docs",
      inputSchema: { type: "object" },
    }],
  }];

  assert.equal(resolveMcpServerRecord(servers, "docs").id, "mcp.workspace.docs");
  assert.equal(resolveMcpServerRecord(servers, "mcp.workspace.docs").label, "Docs");
  assert.equal(resolveMcpServerRecord([{ serverId: "mcp.retired.docs" }], "mcp.retired.docs"), null);

  const byStableId = resolveMcpToolRecord(servers, "mcp.workspace.docs.search");
  assert.equal(byStableId.server.id, "mcp.workspace.docs");
  assert.equal(byStableId.toolName, "search");

  const canonicalRequest = resolveMcpToolRecord(servers, null, {
    server_id: "mcp.workspace.docs",
    tool_name: "search",
    serverId: "mcp.retired",
    toolName: "retired",
    toolId: "mcp.retired.nope",
  });
  assert.equal(canonicalRequest.server.id, "mcp.workspace.docs");
  assert.equal(canonicalRequest.toolName, "search");

  assert.equal(mcpToolIdentityMatches({
    stable_tool_id: "mcp.workspace.docs.search",
    workflow_node_id: "runtime.mcp.docs.search",
    tool_name: "search",
    server_id: "mcp.workspace.docs",
  }, "runtime.mcp.docs.search"), true);
  assert.equal(mcpToolIdentityMatches({
    stableToolId: "mcp.workspace.docs.search",
    workflowNodeId: "runtime.mcp.docs.search",
    toolName: "search",
    serverId: "mcp.workspace.docs",
  }, "runtime.mcp.docs.search"), false);
  assert.equal(mcpToolMatchesQuery({ server_label: "Docs", tool_name: "search" }, "doc"), true);
  assert.equal(mcpToolMatchesQuery({ serverLabel: "Docs", toolName: "search" }, "doc"), false);
});

test("runtime MCP helpers shape serve descriptors", () => {
  assert.deepEqual(mcpServeAllowedToolIds({
    allowed_tools: ["workspace.status", "git.diff", "not.allowed"],
    allowedTools: ["file.inspect"],
    toolIds: ["test.run"],
  }), ["workspace.status", "git.diff"]);
  assert.equal(mcpServeToolIdForName("git.diff", { allowed_tools: ["git.diff"] }), "git.diff");
  assert.equal(mcpServeToolIdForName("git_diff", { allowed_tools: ["git.diff"] }), null);
  assert.deepEqual(mcpServeAllowedToolIds({ allowedTools: ["git.diff"] }), RUNTIME_MCP_SERVE_DEFAULT_ALLOWED_TOOL_IDS);
  assert.deepEqual(mcpServeAllowedToolIds({ toolIds: ["git.diff"] }), RUNTIME_MCP_SERVE_DEFAULT_ALLOWED_TOOL_IDS);

  const descriptor = mcpServeToolDescriptor({
    stable_tool_id: "file.inspect",
    display_name: "Inspect file",
    effect_class: "local_read",
    authority_scope_requirements: ["workspace.fs.read"],
  });
  assert.equal(descriptor.name, "file.inspect");
  assert.equal(descriptor._meta.stable_tool_id, "file.inspect");
  assert.equal(descriptor._meta.effect_class, "local_read");
  assert.deepEqual(descriptor._meta.authority_scope_requirements, ["workspace.fs.read"]);
  assert.equal(descriptor._meta.approval_required, true);
  assert.equal(Object.hasOwn(descriptor._meta, "stableToolId"), false);
  assert.equal(Object.hasOwn(descriptor._meta, "effectClass"), false);
  assert.equal(Object.hasOwn(descriptor._meta, "authorityScopeRequirements"), false);
  assert.equal(Object.hasOwn(descriptor._meta, "credentialReadiness"), false);
  assert.equal(Object.hasOwn(descriptor._meta, "approvalRequired"), false);
  assert.equal(Object.hasOwn(descriptor._meta, "rateLimitProfile"), false);
  assert.equal(Object.hasOwn(descriptor._meta, "idempotencyBehavior"), false);
  assert.equal(Object.hasOwn(descriptor._meta, "receiptBehavior"), false);
  assert.equal(Object.hasOwn(descriptor._meta, "workflowAvailability"), false);
  assert.equal(Object.hasOwn(descriptor._meta, "agentAvailability"), false);
  assert.equal(Object.hasOwn(descriptor._meta, "marketplaceExposure"), false);
  assert.equal(Object.hasOwn(descriptor._meta, "workflowNodeType"), false);
  assert.equal(Object.hasOwn(descriptor._meta, "workflowConfigFields"), false);
  assert.equal(descriptor.annotations.readOnlyHint, true);
});

test("runtime MCP helpers shape JSON-RPC envelopes and transport metadata", () => {
  assert.deepEqual(mcpJsonRpcResult(7, { ok: true }), {
    jsonrpc: "2.0",
    id: 7,
    result: { ok: true },
  });
  assert.deepEqual(mcpJsonRpcError(8, -32602, "Invalid params", { field: "tool" }).error, {
    code: -32602,
    message: "Invalid params",
    data: { field: "tool" },
  });
  assert.equal(mcpJsonRpcErrorCodeFor({ status: 404 }), -32601);
  assert.equal(mcpJsonRpcErrorCodeFor({ status: 422 }), -32602);
  assert.equal(mcpJsonRpcErrorCodeFor({ status: 500 }), -32603);

  assert.equal(mcpLiveExecutionModeForServer({ transport: "stdio", command: "npx" }), "live_stdio");
  assert.equal(
    mcpLiveExecutionModeForServer({ transport: "http", server_url: "http://mcp.test", endpoint: "http://retired.test" }),
    "live_http",
  );
  assert.equal(
    mcpLiveExecutionModeForServer({ transport: "sse", server_url: "http://mcp.test/sse", serverUrl: "http://retired.test/sse" }),
    "live_sse",
  );
  assert.equal(mcpLiveExecutionModeForServer({ transport: "http", endpoint: "http://mcp.test" }), null);
  assert.equal(mcpLiveExecutionModeForServer({ transport: "sse", serverUrl: "http://mcp.test/sse" }), null);
  assert.equal(mcpLiveExecutionModeForServer({ transport: "stdio", command: "npx" }, { simulate: true }), null);
  assert.equal(
    mcpLiveExecutionModeForServer({ transport: "fixture" }, { execution_mode: "live_http", executionMode: "live_stdio" }),
    "live_http",
  );
  assert.equal(mcpLiveExecutionModeForServer({ transport: "fixture" }, { executionMode: "live_http" }), null);
  assert.equal(
    mcpLiveExecutionModeForServer(
      { transport: "fixture", server_url: "http://mcp.test" },
      { live_transport: true, liveTransport: false },
    ),
    "live_http",
  );
  assert.equal(
    mcpLiveExecutionModeForServer({ transport: "fixture", server_url: "http://mcp.test" }, { liveTransport: true }),
    null,
  );
  assert.equal(mcpTransportEvidenceRef({ execution_mode: "live_stdio", executionMode: "live_http" }), "mcp.transport.stdio.live");
  assert.equal(mcpTransportSummary({ execution_mode: "live_http", executionMode: "live_stdio" }), "live HTTP transport");
  assert.equal(mcpTransportEvidenceRef({ executionMode: "live_stdio" }), "mcp.manager.simulated_receipt");
  assert.equal(mcpTransportSummary({ executionMode: "live_http" }), "containment receipt");
});

test("runtime MCP helpers accept only canonical catalog request options", () => {
  assert.equal(mcpToolSearchLimit({ max_results: 7, maxResults: 99 }), 7);
  assert.equal(mcpToolSearchLimit({ maxResults: 7 }), 25);
  assert.equal(mcpCatalogFullRequested({ catalog_mode: "full", catalogMode: "summary" }), true);
  assert.equal(mcpCatalogFullRequested({ mcp_catalog_mode: "full", mcpCatalogMode: "summary" }), true);
  assert.equal(mcpCatalogFullRequested({ include_full_catalog: true, includeFullCatalog: false }), true);
  assert.equal(mcpCatalogFullRequested({ catalogMode: "full" }), false);
  assert.equal(mcpCatalogFullRequested({ mcpCatalogMode: "full" }), false);
  assert.equal(mcpCatalogFullRequested({ includeFullCatalog: true }), false);
});

test("runtime MCP helpers match canonical config source mode", () => {
  assert.equal(
    mcpConfigSourceModeForRequest({
      config_source_mode: "global-only",
      configSourceMode: "workspace",
    }),
    "global",
  );
  assert.equal(
    mcpConfigSourceModeForRequest({
      mcp_config_source_mode: "workspace-only",
      mcpConfigSourceMode: "global",
    }),
    "workspace",
  );
  assert.equal(mcpServerMatchesConfigSourceMode({ sourceScope: "global" }, "global"), false);
  assert.equal(mcpServerMatchesConfigSourceMode({ source_scope: "global", sourceScope: "workspace" }, "global"), true);
  assert.equal(mcpServerMatchesConfigSourceMode({ source_scope: "global" }, "workspace"), false);
});
