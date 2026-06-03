import assert from "node:assert/strict";
import test from "node:test";

import {
  mcpCatalogExposureForStatus,
  mcpCatalogFullRequested,
  mcpConfigSourceModeForRequest,
  mcpJsonRpcError,
  mcpJsonRpcErrorCodeFor,
  mcpJsonRpcResult,
  mcpLiveExecutionModeForServer,
  mcpRegistryWithServers,
  mcpServeAllowedToolIds,
  mcpServeToolCallResult,
  mcpServeToolDescriptor,
  mcpServeToolIdForName,
  mcpServerMatchesConfigSourceMode,
  mcpServerRecordFromAddRequest,
  mcpServerRecordsFromMutationInput,
  mcpToolIdentityMatches,
  mcpToolMatchesQuery,
  mcpToolNamespaces,
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

  const byStableId = resolveMcpToolRecord(servers, "mcp.workspace.docs.search");
  assert.equal(byStableId.server.id, "mcp.workspace.docs");
  assert.equal(byStableId.toolName, "search");

  assert.equal(mcpToolIdentityMatches({
    stableToolId: "mcp.workspace.docs.search",
    workflowNodeId: "runtime.mcp.docs.search",
    toolName: "search",
    serverId: "mcp.workspace.docs",
  }, "runtime.mcp.docs.search"), true);
  assert.equal(mcpToolMatchesQuery({ serverLabel: "Docs", toolName: "search" }, "doc"), true);
});

test("runtime MCP helpers shape serve descriptors and tool results", () => {
  assert.deepEqual(mcpServeAllowedToolIds({
    allowedTools: ["workspace.status", "git.diff", "not.allowed"],
  }), ["workspace.status", "git.diff"]);
  assert.equal(mcpServeToolIdForName("git.diff", { allowedTools: ["git.diff"] }), "git.diff");
  assert.equal(mcpServeToolIdForName("git_diff", { allowedTools: ["git.diff"] }), null);

  const descriptor = mcpServeToolDescriptor({
    stableToolId: "file.inspect",
    displayName: "Inspect file",
    effectClass: "local_read",
    authorityScopeRequirements: ["workspace.fs.read"],
  });
  assert.equal(descriptor.name, "file.inspect");
  assert.equal(descriptor._meta.approvalRequired, true);
  assert.equal(descriptor.annotations.readOnlyHint, true);

  const result = mcpServeToolCallResult({
    tool_name: "file.inspect",
    status: "failed",
    receipt_refs: ["receipt-1"],
    event: { id: "event-1", payload_summary: { summary: "Could not inspect file." } },
    error: { code: "blocked" },
  });
  assert.equal(result.isError, true);
  assert.equal(result.content[0].text, "Could not inspect file.");
  assert.deepEqual(result.structuredContent.receipt_refs, ["receipt-1"]);
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
  assert.equal(mcpLiveExecutionModeForServer({ transport: "http", endpoint: "http://mcp.test" }), "live_http");
  assert.equal(mcpLiveExecutionModeForServer({ transport: "sse", serverUrl: "http://mcp.test/sse" }), "live_sse");
  assert.equal(mcpLiveExecutionModeForServer({ transport: "stdio", command: "npx" }, { simulate: true }), null);
});

test("runtime MCP helpers summarize and defer large catalogs", () => {
  const tools = Array.from({ length: 4 }, (_, index) => ({
    stableToolId: `mcp.docs.search_${index}`,
    toolName: `docs__search_${index}`,
    description: "Search docs",
    inputSchema: { type: "object" },
  }));
  const exposure = mcpCatalogExposureForStatus(
    { id: "mcp.docs", label: "Docs", transport: "stdio" },
    { tools, resources: [{ uri: "docs://root" }], prompts: [{ name: "ask" }] },
    { previewLimit: 2 },
  );

  assert.equal(exposure.tools.length, 2);
  assert.equal(exposure.exposure.deferred, true);
  assert.equal(exposure.summary.toolCount, 4);
  assert.equal(exposure.summary.fullCatalogIncluded, false);
  assert.deepEqual(mcpToolNamespaces(["docs__search", "git.diff", "file.inspect"]), ["docs", "file", "git"]);
  assert.equal(mcpCatalogFullRequested({ catalogMode: "full" }), true);
});

test("runtime MCP helpers normalize mutation inputs and registry projections", () => {
  const record = mcpServerRecordFromAddRequest({
    label: "Docs",
    config: {
      transport: "stdio",
      command: "npx",
      tools: [{ name: "search" }],
    },
  }, "/workspace");
  assert.equal(record.label, "Docs");
  assert.equal(record.sourceScope, "thread");
  assert.equal(record.status, "configured");

  const records = mcpServerRecordsFromMutationInput({
    configSource: "workspace",
    servers: {
      docs: { transport: "stdio", command: "npx" },
    },
  }, "/workspace", "fallback");
  assert.equal(records.length, 1);
  assert.equal(records[0].label, "docs");

  const registry = mcpRegistryWithServers({}, [record]);
  assert.equal(registry.serverCount, 1);
  assert.equal(registry.toolCount, 1);
  assert.equal(mcpConfigSourceModeForRequest({ configSourceMode: "global-only" }), "global");
  assert.equal(mcpServerMatchesConfigSourceMode({ sourceScope: "global" }, "global"), true);
  assert.equal(mcpServerMatchesConfigSourceMode({ sourceScope: "global" }, "workspace"), false);
});
