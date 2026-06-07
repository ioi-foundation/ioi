import assert from "node:assert/strict";
import test from "node:test";

import { RUNTIME_MCP_SERVE_DEFAULT_ALLOWED_TOOL_IDS } from "./runtime-contract-constants.mjs";
import {
  mcpCatalogExposureForStatus,
  mcpCatalogFullRequested,
  mcpConfigSourceModeForRequest,
  mcpJsonRpcError,
  mcpJsonRpcErrorCodeFor,
  mcpJsonRpcResult,
  mcpLiveExecutionModeForServer,
  mcpTransportEvidenceRef,
  mcpTransportSummary,
  mcpRegistryWithServers,
  mcpServeAllowedToolIds,
  mcpServeToolCallResult,
  mcpServeToolDescriptor,
  mcpServeToolIdForName,
  mcpServerMatchesConfigSourceMode,
  mcpServerRecordFromAddRequest,
  mcpServerRecordsFromMutationInput,
  mcpToolSearchLimit,
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

test("runtime MCP helpers shape serve descriptors and tool results", () => {
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
  assert.equal(descriptor._meta.approvalRequired, true);
  assert.equal(descriptor.annotations.readOnlyHint, true);

  const result = mcpServeToolCallResult({
    tool_name: "file.inspect",
    status: "failed",
    receipt_refs: ["receipt-1"],
    event: { event_id: "event-1", payload_summary: { summary: "Could not inspect file." } },
    error: { code: "blocked" },
  });
  assert.equal(result.isError, true);
  assert.equal(result.content[0].text, "Could not inspect file.");
  assert.equal(result.structuredContent.event_id, "event-1");
  assert.deepEqual(result.structuredContent.receipt_refs, ["receipt-1"]);

  const retiredAlias = mcpServeToolCallResult({
    tool_name: "file.inspect",
    event: { id: "legacy-event-id", payload_summary: { summary: "Inspect complete." } },
  });
  assert.equal(retiredAlias.structuredContent.event_id, null);
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

test("runtime MCP helpers summarize and defer large catalogs", () => {
  const tools = Array.from({ length: 4 }, (_, index) => ({
    stable_tool_id: `mcp.docs.search_${index}`,
    tool_name: `docs__search_${index}`,
    description: "Search docs",
    input_schema: { type: "object" },
  }));
  const exposure = mcpCatalogExposureForStatus(
    { id: "mcp.docs", label: "Docs", transport: "stdio" },
    { tools, resources: [{ uri: "docs://root" }], prompts: [{ name: "ask" }] },
    { preview_limit: 2 },
  );

  assert.equal(exposure.tools.length, 2);
  assert.equal(exposure.exposure.deferred, true);
  assert.equal(exposure.summary.tool_count, 4);
  assert.equal(exposure.summary.full_catalog_included, false);
  assert.equal(exposure.exposure.preview_limit, 2);
  assert.equal(Object.hasOwn(exposure.summary, "toolCount"), false);
  assert.equal(Object.hasOwn(exposure.summary, "fullCatalogIncluded"), false);
  assert.equal(Object.hasOwn(exposure.summary, "executionMode"), false);
  assert.equal(Object.hasOwn(exposure.summary, "errorCode"), false);
  assert.equal(Object.hasOwn(exposure.summary, "searchRoute"), false);
  assert.equal(Object.hasOwn(exposure.exposure, "previewLimit"), false);
  assert.equal(Object.hasOwn(exposure.exposure, "returnedToolCount"), false);
  assert.equal(Object.hasOwn(exposure.exposure, "searchRoute"), false);

  const largeCatalogTools = Array.from({ length: 60 }, (_, index) => ({
    stable_tool_id: `mcp.docs.large_${index}`,
    tool_name: `docs__large_${index}`,
  }));
  const retiredOptionExposure = mcpCatalogExposureForStatus(
    { id: "mcp.docs", label: "Docs", transport: "stdio" },
    { tools: largeCatalogTools, resources: [], prompts: [] },
    { previewLimit: 2, forceFullCatalog: true },
  );
  assert.equal(retiredOptionExposure.tools.length, 50);
  assert.equal(retiredOptionExposure.exposure.mode, "deferred");

  assert.deepEqual(mcpToolNamespaces(["docs__search", "git.diff", "file.inspect"]), ["docs", "file", "git"]);
  assert.equal(mcpToolSearchLimit({ max_results: 7, maxResults: 99 }), 7);
  assert.equal(mcpToolSearchLimit({ maxResults: 7 }), 25);
  assert.equal(mcpCatalogFullRequested({ catalog_mode: "full", catalogMode: "summary" }), true);
  assert.equal(mcpCatalogFullRequested({ mcp_catalog_mode: "full", mcpCatalogMode: "summary" }), true);
  assert.equal(mcpCatalogFullRequested({ include_full_catalog: true, includeFullCatalog: false }), true);
  assert.equal(mcpCatalogFullRequested({ catalogMode: "full" }), false);
  assert.equal(mcpCatalogFullRequested({ mcpCatalogMode: "full" }), false);
  assert.equal(mcpCatalogFullRequested({ includeFullCatalog: true }), false);
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
  assert.equal(record.source_scope, "thread");
  assert.equal(record.status, "configured");
  assert.equal(Object.hasOwn(record, "schemaVersion"), false);
  assert.equal(Object.hasOwn(record, "serverUrl"), false);
  assert.equal(Object.hasOwn(record, "sourceScope"), false);
  assert.equal(Object.hasOwn(record, "allowedTools"), false);
  assert.equal(Object.hasOwn(record, "evidenceRefs"), false);
  assert.equal(Object.hasOwn(record, "vaultBoundary"), false);
  assert.equal(Object.hasOwn(record.vault_boundary, "headerRefCount"), false);

  const records = mcpServerRecordsFromMutationInput({
    config_source: "workspace",
    configSource: "retired-camel-source",
    servers: {
      docs: { transport: "stdio", command: "npx" },
    },
  }, "/workspace", "fallback");
  assert.equal(records.length, 1);
  assert.equal(records[0].label, "docs");
  assert.equal(records[0].source, "workspace");

  const canonicalJsonRecords = mcpServerRecordsFromMutationInput({
    mcp_json: {
      mcp_servers: {
        canonical: { transport: "stdio", command: "npx" },
      },
    },
    mcpJson: {
      mcpServers: {
        retired: { transport: "stdio", command: "retired" },
      },
    },
  }, "/workspace", "fallback");
  assert.deepEqual(canonicalJsonRecords.map((item) => item.label), ["canonical"]);

  const retiredJsonRecords = mcpServerRecordsFromMutationInput({
    mcpJson: {
      mcpServers: {
        retired: { transport: "stdio", command: "retired" },
      },
    },
  }, "/workspace", "fallback");
  assert.deepEqual(retiredJsonRecords, []);

  const added = mcpServerRecordFromAddRequest({
    label: "Git",
    config_source: "runtime_control",
    configSource: "retired-camel-source",
    config: {
      transport: "stdio",
      command: "git",
    },
  }, "/workspace");
  assert.equal(added.source, "runtime_control");

  const canonicalServer = mcpServerRecordFromAddRequest({
    label: "Canonical",
    server: { transport: "stdio", command: "npx" },
    mcpServer: { transport: "stdio", command: "retired" },
  }, "/workspace");
  assert.equal(canonicalServer.command, "npx");

  const canonicalServerLabel = mcpServerRecordFromAddRequest({
    server_label: "Canonical Label",
    serverLabel: "Retired Label",
    config: { transport: "stdio", command: "npx" },
  }, "/workspace");
  assert.equal(canonicalServerLabel.label, "Canonical Label");

  const retiredServerLabel = mcpServerRecordFromAddRequest({
    serverLabel: "Retired Label",
    config: { transport: "stdio", command: "npx" },
  }, "/workspace");
  assert.equal(retiredServerLabel.label, "mcp");

  const retiredServer = mcpServerRecordFromAddRequest({
    label: "Retired",
    mcpServer: { transport: "stdio", command: "retired" },
  }, "/workspace");
  assert.equal(retiredServer.command, null);

  const registry = mcpRegistryWithServers({}, [record]);
  assert.equal(registry.server_count, 1);
  assert.equal(registry.tool_count, 1);
  assert.equal(Object.hasOwn(registry, "serverCount"), false);
  assert.equal(Object.hasOwn(registry, "toolCount"), false);
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
