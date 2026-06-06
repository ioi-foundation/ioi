import assert from "node:assert/strict";
import test from "node:test";

import {
  mcpRegistryForWorkspace,
  validateMcpServerRecords,
} from "./mcp-manager.mjs";

test("MCP manager validation emits canonical output fields only", () => {
  const validation = validateMcpServerRecords([
    {
      id: "mcp.invalid",
      transport: "socket",
      allowed_tools: [],
    },
  ]);

  assert.equal(validation.schema_version, "ioi.runtime.mcp-manager-validation.v1");
  assert.equal(validation.ok, false);
  assert.equal(validation.issues[0].server_id, "mcp.invalid");
  assert.equal(validation.warnings[0].server_id, "mcp.invalid");
  assert.equal(Object.hasOwn(validation, "schemaVersion"), false);
  assert.equal(Object.hasOwn(validation.issues[0], "serverId"), false);
  assert.equal(Object.hasOwn(validation.warnings[0], "serverId"), false);
});

test("MCP manager registry and server records emit canonical output fields only", () => {
  const registry = mcpRegistryForWorkspace("/workspace", {
    mcp_config_source_mode: "thread",
    mcpServers: {
      docs: {
        transport: "stdio",
        command: "npx",
        allowed_tools: ["search"],
        headers: { Authorization: "vault://mcp/docs/token" },
      },
    },
  });

  assert.equal(registry.schema_version, "ioi.runtime.mcp-manager-status.v1");
  assert.equal(registry.workspace_root, "/workspace");
  assert.equal(registry.server_count, 1);
  assert.equal(registry.tool_count, 1);
  assert.equal(Object.hasOwn(registry, "schemaVersion"), false);
  assert.equal(Object.hasOwn(registry, "workspaceRoot"), false);
  assert.equal(Object.hasOwn(registry, "serverCount"), false);
  assert.equal(Object.hasOwn(registry, "toolCount"), false);

  const server = registry.servers[0];
  assert.equal(server.schema_version, "ioi.runtime.mcp-manager-status.v1");
  assert.equal(server.server_url, null);
  assert.deepEqual(server.header_names, ["Authorization"]);
  assert.deepEqual(server.allowed_tools, ["search"]);
  assert.equal(server.tool_count, 1);
  assert.equal(server.vault_boundary.header_ref_count, 1);
  assert.equal(server.vault_boundary.secret_values_included, false);
  assert.equal(Object.hasOwn(server, "schemaVersion"), false);
  assert.equal(Object.hasOwn(server, "serverUrl"), false);
  assert.equal(Object.hasOwn(server, "headerNames"), false);
  assert.equal(Object.hasOwn(server, "allowedTools"), false);
  assert.equal(Object.hasOwn(server, "toolCount"), false);
  assert.equal(Object.hasOwn(server, "secretRefs"), false);
  assert.equal(Object.hasOwn(server, "vaultBoundary"), false);
  assert.equal(Object.hasOwn(server, "evidenceRefs"), false);
  assert.equal(Object.hasOwn(server.vault_boundary, "headerRefCount"), false);
  assert.equal(Object.hasOwn(server.vault_boundary, "secretValuesIncluded"), false);
});
