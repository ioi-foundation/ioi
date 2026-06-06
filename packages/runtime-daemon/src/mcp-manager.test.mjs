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
        resources: [{ uri: "docs://root", name: "root" }],
        prompts: [{ name: "ask", arguments: [{ name: "q" }] }],
        headers: { Authorization: "vault://mcp/docs/token" },
      },
    },
  });

  assert.equal(registry.schema_version, "ioi.runtime.mcp-manager-status.v1");
  assert.equal(registry.workspace_root, "/workspace");
  assert.equal(registry.server_count, 1);
  assert.equal(registry.tool_count, 1);
  assert.equal(registry.resource_count, 1);
  assert.equal(registry.prompt_count, 1);
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

  const tool = registry.tools[0];
  assert.equal(tool.stable_tool_id, "mcp.docs.search");
  assert.equal(tool.server_id, "mcp.docs");
  assert.equal(tool.tool_name, "search");
  assert.deepEqual(tool.primitive_capabilities, ["prim:connector.invoke"]);
  assert.equal(tool.input_schema.type, "object");
  assert.equal(Object.hasOwn(tool, "schemaVersion"), false);
  assert.equal(Object.hasOwn(tool, "stableToolId"), false);
  assert.equal(Object.hasOwn(tool, "serverId"), false);
  assert.equal(Object.hasOwn(tool, "toolName"), false);
  assert.equal(Object.hasOwn(tool, "primitiveCapabilities"), false);
  assert.equal(Object.hasOwn(tool, "inputSchema"), false);
  assert.equal(Object.hasOwn(tool, "workflowNodeId"), false);
  assert.equal(Object.hasOwn(tool, "receiptRefs"), false);

  const resource = registry.resources[0];
  assert.equal(resource.stable_resource_id, "mcp.docs.resource.docs_root");
  assert.equal(resource.server_id, "mcp.docs");
  assert.equal(resource.mime_type, null);
  assert.equal(Object.hasOwn(resource, "stableResourceId"), false);
  assert.equal(Object.hasOwn(resource, "serverId"), false);
  assert.equal(Object.hasOwn(resource, "mimeType"), false);
  assert.equal(Object.hasOwn(resource, "workflowNodeId"), false);

  const prompt = registry.prompts[0];
  assert.equal(prompt.stable_prompt_id, "mcp.docs.prompt.ask");
  assert.equal(prompt.server_id, "mcp.docs");
  assert.equal(prompt.prompt_arguments.length, 1);
  assert.equal(Object.hasOwn(prompt, "stablePromptId"), false);
  assert.equal(Object.hasOwn(prompt, "serverId"), false);
  assert.equal(Object.hasOwn(prompt, "promptArguments"), false);
  assert.equal(Object.hasOwn(prompt, "workflowNodeId"), false);
});
