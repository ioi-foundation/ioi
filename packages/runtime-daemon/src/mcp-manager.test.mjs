import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  discoverMcpStdioCatalog,
  mcpRegistryForWorkspace,
  mcpServerRecordsFromValidationInput,
  normalizeMcpServerRecord,
} from "./mcp-manager.mjs";

test("MCP manager validation input consumes canonical MCP JSON fields only", () => {
  const calls = [];
  const contextPolicyCore = {
    projectMcpServerValidationInput(request) {
      calls.push(request);
      return {
        source: "rust_mcp_server_validation_input_command",
        backend: "rust_policy",
        status: "projected",
        workspace_root: request.workspace_root,
        server_count: request.input.mcp_json?.mcp_servers ? 1 : 0,
        servers: request.input.mcp_json?.mcp_servers
          ? [
              {
                id: "mcp.canonical",
                label: "canonical",
                source_scope: "validation",
                workspace_root: request.workspace_root,
              },
            ]
          : [],
      };
    },
  };
  const canonicalRecords = mcpServerRecordsFromValidationInput({
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
  }, "/workspace", { contextPolicyCore });
  assert.deepEqual(canonicalRecords.map((record) => record.label), ["canonical"]);
  assert.equal(calls[0].workspace_root, "/workspace");
  assert.equal(calls[0].input.mcp_json.mcp_servers.canonical.command, "npx");
  assert.equal(canonicalRecords[0].source_scope, "validation");
  assert.equal(Object.hasOwn(canonicalRecords[0], "sourceScope"), false);

  const retiredRecords = mcpServerRecordsFromValidationInput({
    mcpJson: {
      mcpServers: {
        retired: { transport: "stdio", command: "retired" },
      },
    },
  }, "/workspace", { contextPolicyCore });
  assert.deepEqual(retiredRecords, []);
  assert.equal(calls.length, 2);
});

test("MCP manager registry and server records emit canonical output fields only", () => {
  const registry = mcpRegistryForWorkspace("/workspace", {
    mcp_config_source_mode: "thread",
    mcp_servers: {
      docs: {
        transport: "stdio",
        command: "npx",
        allowed_tools: ["search"],
        resources: [{ uri: "docs://root", name: "root" }],
        prompts: [{ name: "ask", arguments: [{ name: "q" }] }],
        headers: { Authorization: "vault://mcp/docs/token" },
      },
    },
    mcpServers: {
      retired: {
        transport: "stdio",
        command: "retired",
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
  assert.equal(server.label, "docs");
  assert.equal(server.workspace_root, "/workspace");
  assert.equal(server.server_url, null);
  assert.deepEqual(server.header_names, ["Authorization"]);
  assert.deepEqual(server.allowed_tools, ["search"]);
  assert.equal(server.tool_count, 1);
  assert.equal(server.containment.workspace_root, "/workspace");
  assert.equal(server.vault_boundary.header_ref_count, 1);
  assert.equal(server.vault_boundary.secret_values_included, false);
  assert.equal(Object.hasOwn(server, "schemaVersion"), false);
  assert.equal(Object.hasOwn(server, "workspaceRoot"), false);
  assert.equal(Object.hasOwn(server, "serverUrl"), false);
  assert.equal(Object.hasOwn(server, "headerNames"), false);
  assert.equal(Object.hasOwn(server, "allowedTools"), false);
  assert.equal(Object.hasOwn(server, "toolCount"), false);
  assert.equal(Object.hasOwn(server, "secretRefs"), false);
  assert.equal(Object.hasOwn(server, "vaultBoundary"), false);
  assert.equal(Object.hasOwn(server, "evidenceRefs"), false);
  assert.equal(Object.hasOwn(server.containment, "workspaceRoot"), false);
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

test("MCP manager server records ignore retired allowedTools aliases", () => {
  const server = normalizeMcpServerRecord(
    "docs",
    {
      transport: "stdio",
      command: "npx",
      allowed_tools: ["search"],
      allowedTools: ["retired.invoke"],
    },
    {
      workspace_root: "/workspace",
      source: "test",
    },
  );

  assert.deepEqual(server.allowed_tools, ["search"]);
  assert.deepEqual(server.tool_count, 1);
  assert.equal(Object.hasOwn(server, "allowedTools"), false);

  const retiredOnly = normalizeMcpServerRecord(
    "docs",
    {
      transport: "stdio",
      command: "npx",
      allowedTools: ["retired.invoke"],
    },
    {
      workspace_root: "/workspace",
      source: "test",
    },
  );

  assert.deepEqual(retiredOnly.allowed_tools, []);
  assert.deepEqual(mcpRegistryForWorkspace("/workspace", {
    mcp_servers: {
      docs: {
        transport: "stdio",
        command: "npx",
        allowedTools: ["retired.invoke"],
      },
    },
  }).tools, []);
});

test("MCP manager server records ignore retired allowedResources and allowedPrompts aliases", () => {
  const server = normalizeMcpServerRecord(
    "docs",
    {
      transport: "stdio",
      command: "npx",
      resources: [{ uri: "docs://canonical", name: "canonical" }],
      allowedResources: [{ uri: "docs://retired", name: "retired" }],
      prompts: [{ name: "ask_canonical" }],
      allowedPrompts: [{ name: "ask_retired" }],
    },
    {
      workspace_root: "/workspace",
      source: "test",
    },
  );

  assert.deepEqual(server.resources.map((resource) => resource.uri), ["docs://canonical"]);
  assert.deepEqual(server.prompts.map((prompt) => prompt.name), ["ask_canonical"]);
  assert.equal(Object.hasOwn(server, "allowedResources"), false);
  assert.equal(Object.hasOwn(server, "allowedPrompts"), false);

  const retiredOnly = mcpRegistryForWorkspace("/workspace", {
    mcp_servers: {
      docs: {
        transport: "stdio",
        command: "npx",
        allowedResources: [{ uri: "docs://retired", name: "retired" }],
        allowedPrompts: [{ name: "ask_retired" }],
      },
    },
  });

  assert.deepEqual(retiredOnly.resources, []);
  assert.deepEqual(retiredOnly.prompts, []);
  assert.equal(retiredOnly.resource_count, 0);
  assert.equal(retiredOnly.prompt_count, 0);
});

test("MCP manager server records ignore retired transport and containment aliases", () => {
  const server = normalizeMcpServerRecord(
    "docs",
    {
      transport: "http",
      server_url: "https://canonical.example.test/mcp",
      serverUrl: "https://retired.example.test/mcp",
      containment_mode: "canonical-sandbox",
      containmentMode: "retired-sandbox",
      allow_network_egress: false,
      allowNetworkEgress: true,
      allow_child_processes: false,
      allowChildProcesses: true,
      containment: {
        allowNetworkEgress: true,
        allowChildProcesses: true,
      },
    },
    {
      workspace_root: "/workspace",
      source: "test",
    },
  );

  assert.equal(server.server_url, "https://canonical.example.test/mcp");
  assert.notEqual(server.server_url, "https://retired.example.test/mcp");
  assert.equal(server.containment.mode, "canonical-sandbox");
  assert.equal(server.containment.allow_network_egress, false);
  assert.equal(server.containment.allow_child_processes, false);
  assert.equal(Object.hasOwn(server, "serverUrl"), false);
  assert.equal(Object.hasOwn(server.containment, "allowNetworkEgress"), false);
  assert.equal(Object.hasOwn(server.containment, "allowChildProcesses"), false);

  const retiredOnly = normalizeMcpServerRecord(
    "docs",
    {
      transport: "http",
      serverUrl: "https://retired.example.test/mcp",
      containmentMode: "retired-sandbox",
      allowNetworkEgress: true,
      allowChildProcesses: true,
      containment: {
        allowNetworkEgress: true,
        allowChildProcesses: true,
      },
    },
    {
      workspace_root: "/workspace",
      source: "test",
    },
  );

  assert.equal(retiredOnly.server_url, null);
  assert.equal(retiredOnly.containment.mode, "sandboxed");
  assert.equal(retiredOnly.containment.allow_network_egress, false);
  assert.equal(retiredOnly.containment.allow_child_processes, false);
});

test("MCP manager server records ignore retired workspaceRoot context alias", () => {
  const server = normalizeMcpServerRecord(
    "docs",
    { transport: "stdio", command: "npx" },
    {
      workspace_root: "/workspace",
      workspaceRoot: "/retired-workspace",
      source: "test",
    },
  );

  assert.equal(server.workspace_root, "/workspace");
  assert.equal(server.containment.workspace_root, "/workspace");
  assert.notEqual(server.workspace_root, "/retired-workspace");
  assert.notEqual(server.containment.workspace_root, "/retired-workspace");
  assert.equal(Object.hasOwn(server, "workspaceRoot"), false);
  assert.equal(Object.hasOwn(server.containment, "workspaceRoot"), false);
});

test("MCP manager server records ignore retired sourcePath and sourceScope aliases", () => {
  const server = normalizeMcpServerRecord(
    "docs",
    {
      transport: "stdio",
      command: "npx",
      source_path: "/canonical/config.json",
      sourcePath: "/retired/config.json",
      source_scope: "workspace",
      sourceScope: "retired",
    },
    {
      workspace_root: "/workspace",
      source: "test",
      source_path: "/canonical/context.json",
      sourcePath: "/retired/context.json",
      source_scope: "thread",
      sourceScope: "retired-context",
    },
  );

  assert.equal(server.source_path, "/canonical/config.json");
  assert.equal(server.source_scope, "workspace");
  assert.notEqual(server.source_path, "/retired/config.json");
  assert.notEqual(server.source_scope, "retired");
  assert.equal(Object.hasOwn(server, "sourcePath"), false);
  assert.equal(Object.hasOwn(server, "sourceScope"), false);

  const retiredOnly = normalizeMcpServerRecord(
    "docs",
    {
      transport: "stdio",
      command: "npx",
      sourcePath: "/retired/config.json",
      sourceScope: "retired",
    },
    {
      workspace_root: "/workspace",
      source: "test",
      sourcePath: "/retired/context.json",
      sourceScope: "retired-context",
    },
  );

  assert.equal(retiredOnly.source_path, null);
  assert.equal(retiredOnly.source_scope, "workspace");
  assert.equal(retiredOnly.evidence_refs.includes("/retired/context.json"), false);
  assert.equal(retiredOnly.evidence_refs.includes("retired-context"), false);
});

test("MCP manager server records ignore retired configCompatibility aliases", () => {
  const server = normalizeMcpServerRecord(
    "docs",
    {
      transport: "stdio",
      command: "npx",
      config_compatibility: "canonical-config",
      configCompatibility: "retired-config",
    },
    {
      workspace_root: "/workspace",
      source: "test",
      config_compatibility: "canonical-context",
      configCompatibility: "retired-context",
    },
  );

  assert.equal(server.config_compatibility, "canonical-config");
  assert.notEqual(server.config_compatibility, "retired-config");
  assert.notEqual(server.config_compatibility, "retired-context");
  assert.equal(Object.hasOwn(server, "configCompatibility"), false);

  const retiredOnly = normalizeMcpServerRecord(
    "docs",
    {
      transport: "stdio",
      command: "npx",
      configCompatibility: "retired-config",
    },
    {
      workspace_root: "/workspace",
      source: "test",
      configCompatibility: "retired-context",
    },
  );

  assert.equal(retiredOnly.config_compatibility, null);
  assert.equal(retiredOnly.evidence_refs.includes("retired-context"), false);
});

test("MCP stdio sessions ignore retired workspaceRoot cwd aliases", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-mcp-cwd-"));
  const canonicalCwd = path.join(root, "canonical");
  const retiredCwd = path.join(root, "retired");
  const fixture = `
    let buffer = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      buffer += chunk;
      let index = buffer.indexOf("\\n");
      while (index >= 0) {
        const line = buffer.slice(0, index).trim();
        buffer = buffer.slice(index + 1);
        if (line) {
          const message = JSON.parse(line);
          if (message.id != null) {
            let result = {};
            if (message.method === "initialize") {
              result = { protocolVersion: "2024-11-05", serverInfo: { name: "cwd-fixture" } };
            } else if (message.method === "tools/list") {
              result = { tools: [] };
            } else if (message.method === "resources/list") {
              result = { resources: [] };
            } else if (message.method === "prompts/list") {
              result = { prompts: [] };
            }
            process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }) + "\\n");
          }
        }
        index = buffer.indexOf("\\n");
      }
    });
  `;

  try {
    const catalog = await discoverMcpStdioCatalog(
      {
        id: "mcp.cwd",
        transport: "stdio",
        command: process.execPath,
        args: ["-e", fixture],
        workspace_root: canonicalCwd,
        workspaceRoot: retiredCwd,
        containment: {
          workspace_root: canonicalCwd,
          workspaceRoot: retiredCwd,
        },
      },
      { timeout_ms: 2_000 },
    );

    assert.equal(catalog.cwd, path.resolve(canonicalCwd));
    assert.notEqual(catalog.cwd, path.resolve(retiredCwd));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
