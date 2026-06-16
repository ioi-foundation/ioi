import assert from "node:assert/strict";
import test from "node:test";

import {
  mcpRegistryForWorkspace,
  mcpServerRecordsFromValidationInput,
} from "./mcp-manager.mjs";

function rustMcpCore(calls = []) {
  return {
    projectMcpServerValidationInput(request) {
      calls.push({ name: "projectMcpServerValidationInput", request });
      const servers = Object.entries(request.input.mcp_json?.mcp_servers ?? {}).map(
        ([label, config]) => {
          const id = config.id ?? `mcp.${label}`;
          return {
            schema_version: "ioi.runtime.mcp-manager-status.v1",
            id,
            label,
            name: label,
            enabled: config.enabled !== false,
            status: request.input.status ?? "configured",
            transport: config.transport ?? "stdio",
            command: config.command ?? null,
            server_url: config.server_url ?? config.url ?? null,
            workspace_root: request.workspace_root,
            source: request.input.source ?? "validation_input",
            source_path: request.input.source_path ?? null,
            source_scope: request.input.source_scope ?? "validation",
            allowed_tools: Array.isArray(config.allowed_tools) ? config.allowed_tools : [],
            resources: Array.isArray(config.resources) ? config.resources : [],
            prompts: Array.isArray(config.prompts) ? config.prompts : [],
            containment: {
              mode: config.containment_mode ?? config.containment?.mode ?? "sandboxed",
              allow_network_egress: config.allow_network_egress ?? false,
              allow_child_processes: config.allow_child_processes ?? Boolean(config.command),
              workspace_root: request.workspace_root,
            },
            vault_boundary: {
              required: Boolean(config.headers || config.env),
              secret_values_included: false,
            },
          };
        },
      );
      return {
        source: "rust_mcp_server_validation_input_api",
        backend: "rust_policy",
        status: "projected",
        workspace_root: request.workspace_root,
        server_count: servers.length,
        servers,
      };
    },
    planMcpManagerCatalogProjection(request) {
      calls.push({ name: "planMcpManagerCatalogProjection", request });
      const servers = [...(request.servers ?? [])].sort((left, right) =>
        left.id.localeCompare(right.id),
      );
      const tools = servers.flatMap((server) =>
        server.allowed_tools.map((tool) => ({
          stable_tool_id: `rust.projected.${server.id}.${tool}`,
          server_id: server.id,
          server_label: server.label,
          tool_name: tool,
          source: "rust_mcp_manager_catalog_projection_api",
        })),
      );
      const resources = servers.flatMap((server) =>
        server.resources.map((resource) => ({
          stable_resource_id: `rust.projected.${server.id}.resource.${resource.uri}`,
          server_id: server.id,
          uri: resource.uri,
          source: "rust_mcp_manager_catalog_projection_api",
        })),
      );
      const prompts = servers.flatMap((server) =>
        server.prompts.map((prompt) => ({
          stable_prompt_id: `rust.projected.${server.id}.prompt.${prompt.name}`,
          server_id: server.id,
          name: prompt.name,
          source: "rust_mcp_manager_catalog_projection_api",
        })),
      );
      return {
        source: "rust_mcp_manager_catalog_projection_api",
        backend: "rust_policy",
        status: "projected",
        servers,
        tools,
        resources,
        prompts,
        enabled_tools: tools,
      };
    },
  };
}

test("MCP manager validation input consumes canonical MCP JSON fields only", () => {
  const calls = [];
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
  }, "/workspace", { contextPolicyCore: rustMcpCore(calls) });

  assert.deepEqual(canonicalRecords.map((record) => record.label), ["canonical"]);
  assert.equal(calls[0].request.workspace_root, "/workspace");
  assert.equal(calls[0].request.input.mcp_json.mcp_servers.canonical.command, "npx");
  assert.equal(canonicalRecords[0].source_scope, "validation");
  assert.equal(Object.hasOwn(canonicalRecords[0], "sourceScope"), false);

  const retiredRecords = mcpServerRecordsFromValidationInput({
    mcpJson: {
      mcpServers: {
        retired: { transport: "stdio", command: "retired" },
      },
    },
  }, "/workspace", { contextPolicyCore: rustMcpCore(calls) });
  assert.deepEqual(retiredRecords, []);
});

test("MCP manager registry returns Rust-projected catalog rows", () => {
  const calls = [];
  const registry = mcpRegistryForWorkspace("/workspace", {
    contextPolicyCore: rustMcpCore(calls),
    mcp_config_source_mode: "thread",
    mcp_servers: {
      docs: {
        transport: "stdio",
        command: "npx",
        allowed_tools: ["search"],
        resources: [{ uri: "docs://root", name: "root" }],
        prompts: [{ name: "ask", arguments: [{ name: "q" }] }],
        headers: { Authorization: "vault://mcp/docs/token" },
        allowedTools: ["retired.invoke"],
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

  assert.deepEqual(calls.map((call) => call.name), [
    "projectMcpServerValidationInput",
    "planMcpManagerCatalogProjection",
  ]);
  assert.equal(calls[0].request.input.source, "inline_options");
  assert.equal(calls[0].request.input.source_scope, "thread");
  assert.equal(Object.hasOwn(calls[0].request.input, "config_compatibility"), false);
  assert.equal(Object.hasOwn(calls[0].request.input, "mcpServers"), false);
  assert.equal(Object.hasOwn(calls[0].request.input.mcp_json.mcp_servers.docs, "allowedTools"), true);

  const server = registry.servers[0];
  assert.equal(server.source, "inline_options");
  assert.equal(server.source_scope, "thread");
  assert.equal(Object.hasOwn(server, "config_compatibility"), false);
  assert.equal(server.workspace_root, "/workspace");
  assert.equal(server.vault_boundary.secret_values_included, false);
  assert.equal(Object.hasOwn(server, "sourceScope"), false);
  assert.equal(Object.hasOwn(server, "configCompatibility"), false);

  assert.equal(registry.tools[0].stable_tool_id, "rust.projected.mcp.docs.search");
  assert.equal(registry.resources[0].stable_resource_id, "rust.projected.mcp.docs.resource.docs://root");
  assert.equal(registry.prompts[0].stable_prompt_id, "rust.projected.mcp.docs.prompt.ask");
  assert.equal(Object.hasOwn(registry.tools[0], "stableToolId"), false);
});

test("MCP manager registry ignores retired top-level MCP config aliases", () => {
  const calls = [];
  const registry = mcpRegistryForWorkspace("/workspace", {
    contextPolicyCore: rustMcpCore(calls),
    mcp_config_source_mode: "thread",
    mcpServers: {
      retired: {
        transport: "stdio",
        command: "retired",
        allowedTools: ["retired.invoke"],
      },
    },
  });

  assert.equal(registry.server_count, 0);
  assert.deepEqual(registry.servers, []);
  assert.deepEqual(registry.tools, []);
  assert.deepEqual(calls.map((call) => call.name), ["planMcpManagerCatalogProjection"]);
});

test("MCP manager registry fails closed without Rust daemon-core projection", () => {
  assert.throws(
    () => mcpRegistryForWorkspace("/workspace", {
      mcp_config_source_mode: "thread",
      mcp_servers: {
        docs: { transport: "stdio", command: "npx" },
      },
    }),
    (error) =>
      error.code === "runtime_mcp_manager_context_policy_core_required" &&
      error.details.boundary === "runtime.mcp_manager" &&
      error.details.required_mount === "contextPolicyCore",
  );
});
