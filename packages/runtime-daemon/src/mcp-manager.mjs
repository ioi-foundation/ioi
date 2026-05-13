import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-status.v1";
export const RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-validation.v1";

export function mcpRegistryForWorkspace(cwd, options = {}) {
  const workspaceRoot = path.resolve(options.local?.cwd ?? cwd ?? process.cwd());
  const servers = [];
  for (const [label, config] of Object.entries(options.mcpServers ?? {})) {
    servers.push(
      normalizeMcpServerRecord(label, config, {
        workspaceRoot,
        source: "inline_options",
        status: "configured",
      }),
    );
  }
  for (const source of loadMcpConfigSources(workspaceRoot)) {
    for (const [label, config] of Object.entries(source.servers)) {
      servers.push(
        normalizeMcpServerRecord(label, config, {
          workspaceRoot,
          source: source.source,
          sourcePath: source.path,
          status: "configured",
        }),
      );
    }
  }
  const byId = new Map();
  for (const server of servers) byId.set(server.id, server);
  const normalizedServers = [...byId.values()].sort((left, right) =>
    left.id.localeCompare(right.id),
  );
  return {
    schemaVersion: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
    schema_version: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
    workspaceRoot,
    workspace_root: workspaceRoot,
    serverCount: normalizedServers.length,
    server_count: normalizedServers.length,
    servers: normalizedServers,
    tools: mcpToolsForServers(normalizedServers),
  };
}

export function mcpServerRecordsFromValidationInput(input = {}, workspaceRoot) {
  const raw = input.mcp_json ?? input.mcpJson ?? input;
  const servers = raw.mcpServers ?? raw.servers ?? (Array.isArray(raw) ? raw : null);
  if (Array.isArray(servers)) {
    return servers.map((server, index) =>
      normalizeMcpServerRecord(
        server.label ?? server.name ?? server.id ?? `server_${index + 1}`,
        server,
        {
          workspaceRoot,
          source: server.source ?? "validation_input",
          status: server.status ?? "configured",
        },
      ),
    );
  }
  return Object.entries(servers ?? {}).map(([label, config]) =>
    normalizeMcpServerRecord(label, config, {
      workspaceRoot,
      source: "validation_input",
      status: "configured",
    }),
  );
}

export function normalizeMcpServerRecord(label, config = {}, context = {}) {
  const name =
    optionalString(label) ??
    optionalString(config.label) ??
    optionalString(config.name) ??
    "mcp";
  const id = optionalString(config.id) ?? `mcp.${safeId(name)}`;
  const serverUrl = optionalString(config.serverUrl ?? config.server_url ?? config.url);
  const transport =
    optionalString(config.transport) ??
    (serverUrl ? (String(serverUrl).includes("/sse") ? "sse" : "http") : "stdio");
  const declaredTools = uniqueStrings([
    ...normalizeArray(config.allowedTools ?? config.allowed_tools),
    ...Object.keys(config.tools ?? {}),
  ]);
  const env =
    config.env && typeof config.env === "object" && !Array.isArray(config.env)
      ? config.env
      : {};
  const headers =
    config.headers && typeof config.headers === "object" && !Array.isArray(config.headers)
      ? config.headers
      : {};
  const secretRefs = Object.fromEntries(
    Object.entries({ ...env, ...headers }).map(([key, value]) => [
      key,
      typeof value === "string" && value.startsWith("vault://")
        ? { redacted: true, hash: doctorHash(value) }
        : { redacted: true, invalidVaultRef: Boolean(value) },
    ]),
  );
  return {
    schema_version: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
    schemaVersion: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
    id,
    label: name,
    name,
    enabled: config.enabled !== false && config.disabled !== true,
    status: optionalString(config.status) ?? context.status ?? "configured",
    transport,
    command: optionalString(config.command) ?? null,
    args: Array.isArray(config.args) ? config.args.map(String) : [],
    server_url: serverUrl ?? null,
    serverUrl: serverUrl ?? null,
    source: optionalString(config.source) ?? context.source ?? "mcp.json",
    source_path:
      optionalString(config.sourcePath ?? config.source_path) ?? context.sourcePath ?? null,
    sourcePath:
      optionalString(config.sourcePath ?? config.source_path) ?? context.sourcePath ?? null,
    workspace_root: context.workspaceRoot ?? null,
    workspaceRoot: context.workspaceRoot ?? null,
    allowed_tools: declaredTools,
    allowedTools: declaredTools,
    tool_count: declaredTools.length,
    toolCount: declaredTools.length,
    containment: {
      mode:
        optionalString(config.containmentMode ?? config.containment_mode ?? config.containment?.mode) ??
        "sandboxed",
      allow_network_egress: Boolean(
        config.allowNetworkEgress ??
          config.allow_network_egress ??
          config.containment?.allowNetworkEgress ??
          serverUrl,
      ),
      allow_child_processes: Boolean(
        config.allowChildProcesses ??
          config.allow_child_processes ??
          config.containment?.allowChildProcesses ??
          config.command,
      ),
      workspace_root: context.workspaceRoot ?? null,
    },
    secret_refs: secretRefs,
    secretRefs,
    health: {
      status: config.status === "connected" ? "connected" : "not_connected",
      live_probe: false,
      reason: "read_only_catalog_status",
    },
    evidence_refs: uniqueStrings([
      "mcp.manager.catalog",
      context.source,
      context.sourcePath,
      id,
    ]),
    evidenceRefs: uniqueStrings([
      "mcp.manager.catalog",
      context.source,
      context.sourcePath,
      id,
    ]),
  };
}

export function mcpToolsForServers(servers = []) {
  return servers.flatMap((server) =>
    normalizeArray(server.allowedTools ?? server.allowed_tools).map((toolName) => ({
      schema_version: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
      schemaVersion: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
      stableToolId: `mcp.${safeId(server.label ?? server.id)}.${safeId(toolName)}`,
      stable_tool_id: `mcp.${safeId(server.label ?? server.id)}.${safeId(toolName)}`,
      displayName: `${server.label ?? server.id}.${toolName}`,
      display_name: `${server.label ?? server.id}.${toolName}`,
      pack: "mcp",
      server_id: server.id,
      serverId: server.id,
      server_label: server.label ?? server.name ?? server.id,
      serverLabel: server.label ?? server.name ?? server.id,
      tool_name: toolName,
      toolName,
      status: server.enabled === false ? "disabled" : server.status ?? "configured",
      transport: server.transport ?? "stdio",
      primitiveCapabilities: ["prim:connector.invoke"],
      authorityScopeRequirements: ["scope:mcp.invoke"],
      effectClass: "connector_call",
      riskDomain: "connector",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      evidenceRequirements: ["mcp_containment_receipt"],
      workflowNodeType: "McpToolNode",
      workflowConfigFields: ["server_id", "tool_name", "allowed_tools", "containment"],
      workflow_node_id: `runtime.mcp-tool.${safeId(server.label ?? server.id)}.${safeId(toolName)}`,
      workflowNodeId: `runtime.mcp-tool.${safeId(server.label ?? server.id)}.${safeId(toolName)}`,
      receipt_refs: [],
      receiptRefs: [],
    })),
  );
}

export function validateMcpServerRecords(servers = []) {
  const issues = [];
  const warnings = [];
  for (const server of servers) {
    if (!server.command && !server.server_url && !server.serverUrl) {
      issues.push({
        code: "mcp_server_transport_missing",
        severity: "error",
        server_id: server.id,
        serverId: server.id,
        message: "MCP server must declare a command or remote URL.",
      });
    }
    const secretRefs = server.secretRefs ?? server.secret_refs ?? {};
    for (const [key, value] of Object.entries(secretRefs)) {
      if (value?.invalidVaultRef) {
        issues.push({
          code: "mcp_secret_not_vault_ref",
          severity: "error",
          server_id: server.id,
          serverId: server.id,
          key,
          message: "MCP env/header secrets must be represented as vault:// refs before activation.",
        });
      }
    }
    if (normalizeArray(server.allowedTools ?? server.allowed_tools).length === 0) {
      warnings.push({
        code: "mcp_allowed_tools_empty",
        severity: "warning",
        server_id: server.id,
        serverId: server.id,
        message: "No allowed_tools list is declared; invocation remains unavailable until tools are narrowed.",
      });
    }
  }
  return {
    schema_version: RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
    schemaVersion: RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
    ok: issues.length === 0,
    issues,
    warnings,
  };
}

function loadMcpConfigSources(workspaceRoot) {
  const sources = [];
  for (const [source, filePath] of [
    [".cursor/mcp.json", path.join(workspaceRoot, ".cursor", "mcp.json")],
    [".agents/mcp.json", path.join(workspaceRoot, ".agents", "mcp.json")],
  ]) {
    if (!fs.existsSync(filePath)) continue;
    try {
      const value = readJson(filePath);
      sources.push({
        source,
        path: filePath,
        servers: value.mcpServers ?? value.servers ?? {},
      });
    } catch {
      sources.push({ source, path: filePath, servers: {} });
    }
  }
  return sources;
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function optionalString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function normalizeArray(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.filter(Boolean);
  return [value].filter(Boolean);
}

function uniqueStrings(values) {
  return [...new Set(values.filter((value) => typeof value === "string" && value.trim()))];
}

function doctorHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function safeId(value) {
  return String(value ?? "item")
    .trim()
    .replace(/[^a-zA-Z0-9_.-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 80) || "item";
}
