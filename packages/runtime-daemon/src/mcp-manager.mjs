import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-status.v1";
export const RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-invocation.v1";

export function mcpRegistryForWorkspace(cwd, options = {}) {
  const workspaceRoot = path.resolve(options.local?.cwd ?? cwd ?? process.cwd());
  const homeDir = path.resolve(options.homeDir ?? options.home_dir ?? process.env.HOME ?? os.homedir());
  const sourceMode = normalizeMcpConfigSourceMode(
    options.mcp_config_source_mode ?? options.config_source_mode,
  );
  const contextPolicyCore = requiredRuntimeMcpManagerContextPolicyCore(
    options,
    "mcpRegistryForWorkspace",
  );
  const sources = [];
  if (sourceMode !== "workspace") {
    for (const source of loadGlobalMcpConfigSources(homeDir)) {
      sources.push(source);
    }
  }
  for (const [label, config] of Object.entries(options.mcp_servers ?? {})) {
    if (sourceMode !== "global") {
      sources.push({
        source: "inline_options",
        path: null,
        scope: "thread",
        compatibility: "inline",
        servers: { [label]: config },
      });
    }
  }
  if (sourceMode !== "global") {
    for (const source of loadWorkspaceMcpConfigSources(workspaceRoot)) {
      sources.push(source);
    }
  }
  const byId = new Map();
  for (const source of sources) {
    for (const server of mcpServerRecordsFromValidationInput(
      mcpValidationInputForSource(source),
      workspaceRoot,
      { contextPolicyCore },
    )) {
      byId.set(server.id, server);
    }
  }
  const projected = contextPolicyCore.planMcpManagerCatalogProjection({
    servers: [...byId.values()],
  });
  const servers = normalizeArray(projected.servers);
  byId.clear();
  for (const server of servers) byId.set(server.id, server);
  const normalizedServers = [...byId.values()].sort((left, right) =>
    left.id.localeCompare(right.id),
  );
  const tools = normalizeArray(projected.tools);
  const resources = normalizeArray(projected.resources);
  const prompts = normalizeArray(projected.prompts);
  return {
    schema_version: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
    workspace_root: workspaceRoot,
    server_count: normalizedServers.length,
    servers: normalizedServers,
    tools,
    tool_count: tools.length,
    resources,
    resource_count: resources.length,
    prompts,
    prompt_count: prompts.length,
  };
}

function mcpValidationInputForSource(source = {}) {
  return {
    mcp_json: {
      mcp_servers: source.servers ?? {},
    },
    source: source.source ?? null,
    source_path: source.path ?? null,
    source_scope: source.scope ?? null,
    config_compatibility: source.compatibility ?? null,
    status: "configured",
  };
}

export function mcpServerRecordsFromValidationInput(input = {}, workspaceRoot, options = {}) {
  const contextPolicyCore = requiredRuntimeMcpManagerContextPolicyCore(
    options,
    "mcpServerRecordsFromValidationInput",
  );
  const projection = contextPolicyCore.projectMcpServerValidationInput({
    input,
    workspace_root: workspaceRoot,
  });
  return Array.isArray(projection.servers) ? projection.servers : [];
}

function loadGlobalMcpConfigSources(homeDir) {
  return loadMcpConfigSourceFiles([
    {
      source: "global.ioi/mcp.json",
      path: path.join(homeDir, ".ioi", "mcp.json"),
      scope: "global",
      compatibility: "ioi",
    },
  ]);
}

function requiredRuntimeMcpManagerContextPolicyCore(options = {}, operation) {
  if (options.contextPolicyCore && typeof options.contextPolicyCore === "object") {
    return options.contextPolicyCore;
  }
  const error = new Error("Runtime MCP manager requires the daemon-mounted Rust context policy core.");
  error.code = "runtime_mcp_manager_context_policy_core_required";
  error.details = {
    boundary: "runtime.mcp_manager",
    operation,
    required_core: "rust_daemon_core",
    required_mount: "contextPolicyCore",
    evidence_refs: [
      "runtime_mcp_manager_single_context_policy_core_required",
      "runtime_mcp_manager_self_core_fallback_retired",
    ],
  };
  throw error;
}

function loadWorkspaceMcpConfigSources(workspaceRoot) {
  return loadMcpConfigSourceFiles([
    {
      source: ".cursor/mcp.json",
      path: path.join(workspaceRoot, ".cursor", "mcp.json"),
      scope: "workspace",
      compatibility: "cursor",
    },
    {
      source: ".agents/mcp.json",
      path: path.join(workspaceRoot, ".agents", "mcp.json"),
      scope: "workspace",
      compatibility: "agents",
    },
  ]);
}

function loadMcpConfigSourceFiles(candidates = []) {
  const sources = [];
  for (const candidate of candidates) {
    if (!fs.existsSync(candidate.path)) continue;
    try {
      const value = readJson(candidate.path);
      sources.push({
        source: candidate.source,
        path: candidate.path,
        scope: candidate.scope,
        compatibility: candidate.compatibility,
        servers: value.mcpServers ?? value.servers ?? {},
      });
    } catch {
      sources.push({
        source: candidate.source,
        path: candidate.path,
        scope: candidate.scope,
        compatibility: candidate.compatibility,
        servers: {},
      });
    }
  }
  return sources;
}

function normalizeMcpConfigSourceMode(value) {
  const text = optionalString(value)?.toLowerCase().replace(/[-\s]+/g, "_");
  if (["workspace", "workspace_only", "local", "local_only"].includes(text)) {
    return "workspace";
  }
  if (["global", "global_only", "global_ioi", "ioi_global"].includes(text)) {
    return "global";
  }
  return "workspace_and_global";
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
