import crypto from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export const RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-status.v1";
export const RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-validation.v1";
export const RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-invocation.v1";

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
    resources: mcpResourcesForServers(normalizedServers),
    resourceCount: mcpResourcesForServers(normalizedServers).length,
    resource_count: mcpResourcesForServers(normalizedServers).length,
    prompts: mcpPromptsForServers(normalizedServers),
    promptCount: mcpPromptsForServers(normalizedServers).length,
    prompt_count: mcpPromptsForServers(normalizedServers).length,
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
  const declaredResources = normalizeMcpResourceDeclarations(
    config.resources ?? config.allowedResources ?? config.allowed_resources,
    { id, label: name, name, transport, enabled: config.enabled !== false && config.disabled !== true },
  );
  const declaredPrompts = normalizeMcpPromptDeclarations(
    config.prompts ?? config.allowedPrompts ?? config.allowed_prompts,
    { id, label: name, name, transport, enabled: config.enabled !== false && config.disabled !== true },
  );
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
    resources: declaredResources,
    resource_count: declaredResources.length,
    resourceCount: declaredResources.length,
    prompts: declaredPrompts,
    prompt_count: declaredPrompts.length,
    promptCount: declaredPrompts.length,
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
    normalizeArray(server.allowedTools ?? server.allowed_tools).map((tool) =>
      normalizeMcpToolEntry(tool, server),
    ),
  );
}

export function mcpResourcesForServers(servers = []) {
  return servers.flatMap((server) =>
    normalizeMcpResourceDeclarations(
      server.resources ?? server.allowedResources ?? server.allowed_resources,
      server,
    ),
  );
}

export function mcpPromptsForServers(servers = []) {
  return servers.flatMap((server) =>
    normalizeMcpPromptDeclarations(
      server.prompts ?? server.allowedPrompts ?? server.allowed_prompts,
      server,
    ),
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

export async function discoverMcpStdioCatalog(server, options = {}) {
  return withMcpStdioSession(server, options, async (session) => {
    const listed = await session.sendRequest("tools/list", {});
    const resourceList = await optionalMcpCatalogRequest(session, "resources/list");
    const promptList = await optionalMcpCatalogRequest(session, "prompts/list");
    const tools = normalizeArray(listed?.tools).map((tool) => normalizeMcpToolEntry(tool, server));
    const resources = normalizeMcpResourceDeclarations(resourceList?.resources, server);
    const prompts = normalizeMcpPromptDeclarations(promptList?.prompts, server);
    return {
      ok: true,
      status: "completed",
      transport: "stdio",
      execution_mode: "live_stdio",
      executionMode: "live_stdio",
      command: session.command,
      args: session.args,
      cwd: session.cwd,
      timeout_ms: session.timeoutMs,
      protocol_version:
        session.initialize?.protocolVersion ?? session.initialize?.protocol_version ?? null,
      protocolVersion:
        session.initialize?.protocolVersion ?? session.initialize?.protocol_version ?? null,
      server_info: session.initialize?.serverInfo ?? session.initialize?.server_info ?? null,
      serverInfo: session.initialize?.serverInfo ?? session.initialize?.server_info ?? null,
      tool_count: tools.length,
      toolCount: tools.length,
      listed_tools: tools,
      listedTools: tools,
      tools,
      resource_count: resources.length,
      resourceCount: resources.length,
      listed_resources: resources,
      listedResources: resources,
      resources,
      prompt_count: prompts.length,
      promptCount: prompts.length,
      listed_prompts: prompts,
      listedPrompts: prompts,
      prompts,
      notifications: session.notifications,
      stderr: session.stderr(),
    };
  });
}

export async function invokeMcpStdioTool(server, toolName, input = {}, options = {}) {
  return withMcpStdioSession(server, options, async (session) => {
    const listed = await session.sendRequest("tools/list", {});
    const resourceList = await optionalMcpCatalogRequest(session, "resources/list");
    const promptList = await optionalMcpCatalogRequest(session, "prompts/list");
    const listedTools = normalizeArray(listed?.tools).map((tool) =>
      normalizeMcpToolEntry(tool, server),
    );
    const listedResources = normalizeMcpResourceDeclarations(resourceList?.resources, server);
    const listedPrompts = normalizeMcpPromptDeclarations(promptList?.prompts, server);
    const call = await session.sendRequest("tools/call", {
      name: toolName,
      arguments:
        input && typeof input === "object" && !Array.isArray(input) ? input : { value: input },
    });
    return {
      ok: true,
      status: "completed",
      transport: "stdio",
      execution_mode: "live_stdio",
      executionMode: "live_stdio",
      command: session.command,
      args: session.args,
      cwd: session.cwd,
      timeout_ms: session.timeoutMs,
      protocol_version:
        session.initialize?.protocolVersion ?? session.initialize?.protocol_version ?? null,
      protocolVersion:
        session.initialize?.protocolVersion ?? session.initialize?.protocol_version ?? null,
      server_info: session.initialize?.serverInfo ?? session.initialize?.server_info ?? null,
      serverInfo: session.initialize?.serverInfo ?? session.initialize?.server_info ?? null,
      tool_count: listedTools.length,
      toolCount: listedTools.length,
      listed_tools: listedTools,
      listedTools,
      resource_count: listedResources.length,
      resourceCount: listedResources.length,
      listed_resources: listedResources,
      listedResources,
      prompt_count: listedPrompts.length,
      promptCount: listedPrompts.length,
      listed_prompts: listedPrompts,
      listedPrompts,
      notifications: session.notifications,
      stderr: session.stderr(),
      result: call ?? {},
    };
  });
}

async function withMcpStdioSession(server, options, callback) {
  const command = optionalString(server?.command);
  if (!command) {
    throw mcpStdioError("mcp_stdio_command_missing", "MCP stdio invocation requires a server command.");
  }
  const args = Array.isArray(server.args) ? server.args.map(String) : [];
  const cwd = path.resolve(
    options.cwd ??
      server.containment?.workspace_root ??
      server.containment?.workspaceRoot ??
      server.workspace_root ??
      server.workspaceRoot ??
      process.cwd(),
  );
  const tmpDir = path.join(cwd, ".tmp");
  fs.mkdirSync(tmpDir, { recursive: true });
  const timeoutMs = positiveInteger(
    options.timeout_ms ?? options.timeoutMs ?? process.env.IOI_MCP_REQUEST_TIMEOUT_MS,
    10_000,
  );
  const child = spawn(command, args, {
    cwd,
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      HOME: cwd,
      TMPDIR: tmpDir,
      IOI_MCP_MODE: optionalString(options.mcp_mode ?? options.mcpMode) ?? "development",
      ...(options.env && typeof options.env === "object" && !Array.isArray(options.env)
        ? Object.fromEntries(
            Object.entries(options.env).map(([key, value]) => [key, String(value)]),
          )
        : {}),
    },
    stdio: ["pipe", "pipe", "pipe"],
  });

  const pending = new Map();
  const notifications = [];
  let stdoutBuffer = "";
  let stderrText = "";
  let nextRequestId = 1;

  const rejectPending = (error) => {
    for (const { reject, timer } of pending.values()) {
      clearTimeout(timer);
      reject(error);
    }
    pending.clear();
  };
  const writeMessage = (message) => {
    if (!child.stdin || child.stdin.destroyed || !child.stdin.writable) {
      throw mcpStdioError("mcp_stdio_stdin_closed", "MCP stdio server stdin is closed.");
    }
    child.stdin.write(`${JSON.stringify(message)}\n`);
  };
  const handleMessage = (message) => {
    if (!message || typeof message !== "object") return;
    const id = message.id == null ? null : String(message.id);
    if (id && pending.has(id)) {
      const pendingRequest = pending.get(id);
      pending.delete(id);
      clearTimeout(pendingRequest.timer);
      if (message.error) {
        pendingRequest.reject(
          mcpStdioError("mcp_stdio_json_rpc_error", "MCP stdio server returned a JSON-RPC error.", {
            error: message.error,
          }),
        );
        return;
      }
      pendingRequest.resolve(message.result ?? null);
      return;
    }
    if (id && message.method) {
      writeMessage({ jsonrpc: "2.0", id: message.id, result: {} });
      return;
    }
    notifications.push(message);
  };
  child.stdout?.on("data", (chunk) => {
    stdoutBuffer += String(chunk);
    let newlineIndex = stdoutBuffer.indexOf("\n");
    while (newlineIndex >= 0) {
      const line = stdoutBuffer.slice(0, newlineIndex).trim();
      stdoutBuffer = stdoutBuffer.slice(newlineIndex + 1);
      if (line) {
        try {
          handleMessage(JSON.parse(line));
        } catch (error) {
          notifications.push({
            parse_error: String(error?.message ?? error),
            raw: line.slice(0, 500),
          });
        }
      }
      newlineIndex = stdoutBuffer.indexOf("\n");
    }
  });
  child.stderr?.on("data", (chunk) => {
    stderrText = limitText(`${stderrText}${String(chunk)}`, 4096);
  });

  const closePromise = new Promise((resolve) => {
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  child.once("error", (error) => {
    rejectPending(
      mcpStdioError("mcp_stdio_spawn_failed", "MCP stdio server failed to spawn.", {
        error: String(error?.message ?? error),
      }),
    );
  });
  child.once("exit", (code, signal) => {
    if (pending.size > 0) {
      rejectPending(
        mcpStdioError("mcp_stdio_server_exited", "MCP stdio server exited before responding.", {
          code,
          signal,
        }),
      );
    }
  });

  const sendRequest = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const id = nextRequestId++;
      const timer = setTimeout(() => {
        pending.delete(String(id));
        reject(
          mcpStdioError("mcp_stdio_request_timeout", `MCP stdio request timed out: ${method}.`, {
            method,
            timeout_ms: timeoutMs,
          }),
        );
      }, timeoutMs);
      pending.set(String(id), { resolve, reject, timer, method });
      try {
        writeMessage({ jsonrpc: "2.0", id, method, params });
      } catch (error) {
        clearTimeout(timer);
        pending.delete(String(id));
        reject(error);
      }
    });

  let initialize = null;
  try {
    initialize = await sendRequest("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: { roots: { listChanged: true } },
      clientInfo: { name: "ioi-runtime-daemon", version: "0.1.0" },
    });
    writeMessage({ jsonrpc: "2.0", method: "notifications/initialized" });
    return await callback({
      command,
      args,
      cwd,
      timeoutMs,
      initialize,
      notifications,
      sendRequest,
      writeMessage,
      stderr: () => stderrText.trim() || null,
    });
  } finally {
    rejectPending(mcpStdioError("mcp_stdio_closed", "MCP stdio invocation closed."));
    if (child.stdin && !child.stdin.destroyed) child.stdin.end();
    if (!child.killed) child.kill();
    await Promise.race([
      closePromise,
      new Promise((resolve) => setTimeout(() => resolve({ code: null, signal: "timeout" }), 500)),
    ]);
  }
}

async function optionalMcpCatalogRequest(session, method) {
  try {
    return await session.sendRequest(method, {});
  } catch (error) {
    session.notifications.push({
      method,
      status: "unavailable",
      error_code: optionalString(error?.code) ?? "mcp_catalog_unavailable",
      message: String(error?.message ?? error),
    });
    return null;
  }
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

function normalizeMcpToolEntry(tool, server = {}) {
  const toolName = optionalString(tool?.name ?? tool?.toolName ?? tool?.tool_name ?? tool) ?? "tool";
  const serverLabel = server.label ?? server.name ?? server.id ?? "mcp";
  return {
    schema_version: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
    schemaVersion: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
    stableToolId: `mcp.${safeId(serverLabel)}.${safeId(toolName)}`,
    stable_tool_id: `mcp.${safeId(serverLabel)}.${safeId(toolName)}`,
    displayName: `${serverLabel}.${toolName}`,
    display_name: `${serverLabel}.${toolName}`,
    pack: "mcp",
    server_id: server.id,
    serverId: server.id,
    server_label: serverLabel,
    serverLabel,
    tool_name: toolName,
    toolName,
    description: optionalString(tool?.description) ?? null,
    status: server.enabled === false ? "disabled" : server.status ?? "configured",
    transport: server.transport ?? "stdio",
    primitiveCapabilities: ["prim:connector.invoke"],
    authorityScopeRequirements: ["scope:mcp.invoke"],
    effectClass: "connector_call",
    riskDomain: "connector",
    inputSchema: tool?.inputSchema ?? tool?.input_schema ?? { type: "object" },
    outputSchema: tool?.outputSchema ?? tool?.output_schema ?? { type: "object" },
    evidenceRequirements: ["mcp_containment_receipt"],
    workflowNodeType: "McpToolNode",
    workflowConfigFields: ["server_id", "tool_name", "allowed_tools", "containment"],
    workflow_node_id: `runtime.mcp-tool.${safeId(serverLabel)}.${safeId(toolName)}`,
    workflowNodeId: `runtime.mcp-tool.${safeId(serverLabel)}.${safeId(toolName)}`,
    receipt_refs: [],
    receiptRefs: [],
  };
}

function normalizeMcpResourceDeclarations(value, server = {}) {
  return normalizeCatalogItems(value).map((resource) => normalizeMcpResourceEntry(resource, server));
}

function normalizeMcpPromptDeclarations(value, server = {}) {
  return normalizeCatalogItems(value).map((prompt) => normalizeMcpPromptEntry(prompt, server));
}

function normalizeMcpResourceEntry(resource, server = {}) {
  const serverLabel = server.label ?? server.name ?? server.id ?? "mcp";
  const uri =
    optionalString(resource?.uri ?? resource?.url ?? resource?.resource_uri ?? resource) ??
    `resource://${safeId(serverLabel)}/unknown`;
  const name = optionalString(resource?.name ?? resource?.title) ?? uri;
  const stableId = `mcp.${safeId(serverLabel)}.resource.${safeId(uri)}`;
  return {
    schema_version: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
    schemaVersion: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
    stableResourceId: stableId,
    stable_resource_id: stableId,
    displayName: `${serverLabel}.${name}`,
    display_name: `${serverLabel}.${name}`,
    pack: "mcp",
    server_id: server.id,
    serverId: server.id,
    server_label: serverLabel,
    serverLabel,
    uri,
    name,
    description: optionalString(resource?.description) ?? null,
    mimeType: optionalString(resource?.mimeType ?? resource?.mime_type) ?? null,
    mime_type: optionalString(resource?.mimeType ?? resource?.mime_type) ?? null,
    status: server.enabled === false ? "disabled" : server.status ?? "configured",
    transport: server.transport ?? "stdio",
    primitiveCapabilities: ["prim:connector.resource.read"],
    authorityScopeRequirements: ["scope:mcp.resource.read"],
    effectClass: "read_only_catalog",
    riskDomain: "connector",
    evidenceRequirements: ["mcp_resource_catalog_receipt"],
    workflowNodeType: "McpResourceNode",
    workflowConfigFields: ["server_id", "uri", "containment"],
    workflow_node_id: `runtime.mcp-resource.${safeId(serverLabel)}.${safeId(uri)}`,
    workflowNodeId: `runtime.mcp-resource.${safeId(serverLabel)}.${safeId(uri)}`,
    receipt_refs: [],
    receiptRefs: [],
  };
}

function normalizeMcpPromptEntry(prompt, server = {}) {
  const serverLabel = server.label ?? server.name ?? server.id ?? "mcp";
  const name = optionalString(prompt?.name ?? prompt?.title ?? prompt) ?? "prompt";
  const stableId = `mcp.${safeId(serverLabel)}.prompt.${safeId(name)}`;
  return {
    schema_version: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
    schemaVersion: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
    stablePromptId: stableId,
    stable_prompt_id: stableId,
    displayName: `${serverLabel}.${name}`,
    display_name: `${serverLabel}.${name}`,
    pack: "mcp",
    server_id: server.id,
    serverId: server.id,
    server_label: serverLabel,
    serverLabel,
    name,
    description: optionalString(prompt?.description) ?? null,
    arguments: Array.isArray(prompt?.arguments) ? prompt.arguments : [],
    prompt_arguments: Array.isArray(prompt?.arguments) ? prompt.arguments : [],
    promptArguments: Array.isArray(prompt?.arguments) ? prompt.arguments : [],
    status: server.enabled === false ? "disabled" : server.status ?? "configured",
    transport: server.transport ?? "stdio",
    primitiveCapabilities: ["prim:connector.prompt.read"],
    authorityScopeRequirements: ["scope:mcp.prompt.read"],
    effectClass: "read_only_catalog",
    riskDomain: "connector",
    evidenceRequirements: ["mcp_prompt_catalog_receipt"],
    workflowNodeType: "McpPromptNode",
    workflowConfigFields: ["server_id", "prompt_name", "containment"],
    workflow_node_id: `runtime.mcp-prompt.${safeId(serverLabel)}.${safeId(name)}`,
    workflowNodeId: `runtime.mcp-prompt.${safeId(serverLabel)}.${safeId(name)}`,
    receipt_refs: [],
    receiptRefs: [],
  };
}

function normalizeCatalogItems(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.filter(Boolean);
  if (typeof value === "object") {
    return Object.entries(value).map(([name, entry]) =>
      entry && typeof entry === "object" && !Array.isArray(entry)
        ? { name, ...entry }
        : { name, uri: String(entry ?? name) },
    );
  }
  return [value].filter(Boolean);
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

function positiveInteger(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : fallback;
}

function limitText(value, maxLength) {
  const text = String(value ?? "");
  if (text.length <= maxLength) return text;
  return text.slice(text.length - maxLength);
}

function mcpStdioError(code, message, details = {}) {
  const error = new Error(message);
  error.code = code;
  error.details = details;
  return error;
}

function safeId(value) {
  return String(value ?? "item")
    .trim()
    .replace(/[^a-zA-Z0-9_.-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 80) || "item";
}
