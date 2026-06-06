import crypto from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-status.v1";
export const RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-validation.v1";
export const RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-invocation.v1";

const MCP_SECRET_REF_BINDINGS = Symbol.for("ioi.runtime.mcp.secretRefBindings");

export function mcpRegistryForWorkspace(cwd, options = {}) {
  const workspaceRoot = path.resolve(options.local?.cwd ?? cwd ?? process.cwd());
  const homeDir = path.resolve(options.homeDir ?? options.home_dir ?? process.env.HOME ?? os.homedir());
  const sourceMode = normalizeMcpConfigSourceMode(
    options.mcp_config_source_mode ?? options.config_source_mode,
  );
  const servers = [];
  if (sourceMode !== "workspace") {
    for (const source of loadGlobalMcpConfigSources(homeDir)) {
      for (const [label, config] of Object.entries(source.servers)) {
        servers.push(
          normalizeMcpServerRecord(label, config, {
            workspaceRoot,
            source: source.source,
            sourcePath: source.path,
            sourceScope: source.scope,
            configCompatibility: source.compatibility,
            status: "configured",
          }),
        );
      }
    }
  }
  for (const [label, config] of Object.entries(options.mcpServers ?? {})) {
    if (sourceMode !== "global") {
      servers.push(
        normalizeMcpServerRecord(label, config, {
          workspaceRoot,
          source: "inline_options",
          sourceScope: "thread",
          configCompatibility: "inline",
          status: "configured",
        }),
      );
    }
  }
  if (sourceMode !== "global") {
    for (const source of loadWorkspaceMcpConfigSources(workspaceRoot)) {
      for (const [label, config] of Object.entries(source.servers)) {
        servers.push(
          normalizeMcpServerRecord(label, config, {
            workspaceRoot,
            source: source.source,
            sourcePath: source.path,
            sourceScope: source.scope,
            configCompatibility: source.compatibility,
            status: "configured",
          }),
        );
      }
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
          sourceScope: server.sourceScope ?? server.source_scope ?? "validation",
          status: server.status ?? "configured",
        },
      ),
    );
  }
  return Object.entries(servers ?? {}).map(([label, config]) =>
    normalizeMcpServerRecord(label, config, {
      workspaceRoot,
      source: "validation_input",
      sourceScope: "validation",
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
  const serverUrl = optionalString(
    config.serverUrl ?? config.server_url ?? config.url ?? config.endpoint,
  );
  const transport = normalizeMcpTransport(
    optionalString(config.transport) ??
      (serverUrl ? (String(serverUrl).includes("/sse") ? "sse" : "http") : "stdio"),
  );
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
  const envSecretRefs = publicMcpSecretRefs(env, "env");
  const headerSecretRefs = publicMcpSecretRefs(headers, "header");
  const secretRefs = { ...envSecretRefs, ...headerSecretRefs };
  const secretRefBindings = mergeMcpSecretRefBindings(
    config[MCP_SECRET_REF_BINDINGS],
    mcpSecretRefBindingsForConfig({ env, headers }),
  );
  const record = {
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
    endpoint: serverUrl ?? null,
    header_names: Object.keys(headers).sort(),
    headerNames: Object.keys(headers).sort(),
    header_secret_refs: headerSecretRefs,
    headerSecretRefs,
    env_secret_refs: envSecretRefs,
    envSecretRefs,
    source: optionalString(config.source) ?? context.source ?? "mcp.json",
    source_path:
      optionalString(config.sourcePath ?? config.source_path) ?? context.sourcePath ?? null,
    sourcePath:
      optionalString(config.sourcePath ?? config.source_path) ?? context.sourcePath ?? null,
    source_scope:
      optionalString(config.sourceScope ?? config.source_scope) ??
      optionalString(context.sourceScope ?? context.source_scope) ??
      "workspace",
    sourceScope:
      optionalString(config.sourceScope ?? config.source_scope) ??
      optionalString(context.sourceScope ?? context.source_scope) ??
      "workspace",
    config_compatibility:
      optionalString(config.configCompatibility ?? config.config_compatibility) ??
      optionalString(context.configCompatibility ?? context.config_compatibility) ??
      null,
    configCompatibility:
      optionalString(config.configCompatibility ?? config.config_compatibility) ??
      optionalString(context.configCompatibility ?? context.config_compatibility) ??
      null,
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
    vault_boundary: {
      required: Object.keys(secretRefs).length > 0,
      header_ref_count: Object.keys(headerSecretRefs).length,
      headerRefCount: Object.keys(headerSecretRefs).length,
      env_ref_count: Object.keys(envSecretRefs).length,
      envRefCount: Object.keys(envSecretRefs).length,
      secret_values_included: false,
      secretValuesIncluded: false,
      runtime_resolution: "execution_time_only",
      runtimeResolution: "execution_time_only",
    },
    vaultBoundary: {
      required: Object.keys(secretRefs).length > 0,
      headerRefCount: Object.keys(headerSecretRefs).length,
      envRefCount: Object.keys(envSecretRefs).length,
      secretValuesIncluded: false,
      runtimeResolution: "execution_time_only",
    },
    health: {
      status: config.status === "connected" ? "connected" : "not_connected",
      live_probe: false,
      reason: "read_only_catalog_status",
    },
    evidence_refs: uniqueStrings([
      "mcp.manager.catalog",
      context.source,
      context.sourcePath,
      context.sourceScope,
      context.configCompatibility,
      id,
    ]),
    evidenceRefs: uniqueStrings([
      "mcp.manager.catalog",
      context.source,
      context.sourcePath,
      context.sourceScope,
      context.configCompatibility,
      id,
    ]),
  };
  return attachMcpSecretRefBindings(record, secretRefBindings);
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
    const transport = normalizeMcpTransport(server.transport);
    const serverUrl = optionalString(server.server_url ?? server.serverUrl ?? server.endpoint);
    if (!["stdio", "http", "sse"].includes(transport)) {
      issues.push({
        code: "mcp_transport_unsupported",
        severity: "error",
        server_id: server.id,
        serverId: server.id,
        transport,
        message: "MCP server transport must be stdio, http, or sse.",
      });
    }
    if (transport === "stdio" && !server.command) {
      issues.push({
        code: "mcp_server_transport_missing",
        severity: "error",
        server_id: server.id,
        serverId: server.id,
        message: "MCP stdio server must declare a command.",
      });
    }
    if ((transport === "http" || transport === "sse") && !serverUrl) {
      issues.push({
        code: "mcp_server_transport_missing",
        severity: "error",
        server_id: server.id,
        serverId: server.id,
        message: "MCP HTTP/SSE server must declare a remote URL.",
      });
    }
    if ((transport === "http" || transport === "sse") && serverUrl && !/^https?:\/\//i.test(serverUrl)) {
      issues.push({
        code: "mcp_remote_url_invalid",
        severity: "error",
        server_id: server.id,
        serverId: server.id,
        message: "MCP HTTP/SSE server URL must use http:// or https://.",
      });
    }
    if (
      (transport === "http" || transport === "sse") &&
      server.containment?.allow_network_egress === false
    ) {
      issues.push({
        code: "mcp_remote_network_blocked",
        severity: "error",
        server_id: server.id,
        serverId: server.id,
        message: "MCP HTTP/SSE server requires network egress in containment policy.",
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

export async function discoverMcpHttpCatalog(server, options = {}) {
  return withMcpRemoteSession(server, options, async (session) => {
    const listed = await session.sendRequest("tools/list", {});
    const resourceList = await optionalMcpCatalogRequest(session, "resources/list");
    const promptList = await optionalMcpCatalogRequest(session, "prompts/list");
    const tools = normalizeArray(listed?.tools).map((tool) => normalizeMcpToolEntry(tool, server));
    const resources = normalizeMcpResourceDeclarations(resourceList?.resources, server);
    const prompts = normalizeMcpPromptDeclarations(promptList?.prompts, server);
    return {
      ok: true,
      status: "completed",
      transport: session.transport,
      execution_mode: session.executionMode,
      executionMode: session.executionMode,
      server_url: session.serverUrl,
      serverUrl: session.serverUrl,
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
      auth_boundary: session.authBoundary ?? session.auth_boundary ?? null,
      authBoundary: session.authBoundary ?? session.auth_boundary ?? null,
    };
  });
}

export async function invokeMcpHttpTool(server, toolName, input = {}, options = {}) {
  return withMcpRemoteSession(server, options, async (session) => {
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
      transport: session.transport,
      execution_mode: session.executionMode,
      executionMode: session.executionMode,
      server_url: session.serverUrl,
      serverUrl: session.serverUrl,
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
      auth_boundary: session.authBoundary ?? session.auth_boundary ?? null,
      authBoundary: session.authBoundary ?? session.auth_boundary ?? null,
      result: call ?? {},
    };
  });
}

async function withMcpRemoteSession(server, options, callback) {
  const transport = normalizeMcpTransport(server?.transport);
  if (transport === "sse") return withMcpSseSession(server, options, callback);
  return withMcpHttpSession(server, options, callback);
}

async function withMcpHttpSession(server, options, callback) {
  const serverUrl = optionalString(server?.serverUrl ?? server?.server_url ?? server?.endpoint);
  if (!serverUrl) {
    throw mcpHttpError("mcp_http_url_missing", "MCP HTTP invocation requires a server URL.");
  }
  const timeoutMs = positiveInteger(
    options.timeout_ms ?? options.timeoutMs ?? process.env.IOI_MCP_REQUEST_TIMEOUT_MS,
    10_000,
  );
  const remoteHeaderResolution = resolveMcpRemoteHeaders(
    mcpRemoteHeaderInputForServer(server, options.headers),
    {
      vault: options.vault,
      serverId: server?.id,
      transport: "http",
    },
  );
  const notifications = [];
  let nextRequestId = 1;
  const sendJsonRpc = async (message, expectsResponse) => {
    const response = await fetchMcpHttp(serverUrl, message, {
      ...options,
      timeoutMs,
      headers: remoteHeaderResolution.headers,
    });
    if (!expectsResponse) return null;
    return resolveMcpJsonRpcResponse(response, message.id, notifications, "mcp_http_json_rpc_error");
  };
  const sendRequest = (method, params = {}) =>
    sendJsonRpc({ jsonrpc: "2.0", id: nextRequestId++, method, params }, true);
  const sendNotification = (method, params = {}) =>
    sendJsonRpc({ jsonrpc: "2.0", method, params }, false);
  const initialize = await sendRequest("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: { roots: { listChanged: true } },
    clientInfo: { name: "ioi-runtime-daemon", version: "0.1.0" },
  });
  await sendNotification("notifications/initialized");
  return callback({
    transport: "http",
    executionMode: "live_http",
    serverUrl,
    timeoutMs,
    authBoundary: remoteHeaderResolution.authBoundary,
    auth_boundary: remoteHeaderResolution.authBoundary,
    initialize,
    notifications,
    sendRequest,
  });
}

async function withMcpSseSession(server, options, callback) {
  const serverUrl = optionalString(server?.serverUrl ?? server?.server_url ?? server?.endpoint);
  if (!serverUrl) {
    throw mcpHttpError("mcp_sse_url_missing", "MCP SSE invocation requires a server URL.");
  }
  const timeoutMs = positiveInteger(
    options.timeout_ms ?? options.timeoutMs ?? process.env.IOI_MCP_REQUEST_TIMEOUT_MS,
    10_000,
  );
  const abortController = new AbortController();
  const remoteHeaderResolution = resolveMcpRemoteHeaders(
    mcpRemoteHeaderInputForServer(server, options.headers),
    {
      vault: options.vault,
      serverId: server?.id,
      transport: "sse",
    },
  );
  const notifications = [];
  const pending = new Map();
  let endpointUrl = null;
  let nextRequestId = 1;
  const rejectPending = (error) => {
    for (const pendingRequest of pending.values()) {
      clearTimeout(pendingRequest.timer);
      pendingRequest.reject(error);
    }
    pending.clear();
  };
  const response = await withTimeout(
    fetch(serverUrl, {
      method: "GET",
      headers: { Accept: "text/event-stream", ...remoteHeaderResolution.headers },
      signal: abortController.signal,
    }),
    timeoutMs,
    () => {
      abortController.abort();
      return mcpHttpError("mcp_sse_connect_timeout", "MCP SSE connection timed out.", {
        timeout_ms: timeoutMs,
      });
    },
  );
  if (!response.ok) {
    throw mcpHttpError("mcp_sse_connect_failed", "MCP SSE server rejected the event stream.", {
      status: response.status,
      statusText: response.statusText,
    });
  }
  if (!response.body?.getReader) {
    throw mcpHttpError("mcp_sse_stream_unavailable", "MCP SSE response body is not readable.");
  }
  const decoder = new TextDecoder();
  let buffer = "";
  let endpointResolved;
  let endpointRejected;
  const endpointPromise = new Promise((resolve, reject) => {
    endpointResolved = resolve;
    endpointRejected = reject;
  });
  const handleEvent = (event) => {
    if (event.event === "endpoint") {
      endpointUrl = new URL(event.data.trim(), serverUrl).href;
      endpointResolved(endpointUrl);
      return;
    }
    if (!event.data.trim()) return;
    let message;
    try {
      message = JSON.parse(event.data);
    } catch (error) {
      notifications.push({
        parse_error: String(error?.message ?? error),
        raw: event.data.slice(0, 500),
      });
      return;
    }
    const id = message.id == null ? null : String(message.id);
    if (id && pending.has(id)) {
      const pendingRequest = pending.get(id);
      pending.delete(id);
      clearTimeout(pendingRequest.timer);
      if (message.error) {
        pendingRequest.reject(
          mcpHttpError("mcp_sse_json_rpc_error", "MCP SSE server returned a JSON-RPC error.", {
            error: message.error,
          }),
        );
        return;
      }
      pendingRequest.resolve(message.result ?? null);
      return;
    }
    notifications.push(message);
  };
  const readLoop = (async () => {
    const reader = response.body.getReader();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const events = consumeSseEventsFromBuffer(() => buffer, (next) => {
          buffer = next;
        });
        for (const event of events) handleEvent(event);
      }
    } catch (error) {
      if (!abortController.signal.aborted) {
        endpointRejected(error);
        rejectPending(error);
      }
    }
  })();
  try {
    await withTimeout(endpointPromise, timeoutMs, () =>
      mcpHttpError("mcp_sse_endpoint_timeout", "MCP SSE endpoint announcement timed out.", {
        timeout_ms: timeoutMs,
      }),
    );
    const postMessage = async (message) => {
      const immediate = await fetchMcpHttp(endpointUrl, message, {
        ...options,
        timeoutMs,
        headers: remoteHeaderResolution.headers,
      });
      if (immediate !== null) {
        const result = resolveMcpJsonRpcResponse(
          immediate,
          message.id,
          notifications,
          "mcp_sse_json_rpc_error",
        );
        if (message.id != null && pending.has(String(message.id))) {
          const pendingRequest = pending.get(String(message.id));
          pending.delete(String(message.id));
          clearTimeout(pendingRequest.timer);
          pendingRequest.resolve(result);
        }
      }
    };
    const sendRequest = (method, params = {}) =>
      new Promise((resolve, reject) => {
        const id = nextRequestId++;
        const timer = setTimeout(() => {
          pending.delete(String(id));
          reject(
            mcpHttpError("mcp_sse_request_timeout", `MCP SSE request timed out: ${method}.`, {
              method,
              timeout_ms: timeoutMs,
            }),
          );
        }, timeoutMs);
        pending.set(String(id), { resolve, reject, timer, method });
        postMessage({ jsonrpc: "2.0", id, method, params }).catch((error) => {
          clearTimeout(timer);
          pending.delete(String(id));
          reject(error);
        });
      });
    const sendNotification = (method, params = {}) =>
      postMessage({ jsonrpc: "2.0", method, params });
    const initialize = await sendRequest("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: { roots: { listChanged: true } },
      clientInfo: { name: "ioi-runtime-daemon", version: "0.1.0" },
    });
    await sendNotification("notifications/initialized");
    return await callback({
      transport: "sse",
      executionMode: "live_sse",
      serverUrl,
      endpointUrl,
      timeoutMs,
      authBoundary: remoteHeaderResolution.authBoundary,
      auth_boundary: remoteHeaderResolution.authBoundary,
      initialize,
      notifications,
      sendRequest,
    });
  } finally {
    rejectPending(mcpHttpError("mcp_sse_closed", "MCP SSE invocation closed."));
    abortController.abort();
    await Promise.race([
      readLoop,
      new Promise((resolve) => setTimeout(resolve, 100)),
    ]);
  }
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

async function fetchMcpHttp(serverUrl, message, options = {}) {
  const response = await fetchWithTimeout(serverUrl, {
    method: "POST",
    headers: {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
      "Mcp-Protocol-Version": "2024-11-05",
      ...mcpRemoteHeaders(options.headers),
    },
    body: JSON.stringify(message),
  }, options.timeoutMs ?? 10_000);
  if (!response.ok) {
    throw mcpHttpError("mcp_http_request_failed", "MCP HTTP server rejected the request.", {
      status: response.status,
      statusText: response.statusText,
    });
  }
  return readMcpHttpResponse(response);
}

async function fetchWithTimeout(url, init = {}, timeoutMs = 10_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const upstreamSignal = init.signal;
  const abortFromUpstream = () => controller.abort();
  if (upstreamSignal) {
    if (upstreamSignal.aborted) controller.abort();
    else upstreamSignal.addEventListener("abort", abortFromUpstream, { once: true });
  }
  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
    });
  } catch (error) {
    if (controller.signal.aborted) {
      throw mcpHttpError("mcp_http_request_timeout", "MCP HTTP request timed out.", {
        url,
        timeout_ms: timeoutMs,
      });
    }
    throw error;
  } finally {
    clearTimeout(timer);
    if (upstreamSignal) upstreamSignal.removeEventListener("abort", abortFromUpstream);
  }
}

async function readMcpHttpResponse(response) {
  if (response.status === 202 || response.status === 204) return null;
  const text = await response.text();
  if (!text.trim()) return null;
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("text/event-stream") || text.trimStart().startsWith("event:") || text.trimStart().startsWith("data:")) {
    return parseSseText(text).map((event) => {
      try {
        return JSON.parse(event.data);
      } catch (error) {
        return { parse_error: String(error?.message ?? error), raw: event.data.slice(0, 500) };
      }
    });
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw mcpHttpError("mcp_http_invalid_json", "MCP HTTP response was not valid JSON.", {
      error: String(error?.message ?? error),
      raw: text.slice(0, 500),
    });
  }
}

function resolveMcpJsonRpcResponse(response, id, notifications, errorCode) {
  const messages = Array.isArray(response) ? response : [response].filter(Boolean);
  const requestedId = String(id);
  for (const message of messages) {
    if (!message || typeof message !== "object") continue;
    if (message.parse_error) {
      notifications.push(message);
      continue;
    }
    const messageId = message.id == null ? null : String(message.id);
    if (messageId === requestedId) {
      if (message.error) {
        throw mcpHttpError(errorCode, "MCP remote server returned a JSON-RPC error.", {
          error: message.error,
        });
      }
      return message.result ?? null;
    }
    notifications.push(message);
  }
  throw mcpHttpError("mcp_http_response_missing", "MCP remote response did not include the requested JSON-RPC id.", {
    id,
  });
}

function consumeSseEventsFromBuffer(readBuffer, writeBuffer) {
  let buffer = readBuffer();
  const events = [];
  let splitIndex = sseBlockBoundaryIndex(buffer);
  while (splitIndex) {
    const block = buffer.slice(0, splitIndex.index);
    buffer = buffer.slice(splitIndex.index + splitIndex.length);
    const event = parseSseBlock(block);
    if (event) events.push(event);
    splitIndex = sseBlockBoundaryIndex(buffer);
  }
  writeBuffer(buffer);
  return events;
}

function parseSseText(text) {
  const normalized = text.endsWith("\n\n") || text.endsWith("\r\n\r\n") ? text : `${text}\n\n`;
  let buffer = normalized;
  const events = [];
  let splitIndex = sseBlockBoundaryIndex(buffer);
  while (splitIndex) {
    const block = buffer.slice(0, splitIndex.index);
    buffer = buffer.slice(splitIndex.index + splitIndex.length);
    const event = parseSseBlock(block);
    if (event) events.push(event);
    splitIndex = sseBlockBoundaryIndex(buffer);
  }
  return events;
}

function sseBlockBoundaryIndex(buffer) {
  const lf = buffer.indexOf("\n\n");
  const crlf = buffer.indexOf("\r\n\r\n");
  const candidates = [
    lf >= 0 ? { index: lf, length: 2 } : null,
    crlf >= 0 ? { index: crlf, length: 4 } : null,
  ].filter(Boolean);
  if (candidates.length === 0) return null;
  return candidates.sort((left, right) => left.index - right.index)[0];
}

function parseSseBlock(block) {
  const lines = String(block ?? "").split(/\r?\n/);
  let event = "message";
  const data = [];
  for (const line of lines) {
    if (!line || line.startsWith(":")) continue;
    if (line.startsWith("event:")) {
      event = line.slice("event:".length).trim() || "message";
      continue;
    }
    if (line.startsWith("data:")) {
      data.push(line.slice("data:".length).trimStart());
    }
  }
  if (data.length === 0) return null;
  return { event, data: data.join("\n") };
}

function withTimeout(promise, timeoutMs, errorFactory) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(errorFactory()), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function mcpRemoteHeaders(headers = {}) {
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) return {};
  return Object.fromEntries(
    Object.entries(headers)
      .filter(([, value]) => typeof value === "string" && value.trim() && !value.startsWith("vault://"))
      .map(([key, value]) => [key, value]),
  );
}

function mcpRemoteHeaderInputForServer(server, requestHeaders = {}) {
  const bindings = server?.[MCP_SECRET_REF_BINDINGS]?.headers ?? {};
  const headers =
    requestHeaders && typeof requestHeaders === "object" && !Array.isArray(requestHeaders)
      ? requestHeaders
      : {};
  return { ...bindings, ...headers };
}

function resolveMcpRemoteHeaders(headers = {}, options = {}) {
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) {
    return emptyMcpRemoteHeaderResolution(options);
  }
  const resolvedHeaders = {};
  const headerNames = [];
  const vaultRefHashes = [];
  const evidenceRefs = [];
  for (const [rawKey, rawValue] of Object.entries(headers)) {
    const headerName = normalizeMcpRemoteHeaderName(rawKey);
    if (!headerName) {
      throw mcpHttpError("mcp_remote_header_invalid", "MCP remote header names must be valid HTTP header tokens.", {
        header_name_hash: doctorHash(rawKey),
      });
    }
    const value = typeof rawValue === "string" ? rawValue.trim() : "";
    if (!value) continue;
    headerNames.push(headerName);
    if (value.startsWith("vault://")) {
      if (!options.vault || typeof options.vault.resolveVaultRef !== "function") {
        throw mcpHttpError("mcp_remote_header_vault_unavailable", "MCP remote header vault resolution is unavailable.", {
          server_id: options.serverId ?? null,
          header_name: headerName,
          vault_ref_hash: doctorHash(value),
        });
      }
      const resolved = options.vault.resolveVaultRef(
        value,
        `mcp.remote_header:${options.serverId ?? "unknown"}:${headerName}`,
      );
      if (!resolved?.resolvedMaterial || typeof resolved.material !== "string" || !resolved.material) {
        throw mcpHttpError("mcp_remote_header_vault_unbound", "MCP remote header vault material is not bound.", {
          server_id: options.serverId ?? null,
          header_name: headerName,
          vault_ref_hash: resolved?.vaultRefHash ?? doctorHash(value),
          material_source: resolved?.materialSource ?? "unbound",
        });
      }
      resolvedHeaders[headerName] = resolved.material;
      vaultRefHashes.push(resolved.vaultRefHash ?? doctorHash(value));
      evidenceRefs.push(...normalizeArray(resolved.evidenceRefs));
      continue;
    }
    if (mcpSensitiveHeaderName(headerName)) {
      throw mcpHttpError("mcp_remote_header_requires_vault_ref", "MCP auth headers must use vault:// refs.", {
        server_id: options.serverId ?? null,
        header_name: headerName,
      });
    }
    resolvedHeaders[headerName] = value;
  }
  const uniqueHeaderNames = uniqueStrings(headerNames).sort();
  const uniqueVaultRefHashes = uniqueStrings(vaultRefHashes).sort();
  const uniqueEvidenceRefs = uniqueStrings(["VaultPort.resolveVaultRef", ...evidenceRefs]).sort();
  return {
    headers: resolvedHeaders,
    authBoundary: {
      required: uniqueHeaderNames.length > 0,
      status: "resolved",
      transport: options.transport ?? null,
      header_names: uniqueHeaderNames,
      headerNames: uniqueHeaderNames,
      vault_ref_hashes: uniqueVaultRefHashes,
      vaultRefHashes: uniqueVaultRefHashes,
      resolved_header_count: Object.keys(resolvedHeaders).length,
      resolvedHeaderCount: Object.keys(resolvedHeaders).length,
      vault_resolved_header_count: uniqueVaultRefHashes.length,
      vaultResolvedHeaderCount: uniqueVaultRefHashes.length,
      secret_values_included: false,
      secretValuesIncluded: false,
      evidence_refs: uniqueEvidenceRefs,
      evidenceRefs: uniqueEvidenceRefs,
    },
  };
}

function emptyMcpRemoteHeaderResolution(options = {}) {
  return {
    headers: {},
    authBoundary: {
      required: false,
      status: "not_configured",
      transport: options.transport ?? null,
      header_names: [],
      headerNames: [],
      vault_ref_hashes: [],
      vaultRefHashes: [],
      resolved_header_count: 0,
      resolvedHeaderCount: 0,
      vault_resolved_header_count: 0,
      vaultResolvedHeaderCount: 0,
      secret_values_included: false,
      secretValuesIncluded: false,
      evidence_refs: [],
      evidenceRefs: [],
    },
  };
}

function normalizeMcpRemoteHeaderName(value) {
  const headerName = optionalString(value);
  if (!headerName) return null;
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(headerName)) return null;
  return headerName.toLowerCase();
}

function mcpSensitiveHeaderName(headerName) {
  return /authorization|token|secret|api[-_]?key|x-api-key/i.test(headerName);
}

function publicMcpSecretRefs(values = {}, source = "secret") {
  if (!values || typeof values !== "object" || Array.isArray(values)) return {};
  return Object.fromEntries(
    Object.entries(values).map(([key, value]) => [
      key,
      typeof value === "string" && value.startsWith("vault://")
        ? { redacted: true, hash: doctorHash(value), source }
        : { redacted: true, invalidVaultRef: Boolean(value), source },
    ]),
  );
}

function mcpSecretRefBindingsForConfig(config = {}) {
  return {
    env: vaultRefBindings(config.env),
    headers: vaultRefBindings(config.headers),
  };
}

function vaultRefBindings(values = {}) {
  if (!values || typeof values !== "object" || Array.isArray(values)) return {};
  return Object.fromEntries(
    Object.entries(values).filter(([, value]) => typeof value === "string" && value.startsWith("vault://")),
  );
}

function mergeMcpSecretRefBindings(...bindings) {
  const merged = { env: {}, headers: {} };
  for (const binding of bindings) {
    if (!binding || typeof binding !== "object" || Array.isArray(binding)) continue;
    Object.assign(merged.env, vaultRefBindings(binding.env));
    Object.assign(merged.headers, vaultRefBindings(binding.headers));
  }
  return merged;
}

function attachMcpSecretRefBindings(record, bindings = {}) {
  const normalized = mergeMcpSecretRefBindings(bindings);
  if (Object.keys(normalized.env).length === 0 && Object.keys(normalized.headers).length === 0) {
    return record;
  }
  Object.defineProperty(record, MCP_SECRET_REF_BINDINGS, {
    value: normalized,
    enumerable: true,
    configurable: false,
    writable: false,
  });
  return record;
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

function normalizeMcpTransport(value) {
  const transport = optionalString(value)?.toLowerCase() ?? "stdio";
  if (["streamable_http", "streamable-http", "http-json-rpc"].includes(transport)) return "http";
  if (["server-sent-events", "eventsource"].includes(transport)) return "sse";
  return transport;
}

function mcpStdioError(code, message, details = {}) {
  const error = new Error(message);
  error.code = code;
  error.details = details;
  return error;
}

function mcpHttpError(code, message, details = {}) {
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
