import crypto from "node:crypto";

import {
  CODING_TOOL_IDS,
  CODING_TOOL_PACK_ID,
} from "./coding-tools.mjs";
import {
  RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
  mcpPromptsForServers,
  mcpResourcesForServers,
  mcpToolsForServers,
  normalizeMcpServerRecord,
} from "./mcp-manager.mjs";
import {
  RUNTIME_MCP_SERVE_DEFAULT_ALLOWED_TOOL_IDS,
  RUNTIME_MCP_SERVE_SCHEMA_VERSION,
  MCP_LIVE_CATALOG_DEFAULT_PREVIEW_LIMIT,
  MCP_LIVE_CATALOG_MAX_PREVIEW_LIMIT,
} from "./runtime-contract-constants.mjs";
import { runtimeToolRegistryGovernanceMetadata } from "./runtime-tool-catalog.mjs";

export function normalizeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

export function optionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

export function normalizeStringList(value) {
  if (Array.isArray(value)) {
    return value.map((item) => optionalString(item)).filter(Boolean);
  }
  const text = optionalString(value);
  return text ? text.split(",").map((item) => item.trim()).filter(Boolean) : [];
}

export function safeId(value) {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}

export function doctorHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

export function uniqueStrings(values) {
  return [...new Set(normalizeArray(values).map((value) => String(value)).filter(Boolean))];
}

export function resolveMcpServerRecord(servers = [], requestedId) {
  const target = optionalString(requestedId);
  if (!target) return null;
  const normalizedTarget = target.toLowerCase();
  return normalizeArray(servers).find((server) => {
    const candidates = [
      server.id,
      server.label,
      server.name,
      server.server_id,
      server.serverId,
    ]
      .map((value) => optionalString(value)?.toLowerCase())
      .filter(Boolean);
    return candidates.includes(normalizedTarget);
  }) ?? null;
}

export function resolveMcpToolRecord(servers = [], toolId, request = {}) {
  const requestedToolId = optionalString(toolId ?? request.tool_id);
  const requestedServerId = optionalString(
    request.server_id ?? request.server ?? request.server_label,
  );
  let requestedToolName = optionalString(
    request.tool_name ?? request.tool ?? request.name,
  );
  let server = requestedServerId ? resolveMcpServerRecord(servers, requestedServerId) : null;
  if (!server && requestedToolId) {
    const toolsByServer = normalizeArray(servers).flatMap((candidate) =>
      mcpToolsForServers([candidate]).map((tool) => ({ server: candidate, tool })),
    );
    const normalizedToolId = requestedToolId.toLowerCase();
    const match = toolsByServer.find(({ tool }) => {
      const candidates = [
        tool.stableToolId,
        tool.stable_tool_id,
        tool.workflowNodeId,
        tool.workflow_node_id,
        `${tool.serverId}.${tool.toolName}`,
        `${tool.server_id}.${tool.tool_name}`,
      ]
        .map((value) => optionalString(value)?.toLowerCase())
        .filter(Boolean);
      return candidates.includes(normalizedToolId);
    });
    if (match) {
      server = match.server;
      requestedToolName ??= match.tool.toolName ?? match.tool.tool_name;
    }
  }
  if (!server && requestedToolId) {
    const segments = requestedToolId.split(".");
    if (segments.length >= 3 && segments[0] === "mcp") {
      server = resolveMcpServerRecord(servers, segments.slice(0, -1).join("."));
      requestedToolName ??= segments.at(-1);
    }
  }
  return { server, toolName: requestedToolName };
}

export function mcpServeAllowedToolIds(options = {}) {
  const requested = normalizeStringList(
    options.allowed_tools ?? options.tools ?? options.tool_ids,
  );
  const candidates = requested.length ? requested : RUNTIME_MCP_SERVE_DEFAULT_ALLOWED_TOOL_IDS;
  return uniqueStrings(candidates).filter((toolId) =>
    RUNTIME_MCP_SERVE_DEFAULT_ALLOWED_TOOL_IDS.includes(toolId) && CODING_TOOL_IDS.has(toolId),
  );
}

export function mcpServeToolDescriptor(tool = {}) {
  tool = runtimeToolRegistryGovernanceMetadata(tool);
  const toolId = optionalString(tool.stableToolId ?? tool.stable_tool_id) ?? "runtime.tool";
  const approvalRequired =
    typeof tool.approvalRequired === "boolean"
      ? tool.approvalRequired
      : typeof tool.approval_required === "boolean"
        ? tool.approval_required
        : normalizeArray(tool.authorityScopeRequirements ?? tool.authority_scope_requirements).length > 0;
  const credentialReadiness =
    tool.credentialReadiness && typeof tool.credentialReadiness === "object"
      ? tool.credentialReadiness
      : { status: "unknown", checkedAt: null, evidenceRefs: [], reason: null };
  const idempotencyBehavior =
    tool.idempotencyBehavior && typeof tool.idempotencyBehavior === "object"
      ? tool.idempotencyBehavior
      : { required: false, strategy: "read_only", keyScope: null, evidenceRefs: [] };
  return {
    name: toolId,
    title: tool.displayName ?? tool.display_name ?? toolId,
    description:
      tool.description ??
      `${tool.displayName ?? toolId} through IOI's governed runtime with receipts and policy evidence.`,
    inputSchema: tool.inputSchema ?? { type: "object" },
    _meta: {
      schema_version: RUNTIME_MCP_SERVE_SCHEMA_VERSION,
      stableToolId: toolId,
      pack: tool.pack ?? CODING_TOOL_PACK_ID,
      effectClass: tool.effectClass ?? "local_read",
      riskDomain: tool.riskDomain ?? "workspace",
      primitiveCapabilities: normalizeArray(tool.primitiveCapabilities ?? tool.primitive_capabilities),
      authorityScopeRequirements: normalizeArray(tool.authorityScopeRequirements ?? tool.authority_scope_requirements),
      evidenceRequirements: normalizeArray(tool.evidenceRequirements ?? tool.evidence_requirements),
      credentialReady: Boolean(tool.credentialReady),
      credentialReadiness,
      approvalRequired,
      approval_required: approvalRequired,
      rateLimitProfile: tool.rateLimitProfile ?? null,
      idempotencyBehavior,
      receiptBehavior: tool.receiptBehavior ?? null,
      workflowAvailability: tool.workflowAvailability ?? null,
      agentAvailability: tool.agentAvailability ?? null,
      marketplaceExposure: tool.marketplaceExposure ?? null,
      workflowNodeType: tool.workflowNodeType ?? null,
      workflowConfigFields: normalizeArray(tool.workflowConfigFields),
    },
    annotations: {
      readOnlyHint: tool.effectClass !== "local_write" && tool.effectClass !== "local_command",
      destructiveHint: false,
      idempotentHint: idempotencyBehavior.strategy === "read_only" || Boolean(idempotencyBehavior.required),
      openWorldHint: false,
    },
  };
}

export function mcpServeToolIdForName(name, options = {}) {
  const requested = optionalString(name);
  if (!requested) return null;
  const allowedToolIds = mcpServeAllowedToolIds(options);
  return allowedToolIds.find((toolId) => toolId === requested || safeId(toolId) === requested) ?? null;
}

export function mcpServeToolCallResult(invocation = {}) {
  const payload = invocation.event?.payload_summary ?? {};
  const status = invocation.status ?? payload.status ?? "completed";
  const summary =
    optionalString(payload.summary) ??
    `IOI runtime tool ${invocation.tool_name ?? "unknown"} ${status}.`;
  return {
    content: [{ type: "text", text: summary }],
    structuredContent: {
      schema_version: RUNTIME_MCP_SERVE_SCHEMA_VERSION,
      object: "ioi.runtime_mcp_serve_tool_result",
      status,
      tool_name: invocation.tool_name ?? null,
      tool_call_id: invocation.tool_call_id ?? null,
      thread_id: invocation.thread_id ?? null,
      workflow_graph_id: invocation.workflow_graph_id ?? null,
      workflow_node_id: invocation.workflow_node_id ?? null,
      receipt_refs: normalizeArray(invocation.receipt_refs),
      policy_decision_refs: normalizeArray(invocation.policy_decision_refs),
      artifact_refs: normalizeArray(invocation.artifact_refs),
      event_id: invocation.event?.event_id ?? null,
      result: invocation.result ?? null,
      error: invocation.error ?? null,
    },
    isError: status !== "completed",
  };
}

export function mcpJsonRpcResult(id, result = {}) {
  return { jsonrpc: "2.0", id: id ?? null, result };
}

export function mcpJsonRpcError(id, code, message, data = {}) {
  return {
    jsonrpc: "2.0",
    id: id ?? null,
    error: { code, message, data },
  };
}

export function mcpJsonRpcErrorCodeFor(error) {
  const status = Number(error?.status ?? 500);
  if (status === 404) return -32601;
  if (status >= 400 && status < 500) return -32602;
  return -32603;
}

export function mcpLiveExecutionModeForServer(server, request = {}) {
  const executionMode = optionalString(request.execution_mode);
  if (
    request.simulated === true ||
    request.simulate === true ||
    executionMode === "simulated_manager_receipt"
  ) {
    return null;
  }
  if (["live_stdio", "live_http", "live_sse"].includes(executionMode)) {
    return executionMode;
  }
  const transport = optionalString(server.transport)?.toLowerCase() ?? "stdio";
  if (transport === "stdio" && optionalString(server.command)) return "live_stdio";
  if (transport === "http" && optionalString(server.server_url ?? server.serverUrl ?? server.endpoint)) return "live_http";
  if (transport === "sse" && optionalString(server.server_url ?? server.serverUrl ?? server.endpoint)) return "live_sse";
  if (request.live_transport === true) {
    if (optionalString(server.command)) return "live_stdio";
    if (optionalString(server.server_url ?? server.serverUrl ?? server.endpoint)) {
      return transport === "sse" ? "live_sse" : "live_http";
    }
  }
  return null;
}

export function mcpTransportEvidenceRef(transportExecution = {}) {
  const executionMode = transportExecution?.executionMode ?? transportExecution?.execution_mode;
  if (executionMode === "live_stdio") return "mcp.transport.stdio.live";
  if (executionMode === "live_http") return "mcp.transport.http.live";
  if (executionMode === "live_sse") return "mcp.transport.sse.live";
  return "mcp.manager.simulated_receipt";
}

export function mcpTransportSummary(transportExecution = {}) {
  const executionMode = transportExecution?.executionMode ?? transportExecution?.execution_mode;
  if (executionMode === "live_stdio") return "live stdio transport";
  if (executionMode === "live_http") return "live HTTP transport";
  if (executionMode === "live_sse") return "live SSE transport";
  return "containment receipt";
}

export function mcpRegistryWithServers(registry = {}, servers = []) {
  const normalizedServers = normalizeArray(servers).sort((left, right) =>
    String(left.id ?? "").localeCompare(String(right.id ?? "")),
  );
  const tools = mcpToolsForServers(normalizedServers);
  const resources = mcpResourcesForServers(normalizedServers);
  const prompts = mcpPromptsForServers(normalizedServers);
  return {
    ...registry,
    server_count: normalizedServers.length,
    serverCount: normalizedServers.length,
    tool_count: tools.length,
    toolCount: tools.length,
    resource_count: resources.length,
    resourceCount: resources.length,
    prompt_count: prompts.length,
    promptCount: prompts.length,
    servers: normalizedServers,
    tools,
    resources,
    prompts,
  };
}

export function mcpServerRecordsFromMutationInput(request = {}, workspaceRoot, fallbackSource) {
  const raw = request.mcp_json ?? request;
  const source = optionalString(request.config_source ?? raw.source) ?? fallbackSource;
  const servers = raw.mcp_servers ?? raw.servers;
  if (Array.isArray(servers)) {
    return servers.map((server, index) =>
      normalizeMcpServerRecord(
        server.label ?? server.name ?? server.id ?? `server_${index + 1}`,
        server,
        { workspaceRoot, source, sourceScope: "thread", status: server.status ?? "configured" },
      ),
    );
  }
  return Object.entries(servers ?? {}).map(([label, config]) =>
    normalizeMcpServerRecord(label, config, {
      workspaceRoot,
      source,
      sourceScope: "thread",
      status: config?.status ?? "configured",
    }),
  );
}

export function mcpServerRecordFromAddRequest(request = {}, workspaceRoot) {
  const config =
    request.server && typeof request.server === "object" && !Array.isArray(request.server)
      ? request.server
      : request.config && typeof request.config === "object" && !Array.isArray(request.config)
        ? request.config
        : request;
  const label =
    optionalString(request.label ?? request.name ?? request.server_label) ??
    optionalString(config.label ?? config.name ?? config.id) ??
    "mcp";
  const source = optionalString(request.config_source ?? config.source) ?? "runtime_mcp_add";
  return normalizeMcpServerRecord(label, config, {
    workspaceRoot,
    source,
    sourceScope: "thread",
    status: config.status ?? "configured",
  });
}

export function mcpToolKey(tool = {}) {
  return optionalString(tool.stableToolId ?? tool.stable_tool_id) ??
    `${optionalString(tool.serverId ?? tool.server_id) ?? "mcp.unknown"}:${optionalString(tool.toolName ?? tool.tool_name) ?? "tool"}`;
}

export function mcpToolIdentityMatches(tool = {}, value) {
  const requested = optionalString(value)?.toLowerCase();
  if (!requested) return false;
  const serverId = optionalString(tool.serverId ?? tool.server_id);
  const toolName = optionalString(tool.toolName ?? tool.tool_name);
  const candidates = [
    tool.stableToolId,
    tool.stable_tool_id,
    tool.workflowNodeId,
    tool.workflow_node_id,
    tool.displayName,
    tool.display_name,
    toolName,
    serverId && toolName ? `${serverId}.${toolName}` : null,
    serverId && toolName ? `${serverId}:${toolName}` : null,
  ]
    .map((candidate) => optionalString(candidate)?.toLowerCase())
    .filter(Boolean);
  return candidates.includes(requested);
}

export function mcpToolMatchesQuery(tool = {}, query) {
  const needle = optionalString(query)?.toLowerCase();
  if (!needle) return true;
  return [
    tool.stableToolId,
    tool.stable_tool_id,
    tool.workflowNodeId,
    tool.workflow_node_id,
    tool.displayName,
    tool.display_name,
    tool.serverId,
    tool.server_id,
    tool.serverLabel,
    tool.server_label,
    tool.toolName,
    tool.tool_name,
    tool.description,
  ]
    .map((candidate) => optionalString(candidate)?.toLowerCase())
    .filter(Boolean)
    .some((candidate) => candidate.includes(needle));
}

export function mcpCatalogPreviewLimit(request = {}) {
  return boundedPositiveInteger(
    request.catalog_preview_limit ??
      request.mcp_catalog_preview_limit ??
      request.preview_limit,
    MCP_LIVE_CATALOG_DEFAULT_PREVIEW_LIMIT,
    MCP_LIVE_CATALOG_MAX_PREVIEW_LIMIT,
  );
}

export function mcpToolSearchLimit(request = {}) {
  return boundedPositiveInteger(request.limit ?? request.max_results, 25, 100);
}

export function mcpConfigSourceModeForRequest(request = {}) {
  const text = optionalString(
    request.mcp_config_source_mode ??
      request.config_source_mode,
  )?.toLowerCase().replace(/[-\s]+/g, "_");
  if (["workspace", "workspace_only", "local", "local_only"].includes(text)) {
    return "workspace";
  }
  if (["global", "global_only", "global_ioi", "ioi_global"].includes(text)) {
    return "global";
  }
  return "workspace_and_global";
}

export function mcpServerMatchesConfigSourceMode(server = {}, sourceMode = "workspace_and_global") {
  if (sourceMode === "workspace_and_global") return true;
  const sourceScope = optionalString(server.sourceScope ?? server.source_scope) ?? "workspace";
  if (sourceMode === "global") return sourceScope === "global";
  if (sourceMode === "workspace") return sourceScope !== "global";
  return true;
}

export function boundedPositiveInteger(value, fallback, max) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return fallback;
  return Math.min(Math.floor(number), max);
}

export function mcpCatalogFullRequested(request = {}) {
  const mode = optionalString(
    request.catalog_mode ?? request.mcp_catalog_mode,
  )?.toLowerCase();
  return mode === "full" || request.include_full_catalog === true;
}

export function mcpCatalogExposureForStatus(server, catalog = {}, options = {}) {
  const tools = normalizeArray(catalog.tools ?? catalog.listed_tools);
  const resources = normalizeArray(catalog.resources ?? catalog.listed_resources);
  const prompts = normalizeArray(catalog.prompts ?? catalog.listed_prompts);
  const previewLimit = boundedPositiveInteger(options.previewLimit, MCP_LIVE_CATALOG_DEFAULT_PREVIEW_LIMIT, MCP_LIVE_CATALOG_MAX_PREVIEW_LIMIT);
  const fullCatalogIncluded = options.forceFullCatalog === true || tools.length <= previewLimit;
  const summary = mcpCatalogSummaryForServer(server, { tools, resources, prompts }, {
    liveMode: catalog.executionMode ?? catalog.execution_mode ?? server.transport ?? "stdio",
    deferred: !fullCatalogIncluded,
    previewLimit,
    catalog,
  });
  const exposedTools = fullCatalogIncluded ? tools : tools.slice(0, previewLimit);
  const exposedResources = fullCatalogIncluded ? resources : resources.slice(0, previewLimit);
  const exposedPrompts = fullCatalogIncluded ? prompts : prompts.slice(0, previewLimit);
  return {
    tools: exposedTools,
    resources: exposedResources,
    prompts: exposedPrompts,
    summary,
    exposure: {
      mode: fullCatalogIncluded ? "full" : "deferred",
      deferred: !fullCatalogIncluded,
      preview_limit: previewLimit,
      full_catalog_included: fullCatalogIncluded,
      returned_tool_count: exposedTools.length,
      returned_resource_count: exposedResources.length,
      returned_prompt_count: exposedPrompts.length,
      search_route: "/v1/mcp/tools/search",
      fetch_route: "/v1/mcp/tools/{tool_id}",
    },
  };
}

export function mcpCatalogSummaryForServer(server = {}, catalog = {}, options = {}) {
  const tools = normalizeArray(catalog.tools);
  const resources = normalizeArray(catalog.resources);
  const prompts = normalizeArray(catalog.prompts);
  const toolNames = tools.map((tool) => optionalString(tool.toolName ?? tool.tool_name)).filter(Boolean).sort();
  const namespaces = mcpToolNamespaces(toolNames);
  const hashPayload = {
    serverId: server.id ?? null,
    tools: tools.map((tool) => ({
      id: tool.stableToolId ?? tool.stable_tool_id ?? null,
      name: tool.toolName ?? tool.tool_name ?? null,
      description: tool.description ?? null,
      inputSchema: tool.inputSchema ?? tool.input_schema ?? null,
    })),
    resources: resources.map((resource) => ({
      id: resource.stableResourceId ?? resource.stable_resource_id ?? null,
      uri: resource.uri ?? null,
      name: resource.name ?? null,
    })),
    prompts: prompts.map((prompt) => ({
      id: prompt.stablePromptId ?? prompt.stable_prompt_id ?? null,
      name: prompt.name ?? null,
    })),
  };
  const catalogHash = doctorHash(JSON.stringify(hashPayload));
  const previewLimit = boundedPositiveInteger(options.previewLimit, MCP_LIVE_CATALOG_DEFAULT_PREVIEW_LIMIT, MCP_LIVE_CATALOG_MAX_PREVIEW_LIMIT);
  const deferred = Boolean(options.deferred ?? tools.length > previewLimit);
  return {
    schema_version: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
    object: "ioi.runtime_mcp_catalog_summary",
    status: options.status ?? "completed",
    server_id: server.id ?? null,
    server_label: server.label ?? server.name ?? server.id ?? null,
    transport: server.transport ?? null,
    execution_mode: options.liveMode ?? null,
    catalog_hash: catalogHash,
    tool_count: tools.length,
    resource_count: resources.length,
    prompt_count: prompts.length,
    namespace_count: namespaces.length,
    namespaces,
    preview_limit: previewLimit,
    preview_tool_names: toolNames.slice(0, Math.min(previewLimit, 20)),
    deferred,
    full_catalog_included: !deferred,
    error_code: options.errorCode ?? null,
    search_route: "/v1/mcp/tools/search",
    fetch_route: "/v1/mcp/tools/{tool_id}",
  };
}

export function mcpToolNamespaces(toolNames = []) {
  return uniqueStrings(
    normalizeArray(toolNames).map((name) => {
      const text = String(name);
      return text.split(/__|[.:/-]/)[0] || text;
    }),
  ).sort().slice(0, 25);
}

export function mcpResourceKey(resource = {}) {
  return optionalString(resource.stableResourceId ?? resource.stable_resource_id) ??
    `${optionalString(resource.serverId ?? resource.server_id) ?? "mcp.unknown"}:${optionalString(resource.uri) ?? "resource"}`;
}

export function mcpPromptKey(prompt = {}) {
  return optionalString(prompt.stablePromptId ?? prompt.stable_prompt_id) ??
    `${optionalString(prompt.serverId ?? prompt.server_id) ?? "mcp.unknown"}:${optionalString(prompt.name) ?? "prompt"}`;
}
