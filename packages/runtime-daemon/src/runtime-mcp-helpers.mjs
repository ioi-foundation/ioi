import {
  CODING_TOOL_IDS,
  CODING_TOOL_PACK_ID,
} from "./coding-tools.mjs";
import {
  mcpToolsForServers,
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
        tool.stable_tool_id,
        tool.workflow_node_id,
        `${tool.server_id}.${tool.tool_name}`,
      ]
        .map((value) => optionalString(value)?.toLowerCase())
        .filter(Boolean);
      return candidates.includes(normalizedToolId);
    });
    if (match) {
      server = match.server;
      requestedToolName ??= match.tool.tool_name;
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
  const toolId = optionalString(tool.stable_tool_id) ?? "runtime.tool";
  const approvalRequired =
    typeof tool.approval_required === "boolean"
      ? tool.approval_required
      : normalizeArray(tool.authority_scope_requirements).length > 0;
  const credentialReadiness =
    tool.credential_readiness && typeof tool.credential_readiness === "object"
      ? tool.credential_readiness
      : { status: "unknown", checked_at: null, evidence_refs: [], reason: null };
  const idempotencyBehavior =
    tool.idempotency_behavior && typeof tool.idempotency_behavior === "object"
      ? tool.idempotency_behavior
      : { required: false, strategy: "read_only", key_scope: null, evidence_refs: [] };
  return {
    name: toolId,
    title: tool.display_name ?? toolId,
    description:
      tool.description ??
      `${tool.display_name ?? toolId} through IOI's governed runtime with receipts and policy evidence.`,
    inputSchema: tool.input_schema ?? { type: "object" },
    _meta: {
      schema_version: RUNTIME_MCP_SERVE_SCHEMA_VERSION,
      stable_tool_id: toolId,
      pack: tool.pack ?? CODING_TOOL_PACK_ID,
      effect_class: tool.effect_class ?? "local_read",
      risk_domain: tool.risk_domain ?? "workspace",
      primitive_capabilities: normalizeArray(tool.primitive_capabilities),
      authority_scope_requirements: normalizeArray(tool.authority_scope_requirements),
      evidence_requirements: normalizeArray(tool.evidence_requirements),
      credential_ready: Boolean(tool.credential_ready),
      credential_readiness: credentialReadiness,
      approval_required: approvalRequired,
      rate_limit_profile: tool.rate_limit_profile ?? null,
      idempotency_behavior: idempotencyBehavior,
      receipt_behavior: tool.receipt_behavior ?? null,
      workflow_availability: tool.workflow_availability ?? null,
      agent_availability: tool.agent_availability ?? null,
      marketplace_exposure: tool.marketplace_exposure ?? null,
      workflow_node_type: tool.workflow_node_type ?? null,
      workflow_config_fields: normalizeArray(tool.workflow_config_fields),
    },
    annotations: {
      readOnlyHint: tool.effect_class !== "local_write" && tool.effect_class !== "local_command",
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
  if (transport === "http" && optionalString(server.server_url)) return "live_http";
  if (transport === "sse" && optionalString(server.server_url)) return "live_sse";
  if (request.live_transport === true) {
    if (optionalString(server.command)) return "live_stdio";
    if (optionalString(server.server_url)) {
      return transport === "sse" ? "live_sse" : "live_http";
    }
  }
  return null;
}

export function mcpTransportEvidenceRef(transportExecution = {}) {
  const executionMode = transportExecution?.execution_mode;
  if (executionMode === "live_stdio") return "mcp.transport.stdio.live";
  if (executionMode === "live_http") return "mcp.transport.http.live";
  if (executionMode === "live_sse") return "mcp.transport.sse.live";
  return "mcp.manager.simulated_receipt";
}

export function mcpTransportSummary(transportExecution = {}) {
  const executionMode = transportExecution?.execution_mode;
  if (executionMode === "live_stdio") return "live stdio transport";
  if (executionMode === "live_http") return "live HTTP transport";
  if (executionMode === "live_sse") return "live SSE transport";
  return "containment receipt";
}

export function mcpToolKey(tool = {}) {
  return optionalString(tool.stable_tool_id) ??
    `${optionalString(tool.server_id) ?? "mcp.unknown"}:${optionalString(tool.tool_name) ?? "tool"}`;
}

export function mcpToolIdentityMatches(tool = {}, value) {
  const requested = optionalString(value)?.toLowerCase();
  if (!requested) return false;
  const serverId = optionalString(tool.server_id);
  const toolName = optionalString(tool.tool_name);
  const candidates = [
    tool.stable_tool_id,
    tool.workflow_node_id,
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
    tool.stable_tool_id,
    tool.workflow_node_id,
    tool.display_name,
    tool.server_id,
    tool.server_label,
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
  const sourceScope = optionalString(server.source_scope) ?? "workspace";
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
