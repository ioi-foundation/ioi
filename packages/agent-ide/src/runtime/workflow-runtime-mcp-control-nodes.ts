import type { Node, NodeLogic } from "../types/graph";

export const WORKFLOW_RUNTIME_MCP_TOOL_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-mcp-tool-control.v1" as const;
export const RUNTIME_MCP_TOOL_SOURCE = "react_flow" as const;
export const RUNTIME_MCP_TOOL_SOURCE_EVENT_KIND =
  "OperatorControl.McpInvoke" as const;
export const RUNTIME_MCP_TOOL_COMPONENT_KIND = "mcp_tool_call" as const;
export const RUNTIME_MCP_TOOL_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-invocation.v1" as const;

export type RuntimeMcpToolOperation = "search" | "fetch" | "invoke";

export interface RuntimeMcpToolControlRequestBody {
  source: typeof RUNTIME_MCP_TOOL_SOURCE;
  actor: string;
  event_kind: typeof RUNTIME_MCP_TOOL_SOURCE_EVENT_KIND;
  eventKind: typeof RUNTIME_MCP_TOOL_SOURCE_EVENT_KIND;
  component_kind: typeof RUNTIME_MCP_TOOL_COMPONENT_KIND;
  componentKind: typeof RUNTIME_MCP_TOOL_COMPONENT_KIND;
  payload_schema_version: typeof RUNTIME_MCP_TOOL_PAYLOAD_SCHEMA_VERSION;
  payloadSchemaVersion: typeof RUNTIME_MCP_TOOL_PAYLOAD_SCHEMA_VERSION;
  workflow_graph_id: string | null;
  workflowGraphId: string | null;
  workflow_node_id: string;
  workflowNodeId: string;
  server_id: string;
  serverId: string;
  tool_name: string;
  toolName: string;
  input: Record<string, unknown>;
  arguments: Record<string, unknown>;
  side_effect_class: string;
  sideEffectClass: string;
  mcp_config_source_mode: string;
  mcpConfigSourceMode: string;
  catalog_mode: string;
  catalogMode: string;
  containment_mode: string;
  containmentMode: string;
  allow_network_egress: boolean;
  allowNetworkEgress: boolean;
  headers: Record<string, string>;
  vault_header_refs: Record<string, string>;
  vaultHeaderRefs: Record<string, string>;
}

export interface RuntimeMcpToolControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_MCP_TOOL_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_mcp_tool";
  operation: RuntimeMcpToolOperation;
  nodeId: string | null;
  threadId: string;
  endpoint: string;
  method: "GET" | "POST";
  toolId: string | null;
  serverId: string | null;
  toolName: string | null;
  body: RuntimeMcpToolControlRequestBody | null;
}

export interface RuntimeMcpToolControlRequestInput {
  nodeId?: string | null;
  operation: RuntimeMcpToolOperation;
  input?: unknown;
  threadId?: string | null;
  threadIdField?: string | null;
  serverId?: string | null;
  serverIdField?: string | null;
  toolName?: string | null;
  toolNameField?: string | null;
  toolId?: string | null;
  toolIdField?: string | null;
  query?: string | null;
  queryField?: string | null;
  toolInputJson?: string | null;
  toolInput?: Record<string, unknown> | null;
  toolInputField?: string | null;
  configSourceMode?: string | null;
  catalogMode?: string | null;
  catalogPreviewLimit?: number | null;
  containmentMode?: string | null;
  allowNetworkEgress?: boolean | null;
  vaultHeaderRefsJson?: string | null;
  vaultHeaderRefs?: Record<string, string> | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeMcpToolWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export function createRuntimeMcpToolControlRequest(
  params: RuntimeMcpToolControlRequestInput,
): RuntimeMcpToolControlRequest {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error("runtime_mcp_tool nodes need a threadId input before dispatch.");
  }

  const serverId =
    cleanString(params.serverId) ??
    stringAtPath(params.input, params.serverIdField ?? "serverId") ??
    stringAtPath(params.input, "server_id");
  const toolName =
    cleanString(params.toolName) ??
    stringAtPath(params.input, params.toolNameField ?? "toolName") ??
    stringAtPath(params.input, "tool_name");
  const toolId =
    cleanString(params.toolId) ??
    stringAtPath(params.input, params.toolIdField ?? "toolId") ??
    stringAtPath(params.input, "tool_id") ??
    toolIdFor(serverId, toolName);

  if ((params.operation === "fetch" || params.operation === "invoke") && !toolId) {
    throw new Error(
      "runtime_mcp_tool fetch/invoke nodes need either toolId or serverId plus toolName.",
    );
  }

  if (params.operation === "search") {
    const query =
      cleanString(params.query) ??
      stringAtPath(params.input, params.queryField ?? "query") ??
      stringAtPath(params.input, "q") ??
      "";
    return {
      schemaVersion: WORKFLOW_RUNTIME_MCP_TOOL_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_mcp_tool",
      operation: "search",
      nodeId: params.nodeId ?? null,
      threadId,
      endpoint: withQuery(
        `/v1/threads/${encodeSegment(threadId)}/mcp/tools/search`,
        mcpCatalogQuery({
          source: RUNTIME_MCP_TOOL_SOURCE,
          q: query,
          query,
          server_id: serverId,
          mcp_config_source_mode: cleanString(params.configSourceMode),
          catalog_mode: cleanString(params.catalogMode),
          catalog_preview_limit: params.catalogPreviewLimit,
          limit: params.catalogPreviewLimit,
          live_discovery: true,
        }),
      ),
      method: "GET",
      toolId: null,
      serverId,
      toolName: null,
      body: null,
    };
  }

  if (params.operation === "fetch") {
    return {
      schemaVersion: WORKFLOW_RUNTIME_MCP_TOOL_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_mcp_tool",
      operation: "fetch",
      nodeId: params.nodeId ?? null,
      threadId,
      endpoint: withQuery(
        `/v1/threads/${encodeSegment(threadId)}/mcp/tools/${encodeSegment(toolId ?? "")}`,
        mcpCatalogQuery({
          source: RUNTIME_MCP_TOOL_SOURCE,
          server_id: serverId,
          mcp_config_source_mode: cleanString(params.configSourceMode),
          catalog_mode: cleanString(params.catalogMode),
          catalog_preview_limit: params.catalogPreviewLimit,
          live_discovery: true,
        }),
      ),
      method: "GET",
      toolId,
      serverId,
      toolName,
      body: null,
    };
  }

  const toolInput =
    params.toolInput ??
    objectAtPath(params.input, params.toolInputField ?? "input") ??
    parseJsonObject(params.toolInputJson, {});
  const headers =
    params.vaultHeaderRefs ??
    parseStringRecord(params.vaultHeaderRefsJson, {});
  const workflowNodeId =
    cleanString(params.workflowNodeId) ??
    (serverId && toolName
      ? `runtime.mcp-tool.${safeId(serverId)}.${safeId(toolName)}`
      : "runtime.mcp-tool.invoke");
  const configSourceMode = cleanString(params.configSourceMode) ?? "workspace_and_global";
  const catalogMode = cleanString(params.catalogMode) ?? "summary";
  const containmentMode = cleanString(params.containmentMode) ?? "sandboxed";
  const allowNetworkEgress = params.allowNetworkEgress === true;

  return {
    schemaVersion: WORKFLOW_RUNTIME_MCP_TOOL_CONTROL_SCHEMA_VERSION,
    nodeType: "runtime_mcp_tool",
    operation: "invoke",
    nodeId: params.nodeId ?? null,
    threadId,
    endpoint: `/v1/threads/${encodeSegment(threadId)}/mcp/tools/${encodeSegment(toolId ?? "")}/invoke`,
    method: "POST",
    toolId,
    serverId,
    toolName,
    body: {
      source: RUNTIME_MCP_TOOL_SOURCE,
      actor: cleanString(params.actor) ?? "operator",
      event_kind: RUNTIME_MCP_TOOL_SOURCE_EVENT_KIND,
      eventKind: RUNTIME_MCP_TOOL_SOURCE_EVENT_KIND,
      component_kind: RUNTIME_MCP_TOOL_COMPONENT_KIND,
      componentKind: RUNTIME_MCP_TOOL_COMPONENT_KIND,
      payload_schema_version: RUNTIME_MCP_TOOL_PAYLOAD_SCHEMA_VERSION,
      payloadSchemaVersion: RUNTIME_MCP_TOOL_PAYLOAD_SCHEMA_VERSION,
      workflow_graph_id: cleanString(params.workflowGraphId) ?? null,
      workflowGraphId: cleanString(params.workflowGraphId) ?? null,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      server_id: serverId ?? "",
      serverId: serverId ?? "",
      tool_name: toolName ?? "",
      toolName: toolName ?? "",
      input: toolInput,
      arguments: toolInput,
      side_effect_class: "read",
      sideEffectClass: "read",
      mcp_config_source_mode: configSourceMode,
      mcpConfigSourceMode: configSourceMode,
      catalog_mode: catalogMode,
      catalogMode,
      containment_mode: containmentMode,
      containmentMode,
      allow_network_egress: allowNetworkEgress,
      allowNetworkEgress,
      headers,
      vault_header_refs: headers,
      vaultHeaderRefs: headers,
    },
  };
}

export function createRuntimeMcpToolControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeMcpToolWorkflowNodeOptions = {},
): RuntimeMcpToolControlRequest {
  const logic = mcpWorkflowNodeLogic(node);
  return createRuntimeMcpToolControlRequest({
    nodeId: node.id,
    input,
    operation: operationForStateOperation(logic.stateOperation),
    threadIdField: "threadId",
    serverId: cleanString(logic.mcpServerId),
    toolName: cleanString(logic.mcpToolName),
    query: cleanString(logic.mcpToolSearchQuery),
    toolInputJson: cleanString(logic.mcpToolInputJson),
    configSourceMode: cleanString(logic.mcpConfigSourceMode),
    catalogMode: cleanString(logic.mcpCatalogMode),
    catalogPreviewLimit:
      typeof logic.mcpToolCatalogPreviewLimit === "number"
        ? logic.mcpToolCatalogPreviewLimit
        : null,
    containmentMode: cleanString(logic.mcpContainmentMode),
    allowNetworkEgress: logic.mcpAllowNetworkEgress === true,
    vaultHeaderRefsJson: cleanString(logic.mcpVaultHeaderRefsJson),
    workflowGraphId: cleanString(options.workflowGraphId),
    actor: cleanString(options.actor),
  });
}

function operationForStateOperation(
  stateOperation: NodeLogic["stateOperation"],
): RuntimeMcpToolOperation {
  if (stateOperation === "mcp_tool_search") return "search";
  if (stateOperation === "mcp_tool_fetch") return "fetch";
  if (stateOperation === "mcp_tool_invoke") return "invoke";
  throw new Error(
    `Expected MCP tool state operation, received ${String(stateOperation ?? "unknown")}.`,
  );
}

function mcpWorkflowNodeLogic(node: Pick<Node, "type" | "config">): NodeLogic {
  if (node.type !== "state") {
    throw new Error(`Expected state node, received ${node.type}.`);
  }
  return node.config?.logic ?? {};
}

function mcpCatalogQuery(values: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(values).filter(([, value]) => {
      if (value === undefined || value === null || value === "") return false;
      return true;
    }),
  );
}

function withQuery(route: string, values: Record<string, unknown>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    params.set(key, String(value));
  }
  const query = params.toString();
  return query ? `${route}?${query}` : route;
}

function toolIdFor(serverId: string | null | undefined, toolName: string | null | undefined) {
  if (!serverId || !toolName) return null;
  return `${serverId}.${toolName}`;
}

function parseJsonObject(
  text: string | null | undefined,
  fallback: Record<string, unknown>,
): Record<string, unknown> {
  const clean = cleanString(text);
  if (!clean) return fallback;
  const parsed = JSON.parse(clean);
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    return parsed as Record<string, unknown>;
  }
  throw new Error("MCP tool input JSON must parse to an object.");
}

function parseStringRecord(
  text: string | null | undefined,
  fallback: Record<string, string>,
): Record<string, string> {
  const parsed = parseJsonObject(text, fallback);
  return Object.fromEntries(
    Object.entries(parsed).map(([key, value]) => [key, String(value)]),
  );
}

function objectAtPath(input: unknown, path: string | null | undefined) {
  const value = valueAtPath(input, path);
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringAtPath(input: unknown, path: string | null | undefined): string | null {
  const value = valueAtPath(input, path);
  return cleanString(value);
}

function valueAtPath(input: unknown, path: string | null | undefined): unknown {
  const clean = cleanString(path);
  if (!clean || input === null || typeof input !== "object") return null;
  return clean.split(".").reduce<unknown>((current, segment) => {
    if (current === null || typeof current !== "object") return null;
    return (current as Record<string, unknown>)[segment];
  }, input);
}

function cleanString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const clean = value.trim();
  return clean ? clean : null;
}

function encodeSegment(value: string): string {
  return encodeURIComponent(value);
}

function safeId(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "") || "mcp";
}
