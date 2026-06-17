import type { Node, NodeLogic } from "../types/graph";

export const WORKFLOW_RUNTIME_MCP_TOOL_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-mcp-tool-control.v1" as const;
export const RUNTIME_MCP_TOOL_SOURCE = "react_flow" as const;
export const RUNTIME_MCP_TOOL_SOURCE_EVENT_KIND =
  "OperatorControl.McpInvoke" as const;
export const RUNTIME_MCP_TOOL_COMPONENT_KIND = "mcp_tool_call" as const;
export const RUNTIME_MCP_TOOL_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-invocation.v1" as const;
export const RUNTIME_MCP_SERVE_CLIENT_SCHEMA_VERSION =
  "ioi.runtime.mcp-serve-client.v1" as const;
export const RUNTIME_MCP_SERVE_DEFAULT_ALLOWED_TOOLS = [
  "workspace.status",
  "git.diff",
  "file.inspect",
] as const;
export const RUNTIME_MCP_SERVE_DEFAULT_AUTHORITY_GRANT_REFS_JSON =
  "[\"wallet.network://grant/mcp-serve/{thread_id}/workspace.status\"]";
export const RUNTIME_MCP_SERVE_DEFAULT_AUTHORITY_RECEIPT_REFS_JSON =
  "[\"receipt://wallet.network/mcp-serve/{thread_id}/workspace.status\"]";
export const RUNTIME_MCP_SERVE_DEFAULT_CUSTODY_REF =
  "ctee://workspace/{thread_id}";
export const RUNTIME_MCP_SERVE_DEFAULT_CONTAINMENT_REF =
  "containment://mcp-serve/{thread_id}/workspace.status";

export type RuntimeMcpToolOperation = "search" | "fetch" | "invoke" | "serve";

export interface RuntimeMcpToolControlRequestBody {
  source: typeof RUNTIME_MCP_TOOL_SOURCE;
  actor: string;
  event_kind: typeof RUNTIME_MCP_TOOL_SOURCE_EVENT_KIND;
  component_kind: typeof RUNTIME_MCP_TOOL_COMPONENT_KIND;
  payload_schema_version: typeof RUNTIME_MCP_TOOL_PAYLOAD_SCHEMA_VERSION;
  workflow_graph_id: string | null;
  workflow_node_id: string;
  server_id: string;
  tool_name: string;
  input: Record<string, unknown>;
  arguments: Record<string, unknown>;
  side_effect_class: string;
  mcp_config_source_mode: string;
  catalog_mode: string;
  containment_mode: string;
  allow_network_egress: boolean;
  headers: Record<string, string>;
  vault_header_refs: Record<string, string>;
}

export interface RuntimeMcpServeProtocolRequestBody {
  schema_version: typeof RUNTIME_MCP_SERVE_CLIENT_SCHEMA_VERSION;
  source: typeof RUNTIME_MCP_TOOL_SOURCE;
  allowed_tools: string[];
  authority_grant_refs: string[];
  authority_receipt_refs: string[];
  custody_ref: string;
  containment_ref: string;
  message: {
    jsonrpc: "2.0";
    id: string;
    method: "tools/list";
  };
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
  body: RuntimeMcpToolControlRequestBody | RuntimeMcpServeProtocolRequestBody | null;
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
  serveAllowedToolsJson?: string | null;
  serveAllowedTools?: string[] | null;
  serveAuthorityGrantRefsJson?: string | null;
  serveAuthorityGrantRefs?: string[] | null;
  serveAuthorityReceiptRefsJson?: string | null;
  serveAuthorityReceiptRefs?: string[] | null;
  serveCustodyRef?: string | null;
  serveContainmentRef?: string | null;
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

  if (params.operation === "serve") {
    const allowedTools = (
      params.serveAllowedTools ??
      parseStringArray(
        params.serveAllowedToolsJson,
        [...RUNTIME_MCP_SERVE_DEFAULT_ALLOWED_TOOLS],
      )
    ).map((ref) => templateThreadRef(ref, threadId));
    const authorityGrantRefs = (
      params.serveAuthorityGrantRefs ??
      parseStringArray(
        params.serveAuthorityGrantRefsJson,
        parseStringArray(RUNTIME_MCP_SERVE_DEFAULT_AUTHORITY_GRANT_REFS_JSON, []),
      )
    ).map((ref) => templateThreadRef(ref, threadId));
    const authorityReceiptRefs = (
      params.serveAuthorityReceiptRefs ??
      parseStringArray(
        params.serveAuthorityReceiptRefsJson,
        parseStringArray(RUNTIME_MCP_SERVE_DEFAULT_AUTHORITY_RECEIPT_REFS_JSON, []),
      )
    ).map((ref) => templateThreadRef(ref, threadId));
    const custodyRef = templateThreadRef(
      cleanString(params.serveCustodyRef) ?? RUNTIME_MCP_SERVE_DEFAULT_CUSTODY_REF,
      threadId,
    );
    const containmentRef = templateThreadRef(
      cleanString(params.serveContainmentRef) ?? RUNTIME_MCP_SERVE_DEFAULT_CONTAINMENT_REF,
      threadId,
    );
    if (
      allowedTools.length === 0 ||
      authorityGrantRefs.length === 0 ||
      authorityReceiptRefs.length === 0 ||
      !custodyRef ||
      !containmentRef
    ) {
      throw new Error(
        "runtime_mcp_tool serve nodes need allowed_tools plus authority, custody, and containment refs before dispatch.",
      );
    }
    return {
      schemaVersion: WORKFLOW_RUNTIME_MCP_TOOL_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_mcp_tool",
      operation: "serve",
      nodeId: params.nodeId ?? null,
      threadId,
      endpoint: `/v1/threads/${encodeSegment(threadId)}/mcp/serve`,
      method: "POST",
      toolId: null,
      serverId: null,
      toolName: null,
      body: {
        schema_version: RUNTIME_MCP_SERVE_CLIENT_SCHEMA_VERSION,
        source: RUNTIME_MCP_TOOL_SOURCE,
        allowed_tools: allowedTools,
        authority_grant_refs: authorityGrantRefs,
        authority_receipt_refs: authorityReceiptRefs,
        custody_ref: custodyRef,
        containment_ref: containmentRef,
        message: {
          jsonrpc: "2.0",
          id: `workflow-mcp-serve-${safeId(params.nodeId ?? threadId)}`,
          method: "tools/list",
        },
      },
    };
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
      component_kind: RUNTIME_MCP_TOOL_COMPONENT_KIND,
      payload_schema_version: RUNTIME_MCP_TOOL_PAYLOAD_SCHEMA_VERSION,
      workflow_graph_id: cleanString(params.workflowGraphId) ?? null,
      workflow_node_id: workflowNodeId,
      server_id: serverId ?? "",
      tool_name: toolName ?? "",
      input: toolInput,
      arguments: toolInput,
      side_effect_class: "read",
      mcp_config_source_mode: configSourceMode,
      catalog_mode: catalogMode,
      containment_mode: containmentMode,
      allow_network_egress: allowNetworkEgress,
      headers,
      vault_header_refs: headers,
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
    serveAllowedToolsJson: cleanString(logic.mcpServeAllowedToolsJson),
    serveAuthorityGrantRefsJson: cleanString(logic.mcpServeAuthorityGrantRefsJson),
    serveAuthorityReceiptRefsJson: cleanString(logic.mcpServeAuthorityReceiptRefsJson),
    serveCustodyRef: cleanString(logic.mcpServeCustodyRef),
    serveContainmentRef: cleanString(logic.mcpServeContainmentRef),
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
  if (stateOperation === "mcp_serve") return "serve";
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

function parseStringArray(text: string | null | undefined, fallback: string[]): string[] {
  const clean = cleanString(text);
  if (!clean) return fallback;
  const parsed = JSON.parse(clean);
  if (!Array.isArray(parsed)) {
    throw new Error("MCP serve JSON fields must parse to string arrays.");
  }
  return parsed.map((value) => String(value)).filter((value) => value.trim());
}

function templateThreadRef(ref: string, threadId: string): string {
  return ref.split("{thread_id}").join(threadId);
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
