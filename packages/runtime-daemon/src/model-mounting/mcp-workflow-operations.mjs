const RETIRED_WORKFLOW_NODE_EXECUTION_REQUEST_ALIASES = [
  "nodeType",
  "modelId",
  "routeId",
  "modelPolicy",
  "maxTokens",
  "workflowGraphId",
  "workflowNodeId",
  "nodeId",
  "node_id",
  "workflowNodeType",
];

const RETIRED_MCP_IMPORT_REQUEST_ALIASES = [
  "mcpJson",
  "mcpServers",
];

const CANONICAL_MCP_IMPORT_REQUEST_FIELDS = [
  "mcp_json",
  "mcp_servers",
  "servers",
];

const RETIRED_EPHEMERAL_MCP_INTEGRATION_ALIASES = [
  "serverLabel",
  "serverUrl",
  "allowedTools",
];

const CANONICAL_EPHEMERAL_MCP_INTEGRATION_FIELDS = [
  "server_label",
  "server_url",
  "allowed_tools",
];

export function compileEphemeralMcpIntegrations(state, { authorization, body = {}, input }, deps = {}) {
  const {
    requiredString,
    safeId,
    stableHash,
  } = deps;
  const integrations = Array.isArray(body.integrations) ? body.integrations : [];
  const ephemeral = integrations.filter((integration) => integration?.type === "ephemeral_mcp");
  const toolReceiptIds = [];
  const serverIds = [];
  const evidenceRefs = [];
  for (const integration of ephemeral) {
    assertCanonicalEphemeralMcpIntegration(integration);
    const label = requiredString(integration.server_label, "server_label");
    const server = state.normalizeMcpServer(label, {
      ...integration,
      url: integration.server_url,
      allowed_tools: integration.allowed_tools,
      source: "ephemeral_mcp",
    });
    const stored = {
      ...server,
      id: `mcp.ephemeral.${safeId(label)}.${stableHash(integration.server_url ?? label).slice(0, 10)}`,
      status: "ephemeral_registered",
    };
    state.mcpServers.set(stored.id, stored);
    serverIds.push(stored.id);
    const serverReceipt = state.receipt("mcp_ephemeral_registration", {
      summary: `Ephemeral MCP server ${label} registered for one model request.`,
      redaction: "redacted",
      evidenceRefs: ["ephemeral_mcp", "RuntimeToolContract", stored.id],
      details: mcpServerReceiptDetails(stored),
    });
    evidenceRefs.push(serverReceipt.id, stored.id);
    const allowedTools = stored.allowedTools.length > 0 ? stored.allowedTools : [];
    for (const tool of allowedTools) {
      const result = state.invokeMcpTool({
        authorization,
        body: {
          server_id: stored.id,
          tool,
          input: {
            source: "ephemeral_mcp",
            requestInputHash: stableHash(input),
          },
        },
      });
      toolReceiptIds.push(result.receipt.id);
      evidenceRefs.push(result.receipt.id);
    }
  }
  if (ephemeral.length > 0) {
    state.writeMap("mcp-servers", state.mcpServers);
  }
  return { toolReceiptIds, serverIds, evidenceRefs };
}

function assertCanonicalEphemeralMcpIntegration(integration = {}) {
  const retiredAliases = RETIRED_EPHEMERAL_MCP_INTEGRATION_ALIASES.filter((field) =>
    Object.prototype.hasOwnProperty.call(integration, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error("Ephemeral MCP integration uses retired compatibility aliases.");
  error.status = 400;
  error.code = "model_mount_ephemeral_mcp_integration_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_EPHEMERAL_MCP_INTEGRATION_FIELDS,
  };
  throw error;
}

export function importMcpJson(state, body = {}) {
  assertCanonicalMcpImportRequestBody(body);
  const raw = body.mcp_json ?? body;
  const servers = raw.mcp_servers ?? raw.servers ?? {};
  const imported = [];
  for (const [label, config] of Object.entries(servers)) {
    const server = state.normalizeMcpServer(label, config);
    state.mcpServers.set(server.id, server);
    imported.push(server);
    state.receipt("mcp_server_import", {
      summary: `MCP server ${label} imported with governed tool narrowing.`,
      redaction: "redacted",
      evidenceRefs: ["mcp.json", "RuntimeToolContract", server.id],
      details: mcpServerReceiptDetails(server),
    });
  }
  state.writeMap("mcp-servers", state.mcpServers);
  return {
    imported,
    count: imported.length,
    empty: imported.length === 0,
  };
}

function assertCanonicalMcpImportRequestBody(body = {}) {
  const retiredAliases = RETIRED_MCP_IMPORT_REQUEST_ALIASES.filter((field) => Object.prototype.hasOwnProperty.call(body, field));
  const nestedRetiredAliases =
    body.mcp_json && typeof body.mcp_json === "object" && Object.prototype.hasOwnProperty.call(body.mcp_json, "mcpServers")
      ? ["mcp_json.mcpServers"]
      : [];
  if (retiredAliases.length === 0 && nestedRetiredAliases.length === 0) return;
  const error = new Error("MCP import request uses retired compatibility aliases.");
  error.status = 400;
  error.code = "model_mount_mcp_import_request_aliases_retired";
  error.details = {
    retired_aliases: [...retiredAliases, ...nestedRetiredAliases],
    canonical_fields: CANONICAL_MCP_IMPORT_REQUEST_FIELDS,
  };
  throw error;
}

export function normalizeMcpServer(state, label, config = {}, deps = {}) {
  const {
    normalizeScopes,
    runtimeError,
    safeId,
    secretRedaction,
  } = deps;
  const id = `mcp.${safeId(label)}`;
  const allowedTools = normalizeScopes(
    config.allowed_tools ?? config.allowedTools,
    config.tools ? Object.keys(config.tools) : [],
  );
  for (const [key, value] of Object.entries(config.headers ?? config.env ?? {})) {
    state.walletAuthority.resolveVaultRef(String(value));
    if (!String(value).startsWith("vault://")) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "MCP secrets must be vault refs.",
        details: { header: key },
      });
    }
  }
  const secretRefs = Object.fromEntries(
    Object.entries(config.headers ?? config.env ?? {}).map(([key]) => [key, `vault://${id}/${safeId(key)}`]),
  );
  return {
    id,
    label,
    transport: config.url || config.server_url || config.serverUrl ? "remote" : "stdio",
    command: config.command ?? null,
    args: Array.isArray(config.args) ? config.args : [],
    serverUrl: config.url ?? config.server_url ?? config.serverUrl ?? null,
    allowedTools,
    secretRefs,
    redactedHeaders: Object.fromEntries(Object.keys(config.headers ?? {}).map((key) => [key, secretRedaction])),
    status: "registered",
    source: config.source ?? "mcp.json",
    importedAt: state.nowIso(),
  };
}

export function listMcpServers(state, deps = {}) {
  const { publicMcpServer } = deps;
  return [...state.mcpServers.values()]
    .map(publicMcpServer)
    .sort((left, right) => left.id.localeCompare(right.id));
}

export function invokeMcpTool(state, { authorization, body = {} }, deps = {}) {
  const {
    notFound,
    requiredString,
    runtimeError,
    safeId,
    stableHash,
  } = deps;
  const serverId = body.server_id ?? body.serverId ?? `mcp.${safeId(body.server_label ?? body.serverLabel ?? "")}`;
  const server = state.mcpServers.get(serverId);
  if (!server) throw notFound(`MCP server not found: ${serverId}`, { server_id: serverId });
  const tool = requiredString(body.tool, "tool");
  state.authorize(authorization, `mcp.call:${server.label}.${tool}`);
  if (server.allowedTools.length > 0 && !server.allowedTools.includes(tool)) {
    throw runtimeError({
      status: 403,
      code: "policy",
      message: "MCP tool is not included in allowed_tools.",
      details: { server_id: serverId, tool },
    });
  }
  const receipt = state.receipt("mcp_tool_invocation", {
    summary: `MCP tool ${server.label}.${tool} executed through governed RuntimeToolContract path.`,
    redaction: "redacted",
    evidenceRefs: ["RuntimeToolContract", server.id, `tool:${tool}`],
    details: {
      server_id: serverId,
      tool,
      input_hash: stableHash(body.input ?? {}),
      output_hash: stableHash({ ok: true, tool }),
    },
  });
  return {
    server: server.label,
    tool,
    result: { ok: true, fixture: true, tool },
    receipt,
  };
}

function mcpServerReceiptDetails(server) {
  return {
    id: server.id,
    label: server.label,
    transport: server.transport,
    command: server.command ?? null,
    args: Array.isArray(server.args) ? [...server.args] : [],
    server_url: server.serverUrl ?? null,
    allowed_tools: Array.isArray(server.allowedTools) ? [...server.allowedTools] : [],
    secret_refs: { ...(server.secretRefs ?? {}) },
    redacted_headers: { ...(server.redactedHeaders ?? {}) },
    status: server.status,
    source: server.source ?? null,
    imported_at: server.importedAt ?? null,
  };
}

export async function executeWorkflowNode(state, { authorization, body = {} }, deps = {}) {
  const {
    capabilityForWorkflowNode,
    nativeInvocationResponseShape,
    requiredString,
    runtimeError,
    workflowKindForNode,
    workflowMemoryOptionsFromBody,
    workflowMemoryWriteBlockReason,
  } = deps;
  assertCanonicalWorkflowNodeExecutionRequestBody(body);
  const node = requiredString(body.node ?? body.node_type, "node");
  const capability = body.capability ?? capabilityForWorkflowNode(node);
  const memoryOptions = workflowMemoryOptionsFromBody(body);
  const base = {
    model: body.model_id ?? body.model,
    route_id: body.route_id,
    model_policy: body.model_policy ?? {},
    input: body.input ?? body.prompt ?? "",
    messages: body.messages,
    max_tokens: body.max_tokens,
    temperature: body.temperature,
    workflow_graph_id: body.workflow_graph_id,
    workflow_node_id: body.workflow_node_id,
    workflow_node_type: body.workflow_node_type ?? node,
  };
  if (memoryOptions) {
    base.memory = memoryOptions;
    base.send_options = { memory: memoryOptions };
  }
  if (node === "Model Router") {
    const routeId = base.route_id ?? "route.local-first";
    state.authorize(authorization, `route.use:${routeId}`);
    return {
      node,
      status: "selected",
      ...(state.testRoute(routeId, { ...base, capability })),
    };
  }
  if (node === "Local Tool/MCP" || node === "Local Tool / MCP") {
    return {
      node,
      status: "executed",
      ...(state.invokeMcpTool({ authorization, body: body.mcp ?? body })),
    };
  }
  if (node === "Receipt Gate") {
    return state.validateReceiptGate(body);
  }
  const kind = workflowKindForNode(node);
  const requiredScope =
    kind === "embeddings"
      ? "model.embeddings:*"
      : kind === "rerank"
        ? "model.rerank:*"
        : kind === "responses"
          ? "model.responses:*"
          : "model.chat:*";
  const memoryWriteBlockReason = workflowMemoryWriteBlockReason(memoryOptions);
  if (memoryWriteBlockReason) {
    throw runtimeError({
      status: 403,
      code: "policy",
      message: "Workflow memory write blocked by policy.",
      details: {
        reason: memoryWriteBlockReason,
        memory: memoryOptions,
        workflow_node_id: base.workflow_node_id ?? null,
      },
    });
  }
  const invocation = await state.invokeModel({
    authorization,
    requiredScope,
    kind,
    body: base,
  });
  return {
    node,
    status: "executed",
    capability,
    invocation: nativeInvocationResponseShape(invocation),
    receipt: invocation.receipt,
    routeReceipt: invocation.routeReceipt,
  };
}

function assertCanonicalWorkflowNodeExecutionRequestBody(body = {}) {
  const retiredAliases = RETIRED_WORKFLOW_NODE_EXECUTION_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Workflow node execution request aliases are retired; use canonical request fields.",
  );
  error.status = 400;
  error.code = "model_mount_workflow_node_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: [
      "node",
      "node_type",
      "model",
      "model_id",
      "route_id",
      "model_policy",
      "max_tokens",
      "workflow_graph_id",
      "workflow_node_id",
      "workflow_node_type",
    ],
  };
  throw error;
}
