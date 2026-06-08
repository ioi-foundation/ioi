const MCP_WORKFLOW_RUST_CORE_EVIDENCE_REFS = [
  "model_mount_mcp_workflow_js_facade_retired",
  "model_mount_mcp_import_js_facade_retired",
  "model_mount_ephemeral_mcp_registration_js_facade_retired",
  "model_mount_mcp_tool_invocation_js_facade_retired",
  "model_mount_workflow_node_execution_js_facade_retired",
  "model_mount_mcp_workflow_receipt_synthesis_js_retired",
  "model_mount_mcp_workflow_record_state_js_retired",
  "rust_daemon_core_model_mount_mcp_workflow_required",
  "agentgres_mcp_workflow_truth_required",
];

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

const RETIRED_MCP_TOOL_INVOCATION_REQUEST_ALIASES = [
  "serverId",
  "server_label",
  "serverLabel",
];

const CANONICAL_MCP_TOOL_INVOCATION_REQUEST_FIELDS = [
  "server_id",
  "tool",
  "input",
];

const RETIRED_MCP_SERVER_CONFIG_ALIASES = [
  "serverUrl",
  "allowedTools",
];

const CANONICAL_MCP_SERVER_CONFIG_FIELDS = [
  "url",
  "server_url",
  "allowed_tools",
  "tools",
];

export function compileEphemeralMcpIntegrations(state, { authorization, body = {}, input }, deps = {}) {
  void state;
  void authorization;
  void input;
  const integrations = Array.isArray(body.integrations) ? body.integrations : [];
  const ephemeral = integrations.filter((integration) => integration?.type === "ephemeral_mcp");
  for (const integration of ephemeral) {
    assertCanonicalEphemeralMcpIntegration(integration);
  }
  if (ephemeral.length > 0) {
    throwMcpWorkflowRustCoreRequired("model_mount.mcp_server.ephemeral_register", {
      integration_count: ephemeral.length,
    }, deps);
  }
  const toolReceiptIds = [];
  const serverIds = [];
  const evidenceRefs = [];
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

export function importMcpJson(state, body = {}, deps = {}) {
  void state;
  assertCanonicalMcpImportRequestBody(body);
  throwMcpWorkflowRustCoreRequired("model_mount.mcp_server.import", {}, deps);
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
  assertCanonicalMcpServerConfig(config);
  const id = `mcp.${safeId(label)}`;
  const allowedTools = normalizeScopes(
    config.allowed_tools,
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
    transport: config.url || config.server_url ? "remote" : "stdio",
    command: config.command ?? null,
    args: Array.isArray(config.args) ? config.args : [],
    serverUrl: config.url ?? config.server_url ?? null,
    allowedTools,
    secretRefs,
    redactedHeaders: Object.fromEntries(Object.keys(config.headers ?? {}).map((key) => [key, secretRedaction])),
    status: "registered",
    source: config.source ?? "mcp.json",
    importedAt: state.nowIso(),
  };
}

function assertCanonicalMcpServerConfig(config = {}) {
  const retiredAliases = RETIRED_MCP_SERVER_CONFIG_ALIASES.filter((field) => Object.prototype.hasOwnProperty.call(config, field));
  if (retiredAliases.length === 0) return;
  const error = new Error("MCP server config uses retired compatibility aliases.");
  error.status = 400;
  error.code = "model_mount_mcp_server_config_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_MCP_SERVER_CONFIG_FIELDS,
  };
  throw error;
}

export function listMcpServers(state, deps = {}) {
  const { publicMcpServer } = deps;
  return [...state.mcpServers.values()]
    .map(publicMcpServer)
    .sort((left, right) => left.id.localeCompare(right.id));
}

export function invokeMcpTool(state, { authorization, body = {} }, deps = {}) {
  void state;
  void authorization;
  assertCanonicalMcpToolInvocationRequestBody(body);
  throwMcpWorkflowRustCoreRequired("model_mount.mcp_tool.invoke", {
    server_id: body.server_id ?? null,
    tool: body.tool ?? null,
  }, deps);
}

function assertCanonicalMcpToolInvocationRequestBody(body = {}) {
  const retiredAliases = RETIRED_MCP_TOOL_INVOCATION_REQUEST_ALIASES.filter((field) => Object.prototype.hasOwnProperty.call(body, field));
  if (retiredAliases.length === 0) return;
  const error = new Error("MCP tool invocation request uses retired compatibility aliases.");
  error.status = 400;
  error.code = "model_mount_mcp_tool_invocation_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_MCP_TOOL_INVOCATION_REQUEST_FIELDS,
  };
  throw error;
}

export async function executeWorkflowNode(state, { authorization, body = {} }, deps = {}) {
  void state;
  void authorization;
  assertCanonicalWorkflowNodeExecutionRequestBody(body);
  throwMcpWorkflowRustCoreRequired("model_mount.workflow_node.execute", {
    node: body.node ?? body.node_type ?? null,
    workflow_graph_id: body.workflow_graph_id ?? null,
    workflow_node_id: body.workflow_node_id ?? null,
  }, deps);
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

function throwMcpWorkflowRustCoreRequired(operation_kind, details = {}, deps = {}) {
  const runtimeError =
    typeof deps.runtimeError === "function"
      ? deps.runtimeError
      : ({ status, code, message, details: errorDetails }) => {
          const error = new Error(message);
          error.status = status;
          error.code = code;
          error.details = errorDetails;
          return error;
        };
  throw runtimeError({
    status: 501,
    code: "model_mount_mcp_workflow_rust_core_required",
    message: "Model-mount MCP workflow mutation and execution require Rust daemon core.",
    details: {
      rust_core_boundary: "model_mount.mcp_workflow",
      operation_kind,
      ...details,
      evidence_refs: MCP_WORKFLOW_RUST_CORE_EVIDENCE_REFS,
    },
  });
}
