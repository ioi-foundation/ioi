import { codingToolContracts } from "./coding-tools.mjs";
import {
  RUNTIME_MCP_SERVE_PROTOCOL_VERSION,
  RUNTIME_MCP_SERVE_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";
import {
  mcpJsonRpcError,
  mcpJsonRpcErrorCodeFor,
  mcpJsonRpcResult,
  mcpServeAllowedToolIds,
  mcpServeToolCallResult,
  mcpServeToolDescriptor,
  mcpServeToolIdForName,
} from "./runtime-mcp-helpers.mjs";
import { doctorHash, objectRecord, optionalString, safeId } from "./runtime-value-helpers.mjs";

export function createRuntimeMcpServeSurface({
  RUNTIME_MCP_SERVE_PROTOCOL_VERSION: protocolVersion = RUNTIME_MCP_SERVE_PROTOCOL_VERSION,
  RUNTIME_MCP_SERVE_SCHEMA_VERSION: schemaVersion = RUNTIME_MCP_SERVE_SCHEMA_VERSION,
  codingToolContracts: codingToolContractsDep = codingToolContracts,
  mcpJsonRpcError: mcpJsonRpcErrorDep = mcpJsonRpcError,
  mcpJsonRpcErrorCodeFor: mcpJsonRpcErrorCodeForDep = mcpJsonRpcErrorCodeFor,
  mcpJsonRpcResult: mcpJsonRpcResultDep = mcpJsonRpcResult,
  mcpServeAllowedToolIds: mcpServeAllowedToolIdsDep = mcpServeAllowedToolIds,
  mcpServeToolCallResult: mcpServeToolCallResultDep = mcpServeToolCallResult,
  mcpServeToolDescriptor: mcpServeToolDescriptorDep = mcpServeToolDescriptor,
  mcpServeToolIdForName: mcpServeToolIdForNameDep = mcpServeToolIdForName,
  optionalString: optionalStringDep = optionalString,
} = {}) {
  function mcpServeRustCoreRequiredError(id, { threadId, toolId, toolName }) {
    return mcpJsonRpcErrorDep(id ?? null, -32000, "MCP serve tool calls require direct Rust daemon-core admission.", {
      code: "runtime_mcp_serve_tool_call_rust_core_required",
      details: {
        rust_core_boundary: "runtime.mcp_serve",
        operation: "runtime_mcp_serve_tool_call",
        operation_kind: "mcp.serve.tools.call",
        thread_id: threadId,
        tool_id: toolId ?? null,
        tool_name: toolName ?? null,
        evidence_refs: [
          "runtime_mcp_serve_tool_call_js_facade_retired",
          "rust_daemon_core_runtime_mcp_serve_tool_call_required",
          "agentgres_runtime_mcp_serve_tool_call_truth_required",
          "wallet_runtime_mcp_serve_authority_required",
        ],
      },
    });
  }

  return {
    mcpServeStatus(store, options = {}) {
      const allowedToolIds = mcpServeAllowedToolIdsDep(options);
      const tools = this.mcpServeToolCatalog(store, options);
      return {
        schema_version: schemaVersion,
        object: "ioi.runtime_mcp_serve_status",
        status: "ready",
        transport: "http_jsonrpc",
        protocol_version: protocolVersion,
        thread_id: optionalStringDep(options.thread_id) ?? null,
        allowed_tool_ids: allowedToolIds,
        tool_count: tools.length,
        tools,
        routes: {
          serve: "/v1/mcp/serve",
          serve_for_thread: "/v1/threads/{thread_id}/mcp/serve",
        },
        evidence_refs: ["mcp.serve.http_jsonrpc", "coding_tool_receipt"],
      };
    },
    mcpServeToolCatalog(store, options = {}) {
      const allowedToolIds = new Set(mcpServeAllowedToolIdsDep(options));
      return codingToolContractsDep()
        .filter((tool) => allowedToolIds.has(tool.stable_tool_id))
        .map((tool) => mcpServeToolDescriptorDep(tool));
    },
    async handleMcpServeJsonRpc(store, threadId, message, request = {}) {
      const context = {
        ...request,
        thread_id: threadId,
      };
      if (Array.isArray(message)) {
        const responses = await Promise.all(
          message.map((entry) => this.handleSingleMcpServeJsonRpc(store, threadId, entry, context)),
        );
        return responses.filter(Boolean);
      }
      return this.handleSingleMcpServeJsonRpc(store, threadId, message, context);
    },
    async handleSingleMcpServeJsonRpc(store, threadId, message, request = {}) {
      const id = message?.id;
      const method = optionalStringDep(message?.method);
      if (!message || typeof message !== "object" || Array.isArray(message) || !method) {
        return mcpJsonRpcErrorDep(id ?? null, -32600, "Invalid MCP JSON-RPC request.", {
          schema_version: schemaVersion,
        });
      }
      try {
        if (method === "initialize") {
          const status = this.mcpServeStatus(store, request);
          return mcpJsonRpcResultDep(id, {
            protocolVersion,
            capabilities: {
              tools: { listChanged: false },
              resources: { subscribe: false, listChanged: false },
              prompts: { listChanged: false },
            },
            serverInfo: {
              name: "ioi-runtime",
              version: schemaVersion,
            },
            instructions:
              "IOI runtime MCP serve mode exposes governed, receipt-backed runtime tools for the selected thread.",
            _meta: status,
          });
        }
        if (method === "notifications/initialized") {
          return id === undefined || id === null ? null : mcpJsonRpcResultDep(id, {});
        }
        if (method === "ping") {
          return mcpJsonRpcResultDep(id, {});
        }
        if (method === "tools/list") {
          return mcpJsonRpcResultDep(id, { tools: this.mcpServeToolCatalog(store, request) });
        }
        if (method === "resources/list") {
          return mcpJsonRpcResultDep(id, { resources: [] });
        }
        if (method === "prompts/list") {
          return mcpJsonRpcResultDep(id, { prompts: [] });
        }
        if (method === "tools/call") {
          const params = message.params && typeof message.params === "object" ? message.params : {};
          const toolName = optionalStringDep(params.name);
          const toolId = mcpServeToolIdForNameDep(toolName, request);
          if (!toolId) {
            return mcpJsonRpcErrorDep(id, -32602, `MCP serve tool is not allowed: ${toolName ?? "missing"}.`, {
              allowed_tools: mcpServeAllowedToolIdsDep(request),
            });
          }
          const invokeRustCodingTool = store?.codingToolInvocationSurface?.invokeThreadTool;
          if (typeof invokeRustCodingTool !== "function") {
            return mcpServeRustCoreRequiredError(id, {
              threadId,
              toolId,
              toolName,
            });
          }
          const invocation = await invokeRustCodingTool.call(
            store.codingToolInvocationSurface,
            store,
            threadId,
            toolId,
            mcpServeToolInvocationRequest({
              id,
              params,
              request,
              schemaVersion,
              threadId,
              toolId,
              toolName,
            }),
          );
          return mcpJsonRpcResultDep(id, mcpServeToolCallResultDep(invocation));
        }
        return mcpJsonRpcErrorDep(id, -32601, `MCP method not found: ${method}.`, {
          supported_methods: [
            "initialize",
            "notifications/initialized",
            "ping",
            "tools/list",
            "tools/call",
            "resources/list",
            "prompts/list",
          ],
        });
      } catch (error) {
        return mcpJsonRpcErrorDep(id, mcpJsonRpcErrorCodeForDep(error), String(error?.message ?? error), {
          code: optionalStringDep(error?.code) ?? "mcp_serve_error",
          details: error?.details ?? null,
        });
      }
    },
  };
}

function mcpServeToolInvocationRequest({
  id,
  params = {},
  request = {},
  schemaVersion,
  threadId,
  toolId,
  toolName,
}) {
  const input = objectRecord(params.arguments) ?? {};
  const requestHash = doctorHash(JSON.stringify({
    id: id ?? null,
    input,
    thread_id: threadId,
    tool_id: toolId,
  })).slice(0, 16);
  const toolCallId =
    optionalString(params.tool_call_id) ??
    optionalString(request.tool_call_id) ??
    `mcp_serve_${safeId(toolId)}_${requestHash}`;
  return {
    ...input,
    source: "mcp_serve",
    tool_call_id: toolCallId,
    idempotency_key:
      optionalString(params.idempotency_key) ??
      optionalString(request.idempotency_key) ??
      `thread:${threadId}:mcp-serve:${toolCallId}`,
    workflow_graph_id: optionalString(request.workflow_graph_id) ?? "runtime.mcp_serve",
    workflow_node_id: optionalString(request.workflow_node_id) ?? `runtime.mcp_serve.${safeId(toolId)}`,
    mcp_serve_request: {
      schema_version: schemaVersion,
      jsonrpc_id: id ?? null,
      method: "tools/call",
      thread_id: threadId,
      tool_id: toolId,
      tool_name: toolName ?? null,
    },
  };
}
