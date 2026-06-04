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
import {
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";

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
  safeId: safeIdDep = safeId,
} = {}) {
  return {
    mcpServeStatus(store, options = {}) {
      const allowedToolIds = mcpServeAllowedToolIdsDep(options);
      const tools = this.mcpServeToolCatalog(store, options);
      return {
        schema_version: schemaVersion,
        schemaVersion,
        object: "ioi.runtime_mcp_serve_status",
        status: "ready",
        transport: "http_jsonrpc",
        protocol_version: protocolVersion,
        protocolVersion,
        thread_id: optionalStringDep(options.thread_id ?? options.threadId) ?? null,
        allowed_tool_ids: allowedToolIds,
        allowedToolIds,
        tool_count: tools.length,
        toolCount: tools.length,
        tools,
        routes: {
          serve: "/v1/mcp/serve",
          serveForThread: "/v1/threads/{thread_id}/mcp/serve",
        },
        evidence_refs: ["mcp.serve.http_jsonrpc", "coding_tool_receipt"],
        evidenceRefs: ["mcp.serve.http_jsonrpc", "coding_tool_receipt"],
      };
    },
    mcpServeToolCatalog(store, options = {}) {
      const allowedToolIds = new Set(mcpServeAllowedToolIdsDep(options));
      return codingToolContractsDep()
        .filter((tool) => allowedToolIds.has(tool.stableToolId))
        .map((tool) => mcpServeToolDescriptorDep(tool));
    },
    async handleMcpServeJsonRpc(store, threadId, message, request = {}) {
      store.agentForThread(threadId);
      const context = {
        ...request,
        thread_id: threadId,
        threadId,
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
          const toolName = optionalStringDep(params.name ?? params.tool_name ?? params.toolName);
          const toolId = mcpServeToolIdForNameDep(toolName, request);
          if (!toolId) {
            return mcpJsonRpcErrorDep(id, -32602, `MCP serve tool is not allowed: ${toolName ?? "missing"}.`, {
              allowedTools: mcpServeAllowedToolIdsDep(request),
            });
          }
          const input = params.arguments && typeof params.arguments === "object" && !Array.isArray(params.arguments)
            ? params.arguments
            : params.args && typeof params.args === "object" && !Array.isArray(params.args)
              ? params.args
              : {};
          const invocation = await store.invokeThreadToolAsync(threadId, toolId, {
            source: "mcp_serve",
            workflow_graph_id:
              optionalStringDep(request.workflow_graph_id ?? request.workflowGraphId) ??
              "runtime.mcp-serve",
            workflow_node_id:
              optionalStringDep(request.workflow_node_id ?? request.workflowNodeId) ??
              `runtime.mcp-serve.${safeIdDep(toolId)}`,
            input,
          });
          return mcpJsonRpcResultDep(id, mcpServeToolCallResultDep(invocation));
        }
        return mcpJsonRpcErrorDep(id, -32601, `MCP method not found: ${method}.`, {
          supportedMethods: [
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
