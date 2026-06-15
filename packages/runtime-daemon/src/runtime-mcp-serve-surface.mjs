import { codingToolContracts } from "./coding-tools.mjs";
import {
  RUNTIME_MCP_SERVE_PROTOCOL_VERSION,
  RUNTIME_MCP_SERVE_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";
import {
  MCP_LIVE_RESULT_REPLAY_REQUEST_SCHEMA_VERSION,
} from "./runtime-context-policy-core.mjs";
import {
  mcpJsonRpcError,
  mcpJsonRpcErrorCodeFor,
  mcpJsonRpcResult,
  mcpServeAllowedToolIds,
  mcpServeToolDescriptor,
  mcpServeToolIdForName,
} from "./runtime-mcp-helpers.mjs";
import { objectRecord, optionalString } from "./runtime-value-helpers.mjs";

const RUNTIME_MCP_LIVE_RESULT_STATE_COMMIT_SCHEMA_VERSION =
  "ioi.runtime_mcp_live_result_state_commit.v1";
const RUNTIME_STATE_STORAGE_BACKEND_REF = "storage://runtime-agentgres/local-json";

export function createRuntimeMcpServeSurface({
  RUNTIME_MCP_SERVE_PROTOCOL_VERSION: protocolVersion = RUNTIME_MCP_SERVE_PROTOCOL_VERSION,
  RUNTIME_MCP_SERVE_SCHEMA_VERSION: schemaVersion = RUNTIME_MCP_SERVE_SCHEMA_VERSION,
  codingToolContracts: codingToolContractsDep = codingToolContracts,
  mcpJsonRpcError: mcpJsonRpcErrorDep = mcpJsonRpcError,
  mcpJsonRpcErrorCodeFor: mcpJsonRpcErrorCodeForDep = mcpJsonRpcErrorCodeFor,
  mcpJsonRpcResult: mcpJsonRpcResultDep = mcpJsonRpcResult,
  mcpServeAllowedToolIds: mcpServeAllowedToolIdsDep = mcpServeAllowedToolIds,
  mcpServeToolDescriptor: mcpServeToolDescriptorDep = mcpServeToolDescriptor,
  mcpServeToolIdForName: mcpServeToolIdForNameDep = mcpServeToolIdForName,
  contextPolicyCore = null,
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
          "rust_daemon_core_runtime_mcp_serve_tool_result_projection_required",
          "rust_daemon_core_runtime_mcp_live_result_replay_required",
          "agentgres_runtime_mcp_live_result_state_commit_required",
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
          const planner = store?.contextPolicyCore ?? contextPolicyCore;
          const invokeRustCodingTool = store?.codingToolInvocationSurface?.invokeThreadTool;
          if (
            typeof planner?.planRuntimeMcpServeToolCall !== "function" ||
            typeof planner?.projectRuntimeMcpServeToolResult !== "function" ||
            typeof planner?.projectMcpLiveResultReplay !== "function" ||
            typeof invokeRustCodingTool !== "function" ||
            typeof store?.commitRuntimeMcpLiveResultState !== "function" ||
            !optionalStringDep(store?.stateDir)
          ) {
            return mcpServeRustCoreRequiredError(id, {
              threadId,
              toolId,
              toolName,
            });
          }
          const plan = planner.planRuntimeMcpServeToolCall({
            operation_kind: "mcp.serve.tools.call",
            thread_id: threadId,
            tool_id: toolId,
            tool_name: toolName,
            method: "tools/call",
            jsonrpc_id: id ?? null,
            params,
            request,
            mcp_serve_schema_version: schemaVersion,
          });
          const invocationRequest = plannedMcpServeToolInvocationRequest(plan, {
            threadId,
            toolId,
          });
          const invocation = await invokeRustCodingTool.call(
            store.codingToolInvocationSurface,
            store,
            threadId,
            toolId,
            invocationRequest,
          );
          const resultProjection = planner.projectRuntimeMcpServeToolResult({
            operation_kind: "mcp.serve.tools.result",
            thread_id: threadId,
            tool_id: toolId,
            tool_name: toolName,
            jsonrpc_id: id ?? null,
            plan,
            invocation,
            mcp_serve_schema_version: schemaVersion,
          });
          const projectedResult = plannedMcpServeToolResult(resultProjection, {
            threadId,
            toolId,
          });
          const liveResult = plannedMcpServeLiveResult(resultProjection, {
            threadId,
            toolId,
          });
          const replayedResult = commitAndReplayMcpServeLiveResult(store, planner, liveResult, {
            threadId,
            toolId,
            projectedResult,
          });
          return mcpJsonRpcResultDep(id, replayedResult);
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

function commitAndReplayMcpServeLiveResult(store, planner, liveResult, { threadId, toolId }) {
  const resultId = optionalString(liveResult.id);
  const receiptId = optionalString(liveResult.receipt_id);
  const commit = store.commitRuntimeMcpLiveResultState({
    schema_version: RUNTIME_MCP_LIVE_RESULT_STATE_COMMIT_SCHEMA_VERSION,
    result_id: resultId,
    operation_kind: "runtime.mcp_serve.result.write",
    storage_backend_ref: RUNTIME_STATE_STORAGE_BACKEND_REF,
    result: liveResult,
    receipt_refs: Array.isArray(liveResult.receipt_refs) ? liveResult.receipt_refs : [receiptId].filter(Boolean),
  });
  if (!commit?.commit_hash) {
    const error = new Error("Rust Agentgres MCP serve live-result commit returned without commit_hash.");
    error.code = "runtime_mcp_serve_live_result_state_commit_invalid";
    error.details = {
      operation_kind: "runtime.mcp_serve.result.write",
      thread_id: threadId,
      tool_id: toolId,
      result_id: resultId ?? null,
    };
    throw error;
  }
  const details = objectRecord(liveResult.details) ?? {};
  const replay = planner.projectMcpLiveResultReplay({
    schema_version: MCP_LIVE_RESULT_REPLAY_REQUEST_SCHEMA_VERSION,
    state_dir: optionalString(store.stateDir),
    result_id: resultId,
    receipt_id: receiptId,
    thread_id: threadId,
    agent_id: optionalString(details.agent_id) ?? null,
    control_kind: "mcp_serve_tool_call",
  });
  const latestResult = objectRecord(replay?.latest_result);
  if (!latestResult || latestResult.id !== resultId) {
    const error = new Error("Rust MCP serve live-result replay did not return the committed result.");
    error.code = "runtime_mcp_serve_live_result_replay_invalid";
    error.details = {
      operation_kind: "runtime.mcp_serve.result.replay",
      thread_id: threadId,
      tool_id: toolId,
      result_id: resultId ?? null,
      replay_hash: replay?.replay_hash ?? null,
    };
    throw error;
  }
  const replayedLiveResult = plannedMcpServeLiveResult({ live_result: latestResult }, {
    threadId,
    toolId,
  });
  const payload = objectRecord(replayedLiveResult.payload);
  return plannedMcpServeProtocolResult(objectRecord(payload?.protocol_result), {
    threadId,
    toolId,
  });
}

function plannedMcpServeToolResult(projection, { threadId, toolId }) {
  const record = objectRecord(projection);
  const result = objectRecord(record?.result);
  return plannedMcpServeProtocolResult(result, { threadId, toolId, record });
}

function plannedMcpServeProtocolResult(result, { threadId, toolId, record = null }) {
  const structuredContent = objectRecord(result?.structuredContent);
  const recordInvalid = record
    ? (
      record.status !== "projected" ||
      record.operation_kind !== "mcp.serve.tools.result" ||
      record.thread_id !== threadId ||
      record.tool_id !== toolId
    )
    : false;
  if (
    recordInvalid ||
    !result ||
    !structuredContent ||
    structuredContent.object !== "ioi.runtime_mcp_serve_tool_result" ||
    structuredContent.thread_id !== threadId
  ) {
    const error = new Error("Rust daemon-core MCP serve tool-result projection is incomplete.");
    error.code = "runtime_mcp_serve_tool_result_projection_incomplete";
    error.details = {
      operation_kind: record?.operation_kind ?? null,
      thread_id: record?.thread_id ?? null,
      tool_id: record?.tool_id ?? null,
    };
    throw error;
  }
  return result;
}

function plannedMcpServeLiveResult(projection, { threadId, toolId }) {
  const record = objectRecord(projection);
  const liveResult = objectRecord(record?.live_result ?? projection?.latest_result ?? projection);
  const details = objectRecord(liveResult?.details);
  const payload = objectRecord(liveResult?.payload);
  const protocolResult = objectRecord(payload?.protocol_result);
  const evidenceRefs = Array.isArray(liveResult?.evidence_refs) ? liveResult.evidence_refs : [];
  const receiptRefs = Array.isArray(liveResult?.receipt_refs) ? liveResult.receipt_refs : [];
  if (
    !liveResult ||
    liveResult.schema_version !== "ioi.runtime.mcp-live-result.v1" ||
    liveResult.object !== "ioi.runtime_mcp_live_result" ||
    liveResult.kind !== "runtime_mcp_live_result" ||
    !optionalString(liveResult.id) ||
    !optionalString(liveResult.receipt_id) ||
    receiptRefs.length === 0 ||
    !details ||
    details.rust_daemon_core_result_author !== "runtime.mcp_serve" ||
    details.control_kind !== "mcp_serve_tool_call" ||
    details.thread_id !== threadId ||
    details.tool_id !== toolId ||
    details.result_materialized !== true ||
    details.backend_materialization_status !== "rust_step_module_invocation_materialized" ||
    details.js_transport_invocation !== false ||
    details.command_transport_fallback !== false ||
    details.binary_bridge_fallback !== false ||
    details.compatibility_fallback !== false ||
    !evidenceRefs.includes("runtime_mcp_live_result_rust_projection") ||
    !evidenceRefs.includes("agentgres_runtime_mcp_live_result_truth_required") ||
    !evidenceRefs.includes("runtime_mcp_serve_result_payload_materialized") ||
    !protocolResult
  ) {
    const error = new Error("Rust daemon-core MCP serve live-result projection is incomplete.");
    error.code = "runtime_mcp_serve_live_result_projection_incomplete";
    error.details = {
      operation_kind: record?.operation_kind ?? null,
      thread_id: details?.thread_id ?? null,
      tool_id: details?.tool_id ?? null,
      result_id: liveResult?.id ?? null,
    };
    throw error;
  }
  return liveResult;
}

function plannedMcpServeToolInvocationRequest(plan, { threadId, toolId }) {
  const record = objectRecord(plan);
  const request = objectRecord(record?.request);
  const mcpServeRequest = objectRecord(request?.mcp_serve_request);
  if (
    !record ||
    record.status !== "planned" ||
    record.operation_kind !== "mcp.serve.tools.call" ||
    record.thread_id !== threadId ||
    record.tool_id !== toolId ||
    !request ||
    request.source !== "mcp_serve" ||
    !optionalString(request.tool_call_id) ||
    !optionalString(request.idempotency_key) ||
    !optionalString(request.workflow_graph_id) ||
    !optionalString(request.workflow_node_id) ||
    !mcpServeRequest ||
    mcpServeRequest.method !== "tools/call" ||
    mcpServeRequest.thread_id !== threadId ||
    mcpServeRequest.tool_id !== toolId
  ) {
    const error = new Error("Rust daemon-core MCP serve tool-call plan is incomplete.");
    error.code = "runtime_mcp_serve_tool_call_plan_incomplete";
    error.details = {
      operation_kind: record?.operation_kind ?? null,
      thread_id: record?.thread_id ?? null,
      tool_id: record?.tool_id ?? null,
    };
    throw error;
  }
  return request;
}
