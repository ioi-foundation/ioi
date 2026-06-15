import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeMcpServeSurface } from "./runtime-mcp-serve-surface.mjs";

const MCP_SERVE_ADMISSION = {
  authority_grant_refs: ["wallet.network://grant/mcp-serve/git.diff"],
  authority_receipt_refs: ["receipt://wallet.network/mcp-serve/git.diff"],
  custody_ref: "ctee://workspace/thread-one",
  containment_ref: "containment://mcp-serve/thread-one/git.diff",
};

function harness() {
  const invocations = [];
  const plans = [];
  const resultProjections = [];
  const resultCommits = [];
  const liveResultReplays = [];
  const tools = [
    { stable_tool_id: "workspace.status", display_name: "Workspace status", input_schema: { type: "object" } },
    { stable_tool_id: "git.diff", display_name: "Git diff", input_schema: { type: "object" } },
    { stable_tool_id: "test.run", display_name: "Run tests", input_schema: { type: "object" } },
  ];
  const allowedToolIds = (options = {}) =>
    options.onlyDiff === true ? ["git.diff"] : ["workspace.status", "git.diff"];
  const surface = createRuntimeMcpServeSurface({
    RUNTIME_MCP_SERVE_PROTOCOL_VERSION: "mcp.protocol.test",
    RUNTIME_MCP_SERVE_SCHEMA_VERSION: "ioi.runtime.mcp-serve.test",
    codingToolContracts() {
      return tools;
    },
    mcpServeAllowedToolIds: allowedToolIds,
    mcpServeToolDescriptor(tool) {
      return {
        name: tool.stable_tool_id,
        title: tool.display_name,
        inputSchema: tool.input_schema,
        _meta: { stableToolId: tool.stable_tool_id },
      };
    },
    mcpServeToolIdForName(name, options = {}) {
      return allowedToolIds(options).includes(name) ? name : null;
    },
  });
  function rustMcpServeToolCallPlan(planRequest = {}) {
    plans.push(planRequest);
    const params = planRequest.params && typeof planRequest.params === "object" ? planRequest.params : {};
    const request = planRequest.request && typeof planRequest.request === "object" ? planRequest.request : {};
    const authorityGrantRefs = Array.isArray(planRequest.authority_grant_refs)
      ? planRequest.authority_grant_refs.filter((ref) => typeof ref === "string" && ref.trim())
      : [];
    const authorityReceiptRefs = Array.isArray(planRequest.authority_receipt_refs)
      ? planRequest.authority_receipt_refs.filter((ref) => typeof ref === "string" && ref.trim())
      : [];
    if (authorityGrantRefs.length === 0 || authorityReceiptRefs.length === 0) {
      const error = new Error("MCP serve tool-call planning requires wallet authority grant and receipt refs.");
      error.code = "runtime_mcp_serve_tool_call_authority_required";
      throw error;
    }
    const custodyRef = typeof planRequest.custody_ref === "string" && planRequest.custody_ref.trim()
      ? planRequest.custody_ref.trim()
      : null;
    if (!custodyRef) {
      const error = new Error("MCP serve tool-call planning requires cTEE custody ref.");
      error.code = "runtime_mcp_serve_tool_call_custody_required";
      throw error;
    }
    const containmentRef = typeof planRequest.containment_ref === "string" && planRequest.containment_ref.trim()
      ? planRequest.containment_ref.trim()
      : null;
    if (!containmentRef) {
      const error = new Error("MCP serve tool-call planning requires transport containment ref.");
      error.code = "runtime_mcp_serve_tool_call_containment_required";
      throw error;
    }
    const input = params.arguments && typeof params.arguments === "object" && !Array.isArray(params.arguments)
      ? { ...params.arguments }
      : {};
    const safeToolId = String(planRequest.tool_id ?? "unknown")
      .replace(/[^A-Za-z0-9]/g, "_")
      .replace(/^_+|_+$/g, "") || "unknown";
    const toolCallId = typeof params.tool_call_id === "string" && params.tool_call_id.trim()
      ? params.tool_call_id.trim()
      : typeof request.tool_call_id === "string" && request.tool_call_id.trim()
        ? request.tool_call_id.trim()
        : `mcp_serve_${safeToolId}_mock`;
    const idempotencyKey = typeof params.idempotency_key === "string" && params.idempotency_key.trim()
      ? params.idempotency_key.trim()
      : typeof request.idempotency_key === "string" && request.idempotency_key.trim()
        ? request.idempotency_key.trim()
        : `thread:${planRequest.thread_id}:mcp-serve:${toolCallId}`;
    const workflowGraphId = typeof request.workflow_graph_id === "string" && request.workflow_graph_id.trim()
      ? request.workflow_graph_id.trim()
      : "runtime.mcp_serve";
    const workflowNodeId = typeof request.workflow_node_id === "string" && request.workflow_node_id.trim()
      ? request.workflow_node_id.trim()
      : `runtime.mcp_serve.${safeToolId}`;
    const requestHash = "hash_mcp_serve_mock";
    const invocationRequest = {
      ...input,
      source: "mcp_serve",
      tool_call_id: toolCallId,
      idempotency_key: idempotencyKey,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      authority_grant_refs: authorityGrantRefs,
      authority_receipt_refs: authorityReceiptRefs,
      custody_ref: custodyRef,
      containment_ref: containmentRef,
      mcp_serve_request: {
        schema_version: planRequest.mcp_serve_schema_version,
        jsonrpc_id: planRequest.jsonrpc_id,
        method: "tools/call",
        thread_id: planRequest.thread_id,
        tool_id: planRequest.tool_id,
        tool_name: planRequest.tool_name,
        request_hash: requestHash,
        wallet_authority_boundary: "wallet.network.mcp_serve_tool_call",
        authority_grant_refs: authorityGrantRefs,
        authority_receipt_refs: authorityReceiptRefs,
        custody_ref: custodyRef,
        containment_ref: containmentRef,
      },
    };
    return {
      schema_version: "ioi.runtime.mcp_serve_tool_call_plan.v1",
      object: "ioi.runtime_mcp_serve_tool_call_plan",
      status: "planned",
      source: "rust_runtime_mcp_serve_tool_call_plan_api",
      backend: "rust_policy",
      operation: "runtime_mcp_serve_tool_call",
      operation_kind: "mcp.serve.tools.call",
      thread_id: planRequest.thread_id,
      tool_id: planRequest.tool_id,
      tool_name: planRequest.tool_name,
      method: "tools/call",
      tool_call_id: toolCallId,
      idempotency_key: idempotencyKey,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      request_hash: requestHash,
      request: invocationRequest,
      authority_grant_refs: authorityGrantRefs,
      authority_receipt_refs: authorityReceiptRefs,
      custody_ref: custodyRef,
      containment_ref: containmentRef,
      receipt_refs: [`receipt_runtime_mcp_serve_tool_call_plan_${safeToolId}`],
      policy_decision_refs: [`policy_runtime_mcp_serve_tool_call_plan_${safeToolId}`],
      evidence_refs: [
        "runtime_mcp_serve_tool_call_rust_owned",
        "rust_daemon_core_runtime_mcp_serve_tool_call_plan",
        "agentgres_runtime_mcp_serve_tool_call_truth_required",
        "wallet_runtime_mcp_serve_authority_required",
        "ctee_runtime_mcp_serve_custody_required",
        "runtime_mcp_serve_transport_containment_required",
      ],
    };
  }
  function rustMcpServeToolResultProjection(projectionRequest = {}) {
    resultProjections.push(projectionRequest);
    const invocation = projectionRequest.invocation && typeof projectionRequest.invocation === "object"
      ? projectionRequest.invocation
      : {};
    const planRequest = projectionRequest.plan?.request?.mcp_serve_request ?? {};
    const authorityGrantRefs = Array.isArray(planRequest.authority_grant_refs)
      ? planRequest.authority_grant_refs
      : [];
    const authorityReceiptRefs = Array.isArray(planRequest.authority_receipt_refs)
      ? planRequest.authority_receipt_refs
      : [];
    const custodyRef = planRequest.custody_ref ?? null;
    const containmentRef = planRequest.containment_ref ?? null;
    const payload = invocation.event?.payload_summary && typeof invocation.event.payload_summary === "object"
      ? invocation.event.payload_summary
      : {};
    const status = typeof invocation.status === "string" && invocation.status.trim()
      ? invocation.status.trim()
      : typeof payload.status === "string" && payload.status.trim()
        ? payload.status.trim()
        : "completed";
    const summary = typeof payload.summary === "string" && payload.summary.trim()
      ? payload.summary.trim()
      : `IOI runtime tool ${invocation.tool_name ?? "unknown"} ${status}.`;
    const safeToolId = String(projectionRequest.tool_id ?? "unknown")
      .replace(/[^A-Za-z0-9]/g, "_")
      .replace(/^_+|_+$/g, "") || "unknown";
    const liveResultId = `result_runtime_mcp_serve_${projectionRequest.thread_id}_${safeToolId}_${invocation.tool_call_id ?? "mock"}`;
    const protocolResult = {
      content: [{ type: "text", text: summary }],
      structuredContent: {
        schema_version: projectionRequest.mcp_serve_schema_version,
        object: "ioi.runtime_mcp_serve_tool_result",
        status,
        tool_name: invocation.tool_name ?? null,
        tool_call_id: invocation.tool_call_id ?? null,
        thread_id: projectionRequest.thread_id,
        workflow_graph_id: invocation.workflow_graph_id ?? null,
        workflow_node_id: invocation.workflow_node_id ?? null,
        receipt_refs: invocation.receipt_refs ?? [],
        policy_decision_refs: invocation.policy_decision_refs ?? [],
        artifact_refs: invocation.artifact_refs ?? [],
        wallet_authority_boundary: "wallet.network.mcp_serve_tool_call",
        authority_grant_refs: authorityGrantRefs,
        authority_receipt_refs: authorityReceiptRefs,
        custody_ref: custodyRef,
        containment_ref: containmentRef,
        event_id: invocation.event?.event_id ?? null,
        result: invocation.result ?? null,
        error: invocation.error ?? null,
      },
      isError: status !== "completed",
    };
    return {
      schema_version: "ioi.runtime.mcp_serve_tool_result_projection.v1",
      object: "ioi.runtime_mcp_serve_tool_result_projection",
      status: "projected",
      source: "rust_runtime_mcp_serve_tool_result_projection_api",
      backend: "rust_policy",
      operation_kind: "mcp.serve.tools.result",
      thread_id: projectionRequest.thread_id,
      tool_id: projectionRequest.tool_id,
      tool_name: projectionRequest.tool_name,
      tool_call_id: invocation.tool_call_id ?? null,
      workflow_graph_id: invocation.workflow_graph_id ?? null,
      workflow_node_id: invocation.workflow_node_id ?? null,
      event_id: invocation.event?.event_id ?? null,
      tool_status: status,
      result: protocolResult,
      live_result: {
        schema_version: "ioi.runtime.mcp-live-result.v1",
        object: "ioi.runtime_mcp_live_result",
        id: liveResultId,
        kind: "runtime_mcp_live_result",
        status: status === "completed" ? "materialized" : "materialized_error",
        redaction: "redacted",
        created_at: "2026-06-06T07:00:00.000Z",
        receipt_id: invocation.receipt_refs?.[0] ?? "receipt_mcp_serve_tool_call",
        receipt_refs: invocation.receipt_refs ?? ["receipt_mcp_serve_tool_call"],
        evidence_refs: [
          "runtime_mcp_serve_tool_result_rust_owned",
          "rust_daemon_core_runtime_mcp_serve_tool_result_projection",
          "runtime_mcp_live_result_rust_projection",
          "agentgres_runtime_mcp_live_result_truth_required",
          "runtime_mcp_serve_result_payload_materialized",
          "runtime_mcp_no_js_transport_result",
          "wallet_runtime_mcp_serve_authority_required",
          "ctee_runtime_mcp_serve_custody_required",
          "runtime_mcp_serve_transport_containment_required",
          "receipt_state_root_binding_required",
        ],
        payload: {
          schema_version: projectionRequest.mcp_serve_schema_version,
          protocol_result: protocolResult,
          payload_hash: "sha256:protocol-result",
          payload_ref: `payload://runtime/mcp-live-results/${liveResultId}/protocol-result`,
        },
        details: {
          rust_daemon_core_result_author: "runtime.mcp_serve",
          control_kind: "mcp_serve_tool_call",
          operation_kind: "mcp.serve.tools.result",
          thread_id: projectionRequest.thread_id,
          tool_id: projectionRequest.tool_id,
          tool_name: projectionRequest.tool_name,
          tool_call_id: invocation.tool_call_id ?? null,
          workflow_graph_id: invocation.workflow_graph_id ?? null,
          workflow_node_id: invocation.workflow_node_id ?? null,
          event_id: invocation.event?.event_id ?? null,
          receipt_id: invocation.receipt_refs?.[0] ?? "receipt_mcp_serve_tool_call",
          wallet_authority_boundary: "wallet.network.mcp_serve_tool_call",
          authority_grant_refs: authorityGrantRefs,
          authority_receipt_refs: authorityReceiptRefs,
          custody_ref: custodyRef,
          containment_ref: containmentRef,
          ctee_custody_required: true,
          transport_containment_required: true,
          result_materialized: true,
          backend_materialization_status: "rust_step_module_invocation_materialized",
          rust_coding_tool_invocation: true,
          step_module_router_owner: "rust_daemon_core",
        },
      },
      receipt_refs: invocation.receipt_refs ?? [],
      policy_decision_refs: invocation.policy_decision_refs ?? [],
      evidence_refs: [
        "runtime_mcp_serve_tool_result_rust_owned",
        "rust_daemon_core_runtime_mcp_serve_tool_result_projection",
        "agentgres_runtime_mcp_serve_tool_call_truth_required",
        "wallet_runtime_mcp_serve_authority_required",
        "ctee_runtime_mcp_serve_custody_required",
        "runtime_mcp_serve_transport_containment_required",
        "agentgres_runtime_mcp_live_result_truth_required",
      ],
    };
  }
  const store = {
    stateDir: "/runtime-state",
    agentForThread() {
      throw new Error("MCP serve tool-call facade must not resolve thread agents in JS.");
    },
    async invokeThreadTool() {
      throw new Error("MCP serve tool-call facade must not invoke JS thread tools.");
    },
    async invokeThreadToolAsync() {
      throw new Error("MCP serve tool-call facade must not invoke retired async JS thread tools.");
    },
    contextPolicyCore: {
      planRuntimeMcpServeToolCall: rustMcpServeToolCallPlan,
      projectRuntimeMcpServeToolResult: rustMcpServeToolResultProjection,
      projectMcpLiveResultReplay(request) {
        liveResultReplays.push(request);
        const commit = [...resultCommits]
          .reverse()
          .find((entry) => entry.request.result_id === request.result_id);
        const latestResult = commit?.request?.result ?? null;
        return {
          source: "rust_mcp_live_result_replay_api",
          backend: "rust_policy",
          schema_version: "ioi.runtime.mcp-live-result-replay.v1",
          object: "ioi.runtime_mcp_live_result_replay",
          status: "projected",
          result_count: latestResult ? 1 : 0,
          results: latestResult ? [latestResult] : [],
          result_ids: latestResult?.id ? [latestResult.id] : [],
          latest_result: latestResult,
          replay_hash: `replay.${request.result_id}`,
        };
      },
    },
    codingToolInvocationSurface: {
      invokeThreadTool(surfaceStore, threadId, toolId, request) {
        invocations.push({ surfaceStore, threadId, toolId, request });
        return {
          schema_version: "ioi.runtime.coding-tool-result.v1",
          object: "ioi.runtime_coding_tool_result",
          status: "completed",
          tool_name: toolId,
          tool_call_id: request.tool_call_id,
          thread_id: threadId,
          workflow_graph_id: request.workflow_graph_id,
          workflow_node_id: request.workflow_node_id,
          receipt_refs: ["receipt_mcp_serve_tool_call"],
          policy_decision_refs: ["policy_mcp_serve_tool_call"],
          artifact_refs: ["artifact_mcp_serve_tool_call"],
          event: {
            event_id: "event_mcp_serve_tool_call",
            payload_summary: { summary: `${toolId} completed through Rust coding-tool invocation.` },
          },
          result: { ok: true, input: request },
        };
      },
    },
    commitRuntimeMcpLiveResultState(request) {
      resultCommits.push({ request });
      return {
        result_id: request.result_id,
        operation_kind: request.operation_kind,
        commit_hash: `commit.${request.result_id}`,
      };
    },
  };
  return { invocations, liveResultReplays, plans, resultCommits, resultProjections, store, surface };
}

test("runtime MCP serve surface projects status and allowed tool catalog", () => {
  const { store, surface } = harness();

  const status = surface.mcpServeStatus(store, {
    thread_id: "thread-one",
    threadId: "thread-retired",
    onlyDiff: true,
  });

  assert.equal(status.schema_version, "ioi.runtime.mcp-serve.test");
  assert.equal(status.protocol_version, "mcp.protocol.test");
  assert.equal(status.thread_id, "thread-one");
  assert.equal(surface.mcpServeStatus(store, { threadId: "thread-retired" }).thread_id, null);
  assert.deepEqual(status.allowed_tool_ids, ["git.diff"]);
  assert.equal(status.tool_count, 1);
  assert.deepEqual(status.tools.map((tool) => tool.name), ["git.diff"]);
  assert.equal(status.routes.serve_for_thread, "/v1/threads/{thread_id}/mcp/serve");
  assert.deepEqual(status.evidence_refs, ["mcp.serve.http_jsonrpc", "coding_tool_receipt"]);
  assert.equal(Object.hasOwn(status, "schemaVersion"), false);
  assert.equal(Object.hasOwn(status, "protocolVersion"), false);
  assert.equal(Object.hasOwn(status, "allowedToolIds"), false);
  assert.equal(Object.hasOwn(status, "toolCount"), false);
  assert.equal(Object.hasOwn(status, "evidenceRefs"), false);
  assert.equal(Object.hasOwn(status.routes, "serveForThread"), false);
});

test("runtime MCP serve surface handles JSON-RPC lifecycle and batch notifications", async () => {
  const { invocations, store, surface } = harness();

  const initialize = await surface.handleMcpServeJsonRpc(
    store,
    "thread-one",
    { jsonrpc: "2.0", id: 1, method: "initialize" },
    { onlyDiff: true },
  );
  assert.equal(initialize.result.protocolVersion, "mcp.protocol.test");
  assert.equal(initialize.result.serverInfo.version, "ioi.runtime.mcp-serve.test");
  assert.equal(initialize.result._meta.thread_id, "thread-one");
  assert.deepEqual(initialize.result._meta.allowed_tool_ids, ["git.diff"]);

  const initializedNotification = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    { jsonrpc: "2.0", method: "notifications/initialized" },
  );
  assert.equal(initializedNotification, null);

  const initializedRequest = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    { jsonrpc: "2.0", id: 2, method: "notifications/initialized" },
  );
  assert.deepEqual(initializedRequest, { jsonrpc: "2.0", id: 2, result: {} });

  const batch = await surface.handleMcpServeJsonRpc(
    store,
    "thread-one",
    [
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 3, method: "ping" },
      { jsonrpc: "2.0", id: 4, method: "tools/list" },
    ],
  );
  assert.equal(batch.length, 2);
  assert.deepEqual(batch.map((response) => response.id), [3, 4]);
  assert.deepEqual(batch[1].result.tools.map((tool) => tool.name), ["workspace.status", "git.diff"]);
  assert.deepEqual(invocations, []);
});

test("runtime MCP serve surface invokes Rust-owned coding-tool path and Rust-owned result projection", async () => {
  const { invocations, liveResultReplays, plans, resultCommits, resultProjections, store, surface } = harness();

  const invalid = await surface.handleSingleMcpServeJsonRpc(store, "thread-one", []);
  assert.equal(invalid.error.code, -32600);
  assert.equal(invalid.error.data.schema_version, "ioi.runtime.mcp-serve.test");

  const disallowed = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "workspace.status" } },
    { onlyDiff: true },
  );
  assert.equal(disallowed.error.code, -32602);
  assert.deepEqual(disallowed.error.data.allowed_tools, ["git.diff"]);
  assert.equal(Object.hasOwn(disallowed.error.data, "allowedTools"), false);

  const retiredToolName = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    { jsonrpc: "2.0", id: 9, method: "tools/call", params: { toolName: "git.diff" } },
    { onlyDiff: true },
  );
  assert.equal(retiredToolName.error.code, -32602);
  assert.match(retiredToolName.error.message, /missing/);
  assert.deepEqual(invocations, []);

  const unsupported = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    { jsonrpc: "2.0", id: 6, method: "resources/read" },
  );
  assert.equal(unsupported.error.code, -32601);
  assert.equal(unsupported.error.data.supported_methods.includes("tools/call"), true);
  assert.equal(Object.hasOwn(unsupported.error.data, "supportedMethods"), false);
  assert.equal(plans.length, 0);

  const response = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "git.diff", arguments: { includeStat: true } },
    },
    {
      onlyDiff: true,
      ...MCP_SERVE_ADMISSION,
      workflow_graph_id: "custom.graph",
      workflow_node_id: "custom.node",
      workflowGraphId: "retired.graph",
      workflowNodeId: "retired.node",
    },
  );
  assert.equal(response.id, 7);
  assert.equal(response.result.structuredContent.status, "completed");
  assert.equal(response.result.structuredContent.tool_name, "git.diff");
  assert.equal(response.result.structuredContent.event_id, "event_mcp_serve_tool_call");
  assert.deepEqual(response.result.structuredContent.receipt_refs, ["receipt_mcp_serve_tool_call"]);
  assert.equal(response.result.content[0].text, "git.diff completed through Rust coding-tool invocation.");
  assert.equal(plans.length, 1);
  assert.equal(plans[0].operation_kind, "mcp.serve.tools.call");
  assert.equal(plans[0].params.arguments.includeStat, true);
  assert.equal(plans[0].request.workflow_graph_id, "custom.graph");
  assert.equal(plans[0].request.workflowGraphId, "retired.graph");
  assert.equal(invocations.length, 1);
  assert.equal(invocations[0].surfaceStore, store);
  assert.equal(invocations[0].threadId, "thread-one");
  assert.equal(invocations[0].toolId, "git.diff");
  assert.equal(invocations[0].request.includeStat, true);
  assert.equal(invocations[0].request.source, "mcp_serve");
  assert.equal(invocations[0].request.workflow_graph_id, "custom.graph");
  assert.equal(invocations[0].request.workflow_node_id, "custom.node");
  assert.deepEqual(invocations[0].request.authority_grant_refs, MCP_SERVE_ADMISSION.authority_grant_refs);
  assert.deepEqual(invocations[0].request.authority_receipt_refs, MCP_SERVE_ADMISSION.authority_receipt_refs);
  assert.equal(invocations[0].request.custody_ref, MCP_SERVE_ADMISSION.custody_ref);
  assert.equal(invocations[0].request.containment_ref, MCP_SERVE_ADMISSION.containment_ref);
  assert.equal(Object.hasOwn(invocations[0].request, "workflowGraphId"), false);
  assert.equal(Object.hasOwn(invocations[0].request, "workflowNodeId"), false);
  assert.equal(invocations[0].request.mcp_serve_request.method, "tools/call");
  assert.equal(invocations[0].request.mcp_serve_request.tool_id, "git.diff");
  assert.deepEqual(
    invocations[0].request.mcp_serve_request.authority_grant_refs,
    MCP_SERVE_ADMISSION.authority_grant_refs,
  );
  assert.equal(invocations[0].request.mcp_serve_request.custody_ref, MCP_SERVE_ADMISSION.custody_ref);
  assert.equal(Object.hasOwn(invocations[0].request.mcp_serve_request, "toolId"), false);
  assert.equal(resultProjections.length, 1);
  assert.equal(resultProjections[0].operation_kind, "mcp.serve.tools.result");
  assert.equal(resultProjections[0].plan.tool_id, "git.diff");
  assert.equal(resultProjections[0].invocation.event.event_id, "event_mcp_serve_tool_call");
  assert.equal(resultProjections[0].invocation.event.id, undefined);
  assert.equal(resultCommits.length, 1);
  assert.equal(resultCommits[0].request.operation_kind, "runtime.mcp_serve.result.write");
  assert.equal(resultCommits[0].request.result.details.rust_daemon_core_result_author, "runtime.mcp_serve");
  assert.equal(resultCommits[0].request.result.details.result_materialized, true);
  assert.deepEqual(
    resultCommits[0].request.result.details.authority_grant_refs,
    MCP_SERVE_ADMISSION.authority_grant_refs,
  );
  assert.equal(resultCommits[0].request.result.details.custody_ref, MCP_SERVE_ADMISSION.custody_ref);
  assert.equal(resultCommits[0].request.result.details.containment_ref, MCP_SERVE_ADMISSION.containment_ref);
  assert.equal(Object.hasOwn(resultCommits[0].request.result.details, "js_transport_invocation"), false);
  assert.equal(Object.hasOwn(resultCommits[0].request.result.details, "command_transport_fallback"), false);
  assert.equal(
    resultCommits[0].request.result.payload.protocol_result.structuredContent.event_id,
    "event_mcp_serve_tool_call",
  );
  assert.equal(liveResultReplays.length, 1);
  assert.equal(liveResultReplays[0].state_dir, "/runtime-state");
  assert.equal(liveResultReplays[0].result_id, resultCommits[0].request.result_id);
  assert.equal(liveResultReplays[0].receipt_id, "receipt_mcp_serve_tool_call");
  assert.equal(liveResultReplays[0].control_kind, "mcp_serve_tool_call");

  const retiredOnlyResponse = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 8,
      method: "tools/call",
      params: { name: "git.diff", arguments: { summary: true } },
    },
    {
      onlyDiff: true,
      ...MCP_SERVE_ADMISSION,
      workflowGraphId: "retired.graph",
      workflowNodeId: "retired.node",
    },
  );
  assert.equal(retiredOnlyResponse.result.structuredContent.status, "completed");
  assert.equal(resultCommits.length, 2);
  assert.equal(liveResultReplays.length, 2);
  const retiredOnlyInvocation = invocations.at(-1);
  assert.equal(retiredOnlyInvocation.request.workflow_graph_id, "runtime.mcp_serve");
  assert.equal(retiredOnlyInvocation.request.workflow_node_id, "runtime.mcp_serve.git_diff");
  assert.equal(Object.hasOwn(retiredOnlyInvocation.request, "workflowGraphId"), false);
  assert.equal(Object.hasOwn(retiredOnlyInvocation.request, "workflowNodeId"), false);

  const retiredArgsResponse = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 10,
      method: "tools/call",
      params: { name: "git.diff", args: { includeStat: "retired" } },
    },
    { onlyDiff: true, ...MCP_SERVE_ADMISSION },
  );
  assert.equal(retiredArgsResponse.result.structuredContent.status, "completed");
  const retiredArgsInvocation = invocations.at(-1);
  assert.equal(Object.hasOwn(retiredArgsInvocation.request, "includeStat"), false);
  assert.equal(Object.hasOwn(retiredArgsInvocation.request, "args"), false);
});

test("runtime MCP serve tool calls reject retired transport fallback proof fields", async () => {
  const { invocations, resultCommits, store, surface } = harness();
  const projectResult = store.contextPolicyCore.projectRuntimeMcpServeToolResult;
  store.contextPolicyCore.projectRuntimeMcpServeToolResult = (request) => {
    const projection = projectResult(request);
    projection.live_result.details.command_transport_fallback = false;
    projection.live_result.details.js_transport_invocation = false;
    return projection;
  };

  const response = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 18,
      method: "tools/call",
      params: { name: "git.diff", arguments: { includeStat: true } },
    },
    { onlyDiff: true, ...MCP_SERVE_ADMISSION },
  );

  assert.equal(response.error.code, -32603);
  assert.equal(response.error.data.code, "runtime_mcp_serve_live_result_projection_incomplete");
  assert.deepEqual(response.error.data.details.retired_transport_proof_fields, [
    "details.js_transport_invocation_retired",
    "details.command_transport_fallback_retired",
  ]);
  assert.equal(invocations.length, 1);
  assert.deepEqual(resultCommits, []);
});

test("runtime MCP serve tool calls fail closed without Rust-owned coding-tool invocation surface", async () => {
  const { store, surface } = harness();
  delete store.codingToolInvocationSurface;

  const response = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "git.diff", arguments: { includeStat: true } },
    },
    { onlyDiff: true, ...MCP_SERVE_ADMISSION },
  );

  assert.equal(response.error.code, -32000);
  assert.equal(response.error.data.code, "runtime_mcp_serve_tool_call_rust_core_required");
  assert.equal(response.error.data.details.rust_core_boundary, "runtime.mcp_serve");
  assert.equal(response.error.data.details.operation_kind, "mcp.serve.tools.call");
  assert.equal(response.error.data.details.thread_id, "thread-one");
  assert.equal(response.error.data.details.tool_id, "git.diff");
  assert.equal(response.error.data.details.tool_name, "git.diff");
  assert.equal(
    response.error.data.details.evidence_refs.includes("runtime_mcp_serve_tool_call_js_facade_retired"),
    true,
  );
  assert.equal(
    response.error.data.details.evidence_refs.includes(
      "rust_daemon_core_runtime_mcp_serve_tool_result_projection_required",
    ),
    true,
  );
});

test("runtime MCP serve tool calls fail closed without Agentgres live-result commit", async () => {
  const { invocations, store, surface } = harness();
  delete store.commitRuntimeMcpLiveResultState;

  const response = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 15,
      method: "tools/call",
      params: { name: "git.diff", arguments: { includeStat: true } },
    },
    { onlyDiff: true, ...MCP_SERVE_ADMISSION },
  );

  assert.equal(response.error.code, -32000);
  assert.equal(response.error.data.code, "runtime_mcp_serve_tool_call_rust_core_required");
  assert.deepEqual(invocations, []);
  assert.equal(
    response.error.data.details.evidence_refs.includes("agentgres_runtime_mcp_live_result_state_commit_required"),
    true,
  );
});

test("runtime MCP serve tool calls fail closed without Rust live-result replay", async () => {
  const { invocations, store, surface } = harness();
  delete store.contextPolicyCore.projectMcpLiveResultReplay;

  const response = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 16,
      method: "tools/call",
      params: { name: "git.diff", arguments: { includeStat: true } },
    },
    { onlyDiff: true },
  );

  assert.equal(response.error.code, -32000);
  assert.equal(response.error.data.code, "runtime_mcp_serve_tool_call_rust_core_required");
  assert.deepEqual(invocations, []);
  assert.equal(
    response.error.data.details.evidence_refs.includes("rust_daemon_core_runtime_mcp_live_result_replay_required"),
    true,
  );
});

test("runtime MCP serve tool calls fail closed without Rust-owned MCP serve planner", async () => {
  const { store, surface } = harness();
  delete store.contextPolicyCore;

  const response = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 11,
      method: "tools/call",
      params: { name: "git.diff", arguments: { includeStat: true } },
    },
    { onlyDiff: true },
  );

  assert.equal(response.error.code, -32000);
  assert.equal(response.error.data.code, "runtime_mcp_serve_tool_call_rust_core_required");
  assert.equal(response.error.data.details.rust_core_boundary, "runtime.mcp_serve");
  assert.equal(response.error.data.details.operation_kind, "mcp.serve.tools.call");
  assert.equal(response.error.data.details.thread_id, "thread-one");
  assert.equal(response.error.data.details.tool_id, "git.diff");
});

test("runtime MCP serve tool calls fail closed without Rust-owned result projection", async () => {
  const { invocations, store, surface } = harness();
  delete store.contextPolicyCore.projectRuntimeMcpServeToolResult;

  const response = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 13,
      method: "tools/call",
      params: { name: "git.diff", arguments: { includeStat: true } },
    },
    { onlyDiff: true },
  );

  assert.equal(response.error.code, -32000);
  assert.equal(response.error.data.code, "runtime_mcp_serve_tool_call_rust_core_required");
  assert.deepEqual(invocations, []);
});

test("runtime MCP serve tool calls reject incomplete Rust daemon-core plans", async () => {
  const { invocations, store, surface } = harness();
  store.contextPolicyCore.planRuntimeMcpServeToolCall = () => ({
    status: "planned",
    operation_kind: "mcp.serve.tools.call",
    thread_id: "thread-one",
    tool_id: "git.diff",
  });

  const response = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 12,
      method: "tools/call",
      params: { name: "git.diff", arguments: { includeStat: true } },
    },
    { onlyDiff: true },
  );

  assert.equal(response.error.code, -32603);
  assert.equal(response.error.data.code, "runtime_mcp_serve_tool_call_plan_incomplete");
  assert.equal(response.error.data.details.operation_kind, "mcp.serve.tools.call");
  assert.deepEqual(invocations, []);
});

test("runtime MCP serve tool calls reject incomplete Rust result projections", async () => {
  const { invocations, store, surface } = harness();
  store.contextPolicyCore.projectRuntimeMcpServeToolResult = () => ({
    status: "projected",
    operation_kind: "mcp.serve.tools.result",
    thread_id: "thread-one",
    tool_id: "git.diff",
  });

  const response = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 14,
      method: "tools/call",
      params: { name: "git.diff", arguments: { includeStat: true } },
    },
    { onlyDiff: true, ...MCP_SERVE_ADMISSION },
  );

  assert.equal(response.error.code, -32603);
  assert.equal(response.error.data.code, "runtime_mcp_serve_tool_result_projection_incomplete");
  assert.equal(response.error.data.details.operation_kind, "mcp.serve.tools.result");
  assert.equal(invocations.length, 1);
});

test("runtime MCP serve tool calls fail closed without authority custody or containment admission", async () => {
  const { invocations, store, surface } = harness();

  const missingAuthority = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 17,
      method: "tools/call",
      params: { name: "git.diff", arguments: { includeStat: true } },
    },
    { onlyDiff: true, custody_ref: MCP_SERVE_ADMISSION.custody_ref, containment_ref: MCP_SERVE_ADMISSION.containment_ref },
  );
  assert.equal(missingAuthority.error.data.code, "runtime_mcp_serve_tool_call_authority_required");
  assert.deepEqual(invocations, []);

  const missingCustody = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 18,
      method: "tools/call",
      params: { name: "git.diff", arguments: { includeStat: true } },
    },
    {
      onlyDiff: true,
      authority_grant_refs: MCP_SERVE_ADMISSION.authority_grant_refs,
      authority_receipt_refs: MCP_SERVE_ADMISSION.authority_receipt_refs,
      containment_ref: MCP_SERVE_ADMISSION.containment_ref,
    },
  );
  assert.equal(missingCustody.error.data.code, "runtime_mcp_serve_tool_call_custody_required");
  assert.deepEqual(invocations, []);

  const missingContainment = await surface.handleSingleMcpServeJsonRpc(
    store,
    "thread-one",
    {
      jsonrpc: "2.0",
      id: 19,
      method: "tools/call",
      params: { name: "git.diff", arguments: { includeStat: true } },
    },
    {
      onlyDiff: true,
      authority_grant_refs: MCP_SERVE_ADMISSION.authority_grant_refs,
      authority_receipt_refs: MCP_SERVE_ADMISSION.authority_receipt_refs,
      custody_ref: MCP_SERVE_ADMISSION.custody_ref,
    },
  );
  assert.equal(missingContainment.error.data.code, "runtime_mcp_serve_tool_call_containment_required");
  assert.deepEqual(invocations, []);
});
