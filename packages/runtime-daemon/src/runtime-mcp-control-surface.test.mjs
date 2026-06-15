import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeMcpControlSurface } from "./runtime-mcp-control-surface.mjs";

function server(id, tools = [{ name: "search" }], extra = {}) {
  return {
    id,
    label: id,
    enabled: extra.enabled ?? true,
    status: extra.status ?? "configured",
    transport: extra.transport ?? "stdio",
    tools,
    resources: extra.resources ?? [],
    prompts: extra.prompts ?? [],
    ...extra,
  };
}

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function failIfCalled(name) {
  return () => {
    throw new Error(`${name} must not be reached by the Rust-owned MCP control surface`);
  };
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function liveExitReceipt({
  request,
  payload,
  agent,
  control,
  receiptId,
  operationRef,
  stateRootBefore,
  stateRootAfter,
  resultingHead,
  payloadHash,
}) {
  return {
    schema_version: "ioi.runtime.mcp-live-exit-receipt.v1",
    object: "ioi.runtime_mcp_live_exit_receipt",
    id: receiptId,
    kind: "runtime_mcp_live_exit",
    redaction: "redacted",
    created_at: request.created_at,
    receipt_refs: [receiptId],
    evidence_refs: [
      "runtime_mcp_control_rust_owned",
      "runtime_mcp_live_exit_rust_receipt",
      "agentgres_runtime_mcp_live_receipt_truth_required",
      "wallet_network_mcp_external_exit_authority_required",
      "ctee_mcp_external_exit_custody_required",
      "mcp_transport_containment_required",
      "runtime_mcp_backend_execution_rust_driver_bound",
      "receipt_state_root_binding_required",
    ],
    details: {
      rust_daemon_core_receipt_author: "runtime.mcp_control",
      control_kind: request.control_kind,
      event_id: request.event_id,
      thread_id: request.thread_id,
      agent_id: agent.id,
      server_id: payload.server_id ?? null,
      tool_ref: payload.tool_id ?? payload.tool_name ?? null,
      live_transport: payload.live_transport ?? null,
      execution_mode: payload.execution_mode ?? null,
      timeout_ms: payload.timeout_ms ?? null,
      wallet_authority_boundary: "wallet.network.mcp_external_exit",
      authority_hash: control.authority_hash,
      authority_grant_refs: payload.authority_grant_refs ?? [],
      authority_receipt_refs: payload.authority_receipt_refs ?? [],
      custody_ref: payload.custody_ref ?? null,
      containment_ref: payload.containment_ref ?? null,
      runtime_mcp_agentgres_operation_ref: operationRef,
      runtime_mcp_agent_state_root_before: stateRootBefore,
      runtime_mcp_agent_state_root_after: stateRootAfter,
      runtime_mcp_resulting_head: resultingHead,
      result_materialized: true,
      result_payload_hash: payloadHash,
      runtime_mcp_backend_execution_status: "rust_driver_contract_bound",
      runtime_mcp_backend_owner: "ioi_drivers::mcp::McpManager",
      runtime_mcp_backend_transport_owner: "ioi_drivers::mcp::transport::McpTransport",
      runtime_mcp_backend_method: request.control_kind === "mcp_live_discovery" ? "tools/list" : "tools/call",
      runtime_mcp_backend_contract_required: true,
      js_backend_execution: false,
      js_transport_invocation: false,
      command_transport_fallback: false,
      binary_bridge_fallback: false,
      compatibility_fallback: false,
    },
  };
}

function liveBackendExecutionContract({ request, payload, agent, operationRef, resultingHead }) {
  return {
    schema_version: "ioi.runtime.mcp-backend-execution.v1",
    object: "ioi.runtime_mcp_backend_execution",
    status: "rust_driver_contract_bound",
    owner: "ioi_drivers::mcp::McpManager",
    transport_owner: "ioi_drivers::mcp::transport::McpTransport",
    method: request.control_kind === "mcp_live_discovery" ? "tools/list" : "tools/call",
    control_kind: request.control_kind,
    event_id: request.event_id,
    thread_id: request.thread_id,
    agent_id: agent.id,
    server_id: payload.server_id ?? null,
    tool_ref: payload.tool_id ?? payload.tool_name ?? null,
    live_transport: payload.live_transport ?? null,
    execution_mode: payload.execution_mode ?? null,
    timeout_ms: payload.timeout_ms ?? null,
    custody_ref: payload.custody_ref ?? null,
    containment_ref: payload.containment_ref ?? null,
    runtime_mcp_agentgres_operation_ref: operationRef,
    runtime_mcp_resulting_head: resultingHead,
    js_backend_execution: false,
    command_transport_fallback: false,
    binary_bridge_fallback: false,
    compatibility_fallback: false,
  };
}

function liveExitResult({
  request,
  payload,
  agent,
  control,
  resultId,
  receiptId,
  operationRef,
  stateRootBefore,
  stateRootAfter,
  resultingHead,
  payloadHash,
}) {
  const payloadKind = request.control_kind === "mcp_live_discovery"
    ? "mcp_live_discovery_result"
    : "mcp_tool_result";
  const backendExecution = liveBackendExecutionContract({
    request,
    payload,
    agent,
    operationRef,
    resultingHead,
  });
  return {
    schema_version: "ioi.runtime.mcp-live-result.v1",
    object: "ioi.runtime_mcp_live_result",
    id: resultId,
    kind: "runtime_mcp_live_result",
    status: "rust_materialized",
    redaction: "redacted",
    created_at: request.created_at,
    receipt_id: receiptId,
    receipt_refs: [receiptId],
    evidence_refs: [
      "runtime_mcp_control_rust_owned",
      "runtime_mcp_live_result_rust_projection",
      "agentgres_runtime_mcp_live_result_truth_required",
      "runtime_mcp_live_result_payload_rust_materialized",
      "runtime_mcp_no_js_transport_result",
      "runtime_mcp_backend_execution_rust_driver_bound",
      "runtime_mcp_live_backend_rust_driver_executed",
      "receipt_state_root_binding_required",
    ],
    payload: {
      schema_version: "ioi.runtime.mcp-live-result-payload.v1",
      object: "ioi.runtime_mcp_live_result_payload",
      payload_kind: payloadKind,
      status: "materialized",
      payload_hash: payloadHash,
      result_payload_hash: payloadHash,
      backend_execution: backendExecution,
      protocol_result: {
        content: [{ type: "text", text: `Rust daemon core materialized ${payloadKind}.` }],
        structuredContent: {
          object: "ioi.runtime_mcp_live_result_payload",
          payload_kind: payloadKind,
          control_kind: request.control_kind,
          event_id: request.event_id,
          backend_execution_status: "rust_driver_contract_bound",
          backend_method: backendExecution.method,
        },
        isError: false,
      },
    },
    details: {
      rust_daemon_core_result_author: "runtime.mcp_control",
      control_kind: request.control_kind,
      event_id: request.event_id,
      thread_id: request.thread_id,
      agent_id: agent.id,
      server_id: payload.server_id ?? null,
      tool_ref: payload.tool_id ?? payload.tool_name ?? null,
      live_transport: payload.live_transport ?? null,
      execution_mode: payload.execution_mode ?? null,
      timeout_ms: payload.timeout_ms ?? null,
      runtime_mcp_agentgres_operation_ref: operationRef,
      runtime_mcp_agent_state_root_before: stateRootBefore,
      runtime_mcp_agent_state_root_after: stateRootAfter,
      runtime_mcp_resulting_head: resultingHead,
      receipt_id: receiptId,
      result_materialized: true,
      backend_materialization_status: "rust_driver_contract_bound",
      runtime_mcp_backend_execution_status: "rust_driver_contract_bound",
      runtime_mcp_backend_owner: "ioi_drivers::mcp::McpManager",
      runtime_mcp_backend_transport_owner: "ioi_drivers::mcp::transport::McpTransport",
      runtime_mcp_backend_method: backendExecution.method,
      runtime_mcp_backend_contract_required: true,
      runtime_mcp_live_backend_execution_status: "rust_driver_executed",
      runtime_mcp_live_backend_execution_required: true,
      payload_ref: null,
      payload_hash: payloadHash,
      result_payload_hash: payloadHash,
      js_backend_execution: false,
      js_transport_invocation: false,
      command_transport_fallback: false,
      binary_bridge_fallback: false,
      compatibility_fallback: false,
    },
  };
}

function liveBackendExecutionObservation(request) {
  const result = cloneJson(request.planned_result);
  const backendExecution = {
    ...(request.backend_execution ?? {}),
    status: "rust_driver_executed",
  };
  result.evidence_refs = Array.from(new Set([
    ...(Array.isArray(result.evidence_refs) ? result.evidence_refs : []),
    "runtime_mcp_live_backend_rust_driver_executed",
  ]));
  result.details = {
    ...(result.details ?? {}),
    runtime_mcp_live_backend_execution_status: "rust_driver_executed",
    runtime_mcp_live_backend_execution_required: true,
    runtime_mcp_live_backend_execution_source: "rust_mcp_live_backend_execution_api",
    runtime_mcp_live_backend_result_observed: true,
  };
  return {
    source: "rust_mcp_live_backend_execution_api",
    backend: "rust_policy",
    schema_version: "ioi.runtime.mcp-live-backend-execution.v1",
    object: "ioi.runtime_mcp_live_backend_execution",
    status: "rust_driver_executed",
    control_kind: request.control_kind,
    event_id: request.event_id,
    thread_id: request.thread_id,
    agent_id: request.agent_id,
    server_id: request.server_id,
    tool_ref: request.tool_ref,
    backend_execution: backendExecution,
    result,
    evidence_refs: ["runtime_mcp_live_backend_rust_driver_executed"],
  };
}

function planMcpControlAgentStateUpdate(request, currentAgent) {
  assert.equal(Object.hasOwn(request, "agent"), false);
  assert.equal(request.agent_id, currentAgent.id);
  assert.equal(request.state_dir, "/runtime-state");
  const agent = cloneJson(currentAgent);
  const payload = request.request ?? {};
  const registry = agent.mcpRegistry ?? { servers: [] };
  let servers = Array.isArray(registry.servers) ? registry.servers.map((item) => cloneJson(item)) : [];
  const serverId = payload.server_id ?? payload.server?.id ?? null;
  if (["mcp_invoke", "mcp_live_discovery"].includes(request.control_kind)) {
    if (!serverId) {
      const error = new Error("Rust MCP live exits require a server_id.");
      error.code = "mcp_control_live_exit_server_required";
      throw error;
    }
    if (request.control_kind === "mcp_invoke" && !payload.tool_id && !payload.tool_name) {
      const error = new Error("Rust MCP invoke exits require a tool id or name.");
      error.code = "mcp_control_live_exit_tool_required";
      throw error;
    }
    if (!Array.isArray(payload.authority_grant_refs) || payload.authority_grant_refs.length === 0) {
      const error = new Error("Rust MCP live exits require wallet authority grant refs.");
      error.code = "mcp_control_live_exit_wallet_authority_required";
      throw error;
    }
    if (!Array.isArray(payload.authority_receipt_refs) || payload.authority_receipt_refs.length === 0) {
      const error = new Error("Rust MCP live exits require wallet authority receipt refs.");
      error.code = "mcp_control_live_exit_wallet_authority_required";
      throw error;
    }
    if (!payload.custody_ref) {
      const error = new Error("Rust MCP live exits require cTEE custody refs.");
      error.code = "mcp_control_live_exit_custody_required";
      throw error;
    }
    if (!payload.containment_ref) {
      const error = new Error("Rust MCP live exits require transport containment refs.");
      error.code = "mcp_control_live_exit_containment_required";
      throw error;
    }
  }
  if (request.control_kind === "mcp_import") {
    servers = Array.isArray(payload.servers) ? payload.servers.map((item) => cloneJson(item)) : [];
  } else if (request.control_kind === "mcp_add" && payload.server) {
    const next = cloneJson(payload.server);
    const index = servers.findIndex((item) => item.id === next.id);
    if (index >= 0) servers[index] = next;
    else servers.push(next);
  } else if (request.control_kind === "mcp_remove" && serverId) {
    servers = servers.filter((item) => item.id !== serverId);
  } else if ((request.control_kind === "mcp_enable" || request.control_kind === "mcp_disable") && serverId) {
    servers = servers.map((item) =>
      item.id === serverId
        ? {
            ...item,
            enabled: request.control_kind === "mcp_enable",
            status: request.control_kind === "mcp_enable" ? "configured" : "disabled",
          }
        : item,
    );
  }
  agent.mcpRegistry = { servers };
  agent.updatedAt = request.created_at;
  const liveExit = ["mcp_invoke", "mcp_live_discovery"].includes(request.control_kind);
  const receiptId = liveExit
    ? `receipt_runtime_mcp_live_exit_${agent.id}_${request.control_kind}_${request.event_id}`
    : null;
  const resultId = liveExit
    ? `result_runtime_mcp_live_exit_${agent.id}_${request.control_kind}_${request.event_id}`
    : null;
  if (receiptId) {
    agent.receipt_refs = [receiptId];
  }
  if (resultId) {
    agent.result_refs = [resultId];
  }
  const stateRootBefore = liveExit ? `sha256:before:${request.control_kind}` : null;
  const stateRootAfter = liveExit ? `sha256:after:${request.control_kind}` : null;
  const operationRef = liveExit
    ? `agentgres://runtime-state/agents/${agent.id}/operations/${request.control_kind}/${request.event_id}`
    : null;
  const resultingHead = liveExit
    ? `agentgres://runtime-state/agents/${agent.id}/head/${stateRootAfter.replaceAll(":", "_")}`
    : null;
  const payloadHash = liveExit ? `sha256:payload:${request.control_kind}:${request.event_id}` : null;
  const control = {
    control_kind: request.control_kind,
    event_id: request.event_id,
    seq: request.seq,
    created_at: request.created_at,
    server_id: serverId,
    server_count: servers.length,
    enabled_server_count: servers.filter((item) => item.enabled !== false).length,
    registry_hash: `hash.${servers.map((item) => item.id).join(".")}`,
    wallet_authority_required: liveExit,
    wallet_authority_boundary: liveExit ? "wallet.network.mcp_external_exit" : null,
    ctee_custody_required: liveExit,
    transport_containment_required: liveExit,
    authority_grant_refs: payload.authority_grant_refs ?? [],
    authority_receipt_refs: payload.authority_receipt_refs ?? [],
    authority_hash: payload.authority_grant_refs?.length
      ? `sha256:authority:${request.control_kind}:${serverId}`
      : null,
    custody_ref: payload.custody_ref ?? null,
    containment_ref: payload.containment_ref ?? null,
    content_receipt_id: receiptId,
    result_receipt_id: receiptId,
    result_record_id: resultId,
    runtime_mcp_live_receipt_required: liveExit,
    runtime_mcp_live_result_required: liveExit,
    runtime_mcp_live_result_status: liveExit ? "rust_materialized" : null,
    runtime_mcp_live_result_materialized: liveExit,
    runtime_mcp_live_result_payload_hash: payloadHash,
    runtime_mcp_agentgres_operation_ref: operationRef,
    runtime_mcp_agent_state_root_before: stateRootBefore,
    runtime_mcp_agent_state_root_after: stateRootAfter,
    runtime_mcp_resulting_head: resultingHead,
    mutation_applied: ["mcp_import", "mcp_add", "mcp_remove", "mcp_enable", "mcp_disable"].includes(
      request.control_kind,
    ),
  };
  return {
    source: "rust_mcp_control_agent_state_update_api",
    backend: "rust_policy",
    schema_version: "ioi.runtime.mcp-control-agent-state-update.v1",
    object: "ioi.runtime_mcp_control_agent_state_update",
    status: "planned",
    operation_kind: `thread.${request.control_kind}`,
    thread_id: request.thread_id,
    agent_id: agent.id,
    updated_at: request.created_at,
    control,
    agent,
    receipt: receiptId
      ? liveExitReceipt({
          request,
          payload,
          agent,
          control,
          receiptId,
          operationRef,
          stateRootBefore,
          stateRootAfter,
          resultingHead,
          payloadHash,
        })
      : null,
    result: resultId
      ? liveExitResult({
          request,
          payload,
          agent,
          control,
          resultId,
          receiptId,
          operationRef,
          stateRootBefore,
          stateRootAfter,
          resultingHead,
          payloadHash,
        })
      : null,
  };
}

function harness(options = {}) {
  const calls = [];
  let agent = {
    id: "agent-one",
    cwd: "/workspace",
    runtimeControls: { approval_mode: "agent" },
    mcpRegistry: {
      servers: [
        server("mcp.docs", [
          { name: "search", side_effect_class: "read" },
          { name: "write", side_effect_class: "write" },
        ], {
          resources: [{ uri: "docs://index" }],
          prompts: [{ name: "summarize" }],
        }),
      ],
    },
  };
  const contextPolicyCore = options.contextPolicyCore ?? {
    validateMcpServers(request) {
      calls.push({ name: "validateMcpServers", request });
      const issues = request.servers.some((item) => item.invalid) ? [{ code: "invalid_server" }] : [];
      return {
        source: "rust_mcp_server_validation_api",
        ok: issues.length === 0,
        status: issues.length === 0 ? "pass" : "blocked",
        issues,
        warnings: [],
      };
    },
    planMcpManagerCatalogProjection(request) {
      calls.push({ name: "planMcpManagerCatalogProjection", request });
      const tools = request.servers.flatMap((item) =>
        (item.tools ?? item.allowed_tools ?? []).map((tool) => ({
          server_id: item.id,
          tool_name: tool.name ?? tool,
          stable_tool_id: `${item.id}.${tool.name ?? tool}`,
          side_effect_class: tool.side_effect_class ?? "read",
        })),
      );
      const resources = request.servers.flatMap((item) => item.resources ?? []);
      const prompts = request.servers.flatMap((item) => item.prompts ?? []);
      return {
        source: "rust_mcp_manager_catalog_projection_api",
        schema_version: "catalog.schema",
        object: "ioi.runtime_mcp_manager_catalog_projection",
        status: "projected",
        server_count: request.servers.length,
        tool_count: tools.length,
        enabled_tool_count: tools.length,
        resource_count: resources.length,
        prompt_count: prompts.length,
        servers: request.servers,
        tools,
        enabled_tools: tools,
        resources,
        prompts,
      };
    },
    planMcpManagerStatusProjection(request) {
      calls.push({ name: "planMcpManagerStatusProjection", request });
      return {
        source: "rust_mcp_manager_status_projection_api",
        schema_version: request.status_schema_version,
        object: "ioi.runtime_mcp_manager_status",
        status: request.validation.ok ? "ready" : "needs_review",
        server_count: request.servers.length,
        enabled_server_count: request.servers.filter((item) => item.enabled !== false).length,
        tool_count: request.tools.length,
        enabled_tool_count: request.enabled_tools.length,
        resource_count: request.resources.length,
        prompt_count: request.prompts.length,
        servers: request.servers,
        tools: request.tools,
        resources: request.resources,
        prompts: request.prompts,
        validation: {
          ...request.validation,
          server_count: request.servers.length,
          tool_count: request.tools.length,
          resource_count: request.resources.length,
          prompt_count: request.prompts.length,
        },
      };
    },
    planMcpControlAgentStateUpdate(request) {
      calls.push({ name: "planMcpControlAgentStateUpdate", request: cloneJson(request) });
      const record = planMcpControlAgentStateUpdate(request, agent);
      return typeof options.planRecordTransform === "function"
        ? options.planRecordTransform(record, request)
        : record;
    },
    executeRuntimeMcpLiveBackend(request) {
      calls.push({ name: "executeRuntimeMcpLiveBackend", request: cloneJson(request) });
      return typeof options.liveBackendTransform === "function"
        ? options.liveBackendTransform(request)
        : liveBackendExecutionObservation(request);
    },
    projectMcpLiveResultReplay(request) {
      calls.push({ name: "projectMcpLiveResultReplay", request: cloneJson(request) });
      const commitCall = [...calls]
        .reverse()
        .find((call) => call.name === "commitRuntimeMcpLiveResultState" && call.request.result_id === request.result_id);
      const result = commitCall?.request?.result;
      return {
        source: "rust_mcp_live_result_replay_api",
        backend: "rust_policy",
        schema_version: "ioi.runtime.mcp-live-result-replay.v1",
        object: "ioi.runtime_mcp_live_result_replay",
        status: "projected",
        result_count: result ? 1 : 0,
        results: result ? [cloneJson(result)] : [],
        result_ids: result?.id ? [result.id] : [],
        latest_result: result ? cloneJson(result) : null,
        replay_hash: `replay.${request.result_id}`,
      };
    },
  };
  const surface = createRuntimeMcpControlSurface({
    RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION: "invoke.schema",
    RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION: "status.schema",
    RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION: "validation.schema",
    runtimeError,
    contextPolicyCore,
    agentIdForThread: () => agent.id,
    eventStreamIdForThread: (threadId) => `events_${threadId}`,
    nowIso: () => "2026-06-06T06:30:00.000Z",
  });
  const store = {
    stateDir: "/runtime-state",
    agents: { set: failIfCalled("agents.set") },
    agentForThread: failIfCalled("agentForThread"),
    appendRuntimeEvent: failIfCalled("appendRuntimeEvent"),
    latestRuntimeEventSeq(eventStreamId) {
      calls.push({ name: "latestRuntimeEventSeq", eventStreamId });
      return 8;
    },
    listMcpServers: failIfCalled("listMcpServers"),
    mcpStatus: failIfCalled("mcpStatus"),
    threadForAgent: failIfCalled("threadForAgent"),
    validateMcp: failIfCalled("validateMcp"),
    commitRuntimeReceiptState(request) {
      calls.push({ name: "commitRuntimeReceiptState", request: cloneJson(request) });
      return {
        receipt_id: request.receipt_id,
        operation_kind: request.operation_kind,
        commit_hash: `receipt.commit.${request.receipt_id}`,
        written_record: { record_path: `receipts/${request.receipt_id}.json` },
      };
    },
    commitRuntimeMcpLiveResultState(request) {
      calls.push({ name: "commitRuntimeMcpLiveResultState", request: cloneJson(request) });
      return {
        result_id: request.result_id,
        operation_kind: request.operation_kind,
        commit_hash: `result.commit.${request.result_id}`,
        written_record: { record_path: `mcp-live-results/${request.result_id}.json` },
      };
    },
    writeAgent(record, operationKind) {
      calls.push({ name: "writeAgent", agent: cloneJson(record), operationKind });
      agent = cloneJson(record);
      return {
        agent_id: record.id,
        operation_kind: operationKind,
        commit_hash: `commit.${operationKind}`,
      };
    },
    ...options.store,
  };
  return { agent, calls, store, surface };
}

function assertNoRetiredDetailAliases(details) {
  for (const alias of [
    "threadId",
    "serverId",
    "toolId",
    "toolName",
    "controlKind",
    "operationKind",
    "expectedOperationKind",
    "requiredCore",
    "migrationTransportOnly",
  ]) {
    assert.equal(Object.hasOwn(details ?? {}, alias), false, `${alias} detail alias must be absent`);
  }
}

function assertRustCoreRequired(error, operation, operationKind) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "mcp_control_rust_core_required");
  assert.equal(error.details.boundary, "runtime.mcp_control");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.required_core, "rust_daemon_core");
  assert.equal(error.details.migration_transport_only, false);
  assertNoRetiredDetailAliases(error.details);
}

test("runtime MCP control surface keeps read-only status projection canonical", () => {
  const { agent, calls, surface } = harness();

  const status = surface.mcpStatusForAgent(agent);

  assert.equal(status.schema_version, "status.schema");
  assert.equal(status.object, "ioi.runtime_mcp_manager_status");
  assert.equal(status.status, "ready");
  assert.equal(status.server_count, 1);
  assert.equal(status.enabled_server_count, 1);
  assert.equal(status.tool_count, 2);
  assert.equal(status.enabled_tool_count, 2);
  assert.equal(status.resource_count, 1);
  assert.equal(status.prompt_count, 1);
  assert.equal(status.source, "rust_mcp_manager_status_projection_api");
  assert.equal(status.validation.source, "rust_mcp_server_validation_api");
  assert.equal(
    calls.find((call) => call.name === "planMcpManagerCatalogProjection")?.request.servers[0].id,
    "mcp.docs",
  );
  assert.deepEqual(status.tools.map((tool) => tool.stable_tool_id), [
    "mcp.docs.search",
    "mcp.docs.write",
  ]);
  assert.deepEqual(
    calls.find((call) => call.name === "validateMcpServers")?.request.servers.map((item) => item.id),
    ["mcp.docs"],
  );
  assert.equal(
    calls.find((call) => call.name === "planMcpManagerStatusProjection")?.request.enabled_tools.length,
    2,
  );
  assert.equal(Object.hasOwn(status.resources[0], "serverId"), false);
  assert.equal(Object.hasOwn(status, "schemaVersion"), false);
  assert.equal(Object.hasOwn(status, "serverCount"), false);
  assert.equal(Object.hasOwn(status, "enabledServerCount"), false);
});

test("runtime MCP control facade rejects retired threadId alias before JS lookup", async () => {
  const { store, surface } = harness();

  assert.throws(
    () => surface.importMcp(store, { threadId: "thread-agent-one", servers: [] }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "mcp_thread_required");
      assertNoRetiredDetailAliases(error.details);
      return true;
    },
  );
  assert.throws(
    () => surface.addMcpServer(store, { threadId: "thread-agent-one", id: "mcp.new" }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "mcp_thread_required");
      assertNoRetiredDetailAliases(error.details);
      return true;
    },
  );
  await assert.rejects(
    () => surface.invokeMcpTool(store, { threadId: "thread-retired", tool_id: "mcp.docs.search" }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "mcp_thread_required");
      assertNoRetiredDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime MCP control mutations plan in Rust and commit agent state without JS state mutation", () => {
  const { calls, store, surface } = harness();

  const imported = surface.importMcp(store, {
    thread_id: "thread-agent-one",
    servers: [server("mcp.imported", [{ name: "lookup" }], { serverId: "retired" })],
    mcpServers: [server("mcp.retired")],
  });
  const added = surface.addMcpServer(store, {
    thread_id: "thread-agent-one",
    id: "mcp.git",
    label: "Git",
    transport: "stdio",
    command: "npx",
    tools: [{ name: "diff" }],
    serverId: "mcp.retired",
  });
  const disabled = surface.setMcpServerEnabled(store, "mcp.git", false, {
    thread_id: "thread-agent-one",
  });
  const status = surface.recordThreadMcpStatus(store, "thread-agent-one", { status: "ready" });
  const validation = surface.validateThreadMcp(store, "thread-agent-one", {
    validation: { ok: true },
  });
  const appended = surface.appendThreadMcpControlEvent(store, {
    thread_id: "thread-agent-one",
    control_kind: "mcp_control",
  });
  const removed = surface.removeMcpServer(store, "mcp.git", { thread_id: "thread-agent-one" });

  assert.equal(imported.source, "rust_mcp_control_agent_state_update_api");
  assert.equal(added.operation_kind, "thread.mcp_add");
  assert.equal(disabled.control.enabled_server_count, 1);
  assert.equal(status.operation_kind, "thread.mcp_status");
  assert.equal(validation.operation_kind, "thread.mcp_validate");
  assert.equal(appended.operation_kind, "thread.mcp_control");
  assert.equal(removed.operation_kind, "thread.mcp_remove");
  assert.equal(added.commit.operation_kind, "thread.mcp_add");
  assert.equal(removed.commit.operation_kind, "thread.mcp_remove");

  const planCalls = calls.filter((call) => call.name === "planMcpControlAgentStateUpdate");
  assert.deepEqual(planCalls.map((call) => call.request.control_kind), [
    "mcp_import",
    "mcp_add",
    "mcp_disable",
    "mcp_status",
    "mcp_validate",
    "mcp_control",
    "mcp_remove",
  ]);
  assert.equal(planCalls[0].request.thread_id, "thread-agent-one");
  assert.equal(planCalls[0].request.agent_id, "agent-one");
  assert.equal(planCalls.every((call) => call.request.state_dir === "/runtime-state"), true);
  assert.equal(planCalls.every((call) => Object.hasOwn(call.request, "agent") === false), true);
  assert.equal(planCalls[0].request.request.servers[0].id, "mcp.imported");
  assert.equal(planCalls[1].request.request.server.id, "mcp.git");
  assert.equal(planCalls[2].request.request.server_id, "mcp.git");
  assert.equal(planCalls[0].request.seq, 9);
  assert.equal(planCalls[0].request.event_id, "mcp_control_thread-agent-one_mcp_import_2026-06-06T06_30_00.000Z");
  for (const call of planCalls) {
    const payload = JSON.stringify(call.request.request);
    assert.equal(payload.includes("threadId"), false);
    assert.equal(payload.includes("serverId"), false);
    assert.equal(payload.includes("mcpServers"), false);
    assert.equal(payload.includes("controlKind"), false);
  }
  assert.deepEqual(
    calls.filter((call) => call.name === "writeAgent").map((call) => call.operationKind),
    [
      "thread.mcp_import",
      "thread.mcp_add",
      "thread.mcp_disable",
      "thread.mcp_status",
      "thread.mcp_validate",
      "thread.mcp_control",
      "thread.mcp_remove",
    ],
  );
  assert.equal(calls.some((call) => call.name === "latestRuntimeEventSeq"), true);
});

test("runtime MCP control planner absence fails closed before JS state mutation", () => {
  const { store, surface } = harness({
    contextPolicyCore: {},
    store: {
      agentForThread: failIfCalled("agentForThread"),
      writeAgent: failIfCalled("writeAgent"),
    },
  });

  assert.throws(
    () => surface.addMcpServer(store, { thread_id: "thread-agent-one", id: "mcp.new" }),
    (error) => {
      assertRustCoreRequired(error, "add_mcp_server", "thread.mcp_add");
      return true;
    },
  );
});

test("runtime MCP live exits use Rust control admission before JS transport invocation", async () => {
  const { calls, store, surface } = harness();

  const invoked = await surface.invokeMcpTool(store, {
    thread_id: "thread-agent-one",
    server_id: "mcp.docs",
    tool_id: "mcp.docs.search",
    tool_name: "search",
    live_transport: "stdio",
    execution_mode: "live",
    timeout_ms: 2500,
    authority_grant_refs: ["wallet.network://grant/mcp/docs/search"],
    authority_receipt_refs: ["receipt://wallet.network/mcp/docs/search"],
    custody_ref: "ctee://workspace/public",
    containment_ref: "containment://mcp/docs",
    timeoutMs: 999,
  });
  const discovered = await surface.mcpStatusWithLiveDiscovery(
    store,
    { status: "ready", servers: [] },
    {
      thread_id: "thread-agent-one",
      server_id: "mcp.docs",
      live_transport: "stdio",
      execution_mode: "discovery",
      timeout_ms: 1500,
      authority_grant_refs: ["wallet.network://grant/mcp/docs/discovery"],
      authority_receipt_refs: ["receipt://wallet.network/mcp/docs/discovery"],
      custody_ref: "ctee://workspace/public",
      containment_ref: "containment://mcp/docs/discovery",
      liveDiscovery: true,
    },
  );

  assert.equal(invoked.operation_kind, "thread.mcp_invoke");
  assert.equal(invoked.control.control_kind, "mcp_invoke");
  assert.equal(invoked.commit.operation_kind, "thread.mcp_invoke");
  assert.equal(discovered.operation_kind, "thread.mcp_live_discovery");
  assert.equal(discovered.control.control_kind, "mcp_live_discovery");
  assert.equal(discovered.commit.operation_kind, "thread.mcp_live_discovery");

  const planCalls = calls.filter((call) => call.name === "planMcpControlAgentStateUpdate");
  assert.deepEqual(planCalls.map((call) => call.request.control_kind), ["mcp_invoke", "mcp_live_discovery"]);
  assert.equal(planCalls.every((call) => call.request.state_dir === "/runtime-state"), true);
  assert.equal(planCalls.every((call) => Object.hasOwn(call.request, "agent") === false), true);
  assert.deepEqual(planCalls.map((call) => call.request.request.timeout_ms), [2500, 1500]);
  assert.deepEqual(planCalls.map((call) => call.request.request.authority_grant_refs), [
    ["wallet.network://grant/mcp/docs/search"],
    ["wallet.network://grant/mcp/docs/discovery"],
  ]);
  assert.deepEqual(planCalls.map((call) => call.request.request.authority_receipt_refs), [
    ["receipt://wallet.network/mcp/docs/search"],
    ["receipt://wallet.network/mcp/docs/discovery"],
  ]);
  assert.deepEqual(planCalls.map((call) => call.request.request.custody_ref), [
    "ctee://workspace/public",
    "ctee://workspace/public",
  ]);
  assert.deepEqual(planCalls.map((call) => call.request.request.containment_ref), [
    "containment://mcp/docs",
    "containment://mcp/docs/discovery",
  ]);
  assert.equal(invoked.control.wallet_authority_required, true);
  assert.equal(invoked.control.wallet_authority_boundary, "wallet.network.mcp_external_exit");
  assert.equal(invoked.control.ctee_custody_required, true);
  assert.equal(invoked.control.transport_containment_required, true);
  assert.equal(invoked.control.runtime_mcp_live_result_status, "rust_materialized");
  assert.equal(invoked.control.runtime_mcp_live_result_materialized, true);
  assert.equal(
    invoked.control.runtime_mcp_live_result_payload_hash,
    `sha256:payload:mcp_invoke:${planCalls[0].request.event_id}`,
  );
  assert.deepEqual(invoked.control.authority_grant_refs, ["wallet.network://grant/mcp/docs/search"]);
  assert.equal(invoked.control.custody_ref, "ctee://workspace/public");
  assert.equal(invoked.control.containment_ref, "containment://mcp/docs");
  assert.equal(
    invoked.control.content_receipt_id,
    "receipt_runtime_mcp_live_exit_agent-one_mcp_invoke_mcp_control_thread-agent-one_mcp_invoke_2026-06-06T06_30_00.000Z",
  );
  assert.equal(invoked.receipt.id, invoked.control.content_receipt_id);
  assert.equal(invoked.receipt.details.rust_daemon_core_receipt_author, "runtime.mcp_control");
  assert.equal(
    invoked.receipt.details.runtime_mcp_agentgres_operation_ref,
    invoked.control.runtime_mcp_agentgres_operation_ref,
  );
  assert.equal(invoked.receipt.details.result_materialized, true);
  assert.equal(invoked.receipt.details.result_payload_hash, invoked.control.runtime_mcp_live_result_payload_hash);
  assert.equal(invoked.receipt.details.runtime_mcp_backend_execution_status, "rust_driver_contract_bound");
  assert.equal(invoked.receipt.details.runtime_mcp_backend_owner, "ioi_drivers::mcp::McpManager");
  assert.equal(invoked.receipt.details.runtime_mcp_backend_transport_owner, "ioi_drivers::mcp::transport::McpTransport");
  assert.equal(invoked.receipt.details.runtime_mcp_backend_method, "tools/call");
  assert.equal(invoked.receipt.details.runtime_mcp_backend_contract_required, true);
  assert.equal(invoked.receipt.details.js_backend_execution, false);
  assert.equal(invoked.receipt.details.js_transport_invocation, false);
  assert.equal(invoked.receipt.details.command_transport_fallback, false);
  assert.equal(invoked.receipt_commit.commit_hash, `receipt.commit.${invoked.receipt.id}`);
  assert.equal(
    invoked.control.result_record_id,
    "result_runtime_mcp_live_exit_agent-one_mcp_invoke_mcp_control_thread-agent-one_mcp_invoke_2026-06-06T06_30_00.000Z",
  );
  assert.equal(invoked.result.id, invoked.control.result_record_id);
  assert.equal(invoked.result.receipt_id, invoked.receipt.id);
  assert.equal(invoked.result.status, "rust_materialized");
  assert.equal(invoked.result.details.rust_daemon_core_result_author, "runtime.mcp_control");
  assert.equal(invoked.result.details.backend_materialization_status, "rust_driver_contract_bound");
  assert.equal(invoked.result.details.runtime_mcp_backend_execution_status, "rust_driver_contract_bound");
  assert.equal(invoked.result.details.runtime_mcp_live_backend_execution_status, "rust_driver_executed");
  assert.equal(invoked.result.details.runtime_mcp_live_backend_execution_required, true);
  assert.equal(invoked.result.details.runtime_mcp_backend_owner, "ioi_drivers::mcp::McpManager");
  assert.equal(invoked.result.details.runtime_mcp_backend_transport_owner, "ioi_drivers::mcp::transport::McpTransport");
  assert.equal(invoked.result.details.runtime_mcp_backend_method, "tools/call");
  assert.equal(invoked.result.details.runtime_mcp_backend_contract_required, true);
  assert.equal(invoked.result.details.result_materialized, true);
  assert.equal(invoked.result.details.payload_hash, invoked.control.runtime_mcp_live_result_payload_hash);
  assert.equal(invoked.result.payload.payload_hash, invoked.control.runtime_mcp_live_result_payload_hash);
  assert.equal(invoked.result.payload.backend_execution.schema_version, "ioi.runtime.mcp-backend-execution.v1");
  assert.equal(invoked.result.payload.backend_execution.status, "rust_driver_contract_bound");
  assert.equal(invoked.result.payload.backend_execution.owner, "ioi_drivers::mcp::McpManager");
  assert.equal(invoked.result.payload.backend_execution.transport_owner, "ioi_drivers::mcp::transport::McpTransport");
  assert.equal(invoked.result.payload.backend_execution.method, "tools/call");
  assert.equal(invoked.result.payload.backend_execution.js_backend_execution, false);
  assert.ok(invoked.result.evidence_refs.includes("runtime_mcp_live_backend_rust_driver_executed"));
  assert.equal(
    invoked.result.payload.protocol_result.structuredContent.object,
    "ioi.runtime_mcp_live_result_payload",
  );
  assert.equal(
    invoked.result.payload.protocol_result.structuredContent.backend_execution_status,
    "rust_driver_contract_bound",
  );
  assert.equal(invoked.result.payload.protocol_result.structuredContent.backend_method, "tools/call");
  assert.equal(invoked.result.details.js_backend_execution, false);
  assert.equal(invoked.result.details.js_transport_invocation, false);
  assert.equal(invoked.result.details.command_transport_fallback, false);
  assert.equal(invoked.result_commit.commit_hash, `result.commit.${invoked.result.id}`);
  assert.equal(invoked.live_backend_execution.status, "rust_driver_executed");
  assert.equal(invoked.live_backend_execution.backend_execution.status, "rust_driver_executed");
  assert.equal(invoked.result_replay.source, "rust_mcp_live_result_replay_api");
  assert.equal(invoked.result_replay.latest_result.id, invoked.result.id);
  assert.equal(invoked.result_projection.replay_hash, `replay.${invoked.result.id}`);
  assert.equal(discovered.receipt.id, discovered.control.content_receipt_id);
  assert.equal(discovered.receipt_commit.commit_hash, `receipt.commit.${discovered.receipt.id}`);
  assert.equal(discovered.result.id, discovered.control.result_record_id);
  assert.equal(discovered.result.receipt_id, discovered.receipt.id);
  assert.equal(discovered.receipt.details.runtime_mcp_backend_method, "tools/list");
  assert.equal(discovered.result.details.runtime_mcp_backend_method, "tools/list");
  assert.equal(discovered.result.payload.backend_execution.method, "tools/list");
  assert.equal(discovered.live_backend_execution.backend_execution.method, "tools/list");
  assert.equal(discovered.result_commit.commit_hash, `result.commit.${discovered.result.id}`);
  assert.equal(discovered.result_replay.latest_result.id, discovered.result.id);
  assert.equal(planCalls[0].request.request.tool_id, "mcp.docs.search");
  assert.equal(planCalls[0].request.request.tool_name, "search");
  assert.equal(planCalls[0].request.request.server_id, "mcp.docs");
  assert.equal(planCalls[0].request.request.live_transport, "stdio");
  assert.equal(planCalls[0].request.request.execution_mode, "live");
  assert.equal(planCalls[1].request.request.execution_mode, "discovery");
  assert.equal(Object.hasOwn(planCalls[1].request.request, "agent_id"), false);
  assert.equal(JSON.stringify(planCalls[0].request.request).includes("timeoutMs"), false);
  assert.equal(JSON.stringify(planCalls[0].request.request).includes("authorityGrantRefs"), false);
  assert.equal(JSON.stringify(planCalls[1].request.request).includes("liveDiscovery"), false);
  assert.deepEqual(
    calls.filter((call) => call.name === "writeAgent").map((call) => call.operationKind),
    ["thread.mcp_invoke", "thread.mcp_live_discovery"],
  );
  assert.deepEqual(
    calls.filter((call) => call.name === "commitRuntimeReceiptState").map((call) => call.request.operation_kind),
    ["runtime.mcp_live_exit.receipt.write", "runtime.mcp_live_exit.receipt.write"],
  );
  assert.deepEqual(
    calls.filter((call) => call.name === "commitRuntimeMcpLiveResultState").map((call) => call.request.operation_kind),
    ["runtime.mcp_live_exit.result.write", "runtime.mcp_live_exit.result.write"],
  );
  const replayCalls = calls.filter((call) => call.name === "projectMcpLiveResultReplay");
  const backendCalls = calls.filter((call) => call.name === "executeRuntimeMcpLiveBackend");
  assert.deepEqual(backendCalls.map((call) => call.request.schema_version), [
    "ioi.runtime.mcp-live-backend-execution-request.v1",
    "ioi.runtime.mcp-live-backend-execution-request.v1",
  ]);
  assert.deepEqual(backendCalls.map((call) => call.request.control_kind), ["mcp_invoke", "mcp_live_discovery"]);
  assert.deepEqual(backendCalls.map((call) => call.request.backend_execution.status), [
    "rust_driver_contract_bound",
    "rust_driver_contract_bound",
  ]);
  assert.deepEqual(backendCalls.map((call) => call.request.backend_execution.owner), [
    "ioi_drivers::mcp::McpManager",
    "ioi_drivers::mcp::McpManager",
  ]);
  assert.equal(backendCalls[0].request.planned_result.id, invoked.control.result_record_id);
  assert.equal(backendCalls[0].request.receipt.id, invoked.receipt.id);
  assert.equal(backendCalls[0].request.arguments.constructor, Object);
  assert.deepEqual(replayCalls.map((call) => call.request.state_dir), ["/runtime-state", "/runtime-state"]);
  assert.deepEqual(replayCalls.map((call) => call.request.result_id), [invoked.result.id, discovered.result.id]);
  assert.deepEqual(replayCalls.map((call) => call.request.receipt_id), [invoked.receipt.id, discovered.receipt.id]);
  assert.deepEqual(replayCalls.map((call) => call.request.thread_id), ["thread-agent-one", "thread-agent-one"]);
  assert.deepEqual(replayCalls.map((call) => call.request.agent_id), ["agent-one", "agent-one"]);
  assert.deepEqual(replayCalls.map((call) => call.request.control_kind), ["mcp_invoke", "mcp_live_discovery"]);
  assert.deepEqual(
    calls
      .filter((call) =>
        [
          "commitRuntimeReceiptState",
          "executeRuntimeMcpLiveBackend",
          "commitRuntimeMcpLiveResultState",
          "projectMcpLiveResultReplay",
          "writeAgent",
        ].includes(call.name)
      )
      .map((call) => call.name),
    [
      "commitRuntimeReceiptState",
      "executeRuntimeMcpLiveBackend",
      "commitRuntimeMcpLiveResultState",
      "projectMcpLiveResultReplay",
      "writeAgent",
      "commitRuntimeReceiptState",
      "executeRuntimeMcpLiveBackend",
      "commitRuntimeMcpLiveResultState",
      "projectMcpLiveResultReplay",
      "writeAgent",
    ],
  );
});

test("runtime MCP live exits reject pending Rust transport result materialization", async () => {
  const { calls, store, surface } = harness({
    planRecordTransform(record) {
      const next = cloneJson(record);
      next.result.status = "admitted_pending_rust_transport";
      next.result.evidence_refs = next.result.evidence_refs
        .filter((ref) => ref !== "runtime_mcp_live_result_payload_rust_materialized");
      next.result.evidence_refs.push("runtime_mcp_transport_backend_pending");
      next.result.details.result_materialized = false;
      next.result.details.backend_materialization_status = "pending_rust_transport_backend";
      next.result.details.payload_hash = null;
      next.result.details.result_payload_hash = null;
      return next;
    },
  });

  await assert.rejects(
    () =>
      surface.invokeMcpTool(store, {
        thread_id: "thread-agent-one",
        server_id: "mcp.docs",
        tool_id: "mcp.docs.search",
        tool_name: "search",
        live_transport: "stdio",
        execution_mode: "live",
        authority_grant_refs: ["wallet.network://grant/mcp/docs/search"],
        authority_receipt_refs: ["receipt://wallet.network/mcp/docs/search"],
        custody_ref: "ctee://workspace/public",
        containment_ref: "containment://mcp/docs",
    }),
    (error) => {
      assert.equal(error.code, "mcp_control_live_exit_result_binding_invalid");
      assert.ok(error.details.missing.includes("admitted_pending_rust_transport_retired"));
      assert.ok(error.details.missing.includes("runtime_mcp_transport_backend_pending_retired"));
      assert.ok(error.details.missing.includes("runtime_mcp_live_result_payload_rust_materialized"));
      assert.ok(error.details.missing.includes("payload_hash"));
      return true;
    },
  );
  assert.deepEqual(
    calls.filter((call) => call.name === "commitRuntimeMcpLiveResultState"),
    [],
  );
});

test("runtime MCP live exits reject missing Rust MCP backend driver contract", async () => {
  const { calls, store, surface } = harness({
    planRecordTransform(record) {
      const next = cloneJson(record);
      next.receipt.evidence_refs = next.receipt.evidence_refs.filter(
        (ref) => ref !== "runtime_mcp_backend_execution_rust_driver_bound",
      );
      delete next.receipt.details.runtime_mcp_backend_execution_status;
      delete next.receipt.details.runtime_mcp_backend_owner;
      delete next.receipt.details.runtime_mcp_backend_transport_owner;
      delete next.receipt.details.runtime_mcp_backend_method;
      delete next.receipt.details.runtime_mcp_backend_contract_required;
      delete next.receipt.details.js_backend_execution;
      next.result.evidence_refs = next.result.evidence_refs.filter(
        (ref) => ref !== "runtime_mcp_backend_execution_rust_driver_bound",
      );
      delete next.result.payload.backend_execution;
      delete next.result.details.runtime_mcp_backend_execution_status;
      delete next.result.details.runtime_mcp_backend_owner;
      delete next.result.details.runtime_mcp_backend_transport_owner;
      delete next.result.details.runtime_mcp_backend_method;
      delete next.result.details.runtime_mcp_backend_contract_required;
      delete next.result.details.js_backend_execution;
      next.result.details.backend_materialization_status = "rust_materialized";
      return next;
    },
  });

  await assert.rejects(
    () =>
      surface.invokeMcpTool(store, {
        thread_id: "thread-agent-one",
        server_id: "mcp.docs",
        tool_id: "mcp.docs.search",
        tool_name: "search",
        live_transport: "stdio",
        execution_mode: "live",
        authority_grant_refs: ["wallet.network://grant/mcp/docs/search"],
        authority_receipt_refs: ["receipt://wallet.network/mcp/docs/search"],
        custody_ref: "ctee://workspace/public",
        containment_ref: "containment://mcp/docs",
      }),
    (error) => {
      assert.equal(error.code, "mcp_control_live_exit_receipt_binding_invalid");
      assert.ok(error.details.missing.includes("runtime_mcp_backend_execution_rust_driver_bound"));
      assert.ok(error.details.missing.includes("runtime_mcp_backend_execution_status"));
      assert.ok(error.details.missing.includes("runtime_mcp_backend_owner"));
      assert.ok(error.details.missing.includes("runtime_mcp_backend_transport_owner"));
      assert.ok(error.details.missing.includes("runtime_mcp_backend_contract_required"));
      assert.ok(error.details.missing.includes("js_backend_execution_false"));
      return true;
    },
  );
  assert.deepEqual(
    calls.filter((call) => call.name === "commitRuntimeMcpLiveResultState"),
    [],
  );
});

test("runtime MCP live exits require Rust live backend execution before result commit", async () => {
  const { calls, store, surface } = harness({
    contextPolicyCore: {
      planMcpControlAgentStateUpdate(request) {
        calls.push({ name: "planMcpControlAgentStateUpdate", request: cloneJson(request) });
        return planMcpControlAgentStateUpdate(request, {
          id: "agent-one",
          cwd: "/workspace",
          mcpRegistry: { servers: [server("mcp.docs")] },
        });
      },
      projectMcpLiveResultReplay: failIfCalled("projectMcpLiveResultReplay"),
    },
    store: {
      writeAgent: failIfCalled("writeAgent"),
    },
  });

  await assert.rejects(
    () =>
      surface.invokeMcpTool(store, {
        thread_id: "thread-agent-one",
        server_id: "mcp.docs",
        tool_id: "mcp.docs.search",
        tool_name: "search",
        live_transport: "stdio",
        execution_mode: "live",
        authority_grant_refs: ["wallet.network://grant/mcp/docs/search"],
        authority_receipt_refs: ["receipt://wallet.network/mcp/docs/search"],
        custody_ref: "ctee://workspace/public",
        containment_ref: "containment://mcp/docs",
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "mcp_control_live_backend_execution_required");
      assert.equal(error.details.required_policy_api, "executeRuntimeMcpLiveBackend");
      return true;
    },
  );
  assert.deepEqual(
    calls.filter((call) => call.name === "commitRuntimeMcpLiveResultState"),
    [],
  );
});

test("runtime MCP live exits fail closed without wallet authority refs", async () => {
  const { store, surface } = harness();

  await assert.rejects(
    () =>
      surface.invokeMcpTool(store, {
        thread_id: "thread-agent-one",
        server_id: "mcp.docs",
        tool_id: "mcp.docs.search",
        tool_name: "search",
        live_transport: "stdio",
        execution_mode: "live",
      }),
    (error) => {
      assert.equal(error.code, "mcp_control_live_exit_wallet_authority_required");
      return true;
    },
  );
});

test("runtime MCP live exits fail closed without custody and containment refs", async () => {
  const { store, surface } = harness();

  await assert.rejects(
    () =>
      surface.invokeMcpTool(store, {
        thread_id: "thread-agent-one",
        server_id: "mcp.docs",
        tool_id: "mcp.docs.search",
        tool_name: "search",
        live_transport: "stdio",
        execution_mode: "live",
        authority_grant_refs: ["wallet.network://grant/mcp/docs/search"],
        authority_receipt_refs: ["receipt://wallet.network/mcp/docs/search"],
      }),
    (error) => {
      assert.equal(error.code, "mcp_control_live_exit_custody_required");
      return true;
    },
  );

  await assert.rejects(
    () =>
      surface.invokeMcpTool(store, {
        thread_id: "thread-agent-one",
        server_id: "mcp.docs",
        tool_id: "mcp.docs.search",
        tool_name: "search",
        live_transport: "stdio",
        execution_mode: "live",
        authority_grant_refs: ["wallet.network://grant/mcp/docs/search"],
        authority_receipt_refs: ["receipt://wallet.network/mcp/docs/search"],
        custody_ref: "ctee://workspace/public",
      }),
    (error) => {
      assert.equal(error.code, "mcp_control_live_exit_containment_required");
      return true;
    },
  );
});

test("runtime MCP live exits fail closed without Rust receipt-state commit", async () => {
  const missingReceiptCore = {
    planMcpControlAgentStateUpdate(request) {
      const planned = planMcpControlAgentStateUpdate(request, {
        id: "agent-one",
        cwd: "/workspace",
        mcpRegistry: { servers: [server("mcp.docs")] },
      });
      delete planned.receipt;
      return planned;
    },
  };
  const { store: missingReceiptStore, surface: missingReceiptSurface } = harness({
    contextPolicyCore: missingReceiptCore,
  });

  await assert.rejects(
    () =>
      missingReceiptSurface.invokeMcpTool(missingReceiptStore, {
        thread_id: "thread-agent-one",
        server_id: "mcp.docs",
        tool_id: "mcp.docs.search",
        authority_grant_refs: ["wallet.network://grant/mcp/docs/search"],
        authority_receipt_refs: ["receipt://wallet.network/mcp/docs/search"],
        custody_ref: "ctee://workspace/public",
        containment_ref: "containment://mcp/docs",
      }),
    (error) => {
      assert.equal(error.code, "mcp_control_live_exit_receipt_required");
      return true;
    },
  );

  const { store: missingCommitStore, surface: missingCommitSurface } = harness();
  delete missingCommitStore.commitRuntimeReceiptState;

  await assert.rejects(
    () =>
      missingCommitSurface.invokeMcpTool(missingCommitStore, {
        thread_id: "thread-agent-one",
        server_id: "mcp.docs",
        tool_id: "mcp.docs.search",
        authority_grant_refs: ["wallet.network://grant/mcp/docs/search"],
        authority_receipt_refs: ["receipt://wallet.network/mcp/docs/search"],
        custody_ref: "ctee://workspace/public",
        containment_ref: "containment://mcp/docs",
      }),
    (error) => {
      assert.equal(error.code, "mcp_control_live_exit_receipt_state_commit_required");
      return true;
    },
  );
});

test("runtime MCP live exits fail closed without Rust result-state commit", async () => {
  const missingResultCore = {
    planMcpControlAgentStateUpdate(request) {
      const planned = planMcpControlAgentStateUpdate(request, {
        id: "agent-one",
        cwd: "/workspace",
        mcpRegistry: { servers: [server("mcp.docs")] },
      });
      delete planned.result;
      return planned;
    },
  };
  const { store: missingResultStore, surface: missingResultSurface } = harness({
    contextPolicyCore: missingResultCore,
  });

  await assert.rejects(
    () =>
      missingResultSurface.invokeMcpTool(missingResultStore, {
        thread_id: "thread-agent-one",
        server_id: "mcp.docs",
        tool_id: "mcp.docs.search",
        authority_grant_refs: ["wallet.network://grant/mcp/docs/search"],
        authority_receipt_refs: ["receipt://wallet.network/mcp/docs/search"],
        custody_ref: "ctee://workspace/public",
        containment_ref: "containment://mcp/docs",
      }),
    (error) => {
      assert.equal(error.code, "mcp_control_live_exit_result_required");
      return true;
    },
  );

  const { store: missingCommitStore, surface: missingCommitSurface } = harness();
  delete missingCommitStore.commitRuntimeMcpLiveResultState;

  await assert.rejects(
    () =>
      missingCommitSurface.invokeMcpTool(missingCommitStore, {
        thread_id: "thread-agent-one",
        server_id: "mcp.docs",
        tool_id: "mcp.docs.search",
        authority_grant_refs: ["wallet.network://grant/mcp/docs/search"],
        authority_receipt_refs: ["receipt://wallet.network/mcp/docs/search"],
        custody_ref: "ctee://workspace/public",
        containment_ref: "containment://mcp/docs",
      }),
    (error) => {
      assert.equal(error.code, "mcp_control_live_exit_result_state_commit_required");
      return true;
    },
  );
});

test("runtime MCP live exits fail closed without Rust result replay projection", async () => {
  const replaylessCore = {
    planMcpControlAgentStateUpdate(request) {
      return planMcpControlAgentStateUpdate(request, {
        id: "agent-one",
        cwd: "/workspace",
        mcpRegistry: { servers: [server("mcp.docs")] },
      });
    },
    executeRuntimeMcpLiveBackend(request) {
      return liveBackendExecutionObservation(request);
    },
  };
  const { store, surface } = harness({
    contextPolicyCore: replaylessCore,
    store: {
      writeAgent: failIfCalled("writeAgent"),
    },
  });

  await assert.rejects(
    () =>
      surface.invokeMcpTool(store, {
        thread_id: "thread-agent-one",
        server_id: "mcp.docs",
        tool_id: "mcp.docs.search",
        authority_grant_refs: ["wallet.network://grant/mcp/docs/search"],
        authority_receipt_refs: ["receipt://wallet.network/mcp/docs/search"],
        custody_ref: "ctee://workspace/public",
        containment_ref: "containment://mcp/docs",
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "mcp_control_live_exit_result_replay_required");
      assert.equal(error.details.required_policy_api, "projectMcpLiveResultReplay");
      return true;
    },
  );
});

test("runtime MCP live exits fail closed when Rust control planner is missing", async () => {
  const { store, surface } = harness({
    contextPolicyCore: {},
    store: {
      agentForThread: failIfCalled("agentForThread"),
      writeAgent: failIfCalled("writeAgent"),
    },
  });

  await assert.rejects(
    () =>
      surface.invokeMcpTool(store, {
        thread_id: "thread-agent-one",
        tool_id: "mcp.docs.search",
      }),
    (error) => {
      assertRustCoreRequired(error, "invoke_mcp_tool", "thread.mcp_invoke");
      assert.equal(error.details.thread_id, "thread-agent-one");
      return true;
    },
  );
  await assert.rejects(
    () =>
      surface.mcpStatusWithLiveDiscovery(
        store,
        { status: "ready", servers: [] },
        { thread_id: "thread-agent-one", live_discovery: true },
      ),
    (error) => {
      assertRustCoreRequired(error, "mcp_live_discovery", "thread.mcp_live_discovery");
      assert.equal(error.details.thread_id, "thread-agent-one");
      return true;
    },
  );
});
