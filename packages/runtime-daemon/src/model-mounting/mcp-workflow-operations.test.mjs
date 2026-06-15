import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

const MCP_WORKFLOW_RETIRED_JS_PROOF_FIELDS = [
  "js_registry_mutation",
  "js_transport_invocation",
  "js_route_test",
  "js_mcp_tool_invocation",
  "js_receipt_gate_dispatch",
  "js_model_invocation",
];

const MCP_WORKFLOW_RETIRED_FALLBACK_FIELDS = [
  "command_transport_fallback",
  "binary_bridge_fallback",
  "compatibility_fallback",
  "legacy_js_result_fallback",
];

const MCP_WORKFLOW_RETIRED_RESULT_PAYLOAD_FIELDS = [
  "js_result_synthesis",
  "command_transport_fallback",
  "binary_bridge_fallback",
  "compatibility_fallback",
];

function assertRetiredFieldsAbsent(value, fields) {
  for (const field of fields) {
    assert.equal(Object.hasOwn(value, field), false);
  }
}

function fakeState() {
  return {
    authorizations: [],
    mcpServers: new Map(),
    mcpWorkflowRequests: [],
    modelInvocations: [],
    readProjectionRequests: [],
    recordStateCommits: [],
    receiptStateCommits: [],
    receipts: [],
    routeTests: [],
    writes: [],
    walletAuthority: {
      resolved: [],
      resolveVaultRef(value) {
        this.resolved.push(value);
      },
    },
    authorize(authorization, scope) {
      this.authorizations.push([authorization, scope]);
      return { grantId: `grant.${scope}` };
    },
    invokeMcpTool(args) {
      return invokeMcpTool(this, args);
    },
    async invokeModel({ requiredScope, kind, body }) {
      this.modelInvocations.push({ requiredScope, kind, body });
      return {
        kind,
        body,
        receipt: { id: "receipt.model" },
        routeReceipt: { id: "receipt.route" },
        outputText: `invoked:${requiredScope}`,
      };
    },
    normalizeMcpServer(label, config) {
      return normalizeMcpServer(this, label, config);
    },
    nowIso() {
      return "2026-06-04T02:00:00.000Z";
    },
    receipt(kind, payload) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, payload };
      this.receipts.push(receipt);
      return receipt;
    },
    persistRustAuthoredReceiptWithCommit(receipt) {
      this.receipts.push(JSON.parse(JSON.stringify(receipt)));
      const commit = {
        receipt_id: receipt.id,
        commit_hash: `sha256:receipt-commit:${receipt.id}`,
        written_record: receipt,
        storage_record: {
          object_ref: `agentgres://model-mounting/receipts/${receipt.id}`,
          content_hash: `sha256:receipt-content:${receipt.id}`,
          admission: {
            admission_hash: `sha256:receipt-admission:${receipt.id}`,
          },
        },
      };
      this.receiptStateCommits.push({ receipt_id: receipt.id, receipt, commit });
      return { receipt, commit };
    },
    planModelMountMcpWorkflow(request) {
      this.mcpWorkflowRequests.push(JSON.parse(JSON.stringify(request)));
      return mcpWorkflowPlan(request);
    },
    readProjectionFacade: {
      mcpServers(state) {
        state.readProjectionRequests.push({ projection_kind: "mcp_servers" });
        return [{ id: "mcp.Projected", label: "Projected", status: "registered" }];
      },
    },
    testRoute(routeId, body) {
      this.routeTests.push([routeId, body]);
      return { routeId, selectedModel: body.model ?? null };
    },
    validateReceiptGate(body) {
      return { node: "Receipt Gate", status: "passed", receiptId: body.receipt_id ?? body.receiptId };
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(JSON.parse(JSON.stringify(request)));
      return {
        record_id: request.record_id,
        commit_hash: `sha256:commit:${request.operation_kind}:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
          admission: {
            admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
          },
        },
      };
    },
  };
}

function mcpWorkflowPlan(request) {
  const operationKind = request.operation_kind;
  if (
    ["model_mount.mcp_tool.invoke", "model_mount.workflow_node.execute"].includes(operationKind) &&
    (!Array.isArray(request.authority_grant_refs) ||
      request.authority_grant_refs.length === 0 ||
      !Array.isArray(request.authority_receipt_refs) ||
      request.authority_receipt_refs.length === 0)
  ) {
    const error = new Error("Rust MCP workflow external exits require wallet authority refs.");
    error.status = 403;
    error.code = "model_mount_mcp_external_exit_wallet_authority_required";
    error.details = {
      rust_core_boundary: "model_mount.mcp_workflow",
      operation_kind: operationKind,
    };
    throw error;
  }
  if (["model_mount.mcp_tool.invoke", "model_mount.workflow_node.execute"].includes(operationKind) && !request.custody_ref) {
    const error = new Error("Rust MCP workflow external exits require cTEE custody refs.");
    error.status = 403;
    error.code = "model_mount_mcp_external_exit_custody_required";
    error.details = {
      rust_core_boundary: "model_mount.mcp_workflow",
      operation_kind: operationKind,
    };
    throw error;
  }
  if (
    ["model_mount.mcp_tool.invoke", "model_mount.workflow_node.execute"].includes(operationKind) &&
    !request.containment_ref
  ) {
    const error = new Error("Rust MCP workflow external exits require transport containment refs.");
    error.status = 403;
    error.code = "model_mount_mcp_external_exit_containment_required";
    error.details = {
      rust_core_boundary: "model_mount.mcp_workflow",
      operation_kind: operationKind,
    };
    throw error;
  }
  const recordDir = operationKind === "model_mount.mcp_server.import" ||
    operationKind === "model_mount.mcp_server.ephemeral_register"
    ? "mcp-servers"
    : "mcp-workflow-controls";
  const recordId = `${operationKind.replace(/[^a-z0-9]+/gi, "_")}.alpha`;
  const serverIds = operationKind === "model_mount.mcp_server.import"
    ? Object.keys(request.body.mcp_servers ?? request.body.servers ?? {}).map((label) => `mcp.${label.toLowerCase()}`)
    : operationKind === "model_mount.mcp_server.ephemeral_register"
      ? ["mcp.search"]
      : [];
  const executionOperation = ["model_mount.mcp_tool.invoke", "model_mount.workflow_node.execute"].includes(
    operationKind,
  );
  const resultPayload = executionOperation
    ? {
      schema_version: "ioi.model_mount.mcp_result.v1",
      payload_kind: operationKind === "model_mount.mcp_tool.invoke" ? "mcp_tool_result" : "workflow_node_result",
      materialization_status: "rust_materialized",
      materialization_owner: "rust_daemon_core.model_mount.mcp_workflow",
      content_receipt_id: `receipt.${recordId}`,
      result_receipt_id: `receipt.${recordId}`,
      is_error: false,
    }
    : undefined;
  const resultPayloadHash = executionOperation ? `sha256:result-payload:${recordId}` : undefined;
  const publicResponse = {
    status: operationKind.includes("mcp_server") ? "committed" : "admitted",
    operation_kind: operationKind,
    server_ids: serverIds,
    tool_receipt_ids: [],
    content_receipt_id: executionOperation
      ? `receipt.${recordId}`
      : undefined,
    result_receipt_id: executionOperation
      ? `receipt.${recordId}`
      : undefined,
    content_receipt_required: executionOperation || undefined,
    result_payload: resultPayload,
    result_payload_hash: resultPayloadHash,
    model_mount_mcp_result_materialized: executionOperation ? true : undefined,
    model_mount_mcp_result_materialization_status: executionOperation ? "rust_materialized" : undefined,
    result_materialization_owner: executionOperation
      ? "rust_daemon_core.model_mount.mcp_workflow"
      : undefined,
    result_payload_replay_owner: executionOperation
      ? "rust_daemon_core.model_mount.read_projection.mcp_workflow_result"
      : undefined,
    transport_execution_status: operationKind === "model_mount.mcp_tool.invoke" ? "rust_admitted" : undefined,
    rust_transport_execution_admitted: operationKind === "model_mount.mcp_tool.invoke" || undefined,
    transport_execution_owner: operationKind === "model_mount.mcp_tool.invoke"
      ? "rust_daemon_core.model_mount.mcp_workflow"
      : undefined,
    execution_status: operationKind === "model_mount.workflow_node.execute" ? "rust_admitted" : undefined,
    rust_step_module_dispatch_admitted: operationKind === "model_mount.workflow_node.execute" || undefined,
    workflow_execution_owner: operationKind === "model_mount.workflow_node.execute"
      ? "rust_daemon_core.model_mount.mcp_workflow"
      : undefined,
    step_module_dispatch_owner: executionOperation
      ? "rust_daemon_core.step_module_router"
      : undefined,
    agentgres_admission_required: executionOperation || undefined,
    receipt_state_root_binding_required: executionOperation || undefined,
    server_id: request.body.server_id ?? null,
    tool: request.body.tool ?? null,
    workflow_node_id: request.body.workflow_node_id ?? null,
  };
  const record = {
    id: recordId,
    object: "ioi.model_mount_mcp_workflow",
    operation_kind: operationKind,
    rust_core_boundary: "model_mount.mcp_workflow",
    details: {
      server_ids: serverIds,
      servers: serverIds.map((id) => ({ id, label: id, status: "registered" })),
      result_payload: resultPayload,
      result_payload_hash: resultPayloadHash,
      model_mount_mcp_result_materialized: executionOperation ? true : undefined,
      model_mount_mcp_result_materialization_status: executionOperation ? "rust_materialized" : undefined,
      result_materialization_owner: executionOperation
        ? "rust_daemon_core.model_mount.mcp_workflow"
        : undefined,
      result_payload_replay_owner: executionOperation
        ? "rust_daemon_core.model_mount.read_projection.mcp_workflow_result"
        : undefined,
      wallet_authority_required: executionOperation,
      wallet_authority_boundary: executionOperation
        ? "wallet.network.mcp_external_exit"
        : null,
      ctee_custody_required: executionOperation,
      transport_containment_required: executionOperation,
      authority_grant_refs: request.authority_grant_refs ?? [],
      authority_receipt_refs: request.authority_receipt_refs ?? [],
      custody_ref: request.custody_ref ?? null,
      containment_ref: request.containment_ref ?? null,
    },
    receipt_id: `receipt.${recordId}`,
    receipt_refs: [`receipt.${recordId}`],
    workflow_hash: `sha256:workflow:${recordId}`,
    authority_hash: `sha256:authority:${recordId}`,
	    evidence_refs: [
	      "rust_daemon_core_model_mount_mcp_workflow",
	      "agentgres_mcp_workflow_truth_required",
	      "model_mount_mcp_workflow_js_facade_retired",
	      "model_mount_mcp_result_payload_rust_materialized",
	    ],
	  };
  const executionReceipt = executionOperation
    ? {
      schemaVersion: "ioi.model_mount.mcp_workflow_receipt.v1",
      id: `receipt.${recordId}`,
      kind: operationKind === "model_mount.mcp_tool.invoke" ? "mcp_tool_invocation" : "workflow_node_execution",
      redaction: "redacted",
      summary: "Rust model_mount MCP execution admitted",
      createdAt: request.generated_at,
      evidenceRefs: [
	        "rust_model_mount_core",
	        "rust_daemon_core_model_mount_mcp_workflow",
	        "model_mount_mcp_execution_content_receipt_rust_owned",
	        "model_mount_mcp_result_payload_rust_materialized",
	        "agentgres_mcp_content_receipt_truth_required",
	      ],
	      details: {
	        rust_daemon_core_receipt_author: "model_mount.mcp_workflow",
	        operation_kind: operationKind,
	        model_mount_mcp_workflow_ref: `model_mount://mcp_workflow/${recordId}`,
	        model_mount_mcp_content_receipt_id: `receipt.${recordId}`,
	        model_mount_mcp_content_hash: `sha256:content:${recordId}`,
        model_mount_mcp_result_materialized: true,
        model_mount_mcp_result_materialization_status: "rust_materialized",
        result_materialization_owner: "rust_daemon_core.model_mount.mcp_workflow",
        result_payload: resultPayload,
        result_payload_hash: resultPayloadHash,
        result_payload_replay_owner: "rust_daemon_core.model_mount.read_projection.mcp_workflow_result",
        workflow_hash: record.workflow_hash,
        authority_hash: record.authority_hash,
        custody_ref: request.custody_ref ?? null,
        containment_ref: request.containment_ref ?? null,
        model_mount_agentgres_operation_ref: `agentgres://model-mounting/mcp-workflow/${recordId}`,
        model_mount_agentgres_state_root_before: `sha256:state-before:${recordId}`,
        model_mount_agentgres_state_root_after: `sha256:state-after:${recordId}`,
        model_mount_agentgres_resulting_head: `agentgres://model-mounting/mcp-workflow/head/${recordId}`,
        model_mount_step_module_result: {
          status: "admitted",
          agentgres_operation_refs: [`agentgres://model-mounting/mcp-workflow/${recordId}`],
          state_root_after: `sha256:state-after:${recordId}`,
          resulting_head: `agentgres://model-mounting/mcp-workflow/head/${recordId}`,
          content_hash: `sha256:content:${recordId}`,
          result_payload_hash: resultPayloadHash,
          result_materialized: true,
          result_materialization_status: "rust_materialized",
          result_materialization_owner: "rust_daemon_core.model_mount.mcp_workflow",
        },
      },
    }
    : null;
  return {
    status: publicResponse.status,
    source: "rust_daemon_core.model_mount.mcp_workflow",
    record_dir: recordDir,
    record_id: recordId,
    record,
    receipt: executionReceipt,
    public_response: publicResponse,
    operation_kind: operationKind,
    rust_core_boundary: "model_mount.mcp_workflow",
    receipt_refs: record.receipt_refs,
    authority_grant_refs: request.authority_grant_refs ?? [],
    authority_receipt_refs: request.authority_receipt_refs ?? [],
    evidence_refs: record.evidence_refs,
    workflow_hash: record.workflow_hash,
    authority_hash: record.authority_hash,
  };
}

const deps = {
  normalizeScopes(value, fallback = []) {
    return Array.isArray(value) ? value : fallback;
  },
  notFound(message, details) {
    const error = new Error(message);
    error.status = 404;
    error.details = details;
    return error;
  },
  publicMcpServer(server) {
    return { id: server.id, label: server.label, status: server.status };
  },
  requiredString(value, field) {
    if (typeof value !== "string" || value.length === 0) throw new Error(`${field} required`);
    return value;
  },
  runtimeError({ status, code, message, details }) {
    const error = new Error(message);
    error.status = status;
    error.code = code;
    error.details = details;
    return error;
  },
  safeId(value) {
    return String(value).replace(/[^a-z0-9]+/gi, "_");
  },
  secretRedaction: "[REDACTED]",
  stableHash(value) {
    return `hash:${JSON.stringify(value)}`;
  },
  workflowMemoryOptionsFromBody(body) {
    return body.memory ?? null;
  },
  workflowMemoryWriteBlockReason(memory) {
    return memory?.write === true ? "write_not_allowed" : null;
  },
};

function compileEphemeralMcpIntegrations(state, args) {
  return ModelMountingState.prototype.compileEphemeralMcpIntegrations.call(state, args);
}

function executeWorkflowNode(state, args) {
  return ModelMountingState.prototype.executeWorkflowNode.call(state, args);
}

function importMcpJson(state, body = {}) {
  return ModelMountingState.prototype.importMcpJson.call(state, body);
}

function invokeMcpTool(state, args) {
  return ModelMountingState.prototype.invokeMcpTool.call(state, args);
}

function listMcpServers(state) {
  return ModelMountingState.prototype.listMcpServers.call(state);
}

function normalizeMcpServer(state, label, config = {}) {
  return ModelMountingState.prototype.normalizeMcpServer.call(state, label, config);
}

test("normalizeMcpServer redacts headers and requires vault refs", () => {
  const state = fakeState();

  const server = normalizeMcpServer(
    state,
    "Docs MCP",
    {
      url: "https://example.test/mcp",
      headers: { Authorization: "vault://mcp/docs/token" },
      tools: { search: {}, read: {} },
    },
  );

  assert.equal(server.id, "mcp.docs.mcp");
  assert.equal(server.transport, "remote");
  assert.deepEqual(server.allowedTools, ["search", "read"]);
  assert.deepEqual(server.secretRefs, { Authorization: "vault://mcp.docs.mcp/authorization" });
  assert.deepEqual(server.redactedHeaders, { Authorization: "[REDACTED]" });
  assert.deepEqual(state.walletAuthority.resolved, ["vault://mcp/docs/token"]);

  assert.throws(
    () => normalizeMcpServer(state, "Bad", { headers: { token: "plaintext" } }),
    (error) => error.status === 403 && error.code === "policy",
  );
});

test("normalizeMcpServer rejects retired config aliases before vault resolution", () => {
  const state = fakeState();

  assert.throws(
    () =>
      normalizeMcpServer(
        state,
        "Legacy",
        {
          serverUrl: "https://legacy.example.test/mcp",
          allowedTools: ["search"],
          headers: { Authorization: "vault://mcp/legacy/token" },
        },
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_mcp_server_config_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["serverUrl", "allowedTools"]);
      assert.deepEqual(error.details.canonical_fields, ["url", "server_url", "allowed_tools", "tools"]);
      return true;
    },
  );
  assert.deepEqual(state.walletAuthority.resolved, []);
});

function assertNoMcpWorkflowMutation(state) {
  assert.equal(state.mcpServers.size, 0);
  assert.deepEqual(state.authorizations, []);
  assert.deepEqual(state.mcpWorkflowRequests, []);
  assert.deepEqual(state.modelInvocations, []);
  assert.deepEqual(state.readProjectionRequests, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.routeTests, []);
  assert.deepEqual(state.writes, []);
}

function assertMcpWorkflowRustCoreRequired(error, operationKind, details = {}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_mcp_workflow_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "model_mount.mcp_workflow");
  assert.equal(error.details.operation_kind, operationKind);
  for (const [key, value] of Object.entries(details)) {
    assert.deepEqual(error.details[key], value);
  }
  assert.deepEqual(error.details.evidence_refs, [
    "rust_daemon_core_model_mount_mcp_workflow",
    "agentgres_mcp_workflow_truth_required",
    "model_mount_mcp_workflow_js_facade_retired",
    "model_mount_mcp_import_js_facade_retired",
    "model_mount_ephemeral_mcp_registration_js_facade_retired",
    "model_mount_mcp_tool_invocation_js_facade_retired",
    "model_mount_workflow_node_execution_js_facade_retired",
    "model_mount_mcp_workflow_receipt_synthesis_js_retired",
    "model_mount_mcp_workflow_record_state_js_retired",
  ]);
  assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
  assert.equal(Object.hasOwn(error.details, "operationKind"), false);
  return true;
}

test("importMcpJson uses Rust MCP workflow planning, record-state commit, and Rust projection", () => {
  const state = fakeState();

  const result = importMcpJson(state, {
    mcp_servers: {
      Local: { command: "node", args: ["server.mjs"], allowed_tools: ["run"] },
      Remote: { url: "https://example.test/mcp", allowed_tools: ["search"] },
    },
  });

  assert.equal(result.operation_kind, "model_mount.mcp_server.import");
  assert.equal(result.rust_core_boundary, "model_mount.mcp_workflow");
  assert.deepEqual(result.server_ids, ["mcp.local", "mcp.remote"]);
  assert.equal(state.mcpWorkflowRequests.length, 1);
  assert.equal(state.mcpWorkflowRequests[0].schema_version, "ioi.model_mount.mcp_workflow.v1");
  assert.equal(state.mcpWorkflowRequests[0].operation_kind, "model_mount.mcp_server.import");
  assert.deepEqual(Object.keys(state.mcpWorkflowRequests[0].body.mcp_servers), ["Local", "Remote"]);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "mcp-servers");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.mcp_server.import");
  assertRetiredFieldsAbsent(result, MCP_WORKFLOW_RETIRED_JS_PROOF_FIELDS);
  assertRetiredFieldsAbsent(state.recordStateCommits[0].record.details, MCP_WORKFLOW_RETIRED_JS_PROOF_FIELDS);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);

  state.mcpServers.set("mcp.Projected", { id: "mcp.Projected", label: "Projected", status: "registered" });
  assert.deepEqual(listMcpServers(state), [
    { id: "mcp.Projected", label: "Projected", status: "registered" },
  ]);
  assert.deepEqual(state.readProjectionRequests, [{ projection_kind: "mcp_servers" }]);
});

test("importMcpJson rejects retired request aliases before state mutation", () => {
  const state = fakeState();

  assert.throws(
    () =>
      importMcpJson(state, {
        mcpJson: {
          servers: {
            Local: { command: "node", args: ["server.mjs"] },
          },
        },
        mcpServers: {
          Remote: { url: "https://legacy.example.test/mcp" },
        },
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_mcp_import_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["mcpJson", "mcpServers"]);
      assert.deepEqual(error.details.canonical_fields, ["mcp_json", "mcp_servers", "servers"]);
      return true;
    },
  );
  assert.equal(state.mcpServers.size, 0);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);

  assert.throws(
    () =>
      importMcpJson(state, {
        mcp_json: {
          mcpServers: {
            Local: { command: "node", args: ["server.mjs"] },
          },
        },
      }),
    (error) => {
      assert.equal(error.code, "model_mount_mcp_import_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["mcp_json.mcpServers"]);
      return true;
    },
  );
  assert.equal(state.mcpServers.size, 0);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
});

test("invokeMcpTool uses Rust MCP workflow admission and rejects JS or command fallback", () => {
  const state = fakeState();
  state.mcpServers.set("mcp.Local", {
    id: "mcp.Local",
    label: "Local",
    allowedTools: ["run"],
  });

  const result = invokeMcpTool(
    state,
    {
      authorization: "auth",
      body: {
        server_id: "mcp.Local",
        tool: "run",
        input: { prompt: "hello" },
        authority_grant_refs: ["wallet.network://grant/mcp/local/run"],
        authority_receipt_refs: ["receipt://wallet.network/mcp/local/run"],
        custody_ref: "ctee://workspace/local",
        containment_ref: "containment://mcp/local",
      },
    },
  );

  assert.equal(result.operation_kind, "model_mount.mcp_tool.invoke");
  assert.equal(result.status, "admitted");
  assert.equal(result.transport_execution_status, "rust_admitted");
  assert.equal(result.rust_transport_execution_admitted, true);
  assert.equal(result.transport_execution_owner, "rust_daemon_core.model_mount.mcp_workflow");
  assert.equal(result.step_module_dispatch_owner, "rust_daemon_core.step_module_router");
  assert.equal(result.content_receipt_required, true);
  assert.equal(result.result_receipt_id, result.content_receipt_id);
  assert.equal(result.model_mount_mcp_result_materialized, true);
  assert.equal(result.model_mount_mcp_result_materialization_status, "rust_materialized");
  assert.equal(result.result_materialization_owner, "rust_daemon_core.model_mount.mcp_workflow");
  assert.equal(result.result_payload.payload_kind, "mcp_tool_result");
  assert.equal(result.result_payload_hash, `sha256:result-payload:${state.recordStateCommits[0]?.record_id ?? "unused"}`);
  assert.equal(result.receipt.kind, "mcp_tool_invocation");
  assert.equal(result.receipt.details.rust_daemon_core_receipt_author, "model_mount.mcp_workflow");
  assert.equal(result.receipt.details.model_mount_mcp_result_materialized, true);
  assert.equal(result.receipt.details.model_mount_mcp_result_materialization_status, "rust_materialized");
  assert.equal(result.receipt.details.result_payload_hash, result.result_payload_hash);
  assert.equal(result.receipt.details.model_mount_step_module_result.result_materialized, true);
  assert.equal(result.receipt_commit.commit_hash, `sha256:receipt-commit:${result.receipt.id}`);
  assertRetiredFieldsAbsent(result, [
    "js_transport_invocation",
    ...MCP_WORKFLOW_RETIRED_FALLBACK_FIELDS,
  ]);
  assertRetiredFieldsAbsent(result.result_payload, MCP_WORKFLOW_RETIRED_RESULT_PAYLOAD_FIELDS);
  assertRetiredFieldsAbsent(result.receipt.details.result_payload, MCP_WORKFLOW_RETIRED_RESULT_PAYLOAD_FIELDS);
  assert.equal(state.mcpWorkflowRequests.length, 1);
  assert.equal(state.mcpWorkflowRequests[0].body.server_id, "mcp.Local");
  assert.equal(state.mcpWorkflowRequests[0].body.tool, "run");
  assert.deepEqual(state.mcpWorkflowRequests[0].authority_grant_refs, [
    "wallet.network://grant/mcp/local/run",
  ]);
  assert.deepEqual(state.mcpWorkflowRequests[0].authority_receipt_refs, [
    "receipt://wallet.network/mcp/local/run",
  ]);
  assert.equal(state.mcpWorkflowRequests[0].custody_ref, "ctee://workspace/local");
  assert.equal(state.mcpWorkflowRequests[0].containment_ref, "containment://mcp/local");
  assert.equal(state.recordStateCommits[0].record.details.wallet_authority_required, true);
  assert.equal(
    state.recordStateCommits[0].record.details.wallet_authority_boundary,
    "wallet.network.mcp_external_exit",
  );
  assert.equal(state.recordStateCommits[0].record.details.ctee_custody_required, true);
  assert.equal(state.recordStateCommits[0].record.details.transport_containment_required, true);
  assert.equal(state.recordStateCommits[0].record.details.custody_ref, "ctee://workspace/local");
  assert.equal(state.recordStateCommits[0].record.details.containment_ref, "containment://mcp/local");
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "mcp-workflow-controls");
  assertRetiredFieldsAbsent(state.recordStateCommits[0].record.details, [
    "js_transport_invocation",
    ...MCP_WORKFLOW_RETIRED_FALLBACK_FIELDS,
  ]);
  assertRetiredFieldsAbsent(
    state.recordStateCommits[0].record.details.result_payload,
    MCP_WORKFLOW_RETIRED_RESULT_PAYLOAD_FIELDS,
  );
  assert.equal(state.recordStateCommits[0].record.details.model_mount_mcp_result_materialized, true);
  assert.equal(state.recordStateCommits[0].record.details.result_payload_hash, result.result_payload_hash);
  assert.equal(state.receiptStateCommits.length, 1);
  assert.equal(state.receiptStateCommits[0].receipt_id, result.content_receipt_id);
  assert.equal(
    state.receiptStateCommits[0].receipt.details.model_mount_agentgres_operation_ref,
    `agentgres://model-mounting/mcp-workflow/${state.recordStateCommits[0].record_id}`,
  );
  assert.deepEqual(state.authorizations, []);
  assert.equal(state.receipts.length, 1);
  assert.equal(state.receipts[0].kind, "mcp_tool_invocation");
});

test("invokeMcpTool fails closed without wallet authority refs", () => {
  const state = fakeState();

  assert.throws(
    () =>
      invokeMcpTool(
        state,
        { authorization: "auth", body: { server_id: "mcp.Local", tool: "run", input: { prompt: "hello" } } },
      ),
    (error) => {
      assert.equal(error.code, "model_mount_mcp_external_exit_wallet_authority_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.mcp_workflow");
      assert.equal(error.details.operation_kind, "model_mount.mcp_tool.invoke");
      return true;
    },
  );
  assert.equal(state.recordStateCommits.length, 0);
  assert.deepEqual(state.authorizations, []);
});

test("invokeMcpTool fails closed without Rust MCP execution receipt commit", () => {
  const missingReceiptState = fakeState();
  missingReceiptState.planModelMountMcpWorkflow = function planWithoutReceipt(request) {
    this.mcpWorkflowRequests.push(JSON.parse(JSON.stringify(request)));
    const plan = mcpWorkflowPlan(request);
    delete plan.receipt;
    return plan;
  };

  assert.throws(
    () =>
      invokeMcpTool(
        missingReceiptState,
        {
          authorization: "auth",
          body: {
            server_id: "mcp.Local",
            tool: "run",
            input: { prompt: "hello" },
            authority_grant_refs: ["wallet.network://grant/mcp/local/run"],
            authority_receipt_refs: ["receipt://wallet.network/mcp/local/run"],
            custody_ref: "ctee://workspace/local",
            containment_ref: "containment://mcp/local",
          },
        },
      ),
    (error) => error.code === "model_mount_mcp_execution_receipt_required",
  );
  assert.equal(missingReceiptState.recordStateCommits.length, 1);
  assert.equal(missingReceiptState.receiptStateCommits.length, 0);

  const missingCommitterState = fakeState();
  delete missingCommitterState.persistRustAuthoredReceiptWithCommit;
  assert.throws(
    () =>
      invokeMcpTool(
        missingCommitterState,
        {
          authorization: "auth",
          body: {
            server_id: "mcp.Local",
            tool: "run",
            input: { prompt: "hello" },
            authority_grant_refs: ["wallet.network://grant/mcp/local/run"],
            authority_receipt_refs: ["receipt://wallet.network/mcp/local/run"],
            custody_ref: "ctee://workspace/local",
            containment_ref: "containment://mcp/local",
          },
        },
      ),
    (error) => error.code === "model_mount_mcp_execution_receipt_state_commit_unconfigured",
  );
  assert.equal(missingCommitterState.recordStateCommits.length, 1);
  assert.equal(missingCommitterState.receiptStateCommits.length, 0);
});

test("invokeMcpTool fails closed without custody and containment refs", () => {
  const state = fakeState();

  assert.throws(
    () =>
      invokeMcpTool(
        state,
        {
          authorization: "auth",
          body: {
            server_id: "mcp.Local",
            tool: "run",
            input: { prompt: "hello" },
            authority_grant_refs: ["wallet.network://grant/mcp/local/run"],
            authority_receipt_refs: ["receipt://wallet.network/mcp/local/run"],
          },
        },
      ),
    (error) => {
      assert.equal(error.code, "model_mount_mcp_external_exit_custody_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.mcp_workflow");
      return true;
    },
  );

  assert.throws(
    () =>
      invokeMcpTool(
        state,
        {
          authorization: "auth",
          body: {
            server_id: "mcp.Local",
            tool: "run",
            input: { prompt: "hello" },
            authority_grant_refs: ["wallet.network://grant/mcp/local/run"],
            authority_receipt_refs: ["receipt://wallet.network/mcp/local/run"],
            custody_ref: "ctee://workspace/local",
          },
        },
      ),
    (error) => {
      assert.equal(error.code, "model_mount_mcp_external_exit_containment_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.mcp_workflow");
      return true;
    },
  );
  assert.equal(state.recordStateCommits.length, 0);
  assert.deepEqual(state.authorizations, []);
});

test("invokeMcpTool rejects retired request aliases before authorization", () => {
  const state = fakeState();
  state.mcpServers.set("mcp.Local", {
    id: "mcp.Local",
    label: "Local",
    allowedTools: ["run"],
  });

  assert.throws(
    () =>
      invokeMcpTool(
        state,
        {
          authorization: "auth",
          body: {
            serverId: "mcp.Local",
            server_label: "Local",
            serverLabel: "Local",
            tool: "run",
            input: { prompt: "hello" },
          },
        },
        deps,
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_mcp_tool_invocation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["serverId", "server_label", "serverLabel"]);
      assert.deepEqual(error.details.canonical_fields, ["server_id", "tool", "input"]);
      return true;
    },
  );
  assert.deepEqual(state.authorizations, []);
  assert.deepEqual(state.receipts, []);
});

test("compileEphemeralMcpIntegrations returns empty projection for no ephemeral MCP integrations", () => {
  const state = fakeState();

  const result = compileEphemeralMcpIntegrations(
    state,
    {
      authorization: "auth",
      input: "question",
      body: { integrations: [{ type: "other" }] },
    },
  );

  assert.deepEqual(result, { toolReceiptIds: [], serverIds: [], evidenceRefs: [] });
  assertNoMcpWorkflowMutation(state);
});

test("compileEphemeralMcpIntegrations uses Rust MCP workflow planning and record-state commit", () => {
  const state = fakeState();

  const result = compileEphemeralMcpIntegrations(
    state,
    {
      authorization: "auth",
      input: "question",
      body: {
        integrations: [
          {
            type: "ephemeral_mcp",
            server_label: "Search",
            server_url: "https://example.test/mcp",
            allowed_tools: ["search"],
          },
        ],
      },
    },
  );

  assert.deepEqual(result.serverIds, ["mcp.search"]);
  assert.deepEqual(result.toolReceiptIds, []);
  assert.equal(state.mcpWorkflowRequests.length, 1);
  assert.equal(state.mcpWorkflowRequests[0].operation_kind, "model_mount.mcp_server.ephemeral_register");
  assert.equal(state.mcpWorkflowRequests[0].body.integrations[0].server_label, "Search");
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "mcp-servers");
  assertRetiredFieldsAbsent(result, MCP_WORKFLOW_RETIRED_JS_PROOF_FIELDS);
  assertRetiredFieldsAbsent(state.recordStateCommits[0].record.details, MCP_WORKFLOW_RETIRED_JS_PROOF_FIELDS);
  assert.deepEqual(state.authorizations, []);
  assert.deepEqual(state.receipts, []);
});

test("compileEphemeralMcpIntegrations rejects retired integration aliases before mutation", () => {
  const state = fakeState();

  assert.throws(
    () =>
      compileEphemeralMcpIntegrations(
        state,
        {
          authorization: "auth",
          input: "question",
          body: {
            integrations: [
              {
                type: "ephemeral_mcp",
                serverLabel: "Search",
                serverUrl: "https://legacy.example.test/mcp",
                allowedTools: ["search"],
              },
            ],
          },
        },
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_ephemeral_mcp_integration_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["serverLabel", "serverUrl", "allowedTools"]);
      assert.deepEqual(error.details.canonical_fields, ["server_label", "server_url", "allowed_tools"]);
      return true;
    },
  );
  assert.equal(state.mcpServers.size, 0);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.authorizations, []);
});

test("executeWorkflowNode uses Rust StepModule dispatch admission and rejects JS fallback", async () => {
  const state = fakeState();
  state.mcpServers.set("mcp.Local", {
    id: "mcp.Local",
    label: "Local",
    allowedTools: ["run"],
  });

  const result = await executeWorkflowNode(
    state,
    {
      authorization: "auth",
      body: {
        node: "Embed",
        model_id: "embedding.local",
        route_id: "route.local-first",
        input: "hello",
        max_tokens: 32,
        workflow_graph_id: "graph.workflow",
        workflow_node_id: "node.embed",
        workflow_node_type: "Embedding",
        authority_grant_refs: ["wallet.network://grant/workflow/node/embed"],
        authority_receipt_refs: ["receipt://wallet.network/workflow/node/embed"],
        custody_ref: "ctee://workspace/workflow",
        containment_ref: "containment://workflow/node/embed",
      },
    },
  );

  assert.equal(result.operation_kind, "model_mount.workflow_node.execute");
  assert.equal(result.status, "admitted");
  assert.equal(result.execution_status, "rust_admitted");
  assert.equal(result.rust_step_module_dispatch_admitted, true);
  assert.equal(result.workflow_execution_owner, "rust_daemon_core.model_mount.mcp_workflow");
  assert.equal(result.step_module_dispatch_owner, "rust_daemon_core.step_module_router");
  assert.equal(result.content_receipt_required, true);
  assert.equal(result.result_receipt_id, result.content_receipt_id);
  assert.equal(result.model_mount_mcp_result_materialized, true);
  assert.equal(result.model_mount_mcp_result_materialization_status, "rust_materialized");
  assert.equal(result.result_payload.payload_kind, "workflow_node_result");
  assert.equal(result.receipt.kind, "workflow_node_execution");
  assert.equal(result.receipt.details.rust_daemon_core_receipt_author, "model_mount.mcp_workflow");
  assert.equal(result.receipt.details.model_mount_mcp_result_materialized, true);
  assert.equal(result.receipt.details.result_payload_hash, result.result_payload_hash);
  assert.equal(result.receipt.details.model_mount_step_module_result.result_materialized, true);
  assert.equal(result.receipt_commit.commit_hash, `sha256:receipt-commit:${result.receipt.id}`);
  assertRetiredFieldsAbsent(result, [
    "js_route_test",
    "js_model_invocation",
    "js_mcp_tool_invocation",
    ...MCP_WORKFLOW_RETIRED_FALLBACK_FIELDS,
  ]);
  assertRetiredFieldsAbsent(result.result_payload, MCP_WORKFLOW_RETIRED_RESULT_PAYLOAD_FIELDS);
  assertRetiredFieldsAbsent(result.receipt.details.result_payload, MCP_WORKFLOW_RETIRED_RESULT_PAYLOAD_FIELDS);
  assert.equal(state.mcpWorkflowRequests.length, 1);
  assert.deepEqual(
    {
      node: state.mcpWorkflowRequests[0].body.node,
      workflow_graph_id: state.mcpWorkflowRequests[0].body.workflow_graph_id,
      workflow_node_id: state.mcpWorkflowRequests[0].body.workflow_node_id,
    },
    {
      node: "Embed",
      workflow_graph_id: "graph.workflow",
      workflow_node_id: "node.embed",
    },
  );
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "mcp-workflow-controls");
  assert.equal(state.recordStateCommits[0].record.details.wallet_authority_required, true);
  assert.equal(state.recordStateCommits[0].record.details.ctee_custody_required, true);
  assert.equal(state.recordStateCommits[0].record.details.transport_containment_required, true);
  assert.equal(state.recordStateCommits[0].record.details.containment_ref, "containment://workflow/node/embed");
  assertRetiredFieldsAbsent(state.recordStateCommits[0].record.details, [
    "js_route_test",
    "js_model_invocation",
    "js_mcp_tool_invocation",
    ...MCP_WORKFLOW_RETIRED_FALLBACK_FIELDS,
  ]);
  assertRetiredFieldsAbsent(
    state.recordStateCommits[0].record.details.result_payload,
    MCP_WORKFLOW_RETIRED_RESULT_PAYLOAD_FIELDS,
  );
  assert.equal(state.receiptStateCommits.length, 1);
  assert.equal(state.receiptStateCommits[0].receipt_id, result.content_receipt_id);
  assert.equal(state.mcpServers.size, 1);
  assert.deepEqual(state.authorizations, []);
  assert.deepEqual(state.routeTests, []);
  assert.deepEqual(state.modelInvocations, []);
  assert.equal(state.receipts.length, 1);
  assert.equal(state.receipts[0].kind, "workflow_node_execution");
});

test("executeWorkflowNode rejects retired request aliases before authorization", async () => {
  const state = fakeState();

  await assert.rejects(
    () =>
      executeWorkflowNode(
        state,
        {
          authorization: "auth",
          body: {
            nodeType: "Model Call",
            modelId: "model.local",
            routeId: "route.local-first",
            modelPolicy: { privacy: "legacy" },
            maxTokens: 16,
            workflowGraphId: "graph.legacy",
            workflowNodeId: "node.legacy",
            nodeId: "node.alias",
            node_id: "node.snake-alias",
            workflowNodeType: "Model Call",
            input: "legacy workflow node aliases",
          },
        },
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_workflow_node_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
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
      ]);
      assert.deepEqual(error.details.canonical_fields, [
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
      ]);
      assert.equal(Object.hasOwn(error.details, "routeId"), false);
      return true;
    },
  );
  assert.deepEqual(state.authorizations, []);
  assert.deepEqual(state.routeTests, []);
  assert.deepEqual(state.modelInvocations, []);
});
