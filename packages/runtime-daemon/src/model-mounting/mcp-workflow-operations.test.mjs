import assert from "node:assert/strict";
import test from "node:test";

import {
  compileEphemeralMcpIntegrations,
  executeWorkflowNode,
  importMcpJson,
  invokeMcpTool,
  listMcpServers,
  normalizeMcpServer,
} from "./mcp-workflow-operations.mjs";

function fakeState() {
  return {
    authorizations: [],
    mcpServers: new Map(),
    modelInvocations: [],
    recordStateCommits: [],
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
      return invokeMcpTool(this, args, deps);
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
      return normalizeMcpServer(this, label, config, deps);
    },
    nowIso() {
      return "2026-06-04T02:00:00.000Z";
    },
    receipt(kind, payload) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, payload };
      this.receipts.push(receipt);
      return receipt;
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

const deps = {
  capabilityForWorkflowNode(node) {
    if (node === "Embed") return "embeddings";
    return "chat";
  },
  nativeInvocationResponseShape(invocation) {
    return { outputText: invocation.outputText, kind: invocation.kind };
  },
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
  workflowKindForNode(node) {
    if (node === "Embed") return "embeddings";
    return "chat";
  },
  workflowMemoryOptionsFromBody(body) {
    return body.memory ?? null;
  },
  workflowMemoryWriteBlockReason(memory) {
    return memory?.write === true ? "write_not_allowed" : null;
  },
};

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
    deps,
  );

  assert.equal(server.id, "mcp.Docs_MCP");
  assert.equal(server.transport, "remote");
  assert.deepEqual(server.allowedTools, ["search", "read"]);
  assert.deepEqual(server.secretRefs, { Authorization: "vault://mcp.Docs_MCP/Authorization" });
  assert.deepEqual(server.redactedHeaders, { Authorization: "[REDACTED]" });
  assert.deepEqual(state.walletAuthority.resolved, ["vault://mcp/docs/token"]);

  assert.throws(
    () => normalizeMcpServer(state, "Bad", { headers: { token: "plaintext" } }, deps),
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
        deps,
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
  assert.deepEqual(state.modelInvocations, []);
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
    "model_mount_mcp_workflow_js_facade_retired",
    "model_mount_mcp_import_js_facade_retired",
    "model_mount_ephemeral_mcp_registration_js_facade_retired",
    "model_mount_mcp_tool_invocation_js_facade_retired",
    "model_mount_workflow_node_execution_js_facade_retired",
    "model_mount_mcp_workflow_receipt_synthesis_js_retired",
    "model_mount_mcp_workflow_record_state_js_retired",
    "rust_daemon_core_model_mount_mcp_workflow_required",
    "agentgres_mcp_workflow_truth_required",
  ]);
  assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
  assert.equal(Object.hasOwn(error.details, "operationKind"), false);
  return true;
}

test("importMcpJson facade fails closed before JS receipts, record-state commits, or projections", () => {
  const state = fakeState();

  assert.throws(
    () =>
      importMcpJson(state, {
        mcp_servers: {
          Local: { command: "node", args: ["server.mjs"], allowed_tools: ["run"] },
          Remote: { url: "https://example.test/mcp", allowed_tools: ["search"] },
        },
      }, deps),
    (error) => assertMcpWorkflowRustCoreRequired(error, "model_mount.mcp_server.import"),
  );

  assertNoMcpWorkflowMutation(state);
  state.mcpServers.set("mcp.Projected", { id: "mcp.Projected", label: "Projected", status: "registered" });
  assert.deepEqual(listMcpServers(state, deps).map((server) => server.id), ["mcp.Projected"]);
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

test("invokeMcpTool facade fails closed before authorization, fixture execution, or receipt synthesis", () => {
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
        { authorization: "auth", body: { server_id: "mcp.Local", tool: "run", input: { prompt: "hello" } } },
        deps,
      ),
    (error) =>
      assertMcpWorkflowRustCoreRequired(error, "model_mount.mcp_tool.invoke", {
        server_id: "mcp.Local",
        tool: "run",
      }),
  );

  assert.deepEqual(state.authorizations, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
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
    deps,
  );

  assert.deepEqual(result, { toolReceiptIds: [], serverIds: [], evidenceRefs: [] });
  assertNoMcpWorkflowMutation(state);
});

test("compileEphemeralMcpIntegrations facade fails closed before registration, tool invocation, or receipts", () => {
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
                server_label: "Search",
                server_url: "https://example.test/mcp",
                allowed_tools: ["search"],
              },
            ],
          },
        },
        deps,
      ),
    (error) => {
      assertMcpWorkflowRustCoreRequired(error, "model_mount.mcp_server.ephemeral_register", {
        integration_count: 1,
      });
      return true;
    },
  );

  assertNoMcpWorkflowMutation(state);
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
        deps,
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

test("executeWorkflowNode facade fails closed before route, MCP, receipt-gate, or model dispatch", async () => {
  const state = fakeState();
  state.mcpServers.set("mcp.Local", {
    id: "mcp.Local",
    label: "Local",
    allowedTools: ["run"],
  });

  await assert.rejects(
    () =>
      executeWorkflowNode(
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
          },
        },
        deps,
      ),
    (error) =>
      assertMcpWorkflowRustCoreRequired(error, "model_mount.workflow_node.execute", {
        node: "Embed",
        workflow_graph_id: "graph.workflow",
        workflow_node_id: "node.embed",
      }),
  );
  assert.equal(state.mcpServers.size, 1);
  assert.deepEqual(state.authorizations, []);
  assert.deepEqual(state.routeTests, []);
  assert.deepEqual(state.modelInvocations, []);
  assert.deepEqual(state.receipts, []);
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
        deps,
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
