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
    invokeModel: async ({ requiredScope, kind, body }) => ({
      kind,
      body,
      receipt: { id: "receipt.model" },
      routeReceipt: { id: "receipt.route" },
      outputText: `invoked:${requiredScope}`,
    }),
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

test("importMcpJson stores servers, emits receipts, and listMcpServers projects public rows", () => {
  const state = fakeState();

  const result = importMcpJson(state, {
    mcpServers: {
      Local: { command: "node", args: ["server.mjs"], allowed_tools: ["run"] },
      Remote: { url: "https://example.test/mcp", allowed_tools: ["search"] },
    },
  });

  assert.equal(result.count, 2);
  assert.equal(result.empty, false);
  assert.equal(state.mcpServers.size, 2);
  assert.equal(state.receipts.length, 2);
  assert.deepEqual(state.receipts[0].payload.details.allowed_tools, ["run"]);
  assert.equal(state.receipts[1].payload.details.server_url, "https://example.test/mcp");
  assert.equal(state.receipts[0].payload.details.imported_at, "2026-06-04T02:00:00.000Z");
  assert.equal(Object.hasOwn(state.receipts[0].payload.details, "allowedTools"), false);
  assert.equal(Object.hasOwn(state.receipts[1].payload.details, "serverUrl"), false);
  assert.equal(Object.hasOwn(state.receipts[0].payload.details, "importedAt"), false);
  assert.equal(state.writes.at(-1)[0], "mcp-servers");
  assert.deepEqual(listMcpServers(state, deps).map((server) => server.id), ["mcp.Local", "mcp.Remote"]);
});

test("invokeMcpTool enforces allowed tools and emits redacted fixture result", () => {
  const state = fakeState();
  state.mcpServers.set("mcp.Local", {
    id: "mcp.Local",
    label: "Local",
    allowedTools: ["run"],
  });

  const result = invokeMcpTool(
    state,
    { authorization: "auth", body: { server_id: "mcp.Local", tool: "run", input: { prompt: "hello" } } },
    deps,
  );

  assert.equal(result.server, "Local");
  assert.deepEqual(result.result, { ok: true, fixture: true, tool: "run" });
  assert.deepEqual(state.authorizations.at(-1), ["auth", "mcp.call:Local.run"]);
  assert.equal(result.receipt.payload.details.server_id, "mcp.Local");
  assert.equal(result.receipt.payload.details.input_hash, 'hash:{"prompt":"hello"}');
  assert.equal(Object.hasOwn(result.receipt.payload.details, "serverId"), false);
  assert.equal(Object.hasOwn(result.receipt.payload.details, "inputHash"), false);
  assert.equal(Object.hasOwn(result.receipt.payload.details, "outputHash"), false);

  assert.throws(
    () => invokeMcpTool(state, { authorization: "auth", body: { server_id: "mcp.Local", tool: "delete" } }, deps),
    (error) =>
      error.status === 403 &&
      error.code === "policy" &&
      error.details.server_id === "mcp.Local" &&
      Object.hasOwn(error.details, "serverId") === false,
  );
});

test("compileEphemeralMcpIntegrations registers ephemeral servers and invokes allowed tools", () => {
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
            allowed_tools: ["search", "read"],
          },
          { type: "other" },
        ],
      },
    },
    deps,
  );

  assert.equal(result.serverIds.length, 1);
  assert.equal(result.toolReceiptIds.length, 2);
  assert.equal(result.evidenceRefs.length, 4);
  assert.equal(state.mcpServers.get(result.serverIds[0]).status, "ephemeral_registered");
  assert.equal(state.receipts[0].payload.details.server_url, "https://example.test/mcp");
  assert.deepEqual(state.receipts[0].payload.details.allowed_tools, ["search", "read"]);
  assert.equal(Object.hasOwn(state.receipts[0].payload.details, "serverUrl"), false);
  assert.equal(Object.hasOwn(state.receipts[0].payload.details, "allowedTools"), false);
  assert.equal(state.writes.at(-1)[0], "mcp-servers");
});

test("executeWorkflowNode dispatches router, MCP, receipt gate, model, and memory policy branches", async () => {
  const state = fakeState();
  state.mcpServers.set("mcp.Local", {
    id: "mcp.Local",
    label: "Local",
    allowedTools: ["run"],
  });

  const router = await executeWorkflowNode(
    state,
    { authorization: "auth", body: { node: "Model Router", route_id: "route.local-first", model: "llama-test" } },
    deps,
  );
  assert.equal(router.status, "selected");
  assert.deepEqual(state.authorizations.at(-1), ["auth", "route.use:route.local-first"]);

  const mcp = await executeWorkflowNode(
    state,
    { authorization: "auth", body: { node: "Local Tool/MCP", mcp: { server_id: "mcp.Local", tool: "run" } } },
    deps,
  );
  assert.equal(mcp.status, "executed");
  assert.equal(mcp.tool, "run");

  const receiptGate = await executeWorkflowNode(
    state,
    { authorization: "auth", body: { node: "Receipt Gate", receipt_id: "receipt.1" } },
    deps,
  );
  assert.equal(receiptGate.status, "passed");

  const model = await executeWorkflowNode(
    state,
    { authorization: "auth", body: { node: "Embed", input: "hello" } },
    deps,
  );
  assert.equal(model.status, "executed");
  assert.equal(model.capability, "embeddings");
  assert.deepEqual(model.invocation, { outputText: "invoked:model.embeddings:*", kind: "embeddings" });

  await assert.rejects(
    () => executeWorkflowNode(state, { authorization: "auth", body: { node: "Model", memory: { write: true } } }, deps),
    (error) =>
      error.status === 403 &&
      error.code === "policy" &&
      Object.hasOwn(error.details, "workflowNodeId") === false,
  );
});
