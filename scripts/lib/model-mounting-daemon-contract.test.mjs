import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

async function requestJson(endpoint, route, { method = "GET", body, token } = {}) {
  const response = await fetch(`${endpoint}${route}`, {
    method,
    headers: {
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  const json = text ? JSON.parse(text) : undefined;
  return { response, json };
}

async function expectOk(endpoint, route, options) {
  const result = await requestJson(endpoint, route, options);
  assert.equal(result.response.ok, true, `${route} -> ${result.response.status}`);
  return result.json;
}

test("model mounting daemon exercises registry, router, tokens, MCP, receipts, and OpenAI compatibility", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-mounting-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-mounting-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const status = await expectOk(daemon.endpoint, "/api/v1/server/status");
    assert.equal(status.schemaVersion, "ioi.model-mounting.runtime.v1");
    assert.equal(status.nativeBaseUrl, `${daemon.endpoint}/api/v1`);
    assert.equal(status.openAiCompatibleBaseUrl, `${daemon.endpoint}/v1`);

    const unauthenticated = await requestJson(daemon.endpoint, "/api/v1/chat", {
      method: "POST",
      body: { input: "blocked" },
    });
    assert.equal(unauthenticated.response.status, 401);

    const blockedGrant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: {
        allowed: ["model.chat:*"],
        denied: ["model.chat:*"],
      },
    });
    const denied = await requestJson(daemon.endpoint, "/api/v1/chat", {
      method: "POST",
      token: blockedGrant.token,
      body: { input: "blocked by deny scope" },
    });
    assert.equal(denied.response.status, 403);

    const expiredGrant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: {
        allowed: ["model.chat:*"],
        expiresAt: "2000-01-01T00:00:00.000Z",
      },
    });
    const expired = await requestJson(daemon.endpoint, "/api/v1/chat", {
      method: "POST",
      token: expiredGrant.token,
      body: { input: "expired token" },
    });
    assert.equal(expired.response.status, 403);

    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: {
        audience: "autopilot-local-server",
        allowed: [
          "model.chat:*",
          "model.responses:*",
          "model.embeddings:*",
          "model.load:*",
          "model.unload:*",
          "model.mount:*",
          "model.download:*",
          "model.import:*",
          "backend.control:*",
          "route.write:*",
          "route.use:*",
          "vault.read:*",
          "mcp.import:*",
          "mcp.call:huggingface.model_search",
        ],
        denied: ["connector.gmail.send", "filesystem.write", "shell.exec"],
      },
    });
    assert.match(grant.token, /^ioi_mnt_/);

    const vaultScopedGrant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: {
        allowed: ["route.use:*"],
        vaultRefs: { openai: "vault://fixture/provider/openai-api-key" },
      },
    });
    assert.equal(vaultScopedGrant.vaultRefs.openai.redacted, true);
    assert.equal(JSON.stringify(vaultScopedGrant).includes("vault://fixture/provider/openai-api-key"), false);

    const snapshot = await expectOk(daemon.endpoint, "/api/v1/models");
    assert.ok(snapshot.artifacts.some((model) => model.modelId === "local:auto"));
    assert.ok(snapshot.providers.some((provider) => provider.kind === "lm_studio"));
    assert.ok(snapshot.providers.some((provider) => provider.kind === "ioi_native_local"));
    assert.ok(snapshot.backends.some((backend) => backend.kind === "native_local"));
    assert.ok(snapshot.backends.some((backend) => backend.kind === "llama_cpp"));
    assert.ok(snapshot.backends.some((backend) => backend.kind === "ollama"));
    assert.ok(snapshot.backends.some((backend) => backend.kind === "vllm"));
    assert.ok(snapshot.routes.some((route) => route.id === "route.local-first"));
    assert.ok(snapshot.routes.some((route) => route.id === "route.native-local"));
    assert.ok(snapshot.workflowNodes.some((node) => node.node === "Model Router"));
    assert.ok(snapshot.workflowNodes.every((node) => node.receiptRequired));
    assert.equal(snapshot.adapterBoundaries.vault.materialAdapter.implementation, "runtime_memory");

    const vaultStatus = await expectOk(daemon.endpoint, "/api/v1/vault/status", { token: grant.token });
    assert.equal(vaultStatus.materialAdapter.implementation, "runtime_memory");
    const vaultHealth = await expectOk(daemon.endpoint, "/api/v1/vault/health", { method: "POST", token: grant.token });
    assert.equal(vaultHealth.status, "session_only");
    assert.equal(vaultHealth.materialAdapter.writeAvailable, true);
    assert.equal(vaultHealth.materialAdapter.plaintextPersistence, false);

    const nativeProviderModels = await expectOk(daemon.endpoint, "/api/v1/providers/provider.autopilot.local/models");
    assert.ok(nativeProviderModels.some((model) => model.modelId === "autopilot:native-fixture"));

    const backends = await expectOk(daemon.endpoint, "/api/v1/backends");
    assert.ok(backends.some((backend) => backend.id === "backend.autopilot.native-local.fixture"));
    assert.ok(backends.some((backend) => backend.id === "backend.llama-cpp"));
    const backendHealth = await expectOk(daemon.endpoint, "/api/v1/backends/backend.autopilot.native-local.fixture/health", {
      method: "POST",
    });
    assert.equal(backendHealth.status, "available");
    assert.equal(typeof backendHealth.lastReceiptId, "string");
    const fixtureBackendStart = await expectOk(daemon.endpoint, "/api/v1/backends/backend.fixture/start", {
      method: "POST",
      token: grant.token,
    });
    assert.equal(fixtureBackendStart.status, "available");

    const importedModelPath = path.join(cwd, "autopilot-imported.Q4_K_M.gguf");
    fs.writeFileSync(
      importedModelPath,
      ["family=autopilot-imported", "quantization=Q4_K_M", "context=4096", "fixture bytes"].join("\n"),
    );
    const imported = await expectOk(daemon.endpoint, "/api/v1/models/import", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "native:imported",
        provider_id: "provider.autopilot.local",
        path: importedModelPath,
        capabilities: ["chat", "responses", "embeddings"],
      },
    });
    assert.equal(imported.providerId, "provider.autopilot.local");
    assert.equal(imported.format, "gguf");
    assert.match(imported.checksum, /^sha256:/);

    const mounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: { model_id: "local:auto", id: "endpoint.test.local-auto" },
    });
    assert.equal(mounted.status, "mounted");

    const loaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
      method: "POST",
      token: grant.token,
      body: {
        endpoint_id: mounted.id,
        load_policy: { mode: "idle_evict", idleTtlSeconds: 0, autoEvict: true },
      },
    });
    assert.equal(loaded.status, "loaded");
    const loadedAfterTtl = await expectOk(daemon.endpoint, "/api/v1/models/loaded");
    assert.equal(loadedAfterTtl.length, 0);

    const chat = await expectOk(daemon.endpoint, "/api/v1/chat", {
      method: "POST",
      token: grant.token,
      body: { model: "local:auto", input: "hello native" },
    });
    assert.equal(chat.route_id, "route.local-first");
    assert.match(chat.output_text, /IOI model router fixture response/);
    const tokenListAfterUse = await expectOk(daemon.endpoint, "/api/v1/tokens");
    const usedGrant = tokenListAfterUse.find((token) => token.id === grant.id);
    assert.equal(typeof usedGrant.lastUsedAt, "string");
    assert.equal(JSON.stringify(tokenListAfterUse).includes(grant.token), false);

    const nativeMounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: { model_id: "native:imported", id: "endpoint.test.native-imported" },
    });
    assert.equal(nativeMounted.providerId, "provider.autopilot.local");
    const nativeLoaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
      method: "POST",
      token: grant.token,
      body: { endpoint_id: nativeMounted.id, load_policy: { mode: "on_demand", idleTtlSeconds: 900, autoEvict: true } },
    });
    assert.equal(nativeLoaded.backend, "autopilot.native_local.fixture");
    const nativeChat = await expectOk(daemon.endpoint, "/api/v1/chat", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.native-local", model: "native:imported", input: "hello autopilot native local" },
    });
    assert.match(nativeChat.output_text, /Autopilot native local model response/);
    const nativeReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${nativeChat.receipt_id}`);
    assert.equal(nativeReceipt.details.providerId, "provider.autopilot.local");
    assert.equal(nativeReceipt.details.backend, "autopilot.native_local.fixture");
    assert.equal(nativeReceipt.details.backendId, "backend.autopilot.native-local.fixture");
    assert.ok(nativeReceipt.details.backendEvidenceRefs.includes("autopilot_native_local_openai_compatible_serving"));
    const nativeBackendLogs = await expectOk(daemon.endpoint, "/api/v1/backends/backend.autopilot.native-local.fixture/logs");
    assert.ok(nativeBackendLogs.some((record) => record.event === "invoke"));

    const nativeCompat = await expectOk(daemon.endpoint, "/v1/chat/completions", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.native-local", model: "native:imported", messages: [{ role: "user", content: "compat native" }] },
    });
    assert.equal(nativeCompat.model, "native:imported");
    assert.match(nativeCompat.choices[0].message.content, /Autopilot native local model response/);

    const nativeBackendStart = await expectOk(daemon.endpoint, "/api/v1/backends/backend.autopilot.native-local.fixture/start", {
      method: "POST",
      token: grant.token,
    });
    assert.equal(nativeBackendStart.status, "available");
    assert.equal(nativeBackendStart.processStatus, "started");
    const nativeBackendStop = await expectOk(daemon.endpoint, "/api/v1/backends/backend.autopilot.native-local.fixture/stop", {
      method: "POST",
      token: grant.token,
    });
    assert.equal(nativeBackendStop.status, "stopped");
    assert.equal(nativeBackendStop.processStatus, "stopped");
    const nativeBackendLifecycleLogs = await expectOk(daemon.endpoint, "/api/v1/backends/backend.autopilot.native-local.fixture/logs");
    assert.ok(nativeBackendLifecycleLogs.some((record) => record.event === "backend_start"));
    assert.ok(nativeBackendLifecycleLogs.some((record) => record.event === "backend_stop"));

    const openAiModels = await expectOk(daemon.endpoint, "/v1/models", {
      token: grant.token,
    });
    assert.equal(openAiModels.object, "list");
    assert.ok(openAiModels.data.some((model) => model.id === "local:auto"));

    const compat = await expectOk(daemon.endpoint, "/v1/chat/completions", {
      method: "POST",
      token: grant.token,
      body: { model: "local:auto", messages: [{ role: "user", content: "hello compat" }] },
    });
    assert.equal(compat.choices[0].message.role, "assistant");
    assert.equal(compat.route_id, "route.local-first");

    const embeddings = await expectOk(daemon.endpoint, "/v1/embeddings", {
      method: "POST",
      token: grant.token,
      body: { model: "local:auto", input: ["alpha", "beta"] },
    });
    assert.equal(embeddings.data.length, 2);
    assert.equal(embeddings.data[0].embedding.length, 8);

    const mcpImport = await expectOk(daemon.endpoint, "/api/v1/mcp/import", {
      method: "POST",
      token: grant.token,
      body: {
        mcpServers: {
          huggingface: {
            url: "https://example.invalid/mcp",
            allowed_tools: ["model_search"],
            headers: { authorization: "vault://fixture/mcp/huggingface" },
          },
        },
      },
    });
    assert.equal(mcpImport.count, 1);

    const mcpServers = await expectOk(daemon.endpoint, "/api/v1/mcp");
    assert.equal(mcpServers[0].redactedHeaders.authorization, "[REDACTED]");
    assert.equal(JSON.stringify(mcpServers).includes("vault://fixture/mcp/huggingface"), false);

    const tool = await expectOk(daemon.endpoint, "/api/v1/mcp/invoke", {
      method: "POST",
      token: grant.token,
      body: { server_label: "huggingface", tool: "model_search", input: { q: "qwen" } },
    });
    assert.equal(tool.result.ok, true);
    assert.equal(tool.receipt.kind, "mcp_tool_invocation");

    const ephemeralMcpResponse = await expectOk(daemon.endpoint, "/api/v1/responses", {
      method: "POST",
      token: grant.token,
      body: {
        route_id: "route.local-first",
        input: "Find a model through ephemeral MCP and answer locally.",
        integrations: [
          {
            type: "ephemeral_mcp",
            server_label: "huggingface",
            server_url: "https://example.invalid/mcp",
            allowed_tools: ["model_search"],
            headers: { authorization: "vault://fixture/mcp/ephemeral-huggingface" },
          },
        ],
      },
    });
    assert.equal(ephemeralMcpResponse.tool_receipt_ids.length, 1);
    const ephemeralReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${ephemeralMcpResponse.receipt_id}`);
    assert.deepEqual(ephemeralReceipt.details.toolReceiptIds, ephemeralMcpResponse.tool_receipt_ids);
    assert.equal(JSON.stringify(ephemeralReceipt).includes("vault://fixture/mcp/ephemeral-huggingface"), false);

    const routeTest = await expectOk(daemon.endpoint, "/api/v1/routes/route.local-first/test", {
      method: "POST",
      token: grant.token,
      body: { capability: "chat", model_policy: { privacy: "local_only" } },
    });
    assert.equal(routeTest.selection.endpoint.modelId, "local:auto");

    await expectOk(daemon.endpoint, "/api/v1/models/import", {
      method: "POST",
      token: grant.token,
      body: { model_id: "hosted:test", provider_id: "provider.openai", capabilities: ["chat"], privacy_class: "hosted" },
    });
    await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: { model_id: "hosted:test", id: "endpoint.hosted.test", provider_id: "provider.openai" },
    });
    await expectOk(daemon.endpoint, "/api/v1/routes", {
      method: "POST",
      token: grant.token,
      body: {
        id: "route.hosted.blocked",
        role: "planner",
        fallback: ["endpoint.hosted.test"],
        denied_providers: [],
        provider_eligibility: ["openai"],
        privacy: "local_or_enterprise",
      },
    });
    const hostedBlocked = await requestJson(daemon.endpoint, "/api/v1/routes/route.hosted.blocked/test", {
      method: "POST",
      token: grant.token,
      body: { capability: "chat", model_policy: { privacy: "local_or_enterprise" } },
    });
    assert.equal(hostedBlocked.response.status, 424);

    const workflowCall = await expectOk(daemon.endpoint, "/api/v1/workflows/nodes/execute", {
      method: "POST",
      token: grant.token,
      body: { node: "Model Call", input: "workflow probe", model_policy: { privacy: "local_only" } },
    });
    assert.equal(workflowCall.status, "executed");
    assert.equal(workflowCall.invocation.route_id, "route.local-first");

    const gate = await expectOk(daemon.endpoint, "/api/v1/workflows/receipt-gate", {
      method: "POST",
      body: {
        receipt_id: ephemeralMcpResponse.receipt_id,
        redaction: "redacted",
        route_id: "route.local-first",
        selected_model: "local:auto",
        selected_endpoint: "endpoint.local.auto",
        selected_backend: "backend.fixture",
        required_tool_receipt_ids: ephemeralMcpResponse.tool_receipt_ids,
      },
    });
    assert.equal(gate.status, "passed");

    const blockedGate = await requestJson(daemon.endpoint, "/api/v1/workflows/receipt-gate", {
      method: "POST",
      body: {
        receipt_id: ephemeralMcpResponse.receipt_id,
        route_id: "route.mismatch",
      },
    });
    assert.equal(blockedGate.response.status, 412);

    const revoked = await expectOk(daemon.endpoint, `/api/v1/tokens/${grant.id}`, {
      method: "DELETE",
    });
    assert.equal(typeof revoked.revokedAt, "string");
    const revokedUse = await requestJson(daemon.endpoint, "/api/v1/chat", {
      method: "POST",
      token: grant.token,
      body: { input: "after revoke" },
    });
    assert.equal(revokedUse.response.status, 403);

    const receipts = await expectOk(daemon.endpoint, "/api/v1/receipts");
    assert.ok(receipts.some((receipt) => receipt.kind === "model_lifecycle"));
    assert.ok(
      receipts.some(
        (receipt) =>
          receipt.details?.operation === "backend_start" &&
          receipt.details?.backendId === "backend.autopilot.native-local.fixture",
      ),
    );
    assert.ok(
      receipts.some(
        (receipt) =>
          receipt.details?.operation === "backend_stop" &&
          receipt.details?.backendId === "backend.autopilot.native-local.fixture",
      ),
    );
    assert.ok(receipts.some((receipt) => receipt.kind === "model_route_selection"));
    assert.ok(receipts.some((receipt) => receipt.kind === "model_invocation"));
    assert.ok(receipts.some((receipt) => receipt.kind === "mcp_tool_invocation"));
    assert.ok(receipts.some((receipt) => receipt.kind === "workflow_receipt_gate"));
    assert.equal(JSON.stringify(receipts).includes("vault://fixture/mcp/huggingface"), false);
    const receiptById = await expectOk(daemon.endpoint, `/api/v1/receipts/${workflowCall.receipt.id}`);
    assert.equal(receiptById.id, workflowCall.receipt.id);

    const legacyModels = await expectOk(daemon.endpoint, "/v1/models");
    assert.equal(Array.isArray(legacyModels), true);
    assert.equal(legacyModels[0].provider, "ioi-daemon-local");
  } finally {
    await daemon.close();
  }
});

test("model download lifecycle supports progress, failure, cancel, cleanup, and projection replay", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-download-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-download-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: { allowed: ["model.download:*", "model.import:*", "model.chat:*", "route.use:*"] },
    });

    const completed = await expectOk(daemon.endpoint, "/api/v1/models/download", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "native:downloaded",
        provider_id: "provider.autopilot.local",
        source_url: "fixture://model/native-downloaded",
        fixture_content: "family=native-downloaded\ncontext=2048\nquantization=Q4_K_M\n",
      },
    });
    assert.equal(completed.status, "completed");
    assert.equal(completed.progress, 1);
    assert.equal(completed.bytesCompleted, completed.bytesTotal);
    assert.match(completed.checksum, /^sha256:/);
    assert.equal(completed.receiptIds.length, 3);
    assert.equal(fs.existsSync(completed.targetPath), true);

    const completedStatus = await expectOk(daemon.endpoint, `/api/v1/models/download/status/${completed.id}`);
    assert.equal(completedStatus.status, "completed");

    const failed = await expectOk(daemon.endpoint, "/api/v1/models/download", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "native:download-fails",
        provider_id: "provider.autopilot.local",
        source_url: "fixture://model/fails",
        simulate_failure: true,
      },
    });
    assert.equal(failed.status, "failed");
    assert.equal(failed.failureReason, "deterministic_fixture_failure");

    const queued = await expectOk(daemon.endpoint, "/api/v1/models/download", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "native:download-queued",
        provider_id: "provider.autopilot.local",
        source_url: "fixture://model/queued",
        queued_only: true,
      },
    });
    assert.equal(queued.status, "queued");
    const canceled = await expectOk(daemon.endpoint, `/api/v1/models/download/cancel/${queued.id}`, {
      method: "POST",
      token: grant.token,
    });
    assert.equal(canceled.status, "canceled");
    assert.equal(fs.existsSync(canceled.targetPath), false);

    const receipts = await expectOk(daemon.endpoint, "/api/v1/receipts");
    assert.ok(receipts.some((receipt) => receipt.details?.operation === "model_download_completed"));
    assert.ok(receipts.some((receipt) => receipt.details?.operation === "model_download_failed"));
    assert.ok(receipts.some((receipt) => receipt.details?.operation === "model_download_canceled"));

    const replay = await expectOk(daemon.endpoint, `/api/v1/receipts/${completed.receiptId}/replay`);
    assert.equal(replay.receipt.id, completed.receiptId);
    assert.equal(replay.source, "agentgres_model_mounting_projection_replay");
    assert.ok(replay.projectionWatermark > 0);

    const projection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
    assert.ok(projection.downloads.some((job) => job.id === completed.id));
    assert.ok(projection.artifacts.some((artifact) => artifact.modelId === "native:downloaded"));
    assert.equal(projection.adapterBoundaries.wallet.port, "WalletAuthorityPort");
    assert.equal(projection.adapterBoundaries.agentgres.port, "AgentgresModelMountingStorePort");
    assert.equal(projection.adapterBoundaries.wallet.remoteAdapter.failClosed, true);
    assert.equal(JSON.stringify(projection).includes("fixture://model/queued?api_key"), false);
  } finally {
    await daemon.close();
  }
});

test("Agentgres model mounting projection and receipt lookup survive daemon restart", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-replay-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-replay-state-"));
  let daemon = await startRuntimeDaemonService({ cwd, stateDir });
  let receiptId;
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: { allowed: ["model.chat:*", "route.use:*"] },
    });
    const chat = await expectOk(daemon.endpoint, "/api/v1/chat", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.native-local", model: "autopilot:native-fixture", input: "restart replay" },
    });
    receiptId = chat.receipt_id;
    const projection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
    assert.ok(projection.invocationReceipts.some((receipt) => receipt.id === receiptId));
  } finally {
    await daemon.close();
  }

  daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const receipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${receiptId}`);
    assert.equal(receipt.id, receiptId);
    assert.equal(receipt.details.routeId, "route.native-local");
    const replay = await expectOk(daemon.endpoint, `/api/v1/receipts/${receiptId}/replay`);
    assert.equal(replay.receipt.id, receiptId);
    assert.equal(replay.route.id, "route.native-local");
    assert.equal(replay.endpoint.modelId, "autopilot:native-fixture");
  } finally {
    await daemon.close();
  }
});

test("Ollama provider adapter lists models, invokes through policy, and redacts provider errors", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-ollama-provider-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-ollama-provider-state-"));
  const providerServer = await startFakeOllamaServer();
  const errorServer = await startFakeOllamaServer({ chatStatus: 500, secret: "ollama-provider-secret-token" });
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: {
        allowed: [
          "provider.write:*",
          "model.import:*",
          "model.mount:*",
          "model.load:*",
          "model.chat:*",
          "model.embeddings:*",
          "route.write:*",
          "route.use:*",
        ],
      },
    });

    await expectOk(daemon.endpoint, "/api/v1/providers", {
      method: "POST",
      token: grant.token,
      body: {
        id: "provider.test.ollama",
        kind: "ollama",
        label: "Fake Ollama",
        api_format: "ollama",
        base_url: providerServer.endpoint,
        status: "configured",
        privacy_class: "local_private",
        capabilities: ["chat", "embeddings"],
      },
    });
    const health = await expectOk(daemon.endpoint, "/api/v1/providers/provider.test.ollama/health", { method: "POST" });
    assert.equal(health.status, "available");
    assert.equal(health.discovery.lastHealthCheck.httpStatus, 200);

    const providerModels = await expectOk(daemon.endpoint, "/api/v1/providers/provider.test.ollama/models");
    assert.ok(providerModels.some((model) => model.modelId === "qwen3:8b"));
    const mounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "qwen3:8b",
        provider_id: "provider.test.ollama",
        id: "endpoint.test.ollama",
      },
    });
    assert.equal(mounted.backendId, "backend.ollama");

    await expectOk(daemon.endpoint, "/api/v1/routes", {
      method: "POST",
      token: grant.token,
      body: {
        id: "route.test.ollama",
        role: "ollama-test",
        privacy: "local_only",
        fallback: ["endpoint.test.ollama"],
        provider_eligibility: ["ollama"],
        denied_providers: [],
        max_cost_usd: 0,
      },
    });

    const chat = await expectOk(daemon.endpoint, "/api/v1/chat", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.test.ollama", input: "hello ollama" },
    });
    assert.equal(chat.route_id, "route.test.ollama");
    assert.equal(chat.backend_id, "backend.ollama");
    assert.match(chat.output_text, /fake ollama chat/);

    const embeddings = await expectOk(daemon.endpoint, "/api/v1/embeddings", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.test.ollama", input: "embed ollama" },
    });
    assert.deepEqual(embeddings.embeddings[0].embedding, [0.12, 0.34, 0.56]);

    const receipts = await expectOk(daemon.endpoint, "/api/v1/receipts");
    const invocation = receipts.find(
      (receipt) =>
        receipt.kind === "model_invocation" &&
        receipt.details?.providerId === "provider.test.ollama" &&
        receipt.details?.providerResponseKind === "ollama.chat",
    );
    assert.equal(invocation.details.backend, "ollama");
    assert.equal(invocation.details.backendId, "backend.ollama");

    await expectOk(daemon.endpoint, "/api/v1/providers", {
      method: "POST",
      token: grant.token,
      body: {
        id: "provider.test.ollama-error",
        kind: "ollama",
        label: "Fake Ollama Error",
        api_format: "ollama",
        base_url: errorServer.endpoint,
        status: "configured",
        privacy_class: "local_private",
        capabilities: ["chat"],
      },
    });
    await expectOk(daemon.endpoint, "/api/v1/models/import", {
      method: "POST",
      token: grant.token,
      body: { model_id: "ollama:error", provider_id: "provider.test.ollama-error", capabilities: ["chat"] },
    });
    await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "ollama:error",
        provider_id: "provider.test.ollama-error",
        id: "endpoint.test.ollama-error",
      },
    });
    await expectOk(daemon.endpoint, "/api/v1/routes", {
      method: "POST",
      token: grant.token,
      body: {
        id: "route.test.ollama-error",
        role: "ollama-error-test",
        privacy: "local_only",
        fallback: ["endpoint.test.ollama-error"],
        provider_eligibility: ["ollama"],
        denied_providers: [],
      },
    });
    const failed = await requestJson(daemon.endpoint, "/api/v1/chat", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.test.ollama-error", input: "trigger provider failure" },
    });
    assert.equal(failed.response.status, 424);
    assert.equal(failed.json.error.details.providerKind, "ollama");
    assert.equal(typeof failed.json.error.details.providerErrorHash, "string");
    assert.equal(JSON.stringify(failed.json).includes("ollama-provider-secret-token"), false);
  } finally {
    await daemon.close();
    await providerServer.close();
    await errorServer.close();
  }
});

test("vLLM and OpenAI-compatible adapters support responses fallback, embeddings, and redacted provider errors", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-vllm-provider-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-vllm-provider-state-"));
  const optionalAuthVaultRef = "vault://provider/openai-compatible/api-key";
  const optionalAuthMaterial = crypto.randomBytes(18).toString("base64url");
  const providerServer = await startFakeVllmServer({ responsesStatus: 404 });
  const optionalAuthServer = await startFakeVllmServer({
    requiredHeaders: { authorization: `Bearer ${optionalAuthMaterial}` },
  });
  const errorServer = await startFakeVllmServer({ chatStatus: 500, secret: "vllm-provider-secret-token" });
  const daemon = await startRuntimeDaemonService({
    cwd,
    stateDir,
    vaultSecrets: { [optionalAuthVaultRef]: optionalAuthMaterial },
  });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: {
        allowed: [
          "provider.write:*",
          "model.import:*",
          "model.mount:*",
          "model.load:*",
          "model.chat:*",
          "model.responses:*",
          "model.embeddings:*",
          "route.write:*",
          "route.use:*",
        ],
      },
    });

    await expectOk(daemon.endpoint, "/api/v1/providers", {
      method: "POST",
      token: grant.token,
      body: {
        id: "provider.test.vllm",
        kind: "vllm",
        label: "Fake vLLM",
        api_format: "openai_compatible",
        base_url: `${providerServer.endpoint}/v1`,
        status: "configured",
        privacy_class: "workspace",
        capabilities: ["chat", "responses", "embeddings"],
      },
    });
    const health = await expectOk(daemon.endpoint, "/api/v1/providers/provider.test.vllm/health", { method: "POST" });
    assert.equal(health.status, "available");

    const providerModels = await expectOk(daemon.endpoint, "/api/v1/providers/provider.test.vllm/models");
    assert.ok(providerModels.some((model) => model.modelId === "vllm-qwen"));

    await expectOk(daemon.endpoint, "/api/v1/providers", {
      method: "POST",
      token: grant.token,
      body: {
        id: "provider.test.openai-compatible-auth",
        kind: "openai_compatible",
        label: "Authenticated OpenAI-compatible",
        api_format: "openai_compatible",
        base_url: `${optionalAuthServer.endpoint}/v1`,
        status: "configured",
        privacy_class: "workspace",
        capabilities: ["chat"],
        secret_ref: optionalAuthVaultRef,
      },
    });
    const optionalAuthModels = await expectOk(daemon.endpoint, "/api/v1/providers/provider.test.openai-compatible-auth/models");
    assert.ok(optionalAuthModels.some((model) => model.modelId === "vllm-qwen"));
    assert.ok(optionalAuthServer.observedHeaders().some((headers) => headers.authorization === `Bearer ${optionalAuthMaterial}`));
    assert.equal(JSON.stringify(optionalAuthModels).includes(optionalAuthVaultRef), false);
    assert.equal(JSON.stringify(optionalAuthModels).includes(optionalAuthMaterial), false);

    const mounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "vllm-qwen",
        provider_id: "provider.test.vllm",
        id: "endpoint.test.vllm",
      },
    });
    assert.equal(mounted.backendId, "backend.vllm");

    await expectOk(daemon.endpoint, "/api/v1/routes", {
      method: "POST",
      token: grant.token,
      body: {
        id: "route.test.vllm",
        role: "vllm-test",
        privacy: "local_or_enterprise",
        fallback: ["endpoint.test.vllm"],
        provider_eligibility: ["vllm"],
        denied_providers: [],
        max_cost_usd: 0.25,
      },
    });

    const response = await expectOk(daemon.endpoint, "/api/v1/responses", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.test.vllm", input: "fallback from responses" },
    });
    assert.equal(response.route_id, "route.test.vllm");
    assert.equal(response.backend_id, "backend.vllm");
    assert.equal(response.compat_translation, "chat_completions");
    assert.match(response.output_text, /fake vllm chat/);

    const embeddings = await expectOk(daemon.endpoint, "/v1/embeddings", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.test.vllm", input: ["alpha", "beta"] },
    });
    assert.deepEqual(embeddings.data[0].embedding, [0.91, 0.82, 0.73]);

    const receipts = await expectOk(daemon.endpoint, "/api/v1/receipts");
    const invocation = receipts.find(
      (receipt) =>
        receipt.kind === "model_invocation" &&
        receipt.details?.providerId === "provider.test.vllm" &&
        receipt.details?.compatTranslation === "chat_completions",
    );
    assert.equal(invocation.details.backend, "openai_compatible");
    assert.equal(invocation.details.backendId, "backend.vllm");
    assert.equal(invocation.details.providerResponseKind, "chat.completions");

    await expectOk(daemon.endpoint, "/api/v1/providers", {
      method: "POST",
      token: grant.token,
      body: {
        id: "provider.test.openai-compatible-error",
        kind: "openai_compatible",
        label: "Fake OpenAI-compatible Error",
        api_format: "openai_compatible",
        base_url: `${errorServer.endpoint}/v1`,
        status: "configured",
        privacy_class: "workspace",
        capabilities: ["chat"],
      },
    });
    await expectOk(daemon.endpoint, "/api/v1/models/import", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "openai-compatible:error",
        provider_id: "provider.test.openai-compatible-error",
        capabilities: ["chat"],
        privacy_class: "workspace",
      },
    });
    await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "openai-compatible:error",
        provider_id: "provider.test.openai-compatible-error",
        id: "endpoint.test.openai-compatible-error",
      },
    });
    await expectOk(daemon.endpoint, "/api/v1/routes", {
      method: "POST",
      token: grant.token,
      body: {
        id: "route.test.openai-compatible-error",
        role: "openai-compatible-error-test",
        privacy: "local_or_enterprise",
        fallback: ["endpoint.test.openai-compatible-error"],
        provider_eligibility: ["openai_compatible"],
        denied_providers: [],
      },
    });
    const failed = await requestJson(daemon.endpoint, "/api/v1/chat", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.test.openai-compatible-error", input: "trigger provider failure" },
    });
    assert.equal(failed.response.status, 424);
    assert.equal(failed.json.error.details.providerKind, "openai_compatible");
    assert.equal(typeof failed.json.error.details.providerErrorHash, "string");
    assert.equal(JSON.stringify(failed.json).includes("vllm-provider-secret-token"), false);
  } finally {
    await daemon.close();
    await providerServer.close();
    await optionalAuthServer.close();
    await errorServer.close();
  }
});

test("hosted and custom HTTP provider auth fails closed behind wallet vault refs", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-provider-vault-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-provider-vault-state-"));
  const vaultRef = "vault://provider/custom-http/api-key";
  const vaultMaterial = crypto.randomBytes(18).toString("base64url");
  const providerServer = await startFakeVllmServer({
    responsesStatus: 404,
    requiredHeaders: { "x-api-key": vaultMaterial },
  });
  let daemon = await startRuntimeDaemonService({
    cwd,
    stateDir,
  });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: {
        allowed: [
          "provider.write:*",
          "vault.write:*",
          "vault.read:*",
          "vault.delete:*",
          "model.import:*",
          "model.mount:*",
          "model.load:*",
          "model.chat:*",
          "route.write:*",
          "route.use:*",
        ],
      },
    });

    const plaintextSecret = "sk-provider-plaintext-secret";
    const rejectedPlaintext = await requestJson(daemon.endpoint, "/api/v1/providers", {
      method: "POST",
      token: grant.token,
      body: {
        id: "provider.test.custom-plaintext",
        kind: "custom_http",
        label: "Plaintext Custom HTTP",
        base_url: `${providerServer.endpoint}/v1`,
        api_key: plaintextSecret,
      },
    });
    assert.equal(rejectedPlaintext.response.status, 403);
    assert.equal(JSON.stringify(rejectedPlaintext.json).includes(plaintextSecret), false);

    const rejectedMalformedVault = await requestJson(daemon.endpoint, "/api/v1/providers", {
      method: "POST",
      token: grant.token,
      body: {
        id: "provider.test.custom-malformed-vault",
        kind: "custom_http",
        label: "Malformed Custom HTTP",
        base_url: `${providerServer.endpoint}/v1`,
        secret_ref: "plain-secret-value",
      },
    });
    assert.equal(rejectedMalformedVault.response.status, 403);
    assert.equal(JSON.stringify(rejectedMalformedVault.json).includes("plain-secret-value"), false);

    const blocked = await expectOk(daemon.endpoint, "/api/v1/providers", {
      method: "POST",
      token: grant.token,
      body: {
        id: "provider.test.custom-blocked",
        kind: "custom_http",
        label: "Blocked Custom HTTP",
        api_format: "openai_compatible",
        base_url: `${providerServer.endpoint}/v1`,
        status: "configured",
        privacy_class: "workspace",
        capabilities: ["chat"],
      },
    });
    assert.equal(blocked.status, "blocked");
    assert.equal(blocked.secretConfigured, false);
    assert.equal(blocked.vaultBoundary.failClosed, true);

    const blockedHealth = await requestJson(daemon.endpoint, "/api/v1/providers/provider.test.custom-blocked/health", {
      method: "POST",
    });
    assert.equal(blockedHealth.response.status, 403);

    const rejectedForbiddenAuthHeader = await requestJson(daemon.endpoint, "/api/v1/providers", {
      method: "POST",
      token: grant.token,
      body: {
        id: "provider.test.custom-forbidden-auth-header",
        kind: "custom_http",
        label: "Forbidden Auth Header",
        api_format: "openai_compatible",
        base_url: `${providerServer.endpoint}/v1`,
        secret_ref: vaultRef,
        auth_header_name: "content-length",
      },
    });
    assert.equal(rejectedForbiddenAuthHeader.response.status, 400);
    assert.equal(JSON.stringify(rejectedForbiddenAuthHeader.json).includes(vaultRef), false);

    await expectOk(daemon.endpoint, "/api/v1/models/import", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "custom-http:blocked",
        provider_id: "provider.test.custom-blocked",
        capabilities: ["chat"],
        privacy_class: "workspace",
      },
    });
    await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "custom-http:blocked",
        provider_id: "provider.test.custom-blocked",
        id: "endpoint.test.custom-blocked",
      },
    });
    await expectOk(daemon.endpoint, "/api/v1/routes", {
      method: "POST",
      token: grant.token,
      body: {
        id: "route.test.custom-blocked",
        role: "custom-blocked-test",
        privacy: "local_or_enterprise",
        fallback: ["endpoint.test.custom-blocked"],
        provider_eligibility: ["custom_http"],
        denied_providers: [],
      },
    });
    const blockedChat = await requestJson(daemon.endpoint, "/api/v1/chat", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.test.custom-blocked", input: "must fail closed" },
    });
    assert.equal(blockedChat.response.status, 403);
    assert.equal(blockedChat.json.error.details.vaultRefConfigured, false);

    const configured = await expectOk(daemon.endpoint, "/api/v1/providers", {
      method: "POST",
      token: grant.token,
      body: {
        id: "provider.test.custom-vault",
        kind: "custom_http",
        label: "Vault Custom HTTP",
        api_format: "openai_compatible",
        base_url: `${providerServer.endpoint}/v1`,
        status: "configured",
        privacy_class: "workspace",
        capabilities: ["chat", "responses", "embeddings"],
        secret_ref: vaultRef,
        auth_scheme: "api_key",
        auth_header_name: "x-api-key",
      },
    });
    assert.equal(configured.status, "configured");
    assert.equal(configured.secretConfigured, true);
    assert.equal(configured.secretRef.redacted, true);
    assert.equal(configured.authScheme, "api_key");
    assert.equal(configured.authHeaderName, "x-api-key");
    assert.equal(JSON.stringify(configured).includes(vaultRef), false);

    const unresolvedHealth = await requestJson(daemon.endpoint, "/api/v1/providers/provider.test.custom-vault/health", { method: "POST" });
    assert.equal(unresolvedHealth.response.status, 403);
    assert.equal(unresolvedHealth.json.error.details.resolvedMaterial, false);
    assert.equal(unresolvedHealth.json.error.details.providerHealthStatus, "blocked");
    assert.equal(typeof unresolvedHealth.json.error.details.providerHealthReceiptId, "string");
    assert.equal(JSON.stringify(unresolvedHealth.json).includes(vaultRef), false);
    assert.equal(JSON.stringify(unresolvedHealth.json).includes(vaultMaterial), false);
    const unresolvedHealthReceipt = await expectOk(
      daemon.endpoint,
      `/api/v1/receipts/${unresolvedHealth.json.error.details.providerHealthReceiptId}`,
    );
    assert.equal(unresolvedHealthReceipt.kind, "provider_health");
    assert.equal(unresolvedHealthReceipt.details.status, "blocked");
    assert.equal(JSON.stringify(unresolvedHealthReceipt).includes(vaultRef), false);
    const providerAfterBlockedHealth = (await expectOk(daemon.endpoint, "/api/v1/providers")).find(
      (provider) => provider.id === "provider.test.custom-vault",
    );
    assert.equal(providerAfterBlockedHealth.status, "blocked");
    assert.equal(providerAfterBlockedHealth.discovery.lastHealthCheck.status, "blocked");
    assert.equal(providerAfterBlockedHealth.discovery.lastHealthCheck.receiptId, unresolvedHealthReceipt.id);

    const bound = await expectOk(daemon.endpoint, "/api/v1/vault/refs", {
      method: "POST",
      token: grant.token,
      body: {
        vault_ref: vaultRef,
        material: vaultMaterial,
        purpose: "provider.auth:provider.test.custom-vault",
        label: "Vault Custom HTTP",
      },
    });
    assert.equal(bound.configured, true);
    assert.equal(bound.vaultRef.redacted, true);
    assert.equal(typeof bound.vaultRefHash, "string");
    assert.equal(typeof bound.receiptId, "string");
    assert.equal(JSON.stringify(bound).includes(vaultRef), false);
    assert.equal(JSON.stringify(bound).includes(vaultMaterial), false);

    const vaultRefs = await expectOk(daemon.endpoint, "/api/v1/vault/refs", { token: grant.token });
    assert.ok(vaultRefs.some((ref) => ref.vaultRefHash === bound.vaultRefHash));
    assert.equal(JSON.stringify(vaultRefs).includes(vaultRef), false);
    assert.equal(JSON.stringify(vaultRefs).includes(vaultMaterial), false);

    const vaultMeta = await expectOk(daemon.endpoint, "/api/v1/vault/refs/meta", {
      method: "POST",
      token: grant.token,
      body: { vault_ref: vaultRef },
    });
    assert.equal(vaultMeta.configured, true);
    assert.equal(vaultMeta.vaultRefHash, bound.vaultRefHash);
    assert.equal(JSON.stringify(vaultMeta).includes(vaultRef), false);
    assert.equal(JSON.stringify(vaultMeta).includes(vaultMaterial), false);
    assert.equal(directoryContainsNeedle(stateDir, vaultMaterial), false);

    const providers = await expectOk(daemon.endpoint, "/api/v1/providers");
    assert.equal(JSON.stringify(providers).includes(vaultRef), false);
    const publicProvider = providers.find((provider) => provider.id === "provider.test.custom-vault");
    assert.equal(publicProvider.secretConfigured, true);
    assert.equal(publicProvider.secretRef.redacted, true);
    assert.equal(publicProvider.authScheme, "api_key");
    assert.equal(publicProvider.authHeaderName, "x-api-key");

    const snapshot = await expectOk(daemon.endpoint, "/api/v1/models");
    assert.equal(JSON.stringify(snapshot.providers).includes(vaultRef), false);
    const projection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
    assert.equal(JSON.stringify(projection.providers).includes(vaultRef), false);

    const health = await expectOk(daemon.endpoint, "/api/v1/providers/provider.test.custom-vault/health", { method: "POST" });
    assert.equal(health.status, "available");
    assert.equal(health.vaultBoundary.runtimeBound, true);
    assert.equal(typeof health.discovery.lastHealthCheck.authVaultRefHash, "string");
    assert.equal(typeof health.discovery.lastHealthCheck.receiptId, "string");
    const providerHealthReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${health.discovery.lastHealthCheck.receiptId}`);
    assert.equal(providerHealthReceipt.kind, "provider_health");
    assert.equal(providerHealthReceipt.details.status, "available");
    assert.equal(JSON.stringify(health).includes(vaultRef), false);
    assert.equal(JSON.stringify(health).includes(vaultMaterial), false);
    assert.equal(JSON.stringify(providerHealthReceipt).includes(vaultMaterial), false);

    const providerModels = await expectOk(daemon.endpoint, "/api/v1/providers/provider.test.custom-vault/models");
    assert.ok(providerModels.some((model) => model.modelId === "vllm-qwen"));
    assert.ok(providerServer.observedHeaders().some((headers) => headers["x-api-key"] === vaultMaterial));
    await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "vllm-qwen",
        provider_id: "provider.test.custom-vault",
        id: "endpoint.test.custom-vault",
      },
    });
    await expectOk(daemon.endpoint, "/api/v1/routes", {
      method: "POST",
      token: grant.token,
      body: {
        id: "route.test.custom-vault",
        role: "custom-vault-test",
        privacy: "local_or_enterprise",
        fallback: ["endpoint.test.custom-vault"],
        provider_eligibility: ["custom_http"],
        denied_providers: [],
      },
    });
    const chat = await expectOk(daemon.endpoint, "/api/v1/chat", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.test.custom-vault", input: "vault backed custom provider" },
    });
    assert.equal(chat.route_id, "route.test.custom-vault");
    const receipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${chat.receipt_id}`);
    assert.equal(receipt.details.providerId, "provider.test.custom-vault");
    assert.equal(typeof receipt.details.authVaultRefHash, "string");
    assert.ok(receipt.details.providerAuthEvidenceRefs.includes("VaultPort.resolveVaultRef"));
    assert.deepEqual(receipt.details.providerAuthHeaderNames, ["x-api-key"]);
    assert.equal(JSON.stringify(receipt).includes(vaultRef), false);
    assert.equal(JSON.stringify(receipt).includes(vaultMaterial), false);
    assert.ok(providerServer.observedHeaders().some((headers) => headers["x-api-key"] === vaultMaterial));
    const projectionAfterAuth = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
    assert.equal(projectionAfterAuth.adapterBoundaries.vault.port, "VaultPort");
    assert.equal(JSON.stringify(projectionAfterAuth).includes(vaultMaterial), false);
    assert.equal(directoryContainsNeedle(stateDir, vaultMaterial), false);

    await daemon.close();
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const restartedVaultRefs = await expectOk(daemon.endpoint, "/api/v1/vault/refs", { token: grant.token });
    const restartedMeta = restartedVaultRefs.find((ref) => ref.vaultRefHash === bound.vaultRefHash);
    assert.equal(restartedMeta.configured, true);
    assert.equal(restartedMeta.resolvedMaterial, false);
    assert.equal(restartedMeta.requiresRebind, true);
    assert.equal(JSON.stringify(restartedVaultRefs).includes(vaultRef), false);
    assert.equal(JSON.stringify(restartedVaultRefs).includes(vaultMaterial), false);
    assert.equal(directoryContainsNeedle(stateDir, vaultMaterial), false);
    const restartedProviders = await expectOk(daemon.endpoint, "/api/v1/providers");
    const restartedProvider = restartedProviders.find((provider) => provider.id === "provider.test.custom-vault");
    assert.equal(restartedProvider.secretConfigured, true);
    assert.equal(restartedProvider.vaultBoundary.requiresRuntimeBinding, true);
    const restartedHealth = await requestJson(daemon.endpoint, "/api/v1/providers/provider.test.custom-vault/health", { method: "POST" });
    assert.equal(restartedHealth.response.status, 403);
    assert.equal(restartedHealth.json.error.details.resolvedMaterial, false);
    assert.equal(JSON.stringify(restartedHealth.json).includes(vaultMaterial), false);
    const rebound = await expectOk(daemon.endpoint, "/api/v1/vault/refs", {
      method: "POST",
      token: grant.token,
      body: {
        vault_ref: vaultRef,
        material: vaultMaterial,
        purpose: "provider.auth:provider.test.custom-vault",
        label: "Vault Custom HTTP",
      },
    });
    assert.equal(rebound.configured, true);
    assert.equal(rebound.resolvedMaterial, true);
    const reboundHealth = await expectOk(daemon.endpoint, "/api/v1/providers/provider.test.custom-vault/health", { method: "POST" });
    assert.equal(reboundHealth.status, "available");

    const removed = await expectOk(daemon.endpoint, "/api/v1/vault/refs", {
      method: "DELETE",
      token: grant.token,
      body: { vault_ref: vaultRef },
    });
    assert.equal(removed.configured, false);
    assert.equal(JSON.stringify(removed).includes(vaultRef), false);
    assert.equal(JSON.stringify(removed).includes(vaultMaterial), false);
    const removedHealth = await requestJson(daemon.endpoint, "/api/v1/providers/provider.test.custom-vault/health", { method: "POST" });
    assert.equal(removedHealth.response.status, 403);
    assert.equal(removedHealth.json.error.details.resolvedMaterial, false);
  } finally {
    await daemon.close();
    await providerServer.close();
  }
});

test("encrypted keychain vault adapter persists material across daemon restart without Agentgres plaintext", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-keychain-vault-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-keychain-vault-state-"));
  const keychainDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-keychain-vault-material-"));
  const keychainPath = path.join(keychainDir, "vault-material.json");
  const vaultRef = "vault://provider/custom-http/keychain-api-key";
  const vaultMaterial = crypto.randomBytes(18).toString("base64url");
  const providerServer = await startFakeVllmServer({
    responsesStatus: 404,
    requiredHeaders: { "x-api-key": vaultMaterial },
  });
  const priorPath = process.env.IOI_KEYCHAIN_VAULT_PATH;
  const priorKey = process.env.IOI_KEYCHAIN_VAULT_KEY;
  process.env.IOI_KEYCHAIN_VAULT_PATH = keychainPath;
  process.env.IOI_KEYCHAIN_VAULT_KEY = crypto.randomBytes(32).toString("base64url");
  let daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: {
        allowed: [
          "provider.write:*",
          "vault.write:*",
          "vault.read:*",
          "vault.delete:*",
          "model.import:*",
          "model.mount:*",
          "model.chat:*",
          "route.write:*",
          "route.use:*",
        ],
      },
    });
    await expectOk(daemon.endpoint, "/api/v1/providers", {
      method: "POST",
      token: grant.token,
      body: {
        id: "provider.test.keychain-vault",
        kind: "custom_http",
        label: "Keychain Vault Custom HTTP",
        api_format: "openai_compatible",
        base_url: `${providerServer.endpoint}/v1`,
        status: "configured",
        privacy_class: "workspace",
        capabilities: ["chat"],
        secret_ref: vaultRef,
        auth_scheme: "api_key",
        auth_header_name: "x-api-key",
      },
    });
    const bound = await expectOk(daemon.endpoint, "/api/v1/vault/refs", {
      method: "POST",
      token: grant.token,
      body: {
        vault_ref: vaultRef,
        material: vaultMaterial,
        purpose: "provider.auth:provider.test.keychain-vault",
        label: "Keychain Vault Custom HTTP",
      },
    });
    assert.equal(bound.configured, true);
    assert.equal(bound.materialSource, "encrypted_keychain_vault_adapter");
    assert.equal(JSON.stringify(bound).includes(vaultMaterial), false);
    assert.equal(directoryContainsNeedle(stateDir, vaultMaterial), false);
    assert.equal(directoryContainsNeedle(keychainDir, vaultMaterial), false);
    const health = await expectOk(daemon.endpoint, "/api/v1/providers/provider.test.keychain-vault/health", { method: "POST" });
    assert.equal(health.status, "available");
    const projection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
    assert.equal(projection.adapterBoundaries.vault.materialAdapter.implementation, "encrypted_keychain_vault_adapter");
    assert.equal(projection.adapterBoundaries.vault.materialAdapter.configured, true);
    assert.equal(JSON.stringify(projection).includes(vaultMaterial), false);
    const adapterHealth = await expectOk(daemon.endpoint, "/api/v1/vault/health", { method: "POST", token: grant.token });
    assert.equal(adapterHealth.status, "healthy");
    assert.equal(adapterHealth.materialAdapter.readAvailable, true);
    assert.equal(adapterHealth.materialAdapter.writeAvailable, true);
    assert.equal(adapterHealth.materialAdapter.pathHash, projection.adapterBoundaries.vault.materialAdapter.pathHash);
    assert.equal(JSON.stringify(adapterHealth).includes(vaultMaterial), false);

    await daemon.close();
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const restartedHealth = await expectOk(daemon.endpoint, "/api/v1/providers/provider.test.keychain-vault/health", { method: "POST" });
    assert.equal(restartedHealth.status, "available");
    assert.ok(providerServer.observedHeaders().some((headers) => headers["x-api-key"] === vaultMaterial));
    const restartedMeta = await expectOk(daemon.endpoint, "/api/v1/vault/refs/meta", {
      method: "POST",
      token: grant.token,
      body: { vault_ref: vaultRef },
    });
    assert.equal(restartedMeta.configured, true);
    assert.equal(restartedMeta.resolvedMaterial, true);
    assert.equal(restartedMeta.materialSource, "encrypted_keychain_vault_adapter");
    assert.equal(JSON.stringify(restartedMeta).includes(vaultRef), false);
    assert.equal(JSON.stringify(restartedMeta).includes(vaultMaterial), false);
    assert.equal(directoryContainsNeedle(stateDir, vaultMaterial), false);
    assert.equal(directoryContainsNeedle(keychainDir, vaultMaterial), false);
  } finally {
    await daemon.close();
    await providerServer.close();
    restoreEnv("IOI_KEYCHAIN_VAULT_PATH", priorPath);
    restoreEnv("IOI_KEYCHAIN_VAULT_KEY", priorKey);
  }
});

test("configured keychain vault adapter fails closed when unavailable", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-keychain-vault-unavailable-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-keychain-vault-unavailable-state-"));
  const unavailablePath = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-keychain-vault-unavailable-dir-"));
  const vaultRef = "vault://provider/custom-http/unavailable-api-key";
  const priorPath = process.env.IOI_KEYCHAIN_VAULT_PATH;
  const priorKey = process.env.IOI_KEYCHAIN_VAULT_KEY;
  process.env.IOI_KEYCHAIN_VAULT_PATH = unavailablePath;
  process.env.IOI_KEYCHAIN_VAULT_KEY = crypto.randomBytes(32).toString("base64url");
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: { allowed: ["provider.write:*", "vault.read:*"] },
    });
    await expectOk(daemon.endpoint, "/api/v1/providers", {
      method: "POST",
      token: grant.token,
      body: {
        id: "provider.test.keychain-unavailable",
        kind: "custom_http",
        label: "Unavailable Keychain Provider",
        api_format: "openai_compatible",
        base_url: "http://127.0.0.1:9/v1",
        status: "configured",
        privacy_class: "workspace",
        capabilities: ["chat"],
        secret_ref: vaultRef,
      },
    });
    const health = await requestJson(daemon.endpoint, "/api/v1/providers/provider.test.keychain-unavailable/health", { method: "POST" });
    assert.equal(health.response.status, 424);
    assert.equal(health.json.error.details.adapter, "encrypted_keychain_vault_adapter");
    assert.equal(JSON.stringify(health.json).includes(vaultRef), false);
    const adapterHealth = await requestJson(daemon.endpoint, "/api/v1/vault/health", { method: "POST", token: grant.token });
    assert.equal(adapterHealth.response.status, 424);
    assert.equal(adapterHealth.json.error.details.adapter, "encrypted_keychain_vault_adapter");
  } finally {
    await daemon.close();
    restoreEnv("IOI_KEYCHAIN_VAULT_PATH", priorPath);
    restoreEnv("IOI_KEYCHAIN_VAULT_KEY", priorKey);
  }
});

test("LM Studio driver delegates load, responses fallback, embeddings, provider models, and receipts through public seams", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-lms-driver-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-lms-driver-state-"));
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-lms-driver-home-"));
  const binDir = path.join(homeDir, ".lmstudio", "bin");
  const callsPath = path.join(homeDir, "lms-calls.log");
  fs.mkdirSync(binDir, { recursive: true });
  const lmsPath = path.join(binDir, "lms");
  fs.writeFileSync(
    lmsPath,
    `#!/usr/bin/env sh
printf '%s\\n' "$*" >> "${callsPath}"
if [ "$1" = "server" ] && [ "$2" = "status" ]; then
  printf 'Server:  ON\\n'
  exit 0
fi
if [ "$1" = "ls" ]; then
  cat <<'MODELS'
LLM                            PARAMS    ARCH      SIZE       DEVICE
qwen/qwen3.5-9b (1 variant)    9B        qwen35    6.55 GB    Local

EMBEDDING                               PARAMS    ARCH          SIZE        DEVICE
text-embedding-nomic-embed-text-v1.5              Nomic BERT    84.11 MB    Local
MODELS
  exit 0
fi
if [ "$1" = "ps" ]; then
  printf 'MODEL                         CONTEXT\\nqwen/qwen3.5-9b              32768\\n'
  exit 0
fi
if [ "$1" = "load" ] || [ "$1" = "unload" ]; then
  exit 0
fi
exit 0
`,
  );
  fs.chmodSync(lmsPath, 0o755);
  const providerServer = await startFakeOpenAiCompatibleServer();
  const priorBaseUrl = process.env.LM_STUDIO_BASE_URL;
  process.env.LM_STUDIO_BASE_URL = `${providerServer.endpoint}/v1`;
  const daemon = await startRuntimeDaemonService({ cwd, stateDir, homeDir });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: {
        allowed: [
          "model.chat:*",
          "model.responses:*",
          "model.embeddings:*",
          "model.load:*",
          "model.unload:*",
          "model.mount:*",
          "route.use:*",
        ],
        denied: ["filesystem.write", "shell.exec"],
      },
    });

    const providerModels = await expectOk(daemon.endpoint, "/api/v1/providers/provider.lmstudio/models");
    assert.ok(providerModels.some((model) => model.modelId === "qwen/qwen3.5-9b"));

    const providerLoaded = await expectOk(daemon.endpoint, "/api/v1/providers/provider.lmstudio/loaded");
    assert.ok(providerLoaded.some((model) => model.modelId === "qwen/qwen3.5-9b"));

    const mounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: { model_id: "qwen/qwen3.5-9b", id: "endpoint.test.lmstudio" },
    });
    assert.equal(mounted.providerId, "provider.lmstudio");

    const loaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
      method: "POST",
      token: grant.token,
      body: { endpoint_id: mounted.id, load_policy: { mode: "manual", autoEvict: false } },
    });
    assert.equal(loaded.backend, "lm_studio");

    const response = await expectOk(daemon.endpoint, "/api/v1/responses", {
      method: "POST",
      token: grant.token,
      body: { model: "qwen/qwen3.5-9b", input: "fallback please" },
    });
    assert.match(response.output_text, /fake lm studio chat/);
    assert.equal(response.compat_translation, "chat_completions");

    const embeddings = await expectOk(daemon.endpoint, "/v1/embeddings", {
      method: "POST",
      token: grant.token,
      body: { model: "text-embedding-nomic-embed-text-v1.5", input: "embed me" },
    });
    assert.deepEqual(embeddings.data[0].embedding, [0.1, 0.2, 0.3]);

    const receipts = await expectOk(daemon.endpoint, "/api/v1/receipts");
    const invocation = receipts.find(
      (receipt) =>
        receipt.kind === "model_invocation" &&
        receipt.details?.selectedModel === "qwen/qwen3.5-9b",
    );
    assert.equal(invocation.details.compatTranslation, "chat_completions");
    assert.equal(invocation.details.backend, "lm_studio");
    assert.equal(JSON.stringify(receipts).includes("Authorization"), false);

    const calls = fs.readFileSync(callsPath, "utf8");
    assert.match(calls, /load qwen\/qwen3\.5-9b/);
    assert.match(calls, /^ps$/m);
  } finally {
    await daemon.close();
    await providerServer.close();
    if (priorBaseUrl === undefined) {
      delete process.env.LM_STUDIO_BASE_URL;
    } else {
      process.env.LM_STUDIO_BASE_URL = priorBaseUrl;
    }
  }
});

test("LM Studio load is idempotent when public lms reports the model already loaded", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-lms-idempotent-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-lms-idempotent-state-"));
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-lms-idempotent-home-"));
  const binDir = path.join(homeDir, ".lmstudio", "bin");
  const callsPath = path.join(homeDir, "lms-calls.log");
  fs.mkdirSync(binDir, { recursive: true });
  const lmsPath = path.join(binDir, "lms");
  fs.writeFileSync(
    lmsPath,
    `#!/usr/bin/env sh
printf '%s\\n' "$*" >> "${callsPath}"
if [ "$1" = "server" ] && [ "$2" = "status" ]; then
  printf 'The server is running on port 1234.\\n' >&2
  exit 0
fi
if [ "$1" = "ls" ]; then
  cat <<'MODELS'
LLM                            PARAMS    ARCH      SIZE       DEVICE
qwen/qwen3.5-9b (1 variant)    9B        qwen35    6.55 GB    Local     ✓ LOADED
MODELS
  exit 0
fi
if [ "$1" = "ps" ]; then
  printf 'IDENTIFIER         MODEL              STATUS\\nqwen/qwen3.5-9b    qwen/qwen3.5-9b    IDLE\\n'
  exit 0
fi
if [ "$1" = "load" ]; then
  printf 'Error: Failed to load model.\\n' >&2
  exit 1
fi
exit 0
`,
  );
  fs.chmodSync(lmsPath, 0o755);
  const daemon = await startRuntimeDaemonService({ cwd, stateDir, homeDir });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: {
        allowed: ["model.load:*", "model.mount:*"],
        denied: ["filesystem.write", "shell.exec"],
      },
    });
    const mounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "qwen/qwen3.5-9b",
        id: "endpoint.test.lmstudio.already-loaded",
        provider_id: "provider.lmstudio",
      },
    });
    const loaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
      method: "POST",
      token: grant.token,
      body: { endpoint_id: mounted.id, load_policy: { mode: "manual", autoEvict: false } },
    });

    assert.equal(loaded.backend, "lm_studio");
    assert.ok(loaded.providerEvidenceRefs.includes("lm_studio_public_lms_load_already_loaded"));
    assert.ok(loaded.providerEvidenceRefs.includes("lm_studio_public_lms_ps"));
    const calls = fs.readFileSync(callsPath, "utf8");
    assert.match(calls, /load qwen\/qwen3\.5-9b/);
    assert.match(calls, /^ps$/m);
  } finally {
    await daemon.close();
  }
});

async function startFakeOpenAiCompatibleServer() {
  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && url.pathname === "/v1/models") {
      response.end(JSON.stringify({ object: "list", data: [{ id: "qwen/qwen3.5-9b" }] }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/responses") {
      response.statusCode = 404;
      response.end(JSON.stringify({ error: { message: "responses unavailable" } }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
      response.end(
        JSON.stringify({
          id: "chatcmpl_fake_lmstudio",
          object: "chat.completion",
          model: "qwen/qwen3.5-9b",
          choices: [{ index: 0, message: { role: "assistant", content: "fake lm studio chat" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 2, completion_tokens: 4, total_tokens: 6 },
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/embeddings") {
      response.end(
        JSON.stringify({
          object: "list",
          data: [{ object: "embedding", index: 0, embedding: [0.1, 0.2, 0.3] }],
          usage: { prompt_tokens: 2, completion_tokens: 0, total_tokens: 2 },
        }),
      );
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: "not found" }));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  return {
    endpoint: `http://${address.address}:${address.port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

async function startFakeOllamaServer({ chatStatus = 200, secret = null } = {}) {
  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && url.pathname === "/api/tags") {
      response.end(
        JSON.stringify({
          models: [
            { name: "qwen3:8b", size: 4_900_000_000, digest: "sha256:fixture-qwen" },
            { name: "nomic-embed-text:latest", size: 274_000_000, digest: "sha256:fixture-embed" },
          ],
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/chat") {
      if (chatStatus !== 200) {
        response.statusCode = chatStatus;
        response.end(JSON.stringify({ error: `provider failed ${secret}` }));
        return;
      }
      response.end(
        JSON.stringify({
          model: "qwen3:8b",
          message: { role: "assistant", content: "fake ollama chat" },
          done: true,
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/embeddings") {
      response.end(JSON.stringify({ embedding: [0.12, 0.34, 0.56] }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: "not found" }));
  });
  await listen(server);
  const address = server.address();
  return {
    endpoint: `http://${address.address}:${address.port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

async function startFakeVllmServer({ responsesStatus = 200, chatStatus = 200, secret = null, requiredAuthorization = null, requiredHeaders = null } = {}) {
  const observedHeaders = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (requiredAuthorization || requiredHeaders) {
      observedHeaders.push({ ...request.headers });
      const missingRequiredHeader = requiredHeaders
        ? Object.entries(requiredHeaders).find(([name, value]) => request.headers[String(name).toLowerCase()] !== value)
        : null;
      if ((requiredAuthorization && request.headers.authorization !== requiredAuthorization) || missingRequiredHeader) {
        response.statusCode = 401;
        response.end(JSON.stringify({ error: { message: "provider auth failed" } }));
        return;
      }
    }
    if (request.method === "GET" && url.pathname === "/v1/models") {
      response.end(JSON.stringify({ object: "list", data: [{ id: "vllm-qwen" }] }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/responses") {
      if (responsesStatus !== 200) {
        response.statusCode = responsesStatus;
        response.end(JSON.stringify({ error: { message: `responses unavailable ${secret ?? ""}` } }));
        return;
      }
      response.end(
        JSON.stringify({
          id: "resp_fake_vllm",
          object: "response",
          model: "vllm-qwen",
          output_text: "fake vllm response",
          usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
      if (chatStatus !== 200) {
        response.statusCode = chatStatus;
        response.end(JSON.stringify({ error: { message: `chat failed ${secret}` } }));
        return;
      }
      response.end(
        JSON.stringify({
          id: "chatcmpl_fake_vllm",
          object: "chat.completion",
          model: "vllm-qwen",
          choices: [{ index: 0, message: { role: "assistant", content: "fake vllm chat" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 4, completion_tokens: 6, total_tokens: 10 },
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/embeddings") {
      response.end(
        JSON.stringify({
          object: "list",
          data: [{ object: "embedding", index: 0, embedding: [0.91, 0.82, 0.73] }],
          usage: { prompt_tokens: 2, completion_tokens: 0, total_tokens: 2 },
        }),
      );
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: "not found" }));
  });
  await listen(server);
  const address = server.address();
  return {
    endpoint: `http://${address.address}:${address.port}`,
    observedHeaders: () => observedHeaders.map((headers) => ({ ...headers })),
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
}

function directoryContainsNeedle(root, needle) {
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    const stat = fs.statSync(current);
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(current)) {
        pending.push(path.join(current, entry));
      }
      continue;
    }
    if (!stat.isFile() || stat.size > 5 * 1024 * 1024) continue;
    try {
      if (fs.readFileSync(current, "utf8").includes(needle)) return true;
    } catch {
      // Binary files are ignored for this redaction scan.
    }
  }
  return false;
}

function restoreEnv(name, priorValue) {
  if (priorValue === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = priorValue;
  }
}

test("LM Studio provider discovery uses guarded public lms commands for installed models", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-lms-discovery-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-lms-discovery-state-"));
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-lms-home-"));
  const binDir = path.join(homeDir, ".lmstudio", "bin");
  fs.mkdirSync(binDir, { recursive: true });
  const lmsPath = path.join(binDir, "lms");
  fs.writeFileSync(
    lmsPath,
    `#!/usr/bin/env sh
if [ "$1" = "server" ] && [ "$2" = "status" ]; then
  printf 'Server:  ON\\n'
  exit 0
fi
if [ "$1" = "ls" ]; then
  cat <<'MODELS'
You have 2 models, taking up 6.63 GB of disk space.

LLM                            PARAMS    ARCH      SIZE       DEVICE
qwen/qwen3.5-9b (1 variant)    9B        qwen35    6.55 GB    Local

EMBEDDING                               PARAMS    ARCH          SIZE        DEVICE
text-embedding-nomic-embed-text-v1.5              Nomic BERT    84.11 MB    Local
MODELS
  exit 0
fi
exit 0
`,
  );
  fs.chmodSync(lmsPath, 0o755);

  const daemon = await startRuntimeDaemonService({ cwd, stateDir, homeDir });
  try {
    const snapshot = await expectOk(daemon.endpoint, "/api/v1/models");
    const lmStudio = snapshot.providers.find((provider) => provider.kind === "lm_studio");
    assert.equal(lmStudio.status, "running");
    assert.ok(lmStudio.discovery.publicCli.serverStatus.includes("Server:  ON"));
    assert.ok(snapshot.artifacts.some((model) => model.modelId === "qwen/qwen3.5-9b"));
    assert.ok(
      snapshot.artifacts.some(
        (model) =>
          model.modelId === "text-embedding-nomic-embed-text-v1.5" &&
          model.capabilities.includes("embeddings"),
      ),
    );
  } finally {
    await daemon.close();
  }
});
