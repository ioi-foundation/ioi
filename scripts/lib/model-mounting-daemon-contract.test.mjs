import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

async function requestJson(endpoint, route, { method = "GET", body, token, headers = {} } = {}) {
  const response = await fetch(`${endpoint}${route}`, {
    method,
    headers: {
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  const json = text ? JSON.parse(text) : undefined;
  return { response, json };
}

async function requestSse(endpoint, route, { method = "POST", body, token, headers = {} } = {}) {
  const response = await fetch(`${endpoint}${route}`, {
    method,
    headers: {
      accept: "text/event-stream",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return { response, text, events: parseSseEvents(text) };
}

async function requestSseAndAbortAfterFirstChunk(endpoint, route, { method = "POST", body, token, headers = {} } = {}) {
  const controller = new AbortController();
  const response = await fetch(`${endpoint}${route}`, {
    method,
    signal: controller.signal,
    headers: {
      accept: "text/event-stream",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const reader = response.body.getReader();
  const first = await reader.read();
  const text = new TextDecoder().decode(first.value ?? new Uint8Array());
  controller.abort();
  try {
    await reader.read();
  } catch {
    // Aborting the stream should reject the reader on some Node versions.
  }
  return { response, text };
}

function parseSseEvents(text) {
  return String(text)
    .trim()
    .split(/\n\n+/)
    .filter(Boolean)
    .map((block) => {
      const lines = block.split(/\n/);
      const event = lines.find((line) => line.startsWith("event: "))?.slice("event: ".length) ?? "message";
      const dataText = lines
        .filter((line) => line.startsWith("data: "))
        .map((line) => line.slice("data: ".length))
        .join("\n");
      return { event, data: dataText === "[DONE]" ? "[DONE]" : dataText ? JSON.parse(dataText) : null };
    });
}

function parseOpenAiSseChunks(text) {
  return String(text)
    .trim()
    .split(/\n\n+/)
    .filter(Boolean)
    .map((block) => {
      const dataText = block
        .split(/\n/)
        .filter((line) => line.startsWith("data: "))
        .map((line) => line.slice("data: ".length))
        .join("\n");
      return dataText === "[DONE]" ? "[DONE]" : JSON.parse(dataText);
    });
}

async function expectOk(endpoint, route, options) {
  const result = await requestJson(endpoint, route, options);
  assert.equal(result.response.ok, true, `${route} -> ${result.response.status}`);
  return result.json;
}

async function waitForReceipt(endpoint, predicate, { timeoutMs = 2000 } = {}) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const receipts = await expectOk(endpoint, "/api/v1/receipts");
    const receipt = receipts.find(predicate);
    if (receipt) return receipt;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.fail("Expected receipt was not recorded before timeout.");
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
    const unauthenticatedServerStart = await requestJson(daemon.endpoint, "/api/v1/server/start", {
      method: "POST",
    });
    assert.equal(unauthenticatedServerStart.response.status, 401);

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
    const deniedMessages = await requestJson(daemon.endpoint, "/v1/messages", {
      method: "POST",
      token: blockedGrant.token,
      body: { model: "local:auto", max_tokens: 16, messages: [{ role: "user", content: "blocked by deny scope" }] },
    });
    assert.equal(deniedMessages.response.status, 403);

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
    const unauthenticatedMessages = await requestJson(daemon.endpoint, "/v1/messages", {
      method: "POST",
      body: { model: "local:auto", max_tokens: 16, messages: [{ role: "user", content: "missing token" }] },
    });
    assert.equal(unauthenticatedMessages.response.status, 401);

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
          "model.delete:*",
          "server.control:*",
          "server.logs:*",
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

    const serverStop = await expectOk(daemon.endpoint, "/api/v1/server/stop", {
      method: "POST",
      token: grant.token,
    });
    assert.equal(serverStop.controlStatus, "stopped");
    assert.match(serverStop.receiptId, /^receipt_model_lifecycle_/);
    const serverRestart = await expectOk(daemon.endpoint, "/api/v1/server/restart", {
      method: "POST",
      token: grant.token,
    });
    assert.equal(serverRestart.controlStatus, "running");
    assert.match(serverRestart.receiptId, /^receipt_model_lifecycle_/);
    const serverLogs = await expectOk(daemon.endpoint, "/api/v1/server/logs?limit=20", { token: grant.token });
    assert.equal(serverLogs.redaction, "redacted");
    assert.ok(serverLogs.records.some((record) => record.event === "server_restart"));
    assert.equal(JSON.stringify(serverLogs).includes(grant.token), false);
    const serverEvents = await expectOk(daemon.endpoint, "/api/v1/server/events?limit=20", { token: grant.token });
    assert.ok(serverEvents.events.some((event) => event.event === "server_events_read"));

    const snapshot = await expectOk(daemon.endpoint, "/api/v1/models");
    assert.equal(snapshot.server.controlStatus, "running");
    assert.equal(snapshot.server.lastServerOperation, "server_restart");
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
    const latestVaultHealth = await expectOk(daemon.endpoint, "/api/v1/vault/health/latest", { token: grant.token });
    assert.equal(latestVaultHealth.receipt.id, vaultHealth.receiptId);
    assert.equal(latestVaultHealth.health.status, "session_only");
    assert.equal(latestVaultHealth.replay.receipt.id, vaultHealth.receiptId);

    const nativeProviderModels = await expectOk(daemon.endpoint, "/api/v1/providers/provider.autopilot.local/models");
    assert.ok(nativeProviderModels.some((model) => model.modelId === "autopilot:native-fixture"));
    const catalog = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=autopilot");
    assert.equal(catalog.providers.find((provider) => provider.id === "catalog.fixture")?.status, "available");
    const fixtureCatalogEntry = catalog.results.find((entry) => entry.sourceUrl === "fixture://catalog/autopilot-native-3b-q4");
    assert.ok(fixtureCatalogEntry);
    assert.equal(fixtureCatalogEntry.architecture, "llama");
    assert.equal(fixtureCatalogEntry.parameterCount, "3B");
    assert.equal(fixtureCatalogEntry.recommendation.label, "recommended");
    assert.ok(fixtureCatalogEntry.backendCompatibility.some((backend) => backend.backendKind === "llama_cpp" && backend.status === "ready"));
    assert.equal(fixtureCatalogEntry.downloadRisk.status, "low");
    assert.equal(fixtureCatalogEntry.benchmarkReadiness.chat, true);
    assert.ok(fixtureCatalogEntry.selectionReceiptFields.includes("approval_decision"));
    assert.equal(JSON.stringify(catalog).includes("sk-"), false);
    const snapshotAfterCatalogSearch = await expectOk(daemon.endpoint, "/api/v1/models");
    assert.equal(snapshotAfterCatalogSearch.catalog.lastSearch.query, "autopilot");
    assert.ok(snapshotAfterCatalogSearch.catalog.results.some((entry) => entry.sourceUrl === "fixture://catalog/autopilot-native-3b-q4" && entry.recommendation?.primaryBackend));

    const backends = await expectOk(daemon.endpoint, "/api/v1/backends");
    assert.ok(backends.some((backend) => backend.id === "backend.autopilot.native-local.fixture"));
    assert.ok(backends.some((backend) => backend.id === "backend.llama-cpp"));
    const runtimeEngines = await expectOk(daemon.endpoint, "/api/v1/runtime/engines");
    assert.ok(runtimeEngines.some((engine) => engine.id === "backend.autopilot.native-local.fixture"));
    assert.ok(runtimeEngines.some((engine) => engine.source === "autopilot_backend_registry"));
    const runtimeSurvey = await expectOk(daemon.endpoint, "/api/v1/runtime/survey", { method: "POST" });
    assert.equal(runtimeSurvey.schemaVersion, "ioi.model-mounting.runtime.v1");
    assert.ok(runtimeSurvey.engines.some((engine) => engine.id === "backend.autopilot.native-local.fixture"));
    assert.equal(typeof runtimeSurvey.hardware.totalMemoryBytes, "number");
    assert.ok(["absent", "available", "blocked"].includes(runtimeSurvey.lmStudio.status));
    assert.match(runtimeSurvey.receiptId, /^receipt_runtime_survey_/);
    const runtimeSurveyReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${runtimeSurvey.receiptId}`);
    assert.equal(runtimeSurveyReceipt.kind, "runtime_survey");
    assert.equal(runtimeSurveyReceipt.details.engineCount, runtimeSurvey.engines.length);
    const runtimeSelection = await expectOk(daemon.endpoint, "/api/v1/runtime/select", {
      method: "POST",
      body: { engine_id: "backend.autopilot.native-local.fixture" },
    });
    assert.equal(runtimeSelection.selectedEngineId, "backend.autopilot.native-local.fixture");
    assert.match(runtimeSelection.receiptId, /^receipt_model_lifecycle_/);
    const selectedRuntimeEngines = await expectOk(daemon.endpoint, "/api/v1/runtime/engines");
    assert.equal(selectedRuntimeEngines.find((engine) => engine.id === "backend.autopilot.native-local.fixture")?.selected, true);
    const llamaProfile = await expectOk(daemon.endpoint, "/api/v1/runtime/engines/backend.llama-cpp", {
      method: "PATCH",
      body: {
        disabled: true,
        priority: 90,
        defaultLoadOptions: { gpu: "off", contextLength: 2048, parallel: 1, ttlSeconds: 120 },
      },
    });
    assert.equal(llamaProfile.engine.operatorProfile.disabled, true);
    assert.equal(llamaProfile.engine.operatorProfile.defaultLoadOptions.contextLength, 2048);
    const disabledRuntimeSelect = await requestJson(daemon.endpoint, "/api/v1/runtime/engines/backend.llama-cpp/select", {
      method: "POST",
    });
    assert.equal(disabledRuntimeSelect.response.status, 409);
    const removedRuntimeProfile = await expectOk(daemon.endpoint, "/api/v1/runtime/engines/backend.llama-cpp", {
      method: "DELETE",
    });
    assert.equal(removedRuntimeProfile.removed, true);
    const selectedRuntimeProfile = await expectOk(daemon.endpoint, "/api/v1/runtime/engines/backend.autopilot.native-local.fixture", {
      method: "PATCH",
      body: {
        label: "Autopilot native fixture tuned",
        priority: 1,
        defaultLoadOptions: { gpu: "auto", contextLength: 3072, parallel: 3, ttlSeconds: 600, identifier: "runtime-profile-default" },
      },
    });
    assert.equal(selectedRuntimeProfile.engine.operatorProfile.defaultLoadOptions.parallel, 3);
    const runtimeEngineDetail = await expectOk(daemon.endpoint, "/api/v1/runtime/engines/backend.autopilot.native-local.fixture");
    assert.equal(runtimeEngineDetail.profile.defaultLoadOptions.contextLength, 3072);
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
    const defaultedLoadEstimate = await expectOk(daemon.endpoint, "/api/v1/models/load", {
      method: "POST",
      token: grant.token,
      body: {
        endpoint_id: nativeMounted.id,
        estimate_only: true,
      },
    });
    assert.equal(defaultedLoadEstimate.loadOptions.contextLength, 3072);
    assert.equal(defaultedLoadEstimate.loadOptions.parallel, 3);
    assert.equal(defaultedLoadEstimate.loadOptions.identifier, "runtime-profile-default");
    const nativeLoadEstimate = await expectOk(daemon.endpoint, "/api/v1/models/load", {
      method: "POST",
      token: grant.token,
      body: {
        endpoint_id: nativeMounted.id,
        load_policy: { mode: "on_demand", idleTtlSeconds: 450, autoEvict: true },
        load_options: {
          estimateOnly: true,
          gpu: "auto",
          contextLength: 4096,
          parallel: 2,
          ttlSeconds: 450,
          identifier: "native-imported-estimate",
        },
      },
    });
    assert.equal(nativeLoadEstimate.status, "estimate_only");
    assert.equal(nativeLoadEstimate.runtimeEngineId, "backend.autopilot.native-local.fixture");
    assert.equal(nativeLoadEstimate.loadOptions.contextLength, 4096);
    assert.match(nativeLoadEstimate.receiptId, /^receipt_model_lifecycle_/);
    const nativeLoadEstimateReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${nativeLoadEstimate.receiptId}`);
    assert.equal(nativeLoadEstimateReceipt.details.operation, "model_load_estimate");
    assert.equal(nativeLoadEstimateReceipt.details.loadOptions.estimateOnly, true);
    const nativeLoaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
      method: "POST",
      token: grant.token,
      body: {
        endpoint_id: nativeMounted.id,
        load_policy: { mode: "on_demand", idleTtlSeconds: 900, autoEvict: true },
        load_options: {
          gpu: "max",
          contextLength: 4096,
          parallel: 2,
          ttlSeconds: 900,
          identifier: "native-imported-dev",
        },
      },
    });
    assert.equal(nativeLoaded.backend, "autopilot.native_local.fixture");
    assert.equal(nativeLoaded.runtimeEngineId, "backend.autopilot.native-local.fixture");
    assert.equal(nativeLoaded.identifier, "native-imported-dev");
    assert.equal(nativeLoaded.contextLength, 4096);
    assert.equal(nativeLoaded.parallelism, 2);
    assert.equal(nativeLoaded.backendProcess.status, "started");
    assert.match(nativeLoaded.backendProcess.pidHash, /^[a-f0-9]{16}$/);
    assert.ok(nativeLoaded.backendProcess.argsHash);
    assert.ok(nativeLoaded.backendProcess.evidenceRefs.includes("ModelBackendDriver.process_supervision"));
    const processBackends = await expectOk(daemon.endpoint, "/api/v1/backends");
    const nativeProcessBackend = processBackends.find((backend) => backend.id === "backend.autopilot.native-local.fixture");
    assert.equal(nativeProcessBackend.process.status, "started");
    assert.equal(nativeProcessBackend.process.argsRedacted.includes("--context"), true);
    assert.equal(nativeProcessBackend.process.argsRedacted.includes("4096"), true);
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
    assert.equal(nativeReceipt.details.backendProcess.status, "started");
    assert.equal(nativeReceipt.details.backendProcessPidHash, nativeLoaded.backendProcess.pidHash);
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

    const nativeCompatStream = await requestSse(daemon.endpoint, "/v1/chat/completions", {
      method: "POST",
      token: grant.token,
      body: {
        route_id: "route.native-local",
        model: "native:imported",
        stream: true,
        messages: [{ role: "user", content: "stream native local compat" }],
      },
    });
    assert.equal(nativeCompatStream.response.status, 200);
    assert.equal(nativeCompatStream.response.headers.get("x-ioi-stream-source"), "provider_native");
    const nativeCompatStreamChunks = parseOpenAiSseChunks(nativeCompatStream.text);
    const nativeCompatStreamText = nativeCompatStreamChunks
      .filter((chunk) => chunk !== "[DONE]")
      .map((chunk) => chunk.choices?.[0]?.delta?.content ?? "")
      .join("");
    assert.match(nativeCompatStreamText, /Autopilot native local model response/);
    const nativeCompatStreamMetadata = nativeCompatStreamChunks.find((chunk) => chunk !== "[DONE]" && chunk.stream_receipt_id);
    assert.equal(nativeCompatStreamMetadata.route_id, "route.native-local");
    assert.equal(nativeCompatStreamMetadata.provider_stream, "native");
    const nativeCompatStreamReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${nativeCompatStreamMetadata.receipt_id}`);
    assert.equal(nativeCompatStreamReceipt.details.providerId, "provider.autopilot.local");
    assert.equal(nativeCompatStreamReceipt.details.backend, "autopilot.native_local.fixture");
    assert.equal(nativeCompatStreamReceipt.details.backendId, "backend.autopilot.native-local.fixture");
    assert.equal(nativeCompatStreamReceipt.details.backendProcessPidHash, nativeLoaded.backendProcess.pidHash);
    assert.equal(nativeCompatStreamReceipt.details.providerResponseKind, "native_local.chat.stream");
    assert.ok(nativeCompatStreamReceipt.details.backendEvidenceRefs.includes("autopilot_native_local_provider_native_stream"));
    const nativeCompatStreamCompleteReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${nativeCompatStreamMetadata.stream_receipt_id}`);
    assert.equal(nativeCompatStreamCompleteReceipt.details.invocationReceiptId, nativeCompatStreamMetadata.receipt_id);
    assert.equal(
      nativeCompatStreamCompleteReceipt.details.outputHash,
      crypto.createHash("sha256").update(nativeCompatStreamText).digest("hex"),
    );

    const nativeResponseStream = await requestSse(daemon.endpoint, "/v1/responses", {
      method: "POST",
      token: grant.token,
      body: {
        route_id: "route.native-local",
        model: "native:imported",
        stream: true,
        input: "stream native local response",
      },
    });
    assert.equal(nativeResponseStream.response.status, 200);
    assert.equal(nativeResponseStream.response.headers.get("x-ioi-stream-source"), "provider_native");
    const nativeResponseStreamText = nativeResponseStream.events
      .filter((event) => event.event === "response.output_text.delta")
      .map((event) => event.data.delta)
      .join("");
    assert.match(nativeResponseStreamText, /Autopilot native local model response/);
    const nativeResponseCompleted = nativeResponseStream.events.find((event) => event.event === "response.completed")?.data.response;
    assert.equal(nativeResponseCompleted.route_id, "route.native-local");
    assert.equal(nativeResponseCompleted.provider_stream, "native");
    const nativeResponseStreamReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${nativeResponseCompleted.receipt_id}`);
    assert.equal(nativeResponseStreamReceipt.details.providerId, "provider.autopilot.local");
    assert.equal(nativeResponseStreamReceipt.details.backend, "autopilot.native_local.fixture");
    assert.equal(nativeResponseStreamReceipt.details.backendId, "backend.autopilot.native-local.fixture");
    assert.equal(nativeResponseStreamReceipt.details.backendProcessPidHash, nativeLoaded.backendProcess.pidHash);
    assert.equal(nativeResponseStreamReceipt.details.providerResponseKind, "native_local.responses.stream");
    assert.ok(nativeResponseStreamReceipt.details.backendEvidenceRefs.includes("autopilot_native_local_provider_native_stream"));
    const nativeResponseStreamCompleteReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${nativeResponseCompleted.stream_receipt_id}`);
    assert.equal(nativeResponseStreamCompleteReceipt.details.invocationReceiptId, nativeResponseCompleted.receipt_id);
    assert.equal(
      nativeResponseStreamCompleteReceipt.details.outputHash,
      crypto.createHash("sha256").update(nativeResponseStreamText).digest("hex"),
    );

    const priorNativeProviderStreamDelay = process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS;
    process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS = "25";
    try {
      const abortedNativeCompatStream = await requestSseAndAbortAfterFirstChunk(daemon.endpoint, "/v1/chat/completions", {
        method: "POST",
        token: grant.token,
        body: {
          route_id: "route.native-local",
          model: "native:imported",
          stream: true,
          messages: [{ role: "user", content: "abort native local compat stream" }],
        },
      });
      assert.equal(abortedNativeCompatStream.response.status, 200);
      assert.match(abortedNativeCompatStream.text, /chat\.completion\.chunk/);
    } finally {
      if (priorNativeProviderStreamDelay === undefined) {
        delete process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS;
      } else {
        process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS = priorNativeProviderStreamDelay;
      }
    }
    const canceledNativeCompatReceipt = await waitForReceipt(
      daemon.endpoint,
      (receipt) =>
        receipt.kind === "model_invocation_stream_canceled" &&
        receipt.details?.streamKind === "openai_chat_completions_native_local" &&
        receipt.details?.routeId === "route.native-local",
    );
    assert.equal(canceledNativeCompatReceipt.details.selectedModel, "native:imported");
    assert.equal(canceledNativeCompatReceipt.details.endpointId, nativeMounted.id);
    assert.equal(canceledNativeCompatReceipt.details.status, "aborted");
    assert.equal(canceledNativeCompatReceipt.details.streamSource, "provider_native");
    assert.equal(canceledNativeCompatReceipt.details.providerResponseKind, "native_local.chat.stream");
    assert.ok(canceledNativeCompatReceipt.details.backendEvidenceRefs.includes("autopilot_native_local_provider_native_stream"));
    const canceledNativeCompatInvocation = await expectOk(
      daemon.endpoint,
      `/api/v1/receipts/${canceledNativeCompatReceipt.details.invocationReceiptId}`,
    );
    assert.equal(canceledNativeCompatInvocation.kind, "model_invocation");
    assert.equal(canceledNativeCompatInvocation.details.backendProcessPidHash, nativeLoaded.backendProcess.pidHash);

    const priorNativeResponsesProviderStreamDelay = process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS;
    process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS = "25";
    try {
      const abortedNativeResponsesStream = await requestSseAndAbortAfterFirstChunk(daemon.endpoint, "/v1/responses", {
        method: "POST",
        token: grant.token,
        body: {
          route_id: "route.native-local",
          model: "native:imported",
          stream: true,
          input: "abort native local responses stream",
        },
      });
      assert.equal(abortedNativeResponsesStream.response.status, 200);
      assert.match(abortedNativeResponsesStream.text, /response\.created/);
    } finally {
      if (priorNativeResponsesProviderStreamDelay === undefined) {
        delete process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS;
      } else {
        process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS = priorNativeResponsesProviderStreamDelay;
      }
    }
    const canceledNativeResponsesReceipt = await waitForReceipt(
      daemon.endpoint,
      (receipt) =>
        receipt.kind === "model_invocation_stream_canceled" &&
        receipt.details?.streamKind === "openai_responses_native_local" &&
        receipt.details?.routeId === "route.native-local",
    );
    assert.equal(canceledNativeResponsesReceipt.details.selectedModel, "native:imported");
    assert.equal(canceledNativeResponsesReceipt.details.endpointId, nativeMounted.id);
    assert.equal(canceledNativeResponsesReceipt.details.status, "aborted");
    assert.equal(canceledNativeResponsesReceipt.details.streamSource, "provider_native");
    assert.equal(canceledNativeResponsesReceipt.details.providerResponseKind, "native_local.responses.stream");
    assert.ok(canceledNativeResponsesReceipt.details.backendEvidenceRefs.includes("autopilot_native_local_provider_native_stream"));

    const nativeProviderAbortLogs = await expectOk(daemon.endpoint, "/api/v1/backends/backend.autopilot.native-local.fixture/logs");
    assert.ok(
      nativeProviderAbortLogs.some(
        (record) => record.event === "stream_abort" && record.kind === "chat.completions" && record.reason === "client_disconnect",
      ),
    );
    assert.ok(
      nativeProviderAbortLogs.some(
        (record) => record.event === "stream_abort" && record.kind === "responses" && record.reason === "client_disconnect",
      ),
    );

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
    const openAiModelsWithXApiKey = await expectOk(daemon.endpoint, "/v1/models", {
      headers: { "x-api-key": grant.token },
    });
    assert.equal(openAiModelsWithXApiKey.object, "list");

    const compat = await expectOk(daemon.endpoint, "/v1/chat/completions", {
      method: "POST",
      token: grant.token,
      body: { model: "local:auto", messages: [{ role: "user", content: "hello compat" }] },
    });
    assert.equal(compat.choices[0].message.role, "assistant");
    assert.equal(compat.route_id, "route.local-first");

    const compatStreaming = await requestSse(daemon.endpoint, "/v1/chat/completions", {
      method: "POST",
      token: grant.token,
      body: { model: "local:auto", stream: true, messages: [{ role: "user", content: "hello streamed compat" }] },
    });
    assert.equal(compatStreaming.response.status, 200);
    assert.match(compatStreaming.response.headers.get("content-type") ?? "", /text\/event-stream/);
    const compatChunks = parseOpenAiSseChunks(compatStreaming.text);
    assert.equal(compatChunks.at(-1), "[DONE]");
    assert.equal(compatChunks[0].object, "chat.completion.chunk");
    assert.equal(compatChunks[0].choices[0].delta.role, "assistant");
    assert.equal(compatChunks.at(-2).choices[0].finish_reason, "stop");
    assert.equal(compatChunks[0].route_id, "route.local-first");
    assert.equal(typeof compatChunks[0].receipt_id, "string");
    assert.equal(compatStreaming.response.headers.get("x-ioi-receipt-id"), compatChunks[0].receipt_id);
    const compatStreamedText = compatChunks
      .filter((chunk) => chunk !== "[DONE]")
      .map((chunk) => chunk.choices[0].delta.content ?? "")
      .join("");
    assert.match(compatStreamedText, /IOI model router fixture response/);
    const compatStreamReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${compatChunks[0].receipt_id}`);
    assert.equal(compatStreamReceipt.kind, "model_invocation");

    const deniedCompatStream = await requestJson(daemon.endpoint, "/v1/chat/completions", {
      method: "POST",
      token: blockedGrant.token,
      body: { model: "local:auto", stream: true, messages: [{ role: "user", content: "blocked compat stream" }] },
    });
    assert.equal(deniedCompatStream.response.status, 403);

    const priorStreamDelay = process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS;
    process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS = "25";
    try {
      const abortedCompatStream = await requestSseAndAbortAfterFirstChunk(daemon.endpoint, "/v1/chat/completions", {
        method: "POST",
        token: grant.token,
        body: { model: "local:auto", stream: true, messages: [{ role: "user", content: "abort this compat stream" }] },
      });
      assert.equal(abortedCompatStream.response.status, 200);
      assert.match(abortedCompatStream.text, /chat\.completion\.chunk/);
    } finally {
      if (priorStreamDelay === undefined) {
        delete process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS;
      } else {
        process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS = priorStreamDelay;
      }
    }
    const canceledCompatReceipt = await waitForReceipt(
      daemon.endpoint,
      (receipt) =>
        receipt.kind === "model_invocation_stream_canceled" &&
        receipt.details?.streamKind === "openai_chat_completions",
    );
    assert.equal(canceledCompatReceipt.details.routeId, "route.local-first");
    assert.equal(canceledCompatReceipt.details.selectedModel, "local:auto");
    assert.equal(canceledCompatReceipt.details.endpointId, "endpoint.local.auto");
    assert.equal(typeof canceledCompatReceipt.details.invocationReceiptId, "string");
    const canceledInvocationReceipt = await expectOk(
      daemon.endpoint,
      `/api/v1/receipts/${canceledCompatReceipt.details.invocationReceiptId}`,
    );
    assert.equal(canceledInvocationReceipt.kind, "model_invocation");

    const responsesStreaming = await requestSse(daemon.endpoint, "/v1/responses", {
      method: "POST",
      token: grant.token,
      body: { model: "local:auto", stream: true, input: "hello streamed responses" },
    });
    assert.equal(responsesStreaming.response.status, 200);
    assert.match(responsesStreaming.response.headers.get("content-type") ?? "", /text\/event-stream/);
    assert.equal(responsesStreaming.events[0].event, "response.created");
    assert.equal(responsesStreaming.events[1].event, "response.output_item.added");
    assert.equal(responsesStreaming.events[2].event, "response.content_part.added");
    assert.ok(responsesStreaming.events.some((event) => event.event === "response.output_text.delta"));
    assert.equal(responsesStreaming.events.at(-3).event, "response.content_part.done");
    assert.equal(responsesStreaming.events.at(-2).event, "response.output_item.done");
    assert.equal(responsesStreaming.events.at(-1).event, "response.completed");
    assert.equal(responsesStreaming.events.at(-1).data.response.route_id, "route.local-first");
    assert.equal(typeof responsesStreaming.events.at(-1).data.response.receipt_id, "string");
    assert.equal(
      responsesStreaming.response.headers.get("x-ioi-receipt-id"),
      responsesStreaming.events.at(-1).data.response.receipt_id,
    );
    const responsesStreamedText = responsesStreaming.events
      .filter((event) => event.event === "response.output_text.delta")
      .map((event) => event.data.delta)
      .join("");
    assert.match(responsesStreamedText, /IOI model router fixture response/);
    const responsesStreamReceipt = await expectOk(
      daemon.endpoint,
      `/api/v1/receipts/${responsesStreaming.events.at(-1).data.response.receipt_id}`,
    );
    assert.equal(responsesStreamReceipt.kind, "model_invocation");

    const deniedResponsesStream = await requestJson(daemon.endpoint, "/v1/responses", {
      method: "POST",
      token: blockedGrant.token,
      body: { model: "local:auto", stream: true, input: "blocked responses stream" },
    });
    assert.equal(deniedResponsesStream.response.status, 403);

    const priorResponsesStreamDelay = process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS;
    process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS = "25";
    try {
      const abortedResponsesStream = await requestSseAndAbortAfterFirstChunk(daemon.endpoint, "/v1/responses", {
        method: "POST",
        token: grant.token,
        body: { model: "local:auto", stream: true, input: "abort this responses stream" },
      });
      assert.equal(abortedResponsesStream.response.status, 200);
      assert.match(abortedResponsesStream.text, /response\.created/);
    } finally {
      if (priorResponsesStreamDelay === undefined) {
        delete process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS;
      } else {
        process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS = priorResponsesStreamDelay;
      }
    }
    const canceledResponsesReceipt = await waitForReceipt(
      daemon.endpoint,
      (receipt) =>
        receipt.kind === "model_invocation_stream_canceled" &&
        receipt.details?.streamKind === "openai_responses",
    );
    assert.equal(canceledResponsesReceipt.details.routeId, "route.local-first");
    assert.equal(canceledResponsesReceipt.details.selectedModel, "local:auto");
    assert.equal(canceledResponsesReceipt.details.endpointId, "endpoint.local.auto");

    const anthropic = await expectOk(daemon.endpoint, "/v1/messages", {
      method: "POST",
      headers: { "x-api-key": grant.token },
      body: {
        model: "local:auto",
        max_tokens: 32,
        system: "Answer through the governed Autopilot model mounting path.",
        messages: [{ role: "user", content: [{ type: "text", text: "hello anthropic compat" }] }],
      },
    });
    assert.equal(anthropic.type, "message");
    assert.equal(anthropic.role, "assistant");
    assert.equal(anthropic.model, "local:auto");
    assert.equal(anthropic.route_id, "route.local-first");
    assert.equal(anthropic.content[0].type, "text");
    assert.match(anthropic.content[0].text, /IOI model router fixture response/);
    assert.equal(typeof anthropic.receipt_id, "string");
    assert.equal(Array.isArray(anthropic.tool_receipt_ids), true);
    assert.equal(typeof anthropic.usage.input_tokens, "number");
    const anthropicReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${anthropic.receipt_id}`);
    assert.equal(anthropicReceipt.kind, "model_invocation");
    assert.equal(anthropicReceipt.details.routeId, "route.local-first");
    assert.equal(anthropicReceipt.details.selectedModel, "local:auto");
    assert.equal(anthropicReceipt.details.endpointId, "endpoint.local.auto");

    const anthropicStreaming = await requestSse(daemon.endpoint, "/v1/messages", {
      method: "POST",
      token: grant.token,
      body: {
        model: "local:auto",
        max_tokens: 16,
        stream: true,
        messages: [{ role: "user", content: "stream later" }],
      },
    });
    assert.equal(anthropicStreaming.response.status, 200);
    assert.match(anthropicStreaming.response.headers.get("content-type") ?? "", /text\/event-stream/);
    assert.equal(anthropicStreaming.events[0].event, "message_start");
    assert.equal(anthropicStreaming.events[1].event, "content_block_start");
    assert.ok(anthropicStreaming.events.some((event) => event.event === "content_block_delta"));
    assert.equal(anthropicStreaming.events.at(-2).event, "message_delta");
    assert.equal(anthropicStreaming.events.at(-1).event, "message_stop");
    assert.equal(typeof anthropicStreaming.events.at(-1).data.receipt_id, "string");
    assert.equal(anthropicStreaming.events.at(-1).data.route_id, "route.local-first");
    assert.equal(
      anthropicStreaming.response.headers.get("x-ioi-receipt-id"),
      anthropicStreaming.events.at(-1).data.receipt_id,
    );
    const streamedText = anthropicStreaming.events
      .filter((event) => event.event === "content_block_delta")
      .map((event) => event.data.delta.text)
      .join("");
    assert.match(streamedText, /IOI model router fixture response/);
    const streamedReceipt = await expectOk(
      daemon.endpoint,
      `/api/v1/receipts/${anthropicStreaming.events.at(-1).data.receipt_id}`,
    );
    assert.equal(streamedReceipt.kind, "model_invocation");

    const priorAnthropicStreamDelay = process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS;
    process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS = "25";
    try {
      const abortedAnthropicStream = await requestSseAndAbortAfterFirstChunk(daemon.endpoint, "/v1/messages", {
        method: "POST",
        token: grant.token,
        body: { model: "local:auto", max_tokens: 16, stream: true, messages: [{ role: "user", content: "abort messages stream" }] },
      });
      assert.equal(abortedAnthropicStream.response.status, 200);
      assert.match(abortedAnthropicStream.text, /message_start/);
    } finally {
      if (priorAnthropicStreamDelay === undefined) {
        delete process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS;
      } else {
        process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS = priorAnthropicStreamDelay;
      }
    }
    const canceledAnthropicReceipt = await waitForReceipt(
      daemon.endpoint,
      (receipt) =>
        receipt.kind === "model_invocation_stream_canceled" &&
        receipt.details?.streamKind === "anthropic_messages",
    );
    assert.equal(canceledAnthropicReceipt.details.routeId, "route.local-first");
    assert.equal(canceledAnthropicReceipt.details.selectedModel, "local:auto");
    assert.equal(canceledAnthropicReceipt.details.endpointId, "endpoint.local.auto");

    const deniedMessagesStream = await requestJson(daemon.endpoint, "/v1/messages", {
      method: "POST",
      token: blockedGrant.token,
      body: { model: "local:auto", stream: true, max_tokens: 16, messages: [{ role: "user", content: "blocked stream" }] },
    });
    assert.equal(deniedMessagesStream.response.status, 403);

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
    const revokedMessagesUse = await requestJson(daemon.endpoint, "/v1/messages", {
      method: "POST",
      token: grant.token,
      body: { model: "local:auto", max_tokens: 16, messages: [{ role: "user", content: "after revoke" }] },
    });
    assert.equal(revokedMessagesUse.response.status, 403);

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

test("model catalog provider ports unify fixture, manifest, custom HTTP, and Ollama entries", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-catalog-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-catalog-state-"));
  const manifestPath = path.join(cwd, "model-catalog.json");
  const operatorManifestPath = path.join(cwd, "operator-model-catalog.json");
  fs.writeFileSync(
    manifestPath,
    JSON.stringify({
      models: [
        {
          model_id: "manifest/local-qwen-3b",
          family: "manifest-local",
          architecture: "qwen",
          parameter_count: "3B",
          format: "gguf",
          quantization: "Q4_K_M",
          size_bytes: 4096,
          context_window: 8192,
          source_url: "fixture://manifest/local-qwen-3b-q4",
          source_label: "Manifest / local qwen",
          compatibility: ["native_local_fixture", "llama_cpp"],
          tags: ["manifest", "chat"],
        },
      ],
    }),
  );
  fs.writeFileSync(
    operatorManifestPath,
    JSON.stringify({
      models: [
        {
          model_id: "operator/local-catalog-1b",
          family: "operator-manifest",
          architecture: "llama",
          parameter_count: "1B",
          format: "gguf",
          quantization: "Q5_K_M",
          size_bytes: 2048,
          context_window: 4096,
          source_url: "fixture://operator/local-catalog-1b-q5",
          source_label: "Operator manifest / local catalog",
          compatibility: ["native_local_fixture", "llama_cpp"],
          tags: ["operator", "catalog"],
        },
      ],
    }),
  );
  const ollamaServer = await startFakeOllamaServer();
  const customCatalogServer = await startFakeCustomCatalogServer();
  const priorManifest = process.env.IOI_MODEL_CATALOG_MANIFEST_PATH;
  const priorCustomCatalog = process.env.IOI_MODEL_CATALOG_CUSTOM_BASE_URL;
  const priorOllamaHost = process.env.OLLAMA_HOST;
  process.env.IOI_MODEL_CATALOG_MANIFEST_PATH = manifestPath;
  process.env.IOI_MODEL_CATALOG_CUSTOM_BASE_URL = customCatalogServer.endpoint;
  process.env.OLLAMA_HOST = ollamaServer.endpoint;
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: { allowed: ["model.download:*", "model.import:*", "provider.write:*"] },
    });
    const catalog = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=&limit=20");
    assert.equal(catalog.adapterBoundary.port, "ModelCatalogProviderPort");
    for (const providerId of ["catalog.fixture", "catalog.local_manifest", "catalog.custom_http", "catalog.ollama", "catalog.huggingface"]) {
      assert.equal(catalog.providers.find((provider) => provider.id === providerId)?.adapterPort, "ModelCatalogProviderPort");
    }
    assert.equal(catalog.providers.find((provider) => provider.id === "catalog.local_manifest")?.status, "available");
    assert.equal(catalog.providers.find((provider) => provider.id === "catalog.custom_http")?.status, "available");
    assert.equal(catalog.providers.find((provider) => provider.id === "catalog.ollama")?.status, "available");
    assert.equal(catalog.providers.find((provider) => provider.id === "catalog.huggingface")?.status, "gated");

    const manifestEntry = catalog.results.find((entry) => entry.catalogProviderId === "catalog.local_manifest");
    const customEntry = catalog.results.find((entry) => entry.catalogProviderId === "catalog.custom_http");
    const ollamaEntry = catalog.results.find((entry) => entry.catalogProviderId === "catalog.ollama" && entry.modelId === "qwen3:8b");
    assert.equal(manifestEntry?.architecture, "qwen");
    assert.equal(manifestEntry?.recommendation.label, "recommended");
    assert.equal(customEntry?.format, "safetensors");
    assert.equal(customEntry?.recommendation.primaryBackend, "vllm");
    assert.equal(ollamaEntry?.format, "ollama");
    assert.ok(ollamaEntry?.backendCompatibility.some((backend) => backend.backendKind === "ollama" && backend.status === "ready"));

    const manifestImport = await expectOk(daemon.endpoint, "/api/v1/models/catalog/import-url", {
      method: "POST",
      token: grant.token,
      body: { source_url: manifestEntry.sourceUrl, model_id: "native:manifest-catalog-import" },
    });
    assert.equal(manifestImport.status, "completed");
    assert.equal(manifestImport.download.variant.catalogProviderId, "catalog.local_manifest");
    assert.equal(manifestImport.download.variant.architecture, "qwen");

    const customImport = await expectOk(daemon.endpoint, "/api/v1/models/catalog/import-url", {
      method: "POST",
      token: grant.token,
      body: { source_url: customEntry.sourceUrl, model_id: "native:custom-catalog-import" },
    });
    assert.equal(customImport.status, "completed");
    assert.equal(customImport.download.variant.catalogProviderId, "catalog.custom_http");
    assert.equal(customImport.download.variant.format, "safetensors");

    const configuredManifest = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.local_manifest", {
      method: "PATCH",
      token: grant.token,
      body: { enabled: true, manifest_path: operatorManifestPath },
    });
    assert.equal(configuredManifest.id, "catalog.local_manifest");
    assert.equal(configuredManifest.materialPersistence, "runtime_vault_binding");
    assert.equal(configuredManifest.runtimeMaterialStatus, "bound_runtime_session");
    assert.equal(Boolean(configuredManifest.manifestPathHash), true);
    assert.equal(Boolean(configuredManifest.materialVaultRefHash), true);
    assert.equal(JSON.stringify(configuredManifest).includes(operatorManifestPath), false);
    assert.equal(directoryContainsNeedle(stateDir, operatorManifestPath), false);

    const catalogVaultRef = "vault://catalog/custom-http/header";
    const configuredCustom = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.custom_http", {
      method: "PATCH",
      token: grant.token,
      body: { enabled: true, base_url: customCatalogServer.endpoint, auth_vault_ref: catalogVaultRef },
    });
    assert.equal(configuredCustom.id, "catalog.custom_http");
    assert.equal(configuredCustom.materialPersistence, "runtime_vault_binding");
    assert.equal(configuredCustom.runtimeMaterialStatus, "bound_runtime_session");
    assert.equal(Boolean(configuredCustom.baseUrlHash), true);
    assert.equal(Boolean(configuredCustom.authVaultRefHash), true);
    assert.equal(Boolean(configuredCustom.materialVaultRefHash), true);
    assert.equal(JSON.stringify(configuredCustom).includes(customCatalogServer.endpoint), false);
    assert.equal(JSON.stringify(configuredCustom).includes(catalogVaultRef), false);
    assert.equal(directoryContainsNeedle(stateDir, customCatalogServer.endpoint), false);

    const configuredCustomGet = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.custom_http");
    assert.equal(configuredCustomGet.id, "catalog.custom_http");
    assert.equal(configuredCustomGet.provider.status, "configured");
    assert.equal(JSON.stringify(configuredCustomGet).includes(customCatalogServer.endpoint), false);
    assert.equal(JSON.stringify(configuredCustomGet).includes(catalogVaultRef), false);

    const operatorCatalog = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=operator&limit=5");
    const operatorEntry = operatorCatalog.results.find((entry) => entry.catalogProviderId === "catalog.local_manifest");
    assert.equal(operatorEntry?.modelId, "operator/local-catalog-1b");
    assert.equal(operatorCatalog.providers.find((provider) => provider.id === "catalog.local_manifest")?.runtimeMaterialStatus, "bound_runtime_session");
    assert.equal(JSON.stringify(operatorCatalog).includes(operatorManifestPath), false);

    const projection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
    assert.equal(projection.catalog.providers.find((provider) => provider.id === "catalog.local_manifest")?.adapterPort, "ModelCatalogProviderPort");
    assert.equal(JSON.stringify(projection).includes(manifestPath), false);
    assert.equal(JSON.stringify(projection).includes(operatorManifestPath), false);
    assert.equal(JSON.stringify(projection).includes(customCatalogServer.endpoint), false);
    assert.equal(JSON.stringify(projection).includes(catalogVaultRef), false);
  } finally {
    restoreEnv("IOI_MODEL_CATALOG_MANIFEST_PATH", priorManifest);
    restoreEnv("IOI_MODEL_CATALOG_CUSTOM_BASE_URL", priorCustomCatalog);
    restoreEnv("OLLAMA_HOST", priorOllamaHost);
    await customCatalogServer.close();
    await ollamaServer.close();
    await daemon.close();
  }
});

test("catalog source material persists through the encrypted vault adapter without plaintext state", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-catalog-keychain-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-catalog-keychain-state-"));
  const keychainDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-catalog-keychain-material-"));
  const keychainPath = path.join(keychainDir, "catalog-vault-material.json");
  const manifestPath = path.join(cwd, "catalog-source.json");
  fs.writeFileSync(
    manifestPath,
    JSON.stringify({
      models: [
        {
          model_id: "keychain/local-catalog-2b",
          family: "keychain-manifest",
          architecture: "llama",
          parameter_count: "2B",
          format: "gguf",
          quantization: "Q4_K_M",
          size_bytes: 3072,
          context_window: 4096,
          source_url: "fixture://keychain/local-catalog-2b-q4",
          source_label: "Keychain manifest / local catalog",
          compatibility: ["native_local_fixture", "llama_cpp"],
          tags: ["keychain", "catalog"],
        },
      ],
    }),
  );
  const customCatalogServer = await startFakeCustomCatalogServer();
  const priorPath = process.env.IOI_KEYCHAIN_VAULT_PATH;
  const priorKey = process.env.IOI_KEYCHAIN_VAULT_KEY;
  const priorManifest = process.env.IOI_MODEL_CATALOG_MANIFEST_PATH;
  const priorCustomCatalog = process.env.IOI_MODEL_CATALOG_CUSTOM_BASE_URL;
  process.env.IOI_KEYCHAIN_VAULT_PATH = keychainPath;
  process.env.IOI_KEYCHAIN_VAULT_KEY = crypto.randomBytes(32).toString("base64url");
  delete process.env.IOI_MODEL_CATALOG_MANIFEST_PATH;
  delete process.env.IOI_MODEL_CATALOG_CUSTOM_BASE_URL;
  let daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: { allowed: ["model.download:*", "model.import:*", "provider.write:*", "vault.read:*"] },
    });
    const configuredManifest = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.local_manifest", {
      method: "PATCH",
      token: grant.token,
      body: { enabled: true, manifest_path: manifestPath },
    });
    assert.equal(configuredManifest.materialPersistence, "vault_material_adapter");
    assert.equal(configuredManifest.runtimeMaterialStatus, "bound_runtime_session");
    assert.equal(configuredManifest.vaultMaterialSource, "encrypted_keychain_vault_adapter");
    assert.equal(Boolean(configuredManifest.materialVaultRefHash), true);
    assert.equal(JSON.stringify(configuredManifest).includes(manifestPath), false);
    assert.equal(directoryContainsNeedle(stateDir, manifestPath), false);
    assert.equal(directoryContainsNeedle(keychainDir, manifestPath), false);

    const configuredCustom = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.custom_http", {
      method: "PATCH",
      token: grant.token,
      body: { enabled: true, base_url: customCatalogServer.endpoint },
    });
    assert.equal(configuredCustom.materialPersistence, "vault_material_adapter");
    assert.equal(configuredCustom.runtimeMaterialStatus, "bound_runtime_session");
    assert.equal(configuredCustom.vaultMaterialSource, "encrypted_keychain_vault_adapter");
    assert.equal(Boolean(configuredCustom.materialVaultRefHash), true);
    assert.equal(JSON.stringify(configuredCustom).includes(customCatalogServer.endpoint), false);
    assert.equal(directoryContainsNeedle(stateDir, customCatalogServer.endpoint), false);
    assert.equal(directoryContainsNeedle(keychainDir, customCatalogServer.endpoint), false);

    const firstCatalog = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=keychain&limit=5");
    assert.equal(firstCatalog.results.find((entry) => entry.catalogProviderId === "catalog.local_manifest")?.modelId, "keychain/local-catalog-2b");
    assert.equal(firstCatalog.providers.find((provider) => provider.id === "catalog.local_manifest")?.runtimeMaterialStatus, "bound_runtime_session");
    const firstCustomCatalog = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=custom&limit=5");
    assert.equal(firstCustomCatalog.results.find((entry) => entry.catalogProviderId === "catalog.custom_http")?.modelId, "custom/http-vllm-fixture");
    const projection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
    assert.equal(JSON.stringify(projection).includes(manifestPath), false);
    assert.equal(JSON.stringify(projection).includes(customCatalogServer.endpoint), false);

    await daemon.close();
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const restartedManifest = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.local_manifest");
    assert.equal(restartedManifest.materialPersistence, "vault_material_adapter");
    assert.equal(restartedManifest.runtimeMaterialStatus, "resolved_from_vault");
    assert.equal(restartedManifest.vaultMaterialSource, "encrypted_keychain_vault_adapter");
    assert.equal(restartedManifest.materialVaultRefHash, configuredManifest.materialVaultRefHash);
    const restartedCustom = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.custom_http");
    assert.equal(restartedCustom.materialPersistence, "vault_material_adapter");
    assert.equal(restartedCustom.runtimeMaterialStatus, "resolved_from_vault");
    assert.equal(restartedCustom.vaultMaterialSource, "encrypted_keychain_vault_adapter");
    assert.equal(restartedCustom.materialVaultRefHash, configuredCustom.materialVaultRefHash);
    const restartedCatalog = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=keychain&limit=5");
    assert.equal(restartedCatalog.results.find((entry) => entry.catalogProviderId === "catalog.local_manifest")?.modelId, "keychain/local-catalog-2b");
    const restartedCustomCatalog = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=custom&limit=5");
    assert.equal(restartedCustomCatalog.results.find((entry) => entry.catalogProviderId === "catalog.custom_http")?.modelId, "custom/http-vllm-fixture");
    const restartedVaultRefs = await expectOk(daemon.endpoint, "/api/v1/vault/refs", { token: grant.token });
    assert.ok(restartedVaultRefs.some((ref) => ref.vaultRefHash === configuredManifest.materialVaultRefHash && ref.resolvedMaterial === true));
    assert.ok(restartedVaultRefs.some((ref) => ref.vaultRefHash === configuredCustom.materialVaultRefHash && ref.resolvedMaterial === true));
    assert.equal(JSON.stringify(restartedVaultRefs).includes(manifestPath), false);
    assert.equal(JSON.stringify(restartedVaultRefs).includes(customCatalogServer.endpoint), false);
    assert.equal(directoryContainsNeedle(stateDir, manifestPath), false);
    assert.equal(directoryContainsNeedle(stateDir, customCatalogServer.endpoint), false);
    assert.equal(directoryContainsNeedle(keychainDir, manifestPath), false);
    assert.equal(directoryContainsNeedle(keychainDir, customCatalogServer.endpoint), false);
  } finally {
    await daemon.close();
    await customCatalogServer.close();
    restoreEnv("IOI_KEYCHAIN_VAULT_PATH", priorPath);
    restoreEnv("IOI_KEYCHAIN_VAULT_KEY", priorKey);
    restoreEnv("IOI_MODEL_CATALOG_MANIFEST_PATH", priorManifest);
    restoreEnv("IOI_MODEL_CATALOG_CUSTOM_BASE_URL", priorCustomCatalog);
  }
});

test("catalog source material fails closed after restart when only session-bound vault material exists", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-catalog-session-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-catalog-session-state-"));
  const manifestPath = path.join(cwd, "session-catalog-source.json");
  fs.writeFileSync(
    manifestPath,
    JSON.stringify({
      models: [
        {
          model_id: "session/local-catalog-1b",
          family: "session-manifest",
          architecture: "llama",
          parameter_count: "1B",
          format: "gguf",
          quantization: "Q4_K_M",
          size_bytes: 2048,
          context_window: 4096,
          source_url: "fixture://session/local-catalog-1b-q4",
          source_label: "Session manifest / local catalog",
          compatibility: ["native_local_fixture", "llama_cpp"],
          tags: ["session", "catalog"],
        },
      ],
    }),
  );
  const priorPath = process.env.IOI_KEYCHAIN_VAULT_PATH;
  const priorKey = process.env.IOI_KEYCHAIN_VAULT_KEY;
  const priorManifest = process.env.IOI_MODEL_CATALOG_MANIFEST_PATH;
  delete process.env.IOI_KEYCHAIN_VAULT_PATH;
  delete process.env.IOI_KEYCHAIN_VAULT_KEY;
  delete process.env.IOI_MODEL_CATALOG_MANIFEST_PATH;
  let daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: { allowed: ["provider.write:*"] },
    });
    const configured = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.local_manifest", {
      method: "PATCH",
      token: grant.token,
      body: { enabled: true, manifest_path: manifestPath },
    });
    assert.equal(configured.materialPersistence, "runtime_vault_binding");
    assert.equal(configured.runtimeMaterialStatus, "bound_runtime_session");
    assert.equal(configured.vaultMaterialSource, "runtime_memory");
    assert.equal(directoryContainsNeedle(stateDir, manifestPath), false);
    const catalog = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=session&limit=5");
    assert.equal(catalog.results.find((entry) => entry.catalogProviderId === "catalog.local_manifest")?.modelId, "session/local-catalog-1b");

    await daemon.close();
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const restarted = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.local_manifest");
    assert.equal(restarted.materialPersistence, "runtime_vault_binding");
    assert.equal(restarted.runtimeMaterialStatus, "missing_runtime_material");
    assert.equal(restarted.vaultMaterialSource, "unbound");
    assert.equal(restarted.provider.status, "metadata_only");
    const restartedCatalog = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=session&limit=5");
    assert.equal(restartedCatalog.results.some((entry) => entry.catalogProviderId === "catalog.local_manifest"), false);
    assert.equal(directoryContainsNeedle(stateDir, manifestPath), false);
  } finally {
    await daemon.close();
    restoreEnv("IOI_KEYCHAIN_VAULT_PATH", priorPath);
    restoreEnv("IOI_KEYCHAIN_VAULT_KEY", priorKey);
    restoreEnv("IOI_MODEL_CATALOG_MANIFEST_PATH", priorManifest);
  }
});

test("catalog provider auth resolves vault-backed headers for custom and live catalog requests", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-catalog-auth-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-catalog-auth-state-"));
  const customVaultRef = "vault://catalog/custom-http/auth-token";
  const customSecret = crypto.randomBytes(14).toString("base64url");
  const liveVaultRef = "vault://catalog/huggingface/auth-token";
  const liveSecret = crypto.randomBytes(14).toString("base64url");
  const customCatalogServer = await startFakeCustomCatalogServer({ requiredHeaders: { "x-catalog-key": customSecret } });
  const liveCatalogServer = await startFakeHuggingFaceCatalogServer({ requiredHeaders: { authorization: `Bearer ${liveSecret}` } });
  const priorLiveCatalog = process.env.IOI_LIVE_MODEL_CATALOG;
  const priorLiveDownload = process.env.IOI_LIVE_MODEL_DOWNLOAD;
  const priorCatalogBase = process.env.IOI_MODEL_CATALOG_HF_BASE_URL;
  process.env.IOI_LIVE_MODEL_CATALOG = "1";
  process.env.IOI_LIVE_MODEL_DOWNLOAD = "1";
  process.env.IOI_MODEL_CATALOG_HF_BASE_URL = liveCatalogServer.endpoint;
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: { allowed: ["provider.write:*", "vault.write:*", "vault.read:*", "model.download:*", "model.import:*"] },
    });
    const configuredCustom = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.custom_http", {
      method: "PATCH",
      token: grant.token,
      body: {
        enabled: true,
        base_url: customCatalogServer.endpoint,
        auth_vault_ref: customVaultRef,
        auth_scheme: "api_key",
        auth_header_name: "x-catalog-key",
      },
    });
    assert.equal(configuredCustom.catalogAuthConfigured, true);
    assert.equal(configuredCustom.catalogAuthScheme, "api_key");
    assert.equal(typeof configuredCustom.catalogAuthHeaderNameHash, "string");
    assert.equal(JSON.stringify(configuredCustom).includes("x-catalog-key"), false);
    assert.equal(JSON.stringify(configuredCustom).includes(customVaultRef), false);

    const blockedCustom = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=custom&limit=5");
    const blockedCustomProvider = blockedCustom.providers.find((provider) => provider.id === "catalog.custom_http");
    assert.equal(blockedCustomProvider.status, "blocked");
    assert.equal(blockedCustomProvider.catalogAuthResolved, false);
    assert.equal(blockedCustom.results.some((entry) => entry.catalogProviderId === "catalog.custom_http"), false);

    await expectOk(daemon.endpoint, "/api/v1/vault/refs", {
      method: "POST",
      token: grant.token,
      body: { vault_ref: customVaultRef, material: customSecret, purpose: "catalog.auth:catalog.custom_http", label: "Custom catalog auth" },
    });
    const customCatalog = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=custom&limit=5");
    const customProvider = customCatalog.providers.find((provider) => provider.id === "catalog.custom_http");
    assert.equal(customProvider.status, "available");
    assert.equal(customProvider.catalogAuthResolved, true);
    assert.equal(customProvider.catalogAuthScheme, "api_key");
    assert.equal(customCatalog.results.find((entry) => entry.catalogProviderId === "catalog.custom_http")?.catalogAuth.resolvedMaterial, true);
    assert.ok(customCatalogServer.observedHeaders().some((headers) => headers["x-catalog-key"] === customSecret));
    assert.equal(JSON.stringify(customCatalog).includes(customSecret), false);
    assert.equal(JSON.stringify(customCatalog).includes(customVaultRef), false);

    const configuredLive = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.huggingface", {
      method: "PATCH",
      token: grant.token,
      body: {
        enabled: true,
        auth_vault_ref: liveVaultRef,
        auth_scheme: "bearer",
        auth_header_name: "authorization",
      },
    });
    assert.equal(configuredLive.catalogAuthConfigured, true);
    assert.equal(configuredLive.catalogAuthScheme, "bearer");
    assert.equal(JSON.stringify(configuredLive).includes(liveVaultRef), false);
    await expectOk(daemon.endpoint, "/api/v1/vault/refs", {
      method: "POST",
      token: grant.token,
      body: { vault_ref: liveVaultRef, material: liveSecret, purpose: "catalog.auth:catalog.huggingface", label: "Live catalog auth" },
    });
    const liveCatalog = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=qwen&format=gguf&limit=5");
    const liveProvider = liveCatalog.providers.find((provider) => provider.id === "catalog.huggingface");
    assert.equal(liveProvider.status, "available");
    assert.equal(liveProvider.catalogAuthResolved, true);
    const liveEntry = liveCatalog.results.find((entry) => entry.catalogProviderId === "catalog.huggingface");
    assert.equal(liveEntry?.catalogAuth.resolvedMaterial, true);
    assert.ok(liveCatalogServer.observedHeaders().some((headers) => headers.authorization === `Bearer ${liveSecret}`));
    const liveImport = await expectOk(daemon.endpoint, "/api/v1/models/catalog/import-url", {
      method: "POST",
      token: grant.token,
      body: { source_url: liveEntry.sourceUrl, model_id: "native:auth-live-catalog", max_bytes: liveEntry.sizeBytes, transfer_approved: true },
    });
    assert.equal(liveImport.status, "completed");
    assert.ok(liveCatalogServer.observedHeaders().some((headers) => headers.authorization === `Bearer ${liveSecret}`));
    const importReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${liveImport.catalogReceiptId}`);
    assert.equal(importReceipt.details.catalogAuth.resolvedMaterial, true);
    const downloadReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${liveImport.download.receiptId}`);
    assert.equal(downloadReceipt.details.catalogAuth.resolvedMaterial, true);
    const projection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
    assert.equal(JSON.stringify(projection).includes(customSecret), false);
    assert.equal(JSON.stringify(projection).includes(liveSecret), false);
    assert.equal(directoryContainsNeedle(stateDir, customSecret), false);
    assert.equal(directoryContainsNeedle(stateDir, liveSecret), false);
  } finally {
    restoreEnv("IOI_LIVE_MODEL_CATALOG", priorLiveCatalog);
    restoreEnv("IOI_LIVE_MODEL_DOWNLOAD", priorLiveDownload);
    restoreEnv("IOI_MODEL_CATALOG_HF_BASE_URL", priorCatalogBase);
    await customCatalogServer.close();
    await liveCatalogServer.close();
    await daemon.close();
  }
});

test("catalog provider OAuth sessions exchange, refresh, revoke, and keep tokens redacted", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-catalog-oauth-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-catalog-oauth-state-"));
  const oauth = await startFakeOAuthServer();
  const customCatalogServer = await startFakeCustomCatalogServer({
    requiredHeaders: () => ({ authorization: `Bearer ${oauth.currentAccessToken()}` }),
  });
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: { allowed: ["provider.write:*", "vault.write:*", "vault.read:*", "vault.delete:*"] },
    });
    const configuredCustom = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.custom_http", {
      method: "PATCH",
      token: grant.token,
      body: {
        enabled: true,
        base_url: customCatalogServer.endpoint,
        auth_scheme: "oauth2",
        auth_header_name: "authorization",
      },
    });
    assert.equal(configuredCustom.catalogAuthScheme, "oauth2");
    assert.equal(configuredCustom.oauthBoundary.status, "requires_oauth_exchange");

    const exchanged = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.custom_http/oauth/exchange", {
      method: "POST",
      token: grant.token,
      body: {
        token_endpoint: oauth.endpoint,
        authorization_code: "valid-oauth-code",
        client_id: "catalog-test-client",
        scopes: ["catalog.read"],
      },
    });
    assert.equal(exchanged.catalogAuthScheme, "oauth2");
    assert.equal(exchanged.oauthBoundary.status, "active");
    assert.equal(exchanged.oauthSession.status, "active");
    assert.equal(JSON.stringify(exchanged).includes(oauth.tokens.access), false);
    assert.equal(JSON.stringify(exchanged).includes(oauth.tokens.refresh), false);
    assert.equal(JSON.stringify(exchanged).includes(oauth.endpoint), false);

    const searched = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=custom&limit=5");
    const customProvider = searched.providers.find((provider) => provider.id === "catalog.custom_http");
    assert.equal(customProvider.status, "available");
    assert.equal(customProvider.catalogAuthResolved, true);
    assert.equal(customProvider.oauthBoundary.status, "active");
    assert.ok(customCatalogServer.observedHeaders().some((headers) => headers.authorization === `Bearer ${oauth.tokens.access}`));
    assert.equal(JSON.stringify(searched).includes(oauth.tokens.access), false);

    const refreshed = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.custom_http/oauth/refresh", {
      method: "POST",
      token: grant.token,
      body: {},
    });
    assert.equal(refreshed.oauthSession.status, "active");
    assert.equal(refreshed.oauthSession.refreshCount, 1);
    assert.equal(JSON.stringify(refreshed).includes(oauth.tokens.refreshedAccess), false);
    assert.equal(JSON.stringify(refreshed).includes(oauth.tokens.refreshedRefresh), false);
    const searchedAfterRefresh = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=custom&limit=5");
    assert.ok(customCatalogServer.observedHeaders().some((headers) => headers.authorization === `Bearer ${oauth.tokens.refreshedAccess}`));
    assert.equal(searchedAfterRefresh.providers.find((provider) => provider.id === "catalog.custom_http").oauthBoundary.refreshCount, 1);

    const revoked = await expectOk(daemon.endpoint, "/api/v1/models/catalog/providers/catalog.custom_http/oauth/revoke", {
      method: "POST",
      token: grant.token,
      body: {},
    });
    assert.equal(revoked.oauthSession.status, "revoked");
    const blocked = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=custom&limit=5");
    const blockedProvider = blocked.providers.find((provider) => provider.id === "catalog.custom_http");
    assert.equal(blockedProvider.status, "blocked");
    assert.equal(blockedProvider.catalogAuthResolved, false);
    assert.equal(blockedProvider.oauthBoundary.status, "revoked");

    const projection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
    assert.ok(projection.oauthSessions.some((session) => session.status === "revoked"));
    for (const secret of [oauth.tokens.access, oauth.tokens.refresh, oauth.tokens.refreshedAccess, oauth.tokens.refreshedRefresh, oauth.endpoint, "valid-oauth-code"]) {
      assert.equal(JSON.stringify(projection).includes(secret), false);
      assert.equal(directoryContainsNeedle(stateDir, secret), false);
    }
    assert.ok(oauth.observed().some((entry) => entry.grantType === "authorization_code"));
    assert.ok(oauth.observed().some((entry) => entry.grantType === "refresh_token"));
  } finally {
    await oauth.close();
    await customCatalogServer.close();
    await daemon.close();
  }
});

test("model download lifecycle supports progress, failure, cancel, cleanup, and projection replay", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-download-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-download-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  const liveCatalogServer = await startFakeHuggingFaceCatalogServer();
  const priorLiveCatalog = process.env.IOI_LIVE_MODEL_CATALOG;
  const priorLiveDownload = process.env.IOI_LIVE_MODEL_DOWNLOAD;
  const priorCatalogBase = process.env.IOI_MODEL_CATALOG_HF_BASE_URL;
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: { allowed: ["model.download:*", "model.import:*", "model.delete:*", "model.chat:*", "route.use:*"] },
    });

    const catalog = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=native");
    assert.ok(catalog.results.some((entry) => entry.modelId === "autopilot/native-fixture-3b"));
    assert.equal(catalog.providers.find((provider) => provider.id === "catalog.huggingface")?.status, "gated");

    process.env.IOI_LIVE_MODEL_CATALOG = "1";
    process.env.IOI_LIVE_MODEL_DOWNLOAD = "1";
    process.env.IOI_MODEL_CATALOG_HF_BASE_URL = liveCatalogServer.endpoint;
    const liveCatalog = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=qwen&format=gguf&quantization=Q4&limit=5");
    assert.equal(liveCatalog.providers.find((provider) => provider.id === "catalog.huggingface")?.status, "available");
    const liveEntry = liveCatalog.results.find((entry) => entry.catalogProviderId === "catalog.huggingface");
    assert.equal(liveEntry.format, "gguf");
    assert.equal(liveEntry.quantization, "Q4_K_M");
    assert.equal(liveEntry.architecture, "qwen");
    assert.equal(liveEntry.parameterCount, "3B");
    assert.ok(liveEntry.backendCompatibility.some((backend) => backend.backendKind === "llama_cpp" && backend.score >= 80));
    assert.equal(liveEntry.downloadRisk.status, "low");
    assert.ok(liveEntry.recommendation.score >= 80);
    assert.equal(liveEntry.benchmarkReadiness.chat, true);
    assert.match(liveEntry.sourceUrl, /\/resolve\/main\/qwen-3b-Q4_K_M\.gguf$/);
    const liveImport = await expectOk(daemon.endpoint, "/api/v1/models/catalog/import-url", {
      method: "POST",
      token: grant.token,
      body: { source_url: liveEntry.sourceUrl, model_id: "native:hf-live", format: "gguf", quantization: "Q4_K_M", max_bytes: liveEntry.sizeBytes, transfer_approved: true },
    });
    assert.equal(liveImport.status, "completed");
    assert.equal(liveImport.download.variant.format, "gguf");
    assert.equal(liveImport.download.variant.recommendation.label, "recommended");
    assert.equal(liveImport.download.variant.downloadRisk.status, "low");
    assert.equal(liveImport.download.maxBytes, liveEntry.sizeBytes);
    assert.equal(liveImport.download.bytesCompleted > 0, true);
    assert.equal(fs.existsSync(liveImport.download.targetPath), true);
    const liveImportReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${liveImport.catalogReceiptId}`);
    assert.equal(liveImportReceipt.details.approvalDecision.required, true);
    assert.equal(liveImportReceipt.details.approvalDecision.approved, true);
    assert.ok(liveImportReceipt.details.selectionReceiptFields.includes("download_risk"));
    assert.equal(liveImport.download.downloadPolicy.externalTransferApproved, true);
    assert.equal(liveImport.download.downloadPolicy.status, "ready");

    const downloadOnlyGrant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: { allowed: ["model.download:*"] },
    });
    const deniedCatalogImport = await requestJson(daemon.endpoint, "/api/v1/models/catalog/import-url", {
      method: "POST",
      token: downloadOnlyGrant.token,
      body: { source_url: "fixture://catalog/autopilot-native-3b-q4", model_id: "native:catalog-denied-import-scope" },
    });
    assert.equal(deniedCatalogImport.response.status, 403);

    delete process.env.IOI_LIVE_MODEL_DOWNLOAD;
    const gatedLiveImport = await requestJson(daemon.endpoint, "/api/v1/models/catalog/import-url", {
      method: "POST",
      token: grant.token,
      body: { source_url: liveEntry.sourceUrl, model_id: "native:hf-gated" },
    });
    assert.equal(gatedLiveImport.response.status, 424);
    process.env.IOI_LIVE_MODEL_DOWNLOAD = "1";

    const unapprovedLiveDownload = await requestJson(daemon.endpoint, "/api/v1/models/download", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "native:hf-unapproved",
        provider_id: "provider.autopilot.local",
        source_url: liveEntry.sourceUrl,
        format: "gguf",
        quantization: "Q4_K_M",
      },
    });
    assert.equal(unapprovedLiveDownload.response.status, 403);
    assert.equal(unapprovedLiveDownload.json.error.code, "external_transfer_approval_required");

    const secretSource = `${liveEntry.sourceUrl}?api_key=hf-live-secret-token`;
    const liveSecretDownload = await expectOk(daemon.endpoint, "/api/v1/models/download", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "native:hf-secret-redacted",
        provider_id: "provider.autopilot.local",
        source_url: secretSource,
        format: "gguf",
        quantization: "Q4_K_M",
        transfer_approved: true,
        bandwidth_bps: 1024 * 1024,
        retry_limit: 2,
        resume_download: true,
      },
    });
    assert.equal(liveSecretDownload.status, "completed");
    assert.equal(liveSecretDownload.downloadPolicy.bandwidthLimitBps, 1024 * 1024);
    assert.equal(liveSecretDownload.downloadPolicy.retryLimit, 2);
    assert.equal(JSON.stringify(liveSecretDownload).includes("hf-live-secret-token"), false);

    const retriedSource = `${liveEntry.sourceUrl}?drop_once_after=12&attempt_key=retry-in-job`;
    const retriedDownload = await expectOk(daemon.endpoint, "/api/v1/models/download", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "native:hf-retry-resume",
        provider_id: "provider.autopilot.local",
        source_url: retriedSource,
        format: "gguf",
        quantization: "Q4_K_M",
        transfer_approved: true,
        retry_limit: 1,
        resume_download: true,
      },
    });
    assert.equal(retriedDownload.status, "completed");
    assert.equal(retriedDownload.attemptCount, 2);
    assert.equal(retriedDownload.retryCount, 1);
    assert.equal(retriedDownload.resumeOffset > 0, true);
    assert.equal(retriedDownload.transfer.resumed, true);

    const interruptedSecretSource = `${liveEntry.sourceUrl}?drop_once_after=13&attempt_key=resume-later&api_key=hf-partial-secret-token`;
    const interruptedDownload = await expectOk(daemon.endpoint, "/api/v1/models/download", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "native:hf-interrupted-resume",
        provider_id: "provider.autopilot.local",
        source_url: interruptedSecretSource,
        format: "gguf",
        quantization: "Q4_K_M",
        transfer_approved: true,
        retry_limit: 0,
        resume_download: true,
      },
    });
    assert.equal(interruptedDownload.status, "failed");
    assert.equal(interruptedDownload.cleanupState, "retained_partial");
    assert.equal(interruptedDownload.attemptCount, 1);
    assert.equal(fs.existsSync(`${interruptedDownload.targetPath}.part`), true);
    assert.equal(fs.existsSync(`${interruptedDownload.targetPath}.part.json`), true);
    assert.equal(fs.readFileSync(`${interruptedDownload.targetPath}.part.json`, "utf8").includes("hf-partial-secret-token"), false);
    const resumedDownload = await expectOk(daemon.endpoint, "/api/v1/models/download", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "native:hf-interrupted-resume",
        provider_id: "provider.autopilot.local",
        source_url: interruptedSecretSource,
        format: "gguf",
        quantization: "Q4_K_M",
        transfer_approved: true,
        retry_limit: 1,
        resume_download: true,
      },
    });
    assert.equal(resumedDownload.status, "completed");
    assert.equal(resumedDownload.resumeOffset > 0, true);
    assert.equal(fs.existsSync(`${resumedDownload.targetPath}.part`), false);
    assert.equal(fs.existsSync(`${resumedDownload.targetPath}.part.json`), false);

    const retryExhausted = await expectOk(daemon.endpoint, "/api/v1/models/download", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "native:hf-retry-exhausted",
        provider_id: "provider.autopilot.local",
        source_url: `${liveEntry.sourceUrl}?status=503&attempt_key=retry-exhausted`,
        format: "gguf",
        quantization: "Q4_K_M",
        transfer_approved: true,
        retry_limit: 1,
        resume_download: true,
      },
    });
    assert.equal(retryExhausted.status, "failed");
    assert.equal(retryExhausted.failureReason, "http_503");
    assert.equal(retryExhausted.attemptCount, 2);
    assert.equal(retryExhausted.retryCount, 1);

    const checksumMismatch = await expectOk(daemon.endpoint, "/api/v1/models/download", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "native:hf-checksum-mismatch",
        provider_id: "provider.autopilot.local",
        source_url: liveEntry.sourceUrl,
        format: "gguf",
        quantization: "Q4_K_M",
        transfer_approved: true,
        checksum: "sha256:not-the-real-checksum",
        retry_limit: 1,
      },
    });
    assert.equal(checksumMismatch.status, "failed");
    assert.equal(checksumMismatch.failureReason, "checksum_mismatch");
    assert.equal(checksumMismatch.attemptCount, 1);
    assert.equal(fs.existsSync(checksumMismatch.targetPath), false);

    const oversizedLiveDownload = await expectOk(daemon.endpoint, "/api/v1/models/download", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "native:hf-oversized",
        provider_id: "provider.autopilot.local",
        source_url: liveEntry.sourceUrl,
        format: "gguf",
        quantization: "Q4_K_M",
        max_bytes: 1,
        transfer_approved: true,
      },
    });
    assert.equal(oversizedLiveDownload.status, "failed");
    assert.equal(oversizedLiveDownload.failureReason, "size_limit_exceeded");

    const catalogImport = await expectOk(daemon.endpoint, "/api/v1/models/catalog/import-url", {
      method: "POST",
      token: grant.token,
      body: { source_url: "fixture://catalog/autopilot-native-3b-q4", model_id: "native:catalog-imported" },
    });
    assert.equal(catalogImport.status, "completed");
    assert.match(catalogImport.catalogReceiptId, /^receipt_model_lifecycle_/);
    assert.equal(catalogImport.download.variant.quantization, "Q4_K_M");

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

    const importSource = path.join(cwd, "dry-run-source.Q4_K_M.gguf");
    fs.writeFileSync(importSource, "family=dry-run-source\ncontext=1024\nquantization=Q4_K_M\n");
    const dryRun = await expectOk(daemon.endpoint, "/api/v1/models/import", {
      method: "POST",
      token: grant.token,
      body: { model_id: "native:dry-run", path: importSource, import_mode: "dry_run" },
    });
    assert.equal(dryRun.status, "dry_run");
    assert.equal(dryRun.importMode, "dry_run");
    const copied = await expectOk(daemon.endpoint, "/api/v1/models/import", {
      method: "POST",
      token: grant.token,
      body: { model_id: "native:copied-import", path: importSource, import_mode: "copy" },
    });
    assert.equal(copied.importMode, "copy");
    assert.equal(copied.artifactPath.startsWith(stateDir), true);
    assert.equal(fs.existsSync(copied.artifactPath), true);

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
      body: { cleanup_partial: true, confirm_destructive: true },
    });
    assert.equal(canceled.status, "canceled");
    assert.equal(canceled.destructiveConfirmation.confirmed, true);
    assert.equal(fs.existsSync(canceled.targetPath), false);

    const orphanDir = path.join(stateDir, "models", "orphan-fixtures");
    fs.mkdirSync(orphanDir, { recursive: true });
    const orphanPath = path.join(orphanDir, "unused.Q4_K_M.gguf");
    fs.writeFileSync(orphanPath, "orphan bytes");

    const cleanup = await expectOk(daemon.endpoint, "/api/v1/models/storage/cleanup", {
      method: "POST",
      token: grant.token,
    });
    assert.equal(cleanup.status, "scanned");
    assert.equal(cleanup.orphanCount >= 1, true);
    assert.equal(cleanup.cleanupState, "scan_only");
    assert.match(cleanup.receiptId, /^receipt_model_lifecycle_/);

    const cleanupDenied = await requestJson(daemon.endpoint, "/api/v1/models/storage/cleanup", {
      method: "POST",
      token: grant.token,
      body: { remove_orphans: true },
    });
    assert.equal(cleanupDenied.response.status, 409);

    const cleanupRemoved = await expectOk(daemon.endpoint, "/api/v1/models/storage/cleanup", {
      method: "POST",
      token: grant.token,
      body: { remove_orphans: true, confirm_destructive: true },
    });
    assert.equal(cleanupRemoved.status, "cleaned");
    assert.equal(cleanupRemoved.destructiveConfirmation.confirmed, true);
    assert.equal(cleanupRemoved.cleanedBytes > 0, true);
    assert.equal(fs.existsSync(orphanPath), false);

    const deleted = await expectOk(daemon.endpoint, `/api/v1/models/${encodeURIComponent(copied.id)}`, {
      method: "DELETE",
      token: grant.token,
      body: { confirm_destructive: true },
    });
    assert.equal(deleted.status, "deleted");
    assert.equal(deleted.destructiveConfirmation.confirmed, true);
    assert.equal(deleted.projectedFreedBytes > 0, true);
    assert.equal(fs.existsSync(copied.artifactPath), false);

    const receipts = await expectOk(daemon.endpoint, "/api/v1/receipts");
    assert.ok(receipts.some((receipt) => receipt.details?.operation === "model_catalog_import_url"));
    assert.ok(receipts.some((receipt) => receipt.details?.operation === "model_import_dry_run"));
    assert.ok(receipts.some((receipt) => receipt.details?.operation === "model_artifact_delete"));
    assert.ok(receipts.some((receipt) => receipt.details?.operation === "model_storage_cleanup"));
    assert.ok(receipts.some((receipt) => receipt.details?.operation === "model_download_completed"));
    assert.ok(receipts.some((receipt) => receipt.details?.operation === "model_download_failed"));
    assert.ok(receipts.some((receipt) => receipt.details?.operation === "model_download_canceled"));
    assert.ok(receipts.some((receipt) => receipt.details?.downloadPolicy?.bandwidthLimitBps === 1024 * 1024));
    assert.ok(receipts.some((receipt) => receipt.details?.destructiveConfirmation?.confirmed === true));
    assert.ok(receipts.some((receipt) => receipt.details?.downloadMode === "live_network"));
    assert.ok(receipts.some((receipt) => receipt.details?.operation === "model_download_retry"));
    assert.ok(receipts.some((receipt) => receipt.details?.operation === "model_download_resume"));
    assert.ok(receipts.some((receipt) => receipt.details?.transfer?.retryCount === 1));
    assert.equal(JSON.stringify(receipts).includes("hf-partial-secret-token"), false);

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
    assert.equal(JSON.stringify(projection).includes("hf-live-secret-token"), false);
    assert.equal(JSON.stringify(projection).includes("hf-partial-secret-token"), false);
    assert.equal(projection.catalog.providers.find((provider) => provider.id === "catalog.huggingface")?.status, "configured");
  } finally {
    restoreEnv("IOI_LIVE_MODEL_CATALOG", priorLiveCatalog);
    restoreEnv("IOI_LIVE_MODEL_DOWNLOAD", priorLiveDownload);
    restoreEnv("IOI_MODEL_CATALOG_HF_BASE_URL", priorCatalogBase);
    await liveCatalogServer.close();
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
    assert.ok(projection.backendProcesses.some((process) => process.backendId === "backend.autopilot.native-local.fixture"));
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
    const restartedProjection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
    const restartedProcess = restartedProjection.backendProcesses.find((process) => process.backendId === "backend.autopilot.native-local.fixture");
    assert.equal(restartedProcess.status, "stale_recovered");
    assert.equal(restartedProcess.staleReason, "daemon_boot_mismatch");
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
        id: "provider.test.ollama",
        kind: "ollama",
        label: "Fake Ollama",
        api_format: "ollama",
        base_url: providerServer.endpoint,
        status: "configured",
        privacy_class: "local_private",
        capabilities: ["chat", "responses", "embeddings"],
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

    const streamedChat = await requestSse(daemon.endpoint, "/v1/chat/completions", {
      method: "POST",
      token: grant.token,
      body: {
        route_id: "route.test.ollama",
        model: "qwen3:8b",
        stream: true,
        messages: [{ role: "user", content: "stream ollama chat" }],
      },
    });
    assert.equal(streamedChat.response.status, 200);
    assert.equal(streamedChat.response.headers.get("x-ioi-stream-source"), "provider_native");
    const streamedChatChunks = parseOpenAiSseChunks(streamedChat.text);
    const streamedChatText = streamedChatChunks
      .filter((chunk) => chunk !== "[DONE]")
      .map((chunk) => chunk.choices?.[0]?.delta?.content ?? "")
      .join("");
    assert.equal(streamedChatText, "fake ollama streamed chat");
    const streamedChatMetadata = streamedChatChunks.find((chunk) => chunk !== "[DONE]" && chunk.stream_receipt_id);
    assert.equal(streamedChatMetadata.route_id, "route.test.ollama");
    assert.equal(streamedChatMetadata.provider_stream, "native");
    const streamedChatReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${streamedChatMetadata.receipt_id}`);
    assert.equal(streamedChatReceipt.details.providerId, "provider.test.ollama");
    assert.equal(streamedChatReceipt.details.providerResponseKind, "ollama.chat.stream");
    assert.ok(streamedChatReceipt.details.backendEvidenceRefs.includes("ollama_api_chat_native_stream"));
    const streamedChatCompleteReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${streamedChatMetadata.stream_receipt_id}`);
    assert.equal(streamedChatCompleteReceipt.details.invocationReceiptId, streamedChatMetadata.receipt_id);
    assert.equal(streamedChatCompleteReceipt.details.outputHash, crypto.createHash("sha256").update(streamedChatText).digest("hex"));

    const streamedResponse = await requestSse(daemon.endpoint, "/v1/responses", {
      method: "POST",
      token: grant.token,
      body: {
        route_id: "route.test.ollama",
        model: "qwen3:8b",
        stream: true,
        input: "stream ollama response",
      },
    });
    assert.equal(streamedResponse.response.status, 200);
    assert.equal(streamedResponse.response.headers.get("x-ioi-stream-source"), "provider_native");
    const streamedResponseText = streamedResponse.events
      .filter((event) => event.event === "response.output_text.delta")
      .map((event) => event.data.delta)
      .join("");
    assert.equal(streamedResponseText, "fake ollama streamed chat");
    const streamedResponseCompleted = streamedResponse.events.find((event) => event.event === "response.completed")?.data.response;
    assert.equal(streamedResponseCompleted.route_id, "route.test.ollama");
    assert.equal(streamedResponseCompleted.provider_stream, "native");
    assert.equal(typeof streamedResponseCompleted.receipt_id, "string");
    assert.equal(typeof streamedResponseCompleted.stream_receipt_id, "string");
    const streamedResponseReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${streamedResponseCompleted.receipt_id}`);
    assert.equal(streamedResponseReceipt.details.providerId, "provider.test.ollama");
    assert.equal(streamedResponseReceipt.details.providerResponseKind, "ollama.responses.stream");
    assert.ok(streamedResponseReceipt.details.backendEvidenceRefs.includes("ollama_api_chat_native_stream"));
    const streamedResponseCompleteReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${streamedResponseCompleted.stream_receipt_id}`);
    assert.equal(streamedResponseCompleteReceipt.details.invocationReceiptId, streamedResponseCompleted.receipt_id);
    assert.equal(streamedResponseCompleteReceipt.details.outputHash, crypto.createHash("sha256").update(streamedResponseText).digest("hex"));

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

test("Ollama provider can supervise serve process, project loaded models, and unload through keep-alive", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-ollama-supervisor-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-ollama-supervisor-state-"));
  const providerServer = await startFakeOllamaServer();
  const callsPath = path.join(cwd, "fake-ollama-calls.jsonl");
  const fakeBinary = path.join(cwd, "ollama");
  fs.writeFileSync(
    fakeBinary,
    `#!/usr/bin/env node
const fs = require("fs");
const callsPath = process.env.IOI_FAKE_OLLAMA_CALLS;
if (callsPath) fs.appendFileSync(callsPath, JSON.stringify({ argv: process.argv.slice(2), host: process.env.OLLAMA_HOST }) + "\\n");
process.stdout.write("fake ollama serve ready\\n");
process.on("SIGTERM", () => process.exit(0));
setInterval(() => {}, 1000);
`,
  );
  fs.chmodSync(fakeBinary, 0o755);
  const priorOllamaHost = process.env.OLLAMA_HOST;
  const priorOllamaBinary = process.env.IOI_OLLAMA_BINARY;
  const priorCalls = process.env.IOI_FAKE_OLLAMA_CALLS;
  process.env.OLLAMA_HOST = providerServer.endpoint;
  process.env.IOI_OLLAMA_BINARY = fakeBinary;
  process.env.IOI_FAKE_OLLAMA_CALLS = callsPath;
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: {
        allowed: [
          "model.mount:*",
          "model.load:*",
          "model.unload:*",
          "model.chat:*",
          "route.write:*",
          "route.use:*",
          "backend.control:*",
        ],
      },
    });
    const backendStart = await expectOk(daemon.endpoint, "/api/v1/backends/backend.ollama/start", {
      method: "POST",
      token: grant.token,
      body: { load_options: { identifier: "ollama-supervisor-test" } },
    });
    assert.equal(backendStart.process.spawned, true);
    assert.equal(backendStart.process.spawnStatus, "spawned");
    const calls = fs.readFileSync(callsPath, "utf8");
    assert.equal(calls.includes('"serve"'), true);
    assert.equal(calls.includes(providerServer.endpoint), true);

    const providerModels = await expectOk(daemon.endpoint, "/api/v1/providers/provider.ollama/models");
    assert.ok(providerModels.some((model) => model.modelId === "qwen3:8b"));
    const mounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "qwen3:8b",
        provider_id: "provider.ollama",
        id: "endpoint.test.ollama.supervised",
      },
    });
    const loaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
      method: "POST",
      token: grant.token,
      body: {
        endpoint_id: mounted.id,
        load_options: { ttlSeconds: 600, identifier: "ollama-load-test" },
      },
    });
    assert.equal(loaded.backend, "ollama");
    assert.equal(loaded.backendId, "backend.ollama");
    assert.equal(loaded.backendProcess.spawned, true);
    assert.equal(loaded.providerEvidenceRefs.includes("ollama_generate_keep_alive_load"), true);

    const providerLoaded = await expectOk(daemon.endpoint, "/api/v1/providers/provider.ollama/loaded");
    assert.ok(providerLoaded.some((model) => model.modelId === "qwen3:8b"));
    assert.equal(providerLoaded.find((model) => model.modelId === "qwen3:8b")?.backendProcess?.spawnStatus, "spawned");

    await expectOk(daemon.endpoint, "/api/v1/routes", {
      method: "POST",
      token: grant.token,
      body: {
        id: "route.test.ollama.supervised",
        role: "ollama-supervised-test",
        privacy: "local_only",
        fallback: [mounted.id],
        provider_eligibility: ["ollama"],
      },
    });
    const chat = await expectOk(daemon.endpoint, "/api/v1/chat", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.test.ollama.supervised", input: "hello supervised ollama" },
    });
    const receipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${chat.receipt_id}`);
    assert.equal(receipt.details.backend, "ollama");
    assert.equal(receipt.details.backendId, "backend.ollama");

    const unloaded = await expectOk(daemon.endpoint, "/api/v1/models/unload", {
      method: "POST",
      token: grant.token,
      body: { instance_id: loaded.id },
    });
    assert.equal(unloaded.status, "unloaded");
    const loadedAfterUnload = await expectOk(daemon.endpoint, "/api/v1/providers/provider.ollama/loaded");
    assert.equal(loadedAfterUnload.some((model) => model.modelId === "qwen3:8b"), false);
    const backendStop = await expectOk(daemon.endpoint, "/api/v1/backends/backend.ollama/stop", {
      method: "POST",
      token: grant.token,
    });
    assert.equal(backendStop.process.processStatus, "stopped");
    const logs = await expectOk(daemon.endpoint, "/api/v1/backends/backend.ollama/logs");
    assert.ok(logs.some((record) => record.event === "backend_process_start"));
    assert.ok(logs.some((record) => record.event === "backend_process_stop"));
  } finally {
    await daemon.close();
    await providerServer.close();
    restoreEnv("OLLAMA_HOST", priorOllamaHost);
    restoreEnv("IOI_OLLAMA_BINARY", priorOllamaBinary);
    restoreEnv("IOI_FAKE_OLLAMA_CALLS", priorCalls);
  }
});

test("vLLM and OpenAI-compatible adapters support responses fallback, embeddings, and redacted provider errors", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-vllm-provider-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-vllm-provider-state-"));
  const optionalAuthVaultRef = "vault://provider/openai-compatible/api-key";
  const optionalAuthMaterial = crypto.randomBytes(18).toString("base64url");
  const providerServer = await startFakeVllmServer({ responsesStatus: 404 });
  const streamServer = await startFakeOpenAiCompatibleServer({ responsesStream: true });
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

    await expectOk(daemon.endpoint, "/api/v1/providers", {
      method: "POST",
      token: grant.token,
      body: {
        id: "provider.test.openai-compatible-stream",
        kind: "openai_compatible",
        label: "Streaming OpenAI-compatible",
        api_format: "openai_compatible",
        base_url: `${streamServer.endpoint}/v1`,
        status: "configured",
        privacy_class: "workspace",
        capabilities: ["chat", "responses"],
      },
    });
    await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "qwen/qwen3.5-9b",
        provider_id: "provider.test.openai-compatible-stream",
        id: "endpoint.test.openai-compatible-stream",
      },
    });
    await expectOk(daemon.endpoint, "/api/v1/routes", {
      method: "POST",
      token: grant.token,
      body: {
        id: "route.test.openai-compatible-stream",
        role: "openai-compatible-stream-test",
        privacy: "local_or_enterprise",
        fallback: ["endpoint.test.openai-compatible-stream"],
        provider_eligibility: ["openai_compatible"],
        denied_providers: [],
      },
    });
    const streamed = await requestSse(daemon.endpoint, "/v1/chat/completions", {
      method: "POST",
      token: grant.token,
      body: {
        route_id: "route.test.openai-compatible-stream",
        model: "qwen/qwen3.5-9b",
        stream: true,
        messages: [{ role: "user", content: "stream through provider" }],
      },
    });
    assert.equal(streamed.response.status, 200);
    assert.equal(streamed.response.headers.get("x-ioi-stream-source"), "provider_native");
    const streamedChunks = parseOpenAiSseChunks(streamed.text);
    assert.equal(streamedChunks.at(-1), "[DONE]");
    const streamedText = streamedChunks
      .filter((chunk) => chunk !== "[DONE]")
      .map((chunk) => chunk.choices?.[0]?.delta?.content ?? "")
      .join("");
    assert.equal(streamedText, "fake openai-compatible streamed chat");
    const metadataChunk = streamedChunks.find((chunk) => chunk !== "[DONE]" && chunk.provider_stream === "native");
    assert.equal(metadataChunk.route_id, "route.test.openai-compatible-stream");
    assert.equal(typeof metadataChunk.receipt_id, "string");
    assert.equal(typeof metadataChunk.stream_receipt_id, "string");
    assert.equal(streamed.response.headers.get("x-ioi-receipt-id"), metadataChunk.receipt_id);
    const streamStartReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${metadataChunk.receipt_id}`);
    assert.equal(streamStartReceipt.kind, "model_invocation");
    assert.equal(streamStartReceipt.details.providerId, "provider.test.openai-compatible-stream");
    assert.equal(streamStartReceipt.details.streamSource, "provider_native");
    assert.equal(streamStartReceipt.details.streamStatus, "started");
    assert.equal(streamStartReceipt.details.providerResponseKind, "chat.completions.stream");
    assert.ok(streamStartReceipt.details.backendEvidenceRefs.includes("openai_compatible_provider_native_stream"));
    const streamCompleteReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${metadataChunk.stream_receipt_id}`);
    assert.equal(streamCompleteReceipt.kind, "model_invocation_stream_completed");
    assert.equal(streamCompleteReceipt.details.invocationReceiptId, metadataChunk.receipt_id);
    assert.equal(streamCompleteReceipt.details.outputHash, crypto.createHash("sha256").update(streamedText).digest("hex"));
    assert.equal(streamCompleteReceipt.details.providerResponseKind, "chat.completions.stream");

    const streamedResponse = await requestSse(daemon.endpoint, "/v1/responses", {
      method: "POST",
      token: grant.token,
      body: {
        route_id: "route.test.openai-compatible-stream",
        model: "qwen/qwen3.5-9b",
        stream: true,
        input: "stream response through provider",
      },
    });
    assert.equal(streamedResponse.response.status, 200);
    assert.equal(streamedResponse.response.headers.get("x-ioi-stream-source"), "provider_native");
    assert.equal(streamedResponse.events[0].event, "response.created");
    assert.ok(streamedResponse.events.some((event) => event.event === "response.output_text.delta"));
    const streamedResponseText = streamedResponse.events
      .filter((event) => event.event === "response.output_text.delta")
      .map((event) => event.data.delta)
      .join("");
    assert.equal(streamedResponseText, "fake openai-compatible streamed response");
    const responseMetadata = streamedResponse.events.find((event) => event.event === "response.ioi.receipt")?.data;
    assert.equal(responseMetadata.route_id, "route.test.openai-compatible-stream");
    assert.equal(responseMetadata.provider_stream, "native");
    assert.equal(typeof responseMetadata.receipt_id, "string");
    assert.equal(typeof responseMetadata.stream_receipt_id, "string");
    assert.equal(streamedResponse.response.headers.get("x-ioi-receipt-id"), responseMetadata.receipt_id);
    const responseStreamStartReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${responseMetadata.receipt_id}`);
    assert.equal(responseStreamStartReceipt.kind, "model_invocation");
    assert.equal(responseStreamStartReceipt.details.providerId, "provider.test.openai-compatible-stream");
    assert.equal(responseStreamStartReceipt.details.streamSource, "provider_native");
    assert.equal(responseStreamStartReceipt.details.streamStatus, "started");
    assert.equal(responseStreamStartReceipt.details.providerResponseKind, "responses.stream");
    assert.ok(responseStreamStartReceipt.details.backendEvidenceRefs.includes("openai_compatible_responses_provider_native_stream"));
    const responseStreamCompleteReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${responseMetadata.stream_receipt_id}`);
    assert.equal(responseStreamCompleteReceipt.kind, "model_invocation_stream_completed");
    assert.equal(responseStreamCompleteReceipt.details.invocationReceiptId, responseMetadata.receipt_id);
    assert.equal(responseStreamCompleteReceipt.details.outputHash, crypto.createHash("sha256").update(streamedResponseText).digest("hex"));
    assert.equal(responseStreamCompleteReceipt.details.providerResponseKind, "responses.stream");

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
    assert.equal(invocation.details.backend, "vllm");
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
    await streamServer.close();
    await optionalAuthServer.close();
    await errorServer.close();
  }
});

test("vLLM provider can supervise serve process and invoke through OpenAI-compatible server", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-vllm-supervisor-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-vllm-supervisor-state-"));
  const providerServer = await startFakeVllmServer({ responsesStatus: 404 });
  const callsPath = path.join(cwd, "fake-vllm-calls.jsonl");
  const fakeBinary = path.join(cwd, "vllm");
  fs.writeFileSync(
    fakeBinary,
    `#!/usr/bin/env node
const fs = require("fs");
const callsPath = process.env.IOI_FAKE_VLLM_CALLS;
if (callsPath) fs.appendFileSync(callsPath, JSON.stringify({ argv: process.argv.slice(2), baseUrl: process.env.IOI_MODEL_BACKEND_BASE_URL }) + "\\n");
process.stdout.write("fake vllm serve ready\\n");
process.on("SIGTERM", () => process.exit(0));
setInterval(() => {}, 1000);
`,
  );
  fs.chmodSync(fakeBinary, 0o755);
  const priorBaseUrl = process.env.VLLM_BASE_URL;
  const priorBinary = process.env.IOI_VLLM_BINARY;
  const priorCalls = process.env.IOI_FAKE_VLLM_CALLS;
  process.env.VLLM_BASE_URL = `${providerServer.endpoint}/v1`;
  process.env.IOI_VLLM_BINARY = fakeBinary;
  process.env.IOI_FAKE_VLLM_CALLS = callsPath;
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: {
        allowed: [
          "model.import:*",
          "model.mount:*",
          "model.load:*",
          "model.unload:*",
          "model.chat:*",
          "model.responses:*",
          "model.embeddings:*",
          "route.write:*",
          "route.use:*",
          "backend.control:*",
        ],
      },
    });
    const backendStart = await expectOk(daemon.endpoint, "/api/v1/backends/backend.vllm/start", {
      method: "POST",
      token: grant.token,
      body: { load_options: { model: "vllm-qwen", contextLength: 4096, parallel: 2, dtype: "auto", gpuMemoryUtilization: 0.42 } },
    });
    assert.equal(backendStart.process.spawned, true);
    assert.equal(backendStart.process.spawnStatus, "spawned");
    assert.match(backendStart.process.pidHash, /^[a-f0-9]{16}$/);
    const calls = fs.readFileSync(callsPath, "utf8");
    assert.equal(calls.includes('"serve"'), true);
    assert.equal(calls.includes("vllm-qwen"), true);
    assert.equal(calls.includes("--tensor-parallel-size"), true);
    assert.equal(calls.includes("--gpu-memory-utilization"), true);

    const providerModels = await expectOk(daemon.endpoint, "/api/v1/providers/provider.vllm/models");
    assert.ok(providerModels.some((model) => model.modelId === "vllm-qwen"));
    await expectOk(daemon.endpoint, "/api/v1/models/import", {
      method: "POST",
      token: grant.token,
      body: { model_id: "vllm-qwen", provider_id: "provider.vllm", capabilities: ["chat", "responses", "embeddings"], privacy_class: "workspace" },
    });
    const mounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "vllm-qwen",
        provider_id: "provider.vllm",
        id: "endpoint.test.vllm.supervised",
      },
    });
    const loaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
      method: "POST",
      token: grant.token,
      body: {
        endpoint_id: mounted.id,
        load_options: { contextLength: 4096, parallel: 2, dtype: "auto", gpuMemoryUtilization: 0.42, identifier: "vllm-load-test" },
      },
    });
    assert.equal(loaded.backend, "vllm");
    assert.equal(loaded.backendId, "backend.vllm");
    assert.equal(loaded.backendProcess.spawned, true);
    assert.equal(loaded.providerEvidenceRefs.includes("vllm_process_supervisor"), true);

    await expectOk(daemon.endpoint, "/api/v1/routes", {
      method: "POST",
      token: grant.token,
      body: {
        id: "route.test.vllm.supervised",
        role: "vllm-supervised-test",
        privacy: "local_or_enterprise",
        fallback: [mounted.id],
        provider_eligibility: ["vllm"],
      },
    });
    const response = await expectOk(daemon.endpoint, "/api/v1/responses", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.test.vllm.supervised", input: "hello supervised vllm" },
    });
    assert.equal(response.compat_translation, "chat_completions");
    const embeddings = await expectOk(daemon.endpoint, "/v1/embeddings", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.test.vllm.supervised", input: "embed supervised vllm" },
    });
    assert.deepEqual(embeddings.data[0].embedding, [0.91, 0.82, 0.73]);
    const receipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${response.receipt_id}`);
    assert.equal(receipt.details.backend, "vllm");
    assert.equal(receipt.details.backendId, "backend.vllm");
    assert.equal(receipt.details.backendProcessPidHash, loaded.backendProcess.pidHash);
    assert.ok(receipt.details.backendEvidenceRefs.includes("vllm_process_supervisor"));

    const streamedChat = await requestSse(daemon.endpoint, "/v1/chat/completions", {
      method: "POST",
      token: grant.token,
      body: {
        route_id: "route.test.vllm.supervised",
        model: "vllm-qwen",
        stream: true,
        messages: [{ role: "user", content: "stream supervised vllm" }],
      },
    });
    assert.equal(streamedChat.response.status, 200);
    assert.equal(streamedChat.response.headers.get("x-ioi-stream-source"), "provider_native");
    const streamedChatChunks = parseOpenAiSseChunks(streamedChat.text);
    const streamedChatText = streamedChatChunks
      .filter((chunk) => chunk !== "[DONE]")
      .map((chunk) => chunk.choices?.[0]?.delta?.content ?? "")
      .join("");
    assert.equal(streamedChatText, "fake vllm streamed chat");
    const streamedChatMetadata = streamedChatChunks.find((chunk) => chunk !== "[DONE]" && chunk.provider_stream === "native");
    assert.equal(streamedChatMetadata.route_id, "route.test.vllm.supervised");
    const streamedChatReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${streamedChatMetadata.receipt_id}`);
    assert.equal(streamedChatReceipt.details.backend, "vllm");
    assert.equal(streamedChatReceipt.details.backendId, "backend.vllm");
    assert.equal(streamedChatReceipt.details.backendProcessPidHash, loaded.backendProcess.pidHash);
    assert.equal(streamedChatReceipt.details.providerResponseKind, "chat.completions.stream");
    assert.ok(streamedChatReceipt.details.backendEvidenceRefs.includes("vllm_openai_compatible_server"));
    assert.ok(streamedChatReceipt.details.backendEvidenceRefs.includes("vllm_process_supervisor"));
    assert.ok(streamedChatReceipt.details.backendEvidenceRefs.includes("vllm_provider_native_stream"));
    const streamedChatCompleteReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${streamedChatMetadata.stream_receipt_id}`);
    assert.equal(streamedChatCompleteReceipt.details.invocationReceiptId, streamedChatMetadata.receipt_id);
    assert.equal(streamedChatCompleteReceipt.details.outputHash, crypto.createHash("sha256").update(streamedChatText).digest("hex"));

    const providerLoaded = await expectOk(daemon.endpoint, "/api/v1/providers/provider.vllm/loaded");
    assert.ok(providerLoaded.some((model) => model.modelId === "vllm-qwen"));
    const unloaded = await expectOk(daemon.endpoint, "/api/v1/models/unload", {
      method: "POST",
      token: grant.token,
      body: { instance_id: loaded.id },
    });
    assert.equal(unloaded.status, "unloaded");
    assert.equal(unloaded.providerEvidenceRefs.includes("clean_backend_stop"), true);
    const logs = await expectOk(daemon.endpoint, "/api/v1/backends/backend.vllm/logs");
    assert.ok(logs.some((record) => record.event === "backend_process_start"));
    assert.ok(logs.some((record) => record.event === "backend_process_stop"));
  } finally {
    await daemon.close();
    await providerServer.close();
    restoreEnv("VLLM_BASE_URL", priorBaseUrl);
    restoreEnv("IOI_VLLM_BINARY", priorBinary);
    restoreEnv("IOI_FAKE_VLLM_CALLS", priorCalls);
  }
});

test("llama.cpp provider driver spawns through backend supervisor and invokes through OpenAI-compatible server", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-llama-cpp-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-llama-cpp-state-"));
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-llama-cpp-bin-"));
  const callsPath = path.join(binDir, "llama-calls.jsonl");
  const fakeBinary = path.join(binDir, "llama-server");
  fs.writeFileSync(
    fakeBinary,
    `#!/usr/bin/env node
const fs = require("node:fs");
fs.appendFileSync(process.env.IOI_FAKE_LLAMA_CALLS, JSON.stringify(process.argv.slice(2)) + "\\n");
process.stdout.write("fake llama.cpp server ready\\n");
process.on("SIGTERM", () => process.exit(0));
setInterval(() => {}, 1000);
`,
  );
  fs.chmodSync(fakeBinary, 0o755);
  const providerServer = await startFakeLlamaCppServer();
  const priorBinary = process.env.IOI_LLAMA_CPP_SERVER_PATH;
  const priorBaseUrl = process.env.IOI_LLAMA_CPP_BASE_URL;
  const priorCalls = process.env.IOI_FAKE_LLAMA_CALLS;
  process.env.IOI_LLAMA_CPP_SERVER_PATH = fakeBinary;
  process.env.IOI_LLAMA_CPP_BASE_URL = `${providerServer.endpoint}/v1`;
  process.env.IOI_FAKE_LLAMA_CALLS = callsPath;
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
          "model.unload:*",
          "model.chat:*",
          "model.responses:*",
          "route.write:*",
          "route.use:*",
        ],
      },
    });
    const providerHealth = await expectOk(daemon.endpoint, "/api/v1/providers/provider.llama-cpp/health", { method: "POST" });
    assert.equal(providerHealth.status, "available");
    const providerModels = await expectOk(daemon.endpoint, "/api/v1/providers/provider.llama-cpp/models");
    assert.ok(providerModels.some((model) => model.modelId === "llama-cpp-qwen"));

    const modelPath = path.join(cwd, "llama-cpp-fixture.Q4_K_M.gguf");
    fs.writeFileSync(modelPath, "family=llama-cpp-fixture\nquantization=Q4_K_M\ncontext=8192\n");
    const imported = await expectOk(daemon.endpoint, "/api/v1/models/import", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "llama-cpp:fixture",
        provider_id: "provider.llama-cpp",
        path: modelPath,
        capabilities: ["chat", "responses", "embeddings"],
      },
    });
    assert.equal(imported.providerId, "provider.llama-cpp");
    const mounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: "llama-cpp:fixture",
        provider_id: "provider.llama-cpp",
        id: "endpoint.test.llama-cpp",
        backend_id: "backend.llama-cpp",
      },
    });
    await expectOk(daemon.endpoint, "/api/v1/routes", {
      method: "POST",
      token: grant.token,
      body: {
        id: "route.test.llama-cpp",
        role: "llama-cpp-test",
        privacy: "local_only",
        fallback: [mounted.id],
        provider_eligibility: ["llama_cpp"],
        denied_providers: [],
      },
    });
    const loaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
      method: "POST",
      token: grant.token,
      body: {
        endpoint_id: mounted.id,
        load_policy: { mode: "on_demand", idleTtlSeconds: 600, autoEvict: true },
        load_options: { contextLength: 4096, parallel: 2, gpu: "off", identifier: "llama-cpp-test" },
      },
    });
    assert.equal(loaded.backend, "llama_cpp");
    assert.equal(loaded.backendId, "backend.llama-cpp");
    assert.equal(loaded.backendProcess.spawned, true);
    assert.equal(loaded.backendProcess.spawnStatus, "spawned");
    assert.match(loaded.backendProcess.pidHash, /^[a-f0-9]{16}$/);
    assert.equal(loaded.backendProcess.argsRedacted.some((arg) => String(arg).startsWith("artifact:")), true);
    assert.equal(JSON.stringify(loaded.backendProcess.argsRedacted).includes(modelPath), false);
    const llamaCalls = fs.readFileSync(callsPath, "utf8");
    assert.equal(llamaCalls.includes(modelPath), true);
    assert.equal(llamaCalls.includes("--ctx-size"), true);

    const chat = await expectOk(daemon.endpoint, "/api/v1/chat", {
      method: "POST",
      token: grant.token,
      body: { route_id: "route.test.llama-cpp", input: "hello llama cpp" },
    });
    assert.match(chat.output_text, /fake llama.cpp chat/);
    const receipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${chat.receipt_id}`);
    assert.equal(receipt.details.backend, "llama_cpp");
    assert.equal(receipt.details.backendId, "backend.llama-cpp");
    assert.equal(receipt.details.backendProcessPidHash, loaded.backendProcess.pidHash);
    assert.ok(receipt.details.backendEvidenceRefs.includes("llama_cpp_process_supervisor"));

    const streamedResponse = await requestSse(daemon.endpoint, "/v1/responses", {
      method: "POST",
      token: grant.token,
      body: {
        route_id: "route.test.llama-cpp",
        model: "llama-cpp:fixture",
        stream: true,
        input: "stream llama cpp response",
      },
    });
    assert.equal(streamedResponse.response.status, 200);
    assert.equal(streamedResponse.response.headers.get("x-ioi-stream-source"), "provider_native");
    const streamedResponseText = streamedResponse.events
      .filter((event) => event.event === "response.output_text.delta")
      .map((event) => event.data.delta)
      .join("");
    assert.equal(streamedResponseText, "fake llama.cpp streamed response");
    const responseMetadata = streamedResponse.events.find((event) => event.event === "response.ioi.receipt")?.data;
    assert.equal(responseMetadata.route_id, "route.test.llama-cpp");
    assert.equal(responseMetadata.provider_stream, "native");
    const responseStreamReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${responseMetadata.receipt_id}`);
    assert.equal(responseStreamReceipt.details.backend, "llama_cpp");
    assert.equal(responseStreamReceipt.details.backendId, "backend.llama-cpp");
    assert.equal(responseStreamReceipt.details.backendProcessPidHash, loaded.backendProcess.pidHash);
    assert.equal(responseStreamReceipt.details.providerResponseKind, "responses.stream");
    assert.ok(responseStreamReceipt.details.backendEvidenceRefs.includes("llama_cpp_openai_compatible_server"));
    assert.ok(responseStreamReceipt.details.backendEvidenceRefs.includes("llama_cpp_process_supervisor"));
    assert.ok(responseStreamReceipt.details.backendEvidenceRefs.includes("llama_cpp_responses_provider_native_stream"));
    const responseStreamCompleteReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${responseMetadata.stream_receipt_id}`);
    assert.equal(responseStreamCompleteReceipt.details.invocationReceiptId, responseMetadata.receipt_id);
    assert.equal(responseStreamCompleteReceipt.details.outputHash, crypto.createHash("sha256").update(streamedResponseText).digest("hex"));

    const unloaded = await expectOk(daemon.endpoint, "/api/v1/models/unload", {
      method: "POST",
      token: grant.token,
      body: { instance_id: loaded.id },
    });
    assert.equal(unloaded.status, "unloaded");
    assert.equal(unloaded.providerEvidenceRefs.includes("clean_backend_stop"), true);
    const logs = await expectOk(daemon.endpoint, "/api/v1/backends/backend.llama-cpp/logs");
    assert.ok(logs.some((record) => record.event === "backend_process_start"));
    assert.ok(logs.some((record) => record.event === "backend_process_stop"));
  } finally {
    await daemon.close();
    await providerServer.close();
    restoreEnv("IOI_LLAMA_CPP_SERVER_PATH", priorBinary);
    restoreEnv("IOI_LLAMA_CPP_BASE_URL", priorBaseUrl);
    restoreEnv("IOI_FAKE_LLAMA_CALLS", priorCalls);
  }
});

test("llama.cpp live gate records unsupported embeddings without failing stream parity", async () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-llama-cpp-live-gate-workspace-"));
  const evidenceRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-llama-cpp-live-gate-evidence-"));
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-llama-cpp-live-gate-bin-"));
  const callsPath = path.join(binDir, "llama-live-gate-calls.jsonl");
  const fakeBinary = path.join(binDir, "llama-server");
  const modelPath = path.join(workspace, "llama-cpp-live-fixture.Q4_K_M.gguf");
  fs.writeFileSync(modelPath, "family=llama-cpp-live-fixture\nquantization=Q4_K_M\ncontext=4096\n");
  fs.writeFileSync(
    fakeBinary,
    `#!/usr/bin/env node
const fs = require("node:fs");
if (process.argv.includes("--version")) {
  process.stdout.write("fake llama-server 0.0.0\\n");
  process.exit(0);
}
fs.appendFileSync(process.env.IOI_FAKE_LLAMA_CALLS, JSON.stringify(process.argv.slice(2)) + "\\n");
process.stdout.write("fake llama.cpp live gate server ready\\n");
process.on("SIGTERM", () => process.exit(0));
setInterval(() => {}, 1000);
`,
  );
  fs.chmodSync(fakeBinary, 0o755);
  const providerServer = await startFakeLlamaCppServer({ embeddingStatus: 400, chatStreamDelayMs: 500 });
  try {
    const result = await runChildProcess("node", ["scripts/live-model-mounting-gate.mjs", "llama-cpp"], {
      cwd: process.cwd(),
      timeoutMs: 120000,
      env: {
        ...process.env,
        IOI_LIVE_LLAMA_CPP: "1",
        IOI_MODEL_MOUNTING_LIVE_EVIDENCE_ROOT: evidenceRoot,
        IOI_LLAMA_CPP_SERVER_PATH: fakeBinary,
        IOI_LLAMA_CPP_MODEL_PATH: modelPath,
        IOI_LLAMA_CPP_BASE_URL: `${providerServer.endpoint}/v1`,
        IOI_LLAMA_CPP_MODEL_ID: "llama-cpp-live-fixture",
        IOI_LLAMA_CPP_LIVE_TIMEOUT_MS: "20000",
        IOI_PROVIDER_HTTP_TIMEOUT_MS: "5000",
        IOI_FAKE_LLAMA_CALLS: callsPath,
      },
    });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    const gateDir = path.join(evidenceRoot, "llama-cpp");
    const evidenceDirs = fs.readdirSync(gateDir).sort();
    assert.equal(evidenceDirs.length, 1);
    const evidence = JSON.parse(fs.readFileSync(path.join(gateDir, evidenceDirs[0], "result.json"), "utf8"));
    assert.equal(evidence.status, "passed");
    assert.equal(evidence.result.embeddingStatus, "unsupported_or_failed");
    assert.match(evidence.result.embeddingErrorHash, /^[a-f0-9]{64}$/);
    assert.equal(evidence.result.embeddingReceiptId, null);
    assert.equal(evidence.result.embeddingVectors, null);
    assert.ok(evidence.result.chatReceiptId);
    assert.ok(evidence.result.responsesReceiptId);
    assert.ok(evidence.result.streamReceipts.completedInvocationReceiptId);
    assert.ok(evidence.result.streamReceipts.completedStreamReceiptId);
    assert.ok(evidence.result.streamReceipts.abortedInvocationReceiptId);
    assert.ok(evidence.result.streamReceipts.abortedStreamReceiptId);
    assert.equal(evidence.result.streamReceipts.streamKind, "openai_chat_completions_provider_native");
    assert.equal(evidence.result.secretScan.passed, true);
    const calls = fs.readFileSync(callsPath, "utf8");
    assert.equal(calls.includes(modelPath), true);
  } finally {
    await providerServer.close();
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
    const projectionAfterHealth = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
    assert.ok(projectionAfterHealth.providerHealth.some((record) => record.receiptId === providerHealthReceipt.id));
    assert.ok(projectionAfterHealth.providerHealthReceipts.some((receipt) => receipt.id === providerHealthReceipt.id));
    assert.equal(JSON.stringify(projectionAfterHealth.providerHealth).includes(vaultRef), false);
    const latestProviderHealth = await expectOk(daemon.endpoint, "/api/v1/providers/provider.test.custom-vault/health/latest");
    assert.equal(latestProviderHealth.receipt.id, providerHealthReceipt.id);
    assert.equal(latestProviderHealth.health.status, "available");
    assert.equal(latestProviderHealth.replay.receipt.id, providerHealthReceipt.id);
    assert.equal(JSON.stringify(latestProviderHealth).includes(vaultMaterial), false);

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
    const restartedProjectionBeforeHealth = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
    assert.ok(restartedProjectionBeforeHealth.providerHealth.some((record) => record.receiptId === providerHealthReceipt.id));
    assert.ok(restartedProjectionBeforeHealth.providerHealthReceipts.some((receipt) => receipt.id === providerHealthReceipt.id));
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
if [ "$1" = "runtime" ] && [ "$2" = "ls" ]; then
  cat <<'RUNTIMES'
LLM ENGINE                                          SELECTED    MODEL FORMAT
llama.cpp-linux-x86_64-avx2@2.13.0                                  GGUF
llama.cpp-linux-x86_64-nvidia-cuda12-avx2@2.13.0       yes          GGUF
RUNTIMES
  exit 0
fi
if [ "$1" = "runtime" ] && [ "$2" = "survey" ]; then
  cat <<'SURVEY'
Survey by llama.cpp-linux-x86_64-nvidia-cuda12-avx2 (2.13.0)
GPU/ACCELERATORS                                      VRAM
NVIDIA Test GPU (CUDA, Discrete)                      8.00 GiB

CPU: x86_64 (AVX2, AVX)
RAM: 64.00 GiB
SURVEY
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

    const runtimeEngines = await expectOk(daemon.endpoint, "/api/v1/runtime/engines");
    assert.ok(runtimeEngines.some((engine) => engine.kind === "lm_studio_runtime" && engine.selected));
    const runtimeSurvey = await expectOk(daemon.endpoint, "/api/v1/runtime/survey", { method: "POST" });
    assert.equal(runtimeSurvey.lmStudio.status, "available");
    assert.equal(runtimeSurvey.lmStudio.cpu, "x86_64 (AVX2, AVX)");
    assert.equal(runtimeSurvey.lmStudio.ram, "64.00 GiB");
    assert.equal(runtimeSurvey.lmStudio.accelerators[0].vram, "8.00 GiB");
    assert.equal(JSON.stringify(runtimeSurvey).includes("NVIDIA Test GPU"), true);
    assert.equal(JSON.stringify(runtimeSurvey).includes(lmsPath), false);

    const mounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: { model_id: "qwen/qwen3.5-9b", id: "endpoint.test.lmstudio" },
    });
    assert.equal(mounted.providerId, "provider.lmstudio");

    const loaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
      method: "POST",
      token: grant.token,
      body: {
        endpoint_id: mounted.id,
        load_policy: { mode: "manual", autoEvict: false },
        load_options: { gpu: "max", contextLength: 8192, parallel: 2, ttlSeconds: 600, identifier: "qwen-dev" },
      },
    });
    assert.equal(loaded.backend, "lm_studio");
    assert.equal(loaded.loadOptions.contextLength, 8192);
    assert.equal(loaded.identifier, "qwen-dev");
    const loadReceipt = (await expectOk(daemon.endpoint, "/api/v1/receipts")).find(
      (receipt) => receipt.details?.operation === "model_load" && receipt.details?.endpointId === mounted.id,
    );
    assert.equal(loadReceipt.details.commandArgsHash.length > 0, true);
    assert.equal(loadReceipt.details.loadOptions.identifier, "qwen-dev");

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

async function startFakeOpenAiCompatibleServer({ responsesStream = false } = {}) {
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && url.pathname === "/v1/models") {
      response.end(JSON.stringify({ object: "list", data: [{ id: "qwen/qwen3.5-9b" }] }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/responses") {
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (responsesStream && body.stream === true) {
        response.setHeader("content-type", "text/event-stream");
        const responseId = "resp_fake_openai_compatible_stream";
        const itemId = "msg_fake_openai_compatible_stream";
        response.write(
          `event: response.created\ndata: ${JSON.stringify({
            type: "response.created",
            response: {
              id: responseId,
              object: "response",
              status: "in_progress",
              model: body.model ?? "qwen/qwen3.5-9b",
              output: [],
            },
          })}\n\n`,
        );
        response.write(
          `event: response.output_item.added\ndata: ${JSON.stringify({
            type: "response.output_item.added",
            output_index: 0,
            item: { id: itemId, type: "message", status: "in_progress", role: "assistant", content: [] },
          })}\n\n`,
        );
        response.write(
          `event: response.output_text.delta\ndata: ${JSON.stringify({
            type: "response.output_text.delta",
            item_id: itemId,
            output_index: 0,
            content_index: 0,
            delta: "fake openai-compatible ",
          })}\n\n`,
        );
        response.write(
          `event: response.output_text.delta\ndata: ${JSON.stringify({
            type: "response.output_text.delta",
            item_id: itemId,
            output_index: 0,
            content_index: 0,
            delta: "streamed response",
          })}\n\n`,
        );
        response.end(
          `event: response.completed\ndata: ${JSON.stringify({
            type: "response.completed",
            response: {
              id: responseId,
              object: "response",
              status: "completed",
              model: body.model ?? "qwen/qwen3.5-9b",
              output_text: "fake openai-compatible streamed response",
              usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
            },
          })}\n\n`,
        );
        return;
      }
      response.statusCode = 404;
      response.end(JSON.stringify({ error: { message: "responses unavailable" } }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (body.stream === true) {
        response.setHeader("content-type", "text/event-stream");
        const created = Math.floor(Date.now() / 1000);
        const base = {
          id: "chatcmpl_fake_openai_compatible_stream",
          object: "chat.completion.chunk",
          created,
          model: body.model ?? "qwen/qwen3.5-9b",
        };
        response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] })}\n\n`);
        response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { content: "fake openai-compatible " }, finish_reason: null }] })}\n\n`);
        response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { content: "streamed chat" }, finish_reason: null }] })}\n\n`);
        response.write(
          `data: ${JSON.stringify({
            ...base,
            choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
            usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
          })}\n\n`,
        );
        response.end("data: [DONE]\n\n");
        return;
      }
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
  const loaded = new Set();
  const server = http.createServer(async (request, response) => {
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
    if (request.method === "GET" && url.pathname === "/api/ps") {
      response.end(
        JSON.stringify({
          models: [...loaded].map((name) => ({
            name,
            model: name,
            size: name.includes("embed") ? 274_000_000 : 4_900_000_000,
            processor: "100% CPU",
            expires_at: new Date(Date.now() + 300000).toISOString(),
          })),
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/generate") {
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (body.keep_alive === 0 || body.keep_alive === "0" || body.keep_alive === "0s") {
        loaded.delete(String(body.model));
      } else if (body.model) {
        loaded.add(String(body.model));
      }
      response.end(JSON.stringify({ model: body.model, response: "", done: true }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/chat") {
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (body.model) loaded.add(String(body.model));
      if (chatStatus !== 200) {
        response.statusCode = chatStatus;
        response.end(JSON.stringify({ error: `provider failed ${secret}` }));
        return;
      }
      if (body.stream === true) {
        writeFakeOllamaChatJsonl(response, {
          model: body.model ?? "qwen3:8b",
          chunks: ["fake ollama ", "streamed chat"],
          usage: { prompt_eval_count: 3, eval_count: 5 },
        });
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
  const server = http.createServer(async (request, response) => {
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
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (responsesStatus !== 200) {
        response.statusCode = responsesStatus;
        response.end(JSON.stringify({ error: { message: `responses unavailable ${secret ?? ""}` } }));
        return;
      }
      if (body.stream === true) {
        writeFakeOpenAiResponseSse(response, {
          responseId: "resp_fake_vllm_stream",
          itemId: "msg_fake_vllm_stream",
          model: body.model ?? "vllm-qwen",
          chunks: ["fake vllm ", "streamed response"],
          usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
        });
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
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (chatStatus !== 200) {
        response.statusCode = chatStatus;
        response.end(JSON.stringify({ error: { message: `chat failed ${secret}` } }));
        return;
      }
      if (body.stream === true) {
        writeFakeOpenAiChatCompletionSse(response, {
          id: "chatcmpl_fake_vllm_stream",
          model: body.model ?? "vllm-qwen",
          chunks: ["fake vllm ", "streamed chat"],
          usage: { prompt_tokens: 4, completion_tokens: 6, total_tokens: 10 },
        });
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

async function startFakeLlamaCppServer({ embeddingStatus = 200, chatStreamDelayMs = 0 } = {}) {
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && url.pathname === "/v1/models") {
      response.end(JSON.stringify({ object: "list", data: [{ id: "llama-cpp-qwen" }] }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/responses") {
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (body.stream === true) {
        writeFakeOpenAiResponseSse(response, {
          responseId: "resp_fake_llama_cpp_stream",
          itemId: "msg_fake_llama_cpp_stream",
          model: body.model ?? "llama-cpp-qwen",
          chunks: ["fake llama.cpp ", "streamed response"],
          usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
        });
        return;
      }
      response.end(
        JSON.stringify({
          id: "resp_fake_llama_cpp",
          object: "response",
          model: "llama-cpp-qwen",
          output_text: "fake llama.cpp response",
          usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (body.stream === true) {
        const isAbortProbe = JSON.stringify(body.messages ?? []).includes("deliberately long numbered list");
        const payload = {
          id: "chatcmpl_fake_llama_cpp_stream",
          model: body.model ?? "llama-cpp-qwen",
          chunks: isAbortProbe
            ? Array.from({ length: 12 }, (_, index) => `fake llama.cpp abort chunk ${index}. `)
            : ["fake llama.cpp ", "streamed chat"],
          usage: { prompt_tokens: 4, completion_tokens: 6, total_tokens: 10 },
        };
        if (isAbortProbe && chatStreamDelayMs > 0) {
          await writeFakeOpenAiChatCompletionSseSlow(response, payload, chatStreamDelayMs);
        } else {
          writeFakeOpenAiChatCompletionSse(response, payload);
        }
        return;
      }
      response.end(
        JSON.stringify({
          id: "chatcmpl_fake_llama_cpp",
          object: "chat.completion",
          model: "llama-cpp-qwen",
          choices: [{ index: 0, message: { role: "assistant", content: "fake llama.cpp chat" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 4, completion_tokens: 6, total_tokens: 10 },
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/embeddings") {
      if (embeddingStatus !== 200) {
        response.statusCode = embeddingStatus;
        response.end(JSON.stringify({ error: { message: "embeddings unsupported by fake llama.cpp fixture" } }));
        return;
      }
      response.end(
        JSON.stringify({
          object: "list",
          data: [{ object: "embedding", index: 0, embedding: [0.44, 0.55, 0.66] }],
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
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function writeFakeOllamaChatJsonl(response, { model, chunks, usage }) {
  response.setHeader("content-type", "application/x-ndjson");
  for (const chunk of chunks) {
    response.write(
      `${JSON.stringify({
        model,
        created_at: new Date().toISOString(),
        message: { role: "assistant", content: chunk },
        done: false,
      })}\n`,
    );
  }
  response.end(
    `${JSON.stringify({
      model,
      created_at: new Date().toISOString(),
      message: { role: "assistant", content: "" },
      done: true,
      done_reason: "stop",
      prompt_eval_count: usage.prompt_eval_count,
      eval_count: usage.eval_count,
    })}\n`,
  );
}

function writeFakeOpenAiChatCompletionSse(response, { id, model, chunks, usage }) {
  const created = Math.floor(Date.now() / 1000);
  const base = {
    id,
    object: "chat.completion.chunk",
    created,
    model,
  };
  response.setHeader("content-type", "text/event-stream");
  response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] })}\n\n`);
  for (const chunk of chunks) {
    response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { content: chunk }, finish_reason: null }] })}\n\n`);
  }
  response.write(
    `data: ${JSON.stringify({
      ...base,
      choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
      usage,
    })}\n\n`,
  );
  response.end("data: [DONE]\n\n");
}

async function writeFakeOpenAiChatCompletionSseSlow(response, { id, model, chunks, usage }, delayMs) {
  const created = Math.floor(Date.now() / 1000);
  const base = {
    id,
    object: "chat.completion.chunk",
    created,
    model,
  };
  const frames = [
    { ...base, choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] },
    ...chunks.map((chunk) => ({ ...base, choices: [{ index: 0, delta: { content: chunk }, finish_reason: null }] })),
    { ...base, choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage },
  ];
  response.setHeader("content-type", "text/event-stream");
  for (const frame of frames) {
    if (response.destroyed || response.writableEnded) return;
    response.write(`data: ${JSON.stringify(frame)}\n\n`);
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  if (!response.destroyed && !response.writableEnded) response.end("data: [DONE]\n\n");
}

function writeFakeOpenAiResponseSse(response, { responseId, itemId, model, chunks, usage }) {
  const outputText = chunks.join("");
  response.setHeader("content-type", "text/event-stream");
  response.write(
    `event: response.created\ndata: ${JSON.stringify({
      type: "response.created",
      response: {
        id: responseId,
        object: "response",
        status: "in_progress",
        model,
        output: [],
      },
    })}\n\n`,
  );
  response.write(
    `event: response.output_item.added\ndata: ${JSON.stringify({
      type: "response.output_item.added",
      output_index: 0,
      item: { id: itemId, type: "message", status: "in_progress", role: "assistant", content: [] },
    })}\n\n`,
  );
  for (const chunk of chunks) {
    response.write(
      `event: response.output_text.delta\ndata: ${JSON.stringify({
        type: "response.output_text.delta",
        item_id: itemId,
        output_index: 0,
        content_index: 0,
        delta: chunk,
      })}\n\n`,
    );
  }
  response.end(
    `event: response.completed\ndata: ${JSON.stringify({
      type: "response.completed",
      response: {
        id: responseId,
        object: "response",
        status: "completed",
        model,
        output_text: outputText,
        usage,
      },
    })}\n\n`,
  );
}

async function readRequestText(request) {
  let text = "";
  for await (const chunk of request) text += chunk;
  return text;
}

async function startFakeHuggingFaceCatalogServer({ requiredHeaders = {} } = {}) {
  const modelBytes = Buffer.from("family=qwen-hf-live\ncontext=4096\nquantization=Q4_K_M\n");
  const downloadAttempts = new Map();
  const observed = [];
  const assertHeaders = (request, response) => {
    observed.push({ ...request.headers });
    for (const [header, expected] of Object.entries(requiredHeaders)) {
      if (request.headers[String(header).toLowerCase()] !== expected) {
        response.statusCode = 401;
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({ error: "unauthorized" }));
        return false;
      }
    }
    return true;
  };
  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (request.method === "GET" && url.pathname === "/api/models") {
      if (!assertHeaders(request, response)) return;
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify([
          {
            id: "Qwen/Qwen3-GGUF",
            modelId: "Qwen/Qwen3-GGUF",
            pipeline_tag: "text-generation",
            tags: ["gguf", "qwen", "Q4_K_M"],
            cardData: { license: "apache-2.0" },
            siblings: [
              { rfilename: "qwen-3b-Q4_K_M.gguf", size: modelBytes.length },
              { rfilename: "mlx/qwen-3b-4bit.safetensors", size: 12 },
            ],
          },
        ]),
      );
      return;
    }
    if (request.method === "GET" && url.pathname === "/Qwen/Qwen3-GGUF/resolve/main/qwen-3b-Q4_K_M.gguf") {
      if (!assertHeaders(request, response)) return;
      const status = Number(url.searchParams.get("status") ?? 0);
      if (status >= 400) {
        response.statusCode = status;
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({ error: "download failed" }));
        return;
      }
      const attemptKey = url.searchParams.get("attempt_key") ?? `${url.pathname}?${url.searchParams.toString()}`;
      const attempt = (downloadAttempts.get(attemptKey) ?? 0) + 1;
      downloadAttempts.set(attemptKey, attempt);
      const range = request.headers.range;
      const dropOnceAfter = Number(url.searchParams.get("drop_once_after") ?? 0);
      if (dropOnceAfter > 0 && attempt === 1 && !range) {
        const chunk = modelBytes.subarray(0, Math.min(dropOnceAfter, modelBytes.length));
        response.setHeader("content-type", "application/octet-stream");
        response.setHeader("content-length", String(modelBytes.length));
        response.write(chunk, () => response.destroy(new Error("deterministic dropped download")));
        return;
      }
      if (range) {
        const offset = Number(String(range).match(/bytes=([0-9]+)-/)?.[1] ?? 0);
        const chunk = modelBytes.subarray(offset);
        response.statusCode = 206;
        response.setHeader("content-range", `bytes ${offset}-${modelBytes.length - 1}/${modelBytes.length}`);
        response.setHeader("content-length", String(chunk.length));
        response.end(chunk);
        return;
      }
      response.setHeader("content-type", "application/octet-stream");
      response.setHeader("content-length", String(modelBytes.length));
      response.end(modelBytes);
      return;
    }
    response.statusCode = 404;
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ error: "not found" }));
  });
  await listen(server);
  const address = server.address();
  return {
    endpoint: `http://${address.address}:${address.port}`,
    observedHeaders: () => observed,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

async function startFakeCustomCatalogServer({ requiredHeaders = {} } = {}) {
  const observed = [];
  const assertHeaders = (request, response) => {
    observed.push({ ...request.headers });
    const headers = typeof requiredHeaders === "function" ? requiredHeaders() : requiredHeaders;
    for (const [header, expected] of Object.entries(headers ?? {})) {
      if (request.headers[String(header).toLowerCase()] !== expected) {
        response.statusCode = 401;
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({ error: "unauthorized" }));
        return false;
      }
    }
    return true;
  };
  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && url.pathname === "/catalog/search") {
      if (!assertHeaders(request, response)) return;
      response.end(
        JSON.stringify({
          results: [
            {
              model_id: "custom/http-vllm-fixture",
              family: "custom-http",
              architecture: "mistral",
              parameter_count: "7B",
              format: "safetensors",
              quantization: "F16",
              size_bytes: 8192,
              context_window: 16384,
              source_url: "fixture://custom-http/vllm-safetensors-f16",
              source_label: "Custom HTTP / vLLM safetensors",
              compatibility: ["vllm", "openai_compatible"],
              tags: ["custom", "vllm"],
              license: "fixture-custom",
            },
          ],
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
    observedHeaders: () => observed,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

async function startFakeOAuthServer({ accessToken, refreshToken, refreshedAccessToken, refreshedRefreshToken, expiresIn = 90 } = {}) {
  const observed = [];
  const tokens = {
    access: accessToken ?? `oauth-access-${crypto.randomBytes(6).toString("hex")}`,
    refresh: refreshToken ?? `oauth-refresh-${crypto.randomBytes(6).toString("hex")}`,
    refreshedAccess: refreshedAccessToken ?? `oauth-access-refreshed-${crypto.randomBytes(6).toString("hex")}`,
    refreshedRefresh: refreshedRefreshToken ?? `oauth-refresh-refreshed-${crypto.randomBytes(6).toString("hex")}`,
  };
  let currentAccess = tokens.access;
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (request.method === "POST" && url.pathname === "/oauth/token") {
      const text = await readRequestText(request);
      const params = new URLSearchParams(text);
      const grantType = params.get("grant_type");
      observed.push({
        grantType,
        codeHash: params.get("code") ? crypto.createHash("sha256").update(params.get("code")).digest("hex") : null,
        refreshTokenHash: params.get("refresh_token") ? crypto.createHash("sha256").update(params.get("refresh_token")).digest("hex") : null,
        clientIdHash: params.get("client_id") ? crypto.createHash("sha256").update(params.get("client_id")).digest("hex") : null,
        scope: params.get("scope"),
      });
      if (grantType === "authorization_code" && params.get("code") === "valid-oauth-code") {
        currentAccess = tokens.access;
        response.end(JSON.stringify({ access_token: tokens.access, refresh_token: tokens.refresh, expires_in: expiresIn, scope: "catalog.read" }));
        return;
      }
      if (grantType === "refresh_token" && params.get("refresh_token") === tokens.refresh) {
        currentAccess = tokens.refreshedAccess;
        response.end(JSON.stringify({ access_token: tokens.refreshedAccess, refresh_token: tokens.refreshedRefresh, expires_in: expiresIn, scope: "catalog.read" }));
        return;
      }
      response.statusCode = 401;
      response.end(JSON.stringify({ error: "invalid_grant" }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: "not found" }));
  });
  await listen(server);
  const address = server.address();
  return {
    endpoint: `http://${address.address}:${address.port}/oauth/token`,
    currentAccessToken: () => currentAccess,
    tokens,
    observed: () => observed,
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

function runChildProcess(command, args, { cwd, env, timeoutMs }) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const child = childProcess.spawn(command, args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once("close", (status, signal) => {
      clearTimeout(timeout);
      resolve({ status, signal, stdout, stderr, timedOut });
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
