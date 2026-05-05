#!/usr/bin/env node
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startRuntimeDaemonService } from "../packages/runtime-daemon/src/index.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const evidenceRoot = path.join(repoRoot, "docs/evidence/model-mounting-live");
const schemaVersion = "ioi.model-mounting.live-gate.v1";

const gates = {
  "lm-studio": {
    env: "IOI_LIVE_LM_STUDIO",
    evidenceDir: "lm-studio",
  },
  "model-backends": {
    env: "IOI_LIVE_MODEL_BACKENDS",
    evidenceDir: "model-backends",
  },
  wallet: {
    env: "IOI_REMOTE_WALLET",
    evidenceDir: "wallet",
  },
  agentgres: {
    env: "IOI_REMOTE_AGENTGRES",
    evidenceDir: "agentgres",
  },
};

function timestamp() {
  return new Date().toISOString().replaceAll(":", "-").replace(/\.\d{3}Z$/, "Z");
}

function usage() {
  return `Usage: node scripts/live-model-mounting-gate.mjs <${Object.keys(gates).join("|")}>`;
}

function runCommand(command, args, { timeout = 15000, env = process.env } = {}) {
  const result = childProcess.spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    timeout,
    env,
  });
  return {
    command: [command, ...args].join(" "),
    status: result.status,
    signal: result.signal,
    error: result.error?.message ?? null,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

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
  const json = text ? JSON.parse(text) : null;
  return { response, json };
}

async function expectOk(endpoint, route, options) {
  const result = await requestJson(endpoint, route, options);
  assert.equal(result.response.ok, true, `${route} -> ${result.response.status} ${JSON.stringify(result.json)}`);
  return result.json;
}

function resolveLmsPath() {
  const candidates = [
    process.env.IOI_LMS_PATH,
    path.join(os.homedir(), ".lmstudio/bin/lms"),
    path.join(os.homedir(), ".local/bin/lms"),
  ].filter(Boolean);
  return candidates.find((candidate) => {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return true;
    } catch {
      return false;
    }
  }) ?? null;
}

function parseServerRunning(text) {
  if (/\b(not running|not started|stopped|off)\b/i.test(text)) {
    return false;
  }
  return /\b(ON|RUNNING|STARTED|LISTENING)\b/i.test(text);
}

function parseLmStudioModelIds(text) {
  const modelIds = [];
  for (const line of String(text ?? "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || /^(LLM|EMBEDDING|MODEL|IDENTIFIER)\b/i.test(trimmed)) continue;
    if (/^(You have|No models|To load|lms load)\b/i.test(trimmed)) continue;
    const match = trimmed.match(/^([A-Za-z0-9_.:/@+-]+(?:\/[A-Za-z0-9_.:@+-]+)?)/);
    if (match?.[1]) modelIds.push(match[1]);
  }
  return [...new Set(modelIds)];
}

function redactLiveEvidence(value) {
  const secretNeedles = [
    process.env.OPENAI_API_KEY,
    process.env.ANTHROPIC_API_KEY,
    process.env.GEMINI_API_KEY,
    process.env.IOI_CUSTOM_MODEL_AUTH,
    process.env.IOI_WALLET_NETWORK_TOKEN,
    process.env.IOI_AGENTGRES_TOKEN,
  ].filter(Boolean);
  let text = JSON.stringify(value, null, 2);
  for (const needle of secretNeedles) {
    text = text.split(needle).join("[REDACTED]");
  }
  return `${text}\n`;
}

function makeEvidence(gateName, outputDir) {
  return {
    schemaVersion,
    gate: gateName,
    status: "running",
    startedAt: new Date().toISOString(),
    outputDir,
    commands: [],
    details: {},
    result: null,
  };
}

function writeEvidence(evidence) {
  evidence.completedAt = new Date().toISOString();
  fs.mkdirSync(evidence.outputDir, { recursive: true });
  const resultPath = path.join(evidence.outputDir, "result.json");
  fs.writeFileSync(resultPath, redactLiveEvidence(evidence), "utf8");
  console.log(`[model-mounting-live:${evidence.gate}] ${evidence.status}: ${resultPath}`);
  return resultPath;
}

async function withTemporaryEnv(overrides, fn) {
  const previous = {};
  for (const [key, value] of Object.entries(overrides)) {
    previous[key] = process.env[key];
    if (value === undefined || value === null) {
      delete process.env[key];
    } else {
      process.env[key] = String(value);
    }
  }
  try {
    return await fn();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

async function startFakeRemoteBoundaryServer(kind) {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    requests.push({ method: request.method, pathname: url.pathname });
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && url.pathname === "/health") {
      response.end(JSON.stringify(fakeBoundaryHealth(kind)));
      return;
    }
    if (request.method === "POST" && url.pathname === "/audit") {
      await readRequestText(request);
      response.end(JSON.stringify({ ok: true, receipt_id: `fake_${kind}_audit_${requests.length}` }));
      return;
    }
    if (kind === "wallet" && request.method === "POST" && url.pathname === "/grants/authorize") {
      await readRequestText(request);
      response.end(JSON.stringify({ ok: true, decision: "allow", grant_id_hash: "fake_grant_hash" }));
      return;
    }
    if (kind === "agentgres" && request.method === "GET" && url.pathname === "/projections/model-mounting") {
      response.end(JSON.stringify({ ok: true, projection: "model-mounting", replay_supported: true }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ ok: false, error: "not_found" }));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  const url = `http://${address.address}:${address.port}`;
  return {
    kind,
    url,
    requests,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function fakeBoundaryHealth(kind) {
  if (kind === "wallet") {
    return {
      ok: true,
      service: "fake-wallet-network",
      port: "WalletAuthorityPort",
      methods: ["createGrant", "authorizeScope", "revokeGrant", "resolveVaultRef", "auditEvent", "recordLastUsed"],
    };
  }
  return {
    ok: true,
    service: "fake-agentgres",
    port: "AgentgresModelMountingStorePort",
    methods: ["projectionReplay", "receiptLookup", "operationLogProjection"],
  };
}

async function readRequestText(request) {
  let text = "";
  for await (const chunk of request) text += chunk;
  return text;
}

async function probeRemoteBoundary(url, kind) {
  const healthUrl = `${String(url).replace(/\/+$/, "")}/health`;
  const response = await fetch(healthUrl, { headers: { accept: "application/json" } });
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  assert.equal(response.ok, true, `${kind} remote boundary /health -> ${response.status} ${text}`);
  return {
    ok: response.ok,
    status: response.status,
    service: body?.service ?? null,
    port: body?.port ?? null,
    methodCount: Array.isArray(body?.methods) ? body.methods.length : 0,
    urlHash: stableHash(url),
  };
}

async function withDaemon(fn) {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-live-model-gate-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-live-model-gate-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    return await fn({ daemon, cwd, stateDir });
  } finally {
    await daemon.close();
  }
}

async function runLmStudioGate(evidence) {
  const lmsPath = resolveLmsPath();
  evidence.details.lmsPath = lmsPath;
  if (!lmsPath) {
    evidence.status = "blocked";
    evidence.result = {
      reason: "lm_studio_public_lms_cli_not_found",
      required: "Install LM Studio or set IOI_LMS_PATH to the public lms CLI.",
    };
    return;
  }

  const serverStatus = runCommand(lmsPath, ["server", "status"]);
  const modelList = runCommand(lmsPath, ["ls"]);
  const processList = runCommand(lmsPath, ["ps"]);
  evidence.commands.push(
    { command: "lms server status", status: serverStatus.status, stdout: serverStatus.stdout, stderr: serverStatus.stderr },
    { command: "lms ls", status: modelList.status, stdout: modelList.stdout, stderr: modelList.stderr },
    { command: "lms ps", status: processList.status, stdout: processList.stdout, stderr: processList.stderr },
  );
  const statusText = `${serverStatus.stdout}\n${serverStatus.stderr}`;
  const installedModelIds = parseLmStudioModelIds(modelList.stdout);
  const loadedModelIds = parseLmStudioModelIds(processList.stdout);
  evidence.details.installedModelIds = installedModelIds;
  evidence.details.loadedModelIds = loadedModelIds;
  evidence.details.serverRunning = parseServerRunning(statusText);

  if (serverStatus.status !== 0) {
    evidence.status = "blocked";
    evidence.result = {
      reason: "lm_studio_server_status_failed",
      exitCode: serverStatus.status,
    };
    return;
  }

  if (!evidence.details.serverRunning) {
    evidence.status = "blocked";
    evidence.result = {
      reason: "lm_studio_server_stopped",
      nextLiveStep: "Start LM Studio local server, then rerun IOI_LIVE_LM_STUDIO=1 npm run test:lm-studio-live.",
    };
    return;
  }

  if (installedModelIds.length === 0) {
    evidence.status = "blocked";
    evidence.result = {
      reason: "lm_studio_no_installed_models",
      nextLiveStep: "Install at least one LM Studio model, then rerun the live gate.",
    };
    return;
  }

  await withDaemon(async ({ daemon, stateDir }) => {
    evidence.details.daemonEndpoint = daemon.endpoint;
    evidence.details.stateDir = stateDir;
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
    const providerLoaded = await expectOk(daemon.endpoint, "/api/v1/providers/provider.lmstudio/loaded");
    const selectedModel =
      providerLoaded.find((model) => model.capabilities?.includes?.("chat"))?.modelId ??
      providerModels.find((model) => model.capabilities?.includes?.("chat"))?.modelId ??
      providerModels[0]?.modelId ??
      installedModelIds[0];
    assert.ok(selectedModel, "LM Studio live gate could not select a model.");

    const mounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
      method: "POST",
      token: grant.token,
      body: {
        model_id: selectedModel,
        id: `endpoint.live.lmstudio.${selectedModel.replace(/[^a-zA-Z0-9]+/g, ".").toLowerCase()}`,
        provider_id: "provider.lmstudio",
      },
    });
    const loaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
      method: "POST",
      token: grant.token,
      body: { endpoint_id: mounted.id, load_policy: { mode: "manual", autoEvict: false } },
    });
    assert.equal(loaded.backend, "lm_studio");

    const response = await expectOk(daemon.endpoint, "/api/v1/responses", {
      method: "POST",
      token: grant.token,
      body: {
        model: selectedModel,
        input: "Reply exactly with: ok",
        max_output_tokens: 8,
      },
    });
    const receipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${response.receipt_id}`);
    assert.equal(receipt.details.providerId, "provider.lmstudio");
    assert.equal(receipt.details.backend, "lm_studio");
    evidence.status = "passed";
    evidence.result = {
      selectedModel,
      endpointId: mounted.id,
      instanceId: loaded.id,
      receiptId: response.receipt_id,
      compatTranslation: response.compat_translation ?? receipt.details.compatTranslation ?? null,
      providerModels: providerModels.length,
      providerLoaded: providerLoaded.length,
    };
  });
}

async function runModelBackendsGate(evidence) {
  const configured = {
    llamaCppBaseUrl: Boolean(process.env.IOI_LLAMA_CPP_BASE_URL),
    llamaCppServerPath: Boolean(process.env.IOI_LLAMA_CPP_SERVER_PATH),
    ollamaHost: Boolean(process.env.OLLAMA_HOST),
    ollamaBinary: Boolean(resolveBinary("ollama")),
    vllmBaseUrl: Boolean(process.env.VLLM_BASE_URL),
    vllmBinary: Boolean(resolveBinary("vllm")),
  };
  evidence.details.configured = configured;
  if (!Object.values(configured).some(Boolean)) {
    evidence.status = "blocked";
    evidence.result = {
      reason: "no_live_model_backends_configured",
      nextLiveStep: "Set IOI_LLAMA_CPP_BASE_URL, OLLAMA_HOST, VLLM_BASE_URL, or install a supported backend binary.",
    };
    return;
  }
  await withDaemon(async ({ daemon }) => {
    const backends = await expectOk(daemon.endpoint, "/api/v1/backends");
    const checked = [];
    for (const backend of backends.filter((item) => ["llama_cpp", "ollama", "vllm"].includes(item.kind))) {
      const health = await expectOk(daemon.endpoint, `/api/v1/backends/${backend.id}/health`, { method: "POST" });
      checked.push({ id: backend.id, kind: backend.kind, status: health.status });
    }
    const available = checked.filter((backend) => !["blocked", "absent"].includes(backend.status));
    if (available.length === 0) {
      evidence.status = "blocked";
      evidence.result = {
        reason: "no_live_model_backend_available",
        checked,
        nextLiveStep: "Configure and start llama.cpp, Ollama, or vLLM, then rerun IOI_LIVE_MODEL_BACKENDS=1 npm run test:model-backends:live.",
      };
      return;
    }
    const result = { checked, available };
    if (available.some((backend) => backend.kind === "ollama")) {
      const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
        method: "POST",
        body: {
          allowed: ["model.chat:*", "model.embeddings:*", "model.load:*", "model.mount:*", "route.use:*"],
          denied: ["filesystem.write", "shell.exec"],
        },
      });
      const providerModels = await expectOk(daemon.endpoint, "/api/v1/providers/provider.ollama/models");
      const chatModel =
        providerModels.find((model) => !String(model.modelId).match(/embed/i))?.modelId ?? providerModels[0]?.modelId;
      assert.ok(chatModel, "Ollama live gate could not select a chat model.");
      const chatEndpoint = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
        method: "POST",
        token: grant.token,
        body: {
          model_id: chatModel,
          id: `endpoint.live.ollama.${chatModel.replace(/[^a-zA-Z0-9]+/g, ".").toLowerCase()}`,
          provider_id: "provider.ollama",
        },
      });
      const chatLoaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
        method: "POST",
        token: grant.token,
        body: { endpoint_id: chatEndpoint.id, load_policy: { mode: "manual", autoEvict: false } },
      });
      assert.equal(chatLoaded.backend, "ollama");
      const chat = await expectOk(daemon.endpoint, "/api/v1/chat", {
        method: "POST",
        token: grant.token,
        body: {
          model: chatModel,
          input: "Reply exactly with: ok",
          stream: false,
          options: { num_predict: 8 },
        },
      });
      const chatReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${chat.receipt_id}`);
      assert.equal(chatReceipt.details.providerId, "provider.ollama");
      assert.equal(chatReceipt.details.backend, "ollama");

      const embeddingModel = providerModels.find((model) => String(model.modelId).match(/embed/i))?.modelId;
      let embeddingReceiptId = null;
      if (embeddingModel) {
        const embeddingEndpoint = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
          method: "POST",
          token: grant.token,
          body: {
            model_id: embeddingModel,
            id: `endpoint.live.ollama.${embeddingModel.replace(/[^a-zA-Z0-9]+/g, ".").toLowerCase()}`,
            provider_id: "provider.ollama",
          },
        });
        await expectOk(daemon.endpoint, "/api/v1/models/load", {
          method: "POST",
          token: grant.token,
          body: { endpoint_id: embeddingEndpoint.id, load_policy: { mode: "manual", autoEvict: false } },
        });
        const embeddings = await expectOk(daemon.endpoint, "/v1/embeddings", {
          method: "POST",
          token: grant.token,
          body: { model: embeddingModel, input: "live ollama embedding check" },
        });
        embeddingReceiptId = embeddings.receipt_id;
        const embeddingReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${embeddingReceiptId}`);
        assert.equal(embeddingReceipt.details.providerId, "provider.ollama");
        assert.equal(embeddingReceipt.details.backend, "ollama");
      }
      result.ollama = {
        providerModels: providerModels.length,
        selectedChatModel: chatModel,
        chatEndpointId: chatEndpoint.id,
        chatInstanceId: chatLoaded.id,
        chatReceiptId: chat.receipt_id,
        selectedEmbeddingModel: embeddingModel ?? null,
        embeddingReceiptId,
      };
    }
    evidence.status = "passed";
    evidence.result = result;
  });
}

async function runWalletGate(evidence) {
  let fakeRemote = null;
  const remoteUrl = process.env.IOI_WALLET_NETWORK_URL ?? (fakeRemote = await startFakeRemoteBoundaryServer("wallet")).url;
  evidence.details.remoteMode = process.env.IOI_WALLET_NETWORK_URL ? "configured_remote" : "deterministic_fake_remote";
  if (!process.env.IOI_WALLET_NETWORK_URL) {
    evidence.details.fallbackReason = "remote_wallet_network_not_configured";
  }
  try {
    const remoteHealth = await probeRemoteBoundary(remoteUrl, "wallet");
    await withTemporaryEnv({ IOI_WALLET_NETWORK_URL: remoteUrl }, async () => {
      await withDaemon(async ({ daemon, stateDir }) => {
        evidence.details.daemonEndpoint = daemon.endpoint;
        evidence.details.stateDir = stateDir;
        const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
          method: "POST",
          body: {
            audience: "autopilot-local-server",
            allowed: ["model.chat:*", "mcp.import:*", "mcp.call:huggingface.model_search"],
            denied: ["filesystem.write", "shell.exec"],
            vault_refs: { provider_key: "vault://wallet.fake/provider-key" },
          },
        });
        const listedTokens = await expectOk(daemon.endpoint, "/api/v1/tokens", { token: grant.token });
        const listedGrant = listedTokens.find((token) => token.id === grant.id);
        assert.equal(listedGrant.vaultRefs.provider_key.redacted, true);
        assert.equal(JSON.stringify(listedGrant).includes("vault://wallet.fake/provider-key"), false);

        const deniedGrant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
          method: "POST",
          body: {
            allowed: ["model.chat:*"],
            denied: ["model.chat:*"],
          },
        });
        const denied = await requestJson(daemon.endpoint, "/api/v1/chat", {
          method: "POST",
          token: deniedGrant.token,
          body: { model: "local:auto", input: "must fail closed" },
        });
        assert.equal(denied.response.status, 403);

        const badMcp = await requestJson(daemon.endpoint, "/api/v1/mcp/import", {
          method: "POST",
          token: grant.token,
          body: {
            mcpServers: {
              bad: {
                url: "https://example.invalid/mcp",
                allowed_tools: ["model_search"],
                headers: { authorization: "Bearer plaintext-secret" },
              },
            },
          },
        });
        assert.equal(badMcp.response.status, 403);

        const projection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
        assert.equal(projection.adapterBoundaries.wallet.remoteAdapter.configured, true);
        assert.equal(projection.adapterBoundaries.wallet.remoteAdapter.urlHash, stableHash(remoteUrl));
        const secretScan = scanFilesForNeedles(stateDir, [grant.token, deniedGrant.token, "Bearer plaintext-secret"]);
        assert.equal(secretScan.passed, true);
        evidence.status = "passed";
        evidence.result = {
          remoteMode: evidence.details.remoteMode,
          remoteHealth,
          port: projection.adapterBoundaries.wallet.port,
          implementation: projection.adapterBoundaries.wallet.implementation,
          remoteAdapter: projection.adapterBoundaries.wallet.remoteAdapter,
          grantId: grant.id,
          deniedStatus: denied.response.status,
          badMcpStatus: badMcp.response.status,
          tokenCount: listedTokens.length,
          secretScan,
          fakeRemoteRequests: fakeRemote?.requests ?? [],
        };
      });
    });
  } finally {
    if (fakeRemote) await fakeRemote.close();
  }
}

async function runAgentgresGate(evidence) {
  let fakeRemote = null;
  const remoteUrl = process.env.IOI_AGENTGRES_URL ?? (fakeRemote = await startFakeRemoteBoundaryServer("agentgres")).url;
  evidence.details.remoteMode = process.env.IOI_AGENTGRES_URL ? "configured_remote" : "deterministic_fake_remote";
  if (!process.env.IOI_AGENTGRES_URL) {
    evidence.details.fallbackReason = "remote_agentgres_not_configured";
  }
  try {
    const remoteHealth = await probeRemoteBoundary(remoteUrl, "agentgres");
    await withTemporaryEnv({ IOI_AGENTGRES_URL: remoteUrl }, async () => {
      await withDaemon(async ({ daemon, stateDir }) => {
        evidence.details.daemonEndpoint = daemon.endpoint;
        evidence.details.stateDir = stateDir;
        const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
          method: "POST",
          body: {
            allowed: ["model.chat:*", "model.download:*"],
            denied: ["filesystem.write", "shell.exec"],
          },
        });
        const download = await expectOk(daemon.endpoint, "/api/v1/models/download", {
          method: "POST",
          token: grant.token,
          body: {
            model_id: "agentgres:remote-boundary-fixture",
            provider_id: "provider.autopilot.local",
            source_url: "fixture://agentgres/remote-boundary",
            fixture_content: "family=agentgres-boundary\ncontext=1024\nquantization=Q4_K_M\n",
          },
        });
        const chat = await expectOk(daemon.endpoint, "/api/v1/chat", {
          method: "POST",
          token: grant.token,
          body: {
            route_id: "route.native-local",
            model: "autopilot:native-fixture",
            input: "Agentgres remote boundary replay check",
          },
        });
        const replay = await expectOk(daemon.endpoint, `/api/v1/receipts/${chat.receipt_id}/replay`);
        assert.equal(replay.receipt.id, chat.receipt_id);
        assert.equal(replay.source, "agentgres_model_mounting_projection_replay");
        const projection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
        assert.equal(projection.adapterBoundaries.agentgres.remoteAdapter.configured, true);
        assert.equal(projection.adapterBoundaries.agentgres.remoteAdapter.urlHash, stableHash(remoteUrl));
        assert.ok(projection.watermark > 0);
        assert.ok(projection.receipts.some((receipt) => receipt.id === chat.receipt_id));
        assert.ok(projection.downloads.some((job) => job.id === download.id));
        const secretScan = scanFilesForNeedles(stateDir, [grant.token, remoteUrl]);
        assert.equal(secretScan.passed, true);
        evidence.status = "passed";
        evidence.result = {
          remoteMode: evidence.details.remoteMode,
          remoteHealth,
          port: projection.adapterBoundaries.agentgres.port,
          implementation: projection.adapterBoundaries.agentgres.implementation,
          remoteAdapter: projection.adapterBoundaries.agentgres.remoteAdapter,
          projectionWatermark: projection.watermark,
          downloadId: download.id,
          chatReceiptId: chat.receipt_id,
          replaySource: replay.source,
          secretScan,
          fakeRemoteRequests: fakeRemote?.requests ?? [],
        };
      });
    });
  } finally {
    if (fakeRemote) await fakeRemote.close();
  }
}

function resolveBinary(name) {
  const paths = String(process.env.PATH ?? "").split(path.delimiter);
  return paths.some((dir) => {
    try {
      fs.accessSync(path.join(dir, name), fs.constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
}

function stableHash(value) {
  const input = typeof value === "string" ? value : JSON.stringify(value);
  return crypto.createHash("sha256").update(input).digest("hex");
}

function scanFilesForNeedles(rootDir, needles) {
  const findings = [];
  const filteredNeedles = needles.filter(Boolean).map(String);
  const visit = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const filePath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        visit(filePath);
        continue;
      }
      if (!entry.isFile()) continue;
      let text = "";
      try {
        text = fs.readFileSync(filePath, "utf8");
      } catch {
        continue;
      }
      for (const needle of filteredNeedles) {
        if (text.includes(needle)) {
          findings.push({ file: path.relative(rootDir, filePath), needleHash: stableHash(needle) });
        }
      }
    }
  };
  visit(rootDir);
  return { passed: findings.length === 0, findings };
}

async function main() {
  const gateName = process.argv[2];
  const gate = gates[gateName];
  if (!gate) {
    console.error(usage());
    process.exit(2);
  }
  const outputDir = path.join(evidenceRoot, gate.evidenceDir, timestamp());
  const evidence = makeEvidence(gateName, outputDir);
  if (process.env[gate.env] !== "1") {
    evidence.status = "skipped";
    evidence.result = {
      reason: "live_gate_not_enabled",
      requiredEnv: `${gate.env}=1`,
    };
    writeEvidence(evidence);
    return;
  }
  try {
    if (gateName === "lm-studio") {
      await runLmStudioGate(evidence);
    } else if (gateName === "model-backends") {
      await runModelBackendsGate(evidence);
    } else if (gateName === "wallet") {
      await runWalletGate(evidence);
    } else if (gateName === "agentgres") {
      await runAgentgresGate(evidence);
    }
  } catch (error) {
    evidence.status = "failed";
    evidence.result = {
      reason: "live_gate_failed",
      error: error instanceof Error ? error.stack ?? error.message : String(error),
    };
    writeEvidence(evidence);
    process.exit(1);
  }
  writeEvidence(evidence);
}

main();
