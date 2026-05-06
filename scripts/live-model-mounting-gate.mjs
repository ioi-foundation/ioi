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
const evidenceRoot = process.env.IOI_MODEL_MOUNTING_LIVE_EVIDENCE_ROOT
  ? path.resolve(process.env.IOI_MODEL_MOUNTING_LIVE_EVIDENCE_ROOT)
  : path.join(repoRoot, "docs/evidence/model-mounting-live");
const schemaVersion = "ioi.model-mounting.live-gate.v1";

const gates = {
  "lm-studio": {
    env: "IOI_LIVE_LM_STUDIO",
    evidenceDir: "lm-studio",
  },
  "llama-cpp": {
    env: "IOI_LIVE_LLAMA_CPP",
    evidenceDir: "llama-cpp",
  },
  "model-backends": {
    env: "IOI_LIVE_MODEL_BACKENDS",
    evidenceDir: "model-backends",
  },
  "model-catalog": {
    env: "IOI_LIVE_MODEL_CATALOG",
    evidenceDir: "model-catalog",
  },
  "model-catalog-oauth": {
    env: "IOI_LIVE_MODEL_CATALOG_OAUTH",
    evidenceDir: "model-catalog-oauth",
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

async function reserveLocalPort() {
  const server = http.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  const port = address?.port;
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  return port;
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

async function requestSse(endpoint, route, { method = "POST", body, token } = {}) {
  const response = await fetch(`${endpoint}${route}`, {
    method,
    headers: {
      accept: "text/event-stream",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return { response, text };
}

async function requestSseAndAbortAfterFirstChunk(endpoint, route, { method = "POST", body, token } = {}) {
  const controller = new AbortController();
  const response = await fetch(`${endpoint}${route}`, {
    method,
    signal: controller.signal,
    headers: {
      accept: "text/event-stream",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
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
    // Aborting a live provider stream rejects the reader on some Node versions.
  }
  return { response, text };
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
  assert.equal(result.response.ok, true, `${route} -> ${result.response.status} ${JSON.stringify(result.json)}`);
  return result.json;
}

async function waitForReceipt(endpoint, predicate, { timeoutMs = 5000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const receipts = await expectOk(endpoint, "/api/v1/receipts");
    const receipt = receipts.find(predicate);
    if (receipt) return receipt;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.fail("Expected live stream receipt was not recorded before timeout.");
}

async function exerciseLiveChatStreamReceipts({
  daemon,
  token,
  routeId,
  modelId,
  endpointId,
  providerId,
  backend,
  backendId,
  streamKind,
  providerResponseKind,
  requestOptions = {},
  abortTimeoutMs = 10000,
}) {
  const completed = await requestSse(daemon.endpoint, "/v1/chat/completions", {
    method: "POST",
    token,
    body: {
      route_id: routeId,
      model: modelId,
      stream: true,
      messages: [{ role: "user", content: "Reply with a short live stream receipt parity check." }],
      max_tokens: 64,
      ...requestOptions,
    },
  });
  assert.equal(completed.response.status, 200);
  assert.equal(completed.response.headers.get("x-ioi-stream-source"), "provider_native");
  const chunks = parseOpenAiSseChunks(completed.text);
  assert.equal(chunks.at(-1), "[DONE]");
  const metadata = chunks.find((chunk) => chunk !== "[DONE]" && chunk.stream_receipt_id);
  assert.ok(metadata?.receipt_id, "completed live stream did not expose invocation receipt metadata");
  assert.ok(metadata?.stream_receipt_id, "completed live stream did not expose stream receipt metadata");
  assert.equal(metadata.route_id, routeId);
  assert.equal(metadata.provider_stream, "native");
  const completedInvocation = await expectOk(daemon.endpoint, `/api/v1/receipts/${metadata.receipt_id}`);
  assert.equal(completedInvocation.kind, "model_invocation");
  assert.equal(completedInvocation.details.routeId, routeId);
  assert.equal(completedInvocation.details.selectedModel, modelId);
  assert.equal(completedInvocation.details.endpointId, endpointId);
  assert.equal(completedInvocation.details.providerId, providerId);
  assert.equal(completedInvocation.details.backend, backend);
  assert.equal(completedInvocation.details.backendId, backendId);
  assert.equal(completedInvocation.details.streamSource, "provider_native");
  assert.equal(completedInvocation.details.providerResponseKind, providerResponseKind);
  const completedReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${metadata.stream_receipt_id}`);
  assertLiveStreamReceipt(completedReceipt, {
    kind: "model_invocation_stream_completed",
    routeId,
    modelId,
    endpointId,
    providerId,
    backendId,
    streamKind,
    providerResponseKind,
    invocationReceiptId: metadata.receipt_id,
  });
  assert.equal(typeof completedReceipt.details.outputHash, "string");
  assert.equal(typeof completedReceipt.details.finishReason, "string");
  const completedReplay = await expectOk(daemon.endpoint, `/api/v1/receipts/${metadata.stream_receipt_id}/replay`);
  assert.equal(completedReplay.receipt.id, metadata.stream_receipt_id);
  assert.equal(completedReplay.route.id, routeId);
  assert.equal(completedReplay.endpoint.id, endpointId);

  const aborted = await requestSseAndAbortAfterFirstChunk(daemon.endpoint, "/v1/chat/completions", {
    method: "POST",
    token,
    body: {
      route_id: routeId,
      model: modelId,
      stream: true,
      messages: [
        {
          role: "user",
          content:
            "Write a deliberately long numbered list for live stream abort validation. Continue until stopped.",
        },
      ],
      max_tokens: 192,
      ...requestOptions,
    },
  });
  assert.equal(aborted.response.status, 200);
  assert.match(aborted.text, /chat\.completion\.chunk/);
  const abortedReceipt = await waitForReceipt(
    daemon.endpoint,
    (receipt) =>
      receipt.kind === "model_invocation_stream_canceled" &&
      receipt.details?.streamKind === streamKind &&
      receipt.details?.routeId === routeId &&
      receipt.details?.selectedModel === modelId,
    { timeoutMs: abortTimeoutMs },
  );
  assertLiveStreamReceipt(abortedReceipt, {
    kind: "model_invocation_stream_canceled",
    routeId,
    modelId,
    endpointId,
    providerId,
    backendId,
    streamKind,
    providerResponseKind,
    status: "aborted",
    reason: "client_disconnect",
  });
  const abortedInvocation = await expectOk(daemon.endpoint, `/api/v1/receipts/${abortedReceipt.details.invocationReceiptId}`);
  assert.equal(abortedInvocation.kind, "model_invocation");
  assert.equal(abortedInvocation.details.streamSource, "provider_native");
  assert.equal(abortedInvocation.details.providerResponseKind, providerResponseKind);
  const abortedReplay = await expectOk(daemon.endpoint, `/api/v1/receipts/${abortedReceipt.id}/replay`);
  assert.equal(abortedReplay.receipt.id, abortedReceipt.id);
  assert.equal(abortedReplay.route.id, routeId);
  assert.equal(abortedReplay.endpoint.id, endpointId);

  return {
    completedInvocationReceiptId: metadata.receipt_id,
    completedStreamReceiptId: metadata.stream_receipt_id,
    abortedInvocationReceiptId: abortedReceipt.details.invocationReceiptId,
    abortedStreamReceiptId: abortedReceipt.id,
    streamKind,
    providerResponseKind,
  };
}

function assertLiveStreamReceipt(
  receipt,
  { kind, routeId, modelId, endpointId, providerId, backendId, streamKind, providerResponseKind, invocationReceiptId, status, reason },
) {
  assert.equal(receipt.kind, kind);
  assert.equal(receipt.redaction, "redacted");
  assert.equal(receipt.details.streamKind, streamKind);
  assert.equal(receipt.details.streamSource, "provider_native");
  assert.equal(receipt.details.routeId, routeId);
  assert.equal(receipt.details.selectedModel, modelId);
  assert.equal(receipt.details.endpointId, endpointId);
  assert.equal(receipt.details.providerId, providerId);
  assert.equal(receipt.details.backendId, backendId);
  assert.equal(receipt.details.selectedBackend, backendId);
  assert.equal(receipt.details.providerResponseKind, providerResponseKind);
  assert.ok(Array.isArray(receipt.details.backendEvidenceRefs));
  assert.equal(typeof receipt.details.invocationReceiptId, "string");
  if (invocationReceiptId) assert.equal(receipt.details.invocationReceiptId, invocationReceiptId);
  if (status) assert.equal(receipt.details.status, status);
  if (reason) assert.equal(receipt.details.reason, reason);
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

function safeLiveId(value) {
  return String(value ?? "live")
    .replace(/[^a-zA-Z0-9]+/g, ".")
    .replace(/^\.+|\.+$/g, "")
    .toLowerCase();
}

function openAiCompatibleBaseUrl(value) {
  const trimmed = String(value ?? "").replace(/\/+$/, "");
  return trimmed.endsWith("/v1") ? trimmed : `${trimmed}/v1`;
}

function redactLiveEvidence(value) {
  const secretNeedles = [
    process.env.OPENAI_API_KEY,
    process.env.ANTHROPIC_API_KEY,
    process.env.GEMINI_API_KEY,
    process.env.IOI_CUSTOM_MODEL_AUTH,
    process.env.IOI_WALLET_NETWORK_TOKEN,
    process.env.IOI_AGENTGRES_TOKEN,
    process.env.IOI_MODEL_CATALOG_DOWNLOAD_SOURCE_URL,
    process.env.IOI_MODEL_CATALOG_OAUTH_CALLBACK_URL,
    process.env.IOI_MODEL_CATALOG_OAUTH_AUTHORIZATION_CODE,
    process.env.IOI_MODEL_CATALOG_OAUTH_STATE,
    process.env.IOI_MODEL_CATALOG_OAUTH_CLIENT_ID,
    process.env.IOI_MODEL_CATALOG_OAUTH_CLIENT_SECRET,
    process.env.IOI_LLAMA_CPP_MODEL_PATH,
    process.env.IOI_LLAMA_CPP_SERVER_PATH,
    process.env.IOI_VLLM_BINARY,
    process.env.IOI_VLLM_MODEL,
    process.env.VLLM_BASE_URL,
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

async function startCatalogOAuthLoopbackServer({ timeoutMs = 120000 } = {}) {
  let capturedCallback = null;
  let resolveCallback;
  const callbackPromise = new Promise((resolve) => {
    resolveCallback = resolve;
  });
  const server = http.createServer((request, response) => {
    const base = `http://${request.headers.host ?? "127.0.0.1"}`;
    const callbackUrl = new URL(request.url ?? "/", base);
    if (callbackUrl.pathname !== "/oauth/callback") {
      response.statusCode = 404;
      response.end("Not found");
      return;
    }
    capturedCallback = {
      url: callbackUrl.toString(),
      state: callbackUrl.searchParams.get("state") ?? "",
      code: callbackUrl.searchParams.get("code") ?? "",
      error: callbackUrl.searchParams.get("error") ?? "",
      providerId: callbackUrl.searchParams.get("mountsOAuthProvider") ?? callbackUrl.searchParams.get("oauthProvider") ?? "",
    };
    response.statusCode = 200;
    response.setHeader("content-type", "text/plain; charset=utf-8");
    response.end("Autopilot received the catalog OAuth callback. You can close this browser tab.");
    resolveCallback(capturedCallback);
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  const redirectUri = `http://127.0.0.1:${address.port}/oauth/callback`;
  return {
    redirectUri,
    wait: () =>
      new Promise((resolve) => {
        const timeout = setTimeout(() => resolve(null), timeoutMs);
        callbackPromise.then((callback) => {
          clearTimeout(timeout);
          resolve(callback);
        });
      }),
    captured: () => capturedCallback,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

async function startCatalogOAuthFixtureServer({
  providerId = "catalog.huggingface",
  authorizationCode = "fixture-catalog-oauth-code",
  accessToken = "fixture-catalog-oauth-access-token",
  refreshToken = "fixture-catalog-oauth-refresh-token",
} = {}) {
  const observed = [];
  const server = http.createServer(async (request, response) => {
    const base = `http://${request.headers.host ?? "127.0.0.1"}`;
    const url = new URL(request.url ?? "/", base);
    if (request.method === "GET" && url.pathname === "/oauth/authorize") {
      const redirectUri = url.searchParams.get("redirect_uri") ?? "";
      const state = url.searchParams.get("state") ?? "";
      const codeChallenge = url.searchParams.get("code_challenge") ?? "";
      observed.push({
        kind: "authorization",
        clientIdHash: stableHash(url.searchParams.get("client_id") ?? ""),
        redirectUriHash: stableHash(redirectUri),
        stateHash: stableHash(state),
        codeChallengeHash: codeChallenge ? stableHash(codeChallenge) : null,
        scopes: splitOAuthScopes(url.searchParams.get("scope") ?? ""),
        method: url.searchParams.get("code_challenge_method") ?? null,
      });
      if (!redirectUri || !state) {
        response.statusCode = 400;
        response.end("missing redirect_uri or state");
        return;
      }
      const callback = new URL(redirectUri);
      callback.searchParams.set("code", authorizationCode);
      callback.searchParams.set("state", state);
      callback.searchParams.set("mountsOAuthProvider", providerId);
      response.statusCode = 302;
      response.setHeader("location", callback.toString());
      response.end();
      return;
    }
    if (request.method === "POST" && url.pathname === "/oauth/token") {
      const body = new URLSearchParams(await readRequestText(request));
      observed.push({
        kind: "token",
        grantType: body.get("grant_type") ?? null,
        codeHash: stableHash(body.get("code") ?? ""),
        clientIdHash: stableHash(body.get("client_id") ?? ""),
        redirectUriHash: stableHash(body.get("redirect_uri") ?? ""),
        codeVerifierHash: body.get("code_verifier") ? stableHash(body.get("code_verifier")) : null,
        scopes: splitOAuthScopes(body.get("scope") ?? ""),
      });
      if (body.get("code") !== authorizationCode || body.get("grant_type") !== "authorization_code") {
        response.statusCode = 403;
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({ error: "invalid_grant" }));
        return;
      }
      response.statusCode = 200;
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify({
          access_token: accessToken,
          refresh_token: refreshToken,
          token_type: "Bearer",
          expires_in: 3600,
          scope: body.get("scope") ?? "catalog.read model.read",
        }),
      );
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  const endpoint = `http://127.0.0.1:${address.port}`;
  return {
    endpoint,
    authorizationEndpoint: `${endpoint}/oauth/authorize`,
    tokenEndpoint: `${endpoint}/oauth/token`,
    observed: () => [...observed],
    secrets: {
      authorizationCode,
      accessToken,
      refreshToken,
    },
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function openCatalogOAuthAuthorizationUrl(url) {
  const configured = process.env.IOI_MODEL_CATALOG_OAUTH_BROWSER_COMMAND;
  const command = configured || (process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open");
  const args = configured ? [url] : process.platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    const child = childProcess.spawn(command, args, {
      cwd: repoRoot,
      detached: true,
      stdio: "ignore",
    });
    child.unref();
    return {
      launched: true,
      command: configured ? "custom browser command" : command,
      errorHash: null,
    };
  } catch (error) {
    return {
      launched: false,
      command: configured ? "custom browser command" : command,
      errorHash: stableHash(error instanceof Error ? error.message : String(error)),
    };
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

async function runLlamaCppGate(evidence) {
  const binaryPath = process.env.IOI_LLAMA_CPP_SERVER_PATH ?? null;
  const modelPath = process.env.IOI_LLAMA_CPP_MODEL_PATH ?? null;
  const configuredBaseUrl = process.env.IOI_LLAMA_CPP_BASE_URL ?? null;
  evidence.details.llamaCpp = {
    binaryPathHash: binaryPath ? stableHash(binaryPath) : null,
    modelPathHash: modelPath ? stableHash(modelPath) : null,
    baseUrlHash: configuredBaseUrl ? stableHash(configuredBaseUrl) : null,
    modelId: process.env.IOI_LLAMA_CPP_MODEL_ID ?? null,
  };

  if (!binaryPath) {
    evidence.status = "blocked";
    evidence.result = {
      reason: "llama_cpp_server_path_not_configured",
      required: "Set IOI_LLAMA_CPP_SERVER_PATH to a real llama-server binary.",
      nextLiveStep:
        "Set IOI_LLAMA_CPP_SERVER_PATH and IOI_LLAMA_CPP_MODEL_PATH, then rerun IOI_LIVE_LLAMA_CPP=1 npm run test:llama-cpp-live.",
    };
    return;
  }
  if (!modelPath) {
    evidence.status = "blocked";
    evidence.result = {
      reason: "llama_cpp_model_path_not_configured",
      required: "Set IOI_LLAMA_CPP_MODEL_PATH to a local GGUF artifact.",
      nextLiveStep:
        "Set IOI_LLAMA_CPP_MODEL_PATH to a GGUF file, then rerun IOI_LIVE_LLAMA_CPP=1 npm run test:llama-cpp-live.",
    };
    return;
  }
  try {
    fs.accessSync(binaryPath, fs.constants.X_OK);
  } catch {
    evidence.status = "blocked";
    evidence.result = {
      reason: "llama_cpp_server_binary_not_executable",
      binaryPathHash: stableHash(binaryPath),
      nextLiveStep: "Make IOI_LLAMA_CPP_SERVER_PATH executable or point it at the llama-server binary.",
    };
    return;
  }
  try {
    fs.accessSync(modelPath, fs.constants.R_OK);
  } catch {
    evidence.status = "blocked";
    evidence.result = {
      reason: "llama_cpp_model_path_not_readable",
      modelPathHash: stableHash(modelPath),
      nextLiveStep: "Point IOI_LLAMA_CPP_MODEL_PATH at a readable local GGUF model.",
    };
    return;
  }

  const version = runCommand(binaryPath, ["--version"], { timeout: 10000 });
  evidence.commands.push({
    command: "llama-server --version",
    status: version.status,
    signal: version.signal,
    stdout: version.stdout,
    stderr: version.stderr,
  });

  const baseUrl = configuredBaseUrl
    ? openAiCompatibleBaseUrl(configuredBaseUrl)
    : `http://127.0.0.1:${await reserveLocalPort()}/v1`;
  const modelId =
    process.env.IOI_LLAMA_CPP_MODEL_ID ??
    path.basename(modelPath).replace(/\.gguf$/i, "") ??
    "llama-cpp-live";
  const liveTimeoutMs = Number(process.env.IOI_LLAMA_CPP_LIVE_TIMEOUT_MS ?? 180000);
  const endpointId = `endpoint.live.llama-cpp.${safeLiveId(modelId)}`;
  const routeId = `route.live.llama-cpp.${safeLiveId(modelId)}`;

  await withTemporaryEnv(
    {
      IOI_LLAMA_CPP_SERVER_PATH: binaryPath,
      IOI_LLAMA_CPP_BASE_URL: baseUrl,
      IOI_PROVIDER_HTTP_TIMEOUT_MS: process.env.IOI_PROVIDER_HTTP_TIMEOUT_MS ?? "5000",
    },
    async () => {
      await withDaemon(async ({ daemon, stateDir }) => {
        evidence.details.daemonEndpoint = daemon.endpoint;
        evidence.details.stateDir = stateDir;
        evidence.details.llamaCpp.baseUrlHash = stableHash(baseUrl);
        evidence.details.llamaCpp.modelId = modelId;

        const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
          method: "POST",
          body: {
            allowed: [
              "model.chat:*",
              "model.responses:*",
              "model.embeddings:*",
              "model.import:*",
              "model.mount:*",
              "model.load:*",
              "model.unload:*",
              "route.write:*",
              "route.use:*",
            ],
            denied: ["filesystem.write", "shell.exec"],
          },
        });

        const imported = await expectOk(daemon.endpoint, "/api/v1/models/import", {
          method: "POST",
          token: grant.token,
          body: {
            model_id: modelId,
            provider_id: "provider.llama-cpp",
            path: modelPath,
            import_mode: "reference",
            capabilities: ["chat", "responses", "embeddings"],
          },
        });
        const mounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
          method: "POST",
          token: grant.token,
          body: {
            model_id: modelId,
            provider_id: "provider.llama-cpp",
            id: endpointId,
            backend_id: "backend.llama-cpp",
          },
        });
        await expectOk(daemon.endpoint, "/api/v1/routes", {
          method: "POST",
          token: grant.token,
          body: {
            id: routeId,
            role: "llama-cpp-live",
            privacy: "local_only",
            fallback: [mounted.id],
            provider_eligibility: ["llama_cpp"],
            denied_providers: [],
            max_cost_usd: 0,
          },
        });

        const loaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
          method: "POST",
          token: grant.token,
          body: {
            endpoint_id: mounted.id,
            load_policy: { mode: "manual", autoEvict: false },
            load_options: {
              gpu: process.env.IOI_LLAMA_CPP_GPU ?? "off",
              contextLength: Number(process.env.IOI_LLAMA_CPP_CONTEXT_LENGTH ?? imported.contextWindow ?? 2048),
              parallel: Number(process.env.IOI_LLAMA_CPP_PARALLEL ?? 1),
              ttlSeconds: Number(process.env.IOI_LLAMA_CPP_TTL_SECONDS ?? 900),
              identifier: "llama-cpp-live-gate",
              embeddings: true,
            },
          },
        });
        assert.equal(loaded.backend, "llama_cpp");
        assert.equal(loaded.backendId, "backend.llama-cpp");
        assert.equal(loaded.backendProcess?.spawned, true);
        assert.equal(loaded.backendProcess?.spawnStatus, "spawned");
        assert.match(loaded.backendProcess?.pidHash ?? "", /^[a-f0-9]{16}$/);

        const providerModels = await waitForProviderModels(daemon.endpoint, "provider.llama-cpp", liveTimeoutMs);
        const health = await waitForProviderHealth(daemon.endpoint, "provider.llama-cpp", liveTimeoutMs);
        assert.equal(health.status, "available");

        const chat = await expectOk(daemon.endpoint, "/api/v1/chat", {
          method: "POST",
          token: grant.token,
          body: { route_id: routeId, input: "Reply exactly with: ok", max_tokens: 8 },
        });
        const compatChat = await expectOk(daemon.endpoint, "/v1/chat/completions", {
          method: "POST",
          token: grant.token,
          body: {
            route_id: routeId,
            model: modelId,
            messages: [{ role: "user", content: "Reply exactly with: ok" }],
            max_tokens: 8,
          },
        });
        const responses = await expectOk(daemon.endpoint, "/api/v1/responses", {
          method: "POST",
          token: grant.token,
          body: { route_id: routeId, input: "Reply exactly with: ok", max_output_tokens: 8 },
        });
        let embeddingReceiptId = null;
        let embeddingStatus = "not_exercised";
        let embeddingVectors = null;
        let embeddingErrorHash = null;
        try {
          const embeddings = await expectOk(daemon.endpoint, "/v1/embeddings", {
            method: "POST",
            token: grant.token,
            body: { route_id: routeId, model: modelId, input: "live llama.cpp embedding check" },
          });
          assert.ok(Array.isArray(embeddings.data));
          embeddingReceiptId = embeddings.receipt_id ?? null;
          embeddingVectors = embeddings.data.length;
          embeddingStatus = "passed";
        } catch (error) {
          embeddingStatus = "unsupported_or_failed";
          embeddingErrorHash = stableHash(String(error?.message ?? error));
        }

        const chatReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${chat.receipt_id}`);
        const responseReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${responses.receipt_id}`);
        const replay = await expectOk(daemon.endpoint, `/api/v1/receipts/${chat.receipt_id}/replay`);
        assert.equal(chatReceipt.details.providerId, "provider.llama-cpp");
        assert.equal(chatReceipt.details.backend, "llama_cpp");
        assert.equal(chatReceipt.details.backendProcessPidHash, loaded.backendProcess.pidHash);
        assert.equal(replay.receipt.id, chat.receipt_id);
        const streamReceipts = await exerciseLiveChatStreamReceipts({
          daemon,
          token: grant.token,
          routeId,
          modelId,
          endpointId: mounted.id,
          providerId: "provider.llama-cpp",
          backend: "llama_cpp",
          backendId: "backend.llama-cpp",
          streamKind: "openai_chat_completions_provider_native",
          providerResponseKind: "chat.completions.stream",
          requestOptions: { max_tokens: 64 },
          abortTimeoutMs: liveTimeoutMs,
        });

        const unloaded = await expectOk(daemon.endpoint, "/api/v1/models/unload", {
          method: "POST",
          token: grant.token,
          body: { instance_id: loaded.id },
        });
        assert.equal(unloaded.status, "unloaded");
        const logs = await expectOk(daemon.endpoint, "/api/v1/backends/backend.llama-cpp/logs");
        assert.ok(logs.some((record) => record.event === "backend_process_start"));
        assert.ok(logs.some((record) => record.event === "backend_process_stop"));
        const secretScan = scanFilesForNeedles(stateDir, [grant.token]);
        assert.equal(secretScan.passed, true);

        evidence.status = "passed";
        evidence.result = {
          modelId,
          artifactId: imported.id,
          endpointId: mounted.id,
          routeId,
          instanceId: loaded.id,
          providerModels: providerModels.length,
          healthStatus: health.status,
          backendProcessId: loaded.backendProcess.id,
          backendProcessPidHash: loaded.backendProcess.pidHash,
          chatReceiptId: chat.receipt_id,
          compatChatModel: compatChat.model,
          responsesReceiptId: responses.receipt_id,
          responsesCompatTranslation: responses.compat_translation ?? responseReceipt.details.compatTranslation ?? null,
          embeddingStatus,
          embeddingReceiptId,
          embeddingVectors,
          embeddingErrorHash,
          streamReceipts,
          replaySource: replay.source,
          secretScan,
        };
      });
    },
  );
}

async function waitForProviderModels(endpoint, providerId, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const models = await expectOk(endpoint, `/api/v1/providers/${providerId}/models`);
      if (Array.isArray(models) && models.length > 0) return models;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  throw lastError ?? new Error(`Timed out waiting for ${providerId} models.`);
}

async function waitForProviderHealth(endpoint, providerId, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastHealth = null;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const health = await expectOk(endpoint, `/api/v1/providers/${providerId}/health`, { method: "POST" });
      lastHealth = health;
      if (health.status === "available") return health;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  throw lastError ?? new Error(`Timed out waiting for ${providerId} health to become available: ${JSON.stringify(lastHealth)}`);
}

async function runModelBackendsGate(evidence) {
  const configured = {
    llamaCppBaseUrl: Boolean(process.env.IOI_LLAMA_CPP_BASE_URL),
    llamaCppServerPath: Boolean(process.env.IOI_LLAMA_CPP_SERVER_PATH),
    ollamaHost: Boolean(process.env.OLLAMA_HOST),
    ollamaBinary: Boolean(resolveBinary("ollama")),
    vllmBaseUrl: Boolean(process.env.VLLM_BASE_URL),
    vllmBinary: Boolean(process.env.IOI_VLLM_BINARY || resolveBinary("vllm")),
    vllmModel: Boolean(process.env.IOI_VLLM_MODEL),
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
  await withDaemon(async ({ daemon, stateDir }) => {
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
          allowed: [
            "model.chat:*",
            "model.embeddings:*",
            "model.load:*",
            "model.unload:*",
            "model.mount:*",
            "route.write:*",
            "route.use:*",
            "backend.control:*",
          ],
          denied: ["filesystem.write", "shell.exec"],
        },
      });
      const ollamaBackendStart = configured.ollamaBinary
        ? await expectOk(daemon.endpoint, "/api/v1/backends/backend.ollama/start", {
            method: "POST",
            token: grant.token,
            body: { load_options: { identifier: "ollama-live-backend-gate" } },
          })
        : null;
      const providerModels = await expectOk(daemon.endpoint, "/api/v1/providers/provider.ollama/models");
      const configuredChatModel = process.env.IOI_OLLAMA_CHAT_MODEL;
      const chatModel =
        providerModels.find((model) => configuredChatModel && model.modelId === configuredChatModel)?.modelId ??
        providerModels.find((model) => !String(model.modelId).match(/embed/i))?.modelId ??
        providerModels[0]?.modelId;
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
      const chatRouteId = `route.live.ollama.${safeLiveId(chatModel)}`;
      await expectOk(daemon.endpoint, "/api/v1/routes", {
        method: "POST",
        token: grant.token,
        body: {
          id: chatRouteId,
          role: "ollama-live",
          privacy: "local_only",
          fallback: [chatEndpoint.id],
          provider_eligibility: ["ollama"],
          denied_providers: [],
          max_cost_usd: 0,
        },
      });
      const chatLoaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
        method: "POST",
        token: grant.token,
        body: { endpoint_id: chatEndpoint.id, load_policy: { mode: "manual", autoEvict: false } },
      });
      assert.equal(chatLoaded.backend, "ollama");
      const providerLoaded = await expectOk(daemon.endpoint, "/api/v1/providers/provider.ollama/loaded");
      assert.ok(providerLoaded.some((model) => model.modelId === chatModel));
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
      const streamReceipts = await exerciseLiveChatStreamReceipts({
        daemon,
        token: grant.token,
        routeId: chatRouteId,
        modelId: chatModel,
        endpointId: chatEndpoint.id,
        providerId: "provider.ollama",
        backend: "ollama",
        backendId: "backend.ollama",
        streamKind: "openai_chat_completions_ollama_native",
        providerResponseKind: "ollama.chat.stream",
        requestOptions: { options: { num_predict: 64 } },
      });

      const configuredEmbeddingModel = process.env.IOI_OLLAMA_EMBEDDING_MODEL;
      const embeddingModel =
        providerModels.find((model) => configuredEmbeddingModel && model.modelId === configuredEmbeddingModel)?.modelId ??
        providerModels.find((model) => String(model.modelId).match(/embed/i))?.modelId;
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
      const chatUnloaded = await expectOk(daemon.endpoint, "/api/v1/models/unload", {
        method: "POST",
        token: grant.token,
        body: { instance_id: chatLoaded.id },
      });
      assert.equal(chatUnloaded.status, "unloaded");
      const ollamaBackendStop = configured.ollamaBinary
        ? await expectOk(daemon.endpoint, "/api/v1/backends/backend.ollama/stop", {
            method: "POST",
            token: grant.token,
          })
        : null;
      result.ollama = {
        providerModels: providerModels.length,
        providerLoaded: providerLoaded.length,
        selectedChatModel: chatModel,
        configuredChatModel: configuredChatModel ?? null,
        chatEndpointId: chatEndpoint.id,
        chatRouteId,
        chatInstanceId: chatLoaded.id,
        backendStartReceiptId: ollamaBackendStart?.lastReceiptId ?? null,
        backendStopReceiptId: ollamaBackendStop?.lastReceiptId ?? null,
        chatReceiptId: chat.receipt_id,
        streamReceipts,
        unloadStatus: chatUnloaded.status,
        selectedEmbeddingModel: embeddingModel ?? null,
        configuredEmbeddingModel: configuredEmbeddingModel ?? null,
        embeddingReceiptId,
      };
    }
    if (available.some((backend) => backend.kind === "vllm")) {
      const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
        method: "POST",
        body: {
          allowed: [
            "model.chat:*",
            "model.responses:*",
            "model.embeddings:*",
            "model.import:*",
            "model.mount:*",
            "model.load:*",
            "model.unload:*",
            "route.write:*",
            "route.use:*",
            "backend.control:*",
          ],
          denied: ["filesystem.write", "shell.exec"],
        },
      });
      const liveTimeoutMs = Number(process.env.IOI_VLLM_LIVE_TIMEOUT_MS ?? 180000);
      const configuredModel = process.env.IOI_VLLM_MODEL ?? null;
      const vllmBackendStart =
        configured.vllmBinary && configuredModel
          ? await expectOk(daemon.endpoint, "/api/v1/backends/backend.vllm/start", {
              method: "POST",
              token: grant.token,
              body: {
                load_options: {
                  model: configuredModel,
                  identifier: "vllm-live-backend-gate",
                  ...(process.env.IOI_VLLM_CONTEXT_LENGTH
                    ? { contextLength: Number(process.env.IOI_VLLM_CONTEXT_LENGTH) }
                    : {}),
                  ...(process.env.IOI_VLLM_TENSOR_PARALLEL_SIZE
                    ? { tensorParallelSize: Number(process.env.IOI_VLLM_TENSOR_PARALLEL_SIZE) }
                    : {}),
                  ...(process.env.IOI_VLLM_DTYPE ? { dtype: process.env.IOI_VLLM_DTYPE } : {}),
                  ...(process.env.IOI_VLLM_GPU_MEMORY_UTILIZATION
                    ? { gpuMemoryUtilization: Number(process.env.IOI_VLLM_GPU_MEMORY_UTILIZATION) }
                    : {}),
                },
              },
            })
          : null;
      let providerModels = [];
      let providerModelErrorHash = null;
      try {
        providerModels = configuredModel
          ? await waitForProviderModels(daemon.endpoint, "provider.vllm", liveTimeoutMs)
          : await expectOk(daemon.endpoint, "/api/v1/providers/provider.vllm/models");
      } catch (error) {
        providerModelErrorHash = stableHash(String(error?.message ?? error));
      }
      const selectedModel = configuredModel ?? providerModels[0]?.modelId ?? null;
      if (!selectedModel) {
        result.vllm = {
          status: "blocked",
          reason: "vllm_model_not_available",
          providerModelErrorHash,
          nextLiveStep:
            "Set IOI_VLLM_MODEL to a model that vllm serve can load, or start a VLLM_BASE_URL server that exposes /v1/models.",
        };
      } else {
        const endpointId = `endpoint.live.vllm.${safeLiveId(selectedModel)}`;
        const routeId = `route.live.vllm.${safeLiveId(selectedModel)}`;
        const imported = await expectOk(daemon.endpoint, "/api/v1/models/import", {
          method: "POST",
          token: grant.token,
          body: {
            model_id: selectedModel,
            provider_id: "provider.vllm",
            capabilities: ["chat", "responses", "embeddings"],
            privacy_class: "workspace",
          },
        });
        const mounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
          method: "POST",
          token: grant.token,
          body: {
            model_id: selectedModel,
            provider_id: "provider.vllm",
            id: endpointId,
            backend_id: "backend.vllm",
          },
        });
        await expectOk(daemon.endpoint, "/api/v1/routes", {
          method: "POST",
          token: grant.token,
          body: {
            id: routeId,
            role: "vllm-live",
            privacy: "local_or_enterprise",
            fallback: [mounted.id],
            provider_eligibility: ["vllm"],
            denied_providers: [],
            max_cost_usd: 0,
          },
        });
        const loaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
          method: "POST",
          token: grant.token,
          body: {
            endpoint_id: mounted.id,
            load_policy: { mode: "manual", autoEvict: false },
            load_options: {
              identifier: "vllm-live-load",
              ...(process.env.IOI_VLLM_CONTEXT_LENGTH
                ? { contextLength: Number(process.env.IOI_VLLM_CONTEXT_LENGTH) }
                : {}),
              ...(process.env.IOI_VLLM_TENSOR_PARALLEL_SIZE
                ? { tensorParallelSize: Number(process.env.IOI_VLLM_TENSOR_PARALLEL_SIZE) }
                : {}),
              ...(process.env.IOI_VLLM_DTYPE ? { dtype: process.env.IOI_VLLM_DTYPE } : {}),
              ...(process.env.IOI_VLLM_GPU_MEMORY_UTILIZATION
                ? { gpuMemoryUtilization: Number(process.env.IOI_VLLM_GPU_MEMORY_UTILIZATION) }
                : {}),
            },
          },
        });
        assert.equal(loaded.backend, "vllm");
        assert.equal(loaded.backendId, "backend.vllm");
        const health = await expectOk(daemon.endpoint, "/api/v1/providers/provider.vllm/health", { method: "POST" });
        assert.equal(health.status, "available");
        const responses = await expectOk(daemon.endpoint, "/api/v1/responses", {
          method: "POST",
          token: grant.token,
          body: { route_id: routeId, input: "Reply exactly with: ok", max_output_tokens: 8 },
        });
        const compatChat = await expectOk(daemon.endpoint, "/v1/chat/completions", {
          method: "POST",
          token: grant.token,
          body: {
            route_id: routeId,
            model: selectedModel,
            messages: [{ role: "user", content: "Reply exactly with: ok" }],
            max_tokens: 8,
          },
        });
        const responseReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${responses.receipt_id}`);
        assert.equal(responseReceipt.details.providerId, "provider.vllm");
        assert.equal(responseReceipt.details.backend, "vllm");
        const streamReceipts = await exerciseLiveChatStreamReceipts({
          daemon,
          token: grant.token,
          routeId,
          modelId: selectedModel,
          endpointId: mounted.id,
          providerId: "provider.vllm",
          backend: "vllm",
          backendId: "backend.vllm",
          streamKind: "openai_chat_completions_provider_native",
          providerResponseKind: "chat.completions.stream",
          requestOptions: { max_tokens: 64 },
          abortTimeoutMs: liveTimeoutMs,
        });
        let embeddingReceiptId = null;
        let embeddingStatus = "not_exercised";
        let embeddingErrorHash = null;
        try {
          const embeddings = await expectOk(daemon.endpoint, "/v1/embeddings", {
            method: "POST",
            token: grant.token,
            body: { route_id: routeId, model: process.env.IOI_VLLM_EMBEDDING_MODEL ?? selectedModel, input: "live vllm embedding check" },
          });
          embeddingReceiptId = embeddings.receipt_id ?? null;
          embeddingStatus = "passed";
        } catch (error) {
          embeddingStatus = "unsupported_or_failed";
          embeddingErrorHash = stableHash(String(error?.message ?? error));
        }
        const providerLoaded = await expectOk(daemon.endpoint, "/api/v1/providers/provider.vllm/loaded");
        assert.ok(providerLoaded.some((model) => model.modelId === selectedModel));
        const unloaded = await expectOk(daemon.endpoint, "/api/v1/models/unload", {
          method: "POST",
          token: grant.token,
          body: { instance_id: loaded.id },
        });
        assert.equal(unloaded.status, "unloaded");
        const logs = await expectOk(daemon.endpoint, "/api/v1/backends/backend.vllm/logs");
        const secretScan = scanFilesForNeedles(stateDir, [grant.token]);
        assert.equal(secretScan.passed, true);
        result.vllm = {
          status: "passed",
          selectedModel,
          artifactId: imported.id,
          endpointId: mounted.id,
          routeId,
          instanceId: loaded.id,
          providerModels: providerModels.length,
          backendStartReceiptId: vllmBackendStart?.lastReceiptId ?? null,
          backendProcessId: loaded.backendProcess?.id ?? null,
          backendProcessPidHash: loaded.backendProcess?.pidHash ?? null,
          healthStatus: health.status,
          responsesReceiptId: responses.receipt_id,
          responsesCompatTranslation: responses.compat_translation ?? responseReceipt.details.compatTranslation ?? null,
          compatChatModel: compatChat.model,
          streamReceipts,
          embeddingStatus,
          embeddingReceiptId,
          embeddingErrorHash,
          unloadStatus: unloaded.status,
          backendLogEvents: logs.length,
          secretScan,
        };
      }
    }
    if (!result.ollama && result.vllm?.status !== "passed") {
      evidence.status = "blocked";
      evidence.result = {
        ...result,
        reason: "no_live_model_backend_scenario_exercised",
        nextLiveStep:
          "Configure Ollama with at least one model, or configure vLLM with IOI_VLLM_MODEL plus a PATH vllm binary, IOI_VLLM_BINARY, or VLLM_BASE_URL, then rerun IOI_LIVE_MODEL_BACKENDS=1 npm run test:model-backends:live.",
      };
      return;
    }
    evidence.status = "passed";
    evidence.result = result;
  });
}

async function runModelCatalogGate(evidence) {
  const query = process.env.IOI_MODEL_CATALOG_QUERY ?? "qwen";
  const format = process.env.IOI_MODEL_CATALOG_FORMAT ?? "gguf";
  const quantization = process.env.IOI_MODEL_CATALOG_QUANTIZATION ?? "";
  const limit = Number(process.env.IOI_MODEL_CATALOG_LIMIT ?? 5);
  const downloadSource = process.env.IOI_MODEL_CATALOG_DOWNLOAD_SOURCE_URL ?? "";
  const downloadFirstResult = process.env.IOI_MODEL_CATALOG_DOWNLOAD_FIRST_RESULT === "1";
  const downloadMaxBytes = process.env.IOI_MODEL_CATALOG_DOWNLOAD_MAX_BYTES ?? process.env.IOI_MODEL_DOWNLOAD_MAX_BYTES ?? "";
  evidence.details.catalog = {
    query,
    format,
    quantization: quantization || null,
    limit,
    baseUrlHash: stableHash(process.env.IOI_MODEL_CATALOG_HF_BASE_URL ?? "https://huggingface.co"),
    downloadGateEnabled: process.env.IOI_LIVE_MODEL_DOWNLOAD === "1",
    explicitDownloadSourceConfigured: Boolean(downloadSource),
    downloadFirstResult,
    downloadMaxBytes: downloadMaxBytes ? Number(downloadMaxBytes) : null,
  };
  await withDaemon(async ({ daemon, stateDir }) => {
    evidence.details.daemonEndpoint = daemon.endpoint;
    evidence.details.stateDir = stateDir;
    const params = new URLSearchParams();
    params.set("q", query);
    if (format) params.set("format", format);
    if (quantization) params.set("quantization", quantization);
    params.set("limit", String(limit));
    const catalog = await expectOk(daemon.endpoint, `/api/v1/models/catalog/search?${params.toString()}`);
    const liveProvider = catalog.providers?.find?.((provider) => provider.id === "catalog.huggingface");
    if (liveProvider?.status !== "available") {
      evidence.status = "blocked";
      evidence.result = {
        reason: "model_catalog_live_provider_unavailable",
        providerStatus: liveProvider?.status ?? "unknown",
        errorHash: liveProvider?.errorHash ?? null,
        nextLiveStep:
          "Confirm network access or set IOI_MODEL_CATALOG_HF_BASE_URL to a Hugging Face-compatible catalog, then rerun IOI_LIVE_MODEL_CATALOG=1 npm run test:model-catalog-live.",
      };
      return;
    }
    const liveResults = catalog.results.filter((entry) => entry.catalogProviderId === "catalog.huggingface");
    if (liveResults.length === 0) {
      evidence.status = "blocked";
      evidence.result = {
        reason: "model_catalog_live_search_returned_no_variants",
        query,
        format,
        quantization: quantization || null,
        nextLiveStep: "Adjust IOI_MODEL_CATALOG_QUERY, IOI_MODEL_CATALOG_FORMAT, or IOI_MODEL_CATALOG_QUANTIZATION.",
      };
      return;
    }
    const result = {
      providerStatus: liveProvider.status,
      resultCount: liveResults.length,
      firstModelId: liveResults[0].modelId,
      firstSourceHash: stableHash(liveResults[0].sourceUrl),
      formats: [...new Set(liveResults.map((entry) => entry.format).filter(Boolean))],
      quantizations: [...new Set(liveResults.map((entry) => entry.quantization).filter(Boolean))],
      download: null,
    };
    const selectedDownloadEntry = liveResults[0];
    const effectiveDownloadSource = downloadSource || (downloadFirstResult ? selectedDownloadEntry.sourceUrl : "");
    if (effectiveDownloadSource) {
      if (process.env.IOI_LIVE_MODEL_DOWNLOAD !== "1") {
        evidence.status = "blocked";
        evidence.result = {
          ...result,
          reason: "model_catalog_download_source_requires_download_gate",
          requiredEnv: "IOI_LIVE_MODEL_DOWNLOAD=1",
        };
        return;
      }
      const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
        method: "POST",
        body: {
          allowed: ["model.download:*", "model.import:*"],
          denied: ["filesystem.write", "shell.exec"],
        },
      });
      const imported = await expectOk(daemon.endpoint, "/api/v1/models/catalog/import-url", {
        method: "POST",
        token: grant.token,
        body: {
          source_url: effectiveDownloadSource,
          model_id: process.env.IOI_MODEL_CATALOG_DOWNLOAD_MODEL_ID ?? "native:live-catalog-gate",
          format: downloadSource ? format : selectedDownloadEntry.format ?? format,
          quantization: downloadSource ? quantization || undefined : selectedDownloadEntry.quantization ?? (quantization || undefined),
          ...(downloadSource
            ? {}
            : {
                source_label: selectedDownloadEntry.sourceLabel,
                variant_id: selectedDownloadEntry.id,
                size_bytes: selectedDownloadEntry.sizeBytes,
              }),
          max_bytes: downloadMaxBytes ? Number(downloadMaxBytes) : undefined,
        },
      });
      assert.equal(imported.status, "completed");
      const download = imported.download;
      assert.equal(download.status, "completed");
      const status = await expectOk(daemon.endpoint, `/api/v1/models/download/status/${download.id}`);
      assert.equal(status.status, "completed");
      assert.equal(status.id, download.id);
      const replay = await expectOk(daemon.endpoint, `/api/v1/receipts/${download.receiptId}/replay`);
      assert.equal(replay.receipt.id, download.receiptId);
      const projection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
      assert.ok(projection.downloads.some((job) => job.id === download.id));
      assert.ok(projection.artifacts.some((artifact) => artifact.id === download.artifactId));
      result.download = {
        mode: downloadSource ? "explicit_source_url" : "first_catalog_result",
        jobId: download.id,
        artifactId: download.artifactId,
        status: download.status,
        bytesCompleted: download.bytesCompleted,
        bytesTotal: download.bytesTotal,
        maxBytes: download.maxBytes ?? null,
        receiptId: download.receiptId,
        statusReceiptId: status.receiptId,
        replaySource: replay.source,
        sourceHash: download.sourceHash ?? download.sourceUrlHash ?? stableHash(effectiveDownloadSource),
        projectionDownloadCount: projection.downloads.length,
      };
      const secretScan = scanFilesForNeedles(stateDir, [sensitiveSourceUrlNeedle(effectiveDownloadSource), grant.token]);
      assert.equal(secretScan.passed, true);
      result.secretScan = secretScan;
    }
    evidence.status = "passed";
    evidence.result = result;
  });
}

function defaultCatalogOAuthRedirectUri(providerId) {
  const url = new URL("ioi://mounts/oauth/callback");
  url.searchParams.set("mountsOAuthCallback", "1");
  url.searchParams.set("mountsOAuthProvider", providerId);
  return url.toString();
}

function splitOAuthScopes(value) {
  return String(value ?? "")
    .split(/,|\n|\s+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseCatalogOAuthCallbackInput(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return { code: "", state: "", error: "", providerId: "" };
  let params;
  try {
    params = new URL(raw).searchParams;
  } catch {
    params = new URLSearchParams(raw.replace(/^[?#]/, ""));
  }
  return {
    code: params.get("code") ?? "",
    state: params.get("state") ?? "",
    error: params.get("error") ?? "",
    providerId: params.get("mountsOAuthProvider") ?? params.get("oauthProvider") ?? "",
  };
}

function catalogOAuthEndpointDefaults(providerId) {
  if (providerId === "catalog.huggingface") {
    return {
      authorizationEndpoint: "https://huggingface.co/oauth/authorize",
      tokenEndpoint: "https://huggingface.co/oauth/token",
      scopes: "catalog.read model.read",
    };
  }
  return {
    authorizationEndpoint: "",
    tokenEndpoint: "",
    scopes: "catalog.read",
  };
}

async function runModelCatalogOAuthGate(evidence) {
  const providerId = process.env.IOI_MODEL_CATALOG_OAUTH_PROVIDER_ID ?? "catalog.huggingface";
  const fixtureOAuthEnabled = process.env.IOI_MODEL_CATALOG_OAUTH_FIXTURE === "1";
  const defaults = catalogOAuthEndpointDefaults(providerId);
  let fixtureOAuthServer = null;
  let authorizationEndpoint = process.env.IOI_MODEL_CATALOG_OAUTH_AUTHORIZATION_URL ?? defaults.authorizationEndpoint;
  let tokenEndpoint = process.env.IOI_MODEL_CATALOG_OAUTH_TOKEN_URL ?? defaults.tokenEndpoint;
  let redirectUri = process.env.IOI_MODEL_CATALOG_OAUTH_REDIRECT_URI ?? defaultCatalogOAuthRedirectUri(providerId);
  const clientId = process.env.IOI_MODEL_CATALOG_OAUTH_CLIENT_ID ?? (fixtureOAuthEnabled ? "fixture-catalog-oauth-client" : "");
  const scopes = splitOAuthScopes(process.env.IOI_MODEL_CATALOG_OAUTH_SCOPES ?? defaults.scopes);
  const callbackUrl = process.env.IOI_MODEL_CATALOG_OAUTH_CALLBACK_URL ?? "";
  const callbackFromUrl = parseCatalogOAuthCallbackInput(callbackUrl);
  let callbackState = process.env.IOI_MODEL_CATALOG_OAUTH_STATE ?? callbackFromUrl.state;
  let authorizationCode = process.env.IOI_MODEL_CATALOG_OAUTH_AUTHORIZATION_CODE ?? callbackFromUrl.code;
  const customBaseUrl = process.env.IOI_MODEL_CATALOG_OAUTH_CUSTOM_BASE_URL ?? process.env.IOI_MODEL_CATALOG_CUSTOM_BASE_URL ?? "";
  const pkceRequired = process.env.IOI_MODEL_CATALOG_OAUTH_PKCE_REQUIRED === "0" ? false : true;
  const loopbackCallbackEnabled = process.env.IOI_MODEL_CATALOG_OAUTH_LOCAL_CALLBACK === "1" || fixtureOAuthEnabled;
  const loopbackTimeoutMs = Number(process.env.IOI_MODEL_CATALOG_OAUTH_CALLBACK_TIMEOUT_MS ?? 120000);
  let loopbackServer = null;

  if (fixtureOAuthEnabled) {
    fixtureOAuthServer = await startCatalogOAuthFixtureServer({ providerId });
    authorizationEndpoint = fixtureOAuthServer.authorizationEndpoint;
    tokenEndpoint = fixtureOAuthServer.tokenEndpoint;
  }

  evidence.details.oauth = {
    providerId,
    fixtureOAuthEnabled,
    fixtureOAuthEndpointHash: fixtureOAuthServer ? stableHash(fixtureOAuthServer.endpoint) : null,
    authorizationEndpointHash: authorizationEndpoint ? stableHash(authorizationEndpoint) : null,
    tokenEndpointHash: tokenEndpoint ? stableHash(tokenEndpoint) : null,
    redirectUriHash: stableHash(redirectUri),
    redirectUriScheme: (() => {
      try {
        return new URL(redirectUri).protocol.replace(/:$/, "");
      } catch {
        return "invalid";
      }
    })(),
    clientIdConfigured: Boolean(clientId),
    clientIdHash: clientId ? stableHash(clientId) : null,
    scopes,
    pkceRequired,
    loopbackCallbackEnabled,
    loopbackTimeoutMs,
    callbackConfigured: Boolean(callbackUrl || callbackState || authorizationCode),
    callbackUrlHash: callbackUrl ? stableHash(callbackUrl) : null,
    customBaseUrlHash: customBaseUrl ? stableHash(customBaseUrl) : null,
  };

  if (!clientId) {
    evidence.status = "blocked";
    evidence.result = {
      reason: "model_catalog_oauth_client_id_not_configured",
      requiredEnv: "IOI_MODEL_CATALOG_OAUTH_CLIENT_ID",
      nextLiveStep:
        "Register a provider OAuth app with the Mounts deep-link redirect URI, then rerun with IOI_LIVE_MODEL_CATALOG_OAUTH=1 and IOI_MODEL_CATALOG_OAUTH_CLIENT_ID set.",
    };
    return;
  }
  if (!authorizationEndpoint || !tokenEndpoint) {
    evidence.status = "blocked";
    evidence.result = {
      reason: "model_catalog_oauth_endpoints_not_configured",
      requiredEnv: "IOI_MODEL_CATALOG_OAUTH_AUTHORIZATION_URL and IOI_MODEL_CATALOG_OAUTH_TOKEN_URL",
    };
    return;
  }
  if (process.env.IOI_MODEL_CATALOG_OAUTH_CLIENT_SECRET) {
    if (fixtureOAuthServer) await fixtureOAuthServer.close();
    evidence.status = "blocked";
    evidence.result = {
      reason: "model_catalog_oauth_client_secret_must_use_vault_ref",
      nextLiveStep:
        "Use a public PKCE client for this callback gate, or bind confidential-client material through the vault-backed exchange path instead of plaintext environment values.",
    };
    return;
  }

  if (loopbackCallbackEnabled) {
    loopbackServer = await startCatalogOAuthLoopbackServer({ timeoutMs: loopbackTimeoutMs });
    redirectUri = loopbackServer.redirectUri;
    evidence.details.oauth.redirectUriHash = stableHash(redirectUri);
    evidence.details.oauth.redirectUriScheme = "http";
  }

  try {
    await withDaemon(async ({ daemon, stateDir }) => {
    evidence.details.daemonEndpoint = daemon.endpoint;
    evidence.details.stateDir = stateDir;
    const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
      method: "POST",
      body: {
        audience: "autopilot-local-server",
        allowed: [`provider.write:${providerId}`, "vault.write:*", "vault.read:*"],
        denied: ["filesystem.write", "shell.exec"],
      },
    });

    if (providerId === "catalog.custom_http" && customBaseUrl) {
      await expectOk(daemon.endpoint, `/api/v1/models/catalog/providers/${encodeURIComponent(providerId)}`, {
        method: "PATCH",
        token: grant.token,
        body: {
          enabled: true,
          base_url: customBaseUrl,
          auth_scheme: "oauth2",
          auth_header_name: "authorization",
        },
      });
    }

    const started = await expectOk(daemon.endpoint, `/api/v1/models/catalog/providers/${encodeURIComponent(providerId)}/oauth/start`, {
      method: "POST",
      token: grant.token,
      body: {
        authorization_endpoint: authorizationEndpoint,
        token_endpoint: tokenEndpoint,
        redirect_uri: redirectUri,
        client_id: clientId,
        scopes,
        pkce_required: pkceRequired,
      },
    });
    assert.equal(started.oauthState.status, "pending");
    assert.equal(started.oauthState.pkceRequired, pkceRequired);
    assert.ok(started.authorizationUrlHash);
    assert.ok(started.authorizationUrlRedacted);
    assert.equal(started.authorizationUrlRedacted.includes(clientId), false);
    const authorizationUrl = new URL(started.authorizationUrl);
    const oauthState = authorizationUrl.searchParams.get("state") ?? "";
    const codeChallenge = authorizationUrl.searchParams.get("code_challenge") ?? "";
    assert.ok(oauthState);
    assert.equal(started.authorizationUrlRedacted.includes(oauthState), false);
    if (codeChallenge) assert.equal(started.authorizationUrlRedacted.includes(codeChallenge), false);

    const startedReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${started.receiptId}`);
    assert.equal(startedReceipt.kind, "catalog_oauth_start");
    const startSecretScan = scanFilesForNeedles(stateDir, [grant.token, clientId, started.authorizationUrl, oauthState, codeChallenge]);
    assert.equal(startSecretScan.passed, true);

    if (callbackFromUrl.error) {
      evidence.status = "blocked";
      evidence.result = {
        reason: "model_catalog_oauth_provider_returned_error",
        errorHash: stableHash(callbackFromUrl.error),
        authorizationUrlHash: started.authorizationUrlHash,
        authorizationUrlRedacted: started.authorizationUrlRedacted,
        receiptId: started.receiptId,
        secretScan: startSecretScan,
      };
      return;
    }
    if (callbackFromUrl.providerId && callbackFromUrl.providerId !== providerId) {
      evidence.status = "blocked";
      evidence.result = {
        reason: "model_catalog_oauth_callback_provider_mismatch",
        callbackProviderHash: stableHash(callbackFromUrl.providerId),
        providerId,
        authorizationUrlHash: started.authorizationUrlHash,
        receiptId: started.receiptId,
        secretScan: startSecretScan,
      };
      return;
    }
    let effectiveCallbackUrl = callbackUrl;
    let effectiveCallbackProviderId = callbackFromUrl.providerId;
    if ((!callbackState || !authorizationCode) && loopbackServer) {
      if (fixtureOAuthServer) {
        const response = await fetch(started.authorizationUrl, { redirect: "follow" });
        await response.text();
        evidence.commands.push({
          command: "fixture oauth authorization redirect",
          status: response.ok ? 0 : 1,
          stdout: response.ok ? "Fixture OAuth provider redirected through loopback without logging raw URL." : "",
          stderr: response.ok ? "" : `status:${response.status}`,
        });
        if (!response.ok) {
          evidence.status = "blocked";
          evidence.result = {
            reason: "model_catalog_oauth_fixture_authorization_failed",
            authorizationUrlHash: started.authorizationUrlHash,
            receiptId: started.receiptId,
            secretScan: startSecretScan,
          };
          return;
        }
      } else {
        const opener = openCatalogOAuthAuthorizationUrl(started.authorizationUrl);
        evidence.commands.push({
          command: opener.command,
          status: opener.launched ? 0 : 1,
          stdout: opener.launched ? "OAuth authorization URL opened without logging raw URL." : "",
          stderr: opener.errorHash ? `errorHash:${opener.errorHash}` : "",
        });
        if (!opener.launched) {
          evidence.status = "blocked";
          evidence.result = {
            reason: "model_catalog_oauth_browser_open_failed",
            authorizationUrlHash: started.authorizationUrlHash,
            authorizationUrlRedacted: started.authorizationUrlRedacted,
            receiptId: started.receiptId,
            secretScan: startSecretScan,
          nextLiveStep:
              "Set IOI_MODEL_CATALOG_OAUTH_BROWSER_COMMAND to a browser opener command, or rerun without loopback mode and complete through the Mounts desktop UI.",
          };
          return;
        }
      }
      const loopbackCallback = await loopbackServer.wait();
      if (!loopbackCallback) {
        evidence.status = "blocked";
        evidence.result = {
          reason: "model_catalog_oauth_loopback_callback_timeout",
          authorizationUrlHash: started.authorizationUrlHash,
          authorizationUrlRedacted: started.authorizationUrlRedacted,
          timeoutMs: loopbackTimeoutMs,
          receiptId: started.receiptId,
          secretScan: startSecretScan,
          nextLiveStep:
            "Rerun with a longer IOI_MODEL_CATALOG_OAUTH_CALLBACK_TIMEOUT_MS and complete provider consent in the same invocation.",
        };
        return;
      }
      effectiveCallbackUrl = loopbackCallback.url;
      callbackState = loopbackCallback.state;
      authorizationCode = loopbackCallback.code;
      effectiveCallbackProviderId = loopbackCallback.providerId;
      if (loopbackCallback.error) {
        evidence.status = "blocked";
        evidence.result = {
          reason: "model_catalog_oauth_provider_returned_error",
          errorHash: stableHash(loopbackCallback.error),
          authorizationUrlHash: started.authorizationUrlHash,
          receiptId: started.receiptId,
          loopbackCallbackUrlHash: stableHash(loopbackCallback.url),
          secretScan: startSecretScan,
        };
        return;
      }
    }
    if (effectiveCallbackProviderId && effectiveCallbackProviderId !== providerId) {
      evidence.status = "blocked";
      evidence.result = {
        reason: "model_catalog_oauth_callback_provider_mismatch",
        callbackProviderHash: stableHash(effectiveCallbackProviderId),
        providerId,
        authorizationUrlHash: started.authorizationUrlHash,
        receiptId: started.receiptId,
        secretScan: startSecretScan,
      };
      return;
    }
    if (!callbackState || !authorizationCode) {
      evidence.status = "blocked";
      evidence.result = {
        reason: "model_catalog_oauth_callback_not_supplied",
        authorizationUrlHash: started.authorizationUrlHash,
        authorizationUrlRedacted: started.authorizationUrlRedacted,
        oauthStateHash: started.oauthState.stateHash,
        stateId: started.oauthState.id,
        pkceRequired,
        receiptId: started.receiptId,
        secretScan: startSecretScan,
        nextLiveStep:
          "Rerun with IOI_MODEL_CATALOG_OAUTH_LOCAL_CALLBACK=1 to keep this process alive for the browser callback, or complete the provider OAuth flow from the Mounts desktop UI.",
      };
      return;
    }

    const completed = await expectOk(daemon.endpoint, `/api/v1/models/catalog/providers/${encodeURIComponent(providerId)}/oauth/callback`, {
      method: "POST",
      token: grant.token,
      body: {
        state_id: started.oauthState.id,
        state: callbackState,
        code: authorizationCode,
      },
    });
    assert.equal(completed.oauthBoundary.status, "active");
    assert.equal(completed.oauthState.status, "completed");
    assert.equal(completed.oauthSession.status, "active");
    assert.equal(JSON.stringify(completed).includes(callbackState), false);
    assert.equal(JSON.stringify(completed).includes(authorizationCode), false);
    assert.equal(JSON.stringify(completed).includes(clientId), false);
    const completedReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${completed.receiptId}`);
    assert.equal(completedReceipt.kind, "catalog_oauth_callback");
    const projection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
    assert.ok(projection.oauthStates.some((state) => state.status === "completed" && state.id === completed.oauthState.id));
    assert.ok(projection.oauthSessions.some((session) => session.status === "active" && session.id === completed.oauthSession.id));
    const secretScan = scanFilesForNeedles(stateDir, [
      grant.token,
      clientId,
      effectiveCallbackUrl,
      callbackState,
      authorizationCode,
      started.authorizationUrl,
      oauthState,
      codeChallenge,
      fixtureOAuthServer?.secrets.accessToken,
      fixtureOAuthServer?.secrets.refreshToken,
      fixtureOAuthServer?.secrets.authorizationCode,
    ]);
    assert.equal(secretScan.passed, true);
    const fixtureObserved = fixtureOAuthServer?.observed() ?? [];
    if (fixtureOAuthServer) {
      assert.ok(fixtureObserved.some((entry) => entry.kind === "authorization"));
      assert.ok(fixtureObserved.some((entry) => entry.kind === "token" && entry.codeVerifierHash));
    }
    evidence.status = "passed";
    evidence.result = {
      providerId,
      reason: fixtureOAuthServer ? "model_catalog_oauth_fixture_completed" : "model_catalog_oauth_completed",
      status: completed.oauthBoundary.status,
      stateId: completed.oauthState.id,
      sessionId: completed.oauthSession.id,
      authorizationUrlHash: started.authorizationUrlHash,
      startReceiptId: started.receiptId,
      callbackReceiptId: completed.receiptId,
      loopbackCallbackUrlHash: effectiveCallbackUrl ? stableHash(effectiveCallbackUrl) : null,
      fixtureObserved,
      projectionOAuthStateCount: projection.oauthStates.length,
      projectionOAuthSessionCount: projection.oauthSessions.length,
      secretScan,
    };
    });
  } finally {
    if (loopbackServer) await loopbackServer.close();
    if (fixtureOAuthServer) await fixtureOAuthServer.close();
  }
}

function sensitiveSourceUrlNeedle(source) {
  try {
    const url = new URL(source);
    return url.search || url.username || url.password ? source : null;
  } catch {
    return null;
  }
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
    } else if (gateName === "llama-cpp") {
      await runLlamaCppGate(evidence);
    } else if (gateName === "model-backends") {
      await runModelBackendsGate(evidence);
    } else if (gateName === "model-catalog") {
      await runModelCatalogGate(evidence);
    } else if (gateName === "model-catalog-oauth") {
      await runModelCatalogOAuthGate(evidence);
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
