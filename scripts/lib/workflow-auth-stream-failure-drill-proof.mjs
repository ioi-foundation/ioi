#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-auth-stream-failure-drill-proof.mjs <output-path>");
}

const { buildWorkflowAuthStreamFailurePanel } = await import(
  "../../packages/hypervisor-workbench/src/runtime/workflow-auth-stream-failure-panel.ts"
);

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
  return { response, json, text };
}

async function expectOk(endpoint, route, options = {}) {
  const result = await requestJson(endpoint, route, options);
  assert.ok(
    result.response.ok,
    `${result.response.status} ${result.response.statusText} ${route}: ${result.text}`,
  );
  return result.json;
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

async function waitForReceipt(endpoint, predicate, { timeoutMs = 2500 } = {}) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const receipts = await expectOk(endpoint, "/v1/model-mount/receipts");
    const receipt = receipts.find(predicate);
    if (receipt) return receipt;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.fail("Expected receipt was not recorded before timeout.");
}

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage19-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage19-state-"));
const daemon = await startRuntimeDaemonService({ cwd, stateDir });
const priorSseDelay = process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS;
const priorProviderDelay = process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS;

try {
  const missingAuth = await requestJson(daemon.endpoint, "/v1/messages", {
    method: "POST",
    body: {
      model: "local:auto",
      max_tokens: 16,
      messages: [{ role: "user", content: "missing token stream auth drill" }],
    },
  });
  assert.equal(missingAuth.response.status, 401);
  assert.equal(JSON.stringify(missingAuth.json).includes("sk-"), false);

  const grant = await expectOk(daemon.endpoint, "/v1/model-mount/tokens", {
    method: "POST",
    body: {
      audience: "hypervisor-local-server",
      allowed: ["model.chat:*", "model.responses:*", "route.use:*"],
    },
  });
  assert.ok(grant.token);
  process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS = "40";
  process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS = "40";

  const aborted = await requestSseAndAbortAfterFirstChunk(daemon.endpoint, "/v1/chat/completions", {
    method: "POST",
    token: grant.token,
    body: {
      route_id: "route.native-local",
      model: "hypervisor:native-fixture",
      stream: true,
      messages: [{ role: "user", content: "abort chat stream for clean failure panel" }],
    },
  });
  assert.equal(aborted.response.status, 200);
  assert.match(aborted.text, /chat\.completion\.chunk/);

  const canceledReceipt = await waitForReceipt(
    daemon.endpoint,
    (receipt) => receipt.kind === "model_invocation_stream_canceled",
  );
  assert.equal(canceledReceipt.details.status, "aborted");
  assert.equal(canceledReceipt.details.reason, "client_disconnect");
  assert.ok(canceledReceipt.details.framesWritten >= 1);

  const recovered = await requestSse(daemon.endpoint, "/v1/chat/completions", {
    method: "POST",
    token: grant.token,
    body: {
      route_id: "route.native-local",
      model: "hypervisor:native-fixture",
      stream: true,
      messages: [{ role: "user", content: "recover after canceled stream" }],
    },
  });
  assert.equal(recovered.response.status, 200);
  assert.ok(recovered.events.some((event) => event.data === "[DONE]"));
  const completedReceipt = await waitForReceipt(
    daemon.endpoint,
    (receipt) =>
      receipt.kind === "model_invocation_stream_completed" &&
      receipt.details?.routeId === "route.native-local",
  );
  assert.equal(completedReceipt.kind, "model_invocation_stream_completed");

  const receipts = await expectOk(daemon.endpoint, "/v1/model-mount/receipts");
  assert.equal(JSON.stringify(receipts).includes(grant.token), false);
  const panel = buildWorkflowAuthStreamFailurePanel({
    authFailures: [
      {
        surface: "/v1/messages",
        status: missingAuth.response.status,
        code: missingAuth.json?.error?.code,
        message: missingAuth.json?.error?.message,
        tokenValueIncluded: JSON.stringify(missingAuth.json).includes(grant.token),
      },
    ],
    receipts,
  });
  assert.equal(panel.status, "ready");
  assert.equal(panel.authFailureCount, 1);
  assert.ok(panel.streamCanceledCount >= 1);
  assert.ok(panel.streamCompletedCount >= 1);
  assert.equal(panel.tokenLeakDetected, false);

  const proof = {
    schemaVersion: "ioi.autopilot.stage19.auth-stream-failure-drill-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    checks: {
      missingAuthReturned401: missingAuth.response.status === 401,
      missingAuthCleanError: JSON.stringify(missingAuth.json).includes("sk-") === false,
      abortedStreamRecordedReceipt: canceledReceipt.kind === "model_invocation_stream_canceled",
      abortedStreamFramesRecorded: canceledReceipt.details.framesWritten >= 1,
      recoveredStreamCompleted: completedReceipt.kind === "model_invocation_stream_completed",
      receiptsDoNotLeakToken: JSON.stringify(receipts).includes(grant.token) === false,
      panelReady: panel.status === "ready",
    },
    authFailure: {
      surface: "/v1/messages",
      status: missingAuth.response.status,
      code: missingAuth.json?.error?.code ?? null,
      message: missingAuth.json?.error?.message ?? null,
    },
    canceledReceipt: {
      id: canceledReceipt.id,
      kind: canceledReceipt.kind,
      streamKind: canceledReceipt.details.streamKind,
      routeId: canceledReceipt.details.routeId,
      selectedModel: canceledReceipt.details.selectedModel,
      framesWritten: canceledReceipt.details.framesWritten,
      reason: canceledReceipt.details.reason,
    },
    completedReceipt: {
      id: completedReceipt.id,
      kind: completedReceipt.kind,
      streamKind: completedReceipt.details.streamKind,
      routeId: completedReceipt.details.routeId,
      selectedModel: completedReceipt.details.selectedModel,
      chunksForwarded: completedReceipt.details.chunksForwarded,
    },
    panel,
  };
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  if (priorSseDelay === undefined) {
    delete process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS;
  } else {
    process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS = priorSseDelay;
  }
  if (priorProviderDelay === undefined) {
    delete process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS;
  } else {
    process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS = priorProviderDelay;
  }
  await daemon.close();
}
