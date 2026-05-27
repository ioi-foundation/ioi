#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-engine-reconnect-banner-proof.mjs <output-path>");
}

const { buildWorkflowEngineReconnectBanner } = await import(
  "../../packages/agent-ide/src/runtime/workflow-engine-reconnect-banner.ts"
);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function endpointPort(endpoint) {
  return Number(new URL(endpoint).port);
}

async function probeDaemon(endpoint, { attempt, maxAttempts, phase, timeoutMs }) {
  const started = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${endpoint}/v1/threads`, { signal: controller.signal });
    const body = await response.json();
    return {
      endpoint,
      phase,
      attempt,
      maxAttempts,
      ok: response.ok,
      statusCode: response.status,
      latencyMs: Math.round(performance.now() - started),
      timeoutMs,
      message: Array.isArray(body.threads)
        ? `thread_count:${body.threads.length}`
        : body.summary ?? body.status ?? response.statusText,
      at: new Date().toISOString(),
    };
  } catch (error) {
    return {
      endpoint,
      phase,
      attempt,
      maxAttempts,
      ok: false,
      statusCode: null,
      latencyMs: Math.round(performance.now() - started),
      timeoutMs,
      errorCode: error?.name === "AbortError" ? "timeout" : error?.cause?.code ?? error?.name ?? "fetch_failed",
      message: String(error?.message ?? error),
      at: new Date().toISOString(),
    };
  } finally {
    clearTimeout(timer);
  }
}

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage30-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage30-state-"));
const maxAttempts = 5;
const timeoutMs = 250;
let daemon = null;
let restarted = null;

try {
  daemon = await startRuntimeDaemonService({ cwd, stateDir });
  const endpoint = daemon.endpoint;
  const port = endpointPort(endpoint);
  const healthyProbe = await probeDaemon(endpoint, {
    attempt: 0,
    maxAttempts,
    phase: "healthy",
    timeoutMs,
  });
  assert.equal(healthyProbe.ok, true);

  const thread = await fetch(`${endpoint}/v1/threads`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove engine reconnect banner freezes and unfreezes the chat composer.",
      options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
    }),
  }).then(async (response) => {
    const body = await response.json();
    assert.ok(response.ok, `${response.status} ${JSON.stringify(body)}`);
    return body;
  });

  await daemon.close();
  daemon = null;
  await sleep(100);

  const failedProbeOne = await probeDaemon(endpoint, {
    attempt: 1,
    maxAttempts,
    phase: "heartbeat_failed",
    timeoutMs,
  });
  const failedProbeTwo = await probeDaemon(endpoint, {
    attempt: 2,
    maxAttempts,
    phase: "reconnecting",
    timeoutMs,
  });
  assert.equal(failedProbeOne.ok, false);
  assert.equal(failedProbeTwo.ok, false);

  const reconnectingPanel = buildWorkflowEngineReconnectBanner({
    probes: [healthyProbe, failedProbeOne, failedProbeTwo],
  });
  assert.equal(reconnectingPanel.status, "reconnecting");
  assert.equal(reconnectingPanel.composerFrozen, true);
  assert.match(reconnectingPanel.bannerLabel, /Attempt 2\/5/);

  restarted = await startRuntimeDaemonService({ cwd, stateDir, port });
  assert.equal(restarted.endpoint, endpoint);
  const restoredProbe = await probeDaemon(endpoint, {
    attempt: 3,
    maxAttempts,
    phase: "restored",
    timeoutMs,
  });
  assert.equal(restoredProbe.ok, true);

  const restoredPanel = buildWorkflowEngineReconnectBanner({
    probes: [healthyProbe, failedProbeOne, failedProbeTwo, restoredProbe],
  });
  assert.equal(restoredPanel.status, "restored");
  assert.equal(restoredPanel.composerFrozen, false);
  assert.equal(restoredPanel.failedAttemptCount, 2);
  assert.equal(restoredPanel.restoredAttemptCount, 1);
  assert.match(restoredPanel.bannerLabel, /reconnected after 2 failed/);
  assert.equal(restoredPanel.endpoint, endpoint);

  const proof = {
    schemaVersion: "ioi.autopilot.stage30.engine-reconnect-banner-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint,
    threadId: thread.thread_id,
    checks: {
      healthyHeartbeatVisible: healthyProbe.ok === true,
      failedHeartbeatVisible: failedProbeOne.ok === false && failedProbeTwo.ok === false,
      attemptCounterVisible: reconnectingPanel.bannerLabel.includes("Attempt 2/5"),
      composerFrozenWhileReconnecting: reconnectingPanel.composerFrozen === true,
      sameEndpointRecovered: restarted.endpoint === endpoint,
      composerUnfrozenAfterRestore: restoredPanel.composerFrozen === false,
      timeoutMetricsVisible: restoredPanel.rows.every((row) => typeof row.timeoutMs === "number"),
      restoredPanelReady: restoredPanel.status === "restored",
    },
    probes: [healthyProbe, failedProbeOne, failedProbeTwo, restoredProbe],
    reconnectingPanel,
    restoredPanel,
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  if (daemon) await daemon.close();
  if (restarted) await restarted.close();
}
