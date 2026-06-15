#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { bootstrapNativeRuntimeModelRoute } from "./autopilot-runtime-agent-service-inference.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-crash-restart-timeline-resume-proof.mjs <output-path>");
}

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);

async function fetchJson(url, options) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  const body = await response.json();
  assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}: ${JSON.stringify(body)}`);
  return body;
}

async function fetchSseEvents(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}: ${text}`);
  return text
    .trim()
    .split(/\n\n+/)
    .filter(Boolean)
    .map((block) => {
      const data = block
        .split(/\r?\n/)
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.replace(/^data:\s?/, ""))
        .join("\n");
      return JSON.parse(data);
    });
}

async function createDaemonModelInvocationToken(endpoint) {
  const response = await fetch(`${endpoint}/api/v1/tokens`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      audience: "autopilot-crash-restart-replay-proof",
      allowed: [
        "model.chat:*",
        "model.responses:*",
        "model.embeddings:*",
        "model.import:*",
        "model.download:*",
        "model.mount:*",
        "model.load:*",
        "model.unload:*",
        "model.unmount:*",
        "model.tokenize:*",
        "model.context:*",
        "route.write:*",
        "route.use:*",
        "server.logs:*",
        "backend.control:*",
      ],
      denied: ["connector.*"],
      source: "crash-restart-replay-proof",
    }),
  });
  const text = await response.text();
  assert.ok(response.ok, `${response.status} ${response.statusText} token request: ${text}`);
  const parsed = text ? JSON.parse(text) : {};
  assert.ok(parsed.token, `token response did not include token: ${text}`);
  return parsed;
}

function terminalEvents(events) {
  return events.filter((event) =>
    ["turn.completed", "turn.failed", "turn.canceled", "turn.cancelled"].includes(event.event_kind),
  );
}

function waitForExit(child) {
  return new Promise((resolve) => {
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
}

function spawnDaemon({ cwd, stateDir, label }) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      ["scripts/ioi-local-runtime-daemon.mjs", "--cwd", cwd, "--state-dir", stateDir],
      {
        cwd: repoRoot,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`Timed out waiting for ${label} daemon readiness. stderr=${stderr}`));
    }, 5000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      const line = stdout.split(/\r?\n/).find(Boolean);
      if (!line) return;
      try {
        const ready = JSON.parse(line);
        clearTimeout(timer);
        resolve({ child, ready, stderr: () => stderr });
      } catch (error) {
        clearTimeout(timer);
        child.kill("SIGKILL");
        reject(error);
      }
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("exit", (code, signal) => {
      if (!stdout.trim()) {
        clearTimeout(timer);
        reject(new Error(`${label} daemon exited before readiness: code=${code} signal=${signal} stderr=${stderr}`));
      }
    });
  });
}

async function killChild(child, signal = "SIGKILL") {
  if (child.exitCode !== null || child.signalCode !== null) {
    return { code: child.exitCode, signal: child.signalCode };
  }
  child.kill(signal);
  return waitForExit(child);
}

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage12-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage12-state-"));
let firstDaemon = null;
let secondDaemon = null;

try {
  firstDaemon = await spawnDaemon({ cwd, stateDir, label: "first" });
  const firstDaemonReady = firstDaemon.ready;
  const modelToken = await createDaemonModelInvocationToken(firstDaemon.ready.endpoint);
  const runtimeModelRoute = await bootstrapNativeRuntimeModelRoute({
    repoRoot,
    daemonEndpoint: firstDaemon.ready.endpoint,
    token: modelToken.token,
    workspaceDir: path.join(cwd, ".ioi", "autopilot-runtime-fixtures"),
  });
  const workflowGraphId = "workflow.react-flow.crash-restart-resume";
  const thread = await fetchJson(`${firstDaemon.ready.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove daemon crash restart timeline resume from durable event state.",
      options: {
        local: { cwd },
        model: {
          id: "auto",
          routeId: "route.native-local",
          reasoningEffort: "low",
          workflowGraphId,
          workflowNodeId: "workflow.model-router.crash-restart",
        },
      },
    }),
  });
  const firstTurn = await fetchJson(`${firstDaemon.ready.endpoint}/v1/threads/${thread.thread_id}/turns`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "workflow.turn.before-crash",
      prompt: "Stage 12 first turn before daemon crash.",
      mode: "send",
    }),
  });
  const beforeCrashEvents = await fetchSseEvents(
    `${firstDaemon.ready.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
  );
  const beforeCrashIds = beforeCrashEvents.map((event) => event.event_id);
  const beforeCrashLastSeq = beforeCrashEvents.at(-1).seq;
  const firstTurnEvents = beforeCrashEvents.filter((event) => event.turn_id === firstTurn.turn_id);
  assert.equal(terminalEvents(firstTurnEvents).length, 1);

  const crashExit = await killChild(firstDaemon.child, "SIGKILL");
  firstDaemon = null;
  assert.equal(crashExit.signal, "SIGKILL");

  secondDaemon = await spawnDaemon({ cwd, stateDir, label: "second" });
  const reloadedThread = await fetchJson(`${secondDaemon.ready.endpoint}/v1/threads/${thread.thread_id}`);
  const afterRestartEvents = await fetchSseEvents(
    `${secondDaemon.ready.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
  );
  assert.deepEqual(afterRestartEvents.map((event) => event.event_id), beforeCrashIds);
  const replayFromLastSeq = await fetchSseEvents(
    `${secondDaemon.ready.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=${beforeCrashLastSeq}`,
  );
  assert.deepEqual(replayFromLastSeq, []);
  const firstRunReplay = await fetchSseEvents(
    `${secondDaemon.ready.endpoint}/v1/runs/${firstTurn.request_id}/events`,
  );
  assert.deepEqual(firstRunReplay.map((event) => event.event_id), firstTurnEvents.map((event) => event.event_id));

  const secondTurn = await fetchJson(`${secondDaemon.ready.endpoint}/v1/threads/${thread.thread_id}/turns`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "workflow.turn.after-restart",
      prompt: "Stage 12 second turn after daemon restart.",
      mode: "send",
    }),
  });
  const finalEvents = await fetchSseEvents(
    `${secondDaemon.ready.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
  );
  const secondTurnEvents = finalEvents.filter((event) => event.turn_id === secondTurn.turn_id);
  assert.deepEqual(finalEvents.slice(0, beforeCrashIds.length).map((event) => event.event_id), beforeCrashIds);
  assert.ok(secondTurn.seq_start > beforeCrashLastSeq);
  assert.equal(terminalEvents(secondTurnEvents).length, 1);
  assert.deepEqual(
    finalEvents.map((event) => event.seq),
    Array.from({ length: finalEvents.length }, (_, index) => index + 1),
  );

  const checks = {
    child_daemon_was_actually_killed: crashExit.signal === "SIGKILL",
    reloaded_thread_preserves_latest_turn: reloadedThread.latest_turn_id === firstTurn.turn_id,
    event_ids_replay_exactly_after_restart:
      JSON.stringify(afterRestartEvents.map((event) => event.event_id)) === JSON.stringify(beforeCrashIds),
    replay_from_last_seq_is_empty_after_restart: replayFromLastSeq.length === 0,
    run_replay_matches_owning_turn_after_restart:
      JSON.stringify(firstRunReplay.map((event) => event.event_id)) ===
      JSON.stringify(firstTurnEvents.map((event) => event.event_id)),
    no_duplicate_terminal_event_for_first_turn: terminalEvents(firstTurnEvents).length === 1,
    post_restart_turn_continues_sequence: secondTurn.seq_start > beforeCrashLastSeq,
    no_duplicate_terminal_event_for_second_turn: terminalEvents(secondTurnEvents).length === 1,
    monotonic_final_timeline:
      JSON.stringify(finalEvents.map((event) => event.seq)) ===
      JSON.stringify(Array.from({ length: finalEvents.length }, (_, index) => index + 1)),
  };

  const proof = {
    schema_version: "workflow.crash-restart-timeline-resume-proof.v1",
    scenario: "daemon_sigkill_restart_timeline_resume",
    passed: Object.values(checks).every(Boolean),
    started_at: new Date().toISOString(),
    workspace_root: cwd,
    state_dir: stateDir,
    first_daemon: {
      pid: firstDaemonReady.pid,
      endpoint: firstDaemonReady.endpoint,
      crash_exit: crashExit,
    },
    second_daemon: {
      pid: secondDaemon.ready.pid,
      endpoint: secondDaemon.ready.endpoint,
    },
    thread_id: thread.thread_id,
    workflow_graph_id: workflowGraphId,
    runtime_model_route: {
      model_id: runtimeModelRoute.modelId,
      endpoint_id: runtimeModelRoute.endpointId,
      route_id: runtimeModelRoute.routeId,
      provider_id: runtimeModelRoute.providerId,
      backend_id: runtimeModelRoute.backendId,
      runtime_engine: runtimeModelRoute.runtimeEngine,
      fixture_free: runtimeModelRoute.fixtureFree,
    },
    first_turn: {
      turn_id: firstTurn.turn_id,
      run_id: firstTurn.request_id,
      status: firstTurn.status,
      seq_start: firstTurn.seq_start,
      seq_end: firstTurn.seq_end,
      terminal_events: terminalEvents(firstTurnEvents).map((event) => event.event_id),
    },
    second_turn: {
      turn_id: secondTurn.turn_id,
      run_id: secondTurn.request_id,
      status: secondTurn.status,
      seq_start: secondTurn.seq_start,
      seq_end: secondTurn.seq_end,
      terminal_events: terminalEvents(secondTurnEvents).map((event) => event.event_id),
    },
    replay: {
      before_crash_event_count: beforeCrashEvents.length,
      after_restart_event_count: afterRestartEvents.length,
      final_event_count: finalEvents.length,
      before_crash_last_seq: beforeCrashLastSeq,
      replay_from_last_seq_count: replayFromLastSeq.length,
      first_run_replay_count: firstRunReplay.length,
    },
    checks,
    source_refs: [
      "scripts/ioi-local-runtime-daemon.mjs",
      "packages/runtime-daemon/src/index.mjs:RuntimeStore",
      "scripts/lib/workflow-crash-restart-timeline-resume-proof.mjs",
      "scripts/lib/autopilot-runtime-agent-service-inference.mjs",
    ],
  };
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
} finally {
  if (firstDaemon) await killChild(firstDaemon.child, "SIGKILL").catch(() => {});
  if (secondDaemon) await killChild(secondDaemon.child, "SIGKILL").catch(() => {});
}
