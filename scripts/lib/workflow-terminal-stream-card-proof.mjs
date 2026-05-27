#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-terminal-stream-card-proof.mjs <output-path>");
}

const { buildWorkflowTerminalStreamCard } = await import(
  "../../packages/agent-ide/src/runtime/workflow-terminal-stream-card.ts"
);

async function fetchJson(url, options) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  const body = await response.json();
  assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}: ${JSON.stringify(body)}`);
  return body;
}

async function fetchSseEvents(url) {
  const response = await fetch(url);
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

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage24-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage24-state-"));
const canary = "TERMINAL_STREAM_CARD_CANARY";
fs.writeFileSync(
  path.join(cwd, "package.json"),
  `${JSON.stringify({ scripts: { test: "node terminal-stream-script.mjs" } }, null, 2)}\n`,
  "utf8",
);
fs.writeFileSync(
  path.join(cwd, "terminal-stream-script.mjs"),
  [
    'import assert from "node:assert/strict";',
    `console.log(${JSON.stringify(`${canary}: stdout line 1`)});`,
    'console.log("stdout line 2 " + "x".repeat(360));',
    'process.stderr.write("stderr diagnostic line\\n");',
    "assert.equal(1 + 1, 2);",
    "",
  ].join("\n"),
  "utf8",
);

const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const workflowGraphId = "workflow.react-flow.terminal-stream-card";
  const workflowNodeId = "workflow.terminal-stream-card.test-run";
  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove terminal output streams into a compact card with final marker and artifact fallback.",
      options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
    }),
  });
  await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mode`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "runtime.thread-mode.yolo.terminal-stream-card",
      mode: "yolo",
      approvalMode: "never_prompt",
    }),
  });

  const testRun = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/test.run/invoke`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId,
      toolCallId: "coding_tool_terminal_stream_card_test_run",
      streamOutput: true,
      input: {
        commandId: "npm.test",
        maxOutputBytes: 140,
      },
    }),
  });
  assert.equal(testRun.status, "completed");
  assert.equal(testRun.result.testStatus, "passed");
  assert.equal(testRun.result.truncated, true);
  assert.ok(testRun.command_stream_events.length >= 2);
  assert.ok(testRun.artifact_refs.length >= 1);

  const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
  const commandStreamEvents = events.filter((event) => event.event_kind === "COMMAND_STREAM");
  const card = buildWorkflowTerminalStreamCard({ events });
  const row = card.rows.find((candidate) => candidate.toolCallId === "coding_tool_terminal_stream_card_test_run");

  assert.ok(row);
  assert.equal(card.status, "ready");
  assert.equal(card.streamCount, 1);
  assert.equal(card.completedCount, 1);
  assert.equal(card.artifactBackedCount, 1);
  assert.equal(row.finalSeen, true);
  assert.equal(row.truncated, true);
  assert.ok(row.preview?.includes(canary));
  assert.ok(row.channels.includes("stdout"));
  assert.ok(row.channels.includes("stderr"));
  assert.ok(row.receiptRefs.some((ref) => ref.startsWith("receipt_coding_tool_test.run_")));
  assert.ok(row.artifactRefs.length >= 1);

  const artifactRead = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/artifact.read/invoke`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "workflow.terminal-stream-card.artifact-read",
      toolCallId: "coding_tool_terminal_stream_card_artifact_read",
      input: {
        artifactId: row.artifactRefs[0],
        maxBytes: 4096,
      },
    }),
  });
  assert.equal(artifactRead.status, "completed");
  assert.match(artifactRead.result.content, /stdout line 2/);

  const proof = {
    schemaVersion: "ioi.autopilot.stage24.terminal-stream-card-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    threadId: thread.thread_id,
    workflowGraphId,
    workflowNodeId,
    testRunEventId: testRun.event.event_id,
    commandStreamEventIds: commandStreamEvents.map((event) => event.event_id),
    artifactReadEventId: artifactRead.event.event_id,
    checks: {
      commandStreamEventsEmitted: commandStreamEvents.length >= 2,
      finalMarkerSeen: row.finalSeen,
      streamCardReady: card.status === "ready",
      previewContainsCanary: row.preview?.includes(canary) === true,
      stdoutAndStderrChannelsVisible: row.channels.includes("stdout") && row.channels.includes("stderr"),
      artifactFallbackVisible: row.artifactRefs.length >= 1,
      artifactReadStillHasFullOutput: /stdout line 2/.test(artifactRead.result.content),
    },
    card,
    artifactRead: {
      artifactId: row.artifactRefs[0],
      contentHash: artifactRead.result.contentHash,
      fullContentHash: artifactRead.result.fullContentHash,
      receiptRefs: artifactRead.receipt_refs,
    },
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  await daemon.close();
}
