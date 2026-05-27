#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-receipt-first-tool-timeline-proof.mjs <output-path>");
}

const { buildWorkflowRuntimeReceiptFirstToolTimeline } = await import(
  "../../packages/agent-ide/src/runtime/workflow-runtime-receipt-first-tool-timeline.ts"
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

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage15-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage15-state-"));
const canary = "RECEIPT_FIRST_TIMELINE_CANARY_" + "x".repeat(512);
fs.writeFileSync(
  path.join(cwd, "receipt-first.test.mjs"),
  [
    'import test from "node:test";',
    'test("receipt-first timeline keeps raw output in artifacts", () => {',
    `  console.log(${JSON.stringify(canary)});`,
    "});",
    "",
  ].join("\n"),
  "utf8",
);

const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const workflowGraphId = "workflow.react-flow.receipt-first-tool-timeline";
  const workflowNodeId = "workflow.receipt-first.test-run";
  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove tool timeline rows render receipts first and raw output as child artifacts.",
      options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
    }),
  });
  const mode = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mode`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "runtime.thread-mode.yolo.receipt-first",
      mode: "yolo",
      approvalMode: "never_prompt",
    }),
  });
  assert.equal(mode.mode, "yolo");

  const testRun = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/test.run/invoke`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId,
      toolCallId: "coding_tool_receipt_first_test_run",
      input: {
        commandId: "node.test",
        path: "receipt-first.test.mjs",
        maxOutputBytes: 80,
      },
    }),
  });
  assert.equal(testRun.status, "completed");
  assert.equal(testRun.result.testStatus, "passed");
  assert.equal(testRun.result.truncated, true);
  assert.ok(testRun.artifact_refs.length >= 1);
  assert.ok(testRun.receipt_refs.some((ref) => ref.startsWith("receipt_coding_tool_test.run_")));
  assert.ok(testRun.receipt_refs.some((ref) => ref.startsWith("receipt_test_run_node.test_")));

  const events = await fetchSseEvents(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
  );
  const timeline = buildWorkflowRuntimeReceiptFirstToolTimeline(events, {
    threadId: thread.thread_id,
    workflowGraphId,
  });
  const testRow = timeline.rows.find((row) => row.toolCallId === "coding_tool_receipt_first_test_run");
  assert.ok(testRow);
  assert.equal(timeline.status, "ready");
  assert.equal(testRow.displayMode, "receipt_first");
  assert.ok(testRow.primaryReceiptRef?.startsWith("receipt_coding_tool_test.run_"));
  assert.ok(testRow.receiptRefs.some((ref) => ref.startsWith("receipt_test_run_node.test_")));
  assert.ok(testRow.artifactRefs.length >= 1);
  assert.equal(testRow.rawOutputDemoted, true);
  assert.equal(testRow.rawOutputIncluded, false);
  assert.equal(JSON.stringify(timeline).includes(canary), false);

  const artifactRead = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/artifact.read/invoke`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "workflow.receipt-first.artifact-read",
      toolCallId: "coding_tool_receipt_first_artifact_read",
      input: {
        artifactId: testRow.artifactRefs[0],
        maxBytes: 4096,
      },
    }),
  });
  assert.equal(artifactRead.status, "completed");
  assert.match(artifactRead.result.content, /RECEIPT_FIRST_TIMELINE_CANARY_/);

  const proof = {
    schemaVersion: "ioi.autopilot.stage15.receipt-first-tool-timeline-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    threadId: thread.thread_id,
    workflowGraphId,
    workflowNodeId,
    testRunEventId: testRun.event.event_id,
    artifactReadEventId: artifactRead.event.event_id,
    checks: {
      testRunPassed: testRun.result.testStatus === "passed",
      outputSpilledToArtifacts: testRun.result.truncated === true && testRun.artifact_refs.length >= 1,
      timelineReady: timeline.status === "ready",
      primaryDisplayIsReceipt: testRow.displayMode === "receipt_first" && Boolean(testRow.primaryReceiptRef),
      rawOutputDemoted: testRow.rawOutputDemoted === true && testRow.rawOutputIncluded === false,
      timelineOmitsRawCanary: !JSON.stringify(timeline).includes(canary),
      childArtifactContainsCanary: /RECEIPT_FIRST_TIMELINE_CANARY_/.test(artifactRead.result.content),
    },
    timeline,
    artifactRead: {
      artifactId: testRow.artifactRefs[0],
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
