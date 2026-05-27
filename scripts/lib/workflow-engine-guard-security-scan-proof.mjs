#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-engine-guard-security-scan-proof.mjs <output-path>");
}

const { buildWorkflowEngineGuardSecurityScanPanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-engine-guard-security-scan.ts"
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

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage32-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage32-state-"));
const targetPath = path.join(cwd, "security-target.js");
fs.writeFileSync(targetPath, "export const endpoint = \"local\";\n", "utf8");
let daemon = null;

try {
  daemon = await startRuntimeDaemonService({ cwd, stateDir });
  const workflowGraphId = "workflow.react-flow.engine-guard-security-scan";
  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove Engine Guard blocks merge when a plaintext secret is introduced.",
      options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
    }),
  });
  await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mode`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "runtime.thread-mode.yolo.security-scan",
      mode: "yolo",
      approvalMode: "never_prompt",
    }),
  });

  const secretLine = "export const API_KEY = \"sk-stage32-do-not-print\";";
  const secretPatch = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "workflow.engine-guard.security.file.apply_patch.secret",
      toolCallId: "coding_tool_engine_guard_secret_patch",
      toolPack: { coding: { diagnosticsMode: "skip" } },
      input: {
        path: "security-target.js",
        oldText: "export const endpoint = \"local\";",
        newText: `export const endpoint = \"local\";\n${secretLine}`,
      },
    }),
  });
  assert.equal(secretPatch.status, "completed");
  assert.equal(secretPatch.result.applied, true);

  const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
  const secretPanel = buildWorkflowEngineGuardSecurityScanPanel({
    events,
    files: [
      {
        path: "security-target.js",
        content: fs.readFileSync(targetPath, "utf8"),
        scope: "active_file",
        sourceEventId: secretPatch.event.event_id,
        receiptRefs: secretPatch.receipt_refs,
        rollbackRefs: secretPatch.rollback_refs,
      },
    ],
  });
  assert.equal(secretPanel.status, "blocked");
  assert.equal(secretPanel.findingCount, 1);
  assert.equal(secretPanel.criticalCount, 1);
  assert.equal(secretPanel.mergeActionDisabled, true);
  assert.equal(secretPanel.secretValuesIncluded, false);
  assert.equal(JSON.stringify(secretPanel).includes("sk-stage32-do-not-print"), false);
  assert.match(secretPanel.findings[0].redactedPreview, /\[REDACTED\]/);

  const repairPatch = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "workflow.engine-guard.security.file.apply_patch.repair",
      toolCallId: "coding_tool_engine_guard_secret_repair",
      toolPack: { coding: { diagnosticsMode: "skip" } },
      input: {
        path: "security-target.js",
        oldText: `\n${secretLine}`,
        newText: "",
      },
    }),
  });
  assert.equal(repairPatch.status, "completed");
  assert.equal(repairPatch.result.applied, true);

  const cleanEvents = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
  const cleanPanel = buildWorkflowEngineGuardSecurityScanPanel({
    events: cleanEvents,
    files: [
      {
        path: "security-target.js",
        content: fs.readFileSync(targetPath, "utf8"),
        scope: "active_file",
        sourceEventId: repairPatch.event.event_id,
        receiptRefs: repairPatch.receipt_refs,
        rollbackRefs: repairPatch.rollback_refs,
      },
    ],
  });
  assert.equal(cleanPanel.status, "passed");
  assert.equal(cleanPanel.findingCount, 0);
  assert.equal(cleanPanel.mergeActionDisabled, false);
  assert.equal(fs.readFileSync(targetPath, "utf8"), "export const endpoint = \"local\";\n");

  const proof = {
    schemaVersion: "ioi.autopilot.stage32.engine-guard-security-scan-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    threadId: thread.thread_id,
    workflowGraphId,
    secretPatchEventId: secretPatch.event.event_id,
    secretPatchReceiptRefs: secretPatch.receipt_refs,
    secretPatchRollbackRefs: secretPatch.rollback_refs,
    repairPatchEventId: repairPatch.event.event_id,
    checks: {
      plaintextSecretBlocked: secretPanel.status === "blocked",
      mergeActionDisabled: secretPanel.mergeActionDisabled === true,
      findingRedacted: secretPanel.secretValuesIncluded === false,
      noSecretInPanel: JSON.stringify(secretPanel).includes("sk-stage32-do-not-print") === false,
      rollbackRefLinked: secretPanel.rollbackRefs.includes(secretPatch.rollback_refs[0]),
      repairClearsFinding: cleanPanel.status === "passed" && cleanPanel.findingCount === 0,
      fileRepaired: fs.readFileSync(targetPath, "utf8") === "export const endpoint = \"local\";\n",
    },
    panels: {
      blocked: secretPanel,
      clean: cleanPanel,
    },
  };
  assert.equal(JSON.stringify(proof).includes("sk-stage32-do-not-print"), false);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  if (daemon) await daemon.close();
}
