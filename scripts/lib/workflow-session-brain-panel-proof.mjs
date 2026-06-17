#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";
import { bootstrapNativeRuntimeModelRoute } from "./hypervisor-runtime-agent-service-inference.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-session-brain-panel-proof.mjs <output-path>");
}

const { buildWorkflowSessionBrainPanel } = await import(
  "../../packages/hypervisor-workbench/src/runtime/workflow-session-brain-panel.ts"
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

async function fetchJsonAllowError(url, options) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  const body = await response.json().catch(() => ({}));
  return { ok: response.ok, status: response.status, body };
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

async function createDaemonModelInvocationToken(endpoint) {
  const response = await fetch(`${endpoint}/v1/model-mount/tokens`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      audience: "autopilot-session-brain-proof",
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
      source: "session-brain-proof",
    }),
  });
  const text = await response.text();
  assert.ok(response.ok, `${response.status} ${response.statusText} token request: ${text}`);
  const parsed = text ? JSON.parse(text) : {};
  assert.ok(parsed.token, `token response did not include token: ${text}`);
  return parsed;
}

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage22-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage22-state-"));
const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const modelToken = await createDaemonModelInvocationToken(daemon.endpoint);
  const runtimeModelRoute = await bootstrapNativeRuntimeModelRoute({
    repoRoot: path.resolve(new URL("../..", import.meta.url).pathname),
    daemonEndpoint: daemon.endpoint,
    token: modelToken.token,
    workspaceDir: path.join(cwd, ".ioi", "autopilot-runtime-fixtures"),
  });
  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove session brain artifacts are scoped, receipted, and audit locked after completion.",
      options: {
        local: { cwd },
        model: { id: "auto", routeId: runtimeModelRoute.routeId },
      },
    }),
  });

  const artifactWrites = [];
  for (const artifact of [
    {
      memoryKey: "implementation_plan",
      text: "# Implementation Plan\n\n- Prove the session brain panel over governed runtime memory.",
      workflowNodeId: "runtime.session-brain.implementation-plan",
    },
    {
      memoryKey: "task",
      text: "# Task\n\n- [x] Write plan\n- [x] Run proof\n- [x] Lock audit state",
      workflowNodeId: "runtime.session-brain.task",
    },
    {
      memoryKey: "walkthrough",
      text: "# Walkthrough\n\nSession brain artifacts were written through runtime memory and projected into Chat/Trace.",
      workflowNodeId: "runtime.session-brain.walkthrough",
    },
    {
      memoryKey: "scratch/eval-script",
      text: "Scratch note: tiny validation scripts belong outside the user workspace.",
      workflowNodeId: "runtime.session-brain.scratch",
    },
  ]) {
    artifactWrites.push(
      await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`, {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          text: artifact.text,
          memoryKey: artifact.memoryKey,
          scope: "thread",
          workflowGraphId: "workflow.react-flow.session-brain",
          workflowNodeId: artifact.workflowNodeId,
        }),
      }),
    );
  }

  const readOnlyPolicy = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory/policy`, {
    method: "PATCH",
    body: JSON.stringify({
      readOnly: true,
      retention: "persistent",
      source: "session_brain_completion_audit_lock",
    }),
  });
  assert.equal(readOnlyPolicy.policy.readOnly, true);

  const blockedWrite = await fetchJsonAllowError(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      text: "This late write should be blocked by the audit lock.",
      memoryKey: "walkthrough",
      scope: "thread",
    }),
  });
  const blockedWriteReason =
    blockedWrite.body?.details?.reason ??
    blockedWrite.body?.error?.details?.reason ??
    null;
  assert.equal(blockedWrite.ok, false);
  assert.equal(blockedWriteReason, "memory_read_only");

  const memoryProjection = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`);
  const memoryPath = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory/path`);
  const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
  const panel = buildWorkflowSessionBrainPanel({
    memoryProjection,
    memoryPath,
    events,
    completion: {
      completed: true,
      completedAt: new Date().toISOString(),
      receiptRefs: ["receipt_session_brain_completion_audit_lock"],
    },
  });

  assert.equal(panel.status, "ready");
  assert.equal(panel.threadId, thread.thread_id);
  assert.equal(panel.artifactCount, 4);
  assert.equal(panel.scratchCount, 1);
  assert.equal(panel.missingArtifactKinds.length, 0);
  assert.equal(panel.brainOutsideWorkspace, true);
  assert.equal(panel.readOnlyAuditMode, true);
  assert.ok(panel.rows.some((row) => row.artifactKind === "implementation_plan" && row.receiptRefs.length > 0));
  assert.ok(panel.rows.some((row) => row.artifactKind === "task" && row.artifactPath?.endsWith("/task.md")));
  assert.ok(panel.rows.some((row) => row.artifactKind === "walkthrough"));
  assert.ok(panel.rows.some((row) => row.artifactKind === "scratch" && row.artifactPath?.includes("/scratch/")));

  const proof = {
    schemaVersion: "ioi.autopilot.stage22.session-brain-panel-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    threadId: thread.thread_id,
    runtimeModelRoute: {
      modelId: runtimeModelRoute.modelId,
      endpointId: runtimeModelRoute.endpointId,
      routeId: runtimeModelRoute.routeId,
      providerId: runtimeModelRoute.providerId,
      backendId: runtimeModelRoute.backendId,
      runtimeEngine: runtimeModelRoute.runtimeEngine,
      fixtureFree: runtimeModelRoute.fixtureFree,
    },
    artifactWriteReceiptIds: artifactWrites.map((write) => write.receipt?.id).filter(Boolean),
    readOnlyPolicyReceiptId: readOnlyPolicy.receipt?.id ?? null,
    blockedWrite: {
      status: blockedWrite.status,
      reason: blockedWriteReason,
      code: blockedWrite.body?.error?.code ?? blockedWrite.body?.code ?? null,
    },
    checks: {
      allBrainArtifactsPresent: panel.artifactCount === 4 && panel.missingArtifactKinds.length === 0,
      scratchIsSeparateLane: panel.scratchCount === 1,
      brainRootOutsideWorkspace: panel.brainOutsideWorkspace,
      readOnlyAuditLockVisible: panel.readOnlyAuditMode,
      lateWriteBlocked: blockedWriteReason === "memory_read_only",
      receiptsLinkedToRows: panel.rows.every((row) => row.status === "missing" || row.receiptRefs.length > 0),
    },
    panel,
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  await daemon.close();
}
