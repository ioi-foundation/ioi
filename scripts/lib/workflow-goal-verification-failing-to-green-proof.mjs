#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-goal-verification-failing-to-green-proof.mjs <output-path>");
}

const { buildWorkflowRuntimeGoalVerificationPanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-runtime-goal-verification-panel.ts"
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

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage14-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage14-state-"));
const targetPath = path.join(cwd, "goal-target.mjs");
fs.writeFileSync(targetPath, "export const goal = 1;\n", "utf8");

const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const workflowGraphId = "workflow.react-flow.goal-verification-failing-to-green";
  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove goal verification blocks completion on diagnostics, then allows completion after repair.",
      options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
    }),
  });
  const mode = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mode`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "runtime.thread-mode.yolo.goal-verification",
      mode: "yolo",
      approvalMode: "never_prompt",
    }),
  });
  assert.equal(mode.mode, "yolo");
  assert.equal(mode.approval_mode, "never_prompt");

  const toolEndpoint = `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`;
  const brokenPatch = await fetchJson(toolEndpoint, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "workflow.goal-verification.file.apply-patch.break",
      toolCallId: "coding_tool_goal_verification_break",
      toolPack: {
        coding: {
          diagnosticsMode: "advisory",
          defaultDiagnosticCommandId: "node.check",
          restorePolicy: "preview_only",
          restoreConflictPolicy: "require_approval",
          diagnosticsRepairDefault: "repair_retry",
        },
      },
      input: {
        path: "goal-target.mjs",
        oldText: "export const goal = 1;",
        newText: "export const goal = ;",
      },
    }),
  });
  assert.equal(brokenPatch.status, "completed");
  assert.equal(brokenPatch.auto_diagnostics?.result.diagnosticStatus, "findings");
  assert.equal(brokenPatch.auto_diagnostics?.result.diagnosticCount, 1);
  assert.equal(fs.readFileSync(targetPath, "utf8"), "export const goal = ;\n");

  const blockedTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      message: "Continue only if goal verification passes.",
      diagnosticsMode: "blocking",
      options: { model: { id: "auto", routeId: "route.native-local" } },
    }),
  });
  assert.equal(blockedTurn.status, "waiting_for_input");
  assert.equal(blockedTurn.completed_at, null);
  assert.equal(blockedTurn.stop_reason, "blocked_by_post_edit_diagnostics");

  const blockedTrace = await fetchJson(`${daemon.endpoint}/v1/runs/${blockedTurn.request_id}/trace`);
  assert.equal(blockedTrace.diagnosticsFeedback?.mode, "blocking");
  assert.equal(blockedTrace.diagnosticsFeedback?.diagnosticStatus, "findings");
  assert.equal(blockedTrace.diagnosticsBlockingGate?.status, "blocked");
  assert.equal(blockedTrace.runtimeChecklist?.blockedItemCount, 1);

  const blockedEvents = await fetchSseEvents(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
  );
  const blockedPanel = buildWorkflowRuntimeGoalVerificationPanel(blockedEvents, {
    threadId: thread.thread_id,
    workflowGraphId,
  });
  assert.equal(blockedPanel.status, "blocked");
  assert.equal(blockedPanel.latestDiagnosticStatus, "findings");
  assert.ok(blockedPanel.rows.some((row) => row.rowKind === "diagnostics_gate" && row.status === "blocked"));

  const repairPatch = await fetchJson(toolEndpoint, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "workflow.goal-verification.file.apply-patch.repair-to-green",
      toolCallId: "coding_tool_goal_verification_repair_to_green",
      toolPack: {
        coding: {
          diagnosticsMode: "advisory",
          defaultDiagnosticCommandId: "node.check",
          restorePolicy: "preview_only",
          diagnosticsRepairDefault: "repair_retry",
        },
      },
      input: {
        path: "goal-target.mjs",
        oldText: "export const goal = ;",
        newText: "export const goal = 2;",
      },
    }),
  });
  assert.equal(repairPatch.status, "completed");
  assert.equal(repairPatch.auto_diagnostics?.result.diagnosticStatus, "clean");
  assert.equal(repairPatch.auto_diagnostics?.result.diagnosticCount, 0);
  assert.equal(fs.readFileSync(targetPath, "utf8"), "export const goal = 2;\n");

  const completedTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      message: "Continue after repair-to-green goal verification.",
      diagnosticsMode: "blocking",
      options: { model: { id: "auto", routeId: "route.native-local" } },
    }),
  });
  assert.equal(completedTurn.status, "completed");
  assert.ok(completedTurn.completed_at);

  const finalEvents = await fetchSseEvents(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
  );
  const finalPanel = buildWorkflowRuntimeGoalVerificationPanel(finalEvents, {
    threadId: thread.thread_id,
    workflowGraphId,
  });
  assert.equal(finalPanel.status, "passed");
  assert.equal(finalPanel.latestDiagnosticStatus, "clean");
  assert.ok(finalPanel.rows.some((row) => row.rowKind === "diagnostics_gate" && row.status === "blocked"));
  assert.ok(finalPanel.rows.some((row) => row.rowKind === "repair_action" && row.status === "passed"));
  assert.ok(finalPanel.rows.some((row) => row.rowKind === "completion" && row.status === "passed"));

  const proof = {
    schemaVersion: "ioi.autopilot.stage14.goal-verification-failing-to-green-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    threadId: thread.thread_id,
    workflowGraphId,
    brokenPatchEventId: brokenPatch.event.event_id,
    brokenDiagnosticsEventId: brokenPatch.auto_diagnostics?.event.event_id,
    blockedTurnId: blockedTurn.turn_id,
    blockedRunId: blockedTurn.request_id,
    repairPatchEventId: repairPatch.event.event_id,
    cleanDiagnosticsEventId: repairPatch.auto_diagnostics?.event.event_id,
    completedTurnId: completedTurn.turn_id,
    completedRunId: completedTurn.request_id,
    checks: {
      brokenDiagnosticsFound: brokenPatch.auto_diagnostics?.result.diagnosticStatus === "findings",
      blockedCompletion: blockedTurn.status === "waiting_for_input",
      blockedChecklistVisible: blockedTrace.runtimeChecklist?.blockedItemCount === 1,
      panelShowsBlocked: blockedPanel.status === "blocked",
      repairDiagnosticsClean: repairPatch.auto_diagnostics?.result.diagnosticStatus === "clean",
      finalCompletionAllowed: completedTurn.status === "completed",
      panelShowsPassed: finalPanel.status === "passed",
      fileRepaired: fs.readFileSync(targetPath, "utf8") === "export const goal = 2;\n",
    },
    panels: {
      blocked: blockedPanel,
      final: finalPanel,
    },
  };
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  await daemon.close();
}
