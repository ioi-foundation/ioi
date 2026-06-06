import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createDiagnosticsFeedbackHelpers } from "./diagnostics-feedback.mjs";
import { createDiagnosticsRepairPolicyHelpers } from "./diagnostics-repair-policy.mjs";

function normalizeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

function optionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function uniqueStrings(values) {
  return [...new Set(normalizeArray(values).filter(Boolean).map(String))];
}

function doctorHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function helpers() {
  const policy = createDiagnosticsRepairPolicyHelpers({
    doctorHash,
    normalizeArray,
    normalizeBooleanOption: (value, fallback) => {
      if (value === true || value === "true" || value === "1" || value === 1) return true;
      if (value === false || value === "false" || value === "0" || value === 0) return false;
      return fallback;
    },
    optionalString,
    uniqueStrings,
  });

  return createDiagnosticsFeedbackHelpers({
    diagnosticsRepairContextForPayload: policy.diagnosticsRepairContextForPayload,
    diagnosticsRepairPolicyConfig: policy.diagnosticsRepairPolicyConfig,
    diagnosticsRepairPolicyConfigForContexts: policy.diagnosticsRepairPolicyConfigForContexts,
    diagnosticsRollbackRepairPolicy: policy.diagnosticsRollbackRepairPolicy,
    doctorHash,
    eventStreamIdForThread: (threadId) => `events_${threadId}`,
    maxInjectedFindings: 2,
    maxInjectedMessageChars: 24,
    normalizeArray,
    normalizeDiagnosticsMode: policy.normalizeDiagnosticsMode,
    optionalString,
    uniqueStrings,
  });
}

test("post-edit diagnostics config normalizes command and repair policy aliases", () => {
  const runtime = helpers();

  const config = runtime.postEditDiagnosticsConfig({
    diagnostics_mode: "fail",
    diagnostic_command_id: "npm.test",
    tool_pack: {
      coding: {
        restore_policy: "preview",
        conflict_policy: "approval",
        default_repair_decision: "apply",
        operator_override_requires_approval: "false",
        timeout_ms: 1500,
      },
    },
  }, {
    cwd: "packages/runtime-daemon",
    diagnostic_max_output_bytes: 2048,
  });

  assert.equal(config.mode, "blocking");
  assert.equal(config.commandId, "npm.test");
  assert.equal(config.cwd, "packages/runtime-daemon");
  assert.equal(config.timeoutMs, 1500);
  assert.equal(config.maxOutputBytes, 2048);
  assert.equal(config.repairPolicyConfig.restorePolicy, "preview_only");
  assert.equal(config.repairPolicyConfig.restoreConflictPolicy, "require_approval");
  assert.equal(config.repairPolicyConfig.diagnosticsRepairDefault, "restore_apply");
  assert.equal(config.repairPolicyConfig.operatorOverrideRequiresApproval, false);
});

test("compact diagnostics feedback preserves public aliases and bounded prompt context", () => {
  const runtime = helpers();
  const feedback = runtime.compactDiagnosticsFeedback({
    threadId: "thread-one",
    mode: "blocking",
    diagnosticEvents: [
      {
        event_id: "event-one",
        receipt_refs: ["receipt-one"],
        rollback_refs: ["rollback-one"],
        payload_summary: {
          result: {
            diagnosticStatus: "findings",
            diagnostics: [
              { path: "src/a.js", line: 4, column: 2, severity: "error", code: "E1", message: "first diagnostic message is long" },
              { path: "src/b.js", line: 8, severity: "warning", message: "second diagnostic" },
              { path: "src/c.js", line: 9, severity: "info", message: "third diagnostic" },
            ],
          },
          diagnostics_repair_context: {
            source_tool_call_id: "tool-call-one",
            workspace_snapshot_id: "snapshot-one",
            restore_policy: "preview",
            restore_conflict_policy: "approval",
            default_repair_decision: "restore_preview",
          },
        },
      },
    ],
  });

  assert.equal(feedback.object, "ioi.runtime_lsp_diagnostics_injection");
  assert.equal(feedback.blocking, true);
  assert.equal(feedback.diagnosticStatus, "findings");
  assert.equal(feedback.diagnosticCount, 3);
  assert.equal(feedback.injectedFindingCount, 2);
  assert.equal(feedback.omittedFindingCount, 1);
  assert.deepEqual(feedback.diagnosticEventIds, ["event-one"]);
  assert.deepEqual(feedback.receiptRefs, ["receipt-one"]);
  assert.deepEqual(feedback.rollbackRefs, ["rollback-one", "snapshot-one"]);
  assert.deepEqual(feedback.workspaceSnapshotRefs, ["rollback-one", "snapshot-one"]);
  assert.deepEqual(feedback.sourceToolCallIds, ["tool-call-one"]);
  assert.equal(feedback.findings[0].message, "first diagnostic message");
  assert.match(feedback.promptText, /Post-edit diagnostics \(blocking, findings\)/);
  assert.match(feedback.promptText, /1 additional finding/);
  assert.equal(feedback.repairPolicy.restorePolicy, "preview_only");
  assert.equal(feedback.repairPolicy.diagnosticsRepairDefault, "restore_preview");
});

test("blocking gate and request feedback preserve repair policy refs", () => {
  const runtime = helpers();
  const diagnosticsFeedback = runtime.compactDiagnosticsFeedback({
    threadId: "thread-one",
    mode: "blocking",
    diagnosticEvents: [
      {
        event_id: "event-one",
        payload_summary: {
          result: {
            diagnosticStatus: "findings",
            diagnostics: [{ path: "src/a.js", line: 1, severity: "error", message: "broken" }],
          },
          diagnostics_repair_context: {
            workspace_snapshot_id: "snapshot-one",
            rollback_refs: ["snapshot-one"],
          },
        },
      },
    ],
  });

  const gate = runtime.diagnosticsBlockingGateForFeedback(diagnosticsFeedback);
  assert.equal(gate.object, "ioi.runtime_lsp_diagnostics_blocking_gate");
  assert.equal(gate.status, "blocked");
  assert.equal(gate.reason, "post_edit_diagnostics_findings");
  assert.equal(gate.requiresInput, true);
  assert.equal(gate.workflowNodeId, "runtime.lsp-diagnostics.blocking-gate");
  assert.deepEqual(gate.rollbackRefs, ["snapshot-one"]);
  assert.deepEqual(gate.workspaceSnapshotRefs, ["snapshot-one"]);
  assert.ok(gate.policyDecisionRefs.includes(gate.repairPolicy.policyId));
  assert.ok(gate.recommendedNextActions.includes("repair_retry"));
  assert.equal(runtime.diagnosticsBlockingGateForFeedback({ blocking: false }), null);

  const request = runtime.requestWithDiagnosticsFeedback({ prompt: "fix it", context: { source: "test" } }, diagnosticsFeedback);
  assert.equal(request.diagnosticsFeedback, diagnosticsFeedback);
  assert.equal(request.diagnostics_feedback, diagnosticsFeedback);
  assert.equal(request.context.diagnosticsFeedback, diagnosticsFeedback);
  assert.equal(request.context.source, "test");

  assert.match(
    runtime.promptWithDiagnosticsFeedback("fix it", diagnosticsFeedback),
    /User request:\nfix it/,
  );
});

test("repair retry and runtime bridge injection events keep public envelopes", () => {
  const runtime = helpers();
  const repairFeedback = runtime.diagnosticsRepairRetryFeedback({
    threadId: "thread-one",
    gateEvent: {
      event_id: "gate-one",
      payload_summary: {
        findings: [{ path: "src/a.js", line: 1, severity: "error", message: "broken" }],
        diagnostic_event_ids: ["event-one"],
        rollback_refs: ["rollback-one"],
        workspace_snapshot_refs: ["snapshot-one"],
        source_tool_call_ids: ["tool-call-one"],
        receipt_refs: ["receipt-one"],
      },
    },
    repairPolicy: {
      rollbackRefs: ["rollback-two"],
      workspaceSnapshotRefs: ["snapshot-two"],
    },
    snapshotId: "snapshot-three",
  });

  assert.equal(repairFeedback.object, "ioi.runtime_lsp_diagnostics_injection");
  assert.equal(repairFeedback.mode, "repair_retry");
  assert.equal(repairFeedback.blocking, false);
  assert.deepEqual(repairFeedback.rollbackRefs, ["snapshot-three", "rollback-one", "rollback-two"]);
  assert.deepEqual(repairFeedback.workspaceSnapshotRefs, ["snapshot-three", "snapshot-one", "snapshot-two"]);
  assert.deepEqual(repairFeedback.sourceToolCallIds, ["tool-call-one"]);
  assert.deepEqual(repairFeedback.receiptRefs, [repairFeedback.receiptId, "receipt-one"]);

  const events = runtime.insertRuntimeBridgeDiagnosticsInjectionEvent({
    projection: {
      runId: "run-one",
      turnId: "turn-one",
      createdAt: "2026-06-03T00:00:00.000Z",
      events: [
        { event_kind: "turn.started", id: "start" },
        { event_kind: "delta", id: "delta" },
      ],
    },
    agent: { cwd: "/workspace" },
    threadId: "thread-one",
    diagnosticsFeedback: repairFeedback,
  });

  assert.equal(events[0].event_kind, "turn.started");
  assert.equal(events[1].event_kind, "lsp.diagnostics.injected");
  assert.equal(events[1].source_event_kind, "LspDiagnostics.Injected");
  assert.equal(events[1].event_stream_id, "events_thread-one");
  assert.equal(events[1].payload.event_kind, "LspDiagnosticsInjected");
  assert.equal(events[1].payload.run_id, "run-one");
  assert.deepEqual(events[1].receipt_refs, [repairFeedback.receiptId]);
});
