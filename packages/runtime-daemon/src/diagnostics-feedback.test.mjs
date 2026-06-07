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

test("post-edit diagnostics config ignores retired request and input aliases", () => {
  const runtime = helpers();

  const config = runtime.postEditDiagnosticsConfig({
    diagnosticsMode: "fail",
    diagnosticCommandId: "alias.command",
    diagnosticTimeoutMs: 1,
    diagnosticMaxOutputBytes: 2,
    toolPack: {
      coding: {
        diagnosticsMode: "blocking",
        diagnosticMode: "fail",
        defaultDiagnosticCommandId: "alias.pack.command",
        timeoutMs: 3,
      },
    },
    options: {
      toolPack: {
        diagnosticsMode: "skip",
        defaultDiagnosticCommandId: "alias.options.command",
      },
    },
  }, {
    diagnosticsMode: "blocking",
    diagnosticCommandId: "alias.input.command",
    diagnosticTimeoutMs: 4,
    diagnosticMaxOutputBytes: 5,
  });

  assert.equal(config.mode, "advisory");
  assert.equal(config.commandId, "auto");
  assert.equal(config.timeoutMs, 30000);
  assert.equal(config.maxOutputBytes, 4096);
});

test("compact diagnostics feedback emits canonical envelope and bounded prompt context", () => {
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
            diagnostic_status: "findings",
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
  assert.equal(feedback.diagnostic_status, "findings");
  assert.equal(feedback.diagnostic_count, 3);
  assert.equal(feedback.injected_finding_count, 2);
  assert.equal(feedback.omitted_finding_count, 1);
  assert.deepEqual(feedback.diagnostic_event_ids, ["event-one"]);
  assert.deepEqual(feedback.receipt_refs, ["receipt-one"]);
  assert.deepEqual(feedback.rollback_refs, ["rollback-one", "snapshot-one"]);
  assert.deepEqual(feedback.workspace_snapshot_refs, ["rollback-one", "snapshot-one"]);
  assert.deepEqual(feedback.source_tool_call_ids, ["tool-call-one"]);
  assert.equal(feedback.findings[0].message, "first diagnostic message");
  assert.equal(feedback.findings[0].diagnostic_event_id, "event-one");
  assert.equal(Object.hasOwn(feedback.findings[0], "diagnosticEventId"), false);
  assert.match(feedback.prompt_text, /Post-edit diagnostics \(blocking, findings\)/);
  assert.match(feedback.prompt_text, /1 additional finding/);
  assert.equal(feedback.repair_policy.restorePolicy, "preview_only");
  assert.equal(feedback.repair_policy.diagnosticsRepairDefault, "restore_preview");
  for (const field of [
    "schemaVersion",
    "injectionId",
    "threadId",
    "diagnosticStatus",
    "diagnosticCount",
    "injectedFindingCount",
    "omittedFindingCount",
    "diagnosticEventIds",
    "receiptRefs",
    "rollbackRefs",
    "workspaceSnapshotRefs",
    "sourceToolCallIds",
    "diagnosticsRepairContexts",
    "repairPolicyConfig",
    "repairPolicy",
    "receiptId",
    "promptText",
  ]) {
    assert.equal(Object.hasOwn(feedback, field), false, `${field} alias must be absent`);
  }
});

test("compact diagnostics feedback ignores retired diagnostic result aliases", () => {
  const runtime = helpers();
  const feedback = runtime.compactDiagnosticsFeedback({
    threadId: "thread-one",
    mode: "blocking",
    diagnosticEvents: [
      {
        event_id: "event-one",
        payload_summary: {
          result: {
            diagnosticStatus: "findings",
            diagnostics: [{ path: "src/a.js", line: 4, severity: "error", message: "alias ignored" }],
          },
          result_summary: {
            diagnosticStatus: "findings",
          },
        },
      },
    ],
  });

  assert.equal(feedback.diagnostic_status, "clean");
  assert.equal(feedback.diagnostic_count, 1);
  assert.equal(feedback.blocking, true);
  assert.doesNotMatch(feedback.prompt_text, /findings/);
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
            diagnostic_status: "findings",
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
  assert.equal(gate.requires_input, true);
  assert.equal(gate.workflow_node_id, "runtime.lsp-diagnostics.blocking-gate");
  assert.deepEqual(gate.rollback_refs, ["snapshot-one"]);
  assert.deepEqual(gate.workspace_snapshot_refs, ["snapshot-one"]);
  assert.ok(gate.policy_decision_refs.includes(gate.repair_policy.policyId));
  assert.ok(gate.recommended_next_actions.includes("repair_retry"));
  assert.equal(runtime.diagnosticsBlockingGateForFeedback({ blocking: false }), null);
  for (const field of [
    "schemaVersion",
    "gateId",
    "policyDecisionId",
    "policyDecisionRefs",
    "receiptId",
    "requiresInput",
    "diagnosticStatus",
    "diagnosticCount",
    "injectedFindingCount",
    "omittedFindingCount",
    "injectionId",
    "diagnosticsReceiptId",
    "diagnosticEventIds",
    "rollbackRefs",
    "workspaceSnapshotRefs",
    "sourceToolCallIds",
    "repairPolicy",
    "repairDecisions",
    "recommendedNextActions",
    "workflowNodeId",
    "componentKind",
  ]) {
    assert.equal(Object.hasOwn(gate, field), false, `${field} alias must be absent`);
  }

  const request = runtime.requestWithDiagnosticsFeedback({ prompt: "fix it", context: { source: "test" } }, diagnosticsFeedback);
  assert.equal(request.diagnostics_feedback, diagnosticsFeedback);
  assert.equal(Object.hasOwn(request, "diagnosticsFeedback"), false);
  assert.equal(Object.hasOwn(request.context, "diagnosticsFeedback"), false);
  assert.equal(request.context.source, "test");

  assert.match(
    runtime.promptWithDiagnosticsFeedback("fix it", diagnosticsFeedback),
    /User request:\nfix it/,
  );
});

test("repair retry and runtime bridge injection events use canonical envelopes", () => {
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
      rollback_refs: ["rollback-two"],
      workspace_snapshot_refs: ["snapshot-two"],
    },
    snapshotId: "snapshot-three",
  });

  assert.equal(repairFeedback.object, "ioi.runtime_lsp_diagnostics_injection");
  assert.equal(repairFeedback.mode, "repair_retry");
  assert.equal(repairFeedback.blocking, false);
  assert.deepEqual(repairFeedback.rollback_refs, ["snapshot-three", "rollback-one", "rollback-two"]);
  assert.deepEqual(repairFeedback.workspace_snapshot_refs, ["snapshot-three", "snapshot-one", "snapshot-two"]);
  assert.deepEqual(repairFeedback.source_tool_call_ids, ["tool-call-one"]);
  assert.deepEqual(repairFeedback.receipt_refs, [repairFeedback.receipt_id, "receipt-one"]);

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
  assert.deepEqual(events[1].receipt_refs, [repairFeedback.receipt_id]);
  assert.equal(events[1].idempotency_key.includes(repairFeedback.injection_id), true);
});

test("repair retry feedback ignores retired request, payload, and policy aliases", () => {
  const runtime = helpers();
  const repairFeedback = runtime.diagnosticsRepairRetryFeedback({
    threadId: "thread-one",
    request: {
      repairRetryReceiptId: "receipt-alias",
      repairPromptText: "alias prompt",
    },
    gateEvent: {
      event_id: "gate-one",
      payload_summary: {
        findings: [{ path: "src/a.js", line: 1, severity: "error", message: "broken" }],
        diagnosticStatus: "clean",
        diagnosticCount: 9,
        injectedFindingCount: 9,
        omittedFindingCount: 9,
        diagnosticEventIds: ["event-alias"],
        rollbackRefs: ["rollback-alias"],
        workspaceSnapshotRefs: ["snapshot-alias"],
        sourceToolCallIds: ["tool-call-alias"],
        receiptRefs: ["receipt-alias"],
      },
    },
    repairPolicy: {
      rollbackRefs: ["policy-rollback-alias"],
      workspaceSnapshotRefs: ["policy-snapshot-alias"],
    },
    snapshotId: null,
  });

  assert.notEqual(repairFeedback.receipt_id, "receipt-alias");
  assert.notEqual(repairFeedback.prompt_text, "alias prompt");
  assert.equal(repairFeedback.diagnostic_status, "findings");
  assert.equal(repairFeedback.diagnostic_count, 1);
  assert.equal(repairFeedback.injected_finding_count, 1);
  assert.equal(repairFeedback.omitted_finding_count, 0);
  assert.deepEqual(repairFeedback.diagnostic_event_ids, []);
  assert.deepEqual(repairFeedback.rollback_refs, []);
  assert.deepEqual(repairFeedback.workspace_snapshot_refs, []);
  assert.deepEqual(repairFeedback.source_tool_call_ids, []);
  assert.deepEqual(repairFeedback.receipt_refs, [repairFeedback.receipt_id]);
});
