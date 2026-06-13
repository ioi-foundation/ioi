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

function diagnosticsRepairPolicyProjector(overrides = {}) {
  const calls = [];
  return {
    calls,
    projectRuntimeDiagnosticsRepairPolicy(request) {
      calls.push(request);
      const policyId = `policy_${request.injection_id}`;
      const defaultDecision = overrides.default_decision ?? "restore_preview";
      return {
        source: "rust_runtime_diagnostics_repair_policy_command",
        operation_kind: "runtime.diagnostics_repair_policy.projection",
        thread_id: request.thread_id,
        injection_id: request.injection_id,
        repair_policy_config: {
          restore_policy: "preview_only",
          restore_conflict_policy: "require_approval",
          diagnostics_repair_default: defaultDecision,
          operator_override_requires_approval: true,
        },
        repair_policy: {
          schema_version: "ioi.runtime.diagnostics-rollback-repair-policy.v1",
          object: "ioi.runtime_diagnostics_rollback_repair_policy",
          policy_id: policyId,
          thread_id: request.thread_id,
          injection_id: request.injection_id,
          mode: request.mode,
          diagnostic_status: request.diagnostic_status,
          diagnostic_count: request.diagnostic_count,
          rollback_refs: request.rollback_refs,
          workspace_snapshot_refs: request.workspace_snapshot_refs,
          source_tool_call_ids: request.source_tool_call_ids,
          restore_policy: "preview_only",
          restore_conflict_policy: "require_approval",
          diagnostics_repair_default: defaultDecision,
          default_decision: defaultDecision,
          operator_override_requires_approval: true,
          decisions: [
            {
              decision_id: `${policyId}_decision_repair_retry`,
              action: "repair_retry",
              status: "available",
              requires_approval: false,
            },
            {
              decision_id: `${policyId}_decision_restore_preview`,
              action: "restore_preview",
              status: "available",
              requires_approval: false,
              rollback_refs: request.rollback_refs,
              workspace_snapshot_refs: request.workspace_snapshot_refs,
            },
          ],
          decision_refs: [
            `${policyId}_decision_repair_retry`,
            `${policyId}_decision_restore_preview`,
          ],
        },
        receipt_refs: [
          ...uniqueStrings(request.receipt_refs),
          "receipt_runtime_diagnostics_repair_policy_projection",
        ],
        evidence_refs: ["runtime_diagnostics_repair_policy_projection_rust_owned"],
        projection_hash: "sha256:policy_projection",
      };
    },
  };
}

test("compact diagnostics feedback fails closed without Rust repair policy projection", () => {
  const runtime = helpers();

  assert.throws(
    () =>
      runtime.compactDiagnosticsFeedback({
        threadId: "thread-one",
        mode: "blocking",
        diagnosticEvents: [
          {
            event_id: "event-one",
            payload_summary: {
              result: {
                diagnostic_status: "findings",
                diagnostics: [{ path: "src/a.js", message: "broken" }],
              },
            },
          },
        ],
      }),
    (error) => {
      assert.equal(error.code, "runtime_diagnostics_repair_policy_projection_required");
      assert.equal(error.details.rust_core_boundary, "runtime.diagnostics_repair_policy");
      return true;
    },
  );
});

test("compact diagnostics feedback emits canonical envelope and bounded prompt context", () => {
  const runtime = helpers();
  const policyProjector = diagnosticsRepairPolicyProjector();
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
            sourceToolCallId: "tool-call-retired",
            workspace_snapshot_id: "snapshot-one",
            workspaceSnapshotId: "snapshot-retired",
            rollback_refs: ["rollback-context-one"],
            rollbackRefs: ["rollback-retired"],
            restore_policy: "preview",
            restore_conflict_policy: "approval",
            default_repair_decision: "restore_preview",
          },
        },
      },
    ],
    diagnosticsRepairPolicyProjector: policyProjector,
  });

  assert.equal(feedback.object, "ioi.runtime_lsp_diagnostics_injection");
  assert.equal(feedback.blocking, true);
  assert.equal(feedback.diagnostic_status, "findings");
  assert.equal(feedback.diagnostic_count, 3);
  assert.equal(feedback.injected_finding_count, 2);
  assert.equal(feedback.omitted_finding_count, 1);
  assert.deepEqual(feedback.diagnostic_event_ids, ["event-one"]);
  assert.deepEqual(feedback.receipt_refs, [
    "receipt-one",
    "receipt_runtime_diagnostics_repair_policy_projection",
  ]);
  assert.deepEqual(feedback.rollback_refs, ["rollback-one", "rollback-context-one", "snapshot-one"]);
  assert.equal(feedback.rollback_refs.includes("rollback-retired"), false);
  assert.equal(feedback.rollback_refs.includes("snapshot-retired"), false);
  assert.deepEqual(feedback.workspace_snapshot_refs, ["rollback-one", "rollback-context-one", "snapshot-one"]);
  assert.equal(feedback.workspace_snapshot_refs.includes("rollback-retired"), false);
  assert.equal(feedback.workspace_snapshot_refs.includes("snapshot-retired"), false);
  assert.deepEqual(feedback.source_tool_call_ids, ["tool-call-one"]);
  assert.equal(feedback.source_tool_call_ids.includes("tool-call-retired"), false);
  assert.equal(feedback.findings[0].message, "first diagnostic message");
  assert.equal(feedback.findings[0].diagnostic_event_id, "event-one");
  assert.equal(Object.hasOwn(feedback.findings[0], "diagnosticEventId"), false);
  assert.match(feedback.prompt_text, /Post-edit diagnostics \(blocking, findings\)/);
  assert.match(feedback.prompt_text, /1 additional finding/);
  assert.equal(feedback.repair_policy.restore_policy, "preview_only");
  assert.equal(feedback.repair_policy.diagnostics_repair_default, "restore_preview");
  assert.equal(feedback.policy_projection_hash, "sha256:policy_projection");
  assert.deepEqual(policyProjector.calls[0].diagnostics_repair_contexts, feedback.diagnostics_repair_contexts);
  assert.equal(feedback.receipt_id, null);
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
    diagnosticsRepairPolicyProjector: diagnosticsRepairPolicyProjector(),
  });

  assert.equal(feedback.diagnostic_status, "clean");
  assert.equal(feedback.diagnostic_count, 1);
  assert.equal(feedback.blocking, true);
  assert.doesNotMatch(feedback.prompt_text, /findings/);
});

test("blocking gate and request feedback keep advisory repair actions without JS policy refs", () => {
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
    diagnosticsRepairPolicyProjector: diagnosticsRepairPolicyProjector(),
  });

  const gate = runtime.diagnosticsBlockingGateForFeedback(diagnosticsFeedback);
  assert.equal(gate.object, "ioi.runtime_lsp_diagnostics_blocking_gate");
  assert.equal(gate.status, "blocked");
  assert.equal(gate.reason, "post_edit_diagnostics_findings");
  assert.equal(gate.requires_input, true);
  assert.equal(gate.workflow_node_id, "runtime.lsp-diagnostics.blocking-gate");
  assert.deepEqual(gate.rollback_refs, ["snapshot-one"]);
  assert.deepEqual(gate.workspace_snapshot_refs, ["snapshot-one"]);
  assert.equal(gate.receipt_id, null);
  assert.equal(gate.policy_decision_id, null);
  assert.deepEqual(gate.policy_decision_refs, []);
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
  assert.equal(repairFeedback.receipt_id, null);
  assert.deepEqual(repairFeedback.receipt_refs, ["receipt-one"]);

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
  assert.deepEqual(events[1].receipt_refs, ["receipt-one"]);
  assert.equal(events[1].idempotency_key.includes(repairFeedback.injection_id), true);
});

test("diagnostics feedback does not synthesize JS receipt or policy refs", () => {
  const runtime = helpers();
  const feedback = runtime.compactDiagnosticsFeedback({
    threadId: "thread-one",
    mode: "blocking",
    diagnosticEvents: [
      {
        event_id: "event-one",
        receipt_refs: ["receipt-rust-diagnostics"],
        payload_summary: {
          result: {
            diagnostic_status: "findings",
            diagnostics: [{ path: "src/a.js", line: 1, severity: "error", message: "broken" }],
          },
        },
      },
    ],
    diagnosticsRepairPolicyProjector: diagnosticsRepairPolicyProjector(),
  });
  const gate = runtime.diagnosticsBlockingGateForFeedback(feedback);

  assert.equal(feedback.receipt_id, null);
  assert.deepEqual(feedback.receipt_refs, [
    "receipt-rust-diagnostics",
    "receipt_runtime_diagnostics_repair_policy_projection",
  ]);
  assert.equal(gate.receipt_id, null);
  assert.equal(gate.policy_decision_id, null);
  assert.deepEqual(gate.policy_decision_refs, []);
  assert.equal(JSON.stringify(feedback).includes("receipt_lsp_diagnostics"), false);
  assert.equal(JSON.stringify(gate).includes("receipt_lsp_diagnostics"), false);
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

  assert.equal(repairFeedback.receipt_id, null);
  assert.notEqual(repairFeedback.prompt_text, "alias prompt");
  assert.equal(repairFeedback.diagnostic_status, "findings");
  assert.equal(repairFeedback.diagnostic_count, 1);
  assert.equal(repairFeedback.injected_finding_count, 1);
  assert.equal(repairFeedback.omitted_finding_count, 0);
  assert.deepEqual(repairFeedback.diagnostic_event_ids, []);
  assert.deepEqual(repairFeedback.rollback_refs, []);
  assert.deepEqual(repairFeedback.workspace_snapshot_refs, []);
  assert.deepEqual(repairFeedback.source_tool_call_ids, []);
  assert.deepEqual(repairFeedback.receipt_refs, []);
});
