import assert from "node:assert/strict";
import test from "node:test";
import { diagnosticsRepairActionsForEvents } from "./workflow-runtime-diagnostics-repair-actions";
import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";

function event(
  id: string,
  seq: number,
  overrides: Partial<WorkflowRuntimeThreadEventLike> = {},
): WorkflowRuntimeThreadEventLike {
  return {
    id,
    cursor: `events_thread:test:${seq}`,
    seq,
    threadId: "thread-test",
    turnId: "turn-test",
    type: "policy_blocked",
    eventKind: "policy.blocked",
    sourceEventKind: "LspDiagnostics.BlockingGate",
    status: "blocked",
    createdAt: `2026-05-12T00:00:0${seq}.000Z`,
    componentKind: "lsp_diagnostics_gate",
    workflowNodeId: "runtime.lsp-diagnostics.blocking-gate",
    workflowGraphId: "workflow-test",
    payloadSchemaVersion: "ioi.runtime.lsp-diagnostics-blocking-gate.v1",
    receiptRefs: ["receipt-gate"],
    artifactRefs: [],
    policyDecisionRefs: ["policy-canonical-event"],
    rollbackRefs: ["rollback-canonical-event"],
    payload: {},
    ...overrides,
  };
}

test("diagnostics repair actions ignore retired camelCase repair aliases", () => {
  const diagnosticsGate = event("event-diagnostics-gate", 1, {
    payload: {
      repair_policy: {
        decisionRefs: ["policy-retired"],
        policyId: "policy-retired-id",
        restoreConflictPolicy: "allow_override",
        threadId: "thread-retired-policy",
        rollbackRefs: ["rollback-retired-policy"],
        workspaceSnapshotRefs: ["snapshot-retired-policy"],
        decisions: [
          {
            decisionId: "decision-retired",
            action: "restore_apply",
            status: "available",
            restoreConflictPolicy: "allow_override",
            requiresApproval: true,
            allowConflicts: true,
            overrideConflicts: true,
            workflowNodeId: "node-retired",
            threadId: "thread-retired-decision",
            workflowGraphId: "graph-retired",
            rollbackRefs: ["rollback-retired-decision"],
            workspaceSnapshotRefs: ["snapshot-retired-decision"],
          },
        ],
      },
    },
  });

  const actions = diagnosticsRepairActionsForEvents(
    [diagnosticsGate],
    diagnosticsGate,
  );

  assert.equal(actions.length, 1);
  assert.deepEqual(actions[0], {
    id: "diagnostics-repair:thread-test:restore_apply:restore_apply",
    decisionId: "restore_apply",
    action: "restore_apply",
    label: "Apply restore",
    summary: null,
    status: "available",
    executable: true,
    requiresApproval: false,
    approvalGranted: true,
    allowConflicts: false,
    restoreConflictPolicy: null,
    threadId: "thread-test",
    workflowGraphId: "workflow-test",
    workflowNodeId: "runtime.run-inspector.diagnostics-repair.restore-apply",
    eventId: "event-diagnostics-gate",
    rollbackRefs: ["rollback-canonical-event"],
    workspaceSnapshotRefs: [],
    policyDecisionRefs: ["policy-canonical-event"],
    receiptRefs: ["receipt-gate"],
  });
});

test("diagnostics repair action containers ignore retired camelCase aliases", () => {
  const diagnosticsGate = event("event-diagnostics-gate", 1, {
    payload: {
      diagnosticsRepairPolicy: {
        decisions: [
          {
            action: "repair_retry",
            status: "available",
          },
        ],
      },
      diagnosticsRepairContext: {
        repairPolicy: {
          decisions: [
            {
              action: "restore_preview",
              status: "available",
            },
          ],
        },
      },
      repairDecisions: [
        {
          action: "restore_apply",
          status: "available",
        },
      ],
    },
  });

  assert.deepEqual(
    diagnosticsRepairActionsForEvents([diagnosticsGate], diagnosticsGate),
    [],
  );
});
