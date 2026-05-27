#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-hunk-decision-receipt-panel-proof.mjs <output-path>");
}

const { buildWorkflowHunkDecisionReceiptPanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-hunk-decision-receipt-panel.ts"
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

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage26-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage26-state-"));
const workflowPath = path.join(cwd, "workflow.json");
const originalWorkflow = {
  metadata: { name: "Hunk proposal proof", version: 1 },
  nodes: [{ id: "node-a", kind: "prompt" }],
};
const approvedWorkflow = {
  metadata: { name: "Approved hunk edit", version: 2 },
  nodes: [{ id: "node-a", kind: "prompt", status: "approved" }],
};
fs.writeFileSync(workflowPath, `${JSON.stringify(originalWorkflow, null, 2)}\n`, "utf8");

const codeDiff = [
  "diff --git a/workflow.json b/workflow.json",
  "--- a/workflow.json",
  "+++ b/workflow.json",
  "@@ -1,6 +1,6 @@",
  " {",
  "   \"metadata\": {",
  "-    \"name\": \"Hunk proposal proof\",",
  "+    \"name\": \"Approved hunk edit\",",
  "-    \"version\": 1",
  "+    \"version\": 2",
  "   },",
  "@@ -7,5 +7,6 @@",
  "   \"nodes\": [",
  "     {",
  "       \"id\": \"node-a\",",
  "-      \"kind\": \"prompt\"",
  "+      \"kind\": \"prompt\",",
  "+      \"status\": \"approved\"",
  "     }",
  "   ]",
].join("\n");

const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const workflowGraphId = "workflow.react-flow.hunk-decision-receipts";
  const workflowNodeId = "runtime.workflow-edit-proposal.hunk-decision-receipts";
  const proposalId = "proposal-inline-hunk-decision-receipts";
  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove inline diff hunk decisions are bound to daemon approvals and receipts.",
      options: {
        local: { cwd },
        model: { id: "auto", routeId: "route.native-local" },
      },
    }),
  });

  const proposal = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/workflow-edit-proposals`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      proposalId,
      title: "Approve exact inline diff hunks",
      summary: "Two hunks should appear in Chat/Trace with daemon approval and apply receipts.",
      workflowGraphId,
      workflowNodeId,
      targetWorkflowNodeIds: ["node.model-edit", "node.workflow-apply"],
      workflowPath: "workflow.json",
      workflowPatch: approvedWorkflow,
      codeDiff,
    }),
  });
  assert.equal(proposal.status, "waiting_for_approval");
  assert.equal(proposal.approval_required, true);
  assert.equal(proposal.mutation_executed, false);
  assert.deepEqual(JSON.parse(fs.readFileSync(workflowPath, "utf8")), originalWorkflow);

  const preApprovalApply = await fetchJson(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/workflow-edit-proposals/${proposalId}/apply`,
    {
      method: "POST",
      body: JSON.stringify({
        source: "agent_studio_inline_diff",
        workflowGraphId,
        workflowNodeId,
      }),
    },
  );
  assert.equal(preApprovalApply.status, "blocked");
  assert.equal(preApprovalApply.reason, "approval_decision_missing");
  assert.deepEqual(JSON.parse(fs.readFileSync(workflowPath, "utf8")), originalWorkflow);

  const approvalDecision = await fetchJson(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/approvals/${proposal.approval_id}/decision`,
    {
      method: "POST",
      body: JSON.stringify({
        source: "agent_studio_inline_diff",
        decision: "approve",
        reason: "Operator accepted the inline diff hunk preview from Agent Studio.",
        workflowGraphId,
        workflowNodeId,
      }),
    },
  );
  assert.equal(approvalDecision.decision, "approve");
  assert.ok(approvalDecision.receipt_refs.length > 0);

  const studioBridgeHunkDecision = {
    requestType: "chat.hunkDecision",
    payload: {
      decision: "approve",
      approvalId: proposal.approval_id,
      proposalId,
      threadId: thread.thread_id,
      turnId: null,
      hunkFile: "workflow.json",
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      ownsRuntimeState: false,
    },
    receiptRefs: approvalDecision.receipt_refs,
    policyDecisionRefs: approvalDecision.policy_decision_refs,
  };

  const applied = await fetchJson(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/workflow-edit-proposals/${proposalId}/apply`,
    {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        approvalId: proposal.approval_id,
        workflowGraphId,
        workflowNodeId,
      }),
    },
  );
  assert.equal(applied.status, "completed");
  assert.equal(applied.approval_satisfied, true);
  assert.equal(applied.mutation_executed, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(workflowPath, "utf8")), approvedWorkflow);

  const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
  const panel = buildWorkflowHunkDecisionReceiptPanel({
    events,
    hunkDecisions: [studioBridgeHunkDecision],
    applyResults: [preApprovalApply, applied],
  });

  assert.equal(panel.status, "ready");
  assert.equal(panel.hunkCount, 2);
  assert.equal(panel.appliedCount, 2);
  assert.equal(panel.missingDecisionReceiptCount, 0);
  assert.ok(panel.rows.every((row) => row.proposalId === proposalId));
  assert.ok(panel.rows.every((row) => row.approvalId === proposal.approval_id));
  assert.ok(panel.rows.every((row) => row.status === "applied"));
  assert.ok(panel.rows.every((row) => row.decision === "approve"));
  assert.ok(panel.rows.every((row) => row.filePath === "workflow.json"));
  assert.ok(panel.rows.every((row) => row.bridgeRequestType === "chat.hunkDecision"));
  assert.ok(panel.rows.every((row) => row.bridgeOwnsRuntimeState === false));
  assert.ok(panel.rows.every((row) => row.decisionReceiptRefs.length > 0));
  assert.ok(panel.rows.every((row) => row.applyReceiptRefs.length > 0));
  assert.ok(panel.rows.every((row) => row.approveEndpoint?.includes("/approvals/")));
  assert.ok(panel.rows.every((row) => row.applyEndpoint?.includes("/workflow-edit-proposals/")));
  assert.deepEqual(
    panel.rows.map((row) => [row.hunkIndex, row.addedLineCount, row.removedLineCount]),
    [
      [0, 2, 2],
      [1, 2, 1],
    ],
  );

  const proof = {
    schemaVersion: "ioi.autopilot.stage26.hunk-decision-receipt-panel-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    threadId: thread.thread_id,
    workflowGraphId,
    workflowNodeId,
    proposalId,
    approvalId: proposal.approval_id,
    proposalEventId: proposal.event_id,
    approvalDecisionEventId: approvalDecision.event_id,
    applyEventId: applied.event.event_id,
    checks: {
      unifiedDiffParsedIntoExactHunks: panel.hunkCount === 2,
      preApprovalApplyBlocked: preApprovalApply.status === "blocked" &&
        preApprovalApply.reason === "approval_decision_missing",
      studioBridgeDecisionIsProjectionOnly: panel.rows.every((row) => row.bridgeOwnsRuntimeState === false),
      decisionReceiptsLinkedToEveryHunk: panel.rows.every((row) => row.decisionReceiptRefs.length > 0),
      applyReceiptsLinkedToEveryHunk: panel.rows.every((row) => row.applyReceiptRefs.length > 0),
      daemonApprovalSatisfiedBeforeMutation: applied.approval_satisfied === true && applied.mutation_executed === true,
      workflowFileMutatedOnlyAfterApproval: JSON.parse(fs.readFileSync(workflowPath, "utf8")).metadata.name ===
        "Approved hunk edit",
      panelReady: panel.status === "ready",
    },
    receiptRefs: {
      proposal: proposal.receipt_refs,
      decision: approvalDecision.receipt_refs,
      apply: applied.event.receipt_refs,
    },
    blockedApply: {
      status: preApprovalApply.status,
      reason: preApprovalApply.reason,
      approvalId: preApprovalApply.approval_id,
    },
    panel,
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  await daemon.close();
}
