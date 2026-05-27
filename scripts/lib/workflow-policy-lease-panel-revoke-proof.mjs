#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-policy-lease-panel-revoke-proof.mjs <output-path>");
}

const { buildWorkflowRuntimePolicyLeasePanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-runtime-policy-lease-panel.ts"
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

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage13-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage13-state-"));
const targetPath = path.join(cwd, "lease.txt");
fs.writeFileSync(targetPath, "lease before\n", "utf8");

const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const workflowGraphId = "workflow.react-flow.policy-lease-panel-revoke";
  const workflowNodeId = "workflow.policy-lease.file.apply-patch";
  const toolCallId = "coding_tool_policy_lease_revoke_probe";
  const expectedReceiptRef = "receipt_policy_lease_expected";
  const policyHash = "policy_hash_policy_lease_revoke_proof";
  const ttlMs = 60_000;
  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove approval policy leases surface in Agent Studio and revoke blocks later execution.",
      options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
    }),
  });
  const mode = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mode`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "runtime.thread-mode.yolo.policy-lease",
      mode: "yolo",
      approvalMode: "never_prompt",
    }),
  });
  assert.equal(mode.mode, "yolo");
  assert.equal(mode.approval_mode, "never_prompt");

  const baseBody = {
    source: "react_flow",
    workflowGraphId,
    workflowNodeId,
    toolCallId,
    ttlMs,
    policyHash,
    expectedReceiptRefs: [expectedReceiptRef],
    requiresApproval: true,
    approvalMode: "human_required",
    nodeApprovalOverride: "require_approval",
    trustProfile: "review_required",
    toolPack: {
      coding: {
        requiresApproval: true,
        approvalMode: "human_required",
        nodeApprovalOverride: "require_approval",
        trustProfile: "review_required",
      },
    },
    input: {
      path: "lease.txt",
      oldText: "lease before",
      newText: "lease after",
      dryRun: true,
    },
  };
  const toolEndpoint = `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`;
  const blocked = await fetchJson(toolEndpoint, {
    method: "POST",
    body: JSON.stringify({
      ...baseBody,
      idempotencyKey: "policy-lease-proof-blocked-attempt",
    }),
  });
  assert.equal(blocked.status, "blocked");
  assert.equal(blocked.approval_required, true);
  assert.equal(fs.readFileSync(targetPath, "utf8"), "lease before\n");

  const approvalEventsBeforeDecision = await fetchSseEvents(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
  );
  const approvalRequiredEvent = approvalEventsBeforeDecision.find(
    (event) => event.event_id === blocked.approval_event_id,
  );
  assert.ok(approvalRequiredEvent);
  assert.equal(approvalRequiredEvent.event_kind, "approval.required");
  assert.equal(approvalRequiredEvent.payload_summary.policy_hash, policyHash);
  assert.equal(approvalRequiredEvent.payload_summary.ttl_ms, ttlMs);
  assert.deepEqual(approvalRequiredEvent.payload_summary.expected_receipt_refs, [expectedReceiptRef]);
  assert.match(approvalRequiredEvent.payload_summary.revoke_endpoint, /\/approvals\/.+\/revoke$/);

  const pendingPanel = buildWorkflowRuntimePolicyLeasePanel(approvalEventsBeforeDecision, {
    threadId: thread.thread_id,
    workflowGraphId,
  });
  const pendingRow = pendingPanel.rows.find((row) => row.approvalId === blocked.approval_id);
  assert.ok(pendingRow);
  assert.equal(pendingRow.status, "pending");
  assert.equal(pendingRow.revokable, true);
  assert.equal(pendingRow.executable, false);

  const approved = await fetchJson(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/approvals/${blocked.approval_id}/approve`,
    {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        workflowGraphId,
        workflowNodeId,
        reason: "Approve policy lease proof execution.",
      }),
    },
  );
  assert.equal(approved.decision, "approve");
  assert.equal(approved.lease_status, "active");

  const executed = await fetchJson(toolEndpoint, {
    method: "POST",
    body: JSON.stringify({
      ...baseBody,
      idempotencyKey: "policy-lease-proof-approved-execution",
      approvalId: blocked.approval_id,
    }),
  });
  assert.equal(executed.status, "completed");
  assert.equal(executed.event.payload_summary.approval_satisfied, true);
  assert.equal(executed.event.payload_summary.approval_id, blocked.approval_id);
  assert.equal(fs.readFileSync(targetPath, "utf8"), "lease before\n");

  const activeEvents = await fetchSseEvents(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
  );
  const activePanel = buildWorkflowRuntimePolicyLeasePanel(activeEvents, {
    threadId: thread.thread_id,
    workflowGraphId,
  });
  const activeRow = activePanel.rows.find((row) => row.approvalId === blocked.approval_id);
  assert.ok(activeRow);
  assert.equal(activeRow.status, "active");
  assert.equal(activeRow.executable, true);
  assert.equal(activeRow.policyHash, policyHash);
  assert.equal(activeRow.ttlMs, ttlMs);
  assert.deepEqual(activeRow.expectedReceiptRefs, [expectedReceiptRef]);

  const revoked = await fetchJson(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/approvals/${blocked.approval_id}/revoke`,
    {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        workflowGraphId,
        workflowNodeId,
        reason: "Revoke lease after one approved dry-run execution.",
      }),
    },
  );
  assert.equal(revoked.decision, "revoke");
  assert.equal(revoked.lease_status, "revoked");

  const blockedAfterRevoke = await fetchJson(toolEndpoint, {
    method: "POST",
    body: JSON.stringify({
      ...baseBody,
      idempotencyKey: "policy-lease-proof-after-revoke",
      approvalId: blocked.approval_id,
    }),
  });
  assert.equal(blockedAfterRevoke.status, "blocked");
  assert.equal(blockedAfterRevoke.error?.code, "coding_tool_approval_required");
  assert.equal(fs.readFileSync(targetPath, "utf8"), "lease before\n");

  const finalEvents = await fetchSseEvents(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
  );
  const revokeEvent = finalEvents.find((event) => event.event_id === revoked.event_id);
  assert.ok(revokeEvent);
  assert.equal(revokeEvent.event_kind, "approval.revoked");
  assert.equal(revokeEvent.payload_summary.lease_status, "revoked");
  assert.equal(revokeEvent.payload_summary.policy_hash, policyHash);
  assert.equal(revokeEvent.payload_summary.approval_decision_event_id, approved.event_id);

  const finalPanel = buildWorkflowRuntimePolicyLeasePanel(finalEvents, {
    threadId: thread.thread_id,
    workflowGraphId,
  });
  const finalRow = finalPanel.rows.find((row) => row.approvalId === blocked.approval_id);
  assert.ok(finalRow);
  assert.equal(finalRow.status, "revoked");
  assert.equal(finalRow.revokable, false);
  assert.equal(finalRow.executable, false);
  assert.equal(finalRow.requestEventId, approvalRequiredEvent.event_id);
  assert.equal(finalRow.decisionEventId, approved.event_id);
  assert.equal(finalRow.revokeEventId, revoked.event_id);
  assert.equal(finalRow.policyHash, policyHash);
  assert.equal(finalRow.ttlMs, ttlMs);
  assert.deepEqual(finalRow.expectedReceiptRefs, [expectedReceiptRef]);
  assert.match(finalRow.revokeEndpoint ?? "", /\/approvals\/.+\/revoke$/);
  assert.equal(finalPanel.revokedCount, 1);
  assert.equal(finalPanel.activeCount, 0);

  const proof = {
    schemaVersion: "ioi.autopilot.stage13.policy-lease-panel-revoke-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    threadId: thread.thread_id,
    workflowGraphId,
    workflowNodeId,
    toolCallId,
    approvalId: blocked.approval_id,
    leaseId: finalRow.leaseId,
    events: {
      approvalRequiredEventId: approvalRequiredEvent.event_id,
      approvalApprovedEventId: approved.event_id,
      toolExecutedEventId: executed.event.event_id,
      approvalRevokedEventId: revoked.event_id,
    },
    checks: {
      pendingPanelVisible: pendingRow.status === "pending",
      activePanelVisible: activeRow.status === "active",
      revokeEndpointVisible: Boolean(finalRow.revokeEndpoint),
      revokeInvalidatesExecution: blockedAfterRevoke.status === "blocked",
      dryRunDidNotMutateFile: fs.readFileSync(targetPath, "utf8") === "lease before\n",
      policyHashPreserved: finalRow.policyHash === policyHash,
      ttlPreserved: finalRow.ttlMs === ttlMs,
      expectedReceiptRefsPreserved: finalRow.expectedReceiptRefs.includes(expectedReceiptRef),
    },
    panels: {
      pending: pendingPanel,
      active: activePanel,
      final: finalPanel,
    },
  };
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  await daemon.close();
}
