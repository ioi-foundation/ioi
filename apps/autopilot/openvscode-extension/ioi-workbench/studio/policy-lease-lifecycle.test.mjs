import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);

const { createStudioPolicyLeaseLifecycle } = require("./policy-lease-lifecycle.js");

function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeReceiptRefs(...sources) {
  const refs = [];
  for (const source of sources) {
    if (!source) continue;
    refs.push(
      ...firstArray(source.receiptRefs),
      ...firstArray(source.receipt_refs),
      ...firstArray(source.receipts).map((receipt) => receipt?.id || receipt?.receipt_id),
    );
  }
  return [...new Set(refs.filter(Boolean))];
}

test("policy lease lifecycle fixture is workspace relative and materialized for dry-run proof", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "policy-lease-lifecycle-"));
  try {
    const lifecycle = createStudioPolicyLeaseLifecycle({
      normalizeReceiptRefs,
      now: () => 12345,
      processId: "test",
      cwd: () => root,
    });

    const fixture = lifecycle.studioPolicyLeaseLifecycleFixture({ path: root });

    assert.equal(fixture.fixtureId, "run-9ix-test");
    assert.equal(fixture.relativePath, ".tmp/agent-studio-policy-lease-lifecycle/run-9ix-test/lease.txt");
    assert.equal(fs.readFileSync(fixture.absolutePath, "utf8"), "lease before\n");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("policy lease tool body preserves daemon approval and dry-run envelope", () => {
  const lifecycle = createStudioPolicyLeaseLifecycle({ normalizeReceiptRefs });
  const body = lifecycle.studioPolicyLeaseToolBody({
    toolCallId: "tool-one",
    ttlMs: 60000,
    policyHash: "policy-hash",
    expectedReceiptRef: "receipt-expected",
    relativePath: ".tmp/lease.txt",
    idempotencyKey: "idem-one",
    approvalId: "approval-one",
  });

  assert.equal(body.source, "agent_studio_runtime_cockpit");
  assert.equal(body.workflowGraphId, "workflow.agent-studio.policy-lease-live-gui");
  assert.equal(body.workflowNodeId, "workflow.agent-studio.policy-lease.file-apply-patch");
  assert.equal(body.requiresApproval, true);
  assert.equal(body.approvalMode, "human_required");
  assert.equal(body.toolPack.coding.nodeApprovalOverride, "require_approval");
  assert.deepEqual(body.expectedReceiptRefs, ["receipt-expected"]);
  assert.deepEqual(body.input, {
    path: ".tmp/lease.txt",
    oldText: "lease before",
    newText: "lease after",
    dryRun: true,
  });
  assert.equal(body.approvalId, "approval-one");
});

test("policy lease lifecycle rows cover allow once, revoke, and expiry outcomes", () => {
  const lifecycle = createStudioPolicyLeaseLifecycle({ normalizeReceiptRefs });
  const rows = lifecycle.studioPolicyLeaseLifecycleRows({
    blocked: { receiptRefs: ["receipt-blocked"] },
    approved: { receiptRefs: ["receipt-approved"] },
    executed: { status: "completed", receiptRefs: ["receipt-executed"] },
    revoked: { receiptRefs: ["receipt-revoked"] },
    blockedAfterRevoke: { status: "blocked", receiptRefs: ["receipt-after-revoke"] },
    expiryBlocked: { receiptRefs: ["receipt-expiry-blocked"] },
    expiryApproved: { receiptRefs: ["receipt-expiry-approved"] },
    expiryExecutedBefore: { status: "completed", receiptRefs: ["receipt-expiry-executed"] },
    expiryBlockedAfterExpiry: { status: "blocked", receiptRefs: ["receipt-after-expiry"] },
    ttlMs: 60000,
    expiryTtlMs: 1300,
  });

  assert.deepEqual(rows.map((row) => row.id), [
    "studio-policy-lease-pending",
    "studio-policy-lease-allow-once",
    "studio-policy-lease-revoked",
    "studio-policy-lease-expired",
  ]);
  assert.equal(rows[1].didExecute, true);
  assert.equal(rows[2].afterRevokeBlocked, true);
  assert.equal(rows[3].executedBeforeExpiry, true);
  assert.equal(rows[3].afterExpiryBlocked, true);
  assert.deepEqual(rows[3].receiptRefs, [
    "receipt-expiry-blocked",
    "receipt-expiry-approved",
    "receipt-expiry-executed",
    "receipt-after-expiry",
  ]);
});

test("request and deny policy lease preserves daemon envelopes and projection flags", async () => {
  const requests = [];
  const receipts = [];
  const timeline = [];
  const projection = {
    policyLeases: [],
    runtimeCockpit: {},
  };
  const lifecycle = createStudioPolicyLeaseLifecycle({
    STUDIO_POLICY_LEASE_ID: "approval-policy-one",
    appendStudioReceiptsFromResponse: (...args) => receipts.push(args),
    appendStudioTimeline: (...args) => timeline.push(args),
    daemonEndpoint: () => "http://daemon.local",
    daemonRequestToken: () => "token-one",
    getStudioRuntimeProjection: () => projection,
    normalizeReceiptRefs,
    requestJson: async (endpoint, route, options) => {
      requests.push({ endpoint, route, options });
      return route.endsWith("/decision")
        ? { receiptRefs: ["receipt-decision"] }
        : { receiptRefs: ["receipt-approval"] };
    },
    studioApprovalTurnPayload: () => ({
      turn_id: "turn-one",
      workflowGraphId: "graph-one",
    }),
  });
  const output = { lines: [], appendLine(line) { this.lines.push(line); } };

  await lifecycle.requestAndDenyStudioPolicyLease("thread-one", output);

  assert.equal(requests.length, 2);
  assert.equal(requests[0].endpoint, "http://daemon.local");
  assert.equal(requests[0].route, "/v1/threads/thread-one/approvals");
  assert.equal(requests[0].options.token, "token-one");
  assert.equal(requests[0].options.payload.approval_id, "approval-policy-one");
  assert.equal(requests[0].options.payload.turn_id, "turn-one");
  assert.equal(requests[1].route, "/v1/threads/thread-one/approvals/approval-policy-one/decision");
  assert.equal(requests[1].options.payload.decision, "reject");
  assert.deepEqual(projection.policyLeases[0], {
    id: "approval-policy-one",
    title: "Permission denied",
    status: "denied",
    action: "shell.exec.destructive",
    reason: "Agent asked to run an elevated action; permission was denied and the action did not run.",
    didExecute: false,
    receiptRefs: ["receipt-approval", "receipt-decision"],
  });
  assert.equal(projection.runtimeCockpit.policyLeaseDialogObserved, true);
  assert.equal(projection.runtimeCockpit.policyDeniedActionDidNotExecute, true);
  assert.equal(receipts.length, 2);
  assert.deepEqual(timeline[0], ["Policy lease denied", "approval-policy-one", "blocked"]);
  assert.match(output.lines[0], /policy lease denied/);
});
