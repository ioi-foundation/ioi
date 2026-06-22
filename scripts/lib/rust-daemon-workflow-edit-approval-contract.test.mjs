// Ported JS-daemon React-Flow workflow-edit approval-gated mutation flow → Rust hypervisor-daemon.
//
// Origin: scripts/lib/live-runtime-daemon-contract.test.mjs ("React Flow workflow edit proposals
// are daemon-gated and replayable"). The Rust daemon now gates the workflow-edit apply on a
// recorded proposal-approval decision (a lighter, proposal-scoped authority surface, distinct
// from the wallet-signed run/agent approval grant):
//   propose                              -> waiting_for_approval (+ approval_id, no mutation)
//   apply WITHOUT a decision             -> blocked (approval_required, no mutation)
//   approvals/:id/reject  then apply     -> blocked (reason: approval_rejected, no mutation)
//   approvals/:id/approve then apply     -> completed (mutation_executed, file mutated, event admitted)
//   re-apply                             -> completed (idempotent_replay, same event_id, no re-mutation)
//
// Faithful-port note: the canonical kernel apply event is `workflow.edit.apply` (component_kind
// `workflow_edit`); the JS contract's `workflow.edit_applied` naming is a client-side mapping.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

let daemon;
let stateDir;
let workspaceDir;
let workflowPath;

const initialWorkflow = {
  version: "1",
  metadata: { id: "workflow.react-flow.edit-proposal-proof", name: "Proposal proof" },
  nodes: [{ id: "model", type: "model_call", name: "Model" }],
  edges: [],
};

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-wfe-appr-state-"));
  workspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-wfe-appr-ws-"));
  workflowPath = path.join(workspaceDir, "proposal-proof.workflow.json");
  fs.writeFileSync(workflowPath, `${JSON.stringify(initialWorkflow, null, 2)}\n`);
  daemon = await startRustHypervisorDaemon({ stateDir });
});

afterEach(async () => {
  await daemon?.close();
  for (const dir of [stateDir, workspaceDir]) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // best effort
    }
  }
});

async function post(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  return { status: response.status, body: await response.json() };
}

async function createThread() {
  const r = await post(`${daemon.endpoint}/v1/threads`, { options: { local: { cwd: workspaceDir } } });
  assert.equal(r.status, 200);
  return r.body.thread_id || r.body.id;
}

function workflowName() {
  return JSON.parse(fs.readFileSync(workflowPath, "utf8")).metadata.name;
}

async function propose(threadId, proposalId, name) {
  return post(`${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals`, {
    source: "react_flow",
    workflow_graph_id: initialWorkflow.metadata.id,
    workflow_node_id: "runtime.workflow-edit-proposal.model",
    proposal_id: proposalId,
    workflow_path: workflowPath,
    workflow_patch: { ...initialWorkflow, metadata: { ...initialWorkflow.metadata, name } },
  });
}

test("Rust workflow-edit rejected proposal stays blocked and never mutates the file", async () => {
  const threadId = await createThread();
  const proposed = await propose(threadId, "proposal-rejected", "Rejected edit");
  assert.equal(proposed.body.status, "waiting_for_approval");
  const approvalId = proposed.body.approval_id;

  // Apply before any decision is recorded -> blocked, even with client-asserted approval flags.
  const directApply = await post(
    `${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals/proposal-rejected/apply`,
    { approved: true, approvalGranted: true, approvalMode: "never_prompt" },
  );
  assert.equal(directApply.body.status, "blocked");
  assert.equal(directApply.body.mutation_executed, false);
  assert.equal(workflowName(), "Proposal proof");

  // Reject the proposal, then apply -> blocked with reason approval_rejected, still no mutation.
  const rejected = await post(`${daemon.endpoint}/v1/threads/${threadId}/approvals/${approvalId}/reject`, {
    reason: "Reject the proposal to prove no workflow mutation occurs.",
  });
  assert.equal(rejected.body.decision, "reject");
  const rejectedApply = await post(
    `${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals/proposal-rejected/apply`,
    { approvalId },
  );
  assert.equal(rejectedApply.body.status, "blocked");
  assert.equal(rejectedApply.body.reason, "approval_rejected");
  assert.equal(rejectedApply.body.mutation_executed, false);
  assert.equal(workflowName(), "Proposal proof");
});

test("Rust workflow-edit approved proposal mutates the file and replays idempotently", async () => {
  const threadId = await createThread();
  const proposed = await propose(threadId, "proposal-approved", "Approved edit");
  assert.equal(proposed.body.status, "waiting_for_approval");
  const approvalId = proposed.body.approval_id;

  const approved = await post(`${daemon.endpoint}/v1/threads/${threadId}/approvals/${approvalId}/approve`, {
    reason: "Approve bounded workflow metadata edit.",
  });
  assert.equal(approved.body.decision, "approve");
  assert.equal(workflowName(), "Proposal proof", "approval alone does not mutate");

  const applyUrl = `${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals/proposal-approved/apply`;
  const applied = await post(applyUrl, { approvalId });
  assert.equal(applied.body.status, "completed");
  assert.equal(applied.body.mutation_executed, true);
  assert.equal(applied.body.idempotent_replay, false);
  assert.equal(applied.body.event.event_kind, "workflow.edit.apply");
  assert.equal(workflowName(), "Approved edit", "apply mutates the workflow file");

  // Re-apply -> idempotent replay (same admitted event, no re-mutation).
  const replay = await post(applyUrl, { approvalId });
  assert.equal(replay.body.status, "completed");
  assert.equal(replay.body.idempotent_replay, true);
  assert.equal(replay.body.event.event_id, applied.body.event.event_id);
  assert.equal(workflowName(), "Approved edit");

  // Both lifecycle events are on the thread stream.
  const events = await (
    await fetch(`${daemon.endpoint}/v1/threads/${threadId}/events`, { headers: { accept: "text/event-stream" } })
  ).text();
  assert.ok(events.includes("workflow.edit_proposed"));
  assert.ok(events.includes("workflow.edit.apply"));
});

test("Rust workflow-edit apply fails closed for an unknown thread (404)", async () => {
  const r = await post(
    `${daemon.endpoint}/v1/threads/thread_missing/workflow-edit-proposals/proposal-x/apply`,
    { approvalId: "approval_x" },
  );
  assert.equal(r.status, 404);
});