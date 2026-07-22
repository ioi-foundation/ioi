// Ported JS-daemon workflow-edit control module → Rust hypervisor-daemon.
//
// Origin: packages/runtime-daemon/src/runtime-workflow-edit-api.mjs
// (proposeWorkflowEdit / applyWorkflowEditProposal). The Rust daemon now serves
//   POST /v1/threads/:id/workflow-edit-proposals                       (propose)
//   POST /v1/threads/:id/workflow-edit-proposals/:proposal_id/apply    (apply)
// wiring the CANONICAL kernel RuntimeWorkflowEditControlCore::plan and admitting the
// planned runtime event onto the thread's event log. This re-homes the workflow-edit
// EVENT-CONTROL coverage onto the Rust true-north.
//
// Scope: the propose event-control + the approval GATE (propose -> waiting_for_approval +
// admitted workflow.edit_proposed event; apply WITHOUT an approval decision -> blocked, no
// mutation). The full approve/reject -> file-mutation / idempotent-replay flow lives in
// rust-daemon-workflow-edit-approval-contract.test.mjs.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

let daemon;
let stateDir;
let workflowPath;

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-wfe-"));
  workflowPath = path.join(stateDir, "proposal-proof.workflow.json");
  fs.writeFileSync(workflowPath, '{"version":"0"}\n');
  daemon = await startRustHypervisorDaemon({ stateDir });
});

afterEach(async () => {
  await daemon?.close();
  try {
    fs.rmSync(stateDir, { recursive: true, force: true });
  } catch {
    // best effort
  }
});

async function post(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

async function createThread() {
  const r = await post(`${daemon.endpoint}/v1/threads`, { options: { local: { cwd: stateDir } } });
  assert.equal(r.status, 200);
  return r.body.thread_id || r.body.id;
}

test("Rust workflow-edit-proposals propose waits for approval + admits a workflow.edit_proposed event", async () => {
  const threadId = await createThread();
  const r = await post(`${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals`, {
    workflow_graph_id: "workflow.react-flow.edit-proposal-proof",
    workflow_node_id: "runtime.workflow-edit-proposal.model",
    workflow_path: workflowPath,
    proposal_id: "proposal-a",
    workflow_patch: { version: "1", metadata: { name: "Proposed edit" } },
  });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.status, "waiting_for_approval");
  assert.equal(r.body.approval_required, true);
  assert.equal(r.body.mutation_executed, false);
  assert.ok(typeof r.body.approval_id === "string" && r.body.approval_id.length > 0);
  // The admitted workflow.edit_proposed event is embedded under `event`.
  assert.equal(r.body.event.event_kind, "workflow.edit_proposed");
  assert.equal(r.body.event.status, "pending_approval");
  assert.equal(r.body.event.component_kind, "workflow_edit");
  assert.equal(r.body.event.payload.proposal_id, "proposal-a");
  assert.equal(r.body.event.payload.workflow_patch_present, true);
  assert.ok(typeof r.body.event.seq === "number");
});

test("Rust workflow-edit apply is BLOCKED without an approval decision (no mutation)", async () => {
  const threadId = await createThread();
  await post(`${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals`, {
    proposal_id: "proposal-a",
    workflow_path: workflowPath,
    workflow_patch: { version: "1" },
  });

  // Client-asserted approval flags can never self-grant — only a recorded decision unblocks.
  const blocked = await post(
    `${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals/proposal-a/apply`,
    { approved: true, approvalGranted: true },
  );
  assert.equal(blocked.status, 200, JSON.stringify(blocked.body));
  assert.equal(blocked.body.status, "blocked");
  assert.equal(blocked.body.approval_required, true);
  assert.equal(blocked.body.mutation_executed, false);
});

test("Rust workflow-edit proposed event lands on the thread event stream", async () => {
  const threadId = await createThread();
  await post(`${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals`, {
    proposal_id: "proposal-stream",
    workflow_path: workflowPath,
    workflow_patch: { version: "1" },
  });
  const events = await (
    await fetch(`${daemon.endpoint}/v1/threads/${threadId}/events`, { headers: { accept: "text/event-stream" } })
  ).text();
  assert.ok(events.includes("workflow.edit_proposed"), "proposed event is on the stream");
});

test("Rust workflow-edit fails closed for an unknown thread (404)", async () => {
  const r = await post(`${daemon.endpoint}/v1/threads/thread_missing/workflow-edit-proposals`, {
    proposal_id: "p",
  });
  assert.equal(r.status, 404);
});
