// Ported JS-daemon workflow-edit control module → Rust hypervisor-daemon.
//
// Origin: packages/runtime-daemon/src/runtime-workflow-edit-api.mjs
// (proposeWorkflowEdit / applyWorkflowEditProposal). The Rust daemon now serves
//   POST /v1/threads/:id/workflow-edit-proposals                       (propose)
//   POST /v1/threads/:id/workflow-edit-proposals/:proposal_id/apply    (apply)
// wiring the CANONICAL kernel RuntimeWorkflowEditControlCore::plan and admitting the
// planned runtime event (idempotently) onto the thread's event log. This re-homes the
// workflow-edit EVENT-CONTROL coverage onto the Rust true-north.
//
// Scope: the event-control module (plan + admit the workflow.edit_proposed /
// workflow.edit.apply events + idempotent replay). The richer approval-GATED mutation
// orchestration (waiting_for_approval → approval decision → file mutation / blocked /
// completed, from the live-contract test's React-Flow flow) is a higher layer and remains
// a follow-on cut.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

let daemon;
let stateDir;

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-wfe-"));
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

test("Rust workflow-edit-proposals propose plans + admits a workflow.edit_proposed event", async () => {
  const threadId = await createThread();
  const r = await post(`${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals`, {
    workflow_graph_id: "workflow.react-flow.edit-proposal-proof",
    workflow_node_id: "runtime.workflow-edit-proposal.model",
    workflow_path: "proposal-proof.workflow.json",
    proposal_id: "proposal-a",
    workflow_patch: { version: "1", metadata: { name: "Proposed edit" } },
  });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.event_kind, "workflow.edit_proposed");
  assert.equal(r.body.status, "pending_approval");
  assert.equal(r.body.component_kind, "workflow_edit");
  assert.equal(r.body.payload.proposal_id, "proposal-a");
  assert.equal(r.body.payload.workflow_patch_present, true);
  assert.ok(typeof r.body.seq === "number");
});

test("Rust workflow-edit apply plans + admits a workflow.edit.apply event (idempotent on replay)", async () => {
  const threadId = await createThread();
  await post(`${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals`, {
    proposal_id: "proposal-a",
    workflow_patch: { version: "1" },
  });

  const applyUrl = `${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals/proposal-a/apply`;
  const first = await post(applyUrl, { workflow_graph_id: "wf.g", approval_id: "appr-a" });
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.equal(first.body.event_kind, "workflow.edit.apply");
  assert.equal(first.body.status, "applied");
  assert.equal(first.body.payload.proposal_id, "proposal-a");

  // Re-apply with the same logical request → admission is idempotent (same event_id).
  const replay = await post(applyUrl, { workflow_graph_id: "wf.g", approval_id: "appr-a" });
  assert.equal(replay.status, 200);
  assert.equal(replay.body.event_id, first.body.event_id, "idempotent replay returns the prior event");
});

test("Rust workflow-edit events land on the thread event stream", async () => {
  const threadId = await createThread();
  await post(`${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals`, {
    proposal_id: "proposal-stream",
    workflow_patch: { version: "1" },
  });
  await post(`${daemon.endpoint}/v1/threads/${threadId}/workflow-edit-proposals/proposal-stream/apply`, {
    approval_id: "appr-stream",
  });
  const events = await (
    await fetch(`${daemon.endpoint}/v1/threads/${threadId}/events`, { headers: { accept: "text/event-stream" } })
  ).text();
  assert.ok(events.includes("workflow.edit_proposed"), "proposed event is on the stream");
  assert.ok(events.includes("workflow.edit.apply"), "apply event is on the stream");
});

test("Rust workflow-edit fails closed for an unknown thread (404)", async () => {
  const r = await post(`${daemon.endpoint}/v1/threads/thread_missing/workflow-edit-proposals`, {
    proposal_id: "p",
  });
  assert.equal(r.status, 404);
});
