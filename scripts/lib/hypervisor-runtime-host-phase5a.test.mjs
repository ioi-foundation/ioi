// Phase 5A gate — the Rust daemon hosts the CANONICAL RuntimeAgentService for
// LIFECYCLE ops (start@v1 + post_message@v1) over a file-backed StateAccess, with
// the event-log bridge wired into /events. Proves the load-bearing Lane B bridge
// WITHOUT driving browser/shell/model tools or mutating the workspace.
//
//   POST /v1/hypervisor/runtime-host/sessions { session_ref, goal, message }
//     - start@v1 + post_message@v1 run against a real StateAccess (state persists)
//     - session→thread linkage is written (agents/<id>.json runtime_session_id)
//     - a host RuntimeThreadEvent is emitted on the wired bridge → admitted to
//       /v1/threads/:id/events
//     - host invariants: gui noop, browser lazy/uninitialized, terminal idle,
//       model NOT invoked, workspace NOT mutated.
//
// Fully offline/deterministic (no Ollama, no harness, no container).

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

let daemon;
let stateDir;

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-5a-state-"));
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

async function pollThreadEventsFor(threadId, needle, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  let lastBody = "";
  while (Date.now() < deadline) {
    const response = await fetch(`${daemon.endpoint}/v1/threads/${encodeURIComponent(threadId)}/events`, {
      headers: { accept: "text/event-stream" },
    });
    lastBody = await response.text();
    if (lastBody.includes(needle)) return lastBody;
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  return lastBody;
}

test("Phase 5A: the daemon hosts start@v1 + post_message@v1 with real state writes + honest no-op drivers", async () => {
  const response = await fetch(`${daemon.endpoint}/v1/hypervisor/runtime-host/sessions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_ref: "session:phase5a-host",
      goal: "exercise the runtime-host lifecycle",
      message: "hello from the Phase 5A host",
    }),
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.schema_version, "ioi.hypervisor.runtime_host_session.v1");
  assert.equal(body.lifecycle, "hosted");
  assert.deepEqual(body.ops, ["start@v1", "post_message@v1"]);

  // Real state writes (the canonical handlers persisted agent state via StateAccess).
  assert.ok(body.state_keys_written > 0, `state keys written: ${body.state_keys_written}`);
  const hostStateDir = path.join(stateDir, "runtime-host-state");
  assert.ok(fs.existsSync(hostStateDir) && fs.readdirSync(hostStateDir).length > 0, "state persisted to disk");

  // Phase 5A invariants: the canonical service is hosted but drives NOTHING.
  assert.equal(body.host.service, "RuntimeAgentService");
  assert.equal(body.host.gui, "noop");
  assert.equal(body.host.browser, "lazy_uninitialized");
  assert.equal(body.host.terminal, "idle");
  assert.equal(body.host.model_invoked, false);
  assert.equal(body.host.workspace_mutated, false);
  assert.equal(body.host.tool_execution_invoked, false);

  // No workspace mutation: the session workspace is real but empty.
  assert.ok(fs.existsSync(body.workspace_path), "workspace path exists");
  assert.equal(fs.readdirSync(body.workspace_path).length, 0, "workspace was not mutated");

  // session → thread linkage written (the bridge resolves the event target from this).
  const agentRecord = JSON.parse(fs.readFileSync(path.join(stateDir, "agents", `${body.agent_id}.json`), "utf8"));
  assert.equal(agentRecord.runtime_session_id, body.runtime_session_id);
  assert.equal(agentRecord.thread_id, body.thread_id);

  // The host RuntimeThreadEvent was admitted to /events via the wired bridge.
  const events = await pollThreadEventsFor(body.thread_id, "runtime_host.session.started");
  assert.match(events, /runtime_host\.session\.started/, "the host lifecycle event reached /events via the bridge");
});

test("Phase 5A: start@v1 alone (no message) still hosts + persists + links", async () => {
  const response = await fetch(`${daemon.endpoint}/v1/hypervisor/runtime-host/sessions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ session_ref: "session:phase5a-startonly", goal: "start only" }),
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(body.ops, ["start@v1"]);
  assert.ok(body.state_keys_written > 0);
  assert.equal(body.host.model_invoked, false);
  const events = await pollThreadEventsFor(body.thread_id, "runtime_host.session.started");
  assert.match(events, /runtime_host\.session\.started/);
});
