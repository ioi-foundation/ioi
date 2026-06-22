// Ported agent-sdk computer-use native-browser behavioral loop → Rust hypervisor-daemon.
//
// Origin: packages/agent-sdk/test/computer-use.test.mjs ("runtime daemon invokes native browser
// loop through thread tool spine"). The Rust daemon's thread tool-invoke route
// (/v1/threads/:id/tools/ioi.computer_use.native_browser/invoke) now drives the DETERMINISTIC,
// read-only 11-event computer-use behavioral loop on top of the canonical kernel lease building
// block (build_computer_use_lease_request — lane/session-mode/authority-scope/provider
// resolution), emits the 11 computer_use.* runtime events onto the thread stream, and shapes
// the agent-sdk thread-tool result.
//
// Faithful-port note: NO real Chromium. The probe is a deterministic read-only inspection —
// the policy approves it (approved_for_read_only_probe, fail_closed=false) and the commit gate
// is not required. The agent-sdk contract's event sequence + cross-references are asserted
// against what the Rust daemon ACTUALLY emits.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

const expectedComputerUseEventKinds = [
  "computer_use.environment_selected",
  "computer_use.lease_acquired",
  "computer_use.run_state",
  "computer_use.observation",
  "computer_use.affordance_graph",
  "computer_use.action_proposed",
  "computer_use.action_executed",
  "computer_use.verification",
  "computer_use.commit_gate",
  "computer_use.trajectory_written",
  "computer_use.cleanup",
];

let daemon;
let stateDir;

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-cu-nb-"));
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
    body: JSON.stringify(body ?? {}),
  });
  return { status: response.status, body: await response.json() };
}

async function createThread() {
  const r = await post(`${daemon.endpoint}/v1/threads`, { options: { local: { cwd: stateDir } } });
  assert.equal(r.status, 200);
  return r.body.thread_id || r.body.id;
}

async function readComputerUseEvents(threadId) {
  const text = await (
    await fetch(`${daemon.endpoint}/v1/threads/${threadId}/events`, { headers: { accept: "text/event-stream" } })
  ).text();
  const events = [];
  for (const line of text.split("\n")) {
    if (!line.startsWith("data:")) continue;
    let event;
    try {
      event = JSON.parse(line.slice(5).trim());
    } catch {
      continue;
    }
    if (typeof event.event_kind === "string" && event.event_kind.startsWith("computer_use.")) {
      events.push(event);
    }
  }
  return events;
}

test("Rust ioi.computer_use.native_browser drives the deterministic 11-event read-only loop", async () => {
  const threadId = await createThread();
  const r = await post(`${daemon.endpoint}/v1/threads/${threadId}/tools/ioi.computer_use.native_browser/invoke`, {
    source: "react_flow",
    workflowGraphId: "workflow.native-browser-tool",
    workflowNodeId: "native-browser-tool",
    input: {
      prompt: "Inspect https://example.com without external side effects.",
      url: "https://example.com",
      observationRetentionMode: "prompt_visible_summary_only",
    },
  });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const result = r.body;
  assert.equal(result.status, "completed");
  assert.equal(result.object, "ioi.runtime_computer_use_native_browser_result");
  assert.equal(result.tool_pack, "computer_use");
  assert.equal(result.tool_name, "ioi.computer_use.native_browser");
  assert.equal(result.workflow_graph_id, "workflow.native-browser-tool");
  assert.equal(result.workflow_node_id, "native-browser-tool");
  assert.equal(result.event_count, expectedComputerUseEventKinds.length);

  // Result projection fields (mirror the agent-sdk native-browser contract).
  assert.equal(result.result.environmentSelection.selected_lane, "native_browser");
  assert.equal(result.result.lease.lane, "native_browser");
  assert.equal(result.result.lease.authority_scope, "computer_use.native_browser.read");
  assert.equal(result.result.observation.retention_mode, "prompt_visible_summary_only");
  assert.equal(result.result.action.action_kind, "inspect");
  assert.equal(result.result.policyDecision.outcome, "approved_for_read_only_probe");
  assert.equal(result.result.policyDecision.fail_closed, false);
  assert.equal(result.result.actionReceipt.status, "completed");
  assert.equal(result.result.commitGate.status, "not_required");

  // The 11-event behavioral loop landed on the thread stream, in canonical order.
  const events = await readComputerUseEvents(threadId);
  assert.deepEqual(
    events.map((event) => event.event_kind),
    expectedComputerUseEventKinds,
  );

  const selected = events[0];
  assert.equal(selected.component_kind, "computer_use_harness");
  assert.equal(selected.workflow_graph_id, "workflow.native-browser-tool");
  assert.equal(selected.workflow_node_id, "native-browser-tool");
  assert.equal(selected.payload.tool_ref, "ioi.computer_use.native_browser");
  assert.equal(selected.payload.computer_use_lane, "native_browser");
  assert.equal(selected.payload.computer_use_contract_ingest, "native_browser_cdp");

  // Cross-references the agent-sdk contract enforces.
  const proposed = events[5];
  assert.equal(proposed.event_kind, "computer_use.action_proposed");
  assert.equal(proposed.payload.action_proposal.target_ref, result.result.action.target_ref);
  assert.equal(proposed.payload.policy_decision_receipt.outcome, "approved_for_read_only_probe");
  assert.equal(
    proposed.payload.policy_decision_receipt.policy_decision_ref,
    proposed.payload.action_proposal.policy_decision_ref,
  );
  const executed = events[6];
  assert.equal(executed.event_kind, "computer_use.action_executed");
  assert.equal(executed.payload.action_receipt.status, "completed");
});

test("Rust ioi.computer_use.native_browser fails closed for an unknown thread (404)", async () => {
  const r = await post(
    `${daemon.endpoint}/v1/threads/thread_missing/tools/ioi.computer_use.native_browser/invoke`,
    { input: { url: "https://example.com" } },
  );
  assert.equal(r.status, 404);
});
