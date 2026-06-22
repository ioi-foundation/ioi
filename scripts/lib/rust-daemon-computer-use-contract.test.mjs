// Ported agent-sdk computer-use projection spine → Rust hypervisor-daemon.
//
// Origin: packages/agent-sdk/test/computer-use.test.mjs ("runtime daemon invokes browser
// discovery through thread tool spine"). The Rust daemon's thread tool-invoke route
// (/v1/threads/:id/tools/:name/invoke) now dispatches the ioi.computer_use.* projection
// tools through the CANONICAL kernel RuntimeComputerUseProjectionCore::project, emits the
// computer_use.<kind> runtime event, and shapes the agent-sdk thread-tool result.
//
// Scope: the DETERMINISTIC projection tools (browser_discovery over an empty process set;
// provider_registry). The Chromium-driven native_browser / visual_gui loops + the agent-sdk
// observation-artifact contract validation are a follow-on (they need the real BrowserDriver).

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

let daemon;
let stateDir;

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-cu-"));
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

test("Rust ioi.computer_use.browser_discovery dispatches through the thread tool spine", async () => {
  const threadId = await createThread();
  const r = await post(`${daemon.endpoint}/v1/threads/${threadId}/tools/ioi.computer_use.browser_discovery/invoke`, {
    source: "react_flow",
    workflowGraphId: "workflow.browser-discovery-tool",
    workflowNodeId: "browser-discovery-tool",
    input: { include_tabs: false, reveal_tab_titles: false, process_rows: [] },
  });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const result = r.body;
  assert.equal(result.status, "completed");
  assert.equal(result.object, "ioi.runtime_computer_use_browser_discovery_result");
  assert.equal(result.tool_pack, "computer_use");
  assert.equal(result.tool_name, "ioi.computer_use.browser_discovery");
  assert.equal(result.workflow_node_id, "browser-discovery-tool");
  assert.equal(result.event.event_kind, "computer_use.browser_discovery");
  assert.equal(result.event.component_kind, "computer_use_harness");
  assert.equal(result.result.object, "ioi.computer_use.browser_discovery_report");
  assert.equal(result.result.safety.read_only, true);

  // The runtime event landed on the thread stream.
  const events = await (
    await fetch(`${daemon.endpoint}/v1/threads/${threadId}/events`, { headers: { accept: "text/event-stream" } })
  ).text();
  assert.ok(events.includes("computer_use.browser_discovery"), "discovery event on the stream");
});

test("Rust ioi.computer_use.provider_registry projects the sandboxed-hosted provider registry", async () => {
  const threadId = await createThread();
  const r = await post(`${daemon.endpoint}/v1/threads/${threadId}/tools/ioi.computer_use.provider_registry/invoke`, {
    workflowNodeId: "provider-registry-tool",
    input: {},
  });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.status, "completed");
  assert.equal(r.body.object, "ioi.runtime_computer_use_provider_registry_result");
  assert.equal(r.body.tool_pack, "computer_use");
  const providers = r.body.result.providers || [];
  assert.ok(providers.length > 0, `provider registry is populated: ${JSON.stringify(r.body.result).slice(0, 200)}`);
});

test("Rust computer-use projection fails closed for an unknown thread (404)", async () => {
  const r = await post(`${daemon.endpoint}/v1/threads/thread_missing/tools/ioi.computer_use.browser_discovery/invoke`, {
    input: {},
  });
  assert.equal(r.status, 404);
});
