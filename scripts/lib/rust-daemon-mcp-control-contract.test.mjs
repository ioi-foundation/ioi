// Ported JS-daemon MCP control surface → Rust hypervisor-daemon.
//
// The Rust daemon serves the thread-scoped MCP control routes, wiring the CANONICAL kernel
// `plan_mcp_control_agent_state_update` (the MCP registry lives on the agent record):
//   POST /v1/threads/:id/mcp/import                         (import a server set)
//   POST /v1/threads/:id/mcp/servers                        (add one)
//   POST /v1/threads/:id/mcp/servers/:server_id/enable      (enable)
//   POST /v1/threads/:id/mcp/servers/:server_id/disable     (disable)
//   POST /v1/threads/:id/mcp/status                         (project the registry)
//   POST /v1/threads/:id/mcp/validate                       (validate)
// This re-homes the deterministic MCP-control coverage from the JS daemon contract.
//
// Scope: the deterministic local control surface (import/add/enable/disable/status/validate).
// Remote-MCP header-auth + `.cursor/mcp.json` discovery + the tools/resources/prompts catalog
// from a live remote fixture are the genuine feature gap and remain a follow-on cut.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

let daemon;
let stateDir;

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-mcp-"));
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

// The MCP registry is dual-cased on the agent record; read whichever the response carries.
function registryServers(body) {
  const registry = body.agent?.mcpRegistry || body.agent?.mcp_registry || {};
  return registry.servers || [];
}

test("Rust mcp/import populates the thread MCP registry via the kernel control planner", async () => {
  const threadId = await createThread();
  const r = await post(`${daemon.endpoint}/v1/threads/${threadId}/mcp/import`, {
    servers: [{ id: "fixture-mcp", name: "Fixture", transport: "stdio", command: "echo", args: ["hi"] }],
  });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.commit.persisted, true);
  assert.equal(r.body.source, "rust_mcp_control");
  const servers = registryServers(r.body);
  const fixture = servers.find((s) => s.id === "fixture-mcp");
  assert.ok(fixture, `imported server present: ${JSON.stringify(servers)}`);
  assert.equal(fixture.command, "echo");
  assert.equal(fixture.transport, "stdio");
  assert.equal(fixture.status, "configured");
});

test("Rust mcp/status projects the imported registry", async () => {
  const threadId = await createThread();
  await post(`${daemon.endpoint}/v1/threads/${threadId}/mcp/import`, {
    servers: [{ id: "fixture-mcp", name: "Fixture", transport: "stdio", command: "echo" }],
  });
  const status = await post(`${daemon.endpoint}/v1/threads/${threadId}/mcp/status`, {});
  assert.equal(status.status, 200);
  assert.ok(registryServers(status.body).some((s) => s.id === "fixture-mcp"));
});

test("Rust mcp enable/disable toggles the server enabled flag", async () => {
  const threadId = await createThread();
  await post(`${daemon.endpoint}/v1/threads/${threadId}/mcp/import`, {
    servers: [{ id: "fixture-mcp", name: "Fixture", transport: "stdio", command: "echo" }],
  });
  const disabled = await post(`${daemon.endpoint}/v1/threads/${threadId}/mcp/servers/fixture-mcp/disable`, {});
  assert.equal(disabled.status, 200);
  assert.equal(registryServers(disabled.body).find((s) => s.id === "fixture-mcp").enabled, false);

  const enabled = await post(`${daemon.endpoint}/v1/threads/${threadId}/mcp/servers/fixture-mcp/enable`, {});
  assert.equal(enabled.status, 200);
  assert.equal(registryServers(enabled.body).find((s) => s.id === "fixture-mcp").enabled, true);
});

test("Rust mcp/validate succeeds and mcp control fails closed for an unknown thread", async () => {
  const threadId = await createThread();
  await post(`${daemon.endpoint}/v1/threads/${threadId}/mcp/import`, {
    servers: [{ id: "fixture-mcp", name: "Fixture", transport: "stdio", command: "echo" }],
  });
  const validate = await post(`${daemon.endpoint}/v1/threads/${threadId}/mcp/validate`, {});
  assert.equal(validate.status, 200);

  const missing = await post(`${daemon.endpoint}/v1/threads/thread_missing/mcp/import`, { servers: [] });
  assert.equal(missing.status, 404);
});
