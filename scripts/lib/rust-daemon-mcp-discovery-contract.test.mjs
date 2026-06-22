// Ported JS-daemon MCP `.cursor/mcp.json` discovery + tools/resources/prompts catalog → Rust daemon.
//
// Origin: scripts/lib/live-runtime-daemon-contract.test.mjs ("daemon owns MCP discovery,
// validation, and React Flow workflow rows"). The Rust daemon now serves the discovery surface:
//   GET /v1/mcp/servers?thread_id=&mcp_config_source_mode=   (read .cursor/mcp.json -> normalize)
//   GET /v1/mcp/tools?thread_id=                             (runtime.mcp-tool.<server>.<tool>)
//   GET /v1/mcp/resources?thread_id=                         (runtime.mcp-resource.<server>.<x>)
//   GET /v1/mcp/prompts?thread_id=                           (runtime.mcp-prompt.<server>.<x>)
//   GET /v1/mcp?thread_id=                                   (server/tool/resource/prompt counts)
// wiring the CANONICAL kernel validation-input projection + manager catalog projection.
//
// Faithful-port notes:
//   * Snake_case projection: the Rust records use snake_case (id, source_scope, allowed_tools,
//     workflow_node_id, secret_refs) — the agent-sdk camelCase is a client-side mapping.
//   * Secret boundary divergence (by design): the Rust kernel surfaces env/header secrets as
//     vault REFERENCES (vault://...) — the safe pointer, resolved at execution time — rather than
//     the JS `{redacted:true}` descriptor. The equivalent guarantee asserted here is
//     vault_boundary.secret_values_included === false (no secret VALUE is ever inlined).
//   * Live remote-MCP catalog fetch (HTTP/SSE header auth, large-catalog deferral) is network-bound
//     and remains a follow-on; this asserts the offline `.cursor/mcp.json` config discovery.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

let daemon;
let stateDir;
let workspaceDir;

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-mcp-disc-state-"));
  workspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-mcp-disc-ws-"));
  fs.mkdirSync(path.join(workspaceDir, ".cursor"), { recursive: true });
  fs.writeFileSync(
    path.join(workspaceDir, ".cursor", "mcp.json"),
    JSON.stringify(
      {
        mcpServers: {
          search: {
            command: "node",
            args: ["fixture.mjs"],
            allowedTools: ["query", "fetch"],
            resources: [{ uri: "ioi://fixture/search-context", name: "search-context" }],
            prompts: [{ name: "search-brief", arguments: [{ name: "topic", required: true }] }],
            env: { SEARCH_TOKEN: "vault://mcp/search/token" },
            containment: { mode: "sandboxed", allowChildProcesses: true },
          },
        },
      },
      null,
      2,
    ),
  );
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

async function get(url) {
  const response = await fetch(url);
  return { status: response.status, body: await response.json() };
}

async function createThread() {
  const r = await post(`${daemon.endpoint}/v1/threads`, { options: { local: { cwd: workspaceDir } } });
  assert.equal(r.status, 200);
  return r.body.thread_id || r.body.id;
}

test("Rust /v1/mcp/servers discovers + normalizes the workspace .cursor/mcp.json server", async () => {
  const threadId = await createThread();
  const r = await get(`${daemon.endpoint}/v1/mcp/servers?thread_id=${threadId}&mcp_config_source_mode=workspace`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.map((server) => server.id), ["mcp.search"]);
  const search = r.body[0];
  assert.equal(search.source, ".cursor/mcp.json");
  assert.equal(search.source_scope, "workspace");
  assert.equal(search.config_compatibility, "cursor");
  assert.equal(search.enabled, true);
  assert.deepEqual(search.allowed_tools.slice().sort(), ["fetch", "query"]);
  // Secret boundary (by-design divergence): vault REF surfaced, no secret VALUE inlined.
  assert.equal(search.secret_refs.SEARCH_TOKEN, "vault://mcp/search/token");
  assert.equal(search.vault_boundary.secret_values_included, false);
  assert.equal(search.vault_boundary.env_ref_count, 1);
});

test("Rust /v1/mcp/tools projects the discovered MCP tool catalog with runtime node ids", async () => {
  const threadId = await createThread();
  const r = await get(`${daemon.endpoint}/v1/mcp/tools?thread_id=${threadId}`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(
    r.body.filter((tool) => tool.server_id === "mcp.search").map((tool) => tool.tool_name).sort(),
    ["fetch", "query"],
  );
  assert.ok(
    r.body
      .filter((tool) => tool.server_id === "mcp.search")
      .every((tool) => tool.workflow_node_id.startsWith("runtime.mcp-tool.search.")),
  );
});

test("Rust /v1/mcp/resources + /v1/mcp/prompts project the declared catalog", async () => {
  const threadId = await createThread();
  const resources = await get(`${daemon.endpoint}/v1/mcp/resources?thread_id=${threadId}`);
  assert.equal(resources.status, 200);
  assert.equal(resources.body[0].uri, "ioi://fixture/search-context");
  assert.ok(resources.body[0].workflow_node_id.startsWith("runtime.mcp-resource.search."));

  const prompts = await get(`${daemon.endpoint}/v1/mcp/prompts?thread_id=${threadId}`);
  assert.equal(prompts.status, 200);
  assert.equal(prompts.body[0].name, "search-brief");
  assert.ok(prompts.body[0].workflow_node_id.startsWith("runtime.mcp-prompt.search."));
});

test("Rust /v1/mcp status projects the discovered manager counts", async () => {
  const threadId = await createThread();
  const r = await get(`${daemon.endpoint}/v1/mcp?thread_id=${threadId}`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.status, "ready");
  assert.equal(r.body.server_count, 1);
  assert.equal(r.body.tool_count, 2);
  assert.equal(r.body.resource_count, 1);
  assert.equal(r.body.prompt_count, 1);
});

test("Rust MCP discovery never inlines a secret value into the response", async () => {
  const threadId = await createThread();
  const servers = await get(`${daemon.endpoint}/v1/mcp/servers?thread_id=${threadId}`);
  // The vault REFERENCE is the safe pointer (by design); no literal secret material appears.
  assert.equal(JSON.stringify(servers.body).includes("vault_resolved_secret"), false);
  assert.ok(servers.body.every((server) => server.vault_boundary.secret_values_included === false));
});

test("Rust MCP discovery fails closed for an unknown thread (404)", async () => {
  const r = await get(`${daemon.endpoint}/v1/mcp/servers?thread_id=thread_missing`);
  assert.equal(r.status, 404);
});
