// Hypervisor session execution — Lane A, Cut #2 EQUIPPED positive gate.
//
// Proves the REAL host-spawn Lane A loop end to end when the box is equipped
// (a local Ollama model + node + the generic-cli-local shim):
//   - launch a session (real provisioned workspace);
//   - execute "create a website that explains post-quantum computers";
//   - the daemon spawns the harness in the workspace, the harness drives the
//     local model and writes real files;
//   - assert a REAL index.html exists on disk with real content;
//   - assert the REAL diff includes index.html;
//   - assert the terminal transcript is the spawned harness's real output;
//   - assert Agentgres-shaped receipts exist;
//   - assert the events SSE surfaces the real terminal_chunk transcript.
//
// HONEST SKIP: when Ollama/model/node/shim are absent the test skips (it never
// fakes a pass). The offline fail-closed contract is covered by
// hypervisor-session-execution-cut1.test.mjs.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const MODEL_ENDPOINT = process.env.IOI_HYPERVISOR_MODEL_UPSTREAM ?? "http://127.0.0.1:11434/v1";
const PQC_INTENT =
  "Create a small static website that explains what post-quantum computers are. " +
  "Include an index.html file with a paragraph about post-quantum cryptography.";

function tagsUrl() {
  // Derive the /api/tags base from the OpenAI-compatible endpoint.
  return `${MODEL_ENDPOINT.replace(/\/v1\/?$/, "")}/api/tags`;
}

async function detectEquipment() {
  const shim = path.resolve(repoRoot, "packages/runtime-daemon/src/harness-shims/generic-cli-local.mjs");
  if (!fs.existsSync(shim)) return { ok: false, reason: "generic-cli-local shim missing" };
  try {
    const response = await fetch(tagsUrl(), { signal: AbortSignal.timeout(3000) });
    if (!response.ok) return { ok: false, reason: `ollama tags ${response.status}` };
    const body = await response.json();
    const models = (body.models ?? []).map((model) => model.name).filter(Boolean);
    if (models.length === 0) return { ok: false, reason: "no local models cached" };
    const preferred = process.env.IOI_HYPERVISOR_MODEL;
    const model =
      (preferred && models.includes(preferred) && preferred) ||
      models.find((name) => /^qwen2\.5/.test(name)) ||
      models.find((name) => /qwen/i.test(name)) ||
      models[0];
    return { ok: true, model, models };
  } catch (error) {
    return { ok: false, reason: `ollama unreachable: ${String(error)}` };
  }
}

function parseSse(text) {
  const frames = [];
  for (const block of text.split("\n\n")) {
    let event = null;
    let data = null;
    for (const line of block.split("\n")) {
      if (line.startsWith("event: ")) event = line.slice("event: ".length);
      else if (line.startsWith("data: ")) data = line.slice("data: ".length);
    }
    if (event && data) frames.push({ event, data: JSON.parse(data) });
  }
  return frames;
}

test("Equipped Cut #2: real host-spawn Lane A writes a real index.html via the local model", { timeout: 240000 }, async (t) => {
  const equipment = await detectEquipment();
  if (!equipment.ok) {
    t.skip(`not equipped (${equipment.reason}) — offline fail-closed path is covered by the cut1 gate`);
    return;
  }

  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-equip-state-"));
  const sessionsRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-equip-ws-"));
  const prev = {
    upstream: process.env.IOI_HYPERVISOR_MODEL_UPSTREAM,
    model: process.env.IOI_HYPERVISOR_MODEL,
    sessions: process.env.IOI_HYPERVISOR_SESSIONS_ROOT,
  };
  process.env.IOI_HYPERVISOR_MODEL_UPSTREAM = MODEL_ENDPOINT;
  process.env.IOI_HYPERVISOR_MODEL = equipment.model;
  process.env.IOI_HYPERVISOR_SESSIONS_ROOT = sessionsRoot;

  const daemon = await startRustHypervisorDaemon({ stateDir });
  const sessionRef = "session:equipped-pqc";
  try {
    const create = await fetch(`${daemon.endpoint}/v1/hypervisor/sessions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ project_ref: "project:pqc", session_ref: sessionRef }),
    });
    assert.equal(create.status, 202);
    const created = await create.json();
    const workspaceRoot = created.environment_status.components.workspace_content.workspace_root;
    assert.ok(fs.existsSync(workspaceRoot), "real workspace dir exists");
    // Equipped: the model route is really reachable → model_mount is READY.
    assert.equal(created.environment_status.components.model_mount.phase, "ready");

    // Run the REAL Lane A loop.
    const execute = await fetch(
      `${daemon.endpoint}/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/execute`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ intent: PQC_INTENT }),
      },
    );
    assert.equal(execute.status, 200, `execute returns 200 (got ${execute.status})`);
    const result = await execute.json();
    assert.equal(result.decision, "executed", `decision executed (error=${JSON.stringify(result.error)})`);
    assert.equal(result.exit_status, "success");
    assert.equal(result.model, equipment.model);

    // Real file writes reported by the harness.
    assert.ok(
      result.files_written.includes("index.html"),
      `files_written includes index.html: ${JSON.stringify(result.files_written)}`,
    );

    // The REAL file exists on disk with REAL content.
    const indexPath = path.join(workspaceRoot, "index.html");
    assert.ok(fs.existsSync(indexPath), "index.html exists on disk");
    const html = fs.readFileSync(indexPath, "utf8");
    assert.ok(html.length > 50, "index.html has real content");
    assert.match(html, /quantum/i, "index.html mentions quantum");

    // The REAL diff surfaces index.html.
    const diffNames = (result.changed_file_groups ?? []).flatMap((group) => group.files.map((file) => file.name));
    assert.ok(diffNames.includes("index.html"), `diff includes index.html: ${JSON.stringify(diffNames)}`);

    // The transcript is the spawned harness's REAL output.
    assert.ok(Array.isArray(result.terminal_events) && result.terminal_events.length > 0, "real transcript present");
    assert.ok(
      result.terminal_events.some((event) => /generic-cli/.test(String(event.text))),
      "transcript carries real harness output lines",
    );

    // Real execution receipt.
    assert.ok(
      (result.latest_receipt_refs ?? []).some((ref) => String(ref).startsWith("receipt://hypervisor/session-execute/")),
      "execute receipt present",
    );

    // The events SSE now surfaces the real terminal transcript as terminal_chunk.
    const events = await fetch(
      `${daemon.endpoint}/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/events`,
      { headers: { accept: "text/event-stream" } },
    );
    const frames = parseSse(await events.text());
    assert.ok(frames.some((frame) => frame.event === "terminal_chunk"), "events surface real terminal_chunk frames");
  } finally {
    await daemon.close();
    for (const [key, value] of [
      ["IOI_HYPERVISOR_MODEL_UPSTREAM", prev.upstream],
      ["IOI_HYPERVISOR_MODEL", prev.model],
      ["IOI_HYPERVISOR_SESSIONS_ROOT", prev.sessions],
    ]) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    for (const dir of [stateDir, sessionsRoot]) {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        // best effort
      }
    }
  }
});
