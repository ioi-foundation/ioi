// Hypervisor session execution surface — Lane A, Cut #1 integration gate.
//
// Proves the Rust daemon owns the Lane A *surface* honestly with NO execution
// substrate present (the only fully-verifiable state on an unequipped box):
//   1. POST /v1/hypervisor/sessions provisions a REAL workspace dir on disk.
//   2. The environment-status projection is REAL — model_mount + harness are
//      honestly `degraded` (no model route, no harness), so the aggregate phase
//      is `updating`, never a fake `running`.
//   3. GET /v1/hypervisor/sessions/:id/events surfaces REAL signals — a real
//      `changed_file_groups` diff of the workspace, an honest `readiness` block,
//      a `receipt_projection` — and emits NO `terminal_chunk` (nothing ran).
//   4. POST /v1/hypervisor/sessions/:id/execute FAILS CLOSED with an honest
//      `no_model_route` reason and fabricates NO work (empty changed_file_groups
//      + terminal_events).
//
// The positive (equipped) execution path is Cut #2; this gate locks the
// fail-closed contract so no "claims to execute but only offline-negative" code
// can regress in.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

let daemon;
let stateDir;
let sessionsRoot;
let priorSessionsRoot;
let priorUpstream;

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-cut1-state-"));
  sessionsRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-cut1-ws-"));
  // Isolate provisioned workspaces under the test dir for deterministic cleanup.
  priorSessionsRoot = process.env.IOI_HYPERVISOR_SESSIONS_ROOT;
  process.env.IOI_HYPERVISOR_SESSIONS_ROOT = sessionsRoot;
  // Force the model route UNREACHABLE so this offline gate is deterministic even
  // when the ambient shell has a live model exported. (The harness shim itself
  // may still resolve — the honest offline signal here is "no model route".)
  priorUpstream = process.env.IOI_HYPERVISOR_MODEL_UPSTREAM;
  process.env.IOI_HYPERVISOR_MODEL_UPSTREAM = "http://127.0.0.1:1/v1";
  daemon = await startRustHypervisorDaemon({ stateDir });
});

afterEach(async () => {
  await daemon?.close();
  if (priorSessionsRoot === undefined) delete process.env.IOI_HYPERVISOR_SESSIONS_ROOT;
  else process.env.IOI_HYPERVISOR_SESSIONS_ROOT = priorSessionsRoot;
  if (priorUpstream === undefined) delete process.env.IOI_HYPERVISOR_MODEL_UPSTREAM;
  else process.env.IOI_HYPERVISOR_MODEL_UPSTREAM = priorUpstream;
  for (const dir of [stateDir, sessionsRoot]) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // best effort
    }
  }
});

function parseSse(text) {
  const frames = [];
  for (const block of text.split("\n\n")) {
    const lines = block.split("\n");
    let event = null;
    let data = null;
    for (const line of lines) {
      if (line.startsWith("event: ")) event = line.slice("event: ".length);
      else if (line.startsWith("data: ")) data = line.slice("data: ".length);
    }
    if (event && data) frames.push({ event, data: JSON.parse(data) });
  }
  return frames;
}

test("Cut #1: provisions a real workspace + projects honest degraded status", async () => {
  const response = await fetch(`${daemon.endpoint}/v1/hypervisor/sessions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      project_ref: "project:pqc-site",
      session_ref: "session:cut1-provision",
      workspace_mount_policy: "public_trunk",
    }),
  });
  assert.equal(response.status, 202);
  const body = await response.json();
  assert.equal(body.schema_version, "ioi.hypervisor.session_create_projection.v1");
  assert.equal(body.session_ref, "session:cut1-provision");

  const status = body.environment_status;
  assert.equal(status.schema_version, "ioi.hypervisor.environment_status.v1");
  assert.equal(status.runtimeTruthSource, "daemon-runtime");

  // Real workspace dir exists on disk under the isolated sessions root.
  const workspaceRoot = status.components.workspace_content.workspace_root;
  assert.ok(workspaceRoot, "workspace_root present");
  assert.ok(workspaceRoot.startsWith(sessionsRoot), `workspace under sessions root: ${workspaceRoot}`);
  assert.ok(fs.existsSync(workspaceRoot) && fs.statSync(workspaceRoot).isDirectory(), "workspace dir exists");

  // Honest status with the model route forced unreachable — never a fake "running".
  // (The harness may be available via the repo shim; the deterministic offline
  // signal is a degraded model_mount, which drives the aggregate to "updating".)
  assert.equal(status.components.provisioner.phase, "ready");
  assert.equal(status.components.workspace_content.phase, "ready");
  assert.equal(status.components.model_mount.phase, "degraded");
  assert.equal(status.phase, "updating");

  assert.ok(body.receipt_ref?.startsWith("receipt://hypervisor/session-provision/"));
});

test("Cut #1: session events surface real diff + honest readiness, no terminal", async () => {
  const create = await fetch(`${daemon.endpoint}/v1/hypervisor/sessions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ session_ref: "session:cut1-events" }),
  });
  const created = await create.json();
  const workspaceRoot = created.environment_status.components.workspace_content.workspace_root;

  // Write a REAL file into the scratch workspace so the diff has a real signal.
  fs.writeFileSync(path.join(workspaceRoot, "index.html"), "<!doctype html>\n<title>PQC</title>\n");

  const events = await fetch(
    `${daemon.endpoint}/v1/hypervisor/sessions/${encodeURIComponent("session:cut1-events")}/events`,
    { headers: { accept: "text/event-stream" } },
  );
  assert.equal(events.status, 200);
  assert.match(events.headers.get("content-type") ?? "", /text\/event-stream/);
  const frames = parseSse(await events.text());
  const byEvent = new Map(frames.map((frame) => [frame.event, frame.data]));

  // Real environment_status.
  assert.ok(byEvent.has("environment_status"));
  assert.equal(byEvent.get("environment_status").schema_version, "ioi.hypervisor.environment_status.v1");

  // Real workspace_change: the file we wrote shows up (filesystem-walked).
  const change = byEvent.get("workspace_change");
  assert.ok(change, "workspace_change frame present");
  const names = (change.changed_file_groups ?? []).flatMap((group) => group.files.map((file) => file.name));
  assert.ok(names.includes("index.html"), `real diff includes index.html: ${JSON.stringify(names)}`);

  // Honest readiness block (no model route).
  const readiness = byEvent.get("readiness");
  assert.equal(readiness.decision, "blocked");
  assert.equal(readiness.reason, "no_model_route");
  assert.equal(readiness.model_route, false);

  // Receipt projection carries the real provisioning receipt.
  const receipts = byEvent.get("receipt_projection");
  assert.ok(Array.isArray(receipts.latest_receipt_refs) && receipts.latest_receipt_refs.length >= 1);

  // No fake terminal transcript — nothing executed.
  assert.equal(byEvent.has("terminal_chunk"), false, "no terminal_chunk fabricated");
});

test("Cut #1: execute fails closed with an honest reason and NO fabricated work", async () => {
  await fetch(`${daemon.endpoint}/v1/hypervisor/sessions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ session_ref: "session:cut1-execute" }),
  });

  const execute = await fetch(
    `${daemon.endpoint}/v1/hypervisor/sessions/${encodeURIComponent("session:cut1-execute")}/execute`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent: "create a website that explains post-quantum computers" }),
    },
  );
  assert.equal(execute.status, 503);
  const body = await execute.json();
  assert.equal(body.decision, "blocked");
  assert.equal(body.reason, "no_model_route");
  // Fail-closed: zero fabricated work.
  assert.deepEqual(body.changed_file_groups, []);
  assert.deepEqual(body.terminal_events, []);
});

test("Cut #1: clones a REAL git repo and surfaces a REAL git diff", async () => {
  // Build a real source repo so the provisioner exercises its real
  // `git clone --depth 1` path and the diff projection's `source: "git"` branch.
  const srcRepo = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-cut1-src-"));
  try {
    execFileSync("git", ["init", "-q", srcRepo]);
    fs.writeFileSync(path.join(srcRepo, "README.md"), "# seed\n");
    execFileSync("git", ["-C", srcRepo, "add", "."]);
    execFileSync("git", [
      "-C", srcRepo,
      "-c", "user.email=cut1@ioi.test",
      "-c", "user.name=cut1",
      "commit", "-q", "-m", "seed",
    ]);

    const create = await fetch(`${daemon.endpoint}/v1/hypervisor/sessions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        session_ref: "session:cut1-clone",
        git: { remote_uri: `file://${srcRepo}` },
      }),
    });
    assert.equal(create.status, 202);
    const created = await create.json();
    const workspaceRoot = created.environment_status.components.workspace_content.workspace_root;

    // The clone really happened: the committed file is on disk + content ready.
    assert.ok(fs.existsSync(path.join(workspaceRoot, "README.md")), "cloned README.md present on disk");
    assert.equal(created.environment_status.components.workspace_content.phase, "ready");

    // Modify a tracked file → the events diff is a REAL `git diff` (not a walk).
    fs.writeFileSync(path.join(workspaceRoot, "README.md"), "# seed\nmore\n");
    const events = await fetch(
      `${daemon.endpoint}/v1/hypervisor/sessions/${encodeURIComponent("session:cut1-clone")}/events`,
      { headers: { accept: "text/event-stream" } },
    );
    const frames = parseSse(await events.text());
    const change = new Map(frames.map((frame) => [frame.event, frame.data])).get("workspace_change");
    const files = (change.changed_file_groups ?? []).flatMap((group) => group.files);
    const readme = files.find((file) => file.name === "README.md");
    assert.ok(readme, `git diff includes README.md: ${JSON.stringify(files.map((f) => f.name))}`);
    assert.equal(readme.status, "modified");
    assert.match(readme.delta, /^\+\d+\/-\d+$/, `git numstat delta shape: ${readme.delta}`);
  } finally {
    fs.rmSync(srcRepo, { recursive: true, force: true });
  }
});

test("Cut #1: execute on an unknown session is 404, not a fake run", async () => {
  const execute = await fetch(
    `${daemon.endpoint}/v1/hypervisor/sessions/${encodeURIComponent("session:does-not-exist")}/execute`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent: "anything" }),
    },
  );
  assert.equal(execute.status, 404);
  const body = await execute.json();
  assert.equal(body.error.code, "session_not_found");
});
