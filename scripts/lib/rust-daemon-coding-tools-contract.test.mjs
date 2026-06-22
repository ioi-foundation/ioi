// Ported JS-daemon coding-tool-pack invocation surface → Rust hypervisor-daemon.
//
// Origin: scripts/lib/live-runtime-daemon-contract.test.mjs ("coding tool pack invokes
// status, diff, inspect, apply patch, …"). The Rust daemon now serves
// POST /v1/threads/:id/tools/:name/invoke, wiring the CANONICAL kernel
// `run_coding_tool_step_module` to a thread's workspace. This re-homes the deterministic
// core of that coverage onto the Rust true-north so it survives the JS daemon's retirement.
//
// Scope: the deterministic, offline-safe coding tools (workspace.status, git.diff,
// file.inspect, file.apply_patch). The env-dependent tools (test.run / lsp.diagnostics =
// node/tsc spawns, computer_use.request_lease, artifact.read / tool.retrieve_result =
// receipt replay) are follow-on cuts.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { afterEach, beforeEach, test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

let daemon;
let stateDir;
let workspace;

function git(args) {
  execFileSync("git", args, { cwd: workspace, stdio: "ignore" });
}

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-coding-state-"));
  workspace = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-coding-ws-"));
  git(["init"]);
  git(["config", "user.email", "runtime@example.test"]);
  git(["config", "user.name", "Runtime Test"]);
  fs.writeFileSync(path.join(workspace, "README.md"), "# Hello\n\nInitial line.\n");
  git(["add", "README.md"]);
  git(["commit", "-m", "init"]);
  fs.appendFileSync(path.join(workspace, "README.md"), "appended line\n"); // dirty (M)
  daemon = await startRustHypervisorDaemon({ stateDir });
});

afterEach(async () => {
  await daemon?.close();
  for (const dir of [stateDir, workspace]) {
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
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

async function createThread() {
  const r = await post(`${daemon.endpoint}/v1/threads`, { options: { local: { cwd: workspace } } });
  assert.equal(r.status, 200);
  return r.body.thread_id || r.body.id;
}

async function invoke(threadId, tool, input) {
  const r = await post(`${daemon.endpoint}/v1/threads/${threadId}/tools/${tool}/invoke`, { input });
  return r;
}

// The kernel response carries the tool result as workload_observation = { tool, result }.
function toolResult(body, tool) {
  const obs = body.workload_observation;
  assert.ok(obs, `response carries a workload_observation: ${Object.keys(body).join(",")}`);
  assert.equal(obs.tool, tool);
  return obs.result;
}

test("Rust /v1/threads/:id/tools/workspace.status/invoke runs real git status against the thread workspace", async () => {
  const threadId = await createThread();
  const r = await invoke(threadId, "workspace.status", {});
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const result = toolResult(r.body, "workspace.status");
  assert.equal(result.git.available, true);
  assert.ok(result.changed_files.some((f) => f.path === "README.md" && f.status === "M"), JSON.stringify(result.changed_files));
  assert.ok(result.counts.changed >= 1);
  assert.match(result.git.porcelain_hash, /^[a-f0-9]{64}$/);
});

test("Rust git.diff/invoke returns the real unified diff for a changed file", async () => {
  const threadId = await createThread();
  const r = await invoke(threadId, "git.diff", { path: "README.md" });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const result = toolResult(r.body, "git.diff");
  assert.match(result.diff, /\+appended line/);
  assert.ok(result.diff.includes("README.md"));
  assert.match(result.diff_hash, /^[a-f0-9]{64}$/);
});

test("Rust file.inspect/invoke reads the workspace file with a hashed preview", async () => {
  const threadId = await createThread();
  const r = await invoke(threadId, "file.inspect", { path: "README.md" });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const result = toolResult(r.body, "file.inspect");
  assert.equal(result.exists, true);
  assert.equal(result.kind, "file");
  assert.ok(result.preview.includes("Initial line."));
  assert.match(result.preview_hash, /^sha256:[a-f0-9]{64}$/);
});

test("Rust file.apply_patch/invoke is dry-run-safe and mutates the workspace on a real apply", async () => {
  const threadId = await createThread();
  const target = path.join(workspace, "README.md");

  // Dry run does NOT touch the file.
  const dry = await invoke(threadId, "file.apply_patch", {
    path: "README.md",
    oldText: "Initial line.",
    newText: "Patched line.",
    dryRun: true,
  });
  assert.equal(dry.status, 200, JSON.stringify(dry.body));
  assert.ok(fs.readFileSync(target, "utf8").includes("Initial line."), "dry run left the file unchanged");
  assert.ok(!fs.readFileSync(target, "utf8").includes("Patched line."));

  // Real apply mutates the file on disk.
  const applied = await invoke(threadId, "file.apply_patch", {
    path: "README.md",
    oldText: "Initial line.",
    newText: "Patched line.",
    dryRun: false,
  });
  assert.equal(applied.status, 200, JSON.stringify(applied.body));
  const after = fs.readFileSync(target, "utf8");
  assert.ok(after.includes("Patched line."), "real apply edited the file");
  assert.ok(!after.includes("Initial line."));
});

test("Rust tool-invoke fails closed: unknown thread → 404, unsupported tool → 400", async () => {
  const threadId = await createThread();
  const missing = await invoke("thread_does_not_exist", "workspace.status", {});
  assert.equal(missing.status, 404);
  const unsupported = await invoke(threadId, "totally.not.a.tool", {});
  assert.equal(unsupported.status, 400);
});
