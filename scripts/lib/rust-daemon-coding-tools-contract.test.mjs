// Ported JS-daemon coding-tool-pack invocation surface → Rust hypervisor-daemon.
//
// Origin: scripts/lib/live-runtime-daemon-contract.test.mjs ("coding tool pack invokes
// status, diff, inspect, apply patch, …"). The Rust daemon now serves
// POST /v1/threads/:id/tools/:name/invoke, wiring the CANONICAL kernel
// `run_coding_tool_step_module` to a thread's workspace. This re-homes the deterministic
// core of that coverage onto the Rust true-north so it survives the JS daemon's retirement.
//
// Scope: the deterministic, offline-safe coding tools (workspace.status, git.diff,
// file.inspect, file.apply_patch, computer_use.request_lease) PLUS:
//   * test.run / lsp.diagnostics — real node/tsc spawns, env-gated (skip honestly when the
//     tool is absent). The Rust result uses snake_case (test_status / diagnostic_status).
//   * artifact.read / tool.retrieve_result — assert the FAIL-CLOSED contract: without a
//     daemon-provided data-plane payload they 400 (data_plane_payload_required). Wiring the
//     daemon data-plane is a separate (non-route) cut; here we prove the boundary fails closed.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const rootTsc = path.join(repoRoot, "node_modules", ".bin", "tsc");

function nodeAvailable() {
  try {
    execFileSync(process.execPath, ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function tscAvailable() {
  return fs.existsSync(rootTsc);
}

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

test("Rust computer_use.request_lease/invoke returns an approval-gated lease request with a wallet authority boundary", async () => {
  const threadId = await createThread();
  const r = await invoke(threadId, "computer_use.request_lease", { prompt: "lease proof" });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const result = toolResult(r.body, "computer_use.request_lease");
  assert.equal(typeof result.approval_required_before_execution, "boolean");
  assert.ok(result.lease_request, "carries a lease_request");
  assert.ok(result.wallet_network_authority_boundary, "carries the wallet.network authority boundary");
  assert.equal(result.shell_fallback_used, false);
});

test("Rust test.run/invoke runs the node test runner against the thread workspace", { skip: nodeAvailable() ? false : "node unavailable" }, async () => {
  const threadId = await createThread();
  // A passing node:test with a large stdout marker so a small maxOutputBytes truncates it.
  fs.writeFileSync(
    path.join(workspace, "sample.test.mjs"),
    "import test from 'node:test';\n" +
      "import assert from 'node:assert/strict';\n" +
      "const marker = `START ${'x'.repeat(4096)} END`;\n" +
      "test('runtime coding test proof', () => { console.log(marker); assert.equal(2 + 2, 4); });\n",
  );
  const r = await invoke(threadId, "test.run", {
    commandId: "node.test",
    path: "sample.test.mjs",
    maxOutputBytes: 128,
  });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const result = toolResult(r.body, "test.run");
  assert.equal(result.command_id, "node.test");
  assert.equal(result.test_status, "passed");
  assert.equal(result.exit_code, 0);
  assert.equal(result.truncated, true, "a 128-byte cap truncates the 4KB marker");
  assert.ok(Array.isArray(result.allowed_command_ids) && result.allowed_command_ids.includes("node.test"));
});

test("Rust test.run/invoke fails closed for a non-allowlisted command id (400)", async () => {
  const threadId = await createThread();
  const r = await invoke(threadId, "test.run", { commandId: "rm.rf", path: "sample.test.mjs" });
  assert.equal(r.status, 400, JSON.stringify(r.body));
});

test("Rust lsp.diagnostics/invoke runs the node syntax check (clean) against the workspace", { skip: nodeAvailable() ? false : "node unavailable" }, async () => {
  const threadId = await createThread();
  fs.writeFileSync(path.join(workspace, "diagnostic-target.mjs"), "export const value = 1;\n");
  const r = await invoke(threadId, "lsp.diagnostics", {
    commandId: "node.check",
    path: "diagnostic-target.mjs",
    maxOutputBytes: 4096,
  });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const result = toolResult(r.body, "lsp.diagnostics");
  assert.equal(result.diagnostic_status, "clean");
  assert.equal(result.diagnostic_count, 0);
  assert.equal(result.resolved_command_id, "node.check");
});

test("Rust lsp.diagnostics/invoke runs project-aware TypeScript diagnostics (clean)", { skip: tscAvailable() ? false : "repo-local tsc unavailable" }, async () => {
  const threadId = await createThread();
  // Mirror the JS setup: a tsconfig + a typed source + a workspace tsc symlinked from the repo.
  fs.writeFileSync(
    path.join(workspace, "tsconfig.json"),
    JSON.stringify(
      { compilerOptions: { strict: true, target: "ES2022", module: "ESNext", noEmit: true }, include: ["src/**/*.ts"] },
      null,
      2,
    ),
  );
  fs.mkdirSync(path.join(workspace, "src"), { recursive: true });
  fs.writeFileSync(path.join(workspace, "src", "project-target.ts"), "export const typed: number = 1;\n");
  fs.mkdirSync(path.join(workspace, "node_modules", ".bin"), { recursive: true });
  fs.symlinkSync(rootTsc, path.join(workspace, "node_modules", ".bin", "tsc"));

  const r = await invoke(threadId, "lsp.diagnostics", {
    commandId: "typescript.check",
    path: "src/project-target.ts",
    maxOutputBytes: 4096,
  });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const result = toolResult(r.body, "lsp.diagnostics");
  assert.equal(result.resolved_command_id, "typescript.check");
  assert.equal(result.backend_status, "available");
  assert.equal(result.diagnostic_status, "clean");
});

test("Rust artifact.read/tool.retrieve_result fail closed without a daemon data-plane payload (400)", async () => {
  const threadId = await createThread();
  // The tool-invoke route does not (yet) supply a StepModuleDataPlaneHandle, so the receipt-
  // replay tools fail closed rather than fabricating an empty payload.
  const artifact = await invoke(threadId, "artifact.read", { artifactId: "artifact_missing" });
  assert.equal(artifact.status, 400, JSON.stringify(artifact.body));
  assert.match(JSON.stringify(artifact.body), /data_plane_payload_required/);

  const retrieve = await invoke(threadId, "tool.retrieve_result", { toolCallId: "tc_missing" });
  assert.equal(retrieve.status, 400, JSON.stringify(retrieve.body));
  assert.match(JSON.stringify(retrieve.body), /data_plane_payload_required/);
});

test("Rust tool-invoke fails closed: unknown thread → 404, unsupported tool → 400", async () => {
  const threadId = await createThread();
  const missing = await invoke("thread_does_not_exist", "workspace.status", {});
  assert.equal(missing.status, 404);
  const unsupported = await invoke(threadId, "totally.not.a.tool", {});
  assert.equal(unsupported.status, 400);
});
