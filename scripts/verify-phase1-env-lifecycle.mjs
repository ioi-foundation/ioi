#!/usr/bin/env node
// Phase 1 — Development Environment Lifecycle verifier (G7, the one-command repeatability harness).
//
// Spawns its OWN hermetic hypervisor-daemon on a scratch data dir + private port, runs the §0
// lifecycle loop, and asserts the closure gates (§11c G1–G7). Grows one gate-block per workstream;
// the completion signal is `node scripts/verify-phase1-env-lifecycle.mjs --n 25` green with zero
// orphans. Usage: --n <iterations> (default 1), --keep (don't wipe data dir on exit).
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO = new URL("..", import.meta.url).pathname;
const DAEMON_BIN = join(REPO, "target/debug/hypervisor-daemon");
const args = process.argv.slice(2);
const N = parseInt((args[args.indexOf("--n") + 1] || "1"), 10) || 1;
const KEEP = args.includes("--keep");
const PORT = 8790 + (process.pid % 50); // avoid the dev daemon on 8765

let failures = 0;
const ok = (cond, msg) => { if (cond) { console.log(`    ✓ ${msg}`); } else { failures++; console.log(`    ✗ FAIL: ${msg}`); } };

async function api(method, path, body) {
  const res = await fetch(`http://127.0.0.1:${PORT}${path}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : {} };
}

async function waitReady(timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}/v1/hypervisor/authority/posture`);
      if (r.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}

// ---- gates ----
// G(WS-1): component-based EnvironmentStatus + typed lifecycle observations.
async function gateWs1() {
  console.log("  [WS-1] component status + typed observations");
  const created = await api("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "verify" } });
  const id = created.json.environment?.id;
  ok(!!id, "env created");
  ok(created.json.environment?.status?.components && Object.keys(created.json.environment.status.components).length === 11, "created env has 11 typed components");
  ok(created.json.environment?.status?.readiness?.mode === "blocked", "created env readiness=blocked (not started)");

  const started = await api("POST", `/v1/hypervisor/environments/${id}/start`);
  const st = started.json.environment?.status || {};
  ok(st.phase === "running", "started env phase=running");
  ok(st.readiness?.mode === "full", `readiness=full after start (got ${st.readiness?.mode})`);
  const required = ["recipe", "provisioner", "workspace_content", "sandbox", "resource_isolation", "connectivity"];
  ok(required.every((c) => st.components?.[c]?.phase === "ready"), "all required components ready");

  const obs = started.json.environment?.lifecycle_observations || [];
  const typed = obs.every((o) => o.observation_ref && o.stage && o.component && o.condition_kind && o.severity);
  ok(obs.length > 0 && typed, `lifecycle observations are typed (stage/component/condition_kind/severity) — ${obs.length} obs`);
  ok(obs.some((o) => o.stage === "provisioning" && o.component === "provisioner"), "provisioning observation present");
  ok(obs.some((o) => o.stage === "ready"), "ready observation present");

  const stopped = await api("POST", `/v1/hypervisor/environments/${id}/stop`);
  ok(stopped.json.environment?.status?.phase === "stopped", "stopped env phase=stopped");
  ok(stopped.json.environment?.status?.readiness?.mode === "blocked", "stopped env readiness=blocked");
  ok(stopped.json.environment?.status?.components?.sandbox?.phase === "pending", "runtime component (sandbox) back to pending on stop");

  await api("POST", `/v1/hypervisor/environments/${id}/delete`);
  return id;
}

// G(WS-2): recipe → resolution → readiness gate (repo-detect-first).
async function gateWs2() {
  console.log("  [WS-2] recipe → resolution → readiness gate (repo-detect-first)");
  const repo = mkdtempSync(join(tmpdir(), "ioi-repo-"));
  mkdirSync(join(repo, ".devcontainer"), { recursive: true });
  writeFileSync(join(repo, ".devcontainer/devcontainer.json"), JSON.stringify({ postCreateCommand: "echo hi", forwardPorts: [3000] }));
  writeFileSync(join(repo, "package.json"), JSON.stringify({ scripts: { start: "node ." } }));
  const det = await api("POST", "/v1/hypervisor/recipes", { repo_path: repo });
  const recipe = det.json.recipe || {};
  ok(recipe.source === "repo_detected", "recipe repo-detected");
  ok((recipe.detected_signals || []).includes("devcontainer.json"), "detected devcontainer.json signal");
  ok((recipe.detected_signals || []).includes("package.json"), "detected package.json signal");
  ok((recipe.ports || []).some((p) => p.port === 3000), "forwardPorts → recipe port 3000");

  // satisfiable recipe → readiness full
  const envOk = await api("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: recipe.recipe_ref } });
  const idOk = envOk.json.environment.id;
  const startedOk = await api("POST", `/v1/hypervisor/environments/${idOk}/start`);
  const rdOk = startedOk.json.environment.status.readiness;
  ok(rdOk.mode === "full", `satisfiable recipe → readiness full (got ${rdOk.mode})`);
  ok(!!startedOk.json.environment.status.readiness_gate_ref, "readiness_gate_ref attached");
  await api("POST", `/v1/hypervisor/environments/${idOk}/delete`);

  // unsatisfiable required edge → dry_run_only naming the edge (READY is gated, not assumed)
  const secretRecipe = await api("POST", "/v1/hypervisor/recipes", { recipe: { substrate: "local_host", secret_requirement_refs: ["DB_PASSWORD"] } });
  const envBlk = await api("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: secretRecipe.json.recipe.recipe_ref } });
  const idBlk = envBlk.json.environment.id;
  const startedBlk = await api("POST", `/v1/hypervisor/environments/${idBlk}/start`);
  const rd = startedBlk.json.environment.status.readiness;
  ok(rd.mode === "dry_run_only", `unsatisfiable required secret → dry_run_only (got ${rd.mode})`);
  ok((rd.blocked_reasons || []).includes("required_secret:DB_PASSWORD"), "blocked_reason names required_secret:DB_PASSWORD");
  await api("POST", `/v1/hypervisor/environments/${idBlk}/delete`);

  // auto-detect on env create via repo_path
  const repo2 = mkdtempSync(join(tmpdir(), "ioi-repo2-"));
  writeFileSync(join(repo2, "Cargo.toml"), "[package]\nname = 'x'\n");
  const envAuto = await api("POST", "/v1/hypervisor/environments", { spec: { repo_path: repo2 } });
  ok(!!envAuto.json.environment.spec.recipe_ref, "env create with repo_path auto-binds a recipe_ref");
  await api("POST", `/v1/hypervisor/environments/${envAuto.json.environment.id}/delete`);

  rmSync(repo, { recursive: true, force: true });
  rmSync(repo2, { recursive: true, force: true });
}

async function runOnce(iter) {
  console.log(`\n=== iteration ${iter}/${N} ===`);
  await gateWs1();
  await gateWs2();
}

// ---- harness ----
const dataDir = mkdtempSync(join(tmpdir(), "ioi-phase1-verify-"));
if (!existsSync(DAEMON_BIN)) { console.error(`daemon binary missing: ${DAEMON_BIN} (cargo build --bin hypervisor-daemon)`); process.exit(2); }
const daemon = spawn(DAEMON_BIN, [], {
  env: { ...process.env, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${PORT}` },
  stdio: ["ignore", "ignore", "inherit"],
});
let exitCode = 0;
try {
  if (!(await waitReady())) { console.error("daemon did not become ready"); process.exit(2); }
  console.log(`daemon up on :${PORT} (data ${dataDir})`);
  for (let i = 1; i <= N; i++) await runOnce(i);
  console.log(`\n${failures === 0 ? "✅ ALL GATES PASS" : `❌ ${failures} FAILURE(S)`} over ${N} iteration(s)`);
  exitCode = failures === 0 ? 0 : 1;
} finally {
  daemon.kill("SIGKILL");
  if (!KEEP) { try { rmSync(dataDir, { recursive: true, force: true }); } catch { /* ignore */ } }
}
process.exit(exitCode);
