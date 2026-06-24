#!/usr/bin/env node
// Phase 1 — Development Environment Lifecycle verifier (G7, the one-command repeatability harness).
//
// Spawns its OWN hermetic hypervisor-daemon on a scratch data dir + private port, runs the §0
// lifecycle loop, and asserts the closure gates (§11c G1–G7). Grows one gate-block per workstream;
// the completion signal is `node scripts/verify-phase1-env-lifecycle.mjs --n 25` green with zero
// orphans. Usage: --n <iterations> (default 1), --keep (don't wipe data dir on exit).
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, mkdirSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
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
  // detection-only (many signals) — do not start an env from heavy detected commands.
  const repo = mkdtempSync(join(tmpdir(), "ioi-repo-"));
  mkdirSync(join(repo, ".devcontainer"), { recursive: true });
  writeFileSync(join(repo, ".devcontainer/devcontainer.json"), JSON.stringify({ postCreateCommand: "echo hi", forwardPorts: [3000] }));
  writeFileSync(join(repo, "package.json"), JSON.stringify({ scripts: { start: "node ." } }));
  writeFileSync(join(repo, "Cargo.toml"), "[package]\nname = 'x'\n");
  const det = await api("POST", "/v1/hypervisor/recipes", { repo_path: repo });
  const recipe = det.json.recipe || {};
  ok(recipe.source === "repo_detected", "recipe repo-detected");
  ok((recipe.detected_signals || []).includes("devcontainer.json"), "detected devcontainer.json signal");
  ok((recipe.detected_signals || []).includes("package.json"), "detected package.json signal");
  ok((recipe.detected_signals || []).includes("Cargo.toml"), "detected Cargo.toml signal");
  ok((recipe.ports || []).some((p) => p.port === 3000), "forwardPorts → recipe port 3000");
  rmSync(repo, { recursive: true, force: true });

  // satisfiable recipe (succeeding required task) → readiness full
  const okRecipe = await api("POST", "/v1/hypervisor/recipes", { recipe: { substrate: "local_host", init_tasks: [{ name: "setup", command: "true", trigger: "environment_start", required: true }] } });
  const envOk = await api("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: okRecipe.json.recipe.recipe_ref } });
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

  // auto-detect on env create via repo_path (create+delete only — no task execution)
  const repo2 = mkdtempSync(join(tmpdir(), "ioi-repo2-"));
  writeFileSync(join(repo2, "go.mod"), "module x\n");
  const envAuto = await api("POST", "/v1/hypervisor/environments", { spec: { repo_path: repo2 } });
  ok(!!envAuto.json.environment.spec.recipe_ref, "env create with repo_path auto-binds a recipe_ref");
  await api("POST", `/v1/hypervisor/environments/${envAuto.json.environment.id}/delete`);
  rmSync(repo2, { recursive: true, force: true });
}

// G(WS-3): typed services/tasks/ports — tasks RUN as real processes; health-checks gate readiness.
async function gateWs3() {
  console.log("  [WS-3] typed services/tasks/ports (real task execution)");
  // task actually runs as a real process and writes to the workspace
  const r1 = await api("POST", "/v1/hypervisor/recipes", { recipe: { substrate: "local_host", init_tasks: [{ name: "writefile", command: "echo built > marker.txt", trigger: "environment_start", required: true }] } });
  const e1 = (await api("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: r1.json.recipe.recipe_ref } })).json.environment.id;
  const s1 = (await api("POST", `/v1/hypervisor/environments/${e1}/start`)).json.environment;
  const task = (s1.status.tasks || [])[0] || {};
  ok(task.phase === "succeeded" && task.exit_code === 0, "required task ran (phase succeeded, exit 0)");
  ok(!!task.log_ref, "task has a log_ref");
  ok(s1.status.readiness.mode === "full", "task success → readiness full");
  const cat = await api("POST", "/v1/hypervisor/exec", { environment_id: e1, command: "cat marker.txt" });
  ok((cat.json.stdout || "").includes("built"), "task wrote a REAL file into the workspace (cat marker.txt)");
  await api("POST", `/v1/hypervisor/environments/${e1}/delete`);

  // failing required task → blocked naming required_task; automations component failed
  const r2 = await api("POST", "/v1/hypervisor/recipes", { recipe: { substrate: "local_host", init_tasks: [{ name: "boom", command: "exit 7", trigger: "environment_start", required: true }] } });
  const e2 = (await api("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: r2.json.recipe.recipe_ref } })).json.environment.id;
  const s2 = (await api("POST", `/v1/hypervisor/environments/${e2}/start`)).json.environment;
  ok(s2.status.readiness.mode === "blocked", `failed required task → readiness blocked (got ${s2.status.readiness.mode})`);
  ok((s2.status.readiness.blocked_reasons || []).includes("required_task:boom"), "blocked_reason names required_task:boom");
  ok((s2.status.tasks || [])[0]?.exit_code === 7, "task exit_code captured (7)");
  ok(s2.status.components.automations.phase === "failed", "automations component=failed");
  await api("POST", `/v1/hypervisor/environments/${e2}/delete`);

  // required service health-check gates readiness: pass → running/full, fail → not full
  const r3 = await api("POST", "/v1/hypervisor/recipes", { recipe: { substrate: "local_host", services: [{ name: "db", lifecycle: "required", healthcheck: "true" }] } });
  const e3 = (await api("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: r3.json.recipe.recipe_ref } })).json.environment.id;
  const s3 = (await api("POST", `/v1/hypervisor/environments/${e3}/start`)).json.environment;
  ok((s3.status.services || [])[0]?.phase === "running", "required service w/ passing healthcheck → running");
  ok(s3.status.readiness.mode === "full", "healthy required service → readiness full");
  await api("POST", `/v1/hypervisor/environments/${e3}/delete`);

  const r4 = await api("POST", "/v1/hypervisor/recipes", { recipe: { substrate: "local_host", services: [{ name: "db", lifecycle: "required", healthcheck: "false" }] } });
  const e4 = (await api("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: r4.json.recipe.recipe_ref } })).json.environment.id;
  const s4 = (await api("POST", `/v1/hypervisor/environments/${e4}/start`)).json.environment;
  ok((s4.status.services || [])[0]?.phase === "degraded", "required service w/ failing healthcheck → degraded");
  ok(s4.status.readiness.mode !== "full", `unhealthy required service → readiness not full (got ${s4.status.readiness.mode})`);
  ok((s4.status.readiness.blocked_reasons || []).includes("required_service:db"), "blocked_reason names required_service:db");
  await api("POST", `/v1/hypervisor/environments/${e4}/delete`);

  // typed ports with exposure_state derived from access_policy
  const r5 = await api("POST", "/v1/hypervisor/recipes", { recipe: { substrate: "local_host", ports: [{ port: 8080, access_policy: "session_lease" }, { port: 9090, access_policy: "shared" }] } });
  const e5 = (await api("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: r5.json.recipe.recipe_ref } })).json.environment.id;
  const s5 = (await api("POST", `/v1/hypervisor/environments/${e5}/start`)).json.environment;
  const ports = s5.status.ports || [];
  ok(ports.find((p) => p.port === 8080)?.exposure_state === "lease_required", "session_lease port → exposure_state lease_required");
  ok(ports.find((p) => p.port === 9090)?.exposure_state === "open", "shared port → exposure_state open");
  await api("POST", `/v1/hypervisor/environments/${e5}/delete`);
}

// G(WS-4): real cloud-hypervisor microVM — in-guest execution (kernel boundary), teardown clean.
import { existsSync as _exists } from "node:fs";
import { homedir } from "node:os";
import { execSync } from "node:child_process";
const TOOLCHAIN = process.env.IOI_VM_TOOLCHAIN_DIR || join(homedir(), ".ioi/vm-toolchain");
const HOST_UNAME = (() => { try { return execSync("uname -r").toString().trim(); } catch { return "?"; } })();

async function gateWs4() {
  if (!_exists(join(TOOLCHAIN, "supply-manifest.json"))) {
    console.log("  [WS-4] SKIPPED — VM toolchain not provisioned (run scripts/phase1/provision-vm-toolchain.sh)");
    failures++; console.log("    ✗ FAIL: WS-4 requires the VM toolchain"); return;
  }
  console.log("  [WS-4] real cloud-hypervisor microVM (in-guest execution, kernel boundary)");
  const recipe = await api("POST", "/v1/hypervisor/recipes", { recipe: { substrate: "microvm", init_tasks: [{ name: "build", command: "echo from-guest > guestbuilt.txt && uname -r > kver.txt", trigger: "environment_start", required: true }] } });
  const env = (await api("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: recipe.json.recipe.recipe_ref } })).json.environment.id;
  const started = (await api("POST", `/v1/hypervisor/environments/${env}/start`)).json.environment;
  const stx = started.status || {};
  ok(stx.vm?.monitor === "cloud-hypervisor", `booted a real cloud-hypervisor microVM (monitor=${stx.vm?.monitor})`);
  ok(stx.isolation_claim === "cross_tenant_capable", `isolation_claim=cross_tenant_capable (got ${stx.isolation_claim})`);
  ok(stx.minimum_isolation === "vm_kernel", `minimum_isolation=vm_kernel (got ${stx.minimum_isolation})`);
  ok(stx.components?.sandbox?.phase === "ready", "sandbox component ready (VM kernel boundary)");
  const task = (stx.tasks || [])[0] || {};
  ok(task.executed_in === "guest" && task.phase === "succeeded", `recipe task ran IN-GUEST + succeeded (executed_in=${task.executed_in})`);
  ok(stx.readiness?.mode === "full", `readiness full (got ${stx.readiness?.mode})`);

  // THE kernel-isolation proof: a command exec'd in the env runs in the GUEST kernel, not the host.
  const guestU = await api("POST", "/v1/hypervisor/exec", { environment_id: env, command: "uname -r" });
  const gk = (guestU.json.stdout || "").trim();
  ok(guestU.json.executed_in === "guest", "exec routes IN-GUEST while VM is live");
  ok(gk && gk !== HOST_UNAME, `guest kernel (${gk}) differs from host kernel (${HOST_UNAME}) — real isolation`);

  // stop tears the VM down (no orphan): exec now falls back to the HOST, and the EXPORTED guest
  // file is present on the host workspace (workspace round-trip proof).
  await api("POST", `/v1/hypervisor/environments/${env}/stop`);
  const hostCat = await api("POST", "/v1/hypervisor/exec", { environment_id: env, command: "cat guestbuilt.txt" });
  ok(hostCat.json.executed_in === "host", "after stop, exec falls back to host (VM torn down — no orphan)");
  ok((hostCat.json.stdout || "").includes("from-guest"), "guest's file exported back to the host workspace");

  await api("POST", `/v1/hypervisor/environments/${env}/delete`);
  ok(countVmProcs(env) === 0, `no orphan cloud-hypervisor process after delete (found ${countVmProcs(env)})`);
}

// Count real cloud-hypervisor processes referencing an env (scans /proc cmdlines — no pgrep
// self-match). Used to prove teardown leaves zero orphan VMs (G3/G7).
function countVmProcs(env) {
  let n = 0;
  for (const pid of readdirSync("/proc")) {
    if (!/^\d+$/.test(pid)) continue;
    try {
      const cl = readFileSync(`/proc/${pid}/cmdline`).toString().replace(/\0/g, " ");
      if (cl.includes("cloud-hypervisor") && cl.includes(env)) n++;
    } catch { /* process gone */ }
  }
  return n;
}

// G(WS-5): monitor abstraction — Firecracker (real 2nd monitor), QEMU lane, policy selection.
async function gateWs5() {
  if (!_exists(join(TOOLCHAIN, "supply-manifest.json"))) {
    console.log("  [WS-5] SKIPPED — VM toolchain not provisioned"); failures++; console.log("    ✗ FAIL: WS-5 requires the VM toolchain"); return;
  }
  console.log("  [WS-5] monitor abstraction (Firecracker lane + QEMU lane + selection)");
  // Firecracker: a real SECOND monitor runs the same recipe in-guest with kernel isolation.
  const fcR = await api("POST", "/v1/hypervisor/recipes", { recipe: { substrate: "microvm", monitor: "firecracker", init_tasks: [{ name: "build", command: "echo fc-guest > out.txt", trigger: "environment_start", required: true }] } });
  const fcEnv = (await api("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: fcR.json.recipe.recipe_ref } })).json.environment.id;
  const fcS = (await api("POST", `/v1/hypervisor/environments/${fcEnv}/start`)).json.environment;
  ok(fcS.status.vm?.monitor === "firecracker", `Firecracker selected + booted (monitor=${fcS.status.vm?.monitor})`);
  ok(/firecracker|monitor=/.test(fcS.status.vm?.selection_reason || ""), "selection_reason records the monitor choice");
  ok(fcS.status.minimum_isolation === "vm_kernel", "Firecracker env: vm_kernel isolation");
  ok((fcS.status.tasks || [])[0]?.executed_in === "guest" && (fcS.status.tasks || [])[0]?.phase === "succeeded", "task ran IN-GUEST under Firecracker");
  const fcU = await api("POST", "/v1/hypervisor/exec", { environment_id: fcEnv, command: "uname -r" });
  ok(fcU.json.executed_in === "guest" && (fcU.json.stdout || "").trim() !== HOST_UNAME, `Firecracker guest kernel (${(fcU.json.stdout || "").trim()}) differs from host — real isolation`);
  await api("POST", `/v1/hypervisor/environments/${fcEnv}/stop`);
  await api("POST", `/v1/hypervisor/environments/${fcEnv}/delete`);
  ok(countVmProcs(fcEnv) === 0, "no orphan firecracker process after delete");

  // policy selection by isolation_profile (recorded, no boot needed to verify the choice)
  const profR = await api("POST", "/v1/hypervisor/recipes", { recipe: { substrate: "microvm", isolation_profile: "minimal_sealed", init_tasks: [{ name: "noop", command: "true", trigger: "environment_start", required: true }] } });
  const profEnv = (await api("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: profR.json.recipe.recipe_ref } })).json.environment.id;
  const profS = (await api("POST", `/v1/hypervisor/environments/${profEnv}/start`)).json.environment;
  ok(profS.status.vm?.monitor === "firecracker", `isolation_profile=minimal_sealed → Firecracker selected (got ${profS.status.vm?.monitor})`);
  await api("POST", `/v1/hypervisor/environments/${profEnv}/stop`);
  await api("POST", `/v1/hypervisor/environments/${profEnv}/delete`);

  // QEMU lane: selected, host-gated, fails closed honestly (no fake boot).
  const qR = await api("POST", "/v1/hypervisor/recipes", { recipe: { substrate: "microvm", monitor: "qemu" } });
  const qEnv = (await api("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: qR.json.recipe.recipe_ref } })).json.environment.id;
  const qS = (await api("POST", `/v1/hypervisor/environments/${qEnv}/start`)).json.environment;
  ok(qS.status.components?.sandbox?.phase === "failed", "QEMU lane host-gated → sandbox failed (honest, no fake boot)");
  ok(/qemu/i.test(qS.status.components?.sandbox?.detail || ""), `sandbox failure names the qemu host-gap (${(qS.status.components?.sandbox?.detail || "").slice(0, 48)})`);
  await api("POST", `/v1/hypervisor/environments/${qEnv}/delete`);
}

// G(WS-6): prebuild & warmup cache — a second env from the same recipe is warm (cache_hit).
async function gateWs6() {
  console.log("  [WS-6] prebuild & warmup cache");
  const r = await api("POST", "/v1/hypervisor/recipes", { recipe: { substrate: "local_host", cache_paths: ["cachedir"], prebuild_tasks: [{ name: "warm", command: "mkdir -p cachedir && echo built > cachedir/marker", trigger: "prebuild", required: false }] } });
  const rid = r.json.recipe.recipe_ref;
  const e1 = (await api("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: rid } })).json.environment.id;
  const s1 = (await api("POST", `/v1/hypervisor/environments/${e1}/start`)).json.environment;
  ok(s1.status.cache_hit === false, `first env: cold cache (cache_hit=${s1.status.cache_hit})`);
  const e2 = (await api("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: rid } })).json.environment.id;
  const s2 = (await api("POST", `/v1/hypervisor/environments/${e2}/start`)).json.environment;
  ok(s2.status.cache_hit === true, `second env (same recipe): warm cache (cache_hit=${s2.status.cache_hit})`);
  ok((s2.lifecycle_observations || []).some((o) => o.stage === "warming_cache" && /warm/.test(o.message || "")), "warming_cache observation records the cache hit");
  const cat = await api("POST", "/v1/hypervisor/exec", { environment_id: e2, command: "cat cachedir/marker" });
  ok((cat.json.stdout || "").includes("built"), "cached artifact present in the warm env");
  await api("POST", `/v1/hypervisor/environments/${e1}/delete`);
  await api("POST", `/v1/hypervisor/environments/${e2}/delete`);
}

// G(WS-7): stop / idle / activity policy — an idle env is swept to stopped (timeout observation).
async function gateWs7() {
  console.log("  [WS-7] stop / idle / activity policy");
  const e = (await api("POST", "/v1/hypervisor/environments", { spec: { stop_policy: { mode: "graceful", idle_timeout_secs: 1, max_lifetime_secs: 0 } } })).json.environment.id;
  const s = (await api("POST", `/v1/hypervisor/environments/${e}/start`)).json.environment;
  ok(s.status.phase === "running", "env running before idle");
  let sw = await api("POST", "/v1/hypervisor/maintenance/idle-sweep");
  ok(!(sw.json.stopped || []).some((x) => x.environment_id === e), "fresh env NOT swept (still active)");
  await new Promise((r) => setTimeout(r, 1600));
  sw = await api("POST", "/v1/hypervisor/maintenance/idle-sweep");
  ok((sw.json.stopped || []).some((x) => x.environment_id === e), "idle env swept to stopped");
  const g = (await api("GET", `/v1/hypervisor/environments/${e}`)).json.environment;
  ok(g.status.phase === "stopped", "idle env transitioned to stopped");
  ok((g.lifecycle_observations || []).some((o) => o.condition_kind === "timeout"), "stop recorded a timeout observation");
  await api("POST", `/v1/hypervisor/environments/${e}/delete`);
}

async function runOnce(iter) {
  console.log(`\n=== iteration ${iter}/${N} ===`);
  await gateWs1();
  await gateWs2();
  await gateWs3();
  await gateWs4();
  await gateWs5();
  await gateWs6();
  await gateWs7();
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
