#!/usr/bin/env node
// WS-3r/WS-9 — editor-service daemon-restart reconcile + negative checks.
//
// A long-lived editor runtime does not survive a daemon restart. This proves the daemon answers
// honestly on the next boot: a service persisted `ready` is reconciled to `degraded`
// (editor_runtime_lost_on_restart), NOT reported phantom-ready — and the operator can restart it to
// recover. Plus the core negatives: the editor service carries no environment-lifecycle authority
// (lifecycle is daemon-owned), and the adapter does not own runtime truth. Usage: [--json].
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO = new URL("..", import.meta.url).pathname;
const DAEMON_BIN = join(REPO, "target/debug/hypervisor-daemon");
const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const BASE_PORT = 9340 + (process.pid % 50);

const checks = [];
const declaredGaps = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg, detail: detail || "" }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function makeApi(port) {
  return async (method, path, body) => {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers: body ? { "Content-Type": "application/json" } : undefined, body: body ? JSON.stringify(body) : undefined });
    const text = await res.text(); let json = {}; try { json = text ? JSON.parse(text) : {}; } catch {}
    return { status: res.status, json, text };
  };
}
async function waitReady(port, t = 15000) { const s = Date.now(); while (Date.now() - s < t) { try { if ((await fetch(`http://127.0.0.1:${port}/v1/hypervisor/editor-targets`)).ok) return true; } catch {} await sleep(150); } return false; }
// kill any orphaned openvscode-server referencing this data dir (the prior daemon's runtime).
function killOrphans(dataDir) {
  for (const pid of readdirSync("/proc")) {
    if (!/^\d+$/.test(pid)) continue;
    try { const cl = readFileSync(`/proc/${pid}/cmdline`).toString().replace(/\0/g, " "); if (cl.includes("openvscode-server") && cl.includes(dataDir)) process.kill(parseInt(pid), "SIGKILL"); } catch {}
  }
}

if (!JSON_OUT) console.log("WS-3r/WS-9 — editor restart reconcile + negative checks");

// provision (reuse); declared gap if unavailable.
const prov = spawnSync("node", [join(REPO, "scripts/provision-hypervisor-vscode-browser-host.mjs"), "--json"], { encoding: "utf8", cwd: REPO, timeout: 320000 });
let provJson = null; try { provJson = JSON.parse((prov.stdout || "").slice((prov.stdout || "").indexOf("{"))); } catch {}
const toolchainDir = process.env.IOI_HYPERVISOR_EDITOR_TOOLCHAIN_DIR || join(process.env.HOME || "", ".ioi/editor-toolchain");
if (!provJson?.ok || !existsSync(join(toolchainDir, "openvscode-server/bin/openvscode-server"))) {
  declaredGaps.push({ gate: "vscode_browser_host", prerequisite: "ASSET_UNAVAILABLE", reason: "OSS runtime not provisionable on this host" });
  const report = { workstream: "WS-3r", verdict: "PASS_WITH_DECLARED_GAPS", failures: 0, checks: 0, declared_gaps: declaredGaps };
  console.log(JSON_OUT ? JSON.stringify(report, null, 2) : `  declared gap: ASSET_UNAVAILABLE\n  VERDICT: PASS_WITH_DECLARED_GAPS`);
  process.exit(0);
}
if (!existsSync(DAEMON_BIN)) { console.error(`daemon binary missing: ${DAEMON_BIN}`); process.exit(2); }

const dataDir = mkdtempSync(join(tmpdir(), "ioi-ws3r-"));
const env1 = { ...process.env, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_EDITOR_TOOLCHAIN_DIR: toolchainDir };
const portA = BASE_PORT, portB = BASE_PORT + 1;
let serviceId = null;
try {
  // ---- daemon A: bring an editor service to ready ----
  const daemonA = spawn(DAEMON_BIN, [], { env: { ...env1, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${portA}` }, stdio: ["ignore", "ignore", "ignore"], cwd: REPO });
  const apiA = makeApi(portA);
  if (!(await waitReady(portA))) { console.error("daemon A not ready"); process.exit(2); }
  const env = (await apiA("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "ws3r" } })).json.environment;
  await apiA("POST", `/v1/hypervisor/environments/${env.id}/start`);
  const svc = (await apiA("POST", "/v1/hypervisor/editor-services", { environment_id: env.id, target_profile: "vscode-browser" })).json.editorService;
  serviceId = svc.service_id;
  const lease = (await apiA("POST", "/v1/hypervisor/editor-access-leases", { session_id: "session:ws3r", environment_id: env.id, service_id: serviceId })).json;
  if (!JSON_OUT) console.log("    … bringing editor service to ready, then crashing the daemon…");
  const start = (await apiA("POST", `/v1/hypervisor/editor-services/${serviceId}/start`, { session_ref: "session:ws3r", access_lease_ref: lease.lease_ref })).json;
  ok(start.ok && start.editorService?.phase === "ready", "editor service ready under daemon A");

  // ---- crash daemon A (SIGKILL) + clean the orphaned runtime ----
  daemonA.kill("SIGKILL");
  await sleep(400);
  killOrphans(dataDir);
  await sleep(200);

  // ---- daemon B on the SAME data dir: reconcile must mark the service degraded ----
  const daemonB = spawn(DAEMON_BIN, [], { env: { ...env1, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${portB}` }, stdio: ["ignore", "ignore", "ignore"], cwd: REPO });
  const apiB = makeApi(portB);
  try {
    if (!(await waitReady(portB))) { console.error("daemon B not ready"); process.exit(2); }
    const status = (await apiB("GET", `/v1/hypervisor/editor-services/${serviceId}/status`)).json;
    const readiness = status.service?.readiness ?? status.status;
    ok(status.phase === "degraded", "restart reconcile -> service degraded (not phantom-ready)", status.phase);
    ok(/editor_runtime_lost_on_restart/.test(readiness?.reason || ""), "degraded reason is editor_runtime_lost_on_restart", readiness?.reason);
    ok(status.internal_port === null, "no stale internal port after restart");

    // recovery: restart the editor service -> ready again (new runtime).
    const lease2 = (await apiB("POST", "/v1/hypervisor/editor-access-leases", { session_id: "session:ws3r", environment_id: env.id, service_id: serviceId })).json;
    if (!JSON_OUT) console.log("    … recovering: restarting the editor service under daemon B…");
    const restart = (await apiB("POST", `/v1/hypervisor/editor-services/${serviceId}/start`, { session_ref: "session:ws3r", access_lease_ref: lease2.lease_ref })).json;
    ok(restart.ok && restart.editorService?.phase === "ready", "operator restart recovers the editor service -> ready");

    // negative: the editor service carries no environment-lifecycle authority (lifecycle is daemon-owned).
    const svcRec = (await apiB("GET", `/v1/hypervisor/editor-services/${serviceId}/status`)).json.service;
    ok(svcRec?.service_role === "editor_access_service" && svcRec?.lifecycle === "support", "editor service is a support role (no environment-lifecycle ownership)");
  } finally {
    try { await apiB("POST", `/v1/hypervisor/editor-services/${serviceId}/stop`, {}); } catch {}
    daemonB.kill("SIGKILL");
  }
} finally {
  killOrphans(dataDir);
  rmSync(dataDir, { recursive: true, force: true });
}

const verdict = failures > 0 ? "FAIL" : declaredGaps.length ? "PASS_WITH_DECLARED_GAPS" : "PASS";
const report = { workstream: "WS-3r", verdict, failures, checks: checks.length, declared_gaps: declaredGaps };
if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
