#!/usr/bin/env node
// WS-6b — editor extension install + readiness gate verifier.
//
// Proves the REQUIRED Hypervisor adapter is installed into the browser-IDE host and recognized by
// the runtime, that the bundle allowlist separates required vs optional, and — the key negative —
// that a MISSING required extension FAILS the browser-host readiness gate (no editor without its
// adapter; never a fake ready). Optional baseline extensions stay declared (offline/marketplace).
// Usage: [--json].
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO = new URL("..", import.meta.url).pathname;
const DAEMON_BIN = join(REPO, "target/debug/hypervisor-daemon");
const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const BASE_PORT = 9290 + (process.pid % 50);
const BUNDLES = join(REPO, "scripts/editor-host/extension-bundles.json");

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

if (!JSON_OUT) console.log("WS-6b — editor extension install + readiness gate");

// bundle allowlist: required vs optional.
const bundles = JSON.parse(readFileSync(BUNDLES, "utf8"));
ok(bundles.required?.some((e) => e.extension_id === "ioi.hypervisor-vscode-extension" && e.required === true), "bundle allowlist marks the Hypervisor adapter REQUIRED");
ok((bundles.optional || []).length >= 1 && bundles.optional.every((e) => e.required === false), "optional baseline extensions are declared (required:false)");

// provision (reuse) the OSS runtime; declared gap if unavailable.
const prov = spawnSync("node", [join(REPO, "scripts/provision-hypervisor-vscode-browser-host.mjs"), "--json"], { encoding: "utf8", cwd: REPO, timeout: 320000 });
let provJson = null; try { provJson = JSON.parse((prov.stdout || "").slice((prov.stdout || "").indexOf("{"))); } catch {}
const toolchainDir = process.env.IOI_HYPERVISOR_EDITOR_TOOLCHAIN_DIR || join(process.env.HOME || "", ".ioi/editor-toolchain");
if (!provJson?.ok || !existsSync(join(toolchainDir, "openvscode-server/bin/openvscode-server"))) {
  declaredGaps.push({ gate: "vscode_browser_host", prerequisite: "ASSET_UNAVAILABLE", reason: "OSS runtime not provisionable on this host; extension lane needs the runtime — not faked" });
  const report = { workstream: "WS-6b", verdict: failures ? "FAIL" : "PASS_WITH_DECLARED_GAPS", failures, checks: checks.length, declared_gaps: declaredGaps };
  console.log(JSON_OUT ? JSON.stringify(report, null, 2) : `  declared gap: ASSET_UNAVAILABLE\n  VERDICT: ${report.verdict}`);
  process.exit(failures ? 1 : 0);
}

if (!existsSync(DAEMON_BIN)) { console.error(`daemon binary missing: ${DAEMON_BIN}`); process.exit(2); }

// ---- positive: required adapter installs + gates readiness ----
const dataDir = mkdtempSync(join(tmpdir(), "ioi-ws6b-"));
const portA = BASE_PORT;
const daemonA = spawn(DAEMON_BIN, [], { env: { ...process.env, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${portA}`, IOI_HYPERVISOR_EDITOR_TOOLCHAIN_DIR: toolchainDir }, stdio: ["ignore", "ignore", "ignore"], cwd: REPO });
const apiA = makeApi(portA);
let svcId = null;
try {
  if (!(await waitReady(portA))) { console.error("daemon A not ready"); process.exit(2); }
  const env = (await apiA("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "ws6b" } })).json.environment;
  await apiA("POST", `/v1/hypervisor/environments/${env.id}/start`);
  const svc = (await apiA("POST", "/v1/hypervisor/editor-services", { environment_id: env.id, target_profile: "vscode-browser" })).json.editorService;
  svcId = svc.service_id;
  const lease = (await apiA("POST", "/v1/hypervisor/editor-access-leases", { session_id: "session:ws6b", environment_id: env.id, service_id: svcId })).json;
  if (!JSON_OUT) console.log("    … launching openvscode-server with the required adapter…");
  const start = (await apiA("POST", `/v1/hypervisor/editor-services/${svcId}/start`, { session_ref: "session:ws6b", access_lease_ref: lease.lease_ref })).json;
  ok(start.ok && start.editorService?.phase === "ready", "service ready with the required adapter installed", start.reason);
  ok((start.editorService?.installed_extensions || []).includes("ioi.hypervisor-vscode-extension"), "required Hypervisor adapter installed into the host", (start.editorService?.installed_extensions || []).join(","));
  // the runtime itself recognizes the installed extension (--list-extensions against the per-service dir).
  const extDir = join(dataDir, "editor-services", svcId, "extensions");
  const listed = spawnSync(join(toolchainDir, "openvscode-server/bin/openvscode-server"), ["--extensions-dir", extDir, "--list-extensions"], { encoding: "utf8", timeout: 40000 });
  ok(/ioi\.hypervisor-vscode-extension/.test(listed.stdout || ""), "runtime --list-extensions recognizes the installed adapter", (listed.stdout || "").trim().split("\n")[0]);
} finally {
  if (svcId) { try { await apiA("POST", `/v1/hypervisor/editor-services/${svcId}/stop`, {}); } catch {} }
  daemonA.kill("SIGKILL");
  rmSync(dataDir, { recursive: true, force: true });
}

// ---- negative: a MISSING required extension fails the readiness gate ----
const dataDirB = mkdtempSync(join(tmpdir(), "ioi-ws6b-neg-"));
const portB = BASE_PORT + 1;
const daemonB = spawn(DAEMON_BIN, [], { env: { ...process.env, IOI_HYPERVISOR_DATA_DIR: dataDirB, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${portB}`, IOI_HYPERVISOR_EDITOR_TOOLCHAIN_DIR: toolchainDir, IOI_HYPERVISOR_REQUIRED_EXTENSION_DIR: "/nonexistent/hypervisor-adapter" }, stdio: ["ignore", "ignore", "ignore"], cwd: REPO });
const apiB = makeApi(portB);
let svcIdB = null;
try {
  if (!(await waitReady(portB))) { console.error("daemon B not ready"); process.exit(2); }
  const env = (await apiB("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "ws6b-neg" } })).json.environment;
  await apiB("POST", `/v1/hypervisor/environments/${env.id}/start`);
  const svc = (await apiB("POST", "/v1/hypervisor/editor-services", { environment_id: env.id, target_profile: "vscode-browser" })).json.editorService;
  svcIdB = svc.service_id;
  const start = (await apiB("POST", `/v1/hypervisor/editor-services/${svcIdB}/start`, {})).json;
  ok(start.ok === false && /editor_required_extension_missing/.test(start.reason || ""), "missing required adapter -> readiness FAILS (no editor without its adapter)", start.reason);
  ok(start.editorService?.phase !== "ready", "service does not reach ready without the required adapter", start.editorService?.phase);
} finally {
  if (svcIdB) { try { await apiB("POST", `/v1/hypervisor/editor-services/${svcIdB}/stop`, {}); } catch {} }
  daemonB.kill("SIGKILL");
  rmSync(dataDirB, { recursive: true, force: true });
}

const verdict = failures > 0 ? "FAIL" : declaredGaps.length ? "PASS_WITH_DECLARED_GAPS" : "PASS";
const report = { workstream: "WS-6b", verdict, failures, checks: checks.length, declared_gaps: declaredGaps };
if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
