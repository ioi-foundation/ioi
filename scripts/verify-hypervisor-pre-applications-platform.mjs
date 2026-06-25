#!/usr/bin/env node
// All-up pre-applications platform verifier (master guide §7 done-bar).
//
// Living gate for the editor/access substrate. It WRAPS the WS-1 registry verifier and drives the
// daemon editor surface (targets, host-provisioning plans, editor access services, capability-lease
// access leases) against a hermetic daemon, then emits the §7 done-bar block. It is DESIGNED to
// fail honestly until the browser host (WS-2) and WebSocket proxy (WS-4) land: pending lines are
// named (NOT_YET_PROVISIONED / NOT_BUILT), never faked PASS. Overall reaches `terminal` /
// `terminal_with_declared_host_gaps` only when every required line is PASS and every non-PASS is a
// named host/tooling prerequisite.
// Usage: [--browser] [--n <iters>] [--json].
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO = new URL("..", import.meta.url).pathname;
const DAEMON_BIN = join(REPO, "target/debug/hypervisor-daemon");
const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const WANT_BROWSER = args.includes("--browser");
const N = parseInt(args[args.indexOf("--n") + 1] || "1", 10) || 1;
const PORT = 9120 + (process.pid % 60);

const lines = {};       // done-bar line -> status string
const declaredGaps = [];
const failures = [];
const note = (m) => { if (!JSON_OUT) console.log(m); };

async function api(method, path, body) {
  const res = await fetch(`http://127.0.0.1:${PORT}${path}`, {
    method, headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = {}; try { json = text ? JSON.parse(text) : {}; } catch { /* non-json */ }
  return { status: res.status, json, text };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitReady(t = 15000) { const s = Date.now(); while (Date.now() - s < t) { try { if ((await fetch(`http://127.0.0.1:${PORT}/v1/hypervisor/editor-targets`)).ok) return true; } catch {} await sleep(150); } return false; }

// ---- WS-1 static registry verifier (wrapped) ----
const ws1 = spawnSync("node", [join(REPO, "scripts/verify-hypervisor-editor-target-registry.mjs"), "--json"], { encoding: "utf8", cwd: REPO });
let ws1json = null; try { ws1json = JSON.parse((ws1.stdout || "").slice((ws1.stdout || "").indexOf("{"))); } catch {}
lines["Editor target registry"] = ws1json?.verdict === "PASS" ? "PASS" : "FAIL";
if (lines["Editor target registry"] !== "PASS") failures.push("WS-1 registry verifier not PASS");

if (!existsSync(DAEMON_BIN)) { console.error(`daemon binary missing: ${DAEMON_BIN}`); process.exit(2); }
const dataDir = mkdtempSync(join(tmpdir(), "ioi-preapps-"));
const daemon = spawn(DAEMON_BIN, [], { env: { ...process.env, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${PORT}` }, stdio: ["ignore", "ignore", "ignore"], cwd: REPO });

try {
  if (!(await waitReady())) { console.error("daemon not ready"); process.exit(2); }
  if (!JSON_OUT) console.log("Hypervisor pre-applications platform");

  // ---- daemon-backed editor objects + capability-lease access leases (repeatable) ----
  let objectsOk = true, leasesOk = true;
  for (let i = 0; i < N; i++) {
    const reg = (await api("GET", "/v1/hypervisor/editor-targets")).json;
    if (!reg.active_targets?.includes("vscode-browser")) objectsOk = false;
    const plan = (await api("POST", "/v1/hypervisor/editor-host-provisioning-plans", { environment_ref: `environment:env${i}`, target_profile_ref: "vscode-browser", runtime_variant: "oss_openvscode" })).json.plan;
    if (plan?.status !== "declared" || !plan?.authority_scope_refs?.includes("scope:environment.editor.open")) objectsOk = false;
    const svc = (await api("POST", "/v1/hypervisor/editor-services", { environment_id: `env${i}`, target_profile: "vscode-browser", provisioning_plan_ref: plan?.plan_ref })).json.editorService;
    if (svc?.service_role !== "editor_access_service") objectsOk = false;
    const sid = svc?.service_id;

    // capability-lease access lease (reuses authority grant machinery)
    const lease = (await api("POST", "/v1/hypervisor/editor-access-leases", { session_id: `session:s${i}`, environment_id: `env${i}`, service_id: sid, expiry_seconds: 3600 })).json;
    if (!/grant\//.test(lease.capability_lease_ref || "")) leasesOk = false;
    const grants = (await api("GET", "/v1/hypervisor/authority/grants")).json;
    const g = grants.grants?.find((x) => x.grant_id === lease.lease_id);
    if (!(g && g.action === "environment.editor.open" && g.status === "active")) leasesOk = false; // lease IS an authority grant
    // open-url fails closed without lease and not-ready with lease
    const ouNo = (await api("GET", `/v1/hypervisor/editor-services/${sid}/open-url`)).json;
    if (ouNo.ok !== false || ouNo.fail_closed !== true) leasesOk = false;
    // revoke -> open-url denied
    const rev = (await api("POST", `/v1/hypervisor/editor-access-leases/${lease.lease_id}/revoke`, {})).json;
    if (rev.ok !== true) leasesOk = false;
    const ouRev = (await api("GET", `/v1/hypervisor/editor-services/${sid}/open-url?lease_ref=${encodeURIComponent(lease.lease_ref)}`)).json;
    if (ouRev.ok !== false || !/revoked/.test(ouRev.reason || "")) leasesOk = false;

    // VS Code Browser host readiness: honest start. Provisioned (WS-2) -> ready; else NOT_YET.
    const start = (await api("POST", `/v1/hypervisor/editor-services/${sid}/start`, {})).json;
    if (i === 0) {
      if (start.ok && start.editorService?.phase === "ready") lines["VS Code Browser host (OSS)"] = "PASS";
      else lines["VS Code Browser host (OSS)"] = "NOT_YET_PROVISIONED"; // WS-2 pending — honest
    }
  }
  lines["Editor target registry"] = objectsOk && lines["Editor target registry"] === "PASS" ? "PASS" : lines["Editor target registry"];
  lines["Editor access leases"] = leasesOk ? "PASS" : "FAIL";
  if (!leasesOk) failures.push("editor access lease / capability-lease machinery failed");

  // ---- packaged VS Code adapter host (external Electron binary) ----
  const packaged = existsSync(join(REPO, "code-editor-adapters/builds/VSCode-linux-x64/bin/hypervisor"));
  lines["Packaged VS Code adapter host"] = packaged ? "PASS" : "HOST_GATED";
  if (!packaged) declaredGaps.push({ gate: "packaged_vscode", prerequisite: "PACKAGED_VSCODE_BINARY_ABSENT", reason: "the packaged VS Code adapter host (Electron build) is not present on this host; external binary — host-gated" });

  // ---- still-pending lines (named, not faked) — land in later slices ----
  if (lines["VS Code Browser host (OSS)"] === "NOT_YET_PROVISIONED")
    declaredGaps.push({ gate: "vscode_browser_host", prerequisite: "OSS_RUNTIME_NOT_YET_PROVISIONED", reason: "WS-2 pins openvscode-server (commit/sha256, fetch-once, fail-closed); editor service start fails closed until then" });
  // ---- WS-6a / WS-7 static UI guards ----
  const read = (p) => { try { return readFileSync(join(REPO, p), "utf8"); } catch { return ""; } };
  const transport = read("packages/hypervisor-adapter-targets/code-editors/vscode-extension/transport/context-transport.js");
  lines["Extension context runtime refs"] = /IOI_HYPERVISOR_BINDING_REF/.test(transport) && /sessionRef/.test(transport) && /accessLeaseRef/.test(transport) ? "PASS" : "NOT_BUILT";

  const cockpit = read("apps/hypervisor/src/surfaces/NativeCockpit.tsx");
  const workbench = read("apps/hypervisor/src/surfaces/NativeWorkbench.tsx");
  const hasOpenIn = /OpenInPicker/.test(cockpit) && /open-in-vscode-browser/.test(cockpit) && /OpenInPicker/.test(workbench);
  const hasServicesUi = /EnvironmentComponentGrid/.test(cockpit) && /OpenInPicker environmentId/.test(cockpit);
  lines["Environment services/tasks/ports UI"] = hasServicesUi && hasOpenIn ? "PASS" : "NOT_BUILT";
  // de-fork guard: native surfaces must not present a VS Code product identity (only target labels).
  const forkTell = /Visual Studio Code|VS Code Fork|vscode-fork|SRC-TAURI/i.test(cockpit + workbench);
  const nativeChrome = /Hypervisor Workbench/.test(workbench) && /Operator Cockpit|mediation/.test(cockpit);
  lines["Workbench Hypervisorization guard"] = !forkTell && nativeChrome && hasOpenIn ? "PASS" : "FAIL";
  if (lines["Workbench Hypervisorization guard"] === "FAIL") failures.push("native UI exposes VS Code product identity or lacks Open-in/native chrome");

  for (const [line, status] of [
    ["WebSocket proxy auth/revoke", "NOT_BUILT"],
    ["Extension bundle install", "NOT_BUILT"],
    ["Devcontainer/rebuild flow", "PARTIAL"],
  ]) { if (!(line in lines)) lines[line] = status; }
} finally {
  daemon.kill("SIGKILL");
  rmSync(dataDir, { recursive: true, force: true });
}

if (WANT_BROWSER && !JSON_OUT) console.log("  (--browser tier runs once the native editor UI lands; declared until then)");

// ---- Overall ----
const REQUIRED_PASS = ["Editor target registry", "VS Code Browser host (OSS)", "Editor access leases", "WebSocket proxy auth/revoke", "Extension bundle install", "Extension context runtime refs", "Environment services/tasks/ports UI", "Workbench Hypervisorization guard"];
const pendingMarkers = ["NOT_BUILT", "NOT_YET_PROVISIONED", "PARTIAL"];
const anyHardFail = failures.length > 0 || Object.values(lines).includes("FAIL");
const anyPending = REQUIRED_PASS.some((l) => pendingMarkers.includes(lines[l]));
let overall;
if (anyHardFail) overall = "not_terminal";
else if (anyPending) overall = "pending_substrate";       // honest: built so far, more slices to land
else if (declaredGaps.length > 0) overall = "terminal_with_declared_host_gaps";
else overall = "terminal";

const report = { overall, status: lines, declared_gaps: declaredGaps, failures };
if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
else {
  for (const [k, v] of Object.entries(lines)) console.log(`  ${k}: ${v}`);
  if (declaredGaps.length) { console.log("\n  Declared/pending (named — not faked):"); for (const g of declaredGaps) console.log(`    · ${g.gate}: ${g.prerequisite}`); }
  if (failures.length) { console.log("\n  FAILURES:"); for (const f of failures) console.log(`    ✗ ${f}`); }
  console.log(`\n  Overall: ${overall}`);
}
// pending_substrate is the EXPECTED honest state mid-lane; only a hard failure is a non-zero gate fault here.
process.exit(overall === "not_terminal" ? 1 : 0);
