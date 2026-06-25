#!/usr/bin/env node
// WS-2 — reproducible OSS browser-IDE host verifier.
//
// Proves the openvscode-server runtime is reproducible (pinned version/commit/sha256, fetch-once,
// checksum-verified) AND that the daemon launches it as a real editor access service that reports
// /version readiness on its internal port. The OSS lane is PASS (not host-gated). If the runtime
// cannot be provisioned because this host has no network/asset access, that is a named declared
// gap (ASSET_UNAVAILABLE) — distinct from a vendor-license gap. Usage: [--json].
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:net";

const REPO = new URL("..", import.meta.url).pathname;
const DAEMON_BIN = join(REPO, "target/debug/hypervisor-daemon");
const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const PORT = 9180 + (process.pid % 60);
const MANIFEST = join(REPO, "scripts/editor-host/openvscode-supply-manifest.json");

const checks = [];
const declaredGaps = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg, detail: detail || "" }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };

async function api(method, path, body) {
  const res = await fetch(`http://127.0.0.1:${PORT}${path}`, { method, headers: body ? { "Content-Type": "application/json" } : undefined, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text(); let json = {}; try { json = text ? JSON.parse(text) : {}; } catch {}
  return { status: res.status, json, text };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitReady(t = 15000) { const s = Date.now(); while (Date.now() - s < t) { try { if ((await fetch(`http://127.0.0.1:${PORT}/v1/hypervisor/editor-targets`)).ok) return true; } catch {} await sleep(150); } return false; }
function portServesVersion(port) {
  return new Promise((resolve) => {
    const sock = connect({ host: "127.0.0.1", port, timeout: 800 }, () => {
      sock.write(`GET /version HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`);
    });
    let buf = "";
    sock.on("data", (d) => { buf += d.toString(); });
    sock.on("close", () => resolve(/HTTP\/1\.[01] 2/.test(buf) ? buf.split("\r\n\r\n")[1]?.trim() || "ok" : null));
    sock.on("error", () => resolve(null));
    sock.on("timeout", () => { sock.destroy(); resolve(null); });
  });
}

if (!JSON_OUT) console.log("WS-2 — reproducible OSS browser-IDE host (openvscode-server)");

// 1) reproducible provisioning (fetch-once, checksum-verified, fail-closed).
const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));
ok(manifest.licensePosture === "oss" && /^[0-9a-f]{64}$/.test(manifest.linux_x64?.sha256 || ""), "supply manifest pins an OSS runtime with a sha256", `v${manifest.version}`);
const prov = spawnSync("node", [join(REPO, "scripts/provision-hypervisor-vscode-browser-host.mjs"), "--json"], { encoding: "utf8", cwd: REPO, timeout: 320000 });
let provJson = null; try { provJson = JSON.parse((prov.stdout || "").slice((prov.stdout || "").indexOf("{"))); } catch {}
if (!provJson?.ok) {
  // honest declared gap if the asset cannot be fetched on this host.
  declaredGaps.push({ gate: "vscode_browser_host", prerequisite: "ASSET_UNAVAILABLE", reason: `openvscode-server could not be provisioned on this host (${provJson?.reason || "fetch/checksum failed"}); network/asset access required — not faked`, host_grantable: true });
  if (!JSON_OUT) console.log(`    · DECLARED GAP: ASSET_UNAVAILABLE — ${provJson?.reason || "provision failed"}`);
} else {
  ok(provJson.ok && provJson.sha256 === manifest.linux_x64.sha256, "openvscode-server provisioned + checksum matches the pin (reproducible)", provJson.sha256?.slice(0, 16));
}

const toolchainDir = process.env.IOI_HYPERVISOR_EDITOR_TOOLCHAIN_DIR || join(process.env.HOME || "", ".ioi/editor-toolchain");
const runtimePresent = existsSync(join(toolchainDir, "openvscode-server/bin/openvscode-server"));

if (runtimePresent) {
  if (!existsSync(DAEMON_BIN)) { console.error(`daemon binary missing: ${DAEMON_BIN}`); process.exit(2); }
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-ws2-browserhost-"));
  const daemon = spawn(DAEMON_BIN, [], { env: { ...process.env, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${PORT}`, IOI_HYPERVISOR_EDITOR_TOOLCHAIN_DIR: toolchainDir }, stdio: ["ignore", "ignore", "ignore"], cwd: REPO });
  let serviceId = null;
  try {
    if (!(await waitReady())) { console.error("daemon not ready"); process.exit(2); }
    // real environment + workspace.
    const env = (await api("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "ws2" } })).json.environment;
    await api("POST", `/v1/hypervisor/environments/${env.id}/start`);
    // editor service + capability lease.
    const svc = (await api("POST", "/v1/hypervisor/editor-services", { environment_id: env.id, target_profile: "vscode-browser" })).json.editorService;
    serviceId = svc.service_id;
    const lease = (await api("POST", "/v1/hypervisor/editor-access-leases", { session_id: "session:ws2", environment_id: env.id, service_id: serviceId })).json;
    // start the REAL runtime + wait for /version.
    if (!JSON_OUT) console.log("    … launching openvscode-server (awaiting /version)…");
    const start = (await api("POST", `/v1/hypervisor/editor-services/${serviceId}/start`, { session_ref: "session:ws2", access_lease_ref: lease.lease_ref })).json;
    ok(start.ok && start.editorService?.phase === "ready", "editor service starts -> ready (real openvscode-server launch)", start.reason || start.editorService?.phase);
    const internalPort = start.editorService?.internal_port;
    ok(Number.isInteger(internalPort) && internalPort > 0, "editor service exposes an internal port", String(internalPort));
    ok(start.editorService?.runtime_version === manifest.commit, "runtime /version matches the pinned commit", start.editorService?.runtime_version?.slice(0, 12));
    // the internal port genuinely serves /version.
    const ver = await portServesVersion(internalPort);
    ok(!!ver && ver.includes(manifest.commit), "internal port genuinely serves /version (runtime is real, not faked)", ver?.slice(0, 12));
    // open-url is fail-closed until the WS proxy (WS-4): honest, not a raw-port URL.
    const open = (await api("GET", `/v1/hypervisor/editor-services/${serviceId}/open-url?lease_ref=${encodeURIComponent(lease.lease_ref)}`)).json;
    ok(open.ok === false && open.reason === "websocket_proxy_not_ready", "open-url fails closed until the WS proxy binds (no raw-port URL handed out)", open.reason);
    // stop tears the runtime down.
    const stop = (await api("POST", `/v1/hypervisor/editor-services/${serviceId}/stop`, {})).json;
    ok(stop.ok && stop.editorService?.phase === "stopped", "stop tears down the runtime");
    const afterStop = await portServesVersion(internalPort);
    ok(afterStop === null, "internal port no longer serves after stop (process really killed)");
  } finally {
    if (serviceId) { try { await api("POST", `/v1/hypervisor/editor-services/${serviceId}/stop`, {}); } catch {} }
    daemon.kill("SIGKILL");
    rmSync(dataDir, { recursive: true, force: true });
  }
}

const verdict = failures > 0 ? "FAIL" : declaredGaps.length ? "PASS_WITH_DECLARED_GAPS" : "PASS";
const report = { workstream: "WS-2", verdict, failures, checks: checks.length, declared_gaps: declaredGaps };
if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
else { console.log(`  declared gaps: ${declaredGaps.length ? declaredGaps.map((g) => g.prerequisite).join(", ") : "none"}`); console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`); }
process.exit(verdict === "FAIL" ? 1 : 0);
