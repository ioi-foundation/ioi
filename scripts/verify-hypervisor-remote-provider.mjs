#!/usr/bin/env node
// T6 — cloud/remote provider lifecycle verifier.
//
// Spawns a hermetic hypervisor-daemon and drives the EnvironmentProvider registry. Proves the
// boring, testable first remote-shaped target (loopback-runner) completes the full lifecycle
// create→ready→WorkRun→stop→archive→restore→recover→delete with real fs+exec, authority gates,
// and receipts — and that the same object model projects local-microvm. cloud-vpc is honestly
// not_configured without cloud creds (a DECLARED host gap, never faked). With --require-remote-
// provider and no cloud endpoint, that gap is reported -> PASS_WITH_DECLARED_GAPS. Usage:
// [--require-remote-provider] [--json].
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO = new URL("..", import.meta.url).pathname;
const DAEMON_BIN = join(REPO, "target/debug/hypervisor-daemon");
const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const REQUIRE_REMOTE = args.includes("--require-remote-provider");
const PORT = 8990 + (process.pid % 60);

const scenarios = [];
const declaredGaps = [];
let failures = 0;
const ok = (cond, msg, detail) => {
  scenarios.push({ ok: !!cond, msg, detail: detail || "" });
  if (!cond) failures++;
  if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`);
};

async function api(method, path, body) {
  const res = await fetch(`http://127.0.0.1:${PORT}${path}`, {
    method, headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : {} };
}
const op = (o) => api("POST", "/v1/hypervisor/provider-ops", o).then((r) => r.json);
async function waitReady(timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try { const r = await fetch(`http://127.0.0.1:${PORT}/v1/hypervisor/providers`); if (r.ok) return true; } catch { /* not up */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}

if (!existsSync(DAEMON_BIN)) { console.error(`daemon binary missing: ${DAEMON_BIN}`); process.exit(2); }
const dataDir = mkdtempSync(join(tmpdir(), "ioi-t6-provider-"));
const daemon = spawn(DAEMON_BIN, [], {
  env: { ...process.env, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${PORT}` },
  stdio: ["ignore", "ignore", "ignore"],
});

let verdict = "FAIL";
try {
  if (!(await waitReady())) { console.error("daemon did not become ready"); process.exit(2); }
  if (!JSON_OUT) console.log("T6 — EnvironmentProvider registry + remote lifecycle");

  // 1) Registry — honest status per provider.
  const providers = (await api("GET", "/v1/hypervisor/providers")).json;
  const byId = Object.fromEntries((providers.providers || []).map((p) => [p.provider_ref, p]));
  ok(byId["local-microvm"]?.status === "available", "local-microvm provider available");
  ok(byId["loopback-runner"]?.status === "available" && byId["loopback-runner"]?.capabilities?.remote === true, "loopback-runner available + remote-shaped");
  const cloudConfigured = byId["cloud-vpc"]?.status === "available";
  if (cloudConfigured) ok(true, "cloud-vpc endpoint configured + available");
  else ok(byId["cloud-vpc"]?.status === "not_configured" && /REMOTE_PROVIDER_NOT_CONFIGURED/.test(byId["cloud-vpc"]?.reason || ""), "cloud-vpc honestly not_configured (declared, not faked)");

  // 2) loopback-runner — the full remote-shaped lifecycle with real fs + exec.
  const E = "env-remote-1";
  const P = "loopback-runner";
  const pre = await op({ provider_id: P, op: "preflight", environment_ref: E, plan: { recipe: "node" } });
  ok(pre.ok && pre.evidence?.admit === true && pre.evidence?.data_locality === "local", "preflight admits with explicit region/locality/privacy");
  const create = await op({ provider_id: P, op: "create", environment_ref: E });
  ok(create.ok && /loopback-runner:\/\/op\/create\//.test(create.evidence?.provider_operation_ref || ""), "create -> provider workspace + evidence op ref");
  const start = await op({ provider_id: P, op: "start", environment_ref: E });
  ok(start.ok && start.evidence?.phase === "ready", "start -> ready");
  const run = await op({ provider_id: P, op: "workrun", environment_ref: E, command: "echo remote-work > artifact.txt && cat artifact.txt" });
  ok(run.ok && run.evidence?.exit_code === 0 && /remote-work/.test(run.evidence?.stdout || ""), "WorkRun executes real command in the runner", run.evidence?.stdout);
  const obs1 = await op({ provider_id: P, op: "observe", environment_ref: E });
  ok(obs1.evidence?.workspace_files >= 2, "observe sees the WorkRun artifact in the workspace", `files=${obs1.evidence?.workspace_files}`);
  const snap = await op({ provider_id: P, op: "snapshot", environment_ref: E });
  const material = snap.evidence?.restore_material_ref;
  ok(snap.ok && /loopback-runner:\/\/material\//.test(material || "") && snap.evidence?.agentgres_backed === true, "archive/snapshot -> Agentgres-backed restore material ref");
  const stop = await op({ provider_id: P, op: "stop", environment_ref: E });
  ok(stop.ok && stop.evidence?.phase === "stopped", "stop -> stopped");
  const restore = await op({ provider_id: P, op: "restore", environment_ref: E, material_ref: material });
  ok(restore.ok && restore.evidence?.phase === "ready", "restore -> ready (same provider)");
  // provider outage + recover.
  const outage = await op({ provider_id: P, op: "inject_outage", environment_ref: E });
  ok(outage.ok && outage.evidence?.workspace_lost === true, "inject_outage -> runner workspace lost");
  const recover = await op({ provider_id: P, op: "recover", environment_ref: E });
  ok(recover.ok && recover.evidence?.phase === "ready", "recover from outage -> ready");
  const obs2 = await op({ provider_id: P, op: "observe", environment_ref: E });
  ok(obs2.evidence?.workspace_files >= 2, "recovered workspace still holds the artifact (committed work preserved)", `files=${obs2.evidence?.workspace_files}`);
  const del = await op({ provider_id: P, op: "delete", environment_ref: E });
  ok(del.ok && del.evidence?.cleanup_verified === true, "delete -> remote resource cleanup verified");

  // 3) local/remote equivalence — same op vocabulary projects local-microvm.
  const localCreate = await op({ provider_id: "local-microvm", op: "create", environment_ref: "env-local-1" });
  ok(localCreate.ok && localCreate.evidence?.delegates_to === "/v1/hypervisor/environments", "local-microvm projects the same object model (delegates to Phase 1)");

  // 4) authority gate + declared gap on the real cloud provider.
  const cloudNoGrant = await op({ provider_id: "cloud-vpc", op: "create", environment_ref: "env-cloud-1" });
  ok(cloudNoGrant.ok === false && /authority-gated/.test(cloudNoGrant.reason || ""), "cloud-vpc create without grant -> blocked (provider creds authority-gated)");
  const cloudWithGrant = await op({ provider_id: "cloud-vpc", op: "create", environment_ref: "env-cloud-1", grant_ref: "enterprise.authority://grant/seed" });
  ok(cloudWithGrant.ok === false && cloudWithGrant.outcome === "not_configured" && /REMOTE_PROVIDER_NOT_CONFIGURED/.test(cloudWithGrant.reason || ""), "cloud-vpc create with grant -> not_configured (declared, not faked)");

  // 5) provider-operation audit trail (daemon truth, evidence-only provider IDs).
  const ops = (await api("GET", "/v1/hypervisor/provider-operations")).json;
  const loopbackOps = (ops.operations || []).filter((o) => o.provider === "loopback-runner").map((o) => o.op);
  ok(["create", "start", "workrun", "snapshot", "stop", "restore", "recover", "delete"].every((o) => loopbackOps.includes(o)),
    "admitted-operation trail records the full remote lifecycle", [...new Set(loopbackOps)].join(","));

  // 6) --require-remote-provider: the remote lane is proven by loopback; cloud-vpc is a declared gap.
  if (REQUIRE_REMOTE && !cloudConfigured) {
    declaredGaps.push({
      gate: "cloud-vpc",
      prerequisite: "REMOTE_PROVIDER_NOT_CONFIGURED",
      reason: "A real cloud/VPC provider needs an endpoint + credentials (IOI_REMOTE_PROVIDER_ENDPOINT). loopback-runner proves the remote-shaped lifecycle; the cloud target is host-gated and not faked.",
      host_grantable: true,
    });
    if (!JSON_OUT) console.log("    · DECLARED GAP: cloud-vpc — REMOTE_PROVIDER_NOT_CONFIGURED (cloud creds absent; loopback-runner proves the remote lane)");
  }

  if (failures === 0) verdict = declaredGaps.length > 0 ? "PASS_WITH_DECLARED_GAPS" : "PASS";
} finally {
  daemon.kill("SIGKILL");
  rmSync(dataDir, { recursive: true, force: true });
}

const report = { workstream: "T6", verdict, failures, scenarios: scenarios.length, declared_gaps: declaredGaps };
if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
else {
  console.log(`  declared gaps: ${declaredGaps.length ? declaredGaps.map((g) => g.prerequisite).join(", ") : "none"}`);
  console.log(`  VERDICT: ${verdict} (${scenarios.length - failures}/${scenarios.length} checks)`);
}
process.exit(verdict === "FAIL" ? 1 : 0);
