#!/usr/bin/env node
// T5 — Resource Management verifier (capacity + budget scheduling).
//
// Spawns a hermetic hypervisor-daemon and injects every shock the guide's done-bar requires —
// capacity shock, budget exhaustion, quota/rate limit, preemption, catch-up, and a budget increase
// that is an authority crossing — proving each yields a typed allocation DECISION + visible reason
// + receipt, never a silent provider error. Uses a fresh pool/budget per scenario for determinism.
// Usage: [--json].
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO = new URL("..", import.meta.url).pathname;
const DAEMON_BIN = join(REPO, "target/debug/hypervisor-daemon");
const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const PORT = 8930 + (process.pid % 60);

const scenarios = [];
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
async function waitReady(timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try { const r = await fetch(`http://127.0.0.1:${PORT}/v1/hypervisor/resource/pools`); if (r.ok) return true; } catch { /* not up */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}
const pool = (o) => api("POST", "/v1/hypervisor/resource/pools", o).then((r) => r.json.pool);
const budget = (o) => api("POST", "/v1/hypervisor/resource/budgets", o).then((r) => r.json.budget);
const allocate = (o) => api("POST", "/v1/hypervisor/resource/allocate", o).then((r) => r.json.decision);

if (!existsSync(DAEMON_BIN)) { console.error(`daemon binary missing: ${DAEMON_BIN}`); process.exit(2); }
const dataDir = mkdtempSync(join(tmpdir(), "ioi-t5-resource-"));
const daemon = spawn(DAEMON_BIN, [], {
  env: { ...process.env, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${PORT}` },
  stdio: ["ignore", "ignore", "ignore"],
});

let verdict = "FAIL";
try {
  if (!(await waitReady())) { console.error("daemon did not become ready"); process.exit(2); }
  if (!JSON_OUT) console.log("T5 — resource pools/budgets + allocation decision engine");

  // baseline admit.
  await pool({ pool_id: "A", capacity: { cpu: 4, memory_mb: 4096 }, quota: { max_concurrent: 10 } });
  const admit = await allocate({ pool_ref: "A", needs: { cpu: 4, memory_mb: 4096 }, priority: 5 });
  ok(admit.decision === "admit" && admit.state === "admitted", "baseline allocation -> admit", admit.decision);

  // 1) capacity shock -> queue.
  const queued = await allocate({ pool_ref: "A", needs: { cpu: 2, memory_mb: 2048 }, priority: 5 });
  ok(queued.decision === "queue" && queued.reason === "capacity_exhausted", "capacity shock -> queue (capacity_exhausted)", queued.reason);
  const wq = (await api("GET", "/v1/hypervisor/resource/work-queue")).json;
  ok(wq.depth >= 1, "work queue holds the blocked request", `depth=${wq.depth}`);

  // 2) degrade.
  await pool({ pool_id: "B", capacity: { cpu: 4, memory_mb: 4096 } });
  await allocate({ pool_ref: "B", needs: { cpu: 3, memory_mb: 3072 }, priority: 5 });
  const degraded = await allocate({ pool_ref: "B", needs: { cpu: 4, memory_mb: 4096 }, priority: 5, degradable: true });
  ok(degraded.decision === "degrade" && degraded.granted_needs?.cpu === 1, "over-capacity degradable -> degrade to fit", `cpu=${degraded.granted_needs?.cpu}`);

  // 3) preemption.
  await pool({ pool_id: "C", capacity: { cpu: 4, memory_mb: 4096 } });
  const victim = await allocate({ pool_ref: "C", needs: { cpu: 4, memory_mb: 4096 }, priority: 1 });
  const preempt = await allocate({ pool_ref: "C", needs: { cpu: 4, memory_mb: 4096 }, priority: 9 });
  ok(preempt.decision === "preempt" && preempt.reason === "lower_priority_preempted", "high-priority over full pool -> preempt", preempt.reason);
  ok(preempt.detail?.preempted_decision === victim.decision_id, "preempt names the lower-priority victim");

  // 4) quota.
  await pool({ pool_id: "D", capacity: { cpu: 100, memory_mb: 100000 }, quota: { max_concurrent: 1 } });
  await allocate({ pool_ref: "D", needs: { cpu: 1, memory_mb: 512 }, priority: 5 });
  const quota = await allocate({ pool_ref: "D", needs: { cpu: 1, memory_mb: 512 }, priority: 5 });
  ok(quota.decision === "queue" && quota.reason === "quota_exhausted", "concurrency quota -> queue (quota_exhausted)", quota.reason);

  // 5) rate limit.
  await pool({ pool_id: "E", capacity: { cpu: 100, memory_mb: 100000 } });
  const rate = await allocate({ pool_ref: "E", needs: { cpu: 1, memory_mb: 512 }, priority: 5, rate_limited: true });
  ok(rate.decision === "queue" && rate.reason === "rate_limited", "rate limit -> queue (rate_limited)", rate.reason);

  // 6) provider health: maintenance -> pause; unhealthy + candidate -> shift_provider; else fail_closed.
  await pool({ pool_id: "F", capacity: { cpu: 8, memory_mb: 8192 }, health: "maintenance" });
  const paused = await allocate({ pool_ref: "F", needs: { cpu: 1, memory_mb: 512 } });
  ok(paused.decision === "pause" && paused.reason === "maintenance_window", "maintenance pool -> pause (maintenance_window)", paused.reason);
  await pool({ pool_id: "G", capacity: { cpu: 8, memory_mb: 8192 }, health: "unhealthy" });
  await pool({ pool_id: "H", capacity: { cpu: 8, memory_mb: 8192 }, health: "healthy" });
  const shifted = await allocate({ pool_ref: "G", needs: { cpu: 1, memory_mb: 512 }, provider_candidates: ["H"] });
  ok(shifted.decision === "shift_provider" && shifted.detail?.shift_to === "H", "unhealthy pool + healthy candidate -> shift_provider", shifted.reason);
  const noShift = await allocate({ pool_ref: "G", needs: { cpu: 1, memory_mb: 512 } });
  ok(noShift.decision === "fail_closed" && noShift.reason === "provider_unhealthy", "unhealthy pool, no candidate -> fail_closed (provider_unhealthy)", noShift.reason);

  // 7) privacy / data locality.
  await pool({ pool_id: "P", capacity: { cpu: 8, memory_mb: 8192 }, locality: "local" });
  const priv = await allocate({ pool_ref: "P", needs: { cpu: 1, memory_mb: 512 }, privacy: "remote" });
  ok(priv.decision === "fail_closed" && priv.reason === "privacy_or_data_locality_block", "privacy/locality mismatch -> fail_closed", priv.reason);

  // 8) budget exhaustion (local hard cap -> fail_closed).
  await pool({ pool_id: "I", capacity: { cpu: 100, memory_mb: 100000 } });
  await budget({ budget_id: "bl", scope: "local_free", limit: 10, spent: 10 });
  const localBudget = await allocate({ pool_ref: "I", needs: { cpu: 1, memory_mb: 512 }, budget_ref: "bl", estimated_cost: 50 });
  ok(localBudget.decision === "fail_closed" && localBudget.reason === "budget_exhausted", "exhausted local budget -> fail_closed (budget_exhausted)", localBudget.reason);

  // 9) authority missing for external spend.
  await budget({ budget_id: "be", scope: "external_spend", limit: 1000, spent: 0 });
  const noAuth = await allocate({ pool_ref: "I", needs: { cpu: 1, memory_mb: 512 }, budget_ref: "be", spend_scope: "external_spend", estimated_cost: 50 });
  ok(noAuth.decision === "fail_closed" && noAuth.reason === "authority_missing", "external spend without grant -> fail_closed (authority_missing)", noAuth.reason);

  // 10) budget increase requiring wallet grant: exhausted external budget + grant -> request_budget,
  //     then the real authority crossing (enterprise grant for spend) + budget raise -> admit.
  await budget({ budget_id: "be2", scope: "external_spend", limit: 10, spent: 10 });
  const reqBudget = await allocate({ pool_ref: "I", needs: { cpu: 1, memory_mb: 512 }, budget_ref: "be2", spend_scope: "external_spend", grant_ref: "enterprise.authority://grant/seed", estimated_cost: 50 });
  ok(reqBudget.decision === "request_budget" && reqBudget.reason === "budget_exhausted", "exhausted external budget -> request_budget (budget increase)", reqBudget.reason);
  ok(reqBudget.detail?.authority_crossing?.effect === "spend", "request_budget flags the spend authority crossing");
  // complete the crossing with a REAL enterprise grant, raise the budget, re-allocate -> admit.
  const grant = (await api("POST", "/v1/hypervisor/authority/grant", { subject: "session:s1", action: "spend", budget: { spend: 50 } })).json.grant;
  ok(grant?.decision === "granted", "enterprise authority grants the budget-increase spend crossing");
  await budget({ budget_id: "be2", scope: "external_spend", limit: 100, spent: 10 }); // increase after grant
  const afterIncrease = await allocate({ pool_ref: "I", needs: { cpu: 1, memory_mb: 512 }, budget_ref: "be2", spend_scope: "external_spend", grant_ref: grant?.grant_ref, estimated_cost: 50 });
  ok(afterIncrease.decision === "admit", "after granted budget increase -> allocation admits", afterIncrease.decision);

  // 11) scheduler catch-up decisions.
  const catchFull = (await api("POST", "/v1/hypervisor/resource/catchup", { missed_schedule_ref: "sched:nightly", work_ref: "wr:1", policy: "catch_up" })).json.catchup;
  ok(catchFull?.policy === "catch_up" && catchFull?.expected_impact?.verified_work_delta === "full", "catch-up policy -> full catch-up decision + impact");
  const catchBudget = (await api("POST", "/v1/hypervisor/resource/catchup", { missed_schedule_ref: "sched:nightly", work_ref: "wr:2", policy: "request_budget" })).json.catchup;
  ok(catchBudget?.expected_impact?.verified_work_delta === "pending_authority", "catch-up request_budget -> pending authority crossing");

  // 12) receipts: every decision is on the audit trail (no silent provider errors).
  const receipts = (await api("GET", "/v1/hypervisor/resource/receipts")).json;
  const decisionsSeen = new Set((receipts.receipts || []).filter((r) => r.event === "allocation_decision").map((r) => r.decision));
  ok(["admit", "queue", "degrade", "preempt", "pause", "shift_provider", "fail_closed", "request_budget"].every((d) => decisionsSeen.has(d)),
    "receipt trail covers all 8 decision kinds", [...decisionsSeen].sort().join(","));

  if (failures === 0) verdict = "PASS";
} finally {
  daemon.kill("SIGKILL");
  rmSync(dataDir, { recursive: true, force: true });
}

const report = { workstream: "T5", verdict, failures, scenarios: scenarios.length };
if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
else console.log(`  VERDICT: ${verdict} (${scenarios.length - failures}/${scenarios.length} checks)`);
process.exit(verdict === "PASS" ? 0 : 1);
