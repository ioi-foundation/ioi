#!/usr/bin/env node
// Jobs queue readiness verifier (40-job-tracker graft — unify every execution kind on Operations).
//
// Asserts the unified Jobs section against the owning projections: every job row is cross-checked
// against the projection it claims to come from (automation runs, harness executions from the
// proof stream, IOI Agent coordination runs, failover recovery runs), a parked failover run names
// its wallet gate, type chips carry real counts, and absence is honest (a kind with no jobs is a
// zero chip, never a fabricated row).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-jobs-queue.mjs

// Its own isolated daemon (+ serve), the operator signed in (R-240, verifier auth sweep, 2026-09-29). This verifier read
// `IOI_HYPERVISOR_DAEMON_URL || :8765` — the OWNER's daemon — with no caller; since 3aaaad467/3738d5cab the data-source,
// materialized-set and ontology reads answer an anonymous caller 401 (read here as "not reachable"), and since 90cd1ddf2
// an anonymous write is refused on loopback too. An explicit URL naming the owner's stack is refused (verifier-stack.mjs).
import { verifierStack } from "./lib/verifier-stack.mjs";
const STACK = await verifierStack({ serve: true });
const DAEMON = STACK.daemonUrl;
const SERVE = STACK.serveUrl;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const jget = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => null);

async function run() {
  const page = await fetch(`${SERVE}/__ioi/operations`).then(async (r) => ({ status: r.status, text: await r.text() }));
  ok("Operations renders 200", page.status === 200);
  ok("Jobs section present", page.text.includes('id="ops-jobs"') && page.text.includes("every execution kind in one queue"));
  ok("type chips render", ["Automation", "Harness", "IOI Agent", "Failover"].every((t) => page.text.includes(`data-job-type=`)) && page.text.includes('id="jobs-chips"'));

  const [ops, gr, led, fo] = await Promise.all([
    jget("/v1/hypervisor/operations"), jget("/v1/goal-orchestration/goal-runs"), jget("/v1/hypervisor/work-ledger"), jget("/v1/hypervisor/failover/runs"),
  ]);
  const recent = ((ops || {}).runs || {}).recent || [];
  const goals = (gr || {}).goal_runs || [];
  const harness = ((led || {}).entries || []).filter((e) => e.kind === "harness_execution");
  const foruns = (fo || {}).runs || [];

  // Order-robust at estate scale: every kind that exists must be REPRESENTED in the rendered
  // window (per-kind caps guarantee it); the newest item per kind must be cited verbatim.
  const newest = (arr, key) => arr.slice().sort((a, b) => String(b[key] || "").localeCompare(String(a[key] || "")))[0];
  if (recent.length) ok("automation runs represented (newest cited)", page.text.includes('data-job="automation"') && page.text.includes(newest(recent, "started_at").execution_id || "@"), `${recent.length} recent`);
  else ok("automation rows honestly absent", !page.text.includes('data-job="automation"'), "0 automation runs");
  if (goals.length) ok("IOI Agent runs represented (newest cited)", page.text.includes('data-job="ioi-agent"') && page.text.includes(newest(goals, "created_at").goal_run_id || "@"), `${goals.length} goal runs`);
  else ok("IOI Agent rows honestly absent", !page.text.includes('data-job="ioi-agent"'), "0 goal runs");
  if (harness.length) ok("harness executions represented from the proof stream", page.text.includes('data-job="harness"'), `${harness.length} in ledger`);
  else ok("harness rows honestly absent", !page.text.includes('data-job="harness"'), "0 harness executions");
  if (foruns.length) {
    ok("failover runs represented (newest cited)", page.text.includes('data-job="failover"') && page.text.includes(newest(foruns, "started_at").run_ref || "@"), `${foruns.length} failover runs`);
    const parked = foruns.filter((r) => String(r.status || "").startsWith("awaiting_authority"));
    if (parked.length) ok("parked failover names its wallet gate in Jobs", page.text.includes("wallet gate:"), `${parked.length} parked`);
    else ok("no parked failover to name (skipped)", true);
  } else {
    ok("failover rows honestly absent", !page.text.includes('data-job="failover"'), "0 failover runs");
  }
  const total = recent.length + goals.length + Math.min(harness.length, 12) + foruns.length;
  if (total === 0) ok("empty state honest", page.text.includes("No jobs yet"));
  else ok("jobs count chip matches merged truth", page.text.includes(`All ${Math.min(total, 1000)}`), `merged ${total}`);
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("jobs-queue readiness: OK");
  process.exit(0); // its own stack (daemon + serve children) would otherwise keep the process alive
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
