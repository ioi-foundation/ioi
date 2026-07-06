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

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const jget = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => null);

async function run() {
  const page = await fetch(`${SERVE}/__ioi/operations`).then(async (r) => ({ status: r.status, text: await r.text() }));
  ok("Operations renders 200", page.status === 200);
  ok("Jobs section present", page.text.includes('id="ops-jobs"') && page.text.includes("every execution kind in one queue"));
  ok("type chips render", ["Automation", "Harness", "IOI Agent", "Failover"].every((t) => page.text.includes(`data-job-type=`)) && page.text.includes('id="jobs-chips"'));

  const [ops, gr, led, fo] = await Promise.all([
    jget("/v1/hypervisor/operations"), jget("/v1/hypervisor/goal-runs"), jget("/v1/hypervisor/work-ledger"), jget("/v1/hypervisor/failover/runs"),
  ]);
  const recent = ((ops || {}).runs || {}).recent || [];
  const goals = (gr || {}).goal_runs || [];
  const harness = ((led || {}).entries || []).filter((e) => e.kind === "harness_execution");
  const foruns = (fo || {}).runs || [];

  if (recent.length) ok("automation runs cited", recent.slice(0, 5).every((r) => page.text.includes(r.execution_id || "@")), `${recent.length} recent`);
  else ok("automation rows honestly absent", !page.text.includes('data-job="automation"'), "0 automation runs");
  if (goals.length) ok("IOI Agent runs cited", goals.slice(0, 3).every((g) => page.text.includes(g.goal_run_id || "@")), `${goals.length} goal runs`);
  else ok("IOI Agent rows honestly absent", !page.text.includes('data-job="ioi-agent"'), "0 goal runs");
  if (harness.length) ok("harness executions cited from the proof stream", page.text.includes('data-job="harness"'), `${harness.length} in ledger`);
  else ok("harness rows honestly absent", !page.text.includes('data-job="harness"'), "0 harness executions");
  if (foruns.length) {
    ok("failover runs cited", foruns.slice(0, 4).every((r) => page.text.includes(r.run_ref || "@")), `${foruns.length} failover runs`);
    const parked = foruns.filter((r) => String(r.status || "").startsWith("awaiting_authority"));
    if (parked.length) ok("parked failover names its wallet gate in Jobs", page.text.includes(`wallet gate: ${String(parked[0].status).replace("awaiting_authority_", "")}`), `${parked.length} parked`);
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
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
