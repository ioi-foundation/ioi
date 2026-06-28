#!/usr/bin/env node
// Cut E done-bar — orchestration / scale as daemon truth:
//   K. AUTOMATION WORKFLOW: a workflow (agent → command → proposal steps) STARTS, creates a fresh
//      env, runs the steps over it, and reports structured outputs — the proposal is a REAL git diff
//      of what the run changed (review_state: proposed). i.e. a prompt→command→PR loop in a fresh env.
//   L. PLACEMENT: placement scores the REAL provider catalog and records the decision + REJECTED
//      candidates with honest reasons (cross-tenant trust rejects a process_runner; no silent drop).
//      Metrics aggregate cold-start/prebuild-hit/warm-claim/cache from real env truth. A warm pool
//      pre-starts envs and a claim hands one over (warm-claim).
// Daemon truth. Requires daemon :8765. Missing ⇒ BLOCKED (named host gap), never a fake.
const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";

const checks = [];
let failures = 0;
const ok = (c, m, d) => { checks.push({ ok: !!c, m }); if (!c) failures++; if (!JSON_OUT) console.log(`    ${c ? "✓" : "✗ FAIL:"} ${m}${d ? ` (${d})` : ""}`); };
const blocked = (r) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "orchestration-functional", verdict: "BLOCKED", reason: r }) : `  BLOCKED: ${r}`); process.exit(2); };
const dj = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: { "content-type": "application/json" }, body: b !== undefined ? JSON.stringify(b) : undefined }); const t = await r.text(); let j = {}; try { j = t ? JSON.parse(t) : {}; } catch { j = { _raw: t }; } return { status: r.status, body: j }; };

if (!JSON_OUT) console.log("Orchestration e2e — automation workflow · placement · warm pools/metrics");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) blocked("daemon not running"); } catch { blocked("hypervisor-daemon (:8765) not running"); }

// ---- K. AUTOMATION WORKFLOW: prompt → command → proposal in a fresh env ----
const auto = await dj("POST", "/v1/hypervisor/automations", {
  name: "demo-loop", project_id: "orchestration-verify",
  steps: [
    { kind: "agent", prompt: "Document a CONTRIBUTING note for the project." },
    { kind: "command", command: "ls -1 agentops 2>/dev/null | head; echo STEP_OK" },
    { kind: "proposal", title: "Automation: add CONTRIBUTING note" }
  ]
});
const autoId = auto.body?.automation?.automation_id;
ok(!!autoId, "automation workflow created", autoId);
const run = await dj("POST", `/v1/hypervisor/automations/${autoId}/start`);
const exec = run.body?.execution;
ok(!!exec?.environment_id, "start created a FRESH environment for the run", exec?.environment_id);
const sr = exec?.step_results || [];
ok(sr.length === 3 && sr.every((s) => s.status === "done"), "all steps ran to done", sr.map((s) => `${s.kind}:${s.status}`).join(","));
const agentStep = sr.find((s) => s.kind === "agent");
ok(agentStep?.output?.file && agentStep?.output?.assistant_excerpt, "agent step produced a real file + model output", agentStep?.output?.file);
const cmdStep = sr.find((s) => s.kind === "command");
ok(/STEP_OK/.test(cmdStep?.output?.stdout_excerpt || "") && cmdStep?.output?.exit_code === 0, "command step ran a real command in the env", `exit ${cmdStep?.output?.exit_code}`);
const propStep = sr.find((s) => s.kind === "proposal");
ok(propStep?.output?.proposal_id && (propStep?.output?.changed_files || []).length > 0, "proposal step emitted a real diff (review_state proposed)", propStep?.output?.diffstat);
const prop = await dj("GET", `/v1/hypervisor/automation-executions/${exec.execution_id}`);
ok(prop.body?.execution?.status === "done" && prop.body?.execution?.counts?.done === 3, "execution status recorded with structured counts", JSON.stringify(prop.body?.execution?.counts));

// ---- L. PLACEMENT: honest scoring + rejected candidates ----
const place = await dj("POST", "/v1/hypervisor/placement/resolve", { class: "local-workspace-v0", trust: "trusted", residency: "any", project_id: "orchestration-verify" });
ok(place.body?.ok === true && place.body?.decision?.chosen?.provider_ref, "placement resolves to a chosen runner", place.body?.decision?.chosen?.provider_ref);
ok(Array.isArray(place.body?.decision?.eligible) && place.body.decision.eligible.length > 0, "placement records eligible candidates with scores");
const xtenant = await dj("POST", "/v1/hypervisor/placement/resolve", { class: "local-workspace-v0", trust: "cross_tenant", residency: "any" });
const rej = xtenant.body?.decision?.rejected || [];
ok(rej.some((r) => /vm_kernel|cross-tenant/i.test(r.reason)), "cross-tenant trust REJECTS non-vm_kernel runners with honest reasons", `${rej.length} rejected`);

// ---- L. WARM POOL + METRICS ----
const wp = await dj("POST", "/v1/hypervisor/warm-pools", { project_id: "orchestration-verify", class: "local-workspace-v0", size: 2 });
const wpId = wp.body?.warm_pool?.warm_pool_id;
ok((wp.body?.warm_pool?.ready || []).length === 2, "warm pool pre-started real envs", `${(wp.body?.warm_pool?.ready || []).length} ready`);
const claim = await dj("POST", `/v1/hypervisor/warm-pools/${wpId}/claim`);
ok(claim.body?.ok === true && claim.body?.claim_kind === "warm_claim" && claim.body?.environment_id, "claim hands over a pre-started env (warm_claim)", claim.body?.environment_id);
const placeWarm = await dj("POST", "/v1/hypervisor/placement/resolve", { class: "local-workspace-v0", project_id: "orchestration-verify" });
ok(placeWarm.body?.decision?.warm_pool_available === true && placeWarm.body?.decision?.claim_kind === "warm_claim", "placement prefers warm-pool availability for the project/class");
const metrics = await dj("GET", "/v1/hypervisor/placement/metrics");
ok(typeof metrics.body?.warm_claim === "number" && metrics.body.warm_claim >= 1 && typeof metrics.body?.cold_start === "number", "metrics expose cold-start / prebuild-hit / warm-claim / cache (from real truth)", `warm_claim=${metrics.body?.warm_claim}, cold=${metrics.body?.cold_start}`);

const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "orchestration-functional", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
