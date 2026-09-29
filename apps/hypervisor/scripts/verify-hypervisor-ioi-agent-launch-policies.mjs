#!/usr/bin/env node
// IOI Agent launch policies — a RETIREMENT GUARD (R-240, GoalRun residue, 2026-09-29).
//
// This verifier used to prove durable launch policies as routing/admission envelopes over the IOI
// Agent planner: seeded protected defaults, clone-to-customize and CRUD lanes, per-policy planner
// semantics (compare-before-write planning a `goal_run`, fast-local planning `direct`), the New
// Session policy selector, and policy_ref reaching the goal-run record, its timeline and the
// ledger's goal_run entry. A launch policy narrowed how a GOAL would be pursued, and R-192 (S5-1)
// took goal pursuit out of the Hypervisor — a goal run is an ioi.ai composition over the thread
// orchestration primitives (standing owner ruling 2026-09-24) — so the policy plane left with it
// and this verifier crashed on its first read. What it proves now, on a stack it owns as that
// stack's signed-in operator, is that the plane STAYS gone and every lane that named it says so:
//   - the daemon mounts no launch-policy route (404 to the operator: no handler);
//   - the serve's Agent Studio management and rollout lanes answer the typed 410
//     `ioi_agent_launch_policy_retired` rather than relaying into a dead namespace;
//   - the New Session context resolves no launch policy;
//   - the improvement plane still admits and reviews a learned launch-policy suggestion, but its
//     apply is refused by name (410 `ioi_agent_launch_policy_retired`) and writes nothing.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-ioi-agent-launch-policies.mjs  (≈1 min)
// Its own isolated daemon + serve, the operator signed in (lib/verifier-stack.mjs); an explicit
// URL naming the owner's stack (:8765, :36173, :4173) is refused.

import { execSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifierStack } from "./lib/verifier-stack.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STACK = await verifierStack({ serve: true });
const DAEMON = STACK.daemonUrl;
const SHELL = STACK.serveUrl;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
    redirect: "manual",
  }).catch(() => null);
  const text = r ? await r.text().catch(() => "") : "";
  let j = null; try { j = JSON.parse(text); } catch { j = null; }
  return { status: r?.status ?? 0, j, text };
}

async function run() {
  const tag = Date.now().toString(16);

  // ── The daemon mounts no launch-policy route ──
  const LP = "/v1/goal-orchestration/ioi-agent/launch-policies";
  const daemonLanes = [
    ["GET", LP, null],
    ["GET", `${LP}/pol_fast_local`, null],
    ["POST", LP, { display_name: `vfy-policy-${tag}`, strategy_preference: "direct" }],
    ["POST", `${LP}/pol_high_assurance/clone`, { display_name: `vfy-clone-${tag}` }],
    ["PATCH", `${LP}/pol_high_assurance`, { description: "x" }],
    ["DELETE", `${LP}/pol_fast_local`, null],
  ];
  const daemonAnswers = [];
  for (const [method, p, body] of daemonLanes) daemonAnswers.push({ method, p, ...(await jd(method, p, body)) });
  ok("the daemon answers every former launch-policy route 404 to the signed-in operator (no handler, not a refused caller)",
    daemonAnswers.every((a) => a.status === 404),
    daemonAnswers.map((a) => `${a.method} ${a.p.replace(LP, "…")}=${a.status}`).join(" "));

  // ── The serve's Agent Studio lanes answer a typed retirement ──
  const serveLanes = [
    "/__ioi/agent-studio/launch-policies",
    "/__ioi/agent-studio/launch-policies/pol_fast_local/clone",
    "/__ioi/agent-studio/launch-policies/pol_fast_local/enable",
    "/__ioi/agent-studio/launch-policies/pol_fast_local/disable",
    "/__ioi/agent-studio/launch-policies/pol_fast_local/delete",
    "/__ioi/agent-studio/launch-policies/pol_fast_local/rollout/promote",
    "/__ioi/agent-studio/launch-policies/pol_fast_local/rollout/rollback",
  ];
  const serveAnswers = [];
  for (const p of serveLanes) serveAnswers.push({ p, ...(await jd("POST", `${SHELL}${p}`, null)) });
  ok("every Agent Studio launch-policy lane (create, clone, enable, disable, delete, promote, roll back) answers 410 ioi_agent_launch_policy_retired",
    serveAnswers.every((a) => a.status === 410 && a.text.includes('data-error-code="ioi_agent_launch_policy_retired"')),
    serveAnswers.map((a) => `${a.p.split("/").slice(-1)[0]}=${a.status}`).join(" "));

  // ── The New Session context resolves no launch policy ──
  const ctx = await jd("GET", `${SHELL}/__ioi/api/new-session/context`);
  ok("the New Session context resolves no launch policy (the launcher offers no policy chooser)",
    ctx.status === 200 && Array.isArray(ctx.j?.launch_policies) && ctx.j.launch_policies.length === 0,
    `status ${ctx.status} · ${JSON.stringify(ctx.j?.launch_policies)}`);

  // ── A learned suggestion is still reviewed, but its apply writes nothing ──
  const prop = (await jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", {
    proposal_kind: "launch_policy_suggestion", signal: "repeated_harness_model_preference",
    target_ref: "ioi-agent-policy://pol_fast_local", evidence_refs: [`work-result://vfy-lp-${tag}`],
    suggested: { description: `learned ${tag}`, harness_preferences: { preferred_harness_refs: ["harness-profile:hp_opencode"], excluded_harness_refs: [], allow_fallback: true } },
  })).j?.proposal || {};
  ok("a learned launch-policy suggestion is still admitted pending, evidence bound",
    prop.state === "pending" && String(prop.proposal_ref || "").startsWith("improvement-proposal://"), prop.improvement_id);
  const sim = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/simulate`, { save: true })).j?.report || {};
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/approve`);
  const applied = await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/apply`);
  const after = (await jd("GET", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}`)).j?.proposal || {};
  ok("its apply is refused by name (410 ioi_agent_launch_policy_retired) and the proposal keeps its decision without claiming an effect",
    String(sim.simulation_ref || "").startsWith("simulation-report://")
    && applied.status === 410 && applied.j?.error?.code === "ioi_agent_launch_policy_retired"
    && after.state === "approved" && !after.applied_ref,
    `${applied.status} ${applied.j?.error?.code} · state ${after.state}`);
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/reject`, { reason: "verifier fixture" });

  // ── Hygiene ──
  let sourceNeutral = false;
  try {
    execSync("npm run check:source-neutral", { cwd: path.join(HERE, ".."), stdio: "pipe" });
    sourceNeutral = true;
  } catch { sourceNeutral = false; }
  ok("source-neutral stays clean", sourceNeutral);
  const ft = await jd("GET", `${SHELL}/__ioi/fallthrough`);
  ok("fallthrough stays empty", Array.isArray(ft.j?.proxied) && ft.j.proxied.length === 0);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`ioi-agent launch-policy retirement: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
