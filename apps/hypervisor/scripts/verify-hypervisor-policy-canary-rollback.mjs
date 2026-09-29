#!/usr/bin/env node
// Canary release + rollback done-bar — re-typed around the release gate (R-240, GoalRun residue, 2026-09-29).
//
// WHAT THIS PROVED. A high-impact learned LAUNCH-POLICY change released to a bounded audience: a
// canary/cohort ReleaseControl made apply create a rollout-bound VARIANT policy, the IOI Agent
// launch preview and launch upgraded only eligible contexts to it, promote made it normal for every
// context, rollback restored the base everywhere, and the ledger cited the whole chain. Every step
// after the gate ran through the IOI Agent launch lane and its launch-policy plane — a launch
// policy narrowed how a GOAL would be pursued — and R-192 (S5-1) took goal pursuit out of the
// Hypervisor (a goal run is an ioi.ai composition over the thread orchestration primitives; standing
// owner ruling 2026-09-24). The variant, the preview overlay, the real launches, the Agent Studio
// promote/rollback cards and the policy_rollout ledger rows are gone with that plane, so this
// verifier crashed on its first launch.
//
// WHAT IT PROVES NOW, on a stack it owns as that stack's signed-in operator: the release gate a
// learned change must pass is still real — the suggestion simulates to a receipted report, the gate
// ApprovalRequest is DECIDED by a real authenticated principal (GOV-ATTR-1: the body names no
// reviewer, the record reports that session's server-derived `user://<principal_id>`; canon
// `identity-access-and-metering.md`), the ReleaseControl carries validated rollout semantics and its
// canary and open/close transitions land on the record — and the step that would have written a
// launch-policy variant is refused BY NAME (410 `ioi_agent_launch_policy_retired`), as are the serve's
// promote/rollback lanes, with no evidence deleted and nothing recorded as applied.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-policy-canary-rollback.mjs  (≈1 min)
// Its own isolated daemon + serve, the operator signed in (lib/verifier-stack.mjs); an explicit
// URL naming the owner's stack (:8765, :36173, :4173) is refused.

import { ANONYMOUS, verifierStack } from "./lib/verifier-stack.mjs";

const STACK = await verifierStack({ serve: true });
const DAEMON = STACK.daemonUrl;
const SHELL = STACK.serveUrl;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
// Every request carries the stack operator's session (verifier-stack) unless it names its own
// `authorization` — the reviewer's session below.
async function jd(method, url, body, headers) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method,
    headers: { "content-type": "application/json", ...(headers || {}) },
    body: body ? JSON.stringify(body) : undefined,
    redirect: "manual",
  }).catch(() => null);
  const text = r ? await r.text().catch(() => "") : "";
  let j = {}; try { j = JSON.parse(text); } catch { j = {}; }
  return { status: r?.status ?? 0, j, text };
}
// GOV-ATTR-1 — a governance decision's reviewer is WHO DECIDED. The gate approval below is approved
// BY a real principal: provisioned through the operator session, logged in for itself, and asked via
// `whoami` who it is — the expected reviewer ref is the daemon's own answer. An unadmitted fixture
// would approve anonymously and prove nothing about the identity seam, so it fails the verifier.
async function admitReviewer(tag) {
  const operator = { authorization: `Bearer ${STACK.token}` };
  const principalId = `usr_vfycrb${tag}`;
  const email = `vfycrb-${tag}@local`;
  const password = `vfycrb-${tag}-reviewer-pass`;
  const created = await jd("POST", "/v1/hypervisor/principals", { email, password, principal_id: principalId }, operator);
  const login = (await jd("POST", "/v1/hypervisor/auth/login", { email, password }, { [ANONYMOUS]: "1" })).j || {};
  const token = login.session_token || "";
  const session = { authorization: `Bearer ${token}` };
  const who = token ? (await jd("GET", "/v1/hypervisor/auth/whoami", undefined, session)).j || {} : {};
  const derived = who.authenticated === true ? String(who.principal?.principal_id || "") : "";
  if (!derived) throw new Error(`reviewer identity fixture NOT admitted (create ${created.status}, whoami ${JSON.stringify(who).slice(0, 200)}) — the gate approval cannot cross the real identity seam`);
  return { principalId: derived, ref: `user://${derived}`, headers: session, operator };
}

async function run() {
  const tag = Date.now().toString(16);
  const BASE = "ioi-agent-policy://pol_fast_local";
  const reviewer = await admitReviewer(tag);
  ok("real principal + login session admitted as the deciding identity", !!reviewer.ref, reviewer.ref);
  // The cohort member is daemon-known truth: a real project.
  await jd("POST", "/v1/hypervisor/projects", { project_name: `vfycrb-${tag}`, repository_url: `https://github.com/ioi-foundation/vfycrb-${tag}` });
  const projRecords = (await jd("GET", "/v1/hypervisor/projects")).j;
  const projectId = ((projRecords.records || projRecords.projects || []).find((x) => String(x.project_id || "").includes(`vfycrb-${tag}`)) || {}).project_id || "";
  const cohortRef = `project://${projectId}`;
  ok("daemon-known project created as the cohort member", projectId.length > 0, projectId);

  // ── A learned suggestion reaches the gate (R-240, 2026-09-29: two REAL IOI Agent launches used to
  // seed its replay subjects and make it high-impact; that lane is retired, so it simulates over no
  // launch replay and the gate chain below is built explicitly) ──
  const marker = `crb-learned-${tag}`;
  const prop = (await jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", {
    proposal_kind: "launch_policy_suggestion", signal: "repeated_harness_model_preference",
    target_ref: BASE, evidence_refs: [`work-result://vfycrb-${tag}`],
    suggested: { description: marker, privacy: { local_only: false, forbid_remote_trust: false, forbid_provider_credentials: false } },
  })).j?.proposal || {};
  const sim = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/simulate`, { save: true })).j?.report || {};
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/approve`);
  ok("the learned suggestion is admitted, simulated to a receipted report, and approved",
    prop.state === "pending" && String(sim.simulation_ref || "").startsWith("simulation-report://")
    && (sim.receipt_refs || []).some((r) => String(r).startsWith("receipt://hypervisor/simulation/")),
    `${prop.improvement_id} · ${sim.simulation_ref}`);

  // ── The gate: a real reviewer decides, the ReleaseControl carries validated rollout semantics ──
  const appr = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: prop.proposal_ref, request_kind: "improvement_apply", reason: `vfycrb-${tag}` })).j?.approval_request || {};
  // The approval is DECIDED by the admitted reviewer session; the body names nobody (GOV-ATTR-1).
  await jd("PATCH", `/v1/hypervisor/governance/approval-requests/${appr.id}`, { transition: "approve" }, reviewer.headers);
  const apprDecided = (await jd("GET", `/v1/hypervisor/governance/approval-requests/${appr.id}`)).j?.approval_request || {};
  ok("the gate approval is attributed to the SERVER-DERIVED principal of the deciding session",
    apprDecided.status === "approved" && apprDecided.reviewer_ref === reviewer.ref,
    `reviewer ${apprDecided.reviewer_ref} · expected ${reviewer.ref}`);
  const relResp = await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: prop.proposal_ref, rollout_mode: "cohort", cohort_refs: [cohortRef], reason: `vfycrb-${tag}` });
  const rel = relResp.j?.release_control || {};
  const badMode = await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: prop.proposal_ref, rollout_mode: "percentage" });
  const noPercent = await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: prop.proposal_ref, rollout_mode: "canary" });
  ok("ReleaseControl carries validated rollout semantics (mode, cohort_refs, rollback_state)",
    rel.rollout_mode === "cohort" && JSON.stringify(rel.cohort_refs) === JSON.stringify([cohortRef])
    && rel.rollback_state === null && rel.promoted_at === null
    && badMode.j?.error?.code === "governance_rollout_mode_invalid" && noPercent.j?.error?.code === "governance_canary_percent_required",
    `${relResp.status} ${rel.rollout_mode} ${JSON.stringify(rel.cohort_refs)} · ${badMode.j?.error?.code} · ${noPercent.j?.error?.code}`);
  // R-240 (2026-09-29): the canary and close/open steps used to be read through the IOI Agent launch
  // preview's overlay (100% in, 0% out; a closed gate disabling it). That preview is retired; what is
  // left to measure is that each transition lands on the ReleaseControl record itself.
  const relRead = async () => (await jd("GET", `/v1/hypervisor/governance/release-controls/${rel.id}`)).j?.release_control || {};
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { transition: "open" });
  const opened = await relRead();
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { rollout_mode: "canary", canary_percent: 100 });
  const canaryIn = await relRead();
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { canary_percent: 0 });
  const canaryOut = await relRead();
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { rollout_mode: "cohort", cohort_refs: [cohortRef] });
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { transition: "close" });
  const closed = await relRead();
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { transition: "open" });
  const reopened = await relRead();
  ok("the ReleaseControl stays the live gate record: open, canary 100 → 0, back to cohort, close and reopen all land on it",
    opened.state === "open" && canaryIn.rollout_mode === "canary" && canaryIn.canary_percent === 100 && canaryOut.canary_percent === 0
    && closed.state === "closed" && closed.rollout_mode === "cohort" && reopened.state === "open",
    `${opened.state} · ${canaryIn.rollout_mode}/${canaryIn.canary_percent} → ${canaryOut.canary_percent} · ${closed.state} · ${reopened.state}`);
  await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}`, { approval_request_ref: appr.ref, release_control_ref: rel.ref });

  // ── The variant step is refused by name, and so are the serve's rollout lanes ──
  const applyResp = await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/apply`);
  const propAfter = (await jd("GET", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}`)).j?.proposal || {};
  ok("apply under the satisfied gate is refused by name — 410 ioi_agent_launch_policy_retired — and no variant is written",
    applyResp.status === 410 && applyResp.j?.error?.code === "ioi_agent_launch_policy_retired"
    && propAfter.state === "approved" && !propAfter.applied_ref,
    `${applyResp.status} ${applyResp.j?.error?.code} · state ${propAfter.state} · applied_ref ${propAfter.applied_ref ?? "none"}`);
  const lanes = [];
  for (const act of ["promote", "rollback"]) {
    lanes.push({ act, ...(await jd("POST", `${SHELL}/__ioi/agent-studio/launch-policies/pol_fast_local/rollout/${act}`)) });
  }
  ok("the serve's promote and rollback lanes answer 410 ioi_agent_launch_policy_retired rather than relaying",
    lanes.every((l) => l.status === 410 && l.text.includes('data-error-code="ioi_agent_launch_policy_retired"')),
    lanes.map((l) => `${l.act}=${l.status}`).join(" "));

  // ── The refusal deletes no evidence and records no effect ──
  const evidence = [
    propAfter,
    (await jd("GET", `/v1/hypervisor/intelligence/simulation-reports/${String(sim.simulation_ref || "").replace("simulation-report://", "")}`)).j?.report,
    (await jd("GET", `/v1/hypervisor/governance/approval-requests/${appr.id}`)).j?.approval_request,
    await relRead(),
  ];
  ok("the refused apply deletes NO evidence: proposal, simulation, approval and release all retained",
    evidence.every((e) => e && Object.keys(e).length > 0) && evidence[0].latest_simulation_ref === sim.simulation_ref);
  const ledger = (await jd("GET", "/v1/hypervisor/work-ledger")).j?.entries || [];
  ok("the Work Ledger records nothing applied and no rollout for this proposal",
    !ledger.some((e) => e.kind === "improvement_applied" && e.proposal_ref === prop.proposal_ref)
    && !ledger.some((e) => e.kind === "policy_rollout" && e.proposal_ref === prop.proposal_ref),
    `${ledger.length} ledger entries`);
  const ft = (await jd("GET", `${SHELL}/__ioi/fallthrough`)).j || {};
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup (evidence receipts remain by design) ──
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/reject`, { reason: "verifier fixture" });
  const delAppr = await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${appr.id}`);
  const delRel = await jd("DELETE", `/v1/hypervisor/governance/release-controls/${rel.id}`);
  const delPrincipal = await jd("DELETE", `/v1/hypervisor/principals/${encodeURIComponent(reviewer.principalId)}`, undefined, reviewer.operator);
  ok("fixtures cleaned (approval, release control, reviewer principal)",
    [delAppr, delRel, delPrincipal].every((r) => r.status >= 200 && r.status < 300),
    [delAppr, delRel, delPrincipal].map((r) => r.status).join(","));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`policy canary rollback readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
