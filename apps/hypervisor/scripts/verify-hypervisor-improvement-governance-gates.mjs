#!/usr/bin/env node
// Improvement governance gates done-bar.
//
// Proves learned improvements fail closed without simulation outside local development,
// unless an exact, approved, receipted, per-kind simulation waiver binds the current proposal
// fingerprint. High-impact simulated improvements additionally CANNOT apply without an
// APPROVED ApprovalRequest and an OPEN ReleaseControl targeting the proposal or its simulation
// report — enforced LIVE at apply time with deterministic reason codes
// (simulation_required, simulation_stale, approval_required, approval_not_approved,
// release_control_required, release_control_not_open). The local-development bypass remains
// explicit; receipts + Work Ledger cite the full governance chain; and the Agent Studio panel
// walks the whole gate (posture chip, disabled Apply, one-click
// request/approve/release). Runs two REAL direct launches to seed replay subjects (≈30s).
// Usage: node apps/hypervisor/scripts/verify-hypervisor-improvement-governance-gates.mjs

import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { mintApprovalGrant } = await import(path.join(HERE, "../../../scripts/lib/mint-approval-grant.mjs"));

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const EXPOSED = { "x-forwarded-host": "hv.example.com" };

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
// node:http, not fetch: synchronous ioi-agent launches legitimately run longer than undici's
// fixed 300s headers timeout under host load (the 600s driver budget) — goalrun convention.
function jd(method, url, body, headers) {
  const target = new URL(url.startsWith("http") ? url : `${DAEMON}${url}`);
  const payload = body ? JSON.stringify(body) : null;
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: target.hostname, port: target.port, path: target.pathname + target.search, method,
        headers: { "content-type": "application/json", ...(headers || {}), ...(payload ? { "content-length": Buffer.byteLength(payload) } : {}) } },
      (res) => {
        let raw = "";
        res.on("data", (c) => { raw += c; });
        res.on("end", () => {
          let j = {};
          try { j = JSON.parse(raw); } catch { j = {}; }
          resolve({ status: res.statusCode, j });
        });
      },
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}
const launch = async (goal) => {
  const a = await jd("POST", "/v1/hypervisor/ioi-agent/launch", { goal, strategy: "direct" });
  const grant = mintApprovalGrant({ policyHash: a.j.approval.policy_hash, requestHash: a.j.approval.request_hash });
  return jd("POST", "/v1/hypervisor/ioi-agent/launch", { launch_id: a.j.launch_id, wallet_approval_grant: grant });
};
const apply = (id, headers) => jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${id}/apply`, undefined, headers);
const getProp = async (id, headers) => (await jd("GET", `/v1/hypervisor/intelligence/improvement-proposals/${id}`, undefined, headers)).j?.proposal || {};

// The require_compare + full-exclusion patch: deterministically high impact (blockers introduced).
const HIGH_IMPACT_SUGGESTED = {
  display_name: "Gated compare-everything policy (verifier)",
  description: "deterministically high-impact fixture",
  harness_preferences: { preferred_harness_refs: [], excluded_harness_refs: ["harness-profile:hp_opencode", "harness-profile:hp_deepseek_tui", "harness-profile:hp_codex", "harness-profile:hp_claude_code"], allow_fallback: false },
  assurance: { require_compare: true },
};

async function run() {
  const tag = Date.now().toString(16);
  const verifierPrincipalId = `usr_vfygov${tag}`;
  const verifierEmail = `vfygov-${tag}@local`;
  const verifierPassword = `pw-vfygov-${tag}`;
  const principalCreated = await jd("POST", "/v1/hypervisor/principals", {
    principal_id: verifierPrincipalId, email: verifierEmail, password: verifierPassword,
  });
  const sessionToken = (await jd("POST", "/v1/hypervisor/auth/login", {
    email: verifierEmail, password: verifierPassword,
  })).j?.session_token || "";
  const MANAGED = { ...EXPOSED, authorization: `Bearer ${sessionToken}` };
  ok("managed-posture verifier principal authenticated", principalCreated.status === 200 && !!sessionToken);

  await jd("POST", "/v1/hypervisor/harness-profiles/hp_opencode/enable");
  const l1 = await launch(`vfygov${tag} exercise the governance gate once`);
  const l2 = await launch(`vfygov${tag} exercise the governance gate again`);
  ok("two real launches executed as replay subjects", l1.status === 200 && l2.status === 200);

  const mkProp = (payload) => jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", payload);
  const propA = (await mkProp({
    proposal_kind: "launch_policy_suggestion", signal: "repeated_harness_model_preference",
    evidence_refs: [`ioi-agent-launch://vfygov-${tag}`], suggested: HIGH_IMPACT_SUGGESTED,
  })).j?.proposal || {};

  // ── simulation_required: policy improvements cannot apply unsimulated ──
  ok("unsimulated policy proposal postures simulation_required",
    propA.gate?.posture === "simulation_required" || (await getProp(propA.improvement_id)).gate?.posture === "simulation_required");
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propA.improvement_id}/approve`);
  const noSim = await apply(propA.improvement_id);
  ok("apply without simulation blocks: simulation_required", noSim.status === 409 && noSim.j?.error?.code === "simulation_required");

  // ── High-impact simulation names an ENFORCED gate with its satisfiable targets ──
  const sim = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propA.improvement_id}/simulate`, { save: true })).j?.report || {};
  const simRef = String(sim.simulation_ref || "");
  ok("saved simulation is high-impact with an enforced requirement + gate targets",
    sim.governance?.high_impact === true && sim.governance?.enforced === true
    && String(sim.governance?.requirement || "").startsWith("enforced:")
    && JSON.stringify(sim.governance?.satisfiable_target_refs) === JSON.stringify([propA.proposal_ref, simRef]));

  // ── approval_required → binding validation → approval_not_approved ──
  const noAppr = await apply(propA.improvement_id);
  ok("apply with high-impact simulation but no controls blocks: approval_required",
    noAppr.status === 409 && noAppr.j?.error?.code === "approval_required"
    && (await getProp(propA.improvement_id)).gate?.posture === "awaiting_approval");
  const badRef = await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${propA.improvement_id}`, { approval_request_ref: "approval-request://appr_nonexistent" });
  const foreign = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: simRef ? "improvement-proposal://imp_nonexistent" : "", request_kind: "improvement_apply", reason: `vfygov-${tag}-foreign` })).j?.approval_request;
  ok("binding validates live: unresolved refs rejected", badRef.status === 422 && badRef.j?.error?.code === "governance_ref_unresolved", JSON.stringify(badRef.j?.error || {}));
  const apprA = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: propA.proposal_ref, request_kind: "improvement_apply", reason: `vfygov-${tag}` })).j?.approval_request || {};
  const bindPending = await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${propA.improvement_id}`, { approval_request_ref: apprA.ref });
  const pendingBlocked = await apply(propA.improvement_id);
  ok("pending ApprovalRequest blocks: approval_not_approved",
    bindPending.status === 200 && pendingBlocked.status === 409 && pendingBlocked.j?.error?.code === "approval_not_approved");

  // ── release_control_required → release_control_not_open (release may target the SIM report) ──
  await jd("PATCH", `/v1/hypervisor/governance/approval-requests/${apprA.id}`, { transition: "approve", reviewer_ref: "principal://verifier" });
  const noRel = await apply(propA.improvement_id);
  ok("approved approval alone blocks: release_control_required", noRel.status === 409 && noRel.j?.error?.code === "release_control_required");
  const relA = (await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: simRef, reason: `vfygov-${tag}` })).j?.release_control || {};
  await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${propA.improvement_id}`, { release_control_ref: relA.ref });
  const closedBlocked = await apply(propA.improvement_id);
  ok("closed ReleaseControl blocks: release_control_not_open", closedBlocked.status === 409 && closedBlocked.j?.error?.code === "release_control_not_open");
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${relA.id}`, { transition: "open" });
  ok("approved + open controls posture READY", (await getProp(propA.improvement_id)).gate?.posture === "ready");

  // ── Freshness: mutating the proposal makes the simulation stale even with controls satisfied ──
  await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${propA.improvement_id}`, { suggested: { harness_preferences: { excluded_harness_refs: [] } } });
  const staleBlocked = await apply(propA.improvement_id);
  ok("post-simulation mutation blocks: simulation_stale (controls alone cannot pass a stale preview)",
    staleBlocked.status === 409 && staleBlocked.j?.error?.code === "simulation_stale"
    && (await getProp(propA.improvement_id)).gate?.posture === "simulation_stale");
  await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${propA.improvement_id}`, { suggested: HIGH_IMPACT_SUGGESTED });
  ok("freshness is content identity: restoring the simulated payload restores READY (no re-simulation needed)",
    (await getProp(propA.improvement_id)).gate?.posture === "ready");

  // ── Gate satisfied → apply lands, citing the full governance chain ──
  const appliedA = (await apply(propA.improvement_id)).j?.proposal || {};
  ok("fresh simulation + approved approval + open release allow apply",
    appliedA.state === "applied" && String(appliedA.applied_ref || "").startsWith("ioi-agent-policy://"));
  const ledger = (await jd("GET", "/v1/hypervisor/work-ledger")).j?.entries || [];
  const entry = ledger.find((e) => e.kind === "improvement_applied" && e.proposal_ref === propA.proposal_ref);
  ok("receipt + Work Ledger cite simulation, approval, and release refs",
    !!entry && entry.simulation_ref === simRef && entry.approval_request_ref === apprA.ref
    && entry.release_control_ref === relA.ref && entry.report_hash === sim.report_hash);

  // ── Low impact still needs a simulation outside local development; local bypass is explicit ──
  const propLow = (await mkProp({
    proposal_kind: "automation_readiness", signal: "repeated_successful_goal_pattern",
    evidence_refs: [`ioi-agent-launch://vfygov-${tag}`], suggested: { title: `Affinity vfygov-${tag}`, goal_pattern: `zzz-nomatch-${tag}` },
  })).j?.proposal || {};
  const lowSim = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propLow.improvement_id}/simulate`, { save: true })).j?.report || {};
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propLow.improvement_id}/approve`);
  const appliedLow = (await apply(propLow.improvement_id)).j?.proposal || {};
  const projectedLow = await getProp(propLow.improvement_id);
  ok("low-impact simulated proposal applies WITHOUT governance controls",
    lowSim.governance?.high_impact === false && projectedLow.gate?.report_impact?.unknown === false
    && appliedLow.state === "applied");
  const propSkill = (await mkProp({
    proposal_kind: "skill_improvement", signal: "repeated_successful_goal_pattern",
    evidence_refs: [`ioi-agent-launch://vfygov-${tag}`], suggested: { title: `Skill vfygov-${tag}`, description: "explicit local-development bypass lane" },
  })).j?.proposal || {};
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propSkill.improvement_id}/approve`);
  const localSkillProjection = await getProp(propSkill.improvement_id);
  const appliedSkill = (await apply(propSkill.improvement_id)).j?.proposal || {};
  ok("unsimulated skill applies only through the explicit local-development bypass",
    localSkillProjection.gate?.posture === "local_development_no_simulation"
    && localSkillProjection.gate?.deployment_posture === "local_development"
    && appliedSkill.state === "applied" && String(appliedSkill.applied_ref || "").startsWith("skill-entry://"));

  // ── Managed posture fails closed, then accepts only an exact approved + receipted waiver ──
  const propManaged = (await mkProp({
    proposal_kind: "skill_improvement", signal: "repeated_successful_goal_pattern",
    evidence_refs: [`ioi-agent-launch://vfygov-${tag}`],
    suggested: { title: `Managed skill vfygov-${tag}`, description: "exact simulation-waiver lane" },
  })).j?.proposal || {};
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propManaged.improvement_id}/approve`);
  const managedProjection = await getProp(propManaged.improvement_id, MANAGED);
  const managedBlocked = await apply(propManaged.improvement_id, MANAGED);
  ok("unsimulated skill is refused under authenticated-managed exposure",
    managedProjection.gate?.deployment_posture === "authenticated_managed"
    && managedProjection.gate?.posture === "simulation_required"
    && String(managedProjection.gate?.proposal_fingerprint || "").startsWith("sha256:")
    && managedBlocked.status === 409 && managedBlocked.j?.error?.code === "simulation_required");

  const waiver = (await jd("POST", "/v1/hypervisor/governance/approval-requests", {
    subject_ref: propManaged.proposal_ref,
    request_kind: "improvement_simulation_waiver",
    reason: `vfygov-${tag}-exact-simulation-waiver`,
    enforcement_preview: {
      requirement: "saved_simulation",
      proposal_kind: propManaged.proposal_kind,
      proposal_fingerprint: managedProjection.gate?.proposal_fingerprint,
    },
  }, MANAGED)).j?.approval_request || {};
  const approvedWaiver = (await jd("PATCH", `/v1/hypervisor/governance/approval-requests/${waiver.id}`, {
    transition: "approve", reviewer_ref: `principal://${verifierPrincipalId}`,
  }, MANAGED)).j?.approval_request || {};
  const waiverBind = await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${propManaged.improvement_id}`, {
    simulation_waiver_ref: waiver.ref,
  }, MANAGED);
  const boundManaged = waiverBind.j?.proposal || {};
  ok("exact waiver is approved, transition-receipted, and bound under managed posture",
    approvedWaiver.status === "approved" && (approvedWaiver.receipt_refs || []).length > 0
    && waiverBind.status === 200 && boundManaged.gate?.posture === "simulation_waived"
    && boundManaged.gate?.deployment_posture === "authenticated_managed");
  const appliedManaged = (await apply(propManaged.improvement_id, MANAGED)).j?.proposal || {};
  ok("exact managed simulation waiver permits apply",
    appliedManaged.state === "applied" && appliedManaged.simulation_waiver_ref === waiver.ref
    && String(appliedManaged.applied_ref || "").startsWith("skill-entry://"));

  // ── UI: full gate walk on a second high-impact proposal ──
  const propB = (await mkProp({
    proposal_kind: "launch_policy_suggestion", signal: "repeated_harness_model_preference",
    evidence_refs: [`ioi-agent-launch://vfygov-${tag}`], suggested: HIGH_IMPACT_SUGGESTED,
  })).j?.proposal || {};
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propB.improvement_id}/simulate`, { save: true });
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propB.improvement_id}/approve`);
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  const studio = `${SHELL}/__ioi/agent-studio#launch-policies`;
  await page.goto(studio, { waitUntil: "networkidle" });
  await page.waitForSelector("#improvement-proposals", { timeout: 15000 });
  const bid = propB.improvement_id;
  ok("card shows awaiting-approval posture with a visibly blocked Apply",
    await page.locator(`button[title="apply blocked: approval_required"][disabled]`).count() >= 1
    && (await page.locator(`[data-gov="${bid}"]`).innerText()).match(/request approval/i) !== null);
  await Promise.all([page.waitForURL("**/agent-studio**"), page.click(`form[action="/__ioi/agent-studio/improvements/${bid}/governance/request-approval"] button`)]);
  await page.goto(studio, { waitUntil: "networkidle" });
  await Promise.all([page.waitForURL("**/agent-studio**"), page.click(`[data-gov="${bid}"] form[action*="/governance/approvals/"] button`)]);
  await page.goto(studio, { waitUntil: "networkidle" });
  await Promise.all([page.waitForURL("**/agent-studio**"), page.click(`form[action="/__ioi/agent-studio/improvements/${bid}/governance/open-release"] button`)]);
  await page.goto(studio, { waitUntil: "networkidle" });
  await Promise.all([page.waitForURL("**/agent-studio**"), page.click(`[data-gov="${bid}"] form[action*="/governance/releases/"] button`)]);
  await page.goto(studio, { waitUntil: "networkidle" });
  const bAfter = await getProp(bid);
  ok("one-click UI walk satisfies the whole gate (request → approve → release → open = ready)",
    bAfter.gate?.posture === "ready" && (await page.locator(`[data-gov="${bid}"]`).innerText()).match(/approved/i) !== null
    && await page.locator(`form[action="/__ioi/agent-studio/improvements/${bid}/apply"] button`).count() === 1);
  await Promise.all([page.waitForURL("**/agent-studio**"), page.click(`form[action="/__ioi/agent-studio/improvements/${bid}/apply"] button`)]);
  const bApplied = await getProp(bid);
  ok("UI apply lands once the gate passes", bApplied.state === "applied");

  // ── Report page names its satisfiable governance targets; ledger drawer backlinks the chain ──
  const simId = String(bApplied.latest_simulation_ref || "").replace("simulation-report://", "");
  await page.goto(`${SHELL}/__ioi/intelligence/simulations/${simId}`, { waitUntil: "networkidle" });
  const repText = await page.evaluate(() => document.body.innerText);
  ok("simulation report page shows enforced gate + exact satisfiable target refs",
    /gate enforced at apply/i.test(repText) && repText.includes(bApplied.proposal_ref) && repText.includes(bApplied.latest_simulation_ref));
  await page.goto(`${SHELL}/__ioi/work-ledger`, { waitUntil: "networkidle" });
  await page.locator(".wlrow", { hasText: "improvement_applied" }).first().click();
  const drawer = await page.locator("#wl-drawer").innerText();
  ok("Work Ledger drawer backlinks simulation + approval + release",
    drawer.includes("simulation-report://") && drawer.includes("approval-request://") && drawer.includes("release-control://"));
  ok("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup + posture restore ──
  for (const prop of [appliedA, bApplied]) {
    const pid = String(prop.applied_ref || "").replace("ioi-agent-policy://", "");
    if (pid) await jd("DELETE", `/v1/hypervisor/ioi-agent/launch-policies/${pid}`);
  }
  await jd("PATCH", `/v1/hypervisor/skill-entries/${String(appliedSkill.applied_ref || "").replace("skill-entry://", "")}`, { status: "archived" });
  await jd("PATCH", `/v1/hypervisor/skill-entries/${String(appliedManaged.applied_ref || "").replace("skill-entry://", "")}`, { status: "archived" });
  await jd("PATCH", `/v1/hypervisor/automation-affinities/${String(appliedLow.applied_ref || "").replace("automation-affinity://", "")}`, { status: "archived" });
  const controls = [
    ["approval-requests", apprA.id],
    ["approval-requests", foreign?.id],
    ["approval-requests", waiver.id],
    ["approval-requests", String(bApplied.approval_request_ref || "").replace("approval-request://", "")],
    ["release-controls", relA.id],
    ["release-controls", String(bApplied.release_control_ref || "").replace("release-control://", "")],
  ];
  for (const [family, id] of controls) {
    if (id) await jd("DELETE", `/v1/hypervisor/governance/${family}/${id}`);
  }
  await jd("POST", "/v1/hypervisor/auth/logout", undefined, MANAGED);
  await jd("DELETE", `/v1/hypervisor/principals/${verifierPrincipalId}`);
  await jd("POST", "/v1/hypervisor/harness-profiles/hp_opencode/disable");
  const fin = await jd("GET", "/v1/hypervisor/harness-profiles");
  ok("fixtures cleaned + drivers restored",
    (fin.j?.profiles || []).filter((p) => p.harness === "opencode").every((p) => p.lifecycle.status === "disabled"));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`improvement governance gates readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
