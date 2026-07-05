#!/usr/bin/env node
// Principal-derived rollout context + durable cohort objects done-bar.
//
// Proves rollout eligibility is IDENTITY/PROJECT/COHORT-derived — never trusted from
// arbitrary caller text: launch preview/launch derive context from the authenticated
// principal (real login session) and daemon-known projects; explicit overrides stay
// possible but are LABELED and cannot masquerade as authenticated identity; cohorts are
// durable governance objects (member refs, scope, enable/disable) that ReleaseControls
// reference by cohort:// (raw member refs still honored but explicitly DEPRECATED);
// canary bucketing hashes the derived stable seed; every explanation names its source
// and matched cohort/member; receipts + Work Ledger cite cohort refs.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-principal-derived-rollout-cohorts.mjs

import { chromium } from "playwright";

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body, headers) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json", ...(headers || {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const BASE = "ioi-agent-policy://pol_fast_local";
const preview = async (extra, headers) => (await jd("POST", "/v1/hypervisor/ioi-agent/launch-preview", {
  goal: "probe derived rollout context", strategy: "direct", policy_ref: BASE, ...extra,
}, headers)).j;

async function run() {
  const tag = Date.now().toString(16);

  // ── Real identity: principal + login session (the derivation source, not caller text) ──
  const principalId = `usr_vfyroll${tag}`;
  await jd("POST", "/v1/hypervisor/principals", { email: `roll-${tag}@local`, name: `Roll ${tag}`, password: `pw-${tag}`, principal_id: principalId });
  const login = (await jd("POST", "/v1/hypervisor/auth/login", { email: `roll-${tag}@local`, password: `pw-${tag}` })).j || {};
  const AUTH = { authorization: `Bearer ${login.session_token || ""}` };
  ok("real principal + login session created", !!login.session_token && login.principal?.principal_id === principalId);

  // ── Daemon-known project (a caller-named project counts only when it RESOLVES) ──
  await jd("POST", "/v1/hypervisor/projects", { project_name: `vfyroll-${tag}`, repository_url: `https://github.com/ioi-foundation/vfyroll-${tag}` });
  const projects = (await jd("GET", "/v1/hypervisor/projects")).j;
  const projectId = ((projects.records || projects.projects || []).find((x) => String(x.project_id || "").includes(`vfyroll-${tag}`)) || {}).project_id || "";
  ok("daemon-known project created", projectId.length > 0, projectId);

  // ── Durable cohort object with validated member refs ──
  const cohort = (await jd("POST", "/v1/hypervisor/governance/cohorts", {
    display_name: `Canary team ${tag}`, scope: "project", description: "verifier rollout audience",
    member_refs: [`principal://${principalId}`, `project://${projectId}`],
    evidence_refs: [`improvement-proposal://vfyroll-${tag}`],
  })).j?.cohort || {};
  const badMember = await jd("POST", "/v1/hypervisor/governance/cohorts", { display_name: "x", member_refs: ["not-a-ref"] });
  const badScope = await jd("POST", "/v1/hypervisor/governance/cohorts", { display_name: "x", scope: "everyone" });
  ok("cohort object durable with validated members + scope",
    String(cohort.ref || "").startsWith("cohort://") && cohort.status === "active" && cohort.scope === "project"
    && (cohort.member_refs || []).length === 2
    && badMember.j?.error?.code === "governance_cohort_member_ref_invalid"
    && badScope.j?.error?.code === "governance_cohort_scope_invalid");

  // ── High-impact-capable learned suggestion → gate chain → cohort-scoped apply ──
  const prop = (await jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", {
    proposal_kind: "launch_policy_suggestion", signal: "repeated_harness_model_preference",
    target_ref: BASE, evidence_refs: [`ioi-agent-launch://vfyroll-${tag}`],
    suggested: { description: `roll-${tag}`, privacy: { local_only: false, forbid_remote_trust: false, forbid_provider_credentials: false } },
  })).j?.proposal || {};
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/simulate`, { save: true });
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/approve`);
  const appr = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: prop.proposal_ref, request_kind: "improvement_apply", reason: `vfyroll-${tag}` })).j?.approval_request || {};
  await jd("PATCH", `/v1/hypervisor/governance/approval-requests/${appr.id}`, { transition: "approve", reviewer_ref: "principal://verifier" });
  const badCohortRC = await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: prop.proposal_ref, rollout_mode: "cohort", cohort_refs: ["cohort://coh_missing"] });
  const rawRC = (await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: prop.proposal_ref, rollout_mode: "cohort", cohort_refs: [`project://${projectId}`], reason: `vfyroll-${tag}-raw` })).j?.release_control || {};
  const rel = (await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: prop.proposal_ref, rollout_mode: "cohort", cohort_refs: [cohort.ref], reason: `vfyroll-${tag}` })).j?.release_control || {};
  ok("ReleaseControl cohort_refs resolve to cohort objects; raw member refs marked DEPRECATED",
    badCohortRC.j?.error?.code === "governance_cohort_unresolved"
    && JSON.stringify(rawRC.deprecated_raw_cohort_refs) === JSON.stringify([`project://${projectId}`])
    && String(rawRC.cohort_refs_deprecation || "").includes("DEPRECATED")
    && JSON.stringify(rel.cohort_refs) === JSON.stringify([cohort.ref]) && (rel.deprecated_raw_cohort_refs || []).length === 0);
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { transition: "open" });
  await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}`, { approval_request_ref: appr.ref, release_control_ref: rel.ref });
  const applied = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/apply`)).j?.proposal || {};
  const variantRef = String(applied.applied_ref || "");
  const variantId = variantRef.replace("ioi-agent-policy://", "");
  ok("cohort-scoped apply creates the rollout-bound variant", applied.state === "applied" && variantRef.startsWith("ioi-agent-policy://"));

  // ── Eligibility derives from the AUTHENTICATED principal — no caller context passed ──
  const authed = await preview({}, AUTH);
  const authNote = authed.policy_rollout || {};
  ok("authenticated principal gets the overlay WITHOUT any explicit context",
    authed.policy_ref === variantRef && authed.rollout_context_source === "authenticated_principal"
    && authNote.rollout_context_source === "authenticated_principal"
    && authNote.matched_ref === `principal://${principalId}` && authNote.override === false
    && authNote.cohort_ref === cohort.ref && authNote.cohort_display_name === `Canary team ${tag}`,
    JSON.stringify(authNote).slice(0, 160));

  // ── Daemon-known project derives; unknown/ineligible contexts stay on base ──
  const viaProject = await preview({ project_ref: projectId });
  ok("daemon-known project derives eligibility (source: project, matched member named)",
    viaProject.policy_ref === variantRef && viaProject.policy_rollout?.rollout_context_source === "project"
    && viaProject.policy_rollout?.matched_ref === `project://${projectId}`);
  const anon = await preview({});
  const unknownProject = await preview({ project_ref: "project:not-a-real-project" });
  ok("anonymous + unknown-project contexts keep base, with honest posture + skip explanation",
    anon.policy_ref === BASE && anon.policy_rollout === null && anon.rollout_context_source === "anonymous"
    && String(anon.rollout_context?.posture_note || "").includes("identity enforcement inactive")
    && (anon.policy_rollout_skipped || []).some((x) => x.variant_policy_ref === variantRef && x.reason_code === "rollout_cohort_no_match")
    && unknownProject.rollout_context_source === "anonymous" && unknownProject.policy_ref === BASE);

  // ── Explicit override: still possible for test/dev, but LABELED — never authenticated ──
  const override = await preview({ rollout_context_ref: `principal://${principalId}` });
  ok("explicit override matches but is labeled and cannot masquerade as authenticated identity",
    override.policy_ref === variantRef && override.rollout_context_source === "explicit_override"
    && override.policy_rollout?.rollout_context_source === "explicit_override" && override.policy_rollout?.override === true);

  // ── Disabled cohorts never match ──
  await jd("PATCH", `/v1/hypervisor/governance/cohorts/${cohort.id}`, { transition: "disable" });
  const disabled = await preview({}, AUTH);
  await jd("PATCH", `/v1/hypervisor/governance/cohorts/${cohort.id}`, { transition: "enable" });
  ok("disabled cohort does not match (explained as rollout_cohort_disabled)",
    disabled.policy_ref === BASE
    && (disabled.policy_rollout_skipped || []).some((x) => x.variant_policy_ref === variantRef && x.reason_code === "rollout_cohort_disabled"));

  // ── Canary buckets the DERIVED stable seed ──
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { rollout_mode: "canary", canary_percent: 100 });
  const c1 = await preview({}, AUTH);
  const c2 = await preview({}, AUTH);
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { canary_percent: 0 });
  const cMiss = await preview({}, AUTH);
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { rollout_mode: "cohort", cohort_refs: [cohort.ref] });
  ok("canary bucketing hashes the derived principal seed and is stable across calls",
    c1.policy_ref === variantRef && String(c1.policy_rollout?.reason_code || "").startsWith("rollout_canary_bucket:")
    && c1.policy_rollout?.reason_code === c2.policy_rollout?.reason_code
    && c1.policy_rollout?.matched_ref === `principal://${principalId}`
    && cMiss.policy_ref === BASE
    && (cMiss.policy_rollout_skipped || []).some((x) => String(x.reason_code || "").startsWith("rollout_canary_bucket_miss:")));

  // ── UI: Cohorts tab, cohort picker on release forms, cohort names on policy cards, modal explanation ──
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  await page.goto(`${SHELL}/__ioi/governance?tab=cohorts`, { waitUntil: "networkidle" });
  const cohortCard = await page.locator(`[data-cohort="${cohort.id}"]`).innerText();
  ok("Governance cockpit Cohorts tab lists the cohort with members + disable control",
    new RegExp(`Canary team ${tag}`).test(cohortCard) && cohortCard.includes(`principal://${principalId}`)
    && await page.locator(`[data-cohort="${cohort.id}"] form[action*="/transition"] button`).count() === 1
    && await page.locator(`form[action="/__ioi/governance/cohorts"] input[name="display_name"]`).count() === 1);
  await page.goto(`${SHELL}/__ioi/governance?tab=releases`, { waitUntil: "networkidle" });
  ok("ReleaseControl form uses a rollout-mode select + cohort picker (not raw text refs)",
    await page.locator(`select[name="rollout_mode"]`).count() === 1
    && await page.locator(`select[name="cohort_refs"] option[value="${cohort.ref}"]`).count() >= 1);
  await page.goto(`${SHELL}/__ioi/agent-studio#launch-policies`, { waitUntil: "networkidle" });
  const card = await page.locator(`.lpcard[data-policy="${variantId}"]`).innerText();
  ok("Agent Studio rollout card names its cohort audience", new RegExp(`cohort: Canary team ${tag}`, "i").test(card));
  await page.goto(`${SHELL}/`, { waitUntil: "networkidle" });
  await page.click('[data-testid="create-session-button"]');
  // New Session now routes to the composer page; the owned modal opens via Advanced launch.
  await page.waitForSelector("#ioi-ns-advanced", { timeout: 15000 });
  await page.click("#ioi-ns-advanced");
  await page.waitForSelector("#ioi-ns-modal.open", { timeout: 15000 });
  await page.selectOption("#ioi-ns-policy", BASE);
  await page.fill("#ioi-ns-goal", "probe why the rollout does not apply here");
  await page.waitForFunction(() => /rollout/i.test(document.getElementById("ioi-ns-preview")?.innerText || ""), { timeout: 15000 });
  const modalText = await page.locator("#ioi-ns-preview").innerText();
  ok("New Session preview explains why the rollout did NOT apply (anonymous browser context)",
    /not applied/i.test(modalText) && /rollout_cohort_no_match/.test(modalText) && /context: anonymous/i.test(modalText));
  await page.keyboard.press("Escape");
  ok("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();

  // ── Receipts + ledger cite cohort refs ──
  await jd("POST", `/v1/hypervisor/ioi-agent/launch-policies/${variantId}/rollout/rollback`);
  const ledger = (await jd("GET", "/v1/hypervisor/work-ledger")).j?.entries || [];
  const entry = ledger.find((e) => e.kind === "policy_rollout" && e.status === "rollback" && e.policy_ref === variantRef);
  ok("rollout receipts + Work Ledger cite cohort refs and mode",
    !!entry && JSON.stringify(entry.cohort_refs) === JSON.stringify([cohort.ref]) && entry.rollout_mode === "cohort"
    && entry.proposal_ref === prop.proposal_ref && entry.release_control_ref === rel.ref);
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup (evidence receipts remain by design) ──
  await jd("DELETE", `/v1/hypervisor/ioi-agent/launch-policies/${variantId}`);
  await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${appr.id}`);
  await jd("DELETE", `/v1/hypervisor/governance/release-controls/${rel.id}`);
  await jd("DELETE", `/v1/hypervisor/governance/release-controls/${rawRC.id}`);
  await jd("DELETE", `/v1/hypervisor/governance/cohorts/${cohort.id}`);
  await jd("DELETE", `/v1/hypervisor/principals/${principalId}`);
  const gone = (await jd("GET", "/v1/hypervisor/governance/cohorts")).j?.cohorts || [];
  ok("fixtures cleaned", !gone.some((c) => c.id === cohort.id));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`principal-derived rollout cohorts readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
