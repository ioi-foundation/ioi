#!/usr/bin/env node
// Auth-gated deployment posture + high-trust rollout enforcement done-bar.
//
// Proves the daemon knows WHICH WORLD it is running in (local_development |
// exposed_untrusted | authenticated_managed — derived from bind/forwarded exposure and the
// auth enforcement mode) and that learned-rollout trust follows: explicit overrides work
// ONLY in local development (labeled), exposed/managed postures fail them closed with
// rollout_explicit_override_disallowed, anonymous contexts never activate learned overlays
// outside local dev (rollout_requires_authenticated_context), sensitive endpoints 401
// unauthenticated when exposed, posture-blocked rollout decisions are receipted into the
// Work Ledger, and Governance/Operations/New-Session surfaces state the posture honestly.
// Exposure is simulated with x-forwarded-host (the daemon's own detection lane).
// Usage: node apps/hypervisor/scripts/verify-hypervisor-auth-gated-rollout-posture.mjs

import { chromium } from "playwright";

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const EXPOSED = { "x-forwarded-host": "hv.example.com" };

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
const preview = async (extra, headers) => jd("POST", "/v1/hypervisor/ioi-agent/launch-preview", {
  goal: "posture probe for rollout trust", strategy: "direct", policy_ref: BASE, ...extra,
}, headers);

async function run() {
  const tag = Date.now().toString(16);

  // ── Fixtures (built in local posture): member + outsider principals, project, cohort, variant ──
  const memberId = `usr_member${tag}`;
  const outsiderId = `usr_outsider${tag}`;
  await jd("POST", "/v1/hypervisor/principals", { email: `member-${tag}@local`, password: `pw-${tag}`, principal_id: memberId });
  await jd("POST", "/v1/hypervisor/principals", { email: `outsider-${tag}@local`, password: `pw-${tag}`, principal_id: outsiderId });
  const memberTok = (await jd("POST", "/v1/hypervisor/auth/login", { email: `member-${tag}@local`, password: `pw-${tag}` })).j.session_token || "";
  const outsiderTok = (await jd("POST", "/v1/hypervisor/auth/login", { email: `outsider-${tag}@local`, password: `pw-${tag}` })).j.session_token || "";
  const MEMBER = { authorization: `Bearer ${memberTok}` };
  const OUTSIDER = { authorization: `Bearer ${outsiderTok}` };
  const cohort = (await jd("POST", "/v1/hypervisor/governance/cohorts", {
    display_name: `Posture team ${tag}`, scope: "personal", member_refs: [`principal://${memberId}`],
  })).j?.cohort || {};
  const prop = (await jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", {
    proposal_kind: "launch_policy_suggestion", signal: "repeated_harness_model_preference",
    target_ref: BASE, evidence_refs: [`ioi-agent-launch://vfyauth-${tag}`],
    suggested: { description: `auth-${tag}`, privacy: { local_only: false, forbid_remote_trust: false, forbid_provider_credentials: false } },
  })).j?.proposal || {};
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/simulate`, { save: true });
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/approve`);
  const appr = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: prop.proposal_ref, request_kind: "improvement_apply", reason: `vfyauth-${tag}` })).j?.approval_request || {};
  await jd("PATCH", `/v1/hypervisor/governance/approval-requests/${appr.id}`, { transition: "approve", reviewer_ref: "principal://verifier" });
  const rel = (await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: prop.proposal_ref, rollout_mode: "cohort", cohort_refs: [cohort.ref], reason: `vfyauth-${tag}` })).j?.release_control || {};
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { transition: "open" });
  await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}`, { approval_request_ref: appr.ref, release_control_ref: rel.ref });
  const applied = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/apply`)).j?.proposal || {};
  const variantRef = String(applied.applied_ref || "");
  const variantId = variantRef.replace("ioi-agent-policy://", "");
  ok("fixtures ready (two principals, cohort, rollout-bound variant)", !!memberTok && !!outsiderTok && variantRef.startsWith("ioi-agent-policy://"));

  // ── local_development: posture stated, override allowed and LABELED ──
  const polLocal = (await jd("GET", "/v1/hypervisor/auth/policy")).j || {};
  ok("local posture declared with rollout trust semantics",
    polLocal.deployment_auth_posture === "local_development"
    && polLocal.rollout_trust?.explicit_override_allowed === true && polLocal.rollout_trust?.high_trust_required === false);
  const localOverride = (await preview({ rollout_context_ref: `principal://${memberId}` })).j;
  ok("local development: explicit override still activates the overlay, labeled as override",
    localOverride.policy_ref === variantRef && localOverride.deployment_auth_posture === "local_development"
    && localOverride.policy_rollout?.override === true && localOverride.policy_rollout?.rollout_context_source === "explicit_override");
  const localAnon = (await preview({})).j;
  ok("local anonymous posture is honest (deterministic local principal, local-dev-only note)",
    localAnon.rollout_context?.deployment_posture === "local_development"
    && String(localAnon.rollout_context?.posture_note || "").includes("local development only"));

  // ── exposed + auto: sensitive endpoints fail closed unauthenticated ──
  const sensitive = [
    ["POST", "/v1/hypervisor/ioi-agent/launch-preview", { goal: "probe" }],
    ["POST", "/v1/hypervisor/ioi-agent/launch", { goal: "probe" }],
    ["POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/apply`, {}],
    ["POST", "/v1/hypervisor/governance/cohorts", { display_name: "x" }],
    ["POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: "x://y" }],
    ["GET", "/v1/hypervisor/intelligence/spaces/default/export", undefined],
  ];
  const rejections = [];
  for (const [m, u, b] of sensitive) rejections.push(await jd(m, u, b, EXPOSED));
  ok("exposed instance rejects unauthenticated sensitive requests (401 across launch/apply/governance/vault)",
    rejections.every((r) => r.status === 401 && r.j?.reason === "authentication_required"),
    rejections.map((r) => r.status).join(","));

  // ── exposed + authenticated: managed posture; authenticated principal activates cohort rollout ──
  const managed = (await preview({}, { ...EXPOSED, ...MEMBER })).j;
  ok("authenticated principal activates the cohort rollout under authenticated_managed posture",
    managed.deployment_auth_posture === "authenticated_managed" && managed.policy_ref === variantRef
    && managed.policy_rollout?.rollout_context_source === "authenticated_principal"
    && String(managed.policy_rollout?.reason_code || "").startsWith("rollout_cohort_match"));
  const managedOverride = (await preview({ rollout_context_ref: `principal://${memberId}` }, { ...EXPOSED, ...OUTSIDER })).j;
  ok("explicit override fails closed in managed posture: rollout_explicit_override_disallowed",
    managedOverride.policy_ref === BASE && managedOverride.policy_rollout === null
    && (managedOverride.policy_rollout_skipped || []).some((x) => x.variant_policy_ref === variantRef && x.reason_code === "rollout_explicit_override_disallowed"));

  // ── exposed_untrusted (enforcement explicitly off while exposed) ──
  await jd("PUT", "/v1/hypervisor/auth/policy", { mode: "never" });
  try {
    const untrusted = (await preview({}, EXPOSED)).j;
    ok("exposed_untrusted posture is declared with an honest warning",
      untrusted.deployment_auth_posture === "exposed_untrusted"
      && String(untrusted.rollout_context?.posture_note || "").includes("EXPOSED without enforced authentication"));
    await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { rollout_mode: "canary", canary_percent: 100 });
    const anonCanary = (await preview({}, EXPOSED)).j;
    ok("anonymous context cannot activate a 100% canary outside local development",
      anonCanary.policy_ref === BASE
      && (anonCanary.policy_rollout_skipped || []).some((x) => x.reason_code === "rollout_requires_authenticated_context"));
    await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { rollout_mode: "cohort", cohort_refs: [cohort.ref] });
    const untrustedOverride = (await preview({ rollout_context_ref: `principal://${memberId}` }, EXPOSED)).j;
    ok("explicit override fails closed in exposed_untrusted posture",
      untrustedOverride.policy_ref === BASE
      && (untrustedOverride.policy_rollout_skipped || []).some((x) => x.reason_code === "rollout_explicit_override_disallowed"));

    // A posture-blocked rollout at LAUNCH time is a receipted security decision.
    const blockedLaunch = await jd("POST", "/v1/hypervisor/ioi-agent/launch", { goal: `vfyauth${tag} blocked override launch`, strategy: "direct", policy_ref: BASE, rollout_context_ref: `principal://${memberId}` }, EXPOSED);
    const ledger = (await jd("GET", "/v1/hypervisor/work-ledger")).j?.entries || [];
    const enforcement = ledger.find((e) => e.kind === "rollout_enforcement" && e.launch_ref === `ioi-agent-launch://${blockedLaunch.j?.launch_id}`);
    ok("Work Ledger records the blocked rollout decision with posture + reason",
      blockedLaunch.status === 403 && !!enforcement && enforcement.status === "blocked"
      && enforcement.deployment_posture === "exposed_untrusted"
      && (enforcement.blocked || []).some((x) => x.reason_code === "rollout_explicit_override_disallowed"));
  } finally {
    await jd("PUT", "/v1/hypervisor/auth/policy", { mode: "auto" });
  }
  const restored = (await jd("GET", "/v1/hypervisor/auth/policy")).j || {};
  ok("auth mode restored to auto (local posture back)", restored.policy?.mode === "auto" && restored.deployment_auth_posture === "local_development");

  // ── Governance overview + surfaces ──
  const ov = (await jd("GET", "/v1/hypervisor/governance/overview")).j || {};
  ok("governance overview declares deployment posture + rollout trust",
    ov.identity_posture?.deployment_auth_posture === "local_development"
    && ov.identity_posture?.rollout_trust?.explicit_override_allowed === true);

  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  await page.goto(`${SHELL}/__ioi/governance`, { waitUntil: "networkidle" });
  const govPosture = await page.locator("#auth-posture").innerText();
  ok("Governance cockpit shows posture, rollout trust, and override policy",
    /local_development/i.test(govPosture) && /allowed \(labeled\)/i.test(govPosture));
  await page.goto(`${SHELL}/__ioi/operations`, { waitUntil: "networkidle" });
  const opsPosture = await page.locator("#ops-auth-posture").innerText();
  ok("Operations shows the auth posture strip", /local_development/i.test(opsPosture) && /not enforced/i.test(opsPosture));
  await page.goto(`${SHELL}/`, { waitUntil: "networkidle" });
  await page.click('[data-testid="create-session-button"]');
  await page.waitForSelector("#ioi-ns-modal.open", { timeout: 15000 });
  await page.selectOption("#ioi-ns-policy", BASE);
  await page.fill("#ioi-ns-goal", "probe the local identity posture note");
  await page.waitForFunction(() => /identity/i.test(document.getElementById("ioi-ns-preview")?.innerText || ""), { timeout: 15000 });
  const modalText = await page.locator("#ioi-ns-preview").innerText();
  ok("New Session preview warns the deterministic local principal is local-development only",
    /deterministic local principal/i.test(modalText) && /local-development posture only/i.test(modalText));
  await page.keyboard.press("Escape");
  ok("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup (evidence receipts remain by design) ──
  await jd("POST", `/v1/hypervisor/ioi-agent/launch-policies/${variantId}/rollout/rollback`);
  await jd("DELETE", `/v1/hypervisor/ioi-agent/launch-policies/${variantId}`);
  await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${appr.id}`);
  await jd("DELETE", `/v1/hypervisor/governance/release-controls/${rel.id}`);
  await jd("DELETE", `/v1/hypervisor/governance/cohorts/${cohort.id}`);
  await jd("DELETE", `/v1/hypervisor/principals/${memberId}`);
  await jd("DELETE", `/v1/hypervisor/principals/${outsiderId}`);
  const finalPol = (await jd("GET", "/v1/hypervisor/auth/policy")).j || {};
  ok("fixtures cleaned + local posture intact", finalPol.deployment_auth_posture === "local_development");
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`auth-gated rollout posture readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch(async (e) => {
  await fetch(`${DAEMON}/v1/hypervisor/auth/policy`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ mode: "auto" }) }).catch(() => {});
  console.error("verifier crashed:", e);
  process.exit(1);
});
