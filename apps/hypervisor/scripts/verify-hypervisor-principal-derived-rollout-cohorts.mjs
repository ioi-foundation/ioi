#!/usr/bin/env node
// Durable cohort objects + the release gate done-bar — re-typed (R-240, GoalRun residue, 2026-09-29).
//
// WHAT THIS PROVED. Rollout eligibility derived from identity, project and cohort — never from
// caller text — read through the IOI Agent launch preview/launch: the authenticated principal, a
// daemon-known project or a labelled explicit override matched a cohort-scoped learned launch-policy
// VARIANT; disabled cohorts never matched; canary bucketing hashed the derived seed; the Agent Studio
// rollout card and the New Session preview explained it; rollout receipts cited the cohort. Every
// one of those reads ran through the IOI Agent launch lane and its launch-policy plane, and R-192
// (S5-1) took goal pursuit out of the Hypervisor — a goal run is an ioi.ai composition over the
// thread orchestration primitives (standing owner ruling 2026-09-24) — so the variant, the preview
// overlay and the rollout receipts are gone, and this verifier crashed on its first read.
//
// WHAT IT PROVES NOW, on a stack it owns as that stack's signed-in operator: cohorts are still
// durable governance objects (validated member refs and scope, disable/enable on the record) that
// ReleaseControls reference by cohort:// — raw member refs still honoured but explicitly DEPRECATED —
// and the Governance cockpit lists and picks them; the gate ApprovalRequest is DECIDED by the
// authenticated session (GOV-ATTR-1: the body names no reviewer, the record reports that session's
// server-derived `user://<principal_id>`; canon `identity-access-and-metering.md`); and the one step
// that would have written a launch-policy variant is refused BY NAME (410
// `ioi_agent_launch_policy_retired`).
//
// RE-AIMED 2026-09-29 (R-240, launcher leftovers): the improvement plane now refuses a launch-policy
// suggestion at PROPOSE, by name, and admits nothing. The cohort-gated learned change is an
// automation-readiness suggestion, and it applies through the satisfied cohort gate.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-principal-derived-rollout-cohorts.mjs  (≈1 min)
// Its own isolated daemon + serve, the operator signed in (lib/verifier-stack.mjs); an explicit
// URL naming the owner's stack (:8765, :36173, :4173) is refused.

import { chromium } from "playwright";
import { ANONYMOUS, verifierStack } from "./lib/verifier-stack.mjs";

const STACK = await verifierStack({ serve: true });
const DAEMON = STACK.daemonUrl;
const SHELL = STACK.serveUrl;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
// Every request carries the stack operator's session (verifier-stack) unless it names its own
// `authorization` (the principal's session) or opts out with ANONYMOUS (its own login).
async function jd(method, url, body, headers) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json", ...(headers || {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const BASE = "ioi-agent-policy://pol_fast_local";

async function run() {
  const tag = Date.now().toString(16);

  // ── Real identity: principal + login session ──
  // Provisioning a principal is org-admin governed EVEN ON LOOPBACK, so the fixture is created
  // through the stack operator's session and then logs in for itself through the public login.
  const OPERATOR = { authorization: `Bearer ${STACK.token}` };
  const principalId = `usr_vfyroll${tag}`;
  const password = `roll-${tag}-principal-pass`;
  const created = await jd("POST", "/v1/hypervisor/principals", { email: `roll-${tag}@local`, name: `Roll ${tag}`, password, principal_id: principalId }, OPERATOR);
  const login = (await jd("POST", "/v1/hypervisor/auth/login", { email: `roll-${tag}@local`, password }, { [ANONYMOUS]: "1" })).j || {};
  const AUTH = { authorization: `Bearer ${login.session_token || ""}` };
  // Ask the daemon WHO this session is; the reviewer ref asserted below is its answer, not a value
  // assembled here. An unadmitted fixture would decide anonymously, so it fails the verifier now.
  const who = login.session_token ? (await jd("GET", "/v1/hypervisor/auth/whoami", undefined, AUTH)).j || {} : {};
  const derivedPrincipalId = who.authenticated === true ? String(who.principal?.principal_id || "") : "";
  const REVIEWER_REF = `user://${derivedPrincipalId}`;
  ok("real principal + login session created", !!login.session_token && login.principal?.principal_id === principalId);
  if (!derivedPrincipalId) throw new Error(`identity fixture NOT admitted (create ${created.status}, whoami ${JSON.stringify(who).slice(0, 200)}) — the gate decision cannot cross the real identity seam`);

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

  // ── A learned suggestion reaches the gate; the gate is decided by the authenticated session ──
  const policyRefused = await jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", {
    proposal_kind: "launch_policy_suggestion", signal: "repeated_harness_model_preference",
    target_ref: BASE, evidence_refs: [`work-result://vfyroll-${tag}`],
    suggested: { description: `roll-${tag}`, privacy: { local_only: false, forbid_remote_trust: false, forbid_provider_credentials: false } },
  });
  ok("a learned launch-policy suggestion is refused at propose by name (410 ioi_agent_launch_policy_retired) — no cohort-scoped variant can be proposed",
    policyRefused.status === 410 && policyRefused.j?.error?.code === "ioi_agent_launch_policy_retired" && !policyRefused.j?.proposal,
    `${policyRefused.status} ${policyRefused.j?.error?.code}`);
  const prop = (await jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", {
    proposal_kind: "automation_readiness", signal: "repeated_successful_goal_pattern",
    evidence_refs: [`work-result://vfyroll-${tag}`],
    suggested: { title: `roll-${tag}`, goal_pattern: `vfyroll ${tag}` },
  })).j?.proposal || {};
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/simulate`, { save: true });
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/approve`);
  const appr = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: prop.proposal_ref, request_kind: "improvement_apply", reason: `vfyroll-${tag}` })).j?.approval_request || {};
  // The gate approval is DECIDED by that same session — no reviewer named in the body (GOV-ATTR-1).
  await jd("PATCH", `/v1/hypervisor/governance/approval-requests/${appr.id}`, { transition: "approve" }, AUTH);
  const apprDecided = (await jd("GET", `/v1/hypervisor/governance/approval-requests/${appr.id}`)).j?.approval_request || {};
  ok("the gate approval is attributed to the SERVER-DERIVED principal of the deciding session",
    apprDecided.status === "approved" && apprDecided.reviewer_ref === REVIEWER_REF,
    `reviewer ${apprDecided.reviewer_ref} · expected ${REVIEWER_REF}`);
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
  const applied = await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/apply`);
  ok("the cohort-gated learned change applies through the satisfied gate, citing the cohort-scoped release",
    applied.status === 200 && applied.j?.proposal?.state === "applied" && String(applied.j?.proposal?.applied_ref || "").startsWith("automation-affinity://")
    && applied.j?.proposal?.release_control_ref === rel.ref,
    `${applied.status} ${applied.j?.proposal?.state} ${applied.j?.proposal?.applied_ref}`);

  // R-240 (2026-09-29): eligibility derivation (authenticated principal, daemon-known project,
  // anonymous and unknown-project contexts, a labelled explicit override, canary bucketing of the
  // derived seed) was read off the IOI Agent launch preview's `policy_rollout` overlay. That preview
  // is retired with goal pursuit; the cohort's own disable/enable is what remains on the record.
  const cohortRead = async () => ((await jd("GET", "/v1/hypervisor/governance/cohorts")).j?.cohorts || []).find((c) => c.id === cohort.id) || {};
  await jd("PATCH", `/v1/hypervisor/governance/cohorts/${cohort.id}`, { transition: "disable" });
  const disabled = await cohortRead();
  await jd("PATCH", `/v1/hypervisor/governance/cohorts/${cohort.id}`, { transition: "enable" });
  const enabled = await cohortRead();
  ok("a cohort disables and re-enables on its own record", disabled.status === "disabled" && enabled.status === "active", `${disabled.status} → ${enabled.status}`);

  // ── UI: Cohorts tab and the cohort picker on release forms ──
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  await STACK.signIn(page);
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
  // R-240 (2026-09-29): the Agent Studio rollout card naming its cohort, the New Session preview's
  // "why the rollout did not apply" and the rollout receipts citing cohort refs all belonged to the
  // retired launch-policy variant; nothing is left to render them over.
  ok("no page errors", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup (evidence receipts remain by design) ──
  const affId = String(applied.j?.proposal?.applied_ref || "").replace("automation-affinity://", "");
  if (affId) await jd("PATCH", `/v1/hypervisor/automation-affinities/${affId}`, { status: "archived" });
  await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${appr.id}`);
  await jd("DELETE", `/v1/hypervisor/governance/release-controls/${rel.id}`);
  await jd("DELETE", `/v1/hypervisor/governance/release-controls/${rawRC.id}`);
  await jd("DELETE", `/v1/hypervisor/governance/cohorts/${cohort.id}`);
  await jd("DELETE", `/v1/hypervisor/principals/${principalId}`, undefined, OPERATOR);
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
