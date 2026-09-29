#!/usr/bin/env node
// Auth-gated deployment posture + high-trust rollout enforcement done-bar.
//
// Proves the daemon knows WHICH WORLD it is running in (local_development |
// exposed_untrusted | authenticated_managed — derived from bind/forwarded exposure and the
// auth enforcement mode) and that the trust it declares follows: explicit rollout overrides are
// allowed (labeled) only in local development, exposed and managed postures declare them failed
// closed and require an authenticated principal, sensitive endpoints 401 unauthenticated when
// exposed, an exposed instance with enforcement OFF refuses global work truth, and the
// Governance/Operations surfaces state the posture honestly.
// Exposure is simulated with x-forwarded-host (the daemon's own detection lane).
// GOV-ATTR-1: the gate ApprovalRequest this chain needs is DECIDED by the member session — the
// request body names no reviewer, and the record must report that session's server-derived
// `user://<principal_id>`. Canon: `identity-access-and-metering.md`.
//
// RE-TYPED 2026-09-29 (R-240, GoalRun residue). The per-context rollout decisions — an override
// activating a learned launch-policy VARIANT in local development, an authenticated member matching
// its cohort, anonymous and overriding contexts failing closed, a posture-blocked launch receipted in
// the ledger, the New Session preview's identity note — were all read through the IOI Agent launch
// preview/launch and its launch-policy plane. R-192 (S5-1) took goal pursuit out of the Hypervisor
// (a goal run is an ioi.ai composition over the thread orchestration primitives; standing owner
// ruling 2026-09-24), so those reads crashed. Each posture claim is now read from the daemon's own
// declaration of it (GET /v1/hypervisor/auth/policy under that posture), the blocked-decision claim
// from the platform's own work-truth refusal, the variant step is asserted refused by name, and the
// sensitive-endpoint probe names the Hypervisor's own launch lane (session create) instead of the
// retired IOI Agent routes.
//
// RE-AIMED 2026-09-29 (R-240, launcher leftovers): the improvement plane refuses a launch-policy
// suggestion at PROPOSE now (410 `ioi_agent_launch_policy_retired`, nothing admitted), so the gate
// chain's subject is an automation-readiness suggestion and the refusal is asserted at propose.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-auth-gated-rollout-posture.mjs  (≈1 min)
// Its own isolated daemon + serve, the operator signed in (lib/verifier-stack.mjs); an explicit
// URL naming the owner's stack (:8765, :36173, :4173) is refused.

import http from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { verifierStack } from "./lib/verifier-stack.mjs";

const STACK = await verifierStack({ serve: true });
const DAEMON = STACK.daemonUrl;
const SHELL = STACK.serveUrl;
const EXPOSED = { "x-forwarded-host": "hv.example.com" };
// The stack's signed-in operator: provisioning a principal and every control-plane write is
// org-admin governed even on loopback, so there is no anonymous fixture shortcut.
const OPERATOR_SESSION = STACK.token;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
// node:http, not fetch: verifier-stack attaches the operator's session to every fetch on the stack's
// origins, and the posture reads and exposed probes below must stay ANONYMOUS — a call names its
// caller explicitly (OPERATOR / MEMBER / OUTSIDER) or it has none.
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
// ── Static self-check: no anonymous enforcement-mode mutation may re-enter this file ────────────
//
// Setting the daemon's enforcement mode is org-admin gated. Sent anonymously it is a 401 no-op, and
// a no-op is invisible at runtime: the posture simply stays put, so the "exposed_untrusted" block
// would keep passing while measuring local_development, and the restore path would keep "succeeding"
// while leaving authentication disabled. There is no observation point that catches that from the
// outside — which is exactly why the guard reads this file's OWN source instead.
//
// Each reference is expanded to its ENCLOSING call and deduplicated by source offset, so a path
// named twice inside one call (the recovery fetch and its operator-facing error message) counts
// once, and a fixed character window can never smear a nearby mutation onto a neighbouring read.
const SOURCE = readFileSync(fileURLToPath(import.meta.url), "utf8");
function enclosingCall(source, at) {
  const open = Math.max(source.lastIndexOf("jd(", at), source.lastIndexOf("fetch(", at));
  if (open < 0) return { start: -1, text: "" };
  let depth = 0;
  for (let i = source.indexOf("(", open); i >= 0 && i < source.length; i++) {
    if (source[i] === "(") depth++;
    else if (source[i] === ")" && --depth === 0) return { start: open, text: source.slice(open, i + 1) };
  }
  return { start: open, text: source.slice(open) };
}
const AUTH_POLICY_CALLS = [...new Map(
  [...SOURCE.matchAll(/\/v1\/hypervisor\/auth\/policy/g)]
    .map((m) => enclosingCall(SOURCE, m.index))
    .filter((call) => call.start >= 0)
    .map((call) => [call.start, call.text]),
).values()];
// Mutations only — reads are ungated and deliberately stay anonymous so the posture they report is
// the posture an unauthenticated caller sees.
const AUTH_POLICY_MUTATIONS = AUTH_POLICY_CALLS.filter((text) => /"PUT"|method:\s*"PUT"/.test(text));
const AUTHORIZED_MUTATIONS = AUTH_POLICY_MUTATIONS.filter((text) => /OPERATOR/.test(text));
// The count is pinned, not merely compared: a NEW mutation site has to be added deliberately and
// re-counted here, so growth cannot slip in unexamined, and an empty scan cannot pass vacuously.
const EXPECTED_POLICY_MUTATIONS = 3;

const BASE = "ioi-agent-policy://pol_fast_local";

async function run() {
  // Runs FIRST and needs no daemon: if a policy mutation ever loses its operator authorization, the
  // failure must be named here rather than dissolving into a silently unchanged posture downstream.
  ok("every enforcement-mode mutation in this verifier carries the operator authorization (static self-check)",
    AUTH_POLICY_MUTATIONS.length === EXPECTED_POLICY_MUTATIONS && AUTHORIZED_MUTATIONS.length === AUTH_POLICY_MUTATIONS.length,
    `${AUTH_POLICY_MUTATIONS.length}/${EXPECTED_POLICY_MUTATIONS} mutation sites found · ${AUTHORIZED_MUTATIONS.length} carry operator authority`);

  const tag = Date.now().toString(16);

  // ── Fixtures (built in local posture): member + outsider principals, cohort, the gate chain ──
  // Provisioning a principal is org-admin governed EVEN ON LOOPBACK, so the fixtures are created
  // through the stack operator's session, then each principal logs in for itself through the
  // public login endpoint.
  const OPERATOR = { authorization: `Bearer ${OPERATOR_SESSION}` };
  const memberId = `usr_member${tag}`;
  const outsiderId = `usr_outsider${tag}`;
  const memberCreate = await jd("POST", "/v1/hypervisor/principals", { email: `member-${tag}@local`, password: `member-${tag}-pass`, principal_id: memberId }, OPERATOR);
  await jd("POST", "/v1/hypervisor/principals", { email: `outsider-${tag}@local`, password: `outsider-${tag}-pass`, principal_id: outsiderId }, OPERATOR);
  const memberLogin = (await jd("POST", "/v1/hypervisor/auth/login", { email: `member-${tag}@local`, password: `member-${tag}-pass` })).j || {};
  const outsiderLogin = (await jd("POST", "/v1/hypervisor/auth/login", { email: `outsider-${tag}@local`, password: `outsider-${tag}-pass` })).j || {};
  const memberTok = memberLogin.session_token || "";
  const outsiderTok = outsiderLogin.session_token || "";
  const MEMBER = { authorization: `Bearer ${memberTok}` };
  const OUTSIDER = { authorization: `Bearer ${outsiderTok}` };
  // GOV-ATTR-1 — the member session is also the identity that DECIDES the governance approval this
  // fixture chain needs. Canon (`identity-access-and-metering.md`): request bodies never select the
  // acting principal, so the transition below names no reviewer and the daemon must attribute it to
  // the server-derived ref of this session. `whoami` is asked WHO that session is, so the expected
  // reviewer ref is the daemon's own answer rather than a value assembled here. Fail outright
  // rather than let an unadmitted fixture turn the decision into an anonymous one that proves
  // nothing.
  const memberWho = memberTok ? (await jd("GET", "/v1/hypervisor/auth/whoami", undefined, MEMBER)).j || {} : {};
  const memberPrincipalId = memberWho.authenticated === true ? String(memberWho.principal?.principal_id || "") : "";
  const MEMBER_REVIEWER_REF = `user://${memberPrincipalId}`;
  if (!memberPrincipalId || !outsiderTok) {
    throw new Error(`identity fixtures NOT admitted (member create ${memberCreate.status}, member whoami ${JSON.stringify(memberWho).slice(0, 200)}, outsider token ${outsiderTok ? "present" : "absent"}) — the posture walk cannot cross the real identity seam`);
  }
  const cohort = (await jd("POST", "/v1/hypervisor/governance/cohorts", {
    display_name: `Posture team ${tag}`, scope: "personal", member_refs: [`principal://${memberId}`],
  }, OPERATOR)).j?.cohort || {};
  const policyRefused = await jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", {
    proposal_kind: "launch_policy_suggestion", signal: "repeated_harness_model_preference",
    target_ref: BASE, evidence_refs: [`work-result://vfyauth-${tag}`],
    suggested: { description: `auth-${tag}`, privacy: { local_only: false, forbid_remote_trust: false, forbid_provider_credentials: false } },
  }, OPERATOR);
  const prop = (await jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", {
    proposal_kind: "automation_readiness", signal: "repeated_successful_goal_pattern",
    evidence_refs: [`work-result://vfyauth-${tag}`],
    suggested: { title: `auth-${tag}`, goal_pattern: `vfyauth ${tag}` },
  }, OPERATOR)).j?.proposal || {};
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/simulate`, { save: true }, OPERATOR);
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/approve`, undefined, OPERATOR);
  const appr = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: prop.proposal_ref, request_kind: "improvement_apply", reason: `vfyauth-${tag}` }, OPERATOR)).j?.approval_request || {};
  // The approval is DECIDED by the member session — no reviewer named in the body (GOV-ATTR-1).
  await jd("PATCH", `/v1/hypervisor/governance/approval-requests/${appr.id}`, { transition: "approve" }, MEMBER);
  const apprDecided = (await jd("GET", `/v1/hypervisor/governance/approval-requests/${appr.id}`, undefined, OPERATOR)).j?.approval_request || {};
  ok("the gate approval is attributed to the SERVER-DERIVED principal of the deciding session",
    apprDecided.status === "approved" && apprDecided.reviewer_ref === MEMBER_REVIEWER_REF,
    `reviewer ${apprDecided.reviewer_ref} · expected ${MEMBER_REVIEWER_REF}`);
  const rel = (await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: prop.proposal_ref, rollout_mode: "cohort", cohort_refs: [cohort.ref], reason: `vfyauth-${tag}` }, OPERATOR)).j?.release_control || {};
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { transition: "open" }, OPERATOR);
  await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}`, { approval_request_ref: appr.ref, release_control_ref: rel.ref }, OPERATOR);
  ok("fixtures ready (two principals, cohort, an open cohort release control) and the launch-policy suggestion refused at propose by name (410 ioi_agent_launch_policy_retired, nothing admitted)",
    !!memberTok && !!outsiderTok && String(cohort.ref || "").startsWith("cohort://") && String(rel.ref || "").startsWith("release-control://")
    && policyRefused.status === 410 && policyRefused.j?.error?.code === "ioi_agent_launch_policy_retired" && !policyRefused.j?.proposal,
    `${cohort.ref} · ${rel.ref} · propose ${policyRefused.status} ${policyRefused.j?.error?.code}`);

  // ── local_development: posture stated, overrides allowed only LABELED ──
  const polLocal = (await jd("GET", "/v1/hypervisor/auth/policy")).j || {};
  ok("local posture declared with rollout trust semantics",
    polLocal.deployment_auth_posture === "local_development"
    && polLocal.rollout_trust?.explicit_override_allowed === true && polLocal.rollout_trust?.high_trust_required === false);
  ok("local development states its deterministic local principal and that an explicit override is allowed only labeled",
    /deterministic local principal/.test(polLocal.rollout_trust?.note || "") && /allowed and labeled/.test(polLocal.rollout_trust?.note || ""),
    polLocal.rollout_trust?.note);

  // ── exposed + auto: sensitive endpoints fail closed unauthenticated ──
  const sensitive = [
    ["POST", "/v1/hypervisor/sessions", {}],
    ["POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/apply`, {}],
    ["POST", "/v1/hypervisor/governance/cohorts", { display_name: "x" }],
    ["POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: "x://y" }],
    ["GET", "/v1/hypervisor/intelligence/spaces/default/export", undefined],
  ];
  const rejections = [];
  for (const [m, u, b] of sensitive) rejections.push(await jd(m, u, b, EXPOSED));
  ok("exposed instance rejects unauthenticated sensitive requests (401 across session launch/apply/governance/vault)",
    rejections.every((r) => r.status === 401 && r.j?.reason === "authentication_required"),
    rejections.map((r) => r.status).join(","));

  // ── exposed + authenticated: managed posture, high trust required, overrides closed ──
  const managed = (await jd("GET", "/v1/hypervisor/auth/policy", undefined, { ...EXPOSED, ...MEMBER })).j || {};
  const managedOutsider = (await jd("GET", "/v1/hypervisor/auth/policy", undefined, { ...EXPOSED, ...OUTSIDER })).j || {};
  ok("an authenticated principal on the exposed instance reads authenticated_managed: high trust required, explicit overrides fail closed",
    [managed, managedOutsider].every((p) => p.deployment_auth_posture === "authenticated_managed" && p.effective_enforced === true
      && p.rollout_trust?.high_trust_required === true && p.rollout_trust?.explicit_override_allowed === false
      && /explicit overrides fail closed/.test(p.rollout_trust?.note || "")),
    `${managed.deployment_auth_posture} / ${managedOutsider.deployment_auth_posture}`);

  // ── exposed_untrusted (enforcement explicitly off while exposed) ──
  // Setting the enforcement mode is an org-admin-gated MUTATION, so it goes out as the operator.
  // Unauthenticated it is a 401 no-op: the posture never changes, every assertion below then
  // measures local_development while claiming to measure exposed_untrusted, and the verifier
  // reports a pass for a world it never entered.
  const untrustedSet = await jd("PUT", "/v1/hypervisor/auth/policy", { mode: "never" }, OPERATOR);
  ok("operator authority actually set the enforcement mode to never (posture change is real)",
    untrustedSet.status === 200 && untrustedSet.j?.policy?.mode === "never",
    `status ${untrustedSet.status} · mode ${untrustedSet.j?.policy?.mode}`);
  try {
    const untrusted = (await jd("GET", "/v1/hypervisor/auth/policy", undefined, EXPOSED)).j || {};
    ok("exposed_untrusted posture is declared honestly: exposed, enforcement off, high trust required, explicit overrides fail closed",
      untrusted.deployment_auth_posture === "exposed_untrusted" && untrusted.exposed === true && untrusted.effective_enforced === false
      && untrusted.rollout_trust?.high_trust_required === true && untrusted.rollout_trust?.explicit_override_allowed === false,
      `${untrusted.deployment_auth_posture} · enforced ${untrusted.effective_enforced}`);
    // A posture-blocked decision is still a typed refusal: the platform's own work truth (WorkResults
    // and the Work Ledger) is withheld from an exposed instance that enforces no identity.
    const workResults = await jd("GET", "/v1/hypervisor/work-results", undefined, EXPOSED);
    const workLedger = await jd("GET", "/v1/hypervisor/work-ledger", undefined, EXPOSED);
    ok("exposed_untrusted withholds global work truth by name (work results and the work ledger)",
      workResults.status === 403 && workResults.j?.error?.code === "work_truth_exposed_untrusted_refused"
      && workLedger.status === 403 && JSON.stringify(workLedger.j).includes("work_ledger_exposed_untrusted_refused"),
      `work-results ${workResults.status} ${workResults.j?.error?.code} · work-ledger ${workLedger.status} ${workLedger.j?.error?.code ?? workLedger.j?.code}`);
  } finally {
    // Restoring the posture is the same gated mutation as setting it. Anonymous, this leaves the
    // deployment enforcing `never` after the run — the verifier would have disabled authentication
    // on the daemon it was asked to prove enforces it.
    await jd("PUT", "/v1/hypervisor/auth/policy", { mode: "auto" }, OPERATOR);
  }
  const restored = (await jd("GET", "/v1/hypervisor/auth/policy")).j || {};
  ok("auth mode restored to auto (local posture back)", restored.policy?.mode === "auto" && restored.deployment_auth_posture === "local_development");

  // ── Governance overview + surfaces ──
  const ov = (await jd("GET", "/v1/hypervisor/governance/overview", undefined, OPERATOR)).j || {};
  ok("governance overview declares deployment posture + rollout trust",
    ov.identity_posture?.deployment_auth_posture === "local_development"
    && ov.identity_posture?.rollout_trust?.explicit_override_allowed === true);

  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  await STACK.signIn(page);
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  await page.goto(`${SHELL}/__ioi/governance`, { waitUntil: "networkidle" });
  const govPosture = await page.locator("#auth-posture").innerText();
  ok("Governance cockpit shows posture, rollout trust, and override policy",
    /local_development/i.test(govPosture) && /allowed \(labeled\)/i.test(govPosture));
  await page.goto(`${SHELL}/__ioi/operations`, { waitUntil: "networkidle" });
  const opsPosture = await page.locator("#ops-auth-posture").innerText();
  ok("Operations shows the auth posture strip", /local_development/i.test(opsPosture) && /not enforced/i.test(opsPosture));
  // R-240 (2026-09-29): the New Session preview's "deterministic local principal" note came from the
  // retired launch-policy chooser's preview; the launcher now previews placement, and the posture
  // note is asserted above from the daemon's own declaration.
  ok("no page errors", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup (evidence receipts remain by design) ──
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/reject`, { reason: "verifier fixture" }, OPERATOR);
  await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${appr.id}`, undefined, OPERATOR);
  await jd("DELETE", `/v1/hypervisor/governance/release-controls/${rel.id}`, undefined, OPERATOR);
  await jd("DELETE", `/v1/hypervisor/governance/cohorts/${cohort.id}`, undefined, OPERATOR);
  await jd("DELETE", `/v1/hypervisor/principals/${memberId}`, undefined, OPERATOR);
  await jd("DELETE", `/v1/hypervisor/principals/${outsiderId}`, undefined, OPERATOR);
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
  // Crash recovery restores the enforcement mode, which is the SAME org-admin-gated mutation as
  // setting it — the operator authorization is not optional here just because the run is failing.
  // Anonymous, this swallowed a 401 and left the daemon enforcing `never`: the one path that runs
  // precisely when something already went wrong was the one that could not put the posture back.
  // The outcome is reported rather than discarded, because a restore that did not land is a
  // standing posture change on the deployment and the operator has to know to undo it by hand.
  const restored = await fetch(`${DAEMON}/v1/hypervisor/auth/policy`, {
    method: "PUT",
    headers: { "content-type": "application/json", ...(OPERATOR_SESSION ? { authorization: `Bearer ${OPERATOR_SESSION}` } : {}) },
    body: JSON.stringify({ mode: "auto" }),
  }).then((r) => r.ok).catch(() => false);
  if (!restored) console.error(`POSTURE NOT RESTORED — the daemon may still be enforcing mode 'never'. Re-send PUT /v1/hypervisor/auth/policy {"mode":"auto"} with the stack operator's session.`);
  // Print what was decided before the crash. The static self-check runs first and needs no daemon,
  // so discarding the results here would hide the one assertion that still had an answer.
  for (const r of results) console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  console.error("verifier crashed:", e);
  process.exit(1);
});
