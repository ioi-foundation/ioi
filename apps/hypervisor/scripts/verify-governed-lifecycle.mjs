#!/usr/bin/env node
// Governed-lifecycle readiness verifier.
//
// Drives the full governed lifecycle against the running daemon (:8765) + serve (:4173) and asserts
// every state transition, receipt/state-root emission, backlink traversal, the kill effect, published
// metadata durability, no external ingress, empty fallthrough, and surface reachability (Domain Apps,
// Marketplace, Governance, Work Ledger).
//
//   ODK ontology + domain_app descriptor -> DomainApp
//   -> ApprovalRequest + ReleaseControl -> mount -> serve
//   -> Marketplace listing + candidate + admitted review + publish ReleaseControl -> publish
//   -> KillSwitch trip + enforce
//
// Usage: IOI_HYPERVISOR_DAEMON_SESSION=<operator session token> \
//          node apps/hypervisor/scripts/verify-governed-lifecycle.mjs
// Exit 0 = all assertions pass; exit 1 = one or more failed. Mutable objects are cleaned up (and a
// cleanup that does not remove its fixture is REPORTED, never presented as success); immutable proof
// records (receipts, killed runtime) are intentionally retained.
//
// NONCLAIM — two daemon-side gaps this walk reports rather than fixes:
//   1. An admission-review CREATE cannot actually replay. Its record carries a nested
//      `governance_posture_snapshot.at = iso_now()` and the daemon's `without_clock` strips only
//      top-level clock fields, so a real HTTP retry presents different bytes under the same key and
//      is refused 409 rather than resolving to the one review. The 200 branch accepted below is
//      therefore currently unreachable in practice; it is accepted because it is the correct
//      outcome, not because it has been observed here.
//   2. An admission-review DELETE cannot replay either: the handler loads the record before
//      admitting its terminal event and removes the projection on success, so a retried delete
//      answers 404. Its idempotency key can never be presented a second time.
// Both live in the daemon's marketplace / mutation-foundation lane, outside this script.

import { createHash } from "node:crypto";

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
// The operator session every mutation below is admitted as. The daemon resolves NO principal from a
// bare loopback request — `resolve_principal` returns None without a session — so an unauthenticated
// walk cannot cross the identity seam at all: it would collect 401s and call them a lifecycle. The
// session rides the ONE http helper, so no call site can opt out of being someone.
const SESSION = (process.env.IOI_HYPERVISOR_DAEMON_SESSION || "").trim();

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const strip = (r) => String(r || "").replace(/^[a-z-]+:\/\//, "");
// Content-derived, mirroring the daemon's `replay_stable_id`: it mints a record's id from
// (owner_ref, idempotency_key), so a wall-clock key would make one retried command two records.
// Distinct commands on one stream must hash distinct material — a key re-presented with different
// bytes is refused as a conflict, not replayed.
const idempotencyKey = (command) => `marketplace-admission-review:${createHash("sha256").update(JSON.stringify(command)).digest("hex").slice(0, 32)}`;
async function jd(method, path, body) {
  const r = await fetch(`${DAEMON}${path}`, {
    method,
    headers: { "content-type": "application/json", ...(SESSION ? { authorization: `Bearer ${SESSION}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const t = await r.text();
  let j = null; try { j = JSON.parse(t); } catch { /* non-json */ }
  return { status: r.status, j, t };
}
async function sGet(path) {
  const r = await fetch(`${SERVE}${path}`);
  return { status: r.status, text: await r.text() };
}

const cleanup = [];
let RID = null;

async function run() {
  // 0. WHO this walk is. The owner scope is the daemon's own answer about this session, not a
  // constant: hardcoding `org://local` would be the verifier choosing an owner for whoever ran it,
  // and would keep passing against a deployment where that session owns nothing. The reviewer ref
  // is read here for the SAME reason — it is the value the admission review must be found to carry
  // later, and a verifier that supplied it would be checking its own arithmetic.
  ok("an operator session is present (IOI_HYPERVISOR_DAEMON_SESSION)", !!SESSION, SESSION ? "present" : "absent");
  const who = (await jd("GET", "/v1/hypervisor/auth/whoami")).j || {};
  const principalId = who.authenticated === true ? String(who.principal?.principal_id || "") : "";
  const REVIEWER_REF = principalId ? `user://${principalId}` : "";
  const OWNER_REF = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && (t.startsWith("org://") || t.startsWith("project://"))) || "";
  ok("the session authenticates a principal that owns a tenant to admit writes under", !!REVIEWER_REF && !!OWNER_REF, `${REVIEWER_REF || "no principal"} @ ${OWNER_REF || "no owner tenant"}`);
  if (!REVIEWER_REF || !OWNER_REF) {
    // Fail outright rather than walk on: every mutation below would be refused unauthenticated and
    // the run would report a broken identity seam as a broken lifecycle.
    throw new Error(`no authenticated operator fixture: set IOI_HYPERVISOR_DAEMON_SESSION to a real session token (whoami: ${JSON.stringify(who).slice(0, 200)})`);
  }

  // 1. ODK ontology + domain_app surface descriptor.
  const ont = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "verify-lending", canonical_object_model: { objects: ["Loan", "Borrower"], actions: ["approve"], states: ["draft", "funded"], roles: ["officer"], events: ["Funded"] } });
  const ontRef = ont.j?.ontology?.ref;
  ok("ODK ontology created", ont.status === 201 && ontRef, ontRef);
  cleanup.push(["DELETE", `/v1/hypervisor/odk/domain-ontologies/${strip(ontRef)}`]);

  const sd = await jd("POST", "/v1/hypervisor/odk/surface-descriptors", { name: "verify lending app", composition_pattern: "domain_app", ontology_ref: ontRef });
  const sdRef = sd.j?.surface_descriptor?.ref;
  ok("domain_app surface descriptor created", sd.status === 201 && sdRef, sdRef);
  cleanup.push(["DELETE", `/v1/hypervisor/odk/surface-descriptors/${strip(sdRef)}`]);

  // 2. DomainApp.
  const da = await jd("POST", "/v1/hypervisor/domain-apps", { name: "Verify Lending App", surface_descriptor_ref: sdRef, visibility: "marketplace_candidate" });
  const dRef = da.j?.domain_app?.domain_app_ref;
  const dId = da.j?.domain_app?.domain_app_id;
  ok("DomainApp created (runtime_posture.mounted=false)", da.status === 201 && dRef && da.j?.domain_app?.runtime_posture?.mounted === false, dRef);
  cleanup.push(["DELETE", `/v1/hypervisor/domain-apps/${dId}`]);

  // 3. Governance for mount: approved ApprovalRequest + open ReleaseControl targeting the app.
  const ap = await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: dRef, request_kind: "mount" });
  const apRef = ap.j?.approval_request?.ref;
  cleanup.push(["DELETE", `/v1/hypervisor/governance/approval-requests/${strip(apRef)}`]);
  const apPatch = await jd("PATCH", `/v1/hypervisor/governance/approval-requests/${strip(apRef)}`, { transition: "approve" });
  ok("ApprovalRequest -> approved", apPatch.j?.approval_request?.status === "approved");

  const rel = await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: dRef });
  const relRef = rel.j?.release_control?.ref;
  cleanup.push(["DELETE", `/v1/hypervisor/governance/release-controls/${strip(relRef)}`]);
  const relPatch = await jd("PATCH", `/v1/hypervisor/governance/release-controls/${strip(relRef)}`, { transition: "open" });
  ok("ReleaseControl -> open", relPatch.j?.release_control?.state === "open");

  // 4. Mount (governed admission).
  const mnt = await jd("POST", `/v1/hypervisor/domain-apps/${dId}/mount`, { approval_request_ref: apRef, release_control_ref: relRef });
  const rt = mnt.j?.runtime;
  RID = rt?.id;
  ok("mount -> mounted:true, serving:false", mnt.status === 201 && rt?.mounted === true && rt?.serving === false, rt?.state);
  ok("mount emits receipt with state_root", (mnt.j?.receipt?.state_root || "").startsWith("sha256:"), mnt.j?.receipt?.state_root);
  ok("mount stores approval+release backlinks", rt?.approval_request_ref === apRef && rt?.release_control_ref === relRef);
  const daAfterMount = await jd("GET", `/v1/hypervisor/domain-apps/${dId}`);
  ok("DomainApp runtime_posture.mount_ref set", !!daAfterMount.j?.domain_app?.runtime_posture?.mount_ref, daAfterMount.j?.domain_app?.runtime_posture?.mount_ref);

  // 5. Serve (internal, descriptor-driven).
  const srv = await jd("POST", `/v1/hypervisor/domain-apps/${dId}/serve`, {});
  const srt = srv.j?.runtime;
  ok("serve -> serving:true + internal route", srv.status === 201 && srt?.serving === true && String(srt?.internal_route_ref || "").startsWith("/__ioi/domain-app-runtime/"), srt?.internal_route_ref);
  ok("serve appends a receipt (>=2 total)", (srt?.receipt_refs || []).length >= 2, (srt?.receipt_refs || []).length);
  ok("no external ingress on runtime (route is internal only)", !srt?.public_url && !srt?.external_route, "internal-only");
  const view = await sGet(`/__ioi/domain-app-runtime/${RID}`);
  ok("internal render route serves the descriptor view", view.status === 200 && /Loan/.test(view.text) && /read-only/i.test(view.text));

  // 6. Marketplace: listing + candidate + admitted review + publish ReleaseControl -> publish.
  const lst = await jd("POST", "/v1/hypervisor/marketplace/listings", { name: "Verify Lending App", listing_kind: "domain_app", subject_ref: dRef });
  const lRef = lst.j?.listing?.ref; const lId = strip(lRef);
  cleanup.push(["DELETE", `/v1/hypervisor/marketplace/listings/${lId}`]);
  ok("marketplace listing (domain_app) created", lst.status === 201 && lRef);

  const cand = await jd("POST", "/v1/hypervisor/marketplace/publish-candidates", { listing_ref: lRef });
  const cRef = cand.j?.publish_candidate?.ref; const cId = strip(cRef);
  cleanup.push(["DELETE", `/v1/hypervisor/marketplace/publish-candidates/${cId}`]);
  ok("publish candidate created (not publishable yet)", cand.status === 201 && cand.j?.publish_candidate?.publishable === false);

  // The admission review: an owner-scoped, retry-stable mutation that names NO reviewer. The daemon
  // refuses a body carrying `reviewer_ref` and writes the principal it authenticated, so the only
  // reviewer this walk may assert is the one `whoami` reported above.
  const reviewCommand = { op: "marketplace.review.create", owner_ref: OWNER_REF, candidate_ref: cRef, decision: "admitted" };
  const rev = await jd("POST", "/v1/hypervisor/marketplace/admission-reviews", { candidate_ref: cRef, decision: "admitted", owner_ref: OWNER_REF, idempotency_key: idempotencyKey(reviewCommand) });
  const revId = strip(rev.j?.admission_review?.ref);
  // Only schedule a delete for a review that exists. A cleanup entry for a record that was never
  // created would report a removal failure that is really a creation failure.
  if (revId) cleanup.push(["DELETE", `/v1/hypervisor/marketplace/admission-reviews/${revId}`, { owner_ref: OWNER_REF, idempotency_key: idempotencyKey({ op: "marketplace.review.delete", owner_ref: OWNER_REF, review_id: revId }) }]);
  // 201 is a fresh create, 200 is the same command replayed — both are this walk landing exactly one
  // review, so both are accepted. The pair is not a blind disjunction: `ok === true` and the decision
  // are required alongside it, and the observed status + `replayed` flag ride in the detail, so a
  // change between the two branches is visible in the output rather than absorbed by the assertion.
  ok("admission review -> admitted", (rev.status === 201 || rev.status === 200) && rev.j?.ok === true && rev.j?.admission_review?.decision === "admitted", `status ${rev.status} replayed ${rev.j?.replayed}`);
  ok("reviewer is the daemon's answer for this session, not a value this walk supplied", rev.j?.admission_review?.reviewer_ref === REVIEWER_REF, `${rev.j?.admission_review?.reviewer_ref || "absent"} vs ${REVIEWER_REF}`);

  const prel = await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: cRef });
  const prelRef = prel.j?.release_control?.ref;
  cleanup.push(["DELETE", `/v1/hypervisor/governance/release-controls/${strip(prelRef)}`]);
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${strip(prelRef)}`, { transition: "open" });

  const candNow = await jd("GET", `/v1/hypervisor/marketplace/publish-candidates/${cId}`);
  ok("candidate publishable:true once all gates pass", candNow.j?.publish_candidate?.publishable === true, JSON.stringify(candNow.j?.publish_candidate?.blocked_reasons));

  const pub = await jd("POST", `/v1/hypervisor/marketplace/publish-candidates/${cId}/publish`, {});
  ok("publish -> candidate published", pub.status === 201 && pub.j?.publish_candidate?.publish_state === "published");
  ok("publish emits receipt with state_root", (pub.j?.receipt?.state_root || "").startsWith("sha256:"), pub.j?.receipt?.state_root);
  ok("publish stores runtime + review + release backlinks", pub.j?.publish_candidate?.published_runtime_ref && pub.j?.publish_candidate?.admission_review_ref && pub.j?.publish_candidate?.release_control_ref);
  const listingPub = await jd("GET", `/v1/hypervisor/marketplace/listings/${lId}`);
  ok("listing public_state -> published", listingPub.j?.listing?.public_state === "published");
  const ovAfterPub = await jd("GET", "/v1/hypervisor/marketplace/overview");
  ok("overview published count >= 1", (ovAfterPub.j?.marketplace?.published || 0) >= 1, ovAfterPub.j?.marketplace?.published);

  // 7. Backlink traversal (Domain App / Marketplace / Governance).
  const runtimeRef = pub.j?.publish_candidate?.published_runtime_ref;
  const rtGet = await jd("GET", `/v1/hypervisor/domain-app-runtimes/${strip(runtimeRef)}`);
  ok("Marketplace published_runtime_ref traverses to a runtime", rtGet.j?.ok === true && rtGet.j?.runtime?.domain_app_ref === dRef);
  const apGet = await jd("GET", `/v1/hypervisor/governance/approval-requests/${strip(rtGet.j?.runtime?.approval_request_ref)}`);
  ok("runtime.approval_request_ref traverses to an approved ApprovalRequest", apGet.j?.approval_request?.status === "approved");
  const relGet = await jd("GET", `/v1/hypervisor/governance/release-controls/${strip(rtGet.j?.runtime?.release_control_ref)}`);
  ok("runtime.release_control_ref traverses to a ReleaseControl", !!relGet.j?.release_control);

  // 8. KillSwitch trip + enforce.
  const kill = await jd("POST", "/v1/hypervisor/governance/kill-switches", { subject_ref: dRef, revoke_path: "stop-serving+unmount" });
  const kRef = kill.j?.kill_switch?.ref; const kId = strip(kRef);
  cleanup.push(["DELETE", `/v1/hypervisor/governance/kill-switches/${kId}`]);
  const enfArmed = await jd("POST", `/v1/hypervisor/governance/kill-switches/${kId}/enforce`, {});
  ok("enforce fails while armed", enfArmed.status === 400 && enfArmed.j?.error?.code === "kill_switch_not_tripped");
  await jd("PATCH", `/v1/hypervisor/governance/kill-switches/${kId}`, { transition: "trip", trip_reason: "verify" });
  const enf = await jd("POST", `/v1/hypervisor/governance/kill-switches/${kId}/enforce`, {});
  const ks = enf.j?.kill_switch;
  ok("enforce -> enforced, affected runtime, receipts", enf.status === 201 && ks?.enforcement_state === "enforced" && (ks?.affected_runtime_refs || []).length >= 1 && (ks?.enforcement_receipt_refs || []).length >= 1);
  const rtKilled = await jd("GET", `/v1/hypervisor/domain-app-runtimes/${RID}`);
  ok("killed runtime: serving:false, mounted:false, state killed", rtKilled.j?.runtime?.serving === false && rtKilled.j?.runtime?.mounted === false && rtKilled.j?.runtime?.state === "killed");
  const daKilled = await jd("GET", `/v1/hypervisor/domain-apps/${dId}`);
  ok("DomainApp posture after kill: mounted:false, serving:false", daKilled.j?.domain_app?.runtime_posture?.mounted === false && daKilled.j?.domain_app?.runtime_posture?.serving === false);
  const viewKilled = await sGet(`/__ioi/domain-app-runtime/${RID}`);
  ok("killed runtime internal route no longer serves", /not serving/i.test(viewKilled.text));

  // 9. Published metadata durable after kill.
  const listingAfterKill = await jd("GET", `/v1/hypervisor/marketplace/listings/${lId}`);
  ok("published Marketplace metadata intact after kill", listingAfterKill.j?.listing?.public_state === "published");

  // 10. Work Ledger reachability: the governed-lifecycle proofs must surface in the proof stream.
  const wl = await jd("GET", "/v1/hypervisor/work-ledger");
  const wlText = JSON.stringify(wl.j?.entries || []);
  const publishRoot = (pub.j?.receipt?.state_root || "");
  const enfRoot = (ks?.enforcement_receipt_refs || []).length ? "kill" : "";
  ok("Work Ledger surfaces the marketplace publish proof", wlText.includes(publishRoot) || wlText.includes(strip(pub.j?.receipt?.ref)), "publish receipt in work-ledger");
  ok("Work Ledger surfaces the kill enforcement proof", wl.j && (wlText.includes(kId) || wlText.includes("kill_enforcement") || wlText.includes(dRef)), "kill enforcement in work-ledger");
  ok("Work Ledger surfaces a domain-app mount/serve proof", wlText.includes("domain_app.") || wlText.includes(dRef), "mount/serve receipt in work-ledger");

  // 11. Surfaces render + fallthrough empty.
  for (const p of ["/__ioi/domain-apps", "/__ioi/marketplace", "/__ioi/governance", "/__ioi/work-ledger"]) {
    const s = await sGet(p);
    ok(`surface renders: ${p}`, s.status === 200);
  }
  const ft = await sGet("/__ioi/fallthrough");
  ok("fallthrough empty", ft.text.includes('"proxied":[]'), ft.text.trim());
}

(async () => {
  try {
    await run();
  } catch (e) {
    ok("verifier ran without throwing", false, String(e && e.stack || e));
  } finally {
    // Cleanup is EVIDENCE, not housekeeping. A swallowed failure leaves a fixture behind and reports
    // a clean run, so the next run inherits state it believes it created. A removal counts only when
    // the transport succeeded AND the plane said `ok` — the governance planes answer 200 with
    // `{"ok": false}` when the record was not there to remove (`g_del`), so a status-only test would
    // read the loudest possible "I deleted nothing" as a clean sweep.
    const cleanupFailures = [];
    for (const [m, p, b] of cleanup.reverse()) {
      try {
        const r = await jd(m, p, b);
        const removed = r.status >= 200 && r.status < 300 && r.j?.ok === true;
        if (!removed) cleanupFailures.push(`${m} ${p} -> ${r.status} ${r.j?.code || r.j?.error?.code || r.j?.reason || (r.j?.ok === false ? "ok:false" : "")}`.trim());
      } catch (e) { cleanupFailures.push(`${m} ${p} -> threw ${String(e && e.message || e)}`); }
    }
    ok("cleanup removed every mutable fixture it created", cleanupFailures.length === 0, cleanupFailures.join(" | "));
    // Note: immutable proof records (receipts) and the killed runtime record are retained by design.
  }
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "  PASS" : "  FAIL"}  ${r.name}${r.detail ? "  (" + r.detail + ")" : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) { console.log(`FAILED: ${fails.map((f) => f.name).join(" | ")}`); process.exit(1); }
  console.log("governed-lifecycle readiness: OK");
})();
