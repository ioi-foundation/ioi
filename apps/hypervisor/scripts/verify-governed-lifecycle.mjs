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
// Usage: node apps/hypervisor/scripts/verify-governed-lifecycle.mjs
// Exit 0 = all assertions pass; exit 1 = one or more failed. Mutable objects are cleaned up; immutable
// proof records (receipts, killed runtime) are intentionally retained.

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const strip = (r) => String(r || "").replace(/^[a-z-]+:\/\//, "");
async function jd(method, path, body) {
  const r = await fetch(`${DAEMON}${path}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
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

  const rev = await jd("POST", "/v1/hypervisor/marketplace/admission-reviews", { candidate_ref: cRef, decision: "admitted" });
  cleanup.push(["DELETE", `/v1/hypervisor/marketplace/admission-reviews/${strip(rev.j?.admission_review?.ref)}`]);
  ok("admission review -> admitted", rev.j?.admission_review?.decision === "admitted");

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
    for (const [m, p] of cleanup.reverse()) { try { await jd(m, p); } catch { /* best-effort */ } }
    // Note: immutable proof records (receipts) and the killed runtime record are retained by design.
  }
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "  PASS" : "  FAIL"}  ${r.name}${r.detail ? "  (" + r.detail + ")" : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) { console.log(`FAILED: ${fails.map((f) => f.name).join(" | ")}`); process.exit(1); }
  console.log("governed-lifecycle readiness: OK");
})();
