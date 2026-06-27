#!/usr/bin/env node
// Done-bar for org identity management (multi-user IdP, Phase 4) — invites, domain verification, and
// custom domain. Invite accept provisions a member principal + session (fails closed on a stale
// link); domain verification issues a DNS TXT challenge and checks it via DoH; custom domain is a
// stored vanity config. All identity/policy — none of it grants machine authority.
// Usage: node scripts/verify-hypervisor-org-identity-functional.mjs [--json]
const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const SERVE = process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173";
const EMAIL = "invited.member@papabearcarwash.com";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "org-identity", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const jd = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, body: t ? JSON.parse(t) : {} }; };
const ja = async (rpc, b) => { const r = await fetch(`${SERVE}/api/gitpod.v1.OrganizationService/${rpc}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b || {}) }); const t = await r.text(); return { status: r.status, body: t ? JSON.parse(t) : {} }; };

if (!JSON_OUT) console.log("Org identity e2e — invites / domain verification / custom domain");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/auth/whoami`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }
try { const r = await fetch(`${SERVE}/ai`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("serve (:4173) not running"); }

// 1) Invite link — get (adapter) + rotate (daemon) changes the id.
const inv1 = await ja("GetOrganizationInvite", {});
const id1 = inv1.body?.invite?.inviteId;
ok(!!id1, "GetOrganizationInvite returns a standing invite id", id1?.slice(0, 14) + "…");
const reset = await jd("POST", "/v1/hypervisor/org-invite");
const id2 = reset.body?.invite?.invite_id;
ok(!!id2 && id2 !== id1, "rotating the invite issues a new id (old link dies)");

// 2) Accept with a STALE id → 403; with the current id → provisions a member + session.
const stale = await jd("POST", "/v1/hypervisor/org-invite/accept", { invite_id: id1, email: EMAIL, name: "Invited Member", password: "invited-pass-123" });
ok(stale.status === 403, "accepting a stale/invalid invite FAILS CLOSED (403)");
const accept = await jd("POST", "/v1/hypervisor/org-invite/accept", { invite_id: id2, email: EMAIL, name: "Invited Member", password: "invited-pass-123" });
const invitedId = accept.body?.principal?.principal_id;
ok(accept.status === 200 && typeof accept.body?.session_token === "string" && accept.body?.principal?.email === EMAIL, "accepting a valid invite provisions a member + session");
ok(accept.body?.principal?.source === "invite" && accept.body?.principal?.role === "member", "invited principal is a member, source=invite");

// 3) The invited member can then log in with the password they set, and shows in the roster.
const login = await jd("POST", "/v1/hypervisor/auth/login", { email: EMAIL, password: "invited-pass-123" });
ok(login.status === 200, "invited member can log in with the password they set");
const members = await ja("ListMembers", {});
ok((members.body?.members || []).some((m) => m.email === EMAIL), "invited member appears in the org roster");

// 4) Domain verification — create issues a TXT challenge; list (pending); verify via DoH; delete.
const dv = await ja("CreateDomainVerification", { domain: "verify-test.papabearcarwash.com" });
const dvId = dv.body?.domainVerification?.id;
ok(dv.status === 200 && (dv.body?.domainVerification?.recordValue || "").includes("ioi-domain-verification="), "CreateDomainVerification issues a TXT challenge value");
const dvList = await ja("ListDomainVerifications", {});
ok((dvList.body?.domainVerifications || []).some((d) => d.id === dvId && d.verified === false), "domain verification lists as pending");
const verify = await ja("VerifyDomainVerification", { domainVerificationId: dvId });
ok(verify.status === 200 && verify.body?.verified === false, "verify checks real DNS (TXT absent → not verified, honest)");
await ja("DeleteDomainVerification", { domainVerificationId: dvId });
const dvList2 = await ja("ListDomainVerifications", {});
ok(!(dvList2.body?.domainVerifications || []).some((d) => d.id === dvId), "DeleteDomainVerification removes it");

// 5) Custom domain — set / get / clear.
await ja("SetCustomDomain", { domain: "hv.papabearcarwash.com" });
const cdGet = await ja("GetCustomDomain", {});
ok(cdGet.body?.customDomain === "hv.papabearcarwash.com", "custom domain set + reflected by GetCustomDomain");
await ja("DeleteCustomDomain", {});
const cdGet2 = await ja("GetCustomDomain", {});
ok(!cdGet2.body?.customDomain, "DeleteCustomDomain clears it");

// cleanup
if (invitedId) await jd("DELETE", `/v1/hypervisor/principals/${invitedId}`);

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "org-identity", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} org-identity ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
