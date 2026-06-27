#!/usr/bin/env node
// Done-bar for org identity management (multi-user IdP, Phase 4) — invites, domain verification, and
// custom domain. Daemon-only (source-neutral): exercises /v1/hypervisor/org-invite,
// /domain-verifications, /custom-domain directly. Invite accept provisions a member + session (fails
// closed on a stale link); domain verification issues a DNS TXT challenge and checks it via DoH.
// All identity/policy — none of it grants machine authority. Usage: node scripts/verify-hypervisor-org-identity-functional.mjs [--json]
const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const EMAIL = "invited.member@papabearcarwash.com";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "org-identity", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const jd = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, body: t ? JSON.parse(t) : {} }; };
const roster = async () => (await jd("GET", "/v1/hypervisor/principals")).body.principals?.filter((p) => p.status === "active").map((p) => p.email) || [];

if (!JSON_OUT) console.log("Org identity e2e — invites / domain verification / custom domain (daemon-only)");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/editor-targets`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// self-heal residue
{ const d = (await jd("GET", "/v1/hypervisor/principals")).body; for (const p of (d.principals || [])) if (p.email === EMAIL) await jd("DELETE", `/v1/hypervisor/principals/${p.principal_id}?purge=true`); }

// 1) Invite link — get + rotate changes the id.
const id1 = (await jd("GET", "/v1/hypervisor/org-invite")).body?.invite?.invite_id;
ok(!!id1, "GET org-invite returns a standing invite id", id1?.slice(0, 14) + "…");
const id2 = (await jd("POST", "/v1/hypervisor/org-invite")).body?.invite?.invite_id;
ok(!!id2 && id2 !== id1, "rotating the invite issues a new id (old link dies)");

// 2) Accept stale → 403; current → provisions a member + session.
ok((await jd("POST", "/v1/hypervisor/org-invite/accept", { invite_id: id1, email: EMAIL, name: "Invited Member", password: "invited-pass-123" })).status === 403, "accepting a stale/invalid invite FAILS CLOSED (403)");
const accept = await jd("POST", "/v1/hypervisor/org-invite/accept", { invite_id: id2, email: EMAIL, name: "Invited Member", password: "invited-pass-123" });
const invitedId = accept.body?.principal?.principal_id;
ok(accept.status === 200 && typeof accept.body?.session_token === "string" && accept.body?.principal?.email === EMAIL, "accepting a valid invite provisions a member + session");
ok(accept.body?.principal?.source === "invite" && accept.body?.principal?.role === "member", "invited principal is a member, source=invite");

// 3) The invited member can log in + shows in the roster.
ok((await jd("POST", "/v1/hypervisor/auth/login", { email: EMAIL, password: "invited-pass-123" })).status === 200, "invited member can log in with the password they set");
ok((await roster()).includes(EMAIL), "invited member appears in the org roster");

// 4) Domain verification — TXT challenge → list pending → DoH verify → delete.
const dv = await jd("POST", "/v1/hypervisor/domain-verifications", { domain: "verify-test.papabearcarwash.com" });
const dvId = dv.body?.domain_verification?.id;
ok(dv.status === 200 && (dv.body?.domain_verification?.verification_token || "").includes("ioi-domain-verification="), "create issues a TXT challenge value");
ok(((await jd("GET", "/v1/hypervisor/domain-verifications")).body.domain_verifications || []).some((d) => d.id === dvId && d.verified === false), "domain verification lists as pending");
const verify = await jd("POST", `/v1/hypervisor/domain-verifications/${dvId}/verify`);
ok(verify.status === 200 && verify.body?.verified === false, "verify checks real DNS (TXT absent → not verified, honest)");
await jd("DELETE", `/v1/hypervisor/domain-verifications/${dvId}`);
ok(!((await jd("GET", "/v1/hypervisor/domain-verifications")).body.domain_verifications || []).some((d) => d.id === dvId), "delete removes the domain verification");

// 5) Custom domain — set / get / clear.
await jd("PUT", "/v1/hypervisor/custom-domain", { domain: "hv.papabearcarwash.com" });
ok((await jd("GET", "/v1/hypervisor/custom-domain")).body?.custom_domain === "hv.papabearcarwash.com", "custom domain set + reflected by GET");
await jd("PUT", "/v1/hypervisor/custom-domain", { domain: "" });
ok(!(await jd("GET", "/v1/hypervisor/custom-domain")).body?.custom_domain, "clearing the custom domain works");

// cleanup
if (invitedId) await jd("DELETE", `/v1/hypervisor/principals/${invitedId}?purge=true`);

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "org-identity", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} org-identity ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
