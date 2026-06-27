#!/usr/bin/env node
// Done-bar for the Team Identity & Access surfaces (Bucket B — deferred-as-epic). SSO / SCIM /
// custom-domain / domain-verification / org-invite presuppose a multi-user federated-login layer
// the single-operator daemon does not run yet. Rather than leave the mock's fabricated rows
// (a Google SSO config, an invite id) — which read as "configured" when nothing is — the adapter
// OWNS these with an honest empty local posture. This done-bar asserts the honest posture (owned,
// not mock). Usage: node scripts/verify-hypervisor-team-identity-functional.mjs [--json]
const JSON_OUT = process.argv.includes("--json");
const SERVE = process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173";
const ORG = "00000000-0000-4000-8000-0000000000a1";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "team-identity", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const ja = async (rpc, b) => { const r = await fetch(`${SERVE}/api/gitpod.v1.OrganizationService/${rpc}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b || {}) }); const t = await r.text(); return { status: r.status, raw: t, body: t ? JSON.parse(t) : {} }; };

if (!JSON_OUT) console.log("Team identity e2e — honest empty local posture (owned, not mock)");
try { const r = await fetch(`${SERVE}/ai`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("serve (:4173) not running"); }

// No fabricated SSO config (the mock seeded a Google IdP) — honest "none configured".
const sso = await ja("ListSSOConfigurations", { organizationId: ORG });
ok(Array.isArray(sso.body.ssoConfigurations) && sso.body.ssoConfigurations.length === 0, "ListSSOConfigurations: no fabricated IdP (honest empty)", `${sso.body.ssoConfigurations?.length} configs`);
ok(!sso.raw.includes("accounts.google.com"), "the mock's seeded Google SSO config is gone");

// SCIM: empty (no IdP provisioning configured).
const scim = await ja("ListSCIMConfigurations", { organizationId: ORG });
ok(!(scim.body.scimConfigurations && scim.body.scimConfigurations.length), "ListSCIMConfigurations: none configured");

// Custom domain: none.
const cd = await ja("GetCustomDomain", { organizationId: ORG });
ok(!cd.body.customDomain && !cd.body.domain, "GetCustomDomain: no custom domain (self-hosted)");

// Domain verifications: none.
const dv = await ja("ListDomainVerifications", { organizationId: ORG });
ok(!(dv.body.domainVerifications && dv.body.domainVerifications.length), "ListDomainVerifications: none");

// Org invite: no standing invite (the mock fabricated an inviteId).
const inv = await ja("GetOrganizationInvite", { organizationId: ORG });
ok(!inv.body.invite, "GetOrganizationInvite: no standing invite (single operator)");
ok(!inv.raw.includes("inviteId"), "the mock's fabricated invite id is gone");

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "team-identity", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} team-identity ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
