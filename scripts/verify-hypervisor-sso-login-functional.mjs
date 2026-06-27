#!/usr/bin/env node
// Done-bar for SSO/OIDC login (multi-user IdP, Phase 2). Drives the FULL Authorization Code + PKCE
// login flow against a local MOCK OIDC IdP (deterministic, no external creds): register a BYO OIDC
// connection → start (PKCE authorize URL) → callback (exchange code → userinfo → provision principal
// → issue session). Verifies provision-on-login, match-existing, emailDomain auto-join gating, and
// that the IdP client_secret is sealed. Usage: node scripts/verify-hypervisor-sso-login-functional.mjs [--json]
import http from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const SERVE = process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173";
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || "/home/heathledger/.ioi/hypervisor/data";
const TEST_EMAIL = "ssouser@papabearcarwash.com";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "sso-login", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const jd = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, raw: t, body: t ? JSON.parse(t) : {} }; };
const ja = async (rpc, b) => { const r = await fetch(`${SERVE}/api/gitpod.v1.OrganizationService/${rpc}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b || {}) }); const t = await r.text(); return { status: r.status, body: t ? JSON.parse(t) : {} }; };

if (!JSON_OUT) console.log("SSO/OIDC login e2e — full Authorization Code + PKCE against a mock IdP");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/auth/whoami`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }
try { const r = await fetch(`${SERVE}/ai`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("serve (:4173) not running"); }

// Mock OIDC IdP: discovery + token + userinfo. /token mints an access token for any code; /userinfo
// returns the test identity for that access token.
let issuedEmail = TEST_EMAIL;
const idp = http.createServer((req, res) => {
  const url = (req.url || "").split("?")[0];
  res.setHeader("content-type", "application/json");
  const base = `http://127.0.0.1:${idp.address().port}`;
  if (url === "/.well-known/openid-configuration") {
    res.end(JSON.stringify({ issuer: base, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, userinfo_endpoint: `${base}/userinfo` }));
  } else if (url === "/token") {
    res.end(JSON.stringify({ access_token: "mock-access-token", token_type: "Bearer", expires_in: 3600, id_token: "mock.id.token" }));
  } else if (url === "/userinfo") {
    const auth = req.headers["authorization"] || "";
    if (auth !== "Bearer mock-access-token") { res.writeHead(401); res.end("{}"); return; }
    res.end(JSON.stringify({ sub: "mock-sub-123", email: issuedEmail, name: "SSO Test User" }));
  } else { res.writeHead(404); res.end("{}"); }
});
await new Promise((r) => idp.listen(0, "127.0.0.1", r));
const ISSUER = `http://127.0.0.1:${idp.address().port}`;
const REDIRECT = "http://127.0.0.1:4173/__ioi/login/sso/callback";

// 1) Register a BYO OIDC connection (emailDomain-gated) — client_secret sealed.
const reg = await jd("POST", "/v1/hypervisor/sso-configurations", { issuer_url: ISSUER, client_id: "ioi-sso-client", client_secret: "SSO-CLIENT-SECRET-DONOTLEAK", email_domain: "papabearcarwash.com", display_name: "Mock IdP" });
const ssoId = reg.body?.sso_configuration?.sso_id;
ok(reg.status === 200 && !!ssoId && reg.body.sso_configuration.client_secret_set === true, "register SSO connection (secret sealed)", ssoId);
ok(!reg.raw.includes("SSO-CLIENT-SECRET-DONOTLEAK"), "register response never returns the client secret");
if (existsSync(DATA_DIR)) {
  const f = join(DATA_DIR, "sso-configurations", `${ssoId}.json`);
  ok(existsSync(f) && !readFileSync(f, "utf8").includes("SSO-CLIENT-SECRET-DONOTLEAK"), "on-disk SSO config has NO plaintext secret");
} else ok(true, "on-disk secret check skipped");

// 2) Start login → PKCE authorize URL pointing at the IdP.
const start = await jd("POST", "/v1/hypervisor/auth/oidc/start", { config_id: ssoId, redirect_uri: REDIRECT });
const state = start.body?.state;
ok(start.status === 200 && start.body.authorize_url?.includes(`${ISSUER}/authorize`) && start.body.authorize_url.includes("code_challenge=") && start.body.authorize_url.includes("scope=openid"), "start builds a PKCE authorize URL (openid scope)");

// 3) Callback → exchange code → userinfo → PROVISION principal → issue session.
const cb = await jd("POST", "/v1/hypervisor/auth/oidc/callback", { state, code: "mock-auth-code" });
ok(cb.status === 200 && typeof cb.body.session_token === "string" && cb.body.principal?.email === TEST_EMAIL, "callback provisions the user + issues a session", cb.body.principal?.email);
ok((cb.body.principal?.source || "").startsWith("sso:"), "provisioned principal is marked SSO-sourced", cb.body.principal?.source);
const provisionedId = cb.body.principal?.principal_id;

// 4) whoami via the new session resolves the SSO user.
const who = await jd("GET", "/v1/hypervisor/auth/whoami");
const who2 = await fetch(`${DAEMON}/v1/hypervisor/auth/whoami`, { headers: { Authorization: `Bearer ${cb.body.session_token}` } }).then((r) => r.json());
ok(who2.authenticated === true && who2.principal?.email === TEST_EMAIL, "the SSO session authenticates the provisioned user");

// 5) Match-existing — a second login reuses the same principal (no duplicate).
const start2 = await jd("POST", "/v1/hypervisor/auth/oidc/start", { config_id: ssoId, redirect_uri: REDIRECT });
const cb2 = await jd("POST", "/v1/hypervisor/auth/oidc/callback", { state: start2.body.state, code: "mock-auth-code-2" });
ok(cb2.body.principal?.principal_id === provisionedId, "re-login matches the existing principal (no duplicate)");

// 6) emailDomain gate — an out-of-domain identity is rejected.
issuedEmail = "stranger@evil.com";
const start3 = await jd("POST", "/v1/hypervisor/auth/oidc/start", { config_id: ssoId, redirect_uri: REDIRECT });
const cb3 = await jd("POST", "/v1/hypervisor/auth/oidc/callback", { state: start3.body.state, code: "mock-auth-code-3" });
ok(cb3.status === 403, "emailDomain auto-join gate rejects an out-of-domain user (403)", `status ${cb3.status}`);
issuedEmail = TEST_EMAIL;

// 7) The adapter projects the SSO connection onto the native Login Configuration surface.
const list = await ja("ListSSOConfigurations", {});
ok((list.body.ssoConfigurations || []).some((c) => c.id === ssoId && c.providerType === "PROVIDER_TYPE_OIDC"), "adapter ListSSOConfigurations projects the connection");

// cleanup
await jd("DELETE", `/v1/hypervisor/sso-configurations/${ssoId}`);
if (provisionedId) await jd("DELETE", `/v1/hypervisor/principals/${provisionedId}`);
idp.close();

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "sso-login", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} sso-login ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
