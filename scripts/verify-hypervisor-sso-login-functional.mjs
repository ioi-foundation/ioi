#!/usr/bin/env node
// Done-bar for SSO/OIDC login (multi-user IdP, Phase 2 + hardening #2). Drives the FULL Authorization
// Code + PKCE login against a local MOCK OIDC IdP that issues REAL RS256-signed id_tokens and serves
// a JWKS. The daemon cryptographically verifies the id_token (RS256 vs JWKS, iss/aud/exp + nonce)
// before provisioning. Negative tests prove a token signed by an UNKNOWN key and a token with a
// WRONG nonce are both rejected. Usage: node scripts/verify-hypervisor-sso-login-functional.mjs [--json]
import http from "node:http";
import crypto from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || "/home/heathledger/.ioi/hypervisor/data";
const TEST_EMAIL = "ssouser@papabearcarwash.com";
const CLIENT_ID = "ioi-sso-client";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "sso-login", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const jd = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, raw: t, body: t ? JSON.parse(t) : {} }; };
const b64url = (x) => Buffer.from(x).toString("base64url");

if (!JSON_OUT) console.log("SSO/OIDC login e2e — RS256 id_token verification (JWKS) + nonce + PKCE");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/editor-targets`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }
const purgeEmail = async (email) => { const r = await jd("GET", "/v1/hypervisor/principals"); for (const p of (r.body.principals || [])) if (p.email === email) await jd("DELETE", `/v1/hypervisor/principals/${p.principal_id}?purge=true`); };
await purgeEmail(TEST_EMAIL);

// --- Mock OIDC IdP: real RS256 signing + JWKS ---
const kp = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const stranger = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }); // an UNKNOWN key (not in JWKS)
const jwk = { ...kp.publicKey.export({ format: "jwk" }), kid: "test-key", alg: "RS256", use: "sig" };
const codes = new Map(); // code → { nonce }
let issuedEmail = TEST_EMAIL;
let signWith = "good"; // good | wrongkey | wrongnonce
const signJwt = (claims, key) => { const h = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "test-key" })); const p = b64url(JSON.stringify(claims)); const s = crypto.sign("RSA-SHA256", Buffer.from(`${h}.${p}`), key).toString("base64url"); return `${h}.${p}.${s}`; };
let issuer = "";
const idp = http.createServer((req, res) => {
  const u = new URL(req.url, issuer);
  res.setHeader("content-type", "application/json");
  if (u.pathname === "/.well-known/openid-configuration") {
    res.end(JSON.stringify({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, userinfo_endpoint: `${issuer}/userinfo`, jwks_uri: `${issuer}/jwks` }));
  } else if (u.pathname === "/jwks") {
    res.end(JSON.stringify({ keys: [jwk] }));
  } else if (u.pathname === "/authorize") {
    const code = "code_" + crypto.randomBytes(8).toString("hex");
    codes.set(code, { nonce: u.searchParams.get("nonce") || "" });
    res.end(JSON.stringify({ code, state: u.searchParams.get("state") || "" }));
  } else if (u.pathname === "/token") {
    let bodyStr = ""; req.on("data", (c) => (bodyStr += c)); req.on("end", () => {
      const form = new URLSearchParams(bodyStr);
      const rec = codes.get(form.get("code")) || { nonce: "" };
      const now = Math.floor(Date.now() / 1000);
      const claims = { iss: issuer, aud: form.get("client_id") || CLIENT_ID, sub: "mock-sub-123", iat: now, exp: now + 3600, email: issuedEmail, name: "SSO Test User", nonce: signWith === "wrongnonce" ? "tampered-nonce" : rec.nonce };
      const idToken = signJwt(claims, signWith === "wrongkey" ? stranger.privateKey : kp.privateKey);
      res.end(JSON.stringify({ access_token: "mock-access-token", token_type: "Bearer", expires_in: 3600, id_token: idToken }));
    });
  } else { res.writeHead(404); res.end("{}"); }
});
await new Promise((r) => idp.listen(0, "127.0.0.1", r));
issuer = `http://127.0.0.1:${idp.address().port}`;
const REDIRECT = "http://127.0.0.1:4173/__ioi/login/sso/callback";

// helper: daemon start → mock /authorize → daemon callback
const runLogin = async (ssoId) => {
  const start = await jd("POST", "/v1/hypervisor/auth/oidc/start", { config_id: ssoId, redirect_uri: REDIRECT });
  const au = new URL(start.body.authorize_url);
  const authz = await (await fetch(`${issuer}/authorize?${au.searchParams.toString()}`)).json();
  return { start, cb: await jd("POST", "/v1/hypervisor/auth/oidc/callback", { state: start.body.state, code: authz.code }) };
};

// 1) Register a BYO OIDC connection (emailDomain-gated) — client_secret sealed.
const reg = await jd("POST", "/v1/hypervisor/sso-configurations", { issuer_url: issuer, client_id: CLIENT_ID, client_secret: "SSO-CLIENT-SECRET-DONOTLEAK", email_domain: "papabearcarwash.com", display_name: "Mock IdP" });
const ssoId = reg.body?.sso_configuration?.sso_id;
ok(reg.status === 200 && !!ssoId && reg.body.sso_configuration.client_secret_set === true, "register SSO connection (secret sealed)", ssoId);
ok(!reg.raw.includes("SSO-CLIENT-SECRET-DONOTLEAK"), "register response never returns the client secret");
if (existsSync(DATA_DIR)) { const f = join(DATA_DIR, "sso-configurations", `${ssoId}.json`); ok(existsSync(f) && !readFileSync(f, "utf8").includes("SSO-CLIENT-SECRET-DONOTLEAK"), "on-disk SSO config has NO plaintext secret"); } else ok(true, "on-disk secret check skipped");

// 2) start builds a PKCE + nonce authorize URL.
const s0 = await jd("POST", "/v1/hypervisor/auth/oidc/start", { config_id: ssoId, redirect_uri: REDIRECT });
ok(s0.body.authorize_url?.includes("code_challenge=") && s0.body.authorize_url.includes("nonce=") && s0.body.authorize_url.includes("scope=openid"), "start builds a PKCE + nonce authorize URL");

// 3) Positive: verified id_token → provision + session.
signWith = "good";
const good = await runLogin(ssoId);
ok(good.cb.status === 200 && good.cb.body?.principal?.email === TEST_EMAIL, "verified id_token → provisions the user + session", good.cb.body?.principal?.email);
const provisionedId = good.cb.body?.principal?.principal_id;
ok((good.cb.body?.principal?.source || "").startsWith("sso:"), "provisioned principal is SSO-sourced");

// 4) HARDENING: id_token signed by an UNKNOWN key (not in JWKS) → rejected (401).
signWith = "wrongkey";
const badKey = await runLogin(ssoId);
ok(badKey.cb.status === 401, "id_token signed by an unknown key → REJECTED (401)", `status ${badKey.cb.status}`);

// 5) HARDENING: id_token with a WRONG nonce (replay) → rejected (401).
signWith = "wrongnonce";
const badNonce = await runLogin(ssoId);
ok(badNonce.cb.status === 401, "id_token with a mismatched nonce → REJECTED (401)", `status ${badNonce.cb.status}`);
signWith = "good";

// 6) Match-existing — a second valid login reuses the same principal.
const again = await runLogin(ssoId);
ok(again.cb.body?.principal?.principal_id === provisionedId, "re-login matches the existing principal (no duplicate)");

// 7) emailDomain gate — out-of-domain identity rejected (403).
issuedEmail = "stranger@evil.com";
const outDomain = await runLogin(ssoId);
ok(outDomain.cb.status === 403, "emailDomain gate rejects an out-of-domain user (403)");
issuedEmail = TEST_EMAIL;

// 8) adapter projects the SSO connection onto the native surface.
const list = await jd("GET", "/v1/hypervisor/sso-configurations");
ok((list.body.sso_configurations || []).some((c) => c.sso_id === ssoId), "daemon lists the SSO connection");

// cleanup
await jd("DELETE", `/v1/hypervisor/sso-configurations/${ssoId}`);
if (provisionedId) await jd("DELETE", `/v1/hypervisor/principals/${provisionedId}?purge=true`);
idp.close();

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "sso-login", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} sso-login ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
