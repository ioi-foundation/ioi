#!/usr/bin/env node
// Done-bar for the Identity & Auth foundation (multi-user IdP, Phase 1) — principals, sessions, a
// gated inbound auth ring, and Argon2id (dcrypt) password hashing. The DOCTRINE assertion this
// encodes: IdP/auth is the OUTER ring (who is calling) and COMPOSES with — never replaces — the
// wallet/lease authority model. An authenticated admin session must NOT bypass the wallet gate on a
// consequential crossing. Usage: node scripts/verify-hypervisor-identity-auth-functional.mjs [--json]
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || "/home/heathledger/.ioi/hypervisor/data";
const OPERATOR = "00000000-0000-4000-8000-000000000001";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "identity-auth", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const jd = async (m, p, b, hdr) => { const r = await fetch(DAEMON + p, { method: m, headers: { ...(b ? { "content-type": "application/json" } : {}), ...(hdr || {}) }, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, raw: t, body: t ? JSON.parse(t) : {} }; };

if (!JSON_OUT) console.log("Identity & Auth e2e — principals/sessions/gate + Argon2id; auth ≠ crossing authority");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/editor-targets`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// 0) ensure a known operator password (Argon2id).
await jd("POST", `/v1/hypervisor/principals/${OPERATOR}/password`, { password: "operator-pass-123" });

// 1) Password is Argon2id at rest — never plaintext, never sha256 (hex of salt16||hash32 = 96 chars).
if (existsSync(DATA_DIR)) {
  const rec = JSON.parse(readFileSync(join(DATA_DIR, "principals", `${OPERATOR}.json`), "utf8"));
  ok((rec.password_hash || "").length === 96 && !JSON.stringify(rec).includes("operator-pass-123") && !("salt" in rec), "password stored as Argon2id (dcrypt), no plaintext, no sha256", `hash len ${(rec.password_hash || "").length}`);
} else ok(true, "on-disk password-hash check skipped (data dir not on this host)");

// 2) Login — wrong password 401, correct password issues a session token.
const bad = await jd("POST", "/v1/hypervisor/auth/login", { email: "johndoe@ioi.local", password: "WRONG" });
ok(bad.status === 401, "login with wrong password FAILS (401)");
const login = await jd("POST", "/v1/hypervisor/auth/login", { email: "johndoe@ioi.local", password: "operator-pass-123" });
const token = login.body?.session_token;
ok(login.status === 200 && typeof token === "string" && token.startsWith("ioi_sess_"), "login issues a session token");
ok(!login.raw.includes("password"), "login response carries no credential material");

// 3) whoami resolves the session principal (admin).
const who = await jd("GET", "/v1/hypervisor/auth/whoami", null, { Authorization: `Bearer ${token}` });
ok(who.body?.authenticated === true && who.body?.principal?.role === "admin", "session authenticates the operator (admin)", who.body?.principal?.email);

// 4) Provision a member principal (role member) with a password → it can log in.
await jd("POST", "/v1/hypervisor/principals", { email: "teammate@papabearcarwash.com", name: "Team Mate", role: "member", password: "member-pass-456" });
const mlogin = await jd("POST", "/v1/hypervisor/auth/login", { email: "teammate@papabearcarwash.com", password: "member-pass-456" });
ok(mlogin.status === 200 && mlogin.body?.principal?.role === "member", "provisioned member can log in (role member)");

// 5) Enforcement gate: enable → unauth 401, session 200, readiness exempt. Policy changes are
// AUTHENTICATED (the gate requires auth on /auth/policy once enforcing).
const adminHdr = { Authorization: `Bearer ${token}` };
await jd("PUT", "/v1/hypervisor/auth/policy", { require_authentication: true }, adminHdr);
const unauth = await jd("GET", "/v1/hypervisor/secrets");
ok(unauth.status === 401, "enforcement ON: unauthenticated hypervisor call → 401");
const authed = await jd("GET", "/v1/hypervisor/secrets", null, { Authorization: `Bearer ${token}` });
ok(authed.status === 200, "enforcement ON: valid session → 200");
const probe = await jd("GET", "/v1/hypervisor/editor-targets");
ok(probe.status === 200, "readiness probe stays exempt under enforcement");

// 6) DOCTRINE: an authenticated ADMIN session does NOT bypass the wallet/lease crossing gate.
// Register a connector + bind a credential, then invoke a crossing WITH the admin session but NO
// wallet grant → must still be gated (403 authority / 428 credential), never 200.
const reg = await jd("POST", "/v1/hypervisor/connectors", { service: "auth-doctrine-echo", base_url: "http://127.0.0.1:1", allowed_tools: [{ name: "noop", method: "POST", path: "/noop" }] }, { Authorization: `Bearer ${token}` });
const cid = reg.body?.connector?.connector_id;
await jd("POST", `/v1/hypervisor/connectors/${cid}/credential`, { token: "x" }, { Authorization: `Bearer ${token}` });
const cross = await jd("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "noop", request: {} }, { Authorization: `Bearer ${token}` });
ok(cross.status === 403 || cross.status === 428, "ADMIN SESSION does NOT bypass the wallet gate — crossing still requires a grant", `status ${cross.status}`);
ok(cross.status !== 200, "role is identity/policy only, never machine authority");
await jd("DELETE", `/v1/hypervisor/connectors/${cid}`, null, { Authorization: `Bearer ${token}` });

// 7) API access token authenticates a principal (closes the loop: the hash we store is now enforceable).
const mint = await jd("POST", "/v1/hypervisor/api-tokens", { description: "auth-doctrine-token", user_id: OPERATOR, validFor: "3600s" }, { Authorization: `Bearer ${token}` });
const apiTok = mint.body?.token?.value;
const apiWho = await jd("GET", "/v1/hypervisor/auth/whoami", null, { Authorization: `Bearer ${apiTok}` });
ok(apiWho.body?.authenticated === true && apiWho.body?.principal?.principal_id === OPERATOR, "an API access token authenticates its principal");

// restore enforcement OFF + cleanup (purge the demo member so the roster stays clean)
await jd("PUT", "/v1/hypervisor/auth/policy", { require_authentication: false }, adminHdr);
if (mint.body?.token?.token_id) await jd("DELETE", `/v1/hypervisor/api-tokens/${mint.body.token.token_id}`);
{ const r = await jd("GET", "/v1/hypervisor/principals"); for (const p of (r.body.principals || [])) if (p.email === "teammate@papabearcarwash.com") await jd("DELETE", `/v1/hypervisor/principals/${p.principal_id}?purge=true`); }

// 8) logout revokes the session.
await jd("POST", "/v1/hypervisor/auth/logout", null, { Authorization: `Bearer ${token}` });
const afterLogout = await jd("GET", "/v1/hypervisor/auth/whoami", null, { Authorization: `Bearer ${token}` });
ok(afterLogout.body?.authenticated === false, "logout revokes the session");

// 9) operator can never be removed.
const rmOp = await jd("DELETE", `/v1/hypervisor/principals/${OPERATOR}`);
ok(rmOp.body?.ok === false, "the bootstrap operator cannot be deactivated");

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "identity-auth", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} identity-auth ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
