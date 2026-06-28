#!/usr/bin/env node
// Done-bar for the OAuth-native MCP Connect (master-guide #5 "make it real", P2b Phase A). Connect =
// "authorize this integration" (OAuth Authorization Code + PKCE, public client), NOT token paste.
// The daemon exchanges the code for tokens, seals the refresh token, and from then on mints scoped
// access per use — the agent only ever gets capability leases. Verified against a mock OAuth+MCP
// server (no browser: we skip straight to the callback with a code the mock accepts).
//   register mcp integration w/ oauth auth_profile → oauth/start (authorize URL w/ PKCE) →
//   oauth/callback (code→tokens, seal refresh) → tools/call leased: daemon mints access from the
//   refresh and calls the MCP server with it (redacted). Usage: node scripts/verify-...mjs [--json]
import { mintApprovalGrant } from "./lib/mint-approval-grant.mjs";
import http from "node:http";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "oauth-connect", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const j = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: await r.json().catch(() => ({})) }; };

if (!JSON_OUT) console.log("OAuth-native MCP Connect e2e — authorize, not paste");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// mock provider: /token (authorization_code → access+refresh; refresh_token → access) + /mcp (JSON-RPC)
const CODE = "auth-code-XYZ", REFRESH = "refresh-DONOTLEAK-r1", ACCESS1 = "access1-DONOTLEAK", ACCESS2 = "access2-DONOTLEAK-fromrefresh";
const srv = http.createServer((req, res) => {
  let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
    const json = (o) => { res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "s1" }); res.end(JSON.stringify(o)); };
    if ((req.url || "").startsWith("/token")) {
      const p = new URLSearchParams(b);
      if (p.get("grant_type") === "authorization_code") return json(p.get("code") === CODE && p.get("code_verifier") ? { access_token: ACCESS1, refresh_token: REFRESH, token_type: "Bearer", expires_in: 3600 } : { error: "invalid_grant" });
      if (p.get("grant_type") === "refresh_token") return json(p.get("refresh_token") === REFRESH ? { access_token: ACCESS2, token_type: "Bearer", expires_in: 3600 } : { error: "invalid_grant" });
      return json({ error: "unsupported_grant_type" });
    }
    const auth = req.headers["authorization"] || "";
    let msg = {}; try { msg = JSON.parse(b); } catch { /* */ }
    if (msg.method === "initialize") return json({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "m", version: "1" } } });
    if (msg.method === "notifications/initialized") { res.writeHead(202); return res.end(); }
    if (msg.method === "tools/list") return json({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "read_thing" }] } });
    if (msg.method === "tools/call") return json(auth === `Bearer ${ACCESS2}` ? { jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: `ran ${msg.params?.name} auth=${auth}` }] } } : { jsonrpc: "2.0", id: msg.id, error: { code: -32001, message: "bad token" } });
    json({ jsonrpc: "2.0", id: msg.id, result: {} });
  });
});
await new Promise((r) => srv.listen(0, "127.0.0.1", r));
const ORIGIN = `http://127.0.0.1:${srv.address().port}`;

// 1) register an MCP integration with an OAuth auth_profile (the org "Add MCP integration")
const reg = await j("POST", "/v1/hypervisor/connectors", { service: "mock-oauth-mcp", kind: "mcp", name: "Mock OAuth MCP", base_url: `${ORIGIN}/mcp`, auth_profile: { type: "oauth_authcode_pkce", authorization_endpoint: `${ORIGIN}/authorize`, token_endpoint: `${ORIGIN}/token`, client_id: "test-client", scopes: ["mcp.read"] } });
const cid = reg.body?.connector?.connector_id;
ok(!!cid && reg.body?.connector?.auth_profile?.type === "oauth_authcode_pkce", "register MCP integration with an OAuth auth_profile");

// 2) oauth/start → authorize URL with PKCE (the "authorize this integration" redirect)
const start = await j("POST", `/v1/hypervisor/connectors/${cid}/oauth/start`, { redirect_uri: "http://127.0.0.1:4173/__ioi/integrations/oauth/callback" });
const au = start.body?.authorize_url || "";
ok(start.status === 200 && au.startsWith(`${ORIGIN}/authorize`), "oauth/start returns the provider authorize URL", `status ${start.status}`);
ok(/response_type=code/.test(au) && /client_id=test-client/.test(au) && /code_challenge=/.test(au) && /code_challenge_method=S256/.test(au) && /state=/.test(au), "authorize URL carries PKCE (code_challenge S256) + client_id + state");
ok(!au.includes("code_verifier"), "the PKCE verifier is NOT in the authorize URL (kept sealed in the daemon)");

// 3) oauth/callback → exchange code for tokens, seal the refresh token
const cb = await j("POST", `/v1/hypervisor/connectors/oauth/callback`, { state: start.body.state, code: CODE });
ok(cb.status === 200 && cb.body?.connected === true && cb.body?.credential_kind === "oauth-refresh", "oauth/callback exchanges the code + seals an oauth-refresh credential", `kind ${cb.body?.credential_kind}`);
const bad = await j("POST", `/v1/hypervisor/connectors/oauth/callback`, { state: "nope", code: CODE });
ok(bad.status === 400, "callback with an unknown state is rejected (400)");

// 4) tools/call (leased) → daemon mints access from the sealed refresh + calls the MCP server with it
const ch = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "read_thing", request: {} });
ok(ch.status === 403, "tools/call without a grant FAILS CLOSED (403)", `status ${ch.status}`);
const grant = mintApprovalGrant({ policyHash: ch.body.approval.policy_hash, requestHash: ch.body.approval.request_hash });
const inv = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "read_thing", request: {}, wallet_approval_grant: grant });
ok(inv.status === 200 && inv.body?.receipt?.credential_source === "oauth-refresh", "authorized tools/call mints access from the sealed refresh (oauth-refresh)", inv.body?.receipt?.credential_source);
const text = JSON.stringify(inv.body?.response || {});
ok(text.includes("ran read_thing"), "the MCP tool actually ran via the OAuth-minted access token");
ok(text.includes("Bearer ***"), "the access token is redacted in the result");
ok(![REFRESH, ACCESS1, ACCESS2, CODE].some((s) => JSON.stringify(inv.body).includes(s)), "no code / access / refresh token leaks anywhere in the result");

await j("DELETE", `/v1/hypervisor/connectors/${cid}`);
srv.close();
const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "oauth-connect", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
