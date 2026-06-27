#!/usr/bin/env node
// Done-bar for MCP OAuth auto-discovery + Dynamic Client Registration (master-guide #5, P2b Phase B).
// The no-BYOA path: register ONLY an MCP URL → the daemon probes (401 → protected-resource-metadata,
// RFC 9728), reads authorization-server metadata (RFC 8414), and dynamically registers a public PKCE
// client (RFC 7591) — no per-service OAuth app, no vendor secret. Then the Phase-A Connect proceeds.
// Verified against a mock that implements the whole MCP auth surface.
//   register (url only) → oauth/discover (auto AS + DCR) → oauth/start (authorize w/ discovered client)
//   → oauth/callback (seal refresh) → leased tools/call mints access and runs.
import { mintApprovalGrant } from "./lib/mint-approval-grant.mjs";
import http from "node:http";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "mcp-dcr", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const j = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: await r.json().catch(() => ({})) }; };

if (!JSON_OUT) console.log("MCP OAuth discovery + DCR e2e — register a URL, no per-service app");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

const CODE = "code-1", REFRESH = "refresh-DONOTLEAK", ACCESS1 = "access1-DONOTLEAK", ACCESS2 = "access2-DONOTLEAK";
let ORIGIN = "";
const srv = http.createServer((req, res) => {
  let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
    const json = (o, code = 200, headers = {}) => { res.writeHead(code, { "content-type": "application/json", "mcp-session-id": "s1", ...headers }); res.end(JSON.stringify(o)); };
    const u = req.url || "";
    if (u.startsWith("/.well-known/oauth-protected-resource")) return json({ resource: `${ORIGIN}/mcp`, authorization_servers: [ORIGIN], scopes_supported: ["mcp.read"] });
    if (u.startsWith("/.well-known/oauth-authorization-server")) return json({ issuer: ORIGIN, authorization_endpoint: `${ORIGIN}/authorize`, token_endpoint: `${ORIGIN}/token`, registration_endpoint: `${ORIGIN}/register`, scopes_supported: ["mcp.read"], code_challenge_methods_supported: ["S256"] });
    if (u.startsWith("/register")) return json({ client_id: "dcr-client-123", client_id_issued_at: 1, token_endpoint_auth_method: "none" });
    if (u.startsWith("/token")) {
      const p = new URLSearchParams(b);
      if (p.get("grant_type") === "authorization_code") return json(p.get("code") === CODE && p.get("code_verifier") ? { access_token: ACCESS1, refresh_token: REFRESH, token_type: "Bearer" } : { error: "invalid_grant" });
      if (p.get("grant_type") === "refresh_token") return json(p.get("refresh_token") === REFRESH ? { access_token: ACCESS2, token_type: "Bearer" } : { error: "invalid_grant" });
      return json({ error: "unsupported_grant_type" });
    }
    // /mcp — unauthenticated probe → 401 with the resource-metadata pointer; authed → JSON-RPC.
    const auth = req.headers["authorization"] || "";
    if (!auth) return json({ error: "unauthorized" }, 401, { "WWW-Authenticate": `Bearer resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource"` });
    let msg = {}; try { msg = JSON.parse(b); } catch { /* */ }
    if (msg.method === "initialize") return json({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "m", version: "1" } } });
    if (msg.method === "notifications/initialized") { res.writeHead(202); return res.end(); }
    if (msg.method === "tools/list") return json({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "do_thing" }] } });
    if (msg.method === "tools/call") return json(auth === `Bearer ${ACCESS2}` ? { jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: `ran ${msg.params?.name} auth=${auth}` }] } } : { jsonrpc: "2.0", id: msg.id, error: { code: -32001, message: "bad token" } });
    json({ jsonrpc: "2.0", id: msg.id, result: {} });
  });
});
await new Promise((r) => srv.listen(0, "127.0.0.1", r));
ORIGIN = `http://127.0.0.1:${srv.address().port}`;

// 1) register an MCP connector with ONLY a URL — no auth_profile
const reg = await j("POST", "/v1/hypervisor/connectors", { service: "dcr-mcp", kind: "mcp", name: "DCR MCP", base_url: `${ORIGIN}/mcp` });
const cid = reg.body?.connector?.connector_id;
ok(!!cid && (reg.body?.connector?.auth_profile == null || reg.body?.connector?.auth_profile === null), "register MCP connector with NO auth_profile (URL only)");

// 2) discover → auto AS metadata + Dynamic Client Registration
const disc = await j("POST", `/v1/hypervisor/connectors/${cid}/oauth/discover`, {});
const ap = disc.body?.auth_profile || {};
ok(disc.status === 200 && disc.body?.discovered === true, "oauth/discover succeeds", `status ${disc.status}`);
ok(ap.authorization_endpoint === `${ORIGIN}/authorize` && ap.token_endpoint === `${ORIGIN}/token`, "discovered authorization + token endpoints (RFC 9728→8414)");
ok(ap.client_id === "dcr-client-123", "dynamically registered a client (RFC 7591 DCR)", ap.client_id);

// 3) oauth/start uses the discovered profile (no per-service app was configured)
const start = await j("POST", `/v1/hypervisor/connectors/${cid}/oauth/start`, {});
ok(start.status === 200 && (start.body?.authorize_url || "").startsWith(`${ORIGIN}/authorize`) && /client_id=dcr-client-123/.test(start.body.authorize_url) && /code_challenge_method=S256/.test(start.body.authorize_url), "authorize URL uses the DCR client + PKCE");

// 4) callback seals the refresh
const cb = await j("POST", `/v1/hypervisor/connectors/oauth/callback`, { state: start.body.state, code: CODE });
ok(cb.status === 200 && cb.body?.connected === true, "oauth/callback seals tokens (connected)", `status ${cb.status}`);

// 5) leased tools/call mints access from the refresh and runs
const ch = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "do_thing", request: {} });
const grant = mintApprovalGrant({ policyHash: ch.body.approval.policy_hash, requestHash: ch.body.approval.request_hash });
const inv = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "do_thing", request: {}, wallet_approval_grant: grant });
ok(inv.status === 200 && JSON.stringify(inv.body?.response || {}).includes("ran do_thing"), "leased tools/call runs via the auto-provisioned OAuth", `status ${inv.status}`);
ok(![REFRESH, ACCESS1, ACCESS2, CODE].some((s) => JSON.stringify(inv.body).includes(s)), "no secret leaks in the result");

await j("DELETE", `/v1/hypervisor/connectors/${cid}`);
srv.close();
const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "mcp-dcr", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
