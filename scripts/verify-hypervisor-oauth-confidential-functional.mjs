#!/usr/bin/env node
// Done-bar for the CONFIDENTIAL BYOA OAuth client profile (#5) — the auth shape Slack needs (no DCR,
// requires a client_secret at the token exchange). The org provides client_id+client_secret; the
// daemon SEALS the secret and sends it at exchange/refresh; the agent only gets scoped leases.
// Verified against a mock OAuth+MCP server that REJECTS the exchange unless the right secret is sent.
import { mintApprovalGrant } from "./lib/mint-approval-grant.mjs";
import http from "node:http";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "oauth-confidential", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const j = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: await r.json().catch(() => ({})) }; };

if (!JSON_OUT) console.log("Confidential BYOA OAuth client e2e — the Slack-shaped profile");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

const CODE = "code-c", CONF_SECRET = "client-secret-DONOTLEAK", ACCESS = "conf-access-DONOTLEAK", REFRESH = "conf-refresh-DONOTLEAK";
const srv = http.createServer((req, res) => {
  let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
    const json = (o, code = 200) => { res.writeHead(code, { "content-type": "application/json", "mcp-session-id": "s1" }); res.end(JSON.stringify(o)); };
    if ((req.url || "").startsWith("/token")) {
      const p = new URLSearchParams(b);
      if (p.get("client_secret") !== CONF_SECRET) return json({ error: "invalid_client" }, 401); // confidential: secret REQUIRED
      if (p.get("grant_type") === "authorization_code") return json(p.get("code") === CODE && p.get("code_verifier") ? { access_token: ACCESS, refresh_token: REFRESH, token_type: "Bearer" } : { error: "invalid_grant" });
      if (p.get("grant_type") === "refresh_token") return json(p.get("refresh_token") === REFRESH ? { access_token: ACCESS, token_type: "Bearer" } : { error: "invalid_grant" });
      return json({ error: "unsupported_grant_type" });
    }
    const auth = req.headers["authorization"] || "";
    let msg = {}; try { msg = JSON.parse(b); } catch { /* */ }
    if (msg.method === "initialize") return json({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "m", version: "1" } } });
    if (msg.method === "notifications/initialized") { res.writeHead(202); return res.end(); }
    if (msg.method === "tools/list") return json({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "c_tool" }] } });
    if (msg.method === "tools/call") return json(auth === `Bearer ${ACCESS}` ? { jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: `ran ${msg.params?.name}` }] } } : { jsonrpc: "2.0", id: msg.id, error: { code: -32001, message: "bad token" } });
    json({ jsonrpc: "2.0", id: msg.id, result: {} });
  });
});
await new Promise((r) => srv.listen(0, "127.0.0.1", r));
const O = `http://127.0.0.1:${srv.address().port}`;

// register a CONFIDENTIAL BYOA OAuth client (client_id + client_secret) — the daemon seals the secret
const reg = await j("POST", "/v1/hypervisor/connectors", { service: "conf-mcp", kind: "mcp", name: "Confidential MCP", base_url: `${O}/mcp`, auth_profile: { type: "oauth_authcode_pkce", authorization_endpoint: `${O}/authorize`, token_endpoint: `${O}/token`, client_id: "conf-client", client_secret: CONF_SECRET, scopes: ["mcp"] } });
const cid = reg.body?.connector?.connector_id;
ok(!!cid, "register a confidential BYOA OAuth client");
const listed = JSON.stringify((await j("GET", "/v1/hypervisor/connectors")).body?.connectors?.find((c) => c.connector_id === cid) || {});
ok(!listed.includes(CONF_SECRET) && /sealed_client_secret/.test(listed), "client_secret is SEALED on the connector (no plaintext in listings)");

// authorize + callback — the daemon must send the sealed secret or the mock rejects (invalid_client)
const start = await j("POST", `/v1/hypervisor/connectors/${cid}/oauth/start`, {});
const cb = await j("POST", `/v1/hypervisor/connectors/oauth/callback`, { state: start.body.state, code: CODE });
ok(cb.status === 200 && cb.body?.connected === true, "confidential code-exchange succeeds (daemon sent the secret)", JSON.stringify(cb.body).slice(0, 80));

// leased tools/call → refresh mint also sends the secret → MCP tool runs
const ch = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "c_tool", request: {} });
const grant = mintApprovalGrant({ policyHash: ch.body.approval.policy_hash, requestHash: ch.body.approval.request_hash });
const inv = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "c_tool", request: {}, wallet_approval_grant: grant });
ok(inv.status === 200 && JSON.stringify(inv.body.response).includes("ran c_tool"), "leased tools/call runs (refresh mint also sent the secret)", `status ${inv.status}`);
ok(![CONF_SECRET, ACCESS, REFRESH].some((s) => JSON.stringify(inv.body).includes(s)), "no secret / token leaks in the result");

await j("DELETE", `/v1/hypervisor/connectors/${cid}`);
srv.close();
const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "oauth-confidential", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
