#!/usr/bin/env node
// Done-bar for Phase D auth profiles (master-guide #5): OAuth Device Authorization Grant (RFC 8628,
// headless/no-redirect connect) + managed service account. Both seal into the same lease pipeline;
// agents still only ever get scoped capability leases. Verified against a mock provider.
//   device/start (user_code) → device/poll (pending → connected, seals oauth-refresh) → leased
//   tools/call mints access and runs. + service-account bind → invoke (credential_source label).
import { mintApprovalGrant } from "./lib/mint-approval-grant.mjs";
import http from "node:http";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "device-managed", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const j = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: await r.json().catch(() => ({})) }; };

if (!JSON_OUT) console.log("Phase D auth profiles e2e — device code + managed service account");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

const REFRESH = "dev-refresh-DONOTLEAK", ACCESS = "dev-access-DONOTLEAK";
let polls = 0;
const srv = http.createServer((req, res) => {
  let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
    const json = (o, code = 200) => { res.writeHead(code, { "content-type": "application/json", "mcp-session-id": "s1" }); res.end(JSON.stringify(o)); };
    const u = req.url || "";
    if (u.startsWith("/device")) return json({ device_code: "dc-1", user_code: "WXYZ-1234", verification_uri: "http://example/activate", interval: 1, expires_in: 600 });
    if (u.startsWith("/token")) {
      const p = new URLSearchParams(b);
      if (p.get("grant_type") === "urn:ietf:params:oauth:grant-type:device_code") {
        polls += 1;
        if (polls < 2) return json({ error: "authorization_pending" }, 400); // user hasn't approved yet
        return json({ access_token: ACCESS, refresh_token: REFRESH, token_type: "Bearer" });
      }
      if (p.get("grant_type") === "refresh_token") return json(p.get("refresh_token") === REFRESH ? { access_token: ACCESS, token_type: "Bearer" } : { error: "invalid_grant" });
      return json({ error: "unsupported_grant_type" });
    }
    const auth = req.headers["authorization"] || "";
    let msg = {}; try { msg = JSON.parse(b); } catch { /* */ }
    if (msg.method === "initialize") return json({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "m", version: "1" } } });
    if (msg.method === "notifications/initialized") { res.writeHead(202); return res.end(); }
    if (msg.method === "tools/list") return json({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "d_tool" }] } });
    if (msg.method === "tools/call") return json(auth === `Bearer ${ACCESS}` ? { jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: `ran ${msg.params?.name}` }] } } : { jsonrpc: "2.0", id: msg.id, error: { code: -32001, message: "bad token" } });
    json({ jsonrpc: "2.0", id: msg.id, result: {} });
  });
});
await new Promise((r) => srv.listen(0, "127.0.0.1", r));
const O = `http://127.0.0.1:${srv.address().port}`;

// ---- Device Authorization Grant ----
const dReg = await j("POST", "/v1/hypervisor/connectors", { service: "device-mcp", kind: "mcp", name: "Device MCP", base_url: `${O}/mcp`, auth_profile: { type: "oauth_device_code", token_endpoint: `${O}/token`, device_authorization_endpoint: `${O}/device`, client_id: "dev-client", scopes: ["mcp"] } });
const dcid = dReg.body?.connector?.connector_id;
const start = await j("POST", `/v1/hypervisor/connectors/${dcid}/oauth/device/start`, {});
ok(start.status === 200 && start.body?.user_code === "WXYZ-1234" && !!start.body?.verification_uri, "device/start returns user_code + verification_uri (RFC 8628)", `status ${start.status}`);
const poll1 = await j("POST", `/v1/hypervisor/connectors/${dcid}/oauth/device/poll`, {});
ok(poll1.status === 200 && poll1.body?.pending === true, "device/poll reports pending while the user hasn't approved", JSON.stringify(poll1.body));
const poll2 = await j("POST", `/v1/hypervisor/connectors/${dcid}/oauth/device/poll`, {});
ok(poll2.status === 200 && poll2.body?.connected === true && poll2.body?.credential_kind === "oauth-refresh", "device/poll completes → seals oauth-refresh (connected)", JSON.stringify(poll2.body));
const dch = await j("POST", `/v1/hypervisor/connectors/${dcid}/invoke`, { tool: "d_tool", request: {} });
const dGrant = mintApprovalGrant({ policyHash: dch.body.approval.policy_hash, requestHash: dch.body.approval.request_hash });
const dInv = await j("POST", `/v1/hypervisor/connectors/${dcid}/invoke`, { tool: "d_tool", request: {}, wallet_approval_grant: dGrant });
ok(dInv.status === 200 && dInv.body?.receipt?.credential_source === "oauth-refresh" && JSON.stringify(dInv.body.response).includes("ran d_tool"), "device-granted lease invokes the MCP tool (mints access from the refresh)", `status ${dInv.status}`);
ok(![REFRESH, ACCESS].some((s) => JSON.stringify(dInv.body).includes(s)), "device tokens never leak in the result");
await j("DELETE", `/v1/hypervisor/connectors/${dcid}`);

// ---- Managed service account (advanced long-lived credential, sealed) ----
const sReg = await j("POST", "/v1/hypervisor/connectors", { service: "sa-test", base_url: `${O}/echo`, allowed_tools: [{ name: "echo", method: "POST", path: "/echo" }] });
const scid = sReg.body?.connector?.connector_id;
const sBind = await j("POST", `/v1/hypervisor/connectors/${scid}/credential`, { kind: "service-account", token: "svc-acct-DONOTLEAK" });
ok(sBind.body?.auth_posture === "token-lease:bound", "bind a managed service-account credential");
const sch = await j("POST", `/v1/hypervisor/connectors/${scid}/invoke`, { tool: "echo" });
const sGrant = mintApprovalGrant({ policyHash: sch.body.approval.policy_hash, requestHash: sch.body.approval.request_hash });
const sInv = await j("POST", `/v1/hypervisor/connectors/${scid}/invoke`, { tool: "echo", request: {}, wallet_approval_grant: sGrant });
ok(sInv.status === 200 && sInv.body?.receipt?.credential_source === "managed-service-account", "service-account invoke labels credential_source managed-service-account", sInv.body?.receipt?.credential_source);
await j("DELETE", `/v1/hypervisor/connectors/${scid}`);

srv.close();
const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "device-managed", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
