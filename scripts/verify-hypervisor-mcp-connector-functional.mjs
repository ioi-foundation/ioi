#!/usr/bin/env node
// Done-bar for MCP integrations (master-guide #5, "make it real: MCP + OAuth") — the daemon as an
// MCP CLIENT. An MCP integration is a connector of kind "mcp": the daemon does the MCP handshake,
// discovers tools (read-only), and performs tools/call as a WALLET-GOVERNED crossing — each tool
// call a CapabilityLease. Verified against a LOCAL mock MCP server (JSON-RPC), no external creds.
//   register mcp connector → discovery fails closed w/o credential → bind → tools/list → tools/call
//   fails closed w/o grant → with grant the daemon calls the server with the sealed token (redacted)
//   → revoke → fail closed. Usage: node scripts/verify-hypervisor-mcp-connector-functional.mjs [--json]
import { mintApprovalGrant } from "./lib/mint-approval-grant.mjs";
import http from "node:http";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "mcp-connector", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const j = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: await r.json().catch(() => ({})) }; };

if (!JSON_OUT) console.log("MCP integration e2e — daemon as MCP client, tool calls leased");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// mock MCP server (Streamable HTTP / JSON-RPC) — requires a bearer + echoes it back from tools/call
const SECRET = "mcp-bearer-DONOTLEAK-aa1199";
const srv = http.createServer((req, res) => {
  let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
    const auth = req.headers["authorization"] || "";
    let msg = {}; try { msg = JSON.parse(b); } catch { /* */ }
    const reply = (obj) => { res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "sess-1" }); res.end(JSON.stringify(obj)); };
    if (msg.method === "initialize") return reply({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "mock-mcp", version: "1" } } });
    if (msg.method === "notifications/initialized") { res.writeHead(202); return res.end(); }
    if (msg.method === "tools/list") return reply({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "echo_tool", description: "echoes", inputSchema: { type: "object" } }] } });
    if (msg.method === "tools/call") {
      if (!auth) return reply({ jsonrpc: "2.0", id: msg.id, error: { code: -32001, message: "unauthorized" } });
      return reply({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: `called ${msg.params?.name} auth=${auth}` }] } });
    }
    reply({ jsonrpc: "2.0", id: msg.id, result: {} });
  });
});
await new Promise((r) => srv.listen(0, "127.0.0.1", r));
const URL = `http://127.0.0.1:${srv.address().port}/mcp`;

// 1) register an MCP connector (kind: mcp) — the "Add MCP integration" target
const reg = await j("POST", "/v1/hypervisor/connectors", { service: "mock-mcp", kind: "mcp", base_url: URL });
const cid = reg.body?.connector?.connector_id;
ok(!!cid && reg.body?.connector?.kind === "mcp", "register an MCP connector (kind: mcp)", reg.body?.connector?.kind);

// 2) discovery before a credential → fail closed
const disc0 = await j("GET", `/v1/hypervisor/connectors/${cid}/mcp/tools`);
ok(disc0.status === 428, "tool discovery FAILS CLOSED before a credential (428)", `status ${disc0.status}`);

// 3) bind the credential (the OAuth access / bearer the integration connect would yield)
await j("POST", `/v1/hypervisor/connectors/${cid}/credential`, { token: SECRET });

// 4) discovery now lists the server's tools (the daemon did the MCP handshake)
const disc = await j("GET", `/v1/hypervisor/connectors/${cid}/mcp/tools`);
ok(disc.status === 200 && Array.isArray(disc.body?.tools) && disc.body.tools.some((t) => t.name === "echo_tool"), "tools/list discovers the MCP server's tools", JSON.stringify(disc.body?.tools?.map?.((t) => t.name)));

// 5) tools/call without a grant → fail closed (403)
const ch = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "echo_tool", request: { hello: "world" } });
ok(ch.status === 403 && ch.body?.reason === "connector_invoke_authority_required", "tools/call without grant FAILS CLOSED (403)", `status ${ch.status}`);
ok(!!ch.body?.approval?.policy_hash, "challenge exposes the lease hashes");

// 6) authorized tools/call → the daemon calls the MCP server with the sealed token (redacted)
const grant = mintApprovalGrant({ policyHash: ch.body.approval.policy_hash, requestHash: ch.body.approval.request_hash });
const inv = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "echo_tool", request: { hello: "world" }, wallet_approval_grant: grant });
ok(inv.status === 200 && inv.body?.ok === true, "authorized tools/call succeeds (200)", `status ${inv.status}`);
const text = JSON.stringify(inv.body?.response || {});
ok(text.includes("called echo_tool"), "the MCP tool actually ran (result returned)");
ok(text.includes("Bearer ***") && !text.includes(SECRET), "daemon SENT the sealed token to the MCP server AND redacted it from the result");
const lease = inv.body?.receipt?.capability_lease || {};
ok(lease.backing_provider === `mock-mcp:connector:${cid}` && Array.isArray(lease.allowed_tools) && lease.allowed_tools.includes("echo_tool"), "receipt lease scopes to the MCP tool");

// 7) revoke → tools/call fails closed
await j("DELETE", `/v1/hypervisor/connectors/${cid}/credential`);
const postRevoke = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "echo_tool", request: {}, wallet_approval_grant: grant });
ok(postRevoke.status === 428, "tools/call AFTER revoke FAILS CLOSED (428)", `status ${postRevoke.status}`);

await j("DELETE", `/v1/hypervisor/connectors/${cid}`);
srv.close();
const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "mcp-connector", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
