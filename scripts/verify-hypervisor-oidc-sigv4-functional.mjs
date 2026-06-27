#!/usr/bin/env node
// Done-bar for the final auth profiles (master-guide #5): OIDC/workload token-exchange (RFC 8693)
// and AWS SigV4 provider-native signed auth. Both flow through the same lease pipeline; the agent
// only ever gets a scoped lease. (SigV4 signature math is proven by the AWS known-answer Rust test
// `sigv4_get_vanilla_matches_aws_vector`; this verifies the end-to-end wiring + no secret leak.)
import { mintApprovalGrant } from "./lib/mint-approval-grant.mjs";
import http from "node:http";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "oidc-sigv4", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const j = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: await r.json().catch(() => ({})) }; };
// the grant binds to the EXACT request, so the challenge must use the same request as the invoke
const grantFor = async (cid, tool, request = {}) => { const c = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool, request }); return mintApprovalGrant({ policyHash: c.body.approval.policy_hash, requestHash: c.body.approval.request_hash }); };

if (!JSON_OUT) console.log("OIDC token-exchange + AWS SigV4 e2e");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

const SUBJECT = "oidc-subject-DONOTLEAK", OIDC_ACCESS = "oidc-access-DONOTLEAK", AWS_SECRET = "aws-secret-DONOTLEAK";
const srv = http.createServer((req, res) => {
  let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
    const json = (o) => { res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "s1" }); res.end(JSON.stringify(o)); };
    const u = req.url || "";
    if (u.startsWith("/token")) {
      const p = new URLSearchParams(b);
      if (p.get("grant_type") === "urn:ietf:params:oauth:grant-type:token-exchange") return json(p.get("subject_token") === SUBJECT ? { access_token: OIDC_ACCESS, issued_token_type: "urn:ietf:params:oauth:token-type:access_token", token_type: "Bearer" } : { error: "invalid_grant" });
      return json({ error: "unsupported_grant_type" });
    }
    if (u.startsWith("/aws/")) return json({ ok: true, received_auth: req.headers["authorization"] || null, x_amz_date: req.headers["x-amz-date"] || null });
    const auth = req.headers["authorization"] || "";
    let msg = {}; try { msg = JSON.parse(b); } catch { /* */ }
    if (msg.method === "initialize") return json({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "m", version: "1" } } });
    if (msg.method === "notifications/initialized") { res.writeHead(202); return res.end(); }
    if (msg.method === "tools/list") return json({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "w_tool" }] } });
    if (msg.method === "tools/call") return json(auth === `Bearer ${OIDC_ACCESS}` ? { jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: `ran ${msg.params?.name}` }] } } : { jsonrpc: "2.0", id: msg.id, error: { code: -32001, message: "bad token" } });
    json({ jsonrpc: "2.0", id: msg.id, result: {} });
  });
});
await new Promise((r) => srv.listen(0, "127.0.0.1", r));
const O = `http://127.0.0.1:${srv.address().port}`;

// ---- OIDC / workload identity (RFC 8693 token exchange) ----
const oReg = await j("POST", "/v1/hypervisor/connectors", { service: "oidc-mcp", kind: "mcp", name: "OIDC MCP", base_url: `${O}/mcp` });
const ocid = oReg.body.connector.connector_id;
const oBind = await j("POST", `/v1/hypervisor/connectors/${ocid}/credential`, { kind: "oidc-workload", token_url: `${O}/token`, subject_token: SUBJECT, audience: "api://mcp", scopes: "read" });
ok(oBind.body?.kind === "oidc-workload", "bind an oidc-workload credential (token exchange)", oBind.body?.kind);
const oInv = await j("POST", `/v1/hypervisor/connectors/${ocid}/invoke`, { tool: "w_tool", request: {}, wallet_approval_grant: await grantFor(ocid, "w_tool") });
ok(oInv.status === 200 && oInv.body?.receipt?.credential_source === "oidc-workload", "invoke exchanges the subject token for access (credential_source oidc-workload)", oInv.body?.receipt?.credential_source);
ok(JSON.stringify(oInv.body.response).includes("ran w_tool"), "the MCP tool ran via the exchanged access token");
ok(![SUBJECT, OIDC_ACCESS].some((s) => JSON.stringify(oInv.body).includes(s)), "no subject/access token leaks (oidc)");
await j("DELETE", `/v1/hypervisor/connectors/${ocid}`);

// ---- AWS SigV4 (provider-native signed auth) ----
const aReg = await j("POST", "/v1/hypervisor/connectors", { service: "aws-api", base_url: O, allowed_tools: [{ name: "aws_op", method: "POST", path: "/aws/op" }] });
const acid = aReg.body.connector.connector_id;
const aBind = await j("POST", `/v1/hypervisor/connectors/${acid}/credential`, { kind: "aws-sigv4", access_key_id: "AKIDTEST", secret_access_key: AWS_SECRET, region: "us-east-1", service: "execute-api" });
ok(aBind.body?.auth_posture === "token-lease:bound", "bind aws-sigv4 credentials");
const aInv = await j("POST", `/v1/hypervisor/connectors/${acid}/invoke`, { tool: "aws_op", request: { hello: "world" }, wallet_approval_grant: await grantFor(acid, "aws_op", { hello: "world" }) });
const recvAuth = aInv.body?.response?.received_auth || "";
ok(aInv.status === 200 && aInv.body?.receipt?.credential_source === "aws-sigv4", "aws-sigv4 invoke (credential_source aws-sigv4)", aInv.body?.receipt?.credential_source);
ok(/^AWS4-HMAC-SHA256 Credential=AKIDTEST\/\d{8}\/us-east-1\/execute-api\/aws4_request/.test(recvAuth), "request was SigV4-signed (AWS4-HMAC-SHA256, scoped credential)", recvAuth.slice(0, 70));
ok(/SignedHeaders=host;x-amz-date/.test(recvAuth) && /Signature=[0-9a-f]{64}/.test(recvAuth), "signed headers + 64-hex signature present", recvAuth.includes("Signature=") ? "sig ok" : "no sig");
ok(!!aInv.body?.response?.x_amz_date, "x-amz-date header sent");
ok(!JSON.stringify(aInv.body).includes(AWS_SECRET), "the AWS secret key never leaks");
await j("DELETE", `/v1/hypervisor/connectors/${acid}`);

srv.close();
const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "oidc-sigv4", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict ? (verdict === "FAIL" ? 1 : 0) : 0);
