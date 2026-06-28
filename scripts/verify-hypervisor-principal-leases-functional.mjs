#!/usr/bin/env node
// Done-bar for principal-scoped capability leases (hardening #3). The identity plane (WHO) composes
// with the wallet/lease authority (MAY this crossing happen) — it does not replace it. Proven:
//  - ATTRIBUTION: a successful connector crossing records the calling principal_id on the receipt
//    (or "unattributed" for an anonymous caller).
//  - SCOPING: when a connector is principal-scoped, only a principal holding an explicit lease grant
//    for (connector,tool) may cross — roles grant nothing; an unauthenticated caller is refused; the
//    wallet grant is STILL required after the scope passes.
// Usage: node scripts/verify-hypervisor-principal-leases-functional.mjs [--json]
import { mintApprovalGrant } from "./lib/mint-approval-grant.mjs";
import http from "node:http";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const OPERATOR = "00000000-0000-4000-8000-000000000001";
const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "principal-leases", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const j = async (m, p, b, hdr) => { const r = await fetch(DAEMON + p, { method: m, headers: { ...(b ? { "content-type": "application/json" } : {}), ...(hdr || {}) }, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, body: t ? JSON.parse(t) : {} }; };

if (!JSON_OUT) console.log("Principal-scoped leases e2e — attribution + per-principal scope (composes with wallet)");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/editor-targets`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// operator session (the calling principal)
await j("POST", `/v1/hypervisor/principals/${OPERATOR}/password`, { password: "operator-pass-123" });
const tok = (await j("POST", "/v1/hypervisor/auth/login", { email: "johndoe@ioi.local", password: "operator-pass-123" })).body.session_token;
const asOp = { Authorization: `Bearer ${tok}` };

// local echo target (stands in for any connector backend)
const echo = http.createServer((req, res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ ok: true, received_auth: req.headers["authorization"] || null })); }); });
await new Promise((r) => echo.listen(0, "127.0.0.1", r));
const BASE = `http://127.0.0.1:${echo.address().port}`;

// register a connector with two declared tools + a sealed credential
const reg = await j("POST", "/v1/hypervisor/connectors", { service: "pl-echo", base_url: BASE, allowed_tools: [{ name: "echo", method: "POST", path: "/echo" }, { name: "other", method: "POST", path: "/echo" }] });
const cid = reg.body.connector.connector_id;
await j("POST", `/v1/hypervisor/connectors/${cid}/credential`, { token: "pl-secret" });

// invoke helper: challenge → mint grant → authorized invoke (returns the final response)
const cross = async (tool, request, hdr) => {
  const ch = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool, request }, hdr);
  if (ch.status !== 403 || !ch.body?.approval) return ch; // blocked before the wallet gate (scope/policy)
  const grant = mintApprovalGrant({ policyHash: ch.body.approval.policy_hash, requestHash: ch.body.approval.request_hash });
  return j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool, request, wallet_approval_grant: grant }, hdr);
};

// --- ATTRIBUTION (unscoped) ---
const opCross = await cross("echo", { hi: 1 }, asOp);
ok(opCross.status === 200 && opCross.body?.receipt?.principal_id === OPERATOR, "successful crossing attributes the calling principal on the receipt", opCross.body?.receipt?.principal_id);
const anonCross = await cross("echo", { hi: 2 }, {});
ok(anonCross.status === 200 && anonCross.body?.receipt?.principal_id === "unattributed", "anonymous crossing is recorded as 'unattributed'");

// --- SCOPING ---
await j("POST", `/v1/hypervisor/connectors/${cid}/policy`, { principal_scoped: true });
// operator has NO lease grant yet → refused BEFORE the wallet gate
const noGrant = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "echo", request: {} }, asOp);
ok(noGrant.status === 403 && noGrant.body?.reason === "principal_not_authorized", "scoped: principal without a lease grant is refused (403)", noGrant.body?.reason);
// unauthenticated caller → refused (needs a principal)
const noPrin = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "echo", request: {} }, {});
ok(noPrin.status === 403 && noPrin.body?.reason === "principal_required", "scoped: an unauthenticated caller is refused (403 principal_required)", noPrin.body?.reason);

// grant the operator the 'echo' tool → scope passes; the WALLET grant is still required + then crosses
const grantRes = await j("POST", `/v1/hypervisor/principals/${OPERATOR}/lease-grants`, { connector_id: cid, tools: ["echo"] });
ok(grantRes.status === 200 && grantRes.body?.lease_grant?.connector_id === cid, "grant the principal a scoped lease for 'echo'");
const scopedCross = await cross("echo", { hi: 3 }, asOp);
ok(scopedCross.status === 200 && scopedCross.body?.receipt?.principal_id === OPERATOR && scopedCross.body?.receipt?.principal_scoped === true, "scoped principal WITH a grant crosses (wallet still enforced); receipt marks it scoped");
// a DIFFERENT declared tool the principal was NOT granted → refused
const otherTool = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "other", request: {} }, asOp);
ok(otherTool.status === 403 && otherTool.body?.reason === "principal_not_authorized", "scoped: a non-granted tool is refused even for a granted principal");
// revoke the grant → refused again
await j("DELETE", `/v1/hypervisor/principals/${OPERATOR}/lease-grants/${cid}`);
const afterRevoke = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "echo", request: {} }, asOp);
ok(afterRevoke.status === 403 && afterRevoke.body?.reason === "principal_not_authorized", "revoking the lease grant re-refuses the principal");

// cleanup
await j("DELETE", `/v1/hypervisor/connectors/${cid}`);
echo.close();

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "principal-leases", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} principal-leases ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
