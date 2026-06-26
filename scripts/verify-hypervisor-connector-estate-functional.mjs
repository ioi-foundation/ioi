#!/usr/bin/env node
// Done-bar for the generic connector estate (master-guide #5) — ANY service as a USE-ONLY lease on
// the one CapabilityLease gateway. Proves a non-SCM connector end to end against a LOCAL echo target
// (deterministic, no external creds): register → bind sealed bearer → invoke a DECLARED tool through
// the wallet crossing → the daemon performs the authenticated call (the echo confirms it received
// the bearer) → the credential is REDACTED from the result → revoke → fail closed.
//
// The agent names a tool; it never holds the credential. Slack/Databricks/etc. are the same shape
// with a real base_url + token. Usage: node scripts/verify-hypervisor-connector-estate-functional.mjs [--json]
import { mintApprovalGrant } from "./lib/mint-approval-grant.mjs";
import http from "node:http";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "connector-estate", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const j = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: await r.json().catch(() => ({})) }; };

if (!JSON_OUT) console.log("Connector estate e2e — any service as a use-only lease");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// local target — stands in for Slack/Databricks/etc. /echo reports the Authorization header it saw;
// /token is a mock OAuth2 endpoint that mints an access token from a refresh grant.
const SECRET = "echo-bearer-DONOTLEAK-9f3a2c";
const OAUTH_REFRESH = "oauth-refresh-DONOTLEAK-c4d8";
const OAUTH_ACCESS = "oauth-access-DONOTLEAK-7b21";
const echo = http.createServer((req, res) => {
  let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
    res.writeHead(200, { "content-type": "application/json" });
    if ((req.url || "").startsWith("/token")) res.end(JSON.stringify({ access_token: OAUTH_ACCESS, token_type: "Bearer", expires_in: 3600 }));
    else res.end(JSON.stringify({ ok: true, received_auth: req.headers["authorization"] || null, path: req.url }));
  });
});
await new Promise((r) => echo.listen(0, "127.0.0.1", r));
const PORT = echo.address().port;
const BASE = `http://127.0.0.1:${PORT}`;

// 1) register a generic connector (echo service) with ONE declared tool
const reg = await j("POST", "/v1/hypervisor/connectors", { service: "echo-test", base_url: BASE, allowed_tools: [{ name: "echo", method: "POST", path: "/echo" }] });
const cid = reg.body?.connector?.connector_id;
ok(!!cid && reg.body?.connector?.auth_posture === "token-lease:unbound", "register generic connector (unbound)", reg.body?.connector?.auth_posture);

// 2) invoke before binding a credential → fail closed (428)
const preCred = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "echo", request: { hi: 1 } });
ok(preCred.status === 428 && preCred.body?.reason === "scm_credential_required", "invoke before credential FAILS CLOSED (428)", `status ${preCred.status}`);

// 3) bind a sealed bearer credential
const bind = await j("POST", `/v1/hypervisor/connectors/${cid}/credential`, { token: SECRET });
ok(bind.body?.auth_posture === "token-lease:bound", "bind sealed bearer credential", bind.body?.auth_posture);

// 4) invoking an UNDECLARED tool is refused (lease only permits declared tools)
const offManifest = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "delete.everything", request: {} });
ok(offManifest.status === 403 && offManifest.body?.reason === "tool_not_allowed", "undeclared tool is refused (tool_not_allowed)", `status ${offManifest.status}`);

// 5) invoke the declared tool WITHOUT a grant → fail closed (403) + challenge exposes hashes
const ch = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "echo", request: { hi: 1 } });
ok(ch.status === 403 && ch.body?.reason === "connector_invoke_authority_required", "invoke without grant FAILS CLOSED (403 authority)", `status ${ch.status}`);
ok(!!ch.body?.approval?.policy_hash && !!ch.body?.approval?.request_hash, "challenge exposes daemon-derived hashes");
ok(Array.isArray(ch.body?.allowed_tools) && ch.body.allowed_tools.includes("echo"), "challenge scopes the lease to the named tool");

// 6) mint a grant → AUTHORIZED invoke → the daemon performs the call with the SEALED bearer
const grant = mintApprovalGrant({ policyHash: ch.body.approval.policy_hash, requestHash: ch.body.approval.request_hash });
const inv = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "echo", request: { hi: 1 }, wallet_approval_grant: grant });
ok(inv.status === 200 && inv.body?.ok === true && inv.body?.status === 200, "authorized invoke succeeds (200)", `status ${inv.status}`);
ok(inv.body?.response?.received_auth === "Bearer ***", "daemon SENT the sealed bearer (echo saw it) AND it is REDACTED in the result", inv.body?.response?.received_auth);
ok(!JSON.stringify(inv.body).includes(SECRET), "the secret never appears in the invoke result");
const lease = inv.body?.receipt?.capability_lease || {};
const NINE = ["authority_provider_ref", "backing_provider", "allowed_tools", "resource_refs", "policy_hash", "request_hash", "expires_at", "receipt_required", "revocation_ref"];
ok(NINE.every((k) => k in lease), "receipt embeds the 9-field capability lease");
ok(lease.backing_provider === `echo-test:connector:${cid}`, "lease backing_provider names the connector", lease.backing_provider);
ok(inv.body?.receipt?.credential_source === "connector", "credential_source: connector (sealed bearer resolved)");

// 7) the audit trail carries the invoke lease and leaks no secret
const leases = JSON.stringify((await j("GET", "/v1/hypervisor/capability-leases")).body?.leases || []);
ok(leases.includes(lease.request_hash) && !leases.includes(SECRET), "capability-leases audit trail records the invoke lease, no secret");

// 8) revoke → invoke with the same grant fails closed (428)
const rev = await j("DELETE", `/v1/hypervisor/connectors/${cid}/credential`);
ok(rev.body?.revoked === true, "revoke deletes the sealed credential");
const postRevoke = await j("POST", `/v1/hypervisor/connectors/${cid}/invoke`, { tool: "echo", request: { hi: 1 }, wallet_approval_grant: grant });
ok(postRevoke.status === 428, "invoke AFTER revoke FAILS CLOSED (428)", `status ${postRevoke.status}`);

await j("DELETE", `/v1/hypervisor/connectors/${cid}`); // clean up the test connector

// 9) OAuth-refresh credential kind (the native-Integrations / Gmail / Atlassian model): the daemon
// MINTS a fresh access token from a sealed refresh token per use — refresh token never leaves.
const oReg = await j("POST", "/v1/hypervisor/connectors", { service: "oauth-test", base_url: BASE, allowed_tools: [{ name: "echo", method: "POST", path: "/echo" }] });
const ocid = oReg.body?.connector?.connector_id;
const oBind = await j("POST", `/v1/hypervisor/connectors/${ocid}/credential`, { kind: "oauth-refresh", refresh_token: OAUTH_REFRESH, token_url: `${BASE}/token`, client_id: "cid", client_secret: "csecret" });
ok(oBind.body?.kind === "oauth-refresh", "bind an oauth-refresh credential", oBind.body?.kind);
const oCh = await j("POST", `/v1/hypervisor/connectors/${ocid}/invoke`, { tool: "echo", request: {} });
ok(oCh.status === 403, "oauth-refresh invoke without grant FAILS CLOSED (403)", `status ${oCh.status}`);
const oGrant = mintApprovalGrant({ policyHash: oCh.body.approval.policy_hash, requestHash: oCh.body.approval.request_hash });
const oInv = await j("POST", `/v1/hypervisor/connectors/${ocid}/invoke`, { tool: "echo", request: {}, wallet_approval_grant: oGrant });
ok(oInv.status === 200 && oInv.body?.receipt?.credential_source === "oauth-refresh", "invoke MINTS a fresh access token (credential_source oauth-refresh)", oInv.body?.receipt?.credential_source);
ok(oInv.body?.response?.received_auth === "Bearer ***", "daemon minted+sent the access token AND redacted it", oInv.body?.response?.received_auth);
ok(!JSON.stringify(oInv.body).includes(OAUTH_REFRESH) && !JSON.stringify(oInv.body).includes(OAUTH_ACCESS), "neither the refresh nor the access token leaks");
await j("DELETE", `/v1/hypervisor/connectors/${ocid}`);

echo.close();
const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "connector-estate", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
