#!/usr/bin/env node
// T4 — live wallet.network authority verifier.
//
// Spawns a hermetic hypervisor-daemon and proves the neutral authority contract end to end against
// a REAL provider: the `enterprise_authority` issuer evaluates AuthorityGrantRequests and issues /
// denies portable grants with real expiry, revoke, preflight admission, and a receipt audit trail.
// `local_operator` covers local effects with no grant. `wallet_network_live` (the Option A device
// signer) is a DECLARED host gap unless IOI_WALLET_NETWORK_URL points at a live endpoint — never
// faked. With --require-wallet and no endpoint, that gap is reported (not a failure); the run is
// PASS_WITH_DECLARED_GAPS. Usage: [--require-wallet] [--json].
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO = new URL("..", import.meta.url).pathname;
const DAEMON_BIN = join(REPO, "target/debug/hypervisor-daemon");
const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const REQUIRE_WALLET = args.includes("--require-wallet");
const PORT = 8870 + (process.pid % 60);

const scenarios = [];
const declaredGaps = [];
let failures = 0;
const ok = (cond, msg, detail) => {
  scenarios.push({ ok: !!cond, msg, detail: detail || "" });
  if (!cond) failures++;
  if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`);
};

async function api(method, path, body) {
  const res = await fetch(`http://127.0.0.1:${PORT}${path}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : {} };
}
async function waitReady(timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try { const r = await fetch(`http://127.0.0.1:${PORT}/v1/hypervisor/authority/providers`); if (r.ok) return true; } catch { /* not up */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}

if (!existsSync(DAEMON_BIN)) { console.error(`daemon binary missing: ${DAEMON_BIN} (cargo build --bin hypervisor-daemon)`); process.exit(2); }
const dataDir = mkdtempSync(join(tmpdir(), "ioi-t4-authority-"));
const daemon = spawn(DAEMON_BIN, [], {
  env: { ...process.env, IOI_HYPERVISOR_dataDir: dataDir, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${PORT}` },
  stdio: ["ignore", "ignore", "ignore"],
});

let verdict = "FAIL";
try {
  if (!(await waitReady())) { console.error("daemon did not become ready"); process.exit(2); }
  if (!JSON_OUT) console.log("T4 — live authority providers + portable-grant lifecycle");

  // 1) Provider modes: enterprise_authority is a real live issuer; wallet_network_live honest.
  const providers = (await api("GET", "/v1/hypervisor/authority/providers")).json;
  const byMode = Object.fromEntries((providers.providers || []).map((p) => [p.mode, p]));
  ok(byMode.local_operator?.status === "available", "local_operator provider available");
  ok(byMode.enterprise_authority?.status === "available" && byMode.enterprise_authority?.live === true
    && byMode.enterprise_authority?.issues_portable_grants === true,
    "enterprise_authority is a live portable-grant issuer");
  const walletLive = byMode.wallet_network_live?.live === true;
  if (walletLive) {
    ok(byMode.wallet_network_live?.status === "available", "wallet_network_live configured + available");
  } else {
    ok(byMode.wallet_network_live?.status === "not_configured" && /WALLET_NETWORK_ENDPOINT_NOT_CONFIGURED/.test(byMode.wallet_network_live?.reason || ""),
      "wallet_network_live honestly not_configured (declared, not faked)");
  }

  // 2) Local effect — admitted by local authority, no portable grant.
  const localPf = (await api("POST", "/v1/hypervisor/authority/preflight", { effect: "local_exec", environment_id: "env-local" })).json;
  ok(localPf.admitted === true && localPf.authority === "local_operator", "local effect admitted by local_operator (no grant)");

  // 3) Missing grant — portable crossing blocked fail-closed.
  const noGrant = (await api("POST", "/v1/hypervisor/authority/preflight", { effect: "secret_release", environment_id: "env-1" })).json;
  ok(noGrant.admitted === false && noGrant.re_auth_required === true, "missing grant -> blocked by authority (re-auth required)");

  // 4) Denied grant — unknown action and over-budget both fail closed.
  const denyUnknown = (await api("POST", "/v1/hypervisor/authority/grant", { subject: "operator", action: "exfiltrate_all" })).json;
  ok(denyUnknown.grant?.decision === "denied", "unrecognized action -> denied fail-closed");
  const denyBudget = (await api("POST", "/v1/hypervisor/authority/grant", { subject: "operator", action: "spend", budget: { spend: 9_999_999 } })).json;
  ok(denyBudget.grant?.decision === "denied" && /ceiling/.test(denyBudget.grant?.reason || ""), "over-ceiling spend -> denied by policy");
  // A denied grant cannot admit a crossing.
  const denyPf = (await api("POST", "/v1/hypervisor/authority/preflight", { effect: "spend", environment_id: "env-1", grant_ref: denyBudget.grant?.grant_ref })).json;
  ok(denyPf.admitted === false, "denied grant -> preflight refuses (fail closed)");

  // 5) Valid grant — granted, then preflight admits + emits receipt (live secret-release crossing).
  const secretGrant = (await api("POST", "/v1/hypervisor/authority/grant", { subject: "session:s1", action: "secret_release", resources: ["secret:DB_URL"] })).json;
  ok(secretGrant.grant?.decision === "granted" && secretGrant.status === "active", "valid grant issued (secret_release, active)");
  ok(/(enterprise\.authority|wallet\.network):\/\/grant\//.test(secretGrant.grant?.grant_ref || ""), "grant carries a portable authority_grant_ref");
  ok(Array.isArray(secretGrant.grant?.authority_receipt_refs) && secretGrant.grant.authority_receipt_refs.length >= 1, "grant carries authority_receipt_refs");
  const okPf = (await api("POST", "/v1/hypervisor/authority/preflight", { effect: "secret_release", environment_id: "env-2", grant_ref: secretGrant.grant?.grant_ref })).json;
  ok(okPf.admitted === true && okPf.authority === "portable", "valid grant -> crossing admitted, receipt emitted");

  // A second portable crossing kind (provider credential materialization) also admits with a grant.
  const credGrant = (await api("POST", "/v1/hypervisor/authority/grant", { subject: "session:s1", action: "provider_credential", resources: ["provider:aws"] })).json;
  const credPf = (await api("POST", "/v1/hypervisor/authority/preflight", { effect: "provider_credential", environment_id: "env-2", grant_ref: credGrant.grant?.grant_ref })).json;
  ok(credPf.admitted === true, "second portable crossing (provider_credential) admitted with grant");

  // 6) Revoked grant — execution refuses next step.
  const revGrant = (await api("POST", "/v1/hypervisor/authority/grant", { subject: "session:s1", action: "external_connector_mutation" })).json;
  const revoke = (await api("POST", "/v1/hypervisor/authority/revoke", { grant_ref: revGrant.grant?.grant_ref })).json;
  ok(revoke.ok === true && revoke.status === "revoked", "grant revoked (receipt emitted)");
  const revPf = (await api("POST", "/v1/hypervisor/authority/preflight", { effect: "external_connector_mutation", environment_id: "env-3", grant_ref: revGrant.grant?.grant_ref })).json;
  ok(revPf.admitted === false && /revoked/.test(revPf.reason || ""), "revoked grant -> crossing refused");

  // 7) Expired grant — real-clock expiry -> re-auth, no execution.
  const expGrant = (await api("POST", "/v1/hypervisor/authority/grant", { subject: "session:s1", action: "restore_apply_protected", expiry_seconds: 1 })).json;
  await new Promise((r) => setTimeout(r, 1400)); // real clock advances past the 1s expiry
  const expPf = (await api("POST", "/v1/hypervisor/authority/preflight", { effect: "restore_apply_protected", environment_id: "env-4", grant_ref: expGrant.grant?.grant_ref })).json;
  ok(expPf.admitted === false && /expired/.test(expPf.reason || "") && expPf.re_auth_required === true, "expired grant -> re-auth prompt, no execution");
  const grantsList = (await api("GET", "/v1/hypervisor/authority/grants")).json;
  ok((grantsList.grants || []).some((g) => g.grant_id === expGrant.grant?.grant_id && g.status === "expired"), "grants list reports expired status from the real clock");

  // 8) Receipt audit trail — granted/denied/revoked/preflight all recorded.
  const receipts = (await api("GET", "/v1/hypervisor/authority/receipts")).json;
  const events = new Set((receipts.receipts || []).map((r) => r.event));
  ok(["granted", "denied", "revoked", "preflight_admit", "preflight_block"].every((e) => events.has(e)),
    "authority receipt audit trail covers granted/denied/revoked/preflight admit+block", [...events].join(","));

  // 9) wallet_network_live crossing — required by --require-wallet; declared gap if no live endpoint.
  if (REQUIRE_WALLET) {
    if (walletLive) {
      const liveGrant = (await api("POST", "/v1/hypervisor/authority/grant", { subject: "device:d1", action: "secret_release" })).json;
      ok(/wallet\.network:\/\/grant\//.test(liveGrant.grant?.grant_ref || ""), "live wallet.network grant minted under wallet.network://");
    } else {
      declaredGaps.push({
        gate: "wallet_network_live",
        prerequisite: "WALLET_NETWORK_ENDPOINT_NOT_CONFIGURED",
        reason: "Option A device signer needs a live wallet.network endpoint (set IOI_WALLET_NETWORK_URL). Not present on this host; not faked.",
        host_grantable: true,
      });
      if (!JSON_OUT) console.log("    · DECLARED GAP: wallet_network_live — WALLET_NETWORK_ENDPOINT_NOT_CONFIGURED (Option A signer endpoint absent; not faked)");
    }
  }

  if (failures === 0) verdict = declaredGaps.length > 0 ? "PASS_WITH_DECLARED_GAPS" : "PASS";
} finally {
  daemon.kill("SIGKILL");
  rmSync(dataDir, { recursive: true, force: true });
}

const report = { workstream: "T4", verdict, failures, scenarios: scenarios.length, declared_gaps: declaredGaps };
if (JSON_OUT) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(`  declared gaps: ${declaredGaps.length ? declaredGaps.map((g) => g.prerequisite).join(", ") : "none"}`);
  console.log(`  VERDICT: ${verdict} (${scenarios.length - failures}/${scenarios.length} checks)`);
}
process.exit(verdict === "FAIL" ? 1 : 0);
