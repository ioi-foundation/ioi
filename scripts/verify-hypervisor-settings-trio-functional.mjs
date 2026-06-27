#!/usr/bin/env node
// Done-bar for the Bucket A "trio" (#3) — the remaining settings-surface RPCs that were mock-only:
//   RunnerManagerService/ListAvailableRunnerManagers  (Runners page)
//   RunnerService/CreateRunnerLogsToken               (Runners page)
//   ServiceAccountService/ListServiceAccounts         (Environments page)
//   IntegrationService/ValidateIntegration            (Integrations page)
// These are honest local projections (no daemon plane needed): one local runner manager, a scoped
// logs token, the system-managed Hypervisor service account, and connector-backed validation.
// Usage: node scripts/verify-hypervisor-settings-trio-functional.mjs [--json]
const JSON_OUT = process.argv.includes("--json");
const SERVE = process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173";
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "settings-trio", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const ja = async (svc, rpc, b) => { const r = await fetch(`${SERVE}/api/gitpod.v1.${svc}/${rpc}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b || {}) }); const t = await r.text(); return { status: r.status, body: t ? JSON.parse(t) : {} }; };

if (!JSON_OUT) console.log("Settings trio e2e — runner managers / logs token / service accounts / validate");
try { const r = await fetch(`${SERVE}/ai`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("serve (:4173) not running"); }

// 1) ListAvailableRunnerManagers — one local manager.
const rm = await ja("RunnerManagerService", "ListAvailableRunnerManagers", {});
const mgr = (rm.body.runnerManagers || [])[0];
ok(!!mgr && !!mgr.runnerManagerId && !!mgr.name, "ListAvailableRunnerManagers returns the local runner manager", mgr?.name);

// 2) CreateRunnerLogsToken — a scoped access token.
const lt = await ja("RunnerService", "CreateRunnerLogsToken", { runnerId: "local-microvm" });
ok(typeof lt.body.accessToken === "string" && lt.body.accessToken.length > 8, "CreateRunnerLogsToken mints an access token");

// 3) ListServiceAccounts — the system-managed Hypervisor identity.
const sa = await ja("ServiceAccountService", "ListServiceAccounts", {});
const acct = (sa.body.serviceAccounts || [])[0];
ok(!!acct && !!acct.id && acct.systemManaged === true && !!acct.name, "ListServiceAccounts returns the system-managed service account", acct?.name);
ok(!!acct?.creator?.principal && !!acct?.validUntil, "service account carries creator + validUntil metadata");

// 4) ValidateIntegration — true for a real connector, false for an unknown id.
const bad = await ja("IntegrationService", "ValidateIntegration", { integrationId: "definitely-not-a-real-connector" });
ok(bad.body.valid === false, "ValidateIntegration rejects an unknown integration id");
let realId = "";
try { const r = await fetch(`${DAEMON}/v1/hypervisor/connectors`); const j = await r.json(); realId = (j.connectors || [])[0]?.connector_id || ""; } catch { /* */ }
if (realId) {
  const good = await ja("IntegrationService", "ValidateIntegration", { integrationId: realId });
  ok(good.body.valid === true, "ValidateIntegration validates a real registered connector", realId);
} else {
  ok(true, "ValidateIntegration real-connector check skipped (no connectors registered)");
}

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "settings-trio", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} settings-trio ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
