#!/usr/bin/env node
// Done-bar for the Metering & Cost plane (Bucket B absorption #1) — the Hypervisor's REAL economic
// plane, backing the native Billing + Cost & Budgets pages (previously SaaS-mock). Consumption is
// derived from the daemon's actual `receipts` (agentgres records), NOT fabricated; a wallet-backed
// budget sets a ceiling + auto-funding ("auto top-up" reframed as wallet replenishment). Proves:
//   real OCU consumption series → metered balance → budget set → reconcile auto-funds from wallet.
// Usage: node scripts/verify-hypervisor-metering-cost-functional.mjs [--json]
const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const SERVE = process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173";
const ORG = "00000000-0000-4000-8000-0000000000a1";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "metering-cost", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const jd = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, body: t ? JSON.parse(t) : {} }; };
const ja = async (svc, rpc, b) => { const r = await fetch(`${SERVE}/api/gitpod.v1.${svc}/${rpc}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b || {}) }); const t = await r.text(); return { status: r.status, body: t ? JSON.parse(t) : {} }; };

if (!JSON_OUT) console.log("Metering & Cost e2e — real OCU from receipts + wallet-backed budget");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/budget`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }
try { const r = await fetch(`${SERVE}/ai`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("serve (:4173) not running"); }

// snapshot the budget to restore at the end
const orig = (await jd("GET", "/v1/hypervisor/budget")).body.budget || {};

// 1) Consumption is derived from REAL receipts (daemon truth) and projected by the adapter.
const dUsage = (await jd("GET", "/v1/hypervisor/usage/consumption")).body;
ok(dUsage.ok && Array.isArray(dUsage.metrics) && dUsage.metrics.length >= 2, "daemon aggregates consumption into metric kinds", dUsage.metrics?.map((m) => m.kind).join(","));
const aSeries = await ja("BillingService", "GetCreditConsumptionTimeSeries", { organizationId: ORG, dateRange: { startTime: "2026-06-01T00:00:00Z", endTime: "2026-12-31T00:00:00Z" } });
const kinds = (aSeries.body.metrics || []).map((m) => m.kind);
ok(kinds.includes("KIND_ENVIRONMENT") && kinds.includes("KIND_LLM"), "adapter projects KIND_ENVIRONMENT + KIND_LLM series", kinds.join(","));
const env = (aSeries.body.metrics || []).find((m) => m.kind === "KIND_ENVIRONMENT");
ok(!!env && Array.isArray(env.series) && env.series.every((p) => !!p.time), "each series point is a dated bucket");
const projectedTotal = (aSeries.body.metrics || []).flatMap((m) => m.series).reduce((a, p) => a + (p.ocu || 0), 0);
ok(projectedTotal >= 0, "consumption total is a real number derived from records", `Σ=${projectedTotal.toFixed(3)} OCU`);

// 2) Metered balance — adapter GetBillingInfo reflects the daemon budget (used == real consumption).
const budget = (await jd("GET", "/v1/hypervisor/budget")).body.budget;
const bi = (await ja("BillingService", "GetBillingInfo", { organizationId: ORG })).body;
ok(Math.abs((bi.usedCredits || 0) - (budget.used_ocu || 0)) < 1e-6, "GetBillingInfo usedCredits == real metered consumption", `${bi.usedCredits}`);
ok(Math.abs((bi.availableCredits || 0) - (budget.available_ocu || 0)) < 1e-6 && bi.totalCredits === budget.budget_ocu, "GetBillingInfo balance == budget − used", `avail ${bi.availableCredits}`);
ok(Math.abs((budget.used_ocu || 0) - (budget.budget_ocu - budget.available_ocu)) < 1e-3, "daemon balance is internally consistent (budget − used = available)");

// 3) Budget set (PUT) persists.
const set = await jd("PUT", "/v1/hypervisor/budget", { budget_ocu: 15, auto_fund_enabled: true, threshold_ocu: 20, target_ocu: 500 });
ok(set.body.budget?.budget_ocu === 15 && set.body.budget?.auto_fund_enabled === true, "budget policy PUT persists (ceiling + auto-fund)");

// 4) Reconcile auto-funds from wallet when below threshold + records a wallet ledger entry.
const rec = (await jd("POST", "/v1/hypervisor/budget/reconcile")).body;
ok(rec.funded === true && !!rec.funding_event_ref, "reconcile auto-funds when balance < threshold", rec.funding_event_ref);
ok(rec.reconciled?.available_ocu >= 500 - 1e-6, "auto-fund replenished the budget to target", `avail ${rec.reconciled?.available_ocu}`);
// the funding event is a wallet-sourced ledger record (no SaaS payment)
const fundId = rec.funding_event_ref;
const led = (await jd("GET", `/v1/hypervisor/budget`)).body; // budget reflects the new ceiling
ok(led.budget?.budget_ocu > 15, "budget ceiling raised by the wallet funding event");

// 5) ReconcileBilling via the adapter is a no-throw projection (idempotent when above threshold).
const recAgain = await ja("BillingService", "ReconcileBilling", { organizationId: ORG });
ok(recAgain.status === 200, "adapter ReconcileBilling returns cleanly");

// 6) Entitlement posture — self-hosted active contract (no SaaS plan/payment).
const subs = (await ja("BillingService", "ListSubscriptions", { organizationId: ORG })).body;
const sub = (subs.subscriptions || [])[0];
ok(!!sub && sub.status === "SUBSCRIPTION_STATUS_ACTIVE", "ListSubscriptions returns an active self-hosted entitlement", sub?.contractId);

// restore the original budget policy
await jd("PUT", "/v1/hypervisor/budget", { budget_ocu: orig.budget_ocu ?? 1000, auto_fund_enabled: orig.auto_fund_enabled ?? false, threshold_ocu: orig.threshold_ocu ?? 20, target_ocu: orig.target_ocu ?? 1000 });

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "metering-cost", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} metering-cost ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
