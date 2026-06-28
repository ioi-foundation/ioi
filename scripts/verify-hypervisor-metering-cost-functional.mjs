#!/usr/bin/env node
// Done-bar for the Metering & Cost plane (Bucket B absorption #1) — the Hypervisor's REAL economic
// plane. Daemon-only (source-neutral): exercises /v1/hypervisor/usage/consumption + /budget directly.
// Consumption is derived from the daemon's actual `receipts` (agentgres records), NOT fabricated; a
// wallet-backed budget sets a ceiling + auto-funding ("auto top-up" reframed as wallet replenishment).
// Usage: node scripts/verify-hypervisor-metering-cost-functional.mjs [--json]
const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "metering-cost", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const jd = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, body: t ? JSON.parse(t) : {} }; };

if (!JSON_OUT) console.log("Metering & Cost e2e — real OCU from receipts + wallet-backed budget (daemon-only)");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/editor-targets`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }
const orig = (await jd("GET", "/v1/hypervisor/budget")).body.budget || {};

// 1) Consumption derived from REAL receipts → per-day OCU series by metric kind (incl. KIND_ALL).
const u = (await jd("GET", "/v1/hypervisor/usage/consumption?from=2026-06-01T00:00:00Z&to=2026-12-31T00:00:00Z")).body;
const kinds = (u.metrics || []).map((m) => m.kind);
ok(u.ok && kinds.includes("KIND_ENVIRONMENT") && kinds.includes("KIND_LLM") && kinds.includes("KIND_ALL"), "consumption aggregates KIND_ENVIRONMENT + KIND_LLM + KIND_ALL", kinds.join(","));
const env = (u.metrics || []).find((m) => m.kind === "KIND_ENVIRONMENT");
ok(!!env && Array.isArray(env.series) && env.series.every((p) => !!p.time), "each series point is a dated bucket");
ok(typeof u.total_ocu === "number" && u.total_ocu >= 0, "consumption total is a real number derived from records", `Σ=${(u.total_ocu || 0).toFixed(3)} OCU`);

// 2) Metered balance is internally consistent (budget − used = available).
const budget = (await jd("GET", "/v1/hypervisor/budget")).body.budget;
ok(typeof budget.used_ocu === "number" && Math.abs((budget.used_ocu || 0) - (budget.budget_ocu - budget.available_ocu)) < 1e-3, "balance consistent: budget − used = available", `used ${budget.used_ocu}`);

// 3) Budget set (PUT) persists.
const set = await jd("PUT", "/v1/hypervisor/budget", { budget_ocu: 15, auto_fund_enabled: true, threshold_ocu: 20, target_ocu: 500 });
ok(set.body.budget?.budget_ocu === 15 && set.body.budget?.auto_fund_enabled === true, "budget policy PUT persists (ceiling + auto-fund)");

// 4) Reconcile auto-funds from wallet when below threshold + records a wallet ledger entry.
const rec = (await jd("POST", "/v1/hypervisor/budget/reconcile")).body;
ok(rec.funded === true && !!rec.funding_event_ref, "reconcile auto-funds when balance < threshold", rec.funding_event_ref);
ok(rec.reconciled?.available_ocu >= 500 - 1e-6, "auto-fund replenished the budget to target", `avail ${rec.reconciled?.available_ocu}`);
ok((await jd("GET", "/v1/hypervisor/budget")).body.budget?.budget_ocu > 15, "budget ceiling raised by the wallet funding event");

// 5) Reconcile again (now above threshold) is idempotent (no double-fund).
const rec2 = (await jd("POST", "/v1/hypervisor/budget/reconcile")).body;
ok(rec2.funded === false, "reconcile above threshold does not re-fund (idempotent)");

// restore the original budget policy
await jd("PUT", "/v1/hypervisor/budget", { budget_ocu: orig.budget_ocu ?? 1000, auto_fund_enabled: orig.auto_fund_enabled ?? false, threshold_ocu: orig.threshold_ocu ?? 20, target_ocu: orig.target_ocu ?? 1000 });

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "metering-cost", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} metering-cost ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
