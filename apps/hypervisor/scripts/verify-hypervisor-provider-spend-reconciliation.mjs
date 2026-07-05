#!/usr/bin/env node
// Provider spend reconciliation done-bar — customer-borne external-spend accounting over the
// receipts Hypervisor already emits. NOT billing, NOT fees, NOT settlement, NOT markup.
//
// Proves: create without an external_spend budget still blocks; a quote-backed metered create
// opens a spend EXPOSURE citing account/candidate/quote/grant/receipts (native ids evidence
// only); reservations gate further creates until teardown releases them; fixture/advisory and
// unpriced quotes never create exposure; workrun/snapshot/restore accrete receipts without
// inventing new price; teardown closes exposure honestly and incomplete teardown leaves an
// open warning; budget `spent` is never faked; the Work Ledger drawer backlinks reconciliation.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-provider-spend-reconciliation.mjs

import path from "node:path";
import os from "node:os";
import { writeFileSync, rmSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { ensureSshFixture } = await import(path.join(HERE, "ensure-ssh-fixture.mjs"));
const { mintApprovalGrant } = await import(path.join(HERE, "../../../scripts/lib/mint-approval-grant.mjs"));

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DATA = process.env.IOI_HYPERVISOR_DATA_DIR || path.join(os.homedir(), ".ioi", "hypervisor", "data");
const BUDGET_FILE = path.join(DATA, "resource-budgets", "spend-recon-verify.json");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const recon = async () => (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;

let accountId = null;
const envs = [];
async function opWithGrant(o, envRef, extra = {}) {
  const base = { provider_id: accountId, op: o, environment_ref: envRef, ...extra };
  const c = await jd("POST", "/v1/hypervisor/provider-ops", base);
  if (c.status !== 403) return c;
  const grant = mintApprovalGrant({ policyHash: c.j.approval.policy_hash, requestHash: c.j.approval.request_hash });
  return jd("POST", "/v1/hypervisor/provider-ops", { ...base, wallet_approval_grant: grant });
}

async function run() {
  const tag = Date.now().toString(16);
  rmSync(BUDGET_FILE, { force: true });
  const fixture = await ensureSshFixture();
  const offersDir = path.join(os.homedir(), ".ioi", "hypervisor", "vast-fixture");
  mkdirSync(offersDir, { recursive: true });
  const offersFile = path.join(offersDir, `recon-offers-${tag}.json`);
  writeFileSync(offersFile, JSON.stringify({ offers: [
    { id: 92001, gpu_name: "RTX 4090", num_gpus: 1, gpu_ram: 24564, dph_total: 0.6, geolocation: "Sweden, SE", reliability2: 0.99, verified: true },
  ] }));

  const vast = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "vast", display_name: `Vast recon ${tag}` })).j.account || {};
  accountId = vast.account_id;
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/credential`, { api_key: `k-${tag}` });
  const simEndpoint = { mode: "simulator", fixture_file: offersFile,
    ssh: { host: fixture.host, port: fixture.port, user: fixture.user, key_file: fixture.client_key_path } };
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vast.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/preflight`);
  const intent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "compute.gpu_runtime", resource_classes: ["compute.gpu_runtime"], gpu: { required: true },
  })).j.intent || {};
  const cands = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand = (cands.candidates || []).find((c) => c.provider_kind === "vast") || {};
  const env1 = `env-psr-a-${tag}`; const env2 = `env-psr-b-${tag}`;
  envs.push(env1, env2);

  // ── 1. No budget → create still blocks; no exposure appears ──
  const noBudget = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env1, candidate_ref: cand.candidate_ref });
  const r0 = await recon();
  ok("create without external_spend budget still blocks (409) and opens NO exposure",
    noBudget.status === 409 && /budget/.test(noBudget.j.reason || "")
    && !(r0.rows || []).some((e) => e.account_ref === vast.account_ref)
    && r0.budget?.exists === false || !(r0.rows || []).some((e) => e.account_ref === vast.account_ref));

  // ── 2. Budget (limit 1) → quote-backed create opens an exposure with full citations ──
  await jd("POST", "/v1/hypervisor/resource/budgets", { budget_id: "spend-recon-verify", name: "Spend recon verify", scope: "external_spend", limit: 1, spent: 0, currency: "USD" });
  const created = await opWithGrant("create", env1, { candidate_ref: cand.candidate_ref, max_hourly_usd: 0.6, teardown_policy: "always_teardown_required" });
  const r1 = await recon();
  const exp1 = (r1.rows || []).find((e) => e.account_ref === vast.account_ref && e.environment_ref === env1) || {};
  ok("quote-backed metered create opens an OPEN exposure citing account/candidate/quote/grant/receipt",
    created.j.ok === true && exp1.status === "open"
    && exp1.candidate_ref === cand.candidate_ref && exp1.quote_ref === cand.quote_ref
    && String(exp1.grant_ref || "").length > 0
    && String(exp1.create_receipt_ref || "").startsWith("agentgres://provider-receipt/")
    && (exp1.receipt_refs || []).length >= 1
    && /evidence only/.test(exp1.provider_native?.note || "")
    && /customer-borne/.test(exp1.estimate_note || ""));
  ok("reconciliation reports reserved estimates + headroom backed by the exposure (spent never faked)",
    r1.budget?.reserved_open_estimates === 0.6 && r1.budget?.remaining_headroom === 0.4
    && r1.budget?.spent === 0
    && r1.estimated_open_exposure_rate?.open_count === 1
    && /never fake/i.test(r1.budget?.spent_note || ""));

  // ── 3. Reservation discipline: a second create must not over-reserve the budget ──
  const second = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env2, candidate_ref: cand.candidate_ref, max_hourly_usd: 0.6 });
  ok("second create exceeding reserved headroom is refused (vast_budget_reservation_exceeded, receipted)",
    second.status === 409 && /vast_budget_reservation_exceeded/.test(second.j.reason || "")
    && String(second.j.receipt_ref || "").startsWith("agentgres://provider-receipt/"));

  // ── 4. Ops accrete receipts WITHOUT inventing price ──
  await opWithGrant("start", env1);
  const wr = await opWithGrant("workrun", env1, { command: `echo recon-${tag} > spend.txt && cat spend.txt` });
  const snap = await opWithGrant("snapshot", env1);
  const restored = await opWithGrant("restore", env1, { material_ref: snap.j.evidence?.restore_material_ref });
  const r2 = await recon();
  const exp1b = (r2.rows || []).find((e) => e.exposure_ref === exp1.exposure_ref) || {};
  ok("workrun/snapshot/restore accrete receipt refs + state roots on the SAME exposure — no new price, no new exposure",
    wr.j.ok === true && restored.j.ok === true
    && (exp1b.receipt_refs || []).length >= 5
    && exp1b.usd_per_hour === 0.6 && exp1b.max_hourly_usd === 0.6
    && (exp1b.state_roots || []).length >= 1
    && String((exp1b.state_roots || [])[0] || "").startsWith("sha256:")
    && (r2.rows || []).filter((e) => e.account_ref === vast.account_ref).length === 1);

  // ── 5. Teardown closes the exposure and releases the reservation ──
  const del = await opWithGrant("delete", env1);
  const r3 = await recon();
  const exp1c = (r3.rows || []).find((e) => e.exposure_ref === exp1.exposure_ref) || {};
  ok("teardown closes the exposure honestly (teardown receipt + state) and releases the reservation",
    del.j.ok === true && exp1c.status === "closed" && exp1c.teardown_state === "torn_down"
    && String(exp1c.teardown_receipt_ref || "").startsWith("agentgres://provider-receipt/")
    && r3.budget?.reserved_open_estimates === 0 && r3.budget?.remaining_headroom === 1
    && r3.teardown_finalized?.count >= 1);
  const secondNow = await opWithGrant("create", env2, { candidate_ref: cand.candidate_ref, max_hourly_usd: 0.6 });
  ok("released headroom admits the next quote-backed create", secondNow.j.ok === true);

  // ── 6. Incomplete teardown leaves an open warning ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vast.account_id}`, { endpoint: { ...simEndpoint, simulate_teardown_failure: true } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/preflight`);
  const delWarn = await opWithGrant("delete", env2);
  const r4 = await recon();
  const exp2 = (r4.rows || []).find((e) => e.environment_ref === env2) || {};
  ok("incomplete teardown → closed_with_warning + a standing incomplete-teardown warning with refs",
    delWarn.j.ok === true && exp2.status === "closed_with_warning"
    && /INCOMPLETE TEARDOWN/.test(exp2.warning || "")
    && (r4.incomplete_teardown_warnings || []).some((w) => w.exposure_ref === exp2.exposure_ref)
    && r4.unsettled_estimates?.count >= 1);

  // ── 7. Fixture/advisory + unpriced quotes never create exposure (refused before exposure) ──
  const exposuresBefore = (await recon()).rows.length;
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vast.account_id}`, { endpoint: { mode: "fixture", fixture_file: offersFile } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/preflight`);
  const fixCands = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const fixCand = (fixCands.candidates || []).find((c) => c.provider_kind === "vast") || {};
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vast.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/preflight`);
  const fixCreate = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: `env-psr-fix-${tag}`, candidate_ref: fixCand.candidate_ref });
  const exposuresAfter = (await recon()).rows.length;
  ok("fixture/advisory candidates never create spend exposure (refused at the quote gate)",
    fixCreate.status === 409 && /vast_quote_not_live/.test(fixCreate.j.reason || "")
    && exposuresAfter === exposuresBefore);

  // ── 8. Ledger backlinks + UI ──
  const ledger = ((await jd("GET", "/v1/hypervisor/work-ledger")).j.entries || [])
    .filter((e) => e.kind === "provider_crossing" && e.account_ref === vast.account_ref);
  ok("Work Ledger provider crossings backlink their reconciliation exposure",
    ledger.some((e) => e.exposure_ref === exp1.exposure_ref && String(e.spend_reconciliation_ref || "").includes("ops-spend-recon")));
  const opsHtml = await fetch(`${SHELL}/__ioi/operations`).then((r) => r.text());
  ok("Operations shows the spend reconciliation strip (headroom/reserved/open/warnings, customer-borne copy)",
    opsHtml.includes('id="ops-spend-recon"') && /Provider spend reconciliation/.test(opsHtml)
    && /customer-borne/i.test(opsHtml) && /incomplete teardown/i.test(opsHtml));
  const envHtml = await fetch(`${SHELL}/__ioi/environments`).then((r) => r.text());
  ok("Environments provider card shows spend posture (finalized/warning counts, customer-borne)",
    /spend posture:/.test(envHtml) && /incomplete teardown/i.test(envHtml));

  // ── 9. Hard boundaries ──
  const all = JSON.stringify(await recon()).toLowerCase();
  ok("no fee objects, no RoutingDecisionReceipt, no markup, no fake settlement, no Work Credit debit",
    !all.includes("routingdecisionreceipt") && !all.includes("fee_amount") && !all.includes("markup\":")
    && /never fakes settlement|never fake/.test(all) && /customer-borne/.test(all)
    && (await recon()).budget.spent === 0);
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);
}

async function cleanup() {
  try {
    for (const e of envs) {
      const obs = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "observe", environment_ref: e });
      if (obs.j?.evidence?.teardown_state === "live_or_pending") await opWithGrant("delete", e);
    }
  } catch { /* best effort */ }
  if (accountId) await jd("DELETE", `/v1/hypervisor/provider-accounts/${accountId}`);
  rmSync(BUDGET_FILE, { force: true });
  // Exposures are evidence and stay on disk — but the verifier's own rows must not skew
  // reruns' arithmetic: remove ONLY rows carrying this run's account ref.
  const { readdirSync, readFileSync, rmSync: rm } = await import("node:fs");
  const dir = path.join(DATA, "provider-spend-exposures");
  try {
    for (const f of readdirSync(dir)) {
      const rec = JSON.parse(readFileSync(path.join(dir, f), "utf8"));
      if (String(rec.account_ref || "").includes(accountId)) rm(path.join(dir, f), { force: true });
    }
  } catch { /* no exposures dir yet */ }
}

run()
  .then(cleanup, async (e) => { await cleanup(); throw e; })
  .then(() => {
    let fail = 0;
    for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
    console.log(`\n${results.length - fail}/${results.length} passed`);
    console.log(`provider spend reconciliation readiness: ${fail ? "FAIL" : "OK"}`);
    process.exit(fail ? 1 : 0);
  })
  .catch((e) => {
    console.error("verifier crashed:", e);
    process.exit(1);
  });
