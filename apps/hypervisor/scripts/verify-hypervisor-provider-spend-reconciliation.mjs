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
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { verifierFixtureDir } from "./lib/verifier-stack.mjs";
import { authorityVerifierStack } from "./lib/verifier-authority-stack.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { ensureSshFixture } = await import(path.join(HERE, "ensure-ssh-fixture.mjs"));
const { teardownFindings, selfTestTeardownContract } = await import(path.join(HERE, "lib/teardown-disposition.mjs"));

// Its own isolated daemon + serve on a temp data dir, the operator signed in, its offer/bid/facts documents in a temp
// fixture dir — never the owner's :8765/:4173 nor anything under ~/.ioi/hypervisor (R-240, verifier hygiene,
// 2026-09-29). This verifier used to delete (and, through the daemon, write) resource-budgets/*-verify.json in the
// OWNER's data dir, delete exposure records out of it, and write fixtures under ~/.ioi/hypervisor/vast-fixture; a fresh
// plane is torn down whole.
//
// A REAL AUTHORITY, NOT A TEST SIGNER (R-240, provider adapters on an authority stack, 2026-09-29). A provider-ops write
// names its owner and an idempotency key (400 mutation_owner_ref_required otherwise), and a grant-gated crossing needs a
// configured authority principal — a test-signer grant is no authority (501 provider_operation_authority_required). The
// daemon takes its grants from a sealed deployment-local wallet.network authority of this verifier's own
// (lib/verifier-authority-stack.mjs): the ungranted call parks a challenge, the operator approves it with the run's
// passphrase on the daemon's decision route, and the retry names the approval_ref. A sealed bring-up takes minutes.
const A = await authorityVerifierStack({ label: "provider-spend-reconciliation" });
const STACK = A.stack;
const DAEMON = STACK.daemonUrl;
const SHELL = STACK.serveUrl;
const FIXTURES = verifierFixtureDir("spend-recon");

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
// one logical op, one idempotency key: the challenged call and its granted retry are the same request
const opWithGrant = (o, envRef, extra = {}) => A.crossing("/v1/hypervisor/provider-ops", A.owned({ provider_id: accountId, op: o, environment_ref: envRef, ...extra }));

async function run() {
  const tag = Date.now().toString(16);
  const fixture = await ensureSshFixture();
  const offersDir = FIXTURES.dir;
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
  const noBudget = await jd("POST", "/v1/hypervisor/provider-ops", A.owned({ provider_id: accountId, op: "create", environment_ref: env1, candidate_ref: cand.candidate_ref }));
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
  const second = await jd("POST", "/v1/hypervisor/provider-ops", A.owned({ provider_id: accountId, op: "create", environment_ref: env2, candidate_ref: cand.candidate_ref, max_hourly_usd: 0.6 }));
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
  // BRANCH 1 of the teardown contract — PROVEN ABSENT. Only this branch may report
  // cleanup_verified, and it owes no cleanup obligation. Before PR #129 the adapter emitted
  // `teardown_state: "torn_down"` and `cleanup_verified: true` as hardcoded constants, so the
  // old form of this assertion was pinning the overclaim and could not have failed.
  const provenAbsent = teardownFindings(del, "torn_down");
  ok("proven-absent teardown owes NO cleanup obligation, closes the exposure honestly (teardown receipt + state) and releases the reservation",
    provenAbsent.length === 0 && exp1c.status === "closed" && exp1c.teardown_state === "torn_down"
    && String(exp1c.teardown_receipt_ref || "").startsWith("agentgres://provider-receipt/")
    && r3.budget?.reserved_open_estimates === 0 && r3.budget?.remaining_headroom === 1
    && r3.teardown_finalized?.count >= 1,
    provenAbsent.join("; "));
  ok("the teardown-outcome checker still rejects every overclaim it names (self-test)",
    selfTestTeardownContract().length === 0, selfTestTeardownContract().join("; "));
  // (a quote lives 15 minutes, and each crossing above was a real authority's approval, minutes long: the next create
  // takes a fresh quote for the same offer, as the product requires — an expired one is refused before any lease)
  const candNow = ((await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j.candidates || [])
    .find((c) => c.provider_kind === "vast") || {};
  const secondNow = await opWithGrant("create", env2, { candidate_ref: candNow.candidate_ref, max_hourly_usd: 0.6 });
  ok("released headroom admits the next quote-backed create", secondNow.j.ok === true);

  // ── 6. Incomplete teardown leaves an open warning ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vast.account_id}`, { endpoint: { ...simEndpoint, simulate_teardown_failure: true } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/preflight`);
  const delWarn = await opWithGrant("delete", env2);
  const r4 = await recon();
  const exp2 = (r4.rows || []).find((e) => e.environment_ref === env2) || {};
  // BRANCH 2 — FAILED. The provider-native destroy explicitly reported it did not destroy, so
  // the resource is presumed live: teardown_failed, cleanup_verified false, a durable cleanup
  // obligation open, and the exposure closed WITH WARNING rather than silently closed. Deletion
  // still ANSWERS.
  const failed = teardownFindings(delWarn, "teardown_failed");
  ok("incomplete teardown → teardown_failed with a durable obligation, never reported verified, closed_with_warning + a standing incomplete-teardown warning with refs",
    failed.length === 0 && delWarn.j.evidence?.native_teardown?.destroyed === false
    && exp2.status === "closed_with_warning"
    && /INCOMPLETE TEARDOWN/.test(exp2.warning || "")
    && (r4.incomplete_teardown_warnings || []).some((w) => w.exposure_ref === exp2.exposure_ref)
    && r4.unsettled_estimates?.count >= 1,
    failed.join("; "));

  // BRANCH 3 — UNKNOWN. The provider half returns, but the remote workspace cleanup half is made
  // unreachable (its root is left unwritable so the remote `rm -rf` cannot prove absence).
  // Absence is unproven: torn_down_unverified, never coerced to success, a durable obligation
  // stays open, and the spend exposure must NOT be silently closed as settled either.
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vast.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/preflight`);
  const envU = `env-recon-unverified-${tag}`;
  envs.push(envU);
  const candU = ((await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j.candidates || [])
    .find((c) => c.provider_kind === "vast") || {};
  await opWithGrant("create", envU, { candidate_ref: candU.candidate_ref, max_hourly_usd: 0.6 });
  await opWithGrant("start", envU);
  const brokeU = await opWithGrant("workrun", envU, { command: "chmod 500 .." });
  const delU = await opWithGrant("delete", envU);
  const unverified = teardownFindings(delU, "torn_down_unverified");
  ok("an UNREACHABLE cleanup half is torn_down_unverified with a durable obligation, is never reported verified, and delete still answers",
    brokeU.j.evidence?.exit_code === 0 && unverified.length === 0
    && delU.j.evidence?.remote_workspace_cleanup === "unreachable",
    unverified.join("; "));
  await opWithGrant("workrun", envU, { command: "chmod 700 .." });
  const delURepaired = await opWithGrant("delete", envU);
  ok("once the cleanup half is reachable again the SAME resource tears down provably and the obligation is discharged",
    teardownFindings(delURepaired, "torn_down").length === 0,
    teardownFindings(delURepaired, "torn_down").join("; "));

  // ── 7. Fixture/advisory + unpriced quotes never create exposure (refused before exposure) ──
  const exposuresBefore = (await recon()).rows.length;
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vast.account_id}`, { endpoint: { mode: "fixture", fixture_file: offersFile } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/preflight`);
  const fixCands = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const fixCand = (fixCands.candidates || []).find((c) => c.provider_kind === "vast") || {};
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vast.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/preflight`);
  const fixCreate = await jd("POST", "/v1/hypervisor/provider-ops", A.owned({ provider_id: accountId, op: "create", environment_ref: `env-psr-fix-${tag}`, candidate_ref: fixCand.candidate_ref }));
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
      const obs = await jd("POST", "/v1/hypervisor/provider-ops", A.owned({ provider_id: accountId, op: "observe", environment_ref: e }));
      if (obs.j?.evidence?.teardown_state === "live_or_pending") await opWithGrant("delete", e);
    }
  } catch { /* best effort */ }
  if (accountId) await jd("DELETE", `/v1/hypervisor/provider-accounts/${accountId}`);
}

run()
  .then(cleanup, async (e) => { await cleanup(); throw e; })
  .then(() => {
    let fail = 0;
    for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
    console.log(`\n${results.length - fail}/${results.length} passed`);
    console.log(`provider spend reconciliation readiness: ${fail ? "FAIL" : "OK"}`);
    if (A.decisionRefusals.length) console.log(`authority decisions refused: ${A.decisionRefusals.map((d) => `${d.op || "?"}: ${d.status} ${d.code}`).join(", ")}`);
    FIXTURES.remove(); A.stop().finally(() => process.exit(fail ? 1 : 0));
  })
  .catch((e) => {
    console.error("verifier crashed:", e);
    A.stop().finally(() => process.exit(1));
  });
