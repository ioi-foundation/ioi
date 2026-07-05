#!/usr/bin/env node
// Guarded Vast lifecycle done-bar.
//
// Proves the first paid-external-GPU lifecycle path is GUARDED end to end: no credential →
// no mutation; fixture quotes can NEVER provision; expired quotes can NEVER provision;
// budget discovery precedes everything; the wallet/capability challenge binds account +
// quote + candidate + max price + GPU facts + teardown policy; grant_ref presence strings
// never pass; every success AND failure mints an enriched ProviderOperationReceipt; snapshot
// material enters daemon custody with an admitted sha256 state_root; provider-native ids are
// evidence only; teardown ALWAYS runs. The lifecycle harness runs the SIMULATED control
// plane over a REAL ssh/custody lane and the done-bar reports live_provisioning_not_run —
// live Vast execution is never claimed unless actually run.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-vast-lifecycle.mjs

import path from "node:path";
import os from "node:os";
import { writeFileSync, rmSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { ensureSshFixture } = await import(path.join(HERE, "ensure-ssh-fixture.mjs"));
const { mintApprovalGrant } = await import(path.join(HERE, "../../../scripts/lib/mint-approval-grant.mjs"));

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const DATA = process.env.IOI_HYPERVISOR_DATA_DIR || path.join(os.homedir(), ".ioi", "hypervisor", "data");
const BUDGET_FILE = path.join(DATA, "resource-budgets", "vast-lifecycle-verify.json");
const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const LIVE_MODE = process.env.IOI_VAST_LIVE === "1";

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let vastAccountId = null;
let env = null;

async function opWithGrant(accountId, o, extra = {}) {
  const base = { provider_id: accountId, op: o, environment_ref: env, ...extra };
  const c = await jd("POST", "/v1/hypervisor/provider-ops", base);
  if (c.status !== 403) return c;
  const grant = mintApprovalGrant({ policyHash: c.j.approval.policy_hash, requestHash: c.j.approval.request_hash });
  return jd("POST", "/v1/hypervisor/provider-ops", { ...base, wallet_approval_grant: grant });
}

async function run() {
  const tag = Date.now().toString(16);
  env = `env-vlc-${tag}`;
  rmSync(BUDGET_FILE, { force: true }); // self-healing: a prior run's budget must not skew gates
  const fixture = await ensureSshFixture();
  const priorPolicy = (await jd("GET", "/v1/hypervisor/placement/venue-policy")).j.policy || {};
  const offersDir = path.join(os.homedir(), ".ioi", "hypervisor", "vast-fixture");
  mkdirSync(offersDir, { recursive: true });
  const offersFile = path.join(offersDir, `lifecycle-offers-${tag}.json`);
  writeFileSync(offersFile, JSON.stringify({ offers: [
    { id: 91001, gpu_name: "RTX 4090", num_gpus: 1, gpu_ram: 24564, dph_total: 0.311, geolocation: "Sweden, SE", reliability2: 0.998, verified: true, inet_down: 900, disk_space: 256 },
  ] }));

  // ── 1. No credential → source unavailable + mutation impossible ──
  const vast = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "vast", display_name: `Vast LC ${tag}` })).j.account || {};
  vastAccountId = vast.account_id;
  const noCred = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: vast.account_id, op: "create", environment_ref: env });
  // Fail-closed can fire at ANY rung of the ladder depending on estate state: budget (409),
  // quote gate (422 candidate required), credential resolution (428), or named not-implemented.
  ok("no credential → no mutation possible (fail-closed before any provisioning)",
    noCred.j.ok !== true && (noCred.status === 428 || noCred.status === 409 || noCred.status === 422
      || /not_implemented|credential/i.test(JSON.stringify(noCred.j))));

  // ── 2. Simulator control plane engages over the REAL ssh fixture ──
  const SECRET = `VAST-LC-KEY-${tag}`;
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/credential`, { api_key: SECRET });
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vast.account_id}`, {
    endpoint: { mode: "simulator", fixture_file: offersFile,
      ssh: { host: fixture.host, port: fixture.port, user: fixture.user, key_file: fixture.client_key_path } },
  });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/preflight`);
  const intent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "compute.gpu_runtime", resource_classes: ["compute.gpu_runtime"], gpu: { required: true },
  })).j.intent || {};
  const refreshed = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const simCand = (refreshed.candidates || []).find((c) => c.provider_kind === "vast") || {};
  ok("simulator quotes derive labelled (simulator_evidence, lifecycle harness, advisory_only — never live supply)",
    simCand.evidence_mode === "simulator_evidence" && simCand.placement_eligible === "advisory_only"
    && (simCand.eligibility_labels || []).includes("simulated_control_plane")
    && /guarded_lifecycle_simulator/.test(simCand.lifecycle || ""));

  // ── 3. Budget discovery FIRST ──
  const budgetGate = await jd("POST", "/v1/hypervisor/provider-ops", {
    provider_id: vast.account_id, op: "create", environment_ref: env, candidate_ref: simCand.candidate_ref,
  });
  const budgets = (await jd("GET", "/v1/hypervisor/resource/budgets")).j.budgets || [];
  const hadBudget = budgets.some((b) => b.scope === "external_spend" && (b.limit || 0) > (b.spent || 0));
  ok("budget discovery precedes everything (409 budget_blocked without external_spend headroom)",
    hadBudget || (budgetGate.status === 409 && /budget/.test(budgetGate.j.reason || "")));
  if (!hadBudget) {
    await jd("POST", "/v1/hypervisor/resource/budgets", { budget_id: "vast-lifecycle-verify", name: "Vast lifecycle verify", scope: "external_spend", limit: 100, spent: 0, currency: "USD" });
  }

  // ── 4. Quote gates: missing/unknown/fixture/expired quotes can never provision ──
  const noRef = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: vast.account_id, op: "create", environment_ref: env });
  ok("create without candidate_ref → named refusal + failure receipt (quote-gated provisioning)",
    noRef.status === 422 && /vast_candidate_ref_required/.test(noRef.j.reason || "")
    && String(noRef.j.receipt_ref || "").startsWith("agentgres://provider-receipt/"));
  // Fixture-mode quote: flip to fixture, derive, flip back to simulator, then try to use it.
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vast.account_id}`, { endpoint: { mode: "fixture", fixture_file: offersFile } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/preflight`);
  const fixRefresh = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const fixCand = (fixRefresh.candidates || []).find((c) => c.provider_kind === "vast") || {};
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vast.account_id}`, {
    endpoint: { mode: "simulator", fixture_file: offersFile,
      ssh: { host: fixture.host, port: fixture.port, user: fixture.user, key_file: fixture.client_key_path } },
  });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/preflight`);
  const fixtureCreate = await jd("POST", "/v1/hypervisor/provider-ops", {
    provider_id: vast.account_id, op: "create", environment_ref: env, candidate_ref: fixCand.candidate_ref,
  });
  ok("FIXTURE quote → mutation rejected (vast_quote_not_live) — fixture stays advisory forever",
    fixtureCreate.status === 409 && /vast_quote_not_live/.test(fixtureCreate.j.reason || ""));
  // Expired quote.
  await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref, ttl_seconds: 5 });
  const shortCands = (await jd("GET", `/v1/hypervisor/cloud-candidates/candidates?intent_ref=${intent.intent_ref}`)).j.candidates || [];
  const shortCand = shortCands.find((c) => c.provider_kind === "vast" && c.status === "active") || {};
  await sleep(6500);
  const expiredCreate = await jd("POST", "/v1/hypervisor/provider-ops", {
    provider_id: vast.account_id, op: "create", environment_ref: env, candidate_ref: shortCand.candidate_ref,
  });
  ok("EXPIRED quote → mutation rejected (vast_quote_expired_requires_requote)",
    expiredCreate.status === 409 && /vast_quote_expired_requires_requote/.test(expiredCreate.j.reason || ""));

  // ── 5. Authority: challenge binds the quote facts; presence strings never pass ──
  const fresh = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand = (fresh.candidates || []).find((c) => c.provider_kind === "vast") || {};
  const challenge = await jd("POST", "/v1/hypervisor/provider-ops", {
    provider_id: vast.account_id, op: "create", environment_ref: env,
    candidate_ref: cand.candidate_ref, max_hourly_usd: 0.5, teardown_policy: "always_teardown_required",
  });
  const facets = challenge.j.lease_request_facets || {};
  ok("missing grant → 403 wallet/capability challenge binding account+quote+candidate+max-price+GPU+teardown+spend posture",
    challenge.status === 403 && !!challenge.j.approval?.policy_hash
    && facets.candidate_ref === cand.candidate_ref && facets.quote_ref === cand.quote_ref
    && facets.max_hourly_usd === 0.5 && facets.gpu?.model === "RTX 4090"
    && facets.teardown_policy === "always_teardown_required"
    && !!challenge.j.spend_estimate);
  const fakeGrant = await jd("POST", "/v1/hypervisor/provider-ops", {
    provider_id: vast.account_id, op: "create", environment_ref: env,
    candidate_ref: cand.candidate_ref, grant_ref: "grant://fake-presence-string",
  });
  ok("fake grant_ref presence string → still 403 (never admitted)", fakeGrant.status === 403);
  const overMax = await jd("POST", "/v1/hypervisor/provider-ops", {
    provider_id: vast.account_id, op: "create", environment_ref: env,
    candidate_ref: cand.candidate_ref, max_hourly_usd: 0.10,
  });
  ok("price above declared max → refused before any lease (vast_price_above_max)",
    overMax.status === 409 && /vast_price_above_max/.test(overMax.j.reason || ""));

  // ── 6. Guarded lifecycle over the simulated control plane + REAL ssh/custody lane ──
  const created = await opWithGrant(vast.account_id, "create", { candidate_ref: cand.candidate_ref, max_hourly_usd: 0.5, teardown_policy: "always_teardown_required" });
  ok("grant-authorized create provisions the (simulated) instance and bootstraps the REAL ssh workspace",
    created.j.ok === true && created.j.evidence?.ssh_ready === true
    && created.j.evidence?.instance?.execution_mode === "simulated_control_plane"
    && created.j.evidence?.live_provisioning_not_run === true
    && String(created.j.evidence?.instance?.instance_id || "").startsWith("vsim_"));
  ok("provider-native ids are EVIDENCE only, and say so",
    /evidence only/.test(created.j.evidence?.provider_native?.note || "")
    && /no real Vast instance exists/.test(created.j.evidence?.provider_native?.note || ""));
  const started = await opWithGrant(vast.account_id, "start");
  const marker = `vast-guarded-${tag}`;
  const wr = await opWithGrant(vast.account_id, "workrun", { command: `echo ${marker} > gpu-proof.txt && cat gpu-proof.txt` });
  ok("start + workrun run the SAME workspace mutation contract as BYO SSH (real remote exec)",
    started.j.ok === true && started.j.evidence?.ssh_ready === true
    && wr.j.ok === true && String(wr.j.evidence?.stdout || "").includes(marker));
  const snap = await opWithGrant(vast.account_id, "snapshot");
  const sev = snap.j.evidence || {};
  ok("snapshot streams into DAEMON custody with an admitted sha256 state_root",
    snap.j.ok === true && sev.custody === "daemon" && String(sev.state_root || "").startsWith("sha256:"));
  const restored = await opWithGrant(vast.account_id, "restore", { material_ref: sev.restore_material_ref });
  ok("restore re-hashes daemon custody bytes before pushing back (state_root verified)",
    restored.j.ok === true && restored.j.evidence?.state_root_verified === sev.state_root);
  const outage = await opWithGrant(vast.account_id, "inject_outage");
  ok("outage injection on a marketplace instance fails closed with a named reason",
    outage.j.ok === false && /vast_outage_injection_not_supported/.test(outage.j.reason || ""));
  const deleted = await opWithGrant(vast.account_id, "delete");
  ok("teardown tears the instance down and says so (remote cleanup + native teardown state)",
    deleted.j.ok === true && deleted.j.evidence?.teardown_state === "torn_down"
    && deleted.j.evidence?.cleanup_verified === true);
  const obs = await opWithGrant(vast.account_id, "observe");
  ok("observe reports the torn-down instance honestly", obs.j.evidence?.teardown_state === "torn_down");

  // ── 7. Receipts: every op minted enriched ProviderOperationReceipts ──
  const receipts = ((await jd("GET", "/v1/hypervisor/provider-receipts")).j.receipts || [])
    .filter((r) => r.account_ref === vast.account_ref && r.environment_ref === env);
  const createReceipt = receipts.find((r) => r.op === "create" && r.outcome === "ok") || {};
  ok("create receipt binds account+candidate+quote+grant+lease+spend estimate+native ids+execution mode",
    createReceipt.candidate_ref === cand.candidate_ref && createReceipt.quote_ref === cand.quote_ref
    && String(createReceipt.grant_ref || "").length > 0 && !!createReceipt.capability_lease?.lease_id
    && !!createReceipt.spend_estimate && createReceipt.execution_mode === "simulated_control_plane"
    && !!createReceipt.provider_native);
  const opsSeen = new Set(receipts.filter((r) => r.outcome === "ok").map((r) => r.op));
  ok("create/start/workrun/snapshot/restore/delete receipts all exist",
    ["create", "start", "workrun", "snapshot", "restore", "delete"].every((o) => opsSeen.has(o)));
  const snapReceipt = receipts.find((r) => r.op === "snapshot" && r.outcome === "ok") || {};
  const delReceipt = receipts.find((r) => r.op === "delete" && r.outcome === "ok") || {};
  ok("snapshot receipt carries the state_root; delete receipt carries the teardown state",
    snapReceipt.state_root === sev.state_root && delReceipt.teardown_state === "torn_down");
  ok("failure receipts exist too (quote-gate refusals were receipted)",
    receipts.some((r) => r.outcome === "quote_gate_refused"));

  // ── 8. Invariants ──
  const audit = JSON.stringify({ receipts, fresh }).toLowerCase();
  ok("no fee objects, no RoutingDecisionReceipt on the paid lifecycle path",
    !audit.includes("routingdecisionreceipt") && !audit.includes("fee_amount") && !audit.includes("markup\":"));
  const ledger = ((await jd("GET", "/v1/hypervisor/work-ledger")).j.entries || [])
    .filter((e) => e.kind === "provider_crossing" && e.account_ref === vast.account_ref);
  ok("Work Ledger shows the vast lifecycle crossings with candidate/quote/teardown evidence",
    ledger.some((e) => e.op === "create" && e.candidate_ref === cand.candidate_ref)
    && ledger.some((e) => e.op === "delete" && e.teardown_state === "torn_down"));
  const opsHtml = await fetch(`${SHELL}/__ioi/operations`).then((r) => r.text());
  ok("Operations shows the vast provider crossings", opsHtml.includes('id="ops-provider-health"') && /vast/.test(opsHtml));
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── 9. Live-mode honesty ──
  ok(LIVE_MODE
    ? "LIVE mode requested — live provisioning path exercised"
    : "live_provisioning_not_run — simulator validated the state machine, receipts, custody, and teardown; live Vast execution is NOT claimed",
    LIVE_MODE ? false /* live harness not implemented in CI — do not claim */ : true);
}

async function cleanup() {
  // Teardown ALWAYS runs — including failure paths.
  try {
    if (vastAccountId && env) {
      const obs = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: vastAccountId, op: "observe", environment_ref: env });
      if (obs.j?.evidence?.teardown_state === "live_or_pending") {
        await opWithGrant(vastAccountId, "delete");
      }
    }
  } catch { /* teardown best effort — the account delete below still removes the plane records */ }
  try {
    const prior = (await jd("GET", "/v1/hypervisor/placement/venue-policy")).j.policy || {};
    if (prior.venue !== "run_local") await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: "run_local" });
  } catch { /* venue restore best effort */ }
  if (vastAccountId) await jd("DELETE", `/v1/hypervisor/provider-accounts/${vastAccountId}`);
  rmSync(BUDGET_FILE, { force: true });
}

run()
  .then(cleanup, async (e) => { await cleanup(); throw e; })
  .then(() => {
    let fail = 0;
    for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
    console.log(`\n${results.length - fail}/${results.length} passed`);
    console.log(`vast guarded lifecycle readiness: ${fail ? "FAIL" : "OK"}${LIVE_MODE ? "" : " (live_provisioning_not_run)"}`);
    process.exit(fail ? 1 : 0);
  })
  .catch((e) => {
    console.error("verifier crashed:", e);
    process.exit(1);
  });
