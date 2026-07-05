#!/usr/bin/env node
// RunPod GPU runtime adapter done-bar — the second external GPU class, proving the provider
// ladder is not Vast-specific while preserving RunPod semantics (direct_provider GPU runtime
// cloud; secure/community rate cards; region chosen at pod create).
//
// Proves: `runpod` account kind validates; no credential → source unavailable; verified but
// unfetched → no supply claim; fixture candidates normalize (secure/community pricing, skip
// unpriced) but stay advisory forever; degraded fetch emits zero fake quotes; the simulator
// lifecycle runs create/start/workrun/snapshot/restore/delete over the REAL loopback SSH
// custody lane with per-kind gate refusals (runpod_quote_not_live, runpod_price_above_max,
// runpod_budget_reservation_exceeded…); exposures open/close in spend reconciliation;
// IOI_RUNPOD_LIVE=1 without IOI_RUNPOD_API_KEY BLOCKS with a named reason — never a fake pass.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-runpod-adapter.mjs

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
const BUDGET_FILE = path.join(DATA, "resource-budgets", "runpod-verify.json");
const LIVE_MODE = process.env.IOI_RUNPOD_LIVE === "1";
const LIVE_KEY = process.env.IOI_RUNPOD_API_KEY || "";

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
const runpodSource = async () => {
  const s = (await jd("GET", "/v1/hypervisor/cloud-candidates/candidate-sources")).j;
  return (s.sources || []).find((x) => x.source === "runpod") || {};
};

let accountId = null;
let env = null;
async function opWithGrant(o, extra = {}) {
  const base = { provider_id: accountId, op: o, environment_ref: env, ...extra };
  const c = await jd("POST", "/v1/hypervisor/provider-ops", base);
  if (c.status !== 403) return c;
  const grant = mintApprovalGrant({ policyHash: c.j.approval.policy_hash, requestHash: c.j.approval.request_hash });
  return jd("POST", "/v1/hypervisor/provider-ops", { ...base, wallet_approval_grant: grant });
}

async function run() {
  const tag = Date.now().toString(16);
  env = `env-rp-${tag}`;
  rmSync(BUDGET_FILE, { force: true });
  const fixture = await ensureSshFixture();
  const dir = path.join(os.homedir(), ".ioi", "hypervisor", "vast-fixture");
  mkdirSync(dir, { recursive: true });
  const gpuFile = path.join(dir, `runpod-gpus-${tag}.json`);
  // REAL RunPod field shapes: secure + community pricing; one type priced only on community;
  // one type entirely unpriced (must be SKIPPED, never estimated).
  writeFileSync(gpuFile, JSON.stringify({ gpu_types: [
    { id: "NVIDIA GeForce RTX 4090", displayName: "RTX 4090", memoryInGb: 24, securePrice: 0.69, communityPrice: 0.34 },
    { id: "NVIDIA A40", displayName: "A40", memoryInGb: 48, communityPrice: 0.28 },
    { id: "NVIDIA H200", displayName: "H200", memoryInGb: 141 },
  ] }));

  // ── 1. Kind + source posture ladder ──
  const badKind = await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "runpodx", display_name: "nope" });
  const rp = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "runpod", display_name: `RunPod ${tag}` })).j.account || {};
  accountId = rp.account_id;
  ok("`runpod` account kind validates with honest GPU-runtime capabilities",
    badKind.status === 422 && rp.account_ref?.startsWith("provider-account://")
    && rp.capabilities?.isolation === "container_gpu_runtime"
    && rp.capabilities?.privacy === "cloud_gpu_runtime_NOT_private"
    && rp.provider_spend_borne_by === "customer");
  const s0 = await runpodSource();
  ok("no credential → runpod source unavailable with evidence",
    s0.state === "candidate_source_unavailable" && /runpod_credential_absent/.test(s0.reason || ""));
  const SECRET = `RUNPOD-KEY-${tag}`;
  await jd("POST", `/v1/hypervisor/provider-accounts/${rp.account_id}/credential`, { api_key: SECRET });
  const pf = await jd("POST", `/v1/hypervisor/provider-accounts/${rp.account_id}/preflight`);
  ok("bearer binds sealed; verified but unfetched → credential_verified_unprobed (no supply claim)",
    pf.j.ok === true && !JSON.stringify(pf.j).includes(SECRET)
    && (await runpodSource()).state === "credential_verified_unprobed");

  // ── 2. Degraded live fetch → zero fake quotes ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${rp.account_id}`, { endpoint: { mode: "live", endpoint: "http://127.0.0.1:9" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${rp.account_id}/preflight`);
  const intent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "compute.gpu_runtime", resource_classes: ["compute.gpu_runtime"], gpu: { required: true },
  })).j.intent || {};
  const degraded = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  ok("unreachable live endpoint → degraded_unreachable with evidence, zero fake quotes",
    (await runpodSource()).state === "degraded_unreachable"
    && !(degraded.candidates || []).some((c) => c.provider_kind === "runpod")
    && (degraded.rejected || []).some((r) => r.reason_code === "candidate_source_degraded" && /runpod/.test(r.adapter_ref || "")));

  // ── 3. Fixture normalization: RunPod semantics preserved, advisory forever ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${rp.account_id}`, { endpoint: { mode: "fixture", fixture_file: gpuFile } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${rp.account_id}/preflight`);
  const fixed = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const rpc = (fixed.candidates || []).filter((c) => c.provider_kind === "runpod");
  const c4090 = rpc.find((c) => c.gpu?.model === "RTX 4090") || {};
  const a40 = rpc.find((c) => c.gpu?.model === "A40") || {};
  ok("fixture GPU types normalize with RunPod semantics (secure preferred; community carries interruption risk; unpriced SKIPPED)",
    rpc.length === 2
    && c4090.quote?.usd_per_hour === 0.69 && c4090.cloud_type === "secure_cloud_on_demand"
    && a40.quote?.usd_per_hour === 0.28 && a40.cloud_type === "community_cloud_interruptible"
    && (a40.risk_labels || []).includes("community_cloud_interruption")
    && c4090.source === "direct_provider" && /rate card/i.test(c4090.region_note || ""));
  ok("fixture candidates stay advisory FOREVER (labelled, never placement-eligible)",
    rpc.every((c) => c.placement_eligible === "advisory_only" && c.evidence_mode === "fixture_evidence"
      && (c.risk_labels || []).includes("fixture_evidence_not_live_supply")));
  ok("every candidate is evidence-bound (source/adapter/observed/expires/coverage) with custody honesty",
    rpc.every((c) => c.evidence?.adapter_ref === "adapter:runpod-quote" && c.evidence?.observed_at
      && c.evidence?.expires_at && c.custody_plan?.privacy === "cloud_gpu_runtime_NOT_private"
      && (c.custody_plan?.supported_postures || []).join() === "Standard"));

  // ── 4. Simulator lifecycle over the REAL loopback SSH custody lane ──
  const simEndpoint = { mode: "simulator", fixture_file: gpuFile,
    ssh: { host: fixture.host, port: fixture.port, user: fixture.user, key_file: fixture.client_key_path } };
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${rp.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${rp.account_id}/preflight`);
  // Fixture-quote refusal FIRST — while the fixture batch is still active (a later refresh
  // supersedes it, which would fire the expired/superseded rung instead of the fixture rung).
  const fixCand = rpc.find((c) => c.cloud_type === "secure_cloud_on_demand") || {};
  await jd("POST", "/v1/hypervisor/resource/budgets", { budget_id: "runpod-verify", name: "RunPod verify", scope: "external_spend", limit: 1, spent: 0, currency: "USD" });
  const fixCreate = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env, candidate_ref: fixCand.candidate_ref });
  const sim = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand = (sim.candidates || []).find((c) => c.provider_kind === "runpod" && c.cloud_type === "secure_cloud_on_demand") || {};
  const overMax = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env, candidate_ref: cand.candidate_ref, max_hourly_usd: 0.10 });
  ok("quote gate refuses fixture + over-max with runpod-named reasons",
    fixCreate.status === 409 && /runpod_quote_not_live/.test(fixCreate.j.reason || "")
    && overMax.status === 409 && /runpod_price_above_max/.test(overMax.j.reason || ""));
  const created = await opWithGrant("create", { candidate_ref: cand.candidate_ref, max_hourly_usd: 0.7, teardown_policy: "always_teardown_required" });
  ok("grant-authorized create provisions the (simulated) pod + bootstraps the REAL ssh workspace",
    created.j.ok === true && created.j.evidence?.ssh_ready === true
    && String(created.j.evidence?.instance?.instance_id || "").startsWith("rpsim_")
    && created.j.evidence?.live_provisioning_not_run === true
    && /no real RunPod pod exists/.test(created.j.evidence?.provider_native?.note || ""));
  const overBudget = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: `env-rp2-${tag}`, candidate_ref: cand.candidate_ref, max_hourly_usd: 0.7 });
  ok("external_spend reservation blocks the over-budget second create",
    overBudget.status === 409 && /runpod_budget_reservation_exceeded/.test(overBudget.j.reason || ""));
  const marker = `runpod-${tag}`;
  await opWithGrant("start");
  const wr = await opWithGrant("workrun", { command: `echo ${marker} > pod.txt && cat pod.txt` });
  const snap = await opWithGrant("snapshot");
  const sev = snap.j.evidence || {};
  const restored = await opWithGrant("restore", { material_ref: sev.restore_material_ref });
  ok("start/workrun/snapshot/restore run the SAME custody contract as BYO SSH",
    wr.j.ok === true && String(wr.j.evidence?.stdout || "").includes(marker)
    && sev.custody === "daemon" && String(sev.state_root || "").startsWith("sha256:")
    && restored.j.evidence?.state_root_verified === sev.state_root);
  const recon1 = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const exp = (recon1.rows || []).find((e) => e.account_ref === rp.account_ref && e.environment_ref === env) || {};
  ok("create opened a spend exposure exactly like Vast (quote-backed, receipt-cited, customer-borne)",
    exp.status === "open" && exp.candidate_ref === cand.candidate_ref
    && exp.provider === "runpod" && (exp.receipt_refs || []).length >= 4
    && /customer-borne/.test(exp.estimate_note || ""));
  const del = await opWithGrant("delete");
  const recon2 = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const expClosed = (recon2.rows || []).find((e) => e.exposure_ref === exp.exposure_ref) || {};
  ok("teardown tears down + closes the exposure and releases the reservation",
    del.j.ok === true && del.j.evidence?.teardown_state === "torn_down"
    && expClosed.status === "closed" && recon2.budget?.reserved_open_estimates === 0);

  // ── 5. Receipts / ledger / surfaces ──
  const receipts = ((await jd("GET", "/v1/hypervisor/provider-receipts")).j.receipts || [])
    .filter((r) => r.account_ref === rp.account_ref);
  ok("create/start/workrun/snapshot/restore/delete receipts exist with candidate/quote/lease enrichment",
    ["create", "start", "workrun", "snapshot", "restore", "delete"].every((o) => receipts.some((r) => r.op === o && r.outcome === "ok"))
    && receipts.some((r) => r.op === "create" && r.candidate_ref === cand.candidate_ref && !!r.capability_lease?.lease_id));
  const ledger = ((await jd("GET", "/v1/hypervisor/work-ledger")).j.entries || [])
    .filter((e) => e.kind === "provider_crossing" && e.account_ref === rp.account_ref);
  ok("Work Ledger provider crossings include RunPod refs + exposure backlink",
    ledger.some((e) => e.op === "create" && e.exposure_ref === exp.exposure_ref));
  const opsHtml = await fetch(`${SHELL}/__ioi/operations`).then((r) => r.text());
  const envHtml = await fetch(`${SHELL}/__ioi/environments`).then((r) => r.text());
  ok("Operations + Environments show RunPod posture",
    /runpod/i.test(opsHtml) && envHtml.includes(rp.account_ref));

  // ── 6. Live-mode honesty + invariants ──
  if (LIVE_MODE && !LIVE_KEY) {
    ok("runpod_live_credentials_absent — IOI_RUNPOD_LIVE=1 requires IOI_RUNPOD_API_KEY; live execution BLOCKED (not faked)", false);
  } else if (!LIVE_MODE) {
    ok("live_provisioning_not_run — simulator validated the ladder; live RunPod execution is NOT claimed", true);
  }
  const audit = JSON.stringify({ recon2, sim }).toLowerCase();
  ok("no fee objects, no RoutingDecisionReceipt, no markup",
    !audit.includes("routingdecisionreceipt") && !audit.includes("fee_amount") && !audit.includes("markup\":"));
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);
}

async function cleanup() {
  try {
    if (accountId && env) {
      const obs = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "observe", environment_ref: env });
      if (obs.j?.evidence?.teardown_state === "live_or_pending") await opWithGrant("delete");
    }
  } catch { /* best effort */ }
  if (accountId) await jd("DELETE", `/v1/hypervisor/provider-accounts/${accountId}`);
  rmSync(BUDGET_FILE, { force: true });
  const { readdirSync, readFileSync, rmSync: rm } = await import("node:fs");
  const dir = path.join(DATA, "provider-spend-exposures");
  try {
    for (const f of readdirSync(dir)) {
      const rec = JSON.parse(readFileSync(path.join(dir, f), "utf8"));
      if (String(rec.account_ref || "").includes(accountId)) rm(path.join(dir, f), { force: true });
    }
  } catch { /* none */ }
}

run()
  .then(cleanup, async (e) => { await cleanup(); throw e; })
  .then(() => {
    let fail = 0;
    for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
    console.log(`\n${results.length - fail}/${results.length} passed`);
    console.log(`runpod adapter readiness: ${fail ? "FAIL" : "OK"}${LIVE_MODE ? "" : " (live_provisioning_not_run)"}`);
    process.exit(fail ? 1 : 0);
  })
  .catch((e) => {
    console.error("verifier crashed:", e);
    process.exit(1);
  });
