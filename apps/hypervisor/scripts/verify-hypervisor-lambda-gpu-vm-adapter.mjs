#!/usr/bin/env node
// Lambda-class GPU VM adapter done-bar — the third GPU class and the missing member of the
// first production external-compute trio: the BORING, high-trust ordinary Linux GPU VM lane
// (VM + ssh user ubuntu + instance-lifetime persistent disk), never flattened into a generic
// cloud. Vast = marketplace, RunPod = runtime cloud, lambda_cloud = plain GPU VMs.
//
// Proves: `lambda_cloud` account kind validates with VM-specific capabilities; no credential →
// source unavailable; verified but unfetched → no supply claim; fixture instance types
// normalize (cents/hour converted verbatim, unpriced SKIPPED, regions-with-capacity preserved)
// but stay advisory forever; degraded fetch emits zero fake quotes; the wallet challenge binds
// the VM shape (region + instance type + disk + teardown policy); ssh is UNKNOWN until boot
// polling proves readiness (pre-boot workruns fail closed lambda_ssh_bootstrap_unknown); the
// simulator lifecycle runs create/start/workrun/snapshot/restore/stop/delete over the REAL
// loopback SSH custody lane (stop is honest: lambda VMs have no native stop — spend accrues
// until teardown); provider-native VM/disk ids stay evidence-only while daemon sha256 state
// roots remain restore truth; exposures open/close (or close_with_warning on incomplete
// teardown) in spend reconciliation; IOI_LAMBDA_LIVE=1 without IOI_LAMBDA_API_KEY BLOCKS with a
// named reason — never a fake pass.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-lambda-gpu-vm-adapter.mjs

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
const BUDGET_FILE = path.join(DATA, "resource-budgets", "lambda-verify.json");
const LIVE_MODE = process.env.IOI_LAMBDA_LIVE === "1";
const LIVE_KEY = process.env.IOI_LAMBDA_API_KEY || "";

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const lambdaSource = async () => {
  const s = (await jd("GET", "/v1/hypervisor/cloud-candidates/candidate-sources")).j;
  return (s.sources || []).find((x) => x.source === "lambda_cloud") || {};
};

let accountId = null;
let env = null;
async function opWithGrant(o, extra = {}) {
  const base = { provider_id: accountId, op: o, environment_ref: extra.environment_ref || env, ...extra };
  const c = await jd("POST", "/v1/hypervisor/provider-ops", base);
  if (c.status !== 403) return c;
  const grant = mintApprovalGrant({ policyHash: c.j.approval.policy_hash, requestHash: c.j.approval.request_hash });
  return jd("POST", "/v1/hypervisor/provider-ops", { ...base, wallet_approval_grant: grant });
}

async function run() {
  const tag = Date.now().toString(16);
  env = `env-lm-${tag}`;
  rmSync(BUDGET_FILE, { force: true });
  const fixture = await ensureSshFixture();
  const dir = path.join(os.homedir(), ".ioi", "hypervisor", "vast-fixture");
  mkdirSync(dir, { recursive: true });
  const typesFile = path.join(dir, `lambda-instance-types-${tag}.json`);
  // REAL Lambda field shapes: instance-type rate cards priced in cents/hour with per-region
  // capacity and VM specs (persistent local storage). One type entirely unpriced — a preview
  // shape that must be SKIPPED, never estimated.
  writeFileSync(typesFile, JSON.stringify({ instance_types: [
    { name: "gpu_1x_a100_sxm4", description: "1x A100 (40 GB SXM4)", gpu_description: "A100 SXM4 40GB",
      vram_gb: 40, price_cents_per_hour: 129,
      specs: { vcpus: 30, memory_gib: 200, storage_gib: 512, gpus: 1 },
      regions: ["us-east-1", "us-west-2"] },
    { name: "gpu_8x_h100_sxm5", description: "8x H100 (80 GB SXM5)", gpu_description: "H100 SXM5 80GB",
      vram_gb: 80, price_cents_per_hour: 2399,
      specs: { vcpus: 208, memory_gib: 1800, storage_gib: 24000, gpus: 8 },
      regions: ["us-east-1"] },
    { name: "gpu_1x_gh200_preview", description: "1x GH200 (96 GB) — preview, unpriced",
      specs: { vcpus: 64, memory_gib: 432, storage_gib: 4000, gpus: 1 }, regions: ["us-east-3"] },
  ] }));

  // ── 1. Kind + source posture ladder ──
  const badKind = await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "lambdax", display_name: "nope" });
  const lm = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "lambda_cloud", display_name: `Lambda ${tag}` })).j.account || {};
  accountId = lm.account_id;
  ok("`lambda_cloud` account kind validates with honest GPU-VM capabilities (VM + ssh + persistent disk)",
    badKind.status === 422 && lm.account_ref?.startsWith("provider-account://")
    && lm.capabilities?.isolation === "gpu_vm"
    && lm.capabilities?.privacy === "cloud_vm_NOT_private"
    && /ordinary Linux GPU VM/.test(lm.capabilities?.vm_class || "")
    && /instance-lifetime/.test(lm.capabilities?.persistent_disk || "")
    && /evidence only/.test(lm.capabilities?.custody || "")
    && lm.provider_spend_borne_by === "customer");
  const s0 = await lambdaSource();
  ok("no credential → lambda_cloud source unavailable with evidence",
    s0.state === "candidate_source_unavailable" && /lambda_cloud_credential_absent/.test(s0.reason || ""));
  const SECRET = `LAMBDA-KEY-${tag}`;
  await jd("POST", `/v1/hypervisor/provider-accounts/${lm.account_id}/credential`, { api_key: SECRET });
  const pf = await jd("POST", `/v1/hypervisor/provider-accounts/${lm.account_id}/preflight`);
  ok("bearer binds sealed; verified but unfetched → credential_verified_unprobed (no supply claim)",
    pf.j.ok === true && !JSON.stringify(pf.j).includes(SECRET)
    && (await lambdaSource()).state === "credential_verified_unprobed");

  // ── 2. Degraded live fetch → zero fake quotes ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${lm.account_id}`, { endpoint: { mode: "live", endpoint: "http://127.0.0.1:9" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${lm.account_id}/preflight`);
  const intent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "compute.vm", resource_classes: ["compute.vm"], gpu: { required: true },
  })).j.intent || {};
  const degraded = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  ok("unreachable live endpoint → degraded_unreachable with evidence, zero fake quotes",
    (await lambdaSource()).state === "degraded_unreachable"
    && !(degraded.candidates || []).some((c) => c.provider_kind === "lambda_cloud")
    && (degraded.rejected || []).some((r) => r.reason_code === "candidate_source_degraded" && /lambda/.test(r.adapter_ref || "")));

  // ── 3. Fixture normalization: VM semantics preserved, advisory forever ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${lm.account_id}`, { endpoint: { mode: "fixture", fixture_file: typesFile } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${lm.account_id}/preflight`);
  const fixed = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const lmc = (fixed.candidates || []).filter((c) => c.provider_kind === "lambda_cloud");
  const a100 = lmc.find((c) => c.instance_type === "gpu_1x_a100_sxm4") || {};
  const h100 = lmc.find((c) => c.instance_type === "gpu_8x_h100_sxm5") || {};
  ok("fixture instance types normalize with VM semantics (cents→USD verbatim; unpriced SKIPPED; regions/disk preserved)",
    lmc.length === 2
    && a100.quote?.usd_per_hour === 1.29 && h100.quote?.usd_per_hour === 23.99
    && /price_cents_per_hour\/100|price_cents_per_hour \/ 100/.test(a100.quote?.basis || "")
    && (a100.regions || []).join() === "us-east-1,us-west-2"
    && a100.storage?.disk_gb === 512 && h100.gpu?.count === 8
    && a100.runtime_class === "compute.vm"
    && a100.source === "direct_provider" && /regions_with_capacity/.test(a100.region_note || ""));
  ok("fixture candidates stay advisory FOREVER (labelled, never placement-eligible)",
    lmc.every((c) => c.placement_eligible === "advisory_only" && c.evidence_mode === "fixture_evidence"
      && (c.risk_labels || []).includes("fixture_evidence_not_live_supply")));
  ok("every candidate is evidence-bound with VM custody honesty (native snapshots evidence-only; daemon roots restore truth)",
    lmc.every((c) => c.evidence?.adapter_ref === "adapter:lambda-quote" && c.evidence?.observed_at
      && c.evidence?.expires_at && c.custody_plan?.privacy === "cloud_vm_NOT_private"
      && (c.custody_plan?.supported_postures || []).join() === "Standard"
      && /EVIDENCE only/.test(c.custody_plan?.detail || "")
      && /state roots are restore truth/.test(c.custody_plan?.rule || "")));

  // ── 4. Guarded lifecycle over the REAL loopback SSH custody lane, boot-delayed ──
  const simEndpoint = { mode: "simulator", fixture_file: typesFile, simulate_boot_delay: true,
    ssh: { host: fixture.host, port: fixture.port, user: fixture.user, key_file: fixture.client_key_path } };
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${lm.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${lm.account_id}/preflight`);
  // Fixture-quote refusal FIRST — while the fixture batch is still active (a later refresh
  // supersedes it, which would fire the expired/superseded rung instead of the fixture rung).
  await jd("POST", "/v1/hypervisor/resource/budgets", { budget_id: "lambda-verify", name: "Lambda verify", scope: "external_spend", limit: 2, spent: 0, currency: "USD" });
  const fixCreate = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env, candidate_ref: a100.candidate_ref });
  const sim = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand = (sim.candidates || []).find((c) => c.provider_kind === "lambda_cloud" && c.instance_type === "gpu_1x_a100_sxm4") || {};
  const overMax = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env, candidate_ref: cand.candidate_ref, max_hourly_usd: 0.10 });
  ok("quote gate refuses fixture + over-max with lambda_cloud-named reasons",
    fixCreate.status === 409 && /lambda_cloud_quote_not_live/.test(fixCreate.j.reason || "")
    && overMax.status === 409 && /lambda_cloud_price_above_max/.test(overMax.j.reason || ""));
  // The wallet challenge must bind the VM SHAPE: capture the 403 before minting the grant.
  const createBase = { provider_id: accountId, op: "create", environment_ref: env,
    candidate_ref: cand.candidate_ref, max_hourly_usd: 1.3, region: "us-east-1", teardown_policy: "always_teardown_required" };
  const challenge = await jd("POST", "/v1/hypervisor/provider-ops", createBase);
  const facets = challenge.j.lease_request_facets || {};
  ok("wallet challenge binds the VM shape (candidate + quote + region + instance type + disk + teardown)",
    challenge.status === 403
    && facets.candidate_ref === cand.candidate_ref && facets.quote_ref === cand.quote_ref
    && facets.region === "us-east-1" && facets.instance_type === "gpu_1x_a100_sxm4"
    && facets.disk_gb === 512 && facets.teardown_policy === "always_teardown_required");
  const grant = mintApprovalGrant({ policyHash: challenge.j.approval.policy_hash, requestHash: challenge.j.approval.request_hash });
  const created = await jd("POST", "/v1/hypervisor/provider-ops", { ...createBase, wallet_approval_grant: grant });
  ok("grant-authorized create provisions the (simulated) VM with ssh UNKNOWN until boot — nothing persisted as ready",
    created.j.ok === true && created.j.evidence?.ssh_ready === false
    && String(created.j.evidence?.instance?.instance_id || "").startsWith("lmsim_")
    && created.j.evidence?.live_provisioning_not_run === true
    && created.j.evidence?.teardown_required === true
    && /no real Lambda VM exists/.test(created.j.evidence?.provider_native?.note || ""));
  const preBoot = await opWithGrant("workrun", { command: "echo too-early" });
  ok("pre-boot workrun fails CLOSED with lambda_ssh_bootstrap_unknown (ssh readiness is never assumed)",
    preBoot.j.ok === false && /lambda_ssh_bootstrap_unknown/.test(preBoot.j.reason || ""));
  const overBudget = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: `env-lm2-${tag}`, candidate_ref: cand.candidate_ref, max_hourly_usd: 1.3 });
  ok("external_spend reservation blocks the over-budget second create",
    overBudget.status === 409 && /lambda_cloud_budget_reservation_exceeded/.test(overBudget.j.reason || ""));
  const started = await opWithGrant("start");
  ok("start boot-polls and persists ssh ONLY with readiness evidence",
    started.j.ok === true && started.j.evidence?.ssh_ready === true
    && started.j.evidence?.boot_evidence?.proven_at
    && String(started.j.evidence?.boot_evidence?.ssh_host || "").length > 0);
  const marker = `lambda-${tag}`;
  const wr = await opWithGrant("workrun", { command: `echo ${marker} > vm.txt && cat vm.txt` });
  const snap = await opWithGrant("snapshot");
  const sev = snap.j.evidence || {};
  const restored = await opWithGrant("restore", { material_ref: sev.restore_material_ref });
  ok("workrun/snapshot/restore run the SAME custody contract as BYO SSH (daemon sha256 roots are restore truth)",
    wr.j.ok === true && String(wr.j.evidence?.stdout || "").includes(marker)
    && sev.custody === "daemon" && String(sev.state_root || "").startsWith("sha256:")
    && restored.j.evidence?.state_root_verified === sev.state_root);
  const stopped = await opWithGrant("stop");
  ok("stop is HONEST about VM billing (lambda has no native stop — spend accrues until teardown)",
    stopped.j.ok === true && stopped.j.evidence?.status === "workspace_stopped_vm_running"
    && /accruing customer-borne spend until teardown/.test(stopped.j.evidence?.spend_note || ""));
  const recon1 = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const exp = (recon1.rows || []).find((e) => e.account_ref === lm.account_ref && e.environment_ref === env) || {};
  ok("create opened a spend exposure exactly like Vast/RunPod (quote-backed, receipt-cited, customer-borne)",
    exp.status === "open" && exp.candidate_ref === cand.candidate_ref
    && exp.provider === "lambda_cloud" && (exp.receipt_refs || []).length >= 4
    && /evidence only/.test(exp.provider_native?.note || "")
    && /customer-borne/.test(exp.estimate_note || ""));
  const del = await opWithGrant("delete");
  const recon2 = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const expClosed = (recon2.rows || []).find((e) => e.exposure_ref === exp.exposure_ref) || {};
  ok("teardown tears down + closes the exposure and releases the reservation",
    del.j.ok === true && del.j.evidence?.teardown_state === "torn_down"
    && expClosed.status === "closed" && recon2.budget?.reserved_open_estimates === 0);

  // ── 5. Incomplete teardown → closed_with_warning (never silently closed) ──
  const env2 = `env-lm2-${tag}`;
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${lm.account_id}`, { endpoint: { ...simEndpoint, simulate_boot_delay: false, simulate_teardown_failure: true } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${lm.account_id}/preflight`);
  const sim2 = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand2 = (sim2.candidates || []).find((c) => c.provider_kind === "lambda_cloud" && c.instance_type === "gpu_1x_a100_sxm4") || {};
  await opWithGrant("create", { environment_ref: env2, candidate_ref: cand2.candidate_ref, max_hourly_usd: 1.3, region: "us-west-2" });
  const del2 = await opWithGrant("delete", { environment_ref: env2 });
  const recon3 = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const expWarn = (recon3.rows || []).find((e) => e.account_ref === lm.account_ref && e.environment_ref === env2) || {};
  ok("incomplete native teardown → exposure closed_with_warning naming the risk",
    del2.j.ok === true && expWarn.status === "closed_with_warning"
    && /INCOMPLETE TEARDOWN/.test(expWarn.warning || ""));

  // ── 6. Receipts / ledger / surfaces ──
  const receipts = ((await jd("GET", "/v1/hypervisor/provider-receipts")).j.receipts || [])
    .filter((r) => r.account_ref === lm.account_ref);
  ok("create/start/workrun/snapshot/restore/delete receipts exist with candidate/quote/lease enrichment",
    ["create", "start", "workrun", "snapshot", "restore", "stop", "delete"].every((o) => receipts.some((r) => r.op === o && r.outcome === "ok"))
    && receipts.some((r) => r.op === "create" && r.candidate_ref === cand.candidate_ref && !!r.capability_lease?.lease_id));
  const ledger = ((await jd("GET", "/v1/hypervisor/work-ledger")).j.entries || [])
    .filter((e) => e.kind === "provider_crossing" && e.account_ref === lm.account_ref);
  ok("Work Ledger provider crossings include Lambda refs + exposure backlink",
    ledger.some((e) => e.op === "create" && e.exposure_ref === exp.exposure_ref));
  const venues = (await jd("GET", "/v1/hypervisor/placement/venues")).j;
  const venueBlob = JSON.stringify(venues);
  ok("placement venues show the simple GPU VM lane DISTINCT from RunPod runtime cloud + Vast marketplace",
    /ordinary Linux \+ ssh \(Lambda-class\)/.test(venueBlob)
    && /instance-lifetime persistent local NVMe/.test(venueBlob)
    && /GPU runtime pods/.test(venueBlob) && /marketplace GPUs/.test(venueBlob));
  const opsHtml = await fetch(`${SHELL}/__ioi/operations`).then((r) => r.text());
  const envHtml = await fetch(`${SHELL}/__ioi/environments`).then((r) => r.text());
  ok("Operations + Environments show Lambda VM posture",
    /lambda/i.test(opsHtml) && envHtml.includes(lm.account_ref));

  // ── 7. Live-mode honesty + invariants ──
  if (LIVE_MODE && !LIVE_KEY) {
    ok("lambda_live_credentials_absent — IOI_LAMBDA_LIVE=1 requires IOI_LAMBDA_API_KEY; live execution BLOCKED (not faked)", false);
  } else if (!LIVE_MODE) {
    ok("live_provisioning_not_run — simulator validated the ladder; live Lambda execution is NOT claimed", true);
  }
  const audit = JSON.stringify({ recon3, sim }).toLowerCase();
  ok("no fee objects, no RoutingDecisionReceipt, no markup",
    !audit.includes("routingdecisionreceipt") && !audit.includes("fee_amount") && !audit.includes("markup\":"));
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);
}

async function cleanup() {
  try {
    if (accountId && env) {
      for (const e of [env, env.replace("env-lm-", "env-lm2-")]) {
        const obs = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "observe", environment_ref: e });
        if (obs.j?.evidence?.teardown_state === "live_or_pending") await opWithGrant("delete", { environment_ref: e });
      }
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
    console.log(`lambda gpu vm adapter readiness: ${fail ? "FAIL" : "OK"}${LIVE_MODE ? "" : " (live_provisioning_not_run)"}`);
    process.exit(fail ? 1 : 0);
  })
  .catch((e) => {
    console.error("verifier crashed:", e);
    process.exit(1);
  });
