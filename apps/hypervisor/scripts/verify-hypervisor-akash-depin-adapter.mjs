#!/usr/bin/env node
// Akash DePIN adapter done-bar — the first DePIN compute/GPU lane, and deliberately NOT a
// generic VM adapter: Akash semantics preserved end to end (deployment intent → SDL manifest →
// provider BIDS → LEASE → lease-assigned endpoints → logs/events → close → REDEPLOY). Bids are
// priced ONLY by source-quoted USD (native uakt/block carried as evidence, never converted);
// provider-native dseq/bid/lease ids are evidence only; deployment persistent storage is SDL
// posture, NEVER restore truth. The storage/archive custody plane closes the DePIN loop:
// simulated lease revocation → close → redeploy to a fresh bid → restore ONLY after daemon
// state_root + storage commitment validation. IOI_AKASH_LIVE=1 without IOI_AKASH_API_KEY
// BLOCKS with a named reason — never a fake pass.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-akash-depin-adapter.mjs

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
const BUDGET_FILE = path.join(DATA, "resource-budgets", "akash-verify.json");
const LIVE_MODE = process.env.IOI_AKASH_LIVE === "1";
const LIVE_KEY = process.env.IOI_AKASH_API_KEY || "";

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const akashSource = async () => {
  const s = (await jd("GET", "/v1/hypervisor/cloud-candidates/candidate-sources")).j;
  return (s.sources || []).find((x) => x.source === "depin_market") || {};
};

let accountId = null;
let env = null;
let casBackendId = null;
async function opWithGrant(o, extra = {}) {
  const base = { provider_id: accountId, op: o, environment_ref: extra.environment_ref || env, ...extra };
  const c = await jd("POST", "/v1/hypervisor/provider-ops", base);
  if (c.status !== 403) return c;
  const grant = mintApprovalGrant({ policyHash: c.j.approval.policy_hash, requestHash: c.j.approval.request_hash });
  return jd("POST", "/v1/hypervisor/provider-ops", { ...base, wallet_approval_grant: grant });
}
async function archiveOp(body) {
  const c = await jd("POST", "/v1/hypervisor/storage-archive-ops", body);
  if (c.status !== 403) return c;
  const grant = mintApprovalGrant({ policyHash: c.j.approval.policy_hash, requestHash: c.j.approval.request_hash });
  return jd("POST", "/v1/hypervisor/storage-archive-ops", { ...body, wallet_approval_grant: grant });
}

async function run() {
  const tag = Date.now().toString(16);
  env = `env-ak-${tag}`;
  rmSync(BUDGET_FILE, { force: true });
  const fixture = await ensureSshFixture();
  const dir = path.join(os.homedir(), ".ioi", "hypervisor", "vast-fixture");
  mkdirSync(dir, { recursive: true });
  const bidsFile = path.join(dir, `akash-bids-${tag}.json`);
  // REAL Akash bid shapes: per-provider offers, native uakt/block rates, source-quoted USD.
  // One bid carries NO source-quoted USD — it must be SKIPPED, never converted by the daemon.
  writeFileSync(bidsFile, JSON.stringify({ bids: [
    { provider: "akash1gpuprov4090xq", region: "us-west", attributes: { tier: "community", auditor: "none" },
      deployment_class: "compute.gpu_runtime",
      gpu: { model: "RTX 4090", count: 1, vram_gb: 24 },
      cpu_milli: 8000, memory_gb: 32, storage_gb: 200, persistent_storage: true,
      price: { uakt_per_block: 145, usd_per_hour_quoted: 0.38, rate_basis: "console-quoted USD (uakt × oracle rate at quote time)" } },
    { provider: "akash1cpuprovzz7e", region: "eu-central", attributes: { tier: "datacenter" },
      deployment_class: "compute.container",
      cpu_milli: 4000, memory_gb: 16, storage_gb: 100, persistent_storage: false,
      price: { uakt_per_block: 40, usd_per_hour_quoted: 0.11, rate_basis: "console-quoted USD (uakt × oracle rate at quote time)" } },
    { provider: "akash1unpricedbid", region: "ap-south",
      cpu_milli: 2000, memory_gb: 8, storage_gb: 50,
      price: { uakt_per_block: 99 } },
  ] }));

  // ── 1. Kind + source posture ladder ──
  const ak = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "akash", display_name: `Akash ${tag}` })).j.account || {};
  accountId = ak.account_id;
  ok("`akash` account kind validates with honest DePIN capabilities (deployment/bid/lease semantics, storage posture ≠ restore truth)",
    ak.account_ref?.startsWith("provider-account://")
    && ak.capabilities?.isolation === "deployment_lease"
    && /SDL manifest → provider bids → lease/.test(ak.capabilities?.deployment_model || "")
    && /NEVER restore truth/.test(ak.capabilities?.persistent_storage || "")
    && /evidence only/.test(ak.capabilities?.custody || "")
    && ak.capabilities?.privacy === "depin_host_NOT_private"
    && ak.provider_spend_borne_by === "customer");
  const s0 = await akashSource();
  ok("no credential → depin_market source unavailable with evidence",
    s0.state === "candidate_source_unavailable" && /akash_credential_absent/.test(s0.reason || ""));
  const SECRET = `AKASH-KEY-${tag}`;
  await jd("POST", `/v1/hypervisor/provider-accounts/${ak.account_id}/credential`, { api_key: SECRET });
  const pf = await jd("POST", `/v1/hypervisor/provider-accounts/${ak.account_id}/preflight`);
  ok("bearer binds sealed; verified but unfetched → credential_verified_unprobed (no supply claim)",
    pf.j.ok === true && !JSON.stringify(pf.j).includes(SECRET)
    && (await akashSource()).state === "credential_verified_unprobed");

  // ── 2. Degraded live fetch → zero fake bids ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${ak.account_id}`, { endpoint: { mode: "live", endpoint: "http://127.0.0.1:9" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${ak.account_id}/preflight`);
  const intent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "compute.gpu_runtime", resource_classes: ["compute.gpu_runtime", "compute.container"], gpu: { required: true },
  })).j.intent || {};
  const degraded = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  ok("unreachable live endpoint → degraded_unreachable with evidence, zero fake bids",
    (await akashSource()).state === "degraded_unreachable"
    && !(degraded.candidates || []).some((c) => c.provider_kind === "akash")
    && (degraded.rejected || []).some((r) => r.reason_code === "candidate_source_degraded" && /akash/.test(r.adapter_ref || "")));

  // ── 3. Fixture normalization: DePIN bid/lease semantics preserved, advisory forever ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${ak.account_id}`, { endpoint: { mode: "fixture", fixture_file: bidsFile } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${ak.account_id}/preflight`);
  const fixed = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const akc = (fixed.candidates || []).filter((c) => c.provider_kind === "akash");
  const gpuBid = akc.find((c) => c.provider_address === "akash1gpuprov4090xq") || {};
  ok("fixture bids normalize with bid/lease/deployment semantics (source-quoted USD verbatim; native uakt evidence; unpriced SKIPPED)",
    akc.length === 2
    && gpuBid.quote?.usd_per_hour === 0.38
    && gpuBid.quote?.native_rate?.uakt_per_block === 145
    && /never converted by the daemon/.test(gpuBid.quote?.native_rate?.note || "")
    && gpuBid.deployment_class === "compute.gpu_runtime"
    && gpuBid.bid_ref?.startsWith("akash-bid-offer://")
    && gpuBid.source === "depin_market" && gpuBid.adapter_ref === "adapter:akash-bid"
    && gpuBid.storage?.persistent_storage === true
    && /NEVER restore truth/.test(gpuBid.storage?.posture || "")
    && /LEASE-ASSIGNED/.test(gpuBid.network?.ports_posture || ""));
  ok("DePIN risks are named on every bid; fixture candidates stay advisory FOREVER",
    akc.every((c) => (c.risk_labels || []).includes("depin_provider_variability")
      && (c.risk_labels || []).includes("bid_lease_revocation")
      && (c.risk_labels || []).includes("deployment_storage_not_restore_truth")
      && c.placement_eligible === "advisory_only" && c.evidence_mode === "fixture_evidence"
      && (c.risk_labels || []).includes("fixture_evidence_not_live_supply")));

  // ── 4. Guarded lifecycle: quote gate, wallet binding, simulator deployment ──
  const simEndpoint = { mode: "simulator", fixture_file: bidsFile,
    ssh: { host: fixture.host, port: fixture.port, user: fixture.user, key_file: fixture.client_key_path } };
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${ak.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${ak.account_id}/preflight`);
  await jd("POST", "/v1/hypervisor/resource/budgets", { budget_id: "akash-verify", name: "Akash verify", scope: "external_spend", limit: 1, spent: 0, currency: "USD" });
  // Fixture-quote refusal FIRST — while the fixture batch is still active.
  const fixCreate = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env, candidate_ref: gpuBid.candidate_ref });
  const sim = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand = (sim.candidates || []).find((c) => c.provider_kind === "akash" && c.provider_address === "akash1gpuprov4090xq") || {};
  const overMax = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env, candidate_ref: cand.candidate_ref, max_hourly_usd: 0.10 });
  ok("quote gate refuses fixture + over-max with akash-named reasons",
    fixCreate.status === 409 && /akash_quote_not_live/.test(fixCreate.j.reason || "")
    && overMax.status === 409 && /akash_price_above_max/.test(overMax.j.reason || ""));
  const createBase = { provider_id: accountId, op: "create", environment_ref: env,
    candidate_ref: cand.candidate_ref, max_hourly_usd: 0.4, teardown_policy: "always_teardown_required" };
  const challenge = await jd("POST", "/v1/hypervisor/provider-ops", createBase);
  const facets = challenge.j.lease_request_facets || {};
  ok("wallet challenge binds the DEPLOYMENT SPEC + bid/lease + spend posture (SDL hash, provider, bid, persistence, rate cap)",
    challenge.status === 403
    && facets.candidate_ref === cand.candidate_ref && facets.quote_ref === cand.quote_ref
    && facets.deployment_class === "compute.gpu_runtime"
    && facets.provider_address === "akash1gpuprov4090xq"
    && facets.bid_ref === cand.bid_ref
    && String(facets.sdl_hash || "").startsWith("sha256:")
    && facets.persistent_storage === true
    && facets.max_hourly_usd === 0.4 && facets.teardown_policy === "always_teardown_required");
  const grant = mintApprovalGrant({ policyHash: challenge.j.approval.policy_hash, requestHash: challenge.j.approval.request_hash });
  const created = await jd("POST", "/v1/hypervisor/provider-ops", { ...createBase, wallet_approval_grant: grant });
  const dep1Ref = created.j.evidence?.deployment?.deployment_ref || "";
  ok("grant-authorized create mints deployment+bid+lease records with endpoint UNKNOWN until readiness",
    created.j.ok === true
    && dep1Ref.startsWith("akash-deployment://")
    && String(created.j.evidence?.deployment?.dseq || "").startsWith("simdseq_")
    && String(created.j.evidence?.bid_ref || "").startsWith("akash-bid://")
    && String(created.j.evidence?.lease_ref || "").startsWith("akash-lease://")
    && created.j.evidence?.endpoint_ready === false
    && created.j.evidence?.live_provisioning_not_run === true
    && created.j.evidence?.teardown_required === true
    && /no real Akash deployment exists/.test(created.j.evidence?.provider_native?.note || ""));
  const preEndpoint = await opWithGrant("workrun", { command: "echo too-early" });
  ok("pre-endpoint exec fails CLOSED with akash_endpoint_unready (endpoints are proven, never assumed)",
    preEndpoint.j.ok === false && /akash_endpoint_unready/.test(preEndpoint.j.reason || ""));
  const overBudget = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: `env-ak2-${tag}`, candidate_ref: cand.candidate_ref, max_hourly_usd: 0.7 });
  ok("external_spend reservation blocks the over-budget second lease",
    overBudget.status === 409 && /akash_budget_reservation_exceeded/.test(overBudget.j.reason || ""));
  const started = await opWithGrant("start");
  ok("start waits for lease endpoint readiness — IP/ports recorded as EVIDENCE, not authority",
    started.j.ok === true && started.j.evidence?.endpoint_ready === true
    && String(started.j.evidence?.endpoint?.endpoint_ref || "").startsWith("akash-endpoint://")
    && (started.j.evidence?.endpoint?.ports || []).some((p) => p.service === "ssh")
    && /EVIDENCE, not authority/.test(started.j.evidence?.endpoint?.authority_note || ""));

  // ── 5. Exec / logs / events over the SDL-declared ssh service ──
  const marker = `akash-${tag}`;
  const wr = await opWithGrant("workrun", { command: `echo ${marker} > lease.txt && cat lease.txt` });
  const logs = await opWithGrant("logs");
  const events = await opWithGrant("events");
  const eventKinds = (events.j.evidence?.events || []).map((e) => e.kind);
  ok("exec runs through the SDL-declared ssh service; logs/events return provider evidence honestly",
    wr.j.ok === true && String(wr.j.evidence?.stdout || "").includes(marker)
    && logs.j.ok === true && /unavailable_in_simulator/.test(logs.j.evidence?.service_logs || "")
    && (logs.j.evidence?.control_plane_log || []).length >= 3
    && ["deployment_created", "bid_selected", "lease_opened", "endpoint_ready"].every((k) => eventKinds.includes(k)));
  const stopped = await opWithGrant("stop");
  ok("stop is HONEST about lease billing (akash leases bill until CLOSED)",
    stopped.j.ok === true && stopped.j.evidence?.status === "workspace_stopped_lease_open"
    && /bill until closed/.test(stopped.j.evidence?.spend_note || ""));
  await opWithGrant("start");

  // ── 6. Snapshot → storage-plane archive; exposure open ──
  const snap = await opWithGrant("snapshot");
  const sev = snap.j.evidence || {};
  const materialRef = sev.restore_material_ref || "";
  const stateRoot = sev.state_root || "";
  const cas = (await jd("POST", "/v1/hypervisor/storage-backends", { kind: "cas", display_name: `Akash CAS ${tag}` })).j.backend || {};
  casBackendId = cas.account_id;
  await jd("POST", `/v1/hypervisor/storage-backends/${cas.account_id}/preflight`);
  const exported = await archiveOp({ op: "export", backend_id: cas.account_id, material_ref: materialRef });
  const archiveRef = exported.j.archive?.archive_ref || "";
  ok("snapshot admits daemon custody; archive export seals to the storage plane (commitment recorded)",
    sev.custody === "daemon" && stateRoot.startsWith("sha256:")
    && exported.j.ok === true && archiveRef.startsWith("storage-archive://")
    && exported.j.archive?.state_root === stateRoot);
  const recon1 = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const exp1 = (recon1.rows || []).find((e) => e.account_ref === ak.account_ref && e.environment_ref === env) || {};
  ok("priced lease opened a customer-borne spend exposure (quote-backed, receipt-cited)",
    exp1.status === "open" && exp1.provider === "akash"
    && exp1.usd_per_hour === 0.38 && /customer-borne/.test(exp1.estimate_note || ""));

  // ── 7. DePIN loss → close → REDEPLOY → restore elsewhere (storage-validated) ──
  const outage = await opWithGrant("inject_outage");
  ok("simulated provider-side lease revocation — the bid_lease_revocation risk, exercised",
    outage.j.ok === true && outage.j.evidence?.lease_state === "closed_by_provider"
    && outage.j.evidence?.workspace_lost === true && outage.j.evidence?.simulated === true);
  const del1 = await opWithGrant("delete");
  const recon2 = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const exp1closed = (recon2.rows || []).find((e) => e.exposure_ref === exp1.exposure_ref) || {};
  ok("close confirms teardown (idempotent over the revoked lease) and closes the exposure",
    del1.j.ok === true && del1.j.evidence?.teardown_state === "torn_down"
    && exp1closed.status === "closed" && recon2.budget?.reserved_open_estimates === 0);
  const sim2 = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand2 = (sim2.candidates || []).find((c) => c.provider_kind === "akash" && c.provider_address === "akash1gpuprov4090xq") || {};
  const redeployBase = { provider_id: accountId, op: "redeploy", environment_ref: env,
    candidate_ref: cand2.candidate_ref, max_hourly_usd: 0.4, teardown_policy: "always_teardown_required",
    restore_material_ref: materialRef, archive_ref: archiveRef };
  const rchallenge = await jd("POST", "/v1/hypervisor/provider-ops", redeployBase);
  const rfacets = rchallenge.j.lease_request_facets || {};
  const rgrant = mintApprovalGrant({ policyHash: rchallenge.j.approval.policy_hash, requestHash: rchallenge.j.approval.request_hash });
  const redeployed = await jd("POST", "/v1/hypervisor/provider-ops", { ...redeployBase, wallet_approval_grant: rgrant });
  const dep2Ref = redeployed.j.evidence?.deployment?.deployment_ref || "";
  ok("REDEPLOY mints a fresh deployment/lease with lineage — the wallet challenge binds the restore refs",
    rchallenge.status === 403
    && rfacets.restore_material_ref === materialRef && rfacets.archive_ref === archiveRef
    && redeployed.j.ok === true && dep2Ref.startsWith("akash-deployment://") && dep2Ref !== dep1Ref
    && redeployed.j.evidence?.redeployed_from === dep1Ref
    && String(redeployed.j.evidence?.redeploy_plan_ref || "").startsWith("akash-redeploy-plan://"));
  await opWithGrant("start");
  const storageRestore = await archiveOp({ op: "restore", archive_ref: archiveRef });
  const restored = await opWithGrant("restore", { material_ref: materialRef });
  const wr2 = await opWithGrant("workrun", { command: "cat lease.txt" });
  ok("restore elsewhere validates daemon state_root + storage commitment — the marker survives the lease loss",
    storageRestore.j.ok === true && storageRestore.j.state_root_verified === stateRoot
    && restored.j.ok === true && restored.j.evidence?.state_root_verified === stateRoot
    && wr2.j.ok === true && String(wr2.j.evidence?.stdout || "").includes(marker));
  const depin = (await jd("GET", "/v1/hypervisor/akash-deployments")).j;
  const plan = (depin.redeploy_plans || []).find((r) => r.new_deployment_ref === dep2Ref) || {};
  ok("AkashRedeployPlan binds old → new deployment + restore refs; provider-native ids stay evidence only",
    plan.old_deployment_ref === dep1Ref && plan.archive_ref === archiveRef
    && /never restore truth/.test(plan.note || "")
    && /never restore or billing truth/.test((depin.deployments || []).find((d) => d.deployment_ref === dep2Ref)?.provider_native?.note || "")
    && /evidence only/.test(((depin.leases || [])[0] || {}).note || ""));

  // ── 8. Warned teardown + surfaces + live honesty + invariants ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${ak.account_id}`, { endpoint: { ...simEndpoint, simulate_teardown_failure: true } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${ak.account_id}/preflight`);
  const del2 = await opWithGrant("delete");
  const recon3 = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const exp2warn = (recon3.rows || []).find((e) => e.account_ref === ak.account_ref && e.environment_ref === env && e.status !== "closed") || {};
  ok("failed lease close → exposure closed_with_warning naming the still-accruing risk",
    del2.j.ok === true && exp2warn.status === "closed_with_warning"
    && /INCOMPLETE TEARDOWN/.test(exp2warn.warning || ""));
  const ledger = ((await jd("GET", "/v1/hypervisor/work-ledger")).j.entries || [])
    .filter((e) => e.kind === "provider_crossing" && e.account_ref === ak.account_ref);
  ok("Work Ledger provider crossings include the Akash lifecycle (create + redeploy) with exposure backlinks",
    ledger.some((e) => e.op === "create" && e.exposure_ref === exp1.exposure_ref)
    && ledger.some((e) => e.op === "redeploy" && !!e.exposure_ref));
  const opsHtml = await fetch(`${SHELL}/__ioi/operations`).then((r) => r.text());
  const venues = JSON.stringify((await jd("GET", "/v1/hypervisor/placement/venues")).j);
  ok("Operations shows DePIN deployments; placement venues show the Akash lane distinct from VM/runtime/marketplace",
    opsHtml.includes('id="ops-akash-depin"') && /DePIN deployments \(Akash\)/.test(opsHtml)
    && /SDL → bids → lease/.test(venues) && /lease-assigned IP\/ports \(evidence, not authority\)/.test(venues));
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${ak.account_id}`, { endpoint: { mode: "live", endpoint: "http://127.0.0.1:9" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${ak.account_id}/preflight`);
  const liveCreate = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: `env-ak3-${tag}`, candidate_ref: cand2.candidate_ref, max_hourly_usd: 0.4 });
  ok("live mode blocks NAMED — live provisioning demands live quotes/config, never a fake deployment",
    liveCreate.status === 409 && /akash_quote_mode_mismatch|akash_quote_expired_requires_requote/.test(liveCreate.j.reason || ""));
  if (LIVE_MODE && !LIVE_KEY) {
    ok("akash_live_credentials_absent — IOI_AKASH_LIVE=1 requires IOI_AKASH_API_KEY; live execution BLOCKED (not faked)", false);
  } else if (!LIVE_MODE) {
    ok("live_provisioning_not_run — simulator validated the DePIN ladder; live Akash execution is NOT claimed", true);
  }
  const audit = JSON.stringify({ recon3, sim2, depin }).toLowerCase();
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
  if (casBackendId) await jd("DELETE", `/v1/hypervisor/storage-backends/${casBackendId}`);
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
    console.log(`akash depin adapter readiness: ${fail ? "FAIL" : "OK"}${LIVE_MODE ? "" : " (live_provisioning_not_run)"}`);
    process.exit(fail ? 1 : 0);
  })
  .catch((e) => {
    console.error("verifier crashed:", e);
    process.exit(1);
  });
