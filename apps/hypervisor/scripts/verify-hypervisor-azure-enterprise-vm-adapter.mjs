#!/usr/bin/env node
// Azure enterprise VM adapter done-bar — the third ENTERPRISE hyperscaler lane and the first
// fully NEW account kind, with AZURE SEMANTICS preserved (never AWS/GCP names): service-
// principal sealed credentials (tenant/client/subscription posture in aux — never leaked),
// SUBSCRIPTION/RESOURCE GROUP/LOCATION scoping, VM sizes, managed OS disks, VNet/subnet/NSG
// posture, and REAL Azure billing semantics: a merely-STOPPED VM keeps billing compute; only
// DEALLOCATED halts compute billing (managed disks bill until delete) — the stop op
// deallocates and SAYS so. Private-only or NSG-denied postures fail CLOSED with Azure-named
// reasons — provisioning state alone is never readiness. IOI_AZURE_LIVE=1 without credentials
// BLOCKS named.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-azure-enterprise-vm-adapter.mjs

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
const BUDGET_FILE = path.join(DATA, "resource-budgets", "azure-verify.json");
const LIVE_MODE = process.env.IOI_AZURE_LIVE === "1";
const LIVE_KEY = process.env.IOI_AZURE_CLIENT_SECRET || "";

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const azureSource = async () => {
  const s = (await jd("GET", "/v1/hypervisor/cloud-candidates/candidate-sources")).j;
  return (s.sources || []).find((x) => x.source === "azure") || {};
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
  env = `env-az-${tag}`;
  rmSync(BUDGET_FILE, { force: true });
  const fixture = await ensureSshFixture();
  const dir = path.join(os.homedir(), ".ioi", "hypervisor", "vast-fixture");
  mkdirSync(dir, { recursive: true });
  const offersFile = path.join(dir, `azure-offers-${tag}.json`);
  // REAL Azure VM offer shapes: subscription/RG/location scoping, VM sizes, managed OS disks,
  // VNet/NSG posture, verbatim pay-as-you-go rates. One offer unpriced — SKIPPED.
  writeFileSync(offersFile, JSON.stringify({ vm_size_offers: [
    { subscription_id: "sim-subscription", resource_group: "sim-rg", location: "eastus2",
      vm_size: "Standard_NC24ads_A100_v4", vcpu: 24, memory_gb: 220,
      gpu: { model: "A100", count: 1, vram_gb: 80 },
      os_disk: { gb: 128, sku: "Premium_LRS" },
      network: { vnet: "default", nsg_ssh_allowed: true, public_ip_supported: true },
      usd_per_hour: 3.673, pricing_basis: "Azure pay-as-you-go rate card (verbatim)" },
    { subscription_id: "sim-subscription", resource_group: "sim-rg", location: "westeurope",
      vm_size: "Standard_D4s_v5", vcpu: 4, memory_gb: 16,
      os_disk: { gb: 64, sku: "StandardSSD_LRS" },
      network: { vnet: "default", nsg_ssh_allowed: true, public_ip_supported: true },
      usd_per_hour: 0.192, pricing_basis: "Azure pay-as-you-go rate card (verbatim)" },
    { subscription_id: "sim-subscription", resource_group: "sim-rg", location: "eastus2",
      vm_size: "Standard_ND96isr_H100_v5", vcpu: 96, memory_gb: 1900,
      gpu: { model: "H100", count: 8, vram_gb: 80 },
      os_disk: { gb: 4096, sku: "Premium_LRS" },
      network: { vnet: "default", nsg_ssh_allowed: true, public_ip_supported: true } },
  ] }));

  // ── 1. NEW kind + service-principal credential + source posture ladder ──
  const az = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "azure", display_name: `Azure ${tag}` })).j.account || {};
  accountId = az.account_id;
  ok("`azure` account kind validates (first fully NEW enterprise kind) with honest capabilities (ARM authority, RG/location, NSG posture, deallocate honesty)",
    az.account_ref?.startsWith("provider-account://")
    && /ENTERPRISE customer-cloud/.test(az.capabilities?.lane || "")
    && /service-principal \/ managed-identity over Azure Resource Manager/.test(az.capabilities?.authority_model || "")
    && /RESOURCE GROUP/.test(az.capabilities?.scoping || "")
    && /NSG/.test(az.capabilities?.network_posture || "")
    && /only DEALLOCATED halts compute billing/.test(az.capabilities?.instance_lifecycle || "")
    && /EVIDENCE only/.test(az.capabilities?.volumes || "")
    && az.provider_spend_borne_by === "customer");
  const s0 = await azureSource();
  ok("no credential → azure source unavailable with evidence",
    s0.state === "candidate_source_unavailable" && /azure_credential_absent/.test(s0.reason || ""));
  const SECRET = `AZ-SP-SECRET-${tag}`;
  const TENANT = `tenant-${tag}`;
  const bind = await jd("POST", `/v1/hypervisor/provider-accounts/${az.account_id}/credential`, {
    client_secret: SECRET,
    aux: { tenant_id: TENANT, client_id: "sp-client-id", subscription_id: "sim-subscription", resource_group: "sim-rg", location: "eastus2" },
  });
  const pf = await jd("POST", `/v1/hypervisor/provider-accounts/${az.account_id}/preflight`);
  ok("service-principal credential binds SEALED as azure-service-principal — client secret never leaks; tenant/client posture kept as aux",
    bind.j.ok !== false && bind.j.credential?.kind === "azure-service-principal"
    && bind.j.credential?.sealed === true
    && !JSON.stringify(bind.j).includes(SECRET)
    && pf.j.ok === true && !JSON.stringify(pf.j).includes(SECRET)
    && (await azureSource()).state === "credential_verified_unprobed");

  // ── 2. Degraded live fetch → zero fake offers ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${az.account_id}`, { endpoint: { mode: "live", endpoint: "http://127.0.0.1:9" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${az.account_id}/preflight`);
  const intent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "compute.vm", resource_classes: ["compute.vm", "compute.gpu_runtime"],
  })).j.intent || {};
  const degraded = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  ok("unreachable live pricing feed → degraded_unreachable with evidence, zero fake offers",
    (await azureSource()).state === "degraded_unreachable"
    && !(degraded.candidates || []).some((c) => c.provider_kind === "azure")
    && (degraded.rejected || []).some((r) => r.reason_code === "candidate_source_degraded" && /azure/.test(r.adapter_ref || "")));

  // ── 3. Fixture normalization: Azure semantics preserved, advisory forever ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${az.account_id}`, { endpoint: { mode: "fixture", fixture_file: offersFile } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${az.account_id}/preflight`);
  const fixed = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const azc = (fixed.candidates || []).filter((c) => c.provider_kind === "azure");
  const nc24 = azc.find((c) => c.vm_size === "Standard_NC24ads_A100_v4") || {};
  ok("fixture offers normalize with Azure semantics (subscription/RG/location/VM size/managed disk/NSG posture; verbatim rate; unpriced SKIPPED)",
    azc.length === 2
    && nc24.quote?.usd_per_hour === 3.673 && nc24.subscription_id === "sim-subscription"
    && nc24.resource_group === "sim-rg" && nc24.location === "eastus2"
    && nc24.gpu?.model === "A100"
    && nc24.storage?.disk_gb === 128 && nc24.storage?.volume_type === "Premium_LRS"
    && /managed OS disk/.test(nc24.storage?.posture || "")
    && nc24.network?.nsg_ssh_allowed === true
    && /NSG allow rule/.test(nc24.network?.ports_posture || "")
    && nc24.source === "direct_provider" && nc24.adapter_ref === "adapter:azure-vm-quote");
  ok("risk labels are AZURE-shaped (Entra/NSG/managed disk) — never AWS/GCP or marketplace labels; advisory forever",
    azc.every((c) => (c.risk_labels || []).includes("entra_service_principal_scope_dependent")
      && (c.risk_labels || []).includes("nsg_ssh_ingress_required")
      && (c.risk_labels || []).includes("managed_disk_native_snapshots_evidence_only")
      && !(c.risk_labels || []).includes("iam_scope_dependent")
      && !(c.risk_labels || []).includes("iam_service_account_scope_dependent")
      && !(c.risk_labels || []).includes("depin_provider_variability")
      && c.placement_eligible === "advisory_only" && c.evidence_mode === "fixture_evidence"));

  // ── 4. Guarded lifecycle: quote gate, wallet facets, simulator ARM ──
  const simEndpoint = { mode: "simulator", fixture_file: offersFile,
    subscription_id: "sim-subscription", location: "eastus2",
    ssh: { host: fixture.host, port: fixture.port, user: fixture.user, key_file: fixture.client_key_path } };
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${az.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${az.account_id}/preflight`);
  await jd("POST", "/v1/hypervisor/resource/budgets", { budget_id: "azure-verify", name: "Azure verify", scope: "external_spend", limit: 10, spent: 0, currency: "USD" });
  const fixCreate = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env, candidate_ref: nc24.candidate_ref });
  const sim = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand = (sim.candidates || []).find((c) => c.provider_kind === "azure" && c.vm_size === "Standard_NC24ads_A100_v4") || {};
  const overMax = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env, candidate_ref: cand.candidate_ref, max_hourly_usd: 0.10 });
  ok("quote gate refuses fixture + over-max with azure-named reasons",
    fixCreate.status === 409 && /azure_quote_not_live/.test(fixCreate.j.reason || "")
    && overMax.status === 409 && /azure_price_above_max/.test(overMax.j.reason || ""));
  const createBase = { provider_id: accountId, op: "create", environment_ref: env,
    candidate_ref: cand.candidate_ref, max_hourly_usd: 4.0, teardown_policy: "always_teardown_required" };
  const challenge = await jd("POST", "/v1/hypervisor/provider-ops", createBase);
  const facets = challenge.j.lease_request_facets || {};
  ok("wallet challenge binds AZURE-specific facets (subscription + resource group + location + VM size + disk + VNet/NSG posture + teardown)",
    challenge.status === 403
    && facets.candidate_ref === cand.candidate_ref
    && facets.subscription_id === "sim-subscription" && facets.resource_group === "sim-rg"
    && facets.location === "eastus2" && facets.vm_size === "Standard_NC24ads_A100_v4" && facets.disk_gb === 128
    && facets.network_posture?.posture_label === "default_vnet_simulator"
    && facets.network_posture?.public_ip === true && facets.network_posture?.ssh_ingress === true
    && facets.teardown_policy === "always_teardown_required");
  const grant = mintApprovalGrant({ policyHash: challenge.j.approval.policy_hash, requestHash: challenge.j.approval.request_hash });
  const created = await jd("POST", "/v1/hypervisor/provider-ops", { ...createBase, wallet_approval_grant: grant });
  ok("grant-authorized create provisions the (simulated) VM — ssh UNKNOWN, ARM resource + managed disk evidence-only",
    created.j.ok === true
    && String(created.j.evidence?.instance?.vm_name || "").startsWith("sim-vm-")
    && created.j.evidence?.ssh_ready === false
    && created.j.evidence?.live_provisioning_not_run === true
    && created.j.evidence?.teardown_required === true
    && String(created.j.evidence?.os_disk?.disk_name || "").startsWith("sim-osdisk-")
    && /evidence only/.test(created.j.evidence?.os_disk?.note || "")
    && /^\/subscriptions\/sim-subscription\/resourceGroups\/sim-rg\/providers\/Microsoft.Compute\/virtualMachines\//.test(created.j.evidence?.provider_native?.resource_id || "")
    && /no real Azure VM exists/.test(created.j.evidence?.provider_native?.note || ""));
  const preBoot = await opWithGrant("workrun", { command: "echo too-early" });
  ok("pre-boot workrun fails CLOSED with azure_ssh_bootstrap_unknown (provisioning state alone is never readiness)",
    preBoot.j.ok === false && /azure_ssh_bootstrap_unknown/.test(preBoot.j.reason || ""));
  const overBudget = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: `env-az2-${tag}`, candidate_ref: cand.candidate_ref, max_hourly_usd: 7.0 });
  ok("external_spend reservation blocks the over-budget second create",
    overBudget.status === 409 && /azure_budget_reservation_exceeded/.test(overBudget.j.reason || ""));
  const started = await opWithGrant("start");
  ok("start boot-polls and persists ssh ONLY with readiness evidence through the reachable VNet/NSG posture",
    started.j.ok === true && started.j.evidence?.ssh_ready === true
    && started.j.evidence?.boot_evidence?.proven_at
    && started.j.evidence?.boot_evidence?.posture?.posture_label === "default_vnet_simulator"
    && /'VM running' state alone was not treated as readiness/.test(started.j.evidence?.boot_evidence?.note || ""));

  // ── 5. Workrun / snapshot (managed-disk evidence) / restore / DEALLOCATE / start / restart ──
  const marker = `azure-${tag}`;
  const wr = await opWithGrant("workrun", { command: `echo ${marker} > vm.txt && cat vm.txt` });
  const snap = await opWithGrant("snapshot");
  const sev = snap.j.evidence || {};
  const restored = await opWithGrant("restore", { material_ref: sev.restore_material_ref });
  ok("workrun/snapshot/restore run the BYO custody contract — managed-disk-style native snapshot rides as EVIDENCE ONLY",
    wr.j.ok === true && String(wr.j.evidence?.stdout || "").includes(marker)
    && sev.custody === "daemon" && String(sev.state_root || "").startsWith("sha256:")
    && String(sev.provider_native_snapshot?.snapshot_name || "").startsWith("sim-snapshot-")
    && /NEVER restore truth/.test(sev.provider_native_snapshot?.note || "")
    && restored.j.evidence?.state_root_verified === sev.state_root);
  const stopped = await opWithGrant("stop");
  const reconStopped = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const expOpen = (reconStopped.rows || []).find((e) => e.account_ref === az.account_ref && e.environment_ref === env) || {};
  ok("stop is HONEST Azure semantics: DEALLOCATED (not merely stopped) — compute halts ONLY because deallocated; disks keep billing; exposure stays OPEN",
    stopped.j.ok === true && stopped.j.evidence?.status === "VM deallocated"
    && stopped.j.evidence?.deallocated === true
    && /merely-stopped VM keeps billing compute/.test(stopped.j.evidence?.spend_note || "")
    && /managed disks keep billing until delete/.test(stopped.j.evidence?.spend_note || "")
    && expOpen.status === "open");
  const restarted2 = await opWithGrant("start");
  const reset = await opWithGrant("restart");
  const wrAfter = await opWithGrant("workrun", { command: "cat vm.txt" });
  const events = await opWithGrant("events");
  const eventKinds = (events.j.evidence?.events || []).map((e) => e.kind);
  ok("start-from-deallocated + restart (in-place, endpoint retained) work; lifecycle events recorded",
    restarted2.j.ok === true && reset.j.ok === true
    && /endpoint retained/.test(reset.j.evidence?.note || "")
    && wrAfter.j.ok === true && String(wrAfter.j.evidence?.stdout || "").includes(marker)
    && ["vm_create_accepted", "boot_proven", "vm_deallocated", "vm_started", "vm_restarted"].every((k) => eventKinds.includes(k)));

  // ── 6. Delete + warn path ──
  const del1 = await opWithGrant("delete");
  const recon2 = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const exp1closed = (recon2.rows || []).find((e) => e.exposure_ref === expOpen.exposure_ref) || {};
  ok("delete always — managed OS disk deletes with the VM; exposure closes and the reservation releases",
    del1.j.ok === true && del1.j.evidence?.teardown_state === "torn_down"
    && /managed OS disk deleted with the VM/.test(del1.j.evidence?.native_teardown?.note || "")
    && exp1closed.status === "closed" && recon2.budget?.reserved_open_estimates === 0);
  const env2 = `env-az2-${tag}`;
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${az.account_id}`, { endpoint: { ...simEndpoint, simulate_teardown_failure: true } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${az.account_id}/preflight`);
  const sim2 = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand2 = (sim2.candidates || []).find((c) => c.provider_kind === "azure" && c.vm_size === "Standard_NC24ads_A100_v4") || {};
  await opWithGrant("create", { environment_ref: env2, candidate_ref: cand2.candidate_ref, max_hourly_usd: 4.0 });
  const del2 = await opWithGrant("delete", { environment_ref: env2 });
  const recon3 = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const exp2warn = (recon3.rows || []).find((e) => e.account_ref === az.account_ref && e.environment_ref === env2) || {};
  ok("failed delete → exposure closed_with_warning naming the still-accruing compute/disk risk",
    del2.j.ok === true && exp2warn.status === "closed_with_warning"
    && /INCOMPLETE TEARDOWN/.test(exp2warn.warning || ""));

  // ── 7. VNet/NSG honesty: NSG-denied posture fails CLOSED ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${az.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${az.account_id}/preflight`);
  const env3 = `env-az3-${tag}`;
  const sim3 = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand3 = (sim3.candidates || []).find((c) => c.provider_kind === "azure" && c.vm_size === "Standard_D4s_v5") || {};
  const nsgBase = { provider_id: accountId, op: "create", environment_ref: env3,
    candidate_ref: cand3.candidate_ref, max_hourly_usd: 0.3,
    network: { vnet: "prod-vnet", subnet: "private-subnet", nsg: "locked-nsg", public_ip: true, ssh_ingress: false } };
  const nsgChallenge = await jd("POST", "/v1/hypervisor/provider-ops", nsgBase);
  const nsgFacets = nsgChallenge.j.lease_request_facets || {};
  const nsgGrant = mintApprovalGrant({ policyHash: nsgChallenge.j.approval.policy_hash, requestHash: nsgChallenge.j.approval.request_hash });
  const nsgCreated = await jd("POST", "/v1/hypervisor/provider-ops", { ...nsgBase, wallet_approval_grant: nsgGrant });
  const nsgStart = await opWithGrant("start", { environment_ref: env3 });
  ok("explicit VNet/NSG config binds in facets; NSG-denied SSH fails CLOSED at boot naming the NSG (never fake-ready)",
    nsgFacets.network_posture?.posture_label === "explicit_vnet_config"
    && nsgFacets.network_posture?.vnet === "prod-vnet"
    && nsgFacets.network_posture?.ssh_ingress === false
    && nsgCreated.j.ok === true
    && nsgStart.j.ok === false && /azure_ssh_ingress_unreachable/.test(nsgStart.j.reason || "")
    && /NSG/.test(nsgStart.j.reason || ""));
  await opWithGrant("delete", { environment_ref: env3 });

  // ── 8. Surfaces + live honesty + invariants ──
  const ledger = ((await jd("GET", "/v1/hypervisor/work-ledger")).j.entries || [])
    .filter((e) => e.kind === "provider_crossing" && e.account_ref === az.account_ref);
  ok("Work Ledger provider crossings include the Azure lifecycle with exposure backlinks",
    ledger.some((e) => e.op === "create" && e.exposure_ref === expOpen.exposure_ref)
    && ledger.some((e) => e.op === "restart"));
  const opsHtml = await fetch(`${SHELL}/__ioi/operations`).then((r) => r.text());
  const envHtml = await fetch(`${SHELL}/__ioi/environments`).then((r) => r.text());
  const venues = JSON.stringify((await jd("GET", "/v1/hypervisor/placement/venues")).j);
  ok("Operations + Environments show Azure posture (subscription, location, vnet); venues show the enterprise lane distinctly",
    /azure/i.test(opsHtml) && envHtml.includes(az.account_ref)
    && /sim-subscription · eastus2 · vnet: default/.test(envHtml)
    && /Azure VM sizes — enterprise customer-cloud \(guarded adapter\)/.test(venues));
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${az.account_id}`, { endpoint: { mode: "live", endpoint: "http://127.0.0.1:9" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${az.account_id}/preflight`);
  const liveCreate = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: `env-az4-${tag}`, candidate_ref: cand3.candidate_ref, max_hourly_usd: 0.3 });
  ok("live mode blocks NAMED — live provisioning demands live quotes/config, never a fake VM",
    liveCreate.status === 409 && /azure_quote_mode_mismatch|azure_quote_expired_requires_requote/.test(liveCreate.j.reason || ""));
  if (LIVE_MODE && !LIVE_KEY) {
    ok("azure_live_credentials_absent — IOI_AZURE_LIVE=1 requires IOI_AZURE_CLIENT_SECRET; live execution BLOCKED (not faked)", false);
  } else if (!LIVE_MODE) {
    ok("live_provisioning_not_run — simulator validated the enterprise ladder; live Azure execution is NOT claimed", true);
  }
  const audit = JSON.stringify({ recon3, sim2 }).toLowerCase();
  ok("no fee objects, no RoutingDecisionReceipt, no markup",
    !audit.includes("routingdecisionreceipt") && !audit.includes("fee_amount") && !audit.includes("markup\":"));
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);
}

async function cleanup() {
  try {
    if (accountId && env) {
      for (const e of [env, env.replace("env-az-", "env-az2-"), env.replace("env-az-", "env-az3-")]) {
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
    console.log(`azure enterprise vm adapter readiness: ${fail ? "FAIL" : "OK"}${LIVE_MODE ? "" : " (live_provisioning_not_run)"}`);
    process.exit(fail ? 1 : 0);
  })
  .catch((e) => {
    console.error("verifier crashed:", e);
    process.exit(1);
  });
