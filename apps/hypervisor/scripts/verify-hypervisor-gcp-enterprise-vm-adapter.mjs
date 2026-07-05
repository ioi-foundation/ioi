#!/usr/bin/env node
// GCP enterprise VM adapter done-bar — the second ENTERPRISE hyperscaler lane, sibling to AWS
// but with GCP SEMANTICS preserved (never EC2 names): service-account/workload-identity sealed
// credentials, PROJECT/region/ZONE scoping, machine types (+ accelerators), VPC
// network/subnetwork/FIREWALL posture, Persistent Disk boot volumes, and REAL Compute Engine
// billing semantics (stop = TERMINATED: vCPU/RAM halts, PD keeps billing; restart = in-place
// reset). Private-only or firewall-closed postures fail CLOSED with GCP-named reasons —
// instance state alone is never readiness. IOI_GCP_LIVE=1 without credentials BLOCKS named.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-gcp-enterprise-vm-adapter.mjs

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
const BUDGET_FILE = path.join(DATA, "resource-budgets", "gcp-verify.json");
const LIVE_MODE = process.env.IOI_GCP_LIVE === "1";
const LIVE_KEY = process.env.IOI_GCP_SERVICE_ACCOUNT_KEY || "";

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const gcpSource = async () => {
  const s = (await jd("GET", "/v1/hypervisor/cloud-candidates/candidate-sources")).j;
  return (s.sources || []).find((x) => x.source === "gcp") || {};
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
  env = `env-gcp-${tag}`;
  rmSync(BUDGET_FILE, { force: true });
  const fixture = await ensureSshFixture();
  const dir = path.join(os.homedir(), ".ioi", "hypervisor", "vast-fixture");
  mkdirSync(dir, { recursive: true });
  const offersFile = path.join(dir, `gcp-offers-${tag}.json`);
  // REAL Compute Engine offer shapes: project/zone scoping, machine types + accelerators,
  // Persistent Disk posture, VPC/firewall posture, verbatim rates. One offer unpriced — SKIPPED.
  writeFileSync(offersFile, JSON.stringify({ machine_offers: [
    { project: "sim-project", region: "us-central1", zone: "us-central1-a", machine_type: "g2-standard-8",
      vcpu: 8, memory_gb: 32, accelerator: { model: "L4", count: 1, vram_gb: 24 },
      boot_disk: { gb: 100, type: "pd-ssd" },
      network: { network: "default", external_ip_supported: true, firewall_ssh_ingress: true },
      usd_per_hour: 0.854, pricing_basis: "Compute Engine on-demand rate card (verbatim)" },
    { project: "sim-project", region: "europe-west4", zone: "europe-west4-b", machine_type: "n2-standard-4",
      vcpu: 4, memory_gb: 16,
      boot_disk: { gb: 50, type: "pd-balanced" },
      network: { network: "default", external_ip_supported: true, firewall_ssh_ingress: true },
      usd_per_hour: 0.194, pricing_basis: "Compute Engine on-demand rate card (verbatim)" },
    { project: "sim-project", region: "us-central1", zone: "us-central1-b", machine_type: "a3-highgpu-8g",
      vcpu: 208, memory_gb: 1872, accelerator: { model: "H100", count: 8, vram_gb: 80 },
      boot_disk: { gb: 2000, type: "pd-ssd" },
      network: { network: "default", external_ip_supported: true, firewall_ssh_ingress: true } },
  ] }));

  // ── 1. Kind + service-account credential + source posture ladder ──
  const gcp = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "gcp", display_name: `GCP ${tag}` })).j.account || {};
  accountId = gcp.account_id;
  ok("`gcp` account kind validates with ENTERPRISE capabilities (service-account authority, project/zone, firewall posture, PD evidence-only)",
    gcp.account_ref?.startsWith("provider-account://")
    && /ENTERPRISE customer-cloud/.test(gcp.capabilities?.lane || "")
    && /service-account \/ workload-identity/.test(gcp.capabilities?.authority_model || "")
    && /project \/ region \/ ZONE/.test(gcp.capabilities?.scoping || "")
    && /FIREWALL/.test(gcp.capabilities?.network_posture || "")
    && /TERMINATED/.test(gcp.capabilities?.instance_lifecycle || "")
    && /EVIDENCE only/.test(gcp.capabilities?.volumes || "")
    && gcp.provider_spend_borne_by === "customer");
  const s0 = await gcpSource();
  ok("no credential → gcp source unavailable with evidence",
    s0.state === "candidate_source_unavailable" && /gcp_credential_absent/.test(s0.reason || ""));
  const SECRET = `GCP-SA-KEY-${tag}`;
  const bind = await jd("POST", `/v1/hypervisor/provider-accounts/${gcp.account_id}/credential`, { service_account_key: SECRET });
  const pf = await jd("POST", `/v1/hypervisor/provider-accounts/${gcp.account_id}/preflight`);
  ok("service-account credential binds SEALED; verified but unfetched → credential_verified_unprobed (no supply claim)",
    bind.j.ok !== false && !JSON.stringify(bind.j).includes(SECRET)
    && pf.j.ok === true && !JSON.stringify(pf.j).includes(SECRET)
    && (await gcpSource()).state === "credential_verified_unprobed");

  // ── 2. Degraded live fetch → zero fake offers ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${gcp.account_id}`, { endpoint: { mode: "live", endpoint: "http://127.0.0.1:9" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${gcp.account_id}/preflight`);
  const intent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "compute.vm", resource_classes: ["compute.vm", "compute.gpu_runtime"],
  })).j.intent || {};
  const degraded = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  ok("unreachable live pricing feed → degraded_unreachable with evidence, zero fake offers",
    (await gcpSource()).state === "degraded_unreachable"
    && !(degraded.candidates || []).some((c) => c.provider_kind === "gcp")
    && (degraded.rejected || []).some((r) => r.reason_code === "candidate_source_degraded" && /gcp/.test(r.adapter_ref || "")));

  // ── 3. Fixture normalization: GCP semantics preserved, advisory forever ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${gcp.account_id}`, { endpoint: { mode: "fixture", fixture_file: offersFile } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${gcp.account_id}/preflight`);
  const fixed = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const gcpc = (fixed.candidates || []).filter((c) => c.provider_kind === "gcp");
  const g2 = gcpc.find((c) => c.machine_type === "g2-standard-8") || {};
  ok("fixture offers normalize with Compute Engine semantics (project/zone/machine type/PD/firewall posture; verbatim rate; unpriced SKIPPED)",
    gcpc.length === 2
    && g2.quote?.usd_per_hour === 0.854 && g2.project === "sim-project" && g2.zone === "us-central1-a"
    && g2.gpu?.model === "L4"
    && g2.storage?.disk_gb === 100 && g2.storage?.volume_type === "pd-ssd"
    && /Persistent Disk boot volume/.test(g2.storage?.posture || "")
    && g2.network?.firewall_ssh_ingress === true
    && /firewall allow rule/.test(g2.network?.ports_posture || "")
    && g2.source === "direct_provider" && g2.adapter_ref === "adapter:gcp-compute-quote");
  ok("risk labels are GCP-shaped (service-account/firewall/PD) — never AWS or marketplace labels; advisory forever",
    gcpc.every((c) => (c.risk_labels || []).includes("iam_service_account_scope_dependent")
      && (c.risk_labels || []).includes("vpc_firewall_ssh_ingress_required")
      && (c.risk_labels || []).includes("pd_native_snapshots_evidence_only")
      && !(c.risk_labels || []).includes("iam_scope_dependent")
      && !(c.risk_labels || []).includes("ebs_native_snapshots_evidence_only")
      && !(c.risk_labels || []).includes("depin_provider_variability")
      && c.placement_eligible === "advisory_only" && c.evidence_mode === "fixture_evidence"));

  // ── 4. Guarded lifecycle: quote gate, wallet facets, simulator Compute Engine ──
  const simEndpoint = { mode: "simulator", fixture_file: offersFile, project: "sim-project", zone: "us-central1-a",
    ssh: { host: fixture.host, port: fixture.port, user: fixture.user, key_file: fixture.client_key_path } };
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${gcp.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${gcp.account_id}/preflight`);
  await jd("POST", "/v1/hypervisor/resource/budgets", { budget_id: "gcp-verify", name: "GCP verify", scope: "external_spend", limit: 3, spent: 0, currency: "USD" });
  const fixCreate = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env, candidate_ref: g2.candidate_ref });
  const sim = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand = (sim.candidates || []).find((c) => c.provider_kind === "gcp" && c.machine_type === "g2-standard-8") || {};
  const overMax = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env, candidate_ref: cand.candidate_ref, max_hourly_usd: 0.10 });
  ok("quote gate refuses fixture + over-max with gcp-named reasons",
    fixCreate.status === 409 && /gcp_quote_not_live/.test(fixCreate.j.reason || "")
    && overMax.status === 409 && /gcp_price_above_max/.test(overMax.j.reason || ""));
  const createBase = { provider_id: accountId, op: "create", environment_ref: env,
    candidate_ref: cand.candidate_ref, max_hourly_usd: 0.9, teardown_policy: "always_teardown_required" };
  const challenge = await jd("POST", "/v1/hypervisor/provider-ops", createBase);
  const facets = challenge.j.lease_request_facets || {};
  ok("wallet challenge binds GCP-specific facets (project + zone + machine type + disk + NETWORK/FIREWALL posture + teardown)",
    challenge.status === 403
    && facets.candidate_ref === cand.candidate_ref && facets.project === "sim-project"
    && facets.zone === "us-central1-a" && facets.machine_type === "g2-standard-8" && facets.disk_gb === 100
    && facets.network_posture?.posture_label === "default_network_simulator"
    && facets.network_posture?.public_ip === true && facets.network_posture?.ssh_ingress === true
    && facets.teardown_policy === "always_teardown_required");
  const grant = mintApprovalGrant({ policyHash: challenge.j.approval.policy_hash, requestHash: challenge.j.approval.request_hash });
  const created = await jd("POST", "/v1/hypervisor/provider-ops", { ...createBase, wallet_approval_grant: grant });
  ok("grant-authorized create provisions the (simulated) instance — ssh UNKNOWN, Persistent Disk evidence-only",
    created.j.ok === true
    && String(created.j.evidence?.instance?.instance_name || "").startsWith("sim-instance-")
    && created.j.evidence?.ssh_ready === false
    && created.j.evidence?.live_provisioning_not_run === true
    && created.j.evidence?.teardown_required === true
    && String(created.j.evidence?.boot_disk?.disk_name || "").startsWith("sim-disk-")
    && /evidence only/.test(created.j.evidence?.boot_disk?.note || "")
    && /projects\/sim-project\/zones\/us-central1-a\/instances\//.test(created.j.evidence?.provider_native?.instance_path || "")
    && /no real GCP instance exists/.test(created.j.evidence?.provider_native?.note || ""));
  const preBoot = await opWithGrant("workrun", { command: "echo too-early" });
  ok("pre-boot workrun fails CLOSED with gcp_ssh_bootstrap_unknown (instance state alone is never readiness)",
    preBoot.j.ok === false && /gcp_ssh_bootstrap_unknown/.test(preBoot.j.reason || ""));
  const overBudget = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: `env-gcp2-${tag}`, candidate_ref: cand.candidate_ref, max_hourly_usd: 2.5 });
  ok("external_spend reservation blocks the over-budget second create",
    overBudget.status === 409 && /gcp_budget_reservation_exceeded/.test(overBudget.j.reason || ""));
  const started = await opWithGrant("start");
  ok("start boot-polls and persists ssh ONLY with readiness evidence through the reachable network/firewall posture",
    started.j.ok === true && started.j.evidence?.ssh_ready === true
    && started.j.evidence?.boot_evidence?.proven_at
    && started.j.evidence?.boot_evidence?.posture?.posture_label === "default_network_simulator"
    && /RUNNING state alone was not treated as readiness/.test(started.j.evidence?.boot_evidence?.note || ""));

  // ── 5. Workrun / snapshot (PD evidence) / restore / stop (TERMINATED) / start / reset ──
  const marker = `gcp-${tag}`;
  const wr = await opWithGrant("workrun", { command: `echo ${marker} > gce.txt && cat gce.txt` });
  const snap = await opWithGrant("snapshot");
  const sev = snap.j.evidence || {};
  const restored = await opWithGrant("restore", { material_ref: sev.restore_material_ref });
  ok("workrun/snapshot/restore run the BYO custody contract — Persistent-Disk-style native snapshot rides as EVIDENCE ONLY",
    wr.j.ok === true && String(wr.j.evidence?.stdout || "").includes(marker)
    && sev.custody === "daemon" && String(sev.state_root || "").startsWith("sha256:")
    && String(sev.provider_native_snapshot?.snapshot_name || "").startsWith("sim-snapshot-")
    && /NEVER restore truth/.test(sev.provider_native_snapshot?.note || "")
    && restored.j.evidence?.state_root_verified === sev.state_root);
  const stopped = await opWithGrant("stop");
  const reconStopped = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const expOpen = (reconStopped.rows || []).find((e) => e.account_ref === gcp.account_ref && e.environment_ref === env) || {};
  ok("stop is HONEST Compute Engine semantics: TERMINATED state, vCPU/RAM halts, PD keeps billing, exposure stays OPEN",
    stopped.j.ok === true && stopped.j.evidence?.status === "TERMINATED"
    && /Persistent Disk boot volume keeps billing until delete/.test(stopped.j.evidence?.spend_note || "")
    && expOpen.status === "open");
  const restarted2 = await opWithGrant("start");
  const reset = await opWithGrant("restart");
  const wrAfter = await opWithGrant("workrun", { command: "cat gce.txt" });
  const events = await opWithGrant("events");
  const eventKinds = (events.j.evidence?.events || []).map((e) => e.kind);
  ok("start-from-TERMINATED + reset (in-place, endpoint retained) work; lifecycle events recorded",
    restarted2.j.ok === true && reset.j.ok === true
    && /endpoint retained/.test(reset.j.evidence?.note || "")
    && wrAfter.j.ok === true && String(wrAfter.j.evidence?.stdout || "").includes(marker)
    && ["instances_insert_accepted", "boot_proven", "instance_stopped", "instance_started", "instance_reset"].every((k) => eventKinds.includes(k)));

  // ── 6. Delete + warn path ──
  const del1 = await opWithGrant("delete");
  const recon2 = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const exp1closed = (recon2.rows || []).find((e) => e.exposure_ref === expOpen.exposure_ref) || {};
  ok("delete always — Persistent Disk auto-deletes with the instance; exposure closes and the reservation releases",
    del1.j.ok === true && del1.j.evidence?.teardown_state === "torn_down"
    && /auto-deleted with the instance/.test(del1.j.evidence?.native_teardown?.note || "")
    && exp1closed.status === "closed" && recon2.budget?.reserved_open_estimates === 0);
  const env2 = `env-gcp2-${tag}`;
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${gcp.account_id}`, { endpoint: { ...simEndpoint, simulate_teardown_failure: true } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${gcp.account_id}/preflight`);
  const sim2 = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand2 = (sim2.candidates || []).find((c) => c.provider_kind === "gcp" && c.machine_type === "g2-standard-8") || {};
  await opWithGrant("create", { environment_ref: env2, candidate_ref: cand2.candidate_ref, max_hourly_usd: 0.9 });
  const del2 = await opWithGrant("delete", { environment_ref: env2 });
  const recon3 = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const exp2warn = (recon3.rows || []).find((e) => e.account_ref === gcp.account_ref && e.environment_ref === env2) || {};
  ok("failed delete → exposure closed_with_warning naming the still-accruing vCPU/PD risk",
    del2.j.ok === true && exp2warn.status === "closed_with_warning"
    && /INCOMPLETE TEARDOWN/.test(exp2warn.warning || ""));

  // ── 7. Network/firewall honesty: private or firewall-closed posture fails CLOSED ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${gcp.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${gcp.account_id}/preflight`);
  const env3 = `env-gcp3-${tag}`;
  const sim3 = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand3 = (sim3.candidates || []).find((c) => c.provider_kind === "gcp" && c.machine_type === "n2-standard-4") || {};
  const fwBase = { provider_id: accountId, op: "create", environment_ref: env3,
    candidate_ref: cand3.candidate_ref, max_hourly_usd: 0.3,
    network: { network: "prod-vpc", subnetwork: "private-subnet", public_ip: true, ssh_ingress: false } };
  const fwChallenge = await jd("POST", "/v1/hypervisor/provider-ops", fwBase);
  const fwFacets = fwChallenge.j.lease_request_facets || {};
  const fwGrant = mintApprovalGrant({ policyHash: fwChallenge.j.approval.policy_hash, requestHash: fwChallenge.j.approval.request_hash });
  const fwCreated = await jd("POST", "/v1/hypervisor/provider-ops", { ...fwBase, wallet_approval_grant: fwGrant });
  const fwStart = await opWithGrant("start", { environment_ref: env3 });
  ok("explicit network config binds in facets; missing FIREWALL ingress fails CLOSED at boot (never fake-ready)",
    fwFacets.network_posture?.posture_label === "explicit_network_config"
    && fwFacets.network_posture?.network === "prod-vpc"
    && fwFacets.network_posture?.ssh_ingress === false
    && fwCreated.j.ok === true
    && fwStart.j.ok === false && /gcp_ssh_ingress_unreachable/.test(fwStart.j.reason || "")
    && /FIREWALL/.test(fwStart.j.reason || ""));
  await opWithGrant("delete", { environment_ref: env3 });

  // ── 8. Surfaces + live honesty + invariants ──
  const ledger = ((await jd("GET", "/v1/hypervisor/work-ledger")).j.entries || [])
    .filter((e) => e.kind === "provider_crossing" && e.account_ref === gcp.account_ref);
  ok("Work Ledger provider crossings include the GCP lifecycle with exposure backlinks",
    ledger.some((e) => e.op === "create" && e.exposure_ref === expOpen.exposure_ref)
    && ledger.some((e) => e.op === "restart"));
  const opsHtml = await fetch(`${SHELL}/__ioi/operations`).then((r) => r.text());
  const envHtml = await fetch(`${SHELL}/__ioi/environments`).then((r) => r.text());
  const venues = JSON.stringify((await jd("GET", "/v1/hypervisor/placement/venues")).j);
  ok("Operations + Environments show GCP posture (project, zone, network); venues show the enterprise lane distinctly",
    /gcp/i.test(opsHtml) && envHtml.includes(gcp.account_ref)
    && /sim-project · us-central1-a · net: default/.test(envHtml)
    && /Compute Engine machine types — enterprise customer-cloud \(guarded adapter\)/.test(venues));
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${gcp.account_id}`, { endpoint: { mode: "live", endpoint: "http://127.0.0.1:9" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${gcp.account_id}/preflight`);
  const liveCreate = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: `env-gcp4-${tag}`, candidate_ref: cand3.candidate_ref, max_hourly_usd: 0.3 });
  ok("live mode blocks NAMED — live provisioning demands live quotes/config, never a fake instance",
    liveCreate.status === 409 && /gcp_quote_mode_mismatch|gcp_quote_expired_requires_requote/.test(liveCreate.j.reason || ""));
  if (LIVE_MODE && !LIVE_KEY) {
    ok("gcp_live_credentials_absent — IOI_GCP_LIVE=1 requires IOI_GCP_SERVICE_ACCOUNT_KEY; live execution BLOCKED (not faked)", false);
  } else if (!LIVE_MODE) {
    ok("live_provisioning_not_run — simulator validated the enterprise ladder; live GCP execution is NOT claimed", true);
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
      for (const e of [env, env.replace("env-gcp-", "env-gcp2-"), env.replace("env-gcp-", "env-gcp3-")]) {
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
    console.log(`gcp enterprise vm adapter readiness: ${fail ? "FAIL" : "OK"}${LIVE_MODE ? "" : " (live_provisioning_not_run)"}`);
    process.exit(fail ? 1 : 0);
  })
  .catch((e) => {
    console.error("verifier crashed:", e);
    process.exit(1);
  });
