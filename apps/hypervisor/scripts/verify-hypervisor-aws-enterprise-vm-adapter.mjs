#!/usr/bin/env node
// AWS enterprise VM adapter done-bar — the first ENTERPRISE hyperscaler lane (canon ladder #5),
// and deliberately NOT a marketplace or generic VM clone: AWS semantics preserved — IAM/SigV4
// sealed credentials, region/AZ, VPC/subnet/security-group posture, EC2 lifecycle with REAL
// stop/start/restart semantics (stop halts instance-hours, EBS keeps billing), EBS root volume
// posture, and native EC2/EBS/snapshot ids as EVIDENCE ONLY under daemon state-root restore
// truth. Enterprise network honesty: private-only / no-ingress postures fail CLOSED with an
// AWS-named reason — never fake-ready. IOI_AWS_LIVE=1 without credentials BLOCKS named.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-aws-enterprise-vm-adapter.mjs

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
const BUDGET_FILE = path.join(DATA, "resource-budgets", "aws-verify.json");
const LIVE_MODE = process.env.IOI_AWS_LIVE === "1";
const LIVE_KEY = process.env.IOI_AWS_SECRET_ACCESS_KEY || "";

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const awsSource = async () => {
  const s = (await jd("GET", "/v1/hypervisor/cloud-candidates/candidate-sources")).j;
  return (s.sources || []).find((x) => x.source === "aws") || {};
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
  env = `env-aws-${tag}`;
  rmSync(BUDGET_FILE, { force: true });
  const fixture = await ensureSshFixture();
  const dir = path.join(os.homedir(), ".ioi", "hypervisor", "vast-fixture");
  mkdirSync(dir, { recursive: true });
  const offersFile = path.join(dir, `aws-offers-${tag}.json`);
  // REAL EC2 offer shapes: region/AZ, instance types, EBS root posture, network posture,
  // verbatim on-demand rates. One offer entirely unpriced — SKIPPED, never estimated.
  writeFileSync(offersFile, JSON.stringify({ instance_offers: [
    { region: "us-east-1", az: "us-east-1a", instance_type: "g5.xlarge", vcpu: 4, memory_gb: 16,
      gpu: { model: "A10G", count: 1, vram_gb: 24 },
      root_volume: { gb: 100, type: "gp3" },
      network: { vpc_posture: "default_vpc", public_ip_supported: true },
      usd_per_hour: 1.006, pricing_basis: "EC2 on-demand rate card (verbatim)" },
    { region: "eu-west-1", az: "eu-west-1b", instance_type: "m5.large", vcpu: 2, memory_gb: 8,
      root_volume: { gb: 50, type: "gp3" },
      network: { vpc_posture: "default_vpc", public_ip_supported: true },
      usd_per_hour: 0.096, pricing_basis: "EC2 on-demand rate card (verbatim)" },
    { region: "us-east-1", az: "us-east-1c", instance_type: "p5.48xlarge",
      gpu: { model: "H100", count: 8, vram_gb: 80 },
      root_volume: { gb: 3840, type: "gp3" },
      network: { vpc_posture: "default_vpc", public_ip_supported: true } },
  ] }));

  // ── 1. Kind + SigV4 credential + source posture ladder ──
  const aws = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "aws", display_name: `AWS ${tag}` })).j.account || {};
  accountId = aws.account_id;
  ok("`aws` account kind validates with ENTERPRISE capabilities (IAM/SigV4, VPC posture, EC2/EBS, evidence-only native ids)",
    aws.account_ref?.startsWith("provider-account://")
    && /ENTERPRISE customer-cloud/.test(aws.capabilities?.lane || "")
    && /IAM\/SigV4/.test(aws.capabilities?.authority_model || "")
    && /fail closed, never fake-ready/.test(aws.capabilities?.network_posture || "")
    && /EBS storage keeps billing/.test(aws.capabilities?.instance_lifecycle || "")
    && /EVIDENCE only/.test(aws.capabilities?.volumes || "")
    && aws.provider_spend_borne_by === "customer");
  const s0 = await awsSource();
  ok("no credential → aws source unavailable with evidence",
    s0.state === "candidate_source_unavailable" && /aws_credential_absent/.test(s0.reason || ""));
  const SECRET = `AWS-SECRET-${tag}`;
  const bind = await jd("POST", `/v1/hypervisor/provider-accounts/${aws.account_id}/credential`, { secret_access_key: SECRET, aux: { access_key_id: "AKIA-VERIFY", region: "us-east-1" } });
  const pf = await jd("POST", `/v1/hypervisor/provider-accounts/${aws.account_id}/preflight`);
  ok("SigV4 credential binds SEALED; verified but unfetched → credential_verified_unprobed (no supply claim)",
    bind.j.ok !== false && !JSON.stringify(bind.j).includes(SECRET)
    && pf.j.ok === true && !JSON.stringify(pf.j).includes(SECRET)
    && (await awsSource()).state === "credential_verified_unprobed");

  // ── 2. Degraded live fetch → zero fake offers ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${aws.account_id}`, { endpoint: { mode: "live", endpoint: "http://127.0.0.1:9" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${aws.account_id}/preflight`);
  const intent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "compute.vm", resource_classes: ["compute.vm", "compute.gpu_runtime"],
  })).j.intent || {};
  const degraded = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  ok("unreachable live pricing feed → degraded_unreachable with evidence, zero fake offers",
    (await awsSource()).state === "degraded_unreachable"
    && !(degraded.candidates || []).some((c) => c.provider_kind === "aws")
    && (degraded.rejected || []).some((r) => r.reason_code === "candidate_source_degraded" && /aws/.test(r.adapter_ref || "")));

  // ── 3. Fixture normalization: AWS semantics preserved, advisory forever ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${aws.account_id}`, { endpoint: { mode: "fixture", fixture_file: offersFile } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${aws.account_id}/preflight`);
  const fixed = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const awsc = (fixed.candidates || []).filter((c) => c.provider_kind === "aws");
  const g5 = awsc.find((c) => c.instance_type === "g5.xlarge") || {};
  ok("fixture offers normalize with EC2 semantics (region/AZ/EBS/network posture; verbatim on-demand rate; unpriced SKIPPED)",
    awsc.length === 2
    && g5.quote?.usd_per_hour === 1.006 && g5.region === "us-east-1" && g5.az === "us-east-1a"
    && g5.storage?.disk_gb === 100 && g5.storage?.volume_type === "gp3"
    && /EBS root volume/.test(g5.storage?.posture || "")
    && g5.network?.public_ip_supported === true
    && /fail closed, never fake-ready/.test(g5.network?.ports_posture || "")
    && g5.source === "direct_provider" && g5.adapter_ref === "adapter:aws-ec2-quote");
  ok("risk labels are AWS-shaped (IAM/VPC/EBS) — never marketplace or DePIN labels; advisory forever",
    awsc.every((c) => (c.risk_labels || []).includes("iam_scope_dependent")
      && (c.risk_labels || []).includes("vpc_ssh_ingress_required")
      && (c.risk_labels || []).includes("ebs_native_snapshots_evidence_only")
      && !(c.risk_labels || []).includes("depin_provider_variability")
      && !(c.risk_labels || []).includes("community_cloud_interruption")
      && c.placement_eligible === "advisory_only" && c.evidence_mode === "fixture_evidence"));

  // ── 4. Guarded lifecycle: quote gate, wallet facets, simulator EC2 ──
  const simEndpoint = { mode: "simulator", fixture_file: offersFile, region: "us-east-1",
    ssh: { host: fixture.host, port: fixture.port, user: fixture.user, key_file: fixture.client_key_path } };
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${aws.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${aws.account_id}/preflight`);
  await jd("POST", "/v1/hypervisor/resource/budgets", { budget_id: "aws-verify", name: "AWS verify", scope: "external_spend", limit: 3, spent: 0, currency: "USD" });
  const fixCreate = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env, candidate_ref: g5.candidate_ref });
  const sim = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand = (sim.candidates || []).find((c) => c.provider_kind === "aws" && c.instance_type === "g5.xlarge") || {};
  const overMax = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env, candidate_ref: cand.candidate_ref, max_hourly_usd: 0.10 });
  ok("quote gate refuses fixture + over-max with aws-named reasons",
    fixCreate.status === 409 && /aws_quote_not_live/.test(fixCreate.j.reason || "")
    && overMax.status === 409 && /aws_price_above_max/.test(overMax.j.reason || ""));
  const createBase = { provider_id: accountId, op: "create", environment_ref: env,
    candidate_ref: cand.candidate_ref, max_hourly_usd: 1.1, teardown_policy: "always_teardown_required" };
  const challenge = await jd("POST", "/v1/hypervisor/provider-ops", createBase);
  const facets = challenge.j.lease_request_facets || {};
  ok("wallet challenge binds AWS-specific facets (region + AZ + instance type + disk + NETWORK POSTURE + teardown)",
    challenge.status === 403
    && facets.candidate_ref === cand.candidate_ref && facets.region === "us-east-1"
    && facets.az === "us-east-1a" && facets.instance_type === "g5.xlarge" && facets.disk_gb === 100
    && facets.network_posture?.posture_label === "default_vpc_simulator"
    && facets.network_posture?.public_ip === true && facets.network_posture?.ssh_ingress === true
    && facets.teardown_policy === "always_teardown_required");
  const grant = mintApprovalGrant({ policyHash: challenge.j.approval.policy_hash, requestHash: challenge.j.approval.request_hash });
  const created = await jd("POST", "/v1/hypervisor/provider-ops", { ...createBase, wallet_approval_grant: grant });
  ok("grant-authorized create provisions the (simulated) EC2 instance — ssh UNKNOWN, EBS root volume evidence-only",
    created.j.ok === true
    && String(created.j.evidence?.instance?.instance_id || "").startsWith("i-sim")
    && created.j.evidence?.ssh_ready === false
    && created.j.evidence?.live_provisioning_not_run === true
    && created.j.evidence?.teardown_required === true
    && String(created.j.evidence?.root_volume?.volume_id || "").startsWith("vol-sim")
    && /evidence only/.test(created.j.evidence?.root_volume?.note || "")
    && /no real AWS instance exists/.test(created.j.evidence?.provider_native?.note || ""));
  const preBoot = await opWithGrant("workrun", { command: "echo too-early" });
  ok("pre-boot workrun fails CLOSED with aws_ssh_bootstrap_unknown",
    preBoot.j.ok === false && /aws_ssh_bootstrap_unknown/.test(preBoot.j.reason || ""));
  const overBudget = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: `env-aws2-${tag}`, candidate_ref: cand.candidate_ref, max_hourly_usd: 2.5 });
  ok("external_spend reservation blocks the over-budget second create",
    overBudget.status === 409 && /aws_budget_reservation_exceeded/.test(overBudget.j.reason || ""));
  const started = await opWithGrant("start");
  ok("start boot-polls and persists ssh ONLY with readiness evidence through the reachable posture",
    started.j.ok === true && started.j.evidence?.ssh_ready === true
    && started.j.evidence?.boot_evidence?.proven_at
    && started.j.evidence?.boot_evidence?.posture?.posture_label === "default_vpc_simulator");

  // ── 5. Workrun / snapshot (EBS evidence) / restore / stop / start / restart ──
  const marker = `aws-${tag}`;
  const wr = await opWithGrant("workrun", { command: `echo ${marker} > ec2.txt && cat ec2.txt` });
  const snap = await opWithGrant("snapshot");
  const sev = snap.j.evidence || {};
  const restored = await opWithGrant("restore", { material_ref: sev.restore_material_ref });
  ok("workrun/snapshot/restore run the BYO custody contract — EBS-style native snapshot id rides as EVIDENCE ONLY",
    wr.j.ok === true && String(wr.j.evidence?.stdout || "").includes(marker)
    && sev.custody === "daemon" && String(sev.state_root || "").startsWith("sha256:")
    && String(sev.provider_native_snapshot?.snapshot_id || "").startsWith("snap-sim")
    && /NEVER restore truth/.test(sev.provider_native_snapshot?.note || "")
    && restored.j.evidence?.state_root_verified === sev.state_root);
  const stopped = await opWithGrant("stop");
  const reconStopped = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const expOpen = (reconStopped.rows || []).find((e) => e.account_ref === aws.account_ref && e.environment_ref === env) || {};
  ok("stop is HONEST EC2 semantics: instance-hours halt, EBS keeps billing, the exposure stays OPEN until terminate",
    stopped.j.ok === true && stopped.j.evidence?.status === "stopped"
    && /EBS root volume keeps billing until terminate/.test(stopped.j.evidence?.spend_note || "")
    && expOpen.status === "open");
  const restarted2 = await opWithGrant("start");
  const rebooted = await opWithGrant("restart");
  const wrAfter = await opWithGrant("workrun", { command: "cat ec2.txt" });
  const events = await opWithGrant("events");
  const eventKinds = (events.j.evidence?.events || []).map((e) => e.kind);
  ok("start-from-stopped + restart (EC2 reboot, endpoint retained) work; lifecycle events recorded",
    restarted2.j.ok === true && rebooted.j.ok === true
    && /endpoint retained/.test(rebooted.j.evidence?.note || "")
    && wrAfter.j.ok === true && String(wrAfter.j.evidence?.stdout || "").includes(marker)
    && ["run_instances_accepted", "boot_proven", "instance_stopped", "instance_started", "instance_rebooted"].every((k) => eventKinds.includes(k)));

  // ── 6. Storage plane + terminate + warn path ──
  const cas = (await jd("POST", "/v1/hypervisor/storage-backends", { kind: "cas", display_name: `AWS CAS ${tag}` })).j.backend || {};
  casBackendId = cas.account_id;
  await jd("POST", `/v1/hypervisor/storage-backends/${cas.account_id}/preflight`);
  const exported = await archiveOp({ op: "export", backend_id: cas.account_id, material_ref: sev.restore_material_ref });
  const archRestore = await archiveOp({ op: "restore", archive_ref: exported.j.archive?.archive_ref });
  ok("archive export + storage-validated restore ride the storage plane (state_root is the only truth)",
    exported.j.ok === true && archRestore.j.ok === true
    && archRestore.j.state_root_verified === sev.state_root);
  const del1 = await opWithGrant("delete");
  const recon2 = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const exp1closed = (recon2.rows || []).find((e) => e.exposure_ref === expOpen.exposure_ref) || {};
  ok("terminate always — exposure closes and the reservation releases",
    del1.j.ok === true && del1.j.evidence?.teardown_state === "torn_down"
    && /deleted on termination/.test(del1.j.evidence?.native_teardown?.note || "")
    && exp1closed.status === "closed" && recon2.budget?.reserved_open_estimates === 0);
  const env2 = `env-aws2-${tag}`;
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${aws.account_id}`, { endpoint: { ...simEndpoint, simulate_teardown_failure: true } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${aws.account_id}/preflight`);
  const sim2 = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand2 = (sim2.candidates || []).find((c) => c.provider_kind === "aws" && c.instance_type === "g5.xlarge") || {};
  await opWithGrant("create", { environment_ref: env2, candidate_ref: cand2.candidate_ref, max_hourly_usd: 1.1 });
  const del2 = await opWithGrant("delete", { environment_ref: env2 });
  const recon3 = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const exp2warn = (recon3.rows || []).find((e) => e.account_ref === aws.account_ref && e.environment_ref === env2) || {};
  ok("failed terminate → exposure closed_with_warning naming the still-accruing EC2/EBS risk",
    del2.j.ok === true && exp2warn.status === "closed_with_warning"
    && /INCOMPLETE TEARDOWN/.test(exp2warn.warning || ""));

  // ── 7. Enterprise network honesty: private/unreachable posture fails CLOSED ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${aws.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${aws.account_id}/preflight`);
  const env3 = `env-aws3-${tag}`;
  const sim3 = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand3 = (sim3.candidates || []).find((c) => c.provider_kind === "aws" && c.instance_type === "m5.large") || {};
  const privBase = { provider_id: accountId, op: "create", environment_ref: env3,
    candidate_ref: cand3.candidate_ref, max_hourly_usd: 0.2,
    network: { vpc_id: "vpc-0priv", subnet_id: "subnet-0priv", security_group_id: "sg-0priv", public_ip: false } };
  const privChallenge = await jd("POST", "/v1/hypervisor/provider-ops", privBase);
  const privFacets = privChallenge.j.lease_request_facets || {};
  const privGrant = mintApprovalGrant({ policyHash: privChallenge.j.approval.policy_hash, requestHash: privChallenge.j.approval.request_hash });
  const privCreated = await jd("POST", "/v1/hypervisor/provider-ops", { ...privBase, wallet_approval_grant: privGrant });
  const privStart = await opWithGrant("start", { environment_ref: env3 });
  ok("explicit VPC config binds in facets; private-only posture fails CLOSED at boot (never fake-ready)",
    privFacets.network_posture?.posture_label === "explicit_vpc_config"
    && privFacets.network_posture?.vpc_id === "vpc-0priv"
    && privFacets.network_posture?.public_ip === false
    && privCreated.j.ok === true
    && privCreated.j.evidence?.network_posture?.posture_label === "explicit_vpc_config"
    && privStart.j.ok === false && /aws_ssh_ingress_unreachable/.test(privStart.j.reason || ""));
  await opWithGrant("delete", { environment_ref: env3 });

  // ── 8. Surfaces + live honesty + invariants ──
  const ledger = ((await jd("GET", "/v1/hypervisor/work-ledger")).j.entries || [])
    .filter((e) => e.kind === "provider_crossing" && e.account_ref === aws.account_ref);
  ok("Work Ledger provider crossings include the AWS lifecycle with exposure backlinks",
    ledger.some((e) => e.op === "create" && e.exposure_ref === expOpen.exposure_ref)
    && ledger.some((e) => e.op === "restart"));
  const opsHtml = await fetch(`${SHELL}/__ioi/operations`).then((r) => r.text());
  const envHtml = await fetch(`${SHELL}/__ioi/environments`).then((r) => r.text());
  const venues = JSON.stringify((await jd("GET", "/v1/hypervisor/placement/venues")).j);
  ok("Operations + Environments show AWS posture (account, region, VPC); venues show the enterprise lane distinctly",
    /aws/i.test(opsHtml) && envHtml.includes(aws.account_ref)
    && /us-east-1 · vpc: default/.test(envHtml)
    && /enterprise customer-cloud \(guarded adapter\)/.test(venues));
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${aws.account_id}`, { endpoint: { mode: "live", endpoint: "http://127.0.0.1:9" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${aws.account_id}/preflight`);
  const liveCreate = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: `env-aws4-${tag}`, candidate_ref: cand3.candidate_ref, max_hourly_usd: 0.2 });
  ok("live mode blocks NAMED — live provisioning demands live quotes/config, never a fake instance",
    liveCreate.status === 409 && /aws_quote_mode_mismatch|aws_quote_expired_requires_requote/.test(liveCreate.j.reason || ""));
  if (LIVE_MODE && !LIVE_KEY) {
    ok("aws_live_credentials_absent — IOI_AWS_LIVE=1 requires IOI_AWS_SECRET_ACCESS_KEY; live execution BLOCKED (not faked)", false);
  } else if (!LIVE_MODE) {
    ok("live_provisioning_not_run — simulator validated the enterprise ladder; live AWS execution is NOT claimed", true);
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
      for (const e of [env, env.replace("env-aws-", "env-aws2-"), env.replace("env-aws-", "env-aws3-")]) {
        const obs = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "observe", environment_ref: e });
        if (obs.j?.evidence?.teardown_state === "live_or_pending") await opWithGrant("delete", { environment_ref: e });
      }
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
    console.log(`aws enterprise vm adapter readiness: ${fail ? "FAIL" : "OK"}${LIVE_MODE ? "" : " (live_provisioning_not_run)"}`);
    process.exit(fail ? 1 : 0);
  })
  .catch((e) => {
    console.error("verifier crashed:", e);
    process.exit(1);
  });
