#!/usr/bin/env node
// Done-bar: cross-provider placement decisions + failover.
//
// Proves the first cut where Hypervisor moves work ACROSS venues:
//   intent → candidates → explicit placement DECISION (challengeable, no fee)
//   → governed provider create → snapshot → CAS archive custody
//   → named failure → failover: replacement on a DIFFERENT provider class,
//   wallet-gated at every mutation, restore admitted only by daemon state_root
//   → old provider closed, spend exposures close/open honestly
//   → Work Ledger links the whole chain; Operations/Environments show posture.
//
// Cross-class path exercised: vast (GPU marketplace, simulator control plane,
// real ssh custody lane) → akash (DePIN deployment, simulator, same fixture).
// Fail-closed negatives: unknown condition, no restore material, corrupt
// custody + corrupt archive, mutation refused without wallet grant.

import path from "node:path";
import os from "node:os";
import { writeFileSync, readFileSync, rmSync, mkdirSync } from "node:fs";
import { ensureSshFixture } from "./ensure-ssh-fixture.mjs";
import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";

const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const SHELL = process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173";
const DATA = process.env.IOI_HYPERVISOR_DATA_DIR || path.join(os.homedir(), ".ioi", "hypervisor", "data");
const BUDGET_FILE = path.join(DATA, "resource-budgets", "xfo-verify.json");

const results = [];
const ok = (name, cond, detail = "") => results.push({ name, pass: !!cond, detail });
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
function grantFor(challenge) {
  const a = challenge?.approval || challenge?.next_required?.approval || {};
  return mintApprovalGrant({ policyHash: a.policy_hash, requestHash: a.request_hash });
}
async function opWithGrant(providerId, op, extra = {}) {
  const base = { provider_id: providerId, op, ...extra };
  const c = await jd("POST", "/v1/hypervisor/provider-ops", base);
  if (c.status !== 403) return c;
  return jd("POST", "/v1/hypervisor/provider-ops", { ...base, wallet_approval_grant: grantFor(c.j) });
}
async function archiveOp(body) {
  const c = await jd("POST", "/v1/hypervisor/storage-archive-ops", body);
  if (c.status !== 403) return c;
  return jd("POST", "/v1/hypervisor/storage-archive-ops", { ...body, wallet_approval_grant: grantFor(c.j) });
}

let vastId = "", akashId = "", env = "", replacementEnv = "";

async function run() {
  const tag = Date.now().toString(16);
  env = `env-xfo-${tag}`;
  rmSync(BUDGET_FILE, { force: true });
  const fixture = await ensureSshFixture();
  const fdir = path.join(os.homedir(), ".ioi", "hypervisor", "vast-fixture");
  mkdirSync(fdir, { recursive: true });

  // ── fixtures: vast offers + akash bids (both quote-live in simulator) ──
  const offersFile = path.join(fdir, `xfo-offers-${tag}.json`);
  writeFileSync(offersFile, JSON.stringify({ offers: [
    { id: 91101, gpu_name: "RTX 4090", num_gpus: 1, gpu_ram: 24564, dph_total: 0.311, geolocation: "Sweden, SE", reliability2: 0.998, verified: true, inet_down: 900, disk_space: 256 },
  ] }));
  const bidsFile = path.join(fdir, `xfo-bids-${tag}.json`);
  writeFileSync(bidsFile, JSON.stringify({ bids: [
    { provider: "akash1xfoprov4090", region: "us-west", attributes: { tier: "datacenter" },
      deployment_class: "compute.gpu_runtime",
      gpu: { model: "RTX 4090", count: 1, vram_gb: 24 },
      cpu_milli: 8000, memory_gb: 32, storage_gb: 200, persistent_storage: true,
      price: { uakt_per_block: 150, usd_per_hour_quoted: 0.38, rate_basis: "console-quoted USD (uakt × oracle rate at quote time)" } },
  ] }));

  // ── self-clean: stale XFO accounts from prior runs would otherwise win the
  // candidate-source pick and skew account-pinned checks ──
  const stale = (await jd("GET", "/v1/hypervisor/provider-accounts")).j;
  for (const a of stale.accounts || []) {
    if (["vast", "akash"].includes(a.kind) && String(a.display_name || "").startsWith("XFO ")) {
      await jd("DELETE", `/v1/hypervisor/provider-accounts/${a.account_id}`);
    }
  }

  // ── accounts: vast (old class) + akash (replacement class) + cas backend ──
  const sshCfg = { host: fixture.host, port: fixture.port, user: fixture.user, key_file: fixture.client_key_path };
  const vast = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "vast", display_name: `XFO vast ${tag}` })).j.account || {};
  vastId = vast.account_id;
  await jd("POST", `/v1/hypervisor/provider-accounts/${vastId}/credential`, { api_key: `VAST-${tag}` });
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vastId}`, { endpoint: { mode: "simulator", fixture_file: offersFile, ssh: sshCfg } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vastId}/preflight`);
  const akash = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "akash", display_name: `XFO akash ${tag}` })).j.account || {};
  akashId = akash.account_id;
  await jd("POST", `/v1/hypervisor/provider-accounts/${akashId}/credential`, { api_key: `AKASH-${tag}` });
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${akashId}`, { endpoint: { mode: "simulator", fixture_file: bidsFile, ssh: sshCfg } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${akashId}/preflight`);
  const cas = (await jd("POST", "/v1/hypervisor/storage-backends", { kind: "cas", display_name: `XFO CAS ${tag}` })).j.backend || {};
  await jd("POST", `/v1/hypervisor/storage-backends/${cas.account_id}/preflight`);
  await jd("POST", "/v1/hypervisor/resource/budgets", { budget_id: "xfo-verify", name: "XFO verify", scope: "external_spend", limit: 5, spent: 0, currency: "USD" });

  // ── intent + candidates across BOTH classes ──
  const intent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "compute.gpu_runtime", resource_classes: ["compute.gpu_runtime", "compute.container"], gpu: { required: true },
  })).j.intent || {};
  const batch = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const vastCand = (batch.candidates || []).find((c) => c.adapter_ref === "adapter:vast-quote" && c.provider_account_ref === vast.account_ref) || {};
  const akashCand = (batch.candidates || []).find((c) => c.adapter_ref === "adapter:akash-bid" && c.provider_account_ref === akash.account_ref) || {};
  ok("candidate plane yields candidates from BOTH provider classes (vast + akash) under one intent",
    !!vastCand.candidate_ref && !!akashCand.candidate_ref);

  // ── explicit placement decision (no mutation, no fee) ──
  const dec = await jd("POST", "/v1/hypervisor/placement/decisions", { intent_ref: intent.intent_ref });
  const d = dec.j.decision || {};
  ok("placement decision records selected candidate + alternatives + rejected with reason codes",
    dec.status === 200
    && String(d.decision_ref || "").startsWith("placement-decision://")
    && !!d.selected_candidate_ref
    && Array.isArray(d.alternatives_considered)
    && Array.isArray(d.rejected_candidates)
    && (d.alternatives_considered.length + 1) >= 2);
  ok("decision carries no fee object and marks routing-fee eligibility only as eligible_future",
    d.spend_posture?.fee_object_minted === false
    && ["eligible_future", "not_applicable"].includes(d.spend_posture?.routing_fee_eligibility)
    && dec.j.receipt?.no_fee === true
    && /NOT a RoutingDecisionReceipt/.test(dec.j.receipt?.note || ""));
  ok("decision is evidence, not authority (explicit note; nothing was provisioned by deciding)",
    /not authority/.test(d.authority || "") && String(d.receipt_root || "").startsWith("sha256:"));

  // ── old provider up: create → marker → snapshot → archive ──
  const created = await opWithGrant(vastId, "create", { environment_ref: env, candidate_ref: vastCand.candidate_ref, max_hourly_usd: 0.4, teardown_policy: "always_teardown_required" });
  ok("old-class (vast) quote-gated create admits under wallet grant; exposure opens", created.j.ok === true);
  await opWithGrant(vastId, "start", { environment_ref: env });
  const marker = `xfo-${tag}`;
  const wr = await opWithGrant(vastId, "workrun", { environment_ref: env, command: `echo ${marker} > xfo.txt && cat xfo.txt` });
  ok("workspace mutated on old provider (marker written)", wr.j.ok === true && String(wr.j.evidence?.stdout || "").includes(marker));
  const snap = await opWithGrant(vastId, "snapshot", { environment_ref: env });
  const materialRef = snap.j.evidence?.restore_material_ref || snap.j.result?.restore_material_ref || "";
  const stateRoot = snap.j.evidence?.state_root || snap.j.result?.state_root || "";
  ok("snapshot admits daemon custody with sha256 state_root", snap.j.ok === true && materialRef !== "" && String(stateRoot).startsWith("sha256:"));
  const exp = await archiveOp({ op: "export", material_ref: materialRef, backend_id: cas.account_id });
  const archList = (await jd("GET", "/v1/hypervisor/storage-archives")).j;
  const archiveRef = ((archList.archives || []).find((a) => a.material_ref === materialRef) || {}).archive_ref || "";
  ok("archive export seals custody bytes to the CAS backend", exp.status === 200 && archiveRef !== "", `status=${exp.status} archive=${archiveRef}`);

  // ── failover plan + fail-closed negatives ──
  const plan = (await jd("POST", "/v1/hypervisor/failover/plans", { environment_ref: env, source_account_ref: vast.account_ref, intent_ref: intent.intent_ref })).j.plan || {};
  ok("failover plan snapshots readiness (daemon custody + archive refs)",
    plan.readiness === "ready_daemon_custody" && (plan.archive_refs || []).includes(archiveRef));
  const badCond = await jd("POST", "/v1/hypervisor/failover/run", { plan_ref: plan.plan_ref, failure_condition: "gremlins" });
  ok("unknown failure condition refused by name", badCond.status === 422 && badCond.j.reason === "failover_condition_unknown");
  const emptyPlan = (await jd("POST", "/v1/hypervisor/failover/plans", { environment_ref: `env-never-${tag}` })).j.plan || {};
  const noMat = await jd("POST", "/v1/hypervisor/failover/run", { plan_ref: emptyPlan.plan_ref, failure_condition: "provider_outage" });
  ok("failover refuses without valid restore material (fail closed)",
    noMat.status === 409 && noMat.j.reason === "failover_refused_no_restore_material");

  // ── the real failover: declared host_unreachable, cross-class ──
  const p1 = await jd("POST", "/v1/hypervisor/failover/run", { plan_ref: plan.plan_ref, failure_condition: "host_unreachable", max_hourly_usd: 0.4, teardown_policy: "always_teardown_required" });
  let runRec = p1.j.run || {};
  replacementEnv = runRec.replacement_environment_ref || "";
  ok("failover selects a replacement on a DIFFERENT provider class (vast excluded by reason code)",
    runRec.status === "awaiting_authority_create"
    && runRec.replacement?.provider_kind === "akash"
    && (runRec.events || []).some((e) => e.phase === "replacement_selected"));
  const decRec = (await jd("GET", "/v1/hypervisor/placement/decisions")).j.decisions.find((x) => x.failover_run_ref === runRec.run_ref) || {};
  ok("failover decision cites the excluded class among rejected candidates",
    (decRec.rejected_candidates || []).some((r) => r.reason_code === "same_class_as_failed_provider" && r.provider_kind === "vast"));
  const opsBefore = (await jd("GET", "/v1/hypervisor/provider-operations")).j;
  const replOpsBefore = (opsBefore.operations || opsBefore || []).filter?.((o) => o.environment_ref === replacementEnv)?.length ?? 0;
  ok("awaiting authority = zero replacement mutation happened (no wallet grant, no create)", replOpsBefore === 0);
  const p2 = await jd("POST", "/v1/hypervisor/failover/run", { run_ref: runRec.run_ref, wallet_approval_grant_create: grantFor(runRec.next_required) });
  runRec = p2.j.run || {};
  ok("granted create lands on replacement class; run advances to start gate",
    runRec.status === "awaiting_authority_start" && (runRec.events || []).some((e) => e.phase === "replacement_created"));
  const p2b = await jd("POST", "/v1/hypervisor/failover/run", { run_ref: runRec.run_ref, wallet_approval_grant_start: grantFor(runRec.next_required) });
  runRec = p2b.j.run || {};
  ok("replacement endpoint proven (started) before restore is attempted",
    runRec.status === "awaiting_authority_restore" && (runRec.events || []).some((e) => e.phase === "started"));
  const p3 = await jd("POST", "/v1/hypervisor/failover/run", { run_ref: runRec.run_ref, wallet_approval_grant_restore: grantFor(runRec.next_required) });
  runRec = p3.j.run || {};
  ok("state_root-validated restore admits on the replacement provider",
    runRec.status === "awaiting_authority_teardown" && (runRec.events || []).some((e) => e.phase === "restored"));
  const p4 = await jd("POST", "/v1/hypervisor/failover/run", { run_ref: runRec.run_ref, wallet_approval_grant_teardown: grantFor(runRec.next_required) });
  runRec = p4.j.run || {};
  ok("old provider closed; failover run completes", ["restored", "restored_with_warning"].includes(runRec.status)
    && (runRec.events || []).some((e) => e.phase === "old_closed"));
  const wr2 = await opWithGrant(akashId, "workrun", { environment_ref: replacementEnv, command: "cat xfo.txt" });
  ok("MARKER SURVIVED the cross-class move (old class → new class via daemon custody)",
    wr2.j.ok === true && String(wr2.j.evidence?.stdout || "").includes(marker));
  ok("old and new provider-native ids stay evidence only",
    /evidence_only/.test(runRec.old_provider?.native_ids || "") && /evidence_only/.test(runRec.replacement?.native_ids || ""));

  // ── spend exposures: old closed, new open ──
  const recon = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const exps = recon.rows || [];
  const oldExp = exps.find((e) => e.environment_ref === env && e.account_ref === vast.account_ref) || {};
  const newExp = exps.find((e) => e.environment_ref === replacementEnv) || {};
  ok("spend exposure closed on old provider and open on replacement",
    ["closed", "closed_with_warning"].includes(oldExp.status) && newExp.status === "open");

  // ── archive ladder positive + corrupt-archive negative ──
  const mats = (await jd("GET", "/v1/hypervisor/provider-materials")).j;
  const mat = (mats.materials || mats || []).find?.((m) => m.material_ref === materialRef) || {};
  if (mat.path) writeFileSync(mat.path, "corrupted-custody-bytes");
  const plan2 = (await jd("POST", "/v1/hypervisor/failover/plans", { environment_ref: env, source_account_ref: vast.account_ref, intent_ref: intent.intent_ref })).j.plan || {};
  let r2 = (await jd("POST", "/v1/hypervisor/failover/run", { plan_ref: plan2.plan_ref, failure_condition: "provider_outage", max_hourly_usd: 0.4 })).j.run || {};
  if (r2.status === "awaiting_authority_archive_restore") {
    r2 = (await jd("POST", "/v1/hypervisor/failover/run", { run_ref: r2.run_ref, wallet_approval_grant_archive_restore: grantFor(r2.next_required) })).j.run || {};
  }
  ok("corrupt daemon custody heals through the storage-archive 5-gate ladder (fetch→hash→decrypt→state_root)",
    (r2.events || []).some((e) => e.phase === "material_secured" && /storage_archive/.test(e.detail?.via || "")));
  // now corrupt custody AND the sealed archive object → must refuse
  if (mat.path) writeFileSync(mat.path, "corrupted-custody-bytes-again");
  const archives = (await jd("GET", "/v1/hypervisor/storage-archives")).j;
  const arch = (archives.archives || []).find((a) => a.archive_ref === archiveRef) || {};
  const archPath = arch.commitment?.path || "";
  if (archPath) writeFileSync(archPath, "corrupted-sealed-bytes");
  const plan3 = (await jd("POST", "/v1/hypervisor/failover/plans", { environment_ref: env, source_account_ref: vast.account_ref, intent_ref: intent.intent_ref })).j.plan || {};
  let r3 = await jd("POST", "/v1/hypervisor/failover/run", { plan_ref: plan3.plan_ref, failure_condition: "provider_outage" });
  let r3run = r3.j.run || {};
  if (r3run.status === "awaiting_authority_archive_restore") {
    // the ladder is wallet-gated even on the way to a refusal — resume, then
    // the commitment-hash gate must refuse the corrupted sealed bytes
    r3 = await jd("POST", "/v1/hypervisor/failover/run", { run_ref: r3run.run_ref, wallet_approval_grant_archive_restore: grantFor(r3run.next_required) });
    r3run = r3.j.run || {};
  }
  ok("corrupt custody + corrupt archive refuses failover by name (stale/corrupt archive never restores)",
    r3.status === 409 && ["archive_invalid", "snapshot_invalid"].includes(r3.j.reason || r3run.refusal?.reason));

  // ── ledger links the chain ──
  const ledger = (await jd("GET", "/v1/hypervisor/work-ledger")).j;
  const lEntries = Array.isArray(ledger) ? ledger : ledger.entries || [];
  const lDecision = lEntries.find((e) => e.kind === "placement_decision" && e.failover_run_ref === runRec.run_ref);
  const lFailover = lEntries.find((e) => e.kind === "failover" && e.run_ref === runRec.run_ref);
  const lStorage = lEntries.some((e) => e.kind === "storage_custody");
  const lCrossing = lEntries.some((e) => e.kind === "provider_crossing" && e.environment_ref === replacementEnv);
  ok("Work Ledger links placement decision + failover run + storage custody + provider crossings",
    !!lDecision && !!lFailover && lStorage && lCrossing && (lFailover.receipt_refs || []).length >= 2);

  // ── UI posture ──
  const opsHtml = await fetch(`${SHELL}/__ioi/operations`).then((r) => r.text()).catch(() => "");
  ok("Operations shows failover runs strip", opsHtml.includes('id="ops-failover"') && opsHtml.includes("host_unreachable"));
  const envHtml = await fetch(`${SHELL}/__ioi/environments`).then((r) => r.text()).catch(() => "");
  ok("Environments shows placement decisions + failover readiness", envHtml.includes('id="env-placement-decisions"'));
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({ proxied: ["unreachable"] }));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);
}

async function cleanup() {
  try {
    if (akashId && replacementEnv) await opWithGrant(akashId, "delete", { environment_ref: replacementEnv });
  } catch { /* best effort */ }
  try {
    if (vastId && env) await opWithGrant(vastId, "delete", { environment_ref: env });
  } catch { /* best effort */ }
  try {
    if (vastId) await jd("DELETE", `/v1/hypervisor/provider-accounts/${vastId}`);
    if (akashId) await jd("DELETE", `/v1/hypervisor/provider-accounts/${akashId}`);
  } catch { /* best effort */ }
  try {
    const sb = await jd("GET", "/v1/hypervisor/storage-backends");
    for (const b of sb.j.backends || []) {
      if (String(b.display_name || "").startsWith("XFO ")) {
        await jd("DELETE", `/v1/hypervisor/storage-backends/${b.account_id}`);
      }
    }
  } catch { /* best effort */ }
  rmSync(BUDGET_FILE, { force: true });
}

run().then(cleanup, (e) => { console.error(e); return cleanup().then(() => { results.push({ name: `run threw: ${e?.message || e}`, pass: false, detail: "" }); }); }).then(() => {
  let fail = 0;
  for (const r of results) {
    console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` (${r.detail})` : ""}`);
    if (!r.pass) fail++;
  }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`cross-provider failover readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
});
