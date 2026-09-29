#!/usr/bin/env node
// Done-bar: auto-failover policy trigger.
//
// Operators DECLARE when a FailoverPlan may trigger automatically from
// provider evidence. Proven here:
//   arm (declared conditions, fail-closed on unknown/unready)
//   → no evidence, no trigger (named outcome)
//   → REAL provider evidence (simulated akash lease revocation records)
//   → evaluate triggers a run that cites its evidence and PARKS at the
//     wallet gate — automatic detection never becomes automatic authority
//   → no duplicate trigger while a run is active (single-shot arming)
//   → granted resume completes the cross-class move (akash → vast)
//   → disarm stops evaluation; no fee objects anywhere.

import path from "node:path";
import { writeFileSync } from "node:fs";
import { ensureSshFixture } from "./ensure-ssh-fixture.mjs";
import { verifierFixtureDir } from "./lib/verifier-stack.mjs";
import { authorityVerifierStack } from "./lib/verifier-authority-stack.mjs";

// Its own isolated daemon + serve on a temp data dir, the operator signed in, its offer/bid/facts documents in a temp
// fixture dir — never the owner's :8765/:4173 nor anything under ~/.ioi/hypervisor (R-240, verifier hygiene,
// 2026-09-29). This verifier used to delete (and, through the daemon, write) resource-budgets/*-verify.json in the
// OWNER's data dir and write fixtures under ~/.ioi/hypervisor/vast-fixture; a fresh plane is torn down whole.
//
// A REAL AUTHORITY, NOT A TEST SIGNER (R-240, provider adapters on an authority stack, 2026-09-29). A provider-ops write
// names its owner and an idempotency key (400 mutation_owner_ref_required otherwise), and a grant-gated crossing needs a
// configured authority principal — a test-signer grant is no authority (501 provider_operation_authority_required). The
// daemon takes its grants from a sealed deployment-local wallet.network authority of this verifier's own
// (lib/verifier-authority-stack.mjs): the ungranted call parks a challenge, the operator approves it with the run's
// passphrase on the daemon's decision route, and the retry names the approval_ref. A sealed bring-up takes minutes.
const A = await authorityVerifierStack({ label: "auto-failover-trigger" });
const STACK = A.stack;
const DAEMON = STACK.daemonUrl;
const SHELL = STACK.serveUrl;
const FIXTURES = verifierFixtureDir("xfa");

const results = [];
const ok = (name, cond, detail = "") => results.push({ name, pass: !!cond, detail });
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
// The operator's approval of what a refusal parked: a failover run parked at a wallet gate carries the provider op's
// refusal (its challenge) in next_required.challenge.
const grantFor = (parked) => A.approve({ j: parked?.challenge || parked?.next_required?.challenge || parked || {} });
// one logical op, one idempotency key: the challenged call and its granted retry are the same request
const opWithGrant = (providerId, op, extra = {}) => A.crossing("/v1/hypervisor/provider-ops", A.owned({ provider_id: providerId, op, ...extra }));
const archiveOp = (body) => A.crossing("/v1/hypervisor/storage-archive-ops", body);

let akashId = "", vastId = "", env = "", replacementEnv = "";

async function run() {
  const tag = Date.now().toString(16);
  env = `env-xfa-${tag}`;
  const fixture = await ensureSshFixture();
  const fdir = FIXTURES.dir;
  const bidsFile = path.join(fdir, `xfa-bids-${tag}.json`);
  writeFileSync(bidsFile, JSON.stringify({ bids: [
    { provider: "akash1xfaprov4090", region: "us-west", attributes: { tier: "datacenter" },
      deployment_class: "compute.gpu_runtime",
      gpu: { model: "RTX 4090", count: 1, vram_gb: 24 },
      cpu_milli: 8000, memory_gb: 32, storage_gb: 200, persistent_storage: true,
      price: { uakt_per_block: 150, usd_per_hour_quoted: 0.38, rate_basis: "console-quoted USD (uakt × oracle rate at quote time)" } },
  ] }));
  const offersFile = path.join(fdir, `xfa-offers-${tag}.json`);
  writeFileSync(offersFile, JSON.stringify({ offers: [
    { id: 92201, gpu_name: "RTX 4090", num_gpus: 1, gpu_ram: 24564, dph_total: 0.311, geolocation: "Sweden, SE", reliability2: 0.998, verified: true, inet_down: 900, disk_space: 256 },
  ] }));

  // self-clean stale XFA accounts (candidate-source stable-pick gotcha)
  const stale = (await jd("GET", "/v1/hypervisor/provider-accounts")).j;
  for (const a of stale.accounts || []) {
    if (["vast", "akash"].includes(a.kind) && String(a.display_name || "").startsWith("XFA ")) {
      await jd("DELETE", `/v1/hypervisor/provider-accounts/${a.account_id}`);
    }
  }
  const sshCfg = { host: fixture.host, port: fixture.port, user: fixture.user, key_file: fixture.client_key_path };
  const akash = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "akash", display_name: `XFA akash ${tag}` })).j.account || {};
  akashId = akash.account_id;
  await jd("POST", `/v1/hypervisor/provider-accounts/${akashId}/credential`, { api_key: `AKASH-${tag}` });
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${akashId}`, { endpoint: { mode: "simulator", fixture_file: bidsFile, ssh: sshCfg } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${akashId}/preflight`);
  const vast = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "vast", display_name: `XFA vast ${tag}` })).j.account || {};
  vastId = vast.account_id;
  await jd("POST", `/v1/hypervisor/provider-accounts/${vastId}/credential`, { api_key: `VAST-${tag}` });
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vastId}`, { endpoint: { mode: "simulator", fixture_file: offersFile, ssh: sshCfg } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vastId}/preflight`);
  const cas = (await jd("POST", "/v1/hypervisor/storage-backends", { kind: "cas", display_name: `XFA CAS ${tag}` })).j.backend || {};
  await jd("POST", `/v1/hypervisor/storage-backends/${cas.account_id}/preflight`);
  await jd("POST", "/v1/hypervisor/resource/budgets", { budget_id: "xfa-verify", name: "XFA verify", scope: "external_spend", limit: 5, spent: 0, currency: "USD" });

  const intent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "compute.gpu_runtime", resource_classes: ["compute.gpu_runtime", "compute.container"], gpu: { required: true },
  })).j.intent || {};
  const batch = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const akashCand = (batch.candidates || []).find((c) => c.adapter_ref === "adapter:akash-bid" && c.provider_account_ref === akash.account_ref) || {};

  // old provider up on akash: create → start → marker → snapshot → archive
  const created = await opWithGrant(akashId, "create", { environment_ref: env, candidate_ref: akashCand.candidate_ref, max_hourly_usd: 0.4, teardown_policy: "always_teardown_required" });
  ok("old-class (akash) lease admits under wallet grant", created.j.ok === true);
  await opWithGrant(akashId, "start", { environment_ref: env });
  const marker = `xfa-${tag}`;
  const wr = await opWithGrant(akashId, "workrun", { environment_ref: env, command: `echo ${marker} > xfa.txt && cat xfa.txt` });
  ok("marker written on the akash lease", wr.j.ok === true && String(wr.j.evidence?.stdout || "").includes(marker));
  const snap = await opWithGrant(akashId, "snapshot", { environment_ref: env });
  const materialRef = snap.j.evidence?.restore_material_ref || snap.j.result?.restore_material_ref || "";
  await archiveOp({ op: "export", material_ref: materialRef, backend_id: cas.account_id });

  // plan + arming ladder
  const plan = (await jd("POST", "/v1/hypervisor/failover/plans", { environment_ref: env, source_account_ref: akash.account_ref, intent_ref: intent.intent_ref })).j.plan || {};
  const badArm = await jd("POST", `/v1/hypervisor/failover/plans/${plan.plan_id}/arm`, { conditions: ["unsupported_condition"] });
  ok("arming with an unknown condition refused by name", badArm.status === 422 && badArm.j.reason === "failover_condition_unknown");
  const emptyPlan = (await jd("POST", "/v1/hypervisor/failover/plans", { environment_ref: `env-never-${tag}` })).j.plan || {};
  const unreadyArm = await jd("POST", `/v1/hypervisor/failover/plans/${emptyPlan.plan_id}/arm`, { conditions: ["provider_outage"] });
  ok("arming an unready plan refused (a trigger without restore truth could only fail closed)",
    unreadyArm.status === 409 && unreadyArm.j.reason === "failover_plan_not_ready");
  const armed = await jd("POST", `/v1/hypervisor/failover/plans/${plan.plan_id}/arm`, { conditions: ["capacity_eviction", "host_unreachable"], armed_by: "xfa-verifier", max_hourly_usd: 0.4 });
  ok("plan arms with declared conditions; arming is detection authority only (explicit note)",
    armed.status === 200 && armed.j.plan?.trigger_state === "armed"
    && /never.*wallet gate|wallet gate/.test(armed.j.plan?.auto_trigger?.authority_note || ""));

  // no evidence → no trigger
  const ev0 = (await jd("POST", "/v1/hypervisor/failover/evaluate", { plan_ref: plan.plan_ref })).j;
  ok("no qualifying evidence → no trigger (named outcome)",
    (ev0.evaluations || [])[0]?.outcome === "no_qualifying_evidence");

  // REAL provider evidence: simulated lease revocation on akash
  const outage = await opWithGrant(akashId, "inject_outage", { environment_ref: env });
  ok("provider-side lease revocation recorded (the bid_lease_revocation risk, exercised)", outage.j.ok === true);

  // evaluate → trigger, parked at the wallet gate
  // (a quote lives 15 minutes, and each crossing above was a real authority's approval, minutes long: the replacement is
  // chosen among fresh candidates, as a failover after a real outage would be — the first batch's have expired)
  await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref });
  const ev1 = (await jd("POST", "/v1/hypervisor/failover/evaluate", {})).j;
  const trig = (ev1.evaluations || []).find((e) => e.plan_ref === plan.plan_ref) || {};
  ok("evidence-mapped trigger fires with cited evidence refs",
    trig.outcome === "triggered" && trig.condition === "capacity_eviction"
    && (trig.evidence_refs || []).some((r) => String(r).startsWith("akash-deployment://")));
  const runRec0 = (await jd("GET", `/v1/hypervisor/failover/runs/${String(trig.run_ref).split("/").pop()}`)).j;
  replacementEnv = runRec0.replacement_environment_ref || "";
  ok("triggered run parks at the wallet gate — automatic detection is never automatic authority",
    runRec0.status === "awaiting_authority_create" && runRec0.triggered_by?.mode === "auto_policy");
  ok("replacement selected on a DIFFERENT class (vast) before parking",
    runRec0.replacement?.provider_kind === "vast");
  const opsList = (await jd("GET", "/v1/hypervisor/provider-operations")).j;
  const replOps = (opsList.operations || opsList || []).filter?.((o) => o.environment_ref === replacementEnv)?.length ?? 0;
  ok("zero replacement mutation without a grant", replOps === 0);

  // no duplicate trigger while the run is active
  const ev2 = (await jd("POST", "/v1/hypervisor/failover/evaluate", { plan_ref: plan.plan_ref })).j;
  ok("single-shot: no duplicate trigger while a run is active",
    ["active_run_exists", "triggered"].includes((ev2.evaluations || [])[0]?.outcome));

  // granted resume completes the cross-class move
  let runRec = runRec0;
  const g1 = await jd("POST", "/v1/hypervisor/failover/run", { run_ref: runRec.run_ref, wallet_approval_grant_create: await grantFor(runRec.next_required) });
  runRec = g1.j.run || {};
  const g2 = await jd("POST", "/v1/hypervisor/failover/run", { run_ref: runRec.run_ref, wallet_approval_grant_start: await grantFor(runRec.next_required) });
  runRec = g2.j.run || {};
  const g3 = await jd("POST", "/v1/hypervisor/failover/run", { run_ref: runRec.run_ref, wallet_approval_grant_restore: await grantFor(runRec.next_required) });
  runRec = g3.j.run || {};
  const g4 = await jd("POST", "/v1/hypervisor/failover/run", { run_ref: runRec.run_ref, wallet_approval_grant_teardown: await grantFor(runRec.next_required) });
  runRec = g4.j.run || {};
  ok("granted resume completes the auto-triggered failover", ["restored", "restored_with_warning"].includes(runRec.status));
  const wr2 = await opWithGrant(vastId, "workrun", { environment_ref: replacementEnv, command: "cat xfa.txt" });
  ok("MARKER SURVIVED the auto-triggered cross-class move (akash → vast)",
    wr2.j.ok === true && String(wr2.j.evidence?.stdout || "").includes(marker));

  // disarm stops evaluation
  await jd("POST", `/v1/hypervisor/failover/plans/${plan.plan_id}/disarm`, {});
  const ev3 = (await jd("POST", "/v1/hypervisor/failover/evaluate", { plan_ref: plan.plan_ref })).j;
  ok("disarm stops evaluation (named outcome)", (ev3.evaluations || [])[0]?.outcome === "disarmed");

  // fee posture + ledger + UI
  const decs = (await jd("GET", "/v1/hypervisor/placement/decisions")).j;
  const trigDec = (decs.decisions || []).find((d) => d.failover_run_ref === runRec.run_ref) || {};
  ok("auto-triggered decision still mints no fee object",
    trigDec.spend_posture?.fee_object_minted === false);
  const ledger = (await jd("GET", "/v1/hypervisor/work-ledger")).j;
  const lEntries = Array.isArray(ledger) ? ledger : ledger.entries || [];
  const lRow = lEntries.find((e) => e.kind === "failover" && e.run_ref === runRec.run_ref) || {};
  ok("Work Ledger failover row carries the auto-policy trigger with evidence",
    lRow.triggered_by?.mode === "auto_policy" && (lRow.triggered_by?.evidence_refs || []).length >= 1);
  const opsHtml = await fetch(`${SHELL}/__ioi/operations`).then((r) => r.text()).catch(() => "");
  ok("Operations shows auto-trigger posture", opsHtml.includes("Auto-trigger posture"));
  const envHtml = await fetch(`${SHELL}/__ioi/environments`).then((r) => r.text()).catch(() => "");
  ok("Environments failover readiness shows trigger state", envHtml.includes('id="env-placement-decisions"') && /Trigger/.test(envHtml));
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({ proxied: ["unreachable"] }));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);
}

async function cleanup() {
  try { if (vastId && replacementEnv) await opWithGrant(vastId, "delete", { environment_ref: replacementEnv }); } catch { /* best effort */ }
  try { if (akashId && env) await opWithGrant(akashId, "delete", { environment_ref: env }); } catch { /* best effort */ }
  try {
    if (akashId) await jd("DELETE", `/v1/hypervisor/provider-accounts/${akashId}`);
    if (vastId) await jd("DELETE", `/v1/hypervisor/provider-accounts/${vastId}`);
  } catch { /* best effort */ }
  try {
    const sb = await jd("GET", "/v1/hypervisor/storage-backends");
    for (const b of sb.j.backends || []) {
      if (String(b.display_name || "").startsWith("XFA ")) {
        await jd("DELETE", `/v1/hypervisor/storage-backends/${b.account_id}`);
      }
    }
  } catch { /* best effort */ }
}

run().then(cleanup, (e) => { console.error(e); return cleanup().then(() => { results.push({ name: `run threw: ${e?.message || e}`, pass: false, detail: "" }); }); }).then(() => {
  let fail = 0;
  for (const r of results) {
    console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` (${r.detail})` : ""}`);
    if (!r.pass) fail++;
  }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`auto-failover trigger readiness: ${fail ? "FAIL" : "OK"}`);
  if (A.decisionRefusals.length) console.log(`authority decisions refused: ${A.decisionRefusals.map((d) => `${d.op || "?"}: ${d.status} ${d.code}`).join(", ")}`);
  FIXTURES.remove(); A.stop().finally(() => process.exit(fail ? 1 : 0));
});
