#!/usr/bin/env node
// BYO provider plane done-bar.
//
// Proves the core product question: Hypervisor can run a governed lifecycle on a
// provider-backed node (bare-metal SSH — a real remote transport, not a local shortcut)
// while preserving authority (real wallet grants via the capability-lease gateway, never
// presence checks), workspace state (snapshot material streams into DAEMON custody and
// restore admits by sha256 state_root — blob existence is never restore truth), receipts
// (every crossing receipted, success AND failure), cost posture (external_spend budget
// discovery BEFORE any provider mutation; BYO spend customer-borne, zero fee objects),
// and honest substrate posture (EnvironmentClass enabled only when a real provider/account
// path backs it; cloud kinds are credential+preflight only and fail closed with named
// reasons; placement admits only verified accounts).
// Usage: node apps/hypervisor/scripts/verify-hypervisor-byo-provider-plane.mjs

import { readFileSync, writeFileSync, rmSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { mintApprovalGrant } = await import(path.join(HERE, "../../../scripts/lib/mint-approval-grant.mjs"));
const { ensureSshFixture } = await import(path.join(HERE, "ensure-ssh-fixture.mjs"));

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DATA = process.env.IOI_HYPERVISOR_DATA_DIR || path.join(os.homedir(), ".ioi", "hypervisor", "data");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}

const BUDGET_FILE = path.join(DATA, "resource-budgets", "byo-verify-external-spend.json");
async function preClean() {
  // Self-healing: a crashed prior run must not poison this one — sweep verifier-named accounts
  // and the verifier's external_spend budget record (the no-budget check needs its absence).
  const accounts = (await jd("GET", "/v1/hypervisor/provider-accounts")).j.accounts || [];
  for (const a of accounts) {
    if (/^(BYO node|BYO unverified|AWS) /.test(a.display_name || "")) {
      await jd("DELETE", `/v1/hypervisor/provider-accounts/${a.account_id}`);
    }
  }
  rmSync(BUDGET_FILE, { force: true });
}

async function run() {
  const tag = Date.now().toString(16);
  const fixture = await ensureSshFixture();
  await preClean();
  const SECRET = `SUPERSECRET-AWS-MATERIAL-${tag}`;
  // A distinctive middle line of the ssh private key — the leak-audit needle for sealed material.
  const keyNeedle = fixture.client_key.split("\n").find((l) => l.length > 30 && !l.startsWith("-----")) || "";

  // ── 1. Catalog: static adapters × durable accounts, spend + truth rules stated ──
  const cat0 = (await jd("GET", "/v1/hypervisor/providers")).j;
  const staticIds = (cat0.providers || []).map((p) => p.provider_ref);
  ok("providers catalog keeps the static adapter ladder + states spend/truth rules",
    ["local-microvm", "loopback-runner", "cloud-vpc"].every((id) => staticIds.includes(id))
    && /customer-borne/.test(cat0.spend_rule || "") && /evidence refs only/.test(cat0.truth_rule || ""));

  // ── 2. ProviderAccount object plane: CRUD + kind validation ──
  const badKind = await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "digitalocean", display_name: "nope" });
  const created = await jd("POST", "/v1/hypervisor/provider-accounts", {
    kind: "baremetal_ssh", display_name: `BYO node ${tag}`,
    endpoint: { host: fixture.host, port: fixture.port, user: fixture.user },
  });
  const acc = created.j.account || {};
  const patched = await jd("PATCH", `/v1/hypervisor/provider-accounts/${acc.account_id}`, { display_name: `BYO node ${tag} (patched)` });
  const got = await jd("GET", `/v1/hypervisor/provider-accounts/${acc.account_id}`);
  const listed = (await jd("GET", "/v1/hypervisor/provider-accounts")).j.accounts || [];
  ok("ProviderAccount CRUD round-trips as a durable record (invalid kind refused 422)",
    badKind.status === 422 && badKind.j.error?.code === "provider_kind_invalid"
    && created.status === 201 && acc.account_ref === `provider-account://${acc.account_id}`
    && acc.schema_version === "ioi.hypervisor.provider-account.v1" && acc.status === "unverified"
    && acc.provider_spend_borne_by === "customer"
    && patched.j.account?.display_name?.includes("(patched)")
    && got.j.account?.display_name?.includes("(patched)")
    && listed.some((a) => a.account_id === acc.account_id));

  // ── 3. Credential binding: sealed at rest, presence-provable, material never returned ──
  const bind = await jd("POST", `/v1/hypervisor/provider-accounts/${acc.account_id}/credential`, { private_key: fixture.client_key });
  const credDisk = readFileSync(path.join(DATA, "provider-credentials", `pcred_${acc.account_id}.json`), "utf8");
  ok("ssh_key credential binds sealed (fingerprint only in response, plaintext absent on disk)",
    bind.status === 201 && bind.j.credential?.sealed === true && bind.j.credential?.kind === "ssh-key"
    && String(bind.j.credential?.fingerprint || "").startsWith("sha256:")
    && !JSON.stringify(bind.j).includes(keyNeedle) && !credDisk.includes(keyNeedle)
    && bind.j.account?.credential_binding_ref === `credential://provider-credentials/pcred_${acc.account_id}`);

  // ── 4. Preflight: a REAL ssh probe admits with posture evidence ──
  const pf = await jd("POST", `/v1/hypervisor/provider-accounts/${acc.account_id}/preflight`);
  const pfEv = pf.j.account?.preflight?.evidence || {};
  ok("preflight runs a real ssh probe and admits with posture evidence",
    pf.j.ok === true && pf.j.account?.status === "verified"
    && /IOI-PREFLIGHT-OK/.test(pfEv.posture || "") && /tar-ok/.test(pfEv.posture || "")
    && String(pf.j.receipt_ref || "").startsWith("agentgres://provider-receipt/"));
  const cat1 = (await jd("GET", "/v1/hypervisor/providers")).j;
  const catAcc = (cat1.accounts || []).find((a) => a.account_ref === acc.account_ref) || {};
  ok("verified account surfaces as an available provider in the live catalog",
    catAcc.status === "available" && catAcc.provider_spend_borne_by === "customer");

  // ── 5. Authority: mutation needs a REAL wallet grant — presence strings do not pass ──
  const env = `env-byo-${tag}`;
  const opRaw = (o, extra = {}) => jd("POST", "/v1/hypervisor/provider-ops", { provider_id: acc.account_id, op: o, environment_ref: env, ...extra });
  const noGrant = await opRaw("create");
  const fakeRef = await opRaw("create", { grant_ref: "grant://not-a-real-grant" });
  ok("mutation without a wallet grant → 403 challenge echoing policy/request hashes (grant_ref presence does NOT pass)",
    noGrant.status === 403 && !!noGrant.j.approval?.policy_hash && !!noGrant.j.approval?.request_hash
    && fakeRef.status === 403);
  const op = async (o, extra = {}) => {
    const c = await opRaw(o, extra);
    if (c.status !== 403) return c;
    const grant = mintApprovalGrant({ policyHash: c.j.approval.policy_hash, requestHash: c.j.approval.request_hash });
    return opRaw(o, { ...extra, wallet_approval_grant: grant });
  };

  // ── 6-7. Real remote lifecycle: create → start → workrun over genuine ssh ──
  const createRes = await op("create");
  const startRes = await op("start");
  const marker = `byo-proof-${tag}`;
  const wr = await op("workrun", { command: `echo ${marker} > proof.txt && cat proof.txt && uname -s` });
  ok("create→start admit the node workspace over ssh (grant-authorized, lease receipted)",
    createRes.j.ok === true && createRes.j.evidence?.phase === "created"
    && String(createRes.j.receipt_ref || "").startsWith("agentgres://provider-receipt/")
    && startRes.j.ok === true && startRes.j.evidence?.phase === "ready");
  ok("workrun executes a real remote command with honest exit/stdout evidence",
    wr.j.ok === true && wr.j.evidence?.exit_code === 0
    && String(wr.j.evidence?.stdout || "").includes(marker) && /Linux|Darwin/.test(wr.j.evidence?.stdout || ""));
  const wrOpRec = ((await jd("GET", "/v1/hypervisor/provider-operations")).j.operations || [])
    .find((o) => o.op === "workrun" && o.account_ref === acc.account_ref) || {};
  ok("budget posture was discovered BEFORE mutation and recorded on the admitted op (ssh = local_free, customer-borne)",
    wrOpRec.budget_discovery?.discovered_before_mutation === true
    && wrOpRec.budget_discovery?.scope === "local_free"
    && wrOpRec.budget_discovery?.provider_spend_borne_by === "customer"
    && /customer_borne/.test(wrOpRec.cost_estimate?.basis || ""));

  // ── 8. Snapshot custody: material streams to the daemon; sha256 admitted as state_root ──
  const snap = await op("snapshot");
  const sev = snap.j.evidence || {};
  const mats = (await jd("GET", "/v1/hypervisor/provider-materials")).j;
  const mat = (mats.materials || []).find((m) => m.material_ref === sev.restore_material_ref) || {};
  const custodyBytes = readFileSync(mat.path);
  const recomputed = "sha256:" + createHash("sha256").update(custodyBytes).digest("hex");
  ok("snapshot streams material into DAEMON custody with an admitted sha256 state_root",
    snap.j.ok === true && sev.custody === "daemon" && sev.bytes > 0
    && String(sev.state_root || "").startsWith("sha256:")
    && mat.custody === "daemon" && mat.state_root === sev.state_root
    && recomputed === sev.state_root
    && /blob existence is not restore truth/.test(mats.custody_rule || ""));

  // ── 9. Outage → honest observe → recover from admitted custody material ──
  const outage = await op("inject_outage");
  const obsOut = await op("observe");
  const rec = await op("recover");
  const wrBack = await op("workrun", { command: "cat proof.txt" });
  ok("inject_outage loses the remote workspace and observe reports it honestly",
    outage.j.ok === true && outage.j.evidence?.workspace_lost === true
    && obsOut.j.evidence?.phase === "outage");
  ok("recover restores from daemon custody with the state_root verified, and the workspace survives",
    rec.j.ok === true && rec.j.evidence?.state_root_verified === sev.state_root
    && String(wrBack.j.evidence?.stdout || "").includes(marker));

  // ── 10. Restore truth = daemon admission: valid hash restores; unknown/corrupt fail closed ──
  const restoreValid = await op("restore", { material_ref: sev.restore_material_ref });
  const restoreUnknown = await op("restore", { material_ref: "provider-material://bogus/none/0" });
  writeFileSync(mat.path, Buffer.from(`corrupted-bytes-${tag}`));
  const restoreCorrupt = await op("restore", { material_ref: sev.restore_material_ref });
  ok("restore admits by matching sha256 and fails closed on unknown material",
    restoreValid.j.ok === true && restoreValid.j.evidence?.state_root_verified === sev.state_root
    && restoreUnknown.j.ok === false && /not daemon-admitted/.test(restoreUnknown.j.reason || ""));
  ok("corrupted custody bytes → restore refused (hash mismatch, receipted — blob existence is not truth)",
    restoreCorrupt.j.ok === false && restoreCorrupt.j.outcome === "restore_refused"
    && /hash_mismatch|hash mismatch/i.test(restoreCorrupt.j.reason || "")
    && String(restoreCorrupt.j.receipt_ref || "").startsWith("agentgres://provider-receipt/"));

  // ── 11. Delete: remote cleanup verified, observe honest afterwards ──
  const del = await op("delete");
  const obsGone = await op("observe");
  ok("delete verifies remote cleanup and observe reports the node absent",
    del.j.ok === true && del.j.evidence?.cleanup_verified === true
    && obsGone.j.evidence?.phase === "absent");

  // ── 12. Receipts: success AND failure crossings receipted with account/grant/lease enrichment ──
  const receipts = ((await jd("GET", "/v1/hypervisor/provider-receipts")).j.receipts || [])
    .filter((r) => r.account_ref === acc.account_ref || r.environment_ref === env);
  const okReceipt = receipts.find((r) => r.op === "workrun" && r.outcome === "ok") || {};
  const failReceipt = receipts.find((r) => r.outcome === "restore_refused");
  const authReceipt = receipts.find((r) => r.outcome === "authority_missing");
  ok("provider receipts embed account_ref + grant_ref + capability_lease descriptor + budget discovery",
    String(okReceipt.grant_ref || "").length > 0 && okReceipt.capability_lease?.lease_id
    && (okReceipt.capability_lease.allowed_tools || []).includes("provider.workrun")
    && okReceipt.budget_discovery?.discovered_before_mutation === true);
  ok("failure crossings are receipted too (refused restore + refused authority are evidence)",
    !!failReceipt && !!authReceipt);
  const leases = ((await jd("GET", "/v1/hypervisor/capability-leases")).j.leases || [])
    .filter((l) => String(l.backing_provider || "") === `provider:account:${acc.account_id}`);
  ok("capability leases persisted for provider crossings carry no secret material",
    leases.length >= 3 && !JSON.stringify(leases).includes(keyNeedle));

  // ── 13. Revoke: credential removal fails ops closed (428) ──
  const revoke = await jd("DELETE", `/v1/hypervisor/provider-accounts/${acc.account_id}/credential`);
  const afterRevoke = await opRaw("create");
  ok("credential revoke flips the account and creds-required ops fail closed 428 (receipted)",
    revoke.j.ok === true && revoke.j.account?.status === "revoked"
    && afterRevoke.status === 428 && /credential/.test(afterRevoke.j.reason || "")
    && String(afterRevoke.j.receipt_ref || "").startsWith("agentgres://provider-receipt/"));

  // ── 14. Cloud kinds: credential + preflight only; lifecycle fails closed with named reasons ──
  const aws = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "aws", display_name: `AWS ${tag}` })).j.account || {};
  await jd("POST", `/v1/hypervisor/provider-accounts/${aws.account_id}/credential`, { secret_access_key: SECRET, aux: { access_key_id: "AKIA-TEST", region: "us-east-1" } });
  const awsPf = await jd("POST", `/v1/hypervisor/provider-accounts/${aws.account_id}/preflight`);
  ok("cloud kind (aws) binds aws-sigv4 credential and preflights honestly as credential-only",
    awsPf.j.ok === true && awsPf.j.account?.status === "verified"
    && awsPf.j.account?.preflight?.evidence?.lifecycle === "credential_preflight_only"
    && /no cloud API call/.test(awsPf.j.account?.preflight?.evidence?.probe || ""));

  // ── 15. Budget discovery gates metered kinds BEFORE authority/mutation ──
  const awsEnv = `env-aws-${tag}`;
  const awsNoBudget = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: aws.account_id, op: "create", environment_ref: awsEnv });
  ok("metered provider mutation without an external_spend budget → budget_blocked BEFORE any crossing",
    awsNoBudget.status === 409 && /budget_undiscovered_before_mutation/.test(awsNoBudget.j.reason || "")
    && String(awsNoBudget.j.receipt_ref || "").startsWith("agentgres://provider-receipt/"));
  await jd("POST", "/v1/hypervisor/resource/budgets", { budget_id: "byo-verify-external-spend", name: "BYO verifier external spend", scope: "external_spend", limit: 100, spent: 0, currency: "USD" });
  const awsChallenged = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: aws.account_id, op: "create", environment_ref: awsEnv });
  const awsGrant = mintApprovalGrant({ policyHash: awsChallenged.j.approval.policy_hash, requestHash: awsChallenged.j.approval.request_hash });
  const awsCreate = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: aws.account_id, op: "create", environment_ref: awsEnv, wallet_approval_grant: awsGrant });
  ok("with budget + real grant, cloud lifecycle still fails closed with a NAMED not-implemented reason (never faked)",
    awsChallenged.status === 403
    && awsCreate.j.ok === false && awsCreate.j.outcome === "not_implemented"
    && /PROVIDER_KIND_LIFECYCLE_NOT_IMPLEMENTED/.test(awsCreate.j.reason || "")
    && awsCreate.j.reason.includes("aws"));

  // ── 16. Secret custody: no provider secret in ANY projection; sealed on disk ──
  const surfaces = {
    providers: (await jd("GET", "/v1/hypervisor/providers")).j,
    accounts: (await jd("GET", "/v1/hypervisor/provider-accounts")).j,
    account_get: (await jd("GET", `/v1/hypervisor/provider-accounts/${aws.account_id}`)).j,
    operations: (await jd("GET", "/v1/hypervisor/provider-operations")).j,
    receipts: (await jd("GET", "/v1/hypervisor/provider-receipts")).j,
    materials: (await jd("GET", "/v1/hypervisor/provider-materials")).j,
    leases: (await jd("GET", "/v1/hypervisor/capability-leases")).j,
  };
  const leaks = Object.entries(surfaces)
    .filter(([, j]) => { const s = JSON.stringify(j); return s.includes(SECRET) || (keyNeedle && s.includes(keyNeedle)); })
    .map(([n]) => n);
  const awsCredDisk = readFileSync(path.join(DATA, "provider-credentials", `pcred_${aws.account_id}.json`), "utf8");
  ok("provider secrets never leak — absent from every projection, sealed (not plaintext) at rest",
    leaks.length === 0 && !awsCredDisk.includes(SECRET) && awsCredDisk.includes("sealed_secret_access_key"),
    leaks.length ? `leaked: ${leaks.join(",")}` : "");

  // ── 17. No fee/markup objects anywhere on the plane (routing-fee covenant: this cut takes NO fee) ──
  const feeAudit = JSON.stringify(surfaces).toLowerCase();
  // routing_fee_eligibility / routing_fee_basis are canon SpendEstimate LABELS (declared copy);
  // fee OBJECTS — amounts, charges, broker fees, RoutingDecisionReceipt — stay forbidden.
  const feeAuditScrubbed = feeAudit.replace(/routing_fee_(eligibility|basis)/g, "");
  ok("zero fee objects: no routing_fee / broker_fee / platform markup / RoutingDecisionReceipt on any provider surface",
    !feeAuditScrubbed.includes("routing_fee") && !feeAuditScrubbed.includes("broker_fee") && !feeAuditScrubbed.includes("routingdecisionreceipt")
    && !feeAuditScrubbed.includes("markup\":") && /customer-borne/.test(surfaces.providers.spend_rule || ""));

  // ── 18. EnvironmentClass durability + honesty ──
  const classes = (await jd("GET", "/v1/hypervisor/environment-classes")).j.environmentClasses || [];
  const cls = Object.fromEntries(classes.map((c) => [c.id, c]));
  ok("environment classes are durable records with provider eligibility (kinds/capabilities/credential/spend)",
    classes.every((c) => c.schema_version === "ioi.hypervisor.environment-class.v1")
    && cls["byo-ssh-node"]?.provider_eligibility?.credential_kind === "ssh_key"
    && cls["byo-ssh-node"]?.provider_eligibility?.spend_posture === "customer_borne_byo"
    && (cls["byo-ssh-node"]?.provider_eligibility?.required_capabilities || []).includes("ssh"));
  ok("class enabled-honesty: microvm gap fixed; vm/devcontainer honestly disabled (no real path)",
    cls["microvm"]?.enabled === true && cls["microvm"]?.enabled_backing?.real === true
    && cls["local-workspace-v0"]?.enabled === true
    && cls["vm"]?.enabled === false && cls["vm"]?.enabled_backing?.real === false
    && cls["devcontainer"]?.enabled === false);

  // ── 19. Placement: verified accounts placeable, unverified rejected honestly ──
  const ssh2 = (await jd("POST", "/v1/hypervisor/provider-accounts", {
    kind: "baremetal_ssh", display_name: `BYO unverified ${tag}`,
    endpoint: { host: fixture.host, port: fixture.port, user: fixture.user },
  })).j.account || {};
  await jd("POST", `/v1/hypervisor/provider-accounts/${acc.account_id}/credential`, { private_key: fixture.client_key });
  await jd("POST", `/v1/hypervisor/provider-accounts/${acc.account_id}/preflight`); // re-verify the revoked account
  const byoClassNow = ((await jd("GET", "/v1/hypervisor/environment-classes")).j.environmentClasses || []).find((c) => c.id === "byo-ssh-node") || {};
  ok("byo-ssh-node class is enabled ONLY while a verified baremetal_ssh account backs it",
    byoClassNow.enabled === true && byoClassNow.enabled_backing?.verified_accounts >= 1);
  const placement = (await jd("POST", "/v1/hypervisor/placement/resolve", { trust: "trusted", residency: "any", class: "byo-ssh-node", project_id: `byo-${tag}` })).j;
  const dec = placement.decision || {};
  const eligibleRefs = (dec.eligible || []).map((e) => e.provider_ref);
  const rejectedMap = Object.fromEntries((dec.rejected || []).map((r) => [r.provider_ref, r.reason]));
  ok("placement reads the LIVE account catalog: verified account eligible, unverified rejected with an honest reason",
    eligibleRefs.includes(`account:${acc.account_id}`)
    && /unverified/.test(rejectedMap[`account:${ssh2.account_id}`] || "")
    && String(dec.decision_id || "").startsWith("plc_"));

  // ── 20. Surfaces: Environments carries Provider accounts; Operations carries provider health ──
  const envHtml = await fetch(`${SHELL}/__ioi/environments`).then((r) => r.text());
  ok("Environments surface shows Provider accounts with customer-borne spend stated plainly",
    envHtml.includes('id="env-provider-accounts"') && envHtml.includes(acc.account_ref)
    && /customer-borne/i.test(envHtml) && /byo-ssh-node/.test(envHtml));
  const opsHtml = await fetch(`${SHELL}/__ioi/operations`).then((r) => r.text());
  ok("Operations surface shows provider health + recent provider receipts",
    opsHtml.includes('id="ops-provider-health"') && opsHtml.includes(acc.account_ref)
    && /Recent provider receipts/i.test(opsHtml) && /customer-borne spend/i.test(opsHtml));
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup (receipts/operations/materials remain by design — they are evidence) ──
  await jd("DELETE", `/v1/hypervisor/provider-accounts/${ssh2.account_id}`);
  await jd("DELETE", `/v1/hypervisor/provider-accounts/${aws.account_id}`);
  await jd("DELETE", `/v1/hypervisor/provider-accounts/${acc.account_id}`);
  rmSync(BUDGET_FILE, { force: true });
  const byoClassAfter = ((await jd("GET", "/v1/hypervisor/environment-classes")).j.environmentClasses || []).find((c) => c.id === "byo-ssh-node") || {};
  const accountsAfter = (await jd("GET", "/v1/hypervisor/provider-accounts")).j.accounts || [];
  ok("cleanup: accounts removed and byo-ssh-node class honestly flips back to disabled",
    !accountsAfter.some((a) => [acc.account_id, aws.account_id, ssh2.account_id].includes(a.account_id))
    && byoClassAfter.enabled === false);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`byo provider plane readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
