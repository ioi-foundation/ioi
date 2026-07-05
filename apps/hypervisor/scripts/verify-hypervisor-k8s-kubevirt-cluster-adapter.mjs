#!/usr/bin/env node
// K8s/KubeVirt cluster adapter done-bar — the CLUSTER substrate lane (canon ladder #7), and
// deliberately NOT fake single-VM SSH: clusters are clusters. Namespace-scoped admission
// (RBAC/quota/PVC/GPU/service posture, each failing closed by NAME), Kubernetes exec semantics
// (a process in the workload — never an ssh hop), PVC/VolumeSnapshot names as evidence only
// under daemon state-root restore truth, KubeVirt VMIs when CRDs exist (explicitly KubeVirt),
// and spend honesty: customer/operator clusters have NO direct provider price — no exposure
// opens without a DECLARED metered posture AND a sourced price. IOI_K8S_LIVE=1 without
// credentials BLOCKS named.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-k8s-kubevirt-cluster-adapter.mjs

import path from "node:path";
import os from "node:os";
import { writeFileSync, rmSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { mintApprovalGrant } = await import(path.join(HERE, "../../../scripts/lib/mint-approval-grant.mjs"));

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DATA = process.env.IOI_HYPERVISOR_DATA_DIR || path.join(os.homedir(), ".ioi", "hypervisor", "data");
const BUDGET_FILE = path.join(DATA, "resource-budgets", "k8s-verify.json");
const LIVE_MODE = process.env.IOI_K8S_LIVE === "1";
const LIVE_KEY = process.env.IOI_K8S_TOKEN || "";

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const k8sSource = async () => {
  const s = (await jd("GET", "/v1/hypervisor/cloud-candidates/candidate-sources")).j;
  return (s.sources || []).find((x) => x.source === "k8s") || {};
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
  env = `env-k8s-${tag}`;
  rmSync(BUDGET_FILE, { force: true });
  const dir = path.join(os.homedir(), ".ioi", "hypervisor", "vast-fixture");
  mkdirSync(dir, { recursive: true });
  const factsFile = path.join(dir, `k8s-facts-${tag}.json`);
  const factsNoKubevirt = path.join(dir, `k8s-facts-nokv-${tag}.json`);
  const facts = {
    cluster: { name: "sim-cluster", context: "sim-context", version: "v1.30" },
    namespaces: [
      { name: "ioi-sim", authorized: true, quota: { cpu_milli_available: 16000, memory_gb_available: 64, gpu_available: 1 } },
      { name: "locked-ns", authorized: false, quota: {} },
    ],
    runtime_classes: ["runc", "kata"],
    gpu: { device_plugin: "nvidia", nodes_with_gpu: 2, models: ["A100"] },
    storage_classes: [{ name: "standard-rwo", pvc_supported: true }, { name: "local-ephemeral", pvc_supported: false }],
    services: { cluster_ip: true, load_balancer: false, ingress_class: "nginx" },
    kubevirt: { installed: true, crd_version: "v1" },
  };
  writeFileSync(factsFile, JSON.stringify(facts));
  writeFileSync(factsNoKubevirt, JSON.stringify({ ...facts, kubevirt: { installed: false } }));

  // ── 1. Kind + kubeconfig credential + source posture ladder ──
  const k8s = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "k8s", display_name: `K8s ${tag}` })).j.account || {};
  accountId = k8s.account_id;
  ok("`k8s` account kind validates with CLUSTER capabilities (namespace admission, k8s exec, PVC posture, KubeVirt, never fake single-VM SSH)",
    k8s.account_ref?.startsWith("provider-account://")
    && /treated as CLUSTERS/.test(k8s.capabilities?.lane || "")
    && /never fake single-VM SSH/.test(k8s.capabilities?.lane || "")
    && /fail closed by name/.test(k8s.capabilities?.admission || "")
    && /Kubernetes exec semantics/.test(k8s.capabilities?.exec || "")
    && /CLUSTER posture/.test(k8s.capabilities?.storage || "")
    && /explicitly KubeVirt/.test(k8s.capabilities?.kubevirt || "")
    && /no direct provider price/.test(k8s.capabilities?.provider_spend || ""));
  const s0 = await k8sSource();
  ok("no credential → k8s source unavailable with evidence",
    s0.state === "candidate_source_unavailable" && /k8s_credential_absent/.test(s0.reason || ""));
  const KUBECONFIG = `apiVersion: v1\nkind: Config\nclusters: [SECRET-${tag}]`;
  const bind = await jd("POST", `/v1/hypervisor/provider-accounts/${k8s.account_id}/credential`, {
    kubeconfig: KUBECONFIG, aux: { namespace: "ioi-sim", cluster: "sim-cluster" },
  });
  const pf = await jd("POST", `/v1/hypervisor/provider-accounts/${k8s.account_id}/preflight`);
  ok("kubeconfig credential seals (kind kubeconfig) — plaintext never leaks; verified but unprobed → no cluster claim",
    bind.j.ok !== false && bind.j.credential?.kind === "kubeconfig" && bind.j.credential?.sealed === true
    && !JSON.stringify(bind.j).includes(`SECRET-${tag}`)
    && pf.j.ok === true && !JSON.stringify(pf.j).includes(`SECRET-${tag}`)
    && (await k8sSource()).state === "credential_verified_unprobed");

  // ── 2. Degraded live probe → zero fake cluster facts ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${k8s.account_id}`, { endpoint: { mode: "live", endpoint: "https://127.0.0.1:9", ca_mode: "insecure_dev" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${k8s.account_id}/preflight`);
  const intent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "compute.container", resource_classes: ["compute.container", "compute.gpu_runtime"],
  })).j.intent || {};
  const degraded = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  ok("unreachable live API server → degraded_unreachable with evidence, zero fake cluster candidates",
    (await k8sSource()).state === "degraded_unreachable"
    && !(degraded.candidates || []).some((c) => c.provider_kind === "k8s")
    && (degraded.rejected || []).some((r) => r.reason_code === "candidate_source_degraded" && /k8s/.test(r.adapter_ref || "")));

  // ── 3. Fixture facts normalize: cluster semantics, RBAC rejections NAMED, unpriced ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${k8s.account_id}`, { endpoint: { mode: "fixture", fixture_file: factsFile } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${k8s.account_id}/preflight`);
  const fixed = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const kc = (fixed.candidates || []).filter((c) => c.provider_kind === "k8s");
  const nsCand = kc.find((c) => c.namespace === "ioi-sim") || {};
  ok("cluster facts normalize per AUTHORIZED namespace with cluster semantics (quota/GPU/storage classes/services/KubeVirt); UNPRICED customer cluster",
    kc.length === 1
    && nsCand.cluster?.name === "sim-cluster" && nsCand.namespace === "ioi-sim"
    && nsCand.quota?.cpu_milli_available === 16000
    && nsCand.gpu?.device_plugin === "nvidia" && nsCand.gpu?.namespace_gpu_available === 1
    && (nsCand.storage?.storage_classes || []).some((c) => c.name === "standard-rwo")
    && nsCand.network?.services?.load_balancer === false
    && nsCand.kubevirt?.installed === true
    && nsCand.quote === null && /unpriced — customer\/operator-owned/.test(nsCand.quote_state || "")
    && nsCand.spend_estimate?.state === "customer_operator_borne");
  ok("unauthorized namespace REJECTED by name (RBAC posture, never silently skipped); cluster risk labels; advisory forever",
    (fixed.rejected || []).some((r) => r.reason_code === "k8s_namespace_unauthorized" && /locked-ns/.test(r.detail || ""))
    && (nsCand.risk_labels || []).includes("quota_exhaustion")
    && (nsCand.risk_labels || []).includes("cluster_operator_controlled")
    && (nsCand.risk_labels || []).includes("storage_not_restore_truth")
    && (nsCand.risk_labels || []).includes("ingress_policy_required")
    && nsCand.placement_eligible === "advisory_only" && nsCand.evidence_mode === "fixture_evidence");

  // ── 4. Admission gate: fixture refusal + NAMED fail-closed admission rungs ──
  const simEndpoint = { mode: "simulator", fixture_file: factsFile, namespace: "ioi-sim", cluster: "sim-cluster" };
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${k8s.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${k8s.account_id}/preflight`);
  const fixCreate = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: env, candidate_ref: nsCand.candidate_ref });
  const sim = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand = (sim.candidates || []).find((c) => c.provider_kind === "k8s" && c.namespace === "ioi-sim") || {};
  ok("fixture facts can never admit (k8s_quote_not_live) — and NO budget was demanded (customer cluster, unmetered by default)",
    fixCreate.status === 409 && /k8s_quote_not_live/.test(fixCreate.j.reason || ""));
  const admit = (extra) => opWithGrant("create", { environment_ref: env, candidate_ref: cand.candidate_ref, teardown_policy: "always_teardown_required", ...extra });
  const badNs = await admit({ namespace: "locked-ns" });
  const ghostNs = await admit({ namespace: "ghost-ns" });
  const overQuota = await admit({ resources: { cpu_milli: 99000, memory_gb: 4, gpu: 0 } });
  ok("namespace admission fails CLOSED by name (unauthorized RBAC + missing namespace + quota)",
    badNs.j.ok === false && /k8s_namespace_unauthorized/.test(badNs.j.reason || "")
    && ghostNs.j.ok === false && /k8s_namespace_missing/.test(ghostNs.j.reason || "")
    && overQuota.j.ok === false && /k8s_quota_insufficient/.test(overQuota.j.reason || ""));
  const badGpu = await admit({ resources: { cpu_milli: 2000, memory_gb: 4, gpu: 5 } });
  const badPvc = await admit({ pvc: { storage_class: "local-ephemeral", size_gb: 10 } });
  const badLb = await admit({ service: { type: "LoadBalancer", port: 8080 } });
  ok("GPU/PVC/service admission fails CLOSED by name (unschedulable GPU + PVC-less storage class + no LoadBalancer)",
    badGpu.j.ok === false && /k8s_gpu_unschedulable/.test(badGpu.j.reason || "")
    && badPvc.j.ok === false && /k8s_pvc_storage_class_unavailable/.test(badPvc.j.reason || "")
    && badLb.j.ok === false && /k8s_service_ingress_unsupported/.test(badLb.j.reason || ""));

  // ── 5. Happy admission: wallet binds the workload spec; create → ready → exec ──
  const createBase = { provider_id: accountId, op: "create", environment_ref: env,
    candidate_ref: cand.candidate_ref, teardown_policy: "always_teardown_required",
    namespace: "ioi-sim", image: "ubuntu:24.04",
    resources: { cpu_milli: 2000, memory_gb: 4, gpu: 1 },
    pvc: { storage_class: "standard-rwo", size_gb: 10 },
    service: { type: "ClusterIP", port: 8080 } };
  const challenge = await jd("POST", "/v1/hypervisor/provider-ops", createBase);
  const facets = challenge.j.lease_request_facets || {};
  ok("wallet challenge binds CLUSTER facets (namespace + workload spec hash + kubernetes exec posture + teardown) — no price facet exists",
    challenge.status === 403
    && facets.namespace === "ioi-sim"
    && String(facets.workload_spec_hash || "").startsWith("sha256:")
    && facets.exec_posture === "kubernetes_exec"
    && facets.teardown_policy === "always_teardown_required"
    && (facets.usd_per_hour === null || facets.usd_per_hour === undefined));
  const grant = mintApprovalGrant({ policyHash: challenge.j.approval.policy_hash, requestHash: challenge.j.approval.request_hash });
  const created = await jd("POST", "/v1/hypervisor/provider-ops", { ...createBase, wallet_approval_grant: grant });
  ok("admitted create mints the workload — pod/PVC/service names + uid EVIDENCE ONLY, Pending until readiness",
    created.j.ok === true
    && String(created.j.evidence?.workload?.workload_name || "").startsWith("pod-sim-")
    && created.j.evidence?.workload?.workload_class === "pod"
    && created.j.evidence?.ready === false
    && created.j.evidence?.live_provisioning_not_run === true
    && String(created.j.evidence?.provider_native?.pvc?.pvc_name || "").startsWith("pvc-sim-")
    && String(created.j.evidence?.provider_native?.service?.service_name || "").startsWith("svc-sim-")
    && /evidence only/.test(created.j.evidence?.provider_native?.note || ""));
  const preReady = await opWithGrant("workrun", { command: "echo too-early" });
  ok("pre-ready exec fails CLOSED (k8s_workload_not_ready — pod phase alone is never readiness)",
    preReady.j.ok === false && /k8s_workload_not_ready/.test(preReady.j.reason || ""));
  const started = await opWithGrant("start");
  ok("start proves readiness through the exec lane (probe round-trip), with service exposure as evidence",
    started.j.ok === true && started.j.evidence?.ready === true
    && /exec round-trip/.test(started.j.evidence?.ready_evidence?.probe || "")
    && /pod phase alone was not treated as readiness/.test(started.j.evidence?.ready_evidence?.note || "")
    && String(started.j.evidence?.service?.service_name || "").startsWith("svc-sim-"));
  const marker = `k8s-${tag}`;
  const wr = await opWithGrant("workrun", { command: `echo ${marker} > workload.txt && cat workload.txt` });
  const logs = await opWithGrant("logs");
  const events = await opWithGrant("events");
  const eventKinds = (events.j.evidence?.events || []).map((e) => e.kind);
  ok("exec is KUBERNETES exec (a process in the workload — never an ssh hop); logs/events honest",
    wr.j.ok === true && String(wr.j.evidence?.stdout || "").includes(marker)
    && /never an ssh hop/.test(wr.j.evidence?.exec_lane || "")
    && logs.j.ok === true && /unavailable_in_simulator/.test(logs.j.evidence?.container_logs || "")
    && ["workload_admitted", "workload_ready", "exec"].every((k) => eventKinds.includes(k)));

  // ── 6. Custody: snapshot/restore + storage plane; NO exposure (unpriced customer cluster) ──
  const snap = await opWithGrant("snapshot");
  const sev = snap.j.evidence || {};
  const restored = await opWithGrant("restore", { material_ref: sev.restore_material_ref });
  ok("workload fs snapshots to DAEMON custody (sha256 root); VolumeSnapshot name evidence-only; restore verifies the root",
    sev.custody === "daemon" && String(sev.state_root || "").startsWith("sha256:")
    && String(sev.provider_native_snapshot?.volume_snapshot_name || "").startsWith("volumesnapshot-sim-")
    && /NEVER restore truth/.test(sev.provider_native_snapshot?.note || "")
    && restored.j.ok === true && restored.j.evidence?.state_root_verified === sev.state_root);
  const cas = (await jd("POST", "/v1/hypervisor/storage-backends", { kind: "cas", display_name: `K8s CAS ${tag}` })).j.backend || {};
  casBackendId = cas.account_id;
  await jd("POST", `/v1/hypervisor/storage-backends/${cas.account_id}/preflight`);
  const exported = await archiveOp({ op: "export", backend_id: cas.account_id, material_ref: sev.restore_material_ref });
  const archRestore = await archiveOp({ op: "restore", archive_ref: exported.j.archive?.archive_ref });
  ok("archive export + storage-validated restore ride the storage plane (state_root is the only truth)",
    exported.j.ok === true && archRestore.j.ok === true && archRestore.j.state_root_verified === sev.state_root);
  const recon = (await jd("GET", "/v1/hypervisor/provider-spend/reconciliation")).j;
  const receipts = ((await jd("GET", "/v1/hypervisor/provider-receipts")).j.receipts || [])
    .filter((r) => r.account_ref === k8s.account_ref);
  ok("NO exposure opens on a customer/operator cluster — budget posture is cluster_customer_operated, nothing priced, nothing invented",
    !(recon.rows || []).some((e) => e.account_ref === k8s.account_ref)
    && receipts.some((r) => r.op === "create" && r.outcome === "ok" && r.budget_discovery?.scope === "cluster_customer_operated"));
  const stopped = await opWithGrant("stop");
  const del1 = await opWithGrant("delete");
  ok("stop/delete are honest cluster ops (no metered lane; PVC posture named; teardown always)",
    stopped.j.ok === true && /no direct provider price/.test(stopped.j.evidence?.spend_note || "")
    && del1.j.ok === true && del1.j.evidence?.teardown_state === "torn_down"
    && del1.j.evidence?.native_teardown?.destroyed === true);

  // ── 7. KubeVirt: explicitly KubeVirt VMIs; CRDs absent fails closed ──
  const env2 = `env-k8s2-${tag}`;
  const sim2 = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand2 = (sim2.candidates || []).find((c) => c.provider_kind === "k8s" && c.namespace === "ioi-sim") || {};
  const kvCreated = await opWithGrant("create", { environment_ref: env2, candidate_ref: cand2.candidate_ref,
    namespace: "ioi-sim", kubevirt: true, resources: { cpu_milli: 2000, memory_gb: 4, gpu: 0 }, teardown_policy: "always_teardown_required" });
  const kvStart = await opWithGrant("start", { environment_ref: env2 });
  const kvDel = await opWithGrant("delete", { environment_ref: env2 });
  ok("KubeVirt path is EXPLICITLY KubeVirt (vmi-sim-* VMI, never a generic VM) with a working lifecycle",
    kvCreated.j.ok === true
    && kvCreated.j.evidence?.workload?.workload_class === "kubevirt_vmi"
    && String(kvCreated.j.evidence?.workload?.workload_name || "").startsWith("vmi-sim-")
    && /explicitly KubeVirt/.test(kvCreated.j.evidence?.provider_native?.note || "")
    && kvStart.j.ok === true && kvDel.j.ok === true);
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${k8s.account_id}`, { endpoint: { ...simEndpoint, fixture_file: factsNoKubevirt } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${k8s.account_id}/preflight`);
  const sim3 = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand3 = (sim3.candidates || []).find((c) => c.provider_kind === "k8s" && c.namespace === "ioi-sim") || {};
  const kvAbsent = await opWithGrant("create", { environment_ref: `env-k8s3-${tag}`, candidate_ref: cand3.candidate_ref,
    namespace: "ioi-sim", kubevirt: true, resources: { cpu_milli: 1000, memory_gb: 2, gpu: 0 } });
  ok("KubeVirt requested but CRDs absent → fails CLOSED by name (candidate said so too)",
    kvAbsent.j.ok === false && /k8s_kubevirt_crds_absent/.test(kvAbsent.j.reason || "")
    && cand3.kubevirt?.installed === false && /fail closed by name/.test(cand3.kubevirt?.note || ""));

  // ── 8. Metered posture honesty: declared metering demands a SOURCED price ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${k8s.account_id}`, { endpoint: { ...simEndpoint, metered: { declared: true } } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${k8s.account_id}/preflight`);
  const noBudget = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: `env-k8s4-${tag}`, candidate_ref: cand3.candidate_ref });
  await jd("POST", "/v1/hypervisor/resource/budgets", { budget_id: "k8s-verify", name: "K8s verify", scope: "external_spend", limit: 5, spent: 0, currency: "USD" });
  const sim4 = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const cand4 = (sim4.candidates || []).find((c) => c.provider_kind === "k8s" && c.namespace === "ioi-sim") || {};
  const unpricedMetered = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: `env-k8s4-${tag}`, candidate_ref: cand4.candidate_ref });
  ok("DECLARED metered posture flips the budget gate AND refuses unpriced candidates (exposure only with a sourced price)",
    noBudget.status === 409 && /budget_undiscovered_before_mutation/.test(noBudget.j.reason || "")
    && unpricedMetered.status === 409 && /k8s_metered_posture_unpriced/.test(unpricedMetered.j.reason || ""));

  // ── 9. Surfaces + live honesty + invariants ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${k8s.account_id}`, { endpoint: simEndpoint });
  await jd("POST", `/v1/hypervisor/provider-accounts/${k8s.account_id}/preflight`);
  const ledger = ((await jd("GET", "/v1/hypervisor/work-ledger")).j.entries || [])
    .filter((e) => e.kind === "provider_crossing" && e.account_ref === k8s.account_ref);
  ok("Work Ledger provider crossings include the cluster lifecycle (create/workrun/snapshot/delete)",
    ["create", "workrun", "snapshot", "delete"].every((o) => ledger.some((e) => e.op === o && e.status === "ok")));
  const opsHtml = await fetch(`${SHELL}/__ioi/operations`).then((r) => r.text());
  const envHtml = await fetch(`${SHELL}/__ioi/environments`).then((r) => r.text());
  const venues = JSON.stringify((await jd("GET", "/v1/hypervisor/placement/venues")).j);
  ok("Operations + Environments show cluster posture (cluster/namespace); venues show the cluster lane distinctly",
    /k8s/i.test(opsHtml) && envHtml.includes(k8s.account_ref)
    && /sim-cluster · ns: ioi-sim/.test(envHtml)
    && /GPU device-plugin scheduling per namespace quota \(guarded adapter\)/.test(venues));
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${k8s.account_id}`, { endpoint: { mode: "live", endpoint: "https://127.0.0.1:9", ca_mode: "insecure_dev" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${k8s.account_id}/preflight`);
  const liveCreate = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "create", environment_ref: `env-k8s5-${tag}`, candidate_ref: cand4.candidate_ref });
  ok("live mode blocks NAMED — live admission demands live cluster facts, never a fake workload",
    liveCreate.status === 409 && /k8s_quote_mode_mismatch|k8s_quote_expired_requires_requote/.test(liveCreate.j.reason || ""));
  if (LIVE_MODE && !LIVE_KEY) {
    ok("k8s_live_credentials_absent — IOI_K8S_LIVE=1 requires IOI_K8S_TOKEN; live execution BLOCKED (not faked)", false);
  } else if (!LIVE_MODE) {
    ok("live_provisioning_not_run — simulator validated the cluster ladder; live cluster access is NOT claimed", true);
  }
  const audit = JSON.stringify({ recon, sim2 }).toLowerCase();
  ok("no fee objects, no RoutingDecisionReceipt, no markup",
    !audit.includes("routingdecisionreceipt") && !audit.includes("fee_amount") && !audit.includes("markup\":"));
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);
}

async function cleanup() {
  try {
    if (accountId && env) {
      for (const e of [env, env.replace("env-k8s-", "env-k8s2-"), env.replace("env-k8s-", "env-k8s3-")]) {
        const obs = await jd("POST", "/v1/hypervisor/provider-ops", { provider_id: accountId, op: "observe", environment_ref: e });
        if (obs.j?.evidence?.teardown_state === "live_or_pending") await opWithGrant("delete", { environment_ref: e });
      }
    }
  } catch { /* best effort */ }
  if (accountId) await jd("DELETE", `/v1/hypervisor/provider-accounts/${accountId}`);
  if (casBackendId) await jd("DELETE", `/v1/hypervisor/storage-backends/${casBackendId}`);
  rmSync(BUDGET_FILE, { force: true });
}

run()
  .then(cleanup, async (e) => { await cleanup(); throw e; })
  .then(() => {
    let fail = 0;
    for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
    console.log(`\n${results.length - fail}/${results.length} passed`);
    console.log(`k8s/kubevirt cluster adapter readiness: ${fail ? "FAIL" : "OK"}${LIVE_MODE ? "" : " (live_provisioning_not_run)"}`);
    process.exit(fail ? 1 : 0);
  })
  .catch((e) => {
    console.error("verifier crashed:", e);
    process.exit(1);
  });
