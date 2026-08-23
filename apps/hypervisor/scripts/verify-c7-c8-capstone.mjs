#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";
import { sealCertificate, validateCertificate } from "./lib/c7-c8-certificate.mjs";

const arg = (name) => { const index = process.argv.indexOf(name); return index >= 0 ? process.argv[index + 1] : null; };

function validFixture() {
  const fixtureSdl = "version: fixture\n";
  const fixtureSdlHash = `sha256:${crypto.createHash("sha256").update(fixtureSdl).digest("hex")}`;
  const providerAddress = "akash1provider000000000000000000000000000";
  return sealCertificate({
    ok: true,
    result: "success",
    source: { commit: "8d536a5da", dirty_state_declaration: "clean", publication_eligible: true, daemon_binary_sha256: `sha256:${"1".repeat(64)}` },
    operator: { principal_ref: "user://operator-one" },
    authority: {
      policy_hash: `sha256:${"2".repeat(64)}`,
      request_hash: `sha256:${"3".repeat(64)}`,
      grant_ref: "wallet.network://grant/one",
      reviewed_facets: { deposit_usd: 1, ceiling_amount: "1000", ceiling_denom: "uact", provider_selector: { mode: "exact", provider_address: providerAddress, selection: "only_qualified_bid_from_exact_provider" }, provider_address: providerAddress, auto_topup: false, sdl_hash: fixtureSdlHash, execution_mode: "live", teardown_policy: "always_teardown_required", provider_account_ref: "provider-account://one", retry_count: 1 },
      binding: { authority_provider_ref: "wallet.network", backing_provider: "provider:account:one", allowed_tools: ["provider.create"], resource_refs: ["provider-account://one", "env-capstone-one"], scopes: ["provider.provision"] },
      lease: { lease_ref: "capability-lease://one", usage_count: 1, remaining_calls: 0, state: "exhausted", expires_at: 1850000000000, revocation_ref: "provider-accounts/one/credential" },
    },
    workload: { redacted_sdl: fixtureSdl, redacted_sdl_hash: fixtureSdlHash, reviewed_sdl_hash: fixtureSdlHash, image_ref: `registry.invalid/ioi/c7@sha256:${"e".repeat(64)}`, image_identity_posture: "immutable_digest" },
    proposal: { source: "daemon-issued-durable-proposal", proposal_ref: "provider-operation-proposal://one", admission_receipt_ref: "proposal-admission://one", consumption_receipt_ref: "proposal-consumption://one", admission_root: `sha256:${"5".repeat(64)}`, consumption_root: `sha256:${"6".repeat(64)}`, request_hash: `sha256:${"d".repeat(64)}`, consumed_once: true },
    journal: { intent_root: `sha256:${"7".repeat(64)}`, outcome_root: `sha256:${"8".repeat(64)}`, outcome_predecessor_root: `sha256:${"7".repeat(64)}` },
    provider: { dseq: "1787000000000", bid_ref: "akash-bid://one", provider_address: providerAddress, lease_ref: "akash-lease://one", lease_state: "closed", endpoint_ref: "akash-endpoint://one", endpoint_discovered: true, service_uri_present: true, desired_replicas: 1, ready_replicas: 0, workload_readiness_proven: false, workload_result_retrieved: false, c6: { retrieved_live: true, provider_response_hash: `sha256:${"9".repeat(64)}` } },
    teardown: { state: "torn_down", provider_terminal: true, close_http: 200 },
    settlement: { state: "final_debit_settled", provider_readback: true, provider_response_hash: `sha256:${"a".repeat(64)}`, final_net_cost_usd: 0.01, open_exposure_count: 0, unknown_exposure_count: 0 },
    negative_receipts: ["provider-receipt://authority-required"],
    claims: { certified_scope: "governed_infrastructure_lifecycle", application_readiness_claimed: false, workload_result_claimed: false, bare_metal_claimed: false, provider_neutrality_claimed: false, remote_worker_secret_non_possession_claimed: false },
    nonclaims: ["provider-neutral execution", "certified bare-metal placement", "remote-worker secret non-possession", "application readiness", "workload result retrieval"],
    durable: { environment_ref: "env-capstone-one", provider_operation_id: "pop_create_one", c6_operation_id: "pop_logs_one", delete_operation_id: "pop_delete_one", deployment_record_id: "akdep_one", provider_lease_record_id: "aklease_one", endpoint_record_id: "akep_endpoint_one", capability_lease_id: "lease_capstone_one", proposal_admission_operation_ref: "substrate-operation://proposal-one", terminal_reconciliation_receipt_ref: "provider-receipt://terminal", substrate_muxlog_bytes: 10, substrate_muxlog_prefix_sha256: `sha256:${"c".repeat(64)}` },
  });
}

async function verifyDurable(certificate, dataDir, repo, daemon) {
  const failures = [];
  const fail = (code, pathName, detail) => failures.push({ code, path: pathName, detail });
  const safe = (value) => typeof value === "string" && /^[A-Za-z0-9_.-]+$/u.test(value);
  const load = (family, id) => {
    if (!safe(id)) { fail("durable_locator_unsafe", `durable.${family}`, String(id)); return null; }
    const file = path.join(dataDir, family, `${id}.json`);
    if (!fs.existsSync(file)) { fail("durable_record_missing", file, id); return null; }
    return JSON.parse(fs.readFileSync(file, "utf8"));
  };
  const endpointFacts = (record) => {
    const services = record?.services && typeof record.services === "object" ? Object.values(record.services) : [];
    return {
      desired: Number(record?.desired_replicas ?? services.reduce((sum, service) => sum + Number(service?.replicas ?? service?.total ?? 0), 0)),
      ready: Number(record?.ready_replicas ?? services.reduce((sum, service) => sum + Number(service?.ready_replicas ?? service?.available_replicas ?? service?.available ?? 0), 0)),
      uri: record?.service_uri_present === true || services.some((service) => Array.isArray(service?.uris) && service.uris.length > 0),
    };
  };
  const d = certificate.durable;
  const create = load("provider-operations", d.provider_operation_id);
  const c6 = load("provider-operations", d.c6_operation_id);
  const deleted = load("provider-operations", d.delete_operation_id);
  const deployment = load("akash-deployments", d.deployment_record_id);
  const providerLease = load("akash-leases", d.provider_lease_record_id);
  const endpoint = load("akash-endpoints", d.endpoint_record_id);
  const capability = load("capability-leases", d.capability_lease_id);
  if (create) {
    if (create.environment_ref !== d.environment_ref || create.op !== "create") fail("durable_create_mismatch", "durable.provider_operation_id", "not the certified create");
    if (create.proposal_consumption?.proposal_ref !== certificate.proposal.proposal_ref || create.proposal_consumption?.proposal_admission_root !== certificate.proposal.admission_root || create.proposal_consumption?.proposal_consumption_root !== certificate.proposal.consumption_root || create.proposal_consumption?.request_hash !== certificate.proposal.request_hash) fail("durable_proposal_mismatch", "proposal", "certificate differs from daemon create record");
    if (create.proposal_consumption?.principal_ref !== certificate.operator.principal_ref) fail("durable_principal_mismatch", "operator.principal_ref", "operator differs from proposal consumer");
    if (JSON.stringify(create.journal_state_roots) !== JSON.stringify([certificate.journal.intent_root, certificate.journal.outcome_root])) fail("durable_journal_mismatch", "journal", "journal roots differ from daemon create record");
    if (create.grant_ref !== certificate.authority.grant_ref) fail("durable_grant_mismatch", "authority.grant_ref", "grant differs from daemon create record");
  }
  if (c6 && (c6.environment_ref !== d.environment_ref || c6.op !== "logs" || c6.evidence?.lease_state_proof?.retrieved_live !== true || c6.evidence?.settlement_readback?.provider_response_hash !== certificate.provider.c6.provider_response_hash)) fail("durable_c6_mismatch", "provider.c6", "live readback differs from daemon logs record");
  if (certificate.claims?.workload_result_claimed === true && c6) {
    const journal = certificate.journal;
    const bundle = c6.evidence?.workload_result?.bundle;
    if (JSON.stringify(c6.journal_state_roots) !== JSON.stringify([
      journal.intent_root,
      journal.outcome_root,
      journal.workload_result_outcome_root,
    ])
      || bundle?.status?.sha256 !== journal.workload_status_hash
      || bundle?.environment?.sha256 !== journal.workload_environment_hash
      || bundle?.results?.sha256 !== journal.workload_result_hash
      || bundle?.manifest?.sha256 !== journal.workload_manifest_hash
      || c6.evidence?.workload_result?.result_ref !== journal.workload_result_ref) {
      fail("durable_workload_result_journal_mismatch", "journal", "the result successor root or authenticated artifact hashes differ from the durable logs operation");
    }
  }
  if (deleted && (deleted.environment_ref !== d.environment_ref || deleted.op !== "delete")) fail("durable_delete_mismatch", "teardown", "delete record does not bind certified environment");
  if (deployment) {
    if (deployment.environment_ref !== d.environment_ref || String(deployment.dseq) !== certificate.provider.dseq || deployment.endpoint_ref !== certificate.provider.endpoint_ref || deployment.account_ref !== certificate.authority.reviewed_facets.provider_account_ref || deployment.deposit_usd !== certificate.authority.reviewed_facets.deposit_usd) fail("durable_deployment_mismatch", "provider", "deployment identity or bounded deposit differs from daemon record");
    if (deployment.teardown_state !== "torn_down" || deployment.provider_native_settlement?.provider_terminal !== true || deployment.provider_readback_hash !== certificate.settlement.provider_response_hash || deployment.provider_native_settlement?.final_debit_usd !== certificate.settlement.final_net_cost_usd) fail("durable_settlement_mismatch", "settlement", "terminal settlement differs from daemon record");
    if (certificate.claims?.workload_result_claimed === true && (
      deployment.provider_operation_intent_root !== certificate.journal.workload_result_intent_root
      || deployment.provider_operation_effect_outcome_root !== certificate.journal.workload_result_predecessor_root
      || deployment.provider_operation_result_outcome_root !== certificate.journal.workload_result_outcome_root
      || deployment.workload_status_hash !== certificate.journal.workload_status_hash
      || deployment.workload_environment_hash !== certificate.journal.workload_environment_hash
      || deployment.workload_result_hash !== certificate.journal.workload_result_hash
      || deployment.workload_manifest_hash !== certificate.journal.workload_manifest_hash
      || deployment.workload_result_ref !== certificate.journal.workload_result_ref
    )) fail("durable_workload_result_projection_mismatch", "journal", "the deployment projection differs from the certified result-binding root and hashes");
  }
  if (providerLease && (providerLease.environment_ref !== d.environment_ref || providerLease.state !== "closed" || providerLease.lease_ref !== certificate.provider.lease_ref)) fail("durable_provider_lease_mismatch", "provider.lease_state", "provider lease projection is not closed");
  if (endpoint) {
    const facts = endpointFacts(endpoint);
    if (endpoint.environment_ref !== d.environment_ref
      || endpoint.endpoint_ref !== certificate.provider.endpoint_ref
      || endpoint.retrieved_live !== true
      || !/^sha256:[0-9a-f]{64}$/u.test(endpoint.provider_response_hash || "")
      || certificate.provider.endpoint_discovered !== true
      || certificate.provider.desired_replicas !== facts.desired
      || certificate.provider.ready_replicas !== facts.ready
      || certificate.provider.service_uri_present !== facts.uri
      || certificate.provider.workload_readiness_proven !== (facts.ready > 0)) {
      fail("durable_endpoint_mismatch", "provider.endpoint_ref", "endpoint discovery or readiness facts differ from the fetched provider readback");
    }
  }
  if (capability && (capability.lease_id !== d.capability_lease_id || capability.grant_ref !== certificate.authority.grant_ref || capability.remaining_calls !== 0 || capability.state !== certificate.authority.lease.state || capability.expires_at !== certificate.authority.lease.expires_at || capability.revocation_ref !== certificate.authority.lease.revocation_ref || capability.policy_hash !== certificate.authority.policy_hash || capability.request_hash !== certificate.authority.request_hash || capability.authority_provider_ref !== certificate.authority.binding.authority_provider_ref || capability.backing_provider !== certificate.authority.binding.backing_provider || JSON.stringify(capability.allowed_tools) !== JSON.stringify(certificate.authority.binding.allowed_tools) || JSON.stringify(capability.resource_refs) !== JSON.stringify(certificate.authority.binding.resource_refs))) fail("durable_authority_mismatch", "authority.lease", "capability projection differs from certificate");
  let promotedReceipts = [];
  try {
    const response = await fetch(`${daemon.replace(/\/$/u, "")}/v1/hypervisor/provider-receipts`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    promotedReceipts = (await response.json()).receipts || [];
  } catch (error) {
    fail("promoted_receipts_unavailable", "--daemon", String(error));
  }
  for (const receiptRef of certificate.negative_receipts) {
    const receipt = promotedReceipts.find((record) => record.receipt_ref === receiptRef);
    if (!receipt) fail("durable_negative_receipt_missing", "negative_receipts", receiptRef);
    else if (receipt.environment_ref !== d.environment_ref || receipt.op !== "create" || receipt.outcome !== "authority_missing") fail("durable_negative_receipt_mismatch", "negative_receipts", receiptRef);
  }
  const terminalReceipt = promotedReceipts.find((record) => record.receipt_ref === d.terminal_reconciliation_receipt_ref);
  if (!terminalReceipt) fail("durable_terminal_receipt_missing", "durable.terminal_reconciliation_receipt_ref", d.terminal_reconciliation_receipt_ref);
  else if (terminalReceipt.environment_ref !== d.environment_ref || !["delete", "reconcile"].includes(terminalReceipt.op) || terminalReceipt.outcome !== "ok") {
    fail("durable_terminal_receipt_mismatch", "durable.terminal_reconciliation_receipt_ref", "terminal provider receipt differs from certificate");
  } else if (terminalReceipt.op === "reconcile" && terminalReceipt.provider_native?.response_hash !== certificate.settlement.provider_response_hash) {
    fail("durable_terminal_receipt_mismatch", "durable.terminal_reconciliation_receipt_ref", "terminal reconciliation receipt differs from certificate");
  } else if (terminalReceipt.op === "delete" && (
    deleted?.receipt_ref !== terminalReceipt.receipt_ref
    || deleted?.evidence?.native_teardown?.provider_response_hash !== certificate.settlement.provider_response_hash
    || deleted?.evidence?.settlement?.provider_terminal !== true
  )) {
    fail("durable_terminal_receipt_mismatch", "durable.terminal_reconciliation_receipt_ref", "terminal delete receipt is not backed by the durable provider settlement");
  }
  const muxlogPath = path.join(dataDir, "substrate/muxlog.bin");
  if (!fs.existsSync(muxlogPath)) fail("substrate_log_missing", muxlogPath, "muxlog absent");
  else {
    const bytes = fs.readFileSync(muxlogPath);
    if (bytes.length < d.substrate_muxlog_bytes) fail("substrate_log_truncated", muxlogPath, `${bytes.length} < ${d.substrate_muxlog_bytes}`);
    else {
      const actual = `sha256:${crypto.createHash("sha256").update(bytes.subarray(0, d.substrate_muxlog_bytes)).digest("hex")}`;
      if (actual !== d.substrate_muxlog_prefix_sha256) fail("substrate_anchor_mismatch", "durable.substrate_muxlog_prefix_sha256", "durable substrate prefix changed");
    }
  }
  const binary = path.join(repo, "target/debug/hypervisor-daemon");
  if (!fs.existsSync(binary)) fail("daemon_binary_missing", binary, "certified binary absent");
  else if (`sha256:${crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex")}` !== certificate.source.daemon_binary_sha256) fail("daemon_binary_mismatch", "source.daemon_binary_sha256", "binary differs from run basis");
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();
  if (commit !== certificate.source.commit) fail("source_commit_mismatch", "source.commit", "repository HEAD differs from run basis");
  return failures;
}

function selfTest() {
  const cases = [
    ["run_not_successful", (c) => { c.ok = false; c.result = "failure"; }],
    ["proposal_provenance_invalid", (c) => { c.proposal.source = "daemon-provider-operation-proposal"; }],
    ["c6_live_proof_missing", (c) => { c.provider.c6.retrieved_live = false; }],
    ["settlement_not_terminal", (c) => { c.settlement.state = "refund_pending"; }],
    ["provider_lease_open", (c) => { c.provider.lease_state = "open"; }],
    ["provider_endpoint_missing", (c) => { c.provider.endpoint_ref = null; c.provider.endpoint_discovered = false; }],
    ["provider_readiness_inflated", (c) => { c.provider.workload_readiness_proven = true; c.claims.application_readiness_claimed = true; }],
    ["application_readiness_claim_mismatch", (c) => { c.claims.application_readiness_claimed = true; }],
    ["exhausted_authority_still_active", (c) => { c.authority.lease.state = "active"; }],
    ["journal_root_mismatch", (c) => { c.journal.outcome_predecessor_root = `sha256:${"b".repeat(64)}`; }],
    ["final_cost_unreconciled", (c) => { c.settlement.final_net_cost_usd = null; }],
    ["open_or_unknown_exposure", (c) => { c.settlement.open_exposure_count = 1; }],
    ["secret_bearing_artifact", (c) => { c.operator.session_token = "ioi_sess_forbidden"; }],
    ["bounded_spend_facets_changed", (c) => { c.authority.reviewed_facets.deposit_usd = 2; }],
    ["provider_selector_changed", (c) => { c.authority.reviewed_facets.provider_selector.selection = "caller_selected"; }],
    ["redacted_sdl_invalid", (c) => { c.workload.redacted_sdl += "# changed"; }],
    ["raw_sdl_retained", (c) => { c.authority.reviewed_facets.sdl_yaml = "password: CANARY"; }],
    ["exact_provider_mismatch", (c) => { c.provider.provider_address = "akash1different000000000000000000000000"; }],
    ["unsupported_architecture_claim", (c) => { c.claims.bare_metal_claimed = true; }],
    ["authority_binding_invalid", (c) => { c.authority.binding.resource_refs[1] = "env-other"; }],
    ["proposal_request_hash_missing", (c) => { c.proposal.request_hash = null; }],
    ["authority_lifecycle_evidence_missing", (c) => { c.authority.lease.revocation_ref = null; }],
  ];
  const base = validFixture();
  const baseResult = validateCertificate(base);
  if (!baseResult.ok) return { ok: false, failures: [{ code: "positive_control_failed", detail: baseResult.failures }] };
  const failures = [];
  for (const [expected, mutate] of cases) {
    const certificate = structuredClone(base);
    mutate(certificate);
    certificate.certificate_hash = sealCertificate(certificate).certificate_hash;
    const result = validateCertificate(certificate);
    if (result.ok || !result.failures.some((failure) => failure.code === expected)) failures.push({ code: "mutation_false_green", mutation: expected, observed: result.failures });
  }
  return {
    ok: failures.length === 0,
    mutation_count: cases.length,
    cases: cases.map(([expected], index) => ({ case: index + 1, expected_failure: expected })),
    failures,
  };
}

async function mutationTest(base, dataDir, repo, daemon) {
  const cases = [
    ["bounded_spend_facets_changed", (c) => { c.authority.reviewed_facets.deposit_usd = 2; }, false],
    ["bounded_spend_facets_changed", (c) => { c.authority.reviewed_facets.ceiling_amount = "2000"; }, false],
    ["bounded_spend_facets_changed", (c) => { c.authority.reviewed_facets.retry_count = 2; }, false],
    ["provider_selector_changed", (c) => { c.authority.reviewed_facets.provider_selector.selection = "caller_selected"; }, false],
    ["redacted_sdl_invalid", (c) => { c.workload.redacted_sdl += "# mutation"; }, false],
    ["raw_sdl_retained", (c) => { c.authority.reviewed_facets.sdl_yaml = "api_key: sk-forbidden-canary"; }, false],
    ["provider_readiness_inflated", (c) => {
      c.provider.workload_readiness_proven = !c.provider.workload_readiness_proven;
      c.claims.application_readiness_claimed = c.provider.workload_readiness_proven;
    }, false],
    ["exact_provider_mismatch", (c) => { c.provider.provider_address = "akash1different000000000000000000000000"; }, false],
    ["proposal_provenance_invalid", (c) => { c.proposal.source = "caller-asserted"; }, false],
    ["durable_proposal_mismatch", (c) => { c.proposal.request_hash = `sha256:${"0".repeat(64)}`; }, true],
    ["durable_journal_mismatch", (c) => { c.journal.outcome_root = `sha256:${"1".repeat(64)}`; c.journal.outcome_predecessor_root = c.journal.intent_root; }, true],
    ["durable_authority_mismatch", (c) => { c.authority.policy_hash = `sha256:${"2".repeat(64)}`; }, true],
    ["durable_authority_mismatch", (c) => { c.authority.lease.expires_at += 1; }, true],
    ["durable_negative_receipt_missing", (c) => { c.negative_receipts[0] = "agentgres://provider-receipt/prc_missing"; }, true],
    ["durable_terminal_receipt_missing", (c) => { c.durable.terminal_reconciliation_receipt_ref = "agentgres://provider-receipt/prc_missing"; }, true],
    ["daemon_binary_mismatch", (c) => { c.source.daemon_binary_sha256 = `sha256:${"3".repeat(64)}`; }, true],
    ["durable_settlement_mismatch", (c) => { c.settlement.final_net_cost_usd = 0.5; }, true],
    ["c6_live_proof_missing", (c) => { c.provider.c6.retrieved_live = false; }, false],
    ["open_or_unknown_exposure", (c) => { c.settlement.unknown_exposure_count = 1; }, false],
    ["secret_bearing_artifact", (c) => { c.operator.session_token = "ioi_sess_forbidden"; }, false],
    ["unsupported_architecture_claim", (c) => { c.claims.bare_metal_claimed = true; }, false],
    ["authority_lifecycle_evidence_missing", (c) => { c.authority.lease.revocation_ref = null; }, false],
  ];
  const failures = [];
  for (const [expected, mutate, needsDurable] of cases) {
    const certificate = structuredClone(base);
    mutate(certificate);
    certificate.certificate_hash = sealCertificate(certificate).certificate_hash;
    const structural = validateCertificate(certificate).failures;
    const durable = needsDurable ? await verifyDurable(certificate, dataDir, repo, daemon) : [];
    const observed = [...structural, ...durable];
    if (!observed.some((failure) => failure.code === expected)) failures.push({ code: "mutation_false_green", mutation: expected, observed });
  }
  return {
    ok: failures.length === 0,
    mutation_count: cases.length,
    cases: cases.map(([expected], index) => ({ case: index + 1, expected_failure: expected })),
    failures,
  };
}

if (process.argv.includes("--self-test")) {
  const result = selfTest();
  console.log(JSON.stringify({ schema_version: "ioi.check.c7-c8-capstone.self-test.v1", ...result }, null, 2));
  process.exit(result.ok ? 0 : 1);
}

const evidence = arg("--evidence");
if (!evidence) {
  console.error("usage: check:c7-c8-capstone -- --evidence <dir-or-certificate.json> | --self-test");
  process.exit(2);
}
const resolved = path.resolve(evidence);
const certificatePath = fs.statSync(resolved).isDirectory() ? path.join(resolved, "certificate.json") : resolved;
if (!fs.existsSync(certificatePath)) {
  console.error(JSON.stringify({ ok: false, failures: [{ code: "certificate_missing", path: certificatePath }] }, null, 2));
  process.exit(1);
}
const certificate = JSON.parse(fs.readFileSync(certificatePath, "utf8"));
const result = validateCertificate(certificate);
const dataDir = path.resolve(arg("--data-dir") || process.env.IOI_HYPERVISOR_DATA_DIR || path.join(os.homedir(), ".ioi/hypervisor/data"));
const daemon = arg("--daemon") || "http://127.0.0.1:8765";
const repo = path.resolve(arg("--repo") || process.cwd());
const durableFailures = await verifyDurable(certificate, dataDir, repo, daemon);
const final = { ok: result.ok && durableFailures.length === 0, failures: [...result.failures, ...durableFailures] };
const mutations = process.argv.includes("--mutation-test") ? await mutationTest(certificate, dataDir, repo, daemon) : null;
const withMutations = { ok: final.ok && (mutations?.ok ?? true), failures: [...final.failures, ...(mutations?.failures || [])] };
console.log(JSON.stringify({ schema_version: "ioi.check.c7-c8-capstone.v1", certificate: certificatePath, ...withMutations, ...(mutations ? { mutations } : {}) }, null, 2));
process.exit(withMutations.ok ? 0 : 1);
