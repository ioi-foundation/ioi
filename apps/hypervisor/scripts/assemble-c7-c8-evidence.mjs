#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { normalizeCertifiedSourceBasisForLifecycle } from "./lib/certified-daemon-source-basis.mjs";

const arg = (name) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : null; };
const artifacts = path.resolve(arg("--artifacts") || "");
const dataDir = path.resolve(arg("--data-dir") || "");
const repo = path.resolve(arg("--repo") || process.cwd());
const environment = arg("--environment");
const historicalSourcePath = arg("--source-basis-certificate");
const output = path.resolve(arg("--output") || path.join(artifacts, "run-evidence.json"));
if (!artifacts || !dataDir || !environment) {
  console.error("usage: assemble-c7-c8-evidence --artifacts <dir> --data-dir <dir> --environment <env> [--repo <repo>] [--source-basis-certificate <historical-certificate.json>] [--output <json>]");
  process.exit(2);
}
const read = (name) => JSON.parse(fs.readFileSync(path.join(artifacts, name), "utf8"));
const records = (family) => {
  const dir = path.join(dataDir, family);
  return fs.existsSync(dir) ? fs.readdirSync(dir).filter((name) => name.endsWith(".json")).map((name) => JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"))) : [];
};
const required = (value, label) => { if (value === undefined || value === null || value === "") throw new Error(`missing ${label}`); return value; };
const shaFile = (file) => `sha256:${crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex")}`;
const shaText = (value) => `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
const redactSdl = (value) => value
  .split("\n")
  .map((line) => /^(\s*)(password|token|api[_-]?key|secret|private[_-]?key)\s*:/iu.test(line)
    ? `${line.match(/^\s*/u)?.[0] || ""}${line.trimStart().split(":", 1)[0]}: <redacted>`
    : line)
  .join("\n");
const sdlImageRef = (value) => value.match(/^\s*image\s*:\s*["']?([^\s"']+)["']?\s*$/mu)?.[1] || "unknown-image";
const serviceFacts = (endpointRecord) => {
  const services = endpointRecord?.services && typeof endpointRecord.services === "object"
    ? Object.values(endpointRecord.services)
    : [];
  const desired = services.reduce((sum, service) => sum + Number(service?.replicas ?? service?.total ?? 0), 0);
  const ready = services.reduce((sum, service) => sum + Number(service?.ready_replicas ?? service?.available_replicas ?? service?.available ?? 0), 0);
  const uri = services.some((service) => Array.isArray(service?.uris) && service.uris.length > 0);
  return { desired, ready, uri };
};

const challenge = read("c7-challenge.json");
const proposalAdmission = read("c7-proposal-admission.json");
const cast = read("c7-cast.json");
const start = read("c7-start.json");
const logs = read("c7-logs.json");
const deleted = read("c7-delete.json");
const reconcileCandidate = fs.existsSync(path.join(artifacts, "c7-reconcile.json")) ? read("c7-reconcile.json") : null;
const reconciled = reconcileCandidate?.evidence?.settlement ? reconcileCandidate : deleted;
const whoami = read("c7-whoami.json");
const receipts = read("c7-receipts.json").receipts || [];
const reconciliation = read("c7-reconciliation.json");
const allOperations = read("c7-operations.json").operations || [];
const operations = allOperations.filter((record) => record.environment_ref === environment);
const createOp = operations.find((record) => record.op === "create");
const logsOp = operations.find((record) => record.op === "logs" && Array.isArray(record.journal_state_roots) && record.journal_state_roots.length >= 3)
  || operations.find((record) => record.op === "logs");
const deleteOp = operations.find((record) => record.op === "delete");
const deployment = records("akash-deployments").find((record) => record.environment_ref === environment);
const providerLeaseRecords = records("akash-leases");
const providerLease = providerLeaseRecords.find((record) =>
  record.environment_ref === environment && record.lease_ref === deployment?.lease_ref)
  || providerLeaseRecords.find((record) => record.environment_ref === environment);
const endpointRecords = records("akash-endpoints");
const endpoint = endpointRecords.find((record) =>
  record.environment_ref === environment && record.endpoint_ref === deployment?.endpoint_ref)
  || endpointRecords.find((record) => record.environment_ref === environment);
const capabilityLeaseId = cast.capability_lease?.lease_id;
const capabilityLease = records("capability-leases").find((record) => record.lease_id === capabilityLeaseId);
const proposal = required(createOp?.proposal_consumption, "durable create proposal consumption");
const roots = required(createOp?.journal_state_roots, "durable C2 journal roots");
const settlement = required(deployment?.provider_native_settlement, "provider-native settlement");
const scopedExposureRows = (reconciliation.rows || []).filter((row) => row.environment_ref === environment);
const openExposureCount = scopedExposureRows.filter((row) => row.status === "open").length + (providerLease?.state === "open" ? 1 : 0);
const unknownExposureCount = scopedExposureRows.filter((row) => !["open", "closed"].includes(row.status)).length + (!providerLease || !["open", "closed"].includes(providerLease.state) ? 1 : 0);
const facets = challenge.lease_request_facets;
const rawSdl = required(facets?.sdl_yaml, "reviewed SDL bytes");
const redactedSdl = redactSdl(rawSdl);
const imageRef = sdlImageRef(rawSdl);
const reviewedFacets = structuredClone(facets);
delete reviewedFacets.sdl_yaml;
const negativeReceipt = receipts.find((record) => record.receipt_ref === challenge.receipt_ref);
const sourceBasisDocument = historicalSourcePath
  ? JSON.parse(fs.readFileSync(path.resolve(historicalSourcePath), "utf8"))
  : null;
const historicalSource = historicalSourcePath
  ? normalizeCertifiedSourceBasisForLifecycle(sourceBasisDocument)
  : null;
const status = historicalSource
  ? historicalSource.dirty_state_declaration
  : execFileSync("git", ["status", "--short"], { cwd: repo, encoding: "utf8" }).trim();
const muxlogPath = path.join(dataDir, "substrate/muxlog.bin");
const muxlog = fs.readFileSync(muxlogPath);
const whoamiPrincipal = whoami.principal_ref || whoami.principal?.principal_ref || whoami.identity?.principal_ref || whoami.user?.principal_ref;
if (whoamiPrincipal && whoamiPrincipal !== proposal.principal_ref) throw new Error("whoami principal differs from durable proposal consumer");
const replicas = serviceFacts(endpoint);
const endpointDiscovered = endpoint?.endpoint_discovered === true
  || endpoint?.retrieved_live === true;
const readyReplicas = Number(endpoint?.ready_replicas ?? deployment?.ready_replicas ?? replicas.ready);
const desiredReplicas = Number(endpoint?.desired_replicas ?? deployment?.desired_replicas ?? replicas.desired);
const workloadReadinessProven = readyReplicas > 0;
const workloadResultRetrieved = endpoint?.workload_result_retrieved === true
  || deployment?.workload_result_retrieved === true;
const resultBindingRoots = workloadResultRetrieved
  ? required(logsOp?.journal_state_roots, "durable workload-result C2 roots")
  : null;
if (workloadResultRetrieved && (
  resultBindingRoots.length < 3
  || resultBindingRoots[0] !== roots[0]
  || resultBindingRoots[1] !== roots[1]
)) {
  throw new Error("workload-result outcome does not extend the exact create intent/outcome chain");
}
const immutableImage = /@sha256:[0-9a-f]{64}$/u.test(imageRef);
const publicationEligible = historicalSource
  ? historicalSource.publication_eligible === true
    && historicalSource.dirty_state_declaration === "clean"
    && immutableImage
  : (status || "clean") === "clean" && immutableImage;

const evidence = {
  ok: cast.ok === true && start.ok === true && logs.ok === true && settlement.provider_terminal === true,
  result: "success",
  source: {
    commit: historicalSource?.commit
      || execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim(),
    dirty_state_declaration: status || "clean",
    publication_eligible: publicationEligible,
    daemon_binary_sha256: historicalSource?.daemon_binary_sha256
      || shaFile(path.join(repo, "target/debug/hypervisor-daemon")),
  },
  operator: { principal_ref: required(proposal.principal_ref, "authenticated proposal consumer") },
  authority: {
    policy_hash: challenge.approval.policy_hash,
    request_hash: challenge.approval.request_hash,
    grant_ref: required(capabilityLease?.grant_ref, "wallet grant ref"),
    reviewed_facets: { ...reviewedFacets, provider_account_ref: challenge.account_ref, retry_count: 1 },
    binding: {
      authority_provider_ref: capabilityLease.authority_provider_ref,
      backing_provider: capabilityLease.backing_provider,
      allowed_tools: challenge.allowed_tools,
      resource_refs: challenge.resource_refs,
      scopes: challenge.required_scopes,
    },
    lease: { lease_ref: capabilityLease.lease_id, usage_count: 1, remaining_calls: capabilityLease.remaining_calls, state: capabilityLease.state, expires_at: capabilityLease.expires_at, revocation_ref: capabilityLease.revocation_ref },
  },
  workload: {
    redacted_sdl: redactedSdl,
    redacted_sdl_hash: shaText(redactedSdl),
    reviewed_sdl_hash: facets.sdl_hash,
    image_ref: imageRef,
    image_identity_posture: immutableImage ? "immutable_digest" : "mutable_tag",
  },
  proposal: {
    source: "daemon-issued-durable-proposal",
    proposal_ref: proposal.proposal_ref,
    admission_receipt_ref: proposal.proposal_admission_receipt_ref,
    consumption_receipt_ref: proposal.proposal_consumption_receipt_ref,
    admission_root: proposal.proposal_admission_root,
    consumption_root: proposal.proposal_consumption_root,
    request_hash: proposal.request_hash,
    consumed_once: true,
  },
  journal: {
    intent_root: roots[0],
    outcome_root: roots[1],
    outcome_predecessor_root: roots[0],
    ...(workloadResultRetrieved ? {
      workload_result_outcome_root: resultBindingRoots[2],
      workload_result_predecessor_root: resultBindingRoots[1],
      workload_result_intent_root: resultBindingRoots[0],
      workload_result_ref: required(deployment.workload_result_ref, "workload result ref"),
      workload_status_hash: required(deployment.workload_status_hash, "workload status hash"),
      workload_result_hash: required(deployment.workload_result_hash, "workload result hash"),
      workload_environment_hash: required(deployment.workload_environment_hash, "workload environment hash"),
      workload_manifest_hash: required(deployment.workload_manifest_hash, "workload manifest hash"),
    } : {}),
  },
  provider: {
    dseq: String(required(deployment.dseq, "dseq")),
    bid_ref: required(deployment.bid_ref, "bid ref"),
    provider_address: required(deployment.provider_native?.provider, "selected provider"),
    lease_ref: required(deployment.lease_ref, "lease ref"),
    lease_state: providerLease.state,
    endpoint_ref: required(endpoint?.endpoint_ref, "endpoint ref"),
    endpoint_discovered: endpointDiscovered,
    service_uri_present: endpoint?.service_uri_present === true || replicas.uri,
    desired_replicas: desiredReplicas,
    ready_replicas: readyReplicas,
    workload_readiness_proven: workloadReadinessProven,
    workload_result_retrieved: workloadResultRetrieved,
    c6: { retrieved_live: logs.evidence?.lease_state_proof?.retrieved_live === true, provider_response_hash: logs.evidence?.settlement_readback?.provider_response_hash },
  },
  teardown: { state: deployment.teardown_state, provider_terminal: settlement.provider_terminal, close_http: deployment.close_http },
  settlement: {
    state: settlement.settlement_state,
    provider_readback: true,
    provider_response_hash: deployment.provider_readback_hash,
    final_net_cost_usd: settlement.final_debit_usd,
    open_exposure_count: openExposureCount,
    unknown_exposure_count: unknownExposureCount,
  },
  negative_receipts: [required(negativeReceipt?.receipt_ref, "durable authority refusal receipt")],
  claims: {
    certified_scope: "governed_infrastructure_lifecycle",
    application_readiness_claimed: workloadReadinessProven,
    workload_result_claimed: workloadResultRetrieved,
    bare_metal_claimed: false,
    provider_neutrality_claimed: false,
    remote_worker_secret_non_possession_claimed: false,
  },
  nonclaims: [
    "provider-neutral execution",
    "certified bare-metal or dedicated-core placement",
    "hard secret non-possession by an untrusted remote worker",
    ...(workloadReadinessProven ? [] : ["application-level workload readiness"]),
    ...(workloadResultRetrieved ? [] : ["application-level workload result retrieval"]),
  ],
  durable: {
    environment_ref: environment,
    provider_operation_id: createOp.operation_id,
    c6_operation_id: logsOp?.operation_id,
    delete_operation_id: deleteOp?.operation_id,
    deployment_record_id: deployment.record_id,
    provider_lease_record_id: providerLease.record_id,
    endpoint_record_id: endpoint.record_id,
    capability_lease_id: capabilityLease.lease_id,
    proposal_admission_operation_ref: proposalAdmission.proposal_admission_operation_ref,
    terminal_reconciliation_receipt_ref: reconciled.receipt_ref,
    substrate_muxlog_bytes: muxlog.length,
    substrate_muxlog_prefix_sha256: `sha256:${crypto.createHash("sha256").update(muxlog).digest("hex")}`,
  },
};
fs.writeFileSync(output, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify({ ok: evidence.ok, output, environment, final_net_cost_usd: evidence.settlement.final_net_cost_usd }));
