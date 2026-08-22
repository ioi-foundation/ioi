#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { assemblePortableBundle, contentHash, sealSelfHash } from "./lib/c8-v3-portable-bundle.mjs";

const repo = path.resolve(import.meta.dirname, "../../..");
const verifier = process.env.IOI_AFT_C8_VERIFIER || path.join(repo, "target/debug/aft-c8-verifier");
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "aft-c8-v3-corpus-"));
const hashBytes = (bytes) => `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
const h = (digit) => `sha256:${digit.repeat(64)}`;
const now = "2026-08-22T16:00:00Z";
const later = "2026-08-23T16:00:00Z";
const write = (name, value) => {
  const target = path.join(temp, name);
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  return target;
};
const object = (name, ref, schemaRef, value) => ({ ref, schema_ref: schemaRef, file: `${name}.json`, path: write(`source-${name}.json`, value) });
const generic = (name, ref, schemaRef, extra = {}) => object(name, ref, schemaRef, { schema_version: schemaRef.replace("schema://", ""), ...extra });
const run = (...args) => spawnSync(verifier, args, { cwd: repo, encoding: "utf8" });

try {
  const binaryHash = hashBytes(fs.readFileSync(verifier));
  const requestRef = "provider-operation://aft/campaign-fixture";
  const requestValue = { schema_version: "ioi.hypervisor.provider-operation.v1", operation: "create_deployment", campaign_id: "campaign-fixture" };
  const requestHash = contentHash(requestValue);
  const resultRef = "result://aft/campaign-fixture";
  const summaries = Array.from({ length: 10 }, (_, index) => ({ scenario: `scenario-${index}`, lane: "base_final", within_threshold: true, metrics: {} }));
  const result = {
    schema_version: "ioi.aft.benchmark-campaign.v1", campaign_id: "campaign-fixture", measured_passes: 5, row_count_per_pass: 10,
    threshold_policy: { injection_tps: 0.1, sustained_tps: 0.1, commit_p50_ms: 0.1, commit_p95_ms: 0.1, commit_p99_ms: 0.15, commit_max_ms: 0.15 },
    verdict: "reproduced_within_threshold", all_rows_within_threshold: true, summaries,
    pass_artifacts: ["run-1.json", "run-2.json", "run-3.json", "run-4.json", "run-5.json"],
  };
  const claimManifest = {
    schema_version: "ioi.components.hypervisor.governed-effect-claim-manifest.v1", manifest_ref: "claim-manifest://c8/v3/campaign-fixture",
    subject_ref: requestRef, subject_hash: requestHash, protection_profile: "trusted_host_hostile_guest",
    claims: [
      ["governed_infrastructure_lifecycle", true], ["workload_readiness", true], ["workload_result_binding", true],
      ["logical_policy_mediation", true], ["workload_bound_isolation_enforced", true], ["worker_secret_non_possession_tested", true],
      ["separate_verifier", true], ["independently_reproduced", true], ["third_party_verified", false],
      ["provider_neutrality", false], ["bare_metal_placement", false],
    ].map(([claim_id, demonstrated]) => ({ claim_id, status: demonstrated ? "demonstrated" : "not_demonstrated", evidence_refs: demonstrated ? ["evidence://corpus/gate"] : [], limitation_note: demonstrated ? "Established by the portable positive corpus." : "Not claimed by this first-party corpus." })),
    source_basis_refs: [{ ref: "source://ioi/corpus", hash: h("a") }], generated_at: now,
  };
  const profile = sealSelfHash({
    schema_version: "ioi.foundations.verifier-independence-profile.v1", profile_ref: "verifier-profile://aft/c8-v3",
    verifier_identity_ref: "verifier://ioi/aft-c8-verifier", verifier_build_hash: binaryHash,
    contract_schema_refs: ["schema://ioi/components/hypervisor/c8-certificate/v3", "schema://ioi/aft/u1-campaign-result/v1"],
    separate_binary: true, separate_codegen: true, separate_transport: true, separate_authoring_party: false,
    accountable_authoring_party_ref: "principal://ioi/aft-verifier-maintainers",
    evidence_refs: ["evidence://verifier/separate-binary", "evidence://verifier/manual-types", "evidence://verifier/filesystem-transport"],
  });
  const policy = sealSelfHash({
    schema_version: "ioi.foundations.relying-party-acceptance-policy.v1", policy_ref: "acceptance-policy://aft/measured-results/v1",
    audience_ref: "relying-party://aft/measured-results-registry", accepted_certificate_schema_refs: ["schema://ioi/components/hypervisor/c8-certificate/v3"],
    accepted_result_schema_refs: ["schema://ioi/aft/u1-campaign-result/v1"], trust_roots: [{ ref: "source://ioi/corpus", hash: h("a") }],
    maximum_certificate_age_seconds: 86400, revocation_check_required: false,
    required_claim_ids: ["governed_infrastructure_lifecycle", "workload_readiness", "workload_result_binding", "logical_policy_mediation", "workload_bound_isolation_enforced", "worker_secret_non_possession_tested", "separate_verifier", "independently_reproduced"],
    tolerated_nonclaim_ids: ["third_party_verified", "provider_neutrality", "bare_metal_placement"], accepted_environment_classes: ["measured_container"],
    verifier_profile_ref: profile.profile_ref, verifier_profile_hash: profile.profile_hash,
    target_transition: { target_registry_ref: "registry://aft/measured-results", mutation_kind: "aft_measured_result_promote", target_schema_ref: "schema://ioi/aft/measured-result-row/v1" },
    valid_from: "2026-08-22T00:00:00Z", valid_until: later,
  });
  const refs = {
    predecessor: "certificate://c8/v2/corpus", source: "source://ioi/corpus", request: requestRef,
    claims: claimManifest.manifest_ref, isolation: "isolation-binding://workrun/corpus", readiness: "evidence://provider/readiness-corpus",
    campaign: "certificate://u1/campaign-fixture", contract: "schema://ioi/aft/u1-campaign-result/v1", result: resultRef,
    retrieval: "receipt://aft/result-retrieval-corpus", environment: "environment://aft/campaign-fixture", variance: "variance://aft/campaign-fixture",
    envelope: "standing-envelope://aft/corpus", drawRequest: "authority-draw-request://aft/corpus", drawReceipt: "receipt://authority-draw/corpus",
    before: "trajectory-state://aft/before-corpus", decision: "trajectory-decision://aft/corpus", after: "trajectory-state://aft/after-corpus",
    secret: "evidence://secret-probe/corpus", settlement: "receipt://provider/settlement-corpus",
  };
  const objects = [
    generic("predecessor", refs.predecessor, "schema://ioi/components/hypervisor/c8-certificate/v2"),
    object("source", refs.source, "schema://ioi/foundations/source-basis/v1", { commit: "1234567890123456789012345678901234567890" }),
    object("request", refs.request, "schema://ioi/components/hypervisor/provider-operation/v1", requestValue),
    object("claims", refs.claims, "schema://ioi/components/hypervisor/governed-effect-claim-manifest/v1", claimManifest),
    generic("isolation", refs.isolation, "schema://ioi/components/hypervisor/workload-isolation-binding/v1"),
    generic("readiness", refs.readiness, "schema://ioi/components/hypervisor/provider-readiness/v1"),
    generic("campaign", refs.campaign, "schema://ioi/components/hypervisor/u1-campaign-certificate/v1"),
    object("result-contract", refs.contract, "schema://json-schema/draft-2020-12", { $id: refs.contract, type: "object" }),
    object("result", refs.result, "schema://ioi/aft/u1-campaign-result/v1", result),
    generic("retrieval", refs.retrieval, "schema://ioi/components/hypervisor/result-retrieval-receipt/v1"),
    generic("environment", refs.environment, "schema://ioi/aft/environment-manifest/v1"),
    generic("variance", refs.variance, "schema://ioi/aft/campaign-variance/v1"),
    generic("envelope", refs.envelope, "schema://ioi/foundations/standing-authority-envelope/v1"),
    generic("draw-request", refs.drawRequest, "schema://ioi/foundations/standing-authority-draw-request/v1"),
    generic("draw-receipt", refs.drawReceipt, "schema://ioi/foundations/standing-authority-consumption/v1"),
    generic("trajectory-before", refs.before, "schema://ioi/foundations/authority-trajectory-state/v1"),
    generic("trajectory-decision", refs.decision, "schema://ioi/foundations/trajectory-admission-decision/v1"),
    generic("trajectory-after", refs.after, "schema://ioi/foundations/authority-trajectory-state/v1"),
    generic("secret-evidence", refs.secret, "schema://ioi/components/hypervisor/worker-secret-non-possession/v1"),
    generic("settlement", refs.settlement, "schema://ioi/components/hypervisor/provider-settlement/v1", { provider_ref: "provider://akash/corpus" }),
  ];
  const sourceEntry = objects.find((entry) => entry.ref === refs.source);
  claimManifest.source_basis_refs[0].hash = contentHash(JSON.parse(fs.readFileSync(sourceEntry.path, "utf8")));
  const claimsEntry = objects.find((entry) => entry.ref === refs.claims);
  fs.writeFileSync(claimsEntry.path, `${JSON.stringify(claimManifest, null, 2)}\n`, { mode: 0o600 });
  policy.trust_roots[0].hash = claimManifest.source_basis_refs[0].hash;
  const resealedPolicy = sealSelfHash(policy);
  const profilePath = write("source-profile.json", profile);
  const policyPath = write("source-policy.json", resealedPolicy);
  const draft = {
    certificate_ref: "certificate://c8/v3/campaign-fixture", predecessor_certificate_schema_version: "ioi.hypervisor.c7-c8-certificate.v2",
    predecessor_certificate_ref: refs.predecessor, source_basis_refs: [refs.source], operator_principal_ref: "principal://ioi/operator/corpus",
    governed_request_ref: refs.request, claim_manifest_ref: refs.claims, isolation_binding_ref: refs.isolation,
    workload_image_ref: "oci://ghcr.io/ioi-foundation/aft-bench", workload_image_digest: h("b"), workload_readiness_evidence: [refs.readiness],
    campaign_certificate_ref: refs.campaign, campaign_id: "campaign-fixture", benchmark_source_commit: "1234567890123456789012345678901234567890",
    benchmark_protocol_version: "res-p4.3.v2", result_contract_ref: refs.contract, result_ref: refs.result, result_retrieval_receipt_ref: refs.retrieval,
    environment_ref: refs.environment, variance_evidence_ref: refs.variance, environment_class: "measured_container", honesty_class: "same_provider_container_unknown_host",
    authority_draw: { standing_envelope_ref: refs.envelope, draw_request_ref: refs.drawRequest, draw_receipt_ref: refs.drawReceipt },
    trajectory_binding: { state_before_ref: refs.before, decision_ref: refs.decision, state_after_ref: refs.after },
    brokered_secret_use_posture: "opaque_handle_final_invoker", secret_use_evidence: [refs.secret], relying_party_audience_ref: resealedPolicy.audience_ref,
    terminal_acceptance_prerequisites: [resealedPolicy.policy_ref], journal_binding: { intent_root: h("c"), outcome_predecessor_root: h("c"), outcome_root: h("d") },
    terminal_settlement_ref: refs.settlement, generated_at: now,
  };
  const draftPath = write("certificate-draft.json", draft);
  const spec = {
    bundle_ref: "evidence-bundle://aft/campaign-fixture", created_at: now, certificate_draft_path: draftPath, certificate_file: "certificate.json", objects,
    trust_inputs: [
      { ref: resealedPolicy.policy_ref, schema_ref: "schema://ioi/foundations/relying-party-acceptance-policy/v1", file: "policy.json", path: policyPath },
      { ref: profile.profile_ref, schema_ref: "schema://ioi/foundations/verifier-independence-profile/v1", file: "verifier-profile.json", path: profilePath },
    ],
  };
  const positive = path.join(temp, "positive-bundle");
  assemblePortableBundle(spec, positive);
  const registry = sealSelfHash({ schema_version: "ioi.aft.measured-results-registry.v1", registry_ref: "registry://aft/measured-results", revision: 0, previous_state_hash: null, entries: [] });
  const registryPath = write("registry.json", registry);
  const accepted = run("accept", "--bundle", positive, "--policy", path.join(positive, "policy.json"), "--registry", registryPath, "--row-output", path.join(temp, "accepted-row.json"), "--receipt", path.join(temp, "accepted-receipt.json"), "--expected-revision", "0", "--now", now);
  if (accepted.status !== 0) throw new Error(`positive acceptance failed: ${accepted.stderr}`);
  const after = JSON.parse(fs.readFileSync(registryPath, "utf8"));
  const acceptedReceipt = JSON.parse(fs.readFileSync(path.join(temp, "accepted-receipt.json"), "utf8"));
  if (after.revision !== 1 || after.entries.length !== 1 || acceptedReceipt.decision !== "accepted" || acceptedReceipt.mutation_applied !== true) throw new Error("positive acceptance did not atomically promote one row");

  const negative = path.join(temp, "negative-bundle");
  fs.cpSync(positive, negative, { recursive: true });
  const negativeResultPath = path.join(negative, "result.json");
  const negativeResult = JSON.parse(fs.readFileSync(negativeResultPath, "utf8"));
  negativeResult.all_rows_within_threshold = false;
  fs.writeFileSync(negativeResultPath, `${JSON.stringify(negativeResult, null, 2)}\n`);
  let negativeBundle = JSON.parse(fs.readFileSync(path.join(negative, "bundle.json"), "utf8"));
  negativeBundle.objects.find((entry) => entry.ref === refs.result).hash = contentHash(negativeResult);
  let negativeCertificate = JSON.parse(fs.readFileSync(path.join(negative, "certificate.json"), "utf8"));
  negativeCertificate.result_hash = contentHash(negativeResult);
  negativeCertificate = sealSelfHash(negativeCertificate);
  fs.writeFileSync(path.join(negative, "certificate.json"), `${JSON.stringify(negativeCertificate, null, 2)}\n`);
  negativeBundle.certificate_hash = negativeCertificate.certificate_hash;
  negativeBundle = sealSelfHash(negativeBundle);
  fs.writeFileSync(path.join(negative, "bundle.json"), `${JSON.stringify(negativeBundle, null, 2)}\n`);
  const negativeRegistryPath = write("negative-registry.json", registry);
  const beforeBytes = fs.readFileSync(negativeRegistryPath);
  const rejected = run("accept", "--bundle", negative, "--policy", path.join(negative, "policy.json"), "--registry", negativeRegistryPath, "--row-output", path.join(temp, "rejected-row.json"), "--receipt", path.join(temp, "rejected-receipt.json"), "--expected-revision", "0", "--now", now);
  if (rejected.status === 0) throw new Error("resealed semantic mutation was accepted");
  if (!fs.readFileSync(negativeRegistryPath).equals(beforeBytes)) throw new Error("rejected candidate changed registry bytes");
  const rejectedReceipt = JSON.parse(fs.readFileSync(path.join(temp, "rejected-receipt.json"), "utf8"));
  if (rejectedReceipt.decision !== "rejected" || rejectedReceipt.mutation_applied !== false || rejectedReceipt.target_state_before_hash !== rejectedReceipt.target_state_after_hash) throw new Error("rejection receipt did not preserve state truth");
  console.log(JSON.stringify({ ok: true, accepted_revision: after.revision, accepted_certificate_hash: acceptedReceipt.certificate_hash, semantic_mutation_rejected: true, rejection_failure_codes: rejectedReceipt.failure_codes }));
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
