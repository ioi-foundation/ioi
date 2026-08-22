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
  const providerRef = "provider://akash/corpus";
  const providerAddress = "akash1aaul837r7en7hpk9wv2svg8u78fdq0t2j2e82z";
  const imageDigest = h("b");
  const sourceCommit = "1234567890123456789012345678901234567890";
  const requestValue = {
    schema_version: "ioi.hypervisor.provider-operation.v1", operation: "create_deployment", campaign_id: "campaign-fixture",
    benchmark_source_commit: sourceCommit, image_digest: imageDigest, provider_ref: providerRef, provider_address: providerAddress,
    result_destination_ref: "result-destination://aft/corpus",
  };
  const requestHash = contentHash(requestValue);
  const resultRef = "result://aft/campaign-fixture";
  const thresholdPolicy = { injection_tps: 0.1, sustained_tps: 0.1, commit_p50_ms: 0.1, commit_p95_ms: 0.1, commit_p99_ms: 0.15, commit_max_ms: 0.15 };
  const scenarioLanes = [
    ["paper_guardian_majority_4v", "base_final"], ["paper_guardian_majority_7v", "base_final"],
    ...["paper_asymptote_4v", "paper_asymptote_7v"].flatMap((scenario) =>
      ["base_final", "canonical_ordering", "durable_collapse", "sealed_final"].map((lane) => [scenario, lane])),
  ];
  const metric = (name, value) => ({
    values: [value, value, value, value, value], min: value, median: value, max: value,
    median_absolute_deviation: 0, coefficient_of_variation: 0, bootstrap_median_95: [value, value],
    relative_spread: 0, threshold: thresholdPolicy[name], within_threshold: true,
  });
  const summaries = scenarioLanes.map(([scenario, lane], index) => ({
    scenario, lane, within_threshold: true,
    metrics: {
      injection_tps: metric("injection_tps", 100 + index), sustained_tps: metric("sustained_tps", 90 + index),
      commit_p50_ms: metric("commit_p50_ms", 2 + index), commit_p95_ms: metric("commit_p95_ms", 4 + index),
      commit_p99_ms: metric("commit_p99_ms", 6 + index), commit_max_ms: metric("commit_max_ms", 8 + index),
    },
  }));
  const result = {
    schema_version: "ioi.aft.benchmark-campaign.v1", campaign_id: "campaign-fixture", measured_passes: 5, row_count_per_pass: 10,
    threshold_policy: thresholdPolicy,
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
    secret: "evidence://secret-probe/corpus", settlement: "receipt://provider/settlement-corpus", terminal: "receipt://provider/terminal-corpus",
  };
  const objects = [
    generic("predecessor", refs.predecessor, "schema://ioi/components/hypervisor/c8-certificate/v2"),
    object("source", refs.source, "schema://ioi/foundations/source-basis/v1", { commit: sourceCommit }),
    object("request", refs.request, "schema://ioi/components/hypervisor/provider-operation/v1", requestValue),
    object("claims", refs.claims, "schema://ioi/components/hypervisor/governed-effect-claim-manifest/v1", claimManifest),
    generic("isolation", refs.isolation, "schema://ioi/components/hypervisor/workload-isolation-binding/v1", {
      binding_ref: refs.isolation, protection_profile: "trusted_host_hostile_guest", network_posture: "no_nic",
      final_invoker_audience: "hypervisor-final-invoker", direct_protected_effect_invocations: 0, final_invoker_calls: 1,
      guest_uid: 0, output_quarantined: true,
    }),
    generic("readiness", refs.readiness, "schema://ioi/components/hypervisor/provider-readiness/v1", {
      status: "ready", campaign_id: "campaign-fixture", provider_ref: providerRef, image_digest: imageDigest,
      source_commit: sourceCommit, requested_replicas: 1, ready_replicas: 1,
    }),
    generic("campaign", refs.campaign, "schema://ioi/components/hypervisor/u1-campaign-certificate/v1"),
    object("result-contract", refs.contract, "schema://json-schema/draft-2020-12", { $id: refs.contract, type: "object" }),
    object("result", refs.result, "schema://ioi/aft/u1-campaign-result/v1", result),
    generic("retrieval", refs.retrieval, "schema://ioi/components/hypervisor/result-retrieval-receipt/v1", {
      status: "verified", authenticated: true, campaign_id: "campaign-fixture", result_ref: refs.result,
      environment_ref: refs.environment,
    }),
    generic("environment", refs.environment, "schema://ioi/aft/environment-manifest/v1", {
      campaign_id: "campaign-fixture", provider_ref: providerRef, image_digest: imageDigest, source_commit: sourceCommit,
      environment_class: "measured_container", honesty_class: "same_provider_container_unknown_host",
    }),
    generic("variance", refs.variance, "schema://ioi/aft/campaign-variance/v1", {
      campaign_id: "campaign-fixture", verdict: "reproduced_within_threshold", threshold_policy: thresholdPolicy,
    }),
    generic("envelope", refs.envelope, "schema://ioi/foundations/standing-authority-envelope/v1", {
      standing_envelope_ref: refs.envelope, owner_ref: "org://local", bounded_system_ref: "system://aft/corpus",
      principal_ref: "principal://aft/worker", audience_ref: "runtime://hypervisor/corpus",
      authority_scope: "scope:hypervisor.live-route.hypervisor-provider-op",
      facet_template: { operations: ["create", "start", "logs", "delete", "reconcile"], provider_addresses: [providerAddress],
        image_digests: [imageDigest], result_destination_refs: [requestValue.result_destination_ref], auto_topup: false,
        teardown_policy: "always_teardown_required" },
      aggregate_bounds: { max_cumulative_deposit_microusd: 2000000, max_cumulative_spend_microusd: 2000000, max_usages: 2,
        max_concurrent_resources: 1, max_provider_fanout: 1, max_failures: 1 },
      not_before_ms: 1787410000000, expires_at_ms: 1787496400000, revocation_epoch: 1,
      trajectory_policy_ref: "policy://aft/trajectory/corpus", trajectory_policy_hash: h("e"), approval_mode: "standing_envelope",
      recovery_posture: "recovery_never_widens_or_resets_drawdown",
    }),
    generic("draw-request", refs.drawRequest, "schema://ioi/foundations/standing-authority-draw-request/v1", {
      standing_envelope_ref: refs.envelope, candidate_operation_ref: refs.request, candidate_operation_hash: requestHash,
    }),
    generic("draw-receipt", refs.drawReceipt, "schema://ioi/foundations/standing-authority-consumption/v1", {
      standing_envelope_ref: refs.envelope, draw_request_ref: refs.drawRequest, candidate_operation_hash: requestHash,
      decision: "consumed", atomic_consumption: true, revoked: false,
    }),
    generic("trajectory-before", refs.before, "schema://ioi/foundations/authority-trajectory-state/v1", {
      trajectory_state_ref: refs.before, owner_ref: "org://local", bounded_system_ref: "system://aft/corpus",
      principal_ref: "principal://aft/worker", envelope_ancestor_refs: [refs.envelope], revocation_epoch: 1,
      window_started_at: "2026-08-22T15:00:00Z", window_ends_at: later, cumulative_spend_usd: 0,
      cumulative_deposit_usd: 0, active_resource_refs: [], provider_refs: [], destination_refs: [], data_class_refs: [],
      admitted_call_count: 0, failed_call_count: 0, admitted_events: [], derived_at: now,
    }),
    generic("trajectory-decision", refs.decision, "schema://ioi/foundations/trajectory-admission-decision/v1", {
      decision_ref: refs.decision, candidate_operation_ref: refs.request, candidate_operation_hash: requestHash,
      state_before_ref: refs.before, constraint_results: [{ constraint_id: "aggregate_bounds", satisfied: true, observed_value: "1", limit_value: "2", evidence_refs: [] }],
      semantic_risk_evidence_refs: [], decision: "admit", reason_codes: ["within_bounds"], step_up_requirement_refs: [],
      policy_ref: "policy://aft/trajectory/corpus", policy_hash: h("e"), state_after_ref: refs.after, policy_epoch: 1, decided_at: now,
    }),
    generic("trajectory-after", refs.after, "schema://ioi/foundations/authority-trajectory-state/v1", {
      trajectory_state_ref: refs.after, owner_ref: "org://local", bounded_system_ref: "system://aft/corpus",
      principal_ref: "principal://aft/worker", envelope_ancestor_refs: [refs.envelope], revocation_epoch: 1,
      window_started_at: "2026-08-22T15:00:00Z", window_ends_at: later, cumulative_spend_usd: 0.01,
      cumulative_deposit_usd: 1, active_resource_refs: ["environment://aft/campaign-fixture"], provider_refs: [providerRef],
      destination_refs: [requestValue.result_destination_ref], data_class_refs: ["data-class://public-benchmark"], admitted_call_count: 1,
      failed_call_count: 0, admitted_events: [{ ref: refs.request, hash: requestHash }], derived_at: now,
    }),
    generic("secret-evidence", refs.secret, "schema://ioi/components/hypervisor/worker-secret-non-possession/v1", {
      guest_uid: 0, seeded_canary_count: 4, secret_findings: 0, provider_credential_observed: false,
      recovery_material_observed: false, broker_separate_from_guest: true,
    }),
    generic("settlement", refs.settlement, "schema://ioi/components/hypervisor/provider-settlement/v1", {
      provider_ref: providerRef, provider_address: providerAddress, campaign_id: "campaign-fixture", lease_status: "closed",
      deployment_status: "closed", escrow_status: "closed", active_lease_count: 0, open_unknown_exposure_microusd: 0, teardown_verified: true,
    }),
    generic("terminal", refs.terminal, "schema://ioi/components/hypervisor/terminal-acceptance-prerequisite/v1", {
      campaign_id: "campaign-fixture", terminal: true, cleanup_verified: true, result_verified: true,
    }),
  ];
  const sourceEntry = objects.find((entry) => entry.ref === refs.source);
  claimManifest.source_basis_refs[0].hash = contentHash(JSON.parse(fs.readFileSync(sourceEntry.path, "utf8")));
  const claimsEntry = objects.find((entry) => entry.ref === refs.claims);
  fs.writeFileSync(claimsEntry.path, `${JSON.stringify(claimManifest, null, 2)}\n`, { mode: 0o600 });
  const readObject = (reference) => {
    const entry = objects.find((candidate) => candidate.ref === reference);
    if (!entry) throw new Error(`fixture object missing: ${reference}`);
    return [entry, JSON.parse(fs.readFileSync(entry.path, "utf8"))];
  };
  const rewriteObject = (entry, value) => fs.writeFileSync(entry.path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  const [resultEntry] = readObject(refs.result);
  const [environmentEntry] = readObject(refs.environment);
  const [settlementEntry] = readObject(refs.settlement);
  const resultHash = contentHash(JSON.parse(fs.readFileSync(resultEntry.path, "utf8")));
  const environmentHash = contentHash(JSON.parse(fs.readFileSync(environmentEntry.path, "utf8")));
  const settlementHash = contentHash(JSON.parse(fs.readFileSync(settlementEntry.path, "utf8")));
  const [retrievalEntry, retrievalValue] = readObject(refs.retrieval);
  Object.assign(retrievalValue, { result_hash: resultHash, environment_hash: environmentHash });
  rewriteObject(retrievalEntry, retrievalValue);
  const [beforeEntry] = readObject(refs.before);
  const [afterEntry] = readObject(refs.after);
  const [decisionEntry, decisionValue] = readObject(refs.decision);
  Object.assign(decisionValue, { state_before_hash: contentHash(JSON.parse(fs.readFileSync(beforeEntry.path, "utf8"))), state_after_hash: contentHash(JSON.parse(fs.readFileSync(afterEntry.path, "utf8"))) });
  rewriteObject(decisionEntry, decisionValue);
  const [campaignEntry, campaignValue] = readObject(refs.campaign);
  Object.assign(campaignValue, {
    status: "complete", campaign_id: "campaign-fixture", provider_ref: providerRef, image_digest: imageDigest,
    source_commit: sourceCommit, result_ref: refs.result, result_hash: resultHash, environment_ref: refs.environment,
    environment_hash: environmentHash, terminal_settlement_ref: refs.settlement, terminal_settlement_hash: settlementHash,
  });
  rewriteObject(campaignEntry, campaignValue);
  policy.trust_roots[0].hash = claimManifest.source_basis_refs[0].hash;
  const resealedPolicy = sealSelfHash(policy);
  const profilePath = write("source-profile.json", profile);
  const policyPath = write("source-policy.json", resealedPolicy);
  const draft = {
    certificate_ref: "certificate://c8/v3/campaign-fixture", predecessor_certificate_schema_version: "ioi.hypervisor.c7-c8-certificate.v2",
    predecessor_certificate_ref: refs.predecessor, source_basis_refs: [refs.source], operator_principal_ref: "principal://ioi/operator/corpus",
    governed_request_ref: refs.request, claim_manifest_ref: refs.claims, isolation_binding_ref: refs.isolation,
    workload_image_ref: "oci://ghcr.io/ioi-foundation/aft-bench", workload_image_digest: imageDigest, workload_readiness_evidence: [refs.readiness],
    campaign_certificate_ref: refs.campaign, campaign_id: "campaign-fixture", benchmark_source_commit: sourceCommit,
    benchmark_protocol_version: "res-p4.3.v2", result_contract_ref: refs.contract, result_ref: refs.result, result_retrieval_receipt_ref: refs.retrieval,
    environment_ref: refs.environment, variance_evidence_ref: refs.variance, environment_class: "measured_container", honesty_class: "same_provider_container_unknown_host",
    authority_draw: { standing_envelope_ref: refs.envelope, draw_request_ref: refs.drawRequest, draw_receipt_ref: refs.drawReceipt },
    trajectory_binding: { state_before_ref: refs.before, decision_ref: refs.decision, state_after_ref: refs.after },
    brokered_secret_use_posture: "opaque_handle_final_invoker", secret_use_evidence: [refs.secret], relying_party_audience_ref: resealedPolicy.audience_ref,
    terminal_acceptance_prerequisites: [refs.terminal], journal_binding: { intent_root: h("c"), outcome_predecessor_root: h("c"), outcome_root: h("d") },
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

  const readBundleObject = (directory, bundle, reference) => {
    const descriptor = [...bundle.objects, ...bundle.trust_inputs].find((entry) => entry.ref === reference);
    if (!descriptor) throw new Error(`portable descriptor missing: ${reference}`);
    return [descriptor, JSON.parse(fs.readFileSync(path.join(directory, descriptor.file), "utf8"))];
  };
  const replaceCertificateBinding = (value, reference, hash) => {
    if (Array.isArray(value)) {
      for (const item of value) replaceCertificateBinding(item, reference, hash);
      return;
    }
    if (!value || typeof value !== "object") return;
    if (value.ref === reference && typeof value.hash === "string") value.hash = hash;
    for (const [key, child] of Object.entries(value)) {
      if (key.endsWith("_ref") && child === reference) {
        const hashKey = `${key.slice(0, -4)}_hash`;
        if (Object.hasOwn(value, hashKey)) value[hashKey] = hash;
      }
      replaceCertificateBinding(child, reference, hash);
    }
  };
  const fullyReseal = (directory, objectRef, mutate, mutateCertificate) => {
    let bundle = JSON.parse(fs.readFileSync(path.join(directory, "bundle.json"), "utf8"));
    let certificate = JSON.parse(fs.readFileSync(path.join(directory, "certificate.json"), "utf8"));
    const writeBoundObject = (reference, value) => {
      const [descriptor] = readBundleObject(directory, bundle, reference);
      try { value = sealSelfHash(value); } catch { /* objects without self-hash contracts use their full JCS hash */ }
      fs.writeFileSync(path.join(directory, descriptor.file), `${JSON.stringify(value, null, 2)}\n`);
      descriptor.hash = contentHash(value);
      replaceCertificateBinding(certificate, reference, descriptor.hash);
      return descriptor.hash;
    };
    if (objectRef) {
      const [, value] = readBundleObject(directory, bundle, objectRef);
      mutate(value);
      const changedHash = writeBoundObject(objectRef, value);
      if (objectRef === refs.request) {
        const [, claims] = readBundleObject(directory, bundle, refs.claims);
        claims.subject_hash = changedHash;
        writeBoundObject(refs.claims, claims);
        for (const dependentRef of [refs.drawRequest, refs.drawReceipt, refs.decision]) {
          const [, dependent] = readBundleObject(directory, bundle, dependentRef);
          dependent.candidate_operation_hash = changedHash;
          writeBoundObject(dependentRef, dependent);
        }
      }
      if (objectRef === refs.result || objectRef === refs.environment) {
        const hashField = objectRef === refs.result ? "result_hash" : "environment_hash";
        for (const dependentRef of [refs.retrieval, refs.campaign]) {
          const [, dependent] = readBundleObject(directory, bundle, dependentRef);
          dependent[hashField] = changedHash;
          writeBoundObject(dependentRef, dependent);
        }
      }
      if (objectRef === refs.settlement) {
        const [, campaignObject] = readBundleObject(directory, bundle, refs.campaign);
        campaignObject.terminal_settlement_hash = changedHash;
        writeBoundObject(refs.campaign, campaignObject);
      }
      if (objectRef === refs.before || objectRef === refs.after) {
        const [, decisionObject] = readBundleObject(directory, bundle, refs.decision);
        decisionObject[objectRef === refs.before ? "state_before_hash" : "state_after_hash"] = changedHash;
        writeBoundObject(refs.decision, decisionObject);
      }
    }
    if (mutateCertificate) mutateCertificate(certificate);
    certificate = sealSelfHash(certificate);
    fs.writeFileSync(path.join(directory, "certificate.json"), `${JSON.stringify(certificate, null, 2)}\n`);
    bundle.certificate_hash = certificate.certificate_hash;
    bundle = sealSelfHash(bundle);
    fs.writeFileSync(path.join(directory, "bundle.json"), `${JSON.stringify(bundle, null, 2)}\n`);
  };
  const mutations = [
    ["result-verdict", refs.result, (v) => { v.all_rows_within_threshold = false; }],
    ["result-scenario", refs.result, (v) => { v.summaries[0].scenario = "paper_unknown_4v"; }],
    ["result-pass-count", refs.result, (v) => { v.summaries[0].metrics.injection_tps.values.pop(); }],
    ["result-threshold", refs.result, (v) => { v.summaries[0].metrics.injection_tps.threshold = 0.2; }],
    ["request-provider", refs.request, (v) => { v.provider_ref = "provider://akash/other"; }],
    ["request-address", refs.request, (v) => { v.provider_address = "akash19zzh7whjt4vfwxd5wtj3tjtyatnpntfhldshd8"; }],
    ["request-image", refs.request, (v) => { v.image_digest = h("9"); }],
    ["request-source", refs.request, (v) => { v.benchmark_source_commit = "9".repeat(40); }],
    ["request-operation", refs.request, (v) => { v.operation = "delete"; }],
    ["readiness-status", refs.readiness, (v) => { v.status = "pending"; }],
    ["readiness-replicas", refs.readiness, (v) => { v.ready_replicas = 0; }],
    ["readiness-provider", refs.readiness, (v) => { v.provider_ref = "provider://akash/other"; }],
    ["readiness-image", refs.readiness, (v) => { v.image_digest = h("9"); }],
    ["retrieval-auth", refs.retrieval, (v) => { v.authenticated = false; }],
    ["retrieval-result", refs.retrieval, (v) => { v.result_hash = h("9"); }],
    ["environment-provider", refs.environment, (v) => { v.provider_ref = "provider://akash/other"; }],
    ["environment-class", refs.environment, (v) => { v.environment_class = "unmeasured"; }],
    ["campaign-status", refs.campaign, (v) => { v.status = "partial"; }],
    ["campaign-result", refs.campaign, (v) => { v.result_hash = h("9"); }],
    ["isolation-network", refs.isolation, (v) => { v.network_posture = "egress_enabled"; }],
    ["isolation-bypass", refs.isolation, (v) => { v.direct_protected_effect_invocations = 1; }],
    ["isolation-invoker", refs.isolation, (v) => { v.final_invoker_calls = 0; }],
    ["secret-finding", refs.secret, (v) => { v.secret_findings = 1; }],
    ["secret-credential", refs.secret, (v) => { v.provider_credential_observed = true; }],
    ["envelope-topup", refs.envelope, (v) => { v.facet_template.auto_topup = true; }],
    ["envelope-image", refs.envelope, (v) => { v.facet_template.image_digests = [h("9")]; }],
    ["draw-decision", refs.drawReceipt, (v) => { v.decision = "refused"; }],
    ["draw-atomicity", refs.drawReceipt, (v) => { v.atomic_consumption = false; }],
    ["trajectory-decision", refs.decision, (v) => { v.decision = "deny"; }],
    ["trajectory-constraint", refs.decision, (v) => { v.constraint_results[0].satisfied = false; }],
    ["trajectory-count", refs.after, (v) => { v.admitted_call_count = 0; }],
    ["trajectory-provider", refs.after, (v) => { v.provider_refs = []; }],
    ["settlement-lease", refs.settlement, (v) => { v.lease_status = "open"; }],
    ["settlement-exposure", refs.settlement, (v) => { v.open_unknown_exposure_microusd = 1; }],
    ["settlement-teardown", refs.settlement, (v) => { v.teardown_verified = false; }],
    ["terminal-result", refs.terminal, (v) => { v.result_verified = false; }],
    ["journal-predecessor", null, null, (v) => { v.journal_binding.outcome_predecessor_root = h("9"); }],
    ["journal-no-advance", null, null, (v) => { v.journal_binding.outcome_root = v.journal_binding.intent_root; }],
  ];
  const rejectionCodes = {};
  for (const [index, [name, objectRef, mutate, mutateCertificate]] of mutations.entries()) {
    const negative = path.join(temp, `negative-${index}-${name}`);
    fs.cpSync(positive, negative, { recursive: true });
    fullyReseal(negative, objectRef, mutate, mutateCertificate);
    const negativeRegistryPath = write(`negative-registry-${index}.json`, registry);
    const beforeBytes = fs.readFileSync(negativeRegistryPath);
    const receiptPath = path.join(temp, `rejected-receipt-${index}.json`);
    const rejected = run("accept", "--bundle", negative, "--policy", path.join(negative, "policy.json"), "--registry", negativeRegistryPath, "--row-output", path.join(temp, `rejected-row-${index}.json`), "--receipt", receiptPath, "--expected-revision", "0", "--now", now);
    if (rejected.status === 0) throw new Error(`resealed semantic mutation was accepted: ${name}`);
    if (!fs.readFileSync(negativeRegistryPath).equals(beforeBytes)) throw new Error(`rejected candidate changed registry bytes: ${name}`);
    const rejectedReceipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    if (rejectedReceipt.decision !== "rejected" || rejectedReceipt.mutation_applied !== false || rejectedReceipt.target_state_before_hash !== rejectedReceipt.target_state_after_hash) throw new Error(`rejection receipt did not preserve state truth: ${name}`);
    rejectionCodes[name] = rejectedReceipt.failure_codes;
  }
  console.log(JSON.stringify({ ok: true, accepted_revision: after.revision, accepted_certificate_hash: acceptedReceipt.certificate_hash, resealed_semantic_mutations_rejected: mutations.length, rejection_codes: rejectionCodes }));
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
