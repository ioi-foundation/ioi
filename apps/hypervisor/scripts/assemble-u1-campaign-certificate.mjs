#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { sealU1Certificate, validateU1Certificate } from "./lib/u1-campaign-certificate.mjs";

const arg = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
};
const artifactsArg = arg("--artifacts");
const lifecycleArg = arg("--lifecycle-certificate");
const lifecycleVerificationArg = arg("--lifecycle-verification");
if (!artifactsArg || !lifecycleArg || !lifecycleVerificationArg) {
  throw new Error("usage: --artifacts <campaign-dir> --lifecycle-certificate <certificate.json> --lifecycle-verification <verification.json> [--output <json>]");
}
const artifacts = path.resolve(artifactsArg);
const lifecyclePath = path.resolve(lifecycleArg);
const lifecycleVerificationPath = path.resolve(lifecycleVerificationArg);
const output = path.resolve(arg("--output") || path.join(artifacts, "u1-campaign-certificate.json"));
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const lifecycle = readJson(lifecyclePath);
const lifecycleVerification = readJson(lifecycleVerificationPath);
const approval = readJson(path.join(artifacts, "approval-request.json"));
const imageBuildIdentity = readJson(path.join(artifacts, "image-build-identity.json"));
const providerPreflight = readJson(path.join(artifacts, "provider-preflight.json"));
const logs = readJson(path.join(artifacts, "c7-logs.json"));
const bundle = logs?.evidence?.workload_result?.bundle;
if (!bundle?.status?.value || !bundle?.environment?.value || !bundle?.results?.value || !bundle?.manifest?.value) {
  throw new Error("campaign logs do not contain the authenticated four-part result bundle");
}
if (lifecycleVerification?.ok !== true || lifecycleVerification?.mutations?.ok !== true) {
  throw new Error("lifecycle certificate and mutation verification must pass before U1 assembly");
}
const facets = approval.reviewed_facets || {};
const certificate = sealU1Certificate({
  ok: true,
  result: "success",
  lifecycle: {
    certificate_hash: lifecycle.certificate_hash,
    verification_ok: true,
    mutation_count: lifecycleVerification.mutations.mutation_count,
    source_commit: lifecycle.source?.commit,
    source_dirty_state: lifecycle.source?.dirty_state_declaration,
    publication_eligible: lifecycle.source?.publication_eligible,
    result_binding: {
      intent_root: lifecycle.journal?.workload_result_intent_root,
      predecessor_root: lifecycle.journal?.workload_result_predecessor_root,
      outcome_root: lifecycle.journal?.workload_result_outcome_root,
      workload_result_ref: lifecycle.journal?.workload_result_ref,
      status_hash: lifecycle.journal?.workload_status_hash,
      environment_hash: lifecycle.journal?.workload_environment_hash,
      result_hash: lifecycle.journal?.workload_result_hash,
      manifest_hash: lifecycle.journal?.workload_manifest_hash,
    },
  },
  authority: {
    policy_hash: approval.policy_hash,
    request_hash: approval.request_hash,
    review_bundle_sha256: approval.review_bundle_sha256,
    campaign_id: facets.campaign_id,
    source_commit: facets.benchmark_source_commit,
    image_digest: facets.image_digest,
    image_build_identity_sha256: facets.image_build_identity_sha256,
    provider_preflight_sha256: facets.provider_preflight_sha256,
    protocol_version: facets.benchmark_protocol_version,
    result_schema_version: facets.result_schema_version,
    warmups: facets.benchmark_warmups,
    measured_passes: facets.benchmark_repeats,
    provider_address: facets.provider_address,
    result_tls_server_certificate_sha256: facets.result_tls_server_certificate_sha256,
    provider_selector: facets.provider_selector,
    auto_topup: facets.auto_topup,
    deposit_usd: facets.deposit_usd,
    ceiling_amount: facets.ceiling_amount,
    ceiling_denom: facets.ceiling_denom,
    teardown_policy: facets.teardown_policy,
    registry_credential_ref_hash: lifecycle.authority?.reviewed_facets?.registry_credential_ref
      ? `bound-in-lifecycle:${lifecycle.certificate_hash}` : null,
    result_credential_ref_hash: lifecycle.authority?.reviewed_facets?.result_credential_ref
      ? `bound-in-lifecycle:${lifecycle.certificate_hash}` : null,
  },
  measurement: {
    status: bundle.status.value,
    environment: bundle.environment.value,
    aggregate: bundle.results.value,
    manifest: bundle.manifest.value,
    response_hashes: {
      status: { sha256: bundle.status.sha256, bytes: bundle.status.bytes },
      environment: { sha256: bundle.environment.sha256, bytes: bundle.environment.bytes },
      results: { sha256: bundle.results.sha256, bytes: bundle.results.bytes },
      manifest: { sha256: bundle.manifest.sha256, bytes: bundle.manifest.bytes },
    },
    raw_response_bodies_base64: {
      status: bundle.status.body_base64,
      environment: bundle.environment.body_base64,
      results: bundle.results.body_base64,
      manifest: bundle.manifest.body_base64,
    },
  },
  workload_build_identity: imageBuildIdentity,
  provider_preflight: providerPreflight,
  provider: {
    dseq: lifecycle.provider?.dseq,
    provider_address: lifecycle.provider?.provider_address,
    lease_ref: lifecycle.provider?.lease_ref,
    lease_state: lifecycle.provider?.lease_state,
    endpoint_ref: lifecycle.provider?.endpoint_ref,
    workload_result_retrieved: lifecycle.provider?.workload_result_retrieved,
  },
  settlement: {
    provider_terminal: lifecycle.teardown?.provider_terminal,
    state: lifecycle.settlement?.state,
    final_net_cost_usd: lifecycle.settlement?.final_net_cost_usd,
    open_exposure_count: lifecycle.settlement?.open_exposure_count,
    unknown_exposure_count: lifecycle.settlement?.unknown_exposure_count,
    provider_response_hash: lifecycle.settlement?.provider_response_hash,
  },
  placement: {
    classification: "same_provider_container_unknown_host",
    attestation_verified: false,
    note: "exact provider pinning does not prove tenant-specific physical placement",
  },
  claims: {
    benchmark_measurement_claimed: true,
    bare_metal_claimed: false,
    provider_neutrality_claimed: false,
    formal_theorem_claimed: false,
  },
  nonclaims: [
    "tenant-specific bare-metal or dedicated-core placement",
    "provider-neutral benchmark reproduction",
    "a formal proof of the AFT theorem",
    "hard secret non-possession by an unattested remote host",
  ],
});
const validation = validateU1Certificate(certificate);
if (!validation.ok) throw new Error(`assembled U1 certificate is invalid: ${JSON.stringify(validation.failures)}`);
fs.writeFileSync(output, `${JSON.stringify(certificate, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify({ ok: true, output, certificate_hash: certificate.certificate_hash }));
