import crypto from "node:crypto";
import { stableStringify } from "./c7-c8-certificate.mjs";

export const U1_SCENARIO_LANES = {
  paper_guardian_majority_4v: ["base_final"],
  paper_guardian_majority_7v: ["base_final"],
  paper_asymptote_4v: ["base_final", "canonical_ordering", "durable_collapse", "sealed_final"],
  paper_asymptote_7v: ["base_final", "canonical_ordering", "durable_collapse", "sealed_final"],
};
export const U1_METRICS = [
  "injection_tps",
  "sustained_tps",
  "commit_p50_ms",
  "commit_p95_ms",
  "commit_p99_ms",
  "commit_max_ms",
];
export const U1_THRESHOLDS = {
  injection_tps: 0.10,
  sustained_tps: 0.10,
  commit_p50_ms: 0.10,
  commit_p95_ms: 0.10,
  commit_p99_ms: 0.15,
  commit_max_ms: 0.15,
};

const hash = (value) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value);
const finite = (value) => typeof value === "number" && Number.isFinite(value);
const same = (left, right) => stableStringify(left) === stableStringify(right);
const sha256Buffer = (value) => `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;

export function u1CertificateHash(certificate) {
  const copy = structuredClone(certificate);
  delete copy.certificate_hash;
  return `sha256:${crypto.createHash("sha256").update(stableStringify(copy)).digest("hex")}`;
}

export function sealU1Certificate(evidence) {
  const certificate = structuredClone(evidence);
  certificate.schema_version = "ioi.hypervisor.u1-aft-campaign-certificate.v1";
  certificate.certificate_hash = u1CertificateHash(certificate);
  return certificate;
}

export function validateU1Certificate(certificate) {
  const failures = [];
  const fail = (code, path, detail) => failures.push({ code, path, detail });
  if (certificate?.schema_version !== "ioi.hypervisor.u1-aft-campaign-certificate.v1") fail("u1_schema_invalid", "schema_version", "unsupported U1 certificate schema");
  if (certificate?.ok !== true || certificate?.result !== "success") fail("u1_campaign_not_successful", "result", "only a successful, complete campaign can certify");
  if (!hash(certificate?.certificate_hash) || u1CertificateHash(certificate) !== certificate.certificate_hash) fail("u1_certificate_hash_mismatch", "certificate_hash", "certificate bytes differ from their seal");

  const lifecycle = certificate?.lifecycle;
  if (!hash(lifecycle?.certificate_hash) || lifecycle?.verification_ok !== true || !Number.isSafeInteger(lifecycle?.mutation_count) || lifecycle.mutation_count < 22) fail("u1_lifecycle_certificate_unverified", "lifecycle", "a verified C7/C8 v2 lifecycle with its mutation run is required");
  if (lifecycle?.publication_eligible !== true || lifecycle?.source_dirty_state !== "clean") fail("u1_lifecycle_source_not_clean", "lifecycle", "U1 must chain to a clean publication-eligible lifecycle basis");
  if (!/^[0-9a-f]{40}$/u.test(lifecycle?.source_commit || "")) fail("u1_lifecycle_source_invalid", "lifecycle.source_commit", "the daemon lifecycle must name its full source commit");

  const authority = certificate?.authority;
  for (const key of ["policy_hash", "request_hash", "review_bundle_sha256", "campaign_id", "source_commit", "image_digest", "image_build_identity_sha256", "provider_preflight_sha256", "protocol_version", "result_schema_version", "provider_address", "result_tls_server_certificate_sha256"]) {
    if (authority?.[key] === undefined || authority?.[key] === null || authority?.[key] === "") fail("u1_authority_facet_missing", `authority.${key}`, "authority-bound campaign facet missing");
  }
  if (![authority?.policy_hash, authority?.request_hash, authority?.review_bundle_sha256].every(hash)) fail("u1_authority_hash_invalid", "authority", "policy, request, and review bundle hashes must be SHA-256 commitments");
  if (!hash(authority?.result_tls_server_certificate_sha256)) fail("u1_result_tls_pin_invalid", "authority.result_tls_server_certificate_sha256", "the owner-reviewed result transport certificate pin is required");
  if (!/^[0-9a-f]{40}$/u.test(authority?.source_commit || "") || !hash(authority?.image_digest)) fail("u1_workload_identity_invalid", "authority", "full source commit and OCI digest are required");
  if (!hash(authority?.image_build_identity_sha256)) fail("u1_build_identity_hash_invalid", "authority.image_build_identity_sha256", "the reviewed workflow build identity hash is required");
  const buildIdentity = certificate?.workload_build_identity;
  if (buildIdentity?.schema_version !== "ioi.aft.benchmark-image-build-identity.v2"
      || buildIdentity?.source_ref !== authority?.source_commit
      || buildIdentity?.image_digest !== authority?.image_digest
      || buildIdentity?.result_tls_server_certificate_sha256 !== authority?.result_tls_server_certificate_sha256
      || sha256Buffer(JSON.stringify(buildIdentity, null, 2) + "\n") !== authority?.image_build_identity_sha256) {
    fail("u1_build_identity_mismatch", "workload_build_identity", "retained workflow identity differs from the owner-reviewed source, image, TLS pin, or exact artifact hash");
  }
  const providerPreflight = certificate?.provider_preflight;
  if (!hash(authority?.provider_preflight_sha256)
      || providerPreflight?.schema_version !== "ioi.aft.u1-provider-preflight.v1"
      || providerPreflight?.provider_address !== authority?.provider_address
      || providerPreflight?.qualified !== true
      || providerPreflight?.bare_metal_attested !== false
      || providerPreflight?.placement_class !== "same_exact_audited_provider_container_allocation_physical_host_unproven"
      || !hash(providerPreflight?.provider_response_sha256)
      || !Array.isArray(providerPreflight?.refusal_codes)
      || providerPreflight.refusal_codes.length !== 0
      || sha256Buffer(JSON.stringify(providerPreflight, null, 2) + "\n") !== authority?.provider_preflight_sha256) {
    fail("u1_provider_preflight_mismatch", "provider_preflight", "the reviewed exact-provider preflight must pass without a bare-metal claim");
  }
  if (authority?.protocol_version !== "res-p4.3.v2" || authority?.result_schema_version !== "ioi.aft.benchmark-campaign.v1" || authority?.warmups !== 1 || authority?.measured_passes !== 5) fail("u1_protocol_contract_invalid", "authority", "U1 fixes one warmup and five measured passes under RES-P4.3 v2");
  if (authority?.provider_selector?.mode !== "exact" || authority?.provider_selector?.selection !== "only_qualified_bid_from_exact_provider" || authority?.provider_selector?.provider_address !== authority?.provider_address) fail("u1_provider_pin_invalid", "authority.provider_selector", "campaign must be bound to one exact provider");
  if (authority?.auto_topup !== false || authority?.teardown_policy !== "always_teardown_required") fail("u1_spend_posture_invalid", "authority", "auto-topup must be false and teardown mandatory");

  const environment = certificate?.measurement?.environment;
  const aggregate = certificate?.measurement?.aggregate;
  const manifest = certificate?.measurement?.manifest;
  const hashes = certificate?.measurement?.response_hashes;
  const rawBodies = certificate?.measurement?.raw_response_bodies_base64;
  if (certificate?.measurement?.status?.schema_version !== "ioi.aft.benchmark-status.v1" || certificate?.measurement?.status?.campaign_id !== authority?.campaign_id || certificate?.measurement?.status?.state !== "complete") fail("u1_status_not_complete", "measurement.status", "authenticated provider status must name the exact completed campaign");
  if (environment?.schema_version !== "ioi.aft.environment-manifest.v1"
      || environment?.campaign_id !== authority?.campaign_id
      || environment?.source_commit !== authority?.source_commit
      || environment?.image_digest !== authority?.image_digest
      || environment?.protocol_version !== authority?.protocol_version
      || environment?.warmups !== authority?.warmups
      || environment?.measured_passes !== authority?.measured_passes) {
    fail("u1_environment_mismatch", "measurement.environment", "environment manifest differs from authorized campaign facets");
  }
  if (aggregate?.schema_version !== authority?.result_schema_version || aggregate?.campaign_id !== authority?.campaign_id || aggregate?.measured_passes !== 5 || aggregate?.row_count_per_pass !== 10) fail("u1_aggregate_identity_mismatch", "measurement.aggregate", "aggregate schema, campaign, pass count, or row count differs");
  if (!same(aggregate?.threshold_policy, U1_THRESHOLDS)) fail("u1_threshold_policy_changed", "measurement.aggregate.threshold_policy", "thresholds differ from the predeclared protocol");

  const expectedKeys = new Set(Object.entries(U1_SCENARIO_LANES).flatMap(([scenario, lanes]) => lanes.map((lane) => `${scenario}/${lane}`)));
  const observedKeys = new Set();
  let allRowsWithin = true;
  for (const row of aggregate?.summaries || []) {
    const key = `${row?.scenario}/${row?.lane}`;
    if (observedKeys.has(key)) fail("u1_duplicate_summary_row", "measurement.aggregate.summaries", key);
    observedKeys.add(key);
    let rowWithin = true;
    for (const metric of U1_METRICS) {
      const summary = row?.metrics?.[metric];
      if (summary?.count !== 5
          || !["min", "median", "max", "median_absolute_deviation", "coefficient_of_variation", "relative_spread", "threshold"].every((field) => finite(summary?.[field]))
          || summary.min > summary.median
          || summary.median > summary.max
          || summary.median_absolute_deviation < 0
          || summary.coefficient_of_variation < 0
          || summary.relative_spread < 0
          || summary.threshold !== U1_THRESHOLDS[metric]
          || summary.within_threshold !== (summary.relative_spread <= summary.threshold)
          || summary?.bootstrap_median_95?.confidence !== 0.95
          || summary?.bootstrap_median_95?.method !== "exact_bootstrap_median"
          || summary?.bootstrap_median_95?.resamples !== 3125
          || !finite(summary?.bootstrap_median_95?.lower)
          || !finite(summary?.bootstrap_median_95?.upper)
          || summary.bootstrap_median_95.lower > summary.median
          || summary.bootstrap_median_95.upper < summary.median) {
        fail("u1_metric_summary_invalid", `measurement.aggregate.${key}.${metric}`, "metric statistics or threshold verdict are malformed");
        rowWithin = false;
      } else {
        rowWithin &&= summary.within_threshold;
      }
    }
    if (row?.within_threshold !== rowWithin) fail("u1_row_verdict_mismatch", `measurement.aggregate.${key}`, "row verdict differs from its metrics");
    allRowsWithin &&= rowWithin;
  }
  if (observedKeys.size !== 10 || [...expectedKeys].some((key) => !observedKeys.has(key)) || [...observedKeys].some((key) => !expectedKeys.has(key))) fail("u1_matrix_incomplete", "measurement.aggregate.summaries", "the canonical 10-row matrix is incomplete or changed");
  if (aggregate?.all_rows_within_threshold !== allRowsWithin || aggregate?.verdict !== (allRowsWithin ? "reproduced_within_threshold" : "variance_caveated")) fail("u1_campaign_verdict_mismatch", "measurement.aggregate.verdict", "campaign verdict differs from the complete metric set");

  if (manifest?.schema_version !== "ioi.aft.artifact-manifest.v1" || manifest?.campaign_id !== authority?.campaign_id) fail("u1_manifest_identity_mismatch", "measurement.manifest", "artifact manifest identity differs");
  for (const name of ["status", "environment", "results", "manifest"]) {
    if (!hash(hashes?.[name]?.sha256) || !Number.isSafeInteger(hashes?.[name]?.bytes) || hashes[name].bytes <= 0) fail("u1_response_hash_missing", `measurement.response_hashes.${name}`, "every authenticated response needs its byte length and SHA-256");
    const encoded = rawBodies?.[name];
    let raw = null;
    let parsed = null;
    try {
      if (typeof encoded !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(encoded)) throw new Error("invalid base64");
      raw = Buffer.from(encoded, "base64");
      if (raw.toString("base64") !== encoded) throw new Error("noncanonical base64");
      parsed = JSON.parse(raw.toString("utf8"));
    } catch {
      fail("u1_response_body_invalid", `measurement.raw_response_bodies_base64.${name}`, "authenticated response body is missing or invalid");
    }
    const expectedValue = name === "results" ? aggregate : certificate?.measurement?.[name];
    if (raw && (
      raw.length !== hashes?.[name]?.bytes
      || sha256Buffer(raw) !== hashes?.[name]?.sha256
      || !same(parsed, expectedValue)
    )) fail("u1_response_body_mismatch", `measurement.raw_response_bodies_base64.${name}`, "parsed evidence differs from its authenticated response bytes");
  }
  const resultBinding = lifecycle?.result_binding;
  if (!hash(resultBinding?.intent_root)
      || !hash(resultBinding?.predecessor_root)
      || !hash(resultBinding?.outcome_root)
      || resultBinding?.outcome_root === resultBinding?.predecessor_root
      || typeof resultBinding?.workload_result_ref !== "string"
      || !resultBinding.workload_result_ref.startsWith("akash-workload-result://")
      || resultBinding?.status_hash !== hashes?.status?.sha256
      || resultBinding?.environment_hash !== hashes?.environment?.sha256
      || resultBinding?.result_hash !== hashes?.results?.sha256
      || resultBinding?.manifest_hash !== hashes?.manifest?.sha256) {
    fail("u1_lifecycle_result_binding_invalid", "lifecycle.result_binding", "the C2 successor root must bind the exact authenticated status, environment, result, and manifest response hashes");
  }
  for (const [name, responseName] of [["environment.json", "environment"], ["result.json", "results"]]) {
    const item = manifest?.artifacts?.find((artifact) => artifact?.name === name);
    if (!item || !hash(item.sha256) || item.sha256 !== hashes?.[responseName]?.sha256 || item.bytes !== hashes?.[responseName]?.bytes) fail("u1_manifest_binding_mismatch", `measurement.manifest.${name}`, "response bytes differ from the provider artifact manifest");
  }

  const provider = certificate?.provider;
  if (provider?.provider_address !== authority?.provider_address || typeof provider?.dseq !== "string" || provider?.lease_state !== "closed" || provider?.workload_result_retrieved !== true) fail("u1_provider_lifecycle_mismatch", "provider", "exact provider, closed lease, and authenticated result retrieval are required");
  const settlement = certificate?.settlement;
  if (settlement?.provider_terminal !== true || settlement?.open_exposure_count !== 0 || settlement?.unknown_exposure_count !== 0 || !finite(settlement?.final_net_cost_usd) || settlement.final_net_cost_usd < 0) fail("u1_settlement_not_terminal", "settlement", "provider settlement must be terminal with no open or unknown exposure");

  if (certificate?.placement?.classification !== "same_provider_container_unknown_host" || certificate?.claims?.bare_metal_claimed !== false) fail("u1_unsupported_bare_metal_claim", "placement", "this certificate version cannot elevate an unattested container run to bare metal");
  if (certificate?.claims?.benchmark_measurement_claimed !== true || certificate?.claims?.provider_neutrality_claimed !== false || certificate?.claims?.formal_theorem_claimed !== false) fail("u1_claim_scope_invalid", "claims", "U1 certifies the benchmark observation only");
  if (!Array.isArray(certificate?.nonclaims) || certificate.nonclaims.length < 3) fail("u1_nonclaims_missing", "nonclaims", "bounded measurement nonclaims are required");

  const serialized = JSON.stringify(certificate);
  if (/"(?:password|session_token|api_key|sealed_token|mnemonic|private_key)"\s*:/iu.test(serialized) || /ioi_sess_[A-Za-z0-9_-]+/u.test(serialized)) fail("u1_secret_bearing_certificate", "$", "certificate contains credential material");
  return { ok: failures.length === 0, failures };
}
