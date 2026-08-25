import crypto from "node:crypto";
import { stableStringify } from "./c7-c8-certificate.mjs";
import { qualifyU1Provider, sha256Bytes } from "./u1-provider-preflight.mjs";
import { sealU1Certificate, U1_METRICS, U1_SCENARIO_LANES, U1_THRESHOLDS } from "./u1-campaign-certificate.mjs";

export function validU1Fixture() {
  const campaign = "u1-campaign-a";
  const sourceCommit = "b".repeat(40);
  const imageDigest = `sha256:${"a".repeat(64)}`;
  const resultTlsPin = `sha256:${"a".repeat(64)}`;
  const providerAddress = "akash15tl6v6gd0nte0syyxnv57zmmspgju4c3xfmdhk";
  const buildIdentity = {
    schema_version: "ioi.aft.benchmark-image-build-identity.v2",
    source_ref: sourceCommit,
    image_digest: imageDigest,
    base_image_digest: `sha256:${"7".repeat(64)}`,
    cargo_lock_sha256: `sha256:${"8".repeat(64)}`,
    dockerfile_sha256: `sha256:${"9".repeat(64)}`,
    runner_sha256: `sha256:${"a".repeat(64)}`,
    result_tools_sha256: `sha256:${"b".repeat(64)}`,
    result_tls_server_certificate_sha256: resultTlsPin,
    github_run_id: "32590976443",
    github_run_attempt: "1",
  };
  const buildIdentityHash = `sha256:${crypto.createHash("sha256").update(`${JSON.stringify(buildIdentity, null, 2)}\n`).digest("hex")}`;
  const providerResponseBytes = Buffer.from(JSON.stringify({
    owner: providerAddress,
    name: "fixture-provider",
    hostUri: "https://provider.fixture.invalid:8443",
    lastCheckDate: "2026-08-22T18:38:26Z",
    isOnline: true,
    isAudited: true,
    isValidVersion: true,
    hardwareCpuArch: "x86-64",
    uptime1d: 1,
    uptime7d: 1,
    stats: {
      cpu: { available: 16_000 },
      memory: { available: 64 * 1024 ** 3 },
      storage: { ephemeral: { available: 1024 ** 4 } },
    },
  }));
  const providerPreflight = {
    schema_version: "ioi.aft.u1-provider-preflight.v1",
    provider_response_sha256: sha256Bytes(providerResponseBytes),
    ...qualifyU1Provider(JSON.parse(providerResponseBytes), providerAddress),
  };
  const providerPreflightHash = `sha256:${crypto.createHash("sha256").update(`${JSON.stringify(providerPreflight, null, 2)}\n`).digest("hex")}`;
  const summaries = Object.entries(U1_SCENARIO_LANES).flatMap(([scenario, lanes]) => lanes.map((lane) => ({
    scenario,
    lane,
    within_threshold: true,
    metrics: Object.fromEntries(U1_METRICS.map((metric) => [metric, {
      values: [98, 99, 100, 101, 102],
      min: 98,
      median: 100,
      max: 102,
      median_absolute_deviation: 1,
      coefficient_of_variation: 0.0158113883008419,
      bootstrap_median_95: [98, 102],
      relative_spread: 0.04,
      threshold: U1_THRESHOLDS[metric],
      within_threshold: true,
    }])),
  })));
  const status = { schema_version: "ioi.aft.benchmark-status.v1", campaign_id: campaign, state: "complete" };
  const environment = {
    schema_version: "ioi.aft.environment-manifest.v1",
    campaign_id: campaign,
    source_commit: sourceCommit,
    image_digest: imageDigest,
    protocol_version: "res-p4.3.v2",
    warmups: 1,
    measured_passes: 5,
  };
  const aggregate = {
    schema_version: "ioi.aft.benchmark-campaign.v1",
    campaign_id: campaign,
    measured_passes: 5,
    row_count_per_pass: 10,
    threshold_policy: U1_THRESHOLDS,
    verdict: "reproduced_within_threshold",
    all_rows_within_threshold: true,
    summaries,
  };
  const raw = (value) => Buffer.from(stableStringify(value));
  const response = (value) => ({
    bytes: raw(value).length,
    sha256: `sha256:${crypto.createHash("sha256").update(raw(value)).digest("hex")}`,
    body_base64: raw(value).toString("base64"),
  });
  const environmentResponse = response(environment);
  const resultsResponse = response(aggregate);
  const manifest = {
    schema_version: "ioi.aft.artifact-manifest.v1",
    campaign_id: campaign,
    artifacts: [
      { name: "environment.json", bytes: environmentResponse.bytes, sha256: environmentResponse.sha256 },
      { name: "result.json", bytes: resultsResponse.bytes, sha256: resultsResponse.sha256 },
    ],
  };
  const responses = {
    status: response(status),
    environment: environmentResponse,
    results: resultsResponse,
    manifest: response(manifest),
  };
  return sealU1Certificate({
    ok: true,
    result: "success",
    lifecycle: {
      certificate_hash: `sha256:${"3".repeat(64)}`,
      verification_ok: true,
      mutation_count: 22,
      source_commit: sourceCommit,
      source_dirty_state: "clean",
      publication_eligible: true,
      result_binding: {
        intent_root: `sha256:${"c".repeat(64)}`,
        predecessor_root: `sha256:${"d".repeat(64)}`,
        outcome_root: `sha256:${"e".repeat(64)}`,
        workload_result_ref: "akash-workload-result://akresult_fixture",
        status_hash: responses.status.sha256,
        environment_hash: responses.environment.sha256,
        result_hash: responses.results.sha256,
        manifest_hash: responses.manifest.sha256,
      },
    },
    authority: {
      policy_hash: `sha256:${"4".repeat(64)}`,
      request_hash: `sha256:${"5".repeat(64)}`,
      review_bundle_sha256: `sha256:${"6".repeat(64)}`,
      campaign_id: campaign,
      source_commit: sourceCommit,
      image_digest: imageDigest,
      image_build_identity_sha256: buildIdentityHash,
      provider_preflight_sha256: providerPreflightHash,
      protocol_version: "res-p4.3.v2",
      result_schema_version: "ioi.aft.benchmark-campaign.v1",
      warmups: 1,
      measured_passes: 5,
      provider_address: providerAddress,
      result_tls_server_certificate_sha256: resultTlsPin,
      provider_selector: {
        mode: "exact",
        provider_address: providerAddress,
        selection: "only_qualified_bid_from_exact_provider",
      },
      auto_topup: false,
      deposit_usd: 1,
      ceiling_amount: "1000",
      ceiling_denom: "uact",
      teardown_policy: "always_teardown_required",
    },
    workload_build_identity: buildIdentity,
    provider_preflight: providerPreflight,
    provider_preflight_response: {
      bytes: providerResponseBytes.length,
      sha256: providerPreflight.provider_response_sha256,
      body_base64: providerResponseBytes.toString("base64"),
    },
    measurement: {
      status,
      environment,
      aggregate,
      manifest,
      response_hashes: {
        status: { bytes: responses.status.bytes, sha256: responses.status.sha256 },
        environment: { bytes: responses.environment.bytes, sha256: responses.environment.sha256 },
        results: { bytes: responses.results.bytes, sha256: responses.results.sha256 },
        manifest: { bytes: responses.manifest.bytes, sha256: responses.manifest.sha256 },
      },
      raw_response_bodies_base64: {
        status: responses.status.body_base64,
        environment: responses.environment.body_base64,
        results: responses.results.body_base64,
        manifest: responses.manifest.body_base64,
      },
    },
    provider: {
      dseq: "1787000000000",
      provider_address: providerAddress,
      lease_ref: "akash-lease://one",
      lease_state: "closed",
      endpoint_ref: "akash-endpoint://one",
      workload_result_retrieved: true,
    },
    settlement: {
      provider_terminal: true,
      state: "final_debit_settled",
      final_net_cost_usd: 0.000002,
      open_exposure_count: 0,
      unknown_exposure_count: 0,
      provider_response_hash: `sha256:${"9".repeat(64)}`,
    },
    placement: {
      classification: "same_provider_container_unknown_host",
      attestation_verified: false,
    },
    claims: {
      benchmark_measurement_claimed: true,
      bare_metal_claimed: false,
      provider_neutrality_claimed: false,
      formal_theorem_claimed: false,
    },
    nonclaims: [
      "tenant-specific bare-metal placement",
      "provider-neutral reproduction",
      "formal theorem proof",
    ],
  });
}
