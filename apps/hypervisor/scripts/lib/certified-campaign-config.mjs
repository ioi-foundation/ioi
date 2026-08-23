import { qualifyU1Provider, sha256Bytes } from "./u1-provider-preflight.mjs";

const unresolvedOwnerReview = /OWNER_(?:APPROVED|SELECTED|SEEDED)|IMMUTABLE_IMAGE_DIGEST|PRIVATE_REGISTRY/u;

export function certifiedWorkloadDeadlineMs(readinessProvenAtMs, maxDurationSeconds) {
  if (!Number.isSafeInteger(readinessProvenAtMs) || readinessProvenAtMs < 0) {
    throw new Error("readinessProvenAtMs must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(maxDurationSeconds) || maxDurationSeconds < 1) {
    throw new Error("maxDurationSeconds must be a positive safe integer");
  }
  const deadline = readinessProvenAtMs + maxDurationSeconds * 1_000;
  if (!Number.isSafeInteger(deadline)) throw new Error("workload deadline exceeds safe integer range");
  return deadline;
}

export function certifiedRemainingDelayMs(nowMs, deadlineMs, requestedMs) {
  if (![nowMs, deadlineMs, requestedMs].every(Number.isSafeInteger) || requestedMs < 0) {
    throw new Error("deadline delay inputs must be safe integers and requestedMs non-negative");
  }
  return Math.max(0, Math.min(requestedMs, deadlineMs - nowMs));
}

/** Refuse a campaign until every authority-bearing choice is concrete. */
export function validateCertifiedCampaignConfig(config) {
  if (unresolvedOwnerReview.test(JSON.stringify(config))) {
    throw new Error("campaign config contains unresolved owner-review tokens");
  }
  if (config?.schema_version !== "ioi.hypervisor.certified-provider-campaign.v1") {
    throw new Error("unsupported campaign config schema");
  }
  const plan = config.plan || {};
  const deposit = plan.deposit_usd;
  const ceiling = String(plan.ceiling_amount || "");
  const selector = plan.provider_selector || {};
  if (!(typeof deposit === "number" && Number.isFinite(deposit) && deposit > 0 && deposit <= 5)) {
    throw new Error("plan.deposit_usd must be an explicit number greater than 0 and at most 5");
  }
  if (!/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/u.test(ceiling) || Number(ceiling) <= 0) {
    throw new Error("plan.ceiling_amount must be an explicit positive decimal string");
  }
  if (plan.ceiling_denom !== "uact") throw new Error("plan.ceiling_denom must be uact");
  if (plan.teardown_policy !== "always_teardown_required") {
    throw new Error("plan.teardown_policy must be always_teardown_required");
  }
  if (plan.auto_topup === true) throw new Error("plan.auto_topup cannot be enabled");
  if (config.workload_effect_broker?.enabled === true) {
    const broker = config.workload_effect_broker;
    const exactKeys = [
      "enabled",
      "isolation_binding_ref",
      "isolation_binding_hash",
      "guest_principal_ref",
      "proposal_nonce",
      "resource_ref",
      "result_destination_ref",
      "expires_in_seconds",
    ];
    if (Object.keys(broker).length !== exactKeys.length
        || Object.keys(broker).some((key) => !exactKeys.includes(key))) {
      throw new Error("workload_effect_broker must use the exact reviewed field set");
    }
    if (!/^workload-isolation-binding:\/\/\S{1,480}$/u.test(String(broker.isolation_binding_ref || ""))
        || !/^sha256:[0-9a-f]{64}$/u.test(String(broker.isolation_binding_hash || ""))
        || !/^principal:\/\/\S{1,480}$/u.test(String(broker.guest_principal_ref || ""))
        || !/^[A-Za-z0-9._-]{8,256}$/u.test(String(broker.proposal_nonce || ""))
        || !/^result-destination:\/\/\S{1,480}$/u.test(String(broker.result_destination_ref || ""))) {
      throw new Error("workload_effect_broker carries an invalid reviewed binding");
    }
    if (broker.resource_ref !== `provider-resource://${config.provider_id}/${config.environment_ref}`) {
      throw new Error("workload_effect_broker resource_ref must bind the exact provider account and environment");
    }
    if (!Number.isSafeInteger(broker.expires_in_seconds)
        || broker.expires_in_seconds < 60
        || broker.expires_in_seconds > 15 * 60) {
      throw new Error("workload_effect_broker expires_in_seconds must be between 60 and 900");
    }
  }
  if (config.standing_authority?.enabled === true) {
    const standing = config.standing_authority;
    const exactKeys = [
      "enabled",
      "factor_profile",
      "standing_envelope_ref",
      "bounded_system_ref",
      "trajectory_policy_ref",
      "trajectory_policy_hash",
      "revocation_epoch",
      "expires_in_seconds",
      "aggregate_bounds",
    ];
    if (Object.keys(standing).length !== exactKeys.length
        || Object.keys(standing).some((key) => !exactKeys.includes(key))) {
      throw new Error("standing_authority must use the exact reviewed field set");
    }
    if (standing.factor_profile !== "software_passkey_trusted_host"
        || !/^standing-envelope:\/\/\S{1,460}$/u.test(String(standing.standing_envelope_ref || ""))
        || !/^[a-z][a-z0-9+._-]*:\/\/\S{1,500}$/u.test(String(standing.bounded_system_ref || ""))
        || !/^policy:\/\/\S{1,490}$/u.test(String(standing.trajectory_policy_ref || ""))
        || !/^sha256:[0-9a-f]{64}$/u.test(String(standing.trajectory_policy_hash || ""))) {
      throw new Error("standing_authority carries an invalid reviewed identity or policy binding");
    }
    if (!Number.isSafeInteger(standing.revocation_epoch) || standing.revocation_epoch < 0
        || !Number.isSafeInteger(standing.expires_in_seconds)
        || standing.expires_in_seconds < 300 || standing.expires_in_seconds > 4 * 60 * 60) {
      throw new Error("standing_authority validity or revocation epoch is invalid");
    }
    const bounds = standing.aggregate_bounds || {};
    const boundKeys = [
      "max_cumulative_deposit_microusd",
      "max_cumulative_spend_microusd",
      "max_usages",
      "max_concurrent_resources",
      "max_provider_fanout",
      "max_failures",
    ];
    if (Object.keys(bounds).length !== boundKeys.length
        || Object.keys(bounds).some((key) => !boundKeys.includes(key))
        || !boundKeys.every((key) => Number.isSafeInteger(bounds[key]) && bounds[key] >= 0)
        || bounds.max_usages < 1 || bounds.max_concurrent_resources < 1
        || bounds.max_provider_fanout < 1
        || bounds.max_cumulative_deposit_microusd < Math.round(deposit * 1_000_000)
        || bounds.max_cumulative_spend_microusd < Math.round(deposit * 1_000_000)) {
      throw new Error("standing_authority aggregate bounds are invalid or smaller than one reviewed draw");
    }
  }
  if (plan.benchmark_protocol_version) {
    if (selector.mode !== "exact"
        || selector.selection !== "only_qualified_bid_from_exact_provider"
        || !/^akash1[02-9ac-hj-np-z]{38}$/u.test(String(selector.provider_address || ""))) {
      throw new Error("U1 requires one explicit exact Akash provider address");
    }
    if (!/^sha256:[0-9a-f]{64}$/u.test(String(plan.result_tls_server_certificate_sha256 || ""))) {
      throw new Error("U1 requires one explicit result TLS server certificate SHA-256 pin");
    }
    if (!/^sha256:[0-9a-f]{64}$/u.test(String(plan.image_build_identity_sha256 || ""))) {
      throw new Error("U1 requires one explicit immutable image build-identity SHA-256");
    }
    if (typeof config.image_build_identity_path !== "string" || config.image_build_identity_path.length === 0) {
      throw new Error("U1 requires image_build_identity_path");
    }
    if (!/^sha256:[0-9a-f]{64}$/u.test(String(plan.provider_preflight_sha256 || ""))) {
      throw new Error("U1 requires one explicit provider-preflight SHA-256");
    }
    if (typeof config.provider_preflight_path !== "string" || config.provider_preflight_path.length === 0) {
      throw new Error("U1 requires provider_preflight_path");
    }
    if (typeof config.provider_response_path !== "string" || config.provider_response_path.length === 0) {
      throw new Error("U1 requires provider_response_path");
    }
    if (!Number.isSafeInteger(plan.max_duration_seconds)
        || plan.max_duration_seconds < 60
        || plan.max_duration_seconds > 24 * 60 * 60) {
      throw new Error("U1 requires an explicit max_duration_seconds between 60 and 86400");
    }
  }
  return config;
}

/** Validate the retained workflow identity before any challenge is prepared. */
export function validateBenchmarkBuildIdentity(identity, config) {
  const plan = config?.plan || {};
  const hash = (value) => /^sha256:[0-9a-f]{64}$/u.test(String(value || ""));
  if (identity?.schema_version !== "ioi.aft.benchmark-image-build-identity.v2") {
    throw new Error("unsupported benchmark image build identity schema");
  }
  if (identity.source_ref !== plan.benchmark_source_commit
      || identity.image_digest !== plan.image_digest
      || identity.result_tls_server_certificate_sha256 !== plan.result_tls_server_certificate_sha256) {
    throw new Error("benchmark image build identity differs from the reviewed workload identity");
  }
  for (const field of [
    "image_digest",
    "base_image_digest",
    "cargo_lock_sha256",
    "dockerfile_sha256",
    "runner_sha256",
    "result_tools_sha256",
    "result_tls_server_certificate_sha256",
  ]) {
    if (!hash(identity[field])) throw new Error(`benchmark image build identity has invalid ${field}`);
  }
  if (!/^[1-9][0-9]*$/u.test(String(identity.github_run_id || ""))
      || !/^[1-9][0-9]*$/u.test(String(identity.github_run_attempt || ""))) {
    throw new Error("benchmark image build identity lacks a valid workflow run identity");
  }
  return identity;
}

export const U1_PROVIDER_PREFLIGHT_MAX_AGE_MS = 15 * 60 * 1_000;
export const U1_PROVIDER_OBSERVATION_MAX_AGE_MS = 30 * 60 * 1_000;

/** Refuse a stale, failed, or fallback provider qualification artifact. */
export function validateProviderPreflight(preflight, config, nowMs = Date.now()) {
  const expected = config?.plan?.provider_selector?.provider_address;
  if (preflight?.schema_version !== "ioi.aft.u1-provider-preflight.v1") {
    throw new Error("unsupported U1 provider preflight schema");
  }
  if (preflight.provider_address !== expected
      || preflight.qualified !== true
      || !Array.isArray(preflight.refusal_codes)
      || preflight.refusal_codes.length !== 0) {
    throw new Error("U1 provider preflight does not qualify the exact reviewed provider");
  }
  if (preflight.bare_metal_attested !== false
      || preflight.placement_class !== "same_exact_audited_provider_container_allocation_physical_host_unproven") {
    throw new Error("U1 provider preflight inflates the supported placement class");
  }
  if (!/^sha256:[0-9a-f]{64}$/u.test(String(preflight.provider_response_sha256 || ""))) {
    throw new Error("U1 provider preflight lacks its raw response hash");
  }
  const capturedAtMs = Date.parse(String(preflight.captured_at || ""));
  const providerCheckedAtMs = Date.parse(String(preflight.provider_last_checked_at || ""));
  const expectedSourceUrl = `https://console-api.akash.network/v1/providers/${expected}`;
  if (!Number.isFinite(nowMs)
      || !Number.isFinite(capturedAtMs)
      || !Number.isFinite(providerCheckedAtMs)
      || preflight.source_url !== expectedSourceUrl) {
    throw new Error("U1 provider preflight lacks valid freshness evidence");
  }
  const futureToleranceMs = 60_000;
  if (capturedAtMs > nowMs + futureToleranceMs
      || nowMs - capturedAtMs > U1_PROVIDER_PREFLIGHT_MAX_AGE_MS) {
    throw new Error("U1 provider preflight capture is stale or future-dated");
  }
  if (providerCheckedAtMs > capturedAtMs + futureToleranceMs
      || capturedAtMs - providerCheckedAtMs > U1_PROVIDER_OBSERVATION_MAX_AGE_MS) {
    throw new Error("U1 provider observation is stale or future-dated");
  }
  return preflight;
}

/** Recompute the qualification summary from the exact provider response bytes. */
export function validateProviderPreflightResponse(responseBytes, preflight, config) {
  if (sha256Bytes(responseBytes) !== preflight?.provider_response_sha256) {
    throw new Error("provider response bytes differ from the preflight commitment");
  }
  let record;
  try {
    record = JSON.parse(Buffer.from(responseBytes).toString("utf8"));
  } catch {
    throw new Error("provider response is not valid JSON");
  }
  const decision = qualifyU1Provider(record, config?.plan?.provider_selector?.provider_address);
  for (const key of [
    "provider_address",
    "provider_name",
    "provider_host_uri",
    "provider_last_checked_at",
    "qualified",
    "refusal_codes",
    "observed",
    "required",
    "placement_class",
    "bare_metal_attested",
  ]) {
    if (JSON.stringify(decision[key]) !== JSON.stringify(preflight?.[key])) {
      throw new Error(`provider preflight field ${key} was not derived from the committed response`);
    }
  }
  return record;
}

/** Materialize only owner-reviewed, non-secret SDL values before challenge hashing. */
export function materializeReviewedSdl(template, config) {
  const values = config.sdl_values || null;
  const hasReviewTokens = unresolvedOwnerReview.test(template);
  if (!values) {
    if (hasReviewTokens) throw new Error("SDL contains unresolved owner-review tokens");
    return template;
  }
  const plan = config.plan || {};
  const safeId = (value) => /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(String(value || ""));
  const digest = String(plan.image_digest || "");
  const commit = String(plan.benchmark_source_commit || "");
  const registryHost = String(values.registry_host || "");
  const imageReference = String(values.image_reference || "");
  const canary = String(values.secret_canary || "");
  if (!safeId(plan.campaign_id)) throw new Error("plan.campaign_id is invalid");
  if (!/^[0-9a-f]{40}$/u.test(commit)) throw new Error("plan.benchmark_source_commit must be a full lowercase Git commit");
  if (!/^sha256:[0-9a-f]{64}$/u.test(digest)) throw new Error("plan.image_digest must be immutable sha256");
  if (!/^[A-Za-z0-9.-]+(?::[0-9]+)?$/u.test(registryHost)) throw new Error("sdl_values.registry_host is invalid");
  if (!imageReference.startsWith(`${registryHost}/`) || !imageReference.endsWith(`@${digest}`) || /[\s'"\\]/u.test(imageReference)) {
    throw new Error("sdl_values.image_reference must be a safe registry path ending in the approved digest");
  }
  if (!/^u1-canary-[A-Za-z0-9_-]{8,80}$/u.test(canary)) throw new Error("sdl_values.secret_canary must be an explicit non-secret U1 canary");
  if (plan.benchmark_protocol_version !== "res-p4.3.v2"
      || plan.result_schema_version !== "ioi.aft.benchmark-campaign.v1"
      || plan.benchmark_warmups !== 1
      || plan.benchmark_repeats !== 5) {
    throw new Error("plan benchmark protocol does not match RES-P4.3 v1");
  }
  const replacements = {
    OWNER_APPROVED_IMAGE_REFERENCE: imageReference,
    OWNER_APPROVED_REGISTRY_HOST: registryHost,
    OWNER_APPROVED_CAMPAIGN_ID: plan.campaign_id,
    OWNER_APPROVED_SOURCE_COMMIT: commit,
    OWNER_APPROVED_IMAGE_DIGEST: digest,
    OWNER_APPROVED_PROTOCOL_VERSION: plan.benchmark_protocol_version,
    OWNER_APPROVED_WARMUPS: String(plan.benchmark_warmups),
    OWNER_APPROVED_REPEATS: String(plan.benchmark_repeats),
    OWNER_SEEDED_NON_SECRET_TEST_CANARY: canary,
    OWNER_APPROVED_UACT_CEILING: String(plan.ceiling_amount || ""),
  };
  let materialized = template;
  for (const [token, value] of Object.entries(replacements)) {
    if (!materialized.includes(token)) throw new Error(`SDL is missing ${token}`);
    materialized = materialized.replaceAll(token, value);
  }
  if (unresolvedOwnerReview.test(materialized)) {
    throw new Error("SDL retains unresolved owner-review tokens after materialization");
  }
  const resultExposure = /expose:\s*\n\s*-\s+port:\s*8080\s*\n(?:\s*#[^\n]*\n)*\s*as:\s*443\s*\n\s*to:\s*\n\s*-\s+global:\s*true(?:\s|$)/u;
  if (!resultExposure.test(materialized)) {
    throw new Error("U1 SDL must expose the workload-terminated TLS result service with external intent port 443");
  }
  if (/\bas:\s*80(?:\s|$)/u.test(materialized)) {
    throw new Error("U1 SDL cannot expose a plaintext external port 80 result route");
  }
  return materialized;
}
