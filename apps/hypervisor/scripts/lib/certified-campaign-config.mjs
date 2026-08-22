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
  if (plan.benchmark_protocol_version) {
    if (selector.mode !== "exact"
        || selector.selection !== "only_qualified_bid_from_exact_provider"
        || !/^akash1[02-9ac-hj-np-z]{38}$/u.test(String(selector.provider_address || ""))) {
      throw new Error("U1 requires one explicit exact Akash provider address");
    }
    if (!/^sha256:[0-9a-f]{64}$/u.test(String(plan.result_tls_server_certificate_sha256 || ""))) {
      throw new Error("U1 requires one explicit result TLS server certificate SHA-256 pin");
    }
    if (!Number.isSafeInteger(plan.max_duration_seconds)
        || plan.max_duration_seconds < 60
        || plan.max_duration_seconds > 24 * 60 * 60) {
      throw new Error("U1 requires an explicit max_duration_seconds between 60 and 86400");
    }
  }
  return config;
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
