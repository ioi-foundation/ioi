/** Materialize only owner-reviewed, non-secret SDL values before challenge hashing. */
export function materializeReviewedSdl(template, config) {
  const values = config.sdl_values || null;
  const hasReviewTokens = /OWNER_(?:APPROVED|SEEDED)|IMMUTABLE_IMAGE_DIGEST|PRIVATE_REGISTRY/u.test(template);
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
  if (/OWNER_(?:APPROVED|SEEDED)|IMMUTABLE_IMAGE_DIGEST|PRIVATE_REGISTRY/u.test(materialized)) {
    throw new Error("SDL retains unresolved owner-review tokens after materialization");
  }
  return materialized;
}
