import crypto from "node:crypto";

export function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}

export function certificateHash(certificate) {
  const copy = structuredClone(certificate);
  delete copy.certificate_hash;
  return `sha256:${crypto.createHash("sha256").update(stableStringify(copy)).digest("hex")}`;
}

export function sealCertificate(evidence) {
  const certificate = structuredClone(evidence);
  certificate.schema_version = "ioi.hypervisor.c7-c8-certificate.v2";
  certificate.certificate_hash = certificateHash(certificate);
  return certificate;
}

const hash = (value) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value);
const ref = (value) => typeof value === "string" && value.length > 8 && !/\s/u.test(value);
const same = (left, right) => stableStringify(left) === stableStringify(right);
const sha256Text = (value) => `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;

export function validateCertificate(certificate) {
  const failures = [];
  const fail = (code, path, detail) => failures.push({ code, path, detail });
  if (certificate?.schema_version !== "ioi.hypervisor.c7-c8-certificate.v2") fail("certificate_schema_invalid", "schema_version", "unknown certificate schema");
  if (certificate?.result !== "success" || certificate?.ok !== true) fail("run_not_successful", "result", "C8 can certify only an explicit successful run");
  if (!hash(certificate?.certificate_hash) || certificateHash(certificate) !== certificate.certificate_hash) fail("certificate_hash_mismatch", "certificate_hash", "certificate bytes do not match their hash");

  if (!ref(certificate?.source?.commit) || !hash(certificate?.source?.daemon_binary_sha256)) fail("source_basis_missing", "source", "commit and daemon binary hash are required");
  if (typeof certificate?.source?.dirty_state_declaration !== "string") fail("dirty_state_undeclared", "source.dirty_state_declaration", "dirty state must be declared");
  if (typeof certificate?.source?.publication_eligible !== "boolean") fail("publication_posture_missing", "source.publication_eligible", "the source basis must explicitly classify public eligibility");
  if (certificate?.source?.publication_eligible === true && certificate?.source?.dirty_state_declaration !== "clean") fail("dirty_source_marked_publication_eligible", "source", "only a clean source basis may be public evidence");
  if (!ref(certificate?.operator?.principal_ref)) fail("operator_principal_missing", "operator.principal_ref", "canonical authenticated principal ref required");

  const facets = certificate?.authority?.reviewed_facets;
  for (const key of ["deposit_usd", "ceiling_amount", "ceiling_denom", "provider_selector", "sdl_hash", "teardown_policy", "provider_account_ref", "retry_count"]) {
    if (facets?.[key] === undefined || facets?.[key] === null || facets?.[key] === "") fail("reviewed_facet_missing", `authority.reviewed_facets.${key}`, "exact LIVE-GO facet missing");
  }
  if (facets?.deposit_usd !== 1 || facets?.ceiling_amount !== "1000" || facets?.ceiling_denom !== "uact" || facets?.retry_count !== 1) fail("bounded_spend_facets_changed", "authority.reviewed_facets", "C7/C8 certifies exactly one attempt with a $1 deposit and 1000 uact bid ceiling");
  const selector = facets?.provider_selector;
  const marketplaceSelector = selector?.mode === "any_marketplace"
    && selector?.selection === "lowest_qualified_bid"
    && selector?.provider_address === undefined;
  const exactSelector = selector?.mode === "exact"
    && selector?.selection === "only_qualified_bid_from_exact_provider"
    && typeof selector?.provider_address === "string"
    && selector.provider_address.startsWith("akash1");
  if ((!marketplaceSelector && !exactSelector) || facets?.auto_topup !== false) fail("provider_selector_changed", "authority.reviewed_facets.provider_selector", "the reviewed selector must be either lowest-qualified marketplace or one exact qualified provider, with auto-topup disabled");
  if (facets?.execution_mode !== "live" || facets?.teardown_policy !== "always_teardown_required") fail("live_teardown_facets_changed", "authority.reviewed_facets", "live execution and mandatory teardown are required");
  if (!hash(facets?.sdl_hash)) fail("sdl_binding_mismatch", "authority.reviewed_facets.sdl_hash", "the reviewed request must carry a canonical SDL hash");
  if (facets?.sdl_yaml !== undefined) fail("raw_sdl_retained", "authority.reviewed_facets.sdl_yaml", "raw SDL is not portable certificate material; retain only its reviewed hash and a separately redacted workload view");
  const workload = certificate?.workload;
  if (typeof workload?.redacted_sdl !== "string" || !hash(workload?.redacted_sdl_hash) || sha256Text(workload.redacted_sdl) !== workload.redacted_sdl_hash) fail("redacted_sdl_invalid", "workload", "the public workload view must be redacted and self-hashing");
  if (!ref(workload?.image_ref) || !["immutable_digest", "mutable_tag"].includes(workload?.image_identity_posture)) fail("workload_identity_missing", "workload", "the workload image reference and identity posture are required");
  if (workload?.image_identity_posture === "immutable_digest" && !/@sha256:[0-9a-f]{64}$/u.test(workload.image_ref)) fail("workload_digest_invalid", "workload.image_ref", "immutable workload identity must use an OCI sha256 digest");
  if (certificate?.source?.publication_eligible === true && workload?.image_identity_posture !== "immutable_digest") fail("mutable_workload_marked_publication_eligible", "workload", "public evidence requires an immutable workload digest");
  if (!hash(certificate?.authority?.policy_hash) || !hash(certificate?.authority?.request_hash)) fail("authority_hash_missing", "authority", "policy and request hashes required");
  if (!ref(certificate?.authority?.grant_ref)) fail("grant_ref_missing", "authority.grant_ref", "wallet grant ref required");
  const authorityLease = certificate?.authority?.lease;
  if (!ref(authorityLease?.lease_ref) || authorityLease?.usage_count !== 1) fail("one_shot_authority_invalid", "authority.lease", "one lease use is required");
  if (authorityLease?.remaining_calls !== 0 || !["exhausted", "closed", "revoked"].includes(authorityLease?.state)) fail("exhausted_authority_still_active", "authority.lease", "one-shot lease must be terminal with zero calls");
  if ((!Number.isSafeInteger(authorityLease?.expires_at) && typeof authorityLease?.expires_at !== "string") || !ref(authorityLease?.revocation_ref)) fail("authority_lifecycle_evidence_missing", "authority.lease", "capability expiry and revocation evidence are required");
  const binding = certificate?.authority?.binding;
  if (binding?.authority_provider_ref !== "wallet.network" || binding?.backing_provider !== `provider:account:${String(facets?.provider_account_ref || "").split("//").at(-1)}`) fail("authority_binding_invalid", "authority.binding", "wallet authority must bind the certified provider account");
  if (!same(binding?.allowed_tools, ["provider.create"]) || !same(binding?.resource_refs, [facets?.provider_account_ref, certificate?.durable?.environment_ref]) || !same(binding?.scopes, ["provider.provision"])) fail("authority_binding_invalid", "authority.binding", "capability tools, resources, and scopes differ from the certified create");

  const proposal = certificate?.proposal;
  if (proposal?.source !== "daemon-issued-durable-proposal") fail("proposal_provenance_invalid", "proposal.source", "inline/caller-asserted proposal provenance is forbidden");
  for (const key of ["proposal_ref", "admission_receipt_ref", "consumption_receipt_ref"]) if (!ref(proposal?.[key])) fail("proposal_evidence_missing", `proposal.${key}`, "proposal admission and consumption evidence required");
  if (!hash(proposal?.admission_root) || !hash(proposal?.consumption_root) || proposal?.admission_root === proposal?.consumption_root) fail("proposal_roots_invalid", "proposal", "distinct durable admission and consumption roots required");
  if (proposal?.consumed_once !== true) fail("proposal_not_one_time", "proposal.consumed_once", "proposal must be consumed exactly once");
  if (!hash(proposal?.request_hash)) fail("proposal_request_hash_missing", "proposal.request_hash", "the exact proposed provider request hash is required");

  const journal = certificate?.journal;
  if (!hash(journal?.intent_root) || !hash(journal?.outcome_root) || journal?.outcome_predecessor_root !== journal?.intent_root || journal?.outcome_root === journal?.intent_root) fail("journal_root_mismatch", "journal", "outcome must be a distinct successor of the exact intent root");

  const provider = certificate?.provider;
  for (const key of ["dseq", "bid_ref", "provider_address", "lease_ref"]) if (!ref(provider?.[key])) fail("provider_native_evidence_missing", `provider.${key}`, "provider-native bid/lease evidence required");
  if (exactSelector && selector.provider_address !== provider?.provider_address) fail("exact_provider_mismatch", "provider.provider_address", "the selected provider must equal the exact authority-bound provider");
  if (provider?.lease_state !== "closed") fail("provider_lease_open", "provider.lease_state", "provider lease must be closed");
  if (!ref(provider?.endpoint_ref) || provider?.endpoint_discovered !== true) fail("provider_endpoint_missing", "provider", "a fetched live provider endpoint is required");
  for (const key of ["desired_replicas", "ready_replicas"]) if (!Number.isSafeInteger(provider?.[key]) || provider[key] < 0) fail("provider_replica_evidence_invalid", `provider.${key}`, "provider replica counts must be nonnegative integers");
  if (typeof provider?.service_uri_present !== "boolean" || typeof provider?.workload_readiness_proven !== "boolean" || typeof provider?.workload_result_retrieved !== "boolean") fail("provider_readiness_evidence_missing", "provider", "endpoint, readiness, and workload-result claims must be explicit");
  if (provider?.workload_readiness_proven !== (provider?.ready_replicas > 0)) fail("provider_readiness_inflated", "provider.workload_readiness_proven", "workload readiness must equal the provider-reported positive ready-replica fact");
  if (provider?.c6?.retrieved_live !== true || !hash(provider?.c6?.provider_response_hash)) fail("c6_live_proof_missing", "provider.c6", "C6 must be fetched live and hash the provider response");

  const teardown = certificate?.teardown;
  if (teardown?.state !== "torn_down" || teardown?.provider_terminal !== true || ![200, 202, 204].includes(teardown?.close_http)) fail("teardown_unconfirmed", "teardown", "provider close and terminal readback required");
  const settlement = certificate?.settlement;
  if (!["refund_settled", "final_debit_settled"].includes(settlement?.state)) fail("settlement_not_terminal", "settlement.state", "refund_pending/reconciliation_required cannot certify");
  if (settlement?.provider_readback !== true || !hash(settlement?.provider_response_hash)) fail("settlement_readback_missing", "settlement", "provider-native settlement readback required");
  if (typeof settlement?.final_net_cost_usd !== "number" || !Number.isFinite(settlement.final_net_cost_usd) || settlement.final_net_cost_usd < 0) fail("final_cost_unreconciled", "settlement.final_net_cost_usd", "finite nonnegative final cost required");
  if (settlement?.open_exposure_count !== 0 || settlement?.unknown_exposure_count !== 0) fail("open_or_unknown_exposure", "settlement", "all exposure must be closed and known");
  if (!Array.isArray(certificate?.negative_receipts) || certificate.negative_receipts.length === 0) fail("negative_receipts_missing", "negative_receipts", "gate-chain refusal evidence required");

  const claims = certificate?.claims;
  if (claims?.certified_scope !== "governed_infrastructure_lifecycle") fail("certified_scope_invalid", "claims.certified_scope", "C7/C8 certifies the governed infrastructure lifecycle only");
  if (claims?.application_readiness_claimed !== provider?.workload_readiness_proven) fail("application_readiness_claim_mismatch", "claims.application_readiness_claimed", "the claim must follow provider replica evidence exactly");
  if (claims?.workload_result_claimed !== provider?.workload_result_retrieved) fail("workload_result_claim_mismatch", "claims.workload_result_claimed", "the claim must follow retrieved workload-result evidence exactly");
  if (claims?.workload_result_claimed === true) {
    if (!hash(journal?.workload_result_outcome_root)
      || journal?.workload_result_intent_root !== journal?.intent_root
      || journal?.workload_result_predecessor_root !== journal?.outcome_root
      || journal?.workload_result_outcome_root === journal?.outcome_root
      || !ref(journal?.workload_result_ref)
      || !hash(journal?.workload_status_hash)
      || !hash(journal?.workload_result_hash)
      || !hash(journal?.workload_environment_hash)
      || !hash(journal?.workload_manifest_hash)) {
      fail("workload_result_journal_binding_invalid", "journal", "a claimed workload result must be a distinct successor of the create outcome and bind result, environment, and manifest hashes");
    }
  }
  if (claims?.bare_metal_claimed !== false || claims?.provider_neutrality_claimed !== false || claims?.remote_worker_secret_non_possession_claimed !== false) fail("unsupported_architecture_claim", "claims", "C7/C8 does not certify bare metal, provider neutrality, or hard remote-worker secret non-possession");
  if (!Array.isArray(certificate?.nonclaims) || certificate.nonclaims.length < 3) fail("nonclaims_missing", "nonclaims", "the certificate must carry explicit bounded nonclaims");

  const durable = certificate?.durable;
  for (const key of ["environment_ref", "provider_operation_id", "c6_operation_id", "delete_operation_id", "deployment_record_id", "provider_lease_record_id", "endpoint_record_id", "capability_lease_id", "proposal_admission_operation_ref", "terminal_reconciliation_receipt_ref"]) {
    if (!ref(durable?.[key])) fail("durable_locator_missing", `durable.${key}`, "independent verification requires exact durable record locators");
  }
  if (!Number.isSafeInteger(durable?.substrate_muxlog_bytes) || durable.substrate_muxlog_bytes <= 0 || !hash(durable?.substrate_muxlog_prefix_sha256)) fail("substrate_anchor_missing", "durable", "certificate must anchor the durable substrate prefix");

  const serialized = JSON.stringify(certificate);
  const secretPatterns = [
    /"(?:password|session_token|api_key|sealed_token|recovery_material|mnemonic|private_key)"\s*:/iu,
    /ioi_sess_[A-Za-z0-9_-]+/u,
    /ioi_bootstrap_[A-Za-z0-9_-]+/u,
    /(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{12,}/u,
  ];
  if (secretPatterns.some((pattern) => pattern.test(serialized))) fail("secret_bearing_artifact", "$", "certificate contains credential or bearer material");
  return { ok: failures.length === 0, failures };
}
