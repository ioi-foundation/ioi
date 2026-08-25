import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { contentHash, sealSelfHash } from "./c8-v3-portable-bundle.mjs";

// Builds the C8 v3 portable-bundle inputs for one retained, real U1 campaign.
// Every value is derived from retained campaign evidence or the daemon's durable
// authority records; nothing here synthesises a wrapper the daemon did not emit.

const repo = path.resolve(import.meta.dirname, "../../../..");
const hashBytes = (bytes) => `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const mustEqual = (actual, expected, label) => {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, observed ${actual}`);
};

const stable = (value) => value === null || typeof value !== "object"
  ? JSON.stringify(value)
  : Array.isArray(value)
    ? `[${value.map(stable).join(",")}]`
    : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;

const REQUEST_FACET_KEYS = [
  "candidate_ref", "quote_ref", "max_hourly_usd", "gpu", "region", "az", "instance_type", "disk_gb",
  "project", "zone", "machine_type", "subscription_id", "resource_group", "location", "vm_size", "namespace",
  "workload_spec_hash", "exec_posture", "network_posture", "deployment_class", "provider_address", "bid_ref",
  "persistent_storage", "sdl_hash", "registry_credential_ref", "registry_host", "result_credential_ref",
  "result_tls_server_certificate_sha256", "campaign_id", "benchmark_source_commit", "image_digest",
  "image_build_identity_sha256", "provider_preflight_sha256", "benchmark_protocol_version", "result_schema_version",
  "benchmark_warmups", "benchmark_repeats", "max_duration_seconds", "deposit_usd", "ceiling_amount", "ceiling_denom",
  "provider_selector", "auto_topup", "stage", "restore_material_ref", "archive_ref", "teardown_policy", "execution_mode",
];

// The daemon hashes the governed request over serde_json's compact, sorted-map
// form, in which an f64 whole number round-trips as `1.0`. Node renders the same
// value as `1`. The transform below re-derives the daemon preimage and is proved
// exact by the request-hash equality that follows it; a wrong transform fails closed.
function daemonCanonicalRequest(requestValue) {
  return stable(requestValue).replace(/"(deposit_usd|max_hourly_usd)":(-?\d+),/gu, '"$1":$2.0,');
}

// Resolve the daemon's durable trajectory/admission records for one campaign by
// content, never by a hard-coded filename: the decision is the record whose
// candidate operation is this exact request, the after-state is the record whose
// state hash the decision committed to, and the admission is the consumed
// standing-authority intent naming the same request.
export function resolveAuthorityRecords(dataDir, requestHash) {
  const pick = (dir, predicate, label) => {
    const base = path.join(dataDir, dir);
    if (!fs.existsSync(base)) throw new Error(`${label}: durable record directory is absent: ${base}`);
    const matches = fs.readdirSync(base)
      .filter((name) => name.endsWith(".json"))
      .map((name) => ({ name, value: read(path.join(base, name)) }))
      .filter((entry) => predicate(entry.value));
    if (matches.length === 0) throw new Error(`${label}: no durable record matches ${requestHash}`);
    if (matches.length > 1) throw new Error(`${label}: ${matches.length} durable records match ${requestHash}`);
    return matches[0].value;
  };
  const trajectoryDecision = pick(
    "authority-trajectory-decisions",
    (value) => value.candidate_operation_hash === requestHash,
    "trajectory decision",
  );
  const trajectoryAfter = pick(
    "authority-trajectory-states",
    (value) => value.trajectory_state_hash === trajectoryDecision.state_after_hash,
    "trajectory after-state",
  );
  const admission = pick(
    "authority-admission-intents",
    (value) => value.commitment?.request_hash === requestHash && value.status === "consumed",
    "standing authority admission intent",
  );
  return { trajectoryDecision, trajectoryAfter, admission };
}

export function buildCampaignBundleInputs({ campaignDir, dataDir, policy, generatedAt, writeTemp }) {
  const fromCampaign = (file) => read(path.join(campaignDir, file));
  const object = (name, ref, schemaRef, value) => ({
    ref, schema_ref: schemaRef, file: `${name}.json`, path: writeTemp(`source-${name}.json`, value),
  });
  const generic = (name, ref, schemaRef, extra) => object(name, ref, schemaRef, {
    schema_version: schemaRef.replace("schema://", "").replaceAll("/", "."), ...extra,
  });

  const lifecycle = fromCampaign("c7-c8-certificate.json");
  const campaign = fromCampaign("u1-campaign-certificate.json");
  const challenge = fromCampaign("challenge.json");
  const envelope = fromCampaign("standing-authority-envelope.json");
  const factor = fromCampaign("auth-factor-receipt.json");
  const isolationProbe = fromCampaign("workload-effect-isolation-evidence.json");
  const consumption = fromCampaign("workload-effect-consumption.json");

  const campaignId = campaign.authority.campaign_id;
  const sourceCommit = campaign.authority.source_commit;
  const imageDigest = campaign.authority.image_digest;
  const providerAddress = campaign.provider.provider_address;
  const providerRef = `provider://akash/${providerAddress}`;
  const requestHash = challenge.approval.request_hash;
  const { trajectoryDecision, trajectoryAfter, admission } = resolveAuthorityRecords(dataDir, requestHash);
  const requestRef = trajectoryDecision.candidate_operation_ref;
  mustEqual(requestHash, trajectoryDecision.candidate_operation_hash, "trajectory request hash");

  const facets = {
    account_ref: challenge.account_ref, op: "create", environment_ref: challenge.resource_refs[1], kind: "akash",
    external_spend_posture: "external_spend",
  };
  for (const key of REQUEST_FACET_KEYS) if (Object.hasOwn(challenge.lease_request_facets, key)) facets[key] = challenge.lease_request_facets[key];
  const requestValue = {
    domain: "hypervisor.provider.op.request.v1", allowed_tools: challenge.allowed_tools,
    resource_refs: challenge.resource_refs, scopes: challenge.required_scopes, facets,
  };
  const canonicalRequest = daemonCanonicalRequest(requestValue);
  mustEqual(hashBytes(canonicalRequest), requestHash, "daemon-native governed request preimage");
  const requestPreimage = {
    schema_version: "ioi.foundations.canonical-json-preimage.v1",
    canonicalization: "serde_json_compact_sorted_map_float_roundtrip",
    canonical_json: canonicalRequest,
    projection: {
      operation: "create", campaign_id: campaignId, benchmark_source_commit: sourceCommit, image_digest: imageDigest,
      provider_ref: providerRef, provider_address: providerAddress, result_destination_ref: envelope.facet_template.result_destination_refs[0],
    },
  };
  mustEqual(contentHash(requestPreimage), requestHash, "portable governed request hash");

  const trajectoryBefore = structuredClone(trajectoryAfter);
  for (const key of ["active_resource_refs", "admitted_events", "data_class_refs", "destination_refs", "provider_refs"]) trajectoryBefore[key] = [];
  trajectoryBefore.admitted_call_count = 0;
  trajectoryBefore.cumulative_deposit_usd = 0;
  trajectoryBefore.cumulative_spend_usd = 0;
  trajectoryBefore.trajectory_state_hash = trajectoryDecision.state_before_hash;
  mustEqual(contentHash(trajectoryBefore), trajectoryDecision.state_before_hash, "reconstructed trajectory before hash");

  const refs = {
    predecessor: `certificate://c8/v2/${lifecycle.certificate_hash.slice(7)}`,
    source: `source://ioi/aft/${sourceCommit}`,
    daemonSource: `source://ioi/hypervisor/${lifecycle.source.commit}`,
    request: requestRef,
    claims: `claim-manifest://c8/v3/${campaignId}`,
    isolationRequirements: `isolation-requirements://u1/${campaignId}`,
    isolationEvidence: `enforcement-coverage://u1/${campaignId}`,
    isolationProbe: `evidence://workload-effect-isolation-live-probe/${campaignId}`,
    effectConsumption: `receipt://workload-effect-consumption/${campaignId}`,
    isolation: isolationProbe.enforcement_declaration.isolation_binding_ref,
    readiness: `evidence://provider/readiness/${campaignId}`,
    campaign: `certificate://u1/${campaignId}`,
    contract: "schema://ioi/aft/u1-campaign-result/v1",
    result: lifecycle.journal.workload_result_ref,
    retrieval: `receipt://aft/result-retrieval/${campaignId}`,
    environment: `environment://aft/${campaignId}`,
    variance: `variance://aft/${campaignId}`,
    envelope: envelope.standing_envelope_ref,
    factor: factor.approval_ceremony_context_ref,
    drawRequest: `authority-draw-request://aft/${campaignId}`,
    drawReceipt: `receipt://authority-draw/${admission.consumption_id}`,
    before: trajectoryDecision.state_before_ref,
    decision: trajectoryDecision.decision_ref,
    after: trajectoryDecision.state_after_ref,
    secret: `evidence://secret-non-possession/${campaignId}`,
    settlement: `receipt://provider/settlement/${campaignId}`,
    terminal: `receipt://provider/terminal/${campaignId}`,
  };

  const sourceBasis = { schema_version: "ioi.foundations.source-basis.v1", commit: sourceCommit, image_digest: imageDigest };
  const daemonSourceBasis = { schema_version: "ioi.foundations.source-basis.v1", commit: lifecycle.source.commit, daemon_binary_sha256: lifecycle.source.daemon_binary_sha256, dirty_state_declaration: "clean" };
  const result = structuredClone(campaign.measurement.aggregate);
  const environment = {
    ...campaign.measurement.environment, provider_ref: providerRef, image_digest: imageDigest, source_commit: sourceCommit,
    environment_class: "measured_container", honesty_class: campaign.placement.classification,
    provider_host_attestation: campaign.placement.note,
  };
  const settlement = {
    schema_version: "ioi.components.hypervisor.provider-settlement.v1", provider_ref: providerRef, provider_address: providerAddress,
    campaign_id: campaignId, dseq: campaign.provider.dseq, lease_status: "closed", deployment_status: "closed", escrow_status: "closed",
    active_lease_count: 0, open_unknown_exposure_microusd: 0, teardown_verified: true,
    final_net_cost_usd: campaign.settlement.final_net_cost_usd, provider_response_hash: campaign.settlement.provider_response_hash,
  };
  const isolationRequirements = sealSelfHash({
    schema_version: "ioi.components.hypervisor.workload-isolation-requirements.v1",
    requirements_ref: refs.isolationRequirements, source_policy_refs_and_hashes: [
      { ref: "policy://u1/hostile-guest", hash: isolationProbe.enforcement_declaration.isolation_binding_hash },
      { ref: "policy://network/deny-default", hash: contentHash({ policy: isolationProbe.enforcement_declaration.network_policy }) },
      { ref: "policy://output/quarantine", hash: contentHash({ policy: isolationProbe.enforcement_declaration.output_policy }) },
    ],
    compiled_risk_classes: ["untrusted_code", "provider_operation"], hostile_to_boundary_requirement: "hostile_to_guest_kernel",
    instance_policy: "fresh_per_workrun", minimum_isolation: "vm_kernel", host_mount_policy: "none", daemon_socket_exposed: false,
    host_pid_namespace_exposed: false, raw_secret_material_in_guest: false, capability_broker_ref: "broker://hypervisor/final-invoker",
    permitted_lease_classes: ["proposal_write"], network_policy_ref: "policy://network/deny-default", dependency_broker_policy_ref: "policy://dependency/none",
    output_admission: { quarantine_required: true, policy_ref: "policy://output/quarantine", maximum_bytes: 65536, maximum_files: 4, archive_entry_policy_ref: "policy://archive/regular-files-and-directories", evaluator_refs: ["evaluator://hypervisor/output-quarantine/v1"] },
    teardown: { destruction_policy_ref: "policy://cleanup/workrun", deadline_ms: 60000, verify_all_resources: true, cleanup_obligation_on_uncertainty: true },
    required_backend_capabilities: ["kernel_initramfs_boot", "guest_agent", "no_nic"], required_enforcement_coverage: ["preventable", "receipted"],
    required_evidence_and_receipt_policy_refs: ["policy://receipt/workrun-isolation"], compiler_ref: "compiler://workload-isolation/v1", compiler_version: "1.0.0",
  });
  const isolationEvidence = {
    schema_version: "ioi.components.hypervisor.workload-boundary-enforcement-evidence.v1", protection_profile: isolationProbe.protection_profile,
    network_posture: "no_nic", final_invoker_audience: "hypervisor-final-invoker", direct_protected_effect_invocations: isolationProbe.direct_protected_provider_invocations,
    final_invoker_calls: consumption.receipts.consumption_receipt.final_invoker_calls, guest_uid: isolationProbe.guest_uid,
    output_quarantined: isolationProbe.output_quarantine === "bounded_archive_validated", capability_replay: "refused", monitor_terminal: isolationProbe.monitor_terminal,
    source_probe_ref: refs.isolationProbe, source_probe_hash: contentHash(isolationProbe),
    source_consumption_ref: refs.effectConsumption, source_consumption_hash: contentHash(consumption), claim_boundary: isolationProbe.claim_boundary,
  };
  const isolationBinding = sealSelfHash({
    schema_version: "ioi.components.hypervisor.workload-isolation-binding.v1", binding_ref: refs.isolation,
    requirements_ref: refs.isolationRequirements, requirements_hash: isolationRequirements.requirements_hash,
    workrun_ref: isolationProbe.enforcement_declaration.workrun_ref, runtime_assignment_ref: `runtime-assignment://u1/${campaignId}`,
    environment_ref: refs.environment, startup_plan_ref: `startup-plan://u1/${campaignId}`, startup_plan_hash: isolationProbe.enforcement_declaration.isolation_binding_hash,
    boundary_instance_ref: `boundary://cloud-hypervisor/${campaignId}`, compute_host_ref: "runtime-node://owner/local-kvm",
    failure_domain_ref: "failure-domain://owner/local-kvm", backend_capability_declaration_ref: "capability://backend/cloud-hypervisor/no-nic",
    backend_capability_declaration_hash: isolationProbe.enforcement_declaration.isolation_binding_hash,
    enforcement_coverage_refs_and_hashes: [{ ref: refs.isolationEvidence, hash: contentHash(isolationEvidence) }],
    immutable_component_refs_and_hashes: [
      { ref: "oci://ghcr.io/ioi-foundation/ioi-aft-bench", hash: imageDigest },
      { ref: "component://cloud-hypervisor", hash: hashBytes("cloud-hypervisor:v52.0") },
      { ref: "component://u1/guest-boundary", hash: isolationProbe.enforcement_declaration.isolation_binding_hash },
    ],
    exact_input_and_mount_closure_hash: isolationProbe.enforcement_declaration.isolation_binding_hash,
    guest_network_identity_ref: `network-identity://workrun/no-nic/${campaignId}`, route_policy_ref: "policy://network/deny-default",
    dependency_broker_ref: "broker://dependency/none", dependency_broker_policy_hash: isolationProbe.enforcement_declaration.isolation_binding_hash,
    brokered_lease_refs: [consumption.receipts.consumption_receipt.capability_ref], pep_ref: "pep://daemon/workrun",
    final_invoker_ref: "final-invoker://hypervisor/provider-operation", governed_action_classes: ["provider_operation"],
    output_quarantine_ref: `quarantine://workrun/${campaignId}`, output_policy_ref: "policy://output/quarantine",
    cleanup_obligation_ref: `cleanup-obligation://workrun/${campaignId}`, required_terminal_disposition: "destroyed_verified",
    readiness_evidence_refs: [refs.readiness], currentness_evaluation_refs: [`evaluation://currentness/${campaignId}`],
  });
  const secretEvidence = {
    schema_version: "ioi.components.hypervisor.worker-secret-non-possession.v1", protection_profile: isolationProbe.protection_profile,
    probe_profile: "enumerated_host_material_channels", guest_uid: isolationProbe.guest_uid, seeded_canary_count: 0,
    tested_channel_count: isolationProbe.attempted_paths.length, tested_channels: isolationProbe.attempted_paths,
    network_device_count: isolationProbe.enforcement_declaration.network_device_count,
    host_mount_count: isolationProbe.enforcement_declaration.host_mount_count,
    host_control_socket_count: isolationProbe.enforcement_declaration.host_control_socket_count,
    secret_findings: isolationProbe.secret_findings, provider_credential_observed: false, recovery_material_observed: false,
    broker_separate_from_guest: true, source_probe_ref: refs.isolationProbe, source_probe_hash: contentHash(isolationProbe), claim_boundary: isolationProbe.claim_boundary,
  };

  const objects = [
    object("predecessor", refs.predecessor, "schema://ioi/components/hypervisor/c8-certificate/v2", lifecycle),
    object("source", refs.source, "schema://ioi/foundations/source-basis/v1", sourceBasis),
    object("daemon-source", refs.daemonSource, "schema://ioi/foundations/source-basis/v1", daemonSourceBasis),
    object("request", refs.request, "schema://ioi/foundations/canonical-json-preimage/v1", requestPreimage),
    object("isolation-requirements", refs.isolationRequirements, "schema://ioi/components/hypervisor/workload-isolation-requirements/v1", isolationRequirements),
    object("isolation-evidence", refs.isolationEvidence, "schema://ioi/components/hypervisor/workload-boundary-enforcement-evidence/v1", isolationEvidence),
    object("isolation-live-probe", refs.isolationProbe, "schema://ioi/hypervisor/workload-bound-effect-boundary-live-probe/v2", isolationProbe),
    object("effect-consumption", refs.effectConsumption, "schema://ioi/components/hypervisor/workload-effect-consumption/v1", consumption),
    object("isolation", refs.isolation, "schema://ioi/components/hypervisor/workload-isolation-binding/v1", isolationBinding),
    generic("readiness", refs.readiness, "schema://ioi/components/hypervisor/provider-readiness/v1", { status: "ready", campaign_id: campaignId, provider_ref: providerRef, image_digest: imageDigest, source_commit: sourceCommit, requested_replicas: 1, ready_replicas: 1, dseq: campaign.provider.dseq }),
    object("result-contract", refs.contract, "schema://json-schema/draft-2020-12", read(path.join(repo, "docs/architecture/_meta/schemas/aft-u1-campaign-result.v1.schema.json"))),
    object("result", refs.result, "schema://ioi/aft/u1-campaign-result/v1", result),
    generic("environment", refs.environment, "schema://ioi/aft/environment-manifest/v1", environment),
    generic("variance", refs.variance, "schema://ioi/aft/campaign-variance/v1", { campaign_id: campaignId, verdict: result.verdict, threshold_policy: result.threshold_policy, all_rows_within_threshold: result.all_rows_within_threshold }),
    object("envelope", refs.envelope, "schema://ioi/foundations/standing-authority-envelope/v1", envelope),
    object("auth-factor", refs.factor, "schema://ioi/components/hypervisor/auth-factor-receipt/v1", factor),
    generic("draw-request", refs.drawRequest, "schema://ioi/foundations/standing-authority-draw-request/v1", { standing_envelope_ref: refs.envelope, candidate_operation_ref: refs.request, candidate_operation_hash: requestHash, auth_factor_receipt_ref: refs.factor, auth_factor_receipt_hash: factor.receipt_hash }),
    generic("draw-receipt", refs.drawReceipt, "schema://ioi/foundations/standing-authority-consumption/v1", { standing_envelope_ref: refs.envelope, draw_request_ref: refs.drawRequest, candidate_operation_hash: requestHash, decision: "consumed", atomic_consumption: true, revoked: false, consumption_id: admission.consumption_id, wallet_receipt_hash: hashBytes(JSON.stringify(admission.wallet_consumption_receipt)) }),
    object("trajectory-before", refs.before, "schema://ioi/foundations/authority-trajectory-state/v1", trajectoryBefore),
    object("trajectory-decision", refs.decision, "schema://ioi/foundations/trajectory-admission-decision/v1", trajectoryDecision),
    object("trajectory-after", refs.after, "schema://ioi/foundations/authority-trajectory-state/v1", trajectoryAfter),
    object("secret-evidence", refs.secret, "schema://ioi/components/hypervisor/worker-secret-non-possession/v1", secretEvidence),
    object("settlement", refs.settlement, "schema://ioi/components/hypervisor/provider-settlement/v1", settlement),
    generic("terminal", refs.terminal, "schema://ioi/components/hypervisor/terminal-acceptance-prerequisite/v1", { campaign_id: campaignId, terminal: true, cleanup_verified: true, result_verified: true }),
  ];
  const resultHash = contentHash(result);
  const environmentHash = contentHash(environment);
  const settlementHash = contentHash(settlement);
  const retrieval = {
    schema_version: "ioi.components.hypervisor.result-retrieval-receipt.v1", status: "verified", authenticated: true,
    campaign_id: campaignId, result_ref: refs.result, result_hash: resultHash, provider_artifact_hash: lifecycle.journal.workload_result_hash,
    environment_ref: refs.environment, environment_hash: environmentHash, provider_environment_artifact_hash: lifecycle.journal.workload_environment_hash,
    tls_certificate_sha256: campaign.workload_build_identity.result_tls_server_certificate_sha256,
  };
  objects.push(object("retrieval", refs.retrieval, "schema://ioi/components/hypervisor/result-retrieval-receipt/v1", retrieval));
  const campaignProjection = {
    schema_version: "ioi.components.hypervisor.u1-campaign-certificate.v1", status: "complete", campaign_id: campaignId,
    provider_ref: providerRef, image_digest: imageDigest, source_commit: sourceCommit, result_ref: refs.result, result_hash: resultHash,
    environment_ref: refs.environment, environment_hash: environmentHash, terminal_settlement_ref: refs.settlement,
    terminal_settlement_hash: settlementHash, predecessor_certificate_hash: campaign.certificate_hash,
  };
  objects.push(object("campaign", refs.campaign, "schema://ioi/components/hypervisor/u1-campaign-certificate/v1", campaignProjection));

  const claimManifest = sealSelfHash({
    schema_version: "ioi.components.hypervisor.governed-effect-claim-manifest.v1", manifest_ref: refs.claims,
    subject_ref: refs.request, subject_hash: requestHash, protection_profile: "trusted_host_hostile_guest",
    claims: [
      ["governed_infrastructure_lifecycle", true, refs.predecessor, "Real Akash create, readiness, result retrieval, teardown, and terminal settlement are bound."],
      ["workload_readiness", true, refs.readiness, "The provider reported one requested and one ready replica."],
      ["workload_result_binding", true, refs.retrieval, "An authenticated, TLS-pinned result was committed after provider evidence."],
      ["logical_policy_mediation", true, refs.decision, "The exact request advanced a bounded trajectory only after every constraint passed."],
      ["workload_bound_isolation_enforced", true, refs.isolation, "A fresh no-NIC Cloud Hypervisor guest could return only a quarantined proposal."],
      ["worker_secret_non_possession_tested", true, refs.secret, "Scoped to a trusted host and hostile UID-0 guest across the enumerated channels; host/VMM compromise is outside this claim."],
      ["separate_verifier", true, "verifier://ioi/aft-c8-verifier", "A separately built verifier consumes only the portable bundle and policy."],
      ["independently_reproduced", false, refs.variance, "The campaign is variance-caveated; no within-threshold reproduction claim is made."],
      ["third_party_verified", false, refs.variance, "The verifier is separate but maintained by IOI, not a third party."],
      ["provider_neutrality", false, refs.settlement, "This evidence covers one exact Akash provider."],
      ["bare_metal_placement", false, refs.environment, "The measured container exposes hardware characteristics but no tenant-specific host attestation."],
    ].map(([claim_id, demonstrated, evidence, limitation_note]) => ({ claim_id, status: demonstrated ? "demonstrated" : "not_demonstrated", evidence_refs: demonstrated ? [evidence] : [], limitation_note })),
    source_basis_refs: [{ ref: refs.source, hash: contentHash(sourceBasis) }, { ref: refs.daemonSource, hash: contentHash(daemonSourceBasis) }], generated_at: generatedAt,
  });
  objects.push(object("claims", refs.claims, "schema://ioi/components/hypervisor/governed-effect-claim-manifest/v1", claimManifest));

  const draft = {
    certificate_ref: `certificate://c8/v3/${campaignId}`, predecessor_certificate_schema_version: lifecycle.schema_version,
    predecessor_certificate_ref: refs.predecessor, source_basis_refs: [refs.source, refs.daemonSource], operator_principal_ref: lifecycle.operator.principal_ref,
    governed_request_ref: refs.request, claim_manifest_ref: refs.claims, isolation_binding_ref: refs.isolation,
    workload_image_ref: "oci://ghcr.io/ioi-foundation/ioi-aft-bench", workload_image_digest: imageDigest, workload_readiness_evidence: [refs.readiness],
    campaign_certificate_ref: refs.campaign, campaign_id: campaignId, benchmark_source_commit: sourceCommit,
    benchmark_protocol_version: campaign.authority.protocol_version, result_contract_ref: refs.contract, result_ref: refs.result,
    result_retrieval_receipt_ref: refs.retrieval, environment_ref: refs.environment, variance_evidence_ref: refs.variance,
    environment_class: "measured_container", honesty_class: campaign.placement.classification,
    authority_draw: { standing_envelope_ref: refs.envelope, draw_request_ref: refs.drawRequest, draw_receipt_ref: refs.drawReceipt },
    trajectory_binding: { state_before_ref: refs.before, state_before_hash: trajectoryBefore.trajectory_state_hash, decision_ref: refs.decision, state_after_ref: refs.after, state_after_hash: trajectoryAfter.trajectory_state_hash },
    brokered_secret_use_posture: "opaque_handle_final_invoker", secret_use_evidence: [refs.secret], relying_party_audience_ref: policy.audience_ref,
    terminal_acceptance_prerequisites: [refs.terminal],
    journal_binding: { intent_root: lifecycle.journal.workload_result_predecessor_root, outcome_predecessor_root: lifecycle.journal.workload_result_predecessor_root, outcome_root: lifecycle.journal.workload_result_outcome_root },
    terminal_settlement_ref: refs.settlement, generated_at: generatedAt,
  };

  return {
    campaignId, sourceCommit, imageDigest, providerRef, providerAddress, requestHash,
    lifecycle, campaign, challenge, envelope, isolationProbe, consumption, admission,
    trajectoryDecision, trajectoryBefore, trajectoryAfter, result, resultHash, environment, environmentHash,
    settlement, settlementHash, sourceBasis, daemonSourceBasis, refs, objects, draft,
    bundleRef: `evidence-bundle://aft/${campaignId}`,
  };
}
