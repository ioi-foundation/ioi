#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { assemblePortableBundle, contentHash, sealSelfHash } from "./lib/c8-v3-portable-bundle.mjs";

const repo = path.resolve(import.meta.dirname, "../../..");
const home = process.env.HOME;
if (!home) throw new Error("HOME is required");
const campaignDir = process.env.IOI_U1_CAMPAIGN_EVIDENCE
  || path.join(home, ".ioi/hypervisor/evidence/u1/campaign-o-aes-phl-14d24907/run");
const dataDir = process.env.IOI_HYPERVISOR_DATA_DIR || path.join(home, ".ioi/hypervisor/data");
const output = path.resolve(process.argv[2] || path.join(path.dirname(campaignDir), "c8-v3-registry-admission"));
const relyingPartyDir = process.env.IOI_C8_RELYING_PARTY_DIR;
if (!relyingPartyDir) throw new Error("IOI_C8_RELYING_PARTY_DIR is required; provision relying-party policy and registry separately");
const verifier = process.env.IOI_AFT_C8_VERIFIER || path.join(repo, "target/debug/aft-c8-verifier");
const acceptedAt = "2026-08-23T23:45:00Z";
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-u1-c8-v3-real-"));
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const fromCampaign = (file) => read(path.join(campaignDir, file));
const write = (name, value) => {
  const target = path.join(temp, name);
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  return target;
};
const hashBytes = (bytes) => `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
const object = (name, ref, schemaRef, value) => ({
  ref, schema_ref: schemaRef, file: `${name}.json`, path: write(`source-${name}.json`, value),
});
const generic = (name, ref, schemaRef, extra) => object(name, ref, schemaRef, {
  schema_version: schemaRef.replace("schema://", "").replaceAll("/", "."), ...extra,
});
const mustEqual = (actual, expected, label) => {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, observed ${actual}`);
};

try {
  if (fs.existsSync(output)) throw new Error(`refusing to overwrite existing admission: ${output}`);
  if (!fs.existsSync(verifier)) throw new Error(`verifier binary missing: ${verifier}`);

  const lifecycle = fromCampaign("c7-c8-certificate.json");
  const campaign = fromCampaign("u1-campaign-certificate.json");
  const challenge = fromCampaign("challenge.json");
  const envelope = fromCampaign("standing-authority-envelope.json");
  const factor = fromCampaign("auth-factor-receipt.json");
  const isolationProbe = fromCampaign("workload-effect-isolation-evidence.json");
  const consumption = fromCampaign("workload-effect-consumption.json");
  const trajectoryDecision = read(path.join(dataDir, "authority-trajectory-decisions/0c643ad093e9e5696e40ac8f3f06c13625bd2df5c62fc81b8b0d69251372ab79.json"));
  const trajectoryAfter = read(path.join(dataDir, "authority-trajectory-states/84ca685e465222a34ddc34575ff524b495eab4746fee3786a887ecb1e9d7db8f-1.json"));
  const admission = read(path.join(dataDir, "authority-admission-intents/sai_be60dabe26a8dcf2508800ac241d466c0c9c6a7f36af64c69322199cc3535e51.json"));

  const campaignId = campaign.authority.campaign_id;
  const sourceCommit = campaign.authority.source_commit;
  const imageDigest = campaign.authority.image_digest;
  const providerAddress = campaign.provider.provider_address;
  const providerRef = `provider://akash/${providerAddress}`;
  const requestHash = challenge.approval.request_hash;
  const requestRef = trajectoryDecision.candidate_operation_ref;
  mustEqual(requestHash, trajectoryDecision.candidate_operation_hash, "trajectory request hash");

  const requestFacetKeys = [
    "candidate_ref", "quote_ref", "max_hourly_usd", "gpu", "region", "az", "instance_type", "disk_gb",
    "project", "zone", "machine_type", "subscription_id", "resource_group", "location", "vm_size", "namespace",
    "workload_spec_hash", "exec_posture", "network_posture", "deployment_class", "provider_address", "bid_ref",
    "persistent_storage", "sdl_hash", "registry_credential_ref", "registry_host", "result_credential_ref",
    "result_tls_server_certificate_sha256", "campaign_id", "benchmark_source_commit", "image_digest",
    "image_build_identity_sha256", "provider_preflight_sha256", "benchmark_protocol_version", "result_schema_version",
    "benchmark_warmups", "benchmark_repeats", "max_duration_seconds", "deposit_usd", "ceiling_amount", "ceiling_denom",
    "provider_selector", "auto_topup", "stage", "restore_material_ref", "archive_ref", "teardown_policy", "execution_mode",
  ];
  const facets = {
    account_ref: challenge.account_ref, op: "create", environment_ref: challenge.resource_refs[1], kind: "akash",
    external_spend_posture: "external_spend",
  };
  for (const key of requestFacetKeys) if (Object.hasOwn(challenge.lease_request_facets, key)) facets[key] = challenge.lease_request_facets[key];
  const requestValue = {
    domain: "hypervisor.provider.op.request.v1", allowed_tools: challenge.allowed_tools,
    resource_refs: challenge.resource_refs, scopes: challenge.required_scopes, facets,
  };
  const stable = (value) => value === null || typeof value !== "object"
    ? JSON.stringify(value)
    : Array.isArray(value)
      ? `[${value.map(stable).join(",")}]`
      : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
  const canonicalRequest = stable(requestValue).replace('"deposit_usd":1,', '"deposit_usd":1.0,');
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
  const entry = (ref) => objects.find((candidate) => candidate.ref === ref);
  const value = (ref) => read(entry(ref).path);
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
    source_basis_refs: [{ ref: refs.source, hash: contentHash(sourceBasis) }, { ref: refs.daemonSource, hash: contentHash(daemonSourceBasis) }], generated_at: acceptedAt,
  });
  objects.push(object("claims", refs.claims, "schema://ioi/components/hypervisor/governed-effect-claim-manifest/v1", claimManifest));

  const policyPath = path.join(relyingPartyDir, "policy.json");
  const profilePath = path.join(relyingPartyDir, "verifier-profile.json");
  const registryPath = path.join(relyingPartyDir, "registry.json");
  const policy = read(policyPath);
  const profile = read(profilePath);
  const registryBefore = read(registryPath);
  mustEqual(profile.verifier_build_hash, hashBytes(fs.readFileSync(verifier)), "pre-provisioned verifier build");
  mustEqual(policy.verifier_profile_hash, contentHash(profile), "pre-provisioned verifier profile");
  mustEqual(policy.trust_roots[0]?.ref, refs.source, "pre-provisioned source trust root ref");
  mustEqual(policy.trust_roots[0]?.hash, contentHash(sourceBasis), "pre-provisioned source trust root hash");
  mustEqual(registryBefore.revision, 0, "pre-provisioned registry revision");
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
    terminal_settlement_ref: refs.settlement, generated_at: acceptedAt,
  };
  const draftPath = write("certificate-draft.json", draft);
  const bundleDir = path.join(output, "portable-bundle");
  fs.mkdirSync(output, { recursive: false, mode: 0o700 });
  assemblePortableBundle({
    bundle_ref: `evidence-bundle://aft/${campaignId}`, created_at: acceptedAt, certificate_draft_path: draftPath,
    certificate_file: "certificate.json", objects,
    trust_inputs: [
      { ref: policy.policy_ref, schema_ref: "schema://ioi/foundations/relying-party-acceptance-policy/v1", file: "policy.json", path: policyPath },
      { ref: profile.profile_ref, schema_ref: "schema://ioi/foundations/verifier-independence-profile/v1", file: "verifier-profile.json", path: profilePath },
    ],
  }, bundleDir);
  const rowPath = path.join(output, "accepted-row.json");
  const receiptPath = path.join(output, "acceptance-receipt.json");
  const accepted = spawnSync(verifier, ["accept", "--bundle", bundleDir, "--policy", path.join(bundleDir, "policy.json"), "--registry", registryPath, "--row-output", rowPath, "--receipt", receiptPath, "--expected-revision", "0", "--now", acceptedAt], { cwd: repo, encoding: "utf8" });
  if (accepted.status !== 0) throw new Error(`registry admission failed: ${accepted.stderr || accepted.stdout}`);
  const after = read(registryPath);
  const receipt = read(receiptPath);
  if (after.revision !== 1 || after.entries.length !== 1 || receipt.decision !== "accepted" || receipt.mutation_applied !== true) throw new Error("registry did not perform exactly one accepted state transition");
  fs.copyFileSync(registryPath, path.join(output, "registry.json"), fs.constants.COPYFILE_EXCL);
  fs.copyFileSync(path.join(relyingPartyDir, "provisioning.json"), path.join(output, "relying-party-provisioning.json"), fs.constants.COPYFILE_EXCL);
  const summary = {
    schema_version: "ioi.aft.c8-v3-offline-registry-admission-summary.v1", campaign_id: campaignId,
    bundle_ref: read(path.join(bundleDir, "bundle.json")).bundle_ref, certificate_ref: receipt.certificate_ref,
    certificate_hash: receipt.certificate_hash, policy_ref: receipt.policy_ref, policy_hash: receipt.policy_hash,
    verifier_identity_ref: receipt.verifier_identity_ref, verifier_build_hash: receipt.verifier_build_hash,
    decision: receipt.decision, mutation_applied: receipt.mutation_applied, accepted_revision: receipt.accepted_revision,
    accepted_object_refs: receipt.accepted_object_refs, registry_state_before_hash: receipt.target_state_before_hash,
    registry_state_after_hash: receipt.target_state_after_hash, result_verdict: result.verdict,
    hard_secret_non_possession_scope: isolationProbe.claim_boundary,
  };
  fs.writeFileSync(path.join(output, "admission-summary.json"), `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  console.log(JSON.stringify({ ok: true, output, ...summary }));
} catch (error) {
  if (fs.existsSync(output)) fs.writeFileSync(path.join(output, "FAILED.txt"), `${error.stack || error}\n`, { mode: 0o600 });
  throw error;
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
