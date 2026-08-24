#!/usr/bin/env node
// Relying-party gate over the RETAINED REAL U1 campaign evidence.
//
// The fixture corpus in verify-c8-v3-relying-party.mjs proves the verifier's
// semantics on a synthetic bundle. This gate proves the same semantics on the
// bytes two paid campaigns actually produced, and it never touches the registry
// of record: every acceptance runs against an isolated replica, and the record's
// bytes are compared before and after.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { assemblePortableBundle, contentHash, sealSelfHash } from "./lib/c8-v3-portable-bundle.mjs";
import { fullyResealBundle } from "./lib/c8-v3-bundle-reseal.mjs";
import { buildCampaignBundleInputs } from "./lib/u1-campaign-c8-v3-bundle.mjs";
import { buildRelyingPartyTrustInputs, differencesOutsideBuildLineage } from "./lib/u1-c8-relying-party-provisioning.mjs";

const repo = path.resolve(import.meta.dirname, "../../..");
const home = process.env.HOME;
if (!home) throw new Error("HOME is required");
const evidenceRoot = process.env.IOI_U1_CAMPAIGN_EVIDENCE_ROOT || path.join(home, ".ioi/hypervisor/evidence/u1");
const dataDir = process.env.IOI_HYPERVISOR_DATA_DIR || path.join(home, ".ioi/hypervisor/data");
const recordDir = process.env.IOI_C8_RELYING_PARTY_DIR
  || path.join(evidenceRoot, "campaign-o-aes-phl-14d24907/c8-v3-relying-party");
const admissionDir = process.env.IOI_C8_REGISTRY_ADMISSION_DIR
  || path.join(evidenceRoot, "campaign-o-aes-phl-14d24907/c8-v3-registry-admission");
const verifier = process.env.IOI_AFT_C8_VERIFIER || path.join(repo, "target/debug/aft-c8-verifier");
const selfTest = process.argv.includes("--self-test");
const now = "2026-08-23T23:45:00Z";

// Each mutation names the exact failure it must provoke. Without this, a
// mutation rejected for some unrelated reason — a duplicate row, a stale
// revision — reads as a semantic pass, and a regression in the very check
// the mutation targets leaves this gate green.
const EXPECTED_REJECTION = {
  "registry-duplicate-row": "registry_duplicate_row",
  "registry-ref-mismatch": "registry_ref_mismatch",
  "result-verdict-promoted": "result_verdict_inconsistent",
  "result-all-rows-inflated": "result_verdict_inconsistent",
  "result-row-verdict-flipped": "campaign_row_verdict_inconsistent",
  "result-metric-verdict-flipped": "campaign_metric_verdict_inconsistent",
  "result-metric-sample-dropped": "campaign_metric_values_invalid",
  "result-metric-summary-substituted": "campaign_metric_summary_inconsistent",
  "result-threshold-widened": "campaign_threshold_substitution",
  "result-scenario-substituted": "campaign_scenario_lane_matrix_mismatch",
  "result-pass-count": "campaign_protocol_mismatch",
  "request-projection-provider": "governed_request_projection_mismatch",
  "request-projection-image": "governed_request_projection_mismatch",
  "request-projection-source": "governed_request_projection_mismatch",
  "request-projection-operation": "governed_request_projection_mismatch",
  "request-projection-destination": "governed_request_projection_mismatch",
  "request-canonical-json": "governed_request_projection_mismatch",
  "readiness-status": "status",
  "readiness-replicas": "workload_not_ready",
  "readiness-image": "image_digest",
  "retrieval-auth": "result_retrieval_not_authenticated",
  "retrieval-result": "result_hash",
  "environment-class": "environment_class",
  "environment-provider": "provider_ref",
  "campaign-status": "status",
  "campaign-result": "result_hash",
  "isolation-bypass": "isolation_boundary_not_demonstrated",
  "isolation-network": "network_posture",
  "isolation-invoker": "isolation_boundary_not_demonstrated",
  "isolation-host-mount": "host_mount_policy",
  "isolation-daemon-socket": "isolation_requirements_not_hostile_guest_safe",
  "secret-finding": "secret_probe_projection_mismatch",
  "secret-credential": "worker_secret_non_possession_not_demonstrated",
  "envelope-topup": "standing_envelope_does_not_cover_request",
  "envelope-image": "standing_envelope_does_not_cover_request",
  "draw-decision": "decision",
  "draw-atomicity": "authority_draw_not_terminally_consumed",
  "trajectory-decision": "decision",
  "trajectory-constraint": "trajectory_constraint_not_satisfied",
  "trajectory-after-count": "trajectory_state_transition_invalid",
  "trajectory-after-provider": "trajectory_state_transition_invalid",
  "trajectory-before-spend": "trajectory_predecessor_not_anchored",
  "trajectory-before-prepopulated": "trajectory_predecessor_not_anchored",
  "settlement-lease": "lease_status",
  "settlement-exposure": "terminal_settlement_incomplete",
  "settlement-teardown": "terminal_settlement_incomplete",
  "terminal-result": "terminal_prerequisite_unsatisfied",
  "claims-inflated-reproduction": "nonclaim_inflated_to_claim",
  "claims-inflated-third-party": "nonclaim_inflated_to_claim",
  "claims-unknown-id": "unsupported_claim_id",
  "claims-dropped-isolation": "required_claim_missing",
  "journal-predecessor": "outcome_predecessor_mismatch",
  "journal-no-advance": "outcome_root_did_not_advance",
  "certificate-audience": "relying_party_audience_ref",
  "certificate-honesty-class": "honesty_class_not_accepted",
  "certificate-environment-class": "environment_class_not_accepted"
};

const temp = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-u1-real-relying-party-"));
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const mustEqual = (actual, expected, label) => {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, observed ${actual}`);
};
const run = (...args) => spawnSync(verifier, args, { cwd: repo, encoding: "utf8" });
const h = (digit) => `sha256:${digit.repeat(64)}`;

// An isolated replica of the relying-party registry at a chosen revision. The
// registry of record is never opened for writing by this gate.
const replicaRegistry = (name, value) => {
  const file = path.join(temp, `${name}.json`);
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  return file;
};

try {
  if (!fs.existsSync(verifier)) throw new Error(`verifier binary missing: ${verifier}`);
  for (const required of [recordDir, admissionDir]) {
    if (!fs.existsSync(required)) throw new Error(`retained relying-party evidence is absent: ${required}`);
  }
  const registryOfRecordPath = path.join(recordDir, "registry.json");
  const retainedPolicy = read(path.join(recordDir, "policy.json"));
  const retainedProfile = read(path.join(recordDir, "verifier-profile.json"));
  const registryOfRecordBefore = fs.readFileSync(registryOfRecordPath);
  const registryOfRecord = JSON.parse(registryOfRecordBefore.toString("utf8"));
  const recordedReceipt = read(path.join(admissionDir, "acceptance-receipt.json"));
  const recordedSummary = read(path.join(admissionDir, "admission-summary.json"));
  const recordedBundle = read(path.join(admissionDir, "portable-bundle/bundle.json"));

  // The verifier refuses any profile that does not name its own executable, so
  // the trust inputs are re-derived for the build under test. They must differ
  // from the retained ones ONLY in the build lineage: anything else would be a
  // different relying party quietly evaluating the same evidence.
  const anySource = read(path.join(evidenceRoot, `${path.basename(path.dirname(recordDir))}/run/u1-campaign-certificate.json`)).authority;
  const sourceBasis = { schema_version: "ioi.foundations.source-basis.v1", commit: anySource.source_commit, image_digest: anySource.image_digest };
  const { policy, profile, verifierBuildHash } = buildRelyingPartyTrustInputs({ verifierPath: verifier, sourceBasis });
  for (const [kind, current, retained] of [["policy", policy, retainedPolicy], ["profile", profile, retainedProfile]]) {
    const drift = differencesOutsideBuildLineage(current, retained, kind);
    if (drift.length > 0) throw new Error(`re-derived relying-party ${kind} drifted outside the build lineage: ${drift.join(", ")}`);
  }
  mustEqual(policy.verifier_profile_hash, contentHash(profile), "re-derived policy binds its own verifier profile");
  const rebuiltVerifier = verifierBuildHash !== retainedProfile.verifier_build_hash;
  const policyPath = path.join(temp, "policy.json");
  const profilePath = path.join(temp, "verifier-profile.json");
  fs.writeFileSync(policyPath, `${JSON.stringify(policy, null, 2)}\n`, { mode: 0o600 });
  fs.writeFileSync(profilePath, `${JSON.stringify(profile, null, 2)}\n`, { mode: 0o600 });

  // Discover every retained campaign that carries a complete run directory.
  const campaigns = fs.readdirSync(evidenceRoot)
    .filter((name) => name.startsWith("campaign-"))
    .map((name) => ({ name, runDir: path.join(evidenceRoot, name, "run") }))
    .filter((entry) => fs.existsSync(path.join(entry.runDir, "u1-campaign-certificate.json"))
      && fs.existsSync(path.join(entry.runDir, "workload-effect-isolation-evidence.json")))
    .sort((left, right) => left.name.localeCompare(right.name));
  if (campaigns.length < 2) throw new Error(`expected at least two retained measured campaigns, observed ${campaigns.length}`);

  const trustInputs = [
    { ref: policy.policy_ref, schema_ref: "schema://ioi/foundations/relying-party-acceptance-policy/v1", file: "policy.json", path: policyPath },
    { ref: profile.profile_ref, schema_ref: "schema://ioi/foundations/verifier-independence-profile/v1", file: "verifier-profile.json", path: profilePath },
  ];

  const built = [];
  for (const campaign of campaigns) {
    const scratch = fs.mkdtempSync(path.join(temp, "objects-"));
    const writeTemp = (name, value) => {
      const target = path.join(scratch, name);
      fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
      return target;
    };
    const inputs = buildCampaignBundleInputs({ campaignDir: campaign.runDir, dataDir, policy, generatedAt: now, writeTemp });
    const bundleDir = path.join(temp, `bundle-${inputs.campaignId}`);
    const { certificate } = assemblePortableBundle({
      bundle_ref: inputs.bundleRef, created_at: now, certificate_draft_path: writeTemp("certificate-draft.json", inputs.draft),
      certificate_file: "certificate.json", objects: inputs.objects, trust_inputs: trustInputs,
    }, bundleDir);
    // Canonical schema validation plus the separate verifier, over the rebuilt
    // bundle. The bundle retained beside the record pins the verifier build that
    // produced it, so it is evidence of that transition, not a re-runnable input.
    const canonical = spawnSync(process.execPath, [path.join(import.meta.dirname, "verify-c8-v3-canonical-bundle.mjs"), bundleDir, now], { cwd: repo, encoding: "utf8" });
    if (canonical.status !== 0) throw new Error(`retained campaign ${inputs.campaignId} failed canonical bundle validation: ${canonical.stderr || canonical.stdout}`);
    const verified = run("verify", "--bundle", bundleDir, "--policy", path.join(bundleDir, "policy.json"), "--now", now);
    if (verified.status !== 0) throw new Error(`separate verifier refused retained campaign ${inputs.campaignId}: ${verified.stderr || verified.stdout}`);
    built.push({ ...campaign, inputs, bundleDir, certificate, canonicalChecks: JSON.parse(canonical.stdout).canonical_schema_checks });
  }

  // 1. Reproduce the registry-of-record transition offline. Revision 0 is
  //    reconstructed from the contract, not copied, and must hash to the
  //    `previous_state_hash` the record itself carries.
  const admitted = built.find((entry) => entry.inputs.campaignId === recordedSummary.campaign_id);
  if (!admitted) throw new Error(`the admitted campaign ${recordedSummary.campaign_id} has no retained run directory`);
  const genesis = sealSelfHash({
    schema_version: "ioi.aft.measured-results-registry.v1", registry_ref: registryOfRecord.registry_ref,
    revision: 0, previous_state_hash: null, entries: [],
  });
  mustEqual(genesis.state_hash, registryOfRecord.previous_state_hash, "reconstructed genesis registry state");
  mustEqual(genesis.state_hash, recordedReceipt.target_state_before_hash, "record's accepted before-state");
  const reproducedPath = replicaRegistry("replica-genesis", genesis);
  const reproduced = run("accept", "--bundle", admitted.bundleDir, "--policy", path.join(admitted.bundleDir, "policy.json"),
    "--registry", reproducedPath, "--row-output", path.join(temp, "reproduced-row.json"),
    "--receipt", path.join(temp, "reproduced-receipt.json"), "--expected-revision", "0", "--now", now);
  if (reproduced.status !== 0) throw new Error(`offline reproduction of the record transition failed: ${reproduced.stderr || reproduced.stdout}`);
  const reproducedReceipt = read(path.join(temp, "reproduced-receipt.json"));
  const reproducedRegistry = read(reproducedPath);
  mustEqual(admitted.certificate.certificate_hash, recordedReceipt.certificate_hash, "reproduced certificate hash");
  mustEqual(reproducedReceipt.target_state_after_hash, recordedReceipt.target_state_after_hash, "reproduced registry after-state");
  mustEqual(reproducedRegistry.state_hash, registryOfRecord.state_hash, "reproduced registry of record");
  mustEqual(JSON.stringify(reproducedRegistry.entries), JSON.stringify(registryOfRecord.entries), "reproduced registry entries");
  mustEqual(reproducedReceipt.decision, "accepted", "reproduced decision");

  // 2. Every other retained campaign is a candidate the registry has not yet
  //    seen. Admitting it exercises compare-and-set against a NON-EMPTY
  //    registry, on a replica seeded byte-for-byte from the record.
  const candidates = built.filter((entry) => entry.inputs.campaignId !== recordedSummary.campaign_id);
  const candidateAdmissions = [];
  for (const candidate of candidates) {
    const replicaPath = replicaRegistry(`replica-successor-${candidate.inputs.campaignId}`, registryOfRecord);
    const receiptPath = path.join(temp, `successor-receipt-${candidate.inputs.campaignId}.json`);
    const accepted = run("accept", "--bundle", candidate.bundleDir, "--policy", path.join(candidate.bundleDir, "policy.json"),
      "--registry", replicaPath, "--row-output", path.join(temp, `successor-row-${candidate.inputs.campaignId}.json`),
      "--receipt", receiptPath, "--expected-revision", String(registryOfRecord.revision), "--now", now);
    if (accepted.status !== 0) throw new Error(`retained campaign ${candidate.inputs.campaignId} was refused by the relying party: ${accepted.stderr || accepted.stdout}`);
    const receipt = read(receiptPath);
    const after = read(replicaPath);
    if (receipt.decision !== "accepted" || receipt.mutation_applied !== true
      || after.revision !== registryOfRecord.revision + 1 || after.entries.length !== registryOfRecord.entries.length + 1) {
      throw new Error(`successor admission was not exactly one compare-and-set transition: ${candidate.inputs.campaignId}`);
    }
    mustEqual(receipt.target_state_before_hash, registryOfRecord.state_hash, "successor before-state is the record's current state");
    candidateAdmissions.push({
      campaign_id: candidate.inputs.campaignId, certificate_hash: candidate.certificate.certificate_hash,
      result_hash: contentHash(candidate.inputs.result), accepted_revision: receipt.accepted_revision,
      replica_state_after_hash: receipt.target_state_after_hash, verdict: candidate.inputs.result.verdict,
      registry_of_record_mutated: false,
    });
  }

  // 3. Real-evidence semantic mutation corpus, resealed, against a replica of
  //    the record's CURRENT state. `control-resealed-identity` carries no
  //    semantic change and must be ACCEPTED: without it a green corpus could be
  //    forty rejections caused by resealing damage rather than by semantics.
  // `state_before_ref` and `state_after_ref` are ONE logical trajectory-state
  // ref carrying two versions, so both are addressed by file. Addressing them by
  // ref alone would silently mutate whichever version came first.
  const refs = {
    ...admitted.inputs.refs,
    before: { ref: admitted.inputs.refs.before, file: "trajectory-before.json" },
    after: { ref: admitted.inputs.refs.after, file: "trajectory-after.json" },
  };
  const realResult = admitted.inputs.result;
  const flipRow = (value) => { value.summaries[0].within_threshold = !value.summaries[0].within_threshold; };
  const mutations = [
    // Two registry-level refusals that are reached only by a SEMANTICALLY VALID
    // bundle, so they also prove the corpus is not being rejected upstream.
    ["registry-duplicate-row", null, null, null, "duplicate"],
    ["registry-ref-mismatch", null, null, null, "wrong-registry"],
    ["control-resealed-identity", null, null, null, "accept"],
    ["result-verdict-promoted", refs.result, (v) => { v.verdict = "reproduced_within_threshold"; }],
    ["result-all-rows-inflated", refs.result, (v) => { v.all_rows_within_threshold = !v.all_rows_within_threshold; }],
    ["result-row-verdict-flipped", refs.result, flipRow],
    ["result-metric-verdict-flipped", refs.result, (v) => { const m = v.summaries[0].metrics.injection_tps; m.within_threshold = !m.within_threshold; }],
    ["result-metric-sample-dropped", refs.result, (v) => { v.summaries[0].metrics.injection_tps.values.pop(); }],
    ["result-metric-summary-substituted", refs.result, (v) => { v.summaries[0].metrics.injection_tps.median += 1; }],
    ["result-threshold-widened", refs.result, (v) => { v.summaries[0].metrics.injection_tps.threshold = 0.5; }],
    ["result-scenario-substituted", refs.result, (v) => { v.summaries[0].scenario = "paper_unknown_4v"; }],
    ["result-pass-count", refs.result, (v) => { v.measured_passes = 4; }],
    ["request-projection-provider", refs.request, (v) => { v.projection.provider_ref = "provider://akash/other"; v.projection.provider_address = "akash1other"; }],
    ["request-projection-image", refs.request, (v) => { v.projection.image_digest = h("9"); }],
    ["request-projection-source", refs.request, (v) => { v.projection.benchmark_source_commit = "9".repeat(40); }],
    ["request-projection-operation", refs.request, (v) => { v.projection.operation = "delete"; }],
    ["request-projection-destination", refs.request, (v) => { v.projection.result_destination_ref = "connector://other"; }],
    ["request-canonical-json", refs.request, (v) => { v.canonical_json = v.canonical_json.replace('"op":"create"', '"op":"delete"'); }],
    ["readiness-status", refs.readiness, (v) => { v.status = "pending"; }],
    ["readiness-replicas", refs.readiness, (v) => { v.ready_replicas = 0; }],
    ["readiness-image", refs.readiness, (v) => { v.image_digest = h("9"); }],
    ["retrieval-auth", refs.retrieval, (v) => { v.authenticated = false; }],
    ["retrieval-result", refs.retrieval, (v) => { v.result_hash = h("9"); }],
    ["environment-class", refs.environment, (v) => { v.environment_class = "bare_metal"; }],
    ["environment-provider", refs.environment, (v) => { v.provider_ref = "provider://akash/other"; }],
    ["campaign-status", refs.campaign, (v) => { v.status = "partial"; }],
    ["campaign-result", refs.campaign, (v) => { v.result_hash = h("9"); }],
    ["isolation-bypass", refs.isolationEvidence, (v) => { v.direct_protected_effect_invocations = 1; }],
    ["isolation-network", refs.isolationEvidence, (v) => { v.network_posture = "egress_enabled"; }],
    ["isolation-invoker", refs.isolationEvidence, (v) => { v.final_invoker_calls = 0; }],
    ["isolation-host-mount", refs.isolationRequirements, (v) => { v.host_mount_policy = "read_only"; }],
    ["isolation-daemon-socket", refs.isolationRequirements, (v) => { v.daemon_socket_exposed = true; }],
    ["secret-finding", refs.secret, (v) => { v.secret_findings = 1; }],
    ["secret-credential", refs.secret, (v) => { v.provider_credential_observed = true; }],
    ["envelope-topup", refs.envelope, (v) => { v.facet_template.auto_topup = true; }],
    ["envelope-image", refs.envelope, (v) => { v.facet_template.image_digests = [h("9")]; }],
    ["draw-decision", refs.drawReceipt, (v) => { v.decision = "refused"; }],
    ["draw-atomicity", refs.drawReceipt, (v) => { v.atomic_consumption = false; }],
    ["trajectory-decision", refs.decision, (v) => { v.decision = "deny"; }],
    ["trajectory-constraint", refs.decision, (v) => { v.constraint_results[0].satisfied = false; }],
    ["trajectory-after-count", refs.after, (v) => { v.admitted_call_count = 0; }],
    ["trajectory-after-provider", refs.after, (v) => { v.provider_refs = []; }],
    ["trajectory-before-spend", refs.before, (v) => { v.cumulative_spend_usd = 1; }],
    ["trajectory-before-prepopulated", refs.before, (v) => { v.admitted_call_count = 1; }],
    ["settlement-lease", refs.settlement, (v) => { v.lease_status = "open"; }],
    ["settlement-exposure", refs.settlement, (v) => { v.open_unknown_exposure_microusd = 1; }],
    ["settlement-teardown", refs.settlement, (v) => { v.teardown_verified = false; }],
    ["terminal-result", refs.terminal, (v) => { v.result_verified = false; }],
    ["claims-inflated-reproduction", refs.claims, (v) => { const c = v.claims.find((entry) => entry.claim_id === "independently_reproduced"); c.status = "demonstrated"; c.evidence_refs = [refs.variance]; }],
    ["claims-inflated-third-party", refs.claims, (v) => { const c = v.claims.find((entry) => entry.claim_id === "third_party_verified"); c.status = "demonstrated"; c.evidence_refs = [refs.variance]; }],
    ["claims-unknown-id", refs.claims, (v) => { v.claims.push({ claim_id: "bare_metal_attested", status: "demonstrated", evidence_refs: [refs.environment], limitation_note: "planted claim the policy has never heard of" }); }],
    ["claims-dropped-isolation", refs.claims, (v) => { v.claims = v.claims.filter((entry) => entry.claim_id !== "workload_bound_isolation_enforced"); }],
    ["journal-predecessor", null, null, (v) => { v.journal_binding.outcome_predecessor_root = h("9"); }],
    ["journal-no-advance", null, null, (v) => { v.journal_binding.outcome_root = v.journal_binding.intent_root; }],
    ["certificate-audience", null, null, (v) => { v.relying_party_audience_ref = "relying-party://other"; }],
    ["certificate-honesty-class", null, null, (v) => { v.honesty_class = "bare_metal_attested"; }],
    ["certificate-environment-class", null, null, (v) => { v.environment_class = "bare_metal"; }],
  ];

  const assertRejected = (name, status, registryPath, beforeBytes, receiptPath) => {
    if (status === 0) throw new Error(`resealed real-evidence mutation was accepted: ${name}`);
    if (!fs.readFileSync(registryPath).equals(beforeBytes)) throw new Error(`rejected candidate changed registry bytes: ${name}`);
    if (!fs.existsSync(receiptPath)) throw new Error(`rejection emitted no typed receipt: ${name}`);
    const receipt = read(receiptPath);
    if (receipt.decision !== "rejected" || receipt.mutation_applied !== false
      || receipt.target_state_before_hash !== receipt.target_state_after_hash
      || !Array.isArray(receipt.failure_codes) || receipt.failure_codes.length === 0) {
      throw new Error(`rejection receipt did not preserve state truth: ${name}`);
    }
    const expected = EXPECTED_REJECTION[name];
    if (!expected) throw new Error(`mutation declares no expected failure code: ${name}`);
    if (!receipt.failure_codes.includes(expected)) {
      throw new Error(`mutation ${name} was rejected for the wrong reason: expected ${expected}, observed ${receipt.failure_codes.join(",")}`);
    }
    return receipt.failure_codes;
  };

  // The trajectory pair is the reason the resealer is version-aware. Prove the
  // guard is live on this bundle: addressing that ref without a file must fail
  // closed rather than silently reseal whichever version came first.
  {
    const probe = path.join(temp, "ambiguity-probe");
    fs.cpSync(admitted.bundleDir, probe, { recursive: true });
    let ambiguityRefused = false;
    try {
      fullyResealBundle({ directory: probe, refs, objectRef: admitted.inputs.refs.before, mutate: (v) => { v.admitted_call_count = 9; } });
    } catch (error) {
      ambiguityRefused = /version-ambiguous/u.test(String(error.message));
    }
    if (!ambiguityRefused) throw new Error("a version-ambiguous trajectory ref was resealed without a file — the corpus could mutate the wrong version");
    fs.rmSync(probe, { recursive: true, force: true });
  }

  const rejectionCodes = {};
  let controlAccepted = false;
  const recordBytes = fs.readFileSync(registryOfRecordPath);
  for (const [index, [name, objectRef, mutate, mutateCertificate, expectation]] of mutations.entries()) {
    const mutatedDir = path.join(temp, `real-negative-${index}-${name}`);
    fs.cpSync(admitted.bundleDir, mutatedDir, { recursive: true });
    fullyResealBundle({ directory: mutatedDir, refs, objectRef, mutate, mutateCertificate });
    // The identity control is admitted against a GENESIS replica: the record's
    // current state already holds this campaign's row, so a rev-1 replica would
    // refuse it for duplication before semantics were ever consulted.
    const seed = expectation === "accept"
      ? genesis
      : expectation === "wrong-registry"
        ? sealSelfHash({ ...registryOfRecord, registry_ref: "registry://aft/other-measured-results" })
        : registryOfRecord;
    const expectedRevision = expectation === "accept" ? 0 : registryOfRecord.revision;
    const registryPath = replicaRegistry(`replica-negative-${index}`, seed);
    const beforeBytes = fs.readFileSync(registryPath);
    const receiptPath = path.join(temp, `real-receipt-${index}.json`);
    const outcome = run("accept", "--bundle", mutatedDir, "--policy", path.join(mutatedDir, "policy.json"),
      "--registry", registryPath, "--row-output", path.join(temp, `real-row-${index}.json`),
      "--receipt", receiptPath, "--expected-revision", String(expectedRevision), "--now", now);
    if (expectation === "accept") {
      if (outcome.status !== 0) throw new Error(`the resealed identity control was rejected — the corpus would prove resealing damage, not semantics: ${outcome.stderr || outcome.stdout}`);
      const receipt = read(receiptPath);
      if (receipt.decision !== "accepted" || receipt.certificate_hash !== recordedReceipt.certificate_hash) throw new Error("the resealed identity control did not reproduce the record's certificate");
      mustEqual(receipt.verifier_build_hash, verifierBuildHash, "control receipt names the build under test");
      controlAccepted = true;
      continue;
    }
    rejectionCodes[name] = assertRejected(name, outcome.status, registryPath, beforeBytes, receiptPath);
    if (selfTest) {
      // Mutation-test this gate against its own finding: the assertion that
      // rejects must itself fail when handed an acceptance.
      let raised = false;
      try { assertRejected(name, 0, registryPath, beforeBytes, receiptPath); } catch { raised = true; }
      if (!raised) throw new Error(`the rejection assertion cannot fail on its own finding: ${name}`);
    }
  }
  if (!controlAccepted) throw new Error("the corpus ran without its resealed identity control");
  if (Object.keys(rejectionCodes).length !== mutations.length - 1) throw new Error("mutation corpus did not run to completion");
  const undeclared = Object.keys(EXPECTED_REJECTION).filter((name) => !Object.hasOwn(rejectionCodes, name));
  if (undeclared.length > 0) throw new Error(`declared expectations never ran: ${undeclared.join(", ")}`);

  // 4. The registry of record was never opened for writing.
  if (!fs.readFileSync(registryOfRecordPath).equals(recordBytes) || !recordBytes.equals(registryOfRecordBefore)) {
    throw new Error("the registry of record changed while this gate ran");
  }

  console.log(JSON.stringify({
    ok: true,
    retained_campaigns_verified: built.map((entry) => entry.inputs.campaignId),
    canonical_schema_checks_per_bundle: built.map((entry) => entry.canonicalChecks),
    record_transition_reproduced_offline: {
      campaign_id: recordedSummary.campaign_id, certificate_hash: reproducedReceipt.certificate_hash,
      state_before_hash: reproducedReceipt.target_state_before_hash, state_after_hash: reproducedReceipt.target_state_after_hash,
      accepted_revision: reproducedReceipt.accepted_revision,
    },
    successor_admissions_on_replica: candidateAdmissions,
    registry_of_record_revision: registryOfRecord.revision,
    verifier_build_hash: verifierBuildHash,
    verifier_rebuilt_since_record: rebuiltVerifier,
    retained_bundle_ref: recordedBundle.bundle_ref,
    registry_of_record_unchanged: true,
    resealed_identity_control_accepted: controlAccepted,
    real_evidence_semantic_mutations_rejected: Object.keys(rejectionCodes).length,
    rejection_codes: rejectionCodes,
    self_test: selfTest,
  }));
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
