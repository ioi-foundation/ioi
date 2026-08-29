use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};

const C8_V3: &str = "ioi.components.hypervisor.c8-certificate.v3";
const BUNDLE_V1: &str = "ioi.components.hypervisor.c8-portable-evidence-bundle.v1";
const POLICY_V1: &str = "ioi.foundations.relying-party-acceptance-policy.v1";
const PROFILE_V1: &str = "ioi.foundations.verifier-independence-profile.v1";
const RESULT_V1: &str = "ioi.aft.benchmark-campaign.v1";
const REGISTRY_V1: &str = "ioi.aft.measured-results-registry.v1";
const ROW_V1: &str = "ioi.aft.measured-result-row.v1";
const RECEIPT_V1: &str = "ioi.foundations.certificate-acceptance-receipt.v1";
const MAX_JSON_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Parser)]
#[command(about = "Verify C8 v3 evidence and admit AFT measured results")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Verify {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        now: String,
    },
    Accept {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        row_output: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        now: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableBundle {
    schema_version: String,
    bundle_ref: String,
    bundle_hash: String,
    certificate_ref: String,
    certificate_hash: String,
    certificate_file: String,
    objects: Vec<BundleObject>,
    trust_inputs: Vec<BundleObject>,
    created_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleObject {
    r#ref: String,
    hash: String,
    schema_ref: String,
    file: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema_version: String,
    policy_ref: String,
    policy_hash: String,
    audience_ref: String,
    accepted_certificate_schema_refs: Vec<String>,
    accepted_result_schema_refs: Vec<String>,
    trust_roots: Vec<RefHash>,
    maximum_certificate_age_seconds: u64,
    revocation_check_required: bool,
    required_claim_ids: Vec<String>,
    tolerated_nonclaim_ids: Vec<String>,
    accepted_environment_classes: Vec<String>,
    accepted_honesty_classes: Vec<String>,
    accepted_result_verdicts: Vec<String>,
    verifier_profile_ref: String,
    verifier_profile_hash: String,
    target_transition: TargetTransition,
    valid_from: String,
    valid_until: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefHash {
    r#ref: String,
    hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetTransition {
    target_registry_ref: String,
    mutation_kind: String,
    target_schema_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifierProfile {
    schema_version: String,
    profile_ref: String,
    profile_hash: String,
    verifier_identity_ref: String,
    verifier_build_hash: String,
    contract_schema_refs: Vec<String>,
    separate_binary: bool,
    separate_codegen: bool,
    separate_transport: bool,
    separate_authoring_party: bool,
    accountable_authoring_party_ref: String,
    evidence_refs: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimManifest {
    schema_version: String,
    manifest_ref: String,
    manifest_hash: String,
    subject_ref: String,
    subject_hash: String,
    protection_profile: String,
    claims: Vec<Claim>,
    source_basis_refs: Vec<RefHash>,
    generated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    claim_id: String,
    status: String,
    evidence_refs: Vec<String>,
    limitation_note: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignResult {
    schema_version: String,
    campaign_id: String,
    measured_passes: u64,
    row_count_per_pass: u64,
    threshold_policy: Value,
    verdict: String,
    all_rows_within_threshold: bool,
    summaries: Vec<Value>,
    pass_artifacts: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    schema_version: String,
    registry_ref: String,
    revision: u64,
    previous_state_hash: Option<String>,
    entries: Vec<RegistryEntry>,
    state_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryEntry {
    row_ref: String,
    row_hash: String,
}

#[derive(Debug, Serialize)]
struct MeasuredRow {
    schema_version: String,
    row_ref: String,
    row_hash: String,
    certificate_ref: String,
    certificate_hash: String,
    result_ref: String,
    result_hash: String,
    environment_hash: String,
    campaign_id: String,
    source_commit: String,
    image_digest: String,
    provider_ref: String,
    environment_class: String,
    honesty_class: String,
    verdict: String,
    accepted_at: String,
}

#[derive(Debug, Serialize)]
struct AcceptanceReceipt {
    schema_version: String,
    receipt_ref: String,
    receipt_hash: String,
    certificate_ref: String,
    certificate_hash: String,
    policy_ref: String,
    policy_hash: String,
    verifier_identity_ref: String,
    verifier_build_hash: String,
    trust_input_hashes: Vec<String>,
    decision: String,
    failure_codes: Vec<String>,
    accepted_object_refs: Vec<String>,
    accepted_revision: u64,
    mutation_applied: bool,
    target_state_before_hash: String,
    target_state_after_hash: String,
    observed_at: String,
    valid_until: String,
}

struct Verified {
    bundle: PortableBundle,
    policy: Policy,
    profile: VerifierProfile,
    certificate: Value,
    result: CampaignResult,
    provider_ref: String,
    trust_hashes: Vec<String>,
}

struct ReceiptDecision {
    after: String,
    accepted: Vec<String>,
    mutated: bool,
    decision: &'static str,
    failures: Vec<String>,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Verify {
            bundle,
            policy,
            now,
        } => {
            let now = parse_time(&now)?;
            let verified = verify_bundle(&bundle, &policy, now)?;
            println!("verified {}", verified.bundle.certificate_hash);
        }
        Command::Accept {
            bundle,
            policy,
            registry,
            row_output,
            receipt,
            expected_revision,
            now,
        } => {
            accept(
                &bundle,
                &policy,
                &registry,
                &row_output,
                &receipt,
                expected_revision,
                parse_time(&now)?,
            )?;
        }
    }
    Ok(())
}

fn verify_bundle(bundle_dir: &Path, policy_path: &Path, now: OffsetDateTime) -> Result<Verified> {
    let manifest_path = bundle_dir.join("bundle.json");
    let bundle_value = read_json(&manifest_path)?;
    let bundle: PortableBundle =
        serde_json::from_value(bundle_value.clone()).context("bundle schema")?;
    ensure_eq(&bundle.schema_version, BUNDLE_V1, "bundle_schema")?;
    if !bundle.bundle_ref.starts_with("evidence-bundle://") {
        bail!("bundle_ref_invalid")
    }
    validate_hash_field(
        &bundle_value,
        "bundle_hash",
        &bundle.bundle_hash,
        "bundle_hash",
    )?;
    parse_time(&bundle.created_at).context("bundle created_at")?;

    let policy_value = read_json(policy_path)?;
    let policy: Policy = serde_json::from_value(policy_value.clone()).context("policy schema")?;
    ensure_eq(&policy.schema_version, POLICY_V1, "policy_schema")?;
    validate_hash_field(
        &policy_value,
        "policy_hash",
        &policy.policy_hash,
        "policy_hash",
    )?;
    let valid_from = parse_time(&policy.valid_from)?;
    let valid_until = parse_time(&policy.valid_until)?;
    if now < valid_from || now > valid_until {
        bail!("policy_not_current")
    }
    if policy.target_transition.target_registry_ref != "registry://aft/measured-results"
        || policy.target_transition.mutation_kind != "aft_measured_result_promote"
        || policy.target_transition.target_schema_ref != "schema://ioi/aft/measured-result-row/v1"
    {
        bail!("policy_target_transition_invalid")
    }

    let all = index_objects(
        bundle_dir,
        bundle.objects.iter().chain(bundle.trust_inputs.iter()),
    )?;
    validate_file_name(&bundle.certificate_file)?;
    let certificate_path = bundle_dir.join(&bundle.certificate_file);
    let certificate_meta = fs::symlink_metadata(&certificate_path)?;
    if certificate_meta.file_type().is_symlink()
        || !certificate_meta.is_file()
        || certificate_meta.len() > MAX_JSON_BYTES
    {
        bail!("unsafe_certificate_file")
    }
    let canonical_bundle_dir = fs::canonicalize(bundle_dir)?;
    if fs::canonicalize(&certificate_path)?.parent() != Some(canonical_bundle_dir.as_path()) {
        bail!("certificate_path_escape")
    }
    let certificate = read_json(&certificate_path)?;
    ensure_value_str(&certificate, "schema_version", C8_V3)?;
    validate_hash_field(
        &certificate,
        "certificate_hash",
        &bundle.certificate_hash,
        "certificate_hash",
    )?;
    ensure_value_str(&certificate, "certificate_ref", &bundle.certificate_ref)?;
    if !policy
        .accepted_certificate_schema_refs
        .iter()
        .any(|v| v == "schema://ioi/components/hypervisor/c8-certificate/v3")
    {
        bail!("certificate_schema_not_accepted")
    }
    ensure_value_str(
        &certificate,
        "relying_party_audience_ref",
        &policy.audience_ref,
    )?;
    let generated = parse_time(required_str(&certificate, "generated_at")?)?;
    if generated > now
        || now - generated > Duration::seconds(policy.maximum_certificate_age_seconds as i64)
    {
        bail!("certificate_stale")
    }
    if policy.revocation_check_required
        && !bundle
            .trust_inputs
            .iter()
            .any(|o| o.schema_ref.contains("revocation"))
    {
        bail!("revocation_input_missing")
    }

    for binding in certificate_bindings(&certificate)? {
        let (entry, _) = all
            .get(&object_binding_key(&binding.r#ref, &binding.hash))
            .ok_or_else(|| anyhow!("bound_object_missing:{}:{}", binding.r#ref, binding.hash))?;
        ensure_eq(&entry.hash, &binding.hash, "bound_object_hash")?;
    }

    let predecessor_ref = required_str(&certificate, "predecessor_certificate_ref")?;
    let predecessor_hash = required_str(&certificate, "predecessor_certificate_hash")?;
    let predecessor = object_value_bound(
        &all,
        predecessor_ref,
        predecessor_hash,
        "predecessor_certificate_missing",
    )?;
    ensure_value_str(
        predecessor,
        "schema_version",
        required_str(&certificate, "predecessor_certificate_schema_version")?,
    )?;
    ensure_value_str(predecessor, "certificate_hash", predecessor_hash)?;
    if predecessor.get("ok").and_then(Value::as_bool) != Some(true)
        || predecessor
            .get("journal")
            .and_then(Value::as_object)
            .is_none()
        || predecessor
            .get("provider")
            .and_then(Value::as_object)
            .is_none()
    {
        bail!("predecessor_certificate_not_complete")
    }

    let manifest_ref = required_str(&certificate, "claim_manifest_ref")?;
    let manifest: ClaimManifest = object_as(&all, manifest_ref, "claim manifest")?;
    ensure_eq(
        &manifest.schema_version,
        "ioi.components.hypervisor.governed-effect-claim-manifest.v1",
        "claim_manifest_schema",
    )?;
    ensure_eq(&manifest.manifest_ref, manifest_ref, "claim_manifest_ref")?;
    ensure_eq(
        &manifest.manifest_hash,
        required_str(&certificate, "claim_manifest_hash")?,
        "claim_manifest_hash",
    )?;
    ensure_eq(
        &manifest.subject_ref,
        required_str(&certificate, "governed_request_ref")?,
        "claim_subject_ref",
    )?;
    ensure_eq(
        &manifest.subject_hash,
        required_str(&certificate, "governed_request_hash")?,
        "claim_subject_hash",
    )?;
    ensure_eq(
        &manifest.protection_profile,
        "trusted_host_hostile_guest",
        "protection_profile",
    )?;
    parse_time(&manifest.generated_at)?;
    if manifest.source_basis_refs.is_empty() {
        bail!("claim_source_basis_missing")
    }
    let claims: BTreeMap<_, _> = manifest
        .claims
        .iter()
        .map(|c| (c.claim_id.as_str(), c))
        .collect();
    if claims.len() != manifest.claims.len() {
        bail!("duplicate_claim_id")
    }
    for id in &policy.required_claim_ids {
        let claim = claims
            .get(id.as_str())
            .ok_or_else(|| anyhow!("required_claim_missing:{id}"))?;
        if claim.status != "demonstrated"
            || claim.evidence_refs.is_empty()
            || claim.limitation_note.is_empty()
        {
            bail!("required_claim_not_demonstrated:{id}")
        }
    }
    for claim in &manifest.claims {
        let required = policy.required_claim_ids.contains(&claim.claim_id);
        let tolerated = policy.tolerated_nonclaim_ids.contains(&claim.claim_id);
        // Allowlist, never denylist: a claim this policy has never heard of is
        // not evidence the policy can weigh.
        if !required && !tolerated {
            bail!("unsupported_claim_id:{}", claim.claim_id)
        }
        if claim.status != "demonstrated" && !tolerated {
            bail!("untolerated_nonclaim:{}", claim.claim_id)
        }
        // A claim appears among the tolerated nonclaims because this relying
        // party does not accept it. Promoting it is a policy change, never a
        // manifest edit.
        if tolerated && claim.status == "demonstrated" {
            bail!("nonclaim_inflated_to_claim:{}", claim.claim_id)
        }
    }

    let result_ref = required_str(&certificate, "result_ref")?;
    let result_entry = all
        .get(&object_binding_key(
            result_ref,
            required_str(&certificate, "result_hash")?,
        ))
        .ok_or_else(|| anyhow!("result_missing"))?;
    if !policy
        .accepted_result_schema_refs
        .contains(&result_entry.0.schema_ref)
    {
        bail!("result_schema_not_accepted")
    }
    let result: CampaignResult =
        serde_json::from_value(result_entry.1.clone()).context("result schema")?;
    ensure_eq(&result.schema_version, RESULT_V1, "result_schema")?;
    ensure_eq(
        &result.campaign_id,
        required_str(&certificate, "campaign_id")?,
        "result_campaign",
    )?;
    validate_campaign_result(&result)?;
    ensure_eq(
        &result_entry.0.hash,
        required_str(&certificate, "result_hash")?,
        "result_hash",
    )?;

    let environment_class = required_str(&certificate, "environment_class")?;
    if !policy
        .accepted_environment_classes
        .iter()
        .any(|v| v == environment_class)
    {
        bail!("environment_class_not_accepted")
    }
    let honesty_class = required_str(&certificate, "honesty_class")?;
    if !policy
        .accepted_honesty_classes
        .iter()
        .any(|v| v == honesty_class)
    {
        bail!("honesty_class_not_accepted")
    }
    if !policy
        .accepted_result_verdicts
        .iter()
        .any(|v| v == &result.verdict)
    {
        bail!("result_verdict_not_accepted")
    }
    if honesty_class == "attested_pinned_bare_metal"
        && environment_class != "attested_pinned_bare_metal"
    {
        bail!("bare_metal_claim_inflated")
    }
    let journal = certificate
        .get("journal_binding")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("journal_binding_missing"))?;
    if journal.get("intent_root") != journal.get("outcome_predecessor_root") {
        bail!("outcome_predecessor_mismatch")
    }
    if journal.get("intent_root") == journal.get("outcome_root") {
        bail!("outcome_root_did_not_advance")
    }

    validate_semantic_chain(&certificate, &all, &result)?;

    let profile_entry = all
        .get(&object_binding_key(
            &policy.verifier_profile_ref,
            &policy.verifier_profile_hash,
        ))
        .ok_or_else(|| anyhow!("verifier_profile_missing"))?;
    ensure_eq(
        &profile_entry.0.hash,
        &policy.verifier_profile_hash,
        "verifier_profile_hash",
    )?;
    let profile: VerifierProfile =
        serde_json::from_value(profile_entry.1.clone()).context("verifier profile schema")?;
    ensure_eq(
        &profile.schema_version,
        PROFILE_V1,
        "verifier_profile_schema",
    )?;
    ensure_eq(
        &profile.profile_ref,
        &policy.verifier_profile_ref,
        "verifier_profile_ref",
    )?;
    ensure_eq(
        &profile.profile_hash,
        &policy.verifier_profile_hash,
        "profile_self_hash",
    )?;
    if !profile.separate_binary
        || !profile.separate_codegen
        || !profile.separate_transport
        || profile.separate_authoring_party
    {
        bail!("verifier_independence_profile_invalid")
    }
    if profile.contract_schema_refs.is_empty()
        || profile.evidence_refs.len() < 3
        || profile.accountable_authoring_party_ref.is_empty()
    {
        bail!("verifier_profile_evidence_incomplete")
    }
    let own_build_hash = executable_hash()?;
    ensure_eq(
        &profile.verifier_build_hash,
        &own_build_hash,
        "verifier_build_hash",
    )?;
    if profile.verifier_identity_ref.is_empty() {
        bail!("verifier_identity_missing")
    }

    for root in &policy.trust_roots {
        let (entry, _) = all
            .get(&object_binding_key(&root.r#ref, &root.hash))
            .ok_or_else(|| anyhow!("trust_root_missing:{}", root.r#ref))?;
        ensure_eq(&entry.hash, &root.hash, "trust_root_hash")?;
    }
    let mut trust_hashes: Vec<_> = bundle.trust_inputs.iter().map(|v| v.hash.clone()).collect();
    trust_hashes.sort();
    trust_hashes.dedup();
    let provider_ref = derive_provider_ref(&certificate, &all)?;
    Ok(Verified {
        bundle,
        policy,
        profile,
        certificate,
        result,
        provider_ref,
        trust_hashes,
    })
}

fn validate_campaign_result(result: &CampaignResult) -> Result<()> {
    if result.measured_passes != 5
        || result.row_count_per_pass != 10
        || result.pass_artifacts.len() != 5
    {
        bail!("campaign_protocol_mismatch")
    }
    let unique: BTreeSet<_> = result.pass_artifacts.iter().collect();
    if unique.len() != result.pass_artifacts.len() || result.summaries.len() != 10 {
        bail!("campaign_coverage_invalid")
    }
    let expected_rows: BTreeSet<_> = [
        ("paper_guardian_majority_4v", "base_final"),
        ("paper_guardian_majority_7v", "base_final"),
        ("paper_asymptote_4v", "base_final"),
        ("paper_asymptote_4v", "canonical_ordering"),
        ("paper_asymptote_4v", "durable_collapse"),
        ("paper_asymptote_4v", "sealed_final"),
        ("paper_asymptote_7v", "base_final"),
        ("paper_asymptote_7v", "canonical_ordering"),
        ("paper_asymptote_7v", "durable_collapse"),
        ("paper_asymptote_7v", "sealed_final"),
    ]
    .into_iter()
    .collect();
    let mut observed_rows = BTreeSet::new();
    let metric_names = [
        "injection_tps",
        "sustained_tps",
        "commit_p50_ms",
        "commit_p95_ms",
        "commit_p99_ms",
        "commit_max_ms",
    ];
    let mut every_row_within = true;
    for summary in &result.summaries {
        let scenario = required_str(summary, "scenario")?;
        let lane = required_str(summary, "lane")?;
        if !observed_rows.insert((scenario, lane)) {
            bail!("campaign_duplicate_scenario_lane")
        }
        let within = summary
            .get("within_threshold")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("campaign_row_threshold_missing"))?;
        every_row_within &= within;
        let metrics = summary
            .get("metrics")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("campaign_metrics_missing"))?;
        if metrics.len() != metric_names.len() {
            bail!("campaign_metric_set_mismatch")
        }
        let mut row_metrics_within = true;
        for name in metric_names {
            let metric_value = metrics
                .get(name)
                .ok_or_else(|| anyhow!("campaign_metric_missing:{name}"))?;
            let metric = metric_value
                .as_object()
                .ok_or_else(|| anyhow!("campaign_metric_invalid:{name}"))?;
            let values = metric
                .get("values")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("campaign_metric_values_missing:{name}"))?;
            if values.len() != result.measured_passes as usize
                || values
                    .iter()
                    .any(|value| value.as_f64().is_none_or(|number| number < 0.0))
            {
                bail!("campaign_metric_values_invalid:{name}")
            }
            if metric.len() != 10 {
                bail!("campaign_metric_set_invalid:{name}")
            }
            let samples: Vec<f64> = values.iter().filter_map(Value::as_f64).collect();
            let observed_min = samples.iter().copied().fold(f64::INFINITY, f64::min);
            let observed_max = samples.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let observed_median = median(&samples)?;
            let mean = samples.iter().sum::<f64>() / samples.len() as f64;
            let observed_mad = median(
                &samples
                    .iter()
                    .map(|sample| (sample - observed_median).abs())
                    .collect::<Vec<_>>(),
            )?;
            let sample_variance = samples
                .iter()
                .map(|sample| (sample - mean).powi(2))
                .sum::<f64>()
                / (samples.len() - 1) as f64;
            let observed_cv = if mean == 0.0 {
                if observed_max == observed_min {
                    0.0
                } else {
                    f64::INFINITY
                }
            } else {
                sample_variance.sqrt() / mean
            };
            let observed_spread = if observed_median == 0.0 {
                if observed_max == observed_min {
                    0.0
                } else {
                    f64::INFINITY
                }
            } else {
                (observed_max - observed_min) / observed_median
            };
            let observed_bootstrap = exact_bootstrap_median_interval(&samples)?;
            let min = required_nonnegative_number(metric_value, "min")?;
            let median = required_nonnegative_number(metric_value, "median")?;
            let max = required_nonnegative_number(metric_value, "max")?;
            let mad = required_nonnegative_number(metric_value, "median_absolute_deviation")?;
            let cv = required_nonnegative_number(metric_value, "coefficient_of_variation")?;
            let spread = required_nonnegative_number(metric_value, "relative_spread")?;
            let bootstrap = metric
                .get("bootstrap_median_95")
                .and_then(Value::as_array)
                .filter(|interval| interval.len() == 2)
                .ok_or_else(|| anyhow!("campaign_metric_bootstrap_invalid:{name}"))?;
            let bootstrap_low = bootstrap[0]
                .as_f64()
                .filter(|number| number.is_finite() && *number >= 0.0)
                .ok_or_else(|| anyhow!("campaign_metric_bootstrap_invalid:{name}"))?;
            let bootstrap_high = bootstrap[1]
                .as_f64()
                .filter(|number| number.is_finite() && *number >= 0.0)
                .ok_or_else(|| anyhow!("campaign_metric_bootstrap_invalid:{name}"))?;
            if !approximately_equal(min, observed_min)
                || !approximately_equal(median, observed_median)
                || !approximately_equal(max, observed_max)
                || !approximately_equal(mad, observed_mad)
                || !approximately_equal(cv, observed_cv)
                || !approximately_equal(spread, observed_spread)
                || !approximately_equal(bootstrap_low, observed_bootstrap.0)
                || !approximately_equal(bootstrap_high, observed_bootstrap.1)
            {
                bail!("campaign_metric_summary_inconsistent:{name}")
            }
            let threshold = required_nonnegative_number(metric_value, "threshold")?;
            let declared_threshold = result
                .threshold_policy
                .get(name)
                .and_then(Value::as_f64)
                .ok_or_else(|| anyhow!("campaign_threshold_missing:{name}"))?;
            if threshold != declared_threshold {
                bail!("campaign_threshold_substitution:{name}")
            }
            let metric_within = metric
                .get("within_threshold")
                .and_then(Value::as_bool)
                .ok_or_else(|| anyhow!("campaign_metric_verdict_missing:{name}"))?;
            if metric_within != (observed_spread <= threshold) {
                bail!("campaign_metric_verdict_inconsistent:{name}")
            }
            row_metrics_within &= metric_within;
        }
        if within != row_metrics_within {
            bail!("campaign_row_verdict_inconsistent")
        }
        every_row_within &= row_metrics_within;
    }
    if observed_rows != expected_rows {
        bail!("campaign_scenario_lane_matrix_mismatch")
    }
    if result.all_rows_within_threshold != every_row_within {
        bail!("result_verdict_inconsistent")
    }
    if (result.verdict == "reproduced_within_threshold") != every_row_within {
        bail!("result_verdict_inconsistent")
    }
    if !matches!(
        result.verdict.as_str(),
        "reproduced_within_threshold" | "variance_caveated"
    ) {
        bail!("result_verdict_unknown")
    }
    if !result.threshold_policy.is_object() {
        bail!("threshold_policy_invalid")
    }
    Ok(())
}

fn approximately_equal(left: f64, right: f64) -> bool {
    left.is_finite()
        && right.is_finite()
        && (left - right).abs() <= 1e-12 * 1.0_f64.max(left.abs()).max(right.abs())
}

fn median(values: &[f64]) -> Result<f64> {
    if values.is_empty() || values.iter().any(|value| !value.is_finite()) {
        bail!("campaign_metric_values_invalid")
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    let middle = ordered.len() / 2;
    Ok(if ordered.len() % 2 == 1 {
        ordered[middle]
    } else {
        (ordered[middle - 1] + ordered[middle]) / 2.0
    })
}

fn percentile(values: &[f64], quantile: f64) -> Result<f64> {
    if values.is_empty() || !(0.0..=1.0).contains(&quantile) {
        bail!("campaign_metric_percentile_invalid")
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    let position = quantile * (ordered.len() - 1) as f64;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        Ok(ordered[lower])
    } else {
        let fraction = position - lower as f64;
        Ok(ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction)
    }
}

fn exact_bootstrap_median_interval(values: &[f64]) -> Result<(f64, f64)> {
    if values.is_empty() || values.iter().any(|value| !value.is_finite()) {
        bail!("campaign_metric_values_invalid")
    }
    let sample_count = values.len().pow(values.len() as u32);
    let mut medians = Vec::with_capacity(sample_count);
    for encoded in 0..sample_count {
        let mut cursor = encoded;
        let mut sample = Vec::with_capacity(values.len());
        for _ in 0..values.len() {
            sample.push(values[cursor % values.len()]);
            cursor /= values.len();
        }
        medians.push(median(&sample)?);
    }
    Ok((percentile(&medians, 0.025)?, percentile(&medians, 0.975)?))
}

fn validate_semantic_chain(
    cert: &Value,
    all: &BTreeMap<String, (BundleObject, Value)>,
    result: &CampaignResult,
) -> Result<()> {
    let campaign_id = required_str(cert, "campaign_id")?;
    let source_commit = required_str(cert, "benchmark_source_commit")?;
    let image_digest = required_str(cert, "workload_image_digest")?;
    let request_ref = required_str(cert, "governed_request_ref")?;
    let request_hash = required_str(cert, "governed_request_hash")?;
    let request_object = object_value(all, request_ref, "governed_request_missing")?;
    let request = if request_object.get("schema_version").and_then(Value::as_str)
        == Some("ioi.foundations.canonical-json-preimage.v1")
    {
        let canonical: Value =
            serde_json::from_str(required_str(request_object, "canonical_json")?)
                .context("governed_request_canonical_json")?;
        let facets = canonical
            .get("facets")
            .ok_or_else(|| anyhow!("governed_request_facets_missing"))?;
        let projection = request_object
            .get("projection")
            .ok_or_else(|| anyhow!("governed_request_projection_missing"))?;
        for (projected, native) in [
            ("operation", "op"),
            ("campaign_id", "campaign_id"),
            ("benchmark_source_commit", "benchmark_source_commit"),
            ("image_digest", "image_digest"),
            ("provider_address", "provider_address"),
        ] {
            if projection.get(projected) != facets.get(native) {
                bail!("governed_request_projection_mismatch:{projected}")
            }
        }
        let provider_address = required_str(projection, "provider_address")?;
        ensure_value_str(
            projection,
            "provider_ref",
            &format!("provider://akash/{provider_address}"),
        )?;
        if projection.get("result_destination_ref") != facets.get("result_credential_ref") {
            bail!("governed_request_projection_mismatch:result_destination_ref")
        }
        projection
    } else {
        request_object
    };
    ensure_value_str(request, "campaign_id", campaign_id)?;
    ensure_value_str(request, "benchmark_source_commit", source_commit)?;
    ensure_value_str(request, "image_digest", image_digest)?;
    if !matches!(
        required_str(request, "operation")?,
        "create" | "create_deployment"
    ) {
        bail!("governed_request_operation_invalid")
    }

    let settlement = object_value(
        all,
        required_str(cert, "terminal_settlement_ref")?,
        "settlement_missing",
    )?;
    let provider_ref = required_str(settlement, "provider_ref")?;
    ensure_value_str(settlement, "campaign_id", campaign_id)?;
    ensure_value_str(settlement, "lease_status", "closed")?;
    ensure_value_str(settlement, "deployment_status", "closed")?;
    ensure_value_str(settlement, "escrow_status", "closed")?;
    if settlement.get("active_lease_count").and_then(Value::as_u64) != Some(0)
        || settlement
            .get("open_unknown_exposure_microusd")
            .and_then(Value::as_u64)
            != Some(0)
        || settlement.get("teardown_verified").and_then(Value::as_bool) != Some(true)
    {
        bail!("terminal_settlement_incomplete")
    }
    ensure_value_str(request, "provider_ref", provider_ref)?;
    let provider_address = required_str(request, "provider_address")?;
    ensure_value_str(settlement, "provider_address", provider_address)?;

    let source_refs = cert
        .get("source_basis_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("source_basis_refs_missing"))?;
    let source_matches = source_refs.iter().any(|entry| {
        let Some(reference) = entry.get("ref").and_then(Value::as_str) else {
            return false;
        };
        let Some(hash) = entry.get("hash").and_then(Value::as_str) else {
            return false;
        };
        object_value_bound(all, reference, hash, "source_basis_missing")
            .ok()
            .and_then(|value| value.get("commit"))
            .and_then(Value::as_str)
            == Some(source_commit)
    });
    if !source_matches {
        bail!("source_basis_commit_mismatch")
    }

    let environment = object_value(
        all,
        required_str(cert, "environment_ref")?,
        "environment_missing",
    )?;
    for (field, expected) in [
        ("campaign_id", campaign_id),
        ("provider_ref", provider_ref),
        ("image_digest", image_digest),
        ("source_commit", source_commit),
        (
            "environment_class",
            required_str(cert, "environment_class")?,
        ),
        ("honesty_class", required_str(cert, "honesty_class")?),
    ] {
        ensure_value_str(environment, field, expected)?;
    }

    let readiness = cert
        .get("workload_readiness_evidence")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("workload_readiness_evidence_missing"))?;
    for binding in readiness {
        let evidence = object_value(
            all,
            required_str(binding, "ref")?,
            "readiness_evidence_missing",
        )?;
        ensure_value_str(evidence, "status", "ready")?;
        for (field, expected) in [
            ("campaign_id", campaign_id),
            ("provider_ref", provider_ref),
            ("image_digest", image_digest),
            ("source_commit", source_commit),
        ] {
            ensure_value_str(evidence, field, expected)?;
        }
        let requested = evidence
            .get("requested_replicas")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("readiness_requested_replicas_missing"))?;
        if requested == 0
            || evidence.get("ready_replicas").and_then(Value::as_u64) != Some(requested)
        {
            bail!("workload_not_ready")
        }
    }

    let retrieval = object_value(
        all,
        required_str(cert, "result_retrieval_receipt_ref")?,
        "result_retrieval_missing",
    )?;
    ensure_value_str(retrieval, "status", "verified")?;
    ensure_value_str(retrieval, "campaign_id", campaign_id)?;
    ensure_value_str(retrieval, "result_ref", required_str(cert, "result_ref")?)?;
    ensure_value_str(retrieval, "result_hash", required_str(cert, "result_hash")?)?;
    ensure_value_str(
        retrieval,
        "environment_ref",
        required_str(cert, "environment_ref")?,
    )?;
    ensure_value_str(
        retrieval,
        "environment_hash",
        required_str(cert, "environment_hash")?,
    )?;
    if retrieval.get("authenticated").and_then(Value::as_bool) != Some(true) {
        bail!("result_retrieval_not_authenticated")
    }

    let campaign = object_value(
        all,
        required_str(cert, "campaign_certificate_ref")?,
        "campaign_certificate_missing",
    )?;
    ensure_value_str(campaign, "status", "complete")?;
    for (field, expected) in [
        ("campaign_id", campaign_id),
        ("provider_ref", provider_ref),
        ("image_digest", image_digest),
        ("source_commit", source_commit),
        ("result_ref", required_str(cert, "result_ref")?),
        ("result_hash", required_str(cert, "result_hash")?),
        ("environment_ref", required_str(cert, "environment_ref")?),
        ("environment_hash", required_str(cert, "environment_hash")?),
        (
            "terminal_settlement_ref",
            required_str(cert, "terminal_settlement_ref")?,
        ),
        (
            "terminal_settlement_hash",
            required_str(cert, "terminal_settlement_hash")?,
        ),
    ] {
        ensure_value_str(campaign, field, expected)?;
    }

    let isolation = object_value(
        all,
        required_str(cert, "isolation_binding_ref")?,
        "isolation_binding_missing",
    )?;
    ensure_value_str(
        isolation,
        "route_policy_ref",
        "policy://network/deny-default",
    )?;
    ensure_value_str(
        isolation,
        "final_invoker_ref",
        "final-invoker://hypervisor/provider-operation",
    )?;
    ensure_value_str(
        isolation,
        "required_terminal_disposition",
        "destroyed_verified",
    )?;
    if !array_contains(isolation, "governed_action_classes", "provider_operation") {
        bail!("isolation_provider_action_not_governed")
    }
    let requirements_ref = required_str(isolation, "requirements_ref")?;
    let requirements = object_value(all, requirements_ref, "isolation_requirements_missing")?;
    ensure_eq(
        &content_hash(requirements)?,
        required_str(isolation, "requirements_hash")?,
        "isolation_requirements_hash",
    )?;
    ensure_value_str(
        requirements,
        "hostile_to_boundary_requirement",
        "hostile_to_guest_kernel",
    )?;
    ensure_value_str(requirements, "minimum_isolation", "vm_kernel")?;
    ensure_value_str(requirements, "host_mount_policy", "none")?;
    if requirements
        .get("daemon_socket_exposed")
        .and_then(Value::as_bool)
        != Some(false)
        || requirements
            .get("host_pid_namespace_exposed")
            .and_then(Value::as_bool)
            != Some(false)
        || requirements
            .get("raw_secret_material_in_guest")
            .and_then(Value::as_bool)
            != Some(false)
        || requirements
            .pointer("/output_admission/quarantine_required")
            .and_then(Value::as_bool)
            != Some(true)
        || requirements
            .pointer("/teardown/verify_all_resources")
            .and_then(Value::as_bool)
            != Some(true)
    {
        bail!("isolation_requirements_not_hostile_guest_safe")
    }
    let coverage = isolation
        .get("enforcement_coverage_refs_and_hashes")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("isolation_enforcement_coverage_missing"))?;
    if coverage.is_empty() {
        bail!("isolation_enforcement_coverage_missing")
    }
    for binding in coverage {
        let evidence = object_value(
            all,
            required_str(binding, "ref")?,
            "isolation_enforcement_evidence_missing",
        )?;
        ensure_eq(
            &content_hash(evidence)?,
            required_str(binding, "hash")?,
            "isolation_enforcement_evidence_hash",
        )?;
        ensure_value_str(evidence, "protection_profile", "trusted_host_hostile_guest")?;
        ensure_value_str(evidence, "network_posture", "no_nic")?;
        ensure_value_str(
            evidence,
            "final_invoker_audience",
            "hypervisor-final-invoker",
        )?;
        if evidence
            .get("direct_protected_effect_invocations")
            .and_then(Value::as_u64)
            != Some(0)
            || evidence.get("final_invoker_calls").and_then(Value::as_u64) != Some(1)
            || evidence.get("guest_uid").and_then(Value::as_u64) != Some(0)
            || evidence.get("output_quarantined").and_then(Value::as_bool) != Some(true)
            || evidence.get("capability_replay").and_then(Value::as_str) != Some("refused")
            || evidence.get("monitor_terminal").and_then(Value::as_bool) != Some(true)
        {
            bail!("isolation_boundary_not_demonstrated")
        }
        if let (Some(source_ref), Some(source_hash)) = (
            evidence
                .get("source_consumption_ref")
                .and_then(Value::as_str),
            evidence
                .get("source_consumption_hash")
                .and_then(Value::as_str),
        ) {
            let source = object_value_bound(
                all,
                source_ref,
                source_hash,
                "isolation_consumption_source_missing",
            )?;
            if source
                .pointer("/receipts/consumption_receipt/final_invoker_calls")
                .and_then(Value::as_u64)
                != Some(1)
                || source
                    .pointer("/receipts/consumption_receipt/status")
                    .and_then(Value::as_str)
                    != Some("consumed")
            {
                bail!("isolation_consumption_source_invalid")
            }
        }
    }

    if required_str(cert, "brokered_secret_use_posture")? != "opaque_handle_final_invoker" {
        bail!("brokered_secret_posture_invalid")
    }
    for binding in cert
        .get("secret_use_evidence")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("secret_use_evidence_missing"))?
    {
        let evidence = object_value(
            all,
            required_str(binding, "ref")?,
            "secret_use_evidence_object_missing",
        )?;
        let seeded_probe = evidence
            .get("seeded_canary_count")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0);
        let enumerated_boundary_probe = evidence.get("probe_profile").and_then(Value::as_str)
            == Some("enumerated_host_material_channels")
            && evidence
                .get("tested_channel_count")
                .and_then(Value::as_u64)
                .is_some_and(|count| count >= 14)
            && evidence.get("network_device_count").and_then(Value::as_u64) == Some(0)
            && evidence.get("host_mount_count").and_then(Value::as_u64) == Some(0)
            && evidence
                .get("host_control_socket_count")
                .and_then(Value::as_u64)
                == Some(0);
        if enumerated_boundary_probe {
            let source = object_value_bound(
                all,
                required_str(evidence, "source_probe_ref")?,
                required_str(evidence, "source_probe_hash")?,
                "secret_probe_source_missing",
            )?;
            let attempted = source
                .get("attempted_paths")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("secret_probe_paths_missing"))?;
            for required in [
                "raw_ip",
                "loopback",
                "ipv6",
                "metadata",
                "provider",
                "udp",
                "proxy",
                "tunnel",
                "dns_exfil",
                "package_fetch",
                "host_device",
                "host_socket",
                "inherited_fd",
                "environment",
            ] {
                if !attempted.iter().any(|item| item.as_str() == Some(required)) {
                    bail!("secret_probe_path_missing:{required}")
                }
            }
            if source.get("guest_uid") != evidence.get("guest_uid")
                || source.get("secret_findings") != evidence.get("secret_findings")
                || source
                    .get("direct_protected_provider_invocations")
                    .and_then(Value::as_u64)
                    != Some(0)
                || source.pointer("/enforcement_declaration/network_device_count")
                    != evidence.get("network_device_count")
                || source.pointer("/enforcement_declaration/host_mount_count")
                    != evidence.get("host_mount_count")
                || source.pointer("/enforcement_declaration/host_control_socket_count")
                    != evidence.get("host_control_socket_count")
            {
                bail!("secret_probe_projection_mismatch")
            }
        }
        if evidence.get("guest_uid").and_then(Value::as_u64) != Some(0)
            || (!seeded_probe && !enumerated_boundary_probe)
            || evidence.get("secret_findings").and_then(Value::as_u64) != Some(0)
            || evidence
                .get("provider_credential_observed")
                .and_then(Value::as_bool)
                != Some(false)
            || evidence
                .get("recovery_material_observed")
                .and_then(Value::as_bool)
                != Some(false)
            || evidence
                .get("broker_separate_from_guest")
                .and_then(Value::as_bool)
                != Some(true)
        {
            bail!("worker_secret_non_possession_not_demonstrated")
        }
    }

    validate_authority_and_trajectory(
        cert,
        all,
        request_ref,
        request_hash,
        provider_ref,
        provider_address,
        image_digest,
    )?;

    for binding in cert
        .get("terminal_acceptance_prerequisites")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("terminal_acceptance_prerequisites_missing"))?
    {
        let prerequisite = object_value(
            all,
            required_str(binding, "ref")?,
            "terminal_prerequisite_missing",
        )?;
        ensure_value_str(prerequisite, "campaign_id", campaign_id)?;
        if prerequisite.get("terminal").and_then(Value::as_bool) != Some(true)
            || prerequisite
                .get("cleanup_verified")
                .and_then(Value::as_bool)
                != Some(true)
            || prerequisite.get("result_verified").and_then(Value::as_bool) != Some(true)
        {
            bail!("terminal_prerequisite_unsatisfied")
        }
    }

    if result.campaign_id != campaign_id {
        bail!("campaign_result_binding_mismatch")
    }
    Ok(())
}

fn validate_authority_and_trajectory(
    cert: &Value,
    all: &BTreeMap<String, (BundleObject, Value)>,
    request_ref: &str,
    request_hash: &str,
    provider_ref: &str,
    provider_address: &str,
    image_digest: &str,
) -> Result<()> {
    let authority = cert
        .get("authority_draw")
        .ok_or_else(|| anyhow!("authority_draw_missing"))?;
    let envelope_ref = required_str(authority, "standing_envelope_ref")?;
    let envelope = object_value(all, envelope_ref, "standing_envelope_missing")?;
    ensure_value_str(envelope, "approval_mode", "standing_envelope")?;
    ensure_value_str(
        envelope,
        "authority_scope",
        "scope:hypervisor.live-route.hypervisor-provider-op",
    )?;
    ensure_value_str(
        envelope,
        "recovery_posture",
        "recovery_never_widens_or_resets_drawdown",
    )?;
    let facets = envelope
        .get("facet_template")
        .ok_or_else(|| anyhow!("standing_envelope_facets_missing"))?;
    let provider_selector = facets
        .get("provider_selector")
        .ok_or_else(|| anyhow!("standing_envelope_provider_selector_missing"))?;
    if facets.get("auto_topup").and_then(Value::as_bool) != Some(false)
        || facets.get("teardown_policy").and_then(Value::as_str) != Some("always_teardown_required")
        || !array_contains(facets, "image_digests", image_digest)
        || !array_contains(provider_selector, "provider_addresses", provider_address)
        || !array_contains(facets, "operations", "create")
    {
        bail!("standing_envelope_does_not_cover_request")
    }

    let draw_request = object_value(
        all,
        required_str(authority, "draw_request_ref")?,
        "authority_draw_request_missing",
    )?;
    ensure_value_str(draw_request, "standing_envelope_ref", envelope_ref)?;
    ensure_value_str(draw_request, "candidate_operation_ref", request_ref)?;
    ensure_value_str(draw_request, "candidate_operation_hash", request_hash)?;

    let draw_receipt = object_value(
        all,
        required_str(authority, "draw_receipt_ref")?,
        "authority_draw_receipt_missing",
    )?;
    ensure_value_str(draw_receipt, "standing_envelope_ref", envelope_ref)?;
    ensure_value_str(
        draw_receipt,
        "draw_request_ref",
        required_str(authority, "draw_request_ref")?,
    )?;
    ensure_value_str(draw_receipt, "candidate_operation_hash", request_hash)?;
    ensure_value_str(draw_receipt, "decision", "consumed")?;
    if draw_receipt
        .get("atomic_consumption")
        .and_then(Value::as_bool)
        != Some(true)
        || draw_receipt.get("revoked").and_then(Value::as_bool) != Some(false)
    {
        bail!("authority_draw_not_terminally_consumed")
    }

    let trajectory = cert
        .get("trajectory_binding")
        .ok_or_else(|| anyhow!("trajectory_binding_missing"))?;
    let before = object_value_bound(
        all,
        required_str(trajectory, "state_before_ref")?,
        required_str(trajectory, "state_before_hash")?,
        "trajectory_before_missing",
    )?;
    let decision = object_value(
        all,
        required_str(trajectory, "decision_ref")?,
        "trajectory_decision_missing",
    )?;
    let after = object_value_bound(
        all,
        required_str(trajectory, "state_after_ref")?,
        required_str(trajectory, "state_after_hash")?,
        "trajectory_after_missing",
    )?;
    ensure_value_str(decision, "decision", "admit")?;
    ensure_value_str(decision, "candidate_operation_ref", request_ref)?;
    ensure_value_str(decision, "candidate_operation_hash", request_hash)?;
    ensure_value_str(
        decision,
        "state_before_ref",
        required_str(trajectory, "state_before_ref")?,
    )?;
    ensure_value_str(
        decision,
        "state_before_hash",
        required_str(trajectory, "state_before_hash")?,
    )?;
    ensure_value_str(
        decision,
        "state_after_ref",
        required_str(trajectory, "state_after_ref")?,
    )?;
    ensure_value_str(
        decision,
        "state_after_hash",
        required_str(trajectory, "state_after_hash")?,
    )?;
    ensure_value_str(
        decision,
        "policy_ref",
        required_str(envelope, "trajectory_policy_ref")?,
    )?;
    ensure_value_str(
        decision,
        "policy_hash",
        required_str(envelope, "trajectory_policy_hash")?,
    )?;
    let constraints = decision
        .get("constraint_results")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("trajectory_constraints_missing"))?;
    if constraints.is_empty()
        || constraints
            .iter()
            .any(|item| item.get("satisfied").and_then(Value::as_bool) != Some(true))
    {
        bail!("trajectory_constraint_not_satisfied")
    }
    for field in [
        "owner_ref",
        "bounded_system_ref",
        "principal_ref",
        "revocation_epoch",
        "window_started_at",
        "window_ends_at",
    ] {
        if before.get(field) != after.get(field) {
            bail!("trajectory_identity_or_window_changed:{field}")
        }
    }
    let before_calls = before
        .get("admitted_call_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("trajectory_before_count_missing"))?;
    // This certificate binds exactly one governed operation and carries no chain
    // to a previously accepted decision, so the only predecessor state it can
    // anchor is the genesis one. A non-genesis predecessor is refused rather
    // than trusted: nothing in the bundle would independently establish it.
    if before_calls != 0
        || required_nonnegative_number(before, "cumulative_spend_usd")? != 0.0
        || required_nonnegative_number(before, "cumulative_deposit_usd")? != 0.0
        || !before
            .get("admitted_events")
            .and_then(Value::as_array)
            .is_some_and(|events| events.is_empty())
        || [
            "active_resource_refs",
            "provider_refs",
            "destination_refs",
            "data_class_refs",
        ]
        .iter()
        .any(|field| {
            !before
                .get(*field)
                .and_then(Value::as_array)
                .is_some_and(|entries| entries.is_empty())
        })
    {
        bail!("trajectory_predecessor_not_anchored")
    }
    if after.get("admitted_call_count").and_then(Value::as_u64) != Some(before_calls + 1)
        || required_nonnegative_number(after, "cumulative_spend_usd")?
            < required_nonnegative_number(before, "cumulative_spend_usd")?
        || required_nonnegative_number(after, "cumulative_deposit_usd")?
            < required_nonnegative_number(before, "cumulative_deposit_usd")?
        || !array_contains(after, "provider_refs", provider_ref)
        || !array_contains(after, "envelope_ancestor_refs", envelope_ref)
    {
        bail!("trajectory_state_transition_invalid")
    }
    Ok(())
}

fn object_value<'a>(
    all: &'a BTreeMap<String, (BundleObject, Value)>,
    reference: &str,
    code: &str,
) -> Result<&'a Value> {
    let mut candidates = all.values().filter(|(entry, _)| entry.r#ref == reference);
    let value = candidates
        .next()
        .map(|(_, value)| value)
        .ok_or_else(|| anyhow!(code.to_string()))?;
    if candidates.next().is_some() {
        bail!("ambiguous_object_ref:{reference}")
    }
    Ok(value)
}

fn object_value_bound<'a>(
    all: &'a BTreeMap<String, (BundleObject, Value)>,
    reference: &str,
    hash: &str,
    code: &str,
) -> Result<&'a Value> {
    all.get(&object_binding_key(reference, hash))
        .map(|(_, value)| value)
        .ok_or_else(|| anyhow!(code.to_string()))
}

fn required_nonnegative_number(value: &Value, key: &str) -> Result<f64> {
    value
        .get(key)
        .and_then(Value::as_f64)
        .filter(|number| *number >= 0.0 && number.is_finite())
        .ok_or_else(|| anyhow!("invalid_nonnegative_number:{key}"))
}

fn array_contains(value: &Value, key: &str, expected: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(expected)))
}

fn accept(
    bundle: &Path,
    policy: &Path,
    registry_path: &Path,
    row_output: &Path,
    receipt_path: &Path,
    expected_revision: u64,
    now: OffsetDateTime,
) -> Result<()> {
    let lock_path = registry_path.with_extension("lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    lock.lock_exclusive()?;
    let before_bytes = fs::read(registry_path).context("read registry")?;
    let before_value: Value = serde_json::from_slice(&before_bytes).context("registry json")?;
    let mut registry: Registry =
        serde_json::from_value(before_value.clone()).context("registry schema")?;
    ensure_eq(&registry.schema_version, REGISTRY_V1, "registry_schema")?;
    validate_hash_field(
        &before_value,
        "state_hash",
        &registry.state_hash,
        "registry_state_hash",
    )?;
    let before_hash = registry.state_hash.clone();

    let verified = match verify_bundle(bundle, policy, now) {
        Ok(v) => v,
        Err(error) => {
            write_receipt(
                rejected_receipt(bundle, policy, &before_hash, registry.revision, now, &error)?,
                receipt_path,
            )?;
            bail!(error)
        }
    };
    if registry.registry_ref != verified.policy.target_transition.target_registry_ref {
        write_receipt(
            rejection(
                &verified,
                &before_hash,
                registry.revision,
                now,
                "registry_ref_mismatch",
            ),
            receipt_path,
        )?;
        bail!("registry_ref_mismatch")
    }
    if registry.revision != expected_revision {
        write_receipt(
            rejection(
                &verified,
                &before_hash,
                registry.revision,
                now,
                "registry_revision_conflict",
            ),
            receipt_path,
        )?;
        bail!("registry_revision_conflict")
    }

    let row_ref = format!(
        "result-row://aft/{}",
        required_str(&verified.certificate, "campaign_id")?
    );
    if registry.entries.iter().any(|e| e.row_ref == row_ref) {
        write_receipt(
            rejection(
                &verified,
                &before_hash,
                registry.revision,
                now,
                "registry_duplicate_row",
            ),
            receipt_path,
        )?;
        bail!("registry_duplicate_row")
    }
    let mut row = MeasuredRow {
        schema_version: ROW_V1.into(),
        row_ref: row_ref.clone(),
        row_hash: zero_hash(),
        certificate_ref: verified.bundle.certificate_ref.clone(),
        certificate_hash: verified.bundle.certificate_hash.clone(),
        result_ref: required_str(&verified.certificate, "result_ref")?.into(),
        result_hash: required_str(&verified.certificate, "result_hash")?.into(),
        environment_hash: required_str(&verified.certificate, "environment_hash")?.into(),
        campaign_id: verified.result.campaign_id.clone(),
        source_commit: required_str(&verified.certificate, "benchmark_source_commit")?.into(),
        image_digest: required_str(&verified.certificate, "workload_image_digest")?.into(),
        provider_ref: verified.provider_ref.clone(),
        environment_class: required_str(&verified.certificate, "environment_class")?.into(),
        honesty_class: required_str(&verified.certificate, "honesty_class")?.into(),
        verdict: verified.result.verdict.clone(),
        accepted_at: format_time(now),
    };
    row.row_hash = hash_without(&serde_json::to_value(&row)?, "row_hash")?;
    write_json_atomic(row_output, &row)?;

    registry.previous_state_hash = Some(before_hash.clone());
    registry.revision += 1;
    registry.entries.push(RegistryEntry {
        row_ref: row_ref.clone(),
        row_hash: row.row_hash.clone(),
    });
    registry.state_hash = zero_hash();
    registry.state_hash = hash_without(&serde_json::to_value(&registry)?, "state_hash")?;
    write_json_atomic(registry_path, &registry)?;
    let receipt = accepted_receipt(
        &verified,
        &before_hash,
        &registry.state_hash,
        registry.revision,
        row_ref,
        now,
    );
    write_receipt(receipt, receipt_path)?;
    lock.unlock()?;
    println!(
        "accepted revision={} state={}",
        registry.revision, registry.state_hash
    );
    Ok(())
}

fn index_objects<'a>(
    bundle_dir: &Path,
    objects: impl Iterator<Item = &'a BundleObject>,
) -> Result<BTreeMap<String, (BundleObject, Value)>> {
    let canonical_dir = fs::canonicalize(bundle_dir)?;
    let mut out = BTreeMap::new();
    for entry in objects {
        validate_supported_schema(entry)?;
        validate_file_name(&entry.file)?;
        let key = object_binding_key(&entry.r#ref, &entry.hash);
        if out.contains_key(&key) {
            bail!("duplicate_object_binding")
        }
        let path = bundle_dir.join(&entry.file);
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_JSON_BYTES
        {
            bail!("unsafe_bundle_object")
        }
        let canonical = fs::canonicalize(&path)?;
        if canonical.parent() != Some(canonical_dir.as_path()) {
            bail!("bundle_path_escape")
        }
        let value = read_json(&path)?;
        if content_hash(&value)? != entry.hash {
            bail!("bundle_object_hash:{}", entry.r#ref)
        }
        out.insert(key, (entry.clone(), value));
    }
    Ok(out)
}

fn validate_supported_schema(entry: &BundleObject) -> Result<()> {
    const SUPPORTED: &[&str] = &[
        "schema://ioi/aft/campaign-variance/v1",
        "schema://ioi/aft/environment-manifest/v1",
        "schema://ioi/aft/u1-campaign-result/v1",
        "schema://ioi/components/hypervisor/auth-factor-receipt/v1",
        "schema://ioi/components/hypervisor/c8-certificate/v2",
        "schema://ioi/components/hypervisor/governed-effect-claim-manifest/v1",
        "schema://ioi/components/hypervisor/provider-readiness/v1",
        "schema://ioi/components/hypervisor/provider-operation/v1",
        "schema://ioi/components/hypervisor/provider-settlement/v1",
        "schema://ioi/components/hypervisor/result-retrieval-receipt/v1",
        "schema://ioi/components/hypervisor/terminal-acceptance-prerequisite/v1",
        "schema://ioi/components/hypervisor/u1-campaign-certificate/v1",
        "schema://ioi/components/hypervisor/worker-secret-non-possession/v1",
        "schema://ioi/components/hypervisor/workload-boundary-enforcement-evidence/v1",
        "schema://ioi/components/hypervisor/workload-effect-consumption/v1",
        "schema://ioi/components/hypervisor/workload-isolation-binding/v1",
        "schema://ioi/components/hypervisor/workload-isolation-requirements/v1",
        "schema://ioi/foundations/authority-trajectory-state/v1",
        "schema://ioi/foundations/canonical-json-preimage/v1",
        "schema://ioi/foundations/relying-party-acceptance-policy/v1",
        "schema://ioi/foundations/source-basis/v1",
        "schema://ioi/foundations/standing-authority-consumption/v1",
        "schema://ioi/foundations/standing-authority-draw-request/v1",
        "schema://ioi/foundations/standing-authority-envelope/v1",
        "schema://ioi/foundations/trajectory-admission-decision/v1",
        "schema://ioi/foundations/verifier-independence-profile/v1",
        "schema://ioi/hypervisor/workload-bound-effect-boundary-live-probe/v2",
        "schema://json-schema/draft-2020-12",
    ];
    if !SUPPORTED.contains(&entry.schema_ref.as_str()) {
        bail!("unsupported_bundle_schema:{}", entry.schema_ref)
    }
    Ok(())
}

fn object_binding_key(reference: &str, hash: &str) -> String {
    format!("{reference}\0{hash}")
}

fn certificate_bindings(cert: &Value) -> Result<Vec<RefHash>> {
    let mut out = vec![
        pair(
            cert,
            "predecessor_certificate_ref",
            "predecessor_certificate_hash",
        )?,
        pair(cert, "governed_request_ref", "governed_request_hash")?,
        pair(cert, "claim_manifest_ref", "claim_manifest_hash")?,
        pair(cert, "isolation_binding_ref", "isolation_binding_hash")?,
        pair(
            cert,
            "campaign_certificate_ref",
            "campaign_certificate_hash",
        )?,
        pair(cert, "result_contract_ref", "result_contract_hash")?,
        pair(cert, "result_ref", "result_hash")?,
        pair(
            cert,
            "result_retrieval_receipt_ref",
            "result_retrieval_receipt_hash",
        )?,
        pair(cert, "environment_ref", "environment_hash")?,
        pair(cert, "variance_evidence_ref", "variance_evidence_hash")?,
        pair(cert, "terminal_settlement_ref", "terminal_settlement_hash")?,
    ];
    for key in [
        "source_basis_refs",
        "workload_readiness_evidence",
        "secret_use_evidence",
        "terminal_acceptance_prerequisites",
    ] {
        let values = cert
            .get(key)
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("{key}_missing"))?;
        if values.is_empty() {
            bail!("{key}_empty")
        }
        for value in values {
            out.push(serde_json::from_value(value.clone()).with_context(|| key.to_string())?);
        }
    }
    for (obj, pairs) in [
        (
            "authority_draw",
            [
                ("standing_envelope_ref", "standing_envelope_hash"),
                ("draw_request_ref", "draw_request_hash"),
                ("draw_receipt_ref", "draw_receipt_hash"),
            ]
            .as_slice(),
        ),
        (
            "trajectory_binding",
            [
                ("state_before_ref", "state_before_hash"),
                ("decision_ref", "decision_hash"),
                ("state_after_ref", "state_after_hash"),
            ]
            .as_slice(),
        ),
    ] {
        let value = cert.get(obj).ok_or_else(|| anyhow!("{obj}_missing"))?;
        for (r, h) in pairs {
            out.push(pair(value, r, h)?);
        }
    }
    Ok(out)
}

fn derive_provider_ref(
    cert: &Value,
    all: &BTreeMap<String, (BundleObject, Value)>,
) -> Result<String> {
    let settlement = object_value(
        all,
        required_str(cert, "terminal_settlement_ref")?,
        "settlement_missing",
    )?;
    for key in ["provider_ref", "selected_provider_ref", "provider"] {
        if let Some(value) = settlement.get(key).and_then(Value::as_str) {
            return Ok(value.into());
        }
    }
    bail!("settlement_provider_ref_missing")
}

fn object_as<T: for<'de> Deserialize<'de>>(
    all: &BTreeMap<String, (BundleObject, Value)>,
    r: &str,
    label: &str,
) -> Result<T> {
    serde_json::from_value(object_value(all, r, &format!("{label}_missing"))?.clone())
        .with_context(|| label.to_string())
}

fn rejected_receipt(
    bundle_dir: &Path,
    policy_path: &Path,
    before: &str,
    revision: u64,
    now: OffsetDateTime,
    error: &anyhow::Error,
) -> Result<AcceptanceReceipt> {
    let bundle: PortableBundle =
        serde_json::from_value(read_json(&bundle_dir.join("bundle.json"))?)?;
    let policy: Policy = serde_json::from_value(read_json(policy_path)?)?;
    let mut receipt = AcceptanceReceipt {
        schema_version: RECEIPT_V1.into(),
        receipt_ref: format!("acceptance-receipt://aft/rejected-{}", now.unix_timestamp()),
        receipt_hash: zero_hash(),
        certificate_ref: bundle.certificate_ref,
        certificate_hash: bundle.certificate_hash,
        policy_ref: policy.policy_ref,
        policy_hash: policy.policy_hash,
        verifier_identity_ref: "verifier://ioi/aft-c8-verifier".into(),
        verifier_build_hash: executable_hash()?,
        trust_input_hashes: vec![content_hash(&read_json(policy_path)?)?],
        decision: "rejected".into(),
        failure_codes: vec![failure_code(error)],
        accepted_object_refs: vec![],
        accepted_revision: revision,
        mutation_applied: false,
        target_state_before_hash: before.into(),
        target_state_after_hash: before.into(),
        observed_at: format_time(now),
        valid_until: format_time(now + Duration::hours(1)),
    };
    receipt.receipt_hash = hash_without(&serde_json::to_value(&receipt)?, "receipt_hash")?;
    Ok(receipt)
}

fn rejection(
    v: &Verified,
    before: &str,
    revision: u64,
    now: OffsetDateTime,
    code: &str,
) -> AcceptanceReceipt {
    make_receipt(
        v,
        before,
        revision,
        now,
        ReceiptDecision {
            after: before.into(),
            accepted: vec![],
            mutated: false,
            decision: "rejected",
            failures: vec![code.into()],
        },
    )
}

fn accepted_receipt(
    v: &Verified,
    before: &str,
    after: &str,
    revision: u64,
    row_ref: String,
    now: OffsetDateTime,
) -> AcceptanceReceipt {
    make_receipt(
        v,
        before,
        revision,
        now,
        ReceiptDecision {
            after: after.into(),
            accepted: vec![row_ref],
            mutated: true,
            decision: "accepted",
            failures: vec![],
        },
    )
}

fn make_receipt(
    v: &Verified,
    before: &str,
    revision: u64,
    now: OffsetDateTime,
    outcome: ReceiptDecision,
) -> AcceptanceReceipt {
    let mut receipt = AcceptanceReceipt {
        schema_version: RECEIPT_V1.into(),
        receipt_ref: format!(
            "acceptance-receipt://aft/{}-{}",
            outcome.decision,
            now.unix_timestamp()
        ),
        receipt_hash: zero_hash(),
        certificate_ref: v.bundle.certificate_ref.clone(),
        certificate_hash: v.bundle.certificate_hash.clone(),
        policy_ref: v.policy.policy_ref.clone(),
        policy_hash: v.policy.policy_hash.clone(),
        verifier_identity_ref: v.profile.verifier_identity_ref.clone(),
        verifier_build_hash: v.profile.verifier_build_hash.clone(),
        trust_input_hashes: v.trust_hashes.clone(),
        decision: outcome.decision.into(),
        failure_codes: outcome.failures,
        accepted_object_refs: outcome.accepted,
        accepted_revision: revision,
        mutation_applied: outcome.mutated,
        target_state_before_hash: before.into(),
        target_state_after_hash: outcome.after,
        observed_at: format_time(now),
        valid_until: format_time(now + Duration::hours(1)),
    };
    receipt.receipt_hash = hash_without(
        &serde_json::to_value(&receipt).expect("serialize receipt"),
        "receipt_hash",
    )
    .expect("hash receipt");
    receipt
}

fn write_receipt(receipt: AcceptanceReceipt, path: &Path) -> Result<()> {
    write_json_atomic(path, &receipt)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("output_parent_missing"))?;
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("output_name_invalid"))?;
    let temp = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn read_json(path: &Path) -> Result<Value> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_JSON_BYTES {
        bail!("json_too_large")
    }
    serde_json::from_slice(&fs::read(path)?).context("invalid json")
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_jcs::to_vec(value)?)
}

fn hash_value(value: &Value) -> Result<String> {
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical(value)?))
    ))
}
fn content_hash(value: &Value) -> Result<String> {
    let schema = value
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if schema == "ioi.foundations.canonical-json-preimage.v1" {
        let canonical_json = required_str(value, "canonical_json")?;
        let _: Value = serde_json::from_str(canonical_json).context("canonical_json_invalid")?;
        return Ok(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(canonical_json.as_bytes()))
        ));
    }
    if schema == "ioi.foundations.standing-authority-envelope.v1" {
        let mut material = value.clone();
        let object = material
            .as_object_mut()
            .ok_or_else(|| anyhow!("hash_subject_not_object"))?;
        object.remove("body_hash");
        object.insert(
            "domain".into(),
            Value::String("ioi.standing-authority-envelope-jcs-sha256.v1".into()),
        );
        return hash_value(&material);
    }
    if schema == "ioi.foundations.trajectory-admission-decision.v1" {
        let mut material = value.clone();
        let object = material
            .as_object_mut()
            .ok_or_else(|| anyhow!("hash_subject_not_object"))?;
        object.remove("decision_hash");
        object.remove("decision_ref");
        return hash_value(&material);
    }
    let self_hash_field = match schema {
        C8_V3 => Some("certificate_hash"),
        BUNDLE_V1 => Some("bundle_hash"),
        POLICY_V1 => Some("policy_hash"),
        PROFILE_V1 => Some("profile_hash"),
        REGISTRY_V1 => Some("state_hash"),
        ROW_V1 => Some("row_hash"),
        RECEIPT_V1 => Some("receipt_hash"),
        "ioi.hypervisor.c7-c8-certificate.v2" => Some("certificate_hash"),
        "ioi.components.hypervisor.governed-effect-claim-manifest.v1" => Some("manifest_hash"),
        "ioi.components.hypervisor.workload-isolation-binding.v1" => Some("binding_hash"),
        "ioi.components.hypervisor.workload-isolation-requirements.v1" => Some("requirements_hash"),
        "ioi.foundations.authority-trajectory-state.v1" => Some("trajectory_state_hash"),
        "ioi.hypervisor.auth-factor-receipt.v1" => Some("receipt_hash"),
        _ => None,
    };
    match self_hash_field {
        Some(field) => hash_without(value, field),
        None => hash_value(value),
    }
}
fn hash_without(value: &Value, field: &str) -> Result<String> {
    let mut value = value.clone();
    value
        .as_object_mut()
        .ok_or_else(|| anyhow!("hash_subject_not_object"))?
        .remove(field);
    hash_value(&value)
}
fn validate_hash_field(value: &Value, field: &str, expected: &str, code: &str) -> Result<()> {
    ensure_eq(&hash_without(value, field)?, expected, code)
}
fn zero_hash() -> String {
    format!("sha256:{}", "0".repeat(64))
}
fn pair(value: &Value, r: &str, h: &str) -> Result<RefHash> {
    Ok(RefHash {
        r#ref: required_str(value, r)?.into(),
        hash: required_str(value, h)?.into(),
    })
}
fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing_{key}"))
}
fn ensure_value_str(value: &Value, key: &str, expected: &str) -> Result<()> {
    ensure_eq(required_str(value, key)?, expected, key)
}
fn ensure_eq(actual: &str, expected: &str, code: &str) -> Result<()> {
    if actual != expected {
        bail!("{code}")
    }
    Ok(())
}
fn parse_time(value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .context("invalid timestamp")
}
fn format_time(value: OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .expect("format timestamp")
}
fn executable_hash() -> Result<String> {
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(fs::read(std::env::current_exe()?)?))
    ))
}
fn validate_file_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 132
        || !name.ends_with(".json")
        || name.contains('/')
        || name.contains('\\')
        || name == ".json"
        || name.starts_with('.')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        bail!("unsafe_bundle_filename")
    }
    Ok(())
}
fn failure_code(error: &anyhow::Error) -> String {
    error
        .to_string()
        .split(':')
        .next()
        .unwrap_or("verification_failed")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn metric_summary(values: &[f64], threshold: f64) -> Value {
        let observed_median = median(values).unwrap();
        let min = values.iter().copied().fold(f64::INFINITY, f64::min);
        let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let mad = median(
            &values
                .iter()
                .map(|value| (value - observed_median).abs())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let variance = values
            .iter()
            .map(|value| (value - mean).powi(2))
            .sum::<f64>()
            / (values.len() - 1) as f64;
        let cv = variance.sqrt() / mean;
        let spread = (max - min) / observed_median;
        let bootstrap = exact_bootstrap_median_interval(values).unwrap();
        json!({
            "bootstrap_median_95": [bootstrap.0, bootstrap.1],
            "coefficient_of_variation": cv,
            "max": max,
            "median": observed_median,
            "median_absolute_deviation": mad,
            "min": min,
            "relative_spread": spread,
            "threshold": threshold,
            "values": values,
            "within_threshold": spread <= threshold,
        })
    }

    fn mixed_campaign_result() -> CampaignResult {
        let rows = [
            ("paper_guardian_majority_4v", "base_final"),
            ("paper_guardian_majority_7v", "base_final"),
            ("paper_asymptote_4v", "base_final"),
            ("paper_asymptote_4v", "canonical_ordering"),
            ("paper_asymptote_4v", "durable_collapse"),
            ("paper_asymptote_4v", "sealed_final"),
            ("paper_asymptote_7v", "base_final"),
            ("paper_asymptote_7v", "canonical_ordering"),
            ("paper_asymptote_7v", "durable_collapse"),
            ("paper_asymptote_7v", "sealed_final"),
        ];
        let metric_names = [
            "injection_tps",
            "sustained_tps",
            "commit_p50_ms",
            "commit_p95_ms",
            "commit_p99_ms",
            "commit_max_ms",
        ];
        let summaries = rows
            .iter()
            .enumerate()
            .map(|(index, (scenario, lane))| {
                let metrics = metric_names
                    .iter()
                    .map(|name| {
                        let values = if index == 0 && *name == "injection_tps" {
                            vec![80.0, 90.0, 100.0, 110.0, 120.0]
                        } else {
                            vec![98.0, 99.0, 100.0, 101.0, 102.0]
                        };
                        ((*name).to_string(), metric_summary(&values, 0.1))
                    })
                    .collect::<serde_json::Map<_, _>>();
                json!({
                    "scenario": scenario,
                    "lane": lane,
                    "within_threshold": index != 0,
                    "metrics": metrics,
                })
            })
            .collect();
        CampaignResult {
            schema_version: RESULT_V1.to_string(),
            campaign_id: "test-campaign".to_string(),
            measured_passes: 5,
            row_count_per_pass: 10,
            threshold_policy: json!({
                "injection_tps": 0.1,
                "sustained_tps": 0.1,
                "commit_p50_ms": 0.1,
                "commit_p95_ms": 0.1,
                "commit_p99_ms": 0.1,
                "commit_max_ms": 0.1,
            }),
            verdict: "variance_caveated".to_string(),
            all_rows_within_threshold: false,
            summaries,
            pass_artifacts: (1..=5).map(|index| format!("pass-{index}.json")).collect(),
        }
    }

    #[test]
    fn canonical_hash_ignores_object_insertion_order() {
        let a: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        assert_eq!(hash_value(&a).unwrap(), hash_value(&b).unwrap());
    }
    #[test]
    fn only_safe_flat_json_names_are_accepted() {
        assert!(validate_file_name("result-1.json").is_ok());
        assert!(validate_file_name("../result.json").is_err());
        assert!(validate_file_name("nested/result.json").is_err());
        assert!(validate_file_name("result").is_err());
    }
    #[test]
    fn self_hash_excludes_only_named_field() {
        let value: Value = serde_json::from_str(r#"{"hash":"sha256:00","x":1}"#).unwrap();
        assert_eq!(
            hash_without(&value, "hash").unwrap(),
            hash_value(&serde_json::json!({"x":1})).unwrap()
        );
    }

    #[test]
    fn variance_caveated_campaign_accepts_mixed_metric_verdicts() {
        assert!(validate_campaign_result(&mixed_campaign_result()).is_ok());
    }

    #[test]
    fn campaign_rejects_row_verdict_that_ignores_a_failed_metric() {
        let mut result = mixed_campaign_result();
        result.summaries[0]["within_threshold"] = Value::Bool(true);
        assert_eq!(
            validate_campaign_result(&result).unwrap_err().to_string(),
            "campaign_row_verdict_inconsistent"
        );
    }

    #[test]
    fn campaign_rejects_resealed_summary_not_derived_from_samples() {
        let mut result = mixed_campaign_result();
        result.summaries[0]["metrics"]["injection_tps"]["median"] = json!(99.0);
        assert_eq!(
            validate_campaign_result(&result).unwrap_err().to_string(),
            "campaign_metric_summary_inconsistent:injection_tps"
        );
    }

    #[test]
    fn versioned_objects_resolve_same_ref_by_hash() {
        let directory = tempfile::tempdir().unwrap();
        let before = json!({"schema_version": "test.state.v1", "revision": 0});
        let after = json!({"schema_version": "test.state.v1", "revision": 1});
        fs::write(
            directory.path().join("before.json"),
            serde_json::to_vec(&before).unwrap(),
        )
        .unwrap();
        fs::write(
            directory.path().join("after.json"),
            serde_json::to_vec(&after).unwrap(),
        )
        .unwrap();
        let reference = "trajectory-state://aft/test".to_string();
        let before_hash = content_hash(&before).unwrap();
        let after_hash = content_hash(&after).unwrap();
        let objects = vec![
            BundleObject {
                r#ref: reference.clone(),
                hash: before_hash.clone(),
                schema_ref: "schema://ioi/foundations/source-basis/v1".to_string(),
                file: "before.json".to_string(),
            },
            BundleObject {
                r#ref: reference.clone(),
                hash: after_hash.clone(),
                schema_ref: "schema://ioi/foundations/source-basis/v1".to_string(),
                file: "after.json".to_string(),
            },
        ];
        let index = index_objects(directory.path(), objects.iter()).unwrap();
        assert_eq!(index.len(), 2);
        assert_eq!(
            object_value_bound(&index, &reference, &before_hash, "missing").unwrap(),
            &before
        );
        assert_eq!(
            object_value_bound(&index, &reference, &after_hash, "missing").unwrap(),
            &after
        );
        assert!(object_value(&index, &reference, "missing")
            .unwrap_err()
            .to_string()
            .starts_with("ambiguous_object_ref"));
    }
}
