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
            .get(&binding.r#ref)
            .ok_or_else(|| anyhow!("bound_object_missing:{}", binding.r#ref))?;
        ensure_eq(&entry.hash, &binding.hash, "bound_object_hash")?;
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
        if claim.status != "demonstrated"
            && !policy.tolerated_nonclaim_ids.contains(&claim.claim_id)
        {
            bail!("untolerated_nonclaim:{}", claim.claim_id)
        }
    }

    let result_ref = required_str(&certificate, "result_ref")?;
    let result_entry = all
        .get(result_ref)
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
    if required_str(&certificate, "honesty_class")? == "attested_pinned_bare_metal"
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

    let profile_entry = all
        .get(&policy.verifier_profile_ref)
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
            .get(&root.r#ref)
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
    if result.verdict == "reproduced_within_threshold" && !result.all_rows_within_threshold {
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
        validate_file_name(&entry.file)?;
        if out.contains_key(&entry.r#ref) {
            bail!("duplicate_object_ref")
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
        ensure_eq(&content_hash(&value)?, &entry.hash, "bundle_object_hash")?;
        out.insert(entry.r#ref.clone(), (entry.clone(), value));
    }
    Ok(out)
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
    let settlement = all
        .get(required_str(cert, "terminal_settlement_ref")?)
        .ok_or_else(|| anyhow!("settlement_missing"))?;
    for key in ["provider_ref", "selected_provider_ref", "provider"] {
        if let Some(value) = settlement.1.get(key).and_then(Value::as_str) {
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
    serde_json::from_value(
        all.get(r)
            .ok_or_else(|| anyhow!("{label}_missing"))?
            .1
            .clone(),
    )
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
    let self_hash_field = match schema {
        C8_V3 => Some("certificate_hash"),
        BUNDLE_V1 => Some("bundle_hash"),
        POLICY_V1 => Some("policy_hash"),
        PROFILE_V1 => Some("profile_hash"),
        REGISTRY_V1 => Some("state_hash"),
        ROW_V1 => Some("row_hash"),
        RECEIPT_V1 => Some("receipt_hash"),
        "ioi.components.hypervisor.governed-effect-claim-manifest.v1" => Some("manifest_hash"),
        "ioi.components.hypervisor.workload-isolation-binding.v1" => Some("binding_hash"),
        "ioi.foundations.standing-authority-envelope.v1" => Some("body_hash"),
        "ioi.foundations.authority-trajectory-state.v1" => Some("trajectory_state_hash"),
        "ioi.foundations.trajectory-admission-decision.v1" => Some("decision_hash"),
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
}
