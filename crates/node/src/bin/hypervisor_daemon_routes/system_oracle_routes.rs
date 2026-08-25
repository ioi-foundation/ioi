//! Active-profile external evidence and ontology-assertion admission (INV-25).
//!
//! One request crosses two distinct exact-head decision chains. The first
//! records the qualified oracle/evidence determination; the second records the
//! domain's operational assertion admission. Neither receipt claims that the
//! external proposition is universally true or grants consequence authority.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use super::system_activation_routes::{
    canonical_system_key, classify, contains_sensitive_key, enumerate_family, jcs_hash,
    load_required_exact, persist_local, required_string, tail, validate_contract, verr,
};
use super::DaemonState;

pub(crate) const ORACLE_RECEIPT_DIR: &str = "autonomous-system-oracle-admission-receipts";
pub(crate) const ASSERTION_RECEIPT_DIR: &str =
    "autonomous-system-ontology-assertion-admission-receipts";
pub(crate) const ASSERTION_DIR: &str = "autonomous-system-ontology-assertions";

const ASSERTION_CONTRACT: &str = "schema://ioi/foundations/ontology-assertion/v1";
const ORACLE_RECEIPT_CONTRACT: &str =
    "schema://ioi/foundations/oracle-evidence-admission-receipt/v1";
const ASSERTION_RECEIPT_CONTRACT: &str =
    "schema://ioi/foundations/ontology-assertion-admission-receipt/v1";
const MAX_VALIDITY: Duration = Duration::minutes(15);

type VErr = (String, String);

static ORACLE_ADMISSION_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OracleDecision {
    Admitted,
    HeldUnknown,
    Rejected,
    Escalated,
}

impl OracleDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted_for_scope",
            Self::HeldUnknown => "held_unknown",
            Self::Rejected => "rejected",
            Self::Escalated => "escalated",
        }
    }

    fn assertion_status(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::HeldUnknown => "held_unknown",
            Self::Rejected => "rejected",
            Self::Escalated => "evidence_pending",
        }
    }
}

#[derive(Debug)]
struct EvaluatedAdmission {
    assertion: Value,
    assertion_commitment: String,
    profile: Value,
    profile_body_hash: String,
    evidence_root: String,
    dependency_root: String,
    decision: OracleDecision,
    effective_at: String,
    valid_until: Option<String>,
}

fn required(value: &Value, pointer: &str) -> Result<String, VErr> {
    required_string(value, pointer).map(str::to_owned)
}

fn strings(value: &Value, pointer: &str) -> Result<Vec<String>, VErr> {
    let items = value
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "system_oracle_request_invalid",
                format!("{pointer} must be an array"),
            )
        })?;
    let mut output = Vec::with_capacity(items.len());
    for item in items {
        let text = item
            .as_str()
            .filter(|text| !text.is_empty())
            .ok_or_else(|| {
                verr(
                    "system_oracle_request_invalid",
                    format!("{pointer} contains a non-string or empty value"),
                )
            })?;
        output.push(text.to_owned());
    }
    let unique: BTreeSet<&str> = output.iter().map(String::as_str).collect();
    if unique.len() != output.len() {
        return Err(verr(
            "system_oracle_request_invalid",
            format!("{pointer} contains duplicates"),
        ));
    }
    Ok(output)
}

fn exact_keys(value: &Value, expected: &[&str], label: &str) -> Result<(), VErr> {
    let object = value.as_object().ok_or_else(|| {
        verr(
            "system_oracle_request_invalid",
            format!("{label} must be an object"),
        )
    })?;
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    if actual != expected {
        return Err(verr(
            "system_oracle_request_invalid",
            format!("{label} has an open, missing, or server-owned field"),
        ));
    }
    Ok(())
}

fn nullable_string(value: &Value, pointer: &str) -> Result<Option<String>, VErr> {
    match value.pointer(pointer) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if !text.is_empty() => Ok(Some(text.clone())),
        _ => Err(verr(
            "system_oracle_request_invalid",
            format!("{pointer} must be null or a non-empty string"),
        )),
    }
}

fn parse_time(value: &str, label: &str) -> Result<OffsetDateTime, VErr> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|error| {
        verr(
            "system_oracle_request_invalid",
            format!("{label} is not canonical RFC3339 ({error})"),
        )
    })
}

fn contains_all(haystack: &[String], needles: &[String]) -> bool {
    needles.iter().all(|needle| haystack.contains(needle))
}

fn select_profile<'a>(
    policies: &'a super::system_policy_routes::ActiveSystemPolicies,
    reference: &str,
) -> Result<&'a Value, VErr> {
    let mut matches = policies.oracle_profiles.iter().filter(|profile| {
        profile
            .get("oracle_evidence_profile_id")
            .and_then(Value::as_str)
            == Some(reference)
    });
    let profile = matches.next().ok_or_else(|| {
        verr(
            "system_oracle_profile_not_found",
            "assertion does not select an active oracle/evidence profile",
        )
    })?;
    if matches.next().is_some() {
        return Err(verr(
            "system_policy_artifact_mismatch",
            "active oracle/evidence profile identity is ambiguous",
        ));
    }
    Ok(profile)
}

fn select_source_requirement<'a>(profile: &'a Value, evidence: &Value) -> Result<&'a Value, VErr> {
    let source_class = required(evidence, "/source_class")?;
    let source_ref = required(evidence, "/source_ref")?;
    let schema_ref = required(evidence, "/evidence_schema_ref")?;
    let signer_ref = required(evidence, "/signer_or_principal_ref")?;
    let independence = nullable_string(evidence, "/independence_group_ref")?;
    let requirements = profile
        .get("source_requirements")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "system_policy_artifact_invalid",
                "active oracle profile lacks source requirements",
            )
        })?;
    let mut matches = requirements.iter().filter(|requirement| {
        requirement.get("source_class").and_then(Value::as_str) == Some(source_class.as_str())
            && requirement
                .get("source_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter()
                        .any(|item| item.as_str() == Some(source_ref.as_str()))
                })
            && requirement
                .get("evidence_schema_ref")
                .and_then(Value::as_str)
                == Some(schema_ref.as_str())
            && requirement
                .get("signer_or_principal_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter()
                        .any(|item| item.as_str() == Some(signer_ref.as_str()))
                })
            && requirement
                .get("independence_group_ref")
                .and_then(Value::as_str)
                == independence.as_deref()
    });
    let selected = matches.next().ok_or_else(|| {
        verr(
            "system_oracle_source_refused",
            "evidence source, schema, signer, or independence group is outside the active profile",
        )
    })?;
    if matches.next().is_some() {
        return Err(verr(
            "system_policy_artifact_mismatch",
            "active oracle source requirement is ambiguous",
        ));
    }
    let missing_required = requirements.iter().any(|requirement| {
        requirement.get("required").and_then(Value::as_bool) == Some(true)
            && !std::ptr::eq(requirement, selected)
    });
    if missing_required {
        return Err(verr(
            "system_oracle_aggregation_unsupported",
            "this admission supplies one source but the active profile requires additional sources",
        ));
    }
    Ok(selected)
}

fn evaluate(
    policies: &super::system_policy_routes::ActiveSystemPolicies,
    principal_ref: &str,
    body: &Value,
    now: OffsetDateTime,
) -> Result<EvaluatedAdmission, VErr> {
    exact_keys(
        body,
        &[
            "assertion",
            "authority_refs",
            "evidence",
            "expected_oracle_admission_head_hash",
            "expected_oracle_admission_receipt_ref",
            "expected_assertion_head_hash",
            "expected_assertion_head_ref",
        ],
        "oracle admission request",
    )?;
    if contains_sensitive_key(body) {
        return Err(verr(
            "system_oracle_request_invalid",
            "oracle admission request contains secret-bearing material",
        ));
    }
    let assertion = body.get("assertion").cloned().ok_or_else(|| {
        verr(
            "system_oracle_request_invalid",
            "oracle admission request lacks assertion",
        )
    })?;
    validate_contract(
        ASSERTION_CONTRACT,
        &assertion,
        "proposed ontology assertion",
    )
    .map_err(|(_, message)| verr("system_oracle_request_invalid", message))?;
    if assertion.get("status").and_then(Value::as_str) != Some("proposed") {
        return Err(verr(
            "system_oracle_request_invalid",
            "caller assertion must be proposed and carry no admission receipts",
        ));
    }
    let profile_ref = required(&assertion, "/oracle_evidence_profile_ref")?;
    let profile = select_profile(policies, &profile_ref)?.clone();
    let fact_class = required(&assertion, "/fact_class_ref")?;
    let fact_classes = strings(&profile, "/fact_class_refs")?;
    if !fact_classes.contains(&fact_class) {
        return Err(verr(
            "system_oracle_fact_class_refused",
            "assertion fact class is outside the active oracle profile",
        ));
    }
    let evidence = body.get("evidence").ok_or_else(|| {
        verr(
            "system_oracle_request_invalid",
            "oracle admission request lacks evidence",
        )
    })?;
    exact_keys(
        evidence,
        &[
            "contradiction_and_challenge_refs",
            "evidence_bundle_refs",
            "evidence_dependency_graph_ref",
            "evidence_dependency_graph_root",
            "evidence_schema_ref",
            "freshness_and_uncertainty_assessment_ref",
            "independence_group_ref",
            "observed_at",
            "signer_or_principal_ref",
            "source_class",
            "source_independence_evidence_refs",
            "source_ref",
            "valid_until",
            "verification_receipt_refs",
            "verifier_path_refs",
        ],
        "oracle evidence",
    )?;
    let _source_requirement = select_source_requirement(&profile, evidence)?;
    let signer = required(evidence, "/signer_or_principal_ref")?;
    if signer != principal_ref {
        return Err(verr(
            "system_oracle_source_authority_required",
            "authenticated principal is not the source signer selected by the active profile",
        ));
    }
    if profile.pointer("/aggregation/rule").and_then(Value::as_str) != Some("single_source")
        || profile
            .pointer("/aggregation/minimum_sources")
            .and_then(Value::as_u64)
            != Some(1)
        || profile
            .pointer("/aggregation/minimum_independent_principals")
            .and_then(Value::as_u64)
            != Some(1)
    {
        return Err(verr(
            "system_oracle_aggregation_unsupported",
            "the current runtime admits only an exact single-source profile; it never downgrades threshold or adjudicated profiles",
        ));
    }
    let requested_authority = strings(body, "/authority_refs")?;
    let profile_authority = strings(&profile, "/admission/required_authority_refs")?;
    if requested_authority != profile_authority || !profile_authority.is_empty() {
        return Err(verr(
            "system_oracle_effect_authority_required",
            "nonempty oracle admission authority requires a separately resolved grant/lease path",
        ));
    }
    let applicability = required(&assertion, "/applicability_scope_ref")?;
    let allowed_applicability = strings(&profile, "/admission/permitted_applicability_scope_refs")?;
    if !allowed_applicability.contains(&applicability) {
        return Err(verr(
            "system_oracle_scope_refused",
            "assertion applicability scope is outside the active profile",
        ));
    }
    let consequences = strings(&assertion, "/permitted_consequence_scope_refs")?;
    let allowed_consequences = strings(&profile, "/admission/permitted_consequence_scope_refs")?;
    if consequences.is_empty() || !contains_all(&allowed_consequences, &consequences) {
        return Err(verr(
            "system_oracle_scope_refused",
            "assertion consequence scope is empty or wider than the active profile",
        ));
    }
    let verifier_paths = strings(evidence, "/verifier_path_refs")?;
    let required_paths = strings(&profile, "/admission/required_verifier_path_refs")?;
    if !contains_all(&verifier_paths, &required_paths) {
        return Err(verr(
            "system_oracle_verification_refused",
            "evidence does not bind every verifier path required by the active profile",
        ));
    }
    let verification_receipts = strings(evidence, "/verification_receipt_refs")?;
    if !required_paths.is_empty() && verification_receipts.is_empty() {
        return Err(verr(
            "system_oracle_verification_refused",
            "a required verifier path has no retained verification receipt",
        ));
    }
    let evidence_refs = strings(evidence, "/evidence_bundle_refs")?;
    if evidence_refs.is_empty()
        || strings(&assertion, "/supporting_evidence_refs")? != evidence_refs
    {
        return Err(verr(
            "system_oracle_evidence_refused",
            "assertion and oracle request must bind the same nonempty evidence set",
        ));
    }
    let source_ref = required(evidence, "/source_ref")?;
    if !strings(&assertion, "/source_and_observation_context_refs")?.contains(&source_ref) {
        return Err(verr(
            "system_oracle_evidence_refused",
            "assertion does not attribute the selected source",
        ));
    }
    if nullable_string(evidence, "/independence_group_ref")?.is_some()
        && strings(evidence, "/source_independence_evidence_refs")?.is_empty()
    {
        return Err(verr(
            "system_oracle_independence_refused",
            "declared source independence has no retained evidence",
        ));
    }
    let observed_text = required(evidence, "/observed_at")?;
    let valid_text = required(evidence, "/valid_until")?;
    let observed = parse_time(&observed_text, "observed_at")?;
    let valid = parse_time(&valid_text, "valid_until")?;
    if required(&assertion, "/transaction_time")? != observed_text {
        return Err(verr(
            "system_oracle_time_refused",
            "assertion transaction_time must equal the attributed observation time",
        ));
    }
    let contradictions = strings(evidence, "/contradiction_and_challenge_refs")?;
    if strings(&assertion, "/contradicting_assertion_refs")? != contradictions {
        return Err(verr(
            "system_oracle_contradiction_refused",
            "assertion and evaluator inputs disagree on contradiction refs",
        ));
    }
    let stale = observed > now + Duration::minutes(1)
        || valid <= now
        || valid <= observed
        || valid - observed > MAX_VALIDITY;
    let decision = if !contradictions.is_empty() {
        match profile
            .pointer("/contradiction/policy")
            .and_then(Value::as_str)
        {
            Some("fail_closed") => OracleDecision::Rejected,
            Some("hold_pending") => OracleDecision::HeldUnknown,
            Some("escalate") => OracleDecision::Escalated,
            _ => {
                return Err(verr(
                    "system_policy_artifact_invalid",
                    "active oracle contradiction policy is unsupported",
                ))
            }
        }
    } else if stale {
        match profile
            .get("missing_or_stale_evidence_mode")
            .and_then(Value::as_str)
        {
            Some("escalate") => OracleDecision::Escalated,
            Some("unknown" | "read_only" | "pause") => OracleDecision::HeldUnknown,
            _ => {
                return Err(verr(
                    "system_policy_artifact_invalid",
                    "active oracle stale-evidence mode is unsupported",
                ))
            }
        }
    } else {
        OracleDecision::Admitted
    };
    let assertion_commitment = jcs_hash(&json!({
        "domain":"ioi.ontology-assertion-commitment-jcs-sha256.v1",
        "assertion":assertion,
    }))?;
    let evidence_root = jcs_hash(&json!({
        "domain":"ioi.oracle-evidence-input-jcs-sha256.v1",
        "evidence":evidence,
    }))?;
    Ok(EvaluatedAdmission {
        assertion,
        assertion_commitment,
        profile_body_hash: jcs_hash(&profile)?,
        profile,
        evidence_root,
        dependency_root: required(evidence, "/evidence_dependency_graph_root")?,
        decision,
        effective_at: observed_text,
        valid_until: (decision == OracleDecision::Admitted).then_some(valid_text),
    })
}

fn exact_converged_records(
    data_dir: &str,
    family: &str,
    contract: &str,
) -> Result<Vec<(String, Value)>, VErr> {
    let records = enumerate_family(data_dir, family)?;
    for (record_tail, value) in &records {
        validate_contract(contract, value, family)?;
        super::substrate_store::admit_required(data_dir, family, record_tail, value).map_err(
            |error| {
                verr(
                    "system_oracle_admission_failed",
                    format!("required admission for '{family}/{record_tail}' failed ({error})"),
                )
            },
        )?;
        if load_required_exact(data_dir, family, record_tail)? != Some(value.clone()) {
            return Err(verr(
                "system_oracle_evidence_mismatch",
                format!("'{family}/{record_tail}' diverges across local and Agentgres truth"),
            ));
        }
    }
    Ok(records)
}

fn current_receipt(
    data_dir: &str,
    family: &str,
    contract: &str,
    assertion_ref: &str,
    predecessor_hash_pointer: &str,
    result_hash_pointer: &str,
) -> Result<Option<Value>, VErr> {
    let records: Vec<Value> = exact_converged_records(data_dir, family, contract)?
        .into_iter()
        .map(|(_, value)| value)
        .filter(|value| value.get("assertion_ref").and_then(Value::as_str) == Some(assertion_ref))
        .collect();
    let cited: BTreeSet<String> = records
        .iter()
        .filter_map(|value| {
            value
                .pointer(predecessor_hash_pointer)
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    let mut current: Vec<Value> = records
        .into_iter()
        .filter(|value| {
            value
                .pointer(result_hash_pointer)
                .and_then(Value::as_str)
                .is_some_and(|root| !cited.contains(root))
        })
        .collect();
    match current.len() {
        0 => Ok(None),
        1 => Ok(current.pop()),
        _ => Err(verr(
            "system_oracle_evidence_mismatch",
            format!("{family} has forked exact-head decisions for one assertion"),
        )),
    }
}

fn receipt_by_coords(
    data_dir: &str,
    family: &str,
    contract: &str,
    assertion_ref: &str,
    expected_ref: Option<&str>,
    expected_hash: Option<&str>,
    ref_pointer: &str,
    hash_pointer: &str,
) -> Result<Option<Value>, VErr> {
    match (expected_ref, expected_hash) {
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => {}
        _ => {
            return Err(verr(
                "system_oracle_request_invalid",
                "expected predecessor ref and hash must be both null or both present",
            ))
        }
    }
    let mut matches: Vec<Value> = exact_converged_records(data_dir, family, contract)?
        .into_iter()
        .map(|(_, value)| value)
        .filter(|value| {
            value.get("assertion_ref").and_then(Value::as_str) == Some(assertion_ref)
                && value.pointer(ref_pointer).and_then(Value::as_str) == expected_ref
                && value.pointer(hash_pointer).and_then(Value::as_str) == expected_hash
        })
        .collect();
    match matches.len() {
        1 => Ok(matches.pop()),
        0 => Err(verr(
            "system_oracle_admission_conflict",
            "expected predecessor does not resolve in the exact decision history",
        )),
        _ => Err(verr(
            "system_oracle_evidence_mismatch",
            "expected predecessor coordinates resolve ambiguously",
        )),
    }
}

fn expected_matches(
    current: Option<&Value>,
    expected_ref: Option<&str>,
    expected_hash: Option<&str>,
    ref_pointer: &str,
    hash_pointer: &str,
) -> bool {
    match current {
        None => expected_ref.is_none() && expected_hash.is_none(),
        Some(value) => {
            value.pointer(ref_pointer).and_then(Value::as_str) == expected_ref
                && value.pointer(hash_pointer).and_then(Value::as_str) == expected_hash
        }
    }
}

fn persist_exact(
    data_dir: &str,
    family: &str,
    record_tail: &str,
    value: &Value,
) -> Result<(), VErr> {
    persist_local(data_dir, family, record_tail, value)?;
    super::substrate_store::admit_required(data_dir, family, record_tail, value).map_err(
        |error| {
            verr(
                "system_oracle_admission_failed",
                format!("required admission for '{family}/{record_tail}' failed ({error})"),
            )
        },
    )?;
    if load_required_exact(data_dir, family, record_tail)? != Some(value.clone()) {
        return Err(verr(
            "system_oracle_evidence_mismatch",
            format!("'{family}/{record_tail}' did not converge byte-exact"),
        ));
    }
    Ok(())
}

fn build_oracle_receipt(
    system_id: &str,
    evaluated: &EvaluatedAdmission,
    evidence: &Value,
    authority_refs: &[String],
    predecessor: Option<&Value>,
) -> Result<Value, VErr> {
    let predecessor_ref = predecessor
        .and_then(|value| value.get("receipt_id"))
        .cloned()
        .unwrap_or(Value::Null);
    let predecessor_hash = predecessor
        .and_then(|value| value.get("resulting_admission_head_hash"))
        .cloned()
        .unwrap_or(Value::Null);
    let applicability = evaluated.assertion["applicability_scope_ref"].clone();
    let consequences = if evaluated.decision == OracleDecision::Admitted {
        evaluated.assertion["permitted_consequence_scope_refs"].clone()
    } else {
        json!([])
    };
    let head = jcs_hash(&json!({
        "domain":"ioi.oracle-evidence-admission-head-jcs-sha256.v1",
        "system_id":system_id,
        "assertion_commitment":evaluated.assertion_commitment,
        "profile_body_hash":evaluated.profile_body_hash,
        "evidence_root":evaluated.evidence_root,
        "decision":evaluated.decision.as_str(),
        "applicability_scope_ref":applicability,
        "permitted_consequence_scope_refs":consequences,
        "valid_until":evaluated.valid_until,
        "predecessor_head":predecessor_hash,
    }))?;
    let hex = &head[7..];
    let receipt = json!({
        "schema_version":"ioi.oracle-evidence-admission-receipt.v1",
        "receipt_id":format!("receipt://oracle-evidence-admission/{hex}"),
        "receipt_type":"oracle_evidence_admission",
        "system_id":system_id,
        "assertion_ref":evaluated.assertion["assertion_id"],
        "assertion_commitment":evaluated.assertion_commitment,
        "fact_class_ref":evaluated.assertion["fact_class_ref"],
        "oracle_evidence_profile_ref":evaluated.profile["oracle_evidence_profile_id"],
        "oracle_evidence_profile_version":evaluated.profile["version"],
        "oracle_evidence_profile_body_hash":evaluated.profile_body_hash,
        "evidence_bundle_refs":evidence["evidence_bundle_refs"],
        "evidence_root":evaluated.evidence_root,
        "evidence_dependency_graph_ref":evidence["evidence_dependency_graph_ref"],
        "evidence_dependency_graph_root":evaluated.dependency_root,
        "source_independence_evidence_refs":evidence["source_independence_evidence_refs"],
        "verifier_path_refs":evidence["verifier_path_refs"],
        "verification_receipt_refs":evidence["verification_receipt_refs"],
        "freshness_and_uncertainty_assessment_ref":evidence["freshness_and_uncertainty_assessment_ref"],
        "contradiction_and_challenge_refs":evidence["contradiction_and_challenge_refs"],
        "decision":evaluated.decision.as_str(),
        "applicability_scope_ref":applicability,
        "permitted_consequence_scope_refs":consequences,
        "effective_at":evaluated.effective_at,
        "valid_until":evaluated.valid_until,
        "policy_ref":evaluated.profile["admission"]["policy_ref"],
        "required_authority_refs":authority_refs,
        "expected_predecessor_admission_receipt_ref":predecessor_ref,
        "expected_predecessor_admission_head_hash":predecessor_hash,
        "resulting_admission_head_hash":head,
        "agentgres_operation_ref":format!("agentgres://operation/oracle-evidence-admission-{hex}"),
    });
    validate_contract(
        ORACLE_RECEIPT_CONTRACT,
        &receipt,
        "oracle admission receipt",
    )?;
    Ok(receipt)
}

fn build_assertion_receipt(
    system_id: &str,
    evaluated: &EvaluatedAdmission,
    oracle_receipt: &Value,
    authority_refs: &[String],
    predecessor: Option<&Value>,
) -> Result<Value, VErr> {
    let predecessor_ref = predecessor
        .and_then(|value| value.get("assertion_ref"))
        .cloned()
        .unwrap_or(Value::Null);
    let predecessor_hash = predecessor
        .and_then(|value| value.get("resulting_assertion_head_hash"))
        .cloned()
        .unwrap_or(Value::Null);
    let admitted = evaluated.decision == OracleDecision::Admitted;
    let consequences = if admitted {
        evaluated.assertion["permitted_consequence_scope_refs"].clone()
    } else {
        json!([])
    };
    let oracle_ref = admitted
        .then(|| oracle_receipt["receipt_id"].clone())
        .unwrap_or(Value::Null);
    let head = jcs_hash(&json!({
        "domain":"ioi.ontology-assertion-admission-head-jcs-sha256.v1",
        "system_id":system_id,
        "assertion_commitment":evaluated.assertion_commitment,
        "oracle_receipt_ref":oracle_ref,
        "decision":if admitted {"admitted"} else {"rejected"},
        "applicability_scope_ref":evaluated.assertion["applicability_scope_ref"],
        "permitted_consequence_scope_refs":consequences,
        "predecessor_head":predecessor_hash,
    }))?;
    let hex = &head[7..];
    let receipt = json!({
        "schema_version":"ioi.ontology-assertion-admission-receipt.v1",
        "receipt_id":format!("receipt://ontology-assertion-admission/{hex}"),
        "receipt_type":"ontology_assertion_admission",
        "system_id":system_id,
        "assertion_ref":evaluated.assertion["assertion_id"],
        "assertion_commitment":evaluated.assertion_commitment,
        "fact_class_ref":evaluated.assertion["fact_class_ref"],
        "oracle_evidence_profile_ref":evaluated.profile["oracle_evidence_profile_id"],
        "oracle_evidence_admission_receipt_ref":oracle_ref,
        "applicability_scope_ref":evaluated.assertion["applicability_scope_ref"],
        "permitted_consequence_scope_refs":consequences,
        "decision":if admitted {"admitted"} else {"rejected"},
        "expected_predecessor_assertion_head_ref":predecessor_ref,
        "expected_predecessor_assertion_head_hash":predecessor_hash,
        "resulting_assertion_head_hash":head,
        "policy_ref":evaluated.profile["admission"]["policy_ref"],
        "authority_refs":authority_refs,
        "agentgres_operation_ref":format!("agentgres://operation/ontology-assertion-admission-{hex}"),
    });
    validate_contract(
        ASSERTION_RECEIPT_CONTRACT,
        &receipt,
        "ontology assertion admission receipt",
    )?;
    Ok(receipt)
}

fn final_assertion(
    evaluated: &EvaluatedAdmission,
    oracle_receipt: &Value,
    assertion_receipt: &Value,
) -> Result<Value, VErr> {
    let mut assertion = evaluated.assertion.clone();
    assertion["oracle_evidence_admission_receipt_ref"] = oracle_receipt["receipt_id"].clone();
    assertion["ontology_assertion_admission_receipt_ref"] = assertion_receipt["receipt_id"].clone();
    assertion["status"] = json!(evaluated.decision.assertion_status());
    if evaluated.decision != OracleDecision::Admitted {
        assertion["permitted_consequence_scope_refs"] = json!([]);
    }
    validate_contract(
        ASSERTION_CONTRACT,
        &assertion,
        "admitted ontology assertion",
    )?;
    Ok(assertion)
}

fn commit_admission(
    data_dir: &str,
    system_id: &str,
    body: &Value,
    evaluated: &EvaluatedAdmission,
) -> Result<(Value, Value, Value, bool), VErr> {
    let assertion_ref = required(&evaluated.assertion, "/assertion_id")?;
    let authority_refs = strings(body, "/authority_refs")?;
    let evidence = &body["evidence"];
    let current_oracle = current_receipt(
        data_dir,
        ORACLE_RECEIPT_DIR,
        ORACLE_RECEIPT_CONTRACT,
        &assertion_ref,
        "/expected_predecessor_admission_head_hash",
        "/resulting_admission_head_hash",
    )?;
    let expected_oracle_ref = nullable_string(body, "/expected_oracle_admission_receipt_ref")?;
    let expected_oracle_hash = nullable_string(body, "/expected_oracle_admission_head_hash")?;
    let oracle_predecessor = receipt_by_coords(
        data_dir,
        ORACLE_RECEIPT_DIR,
        ORACLE_RECEIPT_CONTRACT,
        &assertion_ref,
        expected_oracle_ref.as_deref(),
        expected_oracle_hash.as_deref(),
        "/receipt_id",
        "/resulting_admission_head_hash",
    )?;
    let proposed_oracle = build_oracle_receipt(
        system_id,
        evaluated,
        evidence,
        &authority_refs,
        oracle_predecessor.as_ref(),
    )?;
    let oracle_replay = current_oracle
        .as_ref()
        .is_some_and(|current| *current == proposed_oracle);
    if !oracle_replay
        && !expected_matches(
            current_oracle.as_ref(),
            expected_oracle_ref.as_deref(),
            expected_oracle_hash.as_deref(),
            "/receipt_id",
            "/resulting_admission_head_hash",
        )
    {
        return Err(verr(
            "system_oracle_admission_conflict",
            "oracle decision expected predecessor is stale or forked",
        ));
    }
    let oracle_receipt = if oracle_replay {
        current_oracle.unwrap()
    } else {
        let head = required(&proposed_oracle, "/resulting_admission_head_hash")?;
        persist_exact(
            data_dir,
            ORACLE_RECEIPT_DIR,
            &tail("asoea_", &head)?,
            &proposed_oracle,
        )?;
        proposed_oracle
    };

    let current_assertion = current_receipt(
        data_dir,
        ASSERTION_RECEIPT_DIR,
        ASSERTION_RECEIPT_CONTRACT,
        &assertion_ref,
        "/expected_predecessor_assertion_head_hash",
        "/resulting_assertion_head_hash",
    )?;
    let expected_assertion_ref = nullable_string(body, "/expected_assertion_head_ref")?;
    let expected_assertion_hash = nullable_string(body, "/expected_assertion_head_hash")?;
    let assertion_predecessor = receipt_by_coords(
        data_dir,
        ASSERTION_RECEIPT_DIR,
        ASSERTION_RECEIPT_CONTRACT,
        &assertion_ref,
        expected_assertion_ref.as_deref(),
        expected_assertion_hash.as_deref(),
        "/assertion_ref",
        "/resulting_assertion_head_hash",
    )?;
    let proposed_assertion = build_assertion_receipt(
        system_id,
        evaluated,
        &oracle_receipt,
        &authority_refs,
        assertion_predecessor.as_ref(),
    )?;
    let assertion_replay = current_assertion
        .as_ref()
        .is_some_and(|current| *current == proposed_assertion);
    if !assertion_replay
        && !expected_matches(
            current_assertion.as_ref(),
            expected_assertion_ref.as_deref(),
            expected_assertion_hash.as_deref(),
            "/assertion_ref",
            "/resulting_assertion_head_hash",
        )
    {
        return Err(verr(
            "system_oracle_assertion_conflict",
            "domain assertion expected predecessor is stale or forked",
        ));
    }
    let assertion_receipt = if assertion_replay {
        current_assertion.unwrap()
    } else {
        let head = required(&proposed_assertion, "/resulting_assertion_head_hash")?;
        persist_exact(
            data_dir,
            ASSERTION_RECEIPT_DIR,
            &tail("asoaa_", &head)?,
            &proposed_assertion,
        )?;
        proposed_assertion
    };
    let assertion = final_assertion(evaluated, &oracle_receipt, &assertion_receipt)?;
    let projection_root = jcs_hash(&json!({
        "domain":"ioi.ontology-assertion-projection-jcs-sha256.v1",
        "assertion":assertion,
    }))?;
    let assertion_tail = tail("asoa_", &projection_root)?;
    let already = load_required_exact(data_dir, ASSERTION_DIR, &assertion_tail)?;
    match already {
        Some(existing) if existing == assertion => {}
        Some(_) => {
            return Err(verr(
                "system_oracle_evidence_mismatch",
                "assertion projection is substituted at its admitted head",
            ))
        }
        None => persist_exact(data_dir, ASSERTION_DIR, &assertion_tail, &assertion)?,
    }
    Ok((
        assertion,
        oracle_receipt,
        assertion_receipt,
        oracle_replay && assertion_replay,
    ))
}

/// POST /v1/hypervisor/autonomous-systems/:id/oracle-evidence/admissions
pub(crate) async fn handle_admission(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_oracle_source_key_invalid",
            "id must be 'asg_' plus 64 lowercase hexadecimal characters",
        ));
    }
    let identity = match super::substrate_store::resolve_request_identity(&state.data_dir, &headers)
    {
        Ok(identity) => identity,
        Err(refusal) => {
            let status = match refusal {
                super::substrate_store::RequestScopeRefusal::AuthenticationRequired => {
                    StatusCode::UNAUTHORIZED
                }
                super::substrate_store::RequestScopeRefusal::SubstrateUnavailable(_) => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
                _ => StatusCode::FORBIDDEN,
            };
            return (
                status,
                Json(
                    json!({"error":{"code":refusal.code(),"message":refusal.message(),"runtimeTruthSource":"daemon-runtime"}}),
                ),
            );
        }
    };
    let _guard = ORACLE_ADMISSION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let policies =
        match super::system_policy_routes::load_active_system_policies(&state.data_dir, &key) {
            Ok(policies) => policies,
            Err(error) => return classify(error),
        };
    let evaluated = match evaluate(
        &policies,
        &identity.principal_ref,
        &body,
        OffsetDateTime::now_utc(),
    ) {
        Ok(evaluated) => evaluated,
        Err(error) => return classify(error),
    };
    match commit_admission(&state.data_dir, &policies.system_id, &body, &evaluated) {
        Ok((assertion, oracle_receipt, assertion_receipt, replayed)) => (
            if replayed {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            Json(json!({
                "ok":true,
                "replayed":replayed,
                "decision":oracle_receipt["decision"],
                "assertion":assertion,
                "oracle_evidence_admission_receipt":oracle_receipt,
                "ontology_assertion_admission_receipt":assertion_receipt,
                "runtimeTruthSource":"daemon-runtime"
            })),
        ),
        Err(error) => classify(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(path: &str) -> Value {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        serde_json::from_slice(&std::fs::read(root.join(path)).unwrap()).unwrap()
    }

    fn policies() -> super::super::system_policy_routes::ActiveSystemPolicies {
        let mut profile = fixture(
            "docs/architecture/_meta/schemas/fixtures/oracle-evidence-profile-v1/positive-fail-closed.json",
        );
        profile["source_requirements"][0]["signer_or_principal_refs"] = json!(["user://source"]);
        super::super::system_policy_routes::ActiveSystemPolicies {
            system_id: "system://acme/system-alpha".into(),
            constitution: json!({}),
            ordering_profile: json!({}),
            oracle_profiles: vec![profile],
            lifecycle_profile: json!({}),
            active_profile_set: json!({}),
        }
    }

    fn request(now: OffsetDateTime) -> Value {
        let mut assertion = fixture(
            "docs/architecture/_meta/schemas/fixtures/ontology-assertion-v1/positive-proposed.json",
        );
        let observed = now.format(&Rfc3339).unwrap();
        let valid = (now + Duration::minutes(5)).format(&Rfc3339).unwrap();
        assertion["transaction_time"] = json!(observed);
        assertion["valid_time"] = json!({"starts_at":observed,"ends_at":valid});
        assertion["source_and_observation_context_refs"] = json!(["source://acme/public-records"]);
        assertion["supporting_evidence_refs"] = json!(["evidence://acme/public-records/1"]);
        json!({
            "assertion":assertion,
            "evidence":{
                "source_class":"official_record",
                "source_ref":"source://acme/public-records",
                "evidence_schema_ref":"schema://acme/evidence/public-record/v1",
                "signer_or_principal_ref":"user://source",
                "independence_group_ref":"independence-group://acme/public-records",
                "evidence_bundle_refs":["evidence://acme/public-records/1"],
                "evidence_dependency_graph_ref":"evidence://acme/public-records/dependencies/1",
                "evidence_dependency_graph_root":format!("sha256:{}", "d".repeat(64)),
                "source_independence_evidence_refs":["evidence://acme/public-records/independence/1"],
                "verifier_path_refs":["verifier-path://acme/public-record"],
                "verification_receipt_refs":["receipt://verification/acme/public-record/1"],
                "freshness_and_uncertainty_assessment_ref":"evidence://acme/public-records/freshness/1",
                "contradiction_and_challenge_refs":[],
                "observed_at":observed,
                "valid_until":valid
            },
            "authority_refs":[],
            "expected_oracle_admission_receipt_ref":null,
            "expected_oracle_admission_head_hash":null,
            "expected_assertion_head_ref":null,
            "expected_assertion_head_hash":null
        })
    }

    #[test]
    fn active_single_source_profile_admits_only_its_exact_scopes() {
        let now = OffsetDateTime::now_utc();
        let evaluated = evaluate(&policies(), "user://source", &request(now), now).unwrap();
        assert_eq!(evaluated.decision, OracleDecision::Admitted);
        let mut widened = request(now);
        widened["assertion"]["permitted_consequence_scope_refs"] = json!(["scope:workflow.write"]);
        assert_eq!(
            evaluate(&policies(), "user://source", &widened, now)
                .unwrap_err()
                .0,
            "system_oracle_scope_refused"
        );
    }

    #[test]
    fn contradiction_fails_closed_and_carries_no_consequence() {
        let now = OffsetDateTime::now_utc();
        let mut body = request(now);
        body["assertion"]["contradicting_assertion_refs"] =
            json!(["ontology-assertion://acme/conflict/1"]);
        body["evidence"]["contradiction_and_challenge_refs"] =
            json!(["ontology-assertion://acme/conflict/1"]);
        let evaluated = evaluate(&policies(), "user://source", &body, now).unwrap();
        assert_eq!(evaluated.decision, OracleDecision::Rejected);
        let oracle = build_oracle_receipt(
            "system://acme/system-alpha",
            &evaluated,
            &body["evidence"],
            &[],
            None,
        )
        .unwrap();
        assert_eq!(oracle["permitted_consequence_scope_refs"], json!([]));
        assert!(oracle["valid_until"].is_null());
    }

    #[test]
    fn stale_evidence_is_unknown_never_admitted() {
        let now = OffsetDateTime::now_utc();
        let mut body = request(now);
        let stale = now - Duration::hours(1);
        let expired = now - Duration::minutes(30);
        body["assertion"]["transaction_time"] = json!(stale.format(&Rfc3339).unwrap());
        body["evidence"]["observed_at"] = body["assertion"]["transaction_time"].clone();
        body["evidence"]["valid_until"] = json!(expired.format(&Rfc3339).unwrap());
        let evaluated = evaluate(&policies(), "user://source", &body, now).unwrap();
        assert_eq!(evaluated.decision, OracleDecision::HeldUnknown);
    }

    #[test]
    fn authenticated_source_cannot_substitute_the_profile_signer() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            evaluate(&policies(), "user://attacker", &request(now), now)
                .unwrap_err()
                .0,
            "system_oracle_source_authority_required"
        );
    }

    #[test]
    fn exact_replay_preserves_heads_while_a_successor_advances_them() {
        let now = OffsetDateTime::now_utc();
        let body = request(now);
        let evaluated = evaluate(&policies(), "user://source", &body, now).unwrap();
        let first_oracle = build_oracle_receipt(
            "system://acme/system-alpha",
            &evaluated,
            &body["evidence"],
            &[],
            None,
        )
        .unwrap();
        let replayed_oracle = build_oracle_receipt(
            "system://acme/system-alpha",
            &evaluated,
            &body["evidence"],
            &[],
            None,
        )
        .unwrap();
        assert_eq!(first_oracle, replayed_oracle);

        let first_assertion = build_assertion_receipt(
            "system://acme/system-alpha",
            &evaluated,
            &first_oracle,
            &[],
            None,
        )
        .unwrap();
        let replayed_assertion = build_assertion_receipt(
            "system://acme/system-alpha",
            &evaluated,
            &first_oracle,
            &[],
            None,
        )
        .unwrap();
        assert_eq!(first_assertion, replayed_assertion);

        let successor_oracle = build_oracle_receipt(
            "system://acme/system-alpha",
            &evaluated,
            &body["evidence"],
            &[],
            Some(&first_oracle),
        )
        .unwrap();
        assert_ne!(
            first_oracle["resulting_admission_head_hash"],
            successor_oracle["resulting_admission_head_hash"]
        );
        assert_eq!(
            successor_oracle["expected_predecessor_admission_receipt_ref"],
            first_oracle["receipt_id"]
        );

        let successor_assertion = build_assertion_receipt(
            "system://acme/system-alpha",
            &evaluated,
            &successor_oracle,
            &[],
            Some(&first_assertion),
        )
        .unwrap();
        assert_ne!(
            first_assertion["resulting_assertion_head_hash"],
            successor_assertion["resulting_assertion_head_hash"]
        );
        assert_eq!(
            successor_assertion["expected_predecessor_assertion_head_ref"],
            first_assertion["assertion_ref"]
        );
    }

    #[test]
    fn agentgres_keys_bind_exact_receipt_and_assertion_content() {
        let now = OffsetDateTime::now_utc();
        let body = request(now);
        let evaluated = evaluate(&policies(), "user://source", &body, now).unwrap();
        let oracle = build_oracle_receipt(
            "system://acme/system-alpha",
            &evaluated,
            &body["evidence"],
            &[],
            None,
        )
        .unwrap();
        let oracle_tail = tail(
            "asoea_",
            oracle["resulting_admission_head_hash"].as_str().unwrap(),
        )
        .unwrap();
        super::super::substrate_store::validate_required_identity_for_test(
            ORACLE_RECEIPT_DIR,
            &oracle_tail,
            &oracle,
        )
        .unwrap();
        let mut substituted_oracle = oracle.clone();
        substituted_oracle["evidence_root"] = json!(format!("sha256:{}", "0".repeat(64)));
        assert!(
            super::super::substrate_store::validate_required_identity_for_test(
                ORACLE_RECEIPT_DIR,
                &oracle_tail,
                &substituted_oracle,
            )
            .is_err()
        );

        let assertion_receipt =
            build_assertion_receipt("system://acme/system-alpha", &evaluated, &oracle, &[], None)
                .unwrap();
        let assertion = final_assertion(&evaluated, &oracle, &assertion_receipt).unwrap();
        let projection_root = jcs_hash(&json!({
            "domain":"ioi.ontology-assertion-projection-jcs-sha256.v1",
            "assertion":assertion,
        }))
        .unwrap();
        let assertion_tail = tail("asoa_", &projection_root).unwrap();
        super::super::substrate_store::validate_required_identity_for_test(
            ASSERTION_DIR,
            &assertion_tail,
            &assertion,
        )
        .unwrap();
        let mut substituted_assertion = assertion;
        substituted_assertion["confidence"]["value"] = json!(0.01);
        assert!(
            super::super::substrate_store::validate_required_identity_for_test(
                ASSERTION_DIR,
                &assertion_tail,
                &substituted_assertion,
            )
            .is_err()
        );
    }

    #[test]
    fn durable_admission_replays_once_and_reconstructs_the_successor_heads() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        let now = OffsetDateTime::now_utc();
        let first_body = request(now);
        let first_evaluated = evaluate(&policies(), "user://source", &first_body, now).unwrap();
        let (first_assertion, first_oracle, first_assertion_receipt, replayed) = commit_admission(
            data_dir,
            "system://acme/system-alpha",
            &first_body,
            &first_evaluated,
        )
        .unwrap();
        assert!(!replayed);

        let replay = commit_admission(
            data_dir,
            "system://acme/system-alpha",
            &first_body,
            &first_evaluated,
        )
        .unwrap();
        assert!(replay.3);
        assert_eq!(replay.0, first_assertion);
        assert_eq!(replay.1, first_oracle);
        assert_eq!(replay.2, first_assertion_receipt);
        assert_eq!(
            enumerate_family(data_dir, ORACLE_RECEIPT_DIR)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            enumerate_family(data_dir, ASSERTION_RECEIPT_DIR)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(enumerate_family(data_dir, ASSERTION_DIR).unwrap().len(), 1);

        let mut successor_body = request(now);
        successor_body["assertion"]["contradicting_assertion_refs"] =
            json!(["ontology-assertion://acme/conflict/1"]);
        successor_body["evidence"]["contradiction_and_challenge_refs"] =
            json!(["ontology-assertion://acme/conflict/1"]);
        successor_body["expected_oracle_admission_receipt_ref"] =
            first_oracle["receipt_id"].clone();
        successor_body["expected_oracle_admission_head_hash"] =
            first_oracle["resulting_admission_head_hash"].clone();
        successor_body["expected_assertion_head_ref"] =
            first_assertion_receipt["assertion_ref"].clone();
        successor_body["expected_assertion_head_hash"] =
            first_assertion_receipt["resulting_assertion_head_hash"].clone();
        let successor_evaluated =
            evaluate(&policies(), "user://source", &successor_body, now).unwrap();
        let (successor_assertion, successor_oracle, successor_assertion_receipt, replayed) =
            commit_admission(
                data_dir,
                "system://acme/system-alpha",
                &successor_body,
                &successor_evaluated,
            )
            .unwrap();
        assert!(!replayed);
        assert_eq!(successor_assertion["status"], "rejected");
        assert_eq!(
            successor_assertion["permitted_consequence_scope_refs"],
            json!([])
        );

        // Reloading from the durable families is the restart reconstruction path.
        let reconstructed_oracle = current_receipt(
            data_dir,
            ORACLE_RECEIPT_DIR,
            ORACLE_RECEIPT_CONTRACT,
            successor_assertion["assertion_id"].as_str().unwrap(),
            "/expected_predecessor_admission_head_hash",
            "/resulting_admission_head_hash",
        )
        .unwrap()
        .unwrap();
        let reconstructed_assertion = current_receipt(
            data_dir,
            ASSERTION_RECEIPT_DIR,
            ASSERTION_RECEIPT_CONTRACT,
            successor_assertion["assertion_id"].as_str().unwrap(),
            "/expected_predecessor_assertion_head_hash",
            "/resulting_assertion_head_hash",
        )
        .unwrap()
        .unwrap();
        assert_eq!(reconstructed_oracle, successor_oracle);
        assert_eq!(reconstructed_assertion, successor_assertion_receipt);
        assert_eq!(
            enumerate_family(data_dir, ORACLE_RECEIPT_DIR)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            enumerate_family(data_dir, ASSERTION_RECEIPT_DIR)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(enumerate_family(data_dir, ASSERTION_DIR).unwrap().len(), 2);

        // Drop the process-local writer and rebuild from its durable log.
        super::super::substrate_store::reset_handle_for_test();
        assert_eq!(
            current_receipt(
                data_dir,
                ORACLE_RECEIPT_DIR,
                ORACLE_RECEIPT_CONTRACT,
                successor_assertion["assertion_id"].as_str().unwrap(),
                "/expected_predecessor_admission_head_hash",
                "/resulting_admission_head_hash",
            )
            .unwrap()
            .unwrap(),
            successor_oracle
        );
        let stale = commit_admission(
            data_dir,
            "system://acme/system-alpha",
            &first_body,
            &first_evaluated,
        )
        .unwrap_err();
        assert_eq!(stale.0, "system_oracle_admission_conflict");
    }
}
