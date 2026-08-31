//! M10.3 — the compiled institutional learning boundary, as owner-scoped runtime.
//!
//! Four registered families become one integrated contract on the canonical Agentgres chain:
//! `LearningSourceRightsClaim` (the rights half), `InstitutionalLearningBoundaryProfile` (the
//! compiled most-restrictive intersection), `LearningEvidenceEligibility` (one bounded decision
//! against a bound profile) and `LearningEgressReceipt` (an evidence-bounded crossing, admitted or
//! refused). The route-rights half is NOT restated here: it is resolved through M07.2's read-only
//! owner seam, which remains the semantic owner of what a provider or intermediary may do.
//!
//! THE INTERSECTION IS A SUBTRACTION, NOT AN OPINION. `effective_permitted_uses` is never a field a
//! caller supplies. The compiler starts from the closed fifteen-use vocabulary, subtracts every
//! denial contributed by every resolved input, and what remains is the permission. A use survives
//! only if EVERY input permits it and NO input left it indeterminate. That is what makes
//! "most restrictive intersection" a shape rather than an adjective: there is no branch a later
//! edit can forget to take, because permission is the complement of the denial set.
//!
//! SILENT WIDENING IS UNREPRESENTABLE. A child profile inherits its parent's entire denial set. This
//! seam does not author `widening_releases` at all — it emits the list empty and RETAINS every
//! inherited denial, so the registered coverage invariant (parent's denials at compilation must be
//! covered exactly by what was retained plus what was explicitly released) can only close when
//! nothing was released. Widening therefore requires the system's governed upgrade path, exactly as
//! canon says, and is refused here by name rather than quietly permitted.
//!
//! WHAT THE ROUTE CONTRACT CONTRIBUTES, STATED PRECISELY. This build intersects route rights on
//! three axes and claims no more: currency (a contract that is not active and live makes every
//! route-gated use indeterminate), unresolved route rights (`unresolved_route_uses` deny the
//! learning uses they gate), and the destination/egress ceiling (`no_egress` denies export and
//! publish). It deliberately does NOT attempt a total mapping from the twelve route uses onto the
//! fifteen learning uses: the two vocabularies are not isomorphic, and inventing the missing rows
//! would be reinterpreting a contract this module does not own.
//!
//! NOTHING HERE GRANTS AUTHORITY. A compiled profile is a policy compilation, an eligibility is an
//! admission decision, and a receipt proves an observed boundary fact. None of them is a runtime, a
//! truth store, a legal instrument, or permission to cross a boundary. Each record carries those
//! non-claims in its own bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::model_route_rights_routes::bad;
use super::model_route_rights_routes::{
    authorized_stream, body_object, body_str, contract_owner_ref, contract_tenant_ref,
    family_query, family_token, finish_admission, head_assertion, is_sha256, parse_revision_ref,
    projection_cache_state, read_stream, ref_list, refuse, reject_authored, replay_for_key,
    require_exact_head, resolve_admitted_model_route_rights_contract, vocabulary_list,
    AdmittedRecord, FamilySpec, Reply, ResolvedModelRouteRights, StreamQuery,
};
use super::mutation_event_foundation::{admitted_stamp, require_write_caller, scope_refusal_reply};
use super::substrate_store::{
    authorize_request_resource_scope, bind_request_resource_scope, RequestIdentity,
};
use super::DaemonState;

/// The fifteen canonical learning uses, verbatim and in the order every registered contract that
/// carries this vocabulary declares them.
pub(crate) const LEARNING_USE_VOCABULARY: &[&str] = &[
    "operational_inference",
    "retain",
    "replay",
    "internal_evaluation",
    "internal_analytics",
    "memory_or_context_improvement",
    "dataset_generation",
    "fine_tune",
    "distill",
    "competing_model_training",
    "worker_or_package_improvement",
    "commercialize_derivative",
    "export",
    "publish",
    "cross_tenant_aggregate_learning",
];

/// The learning uses each ROUTE use gates, as this build reads the two vocabularies.
///
/// DECLARED AS A TABLE ON PURPOSE. The route vocabulary (twelve) and the learning vocabulary
/// (fifteen) are not isomorphic, so any intersection between them is a reading. Making that reading
/// an inspectable constant — rather than a chain of conditionals buried in the compiler — is what
/// lets a reviewer disagree with a specific row, and what lets a mutation flip one row and watch the
/// gate go red. Route uses with no learning-vocabulary consequence are absent rather than mapped to
/// something approximate.
const ROUTE_USE_GATES: &[(&str, &[&str])] = &[
    ("model_inference", &["operational_inference"]),
    (
        "model_or_worker_training",
        &["fine_tune", "distill", "worker_or_package_improvement"],
    ),
    ("demonstration_training", &["dataset_generation"]),
    ("publication", &["publish"]),
    ("downstream_use", &["export"]),
    ("oem_or_reseller_use", &["commercialize_derivative"]),
    ("commercial_use", &["commercialize_derivative"]),
];

/// The uses that require material to leave the boundary, so an egress ceiling bears on them.
const EGRESS_GATED_USES: &[&str] = &["export", "publish", "cross_tenant_aggregate_learning"];

// ============================================================================== family descriptors

static CLAIM: FamilySpec = FamilySpec {
    owner_namespace: "learning-source-rights-claims",
    resource_kind: "learning_source_rights_claim",
    admit_op: "event_stream.learning_source_rights_claim_revision_admitted",
    payload_schema: "ioi.hypervisor.learning-source-rights-claim-revision-admission.v1",
    contract_id: "schema://ioi/foundations/objects/learning-source-rights-claim/v1",
    schema_version: "ioi.learning-source-rights-claim.v1",
    record_key: "learning_source_rights_claim_record",
    code_prefix: "learning_source_rights_claim",
    commitment_domain: "ioi.learning-source-rights-claim-content-commitment-jcs-sha256.v1",
    material_fields: &[
        "schema_version",
        "source_rights_claim_id",
        "revision_ref",
        "owner_ref",
        "tenant_ref",
        "asserted_by_ref",
        "asserted_rights_holder_refs",
        "source_class",
        "subject_refs",
        "rights_basis_refs",
        "route_rights_contract_refs",
        "declared_use_vocabulary",
        "permitted_uses",
        "prohibited_uses",
        "declared_prohibited_uses",
        "unresolved_right_uses",
        "unresolved_rights_findings",
        "derivative_disposition",
        "beneficiary_scope_refs",
        "jurisdiction_refs",
        "residency_refs",
        "retention_policy_ref",
        "deletion_or_forget_policy_ref",
        "legal_or_audit_hold_state",
        "validity",
        "evidence_refs",
        "claim_commitment",
        "status",
        "admitted_at",
        "succession",
        "constants",
        "authority_nonclaim",
        "truth_nonclaim",
        "does_not_assert",
    ],
    identity_field: "revision_ref",
    ref_scheme: "learning-source-rights://",
    stamp_field: "admitted_at",
};

static PROFILE: FamilySpec = FamilySpec {
    owner_namespace: "institutional-learning-boundary-profiles",
    resource_kind: "institutional_learning_boundary_profile",
    admit_op: "event_stream.institutional_learning_boundary_profile_revision_admitted",
    payload_schema: "ioi.hypervisor.institutional-learning-boundary-profile-revision-admission.v1",
    contract_id: "schema://ioi/foundations/objects/institutional-learning-boundary-profile/v1",
    schema_version: "ioi.institutional-learning-boundary-profile.v1",
    record_key: "institutional_learning_boundary_profile_record",
    code_prefix: "institutional_learning_boundary_profile",
    commitment_domain:
        "ioi.institutional-learning-boundary-profile-content-commitment-jcs-sha256.v1",
    material_fields: &[
        "schema_version",
        "boundary_profile_id",
        "revision_ref",
        "owner_ref",
        "tenant_ref",
        "governance_owner_ref",
        "scope_level",
        "scope_owner_ref",
        "applies_to_refs",
        "system_binding",
        "protected_material_classes",
        "learning_source_rights_claim_revision_refs",
        "policy_bound_data_view_refs",
        "route_rights_contract_refs",
        "custody",
        "external_recipient_permissions",
        "cross_tenant_learning",
        "target_binding",
        "declared_use_vocabulary",
        "effective_permitted_uses",
        "effective_denied_uses",
        "parent_binding",
        "parent_denied_uses",
        "locally_added_denied_uses",
        "narrowing_decisions",
        "indeterminate_findings",
        "widening_releases",
        "snapshot_binding",
        "jurisdiction_refs",
        "residency_refs",
        "retention_policy_ref",
        "deletion_or_forget_policy_ref",
        "legal_or_audit_hold_policy_ref",
        "derivative_policy_ref",
        "export_policy_ref",
        "revocation_policy_ref",
        "declassification_policy_ref",
        "receipt_obligations",
        "compiled_policy_hash",
        "effective_from",
        "expires_at",
        "status",
        "admitted_at",
        "succession",
        "constants",
        "authority_nonclaim",
        "truth_nonclaim",
        "does_not_assert",
    ],
    identity_field: "revision_ref",
    ref_scheme: "learning-boundary://",
    stamp_field: "admitted_at",
};

static ELIGIBILITY: FamilySpec = FamilySpec {
    owner_namespace: "learning-evidence-eligibilities",
    resource_kind: "learning_evidence_eligibility",
    admit_op: "event_stream.learning_evidence_eligibility_revision_admitted",
    payload_schema: "ioi.hypervisor.learning-evidence-eligibility-revision-admission.v1",
    contract_id: "schema://ioi/foundations/objects/learning-evidence-eligibility/v1",
    schema_version: "ioi.learning-evidence-eligibility.v1",
    record_key: "learning_evidence_eligibility_record",
    code_prefix: "learning_evidence_eligibility",
    commitment_domain: "ioi.learning-evidence-eligibility-content-commitment-jcs-sha256.v1",
    material_fields: &[
        "schema_version",
        "eligibility_id",
        "revision_ref",
        "owner_ref",
        "tenant_ref",
        "governance_owner_ref",
        "eligibility_profile",
        "boundary_profile_revision_ref",
        "boundary_profile_content_hash",
        "effective_learning_policy_hash",
        "boundary_permitted_uses_at_decision",
        "boundary_permitted_use_count_at_decision",
        "learning_use",
        "learning_source_rights_claim_revision_refs",
        "subject_refs",
        "requester_ref",
        "intended_use",
        "learning_use_posture",
        "legacy_binding",
        "applicable_evaluation_epoch_refs",
        "target_binding",
        "owner_and_tenant_scope_refs",
        "contamination_posture",
        "policy_bound_data_view_refs",
        "data_recipe_revision_refs",
        "local_policy_refs",
        "consent_refs",
        "authority_requirement_posture",
        "authority_requirement_kinds",
        "wallet_authority_refs",
        "declassification_refs",
        "learning_egress_receipt_refs",
        "provider_trust_posture",
        "retention_policy_ref",
        "derivative_policy_ref",
        "lineage_root",
        "receipt_root",
        "exclusion_reason",
        "status",
        "admitted_by_ref",
        "admitted_at",
        "succession",
        "constants",
        "authority_nonclaim",
        "truth_nonclaim",
        "does_not_assert",
    ],
    identity_field: "revision_ref",
    ref_scheme: "eligibility://",
    stamp_field: "admitted_at",
};

static EGRESS: FamilySpec = FamilySpec {
    owner_namespace: "learning-egress-receipts",
    resource_kind: "learning_egress_receipt",
    admit_op: "event_stream.learning_egress_receipt_emitted",
    payload_schema: "ioi.hypervisor.learning-egress-receipt-emission.v1",
    contract_id: "schema://ioi/foundations/objects/learning-egress-receipt/v1",
    schema_version: "ioi.learning-egress-receipt.v1",
    record_key: "learning_egress_receipt_record",
    code_prefix: "learning_egress_receipt",
    commitment_domain: "ioi.learning-egress-receipt-content-commitment-jcs-sha256.v1",
    material_fields: &[
        "schema_version",
        "receipt_id",
        "receipt_ref",
        "receipt_type",
        "owner_ref",
        "tenant_ref",
        "source_scope_ref",
        "boundary_profile_revision_ref",
        "boundary_profile_content_hash",
        "effective_learning_policy_hash",
        "boundary_compilation_or_policy_decision_ref",
        "learning_evidence_eligibility_revision_refs",
        "learning_source_rights_claim_revision_refs",
        "material_classes",
        "material_class_count",
        "material_commitment",
        "policy_bound_projection_refs",
        "recipient_class",
        "recipient_ref",
        "purpose",
        "representation",
        "execution_privacy_posture_ref",
        "model_route_rights_revision_ref",
        "intended_customer_output_uses",
        "effective_customer_output_rights_hash",
        "applicable_terms_and_license_refs",
        "provider_use_of_customer_material",
        "retention_posture",
        "retention_policy_ref",
        "local_policy_and_consent_refs",
        "authority_refs",
        "declassification_approval_ref",
        "redaction_or_declassification_receipt_refs",
        "underlying_operation_receipt_refs",
        "revocation_impact_ref",
        "forward_links",
        "decision",
        "reason_codes",
        "transfer_status",
        "enforcement_evidence_binds_request_commitment",
        "network_or_gateway_evidence_refs",
        "state_operation_refs",
        "assurance_stage",
        "chain_position",
        "predecessor_receipt_ref",
        "predecessor_content_hash",
        "emitted_at",
        "constants",
        "authority_nonclaim",
        "truth_nonclaim",
        "does_not_assert",
    ],
    identity_field: "receipt_ref",
    ref_scheme: "receipt://",
    stamp_field: "emitted_at",
};

// ================================================================= LearningSourceRightsClaim (M10.3)

const CLAIM_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "source_rights_claim_id",
    "revision_ref",
    "tenant_ref",
    "declared_use_vocabulary",
    "permitted_uses",
    "prohibited_uses",
    "unresolved_right_uses",
    "admitted_at",
    "succession",
    "constants",
    "authority_nonclaim",
    "truth_nonclaim",
    "content_hash",
];

/// ONE resolved source-rights claim revision, as a caller entitled to it may see it.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedSourceRightsClaim {
    pub(crate) revision_ref: String,
    pub(crate) tenant_ref: String,
    pub(crate) record: Value,
    pub(crate) content_hash: String,
    pub(crate) index_state: &'static str,
}

impl ResolvedSourceRightsClaim {
    fn list(&self, key: &str) -> Vec<String> {
        self.record
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn prohibited_uses(&self) -> Vec<String> {
        self.list("prohibited_uses")
    }

    pub(crate) fn unresolved_right_uses(&self) -> Vec<String> {
        self.list("unresolved_right_uses")
    }

    /// A claim carries permissions only while it is `asserted` or `admitted`. The registered
    /// contract already empties `permitted_uses` in every other state, so this is the reason a
    /// reader can state rather than a second enforcement of the same rule.
    pub(crate) fn is_live(&self) -> bool {
        matches!(
            self.record.get("status").and_then(Value::as_str),
            Some("asserted") | Some("admitted")
        )
    }

    pub(crate) fn finding_resolution(&self, use_token: &str) -> Option<String> {
        self.record
            .get("unresolved_rights_findings")
            .and_then(Value::as_array)?
            .iter()
            .find(|finding| finding.get("use").and_then(Value::as_str) == Some(use_token))
            .and_then(|finding| finding.get("resolution").and_then(Value::as_str))
            .map(str::to_string)
    }

    pub(crate) fn expires_before(&self, at_ms: u64) -> bool {
        match self
            .record
            .pointer("/validity/valid_until")
            .and_then(Value::as_str)
        {
            None => false,
            Some(stamp) => {
                let until = agentgres::parse_rfc3339_ms(stamp);
                until != 0 && until < at_ms
            }
        }
    }
}

/// Resolve ONE exact source-rights claim revision under the CALLER'S OWN owner binding.
pub(crate) fn resolve_admitted_source_rights_claim(
    data_dir: &str,
    identity: &RequestIdentity,
    expected_owner_ref: Option<&str>,
    revision_ref: &str,
) -> Result<ResolvedSourceRightsClaim, Reply> {
    let Some((family, ordinal)) = parse_revision_ref(CLAIM.ref_scheme, revision_ref) else {
        return Err(refuse(
            &CLAIM.code("revision_ref_not_canonical"),
            "a source-rights binding names learning-source-rights://<family>/revision/<n>; a family head or mutable-latest reference is refused where a revision is required",
        ));
    };
    let resource = format!("{}{family}", CLAIM.ref_scheme);
    let scope = authorize_request_resource_scope(
        data_dir,
        identity,
        CLAIM.resource_kind,
        &resource,
        expected_owner_ref,
    )
    .map_err(scope_refusal_reply)?;
    let stream = read_stream(&CLAIM, data_dir, identity, &scope, &resource)?;
    let index_state = projection_cache_state(&resource, &stream);
    let wanted = format!("{resource}/revision/{ordinal}");
    let Some(entry) = stream
        .iter()
        .find(|entry| entry.record.get("revision_ref") == Some(&json!(wanted)))
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &CLAIM.code("revision_absent"),
            format!(
                "this source-rights family has no admitted revision {ordinal}; an absent revision is a typed absence, never the nearest one"
            ),
        ));
    };
    Ok(ResolvedSourceRightsClaim {
        revision_ref: wanted,
        tenant_ref: entry
            .record
            .get("tenant_ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        content_hash: entry
            .record
            .get("content_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        record: entry.record.clone(),
        index_state,
    })
}

/// The claim's fail-closed partition, DERIVED exactly as M07.2 derives the route partition.
fn derive_claim_partition(
    declared_prohibited: &[String],
    findings: &[Value],
) -> Result<(Vec<String>, Vec<String>, Vec<String>), Reply> {
    let mut unresolved: BTreeSet<String> = BTreeSet::new();
    for finding in findings {
        let Some(token) = finding.get("use").and_then(Value::as_str) else {
            return Err(refuse(
                &CLAIM.code("finding_not_canonical"),
                "every unresolved-rights finding names its use, its resolution and the subject it is about",
            ));
        };
        unresolved.insert(token.to_string());
    }
    if let Some(collision) = declared_prohibited
        .iter()
        .find(|token| unresolved.contains(*token))
    {
        return Err(refuse(
            &CLAIM.code("prohibition_declared_and_unresolved"),
            format!(
                "'{collision}' is recorded as both affirmatively prohibited and unresolved; a basis that forbids a use and an unanswered question about it are different facts and cannot be counted twice"
            ),
        ));
    }
    let prohibited: Vec<String> = LEARNING_USE_VOCABULARY
        .iter()
        .filter(|token| {
            declared_prohibited.iter().any(|held| held == *token) || unresolved.contains(**token)
        })
        .map(|token| (*token).to_string())
        .collect();
    let permitted: Vec<String> = LEARNING_USE_VOCABULARY
        .iter()
        .filter(|token| !prohibited.iter().any(|held| held == *token))
        .map(|token| (*token).to_string())
        .collect();
    let unresolved_ordered: Vec<String> = LEARNING_USE_VOCABULARY
        .iter()
        .filter(|token| unresolved.contains(**token))
        .map(|token| (*token).to_string())
        .collect();
    Ok((unresolved_ordered, prohibited, permitted))
}

pub(crate) async fn handle_source_rights_claim_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let spec = &CLAIM;
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        contract_owner_ref(&caller.owner_ref, &spec.code("owner_scheme_unsupported"))
    {
        return response;
    }
    if let Err(response) = reject_authored(&body, spec, CLAIM_SERVER_RESOLVED) {
        return response;
    }
    let family = body_str(&body, "family");
    if !family_token(&family) {
        return refuse(
            &spec.code("family_not_canonical"),
            "'family' is the lineage token this revision extends: [a-z0-9][a-z0-9._-]{0,127}",
        );
    }
    let resource = format!("{}{family}", spec.ref_scheme);
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        spec.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(spec, &st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    match replay_for_key(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        &stream,
        "learning_source_rights_claim",
    ) {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    let expected_head = match head_assertion(&body, spec.code_prefix) {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, spec.code_prefix) {
        return response;
    }

    let declared_prohibited = match vocabulary_list(
        &body,
        "declared_prohibited_uses",
        LEARNING_USE_VOCABULARY,
        spec,
    ) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let mut findings = match body.get("unresolved_rights_findings") {
        None => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => {
            return refuse(
                &spec.code("finding_not_canonical"),
                "'unresolved_rights_findings' is an array of {use, resolution, subject_ref}",
            )
        }
    };

    let status = {
        let raw = body_str(&body, "status");
        if raw.is_empty() {
            "admitted".to_string()
        } else {
            raw
        }
    };
    // A CLAIM THAT IS NOT LIVE PERMITS NOTHING, AND SAYS WHY. The registered contract empties the
    // permitted set for disputed, expired, superseded, revoked and rejected claims. Emptying it
    // silently would leave a record that cannot explain itself, so every use that would otherwise
    // have survived becomes a finding naming the state that removed it.
    if !matches!(status.as_str(), "asserted" | "admitted") {
        let resolution = match status.as_str() {
            "expired" => "expired",
            "revoked" => "revoked",
            "disputed" => "conflicting",
            _ => "unsupported",
        };
        let subject_ref = body
            .get("subject_refs")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(Value::as_str)
            .unwrap_or("subject://unnamed")
            .to_string();
        let already: BTreeSet<String> = findings
            .iter()
            .filter_map(|finding| finding.get("use").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        for token in LEARNING_USE_VOCABULARY {
            if already.contains(*token) || declared_prohibited.iter().any(|held| held == *token) {
                continue;
            }
            findings.push(json!({
                "use": token,
                "resolution": resolution,
                "subject_ref": subject_ref,
            }));
        }
    }

    let (unresolved, prohibited, permitted) =
        match derive_claim_partition(&declared_prohibited, &findings) {
            Ok(parts) => parts,
            Err(response) => return response,
        };

    let ordinal = stream.len() as u64 + 1;
    let revision_ref = format!("{resource}/revision/{ordinal}");
    let predecessor = stream.last();
    let succession = match predecessor {
        None => json!({
            "succession_reason": "genesis",
            "predecessor_revision_ref": Value::Null,
            "predecessor_content_hash": Value::Null,
            "supersedes_predecessor": false,
            "reinterprets_predecessor": false,
        }),
        Some(entry) => {
            let raw = body_str(&body, "succession_reason");
            json!({
                "succession_reason": if raw.is_empty() { "basis_change".to_string() } else { raw },
                "predecessor_revision_ref": entry.record.get("revision_ref").cloned().unwrap_or(Value::Null),
                "predecessor_content_hash": entry.record.get("content_hash").cloned().unwrap_or(Value::Null),
                "supersedes_predecessor": true,
                "reinterprets_predecessor": false,
            })
        }
    };

    let validity = match body_object(&body, "validity", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let asserted_rights_holder_refs = match ref_list(&body, "asserted_rights_holder_refs", 64, spec)
    {
        Ok(list) => list,
        Err(response) => return response,
    };
    let subject_refs = match ref_list(&body, "subject_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let rights_basis_refs = match ref_list(&body, "rights_basis_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let route_rights_contract_refs = match ref_list(&body, "route_rights_contract_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let evidence_refs = match ref_list(&body, "evidence_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let beneficiary_scope_refs = match ref_list(&body, "beneficiary_scope_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let jurisdiction_refs = match ref_list(&body, "jurisdiction_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let residency_refs = match ref_list(&body, "residency_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let does_not_assert = match ref_list(&body, "does_not_assert", 10, spec) {
        Ok(list) if !list.is_empty() => list,
        Ok(_) => vec![
            "authority".to_string(),
            "legal_title".to_string(),
            "ownership".to_string(),
            "semantic_truth".to_string(),
            "training_consent_by_creation".to_string(),
            "redaction_creates_permission".to_string(),
        ],
        Err(response) => return response,
    };

    // EVERY ROUTE-RIGHTS BINDING IS RESOLVED THROUGH M07.2'S OWNER SEAM. A claim that references a
    // route contract it cannot resolve under its own owner binding has named a location, not a
    // contract, and the reference would be uncheckable exactly when it matters.
    for route_ref in &route_rights_contract_refs {
        if let Err(response) = resolve_admitted_model_route_rights_contract(
            &st.data_dir,
            &caller.identity,
            Some(caller.owner_ref.as_str()),
            route_ref,
        ) {
            return response;
        }
    }

    let recorded_at_ms = agentgres::parse_rfc3339_ms(&body_str(&body, "effective_at"));
    let record = json!({
        "schema_version": spec.schema_version,
        "source_rights_claim_id": resource,
        "revision_ref": revision_ref,
        "owner_ref": caller.owner_ref,
        "tenant_ref": contract_tenant_ref(&caller.owner_ref),
        "asserted_by_ref": body_str(&body, "asserted_by_ref"),
        "asserted_rights_holder_refs": asserted_rights_holder_refs,
        "source_class": body_str(&body, "source_class"),
        "subject_refs": subject_refs,
        "rights_basis_refs": rights_basis_refs,
        "route_rights_contract_refs": route_rights_contract_refs,
        "declared_use_vocabulary": LEARNING_USE_VOCABULARY,
        "permitted_uses": permitted,
        "prohibited_uses": prohibited,
        "declared_prohibited_uses": declared_prohibited,
        "unresolved_right_uses": unresolved,
        "unresolved_rights_findings": findings,
        "derivative_disposition": body_str(&body, "derivative_disposition"),
        "beneficiary_scope_refs": beneficiary_scope_refs,
        "jurisdiction_refs": jurisdiction_refs,
        "residency_refs": residency_refs,
        "retention_policy_ref": body_str(&body, "retention_policy_ref"),
        "deletion_or_forget_policy_ref": body_str(&body, "deletion_or_forget_policy_ref"),
        "legal_or_audit_hold_state": body_str(&body, "legal_or_audit_hold_state"),
        "validity": validity,
        "evidence_refs": evidence_refs,
        "claim_commitment": body_str(&body, "claim_commitment"),
        "status": status,
        "admitted_at": admitted_stamp(recorded_at_ms),
        "succession": succession,
        "constants": {
            "lifecycle_id": "learning_source_rights_claim_lifecycle.v1",
            "learning_use_vocabulary_size": LEARNING_USE_VOCABULARY.len(),
            "nonclaim_authority_token": "authority",
            "nonclaim_legal_title_token": "legal_title",
        },
        "authority_nonclaim": "learning_source_rights_claim_grants_no_authority",
        "truth_nonclaim": "learning_source_rights_claim_is_an_asserted_posture_not_a_legal_finding",
        "does_not_assert": does_not_assert,
    });

    finish_admission(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        "learning_source_rights_claim",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        json!({ "claim_is_one_input_to_the_intersection_not_a_grant": true }),
    )
}

pub(crate) async fn handle_source_rights_claim_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    family_query(
        &CLAIM,
        "learning_source_rights_claim_refs",
        st,
        &headers,
        query,
    )
}

// ================================================ InstitutionalLearningBoundaryProfile — the compiler

const PROFILE_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "boundary_profile_id",
    "revision_ref",
    "tenant_ref",
    "declared_use_vocabulary",
    "effective_permitted_uses",
    "effective_denied_uses",
    "parent_binding",
    "parent_denied_uses",
    "locally_added_denied_uses",
    "narrowing_decisions",
    "indeterminate_findings",
    "widening_releases",
    "compiled_policy_hash",
    "admitted_at",
    "succession",
    "constants",
    "authority_nonclaim",
    "truth_nonclaim",
    "content_hash",
];

/// The scope levels that snapshot a parent rather than governing future compilation.
const SNAPSHOT_SCOPE_LEVELS: &[&str] = &[
    "session",
    "goal_run",
    "model_invocation",
    "transformation",
    "foundry_job",
];

/// ONE resolved boundary profile revision, as a caller entitled to it may see it.
///
/// THE SEAM M05.8 BINDS. A `PolicyBoundDataView` revision names the effective learning-boundary
/// hash it compiled under; this is where that hash, and the permission set behind it, are resolved
/// from an owner rather than shape-checked by the consumer.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedBoundaryProfile {
    pub(crate) revision_ref: String,
    pub(crate) tenant_ref: String,
    pub(crate) record: Value,
    pub(crate) content_hash: String,
    pub(crate) compiled_policy_hash: String,
    pub(crate) index_state: &'static str,
}

impl ResolvedBoundaryProfile {
    fn list(&self, key: &str) -> Vec<String> {
        self.record
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn effective_permitted_uses(&self) -> Vec<String> {
        self.list("effective_permitted_uses")
    }

    pub(crate) fn effective_denied_uses(&self) -> Vec<String> {
        self.list("effective_denied_uses")
    }

    /// A profile permits nothing unless it is `active`. `draft`, `suspended`, `superseded` and
    /// `revoked` all empty the permitted set by the registered contract.
    pub(crate) fn is_active(&self) -> bool {
        self.record.get("status").and_then(Value::as_str) == Some("active")
    }
}

/// Resolve ONE exact boundary profile revision under the CALLER'S OWN owner binding.
pub(crate) fn resolve_admitted_boundary_profile(
    data_dir: &str,
    identity: &RequestIdentity,
    expected_owner_ref: Option<&str>,
    revision_ref: &str,
) -> Result<ResolvedBoundaryProfile, Reply> {
    let Some((family, ordinal)) = parse_revision_ref(PROFILE.ref_scheme, revision_ref) else {
        return Err(refuse(
            &PROFILE.code("revision_ref_not_canonical"),
            "a boundary binding names learning-boundary://<family>/revision/<n>; a family head or mutable-latest reference is refused where a revision is required",
        ));
    };
    let resource = format!("{}{family}", PROFILE.ref_scheme);
    let scope = authorize_request_resource_scope(
        data_dir,
        identity,
        PROFILE.resource_kind,
        &resource,
        expected_owner_ref,
    )
    .map_err(scope_refusal_reply)?;
    let stream = read_stream(&PROFILE, data_dir, identity, &scope, &resource)?;
    let index_state = projection_cache_state(&resource, &stream);
    let wanted = format!("{resource}/revision/{ordinal}");
    let Some(entry) = stream
        .iter()
        .find(|entry| entry.record.get("revision_ref") == Some(&json!(wanted)))
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &PROFILE.code("revision_absent"),
            format!(
                "this boundary family has no admitted revision {ordinal}; an absent revision is a typed absence, never the nearest one"
            ),
        ));
    };
    Ok(ResolvedBoundaryProfile {
        revision_ref: wanted,
        tenant_ref: entry
            .record
            .get("tenant_ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        content_hash: entry
            .record
            .get("content_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        compiled_policy_hash: entry
            .record
            .get("compiled_policy_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        record: entry.record.clone(),
        index_state,
    })
}

/// One determinate denial, attributed to the named input that produced it.
struct Denial {
    kind: &'static str,
    governing_ref: String,
    reason: &'static str,
    also: BTreeSet<&'static str>,
}

/// One indeterminacy. Canon is explicit that an indeterminate right DENIES the disputed use, so
/// this is a denial that names its unanswered question rather than a weaker kind of permission.
struct Indeterminacy {
    resolution: &'static str,
    disputed_input_ref: String,
}

/// The accumulator the compiler folds every resolved input into.
///
/// A use ends up in exactly one of the two maps. When an input leaves a use indeterminate AND
/// another input denies it outright, the indeterminacy wins the row: the honest record of "we could
/// not resolve this" is strictly more informative than a second statement that it was denied, and
/// the registered coverage invariant requires each locally added denial to be attributed exactly
/// once.
#[derive(Default)]
struct Intersection {
    denied: BTreeMap<String, Denial>,
    indeterminate: BTreeMap<String, Indeterminacy>,
}

impl Intersection {
    fn deny(
        &mut self,
        use_token: &str,
        kind: &'static str,
        governing_ref: &str,
        reason: &'static str,
    ) {
        if let Some(existing) = self.denied.get_mut(use_token) {
            existing.also.insert(kind);
            return;
        }
        self.denied.insert(
            use_token.to_string(),
            Denial {
                kind,
                governing_ref: governing_ref.to_string(),
                reason,
                also: BTreeSet::new(),
            },
        );
    }

    fn indeterminate(
        &mut self,
        use_token: &str,
        resolution: &'static str,
        disputed_input_ref: &str,
    ) {
        self.indeterminate
            .entry(use_token.to_string())
            .or_insert_with(|| Indeterminacy {
                resolution,
                disputed_input_ref: disputed_input_ref.to_string(),
            });
    }

    /// Every use this intersection denies, for any reason, in vocabulary order.
    fn all_denied(&self) -> Vec<String> {
        LEARNING_USE_VOCABULARY
            .iter()
            .filter(|token| {
                self.denied.contains_key(**token) || self.indeterminate.contains_key(**token)
            })
            .map(|token| (*token).to_string())
            .collect()
    }
}

/// The learning uses a given route use gates, per the declared table.
fn learning_uses_gated_by(route_use: &str) -> &'static [&'static str] {
    ROUTE_USE_GATES
        .iter()
        .find(|(name, _)| *name == route_use)
        .map(|(_, gated)| *gated)
        .unwrap_or(&[])
}

/// Fold ONE resolved route-rights contract into the intersection.
///
/// Three axes only, and the module doc states why: currency, unresolved route rights, and the
/// destination/egress ceiling. A contract that is not live contributes indeterminacy for every use
/// it gates rather than silence, because a lapsed contract is not an absence of opinion.
fn fold_route_contract(intersection: &mut Intersection, route: &ResolvedModelRouteRights) {
    if !route.is_live() {
        for (_, gated) in ROUTE_USE_GATES {
            for token in *gated {
                intersection.indeterminate(token, "revoked_input", &route.revision_ref);
            }
        }
        return;
    }
    for unresolved in route.unresolved_route_uses() {
        for token in learning_uses_gated_by(&unresolved) {
            intersection.deny(
                token,
                "route_rights_contract",
                &route.revision_ref,
                "route_right_unresolved",
            );
        }
    }
    // A route that permits a use is a CEILING INPUT, never a grant; a route that does not carry the
    // use denies it. Anything the route's own partition placed outside `permitted_route_uses` and
    // outside the unresolved lane is an affirmative prohibition in its terms.
    let permitted = route.permitted_route_uses();
    let unresolved = route.unresolved_route_uses();
    for (route_use, gated) in ROUTE_USE_GATES {
        if permitted.iter().any(|held| held == route_use)
            || unresolved.iter().any(|held| held == route_use)
        {
            continue;
        }
        for token in *gated {
            intersection.deny(
                token,
                "route_rights_contract",
                &route.revision_ref,
                "local_policy_prohibits",
            );
        }
    }
    if route.egress_ceiling() == "no_egress" {
        for token in EGRESS_GATED_USES {
            intersection.deny(
                token,
                "route_rights_contract",
                &route.revision_ref,
                "destination_class_prohibits",
            );
        }
    }
    if !route.competing_model_training_permitted() {
        intersection.deny(
            "competing_model_training",
            "route_rights_contract",
            &route.revision_ref,
            "local_policy_prohibits",
        );
    }
}

/// Fold ONE resolved source-rights claim into the intersection.
fn fold_source_claim(
    intersection: &mut Intersection,
    claim: &ResolvedSourceRightsClaim,
    at_ms: u64,
) {
    // EXPIRY AND LIVENESS ARE REVALIDATED AT COMPILATION, not trusted from when the claim was made.
    // A claim whose validity window has closed, or whose status left the live pair, denies
    // everything it could otherwise have permitted.
    if !claim.is_live() || claim.expires_before(at_ms) {
        let resolution = if claim.expires_before(at_ms) {
            "expired_input"
        } else {
            "revoked_input"
        };
        for token in LEARNING_USE_VOCABULARY {
            intersection.indeterminate(token, resolution, &claim.revision_ref);
        }
        return;
    }
    let unresolved = claim.unresolved_right_uses();
    for token in claim.prohibited_uses() {
        if unresolved.iter().any(|held| *held == token) {
            // The claim itself recorded this as unresolved rather than affirmatively prohibited, so
            // it enters the indeterminacy lane carrying the claim's own resolution word.
            let resolution = match claim.finding_resolution(&token).as_deref() {
                Some("expired") => "expired_input",
                Some("revoked") => "revoked_input",
                Some("conflicting") | Some("disputed") => "conflicting_inputs",
                Some("missing") => "missing_required_contract",
                Some("unsupported") => "unavailable_input",
                _ => "indeterminate_right",
            };
            intersection.indeterminate(&token, resolution, &claim.revision_ref);
            continue;
        }
        intersection.deny(
            &token,
            "source_rights_claim",
            &claim.revision_ref,
            "source_right_prohibits",
        );
    }
}

/// JCS-SHA256 over the compiled decision, under its own domain separator.
///
/// DISTINCT FROM `content_hash`. The content hash commits this record's bytes; the compiled policy
/// hash commits the DECISION — the inputs that were intersected and the permission that survived —
/// so a consumer that binds "the effective learning-boundary hash" is binding the policy it ran
/// under rather than the serialization it happened to read.
fn compiled_policy_hash(
    scope_level: &str,
    tenant_ref: &str,
    claim_refs: &[String],
    route_refs: &[String],
    view_refs: &[String],
    parent_ref: Option<&str>,
    permitted: &[String],
    denied: &[String],
) -> Result<String, String> {
    let material = json!({
        "domain": "ioi.institutional-learning-boundary-compiled-policy-jcs-sha256.v1",
        "scope_level": scope_level,
        "tenant_ref": tenant_ref,
        "learning_source_rights_claim_revision_refs": claim_refs,
        "route_rights_contract_refs": route_refs,
        "policy_bound_data_view_refs": view_refs,
        "parent_revision_ref": parent_ref.map(Value::from).unwrap_or(Value::Null),
        "effective_permitted_uses": permitted,
        "effective_denied_uses": denied,
    });
    serde_jcs::to_vec(&material)
        .map(|bytes| format!("sha256:{:x}", <sha2::Sha256 as sha2::Digest>::digest(bytes)))
        .map_err(|error| format!("the compiled policy could not be canonicalized: {error}"))
}

pub(crate) async fn handle_boundary_profile_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let spec = &PROFILE;
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        contract_owner_ref(&caller.owner_ref, &spec.code("owner_scheme_unsupported"))
    {
        return response;
    }
    if let Err(response) = reject_authored(&body, spec, PROFILE_SERVER_RESOLVED) {
        return response;
    }
    let family = body_str(&body, "family");
    if !family_token(&family) {
        return refuse(
            &spec.code("family_not_canonical"),
            "'family' is the lineage token this revision extends: [a-z0-9][a-z0-9._-]{0,127}",
        );
    }
    let resource = format!("{}{family}", spec.ref_scheme);
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        spec.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(spec, &st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    match replay_for_key(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        &stream,
        "institutional_learning_boundary_profile",
    ) {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    let expected_head = match head_assertion(&body, spec.code_prefix) {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, spec.code_prefix) {
        return response;
    }

    let tenant_ref = contract_tenant_ref(&caller.owner_ref);
    let scope_level = {
        let raw = body_str(&body, "scope_level");
        if raw.is_empty() {
            "organization".to_string()
        } else {
            raw
        }
    };
    let recorded_at_ms = agentgres::parse_rfc3339_ms(&body_str(&body, "effective_at"));

    let claim_refs = match ref_list(
        &body,
        "learning_source_rights_claim_revision_refs",
        64,
        spec,
    ) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let route_refs = match ref_list(&body, "route_rights_contract_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let view_refs = match ref_list(&body, "policy_bound_data_view_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };

    // ---------------------------------------------------------------- resolve every named input
    // EVERY input crosses its OWNER'S read-only seam under the caller's own owner binding. Nothing
    // here shape-checks a foreign record locally: a claim is resolved by the claim family, a route
    // contract by M07.2, and a parent by this family. A ref that cannot be resolved that way is
    // refused before any compilation happens, because an input that cannot be read is exactly the
    // "missing required contract" case canon says must deny the disputed use rather than be skipped.
    let parent_ref = body_str(&body, "parent_revision_ref");
    let parent = if parent_ref.is_empty() {
        None
    } else {
        match resolve_admitted_boundary_profile(
            &st.data_dir,
            &caller.identity,
            Some(caller.owner_ref.as_str()),
            &parent_ref,
        ) {
            Ok(resolved) => Some(resolved),
            Err(response) => return response,
        }
    };
    let mut claims = Vec::with_capacity(claim_refs.len());
    for claim_ref in &claim_refs {
        match resolve_admitted_source_rights_claim(
            &st.data_dir,
            &caller.identity,
            Some(caller.owner_ref.as_str()),
            claim_ref,
        ) {
            Ok(resolved) => claims.push(resolved),
            Err(response) => return response,
        }
    }
    let mut routes = Vec::with_capacity(route_refs.len());
    for route_ref in &route_refs {
        match resolve_admitted_model_route_rights_contract(
            &st.data_dir,
            &caller.identity,
            Some(caller.owner_ref.as_str()),
            route_ref,
        ) {
            Ok(resolved) => routes.push(resolved),
            Err(response) => return response,
        }
    }

    // CROSS-TENANT IS CHECKED ON THE RESOLVED BYTES, not on the request. Every input carries its own
    // tenancy and all of them must equal this profile's, so a compilation that quietly intersected
    // another tenant's rights record is refused by name rather than discovered later.
    for (kind, held) in claims
        .iter()
        .map(|claim| ("source rights claim", &claim.tenant_ref))
        .chain(
            routes
                .iter()
                .map(|route| ("route-rights contract", &route.tenant_ref)),
        )
        .chain(
            parent
                .iter()
                .map(|held| ("parent profile", &held.tenant_ref)),
        )
    {
        if held != &tenant_ref {
            return refuse(
                &spec.code("cross_tenant_input_refused"),
                format!(
                    "a {kind} bound by this compilation carries tenancy '{held}' while the profile compiles for '{tenant_ref}'; cross-tenant learning is denied by default and an input from another tenancy is refused, never intersected"
                ),
            );
        }
    }

    // -------------------------------------------------------------------------- fold the intersection
    let mut intersection = Intersection::default();
    for claim in &claims {
        fold_source_claim(&mut intersection, claim, recorded_at_ms);
    }
    for route in &routes {
        fold_route_contract(&mut intersection, route);
    }

    // Local policy narrows, and only narrows.
    let locally_declared = match vocabulary_list(
        &body,
        "locally_declared_denied_uses",
        LEARNING_USE_VOCABULARY,
        spec,
    ) {
        Ok(list) => list,
        Err(response) => return response,
    };
    for token in &locally_declared {
        intersection.deny(
            token,
            "declared_local_policy",
            &format!("{resource}#local-policy"),
            "local_policy_prohibits",
        );
    }

    let custody = match body_object(&body, "custody", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let cross_tenant = match body_object(&body, "cross_tenant_learning", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let external_recipient = match body_object(&body, "external_recipient_permissions", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };

    // CROSS-TENANT AGGREGATE LEARNING IS DENIED BY DEFAULT, and only a named cohort binding plus an
    // aggregation policy can even make it a question. Absent either, it is denied here rather than
    // left to whichever reader remembers the default.
    let cohort_refs = cross_tenant
        .get("permitted_cohort_refs")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    let aggregation_policy = cross_tenant
        .get("aggregation_policy_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    if cohort_refs == 0 || aggregation_policy.is_none() {
        intersection.deny(
            "cross_tenant_aggregate_learning",
            "declared_local_policy",
            &format!("{resource}#cross-tenant-default-deny"),
            "local_policy_prohibits",
        );
    }

    // A CUSTODY POSTURE THAT PERMITS NO PROVIDER TRUST DENIES THE USES THAT REQUIRE LEAVING. Custody
    // is an input to the intersection like any other; a posture that cannot carry material outward
    // narrows what may be done with it.
    let permits_egress = custody
        .get("permitted_provider_trust_postures")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false);
    if !permits_egress {
        for token in EGRESS_GATED_USES {
            intersection.deny(
                token,
                "custody_posture",
                &format!("{resource}#custody"),
                "custody_posture_unsatisfied",
            );
        }
    }

    // JURISDICTION, RESIDENCY AND RETENTION EACH NARROW. An unnamed retention policy is a retention
    // decision nobody made, and canon refuses to treat an indefinite default as one.
    let jurisdiction_refs = match ref_list(&body, "jurisdiction_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let residency_refs = match ref_list(&body, "residency_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let retention_policy_ref = body_str(&body, "retention_policy_ref");
    if retention_policy_ref.is_empty() {
        for token in ["retain", "replay"] {
            intersection.deny(
                token,
                "retention_or_export_policy",
                &format!("{resource}#retention"),
                "retention_or_hold_prohibits",
            );
        }
    }
    if jurisdiction_refs.is_empty() || residency_refs.is_empty() {
        for token in EGRESS_GATED_USES {
            intersection.deny(
                token,
                "jurisdiction_or_residency",
                &format!("{resource}#jurisdiction"),
                "jurisdiction_or_residency_prohibits",
            );
        }
    }

    // ------------------------------------------------------------------ inheritance, without widening
    let inherited: Vec<String> = parent
        .as_ref()
        .map(|held| held.effective_denied_uses())
        .unwrap_or_default();
    let inherited_set: BTreeSet<&String> = inherited.iter().collect();

    // A CHILD MAY NARROW AND MAY NOT WIDEN. This seam authors no `widening_releases` at all, so an
    // attempt to permit something the parent denied is refused BY NAME here rather than emitted as a
    // record whose coverage invariant would fail offline for a reason nobody could read.
    let locally_permitted = match vocabulary_list(
        &body,
        "locally_permitted_uses",
        LEARNING_USE_VOCABULARY,
        spec,
    ) {
        Ok(list) => list,
        Err(response) => return response,
    };
    if let Some(widened) = locally_permitted
        .iter()
        .find(|token| inherited_set.contains(*token))
    {
        return refuse(
            &spec.code("widening_requires_governed_upgrade"),
            format!(
                "'{widened}' is denied by the parent profile this compilation inherits; a child may narrow but never widen, and releasing an inherited denial requires the system's ordinary or protected upgrade path rather than a compilation that quietly drops it"
            ),
        );
    }

    let all_denied = intersection.all_denied();
    let effective_denied: Vec<String> = LEARNING_USE_VOCABULARY
        .iter()
        .filter(|token| {
            inherited_set.contains(&(*token).to_string())
                || all_denied.iter().any(|held| held == *token)
        })
        .map(|token| (*token).to_string())
        .collect();
    let effective_permitted: Vec<String> = LEARNING_USE_VOCABULARY
        .iter()
        .filter(|token| !effective_denied.iter().any(|held| held == *token))
        .map(|token| (*token).to_string())
        .collect();
    let locally_added: Vec<String> = effective_denied
        .iter()
        .filter(|token| !inherited_set.contains(*token))
        .cloned()
        .collect();

    // Every locally added denial is attributed exactly once, to a named input or to an
    // indeterminacy. The registered coverage invariant is what makes an unattributed denial
    // impossible; building the rows from the same set the denial list came from is what makes it
    // pass for the right reason.
    let mut narrowing_decisions = Vec::new();
    let mut indeterminate_findings = Vec::new();
    for token in &locally_added {
        if let Some(found) = intersection.indeterminate.get(token) {
            indeterminate_findings.push(json!({
                "denied_use": token,
                "resolution": found.resolution,
                "disputed_input_ref": found.disputed_input_ref,
            }));
            continue;
        }
        let Some(decision) = intersection.denied.get(token) else {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &spec.code("denial_unattributed"),
                format!("'{token}' was denied by this compilation without an attributable input"),
            );
        };
        narrowing_decisions.push(json!({
            "denied_use": token,
            "governing_source_kind": decision.kind,
            "governing_source_ref": decision.governing_ref,
            "also_denied_by_source_kinds": decision.also.iter().collect::<Vec<_>>(),
            "reason_code": decision.reason,
        }));
    }

    let is_snapshot = SNAPSHOT_SCOPE_LEVELS.contains(&scope_level.as_str());
    let parent_binding = match parent.as_ref() {
        None => json!({
            "compilation_origin": "root_default",
            "parent_revision_ref": Value::Null,
            "parent_content_hash": Value::Null,
            "parent_denied_uses_at_compilation": Vec::<String>::new(),
            "parent_denied_use_count_at_compilation": 0,
        }),
        Some(held) => json!({
            "compilation_origin": "narrowed_from_parent",
            "parent_revision_ref": held.revision_ref,
            "parent_content_hash": held.content_hash,
            "parent_denied_uses_at_compilation": inherited,
            "parent_denied_use_count_at_compilation": inherited.len(),
        }),
    };
    let snapshot_binding = match (is_snapshot, parent.as_ref()) {
        (true, Some(held)) => json!({
            "snapshot_of_revision_ref": held.revision_ref,
            "snapshot_of_content_hash": held.content_hash,
            "mid_run_policy_change_rewrites_admitted_receipts": false,
        }),
        _ => json!({
            "snapshot_of_revision_ref": Value::Null,
            "snapshot_of_content_hash": Value::Null,
            "mid_run_policy_change_rewrites_admitted_receipts": false,
        }),
    };

    let compiled = match compiled_policy_hash(
        &scope_level,
        &tenant_ref,
        &claim_refs,
        &route_refs,
        &view_refs,
        parent.as_ref().map(|held| held.revision_ref.as_str()),
        &effective_permitted,
        &effective_denied,
    ) {
        Ok(hash) => hash,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &spec.code("compiled_policy_hash_failed"),
                reason,
            )
        }
    };

    let ordinal = stream.len() as u64 + 1;
    let succession = match stream.last() {
        None => json!({
            "succession_reason": "genesis",
            "predecessor_revision_ref": Value::Null,
            "predecessor_content_hash": Value::Null,
            "supersedes_predecessor": false,
            "reinterprets_predecessor": false,
        }),
        Some(entry) => {
            let raw = body_str(&body, "succession_reason");
            json!({
                "succession_reason": if raw.is_empty() { "parent_policy_change".to_string() } else { raw },
                "predecessor_revision_ref": entry.record.get("revision_ref").cloned().unwrap_or(Value::Null),
                "predecessor_content_hash": entry.record.get("content_hash").cloned().unwrap_or(Value::Null),
                "supersedes_predecessor": true,
                "reinterprets_predecessor": false,
            })
        }
    };

    let applies_to_refs = match ref_list(&body, "applies_to_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let protected_material_classes = match ref_list(&body, "protected_material_classes", 12, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let receipt_obligations = match ref_list(&body, "receipt_obligations", 8, spec) {
        Ok(list) if !list.is_empty() => list,
        Ok(_) => vec![
            "boundary_compilation".to_string(),
            "learning_evidence_eligibility".to_string(),
            "learning_egress_decision".to_string(),
        ],
        Err(response) => return response,
    };
    let does_not_assert = match ref_list(&body, "does_not_assert", 10, spec) {
        Ok(list) if !list.is_empty() => list,
        Ok(_) => vec![
            "authority".to_string(),
            "execution_power".to_string(),
            "new_authority_plane".to_string(),
            "truth_store".to_string(),
            "legal_right_generation".to_string(),
            "provider_non_learning".to_string(),
            "verified_unlearning".to_string(),
        ],
        Err(response) => return response,
    };
    let system_binding = match body.get("system_binding") {
        Some(value) if value.is_object() => value.clone(),
        _ => json!({
            "system_ref": Value::Null,
            "constitution_ref": Value::Null,
            "deployment_profile_ref": Value::Null,
            "upgrade_required_for_widening": true,
        }),
    };

    let governance_owner_ref = {
        let raw = body_str(&body, "governance_owner_ref");
        if raw.is_empty() {
            caller.owner_ref.clone()
        } else {
            raw
        }
    };
    let scope_owner_ref = {
        let raw = body_str(&body, "scope_owner_ref");
        if raw.is_empty() {
            caller.owner_ref.clone()
        } else {
            raw
        }
    };
    let bound_target_refs = match ref_list(&body, "bound_target_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let profile_status = {
        let raw = body_str(&body, "status");
        if raw.is_empty() {
            "active".to_string()
        } else {
            raw
        }
    };
    let record = json!({
        "schema_version": spec.schema_version,
        "boundary_profile_id": resource,
        "revision_ref": format!("{resource}/revision/{ordinal}"),
        "owner_ref": caller.owner_ref,
        "tenant_ref": tenant_ref,
        "governance_owner_ref": governance_owner_ref,
        "scope_level": scope_level,
        "scope_owner_ref": scope_owner_ref,
        "applies_to_refs": applies_to_refs,
        "system_binding": system_binding,
        "protected_material_classes": protected_material_classes,
        "learning_source_rights_claim_revision_refs": claim_refs,
        "policy_bound_data_view_refs": view_refs,
        "route_rights_contract_refs": route_refs,
        "custody": custody,
        "external_recipient_permissions": external_recipient,
        "cross_tenant_learning": cross_tenant,
        "target_binding": {
            "bound_target_refs": bound_target_refs,
            // PINNED. ACC-12 clause 8: permission for one target does not travel to another.
            "permission_travels_to_other_targets": false,
        },
        "declared_use_vocabulary": LEARNING_USE_VOCABULARY,
        "effective_permitted_uses": effective_permitted,
        "effective_denied_uses": effective_denied,
        "parent_binding": parent_binding,
        "parent_denied_uses": inherited,
        "locally_added_denied_uses": locally_added,
        "narrowing_decisions": narrowing_decisions,
        "indeterminate_findings": indeterminate_findings,
        // PINNED EMPTY. This seam never releases an inherited denial; widening travels the governed
        // upgrade path or does not happen.
        "widening_releases": Vec::<Value>::new(),
        "snapshot_binding": snapshot_binding,
        "jurisdiction_refs": jurisdiction_refs,
        "residency_refs": residency_refs,
        "retention_policy_ref": retention_policy_ref,
        "deletion_or_forget_policy_ref": body_str(&body, "deletion_or_forget_policy_ref"),
        "legal_or_audit_hold_policy_ref": body.get("legal_or_audit_hold_policy_ref").cloned().unwrap_or(Value::Null),
        "derivative_policy_ref": body_str(&body, "derivative_policy_ref"),
        "export_policy_ref": body_str(&body, "export_policy_ref"),
        "revocation_policy_ref": body_str(&body, "revocation_policy_ref"),
        "declassification_policy_ref": body_str(&body, "declassification_policy_ref"),
        "receipt_obligations": receipt_obligations,
        "compiled_policy_hash": compiled,
        "effective_from": admitted_stamp(recorded_at_ms),
        "expires_at": body.get("expires_at").cloned().unwrap_or(Value::Null),
        "status": profile_status,
        "admitted_at": admitted_stamp(recorded_at_ms),
        "succession": succession,
        "constants": {
            "lifecycle_id": "institutional_learning_boundary_profile_lifecycle.v1",
            "learning_use_vocabulary_size": LEARNING_USE_VOCABULARY.len(),
            "cross_tenant_use_token": "cross_tenant_aggregate_learning",
            "recipient_permission_deny_token": "deny",
            "nonclaim_authority_token": "authority",
            "nonclaim_provider_non_learning_token": "provider_non_learning",
        },
        "authority_nonclaim": "institutional_learning_boundary_profile_grants_no_authority",
        "truth_nonclaim": "institutional_learning_boundary_profile_is_a_policy_compilation_not_a_runtime_or_truth_store",
        "does_not_assert": does_not_assert,
    });

    finish_admission(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        "institutional_learning_boundary_profile",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        json!({
            "compiled_inputs": {
                "source_rights_claims": claims.len(),
                "route_rights_contracts": routes.len(),
                "parent_profile": parent.as_ref().map(|held| held.revision_ref.clone()),
                "parent_index_state": parent.as_ref().map(|held| held.index_state),
            },
            "intersection_is_a_subtraction_not_a_grant": true,
        }),
    )
}

pub(crate) async fn handle_boundary_profile_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    family_query(
        &PROFILE,
        "institutional_learning_boundary_profile_refs",
        st,
        &headers,
        query,
    )
}

// ==================================================== LearningEvidenceEligibility — one bounded decision

const ELIGIBILITY_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "eligibility_id",
    "revision_ref",
    "tenant_ref",
    "boundary_profile_content_hash",
    "effective_learning_policy_hash",
    "boundary_permitted_uses_at_decision",
    "boundary_permitted_use_count_at_decision",
    "status",
    "exclusion_reason",
    "admitted_at",
    "succession",
    "constants",
    "authority_nonclaim",
    "truth_nonclaim",
    "content_hash",
];

/// The intended uses the training-compatibility profile may carry, verbatim from the registered
/// conditional. An operational use under that profile is a schema refusal, so it is refused here by
/// name instead.
const TRAINING_COMPATIBILITY_USES: &[&str] = &[
    "conductor_training",
    "worker_training",
    "eval_generation",
    "dataset_distillation",
    "benchmark",
];

/// ONE resolved eligibility revision, published so a consumer reads a decision rather than remaking
/// it.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedEvidenceEligibility {
    pub(crate) revision_ref: String,
    pub(crate) record: Value,
    pub(crate) content_hash: String,
    pub(crate) index_state: &'static str,
}

impl ResolvedEvidenceEligibility {
    pub(crate) fn is_eligible(&self) -> bool {
        self.record.get("status").and_then(Value::as_str) == Some("eligible")
    }

    pub(crate) fn learning_use(&self) -> String {
        self.record
            .get("learning_use")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    pub(crate) fn boundary_profile_revision_ref(&self) -> String {
        self.record
            .get("boundary_profile_revision_ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }
}

/// Resolve ONE exact eligibility revision under the CALLER'S OWN owner binding.
pub(crate) fn resolve_admitted_evidence_eligibility(
    data_dir: &str,
    identity: &RequestIdentity,
    expected_owner_ref: Option<&str>,
    revision_ref: &str,
) -> Result<ResolvedEvidenceEligibility, Reply> {
    let Some((family, ordinal)) = parse_revision_ref(ELIGIBILITY.ref_scheme, revision_ref) else {
        return Err(refuse(
            &ELIGIBILITY.code("revision_ref_not_canonical"),
            "an eligibility binding names eligibility://<family>/revision/<n>; a family head or mutable-latest reference is refused where a revision is required",
        ));
    };
    let resource = format!("{}{family}", ELIGIBILITY.ref_scheme);
    let scope = authorize_request_resource_scope(
        data_dir,
        identity,
        ELIGIBILITY.resource_kind,
        &resource,
        expected_owner_ref,
    )
    .map_err(scope_refusal_reply)?;
    let stream = read_stream(&ELIGIBILITY, data_dir, identity, &scope, &resource)?;
    let index_state = projection_cache_state(&resource, &stream);
    let wanted = format!("{resource}/revision/{ordinal}");
    let Some(entry) = stream
        .iter()
        .find(|entry| entry.record.get("revision_ref") == Some(&json!(wanted)))
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &ELIGIBILITY.code("revision_absent"),
            format!(
                "this eligibility family has no admitted revision {ordinal}; an absent revision is a typed absence, never the nearest one"
            ),
        ));
    };
    Ok(ResolvedEvidenceEligibility {
        revision_ref: wanted,
        content_hash: entry
            .record
            .get("content_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        record: entry.record.clone(),
        index_state,
    })
}

pub(crate) async fn handle_evidence_eligibility_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let spec = &ELIGIBILITY;
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        contract_owner_ref(&caller.owner_ref, &spec.code("owner_scheme_unsupported"))
    {
        return response;
    }
    if let Err(response) = reject_authored(&body, spec, ELIGIBILITY_SERVER_RESOLVED) {
        return response;
    }
    let family = body_str(&body, "family");
    if !family_token(&family) {
        return refuse(
            &spec.code("family_not_canonical"),
            "'family' is the lineage token this revision extends: [a-z0-9][a-z0-9._-]{0,127}",
        );
    }
    let resource = format!("{}{family}", spec.ref_scheme);
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        spec.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(spec, &st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    match replay_for_key(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        &stream,
        "learning_evidence_eligibility",
    ) {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    let expected_head = match head_assertion(&body, spec.code_prefix) {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, spec.code_prefix) {
        return response;
    }

    // THE BOUNDARY IS RESOLVED, NEVER DESCRIBED. The profile revision, its content hash, its
    // compiled policy hash and the permission set this decision was taken against all come from the
    // owner seam. A caller that could supply them could make a decision against a boundary that
    // never existed, which is precisely the admission-over-self-supplied-constants failure INV-37
    // names.
    let boundary_ref = body_str(&body, "boundary_profile_revision_ref");
    let boundary = match resolve_admitted_boundary_profile(
        &st.data_dir,
        &caller.identity,
        Some(caller.owner_ref.as_str()),
        &boundary_ref,
    ) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    let tenant_ref = contract_tenant_ref(&caller.owner_ref);
    if boundary.tenant_ref != tenant_ref {
        return refuse(
            &spec.code("cross_tenant_boundary_refused"),
            format!(
                "the bound boundary profile carries tenancy '{}' while this decision is taken for '{tenant_ref}'; a decision against another tenancy's boundary is refused, never resolved",
                boundary.tenant_ref
            ),
        );
    }

    let learning_use = body_str(&body, "learning_use");
    if !LEARNING_USE_VOCABULARY.contains(&learning_use.as_str()) {
        return refuse(
            &spec.code("learning_use_outside_vocabulary"),
            "'learning_use' is one member of the closed fifteen-use learning vocabulary",
        );
    }
    let eligibility_profile = {
        let raw = body_str(&body, "eligibility_profile");
        if raw.is_empty() {
            "general_learning".to_string()
        } else {
            raw
        }
    };
    let intended_use = body_str(&body, "intended_use");
    if eligibility_profile == "training_compatibility"
        && !TRAINING_COMPATIBILITY_USES.contains(&intended_use.as_str())
    {
        return refuse(
            &spec.code("training_profile_carries_an_operational_use"),
            format!(
                "the training-compatibility profile carries only training, dataset, evaluation and benchmark uses; '{intended_use}' is an operational use and lending the training profile to it would be exactly the evidence-lending canon forbids"
            ),
        );
    }
    let contamination_posture = {
        let raw = body_str(&body, "contamination_posture");
        if raw.is_empty() {
            "unknown".to_string()
        } else {
            raw
        }
    };

    // ------------------------------------------------------------------ the decision, as a subtraction
    // ELIGIBLE IS THE RESIDUAL CASE. Every reason to exclude is checked first and the decision is
    // eligible only if none of them fired. Ordering matters for the REASON, not the outcome: the
    // first reason found is the one recorded, because a decision that excluded for several reasons
    // and named none of them is a refusal nobody can remedy.
    let permitted_at_decision = boundary.effective_permitted_uses();
    let exclusion_reason: Option<&str> = if !boundary.is_active() {
        Some("revoked")
    } else if !matches!(contamination_posture.as_str(), "clean") {
        // Contaminated, quarantined, evaluation-aware and unclassified material is never eligible.
        Some("sealed_evaluation_material")
    } else if !permitted_at_decision
        .iter()
        .any(|held| *held == learning_use)
    {
        // The boundary denies the exact use. Whether it denied it determinately or left it
        // indeterminate is recorded on the PROFILE; this decision reports that it was not permitted.
        if boundary
            .record
            .get("indeterminate_findings")
            .and_then(Value::as_array)
            .is_some_and(|findings| {
                findings.iter().any(|finding| {
                    finding.get("denied_use").and_then(Value::as_str) == Some(learning_use.as_str())
                })
            })
        {
            Some("indeterminate_rights")
        } else {
            Some("boundary_denies_the_use")
        }
    } else {
        None
    };
    let status = if exclusion_reason.is_none() {
        "eligible"
    } else {
        "excluded"
    };

    let target_refs = match ref_list(&body, "allowed_improvement_target_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    if status == "eligible" && target_refs.is_empty() {
        return refuse(
            &spec.code("eligible_without_a_bound_target"),
            "an eligible decision names at least one allowed improvement target; permission for one target does not travel to another, so an unbound eligibility would be a permission with no edge",
        );
    }
    let admitted_by_ref = body_str(&body, "admitted_by_ref");
    if status == "eligible" && admitted_by_ref.is_empty() {
        return refuse(
            &spec.code("eligible_without_an_admitting_operation"),
            "an eligible decision names the operation that admitted it; a decision nobody admitted is a proposal wearing an admission's clothes",
        );
    }

    let claim_refs = match ref_list(
        &body,
        "learning_source_rights_claim_revision_refs",
        64,
        spec,
    ) {
        Ok(list) => list,
        Err(response) => return response,
    };
    for claim_ref in &claim_refs {
        if let Err(response) = resolve_admitted_source_rights_claim(
            &st.data_dir,
            &caller.identity,
            Some(caller.owner_ref.as_str()),
            claim_ref,
        ) {
            return response;
        }
    }
    let subject_refs = match ref_list(&body, "subject_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let view_refs = match ref_list(&body, "policy_bound_data_view_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let recipe_refs = match ref_list(&body, "data_recipe_revision_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let local_policy_refs = match ref_list(&body, "local_policy_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let consent_refs = match ref_list(&body, "consent_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let epoch_refs = match ref_list(&body, "applicable_evaluation_epoch_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    // `none` is a real member of the kinds vocabulary rather than an absence, and the registered
    // contract requires at least one. Recording "no authority is required" explicitly is the honest
    // shape: an empty list would be silence, and silence is what lets a requirement go unnoticed.
    let authority_kinds = match ref_list(&body, "authority_requirement_kinds", 11, spec) {
        Ok(list) if !list.is_empty() => list,
        Ok(_) => vec!["none".to_string()],
        Err(response) => return response,
    };
    let wallet_refs = match ref_list(&body, "wallet_authority_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let declassification_refs = match ref_list(&body, "declassification_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let egress_receipt_refs = match ref_list(&body, "learning_egress_receipt_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let scope_refs = match ref_list(&body, "owner_and_tenant_scope_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let does_not_assert = match ref_list(&body, "does_not_assert", 10, spec) {
        Ok(list) if !list.is_empty() => list,
        Ok(_) => vec![
            "authority".to_string(),
            "declassification".to_string(),
            "capability_lease_crossing".to_string(),
            "source_rights".to_string(),
            "semantic_truth".to_string(),
            "redaction_creates_permission".to_string(),
        ],
        Err(response) => return response,
    };

    let authority_posture = {
        let raw = body_str(&body, "authority_requirement_posture");
        if raw.is_empty() {
            "none".to_string()
        } else {
            raw
        }
    };
    if authority_posture == "required" && authority_kinds.is_empty() {
        return refuse(
            &spec.code("required_authority_not_named"),
            "a decision that says authority is required names which kinds; 'required' with no named kind is a requirement nobody can discharge",
        );
    }

    let recorded_at_ms = agentgres::parse_rfc3339_ms(&body_str(&body, "effective_at"));
    let ordinal = stream.len() as u64 + 1;
    let succession = match stream.last() {
        None => json!({
            "succession_reason": "genesis",
            "predecessor_revision_ref": Value::Null,
            "predecessor_content_hash": Value::Null,
            "supersedes_predecessor": false,
            "reinterprets_predecessor": false,
        }),
        Some(entry) => {
            let raw = body_str(&body, "succession_reason");
            json!({
                "succession_reason": if raw.is_empty() { "boundary_revision_change".to_string() } else { raw },
                "predecessor_revision_ref": entry.record.get("revision_ref").cloned().unwrap_or(Value::Null),
                "predecessor_content_hash": entry.record.get("content_hash").cloned().unwrap_or(Value::Null),
                "supersedes_predecessor": true,
                "reinterprets_predecessor": false,
            })
        }
    };
    let legacy_binding = body
        .get("legacy_binding")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or(Value::Null);
    let governance_owner_ref = {
        let raw = body_str(&body, "governance_owner_ref");
        if raw.is_empty() {
            caller.owner_ref.clone()
        } else {
            raw
        }
    };
    let admitted_by = if status == "eligible" {
        json!(admitted_by_ref)
    } else if admitted_by_ref.is_empty() {
        Value::Null
    } else {
        json!(admitted_by_ref)
    };

    let record = json!({
        "schema_version": spec.schema_version,
        "eligibility_id": resource,
        "revision_ref": format!("{resource}/revision/{ordinal}"),
        "owner_ref": caller.owner_ref,
        "tenant_ref": tenant_ref,
        "governance_owner_ref": governance_owner_ref,
        "eligibility_profile": eligibility_profile,
        "boundary_profile_revision_ref": boundary.revision_ref,
        "boundary_profile_content_hash": boundary.content_hash,
        "effective_learning_policy_hash": boundary.compiled_policy_hash,
        "boundary_permitted_uses_at_decision": permitted_at_decision,
        "boundary_permitted_use_count_at_decision": permitted_at_decision.len(),
        "learning_use": learning_use,
        "learning_source_rights_claim_revision_refs": claim_refs,
        "subject_refs": subject_refs,
        "requester_ref": body_str(&body, "requester_ref"),
        "intended_use": intended_use,
        "learning_use_posture": body_str(&body, "learning_use_posture"),
        "legacy_binding": legacy_binding,
        "applicable_evaluation_epoch_refs": epoch_refs,
        "target_binding": {
            "allowed_improvement_target_refs": target_refs,
            // PINNED by the registered contract. Eligibility for one target never travels.
            "permission_travels_to_other_targets": false,
        },
        "owner_and_tenant_scope_refs": scope_refs,
        "contamination_posture": contamination_posture,
        "policy_bound_data_view_refs": view_refs,
        "data_recipe_revision_refs": recipe_refs,
        "local_policy_refs": local_policy_refs,
        "consent_refs": consent_refs,
        "authority_requirement_posture": authority_posture,
        "authority_requirement_kinds": authority_kinds,
        "wallet_authority_refs": wallet_refs,
        "declassification_refs": declassification_refs,
        "learning_egress_receipt_refs": egress_receipt_refs,
        "provider_trust_posture": body_str(&body, "provider_trust_posture"),
        "retention_policy_ref": body_str(&body, "retention_policy_ref"),
        "derivative_policy_ref": body_str(&body, "derivative_policy_ref"),
        "lineage_root": body_str(&body, "lineage_root"),
        "receipt_root": body_str(&body, "receipt_root"),
        "exclusion_reason": exclusion_reason.map(Value::from).unwrap_or(Value::Null),
        "status": status,
        "admitted_by_ref": admitted_by,
        "admitted_at": admitted_stamp(recorded_at_ms),
        "succession": succession,
        "constants": {
            "lifecycle_id": "learning_evidence_eligibility_lifecycle.v1",
            "learning_use_vocabulary_size": LEARNING_USE_VOCABULARY.len(),
            "nonclaim_authority_token": "authority",
            "nonclaim_declassification_token": "declassification",
        },
        "authority_nonclaim": "learning_evidence_eligibility_grants_no_authority",
        "truth_nonclaim": "learning_evidence_eligibility_is_an_admission_decision_not_a_permission_to_cross_a_boundary",
        "does_not_assert": does_not_assert,
    });

    finish_admission(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        "learning_evidence_eligibility",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        json!({
            "decided_against_boundary": boundary.revision_ref,
            "boundary_index_state": boundary.index_state,
            "eligibility_is_a_decision_not_a_crossing_permission": true,
        }),
    )
}

pub(crate) async fn handle_evidence_eligibility_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    family_query(
        &ELIGIBILITY,
        "learning_evidence_eligibility_refs",
        st,
        &headers,
        query,
    )
}

// ==================================================== LearningEgressReceipt — the receipted crossing

const EGRESS_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "receipt_id",
    "receipt_ref",
    "receipt_type",
    "tenant_ref",
    "boundary_profile_content_hash",
    "effective_learning_policy_hash",
    "decision",
    "reason_codes",
    "transfer_status",
    "chain_position",
    "predecessor_receipt_ref",
    "predecessor_content_hash",
    "emitted_at",
    "constants",
    "authority_nonclaim",
    "truth_nonclaim",
    "content_hash",
];

/// The representations that move learned PARAMETERS rather than content, and therefore make the
/// crossing a declassification event requiring an explicit approval.
const PARAMETER_REPRESENTATIONS: &[&str] = &["declassified", "protected_plaintext"];

/// Emit one learning-egress receipt: an admitted crossing, or a refusal recorded before egress.
///
/// THE DECISION IS COMPUTED, NOT DECLARED. A caller states what it wants to move, to whom, in what
/// representation and under which eligibility; the daemon resolves the boundary and the eligibility
/// through their owner seams and decides. A caller cannot hand in `decision: admitted` — that field
/// is server-resolved, so a receipt claiming a crossing the boundary would have refused is not
/// representable.
pub(crate) async fn handle_learning_egress_receipt_emit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let spec = &EGRESS;
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        contract_owner_ref(&caller.owner_ref, &spec.code("owner_scheme_unsupported"))
    {
        return response;
    }
    if let Err(response) = reject_authored(&body, spec, EGRESS_SERVER_RESOLVED) {
        return response;
    }
    let family = body_str(&body, "family");
    if !family_token(&family) {
        return refuse(
            &spec.code("family_not_canonical"),
            "'family' is the crossing lineage token: [a-z0-9][a-z0-9._-]{0,127}",
        );
    }
    let resource = format!("{}{family}", spec.ref_scheme);
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        spec.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(spec, &st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    match replay_for_key(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        &stream,
        "learning_egress_receipt",
    ) {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    let expected_head = match head_assertion(&body, spec.code_prefix) {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, spec.code_prefix) {
        return response;
    }

    let tenant_ref = contract_tenant_ref(&caller.owner_ref);
    let boundary_ref = body_str(&body, "boundary_profile_revision_ref");
    let boundary = match resolve_admitted_boundary_profile(
        &st.data_dir,
        &caller.identity,
        Some(caller.owner_ref.as_str()),
        &boundary_ref,
    ) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    if boundary.tenant_ref != tenant_ref {
        return refuse(
            &spec.code("cross_tenant_boundary_refused"),
            format!(
                "the bound boundary profile carries tenancy '{}' while this crossing is for '{tenant_ref}'; a crossing decided against another tenancy's boundary is refused",
                boundary.tenant_ref
            ),
        );
    }

    let eligibility_refs = match ref_list(
        &body,
        "learning_evidence_eligibility_revision_refs",
        32,
        spec,
    ) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let mut eligibilities = Vec::with_capacity(eligibility_refs.len());
    for eligibility_ref in &eligibility_refs {
        match resolve_admitted_evidence_eligibility(
            &st.data_dir,
            &caller.identity,
            Some(caller.owner_ref.as_str()),
            eligibility_ref,
        ) {
            Ok(resolved) => eligibilities.push(resolved),
            Err(response) => return response,
        }
    }

    let route_ref = body_str(&body, "model_route_rights_revision_ref");
    let route = if route_ref.is_empty() {
        None
    } else {
        match resolve_admitted_model_route_rights_contract(
            &st.data_dir,
            &caller.identity,
            Some(caller.owner_ref.as_str()),
            &route_ref,
        ) {
            Ok(resolved) => Some(resolved),
            Err(response) => return response,
        }
    };

    let representation = body_str(&body, "representation");
    let recipient_class = body_str(&body, "recipient_class");
    let declassification_approval_ref = body_str(&body, "declassification_approval_ref");

    // ------------------------------------------------------------------------ the crossing decision
    // FAIL-CLOSED, AND EVERY REFUSAL NAMES ITSELF. Reason codes accumulate rather than short-circuit
    // so a blocked crossing tells the operator every gate it failed, not merely the first.
    let mut reason_codes: Vec<&str> = Vec::new();
    if !boundary.is_active() {
        reason_codes.push("LearningEgressDenied");
    }
    if eligibilities.is_empty() || !eligibilities.iter().all(|held| held.is_eligible()) {
        reason_codes.push("LearningEgressDenied");
    }
    // Every bound eligibility must have been decided against THIS boundary revision. An eligibility
    // taken against a different revision is evidence about a different policy, and lending it here
    // is exactly the stale-policy crossing this receipt exists to refuse.
    if eligibilities
        .iter()
        .any(|held| held.boundary_profile_revision_ref() != boundary.revision_ref)
    {
        reason_codes.push("InstitutionalExportDenied");
    }
    // The use each eligibility carries must still be permitted by the boundary as it stands now.
    let permitted_now = boundary.effective_permitted_uses();
    if eligibilities.iter().any(|held| {
        !permitted_now
            .iter()
            .any(|use_token| *use_token == held.learning_use())
    }) {
        reason_codes.push("LearningSourceRightsMissing");
    }
    match route.as_ref() {
        None => {
            if recipient_class == "model_provider" {
                reason_codes.push("RouteRightsUnsatisfied");
            }
        }
        Some(resolved) => {
            if !resolved.is_live() {
                reason_codes.push("RouteRightsUnsatisfied");
            }
            if !resolved.provider_model_training_prohibited()
                && resolved
                    .record
                    .pointer("/provider_use_of_customer_material/provider_model_training_basis_ref")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .is_none()
            {
                // Provider secondary use is denied by default; permitting it needs a NAMED basis.
                reason_codes.push("ProviderSecondaryUseDenied");
            }
            if !resolved
                .permitted_destination_classes()
                .iter()
                .any(|held| *held == recipient_class)
            {
                reason_codes.push("RouteRightsUnsatisfied");
            }
        }
    }
    // MOVING PARAMETERS ACROSS A SOVEREIGN BOUNDARY IS A DECLASSIFICATION EVENT. A declassified or
    // protected-plaintext representation without an approval is refused before egress, not after.
    if PARAMETER_REPRESENTATIONS.contains(&representation.as_str())
        && declassification_approval_ref.is_empty()
    {
        reason_codes.push("DeclassificationApprovalMissing");
    }
    if representation == "protected_plaintext"
        && body_str(&body, "execution_privacy_posture_ref").is_empty()
    {
        reason_codes.push("CustodyPostureUnsatisfied");
    }
    reason_codes.sort_unstable();
    reason_codes.dedup();

    let admitted = reason_codes.is_empty();
    let decision = if admitted {
        "admitted"
    } else {
        "blocked_before_egress"
    };

    // TRANSFER STATUS IS A CLAIM ABOUT THE NETWORK, AND IT IS BOUNDED BY WHAT WE CAN PROVE. A
    // `prevented_before_network_write` claim requires enforcement evidence that binds the request
    // commitment; without it the honest answer is `not_sent`, because "we returned an error" is not
    // the same fact as "the invoker was never called".
    let enforcement_binds = body
        .get("enforcement_evidence_binds_request_commitment")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let gateway_evidence = match ref_list(&body, "network_or_gateway_evidence_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    // The caller's OBSERVATION rides on a differently-named field, and only the four outcomes a
    // caller could legitimately have witnessed are accepted from it. `prevented_before_network_write`
    // is deliberately not among them: that claim is about what the enforcement seam did, not about
    // what the caller saw, and letting a caller assert it would be the exact assurance inflation the
    // registered contract's enforcement-evidence conditional exists to prevent.
    let transfer_status = if admitted {
        let observed = body_str(&body, "observed_transfer_status");
        if matches!(
            observed.as_str(),
            "sent" | "delivery_confirmed" | "failed" | "unknown"
        ) {
            observed
        } else {
            "unknown".to_string()
        }
    } else if enforcement_binds && !gateway_evidence.is_empty() {
        "prevented_before_network_write".to_string()
    } else {
        "not_sent".to_string()
    };

    let material_classes = match ref_list(&body, "material_classes", 12, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    if material_classes.is_empty() {
        return refuse(
            &spec.code("material_classes_required"),
            "a crossing names the material classes it moves; an unnamed class is an unbounded crossing",
        );
    }
    let material_commitment = body_str(&body, "material_commitment");
    if !is_sha256(&material_commitment) {
        return refuse(
            &spec.code("material_commitment_not_canonical"),
            "'material_commitment' is a sha256:<64 lowercase hex> commitment over the material this crossing moves",
        );
    }

    let claim_refs = match ref_list(
        &body,
        "learning_source_rights_claim_revision_refs",
        64,
        spec,
    ) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let projection_refs = match ref_list(&body, "policy_bound_projection_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let terms_refs = match ref_list(&body, "applicable_terms_and_license_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let policy_consent_refs = match ref_list(&body, "local_policy_and_consent_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let authority_refs = match ref_list(&body, "authority_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let redaction_refs = match ref_list(
        &body,
        "redaction_or_declassification_receipt_refs",
        32,
        spec,
    ) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let operation_receipt_refs =
        match ref_list(&body, "underlying_operation_receipt_refs", 32, spec) {
            Ok(list) => list,
            Err(response) => return response,
        };
    let state_operation_refs = match ref_list(&body, "state_operation_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let output_uses = match ref_list(&body, "intended_customer_output_uses", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let does_not_assert = match ref_list(&body, "does_not_assert", 10, spec) {
        Ok(list) if !list.is_empty() => list,
        Ok(_) => vec![
            "authority".to_string(),
            "delivery".to_string(),
            "provider_non_learning".to_string(),
            "provider_deletion".to_string(),
            "verified_unlearning".to_string(),
            "protected_plaintext_custody".to_string(),
            "verdict".to_string(),
        ],
        Err(response) => return response,
    };
    let provider_use = match route.as_ref() {
        // The provider-use snapshot is COPIED from the route contract this crossing resolved, never
        // restated by the caller: the route contract remains the semantic owner and a snapshot that
        // could disagree with it would be a second reading of the same terms.
        Some(resolved) => {
            let mut snapshot = resolved
                .record
                .get("provider_use_of_customer_material")
                .cloned()
                .unwrap_or_else(|| json!({}));
            // The receipt's shape omits `publication`, which the route contract carries.
            if let Some(object) = snapshot.as_object_mut() {
                object.remove("publication");
            }
            snapshot
        }
        None => match body_object(&body, "provider_use_of_customer_material", spec) {
            Ok(value) => value,
            Err(response) => return response,
        },
    };

    let recorded_at_ms = agentgres::parse_rfc3339_ms(&body_str(&body, "effective_at"));
    let ordinal = stream.len() as u64 + 1;
    let receipt_ref = format!("{resource}.{ordinal}");
    let predecessor = stream.last();
    let (chain_position, predecessor_receipt_ref, predecessor_content_hash) = match predecessor {
        None => ("genesis", Value::Null, Value::Null),
        Some(entry) => (
            "successor",
            entry
                .record
                .get("receipt_ref")
                .cloned()
                .unwrap_or(Value::Null),
            entry
                .record
                .get("content_hash")
                .cloned()
                .unwrap_or(Value::Null),
        ),
    };

    let record = json!({
        "schema_version": spec.schema_version,
        "receipt_id": receipt_ref,
        "receipt_ref": receipt_ref,
        "receipt_type": "learning_egress",
        "owner_ref": caller.owner_ref,
        "tenant_ref": tenant_ref,
        "source_scope_ref": body_str(&body, "source_scope_ref"),
        "boundary_profile_revision_ref": boundary.revision_ref,
        "boundary_profile_content_hash": boundary.content_hash,
        "effective_learning_policy_hash": boundary.compiled_policy_hash,
        "boundary_compilation_or_policy_decision_ref": body_str(&body, "boundary_compilation_or_policy_decision_ref"),
        "learning_evidence_eligibility_revision_refs": eligibility_refs,
        "learning_source_rights_claim_revision_refs": claim_refs,
        "material_classes": material_classes,
        "material_class_count": material_classes.len(),
        "material_commitment": material_commitment,
        "policy_bound_projection_refs": projection_refs,
        "recipient_class": recipient_class,
        "recipient_ref": body_str(&body, "recipient_ref"),
        "purpose": body_str(&body, "purpose"),
        "representation": representation,
        "execution_privacy_posture_ref": body_str(&body, "execution_privacy_posture_ref"),
        "model_route_rights_revision_ref": route.as_ref().map(|held| json!(held.revision_ref)).unwrap_or(Value::Null),
        "intended_customer_output_uses": output_uses,
        "effective_customer_output_rights_hash": route
            .as_ref()
            .and_then(|held| held.record.pointer("/customer_output_rights/effective_customer_output_rights_hash").cloned())
            .unwrap_or(Value::Null),
        "applicable_terms_and_license_refs": terms_refs,
        "provider_use_of_customer_material": provider_use,
        "retention_posture": body_str(&body, "retention_posture"),
        "retention_policy_ref": body_str(&body, "retention_policy_ref"),
        "local_policy_and_consent_refs": policy_consent_refs,
        "authority_refs": authority_refs,
        "declassification_approval_ref": if declassification_approval_ref.is_empty() {
            Value::Null
        } else {
            json!(declassification_approval_ref)
        },
        "redaction_or_declassification_receipt_refs": redaction_refs,
        "underlying_operation_receipt_refs": operation_receipt_refs,
        "revocation_impact_ref": body.get("revocation_impact_ref").cloned().unwrap_or(Value::Null),
        "forward_links": Vec::<Value>::new(),
        "decision": decision,
        "reason_codes": reason_codes,
        "transfer_status": transfer_status,
        "enforcement_evidence_binds_request_commitment": enforcement_binds && !gateway_evidence.is_empty(),
        "network_or_gateway_evidence_refs": gateway_evidence,
        "state_operation_refs": state_operation_refs,
        "assurance_stage": "attested",
        "chain_position": chain_position,
        "predecessor_receipt_ref": predecessor_receipt_ref,
        "predecessor_content_hash": predecessor_content_hash,
        "emitted_at": admitted_stamp(recorded_at_ms),
        "constants": {
            "lifecycle_id": "learning_egress_receipt_lifecycle.v1",
            "provider_use_prohibited_token": "prohibited",
            "nonclaim_authority_token": "authority",
            "nonclaim_delivery_token": "delivery",
            "nonclaim_provider_non_learning_token": "provider_non_learning",
        },
        "authority_nonclaim": "learning_egress_receipt_grants_no_authority",
        "truth_nonclaim": "learning_egress_receipt_proves_ioi_observed_boundary_facts_not_recipient_behaviour",
        "does_not_assert": does_not_assert,
    });

    finish_admission(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        "learning_egress_receipt",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        json!({
            "decided_against_boundary": boundary.revision_ref,
            "boundary_index_state": boundary.index_state,
            "receipt_proves_an_observed_boundary_fact_not_recipient_behaviour": true,
        }),
    )
}

pub(crate) async fn handle_learning_egress_receipt_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    family_query(&EGRESS, "learning_egress_receipt_refs", st, &headers, query)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each registered positive fixture must hash to the number it carries under THIS module's
    /// material list. The fixture is a committed pin; the material list is this build's independent
    /// reading of the registered invariant. A gate computing both sides from one source certifies
    /// nothing, so the two sides are deliberately different artifacts.
    fn assert_fixture_commitment(spec: &FamilySpec, fixture: &str) {
        let record: Value = serde_json::from_str(fixture).expect("the fixture parses");
        let committed = record
            .get("content_hash")
            .and_then(Value::as_str)
            .expect("the fixture carries a commitment");
        let derived = spec
            .content_hash(&record)
            .expect("the material list resolves");
        assert_eq!(
            derived, committed,
            "{}'s material list disagrees with the registered commitment",
            spec.code_prefix
        );
    }

    #[test]
    fn registered_claim_fixture_matches_this_modules_material_list() {
        assert_fixture_commitment(
            &CLAIM,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/architecture/_meta/schemas/fixtures/learning-source-rights-claim-v1/positive-genesis-admitted-claim.json"
            )),
        );
    }

    #[test]
    fn registered_profile_fixture_matches_this_modules_material_list() {
        assert_fixture_commitment(
            &PROFILE,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/architecture/_meta/schemas/fixtures/institutional-learning-boundary-profile-v1/positive-root-organization-default.json"
            )),
        );
    }

    #[test]
    fn registered_eligibility_fixture_matches_this_modules_material_list() {
        assert_fixture_commitment(
            &ELIGIBILITY,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/architecture/_meta/schemas/fixtures/learning-evidence-eligibility-v1/positive-eligible-training-compatibility.json"
            )),
        );
    }

    #[test]
    fn registered_egress_fixture_matches_this_modules_material_list() {
        assert_fixture_commitment(
            &EGRESS,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/architecture/_meta/schemas/fixtures/learning-egress-receipt-v1/positive-admitted-redacted-inference-crossing.json"
            )),
        );
    }

    /// The load-bearing property of the whole unit: permission is the COMPLEMENT of the denial set,
    /// so a use denied by any single input cannot survive the intersection no matter how many other
    /// inputs permit it.
    #[test]
    fn one_denial_removes_a_use_no_matter_how_many_inputs_permit_it() {
        let mut intersection = Intersection::default();
        intersection.deny(
            "fine_tune",
            "source_rights_claim",
            "learning-source-rights://x/revision/1",
            "source_right_prohibits",
        );
        let denied = intersection.all_denied();
        assert!(denied.contains(&"fine_tune".to_string()));
        let permitted: Vec<&&str> = LEARNING_USE_VOCABULARY
            .iter()
            .filter(|token| !denied.iter().any(|held| held == *token))
            .collect();
        assert!(!permitted.iter().any(|token| ***token == *"fine_tune"));
    }

    /// An indeterminacy denies, and it wins the attribution row so the record says WHY rather than
    /// merely that the use was unavailable.
    #[test]
    fn an_indeterminacy_denies_and_keeps_its_reason() {
        let mut intersection = Intersection::default();
        intersection.deny(
            "export",
            "declared_local_policy",
            "learning-boundary://x#local",
            "local_policy_prohibits",
        );
        intersection.indeterminate("export", "missing_required_contract", "contract://x");
        assert!(intersection.all_denied().contains(&"export".to_string()));
        assert!(intersection.indeterminate.contains_key("export"));
    }

    /// A route contract that is not live contributes indeterminacy for every use it gates, rather
    /// than the silence a lapsed contract would otherwise be read as.
    #[test]
    fn a_lapsed_route_contract_is_not_read_as_no_opinion() {
        let route = ResolvedModelRouteRights {
            revision_ref: "model-route-rights://x/revision/1".into(),
            owner_ref: "org://x".into(),
            tenant_ref: "tenant://x".into(),
            record: json!({ "status": "revoked", "revocation": { "revocation_state": "revoked" } }),
            content_hash: String::new(),
            admitted_head: String::new(),
            index_state: "rebuilt_from_agentgres",
        };
        let mut intersection = Intersection::default();
        fold_route_contract(&mut intersection, &route);
        assert!(intersection.all_denied().contains(&"fine_tune".to_string()));
        assert!(intersection
            .all_denied()
            .contains(&"operational_inference".to_string()));
    }
}
