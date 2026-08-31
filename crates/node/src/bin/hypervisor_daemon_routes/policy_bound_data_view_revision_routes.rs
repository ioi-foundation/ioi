//! M05.8 — the runtime-enforced `PolicyBoundDataView`, as owner-scoped runtime.
//!
//! The registered v2 contract became an immutable, content-addressed revision in 98a8defca. This is
//! the half that ADMITS one and then ENFORCES it: a second family, `PolicyBoundDataViewMaterialization`,
//! is the only place a reader obtains a bounded row/field/time projection, and it revalidates the
//! whole policy against its OWNERS at the moment bytes would move rather than trusting what the view
//! recorded when it was compiled.
//!
//! THE PERMISSION IS A SUBTRACTION, NOT A FIELD. `allowed_uses` and `rights_derived_allowed_uses`
//! are never supplied by a caller. The admitter starts from the closed eight-use view vocabulary and
//! subtracts every denial contributed by every resolved input — the bound purpose, the compiled
//! learning boundary, each source-rights claim, each route-rights contract, the retention and hold
//! state, the registry status and the destination/egress ceiling. What remains IS the permission.
//! `redaction_derived_allowed_uses` is emitted EMPTY and the registered coverage invariant then
//! makes redaction-as-permission unrepresentable rather than merely refused: a use added without a
//! right leaves the covering short.
//!
//! REDACTION REDUCES EXPOSURE AND CREATES NOTHING. A caller that declares `creates_permission`,
//! `severs_lineage`, or an output privacy class below the source classification is refused BY NAME
//! rather than having the field corrected underneath it — a silently repaired declassification is a
//! declassification that happened and was not recorded.
//!
//! WHAT THE VIEW BINDS IS RESOLVED THROUGH ITS OWNERS' SEAMS, NEVER SHAPE-CHECKED HERE. The learning
//! boundary and the source-rights claims come from M10.3, the route contracts from M07.2, the
//! connector mappings and the redaction recipe from M05.7, the ontology revisions from M05.1, and
//! the purpose-binding decision from Governance. Each crosses that owner's read-only resolver under
//! the CALLER'S OWN owner binding, so a cross-principal or cross-tenant input is refused at the
//! scope boundary before any bytes are read. The resolved principal is taken from the authenticated
//! request identity and is refused if a caller tries to author it.
//!
//! EVERY SOURCE IS RESOLVED THROUGH ITS OWN FAMILY'S OWNER SEAM, AND AN UNRESOLVABLE SCHEME IS A
//! REFUSAL. Canon mints no single protected-source family and the registered contract pins no scheme
//! on `source_revision_ref`, so the owner is per family: ontology revisions through M05.1, and
//! mapping, recipe and transformation-run revisions through M05.7. Each bound row's committed
//! `source_content_hash` is compared against what its owner currently serves, so a silent
//! re-admission is detectable — at admission AND again at the read. A scheme with no registered seam
//! is refused by name rather than accepted as a well-formed string, which is also the fence that
//! keeps M05.9's dataset and media families from being invented in here.
//!
//! CONSENT IS A RIGHTS BASIS, NOT A FAMILY. Canon mints no `ConsentClaim` and no `consent://`
//! scheme; a consent is carried in a `LearningSourceRightsClaim`'s `rights_basis_refs`, and the
//! claim is the auditable record. So every `consent_bindings[].consent_ref` must be COVERED by a
//! basis on one of the bound claim revisions, and that claim's own `is_live()` and
//! `expires_before()` are what revalidate the consent's revocation and expiry at the read. A consent
//! held entirely outside any admitted claim is REFUSED rather than trusted from the view's own
//! `consent_state` — a state a caller attested is not a state anyone can recheck.
//!
//! THIS MODULE MODELS NO PROVIDER CONNECTION AT ALL. `ProviderConnectionBinding` is wallet.network's
//! (M03.16) and is deliberately outside the closed eight-member `revalidated_facts` vocabulary. A
//! view projects over material ALREADY ADMITTED inside the tenant through its owners' seams; it does
//! not connect to anything. What this seam does instead is refuse, typed and fail-closed, any view
//! whose permitted destination classes require a brokered crossing that no admitted authority object
//! covers — the route-rights ceiling is that coverage, and the crossing itself remains M10.3's
//! `LearningEgressReceipt` lane. A stand-in connection field here would be a second authority plane,
//! which both M03 and M05 forbid by name.
//!
//! READS REVALIDATE ALL EIGHT NAMED FACTS. Current authority (the owner seam), current rights (every
//! claim, route and source re-resolved), revocation state, expiry (view, claim validity, boundary
//! window), retention and hold, residency, destination class, and consent state (through the covering
//! claim). A fact that cannot be established denies the disputed read; nothing falls back to the last
//! known permission.
//!
//! THE DECISION RECORD CARRIES NO PROTECTED BYTES. A granted projection is a DESCRIPTOR — which
//! fields, which row predicate and ceiling, which time window on which timebase — and the record
//! non-claims custody of any materialized payload. The daemon bounds the read; it does not become
//! the copy.
//!
//! NOT A REGISTERED CONTRACT, AND SAID SO. `PolicyBoundDataView` v2 is registered and every admitted
//! revision is validated against it. The materialization decision is a DAEMON-LOCAL record with its
//! own commitment domain; it is projected and re-hashed on read exactly like a registered family,
//! but no architecture contract is claimed for it and this module does not mint one.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use agentgres::mux::ExactProjection;

use super::institutional_learning_boundary_routes::{
    resolve_admitted_boundary_profile, resolve_admitted_source_rights_claim,
    ResolvedBoundaryProfile, ResolvedSourceRightsClaim, LEARNING_USE_VOCABULARY,
};
use super::model_route_rights_routes::{
    bad, body_object, body_str, contract_owner_ref, contract_tenant_ref, digest_over, family_query,
    family_token, finish_admission, head_assertion, is_sha256, parse_revision_ref,
    projection_cache_state, read_stream, ref_list, refuse, reject_authored, replay_for_key,
    require_exact_head, resolve_admitted_model_route_rights_contract, vocabulary_list,
    AdmittedRecord, FamilySpec, Reply, ResolvedModelRouteRights, StreamQuery,
};
use super::mutation_event_foundation::{
    admit_owner_scoped_mutation, admitted_stamp, mutation_refusal_reply,
    prior_admission_for_key_on_stream, read_owner_scoped_history, require_write_caller,
    scope_refusal_reply, stream_tail, ScopedMutation,
};
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity, RequestIdentity,
};
use super::DaemonState;

// ================================================================================== the vocabularies

/// The eight canonical view uses, verbatim and in the order the registered contract declares them.
const VIEW_USE_VOCABULARY: &[&str] = &[
    "read",
    "transform",
    "distill",
    "train",
    "evaluate",
    "export",
    "publish",
    "route",
];

/// The learning uses each VIEW use is gated by, as this build reads the two vocabularies.
///
/// DECLARED AS A TABLE, FOR THE SAME REASON M10.3 DECLARES ITS ROUTE TABLE. The learning vocabulary
/// (fifteen) and the view vocabulary (eight) are not isomorphic, so any intersection between them is
/// a reading. An inspectable constant is what lets a reviewer disagree with one row and a mutation
/// flip one row and watch the gate go red. A view use survives only if EVERY learning use naming it
/// survived the compiled boundary; learning uses with no view consequence are absent rather than
/// mapped to something approximate.
const VIEW_USE_GATES: &[(&str, &[&str])] = &[
    ("read", &["operational_inference"]),
    ("transform", &["dataset_generation"]),
    ("distill", &["distill"]),
    ("train", &["fine_tune"]),
    ("evaluate", &["internal_evaluation"]),
    ("export", &["export"]),
    ("publish", &["publish"]),
    ("route", &["operational_inference"]),
];

/// The view uses each BOUND PURPOSE can support.
///
/// PURPOSE-BINDING IS WHAT MAKES MINIMIZATION MEAN ANYTHING. A field set justified for evaluation is
/// not a field set justified for training, and a purpose nobody can check narrows nothing. This is
/// the axis the predecessor could not express at all: it carried free text.
const PURPOSE_GATES: &[(&str, &[&str])] = &[
    ("operational_read", &["read"]),
    ("transformation", &["read", "transform"]),
    ("evaluation", &["read", "transform", "evaluate"]),
    ("dataset_generation", &["read", "transform"]),
    ("model_or_worker_training", &["read", "transform", "train"]),
    ("distillation", &["read", "transform", "distill"]),
    ("analytics", &["read", "transform", "evaluate"]),
    ("audit_or_export", &["read", "export"]),
    ("publication", &["read", "publish"]),
    ("routing", &["read", "route"]),
];

/// The uses that require projected material to leave the owner boundary, so an egress ceiling and a
/// destination class bear on them.
const EGRESS_GATED_VIEW_USES: &[&str] = &["export", "publish", "route"];

/// The uses a legal, audit or incident hold removes.
///
/// A hold NARROWS disposal and can narrow use; it never widens either. The outward and derivative
/// uses go; reading, transforming and evaluating the held material — which is usually the whole point
/// of the hold — do not.
const HOLD_DENIED_VIEW_USES: &[&str] = &["distill", "train", "export", "publish", "route"];

/// Which representations each egress ceiling admits.
///
/// A TABLE RATHER THAN AN ORDERING. `redacted_only` and `synthetic_only` are not comparable, so a
/// numeric ceiling comparison would silently admit one under the other. Every row is exact.
const CEILING_REPRESENTATIONS: &[(&str, &[&str])] = &[
    ("no_egress", &[]),
    ("redacted_only", &["redacted"]),
    ("synthetic_only", &["synthetic"]),
    ("declassified_only", &["declassified"]),
    ("sealed_ciphertext_only", &["sealed_ciphertext"]),
    (
        "protected_plaintext_permitted",
        &[
            "redacted",
            "synthetic",
            "declassified",
            "sealed_ciphertext",
            "protected_plaintext",
        ],
    ),
];

/// Representations that move DECLASSIFIED material and therefore need their own approval.
const DECLASSIFYING_REPRESENTATIONS: &[&str] = &["declassified", "protected_plaintext"];

/// All EIGHT facts the registered precondition names, because this build revalidates all eight at
/// the materialization instant. `consent_state` is included on the same footing as the rest: a
/// consent is a RIGHTS BASIS carried on a `LearningSourceRightsClaim`, so its revocation and expiry
/// are resolved through M10.3's claim seam rather than read off a state a caller attested.
const REVALIDATED_FACTS: &[&str] = &[
    "current_authority",
    "current_rights",
    "revocation_state",
    "expiry",
    "retention_and_hold",
    "residency",
    "destination_class",
    "consent_state",
];

/// The source-ref schemes this build can RESOLVE, each naming the owner module that answers for it.
///
/// A SOURCE IS RESOLVED THROUGH ITS OWN FAMILY'S OWNER SEAM, AND THERE IS NO OTHER LANE. Canon mints
/// no single "protected source" family and the registered contract pins no scheme on
/// `source_revision_ref`, so the owner is per source family. An unlisted scheme is REFUSED rather
/// than accepted as a well-formed string: an accepted free-form ref is silence, and silence about a
/// protected source is inadmissible. That refusal is also the fence that keeps M05.9's dataset and
/// media families from being invented in here — M05.9 depends on this unit, never the reverse.
const RESOLVABLE_SOURCE_SCHEMES: &[(&str, &str)] = &[
    ("ontology://", "M05.1 ontology_version_routes"),
    ("mapping://", "M05.7 data_transformation_routes"),
    ("data-recipe://", "M05.7 data_transformation_routes"),
    ("transform://", "M05.7 data_transformation_routes"),
];

/// Destination classes that put projected material in someone else's hands. Each one needs an
/// admitted authority object that covers it; `in_boundary_only` is the only class that does not.
const BROKERED_DESTINATION_CLASSES: &[&str] = &[
    "model_provider",
    "external_processor",
    "cross_organization",
    "public_export",
    "support_operator",
];

/// The seven mandatory non-claims, exactly as the registered positive fixture carries them.
const DEFAULT_DOES_NOT_ASSERT: &[&str] = &[
    "authority",
    "consent",
    "redaction_creates_permission",
    "declassification",
    "source_rights",
    "semantic_truth",
    "cross_tenant_reuse",
];

/// The full `does_not_assert` vocabulary, so an addition is checked rather than accepted.
const DOES_NOT_ASSERT_VOCABULARY: &[&str] = &[
    "authority",
    "consent",
    "redaction_creates_permission",
    "declassification",
    "source_rights",
    "semantic_truth",
    "cross_tenant_reuse",
    "capability_lease_crossing",
    "provider_non_learning",
    "verified_unlearning",
    "materialized_payload_custody",
    "runtime_enforcement",
];

/// The successor reasons the registered contract admits.
const SUCCESSION_REASONS: &[&str] = &[
    "genesis",
    "source_revision_change",
    "minimization_change",
    "rights_or_consent_change",
    "boundary_revision_change",
    "redaction_recipe_change",
    "retention_or_hold_change",
    "destination_or_residency_change",
    "revocation_or_expiry",
    "correction",
];

/// The predecessor's schema version and identity scheme, named here as the REFUSED form for a v2
/// identity. They appear legitimately in exactly one place: `migration`.
const LEGACY_SCHEMA_VERSION: &str = "ioi.hypervisor.odk.policy-bound-data-view.v1";
const LEGACY_VIEW_SCHEME: &str = "policy-bound-data-view://";

// ============================================================================== family descriptors

static VIEW: FamilySpec = FamilySpec {
    owner_namespace: "policy-bound-data-views",
    resource_kind: "policy_bound_data_view",
    admit_op: "event_stream.policy_bound_data_view_revision_admitted",
    payload_schema: "ioi.hypervisor.policy-bound-data-view-revision-admission.v1",
    contract_id: "schema://ioi/foundations/objects/policy-bound-data-view/v2",
    schema_version: "ioi.policy-bound-data-view.v2",
    record_key: "policy_bound_data_view_record",
    code_prefix: "policy_bound_data_view",
    commitment_domain: "ioi.policy-bound-data-view-content-commitment-jcs-sha256.v2",
    material_fields: &[
        "schema_version",
        "policy_bound_data_view_id",
        "revision_ref",
        "owner_ref",
        "tenant_ref",
        "principal_resolution",
        "resolved_principal_ref",
        "purpose",
        "purpose_binding_ref",
        "source_bindings",
        "source_binding_count",
        "ontology_revision_refs",
        "connector_mapping_revision_refs",
        "object_model_refs",
        "row_scope",
        "field_scope",
        "time_scope",
        "data_classes",
        "privacy_class",
        "source_rights_claim_revision_refs",
        "consent_bindings",
        "route_rights_revision_refs",
        "jurisdiction_refs",
        "residency_refs",
        "redaction",
        "retention_and_hold",
        "destination_and_egress",
        "effective_boundary_binding",
        "materialization_precondition",
        "allowed_uses",
        "rights_derived_allowed_uses",
        "redaction_derived_allowed_uses",
        "registry_status",
        "admitted_at",
        "succession",
        "migration",
        "constants",
        "authority_nonclaim",
        "truth_nonclaim",
        "does_not_assert",
    ],
    identity_field: "revision_ref",
    ref_scheme: "view://",
    stamp_field: "admitted_at",
};

/// Fields the SERVER resolves. Authoring one is INV-37's exact failure mode: a caller that writes
/// the permission its own admission checks has checked a constant it chose.
const VIEW_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "policy_bound_data_view_id",
    "revision_ref",
    "tenant_ref",
    "principal_resolution",
    // THE PRINCIPAL IS RESOLVED, NOT SUPPLIED. `principal_resolution` being pinned to
    // `server_resolved` means nothing if the principal beside it is whatever the caller typed, so
    // the ref itself is server-resolved too and authoring it is refused by name.
    "resolved_principal_ref",
    "source_binding_count",
    "field_scope",
    "effective_boundary_binding",
    "materialization_precondition",
    "allowed_uses",
    "rights_derived_allowed_uses",
    "redaction_derived_allowed_uses",
    "admitted_at",
    "succession",
    "migration",
    "constants",
    "authority_nonclaim",
    "truth_nonclaim",
    "content_hash",
];

// ------------------------------------------------------------------------ the resolved view itself

/// ONE resolved view revision, as a caller entitled to it may see it.
///
/// THE SEAM THE MATERIALIZER BINDS. Enforcement does not read this family's chain, re-derive its
/// commitment or reinterpret its permission. There is one reader, it is here, it shares the owner
/// scope and chain projection of the query route, and it GRANTS NOTHING.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedPolicyBoundDataView {
    pub(crate) revision_ref: String,
    pub(crate) tenant_ref: String,
    pub(crate) record: Value,
    pub(crate) content_hash: String,
    pub(crate) index_state: &'static str,
}

impl ResolvedPolicyBoundDataView {
    fn text(&self, pointer: &str) -> String {
        self.record
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    fn list(&self, pointer: &str) -> Vec<String> {
        self.record
            .pointer(pointer)
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

    pub(crate) fn allowed_uses(&self) -> Vec<String> {
        self.list("/allowed_uses")
    }

    pub(crate) fn is_active(&self) -> bool {
        self.text("/registry_status") == "active"
    }
}

/// Resolve ONE exact view revision under the CALLER'S OWN owner binding.
///
/// The identity is passed in, so a cross-principal or cross-tenant resolution is refused at the
/// scope boundary BEFORE any bytes are returned — not resolved first and compared afterwards, which
/// would be a leak with a check bolted on behind it. A family head is refused by the ref grammar
/// rather than resolved to "latest": a read that resolved `view://acme.intake` would read through
/// whichever policy the family last carried.
pub(crate) fn resolve_admitted_policy_bound_data_view(
    data_dir: &str,
    identity: &RequestIdentity,
    expected_owner_ref: Option<&str>,
    revision_ref: &str,
) -> Result<ResolvedPolicyBoundDataView, Reply> {
    let Some((family, ordinal)) = parse_revision_ref(VIEW.ref_scheme, revision_ref) else {
        return Err(refuse(
            &VIEW.code("revision_ref_not_canonical"),
            "a view binding names view://<family>/revision/<n>; a family head, a mutable-latest reference, or the predecessor's policy-bound-data-view:// spelling is refused where a revision is required",
        ));
    };
    let resource = format!("{}{family}", VIEW.ref_scheme);
    let scope = authorize_request_resource_scope(
        data_dir,
        identity,
        VIEW.resource_kind,
        &resource,
        expected_owner_ref,
    )
    .map_err(scope_refusal_reply)?;
    let stream = read_stream(&VIEW, data_dir, identity, &scope, &resource)?;
    let index_state = projection_cache_state(&resource, &stream);
    let wanted = format!("{resource}/revision/{ordinal}");
    let Some(entry) = stream
        .iter()
        .find(|entry| entry.record.get("revision_ref") == Some(&json!(wanted)))
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &VIEW.code("revision_absent"),
            format!(
                "this view family has no admitted revision {ordinal}; an absent revision is a typed absence, never the nearest one"
            ),
        ));
    };
    Ok(ResolvedPolicyBoundDataView {
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

// ============================================================================ the use intersection

/// One determinate denial of one view use, attributed to the input that produced it.
#[derive(Clone, Debug)]
struct UseDenial {
    kind: &'static str,
    governing_ref: String,
    reason: &'static str,
}

/// The accumulator every resolved input folds into. A use present here is not in the permission.
#[derive(Default)]
struct UseIntersection {
    denied: std::collections::BTreeMap<String, UseDenial>,
}

impl UseIntersection {
    fn deny(
        &mut self,
        use_token: &str,
        kind: &'static str,
        governing_ref: &str,
        reason: &'static str,
    ) {
        self.denied
            .entry(use_token.to_string())
            .or_insert(UseDenial {
                kind,
                governing_ref: governing_ref.to_string(),
                reason,
            });
    }

    fn deny_all(&mut self, kind: &'static str, governing_ref: &str, reason: &'static str) {
        for token in VIEW_USE_VOCABULARY {
            self.deny(token, kind, governing_ref, reason);
        }
    }

    /// The permission: the vocabulary MINUS the denial set, in vocabulary order.
    fn permitted(&self) -> Vec<String> {
        VIEW_USE_VOCABULARY
            .iter()
            .filter(|token| !self.denied.contains_key(**token))
            .map(|token| (*token).to_string())
            .collect()
    }

    fn attributions(&self) -> Vec<Value> {
        VIEW_USE_VOCABULARY
            .iter()
            .filter_map(|token| {
                self.denied.get(*token).map(|denial| {
                    json!({
                        "use": token,
                        "denied_by": denial.kind,
                        "governing_ref": denial.governing_ref,
                        "reason": denial.reason,
                    })
                })
            })
            .collect()
    }
}

/// The view uses a given learning use gates, per the declared table.
fn view_uses_gated_by(learning_use: &str) -> Vec<&'static str> {
    VIEW_USE_GATES
        .iter()
        .filter(|(_, gates)| gates.contains(&learning_use))
        .map(|(view_use, _)| *view_use)
        .collect()
}

fn purpose_permits(purpose: &str) -> &'static [&'static str] {
    PURPOSE_GATES
        .iter()
        .find(|(name, _)| *name == purpose)
        .map(|(_, uses)| *uses)
        .unwrap_or(&[])
}

fn ceiling_representations(ceiling: &str) -> &'static [&'static str] {
    CEILING_REPRESENTATIONS
        .iter()
        .find(|(name, _)| *name == ceiling)
        .map(|(_, reps)| *reps)
        .unwrap_or(&[])
}

/// Fold the BOUND PURPOSE. Anything the purpose does not support is denied by the purpose itself.
fn fold_purpose(intersection: &mut UseIntersection, purpose: &str, purpose_binding_ref: &str) {
    let supported = purpose_permits(purpose);
    for token in VIEW_USE_VOCABULARY {
        if !supported.contains(token) {
            intersection.deny(
                token,
                "bound_purpose",
                purpose_binding_ref,
                "purpose_does_not_support_use",
            );
        }
    }
}

/// Fold the COMPILED LEARNING BOUNDARY. A learning use the boundary denied removes every view use it
/// gates; a boundary that is not active removes everything.
fn fold_boundary(intersection: &mut UseIntersection, boundary: &ResolvedBoundaryProfile) {
    if !boundary.is_active() {
        intersection.deny_all(
            "learning_boundary_profile",
            &boundary.revision_ref,
            "boundary_not_active",
        );
        return;
    }
    let permitted = boundary.effective_permitted_uses();
    for learning_use in LEARNING_USE_VOCABULARY {
        if permitted.iter().any(|held| held == learning_use) {
            continue;
        }
        for token in view_uses_gated_by(learning_use) {
            intersection.deny(
                token,
                "learning_boundary_profile",
                &boundary.revision_ref,
                "boundary_denies_the_gating_learning_use",
            );
        }
    }
}

/// Fold ONE resolved source-rights claim, revalidated for liveness and expiry at this instant.
fn fold_source_claim(
    intersection: &mut UseIntersection,
    claim: &ResolvedSourceRightsClaim,
    at_ms: u64,
) {
    if !claim.is_live() || claim.expires_before(at_ms) {
        let reason = if claim.expires_before(at_ms) {
            "source_rights_claim_expired"
        } else {
            "source_rights_claim_not_live"
        };
        intersection.deny_all("source_rights_claim", &claim.revision_ref, reason);
        return;
    }
    for prohibited in claim.prohibited_uses() {
        for token in view_uses_gated_by(&prohibited) {
            intersection.deny(
                token,
                "source_rights_claim",
                &claim.revision_ref,
                "source_right_prohibits_the_gating_learning_use",
            );
        }
    }
}

/// Fold ONE resolved route contract. A route bears on the ONWARD uses only: a contract that is not
/// live, or whose own ceiling is `no_egress`, removes every egress-gated view use. This build claims
/// no wider mapping between the twelve route uses and the eight view uses.
fn fold_route_contract(intersection: &mut UseIntersection, route: &ResolvedModelRouteRights) {
    if !route.is_live() {
        for token in EGRESS_GATED_VIEW_USES {
            intersection.deny(
                token,
                "route_rights_contract",
                &route.revision_ref,
                "route_contract_not_live",
            );
        }
        return;
    }
    if route.egress_ceiling() == "no_egress" {
        for token in EGRESS_GATED_VIEW_USES {
            intersection.deny(
                token,
                "route_rights_contract",
                &route.revision_ref,
                "route_ceiling_permits_no_egress",
            );
        }
    }
}

/// Fold the view's OWN lifecycle, retention, hold and destination ceiling.
fn fold_view_state(
    intersection: &mut UseIntersection,
    registry_status: &str,
    retention: &Value,
    destination: &Value,
    self_ref: &str,
) {
    if registry_status != "active" {
        intersection.deny_all("view_registry_status", self_ref, "view_is_not_active");
    }
    let retention_state = retention
        .get("retention_state")
        .and_then(Value::as_str)
        .unwrap_or("retention_elapsed");
    if retention_state != "within_retention" {
        intersection.deny_all("retention_state", self_ref, "retention_is_not_current");
    }
    let hold_state = retention
        .get("hold_state")
        .and_then(Value::as_str)
        .unwrap_or("none");
    if hold_state != "none" {
        for token in HOLD_DENIED_VIEW_USES {
            intersection.deny(
                token,
                "hold_state",
                self_ref,
                "a_hold_narrows_outward_and_derivative_use",
            );
        }
    }
    let classes: Vec<String> = destination
        .get("permitted_destination_classes")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if classes.iter().all(|held| held == "in_boundary_only") {
        for token in EGRESS_GATED_VIEW_USES {
            intersection.deny(
                token,
                "destination_ceiling",
                self_ref,
                "no_destination_class_leaves_the_boundary",
            );
        }
    }
    let ceiling = destination
        .get("egress_ceiling")
        .and_then(Value::as_str)
        .unwrap_or("no_egress");
    if ceiling_representations(ceiling).is_empty() {
        for token in EGRESS_GATED_VIEW_USES {
            intersection.deny(
                token,
                "egress_ceiling",
                self_ref,
                "the_egress_ceiling_admits_no_representation",
            );
        }
    }
}

// ================================================================ admission of one view revision

/// Resolve ONE bound source revision through the owner seam its scheme names, and return the content
/// hash that owner CURRENTLY serves.
///
/// The scheme dispatch is the whole point: there is no generic source reader here, only a routing
/// table to the module that owns each family. A scheme with no entry is refused rather than accepted,
/// and a caller cannot widen the table by spelling a ref differently, because each seam parses its
/// own identity strictly and refuses a family head.
fn resolve_source_revision(
    data_dir: &str,
    identity: &RequestIdentity,
    source_revision_ref: &str,
) -> Result<String, Reply> {
    if source_revision_ref.starts_with("ontology://") {
        return super::ontology_version_routes::resolve_admitted_revision(
            data_dir,
            identity,
            source_revision_ref,
        )
        .map(|resolved| resolved.content_hash);
    }
    if source_revision_ref.starts_with("mapping://") {
        return super::data_transformation_routes::resolve_admitted_connector_mapping(
            data_dir,
            identity,
            source_revision_ref,
        )
        .map(|resolved| resolved.content_hash);
    }
    if source_revision_ref.starts_with("data-recipe://") {
        return super::data_transformation_routes::resolve_admitted_data_recipe(
            data_dir,
            identity,
            source_revision_ref,
        )
        .map(|resolved| resolved.content_hash);
    }
    if source_revision_ref.starts_with("transform://") {
        let run = super::data_transformation_routes::resolve_admitted_transformation_run(
            data_dir,
            identity,
            source_revision_ref,
        )?;
        // A run that did not complete produced nothing to project over. Binding one would bind this
        // view to material that does not exist, which no later check could discover.
        if !run.is_completed() {
            return Err(refuse(
                &VIEW.code("source_run_not_completed"),
                format!(
                    "transformation run '{source_revision_ref}' is '{}', not completed; a run that produced nothing is not a source a projection can be over",
                    run.execution_status
                ),
            ));
        }
        return Ok(run.content_hash);
    }
    Err(refuse(
        &VIEW.code("source_scheme_has_no_owner_seam"),
        format!(
            "'{source_revision_ref}' names no family with a registered owner seam; this build resolves {}. An accepted free-form source ref is silence, and silence about a protected source is inadmissible",
            RESOLVABLE_SOURCE_SCHEMES
                .iter()
                .map(|(scheme, owner)| format!("{scheme} ({owner})"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    ))
}

/// Resolve every bound source row and require its committed hash to be what its owner serves NOW.
///
/// THE SAME FUNCTION RUNS AT ADMISSION AND AT THE READ, which is what makes a silent re-admission
/// detectable: the ref still resolves, but the bytes behind it moved, and the committed hash is the
/// only thing that notices.
fn verify_source_bindings(
    data_dir: &str,
    identity: &RequestIdentity,
    bindings: &[Value],
) -> Result<Vec<Value>, Reply> {
    let mut resolved = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let source_revision_ref = item_str(binding, "source_revision_ref");
        let committed = item_str(binding, "source_content_hash");
        let live = resolve_source_revision(data_dir, identity, &source_revision_ref)?;
        if live != committed {
            return Err(refuse(
                &VIEW.code("source_content_hash_moved"),
                format!(
                    "source '{source_revision_ref}' now serves {live} while this view commits {committed}; a ref names a location that may since have been re-admitted, and the hash is what names what was actually bound"
                ),
            ));
        }
        resolved.push(json!({
            "source_revision_ref": source_revision_ref,
            "resolved_content_hash": live,
        }));
    }
    Ok(resolved)
}

/// An array of objects read from the request, deduplicated, with a named refusal rather than a
/// downstream schema error.
fn object_list(
    body: &Value,
    key: &str,
    max: usize,
    spec: &FamilySpec,
) -> Result<Vec<Value>, Reply> {
    let Some(value) = body.get(key) else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_array() else {
        return Err(refuse(
            &spec.code("member_list_invalid"),
            format!("'{key}' is an array of objects on this contract"),
        ));
    };
    if items.len() > max {
        return Err(refuse(
            &spec.code("member_list_invalid"),
            format!("'{key}' admits at most {max} members"),
        ));
    }
    let mut out: Vec<Value> = Vec::with_capacity(items.len());
    for item in items {
        if !item.is_object() {
            return Err(refuse(
                &spec.code("member_list_invalid"),
                format!("'{key}' members are objects"),
            ));
        }
        if !out.iter().any(|held| held == item) {
            out.push(item.clone());
        }
    }
    Ok(out)
}

fn item_str(item: &Value, key: &str) -> String {
    item.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_string()
}

/// The predecessor record this convergence read, and the exact bytes it read.
///
/// v1 carries NO commitment of its own, so the hash is computed here, over the stored record in
/// canonical JSON. That is what makes a convergence checkable at all: a later reader re-reads the
/// stored v1 record, canonicalizes it, and either gets the same number or discovers that the
/// predecessor moved after the convergence claimed to have read it.
fn converge_from_legacy(data_dir: &str, legacy_ref: &str) -> Result<Value, Reply> {
    if !legacy_ref.starts_with(LEGACY_VIEW_SCHEME) {
        return Err(refuse(
            &VIEW.code("legacy_view_ref_not_canonical"),
            format!("'converge_from_view_ref' names the predecessor in the scheme it was ACTUALLY STORED under ({LEGACY_VIEW_SCHEME}pbdv_…); rewriting it into view:// here would be reinterpreting v1, which a convergence may not do"),
        ));
    }
    let id = legacy_ref.trim_start_matches(LEGACY_VIEW_SCHEME);
    let Some(record) =
        super::read_record_dir(data_dir, super::policy_bound_data_view_routes::RECORD_DIR)
            .into_iter()
            .find(|held| held.get("id").and_then(Value::as_str) == Some(id))
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &VIEW.code("legacy_view_absent"),
            format!("no stored v1 view resolves to '{legacy_ref}'; a convergence that cannot read its predecessor's bytes is a typed absence, never an assumed-empty predecessor"),
        ));
    };
    let bytes = serde_jcs::to_vec(&record).map_err(|error| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            &VIEW.code("legacy_view_not_canonicalizable"),
            format!("the stored v1 record could not be canonicalized: {error}"),
        )
    })?;
    Ok(json!({
        "from_schema_version": LEGACY_SCHEMA_VERSION,
        "from_view_ref": legacy_ref,
        "from_content_hash": super::model_route_rights_routes::sha256_of(&bytes),
        "compatibility": "converged_from_v1",
        "reinterprets_predecessor": false,
        "downgrade_to_predecessor": "refused",
        "downgrade_refusal_reason": "v1_cannot_express_revision_identity_source_revisions_field_minimization_rights_consent_boundary_hash_or_commitment",
    }))
}

/// POST /v1/hypervisor/policy-bound-data-views — admit one immutable view revision.
pub(crate) async fn handle_policy_bound_data_view_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let spec = &VIEW;
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        contract_owner_ref(&caller.owner_ref, &spec.code("owner_scheme_unsupported"))
    {
        return response;
    }
    if let Err(response) = reject_authored(&body, spec, VIEW_SERVER_RESOLVED) {
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
    // REPLAY BEFORE PRECONDITIONS: a retry after an ambiguous response necessarily observes a newer
    // head than the one it first compare-and-swapped against, so checking `expected_head` first
    // would turn every real duplicate into a conflict.
    match replay_for_key(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        &stream,
        "policy_bound_data_view",
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

    // The admission instant. A view stamped at epoch because nobody supplied one is a wall-clock
    // stamp wearing an admission's clothes, so an absent or unparseable stamp is refused by name.
    let recorded_at_ms = agentgres::parse_rfc3339_ms(&body_str(&body, "effective_at"));
    if recorded_at_ms == 0 {
        return refuse(
            &spec.code("effective_at_not_canonical"),
            "'effective_at' is the RFC3339 instant this admission is stamped with; an absent or malformed stamp reads as absent, never as zero-o'clock",
        );
    }

    let purpose = body_str(&body, "purpose");
    if purpose_permits(&purpose).is_empty() {
        return refuse(
            &spec.code("purpose_outside_vocabulary"),
            format!("'{purpose}' is not one of this contract's ten bound purposes; an unknown purpose is a typed refusal, never a purpose that narrows nothing"),
        );
    }
    // THE PURPOSE BINDING RESOLVES TO A GOVERNANCE-OWNED DECISION. A non-empty string is a label; a
    // ref that Governance's own resolver can open is a decision someone made. The scheme is pinned
    // to `approval-request://` because that is the one Governance-owned decision family its resolver
    // actually opens — an unknown scheme falls through that resolver as a named ref, so accepting
    // any scheme would be accepting a string again with extra steps.
    //
    // NAMED RESIDUAL: Governance exposes existence, not status. This build proves the decision
    // EXISTS and is Governance-owned; it does not read whether the approval is still approved,
    // because there is no seam that returns it.
    let purpose_binding_ref = body_str(&body, "purpose_binding_ref");
    if !purpose_binding_ref.starts_with("approval-request://") {
        return refuse(
            &spec.code("purpose_binding_not_owner_resolvable"),
            "a purpose asserted by the record alone is a label; 'purpose_binding_ref' names a Governance-owned decision as 'approval-request://<id>', which is the form Governance's own resolver opens",
        );
    }
    if let Err((code, message)) =
        super::governance_routes::resolve_governance_ref(&st.data_dir, &purpose_binding_ref)
    {
        return refuse(
            &spec.code("purpose_binding_unresolved"),
            format!("the purpose binding did not resolve through Governance's own seam ({code}): {message}"),
        );
    }

    // ---------------------------------------------------------------- sources, and the tenant fence
    let source_bindings = match object_list(&body, "source_bindings", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    if source_bindings.is_empty() {
        return refuse(
            &spec.code("source_bindings_required"),
            "a projection over no source is not a projection; admitting one would let an audit count an empty view as coverage",
        );
    }
    let tenant_ref = contract_tenant_ref(&caller.owner_ref);
    for binding in &source_bindings {
        for key in [
            "source_ref",
            "source_revision_ref",
            "source_content_hash",
            "source_tenant_ref",
            "source_owner_ref",
            "source_class",
        ] {
            if item_str(binding, key).is_empty() {
                return refuse(
                    &spec.code("source_binding_not_canonical"),
                    format!("every source binding names its {key}; a partial binding reads as a complete lineage while naming nothing anyone could check"),
                );
            }
        }
        if !is_sha256(&item_str(binding, "source_content_hash")) {
            return refuse(
                &spec.code("source_binding_not_canonical"),
                "a source binding's content hash is sha256:<64 lowercase hex>; a ref names a location that may since have been re-admitted, and the hash names what was actually bound",
            );
        }
        // THE CROSS-TENANT REFUSAL, NAMED AT ADMISSION. The registered invariant refuses this record
        // offline too; naming it here says WHICH source crossed the fence instead of surfacing as a
        // coverage arithmetic failure a reader has to decode.
        let source_tenant = item_str(binding, "source_tenant_ref");
        if source_tenant != tenant_ref {
            return refuse(
                &spec.code("cross_tenant_source_refused"),
                format!(
                    "source '{}' carries {source_tenant} while this view is bound to {tenant_ref}; a source belonging to another tenant is inadmissible rather than a discovery at materialization, by which time the protected bytes are already moving",
                    item_str(binding, "source_ref")
                ),
            );
        }
    }

    // EVERY SOURCE ROW RESOLVES THROUGH ITS OWNER, OR THE VIEW DOES NOT EXIST. The scheme routes to
    // the module that owns the family, the owner answers under this caller's own binding, and the
    // committed hash must be what that owner serves right now.
    let resolved_sources =
        match verify_source_bindings(&st.data_dir, &caller.identity, &source_bindings) {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };

    // ---------------------------------------------------- field minimization, checked one at a time
    let allowed_field_refs = match ref_list(&body, "allowed_field_refs", 256, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    if allowed_field_refs.is_empty() {
        return refuse(
            &spec.code("field_scope_required"),
            "'allowed_field_refs' names at least one field; a view that allows no field cannot be materialized and cannot be reviewed",
        );
    }
    let decisions = match object_list(&body, "field_minimization_decisions", 256, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let decided: BTreeSet<String> = decisions
        .iter()
        .map(|decision| item_str(decision, "field_ref"))
        .collect();
    // THE EXCESS-FIELD REFUSAL, IN BOTH DIRECTIONS. A field admitted without its own justification
    // leaves the covering short; a decision for a field the view does not allow makes it long.
    if let Some(unjustified) = allowed_field_refs
        .iter()
        .find(|field_ref| !decided.contains(*field_ref))
    {
        return refuse(
            &spec.code("excess_field_without_a_decision"),
            format!("'{unjustified}' is allowed with no per-field minimization decision naming which source it comes from and why the purpose needs it; 'useful' is not a minimization basis"),
        );
    }
    if let Some(orphan) = decided
        .iter()
        .find(|field_ref| !allowed_field_refs.iter().any(|held| held == *field_ref))
    {
        return refuse(
            &spec.code("minimization_decision_without_a_field"),
            format!("'{orphan}' carries a minimization decision but is not in the allowed field set; the covering must be exact in both directions"),
        );
    }
    let field_scope = json!({
        "allowed_field_refs": allowed_field_refs,
        "allowed_field_count": allowed_field_refs.len(),
        "field_minimization_decisions": decisions,
    });

    let row_scope = match body_object(&body, "row_scope", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let time_scope = match body_object(&body, "time_scope", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let retention_and_hold = match body_object(&body, "retention_and_hold", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let destination_and_egress = match body_object(&body, "destination_and_egress", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let redaction = match body_object(&body, "redaction", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };

    // ---------------------------------------------- redaction reduces exposure and creates nothing
    let privacy_class = body_str(&body, "privacy_class");
    if privacy_class.is_empty() {
        return refuse(
            &spec.code("privacy_class_required"),
            "'privacy_class' is the source classification this projection inherits, and the anchor of the declassification refusal",
        );
    }
    if redaction.get("creates_permission").and_then(Value::as_bool) != Some(false)
        || redaction.get("severs_lineage").and_then(Value::as_bool) != Some(false)
    {
        return refuse(
            &spec.code("redaction_claims_permission_or_severed_lineage"),
            "redaction reduces exposure; it creates no right and it never severs lineage, and a record that claims otherwise is refused rather than silently corrected — a repaired claim is a claim that was made and not recorded",
        );
    }
    let output_class = redaction
        .get("output_privacy_class")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if output_class != privacy_class {
        return refuse(
            &spec.code("redaction_declassifies"),
            format!("the redaction output is classed '{output_class}' while the source is '{privacy_class}'; lowering a class through a transformation is reclassification, which is a governed act with its own approval, rights and receipts — never a side effect of masking a column"),
        );
    }
    if destination_and_egress
        .get("cross_tenant_read_permitted")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return refuse(
            &spec.code("cross_tenant_read_refused"),
            "cross-tenant learning and reuse are default-deny at the boundary, and this view is not the place they become available; a cohort program binds its own separate objects",
        );
    }
    if destination_and_egress
        .get("declassification_permitted_without_approval")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return refuse(
            &spec.code("declassification_without_approval_refused"),
            "moving protected material across a sovereign boundary is a declassification event requiring its own approval, rights and receipts; a view can never be the approval",
        );
    }

    // ------------------------------------------------------------------------- consent, at admission
    let consent_bindings = match object_list(&body, "consent_bindings", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    if consent_bindings.is_empty() {
        return refuse(
            &spec.code("consent_bindings_required"),
            "'consent_bindings' names at least one resolved consent; binding one records that a consent was resolved, and this record is never itself the consent",
        );
    }
    if let Some(stale) = consent_bindings
        .iter()
        .find(|binding| item_str(binding, "consent_state") != "active")
    {
        return refuse(
            &spec.code("consent_binding_not_active"),
            format!(
                "consent '{}' reads '{}'; a view carrying an expired, revoked, withdrawn or unknown consent cannot be admitted at all — the non-active states exist so a state can be recorded honestly on the way to a successor revision, never so a live projection can carry one",
                item_str(stale, "consent_ref"),
                item_str(stale, "consent_state")
            ),
        );
    }

    // ============================================ every input crosses its OWNER'S read-only seam
    let boundary_ref = body_str(&body, "boundary_profile_revision_ref");
    let boundary = match resolve_admitted_boundary_profile(
        &st.data_dir,
        &caller.identity,
        Some(&caller.owner_ref),
        &boundary_ref,
    ) {
        Ok(boundary) => boundary,
        Err(response) => return response,
    };
    // The registered contract PINS `boundary_status_at_binding` to `active`, because a draft,
    // suspended, superseded or revoked boundary carries no permitted uses: a projection bound to one
    // would be bound to nothing while looking bound to something. Refusing by name here says which
    // state it was in.
    if !boundary.is_active() {
        return refuse(
            &spec.code("boundary_not_active"),
            format!(
                "boundary '{}' is '{}', not active; a view cannot be compiled against a boundary that carries no permitted uses",
                boundary.revision_ref,
                boundary
                    .record
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unreadable")
            ),
        );
    }
    if boundary.tenant_ref != tenant_ref {
        return refuse(
            &spec.code("cross_tenant_boundary_refused"),
            format!(
                "boundary '{}' is bound to {} while this view is bound to {tenant_ref}",
                boundary.revision_ref, boundary.tenant_ref
            ),
        );
    }
    // THE STALE-POLICY ASSERTION TWIN. A caller may ASSERT which compiled policy it believes it is
    // binding and be refused by name when the boundary has moved underneath it; it may never AUTHOR
    // the hash, which is what `effective_boundary_binding` being server-resolved enforces.
    if let Some(asserted) = body
        .get("expected_effective_learning_boundary_hash")
        .and_then(Value::as_str)
    {
        if asserted != boundary.compiled_policy_hash {
            return refuse(
                &spec.code("stale_policy_binding"),
                "expected_effective_learning_boundary_hash does not match the policy this boundary revision actually compiled to; the boundary moved after this request was prepared, and a view compiled against a policy that is no longer the one it names is exactly the stale binding canon refuses",
            );
        }
    }

    let claim_refs = match ref_list(&body, "source_rights_claim_revision_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    if claim_refs.is_empty() {
        return refuse(
            &spec.code("source_rights_claims_required"),
            "at least one source-rights claim revision is required; a projection of protected data with no rights claim behind it has no basis to narrow against",
        );
    }
    let mut claims: Vec<ResolvedSourceRightsClaim> = Vec::with_capacity(claim_refs.len());
    for claim_ref in &claim_refs {
        match resolve_admitted_source_rights_claim(
            &st.data_dir,
            &caller.identity,
            Some(&caller.owner_ref),
            claim_ref,
        ) {
            Ok(claim) => claims.push(claim),
            Err(response) => return response,
        }
    }
    // CONSENT IS COVERED BY A CLAIM, OR IT IS NOT BOUND AT ALL. Canon carries a consent as a
    // `rights_basis_ref` on a `LearningSourceRightsClaim`; there is no consent family to resolve. So
    // every bound consent ref must appear as a basis on one of the claims resolved above — which is
    // what makes its revocation and expiry recheckable at the read, through that claim's own
    // `is_live()` and `expires_before()`. A consent held entirely outside any admitted claim is
    // refused here rather than trusted from the `consent_state` the caller attested, because an
    // attested state is not a state anyone can recheck.
    let claim_bases: BTreeSet<String> = claims
        .iter()
        .flat_map(|claim| claim.rights_basis_refs())
        .collect();
    for binding in &consent_bindings {
        let consent_ref = item_str(binding, "consent_ref");
        if !claim_bases.contains(&consent_ref) {
            return refuse(
                &spec.code("consent_not_covered_by_a_bound_claim"),
                format!(
                    "consent '{consent_ref}' is not a rights basis on any bound source-rights claim, so nothing can revalidate its revocation or expiry at read time. Canon carries a consent as a basis on a LearningSourceRightsClaim; this seam mints no consent family to stand in for one"
                ),
            );
        }
    }

    let route_refs = match ref_list(&body, "route_rights_revision_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let mut routes: Vec<ResolvedModelRouteRights> = Vec::with_capacity(route_refs.len());
    for route_ref in &route_refs {
        match resolve_admitted_model_route_rights_contract(
            &st.data_dir,
            &caller.identity,
            Some(&caller.owner_ref),
            route_ref,
        ) {
            Ok(route) => routes.push(route),
            Err(response) => return response,
        }
    }

    // A BROKERED DESTINATION NEEDS AN ADMITTED AUTHORITY OBJECT THAT COVERS IT. This module models no
    // provider connection — that is wallet.network's `ProviderConnectionBinding` and is outside this
    // contract's closed vocabulary — so the coverage it CAN check is the route-rights ceiling M07.2
    // owns. A permitted destination class that leaves the boundary with no route contract admitting
    // it is refused; the crossing itself still needs its own `LearningEgressReceipt`.
    let route_destinations: BTreeSet<String> = routes
        .iter()
        .flat_map(|route| route.permitted_destination_classes())
        .collect();
    let permitted_destination_classes: Vec<String> = destination_and_egress
        .get("permitted_destination_classes")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    for class in &permitted_destination_classes {
        if BROKERED_DESTINATION_CLASSES.contains(&class.as_str())
            && !route_destinations.contains(class)
        {
            return refuse(
                &spec.code("brokered_destination_without_admitted_authority"),
                format!(
                    "destination class '{class}' puts projected material in another party's hands and no bound route-rights contract admits it. This seam models no provider connection and does not mint one: the refusal is the correct output, and a stand-in would be a second authority plane"
                ),
            );
        }
    }

    // THE MAPPING FENCE. Every mapping ref crosses M05.7's read-only owner seam, so the shape this
    // view claims to scope is an EXACT admitted revision rather than a name — a family head or an
    // absent revision is refused by that owner, not shape-checked here.
    //
    // THE REGISTRY-STATUS CHECK IS DELIBERATELY NOT HERE. A mapping may be deprecated or revoked
    // AFTER a view binds it, and `succession.reinterprets_predecessor` is pinned false precisely
    // because a later narrowing does not retroactively unmake an admitted record: it blocks future
    // materialization. So the status is checked at the READ, where the narrowing takes effect, and
    // a view bound to an already-deprecated mapping is admissible and simply never materializes.
    let mapping_refs = match ref_list(&body, "connector_mapping_revision_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    for mapping_ref in &mapping_refs {
        if let Err(response) = super::data_transformation_routes::resolve_admitted_connector_mapping(
            &st.data_dir,
            &caller.identity,
            mapping_ref,
        ) {
            return response;
        }
    }
    // THE ONTOLOGY FENCE. Exact admitted revisions through M05.1's owner seam. The predecessor
    // carried one head-following `ontology_ref` copied out of its mapping, which is the drift this
    // resolution ends: a view bound to a family head projects whatever the ontology becomes.
    let ontology_refs = match ref_list(&body, "ontology_revision_refs", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    for ontology_ref in &ontology_refs {
        if let Err(response) = super::ontology_version_routes::resolve_admitted_revision(
            &st.data_dir,
            &caller.identity,
            ontology_ref,
        ) {
            return response;
        }
    }
    // THE RECIPE SUBSTITUTION FENCE, WITH NO FALLBACK. The redaction recipe must resolve to an exact
    // admitted DataRecipe revision whose committed bytes hash to what this view commits. There is no
    // opaque-ref path: a recipe nobody can resolve is a transformation nobody can reproduce, and
    // admitting one would let an unreproducible projection carry a reproducible-looking record.
    let recipe_ref = redaction
        .get("recipe_revision_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let recipe_hash = redaction
        .get("recipe_content_hash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if !recipe_ref.starts_with("data-recipe://") {
        return refuse(
            &spec.code("redaction_recipe_not_owner_resolvable"),
            "'redaction.recipe_revision_ref' names an exact owned DataRecipe revision as 'data-recipe://<family>/revision/<n>'; an opaque ref cannot be resolved, so the transformation it names cannot be reproduced",
        );
    }
    let recipe = match super::data_transformation_routes::resolve_admitted_data_recipe(
        &st.data_dir,
        &caller.identity,
        &recipe_ref,
    ) {
        Ok(recipe) => recipe,
        Err(response) => return response,
    };
    if recipe.content_hash != recipe_hash {
        return refuse(
            &spec.code("redaction_recipe_substituted"),
            format!("redaction recipe '{recipe_ref}' hashes to {} while this view commits {recipe_hash}; the transformation that produced this projection must be the one the record names, or the projection is not reproducible", recipe.content_hash),
        );
    }

    // ================================================================== the permission, by subtraction
    let registry_status = {
        let raw = body_str(&body, "registry_status");
        if raw.is_empty() {
            "active".to_string()
        } else {
            raw
        }
    };
    let ordinal = stream.len() as u64 + 1;
    let revision_ref = format!("{resource}/revision/{ordinal}");
    let mut intersection = UseIntersection::default();
    fold_purpose(&mut intersection, &purpose, &purpose_binding_ref);
    fold_boundary(&mut intersection, &boundary);
    for claim in &claims {
        fold_source_claim(&mut intersection, claim, recorded_at_ms);
    }
    for route in &routes {
        fold_route_contract(&mut intersection, route);
    }
    fold_view_state(
        &mut intersection,
        &registry_status,
        &retention_and_hold,
        &destination_and_egress,
        &revision_ref,
    );
    let rights_derived = intersection.permitted();
    let retention_state = retention_and_hold
        .get("retention_state")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // AN ACTIVE VIEW WITHIN RETENTION THAT PERMITS NOTHING IS INADMISSIBLE, and the registered
    // contract says so by requiring at least one use. Rather than emit a record its own contract
    // refuses, this seam refuses by name and reports the attribution — so an operator learns WHICH
    // input emptied the set instead of reading a schema arithmetic failure.
    if registry_status == "active"
        && retention_state == "within_retention"
        && rights_derived.is_empty()
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "ok": false,
                "error": {
                    "code": spec.code("no_use_survives_the_intersection"),
                    "message": "every use in the eight-use vocabulary was denied by a resolved input, so this active, in-retention view would permit nothing; a projection that permits nothing is refused rather than admitted as an empty permission nobody notices",
                },
                "denied_uses": intersection.attributions(),
            })),
        );
    }

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
            let reason = body_str(&body, "succession_reason");
            if !SUCCESSION_REASONS.contains(&reason.as_str()) || reason == "genesis" {
                return refuse(
                    &spec.code("succession_reason_required"),
                    "a successor revision names WHY it exists, from this contract's closed reason vocabulary; a restatement with no reason is a lineage nobody can review",
                );
            }
            json!({
                "succession_reason": reason,
                "predecessor_revision_ref": entry.record.get("revision_ref").cloned().unwrap_or(Value::Null),
                "predecessor_content_hash": entry.record.get("content_hash").cloned().unwrap_or(Value::Null),
                "supersedes_predecessor": true,
                // PINNED. A narrowed view does not retroactively unmake a read admitted under the
                // wider one; it blocks future materialization and leaves the historical evidence
                // exactly as admitted, which is what keeps an impact graph honest.
                "reinterprets_predecessor": false,
            })
        }
    };

    let migration = match body.get("converge_from_view_ref").and_then(Value::as_str) {
        None => json!({
            "from_schema_version": Value::Null,
            "from_view_ref": Value::Null,
            "from_content_hash": Value::Null,
            "compatibility": "initial",
            "reinterprets_predecessor": false,
            "downgrade_to_predecessor": "refused",
            "downgrade_refusal_reason": "v1_cannot_express_revision_identity_source_revisions_field_minimization_rights_consent_boundary_hash_or_commitment",
        }),
        Some(legacy_ref) => match converge_from_legacy(&st.data_dir, legacy_ref) {
            Ok(migration) => migration,
            Err(response) => return response,
        },
    };

    let data_classes = match ref_list(&body, "data_classes", 12, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let object_model_refs = match ref_list(&body, "object_model_refs", 64, spec) {
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
    let does_not_assert = match vocabulary_list(
        &body,
        "additional_does_not_assert",
        DOES_NOT_ASSERT_VOCABULARY,
        spec,
    ) {
        Ok(extra) => {
            let mut all: Vec<String> = DEFAULT_DOES_NOT_ASSERT
                .iter()
                .map(|token| (*token).to_string())
                .collect();
            for token in extra {
                if !all.iter().any(|held| *held == token) {
                    all.push(token);
                }
            }
            all
        }
        Err(response) => return response,
    };

    let record = json!({
        "schema_version": spec.schema_version,
        "policy_bound_data_view_id": resource,
        "revision_ref": revision_ref,
        "owner_ref": caller.owner_ref,
        "tenant_ref": tenant_ref,
        // PINNED, AND THE REF BESIDE IT IS RESOLVED TOO. The predecessor accepted free-form subject
        // strings including wildcards it could only downgrade to `draft`; this is the authenticated
        // request's own principal, so a view that reads "for whoever asks" is unrepresentable.
        "principal_resolution": "server_resolved",
        "resolved_principal_ref": caller.identity.principal_ref,
        "purpose": purpose,
        "purpose_binding_ref": purpose_binding_ref,
        "source_bindings": source_bindings,
        "source_binding_count": source_bindings.len(),
        "ontology_revision_refs": ontology_refs,
        "connector_mapping_revision_refs": mapping_refs,
        "object_model_refs": object_model_refs,
        "row_scope": row_scope,
        "field_scope": field_scope,
        "time_scope": time_scope,
        "data_classes": data_classes,
        "privacy_class": privacy_class,
        "source_rights_claim_revision_refs": claim_refs,
        "consent_bindings": consent_bindings,
        "route_rights_revision_refs": route_refs,
        "jurisdiction_refs": jurisdiction_refs,
        "residency_refs": residency_refs,
        "redaction": redaction,
        "retention_and_hold": retention_and_hold,
        "destination_and_egress": destination_and_egress,
        // SERVER-RESOLVED FROM ONE RESOLUTION, WHICH IS WHAT MAKES THE STALE-POLICY INVARIANT CLOSE.
        // Both hashes below come from the same resolved boundary revision, so the pair cannot be
        // moved independently by anyone who is not tampering with the durable record itself.
        "effective_boundary_binding": {
            "boundary_profile_revision_ref": boundary.revision_ref,
            "boundary_profile_content_hash": boundary.content_hash,
            "effective_learning_boundary_hash": boundary.compiled_policy_hash,
            "boundary_status_at_binding": "active",
        },
        "materialization_precondition": {
            "revalidate_before_materialization": true,
            // ALL EIGHT, because this build rechecks all eight at the materialization instant. The
            // contract makes four mandatory; naming only those would understate what is enforced.
            "revalidated_facts": REVALIDATED_FACTS,
            "required_effective_learning_boundary_hash": boundary.compiled_policy_hash,
            "fails_closed_on_missing_or_conflicting_policy": true,
        },
        "allowed_uses": rights_derived,
        "rights_derived_allowed_uses": rights_derived,
        // PINNED EMPTY. The field exists so the redaction-as-permission claim has somewhere to be
        // made and be refused; this seam never writes a member into it.
        "redaction_derived_allowed_uses": Vec::<String>::new(),
        "registry_status": registry_status,
        "admitted_at": admitted_stamp(recorded_at_ms),
        "succession": succession,
        "migration": migration,
        "constants": {
            "lifecycle_id": "policy_bound_data_view_registry_lifecycle.v2",
            "consent_state_active_token": "active",
            "refused_legacy_view_scheme": LEGACY_VIEW_SCHEME,
            "nonclaim_authority_token": "authority",
            "nonclaim_redaction_permission_token": "redaction_creates_permission",
            "nonclaim_consent_token": "consent",
        },
        "authority_nonclaim": "policy_bound_data_view_grants_no_authority",
        "truth_nonclaim": "policy_bound_data_view_is_a_bounded_projection_not_consent_permission_or_semantic_truth",
        "does_not_assert": does_not_assert,
    });

    finish_admission(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        "policy_bound_data_view",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        json!({
            "denied_uses": intersection.attributions(),
            "redaction_recipe_revision_resolved": recipe.revision_ref,
            // WHAT EACH SOURCE OWNER ACTUALLY SERVED, returned so an operator can see that every
            // bound row was resolved rather than accepted, and against which hash.
            "resolved_source_revisions": resolved_sources,
            "consent_refs_covered_by_bound_claims": consent_bindings.len(),
            "a_view_is_a_projection_not_a_permission": true,
        }),
    )
}

/// GET /v1/hypervisor/policy-bound-data-views — the caller's inventory, one family, or one revision.
pub(crate) async fn handle_policy_bound_data_view_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    family_query(&VIEW, "policy_bound_data_view_refs", st, &headers, query)
}

// ========================================================== the materialization decision family
//
// A DAEMON-LOCAL RECORD, AND SAID SO. `PolicyBoundDataView` v2 is a registered contract and every
// admitted revision above is validated against it. This family has no registered contract: it is
// projected, re-hashed and owner-scoped exactly like a registered one, but no architecture contract
// is claimed for it and this module does not mint one. The chain machinery in
// `model_route_rights_routes` validates a registered contract on every projection, so the ~40 lines
// below are the one place this module cannot reuse it — the duplication is the honest cost of not
// inventing a contract to make a helper fit.

const MAT_OWNER_NAMESPACE: &str = "policy-bound-data-view-materializations";
const MAT_RESOURCE_KIND: &str = "policy_bound_data_view_materialization";
const MAT_ADMIT_OP: &str = "event_stream.policy_bound_data_view_materialization_decided";
const MAT_PAYLOAD_SCHEMA: &str =
    "ioi.hypervisor.policy-bound-data-view-materialization-decision-admission.v1";
const MAT_RECORD_SCHEMA: &str = "ioi.hypervisor.policy-bound-data-view-materialization-decision.v1";
const MAT_RECORD_KEY: &str = "policy_bound_data_view_materialization_record";
const MAT_CODE_PREFIX: &str = "policy_bound_data_view_materialization";
const MAT_REF_SCHEME: &str = "materialization://";
const MAT_COMMITMENT_DOMAIN: &str =
    "ioi.policy-bound-data-view-materialization-decision-commitment-jcs-sha256.v1";
const MAT_MATERIAL_FIELDS: &[&str] = &[
    "schema_version",
    "materialization_id",
    "materialization_ref",
    "owner_ref",
    "tenant_ref",
    "principal_resolution",
    "resolved_principal_ref",
    "policy_bound_data_view_revision_ref",
    "policy_bound_data_view_content_hash",
    "view_registry_status_at_decision",
    "requested_use",
    "requested_projection",
    "observed_source_revisions",
    "revalidated_facts",
    "revalidation_findings",
    "effective_boundary_binding_at_decision",
    "granted_projection",
    "decision",
    "refusal_codes",
    "emitted_at",
    "constants",
    "authority_nonclaim",
    "truth_nonclaim",
    "does_not_assert",
];

fn mat_code(suffix: &str) -> String {
    format!("{MAT_CODE_PREFIX}_{suffix}")
}

/// Project ONE admitted materialization decision, re-deriving its commitment rather than trusting it.
fn project_materialization(entry: &ExactProjection) -> Result<AdmittedRecord, String> {
    if entry.operation.op_kind != MAT_ADMIT_OP {
        return Err(format!(
            "{MAT_CODE_PREFIX} stream carries an unknown operation '{}'",
            entry.operation.op_kind
        ));
    }
    let payload = &entry.operation.payload;
    if payload.get("schema_version").and_then(Value::as_str) != Some(MAT_PAYLOAD_SCHEMA) {
        return Err(format!(
            "{MAT_CODE_PREFIX} admission carries an unknown payload schema"
        ));
    }
    let record = payload
        .get(MAT_RECORD_KEY)
        .cloned()
        .ok_or_else(|| format!("{MAT_CODE_PREFIX} admission carries no record"))?;
    if record.get("schema_version").and_then(Value::as_str) != Some(MAT_RECORD_SCHEMA) {
        return Err(format!(
            "{MAT_CODE_PREFIX} chain holds a record this build does not implement"
        ));
    }
    let derived = digest_over(&record, MAT_COMMITMENT_DOMAIN, MAT_MATERIAL_FIELDS)?;
    if record.get("content_hash").and_then(Value::as_str) != Some(derived.as_str()) {
        return Err(format!(
            "{MAT_CODE_PREFIX} admitted content does not match its committed hash"
        ));
    }
    let stamped = admitted_stamp(entry.operation.recorded_at_ms);
    if record.get("emitted_at").and_then(Value::as_str) != Some(stamped.as_str()) {
        return Err(format!(
            "{MAT_CODE_PREFIX} record's emitted_at is not the stamp of its own admission"
        ));
    }
    let resource = payload
        .get("resource_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let tail = stream_tail(MAT_RESOURCE_KIND, resource);
    let admission = json!({
        "owner_namespace": MAT_OWNER_NAMESPACE,
        "stream_tail": tail,
        "admission_domain_ref": format!(
            "agentgres://domain/{}",
            agentgres::refs::event_stream_domain(MAT_OWNER_NAMESPACE, &tail)
        ),
        "agentgres_operation_ref": agentgres::refs::event_stream_operation_ref(
            MAT_OWNER_NAMESPACE, &tail, entry.seq, &entry.head,
        ),
        "agentgres_receipt_ref": agentgres::refs::event_stream_receipt_ref(
            MAT_OWNER_NAMESPACE, &tail, entry.admission_batch_seq, &entry.admission_root,
        ),
        "admission_seq": entry.seq,
        "admission_head": entry.head,
        "admission_root": entry.admission_root,
        "expected_predecessor_head": entry
            .operation
            .expected_head
            .clone()
            .map_or(Value::Null, Value::String),
    });
    Ok(AdmittedRecord {
        record,
        admission,
        head: entry.head.clone(),
        recorded_at_ms: entry.operation.recorded_at_ms,
    })
}

fn read_materialization_stream(
    data_dir: &str,
    identity: &RequestIdentity,
    scope: &super::substrate_store::RequestResourceScope,
    resource: &str,
) -> Result<Vec<AdmittedRecord>, Reply> {
    let history = read_owner_scoped_history(
        data_dir,
        identity,
        scope,
        MAT_RESOURCE_KIND,
        resource,
        MAT_OWNER_NAMESPACE,
        &stream_tail(MAT_RESOURCE_KIND, resource),
    )
    .map_err(mutation_refusal_reply)?;
    history
        .iter()
        .map(project_materialization)
        .collect::<Result<Vec<_>, String>>()
        .map_err(|reason| {
            bad(
                StatusCode::BAD_GATEWAY,
                &mat_code("projection_failed"),
                reason,
            )
        })
}

// ------------------------------------------------------------------------------- the revalidation

/// The accumulated result of rechecking the whole policy at the materialization instant.
///
/// `refusals` is the whole decision: `materialized` is `refusals.is_empty()`, so a grant is the
/// complement of everything that denied the read rather than a branch someone has to remember to
/// take. A check that records a finding but no refusal has, by construction, not stopped anything.
#[derive(Default)]
struct Revalidation {
    findings: Vec<Value>,
    refusals: Vec<String>,
}

impl Revalidation {
    fn note(&mut self, fact: &str, outcome: &str, governing_ref: &str, detail: &str) {
        self.findings.push(json!({
            "fact": fact,
            "outcome": outcome,
            "governing_ref": governing_ref,
            "detail": detail,
        }));
    }

    /// A fact that could not be established DENIES the disputed read. Every refusal also lands as a
    /// finding, so the record explains itself rather than carrying an opaque code list.
    fn deny(&mut self, fact: &str, code: &str, governing_ref: &str, detail: &str) {
        self.note(fact, "denied", governing_ref, detail);
        let code = mat_code(code);
        if !self.refusals.contains(&code) {
            self.refusals.push(code);
        }
    }
}

/// An RFC3339 stamp that has already passed at `at_ms`. A null or absent stamp is NOT expiry.
fn expired_at(stamp: Option<&str>, at_ms: u64) -> bool {
    match stamp {
        None => false,
        Some(value) => {
            let until = agentgres::parse_rfc3339_ms(value);
            until != 0 && until <= at_ms
        }
    }
}

/// Fields the SERVER resolves on a materialization decision.
const MAT_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "materialization_id",
    "materialization_ref",
    "tenant_ref",
    "principal_resolution",
    "policy_bound_data_view_content_hash",
    "view_registry_status_at_decision",
    "revalidated_facts",
    "revalidation_findings",
    "effective_boundary_binding_at_decision",
    "granted_projection",
    "decision",
    "refusal_codes",
    "emitted_at",
    "constants",
    "authority_nonclaim",
    "truth_nonclaim",
    "content_hash",
];

/// POST /v1/hypervisor/policy-bound-data-view-materializations — THE ENFORCEMENT POINT.
///
/// This is the only place a bounded projection of protected source data is granted. It resolves the
/// exact view revision through this module's own owner seam, revalidates all eight named facts
/// against their OWNERS at the materialization instant, intersects the request against the view, and
/// records the decision on the durable chain whether it granted or refused.
///
/// THE GRANT IS A DESCRIPTOR, NOT A COPY. `granted_projection` names which fields, which committed
/// row predicate under which ceiling, and which time window on which timebase may be read. No
/// protected byte enters this record, and the record non-claims custody of any materialized payload.
pub(crate) async fn handle_policy_bound_data_view_materialize(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        contract_owner_ref(&caller.owner_ref, &mat_code("owner_scheme_unsupported"))
    {
        return response;
    }
    for field in MAT_SERVER_RESOLVED {
        if body.get(*field).is_some() {
            return refuse(
                &mat_code("caller_authored_evidence_refused"),
                format!("'{field}' is resolved by the server from the durable view, the owner seams and the admitted operation; a decision taken over self-supplied constants is void for conformance purposes"),
            );
        }
    }
    let family = body_str(&body, "family");
    if !family_token(&family) {
        return refuse(
            &mat_code("family_not_canonical"),
            "'family' is the lineage token this decision extends: [a-z0-9][a-z0-9._-]{0,127}",
        );
    }
    let resource = format!("{MAT_REF_SCHEME}{family}");
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        MAT_RESOURCE_KIND,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream =
        match read_materialization_stream(&st.data_dir, &caller.identity, &scope, &resource) {
            Ok(stream) => stream,
            Err(response) => return response,
        };
    // REPLAY BEFORE PRECONDITIONS, and before any revalidation: a retried materialization resolves
    // to the decision it already took rather than taking a second one against a moved world.
    match prior_admission_for_key_on_stream(
        &st.data_dir,
        &caller.identity,
        &scope,
        MAT_RESOURCE_KIND,
        &resource,
        MAT_OWNER_NAMESPACE,
        &stream_tail(MAT_RESOURCE_KIND, &resource),
        &caller.idempotency_key,
    ) {
        Ok(Some(prior)) => {
            let Some(entry) = stream.iter().find(|entry| entry.head == prior.head) else {
                return bad(
                    StatusCode::BAD_GATEWAY,
                    &mat_code("projection_disagrees_with_ack"),
                    "this key's admitted head is absent from this stream's projection",
                );
            };
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "replayed": true,
                    "policy_bound_data_view_materialization": entry.record,
                    "admission": entry.admission,
                    "expected_head_for_successor": stream.last().map(|last| last.head.clone()),
                    "index_state": projection_cache_state(&resource, &stream),
                })),
            );
        }
        Ok(None) => {}
        Err(error) => return mutation_refusal_reply(error),
    }
    let expected_head = match head_assertion(&body, MAT_CODE_PREFIX) {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, MAT_CODE_PREFIX) {
        return response;
    }
    let at_ms = agentgres::parse_rfc3339_ms(&body_str(&body, "effective_at"));
    if at_ms == 0 {
        return refuse(
            &mat_code("effective_at_not_canonical"),
            "'effective_at' is the RFC3339 instant this decision is taken at; every expiry below is measured against it, so an absent or malformed stamp reads as absent rather than as zero-o'clock",
        );
    }

    // ============================================================ resolve the view, through the seam
    let view_ref = body_str(&body, "policy_bound_data_view_revision_ref");
    let view = match resolve_admitted_policy_bound_data_view(
        &st.data_dir,
        &caller.identity,
        Some(&caller.owner_ref),
        &view_ref,
    ) {
        Ok(view) => view,
        Err(response) => return response,
    };
    let mut check = Revalidation::default();
    // CURRENT AUTHORITY. The resolution above crossed the owner-scoped seam under this caller's own
    // principal binding, so a cross-principal read was refused before any bytes were returned. That
    // is the fact being recorded — not that a caller asserted it.
    check.note(
        "current_authority",
        "resolved_through_the_owner_scoped_seam",
        &view.revision_ref,
        "the view was resolved under this caller's own principal and owner binding; a cross-principal read is refused at the scope boundary before any bytes are read",
    );
    let tenant_ref = contract_tenant_ref(&caller.owner_ref);
    if view.tenant_ref != tenant_ref {
        check.deny(
            "current_authority",
            "cross_tenant_read_refused",
            &view.revision_ref,
            "this view is bound to another tenant; cross-tenant reuse is default-deny and a view is never the place it becomes available",
        );
    }

    let registry_status = view
        .record
        .get("registry_status")
        .and_then(Value::as_str)
        .unwrap_or("revoked")
        .to_string();
    if !view.is_active() {
        check.deny(
            "revocation_state",
            "view_not_active",
            &view.revision_ref,
            "only an active view carries uses; suspension, expiry, supersession and revocation narrow immediately rather than waiting for a reader to compare timestamps",
        );
    } else {
        check.note(
            "revocation_state",
            "active",
            &view.revision_ref,
            "the view revision is active",
        );
    }

    // RETENTION, HOLD AND EXPIRY — read off the view, measured against this instant.
    let retention = view
        .record
        .get("retention_and_hold")
        .cloned()
        .unwrap_or(Value::Null);
    let retention_state = retention
        .get("retention_state")
        .and_then(Value::as_str)
        .unwrap_or("retention_elapsed");
    if retention_state != "within_retention" {
        check.deny(
            "retention_and_hold",
            "retention_not_current",
            &view.revision_ref,
            "elapsed retention, pending deletion and deletion all empty the permission",
        );
    } else {
        check.note(
            "retention_and_hold",
            "within_retention",
            &view.revision_ref,
            "retention is current",
        );
    }
    let hold_state = retention
        .get("hold_state")
        .and_then(Value::as_str)
        .unwrap_or("none")
        .to_string();
    if expired_at(retention.get("expires_at").and_then(Value::as_str), at_ms) {
        check.deny(
            "expiry",
            "view_expired",
            &view.revision_ref,
            "the view's own retention window closed before this instant",
        );
    } else {
        check.note(
            "expiry",
            "within_window",
            &view.revision_ref,
            "the view has not expired at this instant",
        );
    }

    // CURRENT RIGHTS — every claim re-resolved through M10.3's seam and re-expired here. The
    // resolved claims are kept, because they are also what revalidates CONSENT below: a consent is a
    // basis on a claim, so the claim's liveness and validity window are the consent's too.
    let mut live_claims: Vec<ResolvedSourceRightsClaim> = Vec::new();
    for claim_ref in view.list("/source_rights_claim_revision_refs") {
        match resolve_admitted_source_rights_claim(
            &st.data_dir,
            &caller.identity,
            Some(&caller.owner_ref),
            &claim_ref,
        ) {
            Err(_) => check.deny(
                "current_rights",
                "source_right_unresolvable",
                &claim_ref,
                "a bound source-rights claim could not be resolved at this instant; an unestablished right denies the disputed read rather than falling back to the last known permission",
            ),
            Ok(claim) => {
                if !claim.is_live() {
                    check.deny(
                        "current_rights",
                        "source_right_not_current",
                        &claim_ref,
                        "the claim left the live pair after this view was admitted",
                    );
                } else if claim.expires_before(at_ms) {
                    check.deny(
                        "expiry",
                        "source_right_expired",
                        &claim_ref,
                        "the claim's validity window closed before this instant; its own bytes still carry every permission, which is exactly why the recheck is at read time",
                    );
                } else {
                    check.note("current_rights", "live", &claim_ref, "the source-rights claim is current");
                    live_claims.push(claim);
                }
            }
        }
    }

    // CONSENT STATE — REVALIDATED THROUGH THE CLAIM THAT CARRIES IT. Admission required every bound
    // consent to be a rights basis on one of these claims, so the consent's revocation and expiry
    // are exactly that claim's `is_live()` and `expires_before()`. A consent whose covering claim
    // dropped out of the live set above is no longer covered, and the read is denied on the consent
    // by name rather than only on the claim — the two are different facts to an operator reading the
    // decision, even when one causes the other.
    let live_bases: BTreeSet<String> = live_claims
        .iter()
        .flat_map(|claim| claim.rights_basis_refs())
        .collect();
    for binding in view
        .record
        .get("consent_bindings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let consent_ref = item_str(&binding, "consent_ref");
        if live_bases.contains(&consent_ref) {
            check.note(
                "consent_state",
                "covered_by_a_live_claim",
                &consent_ref,
                "the claim carrying this consent as a rights basis is live and within its validity window at this instant",
            );
        } else {
            check.deny(
                "consent_state",
                "consent_not_current",
                &consent_ref,
                "no live, unexpired source-rights claim still carries this consent as a rights basis, so nothing supports it at this instant",
            );
        }
    }

    // ROUTE RIGHTS — the onward-use ceiling, rechecked through M07.2's seam. The destination classes
    // the LIVE contracts admit are collected, because they are the authority coverage a brokered
    // destination needs below.
    let mut live_route_destinations: BTreeSet<String> = BTreeSet::new();
    for route_ref in view.list("/route_rights_revision_refs") {
        match resolve_admitted_model_route_rights_contract(
            &st.data_dir,
            &caller.identity,
            Some(&caller.owner_ref),
            &route_ref,
        ) {
            Err(_) => check.deny(
                "current_rights",
                "route_right_unresolvable",
                &route_ref,
                "a bound route-rights contract could not be resolved at this instant",
            ),
            Ok(route) => {
                if route.is_live() {
                    check.note(
                        "current_rights",
                        "live",
                        &route_ref,
                        "the route contract is current",
                    );
                    live_route_destinations.extend(route.permitted_destination_classes());
                } else {
                    check.deny(
                        "revocation_state",
                        "route_right_not_current",
                        &route_ref,
                        "the route contract expired, was superseded, suspended or revoked after this view was admitted",
                    );
                }
            }
        }
    }

    // THE MAPPING REGISTRY STATUS — A MAPPING FACT, AND ONLY THAT. A deprecated or revoked mapping
    // means this view can no longer read the source shape it scoped, which is a real narrowing and is
    // enforced here under its own name. It is deliberately NOT presented as evidence about a provider
    // connection: this module models no connection at all, and reusing the word for something else is
    // how a second authority plane starts.
    for mapping_ref in view.list("/connector_mapping_revision_refs") {
        match super::data_transformation_routes::resolve_admitted_connector_mapping(
            &st.data_dir,
            &caller.identity,
            &mapping_ref,
        ) {
            Err(_) => check.deny(
                "current_rights",
                "connector_mapping_unresolvable",
                &mapping_ref,
                "a bound connector-mapping revision could not be resolved at this instant",
            ),
            Ok(mapping) if mapping.registry_status != "active" => check.deny(
                "revocation_state",
                "connector_mapping_not_active",
                &mapping_ref,
                "the mapping this view reads the source shape through is no longer active, so the shape it scoped is no longer readable",
            ),
            Ok(_) => check.note(
                "current_rights",
                "connector_mapping_active",
                &mapping_ref,
                "the connector mapping revision is active; this is a mapping fact and not a provider-connection fact",
            ),
        }
    }

    // THE EFFECTIVE LEARNING-BOUNDARY HASH — re-resolved, and required to be the same policy.
    let boundary_ref = view.text("/effective_boundary_binding/boundary_profile_revision_ref");
    let required_hash =
        view.text("/materialization_precondition/required_effective_learning_boundary_hash");
    let boundary_at_decision = match resolve_admitted_boundary_profile(
        &st.data_dir,
        &caller.identity,
        Some(&caller.owner_ref),
        &boundary_ref,
    ) {
        Err(_) => {
            check.deny(
                "current_authority",
                "boundary_unresolvable",
                &boundary_ref,
                "the compiled boundary this view was bound to could not be resolved at this instant; missing policy denies the disputed read and does not fall back",
            );
            Value::Null
        }
        Ok(boundary) => {
            if !boundary.is_active() {
                check.deny(
                    "revocation_state",
                    "boundary_not_active",
                    &boundary.revision_ref,
                    "the compiled boundary is no longer active, so it carries no permitted uses",
                );
            }
            if boundary.compiled_policy_hash != required_hash {
                check.deny(
                    "current_authority",
                    "stale_policy_binding",
                    &boundary.revision_ref,
                    "the policy this boundary now compiles to is not the one this view requires of a materialization; moving one without the other is exactly the stale binding canon refuses",
                );
            }
            if expired_at(
                boundary.record.get("expires_at").and_then(Value::as_str),
                at_ms,
            ) {
                check.deny(
                    "expiry",
                    "stale_policy_binding",
                    &boundary.revision_ref,
                    "the compiled boundary's own effective window closed before this instant, so the policy this view runs under has lapsed",
                );
            }
            if check
                .refusals
                .iter()
                .all(|code| !code.ends_with("stale_policy_binding"))
            {
                check.note(
                    "current_authority",
                    "policy_agrees",
                    &boundary.revision_ref,
                    "the compiled policy hash still equals the hash this view requires",
                );
            }
            json!({
                "boundary_profile_revision_ref": boundary.revision_ref,
                "boundary_profile_content_hash": boundary.content_hash,
                "effective_learning_boundary_hash": boundary.compiled_policy_hash,
                "boundary_status_at_decision": boundary.record.get("status").cloned().unwrap_or(Value::Null),
            })
        }
    };

    // EXACT SOURCE REVISIONS, RE-RESOLVED THROUGH THEIR OWNERS AT THE READ. This is the same
    // `verify_source_bindings` the admission ran, deliberately: a ref that still resolves while the
    // bytes behind it moved is exactly the silent re-admission the committed hash exists to catch,
    // and only a check at the read instant can catch it. A source whose owner no longer serves the
    // committed hash denies the read.
    let bound_bindings = view
        .record
        .get("source_bindings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    match verify_source_bindings(&st.data_dir, &caller.identity, &bound_bindings) {
        Ok(_) => check.note(
            "current_rights",
            "every_bound_source_still_serves_its_committed_hash",
            &view.revision_ref,
            "each bound source revision was re-resolved through its own family's owner seam and still hashes to what this view committed",
        ),
        Err((_, body)) => check.deny(
            "current_rights",
            "source_revision_not_current",
            &view.revision_ref,
            &format!(
                "a bound source revision no longer resolves to the bytes this view committed: {}",
                body.0
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or("its owner refused the resolution")
            ),
        ),
    }

    // AND THE READER'S OWN DECLARED SET IS CONTAINED BY IT. Resolution answers "is the bound source
    // still what it was"; containment answers the different question "is this read staying inside
    // what was bound". Both are needed: a read could name only resolvable sources and still name one
    // this view never bound.
    let observed = match object_list(&body, "observed_source_revisions", 64, &VIEW) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let bound = &bound_bindings;
    for seen in &observed {
        let matched = bound.iter().any(|binding| {
            item_str(binding, "source_ref") == item_str(seen, "source_ref")
                && item_str(binding, "source_revision_ref") == item_str(seen, "source_revision_ref")
                && item_str(binding, "source_content_hash") == item_str(seen, "source_content_hash")
        });
        if !matched {
            check.deny(
                "current_rights",
                "source_outside_the_bound_set",
                &item_str(seen, "source_ref"),
                "this source ref, revision and content hash are not a byte-exact member of the view's bound source set",
            );
        }
    }
    for binding in bound {
        if !observed.iter().any(|seen| {
            item_str(seen, "source_revision_ref") == item_str(binding, "source_revision_ref")
        }) {
            check.deny(
                "current_rights",
                "bound_source_absent_from_the_observed_set",
                &item_str(binding, "source_ref"),
                "a bound source revision is absent from the observed set; a partial read of a bound projection is not the projection",
            );
        }
    }
    let containment_held = check.refusals.iter().all(|code| {
        !code.ends_with("source_outside_the_bound_set")
            && !code.ends_with("bound_source_absent_from_the_observed_set")
    });
    if !observed.is_empty() && containment_held {
        check.note(
            "current_rights",
            "observed_sources_are_contained_by_the_bound_set",
            &view.revision_ref,
            "the observed set and the bound set agree exactly, and every member of the bound set was itself re-resolved through its owner above",
        );
    }

    // RESIDENCY, JURISDICTION, DESTINATION AND THE EGRESS CEILING.
    let destination = view
        .record
        .get("destination_and_egress")
        .cloned()
        .unwrap_or(Value::Null);
    let requested_destination = body_str(&body, "requested_destination_class");
    let requested_representation = body_str(&body, "requested_representation");
    let requested_region = body_str(&body, "requested_region_ref");
    let requested_jurisdiction = body_str(&body, "requested_jurisdiction_ref");
    let permitted_classes = view.list("/destination_and_egress/permitted_destination_classes");
    if !permitted_classes
        .iter()
        .any(|held| *held == requested_destination)
    {
        check.deny(
            "destination_class",
            "destination_class_refused",
            &view.revision_ref,
            "the requested destination class is outside the view's ceiling; a materialization may carry less than the ceiling permits and never more",
        );
    } else {
        check.note(
            "destination_class",
            "within_ceiling",
            &view.revision_ref,
            "the destination class is permitted",
        );
    }
    // A BROKERED CROSSING NEEDS AUTHORITY THAT IS STILL LIVE AT THE READ. Admission proved a route
    // contract admitted this class; a contract that has since lapsed takes the coverage with it. No
    // connection object is consulted here and none exists to consult — the route ceiling is the
    // authority this seam can resolve, and the crossing itself is still M10.3's egress receipt.
    if BROKERED_DESTINATION_CLASSES.contains(&requested_destination.as_str())
        && !live_route_destinations.contains(&requested_destination)
    {
        check.deny(
            "destination_class",
            "brokered_destination_without_admitted_authority",
            &view.revision_ref,
            "this destination puts projected material in another party's hands and no live route-rights contract admits it at this instant",
        );
    }
    let ceiling = destination
        .get("egress_ceiling")
        .and_then(Value::as_str)
        .unwrap_or("no_egress");
    if !ceiling_representations(ceiling).contains(&requested_representation.as_str()) {
        check.deny(
            "destination_class",
            "egress_ceiling_exceeded",
            &view.revision_ref,
            "the requested representation is not one this egress ceiling admits; the ceilings are a table rather than an ordering, so a near-neighbour is not admitted under it",
        );
    }
    if DECLASSIFYING_REPRESENTATIONS.contains(&requested_representation.as_str())
        && body_str(&body, "declassification_approval_ref").is_empty()
    {
        check.deny(
            "destination_class",
            "declassification_refused",
            &view.revision_ref,
            "moving declassified or protected-plaintext material needs its own declassification approval; the view pins that it is never the approval",
        );
    }
    let permitted_regions = view.list("/destination_and_egress/permitted_region_refs");
    let residency_refs = view.list("/residency_refs");
    if !permitted_regions
        .iter()
        .any(|held| *held == requested_region)
        || !residency_refs.iter().any(|held| *held == requested_region)
    {
        check.deny(
            "residency",
            "residency_refused",
            &view.revision_ref,
            "the requested region is outside the view's permitted regions or its declared residency; the two are separate axes, and conflating them is how a compliant-looking view permits a move neither would allow",
        );
    } else {
        check.note(
            "residency",
            "within_scope",
            &view.revision_ref,
            "the requested region satisfies both the residency and the destination axis",
        );
    }
    if !view
        .list("/jurisdiction_refs")
        .iter()
        .any(|held| *held == requested_jurisdiction)
    {
        check.deny(
            "residency",
            "jurisdiction_refused",
            &view.revision_ref,
            "the requested jurisdiction is not one this projection declared; an unstated jurisdiction is not an absent obligation",
        );
    }

    // ============================================== the request, intersected against the projection
    let requested_use = body_str(&body, "requested_use");
    if !VIEW_USE_VOCABULARY.contains(&requested_use.as_str()) {
        return refuse(
            &mat_code("requested_use_outside_vocabulary"),
            format!("'{requested_use}' is not one of this contract's eight uses; an unknown use is a typed refusal, never a silently ignored one"),
        );
    }
    if !view
        .allowed_uses()
        .iter()
        .any(|held| *held == requested_use)
    {
        check.deny(
            "current_rights",
            "use_not_allowed",
            &view.revision_ref,
            "the requested use is not in this view's permitted set, which is itself the vocabulary minus every denial its resolved inputs contributed",
        );
    }
    if hold_state != "none" && HOLD_DENIED_VIEW_USES.contains(&requested_use.as_str()) {
        check.deny(
            "retention_and_hold",
            "hold_blocks_use",
            &view.revision_ref,
            "a hold narrows outward and derivative use; it never widens either",
        );
    }

    let requested_fields = match ref_list(&body, "requested_field_refs", 256, &VIEW) {
        Ok(list) => list,
        Err(response) => return response,
    };
    if requested_fields.is_empty() {
        return refuse(
            &mat_code("requested_fields_required"),
            "'requested_field_refs' names the fields this read wants; an empty request is not a request for everything",
        );
    }
    let allowed_fields = view.list("/field_scope/allowed_field_refs");
    // THE EXCESS-FIELD REFUSAL AT READ TIME. An out-of-scope field REFUSES rather than being
    // silently trimmed: a caller that asked for a field it may not have needs to learn that, and a
    // quietly narrowed answer is indistinguishable from a permitted one.
    for field_ref in &requested_fields {
        if !allowed_fields.iter().any(|held| held == field_ref) {
            check.deny(
                "current_rights",
                "excess_field",
                field_ref,
                "this field is outside the view's minimized field scope; it is refused rather than trimmed, because a silently narrowed answer reads exactly like a permitted one",
            );
        }
    }

    let row_predicate_ref = view.text("/row_scope/row_predicate_ref");
    let row_predicate_hash = view.text("/row_scope/row_predicate_hash");
    if body_str(&body, "requested_row_predicate_ref") != row_predicate_ref
        || body_str(&body, "requested_row_predicate_hash") != row_predicate_hash
    {
        check.deny(
            "current_rights",
            "row_predicate_substituted",
            &row_predicate_ref,
            "the read names a different row predicate, or the same one at different bytes, than the view committed; a predicate that can be edited after admission is a scope that widens silently",
        );
    }
    let ceiling_rows = view
        .record
        .pointer("/row_scope/max_row_count")
        .and_then(Value::as_u64);
    let requested_rows = body.get("requested_max_row_count").and_then(Value::as_u64);
    if let (Some(ceiling), Some(requested)) = (ceiling_rows, requested_rows) {
        if requested > ceiling {
            check.deny(
                "current_rights",
                "excess_rows",
                &view.revision_ref,
                "the read asks for more rows than the view's hard ceiling admits",
            );
        }
    }
    let granted_rows = match (ceiling_rows, requested_rows) {
        (Some(ceiling), Some(requested)) => Some(ceiling.min(requested)),
        (Some(ceiling), None) => Some(ceiling),
        (None, requested) => requested,
    };

    let timebase = view.text("/time_scope/timebase");
    if body_str(&body, "requested_timebase") != timebase {
        check.deny(
            "current_rights",
            "timebase_mismatch",
            &view.revision_ref,
            "event time and ingest time disagree, and a range read on the wrong clock silently widens or narrows the projection",
        );
    }
    let scope_from = agentgres::parse_rfc3339_ms(&view.text("/time_scope/from"));
    let scope_until = view
        .record
        .pointer("/time_scope/until")
        .and_then(Value::as_str)
        .map(agentgres::parse_rfc3339_ms);
    let requested_from = agentgres::parse_rfc3339_ms(&body_str(&body, "requested_from"));
    let requested_until = agentgres::parse_rfc3339_ms(&body_str(&body, "requested_until"));
    let window_ok = requested_from != 0
        && requested_until != 0
        && requested_from >= scope_from
        && requested_from <= requested_until
        && scope_until.is_none_or(|until| requested_until <= until);
    if !window_ok {
        check.deny(
            "current_rights",
            "time_window_outside_scope",
            &view.revision_ref,
            "the requested window is not contained in the view's committed time scope; a view over all of history is not minimized no matter how few fields it names",
        );
    }

    // ------------------------------------------------------------------------------ the decision
    //
    // THE COMPLEMENT OF THE REFUSAL SET, and nothing else. A grant is reachable exactly when every
    // one of the eight revalidated facts held and nothing denied the read; there is no branch to
    // forget, because permission is what remains after every denial is subtracted.
    let materialized = check.refusals.is_empty();
    let granted = if materialized {
        json!({
            "granted_field_refs": requested_fields,
            "granted_field_count": requested_fields.len(),
            "row_predicate_ref": row_predicate_ref,
            "row_predicate_hash": row_predicate_hash,
            "max_row_count": granted_rows,
            "timebase": timebase,
            "from": body_str(&body, "requested_from"),
            "until": body_str(&body, "requested_until"),
            "use": requested_use,
            "destination_class": requested_destination,
            "representation": requested_representation,
            "region_ref": requested_region,
            // THE GRANT IS A DESCRIPTOR. Pinned in the record's own bytes so a reader cannot later
            // present this decision as though it had carried the material.
            "payload_bytes_included": false,
        })
    } else {
        Value::Null
    };

    let ordinal = stream.len() as u64 + 1;
    let materialization_ref = format!("{resource}/revision/{ordinal}");
    let mut record = json!({
        "schema_version": MAT_RECORD_SCHEMA,
        "materialization_id": resource,
        "materialization_ref": materialization_ref,
        "owner_ref": caller.owner_ref,
        "tenant_ref": tenant_ref,
        "principal_resolution": "server_resolved",
        "resolved_principal_ref": view.record.get("resolved_principal_ref").cloned().unwrap_or(Value::Null),
        "policy_bound_data_view_revision_ref": view.revision_ref,
        "policy_bound_data_view_content_hash": view.content_hash,
        "view_registry_status_at_decision": registry_status,
        "requested_use": requested_use,
        "requested_projection": {
            "requested_field_refs": requested_fields,
            "requested_row_predicate_ref": body_str(&body, "requested_row_predicate_ref"),
            "requested_row_predicate_hash": body_str(&body, "requested_row_predicate_hash"),
            "requested_max_row_count": requested_rows,
            "requested_timebase": body_str(&body, "requested_timebase"),
            "requested_from": body_str(&body, "requested_from"),
            "requested_until": body_str(&body, "requested_until"),
            "requested_destination_class": requested_destination,
            "requested_representation": requested_representation,
            "requested_region_ref": requested_region,
            "requested_jurisdiction_ref": requested_jurisdiction,
        },
        "observed_source_revisions": observed,
        // ALL EIGHT NAMED FACTS, each with its own findings below naming the owner that answered.
        "revalidated_facts": REVALIDATED_FACTS,
        "revalidation_findings": check.findings,
        "effective_boundary_binding_at_decision": boundary_at_decision,
        "granted_projection": granted,
        "decision": if materialized { "materialized" } else { "refused" },
        "refusal_codes": check.refusals,
        "emitted_at": admitted_stamp(at_ms),
        "constants": {
            "lifecycle_id": "policy_bound_data_view_materialization_lifecycle.v1",
            "view_use_vocabulary_size": VIEW_USE_VOCABULARY.len(),
            "revalidated_fact_count": REVALIDATED_FACTS.len(),
            "nonclaim_payload_custody_token": "materialized_payload_custody",
        },
        "authority_nonclaim": "policy_bound_data_view_materialization_grants_no_authority",
        "truth_nonclaim": "policy_bound_data_view_materialization_is_a_bounded_read_decision_not_a_copy_of_the_protected_material",
        "does_not_assert": [
            "authority",
            "consent",
            "source_rights",
            "semantic_truth",
            "declassification",
            "materialized_payload_custody",
            "reader_compliance_with_the_granted_bound",
            // NAMED BECAUSE IT IS OUT OF SCOPE, NOT BECAUSE IT IS UNCHECKED. A live provider
            // connection is wallet.network's ProviderConnectionBinding and is deliberately outside
            // this contract's closed fact vocabulary; this decision asserts nothing about it, and a
            // brokered destination is instead covered by a live route-rights contract or refused.
            "provider_connection_state",
        ],
    });
    let derived = match digest_over(&record, MAT_COMMITMENT_DOMAIN, MAT_MATERIAL_FIELDS) {
        Ok(hash) => hash,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &mat_code("content_hash_failed"),
                reason,
            )
        }
    };
    record["content_hash"] = json!(derived);
    let payload = json!({
        "schema_version": MAT_PAYLOAD_SCHEMA,
        "owner_ref": caller.owner_ref,
        "resource_ref": resource,
        MAT_RECORD_KEY: record,
    });
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        expected_head.is_none(),
        ScopedMutation {
            identity: &caller.identity,
            scope: &scope,
            resource_kind: MAT_RESOURCE_KIND,
            resource_ref: &resource,
            owner_namespace: MAT_OWNER_NAMESPACE,
            stream_tail: &stream_tail(MAT_RESOURCE_KIND, &resource),
            op_kind: MAT_ADMIT_OP,
            expected_head: expected_head.as_deref(),
            payload: &payload,
            idempotency_key: &caller.idempotency_key,
            recorded_at_ms: at_ms,
        },
    ) {
        Ok(commit) => commit,
        Err(error) => return mutation_refusal_reply(error),
    };
    // ANSWER FROM A RE-READ OF THE CHAIN, never from the value this handler happened to build.
    let after = match read_materialization_stream(&st.data_dir, &caller.identity, &scope, &resource)
    {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let Some(entry) = after
        .iter()
        .find(|entry| entry.head == commit.projection.head)
    else {
        return bad(
            StatusCode::BAD_GATEWAY,
            &mat_code("projection_disagrees_with_ack"),
            "the admitted head is absent from this stream's projection",
        );
    };
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "materialized": materialized,
            "policy_bound_data_view_materialization": entry.record,
            "admission": entry.admission,
            "expected_head_for_successor": commit.projection.head,
            "receipt_ref": commit.receipt_ref,
            "operation_ref": commit.operation_ref,
            "request_fingerprint": commit.request_fingerprint,
            "index_state": projection_cache_state(&resource, &after),
            "the_grant_is_a_bounded_descriptor_not_a_copy": true,
        })),
    )
}

/// GET /v1/hypervisor/policy-bound-data-view-materializations — inventory, family, or one decision.
pub(crate) async fn handle_policy_bound_data_view_materialization_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let Some(family) = query.family.as_deref().filter(|value| family_token(value)) else {
        return match authorized_request_resource_refs(&st.data_dir, &identity, MAT_RESOURCE_KIND) {
            Ok(refs) => (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "policy_bound_data_view_materialization_refs": refs.into_iter().collect::<Vec<_>>(),
                })),
            ),
            Err(error) => scope_refusal_reply(error),
        };
    };
    let resource = format!("{MAT_REF_SCHEME}{family}");
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        &identity,
        MAT_RESOURCE_KIND,
        &resource,
        None,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_materialization_stream(&st.data_dir, &identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let index_state = projection_cache_state(&resource, &stream);
    if let Some(ordinal) = query.revision {
        let wanted = format!("{resource}/revision/{ordinal}");
        let Some(entry) = stream
            .iter()
            .find(|entry| entry.record.get("materialization_ref") == Some(&json!(wanted)))
        else {
            return bad(
                StatusCode::NOT_FOUND,
                &mat_code("revision_absent"),
                format!("this family has no decision {ordinal} — an absent decision is a typed absence, never an empty success"),
            );
        };
        return (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "resolved": entry.record,
                "admission": entry.admission,
                "index_state": index_state,
            })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "family": resource,
            "revisions": stream.iter().map(|entry| entry.record.clone()).collect::<Vec<_>>(),
            "admissions": stream.iter().map(|entry| entry.admission.clone()).collect::<Vec<_>>(),
            "head": stream.last().map(|last| last.head.clone()),
            "index_state": index_state,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registered positive fixture must hash to the number it carries under THIS module's
    /// material list. A gate computing both sides from one source would certify nothing: the fixture
    /// is a committed pin and the material list is this build's independent reading of it.
    #[test]
    fn registered_view_fixture_matches_this_modules_material_list() {
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/policy-bound-data-view-v2/positive-genesis-authored-at-v2.json"
        ));
        let record: Value = serde_json::from_str(fixture).expect("the fixture parses");
        let committed = record
            .get("content_hash")
            .and_then(Value::as_str)
            .expect("the fixture carries a commitment");
        let derived = VIEW
            .content_hash(&record)
            .expect("the material list resolves");
        assert_eq!(
            derived, committed,
            "this module's material list disagrees with the registered commitment"
        );
    }

    /// The load-bearing property: permission is the complement of the denial set, so there is no
    /// branch a later edit can forget to take.
    #[test]
    fn a_denied_use_is_never_permitted() {
        let mut intersection = UseIntersection::default();
        intersection.deny(
            "train",
            "bound_purpose",
            "decision://x",
            "purpose_does_not_support_use",
        );
        let permitted = intersection.permitted();
        assert!(!permitted.contains(&"train".to_string()));
        assert_eq!(permitted.len(), VIEW_USE_VOCABULARY.len() - 1);
    }

    /// A purpose narrows: a field set justified for evaluation is not one justified for training.
    #[test]
    fn the_bound_purpose_removes_every_use_it_does_not_support() {
        let mut intersection = UseIntersection::default();
        fold_purpose(&mut intersection, "evaluation", "decision://acme/eval");
        let permitted = intersection.permitted();
        assert_eq!(permitted, vec!["read", "transform", "evaluate"]);
    }

    /// An egress ceiling is a TABLE, not an ordering: `redacted_only` does not admit `synthetic`.
    #[test]
    fn an_egress_ceiling_admits_only_its_own_representations() {
        assert_eq!(ceiling_representations("redacted_only"), &["redacted"]);
        assert!(ceiling_representations("no_egress").is_empty());
        assert!(!ceiling_representations("redacted_only").contains(&"synthetic"));
        assert!(ceiling_representations("protected_plaintext_permitted").contains(&"redacted"));
    }

    /// A DENIAL IS THE ONLY THING THAT STOPS A GRANT, so a decision with no denial grants — which is
    /// what makes every refusal above load-bearing rather than decorative.
    #[test]
    fn a_decision_grants_exactly_when_nothing_denied_it() {
        let mut check = Revalidation::default();
        assert!(
            check.refusals.is_empty(),
            "an unchallenged read is grantable"
        );
        check.deny(
            "consent_state",
            "consent_not_current",
            "grant://x",
            "no live claim carries it",
        );
        assert!(!check.refusals.is_empty());
        assert_eq!(check.refusals.len(), 1);
        assert!(check.refusals[0].ends_with("consent_not_current"));
    }

    /// The registered precondition's vocabulary is closed at eight, and this build names all eight.
    /// A member missing here would be a fact the record claims nobody rechecks.
    #[test]
    fn all_eight_named_facts_are_revalidated() {
        assert_eq!(REVALIDATED_FACTS.len(), 8);
        for token in [
            "current_authority",
            "current_rights",
            "revocation_state",
            "expiry",
            "retention_and_hold",
            "residency",
            "destination_class",
            "consent_state",
        ] {
            assert!(
                REVALIDATED_FACTS.contains(&token),
                "'{token}' is not revalidated"
            );
        }
    }

    /// Every resolvable source scheme routes to an owner module, and `in_boundary_only` is the only
    /// destination class that needs no admitted authority coverage.
    #[test]
    fn the_owner_routing_tables_are_total_and_closed() {
        assert!(RESOLVABLE_SOURCE_SCHEMES
            .iter()
            .all(|(scheme, owner)| scheme.ends_with("://") && !owner.is_empty()));
        assert!(!BROKERED_DESTINATION_CLASSES.contains(&"in_boundary_only"));
        assert_eq!(BROKERED_DESTINATION_CLASSES.len(), 5);
    }

    /// A null or absent stamp is NOT expiry — an unanswered question about a window is not a closed
    /// window, and conflating them would refuse every open-ended consent.
    #[test]
    fn an_absent_expiry_stamp_is_not_an_expiry() {
        assert!(!expired_at(None, 1_000));
        assert!(expired_at(Some("2020-01-01T00:00:00Z"), 1_900_000_000_000));
        assert!(!expired_at(Some("2099-01-01T00:00:00Z"), 1_900_000_000_000));
    }

    /// Every view use is gated by at least one learning use, so no use can enter the permission
    /// without the compiled boundary having an opinion about it.
    #[test]
    fn every_view_use_is_gated_by_a_learning_use() {
        for token in VIEW_USE_VOCABULARY {
            let gates = VIEW_USE_GATES
                .iter()
                .find(|(name, _)| name == token)
                .map(|(_, gates)| *gates)
                .unwrap_or(&[]);
            assert!(!gates.is_empty(), "'{token}' is gated by nothing");
            for gate in gates {
                assert!(
                    LEARNING_USE_VOCABULARY.contains(gate),
                    "'{gate}' is not a learning use"
                );
            }
        }
    }
}
