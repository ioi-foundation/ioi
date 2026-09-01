//! M05.10 — `VerticalOntologyPack` as owner-scoped runtime.
//!
//! WHAT IS TRUTH HERE. One pack family is one owner-namespaced Agentgres operation chain. This
//! module writes no file of its own, mints no store, and admits through
//! `mutation_event_foundation` like every other family in this estate. Everything served is a
//! PROJECTION rebuilt from the chain on every read, including the content hash, which is re-derived
//! and compared rather than trusted.
//!
//! IDENTITY IS OWNER-QUALIFIED AND TWO-SEGMENTED: `vertical-pack://<namespace>/<name>`, extended by
//! `/revision/<n>`. A single-segment family would put every vertical in one flat space where two
//! owners collide on a name; the ontology, mapping and action-contract families already carry their
//! namespace inside the identity for exactly that reason. Because the family token contains a `/`,
//! this module cannot use the shared `parse_revision_ref`/`family_query` helpers — those pin a
//! one-segment family — so it parses its own identity and serves its own query. It still shares
//! every byte of the chain machinery: `FamilySpec`, `read_stream`, `project_admitted`,
//! `replay_for_key`, `require_exact_head` and `finish_admission` are the same implementations
//! M07.2, M10.3 and M05.8 use.
//!
//! A PACK DECLARES; IT DOES NOT DECIDE. Canon's boundary and M05 §5 are enforced here by ABSENCE as
//! much as by fields: nothing in this module consults, mints, widens, presents or redeems a
//! capability, lease, policy decision, authority grant, provider connection or effect admission, and
//! nothing dispatches anything. `does_not_decide` carries the closed nonclaim set and the registered
//! schema and invariant enforce it offline as well.
//!
//! EVERY BINDING IS RESOLVED BY ITS OWNER, NEVER ASSERTED BY THE CALLER. The base ontology revision,
//! every declared object type, every declared action type and every bound `OntologyActionContract`
//! and `ConnectorMapping` crosses that family's own read-only seam under the CALLER'S OWN owner
//! binding, so a cross-principal or cross-tenant input is refused at the scope boundary before any
//! bytes are read. A well-formed, correctly-namespaced term the revision never declared is refused
//! by M05.1's seam rather than accepted as a well-formed string.
//!
//! TWO RULES THE PORTABLE INVARIANT LANGUAGE CANNOT EXPRESS ARE ENFORCED HERE INSTEAD, and the
//! registered profile says so rather than implying otherwise:
//!
//!   1. TASK-CLASS REACHABILITY. Every declared action binding must be named by some task class's
//!      `action_type_refs`, and every action type a task class names must have a binding. The
//!      covering is exact in both directions, so an action with a risk class but no task class
//!      (a risk declared about work the pack does not describe) and a task class naming an action
//!      with no contract (work described with no compiled action) both refuse. `array_exact_ref_coverage`
//!      cannot project a scalar out of an array nested inside array items, so this is inexpressible
//!      offline.
//!   2. RISK AGREEMENT PER ROW. The risk class a pack declares for an action must equal the risk
//!      class the resolved `OntologyActionContract` actually carries. The portable language has no
//!      operator reading two fields of one array item; the binding's `pack_declared_risk_ladder`
//!      carries the multiset half offline and this is the row-by-row half.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::model_route_rights_routes::{
    bad, body_str, contract_owner_ref, contract_tenant_ref, projection_cache_state, read_stream,
    ref_list, refuse, reject_authored, replay_for_key, require_exact_head, AdmittedRecord,
    FamilySpec, Reply,
};
use super::model_route_rights_routes::{finish_admission, head_assertion};
use super::mutation_event_foundation::{admitted_stamp, require_write_caller, scope_refusal_reply};
use super::ontology_action_contract_routes::resolve_admitted_action_contract;
use super::ontology_version_routes::{
    resolve_admitted_action_type, resolve_admitted_revision, resolve_admitted_term,
};
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity, RequestIdentity,
};
use super::DaemonState;

// ============================================================================== identity, exactly

const MAX_SEGMENT: usize = 63;
const MAX_ORDINAL: u64 = 999_999_999;

/// `[a-z0-9][a-z0-9-]{0,62}` — the segment shape the registered schema pins, checked here rather
/// than repaired. Two spellings resolving to one family would let a binding claim it compiled
/// something other than what it compiled.
pub(crate) fn canonical_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SEGMENT
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(crate) fn pack_family_ref(namespace: &str, name: &str) -> String {
    format!("vertical-pack://{namespace}/{name}")
}

/// Parse `<scheme>://<namespace>/<name>/revision/<n>` strictly and totally.
///
/// STRICT, because a consumer is about to BIND whatever comes out of here. Percent-escapes,
/// backslashes, query/fragment tails, extra segments, non-canonical tokens and any ordinal that is
/// signed, zero, zero-padded, oversized or not a bare digit run are REFUSED rather than repaired.
/// The mandatory `/revision/` segment is also what refuses a family head or mutable-latest reference
/// wherever a revision is required.
pub(crate) fn parse_two_segment_revision_ref(scheme: &str, value: &str) -> Option<(String, u64)> {
    if value.len() > 320
        || value.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || byte.is_ascii_control()
                || !byte.is_ascii()
                || matches!(byte, b'?' | b'#' | b'\\' | b'%')
        })
    {
        return None;
    }
    let rest = value.strip_prefix(scheme)?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 4 || parts[2] != "revision" {
        return None;
    }
    if !canonical_segment(parts[0]) || !canonical_segment(parts[1]) {
        return None;
    }
    let ordinal = parts[3];
    if ordinal.is_empty()
        || ordinal.len() > 9
        || ordinal.starts_with('0')
        || !ordinal.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let ordinal: u64 = ordinal.parse().ok()?;
    (ordinal > 0 && ordinal <= MAX_ORDINAL)
        .then(|| (format!("{scheme}{}/{}", parts[0], parts[1]), ordinal))
}

// ============================================================================== family descriptor

static PACK: FamilySpec = FamilySpec {
    owner_namespace: "vertical-ontology-packs",
    resource_kind: "vertical_ontology_pack",
    admit_op: "event_stream.vertical_ontology_pack_revision_admitted",
    payload_schema: "ioi.hypervisor.vertical-ontology-pack-revision-admission.v1",
    contract_id: "schema://ioi/domains/aiagent/vertical-ontology-pack/v1",
    schema_version: "ioi.vertical-ontology-pack.v1",
    record_key: "vertical_ontology_pack_record",
    code_prefix: "vertical_ontology_pack",
    commitment_domain: "ioi.vertical-ontology-pack-content-commitment-jcs-sha256.v1",
    material_fields: &[
        "schema_version",
        "vertical_ontology_pack_id",
        "revision_ref",
        "owner_ref",
        "tenant_ref",
        "principal_resolution",
        "resolved_principal_ref",
        "legacy_pack_id",
        "legacy_pack_id_is_display_only",
        "display_name",
        "base_ontology_revision_ref",
        "base_ontology_content_hash",
        "declared_object_type_refs",
        "declared_task_classes",
        "declared_action_bindings",
        "declared_integration_requirements",
        "declared_output_fields",
        "declared_field_requirements",
        "declared_evidence_requirements",
        "declared_review_modes",
        "forbidden_action_refs",
        "jurisdiction_refs",
        "registry_status",
        "admitted_at",
        "succession",
        "migration",
        "constants",
        "authority_nonclaim",
        "truth_nonclaim",
        "legal_conformity_claim",
        "does_not_decide",
    ],
    identity_field: "revision_ref",
    ref_scheme: "vertical-pack://",
    stamp_field: "admitted_at",
};

/// Fields the SERVER resolves. A caller that authors one is refused BY NAME before anything is read
/// — INV-37's exact failure mode, because a caller that writes the ontology hash its own admission
/// checks has checked a constant it chose.
const PACK_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "vertical_ontology_pack_id",
    "revision_ref",
    "tenant_ref",
    "principal_resolution",
    "resolved_principal_ref",
    "base_ontology_content_hash",
    "legacy_pack_id_is_display_only",
    "admitted_at",
    "succession",
    "migration",
    "constants",
    "authority_nonclaim",
    "truth_nonclaim",
    "legal_conformity_claim",
    "content_hash",
];

/// The SEVEN boundary tokens M05 §5 and ACC-18 clause 13 require of every pack. A record that
/// dropped one would stop stating a boundary that still binds it, so the set is a floor here as well
/// as in the registered schema. The default also carries `credential_custody`, drawn from canon's
/// own "Does Not Own" list, so an ordinarily admitted record is never smaller than eight.
const MANDATORY_NONCLAIMS: &[&str] = &[
    "legality",
    "reviewer_qualification",
    "authority",
    "marketplace_eligibility",
    "payment",
    "correctness",
    "live_medical_suitability",
];

const SUCCESSION_REASONS: &[&str] = &[
    "genesis",
    "ontology_revision_change",
    "action_or_risk_change",
    "field_or_evidence_change",
    "review_mode_change",
    "integration_change",
    "jurisdiction_change",
    "correction",
];

// ------------------------------------------------------------------------ the resolved pack itself

/// ONE resolved pack revision, as a caller entitled to it may see it.
///
/// THE SEAM THE COMPILER BINDS. M05.10's binding module does not read this family's chain, re-derive
/// its commitment or reinterpret its declarations. There is one reader, it is here, it shares the
/// owner scope and chain projection of the query route, and it GRANTS NOTHING.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedVerticalPack {
    pub(crate) revision_ref: String,
    pub(crate) tenant_ref: String,
    pub(crate) record: Value,
    pub(crate) content_hash: String,
    pub(crate) index_state: &'static str,
}

impl ResolvedVerticalPack {
    pub(crate) fn text(&self, pointer: &str) -> String {
        self.record
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    pub(crate) fn list(&self, pointer: &str) -> Vec<String> {
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

    pub(crate) fn rows(&self, pointer: &str) -> Vec<Value> {
        self.record
            .pointer(pointer)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn is_active(&self) -> bool {
        self.text("/registry_status") == "active"
    }
}

/// Resolve ONE exact pack revision under the CALLER'S OWN owner binding.
///
/// The identity is passed in, so a cross-principal or cross-tenant resolution is refused at the
/// scope boundary BEFORE any bytes are returned — not resolved first and compared afterwards, which
/// would be a leak with a check bolted on behind it. A family head is refused by the ref grammar
/// rather than resolved to "latest": a compilation against `vertical-pack://acme-records/intake`
/// would compile whatever the family last carried.
pub(crate) fn resolve_admitted_pack_revision(
    data_dir: &str,
    identity: &RequestIdentity,
    expected_owner_ref: Option<&str>,
    revision_ref: &str,
) -> Result<ResolvedVerticalPack, Reply> {
    let Some((resource, ordinal)) = parse_two_segment_revision_ref(PACK.ref_scheme, revision_ref)
    else {
        return Err(refuse(
            &PACK.code("revision_ref_not_canonical"),
            "a pack binding names vertical-pack://<namespace>/<name>/revision/<n>; a family head, a mutable-latest reference or a one-segment spelling is refused where an owner-qualified revision is required",
        ));
    };
    let scope = authorize_request_resource_scope(
        data_dir,
        identity,
        PACK.resource_kind,
        &resource,
        expected_owner_ref,
    )
    .map_err(scope_refusal_reply)?;
    let stream = read_stream(&PACK, data_dir, identity, &scope, &resource)?;
    let index_state = projection_cache_state(&resource, &stream);
    let wanted = format!("{resource}/revision/{ordinal}");
    let Some(entry) = stream
        .iter()
        .find(|entry| entry.record.get("revision_ref") == Some(&json!(wanted)))
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &PACK.code("revision_absent"),
            format!(
                "this pack family has no admitted revision {ordinal}; an absent revision is a typed absence, never the nearest one"
            ),
        ));
    };
    Ok(ResolvedVerticalPack {
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

// ====================================================================================== admission

fn object_rows(body: &Value, key: &str, max: usize) -> Result<Vec<Value>, Reply> {
    let Some(value) = body.get(key) else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_array() else {
        return Err(refuse(
            &PACK.code("row_list_invalid"),
            format!("'{key}' must be an array of objects"),
        ));
    };
    if items.len() > max {
        return Err(refuse(
            &PACK.code("row_list_invalid"),
            format!("'{key}' admits at most {max} rows"),
        ));
    }
    if let Some(bad_row) = items.iter().find(|item| !item.is_object()) {
        return Err(refuse(
            &PACK.code("row_list_invalid"),
            format!("'{key}' members are objects; got {bad_row}"),
        ));
    }
    Ok(items.clone())
}

fn row_str(row: &Value, key: &str) -> String {
    row.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_string()
}

fn row_list(row: &Value, key: &str) -> Vec<String> {
    row.get(key)
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

/// POST /v1/hypervisor/vertical-ontology-packs — admit one immutable pack revision.
pub(crate) async fn handle_vertical_ontology_pack_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let spec = &PACK;
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        contract_owner_ref(&caller.owner_ref, &spec.code("owner_scheme_unsupported"))
    {
        return response;
    }
    if let Err(response) = reject_authored(&body, spec, PACK_SERVER_RESOLVED) {
        return response;
    }

    let namespace = body_str(&body, "namespace");
    let name = body_str(&body, "name");
    if !canonical_segment(&namespace) || !canonical_segment(&name) {
        return refuse(
            &spec.code("identity_not_canonical"),
            "'namespace' and 'name' are each a canonical lowercase token [a-z0-9][a-z0-9-]{0,62}; a pack family is owner-qualified as vertical-pack://<namespace>/<name>",
        );
    }
    let resource = pack_family_ref(&namespace, &name);
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
    // REPLAY BEFORE PRECONDITIONS. A retry after an ambiguous response necessarily observes a newer
    // head than the one it originally compare-and-swapped against, so checking `expected_head` first
    // would turn every real duplicate into a conflict and make the idempotency key unusable.
    match replay_for_key(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        &stream,
        "vertical_ontology_pack",
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

    // ------------------------------------------- the base ontology, resolved through M05.1's seam
    let ontology_ref = body_str(&body, "base_ontology_revision_ref");
    let ontology = match resolve_admitted_revision(&st.data_dir, &caller.identity, &ontology_ref) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    // AN OUT-OF-DATE BASE IS REFUSED AT THE PACK, NOT DISCOVERED AT THE BINDING. A pack declared
    // against a revision its own owner has already deprecated would produce a compilation whose
    // every field is stale before it is written.
    if ontology.status != "active" {
        return refuse(
            &spec.code("base_ontology_not_active"),
            format!(
                "'{}' is '{}' rather than active; a pack extends a current revision, and a superseded base is a successor's problem rather than this revision's silence",
                ontology.ontology_id, ontology.status
            ),
        );
    }

    let object_type_refs = match ref_list(&body, "declared_object_type_refs", 256, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    if object_type_refs.is_empty() {
        return refuse(
            &spec.code("object_types_required"),
            "a pack declares at least one object type of its base ontology",
        );
    }
    // EVERY TERM IS RESOLVED AGAINST THE EXACT REVISION THAT DECLARES IT. A well-formed,
    // correctly-namespaced term the revision never declared passes every shape check; only the
    // ontology owner's own chain knows whether the revision declares it.
    for term_ref in &object_type_refs {
        if let Err(response) =
            resolve_admitted_term(&st.data_dir, &caller.identity, &ontology_ref, term_ref)
        {
            return response;
        }
    }

    // ------------------------------------------------------------ task classes and action bindings
    let task_classes = match object_rows(&body, "declared_task_classes", 128) {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    let action_bindings = match object_rows(&body, "declared_action_bindings", 128) {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    if task_classes.is_empty() || action_bindings.is_empty() {
        return refuse(
            &spec.code("task_classes_and_actions_required"),
            "a pack declares at least one task class and at least one action binding; a vertical that describes no work and compiles no action is a name",
        );
    }

    let mut declared_actions: BTreeSet<String> = BTreeSet::new();
    let mut resolved_bindings = Vec::with_capacity(action_bindings.len());
    for binding in &action_bindings {
        let action_type_ref = row_str(binding, "action_type_ref");
        if !declared_actions.insert(action_type_ref.clone()) {
            return refuse(
                &spec.code("action_declared_twice"),
                format!(
                    "'{action_type_ref}' carries two action bindings; which risk class, contract and review mode govern it would be undecided, and a consumer reading the first row would silently take whichever it saw"
                ),
            );
        }
        // The action must be one the bound revision actually DECLARES, not merely a well-formed
        // same-family term. M05.1 answers both halves against one projection of its own chain.
        if let Err(response) = resolve_admitted_action_type(
            &st.data_dir,
            &caller.identity,
            &ontology_ref,
            &action_type_ref,
        ) {
            return response;
        }
        let contract_ref = row_str(binding, "action_contract_revision_ref");
        let contract =
            match resolve_admitted_action_contract(&st.data_dir, &caller.identity, &contract_ref) {
                Ok(resolved) => resolved,
                Err(response) => return response,
            };
        if !contract.is_active() {
            return refuse(
                &spec.code("action_contract_not_active"),
                format!("'{contract_ref}' is '{}' rather than active; a pack compiles an action through a current contract", contract.status),
            );
        }
        // THE CONTRACT MUST COMPILE THE SAME MEANING THE PACK EXTENDS, by ref AND by bytes. A
        // contract compiled against another ontology revision would carry a risk class about a term
        // this pack never bound, and both halves are checked because a ref names a location that may
        // since have been re-admitted while the hash names what was actually bound.
        if contract.ontology_revision_ref != ontology.ontology_id {
            return refuse(
                &spec.code("action_contract_binds_another_ontology_revision"),
                format!(
                    "'{}' compiles against '{}' while this pack extends '{}'; an action whose contract means something from another revision is not this pack's action",
                    contract.action_family_ref, contract.ontology_revision_ref, ontology.ontology_id
                ),
            );
        }
        if contract.ontology_content_hash != ontology.content_hash {
            return refuse(
                &spec.code("action_contract_binds_drifted_ontology_bytes"),
                format!(
                    "'{}' committed ontology bytes that are not the bytes M05.1 now serves for '{}'; a silent re-admission underneath an admitted contract is exactly what the committed hash exists to expose",
                    contract.ontology_action_id, ontology.ontology_id
                ),
            );
        }
        // RISK AGREEMENT, ROW BY ROW. THE HALF THE PORTABLE LANGUAGE CANNOT SEE. A pack that filed a
        // `funds` action as `read` would compile a risk mapping that disagrees with the contract the
        // action passes through, and every downstream gate would read the wrong number. The
        // binding's ladder carries the multiset half offline; this is the exact half, and it also
        // refuses the transposition a multiset comparison cannot detect.
        let declared_risk = row_str(binding, "risk_class");
        if declared_risk != contract.risk_class {
            return refuse(
                &spec.code("declared_risk_disagrees_with_the_contract"),
                format!(
                    "'{action_type_ref}' is declared '{declared_risk}' while '{contract_ref}' carries '{}'; the pack does not get to restate its own action's risk",
                    contract.risk_class
                ),
            );
        }
        resolved_bindings.push(json!({
            "action_type_ref": action_type_ref,
            "risk_class": declared_risk,
            "action_contract_revision_ref": contract_ref,
            "review_mode": row_str(binding, "review_mode"),
            "required_integration_surface": row_str(binding, "required_integration_surface"),
        }));
    }

    // TASK-CLASS REACHABILITY, EXACT IN BOTH DIRECTIONS. The other rule the registered profile
    // cannot state: an action with a risk class but no task class is a risk declared about work the
    // pack does not describe, and a task class naming an action with no binding is work described
    // with no compiled action. Both refuse.
    let mut task_class_actions: BTreeSet<String> = BTreeSet::new();
    let mut seen_task_classes: BTreeSet<String> = BTreeSet::new();
    for class in &task_classes {
        let class_ref = row_str(class, "task_class_ref");
        if !seen_task_classes.insert(class_ref.clone()) {
            return refuse(
                &spec.code("task_class_declared_twice"),
                format!("'{class_ref}' is declared twice"),
            );
        }
        for action in row_list(class, "action_type_refs") {
            task_class_actions.insert(action);
        }
    }
    if let Some(orphan) = declared_actions.difference(&task_class_actions).next() {
        return refuse(
            &spec.code("action_reaches_no_task_class"),
            format!(
                "'{orphan}' carries an action binding but no task class names it; a pack that maps a risk class onto an action it does not describe has declared a risk about work nobody can find"
            ),
        );
    }
    if let Some(orphan) = task_class_actions.difference(&declared_actions).next() {
        return refuse(
            &spec.code("task_class_action_has_no_binding"),
            format!(
                "'{orphan}' is named by a task class but carries no action binding; work described with no compiled action, risk class or review mode is a gap, not a declaration"
            ),
        );
    }

    // ------------------------------------------------ integration requirements, resolved at M05.7
    let integrations = match object_rows(&body, "declared_integration_requirements", 64) {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    if integrations.is_empty() {
        return refuse(
            &spec.code("integration_requirements_required"),
            "a pack declares at least one integration surface and the connector mapping that binds it",
        );
    }
    let mut seen_surfaces: BTreeSet<String> = BTreeSet::new();
    let mut resolved_integrations = Vec::with_capacity(integrations.len());
    for requirement in &integrations {
        let surface = row_str(requirement, "integration_surface");
        if !seen_surfaces.insert(surface.clone()) {
            return refuse(
                &spec.code("surface_declared_twice"),
                format!("'{surface}' carries two connector-mapping bindings; which one governs would be undecided"),
            );
        }
        let mapping_ref = row_str(requirement, "connector_mapping_revision_ref");
        let mapping = match super::data_transformation_routes::resolve_admitted_connector_mapping(
            &st.data_dir,
            &caller.identity,
            &mapping_ref,
        ) {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        if mapping.registry_status != "active" {
            return refuse(
                &spec.code("connector_mapping_not_active"),
                format!(
                    "'{mapping_ref}' is '{}' rather than active",
                    mapping.registry_status
                ),
            );
        }
        resolved_integrations.push(json!({
            "integration_surface": surface,
            "connector_mapping_revision_ref": mapping_ref,
            // CANON'S CONFORMANCE CHECK, PINNED SERVER-SIDE. A connector mapping is a field map;
            // possession of one implies no credential and no authority, and the record says so in
            // bytes the caller did not write.
            "credential_custody_nonclaim": "pack_connectors_do_not_imply_credential_custody",
            "safety_envelope_required": requirement
                .get("safety_envelope_required")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }));
    }

    // ---------------------------------------------------------- output fields and their coverage
    let output_fields = match ref_list(&body, "declared_output_fields", 256, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let field_requirements = match object_rows(&body, "declared_field_requirements", 256) {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    if output_fields.is_empty() {
        return refuse(
            &spec.code("output_fields_required"),
            "a pack declares at least one output field; the field set is what a binding must cover exactly once, so an empty one makes the binding's coverage vacuous",
        );
    }
    let required_fields: BTreeSet<String> = field_requirements
        .iter()
        .map(|row| row_str(row, "output_field_ref"))
        .collect();
    if required_fields.len() != field_requirements.len() {
        return refuse(
            &spec.code("field_requirement_declared_twice"),
            "one output field carries two requirement rows; which disposition governs it would be undecided",
        );
    }
    let declared_fields: BTreeSet<String> = output_fields.iter().cloned().collect();
    if let Some(missing) = declared_fields.difference(&required_fields).next() {
        return refuse(
            &spec.code("declared_field_without_a_requirement"),
            format!("'{missing}' is a declared output field with no requirement row; a binding could not tell whether its absence is an abstention or an escalation"),
        );
    }
    if let Some(orphan) = required_fields.difference(&declared_fields).next() {
        return refuse(
            &spec.code("field_requirement_without_a_field"),
            format!("'{orphan}' carries a requirement but is not a declared output field"),
        );
    }

    let evidence_requirements = match object_rows(&body, "declared_evidence_requirements", 128) {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    let review_modes = match object_rows(&body, "declared_review_modes", 32) {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    let mut seen_risk: BTreeSet<String> = BTreeSet::new();
    for mode in &review_modes {
        let risk = row_str(mode, "risk_class");
        if !seen_risk.insert(risk.clone()) {
            return refuse(
                &spec.code("review_mode_declared_twice"),
                format!("'{risk}' carries two review modes; a consumer reading the first row would silently take the weaker one"),
            );
        }
    }
    // THE REVIEW MODE IS THE PACK'S, THE REVIEW IS M03.15'S. Pinned server-side so the record cannot
    // read as though this module performed a review.
    let review_modes: Vec<Value> = review_modes
        .iter()
        .map(|mode| {
            json!({
                "risk_class": row_str(mode, "risk_class"),
                "review_mode": row_str(mode, "review_mode"),
                "review_owner_module": "M03.15",
            })
        })
        .collect();

    let does_not_decide = match ref_list(&body, "does_not_decide", 12, spec) {
        Ok(list) if !list.is_empty() => list,
        Ok(_) => MANDATORY_NONCLAIMS
            .iter()
            .map(|token| (*token).to_string())
            .chain(std::iter::once("credential_custody".to_string()))
            .collect(),
        Err(response) => return response,
    };
    if let Some(missing) = MANDATORY_NONCLAIMS
        .iter()
        .find(|token| !does_not_decide.iter().any(|held| held == *token))
    {
        return refuse(
            &spec.code("nonclaim_dropped"),
            format!(
                "'{missing}' must remain in does_not_decide; the M05 boundary and canon's own Does Not Own list are stated in the record's bytes, and a shortened set is how a boundary quietly stops binding"
            ),
        );
    }

    let ordinal = stream.len() as u64 + 1;
    let revision_ref = format!("{resource}/revision/{ordinal}");
    let predecessor = stream.last();
    let succession_reason = {
        let raw = body_str(&body, "succession_reason");
        if predecessor.is_none() {
            "genesis".to_string()
        } else if raw.is_empty() || !SUCCESSION_REASONS.contains(&raw.as_str()) {
            "correction".to_string()
        } else {
            raw
        }
    };
    let succession = match predecessor {
        None => json!({
            "succession_reason": "genesis",
            "predecessor_revision_ref": Value::Null,
            "predecessor_content_hash": Value::Null,
            "supersedes_predecessor": false,
        }),
        Some(entry) => json!({
            "succession_reason": succession_reason,
            "predecessor_revision_ref": entry.record.get("revision_ref").cloned().unwrap_or(Value::Null),
            "predecessor_content_hash": entry.record.get("content_hash").cloned().unwrap_or(Value::Null),
            "supersedes_predecessor": true,
        }),
    };
    let migration = json!({
        "compatibility": if predecessor.is_none() { "initial" } else { "additive" },
        // A DOWNGRADE IS REFUSED, NOT NEGOTIATED. There is no adapter from this contract to a
        // predecessor, because there is no predecessor; saying so keeps the field honest when there
        // one day is.
        "downgrade_to_predecessor": "refused",
    });

    // HOISTED OUT OF THE `json!` BODY DELIBERATELY. `json!` reads a `{` in value position as a
    // nested object, so a block expression there is a parse error rather than a value — and a
    // `match` that can `return` cannot live inside the macro at all.
    let forbidden_action_refs = match ref_list(&body, "forbidden_action_refs", 128, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let registry_status = {
        let raw = body_str(&body, "registry_status");
        if raw.is_empty() {
            "active".to_string()
        } else {
            raw
        }
    };
    let jurisdiction_refs = match ref_list(&body, "jurisdiction_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };

    let recorded_at_ms = agentgres::parse_rfc3339_ms(&body_str(&body, "effective_at"));
    let record = json!({
        "schema_version": spec.schema_version,
        "vertical_ontology_pack_id": resource,
        "revision_ref": revision_ref,
        "owner_ref": caller.owner_ref,
        "tenant_ref": contract_tenant_ref(&caller.owner_ref),
        // PINNED, AND THE REF BESIDE IT IS RESOLVED TOO. A caller that supplies its own principal
        // resolution has authenticated nothing.
        "principal_resolution": "server_resolved",
        "resolved_principal_ref": caller.identity.principal_ref,
        "legacy_pack_id": body_str(&body, "legacy_pack_id"),
        // CANON'S SPELLING IS CARRIED, AND ITS NON-RESOLVABILITY IS COMMITTED. A consumer that tried
        // to resolve `legacy_pack_id` contradicts a field in the record rather than making an
        // understandable mistake.
        "legacy_pack_id_is_display_only": true,
        "display_name": body_str(&body, "display_name"),
        "base_ontology_revision_ref": ontology.ontology_id,
        // THE BYTES THE OWNER SERVED, not a hash the caller typed beside a ref.
        "base_ontology_content_hash": ontology.content_hash,
        "declared_object_type_refs": object_type_refs,
        "declared_task_classes": task_classes,
        "declared_action_bindings": resolved_bindings,
        "declared_integration_requirements": resolved_integrations,
        "declared_output_fields": output_fields,
        "declared_field_requirements": field_requirements,
        "declared_evidence_requirements": evidence_requirements,
        "declared_review_modes": review_modes,
        "forbidden_action_refs": forbidden_action_refs,
        "jurisdiction_refs": jurisdiction_refs,
        "registry_status": registry_status,
        "admitted_at": admitted_stamp(recorded_at_ms),
        "succession": succession,
        "migration": migration,
        "constants": {
            "commitment_domain": spec.commitment_domain,
            "lifecycle_id": "vertical_ontology_pack_lifecycle.v1",
            "review_owner_module": "M03.15",
            "identity_is_the_revision_ref": true,
            "legality_token": "legality",
        },
        "authority_nonclaim": "vertical_ontology_pack_grants_no_authority",
        "truth_nonclaim": "vertical_ontology_pack_is_a_declared_domain_extension_not_domain_correctness",
        // ACC-18 CLAUSE 13, PINNED. No HIPAA, payer, medical, coding or jurisdictional correctness is
        // asserted by a pack, ever, and a caller cannot set this field at all.
        "legal_conformity_claim": "not_determined",
        "does_not_decide": does_not_decide,
    });

    finish_admission(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        "vertical_ontology_pack",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        json!({
            "a_pack_declares_and_decides_nothing": true,
            "base_ontology_resolved_by": "ontology_version_routes::resolve_admitted_revision",
            "action_contracts_resolved_by": "ontology_action_contract_routes::resolve_admitted_action_contract",
            "connector_mappings_resolved_by": "data_transformation_routes::resolve_admitted_connector_mapping",
        }),
    )
}

// ========================================================================================== query

#[derive(serde::Deserialize)]
pub(crate) struct PackQuery {
    namespace: Option<String>,
    name: Option<String>,
    revision: Option<u64>,
    as_of_admitted_at: Option<String>,
}

/// GET /v1/hypervisor/vertical-ontology-packs — inventory, one family, or one exact revision.
///
/// WRITTEN HERE RATHER THAN SHARED, because the shared `family_query` pins a ONE-segment family
/// token and this family is owner-qualified. Everything below it — scope, chain projection,
/// content-hash re-derivation, cache reporting — is the shared implementation.
pub(crate) async fn handle_vertical_ontology_pack_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<PackQuery>,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let (Some(namespace), Some(name)) = (query.namespace.as_deref(), query.name.as_deref()) else {
        return match authorized_request_resource_refs(&st.data_dir, &identity, PACK.resource_kind) {
            Ok(refs) => (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "vertical_ontology_pack_refs": refs.into_iter().collect::<Vec<_>>(),
                })),
            ),
            Err(error) => scope_refusal_reply(error),
        };
    };
    if !canonical_segment(namespace) || !canonical_segment(name) {
        return refuse(
            &PACK.code("identity_not_canonical"),
            "'namespace' and 'name' are each a canonical lowercase token",
        );
    }
    let resource = pack_family_ref(namespace, name);
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        &identity,
        PACK.resource_kind,
        &resource,
        None,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(&PACK, &st.data_dir, &identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let index_state = projection_cache_state(&resource, &stream);
    let mut records: Vec<&AdmittedRecord> = stream.iter().collect();
    if let Some(cutoff) = query.as_of_admitted_at.as_deref() {
        let cutoff_ms = agentgres::parse_rfc3339_ms(cutoff);
        if cutoff_ms == 0 {
            return refuse(
                &PACK.code("as_of_not_canonical"),
                "as_of_admitted_at is an RFC3339 instant; a malformed stamp reads as absent, never as zero-o'clock",
            );
        }
        records.retain(|entry| entry.recorded_at_ms <= cutoff_ms);
    }
    if let Some(ordinal) = query.revision {
        let wanted = format!("{resource}/revision/{ordinal}");
        let Some(entry) = records
            .iter()
            .find(|entry| entry.record.get("revision_ref") == Some(&json!(wanted)))
        else {
            return bad(
                StatusCode::NOT_FOUND,
                &PACK.code("revision_absent"),
                format!("this family has no revision {ordinal} at the requested point — an absent revision is a typed absence, never an empty success"),
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
            "revisions": records.iter().map(|entry| entry.record.clone()).collect::<Vec<_>>(),
            "admissions": records.iter().map(|entry| entry.admission.clone()).collect::<Vec<_>>(),
            "head": stream.last().map(|last| last.head.clone()),
            "index_state": index_state,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registered positive fixture must hash to the number it carries under THIS module's
    /// material list. A gate computing both sides from one source would certify nothing; the fixture
    /// is a committed pin and the material list is this build's independent reading of it.
    #[test]
    fn registered_pack_fixture_matches_this_modules_material_list() {
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/vertical-ontology-pack-v1/positive-synthetic-sensitive-records.json"
        ));
        let record: Value = serde_json::from_str(fixture).expect("the fixture parses");
        let committed = record
            .get("content_hash")
            .and_then(Value::as_str)
            .expect("the fixture carries a commitment");
        let derived = PACK
            .content_hash(&record)
            .expect("the material list resolves");
        assert_eq!(
            derived, committed,
            "this module's material list disagrees with the registered commitment"
        );
    }

    /// Owner-qualified identity, both segments, and no other spelling.
    #[test]
    fn only_the_two_segment_owner_qualified_identity_parses() {
        let good = "vertical-pack://acme-records/synthetic-sensitive/revision/3";
        let (family, ordinal) =
            parse_two_segment_revision_ref("vertical-pack://", good).expect("the exact ref parses");
        assert_eq!(family, "vertical-pack://acme-records/synthetic-sensitive");
        assert_eq!(ordinal, 3);

        for refused in [
            // a one-segment family — the shape this cut corrected away from
            "vertical-pack://acme-records/revision/3",
            // a family head, where a revision is required
            "vertical-pack://acme-records/synthetic-sensitive",
            // three segments belong to the action-contract family, not this one
            "vertical-pack://acme-records/synthetic-sensitive/extra/revision/3",
            // zero-padded, zero, and non-numeric ordinals
            "vertical-pack://acme-records/synthetic-sensitive/revision/03",
            "vertical-pack://acme-records/synthetic-sensitive/revision/0",
            "vertical-pack://acme-records/synthetic-sensitive/revision/latest",
            // a segment that is not canonical
            "vertical-pack://Acme-Records/synthetic-sensitive/revision/1",
            "vertical-pack://acme_records/synthetic-sensitive/revision/1",
            // smuggled separators and tails
            "vertical-pack://acme-records/synthetic-sensitive/revision/1#x",
            "vertical-pack://acme-records/synthetic-sensitive/revision/1?x=1",
        ] {
            assert!(
                parse_two_segment_revision_ref("vertical-pack://", refused).is_none(),
                "'{refused}' must be refused rather than repaired"
            );
        }
    }

    /// The seven boundary tokens are the ones whose omission would let a pack read as deciding the
    /// thing it does not decide.
    #[test]
    fn the_mandatory_nonclaims_are_the_m05_boundary() {
        assert_eq!(MANDATORY_NONCLAIMS.len(), 7);
        for token in [
            "legality",
            "reviewer_qualification",
            "authority",
            "marketplace_eligibility",
            "payment",
            "correctness",
            "live_medical_suitability",
        ] {
            assert!(MANDATORY_NONCLAIMS.contains(&token));
        }
    }

    /// The content commitment covers content and NOT admission: committing the admission block would
    /// move a predecessor's hash the moment a successor landed.
    #[test]
    fn the_commitment_excludes_admission_and_the_hash_itself() {
        for excluded in ["admission", "content_hash", "index_state"] {
            assert!(!PACK.material_fields.contains(&excluded));
        }
        for included in [
            "base_ontology_content_hash",
            "declared_action_bindings",
            "declared_output_fields",
            "does_not_decide",
            "legal_conformity_claim",
        ] {
            assert!(PACK.material_fields.contains(&included));
        }
    }
}
