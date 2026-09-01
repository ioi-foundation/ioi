//! M05.10 — `VerticalPackWorkerBinding`: the deterministic ontology-to-worker compiler.
//!
//! THIS IS A DERIVATION, NOT A SUBMISSION. Every `compiled_*` array, the risk ladder, the
//! abstentions and the escalations are resolved server-side from the admitted pack and its owners'
//! seams. A caller supplies only REFS and per-field proposals; authoring a compiled field is refused
//! by name before anything is read. That is INV-37 in the shape canon asks for — the admitting core
//! resolves the values it checks instead of reading ones the requester wrote into the request.
//!
//! SILENCE ABOUT A FIELD IS INADMISSIBLE, AND THE LOOP IS WHY. The compiler iterates the PACK's own
//! `declared_output_fields`, not the caller's proposals, and emits exactly one row per field into
//! contracts, abstentions or escalations. A proposal naming a field the pack never declared is
//! refused; a field with no proposal becomes a typed row rather than a gap. Coverage is therefore
//! total BY CONSTRUCTION, and the registered invariant closes over the same set from the other
//! direction: a field in two buckets makes the covering long, a field in none makes it short.
//!
//! EVERY INPUT CROSSES ITS OWNER'S SEAM UNDER THE CALLER'S OWN OWNER BINDING, so a cross-principal
//! or cross-tenant input is refused at the scope boundary before any bytes are read — not resolved
//! first and compared afterwards, which would be a leak with a check bolted on behind it. M05.1 for
//! ontology revisions and terms, M05.2 for crosswalks and mapping decisions, M05.4 for action
//! contracts, M05.7 for recipes, runs and connector mappings, M05.8 for policy-bound views, M07.2
//! for model-route rights, M10.3 for the compiled learning boundary, and M05.10's own pack seam.
//! This module invents no substitute for any of them and reads no other module's chain.
//!
//! ABSTAIN AND ESCALATE ARE DIFFERENT DESKS, AND THE CAUSE CODES SAY WHICH. An abstention is the
//! worker declining to produce a value; an escalation is the vertical unable to proceed without an
//! accountable owner. `insufficient_evidence` is not a mapping problem — the mapping may be exact,
//! admitted, unchallenged and current and the field still lack the evidence the pack itself demanded.
//! `mapping_decision_challenged` is not `reviewer_decision_superseded` — an open dispute nobody has
//! resolved is not a decision that was replaced. Collapsing either pair would send a finding to the
//! wrong person.
//!
//! DETERMINISM IS THE POINT. The field loop runs in the pack's declared order, every derived list is
//! built in a canonical order the server imposes, and no wall-clock or random input enters the
//! commitment. Compiling the same resolved inputs twice yields byte-identical `compiled_*` output
//! and therefore the same `content_hash`, across processes and across a restart with the read index
//! destroyed. The unit's gate asserts exactly that.
//!
//! NOTHING HERE GRANTS ANYTHING. The binding carries its own authority, truth and legal-conformity
//! nonclaims in its own bytes. It compiles no permission, invokes no model, connects no account,
//! routes nothing and performs no review: `compiled_review_modes` states which mode a risk class
//! needs and pins M03.15 as the owner of the review itself.
//!
//! WHAT THIS BUILD DOES NOT RESOLVE, SAID PLAINLY. `WorkerComposition` has no registered contract
//! and no owner seam at this commit, so the declared `composition://` ref is COMMITTED and its
//! non-resolution is stated in `worker_composition_resolution`. This module does not broaden into
//! M14 to invent one; a field that looked resolved because it was well formed is exactly the silence
//! this estate refuses.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::data_transformation_routes::{
    resolve_admitted_connector_mapping, resolve_admitted_data_recipe,
    resolve_admitted_transformation_run,
};
use super::institutional_learning_boundary_routes::resolve_admitted_boundary_profile;
use super::model_route_rights_routes::{
    bad, body_str, contract_owner_ref, contract_tenant_ref, finish_admission, head_assertion,
    projection_cache_state, read_stream, ref_list, refuse, reject_authored, replay_for_key,
    require_exact_head, resolve_admitted_model_route_rights_contract, AdmittedRecord, FamilySpec,
    Reply,
};
use super::mutation_event_foundation::{admitted_stamp, require_write_caller, scope_refusal_reply};
use super::ontology_action_contract_routes::resolve_admitted_action_contract;
use super::ontology_version_routes::resolve_admitted_revision;
use super::policy_bound_data_view_revision_routes::resolve_admitted_policy_bound_data_view;
use super::semantic_mapping_routes::{
    resolve_admitted_crosswalk, resolve_admitted_mapping_revision,
};
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity,
};
use super::vertical_ontology_pack_routes::{
    canonical_segment, resolve_admitted_pack_revision, ResolvedVerticalPack,
};
use super::DaemonState;

// ============================================================================== family descriptor

static BINDING: FamilySpec = FamilySpec {
    owner_namespace: "vertical-pack-worker-bindings",
    resource_kind: "vertical_pack_worker_binding",
    admit_op: "event_stream.vertical_pack_worker_binding_revision_admitted",
    payload_schema: "ioi.hypervisor.vertical-pack-worker-binding-revision-admission.v1",
    contract_id: "schema://ioi/domains/aiagent/vertical-pack-worker-binding/v1",
    schema_version: "ioi.vertical-pack-worker-binding.v1",
    record_key: "vertical_pack_worker_binding_record",
    code_prefix: "vertical_pack_worker_binding",
    commitment_domain: "ioi.vertical-pack-worker-binding-content-commitment-jcs-sha256.v1",
    material_fields: &[
        "schema_version",
        "vertical_pack_worker_binding_id",
        "revision_ref",
        "owner_ref",
        "tenant_ref",
        "principal_resolution",
        "resolved_principal_ref",
        "vertical_ontology_pack_revision_ref",
        "vertical_ontology_pack_content_hash",
        "base_ontology_revision_ref",
        "base_ontology_content_hash",
        "worker_composition_ref",
        "worker_composition_resolution",
        "effective_boundary_binding",
        "declared_output_fields",
        "compiled_task_classes",
        "compiled_action_risk_mappings",
        "pack_declared_risk_ladder",
        "compiled_integration_requirements",
        "compiled_field_contracts",
        "compiled_evidence_requirements",
        "compiled_review_modes",
        "abstentions",
        "escalations",
        "jurisdiction_refs",
        "registry_status",
        "admitted_at",
        "succession",
        "migration",
        "constants",
        "authority_nonclaim",
        "truth_nonclaim",
        "legal_conformity_claim",
        "does_not_assert",
    ],
    identity_field: "revision_ref",
    ref_scheme: "vertical-binding://",
    stamp_field: "admitted_at",
};

/// Fields the SERVER resolves. THIS LIST IS THE COMPILER'S BOUNDARY: everything a caller could use
/// to pre-decide the compilation is here, and authoring any of them is refused by name before a
/// single owner seam is crossed.
const BINDING_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "vertical_pack_worker_binding_id",
    "revision_ref",
    "tenant_ref",
    "principal_resolution",
    "resolved_principal_ref",
    "vertical_ontology_pack_content_hash",
    "base_ontology_revision_ref",
    "base_ontology_content_hash",
    "worker_composition_resolution",
    "effective_boundary_binding",
    "declared_output_fields",
    "compiled_task_classes",
    "compiled_action_risk_mappings",
    "pack_declared_risk_ladder",
    "compiled_integration_requirements",
    "compiled_field_contracts",
    "compiled_evidence_requirements",
    "compiled_review_modes",
    "abstentions",
    "escalations",
    "jurisdiction_refs",
    "admitted_at",
    "succession",
    "migration",
    "constants",
    "authority_nonclaim",
    "truth_nonclaim",
    "legal_conformity_claim",
    "content_hash",
];

/// The ten mandatory nonclaims: NN 9's six, plus the four ACC-18/M05 boundary tokens.
const MANDATORY_NONCLAIMS: &[&str] = &[
    "authority",
    "capability_grant",
    "lease",
    "policy_decision",
    "effect_admission",
    "invocation",
    "legality",
    "reviewer_qualification",
    "marketplace_eligibility",
    "domain_correctness",
];

const DEFAULT_NONCLAIMS: &[&str] = &[
    "authority",
    "capability_grant",
    "lease",
    "policy_decision",
    "effect_admission",
    "invocation",
    "legality",
    "reviewer_qualification",
    "marketplace_eligibility",
    "payment",
    "domain_correctness",
    "live_medical_suitability",
    "measured_field_confidence",
    "worker_composition_resolution",
];

/// The predecessor view family, named here as the REFUSED form. It is mutable and carries no content
/// commitment, so a per-field provenance citation resting on one is unverifiable by construction.
const LEGACY_VIEW_SCHEME: &str = "policy-bound-data-view://";

/// The view use a compiled field needs at minimum. Reading a source through a view IS the use; a
/// field whose view does not permit `read` has no lawful path to a value.
const REQUIRED_VIEW_USE: &str = "read";
/// The additional use a field bound to a transformation run needs.
const TRANSFORM_VIEW_USE: &str = "transform";

// ============================================================================ per-field outcomes

/// One field's compiled outcome. EXACTLY ONE of these per declared field, which is what makes the
/// registered coverage rule closeable.
enum FieldOutcome {
    Compiled(Box<Value>),
    Abstained {
        cause: &'static str,
        cause_ref: String,
        disposition: &'static str,
    },
    Escalated {
        cause: &'static str,
        cause_ref: String,
        disposition: &'static str,
    },
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

// ====================================================================================== the route

/// POST /v1/hypervisor/vertical-pack-worker-bindings — COMPILE one pack onto one composition.
///
/// The whole compilation is one deterministic pass over the resolved pack. Every refusal below is
/// fail-closed: the admission returns a typed error and appends nothing, so a refused compilation
/// leaves the stream head and record count exactly where they were.
pub(crate) async fn handle_vertical_pack_worker_binding_compile(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let spec = &BINDING;
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        contract_owner_ref(&caller.owner_ref, &spec.code("owner_scheme_unsupported"))
    {
        return response;
    }
    // CALLER-AUTHORED COMPILED EVIDENCE IS REFUSED BEFORE ANY SEAM IS CROSSED. A compilation taken
    // over constants the requester supplied is void for conformance purposes.
    if let Err(response) = reject_authored(&body, spec, BINDING_SERVER_RESOLVED) {
        return response;
    }

    let namespace = body_str(&body, "namespace");
    let name = body_str(&body, "name");
    if !canonical_segment(&namespace) || !canonical_segment(&name) {
        return refuse(
            &spec.code("identity_not_canonical"),
            "'namespace' and 'name' are each a canonical lowercase token; a binding family is owner-qualified as vertical-binding://<namespace>/<name>",
        );
    }
    let resource = format!("vertical-binding://{namespace}/{name}");
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
        "vertical_pack_worker_binding",
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

    // ================================================== the pack, through M05.10's own owner seam
    let pack_ref = body_str(&body, "vertical_ontology_pack_revision_ref");
    let pack = match resolve_admitted_pack_revision(
        &st.data_dir,
        &caller.identity,
        Some(&caller.owner_ref),
        &pack_ref,
    ) {
        Ok(pack) => pack,
        Err(response) => return response,
    };
    // CROSS-TENANT IS REFUSED BY NAME AS WELL AS AT THE SCOPE BOUNDARY. The seam above already
    // refused a cross-principal read; this names the tenancy fact so an operator sees WHY rather
    // than reading an opaque scope error.
    let tenant_ref = contract_tenant_ref(&caller.owner_ref);
    if pack.tenant_ref != tenant_ref {
        return refuse(
            &spec.code("cross_tenant_pack_refused"),
            format!(
                "'{pack_ref}' is bound to {} while this compilation is bound to {tenant_ref}; cross-tenant reuse is default-deny and a compilation is never the place it becomes available",
                pack.tenant_ref
            ),
        );
    }
    if !pack.is_active() {
        return refuse(
            &spec.code("pack_not_active"),
            format!(
                "'{pack_ref}' is '{}' rather than active; only an active pack compiles",
                pack.text("/registry_status")
            ),
        );
    }

    // JURISDICTION IS FAIL-CLOSED FOR THE WHOLE BINDING, NOT ONE FIELD. A compilation with no
    // jurisdiction has nothing to be a compilation under, so the admission refuses and no record
    // exists. The PACK carries no jurisdiction floor precisely so this refusal stays reachable.
    let jurisdiction_refs = pack.list("/jurisdiction_refs");
    if jurisdiction_refs.is_empty() {
        return refuse(
            &spec.code("jurisdiction_absent"),
            format!("'{pack_ref}' resolves no jurisdiction; a compilation under no jurisdiction is not a narrower compilation, it is an unbounded one, and it fails closed"),
        );
    }

    // ============================================ the effective policy, through M10.3's owner seam
    let boundary_ref = body_str(&body, "learning_boundary_profile_revision_ref");
    let boundary = match resolve_admitted_boundary_profile(
        &st.data_dir,
        &caller.identity,
        Some(&caller.owner_ref),
        &boundary_ref,
    ) {
        Ok(boundary) => boundary,
        Err(response) => return response,
    };
    if !boundary.is_active() {
        return refuse(
            &spec.code("boundary_not_active"),
            format!("'{boundary_ref}' is not active; a compilation under a boundary that is not in force is a compilation under no boundary"),
        );
    }
    let effective_policy_hash = boundary.compiled_policy_hash.clone();

    // ======================================= model route rights, through M07.2's read-only seam
    let route_ref = body_str(&body, "model_route_rights_revision_ref");
    let route = match resolve_admitted_model_route_rights_contract(
        &st.data_dir,
        &caller.identity,
        Some(&caller.owner_ref),
        &route_ref,
    ) {
        Ok(route) => route,
        Err(response) => return response,
    };
    if !route.is_live() {
        return refuse(
            &spec.code("route_rights_not_live"),
            format!("'{route_ref}' has expired, been superseded, suspended or revoked; a route contract that is not current contributes only denial"),
        );
    }

    // ============================ the composition: COMMITTED, and its non-resolution is committed
    let worker_composition_ref = body_str(&body, "worker_composition_ref");
    if !worker_composition_ref.starts_with("composition://") || worker_composition_ref.len() > 200 {
        return refuse(
            &spec.code("worker_composition_ref_not_canonical"),
            "a worker composition is named as 'composition://…'; M14 owns the family and this build resolves nothing about it, which the record states rather than implies",
        );
    }

    // ================================================ the compiled projections of the pack itself
    let compiled_task_classes = pack.rows("/declared_task_classes");
    let compiled_evidence_requirements = pack.rows("/declared_evidence_requirements");
    let pack_review_modes = pack.rows("/declared_review_modes");
    let compiled_review_modes: Vec<Value> = pack_review_modes
        .iter()
        .map(|mode| {
            json!({
                "risk_class": row_str(mode, "risk_class"),
                "review_mode": row_str(mode, "review_mode"),
                "review_owner_module": "M03.15",
                // PINNED. The record cannot read as though this compilation performed a review.
                "this_binding_performed_no_review": true,
            })
        })
        .collect();

    // ---------------------------------------- action/risk mappings, both columns, resolved again
    let mut compiled_action_risk_mappings = Vec::new();
    let mut pack_declared_risk_ladder = Vec::new();
    for binding in pack.rows("/declared_action_bindings") {
        let action_type_ref = row_str(&binding, "action_type_ref");
        let contract_ref = row_str(&binding, "action_contract_revision_ref");
        let contract =
            match resolve_admitted_action_contract(&st.data_dir, &caller.identity, &contract_ref) {
                Ok(resolved) => resolved,
                Err(response) => return response,
            };
        let declared_risk = row_str(&binding, "risk_class");
        // RISK TRANSPOSITION AND SUBSTITUTION, REFUSED ROW BY ROW. The pack's admission checked this
        // once; the compilation checks it AGAIN against what M05.4 serves NOW, because the contract
        // may have been superseded since. The multiset half of the same fact rides offline in
        // `pack_declared_risk_ladder`, and a transposition between two rows — which a multiset
        // comparison cannot see — is refused here.
        if declared_risk != contract.risk_class {
            return refuse(
                &spec.code("risk_class_disagrees_with_the_resolved_contract"),
                format!(
                    "'{action_type_ref}' is declared '{declared_risk}' while '{contract_ref}' now carries '{}'; a compiled risk mapping that disagrees with the contract the action passes through would make every downstream gate read the wrong number",
                    contract.risk_class
                ),
            );
        }
        pack_declared_risk_ladder.push(declared_risk.clone());
        compiled_action_risk_mappings.push(json!({
            "action_type_ref": action_type_ref,
            "pack_declared_risk_class": declared_risk,
            "action_contract_revision_ref": contract_ref,
            "action_contract_content_hash": contract.content_hash,
            "action_contract_risk_class": contract.risk_class,
            "action_contract_required_gates": contract.required_gates,
            "review_mode": row_str(&binding, "review_mode"),
            "required_integration_surface": row_str(&binding, "required_integration_surface"),
        }));
    }

    // ------------------------------------- integration requirements, each mapping resolved again
    let mut compiled_integration_requirements = Vec::new();
    for requirement in pack.rows("/declared_integration_requirements") {
        let mapping_ref = row_str(&requirement, "connector_mapping_revision_ref");
        let mapping = match resolve_admitted_connector_mapping(
            &st.data_dir,
            &caller.identity,
            &mapping_ref,
        ) {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        compiled_integration_requirements.push(json!({
            "integration_surface": row_str(&requirement, "integration_surface"),
            "connector_mapping_revision_ref": mapping_ref,
            "connector_mapping_content_hash": mapping.content_hash,
            "credential_custody_nonclaim": "pack_connectors_do_not_imply_credential_custody",
            "safety_envelope_required": requirement
                .get("safety_envelope_required")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }));
    }

    // ==================================================================== the per-field compilation
    let declared_output_fields = pack.list("/declared_output_fields");
    let requirements: BTreeMap<String, Value> = pack
        .rows("/declared_field_requirements")
        .into_iter()
        .map(|row| (row_str(&row, "output_field_ref"), row))
        .collect();

    let proposals_raw = match body.get("field_mapping_proposals") {
        None => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => {
            return refuse(
                &spec.code("field_proposals_not_canonical"),
                "'field_mapping_proposals' is an array of per-field proposals; the compiler iterates the PACK's declared fields and looks each one up here",
            )
        }
    };
    let mut proposals: BTreeMap<String, Value> = BTreeMap::new();
    for proposal in &proposals_raw {
        let field_ref = row_str(proposal, "output_field_ref");
        // A PROPOSAL FOR A FIELD THE PACK NEVER DECLARED IS REFUSED, not ignored. Ignoring it would
        // let a caller believe it had bound something the compilation never looked at.
        if !declared_output_fields.iter().any(|held| *held == field_ref) {
            return refuse(
                &spec.code("proposal_for_an_undeclared_field"),
                format!("'{field_ref}' carries a proposal but is not one of this pack's declared output fields"),
            );
        }
        if proposals
            .insert(field_ref.clone(), proposal.clone())
            .is_some()
        {
            return refuse(
                &spec.code("field_proposed_twice"),
                format!(
                    "'{field_ref}' carries two proposals; which one compiles would be undecided"
                ),
            );
        }
    }

    let mut compiled_field_contracts = Vec::new();
    let mut abstentions = Vec::new();
    let mut escalations = Vec::new();

    // THE LOOP IS OVER THE PACK'S FIELDS, IN THE PACK'S ORDER. That is what makes coverage total and
    // the output deterministic; iterating the caller's proposals would let a short list silently
    // shrink the obligation.
    for field_ref in &declared_output_fields {
        let requirement_row = requirements.get(field_ref).cloned().unwrap_or(Value::Null);
        let requirement = {
            let raw = row_str(&requirement_row, "requirement");
            if raw.is_empty() {
                "required".to_string()
            } else {
                raw
            }
        };
        let outcome = match compile_one_field(
            &st,
            &caller.identity,
            &caller.owner_ref,
            &pack,
            field_ref,
            &requirement,
            &requirement_row,
            proposals.get(field_ref),
            &worker_composition_ref,
            &route.revision_ref,
            &route.content_hash,
            &effective_policy_hash,
        ) {
            Ok(outcome) => outcome,
            Err(response) => return response,
        };
        match outcome {
            FieldOutcome::Compiled(contract) => compiled_field_contracts.push(*contract),
            FieldOutcome::Abstained {
                cause,
                cause_ref,
                disposition,
            } => abstentions.push(json!({
                "output_field_ref": field_ref,
                "requirement": requirement,
                "cause": cause,
                "cause_ref": cause_ref,
                "governing_disposition": disposition,
                "no_value_was_produced": true,
            })),
            FieldOutcome::Escalated {
                cause,
                cause_ref,
                disposition,
            } => escalations.push(json!({
                "output_field_ref": field_ref,
                "requirement": requirement,
                "cause": cause,
                "cause_ref": cause_ref,
                "governing_disposition": disposition,
                "no_value_was_produced": true,
                "escalated_to_owner_ref": caller.owner_ref,
            })),
        }
    }

    // COVERAGE, ASSERTED HERE AS WELL AS OFFLINE. The loop makes it total by construction, so this
    // can only fire if the construction itself broke — which is exactly when an assertion earns its
    // keep, and it fails closed rather than admitting a record the registered invariant would then
    // refuse on every future read.
    let covered = compiled_field_contracts.len() + abstentions.len() + escalations.len();
    if covered != declared_output_fields.len() {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            &spec.code("coverage_did_not_close"),
            format!(
                "{covered} rows cover {} declared fields; the compilation would not satisfy its own registered coverage rule and is refused rather than admitted",
                declared_output_fields.len()
            ),
        );
    }

    let does_not_assert = match ref_list(&body, "does_not_assert", 14, spec) {
        Ok(list) if !list.is_empty() => list,
        Ok(_) => DEFAULT_NONCLAIMS
            .iter()
            .map(|token| (*token).to_string())
            .collect(),
        Err(response) => return response,
    };
    if let Some(missing) = MANDATORY_NONCLAIMS
        .iter()
        .find(|token| !does_not_assert.iter().any(|held| held == *token))
    {
        return refuse(
            &spec.code("nonclaim_dropped"),
            format!("'{missing}' must remain in does_not_assert; NN 9's six and ACC-18's boundary tokens are stated in the record's own bytes"),
        );
    }
    // THE UNCERTAINTY NONCLAIM IS MANDATORY BECAUSE EVERY ROW PINS `confidence: null`. A record whose
    // per-field uncertainty is categorical while its nonclaim set implies a number was measured
    // would be overstating itself by omission.
    if !does_not_assert
        .iter()
        .any(|token| token == "measured_field_confidence")
    {
        return refuse(
            &spec.code("measured_confidence_nonclaim_dropped"),
            "'measured_field_confidence' must remain in does_not_assert; every compiled row pins confidence null and confidence_is_measured false, and a measured confidence needs a measurer this build does not have",
        );
    }

    let ordinal = stream.len() as u64 + 1;
    let revision_ref = format!("{resource}/revision/{ordinal}");
    let predecessor = stream.last();
    // HOISTED: `json!` reads a `{` in value position as a nested object, so a block expression
    // cannot appear there.
    let succession_reason = {
        let raw = body_str(&body, "succession_reason");
        if raw.is_empty() {
            "recompilation".to_string()
        } else {
            raw
        }
    };
    let registry_status = {
        let raw = body_str(&body, "registry_status");
        if raw.is_empty() {
            "active".to_string()
        } else {
            raw
        }
    };
    let compiled_field_count = compiled_field_contracts.len();
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
    let migration_compatibility = if predecessor.is_none() {
        "initial"
    } else {
        "additive"
    };

    let recorded_at_ms = agentgres::parse_rfc3339_ms(&body_str(&body, "effective_at"));
    let record = json!({
        "schema_version": spec.schema_version,
        "vertical_pack_worker_binding_id": resource,
        "revision_ref": revision_ref,
        "owner_ref": caller.owner_ref,
        "tenant_ref": tenant_ref,
        "principal_resolution": "server_resolved",
        "resolved_principal_ref": caller.identity.principal_ref,
        "vertical_ontology_pack_revision_ref": pack.revision_ref,
        // THE PACK'S BYTES, taken from what its owner served — not a hash typed beside a ref.
        "vertical_ontology_pack_content_hash": pack.content_hash,
        "base_ontology_revision_ref": pack.text("/base_ontology_revision_ref"),
        "base_ontology_content_hash": pack.text("/base_ontology_content_hash"),
        "worker_composition_ref": worker_composition_ref,
        // SAID PLAINLY RATHER THAN IMPLIED: this build resolved nothing about the composition.
        "worker_composition_resolution": "declared_unresolved_owned_by_m14",
        "effective_boundary_binding": {
            "boundary_profile_revision_ref": boundary.revision_ref,
            "boundary_profile_content_hash": boundary.content_hash,
            "effective_learning_boundary_hash": effective_policy_hash,
            "boundary_status_at_binding": "active",
        },
        "declared_output_fields": declared_output_fields,
        "compiled_task_classes": compiled_task_classes,
        "compiled_action_risk_mappings": compiled_action_risk_mappings,
        "pack_declared_risk_ladder": pack_declared_risk_ladder,
        "compiled_integration_requirements": compiled_integration_requirements,
        "compiled_field_contracts": compiled_field_contracts,
        "compiled_evidence_requirements": compiled_evidence_requirements,
        "compiled_review_modes": compiled_review_modes,
        "abstentions": abstentions,
        "escalations": escalations,
        "jurisdiction_refs": jurisdiction_refs,
        "registry_status": registry_status,
        "admitted_at": admitted_stamp(recorded_at_ms),
        "succession": succession,
        "migration": {
            "compatibility": migration_compatibility,
            "downgrade_to_predecessor": "refused",
            "refused_legacy_view_scheme": LEGACY_VIEW_SCHEME,
        },
        "constants": {
            "commitment_domain": spec.commitment_domain,
            "lifecycle_id": "vertical_pack_worker_binding_lifecycle.v1",
            "review_owner_module": "M03.15",
            "authority_token": "authority",
            "measured_confidence_token": "measured_field_confidence",
            "compilation_is_deterministic": true,
            "worker_composition_owner_module": "M14",
        },
        "authority_nonclaim": "vertical_pack_worker_binding_grants_no_authority",
        "truth_nonclaim": "vertical_pack_worker_binding_is_a_compiled_reading_of_admitted_revisions_not_domain_correctness",
        "legal_conformity_claim": "not_determined",
        "does_not_assert": does_not_assert,
    });

    finish_admission(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        "vertical_pack_worker_binding",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        json!({
            "a_binding_compiles_meaning_and_grants_nothing": true,
            "compiled_fields": compiled_field_count,
            // POSITIVE DETECTION OF THE READ INDEX, reported rather than assumed: an unchanged
            // answer is also consistent with a cache that was never dropped, which would prove
            // nothing about a rebuild.
            "pack_index_state": pack.index_state,
            "inputs_resolved_through_owner_seams": [
                "ontology_version_routes::resolve_admitted_revision",
                "semantic_mapping_routes::resolve_admitted_crosswalk",
                "semantic_mapping_routes::resolve_admitted_mapping_revision",
                "ontology_action_contract_routes::resolve_admitted_action_contract",
                "data_transformation_routes::resolve_admitted_data_recipe",
                "data_transformation_routes::resolve_admitted_transformation_run",
                "data_transformation_routes::resolve_admitted_connector_mapping",
                "policy_bound_data_view_revision_routes::resolve_admitted_policy_bound_data_view",
                "model_route_rights_routes::resolve_admitted_model_route_rights_contract",
                "institutional_learning_boundary_routes::resolve_admitted_boundary_profile",
                "vertical_ontology_pack_routes::resolve_admitted_pack_revision",
            ],
        }),
    )
}

// ============================================================ one field, one deterministic outcome

/// Compile ONE declared output field, or produce the typed reason it could not be compiled.
///
/// THE CAUSE ORDER IS FIXED AND DOCUMENTED, because two runs that ranked causes differently would
/// produce different bytes from the same world. Absence, then staleness, then meaning, then
/// evidence, then policy — each layer only reached when the one before it held.
#[allow(clippy::too_many_arguments)]
fn compile_one_field(
    st: &DaemonState,
    identity: &super::substrate_store::RequestIdentity,
    owner_ref: &str,
    pack: &ResolvedVerticalPack,
    field_ref: &str,
    requirement: &str,
    requirement_row: &Value,
    proposal: Option<&Value>,
    worker_composition_ref: &str,
    route_ref: &str,
    route_content_hash: &str,
    effective_policy_hash: &str,
) -> Result<FieldOutcome, Reply> {
    let spec = &BINDING;
    let is_required = requirement == "required";

    // ---------------------------------------------------------------------------- 1. absence
    let Some(proposal) = proposal else {
        return Ok(if is_required {
            FieldOutcome::Escalated {
                cause: "required_field_proposal_absent",
                cause_ref: field_ref.to_string(),
                disposition: "escalated",
            }
        } else {
            FieldOutcome::Abstained {
                cause: "field_proposal_absent",
                cause_ref: field_ref.to_string(),
                disposition: "not_applicable",
            }
        });
    };

    // ------------------------------------------------------- 2. staleness of the code or form
    let ontology_ref = row_str(proposal, "ontology_revision_ref");
    let ontology = resolve_admitted_revision(&st.data_dir, identity, &ontology_ref)?;
    // A SUPERSEDED REVISION IS NOT A GUESSED VALUE'S EXCUSE. The revision still resolves and its
    // bytes still carry every term; only a check against its CURRENT status finds it stale.
    if ontology.status != "active" {
        return Ok(FieldOutcome::Abstained {
            cause: "stale_code_or_form",
            cause_ref: ontology.ontology_id,
            disposition: "not_applicable",
        });
    }
    // The field must rest on the ontology the PACK was declared against. A proposal quietly moving a
    // field to another revision would compile meaning the pack never extended.
    if ontology.ontology_id != pack.text("/base_ontology_revision_ref") {
        return Ok(FieldOutcome::Abstained {
            cause: "stale_code_or_form",
            cause_ref: ontology.ontology_id,
            disposition: "not_applicable",
        });
    }

    // --------------------------------------------------------------------------- 3. meaning
    let decision_ref = row_str(proposal, "mapping_decision_revision_ref");
    let decision = resolve_admitted_mapping_revision(&st.data_dir, identity, &decision_ref)?;
    // AN OPEN DISPUTE IS NOT A SUPERSESSION. `challenged` means somebody raised a question nobody has
    // answered; `upheld` means the challenge succeeded and the map is revoked. Both need an owner,
    // and both are reported with M05.2's own standing token so the row says which.
    if decision.challenge_standing == "challenged" || decision.challenge_standing == "upheld" {
        return Ok(FieldOutcome::Escalated {
            cause: "mapping_decision_challenged",
            cause_ref: decision.ontology_mapping_id,
            disposition: if decision.challenge_standing == "upheld" {
                "upheld"
            } else {
                "challenged"
            },
        });
    }
    // A DECISION THAT IS NO LONGER STANDING. Distinct from a challenge: this one was replaced rather
    // than disputed.
    if decision.status != "active" && decision.status != "validated" {
        return Ok(FieldOutcome::Escalated {
            cause: "reviewer_decision_superseded",
            cause_ref: decision.ontology_mapping_id,
            disposition: "superseded",
        });
    }

    let crosswalk_ref = row_str(proposal, "crosswalk_revision_ref");
    let crosswalk = resolve_admitted_crosswalk(&st.data_dir, identity, &crosswalk_ref)?;
    let crosswalk_hash = crosswalk
        .get("content_hash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let source_term_ref = row_str(requirement_row, "source_term_ref");
    // AMBIGUITY IS THE CROSSWALK'S OWN FINDING, READ RATHER THAN RE-DECIDED.
    let ambiguous: BTreeSet<String> = crosswalk
        .get("ambiguous_term_refs")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if ambiguous.contains(&source_term_ref) {
        return Ok(FieldOutcome::Escalated {
            cause: "mapping_ambiguous",
            cause_ref: crosswalk_ref,
            disposition: "refused_ambiguous",
        });
    }
    let Some(mapping_row) = crosswalk
        .get("term_mappings")
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter()
                .find(|row| row_str(row, "source_term_id") == source_term_ref)
        })
        .cloned()
    else {
        // NO ROW AT ALL is the same finding as an explicit `unmapped` row, and it escalates for a
        // required field rather than abstaining: the vertical cannot proceed.
        return Ok(if is_required {
            FieldOutcome::Escalated {
                cause: "required_field_unmapped",
                cause_ref: crosswalk_ref,
                disposition: "carried_as_unmapped",
            }
        } else {
            FieldOutcome::Abstained {
                cause: "field_proposal_absent",
                cause_ref: crosswalk_ref,
                disposition: "carried_as_unmapped",
            }
        });
    };
    let relation = row_str(&mapping_row, "relation");
    if relation == "unmapped" || relation.is_empty() {
        return Ok(if is_required {
            FieldOutcome::Escalated {
                cause: "required_field_unmapped",
                cause_ref: crosswalk_ref,
                disposition: "carried_as_unmapped",
            }
        } else {
            FieldOutcome::Abstained {
                cause: "field_proposal_absent",
                cause_ref: crosswalk_ref,
                disposition: "carried_as_unmapped",
            }
        });
    }
    let declared_loss = {
        let raw = row_str(&mapping_row, "loss");
        if raw.is_empty() || raw == "unmapped" {
            "none".to_string()
        } else {
            raw
        }
    };

    // ------------------------------------------------------------------------- 4. evidence
    // THE PACK DEMANDED THIS EVIDENCE; THE PROPOSAL EITHER CARRIES IT OR THE FIELD ABSTAINS. This is
    // NOT a mapping problem: the mapping above may be exact, admitted, unchallenged and current and
    // the field still have nothing satisfying the requirement the pack itself declared.
    let evidence_requirement_ref = row_str(requirement_row, "evidence_requirement_ref");
    let supplied_evidence = row_list(proposal, "evidence_refs");
    if !evidence_requirement_ref.is_empty()
        && !supplied_evidence
            .iter()
            .any(|held| *held == evidence_requirement_ref)
    {
        return Ok(FieldOutcome::Abstained {
            cause: "insufficient_evidence",
            cause_ref: evidence_requirement_ref,
            disposition: "not_applicable",
        });
    }

    // --------------------------------------------------------------------------- 5. policy
    let view_ref = row_str(proposal, "policy_bound_data_view_revision_ref");
    // THE PREDECESSOR SPELLING IS REFUSED BY NAME, not merely unmatched. A v1 view is mutable and
    // carries no content commitment, so a provenance citation resting on one is unverifiable.
    if view_ref.starts_with(LEGACY_VIEW_SCHEME) {
        return Err(refuse(
            &spec.code("legacy_view_scheme_refused"),
            format!("'{view_ref}' names the predecessor's mutable, wall-clock-identified view family; a field-provenance citation resting on a record that carries no content commitment is unverifiable by construction, and only view://<family>/revision/<n> is admissible"),
        ));
    }
    let view = resolve_admitted_policy_bound_data_view(
        &st.data_dir,
        identity,
        Some(owner_ref),
        &view_ref,
    )?;
    if !view.is_active() {
        return Ok(FieldOutcome::Abstained {
            cause: "policy_bound_view_not_active",
            cause_ref: view.revision_ref,
            disposition: "not_applicable",
        });
    }
    // MINIMIZATION IS CHECKED PER FIELD, AGAINST M05.8'S OWN DERIVED FIELD SCOPE. A field outside the
    // view's minimized set has no lawful path to a value, however exact its mapping.
    let allowed_fields: Vec<String> = view
        .record
        .pointer("/field_scope/allowed_field_refs")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let view_field_ref = {
        let raw = row_str(proposal, "view_field_ref");
        if raw.is_empty() {
            field_ref.to_string()
        } else {
            raw
        }
    };
    if !allowed_fields.iter().any(|held| *held == view_field_ref) {
        return Ok(FieldOutcome::Abstained {
            cause: "policy_bound_view_excludes_the_field",
            cause_ref: view.revision_ref,
            disposition: "not_applicable",
        });
    }
    // THE PERMISSION IS M05.8'S SUBTRACTION, READ RATHER THAN RE-DERIVED.
    let allowed_uses = view.allowed_uses();
    let transformation_run_ref = row_str(proposal, "transformation_run_ref");
    let mut needed_uses = vec![REQUIRED_VIEW_USE];
    if !transformation_run_ref.is_empty() {
        needed_uses.push(TRANSFORM_VIEW_USE);
    }
    if let Some(denied) = needed_uses
        .iter()
        .find(|use_token| !allowed_uses.iter().any(|held| held == *use_token))
    {
        let _ = denied;
        return Ok(FieldOutcome::Abstained {
            cause: "policy_bound_view_denies_the_use",
            cause_ref: view.revision_ref,
            disposition: "not_applicable",
        });
    }
    // THE STALE-POLICY CHECK, ACROSS TWO OWNERS. The view was compiled under a boundary hash; this
    // compilation runs under a boundary hash. Moving one without the other is exactly the stale
    // binding M05.8 and M10.3 each refuse at their own layer, arriving here one layer up.
    let required_boundary_hash = view
        .record
        .pointer("/materialization_precondition/required_effective_learning_boundary_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if required_boundary_hash != effective_policy_hash {
        return Ok(FieldOutcome::Abstained {
            cause: "effective_policy_moved",
            cause_ref: view.revision_ref,
            disposition: "not_applicable",
        });
    }

    // ------------------------------------------------------------- the lineage, resolved not typed
    let recipe_ref = row_str(proposal, "data_recipe_revision_ref");
    let recipe = resolve_admitted_data_recipe(&st.data_dir, identity, &recipe_ref)?;
    let run = resolve_admitted_transformation_run(&st.data_dir, identity, &transformation_run_ref)?;
    if !run.is_completed() {
        return Err(refuse(
            &spec.code("transformation_run_not_completed"),
            format!(
                "'{transformation_run_ref}' is '{}'; a queued, running, failed or rejected run produced nothing a field could cite",
                run.execution_status
            ),
        ));
    }
    // THE RUN MUST BE A RUN OF THE RECIPE THE FIELD CITES. Two independent refs with no relation
    // would let a field cite a lineage that never happened.
    if run.data_recipe_family_ref != recipe.data_recipe_id {
        return Err(refuse(
            &spec.code("run_is_not_a_run_of_this_recipe"),
            format!(
                "'{transformation_run_ref}' ran '{}' while this field cites '{}'; a lineage assembled from two unrelated refs is not a lineage",
                run.data_recipe_family_ref, recipe.data_recipe_id
            ),
        ));
    }
    let connector_mapping_ref = row_str(proposal, "connector_mapping_revision_ref");
    let connector =
        resolve_admitted_connector_mapping(&st.data_dir, identity, &connector_mapping_ref)?;

    let span_kind = {
        let raw = row_str(proposal, "source_span_kind");
        if raw.is_empty() {
            "record_field".to_string()
        } else {
            raw
        }
    };

    Ok(FieldOutcome::Compiled(Box::new(json!({
        "output_field_ref": field_ref,
        "requirement": requirement,
        "source_ref": row_str(proposal, "source_ref"),
        "source_span": {
            "span_kind": span_kind,
            "locator": row_str(proposal, "source_span_locator"),
        },
        "data_recipe_revision_ref": recipe.revision_ref,
        "data_recipe_content_hash": recipe.content_hash,
        "transformation_run_ref": run.transformation_run_id,
        "transformation_run_content_hash": run.content_hash,
        "ontology_revision_ref": ontology.ontology_id,
        "ontology_content_hash": ontology.content_hash,
        "source_term_ref": source_term_ref,
        "crosswalk_revision_ref": crosswalk_ref,
        "crosswalk_content_hash": crosswalk_hash,
        "mapping_decision_revision_ref": decision.ontology_mapping_id,
        "mapping_decision_content_hash": decision.content_hash,
        "connector_mapping_revision_ref": connector.revision_ref,
        "connector_mapping_content_hash": connector.content_hash,
        "worker_composition_ref": worker_composition_ref,
        "model_or_rule_version_ref": route_ref,
        "model_or_rule_version_content_hash": route_content_hash,
        "uncertainty": {
            // CATEGORICAL, AND DERIVED FROM SOMEBODY ELSE'S MEASUREMENT. The relation and loss are
            // the crosswalk's own admitted, receipted, challengeable statement of semantic loss.
            "basis": "resolved_crosswalk_relation",
            "crosswalk_relation": relation,
            "declared_loss": declared_loss,
            // PINNED NULL. A float this module invented and then checked against a neighbouring
            // field it also invented would certify nothing; a measured confidence needs a measurer.
            "confidence": Value::Null,
            "confidence_is_measured": false,
        },
        "policy_bound_data_view_revision_ref": view.revision_ref,
        "policy_bound_data_view_content_hash": view.content_hash,
        "effective_policy_hash": effective_policy_hash,
    }))))
}

// ========================================================================================== query

#[derive(serde::Deserialize)]
pub(crate) struct BindingQuery {
    namespace: Option<String>,
    name: Option<String>,
    revision: Option<u64>,
    as_of_admitted_at: Option<String>,
}

/// GET /v1/hypervisor/vertical-pack-worker-bindings — inventory, one family, or one exact revision.
pub(crate) async fn handle_vertical_pack_worker_binding_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<BindingQuery>,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let (Some(namespace), Some(name)) = (query.namespace.as_deref(), query.name.as_deref()) else {
        return match authorized_request_resource_refs(
            &st.data_dir,
            &identity,
            BINDING.resource_kind,
        ) {
            Ok(refs) => (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "vertical_pack_worker_binding_refs": refs.into_iter().collect::<Vec<_>>(),
                })),
            ),
            Err(error) => scope_refusal_reply(error),
        };
    };
    if !canonical_segment(namespace) || !canonical_segment(name) {
        return refuse(
            &BINDING.code("identity_not_canonical"),
            "'namespace' and 'name' are each a canonical lowercase token",
        );
    }
    let resource = format!("vertical-binding://{namespace}/{name}");
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        &identity,
        BINDING.resource_kind,
        &resource,
        None,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(&BINDING, &st.data_dir, &identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let index_state = projection_cache_state(&resource, &stream);
    let mut records: Vec<&AdmittedRecord> = stream.iter().collect();
    if let Some(cutoff) = query.as_of_admitted_at.as_deref() {
        let cutoff_ms = agentgres::parse_rfc3339_ms(cutoff);
        if cutoff_ms == 0 {
            return refuse(
                &BINDING.code("as_of_not_canonical"),
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
                &BINDING.code("revision_absent"),
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
    /// material list — the fixture is a committed pin, the material list is this build's reading.
    #[test]
    fn registered_binding_fixture_matches_this_modules_material_list() {
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/vertical-pack-worker-binding-v1/positive-compiled-with-abstentions-and-an-escalation.json"
        ));
        let record: Value = serde_json::from_str(fixture).expect("the fixture parses");
        let committed = record
            .get("content_hash")
            .and_then(Value::as_str)
            .expect("the fixture carries a commitment");
        let derived = BINDING
            .content_hash(&record)
            .expect("the material list resolves");
        assert_eq!(
            derived, committed,
            "this module's material list disagrees with the registered commitment"
        );
    }

    /// The second positive — the one whose whole point is the two causes this cut added — must hash
    /// under the SAME list. A material list that fit one fixture and not the other would mean the
    /// commitment moved with the content it is supposed to commit.
    #[test]
    fn the_challenged_and_insufficient_evidence_fixture_hashes_under_the_same_list() {
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/vertical-pack-worker-binding-v1/positive-challenged-decision-and-insufficient-evidence.json"
        ));
        let record: Value = serde_json::from_str(fixture).expect("the fixture parses");
        assert_eq!(
            BINDING.content_hash(&record).expect("resolves"),
            record.get("content_hash").and_then(Value::as_str).unwrap()
        );
    }

    /// Ten mandatory nonclaims, and the uncertainty one is separately mandatory because every
    /// compiled row pins `confidence: null`.
    #[test]
    fn the_mandatory_nonclaims_are_nn9_plus_the_acc18_boundary() {
        assert_eq!(MANDATORY_NONCLAIMS.len(), 10);
        for token in [
            "authority",
            "capability_grant",
            "lease",
            "policy_decision",
            "effect_admission",
            "invocation",
        ] {
            assert!(
                MANDATORY_NONCLAIMS.contains(&token),
                "NN 9 token {token} missing"
            );
        }
        for token in [
            "legality",
            "reviewer_qualification",
            "marketplace_eligibility",
            "domain_correctness",
        ] {
            assert!(
                MANDATORY_NONCLAIMS.contains(&token),
                "ACC-18 boundary token {token} missing"
            );
        }
        assert!(DEFAULT_NONCLAIMS.contains(&"measured_field_confidence"));
        assert!(DEFAULT_NONCLAIMS.contains(&"worker_composition_resolution"));
        for mandatory in MANDATORY_NONCLAIMS {
            assert!(DEFAULT_NONCLAIMS.contains(mandatory));
        }
    }

    /// The commitment covers the compilation and NOT the admission block.
    #[test]
    fn the_commitment_excludes_admission_and_covers_every_compiled_array() {
        for excluded in ["admission", "content_hash", "index_state"] {
            assert!(!BINDING.material_fields.contains(&excluded));
        }
        for included in [
            "declared_output_fields",
            "compiled_field_contracts",
            "abstentions",
            "escalations",
            "pack_declared_risk_ladder",
            "effective_boundary_binding",
            "worker_composition_resolution",
        ] {
            assert!(
                BINDING.material_fields.contains(&included),
                "'{included}' must be inside the content commitment"
            );
        }
    }

    /// A binding family is owner-qualified exactly like the pack it compiles.
    #[test]
    fn the_binding_family_is_two_segment_owner_qualified() {
        use super::super::vertical_ontology_pack_routes::parse_two_segment_revision_ref;
        let (family, ordinal) = parse_two_segment_revision_ref(
            "vertical-binding://",
            "vertical-binding://acme-records/records-worker/revision/2",
        )
        .expect("the exact ref parses");
        assert_eq!(family, "vertical-binding://acme-records/records-worker");
        assert_eq!(ordinal, 2);
        assert!(parse_two_segment_revision_ref(
            "vertical-binding://",
            "vertical-binding://acme-records/revision/2"
        )
        .is_none());
    }
}
