//! M06.9 — learning lineage: retention, hold, erasure and residual exposure as DERIVED facts over
//! the daemon's own lineage refs, never a rewrite of them.
//!
//! Canon: `foundations/institutional-learning-boundary.md` § Derived Rights, Revocation, And Honest
//! Unlearning (the impact graph; block, quarantine, rebuild, retrain, recall, minimum audit
//! commitment; "a revocation or impact record does not prove that a trained model has forgotten";
//! residual exposure stays visible) and `foundations/objects/institutional-learning.md`
//! § LearningImpactRecordEnvelope (the registered shape). Three things live here:
//!
//!   * THE WALKER (`GET /v1/hypervisor/learning-lineage/impact`): from a resolved subject it
//!     traverses views by their bound claims, consents, route rights and boundary profiles;
//!     data recipes and transformation runs by their views; Foundry recipes by their data recipe,
//!     claims and boundary; dataset snapshots by their recipe; programs, checkpoints and
//!     qualification proposals by their snapshot; artifact intents by their checkpoint hash — and
//!     derives ONE disposition per affected family. It mutates nothing and offers no verb that
//!     could retro-edit an admitted record.
//!   * THE IMPACT RECORD (`POST /v1/hypervisor/learning-impact-records`): the same traversal
//!     admitted as a registered record on the shared owner-scoped mutation chain, with the trigger
//!     resolved through its owner (an invalidation that has not happened cannot be recorded), the
//!     graph root committed, residual exposure listed, and NO unlearning claim without the
//!     evidence its kind names (`false_unlearning_claim`).
//!   * THE FENCE (`refuse_if_quarantined`): a transformation run, a Foundry recipe run, a program
//!     or a qualification over an input an admitted impact record quarantined is refused
//!     `learning_source_quarantined`. The fence reads the admitted records ESTATE-WIDE — a
//!     quarantine is institutional truth, not one principal's view.
//!
//! What this basis does NOT hold, typed as the frontier rather than pretended: embeddings, models,
//! workers, packages, releases, exports and public commitments have no daemon families; the graph
//! stops at the artifact intent, and a delivered intent reads as residual exposure.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::institutional_learning_boundary_routes::{
    boundary_profile_head_revision_ref, resolve_admitted_boundary_profile,
    resolve_admitted_source_rights_claim,
};
use super::model_route_rights_routes::{
    authorized_stream, bad, body_str, digest_over, family_token, finish_admission, head_assertion,
    project_stream, read_stream, reject_authored, replay_for_key, require_exact_head,
    resolve_admitted_model_route_rights_contract, AdmittedRecord, FamilySpec, Reply,
};
use super::mutation_event_foundation::{
    admitted_stamp, require_write_caller, scope_refusal_reply, stream_tail, WriteCaller,
};
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity, RequestIdentity, RequestResourceScope,
};
use super::{read_record_dir, DaemonState};

const IMPACT_DOMAIN: &str = "ioi.learning-impact-record-content-commitment-jcs-sha256.v1";
const GRAPH_DOMAIN: &str = "ioi.learning-impact-graph-root-jcs-sha256.v1";

pub(crate) const TRIGGER_KINDS: &[&str] = &[
    "source_right_revoked",
    "consent_withdrawn",
    "eligibility_excluded",
    "route_contract_revoked",
    "boundary_profile_superseded",
    "retention_deleted",
    "legal_hold_placed",
    "label_corrected",
];
const UNLEARNING_CLAIMS: &[&str] = &[
    "none",
    "removal_from_future_datasets",
    "clean_retraining",
    "verified_unlearning",
    "deletion",
];
/// The dispositions under which an input feeds nothing further.
const QUARANTINING: &[&str] = &["quarantined", "rebuild_required", "retrain_required"];
const MAX_AFFECTED: usize = 4096;

static IMPACT: FamilySpec = FamilySpec {
    owner_namespace: "learning-impact-records",
    resource_kind: "learning_impact_record",
    admit_op: "event_stream.learning_impact_record_admitted",
    payload_schema: "ioi.hypervisor.learning-impact-record-admission.v1",
    contract_id: "schema://ioi/foundations/objects/learning-impact-record/v1",
    schema_version: "ioi.learning-impact-record.v1",
    record_key: "learning_impact_record_record",
    code_prefix: "learning_impact_record",
    commitment_domain: IMPACT_DOMAIN,
    material_fields: &[
        "schema_version",
        "learning_impact_record_id",
        "owner_ref",
        "trigger",
        "impact_graph_root",
        "affected",
        "residual_exposure",
        "minimum_audit_commitment_ref",
        "unlearning_claim",
        "unlearning_evidence_refs",
    ],
    identity_field: "learning_impact_record_id",
    ref_scheme: "learning-impact://",
    stamp_field: "admitted_at",
};
const IMPACT_REQUEST_FIELDS: &[&str] = &[
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "expected_content_hash",
    "family",
    "trigger",
    "minimum_audit_commitment_ref",
    "unlearning_claim",
    "unlearning_evidence_refs",
];
const IMPACT_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "learning_impact_record_id",
    "impact_graph_root",
    "affected",
    "residual_exposure",
    "content_hash",
    "admitted_at",
];

// ======================================================================================== helpers

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or_default()
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn list(value: &Value, key: &str) -> Vec<String> {
    value
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

fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::from(s.as_str())).collect())
}

/// `a` names `b` when it IS `b`, or when `b` is a revision of the family `a` names, or vice versa.
fn names(a: &str, b: &str) -> bool {
    a == b || b.starts_with(&format!("{a}/revision/")) || a.starts_with(&format!("{b}/revision/"))
}

fn family_of(reference: &str) -> String {
    match reference.find("/revision/") {
        Some(at) => reference[..at].to_string(),
        None => reference.to_string(),
    }
}

fn refuse_unknown_fields(body: &Value, allowed: &[&str]) -> Result<(), Reply> {
    let Some(object) = body.as_object() else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            &IMPACT.code("request_body_not_object"),
            "the request body must be a JSON object",
        ));
    };
    let permitted: BTreeSet<&str> = allowed.iter().copied().collect();
    let unknown: Vec<String> = object
        .keys()
        .filter(|key| !permitted.contains(key.as_str()))
        .cloned()
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    Err(bad(
        StatusCode::BAD_REQUEST,
        &IMPACT.code("request_unknown_field"),
        format!("this route does not admit field(s): {}; the graph, its root and every disposition are derived, never authored", unknown.join(", ")),
    ))
}

// ==================================================================================== the graph

/// One traversal: the edges walked, the affected records with their derived dispositions, the
/// residual exposure found, and the frontier this basis cannot see past.
#[derive(Default)]
pub(crate) struct ImpactGraph {
    pub(crate) edges: Vec<Value>,
    pub(crate) affected: Vec<Value>,
    pub(crate) residual_exposure: Vec<Value>,
    pub(crate) frontier: Vec<String>,
}

impl ImpactGraph {
    fn touched(&self, reference: &str) -> bool {
        self.affected
            .iter()
            .any(|entry| text(entry, "ref") == reference)
    }

    fn reach(
        &mut self,
        from: &str,
        to: &str,
        family: &str,
        disposition: &str,
        basis: &str,
    ) -> bool {
        if self.touched(to) || self.affected.len() >= MAX_AFFECTED {
            return false;
        }
        self.edges.push(json!({ "from": from, "to": to }));
        self.affected.push(json!({
            "ref": to,
            "family": family,
            "edge": from,
            "disposition": disposition,
            "basis": basis,
        }));
        true
    }

    pub(crate) fn root(&self) -> Result<String, Reply> {
        digest_over(&json!({ "edges": self.edges }), GRAPH_DOMAIN, &["edges"]).map_err(|reason| {
            bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &IMPACT.code("graph_root_failed"),
                reason,
            )
        })
    }
}

/// The lineage families this basis holds, read once under the caller's identity.
struct Lineage {
    views: Vec<Value>,
    data_recipes: Vec<Value>,
    transformation_runs: Vec<Value>,
    foundry: super::foundry_execution_routes::FoundryLineage,
}

fn read_lineage(data_dir: &str, identity: &RequestIdentity) -> Result<Lineage, Reply> {
    Ok(Lineage {
        views: super::policy_bound_data_view_revision_routes::lineage_view_revisions(
            data_dir, identity,
        )?,
        data_recipes: super::data_transformation_routes::lineage_data_recipes(data_dir, identity)?,
        transformation_runs: super::data_transformation_routes::lineage_transformation_runs(
            data_dir, identity,
        )?,
        foundry: super::foundry_execution_routes::lineage_heads(data_dir, identity)?,
    })
}

/// Walk forward from one seed. `seed_family` says what the seed is so the first hop knows which
/// members to match; the walk is breadth-first over the families this basis holds.
fn walk(graph: &mut ImpactGraph, lineage: &Lineage, seed: &str, seed_family: &str) {
    let mut queue: Vec<(String, String)> = vec![(seed.to_string(), seed_family.to_string())];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    while let Some((current, family)) = queue.pop() {
        if !seen.insert(format!("{family}:{current}")) {
            continue;
        }
        match family.as_str() {
            "learning_source_rights_claim" => {
                for view in &lineage.views {
                    if list(view, "source_rights_claim_revision_refs")
                        .iter()
                        .any(|r| names(&current, r))
                    {
                        let reference = text(view, "revision_ref");
                        if graph.reach(
                            &current,
                            &reference,
                            "policy_bound_data_view",
                            "fenced",
                            "the view's read revalidates the claim at the read instant and refuses",
                        ) {
                            queue.push((reference, "policy_bound_data_view".into()));
                        }
                    }
                }
                for recipe in &lineage.foundry.recipes {
                    if list(recipe, "learning_source_rights_claim_refs")
                        .iter()
                        .any(|r| names(&current, r))
                    {
                        let reference = text(recipe, "recipe_revision_ref");
                        if graph.reach(&current, &reference, "foundry_recipe_run", "quarantined", "a Foundry recipe bound to a revoked claim materializes nothing further") {
                            queue.push((reference, "foundry_recipe".into()));
                        }
                    }
                }
            }
            "model_route_rights" => {
                for view in &lineage.views {
                    if list(view, "route_rights_revision_refs")
                        .iter()
                        .any(|r| names(&current, r))
                    {
                        let reference = text(view, "revision_ref");
                        if graph.reach(&current, &reference, "policy_bound_data_view", "fenced", "the view's read revalidates the route contract at the read instant and refuses") {
                            queue.push((reference, "policy_bound_data_view".into()));
                        }
                    }
                }
            }
            "learning_boundary_profile" => {
                for view in &lineage.views {
                    if names(&current, &text(view, "boundary_profile_revision_ref")) {
                        let reference = text(view, "revision_ref");
                        if graph.reach(
                            &current,
                            &reference,
                            "policy_bound_data_view",
                            "fenced",
                            "the view's boundary profile revision is no longer current",
                        ) {
                            queue.push((reference, "policy_bound_data_view".into()));
                        }
                    }
                }
                for recipe in &lineage.foundry.recipes {
                    if names(
                        &current,
                        &text(recipe, "institutional_learning_boundary_ref"),
                    ) {
                        let reference = text(recipe, "recipe_revision_ref");
                        if graph.reach(&current, &reference, "foundry_recipe_run", "quarantined", "a Foundry recipe bound to a superseded boundary materializes nothing further") {
                            queue.push((reference, "foundry_recipe".into()));
                        }
                    }
                }
            }
            "policy_bound_data_view" => {
                for recipe in &lineage.data_recipes {
                    if list(recipe, "policy_bound_data_view_refs")
                        .iter()
                        .any(|r| names(&current, r))
                    {
                        let reference = text(recipe, "revision_ref");
                        if graph.reach(
                            &current,
                            &reference,
                            "transformation_run",
                            "quarantined",
                            "a data recipe over a fenced view runs nothing further",
                        ) {
                            queue.push((reference, "data_recipe".into()));
                        }
                    }
                }
                for run in &lineage.transformation_runs {
                    if list(run, "policy_bound_data_view_refs")
                        .iter()
                        .any(|r| names(&current, r))
                    {
                        let reference = text(run, "transformation_run_id");
                        if graph.reach(
                            &current,
                            &reference,
                            "transformation_run",
                            "quarantined",
                            "a run over a fenced view feeds nothing further",
                        ) {
                            queue.push((reference, "transformation_run".into()));
                        }
                    }
                }
            }
            "data_recipe" => {
                for run in &lineage.transformation_runs {
                    if names(&current, &text(run, "data_recipe_revision_ref")) {
                        let reference = text(run, "transformation_run_id");
                        if graph.reach(
                            &current,
                            &reference,
                            "transformation_run",
                            "quarantined",
                            "a run of a quarantined recipe feeds nothing further",
                        ) {
                            queue.push((reference, "transformation_run".into()));
                        }
                    }
                }
                for recipe in &lineage.foundry.recipes {
                    if names(
                        &family_of(&current),
                        &family_of(&text(recipe, "data_recipe_ref")),
                    ) {
                        let reference = text(recipe, "recipe_revision_ref");
                        if graph.reach(&current, &reference, "foundry_recipe_run", "quarantined", "a Foundry recipe over a quarantined data recipe materializes nothing further") {
                            queue.push((reference, "foundry_recipe".into()));
                        }
                    }
                }
            }
            "transformation_run" => {
                for run in &lineage.transformation_runs {
                    if text(run, "transformation_run_id") == current {
                        let recipe_family = family_of(&text(run, "data_recipe_revision_ref"));
                        for recipe in &lineage.foundry.recipes {
                            if names(&recipe_family, &family_of(&text(recipe, "data_recipe_ref"))) {
                                let reference = text(recipe, "recipe_revision_ref");
                                if graph.reach(&current, &reference, "foundry_recipe_run", "quarantined", "a Foundry recipe over the run's data recipe materializes nothing further") {
                                    queue.push((reference, "foundry_recipe".into()));
                                }
                            }
                        }
                    }
                }
            }
            "foundry_recipe" => {
                for snapshot in &lineage.foundry.snapshots {
                    if names(
                        &family_of(&current),
                        &family_of(&text(snapshot, "recipe_revision_ref")),
                    ) {
                        let reference = text(snapshot, "dataset_snapshot_ref");
                        if graph.reach(
                            &current,
                            &reference,
                            "foundry_dataset_snapshot",
                            "rebuild_required",
                            "the snapshot materialized rows the source no longer permits",
                        ) {
                            queue.push((reference, "foundry_dataset_snapshot".into()));
                        }
                    }
                }
            }
            "foundry_dataset_snapshot" => {
                for program in &lineage.foundry.programs {
                    if text(program, "dataset_snapshot_ref") == current {
                        let reference = text(program, "program_id");
                        if graph.reach(&current, &reference, "foundry_program", "retrain_required", "a program trained on the snapshot cannot attribute or revoke what it learned") {
                            queue.push((reference, "foundry_program".into()));
                        }
                    }
                }
            }
            "foundry_program" => {
                for program in &lineage.foundry.programs {
                    if text(program, "program_id") != current {
                        continue;
                    }
                    for checkpoint in program
                        .get("checkpoints")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let reference = text(checkpoint, "checkpoint_ref");
                        if graph.reach(&current, &reference, "foundry_checkpoint", "retrain_required", "parameters derived from the snapshot; retraining, not deletion, answers the invalidation") {
                            queue.push((reference, "foundry_checkpoint".into()));
                        }
                    }
                    let proposal = text(program, "qualification_proposal_ref");
                    if !proposal.is_empty() {
                        graph.reach(&current, &proposal, "foundry_qualification_proposal", "retrain_required", "a qualification over the program's checkpoints stands on evidence that moved");
                    }
                }
            }
            "foundry_checkpoint" => {
                let hash = current.rsplit('/').next().unwrap_or_default().to_string();
                for intent in &lineage.foundry.intents {
                    if text(intent, "artifact_hash").trim_start_matches("sha256:")
                        == hash.trim_start_matches("sha256:")
                    {
                        let reference = text(intent, "intent_ref");
                        let status = text(intent, "status");
                        if graph.reach(&current, &reference, "foundry_artifact_intent", "recall_required", "an artifact packaged from the checkpoint; recall where the terms support it") && matches!(status.as_str(), "delivered" | "exported" | "published" | "installed") {
                            graph.residual_exposure.push(json!({
                                "ref": reference,
                                "recipient_class": "installed_artifact",
                                "reason": format!("the artifact intent is {status}: bytes already delivered cannot be un-delivered by any record here"),
                            }));
                        }
                    }
                }
                graph.frontier.push(format!("{current}: models, workers, packages, releases, exports and public commitments have no daemon families on this basis"));
            }
            _ => {}
        }
    }
}

/// A resolved trigger: what was invalidated, its revision, and where the walk starts.
struct Trigger {
    subject_revision_ref: Option<String>,
    seeds: Vec<(String, String)>,
}

fn resolve_trigger(
    st: &DaemonState,
    identity: &RequestIdentity,
    owner_ref: &str,
    kind: &str,
    subject_ref: &str,
) -> Result<Trigger, Reply> {
    match kind {
        "source_right_revoked" => {
            let claim = resolve_admitted_source_rights_claim(
                &st.data_dir,
                identity,
                Some(owner_ref),
                subject_ref,
            )?;
            let status = text(&claim.record, "status");
            if status != "revoked" {
                return Err(bad(
                    StatusCode::CONFLICT,
                    "impact_trigger_not_invalid",
                    format!("{subject_ref} is {status}; an impact record follows an invalidation the owner admitted — it does not cause one"),
                ));
            }
            // A revocation is a fact about the FAMILY: its current revision says the right is
            // gone, so every view and recipe bound to ANY revision of it is invalidated. The
            // walk therefore seeds on the family; the record still names the exact revision.
            Ok(Trigger {
                subject_revision_ref: Some(claim.revision_ref.clone()),
                seeds: vec![(
                    family_of(&claim.revision_ref),
                    "learning_source_rights_claim".into(),
                )],
            })
        }
        "route_contract_revoked" => {
            let route = resolve_admitted_model_route_rights_contract(
                &st.data_dir,
                identity,
                Some(owner_ref),
                subject_ref,
            )?;
            let state = route
                .record
                .pointer("/revocation/revocation_state")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if state != "revoked" {
                return Err(bad(
                    StatusCode::CONFLICT,
                    "impact_trigger_not_invalid",
                    format!("{subject_ref} is {state}; an impact record follows an invalidation the owner admitted"),
                ));
            }
            Ok(Trigger {
                subject_revision_ref: Some(route.revision_ref.clone()),
                seeds: vec![(family_of(&route.revision_ref), "model_route_rights".into())],
            })
        }
        "boundary_profile_superseded" => {
            let profile = resolve_admitted_boundary_profile(
                &st.data_dir,
                identity,
                Some(owner_ref),
                subject_ref,
            )?;
            let head = boundary_profile_head_revision_ref(
                &st.data_dir,
                identity,
                &family_of(&profile.revision_ref),
            )?;
            if head.as_deref() == Some(profile.revision_ref.as_str()) {
                return Err(bad(
                    StatusCode::CONFLICT,
                    "impact_trigger_not_invalid",
                    format!("{subject_ref} is the family's current revision; nothing superseded it"),
                ));
            }
            Ok(Trigger {
                subject_revision_ref: Some(profile.revision_ref.clone()),
                seeds: vec![(profile.revision_ref, "learning_boundary_profile".into())],
            })
        }
        "retention_deleted" | "legal_hold_placed" => {
            let Some(disposition) = read_record_dir(&st.data_dir, "retention-dispositions")
                .into_iter()
                .find(|record| text(record, "disposition_id") == subject_ref)
            else {
                return Err(bad(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "impact_trigger_unresolvable",
                    format!("{subject_ref} is not a retention disposition of this deployment"),
                ));
            };
            if text(&disposition, "owner_ref") != owner_ref {
                return Err(bad(
                    StatusCode::FORBIDDEN,
                    "impact_trigger_unresolvable",
                    "the disposition belongs to another owner",
                ));
            }
            let executed = text(&disposition, "state") == "delete_executed";
            let held = disposition
                .pointer("/legal_hold/held")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if (kind == "retention_deleted" && !executed) || (kind == "legal_hold_placed" && !held) {
                return Err(bad(
                    StatusCode::CONFLICT,
                    "impact_trigger_not_invalid",
                    format!("{subject_ref} has not {}; an impact record follows the admitted act", if kind == "retention_deleted" { "executed its deletion" } else { "been placed under a legal hold" }),
                ));
            }
            let subject_kind = disposition
                .pointer("/subject/subject_kind")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let subject = disposition
                .pointer("/subject/subject_ref")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let seed_family = match subject_kind.as_str() {
                "foundry_dataset_snapshot" => "foundry_dataset_snapshot",
                "foundry_checkpoint_artifact" => "foundry_checkpoint",
                _ => "retention_subject",
            };
            Ok(Trigger {
                subject_revision_ref: None,
                seeds: vec![(subject, seed_family.into())],
            })
        }
        "consent_withdrawn" | "eligibility_excluded" | "label_corrected" => Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "impact_trigger_unsupported",
            format!("{kind} has no owner record this basis can resolve a withdrawal from (consent is a rights basis on a claim and a binding on a view, M03/M05.8; eligibility excludes the application's findings, M10.3/R-155; labels are corrected on media episodes, M05.9); record the invalidation the owner DID admit — a revoked claim, route contract, superseded boundary, executed deletion or placed hold"),
        )),
        _ => Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &IMPACT.code("trigger_kind_outside_vocabulary"),
            format!("trigger.kind is one of {}", TRIGGER_KINDS.join(" | ")),
        )),
    }
}

/// The traversal under one identity from one resolved trigger.
fn impact_of(
    st: &DaemonState,
    identity: &RequestIdentity,
    trigger: &Trigger,
) -> Result<ImpactGraph, Reply> {
    let lineage = read_lineage(&st.data_dir, identity)?;
    let mut graph = ImpactGraph::default();
    for (seed, family) in &trigger.seeds {
        if family == "retention_subject" {
            graph.frontier.push(format!("{seed}: a managed backup or environment capture; its dependents are the environment plane's, not learning lineage"));
            continue;
        }
        walk(&mut graph, &lineage, seed, family);
    }
    Ok(graph)
}

// ======================================================================================== fence

/// Every affected entry an admitted impact record holds, ESTATE-WIDE. A quarantine is
/// institutional truth read raw from the substrate, not one principal's view of it.
fn raw_affected(data_dir: &str) -> Result<Vec<(String, Value)>, Reply> {
    let tails = super::substrate_store::list_event_stream_tails(data_dir, IMPACT.owner_namespace)
        .map_err(|error| {
        bad(
            StatusCode::SERVICE_UNAVAILABLE,
            &IMPACT.code("inventory_unavailable"),
            error.to_string(),
        )
    })?;
    let mut out = Vec::new();
    for tail in tails {
        let history = super::substrate_store::read_event_stream_history(
            data_dir,
            IMPACT.owner_namespace,
            &tail,
        )
        .map_err(|error| {
            bad(
                StatusCode::SERVICE_UNAVAILABLE,
                &IMPACT.code("inventory_unavailable"),
                error.to_string(),
            )
        })?;
        let stream = project_stream(&IMPACT, &history).map_err(|reason| {
            bad(
                StatusCode::BAD_GATEWAY,
                &IMPACT.code("projection_failed"),
                reason,
            )
        })?;
        if let Some(entry) = stream.last() {
            let id = text(&entry.record, "learning_impact_record_id");
            for affected in entry
                .record
                .get("affected")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                out.push((id.clone(), affected.clone()));
            }
        }
    }
    Ok(out)
}

/// THE FENCE. Refuse `learning_source_quarantined` when any of `inputs` (a ref, or a family whose
/// revision was affected) carries a quarantining disposition on an admitted impact record.
pub(crate) fn refuse_if_quarantined(data_dir: &str, inputs: &[String]) -> Result<(), Reply> {
    if inputs.is_empty() {
        return Ok(());
    }
    for (record_id, affected) in raw_affected(data_dir)? {
        let disposition = text(&affected, "disposition");
        if !QUARANTINING.contains(&disposition.as_str()) {
            continue;
        }
        let reference = text(&affected, "ref");
        if let Some(hit) = inputs.iter().find(|input| names(input, &reference)) {
            return Err(bad(
                StatusCode::CONFLICT,
                "learning_source_quarantined",
                format!(
                    "{hit} is {disposition} by {record_id} ({}); an input an admitted impact record quarantined feeds nothing further — rebuild or retrain from a clean source under a new decision",
                    text(&affected, "basis")
                ),
            ));
        }
    }
    Ok(())
}

// ================================================================================ unlearning claims

fn validate_unlearning_claim(
    st: &DaemonState,
    identity: &RequestIdentity,
    owner_ref: &str,
    claim: &str,
    evidence: &[String],
    trigger: &Trigger,
    graph: &ImpactGraph,
) -> Result<(), Reply> {
    if !UNLEARNING_CLAIMS.contains(&claim) {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &IMPACT.code("unlearning_claim_outside_vocabulary"),
            format!(
                "unlearning_claim is one of {}",
                UNLEARNING_CLAIMS.join(" | ")
            ),
        ));
    }
    if claim == "none" {
        return Ok(());
    }
    let refuse = |why: String| {
        bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "false_unlearning_claim",
            format!("`{claim}` is not evidenced: {why}; a revocation or impact record does not prove that a trained model has forgotten the source, and IOI claims removal, clean retraining, verified unlearning or deletion only when the corresponding evidence exists"),
        )
    };
    if evidence.is_empty() {
        return Err(refuse("no unlearning_evidence_refs were cited".into()));
    }
    let affected: BTreeSet<String> = graph
        .affected
        .iter()
        .map(|entry| text(entry, "ref"))
        .collect();
    match claim {
        "deletion" => {
            let dispositions = read_record_dir(&st.data_dir, "retention-dispositions");
            for reference in evidence {
                let Some(disposition) = dispositions
                    .iter()
                    .find(|record| text(record, "disposition_id") == *reference)
                else {
                    return Err(refuse(format!(
                        "{reference} is not a retention disposition of this deployment"
                    )));
                };
                if text(disposition, "owner_ref") != owner_ref
                    || text(disposition, "state") != "delete_executed"
                {
                    return Err(refuse(format!(
                        "{reference} has not executed a deletion under this owner"
                    )));
                }
            }
        }
        "clean_retraining" => {
            let lineage = super::foundry_execution_routes::lineage_heads(&st.data_dir, identity)?;
            for reference in evidence {
                let Some(program) = lineage
                    .programs
                    .iter()
                    .find(|program| text(program, "program_id") == *reference)
                else {
                    return Err(refuse(format!(
                        "{reference} is not a Foundry training program this identity can read"
                    )));
                };
                let snapshot = text(program, "dataset_snapshot_ref");
                if affected.contains(&snapshot) || affected.contains(reference) {
                    return Err(refuse(format!("{reference} trained on {snapshot}, which this very invalidation affects — a retraining over the tainted snapshot is not clean")));
                }
            }
        }
        "removal_from_future_datasets" => {
            let lineage = super::foundry_execution_routes::lineage_heads(&st.data_dir, identity)?;
            let subject = trigger.subject_revision_ref.clone().unwrap_or_default();
            for reference in evidence {
                let Some(recipe) = lineage
                    .recipes
                    .iter()
                    .find(|recipe| text(recipe, "recipe_revision_ref") == *reference)
                else {
                    return Err(refuse(format!(
                        "{reference} is not a Foundry recipe revision this identity can read"
                    )));
                };
                if !subject.is_empty()
                    && list(recipe, "learning_source_rights_claim_refs")
                        .iter()
                        .any(|r| names(&family_of(&subject), r))
                {
                    return Err(refuse(format!(
                        "{reference} still binds the revoked claim {} ({subject})",
                        family_of(&subject)
                    )));
                }
                if affected.contains(reference) {
                    return Err(refuse(format!(
                        "{reference} is itself affected by this invalidation"
                    )));
                }
            }
        }
        "verified_unlearning" => {
            for reference in evidence {
                let result = super::evaluation_routes::resolve_result_record(st, identity, reference)
                    .map_err(|_| refuse(format!("{reference} is not an admitted evaluation result; verified unlearning names its own evaluation")))?;
                if text(&result, "verdict") != "pass" {
                    return Err(refuse(format!("{reference} recorded verdict {} — an unlearning evaluation that did not pass verifies nothing", text(&result, "verdict"))));
                }
                let kind = super::evaluation_routes::resolve_evaluator_kind(
                    st,
                    identity,
                    &text(&result, "evaluator_revision_ref"),
                )?;
                if kind != "formal_verifier" && kind != "reproduction_harness" {
                    return Err(refuse(format!("{reference} was judged by a {kind}; verified unlearning is a formal_verifier's or a reproduction_harness's finding, not a score")));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

// ====================================================================================== handlers

#[derive(serde::Deserialize)]
pub(crate) struct ImpactQuery {
    pub(crate) trigger_kind: String,
    pub(crate) subject_ref: String,
    pub(crate) owner_ref: Option<String>,
}

/// GET /v1/hypervisor/learning-lineage/impact?trigger_kind=…&subject_ref=…[&owner_ref=…]
///
/// The walk, served without admission: what an invalidation of `subject_ref` WOULD reach and how
/// each record would be disposed. The trigger is resolved the same way (a subject that is not
/// invalid reads `impact_trigger_not_invalid` here too), so the projection previews a record the
/// daemon would admit rather than a story about one it would not.
pub(crate) async fn handle_lineage_impact(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<ImpactQuery>,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let owner_ref = query.owner_ref.clone().unwrap_or_else(|| {
        identity
            .tenant_refs
            .iter()
            .find(|t| t.starts_with("org://") || t.starts_with("project://"))
            .cloned()
            .unwrap_or_default()
    });
    let trigger = match resolve_trigger(
        &st,
        &identity,
        &owner_ref,
        &query.trigger_kind,
        &query.subject_ref,
    ) {
        Ok(trigger) => trigger,
        Err(response) => return response,
    };
    let graph = match impact_of(&st, &identity, &trigger) {
        Ok(graph) => graph,
        Err(response) => return response,
    };
    let root = match graph.root() {
        Ok(root) => root,
        Err(response) => return response,
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "trigger": { "kind": query.trigger_kind, "subject_ref": query.subject_ref, "subject_revision_ref": trigger.subject_revision_ref },
            "impact_graph_root": root,
            "edges": graph.edges,
            "affected": graph.affected,
            "residual_exposure": graph.residual_exposure,
            "frontier": graph.frontier,
            "note": "a projection over admitted records; it mutates nothing and no verb here retro-edits an admitted revision",
        })),
    )
}

/// POST /v1/hypervisor/learning-impact-records
pub(crate) async fn handle_impact_record_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let family = body_str(&body, "family");
    if !family_token(&family) {
        return bad(
            StatusCode::BAD_REQUEST,
            &IMPACT.code("family_not_canonical"),
            "family is the lineage token this record is admitted under: [a-z0-9][a-z0-9._-]{0,127}",
        );
    }
    let resource = format!("{}{family}", IMPACT.ref_scheme);
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) = reject_authored(&body, &IMPACT, IMPACT_SERVER_RESOLVED) {
        return response;
    }
    if let Err(response) = refuse_unknown_fields(&body, IMPACT_REQUEST_FIELDS) {
        return response;
    }
    let trigger_body = body.get("trigger").cloned().unwrap_or(Value::Null);
    let kind = text(&trigger_body, "kind");
    let subject_ref = text(&trigger_body, "subject_ref");
    let decision_ref = text(&trigger_body, "decision_ref");
    if trigger_body.get("subject_revision_ref").is_some() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &IMPACT.code("caller_authored_evidence_refused"),
            "'trigger.subject_revision_ref' is resolved by the server through the subject's owner; name trigger.subject_ref and let the daemon resolve the revision",
        );
    }
    if !TRIGGER_KINDS.contains(&kind.as_str()) {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &IMPACT.code("trigger_kind_outside_vocabulary"),
            format!("trigger.kind is one of {}", TRIGGER_KINDS.join(" | ")),
        );
    }
    if subject_ref.is_empty() || !decision_ref.starts_with("decision://") {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &IMPACT.code("trigger_required"),
            "trigger names the invalidated subject_ref and the decision:// that invalidated it",
        );
    }
    let audit = body_str(&body, "minimum_audit_commitment_ref");
    if !audit.starts_with("policy://") {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &IMPACT.code("audit_commitment_required"),
            "minimum_audit_commitment_ref names the policy:// under which admission evidence is preserved — deletion removes content, never the evidence that content existed",
        );
    }
    // The trigger must be an invalidation the owner admitted, resolved before any scope is bound
    // so a refused record squats no family name.
    let trigger = match resolve_trigger(
        &st,
        &caller.identity,
        &caller.owner_ref,
        &kind,
        &subject_ref,
    ) {
        Ok(trigger) => trigger,
        Err(response) => return response,
    };
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        IMPACT.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(&IMPACT, &st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    match replay_for_key(
        &IMPACT,
        &st,
        &caller,
        &scope,
        &resource,
        &stream,
        "learning_impact_record",
    ) {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    if !stream.is_empty() {
        return bad(
            StatusCode::CONFLICT,
            &IMPACT.code("already_admitted"),
            "an impact record is admitted once for its token; a later invalidation is a new record over the graph as it then stands",
        );
    }
    let expected_head = match head_assertion(&body, IMPACT.code_prefix) {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, IMPACT.code_prefix) {
        return response;
    }
    let graph = match impact_of(&st, &caller.identity, &trigger) {
        Ok(graph) => graph,
        Err(response) => return response,
    };
    let root = match graph.root() {
        Ok(root) => root,
        Err(response) => return response,
    };
    let claim = {
        let raw = body_str(&body, "unlearning_claim");
        if raw.is_empty() {
            "none".to_string()
        } else {
            raw
        }
    };
    let evidence = list(&body, "unlearning_evidence_refs");
    if let Err(response) = validate_unlearning_claim(
        &st,
        &caller.identity,
        &caller.owner_ref,
        &claim,
        &evidence,
        &trigger,
        &graph,
    ) {
        return response;
    }
    let recorded_at_ms = now_ms();
    let record = json!({
        "schema_version": IMPACT.schema_version,
        "learning_impact_record_id": resource,
        "owner_ref": caller.owner_ref,
        "trigger": {
            "kind": kind,
            "subject_ref": subject_ref,
            "subject_revision_ref": trigger.subject_revision_ref,
            "decision_ref": decision_ref,
        },
        "impact_graph_root": root,
        "affected": graph.affected,
        "residual_exposure": graph.residual_exposure,
        "minimum_audit_commitment_ref": audit,
        "unlearning_claim": claim,
        "unlearning_evidence_refs": strings(&evidence),
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    finish_admission(
        &IMPACT,
        &st,
        &caller,
        &scope,
        &resource,
        "learning_impact_record",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        json!({ "frontier": graph.frontier, "edges": graph.edges.len() }),
    )
}

/// GET /v1/hypervisor/learning-impact-records — the caller's inventory of admitted records.
pub(crate) async fn handle_impact_record_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let refs = match authorized_request_resource_refs(&st.data_dir, &identity, IMPACT.resource_kind)
    {
        Ok(refs) => refs,
        Err(error) => return scope_refusal_reply(error),
    };
    let mut held = Vec::new();
    for resource in refs {
        match authorized_stream(&IMPACT, &st.data_dir, &identity, &resource) {
            Ok(stream) if !stream.is_empty() => held.push(resource),
            Ok(_) => {}
            Err(response) => return response,
        }
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "learning_impact_records": held })),
    )
}

/// GET /v1/hypervisor/learning-impact-records/{family}
pub(crate) async fn handle_impact_record_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
) -> Reply {
    if !family_token(&family) {
        return bad(
            StatusCode::BAD_REQUEST,
            &IMPACT.code("family_not_canonical"),
            "family is the lineage token this record is admitted under",
        );
    }
    let resource = format!("{}{family}", IMPACT.ref_scheme);
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    match authorized_stream(&IMPACT, &st.data_dir, &identity, &resource) {
        Ok(stream) if stream.is_empty() => bad(
            StatusCode::NOT_FOUND,
            &IMPACT.code("absent"),
            "no impact record answers to that token",
        ),
        Ok(stream) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "current": stream.last().map(|entry| entry.record.clone()),
                "admissions": stream.iter().map(|entry| entry.record.clone()).collect::<Vec<_>>(),
                "head": stream.last().map(|entry| entry.head.clone()),
            })),
        ),
        Err(response) => response,
    }
}

// The affected list's shape is what the fence and the walker agree on; keep the map type in scope
// for the projection helpers above.
#[allow(dead_code)]
type AffectedIndex = BTreeMap<String, Value>;
#[allow(dead_code)]
type Scope = RequestResourceScope;
#[allow(dead_code)]
type Admitted = AdmittedRecord;
#[allow(dead_code)]
fn _authorize(data_dir: &str, identity: &RequestIdentity, resource: &str) -> bool {
    authorize_request_resource_scope(data_dir, identity, IMPACT.resource_kind, resource, None)
        .is_ok()
        && !stream_tail(IMPACT.resource_kind, resource).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lineage() -> Lineage {
        let claim = "learning-source-rights://acme.intake";
        let boundary = "learning-boundary://acme.default";
        Lineage {
            views: vec![
                json!({ "revision_ref": "view://acme.v1/revision/1", "source_rights_claim_revision_refs": [format!("{claim}/revision/1")], "route_rights_revision_refs": [], "boundary_profile_revision_ref": format!("{boundary}/revision/1") }),
                json!({ "revision_ref": "view://acme.v2/revision/1", "source_rights_claim_revision_refs": [format!("{claim}/revision/2")], "route_rights_revision_refs": ["route://acme.r/revision/1"], "boundary_profile_revision_ref": format!("{boundary}/revision/2") }),
                json!({ "revision_ref": "view://acme.other/revision/1", "source_rights_claim_revision_refs": ["learning-source-rights://acme.intake-clean/revision/1"], "route_rights_revision_refs": [], "boundary_profile_revision_ref": format!("{boundary}/revision/2") }),
            ],
            data_recipes: vec![
                json!({ "revision_ref": "data-recipe://acme.train/revision/1", "policy_bound_data_view_refs": ["view://acme.v1/revision/1"] }),
            ],
            transformation_runs: vec![
                json!({ "transformation_run_id": "transformation-run://acme/run-1", "data_recipe_revision_ref": "data-recipe://acme.train/revision/1", "policy_bound_data_view_refs": [] }),
            ],
            foundry: super::super::foundry_execution_routes::FoundryLineage {
                recipes: vec![
                    json!({ "recipe_revision_ref": "foundry-recipe://acme/tokens/revision/1", "data_recipe_ref": "data-recipe://acme.train/revision/1", "learning_source_rights_claim_refs": ["learning-source-rights://acme.intake-clean/revision/1"], "institutional_learning_boundary_ref": format!("{boundary}/revision/1") }),
                ],
                snapshots: vec![
                    json!({ "dataset_snapshot_ref": "dataset-snapshot://foundry/aaaa", "recipe_revision_ref": "foundry-recipe://acme/tokens/revision/1" }),
                ],
                programs: vec![
                    json!({ "program_id": "trainpipe://acme/p1", "dataset_snapshot_ref": "dataset-snapshot://foundry/aaaa", "checkpoints": [{ "checkpoint_ref": "checkpoint://foundry/ab/2/cccc", "artifact_hash": "sha256:cccc" }], "qualification_proposal_ref": "foundry-qualification://acme/p1" }),
                ],
                intents: vec![
                    json!({ "intent_ref": "artifact-intent://foundry/1", "artifact_hash": "sha256:cccc", "status": "delivered" }),
                    json!({ "intent_ref": "artifact-intent://foundry/2", "artifact_hash": "sha256:cccc", "status": "declared" }),
                    json!({ "intent_ref": "artifact-intent://foundry/3", "artifact_hash": "sha256:dddd", "status": "delivered" }),
                ],
            },
        }
    }

    fn dispositions(graph: &ImpactGraph) -> BTreeMap<String, (String, String)> {
        graph
            .affected
            .iter()
            .map(|entry| {
                (
                    text(entry, "ref"),
                    (text(entry, "family"), text(entry, "disposition")),
                )
            })
            .collect()
    }

    #[test]
    fn names_matches_a_family_to_its_revisions_and_never_across_families() {
        assert!(names("a://f", "a://f"));
        assert!(names("a://f", "a://f/revision/3"));
        assert!(names("a://f/revision/3", "a://f"));
        assert!(!names("a://f/revision/1", "a://f/revision/2"));
        assert!(!names("a://f", "a://f-clean/revision/1"));
        assert_eq!(family_of("a://f/revision/9"), "a://f");
        assert_eq!(family_of("a://f"), "a://f");
    }

    #[test]
    fn a_revoked_claim_family_reaches_every_bound_revision_and_derives_one_disposition_per_family()
    {
        let mut graph = ImpactGraph::default();
        walk(
            &mut graph,
            &lineage(),
            "learning-source-rights://acme.intake",
            "learning_source_rights_claim",
        );
        let got = dispositions(&graph);
        assert_eq!(
            got["view://acme.v1/revision/1"],
            ("policy_bound_data_view".into(), "fenced".into())
        );
        assert_eq!(
            got["view://acme.v2/revision/1"],
            ("policy_bound_data_view".into(), "fenced".into()),
            "revision 2 of the family is bound too: a revocation is a family fact"
        );
        assert!(
            !got.contains_key("view://acme.other/revision/1"),
            "a different family with a shared prefix is not the revoked one"
        );
        assert_eq!(got["data-recipe://acme.train/revision/1"].1, "quarantined");
        assert_eq!(got["transformation-run://acme/run-1"].1, "quarantined");
        assert_eq!(
            got["foundry-recipe://acme/tokens/revision/1"],
            ("foundry_recipe_run".into(), "quarantined".into())
        );
        assert_eq!(got["dataset-snapshot://foundry/aaaa"].1, "rebuild_required");
        assert_eq!(
            got["trainpipe://acme/p1"],
            ("foundry_program".into(), "retrain_required".into())
        );
        assert_eq!(
            got["checkpoint://foundry/ab/2/cccc"],
            ("foundry_checkpoint".into(), "retrain_required".into())
        );
        assert_eq!(got["foundry-qualification://acme/p1"].1, "retrain_required");
        assert_eq!(got["artifact-intent://foundry/1"].1, "recall_required");
        assert_eq!(got["artifact-intent://foundry/2"].1, "recall_required");
        assert!(
            !got.contains_key("artifact-intent://foundry/3"),
            "an intent over other bytes is not reached"
        );
        assert_eq!(
            graph.residual_exposure.len(),
            1,
            "only the DELIVERED intent is residual exposure"
        );
        assert_eq!(
            text(&graph.residual_exposure[0], "ref"),
            "artifact-intent://foundry/1"
        );
        assert!(graph
            .frontier
            .iter()
            .any(|f| f.contains("models, workers, packages")));
        for edge in &graph.edges {
            assert!(
                got.contains_key(&text(edge, "to")),
                "every edge lands on an affected record"
            );
        }
    }

    #[test]
    fn a_superseded_boundary_is_exact_to_the_revision_and_a_route_seeds_its_family() {
        let mut graph = ImpactGraph::default();
        walk(
            &mut graph,
            &lineage(),
            "learning-boundary://acme.default/revision/1",
            "learning_boundary_profile",
        );
        let got = dispositions(&graph);
        assert!(got.contains_key("view://acme.v1/revision/1"));
        assert!(
            !got.contains_key("view://acme.v2/revision/1"),
            "a view on the CURRENT boundary revision is untouched"
        );
        assert!(
            got.contains_key("foundry-recipe://acme/tokens/revision/1"),
            "the Foundry recipe bound to the superseded revision is quarantined"
        );
        let mut routed = ImpactGraph::default();
        walk(
            &mut routed,
            &lineage(),
            "route://acme.r",
            "model_route_rights",
        );
        assert_eq!(
            dispositions(&routed).keys().next().map(String::as_str),
            Some("view://acme.v2/revision/1")
        );
    }

    #[test]
    fn reach_dedupes_caps_and_the_root_commits_the_edges() {
        let mut graph = ImpactGraph::default();
        assert!(graph.reach("a", "b", "f", "fenced", "x"));
        assert!(
            !graph.reach("c", "b", "f", "fenced", "x"),
            "a record already affected is not reached twice"
        );
        let root_one = graph.root().unwrap();
        let mut same = ImpactGraph::default();
        same.reach("a", "b", "f", "fenced", "x");
        assert_eq!(
            same.root().unwrap(),
            root_one,
            "the root is a function of the edges alone"
        );
        same.reach("b", "c", "g", "quarantined", "y");
        assert_ne!(same.root().unwrap(), root_one);
        let mut capped = ImpactGraph::default();
        for i in 0..MAX_AFFECTED {
            assert!(capped.reach("seed", &format!("r{i}"), "f", "fenced", "x"));
        }
        assert!(!capped.reach("seed", "one-too-many", "f", "fenced", "x"));
        assert_eq!(capped.affected.len(), MAX_AFFECTED);
    }

    #[test]
    fn unknown_and_non_object_bodies_are_refused_by_name() {
        let (status, body) = refuse_unknown_fields(
            &json!({ "owner_ref": "org://l", "fitness": 1, "affected": [] }),
            IMPACT_REQUEST_FIELDS,
        )
        .unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let message = body.0["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert_eq!(
            body.0["error"]["code"],
            "learning_impact_record_request_unknown_field"
        );
        assert!(message.contains("affected") && message.contains("fitness"));
        let (status, body) = refuse_unknown_fields(&json!([1]), IMPACT_REQUEST_FIELDS).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body.0["error"]["code"],
            "learning_impact_record_request_body_not_object"
        );
        assert!(
            refuse_unknown_fields(&json!({ "owner_ref": "org://l" }), IMPACT_REQUEST_FIELDS)
                .is_ok()
        );
    }
}
