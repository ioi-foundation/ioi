//! Honest compact and advanced M1 System read projections.
//!
//! Both views are rebuilt from the same verified admission and live-chain
//! owners. No projection record is persisted and presentation grants no
//! authority.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::system_activation_routes::{classify, required_string, verr, with_source_locks};
use super::DaemonState;

type VErr = (String, String);

// M08.9 — the compact row is canon's `HypervisorSystemsProjection`, registered and validated
// before it is served: the verified admission and live chain as before, the membership plane's
// projection (desired topology) and the writer plane's projection (observed) composed in as
// typed presence or typed absence, the seven contextual modes as routes, and the policy basis
// that admitted the row for THIS caller. Nothing here is persisted and nothing grants authority.
const SYSTEMS_PROJECTION_SCHEMA: &str = "ioi.hypervisor.systems-projection.v1";
const SYSTEMS_PROJECTION_CONTRACT_ID: &str =
    "schema://ioi/components/hypervisor/systems-projection/v1";
const SYSTEM_MODES: &[(&str, &str)] = &[
    ("overview", ""),
    ("design", "/design"),
    ("operate", "/operate"),
    ("govern", "/govern"),
    ("evidence", "/evidence"),
    ("improve", "/improve"),
    ("interfaces", "/interfaces"),
];

fn required(value: &Value, pointer: &str) -> Result<String, VErr> {
    required_string(value, pointer).map(str::to_owned)
}

/// A plane's projection as typed presence or typed absence — the refusal CODE a plane answers
/// with is the reason, never an invented topology and never a silent null.
fn plane_presence(result: Result<Value, VErr>) -> Value {
    match result {
        Ok(projection) => {
            json!({ "state": "present", "projection": projection, "reason": Value::Null })
        }
        Err((code, _)) => json!({ "state": "absent", "projection": Value::Null, "reason": code }),
    }
}

/// The seven contextual modes canon names, as routes under the System's canonical route. The
/// `serving` lane is null until the App binds a renderer to the mode — said, not assumed.
fn system_modes(system_id: &str) -> Vec<Value> {
    let tail = system_id.strip_prefix("system://").unwrap_or(system_id);
    SYSTEM_MODES
        .iter()
        .map(|(mode, segment)| {
            json!({ "mode": mode, "route": format!("/systems/{tail}{segment}"), "serving": Value::Null })
        })
        .collect()
}

/// Policy is decided per row from the request identity, three ways. A System is visible to the
/// principal that proposed its genesis, or to a caller holding the tenant its genesis names as
/// owner — both read the genesis record. The third reads the seam's own scope discipline: a
/// principal that holds records under a System through the System-record seam (its
/// request-resource scopes name `<system_id>/…`) sees that System — the composition it admitted
/// lives there, and hiding the System would hide its own records (register R-185, slice S4c-1).
/// Anything else is not in this caller's inventory — not hidden, not present — and a principal
/// with no scope under any System still gets `honest_empty`, never a fabricated row.
fn row_visible_to(
    record: &Value,
    identity: &super::substrate_store::RequestIdentity,
    hosted_record_refs: &std::collections::BTreeSet<String>,
) -> Option<&'static str> {
    if record.get("proposed_by_ref").and_then(Value::as_str)
        == Some(identity.principal_ref.as_str())
    {
        return Some("proposed_by_ref == principal_ref");
    }
    if record
        .get("owner_ref")
        .and_then(Value::as_str)
        .is_some_and(|owner| identity.authorizes_tenant(owner))
    {
        return Some("owner_ref in tenant_refs");
    }
    if record
        .get("system_id")
        .and_then(Value::as_str)
        .is_some_and(|system_id| hosts_records_under(hosted_record_refs, system_id))
    {
        return Some("principal holds System-record seam scopes under system_id");
    }
    None
}

/// A seam resource ref is `<system_id>/<contract slug>/<object slug>`; a System id itself
/// contains `/`, so the match is on the exact `<system_id>/` prefix, never on a split.
fn hosts_records_under(
    hosted_record_refs: &std::collections::BTreeSet<String>,
    system_id: &str,
) -> bool {
    let prefix = format!("{system_id}/");
    hosted_record_refs
        .iter()
        .any(|resource| resource.starts_with(&prefix))
}

fn project_one(data_dir: &str, record: &Value, view: &str, policy: &Value) -> Result<Value, VErr> {
    let system_id = required(record, "/system_id")?;
    let key = super::system_genesis_routes::record_tail(&system_id);
    let admission = super::system_genesis_routes::load_verified_admission_by_key(data_dir, &key)?
        .ok_or_else(|| {
        verr(
            "system_projection_source_missing",
            "verified admission vanished",
        )
    })?;
    let (_, live) = super::system_amendment_routes::load_amendment_source(data_dir, &key)?;
    let canonical_roots = json!({
        "proposal_root":admission.record["proposal_root"],
        "admitted_manifest_root":admission.record["admitted_manifest_root"],
        "initial_profile_bundle_root":admission.record["initial_profile_bundle_root"],
        "active_profile_set_root":live.chain_head["active_profile_set_root"],
        "latest_state_root":live.chain_head["latest_state_root"],
        "operation_log_root":live.chain_head["operation_log_root"],
        "chain_root":live.chain_head["chain_root"],
    });
    let compact = json!({
        "system_id":system_id,
        "source_record_tail":key,
        "package_id":admission.record["package_id"],
        "manifest_ref":admission.record["manifest_ref"],
        "genesis_ref":admission.record["genesis_ref"],
        "constitution_ref":live.chain_head["constitution_ref"],
        "status":live.chain_head["status"],
        "latest_sequence":live.chain_head["latest_sequence"],
        "network_enrollment_ref":live.chain_head["network_enrollment_ref"],
        "canonical_roots":canonical_roots,
        "evidence_refs":{
            "genesis_admission_receipt_ref":admission.record["admission_receipt_ref"],
            "latest_receipt_ref":live.chain_head["latest_receipt_ref"],
            "operation_log_ref":live.chain_head["operation_log_ref"],
            "chain_ref":live.chain_head["chain_ref"]
        }
    });
    // THE ROW IS CANON'S SHAPE, VALIDATED BEFORE IT IS SERVED. The two plane projections are read
    // through their owners' own loaders and builders — never by this module opening their records —
    // and a plane that has nothing admitted for this System is a typed absence carrying that
    // plane's own refusal code, never a topology this module made up.
    let mut row = compact;
    row["schema_version"] = json!(SYSTEMS_PROJECTION_SCHEMA);
    row["projection_row_id"] = json!(format!("hypervisor_systems_projection:{system_id}"));
    row["topology"] = json!({
        "desired": plane_presence(
            super::system_membership_routes::load_membership_source(data_dir, &key).and_then(|source| {
                super::system_membership_routes::build_membership_projection(
                    &source.binding.system_id,
                    source.desired_topology.as_ref().zip(source.desired_topology_root.as_deref()),
                    &source.records,
                    &source.head,
                )
            }),
        ),
        "observed": plane_presence(
            super::system_writer_routes::load_writer_source(data_dir, &key).and_then(|source| {
                super::system_writer_routes::build_writer_projection(
                    &system_id,
                    &source.fence_head,
                    &source.lost_suffix_revisions,
                )
            }),
        ),
    });
    row["modes"] = Value::Array(system_modes(&system_id));
    row["policy_basis"] = policy.clone();
    row["source_projection_refs"] = json!([
        "verified_owner_reconstruction",
        "system_membership_projection",
        "system_writer_projection"
    ]);
    row["read_model_only"] = json!(true);
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        SYSTEMS_PROJECTION_CONTRACT_ID,
        &row,
    )
    .map_err(|error| {
        verr(
            "system_projection_row_contract_invalid",
            format!(
                "the assembled row violates its registered contract and is NOT served: {error}"
            ),
        )
    })?;
    if view == "compact" {
        return Ok(row);
    }
    Ok(json!({
        "compact":row,
        "genesis_admission":admission.record,
        "genesis_admission_receipt":admission.receipt,
        "activation_effect":live.activation_effect,
        "latest_step":live.previous_step,
        "active_profile_set":live.predecessor_profile_set,
        "operation_log":live.operation_log,
        "chain_head":live.chain_head
    }))
}

/// GET /v1/hypervisor/autonomous-systems/projection?view=compact|advanced
pub(crate) async fn handle_get(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let view = query.get("view").map(String::as_str).unwrap_or("compact");
    if !matches!(view, "compact" | "advanced") {
        return classify(verr(
            "system_projection_view_invalid",
            "view must be exactly 'compact' or 'advanced'",
        ));
    }
    // POLICY BEFORE ROWS. The inventory is filtered by the request identity before any row is
    // built, counted or reported as `honest_empty`; an unresolvable caller is a typed refusal.
    let identity = match super::substrate_store::resolve_request_identity(&state.data_dir, &headers)
    {
        Ok(identity) => identity,
        Err(error) => return super::mutation_event_foundation::scope_refusal_reply(error),
    };
    // The seam's own scope discipline, read once before any row: the System-record resources this
    // identity holds, so a System that hosts the caller's records is visible to the caller.
    let hosted_record_refs = match super::substrate_store::authorized_request_resource_refs(
        &state.data_dir,
        &identity,
        super::system_record_routes::RESOURCE_KIND,
    ) {
        Ok(refs) => refs,
        Err(error) => return super::mutation_event_foundation::scope_refusal_reply(error),
    };
    match with_source_locks(|| {
        let mut records = super::system_genesis_routes::scan_records(&state.data_dir)
            .map_err(|message| verr("system_projection_source_unreadable", message))?;
        let mut substrate_records = super::substrate_store::read_required_all(
            &state.data_dir,
            super::system_genesis_routes::RECORD_DIR,
        )
        .map_err(|error| {
            verr(
                "system_projection_source_unreadable",
                format!("Agentgres admission census failed ({error})"),
            )
        })?;
        records.sort_by_key(|record| {
            record
                .get("system_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        });
        substrate_records.sort_by_key(|record| {
            record
                .get("system_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        });
        if substrate_records != records {
            return Err(verr(
                "system_projection_source_incomplete",
                "local and Agentgres genesis admission censuses differ",
            ));
        }
        if let Some(filter) = query.get("system_id") {
            records.retain(|record| {
                record.get("system_id").and_then(Value::as_str) == Some(filter.as_str())
            });
        }
        let visible: Vec<(&Value, &'static str)> = records
            .iter()
            .filter_map(|record| {
                row_visible_to(record, &identity, &hosted_record_refs)
                    .map(|filter| (record, filter))
            })
            .collect();
        let systems = visible
            .iter()
            .map(|(record, filter)| {
                let policy = json!({ "principal_ref": identity.principal_ref, "filter": filter });
                project_one(&state.data_dir, record, view, &policy)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok::<_, VErr>(json!({
            "schema_version":"ioi.hypervisor.autonomous-system-read-projection.v1",
            "row_schema_version": SYSTEMS_PROJECTION_SCHEMA,
            "row_contract_id": SYSTEMS_PROJECTION_CONTRACT_ID,
            "view":view,
            "state":if systems.is_empty(){"honest_empty"}else{"ready"},
            "systems":systems,
            "policy":{"principal_ref": identity.principal_ref, "applied_before": ["rows", "state"], "admitted_rows": systems.len(), "inventory_rows": records.len()},
            "projection_source":"verified_owner_reconstruction",
            "nonclaims":{"authority":false,"mutation":false,"membership":false,"writer":false,"network_assurance":false,"runtime_effect":false,"persistence":false}
        }))
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::super::substrate_store::RequestIdentity;
    use super::{hosts_records_under, row_visible_to};

    fn refs(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|item| (*item).to_string()).collect()
    }

    #[test]
    fn a_system_is_visible_to_the_principal_that_holds_seam_records_under_it_and_to_nobody_else() {
        let identity = RequestIdentity::local_development_operator("user://alice");
        let system = json!({ "system_id": "system://ioi/orchestration/demo", "proposed_by_ref": "project://ioi/orchestration" });
        let hosted = refs(&["system://ioi/orchestration/demo/orchestration-v1/orc-one"]);
        assert_eq!(
            row_visible_to(&system, &identity, &hosted),
            Some("principal holds System-record seam scopes under system_id")
        );
        assert_eq!(row_visible_to(&system, &identity, &BTreeSet::new()), None);
        let other = json!({ "system_id": "system://ioi/orchestration/demo-two", "proposed_by_ref": "project://ioi/orchestration" });
        assert_eq!(row_visible_to(&other, &identity, &hosted), None);
    }

    #[test]
    fn the_prefix_match_is_exact_so_a_system_whose_id_extends_another_is_not_confused_with_it() {
        let hosted = refs(&["system://ioi/orchestration/demo-two/orchestration-v1/orc-one"]);
        assert!(hosts_records_under(
            &hosted,
            "system://ioi/orchestration/demo-two"
        ));
        assert!(!hosts_records_under(
            &hosted,
            "system://ioi/orchestration/demo"
        ));
        assert!(!hosts_records_under(
            &hosted,
            "system://ioi/orchestration/demo-tw"
        ));
    }

    #[test]
    fn the_genesis_clauses_still_decide_first() {
        let identity = RequestIdentity::local_development_operator("user://alice");
        let proposed = json!({ "system_id": "system://x", "proposed_by_ref": "user://alice" });
        assert_eq!(
            row_visible_to(&proposed, &identity, &BTreeSet::new()),
            Some("proposed_by_ref == principal_ref")
        );
    }
}
