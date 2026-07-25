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

fn required(value: &Value, pointer: &str) -> Result<String, VErr> {
    required_string(value, pointer).map(str::to_owned)
}

fn project_one(data_dir: &str, record: &Value, view: &str) -> Result<Value, VErr> {
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
    if view == "compact" {
        return Ok(compact);
    }
    Ok(json!({
        "compact":compact,
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
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let view = query.get("view").map(String::as_str).unwrap_or("compact");
    if !matches!(view, "compact" | "advanced") {
        return classify(verr(
            "system_projection_view_invalid",
            "view must be exactly 'compact' or 'advanced'",
        ));
    }
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
        let systems = records
            .iter()
            .map(|record| project_one(&state.data_dir, record, view))
            .collect::<Result<Vec<_>, _>>()?;
        Ok::<_, VErr>(json!({
            "schema_version":"ioi.hypervisor.autonomous-system-read-projection.v1",
            "view":view,
            "state":if systems.is_empty(){"honest_empty"}else{"ready"},
            "systems":systems,
            "projection_source":"verified_owner_reconstruction",
            "nonclaims":{"authority":false,"mutation":false,"membership":false,"writer":false,"network_assurance":false,"runtime_effect":false}
        }))
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}
