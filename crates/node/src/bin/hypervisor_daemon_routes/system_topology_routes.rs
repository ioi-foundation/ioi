//! M2 minimum product-topology state projection: one read-only route
//! reporting the exact topology tuple of the selected single-node profile —
//! observed membership, active writer epoch, route bindings, restore/change-
//! plan state, and cleanup obligations — each column sourced ONLY from its
//! own durable plane records.
//!
//! This is a state-level proof, not a product journey: the route owns no
//! Systems/Operations/Environments/Provenance journey and declares that as an
//! explicit nonclaim. Absence is honest (`honest_empty`), never fabricated;
//! any source record failing its registered contract, any set root that does
//! not recompute, and any wrong-System record in a column's source fails
//! closed instead of projecting (State Invariants 11-12: desired and observed
//! stay separate, and no column claims what its durable evidence does not
//! prove).

use ioi_types::app::hypervisor_environment_lifecycle::{
    environment_plane_root, route_binding_head, route_identity, EnvironmentLifecycleLogHead,
    EnvironmentPlaneState, CHANGE_PLAN_CONTRACT, CLEANUP_OBLIGATION_CONTRACT,
    ROUTE_BINDING_CONTRACT,
};
use ioi_types::app::system_membership_transitions::{
    membership_set_root, MembershipLogHead, NODE_MEMBERSHIP_CONTRACT,
};
use ioi_types::app::system_writer_fence::{
    WriterFenceHead, LOST_SUFFIX_CONTRACT, WRITER_TRANSITION_CONTRACT,
};
use serde_json::{json, Value};
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;

use super::hypervisor_environment_routes::load_environment_lifecycle_source;
use super::system_activation_routes::{
    canonical_system_key, classify, validate_contract, verr, with_source_locks,
};
use super::system_writer_routes::load_writer_source;
use super::DaemonState;

type VErr = (String, String);

/// The one read-only route this module mounts. No governed operation and no
/// wallet scope exist in this module: the projection is a state-level read.
pub(crate) const MINIMUM_TOPOLOGY_ROUTE: &str =
    "/v1/hypervisor/autonomous-systems/:id/topology/minimum";

/// Projection wire version (a projection shape, not a registered contract —
/// the same posture as the sibling membership/environment projections).
pub(crate) const MINIMUM_TOPOLOGY_SCHEMA_VERSION: &str =
    "ioi.hypervisor.autonomous-system-minimum-topology-projection.v1";

fn opt_str<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

fn plan_err(error: String) -> VErr {
    verr("system_topology_source_invalid", error)
}

/// Pure minimum-topology projection over durable plane records only. Every
/// column names its durable source family; sources that are incomplete,
/// invalid, forked, root-divergent, or wrong-System fail closed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_minimum_topology_projection(
    system_id: &str,
    estate_namespace: &str,
    membership_records: &[Value],
    membership_head: &MembershipLogHead,
    fence_head: &WriterFenceHead,
    lost_suffix_revisions: &[Value],
    environment: &EnvironmentPlaneState,
    environment_head: &EnvironmentLifecycleLogHead,
) -> Result<Value, VErr> {
    // Column 1 — observed membership, sourced from the node-membership
    // records alone; the derived set root must recompute.
    let mut members = Vec::new();
    let mut sorted_records: Vec<&Value> = membership_records.iter().collect();
    sorted_records.sort_by_key(|record| {
        record
            .get("node_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    });
    for record in &sorted_records {
        validate_contract(
            NODE_MEMBERSHIP_CONTRACT,
            record,
            "durable membership record",
        )?;
        if opt_str(record, "/system_id") != Some(system_id) {
            return Err(verr(
                "system_topology_wrong_system",
                "a membership record of another System can never enter this projection",
            ));
        }
        members.push(json!({
            "node_id": record["node_id"],
            "status": record["status"],
            "readiness": record["observation"]["readiness"],
            "membership_epoch": record["membership_epoch"],
            "operation_offset": record["synchronization"]["operation_offset"],
        }));
    }
    let recomputed_membership_root =
        membership_set_root(system_id, membership_records).map_err(plan_err)?;
    if recomputed_membership_root != membership_head.membership_root {
        return Err(verr(
            "system_topology_source_invalid",
            "the durable membership set root does not recompute; incomplete membership truth \
             fails closed",
        ));
    }

    // Column 2 — active writer epoch, sourced from the committed writer-epoch
    // transition log alone (already replayed fail-closed into the head).
    let active_writer = match &fence_head.active_transition {
        None => json!({
            "source": "autonomous-system-writer-epoch-transitions",
            "writer_epoch": 0,
            "node_id": Value::Null,
            "writer_epoch_transition_ref": Value::Null,
            "writer_epoch_transition_hash": Value::Null,
        }),
        Some(transition) => {
            validate_contract(
                WRITER_TRANSITION_CONTRACT,
                transition,
                "active writer transition",
            )?;
            if opt_str(transition, "/system_id") != Some(system_id) {
                return Err(verr(
                    "system_topology_wrong_system",
                    "an active writer transition of another System can never enter this \
                     projection",
                ));
            }
            json!({
                "source": "autonomous-system-writer-epoch-transitions",
                "writer_epoch": fence_head.active_epoch,
                "node_id": transition["successor_writer"]["node_id"],
                "writer_epoch_transition_ref": transition["writer_epoch_transition_id"],
                "writer_epoch_transition_hash": transition["writer_epoch_transition_hash"],
            })
        }
    };
    let mut lost_suffixes = Vec::new();
    for record in lost_suffix_revisions {
        validate_contract(LOST_SUFFIX_CONTRACT, record, "durable lost-suffix record")?;
        if opt_str(record, "/system_id") != Some(system_id) {
            return Err(verr(
                "system_topology_wrong_system",
                "a lost-suffix record of another System can never enter this projection",
            ));
        }
        let empty = Vec::new();
        let ambiguous = record
            .pointer("/excluded_suffix/entries")
            .and_then(Value::as_array)
            .unwrap_or(&empty)
            .iter()
            .filter(|entry| {
                entry.get("custody_status").and_then(Value::as_str) == Some("retained_ambiguous")
            })
            .count();
        lost_suffixes.push(json!({
            "lost_suffix_record_id": record["lost_suffix_record_id"],
            "status": record["status"],
            "retained_ambiguous_entries": ambiguous,
        }));
    }

    // Column 3 — route bindings, sourced from the immutable route-binding
    // revisions alone; a forked lineage fails closed inside the head walk.
    let mut identities: Vec<String> = Vec::new();
    for binding in &environment.bindings {
        validate_contract(ROUTE_BINDING_CONTRACT, binding, "durable route binding")?;
        identities.push(route_identity(binding).map_err(plan_err)?);
    }
    identities.sort();
    identities.dedup();
    let mut routes = Vec::new();
    for identity in identities {
        let Some(head) = route_binding_head(&environment.bindings, &identity).map_err(plan_err)?
        else {
            continue;
        };
        routes.push(json!({
            "route_identity": identity,
            "head_revision": head["route_binding_ref"],
            "owner_principal_ref": head["owner_principal_ref"],
            "system_ref": head["system_ref"],
            "activation_generation": head["activation_generation"],
            "active_head": environment
                .active_heads
                .iter()
                .find(|(held, _)| held == &identity)
                .map(|(_, active)| json!(active))
                .unwrap_or(Value::Null),
        }));
    }

    // Column 4 — restore/change-plan state, sourced from the immutable plans
    // and their committed stage advancements alone.
    let mut change_plans = Vec::new();
    for plan in &environment.plans {
        validate_contract(CHANGE_PLAN_CONTRACT, plan, "durable change plan")?;
        let plan_ref = opt_str(plan, "/plan_ref").unwrap_or_default().to_owned();
        change_plans.push(json!({
            "plan_ref": plan_ref,
            "plan_hash": plan["plan_hash"],
            "plan_type": plan["plan_type"],
            "committed_stage_indexes": environment.stages_for(&plan_ref),
            "declared_stage_count": plan
                .get("steps")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0),
            "restore": {
                "source_backup_ref": plan.pointer("/restore/source_backup_ref").cloned().unwrap_or(Value::Null),
                "restore_manifest_root": plan.pointer("/restore/restore_manifest_root").cloned().unwrap_or(Value::Null),
            },
        }));
    }

    // Column 5 — cleanup obligations, sourced from the durable obligation
    // revisions alone.
    let mut obligations = Vec::new();
    for obligation in &environment.obligations {
        validate_contract(
            CLEANUP_OBLIGATION_CONTRACT,
            obligation,
            "durable cleanup obligation",
        )?;
        obligations.push(json!({
            "cleanup_obligation_ref": obligation["cleanup_obligation_ref"],
            "status": obligation["status"],
            "revision": obligation["revision"],
            "escalation": obligation["escalation"],
            "receipt_refs": obligation["receipt_refs"],
        }));
    }

    // The environment plane set root must recompute from exactly the records
    // this projection consumed.
    let recomputed_plane_root = environment_plane_root(
        estate_namespace,
        &environment.bindings,
        &environment.backups,
        &environment.plans,
        &environment.obligations,
    )
    .map_err(plan_err)?;
    if recomputed_plane_root != environment_head.plane_root {
        return Err(verr(
            "system_topology_source_invalid",
            "the durable environment plane root does not recompute; incomplete environment \
             truth fails closed",
        ));
    }

    let empty = membership_records.is_empty()
        && fence_head.active_transition.is_none()
        && lost_suffix_revisions.is_empty()
        && environment.bindings.is_empty()
        && environment.plans.is_empty()
        && environment.obligations.is_empty();
    Ok(json!({
        "schema_version": MINIMUM_TOPOLOGY_SCHEMA_VERSION,
        "system_id": system_id,
        "topology_profile": "single_node_minimum",
        "state": if empty { "honest_empty" } else { "ready" },
        "observed_membership": {
            "source": "autonomous-system-node-memberships",
            "membership_root": membership_head.membership_root,
            "sequence": membership_head.sequence,
            "members": members,
        },
        "active_writer": active_writer,
        "lost_suffix_custody": {
            "source": "autonomous-system-lost-suffix-records",
            "records": lost_suffixes,
        },
        "route_bindings": {
            "source": "hypervisor-environment-route-bindings",
            "routes": routes,
        },
        "restore_state": {
            "source": "hypervisor-change-plans",
            "change_plans": change_plans,
        },
        "cleanup_obligations": {
            "source": "hypervisor-resource-cleanup-obligations",
            "obligations": obligations,
        },
        "environment_plane_head": {
            "sequence": environment_head.sequence,
            "plane_root": environment_head.plane_root,
        },
        "projection_source": "durable_owner_reconstruction",
        "nonclaims": {
            "availability": false,
            "writer_liveness": false,
            "observed_route_truth": false,
            "restore_truth_from_bytes": false,
            "desired_asserts_observed": false,
            "quorum": false,
            "consensus": false,
            "product_journey_ownership": false
        }
    }))
}

/// GET /v1/hypervisor/autonomous-systems/:id/topology/minimum
pub(crate) async fn handle_get_minimum_topology(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_topology_source_key_invalid",
            "id is not canonical",
        ));
    }
    match with_source_locks(|| {
        let writer = load_writer_source(&state.data_dir, &key)?;
        let environment = load_environment_lifecycle_source(&state.data_dir)?;
        build_minimum_topology_projection(
            &writer.binding.system_id,
            &environment.binding.estate_namespace,
            &writer.membership.records,
            &writer.membership.head,
            &writer.fence_head,
            &writer.lost_suffix_revisions,
            &environment.state,
            &environment.head,
        )
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::system_writer_fence::replay_writer_epoch_transitions;

    const SYSTEM: &str = "system://acme/system-alpha";

    fn fixture(path: &str) -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/../../docs/architecture/_meta/schemas/fixtures/{path}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .expect(path),
        )
        .expect(path)
    }

    fn fence_head() -> WriterFenceHead {
        replay_writer_epoch_transitions(
            SYSTEM,
            &[
                fixture("autonomous-system-writer-epoch-transition-v1/positive-genesis.json"),
                fixture("autonomous-system-writer-epoch-transition-v1/positive-promotion.json"),
            ],
        )
        .expect("fence head replays")
    }

    fn membership_records() -> Vec<Value> {
        vec![fixture(
            "autonomous-system-node-membership-v1/positive-active-ready.json",
        )]
    }

    fn membership_head(records: &[Value]) -> MembershipLogHead {
        MembershipLogHead {
            sequence: records.len() as u64,
            membership_root: membership_set_root(SYSTEM, records).expect("set root"),
        }
    }

    fn environment_state() -> EnvironmentPlaneState {
        EnvironmentPlaneState {
            bindings: vec![fixture(
                "hypervisor-environment-route-binding-v1/positive-declared.json",
            )],
            backups: vec![fixture(
                "hypervisor-environment-backup-v1/positive-complete.json",
            )],
            plans: vec![fixture(
                "hypervisor-change-plan-v1/positive-restore-declared.json",
            )],
            committed_stages: vec![(
                "change-plan://local/env-alpha/restore/0001".to_owned(),
                vec![1, 2],
            )],
            obligations: vec![fixture(
                "hypervisor-resource-cleanup-obligation-v1/positive-open.json",
            )],
            active_heads: vec![],
        }
    }

    fn environment_head(state: &EnvironmentPlaneState) -> EnvironmentLifecycleLogHead {
        EnvironmentLifecycleLogHead {
            sequence: 5,
            plane_root: environment_plane_root(
                "local",
                &state.bindings,
                &state.backups,
                &state.plans,
                &state.obligations,
            )
            .expect("plane root"),
        }
    }

    fn build() -> Value {
        let records = membership_records();
        let head = membership_head(&records);
        let environment = environment_state();
        let env_head = environment_head(&environment);
        build_minimum_topology_projection(
            SYSTEM,
            "local",
            &records,
            &head,
            &fence_head(),
            &[fixture("lost-suffix-record-v1/positive-open-retained.json")],
            &environment,
            &env_head,
        )
        .expect("projection builds")
    }

    // The exact minimum tuple, every column sourced from its durable plane.
    #[test]
    fn minimum_topology_reports_the_exact_tuple_from_durable_records_only() {
        let projection = build();
        assert_eq!(
            projection["schema_version"],
            MINIMUM_TOPOLOGY_SCHEMA_VERSION
        );
        assert_eq!(projection["topology_profile"], "single_node_minimum");
        assert_eq!(projection["state"], "ready");

        assert_eq!(
            projection["observed_membership"]["source"],
            "autonomous-system-node-memberships"
        );
        assert_eq!(
            projection["observed_membership"]["members"][0]["node_id"],
            "node://acme/system-alpha/alpha-node-1"
        );
        assert_eq!(
            projection["observed_membership"]["members"][0]["readiness"],
            "ready"
        );

        assert_eq!(projection["active_writer"]["writer_epoch"], 2);
        assert_eq!(
            projection["active_writer"]["node_id"],
            "node://acme/system-alpha/beta-node-2"
        );
        assert_eq!(
            projection["lost_suffix_custody"]["records"][0]["retained_ambiguous_entries"],
            2
        );

        assert_eq!(
            projection["route_bindings"]["routes"][0]["route_identity"],
            "https://api.acme.example/v1"
        );
        assert_eq!(
            projection["route_bindings"]["routes"][0]["activation_generation"],
            1
        );

        assert_eq!(
            projection["restore_state"]["change_plans"][0]["committed_stage_indexes"],
            serde_json::json!([1, 2])
        );
        assert_eq!(
            projection["restore_state"]["change_plans"][0]["declared_stage_count"],
            5
        );

        assert_eq!(
            projection["cleanup_obligations"]["obligations"][0]["status"],
            "pending"
        );

        // The state-level nonclaims include the journey non-ownership clause.
        assert_eq!(projection["nonclaims"]["product_journey_ownership"], false);
        assert_eq!(projection["nonclaims"]["availability"], false);
        assert_eq!(projection["nonclaims"]["desired_asserts_observed"], false);
    }

    // Restart proof: rebuilding from re-parsed durable records is byte-exact.
    #[test]
    fn restart_rebuilds_the_minimum_topology_projection_byte_exactly() {
        let before = serde_json::to_string(&build()).expect("serializes");
        // Simulate a restart: every input is re-read from its durable bytes.
        let after = serde_json::to_string(&build()).expect("serializes");
        assert_eq!(before, after);
    }

    // Honest absence: no durable truth projects an honest_empty tuple, never
    // a fabricated one.
    #[test]
    fn projection_without_durable_truth_is_honest_empty() {
        let head = MembershipLogHead {
            sequence: 0,
            membership_root: membership_set_root(SYSTEM, &[]).expect("empty root"),
        };
        let environment = EnvironmentPlaneState::default();
        let env_head = EnvironmentLifecycleLogHead {
            sequence: 0,
            plane_root: environment_plane_root("local", &[], &[], &[], &[]).expect("empty root"),
        };
        let projection = build_minimum_topology_projection(
            SYSTEM,
            "local",
            &[],
            &head,
            &WriterFenceHead {
                active_epoch: 0,
                active_transition: None,
            },
            &[],
            &environment,
            &env_head,
        )
        .expect("empty projection");
        assert_eq!(projection["state"], "honest_empty");
        assert_eq!(projection["active_writer"]["writer_epoch"], 0);
        assert_eq!(projection["active_writer"]["node_id"], Value::Null);
        assert_eq!(projection["observed_membership"]["members"], json!([]));
        assert_eq!(projection["route_bindings"]["routes"], json!([]));
    }

    // Wrong-System sources fail closed instead of projecting.
    #[test]
    fn wrong_system_sources_fail_closed() {
        let records = membership_records();
        let head = membership_head(&records);
        let environment = environment_state();
        let env_head = environment_head(&environment);
        let error = build_minimum_topology_projection(
            "system://acme/system-beta",
            "local",
            &records,
            &head,
            &fence_head(),
            &[],
            &environment,
            &env_head,
        )
        .expect_err("a wrong-System membership source refuses");
        assert_eq!(error.0, "system_topology_wrong_system");
    }

    // A membership set root that does not recompute fails closed.
    #[test]
    fn divergent_membership_root_fails_closed() {
        let records = membership_records();
        let head = MembershipLogHead {
            sequence: 1,
            membership_root:
                "sha256:9999999999999999999999999999999999999999999999999999999999999999".to_owned(),
        };
        let environment = environment_state();
        let env_head = environment_head(&environment);
        let error = build_minimum_topology_projection(
            SYSTEM,
            "local",
            &records,
            &head,
            &fence_head(),
            &[],
            &environment,
            &env_head,
        )
        .expect_err("a divergent set root refuses");
        assert_eq!(error.0, "system_topology_source_invalid");
    }

    // The new read route is disjoint from every sibling plane route and this
    // module declares no governed operation and no wallet scope.
    #[test]
    fn topology_route_is_disjoint_and_scopeless() {
        let siblings = [
            "/v1/hypervisor/autonomous-systems/:id/membership/projection",
            "/v1/hypervisor/autonomous-systems/:id/membership/desired-topology",
            "/v1/hypervisor/autonomous-systems/:id/membership/:op",
            "/v1/hypervisor/autonomous-systems/:id/writer/epoch",
            "/v1/hypervisor/autonomous-systems/:id/writer/failover-profile",
            "/v1/hypervisor/autonomous-systems/:id/writer/lost-suffixes",
            "/v1/hypervisor/autonomous-systems/:id/writer/lost-suffixes/resolution",
            "/v1/hypervisor/autonomous-systems/:id/writer/transitions/:kind",
            "/v1/hypervisor/environments/lifecycle/projection",
            "/v1/hypervisor/environments/lifecycle/:op",
            "/v1/hypervisor/hypervisoros/nodes/projection",
        ];
        assert!(MINIMUM_TOPOLOGY_ROUTE.starts_with("/v1/hypervisor/autonomous-systems/:id/"));
        for sibling in siblings {
            assert_ne!(MINIMUM_TOPOLOGY_ROUTE, sibling);
        }
        // Scopelessness: the module exposes exactly one GET projection and
        // never a governed operation; the scope namespace stays untouched.
        assert!(!MINIMUM_TOPOLOGY_ROUTE.contains("scope:"));
    }
}
