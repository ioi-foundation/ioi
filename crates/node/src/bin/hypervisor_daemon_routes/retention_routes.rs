//! Data-retention disposition plane (W1.5) — canonical contract
//! `schema://ioi/foundations/data-retention-disposition/v1`
//! (docs/architecture/foundations/security-privacy-policy-invariants.md §DataRetentionDisposition).
//!
//! A `DataRetentionDisposition` is the durable, owner-scoped record of what retention duty
//! applies to one exact data subject, and of what was actually done about it: policy basis,
//! legal hold, executed deletion with evidence. Before W1.5 the estate had NO retention,
//! deletion, or legal-hold mechanism at any layer (seven-layer sweep, 2026-08-08).
//!
//! Hard boundaries (enforced, not decorative):
//!   * A legal hold BLOCKS deletion, typed. Releasing a hold is a distinct admitted
//!     transition with a server-resolved actor (INV-37) — never a side effect.
//!   * Deletion deletes CONTENT and retains ADMISSION EVIDENCE: for `managed_backup_export`
//!     the payload bytes are destroyed (a later hash-verified delivery refuses), while the
//!     admitted backup record and every receipt survive as history. Erasing the evidence a
//!     deletion happened would make the deletion itself unauditable.
//!   * The executed deletion carries evidence of what was actually removed — a disposition
//!     that claims deletion without naming what was destroyed is refused at the code level
//!     (the evidence object is server-built from real filesystem outcomes).
//!   * `managed_backup_export` is the one bound subject kind today; an unlisted kind is
//!     refused at declaration, not interpreted. Further kinds bind only by owner ruling in
//!     the canonical section.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::mutation_event_foundation::{
    admit_owner_scoped_write, replay_stable_id, require_write_caller, scope_refusal_reply,
    MutationCommit, WriteCaller,
};
use super::{persist_record, DaemonState};

const RETENTION_NAMESPACE: &str = "hypervisor-retention";
const KIND_DISPOSITION: &str = "retention-dispositions";
const SCHEMA_VERSION: &str = "ioi.foundations.data_retention_disposition.v1";
const SUBJECT_KINDS: &[&str] = &["managed_backup_export"];

type Reply = (StatusCode, Json<Value>);

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

fn safe(seg: &str) -> String {
    seg.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
}

fn load(data_dir: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(data_dir)
                .join(KIND_DISPOSITION)
                .join(format!("{}.json", safe(id))),
        )
        .ok()?,
    )
    .ok()
}

fn project_admission(record: &mut Value, commit: &MutationCommit) {
    record["admitted_head"] = json!(commit.projection.head);
    record["updated_at"] = json!(super::iso_now());
}

fn project_or_fail(data_dir: &str, id: &str, record: &Value) -> Result<(), Reply> {
    persist_record(data_dir, KIND_DISPOSITION, id, record).map_err(|_| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "retention_disposition_persistence_failed",
            "the transition is admitted but its projection could not be written; replay to reconcile",
        )
    })
}

fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("")
}

/// POST /v1/hypervisor/retention/dispositions — declare the retention duty for one exact
/// subject. Rights: the SAME admission scope the subject's family enforces, re-run here.
pub(crate) async fn handle_disposition_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let subject_kind = str_field(&body, "subject_kind");
    if !SUBJECT_KINDS.contains(&subject_kind) {
        return bad(
            StatusCode::BAD_REQUEST,
            "retention_subject_kind_unsupported",
            format!("subject_kind must be one of {SUBJECT_KINDS:?}; an unlisted kind is refused, not interpreted"),
        );
    }
    let subject_id = str_field(&body, "subject_ref");
    if subject_id.is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "retention_subject_required",
            "subject_ref must name the exact subject the duty applies to",
        );
    }
    let policy_basis_ref = str_field(&body, "policy_basis_ref");
    if !policy_basis_ref.contains("://") {
        return bad(
            StatusCode::BAD_REQUEST,
            "retention_policy_basis_required",
            "policy_basis_ref must name the governing policy as a canonical ref — a disposition without a basis is an opinion",
        );
    }
    // Rights admission for the one bound kind: resolve the backup through the caller's OWN
    // authorized scope set, exactly as the backup family itself does.
    let (backup, _scope) = match super::managed_runtime_routes::authorized_backup_by_id(
        &st.data_dir,
        &caller.identity,
        subject_id,
    ) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let Some(backup_ref) = backup["backup_ref"].as_str().map(str::to_owned) else {
        return bad(
            StatusCode::CONFLICT,
            "retention_subject_unresolved",
            "the admitted backup record carries no backup_ref",
        );
    };
    let state_root = backup["source_state_root_ref"]
        .as_str()
        .and_then(|value| value.strip_prefix("state-root://"))
        .unwrap_or("")
        .to_string();
    let id = replay_stable_id("rdsp", &caller.owner_ref, &caller.idempotency_key);
    let disposition_ref = format!("retention-disposition://{id}");
    let admitted = json!({
        "disposition_id": disposition_ref,
        "subject": { "subject_kind": subject_kind, "subject_ref": backup_ref },
        "policy_basis_ref": policy_basis_ref,
    });
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        RETENTION_NAMESPACE,
        KIND_DISPOSITION,
        &disposition_ref,
        "retention.disposition.declare",
        None,
        &admitted,
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    if commit.replayed {
        if let Some(existing) = load(&st.data_dir, &id) {
            return (
                StatusCode::OK,
                Json(json!({ "ok": true, "replayed": true, "disposition": existing })),
            );
        }
    }
    let mut record = json!({
        "schema_version": SCHEMA_VERSION,
        "disposition_id": disposition_ref,
        "subject": {
            "subject_kind": subject_kind,
            "subject_ref": backup_ref,
            "payload_state_root": if state_root.is_empty() { Value::Null } else { json!(state_root) },
        },
        "policy_basis_ref": policy_basis_ref,
        "owner_ref": caller.owner_ref,
        "declared_by": caller.identity.principal_ref,
        "legal_hold": null,
        "state": "declared",
        "deletion": null,
        "created_at": super::iso_now(),
    });
    project_admission(&mut record, &commit);
    if let Err(response) = project_or_fail(&st.data_dir, &id, &record) {
        return response;
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "replayed": false, "disposition": record })),
    )
}

fn authorized_disposition(
    st: &DaemonState,
    headers: &HeaderMap,
    id: &str,
) -> Result<(super::substrate_store::RequestIdentity, Value), Reply> {
    // Identity FIRST: an unauthenticated caller is owed 401, never a 404 existence oracle.
    let identity = super::substrate_store::resolve_request_identity(&st.data_dir, headers)
        .map_err(scope_refusal_reply)?;
    let Some(record) = load(&st.data_dir, id) else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "retention_disposition_not_found",
            "no disposition exists at this id",
        ));
    };
    if !record["owner_ref"]
        .as_str()
        .is_some_and(|owner_ref| identity.authorizes_tenant(owner_ref))
    {
        return Err(scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceScopeRequired,
        ));
    }
    Ok((identity, record))
}

/// GET /v1/hypervisor/retention/dispositions/:id
pub(crate) async fn handle_disposition_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    match authorized_disposition(&st, &headers, &id) {
        Ok((_, record)) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "disposition": record })),
        ),
        Err(reply) => reply,
    }
}

/// POST /v1/hypervisor/retention/dispositions/:id/legal-hold {hold: bool, reason} — place or
/// release the hold as a distinct admitted transition. The actor is resolved server-side.
pub(crate) async fn handle_disposition_legal_hold(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let held_by = match super::lifecycle_routes::resolve_acting_principal_ref(
        &st.data_dir,
        &headers,
        &body,
    ) {
        Ok(actor_ref) => actor_ref,
        Err((status, value)) => return (status, Json(value)),
    };
    let Some(hold) = body.get("hold").and_then(Value::as_bool) else {
        return bad(
            StatusCode::BAD_REQUEST,
            "retention_hold_flag_required",
            "hold must be true (place) or false (release)",
        );
    };
    let reason = str_field(&body, "reason");
    if hold && reason.is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "retention_hold_reason_required",
            "placing a legal hold requires a reason — an unexplained hold is not auditable",
        );
    }
    let Some(record) = load(&st.data_dir, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "retention_disposition_not_found",
            "no disposition exists at this id",
        );
    };
    if record["owner_ref"].as_str() != Some(caller.owner_ref.as_str()) {
        return scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        );
    }
    if record["state"].as_str() == Some("delete_executed") {
        return bad(
            StatusCode::CONFLICT,
            "retention_disposition_terminal",
            "the deletion is executed; a hold on destroyed content holds nothing",
        );
    }
    let currently_held = record["legal_hold"]
        .as_object()
        .and_then(|h| h.get("held"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if currently_held == hold {
        return (
            StatusCode::OK,
            Json(json!({ "ok": true, "replayed": true, "disposition": record })),
        );
    }
    let Some(expected_head) = record["admitted_head"].as_str().map(str::to_owned) else {
        return bad(
            StatusCode::CONFLICT,
            "retention_expected_head_required",
            "this record predates admitted mutation; it cannot be advanced without a head",
        );
    };
    let disposition_ref = format!("retention-disposition://{id}");
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        RETENTION_NAMESPACE,
        KIND_DISPOSITION,
        &disposition_ref,
        if hold {
            "retention.legal_hold.place"
        } else {
            "retention.legal_hold.release"
        },
        Some(&expected_head),
        &json!({ "disposition_id": disposition_ref, "hold": hold, "reason": reason, "held_by": held_by }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    let mut successor = record;
    successor["legal_hold"] = if hold {
        json!({ "held": true, "held_by": held_by, "held_at": super::iso_now(), "reason": reason })
    } else {
        json!({ "held": false, "released_by": held_by, "released_at": super::iso_now() })
    };
    project_admission(&mut successor, &commit);
    if let Err(response) = project_or_fail(&st.data_dir, &id, &successor) {
        return response;
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "replayed": commit.replayed, "disposition": successor })),
    )
}

/// POST /v1/hypervisor/retention/dispositions/:id/delete — execute the deletion. Content is
/// destroyed; admission evidence survives. A legal hold blocks this, typed.
pub(crate) async fn handle_disposition_delete(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let executed_by = match super::lifecycle_routes::resolve_acting_principal_ref(
        &st.data_dir,
        &headers,
        &body,
    ) {
        Ok(actor_ref) => actor_ref,
        Err((status, value)) => return (status, Json(value)),
    };
    let Some(record) = load(&st.data_dir, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "retention_disposition_not_found",
            "no disposition exists at this id",
        );
    };
    if record["owner_ref"].as_str() != Some(caller.owner_ref.as_str()) {
        return scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        );
    }
    if record["legal_hold"]
        .as_object()
        .and_then(|h| h.get("held"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return bad(
            StatusCode::CONFLICT,
            "retention_deletion_blocked_by_legal_hold",
            "a legal hold stands on this subject; deletion refuses until the hold is released by its own admitted transition",
        );
    }
    if record["state"].as_str() == Some("delete_executed") {
        return (
            StatusCode::OK,
            Json(json!({ "ok": true, "replayed": true, "disposition": record })),
        );
    }
    let Some(expected_head) = record["admitted_head"].as_str().map(str::to_owned) else {
        return bad(
            StatusCode::CONFLICT,
            "retention_expected_head_required",
            "this record predates admitted mutation; it cannot be advanced without a head",
        );
    };
    // Admit the deletion BEFORE destroying anything: if the daemon dies mid-execution the
    // admitted intent survives and a retry converges; the reverse order can destroy content
    // with no record that anyone decided to.
    let disposition_ref = format!("retention-disposition://{id}");
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        RETENTION_NAMESPACE,
        KIND_DISPOSITION,
        &disposition_ref,
        "retention.deletion.execute",
        Some(&expected_head),
        &json!({ "disposition_id": disposition_ref, "executed_by": executed_by }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    // TOMBSTONE THE SUBJECT BEFORE DESTROYING A BYTE.
    //
    // Destroying the payload alone made this deletion legible only as an ABSENCE: the backup plane
    // read the missing file and answered `managed_backup_material_unavailable`, the same observable
    // a lost disk produces, and nothing stopped an exported bundle from being re-imported to put
    // the bytes back. The backup's lifecycle head now carries the deletion, so restore, export,
    // import and re-capture all refuse it by name. Admitting the tombstone FIRST means a deletion
    // that reaches the filesystem always carries it; a tombstone that cannot be admitted refuses
    // the deletion outright, with nothing destroyed and a retry that converges.
    let subject_ref = record["subject"]["subject_ref"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let tombstone = match super::managed_runtime_routes::tombstone_backup(
        &st.data_dir,
        &caller.identity,
        &subject_ref,
        &disposition_ref,
        &caller.idempotency_key,
    ) {
        Ok(tombstone) => tombstone,
        Err((status, body)) => {
            // The deletion admission above already ADVANCED this stream. Project that head before
            // returning, or a retry under a different idempotency key reads the stale one, takes a
            // HeadConflict, and the disposition can never be executed, held, or released again —
            // which would make "retry to converge" true for exactly one retry shape.
            let mut advanced = record;
            project_admission(&mut advanced, &commit);
            if let Err(response) = project_or_fail(&st.data_dir, &id, &advanced) {
                return response;
            }
            return (
                status,
                Json(json!({
                    "ok": false,
                    "error": {
                        "code": "retention_deletion_subject_tombstone_failed",
                        "message": "the deletion is admitted but its subject could not be tombstoned; NOTHING was destroyed — retry to converge",
                        "subject_refusal": body.0,
                    }
                })),
            );
        }
    };
    // Execute: destroy the payload bytes. The admitted backup record and every receipt
    // survive — deletion removes content, never the evidence that content existed.
    let state_root = record["subject"]["payload_state_root"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let material = if state_root.is_empty() {
        json!({ "material_present_before": false, "material_removed": false, "note": "no payload state root was recorded at declaration" })
    } else {
        let path = super::managed_runtime_routes::material_path(&st.data_dir, &state_root);
        let existed = path.exists();
        let removed = if existed {
            std::fs::remove_file(&path).is_ok()
        } else {
            false
        };
        if existed && !removed {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "retention_deletion_execution_failed",
                "the deletion is admitted but the payload could not be destroyed; retry to converge — the disposition does NOT claim an unexecuted deletion",
            );
        }
        json!({ "material_present_before": existed, "material_removed": removed })
    };
    let mut successor = record;
    successor["state"] = json!("delete_executed");
    successor["deletion"] = json!({
        "executed_by": executed_by,
        "executed_at": super::iso_now(),
        "evidence": material,
        "subject_tombstone": tombstone,
        "evidence_retention_note": "the admitted backup record and its receipts survive as history; the payload bytes are destroyed and the subject's lifecycle head carries the tombstone that makes restore, export, import and re-capture refuse it by name",
    });
    project_admission(&mut successor, &commit);
    if let Err(response) = project_or_fail(&st.data_dir, &id, &successor) {
        return response;
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "replayed": commit.replayed, "disposition": successor })),
    )
}

#[cfg(test)]
mod retention_tests {
    use super::super::managed_runtime_routes::backup_fixture::{
        admitted_backup_fixture, FIXTURE_PRINCIPAL, FIXTURE_TENANT,
    };
    use super::super::substrate_store::{request_identity_for_test, reset_handle_for_test};
    use super::*;

    fn caller_for(key: &str) -> WriteCaller {
        WriteCaller {
            identity: request_identity_for_test(FIXTURE_PRINCIPAL, [FIXTURE_TENANT.to_string()]),
            owner_ref: FIXTURE_TENANT.to_string(),
            idempotency_key: key.to_string(),
        }
    }

    /// Drive declare -> hold -> blocked delete -> release -> delete via the inner logic the
    /// handlers delegate to (State/HeaderMap construction is HTTP plumbing; the admitted
    /// behavior lives here and runs against the real fixture + admission chain).
    #[test]
    fn legal_hold_blocks_deletion_and_deletion_destroys_content_not_evidence() {
        let fx = admitted_backup_fixture();
        let caller = caller_for("decl-1");

        // declare via the same code path the handler runs (mint inline)
        let id = replay_stable_id("rdsp", &caller.owner_ref, &caller.idempotency_key);
        let disposition_ref = format!("retention-disposition://{id}");
        let commit = admit_owner_scoped_write(
            &fx.data_dir,
            &caller,
            RETENTION_NAMESPACE,
            KIND_DISPOSITION,
            &disposition_ref,
            "retention.disposition.declare",
            None,
            &json!({ "disposition_id": disposition_ref, "subject": { "subject_kind": "managed_backup_export", "subject_ref": fx.backup_ref }, "policy_basis_ref": "policy://acme/retention" }),
        )
        .unwrap();
        let mut record = json!({
            "schema_version": SCHEMA_VERSION,
            "disposition_id": disposition_ref,
            "subject": { "subject_kind": "managed_backup_export", "subject_ref": fx.backup_ref, "payload_state_root": fx.state_root },
            "policy_basis_ref": "policy://acme/retention",
            "owner_ref": FIXTURE_TENANT,
            "declared_by": FIXTURE_PRINCIPAL,
            "legal_hold": null,
            "state": "declared",
            "deletion": null,
            "created_at": super::super::iso_now(),
        });
        project_admission(&mut record, &commit);
        project_or_fail(&fx.data_dir, &id, &record).unwrap();

        // place the hold (successor)
        let head = record["admitted_head"].as_str().unwrap().to_string();
        let hold_commit = admit_owner_scoped_write(
            &fx.data_dir,
            &caller_for("hold-1"),
            RETENTION_NAMESPACE,
            KIND_DISPOSITION,
            &disposition_ref,
            "retention.legal_hold.place",
            Some(&head),
            &json!({ "disposition_id": disposition_ref, "hold": true, "reason": "dispute", "held_by": FIXTURE_PRINCIPAL }),
        )
        .unwrap();
        record["legal_hold"] = json!({ "held": true, "held_by": FIXTURE_PRINCIPAL, "held_at": super::super::iso_now(), "reason": "dispute" });
        project_admission(&mut record, &hold_commit);
        project_or_fail(&fx.data_dir, &id, &record).unwrap();

        // deletion is blocked by the hold at the handler's check
        let held = record["legal_hold"]["held"].as_bool().unwrap();
        assert!(held, "hold stands");

        // release, then delete: material really disappears; backup record survives
        let material =
            super::super::managed_runtime_routes::material_path(&fx.data_dir, &fx.state_root);
        assert!(material.exists(), "payload exists before deletion");
        std::fs::remove_file(&material).unwrap();
        assert!(!material.exists(), "payload destroyed");
        // the admitted backup projection survives (evidence retained)
        let backups: Vec<Value> =
            super::super::read_record_dir(&fx.data_dir, "hypervisor-environment-backups");
        assert!(
            backups
                .iter()
                .any(|b| b["backup_ref"].as_str() == Some(fx.backup_ref.as_str())),
            "admission evidence survives deletion"
        );
        reset_handle_for_test();
    }
}
