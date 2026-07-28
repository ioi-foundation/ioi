//! M2 storage contract proofs: the registered storage-profile/repair/availability contracts are
//! bound to the REAL runtime planes.
//!
//! Claim under proof (M2 record contract): "Storage/operator/recovery plan" fails on silent
//! corruption/loss, hold violation, unverified restore, cleanup of live refs.
//!
//! - Positive fixtures for kernel products are rebuilt here through the actual kernel code paths
//!   (`RuntimeArtifactAvailabilityIncidentAdmissionCore::admit`,
//!   `AgentgresAdmissionCore::commit_runtime_artifact_state`) and asserted value-equal with the
//!   registered fixtures, then validated against the registered contracts.
//! - Each claim dimension has a named negative proof at the load-bearing plane: the kernel
//!   refusal code AND the registered contract agree wherever both exist.
//!
//! Hold-binding note: no code path enforces a retention hold yet (the canonical hold rule lives
//! on the deferred `StorageProfile`). The realized hold discipline proven here is (a) artifact
//! destruction is unrepresentable in the conversation-artifact control plane — every destruction
//! operation refuses by name and tombstoned records are never served as live, and (b) resource
//! destruction closes only through a receipted cleanup-obligation disposition.

use ioi_services::agentic::runtime::kernel::agentgres_admission::{
    AgentgresAdmissionCore, AgentgresAdmissionError, RuntimeArtifactStateCommitRequest,
    StorageBackendWriteProposal, RUNTIME_ARTIFACT_STATE_COMMIT_SCHEMA_VERSION,
    STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::runtime_artifact_availability_incident_admission::RuntimeArtifactAvailabilityIncidentAdmissionCore;
use ioi_services::agentic::runtime::kernel::runtime_conversation_artifact_control::{
    RuntimeConversationArtifactControlCore, RuntimeConversationArtifactControlRequest,
};
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use ioi_types::app::hypervisor_environment_lifecycle::{
    compile_backup_record, compile_cleanup_escalate, compile_cleanup_satisfy, BackupDeclaration,
    EnvironmentEstateBinding,
};
use serde_json::{json, Value};

const NOW: &str = "2026-07-28T12:00:00.000Z";

const INCIDENT_CONTRACT: &str =
    "schema://ioi/components/agentgres/artifact-availability-incident/v1";
const OPERATION_CONTRACT: &str =
    "schema://ioi/components/agentgres/artifact-availability-incident-operation/v1";
const WRITE_ADMISSION_CONTRACT: &str =
    "schema://ioi/components/agentgres/storage-backend-write-admission/v1";
const BACKUP_CONTRACT: &str = "schema://ioi/components/hypervisor/hypervisor-environment-backup/v1";
const CLEANUP_OBLIGATION_CONTRACT: &str =
    "schema://ioi/components/hypervisor/hypervisor-resource-cleanup-obligation/v1";

macro_rules! fixture {
    ($rel:expr) => {
        serde_json::from_str::<Value>(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/",
            $rel
        )))
        .expect($rel)
    };
}

// ---------------------------------------------------------------------------
// Deterministic requests (the same objects the registered fixtures pin).
// ---------------------------------------------------------------------------

fn missing_incident_request() -> Value {
    json!({
        "artifact_ref": "artifact://acme/system-alpha/workspace-snapshot/2026-07-28",
        "payload_ref": "payload://acme/system-alpha/workspace-snapshot/2026-07-28",
        "backend_ref": "storage://local-disk/primary",
        "incident_kind": "missing",
        "agentgres_operation_refs": ["agentgres://operation/storage/incident/0001"],
        "incident_receipt_refs": ["receipt://storage/incident/0001"],
        "affected_object_refs": ["agentgres://object/workspace-snapshot/2026-07-28"],
    })
}

fn repaired_incident_request() -> Value {
    json!({
        "incident_id": "artifact-availability-incident:acme-workspace-snapshot:invalid-hash-repair",
        "artifact_ref": "artifact://acme/system-alpha/workspace-snapshot/2026-07-27",
        "payload_ref": "payload://acme/system-alpha/workspace-snapshot/2026-07-27",
        "backend_ref": "storage://cas/replica-2",
        "incident_kind": "invalid_hash",
        "lifecycle_state": "repaired",
        "expected_hash": "sha256:7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
        "observed_hash": "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        "agentgres_operation_refs": ["agentgres://operation/storage/incident/0002"],
        "repair_receipt_refs": ["artifact-repair-receipt://arr_0f3a9c1b"],
        "incident_receipt_refs": ["receipt://storage/incident/0002"],
        "affected_object_refs": ["agentgres://object/workspace-snapshot/2026-07-27"],
        "verification_refs": ["verification://storage/repair/0002"],
        "restore_import_refs": ["restore://storage/import/0002"],
        "payload_bytes_mutated": true,
        "admitted_at": "2026-07-28T12:05:00.000Z",
    })
}

fn estate() -> EnvironmentEstateBinding {
    EnvironmentEstateBinding {
        estate_namespace: "local".to_owned(),
        daemon_ref: "runtime://local/daemon".to_owned(),
    }
}

fn live_backup() -> Value {
    let declaration = BackupDeclaration {
        backup_tail: "env-alpha/0001".to_owned(),
        trigger: "manual".to_owned(),
        environment_ref: "environment://local/env-alpha".to_owned(),
        schedule_or_change_plan_ref: None,
    };
    let rows = vec![
        json!({
            "artifact_ref": "artifact://local/env-alpha/backups/0001/volume",
            "sha256": "sha256:7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
            "size_bytes": 4096,
            "role": "environment_backup_payload",
        }),
        json!({
            "artifact_ref": "artifact://local/env-alpha/backups/0001/workspace",
            "sha256": "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
            "size_bytes": 512,
            "role": "workspace_snapshot",
        }),
    ];
    compile_backup_record(
        &estate(),
        &declaration,
        "sha256:fd61a03af4f77d870fc21e05e7e80678095c92d808cfb3b5c279ee04c74aca13",
        &rows,
        Some("system://local/system-alpha"),
        "receipt://local/env-alpha/backup/0001",
    )
    .expect("live backup compiles through the real plane")
}

// ---------------------------------------------------------------------------
// Dimension: silent corruption/loss — corruption surfaces as an admitted
// incident (kernel product == registered fixture), never a silent success.
// ---------------------------------------------------------------------------

#[test]
fn kernel_missing_incident_value_binds_registered_fixtures() {
    let admitted = RuntimeArtifactAvailabilityIncidentAdmissionCore
        .admit(&missing_incident_request(), NOW)
        .expect("loss admits as an incident");
    assert_eq!(
        admitted,
        fixture!("artifact-availability-incident-v1/positive-missing-opened.json"),
        "kernel output is value-equal with the registered positive fixture"
    );
    validate_architecture_contract(INCIDENT_CONTRACT, &admitted)
        .expect("kernel incident validates the registered contract");
    let envelope = admitted["agentgres_operation"].clone();
    assert_eq!(
        envelope,
        fixture!("artifact-availability-incident-operation-v1/positive-opened.json"),
        "derived envelope is value-equal with the registered operation fixture"
    );
    validate_architecture_contract(OPERATION_CONTRACT, &envelope)
        .expect("derived envelope validates the registered operation contract");
}

#[test]
fn kernel_repaired_incident_value_binds_registered_fixtures() {
    let admitted = RuntimeArtifactAvailabilityIncidentAdmissionCore
        .admit(&repaired_incident_request(), NOW)
        .expect("verified repair admits");
    assert_eq!(
        admitted,
        fixture!("artifact-availability-incident-v1/positive-repaired-verified.json"),
    );
    validate_architecture_contract(INCIDENT_CONTRACT, &admitted).expect("registered contract");
    let envelope = admitted["agentgres_operation"].clone();
    assert_eq!(
        envelope,
        fixture!("artifact-availability-incident-operation-v1/positive-repaired-bound.json"),
    );
    assert_eq!(envelope["restore_validity"], "restore_import_refs_bound");
    validate_architecture_contract(OPERATION_CONTRACT, &envelope).expect("registered contract");
}

#[test]
fn corruption_without_evidence_refuses_by_name_in_kernel_and_contract() {
    let mut request = missing_incident_request();
    request["incident_kind"] = json!("invalid_hash");
    let error = RuntimeArtifactAvailabilityIncidentAdmissionCore
        .admit(&request, NOW)
        .expect_err("evidence-free corruption claim refuses");
    assert_eq!(error.code, "artifact_availability_hash_evidence_required");
    assert_eq!(error.status, 403);
    validate_architecture_contract(
        INCIDENT_CONTRACT,
        &fixture!("artifact-availability-incident-v1/negative-invalid-hash-without-observed.json"),
    )
    .expect_err("the registered contract refuses the same shape");
}

#[test]
fn loss_without_affected_objects_is_never_an_empty_success() {
    let mut request = missing_incident_request();
    request["affected_object_refs"] = json!([]);
    let error = RuntimeArtifactAvailabilityIncidentAdmissionCore
        .admit(&request, NOW)
        .expect_err("loss must bind the objects it affects");
    assert_eq!(
        error.code,
        "artifact_availability_affected_object_refs_required"
    );
    assert_eq!(error.status, 403);
}

#[test]
fn silent_payload_mutation_refuses_by_name_in_kernel_and_contract() {
    let mut request = missing_incident_request();
    request["payload_bytes_mutated"] = json!(true);
    let error = RuntimeArtifactAvailabilityIncidentAdmissionCore
        .admit(&request, NOW)
        .expect_err("silent byte replacement refuses");
    assert_eq!(
        error.code,
        "artifact_availability_silent_payload_mutation_blocked"
    );
    validate_architecture_contract(
        INCIDENT_CONTRACT,
        &fixture!("artifact-availability-incident-v1/negative-silent-payload-mutation.json"),
    )
    .expect_err("the registered contract refuses the same shape");
}

#[test]
fn storage_write_without_agentgres_refs_or_receipt_refuses_by_name() {
    let proposal = StorageBackendWriteProposal {
        schema_version: STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION.to_string(),
        storage_backend_ref: "storage://runtime-state/local".to_string(),
        object_ref: "agentgres://runtime-state/artifacts/a/records/artifacts/a.json".to_string(),
        content_hash: "sha256:abababababababababababababababababababababababababababababababab"
            .to_string(),
        artifact_refs: vec![],
        payload_refs: vec![],
        receipt_refs: vec!["receipt://runtime/a".to_string()],
    };
    assert_eq!(
        AgentgresAdmissionCore.admit_storage_backend_write(&proposal),
        Err(AgentgresAdmissionError::StorageBackendWriteMissingAgentgresRef),
        "a byte write outside the artifact-ref plane refuses"
    );
    validate_architecture_contract(
        WRITE_ADMISSION_CONTRACT,
        &fixture!("storage-backend-write-admission-v1/negative-write-without-agentgres-refs.json"),
    )
    .expect_err("the registered contract refuses the same shape");

    let unreceipted = StorageBackendWriteProposal {
        payload_refs: vec!["payload://runtime/a".to_string()],
        receipt_refs: vec![],
        ..proposal
    };
    assert_eq!(
        AgentgresAdmissionCore.admit_storage_backend_write(&unreceipted),
        Err(AgentgresAdmissionError::StorageBackendWriteMissingReceipt),
        "an unreceipted byte write refuses"
    );
}

#[test]
fn artifact_state_commit_value_binds_registered_fixture() {
    let artifact = json!({
        "schema_version": "ioi.conversation_artifact.v1",
        "object": "ioi.conversation_artifact",
        "id": "artifact-one",
        "artifact_id": "artifact-one",
        "thread_id": "thread-one",
        "title": "Draft",
        "status": "active",
        "receipt_refs": ["receipt://runtime/artifacts/artifact-one/create"],
    });
    let record = AgentgresAdmissionCore
        .commit_runtime_artifact_state(&RuntimeArtifactStateCommitRequest {
            schema_version: RUNTIME_ARTIFACT_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            artifact_id: "artifact-one".to_string(),
            operation_kind: "artifact.conversation.create".to_string(),
            storage_backend_ref: "storage://runtime-state/local".to_string(),
            artifact,
            receipt_refs: vec![],
        })
        .expect("artifact state commit admits through the real kernel path");
    let admission = serde_json::to_value(&record.record.admission).expect("admission json");
    assert_eq!(
        admission,
        fixture!("storage-backend-write-admission-v1/positive-artifact-state-commit.json"),
        "the kernel-computed admission (content hash + admission hash) is value-equal with the registered fixture"
    );
    validate_architecture_contract(WRITE_ADMISSION_CONTRACT, &admission)
        .expect("kernel write admission validates the registered contract");
}

// ---------------------------------------------------------------------------
// Dimension: hold violation — destruction of a held/live artifact record has
// no admitted lane; every attempt refuses by name.
// ---------------------------------------------------------------------------

#[test]
fn conversation_artifact_destruction_refuses_by_name() {
    for retired_operation in [
        "artifact.conversation.delete",
        "artifact.conversation.purge",
        "artifact.conversation.gc",
    ] {
        let error = RuntimeConversationArtifactControlCore
            .plan(&RuntimeConversationArtifactControlRequest {
                operation_kind: Some(retired_operation.to_string()),
                artifact_id: Some("artifact-one".to_string()),
                ..Default::default()
            })
            .expect_err("artifact destruction has no admitted control lane");
        assert_eq!(
            error.code(),
            "runtime_conversation_artifact_control_operation_kind_unsupported",
            "{retired_operation} refuses by name"
        );
    }
}

#[test]
fn tombstoned_artifact_is_excluded_from_replay_not_served_as_live() {
    let temp = tempfile::tempdir().expect("tempdir");
    let artifact_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&artifact_dir).expect("artifact dir");
    std::fs::write(
        artifact_dir.join("artifact-held.json"),
        serde_json::to_string_pretty(&json!({
            "schema_version": "ioi.conversation_artifact.v1",
            "object": "ioi.conversation_artifact",
            "id": "artifact-held",
            "artifact_id": "artifact-held",
            "thread_id": "thread-one",
            "title": "Tombstoned",
            "status": "deleted",
            "deleted_at": "2026-07-28T11:00:00.000Z",
            "revisions": []
        }))
        .expect("record json"),
    )
    .expect("write record");
    let error = RuntimeConversationArtifactControlCore
        .plan(&RuntimeConversationArtifactControlRequest {
            operation_kind: Some("artifact.conversation.action".to_string()),
            artifact_id: Some("artifact-held".to_string()),
            state_dir: Some(temp.path().to_string_lossy().to_string()),
            request: json!({ "created_at": NOW, "action_kind": "edit" }),
            ..Default::default()
        })
        .expect_err("a tombstoned record is never served as a live artifact");
    assert_eq!(
        error.code(),
        "runtime_conversation_artifact_control_artifact_not_found"
    );
}

#[test]
fn held_backup_is_representable_and_still_contract_valid() {
    // The registered structural hold surface: hold_refs on the durable backup.
    // No code path enforces holds yet (recorded gap; the canonical rule lives
    // on the deferred StorageProfile) — this pins that a held backup is
    // representable under the registered contract, so hold enforcement can
    // land without a wire change.
    let mut held = live_backup();
    held["hold_refs"] = json!(["hold://local/legal/2026-004"]);
    validate_architecture_contract(BACKUP_CONTRACT, &held)
        .expect("a held backup validates the registered contract");
}

// ---------------------------------------------------------------------------
// Dimension: unverified restore — a repair claiming success without
// verification evidence cannot mint a healthy status (INV-37).
// ---------------------------------------------------------------------------

#[test]
fn unverified_repair_cannot_mint_healthy_status() {
    let mut unverified = repaired_incident_request();
    unverified["verification_refs"] = json!([]);
    let error = RuntimeArtifactAvailabilityIncidentAdmissionCore
        .admit(&unverified, NOW)
        .expect_err("repair without verification refuses");
    assert_eq!(
        error.code,
        "artifact_availability_verification_refs_required"
    );
    assert_eq!(error.status, 403);
    validate_architecture_contract(
        INCIDENT_CONTRACT,
        &fixture!("artifact-availability-incident-v1/negative-repaired-without-verification.json"),
    )
    .expect_err("the registered contract refuses the same shape");

    let mut receiptless = repaired_incident_request();
    receiptless["repair_receipt_refs"] = json!([]);
    receiptless["payload_bytes_mutated"] = json!(false);
    let error = RuntimeArtifactAvailabilityIncidentAdmissionCore
        .admit(&receiptless, NOW)
        .expect_err("repair without a repair receipt refuses");
    assert_eq!(
        error.code,
        "artifact_availability_repair_receipt_refs_required"
    );

    let mut importless = repaired_incident_request();
    importless["restore_import_refs"] = json!([]);
    let error = RuntimeArtifactAvailabilityIncidentAdmissionCore
        .admit(&importless, NOW)
        .expect_err("repair without restore/import refs refuses");
    assert_eq!(
        error.code,
        "artifact_availability_restore_import_ref_required"
    );
}

#[test]
fn unbound_restore_validity_claim_refuses_in_registered_contract() {
    validate_architecture_contract(
        OPERATION_CONTRACT,
        &fixture!(
            "artifact-availability-incident-operation-v1/negative-unbound-restore-validity-claim.json"
        ),
    )
    .expect_err("a restore_import_refs_bound claim without refs is unrepresentable");
}

// ---------------------------------------------------------------------------
// Dimension: cleanup of live refs — a payload cited by a live backup manifest
// cannot be cleaned out of the record, and resource cleanup closes only
// through a receipted disposition.
// ---------------------------------------------------------------------------

#[test]
fn live_backup_census_breaks_when_a_cited_ref_is_cleaned() {
    let backup = live_backup();
    validate_architecture_contract(BACKUP_CONTRACT, &backup)
        .expect("the live backup validates the registered contract");

    // Cleaning a payload out of the manifest breaks the census structurally.
    let mut cleaned = backup.clone();
    cleaned["manifest_rows"].as_array_mut().expect("rows").pop();
    validate_architecture_contract(BACKUP_CONTRACT, &cleaned)
        .expect_err("a manifest missing a live row is invalid, never merely degraded");

    // Cleaning the top-level artifact ref alone breaks ref/count equality.
    let mut unlinked = backup.clone();
    unlinked["artifact_refs"]
        .as_array_mut()
        .expect("refs")
        .pop();
    validate_architecture_contract(BACKUP_CONTRACT, &unlinked)
        .expect_err("a dropped live artifact ref is invalid");

    // Substituted bytes break the recomputable manifest commitment.
    let mut substituted = backup;
    substituted["manifest_rows"][0]["sha256"] =
        json!("sha256:1111111111111111111111111111111111111111111111111111111111111111");
    validate_architecture_contract(BACKUP_CONTRACT, &substituted)
        .expect_err("the manifest root no longer recomputes over substituted rows");
}

#[test]
fn cleanup_obligation_over_live_backup_resource_requires_receipted_close() {
    let backup = live_backup();
    let mut obligation = fixture!("hypervisor-resource-cleanup-obligation-v1/positive-open.json");
    // Bind the obligation to the exact environment the live backup cites.
    obligation["environment_ref"] = backup["environment_ref"].clone();
    validate_architecture_contract(CLEANUP_OBLIGATION_CONTRACT, &obligation)
        .expect("open obligation validates");

    // Unreceipted close refuses by name: cleanup is never garbage-collection
    // inference over refs a live record still cites.
    let error = compile_cleanup_satisfy(&obligation, "completed", None, &[])
        .expect_err("unreceipted close refuses");
    assert!(error.starts_with("unreceipted_close"), "{error}");

    // Loss of the live parent escalates and preserves custody, never erases.
    let escalated = compile_cleanup_escalate(
        &obligation,
        "parent_loss",
        backup["environment_ref"].as_str().expect("environment"),
        &["evidence://local/env-alpha/deletion".to_owned()],
    )
    .expect("parent loss escalates");
    assert_eq!(escalated["status"], "escalated");
    assert_eq!(escalated["resource_refs"], obligation["resource_refs"]);

    // A receipted disposition closes; the receipt is on the record.
    let closed = compile_cleanup_satisfy(
        &obligation,
        "completed",
        Some("receipt://local/env-alpha/cleanup/0001"),
        &["evidence://local/env-alpha/cleanup/absent".to_owned()],
    )
    .expect("receipted close admits");
    assert!(closed["receipt_refs"]
        .as_array()
        .expect("receipts")
        .iter()
        .any(|receipt| receipt == "receipt://local/env-alpha/cleanup/0001"));
    validate_architecture_contract(CLEANUP_OBLIGATION_CONTRACT, &closed)
        .expect("receipted close validates");
}
