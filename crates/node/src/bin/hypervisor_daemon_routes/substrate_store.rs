//! Agentgres substrate store: engine-backed truth for PROMOTED record
//! families, plus the opt-in dual-write soak lane for families still on
//! the legacy JSON path (doctrine: docs/architecture/components/agentgres/
//! doctrine.md, Substrate Contract Doctrine; migration shape:
//! shadow → compare → promote → CUT).
//!
//! Promoted families (see `PROMOTED_DOMAINS`) are CUT OVER: writes admit
//! into the multiplexed substrate log at `<data_dir>/substrate/` and reads
//! project from it — no legacy JSON file is written or read for them, so
//! there is no split brain. On first engine open, any records still
//! sitting in the family's legacy dir are BACKFILLED once (idempotent:
//! object-head presence check; canonical order `(at, record_id)`); the
//! legacy files then remain on disk as inert history.
//!
//! Non-promoted families keep the legacy JSON path and may opt into the
//! dual-write soak (`IOI_SUBSTRATE_DUAL_WRITE=1` +
//! `IOI_SUBSTRATE_DUAL_WRITE_DOMAINS`), which is the pre-promotion
//! evidence lane proven by `substrate-parity`.

use agentgres::mux::{
    spawn_mux_writer_cfg, ExactProjection, MuxAdmitError, MuxEngine, MuxHandle, WriterConfig,
};
use agentgres::replica::ReplicaLink;
use agentgres::{parse_rfc3339_ms, AdmitAck, Operation, Refusal};
use axum::{extract::State, Json};
use serde_json::{json, Value};
use sha2::Digest;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

/// Families whose truth is the substrate engine. Extend only after the
/// candidate family has passed a dual-write soak with clean parity.
pub(crate) const PROMOTED_DOMAINS: &[&str] = &["provider-receipts"];
/// Families that remain daemon-file projections but MUST also cross the Agentgres operation log
/// before their owner-plane intent may clear. This is a synchronous pre-promotion boundary, not a
/// CUT: reads remain on the owner plane until the normal shadow/compare/promotion bar is met.
pub(crate) const REQUIRED_ADMISSION_DOMAINS: &[&str] = &[
    "autonomous-system-genesis-registry",
    "autonomous-system-genesis-receipts",
    "autonomous-system-genesis-authority-consumptions",
    "autonomous-system-sequence-zero-materializations",
    "autonomous-system-sequence-zero-materialization-receipts",
    "autonomous-system-sequence-zero-component-registries",
    "autonomous-system-sequence-zero-authority-consumptions",
    "autonomous-system-deployment-profile-revisions",
    "autonomous-system-lifecycle-authority-evidence",
    "autonomous-system-lifecycle-authority-consumptions",
    "autonomous-system-lifecycle-proposals",
    "autonomous-system-lifecycle-authority-decisions",
    "autonomous-system-lifecycle-transitions",
    "autonomous-system-initialize-transition-receipts",
    "autonomous-system-activation-receipts",
    "autonomous-system-activation-states",
    "autonomous-system-active-profile-sets",
    "autonomous-system-home-bindings",
    "autonomous-system-operation-log-revisions",
    "autonomous-system-chain-revisions",
];

static HANDLE: OnceLock<Option<MuxHandle>> = OnceLock::new();
static ADMITTED: AtomicU64 = AtomicU64::new(0);
static ERRORS: AtomicU64 = AtomicU64::new(0);
static BACKFILLED: AtomicU64 = AtomicU64::new(0);

pub(crate) fn is_promoted(record_dir: &str) -> bool {
    PROMOTED_DOMAINS.contains(&record_dir)
}

fn soak_enabled() -> bool {
    std::env::var("IOI_SUBSTRATE_DUAL_WRITE")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn soak_domains() -> Vec<String> {
    std::env::var("IOI_SUBSTRATE_DUAL_WRITE_DOMAINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| {
            !s.is_empty() && !is_promoted(s) && !REQUIRED_ADMISSION_DOMAINS.contains(&s.as_str())
        })
        .collect()
}

fn engine_dir(data_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(data_dir).join("substrate")
}

fn confirm_required_admission_durability(data_dir: &str) -> std::io::Result<()> {
    if std::env::var("IOI_TEST_FORCE_REQUIRED_ADMISSION_SYNC_FAILURE")
        .ok()
        .as_deref()
        == Some("1")
    {
        return Err(std::io::Error::other(
            "test-forced required-admission durability failure",
        ));
    }
    let dir = engine_dir(data_dir);
    std::fs::File::open(dir.join("muxlog.bin"))?.sync_all()?;
    std::fs::File::open(dir)?.sync_all()
}

fn build_op(record_dir: &str, record_id: &str, record: &Value) -> Operation {
    Operation {
        domain: record_dir.to_string(),
        object_ref: format!("agentgres://{record_dir}/{record_id}"),
        op_kind: format!("{record_dir}.persist"),
        expected_head: None,
        expected_absent: false,
        payload: record.clone(),
        recorded_at_ms: record
            .get("at")
            .and_then(|v| v.as_str())
            .map(parse_rfc3339_ms)
            .unwrap_or(0),
        idem_key: record_id.to_string(),
    }
}

fn required_object_ref(record_dir: &str, record_id: &str) -> String {
    format!("agentgres://{record_dir}/{record_id}")
}

fn validate_required_domain(record_dir: &str) -> std::io::Result<()> {
    if REQUIRED_ADMISSION_DOMAINS.contains(&record_dir) {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("'{record_dir}' is not a declared required-admission domain"),
    ))
}

fn required_identity(record_dir: &str, record_id: &str) -> (&'static str, String) {
    match record_dir {
        "autonomous-system-genesis-registry" => (
            "admission_id",
            format!("system-genesis-admission://{record_id}"),
        ),
        "autonomous-system-genesis-receipts" => ("receipt_ref", format!("receipt://{record_id}")),
        "autonomous-system-genesis-authority-consumptions" => {
            unreachable!("wallet consumption identity is validated from its 32-byte field")
        }
        "autonomous-system-sequence-zero-materializations" => (
            "materialization_id",
            format!(
                "system-materialization://sequence-zero/sha256:{}",
                record_id.strip_prefix("aszm_").unwrap_or("")
            ),
        ),
        "autonomous-system-sequence-zero-materialization-receipts" => {
            ("receipt_ref", format!("receipt://{record_id}"))
        }
        "autonomous-system-sequence-zero-component-registries" => (
            "component_registry_ref",
            format!(
                "agentgres://object-set/autonomous-system-components/sha256:{}",
                record_id.strip_prefix("aszcr_").unwrap_or("")
            ),
        ),
        "autonomous-system-sequence-zero-authority-consumptions" => {
            unreachable!("wallet consumption identity is validated from its 32-byte field")
        }
        "autonomous-system-deployment-profile-revisions" => (
            "deployment_profile_root",
            format!("sha256:{}", record_id.strip_prefix("asdpr_").unwrap_or("")),
        ),
        "autonomous-system-lifecycle-authority-evidence" => (
            "authority_evidence_ref",
            format!("system-lifecycle-authority-evidence://{record_id}"),
        ),
        "autonomous-system-lifecycle-proposals" => (
            "proposal_root",
            format!("sha256:{}", record_id.strip_prefix("aslp_").unwrap_or("")),
        ),
        "autonomous-system-lifecycle-authority-decisions" => (
            "decision_root",
            format!("sha256:{}", record_id.strip_prefix("aslad_").unwrap_or("")),
        ),
        "autonomous-system-activation-states" => (
            "activation_state_root",
            format!("sha256:{}", record_id.strip_prefix("asls_").unwrap_or("")),
        ),
        "autonomous-system-active-profile-sets" => (
            "active_profile_set_root",
            format!("sha256:{}", record_id.strip_prefix("asaps_").unwrap_or("")),
        ),
        "autonomous-system-home-bindings" => (
            "home_domain_binding_root",
            format!("sha256:{}", record_id.strip_prefix("ashdb_").unwrap_or("")),
        ),
        "autonomous-system-operation-log-revisions" => (
            "operation_log_root",
            format!("sha256:{}", record_id.strip_prefix("asol_").unwrap_or("")),
        ),
        "autonomous-system-chain-revisions" => (
            "chain_root",
            format!("sha256:{}", record_id.strip_prefix("asc_").unwrap_or("")),
        ),
        "autonomous-system-lifecycle-authority-consumptions"
        | "autonomous-system-lifecycle-transitions"
        | "autonomous-system-initialize-transition-receipts"
        | "autonomous-system-activation-receipts" => {
            unreachable!("identity is validated by the family-specific branch")
        }
        _ => unreachable!("required-admission domains are exhaustively matched"),
    }
}

fn jcs_root(material: &Value) -> std::io::Result<String> {
    Ok(format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(
            serde_jcs::to_vec(material).map_err(std::io::Error::other)?
        ))
    ))
}

fn fields_material(record: &Value, domain: &str, fields: &[&str]) -> std::io::Result<Value> {
    let mut material = serde_json::Map::new();
    material.insert("domain".to_owned(), json!(domain));
    for field in fields {
        material.insert(
            (*field).to_owned(),
            record.get(*field).cloned().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("required Agentgres record lacks '{field}'"),
                )
            })?,
        );
    }
    Ok(Value::Object(material))
}

fn validate_embedded_content_root(record_dir: &str, record: &Value) -> std::io::Result<()> {
    let (root_field, material) = match record_dir {
        "autonomous-system-deployment-profile-revisions" => (
            "deployment_profile_root",
            json!({
                "domain":"ioi.autonomous-system-deployment-profile-revision-jcs-sha256.v1",
                "profile":record.get("profile").cloned().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "deployment revision lacks profile"))?,
            }),
        ),
        "autonomous-system-lifecycle-authority-evidence" => {
            let mut evidence = record.clone();
            evidence["authority_evidence_ref"] = Value::Null;
            evidence["authority_evidence_root"] = Value::Null;
            (
                "authority_evidence_root",
                json!({"domain":"ioi.hypervisor.system-lifecycle-authority-evidence-jcs-sha256.v1","evidence":evidence}),
            )
        }
        "autonomous-system-lifecycle-proposals" => {
            let mut material = record.as_object().cloned().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "proposal is not an object",
                )
            })?;
            material.remove("schema_version");
            material.remove("proposal_root");
            material.insert(
                "domain".to_owned(),
                json!("ioi.autonomous-system-activation-proposal-jcs-sha256.v1"),
            );
            ("proposal_root", Value::Object(material))
        }
        "autonomous-system-lifecycle-authority-decisions" => {
            let mut material = record.as_object().cloned().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "decision is not an object",
                )
            })?;
            material.remove("schema_version");
            material.remove("decision_root");
            material.insert(
                "domain".to_owned(),
                json!("ioi.autonomous-system-activation-authority-decision-jcs-sha256.v1"),
            );
            ("decision_root", Value::Object(material))
        }
        "autonomous-system-activation-states" => (
            "activation_state_root",
            fields_material(
                record,
                "ioi.autonomous-system-activation-state-jcs-sha256.v1",
                &[
                    "activation_state_ref",
                    "system_id",
                    "genesis_ref",
                    "manifest_ref",
                    "admitted_manifest_root",
                    "lifecycle_profile_ref",
                    "sequence",
                    "status",
                    "predecessor_state_root",
                    "active_profile_set_ref",
                    "active_profile_set_root",
                    "live_chain_created",
                    "node_membership_refs",
                    "runtime_effect_admitted",
                    "network_effect_admitted",
                ],
            )?,
        ),
        "autonomous-system-active-profile-sets" => (
            "active_profile_set_root",
            fields_material(
                record,
                "ioi.autonomous-system-active-profile-set-jcs-sha256.v1",
                &[
                    "active_profile_set_ref",
                    "system_id",
                    "genesis_ref",
                    "profile_bundle_root",
                    "constitution",
                    "deployment",
                    "ordering_admission_finality",
                    "oracle_evidence_profiles",
                    "lifecycle_continuity",
                    "network_enrollment",
                    "status",
                ],
            )?,
        ),
        "autonomous-system-home-bindings" => (
            "home_domain_binding_root",
            fields_material(
                record,
                "ioi.autonomous-system-home-domain-binding-jcs-sha256.v1",
                &[
                    "system_id",
                    "genesis_ref",
                    "home_domain_ref",
                    "home_domain_commitment",
                    "source_governing_authority_ref",
                    "source_genesis_admission_receipt_ref",
                    "source_genesis_admission_receipt_root",
                    "source_sequence_zero_materialization_ref",
                    "source_sequence_zero_materialization_root",
                    "source_sequence_zero_receipt_ref",
                    "source_sequence_zero_receipt_root",
                    "source_sequence_zero_receipt_artifact_root",
                    "status",
                ],
            )?,
        ),
        "autonomous-system-operation-log-revisions" => {
            let mut material = record.as_object().cloned().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "operation log is not an object",
                )
            })?;
            material.remove("schema_version");
            material.remove("operation_log_ref");
            material.remove("operation_log_root");
            material.insert(
                "domain".to_owned(),
                json!("ioi.autonomous-system-operation-log-jcs-sha256.v1"),
            );
            ("operation_log_root", Value::Object(material))
        }
        "autonomous-system-chain-revisions" => {
            let mut material = record.as_object().cloned().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "chain is not an object")
            })?;
            material.remove("schema_version");
            material.remove("chain_root");
            material.remove("created_at");
            material.insert(
                "domain".to_owned(),
                json!("ioi.autonomous-system-chain-jcs-sha256.v1"),
            );
            ("chain_root", Value::Object(material))
        }
        _ => return Ok(()),
    };
    if record.get(root_field).and_then(Value::as_str) != Some(jcs_root(&material)?.as_str()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "required Agentgres '{root_field}' does not recompute from exact embedded content"
            ),
        ));
    }
    Ok(())
}

fn validate_required_identity(
    record_dir: &str,
    record_id: &str,
    record: &Value,
) -> std::io::Result<()> {
    let required_prefix = match record_dir {
        "autonomous-system-genesis-registry" => "asg_",
        "autonomous-system-genesis-receipts" => "asgr_",
        "autonomous-system-genesis-authority-consumptions" => "asgc_",
        "autonomous-system-sequence-zero-materializations" => "aszm_",
        "autonomous-system-sequence-zero-materialization-receipts" => "aszmr_",
        "autonomous-system-sequence-zero-component-registries" => "aszcr_",
        "autonomous-system-sequence-zero-authority-consumptions" => "aszmc_",
        "autonomous-system-deployment-profile-revisions" => "asdpr_",
        "autonomous-system-lifecycle-authority-evidence" => "aslae_",
        "autonomous-system-lifecycle-authority-consumptions" => "aslac_",
        "autonomous-system-lifecycle-proposals" => "aslp_",
        "autonomous-system-lifecycle-authority-decisions" => "aslad_",
        "autonomous-system-lifecycle-transitions" => "aslt_",
        "autonomous-system-initialize-transition-receipts" => "asltr_",
        "autonomous-system-activation-receipts" => "asar_",
        "autonomous-system-activation-states" => "asls_",
        "autonomous-system-active-profile-sets" => "asaps_",
        "autonomous-system-home-bindings" => "ashdb_",
        "autonomous-system-operation-log-revisions" => "asol_",
        "autonomous-system-chain-revisions" => "asc_",
        _ => unreachable!("required-admission domains are exhaustively matched"),
    };
    if !record_id.strip_prefix(required_prefix).is_some_and(|tail| {
        tail.len() == 64
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "required Agentgres key must be '{required_prefix}' plus 64 lowercase hex characters"
            ),
        ));
    }
    if matches!(
        record_dir,
        "autonomous-system-genesis-authority-consumptions"
            | "autonomous-system-sequence-zero-authority-consumptions"
            | "autonomous-system-lifecycle-authority-consumptions"
    ) {
        let encoded_id = record_id
            .strip_prefix(required_prefix)
            .expect("required prefix was validated");
        let consumption_id: [u8; 32] =
            serde_json::from_value(record.get("consumption_id").cloned().unwrap_or(Value::Null))
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "required Agentgres wallet receipt must contain a 32-byte 'consumption_id'",
                    )
                })?;
        if hex::encode(consumption_id) != encoded_id {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "required Agentgres wallet consumption key does not match the receipt 'consumption_id'",
            ));
        }
        return Ok(());
    }
    if matches!(
        record_dir,
        "autonomous-system-lifecycle-transitions"
            | "autonomous-system-initialize-transition-receipts"
            | "autonomous-system-activation-receipts"
    ) {
        let encoded = record_id
            .strip_prefix(required_prefix)
            .expect("required prefix was validated");
        let (domain, identity_field) = match record_dir {
            "autonomous-system-lifecycle-transitions" => (
                "ioi.autonomous-system-lifecycle-transition-jcs-sha256.v1",
                "lifecycle_transition_id",
            ),
            "autonomous-system-initialize-transition-receipts" => (
                "ioi.lifecycle-transition-receipt-artifact-jcs-sha256.v1",
                "receipt_ref",
            ),
            "autonomous-system-activation-receipts" => (
                "ioi.autonomous-system-activation-receipt-artifact-jcs-sha256.v1",
                "receipt_ref",
            ),
            _ => unreachable!(),
        };
        if record.get(identity_field).and_then(Value::as_str).is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("required Agentgres record lacks '{identity_field}'"),
            ));
        }
        let bytes = serde_jcs::to_vec(&json!({"domain": domain, "artifact": record}))
            .map_err(std::io::Error::other)?;
        let root = sha2::Sha256::digest(bytes);
        if hex::encode(root) != encoded {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "required Agentgres key does not match the embedded artifact root",
            ));
        }
        return Ok(());
    }
    let (identity_field, expected_identity) = required_identity(record_dir, record_id);
    if record.get(identity_field).and_then(Value::as_str) == Some(expected_identity.as_str()) {
        return validate_embedded_content_root(record_dir, record);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "required Agentgres record '{record_dir}/{record_id}' has a mismatched '{identity_field}' identity"
        ),
    ))
}

#[cfg(test)]
pub(crate) fn validate_required_identity_for_test(
    record_dir: &str,
    record_id: &str,
    record: &Value,
) -> std::io::Result<()> {
    validate_required_identity(record_dir, record_id, record)
}

fn build_required_op(record_dir: &str, record_id: &str, record: &Value) -> Operation {
    let mut operation = build_op(record_dir, record_id, record);
    operation.expected_absent = true;
    operation
}

fn required_operations_match(existing: &Operation, proposed: &Operation) -> std::io::Result<bool> {
    if existing != proposed {
        return Ok(false);
    }
    let existing = serde_json::to_vec(existing).map_err(std::io::Error::other)?;
    let proposed = serde_json::to_vec(proposed).map_err(std::io::Error::other)?;
    Ok(existing == proposed)
}

fn classify_required_existing(
    record_dir: &str,
    record_id: &str,
    proposed: &Operation,
    existing: &ExactProjection,
) -> std::io::Result<()> {
    if existing.operation.object_ref != required_object_ref(record_dir, record_id) {
        return Err(std::io::Error::other(format!(
            "Agentgres exact projection returned mismatched key '{}' for '{record_dir}/{record_id}'",
            existing.operation.object_ref
        )));
    }
    if required_operations_match(&existing.operation, proposed)? {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "Agentgres key '{record_dir}/{record_id}' already holds different immutable evidence"
        ),
    ))
}

fn verify_required_projection(
    record_dir: &str,
    record_id: &str,
    record: &Value,
    exact: Option<ExactProjection>,
) -> std::io::Result<ExactProjection> {
    validate_required_domain(record_dir)?;
    validate_required_identity(record_dir, record_id, record)?;
    let exact = exact.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Agentgres required key '{record_dir}/{record_id}' has no exact projection"),
        )
    })?;
    classify_required_existing(
        record_dir,
        record_id,
        &build_required_op(record_dir, record_id, record),
        &exact,
    )?;
    Ok(exact)
}

/// Validate one already-read required projection before an owner plane copies
/// its payload into local recovery evidence. The exact projection itself is
/// the validation subject, so a corrupt same-key payload cannot cross the
/// recovery boundary before its key, operation, and bytes agree.
pub(crate) fn validate_required_exact_projection(
    record_dir: &str,
    record_id: &str,
    exact: ExactProjection,
) -> std::io::Result<Value> {
    let record = exact.operation.payload.clone();
    verify_required_projection(record_dir, record_id, &record, Some(exact))?;
    Ok(record)
}

fn verify_required_ack(
    record_dir: &str,
    record_id: &str,
    ack: &AdmitAck,
    exact: &ExactProjection,
) -> std::io::Result<()> {
    if exact.seq != ack.seq
        || exact.head != ack.new_head
        || exact.admission_batch_seq != ack.batch_seq
        || exact.admission_root != ack.root
    {
        return Err(std::io::Error::other(format!(
            "Agentgres exact projection disagrees with fresh admission ack for '{record_dir}/{record_id}'"
        )));
    }
    Ok(())
}

/// One-time idempotent backfill of a promoted family's legacy JSON dir into
/// the engine, in canonical `(at, record_id)` order. Legacy files are left
/// on disk as inert history; the engine is truth from here on.
fn backfill_domain_with(
    engine: &mut MuxEngine,
    data_dir: &str,
    domain: &str,
    mut admit: impl FnMut(
        &mut MuxEngine,
        Vec<Operation>,
    ) -> std::io::Result<Vec<Result<AdmitAck, Refusal>>>,
) -> std::io::Result<u64> {
    let legacy = std::path::Path::new(data_dir).join(domain);
    let entries = match std::fs::read_dir(&legacy) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut pending: Vec<(String, String, Value)> = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let v = serde_json::from_slice::<Value>(&bytes).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "legacy backfill record '{}' is invalid JSON: {error}",
                    path.display()
                ),
            )
        })?;
        let id = v
            .get("receipt_id")
            .or_else(|| v.get("id"))
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .or_else(|| {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .map(str::to_string)
            })
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "legacy backfill record '{}' has no UTF-8 identity",
                        path.display()
                    ),
                )
            })?;
        let object_ref = format!("agentgres://{domain}/{id}");
        if engine.domain_head(domain, &object_ref).is_some() {
            continue; // already admitted — idempotent re-run
        }
        let at = v
            .get("at")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        pending.push((at, id, v));
    }
    if pending.is_empty() {
        return Ok(0);
    }
    pending.sort_by(|a, b| (a.0.as_str(), a.1.as_str()).cmp(&(b.0.as_str(), b.1.as_str())));
    let mut done = 0u64;
    for chunk in pending.chunks(512) {
        let ops: Vec<Operation> = chunk
            .iter()
            .map(|(_, id, v)| build_op(domain, id, v))
            .collect();
        let results = admit(engine, ops)?;
        if results.len() != chunk.len() {
            return Err(std::io::Error::other(format!(
                "legacy backfill for '{domain}' returned {} outcomes for {} records",
                results.len(),
                chunk.len()
            )));
        }
        if let Some(refusal) = results.iter().find_map(|result| result.as_ref().err()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("legacy backfill for '{domain}' was refused: {refusal}"),
            ));
        }
        done += u64::try_from(results.len()).map_err(std::io::Error::other)?;
    }
    Ok(done)
}

fn backfill_domain(engine: &mut MuxEngine, data_dir: &str, domain: &str) -> std::io::Result<u64> {
    backfill_domain_with(engine, data_dir, domain, MuxEngine::admit_batch)
}

fn backfill_promoted_domains(engine: &mut MuxEngine, data_dir: &str) -> std::io::Result<()> {
    for domain in PROMOTED_DOMAINS {
        let done = backfill_domain(engine, data_dir, domain)?;
        BACKFILLED.fetch_add(done, Ordering::Relaxed);
        eprintln!(
            "substrate-store: backfilled {done} legacy {domain} records into the substrate engine"
        );
    }
    Ok(())
}

fn initialize_handle_with(
    data_dir: &str,
    mut engine: MuxEngine,
    addrs: Vec<String>,
    want_async: bool,
    backfill: impl FnOnce(&mut MuxEngine, &str) -> std::io::Result<()>,
) -> Option<MuxHandle> {
    if let Err(error) = backfill(&mut engine, data_dir) {
        eprintln!(
            "substrate-store: backfill FAILED ({error}) — writer will not start; restart must reopen and recover the engine"
        );
        return None;
    }

    let mut replicas = Vec::new();
    if !addrs.is_empty() {
        let independent = std::env::var("IOI_SUBSTRATE_REPLICA_INDEPENDENT")
            .map(|v| v == "1")
            .unwrap_or(false);
        let epoch = engine.current_epoch();
        let len = engine.log_len().unwrap_or(0);
        let log_path = engine_dir(data_dir).join("muxlog.bin");
        for address in &addrs {
            match ReplicaLink::connect(address.as_str(), independent, epoch, &log_path, len) {
                Ok(link) => replicas.push(link),
                Err(error) => eprintln!(
                    "substrate-store: replica {address} unreachable ({error}) — continuing without it"
                ),
            }
        }
    }
    let ack_quorum = std::env::var("IOI_SUBSTRATE_ACK_QUORUM")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let flush_every_batches = if want_async && replicas.is_empty() {
        eprintln!(
            "substrate-store: FAIL-SAFE — async flush requested but no replica connected; forcing per-batch sync"
        );
        1
    } else {
        0
    };
    let background_flush_ms = if want_async && !replicas.is_empty() {
        std::env::var("IOI_SUBSTRATE_BG_FLUSH_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(200)
    } else {
        0
    };
    let (handle, _writer) = spawn_mux_writer_cfg(
        engine,
        WriterConfig {
            max_batch: 1024,
            replicas,
            ack_quorum,
            flush_every_batches,
            background_flush_ms,
        },
    );
    Some(handle)
}

fn handle(data_dir: &str) -> &'static Option<MuxHandle> {
    HANDLE.get_or_init(|| {
        let addrs = replica_addrs();
        let async_flush =
            std::env::var("IOI_SUBSTRATE_ASYNC_FLUSH").map(|v| v == "1").unwrap_or(false);
        // Conservative default: device-flush sync mode. Async flush (the
        // replicated-latency posture) is opt-in AND requires a connected
        // replica; otherwise the fail-safe below restores per-batch sync.
        let want_async = !addrs.is_empty() && async_flush;
        match MuxEngine::open(&engine_dir(data_dir), !want_async) {
            Ok(engine) => initialize_handle_with(
                data_dir,
                engine,
                addrs,
                want_async,
                backfill_promoted_domains,
            ),
            Err(e) => {
                eprintln!("substrate-store: engine open FAILED ({e}) — promoted-family persistence will fail loudly");
                None
            }
        }
    })
}

fn replica_addrs() -> Vec<String> {
    std::env::var("IOI_SUBSTRATE_REPLICA_ADDRS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Write path for promoted families: the engine IS truth; failure is a
/// loud error to the caller, never a silent drop (INV-14).
pub(crate) fn persist_promoted(
    data_dir: &str,
    record_dir: &str,
    record_id: &str,
    record: &Value,
) -> std::io::Result<()> {
    admit_required_inner(data_dir, record_dir, record_id, record)
}

fn admit_required_inner(
    data_dir: &str,
    record_dir: &str,
    record_id: &str,
    record: &Value,
) -> std::io::Result<()> {
    let Some(h) = handle(data_dir) else {
        ERRORS.fetch_add(1, Ordering::Relaxed);
        return Err(std::io::Error::other("substrate engine unavailable"));
    };
    match h.admit(build_op(record_dir, record_id, record)) {
        Ok(_) => {
            ADMITTED.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        Err(error) => {
            ERRORS.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "substrate-store: admission failed ({error}) record={record_dir}/{record_id}"
            );
            Err(std::io::Error::other(format!(
                "substrate admission failed: {error}"
            )))
        }
    }
}

/// Synchronous Agentgres boundary for a declared pre-promotion family.
///
/// The caller owns its crash-convergent intent and local projection. It may clear that intent only
/// after this admission succeeds; retries are idempotent on the exact record id and bytes.
pub(crate) fn admit_required(
    data_dir: &str,
    record_dir: &str,
    record_id: &str,
    record: &Value,
) -> std::io::Result<()> {
    validate_required_domain(record_dir)?;
    validate_required_identity(record_dir, record_id, record)?;
    let Some(h) = handle(data_dir) else {
        ERRORS.fetch_add(1, Ordering::Relaxed);
        return Err(std::io::Error::other("substrate engine unavailable"));
    };
    let object_ref = required_object_ref(record_dir, record_id);
    let operation = build_required_op(record_dir, record_id, record);
    let existing = h.project_exact(record_dir, &object_ref).map_err(|error| {
        ERRORS.fetch_add(1, Ordering::Relaxed);
        error
    })?;
    if let Some(existing) = existing {
        classify_required_existing(record_dir, record_id, &operation, &existing).map_err(
            |error| {
                ERRORS.fetch_add(1, Ordering::Relaxed);
                error
            },
        )?;
        confirm_required_admission_durability(data_dir).map_err(|error| {
            ERRORS.fetch_add(1, Ordering::Relaxed);
            std::io::Error::other(format!(
                "required Agentgres admission durability is unconfirmed: {error}"
            ))
        })?;
        return Ok(());
    }
    let ack = match h.admit(operation.clone()) {
        Ok(ack) => ack,
        Err(MuxAdmitError::Refused(Refusal::ExpectedAbsentConflict { .. })) => {
            let existing = h.project_exact(record_dir, &object_ref).map_err(|error| {
                ERRORS.fetch_add(1, Ordering::Relaxed);
                error
            })?;
            let Some(existing) = existing else {
                ERRORS.fetch_add(1, Ordering::Relaxed);
                return Err(std::io::Error::other(format!(
                    "Agentgres expected-absent admission for '{record_dir}/{record_id}' lost a conflict but no exact occupant is visible"
                )));
            };
            classify_required_existing(record_dir, record_id, &operation, &existing).map_err(
                |error| {
                    ERRORS.fetch_add(1, Ordering::Relaxed);
                    error
                },
            )?;
            confirm_required_admission_durability(data_dir).map_err(|error| {
                ERRORS.fetch_add(1, Ordering::Relaxed);
                std::io::Error::other(format!(
                    "required Agentgres admission durability is unconfirmed: {error}"
                ))
            })?;
            return Ok(());
        }
        Err(error) => {
            ERRORS.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "substrate-store: admission failed ({error}) record={record_dir}/{record_id}"
            );
            return Err(std::io::Error::other(format!(
                "substrate admission failed: {error}"
            )));
        }
    };
    confirm_required_admission_durability(data_dir).map_err(|error| {
        ERRORS.fetch_add(1, Ordering::Relaxed);
        std::io::Error::other(format!(
            "required Agentgres admission durability is unconfirmed after {} ack: {error}",
            ack.durability
        ))
    })?;
    let exact =
        verify_required_exact(data_dir, record_dir, record_id, record).map_err(|error| {
            ERRORS.fetch_add(1, Ordering::Relaxed);
            error
        })?;
    verify_required_ack(record_dir, record_id, &ack, &exact).map_err(|error| {
        ERRORS.fetch_add(1, Ordering::Relaxed);
        error
    })?;
    ADMITTED.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Strict writer-thread projection for a required-admission key. Callers use
/// the complete operation, admission sequence/head/batch/root, and terminal
/// domain root to verify local evidence before serving it.
pub(crate) fn read_required_exact(
    data_dir: &str,
    record_dir: &str,
    record_id: &str,
) -> std::io::Result<Option<ExactProjection>> {
    validate_required_domain(record_dir)?;
    let Some(handle) = handle(data_dir) else {
        return Err(std::io::Error::other("substrate engine unavailable"));
    };
    handle.project_exact(record_dir, &required_object_ref(record_dir, record_id))
}

/// Verify that a required-admission key contains this exact record and return
/// its strict mux-log proof. Missing keys and foreign same-key occupants are
/// errors; callers never need to reconstruct the private Agentgres operation.
pub(crate) fn verify_required_exact(
    data_dir: &str,
    record_dir: &str,
    record_id: &str,
    record: &Value,
) -> std::io::Result<ExactProjection> {
    verify_required_projection(
        record_dir,
        record_id,
        record,
        read_required_exact(data_dir, record_dir, record_id)?,
    )
}

/// Read path for promoted families: last-write-wins projection served by
/// the writer thread (consistent — never observes a torn tail).
pub(crate) fn read_promoted(data_dir: &str, record_dir: &str) -> Vec<Value> {
    let Some(h) = handle(data_dir) else {
        eprintln!("substrate-store: read with engine unavailable for {record_dir} — returning empty (loud, not fake)");
        return Vec::new();
    };
    match h.project_latest(record_dir) {
        Ok(records) => records,
        Err(e) => {
            eprintln!("substrate-store: projection FAILED for {record_dir}: {e}");
            Vec::new()
        }
    }
}

/// Dual-write soak for NOT-yet-promoted families (opt-in). Runs after the
/// legacy write succeeded; never fails the caller.
pub(crate) fn dual_write(data_dir: &str, record_dir: &str, record_id: &str, record: &Value) {
    if is_promoted(record_dir) || !soak_enabled() {
        return;
    }
    if !soak_domains().iter().any(|d| d == record_dir) {
        return;
    }
    let Some(h) = handle(data_dir) else { return };
    match h.admit(build_op(record_dir, record_id, record)) {
        Ok(_) => {
            ADMITTED.fetch_add(1, Ordering::Relaxed);
        }
        Err(error) => {
            ERRORS.fetch_add(1, Ordering::Relaxed);
            eprintln!("substrate-store: soak dual-write failed ({error}) record={record_dir}/{record_id} — legacy path unaffected");
        }
    }
}

/// GET /v1/hypervisor/substrate/status — engine truth posture: promoted
/// families, per-domain roots/seq, backfill and admission counters, soak
/// configuration, and residual legacy file counts (inert history).
pub(crate) async fn handle_substrate_status(
    State(st): State<Arc<super::DaemonState>>,
) -> Json<Value> {
    let dir = engine_dir(&st.data_dir);
    let mut engine_domains = json!({});
    let mut engine_open_error = matches!(HANDLE.get(), Some(None))
        .then(|| "substrate engine unavailable after initialization failure".to_string());
    let mut engine_recovery = Value::Null;
    let snapshot = match HANDLE.get() {
        Some(Some(handle)) => handle.status_snapshot(),
        Some(None) => MuxEngine::inspect(&dir),
        None => MuxEngine::inspect(&dir),
    };
    match snapshot {
        Ok(snapshot) => {
            engine_recovery = serde_json::to_value(&snapshot.recovery).unwrap_or_else(
                |error| json!({"outcome": "status_encoding_failed", "detail": error.to_string()}),
            );
            if !snapshot.domains.is_empty() {
                let mut m = serde_json::Map::new();
                for (domain, state) in snapshot.domains {
                    m.insert(
                        domain,
                        json!({
                            "root": state.root,
                            "admitted_seq": state.next_seq,
                        }),
                    );
                }
                engine_domains = Value::Object(m);
            }
        }
        Err(error) => {
            engine_open_error = Some(match engine_open_error {
                Some(initialization_error) => {
                    format!("{initialization_error}; status inspection failed: {error}")
                }
                None => error.to_string(),
            })
        }
    }
    let residual_legacy: Value = PROMOTED_DOMAINS
        .iter()
        .map(|d| {
            let n = std::fs::read_dir(std::path::Path::new(&st.data_dir).join(d))
                .map(|it| it.flatten().count())
                .unwrap_or(0);
            (d.to_string(), json!(n))
        })
        .collect::<serde_json::Map<String, Value>>()
        .into();
    Json(json!({
        "schema_version": "ioi.hypervisor.substrate-status.v1",
        "promoted_domains": PROMOTED_DOMAINS,
        "required_admission_domains": REQUIRED_ADMISSION_DOMAINS,
        "required_admission_durability": "explicit muxlog file sync plus substrate-directory sync after every fresh or exact replay; a caller intent may clear only after both succeed",
        "mode": "engine_truth for promoted domains; mandatory admission evidence for required-admission domains whose owner-plane files remain read truth until promotion",
        "engine_dir": dir.display().to_string(),
        "engine_domains": engine_domains,
        "engine_open_error": engine_open_error,
        "engine_recovery": engine_recovery,
        "admitted": ADMITTED.load(Ordering::Relaxed),
        "errors": ERRORS.load(Ordering::Relaxed),
        "backfilled": BACKFILLED.load(Ordering::Relaxed),
        "residual_legacy_files": residual_legacy,
        "residual_note": "legacy JSON files for promoted domains are inert backfilled history, no longer read or written",
        "soak": {
            "enabled": soak_enabled(),
            "domains": soak_domains(),
            "enable_env": "IOI_SUBSTRATE_DUAL_WRITE=1 + IOI_SUBSTRATE_DUAL_WRITE_DOMAINS=<family,...>",
            "parity_tool": "substrate-parity; promotion bar: diverged==0 && extra==0 && missing==0",
        },
        "replication": {
            "configured_replicas": replica_addrs(),
            "declared_failure_independent": std::env::var("IOI_SUBSTRATE_REPLICA_INDEPENDENT").map(|v| v == "1").unwrap_or(false),
            "ack_quorum_env": std::env::var("IOI_SUBSTRATE_ACK_QUORUM").ok(),
            "async_flush_opt_in": std::env::var("IOI_SUBSTRATE_ASYNC_FLUSH").map(|v| v == "1").unwrap_or(false),
            "posture": "default device_flush sync; replicated-ack + async flush is opt-in and fail-safes to per-batch sync when no replica connects; quorum_replicated requires declared failure-independent peers (never same-host)",
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED_DOMAIN: &str = "autonomous-system-genesis-registry";
    const REQUIRED_ID: &str =
        "asg_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CONSUMPTION_DOMAIN: &str = "autonomous-system-genesis-authority-consumptions";

    fn required_record() -> Value {
        json!({
            "admission_id": format!("system-genesis-admission://{REQUIRED_ID}"),
            "at": "2026-07-19T12:00:00Z",
            "payload": {"kind": "genesis"}
        })
    }

    fn exact_projection(operation: Operation) -> ExactProjection {
        ExactProjection {
            operation,
            seq: 7,
            head: "sha256:head".to_string(),
            admission_batch_seq: 3,
            admission_root: "sha256:admission-root".to_string(),
            terminal_root: "sha256:terminal-root".to_string(),
        }
    }

    #[test]
    fn backfill_failure_prevents_writer_start_and_requires_reopen() {
        let data_dir = std::env::temp_dir().join(format!(
            "ioi-substrate-backfill-failure-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let legacy = data_dir.join(PROMOTED_DOMAINS[0]);
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(
            legacy.join("receipt.json"),
            serde_json::to_vec(&json!({
                "receipt_id": "receipt://backfill-failure",
                "at": "2026-07-19T12:00:00Z"
            }))
            .unwrap(),
        )
        .unwrap();
        let engine = MuxEngine::open(&engine_dir(data_dir.to_str().unwrap()), true).unwrap();
        let initialized = initialize_handle_with(
            data_dir.to_str().unwrap(),
            engine,
            Vec::new(),
            false,
            |engine, root| {
                backfill_domain_with(engine, root, PROMOTED_DOMAINS[0], |_engine, _operations| {
                    Err(std::io::Error::other(
                        "test-forced backfill durability uncertainty",
                    ))
                })
                .map(|_| ())
            },
        );
        assert!(
            initialized.is_none(),
            "a failed backfill must not start the writer"
        );

        let reopened = MuxEngine::open(&engine_dir(data_dir.to_str().unwrap()), true).unwrap();
        assert_eq!(reopened.domain_next_seq(PROMOTED_DOMAINS[0]), 0);
        assert_eq!(reopened.log_len().unwrap(), 0);
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[test]
    fn required_projection_verifier_owns_complete_expected_absent_operation() {
        let record = required_record();
        let operation = build_required_op(REQUIRED_DOMAIN, REQUIRED_ID, &record);
        assert!(operation.expected_absent);
        assert_eq!(operation.expected_head, None);
        assert_eq!(
            operation.object_ref,
            format!("agentgres://{REQUIRED_DOMAIN}/{REQUIRED_ID}")
        );
        assert_eq!(operation.op_kind, format!("{REQUIRED_DOMAIN}.persist"));
        assert_eq!(operation.idem_key, REQUIRED_ID);
        assert_eq!(operation.payload, record);

        let exact = exact_projection(operation);
        assert_eq!(
            verify_required_projection(
                REQUIRED_DOMAIN,
                REQUIRED_ID,
                &required_record(),
                Some(exact.clone())
            )
            .unwrap(),
            exact
        );

        let missing =
            verify_required_projection(REQUIRED_DOMAIN, REQUIRED_ID, &required_record(), None)
                .unwrap_err();
        assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);

        let mut foreign = exact;
        foreign.operation.expected_absent = false;
        let conflict = verify_required_projection(
            REQUIRED_DOMAIN,
            REQUIRED_ID,
            &required_record(),
            Some(foreign),
        )
        .unwrap_err();
        assert_eq!(conflict.kind(), std::io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn required_projection_recovery_validates_before_exposing_payload() {
        let record = required_record();
        let exact = exact_projection(build_required_op(REQUIRED_DOMAIN, REQUIRED_ID, &record));
        assert_eq!(
            validate_required_exact_projection(REQUIRED_DOMAIN, REQUIRED_ID, exact).unwrap(),
            record
        );

        let mut foreign = exact_projection(build_required_op(
            REQUIRED_DOMAIN,
            REQUIRED_ID,
            &required_record(),
        ));
        foreign.operation.payload["admission_id"] =
            json!("system-genesis-admission://asg_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert_eq!(
            validate_required_exact_projection(REQUIRED_DOMAIN, REQUIRED_ID, foreign)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn wallet_consumption_required_identity_binds_canonical_key_to_receipt_bytes() {
        let consumption_id = [0xabu8; 32];
        let record_id = format!("asgc_{}", hex::encode(consumption_id));
        let record = json!({
            "schema_version": 1,
            "consumption_id": consumption_id,
        });
        assert!(REQUIRED_ADMISSION_DOMAINS.contains(&CONSUMPTION_DOMAIN));
        validate_required_domain(CONSUMPTION_DOMAIN).unwrap();
        validate_required_identity(CONSUMPTION_DOMAIN, &record_id, &record).unwrap();

        let uppercase = format!("asgc_{}", hex::encode_upper(consumption_id));
        assert_eq!(
            validate_required_identity(CONSUMPTION_DOMAIN, &uppercase, &record)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        let mismatched = format!("asgc_{}", "cd".repeat(32));
        assert_eq!(
            validate_required_identity(CONSUMPTION_DOMAIN, &mismatched, &record)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            validate_required_identity(
                CONSUMPTION_DOMAIN,
                &record_id,
                &json!({"consumption_id": vec![0xabu8; 31]})
            )
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn sequence_zero_required_identities_bind_every_agentgres_key() {
        let materialization_hash = "11".repeat(32);
        let materialization_id = format!("aszm_{materialization_hash}");
        validate_required_identity(
            "autonomous-system-sequence-zero-materializations",
            &materialization_id,
            &json!({
                "materialization_id": format!(
                    "system-materialization://sequence-zero/sha256:{materialization_hash}"
                )
            }),
        )
        .unwrap();

        let receipt_id = format!("aszmr_{}", "22".repeat(32));
        validate_required_identity(
            "autonomous-system-sequence-zero-materialization-receipts",
            &receipt_id,
            &json!({"receipt_ref": format!("receipt://{receipt_id}")}),
        )
        .unwrap();

        let component_hash = "33".repeat(32);
        let component_id = format!("aszcr_{component_hash}");
        validate_required_identity(
            "autonomous-system-sequence-zero-component-registries",
            &component_id,
            &json!({
                "component_registry_ref": format!(
                    "agentgres://object-set/autonomous-system-components/sha256:{component_hash}"
                )
            }),
        )
        .unwrap();

        for (family, record_id, record) in [
            (
                "autonomous-system-sequence-zero-materializations",
                format!("aszm_{}", "AA".repeat(32)),
                json!({
                    "materialization_id": format!(
                        "system-materialization://sequence-zero/sha256:{}",
                        "AA".repeat(32)
                    )
                }),
            ),
            (
                "autonomous-system-sequence-zero-component-registries",
                format!("aszcr_{}", "44".repeat(32)),
                json!({
                    "component_registry_ref": format!(
                        "agentgres://object-set/autonomous-system-components/sha256:{}",
                        "55".repeat(32)
                    )
                }),
            ),
        ] {
            assert_eq!(
                validate_required_identity(family, &record_id, &record)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput,
            );
        }
    }

    #[test]
    fn lifecycle_required_domains_bind_all_family_specific_keys() {
        let hash = "44".repeat(32);
        for (family, prefix, field) in [
            (
                "autonomous-system-deployment-profile-revisions",
                "asdpr_",
                "deployment_profile_root",
            ),
            (
                "autonomous-system-lifecycle-proposals",
                "aslp_",
                "proposal_root",
            ),
            (
                "autonomous-system-lifecycle-authority-decisions",
                "aslad_",
                "decision_root",
            ),
            (
                "autonomous-system-activation-states",
                "asls_",
                "activation_state_root",
            ),
            (
                "autonomous-system-active-profile-sets",
                "asaps_",
                "active_profile_set_root",
            ),
            (
                "autonomous-system-home-bindings",
                "ashdb_",
                "home_domain_binding_root",
            ),
            (
                "autonomous-system-operation-log-revisions",
                "asol_",
                "operation_log_root",
            ),
            ("autonomous-system-chain-revisions", "asc_", "chain_root"),
        ] {
            let id = format!("{prefix}{hash}");
            assert_eq!(
                validate_required_identity(family, &id, &json!({field:format!("sha256:{hash}")}))
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
            assert!(validate_required_identity(
                family,
                &format!("{prefix}{}", "55".repeat(32)),
                &json!({field:format!("sha256:{hash}")})
            )
            .is_err());
        }
        let evidence_id = format!("aslae_{hash}");
        assert!(validate_required_identity(
            "autonomous-system-lifecycle-authority-evidence",
            &evidence_id,
            &json!({"authority_evidence_ref":format!("system-lifecycle-authority-evidence://{evidence_id}")}),
        )
        .is_err());
        let consumption_id = [0x66u8; 32];
        validate_required_identity(
            "autonomous-system-lifecycle-authority-consumptions",
            &format!("aslac_{}", hex::encode(consumption_id)),
            &json!({"consumption_id":consumption_id}),
        )
        .unwrap();
        for (family, prefix, domain, identity) in [
            (
                "autonomous-system-lifecycle-transitions",
                "aslt_",
                "ioi.autonomous-system-lifecycle-transition-jcs-sha256.v1",
                "lifecycle_transition_id",
            ),
            (
                "autonomous-system-initialize-transition-receipts",
                "asltr_",
                "ioi.lifecycle-transition-receipt-artifact-jcs-sha256.v1",
                "receipt_ref",
            ),
            (
                "autonomous-system-activation-receipts",
                "asar_",
                "ioi.autonomous-system-activation-receipt-artifact-jcs-sha256.v1",
                "receipt_ref",
            ),
        ] {
            let record = json!({identity:"ref://exact"});
            let root = sha2::Sha256::digest(
                serde_jcs::to_vec(&json!({"domain":domain,"artifact":record})).unwrap(),
            );
            validate_required_identity(family, &format!("{prefix}{}", hex::encode(root)), &record)
                .unwrap();
        }
    }
}
