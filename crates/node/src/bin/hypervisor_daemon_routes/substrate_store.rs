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
        _ => unreachable!("required-admission domains are exhaustively matched"),
    }
}

fn validate_required_identity(
    record_dir: &str,
    record_id: &str,
    record: &Value,
) -> std::io::Result<()> {
    if record_dir == "autonomous-system-genesis-authority-consumptions" {
        let Some(encoded_id) = record_id.strip_prefix("asgc_") else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "required Agentgres wallet consumption key must start with 'asgc_'",
            ));
        };
        if encoded_id.len() != 64
            || !encoded_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "required Agentgres wallet consumption key must be 'asgc_' plus 64 lowercase hex characters",
            ));
        }
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
    let (identity_field, expected_identity) = required_identity(record_dir, record_id);
    if record.get(identity_field).and_then(Value::as_str) == Some(expected_identity.as_str()) {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "required Agentgres record '{record_dir}/{record_id}' has a mismatched '{identity_field}' identity"
        ),
    ))
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
    const REQUIRED_ID: &str = "sga_0123456789abcdef";
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
}
