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

use agentgres::mux::{spawn_mux_writer_cfg, MuxEngine, MuxHandle, WriterConfig};
use agentgres::replica::ReplicaLink;
use agentgres::{parse_rfc3339_ms, Operation};
use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

/// Families whose truth is the substrate engine. Extend only after the
/// candidate family has passed a dual-write soak with clean parity.
pub(crate) const PROMOTED_DOMAINS: &[&str] = &["provider-receipts"];

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
        .filter(|s| !s.is_empty() && !is_promoted(s))
        .collect()
}

fn engine_dir(data_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(data_dir).join("substrate")
}

fn build_op(record_dir: &str, record_id: &str, record: &Value) -> Operation {
    Operation {
        domain: record_dir.to_string(),
        object_ref: format!("agentgres://{record_dir}/{record_id}"),
        op_kind: format!("{record_dir}.persist"),
        expected_head: None,
        payload: record.clone(),
        recorded_at_ms: record
            .get("at")
            .and_then(|v| v.as_str())
            .map(parse_rfc3339_ms)
            .unwrap_or(0),
        idem_key: record_id.to_string(),
    }
}

/// One-time idempotent backfill of a promoted family's legacy JSON dir into
/// the engine, in canonical `(at, record_id)` order. Legacy files are left
/// on disk as inert history; the engine is truth from here on.
fn backfill_domain(engine: &mut MuxEngine, data_dir: &str, domain: &str) {
    let legacy = std::path::Path::new(data_dir).join(domain);
    let Ok(entries) = std::fs::read_dir(&legacy) else {
        return;
    };
    let mut pending: Vec<(String, String, Value)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        let id = v
            .get("receipt_id")
            .or_else(|| v.get("id"))
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            });
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
        return;
    }
    pending.sort_by(|a, b| (a.0.as_str(), a.1.as_str()).cmp(&(b.0.as_str(), b.1.as_str())));
    let mut done = 0u64;
    for chunk in pending.chunks(512) {
        let ops: Vec<Operation> = chunk
            .iter()
            .map(|(_, id, v)| build_op(domain, id, v))
            .collect();
        match engine.admit_batch(ops) {
            Ok(results) => done += results.iter().filter(|r| r.is_ok()).count() as u64,
            Err(e) => {
                eprintln!("substrate-store: backfill batch FAILED for {domain}: {e}");
                break;
            }
        }
    }
    BACKFILLED.fetch_add(done, Ordering::Relaxed);
    eprintln!(
        "substrate-store: backfilled {done} legacy {domain} records into the substrate engine"
    );
}

fn replica_addrs() -> Vec<String> {
    std::env::var("IOI_SUBSTRATE_REPLICA_ADDRS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
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
            Ok(mut engine) => {
                for domain in PROMOTED_DOMAINS {
                    backfill_domain(&mut engine, data_dir, domain);
                }
                let mut replicas = Vec::new();
                if !addrs.is_empty() {
                    let independent = std::env::var("IOI_SUBSTRATE_REPLICA_INDEPENDENT")
                        .map(|v| v == "1")
                        .unwrap_or(false);
                    let epoch = engine.current_epoch();
                    let len = engine.log_len().unwrap_or(0);
                    let log_path = engine_dir(data_dir).join("muxlog.bin");
                    for a in &addrs {
                        match ReplicaLink::connect(a.as_str(), independent, epoch, &log_path, len) {
                            Ok(l) => replicas.push(l),
                            Err(e) => eprintln!(
                                "substrate-store: replica {a} unreachable ({e}) — continuing without it"
                            ),
                        }
                    }
                }
                let ack_quorum = std::env::var("IOI_SUBSTRATE_ACK_QUORUM")
                    .ok()
                    .and_then(|v| v.parse().ok())
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
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(200)
                } else {
                    0
                };
                let (handle, _writer) = spawn_mux_writer_cfg(
                    engine,
                    WriterConfig { max_batch: 1024, replicas, ack_quorum, flush_every_batches, background_flush_ms },
                );
                Some(handle)
            }
            Err(e) => {
                eprintln!("substrate-store: engine open FAILED ({e}) — promoted-family persistence will fail loudly");
                None
            }
        }
    })
}

/// Write path for promoted families: the engine IS truth; failure is a
/// loud error to the caller, never a silent drop (INV-14).
pub(crate) fn persist_promoted(
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
        Err(refusal) => {
            ERRORS.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "substrate-store: admission refused ({refusal}) record={record_dir}/{record_id}"
            );
            Err(std::io::Error::other(format!(
                "substrate admission refused: {refusal}"
            )))
        }
    }
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
        Err(refusal) => {
            ERRORS.fetch_add(1, Ordering::Relaxed);
            eprintln!("substrate-store: soak dual-write refused ({refusal}) record={record_dir}/{record_id} — legacy path unaffected");
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
    let mut engine_open_error: Option<String> = None;
    if dir.join("muxlog.bin").exists() {
        match MuxEngine::open(&dir, false) {
            Ok(engine) => {
                let mut m = serde_json::Map::new();
                for d in engine.domains() {
                    m.insert(
                        d.clone(),
                        json!({
                            "root": engine.domain_root(d),
                            "admitted_seq": engine.domain_next_seq(d),
                        }),
                    );
                }
                engine_domains = Value::Object(m);
            }
            Err(e) => engine_open_error = Some(e.to_string()),
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
        "mode": "engine_truth for promoted domains; no legacy write/read for them (no split brain)",
        "engine_dir": dir.display().to_string(),
        "engine_domains": engine_domains,
        "engine_open_error": engine_open_error,
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
