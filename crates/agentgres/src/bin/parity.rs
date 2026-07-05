//! Parity comparator: legacy JSON record dir vs substrate engine log.
//!
//! The compare gate of the migration doctrine (shadow → COMPARE → promote).
//! For a record family, this proves the engine carries byte-equivalent
//! payloads to the daemon's legacy per-file JSON store:
//!
//!   diverged == 0 and extra == 0   -> engine payloads are faithful
//!   missing  == 0                  -> engine coverage is complete
//!
//! `missing` counts legacy records the engine has not (yet) seen — nonzero
//! is EXPECTED for records persisted before dual-write was enabled and
//! shrinks to zero after a backfill ingest; it is reported, not failed.
//! `diverged`/`extra` nonzero always fails: payload mismatch or phantom
//! engine records mean the shadow cannot be promoted.
//!
//! Works against either engine layout:
//!   - a mux log (`muxlog.bin`, DOMAIN filter — the live dual-write shape)
//!   - a single-domain log (`oplog.bin` — the offline shadow shape)

use agentgres::mux::{MuxEngine, MuxLogFrame};
use agentgres::{AgentgresSubstrate, LogFrame, SubstrateEngine};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn payload_hash(v: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(v).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(&bytes);
    format!("{:x}", h.finalize())
}

fn main() -> std::io::Result<()> {
    let legacy_dir: PathBuf = PathBuf::from(
        std::env::var("LEGACY_DIR").expect("LEGACY_DIR (daemon record dir of JSON files) required"),
    );
    let engine_dir: PathBuf = PathBuf::from(
        std::env::var("ENGINE_DIR").expect("ENGINE_DIR (substrate engine dir) required"),
    );
    let domain = std::env::var("DOMAIN").unwrap_or_else(|_| "provider-receipts".into());

    // Legacy side: record_id -> payload hash.
    let mut legacy: BTreeMap<String, String> = BTreeMap::new();
    for entry in std::fs::read_dir(&legacy_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path)?) else {
            continue;
        };
        let id = v
            .get("receipt_id")
            .or_else(|| v.get("id"))
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| {
                path.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown").to_string()
            });
        legacy.insert(id, payload_hash(&v));
    }

    // Engine side: object_ref -> payload hash of the LAST admitted write.
    let mut engine: BTreeMap<String, String> = BTreeMap::new();
    let mut collect = |object_ref: &str, payload: &serde_json::Value| {
        // object_ref shape: agentgres://<domain>/<record_id> — key by tail.
        let id = object_ref.rsplit('/').next().unwrap_or(object_ref).to_string();
        engine.insert(id, payload_hash(payload));
    };
    if engine_dir.join("muxlog.bin").exists() {
        let e = MuxEngine::open(&engine_dir, false)?;
        e.project_domain(&domain, 0, &mut |f| {
            if let MuxLogFrame::Admitted(rec) = f {
                collect(&rec.op.object_ref, &rec.op.payload);
            }
        })?;
    } else if engine_dir.join("oplog.bin").exists() {
        let e = SubstrateEngine::open(&engine_dir, false)?;
        e.project(0, &mut |f| {
            if let LogFrame::Admitted(rec) = f {
                if rec.op.domain == domain {
                    collect(&rec.op.object_ref, &rec.op.payload);
                }
            }
        })?;
    } else {
        eprintln!("parity: no engine log at {} (named refusal)", engine_dir.display());
        std::process::exit(2);
    }

    let mut diverged: Vec<String> = Vec::new();
    let mut missing = 0u64;
    for (id, lhash) in &legacy {
        match engine.get(id) {
            Some(ehash) if ehash == lhash => {}
            Some(_) => diverged.push(id.clone()),
            None => missing += 1,
        }
    }
    let extra: Vec<String> = engine.keys().filter(|k| !legacy.contains_key(*k)).cloned().collect();

    let faithful = diverged.is_empty() && extra.is_empty();
    let report = serde_json::json!({
        "harness": "agentgres-substrate-parity v0",
        "domain": domain,
        "legacy_dir": legacy_dir.display().to_string(),
        "engine_dir": engine_dir.display().to_string(),
        "legacy_records": legacy.len(),
        "engine_records": engine.len(),
        "matched": legacy.len() as u64 - missing - diverged.len() as u64,
        "missing_from_engine": missing,
        "missing_note": "expected nonzero before backfill; must be 0 before promotion",
        "diverged": diverged,
        "extra_in_engine": extra,
        "payload_faithful": faithful,
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    std::process::exit(if faithful { 0 } else { 1 });
}
