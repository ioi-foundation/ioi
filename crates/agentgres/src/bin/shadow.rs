//! Shadow-route real daemon provider receipts through the substrate engine.
//!
//! Migration doctrine (master guide): shadow first — represent real daemon
//! truth in the new substrate, compare, THEN promote. This binary ingests
//! `ioi.hypervisor.provider-receipt.v1` records the daemon has already
//! persisted (JSON files under <data>/provider-receipts/), admits them as
//! operations, and proves determinism by running the full ingest twice and
//! comparing final roots. It never mutates daemon state — read-only shadow.
//!
//! Canonical ingest order: (`at`, `receipt_id`) ascending. Directory
//! iteration order is nondeterministic; a shadow needs a declared order to
//! be replayable. Live promotion will use admission arrival order instead.

use agentgres::{parse_rfc3339_ms, AgentgresSubstrate, Operation, SubstrateEngine};
use std::path::{Path, PathBuf};
use std::time::Instant;

struct ShadowInput {
    receipt_id: String,
    at: String,
    recorded_at_ms: u64,
    payload: serde_json::Value,
}

fn load_receipts(dir: &Path) -> (Vec<ShadowInput>, u64) {
    let mut inputs = Vec::new();
    let mut parse_failures = 0u64;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (inputs, 0);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            parse_failures += 1;
            continue;
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            parse_failures += 1;
            continue;
        };
        let receipt_id = v
            .get("receipt_id")
            .and_then(|x| x.as_str())
            .unwrap_or_else(|| {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
            })
            .to_string();
        let at = v
            .get("at")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let recorded_at_ms = parse_rfc3339_ms(&at);
        inputs.push(ShadowInput {
            receipt_id,
            at,
            recorded_at_ms,
            payload: v,
        });
    }
    // Canonical ingest order: (at, receipt_id).
    inputs.sort_by(|a, b| {
        (a.at.as_str(), a.receipt_id.as_str()).cmp(&(b.at.as_str(), b.receipt_id.as_str()))
    });
    (inputs, parse_failures)
}

fn ingest(
    dir: &Path,
    inputs: &[ShadowInput],
    batch: usize,
    sync: bool,
) -> std::io::Result<(String, u64, f64)> {
    let mut engine = SubstrateEngine::open(dir, sync)?;
    let started = Instant::now();
    let mut admitted = 0u64;
    for chunk in inputs.chunks(batch) {
        let ops: Vec<Operation> = chunk
            .iter()
            .map(|r| Operation {
                domain: "provider-receipts".into(),
                object_ref: format!("agentgres://provider-receipt/{}", r.receipt_id),
                op_kind: "provider_receipt.persist".into(),
                expected_head: None,
                expected_absent: false,
                payload: r.payload.clone(),
                recorded_at_ms: r.recorded_at_ms,
                idem_key: r.receipt_id.clone(),
            })
            .collect();
        for res in engine.admit_batch(ops)? {
            if res.is_ok() {
                admitted += 1;
            }
        }
    }
    let secs = started.elapsed().as_secs_f64();
    Ok((engine.current_root().clone(), admitted, secs))
}

fn main() -> std::io::Result<()> {
    let receipts_dir: PathBuf = std::env::var("RECEIPTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            PathBuf::from(home).join(".ioi/hypervisor/data/provider-receipts")
        });
    let out: PathBuf = std::env::var("DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("agentgres-substrate-shadow"));
    let batch: usize = std::env::var("BATCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512);
    let sync = std::env::var("SYNC").map(|v| v != "0").unwrap_or(true);
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out)?;

    let (inputs, parse_failures) = load_receipts(&receipts_dir);
    if inputs.is_empty() {
        eprintln!(
            "shadow: no receipts found at {} — nothing shadowed (named refusal, not a fake pass)",
            receipts_dir.display()
        );
        std::process::exit(2);
    }

    // Run 1 and Run 2: identical canonical ingest into fresh engines.
    let (root1, admitted1, secs1) = ingest(&out.join("run1"), &inputs, batch, sync)?;
    let (root2, admitted2, _) = ingest(&out.join("run2"), &inputs, batch, sync)?;
    let deterministic = root1 == root2 && admitted1 == admitted2;

    // Recovery: reopen run1, root must match.
    let recovered = SubstrateEngine::open(&out.join("run1"), sync)?;
    let recovery_match = recovered.current_root() == &root1;

    // Shadow-vs-daemon comparison: every parsed daemon receipt admitted,
    // each as its own object head.
    let coverage_complete = admitted1 == inputs.len() as u64;

    let report = serde_json::json!({
        "harness": "agentgres-substrate-shadow v0 (provider-receipts)",
        "source": receipts_dir.display().to_string(),
        "receipts_found": inputs.len(),
        "parse_failures": parse_failures,
        "admitted": admitted1,
        "coverage_complete": coverage_complete,
        "ingest_secs": secs1,
        "ingest_rate_ops_s": admitted1 as f64 / secs1.max(1e-9),
        "final_root": root1,
        "double_run_deterministic": deterministic,
        "recovery_root_match": recovery_match,
        "canonical_order": "(at, receipt_id) ascending — declared shadow order; live promotion uses admission arrival order",
        "mutates_daemon_state": false,
    });
    let report_path = out.join("shadow-report.json");
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report).unwrap())?;
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    eprintln!("report: {}", report_path.display());
    if !(deterministic && recovery_match && coverage_complete) {
        std::process::exit(1);
    }
    Ok(())
}
