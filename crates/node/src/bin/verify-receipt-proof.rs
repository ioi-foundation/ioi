//! Offline verifier for portable ReceiptProofBundle v1 exports.
//!
//! This command performs no network access. A locally trusted issuer key set,
//! signed bounded-freshness revocation snapshot, and trusted time are mandatory.

use anyhow::{anyhow, Context, Result};
use ioi_types::app::generated::architecture_contracts::{
    AuthorityKeySetV1, AuthorityRevocationSnapshotV1, ReceiptProofBundleV1,
};
use ioi_validator::portable_receipt_proof::{
    verify_receipt_proof_bundle_v1, ReceiptProofVerificationContext,
};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::{env, fs, path::Path};

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|argument| argument == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn required(args: &[String], name: &str) -> Result<String> {
    flag(args, name).ok_or_else(|| anyhow!("missing required {name}"))
}

fn read_json<T: DeserializeOwned>(path: &str) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", Path::new(path).display()))?;
    serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parse {} as closed portable receipt-proof JSON",
            Path::new(path).display()
        )
    })
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let bundle: ReceiptProofBundleV1 = read_json(&required(&args, "--bundle")?)?;
    let key_set: AuthorityKeySetV1 = read_json(&required(&args, "--key-set")?)?;
    let snapshot: AuthorityRevocationSnapshotV1 =
        read_json(&required(&args, "--revocation-snapshot")?)?;
    let now = required(&args, "--now")?
        .parse::<u64>()
        .context("--now must be Unix seconds")?;
    let max_staleness = flag(&args, "--max-snapshot-staleness-seconds")
        .unwrap_or_else(|| "300".to_string())
        .parse::<u64>()
        .context("--max-snapshot-staleness-seconds must be an integer")?;

    match verify_receipt_proof_bundle_v1(
        &bundle,
        &ReceiptProofVerificationContext {
            now,
            max_snapshot_staleness_seconds: max_staleness,
            key_set: &key_set,
            revocation_snapshot: &snapshot,
        },
    ) {
        Ok(()) => {
            println!(
                "{}",
                json!({
                    "ok": true,
                    "bundle_id": bundle.bundle_id,
                    "receipt_id": bundle.receipt.get("receipt_id"),
                    "receipt_body_hash": bundle.receipt_body_hash,
                    "leaf_index": bundle.leaf.leaf_index,
                    "checkpoint_id": bundle.checkpoint.get("checkpoint_id"),
                    "verification_mode": "offline_local_key_set",
                    "accumulator_algorithm": "ioi.receipt-hash-chain-jcs-sha256.v1",
                    "proof_complexity": "linear"
                })
            );
            Ok(())
        }
        Err(error) => {
            println!(
                "{}",
                json!({
                    "ok": false,
                    "error": { "code": error.code.as_str(), "detail": error.detail }
                })
            );
            Err(anyhow!("portable receipt proof verification failed"))
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
