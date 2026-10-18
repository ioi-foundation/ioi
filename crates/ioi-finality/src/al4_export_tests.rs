//! NET's AL4 export check: the bundles this crate EMITS must be accepted by
//! NET's frozen AL4 verifier v0.3 (`plans/ioi-network/design/AL4-verifier`,
//! `VERIFIER-v0.3-FROZEN.sha256`).
//!
//! `testdata/al4-export/cases.json` was written by NET's
//! `records/port/al4-receipt-root/red/gen_al4_export_cases.py` from the frozen
//! `al4lib.py` and NET's own vector POS-L2-GENESIS. Nothing in it was computed by
//! this crate. Each case names the receipts a template carries and what the
//! frozen verifier requires the emitted bundle to commit:
//! - `receipt_root` = `ioi.receipt-merkle-rfc9162-jcs-sha256.v1`;
//! - each `body_hash` = D(E).
//!
//! When `IOI_FINALITY_AL4_EXPORT_DIR` is set, every emitted bundle is first
//! written to `<dir>/<case>.json`, so the frozen `verify_export.py` judges this
//! crate's own bytes. This module re-implements nothing of the verifier.

use super::*;
use crate::tests::{fixture, successor_of, SINGLE_AUTHORITY_TEMPLATE};
use std::fs;
use std::path::PathBuf;

const CASES: &str = "testdata/al4-export/cases.json";

/// sha256 of `CASES` as NET's generator wrote it.
const CASES_SHA256: &str = "83abfd069aaf5182ec256e843ce0306f1c3e12107fc5e78cb8d32bf9784aff2d";

const EXPORT_DIR: &str = "IOI_FINALITY_AL4_EXPORT_DIR";

const ISSUER_KEY_ID: &str = "key://acme/finality/1";

/// The case names, one test each.
const CASE_NAMES: [&str; 5] = [
    "genesis-1",
    "genesis-3",
    "genesis-5",
    "genesis-unknown-members",
    "successor-2",
];

fn cases() -> Vec<Value> {
    let bytes = fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CASES))
        .expect("cases.json readable");
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        CASES_SHA256,
        "cases.json digest"
    );
    let document: Value = serde_json::from_slice(&bytes).expect("cases.json parses");
    assert_eq!(
        document["algorithm"],
        json!("ioi.receipt-merkle-rfc9162-jcs-sha256.v1")
    );
    document["cases"].as_array().expect("cases").clone()
}

fn named_case(name: &str) -> Value {
    cases()
        .into_iter()
        .find(|case| case["name"] == json!(name))
        .unwrap_or_else(|| panic!("{name} is not a case"))
}

fn placeholder_hash() -> Value {
    Value::String(format!("sha256:{}", "55".repeat(32)))
}

/// The registered single-authority template carrying exactly the case's
/// receipts, in the case's order, and one operation per receipt sequence. The
/// `body_hash` values are placeholders, because `prepare_checkpoint` writes every
/// derived field. When the case names a predecessor, the template is the
/// successor of that case's emitted bundle.
fn template(case: &Value) -> Value {
    let mut template = fixture(SINGLE_AUTHORITY_TEMPLATE);
    if let Some(predecessor) = case["predecessor"].as_str() {
        template = successor_of(&emitted(&named_case(predecessor)), template, "2");
    }
    let receipts = case["receipts"].as_array().expect("case receipts");
    template["operations"] = Value::Array(
        receipts
            .iter()
            .map(|receipt| {
                json!({
                    "sequence": receipt["sequence"],
                    "body": {"op": "set", "key": "item", "sequence": receipt["sequence"]},
                    "body_hash": placeholder_hash(),
                })
            })
            .collect(),
    );
    template["receipts"] = Value::Array(
        receipts
            .iter()
            .map(|receipt| {
                json!({
                    "sequence": receipt["sequence"],
                    "body": receipt["body"],
                    "body_hash": placeholder_hash(),
                })
            })
            .collect(),
    );
    template
}

fn emitted(case: &Value) -> Value {
    let issuer = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");
    emit_single_authority(template(case), ISSUER_KEY_ID, &issuer)
        .unwrap_or_else(|error| panic!("{}: emits: {error}", case["name"]))
}

/// One case end to end. The steps run in this order:
/// 1. emit the case;
/// 2. export its bytes (when asked);
/// 3. hold the emission to what NET's frozen verifier requires.
fn check(name: &str) {
    let case = named_case(name);
    let bundle = emitted(&case);
    if let Some(dir) = std::env::var_os(EXPORT_DIR) {
        let dir = PathBuf::from(dir);
        fs::create_dir_all(&dir).expect("export directory");
        fs::write(
            dir.join(format!("{name}.json")),
            serde_json::to_vec(&bundle).expect("bundle JSON"),
        )
        .expect("exported bundle written");
    }
    verify_bundle(&bundle)
        .unwrap_or_else(|error| panic!("{name}: the emitted bundle verifies in-crate: {error}"));
    assert_eq!(
        bundle["checkpoint"]["receipt_root"], case["expected_receipt_root"],
        "{name}: the emitted receipt_root is NET's ioi.receipt-merkle-rfc9162-jcs-sha256.v1 root"
    );
    let carried = bundle["receipts"].as_array().expect("emitted receipts");
    let expected = case["receipts"].as_array().expect("case receipts");
    assert_eq!(carried.len(), expected.len(), "{name}: receipt count");
    for (index, (receipt, want)) in carried.iter().zip(expected).enumerate() {
        assert_eq!(
            receipt["sequence"], want["sequence"],
            "{name}[{index}]: carried order is never re-sorted"
        );
        assert_eq!(
            receipt["body"], want["body"],
            "{name}[{index}]: the body is carried unchanged"
        );
        assert_eq!(
            receipt["body_hash"], case["expected_body_hashes"][index],
            "{name}[{index}]: the emitted body_hash is D(E)"
        );
    }
}

#[test]
fn al4_export_genesis_1() {
    check("genesis-1");
}

#[test]
fn al4_export_genesis_3() {
    check("genesis-3");
}

#[test]
fn al4_export_genesis_5() {
    check("genesis-5");
}

#[test]
fn al4_export_genesis_unknown_members() {
    check("genesis-unknown-members");
}

#[test]
fn al4_export_successor_2() {
    check("successor-2");
}

#[test]
fn al4_export_every_case_has_a_test() {
    let names = cases()
        .iter()
        .map(|case| case["name"].as_str().expect("name").to_owned())
        .collect::<BTreeSet<_>>();
    let tested = CASE_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(names, tested);
}
