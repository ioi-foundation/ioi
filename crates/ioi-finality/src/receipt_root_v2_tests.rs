//! receipt_root v2 (`ioi.receipt-merkle-rfc9162-jcs-sha256.v1`) and the
//! carried-order rule, reproduced from the AL4 conformance vectors end to end
//! through `prepare_checkpoint` (via `emit_single_authority`) and `verify_bundle`.
//!
//! The vectors in `testdata/receipt-root-v2` are a byte copy of the AL4 vector
//! set (work/al4/vectors/receipt-root-v2/out). Every test checks the copy
//! against its `SHA256SUMS`, and `SHA256SUMS` against the digest the ruling
//! cites, before it reads a vector. Expected values are read from the vector
//! files, never restated here.

use super::*;
use crate::tests::{fixture, signed_bundle, successor_of, v2_template, SINGLE_AUTHORITY_TEMPLATE};
use std::fs;
use std::path::PathBuf;

const VECTOR_DIR: &str = "testdata/receipt-root-v2";

/// sha256 of `testdata/receipt-root-v2/SHA256SUMS`, the manifest the AL4 build
/// plan and the canon draft cite.
const MANIFEST_SHA256: &str = "6fe33c1b0f0bb3897c8bcaa8d41e893150679b12d8e36ab18710621f1db0be67";

const ISSUER_KEY_ID: &str = "key://acme/finality/1";

/// The vectors this module reproduces, one test each (see `vector_test!`).
const REPRODUCED: [&str; 16] = [
    "POS-N1",
    "POS-N2",
    "POS-N3",
    "POS-N5",
    "POS-N7",
    "NEG-REORDERED-ARRAY",
    "NEG-ROOT-OVER-SWAPPED-LEAVES",
    "NEG-SEQUENCE-GAP",
    "NEG-DUPLICATE-SEQUENCE",
    "INV-UNKNOWN-MEMBER",
    "NEG-DROPPED-SIGNATURE",
    "NEG-EMPTY-RANGE",
    "NEG-SEQUENCE-SHIFT",
    "NEG-ODD-NODE-DUPLICATION",
    "INV-URLSAFE-SIGNATURE",
    "INV-KEYIDLESS-COSIGNATURE",
];

fn vector_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(VECTOR_DIR)
        .join(relative)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The copy is byte-identical to the manifest the ruling cites, and every
/// vector file present is listed in it.
fn check_manifest() {
    let manifest = fs::read(vector_path("SHA256SUMS")).expect("SHA256SUMS readable");
    assert_eq!(sha256_hex(&manifest), MANIFEST_SHA256, "SHA256SUMS digest");
    let mut listed = BTreeSet::new();
    for line in String::from_utf8(manifest)
        .expect("SHA256SUMS is UTF-8")
        .lines()
    {
        let (digest, name) = line.split_once("  ").expect("a sha256sum line");
        let bytes = fs::read(vector_path(name)).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(sha256_hex(&bytes), digest, "{name} digest");
        listed.insert(name.to_owned());
    }
    for entry in fs::read_dir(vector_path("vectors")).expect("vectors directory") {
        let name = format!(
            "vectors/{}",
            entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
        );
        assert!(listed.contains(&name), "{name} is not listed in SHA256SUMS");
    }
}

fn read_json(relative: &str) -> Value {
    serde_json::from_slice(&fs::read(vector_path(relative)).expect("vector file readable"))
        .expect("vector file parses")
}

fn index() -> Value {
    check_manifest();
    read_json("index.json")
}

struct Vector {
    id: String,
    raw: Value,
}

impl Vector {
    fn load(id: &str) -> Self {
        let index = index();
        let entry = index["vectors"]
            .as_array()
            .expect("index vectors")
            .iter()
            .find(|entry| entry["id"] == json!(id))
            .unwrap_or_else(|| panic!("{id} is not indexed"));
        let raw = read_json(entry["file"].as_str().expect("indexed file"));
        assert_eq!(raw["id"], json!(id), "{id}: file id");
        assert_eq!(
            raw["expected"], entry["expected"],
            "{id}: index and file agree"
        );
        Self {
            id: id.to_owned(),
            raw,
        }
    }

    fn range(&self) -> (u64, u64) {
        let range = &self.raw["receipt_range"];
        (
            range["first"].as_u64().expect("first"),
            range["last"].as_u64().expect("last"),
        )
    }

    fn receipts(&self) -> Value {
        self.raw["receipts"].clone()
    }

    fn claimed(&self) -> &Value {
        &self.raw["claimed_receipt_root"]
    }

    fn expected(&self) -> &Value {
        &self.raw["expected"]
    }

    fn derived_from(&self) -> Option<Vector> {
        self.raw["derived_from"].as_str().map(Vector::load)
    }
}

fn issuer() -> Ed25519PrivateKey {
    Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key")
}

fn emit(template: Value) -> Result<Value, VerificationError> {
    emit_single_authority(template, ISSUER_KEY_ID, &issuer())
}

fn placeholder_hash() -> Value {
    Value::String(format!("sha256:{}", "55".repeat(32)))
}

fn operations(first: u64, last: u64) -> Value {
    Value::Array(
        (first..=last)
            .map(|sequence| {
                json!({
                    "sequence": sequence,
                    "body": {"op": "set", "key": "item", "sequence": sequence},
                    "body_hash": placeholder_hash(),
                })
            })
            .collect(),
    )
}

/// An emitted genesis checkpoint covering operations and receipts
/// `0..=next_first - 1`. Its receipts are filler DSSE envelopes: a successor's
/// bundle carries only the predecessor's checkpoint, never its receipts.
fn predecessor(next_first: u64) -> Value {
    let envelopes = crate::tests::dsse_envelopes();
    let mut template = v2_template(SINGLE_AUTHORITY_TEMPLATE);
    template["operations"] = operations(0, next_first - 1);
    template["receipts"] = Value::Array(
        (0..next_first)
            .map(|sequence| {
                json!({
                    "sequence": sequence,
                    "body": envelopes[sequence as usize % envelopes.len()].clone(),
                    "body_hash": placeholder_hash(),
                })
            })
            .collect(),
    );
    emit(template).expect("predecessor emits")
}

/// A single-authority template whose operations cover `first..=last` and whose
/// `receipts` are exactly the ones given, in the order given: a genesis
/// checkpoint when `first` is 0, otherwise the successor of an emitted
/// predecessor that ends at `first - 1`.
fn template_over(first: u64, last: u64, receipts: Value) -> Value {
    let mut template = if first == 0 {
        v2_template(SINGLE_AUTHORITY_TEMPLATE)
    } else {
        successor_of(
            &predecessor(first),
            v2_template(SINGLE_AUTHORITY_TEMPLATE),
            "2",
        )
    };
    template["operations"] = operations(first, last);
    template["receipts"] = receipts;
    template
}

/// A conforming emission over a vector's own receipts and range.
fn emitted(vector: &Vector) -> Value {
    let (first, last) = vector.range();
    emit(template_over(first, last, vector.receipts()))
        .unwrap_or_else(|error| panic!("{}: emits: {error}", vector.id))
}

fn rehash_outer(bundle: &mut Value) {
    let outer = hash_value(&without(bundle, &["bundle_hash"]).expect("outer preimage"))
        .expect("outer hash");
    set_text(bundle, "bundle_hash", outer).expect("rewrite unsigned outer hash");
}

/// What a verifier is handed: `base` with the vector's receipts, receipt range
/// and claimed receipt_root in place of its own (an unsigned edit wherever they
/// differ from what `base` committed), and the unsigned outer hash recomputed.
fn carrying(base: &Value, vector: &Vector) -> Value {
    let (first, last) = vector.range();
    let mut bundle = base.clone();
    bundle["receipts"] = vector.receipts();
    bundle["checkpoint"]["receipt_range"] = json!({"first": first, "last": last});
    bundle["checkpoint"]["receipt_root"] = vector.claimed().clone();
    rehash_outer(&mut bundle);
    bundle
}

/// The reference refusal name (index.json `reference_error_precedence`) a
/// refusal reports. `root_mismatch` is `verify_bundle`'s unchanged
/// "receipt root" comparison.
fn refusal(error: &VerificationError) -> String {
    match error {
        VerificationError::Binding(label) if label == "receipt root" => "root_mismatch".into(),
        VerificationError::Binding(label) => match label
            .strip_prefix("receipt_root ")
            .and_then(|rest| rest.split_once(':'))
        {
            Some((reason, _)) => reason.to_owned(),
            None => format!("other binding: {label}"),
        },
        VerificationError::Contract { contract, .. } => format!("schema {contract}"),
        other => format!("other: {other}"),
    }
}

/// One vector, end to end.
///
/// - Expected `verified`: emitting a checkpoint over the vector's receipts
///   commits exactly its `receipt_root` and writes each `body_hash` as D(E); the
///   bundle verifies, and so does the vector's carrier under its claimed root.
/// - Expected `refused`: a correctly emitted bundle carrying the vector's
///   receipts, range and claimed root is refused for the vector's exact reason.
///   A root defect is not a template defect, so that bundle is an emission over
///   the vector's own receipts and range, and only the claimed root differs;
///   emission succeeds with the root of the receipts as carried, which is not
///   the claimed one. A carried-order or coverage defect cannot be emitted: its
///   bundle is an emission over the vector it was derived from (the same range),
///   or over POS-N1 for the empty range, and `prepare_checkpoint` refuses it too.
fn reproduce(id: &str) {
    let vector = Vector::load(id);
    let (first, last) = vector.range();
    match (
        vector.expected()["result"].as_str(),
        vector.expected()["error"].as_str(),
    ) {
        (Some("verified"), None) => {
            let bundle = emitted(&vector);
            assert_eq!(
                bundle["checkpoint"]["receipt_root"],
                vector.expected()["receipt_root"],
                "{id}: emitted receipt_root"
            );
            assert_eq!(
                bundle["receipts"],
                vector.receipts(),
                "{id}: emitted receipts (body_hash = D(E))"
            );
            verify_bundle(&bundle)
                .unwrap_or_else(|error| panic!("{id}: the emitted bundle verifies: {error}"));
            verify_bundle(&carrying(&bundle, &vector)).unwrap_or_else(|error| {
                panic!("{id}: the vector's receipts verify under its claimed root: {error}")
            });
        }
        (Some("refused"), Some(expected)) => {
            let base = if expected == "root_mismatch" {
                emitted(&vector)
            } else {
                match vector.derived_from() {
                    Some(base) => emitted(&base),
                    None => emitted(&Vector::load("POS-N1")),
                }
            };
            let refused = verify_bundle(&carrying(&base, &vector))
                .expect_err(&format!("{id}: verify_bundle refuses"));
            let reason = refusal(&refused);
            if expected == "empty_range" {
                // The bundle schema's receipts minItems 1 may refuse first.
                assert!(
                    reason == "empty_range" || reason == format!("schema {BUNDLE_V2}"),
                    "{id}: verify_bundle refusal {reason} ({refused})"
                );
            } else {
                assert_eq!(reason, expected, "{id}: verify_bundle refusal ({refused})");
            }

            if expected == "root_mismatch" {
                let bundle = &base;
                let root = &bundle["checkpoint"]["receipt_root"];
                assert_ne!(
                    root,
                    vector.claimed(),
                    "{id}: the claimed root is not the root of these receipts"
                );
                assert_eq!(
                    bundle["receipts"],
                    vector.receipts(),
                    "{id}: emitted receipts (body_hash = D(E))"
                );
                if let Some(base) = vector.derived_from() {
                    if base.receipts() == vector.receipts() && base.range() == vector.range() {
                        assert_eq!(
                            root,
                            &base.expected()["receipt_root"],
                            "{id}: these are {}'s receipts, so their root is {}'s",
                            base.id,
                            base.id
                        );
                    }
                }
                for name in [
                    "root_at_relabelled_sequences",
                    "root_if_the_reencoded_envelope_had_been_committed",
                ] {
                    if let Some(alternative) = vector.raw["intermediate"].get(name) {
                        assert_eq!(root, alternative, "{id}: {name}");
                    }
                }
            } else {
                let template = if expected == "empty_range" {
                    template_over(0, 0, vector.receipts())
                } else {
                    template_over(first, last, vector.receipts())
                };
                let refused = prepare_checkpoint(template, "single_authority")
                    .expect_err(&format!("{id}: prepare_checkpoint refuses"));
                assert_eq!(
                    refusal(&refused),
                    expected,
                    "{id}: prepare_checkpoint refusal ({refused})"
                );
            }
        }
        other => panic!("{id}: unknown expectation {other:?}"),
    }
}

macro_rules! vector_test {
    ($($name:ident => $id:literal,)*) => {
        $(
            #[test]
            fn $name() {
                reproduce($id);
            }
        )*
    };
}

vector_test! {
    vector_pos_n1 => "POS-N1",
    vector_pos_n2 => "POS-N2",
    vector_pos_n3 => "POS-N3",
    vector_pos_n5 => "POS-N5",
    vector_pos_n7 => "POS-N7",
    vector_neg_reordered_array => "NEG-REORDERED-ARRAY",
    vector_neg_root_over_swapped_leaves => "NEG-ROOT-OVER-SWAPPED-LEAVES",
    vector_neg_sequence_gap => "NEG-SEQUENCE-GAP",
    vector_neg_duplicate_sequence => "NEG-DUPLICATE-SEQUENCE",
    vector_inv_unknown_member => "INV-UNKNOWN-MEMBER",
    vector_neg_dropped_signature => "NEG-DROPPED-SIGNATURE",
    vector_neg_empty_range => "NEG-EMPTY-RANGE",
    vector_neg_sequence_shift => "NEG-SEQUENCE-SHIFT",
    vector_neg_odd_node_duplication => "NEG-ODD-NODE-DUPLICATION",
    vector_inv_urlsafe_signature => "INV-URLSAFE-SIGNATURE",
    vector_inv_keyidless_cosignature => "INV-KEYIDLESS-COSIGNATURE",
}

#[test]
fn the_vector_copy_matches_its_manifest() {
    check_manifest();
}

#[test]
fn every_indexed_vector_is_reproduced() {
    let indexed = index()["vectors"]
        .as_array()
        .expect("index vectors")
        .iter()
        .map(|entry| entry["id"].as_str().expect("id").to_owned())
        .collect::<BTreeSet<_>>();
    let reproduced = REPRODUCED
        .iter()
        .map(|id| (*id).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(indexed, reproduced);
    assert_eq!(indexed.len(), REPRODUCED.len());
}

/// T2 (named by the Director): NEG-REORDERED-ARRAY end to end through
/// `verify_bundle`. The bundle is emitted and signed over POS-N3's receipts;
/// afterwards only the CARRIED order of `receipts[]` changes, to the vector's
/// 101, 100, 102, as a relay could change it. The checkpoint, its root and its
/// signature are untouched, so a verifier that re-sorted would accept it.
#[test]
fn verify_bundle_refuses_reordered_receipts_and_never_resorts() {
    let in_order = Vector::load("POS-N3");
    let reordered = Vector::load("NEG-REORDERED-ARRAY");
    let bundle = emitted(&in_order);
    verify_bundle(&bundle).expect("the bundle carried in order verifies");
    let mut carried = bundle.clone();
    carried["receipts"] = reordered.receipts();
    rehash_outer(&mut carried);
    let mut sorted = carried["receipts"].as_array().expect("receipts").clone();
    sorted.sort_by_key(|receipt| receipt["sequence"].as_u64());
    assert_eq!(
        Value::Array(sorted),
        bundle["receipts"],
        "the same receipts, only carried in another order"
    );
    let refused =
        verify_bundle(&carried).expect_err("a reordered receipt array is refused, never re-sorted");
    assert_eq!(refusal(&refused), "sequence_order", "{refused}");
}

/// T2, the emitter side: a template whose receipts are carried 101, 100, 102 is
/// refused, never sorted into a checkpoint.
#[test]
fn prepare_checkpoint_refuses_a_reordered_receipt_template() {
    let reordered = Vector::load("NEG-REORDERED-ARRAY");
    let (first, last) = reordered.range();
    let refused = prepare_checkpoint(
        template_over(first, last, reordered.receipts()),
        "single_authority",
    )
    .expect_err("a template carried out of order is refused, never sorted");
    assert_eq!(refusal(&refused), "sequence_order", "{refused}");
}

/// D3: a receipt body that is not a DSSE envelope, like the `{"outcome":"ok"}`
/// body the registered receipt-proof-bundle v2 fixtures carry until canon delta
/// CD-1 lands, has no D(E), and so no receipt_root v2. Both functions refuse it
/// rather than hash it.
#[test]
fn a_receipt_body_that_is_not_a_dsse_envelope_is_refused() {
    let body = json!({"outcome": "ok"});
    let mut template = fixture(SINGLE_AUTHORITY_TEMPLATE);
    template["receipts"][0]["body"] = body.clone();
    let refused = prepare_checkpoint(template, "single_authority")
        .expect_err("a non-DSSE receipt body is refused at emission");
    assert_eq!(refusal(&refused), "envelope_malformed", "{refused}");

    let mut bundle = signed_bundle();
    bundle["receipts"][0]["body_hash"] = Value::String(hash_value(&body).expect("flat hash"));
    bundle["receipts"][0]["body"] = body;
    rehash_outer(&mut bundle);
    let refused = verify_bundle(&bundle).expect_err("a non-DSSE receipt body is refused");
    assert_eq!(refusal(&refused), "envelope_malformed", "{refused}");
}

/// A receipt's body_hash is D(body), not the JCS hash of the whole body.
/// INV-UNKNOWN-MEMBER's envelope carries members D(E) excludes, so the two
/// differ, and a bundle carrying the whole-body hash is refused.
#[test]
fn a_receipt_body_hash_must_be_the_envelope_digest() {
    let unknown = Vector::load("INV-UNKNOWN-MEMBER");
    let bundle = emitted(&unknown);
    assert_eq!(
        bundle["receipts"][0]["body_hash"], unknown.raw["receipts"][0]["body_hash"],
        "the emitted body_hash is D(E)"
    );
    let mut whole_body = bundle.clone();
    let body = whole_body["receipts"][0]["body"].clone();
    whole_body["receipts"][0]["body_hash"] =
        Value::String(hash_value(&body).expect("whole-body hash"));
    assert_ne!(
        whole_body["receipts"][0]["body_hash"],
        bundle["receipts"][0]["body_hash"]
    );
    rehash_outer(&mut whole_body);
    let refused = verify_bundle(&whole_body).expect_err("a whole-body hash is refused");
    assert_eq!(refusal(&refused), "body_hash_mismatch", "{refused}");
}
