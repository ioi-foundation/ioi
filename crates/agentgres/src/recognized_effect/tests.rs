use super::*;
use ioi_api::crypto::SerializableKey;
use serde_json::json;
use std::fs;
use std::fs::OpenOptions;
use std::str::FromStr;
use tempfile::TempDir;

const INITIAL_HEAD: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const ISSUER_KEY_ID: &str = "key://acme/finality/1";

#[derive(Clone)]
struct StaticAuthority(AuthoritySnapshot);

impl AuthorityRevalidator for StaticAuthority {
    fn current_snapshot(&self, _prepared: &AuthoritySnapshot) -> Result<AuthoritySnapshot, String> {
        Ok(self.0.clone())
    }
}

fn authority() -> AuthoritySnapshot {
    AuthoritySnapshot {
        domain_id: "system://acme".into(),
        authority_epoch: 1,
        revocation_epoch: 0,
        issuer_key_id: ISSUER_KEY_ID.into(),
        admission_permitted: true,
    }
}

fn template() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v2/positive-offline-single-authority.json",
    );
    serde_json::from_slice(&fs::read(path).expect("fixture readable")).expect("fixture parses")
}

fn availability_template() -> Value {
    let mut value = template();
    value["requested_axes"] = json!(["availability"]);
    value["checkpoint"]["finality_certificate"]["claimed_axes"] = json!(["availability"]);
    value["checkpoint"]["verifier_contract"]["axes"] = json!([{
        "axis": "availability",
        "required_input_contract_ids": [
            "schema://ioi/foundations/receipt-proof-bundle/v2",
            "schema://ioi/foundations/availability-manifest/v1"
        ],
        "failure_behavior": "fail_closed"
    }]);
    value["checkpoint"]["availability_manifest"]["payloads"] = json!([{
        "payload_ref": "payload://acme/hello",
        "payload_hash": "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "byte_length": 5,
        "location_refs": ["location://acme/local/hello"],
        "failure_domain_refs": ["failure-domain://acme/local"],
        "retrieval_evidence_refs": ["evidence://acme/hello/retrieved"]
    }]);
    value["availability_payloads"] = json!([{
        "payload_ref": "payload://acme/hello",
        "payload_base64": "aGVsbG8="
    }]);
    value
}

fn outbox(effect_id: &str) -> Vec<OutboxIntent> {
    REQUIRED_OUTBOX_KINDS
        .iter()
        .map(|kind| {
            OutboxIntent::new(
                format!("consequence://{effect_id}/{kind}"),
                *kind,
                json!({"effect_id": effect_id, "kind": kind}),
            )
            .expect("valid intent")
        })
        .collect()
}

fn open(temp: &TempDir) -> RecognizedEffectStore {
    RecognizedEffectStore::open(temp.path(), "system://acme", INITIAL_HEAD).expect("store opens")
}

fn prepare(
    store: &mut RecognizedEffectStore,
    effect_id: &str,
    value: Value,
) -> PreparedRecognizedEffect {
    let signing_key = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");
    let owner = StaticAuthority(authority());
    store
        .prepare(
            effect_id,
            value,
            authority(),
            &owner,
            ISSUER_KEY_ID,
            &signing_key,
            outbox(effect_id),
        )
        .expect("effect prepares")
}

#[test]
fn commit_recovery_replay_and_outbox_are_byte_identical() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);
    let owner = StaticAuthority(authority());
    let prepared = prepare(&mut store, "effect-1", availability_template());
    let retry = prepared.clone();
    let expected_bytes = prepared.canonical_bytes().to_vec();

    let committed = store
        .commit(prepared, &owner, 100)
        .expect("commit succeeds");
    assert_eq!(committed.disposition, CommitDisposition::Committed);
    assert_eq!(committed.effect.canonical_bytes, expected_bytes);
    assert_eq!(
        committed.effect.record.outbox.len(),
        REQUIRED_OUTBOX_KINDS.len()
    );
    verify_bundle(&committed.effect.record.bundle).expect("committed proof verifies offline");

    let replay = store
        .commit(retry, &owner, 101)
        .expect("identity retry replays");
    assert_eq!(replay.disposition, CommitDisposition::Replayed);
    assert_eq!(replay.effect.canonical_bytes, expected_bytes);
    drop(store);

    let mut reopened = open(&temp);
    assert_eq!(
        reopened
            .committed("effect-1")
            .expect("recovered")
            .canonical_bytes,
        expected_bytes
    );
    let pending = reopened.pending_outbox("effect-1").expect("pending outbox");
    assert_eq!(pending.len(), REQUIRED_OUTBOX_KINDS.len());
    assert_eq!(
        reopened
            .materialize_projection("effect-1")
            .expect("projected"),
        DeliveryDisposition::Recorded
    );
    for intent in pending {
        assert_eq!(
            reopened
                .record_delivery("effect-1", &intent.consequence_id, &intent.payload)
                .expect("delivery recorded"),
            DeliveryDisposition::Recorded
        );
        assert_eq!(
            reopened
                .record_delivery("effect-1", &intent.consequence_id, &intent.payload)
                .expect("delivery replayed"),
            DeliveryDisposition::Replayed
        );
    }
    assert!(reopened
        .pending_outbox("effect-1")
        .expect("outbox complete")
        .is_empty());
}

#[test]
fn retries_conflicts_stale_heads_and_revocations_fail_closed() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);
    let owner = StaticAuthority(authority());
    let first = prepare(&mut store, "effect-1", template());
    let stale = prepare(&mut store, "effect-2", template());
    let mut conflict = first.clone();
    conflict.record.outbox[0].payload = json!({"substituted": true});
    conflict.record.outbox[0].payload_hash =
        hash_value(&conflict.record.outbox[0].payload).unwrap();
    conflict.record.record_hash = record_hash(&conflict.record).unwrap();
    conflict.canonical_bytes = serde_jcs::to_vec(&conflict.record).unwrap();

    store.commit(first, &owner, 100).expect("first commits");
    assert!(matches!(
        store.commit(conflict, &owner, 101),
        Err(RecognizedEffectError::ReplayConflict { .. })
    ));
    assert!(matches!(
        store.commit(stale, &owner, 102),
        Err(RecognizedEffectError::StaleHead { .. })
    ));

    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);
    let prepared = prepare(&mut store, "effect-revoked", template());
    let mut revoked = authority();
    revoked.revocation_epoch += 1;
    revoked.admission_permitted = false;
    assert!(matches!(
        store.commit(prepared, &StaticAuthority(revoked), 100),
        Err(RecognizedEffectError::StaleAuthority)
    ));
    assert!(store.committed("effect-revoked").is_none());
}

#[test]
fn availability_and_projection_substitution_are_detected() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);
    let owner = StaticAuthority(authority());
    let prepared = prepare(&mut store, "effect-availability", availability_template());
    let payload_path = store
        .availability_path(
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )
        .unwrap();
    fs::write(&payload_path, b"world").expect("substitute payload");
    assert!(store.commit(prepared.clone(), &owner, 100).is_err());
    fs::write(&payload_path, b"hello").expect("restore payload");
    store
        .commit(prepared, &owner, 101)
        .expect("commit after restore");
    store
        .materialize_projection("effect-availability")
        .expect("projection materialized");
    let projection_path = temp
        .path()
        .join("projections")
        .join(format!("{}.json", safe_hash("effect-availability")));
    fs::write(&projection_path, b"substituted").expect("substitute projection");
    assert!(matches!(
        store.materialize_projection("effect-availability"),
        Err(RecognizedEffectError::ProjectionDivergence { .. })
    ));
    fs::remove_file(payload_path).expect("remove payload");
    drop(store);
    let reopened =
        RecognizedEffectStore::open(temp.path(), "system://acme", INITIAL_HEAD).expect("recover");
    assert!(reopened.committed("effect-availability").is_some());
    assert_eq!(
        fs::read(
            reopened
                .availability_path(
                    "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                )
                .unwrap()
        )
        .expect("availability restored"),
        b"hello"
    );
}

#[test]
fn uncommitted_effect_cannot_publish_project_or_ack() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);
    let prepared = prepare(&mut store, "effect-prepared", template());
    let intent = prepared.record().outbox[4].clone();
    assert!(store.pending_outbox("effect-prepared").is_err());
    assert!(store.materialize_projection("effect-prepared").is_err());
    assert!(store
        .record_delivery("effect-prepared", &intent.consequence_id, &intent.payload,)
        .is_err());
}

#[test]
fn torn_rooted_batch_recovers_to_no_effect_and_clean_retry() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);
    let owner = StaticAuthority(authority());
    let prepared = prepare(&mut store, "effect-torn", template());
    let retry = prepared.clone();
    let log_path = temp.path().join("canonical/muxlog.bin");
    let baseline = fs::metadata(&log_path).expect("log exists").len();
    store
        .commit(prepared, &owner, 100)
        .expect("commit succeeds");
    drop(store);
    let full = fs::metadata(&log_path).expect("log exists").len();
    assert!(full > baseline + 1);
    OpenOptions::new()
        .write(true)
        .open(&log_path)
        .expect("open log")
        .set_len(full - 1)
        .expect("tear root frame");

    let mut reopened = open(&temp);
    assert!(reopened.committed("effect-torn").is_none());
    assert_eq!(reopened.canonical_head(), INITIAL_HEAD);
    assert_eq!(
        reopened
            .commit(retry, &owner, 101)
            .expect("retry commits")
            .disposition,
        CommitDisposition::Committed
    );
}

#[test]
fn every_declared_crash_point_is_reachable_and_recovers_atomically() {
    let preparation_phases = &Phase::ALL[..8];
    for phase in preparation_phases {
        for point in [CrashPoint::before(*phase), CrashPoint::after(*phase)] {
            let temp = TempDir::new().expect("tempdir");
            let mut store = open(&temp);
            store.arm_crash(point);
            let signing_key = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");
            let result = store.prepare(
                "effect-crash",
                template(),
                authority(),
                &StaticAuthority(authority()),
                ISSUER_KEY_ID,
                &signing_key,
                outbox("effect-crash"),
            );
            assert!(result.is_err(), "{point} was a no-op");
            drop(store);
            let mut reopened = open(&temp);
            assert!(reopened.committed("effect-crash").is_none(), "{point}");
            let retry = prepare(&mut reopened, "effect-crash", template());
            assert_eq!(
                reopened
                    .commit(retry, &StaticAuthority(authority()), 101)
                    .expect("pre-linearization retry commits")
                    .disposition,
                CommitDisposition::Committed,
                "{point}"
            );
        }
    }

    let commit_phases = &Phase::ALL[8..12];
    for phase in commit_phases {
        for point in [CrashPoint::before(*phase), CrashPoint::after(*phase)] {
            let temp = TempDir::new().expect("tempdir");
            let mut store = open(&temp);
            let prepared = prepare(&mut store, "effect-crash", template());
            let retry = prepared.clone();
            let expected_bytes = prepared.canonical_bytes.clone();
            store.arm_crash(point);
            let result = store.commit(prepared, &StaticAuthority(authority()), 100);
            assert!(result.is_err(), "{point} was a no-op");
            let uncertainty_requires_reopen = matches!(
                point,
                CrashPoint {
                    phase: Phase::CanonicalWrite,
                    boundary: Boundary::After,
                } | CrashPoint {
                    phase: Phase::CanonicalFsync | Phase::HeadRootAdvancement,
                    ..
                }
            );
            if uncertainty_requires_reopen {
                assert!(
                    store
                        .commit(retry.clone(), &StaticAuthority(authority()), 100)
                        .is_err(),
                    "uncertain writer accepted an in-process retry at {point}"
                );
            }
            drop(store);
            let mut reopened = open(&temp);
            let committed = reopened.committed("effect-crash").is_some();
            let expected_committed = !matches!(
                point,
                CrashPoint {
                    phase: Phase::FrameConstruction | Phase::CanonicalWrite,
                    boundary: Boundary::Before,
                } | CrashPoint {
                    phase: Phase::FrameConstruction,
                    boundary: Boundary::After,
                }
            );
            assert_eq!(committed, expected_committed, "atomic recovery at {point}");
            let retry_result = reopened
                .commit(retry, &StaticAuthority(authority()), 101)
                .expect("recovered retry resolves exactly once");
            assert_eq!(
                retry_result.disposition,
                if expected_committed {
                    CommitDisposition::Replayed
                } else {
                    CommitDisposition::Committed
                },
                "{point}"
            );
            assert_eq!(
                retry_result.effect.canonical_bytes, expected_bytes,
                "{point}"
            );
        }
    }

    for phase in &Phase::ALL[12..] {
        for point in [CrashPoint::before(*phase), CrashPoint::after(*phase)] {
            let temp = TempDir::new().expect("tempdir");
            let mut store = open(&temp);
            let prepared = prepare(&mut store, "effect-crash", template());
            store
                .commit(prepared, &StaticAuthority(authority()), 100)
                .expect("canonical commit");
            let expected_bytes = store
                .committed("effect-crash")
                .unwrap()
                .canonical_bytes
                .clone();
            store.arm_crash(point);
            let mut consequence = None;
            let result = if *phase == Phase::ProjectionMaterialization {
                store.materialize_projection("effect-crash").map(|_| ())
            } else {
                let intent = store
                    .committed("effect-crash")
                    .unwrap()
                    .record
                    .outbox
                    .iter()
                    .find(|intent| phase_for_outbox_kind(&intent.kind).unwrap() == *phase)
                    .unwrap()
                    .clone();
                consequence = Some(intent.clone());
                store
                    .record_delivery("effect-crash", &intent.consequence_id, &intent.payload)
                    .map(|_| ())
            };
            assert!(result.is_err(), "{point} was a no-op");
            drop(store);
            let mut reopened = open(&temp);
            assert_eq!(
                reopened
                    .committed("effect-crash")
                    .expect("committed effect survives delivery crash")
                    .canonical_bytes,
                expected_bytes,
                "{point}"
            );
            if *phase == Phase::ProjectionMaterialization {
                reopened
                    .materialize_projection("effect-crash")
                    .expect("projection redrives");
            } else {
                let intent = consequence.expect("publication consequence");
                reopened
                    .record_delivery("effect-crash", &intent.consequence_id, &intent.payload)
                    .expect("publication redrives idempotently");
            }
        }
    }
}

#[test]
fn crash_point_parser_and_record_mutations_fail_closed() {
    for phase in Phase::ALL {
        for point in [CrashPoint::before(phase), CrashPoint::after(phase)] {
            assert_eq!(CrashPoint::from_str(&point.to_string()).unwrap(), point);
        }
    }
    for malformed in [
        "",
        "before",
        "during:canonical_write",
        "before:unknown",
        "before:canonical_write:extra",
    ] {
        assert!(CrashPoint::from_str(malformed).is_err(), "{malformed}");
    }

    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);
    let prepared = prepare(&mut store, "effect-mutation", template());
    let mut mutations = Vec::new();
    let mut record = prepared.record.clone();
    record.record_hash = format!("sha256:{}", "f".repeat(64));
    mutations.push(record);
    let mut record = prepared.record.clone();
    record.bundle["checkpoint"]["previous_canonical_head"] =
        Value::String(format!("sha256:{}", "f".repeat(64)));
    mutations.push(record);
    let mut record = prepared.record.clone();
    record.authority.authority_epoch += 1;
    mutations.push(record);
    let mut record = prepared.record.clone();
    record.outbox[0].payload_hash = format!("sha256:{}", "f".repeat(64));
    mutations.push(record);
    for record in mutations {
        let bytes = serde_jcs::to_vec(&record).unwrap();
        assert!(validate_record(&record, &bytes).is_err());
    }
    let mut canonical_bytes = prepared.canonical_bytes.clone();
    canonical_bytes.push(b' ');
    assert!(validate_record(&prepared.record, &canonical_bytes).is_err());
}
