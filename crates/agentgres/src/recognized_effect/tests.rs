use super::*;
use crate::cutover::{
    guarantee_delta_digest, GovernanceEvidence, GovernanceVerdict, RefuseAllWeakening,
    RollbackKind, RollbackPlan,
};
use crate::profile::{GuaranteeDelta, ProfileFinalityBinding};
use ioi_api::crypto::SerializableKey;
use serde_json::json;
use std::fs;
use std::fs::OpenOptions;
use std::str::FromStr;
use tempfile::TempDir;

const INITIAL_HEAD: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const ISSUER_KEY_ID: &str = "key://acme/finality/1";
const WRITER_A: &str = "writer://acme/a";
const WRITER_B: &str = "writer://acme/b";
const WRITER_C: &str = "writer://acme/c";

fn digest(seed: &str) -> String {
    hash_bytes(seed.as_bytes())
}

fn bindings_digest() -> ProfileBindingsDigest {
    ProfileBindingsDigest {
        policy_digest: digest("policy"),
        verifier_contract_digest: digest("verifier"),
        availability_policy_digest: digest("availability"),
        retention_policy_digest: digest("retention"),
        governance_policy_digest: digest("governance"),
    }
}

fn contract_version() -> String {
    template()["checkpoint"]["profile_contract_version"]
        .as_str()
        .expect("fixture carries a profile contract version")
        .to_owned()
}

fn identity(profile: FinalityProfile) -> ProfileIdentity {
    ProfileIdentity::new(profile, contract_version()).expect("identity")
}

fn genesis(profile: FinalityProfile, writer: &str, fence_token: u64) -> SpineGenesis {
    SpineGenesis {
        identity: identity(profile),
        writer_identity: writer.into(),
        fence_token,
        initial_canonical_head: INITIAL_HEAD.into(),
        bindings: bindings_digest(),
    }
}

/// `single_authority` is never reached by omission: every store below that
/// runs on it names it explicitly at genesis.
fn single_authority_genesis() -> SpineGenesis {
    genesis(FinalityProfile::SingleAuthority, WRITER_A, 1)
}

#[derive(Clone)]
struct StaticAuthority(AuthoritySnapshot);

impl AuthorityRevalidator for StaticAuthority {
    fn current_snapshot(&self, _prepared: &AuthoritySnapshot) -> Result<AuthoritySnapshot, String> {
        Ok(self.0.clone())
    }
}

/// A governance authority that approves exactly the package it is shown.
struct ApproveWeakening;

impl GovernanceValidator for ApproveWeakening {
    fn validate_weakening(
        &self,
        review: &WeakeningReview<'_>,
    ) -> Result<GovernanceVerdict, String> {
        Ok(GovernanceVerdict {
            approved: true,
            approvals: review.governance.approvals(),
            evidence_digest: review.governance.evidence_digest.clone(),
            detail: "approved".into(),
        })
    }
}

/// A validator that approves, but rules on a different evidence package than
/// the one the cutover binds.
struct ApproveDifferentEvidence;

impl GovernanceValidator for ApproveDifferentEvidence {
    fn validate_weakening(
        &self,
        review: &WeakeningReview<'_>,
    ) -> Result<GovernanceVerdict, String> {
        Ok(GovernanceVerdict {
            approved: true,
            approvals: review.governance.approvals(),
            evidence_digest: digest("some other evidence package"),
            detail: "approved the wrong package".into(),
        })
    }
}

/// A validator that returns fewer approvals than the declared threshold.
struct ApproveBelowThreshold;

impl GovernanceValidator for ApproveBelowThreshold {
    fn validate_weakening(
        &self,
        review: &WeakeningReview<'_>,
    ) -> Result<GovernanceVerdict, String> {
        Ok(GovernanceVerdict {
            approved: true,
            approvals: review.governance.approval_threshold.saturating_sub(1),
            evidence_digest: review.governance.evidence_digest.clone(),
            detail: "short of threshold".into(),
        })
    }
}

/// Test double for the AFT certificate seam. It is NOT a finality verifier:
/// it proves only that the spine's profile plumbing is generic. The real
/// adapter arrives with the sibling `ioi-finality` two-profile API.
struct TestAftBinding;

impl TestAftBinding {
    fn seal(bundle: &Value) -> Result<String, RecognizedEffectError> {
        let mut checkpoint = bundle
            .pointer("/checkpoint")
            .cloned()
            .ok_or_else(|| RecognizedEffectError::Invalid("checkpoint absent".into()))?;
        if let Some(object) = checkpoint.as_object_mut() {
            object.remove("test_seal");
        }
        hash_value(&checkpoint)
    }
}

impl ProfileFinalityBinding for TestAftBinding {
    fn profile(&self) -> FinalityProfile {
        FinalityProfile::BftConsensus
    }

    fn emit(
        &self,
        template: Value,
        issuer_key_id: &str,
        _signing_key: &Ed25519PrivateKey,
    ) -> Result<Value, RecognizedEffectError> {
        let mut bundle = template;
        bundle["checkpoint"]["finality_certificate"]["issuer_key_id"] = json!(issuer_key_id);
        let seal = Self::seal(&bundle)?;
        bundle["checkpoint"]["test_seal"] = json!(seal);
        Ok(bundle)
    }

    fn verify(&self, bundle: &Value) -> Result<(), RecognizedEffectError> {
        let profile = FinalityProfile::from_exact(
            pointer_text(bundle, "/checkpoint/profile")?,
            pointer_text(
                bundle,
                "/checkpoint/finality_certificate/certificate_variant",
            )?,
        )?;
        if profile != FinalityProfile::BftConsensus {
            return Err(ProfileRefusal::VariantMismatch {
                profile: profile.profile().into(),
                variant: profile.certificate_variant().into(),
            }
            .into_error());
        }
        if pointer_text(bundle, "/checkpoint/test_seal")? != Self::seal(bundle)? {
            return Err(RecognizedEffectError::Invalid("aft seal mismatch".into()));
        }
        Ok(())
    }
}

fn aft_bindings() -> ProfileBindings {
    ProfileBindings::production().with_binding(Box::new(TestAftBinding))
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

/// The single-authority fixture re-labelled onto the AFT profile pair. Only
/// the test AFT binding accepts it — the production binding refuses.
fn aft_template() -> Value {
    let mut value = template();
    value["checkpoint"]["profile"] = json!(FinalityProfile::BftConsensus.profile());
    value["checkpoint"]["finality_certificate"]["profile"] =
        json!(FinalityProfile::BftConsensus.profile());
    value["checkpoint"]["finality_certificate"]["certificate_variant"] =
        json!(FinalityProfile::BftConsensus.certificate_variant());
    value
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

fn open_at(temp: &TempDir, genesis: SpineGenesis, bindings: ProfileBindings) -> RecognizedEffectStore {
    let writer = WriterClaim::new(genesis.writer_identity.clone(), genesis.fence_token);
    let mut store =
        RecognizedEffectStore::open_with_bindings(temp.path(), "system://acme", genesis, bindings)
            .expect("store opens");
    store.bind_writer(writer).expect("writer binds");
    store
}

fn open(temp: &TempDir) -> RecognizedEffectStore {
    open_at(
        temp,
        single_authority_genesis(),
        ProfileBindings::production(),
    )
}

/// Reopen without claiming a writer — the shape a restart actually takes when
/// the eligible writer is no longer the one named at genesis.
fn reopen(
    temp: &TempDir,
    genesis: SpineGenesis,
    bindings: ProfileBindings,
) -> RecognizedEffectStore {
    RecognizedEffectStore::open_with_bindings(temp.path(), "system://acme", genesis, bindings)
        .expect("store reopens")
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

fn delta(direction: GuaranteeDirection) -> GuaranteeDelta {
    match direction {
        GuaranteeDirection::Weakening => GuaranteeDelta {
            direction,
            lost_guarantees: vec![
                "byzantine-fault-tolerant-ordering".into(),
                "non-equivocation-by-quorum".into(),
            ],
            retained_guarantees: vec!["durability".into()],
            gained_guarantees: vec![],
        },
        GuaranteeDirection::Strengthening => GuaranteeDelta {
            direction,
            lost_guarantees: vec![],
            retained_guarantees: vec!["durability".into()],
            gained_guarantees: vec!["byzantine-fault-tolerant-ordering".into()],
        },
    }
}

fn rollback_plan() -> RollbackPlan {
    RollbackPlan {
        kind: RollbackKind::SuccessorCutover,
        executor_writer_identity: WRITER_C.into(),
        executor_authorization_refs: vec!["authorization://acme/governance/board".into()],
        target: Some(identity(FinalityProfile::BftConsensus)),
        independent_of_new_authority: true,
    }
}

fn governance(store: &RecognizedEffectStore, delta: &GuaranteeDelta) -> GovernanceEvidence {
    let (anchor_batch_seq, anchor_root) = store.current_anchor();
    GovernanceEvidence {
        governance_id: "governance://acme/weakening/1".into(),
        evidence_digest: digest("weakening evidence package"),
        approval_threshold: 2,
        authorization_refs: vec![
            "authorization://acme/governance/board".into(),
            "authorization://acme/governance/security".into(),
        ],
        effective_after_ms: 1_000,
        anchor_batch_seq,
        anchor_root,
        guarantee_delta_digest: guarantee_delta_digest(delta).expect("delta digest"),
    }
}

fn strengthening_request() -> ProfileCutoverRequest {
    ProfileCutoverRequest {
        cutover_id: "cutover://acme/1".into(),
        to_profile: "bft_consensus".into(),
        to_profile_contract_version: contract_version(),
        to_writer_identity: WRITER_B.into(),
        to_fence_token: 2,
        authority: authority(),
        bindings: bindings_digest(),
        guarantee_delta: delta(GuaranteeDirection::Strengthening),
        governance: None,
        rollback: RollbackPlan {
            kind: RollbackKind::Freeze,
            executor_writer_identity: WRITER_C.into(),
            executor_authorization_refs: vec!["authorization://acme/governance/board".into()],
            target: None,
            independent_of_new_authority: true,
        },
    }
}

fn weakening_request(
    store: &RecognizedEffectStore,
    cutover_id: &str,
    to_writer: &str,
    to_fence_token: u64,
) -> ProfileCutoverRequest {
    let guarantee_delta = delta(GuaranteeDirection::Weakening);
    let governance = governance(store, &guarantee_delta);
    ProfileCutoverRequest {
        cutover_id: cutover_id.into(),
        // Exercised through the canon compatibility label, not the canonical
        // spelling: resolution must happen before admission.
        to_profile: "single_authority".into(),
        to_profile_contract_version: contract_version(),
        to_writer_identity: to_writer.into(),
        to_fence_token,
        authority: authority(),
        bindings: bindings_digest(),
        guarantee_delta,
        governance: Some(governance),
        rollback: rollback_plan(),
    }
}

/// Genesis on AFT, then a governed weakening to `single_authority` — the
/// starting point for the weakening-specific tests.
fn aft_store(temp: &TempDir) -> RecognizedEffectStore {
    open_at(
        temp,
        genesis(FinalityProfile::BftConsensus, WRITER_A, 1),
        aft_bindings(),
    )
}

fn commit_cutover(
    store: &mut RecognizedEffectStore,
    request: ProfileCutoverRequest,
    governance: &dyn GovernanceValidator,
    recorded_at_ms: u64,
) -> Result<CommittedProfileCutover, RecognizedEffectError> {
    let owner = StaticAuthority(authority());
    let prepared = store.prepare_cutover(request, &owner, governance, recorded_at_ms)?;
    store.commit_cutover(prepared, &owner, governance, recorded_at_ms)
}

// ---------------------------------------------------------------------------
// Effect plane — preserved behavior
// ---------------------------------------------------------------------------

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
    ioi_finality::verify_bundle(&committed.effect.record.bundle)
        .expect("committed proof verifies offline");

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
    let reopened = open(&temp);
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
    for phase in Phase::EFFECT_PREPARATION {
        for point in [CrashPoint::before(phase), CrashPoint::after(phase)] {
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

    for phase in Phase::LINEARIZATION {
        for point in [CrashPoint::before(phase), CrashPoint::after(phase)] {
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

    for phase in Phase::CONSEQUENCE {
        for point in [CrashPoint::before(phase), CrashPoint::after(phase)] {
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
            let result = if phase == Phase::ProjectionMaterialization {
                store.materialize_projection("effect-crash").map(|_| ())
            } else {
                let intent = store
                    .committed("effect-crash")
                    .unwrap()
                    .record
                    .outbox
                    .iter()
                    .find(|intent| phase_for_outbox_kind(&intent.kind).unwrap() == phase)
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
            if phase == Phase::ProjectionMaterialization {
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

/// The control plane carries the same atomicity obligation as the data plane:
/// an interrupted cutover leaves the prior writer eligible and unchanged, and
/// a clean retry installs the successor exactly once.
#[test]
fn control_plane_crash_points_recover_to_exactly_one_writer() {
    for phase in Phase::CONTROL {
        for point in [CrashPoint::before(phase), CrashPoint::after(phase)] {
            let temp = TempDir::new().expect("tempdir");
            let mut store = open(&temp);
            let request = strengthening_request();
            store.arm_crash(point);
            let owner = StaticAuthority(authority());
            let attempt = store
                .prepare_cutover(request, &owner, &RefuseAllWeakening, 10)
                .and_then(|prepared| {
                    store.commit_cutover(prepared, &owner, &RefuseAllWeakening, 10)
                });
            assert!(attempt.is_err(), "{point} was a no-op");
            drop(store);

            let mut reopened = RecognizedEffectStore::open(
                temp.path(),
                "system://acme",
                single_authority_genesis(),
            )
            .expect("reopen");
            // Whether the cutover linearized is read from committed truth,
            // not inferred from the caller's error: a crash after the rooted
            // batch returns an error for a cutover that did commit.
            let linearized = reopened.committed_cutover("cutover://acme/1").is_some();
            let active = reopened.spine_state().active().expect("not frozen").clone();
            let (expected_writer, expected_token, expected_profile) = if linearized {
                (WRITER_B, 2, FinalityProfile::BftConsensus)
            } else {
                (WRITER_A, 1, FinalityProfile::SingleAuthority)
            };
            assert_eq!(active.writer_identity, expected_writer, "{point}");
            assert_eq!(active.fence_token, expected_token, "{point}");
            assert_eq!(active.identity.profile, expected_profile, "{point}");

            // Exactly one writer is eligible after recovery — never both,
            // never neither.
            let eligible = [
                WriterClaim::new(WRITER_A, 1),
                WriterClaim::new(WRITER_B, 2),
            ]
            .into_iter()
            .filter(|claim| reopened.bind_writer(claim.clone()).is_ok())
            .count();
            assert_eq!(eligible, 1, "{point}");

            if !linearized {
                // A clean retry installs the successor exactly once.
                let retried =
                    commit_cutover(&mut reopened, strengthening_request(), &RefuseAllWeakening, 11)
                        .expect("clean retry commits");
                assert_eq!(retried.record.to_writer_identity, WRITER_B, "{point}");
                assert_eq!(retried.record.to_profile_epoch, 1, "{point}");
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
    // Profile-plane substitutions inside admitted bytes.
    let mut record = prepared.record.clone();
    record.profile = "aft".into();
    mutations.push(record);
    let mut record = prepared.record.clone();
    record.certificate_variant = FinalityProfile::BftConsensus.certificate_variant().into();
    mutations.push(record);
    let mut record = prepared.record.clone();
    record.profile_contract_version = "substituted".into();
    mutations.push(record);
    let mut record = prepared.record.clone();
    record.canonical_expected_head = format!("sha256:{}", "e".repeat(64));
    mutations.push(record);
    let mut record = prepared.record.clone();
    record.bindings.retention_policy_digest = digest("substituted retention");
    mutations.push(record);
    for record in mutations {
        let bytes = serde_jcs::to_vec(&record).unwrap();
        assert!(
            validate_record(&record, &bytes, &ProfileBindings::production()).is_err(),
            "{}",
            record.effect_id
        );
    }
    let mut canonical_bytes = prepared.canonical_bytes.clone();
    canonical_bytes.push(b' ');
    assert!(validate_record(
        &prepared.record,
        &canonical_bytes,
        &ProfileBindings::production()
    )
    .is_err());
}

// ---------------------------------------------------------------------------
// Control plane — genesis, fencing, cutover, freeze
// ---------------------------------------------------------------------------

#[test]
fn genesis_is_sealed_and_a_substituted_reopen_is_refused() {
    let temp = TempDir::new().expect("tempdir");
    let store = open(&temp);
    let sealed = store.sealed_genesis().expect("genesis sealed").clone();
    assert_eq!(sealed.identity.profile, FinalityProfile::SingleAuthority);
    assert_eq!(sealed.writer_identity, WRITER_A);
    assert_eq!(sealed.fence_token, 1);
    assert_eq!(sealed.profile_epoch, 0);
    drop(store);

    // Identical genesis reopens.
    let store = open(&temp);
    assert_eq!(store.sealed_genesis().expect("resealed"), &sealed);
    drop(store);

    // Every field is load-bearing: a restart cannot substitute the profile,
    // the eligible writer, the fence token, the head, or the bindings.
    let mut substitutions = Vec::new();
    substitutions.push(genesis(FinalityProfile::BftConsensus, WRITER_A, 1));
    substitutions.push(genesis(FinalityProfile::SingleAuthority, WRITER_B, 1));
    substitutions.push(genesis(FinalityProfile::SingleAuthority, WRITER_A, 9));
    let mut head = single_authority_genesis();
    head.initial_canonical_head = format!("sha256:{}", "a".repeat(64));
    substitutions.push(head);
    let mut bindings = single_authority_genesis();
    bindings.bindings.policy_digest = digest("substituted policy");
    substitutions.push(bindings);
    let mut version = single_authority_genesis();
    version.identity.profile_contract_version = "substituted".into();
    substitutions.push(version);
    for candidate in substitutions {
        assert!(
            matches!(
                RecognizedEffectStore::open(temp.path(), "system://acme", candidate),
                Err(RecognizedEffectError::Profile(
                    ProfileRefusal::GenesisMismatch { .. }
                ))
            ),
            "a substituted genesis was adopted"
        );
    }
}

#[test]
fn writer_binding_requires_exact_identity_and_fence_token() {
    let temp = TempDir::new().expect("tempdir");
    let mut store =
        RecognizedEffectStore::open(temp.path(), "system://acme", single_authority_genesis())
            .expect("opens");
    assert!(store.bound_writer().is_none());

    // No writer bound: preparation is not progress.
    let signing_key = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");
    assert!(matches!(
        store.prepare(
            "effect-unbound",
            template(),
            authority(),
            &StaticAuthority(authority()),
            ISSUER_KEY_ID,
            &signing_key,
            outbox("effect-unbound"),
        ),
        Err(RecognizedEffectError::Profile(ProfileRefusal::NoWriterBound))
    ));

    assert!(matches!(
        store.bind_writer(WriterClaim::new(WRITER_B, 1)),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::WriterIdentityMismatch { .. }
        ))
    ));
    // A forged higher token wins nothing: the rule is equality with the
    // installed token, not "greater than".
    for token in [0, 2, u64::MAX] {
        assert!(
            matches!(
                store.bind_writer(WriterClaim::new(WRITER_A, token)),
                Err(RecognizedEffectError::Profile(
                    ProfileRefusal::FenceTokenMismatch { .. }
                ))
            ),
            "token {token} bound"
        );
    }
    store
        .bind_writer(WriterClaim::new(WRITER_A, 1))
        .expect("exact claim binds");
    assert_eq!(store.bound_writer().expect("bound").fence_token, 1);
}

#[test]
fn strengthening_cutover_needs_no_governance_and_refuses_stray_evidence() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);
    let committed = commit_cutover(
        &mut store,
        strengthening_request(),
        &RefuseAllWeakening,
        10,
    )
    .expect("strengthening commits without governance");
    assert_eq!(committed.record.to.profile, FinalityProfile::BftConsensus);
    assert_eq!(committed.record.to_profile_epoch, 1);
    assert_eq!(committed.record.to_fence_token, 2);

    // Unvalidated governance material must not ride along inside admitted
    // bytes just because it happens to be well-formed.
    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);
    let mut request = strengthening_request();
    let weakening = delta(GuaranteeDirection::Weakening);
    request.governance = Some(governance(&store, &weakening));
    assert!(matches!(
        commit_cutover(&mut store, request, &ApproveWeakening, 10),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::GovernanceEvidenceRejected { .. }
        ))
    ));
}

#[test]
fn weakening_refuses_by_default_and_needs_the_full_inv42_burden() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = aft_store(&temp);

    // Default production posture: no governance authority is bound, so the
    // weakening is refused rather than silently accepted.
    let request = weakening_request(&store, "cutover://acme/w", WRITER_B, 2);
    assert!(matches!(
        commit_cutover(&mut store, request, &RefuseAllWeakening, 5_000),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::GovernanceEvidenceRejected { .. }
        ))
    ));

    // Missing evidence entirely.
    let mut request = weakening_request(&store, "cutover://acme/w", WRITER_B, 2);
    request.governance = None;
    assert!(matches!(
        commit_cutover(&mut store, request, &ApproveWeakening, 5_000),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::GovernanceEvidenceRequired
        ))
    ));

    // Threshold unmet by the declared refs.
    let mut request = weakening_request(&store, "cutover://acme/w", WRITER_B, 2);
    if let Some(evidence) = request.governance.as_mut() {
        evidence.approval_threshold = 3;
    }
    assert!(matches!(
        commit_cutover(&mut store, request, &ApproveWeakening, 5_000),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::GovernanceThresholdUnmet { .. }
        ))
    ));

    // Delay not yet elapsed.
    let request = weakening_request(&store, "cutover://acme/w", WRITER_B, 2);
    assert!(matches!(
        commit_cutover(&mut store, request, &ApproveWeakening, 999),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::GovernanceDelayUnmet { .. }
        ))
    ));

    // Checkpoint anchor that pins some other state.
    let mut request = weakening_request(&store, "cutover://acme/w", WRITER_B, 2);
    if let Some(evidence) = request.governance.as_mut() {
        evidence.anchor_batch_seq += 1;
    }
    assert!(matches!(
        commit_cutover(&mut store, request, &ApproveWeakening, 5_000),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::GovernanceAnchorUnmet { .. }
        ))
    ));

    // Evidence that approves a different guarantee delta than the one
    // declared: understating what is given up must not pass.
    let mut request = weakening_request(&store, "cutover://acme/w", WRITER_B, 2);
    request.guarantee_delta.lost_guarantees = vec!["something-smaller".into()];
    assert!(matches!(
        commit_cutover(&mut store, request, &ApproveWeakening, 5_000),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::GovernanceEvidenceRejected { .. }
        ))
    ));

    // A validator that rules on a different package, or below threshold.
    let request = weakening_request(&store, "cutover://acme/w", WRITER_B, 2);
    assert!(matches!(
        commit_cutover(&mut store, request, &ApproveDifferentEvidence, 5_000),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::GovernanceEvidenceRejected { .. }
        ))
    ));
    let request = weakening_request(&store, "cutover://acme/w", WRITER_B, 2);
    assert!(matches!(
        commit_cutover(&mut store, request, &ApproveBelowThreshold, 5_000),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::GovernanceThresholdUnmet { .. }
        ))
    ));

    // Nothing above moved the spine.
    let active = store.spine_state().active().expect("still active");
    assert_eq!(active.identity.profile, FinalityProfile::BftConsensus);
    assert_eq!(active.profile_epoch, 0);
    assert_eq!(active.writer_identity, WRITER_A);

    // With the full burden met, it commits.
    let request = weakening_request(&store, "cutover://acme/w", WRITER_B, 2);
    let committed = commit_cutover(&mut store, request, &ApproveWeakening, 5_000)
        .expect("governed weakening commits");
    assert_eq!(
        committed.record.to.profile,
        FinalityProfile::SingleAuthority
    );
    assert_eq!(
        committed.record.guarantee_delta.direction,
        GuaranteeDirection::Weakening
    );
    assert!(!committed.record.guarantee_delta.lost_guarantees.is_empty());
}

#[test]
fn weakening_rollback_must_be_executable_without_the_new_authority() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = aft_store(&temp);

    let mut cases = Vec::new();
    // The incoming writer is also the rollback executor.
    let mut plan = rollback_plan();
    plan.executor_writer_identity = WRITER_B.into();
    cases.push(plan);
    // The rollback's authorization depends on the incoming writer.
    let mut plan = rollback_plan();
    plan.executor_authorization_refs = vec![WRITER_B.into()];
    cases.push(plan);
    // Independence not declared at all.
    let mut plan = rollback_plan();
    plan.independent_of_new_authority = false;
    cases.push(plan);
    // No independent authorization carried.
    let mut plan = rollback_plan();
    plan.executor_authorization_refs = vec![];
    cases.push(plan);
    // A successor-cutover rollback that does not restore the stronger member.
    let mut plan = rollback_plan();
    plan.target = Some(identity(FinalityProfile::SingleAuthority));
    cases.push(plan);

    for plan in cases {
        let mut request = weakening_request(&store, "cutover://acme/w", WRITER_B, 2);
        request.rollback = plan;
        assert!(
            matches!(
                commit_cutover(&mut store, request, &ApproveWeakening, 5_000),
                // Both refusals are correct answers here; which one fires
                // depends on whether the defect is shape or independence.
                Err(RecognizedEffectError::Profile(
                    ProfileRefusal::RollbackNotIndependent { .. }
                        | ProfileRefusal::RollbackPlanInvalid { .. }
                ))
            ),
            "a rollback dependent on the new authority was accepted"
        );
    }

    // A freeze rollback is equally acceptable, provided it is independent.
    let mut request = weakening_request(&store, "cutover://acme/w", WRITER_B, 2);
    request.rollback = RollbackPlan {
        kind: RollbackKind::Freeze,
        executor_writer_identity: WRITER_C.into(),
        executor_authorization_refs: vec!["authorization://acme/governance/board".into()],
        target: None,
        independent_of_new_authority: true,
    };
    commit_cutover(&mut store, request, &ApproveWeakening, 5_000)
        .expect("independent freeze rollback is sufficient");
}

/// INV-41's operative claim, tested directly: across a cutover there is no
/// instant at which two writers are eligible, and none at which zero are.
#[test]
fn no_dual_authority_interval_across_a_cutover() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);

    // Before: A is eligible, B is not.
    assert!(store.bind_writer(WriterClaim::new(WRITER_A, 1)).is_ok());
    assert!(store.bind_writer(WriterClaim::new(WRITER_B, 2)).is_err());

    // A prepared cutover changes nothing — prepared material grants no
    // authority, so B is still ineligible while it sits unsubmitted.
    let owner = StaticAuthority(authority());
    let prepared = store
        .prepare_cutover(
            strengthening_request(),
            &owner,
            &RefuseAllWeakening,
            10,
        )
        .expect("prepares");
    assert!(store.bind_writer(WriterClaim::new(WRITER_B, 2)).is_err());
    assert!(store.bind_writer(WriterClaim::new(WRITER_A, 1)).is_ok());

    store
        .commit_cutover(prepared, &owner, &RefuseAllWeakening, 10)
        .expect("cutover commits");

    // After: exactly the complement. A is fenced out at its retired token.
    assert!(matches!(
        store.bind_writer(WriterClaim::new(WRITER_A, 1)),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::WriterIdentityMismatch { .. }
        ))
    ));
    assert!(store.bind_writer(WriterClaim::new(WRITER_B, 2)).is_ok());

    // The same holds across a restart: a retired writer re-presenting its old
    // coordinates to a freshly recovered store is still fenced out.
    drop(store);
    let mut restarted = RecognizedEffectStore::open_with_bindings(
        temp.path(),
        "system://acme",
        single_authority_genesis(),
        aft_bindings(),
    )
    .expect("reopen");
    assert!(matches!(
        restarted.bind_writer(WriterClaim::new(WRITER_A, 1)),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::WriterIdentityMismatch { .. }
        ))
    ));
    restarted
        .bind_writer(WriterClaim::new(WRITER_B, 2))
        .expect("successor is the sole eligible writer after restart");
}

#[test]
fn cutover_downgrade_reordering_and_duplicates_are_refused() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);
    let owner = StaticAuthority(authority());

    // A no-op cutover burns an epoch and a token for nothing.
    let mut same = strengthening_request();
    same.to_profile = "single_authority".into();
    assert!(matches!(
        commit_cutover(&mut store, same, &RefuseAllWeakening, 10),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::NoOpCutover { .. }
        ))
    ));

    // A non-monotonic fence token is a downgrade.
    let mut stale_token = strengthening_request();
    stale_token.to_fence_token = 1;
    assert!(matches!(
        commit_cutover(&mut store, stale_token, &RefuseAllWeakening, 10),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::FenceTokenNotMonotonic { .. }
        ))
    ));

    // Two prepared cutovers, one committed: the second is stale material
    // chaining off a head that has moved.
    let first = store
        .prepare_cutover(
            strengthening_request(),
            &owner,
            &RefuseAllWeakening,
            10,
        )
        .expect("first prepares");
    let mut second_request = strengthening_request();
    second_request.cutover_id = "cutover://acme/2".into();
    let second = store
        .prepare_cutover(second_request, &owner, &RefuseAllWeakening, 10)
        .expect("second prepares");
    let committed = store
        .commit_cutover(first.clone(), &owner, &RefuseAllWeakening, 10)
        .expect("first commits");
    // The cutover retired the writer that authored it, so the successor must
    // claim eligibility before anything else can be judged.
    store
        .bind_writer(WriterClaim::new(WRITER_B, 2))
        .expect("successor binds");
    // The second was prepared against control state that no longer exists.
    assert!(matches!(
        store.commit_cutover(second, &owner, &RefuseAllWeakening, 11),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::ActiveProfileMismatch { .. }
        ))
    ));

    // A byte-identical retry is the same fact.
    let replay = store
        .commit_cutover(first.clone(), &owner, &RefuseAllWeakening, 12)
        .expect("identical retry replays");
    assert_eq!(replay.canonical_bytes, committed.canonical_bytes);
    assert_eq!(replay.agentgres_head, committed.agentgres_head);

    // Same identity, different bytes, is a duplicate — not a replay.
    let mut mutated = first;
    mutated.record.to_fence_token = 7;
    mutated.record.record_hash = cutover_record_hash(&mutated.record).unwrap();
    mutated.canonical_bytes = serde_jcs::to_vec(&mutated.record).unwrap();
    assert!(matches!(
        store.commit_cutover(mutated, &owner, &RefuseAllWeakening, 13),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::DuplicateControlOperation { .. }
        ))
    ));
}

#[test]
fn effects_refuse_substituted_profile_writer_epoch_fence_and_bindings() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);
    let owner = StaticAuthority(authority());
    let baseline = prepare(&mut store, "effect-substitution", template());

    // Each substitution is re-hashed and re-serialized, so the record is
    // internally consistent and only the live-state comparison can catch it.
    fn substitute(
        baseline: &PreparedRecognizedEffect,
        label: &'static str,
        edit: impl FnOnce(&mut RecognizedEffectRecord),
    ) -> (&'static str, PreparedRecognizedEffect) {
        let mut prepared = baseline.clone();
        edit(&mut prepared.record);
        prepared.record.record_hash = record_hash(&prepared.record).unwrap();
        prepared.canonical_bytes = serde_jcs::to_vec(&prepared.record).unwrap();
        (label, prepared)
    }

    let cases = vec![
        substitute(&baseline, "profile_epoch", |record| record.profile_epoch += 1),
        substitute(&baseline, "writer_identity", |record| {
            record.writer_identity = WRITER_B.into()
        }),
        substitute(&baseline, "fence_token", |record| record.fence_token += 1),
        substitute(&baseline, "verifier_binding", |record| {
            record.bindings.verifier_contract_digest = digest("substituted verifier")
        }),
        substitute(&baseline, "policy_binding", |record| {
            record.bindings.policy_digest = digest("substituted policy")
        }),
        substitute(&baseline, "availability_binding", |record| {
            record.bindings.availability_policy_digest = digest("substituted availability")
        }),
        substitute(&baseline, "retention_binding", |record| {
            record.bindings.retention_policy_digest = digest("substituted retention")
        }),
        substitute(&baseline, "governance_binding", |record| {
            record.bindings.governance_policy_digest = digest("substituted governance")
        }),
    ];

    for (label, prepared) in cases {
        assert!(
            store.commit(prepared, &owner, 100).is_err(),
            "substituted {label} was admitted"
        );
        assert!(store.committed("effect-substitution").is_none(), "{label}");
    }

    // The untouched original still commits, so the refusals above were about
    // the substitutions and not about the fixture being broken.
    store
        .commit(baseline, &owner, 101)
        .expect("unsubstituted effect commits");
}

#[test]
fn effects_are_refused_under_a_profile_that_is_not_active() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = open_at(&temp, single_authority_genesis(), aft_bindings());
    let signing_key = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");

    // Active profile is single_authority; an AFT bundle is refused even
    // though this store has a working AFT binding.
    assert!(matches!(
        store.prepare(
            "effect-wrong-profile",
            aft_template(),
            authority(),
            &StaticAuthority(authority()),
            ISSUER_KEY_ID,
            &signing_key,
            outbox("effect-wrong-profile"),
        ),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::ActiveProfileMismatch { .. }
        ))
    ));

    // And a mismatched contract version is its own refusal.
    let mut wrong_version = template();
    wrong_version["checkpoint"]["profile_contract_version"] = json!("some-other-version");
    assert!(matches!(
        store.prepare(
            "effect-wrong-version",
            wrong_version,
            authority(),
            &StaticAuthority(authority()),
            ISSUER_KEY_ID,
            &signing_key,
            outbox("effect-wrong-version"),
        ),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::ProfileContractVersionMismatch { .. }
        ))
    ));
}

/// The spine is profile-generic: after a cutover to AFT, effects are prepared,
/// committed, and recovered through the AFT adapter with no single-authority
/// code path involved.
#[test]
fn the_spine_carries_effects_under_both_profiles() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = open_at(&temp, single_authority_genesis(), aft_bindings());
    let owner = StaticAuthority(authority());

    let single = prepare(&mut store, "effect-single", template());
    store
        .commit(single, &owner, 100)
        .expect("single-authority effect commits");

    commit_cutover(
        &mut store,
        strengthening_request(),
        &RefuseAllWeakening,
        200,
    )
    .expect("cutover to AFT commits");
    store
        .bind_writer(WriterClaim::new(WRITER_B, 2))
        .expect("successor writer binds");

    let head_before = store.canonical_head().to_owned();
    let mut aft = aft_template();
    aft["checkpoint"]["previous_canonical_head"] = json!(head_before);
    let prepared = prepare(&mut store, "effect-aft", aft);
    let committed = store
        .commit(prepared, &owner, 300)
        .expect("AFT effect commits");
    assert_eq!(
        committed.effect.record.profile,
        FinalityProfile::BftConsensus.profile()
    );
    assert_eq!(committed.effect.record.profile_epoch, 1);
    assert_eq!(committed.effect.record.fence_token, 2);
    drop(store);

    // Recovery replays both planes in one history and lands on the AFT state.
    let reopened = reopen(&temp, single_authority_genesis(), aft_bindings());
    assert!(reopened.committed("effect-single").is_some());
    assert!(reopened.committed("effect-aft").is_some());
    let active = reopened.spine_state().active().expect("active");
    assert_eq!(active.identity.profile, FinalityProfile::BftConsensus);
    assert_eq!(active.profile_epoch, 1);
    assert_eq!(active.writer_identity, WRITER_B);
    assert_eq!(active.fence_token, 2);

    // Without the AFT adapter, the committed AFT effect cannot be verified,
    // so recovery refuses rather than asserting a check it did not run.
    assert!(RecognizedEffectStore::open(
        temp.path(),
        "system://acme",
        single_authority_genesis()
    )
    .is_err());
}

#[test]
fn freeze_recovers_as_an_explicit_frozen_state_and_admits_nothing() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);
    let owner = StaticAuthority(authority());
    let prepared = prepare(&mut store, "effect-before-freeze", template());
    store
        .commit(prepared, &owner, 100)
        .expect("effect commits before freeze");

    store
        .freeze(
            ProfileFreezeRequest {
                freeze_id: "freeze://acme/1".into(),
                reason: "suspected-equivocation".into(),
                authorization_refs: vec!["authorization://acme/governance/board".into()],
            },
            200,
        )
        .expect("freeze commits");

    assert!(store.spine_state().is_frozen());
    // No writer is eligible, including the one that froze it.
    for claim in [
        WriterClaim::new(WRITER_A, 1),
        WriterClaim::new(WRITER_B, 2),
    ] {
        assert!(matches!(
            store.bind_writer(claim),
            Err(RecognizedEffectError::Profile(ProfileRefusal::SpineFrozen { .. }))
        ));
    }

    // Consequences of already-committed effects still redrive: freezing
    // stops new admission, it does not strand a committed record's outbox.
    store
        .materialize_projection("effect-before-freeze")
        .expect("projection redrives while frozen");

    drop(store);
    let reopened =
        RecognizedEffectStore::open(temp.path(), "system://acme", single_authority_genesis())
            .expect("reopen");
    match reopened.spine_state() {
        SpineState::Frozen(frozen) => {
            assert_eq!(frozen.freeze_id, "freeze://acme/1");
            assert_eq!(frozen.retired_writer_identity, WRITER_A);
            assert_eq!(frozen.fence_token, 1);
        }
        SpineState::Active(_) => panic!("a frozen spine recovered as active"),
    }
    assert!(reopened.committed("effect-before-freeze").is_some());
}

/// A rollback taken after next-profile effects exist is a successor cutover:
/// history is never deleted and the retired token is never revived.
#[test]
fn rollback_after_next_profile_effects_is_a_successor_cutover() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = aft_store(&temp);
    let owner = StaticAuthority(authority());

    let request = weakening_request(&store, "cutover://acme/weaken", WRITER_B, 2);
    let cutover = commit_cutover(&mut store, request, &ApproveWeakening, 5_000)
        .expect("governed weakening commits");
    store
        .bind_writer(WriterClaim::new(WRITER_B, 2))
        .expect("successor binds");

    // An effect under the new, weaker profile.
    let head_before = store.canonical_head().to_owned();
    let mut single = template();
    single["checkpoint"]["previous_canonical_head"] = json!(head_before);
    let prepared = prepare(&mut store, "effect-after-weakening", single);
    store
        .commit(prepared, &owner, 6_000)
        .expect("post-cutover effect commits");

    // Reviving the retired token is refused outright.
    assert!(matches!(
        store.bind_writer(WriterClaim::new(WRITER_A, 1)),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::WriterIdentityMismatch { .. }
        ))
    ));

    // The rollback is a forward cutover: new epoch, strictly greater token,
    // and it restores the stronger member.
    let rollback = ProfileCutoverRequest {
        cutover_id: "cutover://acme/rollback".into(),
        to_profile: "aft".into(),
        to_profile_contract_version: contract_version(),
        to_writer_identity: WRITER_C.into(),
        to_fence_token: 3,
        authority: authority(),
        bindings: bindings_digest(),
        guarantee_delta: delta(GuaranteeDirection::Strengthening),
        governance: None,
        rollback: RollbackPlan {
            kind: RollbackKind::Freeze,
            executor_writer_identity: WRITER_A.into(),
            executor_authorization_refs: vec!["authorization://acme/governance/board".into()],
            target: None,
            independent_of_new_authority: true,
        },
    };
    let rolled_back = commit_cutover(&mut store, rollback, &RefuseAllWeakening, 7_000)
        .expect("rollback commits as a successor cutover");
    assert_eq!(rolled_back.record.to_profile_epoch, 2);
    assert_eq!(rolled_back.record.to_fence_token, 3);
    assert_eq!(rolled_back.record.to.profile, FinalityProfile::BftConsensus);

    // A reused fence token is refused even though the profile is restored.
    let mut revived = ProfileCutoverRequest {
        cutover_id: "cutover://acme/revive".into(),
        to_profile: "single_authority".into(),
        to_profile_contract_version: contract_version(),
        to_writer_identity: WRITER_A.into(),
        to_fence_token: 1,
        authority: authority(),
        bindings: bindings_digest(),
        guarantee_delta: delta(GuaranteeDirection::Weakening),
        governance: None,
        rollback: rollback_plan(),
    };
    store
        .bind_writer(WriterClaim::new(WRITER_C, 3))
        .expect("rollback writer binds");
    let weakening = delta(GuaranteeDirection::Weakening);
    revived.governance = Some(governance(&store, &weakening));
    assert!(matches!(
        commit_cutover(&mut store, revived, &ApproveWeakening, 8_000),
        Err(RecognizedEffectError::Profile(
            ProfileRefusal::FenceTokenNotMonotonic { .. }
        ))
    ));

    // Nothing was deleted: the earlier cutover and the post-cutover effect
    // are both still admitted history.
    drop(store);
    let reopened = reopen(
        &temp,
        genesis(FinalityProfile::BftConsensus, WRITER_A, 1),
        aft_bindings(),
    );
    assert!(reopened.committed("effect-after-weakening").is_some());
    assert!(reopened.committed_cutover(&cutover.record.cutover_id).is_some());
    assert!(reopened
        .committed_cutover("cutover://acme/rollback")
        .is_some());
    let active = reopened.spine_state().active().expect("active");
    assert_eq!(active.profile_epoch, 2);
    assert_eq!(active.fence_token, 3);
}

#[test]
fn restart_recovers_exactly_one_eligible_writer() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);
    commit_cutover(
        &mut store,
        strengthening_request(),
        &RefuseAllWeakening,
        10,
    )
    .expect("cutover commits");
    drop(store);

    let mut reopened =
        RecognizedEffectStore::open(temp.path(), "system://acme", single_authority_genesis())
            .expect("reopen");
    // No writer is bound merely by opening: eligibility must be claimed.
    assert!(reopened.bound_writer().is_none());
    let active = reopened.spine_state().active().expect("active").clone();
    assert_eq!(active.writer_identity, WRITER_B);
    assert_eq!(active.fence_token, 2);
    assert_eq!(active.installed_by.as_deref(), Some("cutover://acme/1"));

    // Exactly one claim in the whole space of the ones we have ever used
    // succeeds.
    let candidates = [
        WriterClaim::new(WRITER_A, 1),
        WriterClaim::new(WRITER_A, 2),
        WriterClaim::new(WRITER_B, 1),
        WriterClaim::new(WRITER_B, 2),
        WriterClaim::new(WRITER_C, 3),
    ];
    let accepted = candidates
        .iter()
        .filter(|claim| reopened.bind_writer((*claim).clone()).is_ok())
        .count();
    assert_eq!(accepted, 1, "exactly one writer must be eligible");
}

#[test]
fn control_and_effect_operations_share_one_spine_head() {
    let temp = TempDir::new().expect("tempdir");
    let mut store = open(&temp);
    let owner = StaticAuthority(authority());

    let prepared = prepare(&mut store, "effect-shared-head", template());
    let effect = store
        .commit(prepared, &owner, 100)
        .expect("effect commits")
        .effect;
    let cutover = commit_cutover(
        &mut store,
        strengthening_request(),
        &RefuseAllWeakening,
        200,
    )
    .expect("cutover commits");

    // One head, one sequence: the cutover chains directly off the effect.
    assert_eq!(
        cutover.record.agentgres_expected_head.as_deref(),
        Some(effect.agentgres_head.as_str())
    );
    assert!(cutover.operation_sequence > effect.operation_sequence);
    assert_eq!(
        store.spine_head().as_deref(),
        Some(cutover.agentgres_head.as_str())
    );
    // And both live in the one profile-neutral domain.
    assert!(store
        .mux
        .domain_head(AGENTGRES_PROFILE_SPINE_DOMAIN, &store.object_ref)
        .is_some());
}
