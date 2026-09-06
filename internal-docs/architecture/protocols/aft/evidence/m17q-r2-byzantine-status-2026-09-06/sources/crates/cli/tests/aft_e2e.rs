// Path: crates/cli/tests/aft_e2e.rs
#![cfg(all(feature = "consensus-aft", feature = "vm-wasm", feature = "state-iavl"))]

use agentgres::consequence::{
    ConsequenceReceiptV1, ConsequenceStateV1, DurablePqAtomicRegisterV1, ExternalResourceV1,
};
use anyhow::Result;
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_cli::aft_quv_ceremony::{install_signed_handoff, sign_handoff_draft};
use ioi_cli::testing::backend::ProcessBackend;
use ioi_cli::testing::{
    assert_log_contains, assert_log_contains_any, build_test_artifacts, rpc, wait_for,
    wait_for_height, TestCluster,
};
use ioi_consensus::aft::query_unanimity::{
    quv_candidate_authority_signing_bytes, quv_handoff_domain_id, quv_policy_root,
    validate_quv_handoff_candidate,
};
use ioi_types::app::consensus::{ExternalizationModeV1, GuaranteeRequirementsV1};
use ioi_types::{
    app::{
        account_id_from_key_material, conflict_domain_id_commitment, AccountId, ActiveKeyRecord,
        BlockTimingParams, BlockTimingRuntime, ChainTransaction, EffectAuthorizationModeV1,
        EffectFenceV1, EffectManifestV1, EffectManifestVersionV1, EffectResourceKeyV1,
        QuvAcceptedAuditEvidenceV0, QuvAuthorityModeV0, QuvCandidateV0,
        QuvConfigurationHandoffEnvelopeV0, QuvSlotV0, ReconciliationPolicyV1, SignHeader,
        SignatureProof, SignatureSuite, SystemPayload, SystemTransaction, ValidatorSetV1,
        ValidatorSetsV1, ValidatorV1, AFT_EFFECT_REGISTRY_SERVICE_ID,
        REGISTER_AFT_EFFECT_MANIFEST_V1_METHOD,
    },
    codec,
    config::{AftQuvDomainPolicyV0, AftSafetyMode, InitialServiceConfig},
    service_configs::MigrationConfig,
};
use std::collections::HashSet;
use std::ffi::OsString;
use std::time::{Duration, Instant};

include!("aft_e2e_parts/quv_readiness.rs");
include!("aft_e2e_parts/quv_flood.rs");
include!("aft_e2e_parts/quv_status_squat.rs");

async fn require_quv_preparation_refusal(
    correct_rpc: &str,
    manifest: &EffectManifestV1,
    candidate: &QuvCandidateV0,
    runtime_root: &std::path::Path,
) -> Result<()> {
    // Rejected preparation must not allocate per-effect receipt or
    // endpoint files. Global lock files are outside these directories.
    let effect_storage_snapshot = || -> Result<Vec<(std::path::PathBuf, Vec<u8>)>> {
        let mut files = Vec::new();
        for relative in ["consequence/effects", "quv-external-resource/records"] {
            let directory = runtime_root.join(relative);
            let entries = match std::fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            for entry in entries {
                let path = entry?.path();
                files.push((path.clone(), std::fs::read(path)?));
            }
        }
        files.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(files)
    };
    let before_rejection = effect_storage_snapshot()?;
    let mut invalid_signature = candidate.clone();
    *invalid_signature
        .authority_signature
        .first_mut()
        .ok_or_else(|| anyhow::anyhow!("M16Q candidate fixture has no authority signature"))? ^= 1;
    // A restarted executor must first finish local recovery while
    // the cluster can still advance. Retry only typed startup errors;
    // the exact signature refusal is the successful readiness probe.
    wait_for_read_only_recovery(
        || async {
            let result =
                rpc::execute_aft_quv_effect(&correct_rpc, &manifest.effect_id, &invalid_signature)
                    .await;
            anyhow::ensure!(
                before_rejection == effect_storage_snapshot()?,
                "M16Q rejected preparation changed per-effect storage"
            );
            match result {
                Err(error)
                    if error.downcast_ref::<tonic::Status>().is_some_and(|status| {
                        status.code() == tonic::Code::FailedPrecondition
                            && status.message() == "Invalid(\"invalid QUV member signature\")"
                    }) =>
                {
                    Ok(())
                }
                Err(error) => Err(error.context("M16Q signature preparation probe")),
                Ok(_) => Err(anyhow::anyhow!(
                    "invalid authority signature was accepted during preparation"
                )),
            }
        },
        &(),
        Duration::from_secs(120),
    )
    .await?;
    Ok(())
}

static AFT_E2E_ENV_LOCK: once_cell::sync::Lazy<tokio::sync::Mutex<()>> =
    once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(()));

struct ScopedEnv {
    prior: Vec<(&'static str, Option<OsString>)>,
}

impl ScopedEnv {
    fn set(entries: &[(&'static str, &'static str)]) -> Self {
        let prior = entries
            .iter()
            .map(|(key, value)| {
                let old = std::env::var_os(key);
                std::env::set_var(key, value);
                (*key, old)
            })
            .collect();
        Self { prior }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        for (key, value) in self.prior.drain(..).rev() {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}

async fn aft_hash_async_metrics(metrics_addr: &str) -> Result<String> {
    let response = reqwest::get(format!("http://{metrics_addr}/metrics")).await?;
    Ok(response.error_for_status()?.text().await?)
}

async fn observed_block_tip(rpc_addr: &str, floor: u64) -> Result<u64> {
    let mut tip = floor;
    // Queries are substantially faster than the one-second test cadence, so
    // the first missing successor is a stable snapshot for this restart gate.
    // The cap keeps a malformed server from making the diagnostic unbounded.
    for height in floor.saturating_add(1)..=floor.saturating_add(1_000) {
        if rpc::get_block_by_height_resilient(rpc_addr, height)
            .await?
            .is_none()
        {
            return Ok(tip);
        }
        tip = height;
    }
    Err(anyhow::anyhow!(
        "could not bound the observed block tip above height {floor}"
    ))
}

fn signed_system_transaction(
    keypair: &libp2p::identity::Keypair,
    payload: SystemPayload,
    nonce: u64,
    chain_id: ioi_types::app::ChainId,
) -> Result<ChainTransaction> {
    let public_key = keypair.public().encode_protobuf();
    let mut transaction = SystemTransaction {
        header: SignHeader {
            account_id: AccountId(account_id_from_key_material(
                SignatureSuite::ED25519,
                &public_key,
            )?),
            nonce,
            chain_id,
            tx_version: 1,
            session_auth: None,
        },
        payload,
        signature_proof: SignatureProof::default(),
    };
    let signing_bytes = transaction.to_sign_bytes().map_err(anyhow::Error::msg)?;
    transaction.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature: keypair.sign(&signing_bytes)?,
    };
    Ok(ChainTransaction::System(Box::new(transaction)))
}

fn m16q_effect_manifest(
    effect_id: &str,
    resource_id: &str,
    conflict_domain_id: &str,
    conflict_slot: u64,
    policy_root: [u8; 32],
    configuration_root: [u8; 32],
    endpoint: &ioi_crypto::sign::dilithium::MldsaKeyPair,
    discriminator: u8,
) -> Result<EffectManifestV1> {
    let mut manifest = EffectManifestV1 {
        schema_version: EffectManifestVersionV1::V1,
        effect_id: effect_id.into(),
        resource_id: resource_id.into(),
        conflict_domain_id: conflict_domain_id.into(),
        conflict_slot,
        authorization_mode: EffectAuthorizationModeV1::OnlineQueryUnanimityV0,
        online_authorization_policy_root: Some(policy_root),
        online_authorization_predecessor: Some([77; 32]),
        online_authorization_authority_mode: Some(ioi_types::app::QuvAuthorityModeV0::Unowned),
        read_set: vec![EffectResourceKeyV1 {
            key: format!("m16q/read/{discriminator}"),
            predecessor: Some([discriminator; 32]),
        }],
        write_set: vec![EffectResourceKeyV1 {
            key: format!("m16q/write/{discriminator}"),
            predecessor: None,
        }],
        idempotency_key: "pending".into(),
        request_root: [discriminator.wrapping_add(1); 32],
        predecessor_root: [discriminator.wrapping_add(2); 32],
        intent_root: [discriminator.wrapping_add(3); 32],
        expected_outcome_root: [discriminator.wrapping_add(4); 32],
        resource_profile: DurablePqAtomicRegisterV1::profile_for(endpoint)?,
        required_guarantees: GuaranteeRequirementsV1 {
            require_consensus_pq: true,
            require_externalization_pq: true,
            minimum_externalization: Some(ExternalizationModeV1::IdempotencyRegister),
            require_at_most_once: true,
            ..Default::default()
        },
        fence: EffectFenceV1::ProtocolHeight {
            configuration_hash: configuration_root,
            minimum_height: 1,
            maximum_height: 10_000,
        },
        reconciliation: ReconciliationPolicyV1::LookupByIdempotencyKey {
            maximum_observations: 3,
        },
        irreversible: true,
    };
    manifest.idempotency_key = manifest.query_unanimity_idempotency_key()?;
    manifest.validate()?;
    Ok(manifest)
}

fn m16q_candidate(
    manifest: &EffectManifestV1,
    network_id: [u8; 32],
    configuration_root: [u8; 32],
    policy_root: [u8; 32],
    domain_id: [u8; 32],
    authorizer: AccountId,
    endpoint: &ioi_crypto::sign::dilithium::MldsaKeyPair,
) -> Result<QuvCandidateV0> {
    let mut candidate = QuvCandidateV0 {
        slot: QuvSlotV0 {
            network_id,
            configuration_root,
            policy_root,
            domain_id,
            slot: manifest.conflict_slot,
            predecessor: manifest.online_authorization_predecessor.unwrap(),
            authority_mode: manifest.online_authorization_authority_mode.unwrap(),
        },
        payload_hash: manifest.commitment()?,
        authorizer,
        authority_signature: Vec::new(),
    };
    candidate.authority_signature = endpoint
        .sign(&quv_candidate_authority_signing_bytes(&candidate)?)?
        .to_bytes();
    Ok(candidate)
}

fn require_executed_nonportable_quv_receipt(
    response: &ioi_ipc::public::ExecuteAftQuvEffectResponse,
    expected_configured_members: &HashSet<AccountId>,
    expected_valid_members: &HashSet<AccountId>,
) -> Result<u64> {
    if response.portable_final_receipt {
        return Err(anyhow::anyhow!(
            "online QUV execution mislabeled its consequence audit as portable finality"
        ));
    }
    let receipt: ConsequenceReceiptV1 = serde_json::from_slice(&response.consequence_receipt_jcs)?;
    if serde_jcs::to_vec(&receipt)? != response.consequence_receipt_jcs {
        return Err(anyhow::anyhow!(
            "QUV consequence receipt is not canonical JCS"
        ));
    }
    receipt.validate()?;
    if !matches!(receipt.state, ConsequenceStateV1::Executed { .. }) {
        return Err(anyhow::anyhow!(
            "QUV consequence did not reach the Executed phase"
        ));
    }
    let Some(audit) = receipt.online_authorization_audit.as_ref() else {
        return Err(anyhow::anyhow!(
            "executed consequence omitted its nonportable live QUV audit"
        ));
    };
    if audit.portable_final_receipt || audit.profile != "aft_quv_v0" {
        return Err(anyhow::anyhow!(
            "executed consequence omitted its nonportable live QUV audit"
        ));
    }
    let evidence: QuvAcceptedAuditEvidenceV0 =
        codec::from_bytes_canonical(&audit.protocol_evidence).map_err(anyhow::Error::msg)?;
    let configured_members = evidence
        .configured_members
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let valid_members = evidence
        .valid_replies
        .iter()
        .map(|reply| reply.member)
        .collect::<HashSet<_>>();
    if evidence.configured_members.len() != configured_members.len()
        || configured_members != *expected_configured_members
        || evidence.valid_replies.len() != valid_members.len()
        || valid_members != *expected_valid_members
    {
        return Err(anyhow::anyhow!(
            "QUV audit member coverage differs for effect {} nonce={}: configured_count={} configured={:?} expected_configured={:?}; reply_count={} responding={:?} expected_responding={:?}; reply_elapsed_ms={:?}",
            receipt.manifest.effect_id,
            hex::encode(evidence.request.verifier_nonce),
            evidence.configured_members.len(),
            configured_members,
            expected_configured_members,
            evidence.valid_replies.len(),
            valid_members,
            expected_valid_members,
            evidence.valid_reply_elapsed_millis,
        ));
    }
    if evidence.valid_reply_elapsed_millis.len() != evidence.valid_replies.len() {
        return Err(anyhow::anyhow!(
            "QUV audit reply timings do not align with valid replies"
        ));
    }
    evidence
        .valid_reply_elapsed_millis
        .iter()
        .copied()
        .max()
        .ok_or_else(|| anyhow::anyhow!("QUV audit contains no valid reply timing"))
}

fn require_quv_conflict_rejection(error: &anyhow::Error) -> Result<()> {
    let rendered = format!("{error:#}");
    if error.downcast_ref::<tonic::Status>().is_some_and(|status| {
        status.code() == tonic::Code::Aborted
            && status
                .metadata()
                .get("ioi-quv-refusal")
                .is_some_and(|value| value == "conflict-disclosed-v0")
    }) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "concurrent QUV request failed for a reason other than authenticated conflict disclosure: {rendered}"
        ))
    }
}

/// Post-decision allowance for a singleton effect racing terminal replay on
/// the same executor. delta_rt (5000ms) is the rooted decision interval; the
/// remaining work is the durable claim, register put and RPC return. Retained
/// M16Q runs show 310-980ms of such overhead (sole_correct 5310-5352ms,
/// unrelated 5875ms, conflict 5977ms); 2000ms is about twice the largest
/// observed value and 40% of the rooted continuation window (5000ms), so a
/// replay-induced stall of even one extra RPC round trip cannot hide in it.
/// Upper bound for the chain to pass the position-0 expiry fence; sized for
/// the fence above at the slowest retained block cadence (about 8 s/block).
const M16Q_EXPIRY_WAIT_SECS: u64 = 900;
/// Non-starvation fence for one unrelated singleton to finish end to end
/// (RPC call to executed receipt) while the same executor serves terminal
/// replay pressure: three rooted decision intervals. Sized from retained
/// measurements, not from the theorem: unflooded singletons take 5.6–6.6 s,
/// and under replay pressure 8.4 s and 11.0 s were measured (reserved-receipt
/// initialization, admission behind member work, finalization under store
/// contention). A refusal, timeout or freeze is never counted as progress.
const M16Q_CONCURRENT_REPLAY_SLACK_MS: u64 = 10_000;
/// Operator-declared reply envelope for this host's deployment profile
/// (see the flood fixture's note): measured flood-phase maximum 4010 ms,
/// declared 4500 ms, rooted interval 5000 ms.
const M16Q_QUALIFIED_ENVELOPE_MS: u64 = 4_500;

/// Exact typed status an executor returns when its durable expected-head
/// preflight refuses a candidate before any member push.
const QUV_UNEXPECTED_HEAD_STATUS: &str =
    "Invalid(\"QUV candidate differs from the locally expected history coordinate\")";
/// The rooted initial coordinate refuses a wrong predecessor at the bootstrap
/// slot before any head derivation; later slots refuse through the derived
/// expected head. Both are typed, non-mutating expected-head refusals.
const QUV_BOOTSTRAP_BOUNDARY_STATUS: &str =
    "Invalid(\"QUV request differs from the rooted bootstrap boundary\")";

struct QuvForkFixture {
    tag: &'static str,
    mode: QuvAuthorityModeV0,
    order: &'static str,
    domain: [u8; 32],
    policy_root: [u8; 32],
    position_a: usize,
    position_b: usize,
    manifest_a: EffectManifestV1,
    manifest_b: EffectManifestV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QuvOperationStart {
    process_index: usize,
    payload: [u8; 32],
    independent_preparation: bool,
}

/// Retains every `operation_started` diagnostic from every orchestration
/// process. A lagged subscription is recorded and fails the observation:
/// "no operation started" can only be claimed over a complete stream.
struct QuvOperationStartLog {
    starts: std::sync::Arc<std::sync::Mutex<Vec<QuvOperationStart>>>,
    lagged: std::sync::Arc<std::sync::atomic::AtomicU64>,
    drains: Vec<tokio::task::JoinHandle<()>>,
}

impl QuvOperationStartLog {
    fn drain(cluster: &TestCluster) -> Self {
        let starts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let lagged = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut drains = Vec::new();
        for (process_index, guard) in cluster.validators.iter().enumerate() {
            let (mut logs, _, _) = guard.validator().subscribe_logs();
            let starts = starts.clone();
            let lagged = lagged.clone();
            drains.push(tokio::spawn(async move {
                loop {
                    match logs.recv().await {
                        Ok(line) => {
                            if !line.contains("operation_started") {
                                continue;
                            }
                            let Some(start) = parse_quv_operation_start(process_index, &line)
                            else {
                                continue;
                            };
                            starts
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .push(start);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            lagged.fetch_add(count, std::sync::atomic::Ordering::SeqCst);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                    }
                }
            }));
        }
        Self {
            starts,
            lagged,
            drains,
        }
    }

    fn len(&self) -> usize {
        self.starts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Operation starts retained since `from`, refusing a lagged stream.
    fn since(&self, from: usize) -> Result<Vec<QuvOperationStart>> {
        let lagged = self.lagged.load(std::sync::atomic::Ordering::SeqCst);
        if lagged != 0 {
            return Err(anyhow::anyhow!(
                "operation-start observation lost {lagged} log lines; no-push evidence is unavailable"
            ));
        }
        let starts = self
            .starts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(starts
            .get(from..)
            .map(<[QuvOperationStart]>::to_vec)
            .unwrap_or_default())
    }

    fn stop(self) {
        for drain in self.drains {
            drain.abort();
        }
    }
}

#[derive(Clone, Debug)]
struct NetworkEventRecord {
    process_index: usize,
    event: String,
    peer: Option<String>,
    local_peer: Option<String>,
    claimed_account: Option<String>,
    account: Option<String>,
    error: Option<String>,
}

/// Retains selected `target = "network"` diagnostics from every orchestration
/// process (across restarts: the guard's log channel outlives the child). Used
/// by the M17Q-007 status-claim case as workload evidence that a Byzantine
/// status claim was actually advertised and refused; it authorizes nothing.
struct NetworkEventLog {
    records: std::sync::Arc<std::sync::Mutex<Vec<NetworkEventRecord>>>,
    lagged: std::sync::Arc<std::sync::atomic::AtomicU64>,
    drains: Vec<tokio::task::JoinHandle<()>>,
}

impl NetworkEventLog {
    fn drain(cluster: &TestCluster, events: &'static [&'static str]) -> Self {
        let records = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let lagged = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut drains = Vec::new();
        for (process_index, guard) in cluster.validators.iter().enumerate() {
            let (mut logs, _, _) = guard.validator().subscribe_logs();
            let records = records.clone();
            let lagged = lagged.clone();
            drains.push(tokio::spawn(async move {
                loop {
                    match logs.recv().await {
                        Ok(line) => {
                            if !events.iter().any(|event| line.contains(event)) {
                                continue;
                            }
                            let Some(record) = parse_network_event(process_index, &line, events)
                            else {
                                continue;
                            };
                            records
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .push(record);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            lagged.fetch_add(count, std::sync::atomic::Ordering::SeqCst);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                    }
                }
            }));
        }
        Self {
            records,
            lagged,
            drains,
        }
    }

    fn len(&self) -> usize {
        self.records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Records retained since `from`, refusing a lagged stream.
    fn since(&self, from: usize) -> Result<Vec<NetworkEventRecord>> {
        let lagged = self.lagged.load(std::sync::atomic::Ordering::SeqCst);
        if lagged != 0 {
            return Err(anyhow::anyhow!(
                "network-event observation lost {lagged} log lines; claim evidence is unavailable"
            ));
        }
        let records = self
            .records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(records
            .get(from..)
            .map(<[NetworkEventRecord]>::to_vec)
            .unwrap_or_default())
    }

    fn stop(self) {
        for drain in self.drains {
            drain.abort();
        }
    }
}

fn parse_network_event(
    process_index: usize,
    line: &str,
    events: &[&str],
) -> Option<NetworkEventRecord> {
    let record: serde_json::Value = serde_json::from_str(line).ok()?;
    if record["target"] != "network" {
        return None;
    }
    let fields = &record["fields"];
    let event = fields["event"].as_str()?;
    if !events.contains(&event) {
        return None;
    }
    let text = |name: &str| fields[name].as_str().map(str::to_string);
    Some(NetworkEventRecord {
        process_index,
        event: event.to_string(),
        peer: text("peer").or_else(|| text("_peer")),
        local_peer: text("local_peer"),
        claimed_account: text("claimed_account"),
        account: text("account"),
        error: text("error"),
    })
}

fn parse_quv_operation_start(process_index: usize, line: &str) -> Option<QuvOperationStart> {
    let record: serde_json::Value = serde_json::from_str(line).ok()?;
    if record["target"] != "quv" {
        return None;
    }
    let fields = &record["fields"];
    if fields["event"] != "operation_started" {
        return None;
    }
    let payload = hex::decode(fields["payload"].as_str()?).ok()?;
    Some(QuvOperationStart {
        process_index,
        payload: payload.try_into().ok()?,
        independent_preparation: fields["independent_preparation"].as_bool()?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QuvConflictMeasurement {
    accepts: u8,
    rejections: u8,
    durable_records: u8,
    rejected_resources_unchanged: bool,
}

/// Measure conflict evidence from (rpc_succeeded, register_record_present)
/// pairs. Nothing here is inferred from one field to another.
fn measure_quv_conflict_outcomes(
    observations: impl IntoIterator<Item = (bool, bool)>,
) -> QuvConflictMeasurement {
    let mut measured = QuvConflictMeasurement {
        accepts: 0,
        rejections: 0,
        durable_records: 0,
        rejected_resources_unchanged: true,
    };
    for (succeeded, record_present) in observations {
        if succeeded {
            measured.accepts += 1;
        } else {
            measured.rejections += 1;
            if record_present {
                measured.rejected_resources_unchanged = false;
            }
        }
        if record_present {
            measured.durable_records += 1;
        }
    }
    measured
}

#[test]
fn quv_conflict_measurement_reports_observed_records_not_rpc_outcomes() {
    let one = measure_quv_conflict_outcomes([(true, true), (false, false)]);
    assert_eq!(
        one,
        QuvConflictMeasurement {
            accepts: 1,
            rejections: 1,
            durable_records: 1,
            rejected_resources_unchanged: true
        }
    );
    let none = measure_quv_conflict_outcomes([(false, false), (false, false)]);
    assert_eq!(none.durable_records, 0);
    assert_eq!((none.accepts, none.rejections), (0, 2));
    // A rejected RPC whose register nevertheless holds a record is reported
    // as a mutation, and an accepted RPC without a record is not counted.
    let leaked = measure_quv_conflict_outcomes([(true, true), (false, true)]);
    assert_eq!(leaked.durable_records, 2);
    assert!(!leaked.rejected_resources_unchanged);
    let missing = measure_quv_conflict_outcomes([(true, false), (false, false)]);
    assert_eq!((missing.accepts, missing.durable_records), (1, 0));
}

#[test]
fn quv_operation_start_parser_requires_exact_diagnostic_shape() {
    let payload = "11".repeat(32);
    let line = format!(
        r#"{{"timestamp":"2026-09-06T00:00:00Z","level":"DEBUG","fields":{{"event":"operation_started","independent_preparation":false,"nonce":"{}","payload":"{payload}"}},"target":"quv"}}"#,
        "22".repeat(32)
    );
    let start = parse_quv_operation_start(3, &line).unwrap();
    assert_eq!(start.process_index, 3);
    assert_eq!(start.payload, [0x11; 32]);
    assert!(!start.independent_preparation);
    for (before, after) in [
        (r#""target":"quv""#, r#""target":"network""#),
        ("operation_started", "operation_finished"),
        (
            r#""independent_preparation":false"#,
            r#""independent_preparation":"false""#,
        ),
        (payload.as_str(), "zz"),
    ] {
        assert!(
            parse_quv_operation_start(0, &line.replace(before, after)).is_none(),
            "{before}"
        );
    }
    assert!(parse_quv_operation_start(0, "plain text operation_started").is_none());
}

/// Submit a validly signed candidate whose slot coordinate the executor's
/// durable history cannot admit. The refusal must be the exact typed
/// expected-head status, and rejected preparation must not allocate any
/// per-effect receipt or register file.
async fn require_quv_unexpected_head_refusal(
    executor_rpc: &str,
    manifest: &EffectManifestV1,
    candidate: &QuvCandidateV0,
    runtime_root: &std::path::Path,
) -> Result<()> {
    let snapshot = || -> Result<Vec<(std::path::PathBuf, Vec<u8>)>> {
        let mut files = Vec::new();
        for relative in ["consequence/effects", "quv-external-resource/records"] {
            let directory = runtime_root.join(relative);
            let entries = match std::fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            for entry in entries {
                let path = entry?.path();
                files.push((path.clone(), std::fs::read(path)?));
            }
        }
        files.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(files)
    };
    let before = snapshot()?;
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        rpc::execute_aft_quv_effect(executor_rpc, &manifest.effect_id, candidate),
    )
    .await
    .map_err(|_| anyhow::anyhow!("expected-head refusal probe timed out"))?;
    anyhow::ensure!(
        before == snapshot()?,
        "refused predecessor candidate changed per-effect storage"
    );
    match result {
        Err(error) => require_quv_unexpected_head_status(&error),
        Ok(_) => Err(anyhow::anyhow!(
            "candidate {} with an unexpected predecessor was accepted",
            manifest.effect_id
        )),
    }
}

/// Typed pre-push refusal of a forked candidate for an already executed
/// slot. Returns which rule refused it: `expected_head` (rooted initial
/// coordinate or derived head mismatch) or `claim_index` (the executor's
/// stable-key claim index already names the accepted effect `claimed_by`).
/// Any other outcome, including a claim naming a different effect, is an
/// error. Both rules refuse before any member interaction and mutate nothing.
async fn require_quv_fork_refusal(
    executor_rpc: &str,
    manifest: &EffectManifestV1,
    candidate: &QuvCandidateV0,
    runtime_root: &std::path::Path,
    claimed_by: &str,
) -> Result<&'static str> {
    let snapshot = || -> Result<Vec<(std::path::PathBuf, Vec<u8>)>> {
        let mut files = Vec::new();
        for relative in ["consequence/effects", "quv-external-resource/records"] {
            let directory = runtime_root.join(relative);
            let entries = match std::fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            for entry in entries {
                let path = entry?.path();
                files.push((path.clone(), std::fs::read(path)?));
            }
        }
        files.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(files)
    };
    let before = snapshot()?;
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        rpc::execute_aft_quv_effect(executor_rpc, &manifest.effect_id, candidate),
    )
    .await
    .map_err(|_| anyhow::anyhow!("fork refusal probe timed out"))?;
    anyhow::ensure!(
        before == snapshot()?,
        "refused fork candidate changed per-effect storage"
    );
    match result {
        Err(error) => require_quv_fork_refusal_status(&error, &manifest.effect_id, claimed_by),
        Ok(_) => Err(anyhow::anyhow!(
            "forked candidate {} was accepted",
            manifest.effect_id
        )),
    }
}

fn require_quv_fork_refusal_status(
    error: &anyhow::Error,
    effect_id: &str,
    claimed_by: &str,
) -> Result<&'static str> {
    if require_quv_unexpected_head_status(error).is_ok() {
        return Ok("expected_head");
    }
    let claim_message = format!(
        "ConflictSlotAlreadyClaimed {{ effect_id: {effect_id:?}, claimed_by: {claimed_by:?} }}"
    );
    if error.downcast_ref::<tonic::Status>().is_some_and(|status| {
        status.code() == tonic::Code::FailedPrecondition && status.message() == claim_message
    }) {
        return Ok("claim_index");
    }
    Err(anyhow::anyhow!(
        "forked candidate failed for a reason other than the typed expected-head or exact claim-index refusal: {error:#}"
    ))
}

#[test]
fn quv_fork_refusal_status_requires_exact_typed_rules() {
    let head = anyhow::Error::new(tonic::Status::failed_precondition(
        QUV_UNEXPECTED_HEAD_STATUS,
    ));
    assert_eq!(
        require_quv_fork_refusal_status(&head, "b", "a").unwrap(),
        "expected_head"
    );
    let claim = anyhow::Error::new(tonic::Status::failed_precondition(
        "ConflictSlotAlreadyClaimed { effect_id: \"b\", claimed_by: \"a\" }",
    ));
    assert_eq!(
        require_quv_fork_refusal_status(&claim, "b", "a").unwrap(),
        "claim_index"
    );
    for wrong in [
        anyhow::Error::new(tonic::Status::failed_precondition(
            "ConflictSlotAlreadyClaimed { effect_id: \"b\", claimed_by: \"other\" }",
        )),
        anyhow::Error::new(tonic::Status::aborted(
            "ConflictSlotAlreadyClaimed { effect_id: \"b\", claimed_by: \"a\" }",
        )),
        anyhow::anyhow!("ConflictSlotAlreadyClaimed {{ effect_id: \"b\", claimed_by: \"a\" }}"),
        anyhow::Error::new(tonic::Status::failed_precondition("FenceExpired")),
    ] {
        assert!(require_quv_fork_refusal_status(&wrong, "b", "a").is_err());
    }
}

fn require_quv_unexpected_head_status(error: &anyhow::Error) -> Result<()> {
    let rendered = format!("{error:#}");
    if error.downcast_ref::<tonic::Status>().is_some_and(|status| {
        status.code() == tonic::Code::FailedPrecondition
            && (status.message() == QUV_UNEXPECTED_HEAD_STATUS
                || status.message() == QUV_BOOTSTRAP_BOUNDARY_STATUS)
    }) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "candidate failed for a reason other than the typed expected-head refusal: {rendered}"
        ))
    }
}

#[test]
fn quv_unexpected_head_assertion_requires_exact_typed_status() {
    let typed = anyhow::Error::new(tonic::Status::failed_precondition(
        QUV_UNEXPECTED_HEAD_STATUS,
    ))
    .context("executor request");
    require_quv_unexpected_head_status(&typed).unwrap();
    require_quv_unexpected_head_status(&anyhow::Error::new(tonic::Status::failed_precondition(
        QUV_BOOTSTRAP_BOUNDARY_STATUS,
    )))
    .unwrap();
    for error in [
        anyhow::anyhow!(QUV_UNEXPECTED_HEAD_STATUS),
        anyhow::Error::new(tonic::Status::aborted(QUV_UNEXPECTED_HEAD_STATUS)),
        anyhow::Error::new(tonic::Status::failed_precondition(
            "Invalid(\"invalid QUV member signature\")",
        )),
        anyhow::Error::new(tonic::Status::failed_precondition(
            "QUV candidate differs from the locally expected history coordinate",
        )),
    ] {
        assert!(require_quv_unexpected_head_status(&error).is_err());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_aft_leader_rotation() -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    println!("--- Running Aft deterministic Leader Rotation E2E Test ---");
    build_test_artifacts();

    // 1. Setup a 3-node cluster
    let cluster = TestCluster::builder()
        .with_validators(3)
        .with_consensus_type("Aft")
        .with_state_tree("IAVL")
        .with_chain_id(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::ED25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(move |builder, keys| {
            let mut validators = Vec::new();
            for key in keys {
                let account_id = builder.add_identity(key);
                let pk = key.public().encode_protobuf();
                let hash = account_id_from_key_material(SignatureSuite::ED25519, &pk).unwrap();

                validators.push(ValidatorV1 {
                    account_id,
                    weight: 1, // Equal weight for round-robin
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ED25519,
                        public_key_hash: hash,
                        since_height: 0,
                    },
                });
            }
            // Deterministic sort for stable leader schedule
            validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

            let vs = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: validators.len() as u128,
                    validators,
                },
                next: None,
            };
            builder.set_validators(&vs);

            // Fast blocks for testing
            let timing_params = BlockTimingParams {
                base_interval_secs: 1,
                min_interval_secs: 1,
                max_interval_secs: 5,
                target_gas_per_block: 1_000_000,
                retarget_every_blocks: 0,
                ..Default::default()
            };
            let timing_runtime = BlockTimingRuntime {
                effective_interval_secs: timing_params.base_interval_secs,
                ..Default::default()
            };
            builder.set_block_timing(&timing_params, &timing_runtime);
        })
        .build()
        .await?;

    // [FIX] Spawn log printers for debugging - Handle closed channels gracefully
    for (i, guard) in cluster.validators.iter().enumerate() {
        let (mut orch_logs, mut work_logs, _) = guard.validator().subscribe_logs();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                     res = orch_logs.recv() => {
                        match res {
                            Ok(line) => println!("[Node {} ORCH] {}", i, line),
                            Err(_) => break, // Channel closed, exit loop
                        }
                     }
                     res = work_logs.recv() => {
                        match res {
                            Ok(line) => println!("[Node {} WORK] {}", i, line),
                            Err(_) => break, // Channel closed, exit loop
                        }
                     }
                }
            }
        });
    }

    let rpc_addr = &cluster.validators[0].validator().rpc_addr;

    let test_logic = async {
        // 2. Wait for chain progression
        let target_height = 6;
        println!("Waiting for height {}...", target_height);
        wait_for_height(rpc_addr, target_height, Duration::from_secs(30)).await?;

        // 3. Analyze Blocks
        let mut producers = HashSet::new();
        let mut last_height = 0;

        for h in 1..=target_height {
            // [FIX] Add explicit retry loop with logging for the test
            let mut block = None;
            for _ in 0..10 {
                match rpc::get_block_by_height_resilient(rpc_addr, h).await {
                    Ok(Some(b)) => {
                        block = Some(b);
                        break;
                    }
                    Ok(None) => {
                        println!("Block {} not found yet, retrying...", h);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(e) => {
                        println!("RPC error for block {}: {}, retrying...", h, e);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
            let block =
                block.ok_or_else(|| anyhow::anyhow!("Block {} not found after retries", h))?;

            println!(
                "Block #{}: Producer 0x{}, View {}",
                h,
                hex::encode(&block.header.producer_account_id.0[0..4]),
                block.header.view
            );

            // Verify height continuity
            if block.header.height != last_height + 1 {
                return Err(anyhow::anyhow!("Height gap detected"));
            }
            last_height = block.header.height;

            producers.insert(block.header.producer_account_id);
        }

        // 4. Verify Rotation
        // With 3 validators and 6 blocks, we expect at least 2 unique producers (ideally 3).
        // If only 1 produced all blocks, round-robin failed.
        if producers.len() < 2 {
            return Err(anyhow::anyhow!(
                "Leader rotation failed: observed {:?} unique producers out of 3 validators",
                producers.len()
            ));
        }

        println!("--- Aft deterministic Leader Rotation Test Passed ---");
        Ok(())
    };

    let result = test_logic.await;

    // Always shutdown
    if let Err(e) = cluster.shutdown().await {
        eprintln!("Error shutting down cluster: {}", e);
    }

    result
}

fn emit_handoff_expectations(
    old: &ioi_types::app::ValidatorSetV1,
    successor: &ioi_types::app::ValidatorSetV1,
    domain: [u8; 32],
    delta_rt_millis: u64,
) -> Result<()> {
    let accounts = |set: &ioi_types::app::ValidatorSetV1| {
        set.validators
            .iter()
            .map(|member| hex::encode(member.account_id.as_ref()))
            .collect::<Vec<_>>()
            .join(",")
    };
    eprintln!("[M16Q-HANDOFF] old_root={} domain={} expected_old_members={} expected_successors={} decision_millis={} qualified_reply_millis={}",
        hex::encode(ioi_types::app::canonical_validator_set_hash(old).map_err(anyhow::Error::msg)?),
        hex::encode(domain), accounts(old), accounts(successor), delta_rt_millis,
        delta_rt_millis.saturating_mul(4).div_ceil(5));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_aft_quv_disjoint_successors_install_live_handoff_before_activation() -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    build_test_artifacts();
    let fixture = tempfile::tempdir()?;
    let source_path = fixture.path().join("handoff.scale");
    let draft_path = fixture.path().join("handoff.scale.draft");
    let source_path_string = source_path.to_string_lossy().into_owned();
    let activation_height = 3;
    let delta_rt_millis = 30_000;
    let continuation_millis = 5_000;
    let effect_conflict_domain_id = "domain://aft-e2e/quv-effect";
    let effect_domain =
        conflict_domain_id_commitment(effect_conflict_domain_id).map_err(anyhow::Error::msg)?;
    let effect_delta_rt_millis = 5_000;
    let effect_continuation_millis = 5_000;
    let _env = ScopedEnv::set(&[
        ("IOI_TEST_BUILD_PROFILE", "release"),
        ("IOI_TEST_VALIDATOR_LAUNCH_CONCURRENCY", "2"),
        ("IOI_TEST_FULL_MESH_BOOTNODES", "1"),
        // The cluster intentionally contains four pre-active processes whose
        // canonical height remains zero until their own live QUV install.
        // The test below waits for the canonical handoff draft and then checks
        // every successor boundary explicitly, so the generic all-process
        // shared-tip predicate is inapplicable here.
        ("IOI_TEST_SKIP_SHARED_TIP_WAIT", "1"),
        ("IOI_TEST_READY_HEIGHT_LAG_MAX", "1"),
        ("IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS", "180"),
        ("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS", "30"),
        ("IOI_TEST_SIGNER_STARTUP_TIMEOUT_SECS", "120"),
        ("IOI_BENCH_BLOCK_INTERVAL_MS", "1000"),
        ("IOI_AFT_BLOCK_DIRECT_RELAY", "1"),
    ]);

    let mut cluster = TestCluster::builder()
        // Both the old live-ordering configuration and its fully disjoint
        // successor retain the normative n=3f+1 geometry. QUV changes the
        // effect-authorization/handoff theorem; it does not launder an
        // undersized ordering committee into a qualified BFT profile.
        .with_validators(8)
        .with_consensus_type("Aft")
        .with_aft_safety_mode(AftSafetyMode::ClassicBft)
        .with_state_tree("IAVL")
        .with_chain_id(0xA19)
        .with_quv_handoff_profile(
            4,
            activation_height,
            delta_rt_millis,
            continuation_millis,
            source_path_string,
        )
        .with_quv_domain_policy(AftQuvDomainPolicyV0 {
            authority_slots: 256,
            preparation: ioi_types::app::QuvPreparationPolicyV0::Independent {
                max_attempts_per_slot: 2,
                service_millis: (effect_delta_rt_millis as u64)
                    .saturating_add(effect_continuation_millis as u64),
                readiness_millis: 1_000_000,
            },
            bootstrap: ioi_types::app::QuvDomainBootstrapV0::Fixed {
                initial_slot: 1,
                predecessor: [77; 32],
            },
            domain_id: effect_domain,
            authority_mode: QuvAuthorityModeV0::Unowned,
            owner: None,
            delta_rt_millis: effect_delta_rt_millis,
            qualified_delta_rt_envelope_millis: 4_000,
            qualified_max_configured_members: 4,
            continuation_millis: effect_continuation_millis,
            operation_service_millis: (effect_delta_rt_millis as u64)
                .saturating_add(effect_continuation_millis as u64),
            push_admission: ioi_types::app::QuvPushAdmissionPolicyV0 {
                max_requests_per_identity: 64,
                window_millis: effect_delta_rt_millis as u64,
            },
        })
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 0xA19,
            grace_period_blocks: 0,
            accept_staged_during_grace: false,
            allowed_target_suites: vec![SignatureSuite::ML_DSA_44],
            allow_downgrade: false,
        }))
        .build()
        .await?;

    let run = async {
        let mut keyed = cluster
            .validators
            .iter()
            .enumerate()
            .map(|(index, guard)| {
                let keypair = guard
                    .validator()
                    .pqc_keypair
                    .as_ref()
                    .expect("QUV fixture must retain every ML-DSA validator key");
                let public = keypair.public_key().to_bytes();
                let account = AccountId(account_id_from_key_material(
                    SignatureSuite::ML_DSA_44,
                    &public,
                )?);
                Ok((account, index, public))
            })
            .collect::<Result<Vec<_>>>()?;
        keyed.sort_by_key(|(account, _, _)| *account);

        let old = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: 4,
            validators: keyed[..4]
                .iter()
                .map(|(account, _, _)| ValidatorV1 {
                    account_id: *account,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ML_DSA_44,
                        public_key_hash: account.0,
                        since_height: 0,
                    },
                })
                .collect(),
        };
        let successor = ValidatorSetV1 {
            effective_from_height: activation_height,
            total_weight: 4,
            validators: keyed[4..]
                .iter()
                .map(|(account, _, _)| ValidatorV1 {
                    account_id: *account,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ML_DSA_44,
                        public_key_hash: account.0,
                        since_height: activation_height,
                    },
                })
                .collect(),
        };
        let old_root =
            ioi_types::app::canonical_validator_set_hash(&old).map_err(anyhow::Error::msg)?;
        let successor_root =
            ioi_types::app::canonical_validator_set_hash(&successor).map_err(anyhow::Error::msg)?;
        let network_id = ioi_crypto::algorithms::hash::sha256(cluster.genesis_content.as_bytes())?;
        let domain_id =
            quv_handoff_domain_id(network_id, old_root, successor_root, activation_height)?;
        emit_handoff_expectations(&old, &successor, domain_id, delta_rt_millis)?;
        let policy_root = quv_policy_root(
            domain_id,
            QuvAuthorityModeV0::Owned,
            Some(keyed[0].0),
            delta_rt_millis,
            continuation_millis,
        &ioi_types::app::QuvDomainBootstrapV0::HandoffBoundary { activation_height },
&ioi_types::app::QuvPreparationPolicyV0::OneShot,
    (delta_rt_millis as u64).saturating_add(continuation_millis as u64),
 256,
 ioi_types::app::QuvPushAdmissionPolicyV0 { max_requests_per_identity: 64, window_millis: delta_rt_millis as u64 },)?;

        let interrupted_index = keyed[7].1;
        let interrupted_account = keyed[7].0;
        // Drain every successor's broadcast receiver from the moment the
        // ceremony begins. Waiting on these receivers sequentially after the
        // handoff can lose a one-time activation record to broadcast lag even
        // though that process is already producing successor blocks.
        let successor_activation_waiters = keyed[4..]
            .iter()
            .map(|(_, index, _)| {
                let index = *index;
                let (mut orchestration, _, _) =
                    cluster.validators[index].validator().subscribe_logs();
                let expected = if index == interrupted_index {
                    vec!["Recovered QUV successor authority from its durable local install gate"]
                } else {
                    vec![
                        "Activated successor from its local live old-root QUV install",
                        "Recovered QUV successor authority from its durable local install gate",
                    ]
                };
                tokio::spawn(async move {
                    assert_log_contains_any(
                        &format!("QUV successor node {index}"),
                        &mut orchestration,
                        &expected,
                    )
                    .await
                })
            })
            .collect::<Vec<_>>();
        let envelope = wait_for(
            "the exact unsigned QUV handoff owner-ceremony draft",
            Duration::from_millis(250),
            Duration::from_secs(90),
            || {
                let draft_path = draft_path.clone();
                async move {
                    let Ok(bytes) = std::fs::read(&draft_path) else {
                        return Ok(None);
                    };
                    match codec::from_bytes_canonical::<QuvConfigurationHandoffEnvelopeV0>(&bytes) {
                        Ok(envelope) => Ok(Some(envelope)),
                        Err(_) => Ok(None),
                    }
                }
            },
        )
        .await?;
        let drafted_successor_root =
            ioi_types::app::canonical_validator_set_hash(&envelope.handoff.successor_set)
                .map_err(anyhow::Error::msg)?;
        if envelope.handoff.network_id != network_id
            || envelope.handoff.old_configuration_root != old_root
            || drafted_successor_root != successor_root
            || envelope.handoff.activation_height != activation_height
            || envelope.handoff.state_height != activation_height - 1
            || envelope.handoff.boundary_qc.height != envelope.handoff.state_height
            || envelope.handoff.boundary_qc.block_hash != envelope.handoff.state_block_hash
            || envelope.handoff.boundary_qc.signatures.len() != 3
            || envelope.candidate.slot.domain_id != domain_id
            || envelope.candidate.slot.policy_root != policy_root
            || envelope.candidate.authorizer != keyed[0].0
            || !envelope.candidate.authority_signature.is_empty()
        {
            return Err(anyhow::anyhow!(
                "pre-publication QUV handoff draft differs from the rooted ceremony"
            ));
        }
        validate_quv_handoff_candidate(&envelope.candidate, &envelope.handoff)?;

        // Restart one successor before any signed source or local install
        // exists. Its next attempt is armed to exit in the precise recoverable
        // window after the new handoff state is durable but before the
        // separately rooted anchor advances.
        let interrupted_state = cluster.validators[interrupted_index]
            .validator()
            .state_dir()
            .join("aft-pq-outbox")
            .join(hex::encode(old_root))
            .join(hex::encode(interrupted_account.as_ref()))
            .join("quv-handoff-v0.scale");
        let preinstall_state = wait_for(
            "the interrupted successor's empty durable handoff state",
            Duration::from_millis(50),
            Duration::from_secs(30),
            || {
                let path = interrupted_state.clone();
                async move { Ok(std::fs::read(path).ok()) }
            },
        )
        .await?;
        let crash_marker = fixture.path().join("handoff-state-durable.marker");
        cluster.validators[interrupted_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[interrupted_index]
            .validator_mut()
            .set_orchestration_restart_env(
                "IOI_TESTING_AFT_QUV_HANDOFF_CRASH_AFTER_STATE_MARKER",
                crash_marker.to_string_lossy().as_ref(),
            )?;
        cluster.validators[interrupted_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        wait_for(
            "the pre-install successor restart to expose its RPC without authority",
            Duration::from_millis(100),
            Duration::from_secs(30),
            || {
                let rpc_addr = cluster.validators[interrupted_index]
                    .validator()
                    .rpc_addr
                    .clone();
                async move { Ok(rpc::get_status(&rpc_addr).await.ok().map(|_| ())) }
            },
        )
        .await?;
        let owner_key_path = cluster.validators[keyed[0].1]
            .validator()
            .state_dir()
            .join("pqc_key.json");
        let signed_path = source_path.with_extension("signed.scale");
        let signed_audit = sign_handoff_draft(
            &draft_path,
            &owner_key_path,
            &signed_path,
            false,
        )?;
        if signed_audit.portable_final_receipt
            || signed_audit.process_local_authorization_present
            || !signed_audit.owner_signature_present
        {
            return Err(anyhow::anyhow!(
                "operator ceremony mislabeled replayable handoff input as online authority"
            ));
        }
        install_signed_handoff(
            &signed_path,
            &owner_key_path,
            &source_path,
            false,
        )?;

        wait_for(
            "the QUV handoff state-durable/anchor-pending crash marker",
            Duration::from_millis(25),
            Duration::from_secs(90),
            || {
                let marker = crash_marker.clone();
                async move { Ok(marker.is_file().then_some(())) }
            },
        )
        .await?;
        // Clear the exited child handle, then restart from the state that is
        // exactly one generation ahead of its valid old anchor. Recovery may
        // complete only that transition.
        cluster.validators[interrupted_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[interrupted_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;

        let first_successor_rpc = cluster.validators[keyed[4].1].validator().rpc_addr.clone();
        let synchronized_boundary = wait_for(
            "the first successor's synchronized QUV boundary block",
            Duration::from_millis(250),
            Duration::from_secs(90),
            || {
                let rpc_addr = first_successor_rpc.clone();
                async move {
                    rpc::get_block_by_height_resilient(&rpc_addr, activation_height - 1).await
                }
            },
        )
        .await?;
        let synchronized_hash: [u8; 32] = synchronized_boundary
            .header
            .hash()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("synchronized QUV block hash is not 32 bytes"))?;
        if synchronized_boundary.header.height != envelope.handoff.state_height
            || synchronized_hash != envelope.handoff.state_block_hash
            || synchronized_boundary.header.state_root.0 != envelope.handoff.state_root
        {
            let mut observed = Vec::new();
            for (index, guard) in cluster.validators.iter().enumerate() {
                let role = if keyed[..4]
                    .iter()
                    .any(|(_, member_index, _)| *member_index == index)
                {
                    "old"
                } else {
                    "successor"
                };
                match rpc::get_block_by_height_resilient(
                    &guard.validator().rpc_addr,
                    activation_height - 1,
                )
                .await
                {
                    Ok(Some(block)) => observed.push(format!(
                        "node{index}:{role}:hash={}:root={}:sig={}:view={}:producer={}",
                        hex::encode(block.header.hash()?),
                        hex::encode(&block.header.state_root.0),
                        block.header.signature.len(),
                        block.header.view,
                        hex::encode(block.header.producer_account_id.as_ref()),
                    )),
                    Ok(None) => observed.push(format!("node{index}:{role}:missing")),
                    Err(error) => observed.push(format!("node{index}:{role}:rpc-error({error:#})")),
                }
            }
            return Err(anyhow::anyhow!(
                "successor synchronized a different QUV boundary: height={}/{} hash={}/{} state_root={}/{} signature_len={} guardian={} seal={}; all_nodes=[{}]",
                synchronized_boundary.header.height,
                envelope.handoff.state_height,
                hex::encode(synchronized_hash),
                hex::encode(envelope.handoff.state_block_hash),
                hex::encode(&synchronized_boundary.header.state_root.0),
                hex::encode(&envelope.handoff.state_root),
                synchronized_boundary.header.signature.len(),
                synchronized_boundary.header.guardian_certificate.is_some(),
                synchronized_boundary.header.sealed_finality_proof.is_some(),
                observed.join(", "),
            ));
        }

        for waiter in successor_activation_waiters {
            waiter
                .await
                .map_err(|error| anyhow::anyhow!("QUV activation log waiter failed: {error}"))??;
        }
        // Retired old-root processes have no post-activation role. Stop them
        // before measuring successor liveness so an eight-process fixture on
        // a four-core qualification host does not turn retired busy work into
        // an undeclared scheduler adversary. This also strengthens the
        // handoff check: successor progress must not depend on old members.
        for (_, index, _) in &keyed[..4] {
            cluster.validators[*index]
                .validator_mut()
                .kill_orchestration()
                .await?;
        }
        for (_, index, _) in &keyed[4..] {
            let index = *index;
            let (mut log, _, _) = cluster.validators[index].validator().subscribe_logs();
            tokio::spawn(async move {
                while let Ok(line) = log.recv().await {
                    let normalized = line.to_ascii_lowercase();
                    if normalized.contains("activated successor")
                        || normalized.contains("recovered quv successor")
                        || normalized.contains("canonical head is stale")
                        || normalized.contains("node frozen")
                        || normalized.contains("refusing timeout-certificate transition")
                    {
                        println!("[M16Q-HANDOFF][node{index}] {line}");
                    }
                }
            });
        }
        // Only the rooted successor set is required to carry post-handoff
        // ordering. Retired members are not implicitly observers: that would
        // give their retired validator credentials an undocumented role after
        // the network is reconfigured. Their fail-closed restart behavior is
        // asserted below; a future observer role needs separate credentials.
        for (_, index, _) in &keyed[4..] {
            let index = *index;
            let guard = &cluster.validators[index];
            if let Err(error) = wait_for_height(
                &guard.validator().rpc_addr,
                activation_height + 2,
                Duration::from_secs(180),
            )
            .await
            {
                let mut status = Vec::new();
                for (peer_index, peer) in cluster.validators.iter().enumerate() {
                    match rpc::get_status(&peer.validator().rpc_addr).await {
                        Ok(observed) => status.push(format!("node{peer_index}={}", observed.height)),
                        Err(peer_error) => {
                            status.push(format!("node{peer_index}=rpc-error({peer_error:#})"))
                        }
                    }
                }
                return Err(anyhow::anyhow!(
                    "successor node {index} did not observe post-QUV height {}: {error:#}; status=[{}]",
                    activation_height + 2,
                    status.join(", ")
                ));
            }
            let block = rpc::get_block_by_height_resilient(
                &guard.validator().rpc_addr,
                activation_height + 1,
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("QUV successor block was not observable"))?;
            if !successor
                .validators
                .iter()
                .any(|member| member.account_id == block.header.producer_account_id)
            {
                return Err(anyhow::anyhow!(
                    "post-handoff block was not produced by the installed successor set"
                ));
            }
        }

        // Restart a live successor authority process while leaving its
        // workload/state process intact. Recovery must consume the existing
        // rollback-anchored install gate; it may not re-run QUV against an
        // expired old root or infer authority from the source bytes.
        let restarted_index = keyed[4].1;
        let restarted_rpc = cluster.validators[restarted_index]
            .validator()
            .rpc_addr
            .clone();
        let before_restart = observed_block_tip(&restarted_rpc, activation_height + 2).await?;
        let (mut restarted_log, _, _) = cluster.validators[restarted_index]
            .validator()
            .subscribe_logs();
        cluster.validators[restarted_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[restarted_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        assert_log_contains(
            &format!("restarted QUV successor node {restarted_index}"),
            &mut restarted_log,
            "Recovered QUV successor authority from its durable local install gate",
        )
        .await?;
        let post_restart_height = before_restart.saturating_add(2);
        wait_for(
            "two new canonical QUV blocks after successor restart",
            Duration::from_millis(250),
            Duration::from_secs(240),
            || {
                let rpc_addr = restarted_rpc.clone();
                async move {
                    rpc::get_block_by_height_resilient(&rpc_addr, post_restart_height).await
                }
            },
        )
        .await?;

        // Admit an irreversible effect through the real workload, bind its
        // manifest root into the block's Agentgres record, then ask one
        // relying executor to run fresh QUV against every active successor
        // and immediately continue into the PQ atomic T10 resource. The RPC
        // response is consequence audit/state only, never bearer authority.
        let executor_account = keyed[4].0;
        let executor_key = cluster.validators[restarted_index]
            .validator()
            .pqc_keypair
            .as_ref()
            .expect("QUV executor must retain its ML-DSA key")
            .clone();
        let effect_policy_root = quv_policy_root(
            effect_domain,
            QuvAuthorityModeV0::Unowned,
            None,
            effect_delta_rt_millis,
            effect_continuation_millis,
        &ioi_types::app::QuvDomainBootstrapV0::Fixed { initial_slot: 1, predecessor: [77; 32] },
&ioi_types::app::QuvPreparationPolicyV0::Independent { max_attempts_per_slot: 2, service_millis: (effect_delta_rt_millis as u64).saturating_add(effect_continuation_millis as u64), readiness_millis: 1_000_000 },
    (effect_delta_rt_millis as u64).saturating_add(effect_continuation_millis as u64),
 256,
 ioi_types::app::QuvPushAdmissionPolicyV0 { max_requests_per_identity: 64, window_millis: effect_delta_rt_millis as u64 },)?;
        let mut manifest = EffectManifestV1 {
            schema_version: EffectManifestVersionV1::V1,
            effect_id: "effect-quv-e2e-1".into(),
            resource_id: "resource://aft-e2e/pq-register".into(),
            conflict_domain_id: effect_conflict_domain_id.into(),
            conflict_slot: 1,
            authorization_mode: EffectAuthorizationModeV1::OnlineQueryUnanimityV0,
            online_authorization_policy_root: Some(effect_policy_root),
            online_authorization_predecessor: Some([77; 32]),
            online_authorization_authority_mode: Some(ioi_types::app::QuvAuthorityModeV0::Unowned),
            read_set: vec![EffectResourceKeyV1 {
                key: "account/source".into(),
                predecessor: Some([21; 32]),
            }],
            write_set: vec![EffectResourceKeyV1 {
                key: "settlement/one".into(),
                predecessor: None,
            }],
            idempotency_key: "pending".into(),
            request_root: [22; 32],
            predecessor_root: [23; 32],
            intent_root: [24; 32],
            expected_outcome_root: [25; 32],
            resource_profile: DurablePqAtomicRegisterV1::profile_for(&executor_key)?,
            required_guarantees: GuaranteeRequirementsV1 {
                require_consensus_pq: true,
                require_externalization_pq: true,
                minimum_externalization: Some(ExternalizationModeV1::IdempotencyRegister),
                require_at_most_once: true,
                ..Default::default()
            },
            fence: EffectFenceV1::ProtocolHeight {
                configuration_hash: successor_root,
                minimum_height: activation_height,
                maximum_height: 10_000,
            },
            reconciliation: ReconciliationPolicyV1::LookupByIdempotencyKey {
                maximum_observations: 3,
            },
            irreversible: true,
        };
        manifest.idempotency_key = manifest.query_unanimity_idempotency_key()?;
        manifest.validate()?;
        let registration = signed_system_transaction(
            &cluster.validators[restarted_index].validator().keypair,
            SystemPayload::CallService {
                service_id: AFT_EFFECT_REGISTRY_SERVICE_ID.into(),
                method: REGISTER_AFT_EFFECT_MANIFEST_V1_METHOD.into(),
                params: serde_jcs::to_vec(&manifest)?,
            },
            0,
            0xA19_u32.into(),
        )?;
        rpc::submit_transaction(&restarted_rpc, &registration).await?;

        let mut candidate = QuvCandidateV0 {
            slot: QuvSlotV0 {
                network_id,
                configuration_root: successor_root,
                policy_root: effect_policy_root,
                domain_id: effect_domain,
                slot: manifest.conflict_slot,
                predecessor: manifest.online_authorization_predecessor.unwrap(),
                authority_mode: manifest.online_authorization_authority_mode.unwrap(),
            },
            payload_hash: manifest.commitment()?,
            authorizer: executor_account,
            authority_signature: Vec::new(),
        };
        candidate.authority_signature = executor_key
            .sign(&quv_candidate_authority_signing_bytes(&candidate)?)?
            .to_bytes();
        let response = rpc::execute_aft_quv_effect(
            &restarted_rpc,
            &manifest.effect_id,
            &candidate,
        )
        .await?;
        if response.portable_final_receipt {
            return Err(anyhow::anyhow!(
                "online QUV executor mislabeled consequence audit as portable finality"
            ));
        }
        let receipt: ConsequenceReceiptV1 =
            serde_json::from_slice(&response.consequence_receipt_jcs)?;
        if serde_jcs::to_vec(&receipt)? != response.consequence_receipt_jcs {
            return Err(anyhow::anyhow!(
                "QUV consequence response is not canonical JCS"
            ));
        }
        receipt.validate()?;
        let record = match &receipt.state {
            ConsequenceStateV1::Executed {
                resource_record, ..
            } => resource_record,
            state => {
                return Err(anyhow::anyhow!(
                    "QUV consequence did not reach Executed: {:?}",
                    state.phase()
                ))
            }
        };
        if receipt.online_authorization_audit.as_ref().is_none_or(|audit| {
            audit.portable_final_receipt || audit.profile != "aft_quv_v0"
        }) {
            return Err(anyhow::anyhow!(
                "T10 consequence omitted its nonportable live QUV audit"
            ));
        }
        let resource_root = cluster.validators[restarted_index]
            .validator()
            .state_dir()
            .join("ordering-finality")
            .join("quv-external-resource");
        let mut resource = DurablePqAtomicRegisterV1::open(resource_root, executor_key)?;
        let observed = resource
            .lookup(&manifest.resource_id, &manifest.idempotency_key)
            .map_err(|error| anyhow::anyhow!("resource lookup failed: {error:?}"))?
            .ok_or_else(|| anyhow::anyhow!("T10 resource mutation is absent"))?;
        if observed != *record || !resource.verify_record_evidence(&observed) {
            return Err(anyhow::anyhow!(
                "T10 resource record or its rooted ML-DSA evidence differs"
            ));
        }

        // Source bytes are still replayable input after a successful live
        // install. Replacing even the owner signature cannot borrow the
        // process-local gate created for the original envelope.
        let substituted_index = keyed[5].1;
        let source_bytes = std::fs::read(&source_path)?;
        let mut substituted: QuvConfigurationHandoffEnvelopeV0 =
            codec::from_bytes_canonical(&source_bytes).map_err(anyhow::Error::msg)?;
        substituted.candidate.authority_signature[0] ^= 0x01;
        std::fs::write(
            &source_path,
            codec::to_bytes_canonical(&substituted).map_err(anyhow::Error::msg)?,
        )?;
        let (mut substituted_log, _, _) = cluster.validators[substituted_index]
            .validator()
            .subscribe_logs();
        cluster.validators[substituted_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[substituted_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        assert_log_contains(
            &format!("source-substituted QUV successor node {substituted_index}"),
            &mut substituted_log,
            "QUV recovery source has no exact rollback-anchored local install gate",
        )
        .await?;
        std::fs::write(&source_path, source_bytes)?;

        // Once old authority has expired, loss of either side of the durable
        // install pair fails closed. Startup may not rerun QUV retroactively.
        let missing_gate_index = keyed[6].1;
        let missing_gate_account = keyed[6].0;
        let missing_gate_state = cluster.validators[missing_gate_index]
            .validator()
            .state_dir()
            .join("aft-pq-outbox")
            .join(hex::encode(old_root))
            .join(hex::encode(missing_gate_account.as_ref()))
            .join("quv-handoff-v0.scale");
        if !missing_gate_state.is_file() {
            return Err(anyhow::anyhow!(
                "expected installed QUV handoff state at {}",
                missing_gate_state.display()
            ));
        }
        let (mut missing_gate_log, _, _) = cluster.validators[missing_gate_index]
            .validator()
            .subscribe_logs();
        cluster.validators[missing_gate_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        std::fs::remove_file(&missing_gate_state)?;
        cluster.validators[missing_gate_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        assert_log_contains(
            &format!("missing-gate QUV successor node {missing_gate_index}"),
            &mut missing_gate_log,
            "QUV store and rollback anchor are incomplete",
        )
        .await?;

        // Restoring the captured generation-zero state while retaining the
        // current external anchor is an explicit rollback image, not a crash
        // window. Restart must reject it rather than recreate the live gate.
        let (mut rollback_log, _, _) = cluster.validators[interrupted_index]
            .validator()
            .subscribe_logs();
        cluster.validators[interrupted_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        std::fs::write(&interrupted_state, &preinstall_state)?;
        cluster.validators[interrupted_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        assert_log_contains(
            &format!("rollback-image QUV successor node {interrupted_index}"),
            &mut rollback_log,
            "QUV store rollback or fork detected",
        )
        .await?;

        // A retired old-root process has no successor vote or proposal
        // identity after restart. Until a separately rooted observer profile
        // exists, it must stop rather than infer membership from its old key.
        let retired_index = keyed[0].1;
        let (mut retired_log, _, _) = cluster.validators[retired_index]
            .validator()
            .subscribe_logs();
        cluster.validators[retired_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[retired_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        assert_log_contains(
            &format!("retired old-root QUV node {retired_index}"),
            &mut retired_log,
            "local ML-DSA signer belongs to neither the effective set nor the staged QUV successor set",
        )
        .await?;

        Ok::<(), anyhow::Error>(())
    }
    .await;
    let shutdown = cluster.shutdown().await;
    run?;
    shutdown?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_aft_quv_overlapping_member_installs_and_recovers_the_same_live_handoff() -> Result<()>
{
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    build_test_artifacts();
    let fixture = tempfile::tempdir()?;
    let source_path = fixture.path().join("overlap-handoff.scale");
    let draft_path = fixture.path().join("overlap-handoff.scale.draft");
    let activation_height = 3;
    let delta_rt_millis = 30_000;
    let continuation_millis = 5_000;
    let _env = ScopedEnv::set(&[
        ("IOI_TEST_BUILD_PROFILE", "release"),
        ("IOI_TEST_VALIDATOR_LAUNCH_CONCURRENCY", "2"),
        ("IOI_TEST_FULL_MESH_BOOTNODES", "1"),
        ("IOI_TEST_SKIP_SHARED_TIP_WAIT", "1"),
        ("IOI_TEST_READY_HEIGHT_LAG_MAX", "1"),
        ("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS", "30"),
        ("IOI_TEST_SIGNER_STARTUP_TIMEOUT_SECS", "120"),
        ("IOI_BENCH_BLOCK_INTERVAL_MS", "1000"),
        ("IOI_AFT_BLOCK_DIRECT_RELAY", "1"),
    ]);

    // Four old members, one of which remains, plus three new members. Both
    // configurations therefore retain n=4 and the same ordering geometry.
    let mut cluster = TestCluster::builder()
        .with_validators(7)
        .with_consensus_type("Aft")
        .with_aft_safety_mode(AftSafetyMode::ClassicBft)
        .with_state_tree("IAVL")
        .with_chain_id(0xA1A)
        .with_quv_handoff_profile(
            4,
            activation_height,
            delta_rt_millis,
            continuation_millis,
            source_path.to_string_lossy(),
        )
        .with_quv_handoff_overlap_count(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 0xA1A,
            grace_period_blocks: 0,
            accept_staged_during_grace: false,
            allowed_target_suites: vec![SignatureSuite::ML_DSA_44],
            allow_downgrade: false,
        }))
        .build()
        .await?;

    let run = async {
        let mut keyed = cluster
            .validators
            .iter()
            .enumerate()
            .map(|(index, guard)| {
                let key = guard
                    .validator()
                    .pqc_keypair
                    .as_ref()
                    .expect("overlap fixture requires ML-DSA identities");
                let public = key.public_key().to_bytes();
                let account = AccountId(account_id_from_key_material(
                    SignatureSuite::ML_DSA_44,
                    &public,
                )?);
                Ok((account, index))
            })
            .collect::<Result<Vec<_>>>()?;
        keyed.sort_by_key(|(account, _)| *account);

        let member = |(account, _): &(AccountId, usize), since_height| ValidatorV1 {
            account_id: *account,
            weight: 1,
            consensus_key: ActiveKeyRecord {
                suite: SignatureSuite::ML_DSA_44,
                public_key_hash: account.0,
                since_height,
            },
        };
        let old = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: 4,
            validators: keyed[..4].iter().map(|entry| member(entry, 0)).collect(),
        };
        let mut successor_members = vec![member(&keyed[0], 0)];
        successor_members.extend(
            keyed[4..]
                .iter()
                .map(|entry| member(entry, activation_height)),
        );
        successor_members.sort_by_key(|entry| entry.account_id);
        let successor = ValidatorSetV1 {
            effective_from_height: activation_height,
            total_weight: 4,
            validators: successor_members,
        };
        let old_root = ioi_types::app::canonical_validator_set_hash(&old)
            .map_err(anyhow::Error::msg)?;
        let successor_root = ioi_types::app::canonical_validator_set_hash(&successor)
            .map_err(anyhow::Error::msg)?;
        let network_id = ioi_crypto::algorithms::hash::sha256(cluster.genesis_content.as_bytes())?;
        let domain_id =
            quv_handoff_domain_id(network_id, old_root, successor_root, activation_height)?;
        emit_handoff_expectations(&old, &successor, domain_id, delta_rt_millis)?;
        let policy_root = quv_policy_root(
            domain_id,
            QuvAuthorityModeV0::Owned,
            Some(keyed[0].0),
            delta_rt_millis,
            continuation_millis,
        &ioi_types::app::QuvDomainBootstrapV0::HandoffBoundary { activation_height },
&ioi_types::app::QuvPreparationPolicyV0::OneShot,
    (delta_rt_millis as u64).saturating_add(continuation_millis as u64),
 256,
 ioi_types::app::QuvPushAdmissionPolicyV0 { max_requests_per_identity: 64, window_millis: delta_rt_millis as u64 },)?;

        let mut successor_logs = successor
            .validators
            .iter()
            .map(|member| {
                let index = keyed
                    .iter()
                    .find(|(account, _)| account == &member.account_id)
                    .expect("successor process exists")
                    .1;
                let (log, _, _) = cluster.validators[index].validator().subscribe_logs();
                (index, log)
            })
            .collect::<Vec<_>>();
        let envelope = wait_for(
            "the overlapping QUV handoff draft",
            Duration::from_millis(250),
            Duration::from_secs(90),
            || {
                let path = draft_path.clone();
                async move {
                    let Ok(bytes) = std::fs::read(path) else {
                        return Ok(None);
                    };
                    Ok(
                        codec::from_bytes_canonical::<QuvConfigurationHandoffEnvelopeV0>(&bytes)
                            .ok(),
                    )
                }
            },
        )
        .await?;
        if envelope.handoff.old_configuration_root != old_root
            || ioi_types::app::canonical_validator_set_hash(&envelope.handoff.successor_set)
                .map_err(anyhow::Error::msg)?
                != successor_root
            || envelope.candidate.slot.domain_id != domain_id
            || envelope.candidate.slot.policy_root != policy_root
            || envelope.candidate.authorizer != keyed[0].0
        {
            return Err(anyhow::anyhow!(
                "overlapping QUV draft differs from its rooted configuration"
            ));
        }
        validate_quv_handoff_candidate(&envelope.candidate, &envelope.handoff)?;
        let owner_key_path = cluster.validators[keyed[0].1]
            .validator()
            .state_dir()
            .join("pqc_key.json");
        let signed_path = source_path.with_extension("signed.scale");
        sign_handoff_draft(
            &draft_path,
            &owner_key_path,
            &signed_path,
            false,
        )?;
        install_signed_handoff(
            &signed_path,
            &owner_key_path,
            &source_path,
            false,
        )?;

        for (index, log) in &mut successor_logs {
            assert_log_contains_any(
                &format!("overlapping QUV successor node {index}"),
                log,
                &[
                    "Activated successor from its local live old-root QUV install",
                    "Recovered QUV successor authority from its durable local install gate",
                ],
            )
            .await?;
            wait_for_height(
                &cluster.validators[*index].validator().rpc_addr,
                activation_height + 2,
                Duration::from_secs(180),
            )
            .await?;
        }

        // The member common to both roots must have traversed the same live
        // install gate as every new member. Its old membership cannot stand in
        // for QUV, and restart must recover the exact successor-scoped gate.
        let overlap_index = keyed[0].1;
        let overlap_rpc = cluster.validators[overlap_index]
            .validator()
            .rpc_addr
            .clone();
        let before_restart = observed_block_tip(&overlap_rpc, activation_height + 2).await?;
        let (mut overlap_log, _, _) = cluster.validators[overlap_index]
            .validator()
            .subscribe_logs();
        cluster.validators[overlap_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[overlap_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        assert_log_contains(
            &format!("restarted overlapping QUV member {overlap_index}"),
            &mut overlap_log,
            "Recovered QUV successor authority from its durable local install gate",
        )
        .await?;
        let post_restart_height = before_restart.saturating_add(2);
        wait_for(
            "two new canonical overlapping-root blocks after restart",
            Duration::from_millis(250),
            Duration::from_secs(180),
            || {
                let rpc_addr = overlap_rpc.clone();
                async move {
                    rpc::get_block_by_height_resilient(&rpc_addr, post_restart_height).await
                }
            },
        )
        .await?;

        let retired_index = keyed[1].1;
        let (mut retired_log, _, _) = cluster.validators[retired_index]
            .validator()
            .subscribe_logs();
        cluster.validators[retired_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[retired_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        assert_log_contains(
            &format!("retired non-overlapping member {retired_index}"),
            &mut retired_log,
            "local ML-DSA signer belongs to neither the effective set nor the staged QUV successor set",
        )
        .await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let shutdown = cluster.shutdown().await;
    run?;
    shutdown?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_aft_quv_m16q_each_single_correct_member_and_conflict_isolation() -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    build_test_artifacts();

    const CHAIN_ID: u32 = 0xA20;
    const DELTA_RT_MILLIS: u64 = 5_000;
    // Rooted continuation for the M16Q deployment profile; see the flood
    // fixture's note: the active service budget (delta + continuation) is
    // charged from exclusive admission and includes reserved-receipt
    // initialization, measured at about 3 s under contention on this host.
    const CONTINUATION_MILLIS: u64 = 8_000;
    const CONFLICT_SLOT: u64 = 1;
    let solo_domain_ids = [
        "domain://aft-e2e/m16q/solo-0",
        "domain://aft-e2e/m16q/solo-1",
        "domain://aft-e2e/m16q/solo-2",
        "domain://aft-e2e/m16q/solo-3",
    ];
    let saturation_domain_ids = [
        "domain://aft-e2e/m16q/saturation-0",
        "domain://aft-e2e/m16q/saturation-1",
        "domain://aft-e2e/m16q/saturation-2",
        "domain://aft-e2e/m16q/saturation-3",
    ];
    let conflict_domain_id = "domain://aft-e2e/m16q/conflict";
    let unrelated_domain_id = "domain://aft-e2e/m16q/unrelated";
    // R1 finding 007 (process level): fresh unowned domain for the live
    // operation that runs while a Byzantine process claims position 0's
    // account in every status response.
    let byzantine_status_domain_id = "domain://aft-e2e/m16q/byzantine-status";
    // R1 finding 001: conflict manifests differing only by their signed
    // predecessor. Each order runs on its own fresh domain; owned domains root
    // one process account as owner, so its ML-DSA key is fixed before build.
    let fork_cases = [
        (
            "owned-ab",
            "domain://aft-e2e/m16q/fork-owned-ab",
            QuvAuthorityModeV0::Owned,
            "ab",
        ),
        (
            "owned-ba",
            "domain://aft-e2e/m16q/fork-owned-ba",
            QuvAuthorityModeV0::Owned,
            "ba",
        ),
        (
            "unowned-ab",
            "domain://aft-e2e/m16q/fork-unowned-ab",
            QuvAuthorityModeV0::Unowned,
            "ab",
        ),
        (
            "unowned-ba",
            "domain://aft-e2e/m16q/fork-unowned-ba",
            QuvAuthorityModeV0::Unowned,
            "ba",
        ),
    ];
    let fixture_pq_keys = {
        let scheme = ioi_crypto::sign::dilithium::MldsaScheme::new(
            ioi_crypto::security::SecurityLevel::Level2,
        );
        (0..4)
            .map(|_| {
                scheme
                    .generate_keypair()
                    .map_err(|error| anyhow::anyhow!(error.to_string()))
            })
            .collect::<Result<Vec<_>>>()?
    };
    let fork_owner = AccountId(account_id_from_key_material(
        SignatureSuite::ML_DSA_44,
        &fixture_pq_keys[0].public_key().to_bytes(),
    )?);
    let mut policy_domains = solo_domain_ids
        .iter()
        .map(|domain_id| (*domain_id, QuvAuthorityModeV0::Unowned, None))
        .collect::<Vec<_>>();
    policy_domains.extend(
        saturation_domain_ids
            .iter()
            .map(|domain_id| (*domain_id, QuvAuthorityModeV0::Unowned, None)),
    );
    policy_domains.extend([
        (conflict_domain_id, QuvAuthorityModeV0::Unowned, None),
        (unrelated_domain_id, QuvAuthorityModeV0::Unowned, None),
        (byzantine_status_domain_id, QuvAuthorityModeV0::Unowned, None),
    ]);
    policy_domains.extend(fork_cases.iter().map(|(_, domain_id, mode, _)| {
        (
            *domain_id,
            *mode,
            (*mode == QuvAuthorityModeV0::Owned).then_some(fork_owner),
        )
    }));
    let policies = policy_domains
        .iter()
        .map(|(domain_id, authority_mode, owner)| {
            let domain_id = conflict_domain_id_commitment(domain_id).map_err(anyhow::Error::msg)?;
            Ok(AftQuvDomainPolicyV0 {
                authority_slots: 256,
                preparation: ioi_types::app::QuvPreparationPolicyV0::Independent {
                    max_attempts_per_slot: 2,
                    service_millis: (DELTA_RT_MILLIS as u64)
                        .saturating_add(CONTINUATION_MILLIS as u64),
                    readiness_millis: 1_000_000,
                },
                bootstrap: ioi_types::app::QuvDomainBootstrapV0::Fixed {
                    initial_slot: 1,
                    predecessor: [77; 32],
                },
                domain_id,
                authority_mode: *authority_mode,
                owner: *owner,
                delta_rt_millis: DELTA_RT_MILLIS,
                qualified_delta_rt_envelope_millis: M16Q_QUALIFIED_ENVELOPE_MS,
                qualified_max_configured_members: 4,
                continuation_millis: CONTINUATION_MILLIS,
                operation_service_millis: (DELTA_RT_MILLIS as u64)
                    .saturating_add(CONTINUATION_MILLIS as u64),
                push_admission: ioi_types::app::QuvPushAdmissionPolicyV0 {
                    max_requests_per_identity: 64,
                    window_millis: DELTA_RT_MILLIS as u64,
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let _env = ScopedEnv::set(&[
        ("IOI_TEST_BUILD_PROFILE", "release"),
        ("IOI_TEST_VALIDATOR_LAUNCH_CONCURRENCY", "2"),
        ("IOI_TEST_FULL_MESH_BOOTNODES", "1"),
        ("IOI_TEST_READY_HEIGHT_LAG_MAX", "1"),
        ("IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS", "180"),
        ("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS", "30"),
        ("IOI_TEST_SIGNER_STARTUP_TIMEOUT_SECS", "120"),
        ("IOI_BENCH_BLOCK_INTERVAL_MS", "500"),
        ("IOI_AFT_BLOCK_DIRECT_RELAY", "1"),
    ]);

    let mut builder = TestCluster::builder()
        .with_validators(4)
        .with_consensus_type("Aft")
        .with_aft_safety_mode(AftSafetyMode::ClassicBft)
        .with_pq_consensus_profile()
        .with_validator_pqc_keypairs(fixture_pq_keys)
        .with_state_tree("IAVL")
        .with_chain_id(CHAIN_ID)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: CHAIN_ID,
            grace_period_blocks: 0,
            accept_staged_during_grace: false,
            allowed_target_suites: vec![SignatureSuite::ML_DSA_44],
            allow_downgrade: false,
        }));
    for policy in policies.iter().cloned() {
        builder = builder.with_quv_domain_policy(policy);
    }
    let mut cluster = builder.build().await?;
    // Retain every executor operation start across all processes. This is
    // workload evidence for "no push happened"; it never authorizes anything.
    let operation_starts = QuvOperationStartLog::drain(&cluster);
    // Retain the status-claim diagnostics for the R1 finding 007 case: the
    // claimant's own override warning and every peer's enrollment refusal.
    let network_events = NetworkEventLog::drain(
        &cluster,
        &[
            "testing_status_account_override",
            "testing_status_account_override_invalid",
            "pq_peer_enrollment_refused",
            "pq_handoff_peer_enrollment_refused",
            "pq_provisional_enrollment_lost",
        ],
    );

    let run = async {
        let mut members = cluster
            .validators
            .iter()
            .enumerate()
            .map(|(process_index, guard)| {
                let endpoint = guard
                    .validator()
                    .pqc_keypair
                    .as_ref()
                    .expect("M16Q process member must retain its ML-DSA key")
                    .clone();
                let account = AccountId(account_id_from_key_material(
                    SignatureSuite::ML_DSA_44,
                    &endpoint.public_key().to_bytes(),
                )?);
                Ok((account, process_index, endpoint))
            })
            .collect::<Result<Vec<_>>>()?;
        members.sort_by_key(|(account, _, _)| *account);
        let active_set = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: members.len() as u128,
            validators: members
                .iter()
                .map(|(account, _, _)| ValidatorV1 {
                    account_id: *account,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ML_DSA_44,
                        public_key_hash: account.0,
                        since_height: 0,
                    },
                })
                .collect(),
        };
        let configuration_root = ioi_types::app::canonical_validator_set_hash(&active_set)
            .map_err(anyhow::Error::msg)?;
        let configured_members = members
            .iter()
            .map(|(account, _, _)| *account)
            .collect::<HashSet<_>>();
        let network_id = ioi_crypto::algorithms::hash::sha256(cluster.genesis_content.as_bytes())?;

        // Registration commits one manifest per block, so the fence must
        // outlast every registration, the admission probes and the position-0
        // campaign that run before the expired-result case, while remaining
        // reachable within that case's wait budget.
        // Registration commits one manifest per block and each commit wait
        // spans a few heights (observed: 19 manifests, about 70 heights), so
        // the fence is sized from the manifest count: base headroom for the
        // admission probes and the position-0 campaign, plus four heights per
        // registered manifest. The expired-result case later waits up to
        // M16Q_EXPIRY_WAIT_SECS for the chain to pass this height.
        let registered_manifest_count: u64 = 4 + 4 + 4 + 8;
        let expiry_height = rpc::get_status(&cluster.validators[0].validator().rpc_addr)
            .await?
            .height
            .checked_add(96 + 4 * registered_manifest_count)
            .ok_or_else(|| anyhow::anyhow!("expiry height overflow"))?;
        let mut manifests = Vec::new();
        for (member_position, (_, process_index, endpoint)) in members.iter().enumerate() {
            let domain_id = solo_domain_ids[member_position];
            let domain =
                conflict_domain_id_commitment(domain_id).map_err(anyhow::Error::msg)?;
            let policy_root = quv_policy_root(
                domain,
                QuvAuthorityModeV0::Unowned,
                None,
                DELTA_RT_MILLIS,
                CONTINUATION_MILLIS,
            &ioi_types::app::QuvDomainBootstrapV0::Fixed { initial_slot: 1, predecessor: [77; 32] },
&ioi_types::app::QuvPreparationPolicyV0::Independent { max_attempts_per_slot: 2, service_millis: (DELTA_RT_MILLIS as u64).saturating_add(CONTINUATION_MILLIS as u64), readiness_millis: 1_000_000 },
    (DELTA_RT_MILLIS as u64).saturating_add(CONTINUATION_MILLIS as u64),
 256,
 ioi_types::app::QuvPushAdmissionPolicyV0 { max_requests_per_identity: 64, window_millis: DELTA_RT_MILLIS as u64 },)?;
            manifests.push((
                *process_index,
                domain,
                policy_root,
                m16q_effect_manifest(
                    &format!("effect-m16q-solo-{member_position}"),
                    &format!("resource://aft-e2e/m16q/solo-{member_position}"),
                    domain_id,
                    CONFLICT_SLOT,
                    policy_root,
                    configuration_root,
                    endpoint,
                    10 + member_position as u8,
                )?,
            ));
        }
        if let EffectFenceV1::ProtocolHeight { maximum_height, .. } = &mut manifests[0].3.fence {
            *maximum_height = expiry_height;
        }
        manifests[0].3.idempotency_key = manifests[0].3.query_unanimity_idempotency_key()?;
        let mut saturation_manifests = Vec::new();
        for (member_position, (_, process_index, endpoint)) in members.iter().enumerate() {
            let domain_id = saturation_domain_ids[member_position];
            let domain =
                conflict_domain_id_commitment(domain_id).map_err(anyhow::Error::msg)?;
            let policy_root = quv_policy_root(
                domain,
                QuvAuthorityModeV0::Unowned,
                None,
                DELTA_RT_MILLIS,
                CONTINUATION_MILLIS,
            &ioi_types::app::QuvDomainBootstrapV0::Fixed { initial_slot: 1, predecessor: [77; 32] },
&ioi_types::app::QuvPreparationPolicyV0::Independent { max_attempts_per_slot: 2, service_millis: (DELTA_RT_MILLIS as u64).saturating_add(CONTINUATION_MILLIS as u64), readiness_millis: 1_000_000 },
    (DELTA_RT_MILLIS as u64).saturating_add(CONTINUATION_MILLIS as u64),
 256,
 ioi_types::app::QuvPushAdmissionPolicyV0 { max_requests_per_identity: 64, window_millis: DELTA_RT_MILLIS as u64 },)?;
            saturation_manifests.push((
                *process_index,
                domain,
                policy_root,
                m16q_effect_manifest(
                    &format!("effect-m16q-saturation-{member_position}"),
                    &format!("resource://aft-e2e/m16q/saturation-{member_position}"),
                    domain_id,
                    CONFLICT_SLOT,
                    policy_root,
                    configuration_root,
                    endpoint,
                    20 + member_position as u8,
                )?,
            ));
        }
        let conflict_domain =
            conflict_domain_id_commitment(conflict_domain_id).map_err(anyhow::Error::msg)?;
        let conflict_policy_root = quv_policy_root(
            conflict_domain,
            QuvAuthorityModeV0::Unowned,
            None,
            DELTA_RT_MILLIS,
            CONTINUATION_MILLIS,
        &ioi_types::app::QuvDomainBootstrapV0::Fixed { initial_slot: 1, predecessor: [77; 32] },
&ioi_types::app::QuvPreparationPolicyV0::Independent { max_attempts_per_slot: 2, service_millis: (DELTA_RT_MILLIS as u64).saturating_add(CONTINUATION_MILLIS as u64), readiness_millis: 1_000_000 },
    (DELTA_RT_MILLIS as u64).saturating_add(CONTINUATION_MILLIS as u64),
 256,
 ioi_types::app::QuvPushAdmissionPolicyV0 { max_requests_per_identity: 64, window_millis: DELTA_RT_MILLIS as u64 },)?;
        let conflict_a = m16q_effect_manifest(
            "effect-m16q-conflict-a",
            "resource://aft-e2e/m16q/conflict-a",
            conflict_domain_id,
            CONFLICT_SLOT,
            conflict_policy_root,
            configuration_root,
            &members[0].2,
            40,
        )?;
        let conflict_b = m16q_effect_manifest(
            "effect-m16q-conflict-b",
            "resource://aft-e2e/m16q/conflict-b",
            conflict_domain_id,
            CONFLICT_SLOT,
            conflict_policy_root,
            configuration_root,
            &members[1].2,
            41,
        )?;
        let unrelated_domain =
            conflict_domain_id_commitment(unrelated_domain_id).map_err(anyhow::Error::msg)?;
        let unrelated_policy_root = quv_policy_root(
            unrelated_domain,
            QuvAuthorityModeV0::Unowned,
            None,
            DELTA_RT_MILLIS,
            CONTINUATION_MILLIS,
        &ioi_types::app::QuvDomainBootstrapV0::Fixed { initial_slot: 1, predecessor: [77; 32] },
&ioi_types::app::QuvPreparationPolicyV0::Independent { max_attempts_per_slot: 2, service_millis: (DELTA_RT_MILLIS as u64).saturating_add(CONTINUATION_MILLIS as u64), readiness_millis: 1_000_000 },
    (DELTA_RT_MILLIS as u64).saturating_add(CONTINUATION_MILLIS as u64),
 256,
 ioi_types::app::QuvPushAdmissionPolicyV0 { max_requests_per_identity: 64, window_millis: DELTA_RT_MILLIS as u64 },)?;
        // The unrelated singleton later runs on position 0's executor,
        // concurrently with that executor's terminal replay of its expiring
        // effect; an executor only runs manifests bound to its own resource.
        let unrelated = m16q_effect_manifest(
            "effect-m16q-unrelated",
            "resource://aft-e2e/m16q/unrelated",
            unrelated_domain_id,
            CONFLICT_SLOT,
            unrelated_policy_root,
            configuration_root,
            &members[0].2,
            60,
        )?;
        // R1 finding 007: the status-claim case runs on position 0's executor
        // (the claimed account C) for a fresh manifest bound to position 0's
        // key, so the operation needs C's own reply plus every genuine
        // carrier, including the claimant's, to route correctly.
        let byzantine_status_domain =
            conflict_domain_id_commitment(byzantine_status_domain_id).map_err(anyhow::Error::msg)?;
        let byzantine_status_policy_root = quv_policy_root(
            byzantine_status_domain,
            QuvAuthorityModeV0::Unowned,
            None,
            DELTA_RT_MILLIS,
            CONTINUATION_MILLIS,
            &ioi_types::app::QuvDomainBootstrapV0::Fixed { initial_slot: 1, predecessor: [77; 32] },
            &ioi_types::app::QuvPreparationPolicyV0::Independent { max_attempts_per_slot: 2, service_millis: (DELTA_RT_MILLIS as u64).saturating_add(CONTINUATION_MILLIS as u64), readiness_millis: 1_000_000 },
            (DELTA_RT_MILLIS as u64).saturating_add(CONTINUATION_MILLIS as u64),
            256,
            ioi_types::app::QuvPushAdmissionPolicyV0 { max_requests_per_identity: 64, window_millis: DELTA_RT_MILLIS as u64 },
        )?;
        let byzantine_status = m16q_effect_manifest(
            "effect-m16q-byzantine-status",
            "resource://aft-e2e/m16q/byzantine-status",
            byzantine_status_domain_id,
            CONFLICT_SLOT,
            byzantine_status_policy_root,
            configuration_root,
            &members[0].2,
            61,
        )?;

        // Predecessor-fork fixtures: B differs from A only by its signed
        // predecessor ([78;32] against the rooted bootstrap [77;32]) and by
        // the independently chosen resource/discriminator.
        let owner_position = members
            .iter()
            .position(|(account, _, _)| *account == fork_owner)
            .ok_or_else(|| anyhow::anyhow!("fork owner is not a configured member"))?;
        let mut fork_fixtures = Vec::new();
        for (position, (tag, domain_id, mode, order)) in fork_cases.iter().enumerate() {
            let domain = conflict_domain_id_commitment(domain_id).map_err(anyhow::Error::msg)?;
            let owner = (*mode == QuvAuthorityModeV0::Owned).then_some(fork_owner);
            let policy_root = quv_policy_root(
                domain,
                *mode,
                owner,
                DELTA_RT_MILLIS,
                CONTINUATION_MILLIS,
                &ioi_types::app::QuvDomainBootstrapV0::Fixed { initial_slot: 1, predecessor: [77; 32] },
                &ioi_types::app::QuvPreparationPolicyV0::Independent { max_attempts_per_slot: 2, service_millis: (DELTA_RT_MILLIS as u64).saturating_add(CONTINUATION_MILLIS as u64), readiness_millis: 1_000_000 },
                (DELTA_RT_MILLIS as u64).saturating_add(CONTINUATION_MILLIS as u64),
                256,
                ioi_types::app::QuvPushAdmissionPolicyV0 { max_requests_per_identity: 64, window_millis: DELTA_RT_MILLIS as u64 },
            )?;
            // Owned: one Byzantine owner signs both. Unowned: two members sign.
            let (position_a, position_b) = match mode {
                QuvAuthorityModeV0::Owned => (owner_position, owner_position),
                QuvAuthorityModeV0::Unowned => (0, 1),
            };
            let mut fork_a = m16q_effect_manifest(
                &format!("effect-m16q-fork-{tag}-a"),
                &format!("resource://aft-e2e/m16q/fork-{tag}-a"),
                domain_id,
                CONFLICT_SLOT,
                policy_root,
                configuration_root,
                &members[position_a].2,
                80 + 2 * position as u8,
            )?;
            let mut fork_b = m16q_effect_manifest(
                &format!("effect-m16q-fork-{tag}-b"),
                &format!("resource://aft-e2e/m16q/fork-{tag}-b"),
                domain_id,
                CONFLICT_SLOT,
                policy_root,
                configuration_root,
                &members[position_b].2,
                81 + 2 * position as u8,
            )?;
            fork_a.online_authorization_authority_mode = Some(*mode);
            fork_b.online_authorization_authority_mode = Some(*mode);
            fork_b.online_authorization_predecessor = Some([78; 32]);
            for manifest in [&mut fork_a, &mut fork_b] {
                manifest.idempotency_key = manifest.query_unanimity_idempotency_key()?;
                manifest.validate()?;
            }
            fork_fixtures.push(QuvForkFixture {
                tag,
                mode: *mode,
                order,
                domain,
                policy_root,
                position_a,
                position_b,
                manifest_a: fork_a,
                manifest_b: fork_b,
            });
        }

        let registration_rpc = cluster.validators[0].validator().rpc_addr.clone();
        let mut all_manifests = manifests
            .iter()
            .map(|(_, _, _, manifest)| manifest.clone())
            .collect::<Vec<_>>();
        all_manifests.extend(
            saturation_manifests
                .iter()
                .map(|(_, _, _, manifest)| manifest.clone()),
        );
        all_manifests.extend([
            conflict_a.clone(),
            conflict_b.clone(),
            unrelated.clone(),
            byzantine_status.clone(),
        ]);
        all_manifests.extend(
            fork_fixtures
                .iter()
                .flat_map(|fixture| [fixture.manifest_a.clone(), fixture.manifest_b.clone()]),
        );
        // The registry admits at most one effect manifest per block, so each
        // registration waits for its own commit (a second manifest in the same
        // block is rejected, not deferred). Admission of the last committed
        // height on every process is then required explicitly; that height
        // comes from the submissions themselves, not from a later status
        // sample that may trail or lead them.
        let registration_count = all_manifests.len();
        anyhow::ensure!(
            registration_count as u64 == registered_manifest_count,
            "M16Q fixture registers {registration_count} manifests but sized the expiry fence for {registered_manifest_count}"
        );
        let mut last_committed_height: Option<u64> = None;
        for (nonce, manifest) in all_manifests.iter().enumerate() {
            let registration = signed_system_transaction(
                &cluster.validators[0].validator().keypair,
                SystemPayload::CallService {
                    service_id: AFT_EFFECT_REGISTRY_SERVICE_ID.into(),
                    method: REGISTER_AFT_EFFECT_MANIFEST_V1_METHOD.into(),
                    params: serde_jcs::to_vec(manifest)?,
                },
                nonce as u64,
                CHAIN_ID.into(),
            )?;
            let profile =
                rpc::submit_transaction_profiled(&registration_rpc, &registration).await?;
            if let Some(height) = profile.committed_height {
                last_committed_height =
                    Some(last_committed_height.map_or(height, |known| known.max(height)));
            }
        }
        let last_committed_height = last_committed_height
            .ok_or_else(|| anyhow::anyhow!("M16Q fixture observed no committed registration height"))?;
        let admitted_height = last_committed_height.saturating_add(2);
        for guard in &cluster.validators {
            wait_for_height(
                &guard.validator().rpc_addr,
                admitted_height,
                Duration::from_secs(120),
            )
            .await?;
        }
        println!(
            "[M16Q-REGISTRATION] manifests={registration_count} last_committed_height={last_committed_height} admitted_height={admitted_height}"
        );

        // Establish actual local admission before any process is stopped.
        // A later loss then cannot be mistaken for initial propagation lag.
        for (member_position, (process_index, domain, policy_root, manifest)) in manifests.iter().enumerate() {
            let candidate = m16q_candidate(
                manifest, network_id, configuration_root, *policy_root, *domain,
                members[member_position].0, &members[member_position].2,
            )?;
            require_quv_preparation_refusal(
                &cluster.validators[*process_index].validator().rpc_addr,
                manifest, &candidate,
                &cluster.validators[*process_index].validator().state_dir().join("ordering-finality"),
            ).await?;
            println!("[M16Q-QUV] case=initial_manifest_admission member_position={member_position} result=exact_signature_refusal");
        }

        let mut solo_elapsed_ms = Vec::new();
        let mut expiry_replay = None;
        let mut terminal_recovery_probes = Vec::new();
        for (member_position, (correct_process, domain, policy_root, manifest)) in
            manifests.iter().enumerate()
        {
            let correct_rpc = cluster.validators[*correct_process]
                .validator()
                .rpc_addr
                .clone();
            let candidate = m16q_candidate(
                manifest,
                network_id,
                configuration_root,
                *policy_root,
                *domain,
                members[member_position].0,
                &members[member_position].2,
            )?;
            require_quv_preparation_refusal(
                &correct_rpc, manifest, &candidate,
                &cluster.validators[*correct_process].validator().state_dir().join("ordering-finality"),
            ).await?;
            println!(
                "[M16Q-QUV] case=invalid_signature_preparation member_position={member_position} per_effect_storage_unchanged=true result=rejected"
            );
            for process_index in 0..cluster.validators.len() {
                if process_index != *correct_process {
                    cluster.validators[process_index]
                        .validator_mut()
                        .kill_orchestration()
                        .await?;
                }
            }
            let started = Instant::now();
            let response = tokio::time::timeout(
                Duration::from_secs(30),
                rpc::execute_aft_quv_effect(&correct_rpc, &manifest.effect_id, &candidate),
            )
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "M16Q sole-correct placement {member_position} exceeded its client timeout"
                )
            })??;
            let elapsed = started.elapsed().as_millis();
            let max_valid_reply_elapsed_ms = require_executed_nonportable_quv_receipt(
                &response,
                &configured_members,
                &HashSet::from([members[member_position].0]),
            )?;
            if max_valid_reply_elapsed_ms > M16Q_QUALIFIED_ENVELOPE_MS {
                return Err(anyhow::anyhow!(
                    "M16Q sole-correct placement {member_position} exceeded its qualified 4000ms reply envelope: {max_valid_reply_elapsed_ms}ms"
                ));
            }
            let replay_started = Instant::now();
            let replay = tokio::time::timeout(
                Duration::from_secs(30),
                rpc::execute_aft_quv_effect(&correct_rpc, &manifest.effect_id, &candidate),
            ).await.map_err(|_| anyhow::anyhow!("M16Q terminal replay timed out"))??;
            if replay.portable_final_receipt
                || replay.consequence_receipt_jcs != response.consequence_receipt_jcs
            {
                return Err(anyhow::anyhow!("M16Q terminal replay changed the recorded nonportable result"));
            }
            let replay_elapsed_ms = replay_started.elapsed().as_millis();
            terminal_recovery_probes.push((
                correct_rpc.clone(), manifest.effect_id.clone(), candidate.clone(),
                response.consequence_receipt_jcs.clone(),
            ));
            if member_position == 0 {
                expiry_replay = Some((correct_rpc.clone(), manifest.effect_id.clone(), candidate, response.consequence_receipt_jcs.clone()));
            }

            solo_elapsed_ms.push(elapsed);
            println!(
                "[M16Q-QUV] case=sole_correct member_position={member_position} process_index={correct_process} terminal_replays=1 replay_elapsed_ms={replay_elapsed_ms} elapsed_ms={elapsed} max_valid_reply_elapsed_ms={max_valid_reply_elapsed_ms} qualified_envelope_ms={M16Q_QUALIFIED_ENVELOPE_MS} result=executed"
            );

            for process_index in 0..cluster.validators.len() {
                if process_index != *correct_process {
                    cluster.validators[process_index]
                        .validator_mut()
                        .restart_orchestration_process()
                        .await?;
                }
            }
            let recovery_floor = rpc::get_status(&correct_rpc).await?.height.saturating_add(1);
            wait_for_height(&correct_rpc, recovery_floor, Duration::from_secs(120)).await?;
        }

        // A height observation at one process does not establish recovery of
        // the other executors. Require each exact terminal result before the
        // all-correct campaign; this probe cannot create a fresh live grant.
        for (rpc_addr, effect_id, candidate, receipt_bytes) in &terminal_recovery_probes {
            wait_for_read_only_recovery(
                || async {
                    let response = rpc::execute_aft_quv_effect(rpc_addr, effect_id, candidate).await?;
                    Ok((response.portable_final_receipt, response.consequence_receipt_jcs))
                },
                &(false, receipt_bytes.clone()),
                Duration::from_secs(120),
            ).await?;
        }
        println!("[M16Q-QUV] case=recovered_results exact_nonportable_results=4 result=recorded");

        // Finish expensive candidate signing before releasing any RPC. A
        // barrier aligns request dispatch; retained operation traces must
        // still establish verifier overlap and reserved-lane workload coverage.
        let preparation_started = Instant::now();
        let mut prepared_requests = Vec::new();
        for (member_position, (process_index, domain, policy_root, manifest)) in
            saturation_manifests.iter().enumerate()
        {
            let candidate = m16q_candidate(
                manifest,
                network_id,
                configuration_root,
                *policy_root,
                *domain,
                members[member_position].0,
                &members[member_position].2,
            )?;
            let rpc_addr = cluster.validators[*process_index]
                .validator()
                .rpc_addr
                .clone();
            let effect_id = manifest.effect_id.clone();
            prepared_requests.push((rpc_addr, effect_id, candidate));
        }
        let preparation_elapsed_ms = preparation_started.elapsed().as_millis();
        let start_barrier = std::sync::Arc::new(tokio::sync::Barrier::new(prepared_requests.len() + 1));
        let mut saturation_tasks = tokio::task::JoinSet::new();
        for (rpc_addr, effect_id, candidate) in prepared_requests {
            let barrier = start_barrier.clone();
            saturation_tasks.spawn(async move {
                barrier.wait().await;
                let launched_at = Instant::now();
                let result = rpc::execute_aft_quv_effect(&rpc_addr, &effect_id, &candidate).await;
                (launched_at, result)
            });
        }
        let saturation_started = Instant::now();
        start_barrier.wait().await;
        let mut saturation_launch_times = Vec::new();
        let mut saturation_nonces = Vec::new();
        let mut saturation_reply_elapsed_ms = Vec::new();
        while let Some(joined) = saturation_tasks.join_next().await {
            let (launched_at, result) = joined.map_err(anyhow::Error::new)?;
            saturation_launch_times.push(launched_at);
            let response = result?;
            let reply_elapsed = require_executed_nonportable_quv_receipt(
                &response,
                &configured_members,
                &configured_members,
            )?;
            if reply_elapsed > M16Q_QUALIFIED_ENVELOPE_MS {
                return Err(anyhow::anyhow!(
                    "M16Q authenticated saturation exceeded its qualified 4000ms reply envelope: {reply_elapsed}ms"
                ));
            }
            // Correlate the checked receipt with retained verifier lifecycle logs.
            // This is workload evidence, never an authorization input.
            let receipt: ConsequenceReceiptV1 =
                serde_json::from_slice(&response.consequence_receipt_jcs)?;
            let audit = receipt.online_authorization_audit.as_ref().ok_or_else(||
                anyhow::anyhow!("checked workload receipt lost its online audit"))?;
            let evidence: QuvAcceptedAuditEvidenceV0 =
                codec::from_bytes_canonical(&audit.protocol_evidence)
                    .map_err(anyhow::Error::msg)?;
            saturation_nonces.push(hex::encode(evidence.request.verifier_nonce));
            saturation_reply_elapsed_ms.push(reply_elapsed);
        }
        if saturation_reply_elapsed_ms.len() != members.len() {
            return Err(anyhow::anyhow!(
                "M16Q authenticated saturation did not complete every executor operation"
            ));
        }
        let saturation_elapsed_ms = saturation_started.elapsed().as_millis();
        let rpc_launch_span_ms = saturation_launch_times.iter().max().unwrap()
            .duration_since(*saturation_launch_times.iter().min().unwrap()).as_millis();
        println!(
            "[M16Q-QUV] case=authenticated_saturation operations={} verifier_nonces={} preparation_elapsed_ms={preparation_elapsed_ms} rpc_launch_span_ms={rpc_launch_span_ms} elapsed_ms={saturation_elapsed_ms} max_valid_reply_elapsed_ms={:?} qualified_envelope_ms={M16Q_QUALIFIED_ENVELOPE_MS} result=executed",
            saturation_reply_elapsed_ms.len(),
            saturation_nonces.join(","),
            saturation_reply_elapsed_ms.iter().max()
        );

        let conflict_candidate_a = m16q_candidate(
            &conflict_a,
            network_id,
            configuration_root,
            conflict_policy_root,
            conflict_domain,
            members[0].0,
            &members[0].2,
        )?;
        let conflict_candidate_b = m16q_candidate(
            &conflict_b,
            network_id,
            configuration_root,
            conflict_policy_root,
            conflict_domain,
            members[1].0,
            &members[1].2,
        )?;
        let conflict_rpc_a = cluster.validators[members[0].1]
            .validator()
            .rpc_addr
            .clone();
        let conflict_rpc_b = cluster.validators[members[1].1]
            .validator()
            .rpc_addr
            .clone();
        let mut conflict_resources = members[..2]
            .iter()
            .map(|(_, process_index, endpoint)| {
                DurablePqAtomicRegisterV1::open(
                    cluster.validators[*process_index]
                        .validator()
                        .state_dir()
                        .join("ordering-finality")
                        .join("quv-external-resource"),
                    endpoint.clone(),
                )
                .map_err(anyhow::Error::new)
            })
            .collect::<Result<Vec<_>>>()?;
        for (resource, manifest) in conflict_resources.iter_mut().zip([&conflict_a, &conflict_b]) {
            if resource
                .lookup(&manifest.resource_id, &manifest.idempotency_key)
                .map_err(|error| anyhow::anyhow!("pre-conflict resource lookup failed: {error:?}"))?
                .is_some()
            {
                return Err(anyhow::anyhow!("conflict fixture resource was already mutated"));
            }
        }
        let conflict_started = Instant::now();
        let (result_a, result_b) = tokio::join!(
            rpc::execute_aft_quv_effect(
                &conflict_rpc_a,
                &conflict_a.effect_id,
                &conflict_candidate_a,
            ),
            rpc::execute_aft_quv_effect(
                &conflict_rpc_b,
                &conflict_b.effect_id,
                &conflict_candidate_b,
            )
        );
        let conflict_elapsed_ms = conflict_started.elapsed().as_millis();
        // R1 finding 004: the evidence fields are measured from the observed
        // register records of both executors, then checked; they are never
        // restated from the RPC outcomes.
        let mut conflict_observations = Vec::new();
        for ((result, manifest), resource) in [&result_a, &result_b]
            .into_iter()
            .zip([&conflict_a, &conflict_b])
            .zip(conflict_resources.iter_mut())
        {
            let observed = resource
                .lookup(&manifest.resource_id, &manifest.idempotency_key)
                .map_err(|error| anyhow::anyhow!("post-conflict resource lookup failed: {error:?}"))?;
            let record_verified = observed
                .as_ref()
                .is_some_and(|record| resource.verify_record_evidence(record));
            conflict_observations.push((result, manifest, observed, record_verified));
        }
        let measured = measure_quv_conflict_outcomes(
            conflict_observations
                .iter()
                .map(|(result, _, observed, _)| (result.is_ok(), observed.is_some())),
        );
        println!(
            "[M16Q-QUV] case=concurrent_valid_conflict accepts={} conflict_rejections={} durable_records={} rejected_resources_unchanged={} elapsed_ms={conflict_elapsed_ms} result=safe",
            measured.accepts,
            measured.rejections,
            measured.durable_records,
            measured.rejected_resources_unchanged,
        );
        let mut conflict_accepts = 0_u8;
        let mut conflict_rejections = 0_u8;
        for (result, manifest, observed, record_verified) in conflict_observations {
            match result {
                Ok(response) => {
                    require_executed_nonportable_quv_receipt(
                        response,
                        &configured_members,
                        &configured_members,
                    )?;
                    let receipt: ConsequenceReceiptV1 =
                        serde_json::from_slice(&response.consequence_receipt_jcs)?;
                    let ConsequenceStateV1::Executed { resource_record, .. } = receipt.state else {
                        return Err(anyhow::anyhow!("accepted conflict effect was not executed"));
                    };
                    if receipt.manifest != *manifest
                        || observed.as_ref() != Some(&resource_record)
                        || !record_verified
                    {
                        return Err(anyhow::anyhow!(
                            "accepted conflict effect differs from its durable resource mutation"
                        ));
                    }
                    conflict_accepts += 1;
                }
                Err(error) => {
                    require_quv_conflict_rejection(error)?;
                    if observed.is_some() {
                        return Err(anyhow::anyhow!(
                            "rejected conflict effect nevertheless mutated its durable resource"
                        ));
                    }
                    conflict_rejections += 1;
                }
            }
        }
        if conflict_accepts > 1 || conflict_rejections == 0 {
            return Err(anyhow::anyhow!(
                "concurrent QUV conflict drill lacked the required authenticated conflict rejection"
            ));
        }
        if measured.accepts != conflict_accepts
            || measured.rejections != conflict_rejections
            || measured.durable_records != conflict_accepts
            || !measured.rejected_resources_unchanged
        {
            return Err(anyhow::anyhow!(
                "measured conflict register evidence contradicts the checked outcomes: {measured:?}"
            ));
        }

        // R1 finding 001: a candidate-selected predecessor must not fork the
        // conflict namespace. B (predecessor [78;32]) must be refused by the
        // executor's durable expected-head preflight before any member push,
        // in either submission order, and A must execute exactly once.
        for fixture in &fork_fixtures {
            let candidate_a = m16q_candidate(
                &fixture.manifest_a,
                network_id,
                configuration_root,
                fixture.policy_root,
                fixture.domain,
                members[fixture.position_a].0,
                &members[fixture.position_a].2,
            )?;
            let candidate_b = m16q_candidate(
                &fixture.manifest_b,
                network_id,
                configuration_root,
                fixture.policy_root,
                fixture.domain,
                members[fixture.position_b].0,
                &members[fixture.position_b].2,
            )?;
            if candidate_a.slot.predecessor != [77; 32] || candidate_b.slot.predecessor != [78; 32] {
                return Err(anyhow::anyhow!("fork fixture lost its distinct signed predecessors"));
            }
            let process_a = members[fixture.position_a].1;
            let process_b = members[fixture.position_b].1;
            let rpc_a = cluster.validators[process_a].validator().rpc_addr.clone();
            let rpc_b = cluster.validators[process_b].validator().rpc_addr.clone();
            let runtime_root_b = cluster.validators[process_b]
                .validator()
                .state_dir()
                .join("ordering-finality");
            let mut register_a = DurablePqAtomicRegisterV1::open(
                cluster.validators[process_a].validator().state_dir()
                    .join("ordering-finality").join("quv-external-resource"),
                members[fixture.position_a].2.clone(),
            ).map_err(anyhow::Error::new)?;
            let mut register_b = DurablePqAtomicRegisterV1::open(
                runtime_root_b.join("quv-external-resource"),
                members[fixture.position_b].2.clone(),
            ).map_err(anyhow::Error::new)?;
            let lookup_b = |register: &mut DurablePqAtomicRegisterV1| {
                register
                    .lookup(&fixture.manifest_b.resource_id, &fixture.manifest_b.idempotency_key)
                    .map_err(|error| anyhow::anyhow!("fork resource lookup failed: {error:?}"))
            };
            if lookup_b(&mut register_b)?.is_some() {
                return Err(anyhow::anyhow!("fork fixture resource was already mutated"));
            }
            let started_at = operation_starts.len();
            let mut refusals = 0_u32;
            let mut refusal_rules: Vec<&'static str> = Vec::new();
            let mut accepted = None;
            // Before A executes, B is refused by the expected-head rule; after
            // A executed on the same executor, the stable-key claim index
            // refuses B first (naming exactly A). Both precede any push.
            // The post-A rule depends on where B is submitted: the same
            // executor as A holds the stable-key claim naming A, while a
            // different executor holds no claim and refuses through its own
            // derived expected head. Either way B never reaches a member.
            let same_executor = process_a == process_b;
            let after_a_rule = if same_executor { "claim_index" } else { "expected_head" };
            let (steps, expected_rules): (&[char], Vec<&str>) = match fixture.order {
                "ab" => (&['a', 'b'], vec![after_a_rule]),
                "ba" => (&['b', 'a', 'b'], vec!["expected_head", after_a_rule]),
                other => return Err(anyhow::anyhow!("unknown fork order {other}")),
            };
            for step in steps {
                if *step == 'b' {
                    let rule = require_quv_fork_refusal(
                        &rpc_b, &fixture.manifest_b, &candidate_b, &runtime_root_b,
                        &fixture.manifest_a.effect_id,
                    ).await?;
                    refusal_rules.push(rule);
                    refusals += 1;
                } else {
                    let response = tokio::time::timeout(
                        Duration::from_secs(30),
                        rpc::execute_aft_quv_effect(&rpc_a, &fixture.manifest_a.effect_id, &candidate_a),
                    ).await.map_err(|_| anyhow::anyhow!("fork placement A timed out"))??;
                    let reply_elapsed = require_executed_nonportable_quv_receipt(
                        &response, &configured_members, &configured_members,
                    )?;
                    if reply_elapsed > M16Q_QUALIFIED_ENVELOPE_MS {
                        return Err(anyhow::anyhow!("fork placement A exceeded its qualified reply envelope: {reply_elapsed}ms"));
                    }
                    accepted = Some(response);
                }
            }
            let accepted = accepted.ok_or_else(|| anyhow::anyhow!("fork placement A did not execute"))?;
            if refusal_rules != expected_rules {
                return Err(anyhow::anyhow!(
                    "fork case {} refused B by {refusal_rules:?}, expected {expected_rules:?}",
                    fixture.tag
                ));
            }
            let replay = tokio::time::timeout(
                Duration::from_secs(30),
                rpc::execute_aft_quv_effect(&rpc_a, &fixture.manifest_a.effect_id, &candidate_a),
            ).await.map_err(|_| anyhow::anyhow!("fork terminal replay timed out"))??;
            if replay.portable_final_receipt
                || replay.consequence_receipt_jcs != accepted.consequence_receipt_jcs
            {
                return Err(anyhow::anyhow!("fork terminal replay changed the recorded result"));
            }
            let receipt: ConsequenceReceiptV1 = serde_json::from_slice(&accepted.consequence_receipt_jcs)?;
            let ConsequenceStateV1::Executed { resource_record, .. } = receipt.state else {
                return Err(anyhow::anyhow!("fork placement A was not executed"));
            };
            let observed_a = register_a
                .lookup(&fixture.manifest_a.resource_id, &fixture.manifest_a.idempotency_key)
                .map_err(|error| anyhow::anyhow!("fork resource lookup failed: {error:?}"))?;
            if receipt.manifest != fixture.manifest_a
                || observed_a.as_ref() != Some(&resource_record)
                || !register_a.verify_record_evidence(&resource_record)
            {
                return Err(anyhow::anyhow!("fork placement A differs from its durable resource mutation"));
            }
            let durable_records = usize::from(observed_a.is_some()) + usize::from(lookup_b(&mut register_b)?.is_some());
            if durable_records != 1 {
                return Err(anyhow::anyhow!("refused fork candidate mutated its durable resource"));
            }
            let accepted_payload = fixture.manifest_a.commitment()?;
            let refused_payload = fixture.manifest_b.commitment()?;
            // Retained operation starts since this case began: exactly one
            // executor operation for A, none at all for B on any process.
            let starts = operation_starts.since(started_at)?;
            let a_starts = starts.iter().filter(|start| start.payload == accepted_payload && !start.independent_preparation).count();
            let b_starts = starts.iter().filter(|start| start.payload == refused_payload).count();
            if a_starts != 1 || b_starts != 0 {
                return Err(anyhow::anyhow!(
                    "fork case {} observed {a_starts} executor operation(s) for A and {b_starts} for B",
                    fixture.tag
                ));
            }
            println!(
                "[M16Q-PREDECESSOR-FORK] case={} mode={} order={} refused_before_push=true refusals={refusals} same_executor={same_executor} refusal_rules={} accepts=1 durable_records={durable_records} predecessor_a={} predecessor_b={} accepted_payload={} refused_payload={} result=safe",
                fixture.tag,
                match fixture.mode { QuvAuthorityModeV0::Owned => "owned", QuvAuthorityModeV0::Unowned => "unowned" },
                fixture.order,
                refusal_rules.join(","),
                hex::encode([77_u8; 32]),
                hex::encode([78_u8; 32]),
                hex::encode(accepted_payload),
                hex::encode(refused_payload),
            );
        }

        let unrelated_candidate = m16q_candidate(
            &unrelated,
            network_id,
            configuration_root,
            unrelated_policy_root,
            unrelated_domain,
            members[2].0,
            &members[2].2,
        )?;
        let (expiry_rpc, expiry_effect, expiry_candidate, original_bytes) = expiry_replay
            .ok_or_else(|| anyhow::anyhow!("missing expired replay fixture"))?;
        // R1 finding 010: terminal-result replay of the expiring effect runs
        // concurrently with the unrelated singleton on the SAME executor
        // process, so the one global verifier operation is actually contended.
        // Replay must stay lookup-only (no executor operation start for its
        // payload) and the unrelated effect must finish within
        // delta_rt + M16Q_CONCURRENT_REPLAY_SLACK_MS.
        let unrelated_rpc = expiry_rpc.clone();
        let replay_payload = manifests[0].3.commitment()?;
        let unrelated_payload = unrelated.commitment()?;
        let concurrent_started_at = operation_starts.len();
        let (stop_replay, replay_stopped) = tokio::sync::watch::channel(false);
        let replay_pressure = async {
            let started = Instant::now();
            let mut count = 0_u64;
            loop {
                let response = tokio::time::timeout(
                    Duration::from_secs(30),
                    rpc::execute_aft_quv_effect_with_metadata(&expiry_rpc, &expiry_effect, &expiry_candidate),
                ).await.map_err(|_| anyhow::anyhow!("concurrent terminal replay RPC timed out"))??;
                let observed_height: u64 = response.metadata().get("ioi-quv-result-height")
                    .ok_or_else(|| anyhow::anyhow!("missing committed result height"))?
                    .to_str()?.parse()?;
                let response = response.into_inner();
                require_expired_terminal_observation(
                    expiry_height, observed_height, response.portable_final_receipt,
                    &response.consequence_receipt_jcs, &original_bytes,
                )?;
                count += 1;
                if *replay_stopped.borrow() && count >= 2 {
                    break;
                }
                if count == 4096 {
                    return Err(anyhow::anyhow!("terminal replay exhausted its finite request budget before unrelated completion"));
                }
            }
            Ok::<_, anyhow::Error>((count, started.elapsed().as_millis()))
        };
        let unrelated_call = async {
            let started = Instant::now();
            let result = tokio::time::timeout(
                Duration::from_secs(30),
                rpc::execute_aft_quv_effect(&unrelated_rpc, &unrelated.effect_id, &unrelated_candidate),
            ).await;
            let elapsed = started.elapsed().as_millis();
            let _ = stop_replay.send(true);
            (result, elapsed)
        };
        let (pressure, (unrelated_result, unrelated_elapsed_ms)) =
            tokio::join!(replay_pressure, unrelated_call);
        let (replay_count, replay_span_ms) = pressure?;
        let unrelated_response = unrelated_result
            .map_err(|_| anyhow::anyhow!("unrelated singleton timed out during terminal replay"))??;
        require_executed_nonportable_quv_receipt(
            &unrelated_response,
            &configured_members,
            &configured_members,
        )?;
        let starts = operation_starts.since(concurrent_started_at)?;
        let replay_starts = starts.iter().filter(|start| start.payload == replay_payload).count();
        let unrelated_starts = starts
            .iter()
            .filter(|start| start.payload == unrelated_payload && !start.independent_preparation)
            .count();
        if replay_starts != 0 || unrelated_starts != 1 {
            return Err(anyhow::anyhow!(
                "terminal replay was not lookup-only: replay_starts={replay_starts} unrelated_starts={unrelated_starts}"
            ));
        }
        if unrelated_elapsed_ms > u128::from(DELTA_RT_MILLIS + M16Q_CONCURRENT_REPLAY_SLACK_MS) {
            return Err(anyhow::anyhow!(
                "unrelated singleton exceeded delta_rt + slack during terminal replay: {unrelated_elapsed_ms}ms"
            ));
        }
        println!(
            "[M16Q-QUV] case=unrelated_after_conflict elapsed_ms={unrelated_elapsed_ms} result=executed"
        );
        println!(
            "[M16Q-CONCURRENT-REPLAY] unrelated_elapsed_ms={unrelated_elapsed_ms} replay_count={replay_count} replay_span_ms={replay_span_ms} delta_rt_ms={DELTA_RT_MILLIS} slack_ms={M16Q_CONCURRENT_REPLAY_SLACK_MS} replay_payload={} unrelated_payload={} lookup_only=true",
            hex::encode(replay_payload),
            hex::encode(unrelated_payload),
        );
        let expiry_started = Instant::now();
        // Public block availability can precede this endpoint's admitted height.
        // Poll its own metadata; every observation must preserve the terminal result.
        let observed_height = tokio::time::timeout(Duration::from_secs(M16Q_EXPIRY_WAIT_SECS), async {
            loop {
                let response = tokio::time::timeout(Duration::from_secs(30),
                    rpc::execute_aft_quv_effect_with_metadata(&expiry_rpc, &expiry_effect, &expiry_candidate)
                ).await.map_err(|_| anyhow::anyhow!("expired result replay RPC timed out"))??;
                let observed_height: u64 = response.metadata().get("ioi-quv-result-height")
                    .ok_or_else(|| anyhow::anyhow!("missing committed result height"))?
                    .to_str()?.parse()?;
                let response = response.into_inner();
                if require_expired_terminal_observation(
                    expiry_height, observed_height, response.portable_final_receipt,
                    &response.consequence_receipt_jcs, &original_bytes,
                )? {
                    break Ok::<u64, anyhow::Error>(observed_height);
                }
                println!("[M16Q-EXPIRY-WAIT] expiry_height={expiry_height} observed_height={observed_height} receipt_unchanged=true portable_final_receipt=false");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }).await.map_err(|_| anyhow::anyhow!("effect endpoint did not report admitted height beyond expiry_height={expiry_height} within {M16Q_EXPIRY_WAIT_SECS} seconds"))??;
        let expiry_elapsed_ms = expiry_started.elapsed().as_millis();
        println!("[M16Q-QUV] case=expired_result expiry_height={expiry_height} observed_height={observed_height} elapsed_ms={expiry_elapsed_ms} receipt_unchanged=true result=recorded");

        // R1 finding 007 (process level): a Byzantine process B is restarted
        // with the test-only status override so every status response it
        // sends claims the sole-correct member C's account (position 0). The
        // claim is an unauthenticated routing hint only; the strict-PQ
        // handshake must keep C's genuine carrier (process 0 itself here)
        // and B's genuine carrier bound to their proven keys. A fresh live
        // operation on C's executor must then still collect all four
        // configured replies. Losing C's reply, or routing it to B, is a real
        // finding and fails this case; the assertion is not to be relaxed.
        let claimed_position = 0;
        let claimant_position = 1;
        let (claimed_account, claimed_process, _) = &members[claimed_position];
        let (claimant_account, claimant_process, _) = &members[claimant_position];
        let (claimed_account, claimed_process) = (*claimed_account, *claimed_process);
        let (claimant_account, claimant_process) = (*claimant_account, *claimant_process);
        anyhow::ensure!(
            claimed_process != claimant_process && claimed_account != claimant_account,
            "status-claim case needs two distinct processes and accounts"
        );
        let claimed_hex = hex::encode(claimed_account.as_ref());
        let claimant_peer = cluster.validators[claimant_process]
            .validator()
            .keypair
            .public()
            .to_peer_id()
            .to_string();
        println!(
            "[M16Q-STATUS-CLAIM-EXPECT] member_position={claimed_position} account={claimed_hex} claimant_position={claimant_position} claimant_process={claimant_process} claimant_account={} claimant_peer={claimant_peer}",
            hex::encode(claimant_account.as_ref()),
        );
        let claim_events_from = network_events.len();
        let claimed_rpc = cluster.validators[claimed_process].validator().rpc_addr.clone();
        let claimant_rpc = cluster.validators[claimant_process].validator().rpc_addr.clone();
        cluster.validators[claimant_process]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[claimant_process]
            .validator_mut()
            .set_orchestration_restart_env("IOI_TESTING_AFT_STATUS_CLAIMED_ACCOUNT_HEX", &claimed_hex)?;
        cluster.validators[claimant_process]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        let reconnect_floor = rpc::get_status(&claimed_rpc).await?.height.saturating_add(1);
        wait_for_height(&claimant_rpc, reconnect_floor, Duration::from_secs(120)).await?;
        // The claim must have been advertised by B and refused by at least one
        // genuine process before the operation runs; otherwise the case would
        // measure an honest cluster.
        let claim_delivery = |records: &[NetworkEventRecord]| {
            let overrides = records
                .iter()
                .filter(|record| {
                    record.event == "testing_status_account_override"
                        && record.process_index == claimant_process
                        && record.claimed_account.as_deref() == Some(claimed_hex.as_str())
                        && record.local_peer.as_deref() == Some(claimant_peer.as_str())
                })
                .count();
            let refusals = records
                .iter()
                .filter(|record| {
                    record.event == "pq_peer_enrollment_refused"
                        && record.process_index != claimant_process
                        && record.peer.as_deref() == Some(claimant_peer.as_str())
                })
                .count();
            let foreign_overrides = records
                .iter()
                .filter(|record| {
                    record.event.starts_with("testing_status_account_override")
                        && record.process_index != claimant_process
                })
                .count();
            let invalid_overrides = records
                .iter()
                .filter(|record| record.event == "testing_status_account_override_invalid")
                .count();
            (overrides, refusals, foreign_overrides, invalid_overrides)
        };
        wait_for(
            "the Byzantine status claim to be advertised by B and refused by a genuine process",
            Duration::from_millis(250),
            Duration::from_secs(90),
            || {
                let observed = network_events.since(claim_events_from);
                async move {
                    let (overrides, refusals, _, _) = claim_delivery(&observed?);
                    Ok((overrides >= 1 && refusals >= 1).then_some(()))
                }
            },
        )
        .await?;
        let byzantine_candidate = m16q_candidate(
            &byzantine_status,
            network_id,
            configuration_root,
            byzantine_status_policy_root,
            byzantine_status_domain,
            claimed_account,
            &members[claimed_position].2,
        )?;
        let claim_started = Instant::now();
        let byzantine_response = tokio::time::timeout(
            Duration::from_secs(30),
            rpc::execute_aft_quv_effect(&claimed_rpc, &byzantine_status.effect_id, &byzantine_candidate),
        )
        .await
        .map_err(|_| anyhow::anyhow!("M16Q status-claim operation exceeded its client timeout"))??;
        let claim_elapsed_ms = claim_started.elapsed().as_millis();
        // ALL four configured members must have replied: C's own reply and
        // the genuine carrier for B are both still routed by proven keys.
        let claim_max_valid_reply_elapsed_ms = require_executed_nonportable_quv_receipt(
            &byzantine_response,
            &configured_members,
            &configured_members,
        )?;
        let (override_warnings, claim_refusals, foreign_overrides, invalid_overrides) =
            claim_delivery(&network_events.since(claim_events_from)?);
        if override_warnings < 1 || claim_refusals < 1 || foreign_overrides != 0 || invalid_overrides != 0 {
            return Err(anyhow::anyhow!(
                "status-claim evidence incomplete: override_warnings={override_warnings} claim_refusals={claim_refusals} foreign_overrides={foreign_overrides} invalid_overrides={invalid_overrides}"
            ));
        }
        println!(
            "[M16Q-QUV] case=byzantine_status_claim claimed_account={claimed_hex} claimant_process={claimant_process} claimant_peer={claimant_peer} members_valid={} override_warnings={override_warnings} claim_refusals={claim_refusals} elapsed_ms={claim_elapsed_ms} max_valid_reply_elapsed_ms={claim_max_valid_reply_elapsed_ms} qualified_envelope_ms={M16Q_QUALIFIED_ENVELOPE_MS} result=executed",
            configured_members.len(),
        );
        // Retire the override so the cluster is honest again for teardown.
        cluster.validators[claimant_process]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[claimant_process]
            .validator_mut()
            .clear_orchestration_restart_env("IOI_TESTING_AFT_STATUS_CLAIMED_ACCOUNT_HEX")?;
        cluster.validators[claimant_process]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        let honest_floor = rpc::get_status(&claimed_rpc).await?.height.saturating_add(1);
        wait_for_height(&claimant_rpc, honest_floor, Duration::from_secs(120)).await?;
        println!(
            "[M16Q-SUMMARY] sole_correct_elapsed_ms={solo_elapsed_ms:?} conflict_elapsed_ms={conflict_elapsed_ms} conflict_accepts={conflict_accepts} unrelated_elapsed_ms={unrelated_elapsed_ms} delta_rt_ms={DELTA_RT_MILLIS}"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    operation_starts.stop();
    network_events.stop();
    if run.is_err() {
        // Stop writers before retaining the exact failed local admission stores.
        for guard in &mut cluster.validators {
            if let Err(error) = guard.validator_mut().kill_orchestration().await {
                eprintln!("M16Q failure-state quiescence error: {error:#}");
            }
        }
        if let Some(destination) = std::env::var_os("IOI_AFT_BENCH_TRACE_DIR") {
            fn copy_tree(source: &std::path::Path, target: &std::path::Path) -> Result<()> {
                std::fs::create_dir_all(target)?;
                for entry in std::fs::read_dir(source)? {
                    let entry = entry?;
                    let kind = entry.file_type()?;
                    anyhow::ensure!(!kind.is_symlink(), "unexpected failure-state symlink");
                    let output = target.join(entry.file_name());
                    if kind.is_dir() {
                        copy_tree(&entry.path(), &output)?;
                    } else {
                        std::fs::copy(entry.path(), output)?;
                    }
                }
                Ok(())
            }
            for (index, guard) in cluster.validators.iter().enumerate() {
                let source = guard.validator().state_dir().join("ordering-finality");
                let target = std::path::PathBuf::from(&destination)
                    .join("failed-admission-state")
                    .join(index.to_string());
                // Public test admission material only; no signer/custody keys.
                for directory in [
                    "canonical",
                    "staged",
                    "availability",
                    "deliveries",
                    "projections",
                ] {
                    if source.join(directory).is_dir() {
                        if let Err(error) =
                            copy_tree(&source.join(directory), &target.join(directory))
                        {
                            eprintln!("M16Q failure-state capture error: {error:#}");
                        }
                    }
                }
            }
        }
    }
    let shutdown = cluster.shutdown().await;
    run?;
    shutdown?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_aft_pq_four_validator_timeout_quorum_and_restart() -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    build_test_artifacts();
    let stable = tempfile::tempdir()?;
    let stable_path = stable.path().join("pq-aft-cluster");

    // Normal proposal cadence is safely below the pacemaker timeout. The test
    // forces a genuine timeout by stopping the validator scheduled to lead the
    // next height; the other three validators must then form the exact q=3
    // scoped ML-DSA certificate and continue in the next view. Full-mesh
    // bootstrapping exercises every pairwise ML-KEM/ML-DSA channel.
    let _env = ScopedEnv::set(&[
        ("IOI_TEST_FULL_MESH_BOOTNODES", "1"),
        ("IOI_TEST_READY_HEIGHT_LAG_MAX", "0"),
        ("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS", "30"),
        ("IOI_TEST_SIGNER_STARTUP_TIMEOUT_SECS", "120"),
        ("IOI_BENCH_BLOCK_INTERVAL_MS", "1000"),
        ("IOI_AFT_BLOCK_DIRECT_RELAY", "1"),
    ]);

    let build_cluster = || {
        TestCluster::builder()
            .with_validators(4)
            .with_consensus_type("Aft")
            .with_aft_safety_mode(AftSafetyMode::ClassicBft)
            .with_pq_consensus_profile()
            .with_state_tree("IAVL")
            .with_chain_id(0xA17)
            .with_state_dir(stable_path.clone())
            .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
                chain_id: 0xA17,
                grace_period_blocks: 0,
                accept_staged_during_grace: false,
                allowed_target_suites: vec![SignatureSuite::ML_DSA_44],
                allow_downgrade: false,
            }))
    };

    let mut cluster = build_cluster().build().await?;
    let terminal_finality_errors = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    for (index, guard) in cluster.validators.iter().enumerate() {
        let (mut orchestration, _, _) = guard.validator().subscribe_logs();
        let terminal_finality_errors = terminal_finality_errors.clone();
        tokio::spawn(async move {
            while let Ok(line) = orchestration.recv().await {
                let normalized = line.to_ascii_lowercase();
                if normalized.contains("terminal runtime finality")
                    || normalized.contains("node frozen")
                {
                    terminal_finality_errors
                        .lock()
                        .expect("terminal-finality evidence lock poisoned")
                        .push(format!("node {index}: {line}"));
                }
                if ["pq", "timeout", "fallback", "quorum", "error", "failed"]
                    .iter()
                    .any(|needle| normalized.contains(needle))
                {
                    println!("[PQ-AFT node {index}] {line}");
                }
            }
        });
    }
    let first_run = async {
        let mut observed_heights = Vec::with_capacity(cluster.validators.len());
        for guard in &cluster.validators {
            observed_heights.push(rpc::get_status(&guard.validator().rpc_addr).await?.height);
        }
        let baseline = observed_heights.into_iter().max().unwrap_or(1);

        // Fail a leader three heights ahead. The two immediately preceding
        // heights have different round-robin leaders, allowing the three
        // survivors to converge after the process stop before they encounter
        // the missing proposer.
        let timeout_height = baseline + 3;
        let mut validator_order = cluster
            .validators
            .iter()
            .enumerate()
            .map(|(index, guard)| {
                let keypair = guard
                    .validator()
                    .pqc_keypair
                    .as_ref()
                    .expect("strict PQ cluster must retain its ML-DSA validator key");
                let account = account_id_from_key_material(
                    SignatureSuite::ML_DSA_44,
                    &keypair.public_key().to_bytes(),
                )
                .expect("ML-DSA validator account derivation must succeed");
                (account, index)
            })
            .collect::<Vec<_>>();
        validator_order.sort_by_key(|(account, _)| *account);
        let failed_leader_index = validator_order[((timeout_height - 1) as usize) % 4].1;
        let observer_index = if failed_leader_index == 0 { 1 } else { 0 };
        let first_rpc = cluster.validators[observer_index]
            .validator()
            .rpc_addr
            .clone();

        println!(
            "--- PQ AFT fault drill: baseline={baseline}, timeout_height={timeout_height}, failed_leader_index={failed_leader_index}, observer_index={observer_index} ---"
        );

        {
            let backend = cluster.validators[failed_leader_index]
                .validator_mut()
                .backend
                .as_any_mut()
                .downcast_mut::<ProcessBackend>()
                .ok_or_else(|| {
                    anyhow::anyhow!("PQ timeout drill requires the process test backend")
                })?;
            let mut leader = backend
                .orchestration_process
                .take()
                .ok_or_else(|| anyhow::anyhow!("scheduled leader process was not running"))?;
            leader.start_kill()?;
            let _ = leader.wait().await?;
        }

        // A cold debug build verifies three independent ML-DSA timeout votes
        // and a full ML-DSA proposal/QC while repeatedly exercising dead-peer
        // transport. The protocol timeout remains 30 seconds; this outer
        // harness deadline only gives the exact-q recovery enough host budget
        // to finish before teardown on contended CI workers.
        wait_for_height(&first_rpc, timeout_height + 1, Duration::from_secs(240)).await?;

        let mut saw_timeout_certificate = false;
        let mut saw_exact_q_parent = false;
        for height in 1..=timeout_height + 1 {
            let block = rpc::get_block_by_height_resilient(&first_rpc, height)
                .await?
                .ok_or_else(|| anyhow::anyhow!("PQ AFT cluster omitted block {height}"))?;
            if block.header.producer_key_suite != SignatureSuite::ML_DSA_44 {
                return Err(anyhow::anyhow!(
                    "block {height} downgraded producer suite to {:?}",
                    block.header.producer_key_suite
                ));
            }
            if block.header.timeout_certificate.is_some() {
                return Err(anyhow::anyhow!(
                    "block {height} carried legacy unscoped timeout evidence"
                ));
            }
            if let Some(certificate) = block.header.aft_timeout_certificate.as_ref() {
                if certificate.votes.len() != 3 {
                    return Err(anyhow::anyhow!(
                        "block {height} carried {} scoped timeout votes; expected exact q=3",
                        certificate.votes.len()
                    ));
                }
                if certificate.height != timeout_height {
                    return Err(anyhow::anyhow!(
                        "block {height} carried timeout evidence for unexpected height {}",
                        certificate.height
                    ));
                }
                saw_timeout_certificate = true;
            }
            if height > 1 && block.header.parent_qc.signatures.len() == 3 {
                saw_exact_q_parent = true;
            }
        }
        if !saw_timeout_certificate {
            return Err(anyhow::anyhow!(
                "four-validator PQ AFT drill formed no scoped timeout certificate"
            ));
        }
        if !saw_exact_q_parent {
            return Err(anyhow::anyhow!(
                "four-validator PQ AFT drill formed no exact q=3 parent quorum"
            ));
        }
        Ok(rpc::get_status(&first_rpc).await?.height)
    }
    .await;
    let first_shutdown = cluster.shutdown().await;
    let before_restart = first_run?;
    first_shutdown?;

    let resumed = build_cluster().build().await?;
    for (index, guard) in resumed.validators.iter().enumerate() {
        let (mut orchestration, _, _) = guard.validator().subscribe_logs();
        let terminal_finality_errors = terminal_finality_errors.clone();
        tokio::spawn(async move {
            while let Ok(line) = orchestration.recv().await {
                let normalized = line.to_ascii_lowercase();
                if normalized.contains("terminal runtime finality")
                    || normalized.contains("node frozen")
                {
                    terminal_finality_errors
                        .lock()
                        .expect("terminal-finality evidence lock poisoned")
                        .push(format!("restarted node {index}: {line}"));
                }
            }
        });
    }
    let resumed_rpc = resumed.validators[0].validator().rpc_addr.clone();
    let resumed_run = async {
        wait_for_height(&resumed_rpc, before_restart + 2, Duration::from_secs(240)).await?;
        let resumed_block = rpc::get_block_by_height_resilient(&resumed_rpc, before_restart + 1)
            .await?
            .ok_or_else(|| anyhow::anyhow!("PQ AFT cluster did not continue after restart"))?;
        if resumed_block.header.producer_key_suite != SignatureSuite::ML_DSA_44 {
            return Err(anyhow::anyhow!(
                "resumed PQ AFT cluster downgraded its producer suite"
            ));
        }
        Ok(())
    }
    .await;
    let resumed_shutdown = resumed.shutdown().await;
    resumed_run?;
    resumed_shutdown?;
    let terminal_finality_errors = terminal_finality_errors
        .lock()
        .expect("terminal-finality evidence lock poisoned")
        .clone();
    if !terminal_finality_errors.is_empty() {
        return Err(anyhow::anyhow!(
            "PQ AFT drill emitted terminal runtime-finality failures:\n{}",
            terminal_finality_errors.join("\n")
        ));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_aft_pq_hash_fallback_executes_virtual_block() -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    build_test_artifacts();
    let stable = tempfile::tempdir()?;
    let stable_path = stable.path().join("pq-hash-fallback");
    let _env = ScopedEnv::set(&[
        ("IOI_TEST_FULL_MESH_BOOTNODES", "1"),
        // Startup readiness may observe one node producing the next block
        // while it samples the others. Exact fallback convergence is checked
        // explicitly below, so requiring a zero-height observation window
        // only makes the cold-restart half race normal forward progress.
        ("IOI_TEST_READY_HEIGHT_LAG_MAX", "1"),
        ("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS", "30"),
        ("IOI_TEST_SIGNER_STARTUP_TIMEOUT_SECS", "120"),
        ("IOI_BENCH_BLOCK_INTERVAL_MS", "500"),
        ("IOI_AFT_BLOCK_DIRECT_RELAY", "1"),
        ("IOI_TEST_AFT_FORCE_HASH_FALLBACK_ARMED", "1"),
        ("IOI_TEST_AFT_FORCE_HASH_FALLBACK_HEIGHT", "4"),
        ("IOI_TEST_AFT_FORCE_HASH_FALLBACK_VIEWS", "3"),
        ("IOI_TEST_AFT_STAGE_OPTIMISTIC_PROJECTION", "1"),
    ]);
    let build_cluster = || {
        TestCluster::builder()
            .with_validators(4)
            .with_consensus_type("Aft")
            .with_aft_safety_mode(AftSafetyMode::ClassicBft)
            .with_pq_consensus_profile()
            .with_state_tree("IAVL")
            .with_chain_id(0xA18)
            .with_state_dir(stable_path.clone())
            .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
                chain_id: 0xA18,
                grace_period_blocks: 0,
                accept_staged_during_grace: false,
                allowed_target_suites: vec![SignatureSuite::ML_DSA_44],
                allow_downgrade: false,
            }))
    };
    let cluster = build_cluster().build().await?;

    let terminal_errors = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    for (index, guard) in cluster.validators.iter().enumerate() {
        let (mut orchestration, _, _) = guard.validator().subscribe_logs();
        let terminal_errors = terminal_errors.clone();
        tokio::spawn(async move {
            while let Ok(line) = orchestration.recv().await {
                let normalized = line.to_ascii_lowercase();
                if normalized.contains("terminal runtime finality")
                    || normalized.contains("node frozen")
                {
                    terminal_errors
                        .lock()
                        .expect("fallback error lock poisoned")
                        .push(format!("node {index}: {line}"));
                }
                if normalized.contains("hash")
                    || normalized.contains("fallback")
                    || normalized.contains("timeout")
                {
                    if normalized.contains("\"level\":\"debug\"") {
                        continue;
                    } else if normalized.contains("stack backtrace") {
                        println!("[PQ-HASH-FALLBACK node {index}] timeout path returned an error (backtrace elided)");
                    } else {
                        println!("[PQ-HASH-FALLBACK node {index}] {line}");
                    }
                }
            }
        });
    }

    let observer = cluster.validators[0].validator().rpc_addr.clone();
    let run = async {
        wait_for_height(&observer, 3, Duration::from_secs(60)).await?;
        let optimistic_projection = tokio::time::timeout(Duration::from_secs(60), async {
            'wait_for_projection: loop {
                for guard in &cluster.validators {
                    if let Some(block) =
                        rpc::get_block_by_height_resilient(&guard.validator().rpc_addr, 4).await?
                    {
                        if block.header.view == 0 && block.header.signature.is_empty() {
                            break 'wait_for_projection Ok::<_, anyhow::Error>(block);
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("normal producer staged no optimistic height-4 projection"))??;
        let optimistic_projection_hash = optimistic_projection.header.hash()?;
        println!(
            "--- observed production-generated speculative workload projection at height 4: {} ---",
            hex::encode(&optimistic_projection_hash)
        );
        // Hash-only agreement plus four independent ML-DSA-heavy offline
        // admission checks is deliberately the pessimistic path. Debug CI on
        // constrained hosts can spend well beyond eight minutes on the
        // complete fallback plus native-child verification, so this
        // wall-clock guard must not masquerade as a protocol timeout. The
        // first optimistic child may use the
        // virtual block's empty-signature canonical reference only while the
        // engine retains the separately typed, fully verified asynchronous
        // predecessor proof. It must never manufacture a native QC.
        wait_for_height(&observer, 5, Duration::from_secs(900)).await?;
        let block = rpc::get_block_by_height_resilient(&observer, 4)
            .await?
            .ok_or_else(|| anyhow::anyhow!("hash fallback omitted virtual block 4"))?;
        if block.header.view != 4
            || !block.header.signature.is_empty()
            || block.header.producer_key_suite != SignatureSuite::ML_DSA_44
            || block.header.aft_timeout_certificate.is_some()
        {
            return Err(anyhow::anyhow!(
                "height 4 is not the canonical hash-fallback virtual envelope: view={}, signature_len={}, suite={:?}, timeout_extension={}",
                block.header.view,
                block.header.signature.len(),
                block.header.producer_key_suite,
                block.header.aft_timeout_certificate.is_some(),
            ));
        }
        if block.header.parent_qc.height != 3 {
            return Err(anyhow::anyhow!(
                "hash fallback virtual block did not bind the exact height-3 high QC"
            ));
        }
        let expected_hash = block.header.hash()?;
        if expected_hash == optimistic_projection_hash {
            return Err(anyhow::anyhow!(
                "hash fallback did not replace the staged optimistic workload projection"
            ));
        }
        for guard in &cluster.validators {
            wait_for_height(
                &guard.validator().rpc_addr,
                5,
                Duration::from_secs(120),
            )
            .await?;
            let peer_block = rpc::get_block_by_height_resilient(&guard.validator().rpc_addr, 4)
                .await?
                .ok_or_else(|| anyhow::anyhow!("peer omitted hash fallback block 4"))?;
            if peer_block.header.hash()? != expected_hash {
                return Err(anyhow::anyhow!(
                    "validators executed different hash-fallback virtual blocks"
                ));
            }
        }
        // Height RPCs expose the workload's live candidate as well as the
        // admitted floor. Wait until every validator has crossed H=5 before
        // asserting the stabilized re-entry header; an earlier same-height
        // candidate may still be inside the bounded replacement window.
        let optimistic_child = rpc::get_block_by_height_resilient(&observer, 5)
            .await?
            .ok_or_else(|| anyhow::anyhow!("optimistic path did not resume at height 5"))?;
        if optimistic_child.header.parent_hash != expected_hash.as_slice()
            || optimistic_child.header.parent_qc.height != 4
            || optimistic_child.header.parent_qc.block_hash != expected_hash.as_slice()
            || !optimistic_child.header.parent_qc.signatures.is_empty()
            || !optimistic_child
                .header
                .parent_qc
                .aggregated_signature
                .is_empty()
            || !optimistic_child.header.parent_qc.signers_bitfield.is_empty()
            || optimistic_child.header.signature.is_empty()
            || optimistic_child.header.producer_key_suite != SignatureSuite::ML_DSA_44
        {
            return Err(anyhow::anyhow!(
                "height 5 did not use the typed async-parent bridge followed by native PQ production: parent_hash_match={}, parent_qc_height={}, parent_qc_hash_match={}, parent_qc_signatures={}, parent_qc_aggregate={}, parent_qc_bitfield={}, child_signature={}, child_suite={:?}",
                optimistic_child.header.parent_hash == expected_hash.as_slice(),
                optimistic_child.header.parent_qc.height,
                optimistic_child.header.parent_qc.block_hash == expected_hash.as_slice(),
                optimistic_child.header.parent_qc.signatures.len(),
                optimistic_child.header.parent_qc.aggregated_signature.len(),
                optimistic_child.header.parent_qc.signers_bitfield.len(),
                optimistic_child.header.signature.len(),
                optimistic_child.header.producer_key_suite,
            ));
        }
        let metrics = aft_hash_async_metrics(
            &cluster.validators[0]
                .validator()
                .orchestration_telemetry_addr,
        )
        .await?;
        for stage in [
            "execution_prepare",
            "workload_execution",
            "runtime_stage",
            "runtime_admission",
            "parent_proof_install",
        ] {
            let needle = format!(
                "ioi_aft_hash_async_stage_duration_seconds_count{{stage=\"{stage}\"}} "
            );
            if !metrics.lines().any(|line| line.starts_with(&needle)) {
                return Err(anyhow::anyhow!(
                    "production fallback metrics omitted stage {stage}"
                ));
            }
        }
        println!("--- AFT hash-async production metrics ---");
        for line in metrics.lines().filter(|line| {
            line.starts_with("ioi_aft_hash_async_messages_total")
                || line.starts_with("ioi_aft_hash_async_bytes_total")
                || line.starts_with("ioi_aft_hash_async_stage_duration_seconds_count")
                || line.starts_with("ioi_aft_hash_async_stage_duration_seconds_sum")
        }) {
            println!("{line}");
        }
        Ok::<_, anyhow::Error>(expected_hash)
    }
    .await;
    let shutdown = cluster.shutdown().await;
    let expected_hash = run?;
    shutdown?;

    // Reopen the exact stable process state. Startup must replay the durable
    // fallback transition, reconstruct the compact terminal session, reinstall
    // the typed async-parent proof, and continue without reopening agreement or
    // manufacturing a native QC for the virtual block.
    let resumed = build_cluster().build().await?;
    let resumed_log_tails =
        std::sync::Arc::new(std::sync::Mutex::new(vec![
            Vec::<String>::new();
            resumed.validators.len()
        ]));
    for (index, guard) in resumed.validators.iter().enumerate() {
        let (mut orchestration, _, _) = guard.validator().subscribe_logs();
        let terminal_errors = terminal_errors.clone();
        let resumed_log_tails = resumed_log_tails.clone();
        tokio::spawn(async move {
            while let Ok(line) = orchestration.recv().await {
                {
                    const MAX_DIAGNOSTIC_LINES: usize = 256;
                    let mut tails = resumed_log_tails
                        .lock()
                        .expect("restart diagnostic log lock poisoned");
                    let tail = &mut tails[index];
                    tail.push(line.clone());
                    if tail.len() > MAX_DIAGNOSTIC_LINES {
                        tail.remove(0);
                    }
                }
                let normalized = line.to_ascii_lowercase();
                if normalized.contains("terminal runtime finality")
                    || normalized.contains("node frozen")
                {
                    terminal_errors
                        .lock()
                        .expect("fallback error lock poisoned")
                        .push(format!("restarted node {index}: {line}"));
                }
            }
        });
    }
    let resumed_rpc = resumed.validators[0].validator().rpc_addr.clone();
    let resumed_run = async {
        if let Err(wait_error) = wait_for_height(&resumed_rpc, 7, Duration::from_secs(240)).await {
            let mut diagnostics = vec![format!("observer wait failed: {wait_error:#}")];
            for (index, guard) in resumed.validators.iter().enumerate() {
                let rpc_addr = &guard.validator().rpc_addr;
                let height = rpc::get_chain_height(rpc_addr)
                    .await
                    .map(|height| height.to_string())
                    .unwrap_or_else(|error| format!("rpc-error({error:#})"));
                let mut available = Vec::new();
                for height_to_probe in 4..=7 {
                    match rpc::get_block_by_height_resilient(rpc_addr, height_to_probe).await {
                        Ok(Some(block)) => available.push(format!(
                            "H{}:view{}:sig{}",
                            height_to_probe,
                            block.header.view,
                            block.header.signature.len()
                        )),
                        Ok(None) => available.push(format!("H{height_to_probe}:missing")),
                        Err(error) => {
                            available.push(format!("H{height_to_probe}:rpc-error({error:#})"))
                        }
                    }
                }
                diagnostics.push(format!(
                    "node {index}: reported_height={height}; {}",
                    available.join(", ")
                ));
            }
            let tails = resumed_log_tails
                .lock()
                .expect("restart diagnostic log lock poisoned")
                .clone();
            for (index, tail) in tails.iter().enumerate() {
                diagnostics.push(format!(
                    "node {index} orchestration tail ({} lines):\n{}",
                    tail.len(),
                    tail.join("\n")
                ));
            }
            return Err(anyhow::anyhow!(
                "post-restart PQ AFT progress diagnostics:\n{}",
                diagnostics.join("\n")
            ));
        }
        let recovered_virtual = rpc::get_block_by_height_resilient(&resumed_rpc, 4)
            .await?
            .ok_or_else(|| anyhow::anyhow!("restart omitted hash-fallback block 4"))?;
        if recovered_virtual.header.hash()? != expected_hash {
            return Err(anyhow::anyhow!(
                "restart changed the admitted hash-fallback block"
            ));
        }
        let resumed_child = rpc::get_block_by_height_resilient(&resumed_rpc, 6)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("hash-fallback cluster did not advance after restart")
            })?;
        if resumed_child.header.signature.is_empty()
            || resumed_child.header.producer_key_suite != SignatureSuite::ML_DSA_44
        {
            return Err(anyhow::anyhow!(
                "post-restart optimistic production downgraded or lost authentication"
            ));
        }
        Ok(())
    }
    .await;
    let resumed_shutdown = resumed.shutdown().await;
    resumed_run?;
    resumed_shutdown?;
    let terminal_errors = terminal_errors
        .lock()
        .expect("fallback error lock poisoned")
        .clone();
    if !terminal_errors.is_empty() {
        return Err(anyhow::anyhow!(
            "PQ hash-fallback drill emitted terminal failures:\n{}",
            terminal_errors.join("\n")
        ));
    }
    Ok(())
}

#[test]
fn quv_conflict_assertion_requires_structured_refusal() {
    fn marked(code: tonic::Code, marker: &'static str) -> tonic::Status {
        let mut status = tonic::Status::new(code, "diagnostic text may change");
        status.metadata_mut().insert(
            "ioi-quv-refusal",
            tonic::metadata::MetadataValue::from_static(marker),
        );
        status
    }
    let typed = anyhow::Error::new(marked(tonic::Code::Aborted, "conflict-disclosed-v0"))
        .context("executor request");
    require_quv_conflict_rejection(&typed).unwrap();
    for error in [
        anyhow::anyhow!("a valid conflict was disclosed"),
        anyhow::Error::new(tonic::Status::aborted("a valid conflict was disclosed")),
        anyhow::Error::new(marked(tonic::Code::Unavailable, "conflict-disclosed-v0")),
        anyhow::Error::new(marked(tonic::Code::Aborted, "unknown-refusal")),
    ] {
        assert!(require_quv_conflict_rejection(&error).is_err());
    }
}

fn require_expired_terminal_observation(
    expiry_height: u64,
    observed_height: u64,
    portable_final_receipt: bool,
    receipt: &[u8],
    original: &[u8],
) -> Result<bool> {
    let receipt_unchanged = receipt == original;
    anyhow::ensure!(
        !portable_final_receipt && receipt_unchanged,
        "terminal replay changed: expiry_height={expiry_height} observed_height={observed_height} portable_final_receipt={portable_final_receipt} receipt_unchanged={receipt_unchanged}"
    );
    Ok(observed_height > expiry_height)
}

#[test]
fn quv_expired_result_requires_strict_admitted_height_and_unchanged_receipt() {
    for (height, expired) in [(9, false), (10, false), (11, true)] {
        assert_eq!(
            require_expired_terminal_observation(10, height, false, b"stored", b"stored").unwrap(),
            expired
        );
        for (portable, receipt) in [(true, b"stored".as_slice()), (false, b"changed")] {
            let error =
                require_expired_terminal_observation(10, height, portable, receipt, b"stored")
                    .unwrap_err();
            assert!(error
                .to_string()
                .contains(&format!("observed_height={height}")));
        }
    }
}
