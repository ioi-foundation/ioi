#![cfg(all(feature = "consensus-aft", feature = "vm-wasm", feature = "state-iavl"))]

//! Long-lived real wallet.network fixture used by the Hypervisor room-participation verifier.
//!
//! This is deliberately a real one-validator cluster. Setup is performed through signed
//! `CallService` transactions: configure the control root, register Hypervisor's capability
//! client, register the approval authorities, and install root-signed principal bindings. The
//! JavaScript verifier only receives the public RPC coordinates and encrypted capability-key
//! path; it never receives a resolver-shaped response fixture.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::fd::AsRawFd;

use anyhow::{anyhow, Context, Result};
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair};
use ioi_api::state::service_namespace_prefix;
use ioi_cli::testing::{
    build_test_artifacts,
    rpc::{
        get_block_by_height, get_chain_height, get_chain_timestamp, query_state_key,
        submit_transaction_profiled, tip_height_resilient, SubmissionProfile,
    },
    wait_for_height, TestCluster,
};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
use ioi_services::wallet_network::{
    ApprovalGrantConsumptionReceipt, ConsumeApprovalGrantForEffectV2Params,
    ExpectedPrincipalAuthorityBinding, RecordStandingApprovalGrantParams,
    RegisterApprovalAuthorityParams, RevokeStandingApprovalGrantParams, StandingApprovalGrantState,
    StandingApprovalGrantStatus,
};
use ioi_types::app::action::{ApprovalAuthority, ApprovalGrant, StandingApprovalGrant};
use ioi_types::app::wallet_network::{
    IssuePrincipalAuthorityBindingParams, PrincipalAuthorityBindingHeadV1,
    PrincipalAuthorityBindingProofV1, PrincipalAuthorityBindingStatementV1,
    PrincipalAuthorityBindingStatus, PrincipalAuthorityKind, RevokePrincipalAuthorityBindingParams,
    VaultSurface, WalletApprovalDecision, WalletApprovalDecisionKind, WalletClientRole,
    WalletClientState, WalletConfigureControlRootParams, WalletControlPlaneRootRecord,
    WalletInterceptionContext, WalletRegisterClientParams, WalletRegisteredClientRecord,
    PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
};
use ioi_types::app::{
    account_id_from_key_material, AccountId, ActionTarget, BlockTimingParams, BlockTimingRuntime,
    ChainId, ChainTransaction, SignHeader, SignatureProof, SignatureSuite, StateEntry,
    SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use ioi_types::config::{AftSafetyMode, ServicePolicy};
use ioi_types::keys::ACCOUNT_NONCE_PREFIX;
use ioi_types::service_configs::MethodPermission;
use ioi_validator::common::GuardianContainer;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const HOST_SEED: [u8; 32] = [0x07; 32];
const PARTICIPANT_SEED: [u8; 32] = [0x09; 32];
const PARTICIPANT_TWO_SEED: [u8; 32] = [0x0a; 32];
const PARTICIPANT_THREE_SEED: [u8; 32] = [0x0b; 32];
const SCOPE_LIMITED_PARTICIPANT_SEED: [u8; 32] = [0x0c; 32];
const SUCCESSOR_AUTHORITY_SEED: [u8; 32] = [0x0d; 32];
const ROOT_SEED: [u8; 32] = [0x41; 32];
const CAPABILITY_SEED: [u8; 32] = [0x31; 32];
const EXPIRES_AT_MS: u64 = 1_850_000_000_000;
const COMMAND_SCHEMA_VERSION: u16 = 1;
const MAX_COMMAND_BYTES: u64 = 64 * 1024;
const MAX_PENDING_COMMANDS: usize = 64;
const SYSTEM_GENESIS_SCOPE: &str = "scope:autonomous_system.genesis_admit";
const SYSTEM_SEQUENCE_ZERO_SCOPE: &str = "scope:autonomous_system.genesis_materialize";
const SYSTEM_INITIALIZE_SCOPE: &str = "scope:autonomous_system.lifecycle.initialize";
const SYSTEM_ACTIVATE_SCOPE: &str = "scope:autonomous_system.lifecycle.activate";
const SYSTEM_AMENDMENT_SCOPE: &str = "scope:autonomous_system.lifecycle.amend_constitution";
const SYSTEM_AMENDMENT_APPROVAL_SCOPE: &str =
    "scope:autonomous_system.governance.approve_constitution_amendment";
const GOAL_RUN_CREATE_SCOPE: &str = "scope:goal.run.create";
const SYSTEM_GENESIS_APPROVAL_REASON: &str = "System genesis admission fixture approval";
const SYSTEM_SEQUENCE_ZERO_APPROVAL_REASON: &str =
    "System sequence-zero materialization fixture approval";
const SYSTEM_INITIALIZE_APPROVAL_REASON: &str = "System lifecycle initialize fixture approval";
const SYSTEM_ACTIVATE_APPROVAL_REASON: &str = "System lifecycle activate fixture approval";
const PROTECTED_TRANSITION_APPROVAL_REASON: &str =
    "System protected lifecycle transition fixture approval";
const SYSTEM_AMENDMENT_APPROVAL_REASON: &str = "System constitutional amendment fixture approval";
const SYSTEM_AMENDMENT_GOVERNANCE_APPROVAL_REASON: &str =
    "System constitutional amendment governance fixture approval";
const NAMED_CONTINUITY_APPROVAL_REASON: &str =
    "System named continuity transition fixture approval";
const LIVE_ROUTE_APPROVAL_REASON: &str = "Hypervisor live-route authority fixture approval";
const APPLICATION_GOVERNANCE_APPROVAL_REASON: &str = "Application governed-effect fixture approval";
const GOAL_RUN_CREATE_APPROVAL_REASON: &str = "GoalRun creation fixture approval";
const UNKNOWN_GOVERNED_SCOPE_ERROR: &str =
    "record_approval target_scope is not one of the fixture's recognized governed scopes";
const APPLICATION_GOVERNANCE_SCOPE_PREFIXES: [&str; 9] = [
    "room_participation.",
    "resource_offer.",
    "capability_offer.",
    "work_eligibility.",
    "work_frontier.",
    "work_claim.",
    "attempt.",
    "finding.",
    "verifier_challenge.",
];
const PROTECTED_TRANSITION_OPS: [&str; 14] = [
    "pause",
    "resume",
    "suspend",
    "reinstate",
    "enter_dormancy",
    "wake",
    "begin_recovery",
    "complete_recovery",
    "quarantine",
    "release_quarantine",
    "retire",
    "archive",
    "revoke",
    "decommission",
];
const NAMED_CONTINUITY_SCOPES: [&str; 10] = [
    "scope:autonomous_system.continuity.initiate_succession",
    "scope:autonomous_system.continuity.complete_succession",
    "scope:autonomous_system.continuity.migrate",
    "scope:autonomous_system.continuity.migration_destination_acknowledge",
    "scope:autonomous_system.continuity.initiate_dissolution",
    "scope:autonomous_system.continuity.open_dissolution_disposition",
    "scope:autonomous_system.continuity.record_dissolution_domain_outcome",
    "scope:autonomous_system.continuity.complete_dissolution",
    "scope:autonomous_system.network_enrollment.local.enroll",
    "scope:autonomous_system.network_enrollment.local.exit",
];

fn protected_transition_scope(target_scope: &str) -> bool {
    target_scope
        .strip_prefix("scope:autonomous_system.lifecycle.")
        .is_some_and(|op| PROTECTED_TRANSITION_OPS.contains(&op))
}

fn named_continuity_scope(target_scope: &str) -> bool {
    NAMED_CONTINUITY_SCOPES.contains(&target_scope)
}

fn live_route_scope(target_scope: &str) -> bool {
    target_scope.starts_with("scope:hypervisor.live-route.")
}

fn application_governance_scope(target_scope: &str) -> bool {
    APPLICATION_GOVERNANCE_SCOPE_PREFIXES
        .iter()
        .any(|prefix| target_scope.starts_with(prefix) && target_scope.len() > prefix.len())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCommand {
    schema_version: u16,
    operation: String,
    principal_ref: String,
    #[serde(default)]
    policy_hash: Option<String>,
    #[serde(default)]
    request_hash: Option<String>,
    #[serde(default)]
    approval_grant: Option<ApprovalGrant>,
    #[serde(default)]
    target_scope: Option<String>,
    #[serde(default)]
    standing_approval_grant: Option<StandingApprovalGrant>,
    #[serde(default)]
    standing_authority_envelope: Option<Value>,
    #[serde(default)]
    approval_ceremony_context: Option<Value>,
    #[serde(default)]
    auth_factor_receipt: Option<Value>,
    #[serde(default)]
    standing_grant_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct FixtureCommandResponse {
    schema_version: u16,
    command_id: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    standing_grant_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    standing_envelope_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    standing_grant_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_timestamp_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

enum FixtureCommandResult {
    Approval([u8; 32]),
    Revocation(String),
    StandingRecorded {
        grant_hash: [u8; 32],
        standing_envelope_hash: [u8; 32],
    },
    StandingRevoked([u8; 32]),
    ChainTimestamp(u64),
}

async fn latest_committed_chain_timestamp_ms(rpc_addr: &str) -> Result<u64> {
    // The compatibility status surface can retain both the synthetic parent
    // timestamp and its height in this harness. Walk the committed block store
    // instead; transaction execution consumes those exact headers.
    let height = tip_height_resilient(rpc_addr).await?;
    let block = get_block_by_height(rpc_addr, height)
        .await?
        .ok_or_else(|| anyhow!("wallet fixture latest committed block {height} is unavailable"))?;
    let timestamp_ms = block.header.timestamp_ms_or_legacy();
    if timestamp_ms == 0 {
        return Err(anyhow!(
            "wallet fixture latest committed block has a zero timestamp"
        ));
    }
    Ok(timestamp_ms)
}

fn keypair(seed: &[u8; 32]) -> Result<Ed25519KeyPair> {
    let private =
        Ed25519PrivateKey::from_bytes(seed).map_err(|error| anyhow!(error.to_string()))?;
    Ed25519KeyPair::from_private_key(&private).map_err(|error| anyhow!(error.to_string()))
}

fn wallet_policy() -> ServicePolicy {
    let methods = [
        "configure_control_root@v1",
        "register_client@v1",
        "register_approval_authority@v1",
        "issue_principal_authority_binding@v1",
        "revoke_principal_authority_binding@v1",
        "resolve_principal_authority@v1",
        "record_approval@v1",
        "consume_approval_grant_for_effect@v1",
        "consume_approval_grant_for_effect@v2",
        "record_standing_approval_grant@v1",
        "consume_standing_approval_grant_for_effect@v1",
        "settle_standing_approval_grant_consumption@v1",
        "revoke_standing_approval_grant@v1",
    ]
    .into_iter()
    .map(|method| (method.to_string(), MethodPermission::User))
    .collect();
    ServicePolicy {
        methods,
        allowed_system_prefixes: Vec::new(),
    }
}

fn create_call<P: Encode>(
    signer: &Ed25519KeyPair,
    chain_id: ChainId,
    nonce: u64,
    method: &str,
    params: &P,
) -> Result<ChainTransaction> {
    let public_key = signer.public_key().to_bytes();
    let account_id = AccountId(account_id_from_key_material(
        SignatureSuite::ED25519,
        &public_key,
    )?);
    let mut transaction = SystemTransaction {
        header: SignHeader {
            account_id,
            nonce,
            chain_id,
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "wallet_network".to_string(),
            method: method.to_string(),
            params: codec::to_bytes_canonical(params).map_err(|error| anyhow!(error))?,
        },
        signature_proof: SignatureProof::default(),
    };
    let signing_bytes = transaction
        .to_sign_bytes()
        .map_err(|error| anyhow!(error))?;
    transaction.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature: signer
            .private_key()
            .sign(&signing_bytes)
            .map_err(|error| anyhow!(error.to_string()))?
            .to_bytes(),
    };
    Ok(ChainTransaction::System(Box::new(transaction)))
}

async fn submit<P: Encode>(
    rpc_addr: &str,
    signer: &Ed25519KeyPair,
    chain_id: ChainId,
    nonce: u64,
    method: &str,
    params: &P,
) -> Result<()> {
    submit_profiled(rpc_addr, signer, chain_id, nonce, method, params)
        .await
        .map(|_| ())
}

/// The single submission path every fixture command uses, additionally
/// returning what it observed about its own timing.
///
/// `submit` delegates here rather than duplicating the call, so a profiled run
/// and an unprofiled run submit through byte-identical code.
async fn submit_profiled<P: Encode>(
    rpc_addr: &str,
    signer: &Ed25519KeyPair,
    chain_id: ChainId,
    nonce: u64,
    method: &str,
    params: &P,
) -> Result<SubmissionProfile> {
    let transaction = create_call(signer, chain_id, nonce, method, params)?;
    submit_transaction_profiled(rpc_addr, &transaction)
        .await
        .with_context(|| format!("wallet.network {method} nonce {nonce}"))
}

/// Is the estate's existing AFT benchmark trace seam enabled?
///
/// This is the SAME gate `crates/execution` and `crates/validator` read. The
/// approval observation below is a consumer of that seam, never a second one.
fn benchmark_trace_enabled() -> bool {
    std::env::var_os("IOI_AFT_BENCH_TRACE").is_some()
}

/// Whether this fixture must seed height zero near the host clock.
///
/// Standing-authority journeys need it for RFC3339 freshness. Ordering-parity
/// benchmarks need it so the shared timestamp due-time gate actually paces
/// both engines instead of letting an immediate engine fast-forward from 1970.
fn requires_initial_tip_timestamp(wall_clock_fixture: bool, benchmark_trace: bool) -> bool {
    wall_clock_fixture || benchmark_trace
}

/// The ordering/finality profile this fixture run exercises.
///
/// M04.9 compares the peer-bearing AFT control against the immediate
/// single-authority Solo engine across the SAME admission,
/// execution, IAVL commitment, Redb durability, restart and status/receipt
/// path. The topology is profile-required rather than hidden: AFT runs the
/// minimum honest `n=4, f=1, q=3` membership its certificate claims, while
/// Solo runs its one authority. All other scenario inputs stay identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrderingProfile {
    /// Four-peer Classic-BFT AFT. The default, and the control.
    Aft,
    /// Single-authority immediate ordering.
    Solo,
}

impl OrderingProfile {
    /// The exact `consensus_type` string handed to the cluster builder.
    ///
    /// This is the one place the profile becomes configuration. The builder
    /// serializes it into `orchestration.toml` and `workload.toml`, so a
    /// restart re-reads the profile it was started with instead of silently
    /// adopting a different one.
    fn consensus_type(self) -> &'static str {
        match self {
            OrderingProfile::Aft => "Aft",
            OrderingProfile::Solo => "Solo",
        }
    }

    /// Exact runnable topology required by this profile's honest guarantees.
    fn validator_count(self) -> usize {
        match self {
            OrderingProfile::Aft => 4,
            OrderingProfile::Solo => 1,
        }
    }
}

/// Parses the bounded experiment selector.
///
/// Exactly two values are accepted, and anything else is an error rather than
/// a silent fallback to the default: a comparison whose profile was chosen by
/// a typo would attribute one engine's measurements to the other, which is
/// worse than not running.
fn parse_ordering_profile(raw: Option<&str>) -> Result<OrderingProfile> {
    match raw.map(str::trim) {
        None | Some("") => Ok(OrderingProfile::Aft),
        Some("Aft") => Ok(OrderingProfile::Aft),
        Some("Solo") => Ok(OrderingProfile::Solo),
        Some(other) => Err(anyhow!(
            "IOI_M049_ORDERING_PROFILE must be exactly \"Aft\" or \"Solo\" \
             (unset defaults to \"Aft\"); got {other:?}"
        )),
    }
}

/// The profile selected for this run, defaulting to the AFT control.
fn ordering_profile() -> Result<OrderingProfile> {
    let raw = std::env::var("IOI_M049_ORDERING_PROFILE").ok();
    parse_ordering_profile(raw.as_deref())
}

/// The spelling every unmeasured field on the observation line uses.
///
/// Distinct from `0` on purpose: a parser reading `0` cannot tell "this cost
/// nothing" from "this was never measured", and the whole point of the
/// commit-path artifact is that those two are never confused.
const OBSERVATION_UNAVAILABLE: &str = "unavailable";

/// Renders one `[BENCH-APPROVAL]` field as a value or as `unavailable`.
fn observation_field(value: Option<impl ToString>) -> String {
    value
        .map(|inner| inner.to_string())
        .unwrap_or_else(|| OBSERVATION_UNAVAILABLE.to_string())
}

/// Emit one approval-correlated commit-path observation.
///
/// The line is written to stdout, which the JS fixture tees to
/// `IOI_WALLET_FIXTURE_TEE_LOG`. It reports only what was measured: an absent
/// committed height is reported as `unavailable`, never as a tip reading or a
/// zero. Nothing here is read back into the fixture's own control flow, so the
/// approval's grant, receipt, and response truth are untouched.
///
/// The `event_*` fields carry the EXACT per-transaction completion event. They
/// are `unavailable` only on a run that did not subscribe at all: a run that
/// required an exact event and could not match one fails in
/// `submit_transaction_profiled` and never reaches this line, so `unavailable`
/// here never means "the event was expected and missing".
#[allow(clippy::too_many_arguments)]
fn emit_approval_observation(
    request_hash: &[u8; 32],
    policy_hash: &[u8; 32],
    principal_ref: &str,
    target_scope: &str,
    submission: &SubmissionProfile,
    approval_query_ms: u128,
    approval_verify_ms: u128,
) {
    let event = submission.completion_event.as_ref();
    println!(
        "[BENCH-APPROVAL] request_hash={} policy_hash={} principal_ref={} target_scope={} tx_hash={} admission_ms={} committed_height={} commit_wait_ms={} commit_poll_count={} commit_poll_interval_ms={} approval_query_ms={} approval_verify_ms={} event_wait_ms={} event_committed_height={} event_durable_commit_ms={} event_published_at_ms={} event_observed_at_ms={}",
        hex::encode(request_hash),
        hex::encode(policy_hash),
        principal_ref,
        target_scope,
        submission.tx_hash,
        submission.admission_ms,
        observation_field(submission.committed_height),
        submission.commit_wait_ms,
        submission.commit_poll_count,
        submission.commit_poll_interval_ms,
        approval_query_ms,
        approval_verify_ms,
        observation_field(event.map(|observed| observed.event_wait_ms)),
        observation_field(event.map(|observed| observed.height)),
        observation_field(event.map(|observed| observed.durable_commit_ms)),
        observation_field(event.map(|observed| observed.published_at_ms)),
        observation_field(event.map(|observed| observed.observed_at_wall_ms)),
    );
}

fn approval_authority(seed: &[u8; 32]) -> Result<ApprovalAuthority> {
    approval_authority_with_scopes(
        seed,
        vec![
            "room_participation.*".to_string(),
            "work_frontier.*".to_string(),
            "work_claim.*".to_string(),
            "resource_offer.*".to_string(),
            "capability_offer.*".to_string(),
            "work_eligibility.*".to_string(),
            "attempt.*".to_string(),
            "finding.*".to_string(),
            "verifier_challenge.*".to_string(),
            "scope:hypervisor.live-route.*".to_string(),
            SYSTEM_GENESIS_SCOPE.to_string(),
            SYSTEM_SEQUENCE_ZERO_SCOPE.to_string(),
            SYSTEM_INITIALIZE_SCOPE.to_string(),
            SYSTEM_ACTIVATE_SCOPE.to_string(),
            SYSTEM_AMENDMENT_SCOPE.to_string(),
            SYSTEM_AMENDMENT_APPROVAL_SCOPE.to_string(),
            GOAL_RUN_CREATE_SCOPE.to_string(),
        ]
        .into_iter()
        .chain(
            PROTECTED_TRANSITION_OPS
                .iter()
                .map(|op| format!("scope:autonomous_system.lifecycle.{op}")),
        )
        .chain(
            NAMED_CONTINUITY_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned()),
        )
        .collect(),
    )
}

fn approval_authority_with_scopes(
    seed: &[u8; 32],
    scope_allowlist: Vec<String>,
) -> Result<ApprovalAuthority> {
    let signer = keypair(seed)?;
    let public_key = signer.public_key().to_bytes();
    Ok(ApprovalAuthority {
        schema_version: 1,
        authority_id: account_id_from_key_material(SignatureSuite::ED25519, &public_key)?,
        public_key,
        signature_suite: SignatureSuite::ED25519,
        expires_at: EXPIRES_AT_MS,
        revoked: false,
        scope_allowlist,
    })
}

fn signed_binding(
    root: &Ed25519KeyPair,
    root_record: &WalletControlPlaneRootRecord,
    principal_ref: &str,
    authority: &ApprovalAuthority,
) -> Result<PrincipalAuthorityBindingProofV1> {
    let statement = PrincipalAuthorityBindingStatementV1 {
        schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
        principal_ref: principal_ref.to_string(),
        authority_kind: PrincipalAuthorityKind::Approval,
        binding_version: 1,
        status: PrincipalAuthorityBindingStatus::Active,
        authority_id: authority.authority_id,
        authority_public_key: authority.public_key.clone(),
        authority_signature_suite: authority.signature_suite,
        approval_authority_snapshot_hash: authority.artifact_hash()?,
        previous_binding_ref: None,
        previous_binding_hash: None,
        // TestCluster's deterministic genesis clock can precede host wall time. Version 1 is
        // intentionally ancient-but-active; expiry and local proof verification still use the
        // real future bound below.
        signed_at_ms: 1,
        expires_at_ms: Some(EXPIRES_AT_MS),
        issuer_root_account_id: root_record.account_id,
        reason: Some("Hypervisor held-bar principal binding".to_string()),
    };
    let message = statement.signing_bytes()?;
    PrincipalAuthorityBindingProofV1::new(
        statement,
        SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: root_record.public_key.clone(),
            signature: root
                .private_key()
                .sign(&message)
                .map_err(|error| anyhow!(error.to_string()))?
                .to_bytes(),
        },
    )
    .map_err(|error| anyhow!(error.to_string()))
}

fn exact_hash32(value: &str, field: &str) -> Result<[u8; 32]> {
    let raw = value.trim().strip_prefix("sha256:").unwrap_or(value.trim());
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!("{field} must be exact 32-byte hex"));
    }
    let decoded = hex::decode(raw).with_context(|| format!("{field} must be hex"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn command_id_is_safe(command_id: &str) -> bool {
    command_id.len() == 36
        && command_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

fn authority_for_principal(principal_ref: &str) -> Result<ApprovalAuthority> {
    match principal_ref {
        "domain://acme-host" | "org://acme/research" => approval_authority(&HOST_SEED),
        "worker://independent-alloy-lab" => approval_authority(&PARTICIPANT_SEED),
        "worker://replication-lab-two" => approval_authority(&PARTICIPANT_TWO_SEED),
        "worker://replication-lab-three" => approval_authority(&PARTICIPANT_THREE_SEED),
        "worker://frontier-only-lab" => approval_authority_with_scopes(
            &SCOPE_LIMITED_PARTICIPANT_SEED,
            vec!["work_frontier.*".to_string()],
        ),
        "org://acme/successor-authority" => approval_authority(&SUCCESSOR_AUTHORITY_SEED),
        _ => Err(anyhow!(
            "wallet.network fixture has no approval authority for {principal_ref}"
        )),
    }
}

fn decode_state_value<T: Decode>(bytes: &[u8], label: &str) -> Result<T> {
    if let Ok(value) = codec::from_bytes_canonical::<T>(bytes) {
        return Ok(value);
    }
    let entry: StateEntry = codec::from_bytes_canonical(bytes)
        .map_err(|error| anyhow!("{label} state wrapper is malformed: {error}"))?;
    codec::from_bytes_canonical(&entry.value)
        .map_err(|error| anyhow!("{label} state value is malformed: {error}"))
}

async fn account_nonce(rpc_addr: &str, account_id: &[u8; 32]) -> Result<u64> {
    let key = [ACCOUNT_NONCE_PREFIX, account_id.as_slice()].concat();
    match query_state_key(rpc_addr, &key).await? {
        Some(bytes) => decode_state_value(&bytes, "capability nonce"),
        None => Ok(0),
    }
}

async fn wallet_control_root(rpc_addr: &str) -> Result<Option<WalletControlPlaneRootRecord>> {
    let key = [
        service_namespace_prefix("wallet_network").as_slice(),
        b"control_root",
    ]
    .concat();
    query_state_key(rpc_addr, &key)
        .await?
        .map(|bytes| decode_state_value(&bytes, "wallet control root"))
        .transpose()
}

fn wallet_approval_key(request_hash: &[u8; 32]) -> Vec<u8> {
    [
        service_namespace_prefix("wallet_network").as_slice(),
        b"approval::",
        request_hash.as_slice(),
    ]
    .concat()
}

fn wallet_effect_receipt_key(consumption_id: &[u8; 32]) -> Vec<u8> {
    [
        service_namespace_prefix("wallet_network").as_slice(),
        b"approval_effect_consumption_receipt::",
        consumption_id.as_slice(),
    ]
    .concat()
}

fn wallet_standing_grant_key(grant_hash: &[u8; 32]) -> Vec<u8> {
    [
        service_namespace_prefix("wallet_network").as_slice(),
        b"standing_approval_grant_state::",
        grant_hash.as_slice(),
    ]
    .concat()
}

fn signed_lifecycle_grant(
    signer: &Ed25519KeyPair,
    authority: &ApprovalAuthority,
    request_hash: [u8; 32],
    policy_hash: [u8; 32],
    audience: [u8; 32],
    nonce: [u8; 32],
    counter: u64,
) -> Result<ApprovalGrant> {
    let mut grant = ApprovalGrant {
        schema_version: 1,
        authority_id: authority.authority_id,
        request_hash,
        policy_hash,
        audience,
        nonce,
        counter,
        expires_at: EXPIRES_AT_MS,
        max_usages: Some(1),
        window_id: None,
        pii_action: None,
        scoped_exception: None,
        review_request_hash: None,
        approver_public_key: authority.public_key.clone(),
        approver_sig: Vec::new(),
        approver_suite: authority.signature_suite,
    };
    grant.approver_sig = signer
        .private_key()
        .sign(&grant.signing_bytes()?)
        .map_err(|error| anyhow!(error.to_string()))?
        .to_bytes()
        .to_vec();
    grant.verify()?;
    Ok(grant)
}

fn principal_authority_head_key(principal_ref: &str) -> Vec<u8> {
    let digest = Sha256::digest(principal_ref.as_bytes()).expect("principal-ref hash");
    let mut principal_hash = [0u8; 32];
    principal_hash.copy_from_slice(digest.as_ref());
    [
        service_namespace_prefix("wallet_network").as_slice(),
        b"principal_authority_binding_head::",
        principal_hash.as_slice(),
    ]
    .concat()
}

fn principal_authority_proof_key(binding_hash: &[u8; 32]) -> Vec<u8> {
    [
        service_namespace_prefix("wallet_network").as_slice(),
        b"principal_authority_binding::",
        binding_hash.as_slice(),
    ]
    .concat()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn fixture_root_seed() -> Result<[u8; 32]> {
    match std::env::var("IOI_HYPERVISOR_WALLET_FIXTURE_ROOT_SEED_HEX") {
        Ok(value) => exact_hash32(&value, "IOI_HYPERVISOR_WALLET_FIXTURE_ROOT_SEED_HEX"),
        Err(std::env::VarError::NotPresent) => Ok(ROOT_SEED),
        Err(error) => Err(anyhow!(error)),
    }
}

fn write_atomic_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("atomic fixture publication requires a parent directory"))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("atomic fixture publication requires a UTF-8 filename"))?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        now_ms()
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn process_start_time_ticks(pid: i32) -> Result<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .with_context(|| format!("read process identity for process group {pid}"))?;
    let (_, fields) = stat
        .rsplit_once(") ")
        .ok_or_else(|| anyhow!("process stat for {pid} has no command terminator"))?;
    let start_time_ticks = fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| anyhow!("process stat for {pid} has no start-time field"))?;
    if !start_time_ticks.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(anyhow!(
            "process stat for {pid} has a nonnumeric start-time field"
        ));
    }
    Ok(start_time_ticks.to_string())
}

fn publish_verifier_owner_marker(fixture_dir: &Path) -> Result<()> {
    let owner_pid = std::env::var("IOI_HYPERVISOR_WALLET_FIXTURE_OWNER_PID")
        .context("IOI_HYPERVISOR_WALLET_FIXTURE_OWNER_PID is required")?
        .parse::<u32>()
        .context("IOI_HYPERVISOR_WALLET_FIXTURE_OWNER_PID must be a u32")?;
    let owner_start_time_ticks =
        std::env::var("IOI_HYPERVISOR_WALLET_FIXTURE_OWNER_START_TIME_TICKS")
            .context("IOI_HYPERVISOR_WALLET_FIXTURE_OWNER_START_TIME_TICKS is required")?;
    if owner_start_time_ticks.is_empty()
        || !owner_start_time_ticks
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err(anyhow!(
            "IOI_HYPERVISOR_WALLET_FIXTURE_OWNER_START_TIME_TICKS must be numeric"
        ));
    }
    let process_group_id = unsafe { libc::getpgrp() };
    if process_group_id <= 0 {
        return Err(anyhow!("wallet fixture process group id must be positive"));
    }
    let marker = serde_json::json!({
        "schema_version": 2,
        "owner_pid": owner_pid,
        "owner_start_time_ticks": owner_start_time_ticks,
        "owner_kind": "wallet-network-principal-authority-fixture",
        "process_group_id": process_group_id,
        "process_group_start_time_ticks": process_start_time_ticks(process_group_id)?,
    });
    write_atomic_durable(
        &fixture_dir.join(".ioi-verifier-owner.json"),
        &serde_json::to_vec(&marker)?,
    )
}

fn signed_revocation(
    root: &Ed25519KeyPair,
    root_record: &WalletControlPlaneRootRecord,
    previous: &PrincipalAuthorityBindingProofV1,
    signed_at_ms: u64,
) -> Result<PrincipalAuthorityBindingProofV1> {
    let statement = PrincipalAuthorityBindingStatementV1 {
        schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
        principal_ref: previous.statement.principal_ref.clone(),
        authority_kind: previous.statement.authority_kind,
        binding_version: previous.statement.binding_version.saturating_add(1),
        status: PrincipalAuthorityBindingStatus::Revoked,
        authority_id: previous.statement.authority_id,
        authority_public_key: previous.statement.authority_public_key.clone(),
        authority_signature_suite: previous.statement.authority_signature_suite,
        approval_authority_snapshot_hash: previous.statement.approval_authority_snapshot_hash,
        previous_binding_ref: Some(previous.binding_ref.clone()),
        previous_binding_hash: Some(previous.binding_hash),
        signed_at_ms,
        expires_at_ms: previous.statement.expires_at_ms,
        issuer_root_account_id: root_record.account_id,
        reason: Some("Hypervisor verifier terminal revocation".to_string()),
    };
    let message = statement.signing_bytes()?;
    PrincipalAuthorityBindingProofV1::new(
        statement,
        SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: root_record.public_key.clone(),
            signature: root
                .private_key()
                .sign(&message)
                .map_err(|error| anyhow!(error.to_string()))?
                .to_bytes(),
        },
    )
    .map_err(|error| anyhow!(error.to_string()))
}

fn existing_approval_matches(
    approval: &WalletApprovalDecision,
    request_hash: [u8; 32],
    policy_hash: [u8; 32],
    grant: &ApprovalGrant,
    target_scope: &str,
    reason: &str,
) -> bool {
    approval.interception.session_id.is_none()
        && approval.interception.request_hash == request_hash
        && approval.interception.target.canonical_label() == target_scope
        && approval.interception.policy_hash == policy_hash
        && approval.interception.value_usd_micros.is_none()
        && approval.interception.reason == reason
        && approval.interception.intercepted_at_ms.saturating_add(1) == approval.decided_at_ms
        && approval.decision == WalletApprovalDecisionKind::ApprovedByHuman
        && approval.approval_grant.as_ref() == Some(grant)
        && approval.surface == VaultSurface::Desktop
        && approval.decided_at_ms < grant.expires_at
}

async fn submit_record_approval(
    rpc_addr: &str,
    chain_id: ChainId,
    capability: &Ed25519KeyPair,
    capability_account_id: [u8; 32],
    command: FixtureCommand,
) -> Result<[u8; 32]> {
    if command.schema_version != COMMAND_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported fixture command schema {}",
            command.schema_version
        ));
    }
    if command.operation != "record_approval" {
        return Err(anyhow!(
            "unsupported fixture command operation '{}'",
            command.operation
        ));
    }
    if command.principal_ref.is_empty() || command.principal_ref.len() > 256 {
        return Err(anyhow!("principal_ref must contain 1..=256 bytes"));
    }

    let request_hash = exact_hash32(
        command
            .request_hash
            .as_deref()
            .ok_or_else(|| anyhow!("record_approval requires request_hash"))?,
        "request_hash",
    )?;
    let policy_hash = exact_hash32(
        command
            .policy_hash
            .as_deref()
            .ok_or_else(|| anyhow!("record_approval requires policy_hash"))?,
        "policy_hash",
    )?;
    let expected_authority = authority_for_principal(&command.principal_ref)?;
    let target_scope = command
        .target_scope
        .as_deref()
        .unwrap_or(SYSTEM_GENESIS_SCOPE);
    let reason = match target_scope {
        SYSTEM_GENESIS_SCOPE => SYSTEM_GENESIS_APPROVAL_REASON,
        SYSTEM_SEQUENCE_ZERO_SCOPE => SYSTEM_SEQUENCE_ZERO_APPROVAL_REASON,
        SYSTEM_INITIALIZE_SCOPE => SYSTEM_INITIALIZE_APPROVAL_REASON,
        SYSTEM_ACTIVATE_SCOPE => SYSTEM_ACTIVATE_APPROVAL_REASON,
        SYSTEM_AMENDMENT_SCOPE => SYSTEM_AMENDMENT_APPROVAL_REASON,
        SYSTEM_AMENDMENT_APPROVAL_SCOPE => SYSTEM_AMENDMENT_GOVERNANCE_APPROVAL_REASON,
        GOAL_RUN_CREATE_SCOPE => GOAL_RUN_CREATE_APPROVAL_REASON,
        scope if protected_transition_scope(scope) => PROTECTED_TRANSITION_APPROVAL_REASON,
        scope if named_continuity_scope(scope) => NAMED_CONTINUITY_APPROVAL_REASON,
        scope if live_route_scope(scope) => LIVE_ROUTE_APPROVAL_REASON,
        scope if application_governance_scope(scope) => APPLICATION_GOVERNANCE_APPROVAL_REASON,
        _ => return Err(anyhow!(UNKNOWN_GOVERNED_SCOPE_ERROR)),
    };
    let grant = command
        .approval_grant
        .ok_or_else(|| anyhow!("record_approval requires approval_grant"))?;
    if grant.request_hash != request_hash
        || grant.policy_hash != policy_hash
        || grant.authority_id != expected_authority.authority_id
        || grant.approver_public_key != expected_authority.public_key
        || grant.approver_suite != expected_authority.signature_suite
    {
        return Err(anyhow!(
            "approval grant does not match the requested principal/policy/request tuple"
        ));
    }
    if grant.audience != capability_account_id {
        return Err(anyhow!(
            "approval grant audience does not match the fixture capability account"
        ));
    }
    if grant.max_usages != Some(1) {
        return Err(anyhow!(
            "stateful governed-effect fixture grants must have max_usages=1"
        ));
    }

    let approval_key = wallet_approval_key(&request_hash);
    if let Some(existing_bytes) = query_state_key(rpc_addr, &approval_key).await? {
        let existing: WalletApprovalDecision =
            decode_state_value(&existing_bytes, "approval decision")?;
        if existing_approval_matches(
            &existing,
            request_hash,
            policy_hash,
            &grant,
            target_scope,
            reason,
        ) {
            return Ok(request_hash);
        }
        return Err(anyhow!(
            "request_hash already names a different wallet approval decision"
        ));
    }

    let decided_at_ms = now_ms();
    if grant.expires_at <= decided_at_ms {
        return Err(anyhow!("approval grant is already expired"));
    }
    let approval = WalletApprovalDecision {
        interception: WalletInterceptionContext {
            session_id: None,
            request_hash,
            target: ActionTarget::Custom(target_scope.to_string()),
            policy_hash,
            value_usd_micros: None,
            reason: reason.to_string(),
            intercepted_at_ms: decided_at_ms.saturating_sub(1),
        },
        decision: WalletApprovalDecisionKind::ApprovedByHuman,
        approval_grant: Some(grant.clone()),
        surface: VaultSurface::Desktop,
        decided_at_ms,
    };
    let nonce = account_nonce(rpc_addr, &capability_account_id).await?;
    let submission = submit_profiled(
        rpc_addr,
        capability,
        chain_id,
        nonce,
        "record_approval@v1",
        &approval,
    )
    .await;
    let submission = match submission {
        Ok(submission) => submission,
        Err(error) => {
            // Transaction-status polling can time out after the validator has
            // already advanced the account nonce and committed the approval.
            // Recover only from the same complete logical approval at the exact
            // request-key. A byte-identical retry may carry a later server
            // clock, so timestamps are checked by the same invariant used above
            // rather than requiring byte equality. Conflicting records still
            // fail. A recovered approval yields no submission observation: the
            // profile reports that absence rather than a fabricated timing.
            let recovery_started = std::time::Instant::now();
            loop {
                match query_state_key(rpc_addr, &approval_key).await {
                    Ok(Some(persisted_bytes)) => {
                        let persisted: WalletApprovalDecision = match decode_state_value(
                            &persisted_bytes,
                            "approval decision after timeout",
                        ) {
                            Ok(persisted) => persisted,
                            Err(decode_error) => {
                                return Err(error.context(format!(
                                    "record_approval timeout recovery found undecodable state: {decode_error}"
                                )));
                            }
                        };
                        if existing_approval_matches(
                            &persisted,
                            request_hash,
                            policy_hash,
                            &grant,
                            target_scope,
                            reason,
                        ) {
                            return Ok(request_hash);
                        }
                        return Err(error.context(
                            "record_approval timeout recovery found a different approval decision",
                        ));
                    }
                    Ok(None) | Err(_) if recovery_started.elapsed() < Duration::from_secs(10) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    _ => break,
                }
            }
            let observed_nonce = account_nonce(rpc_addr, &capability_account_id)
                .await
                .unwrap_or(u64::MAX);
            let observed_height = get_chain_height(rpc_addr).await.unwrap_or(u64::MAX);
            return Err(error.context(format!(
                "record_approval diagnostic: submitted_nonce={nonce} observed_nonce={observed_nonce} observed_height={observed_height}"
            )));
        }
    };

    // Post-commit exact approval-state resolution: the read that proves this
    // request hash now names this exact decision. Timing it is the only change
    // here; the query, the decode, and the exactness check are unaltered.
    let approval_query_started = std::time::Instant::now();
    let persisted_bytes = query_state_key(rpc_addr, &approval_key)
        .await?
        .ok_or_else(|| anyhow!("committed record_approval emitted no approval decision"))?;
    let approval_query_ms = approval_query_started.elapsed().as_millis();
    let approval_verify_started = std::time::Instant::now();
    let persisted: WalletApprovalDecision =
        decode_state_value(&persisted_bytes, "approval decision")?;
    let approval_matches = existing_approval_matches(
        &persisted,
        request_hash,
        policy_hash,
        &grant,
        target_scope,
        reason,
    );
    let approval_verify_ms = approval_verify_started.elapsed().as_millis();
    if !approval_matches {
        return Err(anyhow!(
            "persisted wallet approval decision differs from the submitted logical approval"
        ));
    }
    if benchmark_trace_enabled() {
        emit_approval_observation(
            &request_hash,
            &policy_hash,
            &command.principal_ref,
            target_scope,
            &submission,
            approval_query_ms,
            approval_verify_ms,
        );
    }
    Ok(request_hash)
}

async fn submit_revoke_principal_authority(
    rpc_addr: &str,
    chain_id: ChainId,
    root: &Ed25519KeyPair,
    root_record: &WalletControlPlaneRootRecord,
    command: FixtureCommand,
) -> Result<String> {
    if command.schema_version != COMMAND_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported fixture command schema {}",
            command.schema_version
        ));
    }
    if command.operation != "revoke_principal_authority" {
        return Err(anyhow!(
            "unsupported fixture command operation '{}'",
            command.operation
        ));
    }
    if command.principal_ref.is_empty() || command.principal_ref.len() > 256 {
        return Err(anyhow!("principal_ref must contain 1..=256 bytes"));
    }
    if command.policy_hash.is_some()
        || command.request_hash.is_some()
        || command.approval_grant.is_some()
    {
        return Err(anyhow!(
            "revoke_principal_authority accepts no approval payload fields"
        ));
    }

    let head_key = principal_authority_head_key(&command.principal_ref);
    let head_bytes = query_state_key(rpc_addr, &head_key)
        .await?
        .ok_or_else(|| anyhow!("principal authority head is absent"))?;
    let head: PrincipalAuthorityBindingHeadV1 =
        decode_state_value(&head_bytes, "principal authority head")?;
    if head.principal_ref != command.principal_ref
        || head.authority_kind != PrincipalAuthorityKind::Approval
        || head.status != PrincipalAuthorityBindingStatus::Active
    {
        return Err(anyhow!(
            "principal authority head is foreign, unsupported, or already terminal"
        ));
    }
    let proof_bytes = query_state_key(
        rpc_addr,
        &principal_authority_proof_key(&head.coordinates.binding_hash),
    )
    .await?
    .ok_or_else(|| anyhow!("principal authority head proof is absent"))?;
    let previous: PrincipalAuthorityBindingProofV1 =
        decode_state_value(&proof_bytes, "principal authority proof")?;
    if previous.coordinates() != head.coordinates
        || previous.statement.principal_ref != command.principal_ref
    {
        return Err(anyhow!(
            "principal authority head and immutable proof disagree"
        ));
    }

    let signed_at_ms = get_chain_timestamp(rpc_addr).await?.saturating_mul(1_000);
    let revoked = signed_revocation(root, root_record, &previous, signed_at_ms)?;
    let nonce = account_nonce(rpc_addr, &root_record.account_id).await?;
    submit(
        rpc_addr,
        root,
        chain_id,
        nonce,
        "revoke_principal_authority_binding@v1",
        &RevokePrincipalAuthorityBindingParams {
            predecessor_binding_ref: previous.binding_ref,
            proof: revoked.clone(),
        },
    )
    .await?;

    let persisted_bytes = query_state_key(rpc_addr, &head_key)
        .await?
        .ok_or_else(|| anyhow!("revocation emitted no principal authority head"))?;
    let persisted: PrincipalAuthorityBindingHeadV1 =
        decode_state_value(&persisted_bytes, "principal authority head")?;
    if persisted.status != PrincipalAuthorityBindingStatus::Revoked
        || persisted.coordinates != revoked.coordinates()
    {
        return Err(anyhow!(
            "persisted principal authority head differs from the signed revocation"
        ));
    }
    Ok(revoked.binding_ref)
}

async fn submit_record_standing_approval_grant(
    rpc_addr: &str,
    chain_id: ChainId,
    root: &Ed25519KeyPair,
    capability_account_id: [u8; 32],
    command: FixtureCommand,
) -> Result<([u8; 32], [u8; 32])> {
    if command.schema_version != COMMAND_SCHEMA_VERSION
        || command.operation != "record_standing_approval_grant"
    {
        return Err(anyhow!("unsupported standing-grant record command"));
    }
    if command.policy_hash.is_some()
        || command.request_hash.is_some()
        || command.approval_grant.is_some()
        || command.target_scope.is_some()
        || command.standing_grant_hash.is_some()
    {
        return Err(anyhow!(
            "standing-grant record cannot carry one-shot or revocation fields"
        ));
    }
    let expected_authority = authority_for_principal(&command.principal_ref)?;
    let grant = command
        .standing_approval_grant
        .ok_or_else(|| anyhow!("standing-grant record requires its signed grant"))?;
    grant.verify().map_err(|error| anyhow!(error.to_string()))?;
    if grant.authority_id != expected_authority.authority_id
        || grant.approver_public_key != expected_authority.public_key
        || grant.approver_suite != expected_authority.signature_suite
    {
        return Err(anyhow!(
            "standing approval grant does not match the requested principal authority"
        ));
    }
    if grant.audience != capability_account_id {
        return Err(anyhow!(
            "standing approval grant audience does not match the fixture capability account"
        ));
    }
    let params = RecordStandingApprovalGrantParams {
        grant: grant.clone(),
        standing_envelope_json: serde_jcs::to_vec(
            &command
                .standing_authority_envelope
                .ok_or_else(|| anyhow!("standing-grant record requires its envelope"))?,
        )?,
        approval_ceremony_context_json: serde_jcs::to_vec(
            &command
                .approval_ceremony_context
                .ok_or_else(|| anyhow!("standing-grant record requires its approval context"))?,
        )?,
        auth_factor_receipt_json: serde_jcs::to_vec(
            &command
                .auth_factor_receipt
                .ok_or_else(|| anyhow!("standing-grant record requires its factor receipt"))?,
        )?,
    };
    let grant_hash = grant
        .artifact_hash()
        .map_err(|error| anyhow!(error.to_string()))?;
    let key = wallet_standing_grant_key(&grant_hash);
    let matches = |stored: &StandingApprovalGrantState| {
        stored.grant_hash == grant_hash
            && stored.grant == grant
            && stored.standing_envelope_json == params.standing_envelope_json
            && stored.approval_ceremony_context_json == params.approval_ceremony_context_json
            && stored.auth_factor_receipt_json == params.auth_factor_receipt_json
    };
    if let Some(bytes) = query_state_key(rpc_addr, &key).await? {
        let stored: StandingApprovalGrantState =
            decode_state_value(&bytes, "standing approval grant state")?;
        if matches(&stored) {
            return Ok((grant_hash, grant.standing_envelope_hash));
        }
        return Err(anyhow!(
            "standing grant hash is already bound to different evidence"
        ));
    }
    let root_account_id =
        account_id_from_key_material(SignatureSuite::ED25519, &root.public_key().to_bytes())?;
    let nonce = account_nonce(rpc_addr, &root_account_id).await?;
    if let Err(error) = submit(
        rpc_addr,
        root,
        chain_id,
        nonce,
        "record_standing_approval_grant@v1",
        &params,
    )
    .await
    {
        if let Some(bytes) = query_state_key(rpc_addr, &key).await? {
            let stored: StandingApprovalGrantState =
                decode_state_value(&bytes, "standing approval grant state after timeout")?;
            if matches(&stored) {
                return Ok((grant_hash, grant.standing_envelope_hash));
            }
        }
        return Err(error);
    }
    let bytes = query_state_key(rpc_addr, &key)
        .await?
        .ok_or_else(|| anyhow!("committed standing grant emitted no state"))?;
    let stored: StandingApprovalGrantState =
        decode_state_value(&bytes, "standing approval grant state")?;
    if !matches(&stored) {
        return Err(anyhow!("persisted standing grant evidence differs"));
    }
    Ok((grant_hash, grant.standing_envelope_hash))
}

async fn submit_revoke_standing_approval_grant(
    rpc_addr: &str,
    chain_id: ChainId,
    root: &Ed25519KeyPair,
    command: FixtureCommand,
) -> Result<[u8; 32]> {
    if command.schema_version != COMMAND_SCHEMA_VERSION
        || command.operation != "revoke_standing_approval_grant"
    {
        return Err(anyhow!("unsupported standing-grant revocation command"));
    }
    if command.policy_hash.is_some()
        || command.request_hash.is_some()
        || command.approval_grant.is_some()
        || command.target_scope.is_some()
        || command.standing_approval_grant.is_some()
        || command.standing_authority_envelope.is_some()
        || command.approval_ceremony_context.is_some()
        || command.auth_factor_receipt.is_some()
    {
        return Err(anyhow!("standing-grant revocation carries foreign fields"));
    }
    let grant_hash = exact_hash32(
        command
            .standing_grant_hash
            .as_deref()
            .ok_or_else(|| anyhow!("standing-grant revocation requires grant hash"))?,
        "standing_grant_hash",
    )?;
    let key = wallet_standing_grant_key(&grant_hash);
    let bytes = query_state_key(rpc_addr, &key)
        .await?
        .ok_or_else(|| anyhow!("standing approval grant is not registered"))?;
    let stored: StandingApprovalGrantState =
        decode_state_value(&bytes, "standing approval grant state")?;
    let expected_authority = authority_for_principal(&command.principal_ref)?;
    if stored.grant.authority_id != expected_authority.authority_id {
        return Err(anyhow!(
            "standing grant revocation principal does not match its signer"
        ));
    }
    if stored.status == StandingApprovalGrantStatus::Revoked {
        return Ok(grant_hash);
    }
    let root_account_id =
        account_id_from_key_material(SignatureSuite::ED25519, &root.public_key().to_bytes())?;
    let nonce = account_nonce(rpc_addr, &root_account_id).await?;
    submit(
        rpc_addr,
        root,
        chain_id,
        nonce,
        "revoke_standing_approval_grant@v1",
        &RevokeStandingApprovalGrantParams { grant_hash },
    )
    .await?;
    let bytes = query_state_key(rpc_addr, &key)
        .await?
        .ok_or_else(|| anyhow!("revoked standing grant state disappeared"))?;
    let stored: StandingApprovalGrantState =
        decode_state_value(&bytes, "revoked standing approval grant state")?;
    if stored.status != StandingApprovalGrantStatus::Revoked {
        return Err(anyhow!(
            "standing approval grant revocation is not terminal"
        ));
    }
    Ok(grant_hash)
}

fn write_command_response(command_dir: &Path, response: &FixtureCommandResponse) -> Result<()> {
    let final_path = command_dir.join("response.json");
    if final_path.exists() {
        return Ok(());
    }
    let temp_path = command_dir.join("response.json.tmp");
    let bytes = serde_json::to_vec(response)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&temp_path, &final_path)?;
    Ok(())
}

async fn process_fixture_commands(
    commands_dir: &Path,
    transaction_lock_path: &Path,
    rpc_addr: &str,
    chain_id: ChainId,
    capability: &Ed25519KeyPair,
    capability_account_id: [u8; 32],
    root: &Ed25519KeyPair,
    root_record: &WalletControlPlaneRootRecord,
) -> Result<()> {
    let mut commands = Vec::new();
    for entry in std::fs::read_dir(commands_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            commands.push(entry);
        }
    }
    commands.sort_by_key(|entry| entry.file_name());
    if commands.len() > MAX_PENDING_COMMANDS {
        return Err(anyhow!(
            "wallet fixture command queue exceeds {MAX_PENDING_COMMANDS} entries"
        ));
    }

    for entry in commands {
        let command_id = entry.file_name().to_string_lossy().to_string();
        if !command_id_is_safe(&command_id) {
            return Err(anyhow!("unsafe wallet fixture command id"));
        }
        let command_dir = entry.path();
        if command_dir.join("response.json").exists() {
            continue;
        }
        let request_path = command_dir.join("request.json");
        let Ok(metadata) = std::fs::metadata(&request_path) else {
            continue;
        };
        let result = if metadata.len() > MAX_COMMAND_BYTES {
            Err(anyhow!(
                "wallet fixture command exceeds {MAX_COMMAND_BYTES} bytes"
            ))
        } else {
            match std::fs::read(&request_path)
                .context("wallet fixture command could not be read")
                .and_then(|bytes| {
                    serde_json::from_slice::<FixtureCommand>(&bytes)
                        .context("wallet fixture command is invalid JSON")
                }) {
                Ok(command) => match command.operation.as_str() {
                    "record_approval" => {
                        // The daemon and fixture command processor transact
                        // from the same capability account. Serialize nonce
                        // query + submission across both processes.
                        let _transaction_lock =
                            acquire_fixture_transaction_lock(transaction_lock_path).await?;
                        submit_record_approval(
                            rpc_addr,
                            chain_id,
                            capability,
                            capability_account_id,
                            command,
                        )
                        .await
                        .map(FixtureCommandResult::Approval)
                    }
                    "revoke_principal_authority" => submit_revoke_principal_authority(
                        rpc_addr,
                        chain_id,
                        root,
                        root_record,
                        command,
                    )
                    .await
                    .map(FixtureCommandResult::Revocation),
                    "record_standing_approval_grant" => {
                        let _transaction_lock =
                            acquire_fixture_transaction_lock(transaction_lock_path).await?;
                        submit_record_standing_approval_grant(
                            rpc_addr,
                            chain_id,
                            root,
                            capability_account_id,
                            command,
                        )
                        .await
                        .map(|(grant_hash, standing_envelope_hash)| {
                            FixtureCommandResult::StandingRecorded {
                                grant_hash,
                                standing_envelope_hash,
                            }
                        })
                    }
                    "revoke_standing_approval_grant" => {
                        let _transaction_lock =
                            acquire_fixture_transaction_lock(transaction_lock_path).await?;
                        submit_revoke_standing_approval_grant(rpc_addr, chain_id, root, command)
                            .await
                            .map(FixtureCommandResult::StandingRevoked)
                    }
                    "read_chain_timestamp" => latest_committed_chain_timestamp_ms(rpc_addr)
                        .await
                        .map(FixtureCommandResult::ChainTimestamp),
                    operation => Err(anyhow!(
                        "unsupported fixture command operation '{operation}'"
                    )),
                },
                Err(error) => Err(error),
            }
        };
        let (
            ok,
            request_hash,
            binding_ref,
            standing_grant_hash,
            standing_envelope_hash,
            standing_grant_status,
            chain_timestamp_ms,
            error,
        ) = match result {
            Ok(FixtureCommandResult::Approval(request_hash)) => (
                true,
                Some(hex::encode(request_hash)),
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            Ok(FixtureCommandResult::Revocation(binding_ref)) => {
                (true, None, Some(binding_ref), None, None, None, None, None)
            }
            Ok(FixtureCommandResult::StandingRecorded {
                grant_hash,
                standing_envelope_hash,
            }) => (
                true,
                None,
                None,
                Some(hex::encode(grant_hash)),
                Some(hex::encode(standing_envelope_hash)),
                Some("active".to_string()),
                None,
                None,
            ),
            Ok(FixtureCommandResult::StandingRevoked(grant_hash)) => (
                true,
                None,
                None,
                Some(hex::encode(grant_hash)),
                None,
                Some("revoked".to_string()),
                None,
                None,
            ),
            Ok(FixtureCommandResult::ChainTimestamp(timestamp_ms)) => {
                (true, None, None, None, None, None, Some(timestamp_ms), None)
            }
            Err(error) => {
                let text = format!("{error:#}");
                (
                    false,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(text.chars().take(2_048).collect::<String>()),
                )
            }
        };
        write_command_response(
            &command_dir,
            &FixtureCommandResponse {
                schema_version: COMMAND_SCHEMA_VERSION,
                command_id,
                ok,
                request_hash,
                binding_ref,
                standing_grant_hash,
                standing_envelope_hash,
                standing_grant_status,
                chain_timestamp_ms,
                error,
            },
        )?;
    }
    Ok(())
}

#[test]
fn fixture_command_contract_is_canonical_and_bounded() {
    assert_eq!(
        exact_hash32(&format!("sha256:{}", "ab".repeat(32)), "request_hash")
            .expect("canonical hash"),
        [0xabu8; 32]
    );
    assert!(exact_hash32("ab", "request_hash").is_err());
    assert!(command_id_is_safe("123e4567-e89b-12d3-a456-426614174000"));
    assert!(!command_id_is_safe("../record-approval"));

    let policy = wallet_policy();
    assert!(policy.methods.contains_key("record_approval@v1"));
    assert!(policy
        .methods
        .contains_key("consume_approval_grant_for_effect@v1"));
    assert!(policy
        .methods
        .contains_key("consume_approval_grant_for_effect@v2"));
    for method in [
        "record_standing_approval_grant@v1",
        "consume_standing_approval_grant_for_effect@v1",
        "settle_standing_approval_grant_consumption@v1",
        "revoke_standing_approval_grant@v1",
    ] {
        assert_eq!(policy.methods.get(method), Some(&MethodPermission::User));
    }
    let host = approval_authority(&HOST_SEED).expect("host authority");
    assert!(host
        .scope_allowlist
        .iter()
        .any(|scope| scope == SYSTEM_GENESIS_SCOPE));
    assert!(host
        .scope_allowlist
        .iter()
        .any(|scope| scope == SYSTEM_SEQUENCE_ZERO_SCOPE));
    assert!(host
        .scope_allowlist
        .iter()
        .any(|scope| scope == SYSTEM_INITIALIZE_SCOPE));
    assert!(host
        .scope_allowlist
        .iter()
        .any(|scope| scope == SYSTEM_ACTIVATE_SCOPE));
    assert!(host
        .scope_allowlist
        .iter()
        .any(|scope| scope == GOAL_RUN_CREATE_SCOPE));

    // The M04.9 ordering/finality selector is bounded to exactly two profiles
    // and defaults to the AFT control.
    assert_eq!(
        parse_ordering_profile(None).expect("unset selector defaults"),
        OrderingProfile::Aft,
        "an unset selector must run the preserved AFT control, not the experiment"
    );
    assert_eq!(
        parse_ordering_profile(Some("")).expect("empty selector defaults"),
        OrderingProfile::Aft
    );
    assert_eq!(
        parse_ordering_profile(Some("Aft")).expect("Aft is accepted"),
        OrderingProfile::Aft
    );
    assert_eq!(
        parse_ordering_profile(Some("Solo")).expect("Solo is accepted"),
        OrderingProfile::Solo
    );
    assert_eq!(OrderingProfile::Aft.consensus_type(), "Aft");
    assert_eq!(OrderingProfile::Solo.consensus_type(), "Solo");
    assert_eq!(OrderingProfile::Aft.validator_count(), 4);
    assert_eq!(OrderingProfile::Solo.validator_count(), 1);
    // Surrounding whitespace is trimmed (env plumbing routinely adds it), but
    // the trimmed value must still be one of the two exact profile names.
    assert_eq!(
        parse_ordering_profile(Some("  Solo  ")).expect("padded Solo is accepted"),
        OrderingProfile::Solo
    );
    // Near-misses must fail closed rather than silently running the control:
    // a run mislabelled as the other profile is worse than no run.
    for rejected in ["aft", "solo", "SOLO", "ProofOfAuthority", "Solo,Aft"] {
        assert!(
            parse_ordering_profile(Some(rejected)).is_err(),
            "selector must reject {rejected:?} instead of defaulting"
        );
    }

    assert!(requires_initial_tip_timestamp(true, false));
    assert!(requires_initial_tip_timestamp(false, true));
    assert!(requires_initial_tip_timestamp(true, true));
    assert!(!requires_initial_tip_timestamp(false, false));

    // The M04.9(a) observation line reports an absent measurement as
    // `unavailable`, never as a zero. `0` is a real value for several of these
    // fields -- a same-millisecond publication genuinely has a zero-length
    // durable-ACK interval -- so conflating the two would let the profiler
    // read "not measured" as "cost nothing", which is the exact failure the
    // artifact's unmeasured-phase rows exist to prevent.
    assert_eq!(observation_field(Some(0u64)), "0");
    assert_eq!(observation_field(Some(41u64)), "41");
    assert_eq!(observation_field(None::<u64>), OBSERVATION_UNAVAILABLE);
    assert_eq!(observation_field(None::<u128>), "unavailable");
}

#[tokio::test]
#[ignore = "isolated real-wallet M1.5a verifier; run explicitly"]
async fn system_activation_real_wallet_verifier() -> Result<()> {
    build_test_artifacts();
    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Aft")
        .with_state_tree("IAVL")
        .with_service_policy("wallet_network", wallet_policy())
        .build()
        .await?;
    let verification: Result<()> = async {
        let rpc_addr = cluster.validators[0].validator().rpc_addr.clone();
        let chain_id = ChainId(1);
        wait_for_height(&rpc_addr, 1, Duration::from_secs(30)).await?;
        let root = keypair(&ROOT_SEED)?;
        let root_public_key = root.public_key().to_bytes();
        let root_record = WalletControlPlaneRootRecord {
            account_id: account_id_from_key_material(SignatureSuite::ED25519, &root_public_key)?,
            signature_suite: SignatureSuite::ED25519,
            public_key: root_public_key,
            registered_at_ms: 0,
            updated_at_ms: 0,
            metadata: BTreeMap::from([(
                "fixture".to_owned(),
                "system-activation-real-wallet-verifier".to_owned(),
            )]),
        };
        submit(
            &rpc_addr,
            &root,
            chain_id,
            0,
            "configure_control_root@v1",
            &WalletConfigureControlRootParams {
                root: root_record.clone(),
            },
        )
        .await?;
        let capability = keypair(&CAPABILITY_SEED)?;
        let capability_public_key = capability.public_key().to_bytes();
        let capability_account_id =
            account_id_from_key_material(SignatureSuite::ED25519, &capability_public_key)?;
        submit(
            &rpc_addr,
            &root,
            chain_id,
            1,
            "register_client@v1",
            &WalletRegisterClientParams {
                client: WalletRegisteredClientRecord {
                    client_id: capability_account_id,
                    label: "M1.5a lifecycle verifier".to_owned(),
                    surface: VaultSurface::Desktop,
                    signature_suite: SignatureSuite::ED25519,
                    public_key: capability_public_key,
                    role: WalletClientRole::Capability,
                    state: WalletClientState::Active,
                    registered_at_ms: 0,
                    updated_at_ms: 0,
                    expires_at_ms: Some(EXPIRES_AT_MS),
                    allowed_provider_families: Vec::new(),
                    metadata: BTreeMap::new(),
                },
            },
        )
        .await?;
        let approver = keypair(&HOST_SEED)?;
        let authority = approval_authority(&HOST_SEED)?;
        submit(
            &rpc_addr,
            &root,
            chain_id,
            2,
            "register_approval_authority@v1",
            &RegisterApprovalAuthorityParams {
                authority: authority.clone(),
            },
        )
        .await?;
        let binding = signed_binding(&root, &root_record, "org://acme/research", &authority)?;
        submit(
            &rpc_addr,
            &root,
            chain_id,
            3,
            "issue_principal_authority_binding@v1",
            &IssuePrincipalAuthorityBindingParams {
                proof: binding.clone(),
            },
        )
        .await?;

        for (index, scope) in [SYSTEM_INITIALIZE_SCOPE, SYSTEM_ACTIVATE_SCOPE]
            .into_iter()
            .enumerate()
        {
            let request_hash = [0x51 + index as u8; 32];
            let policy_hash = [0x61 + index as u8; 32];
            let grant = signed_lifecycle_grant(
                &approver,
                &authority,
                request_hash,
                policy_hash,
                capability_account_id,
                [0x71 + index as u8; 32],
                index as u64 + 1,
            )?;
            submit_record_approval(
                &rpc_addr,
                chain_id,
                &capability,
                capability_account_id,
                FixtureCommand {
                    schema_version: COMMAND_SCHEMA_VERSION,
                    operation: "record_approval".to_owned(),
                    principal_ref: "org://acme/research".to_owned(),
                    policy_hash: Some(format!("sha256:{}", hex::encode(policy_hash))),
                    request_hash: Some(format!("sha256:{}", hex::encode(request_hash))),
                    approval_grant: Some(grant.clone()),
                    target_scope: Some(scope.to_owned()),
                    standing_approval_grant: None,
                    standing_authority_envelope: None,
                    approval_ceremony_context: None,
                    auth_factor_receipt: None,
                    standing_grant_hash: None,
                },
            )
            .await?;
            let expected = ExpectedPrincipalAuthorityBinding {
                principal_ref: "org://acme/research".to_owned(),
                required_scope: scope.to_owned(),
                coordinates: binding.coordinates(),
                approval_authority: authority.clone(),
                approval_authority_snapshot_hash: binding
                    .statement
                    .approval_authority_snapshot_hash,
            };
            let consumption_id = [0x81 + index as u8; 32];
            let params = ConsumeApprovalGrantForEffectV2Params {
                request_hash,
                grant_hash: grant.artifact_hash()?,
                consumption_id,
                expected_principal_authority: expected,
                expected_target_label: scope.to_owned(),
                expected_max_usages: 1,
            };
            let invalid_base = 0xa0u8.saturating_add((index as u8) * 8);
            let mut wrong_target = params.clone();
            wrong_target.consumption_id = [invalid_base; 32];
            wrong_target.expected_target_label = if scope == SYSTEM_INITIALIZE_SCOPE {
                SYSTEM_ACTIVATE_SCOPE.to_owned()
            } else {
                SYSTEM_INITIALIZE_SCOPE.to_owned()
            };
            let mut wrong_max_usage = params.clone();
            wrong_max_usage.consumption_id = [invalid_base + 1; 32];
            wrong_max_usage.expected_max_usages = 2;
            let mut wrong_principal = params.clone();
            wrong_principal.consumption_id = [invalid_base + 2; 32];
            wrong_principal.expected_principal_authority.principal_ref =
                "org://foreign/principal".to_owned();
            let mut wrong_scope = params.clone();
            wrong_scope.consumption_id = [invalid_base + 3; 32];
            wrong_scope.expected_principal_authority.required_scope =
                "scope:autonomous_system.lifecycle.foreign".to_owned();
            for invalid in [wrong_target, wrong_max_usage, wrong_principal, wrong_scope] {
                let invalid_nonce = account_nonce(&rpc_addr, &capability_account_id).await?;
                let _ = submit(
                    &rpc_addr,
                    &capability,
                    chain_id,
                    invalid_nonce,
                    "consume_approval_grant_for_effect@v2",
                    &invalid,
                )
                .await;
                if query_state_key(
                    &rpc_addr,
                    &wallet_effect_receipt_key(&invalid.consumption_id),
                )
                .await?
                .is_some()
                {
                    return Err(anyhow!(
                        "real wallet admitted a wrong target, usage ceiling, principal, or scope"
                    ));
                }
            }
            let nonce = account_nonce(&rpc_addr, &capability_account_id).await?;
            submit(
                &rpc_addr,
                &capability,
                chain_id,
                nonce,
                "consume_approval_grant_for_effect@v2",
                &params,
            )
            .await?;
            let receipt_bytes =
                query_state_key(&rpc_addr, &wallet_effect_receipt_key(&consumption_id))
                    .await?
                    .ok_or_else(|| {
                        anyhow!("real wallet emitted no lifecycle consumption receipt")
                    })?;
            let receipt: ApprovalGrantConsumptionReceipt =
                decode_state_value(&receipt_bytes, "lifecycle consumption receipt")?;
            if receipt.request_hash != request_hash
                || receipt.grant_hash != params.grant_hash
                || receipt.consumption_id != consumption_id
                || receipt.principal_authority != params.expected_principal_authority
                || receipt.target.canonical_label() != scope
                || receipt.usage_ordinal != 1
                || receipt.remaining_usages != 0
            {
                return Err(anyhow!(
                    "real wallet receipt did not bind the exact lifecycle tuple"
                ));
            }
            let replay_nonce = account_nonce(&rpc_addr, &capability_account_id).await?;
            submit(
                &rpc_addr,
                &capability,
                chain_id,
                replay_nonce,
                "consume_approval_grant_for_effect@v2",
                &params,
            )
            .await?;
            let replayed = query_state_key(&rpc_addr, &wallet_effect_receipt_key(&consumption_id))
                .await?
                .ok_or_else(|| anyhow!("idempotent wallet receipt vanished"))?;
            if replayed != receipt_bytes {
                return Err(anyhow!("idempotent wallet replay changed receipt bytes"));
            }

            let unrelated_id = [0x91 + index as u8; 32];
            let mut unrelated = params.clone();
            unrelated.consumption_id = unrelated_id;
            let unrelated_nonce = account_nonce(&rpc_addr, &capability_account_id).await?;
            let _ = submit(
                &rpc_addr,
                &capability,
                chain_id,
                unrelated_nonce,
                "consume_approval_grant_for_effect@v2",
                &unrelated,
            )
            .await;
            if query_state_key(&rpc_addr, &wallet_effect_receipt_key(&unrelated_id))
                .await?
                .is_some()
            {
                return Err(anyhow!(
                    "one-use lifecycle grant admitted an unrelated second consumption"
                ));
            }
        }
        Ok(())
    }
    .await;
    let shutdown = cluster.shutdown().await;
    shutdown?;
    verification
}

#[tokio::test]
#[ignore = "spawned by verify-hypervisor-room-participation-plane.mjs"]
async fn wallet_network_principal_authority_fixture() -> Result<()> {
    let fixture_dir = PathBuf::from(
        std::env::var("IOI_HYPERVISOR_WALLET_FIXTURE_DIR")
            .context("IOI_HYPERVISOR_WALLET_FIXTURE_DIR is required")?,
    );
    std::fs::create_dir_all(&fixture_dir)?;
    publish_verifier_owner_marker(&fixture_dir)?;
    build_test_artifacts();
    // A real daemon WebAuthn ceremony emits RFC3339 wall-clock evidence.  The
    // deterministic test chain intentionally starts at Unix second one, so
    // standing-authority journeys and explicit ordering-parity profiles seed
    // the height-zero parent clock and validator harness's initial tip from
    // one timestamp. This leaves the normal genesis state root untouched;
    // height one durably publishes the seeded clock through the ordinary
    // ChainStatus transition. Other deterministic fixture consumers retain
    // the default.
    let wall_clock_fixture =
        std::env::var("IOI_HYPERVISOR_WALLET_FIXTURE_WALL_CLOCK").as_deref() == Ok("1");
    // A parity profile must also start close enough to the host clock for the
    // shared `expected_timestamp_ms > now_ms` production gate to be binding.
    // Starting at Unix epoch zero lets Solo consume one second of authority
    // time on every scheduler kick until the chain catches the host, while
    // AFT's protocol work happens to pace the same timestamps. That varies a
    // second dimension and can expire otherwise identical leases/challenges.
    // The benchmark trace is an explicit test-only namespace, so pin its
    // initial tip without opting it into the standing-authority fixture's
    // separate conservative 15-second interval below.
    let initial_tip_timestamp_ms =
        requires_initial_tip_timestamp(wall_clock_fixture, benchmark_trace_enabled()).then(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now_ms: u64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("wallet fixture wall clock must follow the Unix epoch")
                .as_millis()
                .try_into()
                .expect("wallet fixture wall clock must fit in u64");
            now_ms.saturating_sub(1_000)
        });
    if let Some(timestamp_ms) = initial_tip_timestamp_ms {
        std::env::set_var(
            "IOI_TESTING_INITIAL_TIP_TIMESTAMP_MS",
            timestamp_ms.to_string(),
        );
    }
    // The ordering/finality profile is the ONLY dimension this selector
    // varies. Admission, execution, IAVL state commitment, Redb durability,
    // restart and the status/receipt surfaces below are the same code on both
    // profiles, which is what makes the two runs comparable at all.
    //
    // BLOCK TIMESTAMPING IS PART OF THAT SAMENESS, and it was not always.
    // Solo used to derive `max(now_secs, parent_secs + 1)` from the wall clock
    // while AFT derived a millisecond timestamp from on-chain
    // BlockTimingParams/BlockTimingRuntime. Under that split the claim above
    // was FALSE: a Solo-vs-AFT delta was co-produced by the ordering profile
    // AND by second-quantized timestamping, with no artifact field separating
    // them. Both engines now call `compute_next_timestamp_ms` over the same
    // on-chain timing state with the same inputs, and both fail closed on
    // missing timing state, so the claim holds.
    //
    // The genesis interval both engines are floored by comes from one place
    // (`IOI_BENCH_BLOCK_INTERVAL_MS`, read by `cluster.rs`), so a
    // cadence-varying run cannot floor one profile differently from the other.
    let ordering_profile = ordering_profile()?;
    let mut cluster_builder = TestCluster::builder()
        .with_validators(ordering_profile.validator_count())
        .with_consensus_type(ordering_profile.consensus_type())
        // The canonical bft_consensus runtime profile is backed by the
        // authenticated classic-BFT certificate contract. GuardianMajority is
        // a different experimental safety mode and must never be presented as
        // peer-BFT evidence. Keep this fixed for both matched profiles (it is
        // inert under Solo) so ordering_profile remains the sole varied
        // dimension.
        .with_aft_safety_mode(AftSafetyMode::ClassicBft)
        .with_state_tree("IAVL")
        .with_service_policy("wallet_network", wallet_policy());
    if wall_clock_fixture {
        // The real IAVL fixture commits a setup census before publishing
        // readiness. Those blocks can take materially longer than the normal
        // one-second test interval, causing deterministic chain time to fall
        // minutes behind WebAuthn wall time. The explicit wall-clock profile
        // therefore paces its blocks at a conservative deterministic interval
        // instead of weakening wallet.network's 30-second freshness rule.
        cluster_builder = cluster_builder.with_genesis_modifier(|builder, _keys| {
            let timing_params = BlockTimingParams {
                base_interval_secs: 15,
                min_interval_secs: 15,
                max_interval_secs: 15,
                target_gas_per_block: 10_000_000,
                base_interval_ms: 15_000,
                min_interval_ms: 15_000,
                max_interval_ms: 15_000,
                ..Default::default()
            };
            let timing_runtime = BlockTimingRuntime {
                effective_interval_secs: 15,
                effective_interval_ms: 15_000,
                ema_gas_used: 0,
            };
            builder.set_block_timing(&timing_params, &timing_runtime);
        });
    }
    let cluster = cluster_builder.build().await?;

    // This fixture normally stays quiet because its parent captures the cargo
    // process as one authority-plane log.  Clock-domain integration failures
    // can occur before the first committed height, though, so expose all three
    // child-node streams behind an explicit diagnostic switch.
    if std::env::var("IOI_WALLET_FIXTURE_LIVE_LOGS").as_deref() == Ok("1") {
        let (mut orchestration, mut workload, guardian) =
            cluster.validators[0].validator().subscribe_logs();
        tokio::spawn(async move {
            while let Ok(line) = orchestration.recv().await {
                println!("[WALLET-FIXTURE][orchestration] {line}");
            }
        });
        tokio::spawn(async move {
            while let Ok(line) = workload.recv().await {
                println!("[WALLET-FIXTURE][workload] {line}");
            }
        });
        if let Some(mut guardian) = guardian {
            tokio::spawn(async move {
                while let Ok(line) = guardian.recv().await {
                    println!("[WALLET-FIXTURE][guardian] {line}");
                }
            });
        }
    }

    let setup: Result<()> = async {
        let node = cluster.validators[0].validator();
        let rpc_addr = node.rpc_addr.clone();
        let chain_id = ChainId(1);
        wait_for_height(&rpc_addr, 1, Duration::from_secs(30)).await?;

        let root_seed = fixture_root_seed()?;
        let root = keypair(&root_seed)?;
        let root_public_key = root.public_key().to_bytes();
        let mut root_record = WalletControlPlaneRootRecord {
            account_id: account_id_from_key_material(SignatureSuite::ED25519, &root_public_key)?,
            signature_suite: SignatureSuite::ED25519,
            public_key: root_public_key,
            registered_at_ms: 0,
            updated_at_ms: 0,
            metadata: BTreeMap::from([(
                "fixture".to_string(),
                "hypervisor-room-participation".to_string(),
            )]),
        };
        // Setup below submits exactly this many root-signed transactions:
        // configure_control_root (1) + register_client (1) +
        // register_approval_authority (host + 5 participants = 6) +
        // issue_principal_authority_binding (2 host principals + 5
        // participants = 7). A resumed chain (stable cluster state dir, see
        // IOI_TESTING_CLUSTER_STATE_DIR) already carries all of them; a
        // partially set-up chain is refused rather than repaired.
        const SETUP_ROOT_TRANSACTIONS: u64 = 15;
        let root_nonce = account_nonce(&rpc_addr, &root_record.account_id).await?;
        let setup_initial_nonce = match wallet_control_root(&rpc_addr).await? {
            None => {
                root_record.metadata.insert(
                    "fixture_setup_initial_nonce".to_string(),
                    root_nonce.to_string(),
                );
                Some(root_nonce)
            }
            Some(existing) => {
                if existing.account_id != root_record.account_id
                    || existing.signature_suite != root_record.signature_suite
                    || existing.public_key != root_record.public_key
                {
                    return Err(anyhow!(
                        "wallet fixture chain resume found a substituted control root"
                    ));
                }
                let initial_nonce = existing
                    .metadata
                    .get("fixture_setup_initial_nonce")
                    .ok_or_else(|| {
                        anyhow!(
                            "wallet fixture chain resume lacks the setup-initial-nonce marker; \
                             refusing to guess whether authority setup was complete"
                        )
                    })?
                    .parse::<u64>()
                    .context("wallet fixture setup-initial-nonce marker is malformed")?;
                let expected = initial_nonce
                    .checked_add(SETUP_ROOT_TRANSACTIONS)
                    .ok_or_else(|| anyhow!("wallet fixture setup nonce overflow"))?;
                if root_nonce != expected {
                    return Err(anyhow!(
                        "wallet fixture chain resume found root nonce {root_nonce}, expected \
                         {expected} from its rooted initial nonce; refusing a partially \
                         initialized authority topology"
                    ));
                }
                root_record = existing;
                None
            }
        };
        if let Some(initial_nonce) = setup_initial_nonce {
            submit(
                &rpc_addr,
                &root,
                chain_id,
                initial_nonce,
                "configure_control_root@v1",
                &WalletConfigureControlRootParams {
                    root: root_record.clone(),
                },
            )
            .await?;
        }

        let capability = keypair(&CAPABILITY_SEED)?;
        let capability_public_key = capability.public_key().to_bytes();
        let capability_account_id =
            account_id_from_key_material(SignatureSuite::ED25519, &capability_public_key)?;
        if let Some(initial_nonce) = setup_initial_nonce {
            submit(
                &rpc_addr,
                &root,
                chain_id,
                initial_nonce + 1,
                "register_client@v1",
                &WalletRegisterClientParams {
                    client: WalletRegisteredClientRecord {
                        client_id: capability_account_id,
                        label: "Hypervisor room participation".to_string(),
                        surface: VaultSurface::Desktop,
                        signature_suite: SignatureSuite::ED25519,
                        public_key: capability_public_key,
                        role: WalletClientRole::Capability,
                        state: WalletClientState::Active,
                        registered_at_ms: 0,
                        updated_at_ms: 0,
                        expires_at_ms: Some(EXPIRES_AT_MS),
                        allowed_provider_families: Vec::new(),
                        metadata: BTreeMap::new(),
                    },
                },
            )
            .await?;

            let host_authority = approval_authority(&HOST_SEED)?;
            let participant_bindings = [
                (
                    "worker://independent-alloy-lab",
                    approval_authority(&PARTICIPANT_SEED)?,
                ),
                (
                    "worker://replication-lab-two",
                    approval_authority(&PARTICIPANT_TWO_SEED)?,
                ),
                (
                    "worker://replication-lab-three",
                    approval_authority(&PARTICIPANT_THREE_SEED)?,
                ),
                (
                    "worker://frontier-only-lab",
                    approval_authority_with_scopes(
                        &SCOPE_LIMITED_PARTICIPANT_SEED,
                        vec!["work_frontier.*".to_string()],
                    )?,
                ),
                (
                    "org://acme/successor-authority",
                    approval_authority(&SUCCESSOR_AUTHORITY_SEED)?,
                ),
            ];
            submit(
                &rpc_addr,
                &root,
                chain_id,
                initial_nonce + 2,
                "register_approval_authority@v1",
                &RegisterApprovalAuthorityParams {
                    authority: host_authority.clone(),
                },
            )
            .await?;
            let mut nonce = initial_nonce + 3;
            for (_, authority) in &participant_bindings {
                submit(
                    &rpc_addr,
                    &root,
                    chain_id,
                    nonce,
                    "register_approval_authority@v1",
                    &RegisterApprovalAuthorityParams {
                        authority: authority.clone(),
                    },
                )
                .await?;
                nonce += 1;
            }
            submit(
                &rpc_addr,
                &root,
                chain_id,
                nonce,
                "issue_principal_authority_binding@v1",
                &IssuePrincipalAuthorityBindingParams {
                    proof: signed_binding(
                        &root,
                        &root_record,
                        "domain://acme-host",
                        &host_authority,
                    )?,
                },
            )
            .await?;
            nonce += 1;
            submit(
                &rpc_addr,
                &root,
                chain_id,
                nonce,
                "issue_principal_authority_binding@v1",
                &IssuePrincipalAuthorityBindingParams {
                    proof: signed_binding(
                        &root,
                        &root_record,
                        "org://acme/research",
                        &host_authority,
                    )?,
                },
            )
            .await?;
            nonce += 1;
            for (principal_ref, authority) in &participant_bindings {
                submit(
                    &rpc_addr,
                    &root,
                    chain_id,
                    nonce,
                    "issue_principal_authority_binding@v1",
                    &IssuePrincipalAuthorityBindingParams {
                        proof: signed_binding(&root, &root_record, principal_ref, authority)?,
                    },
                )
                .await?;
                nonce += 1;
            }
            let post_setup_nonce = account_nonce(&rpc_addr, &root_record.account_id).await?;
            let expected_post_setup_nonce = initial_nonce + SETUP_ROOT_TRANSACTIONS;
            if post_setup_nonce != expected_post_setup_nonce {
                return Err(anyhow!(
                    "wallet fixture setup committed nonce {post_setup_nonce}, expected \
                     {expected_post_setup_nonce}; the resume detector above is stale"
                ));
            }
        } else {
            println!(
                "--- wallet.network fixture resumed a fully set-up chain (root nonce {root_nonce}); skipping authority topology setup ---"
            );
        }

        std::env::set_var("IOI_GUARDIAN_KEY_PASS", "hypervisor-held-bar");
        let capability_key_path = fixture_dir.join("hypervisor-capability.key");
        GuardianContainer::save_encrypted_file(&capability_key_path, &CAPABILITY_SEED)?;
        let root_record_path = fixture_dir.join("wallet-control-root.json");
        write_atomic_durable(&root_record_path, &serde_json::to_vec_pretty(&root_record)?)?;
        let commands_dir = fixture_dir.join("commands");
        // create_dir_all: a checkpoint-restored fixture dir may already carry
        // the (emptied) command directory from its captured life.
        std::fs::create_dir_all(&commands_dir)?;
        let transaction_lock_path = fixture_dir.join("hypervisor-wallet-transactions.lock");
        std::fs::File::open(&fixture_dir)?.sync_all()?;
        // `GetStatus.latest_timestamp` is a legacy compatibility field and can
        // remain at the synthetic parent timestamp in this harness. Bind the
        // fixture manifest to the actual latest committed header—the clock
        // TxContext exposes to wallet.network validity checks.
        let chain_timestamp_ms = latest_committed_chain_timestamp_ms(&rpc_addr).await?;
        let manifest = serde_json::json!({
            "rpc_addr": rpc_addr,
            "chain_id": chain_id.0,
            "chain_timestamp_ms": chain_timestamp_ms,
            "capability_key_path": capability_key_path,
            "capability_account_id": hex::encode(capability_account_id),
            "root_record_path": root_record_path,
            "commands_dir": commands_dir,
            "transaction_lock_path": transaction_lock_path,
            "guardian_key_pass": "hypervisor-held-bar",
        });
        let ready_bytes = if std::env::var("IOI_TEST_WALLET_FIXTURE_MALFORMED_READY")
            .ok()
            .as_deref()
            == Some("1")
        {
            b"{".to_vec()
        } else {
            serde_json::to_vec_pretty(&manifest)?
        };
        write_atomic_durable(&fixture_dir.join("ready.json"), &ready_bytes)?;

        let shutdown = fixture_dir.join("shutdown");
        while !shutdown.exists() {
            process_fixture_commands(
                &commands_dir,
                &transaction_lock_path,
                &rpc_addr,
                chain_id,
                &capability,
                capability_account_id,
                &root,
                &root_record,
            )
            .await?;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    shutdown_result?;
    setup
}
#[cfg(unix)]
struct FixtureTransactionLock(std::fs::File);

#[cfg(unix)]
impl Drop for FixtureTransactionLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor remains owned by this guard.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(unix)]
async fn acquire_fixture_transaction_lock(path: &Path) -> Result<FixtureTransactionLock> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)?;
        loop {
            // SAFETY: `file` owns a live descriptor for the duration of flock.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(FixtureTransactionLock(file));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    })
    .await
    .context("wallet fixture transaction-lock task failed")?
    .context("wallet fixture transaction lock could not be acquired")
}

#[cfg(not(unix))]
async fn acquire_fixture_transaction_lock(_path: &Path) -> Result<()> {
    Ok(())
}
