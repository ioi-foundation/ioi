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
    rpc::{get_chain_height, get_chain_timestamp, query_state_key},
    submit_transaction, wait_for_height, TestCluster,
};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
use ioi_services::wallet_network::RegisterApprovalAuthorityParams;
use ioi_services::wallet_network::{
    ApprovalGrantConsumptionReceipt, ConsumeApprovalGrantForEffectV2Params,
    ExpectedPrincipalAuthorityBinding,
};
use ioi_types::app::action::{ApprovalAuthority, ApprovalGrant};
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
    account_id_from_key_material, AccountId, ActionTarget, ChainId, ChainTransaction, SignHeader,
    SignatureProof, SignatureSuite, StateEntry, SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use ioi_types::config::ServicePolicy;
use ioi_types::keys::ACCOUNT_NONCE_PREFIX;
use ioi_types::service_configs::MethodPermission;
use ioi_validator::common::GuardianContainer;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

const HOST_SEED: [u8; 32] = [0x07; 32];
const PARTICIPANT_SEED: [u8; 32] = [0x09; 32];
const PARTICIPANT_TWO_SEED: [u8; 32] = [0x0a; 32];
const PARTICIPANT_THREE_SEED: [u8; 32] = [0x0b; 32];
const SCOPE_LIMITED_PARTICIPANT_SEED: [u8; 32] = [0x0c; 32];
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

fn protected_transition_scope(target_scope: &str) -> bool {
    target_scope
        .strip_prefix("scope:autonomous_system.lifecycle.")
        .is_some_and(|op| PROTECTED_TRANSITION_OPS.contains(&op))
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
    error: Option<String>,
}

enum FixtureCommandResult {
    Approval([u8; 32]),
    Revocation(String),
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
    let transaction = create_call(signer, chain_id, nonce, method, params)?;
    submit_transaction(rpc_addr, &transaction)
        .await
        .with_context(|| format!("wallet.network {method} nonce {nonce}"))
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
            SYSTEM_GENESIS_SCOPE.to_string(),
            SYSTEM_SEQUENCE_ZERO_SCOPE.to_string(),
            SYSTEM_INITIALIZE_SCOPE.to_string(),
            SYSTEM_ACTIVATE_SCOPE.to_string(),
            SYSTEM_AMENDMENT_SCOPE.to_string(),
            SYSTEM_AMENDMENT_APPROVAL_SCOPE.to_string(),
        ]
        .into_iter()
        .chain(
            PROTECTED_TRANSITION_OPS
                .iter()
                .map(|op| format!("scope:autonomous_system.lifecycle.{op}")),
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
        scope if protected_transition_scope(scope) => PROTECTED_TRANSITION_APPROVAL_REASON,
        _ => {
            return Err(anyhow!(
                "record_approval target_scope is not one of the fixture's governed System scopes"
            ))
        }
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
            "stateful System-genesis fixture grants must have max_usages=1"
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
        approval_grant: Some(grant),
        surface: VaultSurface::Desktop,
        decided_at_ms,
    };
    let nonce = account_nonce(rpc_addr, &capability_account_id).await?;
    if let Err(error) = submit(
        rpc_addr,
        capability,
        chain_id,
        nonce,
        "record_approval@v1",
        &approval,
    )
    .await
    {
        let observed_nonce = account_nonce(rpc_addr, &capability_account_id)
            .await
            .unwrap_or(u64::MAX);
        let observed_height = get_chain_height(rpc_addr).await.unwrap_or(u64::MAX);
        return Err(error.context(format!(
            "record_approval diagnostic: submitted_nonce={nonce} observed_nonce={observed_nonce} observed_height={observed_height}"
        )));
    }

    let persisted_bytes = query_state_key(rpc_addr, &approval_key)
        .await?
        .ok_or_else(|| anyhow!("committed record_approval emitted no approval decision"))?;
    let persisted: WalletApprovalDecision =
        decode_state_value(&persisted_bytes, "approval decision")?;
    if persisted != approval {
        return Err(anyhow!(
            "persisted wallet approval decision differs from the submitted decision"
        ));
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
                    operation => Err(anyhow!(
                        "unsupported fixture command operation '{operation}'"
                    )),
                },
                Err(error) => Err(error),
            }
        };
        let (ok, request_hash, binding_ref, error) = match result {
            Ok(FixtureCommandResult::Approval(request_hash)) => {
                (true, Some(hex::encode(request_hash)), None, None)
            }
            Ok(FixtureCommandResult::Revocation(binding_ref)) => {
                (true, None, Some(binding_ref), None)
            }
            Err(error) => {
                let text = format!("{error:#}");
                (
                    false,
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
    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Aft")
        .with_state_tree("IAVL")
        .with_service_policy("wallet_network", wallet_policy())
        .build()
        .await?;

    let setup: Result<()> = async {
        let node = cluster.validators[0].validator();
        let rpc_addr = node.rpc_addr.clone();
        let chain_id = ChainId(1);
        wait_for_height(&rpc_addr, 1, Duration::from_secs(30)).await?;

        let root_seed = fixture_root_seed()?;
        let root = keypair(&root_seed)?;
        let root_public_key = root.public_key().to_bytes();
        let root_record = WalletControlPlaneRootRecord {
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
        ];
        submit(
            &rpc_addr,
            &root,
            chain_id,
            2,
            "register_approval_authority@v1",
            &RegisterApprovalAuthorityParams {
                authority: host_authority.clone(),
            },
        )
        .await?;
        let mut nonce = 3;
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
                proof: signed_binding(&root, &root_record, "domain://acme-host", &host_authority)?,
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
                proof: signed_binding(&root, &root_record, "org://acme/research", &host_authority)?,
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

        std::env::set_var("IOI_GUARDIAN_KEY_PASS", "hypervisor-held-bar");
        let capability_key_path = fixture_dir.join("hypervisor-capability.key");
        GuardianContainer::save_encrypted_file(&capability_key_path, &CAPABILITY_SEED)?;
        let root_record_path = fixture_dir.join("wallet-control-root.json");
        write_atomic_durable(&root_record_path, &serde_json::to_vec_pretty(&root_record)?)?;
        let commands_dir = fixture_dir.join("commands");
        std::fs::create_dir(&commands_dir)?;
        let transaction_lock_path = fixture_dir.join("hypervisor-wallet-transactions.lock");
        std::fs::File::open(&fixture_dir)?.sync_all()?;
        let manifest = serde_json::json!({
            "rpc_addr": rpc_addr,
            "chain_id": chain_id.0,
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
