//! `wallet-network-local-authority` — the deployment-local wallet.network authority node for the
//! Hypervisor bounded alpha (ADR 0052; `bounded-alpha-profile.md` step 2b).
//!
//! The alpha names ONE authority node the operator controls, whose approver key the operator
//! custodies. Until this binary existed the only node anyone could point a daemon at was the
//! cargo test fixture (`crates/cli/tests/hypervisor_wallet_network_fixture.rs`) with its public
//! `07…` approver seed. This binary is the supported replacement for that fixture in a
//! deployment: it runs the SAME wallet.network service on the same single-validator Solo chain
//! (the fixture's qualified profile), but every key is generated on the host and custodied there.
//!
//! It adds no second authority plane. The daemon keeps resolving the principal's approval
//! authority through the wallet.network principal-authority binding, verifying grants against
//! that binding and consuming them on chain exactly as before; this binary only issues the
//! root-signed control-plane records that the fixture used to issue with constant seeds.
//!
//! Commands (all take `--state-dir`, the directory that IS the deployment's authority node):
//!
//! * `serve --principal-ref <ref>` — first run generates the control root, the daemon's
//!   capability client key and the operator's approver key, starts the node with durable chain
//!   state under `<state-dir>/chain-state`, commits `configure_control_root`, `register_client`,
//!   `register_approval_authority` and the version-1 `issue_principal_authority_binding`, then
//!   publishes `ready.json` and serves until `<state-dir>/shutdown` appears or SIGTERM/SIGINT
//!   arrives. A later run RESUMES the same chain and refuses to serve if the durable state names a
//!   different control root or a binding head that does not match the custodied approver key.
//! * `rotate` — generates a NEW approver key, registers it and appends an Active successor
//!   binding (version n+1, previous coordinates exact). The retired seed is kept read-only as
//!   `keys/approver.seed.v<n>`; grants signed with it are refused from the next resolution on.
//! * `revoke [--reason ..]` — appends a Revoked successor that retains the exact prior authority
//!   snapshot. Every later resolution for the principal fails typed-unavailable and the daemon
//!   fails closed before any harness runs.
//! * `status` — prints the custodied authority record and the LIVE binding head from the chain.
//! * `record-approval --grant-file <json> --target-scope <scope>` — the operator's approval act
//!   against the node: records the exact one-use grant the operator signed (the daemon's
//!   capability account as audience) as a `WalletApprovalDecision` on chain, signed by the
//!   daemon's capability key under the daemon's transaction lock, so the daemon's consumption
//!   preflight finds state for the exact grant. Idempotent for the same request hash.
//!
//! Transport: the node's gRPC endpoint is plaintext on loopback. The daemon requires an
//! `https://` endpoint with a pinned CA, which `apps/hypervisor/scripts/wallet-network-authority.mjs`
//! provides as a loopback TLS front and records in `<state-dir>/daemon.env`. The JS launcher is
//! the operator's entry point; this binary is what it runs.
//!
//! Chain clock: by default the chain's deterministic clock starts at Unix second one, exactly as
//! the qualified fixture profile does; grants and bindings are validated against that clock.
//! `--wall-clock` seeds the tip from the host clock instead (15-second blocks, the fixture's
//! wall-clock profile) for deployments that need chain time near wall time.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair};
use ioi_api::state::service_namespace_prefix;
use ioi_cli::testing::{
    build_test_artifacts,
    rpc::{get_block_by_height, get_chain_timestamp, query_state_key, submit_transaction, tip_height_resilient},
    wait_for_height, TestCluster,
};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
use ioi_services::wallet_network::RegisterApprovalAuthorityParams;
use ioi_types::app::action::ApprovalAuthority;
use ioi_types::app::action::ApprovalGrant;
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
use ioi_types::config::ServicePolicy;
use ioi_types::keys::ACCOUNT_NONCE_PREFIX;
use ioi_types::service_configs::MethodPermission;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

const CHAIN_ID: u32 = 1;
/// Approval authorities and bindings issued here expire well after any alpha; rotation is the
/// operator's act, never a silent expiry the daemon would have to explain.
const AUTHORITY_EXPIRES_AT_MS: u64 = 1_850_000_000_000;
/// The scope family the deployment approver may sign: every live-route effect the daemon gates
/// (session execute, materializing runs, workspace-restore apply, provider ops, approval
/// decisions). Nothing outside `scope:hypervisor.live-route.*` is signable by the alpha approver.
const APPROVER_SCOPE_ALLOWLIST: &str = "scope:hypervisor.live-route.*";
const AUTHORITY_RECORD_FILE: &str = "authority.json";
const READY_FILE: &str = "ready.json";
const SHUTDOWN_FILE: &str = "shutdown";
const ROOT_RECORD_FILE: &str = "wallet-control-root.json";
const TRANSACTION_LOCK_FILE: &str = "hypervisor-wallet-transactions.lock";

#[derive(Parser, Debug)]
#[command(
    name = "wallet-network-local-authority",
    about = "Deployment-local wallet.network authority node for the Hypervisor bounded alpha"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Bring up (or resume) the authority node and serve until shutdown.
    Serve {
        /// Directory that IS the authority node: keys, durable chain state, records.
        #[arg(long)]
        state_dir: PathBuf,
        /// Canonical principal ref the deployment daemon is pointed at
        /// (IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF), e.g. domain://alpha-host.
        #[arg(long)]
        principal_ref: String,
        /// Label recorded on the daemon's registered wallet client.
        #[arg(long, default_value = "Hypervisor bounded-alpha daemon")]
        client_label: String,
        /// Seed the chain clock from the host clock (15-second blocks) instead of the
        /// deterministic fixture clock.
        #[arg(long)]
        wall_clock: bool,
    },
    /// Rotate the operator's approver key: new key, new Active binding version.
    Rotate {
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Revoke the principal's approval authority: Revoked successor binding.
    Revoke {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value = "operator revoked the deployment approver")]
        reason: String,
    },
    /// Print the custodied authority record and the live binding head.
    Status {
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Record an operator-signed one-use approval grant on the chain (the approval act).
    RecordApproval {
        #[arg(long)]
        state_dir: PathBuf,
        /// JSON file holding the ApprovalGrant the operator signed (`-` reads stdin).
        #[arg(long)]
        grant_file: String,
        /// The exact governed scope the challenge named (e.g. scope:hypervisor.live-route.session-execute).
        #[arg(long)]
        target_scope: String,
        #[arg(long, default_value = "Hypervisor operator approval of the exact effect")]
        reason: String,
    },
}

/// The custodied description of the deployment's authority. It is a RECORD of what the chain
/// holds, kept beside the keys so an operator can read it without the node up; the chain is the
/// truth the daemon resolves against.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorityRecord {
    schema: String,
    principal_ref: String,
    chain_id: u32,
    control_root_account_id: String,
    capability_account_id: String,
    approver_authority_id: String,
    approver_public_key: String,
    approver_scope_allowlist: Vec<String>,
    binding_ref: String,
    binding_version: u64,
    binding_hash: String,
    binding_status: String,
    updated_at: String,
    history: Vec<AuthorityHistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorityHistoryEntry {
    at: String,
    act: String,
    binding_ref: String,
    binding_version: u64,
    approver_authority_id: String,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReadyManifest {
    schema: String,
    pid: u32,
    rpc_addr: String,
    chain_id: u32,
    chain_timestamp_ms: u64,
    principal_ref: String,
    capability_account_id: String,
    capability_key_path: PathBuf,
    root_record_path: PathBuf,
    transaction_lock_path: PathBuf,
    approver_key_path: PathBuf,
    authority_record_path: PathBuf,
    ordering_profile: String,
    wall_clock: bool,
}

struct Keys {
    root: Ed25519KeyPair,
    capability: Ed25519KeyPair,
    approver: Ed25519KeyPair,
    approver_path: PathBuf,
    capability_key_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { state_dir, principal_ref, client_label, wall_clock } => {
            serve(&state_dir, &principal_ref, &client_label, wall_clock).await
        }
        Command::Rotate { state_dir } => rotate(&state_dir).await,
        Command::Revoke { state_dir, reason } => revoke(&state_dir, &reason).await,
        Command::Status { state_dir } => status(&state_dir).await,
        Command::RecordApproval { state_dir, grant_file, target_scope, reason } => {
            record_approval(&state_dir, &grant_file, &target_scope, &reason).await
        }
    }
}

// ---------------------------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------------------------

async fn serve(state_dir: &Path, principal_ref: &str, client_label: &str, wall_clock: bool) -> Result<()> {
    validate_principal_ref(principal_ref)?;
    std::fs::create_dir_all(state_dir.join("keys"))?;
    std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700))?;
    let _ = std::fs::remove_file(state_dir.join(SHUTDOWN_FILE));
    let _ = std::fs::remove_file(state_dir.join(READY_FILE));
    let guardian_pass = guardian_pass()?;
    let keys = load_or_generate_keys(state_dir, &guardian_pass)?;

    println!("--- wallet-network-local-authority: building node artifacts ---");
    build_test_artifacts();
    if wall_clock {
        // Same seam the fixture's wall-clock profile uses: the height-zero parent clock starts one
        // second behind the host so the first block is already due.
        std::env::set_var("IOI_TESTING_INITIAL_TIP_TIMESTAMP_MS", now_ms().saturating_sub(1_000).to_string());
    }
    let mut builder = TestCluster::builder()
        .with_validators(1)
        .with_chain_id(CHAIN_ID)
        .with_consensus_type("Solo")
        .with_state_tree("IAVL")
        .with_service_policy("wallet_network", wallet_policy())
        .with_state_dir(state_dir.join("chain-state"));
    if wall_clock {
        builder = builder.with_genesis_modifier(|genesis, _keys| {
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
            genesis.set_block_timing(&timing_params, &timing_runtime);
        });
    }
    println!("--- wallet-network-local-authority: starting the Solo single-validator node ---");
    let cluster = builder.build().await?;

    let outcome: Result<()> = async {
        let rpc_addr = cluster.validators[0].validator().rpc_addr.clone();
        wait_for_height(&rpc_addr, 1, Duration::from_secs(60)).await?;
        let chain_id = ChainId(CHAIN_ID);

        let root_public_key = keys.root.public_key().to_bytes();
        let root_account_id = account_id_from_key_material(SignatureSuite::ED25519, &root_public_key)?;
        let capability_public_key = keys.capability.public_key().to_bytes();
        let capability_account_id =
            account_id_from_key_material(SignatureSuite::ED25519, &capability_public_key)?;
        let approver_authority = approval_authority(&keys.approver)?;

        let root_record = match wallet_control_root(&rpc_addr).await? {
            None => {
                println!("--- fresh chain: issuing the deployment's control plane ---");
                let root_record = WalletControlPlaneRootRecord {
                    account_id: root_account_id,
                    signature_suite: SignatureSuite::ED25519,
                    public_key: root_public_key.clone(),
                    registered_at_ms: 0,
                    updated_at_ms: 0,
                    metadata: BTreeMap::from([
                        ("deployment".to_string(), "hypervisor-bounded-alpha".to_string()),
                        ("principal_ref".to_string(), principal_ref.to_string()),
                    ]),
                };
                let mut nonce = account_nonce(&rpc_addr, &root_account_id).await?;
                submit(&rpc_addr, &keys.root, chain_id, nonce, "configure_control_root@v1",
                    &WalletConfigureControlRootParams { root: root_record.clone() }).await?;
                nonce += 1;
                submit(&rpc_addr, &keys.root, chain_id, nonce, "register_client@v1",
                    &WalletRegisterClientParams {
                        client: WalletRegisteredClientRecord {
                            client_id: capability_account_id,
                            label: client_label.to_string(),
                            surface: VaultSurface::Desktop,
                            signature_suite: SignatureSuite::ED25519,
                            public_key: capability_public_key.clone(),
                            role: WalletClientRole::Capability,
                            state: WalletClientState::Active,
                            registered_at_ms: 0,
                            updated_at_ms: 0,
                            expires_at_ms: Some(AUTHORITY_EXPIRES_AT_MS),
                            allowed_provider_families: Vec::new(),
                            metadata: BTreeMap::new(),
                        },
                    }).await?;
                nonce += 1;
                submit(&rpc_addr, &keys.root, chain_id, nonce, "register_approval_authority@v1",
                    &RegisterApprovalAuthorityParams { authority: approver_authority.clone() }).await?;
                nonce += 1;
                let proof = signed_binding(&keys.root, &root_record, principal_ref, &approver_authority, 1, None)?;
                submit(&rpc_addr, &keys.root, chain_id, nonce, "issue_principal_authority_binding@v1",
                    &IssuePrincipalAuthorityBindingParams { proof: proof.clone() }).await?;
                let head = read_head(&rpc_addr, principal_ref).await?
                    .ok_or_else(|| anyhow!("binding v1 committed but no head is readable"))?;
                if head.status != PrincipalAuthorityBindingStatus::Active || head.coordinates != proof.coordinates() {
                    bail!("persisted binding head differs from the issued version-1 proof");
                }
                let mut record = AuthorityRecord {
                    schema: "ioi.hypervisor.local-authority-record.v1".to_string(),
                    principal_ref: principal_ref.to_string(),
                    chain_id: CHAIN_ID,
                    control_root_account_id: hex::encode(root_account_id),
                    capability_account_id: hex::encode(capability_account_id),
                    approver_authority_id: hex::encode(approver_authority.authority_id),
                    approver_public_key: hex::encode(&approver_authority.public_key),
                    approver_scope_allowlist: approver_authority.scope_allowlist.clone(),
                    binding_ref: proof.binding_ref.clone(),
                    binding_version: 1,
                    binding_hash: hex::encode(proof.binding_hash),
                    binding_status: "active".to_string(),
                    updated_at: iso_now(),
                    history: Vec::new(),
                };
                record.history.push(AuthorityHistoryEntry {
                    at: iso_now(),
                    act: "issue".to_string(),
                    binding_ref: proof.binding_ref.clone(),
                    binding_version: 1,
                    approver_authority_id: record.approver_authority_id.clone(),
                    detail: "first bring-up: control root, capability client, approver authority and binding v1".to_string(),
                });
                write_authority_record(state_dir, &record)?;
                root_record
            }
            Some(existing) => {
                println!("--- resumed chain: verifying the durable control plane against the custodied keys ---");
                if existing.account_id != root_account_id || existing.public_key != root_public_key {
                    bail!(
                        "durable chain state names a DIFFERENT control root ({}) than keys/root.seed ({}); refusing to serve a substituted authority",
                        hex::encode(existing.account_id), hex::encode(root_account_id)
                    );
                }
                let head = read_head(&rpc_addr, principal_ref).await?
                    .ok_or_else(|| anyhow!("resumed chain carries no binding head for {principal_ref}; the state dir was brought up for a different principal"))?;
                let record = read_authority_record(state_dir)?;
                if head.coordinates.binding_ref != record.binding_ref {
                    bail!("chain binding head {} differs from the custodied record {}; refusing to serve until the record is reconciled", head.coordinates.binding_ref, record.binding_ref);
                }
                if head.status == PrincipalAuthorityBindingStatus::Active {
                    let proof = read_proof(&rpc_addr, &head.coordinates.binding_hash).await?;
                    if proof.statement.authority_public_key != approver_authority.public_key {
                        bail!("the chain's Active binding names an approver key that is not keys/approver.seed; run `rotate` from the custodied key or restore the key file");
                    }
                } else {
                    println!("NOTE: the principal's binding head is {:?}; the daemon will fail closed until `rotate` re-issues an Active binding", head.status);
                }
                existing
            }
        };

        let root_record_path = state_dir.join(ROOT_RECORD_FILE);
        write_atomic_durable(&root_record_path, &serde_json::to_vec_pretty(&root_record)?)?;
        let transaction_lock_path = state_dir.join(TRANSACTION_LOCK_FILE);
        let manifest = ReadyManifest {
            schema: "ioi.hypervisor.local-authority-ready.v1".to_string(),
            pid: std::process::id(),
            rpc_addr: rpc_addr.clone(),
            chain_id: CHAIN_ID,
            chain_timestamp_ms: latest_committed_chain_timestamp_ms(&rpc_addr).await?,
            principal_ref: principal_ref.to_string(),
            capability_account_id: hex::encode(capability_account_id),
            capability_key_path: keys.capability_key_path.clone(),
            root_record_path,
            transaction_lock_path,
            approver_key_path: keys.approver_path.clone(),
            authority_record_path: state_dir.join(AUTHORITY_RECORD_FILE),
            ordering_profile: "Solo".to_string(),
            wall_clock,
        };
        write_atomic_durable(&state_dir.join(READY_FILE), &serde_json::to_vec_pretty(&manifest)?)?;
        println!("--- wallet-network-local-authority: READY rpc={} principal={} ---", rpc_addr, principal_ref);

        let shutdown = state_dir.join(SHUTDOWN_FILE);
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        loop {
            if shutdown.exists() {
                println!("--- shutdown file observed ---");
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(200)) => {},
                _ = tokio::signal::ctrl_c() => { println!("--- SIGINT ---"); break; }
                _ = sigterm.recv() => { println!("--- SIGTERM ---"); break; }
            }
        }
        Ok(())
    }
    .await;

    let _ = std::fs::remove_file(state_dir.join(READY_FILE));
    let shutdown_result = cluster.shutdown().await;
    outcome?;
    shutdown_result
}

// ---------------------------------------------------------------------------------------------
// rotate / revoke / status (against a serving node)
// ---------------------------------------------------------------------------------------------

async fn rotate(state_dir: &Path) -> Result<()> {
    let ready = read_ready(state_dir)?;
    let mut record = read_authority_record(state_dir)?;
    let root = keypair(&read_seed_hex(&state_dir.join("keys/root.seed"))?)?;
    let root_record: WalletControlPlaneRootRecord =
        serde_json::from_slice(&std::fs::read(&ready.root_record_path)?)?;
    let chain_id = ChainId(ready.chain_id);
    let head = read_head(&ready.rpc_addr, &ready.principal_ref).await?
        .ok_or_else(|| anyhow!("no binding head for {}", ready.principal_ref))?;
    let previous = read_proof(&ready.rpc_addr, &head.coordinates.binding_hash).await?;

    // The new key is written FIRST as approver.seed.next; the custodied current key only moves
    // once the chain has committed the successor, so a crash between the two leaves a resumable
    // state (next present, chain unchanged) rather than a key the chain does not know.
    let next_path = state_dir.join("keys/approver.seed.next");
    let next_seed = match read_seed_hex(&next_path) {
        Ok(seed) => seed,
        Err(_) => {
            let seed = random_seed();
            write_secret_hex(&next_path, &seed)?;
            seed
        }
    };
    let next = keypair(&next_seed)?;
    let authority = approval_authority(&next)?;
    let mut nonce = account_nonce(&ready.rpc_addr, &root_record.account_id).await?;
    submit(&ready.rpc_addr, &root, chain_id, nonce, "register_approval_authority@v1",
        &RegisterApprovalAuthorityParams { authority: authority.clone() }).await?;
    nonce += 1;
    let proof = signed_binding(&root, &root_record, &ready.principal_ref, &authority,
        previous.statement.binding_version + 1, Some(&previous))?;
    submit(&ready.rpc_addr, &root, chain_id, nonce, "issue_principal_authority_binding@v1",
        &IssuePrincipalAuthorityBindingParams { proof: proof.clone() }).await?;
    let new_head = read_head(&ready.rpc_addr, &ready.principal_ref).await?
        .ok_or_else(|| anyhow!("rotation committed but no head is readable"))?;
    if new_head.status != PrincipalAuthorityBindingStatus::Active || new_head.coordinates != proof.coordinates() {
        bail!("persisted binding head differs from the signed rotation");
    }
    // Retire the old key (read-only, versioned) and promote the new one.
    let current_path = state_dir.join("keys/approver.seed");
    let retired_path = state_dir.join(format!("keys/approver.seed.v{}", previous.statement.binding_version));
    std::fs::rename(&current_path, &retired_path)?;
    std::fs::set_permissions(&retired_path, std::fs::Permissions::from_mode(0o400))?;
    std::fs::rename(&next_path, &current_path)?;
    record.approver_authority_id = hex::encode(authority.authority_id);
    record.approver_public_key = hex::encode(&authority.public_key);
    record.approver_scope_allowlist = authority.scope_allowlist.clone();
    record.binding_ref = proof.binding_ref.clone();
    record.binding_version = proof.statement.binding_version;
    record.binding_hash = hex::encode(proof.binding_hash);
    record.binding_status = "active".to_string();
    record.updated_at = iso_now();
    record.history.push(AuthorityHistoryEntry {
        at: iso_now(),
        act: "rotate".to_string(),
        binding_ref: proof.binding_ref.clone(),
        binding_version: proof.statement.binding_version,
        approver_authority_id: record.approver_authority_id.clone(),
        detail: format!("previous {} retired to {}", previous.binding_ref, retired_path.display()),
    });
    write_authority_record(state_dir, &record)?;
    println!("rotated: {} v{} authority {}", proof.binding_ref, proof.statement.binding_version, record.approver_authority_id);
    Ok(())
}

async fn revoke(state_dir: &Path, reason: &str) -> Result<()> {
    let ready = read_ready(state_dir)?;
    let mut record = read_authority_record(state_dir)?;
    let root = keypair(&read_seed_hex(&state_dir.join("keys/root.seed"))?)?;
    let root_record: WalletControlPlaneRootRecord =
        serde_json::from_slice(&std::fs::read(&ready.root_record_path)?)?;
    let chain_id = ChainId(ready.chain_id);
    let head = read_head(&ready.rpc_addr, &ready.principal_ref).await?
        .ok_or_else(|| anyhow!("no binding head for {}", ready.principal_ref))?;
    if head.status != PrincipalAuthorityBindingStatus::Active {
        bail!("binding head is already {:?}; nothing to revoke", head.status);
    }
    let previous = read_proof(&ready.rpc_addr, &head.coordinates.binding_hash).await?;
    let signed_at_ms = get_chain_timestamp(&ready.rpc_addr).await?.saturating_mul(1_000);
    let revoked = signed_revocation(&root, &root_record, &previous, signed_at_ms, reason)?;
    let nonce = account_nonce(&ready.rpc_addr, &root_record.account_id).await?;
    submit(&ready.rpc_addr, &root, chain_id, nonce, "revoke_principal_authority_binding@v1",
        &RevokePrincipalAuthorityBindingParams {
            predecessor_binding_ref: previous.binding_ref.clone(),
            proof: revoked.clone(),
        }).await?;
    let new_head = read_head(&ready.rpc_addr, &ready.principal_ref).await?
        .ok_or_else(|| anyhow!("revocation committed but no head is readable"))?;
    if new_head.status != PrincipalAuthorityBindingStatus::Revoked || new_head.coordinates != revoked.coordinates() {
        bail!("persisted binding head differs from the signed revocation");
    }
    record.binding_ref = revoked.binding_ref.clone();
    record.binding_version = revoked.statement.binding_version;
    record.binding_hash = hex::encode(revoked.binding_hash);
    record.binding_status = "revoked".to_string();
    record.updated_at = iso_now();
    record.history.push(AuthorityHistoryEntry {
        at: iso_now(),
        act: "revoke".to_string(),
        binding_ref: revoked.binding_ref.clone(),
        binding_version: revoked.statement.binding_version,
        approver_authority_id: record.approver_authority_id.clone(),
        detail: reason.to_string(),
    });
    write_authority_record(state_dir, &record)?;
    println!("revoked: {} v{}", revoked.binding_ref, revoked.statement.binding_version);
    Ok(())
}

async fn status(state_dir: &Path) -> Result<()> {
    let record = read_authority_record(state_dir)?;
    let mut out = serde_json::json!({ "custodied": record });
    match read_ready(state_dir) {
        Ok(ready) => {
            let head = read_head(&ready.rpc_addr, &ready.principal_ref).await?;
            out["node"] = serde_json::json!({ "ready": true, "rpc_addr": ready.rpc_addr, "pid": ready.pid });
            out["live_head"] = match head {
                Some(head) => serde_json::json!({
                    "binding_ref": head.coordinates.binding_ref,
                    "binding_version": head.coordinates.binding_version,
                    "status": format!("{:?}", head.status).to_ascii_lowercase(),
                }),
                None => serde_json::Value::Null,
            };
        }
        Err(error) => {
            out["node"] = serde_json::json!({ "ready": false, "reason": error.to_string() });
        }
    }
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// record-approval (the operator's approval act against the node)
// ---------------------------------------------------------------------------------------------

fn wallet_approval_key(request_hash: &[u8; 32]) -> Vec<u8> {
    [
        service_namespace_prefix("wallet_network").as_slice(),
        b"approval::",
        request_hash.as_slice(),
    ]
    .concat()
}

fn approval_matches(
    approval: &WalletApprovalDecision,
    grant: &ApprovalGrant,
    target_scope: &str,
    reason: &str,
) -> bool {
    approval.interception.session_id.is_none()
        && approval.interception.request_hash == grant.request_hash
        && approval.interception.target.canonical_label() == target_scope
        && approval.interception.policy_hash == grant.policy_hash
        && approval.interception.reason == reason
        && approval.decision == WalletApprovalDecisionKind::ApprovedByHuman
        && approval.approval_grant.as_ref() == Some(grant)
        && approval.surface == VaultSurface::Desktop
}

/// The daemon serializes its wallet transactions on this lock file; the approval act transacts
/// from the SAME capability account, so it must hold the same lock across nonce query + submit.
struct TransactionLock(std::fs::File);
impl Drop for TransactionLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: the descriptor stays owned by this guard.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN); }
    }
}
fn acquire_transaction_lock(path: &Path) -> Result<TransactionLock> {
    use std::os::fd::AsRawFd;
    let file = OpenOptions::new().create(true).read(true).write(true).open(path)?;
    loop {
        // SAFETY: `file` owns a live descriptor for the duration of flock.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(TransactionLock(file));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

async fn record_approval(state_dir: &Path, grant_file: &str, target_scope: &str, reason: &str) -> Result<()> {
    let ready = read_ready(state_dir)?;
    let record = read_authority_record(state_dir)?;
    if record.binding_status != "active" {
        bail!("the principal's binding is {}; nothing can be approved", record.binding_status);
    }
    let guardian_pass = guardian_pass()?;
    let sealed = std::fs::read(&ready.capability_key_path)?;
    let capability_seed = ioi_crypto::key_store::decrypt_key(&sealed, &guardian_pass)
        .map_err(|error| anyhow!("open capability key: {error}"))?;
    let capability_seed: [u8; 32] = capability_seed.0.as_slice().try_into().map_err(|_| anyhow!("capability key is not a 32-byte seed"))?;
    let capability = keypair(&capability_seed)?;
    let capability_account_id = account_id_from_key_material(SignatureSuite::ED25519, &capability.public_key().to_bytes())?;
    let grant_json = if grant_file == "-" {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
        text
    } else {
        std::fs::read_to_string(grant_file)?
    };
    let grant: ApprovalGrant = serde_json::from_str(&grant_json).context("approval grant JSON")?;
    if hex::encode(grant.authority_id) != record.approver_authority_id || hex::encode(&grant.approver_public_key) != record.approver_public_key {
        bail!("the grant is not signed by the custodied approver ({}); refusing to record a foreign approval", record.approver_authority_id);
    }
    if grant.audience != capability_account_id {
        bail!("the grant's audience is not this deployment's capability account {}", hex::encode(capability_account_id));
    }
    if grant.max_usages != Some(1) {
        bail!("a session-execute approval must be a one-use grant (max_usages=1)");
    }
    if !target_scope.starts_with("scope:hypervisor.live-route.") {
        bail!("target scope {target_scope} is outside the deployment approver's allowlist ({APPROVER_SCOPE_ALLOWLIST})");
    }
    let _lock = acquire_transaction_lock(&ready.transaction_lock_path)?;
    let approval_key = wallet_approval_key(&grant.request_hash);
    if let Some(existing_bytes) = query_state_key(&ready.rpc_addr, &approval_key).await? {
        let existing: WalletApprovalDecision = decode_state_value(&existing_bytes, "approval decision")?;
        if approval_matches(&existing, &grant, target_scope, reason) {
            println!("{}", serde_json::json!({ "ok": true, "request_hash": hex::encode(grant.request_hash), "recorded": "existing" }));
            return Ok(());
        }
        bail!("request_hash already names a different wallet approval decision");
    }
    let decided_at_ms = now_ms();
    if grant.expires_at <= decided_at_ms {
        bail!("approval grant is already expired");
    }
    let approval = WalletApprovalDecision {
        interception: WalletInterceptionContext {
            session_id: None,
            request_hash: grant.request_hash,
            target: ActionTarget::Custom(target_scope.to_string()),
            policy_hash: grant.policy_hash,
            value_usd_micros: None,
            reason: reason.to_string(),
            intercepted_at_ms: decided_at_ms.saturating_sub(1),
        },
        decision: WalletApprovalDecisionKind::ApprovedByHuman,
        approval_grant: Some(grant.clone()),
        surface: VaultSurface::Desktop,
        decided_at_ms,
    };
    let nonce = account_nonce(&ready.rpc_addr, &capability_account_id).await?;
    submit(&ready.rpc_addr, &capability, ChainId(ready.chain_id), nonce, "record_approval@v1", &approval).await?;
    let persisted = query_state_key(&ready.rpc_addr, &approval_key).await?
        .ok_or_else(|| anyhow!("record_approval committed but no approval state is readable"))?;
    let persisted: WalletApprovalDecision = decode_state_value(&persisted, "approval decision")?;
    if !approval_matches(&persisted, &grant, target_scope, reason) {
        bail!("persisted approval decision differs from the one submitted");
    }
    println!("{}", serde_json::json!({ "ok": true, "request_hash": hex::encode(grant.request_hash), "recorded": "committed", "nonce": nonce }));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------------------------

fn guardian_pass() -> Result<String> {
    let pass = std::env::var("IOI_GUARDIAN_KEY_PASS")
        .context("IOI_GUARDIAN_KEY_PASS is required: it seals the daemon's wallet capability key and the daemon needs the same value to open it")?;
    if pass.trim().is_empty() {
        bail!("IOI_GUARDIAN_KEY_PASS cannot be empty");
    }
    Ok(pass)
}

fn load_or_generate_keys(state_dir: &Path, guardian_pass: &str) -> Result<Keys> {
    let keys_dir = state_dir.join("keys");
    std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o700))?;
    let root_path = keys_dir.join("root.seed");
    let approver_path = keys_dir.join("approver.seed");
    let capability_key_path = keys_dir.join("capability.key");
    let fresh = !root_path.exists();
    if fresh {
        if approver_path.exists() || capability_key_path.exists() {
            bail!("keys/ is partially populated (no root.seed but other keys exist); refusing to guess which deployment this is");
        }
        println!("--- generating the deployment's control root, capability client and approver keys ---");
        write_secret_hex(&root_path, &random_seed())?;
        write_secret_hex(&approver_path, &random_seed())?;
        let capability_seed = random_seed();
        let sealed = ioi_crypto::key_store::encrypt_key(&capability_seed, guardian_pass)
            .map_err(|error| anyhow!("seal capability key: {error}"))?;
        write_secret_bytes(&capability_key_path, &sealed)?;
    }
    let root = keypair(&read_seed_hex(&root_path)?)?;
    let approver = keypair(&read_seed_hex(&approver_path)?)?;
    let sealed = std::fs::read(&capability_key_path)?;
    let capability_seed = ioi_crypto::key_store::decrypt_key(&sealed, guardian_pass)
        .map_err(|error| anyhow!("open capability key with IOI_GUARDIAN_KEY_PASS: {error}"))?;
    let capability_seed: [u8; 32] = capability_seed.0.as_slice().try_into()
        .map_err(|_| anyhow!("capability key is not a 32-byte seed"))?;
    let capability = keypair(&capability_seed)?;
    Ok(Keys { root, capability, approver, approver_path, capability_key_path })
}

fn random_seed() -> [u8; 32] {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

fn write_secret_hex(path: &Path, seed: &[u8; 32]) -> Result<()> {
    write_secret_bytes(path, format!("{}\n", hex::encode(seed)).as_bytes())
}

fn write_secret_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_seed_hex(path: &Path) -> Result<[u8; 32]> {
    let metadata = std::fs::metadata(path).with_context(|| format!("read {}", path.display()))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("{} is readable by group/other (mode {:o}); refusing a shared key", path.display(), metadata.permissions().mode() & 0o777);
    }
    let text = std::fs::read_to_string(path)?;
    let bytes = hex::decode(text.trim()).with_context(|| format!("{} is not hex", path.display()))?;
    bytes.as_slice().try_into().map_err(|_| anyhow!("{} is not a 32-byte seed", path.display()))
}

fn keypair(seed: &[u8; 32]) -> Result<Ed25519KeyPair> {
    let private = Ed25519PrivateKey::from_bytes(seed).map_err(|error| anyhow!(error.to_string()))?;
    Ed25519KeyPair::from_private_key(&private).map_err(|error| anyhow!(error.to_string()))
}

// ---------------------------------------------------------------------------------------------
// control-plane records (the same shapes the qualified fixture issues)
// ---------------------------------------------------------------------------------------------

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
    ServicePolicy { methods, allowed_system_prefixes: Vec::new() }
}

fn approval_authority(signer: &Ed25519KeyPair) -> Result<ApprovalAuthority> {
    let public_key = signer.public_key().to_bytes();
    Ok(ApprovalAuthority {
        schema_version: 1,
        authority_id: account_id_from_key_material(SignatureSuite::ED25519, &public_key)?,
        public_key,
        signature_suite: SignatureSuite::ED25519,
        expires_at: AUTHORITY_EXPIRES_AT_MS,
        revoked: false,
        scope_allowlist: vec![APPROVER_SCOPE_ALLOWLIST.to_string()],
    })
}

fn signed_binding(
    root: &Ed25519KeyPair,
    root_record: &WalletControlPlaneRootRecord,
    principal_ref: &str,
    authority: &ApprovalAuthority,
    binding_version: u64,
    previous: Option<&PrincipalAuthorityBindingProofV1>,
) -> Result<PrincipalAuthorityBindingProofV1> {
    let statement = PrincipalAuthorityBindingStatementV1 {
        schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
        principal_ref: principal_ref.to_string(),
        authority_kind: PrincipalAuthorityKind::Approval,
        binding_version,
        status: PrincipalAuthorityBindingStatus::Active,
        authority_id: authority.authority_id,
        authority_public_key: authority.public_key.clone(),
        authority_signature_suite: authority.signature_suite,
        approval_authority_snapshot_hash: authority.artifact_hash()?,
        previous_binding_ref: previous.map(|p| p.binding_ref.clone()),
        previous_binding_hash: previous.map(|p| p.binding_hash),
        // The deterministic chain clock can precede host wall time; a version signed "at 1" is
        // ancient-but-active, and expiry is the real bound.
        signed_at_ms: 1,
        expires_at_ms: Some(AUTHORITY_EXPIRES_AT_MS),
        issuer_root_account_id: root_record.account_id,
        reason: Some(if previous.is_some() {
            "Hypervisor bounded-alpha approver rotation".to_string()
        } else {
            "Hypervisor bounded-alpha deployment approver".to_string()
        }),
    };
    sign_statement(root, root_record, statement)
}

fn signed_revocation(
    root: &Ed25519KeyPair,
    root_record: &WalletControlPlaneRootRecord,
    previous: &PrincipalAuthorityBindingProofV1,
    signed_at_ms: u64,
    reason: &str,
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
        reason: Some(reason.to_string()),
    };
    sign_statement(root, root_record, statement)
}

fn sign_statement(
    root: &Ed25519KeyPair,
    root_record: &WalletControlPlaneRootRecord,
    statement: PrincipalAuthorityBindingStatementV1,
) -> Result<PrincipalAuthorityBindingProofV1> {
    let message = statement.signing_bytes()?;
    PrincipalAuthorityBindingProofV1::new(
        statement,
        SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: root_record.public_key.clone(),
            signature: root.private_key().sign(&message).map_err(|error| anyhow!(error.to_string()))?.to_bytes(),
        },
    )
    .map_err(|error| anyhow!(error.to_string()))
}

fn create_call<P: Encode>(
    signer: &Ed25519KeyPair,
    chain_id: ChainId,
    nonce: u64,
    method: &str,
    params: &P,
) -> Result<ChainTransaction> {
    let public_key = signer.public_key().to_bytes();
    let account_id = AccountId(account_id_from_key_material(SignatureSuite::ED25519, &public_key)?);
    let mut transaction = SystemTransaction {
        header: SignHeader { account_id, nonce, chain_id, tx_version: 1, session_auth: None },
        payload: SystemPayload::CallService {
            service_id: "wallet_network".to_string(),
            method: method.to_string(),
            params: codec::to_bytes_canonical(params).map_err(|error| anyhow!(error))?,
        },
        signature_proof: SignatureProof::default(),
    };
    let signing_bytes = transaction.to_sign_bytes().map_err(|error| anyhow!(error))?;
    transaction.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature: signer.private_key().sign(&signing_bytes).map_err(|error| anyhow!(error.to_string()))?.to_bytes(),
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

// ---------------------------------------------------------------------------------------------
// chain reads
// ---------------------------------------------------------------------------------------------

fn decode_state_value<T: Decode>(bytes: &[u8], label: &str) -> Result<T> {
    if let Ok(value) = codec::from_bytes_canonical::<T>(bytes) {
        return Ok(value);
    }
    let entry: StateEntry = codec::from_bytes_canonical(bytes)
        .map_err(|error| anyhow!("{label} state wrapper is malformed: {error}"))?;
    codec::from_bytes_canonical(&entry.value).map_err(|error| anyhow!("{label} state value is malformed: {error}"))
}

async fn account_nonce(rpc_addr: &str, account_id: &[u8; 32]) -> Result<u64> {
    let key = [ACCOUNT_NONCE_PREFIX, account_id.as_slice()].concat();
    match query_state_key(rpc_addr, &key).await? {
        Some(bytes) => decode_state_value(&bytes, "account nonce"),
        None => Ok(0),
    }
}

async fn wallet_control_root(rpc_addr: &str) -> Result<Option<WalletControlPlaneRootRecord>> {
    let key = [service_namespace_prefix("wallet_network").as_slice(), b"control_root"].concat();
    query_state_key(rpc_addr, &key)
        .await?
        .map(|bytes| decode_state_value(&bytes, "wallet control root"))
        .transpose()
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

async fn read_head(rpc_addr: &str, principal_ref: &str) -> Result<Option<PrincipalAuthorityBindingHeadV1>> {
    query_state_key(rpc_addr, &principal_authority_head_key(principal_ref))
        .await?
        .map(|bytes| decode_state_value(&bytes, "principal authority head"))
        .transpose()
}

async fn read_proof(rpc_addr: &str, binding_hash: &[u8; 32]) -> Result<PrincipalAuthorityBindingProofV1> {
    let bytes = query_state_key(rpc_addr, &principal_authority_proof_key(binding_hash))
        .await?
        .ok_or_else(|| anyhow!("principal authority proof is absent"))?;
    decode_state_value(&bytes, "principal authority proof")
}

async fn latest_committed_chain_timestamp_ms(rpc_addr: &str) -> Result<u64> {
    let height = tip_height_resilient(rpc_addr).await?;
    let block = get_block_by_height(rpc_addr, height)
        .await?
        .ok_or_else(|| anyhow!("latest committed block {height} is unavailable"))?;
    let timestamp_ms = block.header.timestamp_ms_or_legacy();
    if timestamp_ms == 0 {
        bail!("latest committed block has a zero timestamp");
    }
    Ok(timestamp_ms)
}

// ---------------------------------------------------------------------------------------------
// files
// ---------------------------------------------------------------------------------------------

fn read_ready(state_dir: &Path) -> Result<ReadyManifest> {
    let path = state_dir.join(READY_FILE);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("{} is absent: the authority node is not serving", path.display()))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_authority_record(state_dir: &Path) -> Result<AuthorityRecord> {
    let path = state_dir.join(AUTHORITY_RECORD_FILE);
    Ok(serde_json::from_slice(&std::fs::read(&path).with_context(|| format!("read {}", path.display()))?)?)
}

fn write_authority_record(state_dir: &Path, record: &AuthorityRecord) -> Result<()> {
    write_atomic_durable(&state_dir.join(AUTHORITY_RECORD_FILE), &serde_json::to_vec_pretty(record)?)
}

fn write_atomic_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| anyhow!("atomic publication requires a parent directory"))?;
    let file_name = path.file_name().and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("atomic publication requires a UTF-8 filename"))?;
    let temporary = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), now_ms()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary)?;
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

fn validate_principal_ref(principal_ref: &str) -> Result<()> {
    let valid_scheme = ["worker://", "service://", "org://", "domain://", "agentgres://domain/"]
        .iter()
        .any(|scheme| principal_ref.starts_with(scheme) && principal_ref.len() > scheme.len());
    if !valid_scheme {
        bail!("principal ref {principal_ref:?} is not in the canonical grammar (worker:// service:// org:// domain:// agentgres://domain/)");
    }
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

fn iso_now() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    // RFC 3339 without a chrono dependency: days since epoch → civil date (Howard Hinnant).
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", sod / 3_600, (sod % 3_600) / 60, sod % 60)
}
