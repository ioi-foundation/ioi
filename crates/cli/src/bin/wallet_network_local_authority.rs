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
//!   The first run needs the operator passphrase once (the new keys are sealed with it and the
//!   root signs the genesis records); a resume needs none and compares PUBLIC keys only.
//! * `approve --policy-hash <h> --request-hash <h> --audience <a> --target-scope <s>` — the ONE
//!   place a grant is minted: unseals the approver key in memory with the operator passphrase,
//!   mints one one-use grant (random nonce, bounded expiry) for exactly those hashes, records it
//!   on chain (the `record-approval` path), prints the grant JSON and zeroizes the seed.
//! * `rotate` — generates a NEW approver key, registers it and appends an Active successor
//!   binding (version n+1, previous coordinates exact). The retired sealed seed is kept read-only
//!   as `keys/approver.seed.sealed.v<n>` and its public half as `keys/approver.pub.v<n>`; grants
//!   signed with it are refused from the next resolution on.
//! * `revoke [--reason ..]` — appends a Revoked successor that retains the exact prior authority
//!   snapshot. Every later resolution for the principal fails typed-unavailable and the daemon
//!   fails closed before any harness runs.
//! * `status` — prints the custodied authority record and the LIVE binding head from the chain.
//! * `record-approval --grant-file <json> --target-scope <scope>` — records an already-signed
//!   one-use grant (the daemon's capability account as audience) as a `WalletApprovalDecision` on
//!   chain, signed by the daemon's capability key under the daemon's transaction lock, so the
//!   daemon's consumption preflight finds state for the exact grant. Idempotent for the same
//!   request hash. `approve` uses the same recorder.
//! * `seal-keys` — converts a plaintext (pre-sealing, or dev/test) state dir: seals every
//!   plaintext seed with the operator passphrase, writes the public halves, then removes the
//!   plaintext files.
//!
//! Key custody (owner decision 2026-09-28). The daemon and every host-spawned process run as the
//! same uid, so a plaintext approver or root seed would let any unsandboxed host path approve its
//! own effects. In deployment mode the control root and the approver key exist on disk ONLY
//! sealed (`keys/root.seed.sealed`, `keys/approver.seed.sealed`, 0600, `ioi_crypto::key_store`)
//! under the OPERATOR passphrase, with their public halves in plaintext (`keys/root.pub`,
//! `keys/approver.pub`). The passphrase comes from `IOI_AUTHORITY_OPERATOR_PASS` (set for the one
//! command that needs it; this binary scrubs it from its own environment block at startup so no
//! child and no `/proc/<pid>/environ` reader sees it) or from a TTY prompt when stdin is a
//! terminal. It is never read from argv, never written, never logged, and must differ from
//! `IOI_GUARDIAN_KEY_PASS` (which seals only the daemon's capability key). After bring-up no
//! process holds the approver or root private key. Plaintext seeds exist only behind the explicit
//! dev/test `--plaintext-keys` opt-in, which the deployment launcher never passes; a plaintext
//! state dir is refused in deployment mode until `seal-keys` converts it.
//!
//! Transport: the node's gRPC endpoint is plaintext on loopback. The daemon requires an
//! `https://` endpoint with a pinned CA, which `apps/hypervisor/scripts/wallet-network-authority.mjs`
//! provides as a loopback TLS front and records in `<state-dir>/daemon.env`. The JS launcher is
//! the operator's entry point; this binary is what it runs.
//!
//! Relocation: `IOI_NODE_BINARY_DIR=<install>/node-bins` makes `serve` launch the packaged
//! orchestration/workload/guardian/ioi-signer binaries with no cargo and no checkout; a missing
//! binary is a typed `node_binaries_absent` refusal, never a build.
//!
//! Chain clock: by default the chain's deterministic clock starts at Unix second one, exactly as
//! the qualified fixture profile does; grants and bindings are validated against that clock.
//! `--wall-clock` seeds the tip from the host clock instead (15-second blocks, the fixture's
//! wall-clock profile) for deployments that need chain time near wall time.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{IsTerminal, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair};
use ioi_api::state::service_namespace_prefix;
use ioi_cli::testing::{
    build_test_artifacts,
    rpc::{
        get_block_by_height, get_chain_timestamp, query_state_key, submit_transaction,
        tip_height_resilient,
    },
    wait_for_height, TestCluster,
};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
use ioi_services::wallet_network::{
    RecordStandingApprovalGrantParams, RegisterApprovalAuthorityParams,
    RevokeStandingApprovalGrantParams,
};
use ioi_types::app::action::ApprovalAuthority;
use ioi_types::app::action::ApprovalGrant;
use ioi_types::app::action::StandingApprovalGrant;
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
use zeroize::{Zeroize, Zeroizing};

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

/// The operator passphrase that seals the control root and the approver key. Set only for the one
/// command that needs it; never argv, never disk, never a log line, never daemon.env/serve.env.
const OPERATOR_PASS_ENV: &str = "IOI_AUTHORITY_OPERATOR_PASS";
const GUARDIAN_PASS_ENV: &str = "IOI_GUARDIAN_KEY_PASS";
const MIN_OPERATOR_PASS_CHARS: usize = 8;
/// A one-use grant minted by `approve` expires after this long unless `--expires-in-secs` says
/// otherwise, and never later than the ceiling: one use AND a short life.
const DEFAULT_APPROVAL_EXPIRES_IN_SECS: u64 = 900;
const MAX_APPROVAL_EXPIRES_IN_SECS: u64 = 3_600;

// keys/ layout. Sealed (deployment) and plaintext (dev/test opt-in) seeds never coexist.
const ROOT_SEED_SEALED: &str = "root.seed.sealed";
const APPROVER_SEED_SEALED: &str = "approver.seed.sealed";
const ROOT_SEED_PLAINTEXT: &str = "root.seed";
const APPROVER_SEED_PLAINTEXT: &str = "approver.seed";
const ROOT_PUBLIC_KEY_FILE: &str = "root.pub";
const APPROVER_PUBLIC_KEY_FILE: &str = "approver.pub";
const CAPABILITY_KEY_FILE: &str = "capability.key";

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
        #[command(flatten)]
        key_mode: KeyModeArgs,
    },
    /// Rotate the operator's approver key: new key, new Active binding version.
    Rotate {
        #[arg(long)]
        state_dir: PathBuf,
        #[command(flatten)]
        key_mode: KeyModeArgs,
    },
    /// Revoke the principal's approval authority: Revoked successor binding.
    Revoke {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value = "operator revoked the deployment approver")]
        reason: String,
        #[command(flatten)]
        key_mode: KeyModeArgs,
    },
    /// The operator's approval act: unseal the approver key with the operator passphrase, mint ONE
    /// one-use grant for exactly these hashes, record it on chain and print it. The one place a
    /// grant is minted.
    Approve {
        #[arg(long)]
        state_dir: PathBuf,
        /// The challenge's policy hash (64 hex characters, optionally `sha256:`-prefixed).
        #[arg(long)]
        policy_hash: String,
        /// The challenge's request hash (64 hex characters, optionally `sha256:`-prefixed).
        #[arg(long)]
        request_hash: String,
        /// The daemon's wallet capability account the challenge names (bare 64 hex characters).
        #[arg(long)]
        audience: String,
        /// The exact governed scope the challenge named (e.g. scope:hypervisor.live-route.session-execute).
        #[arg(long)]
        target_scope: String,
        /// Lifetime of the one-use grant, in seconds (default 900, at most 3600).
        #[arg(long, default_value_t = DEFAULT_APPROVAL_EXPIRES_IN_SECS)]
        expires_in_secs: u64,
        #[arg(
            long,
            default_value = "Hypervisor operator approval of the exact effect"
        )]
        reason: String,
        #[command(flatten)]
        key_mode: KeyModeArgs,
    },
    /// Convert a plaintext state dir: seal every plaintext seed with the operator passphrase,
    /// write the public halves, then remove the plaintext files.
    SealKeys {
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Print the custodied authority record and the live binding head.
    Status {
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Record an operator-signed STANDING approval grant on the chain (R-14: the deployment-local
    /// operator key is a recognized custody tier for a standing envelope, under the same
    /// one-ceremony, receipted, non-widening rules as a passkey step-up).
    RecordStandingApproval {
        #[arg(long)]
        state_dir: PathBuf,
        /// JSON file holding the StandingApprovalGrant the operator signed (`-` reads stdin).
        #[arg(long)]
        grant_file: String,
        /// JSON file holding the registered SessionStandingEnvelope the grant binds.
        #[arg(long)]
        envelope_file: String,
        /// JSON file holding the ApprovalCeremonyContext for this one ceremony.
        #[arg(long)]
        context_file: String,
        /// JSON file holding the v2 AuthFactorReceipt attesting the deployment-local custody tier.
        #[arg(long)]
        factor_file: String,
        #[command(flatten)]
        key_mode: KeyModeArgs,
    },
    /// Print the node's latest COMMITTED chain timestamp as one line of JSON. A standing
    /// envelope's validity window is judged against the chain clock, never the host's assumption.
    ChainTimestamp {
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Revoke a recorded standing approval grant; the next draw refuses within one commit.
    RevokeStandingApproval {
        #[arg(long)]
        state_dir: PathBuf,
        /// The standing grant's hash (64 hex characters).
        #[arg(long)]
        grant_hash: String,
        #[command(flatten)]
        key_mode: KeyModeArgs,
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
        #[arg(
            long,
            default_value = "Hypervisor operator approval of the exact effect"
        )]
        reason: String,
    },
}

/// Which custody the control root and approver seeds are in. Deployment mode is SEALED; the
/// plaintext form exists only behind the explicit dev/test opt-in below.
#[derive(Args, Debug, Clone, Copy, Default)]
struct KeyModeArgs {
    /// DEV/TEST ONLY: keep the control root and approver seeds as plaintext hex files
    /// (keys/root.seed, keys/approver.seed). The deployment launcher never passes this; without
    /// it the seeds are sealed with the operator passphrase and a plaintext state dir is refused.
    #[arg(long)]
    plaintext_keys: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyCustody {
    Sealed,
    Plaintext,
}

impl KeyCustody {
    fn label(self) -> &'static str {
        match self {
            KeyCustody::Sealed => "sealed",
            KeyCustody::Plaintext => "plaintext",
        }
    }
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
    /// The plaintext approver seed — present ONLY for a dev/test `--plaintext-keys` node. A
    /// deployment's approver key is sealed and no manifest names a path a process could sign with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approver_key_path: Option<PathBuf>,
    /// The approver's PUBLIC half (hex), what every startup identity check compares against.
    #[serde(default)]
    approver_public_key_path: PathBuf,
    /// `sealed` (deployment) or `plaintext` (dev/test opt-in).
    #[serde(default)]
    key_custody: String,
    authority_record_path: PathBuf,
    ordering_profile: String,
    wall_clock: bool,
}

/// What `serve` holds after startup: the daemon's capability key (needed to serve) and the PUBLIC
/// halves of the control root and approver. The root private key exists in memory only on a
/// first bring-up, until the genesis records are committed.
struct ServeKeys {
    custody: KeyCustody,
    capability: Ed25519KeyPair,
    capability_key_path: PathBuf,
    root_public_key: Vec<u8>,
    approver_public_key: Vec<u8>,
    approver_public_key_path: PathBuf,
    approver_plaintext_path: Option<PathBuf>,
    genesis_root: Option<Ed25519KeyPair>,
}

fn main() -> Result<()> {
    // FIRST: take the operator passphrase out of this process's environment — before any thread,
    // runtime or child exists — so no spawned node binary inherits it and no reader of
    // /proc/<pid>/environ finds it for the life of a long-running `serve`.
    let pass = OperatorPassSource::capture_and_scrub();
    let cli = Cli::parse();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(cli, pass))
}

async fn run(cli: Cli, pass: OperatorPassSource) -> Result<()> {
    match cli.command {
        Command::Serve {
            state_dir,
            principal_ref,
            client_label,
            wall_clock,
            key_mode,
        } => {
            serve(
                &state_dir,
                &principal_ref,
                &client_label,
                wall_clock,
                key_mode,
                &pass,
            )
            .await
        }
        Command::Rotate {
            state_dir,
            key_mode,
        } => rotate(&state_dir, key_mode, &pass).await,
        Command::Revoke {
            state_dir,
            reason,
            key_mode,
        } => revoke(&state_dir, &reason, key_mode, &pass).await,
        Command::Approve {
            state_dir,
            policy_hash,
            request_hash,
            audience,
            target_scope,
            expires_in_secs,
            reason,
            key_mode,
        } => {
            approve(
                &state_dir,
                &ApproveRequest {
                    policy_hash: &policy_hash,
                    request_hash: &request_hash,
                    audience: &audience,
                    target_scope: &target_scope,
                    expires_in_secs,
                    reason: &reason,
                },
                key_mode,
                &pass,
            )
            .await
        }
        Command::SealKeys { state_dir } => seal_keys(&state_dir, &pass),
        Command::Status { state_dir } => status(&state_dir).await,
        Command::RecordApproval {
            state_dir,
            grant_file,
            target_scope,
            reason,
        } => record_approval(&state_dir, &grant_file, &target_scope, &reason).await,
        Command::RecordStandingApproval {
            state_dir,
            grant_file,
            envelope_file,
            context_file,
            factor_file,
            key_mode,
        } => {
            record_standing_approval(
                &state_dir,
                &grant_file,
                &envelope_file,
                &context_file,
                &factor_file,
                key_mode,
                &pass,
            )
            .await
        }
        Command::RevokeStandingApproval {
            state_dir,
            grant_hash,
            key_mode,
        } => revoke_standing_approval(&state_dir, &grant_hash, key_mode, &pass).await,
        Command::ChainTimestamp { state_dir } => {
            let ready = read_ready(&state_dir)?;
            let chain_timestamp_ms = latest_committed_chain_timestamp_ms(&ready.rpc_addr).await?;
            println!(
                "{}",
                serde_json::json!({ "ok": true, "chain_timestamp_ms": chain_timestamp_ms })
            );
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------------------------

async fn serve(
    state_dir: &Path,
    principal_ref: &str,
    client_label: &str,
    wall_clock: bool,
    key_mode: KeyModeArgs,
    pass: &OperatorPassSource,
) -> Result<()> {
    validate_principal_ref(principal_ref)?;
    std::fs::create_dir_all(state_dir.join("keys"))?;
    std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700))?;
    let _ = std::fs::remove_file(state_dir.join(SHUTDOWN_FILE));
    let _ = std::fs::remove_file(state_dir.join(READY_FILE));
    let guardian_pass = guardian_pass()?;
    let mut keys = load_or_generate_serve_keys(state_dir, &guardian_pass, key_mode, pass)?;

    // A packaged deployment pins the node binaries (IOI_NODE_BINARY_DIR) and has no cargo: the
    // launcher then builds nothing and refuses typed if a binary is absent. Only a checkout
    // builds the (IBC-test-only) artifacts and, on demand, the node profile.
    match ioi_cli::testing::build::pinned_node_binary_dir() {
        Some(dir) => println!(
            "--- wallet-network-local-authority: node binaries pinned to {} (no build) ---",
            dir.display()
        ),
        None => {
            println!("--- wallet-network-local-authority: building node artifacts ---");
            build_test_artifacts();
        }
    }
    if wall_clock {
        // Same seam the fixture's wall-clock profile uses: the height-zero parent clock starts one
        // second behind the host so the first block is already due.
        std::env::set_var(
            "IOI_TESTING_INITIAL_TIP_TIMESTAMP_MS",
            now_ms().saturating_sub(1_000).to_string(),
        );
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

        // Every identity check below uses PUBLIC keys: a resume needs no passphrase and no
        // private key, and after bring-up this process holds neither the root nor the approver.
        let root_public_key = keys.root_public_key.clone();
        let root_account_id = account_id_from_key_material(SignatureSuite::ED25519, &root_public_key)?;
        let capability_public_key = keys.capability.public_key().to_bytes();
        let capability_account_id =
            account_id_from_key_material(SignatureSuite::ED25519, &capability_public_key)?;
        let approver_authority = approval_authority_from_public_key(&keys.approver_public_key)?;
        let genesis_root = keys.genesis_root.take();

        let root_record = match wallet_control_root(&rpc_addr).await? {
            None => {
                // The root signs the genesis records. On a first bring-up it was generated (and
                // sealed) moments ago; if the keys exist but the chain holds no control plane, a
                // first bring-up was interrupted and the root must be unsealed once.
                let root = match genesis_root {
                    Some(root) => root,
                    None => {
                        if keys.custody == KeyCustody::Sealed && !pass.available() {
                            bail!(
                                "the chain holds no control plane yet (the first bring-up did not finish), so the control root must sign the genesis records: set {OPERATOR_PASS_ENV} for this one run (or run on a terminal to be prompted). Later runs resume without it."
                            );
                        }
                        load_root_signer(state_dir, keys.custody, pass, "the control root signs the genesis records")?
                    }
                };
                if root.public_key().to_bytes() != root_public_key {
                    bail!("the unsealed control root is not keys/{ROOT_PUBLIC_KEY_FILE}; refusing to issue a control plane under a key the state dir does not name");
                }
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
                submit(&rpc_addr, &root, chain_id, nonce, "configure_control_root@v1",
                    &WalletConfigureControlRootParams { root: root_record.clone() }).await?;
                nonce += 1;
                submit(&rpc_addr, &root, chain_id, nonce, "register_client@v1",
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
                submit(&rpc_addr, &root, chain_id, nonce, "register_approval_authority@v1",
                    &RegisterApprovalAuthorityParams { authority: approver_authority.clone() }).await?;
                nonce += 1;
                let proof = signed_binding(&root, &root_record, principal_ref, &approver_authority, 1, None)?;
                submit(&rpc_addr, &root, chain_id, nonce, "issue_principal_authority_binding@v1",
                    &IssuePrincipalAuthorityBindingParams { proof: proof.clone() }).await?;
                // Genesis is committed: the root private key leaves memory now, before serving.
                drop(root);
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
                drop(genesis_root);
                println!("--- resumed chain: verifying the durable control plane against the custodied public keys ---");
                if existing.account_id != root_account_id || existing.public_key != root_public_key {
                    bail!(
                        "durable chain state names a DIFFERENT control root ({}) than keys/{ROOT_PUBLIC_KEY_FILE} ({}); refusing to serve a substituted authority",
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
                        bail!("the chain's Active binding names an approver key that is not keys/{APPROVER_PUBLIC_KEY_FILE}; run `rotate` from the custodied key or restore the key files");
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
            approver_key_path: keys.approver_plaintext_path.clone(),
            approver_public_key_path: keys.approver_public_key_path.clone(),
            key_custody: keys.custody.label().to_string(),
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

async fn rotate(state_dir: &Path, key_mode: KeyModeArgs, pass: &OperatorPassSource) -> Result<()> {
    let custody = require_custody(state_dir, key_mode)?;
    let ready = read_ready(state_dir)?;
    let mut record = read_authority_record(state_dir)?;
    // One passphrase entry opens the root AND seals the new approver key under the same custody.
    let operator_pass = match custody {
        KeyCustody::Sealed => Some(pass.obtain(
            state_dir,
            "rotate: the control root signs the successor binding and the new approver key is sealed",
            false,
        )?),
        KeyCustody::Plaintext => None,
    };
    let root = open_root_signer(
        state_dir,
        custody,
        operator_pass.as_deref().map(String::as_str),
    )?;
    let root_record: WalletControlPlaneRootRecord =
        serde_json::from_slice(&std::fs::read(&ready.root_record_path)?)?;
    let chain_id = ChainId(ready.chain_id);
    let head = read_head(&ready.rpc_addr, &ready.principal_ref)
        .await?
        .ok_or_else(|| anyhow!("no binding head for {}", ready.principal_ref))?;
    let previous = read_proof(&ready.rpc_addr, &head.coordinates.binding_hash).await?;

    // The new key is written FIRST as <seed>.next; the custodied current key only moves once the
    // chain has committed the successor, so a crash between the two leaves a resumable state
    // (next present, chain unchanged) rather than a key the chain does not know.
    let keys_dir = state_dir.join("keys");
    let seed_name = match custody {
        KeyCustody::Sealed => APPROVER_SEED_SEALED,
        KeyCustody::Plaintext => APPROVER_SEED_PLAINTEXT,
    };
    let next_path = keys_dir.join(format!("{seed_name}.next"));
    let next_public_path = keys_dir.join(format!("{APPROVER_PUBLIC_KEY_FILE}.next"));
    let next_seed = if next_path.exists() {
        match &operator_pass {
            Some(operator_pass) => open_sealed_seed(&next_path, operator_pass)?,
            None => read_seed_hex(&next_path)?,
        }
    } else {
        let seed = random_seed();
        match &operator_pass {
            Some(operator_pass) => write_sealed_seed(&next_path, &seed, operator_pass)?,
            None => write_secret_hex(&next_path, &seed)?,
        }
        seed
    };
    let next = keypair(&next_seed)?;
    drop(next_seed);
    let next_public_key = next.public_key().to_bytes();
    drop(next);
    write_public_key(&next_public_path, &next_public_key)?;
    let authority = approval_authority_from_public_key(&next_public_key)?;
    let mut nonce = account_nonce(&ready.rpc_addr, &root_record.account_id).await?;
    submit(
        &ready.rpc_addr,
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
    let proof = signed_binding(
        &root,
        &root_record,
        &ready.principal_ref,
        &authority,
        previous.statement.binding_version + 1,
        Some(&previous),
    )?;
    submit(
        &ready.rpc_addr,
        &root,
        chain_id,
        nonce,
        "issue_principal_authority_binding@v1",
        &IssuePrincipalAuthorityBindingParams {
            proof: proof.clone(),
        },
    )
    .await?;
    let new_head = read_head(&ready.rpc_addr, &ready.principal_ref)
        .await?
        .ok_or_else(|| anyhow!("rotation committed but no head is readable"))?;
    if new_head.status != PrincipalAuthorityBindingStatus::Active
        || new_head.coordinates != proof.coordinates()
    {
        bail!("persisted binding head differs from the signed rotation");
    }
    drop(root);
    // Retire the old key (read-only, versioned; its PUBLIC half stays verifiable beside it) and
    // promote the new one.
    let retired_version = previous.statement.binding_version;
    let current_path = keys_dir.join(seed_name);
    let retired_path = keys_dir.join(format!("{seed_name}.v{retired_version}"));
    std::fs::rename(&current_path, &retired_path)?;
    std::fs::set_permissions(&retired_path, std::fs::Permissions::from_mode(0o400))?;
    let current_public_path = keys_dir.join(APPROVER_PUBLIC_KEY_FILE);
    if current_public_path.exists() {
        let retired_public_path =
            keys_dir.join(format!("{APPROVER_PUBLIC_KEY_FILE}.v{retired_version}"));
        std::fs::rename(&current_public_path, &retired_public_path)?;
        std::fs::set_permissions(&retired_public_path, std::fs::Permissions::from_mode(0o400))?;
    }
    std::fs::rename(&next_path, &current_path)?;
    std::fs::rename(&next_public_path, &current_public_path)?;
    std::fs::File::open(&keys_dir)?.sync_all()?;
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
        detail: format!(
            "previous {} retired to {}",
            previous.binding_ref,
            retired_path.display()
        ),
    });
    write_authority_record(state_dir, &record)?;
    println!(
        "rotated: {} v{} authority {}",
        proof.binding_ref, proof.statement.binding_version, record.approver_authority_id
    );
    Ok(())
}

async fn revoke(
    state_dir: &Path,
    reason: &str,
    key_mode: KeyModeArgs,
    pass: &OperatorPassSource,
) -> Result<()> {
    let custody = require_custody(state_dir, key_mode)?;
    let ready = read_ready(state_dir)?;
    let mut record = read_authority_record(state_dir)?;
    let root = load_root_signer(
        state_dir,
        custody,
        pass,
        "revoke: the control root signs the Revoked successor binding",
    )?;
    let root_record: WalletControlPlaneRootRecord =
        serde_json::from_slice(&std::fs::read(&ready.root_record_path)?)?;
    let chain_id = ChainId(ready.chain_id);
    let head = read_head(&ready.rpc_addr, &ready.principal_ref)
        .await?
        .ok_or_else(|| anyhow!("no binding head for {}", ready.principal_ref))?;
    if head.status != PrincipalAuthorityBindingStatus::Active {
        bail!(
            "binding head is already {:?}; nothing to revoke",
            head.status
        );
    }
    let previous = read_proof(&ready.rpc_addr, &head.coordinates.binding_hash).await?;
    let signed_at_ms = get_chain_timestamp(&ready.rpc_addr)
        .await?
        .saturating_mul(1_000);
    let revoked = signed_revocation(&root, &root_record, &previous, signed_at_ms, reason)?;
    let nonce = account_nonce(&ready.rpc_addr, &root_record.account_id).await?;
    submit(
        &ready.rpc_addr,
        &root,
        chain_id,
        nonce,
        "revoke_principal_authority_binding@v1",
        &RevokePrincipalAuthorityBindingParams {
            predecessor_binding_ref: previous.binding_ref.clone(),
            proof: revoked.clone(),
        },
    )
    .await?;
    let new_head = read_head(&ready.rpc_addr, &ready.principal_ref)
        .await?
        .ok_or_else(|| anyhow!("revocation committed but no head is readable"))?;
    if new_head.status != PrincipalAuthorityBindingStatus::Revoked
        || new_head.coordinates != revoked.coordinates()
    {
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
    println!(
        "revoked: {} v{}",
        revoked.binding_ref, revoked.statement.binding_version
    );
    Ok(())
}

async fn status(state_dir: &Path) -> Result<()> {
    let record = read_authority_record(state_dir)?;
    let keys_dir = state_dir.join("keys");
    let custody = match detect_custody(&keys_dir) {
        Ok(Some(custody)) => custody.label().to_string(),
        Ok(None) => "absent".to_string(),
        Err(error) => format!("inconsistent: {error}"),
    };
    let mut out = serde_json::json!({
        "custodied": record,
        "key_custody": custody,
        "root_public_key": read_public_key(&keys_dir.join(ROOT_PUBLIC_KEY_FILE)).ok().map(hex::encode),
        "approver_public_key": read_public_key(&keys_dir.join(APPROVER_PUBLIC_KEY_FILE)).ok().map(hex::encode),
    });
    match read_ready(state_dir) {
        Ok(ready) => {
            let head = read_head(&ready.rpc_addr, &ready.principal_ref).await?;
            out["node"] =
                serde_json::json!({ "ready": true, "rpc_addr": ready.rpc_addr, "pid": ready.pid });
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
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
fn acquire_transaction_lock(path: &Path) -> Result<TransactionLock> {
    use std::os::fd::AsRawFd;
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(path)?;
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

fn read_json_arg(path: &str, label: &str) -> Result<String> {
    if path == "-" {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
        Ok(text)
    } else {
        std::fs::read_to_string(path).with_context(|| format!("read {label} from {path}"))
    }
}

/// R-14: record a STANDING approval grant signed by the deployment's custodied approver. The
/// deployment-local operator key is a recognized custody tier, so the ceremony evidence this
/// submits carries the v2 auth-factor receipt; the wallet re-validates the whole tuple (envelope
/// containment, one-ceremony consumption, tier/posture match) and this binary asserts only what a
/// deployment can: the grant is the custodied approver's, its audience is this deployment's
/// capability account, and it does not widen the envelope it names.
async fn record_standing_approval(
    state_dir: &Path,
    grant_file: &str,
    envelope_file: &str,
    context_file: &str,
    factor_file: &str,
    key_mode: KeyModeArgs,
    pass: &OperatorPassSource,
) -> Result<()> {
    let custody = require_custody(state_dir, key_mode)?;
    let ready = read_ready(state_dir)?;
    let record = read_authority_record(state_dir)?;
    if record.binding_status != "active" {
        bail!(
            "the principal's binding is {}; nothing can be approved",
            record.binding_status
        );
    }
    let guardian_pass = guardian_pass()?;
    let sealed = std::fs::read(&ready.capability_key_path)?;
    let capability_seed = ioi_crypto::key_store::decrypt_key(&sealed, &guardian_pass)
        .map_err(|error| anyhow!("open capability key: {error}"))?;
    let capability_seed: [u8; 32] = capability_seed
        .0
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("capability key is not a 32-byte seed"))?;
    let capability = keypair(&capability_seed)?;
    let capability_account_id =
        account_id_from_key_material(SignatureSuite::ED25519, &capability.public_key().to_bytes())?;
    // RECORDING a standing grant is a CONTROL-PLANE act (client_auth gates the method to
    // WalletAuthRole::ControlPlane, exactly as it gates authority registration and revocation):
    // it creates standing authority rather than spending it, so the deployment's control root
    // signs it. The CAPABILITY account remains the grant's audience — the signer that will later
    // consume each draw — and is checked below.
    let root = load_root_signer(
        state_dir,
        custody,
        pass,
        "record-standing-approval: the control root records the standing grant",
    )?;
    let root_account_id =
        account_id_from_key_material(SignatureSuite::ED25519, &root.public_key().to_bytes())?;

    let grant: StandingApprovalGrant =
        serde_json::from_str(&read_json_arg(grant_file, "standing approval grant")?)
            .context("standing approval grant JSON")?;
    grant
        .verify()
        .map_err(|error| anyhow!("standing approval grant is structurally invalid: {error}"))?;
    if hex::encode(grant.authority_id) != record.approver_authority_id
        || hex::encode(&grant.approver_public_key) != record.approver_public_key
    {
        bail!("the standing grant is not signed by the custodied approver ({}); refusing to record a foreign approval", record.approver_authority_id);
    }
    if grant.audience != capability_account_id {
        bail!(
            "the standing grant's audience is not this deployment's capability account {}",
            hex::encode(capability_account_id)
        );
    }
    let envelope_json = read_json_arg(envelope_file, "standing envelope")?;
    let context_json = read_json_arg(context_file, "approval ceremony context")?;
    let factor_json = read_json_arg(factor_file, "auth factor receipt")?;
    let envelope: serde_json::Value =
        serde_json::from_str(&envelope_json).context("standing envelope JSON")?;
    let factor: serde_json::Value =
        serde_json::from_str(&factor_json).context("auth factor receipt JSON")?;
    if factor
        .get("factor_kind")
        .and_then(serde_json::Value::as_str)
        != Some("deployment_local_operator")
    {
        bail!("this recorder records the deployment-local operator custody tier only; the factor receipt names another tier");
    }
    if envelope
        .get("body_hash")
        .and_then(serde_json::Value::as_str)
        != Some(format!("sha256:{}", hex::encode(grant.standing_envelope_hash)).as_str())
    {
        bail!("the standing grant does not bind the envelope submitted with it");
    }
    let params = RecordStandingApprovalGrantParams {
        grant: grant.clone(),
        standing_envelope_json: serde_jcs::to_vec(&envelope)?,
        approval_ceremony_context_json: serde_jcs::to_vec(
            &serde_json::from_str::<serde_json::Value>(&context_json)
                .context("approval ceremony context JSON")?,
        )?,
        auth_factor_receipt_json: serde_jcs::to_vec(&factor)?,
    };
    let grant_hash = grant
        .artifact_hash()
        .map_err(|error| anyhow!("standing grant hash: {error}"))?;
    let _lock = acquire_transaction_lock(&ready.transaction_lock_path)?;
    let nonce = account_nonce(&ready.rpc_addr, &root_account_id).await?;
    submit(
        &ready.rpc_addr,
        &root,
        ChainId(ready.chain_id),
        nonce,
        "record_standing_approval_grant@v1",
        &params,
    )
    .await?;
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "standing_grant_hash": hex::encode(grant_hash),
            "standing_envelope_hash": hex::encode(grant.standing_envelope_hash),
            "custody_tier": "deployment_local_operator",
            "recorded": "committed",
            "nonce": nonce,
        })
    );
    Ok(())
}

async fn revoke_standing_approval(
    state_dir: &Path,
    grant_hash: &str,
    key_mode: KeyModeArgs,
    pass: &OperatorPassSource,
) -> Result<()> {
    let custody = require_custody(state_dir, key_mode)?;
    let ready = read_ready(state_dir)?;
    // Revoking a recorded standing grant is a CONTROL-PLANE act (client_auth gates it to the
    // control-plane role), so it is signed by the deployment's control root, which the operator
    // custodies sealed under the operator passphrase.
    let root = load_root_signer(
        state_dir,
        custody,
        pass,
        "revoke-standing-approval: the control root revokes the standing grant",
    )?;
    let root_account_id =
        account_id_from_key_material(SignatureSuite::ED25519, &root.public_key().to_bytes())?;
    let decoded = hex::decode(grant_hash.trim()).context("standing grant hash is not hex")?;
    let grant_hash_bytes: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("standing grant hash must be 32 bytes"))?;
    let _lock = acquire_transaction_lock(&ready.transaction_lock_path)?;
    let nonce = account_nonce(&ready.rpc_addr, &root_account_id).await?;
    submit(
        &ready.rpc_addr,
        &root,
        ChainId(ready.chain_id),
        nonce,
        "revoke_standing_approval_grant@v1",
        &RevokeStandingApprovalGrantParams {
            grant_hash: grant_hash_bytes,
        },
    )
    .await?;
    println!(
        "{}",
        serde_json::json!({ "ok": true, "standing_grant_hash": grant_hash.trim(), "standing_grant_status": "revoked", "nonce": nonce })
    );
    Ok(())
}

async fn record_approval(
    state_dir: &Path,
    grant_file: &str,
    target_scope: &str,
    reason: &str,
) -> Result<()> {
    let grant_json = if grant_file == "-" {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
        text
    } else {
        std::fs::read_to_string(grant_file)?
    };
    let grant: ApprovalGrant = serde_json::from_str(&grant_json).context("approval grant JSON")?;
    let outcome = record_one_use_grant(state_dir, &grant, target_scope, reason).await?;
    println!("{outcome}");
    Ok(())
}

/// The operator's approval request, exactly as the daemon's challenge names it.
struct ApproveRequest<'a> {
    policy_hash: &'a str,
    request_hash: &'a str,
    audience: &'a str,
    target_scope: &'a str,
    expires_in_secs: u64,
    reason: &'a str,
}

/// `approve`: the ONE place a grant is minted. Every check that needs no secret runs first; the
/// approver seed is unsealed in memory only after them, signs exactly one one-use grant, and is
/// zeroized before the grant is recorded. A wrong passphrase refuses before anything is signed or
/// recorded. stdout carries the recording outcome and the grant — never the seed.
async fn approve(
    state_dir: &Path,
    request: &ApproveRequest<'_>,
    key_mode: KeyModeArgs,
    pass: &OperatorPassSource,
) -> Result<()> {
    let custody = require_custody(state_dir, key_mode)?;
    let policy_hash = parse_hash32(request.policy_hash, "--policy-hash")?;
    let request_hash = parse_hash32(request.request_hash, "--request-hash")?;
    let audience = parse_account32(request.audience, "--audience")?;
    if !request
        .target_scope
        .starts_with("scope:hypervisor.live-route.")
    {
        bail!(
            "target scope {} is outside the deployment approver's allowlist ({APPROVER_SCOPE_ALLOWLIST})",
            request.target_scope
        );
    }
    if request.expires_in_secs == 0 || request.expires_in_secs > MAX_APPROVAL_EXPIRES_IN_SECS {
        bail!(
            "--expires-in-secs must be between 1 and {MAX_APPROVAL_EXPIRES_IN_SECS}: a one-use grant is also a short-lived one"
        );
    }
    let ready = read_ready(state_dir)?;
    let record = read_authority_record(state_dir)?;
    if record.binding_status != "active" {
        bail!(
            "the principal's binding is {}; nothing can be approved",
            record.binding_status
        );
    }
    if hex::encode(audience) != ready.capability_account_id {
        bail!(
            "--audience is not this deployment's capability account {}; wallet.network consumes a grant only for its audience",
            ready.capability_account_id
        );
    }
    let approver_public_key =
        read_public_key(&state_dir.join("keys").join(APPROVER_PUBLIC_KEY_FILE))?;
    if hex::encode(&approver_public_key) != record.approver_public_key {
        bail!(
            "keys/{APPROVER_PUBLIC_KEY_FILE} is not the approver on record ({}); refusing to sign with a key the authority record does not name",
            record.approver_authority_id
        );
    }

    let approver = {
        let seed = match custody {
            KeyCustody::Sealed => {
                let operator_pass = pass.obtain(
                    state_dir,
                    "approve: the approver key signs one one-use grant",
                    false,
                )?;
                open_sealed_seed(
                    &state_dir.join("keys").join(APPROVER_SEED_SEALED),
                    &operator_pass,
                )?
            }
            KeyCustody::Plaintext => {
                read_seed_hex(&state_dir.join("keys").join(APPROVER_SEED_PLAINTEXT))?
            }
        };
        keypair(&seed)?
        // `seed` (Zeroizing) is wiped here, at the end of this block.
    };
    if approver.public_key().to_bytes() != approver_public_key {
        bail!("the unsealed approver key is not keys/{APPROVER_PUBLIC_KEY_FILE}; nothing was signed or recorded");
    }
    let expires_at_ms = now_ms().saturating_add(request.expires_in_secs.saturating_mul(1_000));
    let grant = mint_one_use_grant(
        &approver,
        policy_hash,
        request_hash,
        audience,
        expires_at_ms,
    )?;
    drop(approver);

    let mut outcome =
        record_one_use_grant(state_dir, &grant, request.target_scope, request.reason).await?;
    let grant_hash = grant
        .artifact_hash()
        .map_err(|error| anyhow!("approval grant hash: {error}"))?;
    outcome["grant_ref"] = serde_json::json!(format!(
        "wallet.network://grant/approval/{}",
        hex::encode(grant_hash)
    ));
    outcome["expires_at_ms"] = serde_json::json!(grant.expires_at);
    outcome["approval_grant"] = serde_json::to_value(&grant)?;
    println!("{outcome}");
    Ok(())
}

/// Mint ONE grant for ONE exact challenge — the logic of `crates/node/src/bin/mint-approval-grant.rs`
/// (canonical `signing_bytes`, a real Ed25519 signature, `authority_id` derived from the public
/// key, structural `verify()`), with the deployment's properties: a RANDOM nonce, exactly one
/// use and a bounded expiry.
fn mint_one_use_grant(
    approver: &Ed25519KeyPair,
    policy_hash: [u8; 32],
    request_hash: [u8; 32],
    audience: [u8; 32],
    expires_at_ms: u64,
) -> Result<ApprovalGrant> {
    use rand::RngCore;
    let public_key = approver.public_key().to_bytes();
    let authority_id = account_id_from_key_material(SignatureSuite::ED25519, &public_key)?;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut grant = ApprovalGrant {
        schema_version: 1,
        authority_id,
        request_hash,
        policy_hash,
        audience,
        nonce,
        counter: 1,
        expires_at: expires_at_ms,
        max_usages: Some(1),
        window_id: None,
        pii_action: None,
        scoped_exception: None,
        review_request_hash: None,
        approver_public_key: public_key,
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    };
    let signing_bytes = grant
        .signing_bytes()
        .map_err(|error| anyhow!("approval grant signing bytes: {error}"))?;
    grant.approver_sig = approver
        .sign(&signing_bytes)
        .map_err(|error| anyhow!("sign approval grant: {error}"))?
        .to_bytes()
        .to_vec();
    grant
        .verify()
        .map_err(|error| anyhow!("minted approval grant does not verify: {error}"))?;
    Ok(grant)
}

/// Record an already-signed one-use grant as the approval decision for its request hash, from the
/// daemon's capability account under the daemon's transaction lock. Returns the outcome object.
async fn record_one_use_grant(
    state_dir: &Path,
    grant: &ApprovalGrant,
    target_scope: &str,
    reason: &str,
) -> Result<serde_json::Value> {
    let ready = read_ready(state_dir)?;
    let record = read_authority_record(state_dir)?;
    if record.binding_status != "active" {
        bail!(
            "the principal's binding is {}; nothing can be approved",
            record.binding_status
        );
    }
    let guardian_pass = guardian_pass()?;
    let sealed = std::fs::read(&ready.capability_key_path)?;
    let capability_seed = ioi_crypto::key_store::decrypt_key(&sealed, &guardian_pass)
        .map_err(|error| anyhow!("open capability key: {error}"))?;
    let capability_seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        capability_seed
            .0
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("capability key is not a 32-byte seed"))?,
    );
    let capability = keypair(&capability_seed)?;
    let capability_account_id =
        account_id_from_key_material(SignatureSuite::ED25519, &capability.public_key().to_bytes())?;
    let grant = grant.clone();
    if hex::encode(grant.authority_id) != record.approver_authority_id
        || hex::encode(&grant.approver_public_key) != record.approver_public_key
    {
        bail!("the grant is not signed by the custodied approver ({}); refusing to record a foreign approval", record.approver_authority_id);
    }
    if grant.audience != capability_account_id {
        bail!(
            "the grant's audience is not this deployment's capability account {}",
            hex::encode(capability_account_id)
        );
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
        let existing: WalletApprovalDecision =
            decode_state_value(&existing_bytes, "approval decision")?;
        if approval_matches(&existing, &grant, target_scope, reason) {
            return Ok(
                serde_json::json!({ "ok": true, "request_hash": hex::encode(grant.request_hash), "recorded": "existing" }),
            );
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
    submit(
        &ready.rpc_addr,
        &capability,
        ChainId(ready.chain_id),
        nonce,
        "record_approval@v1",
        &approval,
    )
    .await?;
    let persisted = query_state_key(&ready.rpc_addr, &approval_key)
        .await?
        .ok_or_else(|| anyhow!("record_approval committed but no approval state is readable"))?;
    let persisted: WalletApprovalDecision = decode_state_value(&persisted, "approval decision")?;
    if !approval_matches(&persisted, &grant, target_scope, reason) {
        bail!("persisted approval decision differs from the one submitted");
    }
    Ok(
        serde_json::json!({ "ok": true, "request_hash": hex::encode(grant.request_hash), "recorded": "committed", "nonce": nonce }),
    )
}

// ---------------------------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------------------------

fn guardian_pass() -> Result<String> {
    let pass = std::env::var(GUARDIAN_PASS_ENV)
        .context("IOI_GUARDIAN_KEY_PASS is required: it seals the daemon's wallet capability key and the daemon needs the same value to open it")?;
    if pass.trim().is_empty() {
        bail!("IOI_GUARDIAN_KEY_PASS cannot be empty");
    }
    Ok(pass)
}

/// Where the operator passphrase may come from: the environment variable, captured and scrubbed
/// at startup, or a TTY prompt when stdin is a terminal. Never argv, never a file.
struct OperatorPassSource {
    from_env: Option<Zeroizing<String>>,
    prompt_allowed: bool,
}

impl OperatorPassSource {
    /// Take `IOI_AUTHORITY_OPERATOR_PASS` out of this process: copy the value, overwrite it in the
    /// initial environment block and unset it, so neither a child nor `/proc/<pid>/environ` sees it.
    fn capture_and_scrub() -> Self {
        let from_env = std::env::var_os(OPERATOR_PASS_ENV).map(|value| {
            scrub_environment_block(OPERATOR_PASS_ENV);
            std::env::remove_var(OPERATOR_PASS_ENV);
            // A value that is not UTF-8 cannot be compared or typed at a prompt; it becomes the
            // empty passphrase, which validation refuses by name.
            Zeroizing::new(value.into_string().unwrap_or_default())
        });
        Self {
            from_env,
            prompt_allowed: std::io::stdin().is_terminal(),
        }
    }

    fn available(&self) -> bool {
        self.from_env.is_some() || self.prompt_allowed
    }

    /// The passphrase for one act, validated (non-empty, long enough, not the guardian pass).
    /// `confirm` asks twice at a prompt — for acts that create a new sealed key.
    fn obtain(&self, state_dir: &Path, purpose: &str, confirm: bool) -> Result<Zeroizing<String>> {
        let pass = match &self.from_env {
            Some(value) => Zeroizing::new(value.as_str().to_owned()),
            None if self.prompt_allowed => {
                let first = Zeroizing::new(
                    rpassword::prompt_password(format!("Operator passphrase ({purpose}): "))
                        .context("read the operator passphrase from the terminal")?,
                );
                if confirm {
                    let second = Zeroizing::new(
                        rpassword::prompt_password("Repeat the operator passphrase: ")
                            .context("read the operator passphrase from the terminal")?,
                    );
                    if first.as_str() != second.as_str() {
                        bail!("the two passphrase entries differ; nothing was written");
                    }
                }
                first
            }
            None => bail!(
                "{purpose} needs the operator passphrase: set {OPERATOR_PASS_ENV} for this one command, or run it on a terminal to be prompted (it is never read from argv or from a file)"
            ),
        };
        validate_operator_pass(&pass, state_dir)?;
        Ok(pass)
    }
}

/// The operator passphrase is refused when empty, short, or equal to the guardian pass: the
/// guardian pass unlocks the daemon's capability key and lives beside it on this host
/// (`IOI_GUARDIAN_KEY_PASS`, `keys/guardian.pass`), so it can never also seal approval authority.
fn validate_operator_pass(pass: &str, state_dir: &Path) -> Result<()> {
    if pass.trim().is_empty() {
        bail!("the operator passphrase cannot be empty");
    }
    if pass.chars().count() < MIN_OPERATOR_PASS_CHARS {
        bail!("the operator passphrase must be at least {MIN_OPERATOR_PASS_CHARS} characters");
    }
    let mut guardian_values: Vec<Zeroizing<String>> = Vec::new();
    if let Ok(value) = std::env::var(GUARDIAN_PASS_ENV) {
        guardian_values.push(Zeroizing::new(value));
    }
    if let Ok(value) = std::fs::read_to_string(state_dir.join("keys").join("guardian.pass")) {
        guardian_values.push(Zeroizing::new(value));
    }
    let same_as_guardian = guardian_values.iter().any(|guardian| {
        !guardian.trim().is_empty() && (guardian.as_str() == pass || guardian.trim() == pass.trim())
    });
    if same_as_guardian {
        bail!("the operator passphrase must differ from {GUARDIAN_PASS_ENV}: the guardian pass opens the daemon's capability key and sits on this host beside it, so it cannot also seal the approver and root keys");
    }
    Ok(())
}

/// Overwrite `NAME=value` in this process's environment block, in place, before the variable is
/// unset. `remove_var` alone only unlinks the pointer: the bytes the kernel copied at exec stay in
/// the block `/proc/<pid>/environ` reads for the whole life of the process.
#[cfg(target_os = "linux")]
fn scrub_environment_block(name: &str) {
    extern "C" {
        static mut environ: *mut *mut libc::c_char;
    }
    let prefix = format!("{name}=");
    // SAFETY: called first thing in `main`, before any other thread exists, so nothing reads or
    // mutates the environment concurrently. Every entry is a NUL-terminated string owned by this
    // process; only bytes before an entry's terminator are overwritten, and the shared borrow of
    // an entry ends before any byte of it is written.
    unsafe {
        let mut cursor = environ;
        if cursor.is_null() {
            return;
        }
        while !(*cursor).is_null() {
            let entry = *cursor;
            let (matches, total) = {
                let bytes = std::ffi::CStr::from_ptr(entry).to_bytes();
                (bytes.starts_with(prefix.as_bytes()), bytes.len())
            };
            if matches {
                for offset in prefix.len()..total {
                    std::ptr::write_volatile(entry.add(offset), 0);
                }
            }
            cursor = cursor.add(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn scrub_environment_block(_name: &str) {}

/// Which custody keys/ is in, from the files present. Sealed and plaintext seeds never coexist
/// except mid-`seal-keys`, which is refused until that conversion is finished.
fn detect_custody(keys_dir: &Path) -> Result<Option<KeyCustody>> {
    let plaintext = [ROOT_SEED_PLAINTEXT, APPROVER_SEED_PLAINTEXT]
        .iter()
        .any(|name| keys_dir.join(name).exists());
    let sealed = [ROOT_SEED_SEALED, APPROVER_SEED_SEALED]
        .iter()
        .any(|name| keys_dir.join(name).exists());
    match (plaintext, sealed) {
        (false, false) => Ok(None),
        (true, false) => Ok(Some(KeyCustody::Plaintext)),
        (false, true) => Ok(Some(KeyCustody::Sealed)),
        (true, true) => bail!(
            "keys/ holds BOTH plaintext and sealed seeds (an interrupted `seal-keys`?); run `seal-keys --state-dir <dir>` again to finish the conversion"
        ),
    }
}

fn plaintext_refusal(state_dir: &Path) -> anyhow::Error {
    anyhow!(
        "{dir} holds PLAINTEXT keys/{ROOT_SEED_PLAINTEXT} and keys/{APPROVER_SEED_PLAINTEXT} (a pre-sealing or dev/test state dir). Deployment mode refuses plaintext approval and root keys: any process running as this uid could read them and approve its own effects. Convert it once with `wallet-network-local-authority seal-keys --state-dir {dir}` ({OPERATOR_PASS_ENV} set, or on a terminal); a dev/test node may pass --plaintext-keys instead.",
        dir = state_dir.display()
    )
}

/// The custody an act against an existing state dir runs under: sealed unless the dev/test
/// opt-in is given for a plaintext dir; any other combination is refused.
fn require_custody(state_dir: &Path, key_mode: KeyModeArgs) -> Result<KeyCustody> {
    let custody = detect_custody(&state_dir.join("keys"))?.ok_or_else(|| {
        anyhow!(
            "{}/keys holds no control root; bring the node up with `serve` first",
            state_dir.display()
        )
    })?;
    match (custody, key_mode.plaintext_keys) {
        (KeyCustody::Sealed, false) => Ok(KeyCustody::Sealed),
        (KeyCustody::Plaintext, true) => Ok(KeyCustody::Plaintext),
        (KeyCustody::Plaintext, false) => Err(plaintext_refusal(state_dir)),
        (KeyCustody::Sealed, true) => bail!(
            "keys/ is SEALED; --plaintext-keys is a dev/test opt-in for plaintext state dirs and never applies to sealed keys"
        ),
    }
}

/// Open the control root for one signing act and bind it to its public half on disk.
fn open_root_signer(
    state_dir: &Path,
    custody: KeyCustody,
    operator_pass: Option<&str>,
) -> Result<Ed25519KeyPair> {
    let keys_dir = state_dir.join("keys");
    let seed = match custody {
        KeyCustody::Sealed => {
            let operator_pass = operator_pass
                .ok_or_else(|| anyhow!("the sealed control root needs the operator passphrase"))?;
            open_sealed_seed(&keys_dir.join(ROOT_SEED_SEALED), operator_pass)?
        }
        KeyCustody::Plaintext => read_seed_hex(&keys_dir.join(ROOT_SEED_PLAINTEXT))?,
    };
    let root = keypair(&seed)?;
    let public_path = keys_dir.join(ROOT_PUBLIC_KEY_FILE);
    if public_path.exists() {
        if read_public_key(&public_path)? != root.public_key().to_bytes() {
            bail!("the control root does not match keys/{ROOT_PUBLIC_KEY_FILE}; refusing to sign with a key the state dir does not name");
        }
    } else if custody == KeyCustody::Sealed {
        bail!("keys/{ROOT_PUBLIC_KEY_FILE} is missing beside the sealed control root");
    }
    Ok(root)
}

fn load_root_signer(
    state_dir: &Path,
    custody: KeyCustody,
    pass: &OperatorPassSource,
    purpose: &str,
) -> Result<Ed25519KeyPair> {
    match custody {
        KeyCustody::Sealed => {
            let operator_pass = pass.obtain(state_dir, purpose, false)?;
            open_root_signer(state_dir, custody, Some(&operator_pass))
        }
        KeyCustody::Plaintext => open_root_signer(state_dir, custody, None),
    }
}

/// `serve`'s keys. A FRESH state dir generates the control root and the approver key — sealed
/// with the operator passphrase, which is obtained and validated before anything is written —
/// plus the daemon's capability key (guardian pass). A RESUME reads public halves only and needs
/// no passphrase; a plaintext dir is refused unless the dev/test opt-in is given.
fn load_or_generate_serve_keys(
    state_dir: &Path,
    guardian_pass: &str,
    key_mode: KeyModeArgs,
    pass: &OperatorPassSource,
) -> Result<ServeKeys> {
    let keys_dir = state_dir.join("keys");
    std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o700))?;
    let capability_key_path = keys_dir.join(CAPABILITY_KEY_FILE);
    let root_public_path = keys_dir.join(ROOT_PUBLIC_KEY_FILE);
    let approver_public_path = keys_dir.join(APPROVER_PUBLIC_KEY_FILE);
    let mut genesis_root = None;
    let custody = match detect_custody(&keys_dir)? {
        None => {
            if capability_key_path.exists() || root_public_path.exists() || approver_public_path.exists() {
                bail!("keys/ is partially populated (no control root seed but other key files exist); refusing to guess which deployment this is");
            }
            let custody = if key_mode.plaintext_keys {
                KeyCustody::Plaintext
            } else {
                KeyCustody::Sealed
            };
            let operator_pass = match custody {
                KeyCustody::Sealed => {
                    if !pass.available() {
                        bail!(
                            "{} is a FRESH state dir: the first bring-up generates the control root and the approver key SEALED with the operator passphrase, and the root signs the genesis binding, so this one run needs it. Set {OPERATOR_PASS_ENV} for this command only (or run it on a terminal to be prompted); every later run resumes without it.",
                            state_dir.display()
                        );
                    }
                    Some(pass.obtain(
                        state_dir,
                        "first bring-up seals the new control root and approver key",
                        true,
                    )?)
                }
                KeyCustody::Plaintext => None,
            };
            println!(
                "--- generating the deployment's control root, capability client and approver keys ({} custody) ---",
                custody.label()
            );
            let root_seed = random_seed();
            let approver_seed = random_seed();
            match &operator_pass {
                Some(operator_pass) => {
                    write_sealed_seed(&keys_dir.join(ROOT_SEED_SEALED), &root_seed, operator_pass)?;
                    write_sealed_seed(
                        &keys_dir.join(APPROVER_SEED_SEALED),
                        &approver_seed,
                        operator_pass,
                    )?;
                }
                None => {
                    write_secret_hex(&keys_dir.join(ROOT_SEED_PLAINTEXT), &root_seed)?;
                    write_secret_hex(&keys_dir.join(APPROVER_SEED_PLAINTEXT), &approver_seed)?;
                }
            }
            let root = keypair(&root_seed)?;
            write_public_key(&root_public_path, &root.public_key().to_bytes())?;
            write_public_key(
                &approver_public_path,
                &keypair(&approver_seed)?.public_key().to_bytes(),
            )?;
            let capability_seed = random_seed();
            let sealed = ioi_crypto::key_store::encrypt_key(&capability_seed[..], guardian_pass)
                .map_err(|error| anyhow!("seal capability key: {error}"))?;
            write_secret_bytes(&capability_key_path, &sealed)?;
            std::fs::File::open(&keys_dir)?.sync_all()?;
            genesis_root = Some(root);
            custody
        }
        Some(KeyCustody::Plaintext) if !key_mode.plaintext_keys => {
            return Err(plaintext_refusal(state_dir))
        }
        Some(KeyCustody::Sealed) if key_mode.plaintext_keys => bail!(
            "keys/ is SEALED; --plaintext-keys is a dev/test opt-in for plaintext state dirs and never applies to sealed keys"
        ),
        Some(KeyCustody::Plaintext) => {
            // dev/test: the seeds are the truth; (re)derive the public halves the resume compares.
            for (seed_name, public_path) in [
                (ROOT_SEED_PLAINTEXT, &root_public_path),
                (APPROVER_SEED_PLAINTEXT, &approver_public_path),
            ] {
                let seed = read_seed_hex(&keys_dir.join(seed_name))?;
                let public_key = keypair(&seed)?.public_key().to_bytes();
                write_public_key(public_path, &public_key)?;
            }
            KeyCustody::Plaintext
        }
        Some(KeyCustody::Sealed) => {
            for path in [&root_public_path, &approver_public_path] {
                if !path.exists() {
                    bail!(
                        "{} is missing beside the sealed seeds; a resume checks public keys only, so restore it from the deployment's backup",
                        path.display()
                    );
                }
            }
            KeyCustody::Sealed
        }
    };
    let sealed = std::fs::read(&capability_key_path)?;
    let capability_seed = ioi_crypto::key_store::decrypt_key(&sealed, guardian_pass)
        .map_err(|error| anyhow!("open capability key with IOI_GUARDIAN_KEY_PASS: {error}"))?;
    let capability_seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        capability_seed
            .0
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("capability key is not a 32-byte seed"))?,
    );
    let capability = keypair(&capability_seed)?;
    Ok(ServeKeys {
        custody,
        capability,
        capability_key_path,
        root_public_key: read_public_key(&root_public_path)?,
        approver_public_key: read_public_key(&approver_public_path)?,
        approver_public_key_path: approver_public_path,
        approver_plaintext_path: (custody == KeyCustody::Plaintext)
            .then(|| keys_dir.join(APPROVER_SEED_PLAINTEXT)),
        genesis_root,
    })
}

/// `seal-keys`: convert a plaintext state dir. Every plaintext seed (root, approver, retired
/// approvers) is sealed with the operator passphrase and verified by opening it again; only when
/// every one is sealed are the plaintext files overwritten and removed. Re-running it finishes an
/// interrupted conversion.
fn seal_keys(state_dir: &Path, pass: &OperatorPassSource) -> Result<()> {
    let keys_dir = state_dir.join("keys");
    if !keys_dir.is_dir() {
        bail!("{} has no keys/ directory", state_dir.display());
    }
    if keys_dir
        .join(format!("{APPROVER_SEED_PLAINTEXT}.next"))
        .exists()
    {
        bail!("a plaintext rotation is in progress (keys/{APPROVER_SEED_PLAINTEXT}.next); finish it with `rotate --plaintext-keys` before sealing");
    }
    // (plaintext seed, sealed seed, public half, mode)
    let mut plan: Vec<(PathBuf, PathBuf, PathBuf, u32)> = vec![
        (
            keys_dir.join(ROOT_SEED_PLAINTEXT),
            keys_dir.join(ROOT_SEED_SEALED),
            keys_dir.join(ROOT_PUBLIC_KEY_FILE),
            0o600,
        ),
        (
            keys_dir.join(APPROVER_SEED_PLAINTEXT),
            keys_dir.join(APPROVER_SEED_SEALED),
            keys_dir.join(APPROVER_PUBLIC_KEY_FILE),
            0o600,
        ),
    ];
    let retired_prefix = format!("{APPROVER_SEED_PLAINTEXT}.v");
    for entry in std::fs::read_dir(&keys_dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if let Some(version) = name.strip_prefix(&retired_prefix) {
            if !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit()) {
                plan.push((
                    keys_dir.join(&name),
                    keys_dir.join(format!("{APPROVER_SEED_SEALED}.v{version}")),
                    keys_dir.join(format!("{APPROVER_PUBLIC_KEY_FILE}.v{version}")),
                    0o400,
                ));
            }
        }
    }
    let pending: Vec<_> = plan
        .into_iter()
        .filter(|(plaintext, ..)| plaintext.exists())
        .collect();
    if pending.is_empty() {
        if keys_dir.join(ROOT_SEED_SEALED).exists() && keys_dir.join(APPROVER_SEED_SEALED).exists()
        {
            println!(
                "{}",
                serde_json::json!({ "ok": true, "key_custody": "sealed", "sealed": [], "removed": [], "note": "keys/ was already sealed" })
            );
            return Ok(());
        }
        bail!(
            "{}/keys holds no plaintext seeds to seal",
            state_dir.display()
        );
    }
    let operator_pass = pass.obtain(
        state_dir,
        "seal-keys seals the control root and the approver key",
        true,
    )?;
    let file_name = |path: &Path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    let mut sealed_names = Vec::new();
    for (plaintext, sealed, public, mode) in &pending {
        let seed = read_seed_hex(plaintext)?;
        if sealed.exists() {
            // An interrupted earlier run: the sealed file must hold exactly this seed.
            let existing = open_sealed_seed(sealed, &operator_pass)?;
            if *existing != *seed {
                bail!(
                    "{} already exists and seals a DIFFERENT key than {}; refusing to overwrite or remove either",
                    sealed.display(),
                    plaintext.display()
                );
            }
        } else {
            write_sealed_seed(sealed, &seed, &operator_pass)?;
            if *open_sealed_seed(sealed, &operator_pass)? != *seed {
                bail!(
                    "sealing {} did not round-trip; the plaintext file is kept",
                    plaintext.display()
                );
            }
        }
        std::fs::set_permissions(sealed, std::fs::Permissions::from_mode(*mode))?;
        write_public_key(public, &keypair(&seed)?.public_key().to_bytes())?;
        sealed_names.push(file_name(sealed));
    }
    std::fs::File::open(&keys_dir)?.sync_all()?;
    let mut removed_names = Vec::new();
    for (plaintext, ..) in &pending {
        scrub_and_remove(plaintext)?;
        removed_names.push(file_name(plaintext));
    }
    std::fs::File::open(&keys_dir)?.sync_all()?;
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "key_custody": "sealed",
            "sealed": sealed_names,
            "removed": removed_names,
            "root_public_key": read_public_key(&keys_dir.join(ROOT_PUBLIC_KEY_FILE)).ok().map(hex::encode),
            "approver_public_key": read_public_key(&keys_dir.join(APPROVER_PUBLIC_KEY_FILE)).ok().map(hex::encode),
        })
    );
    Ok(())
}

/// Overwrite a plaintext seed file, then unlink it. The overwrite is best effort (a journaling or
/// copy-on-write filesystem may keep older blocks); the unlink is what is guaranteed.
fn scrub_and_remove(path: &Path) -> Result<()> {
    let length = std::fs::metadata(path)?.len() as usize;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
        let _ = file.write_all(&vec![0u8; length]);
        let _ = file.sync_all();
    }
    std::fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    Ok(())
}

fn random_seed() -> Zeroizing<[u8; 32]> {
    use rand::RngCore;
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(seed.as_mut());
    seed
}

fn write_sealed_seed(path: &Path, seed: &[u8; 32], operator_pass: &str) -> Result<()> {
    let sealed = ioi_crypto::key_store::encrypt_key(seed, operator_pass)
        .map_err(|error| anyhow!("seal {}: {error}", path.display()))?;
    write_secret_bytes(path, &sealed)
}

fn open_sealed_seed(path: &Path, operator_pass: &str) -> Result<Zeroizing<[u8; 32]>> {
    refuse_shared_key_file(path)?;
    let sealed = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let opened = ioi_crypto::key_store::decrypt_key(&sealed, operator_pass).map_err(|_| {
        anyhow!(
            "the operator passphrase does not open {} (wrong passphrase, or not a sealed key); nothing was signed or recorded",
            path.display()
        )
    })?;
    let seed: [u8; 32] = opened
        .0
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{} does not seal a 32-byte seed", path.display()))?;
    Ok(Zeroizing::new(seed))
}

fn write_public_key(path: &Path, public_key: &[u8]) -> Result<()> {
    write_atomic_durable(path, format!("{}\n", hex::encode(public_key)).as_bytes())
}

fn read_public_key(path: &Path) -> Result<Vec<u8>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let bytes =
        hex::decode(text.trim()).with_context(|| format!("{} is not hex", path.display()))?;
    if bytes.len() != 32 {
        bail!("{} is not a 32-byte Ed25519 public key", path.display());
    }
    Ok(bytes)
}

fn write_secret_hex(path: &Path, seed: &[u8; 32]) -> Result<()> {
    let text = Zeroizing::new(format!("{}\n", hex::encode(seed)));
    write_secret_bytes(path, text.as_bytes())
}

fn write_secret_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn refuse_shared_key_file(path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path).with_context(|| format!("read {}", path.display()))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!(
            "{} is readable by group/other (mode {:o}); refusing a shared key",
            path.display(),
            metadata.permissions().mode() & 0o777
        );
    }
    Ok(())
}

fn read_seed_hex(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    refuse_shared_key_file(path)?;
    let text = Zeroizing::new(std::fs::read_to_string(path)?);
    let mut bytes =
        hex::decode(text.trim()).with_context(|| format!("{} is not hex", path.display()))?;
    let seed: Result<[u8; 32]> = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{} is not a 32-byte seed", path.display()));
    bytes.zeroize();
    Ok(Zeroizing::new(seed?))
}

fn keypair(seed: &[u8; 32]) -> Result<Ed25519KeyPair> {
    let private =
        Ed25519PrivateKey::from_bytes(seed).map_err(|error| anyhow!(error.to_string()))?;
    Ed25519KeyPair::from_private_key(&private).map_err(|error| anyhow!(error.to_string()))
}

/// A 32-byte hash from the challenge: bare hex or the `sha256:`-prefixed ref form.
fn parse_hash32(raw: &str, label: &str) -> Result<[u8; 32]> {
    let trimmed = raw.trim();
    let hex_part = trimmed.strip_prefix("sha256:").unwrap_or(trimmed);
    let bytes = hex::decode(hex_part).with_context(|| format!("{label} is not hex"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{label} must be 32 bytes (64 hex characters)"))
}

/// A 32-byte account id: bare hex only (an account is not a hash ref).
fn parse_account32(raw: &str, label: &str) -> Result<[u8; 32]> {
    if raw.trim().starts_with("sha256:") {
        bail!("{label} must be bare 32-byte hex (an account id, not a hash ref)");
    }
    parse_hash32(raw, label)
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
    ServicePolicy {
        methods,
        allowed_system_prefixes: Vec::new(),
    }
}

/// The approval authority a PUBLIC key names: registering and binding an approver needs no private
/// key, so neither `serve` nor `rotate` ever holds the approver's seed to do it.
fn approval_authority_from_public_key(public_key: &[u8]) -> Result<ApprovalAuthority> {
    Ok(ApprovalAuthority {
        schema_version: 1,
        authority_id: account_id_from_key_material(SignatureSuite::ED25519, public_key)?,
        public_key: public_key.to_vec(),
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
            signature: root
                .private_key()
                .sign(&message)
                .map_err(|error| anyhow!(error.to_string()))?
                .to_bytes(),
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

// ---------------------------------------------------------------------------------------------
// chain reads
// ---------------------------------------------------------------------------------------------

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
        Some(bytes) => decode_state_value(&bytes, "account nonce"),
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

async fn read_head(
    rpc_addr: &str,
    principal_ref: &str,
) -> Result<Option<PrincipalAuthorityBindingHeadV1>> {
    query_state_key(rpc_addr, &principal_authority_head_key(principal_ref))
        .await?
        .map(|bytes| decode_state_value(&bytes, "principal authority head"))
        .transpose()
}

async fn read_proof(
    rpc_addr: &str,
    binding_hash: &[u8; 32],
) -> Result<PrincipalAuthorityBindingProofV1> {
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
    let bytes = std::fs::read(&path).with_context(|| {
        format!(
            "{} is absent: the authority node is not serving",
            path.display()
        )
    })?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_authority_record(state_dir: &Path) -> Result<AuthorityRecord> {
    let path = state_dir.join(AUTHORITY_RECORD_FILE);
    Ok(serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )?)
}

fn write_authority_record(state_dir: &Path, record: &AuthorityRecord) -> Result<()> {
    write_atomic_durable(
        &state_dir.join(AUTHORITY_RECORD_FILE),
        &serde_json::to_vec_pretty(record)?,
    )
}

fn write_atomic_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("atomic publication requires a parent directory"))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("atomic publication requires a UTF-8 filename"))?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        now_ms()
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
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

fn validate_principal_ref(principal_ref: &str) -> Result<()> {
    let valid_scheme = [
        "worker://",
        "service://",
        "org://",
        "domain://",
        "agentgres://domain/",
    ]
    .iter()
    .any(|scheme| principal_ref.starts_with(scheme) && principal_ref.len() > scheme.len());
    if !valid_scheme {
        bail!("principal ref {principal_ref:?} is not in the canonical grammar (worker:// service:// org:// domain:// agentgres://domain/)");
    }
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn iso_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
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
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sod / 3_600,
        (sod % 3_600) / 60,
        sod % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_services::agentic::runtime::kernel::approval::verify_wallet_approval_grant_binding;

    const OPERATOR: &str = "operator-pass-for-sealing";
    const GUARDIAN: &str = "guardian-pass-for-capability";

    fn pass_source(value: Option<&str>) -> OperatorPassSource {
        OperatorPassSource {
            from_env: value.map(|value| Zeroizing::new(value.to_string())),
            prompt_allowed: false,
        }
    }

    /// A state dir whose keys/guardian.pass holds the guardian pass, as the launcher writes it.
    fn state_dir_with_guardian() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("keys")).unwrap();
        std::fs::write(
            dir.path().join("keys/guardian.pass"),
            format!("{GUARDIAN}\n"),
        )
        .unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn key_file_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir.join("keys"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_sealed_seed_opens_only_with_the_operator_pass() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(APPROVER_SEED_SEALED);
        let seed = random_seed();
        write_sealed_seed(&path, &seed, OPERATOR).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(*open_sealed_seed(&path, OPERATOR).unwrap(), *seed);
        assert!(
            open_sealed_seed(&path, GUARDIAN).is_err(),
            "the guardian pass must not open it"
        );
        assert!(
            open_sealed_seed(&path, "").is_err(),
            "the empty pass must not open it"
        );
        let bytes = std::fs::read(&path).unwrap();
        assert!(!contains(&bytes, &seed[..]), "raw seed bytes on disk");
        assert!(
            !contains(&bytes, hex::encode(*seed).as_bytes()),
            "hex seed on disk"
        );
    }

    #[test]
    fn the_operator_pass_is_refused_when_empty_short_or_equal_to_the_guardian_pass() {
        let dir = state_dir_with_guardian();
        assert!(validate_operator_pass(OPERATOR, dir.path()).is_ok());
        let same = validate_operator_pass(GUARDIAN, dir.path())
            .unwrap_err()
            .to_string();
        assert!(same.contains("must differ"), "{same}");
        assert!(validate_operator_pass(&format!(" {GUARDIAN}\n"), dir.path()).is_err());
        assert!(validate_operator_pass("", dir.path()).is_err());
        assert!(validate_operator_pass("   ", dir.path()).is_err());
        assert!(validate_operator_pass("short", dir.path()).is_err());
    }

    #[test]
    fn a_fresh_sealed_bring_up_without_the_pass_is_refused_and_writes_nothing() {
        let dir = state_dir_with_guardian();
        let error = load_or_generate_serve_keys(
            dir.path(),
            GUARDIAN,
            KeyModeArgs::default(),
            &pass_source(None),
        )
        .err()
        .expect("a fresh sealed bring-up without the passphrase must refuse")
        .to_string();
        assert!(
            error.contains("FRESH state dir") && error.contains(OPERATOR_PASS_ENV),
            "{error}"
        );
        assert_eq!(
            key_file_names(dir.path()),
            vec!["guardian.pass".to_string()]
        );
    }

    #[test]
    fn a_fresh_bring_up_with_the_guardian_pass_as_operator_pass_is_refused_and_writes_nothing() {
        let dir = state_dir_with_guardian();
        let error = load_or_generate_serve_keys(
            dir.path(),
            GUARDIAN,
            KeyModeArgs::default(),
            &pass_source(Some(GUARDIAN)),
        )
        .err()
        .expect("the guardian pass must not seal the root and approver")
        .to_string();
        assert!(error.contains("must differ"), "{error}");
        assert_eq!(
            key_file_names(dir.path()),
            vec!["guardian.pass".to_string()]
        );
    }

    #[test]
    fn a_fresh_sealed_bring_up_leaves_only_sealed_seeds_and_a_resume_needs_no_pass() {
        let dir = state_dir_with_guardian();
        let keys = load_or_generate_serve_keys(
            dir.path(),
            GUARDIAN,
            KeyModeArgs::default(),
            &pass_source(Some(OPERATOR)),
        )
        .unwrap();
        assert_eq!(keys.custody, KeyCustody::Sealed);
        assert!(keys.approver_plaintext_path.is_none());
        assert_eq!(
            key_file_names(dir.path()),
            [
                APPROVER_PUBLIC_KEY_FILE,
                APPROVER_SEED_SEALED,
                CAPABILITY_KEY_FILE,
                "guardian.pass",
                ROOT_PUBLIC_KEY_FILE,
                ROOT_SEED_SEALED
            ]
            .map(String::from)
            .to_vec()
        );
        let keys_dir = dir.path().join("keys");
        for sealed in [ROOT_SEED_SEALED, APPROVER_SEED_SEALED] {
            let path = keys_dir.join(sealed);
            assert_eq!(mode(&path), 0o600, "{sealed}");
            assert!(
                open_sealed_seed(&path, GUARDIAN).is_err(),
                "{sealed} opens with the guardian pass"
            );
            assert!(
                open_sealed_seed(&path, "").is_err(),
                "{sealed} opens with the empty pass"
            );
        }
        // The public halves are what the sealed seeds hold.
        let root = keypair(&open_sealed_seed(&keys_dir.join(ROOT_SEED_SEALED), OPERATOR).unwrap())
            .unwrap();
        let approver =
            keypair(&open_sealed_seed(&keys_dir.join(APPROVER_SEED_SEALED), OPERATOR).unwrap())
                .unwrap();
        assert_eq!(keys.root_public_key, root.public_key().to_bytes());
        assert_eq!(keys.approver_public_key, approver.public_key().to_bytes());
        assert_eq!(
            keys.genesis_root
                .as_ref()
                .map(|key| key.public_key().to_bytes()),
            Some(root.public_key().to_bytes()),
            "the first bring-up holds the root only to sign genesis"
        );
        drop(keys);

        // Resume: no passphrase anywhere, no private root or approver key held.
        let resumed = load_or_generate_serve_keys(
            dir.path(),
            GUARDIAN,
            KeyModeArgs::default(),
            &pass_source(None),
        )
        .unwrap();
        assert!(resumed.genesis_root.is_none());
        assert_eq!(resumed.root_public_key, root.public_key().to_bytes());
        assert_eq!(
            resumed.approver_public_key,
            approver.public_key().to_bytes()
        );
        // And the dev/test opt-in never applies to sealed keys.
        assert!(load_or_generate_serve_keys(
            dir.path(),
            GUARDIAN,
            KeyModeArgs {
                plaintext_keys: true
            },
            &pass_source(None),
        )
        .is_err());
    }

    #[test]
    fn a_plaintext_state_dir_is_refused_in_deployment_mode_and_seal_keys_converts_it() {
        let dir = state_dir_with_guardian();
        let keys_dir = dir.path().join("keys");
        let root_seed = random_seed();
        let approver_seed = random_seed();
        let retired_seed = random_seed();
        write_secret_hex(&keys_dir.join(ROOT_SEED_PLAINTEXT), &root_seed).unwrap();
        write_secret_hex(&keys_dir.join(APPROVER_SEED_PLAINTEXT), &approver_seed).unwrap();
        let retired = keys_dir.join(format!("{APPROVER_SEED_PLAINTEXT}.v1"));
        write_secret_hex(&retired, &retired_seed).unwrap();
        std::fs::set_permissions(&retired, std::fs::Permissions::from_mode(0o400)).unwrap();

        let refused = require_custody(dir.path(), KeyModeArgs::default())
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("PLAINTEXT") && refused.contains("seal-keys"),
            "{refused}"
        );
        let serve_refused = load_or_generate_serve_keys(
            dir.path(),
            GUARDIAN,
            KeyModeArgs::default(),
            &pass_source(Some(OPERATOR)),
        )
        .err()
        .expect("serve must refuse a plaintext dir in deployment mode")
        .to_string();
        assert!(serve_refused.contains("seal-keys"), "{serve_refused}");
        assert_eq!(
            require_custody(
                dir.path(),
                KeyModeArgs {
                    plaintext_keys: true
                }
            )
            .unwrap(),
            KeyCustody::Plaintext
        );

        // A wrong (guardian) pass converts nothing.
        assert!(seal_keys(dir.path(), &pass_source(Some(GUARDIAN))).is_err());
        assert!(keys_dir.join(ROOT_SEED_PLAINTEXT).exists());
        assert!(!keys_dir.join(ROOT_SEED_SEALED).exists());

        seal_keys(dir.path(), &pass_source(Some(OPERATOR))).unwrap();
        for gone in [
            ROOT_SEED_PLAINTEXT,
            APPROVER_SEED_PLAINTEXT,
            "approver.seed.v1",
        ] {
            assert!(!keys_dir.join(gone).exists(), "{gone} survived seal-keys");
        }
        assert_eq!(mode(&keys_dir.join(ROOT_SEED_SEALED)), 0o600);
        assert_eq!(mode(&keys_dir.join(APPROVER_SEED_SEALED)), 0o600);
        assert_eq!(
            mode(&keys_dir.join(format!("{APPROVER_SEED_SEALED}.v1"))),
            0o400
        );
        for (sealed, public, seed) in [
            (
                ROOT_SEED_SEALED.to_string(),
                ROOT_PUBLIC_KEY_FILE.to_string(),
                &root_seed,
            ),
            (
                APPROVER_SEED_SEALED.to_string(),
                APPROVER_PUBLIC_KEY_FILE.to_string(),
                &approver_seed,
            ),
            (
                format!("{APPROVER_SEED_SEALED}.v1"),
                format!("{APPROVER_PUBLIC_KEY_FILE}.v1"),
                &retired_seed,
            ),
        ] {
            assert_eq!(
                *open_sealed_seed(&keys_dir.join(&sealed), OPERATOR).unwrap(),
                **seed
            );
            assert_eq!(
                read_public_key(&keys_dir.join(&public)).unwrap(),
                keypair(seed).unwrap().public_key().to_bytes()
            );
        }
        assert_eq!(
            require_custody(dir.path(), KeyModeArgs::default()).unwrap(),
            KeyCustody::Sealed
        );
        // Idempotent: a second run finds nothing plaintext and says so.
        seal_keys(dir.path(), &pass_source(Some(OPERATOR))).unwrap();
    }

    #[test]
    fn a_minted_grant_is_one_use_short_lived_and_passes_the_daemons_binding_verifier() {
        let approver = keypair(&random_seed()).unwrap();
        let public_key = approver.public_key().to_bytes();
        let (policy, request, audience) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32]);
        let now = now_ms();
        let expires_at = now + DEFAULT_APPROVAL_EXPIRES_IN_SECS * 1_000;
        let grant = mint_one_use_grant(&approver, policy, request, audience, expires_at).unwrap();
        let again = mint_one_use_grant(&approver, policy, request, audience, expires_at).unwrap();
        assert_ne!(
            grant.nonce, again.nonce,
            "every grant carries a fresh random nonce"
        );
        assert_ne!(
            grant.nonce, [4u8; 32],
            "not the fixture minter's constant nonce"
        );
        assert_eq!(grant.max_usages, Some(1));
        assert_eq!(grant.counter, 1);
        assert_eq!(grant.expires_at, expires_at);
        assert_eq!(
            (grant.policy_hash, grant.request_hash, grant.audience),
            (policy, request, audience)
        );

        // The signer tuple the daemon compares against the independently resolved authority,
        // built here from the PUBLIC key alone (what `approver.pub` holds).
        let authority = approval_authority_from_public_key(&public_key).unwrap();
        assert_eq!(grant.authority_id, authority.authority_id);
        assert_eq!(grant.approver_public_key, authority.public_key);
        assert_eq!(grant.approver_suite, authority.signature_suite);

        // The daemon's own grant verifier (authorize_deployment_grant → verify_wallet_approval_
        // grant_binding): structural verify, Ed25519 signature, expiry, exact hashes.
        let value = serde_json::to_value(&grant).unwrap();
        let policy_ref = format!("sha256:{}", hex::encode(policy));
        let request_ref = format!("sha256:{}", hex::encode(request));
        let binding = verify_wallet_approval_grant_binding(
            &value,
            Some(now),
            Some(&policy_ref),
            Some(&request_ref),
        )
        .unwrap();
        assert!(binding
            .grant_ref
            .starts_with("wallet.network://grant/approval/"));
        let other = format!("sha256:{}", hex::encode([0x44u8; 32]));
        assert!(verify_wallet_approval_grant_binding(
            &value,
            Some(now),
            Some(&other),
            Some(&request_ref)
        )
        .is_err());
        assert!(verify_wallet_approval_grant_binding(
            &value,
            Some(now),
            Some(&policy_ref),
            Some(&other)
        )
        .is_err());
        assert!(
            verify_wallet_approval_grant_binding(
                &value,
                Some(expires_at + 1),
                Some(&policy_ref),
                Some(&request_ref)
            )
            .is_err(),
            "an expired grant is refused"
        );
        let mut forged = value.clone();
        forged["audience"] = serde_json::to_value([0x55u8; 32]).unwrap();
        assert!(
            verify_wallet_approval_grant_binding(
                &forged,
                Some(now),
                Some(&policy_ref),
                Some(&request_ref)
            )
            .is_err(),
            "a field changed after signing breaks the signature"
        );
        // Neither the grant nor its JSON carries the seed.
        let text = value.to_string();
        assert!(!text.contains("seed") && !text.contains("private"));
    }

    #[test]
    fn challenge_hashes_parse_in_both_forms_and_the_audience_only_bare() {
        let hex64 = "ab".repeat(32);
        assert_eq!(parse_hash32(&hex64, "h").unwrap(), [0xab; 32]);
        assert_eq!(
            parse_hash32(&format!("sha256:{hex64}"), "h").unwrap(),
            [0xab; 32]
        );
        assert!(parse_hash32("abcd", "h").is_err());
        assert_eq!(parse_account32(&hex64, "a").unwrap(), [0xab; 32]);
        assert!(parse_account32(&format!("sha256:{hex64}"), "a").is_err());
    }

    #[test]
    fn scrubbing_overwrites_the_value_in_place_before_it_is_unset() {
        let name = "IOI_WALLET_AUTHORITY_SCRUB_TEST_ONLY";
        std::env::set_var(name, "scrub-me-please");
        scrub_environment_block(name);
        assert_eq!(
            std::env::var(name).as_deref(),
            Ok(""),
            "the value bytes are overwritten"
        );
        std::env::remove_var(name);
        assert!(std::env::var_os(name).is_none());
    }
}
