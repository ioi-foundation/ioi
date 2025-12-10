// Path: crates/forge/src/main.rs
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo,
        clippy::indexing_slicing
    )
)]

//! # IOI SDK Forge CLI
//!
//! The primary developer toolchain for building, testing, and interacting with IOI chains.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_crypto::sign::{dilithium::DilithiumScheme, eddsa::Ed25519KeyPair};
use ioi_forge::{build_test_artifacts, TestCluster};
use ioi_types::{
    app::{
        account_id_from_key_material, ActiveKeyRecord, BlockTimingParams, BlockTimingRuntime,
        SignatureSuite, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    config::{
        CommitmentSchemeType, ConsensusType, InitialServiceConfig, OrchestrationConfig,
        RpcHardeningConfig, StateTreeType, ValidatorRole, VmFuelCosts, WorkloadConfig, ZkConfig,
    },
    service_configs::{GovernanceParams, MigrationConfig},
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::signal;

#[derive(Parser, Debug)]
#[clap(
    name = "forge",
    version,
    about = "The IOI SDK Developer Toolchain",
    long_about = "Forge provides tools for scaffolding chains, managing keys, running local devnets, and interacting with the IOI network."
)]
struct ForgeCli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    // --- Core Workflow ---
    /// Initialize a new IOI SDK project structure.
    Init(InitArgs),

    /// Scaffold new components (services, contracts).
    Scaffold(ScaffoldArgs),

    // --- Devnet ---
    /// Runs a local, single-node chain for development.
    Node(NodeArgs),

    /// Compiles and runs the project's test suite.
    Test(TestArgs),

    // --- Tools ---
    /// Manage cryptographic keys and identities (Classical & PQC).
    Keys(KeysArgs),

    /// Generate and validate node configurations.
    Config(ConfigCmdArgs),

    /// Query a running node's state or status.
    Query(QueryArgs),
}

// -----------------------------------------------------------------------------
// Argument Structs
// -----------------------------------------------------------------------------

#[derive(Parser, Debug)]
struct InitArgs {
    /// Name of the project.
    name: String,
    /// Chain ID for the new project.
    #[clap(long, default_value = "1")]
    chain_id: u32,
}

#[derive(Parser, Debug)]
struct ScaffoldArgs {
    #[clap(subcommand)]
    command: ScaffoldCommands,
}

#[derive(Subcommand, Debug)]
enum ScaffoldCommands {
    /// Scaffold a new native Service module.
    Service { name: String },
    /// Scaffold a new WASM Smart Contract.
    Contract { name: String },
}

#[derive(Clone, Debug, ValueEnum)]
enum ConsensusMode {
    Poa,
    Pos,
}

#[derive(Clone, Debug, ValueEnum)]
enum TreeType {
    Iavl,
    Smt,
    Verkle,
}

#[derive(Parser, Debug)]
struct NodeArgs {
    /// Port for the JSON-RPC API of the first validator.
    #[clap(long, default_value = "8545")]
    port: u16,

    /// Number of validators to spin up.
    #[clap(long, default_value = "1")]
    validators: usize,

    /// The consensus engine to use.
    #[clap(long, value_enum, default_value = "poa")]
    consensus: ConsensusMode,

    /// The state tree backend to use.
    #[clap(long, value_enum, default_value = "iavl")]
    tree: TreeType,

    /// Block time in seconds.
    #[clap(long, default_value = "1")]
    block_time: u64,

    /// Disable block production (for debugging).
    #[clap(long)]
    no_mine: bool,
}

#[derive(Parser, Debug)]
struct TestArgs {
    filter: Option<String>,
}

#[derive(Parser, Debug)]
struct KeysArgs {
    #[clap(subcommand)]
    command: KeysCommands,
}

#[derive(Subcommand, Debug)]
enum KeysCommands {
    /// Generate a new keypair.
    Generate {
        #[clap(long, value_enum, default_value = "ed25519")]
        suite: KeySuite,
    },
    /// Inspect a public key (hex) to derive its Account ID.
    Inspect {
        #[clap(long, value_enum, default_value = "ed25519")]
        suite: KeySuite,
        hex_key: String,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum KeySuite {
    Ed25519,
    Dilithium2,
}

#[derive(Parser, Debug)]
struct ConfigCmdArgs {
    #[clap(subcommand)]
    command: ConfigSubCommands,
}

#[derive(Subcommand, Debug)]
enum ConfigSubCommands {
    /// Generate a pair of orchestration.toml and workload.toml.
    New {
        #[clap(long, default_value = ".")]
        out_dir: PathBuf,
        #[clap(long, default_value = "1")]
        chain_id: u32,
    },
}

#[derive(Parser, Debug)]
struct QueryArgs {
    /// The RPC address of the node.
    #[clap(long, default_value = "127.0.0.1:8555")]
    ipc_addr: String,

    #[clap(subcommand)]
    command: QueryCommands,
}

#[derive(Subcommand, Debug)]
enum QueryCommands {
    /// Get the current chain status.
    Status,
    /// Query a raw state key (hex).
    State { key: String },
}

// -----------------------------------------------------------------------------
// Logic Implementation
// -----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = ForgeCli::parse();

    // Initialize basic logging for CLI output
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    match cli.command {
        // --- Init & Scaffold ---
        Commands::Init(args) => run_init(args),
        Commands::Scaffold(args) => run_scaffold(args),

        // --- Keys ---
        Commands::Keys(args) => run_keys(args),

        // --- Config ---
        Commands::Config(args) => run_config(args),

        // --- Node (Devnet) ---
        Commands::Node(args) => run_node(args).await,

        // --- Test ---
        Commands::Test(args) => run_test(args),

        // --- Query ---
        Commands::Query(args) => run_query(args).await,
    }
}

// -----------------------------------------------------------------------------
// Scaffolding Handlers
// -----------------------------------------------------------------------------

fn run_init(args: InitArgs) -> Result<()> {
    let root = Path::new(&args.name);
    if root.exists() {
        return Err(anyhow!("Directory '{}' already exists", args.name));
    }

    fs::create_dir(root)?;
    fs::create_dir(root.join("services"))?;
    fs::create_dir(root.join("contracts"))?;
    fs::create_dir(root.join("config"))?;

    // Generate Cargo.toml
    let cargo_toml = format!(
        r#"[workspace]
resolver = "2"
members = ["services/*", "contracts/*"]

[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[dependencies]
ioi-sdk = {{ git = "https://github.com/ioi-foundation/ioi-sdk" }}
"#,
        args.name
    );
    fs::write(root.join("Cargo.toml"), cargo_toml)?;

    println!("✅ Initialized new IOI project: {}", args.name);
    println!("   📂 services/  (Native modules)");
    println!("   📂 contracts/ (WASM contracts)");
    println!("   📂 config/    (Chain configuration)");
    Ok(())
}

fn run_scaffold(args: ScaffoldArgs) -> Result<()> {
    match args.command {
        ScaffoldCommands::Service { name } => {
            let path = Path::new("services").join(&name);
            if path.exists() {
                return Err(anyhow!("Service '{}' already exists", name));
            }
            fs::create_dir_all(path.join("src"))?;

            let lib_rs = format!(
                r#"use ioi_sdk::prelude::*;
use ioi_sdk::macros::service_interface;

pub struct {0}Service;

#[service_interface(
    id = "{1}",
    abi_version = 1,
    state_schema = "v1",
    capabilities = ""
)]
impl {0}Service {{
    #[method]
    pub fn do_something(&self, state: &mut dyn StateAccess, ctx: &TxContext) -> Result<(), String> {{
        // Implementation
        Ok(())
    }}
}}
"#,
                titlecase(&name),
                name.to_lowercase()
            );
            fs::write(path.join("src/lib.rs"), lib_rs)?;

            let cargo_toml = format!(
                r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[dependencies]
ioi-sdk = {{ git = "https://github.com/ioi-foundation/ioi-sdk" }}
"#,
                name
            );
            fs::write(path.join("Cargo.toml"), cargo_toml)?;
            println!("✅ Scaffoled service: {}", name);
        }
        ScaffoldCommands::Contract { name } => {
            let path = Path::new("contracts").join(&name);
            fs::create_dir_all(path.join("src"))?;

            let lib_rs = format!(
                r#"#![no_std]
extern crate alloc;
use ioi_contract_sdk::{{ioi_contract, IoiService}};
use alloc::string::String;
use alloc::vec::Vec;

struct {0}Contract;

#[ioi_contract]
impl IoiService for {0}Contract {{
    fn id() -> String {{ "{1}".into() }}
    fn abi_version() -> u32 {{ 1 }}
    fn state_schema() -> String {{ "v1".into() }}
    fn manifest() -> String {{ String::new() }}

    fn handle_service_call(method: String, params: Vec<u8>) -> Result<Vec<u8>, String> {{
        Ok(Vec::new())
    }}
}}
"#,
                titlecase(&name),
                name.to_lowercase()
            );
            fs::write(path.join("src/lib.rs"), lib_rs)?;
            let cargo_toml = format!(
                r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
ioi-contract-sdk = {{ git = "https://github.com/ioi-foundation/ioi-sdk" }}
"#,
                name
            );
            fs::write(path.join("Cargo.toml"), cargo_toml)?;
            println!("✅ Scaffoled contract: {}", name);
        }
    }
    Ok(())
}

fn titlecase(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

// -----------------------------------------------------------------------------
// Keys Handlers
// -----------------------------------------------------------------------------

fn run_keys(args: KeysArgs) -> Result<()> {
    match args.command {
        KeysCommands::Generate { suite } => {
            match suite {
                KeySuite::Ed25519 => {
                    let kp =
                        Ed25519KeyPair::generate().map_err(|e| anyhow!("Gen failed: {}", e))?;
                    let pub_bytes = kp.public_key().to_bytes();
                    let pk_hex = hex::encode(&pub_bytes);
                    // Convert to libp2p encoding for AccountID derivation to match system
                    let libp2p_pk =
                        libp2p::identity::ed25519::PublicKey::try_from_bytes(&pub_bytes).unwrap();
                    let proto_pk = libp2p::identity::PublicKey::from(libp2p_pk).encode_protobuf();

                    let acct =
                        account_id_from_key_material(SignatureSuite::Ed25519, &proto_pk).unwrap();

                    println!("--- New Ed25519 Identity ---");
                    println!(
                        "Private Key (Seed): {}",
                        hex::encode(kp.private_key().as_bytes())
                    );
                    println!("Public Key:         {}", pk_hex);
                    println!("Account ID:         0x{}", hex::encode(acct));
                }
                KeySuite::Dilithium2 => {
                    let kp = DilithiumScheme::new(ioi_crypto::security::SecurityLevel::Level2)
                        .generate_keypair()
                        .map_err(|e| anyhow!("PQC Gen failed: {}", e))?;
                    let pk_bytes = kp.public_key().to_bytes();
                    let acct = account_id_from_key_material(SignatureSuite::Dilithium2, &pk_bytes)
                        .unwrap();

                    println!("--- New Dilithium2 (PQC) Identity ---");
                    println!(
                        "Public Key ({} bytes): {}",
                        pk_bytes.len(),
                        hex::encode(&pk_bytes)
                    );
                    println!("Account ID:            0x{}", hex::encode(acct));
                }
            }
        }
        KeysCommands::Inspect { suite, hex_key } => {
            let bytes = hex::decode(&hex_key).context("Invalid hex")?;
            match suite {
                KeySuite::Ed25519 => {
                    // For Ed25519, we must wrap in libp2p protobuf to match system derivation
                    let libp2p_pk = libp2p::identity::ed25519::PublicKey::try_from_bytes(&bytes)
                        .context("Invalid Ed25519 key bytes")?;
                    let proto_pk = libp2p::identity::PublicKey::from(libp2p_pk).encode_protobuf();
                    let acct = account_id_from_key_material(SignatureSuite::Ed25519, &proto_pk)?;
                    println!("Account ID: 0x{}", hex::encode(acct));
                }
                KeySuite::Dilithium2 => {
                    let acct = account_id_from_key_material(SignatureSuite::Dilithium2, &bytes)?;
                    println!("Account ID: 0x{}", hex::encode(acct));
                }
            }
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Config Handler
// -----------------------------------------------------------------------------

fn run_config(args: ConfigCmdArgs) -> Result<()> {
    match args.command {
        ConfigSubCommands::New { out_dir, chain_id } => {
            fs::create_dir_all(&out_dir)?;

            let orch_cfg = OrchestrationConfig {
                chain_id: chain_id.into(),
                config_schema_version: 1,
                validator_role: ValidatorRole::Consensus,
                consensus_type: ConsensusType::ProofOfAuthority,
                rpc_listen_address: "127.0.0.1:8545".into(),
                rpc_hardening: RpcHardeningConfig::default(),
                initial_sync_timeout_secs: 5,
                block_production_interval_secs: 1,
                round_robin_view_timeout_secs: 20,
                default_query_gas_limit: 1_000_000,
                ibc_gateway_listen_address: Some("127.0.0.1:9876".into()),
            };

            let workload_cfg = WorkloadConfig {
                runtimes: vec!["wasm".into()],
                state_tree: StateTreeType::IAVL,
                commitment_scheme: CommitmentSchemeType::Hash,
                consensus_type: ConsensusType::ProofOfAuthority,
                genesis_file: "./genesis.json".into(),
                state_file: "./data/state.db".into(),
                srs_file_path: None,
                fuel_costs: VmFuelCosts::default(),
                initial_services: vec![],
                service_policies: ioi_types::config::default_service_policies(),
                min_finality_depth: 100,
                keep_recent_heights: 10_000,
                epoch_size: 5000,
                gc_interval_secs: 3600,
                zk_config: ZkConfig::default(),
            };

            fs::write(
                out_dir.join("orchestration.toml"),
                toml::to_string_pretty(&orch_cfg)?,
            )?;
            fs::write(
                out_dir.join("workload.toml"),
                toml::to_string_pretty(&workload_cfg)?,
            )?;

            println!("✅ Generated config files in {}", out_dir.display());
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Node (Devnet) Handler
// -----------------------------------------------------------------------------

async fn run_node(args: NodeArgs) -> Result<()> {
    println!("🔨 Building necessary artifacts (contracts, services)...");
    build_test_artifacts();

    println!("🚀 Starting local development cluster...");
    println!("   • Validators: {}", args.validators);
    println!("   • Consensus:  {:?}", args.consensus);
    println!("   • State Tree: {:?}", args.tree);

    let consensus_str = match args.consensus {
        ConsensusMode::Poa => "ProofOfAuthority",
        ConsensusMode::Pos => "ProofOfStake",
    };

    let (tree_str, commitment_str) = match args.tree {
        TreeType::Iavl => ("IAVL", "Hash"),
        TreeType::Smt => ("SparseMerkle", "Hash"),
        TreeType::Verkle => ("Verkle", "KZG"),
    };

    let cluster = TestCluster::builder()
        .with_validators(args.validators)
        .with_chain_id(1337)
        .with_consensus_type(consensus_str)
        .with_state_tree(tree_str)
        .with_commitment_scheme(commitment_str)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1337,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_initial_service(InitialServiceConfig::Governance(GovernanceParams::default()))
        .with_genesis_modifier(move |builder, keys| {
            let mut validators = Vec::new();
            let weight = match args.consensus {
                ConsensusMode::Poa => 1,
                ConsensusMode::Pos => 1_000_000,
            };

            for key in keys {
                let account_id = builder.add_identity(key);
                let acct_hash = account_id.0;
                validators.push(ValidatorV1 {
                    account_id,
                    weight,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::Ed25519,
                        public_key_hash: acct_hash,
                        since_height: 0,
                    },
                });
            }
            validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

            let vs = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: validators.iter().map(|v| v.weight).sum(),
                    validators,
                },
                next: None,
            };
            builder.set_validators(&vs);

            let timing_params = BlockTimingParams {
                base_interval_secs: args.block_time,
                min_interval_secs: 1,
                max_interval_secs: args.block_time * 5,
                target_gas_per_block: 10_000_000,
                retarget_every_blocks: 0,
                ..Default::default()
            };
            let timing_runtime = BlockTimingRuntime {
                effective_interval_secs: args.block_time,
                ema_gas_used: 0,
            };
            builder.set_block_timing(&timing_params, &timing_runtime);
        })
        .build()
        .await?;

    println!("\n✅ Cluster is ready!");
    println!("---------------------------------------------------------");
    for (i, guard) in cluster.validators.iter().enumerate() {
        let v = guard.validator();
        let pk = v.keypair.public().encode_protobuf();
        let acc_bytes = account_id_from_key_material(SignatureSuite::Ed25519, &pk).unwrap();

        println!("Node {}:", i);
        println!("  RPC:       http://{}", v.rpc_addr);
        println!("  P2P:       {}", v.p2p_addr);
        println!("  Account:   0x{}", hex::encode(acc_bytes));
    }
    println!("---------------------------------------------------------");
    println!("Logs follow below. Press Ctrl+C to stop.\n");

    for guard in &cluster.validators {
        let (mut orch_logs, mut work_logs, _) = guard.validator().subscribe_logs();
        let prefix = format!(
            "Node{:?}",
            guard
                .validator()
                .p2p_addr
                .to_string()
                .split('/')
                .last()
                .unwrap_or("?")
        );

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // [FIX] Gracefully handle closed channels
                    res = orch_logs.recv() => {
                        match res {
                            Ok(line) => println!("[{}|ORCH] {}", prefix, line),
                            Err(_) => break, // Channel closed, exit loop
                        }
                    }
                    res = work_logs.recv() => {
                        match res {
                            Ok(line) => println!("[{}|WORK] {}", prefix, line),
                            Err(_) => break, // Channel closed, exit loop
                        }
                    }
                }
            }
        });
    }

    signal::ctrl_c().await?;
    println!("\n🛑 Shutting down cluster...");
    cluster.shutdown().await?;
    println!("Bye!");
    Ok(())
}

// -----------------------------------------------------------------------------
// Test Handler
// -----------------------------------------------------------------------------

fn run_test(args: TestArgs) -> Result<()> {
    println!("🧪 Running tests via cargo...");
    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("test").arg("-p").arg("ioi-forge");

    if let Some(filter) = args.filter {
        cmd.arg("--").arg(filter);
    }

    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let status = cmd
        .status()
        .map_err(|e| anyhow!("Failed to execute cargo test: {}", e))?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Query Handler
// -----------------------------------------------------------------------------

async fn run_query(args: QueryArgs) -> Result<()> {
    // Note: In a real scenario we'd use the TLS certs, but for dev CLI we might
    // need a simpler HTTP client if the node exposes a public non-mTLS port.
    // For now, we assume the user points to the Orchestrator's PUBLIC RPC port (e.g. 8545).
    // The WorkloadClient struct is designed for mTLS internal comms.
    // We need a PublicClient or direct gRPC via ioi-ipc::public.

    use ioi_ipc::public::public_api_client::PublicApiClient;

    let channel = tonic::transport::Channel::from_shared(format!("http://{}", args.ipc_addr))?
        .connect()
        .await
        .context("Failed to connect to node RPC")?;

    let mut client = PublicApiClient::new(channel);

    match args.command {
        QueryCommands::Status => {
            let req = ioi_ipc::blockchain::GetStatusRequest {};
            let status = client.get_status(req).await?.into_inner();
            println!("Chain Status:");
            println!("  Height: {}", status.height);
            println!("  Timestamp: {}", status.latest_timestamp);
            println!("  Tx Count: {}", status.total_transactions);
            println!("  Running: {}", status.is_running);
        }
        QueryCommands::State { key } => {
            let key_bytes = hex::decode(key).context("Invalid hex key")?;
            let req = ioi_ipc::blockchain::QueryRawStateRequest { key: key_bytes };
            let resp = client.query_raw_state(req).await?.into_inner();

            if resp.found {
                println!("Value (Hex): {}", hex::encode(&resp.value));
                if let Ok(s) = String::from_utf8(resp.value) {
                    println!("Value (UTF8): {}", s);
                }
            } else {
                println!("Key not found.");
            }
        }
    }

    Ok(())
}
