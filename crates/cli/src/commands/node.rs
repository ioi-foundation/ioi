// Path: crates/cli/src/commands/node.rs

use anyhow::Result;
use clap::{Parser, ValueEnum};
use ioi_cli::{build_test_artifacts, TestCluster};
use ioi_types::{
    app::{
        account_id_from_key_material, ActiveKeyRecord, BlockTimingParams, BlockTimingRuntime,
        SignatureSuite, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    config::InitialServiceConfig,
    service_configs::{GovernanceParams, MigrationConfig},
};
use ioi_api::crypto::SerializableKey;
use tokio::signal;

#[derive(Clone, Debug, ValueEnum)]
pub enum ConsensusMode {
    Poa,
    Pos,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum TreeType {
    Iavl,
    Smt,
    Verkle,
    Jellyfish,
}

#[derive(Parser, Debug)]
pub struct NodeArgs {
    /// Port for the JSON-RPC API of the first validator.
    #[clap(long, default_value = "8545")]
    pub port: u16,

    /// Number of validators to spin up.
    #[clap(long, default_value = "1")]
    pub validators: usize,

    /// The consensus engine to use.
    #[clap(long, value_enum, default_value = "poa")]
    pub consensus: ConsensusMode,

    /// The state tree backend to use.
    #[clap(long, value_enum, default_value = "iavl")]
    pub tree: TreeType,

    /// Block time in seconds.
    #[clap(long, default_value = "1")]
    pub block_time: u64,

    /// Disable block production (for debugging).
    #[clap(long)]
    pub no_mine: bool,
}

pub async fn run(args: NodeArgs) -> Result<()> {
    println!("🔨 Building necessary artifacts (contracts, services)...");
    build_test_artifacts();

    println!("🚀 Starting local development cluster...");
    println!("   • Validators: {}", args.validators);
    println!("   • Consensus:  {:?}", args.consensus);
    println!("   • State Tree: {:?}", args.tree);

    let consensus_str = match args.consensus {
        ConsensusMode::Poa => "Admft",
        ConsensusMode::Pos => "ProofOfStake",
    };

    let (tree_str, commitment_str) = match args.tree {
        TreeType::Iavl => ("IAVL", "Hash"),
        TreeType::Smt => ("SparseMerkle", "Hash"),
        TreeType::Verkle => ("Verkle", "KZG"),
        TreeType::Jellyfish => ("Jellyfish", "Hash"),
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
            allowed_target_suites: vec![SignatureSuite::ED25519],
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
                        suite: SignatureSuite::ED25519,
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
        let acc_bytes = account_id_from_key_material(SignatureSuite::ED25519, &pk).unwrap();

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
                    res = orch_logs.recv() => {
                        match res {
                            Ok(line) => println!("[{}|ORCH] {}", prefix, line),
                            Err(_) => break,
                        }
                    }
                    res = work_logs.recv() => {
                        match res {
                            Ok(line) => println!("[{}|WORK] {}", prefix, line),
                            Err(_) => break,
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