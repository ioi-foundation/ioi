// Path: crates/cli/src/commands/config.rs

use anyhow::Result;
use clap::{Parser, Subcommand};
use ioi_types::config::{
    CommitmentSchemeType, ConsensusType, ConnectorConfig, InferenceConfig, InitialServiceConfig,
    OrchestrationConfig, RpcHardeningConfig, StateTreeType, ValidatorRole, VmFuelCosts,
    WorkloadConfig, ZkConfig,
};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct ConfigCmdArgs {
    #[clap(subcommand)]
    pub command: ConfigSubCommands,
}

#[derive(Subcommand, Debug)]
pub enum ConfigSubCommands {
    /// Generate a pair of orchestration.toml and workload.toml.
    New {
        #[clap(long, default_value = ".")]
        out_dir: PathBuf,
        #[clap(long, default_value = "1")]
        chain_id: u32,
    },
}

pub fn run(args: ConfigCmdArgs) -> Result<()> {
    match args.command {
        ConfigSubCommands::New { out_dir, chain_id } => {
            fs::create_dir_all(&out_dir)?;

            let orch_cfg = OrchestrationConfig {
                chain_id: chain_id.into(),
                config_schema_version: 1,
                validator_role: ValidatorRole::Consensus,
                consensus_type: ConsensusType::Admft,
                rpc_listen_address: "127.0.0.1:8545".into(),
                rpc_hardening: RpcHardeningConfig::default(),
                initial_sync_timeout_secs: 5,
                block_production_interval_secs: 1,
                round_robin_view_timeout_secs: 20,
                default_query_gas_limit: 1_000_000,
                ibc_gateway_listen_address: Some("127.0.0.1:9876".into()),
                safety_model_path: None,
                tokenizer_path: None,
            };

            let mut connectors = std::collections::HashMap::new();
            connectors.insert(
                "openai_primary".to_string(),
                ConnectorConfig {
                    enabled: true,
                    key_ref: "openai".to_string(),
                },
            );

            let workload_cfg = WorkloadConfig {
                runtimes: vec!["wasm".into()],
                state_tree: StateTreeType::IAVL,
                commitment_scheme: CommitmentSchemeType::Hash,
                consensus_type: ConsensusType::Admft,
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
                inference: InferenceConfig::default(),
                fast_inference: None,
                reasoning_inference: None,
                connectors,
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