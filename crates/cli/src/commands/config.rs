// Path: crates/cli/src/commands/config.rs

use anyhow::Result;
use clap::{Parser, Subcommand};
use ioi_types::config::{
    CommitmentSchemeType, ConsensusType, ConnectorConfig, InferenceConfig, InitialServiceConfig,
    OrchestrationConfig, RpcHardeningConfig, StateTreeType, ValidatorRole, VmFuelCosts,
    WorkloadConfig, ZkConfig, McpConfigEntry,
};
use std::fs;
use std::path::PathBuf;
use std::collections::HashMap;

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

            let mut connectors = HashMap::new();
            connectors.insert(
                "openai_primary".to_string(),
                ConnectorConfig {
                    enabled: true,
                    key_ref: "openai".to_string(),
                },
            );

            // [NEW] Default MCP Server Configuration
            let mut mcp_servers = HashMap::new();
            
            // Example: Filesystem MCP
            // This assumes 'npx' is available in the environment.
            // It mounts the current directory as an allowed path.
            mcp_servers.insert(
                "filesystem".to_string(),
                McpConfigEntry {
                    command: "npx".to_string(),
                    args: vec![
                        "-y".to_string(),
                        "@modelcontextprotocol/server-filesystem".to_string(),
                        "./".to_string(), // Allow access to current directory
                    ],
                    env: HashMap::new(),
                }
            );

            // Example: Brave Search MCP (Commented out in logic, but structure ready)
            // Users would need to provide BRAVE_API_KEY in the vault.
            /*
            let mut brave_env = HashMap::new();
            brave_env.insert("BRAVE_API_KEY".to_string(), "env:brave_search_key".to_string());
            mcp_servers.insert(
                "brave_search".to_string(),
                McpConfigEntry {
                    command: "npx".to_string(),
                    args: vec![
                        "-y".to_string(),
                        "@modelcontextprotocol/server-brave-search".to_string(),
                    ],
                    env: brave_env,
                }
            );
            */

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
                mcp_servers,
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
            println!("ℹ️  Edit workload.toml to configure MCP servers.");
            println!("   Default: 'filesystem' MCP server is enabled (via npx).");
        }
    }
    Ok(())
}