// Path: crates/cli/src/main.rs
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

//! # IOI Kernel CLI
//!
//! The primary developer toolchain for building, testing, and interacting with IOI chains.

use anyhow::Result;
use clap::{Parser, Subcommand};

// Import command modules
mod commands;
mod util;

use commands::*;

#[derive(Parser, Debug)]
#[clap(
    name = "cli",
    version,
    about = "The IOI CLI (the management interface for the IOI Kernel).",
    long_about = "CLI provides tools for scaffolding chains, managing keys, running local devnets, and interacting with the IOI network."
)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    // --- Core Workflow ---
    /// Initialize a new IOI Kernel project structure.
    Init(init::InitArgs),

    /// Scaffold new components (services, contracts).
    Scaffold(scaffold::ScaffoldArgs),

    /// Inspect, validate, and materialize Chat artifact packages.
    Artifact(artifact::ArtifactArgs),

    // --- Devnet ---
    /// Runs a local, single-node chain for development.
    Node(node::NodeArgs),

    /// Compiles and runs the project's test suite.
    Test(test_cmd::TestArgs),

    // --- Tools ---
    /// Manage cryptographic keys and identities (Classical & PQC).
    Keys(keys::KeysArgs),

    /// Generate and validate node configurations.
    Config(config::ConfigCmdArgs),

    /// Query a running node's state or status.
    Query(query::QueryArgs),

    /// Manage model registry artifacts, mounts, loads, and loaded instances.
    Models(models::ModelsArgs),

    /// Manage local and provider-backed model backend runtimes.
    Backends(backends::BackendsArgs),

    /// Manage model routing policies.
    Routes(routes::RoutesArgs),

    /// Probe or control the local model server surface.
    Server(server::ServerArgs),

    /// Manage local capability tokens for model and MCP access.
    Tokens(tokens::TokensArgs),

    /// Inspect Agentgres model, route, tool, workflow, and token receipts.
    Receipts(receipts::ReceiptsArgs),

    /// Interact with the local Desktop Agent (Jarvis Mode).
    Agent(agent::AgentArgs),

    /// Visualize agent execution traces.
    Trace(trace::TraceArgs),

    /// Verify determinism-boundary evidence artifacts.
    Verify(verify::VerifyArgs),

    /// Policy management tools.
    Policy(policy::PolicyArgs),

    /// Manage and inspect configured MCP servers.
    Mcp(mcp::McpArgs),

    /// PII review tools.
    Pii(pii::PiiArgs),

    /// [NEW] Ghost Mode Tools
    Ghost {
        #[clap(subcommand)]
        command: ghost::GhostCommands,
    },

    /// [NEW] Developer tools (Injection, Debugging).
    Dev(dev::DevArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize basic logging for CLI output
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    match cli.command {
        // --- Init & Scaffold ---
        Commands::Init(args) => init::run(args),
        Commands::Scaffold(args) => scaffold::run(args),
        Commands::Artifact(args) => artifact::run(args).await,

        // --- Keys ---
        Commands::Keys(args) => keys::run(args),

        // --- Config ---
        Commands::Config(args) => config::run(args),

        // --- Node (Devnet) ---
        Commands::Node(args) => node::run(args).await,

        // --- Test ---
        Commands::Test(args) => test_cmd::run(args),

        // --- Query ---
        Commands::Query(args) => query::run(args).await,

        // --- Model mounting ---
        Commands::Models(args) => models::run(args).await,
        Commands::Backends(args) => backends::run(args).await,
        Commands::Routes(args) => routes::run(args).await,
        Commands::Server(args) => server::run(args).await,
        Commands::Tokens(args) => tokens::run(args).await,
        Commands::Receipts(args) => receipts::run(args).await,

        // --- Agent ---
        Commands::Agent(args) => agent::run(args).await,

        // --- Trace ---
        Commands::Trace(args) => trace::run(args).await,

        // --- Verify ---
        Commands::Verify(args) => verify::run(args).await,

        // --- Policy ---
        Commands::Policy(args) => policy::run(args).await,

        // --- MCP ---
        Commands::Mcp(args) => mcp::run(args).await,

        // --- PII ---
        Commands::Pii(args) => pii::run(args).await,

        // --- Ghost ---
        Commands::Ghost { command } => ghost::run(command).await,

        // --- Dev ---
        Commands::Dev(args) => dev::run(args).await,
    }
}
