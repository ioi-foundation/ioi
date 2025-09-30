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

//! # DePIN SDK Forge CLI
//!
//! This is the command-line interface for `forge`, the primary developer
//! tool for building, testing, and deploying on the DePIN SDK.
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[clap(name = "forge", version, about = "A development toolkit for the DePIN SDK.", long_about = None)]
struct ForgeCli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Runs a local, single-node chain for development and testing.
    /// This node is optimized for speed and developer experience, not for
    /// production security or decentralization.
    Node(NodeArgs),

    /// Compiles and runs smart contract and system-level tests.
    /// This command will use the helpers in the `depin-sdk-forge` library
    /// to orchestrate test runs against a local development node.
    Test(TestArgs),
    // Future commands can be added here, for example:
    // /// Compiles smart contracts to their WASM target.
    // Build(BuildArgs),
    // /// Deploys a smart contract to a specified network.
    // Deploy(DeployArgs),
}

#[derive(Parser, Debug)]
struct NodeArgs {
    #[clap(long, default_value = "8545")]
    port: u16,
    #[clap(long)]
    no_mine: bool,
}

#[derive(Parser, Debug)]
struct TestArgs {
    /// Optional: only run tests that match this filter.
    filter: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = ForgeCli::parse();

    match cli.command {
        Commands::Node(args) => {
            println!("Starting local development node on port {}...", args.port);
            // Placeholder: Here you would implement the logic to start a
            // lightweight, single-instance version of the DePIN node, likely
            // using an instant-seal or round-robin consensus engine.
        }
        Commands::Test(args) => {
            println!("Running tests with filter: {:?}...", args.filter);
            // Placeholder: Here you would implement the test runner logic.
            // This would likely involve:
            // 1. Spawning a local node using the `forge::testing` helpers.
            // 2. Discovering and running tests against it.
            // 3. Reporting results.
        }
    }

    Ok(())
}
