// Path: crates/cli/src/commands/test_cmd.rs

use anyhow::{anyhow, Result};
use clap::Parser;
use std::process::Stdio;

#[derive(Parser, Debug)]
pub struct TestArgs {
    pub filter: Option<String>,
}

pub fn run(args: TestArgs) -> Result<()> {
    println!("🧪 Running tests via cargo...");
    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("test").arg("-p").arg("ioi-cli");

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
