// Path: crates/cli/src/commands/init.rs

use anyhow::{anyhow, Result};
use clap::Parser;
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
pub struct InitArgs {
    /// Name of the project.
    pub name: String,
    /// Chain ID for the new project.
    #[clap(long, default_value = "1")]
    pub chain_id: u32,
}

pub fn run(args: InitArgs) -> Result<()> {
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
ioi = {{ git = "https://github.com/ioi-foundation/ioi" }}
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