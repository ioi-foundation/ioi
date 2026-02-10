// Path: crates/cli/src/commands/scaffold.rs

use crate::util::titlecase;
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
pub struct ScaffoldArgs {
    #[clap(subcommand)]
    pub command: ScaffoldCommands,
}

#[derive(Subcommand, Debug)]
pub enum ScaffoldCommands {
    /// Scaffold a new native Service module.
    Service { name: String },
    /// Scaffold a new WASM Smart Contract.
    Contract { name: String },
}

pub fn run(args: ScaffoldArgs) -> Result<()> {
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
ioi = {{ git = "https://github.com/ioi-foundation/ioi" }}
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
ioi-contract-sdk = {{ git = "https://github.com/ioi-foundation/ioi" }}
"#,
                name
            );
            fs::write(path.join("Cargo.toml"), cargo_toml)?;
            println!("✅ Scaffoled contract: {}", name);
        }
    }
    Ok(())
}
