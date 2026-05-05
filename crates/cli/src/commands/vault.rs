use super::model_mount_http::{daemon_request, print_value};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use reqwest::Method;
use serde_json::{json, Value};
use std::io::Read;

#[derive(Parser, Debug)]
pub struct VaultArgs {
    /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
    #[clap(long)]
    pub endpoint: Option<String>,

    /// Capability token. Defaults to IOI_DAEMON_TOKEN.
    #[clap(long)]
    pub token: Option<String>,

    /// Emit machine-readable JSON.
    #[clap(long)]
    pub json: bool,

    #[clap(subcommand)]
    pub command: VaultCommands,
}

#[derive(Subcommand, Debug)]
pub enum VaultCommands {
    /// Bind local runtime material to a wallet.network vault ref.
    Set {
        #[clap(long)]
        vault_ref: String,
        #[clap(long)]
        material: Option<String>,
        #[clap(long)]
        material_env: Option<String>,
        #[clap(long)]
        material_stdin: bool,
        #[clap(long, default_value = "operator_provider_auth_binding")]
        purpose: String,
        #[clap(long)]
        label: Option<String>,
    },
    /// List redacted local vault binding metadata.
    Ls,
    /// Show the active vault material adapter mode.
    Status,
    /// Inspect one vault ref's redacted metadata.
    GetMeta {
        #[clap(long)]
        vault_ref: String,
    },
    /// Remove local runtime material for a vault ref.
    Rm {
        #[clap(long)]
        vault_ref: String,
    },
}

pub async fn run(args: VaultArgs) -> Result<()> {
    let endpoint = args.endpoint.as_deref();
    let token = args.token.as_deref();
    let value = match args.command {
        VaultCommands::Set {
            vault_ref,
            material,
            material_env,
            material_stdin,
            purpose,
            label,
        } => {
            let material = resolve_material(material, material_env, material_stdin)?;
            daemon_request(
                endpoint,
                token,
                Method::POST,
                "/api/v1/vault/refs",
                Some(json!({
                    "vault_ref": vault_ref,
                    "material": material,
                    "purpose": purpose,
                    "label": label
                })),
            )
            .await?
        }
        VaultCommands::Ls => {
            daemon_request(endpoint, token, Method::GET, "/api/v1/vault/refs", None).await?
        }
        VaultCommands::Status => {
            let projection = daemon_request(
                endpoint,
                token,
                Method::GET,
                "/api/v1/projections/model-mounting",
                None,
            )
            .await?;
            vault_status_from_projection(&projection)
        }
        VaultCommands::GetMeta { vault_ref } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                "/api/v1/vault/refs/meta",
                Some(json!({ "vault_ref": vault_ref })),
            )
            .await?
        }
        VaultCommands::Rm { vault_ref } => {
            daemon_request(
                endpoint,
                token,
                Method::DELETE,
                "/api/v1/vault/refs",
                Some(json!({ "vault_ref": vault_ref })),
            )
            .await?
        }
    };
    print_value(&value, args.json)
}

fn vault_status_from_projection(projection: &Value) -> Value {
    let vault = projection
        .pointer("/adapterBoundaries/vault")
        .cloned()
        .unwrap_or(Value::Null);
    let material_adapter = vault
        .pointer("/materialAdapter")
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "port": vault.pointer("/port").cloned().unwrap_or(Value::Null),
        "implementation": vault.pointer("/implementation").cloned().unwrap_or(Value::Null),
        "materialAdapter": material_adapter,
        "materialSources": vault.pointer("/materialSources").cloned().unwrap_or(Value::Null),
        "remoteAdapter": vault.pointer("/remoteAdapter").cloned().unwrap_or(Value::Null),
        "evidenceRefs": vault.pointer("/evidenceRefs").cloned().unwrap_or(Value::Null)
    })
}

fn resolve_material(
    material: Option<String>,
    material_env: Option<String>,
    material_stdin: bool,
) -> Result<String> {
    let sources =
        material.iter().count() + material_env.iter().count() + usize::from(material_stdin);
    if sources != 1 {
        return Err(anyhow!(
            "provide exactly one of --material, --material-env, or --material-stdin"
        ));
    }
    if let Some(material) = material {
        return Ok(material);
    }
    if let Some(name) = material_env {
        return std::env::var(&name)
            .with_context(|| format!("environment variable '{}' was not set", name));
    }
    let mut buffer = String::new();
    std::io::stdin()
        .read_to_string(&mut buffer)
        .context("failed to read vault material from stdin")?;
    Ok(buffer
        .trim_end_matches(|c| c == '\r' || c == '\n')
        .to_string())
}
