use super::model_mount_http::{daemon_request, print_value};
use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::Method;
use serde_json::{json, Map, Value};

#[derive(Parser, Debug)]
pub struct BackendsArgs {
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
    pub command: BackendsCommands,
}

#[derive(Subcommand, Debug)]
pub enum BackendsCommands {
    /// List model backend drivers and runtime state.
    Ls,
    /// Probe backend health and record a lifecycle receipt.
    Health { id: String },
    /// Request backend start through the daemon control path.
    Start { id: String },
    /// Request backend stop through the daemon control path.
    Stop { id: String },
    /// Show recent backend logs.
    Logs { id: String },
    /// Capture a runtime engine and hardware survey through the daemon.
    Survey,
    /// List runtime engines discovered from backend drivers and provider CLIs.
    Engines,
    /// Inspect a runtime engine, its operator profile, and linked receipts.
    EngineGet { engine_id: String },
    /// Select the preferred runtime engine for subsequent loads.
    Select { engine_id: String },
    /// Update a runtime engine operator profile and default load options.
    EngineUpdate {
        engine_id: String,
        #[clap(long)]
        label: Option<String>,
        #[clap(long)]
        priority: Option<i64>,
        #[clap(long)]
        disable: bool,
        #[clap(long)]
        enable: bool,
        #[clap(long)]
        gpu: Option<String>,
        #[clap(long)]
        context_length: Option<u64>,
        #[clap(long)]
        parallel: Option<u64>,
        #[clap(long)]
        ttl_seconds: Option<u64>,
        #[clap(long)]
        identifier: Option<String>,
    },
    /// Forget the operator profile for a runtime engine.
    EngineRemove { engine_id: String },
}

pub async fn run(args: BackendsArgs) -> Result<()> {
    let endpoint = args.endpoint.as_deref();
    let token = args.token.as_deref();
    let value = match args.command {
        BackendsCommands::Ls => {
            daemon_request(endpoint, token, Method::GET, "/api/v1/backends", None).await?
        }
        BackendsCommands::Health { id } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                &format!("/api/v1/backends/{id}/health"),
                None,
            )
            .await?
        }
        BackendsCommands::Start { id } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                &format!("/api/v1/backends/{id}/start"),
                None,
            )
            .await?
        }
        BackendsCommands::Stop { id } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                &format!("/api/v1/backends/{id}/stop"),
                None,
            )
            .await?
        }
        BackendsCommands::Logs { id } => {
            daemon_request(
                endpoint,
                token,
                Method::GET,
                &format!("/api/v1/backends/{id}/logs"),
                None,
            )
            .await?
        }
        BackendsCommands::Survey => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                "/api/v1/runtime/survey",
                None,
            )
            .await?
        }
        BackendsCommands::Engines => {
            daemon_request(
                endpoint,
                token,
                Method::GET,
                "/api/v1/runtime/engines",
                None,
            )
            .await?
        }
        BackendsCommands::EngineGet { engine_id } => {
            daemon_request(
                endpoint,
                token,
                Method::GET,
                &format!("/api/v1/runtime/engines/{engine_id}"),
                None,
            )
            .await?
        }
        BackendsCommands::Select { engine_id } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                "/api/v1/runtime/select",
                Some(json!({ "engine_id": engine_id })),
            )
            .await?
        }
        BackendsCommands::EngineUpdate {
            engine_id,
            label,
            priority,
            disable,
            enable,
            gpu,
            context_length,
            parallel,
            ttl_seconds,
            identifier,
        } => {
            let mut body = Map::new();
            if let Some(label) = label {
                body.insert("label".to_string(), Value::String(label));
            }
            if let Some(priority) = priority {
                body.insert("priority".to_string(), Value::Number(priority.into()));
            }
            if disable {
                body.insert("disabled".to_string(), Value::Bool(true));
            } else if enable {
                body.insert("disabled".to_string(), Value::Bool(false));
            }
            let mut defaults = Map::new();
            if let Some(gpu) = gpu {
                defaults.insert("gpu".to_string(), Value::String(gpu));
            }
            if let Some(context_length) = context_length {
                defaults.insert(
                    "contextLength".to_string(),
                    Value::Number(context_length.into()),
                );
            }
            if let Some(parallel) = parallel {
                defaults.insert("parallel".to_string(), Value::Number(parallel.into()));
            }
            if let Some(ttl_seconds) = ttl_seconds {
                defaults.insert("ttlSeconds".to_string(), Value::Number(ttl_seconds.into()));
            }
            if let Some(identifier) = identifier {
                defaults.insert("identifier".to_string(), Value::String(identifier));
            }
            if !defaults.is_empty() {
                body.insert("defaultLoadOptions".to_string(), Value::Object(defaults));
            }
            daemon_request(
                endpoint,
                token,
                Method::PATCH,
                &format!("/api/v1/runtime/engines/{engine_id}"),
                Some(Value::Object(body)),
            )
            .await?
        }
        BackendsCommands::EngineRemove { engine_id } => {
            daemon_request(
                endpoint,
                token,
                Method::DELETE,
                &format!("/api/v1/runtime/engines/{engine_id}"),
                None,
            )
            .await?
        }
    };
    print_value(&value, args.json)
}
