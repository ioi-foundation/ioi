use super::model_mount_http::{daemon_request, print_value};
use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::Method;
use serde_json::json;

#[derive(Parser, Debug)]
pub struct ModelsArgs {
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
    pub command: ModelsCommands,
}

#[derive(Subcommand, Debug)]
pub enum ModelsCommands {
    /// List registry artifacts, endpoints, instances, providers, routes, and receipts.
    Ls,
    /// Inspect one model artifact by artifact id or model id.
    Get { id: String },
    /// Import a model artifact into the registry.
    Import {
        model_id: String,
        #[clap(long)]
        provider_id: Option<String>,
        #[clap(long)]
        path: Option<String>,
    },
    /// Create a model download job through the daemon lifecycle path.
    Download {
        model_id: String,
        #[clap(long)]
        provider_id: Option<String>,
        #[clap(long)]
        source_url: Option<String>,
        #[clap(long)]
        queued_only: bool,
    },
    /// Cancel a queued or running model download job.
    CancelDownload { job_id: String },
    /// Mount a model endpoint.
    Mount {
        model_id: String,
        #[clap(long)]
        id: Option<String>,
        #[clap(long)]
        provider_id: Option<String>,
    },
    /// Load a mounted endpoint or model id.
    Load {
        #[clap(long)]
        endpoint_id: Option<String>,
        #[clap(long)]
        model_id: Option<String>,
        #[clap(long, default_value = "on_demand")]
        mode: String,
        #[clap(long, default_value_t = 900)]
        idle_ttl_seconds: u64,
    },
    /// Unload a model instance or endpoint.
    Unload {
        #[clap(long)]
        instance_id: Option<String>,
        #[clap(long)]
        endpoint_id: Option<String>,
        #[clap(long)]
        model_id: Option<String>,
    },
    /// List loaded model instances.
    Ps,
    /// List models discovered by a provider driver.
    ProviderModels { provider_id: String },
    /// List loaded models observed by a provider driver.
    ProviderLoaded { provider_id: String },
    /// Create or update a provider profile.
    ProviderSet {
        #[clap(long)]
        id: String,
        #[clap(long)]
        kind: String,
        #[clap(long)]
        label: Option<String>,
        #[clap(long)]
        api_format: Option<String>,
        #[clap(long)]
        base_url: Option<String>,
        #[clap(long)]
        status: Option<String>,
        #[clap(long)]
        privacy_class: Option<String>,
        #[clap(long, value_delimiter = ',')]
        capabilities: Vec<String>,
        /// Wallet vault reference for provider auth material. Raw keys are rejected by the daemon.
        #[clap(long)]
        secret_ref: Option<String>,
        /// Provider auth scheme: bearer, api_key, or raw.
        #[clap(long)]
        auth_scheme: Option<String>,
        /// Provider auth header name, such as authorization or x-api-key.
        #[clap(long)]
        auth_header_name: Option<String>,
    },
}

pub async fn run(args: ModelsArgs) -> Result<()> {
    let endpoint = args.endpoint.as_deref();
    let token = args.token.as_deref();
    let value = match args.command {
        ModelsCommands::Ls => {
            daemon_request(endpoint, token, Method::GET, "/api/v1/models", None).await?
        }
        ModelsCommands::Get { id } => {
            daemon_request(
                endpoint,
                token,
                Method::GET,
                &format!("/api/v1/models/{id}"),
                None,
            )
            .await?
        }
        ModelsCommands::Import {
            model_id,
            provider_id,
            path,
        } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                "/api/v1/models/import",
                Some(json!({ "model_id": model_id, "provider_id": provider_id, "path": path })),
            )
            .await?
        }
        ModelsCommands::Download {
            model_id,
            provider_id,
            source_url,
            queued_only,
        } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                "/api/v1/models/download",
                Some(json!({
                    "model_id": model_id,
                    "provider_id": provider_id,
                    "source_url": source_url,
                    "queued_only": queued_only
                })),
            )
            .await?
        }
        ModelsCommands::CancelDownload { job_id } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                &format!("/api/v1/models/download/{job_id}/cancel"),
                None,
            )
            .await?
        }
        ModelsCommands::Mount {
            model_id,
            id,
            provider_id,
        } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                "/api/v1/models/mount",
                Some(json!({ "id": id, "model_id": model_id, "provider_id": provider_id })),
            )
            .await?
        }
        ModelsCommands::Load {
            endpoint_id,
            model_id,
            mode,
            idle_ttl_seconds,
        } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                "/api/v1/models/load",
                Some(json!({
                    "endpoint_id": endpoint_id,
                    "model_id": model_id,
                    "load_policy": {
                        "mode": mode,
                        "idleTtlSeconds": idle_ttl_seconds,
                        "autoEvict": true
                    }
                })),
            )
            .await?
        }
        ModelsCommands::Unload {
            instance_id,
            endpoint_id,
            model_id,
        } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                "/api/v1/models/unload",
                Some(json!({
                    "instance_id": instance_id,
                    "endpoint_id": endpoint_id,
                    "model_id": model_id
                })),
            )
            .await?
        }
        ModelsCommands::Ps => {
            daemon_request(endpoint, token, Method::GET, "/api/v1/models/loaded", None).await?
        }
        ModelsCommands::ProviderModels { provider_id } => {
            daemon_request(
                endpoint,
                token,
                Method::GET,
                &format!("/api/v1/providers/{provider_id}/models"),
                None,
            )
            .await?
        }
        ModelsCommands::ProviderLoaded { provider_id } => {
            daemon_request(
                endpoint,
                token,
                Method::GET,
                &format!("/api/v1/providers/{provider_id}/loaded"),
                None,
            )
            .await?
        }
        ModelsCommands::ProviderSet {
            id,
            kind,
            label,
            api_format,
            base_url,
            status,
            privacy_class,
            capabilities,
            secret_ref,
            auth_scheme,
            auth_header_name,
        } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                "/api/v1/providers",
                Some(json!({
                    "id": id,
                    "kind": kind,
                    "label": label,
                    "api_format": api_format,
                    "base_url": base_url,
                    "status": status,
                    "privacy_class": privacy_class,
                    "capabilities": capabilities,
                    "secret_ref": secret_ref,
                    "auth_scheme": auth_scheme,
                    "auth_header_name": auth_header_name
                })),
            )
            .await?
        }
    };
    print_value(&value, args.json)
}
