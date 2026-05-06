use super::model_mount_http::{daemon_request, print_value};
use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::Method;
use serde_json::{json, Map, Value};

#[derive(Parser, Debug)]
pub struct TokensArgs {
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
    pub command: TokensCommands,
}

#[derive(Subcommand, Debug)]
pub enum TokensCommands {
    /// List redacted capability token grants.
    Ls,
    /// Create a scoped capability token.
    Create {
        #[clap(long, default_value = "autopilot-local-server")]
        audience: String,
        #[clap(long = "allow")]
        allowed: Vec<String>,
        #[clap(long = "deny")]
        denied: Vec<String>,
    },
    /// Revoke a capability token by grant id.
    Revoke { id: String },
    /// Count model input tokens through the daemon tokenizer/context path.
    Count {
        #[clap(long)]
        model: Option<String>,
        #[clap(long)]
        route_id: Option<String>,
        input: String,
    },
}

pub async fn run(args: TokensArgs) -> Result<()> {
    let endpoint = args.endpoint.as_deref();
    let token = args.token.as_deref();
    let value = match args.command {
        TokensCommands::Ls => {
            daemon_request(endpoint, token, Method::GET, "/api/v1/tokens", None).await?
        }
        TokensCommands::Create {
            audience,
            allowed,
            denied,
        } => {
            let mut body = Map::new();
            body.insert("audience".to_string(), json!(audience));
            if !allowed.is_empty() {
                body.insert("allowed".to_string(), json!(allowed));
            }
            if !denied.is_empty() {
                body.insert("denied".to_string(), json!(denied));
            }
            daemon_request(
                endpoint,
                token,
                Method::POST,
                "/api/v1/tokens",
                Some(Value::Object(body)),
            )
            .await?
        }
        TokensCommands::Revoke { id } => {
            daemon_request(
                endpoint,
                token,
                Method::DELETE,
                &format!("/api/v1/tokens/{id}"),
                None,
            )
            .await?
        }
        TokensCommands::Count {
            model,
            route_id,
            input,
        } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                "/api/v1/tokens/count",
                Some(json!({
                    "model": model,
                    "route_id": route_id,
                    "input": input
                })),
            )
            .await?
        }
    };
    print_value(&value, args.json)
}
