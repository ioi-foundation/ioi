// M05.8 — the CLI thin client for PolicyBoundDataView.
//
// A PASS-THROUGH, NOT A CHECKER. `ioi policy-bound-data-view {admit,query,materialize}` serializes a
// body, adds the caller's own bearer token, hits ONE of the two native owner routes, and prints the
// daemon's JSON verbatim. Every admission and materialization decision is made in
// the daemon's PolicyBoundDataView owner module — this file resolves no policy, reinterprets no refusal
// code, and grants no authority. It holds a TOKEN, never a principal, so it cannot choose a tenant or
// author a server-resolved field; the daemon refuses those regardless of which client sent them.
//
// WHY NOT `model_mount_http::daemon_request`: that shared helper collapses a non-2xx body into an
// anyhow error string, which would DISCARD the typed refusal envelope this client exists to surface
// unchanged. So the request is issued here and the body is printed byte-for-byte on every status; a
// non-2xx status yields a nonzero exit with the refusal JSON already on stdout.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use reqwest::Method;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
pub struct PolicyBoundDataViewArgs {
    /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
    #[clap(long)]
    pub endpoint: Option<String>,

    /// Bearer token (a session token or a `pat_*` API token). Defaults to IOI_DAEMON_TOKEN.
    /// The token IS the principal binding — this client never names a principal or tenant itself.
    #[clap(long)]
    pub token: Option<String>,

    #[clap(subcommand)]
    pub command: PolicyBoundDataViewCommands,
}

#[derive(Subcommand, Debug)]
pub enum PolicyBoundDataViewCommands {
    /// Admit one immutable view revision. The body is the exact admission request the native route
    /// expects; every binding is resolved server-side through its owner seam.
    Admit {
        /// Path to a JSON body, or `-` to read the body from stdin.
        #[clap(long, default_value = "-")]
        file: PathBuf,
    },
    /// Read the caller's own view inventory, one family, or one exact revision.
    Query {
        /// A family token; omit to list the inventory of families the caller is authorized on.
        #[clap(long)]
        family: Option<String>,
        /// An exact revision ordinal within `--family`.
        #[clap(long)]
        revision: Option<u64>,
    },
    /// Ask for a bounded projection. THE DAEMON decides whether a descriptor is granted; a refused
    /// decision is still admitted to the chain as evidence and printed here unchanged.
    Materialize {
        /// Path to a JSON body, or `-` to read the body from stdin.
        #[clap(long, default_value = "-")]
        file: PathBuf,
    },
}

const VIEWS: &str = "/v1/hypervisor/policy-bound-data-views";
const MATERIALIZATIONS: &str = "/v1/hypervisor/policy-bound-data-view-materializations";

fn read_body(file: &PathBuf) -> Result<Value> {
    let raw = if file.as_os_str() == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read the request body from stdin")?;
        buf
    } else {
        std::fs::read_to_string(file)
            .with_context(|| format!("failed to read the request body from {}", file.display()))?
    };
    serde_json::from_str(&raw).with_context(|| {
        "the request body is not valid JSON; this client sends it to the daemon unmodified"
    })
}

/// Issue one request and print the daemon's JSON body verbatim, whatever the status.
///
/// The body is NEVER reinterpreted: a refusal `code` reaches the operator exactly as the owner route
/// wrote it. A non-2xx status returns an error so the process exits nonzero, but the terse message
/// names only the status — the typed refusal is already on stdout.
async fn forward(
    endpoint: Option<&str>,
    token: Option<&str>,
    method: Method,
    route: &str,
    query: &[(String, String)],
    body: Option<Value>,
) -> Result<()> {
    let endpoint = endpoint
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("IOI_DAEMON_ENDPOINT").ok())
        .unwrap_or_else(|| "http://127.0.0.1:8765".to_string());
    let url = format!("{}{}", endpoint.trim_end_matches('/'), route);
    let token = token
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("IOI_DAEMON_TOKEN").ok());

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build()
        .context("failed to build local IOI daemon HTTP client")?;
    let mut request = client
        .request(method, &url)
        .header("accept", "application/json")
        .query(query);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("failed to call local IOI daemon at {url}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .with_context(|| format!("failed to read the local IOI daemon response from {url}"))?;

    // The body is printed exactly as received. If it parses as JSON we pretty-print it; if the daemon
    // ever returned non-JSON we still emit the raw bytes rather than swallow them.
    match serde_json::from_str::<Value>(&text) {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
        Err(_) => println!("{text}"),
    }

    if !status.is_success() {
        // No code translation: the refusal is on stdout above. This only sets the exit status.
        return Err(anyhow!(
            "daemon responded {} — the typed response body is printed above",
            status.as_u16()
        ));
    }
    Ok(())
}

pub async fn run(args: PolicyBoundDataViewArgs) -> Result<()> {
    let endpoint = args.endpoint.as_deref();
    let token = args.token.as_deref();
    match args.command {
        PolicyBoundDataViewCommands::Admit { file } => {
            let body = read_body(&file)?;
            forward(endpoint, token, Method::POST, VIEWS, &[], Some(body)).await
        }
        PolicyBoundDataViewCommands::Query { family, revision } => {
            let mut query: Vec<(String, String)> = Vec::new();
            if let Some(family) = family {
                query.push(("family".to_string(), family));
            }
            if let Some(revision) = revision {
                query.push(("revision".to_string(), revision.to_string()));
            }
            forward(endpoint, token, Method::GET, VIEWS, &query, None).await
        }
        PolicyBoundDataViewCommands::Materialize { file } => {
            let body = read_body(&file)?;
            forward(
                endpoint,
                token,
                Method::POST,
                MATERIALIZATIONS,
                &[],
                Some(body),
            )
            .await
        }
    }
}
