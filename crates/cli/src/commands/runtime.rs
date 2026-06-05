use super::model_mount_http::{daemon_request, print_value};
use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use reqwest::Method;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct RuntimeArgs {
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
    pub command: RuntimeCommands,
}

#[derive(Subcommand, Debug)]
pub enum RuntimeCommands {
    /// Submit trigger-required sparse L1 settlement attempts to the daemon.
    L1Settlement {
        #[clap(subcommand)]
        command: L1SettlementCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum L1SettlementCommands {
    /// Admit a settlement attempt through the daemon-mounted Rust trigger guard.
    Admit(L1SettlementAdmitArgs),
}

#[derive(Args, Debug)]
pub struct L1SettlementAdmitArgs {
    /// Runtime thread id that owns the admission request.
    pub thread_id: String,

    /// Settlement attempt JSON object.
    #[clap(long, conflicts_with = "attempt_file")]
    pub attempt_json: Option<String>,

    /// Path to a settlement attempt JSON file.
    #[clap(long, conflicts_with = "attempt_json")]
    pub attempt_file: Option<PathBuf>,
}

pub async fn run(args: RuntimeArgs) -> Result<()> {
    let endpoint = args.endpoint.as_deref();
    let token = args.token.as_deref();
    let value = match args.command {
        RuntimeCommands::L1Settlement { command } => match command {
            L1SettlementCommands::Admit(admit_args) => {
                let attempt = parse_json_input(
                    admit_args.attempt_json.as_deref(),
                    admit_args.attempt_file.as_ref(),
                    "L1 settlement attempt",
                )?;
                daemon_request(
                    endpoint,
                    token,
                    Method::POST,
                    &l1_settlement_attempts_route(&admit_args.thread_id),
                    Some(l1_settlement_admission_body(attempt)),
                )
                .await?
            }
        },
    };
    print_value(&value, args.json)
}

pub(crate) fn l1_settlement_attempts_route(thread_id: &str) -> String {
    format!(
        "/v1/threads/{}/l1-settlement-attempts",
        encode_path_segment(thread_id)
    )
}

fn l1_settlement_admission_body(attempt: Value) -> Value {
    json!({
        "source": "cli_client",
        "attempt": attempt,
    })
}

fn parse_json_input(inline: Option<&str>, file: Option<&PathBuf>, label: &str) -> Result<Value> {
    match (inline, file) {
        (Some(_), Some(_)) => Err(anyhow!(
            "{label} accepts either --attempt-json or --attempt-file, not both."
        )),
        (Some(value), None) => serde_json::from_str(value)
            .with_context(|| format!("{label} JSON argument must be a JSON object.")),
        (None, Some(path)) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {label} JSON from {}", path.display()))?;
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "{label} file must contain a JSON object: {}",
                    path.display()
                )
            })
        }
        (None, None) => Err(anyhow!(
            "{label} requires --attempt-json or --attempt-file."
        )),
    }
    .and_then(|value: Value| {
        if value.is_object() {
            Ok(value)
        } else {
            Err(anyhow!("{label} must be a JSON object."))
        }
    })
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(*byte))
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l1_settlement_route_encodes_thread_id() {
        assert_eq!(
            l1_settlement_attempts_route("thread/with spaces"),
            "/v1/threads/thread%2Fwith%20spaces/l1-settlement-attempts"
        );
    }

    #[test]
    fn l1_settlement_body_is_cli_admission_only() -> Result<()> {
        let attempt = serde_json::json!({
            "schema_version": "ioi.l1_settlement_admission.v1",
            "settlement_ref": "l1://settlement/cli",
            "trigger_refs": ["l1-trigger://operator"],
            "receipt_refs": ["receipt://local-settlement/cli"]
        });
        let body = l1_settlement_admission_body(attempt);

        assert_eq!(
            body.get("source"),
            Some(&Value::String("cli_client".to_string()))
        );
        assert!(body.get("attempt").is_some());
        assert!(body.get("settlement_admitted").is_none());
        assert!(body.get("accepted_receipt_append").is_none());
        Ok(())
    }
}
