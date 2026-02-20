// Path: crates/cli/src/commands/dev.rs

use crate::util::create_cli_tx;
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{GetTransactionStatusRequest, SubmitTransactionRequest};
use ioi_types::app::agentic::{AgentMacro, LlmToolDefinition};
use ioi_types::app::{
    ActionContext, ActionRequest, ActionTarget, MailConnectorAuthMode, MailConnectorConfig,
    MailConnectorEndpoint, MailConnectorProvider, MailConnectorSecretAliases, MailConnectorTlsMode,
    MailConnectorUpsertParams, SecretKind, SystemPayload, VaultSecretRecord,
};
use ioi_types::codec;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::transport::Channel;

const MAIL_E2E_DEFAULT_MAILBOX: &str = "primary";
const MAIL_E2E_DEFAULT_IMAP_USERNAME_ALIAS: &str = "mail.imap.username";
const MAIL_E2E_DEFAULT_IMAP_PASSWORD_ALIAS: &str = "mail.imap.password";
const MAIL_E2E_DEFAULT_IMAP_BEARER_TOKEN_ALIAS: &str = "mail.imap.bearer_token";
const MAIL_E2E_DEFAULT_SMTP_USERNAME_ALIAS: &str = "mail.smtp.username";
const MAIL_E2E_DEFAULT_SMTP_PASSWORD_ALIAS: &str = "mail.smtp.password";
const MAIL_E2E_DEFAULT_SMTP_BEARER_TOKEN_ALIAS: &str = "mail.smtp.bearer_token";
const MAIL_E2E_DEFAULT_IMAP_USERNAME_SECRET_ID: &str = "mail-imap-username";
const MAIL_E2E_DEFAULT_IMAP_PASSWORD_SECRET_ID: &str = "mail-imap-password";
const MAIL_E2E_DEFAULT_IMAP_BEARER_TOKEN_SECRET_ID: &str = "mail-imap-bearer-token";
const MAIL_E2E_DEFAULT_SMTP_USERNAME_SECRET_ID: &str = "mail-smtp-username";
const MAIL_E2E_DEFAULT_SMTP_PASSWORD_SECRET_ID: &str = "mail-smtp-password";
const MAIL_E2E_DEFAULT_SMTP_BEARER_TOKEN_SECRET_ID: &str = "mail-smtp-bearer-token";

const MAIL_E2E_KEY_AUTH_MODE: &str = "MAIL_E2E_AUTH_MODE";
const MAIL_E2E_KEY_MAILBOX: &str = "MAIL_E2E_MAILBOX";
const MAIL_E2E_KEY_ACCOUNT_EMAIL: &str = "MAIL_E2E_ACCOUNT_EMAIL";
const MAIL_E2E_KEY_IMAP_HOST: &str = "MAIL_E2E_IMAP_HOST";
const MAIL_E2E_KEY_IMAP_PORT: &str = "MAIL_E2E_IMAP_PORT";
const MAIL_E2E_KEY_IMAP_TLS_MODE: &str = "MAIL_E2E_IMAP_TLS_MODE";
const MAIL_E2E_KEY_SMTP_HOST: &str = "MAIL_E2E_SMTP_HOST";
const MAIL_E2E_KEY_SMTP_PORT: &str = "MAIL_E2E_SMTP_PORT";
const MAIL_E2E_KEY_SMTP_TLS_MODE: &str = "MAIL_E2E_SMTP_TLS_MODE";
const MAIL_E2E_KEY_IMAP_USERNAME: &str = "MAIL_E2E_IMAP_USERNAME";
const MAIL_E2E_KEY_IMAP_PASSWORD: &str = "MAIL_E2E_IMAP_PASSWORD";
const MAIL_E2E_KEY_IMAP_BEARER_TOKEN: &str = "MAIL_E2E_IMAP_BEARER_TOKEN";
const MAIL_E2E_KEY_SMTP_USERNAME: &str = "MAIL_E2E_SMTP_USERNAME";
const MAIL_E2E_KEY_SMTP_PASSWORD: &str = "MAIL_E2E_SMTP_PASSWORD";
const MAIL_E2E_KEY_SMTP_BEARER_TOKEN: &str = "MAIL_E2E_SMTP_BEARER_TOKEN";
const MAIL_E2E_KEY_IMAP_USERNAME_ALIAS: &str = "MAIL_E2E_IMAP_USERNAME_ALIAS";
const MAIL_E2E_KEY_IMAP_PASSWORD_ALIAS: &str = "MAIL_E2E_IMAP_PASSWORD_ALIAS";
const MAIL_E2E_KEY_IMAP_BEARER_TOKEN_ALIAS: &str = "MAIL_E2E_IMAP_BEARER_TOKEN_ALIAS";
const MAIL_E2E_KEY_SMTP_USERNAME_ALIAS: &str = "MAIL_E2E_SMTP_USERNAME_ALIAS";
const MAIL_E2E_KEY_SMTP_PASSWORD_ALIAS: &str = "MAIL_E2E_SMTP_PASSWORD_ALIAS";
const MAIL_E2E_KEY_SMTP_BEARER_TOKEN_ALIAS: &str = "MAIL_E2E_SMTP_BEARER_TOKEN_ALIAS";
const MAIL_E2E_KEY_IMAP_USERNAME_SECRET_ID: &str = "MAIL_E2E_IMAP_USERNAME_SECRET_ID";
const MAIL_E2E_KEY_IMAP_PASSWORD_SECRET_ID: &str = "MAIL_E2E_IMAP_PASSWORD_SECRET_ID";
const MAIL_E2E_KEY_IMAP_BEARER_TOKEN_SECRET_ID: &str = "MAIL_E2E_IMAP_BEARER_TOKEN_SECRET_ID";
const MAIL_E2E_KEY_SMTP_USERNAME_SECRET_ID: &str = "MAIL_E2E_SMTP_USERNAME_SECRET_ID";
const MAIL_E2E_KEY_SMTP_PASSWORD_SECRET_ID: &str = "MAIL_E2E_SMTP_PASSWORD_SECRET_ID";
const MAIL_E2E_KEY_SMTP_BEARER_TOKEN_SECRET_ID: &str = "MAIL_E2E_SMTP_BEARER_TOKEN_SECRET_ID";

#[derive(Parser, Debug)]
pub struct DevArgs {
    #[clap(subcommand)]
    pub command: DevCommands,

    #[clap(long, default_value = "127.0.0.1:9000")]
    pub rpc: String,
}

#[derive(Subcommand, Debug)]
pub enum DevCommands {
    /// Inject a raw skill JSON into the node's SCS.
    InjectSkill { file: PathBuf },

    /// Bootstrap wallet mail connector + secret aliases from local env file.
    BootstrapMail {
        #[clap(long, default_value = ".env.mail-e2e.local")]
        env_file: PathBuf,
    },
}

#[derive(serde::Deserialize)]
struct HumanSkill {
    name: String,
    description: String,
    steps: Vec<HumanStep>,
}

#[derive(serde::Deserialize)]
struct HumanStep {
    tool: String,
    params: serde_json::Value,
}

struct LocalMailBootstrapConfig {
    auth_mode: MailConnectorAuthMode,
    mailbox: String,
    account_email: String,
    imap_host: String,
    imap_port: u16,
    imap_tls_mode: MailConnectorTlsMode,
    smtp_host: String,
    smtp_port: u16,
    smtp_tls_mode: MailConnectorTlsMode,
    imap_username_alias: String,
    imap_secret_alias: String,
    smtp_username_alias: String,
    smtp_secret_alias: String,
    imap_username_secret_id: String,
    imap_secret_secret_id: String,
    smtp_username_secret_id: String,
    smtp_secret_secret_id: String,
    imap_username: String,
    imap_secret: String,
    smtp_username: String,
    smtp_secret: String,
}

struct LocalMailSecretSpec {
    secret_id: String,
    alias: String,
    value: String,
}

pub async fn run(args: DevArgs) -> Result<()> {
    match args.command {
        DevCommands::InjectSkill { file } => run_inject_skill(&args.rpc, file).await,
        DevCommands::BootstrapMail { env_file } => run_bootstrap_mail(&args.rpc, env_file).await,
    }
}

async fn run_inject_skill(rpc: &str, file: PathBuf) -> Result<()> {
    let json = std::fs::read_to_string(&file)
        .with_context(|| format!("Failed to read skill file '{}'", file.display()))?;
    let human: HumanSkill = serde_json::from_str(&json).context("Failed to parse skill JSON")?;

    let mut steps = Vec::new();
    for step in human.steps {
        let target = match step.tool.as_str() {
            "sys__exec" => ActionTarget::SysExec,
            "agent__complete" => ActionTarget::Custom("agent__complete".into()),
            other => ActionTarget::Custom(other.to_string()),
        };

        let params = serde_json::to_vec(&step.params)?;
        steps.push(ActionRequest {
            target,
            params,
            context: ActionContext {
                agent_id: "macro".into(),
                session_id: None,
                window_id: None,
            },
            nonce: 0,
        });
    }

    let skill = AgentMacro {
        definition: LlmToolDefinition {
            name: human.name,
            description: human.description,
            parameters: r#"{"type":"object"}"#.into(),
        },
        steps,
        source_trace_hash: [0; 32],
        fitness: 1.0,
    };

    let params_bytes = codec::to_bytes_canonical(&skill)
        .map_err(|e| anyhow!("Failed to encode AgentMacro: {}", e))?;
    let payload = SystemPayload::CallService {
        service_id: "optimizer".to_string(),
        method: "import_skill@v1".to_string(),
        params: params_bytes,
    };

    let keypair = ioi_crypto::sign::eddsa::Ed25519KeyPair::generate()
        .map_err(|e| anyhow!("Failed to generate keypair: {}", e))?;
    let tx = create_cli_tx(&keypair, payload, 0);

    let mut client = connect_public_client(rpc).await?;
    let tx_hash = submit_tx_and_wait(&mut client, &tx).await?;
    println!(
        "Skill '{}' injected. tx_hash={}",
        skill.definition.name, tx_hash
    );
    Ok(())
}

async fn run_bootstrap_mail(rpc: &str, env_file: PathBuf) -> Result<()> {
    let env_path = resolve_env_file_path(&env_file)?;
    let env_map = parse_env_file(&env_path)?;
    let config = parse_mail_bootstrap_config(&env_map)?;
    let secret_specs = build_secret_specs(&config);

    let keypair = ioi_crypto::sign::eddsa::Ed25519KeyPair::generate()
        .map_err(|e| anyhow!("Failed to generate keypair: {}", e))?;
    let mut client = connect_public_client(rpc).await?;
    let mut nonce: u64 = 0;
    let now_ms = now_ms();

    for spec in &secret_specs {
        let record = VaultSecretRecord {
            secret_id: spec.secret_id.clone(),
            alias: spec.alias.clone(),
            kind: SecretKind::AccessToken,
            ciphertext: spec.value.as_bytes().to_vec(),
            metadata: BTreeMap::new(),
            created_at_ms: now_ms,
            rotated_at_ms: None,
        };
        let params = codec::to_bytes_canonical(&record)
            .map_err(|e| anyhow!("Failed to encode secret record: {}", e))?;
        let payload = SystemPayload::CallService {
            service_id: "wallet_network".to_string(),
            method: "store_secret_record@v1".to_string(),
            params,
        };
        let tx = create_cli_tx(&keypair, payload, nonce);
        nonce = nonce.saturating_add(1);
        let tx_hash = submit_tx_and_wait(&mut client, &tx).await?;
        println!(
            "Stored secret alias '{}' (secret_id='{}'). tx_hash={}",
            spec.alias, spec.secret_id, tx_hash
        );
    }

    let upsert = MailConnectorUpsertParams {
        mailbox: config.mailbox.clone(),
        config: MailConnectorConfig {
            provider: MailConnectorProvider::ImapSmtp,
            auth_mode: config.auth_mode,
            account_email: config.account_email.clone(),
            imap: MailConnectorEndpoint {
                host: config.imap_host.clone(),
                port: config.imap_port,
                tls_mode: config.imap_tls_mode,
            },
            smtp: MailConnectorEndpoint {
                host: config.smtp_host.clone(),
                port: config.smtp_port,
                tls_mode: config.smtp_tls_mode,
            },
            secret_aliases: MailConnectorSecretAliases {
                imap_username_alias: config.imap_username_alias.clone(),
                imap_password_alias: config.imap_secret_alias.clone(),
                smtp_username_alias: config.smtp_username_alias.clone(),
                smtp_password_alias: config.smtp_secret_alias.clone(),
            },
            metadata: BTreeMap::new(),
        },
    };
    let params = codec::to_bytes_canonical(&upsert)
        .map_err(|e| anyhow!("Failed to encode mail connector config: {}", e))?;
    let payload = SystemPayload::CallService {
        service_id: "wallet_network".to_string(),
        method: "mail_connector_upsert@v1".to_string(),
        params,
    };
    let tx = create_cli_tx(&keypair, payload, nonce);
    let tx_hash = submit_tx_and_wait(&mut client, &tx).await?;

    println!(
        "Mail connector upserted for mailbox='{}' account='{}'. tx_hash={}",
        upsert.mailbox, upsert.config.account_email, tx_hash
    );
    println!(
        "Bootstrap complete from '{}' via CLI.",
        env_path.canonicalize().unwrap_or(env_path).display()
    );
    Ok(())
}

fn resolve_env_file_path(path: &Path) -> Result<PathBuf> {
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("Failed to read current working directory")?
            .join(path)
    };
    if !resolved.is_file() {
        return Err(anyhow!(
            "Env file '{}' does not exist or is not a file",
            resolved.display()
        ));
    }
    Ok(resolved)
}

fn parse_double_quoted_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            match ch {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '\\' => out.push('\\'),
                '"' => out.push('"'),
                _ => out.push(ch),
            }
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
        } else {
            out.push(ch);
        }
    }
    if escaped {
        out.push('\\');
    }
    out
}

fn parse_env_assignment_value(value: &str, line_number: usize) -> Result<String> {
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.starts_with('"') {
        if value.len() < 2 || !value.ends_with('"') {
            return Err(anyhow!(
                "Invalid env line {}: unmatched double quote",
                line_number
            ));
        }
        return Ok(parse_double_quoted_value(&value[1..value.len() - 1]));
    }
    if value.starts_with('\'') {
        if value.len() < 2 || !value.ends_with('\'') {
            return Err(anyhow!(
                "Invalid env line {}: unmatched single quote",
                line_number
            ));
        }
        return Ok(value[1..value.len() - 1].to_string());
    }

    let mut normalized = value.to_string();
    if let Some(comment_idx) = normalized.find(" #") {
        normalized.truncate(comment_idx);
    }
    Ok(normalized.trim().to_string())
}

fn parse_env_file(path: &Path) -> Result<BTreeMap<String, String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read env file '{}'", path.display()))?;
    let mut vars = BTreeMap::new();
    for (idx, raw_line) in content.lines().enumerate() {
        let line_number = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim();
        let (raw_key, raw_value) = line.split_once('=').ok_or_else(|| {
            anyhow!(
                "Invalid env line {}: expected KEY=VALUE assignment",
                line_number
            )
        })?;
        let key = raw_key.trim();
        if key.is_empty() {
            return Err(anyhow!("Invalid env line {}: empty key", line_number));
        }
        let value = parse_env_assignment_value(raw_value.trim(), line_number)?;
        vars.insert(key.to_string(), value);
    }
    Ok(vars)
}

fn required_env_value(map: &BTreeMap<String, String>, key: &str) -> Result<String> {
    map.get(key)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("Missing required env key: {}", key))
}

fn optional_env_value(map: &BTreeMap<String, String>, key: &str, default: &str) -> String {
    map.get(key)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn nonempty_env_value(map: &BTreeMap<String, String>, key: &str) -> Option<String> {
    map.get(key)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_mail_auth_mode_value(raw: &str) -> Result<MailConnectorAuthMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "password" | "pass" => Ok(MailConnectorAuthMode::Password),
        "oauth2" | "xoauth2" | "oauth" => Ok(MailConnectorAuthMode::Oauth2),
        _ => Err(anyhow!(
            "Invalid {} '{}': expected password or oauth2",
            MAIL_E2E_KEY_AUTH_MODE,
            raw
        )),
    }
}

fn parse_mail_auth_mode_env(map: &BTreeMap<String, String>) -> Result<MailConnectorAuthMode> {
    if let Some(raw) = nonempty_env_value(map, MAIL_E2E_KEY_AUTH_MODE) {
        return parse_mail_auth_mode_value(&raw);
    }

    let has_password = nonempty_env_value(map, MAIL_E2E_KEY_IMAP_PASSWORD).is_some()
        || nonempty_env_value(map, MAIL_E2E_KEY_SMTP_PASSWORD).is_some();
    let has_bearer = nonempty_env_value(map, MAIL_E2E_KEY_IMAP_BEARER_TOKEN).is_some()
        || nonempty_env_value(map, MAIL_E2E_KEY_SMTP_BEARER_TOKEN).is_some();
    if has_bearer && !has_password {
        Ok(MailConnectorAuthMode::Oauth2)
    } else {
        Ok(MailConnectorAuthMode::Password)
    }
}

fn parse_required_u16_env(map: &BTreeMap<String, String>, key: &str) -> Result<u16> {
    let raw = required_env_value(map, key)?;
    let port = raw
        .parse::<u16>()
        .with_context(|| format!("Invalid {} '{}'", key, raw))?;
    if port == 0 {
        return Err(anyhow!("Invalid {}: value must be > 0", key));
    }
    Ok(port)
}

fn parse_tls_mode_value(raw: &str, key: &str) -> Result<MailConnectorTlsMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "plaintext" | "plain" => Ok(MailConnectorTlsMode::Plaintext),
        "starttls" | "start_tls" | "start-tls" => Ok(MailConnectorTlsMode::StartTls),
        "tls" | "ssl" => Ok(MailConnectorTlsMode::Tls),
        _ => Err(anyhow!(
            "Invalid {} '{}': expected plaintext, starttls, or tls",
            key,
            raw
        )),
    }
}

fn parse_optional_tls_mode_env(
    map: &BTreeMap<String, String>,
    key: &str,
    default: MailConnectorTlsMode,
) -> Result<MailConnectorTlsMode> {
    let Some(raw) = map
        .get(key)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    else {
        return Ok(default);
    };
    parse_tls_mode_value(raw, key)
}

fn parse_mail_bootstrap_config(map: &BTreeMap<String, String>) -> Result<LocalMailBootstrapConfig> {
    let auth_mode = parse_mail_auth_mode_env(map)?;
    let (
        imap_secret_alias,
        smtp_secret_alias,
        imap_secret_secret_id,
        smtp_secret_secret_id,
        imap_secret,
        smtp_secret,
    ) = match auth_mode {
        MailConnectorAuthMode::Password => (
            optional_env_value(
                map,
                MAIL_E2E_KEY_IMAP_PASSWORD_ALIAS,
                MAIL_E2E_DEFAULT_IMAP_PASSWORD_ALIAS,
            ),
            optional_env_value(
                map,
                MAIL_E2E_KEY_SMTP_PASSWORD_ALIAS,
                MAIL_E2E_DEFAULT_SMTP_PASSWORD_ALIAS,
            ),
            optional_env_value(
                map,
                MAIL_E2E_KEY_IMAP_PASSWORD_SECRET_ID,
                MAIL_E2E_DEFAULT_IMAP_PASSWORD_SECRET_ID,
            ),
            optional_env_value(
                map,
                MAIL_E2E_KEY_SMTP_PASSWORD_SECRET_ID,
                MAIL_E2E_DEFAULT_SMTP_PASSWORD_SECRET_ID,
            ),
            required_env_value(map, MAIL_E2E_KEY_IMAP_PASSWORD)?,
            required_env_value(map, MAIL_E2E_KEY_SMTP_PASSWORD)?,
        ),
        MailConnectorAuthMode::Oauth2 => (
            optional_env_value(
                map,
                MAIL_E2E_KEY_IMAP_BEARER_TOKEN_ALIAS,
                MAIL_E2E_DEFAULT_IMAP_BEARER_TOKEN_ALIAS,
            ),
            optional_env_value(
                map,
                MAIL_E2E_KEY_SMTP_BEARER_TOKEN_ALIAS,
                MAIL_E2E_DEFAULT_SMTP_BEARER_TOKEN_ALIAS,
            ),
            optional_env_value(
                map,
                MAIL_E2E_KEY_IMAP_BEARER_TOKEN_SECRET_ID,
                MAIL_E2E_DEFAULT_IMAP_BEARER_TOKEN_SECRET_ID,
            ),
            optional_env_value(
                map,
                MAIL_E2E_KEY_SMTP_BEARER_TOKEN_SECRET_ID,
                MAIL_E2E_DEFAULT_SMTP_BEARER_TOKEN_SECRET_ID,
            ),
            required_env_value(map, MAIL_E2E_KEY_IMAP_BEARER_TOKEN)?,
            required_env_value(map, MAIL_E2E_KEY_SMTP_BEARER_TOKEN)?,
        ),
    };

    Ok(LocalMailBootstrapConfig {
        auth_mode,
        mailbox: optional_env_value(map, MAIL_E2E_KEY_MAILBOX, MAIL_E2E_DEFAULT_MAILBOX),
        account_email: required_env_value(map, MAIL_E2E_KEY_ACCOUNT_EMAIL)?,
        imap_host: required_env_value(map, MAIL_E2E_KEY_IMAP_HOST)?,
        imap_port: parse_required_u16_env(map, MAIL_E2E_KEY_IMAP_PORT)?,
        imap_tls_mode: parse_optional_tls_mode_env(
            map,
            MAIL_E2E_KEY_IMAP_TLS_MODE,
            MailConnectorTlsMode::Tls,
        )?,
        smtp_host: required_env_value(map, MAIL_E2E_KEY_SMTP_HOST)?,
        smtp_port: parse_required_u16_env(map, MAIL_E2E_KEY_SMTP_PORT)?,
        smtp_tls_mode: parse_optional_tls_mode_env(
            map,
            MAIL_E2E_KEY_SMTP_TLS_MODE,
            MailConnectorTlsMode::StartTls,
        )?,
        imap_username_alias: optional_env_value(
            map,
            MAIL_E2E_KEY_IMAP_USERNAME_ALIAS,
            MAIL_E2E_DEFAULT_IMAP_USERNAME_ALIAS,
        ),
        imap_secret_alias,
        smtp_username_alias: optional_env_value(
            map,
            MAIL_E2E_KEY_SMTP_USERNAME_ALIAS,
            MAIL_E2E_DEFAULT_SMTP_USERNAME_ALIAS,
        ),
        smtp_secret_alias,
        imap_username_secret_id: optional_env_value(
            map,
            MAIL_E2E_KEY_IMAP_USERNAME_SECRET_ID,
            MAIL_E2E_DEFAULT_IMAP_USERNAME_SECRET_ID,
        ),
        imap_secret_secret_id,
        smtp_username_secret_id: optional_env_value(
            map,
            MAIL_E2E_KEY_SMTP_USERNAME_SECRET_ID,
            MAIL_E2E_DEFAULT_SMTP_USERNAME_SECRET_ID,
        ),
        smtp_secret_secret_id,
        imap_username: required_env_value(map, MAIL_E2E_KEY_IMAP_USERNAME)?,
        imap_secret,
        smtp_username: required_env_value(map, MAIL_E2E_KEY_SMTP_USERNAME)?,
        smtp_secret,
    })
}

fn build_secret_specs(config: &LocalMailBootstrapConfig) -> Vec<LocalMailSecretSpec> {
    vec![
        LocalMailSecretSpec {
            secret_id: config.imap_username_secret_id.clone(),
            alias: config.imap_username_alias.clone(),
            value: config.imap_username.clone(),
        },
        LocalMailSecretSpec {
            secret_id: config.imap_secret_secret_id.clone(),
            alias: config.imap_secret_alias.clone(),
            value: config.imap_secret.clone(),
        },
        LocalMailSecretSpec {
            secret_id: config.smtp_username_secret_id.clone(),
            alias: config.smtp_username_alias.clone(),
            value: config.smtp_username.clone(),
        },
        LocalMailSecretSpec {
            secret_id: config.smtp_secret_secret_id.clone(),
            alias: config.smtp_secret_alias.clone(),
            value: config.smtp_secret.clone(),
        },
    ]
}

async fn connect_public_client(rpc: &str) -> Result<PublicApiClient<Channel>> {
    let url = if rpc.starts_with("http://") || rpc.starts_with("https://") {
        rpc.to_string()
    } else {
        format!("http://{}", rpc)
    };
    let channel = Channel::from_shared(url.clone())
        .with_context(|| format!("Invalid RPC URL '{}'", url))?
        .connect()
        .await
        .with_context(|| format!("Failed to connect to RPC '{}'", url))?;
    Ok(PublicApiClient::new(channel))
}

async fn submit_tx_and_wait(
    client: &mut PublicApiClient<Channel>,
    tx: &ioi_types::app::ChainTransaction,
) -> Result<String> {
    let tx_bytes = codec::to_bytes_canonical(tx)
        .map_err(|e| anyhow!("Failed to encode transaction: {}", e))?;
    let submit = client
        .submit_transaction(SubmitTransactionRequest {
            transaction_bytes: tx_bytes,
        })
        .await
        .context("submit_transaction RPC failed")?
        .into_inner();
    let tx_hash = submit.tx_hash;

    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(350)).await;
        let status = client
            .get_transaction_status(GetTransactionStatusRequest {
                tx_hash: tx_hash.clone(),
            })
            .await
            .context("get_transaction_status RPC failed")?
            .into_inner();

        if status.status == 3 {
            return Ok(tx_hash);
        }
        if status.status == 4 {
            if status.error_message.trim().is_empty() {
                return Err(anyhow!("Transaction rejected: {}", tx_hash));
            }
            return Err(anyhow!("Transaction rejected: {}", status.error_message));
        }
    }

    Err(anyhow!(
        "Timed out waiting for tx commit (tx_hash={})",
        tx_hash
    ))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
