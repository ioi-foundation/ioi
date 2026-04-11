// Path: crates/cli/src/commands/dev.rs

use crate::util::create_cli_tx;
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use ioi_crypto::algorithms::hash::sha256;
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{GetTransactionStatusRequest, SubmitTransactionRequest};
use ioi_services::agentic::runtime::keys::{
    get_skill_doc_key, get_skill_record_key, SKILL_DOC_INDEX_KEY,
};
use ioi_services::agentic::skill_registry::{
    render_skill_markdown, skill_doc_relative_path, SKILL_DOC_GENERATOR_VERSION,
};
use ioi_types::app::agentic::{
    AgentMacro, ExternalSkillEvidence, LlmToolDefinition, PublishedSkillDoc, SkillCatalogIndex,
    SkillLifecycleState, SkillRecord,
};
use ioi_types::app::{
    ActionContext, ActionRequest, ActionTarget, ConnectorAuthProtocol, ConnectorAuthRecord,
    ConnectorAuthState, ConnectorAuthUpsertParams, MailConnectorAuthMode, MailConnectorConfig,
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
const MAIL_E2E_KEY_PROVIDER_DRIVER: &str = "MAIL_E2E_PROVIDER_DRIVER";

#[derive(Parser, Debug)]
pub struct DevArgs {
    #[clap(subcommand)]
    pub command: DevCommands,

    #[clap(long, default_value = "127.0.0.1:9000")]
    pub rpc: String,
}

#[derive(Subcommand, Debug)]
pub enum DevCommands {
    /// Inject a raw skill JSON into the node's local skill archive.
    InjectSkill { file: PathBuf },

    /// Ingest normalized external evidence and synthesize a candidate executable skill.
    IngestSkillEvidence { file: PathBuf },

    /// Export promoted generated skill docs from chain state to a local directory.
    ExportSkillDocs {
        #[clap(long, default_value = "docs")]
        out_dir: PathBuf,
    },

    /// Verify exported skill docs match the promoted state-backed publications exactly.
    VerifySkillDocs {
        #[clap(long, default_value = "docs")]
        out_dir: PathBuf,
    },

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
    provider_driver: Option<String>,
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
    kind: SecretKind,
}

struct PublishedSkillBundle {
    record: SkillRecord,
    doc: PublishedSkillDoc,
}

pub async fn run(args: DevArgs) -> Result<()> {
    match args.command {
        DevCommands::InjectSkill { file } => run_inject_skill(&args.rpc, file).await,
        DevCommands::IngestSkillEvidence { file } => {
            run_ingest_skill_evidence(&args.rpc, file).await
        }
        DevCommands::ExportSkillDocs { out_dir } => run_export_skill_docs(&args.rpc, out_dir).await,
        DevCommands::VerifySkillDocs { out_dir } => run_verify_skill_docs(&args.rpc, out_dir).await,
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
            "shell__run" => ActionTarget::SysExec,
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

async fn run_ingest_skill_evidence(rpc: &str, file: PathBuf) -> Result<()> {
    let json = std::fs::read_to_string(&file)
        .with_context(|| format!("Failed to read evidence file '{}'", file.display()))?;
    let evidence: ExternalSkillEvidence =
        serde_json::from_str(&json).context("Failed to parse external skill evidence JSON")?;

    let params_bytes = codec::to_bytes_canonical(&evidence)
        .map_err(|e| anyhow!("Failed to encode ExternalSkillEvidence: {}", e))?;
    let payload = SystemPayload::CallService {
        service_id: "optimizer".to_string(),
        method: "ingest_skill_evidence@v1".to_string(),
        params: params_bytes,
    };

    let keypair = ioi_crypto::sign::eddsa::Ed25519KeyPair::generate()
        .map_err(|e| anyhow!("Failed to generate keypair: {}", e))?;
    let tx = create_cli_tx(&keypair, payload, 0);

    let mut client = connect_public_client(rpc).await?;
    let tx_hash = submit_tx_and_wait(&mut client, &tx).await?;
    println!(
        "Ingested external evidence from '{}' via tx_hash={}",
        file.display(),
        tx_hash
    );
    Ok(())
}

async fn run_export_skill_docs(rpc: &str, out_dir: PathBuf) -> Result<()> {
    let mut client = connect_public_client(rpc).await?;
    let bundle = load_published_skill_docs(&mut client).await?;
    let index_markdown = render_skill_index_markdown(&bundle);

    std::fs::create_dir_all(&out_dir).with_context(|| {
        format!(
            "Failed to create skill export directory '{}'",
            out_dir.display()
        )
    })?;

    for item in &bundle {
        verify_state_publication(item)?;
        let full_path = out_dir.join(&item.doc.relative_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create parent directory '{}' for generated skill doc",
                    parent.display()
                )
            })?;
        }
        std::fs::write(&full_path, item.doc.markdown.as_bytes()).with_context(|| {
            format!(
                "Failed to write generated skill doc '{}'",
                full_path.display()
            )
        })?;
    }

    let index_path = out_dir.join("skills.md");
    std::fs::write(&index_path, index_markdown.as_bytes()).with_context(|| {
        format!(
            "Failed to write generated skill index '{}'",
            index_path.display()
        )
    })?;

    println!(
        "Exported {} promoted skill docs into '{}'",
        bundle.len(),
        out_dir.display()
    );
    Ok(())
}

async fn run_verify_skill_docs(rpc: &str, out_dir: PathBuf) -> Result<()> {
    let mut client = connect_public_client(rpc).await?;
    let bundle = load_published_skill_docs(&mut client).await?;
    let index_markdown = render_skill_index_markdown(&bundle);

    for item in &bundle {
        verify_state_publication(item)?;
        let full_path = out_dir.join(&item.doc.relative_path);
        let disk_markdown = std::fs::read_to_string(&full_path).with_context(|| {
            format!(
                "Generated skill doc '{}' is missing or unreadable",
                full_path.display()
            )
        })?;
        if disk_markdown != item.doc.markdown {
            return Err(anyhow!(
                "Generated skill doc '{}' drifted from published state",
                full_path.display()
            ));
        }
    }

    let index_path = out_dir.join("skills.md");
    let disk_index = std::fs::read_to_string(&index_path).with_context(|| {
        format!(
            "Generated skill index '{}' is missing or unreadable",
            index_path.display()
        )
    })?;
    if disk_index != index_markdown {
        return Err(anyhow!(
            "Generated skill index '{}' drifted from published state",
            index_path.display()
        ));
    }

    println!(
        "Verified {} promoted skill docs in '{}'",
        bundle.len(),
        out_dir.display()
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
            kind: spec.kind.clone(),
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

    let mut connector_metadata = BTreeMap::new();
    if let Some(driver) = config.provider_driver.clone() {
        connector_metadata.insert("driver".to_string(), driver);
    }

    let upsert = MailConnectorUpsertParams {
        mailbox: config.mailbox.clone(),
        config: MailConnectorConfig {
            provider: MailConnectorProvider::ImapSmtp,
            auth_mode: config.auth_mode,
            account_email: config.account_email.clone(),
            sender_display_name: None,
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
            metadata: connector_metadata,
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
    nonce = nonce.saturating_add(1);
    let tx_hash = submit_tx_and_wait(&mut client, &tx).await?;

    println!(
        "Mail connector upserted for mailbox='{}' account='{}'. tx_hash={}",
        upsert.mailbox, upsert.config.account_email, tx_hash
    );

    let auth_record = ConnectorAuthRecord {
        connector_id: format!("mail.{}", upsert.mailbox),
        provider_family: "mail.wallet_network".to_string(),
        auth_protocol: match config.auth_mode {
            MailConnectorAuthMode::Password => ConnectorAuthProtocol::StaticPassword,
            MailConnectorAuthMode::Oauth2 => ConnectorAuthProtocol::OAuth2Bearer,
        },
        state: ConnectorAuthState::Connected,
        account_label: Some(config.account_email.clone()),
        mailbox: Some(config.mailbox.clone()),
        granted_scopes: vec![
            "mail.read.latest".to_string(),
            "mail.list.recent".to_string(),
            "mail.delete.spam".to_string(),
            "mail.reply".to_string(),
        ],
        credential_aliases: BTreeMap::from([
            (
                "imap_username".to_string(),
                config.imap_username_alias.clone(),
            ),
            ("imap_secret".to_string(), config.imap_secret_alias.clone()),
            (
                "smtp_username".to_string(),
                config.smtp_username_alias.clone(),
            ),
            ("smtp_secret".to_string(), config.smtp_secret_alias.clone()),
        ]),
        metadata: {
            let mut metadata = BTreeMap::new();
            if let Some(driver) = config.provider_driver.clone() {
                metadata.insert("driver".to_string(), driver);
            }
            metadata.insert(
                "configured_by".to_string(),
                "cli.dev.bootstrap_mail".to_string(),
            );
            metadata
        },
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
        expires_at_ms: None,
        last_validated_at_ms: Some(now_ms),
    };
    let params = codec::to_bytes_canonical(&ConnectorAuthUpsertParams {
        record: auth_record,
    })
    .map_err(|e| anyhow!("Failed to encode connector auth record: {}", e))?;
    let payload = SystemPayload::CallService {
        service_id: "wallet_network".to_string(),
        method: "connector_auth_upsert@v1".to_string(),
        params,
    };
    let tx = create_cli_tx(&keypair, payload, nonce);
    let tx_hash = submit_tx_and_wait(&mut client, &tx).await?;
    println!(
        "Connector auth upserted for mailbox='{}' account='{}'. tx_hash={}",
        config.mailbox, config.account_email, tx_hash
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
        provider_driver: nonempty_env_value(map, MAIL_E2E_KEY_PROVIDER_DRIVER)
            .map(|value| value.to_ascii_lowercase()),
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
    let auth_secret_kind = match config.auth_mode {
        MailConnectorAuthMode::Password => SecretKind::Password,
        MailConnectorAuthMode::Oauth2 => SecretKind::AccessToken,
    };
    vec![
        LocalMailSecretSpec {
            secret_id: config.imap_username_secret_id.clone(),
            alias: config.imap_username_alias.clone(),
            value: config.imap_username.clone(),
            kind: SecretKind::Custom("username".to_string()),
        },
        LocalMailSecretSpec {
            secret_id: config.imap_secret_secret_id.clone(),
            alias: config.imap_secret_alias.clone(),
            value: config.imap_secret.clone(),
            kind: auth_secret_kind.clone(),
        },
        LocalMailSecretSpec {
            secret_id: config.smtp_username_secret_id.clone(),
            alias: config.smtp_username_alias.clone(),
            value: config.smtp_username.clone(),
            kind: SecretKind::Custom("username".to_string()),
        },
        LocalMailSecretSpec {
            secret_id: config.smtp_secret_secret_id.clone(),
            alias: config.smtp_secret_alias.clone(),
            value: config.smtp_secret.clone(),
            kind: auth_secret_kind,
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

async fn query_raw_state(
    client: &mut PublicApiClient<Channel>,
    key: Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    let response = client
        .query_raw_state(QueryRawStateRequest { key })
        .await
        .context("query_raw_state RPC failed")?
        .into_inner();
    if response.found {
        Ok(Some(response.value))
    } else {
        Ok(None)
    }
}

async fn load_published_skill_docs(
    client: &mut PublicApiClient<Channel>,
) -> Result<Vec<PublishedSkillBundle>> {
    let index = if let Some(bytes) = query_raw_state(client, SKILL_DOC_INDEX_KEY.to_vec()).await? {
        codec::from_bytes_canonical::<SkillCatalogIndex>(&bytes)
            .map_err(|e| anyhow!("Failed to decode skill doc index: {}", e))?
    } else {
        SkillCatalogIndex::default()
    };

    let mut bundle = Vec::new();
    for skill_hash in index.skills {
        let Some(doc_bytes) = query_raw_state(client, get_skill_doc_key(&skill_hash)).await? else {
            continue;
        };
        let doc = codec::from_bytes_canonical::<PublishedSkillDoc>(&doc_bytes)
            .map_err(|e| anyhow!("Failed to decode published skill doc: {}", e))?;

        let Some(record_bytes) = query_raw_state(client, get_skill_record_key(&skill_hash)).await?
        else {
            return Err(anyhow!(
                "Published skill doc '{}' is missing its backing SkillRecord",
                doc.name
            ));
        };
        let record = codec::from_bytes_canonical::<SkillRecord>(&record_bytes)
            .map_err(|e| anyhow!("Failed to decode skill record: {}", e))?;

        if record.lifecycle_state == SkillLifecycleState::Promoted && !doc.stale {
            bundle.push(PublishedSkillBundle { record, doc });
        }
    }

    bundle.sort_by(|left, right| left.doc.name.cmp(&right.doc.name));
    Ok(bundle)
}

fn verify_state_publication(item: &PublishedSkillBundle) -> Result<()> {
    let expected_markdown = render_skill_markdown(&item.record);
    let expected_relative_path = skill_doc_relative_path(&item.record);
    let expected_hash_bytes = sha256(expected_markdown.as_bytes())
        .map_err(|e| anyhow!("Failed to hash generated skill markdown: {}", e))?;
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(expected_hash_bytes.as_ref());

    if item.doc.markdown != expected_markdown {
        return Err(anyhow!(
            "Published skill doc '{}' drifted from its backing SkillRecord",
            item.doc.name
        ));
    }
    if item.doc.relative_path != expected_relative_path {
        return Err(anyhow!(
            "Published skill doc '{}' has a stale relative path",
            item.doc.name
        ));
    }
    if item.doc.doc_hash != expected_hash {
        return Err(anyhow!(
            "Published skill doc '{}' has a stale doc hash",
            item.doc.name
        ));
    }
    if item.doc.generator_version != SKILL_DOC_GENERATOR_VERSION {
        return Err(anyhow!(
            "Published skill doc '{}' was generated by an unexpected generator version",
            item.doc.name
        ));
    }
    let publication = item.record.publication.as_ref().ok_or_else(|| {
        anyhow!(
            "Promoted skill '{}' is missing publication metadata",
            item.doc.name
        )
    })?;
    if publication.stale {
        return Err(anyhow!(
            "Promoted skill '{}' is marked stale and must be republished",
            item.doc.name
        ));
    }
    if publication.relative_path != item.doc.relative_path
        || publication.doc_hash != item.doc.doc_hash
    {
        return Err(anyhow!(
            "Promoted skill '{}' publication metadata drifted from the published doc",
            item.doc.name
        ));
    }
    Ok(())
}

fn render_skill_index_markdown(bundle: &[PublishedSkillBundle]) -> String {
    let mut out = String::from("# Skills\n\n");
    out.push_str("Generated skill docs derived from promoted executable `AgentMacro` records.\n\n");
    if bundle.is_empty() {
        out.push_str("No promoted skill docs are currently published.\n");
        return out;
    }

    out.push_str("## Published Skills\n\n");
    for item in bundle {
        let description = item.record.macro_body.definition.description.trim();
        let success_rate = item
            .record
            .benchmark
            .as_ref()
            .map(|benchmark| benchmark.success_rate_bps)
            .unwrap_or_default();
        out.push_str(&format!(
            "- `{}`: {} (`{}`; success=`{} bps`)\n",
            item.doc.name,
            if description.is_empty() {
                "No description".to_string()
            } else {
                description.to_string()
            },
            item.doc.relative_path,
            success_rate
        ));
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::agentic::{SkillBenchmarkReport, SkillPublicationInfo, SkillSourceType};

    fn sample_bundle() -> PublishedSkillBundle {
        let record = SkillRecord {
            skill_hash: [7u8; 32],
            archival_record_id: 11,
            macro_body: AgentMacro {
                definition: LlmToolDefinition {
                    name: "browser__open_dashboard".to_string(),
                    description: "Open the dashboard.".to_string(),
                    parameters: r#"{"type":"object","properties":{"url":{"type":"string"}}}"#
                        .to_string(),
                },
                steps: vec![ActionRequest {
                    target: ActionTarget::BrowserInteract,
                    params: br#"{"__ioi_tool_name":"browser__navigate","url":"{{url}}"}"#.to_vec(),
                    context: ActionContext {
                        agent_id: "macro".to_string(),
                        session_id: None,
                        window_id: None,
                    },
                    nonce: 0,
                }],
                source_trace_hash: [3u8; 32],
                fitness: 1.0,
            },
            lifecycle_state: SkillLifecycleState::Promoted,
            source_type: SkillSourceType::Imported,
            source_session_id: None,
            source_evidence_hash: Some([5u8; 32]),
            benchmark: Some(SkillBenchmarkReport {
                sample_size: 8,
                success_rate_bps: 9_250,
                intervention_rate_bps: 0,
                policy_incident_rate_bps: 0,
                avg_cost: 77,
                avg_latency_ms: 0,
                passed: true,
                last_evaluated_height: 9,
            }),
            publication: None,
            created_at: 1,
            updated_at: 2,
        };
        let markdown = render_skill_markdown(&record);
        let digest = sha256(markdown.as_bytes()).expect("hash");
        let mut doc_hash = [0u8; 32];
        doc_hash.copy_from_slice(digest.as_ref());
        let relative_path = skill_doc_relative_path(&record);
        let publication = SkillPublicationInfo {
            generator_version: SKILL_DOC_GENERATOR_VERSION.to_string(),
            generated_at: 123,
            doc_hash,
            relative_path: relative_path.clone(),
            stale: false,
        };
        let doc = PublishedSkillDoc {
            skill_hash: record.skill_hash,
            name: record.macro_body.definition.name.clone(),
            markdown,
            generator_version: SKILL_DOC_GENERATOR_VERSION.to_string(),
            generated_at: 123,
            source_trace_hash: record.macro_body.source_trace_hash,
            source_evidence_hash: record.source_evidence_hash,
            lifecycle_state: record.lifecycle_state,
            doc_hash,
            relative_path,
            stale: false,
        };
        PublishedSkillBundle {
            record: SkillRecord {
                publication: Some(publication),
                ..record
            },
            doc,
        }
    }

    #[test]
    fn verify_state_publication_accepts_matching_bundle() {
        let bundle = sample_bundle();
        verify_state_publication(&bundle).expect("bundle should verify");
    }

    #[test]
    fn render_skill_index_markdown_lists_promoted_docs() {
        let bundle = sample_bundle();
        let markdown = render_skill_index_markdown(&[bundle]);
        assert!(markdown.contains("browser__open_dashboard"));
        assert!(markdown.contains("skills/browser__open_dashboard/SKILL.md"));
        assert!(markdown.contains("success=`9250 bps`"));
    }
}
