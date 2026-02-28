use anyhow::{anyhow, Result};
use async_trait::async_trait;
use image::{ImageBuffer, ImageFormat, Rgba};
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_scs::{SovereignContextStore, StoreConfig};
use ioi_services::agentic::desktop::keys::AGENT_POLICY_PREFIX;
use ioi_services::agentic::desktop::service::step::helpers::{
    default_safe_policy, is_mailbox_connector_goal,
};
use ioi_services::agentic::desktop::{
    AgentMode, AgentState, AgentStatus, DesktopAgentService, ResumeAgentParams, StartAgentParams,
    StepAgentParams,
};
use ioi_services::agentic::rules::DefaultPolicy;
use ioi_services::wallet_network::WalletNetworkService;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::action::{ApprovalScope, ApprovalToken};
use ioi_types::app::agentic::{
    CapabilityId, IntentAmbiguityAction, IntentConfidenceBand, IntentScopeProfile,
    ResolvedIntentState,
};
use ioi_types::app::{
    ActionRequest, ContextSlice, KernelEvent, MailConnectorAuthMode, MailConnectorConfig,
    MailConnectorEndpoint, MailConnectorProvider, MailConnectorSecretAliases, MailConnectorTlsMode,
    MailConnectorUpsertParams, RoutingReceiptEvent, SecretKind, SessionChannelDelegationRules,
    SessionChannelEnvelope, SessionChannelMode, SessionChannelOrdering, SessionChannelRecord,
    SessionChannelState, SessionLease, SessionLeaseMode, SignatureSuite, VaultSecretRecord,
    WorkloadReceipt,
};
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::{ActiveServiceMeta, Capabilities, MethodPermission};
use ioi_types::{codec, error::VmError};
use parity_scale_codec::Encode;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use tokio::sync::broadcast;

use super::types::{ActionEvidence, CommandHistoryEvidence, QueryCase, RunObservation};

#[derive(Clone)]
struct MockGuiDriver;

#[async_trait]
impl GuiDriver for MockGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));

        let mut bytes: Vec<u8> = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .map_err(|e| VmError::HostError(format!("Mock PNG encoding failed: {}", e)))?;

        Ok(bytes)
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        self.capture_screen(None).await
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok(String::new())
    }

    async fn capture_context(&self, _: &ActionRequest) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [0; 32],
            frame_id: 0,
            chunks: vec![],
            mhnsw_root: [0; 32],
            traversal_proof: None,
            intent_id: [0; 32],
        })
    }

    async fn inject_input(&self, _: InputEvent) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }
}

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
const VLC_INSTALL_CASE_ID: &str = "download_and_install_vlc_media_player";
const VLC_INSTALL_FIXTURE_MODE: &str = "apt_get_vlc_fixture_v1";
const VLC_INSTALL_FIXTURE_PROBE_SOURCE: &str = "harness.vlc_install_fixture";

#[derive(Debug, Clone)]
struct MailRuntimeBootstrapConfig {
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

#[derive(Debug, Clone)]
struct MailRuntimeSecretSpec {
    secret_id: String,
    alias: String,
    value: String,
}

struct ScopedEnvVar {
    key: String,
    previous: Option<String>,
}

impl ScopedEnvVar {
    fn set(key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let previous = std::env::var(&key).ok();
        std::env::set_var(&key, value.into());
        Self { key, previous }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.as_ref() {
            std::env::set_var(&self.key, previous);
        } else {
            std::env::remove_var(&self.key);
        }
    }
}

struct VlcInstallFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_path: ScopedEnvVar,
    _env_prefix: ScopedEnvVar,
    _env_mode: ScopedEnvVar,
    prefix: PathBuf,
    download_receipt_path: PathBuf,
    install_receipt_path: PathBuf,
    vlc_binary_path: PathBuf,
}

fn find_workspace_file(file_name: &str) -> Option<PathBuf> {
    let mut cursor = std::env::current_dir().ok();
    while let Some(path) = cursor.clone() {
        let candidate = path.join(file_name);
        if candidate.is_file() {
            return Some(candidate);
        }
        cursor = path.parent().map(|parent| parent.to_path_buf());
    }
    None
}

fn load_env_file_if_present(file_name: &str) {
    let Some(path) = find_workspace_file(file_name) else {
        return;
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return;
    };

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || std::env::var(key).is_ok() {
            continue;
        }
        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        if !value.is_empty() {
            std::env::set_var(key, value);
        }
    }
}

pub fn load_env_from_workspace_dotenv_if_present() {
    load_env_file_if_present(".env");
    load_env_file_if_present(".env.mail-e2e.local");
}

fn required_env_value(key: &str) -> Result<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("missing required environment variable '{}'", key))
}

fn optional_env_value(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn nonempty_env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_u16_env(key: &str) -> Result<u16> {
    let raw = required_env_value(key)?;
    let value = raw
        .parse::<u16>()
        .map_err(|e| anyhow!("invalid {} '{}': {}", key, raw, e))?;
    if value == 0 {
        return Err(anyhow!("invalid {}: value must be > 0", key));
    }
    Ok(value)
}

fn parse_mail_auth_mode_env() -> Result<MailConnectorAuthMode> {
    if let Some(raw) = nonempty_env_value(MAIL_E2E_KEY_AUTH_MODE) {
        return match raw.to_ascii_lowercase().as_str() {
            "password" | "pass" => Ok(MailConnectorAuthMode::Password),
            "oauth2" | "oauth" | "xoauth2" => Ok(MailConnectorAuthMode::Oauth2),
            _ => Err(anyhow!(
                "invalid {} '{}': expected password or oauth2",
                MAIL_E2E_KEY_AUTH_MODE,
                raw
            )),
        };
    }

    let has_password = nonempty_env_value(MAIL_E2E_KEY_IMAP_PASSWORD).is_some()
        || nonempty_env_value(MAIL_E2E_KEY_SMTP_PASSWORD).is_some();
    let has_bearer = nonempty_env_value(MAIL_E2E_KEY_IMAP_BEARER_TOKEN).is_some()
        || nonempty_env_value(MAIL_E2E_KEY_SMTP_BEARER_TOKEN).is_some();
    if has_bearer && !has_password {
        Ok(MailConnectorAuthMode::Oauth2)
    } else {
        Ok(MailConnectorAuthMode::Password)
    }
}

fn parse_tls_mode_env(key: &str, default: MailConnectorTlsMode) -> Result<MailConnectorTlsMode> {
    let Some(raw) = nonempty_env_value(key) else {
        return Ok(default);
    };
    match raw.to_ascii_lowercase().as_str() {
        "plaintext" | "plain" => Ok(MailConnectorTlsMode::Plaintext),
        "starttls" | "start_tls" | "start-tls" => Ok(MailConnectorTlsMode::StartTls),
        "tls" | "ssl" => Ok(MailConnectorTlsMode::Tls),
        _ => Err(anyhow!(
            "invalid {} '{}': expected plaintext, starttls, or tls",
            key,
            raw
        )),
    }
}

fn parse_mail_runtime_bootstrap_config() -> Result<MailRuntimeBootstrapConfig> {
    let auth_mode = parse_mail_auth_mode_env()?;
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
                MAIL_E2E_KEY_IMAP_PASSWORD_ALIAS,
                MAIL_E2E_DEFAULT_IMAP_PASSWORD_ALIAS,
            ),
            optional_env_value(
                MAIL_E2E_KEY_SMTP_PASSWORD_ALIAS,
                MAIL_E2E_DEFAULT_SMTP_PASSWORD_ALIAS,
            ),
            optional_env_value(
                MAIL_E2E_KEY_IMAP_PASSWORD_SECRET_ID,
                MAIL_E2E_DEFAULT_IMAP_PASSWORD_SECRET_ID,
            ),
            optional_env_value(
                MAIL_E2E_KEY_SMTP_PASSWORD_SECRET_ID,
                MAIL_E2E_DEFAULT_SMTP_PASSWORD_SECRET_ID,
            ),
            required_env_value(MAIL_E2E_KEY_IMAP_PASSWORD)?,
            required_env_value(MAIL_E2E_KEY_SMTP_PASSWORD)?,
        ),
        MailConnectorAuthMode::Oauth2 => (
            optional_env_value(
                MAIL_E2E_KEY_IMAP_BEARER_TOKEN_ALIAS,
                MAIL_E2E_DEFAULT_IMAP_BEARER_TOKEN_ALIAS,
            ),
            optional_env_value(
                MAIL_E2E_KEY_SMTP_BEARER_TOKEN_ALIAS,
                MAIL_E2E_DEFAULT_SMTP_BEARER_TOKEN_ALIAS,
            ),
            optional_env_value(
                MAIL_E2E_KEY_IMAP_BEARER_TOKEN_SECRET_ID,
                MAIL_E2E_DEFAULT_IMAP_BEARER_TOKEN_SECRET_ID,
            ),
            optional_env_value(
                MAIL_E2E_KEY_SMTP_BEARER_TOKEN_SECRET_ID,
                MAIL_E2E_DEFAULT_SMTP_BEARER_TOKEN_SECRET_ID,
            ),
            required_env_value(MAIL_E2E_KEY_IMAP_BEARER_TOKEN)?,
            required_env_value(MAIL_E2E_KEY_SMTP_BEARER_TOKEN)?,
        ),
    };

    Ok(MailRuntimeBootstrapConfig {
        auth_mode,
        mailbox: optional_env_value(MAIL_E2E_KEY_MAILBOX, MAIL_E2E_DEFAULT_MAILBOX)
            .to_ascii_lowercase(),
        account_email: required_env_value(MAIL_E2E_KEY_ACCOUNT_EMAIL)?.to_ascii_lowercase(),
        imap_host: required_env_value(MAIL_E2E_KEY_IMAP_HOST)?.to_ascii_lowercase(),
        imap_port: parse_u16_env(MAIL_E2E_KEY_IMAP_PORT)?,
        imap_tls_mode: parse_tls_mode_env(MAIL_E2E_KEY_IMAP_TLS_MODE, MailConnectorTlsMode::Tls)?,
        smtp_host: required_env_value(MAIL_E2E_KEY_SMTP_HOST)?.to_ascii_lowercase(),
        smtp_port: parse_u16_env(MAIL_E2E_KEY_SMTP_PORT)?,
        smtp_tls_mode: parse_tls_mode_env(
            MAIL_E2E_KEY_SMTP_TLS_MODE,
            MailConnectorTlsMode::StartTls,
        )?,
        imap_username_alias: optional_env_value(
            MAIL_E2E_KEY_IMAP_USERNAME_ALIAS,
            MAIL_E2E_DEFAULT_IMAP_USERNAME_ALIAS,
        )
        .to_ascii_lowercase(),
        imap_secret_alias: imap_secret_alias.to_ascii_lowercase(),
        smtp_username_alias: optional_env_value(
            MAIL_E2E_KEY_SMTP_USERNAME_ALIAS,
            MAIL_E2E_DEFAULT_SMTP_USERNAME_ALIAS,
        )
        .to_ascii_lowercase(),
        smtp_secret_alias: smtp_secret_alias.to_ascii_lowercase(),
        imap_username_secret_id: optional_env_value(
            MAIL_E2E_KEY_IMAP_USERNAME_SECRET_ID,
            MAIL_E2E_DEFAULT_IMAP_USERNAME_SECRET_ID,
        ),
        imap_secret_secret_id,
        smtp_username_secret_id: optional_env_value(
            MAIL_E2E_KEY_SMTP_USERNAME_SECRET_ID,
            MAIL_E2E_DEFAULT_SMTP_USERNAME_SECRET_ID,
        ),
        smtp_secret_secret_id,
        imap_username: required_env_value(MAIL_E2E_KEY_IMAP_USERNAME)?,
        imap_secret,
        smtp_username: required_env_value(MAIL_E2E_KEY_SMTP_USERNAME)?,
        smtp_secret,
    })
}

fn build_mail_runtime_secret_specs(
    config: &MailRuntimeBootstrapConfig,
) -> Vec<MailRuntimeSecretSpec> {
    vec![
        MailRuntimeSecretSpec {
            secret_id: config.imap_username_secret_id.clone(),
            alias: config.imap_username_alias.clone(),
            value: config.imap_username.clone(),
        },
        MailRuntimeSecretSpec {
            secret_id: config.imap_secret_secret_id.clone(),
            alias: config.imap_secret_alias.clone(),
            value: config.imap_secret.clone(),
        },
        MailRuntimeSecretSpec {
            secret_id: config.smtp_username_secret_id.clone(),
            alias: config.smtp_username_alias.clone(),
            value: config.smtp_username.clone(),
        },
        MailRuntimeSecretSpec {
            secret_id: config.smtp_secret_secret_id.clone(),
            alias: config.smtp_secret_alias.clone(),
            value: config.smtp_secret.clone(),
        },
    ]
}

fn build_ctx<'a>(services: &'a ServiceDirectory) -> TxContext<'a> {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    TxContext {
        block_height: 1,
        block_timestamp: now_ns,
        chain_id: ioi_types::app::ChainId(0),
        signer_account_id: ioi_types::app::AccountId::default(),
        services,
        simulation: false,
        is_internal: false,
    }
}

fn deterministic_id(run_index: usize, salt: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = (run_index as u8)
            .wrapping_add((idx as u8).wrapping_mul(17))
            .wrapping_add(salt);
    }
    out
}

fn session_id_for_index(run_index: usize) -> [u8; 32] {
    deterministic_id(run_index, 0x63)
}

fn build_approval_token_for_resume(
    request_hash: [u8; 32],
    now_ms: u64,
    pending_visual_hash: Option<[u8; 32]>,
) -> ApprovalToken {
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&request_hash);
    ApprovalToken {
        schema_version: 2,
        request_hash,
        audience: [0u8; 32],
        revocation_epoch: 0,
        nonce,
        counter: 1,
        scope: ApprovalScope {
            expires_at: now_ms.saturating_add(120_000),
            max_usages: Some(1),
        },
        visual_hash: pending_visual_hash,
        pii_action: None,
        scoped_exception: None,
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    }
}

fn read_agent_state(state: &IAVLTree<HashCommitmentScheme>, session_id: [u8; 32]) -> AgentState {
    let key = [b"agent::state::".as_slice(), session_id.as_slice()].concat();
    let bytes = state
        .get(&key)
        .expect("state get should not fail")
        .expect("session state should exist");
    codec::from_bytes_canonical(&bytes).expect("agent state should decode")
}

fn seeded_required_capabilities(scope: IntentScopeProfile, intent_id: &str) -> Vec<CapabilityId> {
    let mut caps = match scope {
        IntentScopeProfile::Conversation => vec![CapabilityId::from("conversation.reply")],
        IntentScopeProfile::WebResearch => vec![
            CapabilityId::from("web.retrieve"),
            CapabilityId::from("browser.interact"),
            CapabilityId::from("browser.inspect"),
            CapabilityId::from("conversation.reply"),
            CapabilityId::from("sys.time.read"),
        ],
        IntentScopeProfile::WorkspaceOps => vec![
            CapabilityId::from("filesystem.read"),
            CapabilityId::from("filesystem.write"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::AppLaunch => vec![
            CapabilityId::from("app.launch"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::UiInteraction => vec![
            CapabilityId::from("ui.interact"),
            CapabilityId::from("ui.inspect"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::CommandExecution => vec![
            CapabilityId::from("command.exec"),
            CapabilityId::from("command.probe"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::Delegation => vec![
            CapabilityId::from("delegation.manage"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::Unknown => vec![CapabilityId::from("conversation.reply")],
    };

    let install_intent = intent_id.to_ascii_lowercase().contains("install");
    if install_intent && matches!(scope, IntentScopeProfile::CommandExecution) {
        caps.push(CapabilityId::from("system.install_package"));
    }

    caps
}

fn seed_resolved_intent(
    state: &mut IAVLTree<HashCommitmentScheme>,
    session_id: [u8; 32],
    intent_id: &str,
    scope: IntentScopeProfile,
) {
    let key = [b"agent::state::".as_slice(), session_id.as_slice()].concat();
    let bytes = state
        .get(&key)
        .expect("state get should not fail")
        .expect("session state should exist");
    let mut agent_state: AgentState =
        codec::from_bytes_canonical(&bytes).expect("agent state should decode");
    agent_state.resolved_intent = Some(ResolvedIntentState {
        intent_id: intent_id.to_string(),
        scope,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![],
        required_capabilities: seeded_required_capabilities(scope, intent_id),
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "test".to_string(),
        embedding_model_id: "test-embed".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [0u8; 32],
        receipt_hash: [0u8; 32],
        constrained: false,
    });
    agent_state.awaiting_intent_clarification = false;
    agent_state.status = AgentStatus::Running;
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&agent_state).expect("state encode"),
        )
        .expect("state insert should not fail");
}

fn enable_intent_shadow_mode(state: &mut IAVLTree<HashCommitmentScheme>, session_id: [u8; 32]) {
    let mut rules = default_safe_policy();
    // Dedicated live capabilities suite should validate execution success without
    // interactive approval gates blocking baseline command/app flows.
    rules.defaults = DefaultPolicy::AllowAll;
    rules.ontology_policy.intent_routing.shadow_mode = true;
    rules
        .ontology_policy
        .intent_routing
        .ambiguity
        .low_confidence_action = IntentAmbiguityAction::Proceed;
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    state
        .insert(
            &policy_key,
            &codec::to_bytes_canonical(&rules).expect("policy encode"),
        )
        .expect("policy insert should not fail");
}

fn build_scs(path_name: &str) -> Result<(SovereignContextStore, tempfile::TempDir)> {
    let temp_dir = tempdir()?;
    let scs_path = temp_dir.path().join(path_name);
    let scs = SovereignContextStore::create(
        &scs_path,
        StoreConfig {
            chain_id: 1,
            owner_id: [0u8; 32],
            identity_key: [0x11; 32],
        },
    )?;
    Ok((scs, temp_dir))
}

fn drain_events(rx: &mut broadcast::Receiver<KernelEvent>, sink: &mut Vec<KernelEvent>) {
    while let Ok(event) = rx.try_recv() {
        sink.push(event);
    }
}

fn requires_human_intervention(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    [
        "waiting for approval",
        "waiting for user intervention",
        "human verification",
        "captcha",
        "sudo password",
        "credential",
        "clarification",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn truncate_for_log(input: &str, max_chars: usize) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        compact
    } else {
        compact.chars().take(max_chars).collect::<String>() + "..."
    }
}

fn event_log_line(event: &KernelEvent, max_chars: usize) -> String {
    match event {
        KernelEvent::AgentActionResult {
            tool_name,
            output,
            agent_status,
            ..
        } => format!(
            "action tool={} status={} output={}",
            tool_name,
            agent_status,
            truncate_for_log(output, max_chars)
        ),
        KernelEvent::RoutingReceipt(RoutingReceiptEvent {
            tool_name,
            policy_decision,
            post_state,
            ..
        }) => format!(
            "routing tool={} decision={} success={} checks={}",
            tool_name,
            policy_decision,
            post_state.success,
            truncate_for_log(&post_state.verification_checks.join(","), max_chars)
        ),
        KernelEvent::WorkloadReceipt(workload) => match &workload.receipt {
            WorkloadReceipt::WebRetrieve(web) => format!(
                "workload web tool={} success={} sources={} docs={}",
                web.tool_name, web.success, web.sources_count, web.documents_count
            ),
            _ => "workload other".to_string(),
        },
        KernelEvent::IntentResolutionReceipt(receipt) => {
            format!("intent scope={:?} band={:?}", receipt.scope, receipt.band)
        }
        _ => {
            let debug_payload = format!("{:?}", event);
            format!(
                "event(other) payload={}",
                truncate_for_log(&debug_payload, max_chars)
            )
        }
    }
}

fn event_summary_line(event: &KernelEvent) -> String {
    event_log_line(event, 280)
}

fn event_full_line(event: &KernelEvent) -> String {
    event_log_line(event, 2_000)
}

#[derive(Debug, Deserialize)]
struct CommandHistoryPayload {
    command: String,
    exit_code: i32,
    stdout: String,
    stderr: String,
}

fn extract_json_prefix_object(input: &str) -> Option<&str> {
    let trimmed = input.trim_start();
    let mut chars = trimmed.char_indices();
    let (start_idx, first_char) = chars.next()?;
    if start_idx != 0 || first_char != '{' {
        return None;
    }

    let mut depth = 1usize;
    let mut in_string = false;
    let mut escaped = false;

    for (idx, ch) in chars {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(&trimmed[..=idx]);
                }
            }
            _ => {}
        }
    }

    None
}

fn extract_command_history_evidence(output: &str) -> Option<CommandHistoryEvidence> {
    let payload = output.strip_prefix("COMMAND_HISTORY:")?;
    let json_fragment = extract_json_prefix_object(payload)?;
    let parsed: CommandHistoryPayload = serde_json::from_str(json_fragment).ok()?;
    Some(CommandHistoryEvidence {
        command: parsed.command,
        exit_code: parsed.exit_code,
        stdout: parsed.stdout,
        stderr: parsed.stderr,
    })
}

fn civil_date_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

fn iso_datetime_from_unix_ms(unix_ms: u64) -> String {
    let days_since_epoch = (unix_ms / 86_400_000) as i64;
    let (year, month, day) = civil_date_from_days(days_since_epoch);
    let ms_of_day = unix_ms % 86_400_000;
    let hour = ms_of_day / 3_600_000;
    let minute = (ms_of_day % 3_600_000) / 60_000;
    let second = (ms_of_day % 60_000) / 1_000;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn render_query_for_run(query_template: &str, run_index: usize, run_timestamp_ms: u64) -> String {
    let run_unique_num = format!("{}{:03}", run_timestamp_ms, run_index);
    query_template
        .replace("{RUN_UNIQUE_NUM}", &run_unique_num)
        .replace("{RUN_INDEX}", &run_index.to_string())
}

fn should_bootstrap_mailbox_runtime(goal: &str) -> bool {
    is_mailbox_connector_goal(goal)
}

fn should_bootstrap_vlc_install_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(VLC_INSTALL_CASE_ID)
}

fn write_executable_script(path: &Path, content: &str) -> Result<()> {
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn bootstrap_vlc_install_fixture_runtime() -> Result<VlcInstallFixtureRuntime> {
    let temp_dir = tempdir()?;
    let fixture_bin = temp_dir.path().join("bin");
    let fixture_prefix = temp_dir.path().join("prefix");
    let fixture_prefix_bin = fixture_prefix.join("bin");
    let fixture_downloads = fixture_prefix.join("downloads");
    let fixture_receipts = fixture_prefix.join("install_receipts");
    std::fs::create_dir_all(&fixture_bin)?;
    std::fs::create_dir_all(&fixture_prefix_bin)?;
    std::fs::create_dir_all(&fixture_downloads)?;
    std::fs::create_dir_all(&fixture_receipts)?;

    let sudo_script = r#"#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -eq 0 ]; then
  exit 0
fi
args=()
for arg in "$@"; do
  case "$arg" in
    -n|-S|-k|--) ;;
    *) args+=("$arg") ;;
  esac
done
if [ "${#args[@]}" -eq 0 ]; then
  exit 0
fi
exec "${args[@]}"
"#;
    write_executable_script(&fixture_bin.join("sudo"), sudo_script)?;

    let apt_script = r#"#!/usr/bin/env bash
set -euo pipefail
prefix="${IOI_VLC_FIXTURE_PREFIX:-}"
if [ -z "$prefix" ]; then
  echo "apt-get fixture: IOI_VLC_FIXTURE_PREFIX missing" >&2
  exit 2
fi
command_name="${1:-}"
if [ -z "$command_name" ]; then
  echo "apt-get fixture: missing command" >&2
  exit 2
fi
shift
case "$command_name" in
  update)
    echo "Hit:1 http://fixture.example stable InRelease"
    echo "Reading package lists... Done"
    exit 0
    ;;
  install)
    package=""
    for arg in "$@"; do
      case "$arg" in
        -*) ;;
        *) package="$arg" ;;
      esac
    done
    if [ -z "$package" ]; then
      echo "E: Unable to locate package" >&2
      exit 100
    fi
    if [ "$package" != "vlc" ]; then
      echo "E: Unable to locate package $package" >&2
      exit 100
    fi

    mkdir -p "$prefix/bin" "$prefix/downloads" "$prefix/install_receipts"
    cat > "$prefix/bin/vlc" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--version" ]; then
  echo "VLC media player 3.0.20 Vetinari (fixture)"
else
  echo "VLC fixture executable"
fi
EOS
    chmod +x "$prefix/bin/vlc"
    printf 'fixture-vlc-package\n' > "$prefix/downloads/vlc-fixture.deb"
    printf 'vlc\n' > "$prefix/install_receipts/vlc.installed"
    echo "Get:1 http://fixture.example/vlc vlc 3.0.20-fixture amd64"
    echo "Fetched 42.0 MB in 1s (42.0 MB/s)"
    echo "Selecting previously unselected package vlc."
    echo "Setting up vlc (3.0.20-fixture) ..."
    exit 0
    ;;
  *)
    echo "apt-get fixture: unsupported command '$command_name'" >&2
    exit 2
    ;;
esac
"#;
    write_executable_script(&fixture_bin.join("apt-get"), apt_script)?;
    write_executable_script(
        &fixture_bin.join("apt"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec apt-get \"$@\"\n",
    )?;

    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let fixture_path = format!(
        "{}:{}:{}",
        fixture_bin.to_string_lossy(),
        fixture_prefix_bin.to_string_lossy(),
        inherited_path
    );
    let env_path = ScopedEnvVar::set("PATH", fixture_path);
    let env_prefix = ScopedEnvVar::set(
        "IOI_VLC_FIXTURE_PREFIX",
        fixture_prefix.to_string_lossy().to_string(),
    );
    let env_mode = ScopedEnvVar::set("IOI_VLC_FIXTURE_MODE", VLC_INSTALL_FIXTURE_MODE);

    Ok(VlcInstallFixtureRuntime {
        _temp_dir: temp_dir,
        _env_path: env_path,
        _env_prefix: env_prefix,
        _env_mode: env_mode,
        prefix: fixture_prefix.clone(),
        download_receipt_path: fixture_downloads.join("vlc-fixture.deb"),
        install_receipt_path: fixture_receipts.join("vlc.installed"),
        vlc_binary_path: fixture_prefix_bin.join("vlc"),
    })
}

fn vlc_install_fixture_preflight_checks(
    fixture: &VlcInstallFixtureRuntime,
    run_timestamp_ms: u64,
) -> Vec<String> {
    vec![
        format!("env_receipt::vlc_fixture_mode={}", VLC_INSTALL_FIXTURE_MODE),
        format!(
            "env_receipt::vlc_fixture_prefix={}",
            fixture.prefix.to_string_lossy()
        ),
        format!(
            "env_receipt::vlc_fixture_probe_source={}",
            VLC_INSTALL_FIXTURE_PROBE_SOURCE
        ),
        format!(
            "env_receipt::vlc_fixture_timestamp_ms={}",
            run_timestamp_ms
        ),
        "env_receipt::vlc_fixture_satisfied=true".to_string(),
    ]
}

fn vlc_install_fixture_post_run_checks(fixture: &VlcInstallFixtureRuntime) -> Vec<String> {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let download_exists = fixture.download_receipt_path.is_file();
    let install_exists = fixture.install_receipt_path.is_file();
    let binary_exists = fixture.vlc_binary_path.is_file();
    let install_receipt_value = std::fs::read_to_string(&fixture.install_receipt_path)
        .ok()
        .map(|value| value.trim().to_string())
        .unwrap_or_default();
    let install_receipt_value_satisfied = install_receipt_value == "vlc";
    let probe_source = format!("{}.fs_probe", VLC_INSTALL_FIXTURE_PROBE_SOURCE);

    vec![
        format!(
            "env_receipt::vlc_download_receipt_path={}",
            fixture.download_receipt_path.to_string_lossy()
        ),
        format!(
            "env_receipt::vlc_download_receipt_probe_source={}",
            probe_source
        ),
        format!(
            "env_receipt::vlc_download_receipt_timestamp_ms={}",
            timestamp_ms
        ),
        format!(
            "env_receipt::vlc_download_receipt_satisfied={}",
            download_exists
        ),
        format!(
            "env_receipt::vlc_install_receipt_path={}",
            fixture.install_receipt_path.to_string_lossy()
        ),
        format!(
            "env_receipt::vlc_install_receipt_probe_source={}",
            probe_source
        ),
        format!(
            "env_receipt::vlc_install_receipt_timestamp_ms={}",
            timestamp_ms
        ),
        format!(
            "env_receipt::vlc_install_receipt_satisfied={}",
            install_exists
        ),
        format!(
            "env_receipt::vlc_install_receipt_value={}",
            install_receipt_value
        ),
        format!(
            "env_receipt::vlc_install_receipt_value_satisfied={}",
            install_receipt_value_satisfied
        ),
        format!(
            "env_receipt::vlc_binary_path={}",
            fixture.vlc_binary_path.to_string_lossy()
        ),
        format!("env_receipt::vlc_binary_probe_source={}", probe_source),
        format!("env_receipt::vlc_binary_timestamp_ms={}", timestamp_ms),
        format!("env_receipt::vlc_binary_satisfied={}", binary_exists),
    ]
}

fn wallet_channel_key(channel_id: &[u8; 32]) -> Vec<u8> {
    [b"channel::".as_slice(), channel_id.as_slice()].concat()
}

fn wallet_lease_key(channel_id: &[u8; 32], lease_id: &[u8; 32]) -> Vec<u8> {
    [
        b"lease::".as_slice(),
        channel_id.as_slice(),
        b"::",
        lease_id.as_slice(),
    ]
    .concat()
}

fn action_output_excerpt_limit(tool_name: &str) -> usize {
    let lower = tool_name.to_ascii_lowercase();
    if lower.starts_with("wallet_network__mail_")
        || lower.starts_with("wallet_mail_")
        || lower.starts_with("mail__")
    {
        1_400
    } else {
        220
    }
}

fn upsert_wallet_network_service_meta(state: &mut IAVLTree<HashCommitmentScheme>) -> Result<()> {
    let mut methods = BTreeMap::new();
    for method in [
        "store_secret_record@v1",
        "mail_connector_upsert@v1",
        "mail_read_latest@v1",
        "mail_list_recent@v1",
        "mail_delete_spam@v1",
        "mail_reply@v1",
    ] {
        methods.insert(method.to_string(), MethodPermission::User);
    }

    let meta = ActiveServiceMeta {
        id: "wallet_network".to_string(),
        abi_version: 1,
        state_schema: "v1".to_string(),
        caps: Capabilities::empty(),
        artifact_hash: [0u8; 32],
        activated_at: 0,
        methods,
        allowed_system_prefixes: vec![],
        generation_id: 0,
        parent_hash: None,
        author: None,
        context_filter: None,
    };
    state.insert(
        &active_service_key("wallet_network"),
        &codec::to_bytes_canonical(&meta)
            .map_err(|e| anyhow!("failed to encode wallet_network ActiveServiceMeta: {}", e))?,
    )?;
    Ok(())
}

async fn invoke_wallet_method<P: Encode>(
    wallet_service: &WalletNetworkService,
    state: &mut IAVLTree<HashCommitmentScheme>,
    ctx: &mut TxContext<'_>,
    method: &str,
    params: &P,
) -> Result<()> {
    let payload = codec::to_bytes_canonical(params)
        .map_err(|e| anyhow!("failed to encode wallet method params '{}': {}", method, e))?;
    wallet_service
        .handle_service_call(state, method, &payload, ctx)
        .await
        .map_err(|e| anyhow!("wallet method '{}' failed: {}", method, e))
}

async fn bootstrap_mailbox_runtime_state(
    state: &mut IAVLTree<HashCommitmentScheme>,
    ctx: &mut TxContext<'_>,
    wallet_service: &WalletNetworkService,
    run_index: usize,
    run_timestamp_ms: u64,
) -> Result<Vec<String>> {
    let config = parse_mail_runtime_bootstrap_config()?;
    upsert_wallet_network_service_meta(state)?;

    let secret_specs = build_mail_runtime_secret_specs(&config);
    for spec in secret_specs {
        let record = VaultSecretRecord {
            secret_id: spec.secret_id,
            alias: spec.alias,
            kind: SecretKind::AccessToken,
            ciphertext: spec.value.as_bytes().to_vec(),
            metadata: BTreeMap::new(),
            created_at_ms: run_timestamp_ms,
            rotated_at_ms: None,
        };
        invoke_wallet_method(
            wallet_service,
            state,
            ctx,
            "store_secret_record@v1",
            &record,
        )
        .await?;
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
    invoke_wallet_method(
        wallet_service,
        state,
        ctx,
        "mail_connector_upsert@v1",
        &upsert,
    )
    .await?;

    let channel_id = deterministic_id(run_index, 0xB1);
    let lease_id = deterministic_id(run_index, 0xB2);
    let policy_hash = deterministic_id(run_index, 0xB3);
    let envelope_hash = deterministic_id(run_index, 0xB4);
    let root_grant_id = deterministic_id(run_index, 0xB5);
    let issuer_id = deterministic_id(run_index, 0xB6);
    let subject_id = deterministic_id(run_index, 0xB7);
    let lease_nonce = deterministic_id(run_index, 0xB8);
    let channel_expires_at_ms = run_timestamp_ms.saturating_add(30 * 60 * 1_000);
    let lease_expires_at_ms = run_timestamp_ms.saturating_add(15 * 60 * 1_000);

    let mut constraints = BTreeMap::new();
    constraints.insert("mailbox".to_string(), config.mailbox.clone());

    let envelope = SessionChannelEnvelope {
        channel_id,
        lc_id: issuer_id,
        rc_id: subject_id,
        ordering: SessionChannelOrdering::Ordered,
        mode: SessionChannelMode::AttestedRemoteExecution,
        policy_hash,
        policy_version: 1,
        root_grant_id,
        capability_set: vec![
            "mail.read.latest".to_string(),
            "mail.read".to_string(),
            "email:read".to_string(),
            "mail.list.recent".to_string(),
            "mail.list".to_string(),
            "email:list".to_string(),
        ],
        constraints: constraints.clone(),
        delegation_rules: SessionChannelDelegationRules {
            max_depth: 0,
            can_redelegate: false,
            issuance_budget: Some(0),
        },
        revocation_epoch: 0,
        expires_at_ms: channel_expires_at_ms,
    };
    let channel = SessionChannelRecord {
        envelope,
        state: SessionChannelState::Open,
        envelope_hash,
        opened_at_ms: Some(run_timestamp_ms),
        closed_at_ms: None,
        last_seq: 0,
        close_reason: None,
    };
    state.insert(
        &wallet_channel_key(&channel_id),
        &codec::to_bytes_canonical(&channel)
            .map_err(|e| anyhow!("failed to encode seeded SessionChannelRecord: {}", e))?,
    )?;

    let lease = SessionLease {
        lease_id,
        channel_id,
        issuer_id,
        subject_id,
        policy_hash,
        grant_id: root_grant_id,
        capability_subset: vec![
            "mail.read.latest".to_string(),
            "mail.read".to_string(),
            "email:read".to_string(),
        ],
        constraints_subset: constraints,
        mode: SessionLeaseMode::Lease,
        expires_at_ms: lease_expires_at_ms,
        revocation_epoch: 0,
        audience: ctx.signer_account_id.0,
        nonce: lease_nonce,
        counter: 1,
        issued_at_ms: run_timestamp_ms,
        sig_hybrid_lc: vec![1u8],
    };
    state.insert(
        &wallet_lease_key(&channel_id, &lease_id),
        &codec::to_bytes_canonical(&lease)
            .map_err(|e| anyhow!("failed to encode seeded SessionLease: {}", e))?,
    )?;

    let auth_mode_label = match config.auth_mode {
        MailConnectorAuthMode::Password => "password",
        MailConnectorAuthMode::Oauth2 => "oauth2",
    };

    Ok(vec![
        "env_receipt::mail_env_file_loaded=true".to_string(),
        "env_receipt::mail_service_meta_registered=true".to_string(),
        "env_receipt::mail_connector_bootstrap=true".to_string(),
        "env_receipt::mail_channel_seeded=true".to_string(),
        "env_receipt::mail_lease_seeded=true".to_string(),
        format!("env_receipt::mail_auth_mode={}", auth_mode_label),
        format!("env_receipt::mail_mailbox={}", config.mailbox),
        format!("env_receipt::mail_setup_timestamp_ms={}", run_timestamp_ms),
    ])
}

pub async fn run_case(
    case: &QueryCase,
    run_index: usize,
    agent_runtime: Arc<dyn InferenceRuntime>,
) -> Result<RunObservation> {
    let (event_tx, mut event_rx) = broadcast::channel(1024);
    let gui = Arc::new(MockGuiDriver);
    let (scs, _scs_tmp_dir) = build_scs(&format!("capabilities_{}_{}.scs", case.id, run_index))?;
    let service = DesktopAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        agent_runtime.clone(),
        agent_runtime,
    )
    .with_scs(Arc::new(Mutex::new(scs)))
    .with_event_sender(event_tx);

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let wallet_service = Arc::new(WalletNetworkService::default());
    let services_dir =
        ServiceDirectory::new(vec![wallet_service.clone() as Arc<dyn BlockchainService>]);
    let mut ctx = build_ctx(&services_dir);
    let session_id = session_id_for_index(run_index);
    let run_timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let run_query = render_query_for_run(case.query, run_index, run_timestamp_ms);
    let mut runtime_setup_verification_checks = Vec::<String>::new();
    let vlc_install_fixture = if should_bootstrap_vlc_install_fixture(case.id) {
        let fixture = bootstrap_vlc_install_fixture_runtime()?;
        runtime_setup_verification_checks
            .extend(vlc_install_fixture_preflight_checks(&fixture, run_timestamp_ms));
        Some(fixture)
    } else {
        None
    };
    if should_bootstrap_mailbox_runtime(&run_query) {
        runtime_setup_verification_checks.extend(
            bootstrap_mailbox_runtime_state(
                &mut state,
                &mut ctx,
                wallet_service.as_ref(),
                run_index,
                run_timestamp_ms,
            )
            .await?,
        );
    }

    let start_params = StartAgentParams {
        session_id,
        goal: run_query.clone(),
        max_steps: case.max_steps,
        parent_session_id: None,
        initial_budget: 4_000,
        mode: AgentMode::Agent,
    };

    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params)
                .map_err(|e| anyhow!("failed to encode start params: {}", e))?,
            &mut ctx,
        )
        .await?;

    enable_intent_shadow_mode(&mut state, session_id);
    if case.seed_resolved_intent {
        seed_resolved_intent(
            &mut state,
            session_id,
            case.seeded_intent_id,
            case.intent_scope,
        );
    }

    let started = Instant::now();
    let deadline = Duration::from_secs(case.sla_seconds);
    let mut captured_events: Vec<KernelEvent> = Vec::new();
    let mut paused_reason: Option<String> = None;
    let mut auto_resume_count = 0usize;
    let mut duplicate_incident_retry_count = 0usize;
    const MAX_AUTO_APPROVAL_RESUMES: usize = 2;
    const MAX_DUPLICATE_INCIDENT_RETRY_COUNT: usize = 3;

    loop {
        drain_events(&mut event_rx, &mut captured_events);
        let current = read_agent_state(&state, session_id);

        if matches!(current.status, AgentStatus::Completed(_))
            || matches!(current.status, AgentStatus::Failed(_))
        {
            break;
        }
        if started.elapsed() > deadline {
            break;
        }

        match &current.status {
            AgentStatus::Running => {}
            AgentStatus::Paused(reason) => {
                let waiting_for_approval = reason.to_ascii_lowercase().contains("approval");
                if waiting_for_approval && auto_resume_count < MAX_AUTO_APPROVAL_RESUMES {
                    if let Some(request_hash) = current.pending_tool_hash {
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let approval_token = build_approval_token_for_resume(
                            request_hash,
                            now_ms,
                            current.pending_visual_hash,
                        );
                        service
                            .handle_service_call(
                                &mut state,
                                "resume@v1",
                                &codec::to_bytes_canonical(&ResumeAgentParams {
                                    session_id,
                                    approval_token: Some(approval_token),
                                })
                                .map_err(|e| anyhow!("failed to encode resume params: {}", e))?,
                                &mut ctx,
                            )
                            .await?;
                        auto_resume_count = auto_resume_count.saturating_add(1);
                        continue;
                    }
                }
                paused_reason = Some(reason.clone());
                break;
            }
            AgentStatus::Idle | AgentStatus::Terminated => {
                break;
            }
            AgentStatus::Completed(_) | AgentStatus::Failed(_) => {}
        }

        let step_result = service
            .handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(|e| anyhow!("failed to encode step params: {}", e))?,
                &mut ctx,
            )
            .await;
        if let Err(err) = step_result {
            let err_text = err.to_string();
            if err_text.contains("Duplicate incident remedy fingerprint")
                && duplicate_incident_retry_count < MAX_DUPLICATE_INCIDENT_RETRY_COUNT
            {
                duplicate_incident_retry_count =
                    duplicate_incident_retry_count.saturating_add(1);
                continue;
            }
            return Err(err.into());
        }
        duplicate_incident_retry_count = 0;
    }

    drain_events(&mut event_rx, &mut captured_events);
    let elapsed_ms = started.elapsed().as_millis();

    let final_state = read_agent_state(&state, session_id);

    let mut action_tools = BTreeSet::new();
    let mut routing_tools = BTreeSet::new();
    let mut workload_tools = BTreeSet::new();
    let mut verification_checks = BTreeSet::new();
    let mut action_evidence = Vec::new();
    let mut command_history_evidence = Vec::new();
    let mut final_reply = String::new();
    let mut chat_reply_count = 0usize;
    let mut approval_required_events = 0usize;

    for event in &captured_events {
        match event {
            KernelEvent::AgentActionResult {
                tool_name,
                output,
                agent_status,
                ..
            } => {
                action_tools.insert(tool_name.clone());
                if tool_name.starts_with("sys__exec") {
                    if let Some(entry) = extract_command_history_evidence(output) {
                        command_history_evidence.push(entry);
                    }
                }
                action_evidence.push(ActionEvidence {
                    tool_name: tool_name.clone(),
                    agent_status: agent_status.clone(),
                    output_excerpt: truncate_for_log(
                        output,
                        action_output_excerpt_limit(tool_name),
                    ),
                });
                if tool_name == "chat__reply" && agent_status.eq_ignore_ascii_case("completed") {
                    chat_reply_count = chat_reply_count.saturating_add(1);
                    final_reply = output.clone();
                }
            }
            KernelEvent::RoutingReceipt(receipt) => {
                routing_tools.insert(receipt.tool_name.clone());
                for check in &receipt.post_state.verification_checks {
                    verification_checks.insert(check.clone());
                }
                if receipt
                    .policy_decision
                    .eq_ignore_ascii_case("require_approval")
                {
                    approval_required_events = approval_required_events.saturating_add(1);
                }
            }
            KernelEvent::WorkloadReceipt(workload) => {
                if let WorkloadReceipt::WebRetrieve(web) = &workload.receipt {
                    workload_tools.insert(web.tool_name.clone());
                }
            }
            KernelEvent::FirewallInterception { verdict, .. } => {
                if verdict.eq_ignore_ascii_case("require_approval") {
                    approval_required_events = approval_required_events.saturating_add(1);
                }
            }
            _ => {}
        }
    }

    if let Some(reason) = paused_reason {
        if requires_human_intervention(&reason) {
            approval_required_events = approval_required_events.saturating_add(1);
            verification_checks.insert(format!("human_intervention_pause_reason={}", reason));
        } else {
            verification_checks.insert(format!("terminal_pause_reason={}", reason));
        }
    }
    for check in runtime_setup_verification_checks {
        verification_checks.insert(check);
    }
    if let Some(fixture) = vlc_install_fixture.as_ref() {
        for check in vlc_install_fixture_post_run_checks(fixture) {
            verification_checks.insert(check);
        }
    }

    let event_excerpt = captured_events
        .iter()
        .rev()
        .take(24)
        .map(event_summary_line)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    let kernel_log_lines = captured_events
        .iter()
        .map(event_full_line)
        .collect::<Vec<_>>();

    Ok(RunObservation {
        case_id: case.id.to_string(),
        query: run_query,
        run_timestamp_ms,
        run_timestamp_iso_utc: iso_datetime_from_unix_ms(run_timestamp_ms),
        elapsed_ms,
        completed: matches!(final_state.status, AgentStatus::Completed(_)),
        failed: matches!(final_state.status, AgentStatus::Failed(_)),
        final_status: format!("{:?}", final_state.status),
        final_reply,
        chat_reply_count,
        action_tools: action_tools.into_iter().collect(),
        routing_tools: routing_tools.into_iter().collect(),
        workload_tools: workload_tools.into_iter().collect(),
        verification_checks: verification_checks.into_iter().collect(),
        approval_required_events,
        action_evidence,
        command_history_evidence,
        event_excerpt,
        kernel_event_count: captured_events.len(),
        kernel_log_lines,
    })
}
