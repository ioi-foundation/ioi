// Path: crates/cli/tests/agent_live_mail_query_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]
#![recursion_limit = "512"]

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime};
use ioi_cli::testing::build_test_artifacts;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_scs::{SovereignContextStore, StoreConfig};
use ioi_services::agentic::desktop::keys::pii;
use ioi_services::agentic::desktop::keys::AGENT_POLICY_PREFIX;
use ioi_services::agentic::desktop::service::step::helpers::default_safe_policy;
use ioi_services::agentic::desktop::{
    AgentMode, AgentState, AgentStatus, DesktopAgentService, ResumeAgentParams, StartAgentParams,
    StepAgentParams,
};
use ioi_services::wallet_network::{LeaseActionReplayWindowState, WalletNetworkService};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::{
    InferenceOptions, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
};
use ioi_types::app::wallet_network::{
    MailConnectorAuthMode, MailConnectorConfig, MailConnectorEndpoint, MailConnectorProvider,
    MailConnectorSecretAliases, MailConnectorTlsMode, MailConnectorUpsertParams,
    MailListRecentParams, MailListRecentReceipt, MailboxTotalCountParams,
    MailboxTotalCountProvenance, MailboxTotalCountReceipt, SecretKind,
    SessionChannelDelegationRules, SessionChannelEnvelope, SessionChannelMode,
    SessionChannelOrdering, SessionChannelRecord, SessionChannelState, SessionLease,
    SessionLeaseMode, VaultSecretRecord,
};
use ioi_types::app::{
    ActionRequest, ApprovalScope, ApprovalToken, ContextSlice, KernelEvent, PiiApprovalAction,
    RoutingPostStateSummary, RoutingReceiptEvent, RoutingStateSummary, SignatureSuite,
    WorkloadReceipt,
};
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::{ActiveServiceMeta, Capabilities, MethodPermission};
use ioi_types::{codec, error::VmError};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use tokio::sync::broadcast;

use image::{ImageBuffer, ImageFormat, Rgba};

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

#[derive(Debug, Deserialize)]
struct ArbiterVerdict {
    pass: bool,
    confidence: String,
    rationale: String,
    #[serde(default)]
    failures: Vec<String>,
}

// Locked constants inferred once for this run (kept stable):
// - single latest-email intent => one story + one citation floor
// - live mailbox + inference round-trips can exceed 90s under variance; use conservative SLA
const SLA_SECONDS: u64 = 150;
const MIN_SOURCES: usize = 1;
const REQUIRED_STORIES: usize = 1;
const REQUIRED_CITATIONS_PER_STORY: usize = 1;
const CONSECUTIVE_PASS_TARGET: usize = 2;
const GENERALIZATION_VARIANTS: [&str; 3] = [
    "Please read the newest email in my inbox.",
    "What is the most recent email message I received?",
    "Summarize the latest email that arrived in my mailbox.",
];

const PRIMARY_QUERY: &str = "Read me the last email I received.";
const PRIMARY_WRITE_INTENT_QUERY: &str =
    "Reply to my latest email: thank the sender and say I will follow up tomorrow.";
const PRIMARY_LARGE_VOLUME_QUERY: &str =
    "Analyze the 120 most recent emails, classify high-confidence spam candidates, and summarize priority communications.";
const PRIMARY_DELETE_SPAM_QUERY: &str =
    "Delete high-confidence spam messages from my spam mailbox and summarize what was removed.";
const PRIMARY_CLEANUP_INBOX_QUERY: &str =
    "Clean my inbox of marketing mail, keep transactional/personal.";
const MAX_TERMINAL_CHAT_REPLY_EVENTS: usize = 1;
// Mailbox read paraphrases can require multiple gated tool invocations before terminal synthesis.
const MAX_APPROVAL_RESUME_ATTEMPTS: usize = 6;
const APPROVAL_TOKEN_TTL_MS: u64 = 300_000;
const CHURN_REPEAT_THRESHOLD: usize = 3;
const LARGE_VOLUME_PARSE_CONFIDENCE_FLOOR_BPS: u16 = 8_200;
const LARGE_VOLUME_MIN_EVALUATED_DEFAULT: u32 = 10;
const CLEANUP_COUNT_SAMPLE_LIMIT_DEFAULT: u32 = 100;
const CLEANUP_SLA_SECONDS: u64 = 210;
const QUERY_LITERAL_GATING_PATTERNS: [&str; 2] = [
    "read me the last email i received",
    "please read the newest email in my inbox",
];
const STATIC_AUDIT_FILES: [&str; 4] = [
    "crates/services/src/agentic/desktop/service/step/cognition.rs",
    "crates/services/src/agentic/desktop/service/step/intent_resolver.rs",
    "crates/services/src/agentic/desktop/service/step/queue/support/mod.rs",
    "crates/services/src/agentic/desktop/service/step/queue/processing/mod.rs",
];

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

fn seed_wallet_network_mail_service_meta(state: &mut IAVLTree<HashCommitmentScheme>) {
    let mut methods = BTreeMap::new();
    methods.insert("mail_read_latest@v1".to_string(), MethodPermission::User);
    methods.insert("mail_list_recent@v1".to_string(), MethodPermission::User);
    methods.insert("mailbox_total_count@v1".to_string(), MethodPermission::User);
    methods.insert("mail_delete_spam@v1".to_string(), MethodPermission::User);
    methods.insert("mail_reply@v1".to_string(), MethodPermission::User);

    let meta = ActiveServiceMeta {
        id: "wallet_network".to_string(),
        abi_version: 1,
        state_schema: "wallet-network/v1".to_string(),
        caps: Capabilities::empty(),
        artifact_hash: [0u8; 32],
        activated_at: 1,
        methods,
        allowed_system_prefixes: vec![],
        generation_id: 0,
        parent_hash: None,
        author: None,
        context_filter: None,
    };

    let key = active_service_key("wallet_network");
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&meta).expect("active service meta encode"),
        )
        .expect("active service meta insert should not fail");
}

fn channel_storage_key(channel_id: &[u8; 32]) -> Vec<u8> {
    [b"channel::".as_slice(), channel_id.as_slice()].concat()
}

fn lease_storage_key(channel_id: &[u8; 32], lease_id: &[u8; 32]) -> Vec<u8> {
    [
        b"lease::".as_slice(),
        channel_id.as_slice(),
        b"::",
        lease_id.as_slice(),
    ]
    .concat()
}

fn lease_action_window_storage_key(channel_id: &[u8; 32], lease_id: &[u8; 32]) -> Vec<u8> {
    [
        b"lease_action_window::".as_slice(),
        channel_id.as_slice(),
        b"::".as_slice(),
        lease_id.as_slice(),
    ]
    .concat()
}

fn mail_list_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [b"mail_list_receipt::".as_slice(), operation_id.as_slice()].concat()
}

fn mail_count_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [b"mail_count_receipt::".as_slice(), operation_id.as_slice()].concat()
}

fn read_required_env(key: &str) -> Result<String> {
    std::env::var(key).map_err(|_| anyhow!("{} is required for live mail e2e", key))
}

fn read_optional_env(key: &str, default_value: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default_value.to_string())
}

fn read_optional_nonempty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_optional_u32_env(key: &str, default_value: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(default_value)
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn refresh_block_timestamp(ctx: &mut TxContext<'_>) {
    ctx.block_timestamp = now_unix_ns();
}

fn parse_mail_auth_mode(value: &str, key: &str) -> Result<MailConnectorAuthMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "password" | "pass" => Ok(MailConnectorAuthMode::Password),
        "oauth2" | "xoauth2" | "oauth" => Ok(MailConnectorAuthMode::Oauth2),
        other => Err(anyhow!(
            "{} must be one of password|oauth2 (got '{}')",
            key,
            other
        )),
    }
}

fn infer_mail_auth_mode() -> Result<MailConnectorAuthMode> {
    if let Some(raw) = read_optional_nonempty_env("MAIL_E2E_AUTH_MODE") {
        return parse_mail_auth_mode(&raw, "MAIL_E2E_AUTH_MODE");
    }
    let has_password = read_optional_nonempty_env("MAIL_E2E_IMAP_PASSWORD").is_some()
        || read_optional_nonempty_env("MAIL_E2E_SMTP_PASSWORD").is_some();
    let has_bearer = read_optional_nonempty_env("MAIL_E2E_IMAP_BEARER_TOKEN").is_some()
        || read_optional_nonempty_env("MAIL_E2E_SMTP_BEARER_TOKEN").is_some();
    if has_bearer && !has_password {
        Ok(MailConnectorAuthMode::Oauth2)
    } else {
        Ok(MailConnectorAuthMode::Password)
    }
}

fn parse_mail_tls_mode(value: &str, key: &str) -> Result<MailConnectorTlsMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "plaintext" => Ok(MailConnectorTlsMode::Plaintext),
        "starttls" => Ok(MailConnectorTlsMode::StartTls),
        "tls" => Ok(MailConnectorTlsMode::Tls),
        other => Err(anyhow!(
            "{} must be one of plaintext|starttls|tls (got '{}')",
            key,
            other
        )),
    }
}

fn normalize_mailbox(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "primary".to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

async fn seed_wallet_mail_runtime_state(
    wallet_service: &WalletNetworkService,
    state: &mut IAVLTree<HashCommitmentScheme>,
    ctx: &mut TxContext<'_>,
    channel_id: [u8; 32],
    lease_id: [u8; 32],
) -> Result<()> {
    let account_email = read_required_env("MAIL_E2E_ACCOUNT_EMAIL")?;
    let imap_host = read_required_env("MAIL_E2E_IMAP_HOST")?;
    let imap_port = read_required_env("MAIL_E2E_IMAP_PORT")?
        .parse::<u16>()
        .map_err(|e| anyhow!("MAIL_E2E_IMAP_PORT must be a valid u16: {}", e))?;
    let smtp_host = read_required_env("MAIL_E2E_SMTP_HOST")?;
    let smtp_port = read_required_env("MAIL_E2E_SMTP_PORT")?
        .parse::<u16>()
        .map_err(|e| anyhow!("MAIL_E2E_SMTP_PORT must be a valid u16: {}", e))?;

    let imap_tls_mode = parse_mail_tls_mode(
        &read_optional_env("MAIL_E2E_IMAP_TLS_MODE", "tls"),
        "MAIL_E2E_IMAP_TLS_MODE",
    )?;
    let smtp_tls_mode = parse_mail_tls_mode(
        &read_optional_env("MAIL_E2E_SMTP_TLS_MODE", "starttls"),
        "MAIL_E2E_SMTP_TLS_MODE",
    )?;

    let mailbox = normalize_mailbox(read_optional_env("MAIL_E2E_MAILBOX", "primary").as_str());
    let auth_mode = infer_mail_auth_mode()?;

    let imap_username_alias =
        read_optional_env("MAIL_E2E_IMAP_USERNAME_ALIAS", "mail.imap.username")
            .to_ascii_lowercase();
    let smtp_username_alias =
        read_optional_env("MAIL_E2E_SMTP_USERNAME_ALIAS", "mail.smtp.username")
            .to_ascii_lowercase();
    let (
        imap_secret_alias,
        smtp_secret_alias,
        imap_secret_id,
        smtp_secret_id,
        imap_secret,
        smtp_secret,
    ) = match auth_mode {
        MailConnectorAuthMode::Password => (
            read_optional_env("MAIL_E2E_IMAP_PASSWORD_ALIAS", "mail.imap.password")
                .to_ascii_lowercase(),
            read_optional_env("MAIL_E2E_SMTP_PASSWORD_ALIAS", "mail.smtp.password")
                .to_ascii_lowercase(),
            read_optional_env("MAIL_E2E_IMAP_PASSWORD_SECRET_ID", "mail-imap-password"),
            read_optional_env("MAIL_E2E_SMTP_PASSWORD_SECRET_ID", "mail-smtp-password"),
            read_required_env("MAIL_E2E_IMAP_PASSWORD")?,
            read_required_env("MAIL_E2E_SMTP_PASSWORD")?,
        ),
        MailConnectorAuthMode::Oauth2 => (
            read_optional_env("MAIL_E2E_IMAP_BEARER_TOKEN_ALIAS", "mail.imap.bearer_token")
                .to_ascii_lowercase(),
            read_optional_env("MAIL_E2E_SMTP_BEARER_TOKEN_ALIAS", "mail.smtp.bearer_token")
                .to_ascii_lowercase(),
            read_optional_env(
                "MAIL_E2E_IMAP_BEARER_TOKEN_SECRET_ID",
                "mail-imap-bearer-token",
            ),
            read_optional_env(
                "MAIL_E2E_SMTP_BEARER_TOKEN_SECRET_ID",
                "mail-smtp-bearer-token",
            ),
            read_required_env("MAIL_E2E_IMAP_BEARER_TOKEN")?,
            read_required_env("MAIL_E2E_SMTP_BEARER_TOKEN")?,
        ),
    };

    let secret_specs = [
        (
            read_optional_env("MAIL_E2E_IMAP_USERNAME_SECRET_ID", "mail-imap-username"),
            imap_username_alias.clone(),
            read_required_env("MAIL_E2E_IMAP_USERNAME")?,
        ),
        (imap_secret_id, imap_secret_alias.clone(), imap_secret),
        (
            read_optional_env("MAIL_E2E_SMTP_USERNAME_SECRET_ID", "mail-smtp-username"),
            smtp_username_alias.clone(),
            read_required_env("MAIL_E2E_SMTP_USERNAME")?,
        ),
        (smtp_secret_id, smtp_secret_alias.clone(), smtp_secret),
    ];

    let now_ms = ctx.block_timestamp / 1_000_000;
    for (secret_id, alias, value) in secret_specs {
        let secret = VaultSecretRecord {
            secret_id,
            alias,
            kind: SecretKind::AccessToken,
            ciphertext: value.into_bytes(),
            metadata: BTreeMap::new(),
            created_at_ms: now_ms,
            rotated_at_ms: None,
        };
        wallet_service
            .handle_service_call(
                state,
                "store_secret_record@v1",
                &codec::to_bytes_canonical(&secret)
                    .map_err(|e| anyhow!("failed to encode wallet secret record: {}", e))?,
                ctx,
            )
            .await?;
    }

    let connector_config = MailConnectorConfig {
        provider: MailConnectorProvider::ImapSmtp,
        auth_mode,
        account_email,
        imap: MailConnectorEndpoint {
            host: imap_host,
            port: imap_port,
            tls_mode: imap_tls_mode,
        },
        smtp: MailConnectorEndpoint {
            host: smtp_host,
            port: smtp_port,
            tls_mode: smtp_tls_mode,
        },
        secret_aliases: MailConnectorSecretAliases {
            imap_username_alias,
            imap_password_alias: imap_secret_alias,
            smtp_username_alias,
            smtp_password_alias: smtp_secret_alias,
        },
        metadata: BTreeMap::new(),
    };

    let mut connector_mailboxes = BTreeSet::new();
    connector_mailboxes.insert(mailbox);
    connector_mailboxes.insert("primary".to_string());
    connector_mailboxes.insert("spam".to_string());

    for connector_mailbox in connector_mailboxes {
        let connector = MailConnectorUpsertParams {
            mailbox: connector_mailbox,
            config: connector_config.clone(),
        };
        wallet_service
            .handle_service_call(
                state,
                "mail_connector_upsert@v1",
                &codec::to_bytes_canonical(&connector)
                    .map_err(|e| anyhow!("failed to encode mail connector upsert params: {}", e))?,
                ctx,
            )
            .await?;
    }

    let channel = SessionChannelRecord {
        envelope: SessionChannelEnvelope {
            channel_id,
            lc_id: [0x31; 32],
            rc_id: [0x32; 32],
            ordering: SessionChannelOrdering::Ordered,
            mode: SessionChannelMode::RemoteRequestLocalExecution,
            policy_hash: [0x33; 32],
            policy_version: 1,
            root_grant_id: [0x34; 32],
            capability_set: vec!["email:read".to_string(), "mail.write".to_string()],
            constraints: BTreeMap::new(),
            delegation_rules: SessionChannelDelegationRules {
                max_depth: 0,
                can_redelegate: false,
                issuance_budget: None,
            },
            revocation_epoch: 0,
            expires_at_ms: now_ms.saturating_add(86_400_000),
        },
        state: SessionChannelState::Open,
        envelope_hash: [0x35; 32],
        opened_at_ms: Some(now_ms),
        closed_at_ms: None,
        last_seq: 0,
        close_reason: None,
    };
    state.insert(
        &channel_storage_key(&channel_id),
        &codec::to_bytes_canonical(&channel)
            .map_err(|e| anyhow!("failed to encode wallet channel record: {}", e))?,
    )?;

    let lease = SessionLease {
        lease_id,
        channel_id,
        issuer_id: [0x36; 32],
        subject_id: [0x37; 32],
        policy_hash: [0x33; 32],
        grant_id: [0x38; 32],
        capability_subset: vec!["email:read".to_string(), "mail.write".to_string()],
        constraints_subset: BTreeMap::new(),
        mode: SessionLeaseMode::Lease,
        expires_at_ms: now_ms.saturating_add(86_400_000),
        revocation_epoch: 0,
        audience: ctx.signer_account_id.0,
        nonce: [0x39; 32],
        counter: 1,
        issued_at_ms: now_ms,
        sig_hybrid_lc: Vec::new(),
    };
    state.insert(
        &lease_storage_key(&channel_id, &lease_id),
        &codec::to_bytes_canonical(&lease)
            .map_err(|e| anyhow!("failed to encode wallet lease record: {}", e))?,
    )?;

    Ok(())
}

fn next_mail_op_seq_for_lease(
    state: &IAVLTree<HashCommitmentScheme>,
    channel_id: [u8; 32],
    lease_id: [u8; 32],
) -> u64 {
    state
        .get(&lease_action_window_storage_key(&channel_id, &lease_id))
        .ok()
        .flatten()
        .and_then(|bytes| codec::from_bytes_canonical::<LeaseActionReplayWindowState>(&bytes).ok())
        .map(|window| window.highest_seq.saturating_add(1).max(1))
        .unwrap_or(1)
}

#[derive(Debug, Clone, Copy)]
struct MailboxCountSnapshot {
    sampled_count: u32,
    list_reported_total_count: u32,
}

#[derive(Debug, Clone)]
struct MailboxTotalCountSnapshot {
    mailbox_total_count: u32,
    provenance: MailboxTotalCountProvenance,
}

fn is_count_provenance_fresh(marker: &str) -> bool {
    marker.trim().eq_ignore_ascii_case("status_exists_fresh")
}

fn is_count_provenance_stale(marker: &str) -> bool {
    let normalized = marker.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "status_exists_reconciled" | "fallback_no_status" | "fallback_status_zero"
    )
}

fn count_provenance_raw_observation_present(provenance: &MailboxTotalCountProvenance) -> bool {
    provenance.status_exists.is_some()
        || provenance.select_exists.is_some()
        || provenance.uid_search_count.is_some()
        || provenance.search_count.is_some()
}

async fn mailbox_message_count_via_wallet_list(
    wallet_service: &WalletNetworkService,
    state: &mut IAVLTree<HashCommitmentScheme>,
    ctx: &mut TxContext<'_>,
    channel_id: [u8; 32],
    lease_id: [u8; 32],
    mailbox: &str,
    limit: u32,
    operation_id: [u8; 32],
) -> Result<MailboxCountSnapshot> {
    refresh_block_timestamp(ctx);
    let params = MailListRecentParams {
        operation_id,
        channel_id,
        lease_id,
        op_seq: next_mail_op_seq_for_lease(state, channel_id, lease_id),
        op_nonce: Some(operation_id),
        mailbox: normalize_mailbox(mailbox),
        limit,
        requested_at_ms: ctx.block_timestamp / 1_000_000,
    };
    wallet_service
        .handle_service_call(
            state,
            "mail_list_recent@v1",
            &codec::to_bytes_canonical(&params)
                .map_err(|e| anyhow!("failed to encode MailListRecentParams: {}", e))?,
            ctx,
        )
        .await?;

    let receipt_bytes = state
        .get(&mail_list_receipt_storage_key(&operation_id))
        .map_err(|e| anyhow!("failed to read mail_list_recent receipt state: {}", e))?
        .ok_or_else(|| anyhow!("mail_list_recent receipt missing after invocation"))?;
    let receipt: MailListRecentReceipt = codec::from_bytes_canonical(&receipt_bytes)
        .map_err(|e| anyhow!("failed to decode MailListRecentReceipt: {}", e))?;
    let sampled_count = receipt.messages.len().min(u32::MAX as usize) as u32;
    let list_reported_total_count = if receipt.mailbox_total_count == 0 {
        sampled_count
    } else {
        receipt.mailbox_total_count
    };
    Ok(MailboxCountSnapshot {
        sampled_count,
        list_reported_total_count,
    })
}

async fn optional_mailbox_message_count_via_wallet_list(
    wallet_service: &WalletNetworkService,
    state: &mut IAVLTree<HashCommitmentScheme>,
    ctx: &mut TxContext<'_>,
    channel_id: [u8; 32],
    lease_id: [u8; 32],
    mailbox: &str,
    limit: u32,
    operation_id: [u8; 32],
) -> Result<Option<MailboxCountSnapshot>> {
    match mailbox_message_count_via_wallet_list(
        wallet_service,
        state,
        ctx,
        channel_id,
        lease_id,
        mailbox,
        limit,
        operation_id,
    )
    .await
    {
        Ok(count) => Ok(Some(count)),
        Err(error) => {
            let lower = error.to_string().to_ascii_lowercase();
            if lower.contains("imap select")
                || lower.contains("folder does not exist")
                || lower.contains("not an allowed spam/junk target")
            {
                Ok(None)
            } else {
                Err(error)
            }
        }
    }
}

async fn mailbox_total_count_via_wallet_count(
    wallet_service: &WalletNetworkService,
    state: &mut IAVLTree<HashCommitmentScheme>,
    ctx: &mut TxContext<'_>,
    channel_id: [u8; 32],
    lease_id: [u8; 32],
    mailbox: &str,
    operation_id: [u8; 32],
) -> Result<MailboxTotalCountSnapshot> {
    refresh_block_timestamp(ctx);
    let params = MailboxTotalCountParams {
        operation_id,
        channel_id,
        lease_id,
        op_seq: next_mail_op_seq_for_lease(state, channel_id, lease_id),
        op_nonce: Some(operation_id),
        mailbox: normalize_mailbox(mailbox),
        requested_at_ms: ctx.block_timestamp / 1_000_000,
    };
    wallet_service
        .handle_service_call(
            state,
            "mailbox_total_count@v1",
            &codec::to_bytes_canonical(&params)
                .map_err(|e| anyhow!("failed to encode MailboxTotalCountParams: {}", e))?,
            ctx,
        )
        .await?;

    let receipt_bytes = state
        .get(&mail_count_receipt_storage_key(&operation_id))
        .map_err(|e| anyhow!("failed to read mailbox_total_count receipt state: {}", e))?
        .ok_or_else(|| anyhow!("mailbox_total_count receipt missing after invocation"))?;
    let receipt: MailboxTotalCountReceipt = codec::from_bytes_canonical(&receipt_bytes)
        .map_err(|e| anyhow!("failed to decode MailboxTotalCountReceipt: {}", e))?;
    let mailbox_total_count = receipt.mailbox_total_count.max(
        receipt
            .provenance
            .status_exists
            .or(receipt.provenance.select_exists)
            .or(receipt.provenance.uid_search_count)
            .or(receipt.provenance.search_count)
            .unwrap_or(0),
    );
    Ok(MailboxTotalCountSnapshot {
        mailbox_total_count,
        provenance: receipt.provenance,
    })
}

async fn optional_mailbox_total_count_via_wallet_count(
    wallet_service: &WalletNetworkService,
    state: &mut IAVLTree<HashCommitmentScheme>,
    ctx: &mut TxContext<'_>,
    channel_id: [u8; 32],
    lease_id: [u8; 32],
    mailbox: &str,
    operation_id: [u8; 32],
) -> Result<Option<MailboxTotalCountSnapshot>> {
    match mailbox_total_count_via_wallet_count(
        wallet_service,
        state,
        ctx,
        channel_id,
        lease_id,
        mailbox,
        operation_id,
    )
    .await
    {
        Ok(snapshot) => Ok(Some(snapshot)),
        Err(error) => {
            let lower = error.to_string().to_ascii_lowercase();
            if lower.contains("imap select")
                || lower.contains("folder does not exist")
                || lower.contains("not an allowed spam/junk target")
            {
                Ok(None)
            } else {
                Err(error)
            }
        }
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

fn seed_resolved_intent(
    state: &mut IAVLTree<HashCommitmentScheme>,
    session_id: [u8; 32],
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
        intent_id: "web.research".to_string(),
        scope,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![],
        preferred_tier: "tool_first".to_string(),
        matrix_version: "test".to_string(),
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
    rules.ontology_policy.intent_routing.shadow_mode = true;
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

fn is_url_like(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("imap://")
        || lower.starts_with("mailto:")
}

fn is_mail_connector_tool_name(tool_name: &str) -> bool {
    let normalized = tool_name.trim().to_ascii_lowercase();
    normalized.starts_with("wallet_network__mail_")
        || normalized.starts_with("wallet_mail_")
        || normalized.starts_with("mail__")
}

fn extract_urls(text: &str) -> BTreeSet<String> {
    text.split_whitespace()
        .filter_map(|token| {
            let trimmed = token
                .trim_matches(|ch: char| ",.;:!?()[]}\"'".contains(ch))
                .trim();
            if is_url_like(trimmed) {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn contains_absolute_utc_datetime(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return false;
    }
    for i in 0..=bytes.len() - 20 {
        let s = &bytes[i..i + 20];
        let ok = s[0].is_ascii_digit()
            && s[1].is_ascii_digit()
            && s[2].is_ascii_digit()
            && s[3].is_ascii_digit()
            && s[4] == b'-'
            && s[5].is_ascii_digit()
            && s[6].is_ascii_digit()
            && s[7] == b'-'
            && s[8].is_ascii_digit()
            && s[9].is_ascii_digit()
            && s[10] == b'T'
            && s[11].is_ascii_digit()
            && s[12].is_ascii_digit()
            && s[13] == b':'
            && s[14].is_ascii_digit()
            && s[15].is_ascii_digit()
            && s[16] == b':'
            && s[17].is_ascii_digit()
            && s[18].is_ascii_digit()
            && s[19] == b'Z';
        if ok {
            return true;
        }
    }
    false
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

#[derive(Default, Debug, Clone)]
struct StorySection {
    has_direct_mail_result: bool,
    has_access_limitation: bool,
    has_actionable_next_step: bool,
    citation_count: usize,
    citation_with_datetime_count: usize,
    unique_citation_urls: BTreeSet<String>,
    has_confidence: bool,
    has_caveat: bool,
}

#[derive(Default, Debug, Clone)]
struct MailToolStructuredEvidence {
    citation_urls: BTreeSet<String>,
    has_executed_at_utc: bool,
    has_message_from: bool,
    has_message_subject: bool,
    has_message_received_at_ms: bool,
    has_spam_confidence_fields: bool,
    has_high_confidence_candidate_metric: bool,
    max_parse_confidence_bps: u16,
    max_evaluated_count: u32,
    max_returned_count: u32,
    max_high_confidence_spam_candidates: u32,
    saw_medium_or_large_volume_band: bool,
    saw_delete_high_confidence_policy: bool,
    max_deleted_count: u32,
    max_high_confidence_deleted_count: u32,
    max_mailbox_total_count_before: u32,
    max_mailbox_total_count_after: u32,
    max_mailbox_total_count_delta: u32,
    saw_delete_spam_tool_output: bool,
    saw_primary_cleanup_scope: bool,
    saw_preservation_evidence: bool,
    saw_kept_vs_deleted_rationale: bool,
    saw_preservation_accounting_consistent: bool,
    saw_explicit_preserved_reason_classes: bool,
    max_preserved_transactional_or_personal_count: u32,
    max_preserved_trusted_system_count: u32,
    max_preserved_low_confidence_other_count: u32,
    max_preserved_due_to_delete_cap_count: u32,
    max_total_preserved_count: u32,
}

fn parse_mail_tool_output_evidence(output: &str, evidence: &mut MailToolStructuredEvidence) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(output) else {
        return;
    };
    if let Some(citation) = value.get("citation").and_then(|v| v.as_str()) {
        for url in extract_urls(citation) {
            evidence.citation_urls.insert(url);
        }
    }
    if let Some(executed_at) = value.get("executed_at_utc").and_then(|v| v.as_str()) {
        if contains_absolute_utc_datetime(executed_at) {
            evidence.has_executed_at_utc = true;
        }
    }

    if let Some(message) = value.get("message").and_then(|v| v.as_object()) {
        evidence.has_message_from |= message
            .get("from")
            .and_then(|v| v.as_str())
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        evidence.has_message_subject |= message
            .get("subject")
            .and_then(|v| v.as_str())
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let has_received_at_ms = message
            .get("received_at_ms")
            .and_then(|v| v.as_u64())
            .map(|v| v > 0)
            .unwrap_or(false);
        let has_received_at_utc = message
            .get("received_at_utc")
            .and_then(|v| v.as_str())
            .map(contains_absolute_utc_datetime)
            .unwrap_or(false);
        evidence.has_message_received_at_ms |= has_received_at_ms || has_received_at_utc;
        evidence.has_spam_confidence_fields |= message
            .get("spam_confidence_bps")
            .and_then(|v| v.as_u64())
            .is_some();
        if let Some(tags) = message.get("spam_signal_tags").and_then(|v| v.as_array()) {
            evidence.has_spam_confidence_fields |= !tags.is_empty();
        }
    }

    if let Some(messages) = value.get("messages").and_then(|v| v.as_array()) {
        for entry in messages {
            if let Some(message) = entry.as_object() {
                evidence.has_message_from |= message
                    .get("from")
                    .and_then(|v| v.as_str())
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false);
                evidence.has_message_subject |= message
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false);
                let has_received_at_ms = message
                    .get("received_at_ms")
                    .and_then(|v| v.as_u64())
                    .map(|v| v > 0)
                    .unwrap_or(false);
                let has_received_at_utc = message
                    .get("received_at_utc")
                    .and_then(|v| v.as_str())
                    .map(contains_absolute_utc_datetime)
                    .unwrap_or(false);
                evidence.has_message_received_at_ms |= has_received_at_ms || has_received_at_utc;
                evidence.has_spam_confidence_fields |= message
                    .get("spam_confidence_bps")
                    .and_then(|v| v.as_u64())
                    .is_some();
                if let Some(tags) = message.get("spam_signal_tags").and_then(|v| v.as_array()) {
                    evidence.has_spam_confidence_fields |= !tags.is_empty();
                }
                if let Some(citation) = message.get("citation").and_then(|v| v.as_str()) {
                    for url in extract_urls(citation) {
                        evidence.citation_urls.insert(url);
                    }
                }
            }
        }
    }

    if let Some(analysis) = value.get("analysis").and_then(|v| v.as_object()) {
        if let Some(parse_confidence_bps) = analysis
            .get("parse_confidence_bps")
            .and_then(|v| v.as_u64())
        {
            evidence.max_parse_confidence_bps = evidence
                .max_parse_confidence_bps
                .max(parse_confidence_bps.min(u16::MAX as u64) as u16);
        }
        if let Some(evaluated_count) = analysis.get("evaluated_count").and_then(|v| v.as_u64()) {
            evidence.max_evaluated_count = evidence
                .max_evaluated_count
                .max(evaluated_count.min(u32::MAX as u64) as u32);
        }
        if let Some(returned_count) = analysis.get("returned_count").and_then(|v| v.as_u64()) {
            evidence.max_returned_count = evidence
                .max_returned_count
                .max(returned_count.min(u32::MAX as u64) as u32);
        }
        if let Some(spam_candidates) = analysis
            .get("high_confidence_spam_candidates")
            .and_then(|v| v.as_u64())
        {
            evidence.has_high_confidence_candidate_metric = true;
            evidence.max_high_confidence_spam_candidates = evidence
                .max_high_confidence_spam_candidates
                .max(spam_candidates.min(u32::MAX as u64) as u32);
        }
        if let Some(volume_band) = analysis.get("parse_volume_band").and_then(|v| v.as_str()) {
            let lower = volume_band.to_ascii_lowercase();
            if lower == "medium" || lower == "large" {
                evidence.saw_medium_or_large_volume_band = true;
            }
        }
    }

    if let Some(classification_policy) = value
        .get("classification_policy")
        .and_then(|v| v.as_object())
    {
        let mode_is_high_confidence = classification_policy
            .get("mode")
            .and_then(|v| v.as_str())
            .map(|mode| {
                let normalized = mode.trim().to_ascii_lowercase();
                normalized.starts_with("high_confidence_")
            })
            .unwrap_or(false);
        let threshold_present = classification_policy
            .get("spam_confidence_threshold_bps")
            .and_then(|v| v.as_u64())
            .map(|value| value > 0)
            .unwrap_or(false);
        evidence.saw_delete_high_confidence_policy |= mode_is_high_confidence && threshold_present;
    };

    if let Some(cleanup_scope) = value.get("cleanup_scope").and_then(|v| v.as_str()) {
        evidence.saw_primary_cleanup_scope |= cleanup_scope.eq_ignore_ascii_case("primary_inbox");
    }

    if let Some(deleted_count) = value.get("deleted_count").and_then(|v| v.as_u64()) {
        evidence.saw_delete_spam_tool_output = true;
        evidence.max_deleted_count = evidence
            .max_deleted_count
            .max(deleted_count.min(u32::MAX as u64) as u32);
    }
    if let Some(high_confidence_deleted_count) = value
        .get("high_confidence_deleted_count")
        .and_then(|v| v.as_u64())
    {
        evidence.saw_delete_spam_tool_output = true;
        evidence.max_high_confidence_deleted_count = evidence
            .max_high_confidence_deleted_count
            .max(high_confidence_deleted_count.min(u32::MAX as u64) as u32);
    }
    if let Some(mailbox_total_count_before) = value
        .get("mailbox_total_count_before")
        .and_then(|v| v.as_u64())
    {
        evidence.max_mailbox_total_count_before = evidence
            .max_mailbox_total_count_before
            .max(mailbox_total_count_before.min(u32::MAX as u64) as u32);
    }
    if let Some(mailbox_total_count_after) = value
        .get("mailbox_total_count_after")
        .and_then(|v| v.as_u64())
    {
        evidence.max_mailbox_total_count_after = evidence
            .max_mailbox_total_count_after
            .max(mailbox_total_count_after.min(u32::MAX as u64) as u32);
    }
    if let Some(mailbox_total_count_delta) = value
        .get("mailbox_total_count_delta")
        .and_then(|v| v.as_u64())
    {
        evidence.max_mailbox_total_count_delta = evidence
            .max_mailbox_total_count_delta
            .max(mailbox_total_count_delta.min(u32::MAX as u64) as u32);
    }

    let mut preserved_transactional_or_personal_count = value
        .get("preserved_transactional_or_personal_count")
        .and_then(|v| v.as_u64())
        .map(|value| value.min(u32::MAX as u64) as u32)
        .unwrap_or(0);
    let mut preserved_trusted_system_count = value
        .get("preserved_trusted_system_count")
        .and_then(|v| v.as_u64())
        .map(|value| value.min(u32::MAX as u64) as u32)
        .unwrap_or(0);
    let mut preserved_low_confidence_other_count = value
        .get("preserved_low_confidence_other_count")
        .and_then(|v| v.as_u64())
        .map(|value| value.min(u32::MAX as u64) as u32)
        .unwrap_or(0);
    let mut preserved_due_to_delete_cap_count = value
        .get("preserved_due_to_delete_cap_count")
        .and_then(|v| v.as_u64())
        .map(|value| value.min(u32::MAX as u64) as u32)
        .unwrap_or(0);
    let mut total_preserved_count = value
        .get("total_preserved_count")
        .and_then(|v| v.as_u64())
        .map(|value| value.min(u32::MAX as u64) as u32)
        .unwrap_or(0);
    let mut preserved_reason_has_transactional_or_personal = false;
    let mut preserved_reason_has_trusted_system_sender = false;
    if let Some(reason_counts) = value
        .get("preserved_reason_counts")
        .and_then(|v| v.as_object())
    {
        if reason_counts
            .get("transactional_or_personal")
            .and_then(|v| v.as_u64())
            .is_some()
        {
            preserved_reason_has_transactional_or_personal = true;
        }
        if reason_counts
            .get("trusted_system_sender")
            .and_then(|v| v.as_u64())
            .is_some()
        {
            preserved_reason_has_trusted_system_sender = true;
        }
    }
    let mut preserve_modes_contains_transactional_or_personal = false;
    if let Some(preservation_evidence) = value
        .get("preservation_evidence")
        .and_then(|v| v.as_object())
    {
        evidence.saw_preservation_evidence = true;
        if let Some(value) = preservation_evidence
            .get("transactional_or_personal_count")
            .and_then(|v| v.as_u64())
        {
            preserved_transactional_or_personal_count = value.min(u32::MAX as u64) as u32;
        }
        if let Some(value) = preservation_evidence
            .get("trusted_system_sender_count")
            .and_then(|v| v.as_u64())
        {
            preserved_trusted_system_count = value.min(u32::MAX as u64) as u32;
        }
        if let Some(value) = preservation_evidence
            .get("low_confidence_other_count")
            .and_then(|v| v.as_u64())
        {
            preserved_low_confidence_other_count = value.min(u32::MAX as u64) as u32;
        }
        if let Some(value) = preservation_evidence
            .get("due_to_delete_cap_count")
            .and_then(|v| v.as_u64())
        {
            preserved_due_to_delete_cap_count = value.min(u32::MAX as u64) as u32;
        }
        if let Some(value) = preservation_evidence
            .get("total_preserved_count")
            .and_then(|v| v.as_u64())
        {
            total_preserved_count = value.min(u32::MAX as u64) as u32;
        }
        if let Some(reason_counts) = preservation_evidence
            .get("reason_counts")
            .and_then(|v| v.as_object())
        {
            if reason_counts
                .get("transactional_or_personal")
                .and_then(|v| v.as_u64())
                .is_some()
            {
                preserved_reason_has_transactional_or_personal = true;
            }
            if reason_counts
                .get("trusted_system_sender")
                .and_then(|v| v.as_u64())
                .is_some()
            {
                preserved_reason_has_trusted_system_sender = true;
            }
        }
        preserve_modes_contains_transactional_or_personal = preservation_evidence
            .get("preserve_modes")
            .and_then(|v| v.as_array())
            .map(|modes| {
                modes.iter().any(|mode| {
                    mode.as_str()
                        .map(|text| text.eq_ignore_ascii_case("transactional_or_personal"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
    }

    let saw_any_preserved_field = value
        .get("preserved_transactional_or_personal_count")
        .is_some()
        || value.get("preserved_trusted_system_count").is_some()
        || value.get("preserved_low_confidence_other_count").is_some()
        || value.get("preserved_due_to_delete_cap_count").is_some()
        || value.get("total_preserved_count").is_some();
    evidence.saw_preservation_evidence |= saw_any_preserved_field;
    evidence.max_preserved_transactional_or_personal_count = evidence
        .max_preserved_transactional_or_personal_count
        .max(preserved_transactional_or_personal_count);
    evidence.max_preserved_trusted_system_count = evidence
        .max_preserved_trusted_system_count
        .max(preserved_trusted_system_count);
    evidence.max_preserved_low_confidence_other_count = evidence
        .max_preserved_low_confidence_other_count
        .max(preserved_low_confidence_other_count);
    evidence.max_preserved_due_to_delete_cap_count = evidence
        .max_preserved_due_to_delete_cap_count
        .max(preserved_due_to_delete_cap_count);
    evidence.max_total_preserved_count = evidence
        .max_total_preserved_count
        .max(total_preserved_count);

    let preserved_sum = preserved_transactional_or_personal_count
        .saturating_add(preserved_trusted_system_count)
        .saturating_add(preserved_low_confidence_other_count)
        .saturating_add(preserved_due_to_delete_cap_count);
    if saw_any_preserved_field && total_preserved_count >= preserved_sum {
        evidence.saw_preservation_accounting_consistent = true;
    }
    evidence.saw_explicit_preserved_reason_classes |= preserved_reason_has_transactional_or_personal
        && preserved_reason_has_trusted_system_sender;
    evidence.saw_kept_vs_deleted_rationale |= preserve_modes_contains_transactional_or_personal
        || value
            .get("classification_policy")
            .and_then(|v| v.get("mode"))
            .and_then(|v| v.as_str())
            .map(|mode| {
                mode.eq_ignore_ascii_case(
                    "high_confidence_unwanted_preserve_transactional_personal",
                )
            })
            .unwrap_or(false);
}

fn parse_story_sections(reply: &str) -> Vec<StorySection> {
    let mut section = StorySection::default();
    let lower = reply.to_ascii_lowercase();

    let has_from = lower.contains("from:");
    let has_subject = lower.contains("subject:");
    let has_received = lower.contains("received") && lower.contains("utc");
    section.has_direct_mail_result = has_from && has_subject && has_received;

    section.has_access_limitation = lower.contains("can't access")
        || lower.contains("cannot access")
        || lower.contains("unable to access")
        || lower.contains("don't have access")
        || lower.contains("do not have access");

    section.has_actionable_next_step = lower.contains("next step")
        || lower.contains("you can")
        || lower.contains("please provide")
        || lower.contains("connect")
        || lower.contains("grant access");

    let mut in_citations = false;
    for raw_line in reply.lines() {
        let line = raw_line.trim();
        let line_lower = line.to_ascii_lowercase();
        if line_lower == "citations:" {
            in_citations = true;
            continue;
        }
        if line_lower.starts_with("confidence:") {
            section.has_confidence = true;
            in_citations = false;
            continue;
        }
        if line_lower.starts_with("caveat:") {
            section.has_caveat = true;
            in_citations = false;
            continue;
        }

        let urls = extract_urls(line);
        if in_citations && (line.starts_with("- ") || !urls.is_empty()) {
            section.citation_count += 1;
            if contains_absolute_utc_datetime(line) {
                section.citation_with_datetime_count += 1;
            }
            for url in urls {
                section.unique_citation_urls.insert(url);
            }
        }
    }

    // Fallback: if no explicit citations section, still count URL-bearing lines as citation evidence.
    if section.citation_count == 0 {
        for raw_line in reply.lines() {
            let line = raw_line.trim();
            let urls = extract_urls(line);
            if urls.is_empty() {
                continue;
            }
            section.citation_count += 1;
            if contains_absolute_utc_datetime(line) {
                section.citation_with_datetime_count += 1;
            }
            for url in urls {
                section.unique_citation_urls.insert(url);
            }
        }
    }

    vec![section]
}

fn validate_story_sections(reply: &str) -> Vec<String> {
    let sections = parse_story_sections(reply);
    let mut failures = Vec::new();

    if sections.len() != REQUIRED_STORIES {
        failures.push(format!(
            "required_story_count_mismatch expected={} got={}",
            REQUIRED_STORIES,
            sections.len()
        ));
        return failures;
    }

    let section = &sections[0];
    if !(section.has_direct_mail_result
        || (section.has_access_limitation && section.has_actionable_next_step))
    {
        failures.push("story_1_missing_direct_result_or_actionable_limitation".to_string());
    }
    if section.citation_count < REQUIRED_CITATIONS_PER_STORY {
        failures.push(format!(
            "story_1_citations_below_floor required>={} got={}",
            REQUIRED_CITATIONS_PER_STORY, section.citation_count
        ));
    }
    if section.citation_with_datetime_count < REQUIRED_CITATIONS_PER_STORY {
        failures.push(format!(
            "story_1_citation_datetimes_below_floor required>={} got={}",
            REQUIRED_CITATIONS_PER_STORY, section.citation_with_datetime_count
        ));
    }
    if section.unique_citation_urls.len() < REQUIRED_CITATIONS_PER_STORY {
        failures.push(format!(
            "story_1_distinct_citations_below_floor required>={} got={}",
            REQUIRED_CITATIONS_PER_STORY,
            section.unique_citation_urls.len()
        ));
    }
    if !section.has_confidence {
        failures.push("story_1_missing_confidence".to_string());
    }
    if !section.has_caveat {
        failures.push("story_1_missing_caveat".to_string());
    }

    failures
}

fn extract_check_value<'a>(checks: &'a [String], key: &str) -> Option<&'a str> {
    let prefix = format!("{}=", key);
    checks
        .iter()
        .find_map(|check| check.strip_prefix(&prefix).map(str::trim))
}

fn churn_signatures(events: &[KernelEvent]) -> Vec<String> {
    let mut signatures = Vec::new();
    let mut attempt_key_repeats: BTreeMap<String, usize> = BTreeMap::new();

    for event in events {
        let KernelEvent::RoutingReceipt(receipt) = event else {
            continue;
        };
        let checks = &receipt.post_state.verification_checks;
        if checks
            .iter()
            .any(|check| check == "attempt_retry_blocked_without_change=true")
        {
            signatures.push(format!(
                "blocked_without_change tool={} step={}",
                receipt.tool_name, receipt.step_index
            ));
        }

        if let Some(hash) = extract_check_value(checks, "attempt_key_hash") {
            let repeats = attempt_key_repeats.entry(hash.to_string()).or_insert(0);
            *repeats += 1;
            if *repeats >= CHURN_REPEAT_THRESHOLD && !receipt.post_state.success {
                signatures.push(format!(
                    "attempt_key_repeated hash={} count={}",
                    hash, repeats
                ));
            }
        }
    }

    signatures.sort();
    signatures.dedup();
    signatures
}

fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (end >= start).then_some(&raw[start..=end])
}

fn is_iso_utc_at(bytes: &[u8], i: usize) -> bool {
    if i + 20 > bytes.len() {
        return false;
    }
    let s = &bytes[i..i + 20];
    s[0].is_ascii_digit()
        && s[1].is_ascii_digit()
        && s[2].is_ascii_digit()
        && s[3].is_ascii_digit()
        && s[4] == b'-'
        && s[5].is_ascii_digit()
        && s[6].is_ascii_digit()
        && s[7] == b'-'
        && s[8].is_ascii_digit()
        && s[9].is_ascii_digit()
        && s[10] == b'T'
        && s[11].is_ascii_digit()
        && s[12].is_ascii_digit()
        && s[13] == b':'
        && s[14].is_ascii_digit()
        && s[15].is_ascii_digit()
        && s[16] == b':'
        && s[17].is_ascii_digit()
        && s[18].is_ascii_digit()
        && s[19] == b'Z'
}

fn redact_iso_utc_timestamps(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if is_iso_utc_at(bytes, i) {
            out.push_str("<UTC_TIMESTAMP>");
            i += 20;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn requires_human_intervention(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("waiting for approval")
        || lower.contains("sudo password")
        || lower.contains("clarification")
        || lower.contains("human verification")
        || lower.contains("waiting for user intervention")
}

fn is_waiting_for_approval(reason: &str) -> bool {
    reason.to_ascii_lowercase().contains("waiting for approval")
}

fn fatal_mail_connector_error(events: &[KernelEvent]) -> Option<String> {
    let markers = [
        "imap login failed",
        "authenticationfailed",
        "invalid credentials",
        "smtp authentication failed",
        "error_class=toolunavailable",
    ];

    for event in events.iter().rev() {
        let text = match event {
            KernelEvent::AgentStep(step) => step.error.as_deref().unwrap_or("").to_string(),
            KernelEvent::AgentActionResult { output, .. } => output.clone(),
            KernelEvent::RoutingReceipt(receipt) => receipt.failure_class_name.clone(),
            _ => continue,
        };
        let lower = text.to_ascii_lowercase();
        if markers.iter().any(|marker| lower.contains(marker)) {
            return Some(text);
        }
    }
    None
}

fn latest_require_approval_request_hash(
    events: &[KernelEvent],
    session_id: [u8; 32],
) -> Option<[u8; 32]> {
    events.iter().rev().find_map(|event| match event {
        KernelEvent::FirewallInterception {
            verdict,
            request_hash,
            session_id: Some(observed_session_id),
            ..
        } if *observed_session_id == session_id
            && verdict.eq_ignore_ascii_case("require_approval") =>
        {
            Some(*request_hash)
        }
        _ => None,
    })
}

fn build_approval_token_for_resume(
    request_hash: [u8; 32],
    now_ms: u64,
    pending_visual_hash: Option<[u8; 32]>,
    requires_pii_action: bool,
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
            expires_at: now_ms.saturating_add(APPROVAL_TOKEN_TTL_MS),
            max_usages: Some(1),
        },
        visual_hash: pending_visual_hash,
        pii_action: if requires_pii_action {
            Some(PiiApprovalAction::ApproveTransform)
        } else {
            None
        },
        scoped_exception: None,
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    }
}

fn truncate_for_log(input: &str, max_chars: usize) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        return compact;
    }
    compact.chars().take(max_chars).collect::<String>() + "..."
}

fn summarize_recent_events(events: &[KernelEvent], limit: usize) -> String {
    if events.is_empty() {
        return "(no events captured)".to_string();
    }

    let mut lines = Vec::new();
    for event in events.iter().rev().take(limit).rev() {
        let line = match event {
            KernelEvent::AgentActionResult {
                tool_name,
                output,
                agent_status,
                ..
            } => format!(
                "action tool={} status={} output={}",
                tool_name,
                agent_status,
                truncate_for_log(output, 160)
            ),
            KernelEvent::RoutingReceipt(receipt) => format!(
                "routing tool={} decision={} success={} failure_class={} escalation={:?} checks={}",
                receipt.tool_name,
                receipt.policy_decision,
                receipt.post_state.success,
                receipt.failure_class_name,
                receipt.escalation_path,
                truncate_for_log(&receipt.post_state.verification_checks.join(","), 1000)
            ),
            KernelEvent::WorkloadReceipt(workload) => match &workload.receipt {
                WorkloadReceipt::WebRetrieve(web) => format!(
                    "workload web tool={} backend={} success={} sources={} docs={} error_class={}",
                    web.tool_name,
                    web.backend,
                    web.success,
                    web.sources_count,
                    web.documents_count,
                    web.error_class.as_deref().unwrap_or("none")
                ),
                _ => "workload other".to_string(),
            },
            KernelEvent::AgentStep(trace) => format!(
                "trace step={} success={} error={} output={}",
                trace.step_index,
                trace.success,
                trace.error.as_deref().unwrap_or("none"),
                truncate_for_log(&trace.raw_output, 220)
            ),
            KernelEvent::IntentResolutionReceipt(receipt) => {
                format!("intent scope={:?} band={:?}", receipt.scope, receipt.band)
            }
            _ => "event(other)".to_string(),
        };
        lines.push(line);
    }
    lines.join("\n")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(".."))
}

fn static_audit_no_query_literal_gating() -> bool {
    let repo_root = repo_root();
    let mut combined = String::new();

    for rel in STATIC_AUDIT_FILES {
        let path = repo_root.join(rel);
        let Ok(text) = std::fs::read_to_string(&path) else {
            return false;
        };
        combined.push('\n');
        combined.push_str(&text.to_ascii_lowercase());
    }

    !QUERY_LITERAL_GATING_PATTERNS
        .iter()
        .any(|pattern| combined.contains(pattern))
}

async fn run_arbiter(
    runtime: Arc<dyn InferenceRuntime>,
    payload: &serde_json::Value,
) -> Result<ArbiterVerdict> {
    let prompt = format!(
        "You are a strict e2e arbiter for latest-email synthesis quality.\n\
Return JSON only with exact schema: \
{{\"pass\":bool,\"confidence\":\"high|medium|low\",\"rationale\":string,\"failures\":[string]}}.\n\
Decision policy (fail-closed):\n\
1) If any value in `deterministic.checks` is false, set pass=false.\n\
2) If `deterministic.story_section_failures` is non-empty, set pass=false.\n\
   Ignore `deterministic.story_section_failures_raw`; it is diagnostics-only.\n\
	3) Otherwise evaluate only synthesis quality from `final_reply_excerpt`:\n\
	   - response is valid if it either (a) provides a direct mailbox result OR (b) clearly states mailbox access limitation and gives actionable next steps,\n\
	   - when deterministic checks are all true, default to pass unless the reply is empty, unrelated, or self-contradictory,\n\
	   - concise/actionable,\n\
	   - includes caveat semantics; explicit confidence labels are optional when deterministic payload already proves direct mailbox evidence with citation + UTC timestamp.\n\
	   - treat phrases like \"preview not fully visible\", \"cannot provide full details\", and \"let me know how you'd like to proceed\" as valid caveat/actionable limitation semantics.\n\
	   - Do not fail solely because limitation-path response is used when direct mailbox access is unavailable.\n\
4) If uncertain, set pass=false and include failure `arbiter_uncertain`.\n\
5) If pass=true, failures must be [].\n\
Treat `run_timestamp_ms` and `run_timestamp_iso_utc` as authoritative for recency checks.\n\
Payload:\n{}",
        serde_json::to_string_pretty(payload)?
    );

    let options = InferenceOptions {
        tools: vec![],
        temperature: 0.0,
        json_mode: true,
        max_tokens: 600,
    };
    let raw = runtime
        .execute_inference([0u8; 32], prompt.as_bytes(), options)
        .await
        .map_err(|e| anyhow!("arbiter inference failed: {}", e))?;
    let text = String::from_utf8(raw).map_err(|_| anyhow!("arbiter response was not UTF-8"))?;
    let json_text = extract_json_object(&text)
        .ok_or_else(|| anyhow!("arbiter did not return JSON object: {}", text))?;
    let verdict: ArbiterVerdict = serde_json::from_str(json_text)
        .map_err(|e| anyhow!("failed to parse arbiter verdict: {} raw={}", e, text))?;

    if !matches!(verdict.confidence.as_str(), "high" | "medium" | "low") {
        return Err(anyhow!(
            "arbiter returned invalid confidence '{}'; expected high|medium|low",
            verdict.confidence
        ));
    }
    if verdict.pass && !verdict.failures.is_empty() {
        return Err(anyhow!(
            "arbiter returned pass=true but non-empty failures: {:?}",
            verdict.failures
        ));
    }
    if !verdict.pass && verdict.failures.is_empty() {
        return Err(anyhow!(
            "arbiter returned pass=false but empty failures; rationale={}",
            verdict.rationale
        ));
    }

    Ok(verdict)
}

async fn run_cleanup_arbiter(
    runtime: Arc<dyn InferenceRuntime>,
    payload: &serde_json::Value,
) -> Result<ArbiterVerdict> {
    let prompt = format!(
        "You are a strict e2e arbiter for mailbox cleanup quality.\n\
Return JSON only with exact schema: \
{{\"pass\":bool,\"confidence\":\"high|medium|low\",\"rationale\":string,\"failures\":[string]}}.\n\
Decision policy (fail-closed):\n\
1) If any value in `deterministic.checks` is false, set pass=false.\n\
2) Treat `deterministic.checks` as authoritative for objective pass criteria.\n\
3) If all deterministic checks are true, default to pass=true.\n\
4) Evaluate cleanup efficacy using `cleanup_metrics` and `mail_tool_structured_evidence`.\n\
   - required evidence: `max_deleted_count` > 0 OR `max_high_confidence_deleted_count` > 0.\n\
   - required evidence: absolute delta path present (`absolute_count_delta_path_observed=true`).\n\
   - required evidence: preserve evidence exists for unwanted-in-primary cleanup (transactional/personal keep rationale).\n\
   - no-worse rule: `post_primary_inbox_count_total` <= `pre_primary_inbox_count_total`.\n\
5) Provenance-aware count policy (mandatory): require provenance fields and marker to be present (`count_provenance_raw_observed=true`, `count_provenance_marker_observed=true`, `count_provenance_staleness_diagnosable=true`).\n\
   - if provenance is fresh, use pre/post total no-worse rule.\n\
   - if provenance is stale/reconciled, treat delete-receipt absolute delta as authoritative (`primary_count_delta_policy_pass=true`).\n\
6) Coarse provider rule (mandatory): if `max_mailbox_total_count_delta` > 0, cleanup is effective even when pre/post totals are equal.\n\
   - In that case, NEVER fail for `post_primary_inbox_count_total_not_reduced`.\n\
7) Terminal reply quality: pass when reply is non-empty, aligned with evidence, and states cleanup outcome + preservation intent.\n\
8) Set pass=false only for clear contradictions (empty/unrelated reply, claims conflicting with deterministic evidence, or missing preserve semantics).\n\
9) If uncertain, set pass=false and include failure `arbiter_uncertain`.\n\
10) If pass=true, failures must be [].\n\
Treat `run_timestamp_ms` and `run_timestamp_iso_utc` as authoritative for recency checks.\n\
Payload:\n{}",
        serde_json::to_string_pretty(payload)?
    );

    let options = InferenceOptions {
        tools: vec![],
        temperature: 0.0,
        json_mode: true,
        max_tokens: 600,
    };
    let raw = runtime
        .execute_inference([0u8; 32], prompt.as_bytes(), options)
        .await
        .map_err(|e| anyhow!("cleanup arbiter inference failed: {}", e))?;
    let text =
        String::from_utf8(raw).map_err(|_| anyhow!("cleanup arbiter response was not UTF-8"))?;
    let json_text = extract_json_object(&text)
        .ok_or_else(|| anyhow!("cleanup arbiter did not return JSON object: {}", text))?;
    let verdict: ArbiterVerdict = serde_json::from_str(json_text).map_err(|e| {
        anyhow!(
            "failed to parse cleanup arbiter verdict: {} raw={}",
            e,
            text
        )
    })?;

    if !matches!(verdict.confidence.as_str(), "high" | "medium" | "low") {
        return Err(anyhow!(
            "cleanup arbiter returned invalid confidence '{}'; expected high|medium|low",
            verdict.confidence
        ));
    }
    if verdict.pass && !verdict.failures.is_empty() {
        return Err(anyhow!(
            "cleanup arbiter returned pass=true but non-empty failures: {:?}",
            verdict.failures
        ));
    }
    if !verdict.pass && verdict.failures.is_empty() {
        return Err(anyhow!(
            "cleanup arbiter returned pass=false but empty failures; rationale={}",
            verdict.rationale
        ));
    }

    Ok(verdict)
}

fn session_id_for_index(index: usize) -> [u8; 32] {
    let mut session_id = [0u8; 32];
    for (offset, byte) in session_id.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_add(0x42).wrapping_add(offset as u8);
    }
    session_id
}

fn deterministic_id(run_index: usize, salt: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    for (offset, byte) in id.iter_mut().enumerate() {
        *byte = (run_index as u8)
            .wrapping_add(salt)
            .wrapping_add((offset as u8).wrapping_mul(3));
    }
    id
}

async fn run_live_case(
    label: &str,
    query: &str,
    run_index: usize,
    agent_runtime: Arc<dyn InferenceRuntime>,
    arbiter_runtime: Arc<dyn InferenceRuntime>,
) -> Result<()> {
    let (event_tx, mut event_rx) = broadcast::channel(1024);
    let gui = Arc::new(MockGuiDriver);
    let (scs, _scs_tmp_dir) = build_scs(&format!("live_mail_{}.scs", run_index))?;
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
    let channel_id = deterministic_id(run_index, 0x81);
    let lease_id = deterministic_id(run_index, 0xA1);
    seed_wallet_network_mail_service_meta(&mut state);
    seed_wallet_mail_runtime_state(
        wallet_service.as_ref(),
        &mut state,
        &mut ctx,
        channel_id,
        lease_id,
    )
    .await?;
    let run_timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let run_timestamp_iso_utc = iso_datetime_from_unix_ms(run_timestamp_ms);

    let start_params = StartAgentParams {
        session_id,
        goal: query.to_string(),
        max_steps: 16,
        parent_session_id: None,
        initial_budget: 4000,
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

    // Keep routing deterministic while preserving mailbox-local intent semantics.
    enable_intent_shadow_mode(&mut state, session_id);
    seed_resolved_intent(&mut state, session_id, IntentScopeProfile::Conversation);

    let started = Instant::now();
    let deadline = Duration::from_secs(SLA_SECONDS);
    let mut captured_events: Vec<KernelEvent> = Vec::new();
    let mut approval_resume_attempts = 0usize;

    loop {
        drain_events(&mut event_rx, &mut captured_events);
        if let Some(fatal_error) = fatal_mail_connector_error(&captured_events) {
            return Err(anyhow!(
                "live mail e2e encountered fatal mailbox connector error: {}\nrecent_events:\n{}",
                fatal_error,
                summarize_recent_events(&captured_events, 24)
            ));
        }
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
                if is_waiting_for_approval(reason) {
                    if approval_resume_attempts >= MAX_APPROVAL_RESUME_ATTEMPTS {
                        return Err(anyhow!(
                            "agent remained approval-gated after {} resume attempts\nrecent_events:\n{}",
                            MAX_APPROVAL_RESUME_ATTEMPTS,
                            summarize_recent_events(&captured_events, 24)
                        ));
                    }

                    let request_hash = latest_require_approval_request_hash(&captured_events, session_id)
                        .or(current.pending_tool_hash)
                        .ok_or_else(|| {
                            anyhow!(
                                "missing approval request hash while paused for approval\nrecent_events:\n{}",
                                summarize_recent_events(&captured_events, 24)
                            )
                        })?;
                    let requires_pii_action = state
                        .get(&pii::review::request(&request_hash))
                        .map_err(|e| anyhow!("failed to read review request state: {}", e))?
                        .is_some();
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let approval_token = build_approval_token_for_resume(
                        request_hash,
                        now_ms,
                        current.pending_visual_hash,
                        requires_pii_action,
                    );
                    let resume_params = ResumeAgentParams {
                        session_id,
                        approval_token: Some(approval_token),
                    };
                    service
                        .handle_service_call(
                            &mut state,
                            "resume@v1",
                            &codec::to_bytes_canonical(&resume_params)
                                .map_err(|e| anyhow!("failed to encode resume params: {}", e))?,
                            &mut ctx,
                        )
                        .await?;
                    approval_resume_attempts += 1;
                    continue;
                }
                if requires_human_intervention(reason) {
                    return Err(anyhow!(
                        "agent paused and requires user intervention: {}\nrecent_events:\n{}",
                        reason,
                        summarize_recent_events(&captured_events, 24)
                    ));
                }
                return Err(anyhow!(
                    "agent paused unexpectedly: {}\nrecent_events:\n{}",
                    reason,
                    summarize_recent_events(&captured_events, 24)
                ));
            }
            AgentStatus::Idle | AgentStatus::Terminated => {
                return Err(anyhow!(
                    "agent entered unexpected non-terminal status: {:?}",
                    current.status
                ));
            }
            AgentStatus::Completed(_) | AgentStatus::Failed(_) => {}
        }
        service
            .handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(|e| anyhow!("failed to encode step params: {}", e))?,
                &mut ctx,
            )
            .await?;
    }
    drain_events(&mut event_rx, &mut captured_events);

    let elapsed = started.elapsed();
    let final_state = read_agent_state(&state, session_id);
    if elapsed > deadline {
        return Err(anyhow!(
            "live mail e2e exceeded SLA: elapsed={}ms final_status={:?}\nrecent_events:\n{}",
            elapsed.as_millis(),
            final_state.status,
            summarize_recent_events(&captured_events, 16)
        ));
    }
    if !matches!(final_state.status, AgentStatus::Completed(_)) {
        return Err(anyhow!(
            "agent did not complete successfully; final status={:?}\nrecent_events:\n{}",
            final_state.status,
            summarize_recent_events(&captured_events, 16)
        ));
    }

    let mut saw_terminal_chat_reply = false;
    let mut terminal_chat_reply_events = 0usize;
    let mut final_reply = String::new();
    let mut saw_web_routing = false;
    let mut saw_web_retrieve_receipt = false;
    let mut saw_web_search_routing = false;
    let mut saw_web_read_routing = false;
    let mut saw_web_search_receipt = false;
    let mut saw_web_read_receipt = false;
    let mut saw_mail_connector_routing = false;
    let mut saw_mail_connector_action = false;
    let mut saw_terminal_chat_reply_ready_marker = false;
    let mut saw_terminal_chat_reply_emitted_marker = false;
    let mut mail_tool_structured_evidence = MailToolStructuredEvidence::default();
    let mut evidence = Vec::new();

    for event in &captured_events {
        match event {
            KernelEvent::AgentActionResult {
                tool_name,
                output,
                agent_status,
                ..
            } => {
                if is_mail_connector_tool_name(tool_name) {
                    saw_mail_connector_action = true;
                    parse_mail_tool_output_evidence(output, &mut mail_tool_structured_evidence);
                    evidence.push(format!("action:{} status={}", tool_name, agent_status));
                }
                let is_terminal_response_tool =
                    matches!(tool_name.as_str(), "chat__reply" | "agent__complete");
                if is_terminal_response_tool && agent_status.eq_ignore_ascii_case("completed") {
                    terminal_chat_reply_events += 1;
                    saw_terminal_chat_reply = true;
                    final_reply = output.clone();
                }
            }
            KernelEvent::WorkloadReceipt(workload) => {
                if let WorkloadReceipt::WebRetrieve(web) = &workload.receipt {
                    if matches!(web.tool_name.as_str(), "web__search" | "web__read") {
                        saw_web_retrieve_receipt = true;
                        if web.tool_name == "web__search" {
                            saw_web_search_receipt = true;
                        }
                        if web.tool_name == "web__read" {
                            saw_web_read_receipt = true;
                        }
                        evidence.push(format!(
                            "workload:{} success={} sources={} documents={}",
                            web.tool_name, web.success, web.sources_count, web.documents_count
                        ));
                    }
                }
            }
            KernelEvent::RoutingReceipt(receipt) => {
                if is_mail_connector_tool_name(&receipt.tool_name) {
                    saw_mail_connector_routing = true;
                    evidence.push(format!(
                        "routing:{} decision={} success={}",
                        receipt.tool_name, receipt.policy_decision, receipt.post_state.success
                    ));
                }
                if matches!(receipt.tool_name.as_str(), "web__search" | "web__read") {
                    saw_web_routing = true;
                    if receipt.tool_name == "web__search" {
                        saw_web_search_routing = true;
                    }
                    if receipt.tool_name == "web__read" {
                        saw_web_read_routing = true;
                    }
                    evidence.push(format!(
                        "routing:{} decision={} success={}",
                        receipt.tool_name, receipt.policy_decision, receipt.post_state.success
                    ));
                }
                if receipt
                    .post_state
                    .verification_checks
                    .iter()
                    .any(|check| check == "terminal_chat_reply_ready=true")
                {
                    saw_terminal_chat_reply_ready_marker = true;
                }
                if receipt
                    .post_state
                    .verification_checks
                    .iter()
                    .any(|check| check == "terminal_chat_reply_emitted=true")
                {
                    saw_terminal_chat_reply_emitted_marker = true;
                }
            }
            KernelEvent::AgentStep(trace) => {
                parse_mail_tool_output_evidence(
                    trace.raw_output.as_str(),
                    &mut mail_tool_structured_evidence,
                );
            }
            _ => {}
        }
    }

    let mut source_url_set = extract_urls(&final_reply);
    source_url_set.extend(mail_tool_structured_evidence.citation_urls.clone());
    let source_urls = source_url_set.iter().cloned().collect::<Vec<_>>();
    let story_sections = parse_story_sections(&final_reply);
    let story_section_failures = validate_story_sections(&final_reply);
    let primary_story = story_sections.first().cloned().unwrap_or_default();
    let mailbox_limitation_path = primary_story.has_access_limitation;
    let structured_direct_mail_result_path = mail_tool_structured_evidence.has_message_from
        && mail_tool_structured_evidence.has_message_subject
        && mail_tool_structured_evidence.has_message_received_at_ms;
    let direct_mail_result_path =
        primary_story.has_direct_mail_result || structured_direct_mail_result_path;
    let churn = churn_signatures(&captured_events);
    let static_audit_passed = static_audit_no_query_literal_gating();

    let terminal_chat_reply_non_empty = !final_reply.trim().is_empty();
    let elapsed_within_sla = elapsed <= deadline;
    let has_min_sources = source_url_set.len() >= MIN_SOURCES;
    let has_absolute_datetime = contains_absolute_utc_datetime(&final_reply)
        || mail_tool_structured_evidence.has_executed_at_utc;
    let has_mail_connector_evidence = saw_mail_connector_routing || saw_mail_connector_action;
    let has_retrieval_evidence = saw_web_routing
        || saw_web_retrieve_receipt
        || has_mail_connector_evidence
        || mailbox_limitation_path;
    let intended_retrieval_path_present = if direct_mail_result_path {
        has_mail_connector_evidence
            || ((saw_web_search_routing || saw_web_search_receipt)
                && (saw_web_read_routing || saw_web_read_receipt))
    } else if mailbox_limitation_path {
        true
    } else {
        (saw_web_search_routing || saw_web_search_receipt)
            && (saw_web_read_routing || saw_web_read_receipt)
    };
    let mailbox_query_avoids_web_research = !saw_web_routing && !saw_web_retrieve_receipt;
    let structured_story_contract_passed = structured_direct_mail_result_path
        && !mail_tool_structured_evidence.citation_urls.is_empty()
        && mail_tool_structured_evidence.has_executed_at_utc;
    let strict_story_contract_passed =
        story_section_failures.is_empty() || structured_story_contract_passed;
    let single_terminal_chat_reply_event =
        terminal_chat_reply_events <= MAX_TERMINAL_CHAT_REPLY_EVENTS;
    let terminal_verification_markers_present =
        saw_terminal_chat_reply_emitted_marker || saw_terminal_chat_reply;
    let no_churn_signatures = churn.is_empty();
    let effective_story_section_failures = if strict_story_contract_passed {
        Vec::new()
    } else {
        story_section_failures.clone()
    };

    let mut deterministic_checks = BTreeMap::new();
    deterministic_checks.insert(
        "terminal_chat_reply_observed".to_string(),
        saw_terminal_chat_reply,
    );
    deterministic_checks.insert(
        "terminal_chat_reply_non_empty".to_string(),
        terminal_chat_reply_non_empty,
    );
    deterministic_checks.insert("elapsed_within_sla".to_string(), elapsed_within_sla);
    deterministic_checks.insert("min_distinct_sources".to_string(), has_min_sources);
    deterministic_checks.insert(
        "absolute_utc_datetime_present".to_string(),
        has_absolute_datetime,
    );
    deterministic_checks.insert(
        "strict_story_contract_passed".to_string(),
        strict_story_contract_passed,
    );
    deterministic_checks.insert(
        "single_terminal_chat_reply_event".to_string(),
        single_terminal_chat_reply_event,
    );
    deterministic_checks.insert(
        "retrieval_evidence_present".to_string(),
        has_retrieval_evidence,
    );
    deterministic_checks.insert(
        "intended_retrieval_path_present".to_string(),
        intended_retrieval_path_present,
    );
    deterministic_checks.insert(
        "mailbox_query_avoids_web_research".to_string(),
        mailbox_query_avoids_web_research,
    );
    deterministic_checks.insert(
        "terminal_verification_markers_present".to_string(),
        terminal_verification_markers_present,
    );
    deterministic_checks.insert("no_churn_signatures".to_string(), no_churn_signatures);
    deterministic_checks.insert(
        "static_audit_no_query_literal_gating".to_string(),
        static_audit_passed,
    );

    let mut deterministic_failures = deterministic_checks
        .iter()
        .filter_map(|(name, passed)| (!*passed).then_some(name.clone()))
        .collect::<Vec<_>>();
    if !effective_story_section_failures.is_empty() {
        deterministic_failures.extend(
            effective_story_section_failures
                .iter()
                .map(|failure| format!("story_contract:{}", failure)),
        );
    }
    if !churn.is_empty() {
        deterministic_failures.push(format!("churn:{}", churn.join(" | ")));
    }

    let deterministic_payload = json!({
        "checks": deterministic_checks,
        "elapsed_ms": elapsed.as_millis(),
        "sla_seconds": SLA_SECONDS,
        "required_stories": REQUIRED_STORIES,
        "required_citations_per_story": REQUIRED_CITATIONS_PER_STORY,
        "required_min_sources": MIN_SOURCES,
        "consecutive_pass_target": CONSECUTIVE_PASS_TARGET,
        "generalization_variant_count": GENERALIZATION_VARIANTS.len(),
        "source_url_count": source_urls.len(),
        "terminal_chat_reply_events": terminal_chat_reply_events,
        "source_urls": source_urls,
        "story_section_summary": story_sections
            .iter()
            .enumerate()
            .map(|(idx, story)| json!({
                "story_index": idx + 1,
                "has_direct_mail_result": story.has_direct_mail_result,
                "has_access_limitation": story.has_access_limitation,
                "has_actionable_next_step": story.has_actionable_next_step,
                "citation_count": story.citation_count,
                "citation_with_datetime_count": story.citation_with_datetime_count,
                "distinct_citation_url_count": story.unique_citation_urls.len(),
                "has_confidence": story.has_confidence,
                "has_caveat": story.has_caveat,
            }))
            .collect::<Vec<_>>(),
        "story_section_failures": effective_story_section_failures,
        "story_section_failures_raw": story_section_failures,
        "mail_tool_structured_evidence": {
            "has_executed_at_utc": mail_tool_structured_evidence.has_executed_at_utc,
            "has_message_from": mail_tool_structured_evidence.has_message_from,
            "has_message_subject": mail_tool_structured_evidence.has_message_subject,
            "has_message_received_at_ms": mail_tool_structured_evidence.has_message_received_at_ms,
            "has_spam_confidence_fields": mail_tool_structured_evidence.has_spam_confidence_fields,
            "has_high_confidence_candidate_metric": mail_tool_structured_evidence.has_high_confidence_candidate_metric,
            "max_parse_confidence_bps": mail_tool_structured_evidence.max_parse_confidence_bps,
            "max_evaluated_count": mail_tool_structured_evidence.max_evaluated_count,
            "max_returned_count": mail_tool_structured_evidence.max_returned_count,
            "max_high_confidence_spam_candidates": mail_tool_structured_evidence.max_high_confidence_spam_candidates,
            "saw_medium_or_large_volume_band": mail_tool_structured_evidence.saw_medium_or_large_volume_band,
            "saw_delete_high_confidence_policy": mail_tool_structured_evidence.saw_delete_high_confidence_policy,
            "max_deleted_count": mail_tool_structured_evidence.max_deleted_count,
            "citation_url_count": mail_tool_structured_evidence.citation_urls.len(),
            "citation_urls": mail_tool_structured_evidence
                .citation_urls
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
        },
        "churn_signatures": churn,
        "routing_markers": {
            "terminal_chat_reply_ready": saw_terminal_chat_reply_ready_marker,
            "terminal_chat_reply_emitted": saw_terminal_chat_reply_emitted_marker,
            "saw_web_search": saw_web_search_routing || saw_web_search_receipt,
            "saw_web_read": saw_web_read_routing || saw_web_read_receipt,
            "saw_mail_connector_routing": saw_mail_connector_routing,
            "saw_mail_connector_action": saw_mail_connector_action,
        }
    });

    println!(
        "LIVE_MAIL_E2E_DETERMINISTIC_{}={}",
        label,
        serde_json::to_string_pretty(&deterministic_payload)?
    );

    if !deterministic_failures.is_empty() {
        return Err(anyhow!(
            "deterministic checks failed ({}): {}\nfinal_reply:\n{}\nrecent_events:\n{}",
            label,
            deterministic_failures.join(", "),
            final_reply,
            summarize_recent_events(&captured_events, 24)
        ));
    }

    let final_reply_excerpt = final_reply.chars().take(2_000).collect::<String>();
    let final_reply_excerpt = redact_iso_utc_timestamps(&final_reply_excerpt);
    let mut arbiter_deterministic = deterministic_payload.clone();
    if let Some(map) = arbiter_deterministic.as_object_mut() {
        map.remove("story_section_failures_raw");
    }
    let arbiter_payload = json!({
        "label": label,
        "query": query,
        "run_timestamp_ms": run_timestamp_ms,
        "run_timestamp_iso_utc": run_timestamp_iso_utc,
        "deterministic": arbiter_deterministic,
        "final_reply_excerpt": final_reply_excerpt,
        "final_reply_char_len": final_reply.chars().count(),
        "source_url_count": source_urls.len(),
        "event_evidence": evidence,
    });
    println!(
        "LIVE_MAIL_E2E_ARBITER_INPUT_{}={}",
        label,
        serde_json::to_string_pretty(&arbiter_payload)?
    );

    let verdict = run_arbiter(arbiter_runtime, &arbiter_payload).await?;
    let verdict_json = json!({
        "pass": verdict.pass,
        "confidence": verdict.confidence,
        "rationale": verdict.rationale,
        "failures": verdict.failures,
    });
    println!(
        "LIVE_MAIL_E2E_ARBITER_VERDICT_{}={}",
        label,
        serde_json::to_string_pretty(&verdict_json)?
    );

    if !verdict.pass {
        return Err(anyhow!(
            "arbiter failed live mail response ({}): confidence={} rationale={} failures={}",
            label,
            verdict.confidence,
            verdict.rationale,
            verdict.failures.join("; ")
        ));
    }

    Ok(())
}

async fn run_live_write_intent_case(
    label: &str,
    query: &str,
    run_index: usize,
    agent_runtime: Arc<dyn InferenceRuntime>,
) -> Result<()> {
    let (event_tx, mut event_rx) = broadcast::channel(1024);
    let gui = Arc::new(MockGuiDriver);
    let (scs, _scs_tmp_dir) = build_scs(&format!("live_mail_write_intent_{}.scs", run_index))?;
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
    seed_wallet_network_mail_service_meta(&mut state);
    let wallet_service = Arc::new(WalletNetworkService::default());
    let services_dir =
        ServiceDirectory::new(vec![wallet_service.clone() as Arc<dyn BlockchainService>]);
    let mut ctx = build_ctx(&services_dir);
    let session_id = session_id_for_index(run_index);
    let channel_id = deterministic_id(run_index, 0x82);
    let lease_id = deterministic_id(run_index, 0xA2);
    seed_wallet_mail_runtime_state(
        wallet_service.as_ref(),
        &mut state,
        &mut ctx,
        channel_id,
        lease_id,
    )
    .await?;

    let start_params = StartAgentParams {
        session_id,
        goal: query.to_string(),
        max_steps: 16,
        parent_session_id: None,
        initial_budget: 4000,
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

    // Keep intent routing deterministic while allowing mailbox-intent policy gates to fire.
    enable_intent_shadow_mode(&mut state, session_id);
    seed_resolved_intent(&mut state, session_id, IntentScopeProfile::Conversation);

    let started = Instant::now();
    let deadline = Duration::from_secs(SLA_SECONDS);
    let mut captured_events: Vec<KernelEvent> = Vec::new();
    let mut paused_waiting_for_approval = false;

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
                if is_waiting_for_approval(reason) {
                    paused_waiting_for_approval = true;
                    break;
                }
                if requires_human_intervention(reason) {
                    return Err(anyhow!(
                        "agent paused and requires user intervention: {}\nrecent_events:\n{}",
                        reason,
                        summarize_recent_events(&captured_events, 24)
                    ));
                }
            }
            AgentStatus::Idle | AgentStatus::Terminated => {
                return Err(anyhow!(
                    "agent entered unexpected non-terminal status: {:?}",
                    current.status
                ));
            }
            AgentStatus::Completed(_) | AgentStatus::Failed(_) => {}
        }
        service
            .handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(|e| anyhow!("failed to encode step params: {}", e))?,
                &mut ctx,
            )
            .await?;
    }
    drain_events(&mut event_rx, &mut captured_events);

    let elapsed = started.elapsed();
    let final_state = read_agent_state(&state, session_id);
    if elapsed > deadline {
        return Err(anyhow!(
            "live mail write-intent e2e exceeded SLA: elapsed={}ms final_status={:?}\nrecent_events:\n{}",
            elapsed.as_millis(),
            final_state.status,
            summarize_recent_events(&captured_events, 16)
        ));
    }

    let final_state_paused_waiting_for_approval = matches!(
        &final_state.status,
        AgentStatus::Paused(reason) if is_waiting_for_approval(reason)
    );

    let mut saw_mail_connector_routing = false;
    let mut saw_mail_connector_action = false;
    let mut saw_web_routing = false;
    let mut saw_web_retrieve_receipt = false;
    let mut saw_firewall_require_approval = false;
    let mut saw_firewall_require_approval_for_mail = false;
    let mut saw_policy_require_approval = false;
    let mut saw_policy_require_approval_for_mail_tool = false;
    let mut saw_approval_single_pending_marker = false;
    let mut terminal_chat_reply_events = 0usize;
    let mut terminal_chat_reply_ready_marker_count = 0usize;
    let mut terminal_chat_reply_emitted_marker_count = 0usize;
    let mut evidence = Vec::new();

    for event in &captured_events {
        match event {
            KernelEvent::FirewallInterception {
                verdict, target, ..
            } => {
                if verdict.eq_ignore_ascii_case("require_approval") {
                    saw_firewall_require_approval = true;
                    if is_mail_connector_tool_name(target)
                        || target.to_ascii_lowercase().contains("mail")
                    {
                        saw_firewall_require_approval_for_mail = true;
                    }
                    evidence.push(format!("firewall verdict={} target={}", verdict, target));
                }
            }
            KernelEvent::AgentActionResult {
                tool_name,
                agent_status,
                ..
            } => {
                if is_mail_connector_tool_name(tool_name) {
                    saw_mail_connector_action = true;
                    evidence.push(format!("action tool={} status={}", tool_name, agent_status));
                }
                if tool_name == "chat__reply" && agent_status.eq_ignore_ascii_case("completed") {
                    terminal_chat_reply_events += 1;
                }
            }
            KernelEvent::WorkloadReceipt(workload) => {
                if let WorkloadReceipt::WebRetrieve(web) = &workload.receipt {
                    if matches!(web.tool_name.as_str(), "web__search" | "web__read") {
                        saw_web_retrieve_receipt = true;
                        evidence.push(format!(
                            "workload:{} success={} sources={} documents={}",
                            web.tool_name, web.success, web.sources_count, web.documents_count
                        ));
                    }
                }
            }
            KernelEvent::RoutingReceipt(receipt) => {
                if is_mail_connector_tool_name(&receipt.tool_name) {
                    saw_mail_connector_routing = true;
                    evidence.push(format!(
                        "routing:{} decision={} success={}",
                        receipt.tool_name, receipt.policy_decision, receipt.post_state.success
                    ));
                }
                if matches!(receipt.tool_name.as_str(), "web__search" | "web__read") {
                    saw_web_routing = true;
                    evidence.push(format!(
                        "routing:{} decision={} success={}",
                        receipt.tool_name, receipt.policy_decision, receipt.post_state.success
                    ));
                }
                if receipt
                    .policy_decision
                    .eq_ignore_ascii_case("require_approval")
                {
                    saw_policy_require_approval = true;
                    if is_mail_connector_tool_name(&receipt.tool_name) {
                        saw_policy_require_approval_for_mail_tool = true;
                    }
                }

                for check in &receipt.post_state.verification_checks {
                    if check.starts_with("approval_suppressed_single_pending=") {
                        saw_approval_single_pending_marker = true;
                    }
                    if check == "terminal_chat_reply_ready=true" {
                        terminal_chat_reply_ready_marker_count += 1;
                    }
                    if check == "terminal_chat_reply_emitted=true" {
                        terminal_chat_reply_emitted_marker_count += 1;
                    }
                }
            }
            _ => {}
        }
    }

    let mail_tooling_path_observed = saw_mail_connector_routing
        || saw_mail_connector_action
        || saw_policy_require_approval_for_mail_tool
        || saw_firewall_require_approval_for_mail;
    let approval_gate_evidence_present =
        saw_firewall_require_approval && saw_policy_require_approval;
    let approval_gate_bound_to_mail_tooling =
        saw_policy_require_approval_for_mail_tool || saw_firewall_require_approval_for_mail;
    let mailbox_query_avoids_web_fallback = !saw_web_routing && !saw_web_retrieve_receipt;
    let terminal_lifecycle_single_chat_reply =
        terminal_chat_reply_events <= MAX_TERMINAL_CHAT_REPLY_EVENTS;
    let terminal_marker_cardinality_valid = terminal_chat_reply_ready_marker_count <= 1
        && terminal_chat_reply_emitted_marker_count <= 1;
    let terminal_marker_order_valid = terminal_chat_reply_emitted_marker_count == 0
        || terminal_chat_reply_ready_marker_count >= terminal_chat_reply_emitted_marker_count;
    let no_churn_signatures = churn_signatures(&captured_events).is_empty();

    let mut deterministic_checks = BTreeMap::new();
    deterministic_checks.insert(
        "final_state_paused_waiting_for_approval".to_string(),
        final_state_paused_waiting_for_approval,
    );
    deterministic_checks.insert(
        "loop_observed_paused_waiting_for_approval".to_string(),
        paused_waiting_for_approval,
    );
    deterministic_checks.insert("elapsed_within_sla".to_string(), elapsed <= deadline);
    deterministic_checks.insert(
        "mail_tooling_path_observed".to_string(),
        mail_tooling_path_observed,
    );
    deterministic_checks.insert(
        "approval_gate_evidence_present".to_string(),
        approval_gate_evidence_present,
    );
    deterministic_checks.insert(
        "approval_gate_bound_to_mail_tooling".to_string(),
        approval_gate_bound_to_mail_tooling,
    );
    deterministic_checks.insert(
        "approval_single_pending_marker_present".to_string(),
        saw_approval_single_pending_marker,
    );
    deterministic_checks.insert(
        "mailbox_query_avoids_web_fallback".to_string(),
        mailbox_query_avoids_web_fallback,
    );
    deterministic_checks.insert(
        "terminal_lifecycle_single_chat_reply".to_string(),
        terminal_lifecycle_single_chat_reply,
    );
    deterministic_checks.insert(
        "terminal_marker_cardinality_valid".to_string(),
        terminal_marker_cardinality_valid,
    );
    deterministic_checks.insert(
        "terminal_marker_order_valid".to_string(),
        terminal_marker_order_valid,
    );
    deterministic_checks.insert("no_churn_signatures".to_string(), no_churn_signatures);

    let deterministic_failures = deterministic_checks
        .iter()
        .filter_map(|(name, passed)| (!*passed).then_some(name.clone()))
        .collect::<Vec<_>>();

    let deterministic_payload = json!({
        "checks": deterministic_checks,
        "elapsed_ms": elapsed.as_millis(),
        "sla_seconds": SLA_SECONDS,
        "terminal_chat_reply_events": terminal_chat_reply_events,
        "terminal_chat_reply_ready_marker_count": terminal_chat_reply_ready_marker_count,
        "terminal_chat_reply_emitted_marker_count": terminal_chat_reply_emitted_marker_count,
        "routing_markers": {
            "saw_mail_connector_routing": saw_mail_connector_routing,
            "saw_mail_connector_action": saw_mail_connector_action,
            "saw_web_routing": saw_web_routing,
            "saw_web_retrieve_receipt": saw_web_retrieve_receipt,
            "saw_policy_require_approval": saw_policy_require_approval,
            "saw_policy_require_approval_for_mail_tool": saw_policy_require_approval_for_mail_tool,
            "saw_firewall_require_approval": saw_firewall_require_approval,
            "saw_firewall_require_approval_for_mail": saw_firewall_require_approval_for_mail,
            "saw_approval_single_pending_marker": saw_approval_single_pending_marker,
        },
        "event_evidence": evidence,
    });

    println!(
        "LIVE_MAIL_WRITE_INTENT_E2E_DETERMINISTIC_{}={}",
        label,
        serde_json::to_string_pretty(&deterministic_payload)?
    );

    if !deterministic_failures.is_empty() {
        return Err(anyhow!(
            "deterministic checks failed ({}): {}\nrecent_events:\n{}",
            label,
            deterministic_failures.join(", "),
            summarize_recent_events(&captured_events, 24)
        ));
    }

    Ok(())
}

async fn run_live_large_volume_case(
    label: &str,
    query: &str,
    run_index: usize,
    agent_runtime: Arc<dyn InferenceRuntime>,
) -> Result<()> {
    let (event_tx, mut event_rx) = broadcast::channel(1024);
    let gui = Arc::new(MockGuiDriver);
    let (scs, _scs_tmp_dir) = build_scs(&format!("live_mail_volume_{}.scs", run_index))?;
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
    let channel_id = deterministic_id(run_index, 0x83);
    let lease_id = deterministic_id(run_index, 0xA3);
    seed_wallet_network_mail_service_meta(&mut state);
    seed_wallet_mail_runtime_state(
        wallet_service.as_ref(),
        &mut state,
        &mut ctx,
        channel_id,
        lease_id,
    )
    .await?;

    let start_params = StartAgentParams {
        session_id,
        goal: query.to_string(),
        max_steps: 20,
        parent_session_id: None,
        initial_budget: 5000,
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
    seed_resolved_intent(&mut state, session_id, IntentScopeProfile::Conversation);

    let min_evaluated = read_optional_u32_env(
        "LIVE_MAIL_VOLUME_E2E_MIN_EVALUATED",
        LARGE_VOLUME_MIN_EVALUATED_DEFAULT,
    );
    let parse_confidence_floor = read_optional_u32_env(
        "LIVE_MAIL_VOLUME_E2E_PARSE_CONFIDENCE_FLOOR_BPS",
        LARGE_VOLUME_PARSE_CONFIDENCE_FLOOR_BPS as u32,
    )
    .min(u16::MAX as u32) as u16;

    let started = Instant::now();
    let deadline = Duration::from_secs(SLA_SECONDS);
    let mut captured_events: Vec<KernelEvent> = Vec::new();
    let mut approval_resume_attempts = 0usize;

    loop {
        drain_events(&mut event_rx, &mut captured_events);
        if let Some(fatal_error) = fatal_mail_connector_error(&captured_events) {
            return Err(anyhow!(
                "live large-volume mail e2e encountered fatal mailbox connector error: {}\nrecent_events:\n{}",
                fatal_error,
                summarize_recent_events(&captured_events, 24)
            ));
        }
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
                if is_waiting_for_approval(reason) {
                    if approval_resume_attempts >= MAX_APPROVAL_RESUME_ATTEMPTS {
                        return Err(anyhow!(
                            "large-volume mail e2e remained approval-gated after {} resume attempts\nrecent_events:\n{}",
                            MAX_APPROVAL_RESUME_ATTEMPTS,
                            summarize_recent_events(&captured_events, 24)
                        ));
                    }
                    let request_hash = latest_require_approval_request_hash(&captured_events, session_id)
                        .or(current.pending_tool_hash)
                        .ok_or_else(|| {
                            anyhow!(
                                "missing approval request hash in large-volume mail e2e\nrecent_events:\n{}",
                                summarize_recent_events(&captured_events, 24)
                            )
                        })?;
                    let requires_pii_action = state
                        .get(&pii::review::request(&request_hash))
                        .map_err(|e| anyhow!("failed to read review request state: {}", e))?
                        .is_some();
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let approval_token = build_approval_token_for_resume(
                        request_hash,
                        now_ms,
                        current.pending_visual_hash,
                        requires_pii_action,
                    );
                    let resume_params = ResumeAgentParams {
                        session_id,
                        approval_token: Some(approval_token),
                    };
                    service
                        .handle_service_call(
                            &mut state,
                            "resume@v1",
                            &codec::to_bytes_canonical(&resume_params)
                                .map_err(|e| anyhow!("failed to encode resume params: {}", e))?,
                            &mut ctx,
                        )
                        .await?;
                    approval_resume_attempts += 1;
                    continue;
                }
                if requires_human_intervention(reason) {
                    return Err(anyhow!(
                        "large-volume mail e2e paused for intervention: {}\nrecent_events:\n{}",
                        reason,
                        summarize_recent_events(&captured_events, 24)
                    ));
                }
                return Err(anyhow!(
                    "large-volume mail e2e paused unexpectedly: {}\nrecent_events:\n{}",
                    reason,
                    summarize_recent_events(&captured_events, 24)
                ));
            }
            AgentStatus::Idle | AgentStatus::Terminated => {
                return Err(anyhow!(
                    "agent entered unexpected non-terminal status: {:?}",
                    current.status
                ));
            }
            AgentStatus::Completed(_) | AgentStatus::Failed(_) => {}
        }
        service
            .handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(|e| anyhow!("failed to encode step params: {}", e))?,
                &mut ctx,
            )
            .await?;
    }
    drain_events(&mut event_rx, &mut captured_events);

    let elapsed = started.elapsed();
    let final_state = read_agent_state(&state, session_id);
    if elapsed > deadline {
        return Err(anyhow!(
            "live large-volume mail e2e exceeded SLA: elapsed={}ms final_status={:?}\nrecent_events:\n{}",
            elapsed.as_millis(),
            final_state.status,
            summarize_recent_events(&captured_events, 24)
        ));
    }
    if !matches!(final_state.status, AgentStatus::Completed(_)) {
        return Err(anyhow!(
            "large-volume mail e2e did not complete; final status={:?}\nrecent_events:\n{}",
            final_state.status,
            summarize_recent_events(&captured_events, 24)
        ));
    }

    let mut saw_mail_connector_routing = false;
    let mut saw_mail_connector_action = false;
    let mut saw_mail_list_recent_routing = false;
    let mut saw_mail_list_recent_action = false;
    let mut saw_web_routing = false;
    let mut saw_web_retrieve_receipt = false;
    let mut terminal_chat_reply_events = 0usize;
    let mut saw_terminal_chat_reply = false;
    let mut final_reply = String::new();
    let mut mail_tool_structured_evidence = MailToolStructuredEvidence::default();
    let mut evidence = Vec::new();

    for event in &captured_events {
        match event {
            KernelEvent::AgentActionResult {
                tool_name,
                output,
                agent_status,
                ..
            } => {
                if is_mail_connector_tool_name(tool_name) {
                    saw_mail_connector_action = true;
                    if tool_name.to_ascii_lowercase().contains("mail_list_recent") {
                        saw_mail_list_recent_action = true;
                    }
                    parse_mail_tool_output_evidence(output, &mut mail_tool_structured_evidence);
                    evidence.push(format!("action:{} status={}", tool_name, agent_status));
                }
                let is_terminal_response_tool =
                    matches!(tool_name.as_str(), "chat__reply" | "agent__complete");
                if is_terminal_response_tool && agent_status.eq_ignore_ascii_case("completed") {
                    terminal_chat_reply_events += 1;
                    saw_terminal_chat_reply = true;
                    final_reply = output.clone();
                }
            }
            KernelEvent::RoutingReceipt(receipt) => {
                if is_mail_connector_tool_name(&receipt.tool_name) {
                    saw_mail_connector_routing = true;
                    if receipt
                        .tool_name
                        .to_ascii_lowercase()
                        .contains("mail_list_recent")
                    {
                        saw_mail_list_recent_routing = true;
                    }
                    evidence.push(format!(
                        "routing:{} decision={} success={}",
                        receipt.tool_name, receipt.policy_decision, receipt.post_state.success
                    ));
                }
                if matches!(receipt.tool_name.as_str(), "web__search" | "web__read") {
                    saw_web_routing = true;
                }
            }
            KernelEvent::WorkloadReceipt(workload) => {
                if let WorkloadReceipt::WebRetrieve(web) = &workload.receipt {
                    if matches!(web.tool_name.as_str(), "web__search" | "web__read") {
                        saw_web_retrieve_receipt = true;
                    }
                }
            }
            KernelEvent::AgentStep(trace) => {
                parse_mail_tool_output_evidence(
                    trace.raw_output.as_str(),
                    &mut mail_tool_structured_evidence,
                );
            }
            _ => {}
        }
    }

    let mail_tooling_path_observed = saw_mail_connector_routing || saw_mail_connector_action;
    let list_recent_tool_observed = saw_mail_list_recent_routing || saw_mail_list_recent_action;
    let mailbox_query_avoids_web_fallback = !saw_web_routing && !saw_web_retrieve_receipt;
    let parse_confidence_meets_floor =
        mail_tool_structured_evidence.max_parse_confidence_bps >= parse_confidence_floor;
    let evaluated_volume_meets_floor =
        mail_tool_structured_evidence.max_evaluated_count >= min_evaluated;
    let spam_confidence_fields_present = mail_tool_structured_evidence.has_spam_confidence_fields;
    let high_confidence_metric_present =
        mail_tool_structured_evidence.has_high_confidence_candidate_metric;
    let medium_or_large_volume_band_observed =
        mail_tool_structured_evidence.saw_medium_or_large_volume_band;
    let terminal_chat_reply_non_empty = !final_reply.trim().is_empty();
    let terminal_lifecycle_single_chat_reply =
        terminal_chat_reply_events <= MAX_TERMINAL_CHAT_REPLY_EVENTS;
    let no_churn_signatures = churn_signatures(&captured_events).is_empty();

    let mut deterministic_checks = BTreeMap::new();
    deterministic_checks.insert(
        "terminal_chat_reply_observed".to_string(),
        saw_terminal_chat_reply,
    );
    deterministic_checks.insert(
        "terminal_chat_reply_non_empty".to_string(),
        terminal_chat_reply_non_empty,
    );
    deterministic_checks.insert("elapsed_within_sla".to_string(), elapsed <= deadline);
    deterministic_checks.insert(
        "mail_tooling_path_observed".to_string(),
        mail_tooling_path_observed,
    );
    deterministic_checks.insert(
        "list_recent_tool_observed".to_string(),
        list_recent_tool_observed,
    );
    deterministic_checks.insert(
        "mailbox_query_avoids_web_fallback".to_string(),
        mailbox_query_avoids_web_fallback,
    );
    deterministic_checks.insert(
        "parse_confidence_meets_floor".to_string(),
        parse_confidence_meets_floor,
    );
    deterministic_checks.insert(
        "evaluated_volume_meets_floor".to_string(),
        evaluated_volume_meets_floor,
    );
    deterministic_checks.insert(
        "spam_confidence_fields_present".to_string(),
        spam_confidence_fields_present,
    );
    deterministic_checks.insert(
        "high_confidence_metric_present".to_string(),
        high_confidence_metric_present,
    );
    deterministic_checks.insert(
        "medium_or_large_volume_band_observed".to_string(),
        medium_or_large_volume_band_observed,
    );
    deterministic_checks.insert(
        "terminal_lifecycle_single_chat_reply".to_string(),
        terminal_lifecycle_single_chat_reply,
    );
    deterministic_checks.insert("no_churn_signatures".to_string(), no_churn_signatures);

    let deterministic_failures = deterministic_checks
        .iter()
        .filter_map(|(name, passed)| (!*passed).then_some(name.clone()))
        .collect::<Vec<_>>();

    let deterministic_payload = json!({
        "checks": deterministic_checks,
        "elapsed_ms": elapsed.as_millis(),
        "sla_seconds": SLA_SECONDS,
        "parse_confidence_floor_bps": parse_confidence_floor,
        "min_evaluated_required": min_evaluated,
        "terminal_chat_reply_events": terminal_chat_reply_events,
        "mail_tool_structured_evidence": {
            "max_parse_confidence_bps": mail_tool_structured_evidence.max_parse_confidence_bps,
            "max_evaluated_count": mail_tool_structured_evidence.max_evaluated_count,
            "max_returned_count": mail_tool_structured_evidence.max_returned_count,
            "max_high_confidence_spam_candidates": mail_tool_structured_evidence.max_high_confidence_spam_candidates,
            "saw_medium_or_large_volume_band": mail_tool_structured_evidence.saw_medium_or_large_volume_band,
            "has_spam_confidence_fields": mail_tool_structured_evidence.has_spam_confidence_fields,
        },
        "routing_markers": {
            "saw_mail_connector_routing": saw_mail_connector_routing,
            "saw_mail_connector_action": saw_mail_connector_action,
            "saw_mail_list_recent_routing": saw_mail_list_recent_routing,
            "saw_mail_list_recent_action": saw_mail_list_recent_action,
            "saw_web_routing": saw_web_routing,
            "saw_web_retrieve_receipt": saw_web_retrieve_receipt,
        },
        "event_evidence": evidence,
    });
    println!(
        "LIVE_MAIL_LARGE_VOLUME_E2E_DETERMINISTIC_{}={}",
        label,
        serde_json::to_string_pretty(&deterministic_payload)?
    );

    if !deterministic_failures.is_empty() {
        return Err(anyhow!(
            "large-volume deterministic checks failed ({}): {}\nfinal_reply:\n{}\nrecent_events:\n{}",
            label,
            deterministic_failures.join(", "),
            final_reply,
            summarize_recent_events(&captured_events, 24)
        ));
    }

    Ok(())
}

async fn run_live_delete_spam_case(
    label: &str,
    query: &str,
    run_index: usize,
    agent_runtime: Arc<dyn InferenceRuntime>,
) -> Result<()> {
    let (event_tx, mut event_rx) = broadcast::channel(1024);
    let gui = Arc::new(MockGuiDriver);
    let (scs, _scs_tmp_dir) = build_scs(&format!("live_mail_delete_spam_{}.scs", run_index))?;
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
    seed_wallet_network_mail_service_meta(&mut state);
    let wallet_service = Arc::new(WalletNetworkService::default());
    let services_dir =
        ServiceDirectory::new(vec![wallet_service.clone() as Arc<dyn BlockchainService>]);
    let mut ctx = build_ctx(&services_dir);
    let session_id = session_id_for_index(run_index);
    let channel_id = deterministic_id(run_index, 0x84);
    let lease_id = deterministic_id(run_index, 0xA4);
    seed_wallet_mail_runtime_state(
        wallet_service.as_ref(),
        &mut state,
        &mut ctx,
        channel_id,
        lease_id,
    )
    .await?;

    let start_params = StartAgentParams {
        session_id,
        goal: query.to_string(),
        max_steps: 18,
        parent_session_id: None,
        initial_budget: 4500,
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
    seed_resolved_intent(&mut state, session_id, IntentScopeProfile::Conversation);

    let started = Instant::now();
    let deadline = Duration::from_secs(SLA_SECONDS);
    let mut captured_events: Vec<KernelEvent> = Vec::new();
    let mut approval_resume_attempts = 0usize;

    loop {
        drain_events(&mut event_rx, &mut captured_events);
        if let Some(fatal_error) = fatal_mail_connector_error(&captured_events) {
            return Err(anyhow!(
                "live delete-spam e2e encountered fatal mailbox connector error: {}\nrecent_events:\n{}",
                fatal_error,
                summarize_recent_events(&captured_events, 24)
            ));
        }
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
                if is_waiting_for_approval(reason) {
                    if approval_resume_attempts >= MAX_APPROVAL_RESUME_ATTEMPTS {
                        return Err(anyhow!(
                            "delete-spam e2e remained approval-gated after {} resume attempts\nrecent_events:\n{}",
                            MAX_APPROVAL_RESUME_ATTEMPTS,
                            summarize_recent_events(&captured_events, 24)
                        ));
                    }
                    let request_hash =
                        latest_require_approval_request_hash(&captured_events, session_id)
                            .or(current.pending_tool_hash)
                            .ok_or_else(|| {
                                anyhow!(
                            "missing approval request hash in delete-spam e2e\nrecent_events:\n{}",
                            summarize_recent_events(&captured_events, 24)
                        )
                            })?;
                    let requires_pii_action = state
                        .get(&pii::review::request(&request_hash))
                        .map_err(|e| anyhow!("failed to read review request state: {}", e))?
                        .is_some();
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let approval_token = build_approval_token_for_resume(
                        request_hash,
                        now_ms,
                        current.pending_visual_hash,
                        requires_pii_action,
                    );
                    let resume_params = ResumeAgentParams {
                        session_id,
                        approval_token: Some(approval_token),
                    };
                    service
                        .handle_service_call(
                            &mut state,
                            "resume@v1",
                            &codec::to_bytes_canonical(&resume_params)
                                .map_err(|e| anyhow!("failed to encode resume params: {}", e))?,
                            &mut ctx,
                        )
                        .await?;
                    approval_resume_attempts += 1;
                    continue;
                }
                if requires_human_intervention(reason) {
                    return Err(anyhow!(
                        "delete-spam e2e paused for intervention: {}\nrecent_events:\n{}",
                        reason,
                        summarize_recent_events(&captured_events, 24)
                    ));
                }
                return Err(anyhow!(
                    "delete-spam e2e paused unexpectedly: {}\nrecent_events:\n{}",
                    reason,
                    summarize_recent_events(&captured_events, 24)
                ));
            }
            AgentStatus::Idle | AgentStatus::Terminated => {
                return Err(anyhow!(
                    "agent entered unexpected non-terminal status: {:?}",
                    current.status
                ));
            }
            AgentStatus::Completed(_) | AgentStatus::Failed(_) => {}
        }
        service
            .handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(|e| anyhow!("failed to encode step params: {}", e))?,
                &mut ctx,
            )
            .await?;
    }
    drain_events(&mut event_rx, &mut captured_events);

    let elapsed = started.elapsed();
    let final_state = read_agent_state(&state, session_id);
    if elapsed > deadline {
        return Err(anyhow!(
            "live delete-spam e2e exceeded SLA: elapsed={}ms final_status={:?}\nrecent_events:\n{}",
            elapsed.as_millis(),
            final_state.status,
            summarize_recent_events(&captured_events, 24)
        ));
    }
    if !matches!(final_state.status, AgentStatus::Completed(_)) {
        return Err(anyhow!(
            "delete-spam e2e did not complete; final status={:?}\nrecent_events:\n{}",
            final_state.status,
            summarize_recent_events(&captured_events, 24)
        ));
    }

    let mut saw_mail_connector_routing = false;
    let mut saw_mail_connector_action = false;
    let mut saw_mail_delete_routing = false;
    let mut saw_mail_delete_action = false;
    let mut saw_web_routing = false;
    let mut saw_web_retrieve_receipt = false;
    let mut saw_firewall_require_approval = false;
    let mut saw_policy_require_approval = false;
    let mut terminal_chat_reply_events = 0usize;
    let mut saw_terminal_chat_reply = false;
    let mut final_reply = String::new();
    let mut mail_tool_structured_evidence = MailToolStructuredEvidence::default();
    let mut evidence = Vec::new();

    for event in &captured_events {
        match event {
            KernelEvent::FirewallInterception {
                verdict, target, ..
            } => {
                if verdict.eq_ignore_ascii_case("require_approval") {
                    saw_firewall_require_approval = true;
                    evidence.push(format!("firewall verdict={} target={}", verdict, target));
                }
            }
            KernelEvent::AgentActionResult {
                tool_name,
                output,
                agent_status,
                ..
            } => {
                if is_mail_connector_tool_name(tool_name) {
                    saw_mail_connector_action = true;
                    if tool_name.to_ascii_lowercase().contains("mail_delete_spam") {
                        saw_mail_delete_action = true;
                    }
                    parse_mail_tool_output_evidence(output, &mut mail_tool_structured_evidence);
                    evidence.push(format!("action:{} status={}", tool_name, agent_status));
                }
                let is_terminal_response_tool =
                    matches!(tool_name.as_str(), "chat__reply" | "agent__complete");
                if is_terminal_response_tool && agent_status.eq_ignore_ascii_case("completed") {
                    terminal_chat_reply_events += 1;
                    saw_terminal_chat_reply = true;
                    final_reply = output.clone();
                }
            }
            KernelEvent::RoutingReceipt(receipt) => {
                if is_mail_connector_tool_name(&receipt.tool_name) {
                    saw_mail_connector_routing = true;
                    if receipt
                        .tool_name
                        .to_ascii_lowercase()
                        .contains("mail_delete_spam")
                    {
                        saw_mail_delete_routing = true;
                    }
                    evidence.push(format!(
                        "routing:{} decision={} success={}",
                        receipt.tool_name, receipt.policy_decision, receipt.post_state.success
                    ));
                }
                if receipt
                    .policy_decision
                    .eq_ignore_ascii_case("require_approval")
                {
                    saw_policy_require_approval = true;
                }
                if matches!(receipt.tool_name.as_str(), "web__search" | "web__read") {
                    saw_web_routing = true;
                }
            }
            KernelEvent::WorkloadReceipt(workload) => {
                if let WorkloadReceipt::WebRetrieve(web) = &workload.receipt {
                    if matches!(web.tool_name.as_str(), "web__search" | "web__read") {
                        saw_web_retrieve_receipt = true;
                    }
                }
            }
            KernelEvent::AgentStep(trace) => {
                parse_mail_tool_output_evidence(
                    trace.raw_output.as_str(),
                    &mut mail_tool_structured_evidence,
                );
            }
            _ => {}
        }
    }

    let mail_tooling_path_observed = saw_mail_connector_routing || saw_mail_connector_action;
    let delete_tool_observed = saw_mail_delete_routing || saw_mail_delete_action;
    let mailbox_query_avoids_web_fallback = !saw_web_routing && !saw_web_retrieve_receipt;
    let delete_high_confidence_policy_present =
        mail_tool_structured_evidence.saw_delete_high_confidence_policy;
    let approval_gate_evidence_present =
        saw_firewall_require_approval && saw_policy_require_approval;
    let terminal_chat_reply_non_empty = !final_reply.trim().is_empty();
    let terminal_lifecycle_single_chat_reply =
        terminal_chat_reply_events <= MAX_TERMINAL_CHAT_REPLY_EVENTS;
    let no_churn_signatures = churn_signatures(&captured_events).is_empty();

    let mut deterministic_checks = BTreeMap::new();
    deterministic_checks.insert(
        "terminal_chat_reply_observed".to_string(),
        saw_terminal_chat_reply,
    );
    deterministic_checks.insert(
        "terminal_chat_reply_non_empty".to_string(),
        terminal_chat_reply_non_empty,
    );
    deterministic_checks.insert("elapsed_within_sla".to_string(), elapsed <= deadline);
    deterministic_checks.insert(
        "mail_tooling_path_observed".to_string(),
        mail_tooling_path_observed,
    );
    deterministic_checks.insert("delete_tool_observed".to_string(), delete_tool_observed);
    deterministic_checks.insert(
        "mailbox_query_avoids_web_fallback".to_string(),
        mailbox_query_avoids_web_fallback,
    );
    deterministic_checks.insert(
        "delete_high_confidence_policy_present".to_string(),
        delete_high_confidence_policy_present,
    );
    deterministic_checks.insert(
        "approval_gate_evidence_present".to_string(),
        approval_gate_evidence_present,
    );
    deterministic_checks.insert(
        "terminal_lifecycle_single_chat_reply".to_string(),
        terminal_lifecycle_single_chat_reply,
    );
    deterministic_checks.insert("no_churn_signatures".to_string(), no_churn_signatures);

    let deterministic_failures = deterministic_checks
        .iter()
        .filter_map(|(name, passed)| (!*passed).then_some(name.clone()))
        .collect::<Vec<_>>();

    let deterministic_payload = json!({
        "checks": deterministic_checks,
        "elapsed_ms": elapsed.as_millis(),
        "sla_seconds": SLA_SECONDS,
        "terminal_chat_reply_events": terminal_chat_reply_events,
        "mail_tool_structured_evidence": {
            "saw_delete_high_confidence_policy": mail_tool_structured_evidence.saw_delete_high_confidence_policy,
            "max_evaluated_count": mail_tool_structured_evidence.max_evaluated_count,
            "max_deleted_count": mail_tool_structured_evidence.max_deleted_count,
        },
        "routing_markers": {
            "saw_mail_connector_routing": saw_mail_connector_routing,
            "saw_mail_connector_action": saw_mail_connector_action,
            "saw_mail_delete_routing": saw_mail_delete_routing,
            "saw_mail_delete_action": saw_mail_delete_action,
            "saw_web_routing": saw_web_routing,
            "saw_web_retrieve_receipt": saw_web_retrieve_receipt,
            "saw_firewall_require_approval": saw_firewall_require_approval,
            "saw_policy_require_approval": saw_policy_require_approval,
        },
        "event_evidence": evidence,
    });
    println!(
        "LIVE_MAIL_DELETE_SPAM_E2E_DETERMINISTIC_{}={}",
        label,
        serde_json::to_string_pretty(&deterministic_payload)?
    );

    if !deterministic_failures.is_empty() {
        return Err(anyhow!(
            "delete-spam deterministic checks failed ({}): {}\nfinal_reply:\n{}\nrecent_events:\n{}",
            label,
            deterministic_failures.join(", "),
            final_reply,
            summarize_recent_events(&captured_events, 24)
        ));
    }

    Ok(())
}

async fn run_live_cleanup_inbox_case(
    label: &str,
    query: &str,
    run_index: usize,
    agent_runtime: Arc<dyn InferenceRuntime>,
    arbiter_runtime: Arc<dyn InferenceRuntime>,
) -> Result<()> {
    let (event_tx, mut event_rx) = broadcast::channel(1024);
    let gui = Arc::new(MockGuiDriver);
    let (scs, _scs_tmp_dir) = build_scs(&format!("live_mail_cleanup_{}.scs", run_index))?;
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
    seed_wallet_network_mail_service_meta(&mut state);
    let wallet_service = Arc::new(WalletNetworkService::default());
    let services_dir =
        ServiceDirectory::new(vec![wallet_service.clone() as Arc<dyn BlockchainService>]);
    let mut ctx = build_ctx(&services_dir);
    let session_id = session_id_for_index(run_index);
    let channel_id = deterministic_id(run_index, 0x85);
    let lease_id = deterministic_id(run_index, 0xA5);
    seed_wallet_mail_runtime_state(
        wallet_service.as_ref(),
        &mut state,
        &mut ctx,
        channel_id,
        lease_id,
    )
    .await?;

    let sample_limit = read_optional_u32_env(
        "LIVE_MAIL_CLEANUP_E2E_COUNT_SAMPLE_LIMIT",
        CLEANUP_COUNT_SAMPLE_LIMIT_DEFAULT,
    )
    .clamp(25, 500);

    let pre_primary_counts = mailbox_message_count_via_wallet_list(
        wallet_service.as_ref(),
        &mut state,
        &mut ctx,
        channel_id,
        lease_id,
        "primary",
        sample_limit,
        deterministic_id(run_index, 0xD1),
    )
    .await?;
    let pre_spam_counts = optional_mailbox_message_count_via_wallet_list(
        wallet_service.as_ref(),
        &mut state,
        &mut ctx,
        channel_id,
        lease_id,
        "spam",
        sample_limit,
        deterministic_id(run_index, 0xD2),
    )
    .await?;
    let pre_primary_total_snapshot = mailbox_total_count_via_wallet_count(
        wallet_service.as_ref(),
        &mut state,
        &mut ctx,
        channel_id,
        lease_id,
        "primary",
        deterministic_id(run_index, 0xE1),
    )
    .await?;
    let pre_spam_total_snapshot = optional_mailbox_total_count_via_wallet_count(
        wallet_service.as_ref(),
        &mut state,
        &mut ctx,
        channel_id,
        lease_id,
        "spam",
        deterministic_id(run_index, 0xE2),
    )
    .await?;

    let start_params = StartAgentParams {
        session_id,
        goal: query.to_string(),
        max_steps: 22,
        parent_session_id: None,
        initial_budget: 5_000,
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
    seed_resolved_intent(&mut state, session_id, IntentScopeProfile::Conversation);

    let run_timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let run_timestamp_iso_utc = iso_datetime_from_unix_ms(run_timestamp_ms);
    let started = Instant::now();
    let deadline = Duration::from_secs(CLEANUP_SLA_SECONDS);
    let mut captured_events: Vec<KernelEvent> = Vec::new();
    let mut approval_resume_attempts = 0usize;

    loop {
        drain_events(&mut event_rx, &mut captured_events);
        if let Some(fatal_error) = fatal_mail_connector_error(&captured_events) {
            return Err(anyhow!(
                "live cleanup e2e encountered fatal mailbox connector error: {}\nrecent_events:\n{}",
                fatal_error,
                summarize_recent_events(&captured_events, 24)
            ));
        }
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
                if is_waiting_for_approval(reason) {
                    if approval_resume_attempts >= MAX_APPROVAL_RESUME_ATTEMPTS {
                        return Err(anyhow!(
                            "cleanup e2e remained approval-gated after {} resume attempts\nrecent_events:\n{}",
                            MAX_APPROVAL_RESUME_ATTEMPTS,
                            summarize_recent_events(&captured_events, 24)
                        ));
                    }
                    let request_hash =
                        latest_require_approval_request_hash(&captured_events, session_id)
                            .or(current.pending_tool_hash)
                            .ok_or_else(|| {
                                anyhow!(
                            "missing approval request hash in cleanup e2e\nrecent_events:\n{}",
                            summarize_recent_events(&captured_events, 24)
                        )
                            })?;
                    let requires_pii_action = state
                        .get(&pii::review::request(&request_hash))
                        .map_err(|e| anyhow!("failed to read review request state: {}", e))?
                        .is_some();
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let approval_token = build_approval_token_for_resume(
                        request_hash,
                        now_ms,
                        current.pending_visual_hash,
                        requires_pii_action,
                    );
                    let resume_params = ResumeAgentParams {
                        session_id,
                        approval_token: Some(approval_token),
                    };
                    service
                        .handle_service_call(
                            &mut state,
                            "resume@v1",
                            &codec::to_bytes_canonical(&resume_params)
                                .map_err(|e| anyhow!("failed to encode resume params: {}", e))?,
                            &mut ctx,
                        )
                        .await?;
                    approval_resume_attempts += 1;
                    continue;
                }
                if requires_human_intervention(reason) {
                    return Err(anyhow!(
                        "cleanup e2e paused for intervention: {}\nrecent_events:\n{}",
                        reason,
                        summarize_recent_events(&captured_events, 24)
                    ));
                }
                return Err(anyhow!(
                    "cleanup e2e paused unexpectedly: {}\nrecent_events:\n{}",
                    reason,
                    summarize_recent_events(&captured_events, 24)
                ));
            }
            AgentStatus::Idle | AgentStatus::Terminated => {
                return Err(anyhow!(
                    "agent entered unexpected non-terminal status: {:?}",
                    current.status
                ));
            }
            AgentStatus::Completed(_) | AgentStatus::Failed(_) => {}
        }

        service
            .handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(|e| anyhow!("failed to encode step params: {}", e))?,
                &mut ctx,
            )
            .await?;
    }
    drain_events(&mut event_rx, &mut captured_events);

    let elapsed = started.elapsed();
    let final_state = read_agent_state(&state, session_id);
    if elapsed > deadline {
        return Err(anyhow!(
            "live cleanup e2e exceeded SLA: elapsed={}ms final_status={:?}\nrecent_events:\n{}",
            elapsed.as_millis(),
            final_state.status,
            summarize_recent_events(&captured_events, 24)
        ));
    }
    if !matches!(final_state.status, AgentStatus::Completed(_)) {
        return Err(anyhow!(
            "cleanup e2e did not complete; final status={:?}\nrecent_events:\n{}",
            final_state.status,
            summarize_recent_events(&captured_events, 24)
        ));
    }

    let post_primary_counts = mailbox_message_count_via_wallet_list(
        wallet_service.as_ref(),
        &mut state,
        &mut ctx,
        channel_id,
        lease_id,
        "primary",
        sample_limit,
        deterministic_id(run_index, 0xD3),
    )
    .await?;
    let post_spam_counts = optional_mailbox_message_count_via_wallet_list(
        wallet_service.as_ref(),
        &mut state,
        &mut ctx,
        channel_id,
        lease_id,
        "spam",
        sample_limit,
        deterministic_id(run_index, 0xD4),
    )
    .await?;
    let post_primary_total_snapshot = mailbox_total_count_via_wallet_count(
        wallet_service.as_ref(),
        &mut state,
        &mut ctx,
        channel_id,
        lease_id,
        "primary",
        deterministic_id(run_index, 0xE3),
    )
    .await?;
    let post_spam_total_snapshot = optional_mailbox_total_count_via_wallet_count(
        wallet_service.as_ref(),
        &mut state,
        &mut ctx,
        channel_id,
        lease_id,
        "spam",
        deterministic_id(run_index, 0xE4),
    )
    .await?;

    let mut saw_mail_connector_routing = false;
    let mut saw_mail_connector_action = false;
    let mut saw_mail_delete_routing = false;
    let mut saw_mail_delete_action = false;
    let mut saw_mail_list_routing = false;
    let mut saw_mail_list_action = false;
    let mut saw_web_routing = false;
    let mut saw_web_retrieve_receipt = false;
    let mut saw_firewall_require_approval = false;
    let mut saw_policy_require_approval = false;
    let mut terminal_chat_reply_events = 0usize;
    let mut saw_terminal_chat_reply = false;
    let mut final_reply = String::new();
    let mut mail_tool_structured_evidence = MailToolStructuredEvidence::default();
    let mut evidence = vec![
        format!(
            "mailbox_count pre primary_sample={} primary_list_total={} primary_absolute_total={} spam_sample={} spam_list_total={} spam_absolute_total={} sample_limit={}",
            pre_primary_counts.sampled_count,
            pre_primary_counts.list_reported_total_count,
            pre_primary_total_snapshot.mailbox_total_count,
            pre_spam_counts
                .map(|value| value.sampled_count.to_string())
                .unwrap_or_else(|| "unavailable".to_string()),
            pre_spam_counts
                .map(|value| value.list_reported_total_count.to_string())
                .unwrap_or_else(|| "unavailable".to_string()),
            pre_spam_total_snapshot
                .as_ref()
                .map(|value| value.mailbox_total_count.to_string())
                .unwrap_or_else(|| "unavailable".to_string()),
            sample_limit
        ),
        format!(
            "mailbox_count post primary_sample={} primary_list_total={} primary_absolute_total={} spam_sample={} spam_list_total={} spam_absolute_total={} sample_limit={}",
            post_primary_counts.sampled_count,
            post_primary_counts.list_reported_total_count,
            post_primary_total_snapshot.mailbox_total_count,
            post_spam_counts
                .map(|value| value.sampled_count.to_string())
                .unwrap_or_else(|| "unavailable".to_string()),
            post_spam_counts
                .map(|value| value.list_reported_total_count.to_string())
                .unwrap_or_else(|| "unavailable".to_string()),
            post_spam_total_snapshot
                .as_ref()
                .map(|value| value.mailbox_total_count.to_string())
                .unwrap_or_else(|| "unavailable".to_string()),
            sample_limit
        ),
    ];

    for event in &captured_events {
        match event {
            KernelEvent::FirewallInterception {
                verdict, target, ..
            } => {
                if verdict.eq_ignore_ascii_case("require_approval") {
                    saw_firewall_require_approval = true;
                    evidence.push(format!("firewall verdict={} target={}", verdict, target));
                }
            }
            KernelEvent::AgentActionResult {
                tool_name,
                output,
                agent_status,
                ..
            } => {
                if is_mail_connector_tool_name(tool_name) {
                    saw_mail_connector_action = true;
                    let lower = tool_name.to_ascii_lowercase();
                    if lower.contains("mail_delete_spam") {
                        saw_mail_delete_action = true;
                    }
                    if lower.contains("mail_list_recent") {
                        saw_mail_list_action = true;
                    }
                    parse_mail_tool_output_evidence(output, &mut mail_tool_structured_evidence);
                    evidence.push(format!("action:{} status={}", tool_name, agent_status));
                }
                let is_terminal_response_tool =
                    matches!(tool_name.as_str(), "chat__reply" | "agent__complete");
                if is_terminal_response_tool && agent_status.eq_ignore_ascii_case("completed") {
                    terminal_chat_reply_events += 1;
                    saw_terminal_chat_reply = true;
                    final_reply = output.clone();
                }
            }
            KernelEvent::RoutingReceipt(receipt) => {
                if is_mail_connector_tool_name(&receipt.tool_name) {
                    saw_mail_connector_routing = true;
                    let lower = receipt.tool_name.to_ascii_lowercase();
                    if lower.contains("mail_delete_spam") {
                        saw_mail_delete_routing = true;
                    }
                    if lower.contains("mail_list_recent") {
                        saw_mail_list_routing = true;
                    }
                    evidence.push(format!(
                        "routing:{} decision={} success={}",
                        receipt.tool_name, receipt.policy_decision, receipt.post_state.success
                    ));
                }
                if receipt
                    .policy_decision
                    .eq_ignore_ascii_case("require_approval")
                {
                    saw_policy_require_approval = true;
                }
                if matches!(receipt.tool_name.as_str(), "web__search" | "web__read") {
                    saw_web_routing = true;
                }
            }
            KernelEvent::WorkloadReceipt(workload) => {
                if let WorkloadReceipt::WebRetrieve(web) = &workload.receipt {
                    if matches!(web.tool_name.as_str(), "web__search" | "web__read") {
                        saw_web_retrieve_receipt = true;
                    }
                }
            }
            KernelEvent::AgentStep(trace) => {
                parse_mail_tool_output_evidence(
                    trace.raw_output.as_str(),
                    &mut mail_tool_structured_evidence,
                );
            }
            _ => {}
        }
    }

    let mail_tooling_path_observed = saw_mail_connector_routing || saw_mail_connector_action;
    let delete_tool_observed = saw_mail_delete_routing || saw_mail_delete_action;
    let list_tool_observed = saw_mail_list_routing || saw_mail_list_action;
    let mailbox_query_avoids_web_fallback = !saw_web_routing && !saw_web_retrieve_receipt;
    let approval_gate_evidence_present =
        saw_firewall_require_approval && saw_policy_require_approval;
    let delete_high_confidence_policy_present =
        mail_tool_structured_evidence.saw_delete_high_confidence_policy;
    let deleted_count_metric_observed = mail_tool_structured_evidence.saw_delete_spam_tool_output;
    let cleanup_scope_primary_observed = mail_tool_structured_evidence.saw_primary_cleanup_scope;
    let preservation_evidence_observed = mail_tool_structured_evidence.saw_preservation_evidence;
    let kept_vs_deleted_rationale_observed =
        mail_tool_structured_evidence.saw_kept_vs_deleted_rationale;
    let preservation_accounting_consistent =
        mail_tool_structured_evidence.saw_preservation_accounting_consistent;
    let explicit_preserved_reason_classes_observed =
        mail_tool_structured_evidence.saw_explicit_preserved_reason_classes;
    let terminal_chat_reply_non_empty = !final_reply.trim().is_empty();
    let terminal_lifecycle_single_chat_reply =
        terminal_chat_reply_events <= MAX_TERMINAL_CHAT_REPLY_EVENTS;
    let no_churn_signatures = churn_signatures(&captured_events).is_empty();

    let primary_sample_delta =
        pre_primary_counts.sampled_count as i64 - post_primary_counts.sampled_count as i64;
    let primary_list_reported_total_delta = pre_primary_counts.list_reported_total_count as i64
        - post_primary_counts.list_reported_total_count as i64;
    let pre_primary_total_count = pre_primary_total_snapshot.mailbox_total_count;
    let post_primary_total_count = post_primary_total_snapshot.mailbox_total_count;
    let pre_spam_total_count = pre_spam_total_snapshot
        .as_ref()
        .map(|snapshot| snapshot.mailbox_total_count);
    let post_spam_total_count = post_spam_total_snapshot
        .as_ref()
        .map(|snapshot| snapshot.mailbox_total_count);
    let primary_total_delta = pre_primary_total_count as i64 - post_primary_total_count as i64;
    let spam_sample_delta = match (pre_spam_counts, post_spam_counts) {
        (Some(pre), Some(post)) => Some(pre.sampled_count as i64 - post.sampled_count as i64),
        _ => None,
    };
    let spam_list_reported_total_delta = match (pre_spam_counts, post_spam_counts) {
        (Some(pre), Some(post)) => {
            Some(pre.list_reported_total_count as i64 - post.list_reported_total_count as i64)
        }
        _ => None,
    };
    let spam_total_delta = match (pre_spam_total_count, post_spam_total_count) {
        (Some(pre), Some(post)) => Some(pre as i64 - post as i64),
        _ => None,
    };
    let combined_total_delta = match (pre_spam_total_count, post_spam_total_count) {
        (Some(pre), Some(post)) => {
            Some((pre_primary_total_count + pre) as i64 - (post_primary_total_count + post) as i64)
        }
        _ => None,
    };
    let primary_total_not_worse = post_primary_total_count <= pre_primary_total_count;
    let combined_total_not_worse = combined_total_delta.map(|delta| delta >= 0);
    let primary_count_provenance_raw_observed =
        count_provenance_raw_observation_present(&pre_primary_total_snapshot.provenance)
            && count_provenance_raw_observation_present(&post_primary_total_snapshot.provenance);
    let primary_count_provenance_marker_observed = !pre_primary_total_snapshot
        .provenance
        .freshness_marker
        .trim()
        .is_empty()
        && !post_primary_total_snapshot
            .provenance
            .freshness_marker
            .trim()
            .is_empty();
    let primary_count_provenance_fresh =
        is_count_provenance_fresh(&pre_primary_total_snapshot.provenance.freshness_marker)
            && is_count_provenance_fresh(&post_primary_total_snapshot.provenance.freshness_marker);
    let primary_count_provenance_stale =
        is_count_provenance_stale(&pre_primary_total_snapshot.provenance.freshness_marker)
            || is_count_provenance_stale(&post_primary_total_snapshot.provenance.freshness_marker);
    let delete_receipt_absolute_delta_observed =
        mail_tool_structured_evidence.max_mailbox_total_count_delta > 0;
    let primary_count_delta_policy_pass = if primary_count_provenance_fresh {
        primary_total_not_worse
    } else if primary_count_provenance_stale {
        primary_total_not_worse || delete_receipt_absolute_delta_observed
    } else {
        // Unknown freshness markers must still be diagnosable via non-empty marker
        // and corroborated by delete-receipt absolute delta or non-worse totals.
        primary_count_provenance_marker_observed
            && (primary_total_not_worse || delete_receipt_absolute_delta_observed)
    };
    let count_provenance_staleness_diagnosable =
        primary_count_provenance_fresh || primary_count_provenance_stale;
    evidence.push(format!(
        "count_provenance pre(status_exists={:?},select_exists={:?},uid_search_count={:?},search_count={:?},freshness_marker={}) post(status_exists={:?},select_exists={:?},uid_search_count={:?},search_count={:?},freshness_marker={})",
        pre_primary_total_snapshot.provenance.status_exists,
        pre_primary_total_snapshot.provenance.select_exists,
        pre_primary_total_snapshot.provenance.uid_search_count,
        pre_primary_total_snapshot.provenance.search_count,
        pre_primary_total_snapshot.provenance.freshness_marker,
        post_primary_total_snapshot.provenance.status_exists,
        post_primary_total_snapshot.provenance.select_exists,
        post_primary_total_snapshot.provenance.uid_search_count,
        post_primary_total_snapshot.provenance.search_count,
        post_primary_total_snapshot.provenance.freshness_marker
    ));
    evidence.push(format!(
        "count_delta_policy fresh={} stale={} delete_receipt_delta={} pass={}",
        primary_count_provenance_fresh,
        primary_count_provenance_stale,
        delete_receipt_absolute_delta_observed,
        primary_count_delta_policy_pass
    ));
    let absolute_count_delta_path_observed = pre_primary_total_count > 0
        && post_primary_total_count > 0
        && primary_count_provenance_raw_observed
        && primary_count_provenance_marker_observed
        && (pre_spam_total_count.is_none() || post_spam_total_count.is_some());
    let absolute_delete_delta_observed = mail_tool_structured_evidence.max_deleted_count == 0
        || mail_tool_structured_evidence.max_mailbox_total_count_delta > 0;

    let mut deterministic_checks = BTreeMap::new();
    deterministic_checks.insert(
        "terminal_chat_reply_observed".to_string(),
        saw_terminal_chat_reply,
    );
    deterministic_checks.insert(
        "terminal_chat_reply_non_empty".to_string(),
        terminal_chat_reply_non_empty,
    );
    deterministic_checks.insert("elapsed_within_sla".to_string(), elapsed <= deadline);
    deterministic_checks.insert(
        "mail_tooling_path_observed".to_string(),
        mail_tooling_path_observed,
    );
    deterministic_checks.insert("delete_tool_observed".to_string(), delete_tool_observed);
    deterministic_checks.insert(
        "mailbox_query_avoids_web_fallback".to_string(),
        mailbox_query_avoids_web_fallback,
    );
    deterministic_checks.insert(
        "approval_gate_evidence_present".to_string(),
        approval_gate_evidence_present,
    );
    deterministic_checks.insert(
        "delete_high_confidence_policy_present".to_string(),
        delete_high_confidence_policy_present,
    );
    deterministic_checks.insert(
        "deleted_count_metric_observed".to_string(),
        deleted_count_metric_observed,
    );
    deterministic_checks.insert(
        "cleanup_scope_primary_observed".to_string(),
        cleanup_scope_primary_observed,
    );
    deterministic_checks.insert(
        "preservation_evidence_observed".to_string(),
        preservation_evidence_observed,
    );
    deterministic_checks.insert(
        "kept_vs_deleted_rationale_observed".to_string(),
        kept_vs_deleted_rationale_observed,
    );
    deterministic_checks.insert(
        "preservation_accounting_consistent".to_string(),
        preservation_accounting_consistent,
    );
    deterministic_checks.insert(
        "explicit_preserved_reason_classes_observed".to_string(),
        explicit_preserved_reason_classes_observed,
    );
    deterministic_checks.insert(
        "absolute_count_delta_path_observed".to_string(),
        absolute_count_delta_path_observed,
    );
    deterministic_checks.insert(
        "count_provenance_raw_observed".to_string(),
        primary_count_provenance_raw_observed,
    );
    deterministic_checks.insert(
        "count_provenance_marker_observed".to_string(),
        primary_count_provenance_marker_observed,
    );
    deterministic_checks.insert(
        "count_provenance_staleness_diagnosable".to_string(),
        count_provenance_staleness_diagnosable,
    );
    deterministic_checks.insert(
        "primary_count_delta_policy_pass".to_string(),
        primary_count_delta_policy_pass,
    );
    deterministic_checks.insert(
        "absolute_delete_delta_observed".to_string(),
        absolute_delete_delta_observed,
    );
    deterministic_checks.insert(
        "absolute_primary_not_worse".to_string(),
        primary_total_not_worse,
    );
    deterministic_checks.insert(
        "absolute_combined_not_worse".to_string(),
        combined_total_not_worse.unwrap_or(primary_total_not_worse),
    );
    deterministic_checks.insert(
        "terminal_lifecycle_single_chat_reply".to_string(),
        terminal_lifecycle_single_chat_reply,
    );
    deterministic_checks.insert("no_churn_signatures".to_string(), no_churn_signatures);

    let deterministic_failures = deterministic_checks
        .iter()
        .filter_map(|(name, passed)| (!*passed).then_some(name.clone()))
        .collect::<Vec<_>>();

    let deterministic_payload = json!({
        "checks": deterministic_checks,
        "elapsed_ms": elapsed.as_millis(),
        "sla_seconds": CLEANUP_SLA_SECONDS,
        "terminal_chat_reply_events": terminal_chat_reply_events,
        "list_tool_observed": list_tool_observed,
        "cleanup_metrics": {
            "sample_limit": sample_limit,
            "pre_primary_inbox_count_sampled": pre_primary_counts.sampled_count,
            "post_primary_inbox_count_sampled": post_primary_counts.sampled_count,
            "primary_inbox_delta_sampled": primary_sample_delta,
            "pre_primary_inbox_count_total_from_list": pre_primary_counts.list_reported_total_count,
            "post_primary_inbox_count_total_from_list": post_primary_counts.list_reported_total_count,
            "primary_inbox_delta_total_from_list": primary_list_reported_total_delta,
            "pre_primary_inbox_count_total": pre_primary_total_count,
            "post_primary_inbox_count_total": post_primary_total_count,
            "primary_inbox_delta_total": primary_total_delta,
            "pre_primary_count_provenance": pre_primary_total_snapshot.provenance.clone(),
            "post_primary_count_provenance": post_primary_total_snapshot.provenance.clone(),
            "pre_spam_count_sampled": pre_spam_counts.map(|value| value.sampled_count),
            "post_spam_count_sampled": post_spam_counts.map(|value| value.sampled_count),
            "spam_delta_sampled": spam_sample_delta,
            "pre_spam_count_total_from_list": pre_spam_counts.map(|value| value.list_reported_total_count),
            "post_spam_count_total_from_list": post_spam_counts.map(|value| value.list_reported_total_count),
            "spam_delta_total_from_list": spam_list_reported_total_delta,
            "pre_spam_count_total": pre_spam_total_count,
            "post_spam_count_total": post_spam_total_count,
            "spam_delta_total": spam_total_delta,
            "pre_spam_count_provenance": pre_spam_total_snapshot
                .as_ref()
                .map(|snapshot| snapshot.provenance.clone()),
            "post_spam_count_provenance": post_spam_total_snapshot
                .as_ref()
                .map(|snapshot| snapshot.provenance.clone()),
            "combined_delta_total": combined_total_delta,
            "primary_total_not_worse": primary_total_not_worse,
            "combined_total_not_worse": combined_total_not_worse,
            "count_provenance_raw_observed": primary_count_provenance_raw_observed,
            "count_provenance_marker_observed": primary_count_provenance_marker_observed,
            "count_provenance_staleness_diagnosable": count_provenance_staleness_diagnosable,
            "primary_count_provenance_fresh": primary_count_provenance_fresh,
            "primary_count_provenance_stale": primary_count_provenance_stale,
            "primary_count_delta_policy_pass": primary_count_delta_policy_pass,
        },
        "mail_tool_structured_evidence": {
            "saw_delete_high_confidence_policy": mail_tool_structured_evidence.saw_delete_high_confidence_policy,
            "max_evaluated_count": mail_tool_structured_evidence.max_evaluated_count,
            "max_deleted_count": mail_tool_structured_evidence.max_deleted_count,
            "max_high_confidence_deleted_count": mail_tool_structured_evidence.max_high_confidence_deleted_count,
            "saw_delete_spam_tool_output": mail_tool_structured_evidence.saw_delete_spam_tool_output,
            "saw_primary_cleanup_scope": mail_tool_structured_evidence.saw_primary_cleanup_scope,
            "saw_preservation_evidence": mail_tool_structured_evidence.saw_preservation_evidence,
            "saw_kept_vs_deleted_rationale": mail_tool_structured_evidence.saw_kept_vs_deleted_rationale,
            "saw_preservation_accounting_consistent": mail_tool_structured_evidence.saw_preservation_accounting_consistent,
            "max_preserved_transactional_or_personal_count": mail_tool_structured_evidence.max_preserved_transactional_or_personal_count,
            "max_preserved_trusted_system_count": mail_tool_structured_evidence.max_preserved_trusted_system_count,
            "max_preserved_low_confidence_other_count": mail_tool_structured_evidence.max_preserved_low_confidence_other_count,
            "max_preserved_due_to_delete_cap_count": mail_tool_structured_evidence.max_preserved_due_to_delete_cap_count,
            "max_total_preserved_count": mail_tool_structured_evidence.max_total_preserved_count,
            "max_mailbox_total_count_before": mail_tool_structured_evidence.max_mailbox_total_count_before,
            "max_mailbox_total_count_after": mail_tool_structured_evidence.max_mailbox_total_count_after,
            "max_mailbox_total_count_delta": mail_tool_structured_evidence.max_mailbox_total_count_delta,
            "saw_explicit_preserved_reason_classes": mail_tool_structured_evidence.saw_explicit_preserved_reason_classes,
        },
        "routing_markers": {
            "saw_mail_connector_routing": saw_mail_connector_routing,
            "saw_mail_connector_action": saw_mail_connector_action,
            "saw_mail_delete_routing": saw_mail_delete_routing,
            "saw_mail_delete_action": saw_mail_delete_action,
            "saw_mail_list_routing": saw_mail_list_routing,
            "saw_mail_list_action": saw_mail_list_action,
            "saw_web_routing": saw_web_routing,
            "saw_web_retrieve_receipt": saw_web_retrieve_receipt,
            "saw_firewall_require_approval": saw_firewall_require_approval,
            "saw_policy_require_approval": saw_policy_require_approval,
        },
        "event_evidence": evidence,
    });
    println!(
        "LIVE_MAIL_CLEANUP_E2E_DETERMINISTIC_{}={}",
        label,
        serde_json::to_string_pretty(&deterministic_payload)?
    );

    if !deterministic_failures.is_empty() {
        return Err(anyhow!(
            "cleanup deterministic checks failed ({}): {}\nfinal_reply:\n{}\nrecent_events:\n{}",
            label,
            deterministic_failures.join(", "),
            final_reply,
            summarize_recent_events(&captured_events, 24)
        ));
    }

    let final_reply_excerpt = final_reply.chars().take(2_000).collect::<String>();
    let final_reply_excerpt = redact_iso_utc_timestamps(&final_reply_excerpt);
    let arbiter_cleanup_metrics_payload = json!({
        "sample_limit": sample_limit,
        "pre_primary_inbox_count_sampled": pre_primary_counts.sampled_count,
        "post_primary_inbox_count_sampled": post_primary_counts.sampled_count,
        "primary_inbox_delta_sampled": primary_sample_delta,
        "pre_primary_inbox_count_total_from_list": pre_primary_counts.list_reported_total_count,
        "post_primary_inbox_count_total_from_list": post_primary_counts.list_reported_total_count,
        "primary_inbox_delta_total_from_list": primary_list_reported_total_delta,
        "pre_primary_inbox_count_total": pre_primary_total_count,
        "post_primary_inbox_count_total": post_primary_total_count,
        "primary_inbox_delta_total": primary_total_delta,
        "pre_primary_count_provenance": pre_primary_total_snapshot.provenance.clone(),
        "post_primary_count_provenance": post_primary_total_snapshot.provenance.clone(),
        "pre_spam_count_sampled": pre_spam_counts.map(|value| value.sampled_count),
        "post_spam_count_sampled": post_spam_counts.map(|value| value.sampled_count),
        "spam_delta_sampled": spam_sample_delta,
        "pre_spam_count_total_from_list": pre_spam_counts.map(|value| value.list_reported_total_count),
        "post_spam_count_total_from_list": post_spam_counts.map(|value| value.list_reported_total_count),
        "spam_delta_total_from_list": spam_list_reported_total_delta,
        "pre_spam_count_total": pre_spam_total_count,
        "post_spam_count_total": post_spam_total_count,
        "spam_delta_total": spam_total_delta,
        "pre_spam_count_provenance": pre_spam_total_snapshot
            .as_ref()
            .map(|snapshot| snapshot.provenance.clone()),
        "post_spam_count_provenance": post_spam_total_snapshot
            .as_ref()
            .map(|snapshot| snapshot.provenance.clone()),
        "combined_delta_total": combined_total_delta,
        "primary_total_not_worse": primary_total_not_worse,
        "combined_total_not_worse": combined_total_not_worse,
        "count_provenance_raw_observed": primary_count_provenance_raw_observed,
        "count_provenance_marker_observed": primary_count_provenance_marker_observed,
        "count_provenance_staleness_diagnosable": count_provenance_staleness_diagnosable,
        "primary_count_provenance_fresh": primary_count_provenance_fresh,
        "primary_count_provenance_stale": primary_count_provenance_stale,
        "primary_count_delta_policy_pass": primary_count_delta_policy_pass,
        "max_deleted_count": mail_tool_structured_evidence.max_deleted_count,
        "max_high_confidence_deleted_count": mail_tool_structured_evidence.max_high_confidence_deleted_count,
        "max_mailbox_total_count_before": mail_tool_structured_evidence.max_mailbox_total_count_before,
        "max_mailbox_total_count_after": mail_tool_structured_evidence.max_mailbox_total_count_after,
        "max_mailbox_total_count_delta": mail_tool_structured_evidence.max_mailbox_total_count_delta,
        "explicit_preserved_reason_classes_observed": explicit_preserved_reason_classes_observed,
        "max_preserved_transactional_or_personal_count": mail_tool_structured_evidence.max_preserved_transactional_or_personal_count,
        "max_preserved_trusted_system_count": mail_tool_structured_evidence.max_preserved_trusted_system_count,
        "max_preserved_low_confidence_other_count": mail_tool_structured_evidence.max_preserved_low_confidence_other_count,
        "max_preserved_due_to_delete_cap_count": mail_tool_structured_evidence.max_preserved_due_to_delete_cap_count,
        "max_total_preserved_count": mail_tool_structured_evidence.max_total_preserved_count,
    });
    let arbiter_payload = json!({
        "label": label,
        "query": query,
        "run_timestamp_ms": run_timestamp_ms,
        "run_timestamp_iso_utc": run_timestamp_iso_utc,
        "deterministic": deterministic_payload,
        "cleanup_metrics": arbiter_cleanup_metrics_payload,
        "final_reply_excerpt": final_reply_excerpt,
        "final_reply_char_len": final_reply.chars().count(),
        "event_evidence": evidence,
    });
    println!(
        "LIVE_MAIL_CLEANUP_E2E_ARBITER_INPUT_{}={}",
        label,
        serde_json::to_string_pretty(&arbiter_payload)?
    );

    let verdict = run_cleanup_arbiter(arbiter_runtime, &arbiter_payload).await?;
    let verdict_json = json!({
        "pass": verdict.pass,
        "confidence": verdict.confidence,
        "rationale": verdict.rationale,
        "failures": verdict.failures,
    });
    println!(
        "LIVE_MAIL_CLEANUP_E2E_ARBITER_VERDICT_{}={}",
        label,
        serde_json::to_string_pretty(&verdict_json)?
    );

    if !verdict.pass {
        return Err(anyhow!(
            "cleanup arbiter failed ({}): confidence={} rationale={} failures={}",
            label,
            verdict.confidence,
            verdict.rationale,
            verdict.failures.join("; ")
        ));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live internet + external inference required"]
async fn live_latest_mail_chat_reply_e2e() -> Result<()> {
    build_test_artifacts();

    let openai_api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| anyhow!("OPENAI_API_KEY required for live e2e"))?;
    let openai_model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
    let arbiter_model =
        std::env::var("MAIL_E2E_ARBITER_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
    let api_url = "https://api.openai.com/v1/chat/completions".to_string();

    let agent_runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        api_url.clone(),
        openai_api_key.clone(),
        openai_model,
    ));
    let arbiter_runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        api_url,
        openai_api_key,
        arbiter_model,
    ));

    let query = std::env::var("LIVE_MAIL_E2E_QUERY").unwrap_or_else(|_| PRIMARY_QUERY.to_string());
    let label = std::env::var("LIVE_MAIL_E2E_LABEL").unwrap_or_else(|_| "single_run".to_string());
    let run_index = std::env::var("LIVE_MAIL_E2E_RUN_INDEX")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1);

    println!(
        "LIVE_MAIL_E2E_LOCKED_CONSTANTS={}",
        serde_json::to_string_pretty(&json!({
            "SLA_SECONDS": SLA_SECONDS,
            "MIN_SOURCES": MIN_SOURCES,
            "REQUIRED_STORIES": REQUIRED_STORIES,
            "REQUIRED_CITATIONS_PER_STORY": REQUIRED_CITATIONS_PER_STORY,
            "CONSECUTIVE_PASS_TARGET": CONSECUTIVE_PASS_TARGET,
            "GENERALIZATION_VARIANTS": GENERALIZATION_VARIANTS,
            "PRIMARY_QUERY": PRIMARY_QUERY,
            "ACTIVE_QUERY": query,
            "RUN_LABEL": label,
            "RUN_INDEX": run_index,
        }))?
    );

    run_live_case(&label, &query, run_index, agent_runtime, arbiter_runtime).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live external inference required for mailbox write-intent approval routing"]
async fn live_mail_write_intent_routes_to_mail_tooling_with_approval_e2e() -> Result<()> {
    build_test_artifacts();

    let openai_api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| anyhow!("OPENAI_API_KEY required for live e2e"))?;
    let openai_model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
    let api_url = "https://api.openai.com/v1/chat/completions".to_string();

    let agent_runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        api_url,
        openai_api_key,
        openai_model,
    ));

    let query = std::env::var("LIVE_MAIL_WRITE_INTENT_E2E_QUERY")
        .unwrap_or_else(|_| PRIMARY_WRITE_INTENT_QUERY.to_string());
    let label = std::env::var("LIVE_MAIL_WRITE_INTENT_E2E_LABEL")
        .unwrap_or_else(|_| "write_intent_single_run".to_string());
    let run_index = std::env::var("LIVE_MAIL_WRITE_INTENT_E2E_RUN_INDEX")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1001);

    println!(
        "LIVE_MAIL_WRITE_INTENT_E2E_LOCKED_CONSTANTS={}",
        serde_json::to_string_pretty(&json!({
            "SLA_SECONDS": SLA_SECONDS,
            "PRIMARY_QUERY": PRIMARY_WRITE_INTENT_QUERY,
            "ACTIVE_QUERY": query,
            "RUN_LABEL": label,
            "RUN_INDEX": run_index,
        }))?
    );

    run_live_write_intent_case(&label, &query, run_index, agent_runtime).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live external inference required for mailbox large-volume parsing"]
async fn live_mail_large_volume_parse_with_confidence_e2e() -> Result<()> {
    build_test_artifacts();

    let openai_api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| anyhow!("OPENAI_API_KEY required for live e2e"))?;
    let openai_model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
    let api_url = "https://api.openai.com/v1/chat/completions".to_string();

    let agent_runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        api_url,
        openai_api_key,
        openai_model,
    ));

    let query = std::env::var("LIVE_MAIL_LARGE_VOLUME_E2E_QUERY")
        .unwrap_or_else(|_| PRIMARY_LARGE_VOLUME_QUERY.to_string());
    let label = std::env::var("LIVE_MAIL_LARGE_VOLUME_E2E_LABEL")
        .unwrap_or_else(|_| "large_volume_single_run".to_string());
    let run_index = std::env::var("LIVE_MAIL_LARGE_VOLUME_E2E_RUN_INDEX")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2001);

    println!(
        "LIVE_MAIL_LARGE_VOLUME_E2E_LOCKED_CONSTANTS={}",
        serde_json::to_string_pretty(&json!({
            "SLA_SECONDS": SLA_SECONDS,
            "PRIMARY_QUERY": PRIMARY_LARGE_VOLUME_QUERY,
            "ACTIVE_QUERY": query,
            "RUN_LABEL": label,
            "RUN_INDEX": run_index,
            "PARSE_CONFIDENCE_FLOOR_BPS": LARGE_VOLUME_PARSE_CONFIDENCE_FLOOR_BPS,
            "MIN_EVALUATED_DEFAULT": LARGE_VOLUME_MIN_EVALUATED_DEFAULT,
        }))?
    );

    run_live_large_volume_case(&label, &query, run_index, agent_runtime).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live external inference required for mailbox high-confidence spam delete"]
async fn live_mail_delete_spam_with_high_confidence_policy_e2e() -> Result<()> {
    build_test_artifacts();

    let openai_api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| anyhow!("OPENAI_API_KEY required for live e2e"))?;
    let openai_model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
    let api_url = "https://api.openai.com/v1/chat/completions".to_string();

    let agent_runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        api_url,
        openai_api_key,
        openai_model,
    ));

    let query = std::env::var("LIVE_MAIL_DELETE_SPAM_E2E_QUERY")
        .unwrap_or_else(|_| PRIMARY_DELETE_SPAM_QUERY.to_string());
    let label = std::env::var("LIVE_MAIL_DELETE_SPAM_E2E_LABEL")
        .unwrap_or_else(|_| "delete_spam_single_run".to_string());
    let run_index = std::env::var("LIVE_MAIL_DELETE_SPAM_E2E_RUN_INDEX")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(3001);

    println!(
        "LIVE_MAIL_DELETE_SPAM_E2E_LOCKED_CONSTANTS={}",
        serde_json::to_string_pretty(&json!({
            "SLA_SECONDS": SLA_SECONDS,
            "PRIMARY_QUERY": PRIMARY_DELETE_SPAM_QUERY,
            "ACTIVE_QUERY": query,
            "RUN_LABEL": label,
            "RUN_INDEX": run_index,
        }))?
    );

    run_live_delete_spam_case(&label, &query, run_index, agent_runtime).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live external inference required for mailbox cleanup validation"]
async fn live_mail_cleanup_inbox_reduces_count_and_deletes_spam_e2e() -> Result<()> {
    build_test_artifacts();

    let openai_api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| anyhow!("OPENAI_API_KEY required for live e2e"))?;
    let openai_model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
    let arbiter_model =
        std::env::var("MAIL_E2E_ARBITER_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
    let api_url = "https://api.openai.com/v1/chat/completions".to_string();

    let agent_runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        api_url.clone(),
        openai_api_key.clone(),
        openai_model,
    ));
    let arbiter_runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        api_url,
        openai_api_key,
        arbiter_model,
    ));

    let query = std::env::var("LIVE_MAIL_CLEANUP_E2E_QUERY")
        .unwrap_or_else(|_| PRIMARY_CLEANUP_INBOX_QUERY.to_string());
    let label = std::env::var("LIVE_MAIL_CLEANUP_E2E_LABEL")
        .unwrap_or_else(|_| "cleanup_inbox_single_run".to_string());
    let run_index = std::env::var("LIVE_MAIL_CLEANUP_E2E_RUN_INDEX")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(4001);
    let sample_limit = read_optional_u32_env(
        "LIVE_MAIL_CLEANUP_E2E_COUNT_SAMPLE_LIMIT",
        CLEANUP_COUNT_SAMPLE_LIMIT_DEFAULT,
    )
    .clamp(25, 500);

    println!(
        "LIVE_MAIL_CLEANUP_E2E_LOCKED_CONSTANTS={}",
        serde_json::to_string_pretty(&json!({
            "SLA_SECONDS": CLEANUP_SLA_SECONDS,
            "PRIMARY_QUERY": PRIMARY_CLEANUP_INBOX_QUERY,
            "ACTIVE_QUERY": query,
            "RUN_LABEL": label,
            "RUN_INDEX": run_index,
            "COUNT_SAMPLE_LIMIT": sample_limit,
        }))?
    );

    run_live_cleanup_inbox_case(&label, &query, run_index, agent_runtime, arbiter_runtime).await
}

#[test]
fn helper_detects_absolute_utc_datetime() {
    assert!(contains_absolute_utc_datetime(
        "Run timestamp (UTC): 2026-02-19T12:34:56Z"
    ));
    assert!(!contains_absolute_utc_datetime(
        "Run timestamp (UTC): 2026-02-19 12:34:56"
    ));
}

#[test]
fn helper_parses_mail_sections() {
    let reply = "\
Latest email:\n\
From: sender@example.com\n\
Subject: test\n\
Received at (UTC): 2026-02-19T12:34:56Z\n\
Summary: hello\n\
Citations:\n\
- Source | https://mail.example.com/msg/abc | 2026-02-19T12:34:56Z\n\
Confidence: medium\n\
Caveat: Could be partial if mailbox sync is delayed.\n";

    let sections = parse_story_sections(reply);
    assert_eq!(sections.len(), REQUIRED_STORIES);
    assert!(validate_story_sections(reply).is_empty());
}

fn routing_event_for_test(step_index: u32, success: bool, checks: &[&str]) -> KernelEvent {
    KernelEvent::RoutingReceipt(RoutingReceiptEvent {
        session_id: [7u8; 32],
        step_index,
        intent_hash: "intent_hash".to_string(),
        policy_decision: "allowed".to_string(),
        tool_name: "web__read".to_string(),
        tool_version: "test".to_string(),
        pre_state: RoutingStateSummary {
            agent_status: "Running".to_string(),
            tier: "tool_first".to_string(),
            step_index,
            consecutive_failures: 0,
            target_hint: None,
        },
        action_json: "{}".to_string(),
        post_state: RoutingPostStateSummary {
            agent_status: "Running".to_string(),
            tier: "tool_first".to_string(),
            step_index: step_index + 1,
            consecutive_failures: 1,
            success,
            verification_checks: checks.iter().map(|value| value.to_string()).collect(),
        },
        artifacts: vec![],
        failure_class: None,
        failure_class_name: String::new(),
        intent_class: "web.research".to_string(),
        incident_id: String::new(),
        incident_stage: "none".to_string(),
        strategy_name: "none".to_string(),
        strategy_node: "none".to_string(),
        gate_state: "none".to_string(),
        resolution_action: "execute".to_string(),
        stop_condition_hit: false,
        escalation_path: None,
        scs_lineage_ptr: None,
        mutation_receipt_ptr: None,
        policy_binding_hash: "binding_hash".to_string(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    })
}

#[test]
fn helper_classifies_churn_signatures() {
    let events = vec![
        routing_event_for_test(
            1,
            false,
            &[
                "attempt_key_hash=abc123",
                "attempt_retry_blocked_without_change=false",
            ],
        ),
        routing_event_for_test(
            2,
            false,
            &[
                "attempt_key_hash=abc123",
                "attempt_retry_blocked_without_change=false",
            ],
        ),
        routing_event_for_test(
            3,
            false,
            &[
                "attempt_key_hash=abc123",
                "attempt_retry_blocked_without_change=true",
            ],
        ),
    ];
    let signatures = churn_signatures(&events);
    assert!(
        signatures
            .iter()
            .any(|value| value.contains("attempt_key_repeated")),
        "expected repeated attempt signature, got {:?}",
        signatures
    );
    assert!(
        signatures
            .iter()
            .any(|value| value.contains("blocked_without_change")),
        "expected blocked-without-change signature, got {:?}",
        signatures
    );
}
