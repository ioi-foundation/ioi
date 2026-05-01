use anyhow::{anyhow, Result};
use async_trait::async_trait;
use image::{ImageBuffer, ImageFormat, Rgba};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_crypto::sign::eddsa::Ed25519KeyPair;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_memory::MemoryRuntime;
use ioi_services::agentic::rules::DefaultPolicy;
use ioi_services::agentic::runtime::keys::{AGENT_POLICY_PREFIX, INCIDENT_PREFIX};
use ioi_services::agentic::runtime::service::decision_loop::helpers::default_safe_policy;
use ioi_services::agentic::runtime::service::recovery::incident::IncidentState;
use ioi_services::agentic::runtime::{
    AgentMode, AgentState, AgentStatus, ResumeAgentParams, RuntimeAgentService, StartAgentParams,
    StepAgentParams,
};
use ioi_services::wallet_network::WalletNetworkService;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::action::PiiApprovalAction;
use ioi_types::app::action::{ApprovalAuthority, ApprovalGrant};
use ioi_types::app::agentic::RegisterApprovalAuthorityParams;
use ioi_types::app::agentic::{
    CapabilityId, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
};
use ioi_types::app::{
    account_id_from_key_material, ActionRequest, ContextSlice, KernelEvent, MailConnectorAuthMode,
    MailConnectorConfig, MailConnectorEndpoint, MailConnectorProvider, MailConnectorSecretAliases,
    MailConnectorTlsMode, MailConnectorUpsertParams, RoutingReceiptEvent, SecretKind,
    SignatureSuite, VaultSecretRecord, WorkloadActivityKind, WorkloadExecReceipt, WorkloadReceipt,
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
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use tokio::sync::broadcast;
use zip::ZipArchive;

use super::types::{
    cec_receipt_bool, cec_receipt_latest_values, cec_receipt_usize, cec_receipt_value,
    has_policy_decision, has_verification_pair, observation_has_any_tool_name,
    observation_has_tool_name, parse_verification_fact, parse_verification_facts, ActionEvidence,
    CecReceiptEvidence, CommandHistoryEvidence, EnvironmentReceiptObservation,
    GoogleCalendarPayloadObservation, GoogleGmailPayloadObservation, GoogleObservation,
    IntentResolutionEvidence, MailObservation, MailReadLatestPayloadObservation,
    MailReplyPayloadObservation, ParentPlaybookObservation, PlannedToolCallEvidence, QueryCase,
    RouteDecisionObservation, RunObservation, ScreenshotObservation, ToolNormalizationObservation,
    ToolRecoveryObservation, WebObservation,
};

include!("harness/gui_mock.rs");

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
const VLC_INSTALL_UNSEEDED_CASE_ID: &str = "download_and_install_vlc_media_player_unseeded";
const VLC_INSTALL_FIXTURE_MODE: &str = "apt_get_vlc_fixture_v1";
const VLC_INSTALL_FIXTURE_PROBE_SOURCE: &str = "harness.vlc_install_fixture";
const DESKTOP_PROJECT_CREATE_CASE_ID: &str =
    "create_a_new_folder_on_my_desktop_called_project_some_number";
const DESKTOP_PROJECT_CREATE_FIXTURE_MODE: &str = "desktop_project_create_fixture_v1";
const DESKTOP_PROJECT_CREATE_FIXTURE_PROBE_SOURCE: &str = "harness.desktop_project_create_fixture";
const PROJECTS_ZIP_CASE_ID: &str =
    "compress_the_projects_folder_into_a_zip_file_and_put_it_on_my_desktop";
const PROJECTS_ZIP_FIXTURE_MODE: &str = "desktop_projects_zip_fixture_v1";
const PROJECTS_ZIP_FIXTURE_PROBE_SOURCE: &str = "harness.projects_zip_fixture";
const PROJECTS_ZIP_EXPECTED_ENTRIES: [&str; 3] = ["README.md", "docs/spec.txt", "src/main.rs"];

fn build_memory_runtime() -> Result<Arc<MemoryRuntime>> {
    Ok(Arc::new(MemoryRuntime::open_sqlite_in_memory()?))
}
const DOWNLOADS_LOWERCASE_CASE_ID: &str = "rename_every_file_in_my_downloads_folder_to_lowercase";
const DOWNLOADS_LOWERCASE_FIXTURE_MODE: &str = "downloads_lowercase_fixture_v1";
const DOWNLOADS_LOWERCASE_FIXTURE_PROBE_SOURCE: &str = "harness.downloads_lowercase_fixture";
const DOWNLOADS_LOWERCASE_TARGET_PREFIX: &str = "ioi_lowercase_";
const DOWNLOADS_LOWERCASE_EXPECTED_FINAL_FILES: [&str; 3] =
    ["alpha.txt", "budget 2026.pdf", "mixed_case.jpg"];
const DOWNLOADS_LOWERCASE_EXPECTED_ORIGINAL_FILES: [&str; 3] =
    ["Alpha.TXT", "Budget 2026.PDF", "MiXeD_Case.JPG"];
const DOWNLOADS_PNG_MOVE_CASE_ID: &str =
    "move_all_png_files_from_downloads_into_a_new_folder_called_images";
const DOWNLOADS_PNG_MOVE_FIXTURE_MODE: &str = "downloads_png_move_fixture_v1";
const DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE: &str = "harness.downloads_png_move_fixture";
const DOWNLOADS_PNG_MOVE_TARGET_PREFIX: &str = "ioi_png_move_";
const DOWNLOADS_PNG_MOVE_IMAGES_DIR_NAME: &str = "Images";
const DOWNLOADS_PNG_MOVE_EXPECTED_PNG_FILES: [&str; 2] = ["alpha.png", "graph.png"];
const DOWNLOADS_PNG_MOVE_EXPECTED_NON_PNG_FILES: [&str; 2] = ["notes.txt", "thumb.jpg"];
const DESKTOP_DOCUMENTS_BACKUP_CASE_ID: &str =
    "back_up_my_desktop_and_documents_folders_to_an_external_drive";
const DESKTOP_DOCUMENTS_BACKUP_FIXTURE_MODE: &str =
    "desktop_documents_backup_external_drive_fixture_v1";
const DESKTOP_DOCUMENTS_BACKUP_FIXTURE_PROBE_SOURCE: &str =
    "harness.desktop_documents_backup_fixture";
const DESKTOP_DOCUMENTS_BACKUP_TARGET_PREFIX: &str = "ioi_backup_";
const DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DESKTOP_FILES: [&str; 3] =
    ["Projects/roadmap.md", "Screenshots/sprint.png", "todo.txt"];
const DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DOCUMENTS_FILES: [&str; 3] = [
    "finance/q1-budget.csv",
    "reference/ops/runbook.txt",
    "report.md",
];
const DOCUMENTS_SUMMARY_CASE_ID: &str =
    "summarize_the_contents_of_the_most_recent_document_in_my_documents_folder";
const DOCUMENTS_SUMMARY_FIXTURE_MODE: &str = "documents_latest_summary_fixture_v1";
const DOCUMENTS_SUMMARY_FIXTURE_PROBE_SOURCE: &str = "harness.documents_latest_summary_fixture";
const DOCUMENTS_SUMMARY_FIXTURE_DIR_PREFIX: &str = "ioi_recent_document_";
const DOCUMENTS_SUMMARY_EXPECTED_FILE_NAMES: [&str; 3] = [
    "project_brief.txt",
    "meeting_notes.txt",
    "incident_update_latest.txt",
];
const DOCUMENTS_SUMMARY_EXPECTED_LATEST_MARKERS: [&str; 3] = [
    "root cause: expired api token on ingestion worker",
    "mitigation: rotated the token and restarted the worker",
    "next step: add a 30-day token expiry alert",
];
const PDF_LAST_WEEK_CASE_ID: &str = "find_all_pdf_files_on_my_computer_modified_in_the_last_week";
const PDF_LAST_WEEK_FIXTURE_MODE: &str = "pdf_last_week_fixture_v1";
const PDF_LAST_WEEK_FIXTURE_PROBE_SOURCE: &str = "harness.pdf_last_week_fixture";
const PDF_LAST_WEEK_FIXTURE_DIR_PREFIX: &str = "ioi_pdf_last_week_";
const PDF_LAST_WEEK_EXPECTED_PDF_FILES: [&str; 2] = ["weekly_status.pdf", "incident_report.pdf"];
const PDF_LAST_WEEK_SUPPORTING_FILE: &str = "notes.txt";
const SPOTIFY_UNINSTALL_CASE_ID: &str = "uninstall_spotify_and_remove_its_leftover_config_files";
const SPOTIFY_UNINSTALL_FIXTURE_MODE: &str = "spotify_uninstall_fixture_v1";
const SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE: &str = "harness.spotify_uninstall_fixture";
const SPOTIFY_UNINSTALL_PROVIDER_IDS: [&str; 5] = ["apt-get", "snap", "flatpak", "brew", "pacman"];
const SPOTIFY_UNINSTALL_CONFIG_RELATIVE_PATHS: [&str; 3] =
    [".config/spotify", ".cache/spotify", ".local/share/spotify"];
const SPOTIFY_UNINSTALL_SENTINEL_FILE_NAME: &str = "ioi_fixture_keep_sentinel.txt";
const TOP_MEMORY_APPS_CASE_ID: &str =
    "check_which_apps_are_using_the_most_memory_right_now_and_list_them";
const TOP_MEMORY_APPS_FIXTURE_MODE: &str = "top_memory_apps_fixture_v1";
const TOP_MEMORY_APPS_FIXTURE_PROBE_SOURCE: &str = "harness.top_memory_apps_fixture";
const TOP_MEMORY_APPS_PROBE_SCRIPT_NAME: &str = "top_memory_apps_probe";
const MEDIA_TRANSCRIPT_SUMMARY_CASE_ID: &str =
    "summarize_the_key_points_from_this_45_minute_youtube_video";
const MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_MODE: &str = "media_multimodal_tool_home_fixture_v1";
const MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_PROBE_SOURCE: &str =
    "harness.media_multimodal_summary_fixture";
const MEDIA_TRANSCRIPT_SUMMARY_TOOL_HOME_ENV_KEY: &str = "IOI_MEDIA_TOOL_HOME";
const MEDIA_TRANSCRIPT_SUMMARY_EXPECTED_URL: &str = "https://www.youtube.com/watch?v=9Tm2c6NJH4Y";
const SHUTDOWN_SCHEDULE_CASE_ID: &str = "schedule_my_computer_to_shut_down_at_11_pm_tonight";
const SHUTDOWN_SCHEDULE_FIXTURE_MODE: &str = "shutdown_schedule_fixture_v1";
const SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE: &str = "harness.shutdown_schedule_fixture";
const SHUTDOWN_SCHEDULE_PROBE_SCRIPT_NAME: &str = "shutdown_schedule_probe";
const SHUTDOWN_SCHEDULE_PROVIDER_IDS: [&str; 3] = ["shutdown", "systemctl", "at"];
const SHUTDOWN_SCHEDULE_TARGET_LOCAL_TIME: &str = "23:00";
const HACKER_NEWS_MONITOR_CASE_ID: &str =
    "monitor_hacker_news_and_notify_me_whenever_a_post_about_web4_or_post_quantum_cryptography_hits_the_front_page";
const HACKER_NEWS_MONITOR_FIXTURE_MODE: &str = "hacker_news_front_page_monitor_fixture_v1";
const HACKER_NEWS_MONITOR_FIXTURE_PROBE_SOURCE: &str =
    "harness.hacker_news_front_page_monitor_fixture";
const HACKER_NEWS_MONITOR_FIXTURE_MANIFEST_NAME: &str =
    "hacker_news_front_page_monitor_fixture_manifest.txt";
const RESTAURANTS_NEAR_ME_CASE_ID: &str =
    "find_the_three_best_reviewed_italian_restaurants_near_me_and_compare_their_menus";
const RESTAURANTS_NEAR_ME_FIXTURE_MODE: &str = "runtime_locality_observation_fixture_v2";
const RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE: &str = "harness.restaurants_near_me_fixture";
const RESTAURANTS_NEAR_ME_FIXTURE_DIR_PREFIX: &str = "ioi_restaurants_near_me_";
const RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY: &str = "IOI_SESSION_LOCALITY";
const GOOGLE_AUTH_ENV_KEY: &str = "IOI_GOOGLE_AUTH_PATH";
const GOOGLE_CLIENT_CONFIG_ENV_KEY: &str = "IOI_GOOGLE_CLIENT_CONFIG_PATH";
const GOOGLE_OAUTH_CLIENT_ID_ENV_KEYS: [&str; 2] =
    ["GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_WORKSPACE_OAUTH_CLIENT_ID"];
const GOOGLE_AUTH_FILE_NAME: &str = "google_workspace_oauth.json";
const GOOGLE_CLIENT_FILE_NAME: &str = "google_workspace_client.json";
const LATEST_NIST_PQC_BRIEFING_CASE_ID: &str =
    "research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing";
const LATEST_NIST_PQC_BRIEFING_UNSEEDED_CASE_ID: &str =
    "research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing_unseeded";
const LATEST_NIST_PQC_BRIEFING_FIXTURE_MODE: &str = "latest_nist_pqc_briefing_fixture_v1";
const LATEST_NIST_PQC_BRIEFING_FIXTURE_PROBE_SOURCE: &str =
    "harness.latest_nist_pqc_briefing_fixture";
const LATEST_NIST_PQC_BRIEFING_FIXTURE_DIR_PREFIX: &str = "ioi_latest_nist_pqc_briefing_";
const CODING_PATH_NORMALIZER_CASE_ID: &str =
    "fix_the_fixture_repo_path_normalizer_and_verify_the_targeted_tests";
const CODING_PATH_NORMALIZER_FIXTURE_MODE: &str = "coding_path_normalizer_fixture_v1";
const CODING_PATH_NORMALIZER_FIXTURE_PROBE_SOURCE: &str = "harness.coding_path_normalizer_fixture";

include!("harness/mail_runtime.rs");

include!("harness/project_fixtures.rs");

fn normalized_seeded_intent_id(case: &QueryCase) -> String {
    case.seeded_intent_id.trim().to_ascii_lowercase()
}

fn case_requires_wallet_mail_runtime(case: &QueryCase) -> bool {
    matches!(
        normalized_seeded_intent_id(case).as_str(),
        "mail.read.latest" | "mail.reply" | "mail.list.recent" | "mail.delete.spam"
    )
}

fn case_requires_google_workspace_runtime(case: &QueryCase) -> bool {
    matches!(
        normalized_seeded_intent_id(case).as_str(),
        "gmail.draft_email"
            | "google.gmail.draft_email"
            | "gmail.send_email"
            | "google.gmail.send_email"
            | "calendar.create_event"
            | "google.calendar.create_event"
    )
}

fn google_auth_storage_path_candidate() -> Option<PathBuf> {
    if let Some(path) = nonempty_env_value(GOOGLE_AUTH_ENV_KEY) {
        return Some(PathBuf::from(path));
    }
    if let Some(base) = nonempty_env_value("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(base).join("ioi").join(GOOGLE_AUTH_FILE_NAME));
    }
    if let Some(base) = nonempty_env_value("APPDATA") {
        return Some(PathBuf::from(base).join("ioi").join(GOOGLE_AUTH_FILE_NAME));
    }
    nonempty_env_value("HOME")
        .map(PathBuf::from)
        .map(|base| base.join(".config").join("ioi").join(GOOGLE_AUTH_FILE_NAME))
}

fn google_client_storage_path_candidate(auth_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = nonempty_env_value(GOOGLE_CLIENT_CONFIG_ENV_KEY) {
        return Some(PathBuf::from(path));
    }
    auth_path
        .and_then(Path::parent)
        .map(PathBuf::from)
        .map(|base| base.join(GOOGLE_CLIENT_FILE_NAME))
}

fn json_file_is_present_and_parseable(path: &Path) -> bool {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .is_some()
}

fn google_workspace_runtime_configured() -> bool {
    let auth_path = google_auth_storage_path_candidate();
    let auth_ready = auth_path
        .as_deref()
        .map(json_file_is_present_and_parseable)
        .unwrap_or(false);
    if !auth_ready {
        return false;
    }
    if GOOGLE_OAUTH_CLIENT_ID_ENV_KEYS
        .iter()
        .any(|key| nonempty_env_value(key).is_some())
    {
        return true;
    }
    google_client_storage_path_candidate(auth_path.as_deref())
        .as_deref()
        .map(json_file_is_present_and_parseable)
        .unwrap_or(false)
}

pub(crate) fn case_missing_runtime_prerequisites(case: &QueryCase) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if case_requires_wallet_mail_runtime(case) && !mail_runtime_env_bootstrap_configured() {
        missing.push("MAIL_E2E_*");
    }
    if case_requires_google_workspace_runtime(case) && !google_workspace_runtime_configured() {
        missing.push("Google Workspace auth");
    }
    missing
}

#[derive(Debug, Clone, Default)]
struct ShutdownProviderInvocationReceipt {
    provider: String,
    provider_invoked: bool,
    provider_args: String,
}

include!("harness/case_runner.rs");

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

fn active_policy_hash_for_session(
    state: &IAVLTree<HashCommitmentScheme>,
    session_id: [u8; 32],
) -> Result<[u8; 32]> {
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    let rules = match state.get(&policy_key)? {
        Some(bytes) => {
            codec::from_bytes_canonical::<ioi_services::agentic::rules::ActionRules>(&bytes)
                .map_err(anyhow::Error::msg)?
        }
        None => default_safe_policy(),
    };
    let canonical = serde_jcs::to_vec(&rules).map_err(anyhow::Error::msg)?;
    let digest = sha256(&canonical).map_err(anyhow::Error::msg)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn build_approval_grant_for_resume(
    session_id: [u8; 32],
    request_hash: [u8; 32],
    policy_hash: [u8; 32],
    now_ms: u64,
    _pending_visual_hash: Option<[u8; 32]>,
    pii_action: Option<PiiApprovalAction>,
) -> Result<(ApprovalAuthority, ApprovalGrant)> {
    let keypair =
        Ed25519KeyPair::generate().map_err(|e| anyhow!("approval keygen failed: {}", e))?;
    let public_key = keypair.public_key().to_bytes();
    let authority_id = account_id_from_key_material(SignatureSuite::ED25519, &public_key)
        .map_err(anyhow::Error::msg)?;
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&request_hash);
    let authority = ApprovalAuthority {
        schema_version: 1,
        authority_id,
        public_key: public_key.clone(),
        signature_suite: SignatureSuite::ED25519,
        expires_at: now_ms.saturating_add(120_000),
        revoked: false,
        scope_allowlist: vec!["desktop_agent.resume".to_string()],
    };
    let mut grant = ApprovalGrant {
        schema_version: 1,
        authority_id,
        request_hash,
        policy_hash,
        audience: session_id,
        nonce,
        counter: 1,
        expires_at: now_ms.saturating_add(120_000),
        max_usages: Some(1),
        window_id: None,
        pii_action,
        scoped_exception: None,
        review_request_hash: None,
        approver_public_key: public_key,
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    };
    let signing_bytes = grant.signing_bytes().map_err(anyhow::Error::msg)?;
    grant.approver_sig = keypair
        .sign(&signing_bytes)
        .map_err(|e| anyhow!("approval signing failed: {}", e))?
        .to_bytes()
        .to_vec();
    Ok((authority, grant))
}

fn parse_hex_hash_32(raw: &str) -> Option<[u8; 32]> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(stripped).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

#[derive(Debug, Deserialize)]
struct CommandHistoryPayload {
    command: String,
    exit_code: i32,
    stdout: String,
    stderr: String,
}

#[derive(Default)]
struct ExecWorkloadEvidence {
    stdout: BTreeMap<u64, String>,
    stderr: BTreeMap<u64, String>,
    exit_code: Option<i32>,
}

impl ExecWorkloadEvidence {
    fn append_chunk(&mut self, stream: &str, seq: u64, chunk: &str, exit_code: Option<i32>) {
        if let Some(code) = exit_code {
            self.exit_code = Some(code);
        }
        match stream {
            "stdout" => {
                self.stdout.insert(seq, chunk.to_string());
            }
            "stderr" => {
                self.stderr.insert(seq, chunk.to_string());
            }
            "status" => {}
            _ => {}
        }
    }

    fn set_exit_code(&mut self, exit_code: Option<i32>) {
        if let Some(code) = exit_code {
            self.exit_code = Some(code);
        }
    }

    fn stdout_text(&self) -> String {
        self.stdout.values().cloned().collect::<Vec<_>>().join("")
    }

    fn stderr_text(&self) -> String {
        self.stderr.values().cloned().collect::<Vec<_>>().join("")
    }
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

fn typed_receipt_state(observation: &RunObservation, stage: &str, key: &str) -> Option<bool> {
    observation
        .cec_receipts
        .iter()
        .rev()
        .find(|receipt| {
            receipt.stage.eq_ignore_ascii_case(stage) && receipt.key.eq_ignore_ascii_case(key)
        })
        .map(|receipt| receipt.satisfied)
}

fn collect_unique_urls(values: Vec<String>) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
            continue;
        }
        let key = trimmed.to_ascii_lowercase();
        if seen.insert(key) {
            urls.push(trimmed.to_string());
        }
    }
    urls
}

fn collect_unique_names(values: Vec<String>) -> Vec<String> {
    let mut names = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let key = trimmed.to_ascii_lowercase();
        if seen.insert(key) {
            names.push(trimmed.to_string());
        }
    }
    names
}

#[derive(Debug, Deserialize)]
struct ProviderCandidateReceiptPayload {
    provider_id: String,
    #[serde(default)]
    modality: Option<String>,
    source_count: u32,
    selected: bool,
    success: bool,
    #[serde(default)]
    execution_attempted: Option<bool>,
    #[serde(default)]
    execution_satisfied: Option<bool>,
    #[serde(default)]
    execution_failure_reason: Option<String>,
    request_url: Option<String>,
    challenge_reason: Option<String>,
    #[serde(default)]
    affordances: Vec<ioi_types::app::agentic::WebRetrievalAffordance>,
}

fn derive_provider_candidates(
    observation: &RunObservation,
) -> Vec<super::types::WebProviderCandidateObservation> {
    observation
        .cec_receipts
        .iter()
        .filter(|receipt| {
            receipt.stage.eq_ignore_ascii_case("discovery")
                && receipt.key.eq_ignore_ascii_case("provider_candidate")
        })
        .filter_map(|receipt| receipt.observed_value.as_deref())
        .filter_map(|payload| serde_json::from_str::<ProviderCandidateReceiptPayload>(payload).ok())
        .map(|payload| super::types::WebProviderCandidateObservation {
            provider_id: payload.provider_id,
            modality: payload.modality,
            source_count: payload.source_count as usize,
            selected: payload.selected,
            success: payload.success,
            execution_attempted: payload.execution_attempted,
            execution_satisfied: payload.execution_satisfied,
            execution_failure_reason: payload.execution_failure_reason,
            request_url: payload.request_url,
            challenge_reason: payload.challenge_reason,
            affordances: payload.affordances,
        })
        .collect()
}

#[derive(Default)]
struct EnvironmentReceiptAccumulator {
    observed_values: Vec<String>,
    probe_source: Option<String>,
    timestamp_ms: Option<u64>,
    satisfied: Option<bool>,
}

#[derive(Default)]
struct EnvironmentEvidenceBatch {
    checks: Vec<String>,
    evidence: Vec<EnvironmentReceiptObservation>,
}

trait IntoEnvironmentEvidenceBatch {
    fn into_environment_evidence_batch(self) -> EnvironmentEvidenceBatch;
}

impl IntoEnvironmentEvidenceBatch for EnvironmentEvidenceBatch {
    fn into_environment_evidence_batch(self) -> EnvironmentEvidenceBatch {
        self
    }
}

impl IntoEnvironmentEvidenceBatch for Vec<String> {
    fn into_environment_evidence_batch(self) -> EnvironmentEvidenceBatch {
        let evidence = derive_environment_receipts(&self);
        EnvironmentEvidenceBatch {
            checks: self,
            evidence,
        }
    }
}

fn environment_evidence_batch_from_checks<T>(checks: T) -> EnvironmentEvidenceBatch
where
    T: IntoEnvironmentEvidenceBatch,
{
    checks.into_environment_evidence_batch()
}

fn planned_tool_call_from_step(
    trace: &ioi_types::app::agentic::StepTrace,
) -> Option<PlannedToolCallEvidence> {
    let payload = serde_json::from_str::<serde_json::Value>(&trace.raw_output).ok()?;
    let tool_name = payload.get("name")?.as_str()?.trim();
    if tool_name.is_empty() {
        return None;
    }

    Some(PlannedToolCallEvidence {
        step_index: trace.step_index,
        tool_name: tool_name.to_string(),
        arguments: payload
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    })
}

fn derive_web_observation(observation: &RunObservation) -> Option<WebObservation> {
    let retrieval_contract = cec_receipt_value(observation, "execution", "retrieval_contract")
        .and_then(|value| serde_json::from_str(&value).ok());
    let query_contract = cec_receipt_value(observation, "execution", "query_contract");
    let query_value = cec_receipt_value(observation, "execution", "query_value");
    let currentness_required = cec_receipt_bool(observation, "execution", "currentness_required");
    let runtime_locality_required =
        cec_receipt_bool(observation, "discovery", "runtime_locality_required");
    let runtime_locality_scope =
        cec_receipt_value(observation, "discovery", "runtime_locality_scope").filter(|value| {
            let trimmed = value.trim();
            !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("<unset>")
        });
    let runtime_locality_alignment = typed_receipt_state(
        observation,
        "discovery",
        "query_contract_locality_alignment",
    );
    let semantic_subject_alignment_required = cec_receipt_bool(
        observation,
        "discovery",
        "semantic_subject_alignment_required",
    );
    let semantic_subject_alignment_floor_met =
        typed_receipt_state(observation, "discovery", "semantic_subject_alignment_floor");
    let semantic_subject_alignment_urls = collect_unique_urls(
        cec_receipt_latest_values(observation, "discovery", "semantic_subject_alignment_url")
            .into_iter()
            .chain(cec_receipt_latest_values(
                observation,
                "discovery",
                "semantic_subject_alignment_selection_url",
            ))
            .collect(),
    );
    let min_sources = cec_receipt_usize(observation, "execution", "min_sources_required");
    let sources_success = cec_receipt_usize(observation, "verification", "sources_success");
    let source_floor_met = typed_receipt_state(observation, "verification", "source_floor");
    let selected_source_quality_floor_met =
        typed_receipt_state(observation, "verification", "selected_source_quality_floor");
    let selected_source_subject_alignment_floor_met = typed_receipt_state(
        observation,
        "verification",
        "selected_source_subject_alignment_floor",
    );
    let selected_source_urls = collect_unique_urls(cec_receipt_latest_values(
        observation,
        "verification",
        "selected_source_url",
    ));
    let selected_source_subject_alignment_urls = collect_unique_urls(cec_receipt_latest_values(
        observation,
        "verification",
        "selected_source_subject_alignment_url",
    ));
    let selected_source_count =
        cec_receipt_usize(observation, "verification", "selected_source_total");
    let selected_source_distinct_domains = cec_receipt_usize(
        observation,
        "verification",
        "selected_source_distinct_domains",
    );
    let local_business_entity_floor_met =
        typed_receipt_state(observation, "verification", "local_business_entity_floor");
    let local_business_entity_anchor_floor_met = typed_receipt_state(
        observation,
        "verification",
        "local_business_entity_anchor_floor",
    );
    let local_business_entity_names = collect_unique_names(cec_receipt_latest_values(
        observation,
        "verification",
        "local_business_entity_name",
    ));
    let local_business_entity_source_urls = collect_unique_urls(cec_receipt_latest_values(
        observation,
        "verification",
        "local_business_entity_source_url",
    ));
    let local_business_entity_anchor_source_urls = collect_unique_urls(cec_receipt_latest_values(
        observation,
        "verification",
        "local_business_entity_anchor_source_url",
    ));
    let local_business_entity_anchor_mismatched_urls =
        collect_unique_urls(cec_receipt_latest_values(
            observation,
            "verification",
            "local_business_entity_anchor_mismatched_url",
        ));
    let local_business_menu_inventory_floor_met = typed_receipt_state(
        observation,
        "verification",
        "local_business_menu_inventory_floor",
    );
    let local_business_menu_inventory_total_item_count = cec_receipt_usize(
        observation,
        "verification",
        "local_business_menu_inventory_total_item_count",
    );
    let local_business_menu_inventory_source_urls = collect_unique_urls(cec_receipt_latest_values(
        observation,
        "verification",
        "local_business_menu_inventory_source_url",
    ));
    let story_slots_observed =
        cec_receipt_usize(observation, "verification", "story_slots_observed");
    let story_slot_floor_met = typed_receipt_state(observation, "verification", "story_slot_floor");
    let story_citation_floor_met =
        typed_receipt_state(observation, "verification", "story_citation_floor");
    let comparison_ready = typed_receipt_state(observation, "verification", "comparison_ready");
    let single_snapshot_metric_grounding = typed_receipt_state(
        observation,
        "verification",
        "single_snapshot_metric_grounding",
    );
    let provider_candidates = derive_provider_candidates(observation);

    let evidence_present = query_contract
        .as_ref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
        || retrieval_contract.is_some()
        || currentness_required.is_some()
        || runtime_locality_required.is_some()
        || semantic_subject_alignment_required.is_some()
        || min_sources.is_some()
        || sources_success.is_some()
        || !selected_source_urls.is_empty()
        || !semantic_subject_alignment_urls.is_empty()
        || !provider_candidates.is_empty()
        || !local_business_entity_names.is_empty()
        || !local_business_entity_anchor_source_urls.is_empty()
        || !local_business_entity_anchor_mismatched_urls.is_empty()
        || local_business_menu_inventory_floor_met.is_some()
        || story_slots_observed.is_some()
        || observation_has_any_tool_name(observation, &["web__search", "web__read"]);
    if !evidence_present {
        return None;
    }

    Some(WebObservation {
        retrieval_contract,
        query_contract,
        query_value,
        currentness_required,
        runtime_locality_required,
        runtime_locality_scope,
        runtime_locality_alignment,
        semantic_subject_alignment_required,
        semantic_subject_alignment_floor_met,
        semantic_subject_alignment_urls,
        min_sources,
        sources_success,
        source_floor_met,
        selected_source_quality_floor_met,
        selected_source_subject_alignment_floor_met,
        selected_source_count,
        selected_source_distinct_domains,
        selected_source_urls,
        selected_source_subject_alignment_urls,
        local_business_entity_floor_met,
        local_business_entity_anchor_floor_met,
        local_business_entity_names,
        local_business_entity_source_urls,
        local_business_entity_anchor_source_urls,
        local_business_entity_anchor_mismatched_urls,
        local_business_menu_inventory_floor_met,
        local_business_menu_inventory_total_item_count,
        local_business_menu_inventory_source_urls,
        story_slots_observed,
        story_slot_floor_met,
        story_citation_floor_met,
        comparison_ready,
        single_snapshot_metric_grounding,
        provider_candidates,
    })
}

fn derive_screenshot_observation(observation: &RunObservation) -> Option<ScreenshotObservation> {
    let capture_action_count = observation
        .action_evidence
        .iter()
        .filter(|entry| {
            entry.tool_name.eq_ignore_ascii_case("screen")
                && entry.agent_status.eq_ignore_ascii_case("completed")
        })
        .count();
    let capture_failure_count = observation
        .action_evidence
        .iter()
        .filter(|entry| {
            entry.tool_name.eq_ignore_ascii_case("screen")
                && (entry.agent_status.eq_ignore_ascii_case("failed")
                    || entry
                        .error_class
                        .as_deref()
                        .map(|value| !value.trim().eq_ignore_ascii_case("NoEffectAfterAction"))
                        .unwrap_or(false))
        })
        .count();
    let gui_snapshot_action_count = observation
        .action_evidence
        .iter()
        .filter(|entry| entry.tool_name.eq_ignore_ascii_case("screen__inspect"))
        .count();
    let gui_snapshot_routing_count = observation
        .routing_tools
        .iter()
        .filter(|tool| tool.eq_ignore_ascii_case("screen__inspect"))
        .count();
    let capture_route_seen = observation_has_tool_name(observation, "screen");
    let capture_route_terminalized =
        has_verification_pair(observation, "screenshot_capture_terminalized", "true");
    let incident_resolved = has_verification_pair(observation, "incident_resolved", "true");
    let approval_gate_seen = observation.approval_required_events > 0
        || has_policy_decision(observation, "require_approval");
    let approval_transition_seen = approval_gate_seen
        && (has_policy_decision(observation, "approved")
            || has_policy_decision(observation, "allowed"));
    let no_gui_snapshot_fallback =
        gui_snapshot_action_count == 0 && gui_snapshot_routing_count == 0;

    let evidence_present = capture_action_count > 0
        || capture_failure_count > 0
        || capture_route_seen
        || approval_gate_seen
        || capture_route_terminalized
        || incident_resolved;
    if !evidence_present {
        return None;
    }

    Some(ScreenshotObservation {
        capture_action_count,
        capture_failure_count,
        gui_snapshot_action_count,
        gui_snapshot_routing_count,
        capture_route_seen,
        capture_route_terminalized,
        incident_resolved,
        approval_gate_seen,
        approval_transition_seen,
        no_gui_snapshot_fallback,
    })
}

fn is_no_effect_after_action_error(error_class: Option<&str>) -> bool {
    error_class
        .map(|value| value.trim().eq_ignore_ascii_case("NoEffectAfterAction"))
        .unwrap_or(false)
}

fn is_mail_read_latest_tool_name(tool_name: &str) -> bool {
    tool_name.eq_ignore_ascii_case("wallet_network__mail_read_latest")
        || tool_name.eq_ignore_ascii_case("wallet_mail_read_latest")
        || tool_name.eq_ignore_ascii_case("mail__read_latest")
}

fn is_mail_reply_tool_name(tool_name: &str) -> bool {
    tool_name.eq_ignore_ascii_case("wallet_network__mail_reply")
        || tool_name.eq_ignore_ascii_case("wallet_mail_reply")
        || tool_name.eq_ignore_ascii_case("mail__reply")
}

fn is_google_gmail_draft_tool_name(tool_name: &str) -> bool {
    tool_name.eq_ignore_ascii_case("connector__google__gmail_draft_email")
}

fn is_google_gmail_send_tool_name(tool_name: &str) -> bool {
    tool_name.eq_ignore_ascii_case("connector__google__gmail_send_email")
}

fn is_google_calendar_create_tool_name(tool_name: &str) -> bool {
    tool_name.eq_ignore_ascii_case("connector__google__calendar_create_event")
}

fn json_string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
}

fn json_u64_field(value: &serde_json::Value, key: &str) -> Option<u64> {
    value.get(key).and_then(serde_json::Value::as_u64)
}

fn json_string_array_field(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(ToString::to_string)
        .collect()
}

fn extract_first_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let mut brace_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in raw[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if ch == '{' {
            brace_depth = brace_depth.saturating_add(1);
            continue;
        }
        if ch == '}' {
            brace_depth = brace_depth.saturating_sub(1);
            if brace_depth == 0 {
                let end = start + idx + 1;
                return Some(raw[start..end].to_string());
            }
        }
    }
    None
}

fn parse_google_connector_payload(output: &str) -> Option<serde_json::Value> {
    extract_first_json_object(output)
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
}

fn parse_mail_read_latest_payload(output: &str) -> Option<MailReadLatestPayloadObservation> {
    let value = serde_json::from_str::<serde_json::Value>(output).ok()?;
    if json_string_field(&value, "operation")?.trim() != "mail_read_latest@v1" {
        return None;
    }
    let message = value.get("message")?;

    Some(MailReadLatestPayloadObservation {
        operation: json_string_field(&value, "operation"),
        mailbox: json_string_field(&value, "mailbox"),
        citation: json_string_field(&value, "citation"),
        message_id: json_string_field(message, "message_id"),
        from: json_string_field(message, "from"),
        subject: json_string_field(message, "subject"),
        preview: json_string_field(message, "preview"),
        received_at_ms: json_u64_field(message, "received_at_ms"),
        received_at_utc: json_string_field(message, "received_at_utc"),
    })
}

fn parse_mail_reply_payload(output: &str) -> Option<MailReplyPayloadObservation> {
    let value = serde_json::from_str::<serde_json::Value>(output).ok()?;
    if json_string_field(&value, "operation")?.trim() != "mail_reply@v1" {
        return None;
    }

    Some(MailReplyPayloadObservation {
        operation: json_string_field(&value, "operation"),
        mailbox: json_string_field(&value, "mailbox"),
        to: json_string_field(&value, "to"),
        subject: json_string_field(&value, "subject"),
        body: json_string_field(&value, "body"),
        sent_message_id: json_string_field(&value, "sent_message_id"),
        citation: json_string_field(&value, "citation"),
    })
}

fn parse_google_gmail_draft_payload(output: &str) -> Option<GoogleGmailPayloadObservation> {
    let value = parse_google_connector_payload(output)?;
    let message = value.get("message")?;
    let message_id = json_string_field(message, "id")?;

    Some(GoogleGmailPayloadObservation {
        action_id: Some("gmail.draft_email".to_string()),
        message_id: Some(message_id),
        thread_id: json_string_field(message, "threadId"),
        to: json_string_field(message, "to"),
        subject: json_string_field(message, "subject"),
        body_text: json_string_field(message, "bodyText"),
        label_ids: json_string_array_field(message, "labelIds"),
    })
}

fn parse_google_gmail_send_payload(output: &str) -> Option<GoogleGmailPayloadObservation> {
    let value = parse_google_connector_payload(output)?;
    let message_id = json_string_field(&value, "id")?;

    Some(GoogleGmailPayloadObservation {
        action_id: Some("gmail.send_email".to_string()),
        message_id: Some(message_id),
        thread_id: json_string_field(&value, "threadId"),
        to: json_string_field(&value, "to"),
        subject: json_string_field(&value, "subject"),
        body_text: json_string_field(&value, "bodyText"),
        label_ids: json_string_array_field(&value, "labelIds"),
    })
}

fn parse_google_calendar_create_payload(output: &str) -> Option<GoogleCalendarPayloadObservation> {
    let value = parse_google_connector_payload(output)?;
    let event_id = json_string_field(&value, "id")?;

    Some(GoogleCalendarPayloadObservation {
        action_id: Some("calendar.create_event".to_string()),
        event_id: Some(event_id),
        calendar_id: json_string_field(&value, "calendarId"),
        summary: json_string_field(&value, "summary"),
        start: value
            .get("start")
            .and_then(|start| json_string_field(start, "dateTime")),
        end: value
            .get("end")
            .and_then(|end| json_string_field(end, "dateTime")),
        html_link: json_string_field(&value, "htmlLink"),
        attendee_emails: value
            .get("attendees")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| json_string_field(entry, "email"))
            .collect(),
    })
}

fn derive_mail_observation(
    observation: &RunObservation,
    read_latest_success_count: usize,
    read_latest_failure_count: usize,
    reply_success_count: usize,
    reply_failure_count: usize,
    read_latest_payloads: Vec<MailReadLatestPayloadObservation>,
    reply_payloads: Vec<MailReplyPayloadObservation>,
) -> Option<MailObservation> {
    let connector_path_required =
        has_verification_pair(observation, "mailbox_connector_path_required", "true");
    let non_connector_tool_blocked =
        has_verification_pair(observation, "mailbox_non_connector_tool_blocked", "true");
    let invalid_tool_call_fail_fast =
        has_verification_pair(observation, "mailbox_invalid_tool_call_fail_fast", "true");
    let system_fail_degraded_to_reply =
        has_verification_pair(observation, "mailbox_system_fail_degraded_to_reply", "true");
    let fallback_marker_present = connector_path_required
        || non_connector_tool_blocked
        || invalid_tool_call_fail_fast
        || system_fail_degraded_to_reply;

    let evidence_present = read_latest_success_count > 0
        || read_latest_failure_count > 0
        || reply_success_count > 0
        || reply_failure_count > 0
        || !read_latest_payloads.is_empty()
        || !reply_payloads.is_empty()
        || fallback_marker_present
        || observation_has_any_tool_name(
            observation,
            &[
                "wallet_network__mail_read_latest",
                "wallet_mail_read_latest",
                "mail__read_latest",
                "wallet_network__mail_reply",
                "wallet_mail_reply",
                "mail__reply",
            ],
        );
    if !evidence_present {
        return None;
    }

    Some(MailObservation {
        read_latest_success_count,
        read_latest_failure_count,
        reply_success_count,
        reply_failure_count,
        read_latest_payloads,
        reply_payloads,
        connector_path_required,
        non_connector_tool_blocked,
        invalid_tool_call_fail_fast,
        system_fail_degraded_to_reply,
        fallback_marker_present,
    })
}

fn derive_google_observation(
    observation: &RunObservation,
    gmail_draft_success_count: usize,
    gmail_draft_failure_count: usize,
    gmail_send_success_count: usize,
    gmail_send_failure_count: usize,
    calendar_create_success_count: usize,
    calendar_create_failure_count: usize,
    gmail_draft_payloads: Vec<GoogleGmailPayloadObservation>,
    gmail_send_payloads: Vec<GoogleGmailPayloadObservation>,
    calendar_create_payloads: Vec<GoogleCalendarPayloadObservation>,
) -> Option<GoogleObservation> {
    let evidence_present = gmail_draft_success_count > 0
        || gmail_draft_failure_count > 0
        || gmail_send_success_count > 0
        || gmail_send_failure_count > 0
        || calendar_create_success_count > 0
        || calendar_create_failure_count > 0
        || !gmail_draft_payloads.is_empty()
        || !gmail_send_payloads.is_empty()
        || !calendar_create_payloads.is_empty()
        || observation_has_any_tool_name(
            observation,
            &[
                "connector__google__gmail_draft_email",
                "connector__google__gmail_send_email",
                "connector__google__calendar_create_event",
            ],
        );
    if !evidence_present {
        return None;
    }

    Some(GoogleObservation {
        gmail_draft_success_count,
        gmail_draft_failure_count,
        gmail_send_success_count,
        gmail_send_failure_count,
        calendar_create_success_count,
        calendar_create_failure_count,
        gmail_draft_payloads,
        gmail_send_payloads,
        calendar_create_payloads,
    })
}

fn run_unique_num(run_index: usize, run_timestamp_ms: u64) -> String {
    format!("{}{:03}", run_timestamp_ms, run_index)
}

fn render_query_for_run(query_template: &str, run_index: usize, run_timestamp_ms: u64) -> String {
    let run_unique_num = run_unique_num(run_index, run_timestamp_ms);
    query_template
        .replace("{RUN_UNIQUE_NUM}", &run_unique_num)
        .replace("{RUN_INDEX}", &run_index.to_string())
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

fn desktop_project_create_fixture_preflight_checks(
    fixture: &DesktopProjectCreateFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let expected_absent = !fixture.expected_project_dir.exists();
    let desktop_ready = fixture.desktop_dir.is_dir();
    let run_unique_satisfied = fixture
        .expected_project_dir
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case(&format!("Project_{}", run_unique_num)))
        .unwrap_or(false);
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "desktop_project_fixture_mode",
        DESKTOP_PROJECT_CREATE_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "desktop_project_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "desktop_project_desktop_dir",
        fixture.desktop_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "desktop_project_expected_path",
        fixture.expected_project_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "desktop_project_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_project_expected_absent",
        Some(DESKTOP_PROJECT_CREATE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(expected_absent && desktop_ready && run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_project_fixture",
        Some(DESKTOP_PROJECT_CREATE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(desktop_ready),
    );
    batch
}

include!("harness/post_run_checks.rs");

fn desktop_project_create_fixture_cleanup_checks(
    fixture: &DesktopProjectCreateFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!(
        "{}.cleanup_probe",
        DESKTOP_PROJECT_CREATE_FIXTURE_PROBE_SOURCE
    );
    let _ = std::fs::remove_dir_all(&fixture.expected_project_dir);
    let remaining_entries = list_directory_entry_names(&fixture.desktop_dir);
    let cleanup_satisfied = !fixture.expected_project_dir.exists() && remaining_entries.is_empty();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "desktop_project_cleanup_desktop_entries",
        remaining_entries.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_project_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn zip_archive_entries(path: &Path) -> Result<Vec<String>> {
    let file = std::fs::File::open(path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut entries = Vec::new();
    for idx in 0..archive.len() {
        let entry = archive.by_index(idx)?;
        entries.push(entry.name().to_string());
    }
    entries.sort();
    Ok(entries)
}

fn list_directory_entry_names(path: &Path) -> Vec<String> {
    let mut entries = std::fs::read_dir(path)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

fn list_relative_file_paths(path: &Path) -> Vec<String> {
    fn collect(root: &Path, cursor: &Path, output: &mut Vec<String>) {
        let mut entries = std::fs::read_dir(cursor)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.file_name().cmp(&right.file_name()));

        for entry in entries {
            let entry_path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                collect(root, &entry_path, output);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let Ok(relative) = entry_path.strip_prefix(root) else {
                continue;
            };
            output.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }

    if !path.is_dir() {
        return Vec::new();
    }

    let mut files = Vec::new();
    collect(path, path, &mut files);
    files.sort();
    files
}

fn file_sets_content_match(
    source_root: &Path,
    destination_root: &Path,
    relative_files: &[String],
) -> bool {
    relative_files.iter().all(|relative| {
        let source = source_root.join(relative);
        let destination = destination_root.join(relative);
        let source_bytes = std::fs::read(source).ok();
        let destination_bytes = std::fs::read(destination).ok();
        match (source_bytes, destination_bytes) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        }
    })
}

fn file_modified_epoch_ms(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
}

fn latest_file_path_and_mtime(path: &Path) -> Option<(PathBuf, u64)> {
    let mut candidates = std::fs::read_dir(path)
        .ok()?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let entry_path = entry.path();
            let metadata = entry.metadata().ok()?;
            if !metadata.is_file() {
                return None;
            }
            let mtime_ms = metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_millis() as u64)?;
            Some((entry_path, mtime_ms))
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|left, right| {
        left.1
            .cmp(&right.1)
            .then_with(|| left.0.to_string_lossy().cmp(&right.0.to_string_lossy()))
    });
    candidates.pop()
}

fn list_pdf_file_paths(path: &Path) -> Vec<PathBuf> {
    let mut entries = std::fs::read_dir(path)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|entry_path| {
            entry_path
                .extension()
                .and_then(|value| value.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("pdf"))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.to_string_lossy().cmp(&right.to_string_lossy()));
    entries
}

fn join_paths_csv(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_shutdown_provider_invocation_receipt(path: &Path) -> ShutdownProviderInvocationReceipt {
    let mut receipt = ShutdownProviderInvocationReceipt::default();
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "provider" => receipt.provider = value.to_string(),
            "provider_invoked" => receipt.provider_invoked = value.eq_ignore_ascii_case("true"),
            "provider_args" => receipt.provider_args = value.to_string(),
            _ => {}
        }
    }
    receipt
}

fn action_output_excerpt_limit(tool_name: &str) -> usize {
    let lower = tool_name.to_ascii_lowercase();
    if lower.starts_with("wallet_network__mail_")
        || lower.starts_with("wallet_mail_")
        || lower.starts_with("mail__")
        || lower.starts_with("connector__google__")
    {
        1_400
    } else {
        220
    }
}

fn upsert_wallet_network_service_meta(state: &mut IAVLTree<HashCommitmentScheme>) -> Result<()> {
    let mut methods = BTreeMap::new();
    for method in [
        "configure_control_root@v1",
        "register_client@v1",
        "revoke_client@v1",
        "get_client@v1",
        "list_clients@v1",
        "store_secret_record@v1",
        "connector_auth_upsert@v1",
        "connector_auth_get@v1",
        "connector_auth_list@v1",
        "connector_auth_export@v1",
        "connector_auth_import@v1",
        "mail_connector_upsert@v1",
        "mail_connector_get@v1",
        "mail_connector_ensure_binding@v1",
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

fn insert_fixture_evidence<T>(
    verification_checks: &mut BTreeSet<String>,
    environment_receipts: &mut Vec<EnvironmentReceiptObservation>,
    fixture: Option<&T>,
    post_run: fn(&T) -> EnvironmentEvidenceBatch,
    cleanup: Option<fn(&T) -> EnvironmentEvidenceBatch>,
) {
    let Some(fixture) = fixture else {
        return;
    };
    let post_run_batch = post_run(fixture);
    environment_receipts.extend(post_run_batch.evidence);
    for check in post_run_batch.checks {
        verification_checks.insert(check);
    }
    if let Some(cleanup_fn) = cleanup {
        let cleanup_batch = cleanup_fn(fixture);
        environment_receipts.extend(cleanup_batch.evidence);
        for check in cleanup_batch.checks {
            verification_checks.insert(check);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        case_step_timeout_reason, merge_environment_receipts, parse_mail_read_latest_payload,
        parse_mail_reply_payload, parse_tool_normalization_observation, remaining_case_budget,
        route_decision_observation,
    };
    use crate::capabilities_suite::types::EnvironmentReceiptObservation;
    use std::time::Duration;

    #[test]
    fn parses_mail_read_latest_payload_into_typed_observation() {
        let payload = parse_mail_read_latest_payload(
            r#"{
                "operation":"mail_read_latest@v1",
                "mailbox":"primary",
                "citation":"imap://primary/msg-123",
                "message":{
                    "message_id":"msg-123",
                    "from":"alerts@example.com",
                    "subject":"Status update",
                    "received_at_ms":1772862000000,
                    "received_at_utc":"2026-03-07T05:00:00Z",
                    "preview":"Latest status update preview"
                }
            }"#,
        )
        .expect("mail read payload should parse");

        assert_eq!(payload.operation.as_deref(), Some("mail_read_latest@v1"));
        assert_eq!(payload.mailbox.as_deref(), Some("primary"));
        assert_eq!(payload.citation.as_deref(), Some("imap://primary/msg-123"));
        assert_eq!(payload.message_id.as_deref(), Some("msg-123"));
        assert_eq!(payload.from.as_deref(), Some("alerts@example.com"));
        assert_eq!(payload.subject.as_deref(), Some("Status update"));
        assert_eq!(payload.received_at_ms, Some(1772862000000));
        assert_eq!(
            payload.received_at_utc.as_deref(),
            Some("2026-03-07T05:00:00Z")
        );
    }

    #[test]
    fn parses_mail_reply_payload_into_typed_observation() {
        let payload = parse_mail_reply_payload(
            r#"{
                "operation":"mail_reply@v1",
                "mailbox":"primary",
                "to":"team@ioi.network",
                "subject":"Standup moved",
                "body":"Tomorrow's standup is moved to 2 PM.",
                "sent_message_id":"sent-456",
                "citation":"mailto:team@ioi.network?subject=Standup%20moved"
            }"#,
        )
        .expect("mail reply payload should parse");

        assert_eq!(payload.operation.as_deref(), Some("mail_reply@v1"));
        assert_eq!(payload.mailbox.as_deref(), Some("primary"));
        assert_eq!(payload.to.as_deref(), Some("team@ioi.network"));
        assert_eq!(payload.subject.as_deref(), Some("Standup moved"));
        assert_eq!(
            payload.body.as_deref(),
            Some("Tomorrow's standup is moved to 2 PM.")
        );
        assert_eq!(payload.sent_message_id.as_deref(), Some("sent-456"));
        assert_eq!(
            payload.citation.as_deref(),
            Some("mailto:team@ioi.network?subject=Standup%20moved")
        );
    }

    #[test]
    fn merge_environment_receipts_deduplicates_observed_values() {
        let existing = vec![EnvironmentReceiptObservation {
            key: "top_memory_apps_row".to_string(),
            observed_values: vec!["1|code|4003|4437552".to_string()],
            probe_source: Some("fixture.receipt_probe".to_string()),
            timestamp_ms: Some(1),
            satisfied: Some(true),
        }];
        let checks = vec![
            "env_evidence::top_memory_apps_row=1|code|4003|4437552".to_string(),
            "env_evidence::top_memory_apps_row=2|firefox-bin|5461|841404".to_string(),
        ];

        let merged = merge_environment_receipts(existing, &checks);
        let row_receipt = merged
            .iter()
            .find(|receipt| receipt.key == "top_memory_apps_row")
            .expect("row receipt should be present");

        assert_eq!(
            row_receipt.observed_values,
            vec![
                "1|code|4003|4437552".to_string(),
                "2|firefox-bin|5461|841404".to_string(),
            ]
        );
    }

    #[test]
    fn remaining_case_budget_respects_deadline_exhaustion() {
        assert_eq!(
            remaining_case_budget(Duration::from_secs(120), Duration::from_secs(30)),
            Some(Duration::from_secs(90))
        );
        assert_eq!(
            remaining_case_budget(Duration::from_secs(120), Duration::from_secs(120)),
            None
        );
        assert_eq!(
            remaining_case_budget(Duration::from_secs(120), Duration::from_secs(121)),
            None
        );
    }

    #[test]
    fn case_step_timeout_reason_records_elapsed_and_budget() {
        let reason = case_step_timeout_reason(
            Duration::from_millis(120_250),
            Duration::from_secs(120),
            Duration::from_millis(250),
        );

        assert!(
            reason.contains("case_sla_timeout_waiting_for_step_completion"),
            "reason={reason}"
        );
        assert!(reason.contains("elapsed_ms=120250"), "reason={reason}");
        assert!(reason.contains("deadline_ms=120000"), "reason={reason}");
        assert!(reason.contains("step_budget_ms=250"), "reason={reason}");
    }

    #[test]
    fn parse_tool_normalization_observation_retains_alias_and_labels() {
        let observation = parse_tool_normalization_observation(
            "ask_user_input_v0",
            &[
                "tool_normalization_raw_name=ask_user_input_v0".to_string(),
                "tool_normalization_name=user__ask_choice".to_string(),
                "tool_normalization_changed=true".to_string(),
                "tool_normalization_label=legacy_alias".to_string(),
                "tool_normalization_label=canonicalized".to_string(),
            ],
        )
        .expect("normalization observation should be present");

        assert_eq!(observation.tool_name, "ask_user_input_v0");
        assert_eq!(observation.raw_name.as_deref(), Some("ask_user_input_v0"));
        assert_eq!(
            observation.normalized_name.as_deref(),
            Some("user__ask_choice")
        );
        assert!(observation.changed);
        assert_eq!(
            observation.labels,
            vec!["legacy_alias".to_string(), "canonicalized".to_string()]
        );
    }

    #[test]
    fn route_decision_observation_retains_projected_tool_surface() {
        let decision = ioi_types::app::RoutingRouteDecision {
            route_family: "connectors".to_string(),
            direct_answer_allowed: false,
            direct_answer_blockers: vec!["connector_match".to_string()],
            currentness_override: true,
            connector_candidate_count: 2,
            selected_provider_family: Some("gmail".to_string()),
            selected_provider_route_label: Some("provider_first".to_string()),
            connector_first_preference: true,
            narrow_tool_preference: true,
            file_output_intent: false,
            artifact_output_intent: false,
            inline_visual_intent: false,
            skill_prep_required: false,
            output_intent: "tool_execution".to_string(),
            effective_tool_surface: ioi_types::app::RoutingEffectiveToolSurface {
                projected_tools: vec![
                    "gmail__send_email".to_string(),
                    "conversation__reply".to_string(),
                ],
                primary_tools: vec!["gmail__send_email".to_string()],
                broad_fallback_tools: vec!["conversation__reply".to_string()],
                diagnostic_tools: vec!["web__search".to_string()],
            },
        };

        let observation = route_decision_observation("gmail__send_email", &decision)
            .expect("route decision observation should be present");

        assert_eq!(observation.tool_name, "gmail__send_email");
        assert_eq!(observation.route_family, "connectors");
        assert_eq!(observation.output_intent, "tool_execution");
        assert!(!observation.direct_answer_allowed);
        assert!(observation.currentness_override);
        assert!(observation.connector_first_preference);
        assert!(observation.narrow_tool_preference);
        assert_eq!(
            observation.selected_provider_family.as_deref(),
            Some("gmail")
        );
        assert_eq!(
            observation.selected_provider_route_label.as_deref(),
            Some("provider_first")
        );
        assert_eq!(
            observation.projected_tools,
            vec![
                "gmail__send_email".to_string(),
                "conversation__reply".to_string()
            ]
        );
        assert_eq!(
            observation.primary_tools,
            vec!["gmail__send_email".to_string()]
        );
        assert_eq!(
            observation.broad_fallback_tools,
            vec!["conversation__reply".to_string()]
        );
    }

    #[test]
    fn parse_tool_recovery_observation_retains_runtime_strategy_and_retry_signals() {
        let observation = super::parse_tool_recovery_observation(
            "filesystem__patch",
            &[
                "invalid_tool_call_repair_attempted=true".to_string(),
                "invalid_tool_call_repair_succeeded=true".to_string(),
                "invalid_tool_call_repair_runtime=deterministic".to_string(),
                "invalid_tool_call_repair_tool=filesystem__patch".to_string(),
                "invalid_tool_call_repair_workflow=patch_build_verify".to_string(),
                "invalid_tool_call_repair_deterministic_source=goal_constrained_snapshot"
                    .to_string(),
                "invalid_tool_call_repair_deterministic_recovery=targeted_exec".to_string(),
                "invalid_tool_call_repair_targeted_command_boundary=post_edit_unexpected_state"
                    .to_string(),
                "invalid_tool_call_repair_targeted_command_rerun=post_edit".to_string(),
                "determinism_recovery_retry=true".to_string(),
                "invalid_tool_call_repair_runtime_line_edit_upconverted=true".to_string(),
            ],
        )
        .expect("recovery observation should be present");

        assert_eq!(observation.tool_name, "filesystem__patch");
        assert!(observation.repair_attempted);
        assert_eq!(observation.repair_succeeded, Some(true));
        assert!(observation.retry_path);
        assert_eq!(observation.repair_runtime.as_deref(), Some("deterministic"));
        assert_eq!(
            observation.repair_tool.as_deref(),
            Some("filesystem__patch")
        );
        assert_eq!(
            observation.repair_workflow.as_deref(),
            Some("patch_build_verify")
        );
        assert_eq!(
            observation.recovery_strategy.as_deref(),
            Some("targeted_exec")
        );
        assert_eq!(
            observation.recovery_source.as_deref(),
            Some("goal_constrained_snapshot")
        );
        assert_eq!(
            observation.boundary_events,
            vec![
                "invalid_tool_call_repair_targeted_command_boundary=post_edit_unexpected_state"
                    .to_string(),
                "invalid_tool_call_repair_targeted_command_rerun=post_edit".to_string(),
            ]
        );
        assert!(observation
            .labels
            .contains(&"determinism_recovery_retry".to_string()));
        assert!(observation
            .labels
            .contains(&"invalid_tool_call_repair_runtime_line_edit_upconverted".to_string()));
    }
}
