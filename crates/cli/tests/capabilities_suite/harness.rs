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
use ioi_services::agentic::desktop::keys::{AGENT_POLICY_PREFIX, INCIDENT_PREFIX};
use ioi_services::agentic::desktop::service::step::helpers::{
    default_safe_policy, is_mailbox_connector_goal,
};
use ioi_services::agentic::desktop::service::step::incident::IncidentState;
use ioi_services::agentic::desktop::{
    AgentMode, AgentState, AgentStatus, DesktopAgentService, ResumeAgentParams, StartAgentParams,
    StepAgentParams,
};
use ioi_services::agentic::rules::DefaultPolicy;
use ioi_services::wallet_network::WalletNetworkService;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::action::PiiApprovalAction;
use ioi_types::app::action::{ApprovalScope, ApprovalToken};
use ioi_types::app::agentic::{
    CapabilityId, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
};
use ioi_types::app::{
    ActionRequest, ContextSlice, KernelEvent, MailConnectorAuthMode, MailConnectorConfig,
    MailConnectorEndpoint, MailConnectorProvider, MailConnectorSecretAliases, MailConnectorTlsMode,
    MailConnectorUpsertParams, RoutingReceiptEvent, SecretKind, SessionChannelDelegationRules,
    SessionChannelEnvelope, SessionChannelMode, SessionChannelOrdering, SessionChannelRecord,
    SessionChannelState, SessionLease, SessionLeaseMode, SignatureSuite, VaultSecretRecord,
    WorkloadActivityKind, WorkloadExecReceipt, WorkloadReceipt,
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
use zip::ZipArchive;

use super::types::{
    cec_receipt_bool, cec_receipt_usize, cec_receipt_value, cec_receipt_values,
    has_policy_decision, has_verification_pair, observation_has_any_tool_name,
    observation_has_tool_name, parse_verification_fact, parse_verification_facts, ActionEvidence,
    CecReceiptEvidence, CommandHistoryEvidence, EnvironmentReceiptObservation, MailObservation,
    MailReadLatestPayloadObservation, MailReplyPayloadObservation, PlannedToolCallEvidence,
    QueryCase, RunObservation, ScreenshotObservation, WebObservation,
};

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
const MAIL_E2E_KEY_PROVIDER_DRIVER: &str = "MAIL_E2E_PROVIDER_DRIVER";
const VLC_INSTALL_CASE_ID: &str = "download_and_install_vlc_media_player";
const VLC_INSTALL_UNSEEDED_CASE_ID: &str = "download_and_install_vlc_media_player_unseeded";
const VLC_INSTALL_FIXTURE_MODE: &str = "apt_get_vlc_fixture_v1";
const VLC_INSTALL_FIXTURE_PROBE_SOURCE: &str = "harness.vlc_install_fixture";
const DESKTOP_PROJECT_CREATE_CASE_ID: &str =
    "create_a_new_folder_on_my_desktop_called_project_some_number";
const DESKTOP_PROJECT_CREATE_FIXTURE_MODE: &str = "desktop_project_create_fixture_v1";
const DESKTOP_PROJECT_CREATE_FIXTURE_PROBE_SOURCE: &str =
    "harness.desktop_project_create_fixture";
const PROJECTS_ZIP_CASE_ID: &str =
    "compress_the_projects_folder_into_a_zip_file_and_put_it_on_my_desktop";
const PROJECTS_ZIP_FIXTURE_MODE: &str = "desktop_projects_zip_fixture_v1";
const PROJECTS_ZIP_FIXTURE_PROBE_SOURCE: &str = "harness.projects_zip_fixture";
const PROJECTS_ZIP_EXPECTED_ENTRIES: [&str; 3] = ["README.md", "docs/spec.txt", "src/main.rs"];
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
const SHUTDOWN_SCHEDULE_CASE_ID: &str = "schedule_my_computer_to_shut_down_at_11_pm_tonight";
const SHUTDOWN_SCHEDULE_FIXTURE_MODE: &str = "shutdown_schedule_fixture_v1";
const SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE: &str = "harness.shutdown_schedule_fixture";
const SHUTDOWN_SCHEDULE_PROBE_SCRIPT_NAME: &str = "shutdown_schedule_probe";
const SHUTDOWN_SCHEDULE_PROVIDER_IDS: [&str; 3] = ["shutdown", "systemctl", "at"];
const SHUTDOWN_SCHEDULE_TARGET_LOCAL_TIME: &str = "23:00";
const MAIL_REPLY_SEND_CASE_ID: &str =
    "draft_an_email_to_team_ioi_network_saying_tomorrows_standup_is_moved_to_2_pm_and_send_it";
const MAIL_REPLY_MOCK_FIXTURE_MODE: &str = "mail_reply_mock_driver_fixture_v1";
const MAIL_REPLY_MOCK_FIXTURE_PROBE_SOURCE: &str = "harness.mail_reply_mock_driver_fixture";
const RESTAURANTS_NEAR_ME_CASE_ID: &str =
    "find_the_three_best_reviewed_italian_restaurants_near_me_and_compare_their_menus";
const RESTAURANTS_NEAR_ME_FIXTURE_MODE: &str = "runtime_locality_observation_fixture_v2";
const RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE: &str = "harness.restaurants_near_me_fixture";
const RESTAURANTS_NEAR_ME_FIXTURE_DIR_PREFIX: &str = "ioi_restaurants_near_me_";
const RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY: &str = "IOI_SESSION_LOCALITY";

#[derive(Debug, Clone)]
struct MailRuntimeBootstrapConfig {
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

#[derive(Debug, Clone)]
struct MailRuntimeSecretSpec {
    secret_id: String,
    alias: String,
    value: String,
}

struct ScopedEnvVar {
    key: String,
    previous: Option<String>,
    restored: bool,
}

impl ScopedEnvVar {
    fn set(key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let previous = std::env::var(&key).ok();
        std::env::set_var(&key, value.into());
        Self {
            key,
            previous,
            restored: false,
        }
    }

    fn restore_now(&mut self) {
        if self.restored {
            return;
        }
        if let Some(previous) = self.previous.as_ref() {
            std::env::set_var(&self.key, previous);
        } else {
            std::env::remove_var(&self.key);
        }
        self.restored = true;
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        self.restore_now();
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

struct ProjectsZipFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    home_dir: PathBuf,
    projects_dir: PathBuf,
    desktop_dir: PathBuf,
    archive_path: PathBuf,
}

struct DesktopProjectCreateFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    home_dir: PathBuf,
    desktop_dir: PathBuf,
    expected_project_dir: PathBuf,
}

struct DownloadsLowercaseFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    home_dir: PathBuf,
    downloads_dir: PathBuf,
    target_dir: PathBuf,
}

struct DownloadsPngMoveFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    home_dir: PathBuf,
    downloads_dir: PathBuf,
    target_dir: PathBuf,
    images_dir: PathBuf,
}

struct DesktopDocumentsBackupFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    home_dir: PathBuf,
    desktop_dir: PathBuf,
    documents_dir: PathBuf,
    external_drive_path: PathBuf,
    backup_root: PathBuf,
    backup_desktop_path: PathBuf,
    backup_documents_path: PathBuf,
}

struct DocumentsSummaryFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    home_dir: PathBuf,
    documents_dir: PathBuf,
    fixture_dir: PathBuf,
    latest_document_path: PathBuf,
}

struct PdfLastWeekFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    home_dir: PathBuf,
    documents_dir: PathBuf,
    fixture_dir: PathBuf,
    expected_pdf_paths: Vec<PathBuf>,
    window_start_epoch_ms: u64,
}

struct SpotifyUninstallFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    _env_path: ScopedEnvVar,
    _env_fixture_root: ScopedEnvVar,
    _env_fixture_mode: ScopedEnvVar,
    _env_install_marker: ScopedEnvVar,
    _env_binary_path: ScopedEnvVar,
    _env_provider_receipt: ScopedEnvVar,
    home_dir: PathBuf,
    fixture_root: PathBuf,
    provider_receipt_path: PathBuf,
    install_marker_path: PathBuf,
    binary_path: PathBuf,
    config_paths: Vec<PathBuf>,
    sentinel_paths: Vec<PathBuf>,
}

struct TopMemoryAppsFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_path: ScopedEnvVar,
    _env_fixture_mode: ScopedEnvVar,
    _env_receipt_path: ScopedEnvVar,
    fixture_root: PathBuf,
    probe_script_path: PathBuf,
    receipt_path: PathBuf,
}

struct ShutdownScheduleFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_path: ScopedEnvVar,
    _env_fixture_mode: ScopedEnvVar,
    _env_receipt_path: ScopedEnvVar,
    _env_provider_receipt_path: ScopedEnvVar,
    _env_run_unique_num: ScopedEnvVar,
    fixture_root: PathBuf,
    probe_script_path: PathBuf,
    receipt_path: PathBuf,
    provider_receipt_path: PathBuf,
}

struct MailReplyMockDriverFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    fixture_root: PathBuf,
    manifest_path: PathBuf,
}

struct RestaurantsNearMeFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    fixture_root: PathBuf,
    manifest_path: PathBuf,
    observed_locality: Option<String>,
}

#[derive(Debug, Clone)]
struct TopMemoryAppProbeRow {
    rank: usize,
    app: String,
    pid: u32,
    rss_kb: u64,
}

#[derive(Debug, Clone, Default)]
struct TopMemoryAppsProbeReceipt {
    provider: String,
    rows: Vec<TopMemoryAppProbeRow>,
}

#[derive(Debug, Clone, Default)]
struct ShutdownScheduleProbeReceipt {
    provider: String,
    target_local_time: String,
    target_local_date: String,
    now_epoch_sec: i64,
    target_epoch_sec: i64,
    delay_seconds: i64,
    rollover_to_next_day: bool,
    run_unique_num: String,
    scheduled: bool,
}

#[derive(Debug, Clone, Default)]
struct ShutdownProviderInvocationReceipt {
    provider: String,
    provider_invoked: bool,
    provider_args: String,
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
        provider_driver: nonempty_env_value(MAIL_E2E_KEY_PROVIDER_DRIVER)
            .map(|value| value.to_ascii_lowercase()),
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
    pii_action: Option<PiiApprovalAction>,
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
        pii_action,
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

fn read_incident_pending_gate_hash(
    state: &IAVLTree<HashCommitmentScheme>,
    session_id: [u8; 32],
) -> Option<[u8; 32]> {
    let key = [INCIDENT_PREFIX, session_id.as_slice()].concat();
    let bytes = state.get(&key).ok().flatten()?;
    let incident: IncidentState = codec::from_bytes_canonical(&bytes).ok()?;
    if !incident.active {
        return None;
    }
    incident
        .pending_gate
        .as_ref()
        .and_then(|gate| parse_hex_hash_32(&gate.request_hash))
}

fn has_review_request_for_hash(
    state: &IAVLTree<HashCommitmentScheme>,
    request_hash: [u8; 32],
) -> bool {
    let key = ioi_services::agentic::desktop::keys::pii::review::request(&request_hash);
    state.get(&key).ok().flatten().is_some()
}

fn seeded_required_capabilities(scope: IntentScopeProfile, intent_id: &str) -> Vec<CapabilityId> {
    let normalized_intent_id = intent_id.trim().to_ascii_lowercase();
    if normalized_intent_id == "mail.read.latest" {
        return vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("mail.read.latest"),
        ];
    }
    if normalized_intent_id == "mail.list.recent" {
        return vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("mail.list.recent"),
        ];
    }
    if normalized_intent_id == "mail.delete.spam" {
        return vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("mail.delete.spam"),
        ];
    }
    if normalized_intent_id == "mail.reply" {
        return vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("mail.reply"),
        ];
    }

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

    let install_intent = normalized_intent_id.contains("install");
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

fn apply_capabilities_policy(state: &mut IAVLTree<HashCommitmentScheme>, session_id: [u8; 32]) {
    let mut rules = default_safe_policy();
    // Dedicated live capabilities suite should validate execution success without
    // interactive approval gates blocking baseline command/app flows.
    rules.defaults = DefaultPolicy::AllowAll;
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
            error_class,
            agent_status,
            ..
        } => format!(
            "action tool={} status={} error_class={} output={}",
            tool_name,
            agent_status,
            error_class.as_deref().unwrap_or("none"),
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

fn command_history_key(entry: &CommandHistoryEvidence) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        entry.command, entry.exit_code, entry.stdout, entry.stderr
    )
}

fn push_command_history_evidence(
    command_history_evidence: &mut Vec<CommandHistoryEvidence>,
    command_history_keys: &mut BTreeSet<String>,
    entry: CommandHistoryEvidence,
) {
    let key = command_history_key(&entry);
    if command_history_keys.insert(key) {
        command_history_evidence.push(entry);
    }
}

fn command_history_from_exec_workload(
    exec: &WorkloadExecReceipt,
    evidence: Option<&ExecWorkloadEvidence>,
) -> CommandHistoryEvidence {
    let command = if !exec.command_preview.trim().is_empty() {
        exec.command_preview.clone()
    } else if exec.args.is_empty() {
        exec.command.clone()
    } else {
        format!("{} {}", exec.command, exec.args.join(" "))
    };
    let exit_code = evidence
        .and_then(|item| item.exit_code)
        .or(exec.exit_code)
        .unwrap_or(if exec.success { 0 } else { 1 });
    let stdout = evidence
        .map(ExecWorkloadEvidence::stdout_text)
        .unwrap_or_default();
    let stderr = evidence
        .map(ExecWorkloadEvidence::stderr_text)
        .unwrap_or_default();
    CommandHistoryEvidence {
        command,
        exit_code,
        stdout,
        stderr,
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
    source_count: u32,
    selected: bool,
    success: bool,
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
            source_count: payload.source_count as usize,
            selected: payload.selected,
            success: payload.success,
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

fn accumulate_environment_receipts_from_checks(
    grouped: &mut BTreeMap<String, EnvironmentReceiptAccumulator>,
    checks: &[String],
) {
    for fact in checks.iter().map(|check| parse_verification_fact(check)) {
        let Some(normalized_key) = fact.key.strip_prefix("env_receipt::") else {
            continue;
        };
        let Some(raw_value) = fact.value else {
            continue;
        };
        let value = raw_value.trim().to_string();
        let (base_key, field_kind) =
            if let Some(base) = normalized_key.strip_suffix("_probe_source") {
                (base, "probe_source")
            } else if let Some(base) = normalized_key.strip_suffix("_timestamp_ms") {
                (base, "timestamp_ms")
            } else if let Some(base) = normalized_key.strip_suffix("_satisfied") {
                (base, "satisfied")
            } else {
                (normalized_key, "observed_value")
            };

        let entry = grouped.entry(base_key.to_string()).or_default();
        match field_kind {
            "probe_source" => {
                if !value.is_empty() {
                    entry.probe_source = Some(value);
                }
            }
            "timestamp_ms" => {
                if let Ok(parsed) = value.parse::<u64>() {
                    entry.timestamp_ms = Some(parsed);
                }
            }
            "satisfied" => {
                let normalized = value.to_ascii_lowercase();
                entry.satisfied = match normalized.as_str() {
                    "true" | "1" | "yes" => Some(true),
                    "false" | "0" | "no" => Some(false),
                    _ => entry.satisfied,
                };
            }
            _ => {
                if !value.is_empty() && !entry.observed_values.contains(&value) {
                    entry.observed_values.push(value.clone());
                }
                let normalized = value.to_ascii_lowercase();
                if entry.satisfied.is_none() {
                    entry.satisfied = match normalized.as_str() {
                        "true" | "1" | "yes" => Some(true),
                        "false" | "0" | "no" => Some(false),
                        _ => None,
                    };
                }
            }
        }
    }
}

fn accumulate_environment_receipts_from_observations(
    grouped: &mut BTreeMap<String, EnvironmentReceiptAccumulator>,
    receipts: &[EnvironmentReceiptObservation],
) {
    for receipt in receipts {
        let entry = grouped.entry(receipt.key.clone()).or_default();
        for value in &receipt.observed_values {
            if !value.is_empty() && !entry.observed_values.contains(value) {
                entry.observed_values.push(value.clone());
            }
        }
        if let Some(probe_source) = receipt.probe_source.as_ref() {
            if !probe_source.trim().is_empty() {
                entry.probe_source = Some(probe_source.clone());
            }
        }
        if let Some(timestamp_ms) = receipt.timestamp_ms {
            entry.timestamp_ms = Some(timestamp_ms);
        }
        if let Some(satisfied) = receipt.satisfied {
            entry.satisfied = Some(satisfied);
        }
    }
}

fn finalize_environment_receipts(
    grouped: BTreeMap<String, EnvironmentReceiptAccumulator>,
) -> Vec<EnvironmentReceiptObservation> {
    grouped
        .into_iter()
        .map(|(key, entry)| EnvironmentReceiptObservation {
            key,
            observed_values: entry.observed_values,
            probe_source: entry.probe_source,
            timestamp_ms: entry.timestamp_ms,
            satisfied: entry.satisfied,
        })
        .collect()
}

fn derive_environment_receipts(checks: &[String]) -> Vec<EnvironmentReceiptObservation> {
    let mut grouped = BTreeMap::<String, EnvironmentReceiptAccumulator>::new();
    accumulate_environment_receipts_from_checks(&mut grouped, checks);
    finalize_environment_receipts(grouped)
}

fn merge_environment_receipts(
    existing: Vec<EnvironmentReceiptObservation>,
    checks: &[String],
) -> Vec<EnvironmentReceiptObservation> {
    let mut grouped = BTreeMap::<String, EnvironmentReceiptAccumulator>::new();
    accumulate_environment_receipts_from_observations(&mut grouped, &existing);
    accumulate_environment_receipts_from_checks(&mut grouped, checks);
    finalize_environment_receipts(grouped)
}

#[derive(Default)]
struct EnvironmentEvidenceBatch {
    checks: Vec<String>,
    receipts: Vec<EnvironmentReceiptObservation>,
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
        let receipts = derive_environment_receipts(&self);
        EnvironmentEvidenceBatch {
            checks: self,
            receipts,
        }
    }
}

fn mirror_environment_receipt_checks(receipt: &EnvironmentReceiptObservation) -> Vec<String> {
    let mut checks = Vec::new();
    for value in &receipt.observed_values {
        checks.push(format!("env_receipt::{}={}", receipt.key, value));
    }
    if let Some(probe_source) = receipt.probe_source.as_ref() {
        checks.push(format!(
            "env_receipt::{}_probe_source={}",
            receipt.key, probe_source
        ));
    }
    if let Some(timestamp_ms) = receipt.timestamp_ms {
        checks.push(format!(
            "env_receipt::{}_timestamp_ms={}",
            receipt.key, timestamp_ms
        ));
    }
    if let Some(satisfied) = receipt.satisfied {
        checks.push(format!("env_receipt::{}_satisfied={}", receipt.key, satisfied));
    }
    checks
}

fn push_environment_observation(
    batch: &mut EnvironmentEvidenceBatch,
    key: impl Into<String>,
    observed_value: impl Into<String>,
) {
    let receipt = EnvironmentReceiptObservation {
        key: key.into(),
        observed_values: vec![observed_value.into()],
        probe_source: None,
        timestamp_ms: None,
        satisfied: None,
    };
    batch.checks.extend(mirror_environment_receipt_checks(&receipt));
    batch.receipts.push(receipt);
}

fn push_environment_metadata(
    batch: &mut EnvironmentEvidenceBatch,
    key: impl Into<String>,
    probe_source: Option<String>,
    timestamp_ms: Option<u64>,
    satisfied: Option<bool>,
) {
    let receipt = EnvironmentReceiptObservation {
        key: key.into(),
        observed_values: Vec::new(),
        probe_source,
        timestamp_ms,
        satisfied,
    };
    batch.checks.extend(mirror_environment_receipt_checks(&receipt));
    batch.receipts.push(receipt);
}

fn push_environment_receipt(
    batch: &mut EnvironmentEvidenceBatch,
    key: impl Into<String>,
    observed_value: impl Into<String>,
    probe_source: Option<String>,
    timestamp_ms: Option<u64>,
    satisfied: Option<bool>,
) {
    let receipt = EnvironmentReceiptObservation {
        key: key.into(),
        observed_values: vec![observed_value.into()],
        probe_source,
        timestamp_ms,
        satisfied,
    };
    batch.checks.extend(mirror_environment_receipt_checks(&receipt));
    batch.receipts.push(receipt);
}

fn extend_environment_evidence_batch(
    checks: &mut Vec<String>,
    receipts: &mut Vec<EnvironmentReceiptObservation>,
    batch: EnvironmentEvidenceBatch,
) {
    checks.extend(batch.checks);
    receipts.extend(batch.receipts);
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
    let semantic_subject_alignment_floor_met = typed_receipt_state(
        observation,
        "discovery",
        "semantic_subject_alignment_floor",
    );
    let semantic_subject_alignment_urls = collect_unique_urls(cec_receipt_values(
        observation,
        "discovery",
        "semantic_subject_alignment_url",
    ));
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
    let selected_source_urls = collect_unique_urls(cec_receipt_values(
        observation,
        "verification",
        "selected_source_url",
    ));
    let selected_source_subject_alignment_urls = collect_unique_urls(cec_receipt_values(
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
    let local_business_entity_names = collect_unique_names(cec_receipt_values(
        observation,
        "verification",
        "local_business_entity_name",
    ));
    let local_business_entity_source_urls = collect_unique_urls(cec_receipt_values(
        observation,
        "verification",
        "local_business_entity_source_url",
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
        local_business_entity_names,
        local_business_entity_source_urls,
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
            entry.tool_name.eq_ignore_ascii_case("computer")
                && entry.agent_status.eq_ignore_ascii_case("completed")
        })
        .count();
    let capture_failure_count = observation
        .action_evidence
        .iter()
        .filter(|entry| {
            entry.tool_name.eq_ignore_ascii_case("computer")
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
        .filter(|entry| entry.tool_name.eq_ignore_ascii_case("gui__snapshot"))
        .count();
    let gui_snapshot_routing_count = observation
        .routing_tools
        .iter()
        .filter(|tool| tool.eq_ignore_ascii_case("gui__snapshot"))
        .count();
    let capture_route_seen = observation_has_tool_name(observation, "computer");
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

fn json_string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
}

fn json_u64_field(value: &serde_json::Value, key: &str) -> Option<u64> {
    value.get(key).and_then(serde_json::Value::as_u64)
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

fn run_unique_num(run_index: usize, run_timestamp_ms: u64) -> String {
    format!("{}{:03}", run_timestamp_ms, run_index)
}

fn render_query_for_run(query_template: &str, run_index: usize, run_timestamp_ms: u64) -> String {
    let run_unique_num = run_unique_num(run_index, run_timestamp_ms);
    query_template
        .replace("{RUN_UNIQUE_NUM}", &run_unique_num)
        .replace("{RUN_INDEX}", &run_index.to_string())
}

fn should_bootstrap_mailbox_runtime(goal: &str) -> bool {
    is_mailbox_connector_goal(goal)
}

fn should_bootstrap_vlc_install_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(VLC_INSTALL_CASE_ID)
        || case_id.eq_ignore_ascii_case(VLC_INSTALL_UNSEEDED_CASE_ID)
}

fn should_bootstrap_desktop_project_create_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(DESKTOP_PROJECT_CREATE_CASE_ID)
}

fn should_bootstrap_projects_zip_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(PROJECTS_ZIP_CASE_ID)
}

fn should_bootstrap_downloads_lowercase_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(DOWNLOADS_LOWERCASE_CASE_ID)
}

fn should_bootstrap_downloads_png_move_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(DOWNLOADS_PNG_MOVE_CASE_ID)
}

fn should_bootstrap_desktop_documents_backup_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(DESKTOP_DOCUMENTS_BACKUP_CASE_ID)
}

fn should_bootstrap_documents_summary_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(DOCUMENTS_SUMMARY_CASE_ID)
}

fn should_bootstrap_pdf_last_week_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(PDF_LAST_WEEK_CASE_ID)
}

fn should_bootstrap_spotify_uninstall_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(SPOTIFY_UNINSTALL_CASE_ID)
}

fn should_bootstrap_top_memory_apps_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(TOP_MEMORY_APPS_CASE_ID)
}

fn should_bootstrap_shutdown_schedule_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(SHUTDOWN_SCHEDULE_CASE_ID)
}

fn should_bootstrap_mail_reply_mock_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(MAIL_REPLY_SEND_CASE_ID)
}

fn should_bootstrap_restaurants_near_me_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(RESTAURANTS_NEAR_ME_CASE_ID)
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
) -> EnvironmentEvidenceBatch {
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(&mut batch, "vlc_fixture_mode", VLC_INSTALL_FIXTURE_MODE);
    push_environment_observation(
        &mut batch,
        "vlc_fixture_prefix",
        fixture.prefix.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "vlc_fixture",
        Some(VLC_INSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(true),
    );
    batch
}

fn vlc_install_fixture_post_run_checks(
    fixture: &VlcInstallFixtureRuntime,
) -> EnvironmentEvidenceBatch {
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
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "vlc_download_receipt_path",
        fixture.download_receipt_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "vlc_download_receipt",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(download_exists),
    );
    push_environment_observation(
        &mut batch,
        "vlc_install_receipt_path",
        fixture.install_receipt_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "vlc_install_receipt",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(install_exists),
    );
    push_environment_receipt(
        &mut batch,
        "vlc_install_receipt_value",
        install_receipt_value,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(install_receipt_value_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "vlc_binary_path",
        fixture.vlc_binary_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "vlc_binary",
        Some(probe_source),
        Some(timestamp_ms),
        Some(binary_exists),
    );
    batch
}

fn bootstrap_projects_zip_fixture_runtime() -> Result<ProjectsZipFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let projects_dir = home_dir.join("Projects");
    let desktop_dir = home_dir.join("Desktop");
    let archive_path = desktop_dir.join("Projects.zip");
    std::fs::create_dir_all(projects_dir.join("src"))?;
    std::fs::create_dir_all(projects_dir.join("docs"))?;
    std::fs::create_dir_all(&desktop_dir)?;

    std::fs::write(projects_dir.join("README.md"), "# fixture project\n")?;
    std::fs::write(
        projects_dir.join("src").join("main.rs"),
        "fn main() { println!(\"fixture\"); }\n",
    )?;
    std::fs::write(
        projects_dir.join("docs").join("spec.txt"),
        "fixture spec document\n",
    )?;

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());

    Ok(ProjectsZipFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        home_dir,
        projects_dir,
        desktop_dir,
        archive_path,
    })
}

fn bootstrap_desktop_project_create_fixture_runtime(
    run_unique_num: &str,
) -> Result<DesktopProjectCreateFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let desktop_dir = home_dir.join("Desktop");
    let expected_project_dir = desktop_dir.join(format!("Project_{}", run_unique_num));
    std::fs::create_dir_all(&desktop_dir)?;

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());

    Ok(DesktopProjectCreateFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        home_dir,
        desktop_dir,
        expected_project_dir,
    })
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

fn desktop_project_create_fixture_post_run_checks(
    fixture: &DesktopProjectCreateFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", DESKTOP_PROJECT_CREATE_FIXTURE_PROBE_SOURCE);
    let desktop_entries = list_directory_entry_names(&fixture.desktop_dir);
    let expected_dir_name = fixture
        .expected_project_dir
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string();
    let created_satisfied = fixture.expected_project_dir.is_dir();
    let scope_satisfied = created_satisfied
        && desktop_entries.len() == 1
        && desktop_entries
            .first()
            .map(|entry| entry == &expected_dir_name)
            .unwrap_or(false);
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "desktop_project_observed_path",
        fixture.expected_project_dir.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_project_created",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(created_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "desktop_project_desktop_entries",
        desktop_entries.join(","),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_project_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn desktop_project_create_fixture_cleanup_checks(
    fixture: &DesktopProjectCreateFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", DESKTOP_PROJECT_CREATE_FIXTURE_PROBE_SOURCE);
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

fn projects_zip_fixture_preflight_checks(
    fixture: &ProjectsZipFixtureRuntime,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "projects_zip_fixture_mode",
        PROJECTS_ZIP_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "projects_zip_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "projects_zip_projects_dir",
        fixture.projects_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "projects_zip_desktop_dir",
        fixture.desktop_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "projects_zip_archive_path",
        fixture.archive_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "projects_zip_expected_entries",
        PROJECTS_ZIP_EXPECTED_ENTRIES.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "projects_zip_fixture",
        Some(PROJECTS_ZIP_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(true),
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

fn projects_zip_fixture_post_run_checks(
    fixture: &ProjectsZipFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", PROJECTS_ZIP_FIXTURE_PROBE_SOURCE);
    let archive_exists = fixture.archive_path.is_file();
    let archive_entries = if archive_exists {
        zip_archive_entries(&fixture.archive_path).unwrap_or_default()
    } else {
        Vec::new()
    };
    let expected_entries_satisfied = PROJECTS_ZIP_EXPECTED_ENTRIES
        .iter()
        .all(|entry| archive_entries.iter().any(|observed| observed == entry));
    let source_preserved = PROJECTS_ZIP_EXPECTED_ENTRIES
        .iter()
        .all(|entry| fixture.projects_dir.join(entry).is_file());
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "projects_zip_archive_path",
        fixture.archive_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "projects_zip_archive",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(archive_exists),
    );
    push_environment_receipt(
        &mut batch,
        "projects_zip_entries",
        archive_entries.join(","),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(expected_entries_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "projects_zip_source_preserved",
        Some(probe_source),
        Some(timestamp_ms),
        Some(source_preserved),
    );
    batch
}

fn projects_zip_fixture_cleanup_checks(
    fixture: &ProjectsZipFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", PROJECTS_ZIP_FIXTURE_PROBE_SOURCE);

    let _ = std::fs::remove_file(&fixture.archive_path);
    let _ = std::fs::remove_dir_all(&fixture.projects_dir);
    let cleanup_satisfied = !fixture.archive_path.exists() && !fixture.projects_dir.exists();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_metadata(
        &mut batch,
        "projects_zip_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_downloads_lowercase_fixture_runtime(
    run_unique_num: &str,
) -> Result<DownloadsLowercaseFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let downloads_dir = home_dir.join("Downloads");
    std::fs::create_dir_all(&downloads_dir)?;
    let target_dir = downloads_dir.join(format!(
        "{}{}",
        DOWNLOADS_LOWERCASE_TARGET_PREFIX, run_unique_num
    ));
    std::fs::create_dir_all(&target_dir)?;
    for file_name in DOWNLOADS_LOWERCASE_EXPECTED_ORIGINAL_FILES {
        std::fs::write(
            target_dir.join(file_name),
            format!("fixture content for {}", file_name),
        )?;
    }

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());

    Ok(DownloadsLowercaseFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        home_dir,
        downloads_dir,
        target_dir,
    })
}

fn downloads_lowercase_fixture_preflight_checks(
    fixture: &DownloadsLowercaseFixtureRuntime,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let seeded_files = list_directory_entry_names(&fixture.target_dir);
    let seeded_files_satisfied = DOWNLOADS_LOWERCASE_EXPECTED_ORIGINAL_FILES
        .iter()
        .all(|expected| seeded_files.iter().any(|observed| observed == expected));
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "downloads_lowercase_fixture_mode",
        DOWNLOADS_LOWERCASE_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "downloads_lowercase_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_lowercase_downloads_dir",
        fixture.downloads_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_lowercase_target_dir",
        fixture.target_dir.to_string_lossy().to_string(),
    );
    push_environment_receipt(
        &mut batch,
        "downloads_lowercase_seeded_files",
        seeded_files.join(","),
        None,
        None,
        Some(seeded_files_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_lowercase_fixture",
        Some(DOWNLOADS_LOWERCASE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(true),
    );
    batch
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

fn downloads_lowercase_fixture_post_run_checks(
    fixture: &DownloadsLowercaseFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", DOWNLOADS_LOWERCASE_FIXTURE_PROBE_SOURCE);
    let mut target_dirs_sorted = std::fs::read_dir(&fixture.downloads_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .filter(|name| name.starts_with(DOWNLOADS_LOWERCASE_TARGET_PREFIX))
        .collect::<Vec<_>>();
    target_dirs_sorted.sort();
    let target_dir_count = target_dirs_sorted.len();
    let target_dir_name = target_dirs_sorted.first().cloned().unwrap_or_default();
    let target_dir_path = if target_dir_name.is_empty() {
        String::new()
    } else {
        fixture
            .downloads_dir
            .join(&target_dir_name)
            .to_string_lossy()
            .to_string()
    };
    let target_dir_satisfied = target_dir_count == 1 && !target_dir_path.is_empty();
    let target_entries = if target_dir_satisfied {
        list_directory_entry_names(&fixture.downloads_dir.join(&target_dir_name))
    } else {
        Vec::new()
    };
    let entries_satisfied = DOWNLOADS_LOWERCASE_EXPECTED_FINAL_FILES
        .iter()
        .all(|expected| target_entries.iter().any(|observed| observed == expected));
    let uppercase_absent = DOWNLOADS_LOWERCASE_EXPECTED_ORIGINAL_FILES
        .iter()
        .all(|original| !target_entries.iter().any(|observed| observed == original));
    let scope_satisfied = std::fs::read_dir(&fixture.downloads_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .all(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| name.starts_with(DOWNLOADS_LOWERCASE_TARGET_PREFIX))
                .unwrap_or(false)
        });
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "downloads_lowercase_target_dir_count",
        target_dir_count.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_lowercase_target_dir_path",
        target_dir_path,
    );
    push_environment_metadata(
        &mut batch,
        "downloads_lowercase_target_dir",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(target_dir_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "downloads_lowercase_entries",
        target_entries.join(","),
        None,
        None,
        Some(entries_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_lowercase_uppercase_absent",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(uppercase_absent),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_lowercase_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn downloads_lowercase_fixture_cleanup_checks(
    fixture: &DownloadsLowercaseFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", DOWNLOADS_LOWERCASE_FIXTURE_PROBE_SOURCE);
    let _ = std::fs::remove_dir_all(&fixture.downloads_dir);
    let _ = std::fs::create_dir_all(&fixture.downloads_dir);
    let remaining_entries = list_directory_entry_names(&fixture.downloads_dir);
    let cleanup_satisfied = remaining_entries.is_empty();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_metadata(
        &mut batch,
        "downloads_lowercase_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_downloads_png_move_fixture_runtime(
    run_unique_num: &str,
) -> Result<DownloadsPngMoveFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let downloads_dir = home_dir.join("Downloads");
    std::fs::create_dir_all(&downloads_dir)?;
    let target_dir = downloads_dir.join(format!(
        "{}{}",
        DOWNLOADS_PNG_MOVE_TARGET_PREFIX, run_unique_num
    ));
    std::fs::create_dir_all(&target_dir)?;
    for file_name in DOWNLOADS_PNG_MOVE_EXPECTED_PNG_FILES {
        std::fs::write(
            target_dir.join(file_name),
            format!("fixture png payload for {}", file_name),
        )?;
    }
    for file_name in DOWNLOADS_PNG_MOVE_EXPECTED_NON_PNG_FILES {
        std::fs::write(
            target_dir.join(file_name),
            format!("fixture non-png payload for {}", file_name),
        )?;
    }
    let images_dir = target_dir.join(DOWNLOADS_PNG_MOVE_IMAGES_DIR_NAME);

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());

    Ok(DownloadsPngMoveFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        home_dir,
        downloads_dir,
        target_dir,
        images_dir,
    })
}

fn downloads_png_move_fixture_preflight_checks(
    fixture: &DownloadsPngMoveFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let seeded_entries = list_directory_entry_names(&fixture.target_dir);
    let seeded_png_satisfied = DOWNLOADS_PNG_MOVE_EXPECTED_PNG_FILES
        .iter()
        .all(|expected| seeded_entries.iter().any(|observed| observed == expected));
    let seeded_non_png_satisfied = DOWNLOADS_PNG_MOVE_EXPECTED_NON_PNG_FILES
        .iter()
        .all(|expected| seeded_entries.iter().any(|observed| observed == expected));
    let images_dir_absent_satisfied = !fixture.images_dir.exists();
    let run_unique_satisfied = fixture
        .target_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let fixture_satisfied = seeded_png_satisfied
        && seeded_non_png_satisfied
        && images_dir_absent_satisfied
        && run_unique_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "downloads_png_move_fixture_mode",
        DOWNLOADS_PNG_MOVE_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_downloads_dir",
        fixture.downloads_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_target_dir",
        fixture.target_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_images_dir",
        fixture.images_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_seeded_entries",
        seeded_entries.join(","),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_seeded_png_files",
        DOWNLOADS_PNG_MOVE_EXPECTED_PNG_FILES.join(","),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_seeded_non_png_files",
        DOWNLOADS_PNG_MOVE_EXPECTED_NON_PNG_FILES.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_seeded_png",
        Some(DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(seeded_png_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_seeded_non_png",
        Some(DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(seeded_non_png_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_images_dir_absent",
        Some(DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(images_dir_absent_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_run_unique",
        Some(DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_fixture",
        Some(DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn downloads_png_move_fixture_post_run_checks(
    fixture: &DownloadsPngMoveFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE);

    let expected_target_dir_name = fixture
        .target_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    let mut target_dirs_sorted = std::fs::read_dir(&fixture.downloads_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .filter(|name| name.starts_with(DOWNLOADS_PNG_MOVE_TARGET_PREFIX))
        .collect::<Vec<_>>();
    target_dirs_sorted.sort();
    let target_dir_count = target_dirs_sorted.len();
    let target_dir_name = target_dirs_sorted.first().cloned().unwrap_or_default();
    let target_dir_path = if target_dir_name.is_empty() {
        String::new()
    } else {
        fixture
            .downloads_dir
            .join(&target_dir_name)
            .to_string_lossy()
            .to_string()
    };
    let target_dir_satisfied = target_dir_count == 1
        && !target_dir_path.is_empty()
        && target_dir_name == expected_target_dir_name;

    let source_dir_path = fixture.downloads_dir.join(&target_dir_name);
    let source_entries = if target_dir_satisfied {
        list_directory_entry_names(&source_dir_path)
    } else {
        Vec::new()
    };
    let images_dir_path = if target_dir_satisfied {
        source_dir_path.join(DOWNLOADS_PNG_MOVE_IMAGES_DIR_NAME)
    } else {
        fixture.images_dir.clone()
    };
    let images_dir_exists = images_dir_path.is_dir();
    let images_entries = if images_dir_exists {
        list_directory_entry_names(&images_dir_path)
    } else {
        Vec::new()
    };
    let images_entries_satisfied = DOWNLOADS_PNG_MOVE_EXPECTED_PNG_FILES
        .iter()
        .all(|expected| images_entries.iter().any(|observed| observed == expected))
        && images_entries.len() == DOWNLOADS_PNG_MOVE_EXPECTED_PNG_FILES.len();
    let source_non_png_preserved = DOWNLOADS_PNG_MOVE_EXPECTED_NON_PNG_FILES
        .iter()
        .all(|expected| source_entries.iter().any(|observed| observed == expected));
    let source_png_absent = DOWNLOADS_PNG_MOVE_EXPECTED_PNG_FILES
        .iter()
        .all(|png_name| !source_entries.iter().any(|observed| observed == png_name));
    let source_entries_scope_satisfied = source_entries.iter().all(|entry| {
        entry == DOWNLOADS_PNG_MOVE_IMAGES_DIR_NAME
            || DOWNLOADS_PNG_MOVE_EXPECTED_NON_PNG_FILES
                .iter()
                .any(|expected| entry == expected)
    }) && source_entries.len()
        == DOWNLOADS_PNG_MOVE_EXPECTED_NON_PNG_FILES.len() + 1;
    let downloads_scope_satisfied = std::fs::read_dir(&fixture.downloads_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .all(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| name.starts_with(DOWNLOADS_PNG_MOVE_TARGET_PREFIX))
                .unwrap_or(false)
        });
    let scope_satisfied =
        target_dir_satisfied && source_entries_scope_satisfied && downloads_scope_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "downloads_png_move_target_dir_count",
        target_dir_count.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_target_dir_path",
        target_dir_path,
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_target_dir",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(target_dir_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_images_dir_path",
        images_dir_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_images_dir",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(images_dir_exists),
    );
    push_environment_receipt(
        &mut batch,
        "downloads_png_move_images_entries",
        images_entries.join(","),
        None,
        None,
        Some(images_entries_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_source_entries",
        source_entries.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_source_non_png_preserved",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(source_non_png_preserved),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_source_png_absent",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(source_png_absent),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn downloads_png_move_fixture_cleanup_checks(
    fixture: &DownloadsPngMoveFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE);
    let _ = std::fs::remove_dir_all(&fixture.downloads_dir);
    let _ = std::fs::create_dir_all(&fixture.downloads_dir);
    let remaining_entries = list_directory_entry_names(&fixture.downloads_dir);
    let cleanup_satisfied = remaining_entries.is_empty();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_desktop_documents_backup_fixture_runtime(
    run_unique_num: &str,
) -> Result<DesktopDocumentsBackupFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let desktop_dir = home_dir.join("Desktop");
    let documents_dir = home_dir.join("Documents");
    let external_drive_path = temp_dir.path().join("mnt").join("external_drive");
    let backup_root = external_drive_path.join(format!(
        "{}{}",
        DESKTOP_DOCUMENTS_BACKUP_TARGET_PREFIX, run_unique_num
    ));
    let backup_desktop_path = backup_root.join("Desktop");
    let backup_documents_path = backup_root.join("Documents");

    std::fs::create_dir_all(desktop_dir.join("Projects"))?;
    std::fs::create_dir_all(desktop_dir.join("Screenshots"))?;
    std::fs::create_dir_all(documents_dir.join("finance"))?;
    std::fs::create_dir_all(documents_dir.join("reference").join("ops"))?;
    std::fs::create_dir_all(&external_drive_path)?;

    std::fs::write(
        desktop_dir.join("todo.txt"),
        "Desktop todo list\n- ship backup flow\n",
    )?;
    std::fs::write(
        desktop_dir.join("Projects").join("roadmap.md"),
        "Q2 roadmap checkpoint\n",
    )?;
    std::fs::write(
        desktop_dir.join("Screenshots").join("sprint.png"),
        "fixture screenshot bytes\n",
    )?;

    std::fs::write(
        documents_dir.join("report.md"),
        "Weekly report\nStatus: green\n",
    )?;
    std::fs::write(
        documents_dir.join("finance").join("q1-budget.csv"),
        "category,amount\ninfra,1200\n",
    )?;
    std::fs::write(
        documents_dir
            .join("reference")
            .join("ops")
            .join("runbook.txt"),
        "Incident runbook v1\n",
    )?;

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());

    Ok(DesktopDocumentsBackupFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        home_dir,
        desktop_dir,
        documents_dir,
        external_drive_path,
        backup_root,
        backup_desktop_path,
        backup_documents_path,
    })
}

fn desktop_documents_backup_fixture_preflight_checks(
    fixture: &DesktopDocumentsBackupFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let seeded_desktop_files = list_relative_file_paths(&fixture.desktop_dir);
    let seeded_documents_files = list_relative_file_paths(&fixture.documents_dir);
    let seeded_desktop_satisfied =
        DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DESKTOP_FILES
            .iter()
            .all(|expected| {
                seeded_desktop_files
                    .iter()
                    .any(|observed| observed == expected)
            })
            && seeded_desktop_files.len() == DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DESKTOP_FILES.len();
    let seeded_documents_satisfied = DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DOCUMENTS_FILES
        .iter()
        .all(|expected| {
            seeded_documents_files
                .iter()
                .any(|observed| observed == expected)
        })
        && seeded_documents_files.len() == DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DOCUMENTS_FILES.len();
    let destination_absent_satisfied = !fixture.backup_root.exists();
    let run_unique_satisfied = fixture
        .backup_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let fixture_satisfied = fixture.external_drive_path.is_dir()
        && seeded_desktop_satisfied
        && seeded_documents_satisfied
        && destination_absent_satisfied
        && run_unique_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_fixture_mode",
        DESKTOP_DOCUMENTS_BACKUP_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_desktop_dir",
        fixture.desktop_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_documents_dir",
        fixture.documents_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_external_drive_path",
        fixture.external_drive_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_destination_root",
        fixture.backup_root.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_receipt(
        &mut batch,
        "desktop_documents_backup_seeded_desktop_files",
        seeded_desktop_files.join(","),
        None,
        None,
        Some(seeded_desktop_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "desktop_documents_backup_seeded_documents_files",
        seeded_documents_files.join(","),
        None,
        None,
        Some(seeded_documents_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_destination_absent",
        Some(DESKTOP_DOCUMENTS_BACKUP_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(destination_absent_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_run_unique",
        Some(DESKTOP_DOCUMENTS_BACKUP_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_fixture",
        Some(DESKTOP_DOCUMENTS_BACKUP_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn desktop_documents_backup_fixture_post_run_checks(
    fixture: &DesktopDocumentsBackupFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", DESKTOP_DOCUMENTS_BACKUP_FIXTURE_PROBE_SOURCE);

    let backup_root_satisfied = fixture.backup_root.is_dir();
    let backup_desktop_satisfied = fixture.backup_desktop_path.is_dir();
    let backup_documents_satisfied = fixture.backup_documents_path.is_dir();

    let source_desktop_files = list_relative_file_paths(&fixture.desktop_dir);
    let source_documents_files = list_relative_file_paths(&fixture.documents_dir);
    let backup_desktop_files = list_relative_file_paths(&fixture.backup_desktop_path);
    let backup_documents_files = list_relative_file_paths(&fixture.backup_documents_path);

    let source_desktop_satisfied =
        DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DESKTOP_FILES
            .iter()
            .all(|expected| {
                source_desktop_files
                    .iter()
                    .any(|observed| observed == expected)
            })
            && source_desktop_files.len() == DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DESKTOP_FILES.len();
    let source_documents_satisfied = DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DOCUMENTS_FILES
        .iter()
        .all(|expected| {
            source_documents_files
                .iter()
                .any(|observed| observed == expected)
        })
        && source_documents_files.len() == DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DOCUMENTS_FILES.len();
    let backup_desktop_files_satisfied = DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DESKTOP_FILES
        .iter()
        .all(|expected| {
            backup_desktop_files
                .iter()
                .any(|observed| observed == expected)
        })
        && backup_desktop_files.len() == DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DESKTOP_FILES.len();
    let backup_documents_files_satisfied = DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DOCUMENTS_FILES
        .iter()
        .all(|expected| {
            backup_documents_files
                .iter()
                .any(|observed| observed == expected)
        })
        && backup_documents_files.len() == DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DOCUMENTS_FILES.len();
    let source_preserved_satisfied = source_desktop_satisfied && source_documents_satisfied;
    let content_match_satisfied = backup_desktop_files_satisfied
        && backup_documents_files_satisfied
        && file_sets_content_match(
            &fixture.desktop_dir,
            &fixture.backup_desktop_path,
            &backup_desktop_files,
        )
        && file_sets_content_match(
            &fixture.documents_dir,
            &fixture.backup_documents_path,
            &backup_documents_files,
        );

    let external_drive_entries = list_directory_entry_names(&fixture.external_drive_path);
    let expected_backup_dir_name = fixture
        .backup_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    let scope_satisfied = !expected_backup_dir_name.is_empty()
        && external_drive_entries.len() == 1
        && external_drive_entries
            .iter()
            .any(|entry| entry == &expected_backup_dir_name);
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_backup_root_path",
        fixture.backup_root.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_backup",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(true),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_backup_root",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(backup_root_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_backup_desktop_path",
        fixture.backup_desktop_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_backup_desktop",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(backup_desktop_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "desktop_documents_backup_backup_desktop_files",
        backup_desktop_files.join(","),
        None,
        None,
        Some(backup_desktop_files_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_backup_documents_path",
        fixture.backup_documents_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_backup_documents",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(backup_documents_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "desktop_documents_backup_backup_documents_files",
        backup_documents_files.join(","),
        None,
        None,
        Some(backup_documents_files_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_source_desktop_files",
        source_desktop_files.join(","),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_source_documents_files",
        source_documents_files.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_source_preserved",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(source_preserved_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_content_match",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(content_match_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn desktop_documents_backup_fixture_cleanup_checks(
    fixture: &DesktopDocumentsBackupFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!(
        "{}.cleanup_probe",
        DESKTOP_DOCUMENTS_BACKUP_FIXTURE_PROBE_SOURCE
    );

    let _ = std::fs::remove_dir_all(&fixture.backup_root);
    let _ = std::fs::remove_dir_all(&fixture.external_drive_path);
    let _ = std::fs::remove_dir_all(&fixture.desktop_dir);
    let _ = std::fs::remove_dir_all(&fixture.documents_dir);
    let cleanup_satisfied = !fixture.backup_root.exists()
        && !fixture.external_drive_path.exists()
        && !fixture.desktop_dir.exists()
        && !fixture.documents_dir.exists();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_documents_summary_fixture_runtime(
    run_unique_num: &str,
) -> Result<DocumentsSummaryFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let documents_dir = home_dir.join("Documents");
    let fixture_dir = documents_dir.join(format!(
        "{}{}",
        DOCUMENTS_SUMMARY_FIXTURE_DIR_PREFIX, run_unique_num
    ));
    std::fs::create_dir_all(&fixture_dir)?;

    let brief_path = fixture_dir.join(DOCUMENTS_SUMMARY_EXPECTED_FILE_NAMES[0]);
    let notes_path = fixture_dir.join(DOCUMENTS_SUMMARY_EXPECTED_FILE_NAMES[1]);
    let latest_path = fixture_dir.join(DOCUMENTS_SUMMARY_EXPECTED_FILE_NAMES[2]);

    std::fs::write(
        &brief_path,
        concat!(
            "Project brief\n",
            "Owner: Platform Ops\n",
            "Status: Planning\n",
        ),
    )?;
    std::thread::sleep(Duration::from_millis(1_100));
    std::fs::write(
        &notes_path,
        concat!(
            "Meeting notes\n",
            "Topic: ingestion backlog\n",
            "Action: investigate worker token expiry policy\n",
        ),
    )?;
    std::thread::sleep(Duration::from_millis(1_100));
    std::fs::write(
        &latest_path,
        concat!(
            "Incident update\n",
            "Root cause: expired API token on ingestion worker.\n",
            "Mitigation: rotated the token and restarted the worker.\n",
            "Next step: add a 30-day token expiry alert.\n",
        ),
    )?;

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());

    Ok(DocumentsSummaryFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        home_dir,
        documents_dir,
        fixture_dir,
        latest_document_path: latest_path,
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

fn documents_summary_fixture_preflight_checks(
    fixture: &DocumentsSummaryFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let seeded_files = list_directory_entry_names(&fixture.fixture_dir);
    let seeded_files_satisfied = DOCUMENTS_SUMMARY_EXPECTED_FILE_NAMES
        .iter()
        .all(|expected| seeded_files.iter().any(|observed| observed == expected));
    let run_unique_satisfied = fixture
        .fixture_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let fixture_satisfied = seeded_files_satisfied && run_unique_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "documents_summary_fixture_mode",
        DOCUMENTS_SUMMARY_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_documents_dir",
        fixture.documents_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_fixture_dir",
        fixture.fixture_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_expected_latest_path",
        fixture.latest_document_path.to_string_lossy().to_string(),
    );
    push_environment_receipt(
        &mut batch,
        "documents_summary_seeded_files",
        seeded_files.join(","),
        None,
        None,
        Some(seeded_files_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "documents_summary_run_unique",
        Some(DOCUMENTS_SUMMARY_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "documents_summary_fixture",
        Some(DOCUMENTS_SUMMARY_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn documents_summary_fixture_post_run_checks(
    fixture: &DocumentsSummaryFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", DOCUMENTS_SUMMARY_FIXTURE_PROBE_SOURCE);
    let observed_files = list_directory_entry_names(&fixture.fixture_dir);
    let observed_files_satisfied = DOCUMENTS_SUMMARY_EXPECTED_FILE_NAMES
        .iter()
        .all(|expected| observed_files.iter().any(|observed| observed == expected));
    let latest_observed = latest_file_path_and_mtime(&fixture.fixture_dir);
    let latest_observed_path = latest_observed
        .as_ref()
        .map(|(path, _)| path.to_string_lossy().to_string())
        .unwrap_or_default();
    let latest_observed_mtime_ms = latest_observed
        .as_ref()
        .map(|(_, mtime_ms)| *mtime_ms)
        .unwrap_or(0);
    let latest_expected_path = fixture.latest_document_path.to_string_lossy().to_string();
    let latest_path_satisfied = latest_observed
        .as_ref()
        .map(|(path, _)| path == &fixture.latest_document_path)
        .unwrap_or(false);
    let latest_content = std::fs::read_to_string(&fixture.latest_document_path).unwrap_or_default();
    let latest_content_lower = latest_content.to_ascii_lowercase();
    let latest_content_satisfied = DOCUMENTS_SUMMARY_EXPECTED_LATEST_MARKERS
        .iter()
        .all(|marker| latest_content_lower.contains(marker));
    let latest_content_probe_source = format!("{}.content_probe", probe_source);
    let latest_expected_mtime_ms =
        file_modified_epoch_ms(&fixture.latest_document_path).unwrap_or(0);
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "documents_summary_observed_files",
        observed_files.join(","),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(observed_files_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "documents_summary_latest_observed_path",
        latest_observed_path,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(latest_path_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_latest_observed_modified_epoch_ms",
        latest_observed_mtime_ms.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_latest_expected_modified_epoch_ms",
        latest_expected_mtime_ms.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_latest_expected_path",
        latest_expected_path,
    );
    push_environment_receipt(
        &mut batch,
        "documents_summary_latest_content_excerpt",
        truncate_for_log(&latest_content, 240),
        Some(latest_content_probe_source),
        Some(timestamp_ms),
        Some(latest_content_satisfied),
    );
    batch
}

fn documents_summary_fixture_cleanup_checks(
    fixture: &DocumentsSummaryFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", DOCUMENTS_SUMMARY_FIXTURE_PROBE_SOURCE);
    let _ = std::fs::remove_dir_all(&fixture.fixture_dir);
    let fixture_dir_exists_after_cleanup = fixture.fixture_dir.exists();
    let documents_dir_entries = list_directory_entry_names(&fixture.documents_dir);
    let cleanup_satisfied = !fixture_dir_exists_after_cleanup && documents_dir_entries.is_empty();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "documents_summary_cleanup_fixture_dir_exists",
        fixture_dir_exists_after_cleanup.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_cleanup_documents_dir_entries",
        documents_dir_entries.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "documents_summary_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
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

fn bootstrap_pdf_last_week_fixture_runtime(
    run_unique_num: &str,
) -> Result<PdfLastWeekFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let documents_dir = home_dir.join("Documents");
    let fixture_dir = documents_dir.join(format!(
        "{}{}",
        PDF_LAST_WEEK_FIXTURE_DIR_PREFIX, run_unique_num
    ));
    std::fs::create_dir_all(&fixture_dir)?;

    let weekly_status = fixture_dir.join(PDF_LAST_WEEK_EXPECTED_PDF_FILES[0]);
    let incident_report = fixture_dir.join(PDF_LAST_WEEK_EXPECTED_PDF_FILES[1]);
    let notes = fixture_dir.join(PDF_LAST_WEEK_SUPPORTING_FILE);
    std::fs::write(
        &weekly_status,
        concat!(
            "Weekly status packet\n",
            "PDF fixture content for deterministic capabilities testing.\n",
        ),
    )?;
    std::thread::sleep(Duration::from_millis(1_100));
    std::fs::write(
        &incident_report,
        concat!(
            "Incident report packet\n",
            "PDF fixture content for deterministic capabilities testing.\n",
        ),
    )?;
    std::thread::sleep(Duration::from_millis(1_100));
    std::fs::write(
        &notes,
        concat!(
            "Supporting notes\n",
            "This file is intentionally non-PDF and must not appear in results.\n",
        ),
    )?;

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());
    let now_epoch_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let seven_days_ms = 7 * 24 * 60 * 60 * 1_000;

    Ok(PdfLastWeekFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        home_dir,
        documents_dir,
        fixture_dir,
        expected_pdf_paths: vec![incident_report, weekly_status],
        window_start_epoch_ms: now_epoch_ms.saturating_sub(seven_days_ms),
    })
}

fn pdf_last_week_fixture_preflight_checks(
    fixture: &PdfLastWeekFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let seeded_files = list_directory_entry_names(&fixture.fixture_dir);
    let expected_seeded_files_present = PDF_LAST_WEEK_EXPECTED_PDF_FILES
        .iter()
        .all(|expected| seeded_files.iter().any(|observed| observed == expected))
        && seeded_files
            .iter()
            .any(|observed| observed.eq_ignore_ascii_case(PDF_LAST_WEEK_SUPPORTING_FILE));
    let expected_pdf_paths_satisfied = fixture.expected_pdf_paths.iter().all(|path| path.is_file());
    let run_unique_satisfied = fixture
        .fixture_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let fixture_satisfied =
        expected_seeded_files_present && expected_pdf_paths_satisfied && run_unique_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(&mut batch, "pdf_last_week_fixture_mode", PDF_LAST_WEEK_FIXTURE_MODE);
    push_environment_observation(
        &mut batch,
        "pdf_last_week_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_documents_dir",
        fixture.documents_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_fixture_dir",
        fixture.fixture_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_receipt(
        &mut batch,
        "pdf_last_week_expected_paths",
        join_paths_csv(&fixture.expected_pdf_paths),
        None,
        None,
        Some(expected_pdf_paths_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_expected_count",
        fixture.expected_pdf_paths.len().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_expected_window_start_epoch_ms",
        fixture.window_start_epoch_ms.to_string(),
    );
    push_environment_receipt(
        &mut batch,
        "pdf_last_week_seeded_files",
        seeded_files.join(","),
        None,
        None,
        Some(expected_seeded_files_present),
    );
    push_environment_metadata(
        &mut batch,
        "pdf_last_week_run_unique",
        Some(PDF_LAST_WEEK_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "pdf_last_week_fixture",
        Some(PDF_LAST_WEEK_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn pdf_last_week_fixture_post_run_checks(
    fixture: &PdfLastWeekFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", PDF_LAST_WEEK_FIXTURE_PROBE_SOURCE);
    let observed_files = list_directory_entry_names(&fixture.fixture_dir);
    let observed_pdf_paths = list_pdf_file_paths(&fixture.fixture_dir);
    let observed_pdf_paths_csv = join_paths_csv(&observed_pdf_paths);
    let expected_pdf_paths_csv = join_paths_csv(&fixture.expected_pdf_paths);
    let observed_files_satisfied = PDF_LAST_WEEK_EXPECTED_PDF_FILES
        .iter()
        .all(|expected| observed_files.iter().any(|observed| observed == expected))
        && observed_files
            .iter()
            .any(|observed| observed.eq_ignore_ascii_case(PDF_LAST_WEEK_SUPPORTING_FILE));
    let expected_pdf_paths_satisfied = observed_pdf_paths == fixture.expected_pdf_paths;
    let observed_within_window_count = observed_pdf_paths
        .iter()
        .filter_map(|path| file_modified_epoch_ms(path))
        .filter(|mtime_ms| *mtime_ms >= fixture.window_start_epoch_ms)
        .count();
    let observed_within_window_satisfied =
        observed_within_window_count == fixture.expected_pdf_paths.len();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "pdf_last_week_observed_files",
        observed_files.join(","),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(observed_files_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_expected_paths",
        expected_pdf_paths_csv,
    );
    push_environment_receipt(
        &mut batch,
        "pdf_last_week_observed_pdf_paths",
        observed_pdf_paths_csv,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(expected_pdf_paths_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_observed_window_start_epoch_ms",
        fixture.window_start_epoch_ms.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "pdf_last_week_observed_window_start",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(true),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_observed_within_window_count",
        observed_within_window_count.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "pdf_last_week_observed_within_window",
        Some(probe_source),
        Some(timestamp_ms),
        Some(observed_within_window_satisfied),
    );
    batch
}

fn pdf_last_week_fixture_cleanup_checks(
    fixture: &PdfLastWeekFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", PDF_LAST_WEEK_FIXTURE_PROBE_SOURCE);
    let _ = std::fs::remove_dir_all(&fixture.fixture_dir);
    let fixture_dir_exists_after_cleanup = fixture.fixture_dir.exists();
    let documents_dir_entries = list_directory_entry_names(&fixture.documents_dir);
    let cleanup_satisfied = !fixture_dir_exists_after_cleanup && documents_dir_entries.is_empty();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "pdf_last_week_cleanup_fixture_dir_exists",
        fixture_dir_exists_after_cleanup.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_cleanup_documents_dir_entries",
        documents_dir_entries.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "pdf_last_week_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_spotify_uninstall_fixture_runtime(
    run_unique_num: &str,
) -> Result<SpotifyUninstallFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let fixture_root = temp_dir
        .path()
        .join(format!("spotify_uninstall_{}", run_unique_num));
    let fixture_bin = temp_dir.path().join("bin");
    let install_state_dir = fixture_root.join("install_state");
    let receipts_dir = fixture_root.join("receipts");
    let local_bin_dir = home_dir.join(".local").join("bin");

    std::fs::create_dir_all(&fixture_bin)?;
    std::fs::create_dir_all(&install_state_dir)?;
    std::fs::create_dir_all(&receipts_dir)?;
    std::fs::create_dir_all(&local_bin_dir)?;

    let config_paths = SPOTIFY_UNINSTALL_CONFIG_RELATIVE_PATHS
        .iter()
        .map(|relative| home_dir.join(relative))
        .collect::<Vec<_>>();
    for path in &config_paths {
        std::fs::create_dir_all(path)?;
        std::fs::write(
            path.join("prefs.json"),
            format!("fixture config payload for {}", path.to_string_lossy()),
        )?;
    }

    let sentinel_paths = vec![
        home_dir
            .join(".config")
            .join(SPOTIFY_UNINSTALL_SENTINEL_FILE_NAME),
        home_dir
            .join(".cache")
            .join(SPOTIFY_UNINSTALL_SENTINEL_FILE_NAME),
        home_dir
            .join(".local")
            .join("share")
            .join(SPOTIFY_UNINSTALL_SENTINEL_FILE_NAME),
    ];
    for path in &sentinel_paths {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, "fixture sentinel must persist\n")?;
    }

    let install_marker_path = install_state_dir.join("spotify.installed");
    std::fs::write(&install_marker_path, "spotify\n")?;
    let binary_path = local_bin_dir.join("spotify");
    write_executable_script(
        &binary_path,
        "#!/usr/bin/env bash\nset -euo pipefail\necho \"Spotify fixture binary\"\n",
    )?;

    let provider_receipt_path = receipts_dir.join("provider.txt");
    let _ = std::fs::remove_file(&provider_receipt_path);

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

    let provider_script = r#"#!/usr/bin/env bash
set -euo pipefail
provider="${1:-}"
if [ -z "$provider" ]; then
  echo "spotify fixture provider: missing provider id" >&2
  exit 2
fi
shift || true

command_name="${1:-}"
if [ -z "$command_name" ]; then
  echo "spotify fixture provider: missing provider command" >&2
  exit 2
fi
shift || true

is_uninstall=0
case "$provider" in
  apt-get)
    case "$command_name" in
      update|--version|-v|help)
        echo "Hit:1 http://fixture.example stable InRelease"
        echo "Reading package lists... Done"
        exit 0
        ;;
      remove|purge|autoremove|uninstall)
        is_uninstall=1
        ;;
      *)
        echo "spotify fixture apt-get: unsupported command '$command_name'" >&2
        exit 2
        ;;
    esac
    ;;
  snap)
    case "$command_name" in
      --version|version|list|find|info)
        echo "snap    2.0-fixture"
        exit 0
        ;;
      remove|uninstall)
        is_uninstall=1
        ;;
      *)
        echo "spotify fixture snap: unsupported command '$command_name'" >&2
        exit 2
        ;;
    esac
    ;;
  flatpak)
    case "$command_name" in
      --version|--installations|list|info|remotes|search)
        echo "flatpak fixture discovery ok"
        exit 0
        ;;
      uninstall|remove)
        is_uninstall=1
        ;;
      *)
        echo "spotify fixture flatpak: unsupported command '$command_name'" >&2
        exit 2
        ;;
    esac
    ;;
  brew)
    case "$command_name" in
      --version|list|info|search)
        echo "Homebrew 4.0-fixture"
        exit 0
        ;;
      uninstall|remove)
        is_uninstall=1
        ;;
      *)
        echo "spotify fixture brew: unsupported command '$command_name'" >&2
        exit 2
        ;;
    esac
    ;;
  pacman)
    case "$command_name" in
      -V|-Q|-Qi|-Ss)
        echo "pacman fixture discovery ok"
        exit 0
        ;;
      -R|-Rs|-Rns|-Rnsc|--remove)
        is_uninstall=1
        ;;
      *)
        echo "spotify fixture pacman: unsupported command '$command_name'" >&2
        exit 2
        ;;
    esac
    ;;
  *)
    echo "spotify fixture provider: unsupported provider '$provider'" >&2
    exit 2
    ;;
esac

if [ "$is_uninstall" -ne 1 ]; then
  exit 0
fi

spotify_match=0
for arg in "$@"; do
  case "$arg" in
    -*) ;;
    spotify|spotify:*|spotify-client*|com.spotify.Client|com.spotify.Client//stable)
      spotify_match=1
      ;;
  esac
done
if [ "$spotify_match" -ne 1 ]; then
  echo "spotify fixture provider: spotify package id missing" >&2
  exit 100
fi

install_marker="${IOI_SPOTIFY_INSTALL_MARKER:-}"
binary_path="${IOI_SPOTIFY_BINARY_PATH:-}"
provider_receipt="${IOI_SPOTIFY_PROVIDER_RECEIPT:-}"
if [ -z "$install_marker" ] || [ -z "$provider_receipt" ]; then
  echo "spotify fixture provider: required env vars are missing" >&2
  exit 2
fi

rm -f "$install_marker"
if [ -n "$binary_path" ]; then
  rm -f "$binary_path"
fi
mkdir -p "$(dirname "$provider_receipt")"
printf '%s\n' "$provider" > "$provider_receipt"
echo "spotify fixture: removed spotify via provider '$provider'"
"#;
    write_executable_script(
        &fixture_bin.join("spotify_fixture_provider"),
        provider_script,
    )?;

    write_executable_script(
        &fixture_bin.join("apt-get"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec spotify_fixture_provider apt-get \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("apt"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec apt-get \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("snap"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec spotify_fixture_provider snap \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("flatpak"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec spotify_fixture_provider flatpak \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("brew"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec spotify_fixture_provider brew \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("pacman"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec spotify_fixture_provider pacman \"$@\"\n",
    )?;

    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let fixture_path = format!(
        "{}:{}:{}",
        fixture_bin.to_string_lossy(),
        local_bin_dir.to_string_lossy(),
        inherited_path
    );
    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());
    let env_path = ScopedEnvVar::set("PATH", fixture_path);
    let env_fixture_root = ScopedEnvVar::set(
        "IOI_SPOTIFY_FIXTURE_ROOT",
        fixture_root.to_string_lossy().to_string(),
    );
    let env_fixture_mode =
        ScopedEnvVar::set("IOI_SPOTIFY_FIXTURE_MODE", SPOTIFY_UNINSTALL_FIXTURE_MODE);
    let env_install_marker = ScopedEnvVar::set(
        "IOI_SPOTIFY_INSTALL_MARKER",
        install_marker_path.to_string_lossy().to_string(),
    );
    let env_binary_path = ScopedEnvVar::set(
        "IOI_SPOTIFY_BINARY_PATH",
        binary_path.to_string_lossy().to_string(),
    );
    let env_provider_receipt = ScopedEnvVar::set(
        "IOI_SPOTIFY_PROVIDER_RECEIPT",
        provider_receipt_path.to_string_lossy().to_string(),
    );

    Ok(SpotifyUninstallFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        _env_path: env_path,
        _env_fixture_root: env_fixture_root,
        _env_fixture_mode: env_fixture_mode,
        _env_install_marker: env_install_marker,
        _env_binary_path: env_binary_path,
        _env_provider_receipt: env_provider_receipt,
        home_dir,
        fixture_root,
        provider_receipt_path,
        install_marker_path,
        binary_path,
        config_paths,
        sentinel_paths,
    })
}

fn spotify_uninstall_fixture_preflight_checks(
    fixture: &SpotifyUninstallFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let config_paths_seeded = fixture.config_paths.iter().all(|path| path.is_dir());
    let sentinel_paths_seeded = fixture.sentinel_paths.iter().all(|path| path.is_file());
    let install_marker_seeded = fixture.install_marker_path.is_file();
    let binary_seeded = fixture.binary_path.is_file();
    let provider_receipt_absent = !fixture.provider_receipt_path.exists();
    let run_unique_satisfied = fixture
        .fixture_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let fixture_satisfied = config_paths_seeded
        && sentinel_paths_seeded
        && install_marker_seeded
        && binary_seeded
        && provider_receipt_absent
        && run_unique_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_fixture_mode",
        SPOTIFY_UNINSTALL_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_fixture_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_fixture_root",
        fixture.fixture_root.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_provider_candidates",
        SPOTIFY_UNINSTALL_PROVIDER_IDS.join(","),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_provider_receipt_path",
        fixture.provider_receipt_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_install_marker_path",
        fixture.install_marker_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_binary_path",
        fixture.binary_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_config_paths",
        join_paths_csv(&fixture.config_paths),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_sentinel_paths",
        join_paths_csv(&fixture.sentinel_paths),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_config_paths_seeded",
        Some(SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(config_paths_seeded),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_sentinel_paths_seeded",
        Some(SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(sentinel_paths_seeded),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_install_marker_seeded",
        Some(SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(install_marker_seeded),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_binary_seeded",
        Some(SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(binary_seeded),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_provider_receipt_absent",
        Some(SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(provider_receipt_absent),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_run_unique",
        Some(SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_fixture",
        Some(SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn spotify_uninstall_fixture_post_run_checks(
    fixture: &SpotifyUninstallFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE);

    let provider_selected = std::fs::read_to_string(&fixture.provider_receipt_path)
        .unwrap_or_default()
        .trim()
        .to_string();
    let provider_satisfied = SPOTIFY_UNINSTALL_PROVIDER_IDS
        .iter()
        .any(|provider| provider_selected.eq_ignore_ascii_case(provider));
    let install_marker_removed = !fixture.install_marker_path.exists();
    let binary_absent = !fixture.binary_path.exists();
    let config_paths_removed = fixture.config_paths.iter().all(|path| !path.exists());
    let sentinel_paths_preserved = fixture.sentinel_paths.iter().all(|path| path.is_file());
    let scope_satisfied = sentinel_paths_preserved;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "spotify_uninstall_provider",
        provider_selected,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(provider_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_install_marker_path",
        fixture.install_marker_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_install_marker_removed",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(install_marker_removed),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_binary_path",
        fixture.binary_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_binary_absent",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(binary_absent),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_config_paths",
        join_paths_csv(&fixture.config_paths),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_config_paths_removed",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(config_paths_removed),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_sentinel_paths",
        join_paths_csv(&fixture.sentinel_paths),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn spotify_uninstall_fixture_cleanup_checks(
    fixture: &SpotifyUninstallFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE);

    let _ = std::fs::remove_file(&fixture.provider_receipt_path);
    let _ = std::fs::remove_dir_all(&fixture.home_dir);
    let _ = std::fs::create_dir_all(&fixture.home_dir);
    let _ = std::fs::remove_dir_all(&fixture.fixture_root);
    let _ = std::fs::create_dir_all(&fixture.fixture_root);
    let home_entries = list_directory_entry_names(&fixture.home_dir);
    let fixture_root_entries = list_directory_entry_names(&fixture.fixture_root);
    let cleanup_satisfied = home_entries.is_empty() && fixture_root_entries.is_empty();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_cleanup_home_entries",
        home_entries.join(","),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_cleanup_fixture_root_entries",
        fixture_root_entries.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_top_memory_apps_fixture_runtime(
    run_unique_num: &str,
) -> Result<TopMemoryAppsFixtureRuntime> {
    let temp_dir = tempdir()?;
    let fixture_root = temp_dir
        .path()
        .join(format!("top_memory_apps_{}", run_unique_num));
    let fixture_bin = fixture_root.join("bin");
    let fixture_receipts = fixture_root.join("receipts");
    std::fs::create_dir_all(&fixture_bin)?;
    std::fs::create_dir_all(&fixture_receipts)?;

    let probe_script_path = fixture_bin.join(TOP_MEMORY_APPS_PROBE_SCRIPT_NAME);
    let receipt_path = fixture_receipts.join("latest_probe_receipt.txt");
    let _ = std::fs::remove_file(&receipt_path);

    let probe_script = r#"#!/usr/bin/env bash
set -euo pipefail

top_n="${1:-5}"
if ! [[ "$top_n" =~ ^[0-9]+$ ]] || [ "$top_n" -lt 1 ]; then
  echo "invalid top_n argument; expected positive integer" >&2
  exit 2
fi

for required in ps sort head awk; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "missing required provider binary: $required" >&2
    exit 3
  fi
done

receipt_path="${IOI_TOP_MEMORY_APPS_RECEIPT_PATH:-}"
if [ -z "$receipt_path" ]; then
  echo "missing IOI_TOP_MEMORY_APPS_RECEIPT_PATH" >&2
  exit 4
fi

rows="$(
  ps -eo pid=,comm=,rss= 2>/dev/null \
    | awk '
      {
        pid=$1; app=$2; rss=$3;
        if (pid ~ /^[0-9]+$/ && rss ~ /^[0-9]+$/ && app != "") {
          print rss "\t" app "\t" pid;
        }
      }
    ' \
    | sort -t$'\t' -k1,1nr \
    | head -n "$top_n"
)"

if [ -z "$rows" ]; then
  echo "no process rows were produced by ps provider" >&2
  exit 5
fi

mkdir -p "$(dirname "$receipt_path")"
{
  echo "provider=ps"
  rank=1
  while IFS=$'\t' read -r rss app pid; do
    if [ -z "${rss:-}" ] || [ -z "${app:-}" ] || [ -z "${pid:-}" ]; then
      continue
    fi
    echo "row|${rank}|${app}|${pid}|${rss}"
    rank=$((rank + 1))
  done <<< "$rows"
} > "$receipt_path"

cat "$receipt_path"
"#;
    write_executable_script(&probe_script_path, probe_script)?;

    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let fixture_path = format!("{}:{}", fixture_bin.to_string_lossy(), inherited_path);
    let env_path = ScopedEnvVar::set("PATH", fixture_path);
    let env_fixture_mode = ScopedEnvVar::set(
        "IOI_TOP_MEMORY_APPS_FIXTURE_MODE",
        TOP_MEMORY_APPS_FIXTURE_MODE,
    );
    let env_receipt_path = ScopedEnvVar::set(
        "IOI_TOP_MEMORY_APPS_RECEIPT_PATH",
        receipt_path.to_string_lossy().to_string(),
    );

    Ok(TopMemoryAppsFixtureRuntime {
        _temp_dir: temp_dir,
        _env_path: env_path,
        _env_fixture_mode: env_fixture_mode,
        _env_receipt_path: env_receipt_path,
        fixture_root,
        probe_script_path,
        receipt_path,
    })
}

fn top_memory_apps_fixture_preflight_checks(
    fixture: &TopMemoryAppsFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let run_unique_satisfied = fixture
        .fixture_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let probe_script_seeded_satisfied = fixture.probe_script_path.is_file();
    let receipt_absent_satisfied = !fixture.receipt_path.exists();
    let fixture_satisfied =
        run_unique_satisfied && probe_script_seeded_satisfied && receipt_absent_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "top_memory_apps_fixture_mode",
        TOP_MEMORY_APPS_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "top_memory_apps_fixture_root",
        fixture.fixture_root.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "top_memory_apps_probe_script_path",
        fixture.probe_script_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "top_memory_apps_receipt_path",
        fixture.receipt_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "top_memory_apps_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_run_unique",
        Some(TOP_MEMORY_APPS_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_probe_script_seeded",
        Some(TOP_MEMORY_APPS_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(probe_script_seeded_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_receipt_absent",
        Some(TOP_MEMORY_APPS_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(receipt_absent_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_fixture",
        Some(TOP_MEMORY_APPS_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn parse_top_memory_apps_probe_receipt(path: &Path) -> TopMemoryAppsProbeReceipt {
    let mut receipt = TopMemoryAppsProbeReceipt::default();
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(provider) = trimmed.strip_prefix("provider=") {
            receipt.provider = provider.trim().to_string();
            continue;
        }
        if let Some(payload) = trimmed.strip_prefix("row|") {
            let mut parts = payload.split('|').map(str::trim);
            let rank = parts.next().and_then(|value| value.parse::<usize>().ok());
            let app = parts.next().map(str::to_string);
            let pid = parts.next().and_then(|value| value.parse::<u32>().ok());
            let rss_kb = parts.next().and_then(|value| value.parse::<u64>().ok());
            if let (Some(rank), Some(app), Some(pid), Some(rss_kb)) = (rank, app, pid, rss_kb) {
                if !app.is_empty() && pid > 0 && rss_kb > 0 {
                    receipt.rows.push(TopMemoryAppProbeRow {
                        rank,
                        app,
                        pid,
                        rss_kb,
                    });
                }
            }
        }
    }
    receipt.rows.sort_by_key(|row| row.rank);
    receipt
}

fn top_memory_apps_rows_sorted_desc(rows: &[TopMemoryAppProbeRow]) -> bool {
    if rows.len() < 3 {
        return false;
    }

    let mut previous_rss: Option<u64> = None;
    for (index, row) in rows.iter().enumerate() {
        if row.rank != index + 1 || row.app.trim().is_empty() || row.pid == 0 || row.rss_kb == 0 {
            return false;
        }
        if let Some(previous) = previous_rss {
            if row.rss_kb > previous {
                return false;
            }
        }
        previous_rss = Some(row.rss_kb);
    }
    true
}

fn top_memory_apps_fixture_post_run_checks(
    fixture: &TopMemoryAppsFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.receipt_probe", TOP_MEMORY_APPS_FIXTURE_PROBE_SOURCE);
    let receipt_present_satisfied = fixture.receipt_path.is_file();
    let receipt = if receipt_present_satisfied {
        parse_top_memory_apps_probe_receipt(&fixture.receipt_path)
    } else {
        TopMemoryAppsProbeReceipt::default()
    };
    let provider_satisfied = receipt.provider.eq_ignore_ascii_case("ps");
    let row_count = receipt.rows.len();
    let row_count_satisfied = row_count >= 3;
    let rows_sorted_desc_satisfied = top_memory_apps_rows_sorted_desc(&receipt.rows);
    let scope_satisfied = provider_satisfied && row_count_satisfied && rows_sorted_desc_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "top_memory_apps_provider",
        receipt.provider,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(provider_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "top_memory_apps_row_count",
        row_count.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(row_count_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_rows_sorted_desc",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(rows_sorted_desc_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "top_memory_apps_receipt_path",
        fixture.receipt_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_receipt",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(receipt_present_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    for row in receipt.rows {
        push_environment_observation(
            &mut batch,
            "top_memory_apps_row",
            format!("{}|{}|{}|{}", row.rank, row.app, row.pid, row.rss_kb),
        );
    }
    batch
}

fn top_memory_apps_fixture_cleanup_checks(
    fixture: &TopMemoryAppsFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", TOP_MEMORY_APPS_FIXTURE_PROBE_SOURCE);
    let _ = std::fs::remove_file(&fixture.receipt_path);
    let _ = std::fs::remove_dir_all(&fixture.fixture_root);
    let fixture_root_exists_after_cleanup = fixture.fixture_root.exists();
    let receipt_exists_after_cleanup = fixture.receipt_path.exists();
    let cleanup_satisfied = !fixture_root_exists_after_cleanup && !receipt_exists_after_cleanup;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "top_memory_apps_cleanup_fixture_root_exists",
        fixture_root_exists_after_cleanup.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "top_memory_apps_cleanup_receipt_exists",
        receipt_exists_after_cleanup.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_shutdown_schedule_fixture_runtime(
    run_unique_num: &str,
) -> Result<ShutdownScheduleFixtureRuntime> {
    let temp_dir = tempdir()?;
    let fixture_root = temp_dir
        .path()
        .join(format!("shutdown_schedule_{}", run_unique_num));
    let fixture_bin = fixture_root.join("bin");
    let fixture_receipts = fixture_root.join("receipts");
    std::fs::create_dir_all(&fixture_bin)?;
    std::fs::create_dir_all(&fixture_receipts)?;

    let probe_script_path = fixture_bin.join(SHUTDOWN_SCHEDULE_PROBE_SCRIPT_NAME);
    let receipt_path = fixture_receipts.join("shutdown_schedule_receipt.txt");
    let provider_receipt_path = fixture_receipts.join("shutdown_provider_receipt.txt");
    let _ = std::fs::remove_file(&receipt_path);
    let _ = std::fs::remove_file(&provider_receipt_path);

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

    let provider_script = r#"#!/usr/bin/env bash
set -euo pipefail

provider="${1:-}"
if [ -z "$provider" ]; then
  echo "shutdown schedule fixture: missing provider id" >&2
  exit 2
fi
shift || true

provider_receipt_path="${IOI_SHUTDOWN_SCHEDULE_PROVIDER_RECEIPT_PATH:-}"
if [ -z "$provider_receipt_path" ]; then
  echo "shutdown schedule fixture: IOI_SHUTDOWN_SCHEDULE_PROVIDER_RECEIPT_PATH missing" >&2
  exit 3
fi

mkdir -p "$(dirname "$provider_receipt_path")"
{
  echo "provider=${provider}"
  echo "provider_invoked=true"
  echo "provider_args=$*"
} > "$provider_receipt_path"

case "$provider" in
  shutdown|systemctl|at)
    exit 0
    ;;
  *)
    echo "shutdown schedule fixture: unsupported provider '$provider'" >&2
    exit 2
    ;;
esac
"#;
    write_executable_script(
        &fixture_bin.join("shutdown_fixture_provider"),
        provider_script,
    )?;

    write_executable_script(
        &fixture_bin.join("shutdown"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec shutdown_fixture_provider shutdown \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("systemctl"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec shutdown_fixture_provider systemctl \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("at"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec shutdown_fixture_provider at \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("poweroff"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec shutdown_fixture_provider shutdown poweroff \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("halt"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec shutdown_fixture_provider shutdown halt \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("reboot"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec shutdown_fixture_provider shutdown reboot \"$@\"\n",
    )?;

    let probe_script = r#"#!/usr/bin/env bash
set -euo pipefail

if [ "${1:-}" != "--target-local" ]; then
  echo "expected usage: shutdown_schedule_probe --target-local <HH:MM>" >&2
  exit 2
fi
target_local="${2:-}"
if [ -z "$target_local" ]; then
  echo "missing --target-local value" >&2
  exit 2
fi
if ! [[ "$target_local" =~ ^([0-1][0-9]|2[0-3]):[0-5][0-9]$ ]]; then
  echo "invalid target time format '$target_local'; expected HH:MM" >&2
  exit 2
fi

receipt_path="${IOI_SHUTDOWN_SCHEDULE_RECEIPT_PATH:-}"
run_unique_num="${IOI_SHUTDOWN_SCHEDULE_RUN_UNIQUE_NUM:-}"
if [ -z "$receipt_path" ]; then
  echo "missing IOI_SHUTDOWN_SCHEDULE_RECEIPT_PATH" >&2
  exit 3
fi
if [ -z "$run_unique_num" ]; then
  echo "missing IOI_SHUTDOWN_SCHEDULE_RUN_UNIQUE_NUM" >&2
  exit 3
fi

for required in date shutdown_fixture_provider; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "missing required provider binary: $required" >&2
    exit 4
  fi
done

provider=""
for candidate in shutdown systemctl at; do
  if command -v "$candidate" >/dev/null 2>&1; then
    provider="$candidate"
    break
  fi
done
if [ -z "$provider" ]; then
  echo "no supported shutdown scheduling provider found" >&2
  exit 5
fi

now_epoch="$(date +%s 2>/dev/null || true)"
today_date="$(date +%F 2>/dev/null || true)"
target_today_epoch="$(date -d "${today_date} ${target_local}:00" +%s 2>/dev/null || true)"
if [ -z "$now_epoch" ] || [ -z "$today_date" ] || [ -z "$target_today_epoch" ]; then
  echo "date provider did not return required values" >&2
  exit 6
fi
if ! [[ "$now_epoch" =~ ^-?[0-9]+$ ]] || ! [[ "$target_today_epoch" =~ ^-?[0-9]+$ ]]; then
  echo "date provider returned non-numeric epoch values" >&2
  exit 6
fi

target_epoch="$target_today_epoch"
rollover_to_next_day=false
if [ "$target_epoch" -le "$now_epoch" ]; then
  target_epoch="$((target_today_epoch + 86400))"
  rollover_to_next_day=true
fi
delay_seconds="$((target_epoch - now_epoch))"
if [ "$delay_seconds" -le 0 ]; then
  echo "computed delay_seconds must be positive" >&2
  exit 7
fi
target_local_date="$(date -d "@${target_epoch}" +%F 2>/dev/null || true)"
if [ -z "$target_local_date" ]; then
  echo "failed to compute local target date" >&2
  exit 7
fi

case "$provider" in
  shutdown)
    shutdown -h "$target_local"
    ;;
  systemctl)
    systemctl poweroff "--when=${target_local}"
    ;;
  at)
    at "$target_local" </dev/null
    ;;
  *)
    echo "unsupported provider '$provider'" >&2
    exit 8
    ;;
esac

mkdir -p "$(dirname "$receipt_path")"
{
  echo "provider=${provider}"
  echo "target_local_time=${target_local}"
  echo "target_local_date=${target_local_date}"
  echo "now_epoch_sec=${now_epoch}"
  echo "target_epoch_sec=${target_epoch}"
  echo "delay_seconds=${delay_seconds}"
  echo "rollover_to_next_day=${rollover_to_next_day}"
  echo "run_unique_num=${run_unique_num}"
  echo "scheduled=true"
} > "$receipt_path"

cat "$receipt_path"
"#;
    write_executable_script(&probe_script_path, probe_script)?;

    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let fixture_path = format!("{}:{}", fixture_bin.to_string_lossy(), inherited_path);
    let env_path = ScopedEnvVar::set("PATH", fixture_path);
    let env_fixture_mode = ScopedEnvVar::set(
        "IOI_SHUTDOWN_SCHEDULE_FIXTURE_MODE",
        SHUTDOWN_SCHEDULE_FIXTURE_MODE,
    );
    let env_receipt_path = ScopedEnvVar::set(
        "IOI_SHUTDOWN_SCHEDULE_RECEIPT_PATH",
        receipt_path.to_string_lossy().to_string(),
    );
    let env_provider_receipt_path = ScopedEnvVar::set(
        "IOI_SHUTDOWN_SCHEDULE_PROVIDER_RECEIPT_PATH",
        provider_receipt_path.to_string_lossy().to_string(),
    );
    let env_run_unique_num = ScopedEnvVar::set(
        "IOI_SHUTDOWN_SCHEDULE_RUN_UNIQUE_NUM",
        run_unique_num.to_string(),
    );

    Ok(ShutdownScheduleFixtureRuntime {
        _temp_dir: temp_dir,
        _env_path: env_path,
        _env_fixture_mode: env_fixture_mode,
        _env_receipt_path: env_receipt_path,
        _env_provider_receipt_path: env_provider_receipt_path,
        _env_run_unique_num: env_run_unique_num,
        fixture_root,
        probe_script_path,
        receipt_path,
        provider_receipt_path,
    })
}

fn shutdown_schedule_fixture_preflight_checks(
    fixture: &ShutdownScheduleFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let run_unique_satisfied = fixture
        .fixture_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let probe_script_seeded_satisfied = fixture.probe_script_path.is_file();
    let receipt_absent_satisfied = !fixture.receipt_path.exists();
    let provider_receipt_absent_satisfied = !fixture.provider_receipt_path.exists();
    let fixture_satisfied = run_unique_satisfied
        && probe_script_seeded_satisfied
        && receipt_absent_satisfied
        && provider_receipt_absent_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_fixture_mode",
        SHUTDOWN_SCHEDULE_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_fixture_root",
        fixture.fixture_root.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_probe_script_path",
        fixture.probe_script_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_receipt_path",
        fixture.receipt_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_provider_receipt_path",
        fixture.provider_receipt_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_run_unique",
        Some(SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_probe_script_seeded",
        Some(SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(probe_script_seeded_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_receipt_absent",
        Some(SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(receipt_absent_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_provider_receipt_absent",
        Some(SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(provider_receipt_absent_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_fixture",
        Some(SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn parse_shutdown_schedule_probe_receipt(path: &Path) -> ShutdownScheduleProbeReceipt {
    let mut receipt = ShutdownScheduleProbeReceipt::default();
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
            "target_local_time" => receipt.target_local_time = value.to_string(),
            "target_local_date" => receipt.target_local_date = value.to_string(),
            "now_epoch_sec" => receipt.now_epoch_sec = value.parse::<i64>().unwrap_or_default(),
            "target_epoch_sec" => {
                receipt.target_epoch_sec = value.parse::<i64>().unwrap_or_default()
            }
            "delay_seconds" => receipt.delay_seconds = value.parse::<i64>().unwrap_or_default(),
            "rollover_to_next_day" => {
                receipt.rollover_to_next_day = value.eq_ignore_ascii_case("true")
            }
            "run_unique_num" => receipt.run_unique_num = value.to_string(),
            "scheduled" => receipt.scheduled = value.eq_ignore_ascii_case("true"),
            _ => {}
        }
    }
    receipt
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

fn shutdown_schedule_fixture_post_run_checks(
    fixture: &ShutdownScheduleFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.receipt_probe", SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE);

    let receipt_path_satisfied = fixture.receipt_path.is_file();
    let provider_receipt_path_satisfied = fixture.provider_receipt_path.is_file();
    let receipt = if receipt_path_satisfied {
        parse_shutdown_schedule_probe_receipt(&fixture.receipt_path)
    } else {
        ShutdownScheduleProbeReceipt::default()
    };
    let provider_receipt = if provider_receipt_path_satisfied {
        parse_shutdown_provider_invocation_receipt(&fixture.provider_receipt_path)
    } else {
        ShutdownProviderInvocationReceipt::default()
    };

    let provider_satisfied = SHUTDOWN_SCHEDULE_PROVIDER_IDS
        .iter()
        .any(|provider| receipt.provider.eq_ignore_ascii_case(provider));
    let target_local_time_satisfied =
        receipt.target_local_time == SHUTDOWN_SCHEDULE_TARGET_LOCAL_TIME;
    let target_after_run_satisfied = receipt.target_epoch_sec > 0
        && receipt.now_epoch_sec > 0
        && receipt.target_epoch_sec > receipt.now_epoch_sec;
    let expected_delay = receipt
        .target_epoch_sec
        .saturating_sub(receipt.now_epoch_sec);
    let delay_window_satisfied = target_after_run_satisfied
        && expected_delay == receipt.delay_seconds
        && receipt.delay_seconds > 0
        && receipt.delay_seconds <= 86_400;
    let run_unique_match_satisfied = !receipt.run_unique_num.trim().is_empty()
        && fixture
            .fixture_root
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.ends_with(&receipt.run_unique_num))
            .unwrap_or(false);
    let provider_invoked_satisfied = provider_receipt.provider_invoked
        && provider_receipt
            .provider
            .eq_ignore_ascii_case(&receipt.provider);
    let provider_args_target_satisfied = provider_receipt
        .provider_args
        .contains(SHUTDOWN_SCHEDULE_TARGET_LOCAL_TIME);
    let scheduled_satisfied = receipt.scheduled;
    let scope_satisfied = provider_satisfied
        && target_local_time_satisfied
        && target_after_run_satisfied
        && delay_window_satisfied
        && run_unique_match_satisfied
        && scheduled_satisfied
        && provider_invoked_satisfied
        && provider_args_target_satisfied
        && receipt_path_satisfied
        && provider_receipt_path_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "shutdown_schedule_provider",
        receipt.provider,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(provider_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "shutdown_schedule_target_local_time",
        receipt.target_local_time,
        None,
        None,
        Some(target_local_time_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_target_local_date",
        receipt.target_local_date,
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_now_epoch_sec",
        receipt.now_epoch_sec.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_target_epoch_sec",
        receipt.target_epoch_sec.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_delay_seconds",
        receipt.delay_seconds.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_delay_window",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(delay_window_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_target_after_run",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(target_after_run_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_rollover_to_next_day",
        receipt.rollover_to_next_day.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_run_unique_observed",
        receipt.run_unique_num,
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_run_unique_match",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(run_unique_match_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_scheduled",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(scheduled_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_provider_receipt_provider",
        provider_receipt.provider,
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_provider_args",
        provider_receipt.provider_args,
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_provider_receipt",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(provider_receipt_path_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_provider_invoked",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(provider_invoked_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_provider_args_target",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(provider_args_target_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_receipt_path",
        fixture.receipt_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_provider_receipt_path",
        fixture.provider_receipt_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_receipt_path",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(receipt_path_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_provider_receipt_path",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(provider_receipt_path_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn shutdown_schedule_fixture_cleanup_checks(
    fixture: &ShutdownScheduleFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE);
    let _ = std::fs::remove_file(&fixture.receipt_path);
    let _ = std::fs::remove_file(&fixture.provider_receipt_path);
    let _ = std::fs::remove_dir_all(&fixture.fixture_root);
    let fixture_root_exists_after_cleanup = fixture.fixture_root.exists();
    let receipt_exists_after_cleanup = fixture.receipt_path.exists();
    let provider_receipt_exists_after_cleanup = fixture.provider_receipt_path.exists();
    let cleanup_satisfied = !fixture_root_exists_after_cleanup
        && !receipt_exists_after_cleanup
        && !provider_receipt_exists_after_cleanup;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_cleanup_fixture_root_exists",
        fixture_root_exists_after_cleanup.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_cleanup_receipt_exists",
        receipt_exists_after_cleanup.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_cleanup_provider_receipt_exists",
        provider_receipt_exists_after_cleanup.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_mail_reply_mock_fixture_runtime(
    run_unique_num: &str,
) -> Result<MailReplyMockDriverFixtureRuntime> {
    let temp_dir = tempdir()?;
    let fixture_root = temp_dir
        .path()
        .join(format!("ioi_mail_reply_fixture_{}", run_unique_num));
    std::fs::create_dir_all(&fixture_root)?;
    let manifest_path = fixture_root.join("fixture_manifest.txt");
    std::fs::write(
        &manifest_path,
        format!(
            "mode={}\nrun_unique_num={}\nprovider_driver=mock\n",
            MAIL_REPLY_MOCK_FIXTURE_MODE, run_unique_num
        ),
    )?;

    Ok(MailReplyMockDriverFixtureRuntime {
        _temp_dir: temp_dir,
        fixture_root,
        manifest_path,
    })
}

fn mail_reply_mock_fixture_preflight_checks(
    fixture: &MailReplyMockDriverFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let probe_source = format!("{}.preflight", MAIL_REPLY_MOCK_FIXTURE_PROBE_SOURCE);
    let fixture_root = fixture.fixture_root.to_string_lossy().to_string();
    let run_unique_satisfied = fixture_root.contains(run_unique_num);
    let manifest_seeded_satisfied = fixture.manifest_path.is_file();
    let fixture_satisfied = fixture.fixture_root.is_dir() && run_unique_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "mail_reply_fixture_mode",
        MAIL_REPLY_MOCK_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "mail_reply_fixture_root",
        fixture.fixture_root.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "mail_reply_fixture_manifest_path",
        fixture.manifest_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "mail_reply_fixture_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_observation(&mut batch, "mail_reply_fixture_probe", probe_source);
    push_environment_metadata(
        &mut batch,
        "mail_reply_fixture_run_unique",
        Some(MAIL_REPLY_MOCK_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "mail_reply_fixture_manifest_seeded",
        Some(MAIL_REPLY_MOCK_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(manifest_seeded_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "mail_reply_fixture",
        Some(MAIL_REPLY_MOCK_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn mail_reply_mock_fixture_post_run_checks(
    fixture: &MailReplyMockDriverFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let root_exists_satisfied = fixture.fixture_root.is_dir();
    let manifest_exists_satisfied = fixture.manifest_path.is_file();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_metadata(
        &mut batch,
        "mail_reply_fixture_root_exists",
        None,
        None,
        Some(root_exists_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "mail_reply_fixture_manifest_exists",
        None,
        None,
        Some(manifest_exists_satisfied),
    );
    batch
}

fn mail_reply_mock_fixture_cleanup_checks(
    fixture: &MailReplyMockDriverFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", MAIL_REPLY_MOCK_FIXTURE_PROBE_SOURCE);

    let _ = std::fs::remove_file(&fixture.manifest_path);
    let _ = std::fs::remove_dir_all(&fixture.fixture_root);
    let fixture_root_exists_after_cleanup = fixture.fixture_root.exists();
    let manifest_exists_after_cleanup = fixture.manifest_path.exists();
    let cleanup_satisfied = !fixture_root_exists_after_cleanup && !manifest_exists_after_cleanup;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "mail_reply_fixture_cleanup_root_exists",
        fixture_root_exists_after_cleanup.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "mail_reply_fixture_cleanup_manifest_exists",
        manifest_exists_after_cleanup.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "mail_reply_fixture_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn display_optional_env_value(value: Option<&str>) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "<unset>".to_string())
}

fn restore_optional_env_value(key: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
}

fn bootstrap_restaurants_near_me_fixture_runtime(
    run_unique_num: &str,
) -> Result<RestaurantsNearMeFixtureRuntime> {
    let temp_dir = tempdir()?;
    let fixture_root = temp_dir.path().join(format!(
        "{}{}",
        RESTAURANTS_NEAR_ME_FIXTURE_DIR_PREFIX, run_unique_num
    ));
    std::fs::create_dir_all(&fixture_root)?;
    let manifest_path = fixture_root.join("fixture_manifest.txt");
    let observed_locality = std::env::var(RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    std::fs::write(
        &manifest_path,
        format!(
            "mode={}\nrun_unique_num={}\nlocality_env_key={}\nobserved_locality={}\n",
            RESTAURANTS_NEAR_ME_FIXTURE_MODE,
            run_unique_num,
            RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY,
            display_optional_env_value(observed_locality.as_deref())
        ),
    )?;

    Ok(RestaurantsNearMeFixtureRuntime {
        _temp_dir: temp_dir,
        fixture_root,
        manifest_path,
        observed_locality,
    })
}

fn restaurants_near_me_fixture_preflight_checks(
    fixture: &RestaurantsNearMeFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let probe_source = format!("{}.preflight", RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE);
    let fixture_root = fixture.fixture_root.to_string_lossy().to_string();
    let locality_observed = std::env::var(RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let run_unique_satisfied = fixture_root.contains(run_unique_num);
    let manifest_seeded_satisfied = fixture.manifest_path.is_file();
    let locality_observation_satisfied =
        locality_observed.as_deref() == fixture.observed_locality.as_deref();
    let fixture_satisfied =
        run_unique_satisfied && manifest_seeded_satisfied && locality_observation_satisfied;

    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_fixture_mode",
        RESTAURANTS_NEAR_ME_FIXTURE_MODE,
        Some(RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_fixture_root",
        fixture.fixture_root.to_string_lossy().to_string(),
        Some(RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_fixture_manifest_path",
        fixture.manifest_path.to_string_lossy().to_string(),
        Some(RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(manifest_seeded_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_run_unique_num",
        run_unique_num.to_string(),
        Some(RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_locality_env_key",
        RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY,
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_locality_observed_value",
        display_optional_env_value(locality_observed.as_deref()),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(locality_observation_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_locality_initial_value",
        display_optional_env_value(fixture.observed_locality.as_deref()),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(locality_observation_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_locality",
        display_optional_env_value(locality_observed.as_deref()),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(locality_observation_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_locality_observation",
        locality_observation_satisfied.to_string(),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(locality_observation_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_manifest_seeded",
        manifest_seeded_satisfied.to_string(),
        Some(RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(manifest_seeded_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_fixture",
        fixture_satisfied.to_string(),
        Some(RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn restaurants_near_me_fixture_post_run_checks(
    fixture: &RestaurantsNearMeFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let root_exists_satisfied = fixture.fixture_root.is_dir();
    let manifest_exists_satisfied = fixture.manifest_path.is_file();
    let locality_post_run = std::env::var(RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let locality_unchanged_satisfied = std::env::var(RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .as_deref()
        == fixture.observed_locality.as_deref();
    let scope_satisfied = root_exists_satisfied && manifest_exists_satisfied;

    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.post_run", RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE);
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_fixture_root_exists",
        root_exists_satisfied.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(root_exists_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_manifest_exists",
        manifest_exists_satisfied.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(manifest_exists_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_locality_unchanged_post_run",
        locality_unchanged_satisfied.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(locality_unchanged_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_locality_post_run_value",
        display_optional_env_value(locality_post_run.as_deref()),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(locality_unchanged_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_scope",
        scope_satisfied.to_string(),
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn restaurants_near_me_fixture_cleanup_checks(
    fixture: &RestaurantsNearMeFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE);

    let observed_locality = std::env::var(RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    restore_optional_env_value(
        RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY,
        fixture.observed_locality.as_deref(),
    );
    let restored_locality = std::env::var(RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let locality_unchanged_satisfied =
        restored_locality.as_deref() == fixture.observed_locality.as_deref();

    let _ = std::fs::remove_file(&fixture.manifest_path);
    let _ = std::fs::remove_dir_all(&fixture.fixture_root);
    let fixture_root_exists_after_cleanup = fixture.fixture_root.exists();
    let manifest_exists_after_cleanup = fixture.manifest_path.exists();
    let cleanup_satisfied = !fixture_root_exists_after_cleanup
        && !manifest_exists_after_cleanup
        && locality_unchanged_satisfied;

    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_cleanup_root_exists",
        fixture_root_exists_after_cleanup.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(!fixture_root_exists_after_cleanup),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_cleanup_manifest_exists",
        manifest_exists_after_cleanup.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(!manifest_exists_after_cleanup),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_cleanup_locality_observed_value",
        display_optional_env_value(restored_locality.as_deref()),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(locality_unchanged_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_cleanup_locality_pre_restore_value",
        display_optional_env_value(observed_locality.as_deref()),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_cleanup_locality_unchanged",
        locality_unchanged_satisfied.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(locality_unchanged_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_cleanup",
        cleanup_satisfied.to_string(),
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
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
    provider_driver_override: Option<&str>,
) -> Result<EnvironmentEvidenceBatch> {
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

    let provider_driver = provider_driver_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .or_else(|| config.provider_driver.clone());
    let provider_driver_source = if provider_driver_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
    {
        "fixture_override"
    } else if config.provider_driver.is_some() {
        "env"
    } else {
        "default"
    };
    let mut connector_metadata = BTreeMap::new();
    if let Some(driver) = provider_driver.clone() {
        connector_metadata.insert("driver".to_string(), driver);
    }

    let channel_capability_set = vec![
        "mail.read.latest".to_string(),
        "mail.read".to_string(),
        "email:read".to_string(),
        "mail.list.recent".to_string(),
        "mail.list".to_string(),
        "email:list".to_string(),
        "mail.reply".to_string(),
        "mail.send".to_string(),
        "email:send".to_string(),
        "mail.write".to_string(),
        "email:write".to_string(),
        "mail.compose".to_string(),
        "email:compose".to_string(),
    ];
    let lease_capability_subset = channel_capability_set.clone();
    let mail_send_capability_seeded = channel_capability_set
        .iter()
        .any(|capability| capability == "mail.reply" || capability == "mail.send")
        && lease_capability_subset
            .iter()
            .any(|capability| capability == "mail.reply" || capability == "mail.send");
    let provider_driver_label = provider_driver
        .clone()
        .unwrap_or_else(|| "live".to_string());

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
        capability_set: channel_capability_set.clone(),
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
        capability_subset: lease_capability_subset.clone(),
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

    let probe_source = "harness.mail_runtime_bootstrap".to_string();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "mail_env_file_loaded",
        "true",
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_service_meta_registered",
        "true",
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_connector_bootstrap",
        "true",
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_channel_seeded",
        "true",
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_lease_seeded",
        "true",
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_send_capability_seeded",
        mail_send_capability_seeded.to_string(),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(mail_send_capability_seeded),
    );
    push_environment_receipt(
        &mut batch,
        "mail_channel_capabilities",
        channel_capability_set.join(","),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_lease_capabilities",
        lease_capability_subset.join(","),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_provider_driver",
        provider_driver_label,
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_provider_driver_source",
        provider_driver_source,
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_auth_mode",
        auth_mode_label,
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_mailbox",
        config.mailbox,
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_setup_timestamp_ms",
        run_timestamp_ms.to_string(),
        Some(probe_source),
        Some(run_timestamp_ms),
        Some(true),
    );
    Ok(batch)
}

fn bootstrap_optional_fixture<T, B, P>(
    enabled: bool,
    bootstrap: B,
    preflight: P,
    setup_checks: &mut Vec<String>,
    setup_receipts: &mut Vec<EnvironmentReceiptObservation>,
) -> Result<Option<T>>
where
    B: FnOnce() -> Result<T>,
    P: FnOnce(&T) -> EnvironmentEvidenceBatch,
{
    if !enabled {
        return Ok(None);
    }
    let fixture = bootstrap()?;
    extend_environment_evidence_batch(setup_checks, setup_receipts, preflight(&fixture));
    Ok(Some(fixture))
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
    environment_receipts.extend(post_run_batch.receipts);
    for check in post_run_batch.checks {
        verification_checks.insert(check);
    }
    if let Some(cleanup_fn) = cleanup {
        let cleanup_batch = cleanup_fn(fixture);
        environment_receipts.extend(cleanup_batch.receipts);
        for check in cleanup_batch.checks {
            verification_checks.insert(check);
        }
    }
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
    let run_unique_num = run_unique_num(run_index, run_timestamp_ms);
    let mut run_query = render_query_for_run(case.query, run_index, run_timestamp_ms);
    let mut runtime_setup_verification_checks = Vec::<String>::new();
    let mut runtime_setup_environment_receipts = Vec::<EnvironmentReceiptObservation>::new();
    let vlc_install_fixture = bootstrap_optional_fixture(
        should_bootstrap_vlc_install_fixture(case.id),
        bootstrap_vlc_install_fixture_runtime,
        |fixture| environment_evidence_batch_from_checks(vlc_install_fixture_preflight_checks(fixture, run_timestamp_ms)),
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let desktop_project_create_fixture = bootstrap_optional_fixture(
        should_bootstrap_desktop_project_create_fixture(case.id),
        || bootstrap_desktop_project_create_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(desktop_project_create_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let projects_zip_fixture = bootstrap_optional_fixture(
        should_bootstrap_projects_zip_fixture(case.id),
        bootstrap_projects_zip_fixture_runtime,
        |fixture| environment_evidence_batch_from_checks(projects_zip_fixture_preflight_checks(fixture, run_timestamp_ms)),
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let downloads_lowercase_fixture = bootstrap_optional_fixture(
        should_bootstrap_downloads_lowercase_fixture(case.id),
        || bootstrap_downloads_lowercase_fixture_runtime(&run_unique_num),
        |fixture| environment_evidence_batch_from_checks(downloads_lowercase_fixture_preflight_checks(fixture, run_timestamp_ms)),
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let downloads_png_move_fixture = bootstrap_optional_fixture(
        should_bootstrap_downloads_png_move_fixture(case.id),
        || bootstrap_downloads_png_move_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(
                downloads_png_move_fixture_preflight_checks(
                    fixture,
                    &run_unique_num,
                    run_timestamp_ms,
                ),
            )
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    if let Some(fixture) = downloads_png_move_fixture.as_ref() {
        run_query = run_query.replace(
            "{DOWNLOADS_PNG_MOVE_FIXTURE_DIR}",
            &fixture.target_dir.to_string_lossy(),
        );
    }
    let desktop_documents_backup_fixture = bootstrap_optional_fixture(
        should_bootstrap_desktop_documents_backup_fixture(case.id),
        || bootstrap_desktop_documents_backup_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(desktop_documents_backup_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    if let Some(fixture) = desktop_documents_backup_fixture.as_ref() {
        run_query = run_query.replace(
            "{BACKUP_EXTERNAL_DRIVE_PATH}",
            &fixture.external_drive_path.to_string_lossy(),
        );
        run_query = run_query.replace(
            "{BACKUP_DESTINATION_PATH}",
            &fixture.backup_root.to_string_lossy(),
        );
    }
    let documents_summary_fixture = bootstrap_optional_fixture(
        should_bootstrap_documents_summary_fixture(case.id),
        || bootstrap_documents_summary_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(documents_summary_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    if let Some(fixture) = documents_summary_fixture.as_ref() {
        run_query = run_query.replace("{DOCS_FIXTURE_DIR}", &fixture.fixture_dir.to_string_lossy());
    }
    let pdf_last_week_fixture = bootstrap_optional_fixture(
        should_bootstrap_pdf_last_week_fixture(case.id),
        || bootstrap_pdf_last_week_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(pdf_last_week_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    if let Some(fixture) = pdf_last_week_fixture.as_ref() {
        run_query = run_query.replace(
            "{PDF_LAST_WEEK_FIXTURE_DIR}",
            &fixture.fixture_dir.to_string_lossy(),
        );
    }
    let spotify_uninstall_fixture = bootstrap_optional_fixture(
        should_bootstrap_spotify_uninstall_fixture(case.id),
        || bootstrap_spotify_uninstall_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(spotify_uninstall_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    if let Some(fixture) = spotify_uninstall_fixture.as_ref() {
        run_query = run_query.replace(
            "{SPOTIFY_UNINSTALL_FIXTURE_ROOT}",
            &fixture.fixture_root.to_string_lossy(),
        );
    }
    let top_memory_apps_fixture = bootstrap_optional_fixture(
        should_bootstrap_top_memory_apps_fixture(case.id),
        || bootstrap_top_memory_apps_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(top_memory_apps_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    if let Some(fixture) = top_memory_apps_fixture.as_ref() {
        run_query = run_query.replace(
            "{TOP_MEMORY_APPS_PROBE_PATH}",
            &fixture.probe_script_path.to_string_lossy(),
        );
    }
    let shutdown_schedule_fixture = bootstrap_optional_fixture(
        should_bootstrap_shutdown_schedule_fixture(case.id),
        || bootstrap_shutdown_schedule_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(shutdown_schedule_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    if let Some(fixture) = shutdown_schedule_fixture.as_ref() {
        run_query = run_query.replace(
            "{SHUTDOWN_SCHEDULE_PROBE_PATH}",
            &fixture.probe_script_path.to_string_lossy(),
        );
    }
    let mail_reply_mock_fixture = bootstrap_optional_fixture(
        should_bootstrap_mail_reply_mock_fixture(case.id),
        || bootstrap_mail_reply_mock_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(mail_reply_mock_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let restaurants_near_me_fixture = bootstrap_optional_fixture(
        should_bootstrap_restaurants_near_me_fixture(case.id),
        || bootstrap_restaurants_near_me_fixture_runtime(&run_unique_num),
        |fixture| {
            restaurants_near_me_fixture_preflight_checks(fixture, &run_unique_num, run_timestamp_ms)
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let mail_provider_driver_override = mail_reply_mock_fixture.as_ref().map(|_| "mock");
    if should_bootstrap_mailbox_runtime(&run_query) {
        extend_environment_evidence_batch(
            &mut runtime_setup_verification_checks,
            &mut runtime_setup_environment_receipts,
            bootstrap_mailbox_runtime_state(
                &mut state,
                &mut ctx,
                wallet_service.as_ref(),
                run_index,
                run_timestamp_ms,
                mail_provider_driver_override,
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

    apply_capabilities_policy(&mut state, session_id);
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
                    if let Some(tool_hash) = current.pending_tool_hash {
                        let request_hash = read_incident_pending_gate_hash(&state, session_id)
                            .unwrap_or(tool_hash);
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let pii_action = if has_review_request_for_hash(&state, request_hash) {
                            Some(PiiApprovalAction::ApproveTransform)
                        } else {
                            None
                        };
                        let approval_token = build_approval_token_for_resume(
                            request_hash,
                            now_ms,
                            current.pending_visual_hash,
                            pii_action,
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
                duplicate_incident_retry_count = duplicate_incident_retry_count.saturating_add(1);
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
    let mut planned_tool_calls = Vec::new();
    let mut routing_tools = BTreeSet::new();
    let mut workload_tools = BTreeSet::new();
    let mut routing_policy_decisions = BTreeSet::new();
    let mut routing_failure_classes = BTreeSet::new();
    let mut routing_stop_condition_hits = 0usize;
    let mut verification_checks = BTreeSet::new();
    let mut action_evidence = Vec::new();
    let mut action_error_classes = BTreeSet::new();
    let mut command_history_evidence = Vec::new();
    let mut command_history_keys = BTreeSet::new();
    let mut exec_workload_evidence = BTreeMap::<(u32, String), ExecWorkloadEvidence>::new();
    let mut cec_receipts = Vec::new();
    let mut environment_receipts = runtime_setup_environment_receipts;
    let mut final_reply = String::new();
    let mut chat_reply_count = 0usize;
    let mut approval_required_events = 0usize;
    let mut mail_read_latest_success_count = 0usize;
    let mut mail_read_latest_failure_count = 0usize;
    let mut mail_reply_success_count = 0usize;
    let mut mail_reply_failure_count = 0usize;
    let mut mail_read_latest_payloads = Vec::<MailReadLatestPayloadObservation>::new();
    let mut mail_reply_payloads = Vec::<MailReplyPayloadObservation>::new();

    for event in &captured_events {
        match event {
            KernelEvent::AgentStep(trace) => {
                if let Some(entry) = planned_tool_call_from_step(trace) {
                    planned_tool_calls.push(entry);
                }
            }
            KernelEvent::AgentActionResult {
                tool_name,
                output,
                error_class,
                agent_status,
                ..
            } => {
                action_tools.insert(tool_name.clone());
                if tool_name.starts_with("sys__exec") {
                    if let Some(entry) = extract_command_history_evidence(output) {
                        push_command_history_evidence(
                            &mut command_history_evidence,
                            &mut command_history_keys,
                            entry,
                        );
                    }
                }
                if let Some(class_name) = error_class.as_ref() {
                    action_error_classes.insert(class_name.clone());
                }
                let hard_error = error_class
                    .as_deref()
                    .map(|value| !is_no_effect_after_action_error(Some(value)))
                    .unwrap_or(false);
                if is_mail_read_latest_tool_name(tool_name) {
                    if !hard_error {
                        if let Some(payload) = parse_mail_read_latest_payload(output) {
                            mail_read_latest_success_count =
                                mail_read_latest_success_count.saturating_add(1);
                            mail_read_latest_payloads.push(payload);
                        } else if agent_status.eq_ignore_ascii_case("failed") {
                            mail_read_latest_failure_count =
                                mail_read_latest_failure_count.saturating_add(1);
                        }
                    } else {
                        mail_read_latest_failure_count =
                            mail_read_latest_failure_count.saturating_add(1);
                    }
                }
                if is_mail_reply_tool_name(tool_name) {
                    if !hard_error {
                        if let Some(payload) = parse_mail_reply_payload(output) {
                            mail_reply_success_count = mail_reply_success_count.saturating_add(1);
                            mail_reply_payloads.push(payload);
                        } else if agent_status.eq_ignore_ascii_case("failed") {
                            mail_reply_failure_count = mail_reply_failure_count.saturating_add(1);
                        }
                    } else {
                        mail_reply_failure_count = mail_reply_failure_count.saturating_add(1);
                    }
                }
                action_evidence.push(ActionEvidence {
                    tool_name: tool_name.clone(),
                    agent_status: agent_status.clone(),
                    output_excerpt: truncate_for_log(
                        output,
                        action_output_excerpt_limit(tool_name),
                    ),
                    error_class: error_class.clone(),
                });
                if tool_name == "chat__reply" && agent_status.eq_ignore_ascii_case("completed") {
                    chat_reply_count = chat_reply_count.saturating_add(1);
                    final_reply = output.clone();
                }
            }
            KernelEvent::RoutingReceipt(receipt) => {
                routing_tools.insert(receipt.tool_name.clone());
                routing_policy_decisions.insert(receipt.policy_decision.clone());
                if !receipt.failure_class_name.trim().is_empty() {
                    routing_failure_classes.insert(receipt.failure_class_name.clone());
                }
                if receipt.stop_condition_hit {
                    routing_stop_condition_hits = routing_stop_condition_hits.saturating_add(1);
                }
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
            KernelEvent::WorkloadReceipt(workload) => match &workload.receipt {
                WorkloadReceipt::WebRetrieve(web) => {
                    workload_tools.insert(web.tool_name.clone());
                    if let Some(error_class) = web.error_class.as_ref() {
                        action_error_classes.insert(error_class.clone());
                    }
                }
                WorkloadReceipt::FsWrite(fs) => {
                    workload_tools.insert(fs.tool_name.clone());
                    if let Some(error_class) = fs.error_class.as_ref() {
                        action_error_classes.insert(error_class.clone());
                    }
                }
                WorkloadReceipt::Exec(exec) => {
                    workload_tools.insert(exec.tool_name.clone());
                    if let Some(error_class) = exec.error_class.as_ref() {
                        action_error_classes.insert(error_class.clone());
                    }
                    let workload_key = (workload.step_index, workload.workload_id.clone());
                    let entry = command_history_from_exec_workload(
                        exec,
                        exec_workload_evidence.get(&workload_key),
                    );
                    push_command_history_evidence(
                        &mut command_history_evidence,
                        &mut command_history_keys,
                        entry,
                    );
                }
                WorkloadReceipt::NetFetch(fetch) => {
                    workload_tools.insert(fetch.tool_name.clone());
                    if let Some(error_class) = fetch.error_class.as_ref() {
                        action_error_classes.insert(error_class.clone());
                    }
                }
                WorkloadReceipt::ScsRetrieve(scs) => {
                    workload_tools.insert(scs.tool_name.clone());
                    if let Some(error_class) = scs.error_class.as_ref() {
                        action_error_classes.insert(error_class.clone());
                    }
                }
            },
            KernelEvent::WorkloadActivity(activity) => match &activity.kind {
                WorkloadActivityKind::Lifecycle { exit_code, .. } => {
                    let workload_key = (activity.step_index, activity.workload_id.clone());
                    exec_workload_evidence
                        .entry(workload_key)
                        .or_default()
                        .set_exit_code(*exit_code);
                }
                WorkloadActivityKind::Stdio {
                    stream,
                    chunk,
                    seq,
                    exit_code,
                    ..
                } => {
                    let workload_key = (activity.step_index, activity.workload_id.clone());
                    exec_workload_evidence
                        .entry(workload_key)
                        .or_default()
                        .append_chunk(stream, *seq, chunk, *exit_code);
                }
            },
            KernelEvent::ExecutionContractReceipt(receipt) => {
                cec_receipts.push(CecReceiptEvidence {
                    contract_version: receipt.contract_version.clone(),
                    stage: receipt.stage.clone(),
                    key: receipt.key.clone(),
                    satisfied: receipt.satisfied,
                    timestamp_ms: receipt.timestamp_ms,
                    probe_source: receipt.probe_source.clone(),
                    observed_value: receipt.observed_value.clone(),
                    evidence_type: receipt.evidence_type.clone(),
                    provider_id: receipt.provider_id.clone(),
                });
            }
            KernelEvent::FirewallInterception { verdict, .. } => {
                if verdict.eq_ignore_ascii_case("require_approval") {
                    approval_required_events = approval_required_events.saturating_add(1);
                }
            }
            _ => {}
        }
    }

    let terminal_pause_reason = if let AgentStatus::Paused(reason) = &final_state.status {
        Some(reason.clone())
    } else {
        paused_reason.clone()
    };
    let terminal_failure_reason = if let AgentStatus::Failed(reason) = &final_state.status {
        Some(reason.clone())
    } else {
        None
    };

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
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        vlc_install_fixture.as_ref(),
        |fixture| environment_evidence_batch_from_checks(vlc_install_fixture_post_run_checks(fixture)),
        None,
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        desktop_project_create_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(desktop_project_create_fixture_post_run_checks(
                fixture,
            ))
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(desktop_project_create_fixture_cleanup_checks(
                fixture,
            ))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        projects_zip_fixture.as_ref(),
        |fixture| environment_evidence_batch_from_checks(projects_zip_fixture_post_run_checks(fixture)),
        Some(|fixture| environment_evidence_batch_from_checks(projects_zip_fixture_cleanup_checks(fixture))),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        downloads_lowercase_fixture.as_ref(),
        |fixture| environment_evidence_batch_from_checks(downloads_lowercase_fixture_post_run_checks(fixture)),
        Some(|fixture| environment_evidence_batch_from_checks(downloads_lowercase_fixture_cleanup_checks(fixture))),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        downloads_png_move_fixture.as_ref(),
        |fixture| environment_evidence_batch_from_checks(downloads_png_move_fixture_post_run_checks(fixture)),
        Some(|fixture| environment_evidence_batch_from_checks(downloads_png_move_fixture_cleanup_checks(fixture))),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        desktop_documents_backup_fixture.as_ref(),
        |fixture| environment_evidence_batch_from_checks(desktop_documents_backup_fixture_post_run_checks(fixture)),
        Some(|fixture| environment_evidence_batch_from_checks(desktop_documents_backup_fixture_cleanup_checks(fixture))),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        documents_summary_fixture.as_ref(),
        |fixture| environment_evidence_batch_from_checks(documents_summary_fixture_post_run_checks(fixture)),
        Some(|fixture| environment_evidence_batch_from_checks(documents_summary_fixture_cleanup_checks(fixture))),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        pdf_last_week_fixture.as_ref(),
        |fixture| environment_evidence_batch_from_checks(pdf_last_week_fixture_post_run_checks(fixture)),
        Some(|fixture| environment_evidence_batch_from_checks(pdf_last_week_fixture_cleanup_checks(fixture))),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        spotify_uninstall_fixture.as_ref(),
        |fixture| environment_evidence_batch_from_checks(spotify_uninstall_fixture_post_run_checks(fixture)),
        Some(|fixture| environment_evidence_batch_from_checks(spotify_uninstall_fixture_cleanup_checks(fixture))),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        top_memory_apps_fixture.as_ref(),
        |fixture| environment_evidence_batch_from_checks(top_memory_apps_fixture_post_run_checks(fixture)),
        Some(|fixture| environment_evidence_batch_from_checks(top_memory_apps_fixture_cleanup_checks(fixture))),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        shutdown_schedule_fixture.as_ref(),
        |fixture| environment_evidence_batch_from_checks(shutdown_schedule_fixture_post_run_checks(fixture)),
        Some(|fixture| environment_evidence_batch_from_checks(shutdown_schedule_fixture_cleanup_checks(fixture))),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        mail_reply_mock_fixture.as_ref(),
        |fixture| environment_evidence_batch_from_checks(mail_reply_mock_fixture_post_run_checks(fixture)),
        Some(|fixture| environment_evidence_batch_from_checks(mail_reply_mock_fixture_cleanup_checks(fixture))),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        restaurants_near_me_fixture.as_ref(),
        restaurants_near_me_fixture_post_run_checks,
        Some(restaurants_near_me_fixture_cleanup_checks),
    );

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

    let verification_checks = verification_checks.into_iter().collect::<Vec<_>>();
    let verification_facts = parse_verification_facts(&verification_checks);
    let mut observation = RunObservation {
        case_id: case.id.to_string(),
        query: run_query,
        run_timestamp_ms,
        run_timestamp_iso_utc: iso_datetime_from_unix_ms(run_timestamp_ms),
        elapsed_ms,
        completed: matches!(final_state.status, AgentStatus::Completed(_)),
        failed: matches!(final_state.status, AgentStatus::Failed(_)),
        final_status: format!("{:?}", final_state.status),
        terminal_pause_reason,
        terminal_failure_reason,
        final_reply,
        chat_reply_count,
        action_tools: action_tools.into_iter().collect(),
        planned_tool_calls,
        routing_tools: routing_tools.into_iter().collect(),
        workload_tools: workload_tools.into_iter().collect(),
        routing_policy_decisions: routing_policy_decisions.into_iter().collect(),
        routing_failure_classes: routing_failure_classes.into_iter().collect(),
        routing_stop_condition_hits,
        verification_checks,
        verification_facts,
        approval_required_events,
        action_evidence,
        action_error_classes: action_error_classes.into_iter().collect(),
        command_history_evidence,
        cec_receipts,
        environment_receipts,
        web: None,
        screenshot: None,
        mail: None,
        event_excerpt,
        kernel_event_count: captured_events.len(),
        kernel_log_lines,
    };
    observation.web = derive_web_observation(&observation);
    observation.screenshot = derive_screenshot_observation(&observation);
    observation.mail = derive_mail_observation(
        &observation,
        mail_read_latest_success_count,
        mail_read_latest_failure_count,
        mail_reply_success_count,
        mail_reply_failure_count,
        mail_read_latest_payloads,
        mail_reply_payloads,
    );

    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::{
        merge_environment_receipts, parse_mail_read_latest_payload, parse_mail_reply_payload,
    };
    use crate::capabilities_suite::types::EnvironmentReceiptObservation;

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
            "env_receipt::top_memory_apps_row=1|code|4003|4437552".to_string(),
            "env_receipt::top_memory_apps_row=2|firefox-bin|5461|841404".to_string(),
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
}
