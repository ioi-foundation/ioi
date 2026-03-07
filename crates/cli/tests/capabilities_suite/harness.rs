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
const MEDIA_TRANSCRIPT_SUMMARY_CASE_ID: &str =
    "summarize_the_key_points_from_this_45_minute_youtube_video";
const MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_MODE: &str = "media_multimodal_tool_home_fixture_v1";
const MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_PROBE_SOURCE: &str =
    "harness.media_multimodal_summary_fixture";
const MEDIA_TRANSCRIPT_SUMMARY_TOOL_HOME_ENV_KEY: &str = "IOI_MEDIA_TOOL_HOME";
const MEDIA_TRANSCRIPT_SUMMARY_EXPECTED_URL: &str =
    "https://www.youtube.com/watch?v=9Tm2c6NJH4Y";
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

include!("harness/mail_runtime.rs");

include!("harness/project_fixtures.rs");

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
