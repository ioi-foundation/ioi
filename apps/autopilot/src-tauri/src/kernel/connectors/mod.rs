mod auth;
mod commands;
mod config;
mod constants;
mod google_workspace;
mod operations;
mod policy;
mod rpc;
mod subscriptions;
mod types;
mod utils;

use crate::models::AppState;
use chrono::{TimeZone, Utc};
use ioi_services::agentic::desktop::connectors::mock_fixtures::{
    generic_connector_mock_records as shared_generic_connector_mock_records,
    google_mock_fixture_active as shared_google_mock_fixture_active,
    mail_mock_fixture as shared_mail_mock_fixture, GenericConnectorMockRecord,
    MailAccountMockFixture, MailMessageMockFixture, MockConnectorCatalogEntry,
};
use serde_json::Value;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, State};

pub(crate) use auth::bootstrap_google_wallet_auth;
pub(crate) use policy::bootstrap_wallet_policy_state;
pub use policy::{
    policy_state_path_for, AutomationPolicyMode, ConnectorPolicyOverride, DataHandlingMode,
    GlobalPolicyDefaults, PolicyDecisionMode, ShieldApprovalHookReceipt, ShieldPolicyManager,
    ShieldPolicyState, ShieldRememberApprovalInput, ShieldRememberedApprovalExpiryUpdateInput,
    ShieldRememberedApprovalScopeUpdateInput, ShieldRememberedApprovalSnapshot,
};
pub use subscriptions::{
    registry_path_for, GoogleAutomationManager, GoogleConnectorSubscriptionView,
};
pub use types::{
    ConnectorCatalogEntry, WalletConnectorAuthExportResult, WalletConnectorAuthGetResult,
    WalletConnectorAuthImportResult, WalletConnectorAuthListResult,
    WalletMailConfigureAccountResult, WalletMailConfiguredAccountView, WalletMailDeleteSpamResult,
    WalletMailListRecentResult, WalletMailReadLatestResult, WalletMailReplyResult,
};

const GOOGLE_CONNECTOR_ID: &str = "google.workspace";
const MAIL_CONNECTOR_ID: &str = "mail.primary";
const MAIL_PROVIDER_FAMILY: &str = "mail.wallet_network";
const SHIELD_APPROVAL_MEMORY_UPDATED_EVENT: &str = "shield-approval-memory-updated";
const MAIL_MOCK_DEFAULT_CHANNEL_ID_HEX: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const MAIL_MOCK_DEFAULT_LEASE_ID_HEX: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";

fn google_mock_fixture_active() -> bool {
    shared_google_mock_fixture_active()
}

fn catalog_entry_from_shared(record: MockConnectorCatalogEntry) -> ConnectorCatalogEntry {
    ConnectorCatalogEntry {
        id: record.id,
        plugin_id: record.plugin_id,
        name: record.name,
        provider: record.provider,
        category: record.category,
        description: record.description,
        status: record.status,
        auth_mode: record.auth_mode,
        scopes: record.scopes,
        last_sync_at_utc: record.last_sync_at_utc,
        notes: record.notes,
    }
}

fn generic_connector_mock_records() -> Vec<GenericConnectorMockRecord> {
    shared_generic_connector_mock_records()
        .unwrap_or_default()
        .into_iter()
        .map(|mut record| {
            record.catalog = MockConnectorCatalogEntry {
                id: record.catalog.id.trim().to_string(),
                plugin_id: record.catalog.plugin_id.trim().to_string(),
                name: record.catalog.name.trim().to_string(),
                provider: record.catalog.provider,
                category: record.catalog.category,
                description: record.catalog.description,
                status: record.catalog.status,
                auth_mode: record.catalog.auth_mode,
                scopes: record.catalog.scopes,
                last_sync_at_utc: record.catalog.last_sync_at_utc,
                notes: record.catalog.notes,
            };
            record
        })
        .filter(|record| {
            !record.catalog.id.trim().is_empty()
                && !record.catalog.plugin_id.trim().is_empty()
                && !record.catalog.name.trim().is_empty()
        })
        .collect()
}

fn mail_mock_fixture_accounts() -> Vec<WalletMailConfiguredAccountView> {
    let fixture = match shared_mail_mock_fixture().ok().flatten() {
        Some(fixture) => fixture,
        None => return Vec::new(),
    };
    fixture
        .accounts
        .into_iter()
        .filter_map(|mut account| {
            if account.mailbox.trim().is_empty() || account.account_email.trim().is_empty() {
                return None;
            }
            if account
                .default_channel_id_hex
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                account.default_channel_id_hex = Some(MAIL_MOCK_DEFAULT_CHANNEL_ID_HEX.to_string());
            }
            if account
                .default_lease_id_hex
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                account.default_lease_id_hex = Some(MAIL_MOCK_DEFAULT_LEASE_ID_HEX.to_string());
            }
            Some(mail_account_from_shared(account))
        })
        .collect()
}

pub(crate) fn mail_mock_fixture_messages(mailbox: &str) -> Vec<types::WalletMailMessageView> {
    let fixture = match shared_mail_mock_fixture().ok().flatten() {
        Some(fixture) => fixture,
        None => return Vec::new(),
    };
    let normalized_mailbox = mailbox.trim().to_ascii_lowercase();
    let mut messages = fixture
        .messages_by_mailbox
        .into_iter()
        .find_map(|(key, value)| {
            if key.trim().eq_ignore_ascii_case(&normalized_mailbox) {
                Some(value)
            } else {
                None
            }
        })
        .unwrap_or_default()
        .into_iter()
        .filter(|message| {
            !message.message_id.trim().is_empty()
                && !message.subject.trim().is_empty()
                && !message.from.trim().is_empty()
        })
        .map(mail_message_from_shared)
        .collect::<Vec<_>>();
    messages.sort_by(|left, right| {
        right
            .received_at_ms
            .cmp(&left.received_at_ms)
            .then_with(|| left.message_id.cmp(&right.message_id))
    });
    messages
}

fn mail_account_from_shared(account: MailAccountMockFixture) -> WalletMailConfiguredAccountView {
    WalletMailConfiguredAccountView {
        mailbox: account.mailbox,
        account_email: account.account_email,
        sender_display_name: account.sender_display_name,
        default_channel_id_hex: account.default_channel_id_hex,
        default_lease_id_hex: account.default_lease_id_hex,
        updated_at_ms: account.updated_at_ms,
    }
}

fn mail_message_from_shared(message: MailMessageMockFixture) -> types::WalletMailMessageView {
    types::WalletMailMessageView {
        message_id: message.message_id,
        from: message.from,
        subject: message.subject,
        received_at_ms: message.received_at_ms,
        preview: message.preview,
    }
}

fn patch_connector_catalog_from_generic_mock_fixture(entries: &mut Vec<ConnectorCatalogEntry>) {
    for record in generic_connector_mock_records() {
        entries.retain(|entry| entry.id != record.catalog.id);
        entries.push(catalog_entry_from_shared(record.catalog));
    }
}

fn generic_connector_mock_actions(
    connector_id: &str,
) -> Option<Vec<google_workspace::ConnectorActionDefinition>> {
    generic_connector_mock_records()
        .into_iter()
        .find(|record| record.catalog.id == connector_id)
        .map(|record| record.actions)
}

fn generic_connector_mock_configure_result(
    connector_id: &str,
) -> Option<google_workspace::ConnectorConfigureResult> {
    let record = generic_connector_mock_records()
        .into_iter()
        .find(|record| record.catalog.id == connector_id)?;
    let mut result =
        record
            .configure_result
            .unwrap_or(google_workspace::ConnectorConfigureResult {
                connector_id: record.catalog.id.clone(),
                provider: record.catalog.provider.clone(),
                status: "connected".to_string(),
                summary: format!(
                    "Connected {} through the local generic mock fixture.",
                    record.catalog.name
                ),
                data: Some(serde_json::json!({
                    "mockFixture": true,
                    "connectorId": record.catalog.id,
                })),
                executed_at_utc: Utc::now().to_rfc3339(),
            });
    result.connector_id = connector_id.to_string();
    if result.provider.trim().is_empty() {
        result.provider = record.catalog.provider;
    }
    if result.executed_at_utc.trim().is_empty() {
        result.executed_at_utc = Utc::now().to_rfc3339();
    }
    Some(result)
}

fn generic_connector_mock_action_result(
    connector_id: &str,
    action_id: &str,
    input: &Value,
) -> Option<google_workspace::ConnectorActionResult> {
    let record = generic_connector_mock_records()
        .into_iter()
        .find(|record| record.catalog.id == connector_id)?;
    let action = record
        .actions
        .iter()
        .find(|candidate| candidate.id == action_id)?;
    let mut result = record.action_results.get(action_id).cloned().unwrap_or(
        google_workspace::ConnectorActionResult {
            connector_id: connector_id.to_string(),
            action_id: action_id.to_string(),
            tool_name: action.tool_name.clone(),
            provider: record.catalog.provider.clone(),
            summary: format!(
                "Ran {} through the local generic mock fixture.",
                action.label
            ),
            data: serde_json::json!({
                "mockFixture": true,
                "connectorId": connector_id,
                "actionId": action_id,
                "input": input,
            }),
            raw_output: None,
            executed_at_utc: Utc::now().to_rfc3339(),
        },
    );
    result.connector_id = connector_id.to_string();
    result.action_id = action_id.to_string();
    if result.tool_name.trim().is_empty() {
        result.tool_name = action.tool_name.clone();
    }
    if result.provider.trim().is_empty() {
        result.provider = record.catalog.provider;
    }
    if result.executed_at_utc.trim().is_empty() {
        result.executed_at_utc = Utc::now().to_rfc3339();
    }
    Some(result)
}

fn connector_status_from_wallet_state(state: &str) -> String {
    match state.trim().to_ascii_lowercase().as_str() {
        "connected" => "connected".to_string(),
        "expired" | "revoked" | "degraded" => "degraded".to_string(),
        _ => "needs_auth".to_string(),
    }
}

fn timestamp_ms_to_utc(value: u64) -> Option<String> {
    Utc.timestamp_millis_opt(value as i64)
        .single()
        .map(|timestamp| timestamp.to_rfc3339())
}

fn base_connector_catalog() -> Vec<ConnectorCatalogEntry> {
    vec![
        ConnectorCatalogEntry {
            id: MAIL_CONNECTOR_ID.to_string(),
            plugin_id: "wallet_mail".to_string(),
            name: "Mail".to_string(),
            provider: "wallet.network".to_string(),
            category: "communication".to_string(),
            description:
                "Wallet-backed mail connector for delegated inbox listing, latest-message reads, spam cleanup, and governed replies.".to_string(),
            status: "needs_auth".to_string(),
            auth_mode: "wallet_capability".to_string(),
            scopes: vec![
                "mail.read.latest".to_string(),
                "mail.list.recent".to_string(),
                "mail.delete.spam".to_string(),
                "mail.reply".to_string(),
            ],
            last_sync_at_utc: None,
            notes: Some(
                "Configure a mailbox to bind durable mail operations through the wallet auth layer."
                    .to_string(),
            ),
        },
        ConnectorCatalogEntry {
            id: GOOGLE_CONNECTOR_ID.to_string(),
            plugin_id: "google_workspace".to_string(),
            name: "Google".to_string(),
            provider: "google".to_string(),
            category: "productivity".to_string(),
            description:
                "Single Google connector exposing Gmail, Calendar, Docs, Sheets, BigQuery, Drive, Tasks, Chat, events, workflows, and expert raw access.".to_string(),
            status: "needs_auth".to_string(),
            auth_mode: "wallet_capability".to_string(),
            scopes: vec![
                "gmail".to_string(),
                "calendar".to_string(),
                "docs".to_string(),
                "sheets".to_string(),
                "bigquery".to_string(),
                "drive".to_string(),
                "tasks".to_string(),
                "chat".to_string(),
                "events".to_string(),
                "workflow".to_string(),
                "expert".to_string(),
            ],
            last_sync_at_utc: None,
            notes: Some(
                "Uses native Google OAuth for consent, then binds durable auth and governed execution through the wallet layer.".to_string(),
            ),
        },
    ]
}

fn patch_connector_catalog_from_auth(
    entries: &mut [ConnectorCatalogEntry],
    auth: &WalletConnectorAuthListResult,
) {
    if let Some(google_entry) = entries
        .iter_mut()
        .find(|entry| entry.id == GOOGLE_CONNECTOR_ID)
    {
        if let Some(record) = auth
            .records
            .iter()
            .find(|record| record.connector_id == GOOGLE_CONNECTOR_ID)
        {
            google_entry.status = connector_status_from_wallet_state(&record.state);
            google_entry.last_sync_at_utc = timestamp_ms_to_utc(record.updated_at_ms);
            if !record.granted_scopes.is_empty() {
                google_entry.scopes = record.granted_scopes.clone();
            }
            google_entry.notes = Some(match record.account_label.as_deref() {
                Some(account) if !account.trim().is_empty() => {
                    format!("Connected Google Workspace account {}.", account.trim())
                }
                _ => "Google Workspace auth is registered in the wallet layer.".to_string(),
            });
        }
    }

    if let Some(mail_entry) = entries
        .iter_mut()
        .find(|entry| entry.id == MAIL_CONNECTOR_ID)
    {
        let mail_records: Vec<_> = auth
            .records
            .iter()
            .filter(|record| {
                record.provider_family == MAIL_PROVIDER_FAMILY
                    || record.connector_id.starts_with("mail.")
            })
            .collect();

        if let Some(latest_record) = mail_records
            .iter()
            .max_by_key(|record| record.updated_at_ms)
        {
            mail_entry.status = connector_status_from_wallet_state(&latest_record.state);
            mail_entry.last_sync_at_utc = timestamp_ms_to_utc(latest_record.updated_at_ms);
            if !latest_record.granted_scopes.is_empty() {
                mail_entry.scopes = latest_record.granted_scopes.clone();
            }

            let configured_mailboxes = mail_records
                .iter()
                .filter_map(|record| record.mailbox.as_deref())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();

            let account = latest_record
                .account_label
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            mail_entry.notes = Some(match (configured_mailboxes.len(), account) {
                (count, Some(account_label)) if count > 1 => format!(
                    "Connected {} wallet-backed mailboxes. Most recent account: {}.",
                    count, account_label
                ),
                (_, Some(account_label)) => {
                    format!("Connected wallet-backed mail account {}.", account_label)
                }
                (count, None) if count > 1 => {
                    format!("Connected {} wallet-backed mailboxes.", count)
                }
                _ => "Wallet-backed mail auth is registered.".to_string(),
            });
        }
    }
}

fn patch_connector_catalog_from_google_mock_fixture(entries: &mut [ConnectorCatalogEntry]) {
    if !google_mock_fixture_active() {
        return;
    }

    if let Some(google_entry) = entries
        .iter_mut()
        .find(|entry| entry.id == GOOGLE_CONNECTOR_ID)
    {
        google_entry.status = "connected".to_string();
        google_entry.notes = Some(
            "Connected Google Workspace auth is being provided by the local mock fixture."
                .to_string(),
        );
        google_entry.last_sync_at_utc = None;
    }
}

fn mail_account_views_from_auth(
    auth: &WalletConnectorAuthListResult,
) -> Vec<WalletMailConfiguredAccountView> {
    let mut accounts = auth
        .records
        .iter()
        .filter(|record| {
            record.provider_family == MAIL_PROVIDER_FAMILY
                || record.connector_id.starts_with("mail.")
        })
        .filter_map(|record| {
            let mailbox = record.mailbox.as_deref()?.trim().to_string();
            let account_email = record.account_label.as_deref()?.trim().to_string();
            if mailbox.is_empty() || account_email.is_empty() {
                return None;
            }
            Some(WalletMailConfiguredAccountView {
                mailbox,
                account_email,
                sender_display_name: None,
                default_channel_id_hex: None,
                default_lease_id_hex: None,
                updated_at_ms: record.updated_at_ms,
            })
        })
        .collect::<Vec<_>>();
    accounts.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.mailbox.cmp(&right.mailbox))
    });
    accounts.dedup_by(|left, right| left.mailbox == right.mailbox);
    accounts
}

fn patch_connector_catalog_from_mail_mock_fixture(
    entries: &mut [ConnectorCatalogEntry],
    accounts: &[WalletMailConfiguredAccountView],
) {
    if accounts.is_empty() {
        return;
    }

    if let Some(mail_entry) = entries
        .iter_mut()
        .find(|entry| entry.id == MAIL_CONNECTOR_ID)
    {
        mail_entry.status = "connected".to_string();
        mail_entry.last_sync_at_utc = accounts
            .iter()
            .map(|account| account.updated_at_ms)
            .max()
            .and_then(timestamp_ms_to_utc);
        mail_entry.notes = Some(match accounts.len() {
            1 => format!(
                "Connected mail mock account {} on mailbox {}.",
                accounts[0].account_email, accounts[0].mailbox
            ),
            count => format!(
                "Connected {} mock mailboxes for local connector proof.",
                count
            ),
        });
    }
}

pub(crate) fn wallet_backed_bootstrap_enabled() -> bool {
    if let Ok(explicit) = std::env::var("AUTOPILOT_CONNECTOR_WALLET_BOOTSTRAP") {
        let normalized = explicit.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "1" | "true" | "yes" | "on") {
            return true;
        }
        if matches!(normalized.as_str(), "0" | "false" | "no" | "off") {
            return false;
        }
    }

    if crate::is_env_var_truthy("AUTOPILOT_LOCAL_GPU_DEV") {
        return false;
    }

    !matches!(
        std::env::var("AUTOPILOT_DATA_PROFILE")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("desktop-localgpu")
    )
}

#[cfg(test)]
mod tests {
    use super::{
        base_connector_catalog, generic_connector_mock_action_result,
        generic_connector_mock_actions, generic_connector_mock_configure_result,
        mail_mock_fixture_accounts, mail_mock_fixture_messages,
        patch_connector_catalog_from_generic_mock_fixture,
        patch_connector_catalog_from_google_mock_fixture,
        patch_connector_catalog_from_mail_mock_fixture, wallet_backed_bootstrap_enabled,
        GOOGLE_CONNECTOR_ID, MAIL_CONNECTOR_ID, MAIL_MOCK_DEFAULT_CHANNEL_ID_HEX,
        MAIL_MOCK_DEFAULT_LEASE_ID_HEX,
    };
    use ioi_services::agentic::desktop::connectors::mock_fixtures::{
        CONNECTOR_MOCK_FIXTURE_PATH_ENV, LEGACY_GENERIC_CONNECTOR_MOCK_FIXTURE_PATH_ENV,
        LEGACY_GOOGLE_MOCK_FIXTURE_PATH_ENV, LEGACY_MAIL_MOCK_FIXTURE_PATH_ENV,
    };
    use serde_json::json;
    use std::sync::{Mutex, OnceLock};

    fn fixture_env_guard() -> std::sync::MutexGuard<'static, ()> {
        static FIXTURE_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        FIXTURE_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("lock fixture env guard")
    }

    fn capture_fixture_envs() -> [Option<std::ffi::OsString>; 4] {
        [
            std::env::var_os(CONNECTOR_MOCK_FIXTURE_PATH_ENV),
            std::env::var_os(LEGACY_GOOGLE_MOCK_FIXTURE_PATH_ENV),
            std::env::var_os(LEGACY_MAIL_MOCK_FIXTURE_PATH_ENV),
            std::env::var_os(LEGACY_GENERIC_CONNECTOR_MOCK_FIXTURE_PATH_ENV),
        ]
    }

    fn restore_fixture_envs(previous: [Option<std::ffi::OsString>; 4]) {
        match previous[0].clone() {
            Some(value) => std::env::set_var(CONNECTOR_MOCK_FIXTURE_PATH_ENV, value),
            None => std::env::remove_var(CONNECTOR_MOCK_FIXTURE_PATH_ENV),
        }
        match previous[1].clone() {
            Some(value) => std::env::set_var(LEGACY_GOOGLE_MOCK_FIXTURE_PATH_ENV, value),
            None => std::env::remove_var(LEGACY_GOOGLE_MOCK_FIXTURE_PATH_ENV),
        }
        match previous[2].clone() {
            Some(value) => std::env::set_var(LEGACY_MAIL_MOCK_FIXTURE_PATH_ENV, value),
            None => std::env::remove_var(LEGACY_MAIL_MOCK_FIXTURE_PATH_ENV),
        }
        match previous[3].clone() {
            Some(value) => std::env::set_var(LEGACY_GENERIC_CONNECTOR_MOCK_FIXTURE_PATH_ENV, value),
            None => std::env::remove_var(LEGACY_GENERIC_CONNECTOR_MOCK_FIXTURE_PATH_ENV),
        }
    }

    #[test]
    fn wallet_bootstrap_is_disabled_for_local_gpu_dev() {
        let prev_local_gpu = std::env::var_os("AUTOPILOT_LOCAL_GPU_DEV");
        let prev_profile = std::env::var_os("AUTOPILOT_DATA_PROFILE");
        let prev_bootstrap = std::env::var_os("AUTOPILOT_CONNECTOR_WALLET_BOOTSTRAP");

        std::env::set_var("AUTOPILOT_LOCAL_GPU_DEV", "1");
        std::env::remove_var("AUTOPILOT_DATA_PROFILE");
        std::env::remove_var("AUTOPILOT_CONNECTOR_WALLET_BOOTSTRAP");

        assert!(!wallet_backed_bootstrap_enabled());

        match prev_local_gpu {
            Some(value) => std::env::set_var("AUTOPILOT_LOCAL_GPU_DEV", value),
            None => std::env::remove_var("AUTOPILOT_LOCAL_GPU_DEV"),
        }
        match prev_profile {
            Some(value) => std::env::set_var("AUTOPILOT_DATA_PROFILE", value),
            None => std::env::remove_var("AUTOPILOT_DATA_PROFILE"),
        }
        match prev_bootstrap {
            Some(value) => std::env::set_var("AUTOPILOT_CONNECTOR_WALLET_BOOTSTRAP", value),
            None => std::env::remove_var("AUTOPILOT_CONNECTOR_WALLET_BOOTSTRAP"),
        }
    }

    #[test]
    fn google_mock_fixture_marks_catalog_as_connected() {
        let _guard = fixture_env_guard();
        let previous = capture_fixture_envs();
        let fixture_path = std::env::temp_dir().join("connector-google-mock-fixture.json");
        std::fs::write(
            &fixture_path,
            r#"{"google":{"auth":{"accountEmail":"calendar-proof@example.com","grantedScopes":["https://www.googleapis.com/auth/gmail.readonly","https://www.googleapis.com/auth/calendar"]}}}"#,
        )
        .expect("write unified google mock fixture");
        std::env::set_var(CONNECTOR_MOCK_FIXTURE_PATH_ENV, &fixture_path);
        std::env::remove_var(LEGACY_GOOGLE_MOCK_FIXTURE_PATH_ENV);
        std::env::remove_var(LEGACY_MAIL_MOCK_FIXTURE_PATH_ENV);
        std::env::remove_var(LEGACY_GENERIC_CONNECTOR_MOCK_FIXTURE_PATH_ENV);

        let mut entries = base_connector_catalog();
        patch_connector_catalog_from_google_mock_fixture(&mut entries);

        let google = entries
            .into_iter()
            .find(|entry| entry.id == GOOGLE_CONNECTOR_ID)
            .expect("google catalog entry");
        assert_eq!(google.status, "connected");
        assert!(google
            .notes
            .as_deref()
            .unwrap_or_default()
            .contains("mock fixture"));

        let _ = std::fs::remove_file(&fixture_path);
        restore_fixture_envs(previous);
    }

    #[test]
    fn mail_mock_fixture_marks_catalog_as_connected_and_lists_accounts() {
        let _guard = fixture_env_guard();
        let previous = capture_fixture_envs();
        let fixture_path = std::env::temp_dir().join("connector-mail-mock-fixture.json");
        std::fs::write(
            &fixture_path,
            r#"{"mail":{"accounts":[{"mailbox":"primary","accountEmail":"proof-mail@example.com","updatedAtMs":1712345678000}],"messagesByMailbox":{"primary":[{"messageId":"msg-2","from":"two@example.com","subject":"Two","receivedAtMs":200,"preview":"Second"},{"messageId":"msg-1","from":"one@example.com","subject":"One","receivedAtMs":100,"preview":"First"}]}}}"#,
        )
        .expect("write unified mail mock fixture");
        std::env::set_var(CONNECTOR_MOCK_FIXTURE_PATH_ENV, &fixture_path);
        std::env::remove_var(LEGACY_GOOGLE_MOCK_FIXTURE_PATH_ENV);
        std::env::remove_var(LEGACY_MAIL_MOCK_FIXTURE_PATH_ENV);
        std::env::remove_var(LEGACY_GENERIC_CONNECTOR_MOCK_FIXTURE_PATH_ENV);

        let accounts = mail_mock_fixture_accounts();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].mailbox, "primary");
        assert_eq!(accounts[0].account_email, "proof-mail@example.com");
        assert_eq!(
            accounts[0].default_channel_id_hex.as_deref(),
            Some(MAIL_MOCK_DEFAULT_CHANNEL_ID_HEX)
        );
        assert_eq!(
            accounts[0].default_lease_id_hex.as_deref(),
            Some(MAIL_MOCK_DEFAULT_LEASE_ID_HEX)
        );
        let messages = mail_mock_fixture_messages("primary");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].message_id, "msg-2");
        assert_eq!(messages[1].message_id, "msg-1");

        let mut entries = base_connector_catalog();
        patch_connector_catalog_from_mail_mock_fixture(&mut entries, &accounts);
        let mail = entries
            .into_iter()
            .find(|entry| entry.id == MAIL_CONNECTOR_ID)
            .expect("mail catalog entry");
        assert_eq!(mail.status, "connected");
        assert!(mail.notes.as_deref().unwrap_or_default().contains("mock"));

        let _ = std::fs::remove_file(&fixture_path);
        restore_fixture_envs(previous);
    }

    #[test]
    fn generic_mock_fixture_adds_catalog_and_serves_runtime_shapes() {
        let _guard = fixture_env_guard();
        let previous = capture_fixture_envs();
        let fixture_path = std::env::temp_dir().join("connector-generic-mock-fixture.json");
        std::fs::write(
            &fixture_path,
            r#"{"connectors":[{"catalog":{"id":"mock.crm","pluginId":"mock_crm","name":"Mock CRM","provider":"mock.fixture","category":"productivity","description":"Safe generic connector fixture for the shared fallback.","status":"needs_auth","authMode":"api_key","scopes":["accounts.read","accounts.write"],"notes":"Safe generic mock fixture for connector fallback proof."},"actions":[{"id":"accounts.list_recent","service":"accounts","serviceLabel":"Accounts","toolName":"mock__crm__accounts__list_recent","label":"List recent accounts","description":"Inspect recently updated accounts from the mock fixture.","kind":"read","fields":[{"id":"limit","label":"Limit","type":"number","required":false,"defaultValue":5}],"requiredScopes":["accounts.read"]},{"id":"accounts.create_note","service":"accounts","serviceLabel":"Accounts","toolName":"mock__crm__accounts__create_note","label":"Create account note","description":"Attach a note to the selected mock account.","kind":"write","confirmBeforeRun":true,"fields":[{"id":"accountId","label":"Account ID","type":"text","required":true},{"id":"title","label":"Title","type":"text","required":true},{"id":"note","label":"Note","type":"textarea","required":true},{"id":"visibility","label":"Visibility","type":"select","required":true,"options":[{"label":"Private","value":"private"},{"label":"Shared","value":"shared"}]}],"requiredScopes":["accounts.write"]}],"configureResult":{"connectorId":"mock.crm","provider":"mock.fixture","status":"connected","summary":"Connected Mock CRM through the local generic mock fixture.","data":{"mockFixture":true},"executedAtUtc":"2026-04-05T12:00:00Z"},"actionResults":{"accounts.list_recent":{"connectorId":"mock.crm","actionId":"accounts.list_recent","toolName":"mock__crm__accounts__list_recent","provider":"mock.fixture","summary":"Loaded 2 recent mock accounts.","data":{"accounts":[{"id":"acct_001","name":"Northwind"},{"id":"acct_002","name":"Fabrikam"}]},"executedAtUtc":"2026-04-05T12:00:01Z"}}}]}"#,
        )
        .expect("write unified generic connector mock fixture");
        std::env::set_var(CONNECTOR_MOCK_FIXTURE_PATH_ENV, &fixture_path);
        std::env::remove_var(LEGACY_GOOGLE_MOCK_FIXTURE_PATH_ENV);
        std::env::remove_var(LEGACY_MAIL_MOCK_FIXTURE_PATH_ENV);
        std::env::remove_var(LEGACY_GENERIC_CONNECTOR_MOCK_FIXTURE_PATH_ENV);

        let mut entries = base_connector_catalog();
        patch_connector_catalog_from_generic_mock_fixture(&mut entries);
        let generic = entries
            .into_iter()
            .find(|entry| entry.id == "mock.crm")
            .expect("generic connector entry");
        assert_eq!(generic.plugin_id, "mock_crm");
        assert_eq!(generic.status, "needs_auth");

        let actions = generic_connector_mock_actions("mock.crm").expect("mock actions");
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[1].id, "accounts.create_note");

        let configure =
            generic_connector_mock_configure_result("mock.crm").expect("generic configure result");
        assert_eq!(configure.status, "connected");

        let list_result = generic_connector_mock_action_result(
            "mock.crm",
            "accounts.list_recent",
            &json!({ "limit": 2 }),
        )
        .expect("list result");
        assert_eq!(list_result.summary, "Loaded 2 recent mock accounts.");

        let default_result = generic_connector_mock_action_result(
            "mock.crm",
            "accounts.create_note",
            &json!({ "accountId": "acct_001", "title": "Follow up" }),
        )
        .expect("default result");
        assert_eq!(default_result.connector_id, "mock.crm");
        assert_eq!(default_result.action_id, "accounts.create_note");
        assert_eq!(default_result.tool_name, "mock__crm__accounts__create_note");

        let _ = std::fs::remove_file(&fixture_path);
        restore_fixture_envs(previous);
    }
}

#[tauri::command]
pub async fn connector_list_catalog(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<ConnectorCatalogEntry>, String> {
    let mut entries = base_connector_catalog();
    patch_connector_catalog_from_google_mock_fixture(&mut entries);
    if let Ok(auth) = auth::wallet_connector_auth_list_inner(&state, None).await {
        patch_connector_catalog_from_auth(&mut entries, &auth);
    }
    let mail_fixture_accounts = mail_mock_fixture_accounts();
    patch_connector_catalog_from_mail_mock_fixture(&mut entries, &mail_fixture_accounts);
    patch_connector_catalog_from_generic_mock_fixture(&mut entries);
    Ok(entries)
}

#[tauri::command]
pub async fn wallet_mail_list_accounts(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<WalletMailConfiguredAccountView>, String> {
    let fixture_accounts = mail_mock_fixture_accounts();
    if !fixture_accounts.is_empty() {
        return Ok(fixture_accounts);
    }

    let auth =
        auth::wallet_connector_auth_list_inner(&state, Some(MAIL_PROVIDER_FAMILY.to_string()))
            .await?;
    Ok(mail_account_views_from_auth(&auth))
}

#[tauri::command]
pub async fn wallet_mail_configure_account(
    state: State<'_, Mutex<AppState>>,
    mailbox: Option<String>,
    account_email: String,
    auth_mode: Option<String>,
    imap_host: String,
    imap_port: u16,
    imap_tls_mode: Option<String>,
    smtp_host: String,
    smtp_port: u16,
    smtp_tls_mode: Option<String>,
    sender_display_name: Option<String>,
    imap_username: Option<String>,
    imap_secret: String,
    smtp_username: Option<String>,
    smtp_secret: String,
) -> Result<WalletMailConfigureAccountResult, String> {
    commands::wallet_mail_configure_account(
        state,
        mailbox,
        account_email,
        auth_mode,
        imap_host,
        imap_port,
        imap_tls_mode,
        smtp_host,
        smtp_port,
        smtp_tls_mode,
        sender_display_name,
        imap_username,
        imap_secret,
        smtp_username,
        smtp_secret,
    )
    .await
}

#[tauri::command]
pub async fn wallet_mail_read_latest(
    app: AppHandle,
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, ShieldPolicyManager>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    shield_approved: Option<bool>,
) -> Result<WalletMailReadLatestResult, String> {
    let result = commands::wallet_mail_read_latest(
        state,
        policy_manager.clone(),
        channel_id,
        lease_id,
        op_seq,
        mailbox,
        shield_approved,
    )
    .await;
    let _ = app.emit(
        SHIELD_APPROVAL_MEMORY_UPDATED_EVENT,
        policy_manager.approval_snapshot(),
    );
    result
}

#[tauri::command]
pub async fn wallet_mail_list_recent(
    app: AppHandle,
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, ShieldPolicyManager>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    limit: Option<u32>,
    shield_approved: Option<bool>,
) -> Result<WalletMailListRecentResult, String> {
    let result = commands::wallet_mail_list_recent(
        state,
        policy_manager.clone(),
        channel_id,
        lease_id,
        op_seq,
        mailbox,
        limit,
        shield_approved,
    )
    .await;
    let _ = app.emit(
        SHIELD_APPROVAL_MEMORY_UPDATED_EVENT,
        policy_manager.approval_snapshot(),
    );
    result
}

#[tauri::command]
pub async fn wallet_mail_delete_spam(
    app: AppHandle,
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, ShieldPolicyManager>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    max_delete: Option<u32>,
    shield_approved: Option<bool>,
) -> Result<WalletMailDeleteSpamResult, String> {
    let result = commands::wallet_mail_delete_spam(
        state,
        policy_manager.clone(),
        channel_id,
        lease_id,
        op_seq,
        mailbox,
        max_delete,
        shield_approved,
    )
    .await;
    let _ = app.emit(
        SHIELD_APPROVAL_MEMORY_UPDATED_EVENT,
        policy_manager.approval_snapshot(),
    );
    result
}

#[tauri::command]
pub async fn wallet_mail_reply(
    app: AppHandle,
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, ShieldPolicyManager>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    to: String,
    subject: String,
    body: String,
    reply_to_message_id: Option<String>,
    shield_approved: Option<bool>,
) -> Result<WalletMailReplyResult, String> {
    let result = commands::wallet_mail_reply(
        state,
        policy_manager.clone(),
        channel_id,
        lease_id,
        op_seq,
        mailbox,
        to,
        subject,
        body,
        reply_to_message_id,
        shield_approved,
    )
    .await;
    let _ = app.emit(
        SHIELD_APPROVAL_MEMORY_UPDATED_EVENT,
        policy_manager.approval_snapshot(),
    );
    result
}

#[tauri::command]
pub async fn wallet_connector_auth_get(
    state: State<'_, Mutex<AppState>>,
    connector_id: String,
) -> Result<WalletConnectorAuthGetResult, String> {
    auth::wallet_connector_auth_get(state, connector_id).await
}

#[tauri::command]
pub async fn wallet_connector_auth_list(
    state: State<'_, Mutex<AppState>>,
    provider_family: Option<String>,
) -> Result<WalletConnectorAuthListResult, String> {
    auth::wallet_connector_auth_list(state, provider_family).await
}

#[tauri::command]
pub async fn wallet_connector_auth_export(
    state: State<'_, Mutex<AppState>>,
    connector_ids: Option<Vec<String>>,
    passphrase: String,
) -> Result<WalletConnectorAuthExportResult, String> {
    auth::wallet_connector_auth_export(state, connector_ids, passphrase).await
}

#[tauri::command]
pub async fn wallet_connector_auth_import(
    state: State<'_, Mutex<AppState>>,
    bundle_base64: String,
    passphrase: String,
    replace_existing: Option<bool>,
) -> Result<WalletConnectorAuthImportResult, String> {
    auth::wallet_connector_auth_import(state, bundle_base64, passphrase, replace_existing).await
}

#[tauri::command]
pub async fn connector_list_actions(
    connector_id: String,
) -> Result<Vec<google_workspace::ConnectorActionDefinition>, String> {
    if let Some(actions) = generic_connector_mock_actions(&connector_id) {
        return Ok(actions);
    }
    google_workspace::connector_list_actions(connector_id).await
}

#[tauri::command]
pub async fn connector_configure(
    state: State<'_, Mutex<AppState>>,
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    input: Value,
) -> Result<google_workspace::ConnectorConfigureResult, String> {
    if let Some(result) = generic_connector_mock_configure_result(&connector_id) {
        return Ok(result);
    }
    google_workspace::connector_configure(state, manager, connector_id, input).await
}

#[tauri::command]
pub async fn connector_run_action(
    app: AppHandle,
    manager: State<'_, GoogleAutomationManager>,
    policy_manager: State<'_, ShieldPolicyManager>,
    connector_id: String,
    action_id: String,
    input: Value,
) -> Result<google_workspace::ConnectorActionResult, String> {
    if let Some(result) = generic_connector_mock_action_result(&connector_id, &action_id, &input) {
        return Ok(result);
    }
    let result = google_workspace::connector_run_action(
        manager,
        policy_manager.clone(),
        connector_id,
        action_id,
        input,
    )
    .await;
    let _ = app.emit(
        SHIELD_APPROVAL_MEMORY_UPDATED_EVENT,
        policy_manager.approval_snapshot(),
    );
    result
}

#[tauri::command]
pub async fn connector_list_subscriptions(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
) -> Result<Vec<GoogleConnectorSubscriptionView>, String> {
    google_workspace::connector_list_subscriptions(manager, connector_id).await
}

#[tauri::command]
pub async fn connector_stop_subscription(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    subscription_id: String,
) -> Result<GoogleConnectorSubscriptionView, String> {
    google_workspace::connector_stop_subscription(manager, connector_id, subscription_id).await
}

#[tauri::command]
pub async fn connector_resume_subscription(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    subscription_id: String,
) -> Result<GoogleConnectorSubscriptionView, String> {
    google_workspace::connector_resume_subscription(manager, connector_id, subscription_id).await
}

#[tauri::command]
pub async fn connector_renew_subscription(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    subscription_id: String,
) -> Result<GoogleConnectorSubscriptionView, String> {
    google_workspace::connector_renew_subscription(manager, connector_id, subscription_id).await
}

#[tauri::command]
pub async fn connector_get_subscription(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    subscription_id: String,
) -> Result<GoogleConnectorSubscriptionView, String> {
    google_workspace::connector_get_subscription(manager, connector_id, subscription_id).await
}

#[tauri::command]
pub async fn connector_fetch_gmail_thread(
    policy_manager: State<'_, ShieldPolicyManager>,
    connector_id: String,
    thread_id: String,
) -> Result<google_workspace::ConnectorActionResult, String> {
    google_workspace::connector_fetch_gmail_thread(policy_manager, connector_id, thread_id).await
}

#[tauri::command]
pub async fn connector_fetch_calendar_event(
    policy_manager: State<'_, ShieldPolicyManager>,
    connector_id: String,
    calendar_id: String,
    event_id: String,
) -> Result<google_workspace::ConnectorActionResult, String> {
    google_workspace::connector_fetch_calendar_event(
        policy_manager,
        connector_id,
        calendar_id,
        event_id,
    )
    .await
}

#[tauri::command]
pub async fn connector_policy_get(
    state: State<'_, Mutex<AppState>>,
    manager: State<'_, ShieldPolicyManager>,
) -> Result<ShieldPolicyState, String> {
    policy::current_policy_state(state, manager).await
}

#[tauri::command]
pub async fn connector_policy_set(
    state: State<'_, Mutex<AppState>>,
    manager: State<'_, ShieldPolicyManager>,
    policy: ShieldPolicyState,
) -> Result<ShieldPolicyState, String> {
    policy::replace_policy_state(state, manager, policy).await
}

#[tauri::command]
pub async fn connector_policy_memory_get(
    manager: State<'_, ShieldPolicyManager>,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    policy::current_remembered_approval_snapshot(manager).await
}

#[tauri::command]
pub async fn connector_policy_memory_remember(
    app: AppHandle,
    manager: State<'_, ShieldPolicyManager>,
    input: ShieldRememberApprovalInput,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    let snapshot = policy::remember_approval_in_runtime(manager, input).await?;
    let _ = app.emit(SHIELD_APPROVAL_MEMORY_UPDATED_EVENT, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub async fn connector_policy_memory_forget(
    app: AppHandle,
    manager: State<'_, ShieldPolicyManager>,
    decision_id: String,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    let snapshot = policy::forget_approval_in_runtime(manager, decision_id).await?;
    let _ = app.emit(SHIELD_APPROVAL_MEMORY_UPDATED_EVENT, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub async fn connector_policy_memory_set_scope_mode(
    app: AppHandle,
    manager: State<'_, ShieldPolicyManager>,
    input: ShieldRememberedApprovalScopeUpdateInput,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    let snapshot = policy::update_approval_scope_mode_in_runtime(manager, input).await?;
    let _ = app.emit(SHIELD_APPROVAL_MEMORY_UPDATED_EVENT, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub async fn connector_policy_memory_set_expiry(
    app: AppHandle,
    manager: State<'_, ShieldPolicyManager>,
    input: ShieldRememberedApprovalExpiryUpdateInput,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    let snapshot = policy::update_approval_expiry_in_runtime(manager, input).await?;
    let _ = app.emit(SHIELD_APPROVAL_MEMORY_UPDATED_EVENT, &snapshot);
    Ok(snapshot)
}
