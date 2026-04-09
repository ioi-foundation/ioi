use super::google_workspace::{
    ConnectorActionDefinition, ConnectorActionResult, ConnectorConfigureResult,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

pub const CONNECTOR_MOCK_FIXTURE_PATH_ENV: &str = "IOI_CONNECTOR_MOCK_FIXTURE_PATH";
pub const LEGACY_GOOGLE_MOCK_FIXTURE_PATH_ENV: &str = "IOI_GOOGLE_MOCK_FIXTURE_PATH";
pub const LEGACY_MAIL_MOCK_FIXTURE_PATH_ENV: &str = "IOI_MAIL_MOCK_FIXTURE_PATH";
pub const LEGACY_GENERIC_CONNECTOR_MOCK_FIXTURE_PATH_ENV: &str =
    "IOI_GENERIC_CONNECTOR_MOCK_FIXTURE_PATH";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorMockFixtureContract {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub google: Option<GoogleConnectorMockFixture>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<MailConnectorMockFixture>,
    #[serde(default)]
    pub connectors: Vec<GenericConnectorMockRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleConnectorMockFixture {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<GoogleAuthMockFixture>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleAuthMockFixture {
    pub account_email: String,
    #[serde(default)]
    pub granted_scopes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailConnectorMockFixture {
    #[serde(default)]
    pub accounts: Vec<MailAccountMockFixture>,
    #[serde(default)]
    pub messages_by_mailbox: BTreeMap<String, Vec<MailMessageMockFixture>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailAccountMockFixture {
    pub mailbox: String,
    pub account_email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_channel_id_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_lease_id_hex: Option<String>,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailMessageMockFixture {
    pub message_id: String,
    pub from: String,
    pub subject: String,
    pub received_at_ms: u64,
    pub preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MockConnectorCatalogEntry {
    pub id: String,
    pub plugin_id: String,
    pub name: String,
    pub provider: String,
    pub category: String,
    pub description: String,
    pub status: String,
    pub auth_mode: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync_at_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenericConnectorMockRecord {
    pub catalog: MockConnectorCatalogEntry,
    #[serde(default)]
    pub actions: Vec<ConnectorActionDefinition>,
    #[serde(default)]
    pub configure_result: Option<ConnectorConfigureResult>,
    #[serde(default)]
    pub action_results: BTreeMap<String, ConnectorActionResult>,
}

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &PathBuf, label: &str) -> Result<T, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read {} '{}': {}", label, path.display(), error))?;
    serde_json::from_str::<T>(&raw)
        .map_err(|error| format!("Failed to parse {} '{}': {}", label, path.display(), error))
}

fn load_unified_fixture() -> Result<Option<ConnectorMockFixtureContract>, String> {
    let Some(path) = env_path(CONNECTOR_MOCK_FIXTURE_PATH_ENV) else {
        return Ok(None);
    };
    read_json_file(&path, "connector mock fixture").map(Some)
}

fn load_legacy_google_fixture() -> Result<Option<GoogleAuthMockFixture>, String> {
    let Some(path) = env_path(LEGACY_GOOGLE_MOCK_FIXTURE_PATH_ENV) else {
        return Ok(None);
    };
    read_json_file(&path, "legacy Google mock fixture").map(Some)
}

fn load_legacy_mail_fixture() -> Result<Option<MailConnectorMockFixture>, String> {
    let Some(path) = env_path(LEGACY_MAIL_MOCK_FIXTURE_PATH_ENV) else {
        return Ok(None);
    };
    read_json_file(&path, "legacy Mail mock fixture").map(Some)
}

fn load_legacy_generic_fixture() -> Result<Option<ConnectorMockFixtureContract>, String> {
    let Some(path) = env_path(LEGACY_GENERIC_CONNECTOR_MOCK_FIXTURE_PATH_ENV) else {
        return Ok(None);
    };
    read_json_file(&path, "legacy generic connector mock fixture").map(Some)
}

pub fn load_connector_mock_fixture_contract() -> Result<Option<ConnectorMockFixtureContract>, String>
{
    let mut fixture = load_unified_fixture()?.unwrap_or_default();
    let mut has_any =
        fixture.google.is_some() || fixture.mail.is_some() || !fixture.connectors.is_empty();

    if fixture
        .google
        .as_ref()
        .and_then(|google| google.auth.as_ref())
        .is_none()
    {
        if let Some(legacy_google) = load_legacy_google_fixture()? {
            fixture
                .google
                .get_or_insert_with(GoogleConnectorMockFixture::default)
                .auth = Some(legacy_google);
            has_any = true;
        }
    }

    if fixture.mail.is_none() {
        if let Some(legacy_mail) = load_legacy_mail_fixture()? {
            fixture.mail = Some(legacy_mail);
            has_any = true;
        }
    }

    if let Some(legacy_generic) = load_legacy_generic_fixture()? {
        if fixture.connectors.is_empty() {
            fixture.connectors = legacy_generic.connectors;
        } else {
            for record in legacy_generic.connectors {
                fixture
                    .connectors
                    .retain(|existing| existing.catalog.id != record.catalog.id);
                fixture.connectors.push(record);
            }
        }
        has_any = true;
    }

    if has_any {
        Ok(Some(fixture))
    } else {
        Ok(None)
    }
}

pub fn google_auth_mock_fixture() -> Result<Option<GoogleAuthMockFixture>, String> {
    Ok(load_connector_mock_fixture_contract()?
        .and_then(|fixture| fixture.google)
        .and_then(|google| google.auth))
}

pub fn google_bootstrap_mock_fixture() -> Result<Option<Value>, String> {
    Ok(load_connector_mock_fixture_contract()?
        .and_then(|fixture| fixture.google)
        .and_then(|google| google.bootstrap))
}

pub fn google_mock_fixture_active() -> bool {
    load_connector_mock_fixture_contract()
        .ok()
        .flatten()
        .and_then(|fixture| fixture.google)
        .is_some()
}

pub fn mail_mock_fixture() -> Result<Option<MailConnectorMockFixture>, String> {
    Ok(load_connector_mock_fixture_contract()?.and_then(|fixture| fixture.mail))
}

pub fn generic_connector_mock_records() -> Result<Vec<GenericConnectorMockRecord>, String> {
    Ok(load_connector_mock_fixture_contract()?
        .map(|fixture| fixture.connectors)
        .unwrap_or_default())
}
