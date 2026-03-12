use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const GOOGLE_CONNECTOR_ID: &str = "google.workspace";
pub const GOOGLE_CONNECTOR_PROVIDER: &str = "google";
pub(super) const GWS_DEFAULT_TIMEOUT_SECS: u64 = 120;
pub(super) const BIGQUERY_TOOL_NAME: &str = "connector__google__bigquery_execute_query";
pub(super) const BIGQUERY_READ_TARGET: &str = "connector__google__bigquery_execute_query__read";
pub(super) const BIGQUERY_WRITE_TARGET: &str = "connector__google__bigquery_execute_query__write";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorFieldOption {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorFieldDefinition {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(default)]
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<ConnectorFieldOption>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorActionDefinition {
    pub id: String,
    pub service: String,
    pub service_label: String,
    pub tool_name: String,
    pub label: String,
    pub description: String,
    pub kind: String,
    #[serde(default)]
    pub confirm_before_run: bool,
    pub fields: Vec<ConnectorFieldDefinition>,
    #[serde(default)]
    pub required_scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorActionResult {
    pub connector_id: String,
    pub action_id: String,
    pub tool_name: String,
    pub provider: String,
    pub summary: String,
    pub data: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_output: Option<String>,
    pub executed_at_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorConfigureResult {
    pub connector_id: String,
    pub provider: String,
    pub status: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    pub executed_at_utc: String,
}

#[derive(Debug)]
pub(super) struct GwsCommandOutput {
    pub(super) stdout: String,
}

#[derive(Debug, Clone)]
pub(super) struct GoogleConnectorActionSpec {
    pub(super) id: &'static str,
    pub(super) service: &'static str,
    pub(super) service_label: &'static str,
    pub(super) tool_name: &'static str,
    pub(super) label: &'static str,
    pub(super) description: &'static str,
    pub(super) kind: &'static str,
    pub(super) confirm_before_run: bool,
    pub(super) required_scopes: &'static [&'static str],
    pub(super) capabilities: &'static [&'static str],
    pub(super) fields: Vec<ConnectorFieldDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ShieldDecisionMode {
    Auto,
    Confirm,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ShieldAutomationMode {
    ConfirmOnCreate,
    ConfirmOnRun,
    ManualOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ShieldDataHandlingMode {
    LocalOnly,
    LocalRedacted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ShieldGlobalPolicyDefaults {
    pub(super) reads: ShieldDecisionMode,
    pub(super) writes: ShieldDecisionMode,
    pub(super) admin: ShieldDecisionMode,
    pub(super) expert: ShieldDecisionMode,
    pub(super) automations: ShieldAutomationMode,
    pub(super) data_handling: ShieldDataHandlingMode,
}

impl Default for ShieldGlobalPolicyDefaults {
    fn default() -> Self {
        Self {
            reads: ShieldDecisionMode::Auto,
            writes: ShieldDecisionMode::Confirm,
            admin: ShieldDecisionMode::Confirm,
            expert: ShieldDecisionMode::Block,
            automations: ShieldAutomationMode::ConfirmOnCreate,
            data_handling: ShieldDataHandlingMode::LocalOnly,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ShieldConnectorPolicyOverride {
    #[serde(default = "default_true")]
    pub(super) inherit_global: bool,
    pub(super) reads: ShieldDecisionMode,
    pub(super) writes: ShieldDecisionMode,
    pub(super) admin: ShieldDecisionMode,
    pub(super) expert: ShieldDecisionMode,
    pub(super) automations: ShieldAutomationMode,
    pub(super) data_handling: ShieldDataHandlingMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ShieldPolicyState {
    #[allow(dead_code)]
    pub(super) version: u8,
    #[serde(default)]
    pub(super) global: ShieldGlobalPolicyDefaults,
    #[serde(default)]
    pub(super) overrides: std::collections::BTreeMap<String, ShieldConnectorPolicyOverride>,
}

impl Default for ShieldPolicyState {
    fn default() -> Self {
        Self {
            version: 1,
            global: ShieldGlobalPolicyDefaults::default(),
            overrides: std::collections::BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedShieldPolicy {
    pub(super) reads: ShieldDecisionMode,
    pub(super) writes: ShieldDecisionMode,
    pub(super) admin: ShieldDecisionMode,
    pub(super) expert: ShieldDecisionMode,
    pub(super) automations: ShieldAutomationMode,
}

fn default_true() -> bool {
    true
}
