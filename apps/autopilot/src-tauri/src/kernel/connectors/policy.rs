use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const POLICY_VERSION: u8 = 1;
const POLICY_APPROVAL_PREFIX: &str = "SHIELD_APPROVAL_REQUIRED:";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionMode {
    Auto,
    Confirm,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutomationPolicyMode {
    ConfirmOnCreate,
    ConfirmOnRun,
    ManualOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataHandlingMode {
    LocalOnly,
    LocalRedacted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalPolicyDefaults {
    pub reads: PolicyDecisionMode,
    pub writes: PolicyDecisionMode,
    pub admin: PolicyDecisionMode,
    pub expert: PolicyDecisionMode,
    pub automations: AutomationPolicyMode,
    pub data_handling: DataHandlingMode,
}

impl Default for GlobalPolicyDefaults {
    fn default() -> Self {
        Self {
            reads: PolicyDecisionMode::Auto,
            writes: PolicyDecisionMode::Confirm,
            admin: PolicyDecisionMode::Confirm,
            expert: PolicyDecisionMode::Block,
            automations: AutomationPolicyMode::ConfirmOnCreate,
            data_handling: DataHandlingMode::LocalOnly,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorPolicyOverride {
    pub inherit_global: bool,
    pub reads: PolicyDecisionMode,
    pub writes: PolicyDecisionMode,
    pub admin: PolicyDecisionMode,
    pub expert: PolicyDecisionMode,
    pub automations: AutomationPolicyMode,
    pub data_handling: DataHandlingMode,
}

impl ConnectorPolicyOverride {
    fn inheriting(defaults: &GlobalPolicyDefaults) -> Self {
        Self {
            inherit_global: true,
            reads: defaults.reads.clone(),
            writes: defaults.writes.clone(),
            admin: defaults.admin.clone(),
            expert: defaults.expert.clone(),
            automations: defaults.automations.clone(),
            data_handling: defaults.data_handling.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldPolicyState {
    pub version: u8,
    pub global: GlobalPolicyDefaults,
    #[serde(default)]
    pub overrides: HashMap<String, ConnectorPolicyOverride>,
}

impl Default for ShieldPolicyState {
    fn default() -> Self {
        Self {
            version: POLICY_VERSION,
            global: GlobalPolicyDefaults::default(),
            overrides: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedConnectorPolicy {
    pub reads: PolicyDecisionMode,
    pub writes: PolicyDecisionMode,
    pub admin: PolicyDecisionMode,
    pub expert: PolicyDecisionMode,
    pub automations: AutomationPolicyMode,
    pub data_handling: DataHandlingMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldApprovalRequest {
    pub connector_id: String,
    pub action_id: String,
    pub action_label: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ShieldPolicyManager {
    path: Arc<PathBuf>,
    state: Arc<Mutex<ShieldPolicyState>>,
}

impl ShieldPolicyManager {
    pub fn new(path: PathBuf) -> Self {
        let state = load_policy_state(&path).unwrap_or_default();
        Self {
            path: Arc::new(path),
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn current_state(&self) -> ShieldPolicyState {
        self.state
            .lock()
            .expect("shield policy lock poisoned")
            .clone()
    }

    pub fn replace_state(&self, next_state: ShieldPolicyState) -> Result<ShieldPolicyState, String> {
        let normalized = normalize_policy_state(next_state);
        persist_policy_state(&self.path, &normalized)?;
        let mut state = self.state.lock().expect("shield policy lock poisoned");
        *state = normalized.clone();
        Ok(normalized)
    }

    pub fn resolve_connector_policy(&self, connector_id: &str) -> ResolvedConnectorPolicy {
        let state = self.state.lock().expect("shield policy lock poisoned");
        resolve_connector_policy_from_state(&state, connector_id)
    }
}

fn normalize_policy_state(input: ShieldPolicyState) -> ShieldPolicyState {
    let global = input.global;
    let overrides = input
        .overrides
        .into_iter()
        .map(|(connector_id, override_state)| {
            let normalized = ConnectorPolicyOverride {
                inherit_global: override_state.inherit_global,
                reads: override_state.reads,
                writes: override_state.writes,
                admin: override_state.admin,
                expert: override_state.expert,
                automations: override_state.automations,
                data_handling: override_state.data_handling,
            };
            (connector_id, normalized)
        })
        .collect();

    ShieldPolicyState {
        version: POLICY_VERSION,
        global,
        overrides,
    }
}

fn resolve_connector_policy_from_state(
    state: &ShieldPolicyState,
    connector_id: &str,
) -> ResolvedConnectorPolicy {
    let defaults = &state.global;
    let override_state = state
        .overrides
        .get(connector_id)
        .cloned()
        .unwrap_or_else(|| ConnectorPolicyOverride::inheriting(defaults));

    if override_state.inherit_global {
        return ResolvedConnectorPolicy {
            reads: defaults.reads.clone(),
            writes: defaults.writes.clone(),
            admin: defaults.admin.clone(),
            expert: defaults.expert.clone(),
            automations: defaults.automations.clone(),
            data_handling: defaults.data_handling.clone(),
        };
    }

    ResolvedConnectorPolicy {
        reads: override_state.reads,
        writes: override_state.writes,
        admin: override_state.admin,
        expert: override_state.expert,
        automations: override_state.automations,
        data_handling: override_state.data_handling,
    }
}

fn load_policy_state(path: &Path) -> Result<ShieldPolicyState, String> {
    let raw = fs::read_to_string(path).map_err(|error| format!("Failed to read Shield policy: {}", error))?;
    let parsed: ShieldPolicyState =
        serde_json::from_str(&raw).map_err(|error| format!("Failed to parse Shield policy: {}", error))?;
    Ok(normalize_policy_state(parsed))
}

fn persist_policy_state(path: &Path, state: &ShieldPolicyState) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create Shield policy directory: {}", error))?;
    }
    let raw = serde_json::to_vec_pretty(state)
        .map_err(|error| format!("Failed to serialize Shield policy: {}", error))?;
    fs::write(path, raw).map_err(|error| format!("Failed to persist Shield policy: {}", error))?;
    Ok(())
}

pub fn policy_state_path_for(data_dir: &Path) -> PathBuf {
    data_dir.join("shield_policy.json")
}

pub fn current_policy_state(
    manager: tauri::State<'_, ShieldPolicyManager>,
) -> Result<ShieldPolicyState, String> {
    Ok(manager.current_state())
}

pub fn replace_policy_state(
    manager: tauri::State<'_, ShieldPolicyManager>,
    policy: ShieldPolicyState,
) -> Result<ShieldPolicyState, String> {
    manager.replace_state(policy)
}

pub fn approval_marker_present(input: &serde_json::Value) -> bool {
    input
        .get("_shieldApproved")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

pub fn approval_required_error(request: &ShieldApprovalRequest) -> String {
    let payload = serde_json::to_string(request).unwrap_or_else(|_| {
        "{\"connectorId\":\"unknown\",\"actionId\":\"unknown\",\"actionLabel\":\"Approval required\",\"message\":\"Shield policy requires explicit approval before this action can run.\"}".to_string()
    });
    format!("{}{}", POLICY_APPROVAL_PREFIX, payload)
}

pub fn parse_approval_error(message: &str) -> Option<&str> {
    message
        .split_once(POLICY_APPROVAL_PREFIX)
        .map(|(_, payload)| payload)
}
