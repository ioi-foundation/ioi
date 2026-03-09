use super::auth::wallet_connector_auth_list_inner;
use super::rpc::{build_wallet_call_tx, query_wallet_state_optional, submit_tx_and_wait};
use crate::kernel::state::get_rpc_client;
use crate::models::AppState;
use ioi_types::app::{ActionTarget, VaultPolicyRule};
use ioi_types::codec;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::State;

const POLICY_VERSION: u8 = 1;
const POLICY_APPROVAL_PREFIX: &str = "SHIELD_APPROVAL_REQUIRED:";
const POLICY_RULE_PREFIX: &[u8] = b"policy::";
const SHIELD_POLICY_RULE_PREFIX: &str = "shield_policy::";
const SHIELD_POLICY_OVERRIDE_ROSTER_RULE_ID: &str = "shield_policy::meta::override_roster";
const POLICY_FIELD_READS: &str = "reads";
const POLICY_FIELD_WRITES: &str = "writes";
const POLICY_FIELD_ADMIN: &str = "admin";
const POLICY_FIELD_EXPERT: &str = "expert";
const POLICY_FIELD_AUTOMATIONS: &str = "automations";
const POLICY_FIELD_DATA_HANDLING: &str = "data_handling";
const POLICY_FIELD_INHERIT_GLOBAL: &str = "inherit_global";

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

    pub fn replace_state(
        &self,
        next_state: ShieldPolicyState,
    ) -> Result<ShieldPolicyState, String> {
        let normalized = normalize_policy_state(next_state);
        persist_policy_state(&self.path, &normalized)?;
        let mut state = self.state.lock().expect("shield policy lock poisoned");
        *state = normalized.clone();
        Ok(normalized)
    }

    pub fn reset_to_default(&self) -> Result<ShieldPolicyState, String> {
        self.replace_state(ShieldPolicyState::default())
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
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read Shield policy: {}", error))?;
    let parsed: ShieldPolicyState = serde_json::from_str(&raw)
        .map_err(|error| format!("Failed to parse Shield policy: {}", error))?;
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

fn global_policy_fields() -> [&'static str; 6] {
    [
        POLICY_FIELD_READS,
        POLICY_FIELD_WRITES,
        POLICY_FIELD_ADMIN,
        POLICY_FIELD_EXPERT,
        POLICY_FIELD_AUTOMATIONS,
        POLICY_FIELD_DATA_HANDLING,
    ]
}

fn connector_policy_fields() -> [&'static str; 7] {
    [
        POLICY_FIELD_INHERIT_GLOBAL,
        POLICY_FIELD_READS,
        POLICY_FIELD_WRITES,
        POLICY_FIELD_ADMIN,
        POLICY_FIELD_EXPERT,
        POLICY_FIELD_AUTOMATIONS,
        POLICY_FIELD_DATA_HANDLING,
    ]
}

fn policy_rule_key(rule_id: &str) -> Vec<u8> {
    [POLICY_RULE_PREFIX, rule_id.as_bytes()].concat()
}

fn encode_connector_rule_scope(connector_id: &str) -> String {
    hex::encode(connector_id.as_bytes())
}

fn decode_connector_rule_scope(raw: &str) -> Option<String> {
    String::from_utf8(hex::decode(raw).ok()?).ok()
}

fn global_rule_id(field: &str) -> String {
    format!("{SHIELD_POLICY_RULE_PREFIX}global::{field}")
}

fn connector_rule_id(connector_id: &str, field: &str) -> String {
    format!(
        "{SHIELD_POLICY_RULE_PREFIX}connector::{}::{field}",
        encode_connector_rule_scope(connector_id)
    )
}

fn decision_mode_value(value: &PolicyDecisionMode) -> &'static str {
    match value {
        PolicyDecisionMode::Auto => "auto",
        PolicyDecisionMode::Confirm => "confirm",
        PolicyDecisionMode::Block => "block",
    }
}

fn parse_decision_mode(value: &str) -> Option<PolicyDecisionMode> {
    match value {
        "auto" => Some(PolicyDecisionMode::Auto),
        "confirm" => Some(PolicyDecisionMode::Confirm),
        "block" => Some(PolicyDecisionMode::Block),
        _ => None,
    }
}

fn automation_mode_value(value: &AutomationPolicyMode) -> &'static str {
    match value {
        AutomationPolicyMode::ConfirmOnCreate => "confirm_on_create",
        AutomationPolicyMode::ConfirmOnRun => "confirm_on_run",
        AutomationPolicyMode::ManualOnly => "manual_only",
    }
}

fn parse_automation_mode(value: &str) -> Option<AutomationPolicyMode> {
    match value {
        "confirm_on_create" => Some(AutomationPolicyMode::ConfirmOnCreate),
        "confirm_on_run" => Some(AutomationPolicyMode::ConfirmOnRun),
        "manual_only" => Some(AutomationPolicyMode::ManualOnly),
        _ => None,
    }
}

fn data_handling_value(value: &DataHandlingMode) -> &'static str {
    match value {
        DataHandlingMode::LocalOnly => "local_only",
        DataHandlingMode::LocalRedacted => "local_redacted",
    }
}

fn parse_data_handling_mode(value: &str) -> Option<DataHandlingMode> {
    match value {
        "local_only" => Some(DataHandlingMode::LocalOnly),
        "local_redacted" => Some(DataHandlingMode::LocalRedacted),
        _ => None,
    }
}

fn policy_rule_value(rule: &VaultPolicyRule) -> Option<&str> {
    rule.domain_allowlist
        .iter()
        .find_map(|entry| entry.strip_prefix("value:"))
}

fn shield_policy_rule(rule_id: String, label: String, value: String) -> VaultPolicyRule {
    VaultPolicyRule {
        rule_id: rule_id.clone(),
        label,
        target: ActionTarget::Custom(rule_id),
        auto_approve: matches!(value.as_str(), "auto" | "true" | "local_only"),
        max_value_usd_micros: None,
        max_ttl_secs: None,
        domain_allowlist: vec![format!("value:{value}")],
    }
}

fn wallet_policy_rules_from_state(state: &ShieldPolicyState) -> Vec<VaultPolicyRule> {
    let mut rules = vec![
        shield_policy_rule(
            global_rule_id(POLICY_FIELD_READS),
            "Shield policy global reads".to_string(),
            decision_mode_value(&state.global.reads).to_string(),
        ),
        shield_policy_rule(
            global_rule_id(POLICY_FIELD_WRITES),
            "Shield policy global writes".to_string(),
            decision_mode_value(&state.global.writes).to_string(),
        ),
        shield_policy_rule(
            global_rule_id(POLICY_FIELD_ADMIN),
            "Shield policy global admin".to_string(),
            decision_mode_value(&state.global.admin).to_string(),
        ),
        shield_policy_rule(
            global_rule_id(POLICY_FIELD_EXPERT),
            "Shield policy global expert".to_string(),
            decision_mode_value(&state.global.expert).to_string(),
        ),
        shield_policy_rule(
            global_rule_id(POLICY_FIELD_AUTOMATIONS),
            "Shield policy global automations".to_string(),
            automation_mode_value(&state.global.automations).to_string(),
        ),
        shield_policy_rule(
            global_rule_id(POLICY_FIELD_DATA_HANDLING),
            "Shield policy global data handling".to_string(),
            data_handling_value(&state.global.data_handling).to_string(),
        ),
    ];

    let mut connector_ids = state.overrides.keys().cloned().collect::<Vec<_>>();
    connector_ids.sort();
    rules.push(VaultPolicyRule {
        rule_id: SHIELD_POLICY_OVERRIDE_ROSTER_RULE_ID.to_string(),
        label: "Shield policy override roster".to_string(),
        target: ActionTarget::Custom(SHIELD_POLICY_OVERRIDE_ROSTER_RULE_ID.to_string()),
        auto_approve: false,
        max_value_usd_micros: None,
        max_ttl_secs: None,
        domain_allowlist: connector_ids
            .iter()
            .map(|connector_id| format!("value:{}", encode_connector_rule_scope(connector_id)))
            .collect(),
    });

    for connector_id in connector_ids {
        let override_state = state
            .overrides
            .get(&connector_id)
            .expect("connector override must exist");
        let scope_label = format!("Shield policy override {connector_id}");
        rules.push(shield_policy_rule(
            connector_rule_id(&connector_id, POLICY_FIELD_INHERIT_GLOBAL),
            format!("{scope_label} inherit global"),
            override_state.inherit_global.to_string(),
        ));
        rules.push(shield_policy_rule(
            connector_rule_id(&connector_id, POLICY_FIELD_READS),
            format!("{scope_label} reads"),
            decision_mode_value(&override_state.reads).to_string(),
        ));
        rules.push(shield_policy_rule(
            connector_rule_id(&connector_id, POLICY_FIELD_WRITES),
            format!("{scope_label} writes"),
            decision_mode_value(&override_state.writes).to_string(),
        ));
        rules.push(shield_policy_rule(
            connector_rule_id(&connector_id, POLICY_FIELD_ADMIN),
            format!("{scope_label} admin"),
            decision_mode_value(&override_state.admin).to_string(),
        ));
        rules.push(shield_policy_rule(
            connector_rule_id(&connector_id, POLICY_FIELD_EXPERT),
            format!("{scope_label} expert"),
            decision_mode_value(&override_state.expert).to_string(),
        ));
        rules.push(shield_policy_rule(
            connector_rule_id(&connector_id, POLICY_FIELD_AUTOMATIONS),
            format!("{scope_label} automations"),
            automation_mode_value(&override_state.automations).to_string(),
        ));
        rules.push(shield_policy_rule(
            connector_rule_id(&connector_id, POLICY_FIELD_DATA_HANDLING),
            format!("{scope_label} data handling"),
            data_handling_value(&override_state.data_handling).to_string(),
        ));
    }

    rules
}

fn wallet_policy_state_from_rules(rules: &[VaultPolicyRule]) -> Option<ShieldPolicyState> {
    if rules.is_empty() {
        return None;
    }

    let mut global = GlobalPolicyDefaults::default();
    let mut override_roster = BTreeSet::new();
    let mut connector_fields: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut saw_any = false;

    for rule in rules {
        let Some(value) = policy_rule_value(rule) else {
            continue;
        };
        match rule.rule_id.as_str() {
            SHIELD_POLICY_OVERRIDE_ROSTER_RULE_ID => {
                saw_any = true;
                for entry in &rule.domain_allowlist {
                    let Some(encoded_connector) = entry.strip_prefix("value:") else {
                        continue;
                    };
                    if let Some(connector_id) = decode_connector_rule_scope(encoded_connector) {
                        override_roster.insert(connector_id);
                    }
                }
            }
            _ => {
                if let Some(field) = rule.rule_id.strip_prefix("shield_policy::global::") {
                    saw_any = true;
                    match field {
                        POLICY_FIELD_READS => {
                            if let Some(parsed) = parse_decision_mode(value) {
                                global.reads = parsed;
                            }
                        }
                        POLICY_FIELD_WRITES => {
                            if let Some(parsed) = parse_decision_mode(value) {
                                global.writes = parsed;
                            }
                        }
                        POLICY_FIELD_ADMIN => {
                            if let Some(parsed) = parse_decision_mode(value) {
                                global.admin = parsed;
                            }
                        }
                        POLICY_FIELD_EXPERT => {
                            if let Some(parsed) = parse_decision_mode(value) {
                                global.expert = parsed;
                            }
                        }
                        POLICY_FIELD_AUTOMATIONS => {
                            if let Some(parsed) = parse_automation_mode(value) {
                                global.automations = parsed;
                            }
                        }
                        POLICY_FIELD_DATA_HANDLING => {
                            if let Some(parsed) = parse_data_handling_mode(value) {
                                global.data_handling = parsed;
                            }
                        }
                        _ => {}
                    }
                    continue;
                }

                let Some(rest) = rule.rule_id.strip_prefix("shield_policy::connector::") else {
                    continue;
                };
                let Some((encoded_connector, field)) = rest.split_once("::") else {
                    continue;
                };
                let Some(connector_id) = decode_connector_rule_scope(encoded_connector) else {
                    continue;
                };
                saw_any = true;
                connector_fields
                    .entry(connector_id)
                    .or_default()
                    .insert(field.to_string(), value.to_string());
            }
        }
    }

    if !saw_any {
        return None;
    }

    let mut overrides = HashMap::new();
    for connector_id in override_roster {
        let fields = connector_fields.remove(&connector_id).unwrap_or_default();
        let mut override_state = ConnectorPolicyOverride::inheriting(&global);
        if let Some(value) = fields.get(POLICY_FIELD_INHERIT_GLOBAL) {
            override_state.inherit_global = matches!(value.as_str(), "true");
        }
        if let Some(value) = fields
            .get(POLICY_FIELD_READS)
            .and_then(|value| parse_decision_mode(value))
        {
            override_state.reads = value;
        }
        if let Some(value) = fields
            .get(POLICY_FIELD_WRITES)
            .and_then(|value| parse_decision_mode(value))
        {
            override_state.writes = value;
        }
        if let Some(value) = fields
            .get(POLICY_FIELD_ADMIN)
            .and_then(|value| parse_decision_mode(value))
        {
            override_state.admin = value;
        }
        if let Some(value) = fields
            .get(POLICY_FIELD_EXPERT)
            .and_then(|value| parse_decision_mode(value))
        {
            override_state.expert = value;
        }
        if let Some(value) = fields
            .get(POLICY_FIELD_AUTOMATIONS)
            .and_then(|value| parse_automation_mode(value))
        {
            override_state.automations = value;
        }
        if let Some(value) = fields
            .get(POLICY_FIELD_DATA_HANDLING)
            .and_then(|value| parse_data_handling_mode(value))
        {
            override_state.data_handling = value;
        }
        overrides.insert(connector_id, override_state);
    }

    Some(normalize_policy_state(ShieldPolicyState {
        version: POLICY_VERSION,
        global,
        overrides,
    }))
}

async fn load_wallet_policy_rule(
    state: &State<'_, Mutex<AppState>>,
    rule_id: &str,
) -> Result<Option<VaultPolicyRule>, String> {
    let mut client = get_rpc_client(state).await?;
    let Some(bytes) = query_wallet_state_optional(&mut client, policy_rule_key(rule_id)).await?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical(&bytes)
        .map(Some)
        .map_err(|e| e.to_string())
}

async fn load_wallet_policy_state(
    state: &State<'_, Mutex<AppState>>,
    manager: &ShieldPolicyManager,
) -> Result<Option<ShieldPolicyState>, String> {
    let mut rules = Vec::new();
    for field in global_policy_fields() {
        if let Some(rule) = load_wallet_policy_rule(state, &global_rule_id(field)).await? {
            rules.push(rule);
        }
    }

    let roster_rule = load_wallet_policy_rule(state, SHIELD_POLICY_OVERRIDE_ROSTER_RULE_ID).await?;
    let mut connector_ids = BTreeSet::new();
    if let Some(rule) = &roster_rule {
        rules.push(rule.clone());
        for entry in &rule.domain_allowlist {
            let Some(encoded_connector) = entry.strip_prefix("value:") else {
                continue;
            };
            if let Some(connector_id) = decode_connector_rule_scope(encoded_connector) {
                connector_ids.insert(connector_id);
            }
        }
    }

    if connector_ids.is_empty() {
        connector_ids.extend(manager.current_state().overrides.into_keys());
        if let Ok(records) = wallet_connector_auth_list_inner(state, None).await {
            connector_ids.extend(
                records
                    .records
                    .into_iter()
                    .map(|record| record.connector_id),
            );
        }
    }

    for connector_id in connector_ids {
        for field in connector_policy_fields() {
            if let Some(rule) =
                load_wallet_policy_rule(state, &connector_rule_id(&connector_id, field)).await?
            {
                rules.push(rule);
            }
        }
    }

    Ok(wallet_policy_state_from_rules(&rules))
}

async fn sync_policy_state_to_wallet(
    state: &State<'_, Mutex<AppState>>,
    policy: &ShieldPolicyState,
) -> Result<(), String> {
    let mut client = get_rpc_client(state).await?;
    for rule in wallet_policy_rules_from_state(policy) {
        let params = codec::to_bytes_canonical(&rule).map_err(|e| e.to_string())?;
        let tx = build_wallet_call_tx("upsert_policy_rule@v1", params)?;
        submit_tx_and_wait(&mut client, tx).await?;
    }
    Ok(())
}

pub(crate) async fn bootstrap_wallet_policy_state(
    state: &State<'_, Mutex<AppState>>,
    manager: &ShieldPolicyManager,
) -> Result<(), String> {
    if let Some(wallet_state) = load_wallet_policy_state(state, manager).await? {
        manager.replace_state(wallet_state)?;
        return Ok(());
    }
    let current = manager.current_state();
    sync_policy_state_to_wallet(state, &current).await
}

pub async fn current_policy_state(
    state: State<'_, Mutex<AppState>>,
    manager: State<'_, ShieldPolicyManager>,
) -> Result<ShieldPolicyState, String> {
    if let Some(wallet_state) = load_wallet_policy_state(&state, &manager).await? {
        manager.replace_state(wallet_state.clone())?;
        return Ok(wallet_state);
    }
    Ok(manager.current_state())
}

pub async fn replace_policy_state(
    state: State<'_, Mutex<AppState>>,
    manager: tauri::State<'_, ShieldPolicyManager>,
    policy: ShieldPolicyState,
) -> Result<ShieldPolicyState, String> {
    let previous = manager.current_state();
    let normalized = manager.replace_state(policy)?;
    if let Err(error) = sync_policy_state_to_wallet(&state, &normalized).await {
        let _ = manager.replace_state(previous);
        return Err(error);
    }
    Ok(normalized)
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
