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
const SHIELD_POLICY_MEMORY_FILE: &str = "shield_policy_memory.json";
const POLICY_FIELD_READS: &str = "reads";
const POLICY_FIELD_WRITES: &str = "writes";
const POLICY_FIELD_ADMIN: &str = "admin";
const POLICY_FIELD_EXPERT: &str = "expert";
const POLICY_FIELD_AUTOMATIONS: &str = "automations";
const POLICY_FIELD_DATA_HANDLING: &str = "data_handling";
const POLICY_FIELD_INHERIT_GLOBAL: &str = "inherit_global";
const MAX_REMEMBERED_APPROVALS: usize = 48;
const MAX_REMEMBERED_APPROVAL_RECEIPTS: usize = 24;

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
    #[serde(default)]
    pub policy_family: Option<String>,
    #[serde(default)]
    pub scope_key: Option<String>,
    #[serde(default)]
    pub scope_label: Option<String>,
    #[serde(default)]
    pub rememberable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ShieldApprovalScopeMode {
    #[default]
    ExactAction,
    ConnectorPolicyFamily,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldRememberedApprovalDecision {
    pub decision_id: String,
    pub connector_id: String,
    pub action_id: String,
    pub action_label: String,
    pub policy_family: String,
    pub scope_key: String,
    pub scope_label: String,
    #[serde(default)]
    pub scope_mode: ShieldApprovalScopeMode,
    pub source_label: String,
    pub created_at_ms: u64,
    #[serde(default)]
    pub last_matched_at_ms: Option<u64>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    pub match_count: u32,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldApprovalHookReceipt {
    pub receipt_id: String,
    pub timestamp_ms: u64,
    pub hook_kind: String,
    pub status: String,
    pub summary: String,
    pub connector_id: String,
    pub action_id: String,
    #[serde(default)]
    pub decision_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldRememberedApprovalSnapshot {
    pub generated_at_ms: u64,
    pub active_decision_count: usize,
    pub recent_receipt_count: usize,
    #[serde(default)]
    pub decisions: Vec<ShieldRememberedApprovalDecision>,
    #[serde(default)]
    pub recent_receipts: Vec<ShieldApprovalHookReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldRememberApprovalInput {
    pub connector_id: String,
    pub action_id: String,
    pub action_label: String,
    pub policy_family: String,
    #[serde(default)]
    pub scope_key: Option<String>,
    #[serde(default)]
    pub scope_label: Option<String>,
    #[serde(default)]
    pub source_label: Option<String>,
    #[serde(default)]
    pub scope_mode: Option<ShieldApprovalScopeMode>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldRememberedApprovalScopeUpdateInput {
    pub decision_id: String,
    pub scope_mode: ShieldApprovalScopeMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldRememberedApprovalExpiryUpdateInput {
    pub decision_id: String,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ShieldApprovalMemoryState {
    #[serde(default)]
    decisions: Vec<ShieldRememberedApprovalDecision>,
    #[serde(default)]
    recent_receipts: Vec<ShieldApprovalHookReceipt>,
}

#[derive(Debug, Clone)]
pub struct ShieldPolicyManager {
    path: Arc<PathBuf>,
    state: Arc<Mutex<ShieldPolicyState>>,
    approval_memory_path: Arc<PathBuf>,
    approval_memory: Arc<Mutex<ShieldApprovalMemoryState>>,
}

impl ShieldPolicyManager {
    pub fn new(path: PathBuf) -> Self {
        let state = load_policy_state(&path).unwrap_or_default();
        let approval_memory_path = approval_memory_path_for(&path);
        let approval_memory = load_approval_memory_state(&approval_memory_path).unwrap_or_default();
        Self {
            path: Arc::new(path),
            state: Arc::new(Mutex::new(state)),
            approval_memory_path: Arc::new(approval_memory_path),
            approval_memory: Arc::new(Mutex::new(approval_memory)),
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

    fn replace_approval_memory_state(
        &self,
        next_state: ShieldApprovalMemoryState,
    ) -> Result<ShieldApprovalMemoryState, String> {
        let normalized = normalize_approval_memory_state(next_state);
        persist_approval_memory_state(&self.approval_memory_path, &normalized)?;
        let mut state = self
            .approval_memory
            .lock()
            .expect("shield approval memory lock poisoned");
        *state = normalized.clone();
        Ok(normalized)
    }

    pub fn approval_snapshot(&self) -> ShieldRememberedApprovalSnapshot {
        let now = crate::kernel::state::now();
        let mut state = self
            .approval_memory
            .lock()
            .expect("shield approval memory lock poisoned")
            .clone();
        if sweep_expired_approvals(&mut state, now) {
            if let Ok(next_state) = self.replace_approval_memory_state(state) {
                return approval_snapshot_from_state(&next_state);
            }
            let fallback = self
                .approval_memory
                .lock()
                .expect("shield approval memory lock poisoned")
                .clone();
            return approval_snapshot_from_state(&fallback);
        }
        approval_snapshot_from_state(&state)
    }

    pub fn remember_approval(
        &self,
        input: ShieldRememberApprovalInput,
    ) -> Result<ShieldRememberedApprovalSnapshot, String> {
        let now = crate::kernel::state::now();
        let mut state = self
            .approval_memory
            .lock()
            .expect("shield approval memory lock poisoned")
            .clone();
        sweep_expired_approvals(&mut state, now);
        let requested_scope_mode = input.scope_mode.clone();
        let requested_expiry = input.expires_at_ms;
        let source_label = normalize_source_label(input.source_label.as_deref());

        if let Some(existing_index) = state.decisions.iter().position(|decision| {
            decision.connector_id == input.connector_id
                && decision.action_id == input.action_id
                && decision.policy_family == input.policy_family
                && decision.scope_mode
                    == requested_scope_mode
                        .clone()
                        .unwrap_or_else(|| decision.scope_mode.clone())
        }) {
            let (decision_id, connector_id, action_id, action_label, scope_label) = {
                let existing = &mut state.decisions[existing_index];
                let next_scope_mode = requested_scope_mode
                    .clone()
                    .unwrap_or_else(|| existing.scope_mode.clone());
                let (scope_key, scope_label) = derive_scope_identity(
                    &next_scope_mode,
                    &existing.connector_id,
                    &existing.action_id,
                    input.action_label.as_str(),
                    &existing.policy_family,
                    input.scope_key.as_deref(),
                    input.scope_label.as_deref(),
                );
                existing.action_label = input.action_label.clone();
                existing.scope_key = scope_key;
                existing.scope_label = scope_label.clone();
                existing.scope_mode = next_scope_mode;
                existing.source_label = source_label.clone();
                if requested_expiry.is_some() {
                    existing.expires_at_ms = requested_expiry;
                }
                existing.status = "active".to_string();
                (
                    existing.decision_id.clone(),
                    existing.connector_id.clone(),
                    existing.action_id.clone(),
                    existing.action_label.clone(),
                    existing.scope_label.clone(),
                )
            };
            push_approval_hook_receipt(
                &mut state,
                ShieldApprovalHookReceipt {
                    receipt_id: format!("remember:{}:{now}", decision_id),
                    timestamp_ms: now,
                    hook_kind: "post_run_evidence_hook".to_string(),
                    status: "recorded".to_string(),
                    summary: format!(
                        "Remembered approval for {} on {}.",
                        action_label, scope_label
                    ),
                    connector_id,
                    action_id,
                    decision_id: Some(decision_id),
                },
            );
            let next_state = self.replace_approval_memory_state(state)?;
            return Ok(approval_snapshot_from_state(&next_state));
        }

        let connector_id = input.connector_id.trim().to_string();
        let action_id = input.action_id.trim().to_string();
        let action_label = input.action_label.trim().to_string();
        let policy_family = input.policy_family.trim().to_string();
        let scope_mode = input.scope_mode.unwrap_or_default();
        let (scope_key, scope_label) = derive_scope_identity(
            &scope_mode,
            &connector_id,
            &action_id,
            &action_label,
            &policy_family,
            input.scope_key.as_deref(),
            input.scope_label.as_deref(),
        );
        let decision_id = format!(
            "shield-approval:{}:{}:{}:{}:{}",
            connector_id,
            action_id,
            policy_family,
            scope_mode_token(&scope_mode),
            hex::encode(scope_key.as_bytes())
        );
        let decision = ShieldRememberedApprovalDecision {
            decision_id: decision_id.clone(),
            connector_id: connector_id.clone(),
            action_id: action_id.clone(),
            action_label: action_label.clone(),
            policy_family,
            scope_key: scope_key.clone(),
            scope_label: scope_label.clone(),
            scope_mode,
            source_label,
            created_at_ms: now,
            last_matched_at_ms: None,
            expires_at_ms: requested_expiry,
            match_count: 0,
            status: "active".to_string(),
        };
        state
            .decisions
            .retain(|existing| existing.decision_id != decision_id);
        state.decisions.insert(0, decision);
        if state.decisions.len() > MAX_REMEMBERED_APPROVALS {
            state.decisions.truncate(MAX_REMEMBERED_APPROVALS);
        }
        push_approval_hook_receipt(
            &mut state,
            ShieldApprovalHookReceipt {
                receipt_id: format!("remember:{}:{now}", decision_id),
                timestamp_ms: now,
                hook_kind: "post_run_evidence_hook".to_string(),
                status: "recorded".to_string(),
                summary: format!(
                    "Remembered approval for {} on {}.",
                    action_label, scope_label
                ),
                connector_id,
                action_id,
                decision_id: Some(decision_id),
            },
        );
        let next_state = self.replace_approval_memory_state(state)?;
        Ok(approval_snapshot_from_state(&next_state))
    }

    pub fn forget_approval(
        &self,
        decision_id: &str,
    ) -> Result<ShieldRememberedApprovalSnapshot, String> {
        let trimmed = decision_id.trim();
        if trimmed.is_empty() {
            return Err("Decision id is required.".to_string());
        }
        let now = crate::kernel::state::now();
        let mut state = self
            .approval_memory
            .lock()
            .expect("shield approval memory lock poisoned")
            .clone();
        sweep_expired_approvals(&mut state, now);
        let Some(removed) = state
            .decisions
            .iter()
            .find(|decision| decision.decision_id == trimmed)
            .cloned()
        else {
            return Err(format!("Unknown remembered approval '{}'.", trimmed));
        };
        state
            .decisions
            .retain(|decision| decision.decision_id != trimmed);
        push_approval_hook_receipt(
            &mut state,
            ShieldApprovalHookReceipt {
                receipt_id: format!("forget:{}:{now}", trimmed),
                timestamp_ms: now,
                hook_kind: "post_run_evidence_hook".to_string(),
                status: "revoked".to_string(),
                summary: format!("Revoked remembered approval for {}.", removed.action_label),
                connector_id: removed.connector_id,
                action_id: removed.action_id,
                decision_id: Some(trimmed.to_string()),
            },
        );
        let next_state = self.replace_approval_memory_state(state)?;
        Ok(approval_snapshot_from_state(&next_state))
    }

    pub fn set_approval_scope_mode(
        &self,
        input: ShieldRememberedApprovalScopeUpdateInput,
    ) -> Result<ShieldRememberedApprovalSnapshot, String> {
        let decision_id = input.decision_id.trim();
        if decision_id.is_empty() {
            return Err("Decision id is required.".to_string());
        }
        let now = crate::kernel::state::now();
        let mut state = self
            .approval_memory
            .lock()
            .expect("shield approval memory lock poisoned")
            .clone();
        sweep_expired_approvals(&mut state, now);
        let Some(decision_index) = state
            .decisions
            .iter()
            .position(|decision| decision.decision_id == decision_id)
        else {
            return Err(format!("Unknown remembered approval '{}'.", decision_id));
        };
        let (connector_id, action_id, action_label, next_scope_label) = {
            let decision = &mut state.decisions[decision_index];
            let (scope_key, scope_label) = derive_scope_identity(
                &input.scope_mode,
                &decision.connector_id,
                &decision.action_id,
                &decision.action_label,
                &decision.policy_family,
                None,
                None,
            );
            decision.scope_mode = input.scope_mode.clone();
            decision.scope_key = scope_key;
            decision.scope_label = scope_label.clone();
            (
                decision.connector_id.clone(),
                decision.action_id.clone(),
                decision.action_label.clone(),
                scope_label,
            )
        };
        push_approval_hook_receipt(
            &mut state,
            ShieldApprovalHookReceipt {
                receipt_id: format!("scope-update:{}:{now}", decision_id),
                timestamp_ms: now,
                hook_kind: "post_run_evidence_hook".to_string(),
                status: "updated".to_string(),
                summary: format!(
                    "Updated remembered approval scope for {} to {}.",
                    action_label, next_scope_label
                ),
                connector_id,
                action_id,
                decision_id: Some(decision_id.to_string()),
            },
        );
        let next_state = self.replace_approval_memory_state(state)?;
        Ok(approval_snapshot_from_state(&next_state))
    }

    pub fn set_approval_expiry(
        &self,
        input: ShieldRememberedApprovalExpiryUpdateInput,
    ) -> Result<ShieldRememberedApprovalSnapshot, String> {
        let decision_id = input.decision_id.trim();
        if decision_id.is_empty() {
            return Err("Decision id is required.".to_string());
        }
        let now = crate::kernel::state::now();
        let mut state = self
            .approval_memory
            .lock()
            .expect("shield approval memory lock poisoned")
            .clone();
        sweep_expired_approvals(&mut state, now);
        let Some(decision_index) = state
            .decisions
            .iter()
            .position(|decision| decision.decision_id == decision_id)
        else {
            return Err(format!("Unknown remembered approval '{}'.", decision_id));
        };
        let (connector_id, action_id, action_label, expiry_summary) = {
            let decision = &mut state.decisions[decision_index];
            decision.expires_at_ms = input.expires_at_ms;
            (
                decision.connector_id.clone(),
                decision.action_id.clone(),
                decision.action_label.clone(),
                match input.expires_at_ms {
                    Some(expires_at_ms) => {
                        format!("now expires at {}.", expires_at_ms)
                    }
                    None => "no longer expires automatically.".to_string(),
                },
            )
        };
        push_approval_hook_receipt(
            &mut state,
            ShieldApprovalHookReceipt {
                receipt_id: format!("expiry-update:{}:{now}", decision_id),
                timestamp_ms: now,
                hook_kind: "post_run_evidence_hook".to_string(),
                status: "updated".to_string(),
                summary: format!(
                    "Updated remembered approval expiry for {} so it {}",
                    action_label, expiry_summary
                ),
                connector_id,
                action_id,
                decision_id: Some(decision_id.to_string()),
            },
        );
        sweep_expired_approvals(&mut state, now);
        let next_state = self.replace_approval_memory_state(state)?;
        Ok(approval_snapshot_from_state(&next_state))
    }

    pub fn match_remembered_approval(
        &self,
        connector_id: &str,
        action_id: &str,
        policy_family: &str,
        scope_key: Option<&str>,
        action_label: &str,
    ) -> bool {
        let connector_id = connector_id.trim();
        let action_id = action_id.trim();
        let policy_family = policy_family.trim();
        if connector_id.is_empty() || action_id.is_empty() || policy_family.is_empty() {
            return false;
        }
        let now = crate::kernel::state::now();
        let scope_key = normalize_scope_key(scope_key);
        let mut state = self
            .approval_memory
            .lock()
            .expect("shield approval memory lock poisoned")
            .clone();
        let mut changed = sweep_expired_approvals(&mut state, now);
        let Some(decision_index) = state.decisions.iter().position(|decision| {
            decision_matches_request(decision, connector_id, action_id, policy_family, &scope_key)
        }) else {
            if let Some((mismatched_decision_id, mismatched_action_label, mismatched_scope_label)) =
                state
                    .decisions
                    .iter()
                    .find(|decision| {
                        decision.status == "active"
                            && decision.connector_id == connector_id
                            && decision.policy_family == policy_family
                            && !decision_matches_request(
                                decision,
                                connector_id,
                                action_id,
                                policy_family,
                                &scope_key,
                            )
                    })
                    .map(|decision| {
                        (
                            decision.decision_id.clone(),
                            decision.action_label.clone(),
                            decision.scope_label.clone(),
                        )
                    })
            {
                push_approval_hook_receipt(
                    &mut state,
                    ShieldApprovalHookReceipt {
                        receipt_id: format!(
                            "scope-mismatch:{}:{}:{now}",
                            connector_id, action_id
                        ),
                        timestamp_ms: now,
                        hook_kind: "pre_run_approval_hook".to_string(),
                        status: "scope_mismatch".to_string(),
                        summary: format!(
                            "Remembered approval for {} did not auto-match because it is scoped to {}.",
                            mismatched_action_label, mismatched_scope_label
                        ),
                        connector_id: connector_id.to_string(),
                        action_id: action_id.to_string(),
                        decision_id: Some(mismatched_decision_id),
                    },
                );
                changed = true;
            }
            if changed {
                let _ = self.replace_approval_memory_state(state);
            }
            return false;
        };
        let (decision_id, remembered_action_label, scope_label) = {
            let decision = &mut state.decisions[decision_index];
            decision.last_matched_at_ms = Some(now);
            decision.match_count = decision.match_count.saturating_add(1);
            (
                decision.decision_id.clone(),
                decision.action_label.clone(),
                decision.scope_label.clone(),
            )
        };
        push_approval_hook_receipt(
            &mut state,
            ShieldApprovalHookReceipt {
                receipt_id: format!("match:{}:{now}", decision_id),
                timestamp_ms: now,
                hook_kind: "pre_run_approval_hook".to_string(),
                status: "matched".to_string(),
                summary: format!(
                    "Used remembered approval for {} within {}.",
                    if action_label.trim().is_empty() {
                        remembered_action_label.as_str()
                    } else {
                        action_label.trim()
                    },
                    scope_label
                ),
                connector_id: connector_id.to_string(),
                action_id: action_id.to_string(),
                decision_id: Some(decision_id),
            },
        );
        self.replace_approval_memory_state(state).is_ok()
    }

    pub fn record_blocker_escalation(
        &self,
        connector_id: &str,
        action_id: &str,
        action_label: &str,
        policy_family: &str,
        scope_key: Option<&str>,
    ) {
        let now = crate::kernel::state::now();
        let connector_id = connector_id.trim().to_string();
        let action_id = action_id.trim().to_string();
        if connector_id.is_empty() || action_id.is_empty() {
            return;
        }
        let scope_label = normalize_scope_label(scope_key, &normalize_scope_key(scope_key));
        let summary = format!(
            "Approval required for {} ({} · {}).",
            if action_label.trim().is_empty() {
                action_id.as_str()
            } else {
                action_label.trim()
            },
            if policy_family.trim().is_empty() {
                "governed"
            } else {
                policy_family.trim()
            },
            scope_label
        );
        let mut state = self
            .approval_memory
            .lock()
            .expect("shield approval memory lock poisoned")
            .clone();
        push_approval_hook_receipt(
            &mut state,
            ShieldApprovalHookReceipt {
                receipt_id: format!("blocker:{}:{}:{now}", connector_id, action_id),
                timestamp_ms: now,
                hook_kind: "blocker_escalation_hook".to_string(),
                status: "requested".to_string(),
                summary,
                connector_id,
                action_id,
                decision_id: None,
            },
        );
        let _ = self.replace_approval_memory_state(state);
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

fn approval_memory_path_for(policy_path: &Path) -> PathBuf {
    policy_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(SHIELD_POLICY_MEMORY_FILE)
}

fn normalize_scope_key(value: Option<&str>) -> String {
    value
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or("connector_action")
        .to_string()
}

fn normalize_scope_label(value: Option<&str>, scope_key: &str) -> String {
    value
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or(scope_key)
        .to_string()
}

fn normalize_source_label(value: Option<&str>) -> String {
    value
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or("operator")
        .to_string()
}

fn scope_mode_token(value: &ShieldApprovalScopeMode) -> &'static str {
    match value {
        ShieldApprovalScopeMode::ExactAction => "exact_action",
        ShieldApprovalScopeMode::ConnectorPolicyFamily => "connector_policy_family",
    }
}

fn humanize_scope_subject(value: &str) -> String {
    value
        .trim()
        .replace(['_', '-', '.'], " ")
        .split_whitespace()
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn derive_scope_identity(
    scope_mode: &ShieldApprovalScopeMode,
    connector_id: &str,
    action_id: &str,
    action_label: &str,
    policy_family: &str,
    requested_scope_key: Option<&str>,
    requested_scope_label: Option<&str>,
) -> (String, String) {
    match scope_mode {
        ShieldApprovalScopeMode::ExactAction => {
            let fallback_scope_key = format!("connector:{}:action:{}", connector_id, action_id);
            let scope_key = requested_scope_key
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .unwrap_or(fallback_scope_key.as_str())
                .to_string();
            let fallback_scope_label = format!("{} · {}", connector_id, action_label.trim());
            let scope_label = requested_scope_label
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .unwrap_or(fallback_scope_label.as_str())
                .to_string();
            (scope_key, scope_label)
        }
        ShieldApprovalScopeMode::ConnectorPolicyFamily => (
            format!("connector:{}:policy_family:{}", connector_id, policy_family),
            format!(
                "{} · {} family",
                connector_id,
                humanize_scope_subject(policy_family)
            ),
        ),
    }
}

fn decision_matches_request(
    decision: &ShieldRememberedApprovalDecision,
    connector_id: &str,
    action_id: &str,
    policy_family: &str,
    scope_key: &str,
) -> bool {
    if decision.status != "active"
        || decision.connector_id != connector_id
        || decision.policy_family != policy_family
    {
        return false;
    }

    match decision.scope_mode {
        ShieldApprovalScopeMode::ExactAction => {
            decision.action_id == action_id && decision.scope_key == scope_key
        }
        ShieldApprovalScopeMode::ConnectorPolicyFamily => true,
    }
}

fn sweep_expired_approvals(state: &mut ShieldApprovalMemoryState, now: u64) -> bool {
    let mut changed = false;
    let mut active_decisions = Vec::with_capacity(state.decisions.len());
    let mut expired_decisions = Vec::new();
    for decision in state.decisions.drain(..) {
        if decision.status == "active"
            && decision
                .expires_at_ms
                .map(|expires_at_ms| expires_at_ms <= now)
                .unwrap_or(false)
        {
            expired_decisions.push(decision);
            changed = true;
        } else {
            active_decisions.push(decision);
        }
    }
    state.decisions = active_decisions;
    for decision in expired_decisions {
        push_approval_hook_receipt(
            state,
            ShieldApprovalHookReceipt {
                receipt_id: format!("expired:{}:{now}", decision.decision_id),
                timestamp_ms: now,
                hook_kind: "pre_run_approval_hook".to_string(),
                status: "expired".to_string(),
                summary: format!(
                    "Remembered approval for {} expired and no longer auto-matches {}.",
                    decision.action_label, decision.scope_label
                ),
                connector_id: decision.connector_id,
                action_id: decision.action_id,
                decision_id: Some(decision.decision_id),
            },
        );
    }
    changed
}

fn normalize_approval_memory_state(
    mut input: ShieldApprovalMemoryState,
) -> ShieldApprovalMemoryState {
    input
        .decisions
        .retain(|decision| decision.status == "active");
    input
        .decisions
        .sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
    if input.decisions.len() > MAX_REMEMBERED_APPROVALS {
        input.decisions.truncate(MAX_REMEMBERED_APPROVALS);
    }
    input
        .recent_receipts
        .sort_by(|left, right| right.timestamp_ms.cmp(&left.timestamp_ms));
    if input.recent_receipts.len() > MAX_REMEMBERED_APPROVAL_RECEIPTS {
        input
            .recent_receipts
            .truncate(MAX_REMEMBERED_APPROVAL_RECEIPTS);
    }
    input
}

fn load_approval_memory_state(path: &Path) -> Result<ShieldApprovalMemoryState, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read Shield approval memory: {}", error))?;
    let parsed: ShieldApprovalMemoryState = serde_json::from_str(&raw)
        .map_err(|error| format!("Failed to parse Shield approval memory: {}", error))?;
    Ok(normalize_approval_memory_state(parsed))
}

fn persist_approval_memory_state(
    path: &Path,
    state: &ShieldApprovalMemoryState,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create Shield approval memory directory: {}",
                error
            )
        })?;
    }
    let raw = serde_json::to_vec_pretty(state)
        .map_err(|error| format!("Failed to serialize Shield approval memory: {}", error))?;
    fs::write(path, raw)
        .map_err(|error| format!("Failed to persist Shield approval memory: {}", error))?;
    Ok(())
}

fn push_approval_hook_receipt(
    state: &mut ShieldApprovalMemoryState,
    receipt: ShieldApprovalHookReceipt,
) {
    state.recent_receipts.insert(0, receipt);
    if state.recent_receipts.len() > MAX_REMEMBERED_APPROVAL_RECEIPTS {
        state
            .recent_receipts
            .truncate(MAX_REMEMBERED_APPROVAL_RECEIPTS);
    }
}

fn approval_snapshot_from_state(
    state: &ShieldApprovalMemoryState,
) -> ShieldRememberedApprovalSnapshot {
    ShieldRememberedApprovalSnapshot {
        generated_at_ms: crate::kernel::state::now(),
        active_decision_count: state.decisions.len(),
        recent_receipt_count: state.recent_receipts.len(),
        decisions: state.decisions.clone(),
        recent_receipts: state.recent_receipts.clone(),
    }
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

pub async fn current_remembered_approval_snapshot(
    manager: State<'_, ShieldPolicyManager>,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    Ok(manager.approval_snapshot())
}

pub async fn remember_approval_in_runtime(
    manager: State<'_, ShieldPolicyManager>,
    input: ShieldRememberApprovalInput,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    manager.remember_approval(input)
}

pub async fn forget_approval_in_runtime(
    manager: State<'_, ShieldPolicyManager>,
    decision_id: String,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    manager.forget_approval(&decision_id)
}

pub async fn update_approval_scope_mode_in_runtime(
    manager: State<'_, ShieldPolicyManager>,
    input: ShieldRememberedApprovalScopeUpdateInput,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    manager.set_approval_scope_mode(input)
}

pub async fn update_approval_expiry_in_runtime(
    manager: State<'_, ShieldPolicyManager>,
    input: ShieldRememberedApprovalExpiryUpdateInput,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    manager.set_approval_expiry(input)
}

pub async fn replace_policy_state(
    state: State<'_, Mutex<AppState>>,
    manager: tauri::State<'_, ShieldPolicyManager>,
    policy: ShieldPolicyState,
) -> Result<ShieldPolicyState, String> {
    let previous = manager.current_state();
    let normalized = manager.replace_state(policy)?;
    if !super::wallet_backed_bootstrap_enabled() {
        return Ok(normalized);
    }
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

#[cfg(test)]
pub fn parse_approval_error(message: &str) -> Option<&str> {
    message
        .split_once(POLICY_APPROVAL_PREFIX)
        .map(|(_, payload)| payload)
}

#[cfg(test)]
#[path = "policy/tests.rs"]
mod tests;
