use crate::agentic::rules::Verdict;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.context-budget-policy-request.v1";
pub const CONTEXT_BUDGET_POLICY_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.context-budget-policy.v1";
pub const CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-budget-policy-request.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluationRecord {
    pub verdict: Verdict,
    #[serde(default)]
    pub matched_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_policy_used: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pii_decision_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_eval_trace_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_eval_hash: Option<[u8; 32]>,
}

impl PolicyEvaluationRecord {
    pub fn matched_rules_for_decision(&self) -> Vec<String> {
        let mut rules = self.matched_rule_ids.clone();
        if rules.is_empty() {
            if let Some(default_policy) = &self.default_policy_used {
                rules.push(format!("default:{}", default_policy));
            }
        }
        if let Some(hash) = self.pii_decision_hash {
            rules.push(format!("pii:{}", hex::encode(hash)));
        }
        rules
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContextBudgetPolicyError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextBudgetPolicyRequest {
    pub schema_version: String,
    #[serde(default)]
    pub usage_telemetry: Value,
    #[serde(default)]
    pub thresholds: ContextBudgetThresholds,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub tool_id: Option<String>,
    #[serde(default)]
    pub tool_call_id: Option<String>,
    #[serde(default)]
    pub workflow_graph_id: Option<String>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub event_kind: Option<String>,
    #[serde(default)]
    pub component_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ContextBudgetThresholds {
    #[serde(default)]
    pub max_total_tokens: Option<f64>,
    #[serde(default)]
    pub max_cost_usd: Option<f64>,
    #[serde(default)]
    pub max_context_pressure: Option<f64>,
    #[serde(default)]
    pub warn_at_ratio: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextBudgetUsageSummary {
    pub total_tokens: f64,
    pub estimated_cost_usd: f64,
    pub context_pressure: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub scope: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextBudgetCheck {
    pub id: String,
    pub label: String,
    pub actual: f64,
    pub limit: f64,
    pub ratio: f64,
    pub severity: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextBudgetDecision {
    pub policy_decision_id: String,
    pub status: String,
    pub mode: String,
    pub would_block: bool,
    pub summary: String,
    pub checks: Vec<ContextBudgetCheck>,
    pub violations: Vec<ContextBudgetCheck>,
    pub warnings: Vec<ContextBudgetCheck>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextBudgetPolicyRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub mode: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub source: String,
    pub actor: String,
    pub event_kind: String,
    pub component_kind: String,
    pub payload_schema_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_graph_id: Option<String>,
    pub workflow_node_id: String,
    pub tool_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub thresholds: ContextBudgetThresholds,
    pub usage_telemetry: Value,
    pub usage_summary: ContextBudgetUsageSummary,
    pub policy_decision_id: String,
    pub policy_decision: ContextBudgetDecision,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub warnings: Vec<ContextBudgetCheck>,
    pub violations: Vec<ContextBudgetCheck>,
    pub would_block: bool,
    pub simulation_mode: bool,
    pub summary: String,
    pub generated_at: String,
}

#[derive(Debug, Default, Clone)]
pub struct ContextBudgetPolicyCore;

impl ContextBudgetPolicyCore {
    pub fn evaluate(
        &self,
        request: &ContextBudgetPolicyRequest,
    ) -> Result<ContextBudgetPolicyRecord, ContextBudgetPolicyError> {
        request.validate()?;
        let usage_summary = budget_usage_summary(&request.usage_telemetry);
        let warn_at_ratio = request.thresholds.warn_at_ratio.unwrap_or(0.8);
        let checks = vec![
            budget_check(
                "total_tokens",
                "total tokens",
                usage_summary.total_tokens,
                request.thresholds.max_total_tokens,
                warn_at_ratio,
            ),
            budget_check(
                "estimated_cost_usd",
                "estimated cost USD",
                usage_summary.estimated_cost_usd,
                request.thresholds.max_cost_usd,
                warn_at_ratio,
            ),
            budget_check(
                "context_pressure",
                "context pressure",
                usage_summary.context_pressure,
                request.thresholds.max_context_pressure,
                warn_at_ratio,
            ),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let violations = checks
            .iter()
            .filter(|check| check.severity == "violation")
            .cloned()
            .collect::<Vec<_>>();
        let warnings = checks
            .iter()
            .filter(|check| check.severity == "warning")
            .cloned()
            .collect::<Vec<_>>();
        let would_block = !violations.is_empty();
        let mode = budget_mode(request.mode.as_deref());
        let status = if would_block && mode == "block" {
            "blocked"
        } else if would_block || !warnings.is_empty() {
            "warn"
        } else {
            "ok"
        }
        .to_string();
        let scope = optional_trimmed(request.scope.as_deref()).unwrap_or_else(|| {
            if usage_summary.scope.is_empty() {
                "thread".to_string()
            } else {
                usage_summary.scope.clone()
            }
        });
        let thread_id =
            optional_trimmed(request.thread_id.as_deref()).or(usage_summary.thread_id.clone());
        let run_id = optional_trimmed(request.run_id.as_deref()).or(usage_summary.run_id.clone());
        let workflow_node_id = optional_trimmed(request.workflow_node_id.as_deref())
            .unwrap_or_else(|| "runtime.context-budget".to_string());
        let workflow_graph_id = optional_trimmed(request.workflow_graph_id.as_deref());
        let is_coding_tool =
            request.schema_version == CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION;
        let event_kind = optional_trimmed(request.event_kind.as_deref()).unwrap_or_else(|| {
            if is_coding_tool {
                "RuntimeCodingToolBudget.Evaluate".to_string()
            } else {
                "RuntimeContextBudget.Evaluate".to_string()
            }
        });
        let component_kind =
            optional_trimmed(request.component_kind.as_deref()).unwrap_or_else(|| {
                if is_coding_tool {
                    "coding_tool".to_string()
                } else {
                    "context_budget".to_string()
                }
            });
        let decision_hash = budget_hash(&json!({
            "scope": scope,
            "thread_id": thread_id,
            "run_id": run_id,
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "status": status,
            "mode": mode,
            "checks": checks,
        }))?;
        let decision_short = decision_hash
            .strip_prefix("sha256:")
            .unwrap_or(&decision_hash)
            .chars()
            .take(16)
            .collect::<String>();
        let policy_decision_id = format!(
            "policy_context_budget_{}_{}_{}",
            safe_id(&scope),
            decision_short,
            status
        );
        let receipt_id = format!(
            "receipt_context_budget_{}_{}",
            safe_id(&scope),
            decision_short
        );
        let summary = budget_summary(&status, &violations, &warnings);
        let decision = ContextBudgetDecision {
            policy_decision_id: policy_decision_id.clone(),
            status: status.clone(),
            mode: mode.clone(),
            would_block,
            summary: summary.clone(),
            checks: checks.clone(),
            violations: violations.clone(),
            warnings: warnings.clone(),
        };

        Ok(ContextBudgetPolicyRecord {
            schema_version: CONTEXT_BUDGET_POLICY_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_context_budget_policy".to_string(),
            status: status.clone(),
            mode: mode.clone(),
            scope,
            thread_id,
            run_id,
            source: optional_trimmed(request.source.as_deref())
                .unwrap_or_else(|| "react_flow".to_string()),
            actor: optional_trimmed(request.actor.as_deref())
                .unwrap_or_else(|| "operator".to_string()),
            event_kind,
            component_kind,
            payload_schema_version: CONTEXT_BUDGET_POLICY_RESULT_SCHEMA_VERSION.to_string(),
            workflow_graph_id,
            workflow_node_id,
            tool_id: optional_trimmed(request.tool_id.as_deref()),
            tool_call_id: optional_trimmed(request.tool_call_id.as_deref()),
            thresholds: request.thresholds.clone(),
            usage_telemetry: request.usage_telemetry.clone(),
            usage_summary,
            policy_decision_id: policy_decision_id.clone(),
            policy_decision: decision,
            receipt_refs: vec![receipt_id],
            policy_decision_refs: vec![policy_decision_id],
            warnings,
            violations,
            would_block,
            simulation_mode: mode == "simulate",
            summary,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

impl ContextBudgetPolicyRequest {
    pub fn validate(&self) -> Result<(), ContextBudgetPolicyError> {
        if self.schema_version != CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION
            && self.schema_version != CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION
        {
            return Err(ContextBudgetPolicyError::InvalidSchemaVersion {
                expected: CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if !self.usage_telemetry.is_object() {
            return Err(ContextBudgetPolicyError::MissingField("usage_telemetry"));
        }
        Ok(())
    }
}

fn budget_usage_summary(value: &Value) -> ContextBudgetUsageSummary {
    if let Some(entries) = value.get("usage").and_then(Value::as_array) {
        let total_tokens = entries
            .iter()
            .map(|entry| number_field(entry, "total_tokens"))
            .sum();
        let estimated_cost_usd = entries
            .iter()
            .map(|entry| number_field(entry, "estimated_cost_usd"))
            .sum();
        let context_pressure = entries
            .iter()
            .map(|entry| number_field(entry, "context_pressure"))
            .fold(0.0, f64::max);
        return ContextBudgetUsageSummary {
            total_tokens,
            estimated_cost_usd,
            context_pressure,
            thread_id: string_field(value, "thread_id"),
            run_id: string_field(value, "run_id"),
            scope: string_field(value, "scope").unwrap_or_else(|| "workflow".to_string()),
        };
    }
    ContextBudgetUsageSummary {
        total_tokens: number_field(value, "total_tokens"),
        estimated_cost_usd: number_field(value, "estimated_cost_usd"),
        context_pressure: number_field(value, "context_pressure"),
        thread_id: string_field(value, "thread_id"),
        run_id: string_field(value, "run_id"),
        scope: string_field(value, "scope").unwrap_or_else(|| "thread".to_string()),
    }
}

fn budget_check(
    id: &str,
    label: &str,
    actual: f64,
    limit: Option<f64>,
    warn_at_ratio: f64,
) -> Option<ContextBudgetCheck> {
    let limit = limit?;
    if limit <= 0.0 {
        return None;
    }
    let ratio = ((actual / limit) * 10000.0).round() / 10000.0;
    let severity = if actual > limit {
        "violation"
    } else if actual >= limit * warn_at_ratio {
        "warning"
    } else {
        "ok"
    };
    Some(ContextBudgetCheck {
        id: id.to_string(),
        label: label.to_string(),
        actual,
        limit,
        ratio,
        severity: severity.to_string(),
    })
}

fn budget_mode(value: Option<&str>) -> String {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("warn") => "warn".to_string(),
        Some("block") => "block".to_string(),
        _ => "simulate".to_string(),
    }
}

fn budget_summary(
    status: &str,
    violations: &[ContextBudgetCheck],
    warnings: &[ContextBudgetCheck],
) -> String {
    if status == "blocked" {
        return format!(
            "Context budget blocked: {} exceeded.",
            violations
                .iter()
                .map(|check| check.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if status == "warn" {
        return format!(
            "Context budget warning: {} near or over limit.",
            violations
                .iter()
                .chain(warnings.iter())
                .map(|check| check.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    "Context budget is within policy.".to_string()
}

fn number_field(value: &Value, key: &str) -> f64 {
    value
        .get(key)
        .and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str()?.parse::<f64>().ok())
        })
        .filter(|value| value.is_finite() && *value >= 0.0)
        .unwrap_or(0.0)
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn safe_id(value: &str) -> String {
    let mut output = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    while output.contains("__") {
        output = output.replace("__", "_");
    }
    output.trim_matches('_').to_string()
}

fn budget_hash(value: &Value) -> Result<String, ContextBudgetPolicyError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ContextBudgetPolicyError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget_request() -> ContextBudgetPolicyRequest {
        ContextBudgetPolicyRequest {
            schema_version: CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION.to_string(),
            usage_telemetry: json!({
                "total_tokens": 120,
                "estimated_cost_usd": 0.03,
                "context_pressure": 0.2,
            }),
            thresholds: ContextBudgetThresholds {
                max_total_tokens: Some(100.0),
                max_cost_usd: None,
                max_context_pressure: None,
                warn_at_ratio: Some(0.8),
            },
            mode: Some("block".to_string()),
            scope: Some("thread".to_string()),
            thread_id: Some("thread_budget".to_string()),
            run_id: None,
            tool_id: Some("file.inspect".to_string()),
            tool_call_id: Some("call_budget".to_string()),
            workflow_graph_id: Some("graph_budget".to_string()),
            workflow_node_id: Some("node_budget".to_string()),
            source: Some("react_flow".to_string()),
            actor: None,
            event_kind: None,
            component_kind: None,
        }
    }

    #[test]
    fn rust_policy_blocks_context_budget_excess() {
        let mut request = budget_request();
        request.schema_version = CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION.to_string();
        request.tool_id = None;
        request.tool_call_id = None;

        let record = ContextBudgetPolicyCore
            .evaluate(&request)
            .expect("budget record");

        assert_eq!(
            record.schema_version,
            CONTEXT_BUDGET_POLICY_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "blocked");
        assert_eq!(record.event_kind, "RuntimeContextBudget.Evaluate");
        assert_eq!(record.component_kind, "context_budget");
        assert_eq!(record.workflow_node_id, "node_budget");
        assert_eq!(record.usage_summary.total_tokens, 120.0);
        assert_eq!(record.violations[0].id, "total_tokens");
        assert!(record
            .policy_decision_id
            .starts_with("policy_context_budget_thread_"));
        assert_eq!(
            record.policy_decision_refs,
            vec![record.policy_decision_id.clone()]
        );
    }

    #[test]
    fn rust_policy_blocks_coding_tool_budget_excess() {
        let record = ContextBudgetPolicyCore
            .evaluate(&budget_request())
            .expect("coding-tool budget record");

        assert_eq!(record.status, "blocked");
        assert_eq!(record.event_kind, "RuntimeCodingToolBudget.Evaluate");
        assert_eq!(record.component_kind, "coding_tool");
        assert_eq!(record.tool_id.as_deref(), Some("file.inspect"));
        assert_eq!(record.tool_call_id.as_deref(), Some("call_budget"));
    }

    #[test]
    fn rust_policy_warns_coding_tool_budget_near_limit() {
        let mut request = budget_request();
        request.usage_telemetry = json!({ "total_tokens": 90 });
        request.mode = Some("warn".to_string());

        let record = ContextBudgetPolicyCore
            .evaluate(&request)
            .expect("budget warning");

        assert_eq!(record.status, "warn");
        assert_eq!(record.warnings[0].severity, "warning");
        assert!(record.violations.is_empty());
    }

    #[test]
    fn rust_policy_rejects_invalid_budget_schema() {
        let mut request = budget_request();
        request.schema_version = "legacy.schema".to_string();

        let error = ContextBudgetPolicyCore
            .evaluate(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            ContextBudgetPolicyError::InvalidSchemaVersion {
                expected: CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }
}
