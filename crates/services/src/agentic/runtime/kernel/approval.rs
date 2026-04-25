use ioi_types::app::{ActionRequest, ActionTarget, ApprovalAuthority, ApprovalGrant};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalScopeContext {
    pub target_label: String,
    #[serde(default)]
    pub labels: Vec<String>,
}

impl ApprovalScopeContext {
    pub fn new(target_label: impl Into<String>) -> Self {
        let target_label = target_label.into();
        Self {
            labels: vec![target_label.clone()],
            target_label,
        }
    }

    pub fn from_action_request(request: &ActionRequest) -> Self {
        let mut context = Self::new(request.target.canonical_label());
        context.push_label(format!("target:{}", context.target_label));
        context.push_label(format!("agent:{}", request.context.agent_id));
        if let Some(session_id) = request.context.session_id {
            context.push_label(format!("session:{}", hex::encode(session_id)));
        }
        if let Some(window_id) = request.context.window_id {
            context.push_label(format!("window:{}", window_id));
        }
        context.extend_from_params(&request.target, &request.params);
        context
    }

    pub fn with_operation_label(mut self, label: impl Into<String>) -> Self {
        self.push_label(label);
        self
    }

    pub fn push_label(&mut self, label: impl Into<String>) {
        let label = normalize_scope_label(label.into());
        if !label.is_empty() && !self.labels.iter().any(|existing| existing == &label) {
            self.labels.push(label);
        }
    }

    fn extend_from_params(&mut self, target: &ActionTarget, params: &[u8]) {
        let Ok(value) = serde_json::from_slice::<Value>(params) else {
            return;
        };
        if let Some(tool) = value
            .get("tool_name")
            .or_else(|| value.get("tool"))
            .and_then(Value::as_str)
        {
            self.push_label(format!("tool:{}", tool));
        }
        if let Some(connector) = value
            .get("connector_id")
            .or_else(|| value.get("connector"))
            .and_then(Value::as_str)
        {
            self.push_label(format!("connector:{}", connector));
        }
        for key in ["url", "endpoint", "merchant_url"] {
            if let Some(url) = value.get(key).and_then(Value::as_str) {
                if let Some(host) = host_label(url) {
                    self.push_label(format!("domain:{}", host));
                }
            }
        }
        for key in ["path", "source_path", "destination_path", "cwd"] {
            if let Some(path) = value.get(key).and_then(Value::as_str) {
                self.push_label(format!("path:{}", path));
            }
        }
        if matches!(target, ActionTarget::WalletSend | ActionTarget::WalletSign) {
            self.push_label("wallet_network.approval");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeMatchDecision {
    pub allowed: bool,
    pub matched_scope: Option<String>,
    pub reason: Option<String>,
}

pub struct AuthorityScopeMatcher;

impl AuthorityScopeMatcher {
    pub fn evaluate(
        authority: &ApprovalAuthority,
        context: &ApprovalScopeContext,
    ) -> ScopeMatchDecision {
        if authority.scope_allowlist.is_empty() {
            return ScopeMatchDecision {
                allowed: false,
                matched_scope: None,
                reason: Some("approval_authority_scope_allowlist_empty".to_string()),
            };
        }

        for scope in &authority.scope_allowlist {
            let normalized_scope = normalize_scope_label(scope);
            if normalized_scope == "*" {
                return ScopeMatchDecision {
                    allowed: true,
                    matched_scope: Some(scope.clone()),
                    reason: None,
                };
            }
            if context
                .labels
                .iter()
                .any(|label| scope_pattern_matches(&normalized_scope, label))
            {
                return ScopeMatchDecision {
                    allowed: true,
                    matched_scope: Some(scope.clone()),
                    reason: None,
                };
            }
        }

        ScopeMatchDecision {
            allowed: false,
            matched_scope: None,
            reason: Some(format!(
                "approval_grant_out_of_scope:target={}",
                context.target_label
            )),
        }
    }

    pub fn validate(
        authority: &ApprovalAuthority,
        context: &ApprovalScopeContext,
    ) -> Result<(), String> {
        let decision = Self::evaluate(authority, context);
        if decision.allowed {
            Ok(())
        } else {
            Err(decision
                .reason
                .unwrap_or_else(|| "approval_grant_out_of_scope".to_string()))
        }
    }

    pub fn validate_grant_for_request(
        authority: &ApprovalAuthority,
        grant: &ApprovalGrant,
        request: &ActionRequest,
        operation_label: &str,
    ) -> Result<(), String> {
        if grant.window_id.is_some() && grant.window_id != request.context.window_id {
            return Err("approval_grant_window_scope_mismatch".to_string());
        }
        let context = ApprovalScopeContext::from_action_request(request)
            .with_operation_label(operation_label.to_string());
        Self::validate(authority, &context)
    }
}

fn normalize_scope_label(label: impl AsRef<str>) -> String {
    label.as_ref().trim().to_ascii_lowercase()
}

fn scope_pattern_matches(pattern: &str, label: &str) -> bool {
    if pattern == label {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("::*") {
        return label.starts_with(&format!("{}::", prefix));
    }
    if let Some(prefix) = pattern.strip_suffix(":*") {
        return label.starts_with(&format!("{}:", prefix));
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return label.starts_with(prefix);
    }
    false
}

fn host_label(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Url::parse(trimmed)
        .or_else(|_| Url::parse(&format!("https://{}", trimmed)))
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{ActionContext, SignatureSuite};

    fn authority(scopes: Vec<&str>) -> ApprovalAuthority {
        ApprovalAuthority {
            schema_version: 1,
            authority_id: [7u8; 32],
            public_key: vec![1, 2, 3],
            signature_suite: SignatureSuite::ED25519,
            expires_at: 10,
            revoked: false,
            scope_allowlist: scopes.into_iter().map(str::to_string).collect(),
        }
    }

    #[test]
    fn matches_operation_label() {
        let request = ActionRequest {
            target: ActionTarget::BrowserInteract,
            params: br#"{"url":"https://example.com/a"}"#.to_vec(),
            context: ActionContext {
                agent_id: "agent".to_string(),
                session_id: None,
                window_id: None,
            },
            nonce: 1,
        };
        let context = ApprovalScopeContext::from_action_request(&request)
            .with_operation_label("desktop_agent.resume");
        let decision =
            AuthorityScopeMatcher::evaluate(&authority(vec!["desktop_agent.resume"]), &context);
        assert!(decision.allowed);
    }

    #[test]
    fn rejects_out_of_scope_authority() {
        let context = ApprovalScopeContext::new("browser::interact");
        let decision =
            AuthorityScopeMatcher::evaluate(&authority(vec!["wallet_network.approval"]), &context);
        assert!(!decision.allowed);
        assert_eq!(
            decision.reason.as_deref(),
            Some("approval_grant_out_of_scope:target=browser::interact")
        );
    }

    #[test]
    fn matches_domain_scope_from_params() {
        let request = ActionRequest {
            target: ActionTarget::NetFetch,
            params: br#"{"url":"https://api.example.com/v1"}"#.to_vec(),
            context: ActionContext {
                agent_id: "agent".to_string(),
                session_id: None,
                window_id: None,
            },
            nonce: 1,
        };
        let context = ApprovalScopeContext::from_action_request(&request);
        let decision =
            AuthorityScopeMatcher::evaluate(&authority(vec!["domain:api.example.com"]), &context);
        assert!(decision.allowed);
    }
}
