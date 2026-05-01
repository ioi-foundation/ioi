use ioi_types::app::{
    ConfidenceBand, EvidenceRef, ModelCandidateScore, ModelRoutingDecision, PromptPrivacyClass,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRouterInput {
    pub task_class: String,
    pub risk_class: String,
    pub privacy_class: PromptPrivacyClass,
    pub required_modality: String,
    pub requested_model: Option<String>,
    pub policy_allows_egress: bool,
    pub allow_sensitive_remote: bool,
    pub latency_budget_ms: u64,
    pub token_estimate: u64,
}

impl Default for ModelRouterInput {
    fn default() -> Self {
        Self {
            task_class: "agent_runtime".to_string(),
            risk_class: "normal".to_string(),
            privacy_class: PromptPrivacyClass::Internal,
            required_modality: "text".to_string(),
            requested_model: None,
            policy_allows_egress: false,
            allow_sensitive_remote: false,
            latency_budget_ms: 30_000,
            token_estimate: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRuntimeRoute {
    pub api_url: String,
    pub api_key: String,
    pub model_name: String,
    pub decision: ModelRoutingDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeCandidate {
    profile: &'static str,
    provider: &'static str,
    model: String,
    api_url: String,
    api_key: String,
    remote: bool,
    cost_estimate_units: u64,
    latency_budget_ms: u64,
    rejection_reason: String,
}

impl RuntimeCandidate {
    fn score(&self, input: &ModelRouterInput) -> ModelCandidateScore {
        ModelCandidateScore {
            profile: self.profile.to_string(),
            provider: self.provider.to_string(),
            model: self.model.clone(),
            privacy_class: input.privacy_class,
            risk_fit: if self.rejection_reason.is_empty() {
                ConfidenceBand::High
            } else {
                ConfidenceBand::Low
            },
            cost_estimate_units: self.cost_estimate_units,
            latency_budget_ms: self.latency_budget_ms,
            allowed_by_policy: self.rejection_reason.is_empty(),
            rejection_reason: self.rejection_reason.clone(),
        }
    }
}

pub struct RuntimeModelRouter;

impl RuntimeModelRouter {
    pub fn route_from_env(
        input: ModelRouterInput,
    ) -> Result<ModelRuntimeRoute, ModelRoutingDecision> {
        Self::route_with_lookup(input, |key| std::env::var(key).ok())
    }

    pub fn route_with_lookup<F>(
        input: ModelRouterInput,
        lookup: F,
    ) -> Result<ModelRuntimeRoute, ModelRoutingDecision>
    where
        F: Fn(&str) -> Option<String>,
    {
        let candidates = configured_candidates(&input, &lookup);
        let selected = select_candidate(&input, &candidates);
        let mut decision = decision_for_candidates(&input, &candidates, selected.as_ref());

        if let Some(candidate) = selected {
            Ok(ModelRuntimeRoute {
                api_url: candidate.api_url,
                api_key: candidate.api_key,
                model_name: candidate.model,
                decision,
            })
        } else {
            decision.error_class = "model_route_unavailable".to_string();
            Err(decision)
        }
    }
}

fn configured_candidates<F>(input: &ModelRouterInput, lookup: &F) -> Vec<RuntimeCandidate>
where
    F: Fn(&str) -> Option<String>,
{
    let requested = input
        .requested_model
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let mut candidates = Vec::new();

    if let Some(local_url) = env_text(lookup, "LOCAL_LLM_URL")
        .or_else(|| env_text(lookup, "AUTOPILOT_LOCAL_RUNTIME_URL"))
    {
        let model = env_text(lookup, "LOCAL_LLM_MODEL")
            .or_else(|| env_text(lookup, "AUTOPILOT_LOCAL_RUNTIME_MODEL"))
            .or_else(|| {
                requested
                    .filter(|model| !looks_remote_family(model))
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "llama3".to_string());
        candidates.push(RuntimeCandidate {
            profile: "local",
            provider: "local",
            model,
            api_url: local_url,
            api_key: String::new(),
            remote: false,
            cost_estimate_units: 1,
            latency_budget_ms: input.latency_budget_ms.min(15_000),
            rejection_reason: String::new(),
        });
    }

    if let Some(api_key) = env_text(lookup, "OPENAI_API_KEY") {
        let model = requested
            .filter(|model| !looks_anthropic_family(model))
            .map(str::to_string)
            .or_else(|| env_text(lookup, "OPENAI_MODEL"))
            .unwrap_or_else(|| "gpt-4o".to_string());
        let rejection_reason = remote_rejection_reason(input);
        candidates.push(RuntimeCandidate {
            profile: "remote_openai",
            provider: "openai",
            model,
            api_url: env_text(lookup, "OPENAI_API_URL")
                .unwrap_or_else(|| "https://api.openai.com/v1/chat/completions".to_string()),
            api_key,
            remote: true,
            cost_estimate_units: 3,
            latency_budget_ms: input.latency_budget_ms,
            rejection_reason,
        });
    }

    if let Some(api_key) = env_text(lookup, "ANTHROPIC_API_KEY") {
        let model = requested
            .filter(|model| looks_anthropic_family(model))
            .map(str::to_string)
            .or_else(|| env_text(lookup, "ANTHROPIC_MODEL"))
            .unwrap_or_else(|| "claude-3-5-sonnet-latest".to_string());
        let rejection_reason = remote_rejection_reason(input);
        candidates.push(RuntimeCandidate {
            profile: "remote_anthropic",
            provider: "anthropic",
            model,
            api_url: env_text(lookup, "ANTHROPIC_API_URL")
                .unwrap_or_else(|| "https://api.anthropic.com/v1/messages".to_string()),
            api_key,
            remote: true,
            cost_estimate_units: 4,
            latency_budget_ms: input.latency_budget_ms,
            rejection_reason,
        });
    }

    candidates
}

fn select_candidate<'a>(
    input: &ModelRouterInput,
    candidates: &'a [RuntimeCandidate],
) -> Option<RuntimeCandidate> {
    let mut allowed = candidates
        .iter()
        .filter(|candidate| candidate.rejection_reason.is_empty())
        .collect::<Vec<_>>();

    if allowed.is_empty() {
        return None;
    }

    allowed.sort_by_key(|candidate| {
        (
            selection_priority(input, candidate),
            candidate.cost_estimate_units,
            candidate.latency_budget_ms,
            candidate.profile,
        )
    });

    allowed.first().map(|candidate| (*candidate).clone())
}

fn selection_priority(input: &ModelRouterInput, candidate: &RuntimeCandidate) -> u8 {
    let requested = input
        .requested_model
        .as_deref()
        .map(|model| model.trim().to_ascii_lowercase());
    let candidate_model = candidate.model.to_ascii_lowercase();

    if matches!(
        input.privacy_class,
        PromptPrivacyClass::Sensitive | PromptPrivacyClass::Secret
    ) && !candidate.remote
    {
        return 0;
    }

    if requested
        .as_deref()
        .is_some_and(|model| model == candidate_model)
    {
        return 1;
    }

    if requested.as_deref().is_some_and(looks_anthropic_family) && candidate.provider == "anthropic"
    {
        return 2;
    }

    if requested.as_deref().is_some_and(looks_openai_family) && candidate.provider == "openai" {
        return 2;
    }

    if !candidate.remote {
        return 3;
    }

    4
}

fn decision_for_candidates(
    input: &ModelRouterInput,
    candidates: &[RuntimeCandidate],
    selected: Option<&RuntimeCandidate>,
) -> ModelRoutingDecision {
    let mut decision = ModelRoutingDecision {
        routing_id: format!(
            "model-route:{}:{}:{}",
            input.task_class, input.risk_class, input.required_modality
        ),
        task_class: input.task_class.clone(),
        risk_class: input.risk_class.clone(),
        privacy_class: input.privacy_class,
        required_modality: input.required_modality.clone(),
        candidates: candidates
            .iter()
            .map(|candidate| candidate.score(input))
            .collect(),
        token_estimate: input.token_estimate,
        latency_budget_ms: input.latency_budget_ms,
        policy_allows_egress: input.policy_allows_egress,
        evidence_refs: routing_evidence_refs(candidates),
        ..ModelRoutingDecision::default()
    };

    if let Some(candidate) = selected {
        decision.selected_profile = candidate.profile.to_string();
        decision.selected_provider = candidate.provider.to_string();
        decision.selected_model = candidate.model.clone();
        decision.cost_estimate_units = candidate.cost_estimate_units;
        decision.fallback_reason = fallback_reason(input, candidate, candidates);
    }

    decision
}

fn routing_evidence_refs(candidates: &[RuntimeCandidate]) -> Vec<EvidenceRef> {
    candidates
        .iter()
        .map(|candidate| {
            let mut evidence = EvidenceRef::new("model_router_candidate", candidate.profile);
            evidence.summary = format!(
                "{} provider candidate using configured endpoint for model {}",
                candidate.provider, candidate.model
            );
            evidence
        })
        .collect()
}

fn fallback_reason(
    input: &ModelRouterInput,
    selected: &RuntimeCandidate,
    candidates: &[RuntimeCandidate],
) -> String {
    if selected.remote && candidates.iter().any(|candidate| !candidate.remote) {
        "local candidate unavailable or lower priority for requested model".to_string()
    } else if !selected.remote
        && matches!(
            input.privacy_class,
            PromptPrivacyClass::Sensitive | PromptPrivacyClass::Secret
        )
    {
        "privacy-sensitive request routed to local runtime".to_string()
    } else if selected.remote && !input.allow_sensitive_remote {
        "remote route selected for non-sensitive request with policy-approved egress".to_string()
    } else {
        "highest ranked policy-allowed candidate selected".to_string()
    }
}

fn remote_rejection_reason(input: &ModelRouterInput) -> String {
    if !input.policy_allows_egress {
        return "remote model egress is not allowed by policy".to_string();
    }
    if matches!(
        input.privacy_class,
        PromptPrivacyClass::Sensitive | PromptPrivacyClass::Secret
    ) && !input.allow_sensitive_remote
    {
        return "sensitive prompt class requires explicit remote allowance".to_string();
    }
    String::new()
}

fn env_text<F>(lookup: &F, key: &str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key).and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn looks_remote_family(model: &str) -> bool {
    looks_openai_family(model) || looks_anthropic_family(model)
}

fn looks_openai_family(model: &str) -> bool {
    let model = model.to_ascii_lowercase();
    model.starts_with("gpt-") || model.starts_with("o1") || model.starts_with("o3")
}

fn looks_anthropic_family(model: &str) -> bool {
    model.to_ascii_lowercase().contains("claude")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn lookup(values: BTreeMap<&'static str, &'static str>) -> impl Fn(&str) -> Option<String> {
        move |key| values.get(key).map(|value| value.to_string())
    }

    #[test]
    fn sensitive_prompt_prefers_local_and_rejects_remote_without_explicit_allowance() {
        let values = BTreeMap::from([
            (
                "LOCAL_LLM_URL",
                "http://localhost:11434/v1/chat/completions",
            ),
            ("OPENAI_API_KEY", "sk-test"),
            ("OPENAI_MODEL", "gpt-4o"),
        ]);
        let route = RuntimeModelRouter::route_with_lookup(
            ModelRouterInput {
                privacy_class: PromptPrivacyClass::Sensitive,
                policy_allows_egress: true,
                ..ModelRouterInput::default()
            },
            lookup(values),
        )
        .expect("local route should be selected");

        assert_eq!(route.decision.selected_provider, "local");
        assert!(route
            .decision
            .candidates
            .iter()
            .any(|candidate| candidate.provider == "openai"
                && !candidate.allowed_by_policy
                && candidate
                    .rejection_reason
                    .contains("sensitive prompt class")));
    }

    #[test]
    fn public_prompt_can_use_remote_when_egress_is_allowed() {
        let values = BTreeMap::from([("OPENAI_API_KEY", "sk-test"), ("OPENAI_MODEL", "gpt-4o")]);
        let route = RuntimeModelRouter::route_with_lookup(
            ModelRouterInput {
                privacy_class: PromptPrivacyClass::Public,
                policy_allows_egress: true,
                requested_model: Some("gpt-4o".to_string()),
                ..ModelRouterInput::default()
            },
            lookup(values),
        )
        .expect("remote route should be selected");

        assert_eq!(route.decision.selected_provider, "openai");
        assert_eq!(route.model_name, "gpt-4o");
        assert!(route.decision.has_policy_explainable_selection());
    }

    #[test]
    fn remote_candidate_is_blocked_when_egress_is_not_allowed() {
        let values = BTreeMap::from([("OPENAI_API_KEY", "sk-test"), ("OPENAI_MODEL", "gpt-4o")]);
        let decision = RuntimeModelRouter::route_with_lookup(
            ModelRouterInput {
                privacy_class: PromptPrivacyClass::Internal,
                policy_allows_egress: false,
                ..ModelRouterInput::default()
            },
            lookup(values),
        )
        .expect_err("no route should be selected");

        assert_eq!(decision.error_class, "model_route_unavailable");
        assert!(decision
            .candidates
            .iter()
            .all(|candidate| !candidate.allowed_by_policy));
        assert!(decision
            .candidates
            .iter()
            .any(|candidate| candidate.rejection_reason.contains("egress")));
    }

    #[test]
    fn claude_request_selects_anthropic_candidate() {
        let values = BTreeMap::from([
            ("OPENAI_API_KEY", "sk-test"),
            ("ANTHROPIC_API_KEY", "anthropic-test"),
        ]);
        let route = RuntimeModelRouter::route_with_lookup(
            ModelRouterInput {
                privacy_class: PromptPrivacyClass::Internal,
                policy_allows_egress: true,
                requested_model: Some("claude-3-5-sonnet-latest".to_string()),
                ..ModelRouterInput::default()
            },
            lookup(values),
        )
        .expect("anthropic route should be selected");

        assert_eq!(route.decision.selected_provider, "anthropic");
        assert_eq!(route.model_name, "claude-3-5-sonnet-latest");
    }
}
