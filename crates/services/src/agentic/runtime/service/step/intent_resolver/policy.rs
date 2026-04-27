use super::*;
use serde::Deserialize;

pub(super) fn preferred_tier_from_label(label: &str, scope: IntentScopeProfile) -> ExecutionTier {
    match label {
        "visual_last" => ExecutionTier::VisualForeground,
        "ax_first" => ExecutionTier::VisualBackground,
        "tool_first" => ExecutionTier::DomHeadless,
        _ => match scope {
            IntentScopeProfile::UiInteraction => ExecutionTier::VisualForeground,
            _ => ExecutionTier::DomHeadless,
        },
    }
}

pub(super) fn score_to_bps(score: f32) -> u16 {
    let clamped = score.clamp(0.0, 1.0);
    (clamped * 10_000.0).round() as u16
}

pub(super) fn quantization_step_bps(policy: &IntentRoutingPolicy) -> u16 {
    policy.score_quantization_bps.clamp(1, 10_000)
}

pub(super) fn tie_region_eps_bps(policy: &IntentRoutingPolicy) -> u16 {
    policy.tie_region_eps_bps.min(10_000)
}

pub(super) fn ambiguity_margin_bps(policy: &IntentRoutingPolicy) -> u16 {
    policy.ambiguity_margin_bps.min(10_000)
}

pub(super) fn is_ambiguity_abstain_exempt(policy: &IntentRoutingPolicy, intent_id: &str) -> bool {
    policy
        .ambiguity_abstain_exempt_intents
        .iter()
        .map(|id| id.trim())
        .any(|id| !id.is_empty() && id == intent_id)
}

pub(super) fn quantize_score(score: f32, policy: &IntentRoutingPolicy) -> f32 {
    let step = quantization_step_bps(policy);
    let bps = score_to_bps(score);
    let remainder = bps % step;
    let rounded_bps = if remainder.saturating_mul(2) >= step {
        bps.saturating_add(step.saturating_sub(remainder))
    } else {
        bps.saturating_sub(remainder)
    }
    .min(10_000);
    (rounded_bps as f32 / 10_000.0).clamp(0.0, 1.0)
}

pub(super) fn normalize_query_for_ranking(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn query_binding_for_intent(entry: &IntentCatalogEntry) -> IntentQueryBindingClass {
    entry.query_binding
}

pub(super) fn intent_supports_remote_public_fact_grounding(entry: &IntentCatalogEntry) -> bool {
    let has_web_retrieve_capability = entry
        .required_capabilities
        .iter()
        .any(|capability| capability.as_str() == "web.retrieve");
    match entry.applicability_class {
        ExecutionApplicabilityClass::RemoteRetrieval => true,
        ExecutionApplicabilityClass::Mixed => has_web_retrieve_capability,
        _ => false,
    }
}

fn intent_can_defer_remote_public_fact_grounding(
    entry: &IntentCatalogEntry,
    query_binding_profile: &QueryBindingProfile,
) -> bool {
    query_binding_profile.durable_automation_requested
        && matches!(
            query_binding_for_intent(entry),
            IntentQueryBindingClass::DurableAutomation
        )
}

fn extract_first_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let mut brace_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in raw[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if ch == '{' {
            brace_depth = brace_depth.saturating_add(1);
            continue;
        }
        if ch == '}' {
            brace_depth = brace_depth.saturating_sub(1);
            if brace_depth == 0 {
                let end = start + idx + 1;
                return Some(raw[start..end].to_string());
            }
        }
    }
    None
}

#[derive(Debug, Clone, Deserialize, Default)]
struct QueryBindingProfilePayload {
    #[serde(default)]
    remote_public_fact_required: bool,
    #[serde(default)]
    host_local_clock_targeted: bool,
    #[serde(default)]
    command_directed: bool,
    #[serde(default)]
    durable_automation_requested: bool,
    #[serde(default)]
    model_registry_control_requested: bool,
    #[serde(default)]
    app_launch_directed: bool,
    #[serde(default)]
    direct_ui_input: bool,
    #[serde(default)]
    desktop_screenshot_requested: bool,
    #[serde(default)]
    temporal_filesystem_filter: bool,
}

fn parse_query_binding_profile(raw: &str) -> Result<QueryBindingProfile, TransactionError> {
    let parsed = serde_json::from_str::<QueryBindingProfilePayload>(raw).or_else(|_| {
        let extracted = extract_first_json_object(raw).ok_or_else(|| {
            TransactionError::Invalid(
                "ERROR_CLASS=ResolverContractViolation query binding output missing JSON"
                    .to_string(),
            )
        })?;
        serde_json::from_str::<QueryBindingProfilePayload>(&extracted).map_err(|e| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=ResolverContractViolation query binding output parse failed: {}",
                e
            ))
        })
    })?;
    Ok(QueryBindingProfile {
        available: true,
        remote_public_fact_required: parsed.remote_public_fact_required,
        host_local_clock_targeted: parsed.host_local_clock_targeted,
        command_directed: parsed.command_directed,
        durable_automation_requested: parsed.durable_automation_requested,
        model_registry_control_requested: parsed.model_registry_control_requested,
        app_launch_directed: parsed.app_launch_directed,
        direct_ui_input: parsed.direct_ui_input,
        desktop_screenshot_requested: parsed.desktop_screenshot_requested,
        temporal_filesystem_filter: parsed.temporal_filesystem_filter,
    })
}

pub(super) async fn infer_query_binding_profile(
    service: &RuntimeAgentService,
    runtime: &Arc<dyn InferenceRuntime>,
    session_id: [u8; 32],
    query: &str,
) -> QueryBindingProfile {
    let payload = json!([
        {
            "role": "system",
            "content": "Classify query semantics for intent-policy feasibility. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Query:\n{}\n\nReturn exactly one JSON object with this schema:\n{{\"remote_public_fact_required\":<bool>,\"host_local_clock_targeted\":<bool>,\"command_directed\":<bool>,\"durable_automation_requested\":<bool>,\"model_registry_control_requested\":<bool>,\"app_launch_directed\":<bool>,\"direct_ui_input\":<bool>,\"desktop_screenshot_requested\":<bool>,\"temporal_filesystem_filter\":<bool>}}\nRules:\n1) remote_public_fact_required=true only when current/public external grounding is required.\n2) host_local_clock_targeted=true only when the user explicitly asks for this host machine/system clock.\n3) command_directed=true for local shell/terminal or host automation tasks.\n4) durable_automation_requested=true only when the user is asking for an installed recurring watch/monitor/notify-later workflow rather than a one-shot command.\n5) model_registry_control_requested=true only when the user is explicitly asking to load unload install import activate deactivate warm sync or otherwise manage local model backend or gallery lifecycle inside the kernel control plane.\n6) app_launch_directed=true for opening/launching a local application.\n7) direct_ui_input=true for click/type/scroll-like interaction in an active UI.\n8) desktop_screenshot_requested=true for screenshot capture intent.\n9) temporal_filesystem_filter=true for recency filters on local files/folders.\n10) Keep decisions semantic; do not keyword-match mechanically.",
                query
            )
        }
    ]);
    let input_bytes = match serde_json::to_vec(&payload) {
        Ok(encoded) => encoded,
        Err(err) => {
            log::warn!(
                "IntentResolver query binding payload encode failed error={}",
                err
            );
            return QueryBindingProfile::default();
        }
    };
    let airlocked_input = match service
        .prepare_cloud_inference_input(
            Some(session_id),
            "intent_resolver",
            INTENT_QUERY_BINDING_MODEL_ID,
            &input_bytes,
        )
        .await
    {
        Ok(encoded) => encoded,
        Err(err) => {
            log::warn!(
                "IntentResolver query binding airlock failed session={} error={}",
                hex::encode(&session_id[..4]),
                err
            );
            return QueryBindingProfile::default();
        }
    };
    let output = match runtime
        .execute_inference(
            [0u8; 32],
            &airlocked_input,
            ioi_types::app::agentic::InferenceOptions {
                temperature: 0.0,
                json_mode: true,
                max_tokens: 256,
                ..Default::default()
            },
        )
        .await
    {
        Ok(bytes) => bytes,
        Err(err) => {
            log::warn!(
                "IntentResolver query binding inference failed error={}",
                vm_error_to_tx(err)
            );
            return QueryBindingProfile::default();
        }
    };
    let raw = match String::from_utf8(output) {
        Ok(content) => content,
        Err(err) => {
            log::warn!(
                "IntentResolver query binding utf8 decode failed error={}",
                err
            );
            return QueryBindingProfile::default();
        }
    };
    match parse_query_binding_profile(&raw) {
        Ok(parsed) => {
            let profile = parsed;
            log::info!(
                "IntentResolver query binding classified model_id={} model_version={} schema_id={}",
                INTENT_QUERY_BINDING_MODEL_ID,
                INTENT_QUERY_BINDING_MODEL_VERSION,
                INTENT_QUERY_BINDING_SCHEMA_ID
            );
            log::info!(
                "IntentResolver query binding profile session={} remote_public_fact_required={} host_local_clock_targeted={} command_directed={} durable_automation_requested={} model_registry_control_requested={} app_launch_directed={} direct_ui_input={} desktop_screenshot_requested={} temporal_filesystem_filter={}",
                hex::encode(&session_id[..4]),
                profile.remote_public_fact_required,
                profile.host_local_clock_targeted,
                profile.command_directed,
                profile.durable_automation_requested,
                profile.model_registry_control_requested,
                profile.app_launch_directed,
                profile.direct_ui_input,
                profile.desktop_screenshot_requested,
                profile.temporal_filesystem_filter
            );
            profile
        }
        Err(err) => {
            log::warn!("IntentResolver query binding parse failed error={}", err);
            QueryBindingProfile::default()
        }
    }
}

pub(super) fn query_binding_satisfied(
    entry: &IntentCatalogEntry,
    query_binding_profile: &QueryBindingProfile,
) -> bool {
    if !query_binding_profile.available {
        return true;
    }
    if query_binding_profile.remote_public_fact_required
        && !intent_supports_remote_public_fact_grounding(entry)
        && !intent_can_defer_remote_public_fact_grounding(entry, query_binding_profile)
    {
        return false;
    }
    match query_binding_for_intent(entry) {
        IntentQueryBindingClass::None => true,
        IntentQueryBindingClass::HostLocal => query_binding_profile.host_local_clock_targeted,
        IntentQueryBindingClass::RemotePublicFact => {
            query_binding_profile.remote_public_fact_required
        }
        IntentQueryBindingClass::AppLaunchDirected => query_binding_profile.app_launch_directed,
        IntentQueryBindingClass::CommandDirected => query_binding_profile.command_directed,
        IntentQueryBindingClass::DurableAutomation => {
            query_binding_profile.durable_automation_requested
        }
        IntentQueryBindingClass::ModelRegistryControl => {
            query_binding_profile.model_registry_control_requested
        }
        IntentQueryBindingClass::DirectUiInput => query_binding_profile.direct_ui_input,
        IntentQueryBindingClass::DesktopScreenshot => {
            query_binding_profile.desktop_screenshot_requested
        }
    }
}

pub(super) fn resolve_band(score: f32, policy: &IntentRoutingPolicy) -> IntentConfidenceBand {
    let high = policy
        .confidence
        .high_threshold_bps
        .max(policy.confidence.medium_threshold_bps)
        .min(10_000);
    let medium = policy.confidence.medium_threshold_bps.min(high);
    let score_bps = score_to_bps(score);
    if score_bps >= high {
        IntentConfidenceBand::High
    } else if score_bps >= medium {
        IntentConfidenceBand::Medium
    } else {
        IntentConfidenceBand::Low
    }
}

pub(super) fn valid_preferred_tier_label(label: &str) -> bool {
    matches!(label, "tool_first" | "ax_first" | "visual_last")
}
