use super::*;

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

pub(super) fn query_binding_for_intent(entry: &IntentMatrixEntry) -> IntentQueryBindingClass {
    match entry.intent_id.as_str() {
        "system.clock.read" => IntentQueryBindingClass::HostLocal,
        "web.research" => IntentQueryBindingClass::RemotePublicFact,
        "app.launch" => IntentQueryBindingClass::AppLaunchDirected,
        "command.exec" => IntentQueryBindingClass::CommandDirected,
        "ui.interaction" => IntentQueryBindingClass::DirectUiInput,
        "ui.capture_screenshot" => IntentQueryBindingClass::DesktopScreenshot,
        _ => IntentQueryBindingClass::None,
    }
}

pub(super) fn query_requests_desktop_screenshot(query: &str) -> bool {
    let padded = format!(" {} ", query.to_ascii_lowercase());
    const SCREENSHOT_MARKERS: [&str; 9] = [
        " screenshot ",
        " screenshots ",
        " screen capture ",
        " capture screen ",
        " capture my screen ",
        " capture desktop ",
        " capture my desktop ",
        " desktop screenshot ",
        " take a screenshot ",
    ];
    SCREENSHOT_MARKERS
        .iter()
        .any(|marker| padded.contains(marker))
}

pub(super) fn query_explicitly_targets_host_local_clock(query: &str) -> bool {
    let padded = format!(" {} ", query.to_ascii_lowercase());
    const HOST_LOCAL_CLOCK_MARKERS: [&str; 12] = [
        " this machine ",
        " this computer ",
        " this host ",
        " this system ",
        " local machine ",
        " local computer ",
        " local host ",
        " local system ",
        " on my machine ",
        " on my computer ",
        " on this machine ",
        " on this computer ",
    ];
    HOST_LOCAL_CLOCK_MARKERS
        .iter()
        .any(|marker| padded.contains(marker))
}

pub(super) fn query_requires_remote_public_fact_grounding(facets: &QueryFacetProfile) -> bool {
    facets.grounded_external_required
        || facets.time_sensitive_public_fact
        || facets.goal.external_hits > 0
        || facets.goal.public_fact_hits > 0
        || facets.goal.explicit_url_hits > 0
}

pub(super) fn intent_supports_remote_public_fact_grounding(entry: &IntentMatrixEntry) -> bool {
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

pub(super) fn query_has_timer_scheduling_shape(query: &str) -> bool {
    let padded = format!(" {} ", query.to_ascii_lowercase());
    const TIMER_MARKERS: [&str; 6] = [
        " timer ",
        " countdown ",
        " alarm ",
        " remind me ",
        " reminder ",
        " notify me ",
    ];
    TIMER_MARKERS.iter().any(|marker| padded.contains(marker))
}

pub(super) fn query_expresses_command_execution_intent(
    query: &str,
    query_facets: &QueryFacetProfile,
) -> bool {
    query_facets.goal.command_hits > 0
        || query_facets.goal.workspace_hits > 0
        || query_facets.goal.install_hits > 0
        || query_has_timer_scheduling_shape(query)
}

pub(super) fn query_explicitly_mentions_app_target(query: &str) -> bool {
    let padded = format!(" {} ", query.to_ascii_lowercase());
    const APP_TARGET_MARKERS: [&str; 10] = [
        " app ",
        " application ",
        " program ",
        " calculator ",
        " browser ",
        " chrome ",
        " firefox ",
        " safari ",
        " terminal ",
        " settings ",
    ];
    APP_TARGET_MARKERS
        .iter()
        .any(|marker| padded.contains(marker))
}

pub(super) fn query_expresses_app_launch_intent(
    query: &str,
    query_facets: &QueryFacetProfile,
) -> bool {
    if query_requests_desktop_screenshot(query) || query_facets.goal.launch_hits == 0 {
        return false;
    }

    // Keep app launch from hijacking file/command workflows unless the user explicitly
    // identifies an application target.
    let command_directed = query_expresses_command_execution_intent(query, query_facets);
    !command_directed || query_explicitly_mentions_app_target(query)
}

pub(super) fn query_expresses_direct_ui_input(
    query: &str,
    query_facets: &QueryFacetProfile,
) -> bool {
    !query_requests_desktop_screenshot(query) && query_facets.goal.ui_hits > 0
}

pub(super) fn query_binding_satisfied(
    entry: &IntentMatrixEntry,
    query: &str,
    query_facets: &QueryFacetProfile,
) -> bool {
    if query_requires_remote_public_fact_grounding(query_facets)
        && !intent_supports_remote_public_fact_grounding(entry)
    {
        return false;
    }
    match query_binding_for_intent(entry) {
        IntentQueryBindingClass::None => true,
        IntentQueryBindingClass::HostLocal => {
            query_explicitly_targets_host_local_clock(query)
                || !query_requires_remote_public_fact_grounding(query_facets)
        }
        IntentQueryBindingClass::RemotePublicFact => {
            query_requires_remote_public_fact_grounding(query_facets)
        }
        IntentQueryBindingClass::AppLaunchDirected => {
            query_expresses_app_launch_intent(query, query_facets)
        }
        IntentQueryBindingClass::CommandDirected => {
            query_expresses_command_execution_intent(query, query_facets)
        }
        IntentQueryBindingClass::DirectUiInput => {
            query_expresses_direct_ui_input(query, query_facets)
        }
        IntentQueryBindingClass::DesktopScreenshot => query_requests_desktop_screenshot(query),
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
