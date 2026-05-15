use super::BrowserObservationArtifacts;
use ioi_types::app::runtime::computer_use::{
    ActionProposal, AffordanceGraph, AffordanceRecord, CommitGate, CommitGateStatus,
    ComputerActionKind, ComputerControlAdapterContract, ComputerUseLane, ComputerUseLease,
    ComputerUseObservationBundle, ComputerUseSessionMode, ComputerUseTargetEntry,
    ObservationRetentionMode, TargetIndex,
};

fn artifact_ref(observation_ref: &str, suffix: &str, present: bool) -> Option<String> {
    present.then(|| format!("{observation_ref}:{suffix}"))
}

pub fn owned_browser_adapter_contract() -> ComputerControlAdapterContract {
    ComputerControlAdapterContract::default()
}

pub fn owned_browser_lease(
    lease_id: impl Into<String>,
    target_hint: impl Into<String>,
    environment_ref: impl Into<String>,
) -> ComputerUseLease {
    ComputerUseLease {
        lease_id: lease_id.into(),
        target_hint: target_hint.into(),
        environment_ref: environment_ref.into(),
        lane: ComputerUseLane::NativeBrowser,
        session_mode: ComputerUseSessionMode::OwnedHermeticBrowser,
        ..ComputerUseLease::default()
    }
}

pub fn observation_bundle_from_browser_artifacts(
    lease_id: impl Into<String>,
    observation_ref: impl Into<String>,
    artifacts: &BrowserObservationArtifacts,
) -> ComputerUseObservationBundle {
    let observation_ref = observation_ref.into();
    ComputerUseObservationBundle {
        observation_ref: observation_ref.clone(),
        lease_id: lease_id.into(),
        lane: ComputerUseLane::NativeBrowser,
        session_mode: ComputerUseSessionMode::OwnedHermeticBrowser,
        url: artifacts.url.clone(),
        title: artifacts.page_title.clone(),
        dom_ref: artifact_ref(
            &observation_ref,
            "browsergym_dom",
            artifacts.browsergym_dom_text.is_some(),
        ),
        ax_ref: artifact_ref(
            &observation_ref,
            "browsergym_ax",
            artifacts.browsergym_axtree_text.is_some(),
        ),
        selector_map_ref: artifact_ref(
            &observation_ref,
            "selector_map",
            artifacts.browser_use_selector_map_text.is_some(),
        ),
        target_index_ref: artifact_ref(
            &observation_ref,
            "target_index",
            artifacts.browsergym_focused_bid.is_some()
                || artifacts.browser_use_selector_map_text.is_some(),
        ),
        retention_mode: ObservationRetentionMode::PromptVisibleSummaryOnly,
        ..ComputerUseObservationBundle::default()
    }
}

pub fn target_index_from_browser_artifacts(
    observation: &ComputerUseObservationBundle,
    artifacts: &BrowserObservationArtifacts,
) -> TargetIndex {
    let coordinate_space_id = format!("viewport:{}", observation.observation_ref);
    let mut targets = artifacts
        .browser_use_selector_map_text
        .as_deref()
        .map(|selector_map| {
            selector_map_targets(
                selector_map,
                &observation.observation_ref,
                observation.ax_ref.as_deref(),
            )
        })
        .unwrap_or_default();
    if targets.is_empty() {
        targets.push(document_target(
            observation,
            &coordinate_space_id,
            artifacts.browsergym_focused_bid.as_deref(),
        ));
    }
    TargetIndex {
        target_index_ref: observation
            .target_index_ref
            .clone()
            .unwrap_or_else(|| format!("{}:target_index", observation.observation_ref)),
        observation_ref: observation.observation_ref.clone(),
        coordinate_space_id,
        drift_state: "fresh".to_string(),
        targets,
    }
}

pub fn affordance_graph_from_target_index(target_index: &TargetIndex) -> AffordanceGraph {
    let affordances = target_index
        .targets
        .iter()
        .flat_map(|target| {
            target
                .available_actions
                .iter()
                .map(|action| AffordanceRecord {
                    target_ref: target.target_ref.clone(),
                    possible_action: *action,
                    action_preconditions: vec![
                        "fresh_observation".to_string(),
                        "target_index_present".to_string(),
                        "grounded_target_ref".to_string(),
                    ],
                    confidence: target.confidence,
                    expected_state_transition: expected_transition_for_action(*action),
                    risk_class: risk_class_for_action(*action).to_string(),
                    required_authority: authority_for_action(*action).to_string(),
                    confirmation_required: confirmation_required_for_action(*action),
                    fallback_action_paths: vec![
                        "reobserve".to_string(),
                        "switch_to_visual_lane".to_string(),
                    ],
                    invalidation_conditions: vec![
                        "navigation".to_string(),
                        "modal_interruption".to_string(),
                        "target_drift".to_string(),
                    ],
                })
        })
        .collect();
    AffordanceGraph {
        graph_ref: format!("{}:affordance_graph", target_index.target_index_ref),
        target_index_ref: target_index.target_index_ref.clone(),
        observation_ref: target_index.observation_ref.clone(),
        affordances,
    }
}

pub fn action_proposal_from_affordance_graph(
    run_id: impl AsRef<str>,
    proposed_by: impl Into<String>,
    affordance_graph: &AffordanceGraph,
) -> Option<ActionProposal> {
    let affordance = affordance_graph.affordances.first()?;
    let action = action_kind_slug(affordance.possible_action);
    let target_ref =
        (!affordance.target_ref.trim().is_empty()).then(|| affordance.target_ref.clone());
    let target_fragment = target_ref
        .as_deref()
        .map(stable_ref_fragment)
        .unwrap_or_else(|| action.to_string());
    Some(ActionProposal {
        proposal_ref: format!(
            "proposal_{}_native_browser_{}",
            stable_ref_fragment(run_id.as_ref()),
            target_fragment,
        ),
        proposed_by: proposed_by.into(),
        model_role: "grounder".to_string(),
        raw_model_output_ref: None,
        normalized_action_candidate: target_ref
            .as_deref()
            .map(|target| format!("{action} {target}"))
            .unwrap_or_else(|| action.to_string()),
        target_ref,
        confidence: affordance.confidence,
        rationale_summary: format!(
            "Selected top native-browser affordance from {} for policy review before execution.",
            affordance_graph.graph_ref,
        ),
        predicted_postcondition: affordance.expected_state_transition.clone(),
        risk_assessment: affordance.risk_class.clone(),
        policy_decision_ref: Some(format!(
            "policy_{}_native_browser_{}_proposal",
            stable_ref_fragment(run_id.as_ref()),
            target_fragment,
        )),
    })
}

pub fn commit_gate_for_action_proposal(
    run_id: impl AsRef<str>,
    proposal: &ActionProposal,
    affordance_graph: &AffordanceGraph,
) -> CommitGate {
    let proposal_target = proposal.target_ref.as_deref().unwrap_or_default();
    let affordance = affordance_graph
        .affordances
        .iter()
        .find(|candidate| candidate.target_ref == proposal_target)
        .or_else(|| affordance_graph.affordances.first());
    let requires_confirmation = affordance
        .map(|candidate| candidate.confirmation_required || candidate.risk_class != "read_only")
        .unwrap_or(true);
    let run_fragment = stable_ref_fragment(run_id.as_ref());
    let proposal_fragment = stable_ref_fragment(&proposal.proposal_ref);
    CommitGate {
        gate_ref: format!("commit_gate_{run_fragment}_{proposal_fragment}"),
        status: if requires_confirmation {
            CommitGateStatus::Pending
        } else {
            CommitGateStatus::NotRequired
        },
        final_action_ref: None,
        external_effect: if requires_confirmation {
            "possible_external_effect".to_string()
        } else {
            "none".to_string()
        },
        user_confirmation_required: requires_confirmation,
        pre_commit_summary: if requires_confirmation {
            format!(
                "Native-browser proposal '{}' requires confirmation before it can become an executable action.",
                proposal.normalized_action_candidate,
            )
        } else {
            format!(
                "Native-browser proposal '{}' is read-only and can remain proposal-only without a commit gate.",
                proposal.normalized_action_candidate,
            )
        },
        post_commit_verification_ref: None,
    }
}

fn selector_map_targets(
    selector_map: &str,
    observation_ref: &str,
    ax_ref: Option<&str>,
) -> Vec<ComputerUseTargetEntry> {
    selector_map
        .lines()
        .filter_map(|line| selector_map_target(line, observation_ref, ax_ref))
        .collect()
}

fn selector_map_target(
    line: &str,
    observation_ref: &str,
    ax_ref: Option<&str>,
) -> Option<ComputerUseTargetEntry> {
    let trimmed = line.trim();
    let backend_id = trimmed
        .strip_prefix('[')?
        .split_once(']')?
        .0
        .trim()
        .to_string();
    let tag = trimmed
        .split_once('<')
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .unwrap_or("element")
        .trim_matches('/')
        .to_ascii_lowercase();
    let target_id = attr_value(trimmed, "target_id");
    let label = attr_value(trimmed, "name")
        .or_else(|| attr_value(trimmed, "aria-label"))
        .or_else(|| attr_value(trimmed, "placeholder"))
        .unwrap_or_else(|| tag.clone());
    let mut semantic_ids = vec![format!("browser-use.backend-node:{backend_id}")];
    if let Some(target_id) = target_id.as_deref() {
        semantic_ids.push(format!("browser-use.target:{target_id}"));
    }
    Some(ComputerUseTargetEntry {
        target_ref: target_id
            .map(|target_id| format!("target:{observation_ref}:{target_id}"))
            .unwrap_or_else(|| format!("target:{observation_ref}:backend:{backend_id}")),
        label,
        role: role_for_tag(&tag).to_string(),
        semantic_ids,
        selectors: vec![format!("browser-use://backend-node/{backend_id}")],
        som_id: None,
        ax_ref: ax_ref.map(|value| format!("{value}#backend-{backend_id}")),
        bounds: None,
        confidence: confidence_for_tag(&tag),
        available_actions: actions_for_tag(&tag),
    })
}

fn document_target(
    observation: &ComputerUseObservationBundle,
    coordinate_space_id: &str,
    focused_bid: Option<&str>,
) -> ComputerUseTargetEntry {
    let mut semantic_ids = vec!["document".to_string(), "page-root".to_string()];
    if let Some(focused_bid) = focused_bid {
        semantic_ids.push(format!("browsergym.bid:{focused_bid}"));
    }
    ComputerUseTargetEntry {
        target_ref: format!("target:{}:document", observation.observation_ref),
        label: observation
            .title
            .clone()
            .unwrap_or_else(|| "Current page".to_string()),
        role: "document".to_string(),
        semantic_ids,
        selectors: vec!["html".to_string(), "body".to_string()],
        som_id: None,
        ax_ref: observation
            .ax_ref
            .as_ref()
            .map(|value| format!("{value}#document")),
        bounds: Some(ioi_types::app::runtime::computer_use::ComputerUseBounds {
            x: 0,
            y: 0,
            width: 1280,
            height: 720,
            coordinate_space_id: coordinate_space_id.to_string(),
        }),
        confidence: 90,
        available_actions: vec![ComputerActionKind::Inspect, ComputerActionKind::Scroll],
    }
}

fn attr_value(line: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let value = if let Some(stripped) = rest.strip_prefix('"') {
        stripped.split_once('"')?.0
    } else {
        rest.split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches("/>")
            .trim_end_matches('/')
    };
    (!value.trim().is_empty()).then(|| value.trim().to_string())
}

fn role_for_tag(tag: &str) -> &'static str {
    match tag {
        "a" => "link",
        "button" => "button",
        "input" | "textarea" => "textbox",
        "select" => "combobox",
        _ => "element",
    }
}

fn actions_for_tag(tag: &str) -> Vec<ComputerActionKind> {
    match tag {
        "button" | "a" => vec![ComputerActionKind::Inspect, ComputerActionKind::Click],
        "input" | "textarea" => vec![ComputerActionKind::Inspect, ComputerActionKind::TypeText],
        "select" => vec![ComputerActionKind::Inspect, ComputerActionKind::Select],
        _ => vec![ComputerActionKind::Inspect],
    }
}

fn action_kind_slug(action: ComputerActionKind) -> &'static str {
    match action {
        ComputerActionKind::Click => "click",
        ComputerActionKind::TypeText => "type_text",
        ComputerActionKind::KeyPress => "key_press",
        ComputerActionKind::Scroll => "scroll",
        ComputerActionKind::Drag => "drag",
        ComputerActionKind::Hover => "hover",
        ComputerActionKind::Select => "select",
        ComputerActionKind::Upload => "upload",
        ComputerActionKind::Clipboard => "clipboard",
        ComputerActionKind::Wait => "wait",
        ComputerActionKind::Shell => "shell",
        ComputerActionKind::MobileGesture => "mobile_gesture",
        ComputerActionKind::Navigate => "navigate",
        ComputerActionKind::Inspect => "inspect",
    }
}

fn stable_ref_fragment(value: &str) -> String {
    let mut fragment = String::with_capacity(value.len().min(64));
    let mut previous_was_separator = false;
    for ch in value.chars() {
        let normalized = if ch.is_ascii_alphanumeric() {
            previous_was_separator = false;
            Some(ch.to_ascii_lowercase())
        } else if !previous_was_separator {
            previous_was_separator = true;
            Some('_')
        } else {
            None
        };
        if let Some(normalized) = normalized {
            fragment.push(normalized);
        }
        if fragment.len() >= 64 {
            break;
        }
    }
    let trimmed = fragment.trim_matches('_');
    if trimmed.is_empty() {
        "target".to_string()
    } else {
        trimmed.to_string()
    }
}

fn confidence_for_tag(tag: &str) -> u8 {
    match tag {
        "button" | "a" | "input" | "textarea" | "select" => 94,
        _ => 82,
    }
}

fn authority_for_action(action: ComputerActionKind) -> &'static str {
    match action {
        ComputerActionKind::Inspect
        | ComputerActionKind::Scroll
        | ComputerActionKind::Hover
        | ComputerActionKind::Wait => "computer_use.native_browser.read",
        _ => "computer_use.native_browser.act",
    }
}

fn risk_class_for_action(action: ComputerActionKind) -> &'static str {
    match action {
        ComputerActionKind::Inspect
        | ComputerActionKind::Scroll
        | ComputerActionKind::Hover
        | ComputerActionKind::Wait => "read_only",
        _ => "possible_external_effect",
    }
}

fn confirmation_required_for_action(action: ComputerActionKind) -> bool {
    !matches!(
        action,
        ComputerActionKind::Inspect
            | ComputerActionKind::Scroll
            | ComputerActionKind::Hover
            | ComputerActionKind::Wait
    )
}

fn expected_transition_for_action(action: ComputerActionKind) -> String {
    match action {
        ComputerActionKind::Inspect => {
            "A read-only inspection summary can be produced without external side effects."
                .to_string()
        }
        ComputerActionKind::Scroll => {
            "The viewport position changes after a grounded scroll.".to_string()
        }
        ComputerActionKind::Click => {
            "The selected element may activate navigation, submit, or open UI state.".to_string()
        }
        ComputerActionKind::TypeText => "The selected field receives text input.".to_string(),
        ComputerActionKind::Select => "The selected option changes form state.".to_string(),
        _ => "The target state changes according to the grounded browser action.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn artifacts() -> BrowserObservationArtifacts {
        BrowserObservationArtifacts {
            captured_at: Instant::now(),
            url: Some("https://example.test/app".to_string()),
            page_title: Some("Example App".to_string()),
            browser_use_state_text: Some("state".to_string()),
            browser_use_selector_map_text: Some("button=submit".to_string()),
            browser_use_html_text: None,
            browser_use_eval_text: None,
            browser_use_markdown_text: None,
            browser_use_pagination_text: None,
            browser_use_tabs_text: None,
            browser_use_page_info_text: None,
            browser_use_pending_requests_text: None,
            browser_use_recent_events_text: None,
            browser_use_closed_popup_messages_text: None,
            browsergym_extra_properties_text: None,
            browsergym_focused_bid: Some("bid-1".to_string()),
            browsergym_dom_text: Some("<button bid=\"bid-1\">Submit</button>".to_string()),
            browsergym_axtree_text: Some("button Submit".to_string()),
        }
    }

    #[test]
    fn owned_browser_adapter_defaults_to_native_browser_contract() {
        let adapter = owned_browser_adapter_contract();
        assert_eq!(adapter.lane, ComputerUseLane::NativeBrowser);
        assert!(adapter
            .supported_session_modes
            .contains(&ComputerUseSessionMode::OwnedHermeticBrowser));
        assert!(adapter.emits_observation_bundle);
        assert!(adapter.emits_action_receipts);
        assert!(adapter.fail_closed_when_unavailable);
    }

    #[test]
    fn owned_browser_lease_is_cleanup_required_and_hermetic() {
        let lease = owned_browser_lease("lease:1", "https://example.test", "browser:owned");
        assert_eq!(lease.lease_id, "lease:1");
        assert_eq!(lease.target_hint, "https://example.test");
        assert_eq!(lease.environment_ref, "browser:owned");
        assert_eq!(lease.lane, ComputerUseLane::NativeBrowser);
        assert_eq!(
            lease.session_mode,
            ComputerUseSessionMode::OwnedHermeticBrowser
        );
        assert!(lease.cleanup_required);
    }

    #[test]
    fn browser_artifacts_project_to_observation_bundle_refs_without_raw_persistence() {
        let bundle = observation_bundle_from_browser_artifacts("lease:1", "obs:1", &artifacts());
        assert_eq!(bundle.lease_id, "lease:1");
        assert_eq!(bundle.observation_ref, "obs:1");
        assert_eq!(bundle.url.as_deref(), Some("https://example.test/app"));
        assert_eq!(bundle.title.as_deref(), Some("Example App"));
        assert_eq!(bundle.dom_ref.as_deref(), Some("obs:1:browsergym_dom"));
        assert_eq!(bundle.ax_ref.as_deref(), Some("obs:1:browsergym_ax"));
        assert_eq!(
            bundle.selector_map_ref.as_deref(),
            Some("obs:1:selector_map")
        );
        assert_eq!(
            bundle.target_index_ref.as_deref(),
            Some("obs:1:target_index")
        );
        assert_eq!(
            bundle.retention_mode,
            ObservationRetentionMode::PromptVisibleSummaryOnly
        );
    }

    #[test]
    fn browser_artifacts_project_selector_map_to_targets_and_affordances() {
        let mut artifacts = artifacts();
        artifacts.browser_use_selector_map_text = Some(
            "[42] <button name=Submit target_id=target-submit />\n\
             [43] <input name=Search placeholder=Search target_id=target-search />"
                .to_string(),
        );
        let observation = observation_bundle_from_browser_artifacts("lease:1", "obs:1", &artifacts);
        let target_index = target_index_from_browser_artifacts(&observation, &artifacts);

        assert_eq!(target_index.target_index_ref, "obs:1:target_index");
        assert_eq!(target_index.targets.len(), 2);
        let button = &target_index.targets[0];
        assert_eq!(button.target_ref, "target:obs:1:target-submit");
        assert_eq!(button.label, "Submit");
        assert_eq!(button.role, "button");
        assert!(button
            .available_actions
            .contains(&ComputerActionKind::Click));
        let input = &target_index.targets[1];
        assert_eq!(input.label, "Search");
        assert!(input
            .available_actions
            .contains(&ComputerActionKind::TypeText));

        let affordance_graph = affordance_graph_from_target_index(&target_index);
        assert_eq!(
            affordance_graph.target_index_ref,
            target_index.target_index_ref
        );
        assert!(affordance_graph.affordances.iter().any(|affordance| {
            affordance.target_ref == button.target_ref
                && affordance.possible_action == ComputerActionKind::Click
                && affordance.confirmation_required
                && affordance.risk_class == "possible_external_effect"
        }));
        assert!(affordance_graph.affordances.iter().any(|affordance| {
            affordance.target_ref == input.target_ref
                && affordance.possible_action == ComputerActionKind::Inspect
                && !affordance.confirmation_required
                && affordance.required_authority == "computer_use.native_browser.read"
        }));
    }

    #[test]
    fn top_affordance_projects_to_policy_gated_action_proposal() {
        let mut artifacts = artifacts();
        artifacts.browser_use_selector_map_text =
            Some("[42] <button name=Submit target_id=target-submit />".to_string());
        let observation = observation_bundle_from_browser_artifacts("lease:1", "obs:1", &artifacts);
        let target_index = target_index_from_browser_artifacts(&observation, &artifacts);
        let affordance_graph = affordance_graph_from_target_index(&target_index);

        let proposal = action_proposal_from_affordance_graph(
            "run:browser",
            "runtime_service_bridge",
            &affordance_graph,
        )
        .expect("top affordance should produce a proposal");
        assert!(proposal.is_ready_for_execution());
        assert_eq!(proposal.proposed_by, "runtime_service_bridge");
        assert_eq!(proposal.model_role, "grounder");
        assert_eq!(
            proposal.target_ref.as_deref(),
            Some("target:obs:1:target-submit")
        );
        assert_eq!(proposal.risk_assessment, "read_only");

        let gate = commit_gate_for_action_proposal("run:browser", &proposal, &affordance_graph);
        assert_eq!(gate.status, CommitGateStatus::NotRequired);
        assert!(!gate.blocks_without_confirmation());
        assert_eq!(gate.external_effect, "none");
    }

    #[test]
    fn mutating_affordance_blocks_at_commit_gate_until_confirmed() {
        let mut artifacts = artifacts();
        artifacts.browser_use_selector_map_text =
            Some("[42] <button name=Submit target_id=target-submit />".to_string());
        let observation = observation_bundle_from_browser_artifacts("lease:1", "obs:1", &artifacts);
        let target_index = target_index_from_browser_artifacts(&observation, &artifacts);
        let mut affordance_graph = affordance_graph_from_target_index(&target_index);
        affordance_graph
            .affordances
            .retain(|affordance| affordance.possible_action == ComputerActionKind::Click);

        let proposal = action_proposal_from_affordance_graph(
            "run:browser",
            "runtime_service_bridge",
            &affordance_graph,
        )
        .expect("click affordance should produce a proposal");
        assert_eq!(proposal.risk_assessment, "possible_external_effect");

        let gate = commit_gate_for_action_proposal("run:browser", &proposal, &affordance_graph);
        assert_eq!(gate.status, CommitGateStatus::Pending);
        assert!(gate.blocks_without_confirmation());
        assert_eq!(gate.external_effect, "possible_external_effect");
    }

    #[test]
    fn browser_artifacts_fallback_to_document_target_without_selector_map() {
        let mut artifacts = artifacts();
        artifacts.browser_use_selector_map_text = None;
        let observation = observation_bundle_from_browser_artifacts("lease:1", "obs:1", &artifacts);
        let target_index = target_index_from_browser_artifacts(&observation, &artifacts);

        assert_eq!(target_index.targets.len(), 1);
        assert_eq!(target_index.targets[0].role, "document");
        assert!(target_index.targets[0]
            .semantic_ids
            .contains(&"browsergym.bid:bid-1".to_string()));
        assert!(target_index.targets[0]
            .available_actions
            .contains(&ComputerActionKind::Scroll));
    }
}
