use super::reward_meets_floor;
use super::types::{
    AllowedToolProfile, BenchmarkSupportState, ComputerUseCase, ComputerUseCaseResult,
    ComputerUseMode, GapClass, KernelBehaviorObservation, LocalJudge, RecipeId, ValidationSummary,
};
use serde_json::Value;

struct GapClassification {
    support_state: BenchmarkSupportState,
    primary_gap_class: Option<GapClass>,
    secondary_gap_tags: Vec<String>,
}

fn is_synthetic_kernel_tool(tool_name: &str) -> bool {
    tool_name.starts_with("system::")
}

fn allowed_tools(mode: ComputerUseMode, profile: AllowedToolProfile) -> &'static [&'static str] {
    match (mode, profile) {
        (ComputerUseMode::Oracle, _) => &[],
        (_, AllowedToolProfile::BrowserCore) => &[
            "browser__navigate",
            "browser__snapshot",
            "browser__click",
            "browser__click_element",
            "browser__hover",
            "browser__move_mouse",
            "browser__mouse_down",
            "browser__mouse_up",
            "browser__synthetic_click",
            "browser__type",
            "browser__key",
            "browser__wait",
            "browser__scroll",
            "browser__canvas_summary",
            "browser__screenshot",
            "agent__complete",
            "chat__reply",
        ],
        (_, AllowedToolProfile::BrowserCoreWithSelect) => &[
            "browser__navigate",
            "browser__snapshot",
            "browser__click",
            "browser__click_element",
            "browser__hover",
            "browser__move_mouse",
            "browser__mouse_down",
            "browser__mouse_up",
            "browser__synthetic_click",
            "browser__type",
            "browser__key",
            "browser__wait",
            "browser__scroll",
            "browser__canvas_summary",
            "browser__screenshot",
            "browser__dropdown_options",
            "browser__select_dropdown",
            "agent__complete",
            "chat__reply",
        ],
        (_, AllowedToolProfile::BrowserCoreWithSelectionClipboard) => &[
            "browser__navigate",
            "browser__snapshot",
            "browser__click",
            "browser__click_element",
            "browser__hover",
            "browser__move_mouse",
            "browser__mouse_down",
            "browser__mouse_up",
            "browser__synthetic_click",
            "browser__type",
            "browser__select_text",
            "browser__key",
            "browser__dropdown_options",
            "browser__select_dropdown",
            "browser__copy_selection",
            "browser__paste_clipboard",
            "browser__wait",
            "browser__scroll",
            "browser__canvas_summary",
            "browser__screenshot",
            "agent__complete",
            "chat__reply",
        ],
        (_, AllowedToolProfile::OracleBridge) => &[],
    }
}

pub fn judge_case(
    case: &ComputerUseCase,
    mut result: ComputerUseCaseResult,
) -> ComputerUseCaseResult {
    let (task_success, reward_floor_met, notes) = match case.local_judge {
        LocalJudge::BridgeReward | LocalJudge::MiniwobReward => {
            let effective_reward = result
                .bridge_state
                .info
                .raw_reward
                .unwrap_or(result.final_reward);
            let reward_floor_met = reward_meets_floor(effective_reward, case.expected_reward_floor);
            let mut notes = Vec::new();
            if effective_reward != result.final_reward {
                notes.push(format!(
                    "judge used raw_reward={:.3} instead of decayed final_reward={:.3}",
                    effective_reward, result.final_reward
                ));
            }
            (
                reward_floor_met && result.terminated == case.expected_pass,
                reward_floor_met,
                notes,
            )
        }
        LocalJudge::HoverShapeReceipts => judge_hover_shape_receipts(&result),
    };

    let allowed = allowed_tools(result.mode, case.allowed_tool_profile);
    let real_executed_tools = result
        .kernel_behavior
        .executed_tools
        .iter()
        .filter(|tool_name| !is_synthetic_kernel_tool(tool_name))
        .cloned()
        .collect::<Vec<_>>();
    let disallowed_tools = result
        .kernel_behavior
        .executed_tools
        .iter()
        .filter(|tool_name| !is_synthetic_kernel_tool(tool_name))
        .filter(|tool_name| !allowed.is_empty() && !allowed.contains(&tool_name.as_str()))
        .cloned()
        .collect::<Vec<_>>();

    let kernel_success = if matches!(result.mode, ComputerUseMode::Oracle) {
        disallowed_tools.is_empty()
    } else {
        disallowed_tools.is_empty() && !real_executed_tools.is_empty()
    };

    result.kernel_behavior = KernelBehaviorObservation {
        executed_tools: real_executed_tools,
        disallowed_tools,
        ..result.kernel_behavior
    };
    result.validation = ValidationSummary {
        task_success,
        kernel_success,
        reward_floor_met,
        terminated: result.terminated,
        notes,
    };
    result.overall_pass = task_success && kernel_success;
    if result.overall_pass {
        result.failure_class = None;
    }
    if !result.validation.task_success && result.failure_class.is_none() {
        result.failure_class = Some("task_incomplete".to_string());
    }
    if !result.validation.kernel_success && result.failure_class.is_none() {
        result.failure_class = Some("kernel_contract_violation".to_string());
    }
    let classification = classify_gap(case, &result);
    result.support_state = classification.support_state;
    result.primary_gap_class = classification.primary_gap_class;
    result.secondary_gap_tags = classification.secondary_gap_tags;
    result
}

fn judge_hover_shape_receipts(result: &ComputerUseCaseResult) -> (bool, bool, Vec<String>) {
    let mut hover_receipts = 0usize;
    let mut total_wait_ms = 0u64;

    for step in &result.tool_steps {
        if step.success && step.tool_name == "browser__wait" {
            if let Some(ms) = step.arguments.get("ms").and_then(Value::as_u64) {
                total_wait_ms = total_wait_ms.saturating_add(ms);
            }
        }

        if !step.success || step.tool_name != "browser__hover" {
            continue;
        }

        let Some(history_entry) = step.history_entry.as_deref() else {
            continue;
        };
        let Ok(payload) = serde_json::from_str::<Value>(history_entry) else {
            continue;
        };
        let pointer = payload.get("pointer").and_then(Value::as_object);
        let hovered = pointer
            .and_then(|pointer| pointer.get("hovered"))
            .and_then(Value::as_bool)
            == Some(true);
        let target_selector = pointer
            .and_then(|pointer| pointer.get("target"))
            .and_then(Value::as_object)
            .and_then(|target| target.get("selector"))
            .and_then(Value::as_str);
        if hovered && target_selector == Some("#highlight") {
            hover_receipts = hover_receipts.saturating_add(1);
        }
    }

    let hover_success = hover_receipts >= 3 && total_wait_ms >= 2_200;
    let notes = vec![format!(
        "hover-shape local judge counted {} successful browser__hover receipts on #highlight across {}ms of browser__wait time",
        hover_receipts, total_wait_ms
    )];
    (hover_success, hover_success, notes)
}

fn classify_gap(case: &ComputerUseCase, result: &ComputerUseCaseResult) -> GapClassification {
    if result.overall_pass {
        return GapClassification {
            support_state: BenchmarkSupportState::Passing,
            primary_gap_class: None,
            secondary_gap_tags: Vec::new(),
        };
    }

    let failure_gap = primary_gap_from_failure_class(result.failure_class.as_deref());
    if !result.validation.kernel_success && failure_gap.is_none() {
        return GapClassification {
            support_state: BenchmarkSupportState::KnownGap,
            primary_gap_class: Some(GapClass::VerificationGap),
            secondary_gap_tags: vec!["kernel_contract".to_string()],
        };
    }

    let (env_gap, mut env_tags) = env_gap_hints(&case.env_id);
    let support_state = if matches!(failure_gap, Some(GapClass::InfraOrBridgeGap)) {
        BenchmarkSupportState::InfraBlocked
    } else {
        BenchmarkSupportState::KnownGap
    };

    if let Some(tag) = failure_tag_hint(result.failure_class.as_deref()) {
        push_unique_tag(&mut env_tags, tag);
    }

    let primary_gap_class = if case.recipe == RecipeId::SurveyOnly {
        Some(env_gap.unwrap_or(GapClass::PlannerGap))
    } else {
        failure_gap.or(env_gap).or(Some(GapClass::PlannerGap))
    };

    GapClassification {
        support_state,
        primary_gap_class,
        secondary_gap_tags: env_tags,
    }
}

fn primary_gap_from_failure_class(failure_class: Option<&str>) -> Option<GapClass> {
    match failure_class.unwrap_or_default() {
        "kernel_contract_violation" => Some(GapClass::VerificationGap),
        "harness_error" => Some(GapClass::InfraOrBridgeGap),
        "PermissionOrApprovalRequired" | "PolicyBlocked" | "UserInterventionNeeded" => {
            Some(GapClass::InfraOrBridgeGap)
        }
        "TargetNotFound" | "CatalogSurvey" => None,
        "TimeoutOrHang" => Some(GapClass::RecoveryGap),
        "agent_paused" | "agent_failed" | "task_not_terminated" | "task_incomplete" => {
            Some(GapClass::PlannerGap)
        }
        other if other.contains("bridge") || other.contains("launch Chromium") => {
            Some(GapClass::InfraOrBridgeGap)
        }
        _ => None,
    }
}

fn failure_tag_hint(failure_class: Option<&str>) -> Option<&'static str> {
    match failure_class.unwrap_or_default() {
        "TargetNotFound" => Some("ocr_readback"),
        "TimeoutOrHang" => Some("stabilization"),
        "CatalogSurvey" => Some("survey_only"),
        "PermissionOrApprovalRequired" => Some("approval_required"),
        "PolicyBlocked" => Some("policy_scope"),
        "UserInterventionNeeded" => Some("user_intervention"),
        _ => None,
    }
}

fn env_gap_hints(env_id: &str) -> (Option<GapClass>, Vec<String>) {
    let env_id = env_id.to_ascii_lowercase();
    let mut tags = Vec::new();

    if env_id.contains("hover") {
        push_unique_tag(&mut tags, "hover");
        push_unique_tag(&mut tags, "pointer_move");
        return (Some(GapClass::MissingPointerPrimitive), tags);
    }

    if env_id.contains("copy-paste") {
        push_unique_tag(&mut tags, "clipboard");
        push_unique_tag(&mut tags, "key_chord");
        return (Some(GapClass::MissingClipboardPrimitive), tags);
    }

    if env_id.contains("highlight") || env_id == "text-editor" {
        push_unique_tag(&mut tags, "selection_range");
        if env_id == "text-editor" {
            push_unique_tag(&mut tags, "key_chord");
        }
        return (Some(GapClass::MissingSelectionPrimitive), tags);
    }

    if env_id.contains("drag")
        || env_id.contains("resize")
        || env_id.contains("draw")
        || env_id.contains("slider")
        || env_id.contains("colorwheel")
    {
        push_unique_tag(&mut tags, "drag");
        push_unique_tag(&mut tags, "mouse_down_up");
        return (Some(GapClass::MissingPointerPrimitive), tags);
    }

    if env_id.contains("terminal")
        || env_id.contains("form-sequence")
        || env_id.contains("login-user-popup")
    {
        push_unique_tag(&mut tags, "key_chord");
        push_unique_tag(&mut tags, "focus_traversal");
        return (Some(GapClass::MissingKeyboardPrimitive), tags);
    }

    if env_id.contains("find-")
        || env_id.contains("read-table")
        || env_id.contains("social-media")
        || env_id.contains("email-inbox")
        || env_id.contains("stock-market")
        || env_id.contains("phone-book")
        || env_id.contains("identify-shape")
        || env_id.contains("count-shape")
        || env_id.contains("count-sides")
        || env_id.contains("unicode-test")
        || env_id.contains("visual-addition")
        || env_id.contains("simple-")
        || env_id.contains("odd-or-even")
        || env_id.contains("guess-number")
    {
        push_unique_tag(&mut tags, "ocr_readback");
        return (Some(GapClass::ObservationGap), tags);
    }

    if env_id.contains("workflow-mutation-isolation") {
        push_unique_tag(&mut tags, "multi_page");
        push_unique_tag(&mut tags, "persistent_state");
        push_unique_tag(&mut tags, "verification");
        push_unique_tag(&mut tags, "audit_history");
        push_unique_tag(&mut tags, "recovery");
        push_unique_tag(&mut tags, "negative_verification");
        push_unique_tag(&mut tags, "cross_ticket");
        push_unique_tag(&mut tags, "mutation_isolation");
        return (Some(GapClass::PlannerGap), tags);
    }

    if env_id.contains("workflow-stale-queue-reorder") {
        push_unique_tag(&mut tags, "multi_page");
        push_unique_tag(&mut tags, "persistent_state");
        push_unique_tag(&mut tags, "verification");
        push_unique_tag(&mut tags, "audit_history");
        push_unique_tag(&mut tags, "recovery");
        push_unique_tag(&mut tags, "negative_verification");
        push_unique_tag(&mut tags, "stale_observation");
        push_unique_tag(&mut tags, "queue_reorder");
        return (Some(GapClass::PlannerGap), tags);
    }

    if env_id.contains("workflow-audit-history") {
        push_unique_tag(&mut tags, "multi_page");
        push_unique_tag(&mut tags, "persistent_state");
        push_unique_tag(&mut tags, "verification");
        push_unique_tag(&mut tags, "audit_history");
        push_unique_tag(&mut tags, "recovery");
        return (Some(GapClass::PlannerGap), tags);
    }

    if env_id.contains("workflow-ticket-routing") || env_id.contains("workflow") {
        push_unique_tag(&mut tags, "multi_page");
        push_unique_tag(&mut tags, "persistent_state");
        push_unique_tag(&mut tags, "verification");
        return (Some(GapClass::PlannerGap), tags);
    }

    if env_id.contains("menu")
        || env_id.contains("dialog")
        || env_id.contains("widget")
        || env_id.contains("date")
        || env_id.contains("flight")
        || env_id.contains("ticket")
        || env_id.contains("calendar")
        || env_id.contains("tree")
        || env_id.contains("order-food")
        || env_id.contains("multi-")
    {
        return (Some(GapClass::PlannerGap), tags);
    }

    (None, tags)
}

fn push_unique_tag(tags: &mut Vec<String>, tag: impl Into<String>) {
    let tag = tag.into();
    if !tags.iter().any(|existing| existing == &tag) {
        tags.push(tag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::computer_use_suite::types::{
        AgentBackend, ArtifactBundle, BenchmarkSupportState, BridgeState, ComputerUseMode, TaskSet,
        ToolStepRecord,
    };
    use serde_json::json;

    fn base_result() -> ComputerUseCaseResult {
        ComputerUseCaseResult {
            case_id: "case".to_string(),
            env_id: "hover-shape".to_string(),
            seed: 1,
            mode: ComputerUseMode::Runtime,
            agent_backend: None,
            task_set: TaskSet::Catalog,
            utterance: String::new(),
            elapsed_ms: 0,
            expected_reward_floor: 1.0,
            final_reward: 0.0,
            expected_pass: true,
            terminated: false,
            truncated: false,
            overall_pass: false,
            tool_steps: Vec::new(),
            oracle_steps: Vec::new(),
            kernel_events: Vec::new(),
            bridge_state: BridgeState::default(),
            kernel_behavior: KernelBehaviorObservation {
                executed_tools: vec!["browser__snapshot".to_string()],
                ..KernelBehaviorObservation::default()
            },
            validation: ValidationSummary {
                task_success: false,
                kernel_success: true,
                reward_floor_met: false,
                terminated: false,
                notes: Vec::new(),
            },
            artifacts: ArtifactBundle::default(),
            failure_class: Some("CatalogSurvey".to_string()),
            support_state: BenchmarkSupportState::NotYetAttempted,
            primary_gap_class: None,
            secondary_gap_tags: Vec::new(),
        }
    }

    #[test]
    fn survey_hover_case_is_classified_as_pointer_gap() {
        let case = ComputerUseCase {
            id: "hover".to_string(),
            env_id: "hover-shape".to_string(),
            seed: 1,
            task_set: TaskSet::Catalog,
            max_steps: 1,
            timeout_seconds: 1,
            allowed_tool_profile: AllowedToolProfile::BrowserCore,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::MiniwobReward,
            recipe: RecipeId::SurveyOnly,
        };

        let classified = judge_case(&case, base_result());
        assert_eq!(classified.support_state, BenchmarkSupportState::KnownGap);
        assert_eq!(
            classified.primary_gap_class,
            Some(GapClass::MissingPointerPrimitive)
        );
        assert!(classified
            .secondary_gap_tags
            .iter()
            .any(|tag| tag == "hover"));
    }

    #[test]
    fn hover_shape_receipts_can_pass_without_bridge_termination() {
        let case = ComputerUseCase {
            id: "hover".to_string(),
            env_id: "hover-shape".to_string(),
            seed: 1,
            task_set: TaskSet::Catalog,
            max_steps: 8,
            timeout_seconds: 20,
            allowed_tool_profile: AllowedToolProfile::BrowserCore,
            expected_reward_floor: 0.0,
            expected_pass: true,
            local_judge: LocalJudge::HoverShapeReceipts,
            recipe: RecipeId::HoverShape,
        };

        let mut result = base_result();
        result.failure_class = Some("task_not_terminated".to_string());
        result.tool_steps = vec![
            ToolStepRecord {
                step_index: 1,
                tool_name: "browser__hover".to_string(),
                arguments: json!({ "selector": "#highlight" }),
                success: true,
                history_entry: Some(
                    json!({
                        "pointer": {
                            "action": "hover",
                            "hovered": true,
                            "target": { "selector": "#highlight" }
                        }
                    })
                    .to_string(),
                ),
                error: None,
                bridge_reward: 0.0,
                bridge_terminated: false,
            },
            ToolStepRecord {
                step_index: 2,
                tool_name: "browser__wait".to_string(),
                arguments: json!({ "ms": 1300 }),
                success: true,
                history_entry: Some("Waited 1300ms".to_string()),
                error: None,
                bridge_reward: 0.0,
                bridge_terminated: false,
            },
            ToolStepRecord {
                step_index: 3,
                tool_name: "browser__hover".to_string(),
                arguments: json!({ "selector": "#highlight" }),
                success: true,
                history_entry: Some(
                    json!({
                        "pointer": {
                            "action": "hover",
                            "hovered": true,
                            "target": { "selector": "#highlight" }
                        }
                    })
                    .to_string(),
                ),
                error: None,
                bridge_reward: 0.0,
                bridge_terminated: false,
            },
            ToolStepRecord {
                step_index: 4,
                tool_name: "browser__wait".to_string(),
                arguments: json!({ "ms": 1300 }),
                success: true,
                history_entry: Some("Waited 1300ms".to_string()),
                error: None,
                bridge_reward: 0.0,
                bridge_terminated: false,
            },
            ToolStepRecord {
                step_index: 5,
                tool_name: "browser__hover".to_string(),
                arguments: json!({ "selector": "#highlight" }),
                success: true,
                history_entry: Some(
                    json!({
                        "pointer": {
                            "action": "hover",
                            "hovered": true,
                            "target": { "selector": "#highlight" }
                        }
                    })
                    .to_string(),
                ),
                error: None,
                bridge_reward: 0.0,
                bridge_terminated: false,
            },
        ];

        let judged = judge_case(&case, result);
        assert!(judged.overall_pass);
        assert!(judged.validation.task_success);
        assert!(judged.validation.reward_floor_met);
        assert!(judged.failure_class.is_none());
    }

    #[test]
    fn miniwob_reward_judge_tolerates_float_noise_at_reward_floor() {
        let case = ComputerUseCase {
            id: "bisect".to_string(),
            env_id: "bisect-angle".to_string(),
            seed: 1,
            task_set: TaskSet::Catalog,
            max_steps: 8,
            timeout_seconds: 20,
            allowed_tool_profile: AllowedToolProfile::BrowserCore,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::MiniwobReward,
            recipe: RecipeId::SurveyOnly,
        };

        let mut result = base_result();
        result.mode = ComputerUseMode::Agent;
        result.terminated = true;
        result.final_reward = 0.0633;
        result.bridge_state.reward = 0.0633;
        result.bridge_state.info.raw_reward = Some(0.999_999_94);
        result.kernel_behavior.executed_tools = vec!["browser__synthetic_click".to_string()];
        result.failure_class = None;

        let judged = judge_case(&case, result);
        assert!(judged.overall_pass);
        assert!(judged.validation.task_success);
        assert!(judged.validation.reward_floor_met);
    }

    #[test]
    fn synthetic_kernel_events_do_not_count_as_executed_tools() {
        let case = ComputerUseCase {
            id: "tabs".to_string(),
            env_id: "click-tab-2".to_string(),
            seed: 1,
            task_set: TaskSet::Catalog,
            max_steps: 8,
            timeout_seconds: 20,
            allowed_tool_profile: AllowedToolProfile::BrowserCore,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::MiniwobReward,
            recipe: RecipeId::ClickTab,
        };

        let mut result = base_result();
        result.mode = ComputerUseMode::Agent;
        result.kernel_behavior.executed_tools = vec![
            "browser__navigate".to_string(),
            "browser__click".to_string(),
            "system::max_steps_reached".to_string(),
        ];
        result.failure_class = Some("NoEffectAfterAction".to_string());

        let judged = judge_case(&case, result);
        assert!(judged.validation.kernel_success);
        assert_eq!(
            judged.kernel_behavior.executed_tools,
            vec![
                "browser__navigate".to_string(),
                "browser__click".to_string()
            ]
        );
        assert!(judged.kernel_behavior.disallowed_tools.is_empty());
    }

    #[test]
    fn workflow_permission_failures_are_classified_as_infra_with_workflow_tags() {
        let case = ComputerUseCase {
            id: "workflow_ticket_routing_billing_review".to_string(),
            env_id: "workflow-ticket-routing".to_string(),
            seed: 42,
            task_set: TaskSet::Workflow,
            max_steps: 12,
            timeout_seconds: 25,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowTicketRouting,
        };

        let mut result = base_result();
        result.env_id = case.env_id.clone();
        result.task_set = TaskSet::Workflow;
        result.mode = ComputerUseMode::Agent;
        result.kernel_behavior.executed_tools = vec!["browser__navigate".to_string()];
        result.failure_class = Some("PermissionOrApprovalRequired".to_string());

        let judged = judge_case(&case, result);
        assert_eq!(judged.support_state, BenchmarkSupportState::InfraBlocked);
        assert_eq!(judged.primary_gap_class, Some(GapClass::InfraOrBridgeGap));
        assert!(judged
            .secondary_gap_tags
            .iter()
            .any(|tag| tag == "multi_page"));
        assert!(judged
            .secondary_gap_tags
            .iter()
            .any(|tag| tag == "persistent_state"));
        assert!(judged
            .secondary_gap_tags
            .iter()
            .any(|tag| tag == "verification"));
        assert!(judged
            .secondary_gap_tags
            .iter()
            .any(|tag| tag == "approval_required"));
    }

    #[test]
    fn bridge_startup_failure_is_classified_as_infra_even_without_kernel_success() {
        let case = ComputerUseCase {
            id: "miniwob_click_button_smoke".to_string(),
            env_id: "click-button".to_string(),
            seed: 101,
            task_set: TaskSet::Smoke,
            max_steps: 8,
            timeout_seconds: 20,
            allowed_tool_profile: AllowedToolProfile::BrowserCore,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::MiniwobReward,
            recipe: RecipeId::ClickButton,
        };

        let mut result = base_result();
        result.case_id = case.id.clone();
        result.env_id = case.env_id.clone();
        result.task_set = TaskSet::Smoke;
        result.mode = ComputerUseMode::Agent;
        result.agent_backend = Some(AgentBackend::LiveHttp);
        result.kernel_behavior = KernelBehaviorObservation::default();
        result.validation = ValidationSummary {
            kernel_success: false,
            ..ValidationSummary::default()
        };
        result.failure_class = Some("bridge_startup_failure".to_string());

        let judged = judge_case(&case, result);
        assert_eq!(judged.support_state, BenchmarkSupportState::InfraBlocked);
        assert_eq!(judged.primary_gap_class, Some(GapClass::InfraOrBridgeGap));
        assert!(judged
            .secondary_gap_tags
            .iter()
            .all(|tag| tag != "kernel_contract"));
    }

    #[test]
    fn workflow_audit_history_env_hints_include_audit_and_recovery_tags() {
        let case = ComputerUseCase {
            id: "workflow_audit_history_network_ops".to_string(),
            env_id: "workflow-audit-history".to_string(),
            seed: 61,
            task_set: TaskSet::WorkflowAudit,
            max_steps: 24,
            timeout_seconds: 40,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowAuditHistory,
        };

        let mut result = base_result();
        result.env_id = case.env_id.clone();
        result.task_set = TaskSet::WorkflowAudit;
        result.mode = ComputerUseMode::Agent;
        result.kernel_behavior.executed_tools = vec!["browser__navigate".to_string()];
        result.failure_class = Some("task_incomplete".to_string());

        let judged = judge_case(&case, result);
        assert_eq!(judged.primary_gap_class, Some(GapClass::PlannerGap));
        assert!(judged
            .secondary_gap_tags
            .iter()
            .any(|tag| tag == "audit_history"));
        assert!(judged
            .secondary_gap_tags
            .iter()
            .any(|tag| tag == "recovery"));
    }

    #[test]
    fn workflow_mutation_env_hints_include_negative_verification_tags() {
        let case = ComputerUseCase {
            id: "workflow_mutation_isolation_network_ops".to_string(),
            env_id: "workflow-mutation-isolation".to_string(),
            seed: 71,
            task_set: TaskSet::WorkflowMutation,
            max_steps: 32,
            timeout_seconds: 45,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowMutationIsolation,
        };

        let mut result = base_result();
        result.env_id = case.env_id.clone();
        result.task_set = TaskSet::WorkflowMutation;
        result.mode = ComputerUseMode::Agent;
        result.kernel_behavior.executed_tools = vec!["browser__navigate".to_string()];
        result.failure_class = Some("task_incomplete".to_string());

        let judged = judge_case(&case, result);
        assert_eq!(judged.primary_gap_class, Some(GapClass::PlannerGap));
        assert!(judged
            .secondary_gap_tags
            .iter()
            .any(|tag| tag == "negative_verification"));
        assert!(judged
            .secondary_gap_tags
            .iter()
            .any(|tag| tag == "cross_ticket"));
        assert!(judged
            .secondary_gap_tags
            .iter()
            .any(|tag| tag == "mutation_isolation"));
    }

    #[test]
    fn workflow_reorder_env_hints_include_stale_queue_tags() {
        let case = ComputerUseCase {
            id: "workflow_stale_queue_reorder_network_ops".to_string(),
            env_id: "workflow-stale-queue-reorder".to_string(),
            seed: 81,
            task_set: TaskSet::WorkflowReorder,
            max_steps: 34,
            timeout_seconds: 50,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowStaleQueueReorder,
        };

        let mut result = base_result();
        result.env_id = case.env_id.clone();
        result.task_set = TaskSet::WorkflowReorder;
        result.mode = ComputerUseMode::Agent;
        result.kernel_behavior.executed_tools = vec!["browser__navigate".to_string()];
        result.failure_class = Some("task_incomplete".to_string());

        let judged = judge_case(&case, result);
        assert_eq!(judged.primary_gap_class, Some(GapClass::PlannerGap));
        assert!(judged
            .secondary_gap_tags
            .iter()
            .any(|tag| tag == "stale_observation"));
        assert!(judged
            .secondary_gap_tags
            .iter()
            .any(|tag| tag == "queue_reorder"));
        assert!(judged
            .secondary_gap_tags
            .iter()
            .any(|tag| tag == "negative_verification"));
    }
}
