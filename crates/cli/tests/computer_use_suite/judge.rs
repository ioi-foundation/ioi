use super::types::{
    AllowedToolProfile, ComputerUseCase, ComputerUseCaseResult, ComputerUseMode,
    KernelBehaviorObservation, ValidationSummary,
};

fn allowed_tools(
    mode: ComputerUseMode,
    profile: AllowedToolProfile,
) -> &'static [&'static str] {
    match (mode, profile) {
        (ComputerUseMode::Oracle, _) => &[],
        (_, AllowedToolProfile::BrowserCore) => &[
            "browser__navigate",
            "browser__snapshot",
            "browser__click",
            "browser__click_element",
            "browser__synthetic_click",
            "browser__type",
            "browser__key",
            "browser__wait",
            "browser__scroll",
            "browser__screenshot",
            "agent__complete",
            "chat__reply",
        ],
        (_, AllowedToolProfile::BrowserCoreWithSelect) => &[
            "browser__navigate",
            "browser__snapshot",
            "browser__click",
            "browser__click_element",
            "browser__synthetic_click",
            "browser__type",
            "browser__key",
            "browser__wait",
            "browser__scroll",
            "browser__screenshot",
            "browser__dropdown_options",
            "browser__select_dropdown",
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
    let effective_reward = result
        .bridge_state
        .info
        .raw_reward
        .unwrap_or(result.final_reward);
    let reward_floor_met = effective_reward >= case.expected_reward_floor;
    let task_success = reward_floor_met && result.terminated == case.expected_pass;

    let allowed = allowed_tools(result.mode, case.allowed_tool_profile);
    let disallowed_tools = result
        .kernel_behavior
        .executed_tools
        .iter()
        .filter(|tool_name| !allowed.is_empty() && !allowed.contains(&tool_name.as_str()))
        .cloned()
        .collect::<Vec<_>>();

    let kernel_success = if matches!(result.mode, ComputerUseMode::Oracle) {
        disallowed_tools.is_empty()
    } else {
        disallowed_tools.is_empty() && !result.kernel_behavior.executed_tools.is_empty()
    };

    result.kernel_behavior = KernelBehaviorObservation {
        disallowed_tools,
        ..result.kernel_behavior
    };
    result.validation = ValidationSummary {
        task_success,
        kernel_success,
        reward_floor_met,
        terminated: result.terminated,
        notes: (effective_reward != result.final_reward)
            .then(|| {
                vec![format!(
                    "judge used raw_reward={:.3} instead of decayed final_reward={:.3}",
                    effective_reward, result.final_reward
                )]
            })
            .unwrap_or_default(),
    };
    result.overall_pass = task_success && kernel_success;
    if !result.validation.task_success && result.failure_class.is_none() {
        result.failure_class = Some("task_incomplete".to_string());
    }
    if !result.validation.kernel_success && result.failure_class.is_none() {
        result.failure_class = Some("kernel_contract_violation".to_string());
    }
    result
}
