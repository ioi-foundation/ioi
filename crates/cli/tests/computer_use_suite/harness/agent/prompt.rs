use crate::computer_use_suite::types::{
    BridgeInteractiveElement, BridgeState, ComputerUseCase, ToolStepRecord,
};

fn compact_text(value: &str, limit: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.len() <= limit {
        compact
    } else {
        format!("{}...", &compact[..limit.saturating_sub(3)])
    }
}

fn summarize_element(element: &BridgeInteractiveElement) -> String {
    let selector = element.selector.clone().unwrap_or_default();
    let id = element.id.clone().unwrap_or_default();
    let mut bits = vec![format!("tag={}", element.tag)];
    if !id.is_empty() {
        bits.push(format!("id={id}"));
    }
    if !selector.is_empty() {
        bits.push(format!("selector={selector}"));
    }
    if !element.text.trim().is_empty() {
        bits.push(format!("text={}", compact_text(&element.text, 80)));
    }
    if let Some(value) = &element.value {
        if !value.trim().is_empty() {
            bits.push(format!("value={}", compact_text(value, 80)));
        }
    }
    if let Some(input_type) = &element.input_type {
        bits.push(format!("input_type={input_type}"));
    }
    if let Some(checked) = element.checked {
        bits.push(format!("checked={checked}"));
    }
    if !element.selected_labels.is_empty() {
        bits.push(format!(
            "selected_labels={}",
            element.selected_labels.join("|")
        ));
    }
    if let (Some(x), Some(y)) = (element.center_x, element.center_y) {
        bits.push(format!("center=({x},{y})"));
    }
    bits.push(format!("visible={}", element.visible));
    bits.push(format!("disabled={}", element.disabled));
    bits.join(" ")
}

fn summarize_history_step(step: &ToolStepRecord) -> String {
    let mut line = format!(
        "{}. {} {} success={} reward={} terminated={}",
        step.step_index,
        step.tool_name,
        step.arguments,
        step.success,
        step.bridge_reward,
        step.bridge_terminated
    );
    if let Some(error) = &step.error {
        line.push_str(&format!(" error={}", compact_text(error, 160)));
    }
    if let Some(history_entry) = &step.history_entry {
        let output_limit = if step.tool_name == "browser__inspect" {
            640
        } else {
            160
        };
        let compact = compact_text(history_entry, output_limit);
        if !compact.is_empty() {
            line.push_str(&format!(" output={compact}"));
        }
    }
    line
}

pub(super) fn build_system_prompt() -> String {
    [
        "You are the MiniWoB benchmark agent harness.",
        "Choose exactly one browser tool call each turn.",
        "Use only selectors, labels, ids, coordinates, and visible facts present in the current observation or recent tool history.",
        "Never invent a selector or semantic id that is not explicitly present in the current observation or tool history.",
        "Do not restart, relaunch, or navigate away from the assigned task page.",
        "Prefer browser__type with selector for text entry.",
        "If the goal specifies a target date and a date input is visible, prefer typing the exact date into the visible date field before exploring calendar navigation.",
        "Prefer browser__select_option with selector and exact label/value for native select controls.",
        "Prefer browser__click for literal CSS selectors already shown as selector=... in the observation.",
        "When browser__inspect returns XML node ids like btn_*, tab_*, or grp_*, use browser__click with id. Those ids are not CSS selectors, so do not prepend '#'.",
        "For checkbox tasks, click only the checkbox selectors explicitly listed in the observation, and do not extrapolate unseen numeric ids such as #ch12 if the observation only shows up to #ch11.",
        "If the exact target control is not currently listed, refresh observation instead of guessing.",
        "Use browser__wait or browser__inspect to verify unclear state changes instead of blindly repeating the same failing action.",
        "Do not use web retrieval or filesystem/system tools.",
    ]
    .join("\n")
}

pub(super) fn build_user_prompt(
    case: &ComputerUseCase,
    state: &BridgeState,
    tool_history: &[ToolStepRecord],
) -> String {
    let mut lines = vec![
        format!(
            "Goal: {}",
            state
                .info
                .query_text
                .clone()
                .unwrap_or_else(|| case.id.clone())
        ),
        format!(
            "Progress: reward={} raw_reward={:?} terminated={} truncated={} episode_step={}",
            state.reward,
            state.info.raw_reward,
            state.terminated,
            state.truncated,
            state.episode_step
        ),
        format!(
            "Focus: focused_tag={:?} focused_id={:?} task_ready={:?}",
            state.info.focused_tag, state.info.focused_id, state.info.task_ready
        ),
    ];

    if let Some(page_url) = &state.info.page_url {
        lines.push(format!("Page URL: {page_url}"));
    }
    if let Some(visible_text) = &state.info.visible_text_excerpt {
        lines.push(format!("Visible text: {}", compact_text(visible_text, 240)));
    }
    if let Some(last_event) = &state.info.last_event {
        lines.push(format!(
            "Last bridge event: kind={:?} selector={:?} id={:?}",
            last_event.kind, last_event.target_selector, last_event.target_id
        ));
    }

    lines.push("Interactive elements:".to_string());
    if state.info.interactive_elements.is_empty() {
        lines.push("- none".to_string());
    } else {
        for element in state.info.interactive_elements.iter().take(40) {
            lines.push(format!("- {}", summarize_element(element)));
        }
    }

    lines.push("Recent tool history:".to_string());
    if tool_history.is_empty() {
        lines.push("- none".to_string());
    } else {
        for step in tool_history.iter().rev().take(6).rev() {
            lines.push(format!("- {}", summarize_history_step(step)));
        }
    }

    lines.push("Return exactly one browser tool call.".to_string());
    lines.join("\n")
}
