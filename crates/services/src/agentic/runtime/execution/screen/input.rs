use super::super::{ToolExecutionResult, ToolExecutor};
use ioi_api::vm::drivers::gui::{AtomicInput, InputEvent, MouseButton};

/// Build an atomic click sequence using the current cursor position.
pub fn build_cursor_click_sequence(button: MouseButton) -> Vec<AtomicInput> {
    vec![
        AtomicInput::MouseDown { button },
        AtomicInput::Wait { millis: 50 },
        AtomicInput::MouseUp { button },
    ]
}

/// Build a drag sequence from current cursor position to an absolute coordinate.
pub fn build_cursor_drag_sequence(to: [u32; 2]) -> Vec<AtomicInput> {
    vec![
        AtomicInput::MouseDown {
            button: MouseButton::Left,
        },
        AtomicInput::Wait { millis: 120 },
        AtomicInput::MouseMove { x: to[0], y: to[1] },
        AtomicInput::Wait { millis: 120 },
        AtomicInput::MouseUp {
            button: MouseButton::Left,
        },
    ]
}

fn map_char_to_atomic_key(ch: char) -> Option<String> {
    match ch {
        '\n' | '\r' => Some("enter".to_string()),
        '\t' => Some("tab".to_string()),
        _ if ch.is_control() => None,
        _ => Some(ch.to_string()),
    }
}

fn build_atomic_type_sequence(text: &str) -> Option<Vec<AtomicInput>> {
    let mut steps = Vec::with_capacity(text.chars().count());
    for ch in text.chars() {
        let key = map_char_to_atomic_key(ch)?;
        steps.push(AtomicInput::KeyPress { key });
    }
    Some(steps)
}

pub(super) async fn exec_input(exec: &ToolExecutor, event: InputEvent) -> ToolExecutionResult {
    match exec.gui.inject_input(event.clone()).await {
        Ok(_) => ToolExecutionResult::success(format!("Input executed: {:?}", event)),
        Err(primary_error) => match event {
            InputEvent::Type { text } => {
                let Some(steps) = build_atomic_type_sequence(&text) else {
                    return ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=UnexpectedState Input injection failed: {}. Atomic typing fallback cannot encode one or more control characters.",
                        primary_error
                    ));
                };

                let fallback_event = InputEvent::AtomicSequence(steps);
                match exec.gui.inject_input(fallback_event).await {
                    Ok(_) => ToolExecutionResult::success(format!(
                        "Input executed: Type {{ text: {:?} }} (atomic fallback)",
                        text
                    )),
                    Err(fallback_error) => ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=ToolUnavailable Input injection failed: {}. Atomic typing fallback failed: {}",
                        primary_error, fallback_error
                    )),
                }
            }
            _ => ToolExecutionResult::failure(format!("Input injection failed: {}", primary_error)),
        },
    }
}

pub(super) fn parse_mouse_button(button: Option<&str>) -> MouseButton {
    match button
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("right") => MouseButton::Right,
        Some("middle") => MouseButton::Middle,
        _ => MouseButton::Left,
    }
}
