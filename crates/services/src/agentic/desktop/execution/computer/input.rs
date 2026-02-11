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

pub(super) async fn exec_input(exec: &ToolExecutor, event: InputEvent) -> ToolExecutionResult {
    match exec.gui.inject_input(event.clone()).await {
        Ok(_) => ToolExecutionResult::success(format!("Input executed: {:?}", event)),
        Err(e) => ToolExecutionResult::failure(format!("Input injection failed: {}", e)),
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
