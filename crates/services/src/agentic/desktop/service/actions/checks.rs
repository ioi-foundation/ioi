// Path: crates/services/src/agentic/desktop/service/actions/checks.rs

use crate::agentic::desktop::types::AgentState;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_types::app::agentic::{AgentTool, ComputerAction};

/// Truncate strings safely for logging/history.
pub fn safe_truncate(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let mut result: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        result.push_str("...");
    }
    result
}

#[allow(dead_code)]
pub fn is_atomic_os_action(goal: &str) -> bool {
    let g = goal.trim().to_lowercase();
    if g.len() > 60 {
        return false;
    }
    let verbs = [
        "open", "launch", "start", "run", "click", "type", "press", "close",
    ];
    let objects = [
        "calculator",
        "terminal",
        "settings",
        "browser",
        "app",
        "application",
        "code",
        "vscode",
    ];
    let has_verb = verbs.iter().any(|v| g.starts_with(v));
    let has_object = objects.iter().any(|o| g.contains(o));
    has_verb && has_object
}

#[allow(dead_code)]
pub fn is_question(text: &str) -> bool {
    let t = text.trim().to_lowercase();
    t.ends_with('?') || t.starts_with("can you")
}

/// Helper to determine if an action relies on precise screen coordinates.
pub fn requires_visual_integrity(tool: &AgentTool) -> bool {
    match tool {
        AgentTool::Computer(action) => matches!(
            action,
            ComputerAction::LeftClickId { .. }
                | ComputerAction::LeftClickElement { .. }
                | ComputerAction::RightClickId { .. }
                | ComputerAction::RightClickElement { .. }
                | ComputerAction::LeftClick {
                    coordinate: Some(_),
                    ..
                }
                | ComputerAction::RightClick {
                    coordinate: Some(_),
                    ..
                }
                | ComputerAction::LeftClickDrag { .. }
                | ComputerAction::DragDrop { .. }
                | ComputerAction::MouseMove { .. }
                | ComputerAction::Scroll {
                    coordinate: Some(_),
                    ..
                }
        ),
        AgentTool::GuiClick { .. } => true,
        AgentTool::GuiScroll { .. } => true,
        AgentTool::GuiClickElement { .. } => true,
        AgentTool::BrowserSyntheticClick { .. } => true,
        AgentTool::BrowserClick { .. } => true,
        AgentTool::BrowserClickElement { .. } => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::requires_visual_integrity;
    use ioi_types::app::agentic::{AgentTool, ComputerAction};

    #[test]
    fn right_click_variants_are_visual_integrity_sensitive() {
        assert!(requires_visual_integrity(&AgentTool::Computer(
            ComputerAction::RightClick {
                coordinate: Some([640, 320]),
            },
        )));
        assert!(requires_visual_integrity(&AgentTool::Computer(
            ComputerAction::RightClickId { id: 7 },
        )));
        assert!(requires_visual_integrity(&AgentTool::Computer(
            ComputerAction::RightClickElement {
                id: "context_menu_anchor".to_string(),
            },
        )));
    }

    #[test]
    fn cursor_relative_right_click_does_not_require_visual_guard() {
        assert!(!requires_visual_integrity(&AgentTool::Computer(
            ComputerAction::RightClick { coordinate: None },
        )));
    }
}

/// Helper to check focus invariant with "Launch Exception"
#[allow(dead_code)]
pub async fn enforce_focus_precondition(
    os: &dyn OsDriver,
    agent_state: &AgentState,
) -> Result<(), String> {
    // 1. If no target is set, we assume Global/Desktop mode -> Allow.
    let target = match &agent_state.target {
        Some(t) => t,
        None => return Ok(()),
    };

    // 2. Get Current Foreground Window from OS Driver
    let fg_info = os
        .get_active_window_info()
        .await
        .map_err(|e| format!("OS Driver Error: {}", e))?
        .ok_or("No active window found. Cannot verify focus.")?;

    let fg_title = fg_info.title.to_lowercase();
    let fg_app = fg_info.app_name.to_lowercase();
    let hint = target.app_hint.as_deref().unwrap_or("").to_lowercase();

    // 3. Match Logic
    let is_target_focused =
        !hint.is_empty() && (fg_title.contains(&hint) || fg_app.contains(&hint));

    // [OPEN-INTERPRETER STRATEGY]
    let goal_lower = agent_state.goal.to_lowercase();
    let is_launch_intent = goal_lower.starts_with("open")
        || goal_lower.starts_with("launch")
        || goal_lower.starts_with("start");

    let is_system_surface = fg_app.contains("finder")
        || fg_app.contains("explorer")
        || fg_app.contains("dock")
        || fg_app.contains("shell")
        || fg_app.contains("launcher")
        || fg_app.contains("autopilot")
        || fg_title.contains("desktop");

    if is_target_focused || (is_launch_intent && is_system_surface) {
        Ok(())
    } else {
        Err(format!(
            "FOCUS_REQUIRED: Foreground is '{}' (App: '{}') but goal requires interacting with '{}'. \
             To interact with '{}', you must either:\n\
             1. Call `os__focus_window(title='{}')` if it is running.\n\
             2. Call `os__launch_app(app_name='{}')` if it is not running.\n\
             3. If clicking the Dock/Taskbar, ensure that is the active window first.",
            fg_info.title, fg_info.app_name, hint, hint, hint, hint
        ))
    }
}
