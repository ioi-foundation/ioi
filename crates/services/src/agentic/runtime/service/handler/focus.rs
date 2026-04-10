use ioi_api::vm::drivers::os::WindowInfo;
use ioi_types::app::agentic::{AgentTool, ComputerAction};

pub(super) fn is_focus_sensitive_tool(tool: &AgentTool) -> bool {
    match tool {
        AgentTool::GuiClick { .. }
        | AgentTool::GuiScroll { .. }
        | AgentTool::GuiClickElement { .. } => true,
        AgentTool::Computer(action) => matches!(
            action,
            ComputerAction::LeftClick { .. }
                | ComputerAction::LeftClickId { .. }
                | ComputerAction::LeftClickElement { .. }
                | ComputerAction::RightClick { .. }
                | ComputerAction::DoubleClick { .. }
                | ComputerAction::RightClickId { .. }
                | ComputerAction::RightClickElement { .. }
                | ComputerAction::LeftClickDrag { .. }
                | ComputerAction::DragDrop { .. }
                | ComputerAction::DragDropId { .. }
                | ComputerAction::DragDropElement { .. }
                | ComputerAction::Scroll { .. }
        ),
        _ => false,
    }
}

pub(super) fn window_matches_hint(window: Option<&WindowInfo>, hint: &str) -> bool {
    let normalized = hint.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return true;
    }

    if let Some(win) = window {
        let title = win.title.to_ascii_lowercase();
        let app = win.app_name.to_ascii_lowercase();
        title.contains(&normalized) || app.contains(&normalized)
    } else {
        false
    }
}

pub(super) fn is_missing_focus_dependency_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("error_class=missingdependency")
        || (lower.contains("wmctrl")
            && (lower.contains("no such file")
                || lower.contains("not found")
                || lower.contains("missing dependency")))
}
