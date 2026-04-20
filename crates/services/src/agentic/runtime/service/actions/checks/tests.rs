use super::requires_visual_integrity;
use ioi_types::app::agentic::{AgentTool, ScreenAction};

#[test]
fn right_click_variants_are_visual_integrity_sensitive() {
    assert!(requires_visual_integrity(&AgentTool::Screen(
        ScreenAction::RightClick {
            coordinate: Some([640, 320]),
        },
    )));
    assert!(requires_visual_integrity(&AgentTool::Screen(
        ScreenAction::RightClickId { id: 7 },
    )));
    assert!(requires_visual_integrity(&AgentTool::Screen(
        ScreenAction::RightClickElement {
            id: "context_menu_anchor".to_string(),
        },
    )));
}

#[test]
fn cursor_relative_right_click_does_not_require_visual_guard() {
    assert!(!requires_visual_integrity(&AgentTool::Screen(
        ScreenAction::RightClick { coordinate: None },
    )));
}
