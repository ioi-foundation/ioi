use ioi_types::app::agentic::{AgentTool, ComputerAction};
use ioi_types::app::ActionTarget;

#[test]
fn scroll_tool_types_and_target_mapping() {
    let tool = AgentTool::GuiScroll {
        delta_x: 0,
        delta_y: 10,
    };
    assert_eq!(tool.target(), ActionTarget::GuiScroll);

    let computer_scroll = AgentTool::Computer(ComputerAction::Scroll {
        coordinate: Some([100, 100]),
        delta: [0, -5],
    });
    assert_eq!(computer_scroll.target(), ActionTarget::GuiScroll);
}
