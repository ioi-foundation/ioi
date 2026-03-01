use crate::app::ActionTarget;

use super::{AgentTool, ComputerAction};

pub(super) fn target_for_tool(tool: &AgentTool) -> ActionTarget {
    match tool {
        AgentTool::FsWrite { .. } | AgentTool::FsPatch { .. } | AgentTool::FsDelete { .. } => {
            ActionTarget::FsWrite
        }
        AgentTool::FsRead { .. }
        | AgentTool::FsList { .. }
        | AgentTool::FsSearch { .. }
        | AgentTool::FsStat { .. } => ActionTarget::FsRead,
        AgentTool::FsCreateDirectory { .. } => {
            ActionTarget::Custom("filesystem__create_directory".into())
        }
        AgentTool::FsCreateZip { .. } => ActionTarget::Custom("filesystem__create_zip".into()),
        AgentTool::FsMove { .. } => ActionTarget::Custom("filesystem__move_path".into()),
        AgentTool::FsCopy { .. } => ActionTarget::Custom("filesystem__copy_path".into()),

        AgentTool::SysExec { .. }
        | AgentTool::SysExecSession { .. }
        | AgentTool::SysExecSessionReset {}
        | AgentTool::SysChangeDir { .. } => ActionTarget::SysExec,
        AgentTool::SysInstallPackage { .. } => ActionTarget::SysInstallPackage,

        AgentTool::WebSearch { .. } | AgentTool::WebRead { .. } => ActionTarget::WebRetrieve,
        AgentTool::NetFetch { .. } => ActionTarget::NetFetch,

        AgentTool::BrowserNavigate { .. }
        | AgentTool::BrowserClick { .. }
        | AgentTool::BrowserClickElement { .. }
        | AgentTool::BrowserSyntheticClick { .. }
        | AgentTool::BrowserScroll { .. }
        | AgentTool::BrowserType { .. }
        | AgentTool::BrowserKey { .. } => ActionTarget::BrowserInteract,

        AgentTool::BrowserSnapshot { .. } => ActionTarget::BrowserInspect,

        AgentTool::GuiClick { .. } => ActionTarget::GuiClick,
        AgentTool::GuiType { .. } => ActionTarget::GuiType,
        AgentTool::GuiScroll { .. } => ActionTarget::GuiScroll,
        AgentTool::GuiSnapshot { .. } => ActionTarget::GuiInspect,
        AgentTool::GuiClickElement { .. } => ActionTarget::GuiClick,

        AgentTool::UiFind { .. } => ActionTarget::Custom("ui::find".into()),
        AgentTool::OsFocusWindow { .. } => ActionTarget::WindowFocus,
        AgentTool::OsCopy { .. } => ActionTarget::ClipboardWrite,
        AgentTool::OsPaste { .. } => ActionTarget::ClipboardRead,
        AgentTool::OsLaunchApp { .. } => ActionTarget::Custom("os::launch_app".into()),
        AgentTool::MathEval { .. } => ActionTarget::Custom("math::eval".into()),

        AgentTool::ChatReply { .. } => ActionTarget::Custom("chat__reply".into()),

        AgentTool::Computer(action) => match action {
            ComputerAction::LeftClickId { .. }
            | ComputerAction::LeftClickElement { .. }
            | ComputerAction::RightClickId { .. }
            | ComputerAction::RightClickElement { .. } => ActionTarget::GuiClick,

            ComputerAction::Type { .. }
            | ComputerAction::Key { .. }
            | ComputerAction::Hotkey { .. } => ActionTarget::GuiType,
            ComputerAction::MouseMove { .. } => ActionTarget::GuiMouseMove,
            ComputerAction::LeftClick { .. }
            | ComputerAction::RightClick { .. }
            | ComputerAction::DoubleClick { .. } => ActionTarget::GuiClick,
            ComputerAction::LeftClickDrag { .. }
            | ComputerAction::DragDrop { .. }
            | ComputerAction::DragDropId { .. }
            | ComputerAction::DragDropElement { .. } => ActionTarget::GuiClick,
            ComputerAction::Screenshot => ActionTarget::GuiScreenshot,
            ComputerAction::CursorPosition => ActionTarget::Custom("computer::cursor".into()),
            ComputerAction::Scroll { .. } => ActionTarget::GuiScroll,
        },

        AgentTool::CommerceCheckout { .. } => ActionTarget::CommerceCheckout,

        AgentTool::MemorySearch { .. } => ActionTarget::Custom("memory::search".into()),
        AgentTool::MemoryInspect { .. } => ActionTarget::Custom("memory::inspect".into()),

        AgentTool::AgentDelegate { .. } => ActionTarget::Custom("agent__delegate".into()),
        AgentTool::AgentAwait { .. } => ActionTarget::Custom("agent__await_result".into()),
        AgentTool::AgentPause { .. } => ActionTarget::Custom("agent__pause".into()),
        AgentTool::AgentComplete { .. } => ActionTarget::Custom("agent__complete".into()),
        AgentTool::SystemFail { .. } => ActionTarget::Custom("system__fail".into()),

        AgentTool::Dynamic(val) => {
            if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                match name {
                    "ui__click_component" | "gui__click_element" => ActionTarget::GuiClick,
                    "gui__snapshot" => ActionTarget::GuiInspect,
                    "web__search" | "web__read" => ActionTarget::WebRetrieve,
                    "browser__snapshot" => ActionTarget::BrowserInspect,
                    "browser__navigate"
                    | "browser__click"
                    | "browser__click_element"
                    | "browser__synthetic_click"
                    | "browser__scroll"
                    | "browser__type"
                    | "browser__key" => ActionTarget::BrowserInteract,
                    "sys__exec"
                    | "sys__exec_session"
                    | "sys__exec_session_reset"
                    | "sys__change_directory" => ActionTarget::SysExec,
                    "os__launch_app" => ActionTarget::Custom("os::launch_app".to_string()),
                    "math__eval" => ActionTarget::Custom("math::eval".to_string()),
                    "sys__install_package" => ActionTarget::SysInstallPackage,
                    _ => ActionTarget::Custom(name.to_string()),
                }
            } else {
                ActionTarget::Custom("unknown".into())
            }
        }
    }
}
