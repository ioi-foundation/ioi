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

        AgentTool::WebSearch { .. }
        | AgentTool::WebRead { .. }
        | AgentTool::MediaExtractTranscript { .. }
        | AgentTool::MediaExtractMultimodalEvidence { .. } => ActionTarget::WebRetrieve,
        AgentTool::NetFetch { .. } => ActionTarget::NetFetch,

        AgentTool::BrowserNavigate { .. }
        | AgentTool::BrowserClick { .. }
        | AgentTool::BrowserClickElement { .. }
        | AgentTool::BrowserSyntheticClick { .. }
        | AgentTool::BrowserScroll { .. }
        | AgentTool::BrowserType { .. }
        | AgentTool::BrowserKey { .. }
        | AgentTool::BrowserFindText { .. }
        | AgentTool::BrowserScreenshot { .. }
        | AgentTool::BrowserWait { .. }
        | AgentTool::BrowserUploadFile { .. }
        | AgentTool::BrowserDropdownOptions { .. }
        | AgentTool::BrowserSelectDropdown { .. }
        | AgentTool::BrowserGoBack { .. }
        | AgentTool::BrowserTabList {}
        | AgentTool::BrowserTabSwitch { .. }
        | AgentTool::BrowserTabClose { .. } => ActionTarget::BrowserInteract,

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
        AgentTool::AutomationCreateMonitor { .. } => {
            ActionTarget::Custom("automation__create_monitor".into())
        }

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
                    "web__search"
                    | "web__read"
                    | "media__extract_transcript"
                    | "media__extract_multimodal_evidence" => ActionTarget::WebRetrieve,
                    "browser__snapshot" => ActionTarget::BrowserInspect,
                    "browser__navigate"
                    | "browser__click"
                    | "browser__click_element"
                    | "browser__synthetic_click"
                    | "browser__scroll"
                    | "browser__type"
                    | "browser__key"
                    | "browser__find_text"
                    | "browser__screenshot"
                    | "browser__wait"
                    | "browser__upload_file"
                    | "browser__dropdown_options"
                    | "browser__select_dropdown"
                    | "browser__go_back"
                    | "browser__tab_list"
                    | "browser__tab_switch"
                    | "browser__tab_close" => ActionTarget::BrowserInteract,
                    "sys__exec"
                    | "sys__exec_session"
                    | "sys__exec_session_reset"
                    | "sys__change_directory" => ActionTarget::SysExec,
                    "os__launch_app" => ActionTarget::Custom("os::launch_app".to_string()),
                    "math__eval" => ActionTarget::Custom("math::eval".to_string()),
                    "automation__create_monitor" => {
                        ActionTarget::Custom("automation__create_monitor".to_string())
                    }
                    "sys__install_package" => ActionTarget::SysInstallPackage,
                    "connector__google__bigquery_execute_query" => {
                        let query = val
                            .get("arguments")
                            .and_then(|arguments| arguments.get("query"))
                            .and_then(|query| query.as_str())
                            .unwrap_or_default()
                            .trim_start()
                            .trim_start_matches(|ch: char| ch == '(')
                            .trim_start()
                            .to_ascii_lowercase();
                        let label = if query.starts_with("select")
                            || query.starts_with("with")
                            || query.starts_with("show")
                            || query.starts_with("describe")
                            || query.starts_with("explain")
                        {
                            "connector__google__bigquery_execute_query__read"
                        } else {
                            "connector__google__bigquery_execute_query__write"
                        };
                        ActionTarget::Custom(label.to_string())
                    }
                    name if name.starts_with("connector__google__") => {
                        ActionTarget::Custom(name.to_string())
                    }
                    _ => ActionTarget::Custom(name.to_string()),
                }
            } else {
                ActionTarget::Custom("unknown".into())
            }
        }
    }
}
