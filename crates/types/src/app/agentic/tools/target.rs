use crate::app::ActionTarget;

use super::{AgentTool, ScreenAction};

pub(super) fn target_for_tool(tool: &AgentTool) -> ActionTarget {
    match tool {
        AgentTool::FsWrite { .. }
        | AgentTool::FsPatch { .. }
        | AgentTool::FsMultiPatch { .. }
        | AgentTool::FsDelete { .. } => ActionTarget::FsWrite,
        AgentTool::FsRead { .. }
        | AgentTool::FsView { .. }
        | AgentTool::FsList { .. }
        | AgentTool::FsSearch { .. }
        | AgentTool::FsStat { .. } => ActionTarget::FsRead,
        AgentTool::FsCreateDirectory { .. } => ActionTarget::Custom("file__create_dir".into()),
        AgentTool::FsCreateZip { .. } => ActionTarget::Custom("file__zip".into()),
        AgentTool::FsMove { .. } => ActionTarget::Custom("file__move".into()),
        AgentTool::FsCopy { .. } => ActionTarget::Custom("file__copy".into()),

        AgentTool::SysExec { .. }
        | AgentTool::SysExecSession { .. }
        | AgentTool::SysExecStatus { .. }
        | AgentTool::SysExecInput { .. }
        | AgentTool::SysExecTerminate { .. }
        | AgentTool::SysExecSessionReset {}
        | AgentTool::SysChangeDir { .. } => ActionTarget::SysExec,
        AgentTool::SysInstallPackage { .. } => ActionTarget::SysInstallPackage,

        AgentTool::WebSearch { .. } | AgentTool::WebRead { .. } => ActionTarget::WebRetrieve,
        AgentTool::MediaExtractTranscript { .. } => ActionTarget::MediaExtractTranscript,
        AgentTool::MediaExtractMultimodalEvidence { .. } => {
            ActionTarget::MediaExtractMultimodalEvidence
        }
        AgentTool::NetFetch { .. } => ActionTarget::NetFetch,

        AgentTool::BrowserNavigate { .. }
        | AgentTool::BrowserClick { .. }
        | AgentTool::BrowserHover { .. }
        | AgentTool::BrowserMoveMouse { .. }
        | AgentTool::BrowserMouseDown { .. }
        | AgentTool::BrowserMouseUp { .. }
        | AgentTool::BrowserSyntheticClick { .. }
        | AgentTool::BrowserScroll { .. }
        | AgentTool::BrowserType { .. }
        | AgentTool::BrowserSelectText { .. }
        | AgentTool::BrowserKey { .. }
        | AgentTool::BrowserCopySelection {}
        | AgentTool::BrowserPasteClipboard { .. }
        | AgentTool::BrowserFindText { .. }
        | AgentTool::BrowserWait { .. }
        | AgentTool::BrowserUploadFile { .. }
        | AgentTool::BrowserDropdownOptions { .. }
        | AgentTool::BrowserSelectDropdown { .. }
        | AgentTool::BrowserGoBack { .. }
        | AgentTool::BrowserTabList {}
        | AgentTool::BrowserTabSwitch { .. }
        | AgentTool::BrowserTabClose { .. } => ActionTarget::BrowserInteract,

        AgentTool::BrowserScreenshot { .. } | AgentTool::BrowserCanvasSummary { .. } => {
            ActionTarget::BrowserInspect
        }

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
        AgentTool::AutomationCreateMonitor { .. } => ActionTarget::Custom("monitor__create".into()),

        AgentTool::Screen(action) => match action {
            ScreenAction::LeftClickId { .. }
            | ScreenAction::LeftClickElement { .. }
            | ScreenAction::RightClickId { .. }
            | ScreenAction::RightClickElement { .. } => ActionTarget::GuiClick,

            ScreenAction::Type { .. } | ScreenAction::Key { .. } | ScreenAction::Hotkey { .. } => {
                ActionTarget::GuiType
            }
            ScreenAction::MouseMove { .. } => ActionTarget::GuiMouseMove,
            ScreenAction::LeftClick { .. }
            | ScreenAction::RightClick { .. }
            | ScreenAction::DoubleClick { .. } => ActionTarget::GuiClick,
            ScreenAction::LeftClickDrag { .. }
            | ScreenAction::DragDrop { .. }
            | ScreenAction::DragDropId { .. }
            | ScreenAction::DragDropElement { .. } => ActionTarget::GuiClick,
            ScreenAction::Screenshot => ActionTarget::GuiScreenshot,
            ScreenAction::CursorPosition => ActionTarget::Custom("screen::cursor".into()),
            ScreenAction::Scroll { .. } => ActionTarget::GuiScroll,
        },

        AgentTool::CommerceCheckout { .. } => ActionTarget::CommerceCheckout,

        AgentTool::MemorySearch { .. } => ActionTarget::Custom("memory::search".into()),
        AgentTool::MemoryInspect { .. } => ActionTarget::Custom("memory::inspect".into()),
        AgentTool::MemoryReplaceCore { .. } => ActionTarget::Custom("memory::replace_core".into()),
        AgentTool::MemoryAppendCore { .. } => ActionTarget::Custom("memory::append_core".into()),
        AgentTool::MemoryClearCore { .. } => ActionTarget::Custom("memory::clear_core".into()),

        AgentTool::AgentDelegate { .. } => ActionTarget::Custom("agent__delegate".into()),
        AgentTool::AgentAwait { .. } => ActionTarget::Custom("agent__await".into()),
        AgentTool::AgentPause { .. } => ActionTarget::Custom("agent__pause".into()),
        AgentTool::AgentComplete { .. } => ActionTarget::Custom("agent__complete".into()),
        AgentTool::SystemFail { .. } => ActionTarget::Custom("agent__escalate".into()),

        AgentTool::Dynamic(val) => {
            if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                match name {
                    "screen__click" => ActionTarget::GuiClick,
                    "screen__inspect" => ActionTarget::GuiInspect,
                    "web__search" | "web__read" => ActionTarget::WebRetrieve,
                    "model__responses" => ActionTarget::ModelRespond,
                    "model__embeddings" => ActionTarget::ModelEmbed,
                    "model__rerank" => ActionTarget::ModelRerank,
                    "media__extract_transcript" => ActionTarget::MediaExtractTranscript,
                    "media__extract_evidence" => ActionTarget::MediaExtractMultimodalEvidence,
                    "browser__inspect" => ActionTarget::BrowserInspect,
                    "browser__subagent" => ActionTarget::BrowserInteract,
                    "browser__navigate"
                    | "browser__click"
                    | "browser__hover"
                    | "browser__move_pointer"
                    | "browser__pointer_down"
                    | "browser__pointer_up"
                    | "browser__click_at"
                    | "browser__scroll"
                    | "browser__type"
                    | "browser__select"
                    | "browser__press_key"
                    | "browser__copy"
                    | "browser__paste"
                    | "browser__find_text"
                    | "browser__wait"
                    | "browser__upload"
                    | "browser__list_options"
                    | "browser__select_option"
                    | "browser__back"
                    | "browser__list_tabs"
                    | "browser__switch_tab"
                    | "browser__close_tab" => ActionTarget::BrowserInteract,
                    "browser__screenshot" | "browser__inspect_canvas" => {
                        ActionTarget::BrowserInspect
                    }
                    "shell__run" | "shell__start" | "shell__status" | "shell__input"
                    | "shell__terminate" | "shell__reset" | "shell__cd" => ActionTarget::SysExec,
                    "app__launch" => ActionTarget::Custom("os::launch_app".to_string()),
                    "math__eval" => ActionTarget::Custom("math::eval".to_string()),
                    "monitor__create" => ActionTarget::Custom("monitor__create".to_string()),
                    "package__install" => ActionTarget::SysInstallPackage,
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
