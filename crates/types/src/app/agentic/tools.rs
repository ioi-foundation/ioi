// Path: crates/types/src/app/agentic/tools.rs

use crate::app::ActionTarget;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// An item in a commerce transaction.
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct CommerceItem {
    /// Item ID.
    pub id: String,
    /// Quantity.
    pub quantity: u32,
}

/// Actions available via the Computer meta-tool.
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ComputerAction {
    /// Type text.
    #[serde(rename = "type")]
    Type {
        /// Text to type.
        text: String,
    },

    /// Press a key.
    #[serde(rename = "key")]
    Key {
        /// Key name.
        text: String,
    },

    /// Execute a keyboard shortcut (Chord).
    #[serde(rename = "hotkey")]
    Hotkey {
        /// Sequence of keys to press. Modifiers first.
        keys: Vec<String>,
    },

    /// Move mouse cursor.
    MouseMove {
        /// Coordinates [x, y].
        coordinate: [u32; 2],
    },

    /// Click left mouse button.
    #[serde(rename = "left_click")]
    LeftClick {
        /// Optional coordinates for stateless execution.
        #[serde(default)]
        coordinate: Option<[u32; 2]>,
    },

    /// Click right mouse button.
    #[serde(rename = "right_click")]
    RightClick {
        /// Optional coordinates for stateless execution.
        #[serde(default)]
        coordinate: Option<[u32; 2]>,
    },

    /// Double-click left mouse button.
    #[serde(rename = "double_click")]
    DoubleClick {
        /// Optional coordinates for stateless execution.
        #[serde(default)]
        coordinate: Option<[u32; 2]>,
    },

    /// Click a specific element by its Set-of-Marks numeric tag.
    /// Visual Mode Only.
    #[serde(rename = "left_click_id")]
    LeftClickId {
        /// The unique numeric tag from the visual overlay.
        id: u32,
    },

    /// Click a specific element by its semantic ID string.
    #[serde(rename = "left_click_element")]
    LeftClickElement {
        /// The element ID string.
        id: String,
    },

    /// Right-click a specific element by its Set-of-Marks numeric tag.
    /// Visual Mode Only.
    #[serde(rename = "right_click_id")]
    RightClickId {
        /// The unique numeric tag from the visual overlay.
        id: u32,
    },

    /// Right-click a specific element by its semantic ID string.
    #[serde(rename = "right_click_element")]
    RightClickElement {
        /// The element ID string.
        id: String,
    },

    /// Click and drag (Stateful/Relative).
    LeftClickDrag {
        /// Coordinates [x, y].
        coordinate: [u32; 2],
    },

    /// Explicit Drag and Drop (Stateless/Absolute).
    #[serde(rename = "drag_drop")]
    DragDrop {
        /// Start coordinates [x, y].
        from: [u32; 2],
        /// End coordinates [x, y].
        to: [u32; 2],
    },

    /// Drag and drop by Set-of-Marks numeric IDs.
    #[serde(rename = "drag_drop_id")]
    DragDropId {
        /// Start SoM ID.
        from_id: u32,
        /// End SoM ID.
        to_id: u32,
    },

    /// Drag and drop by semantic element IDs.
    #[serde(rename = "drag_drop_element")]
    DragDropElement {
        /// Start semantic element ID.
        from_id: String,
        /// End semantic element ID.
        to_id: String,
    },

    /// Take a screenshot.
    Screenshot,

    /// Get cursor position.
    CursorPosition,

    /// Scroll the mouse wheel.
    Scroll {
        /// Optional coordinates [x, y] to move mouse before scrolling.
        #[serde(default)]
        coordinate: Option<[u32; 2]>,
        /// Scroll delta [dx, dy]. Positive dy = down, positive dx = right.
        delta: [i32; 2],
    },
}

/// The single source of truth for all Agent Capabilities.
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(tag = "name", content = "arguments", rename_all = "snake_case")]
pub enum AgentTool {
    /// Meta-tool for computer control (Claude 3.5 Sonnet style)
    #[serde(rename = "computer")]
    Computer(ComputerAction),

    /// Writes content to a file.
    #[serde(rename = "filesystem__write_file")]
    FsWrite {
        /// Path to the file.
        path: String,
        /// Content to write.
        content: String,
        /// Optional 1-based line index for atomic line edits.
        /// If set, only that line is replaced instead of rewriting the full file.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        line_number: Option<u32>,
    },

    /// Patches a file by replacing a unique string block.
    #[serde(rename = "filesystem__patch")]
    FsPatch {
        /// Path to the file.
        path: String,
        /// Exact string block to find and replace. Must occur exactly once.
        search: String,
        /// Replacement string block.
        replace: String,
    },

    /// Reads content from a file.
    #[serde(rename = "filesystem__read_file")]
    FsRead {
        /// Path to the file.
        path: String,
    },

    /// Lists directory contents.
    #[serde(rename = "filesystem__list_directory")]
    FsList {
        /// Path to the directory.
        path: String,
    },

    /// Recursively searches files for lines matching a regex pattern.
    #[serde(rename = "filesystem__search")]
    FsSearch {
        /// Root path to search from.
        path: String,
        /// Rust regex pattern to match in file contents.
        regex: String,
        /// Optional glob-style filename filter (e.g. "*.rs").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        file_pattern: Option<String>,
    },

    /// Moves or renames a file/directory deterministically.
    #[serde(rename = "filesystem__move_path")]
    FsMove {
        /// Source path to move from.
        source_path: String,
        /// Destination path to move to.
        destination_path: String,
        /// When true, replace an existing destination.
        #[serde(default)]
        overwrite: bool,
    },

    /// Executes a system command.
    #[serde(rename = "sys__exec")]
    SysExec {
        /// Command to execute.
        command: String,
        /// Arguments for the command.
        #[serde(default)]
        args: Vec<String>,
        /// Whether to detach the process.
        #[serde(default)]
        detach: bool,
    },

    /// Installs a package using a deterministic package manager mapping.
    #[serde(rename = "sys__install_package")]
    SysInstallPackage {
        /// Package name or identifier.
        package: String,
        /// Optional package manager override.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manager: Option<String>,
    },

    /// Changes the persistent working directory for subsequent system commands.
    #[serde(rename = "sys__change_directory")]
    SysChangeDir {
        /// Target directory path (absolute or relative).
        path: String,
    },

    /// Navigates the browser to a URL.
    #[serde(rename = "browser__navigate")]
    BrowserNavigate {
        /// URL to navigate to.
        url: String,
    },

    /// Extracts content from the browser.
    #[serde(rename = "browser__extract")]
    BrowserExtract {},

    /// Clicks an element in the browser.
    #[serde(rename = "browser__click")]
    BrowserClick {
        /// CSS selector of element to click.
        selector: String,
    },

    /// Clicks an element in the browser by semantic ID from `browser__extract`.
    #[serde(rename = "browser__click_element")]
    BrowserClickElement {
        /// Stable semantic ID of element (e.g. "btn_submit").
        id: String,
    },

    /// Synthetic click for background execution.
    #[serde(rename = "browser__synthetic_click")]
    BrowserSyntheticClick {
        /// X coordinate relative to viewport.
        x: u32,
        /// Y coordinate relative to viewport.
        y: u32,
    },

    /// Scroll the browser viewport (headless-compatible).
    #[serde(rename = "browser__scroll")]
    BrowserScroll {
        /// Vertical scroll amount. Positive = down.
        #[serde(default)]
        delta_y: i32,
        /// Horizontal scroll amount. Positive = right.
        #[serde(default)]
        delta_x: i32,
    },

    /// Type text in the browser via CDP input events (headless-compatible).
    #[serde(rename = "browser__type")]
    BrowserType {
        /// Text to type.
        text: String,
        /// Optional CSS selector to focus before typing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
    },

    /// Press a keyboard key in the browser via CDP key events (headless-compatible).
    #[serde(rename = "browser__key")]
    BrowserKey {
        /// Key name (for example: "Enter", "Tab", "ArrowDown").
        key: String,
    },

    /// Legacy GUI click tool.
    #[serde(rename = "gui__click")]
    GuiClick {
        /// X coordinate.
        x: u32,
        /// Y coordinate.
        y: u32,
        /// Mouse button (left/right/middle).
        button: Option<String>,
    },

    /// Legacy GUI typing tool.
    #[serde(rename = "gui__type")]
    GuiType {
        /// Text to type.
        text: String,
    },

    /// Scroll the active window/element.
    #[serde(rename = "gui__scroll")]
    GuiScroll {
        /// Vertical scroll amount. Positive = down.
        #[serde(default)]
        delta_y: i32,
        /// Horizontal scroll amount. Positive = right.
        #[serde(default)]
        delta_x: i32,
    },

    /// Click a UI element by its stable ID. Global capability (works in background).
    #[serde(rename = "gui__click_element")]
    GuiClickElement {
        /// The stable ID of the element (e.g. "btn_submit").
        id: String,
    },

    /// [NEW] Find a UI element by visual or semantic description.
    #[serde(rename = "ui__find")]
    UiFind {
        /// Description to find (text, icon, color, shape, logo).
        query: String,
    },

    /// [NEW] Focus a specific window.
    #[serde(rename = "os__focus_window")]
    OsFocusWindow {
        /// Title of the window to focus.
        title: String,
    },

    /// [NEW] Copy text to clipboard.
    #[serde(rename = "os__copy")]
    OsCopy {
        /// Content to copy.
        content: String,
    },

    /// [NEW] Paste text from clipboard.
    #[serde(rename = "os__paste")]
    OsPaste {},

    /// [NEW] Launch an application.
    #[serde(rename = "os__launch_app")]
    OsLaunchApp {
        /// Name of the application to launch.
        app_name: String,
    },

    /// Sends a reply in the chat.
    #[serde(rename = "chat__reply")]
    ChatReply {
        /// Message content.
        message: String,
    },

    /// Meta Tool: Delegates a task to a sub-agent.
    #[serde(rename = "agent__delegate")]
    AgentDelegate {
        /// Goal for the sub-agent.
        goal: String,
        /// Budget allocated.
        budget: u64,
    },

    /// Meta Tool: Awaits result from a sub-agent.
    #[serde(rename = "agent__await_result")]
    AgentAwait {
        /// Session ID of the child agent.
        child_session_id_hex: String,
    },

    /// Meta Tool: Pauses execution.
    #[serde(rename = "agent__pause")]
    AgentPause {
        /// Reason for pausing.
        reason: String,
    },

    /// Meta Tool: Completes the task.
    #[serde(rename = "agent__complete")]
    AgentComplete {
        /// Final result description.
        result: String,
    },

    /// Commerce Tool: Initiates a checkout.
    #[serde(rename = "commerce__checkout")]
    CommerceCheckout {
        /// Merchant URL.
        merchant_url: String,
        /// Items to purchase.
        items: Vec<CommerceItem>,
        /// Total amount.
        total_amount: f64,
        /// Currency code.
        currency: String,
        /// Buyer email address.
        buyer_email: Option<String>,
    },

    /// Meta Tool: Explicit Failure (Trigger Escalation)
    #[serde(rename = "system__fail")]
    SystemFail {
        /// Reason for failure.
        reason: String,
        /// The specific tool or permission needed.
        missing_capability: Option<String>,
    },

    /// Catch-all for dynamic/unknown tools (e.g. MCP extensions) not yet strictly typed
    #[serde(untagged)]
    Dynamic(serde_json::Value),
}

/// Trait to map high-level tools to Kernel Security Scopes
impl AgentTool {
    /// Maps the tool to its corresponding `ActionTarget` for policy enforcement.
    pub fn target(&self) -> ActionTarget {
        match self {
            AgentTool::FsWrite { .. } | AgentTool::FsPatch { .. } => ActionTarget::FsWrite,
            AgentTool::FsRead { .. } | AgentTool::FsList { .. } | AgentTool::FsSearch { .. } => {
                ActionTarget::FsRead
            }
            AgentTool::FsMove { .. } => ActionTarget::Custom("filesystem__move_path".into()),

            AgentTool::SysExec { .. } | AgentTool::SysChangeDir { .. } => ActionTarget::SysExec,
            AgentTool::SysInstallPackage { .. } => ActionTarget::SysInstallPackage,

            AgentTool::BrowserNavigate { .. } => ActionTarget::BrowserNavigateHermetic,

            AgentTool::BrowserExtract { .. } => ActionTarget::BrowserExtract,
            AgentTool::BrowserClick { .. } => ActionTarget::Custom("browser::click".into()),
            AgentTool::BrowserClickElement { .. } => ActionTarget::Custom("browser::click".into()),
            AgentTool::BrowserSyntheticClick { .. } => {
                ActionTarget::Custom("browser::synthetic_click".into())
            }
            AgentTool::BrowserScroll { .. } => ActionTarget::Custom("browser::scroll".into()),
            AgentTool::BrowserType { .. } => ActionTarget::Custom("browser__type".into()),
            AgentTool::BrowserKey { .. } => ActionTarget::Custom("browser__key".into()),

            AgentTool::GuiClick { .. } => ActionTarget::GuiClick,
            AgentTool::GuiType { .. } => ActionTarget::GuiType,
            AgentTool::GuiScroll { .. } => ActionTarget::GuiScroll,
            AgentTool::GuiClickElement { .. } => ActionTarget::GuiClick,

            AgentTool::UiFind { .. } => ActionTarget::Custom("ui::find".into()),
            AgentTool::OsFocusWindow { .. } => ActionTarget::WindowFocus,
            AgentTool::OsCopy { .. } => ActionTarget::ClipboardWrite,
            AgentTool::OsPaste { .. } => ActionTarget::ClipboardRead,
            AgentTool::OsLaunchApp { .. } => ActionTarget::SysExec,

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

            AgentTool::AgentDelegate { .. } => ActionTarget::Custom("agent__delegate".into()),
            AgentTool::AgentAwait { .. } => ActionTarget::Custom("agent__await_result".into()),
            AgentTool::AgentPause { .. } => ActionTarget::Custom("agent__pause".into()),
            AgentTool::AgentComplete { .. } => ActionTarget::Custom("agent__complete".into()),
            AgentTool::SystemFail { .. } => ActionTarget::Custom("system__fail".into()),

            AgentTool::Dynamic(val) => {
                if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                    match name {
                        "ui__click_component" | "gui__click_element" => ActionTarget::GuiClick,
                        "os__launch_app" | "sys__exec" | "sys__change_directory" => {
                            ActionTarget::SysExec
                        }
                        "sys__install_package" => ActionTarget::SysInstallPackage,
                        _ => ActionTarget::Custom(name.to_string()),
                    }
                } else {
                    ActionTarget::Custom("unknown".into())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_navigate_target_maps_to_hermetic_scope() {
        let tool = AgentTool::BrowserNavigate {
            url: "https://news.ycombinator.com".to_string(),
        };
        assert_eq!(tool.target(), ActionTarget::BrowserNavigateHermetic);
    }

    #[test]
    fn filesystem_patch_target_maps_to_fs_write_scope() {
        let tool = AgentTool::FsPatch {
            path: "/tmp/demo.txt".to_string(),
            search: "hello".to_string(),
            replace: "world".to_string(),
        };
        assert_eq!(tool.target(), ActionTarget::FsWrite);
    }

    #[test]
    fn filesystem_search_target_maps_to_fs_read_scope() {
        let tool = AgentTool::FsSearch {
            path: "/tmp".to_string(),
            regex: "needle".to_string(),
            file_pattern: Some("*.rs".to_string()),
        };
        assert_eq!(tool.target(), ActionTarget::FsRead);
    }

    #[test]
    fn filesystem_move_target_maps_to_custom_scope() {
        let tool = AgentTool::FsMove {
            source_path: "/tmp/a.txt".to_string(),
            destination_path: "/tmp/b.txt".to_string(),
            overwrite: false,
        };
        assert_eq!(
            tool.target(),
            ActionTarget::Custom("filesystem__move_path".into())
        );
    }

    #[test]
    fn browser_click_element_target_maps_to_browser_click_scope() {
        let tool = AgentTool::BrowserClickElement {
            id: "btn_submit".to_string(),
        };
        assert_eq!(tool.target(), ActionTarget::Custom("browser::click".into()));
    }

    #[test]
    fn browser_scroll_target_maps_to_browser_scroll_scope() {
        let tool = AgentTool::BrowserScroll {
            delta_x: 0,
            delta_y: 480,
        };
        assert_eq!(
            tool.target(),
            ActionTarget::Custom("browser::scroll".into())
        );
    }

    #[test]
    fn browser_type_target_maps_to_custom_browser_type_tool() {
        let tool = AgentTool::BrowserType {
            text: "hello".to_string(),
            selector: Some("input[name='q']".to_string()),
        };
        assert_eq!(tool.target(), ActionTarget::Custom("browser__type".into()));
    }

    #[test]
    fn browser_key_target_maps_to_custom_browser_key_tool() {
        let tool = AgentTool::BrowserKey {
            key: "Enter".to_string(),
        };
        assert_eq!(tool.target(), ActionTarget::Custom("browser__key".into()));
    }
}
