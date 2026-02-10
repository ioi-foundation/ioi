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

    /// Take a screenshot.
    Screenshot,

    /// Get cursor position.
    CursorPosition,
}

fn default_context_hermetic() -> String {
    "hermetic".to_string()
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

    /// Navigates the browser to a URL.
    #[serde(rename = "browser__navigate")]
    BrowserNavigate {
        /// URL to navigate to.
        url: String,
        /// The context to use: "hermetic" (default) or "local".
        /// "hermetic": A fresh, isolated container/process (Safe).
        /// "local": The user's existing Chrome session (Privileged).
        #[serde(default = "default_context_hermetic")]
        context: String,
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

    /// Synthetic click for background execution.
    #[serde(rename = "browser__synthetic_click")]
    BrowserSyntheticClick {
        /// X coordinate relative to viewport.
        x: u32,
        /// Y coordinate relative to viewport.
        y: u32,
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

    /// Click a UI element by its stable ID. Global capability (works in background).
    #[serde(rename = "gui__click_element")]
    GuiClickElement {
        /// The stable ID of the element (e.g. "btn_submit").
        id: String,
    },

    /// [NEW] Find a UI element visually or by text description.
    #[serde(rename = "ui__find")]
    UiFind {
        /// Text or description to find.
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
            AgentTool::FsWrite { .. } => ActionTarget::FsWrite,
            AgentTool::FsRead { .. } | AgentTool::FsList { .. } => ActionTarget::FsRead,

            AgentTool::SysExec { .. } => ActionTarget::SysExec,

            // [MODIFIED] Browser Navigation Split
            AgentTool::BrowserNavigate { context, .. } => {
                if context == "local" {
                    ActionTarget::BrowserNavigateLocal
                } else {
                    ActionTarget::BrowserNavigateHermetic
                }
            }

            AgentTool::BrowserExtract { .. } => ActionTarget::BrowserExtract,
            AgentTool::BrowserClick { .. } => ActionTarget::Custom("browser::click".into()),
            AgentTool::BrowserSyntheticClick { .. } => {
                ActionTarget::Custom("browser::synthetic_click".into())
            }

            AgentTool::GuiClick { .. } => ActionTarget::GuiClick,
            AgentTool::GuiType { .. } => ActionTarget::GuiType,
            AgentTool::GuiClickElement { .. } => ActionTarget::GuiClick,

            AgentTool::UiFind { .. } => ActionTarget::Custom("ui::find".into()),
            AgentTool::OsFocusWindow { .. } => ActionTarget::WindowFocus,
            AgentTool::OsCopy { .. } => ActionTarget::ClipboardWrite,
            AgentTool::OsPaste { .. } => ActionTarget::ClipboardRead,
            AgentTool::OsLaunchApp { .. } => ActionTarget::SysExec,

            AgentTool::ChatReply { .. } => ActionTarget::Custom("chat__reply".into()),

            AgentTool::Computer(action) => match action {
                ComputerAction::LeftClickId { .. } | ComputerAction::LeftClickElement { .. } => {
                    ActionTarget::GuiClick
                }

                ComputerAction::Type { .. }
                | ComputerAction::Key { .. }
                | ComputerAction::Hotkey { .. } => ActionTarget::GuiType,
                ComputerAction::MouseMove { .. } => ActionTarget::GuiMouseMove,
                ComputerAction::LeftClick { .. } => ActionTarget::GuiClick,
                ComputerAction::LeftClickDrag { .. } | ComputerAction::DragDrop { .. } => {
                    ActionTarget::GuiClick
                }
                ComputerAction::Screenshot => ActionTarget::GuiScreenshot,
                ComputerAction::CursorPosition => ActionTarget::Custom("computer::cursor".into()),
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
                        "os__launch_app" => ActionTarget::SysExec,
                        _ => ActionTarget::Custom(name.to_string()),
                    }
                } else {
                    ActionTarget::Custom("unknown".into())
                }
            }
        }
    }
}
