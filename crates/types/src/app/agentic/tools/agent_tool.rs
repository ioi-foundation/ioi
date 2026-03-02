use crate::app::ActionTarget;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{CommerceItem, ComputerAction};

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

    /// Returns metadata for a filesystem path.
    #[serde(rename = "filesystem__stat")]
    FsStat {
        /// Path to inspect.
        path: String,
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

    /// Copies a file/directory deterministically.
    #[serde(rename = "filesystem__copy_path")]
    FsCopy {
        /// Source path to copy from.
        source_path: String,
        /// Destination path to copy to.
        destination_path: String,
        /// When true, replace an existing destination.
        #[serde(default)]
        overwrite: bool,
    },

    /// Deletes a file, symlink, or directory deterministically.
    #[serde(rename = "filesystem__delete_path")]
    FsDelete {
        /// Path to delete.
        path: String,
        /// When true, directory deletion is recursive.
        #[serde(default)]
        recursive: bool,
        /// When true, missing paths are treated as success.
        #[serde(default)]
        ignore_missing: bool,
    },

    /// Creates a directory deterministically.
    #[serde(rename = "filesystem__create_directory")]
    FsCreateDirectory {
        /// Directory path to create.
        path: String,
        /// When true, create missing parent directories as well.
        #[serde(default)]
        recursive: bool,
    },

    /// Creates a ZIP archive from a source directory deterministically.
    #[serde(rename = "filesystem__create_zip")]
    FsCreateZip {
        /// Source directory to archive.
        source_path: String,
        /// Destination .zip file path.
        destination_zip_path: String,
        /// When true, replace an existing destination archive.
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
        /// Optional stdin payload forwarded to the process.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdin: Option<String>,
        /// Whether to detach the process.
        #[serde(default)]
        detach: bool,
    },

    /// Executes a system command inside a persistent shell session.
    ///
    /// This is the OpenInterpreter-style "shell continuity" primitive: state (environment, shell
    /// variables, etc.) is preserved across calls within the same agent session, while the tool
    /// interface remains atomic (one invocation -> one command -> one exit code).
    #[serde(rename = "sys__exec_session")]
    SysExecSession {
        /// Command to execute.
        command: String,
        /// Arguments for the command.
        #[serde(default)]
        args: Vec<String>,
        /// Optional stdin payload forwarded to the process.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdin: Option<String>,
    },

    /// Resets the persistent shell session used by `sys__exec_session`.
    #[serde(rename = "sys__exec_session_reset")]
    SysExecSessionReset {},

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

    /// Snapshot/inspect the current browser page.
    ///
    /// Returns a semantic representation (a11y tree / DOM-derived view) suitable for
    /// robust follow-up actions like `browser__click_element`.
    #[serde(rename = "browser__snapshot")]
    BrowserSnapshot {},

    /// Clicks an element in the browser.
    #[serde(rename = "browser__click")]
    BrowserClick {
        /// CSS selector of element to click.
        selector: String,
    },

    /// Clicks an element in the browser by semantic ID from `browser__snapshot`.
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

    /// Search the web via an edge/local SERP and return typed sources with provenance.
    ///
    /// Note: the `url` field is computed deterministically by the runtime and is not intended
    /// to be provided by the model directly.
    #[serde(rename = "web__search")]
    WebSearch {
        /// Search query.
        query: String,
        /// Optional max results to return.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        /// Computed SERP URL (filled by the runtime for policy enforcement + hashing).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
    },

    /// Read a URL and return extracted text + deterministic quote spans.
    #[serde(rename = "web__read")]
    WebRead {
        /// URL to read.
        url: String,
        /// Optional max characters of extracted text to return.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_chars: Option<u32>,
    },

    /// Direct HTTP fetch for known URLs (no citations; raw response text/headers).
    ///
    /// This is the governed egress primitive used when a URL is already known and the agent
    /// needs the raw response rather than search/read evidence extraction.
    #[serde(rename = "net__fetch")]
    NetFetch {
        /// URL to fetch.
        url: String,
        /// Optional max character budget for the response body.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_chars: Option<u32>,
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

    /// Snapshot/inspect the current UI accessibility tree.
    ///
    /// Returns semantic XML with stable IDs suitable for follow-up actions like `gui__click_element`.
    #[serde(rename = "gui__snapshot")]
    GuiSnapshot {},

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

    /// Deterministically evaluate an arithmetic expression locally.
    #[serde(rename = "math__eval")]
    MathEval {
        /// Arithmetic expression (for example: "247 * 38" or "(12 + 8) / 5").
        expression: String,
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

    /// Memory Tool: Semantic search over the agent's long-term memory (SCS).
    #[serde(rename = "memory__search")]
    MemorySearch {
        /// Semantic search query.
        query: String,
    },

    /// Memory Tool: Inspect a specific memory frame by ID.
    #[serde(rename = "memory__inspect")]
    MemoryInspect {
        /// Frame ID to inspect (from memory__search).
        frame_id: u64,
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

// Keep `crate::app::ActionTarget` referenced here so consumers get a stable, discoverable API.
impl AgentTool {
    /// Returns true when `name` is reserved by a typed/native tool.
    pub fn is_reserved_tool_name(name: &str) -> bool {
        matches!(
            name,
            "computer"
                | "filesystem__write_file"
                | "filesystem__patch"
                | "filesystem__read_file"
                | "filesystem__list_directory"
                | "filesystem__search"
                | "filesystem__stat"
                | "filesystem__move_path"
                | "filesystem__copy_path"
                | "filesystem__delete_path"
                | "filesystem__create_directory"
                | "filesystem__create_zip"
                | "sys__exec"
                | "sys__exec_session"
                | "sys__exec_session_reset"
                | "sys__install_package"
                | "sys__change_directory"
                | "browser__navigate"
                | "browser__snapshot"
                | "browser__click"
                | "browser__click_element"
                | "browser__synthetic_click"
                | "browser__scroll"
                | "browser__type"
                | "browser__key"
                | "web__search"
                | "web__read"
                | "net__fetch"
                | "memory__search"
                | "memory__inspect"
                | "gui__click"
                | "gui__type"
                | "gui__scroll"
                | "gui__snapshot"
                | "gui__click_element"
                | "ui__find"
                | "os__focus_window"
                | "os__copy"
                | "os__paste"
                | "os__launch_app"
                | "math__eval"
                | "chat__reply"
                | "agent__delegate"
                | "agent__await_result"
                | "agent__pause"
                | "agent__complete"
                | "commerce__checkout"
                | "system__fail"
        )
    }

    /// Maps the tool to its corresponding `ActionTarget` for policy enforcement.
    pub fn target(&self) -> ActionTarget {
        super::target::target_for_tool(self)
    }
}
