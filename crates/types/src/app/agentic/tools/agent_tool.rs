use crate::app::agentic::WebRetrievalContract;
use crate::app::ActionTarget;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{CommerceItem, ScreenAction};

fn default_true() -> bool {
    true
}

/// A typed nested tool invocation payload used by higher-level primitives.
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct AgentToolCall {
    /// The nested tool name, for example `browser__click`.
    pub name: String,
    /// The nested tool arguments payload.
    pub arguments: serde_json::Value,
}

/// The single source of truth for all Agent Capabilities.
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(tag = "name", content = "arguments", rename_all = "snake_case")]
pub enum AgentTool {
    /// Meta-tool for screen control (Claude 3.5 Sonnet style)
    #[serde(rename = "screen")]
    Screen(ScreenAction),

    /// Writes content to a file.
    #[serde(rename = "file__write")]
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
    #[serde(rename = "file__edit")]
    FsPatch {
        /// Path to the file.
        path: String,
        /// Exact string block to find and replace. Must occur exactly once.
        search: String,
        /// Replacement string block.
        replace: String,
    },

    /// Reads content from a file.
    #[serde(rename = "file__read")]
    FsRead {
        /// Path to the file.
        path: String,
    },

    /// Lists directory contents.
    #[serde(rename = "file__list")]
    FsList {
        /// Path to the directory.
        path: String,
    },

    /// Recursively searches files for lines matching a regex pattern.
    #[serde(rename = "file__search")]
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
    #[serde(rename = "file__info")]
    FsStat {
        /// Path to inspect.
        path: String,
    },

    /// Moves or renames a file/directory deterministically.
    #[serde(rename = "file__move")]
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
    #[serde(rename = "file__copy")]
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
    #[serde(rename = "file__delete")]
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
    #[serde(rename = "file__create_dir")]
    FsCreateDirectory {
        /// Directory path to create.
        path: String,
        /// When true, create missing parent directories as well.
        #[serde(default)]
        recursive: bool,
    },

    /// Creates a ZIP archive from a source directory deterministically.
    #[serde(rename = "file__zip")]
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
    #[serde(rename = "shell__run")]
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
    #[serde(rename = "shell__start")]
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

    /// Resets the persistent shell session used by `shell__start`.
    #[serde(rename = "shell__reset")]
    SysExecSessionReset {},

    /// Installs a package using a deterministic package manager mapping.
    #[serde(rename = "package__install")]
    SysInstallPackage {
        /// Package name or identifier.
        package: String,
        /// Optional package manager override.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manager: Option<String>,
    },

    /// Changes the persistent working directory for subsequent system commands.
    #[serde(rename = "shell__cd")]
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
    /// robust follow-up actions like `browser__click`.
    #[serde(rename = "browser__inspect")]
    BrowserSnapshot {},

    /// Clicks an element in the browser.
    #[serde(rename = "browser__click")]
    BrowserClick {
        /// Optional CSS selector of the element to click.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        selector: String,
        /// Stable semantic ID of a single element (e.g. "btn_submit").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// Ordered semantic IDs from `browser__inspect` to click in sequence.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ids: Vec<String>,
        /// Optional fixed delay inserted between consecutive `ids` clicks.
        ///
        /// Use this only with ordered `ids` when a precise delay matters enough that another
        /// inference round would introduce avoidable timing drift.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        delay_ms_between_ids: Option<u64>,
        /// Optional immediate follow-up browser action to execute after the click succeeds.
        ///
        /// This is useful when a visible gate or commit click should hand off immediately to a
        /// grounded browser action without another inference turn.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        continue_with: Option<AgentToolCall>,
    },

    /// Move the browser pointer onto a target without clicking.
    #[serde(rename = "browser__hover")]
    BrowserHover {
        /// Optional CSS selector for the hover target. Provide this or `id`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
        /// Optional semantic ID from `browser__inspect`. Provide this or `selector`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// Optional duration to keep reacquiring the target without another inference turn.
        ///
        /// Use this when the target moves or when hover must be maintained over time.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        /// Optional refresh interval used while `duration_ms` tracking is active.
        ///
        /// Smaller values follow moving targets more closely but spend more runtime budget.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resample_interval_ms: Option<u64>,
    },

    /// Move the browser pointer to raw viewport coordinates.
    #[serde(rename = "browser__move_pointer")]
    BrowserMoveMouse {
        /// Absolute X coordinate in viewport CSS pixels.
        x: f64,
        /// Absolute Y coordinate in viewport CSS pixels.
        y: f64,
    },

    /// Press a mouse button at the current browser pointer position.
    #[serde(rename = "browser__pointer_down")]
    BrowserMouseDown {
        /// Mouse button name (for example: "left", "right", "middle"). Defaults to left.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        button: Option<String>,
    },

    /// Release a mouse button at the current browser pointer position.
    #[serde(rename = "browser__pointer_up")]
    BrowserMouseUp {
        /// Mouse button name (for example: "left", "right", "middle"). Defaults to left.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        button: Option<String>,
    },

    /// Synthetic click for background execution.
    #[serde(rename = "browser__click_at")]
    BrowserSyntheticClick {
        /// Optional semantic ID from `browser__inspect` for a grounded coordinate target.
        ///
        /// Prefer this when the target is already grounded in the browser observation but still
        /// requires a coordinate-style click (for example SVG, canvas, or blank-region surfaces).
        /// When combined with explicit `x` and `y`, the id acts as the grounded surface or target
        /// anchor while the runtime preserves the supplied coordinates.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// Optional absolute X coordinate in viewport CSS pixels.
        ///
        /// Use this together with `y` when no grounded target id is available.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        x: Option<f64>,
        /// Optional absolute Y coordinate in viewport CSS pixels.
        ///
        /// Use this together with `x` when no grounded target id is available.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        y: Option<f64>,
        /// Optional immediate follow-up browser action to execute after the click succeeds.
        ///
        /// Use this when the coordinate action and the next browser action are already
        /// grounded and another inference turn would introduce avoidable delay.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        continue_with: Option<AgentToolCall>,
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

    /// Select text within a browser element or the current active element.
    #[serde(rename = "browser__select")]
    BrowserSelectText {
        /// Optional CSS selector for the selection target. Defaults to the active element.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
        /// Optional inclusive start offset within the target text/value. Defaults to `0`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        start_offset: Option<u32>,
        /// Optional exclusive end offset within the target text/value. Defaults to the full length.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        end_offset: Option<u32>,
    },

    /// Press a keyboard key in the browser via CDP key events (headless-compatible).
    #[serde(rename = "browser__press_key")]
    BrowserKey {
        /// Key name (for example: "Enter", "Tab", "ArrowDown").
        key: String,
        /// Optional CSS selector to focus before pressing the key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
        /// Optional modifier keys to hold while pressing `key`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        modifiers: Option<Vec<String>>,
        /// Optional immediate follow-up browser action to execute after the key succeeds.
        ///
        /// This is useful when a grounded control-local key is expected to finish a local state
        /// change and the next grounded browser action is already known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        continue_with: Option<AgentToolCall>,
    },

    /// Copy the current browser text selection into the system clipboard.
    #[serde(rename = "browser__copy")]
    BrowserCopySelection {},

    /// Paste the current system clipboard contents into the browser.
    #[serde(rename = "browser__paste")]
    BrowserPasteClipboard {
        /// Optional CSS selector to focus before inserting clipboard text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
    },

    /// Find literal text on the current page and optionally scroll to the first match.
    #[serde(rename = "browser__find_text")]
    BrowserFindText {
        /// Literal text to find.
        query: String,
        /// Optional search scope: `visible` (default) or `document`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        /// Whether to scroll the first match into view.
        #[serde(default)]
        scroll: bool,
    },

    /// Summarize the visible content of a browser canvas element.
    #[serde(rename = "browser__inspect_canvas")]
    BrowserCanvasSummary {
        /// CSS selector for the canvas element or a container that resolves to a canvas.
        selector: String,
    },

    /// Capture a browser screenshot as a visual observation.
    #[serde(rename = "browser__screenshot")]
    BrowserScreenshot {
        /// Whether to capture beyond viewport for full-page output.
        full_page: bool,
    },

    /// Explicit wait primitive for browser workflows.
    #[serde(rename = "browser__wait")]
    BrowserWait {
        /// Optional fixed duration to wait in milliseconds.
        ///
        /// When `condition` is absent, this must be provided.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ms: Option<u64>,
        /// Optional condition to wait for.
        ///
        /// Supported values: `selector_visible`, `text_present`, `dom_stable`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        condition: Option<String>,
        /// Optional selector used by `selector_visible`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
        /// Optional literal text used by `text_present`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query: Option<String>,
        /// Optional text scope for `text_present`: `visible` (default) or `document`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        /// Optional timeout in milliseconds for condition waits.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
        /// Optional immediate follow-up browser action to execute as soon as the wait completes.
        ///
        /// Use this when the next browser action is already grounded and timing matters enough
        /// that another inference round would introduce avoidable delay.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        continue_with: Option<AgentToolCall>,
    },

    /// Attach one or more local files to a browser file input.
    #[serde(rename = "browser__upload")]
    BrowserUploadFile {
        /// Paths to files on the local filesystem.
        paths: Vec<String>,
        /// Optional CSS selector for the target file input. Defaults to `input[type='file']`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
        /// Optional SoM ID for the target element (resolved via current visual semantic map).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        som_id: Option<u32>,
    },

    /// List options for a native `<select>` dropdown.
    #[serde(rename = "browser__list_options")]
    BrowserDropdownOptions {
        /// Optional semantic browser ID from `browser__inspect` / browser observations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// Optional CSS selector for the dropdown element.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
        /// Optional SoM ID for the dropdown element (resolved via current visual semantic map).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        som_id: Option<u32>,
    },

    /// Select a value or label for a native `<select>` dropdown.
    #[serde(rename = "browser__select_option")]
    BrowserSelectDropdown {
        /// Optional semantic browser ID from `browser__inspect` / browser observations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// Optional CSS selector for the dropdown element.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
        /// Optional SoM ID for the dropdown element (resolved via current visual semantic map).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        som_id: Option<u32>,
        /// Optional option value to select.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        /// Optional visible label text to select.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },

    /// Navigate backward in browser history.
    #[serde(rename = "browser__back")]
    BrowserGoBack {
        /// Number of history entries to go back. Defaults to 1.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        steps: Option<u32>,
    },

    /// List open browser tabs for the interactive browser context.
    #[serde(rename = "browser__list_tabs")]
    BrowserTabList {},

    /// Switch focus to an existing browser tab by tab id.
    #[serde(rename = "browser__switch_tab")]
    BrowserTabSwitch {
        /// Stable tab identifier for the current browser session.
        tab_id: String,
    },

    /// Close an existing browser tab by tab id.
    #[serde(rename = "browser__close_tab")]
    BrowserTabClose {
        /// Stable tab identifier for the current browser session.
        tab_id: String,
        /// Distinguishes close replay from other tab actions in ActionTarget-level queues.
        #[serde(default = "default_true")]
        close: bool,
    },

    /// Search the web via an edge/local SERP and return typed sources with provenance.
    ///
    /// Note: the `url` field is computed deterministically by the runtime and is not intended
    /// to be provided by the model directly.
    #[serde(rename = "web__search")]
    WebSearch {
        /// Search query.
        query: String,
        /// Optional full query contract used for provider selection and completion policy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query_contract: Option<String>,
        /// Optional typed retrieval contract carried by runtime continuations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retrieval_contract: Option<WebRetrievalContract>,
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
        /// Whether browser-backed fallback retrieval is allowed when HTTP extraction is insufficient.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allow_browser_fallback: Option<bool>,
    },

    /// Extract transcript text from a remote media URL using managed media providers.
    #[serde(rename = "media__extract_transcript")]
    MediaExtractTranscript {
        /// URL to inspect.
        url: String,
        /// Requested transcript language (for example: "en").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        language: Option<String>,
        /// Optional max characters of transcript text to return.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_chars: Option<u32>,
    },

    /// Extract multimodal evidence from a remote media URL using transcript + visual providers.
    #[serde(rename = "media__extract_evidence")]
    MediaExtractMultimodalEvidence {
        /// URL to inspect.
        url: String,
        /// Requested transcript language (for example: "en").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        language: Option<String>,
        /// Optional max characters of transcript text to return.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_chars: Option<u32>,
        /// Optional max sampled frames to analyze.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        frame_limit: Option<u32>,
    },

    /// Direct HTTP fetch for known URLs (no citations; raw response text/headers).
    ///
    /// This is the governed egress primitive used when a URL is already known and the agent
    /// needs the raw response rather than search/read evidence extraction.
    #[serde(rename = "http__fetch")]
    NetFetch {
        /// URL to fetch.
        url: String,
        /// Optional max character budget for the response body.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_chars: Option<u32>,
    },

    /// Legacy GUI click tool.
    #[serde(rename = "screen__click_at")]
    GuiClick {
        /// X coordinate.
        x: u32,
        /// Y coordinate.
        y: u32,
        /// Mouse button (left/right/middle).
        button: Option<String>,
    },

    /// Legacy GUI typing tool.
    #[serde(rename = "screen__type")]
    GuiType {
        /// Text to type.
        text: String,
    },

    /// Scroll the active window/element.
    #[serde(rename = "screen__scroll")]
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
    /// Returns semantic XML with stable IDs suitable for follow-up actions like `screen__click`.
    #[serde(rename = "screen__inspect")]
    GuiSnapshot {},

    /// Click a UI element by its stable ID. Global capability (works in background).
    #[serde(rename = "screen__click")]
    GuiClickElement {
        /// The stable ID of the element (e.g. "btn_submit").
        id: String,
    },

    /// [NEW] Find a UI element by visual or semantic description.
    #[serde(rename = "screen__find")]
    UiFind {
        /// Description to find (text, icon, color, shape, logo).
        query: String,
    },

    /// [NEW] Focus a specific window.
    #[serde(rename = "window__focus")]
    OsFocusWindow {
        /// Title of the window to focus.
        title: String,
    },

    /// [NEW] Copy text to clipboard.
    #[serde(rename = "clipboard__copy")]
    OsCopy {
        /// Content to copy.
        content: String,
    },

    /// [NEW] Paste text from clipboard.
    #[serde(rename = "clipboard__paste")]
    OsPaste {},

    /// [NEW] Launch an application.
    #[serde(rename = "app__launch")]
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

    /// Install a durable local monitor workflow that polls a source and notifies on matches.
    #[serde(rename = "monitor__create")]
    AutomationCreateMonitor {
        /// Optional human-facing title for the installed workflow.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        /// Optional human-facing description for the installed workflow.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// Match keywords for the monitor predicate.
        keywords: Vec<String>,
        /// Optional polling interval in seconds. Runtime enforces a minimum.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interval_seconds: Option<u64>,
        /// Optional original user prompt or query contract used to author the workflow.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_prompt: Option<String>,
    },

    /// Meta Tool: Delegates a task to a sub-agent.
    #[serde(rename = "agent__delegate")]
    AgentDelegate {
        /// Goal for the sub-agent.
        goal: String,
        /// Budget allocated.
        budget: u64,
        /// Optional higher-order parent playbook id coordinating this delegation sequence.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        playbook_id: Option<String>,
        /// Optional worker template id for bounded specialist spawning.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        template_id: Option<String>,
        /// Optional playbook/workflow id within the selected worker template.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        workflow_id: Option<String>,
        /// Optional role label when the delegation does not use a named template.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role: Option<String>,
        /// Optional explicit success criteria for the child worker.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        success_criteria: Option<String>,
        /// Optional merge policy label for parent collapse semantics.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        merge_mode: Option<String>,
        /// Optional expected output artifact or payload shape.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_output: Option<String>,
    },

    /// Memory Tool: Semantic search over the agent's long-term archival memory.
    #[serde(rename = "memory__search")]
    MemorySearch {
        /// Semantic search query.
        query: String,
    },

    /// Memory Tool: Inspect a specific memory record by frame/record ID.
    #[serde(rename = "memory__read")]
    MemoryInspect {
        /// Frame ID to inspect (from memory__search).
        frame_id: u64,
    },

    /// Memory Tool: Replace a typed core-memory register.
    #[serde(rename = "memory__replace")]
    MemoryReplaceCore {
        /// Core-memory section name.
        section: String,
        /// New content for the section.
        content: String,
    },

    /// Memory Tool: Append content to an appendable core-memory register.
    #[serde(rename = "memory__append")]
    MemoryAppendCore {
        /// Core-memory section name.
        section: String,
        /// Content to append.
        content: String,
    },

    /// Memory Tool: Clear a typed core-memory register.
    #[serde(rename = "memory__clear")]
    MemoryClearCore {
        /// Core-memory section name.
        section: String,
    },

    /// Meta Tool: Awaits result from a sub-agent.
    #[serde(rename = "agent__await")]
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
    #[serde(rename = "agent__escalate")]
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
    /// Returns the canonical serialized tool name for policy checks and receipts.
    pub fn name_string(&self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|value| {
                value
                    .get("name")
                    .and_then(|name| name.as_str())
                    .map(str::to_string)
                    .or_else(|| {
                        value
                            .get("tool_name")
                            .and_then(|name| name.as_str())
                            .map(str::to_string)
                    })
            })
            .unwrap_or_else(|| "unknown_tool".to_string())
    }

    /// Returns true when `name` is reserved by a typed/native tool.
    pub fn is_reserved_tool_name(name: &str) -> bool {
        matches!(
            name,
            "screen"
                | "file__write"
                | "file__edit"
                | "file__read"
                | "file__list"
                | "file__search"
                | "file__info"
                | "file__move"
                | "file__copy"
                | "file__delete"
                | "file__create_dir"
                | "file__zip"
                | "shell__run"
                | "shell__start"
                | "shell__reset"
                | "package__install"
                | "shell__cd"
                | "browser__navigate"
                | "browser__inspect"
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
                | "browser__inspect_canvas"
                | "browser__screenshot"
                | "browser__wait"
                | "browser__upload"
                | "browser__list_options"
                | "browser__select_option"
                | "browser__back"
                | "browser__list_tabs"
                | "browser__switch_tab"
                | "browser__close_tab"
                | "web__search"
                | "web__read"
                | "media__extract_transcript"
                | "media__extract_evidence"
                | "http__fetch"
                | "memory__search"
                | "memory__read"
                | "memory__replace"
                | "memory__append"
                | "memory__clear"
                | "screen__click_at"
                | "screen__type"
                | "screen__scroll"
                | "screen__inspect"
                | "screen__click"
                | "screen__find"
                | "window__focus"
                | "clipboard__copy"
                | "clipboard__paste"
                | "app__launch"
                | "math__eval"
                | "chat__reply"
                | "monitor__create"
                | "agent__delegate"
                | "agent__await"
                | "agent__pause"
                | "agent__complete"
                | "commerce__checkout"
                | "agent__escalate"
        )
    }

    /// Maps the tool to its corresponding `ActionTarget` for policy enforcement.
    pub fn target(&self) -> ActionTarget {
        super::target::target_for_tool(self)
    }
}
