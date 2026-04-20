use crate::models::{
    CapabilityAuthorityDescriptor, CapabilityLeaseDescriptor, CapabilityRegistryEntry,
};
use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const DIAGNOSTIC_GRACE_PERIOD: Duration = Duration::from_millis(350);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceLspDiagnostic {
    pub severity: String,
    pub title: String,
    pub detail: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    pub path: String,
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceLspLocation {
    pub path: String,
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceLspTextEdit {
    pub path: String,
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub new_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceLspCodeAction {
    pub title: String,
    #[serde(default)]
    pub kind: Option<String>,
    pub is_preferred: bool,
    #[serde(default)]
    pub disabled_reason: Option<String>,
    #[serde(default)]
    pub edits: Vec<WorkspaceLspTextEdit>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceLspSymbol {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub detail: Option<String>,
    pub path: String,
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub end_column: u32,
    #[serde(default)]
    pub children: Vec<WorkspaceLspSymbol>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceLspSnapshot {
    pub generated_at_ms: u64,
    pub workspace_root: String,
    pub path: String,
    pub language_id: String,
    pub availability: String,
    pub status_label: String,
    pub service_label: String,
    #[serde(default)]
    pub server_label: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub diagnostics: Vec<WorkspaceLspDiagnostic>,
    #[serde(default)]
    pub symbols: Vec<WorkspaceLspSymbol>,
}

#[derive(Debug, Clone)]
enum WorkspaceLspServerKind {
    RustAnalyzer,
    TypeScriptLanguageServer,
}

#[derive(Debug, Clone)]
struct WorkspaceLspServerSpec {
    kind: WorkspaceLspServerKind,
    label: String,
    program: PathBuf,
    args: Vec<String>,
    language_id: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct LspPositionPayload {
    line: u32,
    character: u32,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct LspRangePayload {
    start: LspPositionPayload,
    end: LspPositionPayload,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LspLocationPayload {
    uri: String,
    range: LspRangePayload,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LspLocationLinkPayload {
    target_uri: String,
    target_selection_range: LspRangePayload,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LspDocumentSymbolPayload {
    name: String,
    kind: u32,
    #[serde(default)]
    detail: Option<String>,
    range: LspRangePayload,
    #[serde(default)]
    children: Option<Vec<LspDocumentSymbolPayload>>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LspSymbolInformationPayload {
    name: String,
    kind: u32,
    #[serde(default)]
    container_name: Option<String>,
    location: LspLocationPayload,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct LspDiagnosticPayload {
    range: LspRangePayload,
    #[serde(default)]
    severity: Option<u32>,
    #[serde(default)]
    code: Option<Value>,
    #[serde(default)]
    source: Option<String>,
    message: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LspCodeActionDisabledPayload {
    reason: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LspTextEditPayload {
    range: LspRangePayload,
    new_text: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LspVersionedTextDocumentIdentifierPayload {
    uri: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LspTextDocumentEditPayload {
    text_document: LspVersionedTextDocumentIdentifierPayload,
    edits: Vec<LspTextEditPayload>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum LspDocumentChangePayload {
    TextDocumentEdit(LspTextDocumentEditPayload),
    ResourceOp {
        #[serde(flatten)]
        _value: Value,
    },
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LspWorkspaceEditPayload {
    #[serde(default)]
    changes: Option<HashMap<String, Vec<LspTextEditPayload>>>,
    #[serde(default)]
    document_changes: Option<Vec<LspDocumentChangePayload>>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LspCodeActionPayload {
    title: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    is_preferred: Option<bool>,
    #[serde(default)]
    disabled: Option<LspCodeActionDisabledPayload>,
    #[serde(default)]
    edit: Option<LspWorkspaceEditPayload>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublishDiagnosticsPayload {
    uri: String,
    diagnostics: Vec<LspDiagnosticPayload>,
}

#[derive(Debug)]
struct LspProcessClient {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<Value>,
    next_id: u64,
    diagnostics_by_uri: HashMap<String, Vec<LspDiagnosticPayload>>,
}

fn normalize_relative_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn path_to_uri(path: &Path) -> Result<String, String> {
    Url::from_file_path(path)
        .map(|uri| uri.to_string())
        .map_err(|_| format!("Failed to build file URI for '{}'.", path.display()))
}

fn uri_to_workspace_path(workspace_root: &Path, uri: &str) -> Option<String> {
    let url = Url::parse(uri).ok()?;
    if url.scheme() != "file" {
        return None;
    }
    let file_path = url.to_file_path().ok()?;
    let relative = file_path.strip_prefix(workspace_root).ok()?;
    Some(normalize_relative_path(relative))
}

fn relative_to_absolute(workspace_root: &Path, path: &str) -> PathBuf {
    workspace_root.join(path)
}

fn language_server_env_var(kind: &WorkspaceLspServerKind) -> &'static str {
    match kind {
        WorkspaceLspServerKind::RustAnalyzer => "IOI_RUST_ANALYZER",
        WorkspaceLspServerKind::TypeScriptLanguageServer => "IOI_TYPESCRIPT_LANGUAGE_SERVER",
    }
}

fn workspace_language_id(path: &Path) -> Option<&'static str> {
    match path.extension().and_then(|value| value.to_str()) {
        Some("rs") => Some("rust"),
        Some("ts") | Some("tsx") => Some("typescript"),
        Some("js") | Some("jsx") => Some("javascript"),
        _ => None,
    }
}

fn candidate_executable_names(kind: &WorkspaceLspServerKind) -> &'static [&'static str] {
    match kind {
        WorkspaceLspServerKind::RustAnalyzer => &["rust-analyzer"],
        WorkspaceLspServerKind::TypeScriptLanguageServer => &["typescript-language-server"],
    }
}

fn current_dir_or(root: &Path) -> PathBuf {
    env::current_dir().unwrap_or_else(|_| root.to_path_buf())
}

fn candidate_local_paths(root: &Path, kind: &WorkspaceLspServerKind) -> Vec<PathBuf> {
    let current_dir = current_dir_or(root);
    match kind {
        WorkspaceLspServerKind::RustAnalyzer => Vec::new(),
        WorkspaceLspServerKind::TypeScriptLanguageServer => vec![
            root.join("node_modules/.bin/typescript-language-server"),
            current_dir.join("node_modules/.bin/typescript-language-server"),
        ],
    }
}

fn is_executable(path: &Path) -> bool {
    path.exists() && path.is_file()
}

fn find_executable(kind: &WorkspaceLspServerKind, root: &Path) -> Option<PathBuf> {
    if let Some(explicit) = env::var_os(language_server_env_var(kind))
        .map(PathBuf::from)
        .filter(|path| is_executable(path))
    {
        return Some(explicit);
    }

    for candidate in candidate_local_paths(root, kind) {
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }

    let path_var = env::var_os("PATH")?;
    for directory in env::split_paths(&path_var) {
        for name in candidate_executable_names(kind) {
            let candidate = directory.join(name);
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }

    None
}

fn discover_server_for_path(
    workspace_root: &Path,
    absolute_path: &Path,
) -> Option<WorkspaceLspServerSpec> {
    match workspace_language_id(absolute_path)? {
        "rust" => Some(WorkspaceLspServerSpec {
            kind: WorkspaceLspServerKind::RustAnalyzer,
            label: "Rust Analyzer".to_string(),
            program: find_executable(&WorkspaceLspServerKind::RustAnalyzer, workspace_root)?,
            args: Vec::new(),
            language_id: "rust".to_string(),
        }),
        "typescript" => Some(WorkspaceLspServerSpec {
            kind: WorkspaceLspServerKind::TypeScriptLanguageServer,
            label: "TypeScript language server".to_string(),
            program: find_executable(
                &WorkspaceLspServerKind::TypeScriptLanguageServer,
                workspace_root,
            )?,
            args: vec!["--stdio".to_string()],
            language_id: "typescript".to_string(),
        }),
        "javascript" => Some(WorkspaceLspServerSpec {
            kind: WorkspaceLspServerKind::TypeScriptLanguageServer,
            label: "TypeScript language server".to_string(),
            program: find_executable(
                &WorkspaceLspServerKind::TypeScriptLanguageServer,
                workspace_root,
            )?,
            args: vec!["--stdio".to_string()],
            language_id: "javascript".to_string(),
        }),
        _ => None,
    }
}

fn service_label_for_path(path: &Path) -> String {
    match workspace_language_id(path) {
        Some("rust") => "Workspace intelligence".to_string(),
        Some("typescript") | Some("javascript") => "Workspace intelligence".to_string(),
        _ => "Workspace intelligence".to_string(),
    }
}

fn lsp_severity_label(severity: Option<u32>) -> String {
    match severity.unwrap_or(1) {
        1 => "error".to_string(),
        2 => "warning".to_string(),
        3 | 4 => "info".to_string(),
        _ => "info".to_string(),
    }
}

fn lsp_symbol_kind_label(kind: u32) -> String {
    match kind {
        1 => "file",
        2 => "module",
        3 => "namespace",
        4 => "package",
        5 => "class",
        6 => "method",
        7 => "property",
        8 => "field",
        9 => "constructor",
        10 => "enum",
        11 => "interface",
        12 => "function",
        13 => "variable",
        14 => "constant",
        15 => "string",
        16 => "number",
        17 => "boolean",
        18 => "array",
        19 => "object",
        20 => "key",
        21 => "null",
        22 => "enum_member",
        23 => "struct",
        24 => "event",
        25 => "operator",
        26 => "type_parameter",
        _ => "symbol",
    }
    .replace('_', " ")
}

fn lsp_diagnostic_code(value: Option<Value>) -> Option<String> {
    match value {
        Some(Value::String(text)) => Some(text),
        Some(Value::Number(number)) => Some(number.to_string()),
        Some(other) => Some(other.to_string()),
        None => None,
    }
}

fn to_workspace_location(
    workspace_root: &Path,
    uri: &str,
    range: &LspRangePayload,
) -> Option<WorkspaceLspLocation> {
    Some(WorkspaceLspLocation {
        path: uri_to_workspace_path(workspace_root, uri)?,
        line: range.start.line.saturating_add(1),
        column: range.start.character.saturating_add(1),
        end_line: range.end.line.saturating_add(1),
        end_column: range.end.character.saturating_add(1),
    })
}

fn to_workspace_text_edit(
    workspace_root: &Path,
    uri: &str,
    edit: LspTextEditPayload,
) -> Option<WorkspaceLspTextEdit> {
    Some(WorkspaceLspTextEdit {
        path: uri_to_workspace_path(workspace_root, uri)?,
        line: edit.range.start.line.saturating_add(1),
        column: edit.range.start.character.saturating_add(1),
        end_line: edit.range.end.line.saturating_add(1),
        end_column: edit.range.end.character.saturating_add(1),
        new_text: edit.new_text,
    })
}

fn parse_workspace_edit(
    workspace_root: &Path,
    edit: LspWorkspaceEditPayload,
) -> Vec<WorkspaceLspTextEdit> {
    let mut parsed = Vec::new();

    if let Some(changes) = edit.changes {
        for (uri, edits) in changes {
            for text_edit in edits {
                if let Some(parsed_edit) = to_workspace_text_edit(workspace_root, &uri, text_edit) {
                    parsed.push(parsed_edit);
                }
            }
        }
    }

    if let Some(document_changes) = edit.document_changes {
        for change in document_changes {
            match change {
                LspDocumentChangePayload::TextDocumentEdit(change) => {
                    for text_edit in change.edits {
                        if let Some(parsed_edit) = to_workspace_text_edit(
                            workspace_root,
                            &change.text_document.uri,
                            text_edit,
                        ) {
                            parsed.push(parsed_edit);
                        }
                    }
                }
                LspDocumentChangePayload::ResourceOp { .. } => {}
            }
        }
    }

    parsed
}

fn parse_code_action_result(workspace_root: &Path, value: Value) -> Vec<WorkspaceLspCodeAction> {
    if value.is_null() {
        return Vec::new();
    }

    serde_json::from_value::<Vec<LspCodeActionPayload>>(value)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|action| {
            let edits = action
                .edit
                .map(|edit| parse_workspace_edit(workspace_root, edit))
                .unwrap_or_default();
            let disabled_reason = action.disabled.map(|disabled| disabled.reason);
            if edits.is_empty() && disabled_reason.is_none() {
                return None;
            }
            Some(WorkspaceLspCodeAction {
                title: action.title,
                kind: action.kind,
                is_preferred: action.is_preferred.unwrap_or(false),
                disabled_reason,
                edits,
            })
        })
        .collect()
}

fn to_workspace_symbol(path: &str, symbol: LspDocumentSymbolPayload) -> WorkspaceLspSymbol {
    WorkspaceLspSymbol {
        name: symbol.name,
        kind: lsp_symbol_kind_label(symbol.kind),
        detail: symbol.detail,
        path: path.to_string(),
        line: symbol.range.start.line.saturating_add(1),
        column: symbol.range.start.character.saturating_add(1),
        end_line: symbol.range.end.line.saturating_add(1),
        end_column: symbol.range.end.character.saturating_add(1),
        children: symbol
            .children
            .unwrap_or_default()
            .into_iter()
            .map(|child| to_workspace_symbol(path, child))
            .collect(),
    }
}

fn to_workspace_symbol_from_information(
    workspace_root: &Path,
    symbol: LspSymbolInformationPayload,
) -> Option<WorkspaceLspSymbol> {
    let location =
        to_workspace_location(workspace_root, &symbol.location.uri, &symbol.location.range)?;
    Some(WorkspaceLspSymbol {
        name: symbol.name,
        kind: lsp_symbol_kind_label(symbol.kind),
        detail: symbol.container_name,
        path: location.path,
        line: location.line,
        column: location.column,
        end_line: location.end_line,
        end_column: location.end_column,
        children: Vec::new(),
    })
}

fn to_workspace_diagnostic(path: &str, diagnostic: LspDiagnosticPayload) -> WorkspaceLspDiagnostic {
    let severity = lsp_severity_label(diagnostic.severity);
    let code = lsp_diagnostic_code(diagnostic.code);
    let title = code
        .as_ref()
        .map(|code| format!("{}: {}", code, diagnostic.message))
        .unwrap_or_else(|| diagnostic.message.clone());

    let location = WorkspaceLspLocation {
        path: path.to_string(),
        line: diagnostic.range.start.line.saturating_add(1),
        column: diagnostic.range.start.character.saturating_add(1),
        end_line: diagnostic.range.end.line.saturating_add(1),
        end_column: diagnostic.range.end.character.saturating_add(1),
    };

    WorkspaceLspDiagnostic {
        severity,
        title,
        detail: diagnostic.message,
        code,
        source: diagnostic.source,
        path: location.path,
        line: location.line,
        column: location.column,
        end_line: location.end_line,
        end_column: location.end_column,
    }
}

fn generated_at_ms() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}

fn unavailable_snapshot(
    workspace_root: &Path,
    relative_path: &str,
    detail: Option<String>,
) -> WorkspaceLspSnapshot {
    WorkspaceLspSnapshot {
        generated_at_ms: generated_at_ms(),
        workspace_root: workspace_root.display().to_string(),
        path: relative_path.to_string(),
        language_id: workspace_language_id(&workspace_root.join(relative_path))
            .unwrap_or("plaintext")
            .to_string(),
        availability: "unavailable".to_string(),
        status_label: "Unavailable".to_string(),
        service_label: service_label_for_path(&workspace_root.join(relative_path)),
        server_label: None,
        detail,
        diagnostics: Vec::new(),
        symbols: Vec::new(),
    }
}

fn error_snapshot(
    workspace_root: &Path,
    relative_path: &str,
    language_id: &str,
    server_label: Option<String>,
    detail: String,
) -> WorkspaceLspSnapshot {
    WorkspaceLspSnapshot {
        generated_at_ms: generated_at_ms(),
        workspace_root: workspace_root.display().to_string(),
        path: relative_path.to_string(),
        language_id: language_id.to_string(),
        availability: "error".to_string(),
        status_label: "Error".to_string(),
        service_label: service_label_for_path(&workspace_root.join(relative_path)),
        server_label,
        detail: Some(detail),
        diagnostics: Vec::new(),
        symbols: Vec::new(),
    }
}

fn build_authority(
    tier_id: &str,
    tier_label: &str,
    summary: impl Into<String>,
    detail: impl Into<String>,
    signals: Vec<String>,
) -> CapabilityAuthorityDescriptor {
    CapabilityAuthorityDescriptor {
        tier_id: tier_id.to_string(),
        tier_label: tier_label.to_string(),
        governed_profile_id: Some("native_family".to_string()),
        governed_profile_label: Some("Native tool family".to_string()),
        summary: summary.into(),
        detail: detail.into(),
        signals,
    }
}

fn build_lease(
    availability: &str,
    summary: impl Into<String>,
    detail: impl Into<String>,
    signals: Vec<String>,
) -> CapabilityLeaseDescriptor {
    CapabilityLeaseDescriptor {
        availability: availability.to_string(),
        availability_label: match availability {
            "ready" => "Ready".to_string(),
            "attention" => "Needs attention".to_string(),
            "blocked" => "Blocked".to_string(),
            other => other.to_string(),
        },
        runtime_target_id: Some("workspace_runtime".to_string()),
        runtime_target_label: Some("Workspace runtime".to_string()),
        mode_id: Some("managed_runtime".to_string()),
        mode_label: Some("Managed runtime".to_string()),
        summary: summary.into(),
        detail: detail.into(),
        requires_auth: false,
        signals,
    }
}

pub fn capability_registry_entry() -> CapabilityRegistryEntry {
    let rust_analyzer = find_executable(
        &WorkspaceLspServerKind::RustAnalyzer,
        &current_dir_or(Path::new(".")),
    );
    let ts_server = find_executable(
        &WorkspaceLspServerKind::TypeScriptLanguageServer,
        &current_dir_or(Path::new(".")),
    );
    let mut signals = Vec::new();
    if let Some(path) = rust_analyzer.as_ref() {
        signals.push(format!("Rust Analyzer {}", path.display()));
    }
    if let Some(path) = ts_server.as_ref() {
        signals.push(format!("TypeScript language server {}", path.display()));
    }
    if signals.is_empty() {
        signals.push("No managed language server binary discovered yet.".to_string());
    }
    let availability = if rust_analyzer.is_some() || ts_server.is_some() {
        "ready"
    } else {
        "attention"
    };

    CapabilityRegistryEntry {
        entry_id: "workspace_service:lsp".to_string(),
        kind: "workspace_service".to_string(),
        label: "Workspace intelligence".to_string(),
        summary:
            "Diagnostics, definitions, references, symbols, and first-slice code actions served by governed workspace language services."
                .to_string(),
        source_kind: "workspace_runtime".to_string(),
        source_label: "Workspace runtime".to_string(),
        source_uri: None,
        trust_posture: "contained_local".to_string(),
        governed_profile: Some("native_family".to_string()),
        availability: availability.to_string(),
        status_label: if availability == "ready" {
            "Ready".to_string()
        } else {
            "Needs setup".to_string()
        },
        why_selectable: if availability == "ready" {
            "Governed code-intelligence service available for workspace editing, review, and guided quick-fix flows.".to_string()
        } else {
            "No managed language server binary is currently visible to the workspace runtime."
                .to_string()
        },
        governing_family_id: None,
        related_governing_entry_ids: Vec::new(),
        governing_family_hints: vec![
            "capability:lsp".to_string(),
            "capability:review".to_string(),
            "source-root:workspace".to_string(),
        ],
        runtime_target: Some("workspace_runtime".to_string()),
        lease_mode: Some("managed_runtime".to_string()),
        authority: build_authority(
            "contained_local",
            "Contained local",
            "Workspace language services stay inside the local operator trust boundary.",
            "These services inspect files and return typed code-intelligence results, but they do not widen execution authority outside the workspace runtime.",
            signals.clone(),
        ),
        lease: build_lease(
            availability,
            "Diagnostics and navigation flow through a governed runtime service instead of editor-only heuristics.",
            "Operators inherit code-intelligence through the workspace runtime, which keeps definitions, symbols, and diagnostics auditable beside the rest of the capability fabric.",
            signals,
        ),
    }
}

impl LspProcessClient {
    fn spawn(server: &WorkspaceLspServerSpec) -> Result<Self, String> {
        let mut command = Command::new(&server.program);
        command
            .args(&server.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut child = command.spawn().map_err(|error| {
            format!(
                "Failed to launch {} from '{}': {}",
                server.label,
                server.program.display(),
                error
            )
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("{} did not expose stdin.", server.label))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("{} did not expose stdout.", server.label))?;
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_json_rpc_message(&mut reader) {
                    Ok(Some(message)) => {
                        if tx.send(message).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            child,
            stdin,
            rx,
            next_id: 1,
            diagnostics_by_uri: HashMap::new(),
        })
    }

    fn send_notification(&mut self, method: &str, params: Value) -> Result<(), String> {
        write_json_rpc_message(
            &mut self.stdin,
            &json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
            }),
        )
    }

    fn send_request(&mut self, method: &str, params: Value) -> Result<u64, String> {
        let id = self.next_id;
        self.next_id += 1;
        write_json_rpc_message(
            &mut self.stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params,
            }),
        )?;
        Ok(id)
    }

    fn await_response(&mut self, request_id: u64, timeout: Duration) -> Result<Value, String> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "Language service timed out waiting for request {}.",
                    request_id
                ));
            }

            match self.rx.recv_timeout(remaining) {
                Ok(message) => {
                    if let Some(id) = message.get("id").and_then(Value::as_u64) {
                        if message.get("method").is_some() {
                            self.respond_to_server_request(id)?;
                            continue;
                        }
                        if id != request_id {
                            continue;
                        }
                        if let Some(error) = message.get("error") {
                            return Err(format!("Language service error: {}", error));
                        }
                        return Ok(message.get("result").cloned().unwrap_or(Value::Null));
                    }

                    self.handle_message(message)?;
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!(
                        "Language service timed out waiting for request {}.",
                        request_id
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err("Language service exited unexpectedly.".to_string());
                }
            }
        }
    }

    fn drain_messages(&mut self, duration: Duration) -> Result<(), String> {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            match self
                .rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(message) => self.handle_message(message)?,
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        Ok(())
    }

    fn handle_message(&mut self, message: Value) -> Result<(), String> {
        if let Some(id) = message.get("id").and_then(Value::as_u64) {
            if message.get("method").is_some() {
                self.respond_to_server_request(id)?;
            }
            return Ok(());
        }

        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return Ok(());
        };

        if method == "textDocument/publishDiagnostics" {
            if let Some(params) = message.get("params") {
                if let Ok(payload) =
                    serde_json::from_value::<PublishDiagnosticsPayload>(params.clone())
                {
                    self.diagnostics_by_uri
                        .insert(payload.uri, payload.diagnostics);
                }
            }
        }
        Ok(())
    }

    fn respond_to_server_request(&mut self, request_id: u64) -> Result<(), String> {
        write_json_rpc_message(
            &mut self.stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": Value::Null,
            }),
        )
    }

    fn initialize(
        &mut self,
        workspace_root: &Path,
        server: &WorkspaceLspServerSpec,
    ) -> Result<(), String> {
        let root_uri = path_to_uri(workspace_root)?;
        let request_id = self.send_request(
            "initialize",
            json!({
                "processId": std::process::id(),
                "rootUri": root_uri,
                "workspaceFolders": [
                    {
                        "uri": path_to_uri(workspace_root)?,
                        "name": workspace_root.file_name().and_then(|value| value.to_str()).unwrap_or("workspace"),
                    }
                ],
                "capabilities": {
                    "textDocument": {
                        "publishDiagnostics": {
                            "relatedInformation": true
                        }
                    }
                },
                "clientInfo": {
                    "name": "ioi-autopilot",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "initializationOptions": match server.kind {
                    WorkspaceLspServerKind::RustAnalyzer => json!({
                        "cargo": { "allFeatures": true },
                        "checkOnSave": true
                    }),
                    WorkspaceLspServerKind::TypeScriptLanguageServer => Value::Null,
                }
            }),
        )?;
        let _ = self.await_response(request_id, REQUEST_TIMEOUT)?;
        self.send_notification("initialized", json!({}))
    }

    fn shutdown(mut self) {
        let _ = self.send_request("shutdown", json!(null));
        let _ = self.send_notification("exit", json!(null));
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_json_rpc_message(writer: &mut ChildStdin, value: &Value) -> Result<(), String> {
    let body = serde_json::to_vec(value)
        .map_err(|error| format!("Failed to encode JSON-RPC message: {}", error))?;
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    writer
        .write_all(header.as_bytes())
        .map_err(|error| format!("Failed to write JSON-RPC header: {}", error))?;
    writer
        .write_all(&body)
        .map_err(|error| format!("Failed to write JSON-RPC body: {}", error))?;
    writer
        .flush()
        .map_err(|error| format!("Failed to flush JSON-RPC body: {}", error))
}

fn read_json_rpc_message(reader: &mut impl BufRead) -> Result<Option<Value>, String> {
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        let bytes_read = reader
            .read_line(&mut line)
            .map_err(|error| format!("Failed to read JSON-RPC header: {}", error))?;
        if bytes_read == 0 {
            return Ok(None);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let lower = trimmed.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            content_length = value.trim().parse::<usize>().ok();
        }
    }

    let length = content_length
        .ok_or_else(|| "JSON-RPC message did not include Content-Length.".to_string())?;
    let mut body = vec![0u8; length];
    reader
        .read_exact(&mut body)
        .map_err(|error| format!("Failed to read JSON-RPC body: {}", error))?;
    serde_json::from_slice::<Value>(&body)
        .map(Some)
        .map_err(|error| format!("Failed to parse JSON-RPC body: {}", error))
}

fn read_document_text(absolute_path: &Path, content: Option<String>) -> Result<String, String> {
    match content {
        Some(content) => Ok(content),
        None => fs::read_to_string(absolute_path)
            .map_err(|error| format!("Failed to read '{}': {}", absolute_path.display(), error)),
    }
}

fn lsp_session_snapshot_inner(
    workspace_root: &Path,
    relative_path: &str,
    content: Option<String>,
) -> Result<WorkspaceLspSnapshot, String> {
    let absolute_path = relative_to_absolute(workspace_root, relative_path);
    let Some(server) = discover_server_for_path(workspace_root, &absolute_path) else {
        return Ok(unavailable_snapshot(
            workspace_root,
            relative_path,
            Some(
                "No managed language server is currently configured for this file type."
                    .to_string(),
            ),
        ));
    };
    let document_text = read_document_text(&absolute_path, content)?;
    let document_uri = path_to_uri(&absolute_path)?;
    let mut client = LspProcessClient::spawn(&server)?;
    if let Err(error) = client.initialize(workspace_root, &server) {
        client.shutdown();
        return Ok(error_snapshot(
            workspace_root,
            relative_path,
            &server.language_id,
            Some(server.label.clone()),
            error,
        ));
    }
    if let Err(error) = client.send_notification(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": document_uri.as_str(),
                "languageId": server.language_id.as_str(),
                "version": 1,
                "text": document_text,
            }
        }),
    ) {
        client.shutdown();
        return Ok(error_snapshot(
            workspace_root,
            relative_path,
            &server.language_id,
            Some(server.label.clone()),
            error,
        ));
    }

    let symbol_request = client.send_request(
        "textDocument/documentSymbol",
        json!({
            "textDocument": { "uri": document_uri.as_str() }
        }),
    )?;
    let symbol_result = match client.await_response(symbol_request, REQUEST_TIMEOUT) {
        Ok(value) => value,
        Err(error) => {
            client.shutdown();
            return Ok(error_snapshot(
                workspace_root,
                relative_path,
                &server.language_id,
                Some(server.label.clone()),
                error,
            ));
        }
    };
    let _ = client.drain_messages(DIAGNOSTIC_GRACE_PERIOD);

    let symbols = parse_document_symbols(workspace_root, relative_path, symbol_result);
    let diagnostics = client
        .diagnostics_by_uri
        .remove(&document_uri)
        .unwrap_or_default()
        .into_iter()
        .map(|diagnostic| to_workspace_diagnostic(relative_path, diagnostic))
        .collect();
    client.shutdown();

    Ok(WorkspaceLspSnapshot {
        generated_at_ms: generated_at_ms(),
        workspace_root: workspace_root.display().to_string(),
        path: relative_path.to_string(),
        language_id: server.language_id,
        availability: "ready".to_string(),
        status_label: "Ready".to_string(),
        service_label: service_label_for_path(&absolute_path),
        server_label: Some(server.label),
        detail: None,
        diagnostics,
        symbols,
    })
}

fn parse_document_symbols(
    workspace_root: &Path,
    relative_path: &str,
    value: Value,
) -> Vec<WorkspaceLspSymbol> {
    if value.is_null() {
        return Vec::new();
    }

    if let Ok(symbols) = serde_json::from_value::<Vec<LspDocumentSymbolPayload>>(value.clone()) {
        return symbols
            .into_iter()
            .map(|symbol| to_workspace_symbol(relative_path, symbol))
            .collect();
    }

    serde_json::from_value::<Vec<LspSymbolInformationPayload>>(value)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|symbol| to_workspace_symbol_from_information(workspace_root, symbol))
        .collect()
}

fn lsp_locations_inner(
    workspace_root: &Path,
    relative_path: &str,
    content: Option<String>,
    method: &str,
    params: Value,
) -> Result<Vec<WorkspaceLspLocation>, String> {
    let absolute_path = relative_to_absolute(workspace_root, relative_path);
    let Some(server) = discover_server_for_path(workspace_root, &absolute_path) else {
        return Ok(Vec::new());
    };
    let document_text = read_document_text(&absolute_path, content)?;
    let document_uri = path_to_uri(&absolute_path)?;
    let mut client = LspProcessClient::spawn(&server)?;
    client.initialize(workspace_root, &server)?;
    client.send_notification(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": document_uri.as_str(),
                "languageId": server.language_id.as_str(),
                "version": 1,
                "text": document_text,
            }
        }),
    )?;
    let request_id = client.send_request(method, params)?;
    let result = client.await_response(request_id, REQUEST_TIMEOUT)?;
    client.shutdown();
    Ok(parse_location_result(workspace_root, result))
}

fn parse_location_result(workspace_root: &Path, value: Value) -> Vec<WorkspaceLspLocation> {
    if value.is_null() {
        return Vec::new();
    }

    if let Ok(location) = serde_json::from_value::<LspLocationPayload>(value.clone()) {
        return to_workspace_location(workspace_root, &location.uri, &location.range)
            .into_iter()
            .collect();
    }

    if let Ok(locations) = serde_json::from_value::<Vec<LspLocationPayload>>(value.clone()) {
        return locations
            .into_iter()
            .filter_map(|location| {
                to_workspace_location(workspace_root, &location.uri, &location.range)
            })
            .collect();
    }

    serde_json::from_value::<Vec<LspLocationLinkPayload>>(value)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|location| {
            to_workspace_location(
                workspace_root,
                &location.target_uri,
                &location.target_selection_range,
            )
        })
        .collect()
}

pub fn snapshot_workspace_file(
    workspace_root: &Path,
    relative_path: &str,
    content: Option<String>,
) -> Result<WorkspaceLspSnapshot, String> {
    lsp_session_snapshot_inner(workspace_root, relative_path, content)
}

pub fn definition_locations_for_workspace_file(
    workspace_root: &Path,
    relative_path: &str,
    line: u32,
    column: u32,
    content: Option<String>,
) -> Result<Vec<WorkspaceLspLocation>, String> {
    let absolute_path = relative_to_absolute(workspace_root, relative_path);
    let uri = path_to_uri(&absolute_path)?;
    lsp_locations_inner(
        workspace_root,
        relative_path,
        content,
        "textDocument/definition",
        json!({
            "textDocument": { "uri": uri },
            "position": {
                "line": line.saturating_sub(1),
                "character": column.saturating_sub(1),
            }
        }),
    )
}

pub fn reference_locations_for_workspace_file(
    workspace_root: &Path,
    relative_path: &str,
    line: u32,
    column: u32,
    content: Option<String>,
) -> Result<Vec<WorkspaceLspLocation>, String> {
    let absolute_path = relative_to_absolute(workspace_root, relative_path);
    let uri = path_to_uri(&absolute_path)?;
    lsp_locations_inner(
        workspace_root,
        relative_path,
        content,
        "textDocument/references",
        json!({
            "textDocument": { "uri": uri },
            "position": {
                "line": line.saturating_sub(1),
                "character": column.saturating_sub(1),
            },
            "context": {
                "includeDeclaration": true,
            }
        }),
    )
}

pub fn code_actions_for_workspace_file(
    workspace_root: &Path,
    relative_path: &str,
    line: u32,
    column: u32,
    end_line: u32,
    end_column: u32,
    content: Option<String>,
) -> Result<Vec<WorkspaceLspCodeAction>, String> {
    let absolute_path = relative_to_absolute(workspace_root, relative_path);
    let Some(server) = discover_server_for_path(workspace_root, &absolute_path) else {
        return Ok(Vec::new());
    };
    let document_text = read_document_text(&absolute_path, content)?;
    let document_uri = path_to_uri(&absolute_path)?;
    let mut client = LspProcessClient::spawn(&server)?;
    client.initialize(workspace_root, &server)?;
    client.send_notification(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": document_uri.as_str(),
                "languageId": server.language_id.as_str(),
                "version": 1,
                "text": document_text,
            }
        }),
    )?;
    let _ = client.drain_messages(DIAGNOSTIC_GRACE_PERIOD);
    let diagnostics = client
        .diagnostics_by_uri
        .get(&document_uri)
        .cloned()
        .unwrap_or_default();
    let request_id = client.send_request(
        "textDocument/codeAction",
        json!({
            "textDocument": { "uri": document_uri.as_str() },
            "range": {
                "start": {
                    "line": line.saturating_sub(1),
                    "character": column.saturating_sub(1),
                },
                "end": {
                    "line": end_line.saturating_sub(1),
                    "character": end_column.saturating_sub(1),
                }
            },
            "context": {
                "diagnostics": diagnostics,
            }
        }),
    )?;
    let result = client.await_response(request_id, REQUEST_TIMEOUT)?;
    client.shutdown();
    Ok(parse_code_action_result(workspace_root, result))
}

#[cfg(test)]
#[path = "lsp/tests.rs"]
mod tests;
