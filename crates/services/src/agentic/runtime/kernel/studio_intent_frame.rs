use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const STUDIO_INTENT_FRAME_SCHEMA_VERSION: &str = "ioi.studio.intent-frame.v1";
pub const STUDIO_INTENT_FRAME_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.studio.intent-frame-projection-request.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct StudioIntentFrameProjectionRequest {
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub input: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub execution_mode: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StudioIntentFrameProjectionError {
    code: &'static str,
    message: String,
}

impl StudioIntentFrameProjectionError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, Default)]
pub struct StudioIntentFrameProjectionCore;

#[derive(Debug, Clone)]
pub struct StudioIntentFrameProjectionRecord {
    pub object: String,
    pub status: String,
    pub operation: String,
    pub operation_kind: String,
    pub frame: Value,
    pub record_count: usize,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
}

impl StudioIntentFrameProjectionCore {
    pub fn project(
        &self,
        request: StudioIntentFrameProjectionRequest,
    ) -> Result<StudioIntentFrameProjectionRecord, StudioIntentFrameProjectionError> {
        let operation = request
            .operation
            .clone()
            .unwrap_or_else(|| "studio_intent_frame_projection".to_string());
        let operation_kind = request
            .operation_kind
            .clone()
            .unwrap_or_else(|| "studio.intent_frame.projection".to_string());
        if operation_kind != "studio.intent_frame.projection" {
            return Err(StudioIntentFrameProjectionError::new(
                "studio_intent_frame_projection_operation_kind_invalid",
                format!("unsupported studio intent frame operation kind {operation_kind}"),
            ));
        }

        let prompt = compact_text(
            request
                .prompt
                .as_deref()
                .or(request.input.as_deref())
                .or(request.query.as_deref())
                .unwrap_or_default(),
        );
        let execution_mode =
            if lower_text(request.execution_mode.as_deref().unwrap_or("agent")) == "ask" {
                "ask"
            } else {
                "agent"
            };
        let runtime_action = if execution_mode == "agent" {
            local_runtime_action_for_prompt(&prompt)
        } else {
            None
        };
        let artifact_class = if runtime_action.is_some() {
            None
        } else {
            artifact_class_for_prompt(&prompt)
        };
        let artifact_required = artifact_class
            .as_deref()
            .map(is_artifact_class)
            .unwrap_or(false);
        let retrieval_requirements = if runtime_action.is_some() {
            vec![]
        } else {
            retrieval_requirements_for_prompt(&prompt, artifact_class.as_deref(), execution_mode)
        };
        let retrieval_required = !retrieval_requirements.is_empty();
        let workspace_requirements = if runtime_action.is_some() {
            vec![]
        } else {
            workspace_requirements_for_prompt(&prompt, execution_mode)
        };
        let workspace_required = !workspace_requirements.is_empty();
        let workspace_targets = if workspace_required {
            workspace_targets_for_prompt(&prompt)
        } else {
            vec![]
        };
        let runtime_inspect =
            !artifact_required && regex_is_match(RUNTIME_INSPECTION_PATTERN, &prompt);

        let mut matched_features = vec![];
        if runtime_action.is_some() {
            matched_features.push("local_runtime_action");
        }
        if artifact_required {
            matched_features.push("artifact_deliverable");
        }
        if retrieval_required {
            matched_features.push("retrieval_required");
        }
        if workspace_required {
            matched_features.push("workspace_context_required");
        }
        if runtime_inspect {
            matched_features.push("runtime_inspection");
        }
        if regex_is_match(INTERNAL_PROBE_PATTERN, &prompt) {
            matched_features.push("internal_probe");
        }

        let route_directive = if execution_mode == "ask" {
            "ask"
        } else if runtime_action.is_some() {
            "runtime_action"
        } else if artifact_required {
            "artifact"
        } else if runtime_inspect {
            "runtime_cockpit"
        } else {
            "agent"
        };
        let intent_id = if runtime_action.is_some() {
            "command.exec"
        } else if artifact_required {
            "artifact.create"
        } else if runtime_inspect {
            "runtime.inspect"
        } else if retrieval_required {
            "retrieval.answer"
        } else if workspace_required {
            "workspace.context"
        } else {
            "conversation.reply"
        };
        let confidence = if runtime_action.is_some()
            || artifact_required
            || runtime_inspect
            || retrieval_required
            || workspace_required
        {
            0.92
        } else {
            0.56
        };
        let runtime_action_value = runtime_action.unwrap_or(Value::Null);
        let artifact = artifact_for(artifact_class.as_deref(), artifact_required, &prompt);
        let required_capabilities = required_capabilities(
            runtime_action_value.is_object(),
            artifact_required,
            retrieval_required,
            workspace_required,
            runtime_inspect,
        );
        let effect_contract = effect_contract_for(
            runtime_action_value.is_object(),
            artifact_required,
            artifact_class.as_deref(),
            retrieval_required,
            workspace_required,
            route_directive,
        );
        let prompt_hash = prompt_hash(&prompt);
        let prompt_preview = prompt.chars().take(120).collect::<String>();
        let frame = json!({
            "schemaVersion": STUDIO_INTENT_FRAME_SCHEMA_VERSION,
            "schema_version": STUDIO_INTENT_FRAME_SCHEMA_VERSION,
            "object": "ioi.studio_intent_frame",
            "target": prompt,
            "query": if retrieval_required { Value::String(prompt.clone()) } else { Value::Null },
            "intentId": intent_id,
            "intent_id": intent_id,
            "routeDirective": route_directive,
            "route_directive": route_directive,
            "executionMode": execution_mode,
            "execution_mode": execution_mode,
            "confidence": confidence,
            "decision": if prompt.is_empty() { "abstain" } else { "selected" },
            "requiredCapabilities": required_capabilities,
            "required_capabilities": required_capabilities,
            "retrieval": {
                "required": retrieval_required,
                "requirements": retrieval_requirements,
            },
            "workspace": {
                "required": workspace_required,
                "requirements": workspace_requirements,
                "targets": workspace_targets,
            },
            "artifact": artifact,
            "runtimeAction": runtime_action_value,
            "runtime_action": runtime_action_value,
            "effectContract": effect_contract,
            "effect_contract": effect_contract,
            "decisionMaterial": {
                "source": "rust_studio_intent_frame_projection",
                "matchedFeatures": matched_features,
                "promptHash": prompt_hash,
                "promptPreview": prompt_preview,
            },
            "decision_material": {
                "source": "rust_studio_intent_frame_projection",
                "matched_features": matched_features,
                "prompt_hash": prompt_hash,
                "prompt_preview": prompt_preview,
            },
        });

        Ok(StudioIntentFrameProjectionRecord {
            object: "ioi.studio_intent_frame_projection".to_string(),
            status: "projected".to_string(),
            operation,
            operation_kind,
            frame,
            record_count: 1,
            evidence_refs: vec!["rust_daemon_core_studio_intent_frame_projection".to_string()],
            receipt_refs: vec!["receipt_studio_intent_frame_projection".to_string()],
        })
    }
}

impl StudioIntentFrameProjectionRecord {
    pub fn to_json(&self) -> Value {
        json!({
            "source": "rust_studio_intent_frame_projection_api",
            "backend": "rust_policy",
            "object": self.object,
            "status": self.status,
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "frame": self.frame,
            "record_count": self.record_count,
            "evidence_refs": self.evidence_refs,
            "receipt_refs": self.receipt_refs,
        })
    }
}

const CREATION_VERB_PATTERN: &str =
    r"(?i)\b(create|build|make|generate|draft|design|prototype|turn|convert|render|show|prepare)\b";
const WEB_DELIVERABLE_PATTERN: &str = r"(?i)\b(website|web\s*site|webpage|web\s*page|landing\s+page|microsite|static\s+site|standalone\s+site)\b";
const RUNTIME_INSPECTION_PATTERN: &str = r"(?i)\b(runtime cockpit|tool proposal|policy lease|sandbox(?:ed)? command|inline diff|hunk|diagnostics?|test gate|browser status|worker status|subagent|receipt timeline|replay)\b";
const INTERNAL_PROBE_PATTERN: &str = r"(?i)\bTOOLCAT_(?:SINGLE_TOOL|STAGE[0-9]+_[A-Z0-9_]+)\b|workspace_fixture_|daemon_endpoint=|computer_use_providers_url=|live IDE Rust/provider tool row";
const INLINE_COMMAND_REQUEST_PATTERN: &str =
    r"(?is)\b(run|execute|start|launch)\b[\s\S]{0,80}`([^`]+)`";
const RETAINED_SHELL_LIFECYCLE_PATTERN: &str = r"(?is)\b(retained|persistent|long[- ]running|background)\b[\s\S]{0,160}\b(shell|command|process|helper|session)\b";
const RETAINED_SHELL_CONTROL_PATTERN: &str =
    r"(?i)\b(stdin|status|send(?:\s+the)?\s+input|terminate|reset)\b";

fn regex_is_match(pattern: &str, text: &str) -> bool {
    Regex::new(pattern)
        .map(|regex| regex.is_match(text))
        .unwrap_or(false)
}

fn regex_capture(pattern: &str, text: &str, index: usize) -> Option<String> {
    Regex::new(pattern)
        .ok()
        .and_then(|regex| regex.captures(text))
        .and_then(|captures| {
            captures
                .get(index)
                .map(|value| compact_text(value.as_str()))
        })
}

fn compact_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn lower_text(value: &str) -> String {
    compact_text(value).to_lowercase()
}

fn shell_command_literal(prompt: &str) -> String {
    regex_capture(INLINE_COMMAND_REQUEST_PATTERN, prompt, 2).unwrap_or_default()
}

fn prompt_requests_retained_shell_lifecycle(prompt: &str) -> bool {
    regex_is_match(RETAINED_SHELL_LIFECYCLE_PATTERN, prompt)
        && regex_is_match(RETAINED_SHELL_CONTROL_PATTERN, prompt)
}

fn shell_command_literal_looks_executable(command: &str) -> bool {
    let value = compact_text(command);
    if value.is_empty() {
        return false;
    }
    let mut parts = value.split_whitespace();
    let first_token = parts.next().unwrap_or_default();
    let has_arguments = parts.next().is_some();
    let has_shell_operator = regex_is_match(r"(?:&&|\|\||[;|<>])", &value);
    let path_like = regex_is_match(r"^(?:\.{0,2}/|~/|[A-Za-z]:\\|/)", first_token);
    has_arguments || has_shell_operator || path_like
}

fn local_runtime_action_for_prompt(prompt: &str) -> Option<Value> {
    if prompt_requests_retained_shell_lifecycle(prompt) {
        return None;
    }
    let command = shell_command_literal(prompt);
    if !shell_command_literal_looks_executable(&command) {
        return None;
    }
    Some(json!({
        "required": true,
        "intentClass": "local_runtime_action",
        "intent_class": "local_runtime_action",
        "actionFamily": "shell",
        "action_family": "shell",
        "targetKind": "shell_command",
        "target_kind": "shell_command",
        "targetCommand": command,
        "target_command": command,
        "hostMutation": true,
        "host_mutation": true,
    }))
}

fn title_case_first(value: &str) -> String {
    let cleaned = compact_text(value);
    let mut chars = cleaned.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

fn prompt_topic_for_web_artifact(prompt: &str) -> String {
    let text = compact_text(prompt);
    let mut topic = regex_capture(
        r#"(?i)\b(?:explains?|about|for|on)\s+([^.!?\n]{3,90})"#,
        &text,
        1,
    )
    .unwrap_or_default();
    topic = Regex::new(r"(?i)\b(?:as|with|using|and)\b.*$")
        .unwrap()
        .replace(&topic, "")
        .to_string();
    topic
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .to_string()
}

fn artifact_class_for_prompt(prompt: &str) -> Option<String> {
    let text = lower_text(prompt);
    let creation_like = regex_is_match(CREATION_VERB_PATTERN, &text);
    let browser_observation_artifact = regex_is_match(
        r"(?is)\b(capture|save|export|promote|turn|convert|render)\b[\s\S]{0,100}\b(browser|computer)\b[\s\S]{0,100}\b(artifact|capture|observation|result)\b",
        &text,
    ) || regex_is_match(
        r"(?is)\b(browser|computer)\s+session\s+result\b[\s\S]{0,80}\bas\s+an?\s+artifact\b",
        &text,
    );
    if regex_is_match(
        r"(?i)\b(odt|docx|document artifact|editable projection|word document|open document)\b",
        &text,
    ) {
        return Some("imported_document".to_string());
    }
    if regex_is_match(r"(?i)\b(pdf|read-only document|readonly document)\b", &text) {
        return Some("pdf_preview".to_string());
    }
    if regex_is_match(
        r"(?i)\b(react|vite|mini app|generated app|app preview)\b",
        &text,
    ) {
        return Some("react_vite_app".to_string());
    }
    if creation_like && regex_is_match(WEB_DELIVERABLE_PATTERN, &text) {
        return Some("static_html_js".to_string());
    }
    if regex_is_match(
        r"(?i)\b(standalone html|html/css/js|static html|html css js)\b",
        &text,
    ) {
        return Some("static_html_js".to_string());
    }
    if regex_is_match(r"(?i)\b(diff|patch|reviewable patch)\b", &text) {
        return Some("diff_patch".to_string());
    }
    if regex_is_match(r"(?i)\b(csv|dataset|chart|table)\b", &text) {
        return Some("dataset_chart".to_string());
    }
    if browser_observation_artifact
        || regex_is_match(r"(?i)\b(observation artifact|browser capture)\b", &text)
    {
        return Some("browser_observation".to_string());
    }
    if regex_is_match(r"(?i)\b(markdown report|html report|memo)\b", &text)
        || (creation_like && regex_is_match(r"(?i)\breport\b", &text))
    {
        return Some("markdown_html_report".to_string());
    }
    if regex_is_match(
        r"(?i)\bartifact|embedded document|document embed|artifact canvas|document canvas|embedded document canvas\b",
        &text,
    ) {
        return Some("markdown_html_report".to_string());
    }
    None
}

fn is_artifact_class(value: &str) -> bool {
    matches!(
        value,
        "markdown_html_report"
            | "static_html_js"
            | "react_vite_app"
            | "imported_document"
            | "pdf_preview"
            | "diff_patch"
            | "dataset_chart"
            | "browser_observation"
    )
}

fn artifact_title_for_prompt(class_id: &str, prompt: &str) -> String {
    match class_id {
        "imported_document" => "Document artifact".to_string(),
        "pdf_preview" => "Read-only PDF artifact".to_string(),
        "react_vite_app" => "Generated app artifact".to_string(),
        "static_html_js" => {
            let topic = title_case_first(&prompt_topic_for_web_artifact(prompt));
            if topic.is_empty() {
                "Generated website".to_string()
            } else {
                format!("{topic} website")
            }
        }
        "diff_patch" => "Reviewable patch".to_string(),
        "dataset_chart" => "Dataset artifact".to_string(),
        "browser_observation" => "Browser session capture".to_string(),
        _ => "Generated report artifact".to_string(),
    }
}

fn prompt_targets_local_workspace(prompt: &str) -> bool {
    let text = lower_text(prompt);
    regex_is_match(
        r"(?i)\b(repository|repo|workspace|project|codebase|source tree|current workspace|local source|inspect\b.*workspace|files?)\b",
        &text,
    ) || regex_is_match(
        r#"(?i)(?:^|\s|["'`])(?:\./|\.\./|/)?(?:\.internal|apps|crates|docs|examples|ide|packages|scripts|src|tests?)/"#,
        &text,
    ) || text.contains("workspace_fixture_")
        || text.contains("daemon_endpoint=")
        || text.contains("computer_use_providers_url=")
        || text.contains("current trace history")
}

fn workspace_targets_for_prompt(prompt: &str) -> Vec<Value> {
    let raw = compact_text(prompt);
    let path_regex = Regex::new(
        r#"(?i)(?:^|\s|["'`])((?:\./|\.\./|/)?(?:\.internal|apps|crates|docs|examples|ide|packages|scripts|src|tests?)/[^\s"'`),;:]+)"#,
    )
    .unwrap();
    let mut targets = vec![];
    for captures in path_regex.captures_iter(&raw) {
        let path = captures
            .get(1)
            .map(|value| {
                compact_text(value.as_str())
                    .trim_end_matches(['.', '!', '?'])
                    .to_string()
            })
            .unwrap_or_default();
        if !path.is_empty()
            && !targets
                .iter()
                .any(|target: &Value| target["kind"] == "path" && target["path"] == path)
        {
            targets.push(json!({
                "kind": "path",
                "path": path,
                "reason": "explicit_workspace_path",
            }));
        }
    }
    if !targets.is_empty() {
        return targets;
    }

    let stop_words = [
        "about",
        "and",
        "are",
        "between",
        "codebase",
        "does",
        "explain",
        "find",
        "first",
        "from",
        "how",
        "inspect",
        "into",
        "look",
        "or",
        "per",
        "project",
        "read",
        "repo",
        "repository",
        "search",
        "should",
        "summarize",
        "the",
        "this",
        "what",
        "where",
        "which",
        "workspace",
    ];
    let normalized = Regex::new(r"[^a-z0-9_-]+")
        .unwrap()
        .replace_all(&raw.to_lowercase(), " ")
        .to_string();
    let mut seen_terms = vec![];
    for term in normalized.split_whitespace() {
        let trimmed = term.trim_matches(|c| c == '-' || c == '.' || c == '/' || c == '_');
        if trimmed.len() < 3
            || stop_words.contains(&trimmed)
            || seen_terms.iter().any(|existing| existing == trimmed)
        {
            continue;
        }
        seen_terms.push(trimmed.to_string());
        if seen_terms.len() >= 8 {
            break;
        }
    }
    let query = if seen_terms.is_empty() {
        raw.chars().take(120).collect::<String>()
    } else {
        seen_terms.join(" ")
    };
    if query.is_empty() {
        vec![]
    } else {
        vec![json!({
            "kind": "search",
            "query": query,
            "reason": "workspace_context_query",
        })]
    }
}

fn workspace_requirements_for_prompt(prompt: &str, execution_mode: &str) -> Vec<String> {
    if regex_is_match(INTERNAL_PROBE_PATTERN, prompt) || lower_text(execution_mode) != "agent" {
        return vec![];
    }
    let text = lower_text(prompt);
    if !prompt_targets_local_workspace(&text) {
        return vec![];
    }
    let asks_for_workspace_context = regex_is_match(
        r"(?i)\b(audit|check|decides?|explain|explore|find|how|inspect|list|locate|look like|progress|read|review|scan|search|summari[sz]e|where|which|what)\b",
        &text,
    ) || regex_is_match(
        r#"(?i)(?:^|\s|["'`])(?:\./|\.\./|/)?(?:\.internal|apps|crates|docs|examples|ide|packages|scripts|src|tests?)/"#,
        &text,
    );
    if asks_for_workspace_context {
        vec!["workspace_context".to_string()]
    } else {
        vec![]
    }
}

fn retrieval_requirements_for_prompt(
    prompt: &str,
    artifact_class: Option<&str>,
    execution_mode: &str,
) -> Vec<String> {
    if regex_is_match(INTERNAL_PROBE_PATTERN, prompt) {
        return vec![];
    }
    let text = lower_text(prompt);
    let targets_local_workspace = prompt_targets_local_workspace(&text);
    let asks_for_external_fact = regex_is_match(
        r"(?i)\b(today|right now|latest|recent|news|price|market|market cap|investment|invest|better|akt|akash|filecoin|fil|crypto|stock|exchange rate|weather)\b",
        &text,
    );
    let asks_for_public_source = regex_is_match(
        r"(?i)\b(cite|citation|sources?|web|internet|online|public)\b",
        &text,
    );
    let asks_for_current_external_state = regex_is_match(r"(?i)\b(current|currently)\b", &text)
        && regex_is_match(
            r"(?i)\b(price|market|news|investment|crypto|stock|exchange rate|weather|public|web|online)\b",
            &text,
        );
    let source_grounded_artifact_class = matches!(
        artifact_class,
        Some("static_html_js") | Some("markdown_html_report") | Some("react_vite_app")
    );
    let asks_for_factual_artifact = execution_mode == "agent"
        && source_grounded_artifact_class
        && !targets_local_workspace
        && regex_is_match(
            r"(?i)\b(explains?|guide|educational|overview|report|briefing|compare|versus|vs\.?|what is|how does|how do|history|timeline)\b",
            &text,
        );
    if targets_local_workspace && !asks_for_external_fact && !asks_for_current_external_state {
        return vec![];
    }
    let mut requirements = vec![];
    if asks_for_external_fact || asks_for_current_external_state {
        requirements.push("current_external_state".to_string());
    }
    if asks_for_public_source || asks_for_factual_artifact {
        requirements.push("source_grounding".to_string());
    }
    requirements.sort();
    requirements.dedup();
    requirements
}

fn artifact_for(artifact_class: Option<&str>, artifact_required: bool, prompt: &str) -> Value {
    if !artifact_required {
        return json!({
            "required": false,
            "class": Value::Null,
            "artifactClass": Value::Null,
            "outputModality": Value::Null,
            "title": Value::Null,
            "summary": Value::Null,
        });
    }
    let class_id = artifact_class.unwrap_or("markdown_html_report");
    json!({
        "required": true,
        "class": class_id,
        "artifactClass": class_id,
        "outputModality": if class_id == "static_html_js" {
            "website".to_string()
        } else {
            class_id.replace('_', "-")
        },
        "title": artifact_title_for_prompt(class_id, prompt),
        "summary": if class_id == "static_html_js" {
            "Sandboxed website preview generated through the daemon-owned artifact lifecycle."
        } else {
            "Hypervisor Workbench conversation artifact created through the daemon-owned artifact lifecycle."
        },
    })
}

fn required_capabilities(
    runtime_action: bool,
    artifact_required: bool,
    retrieval_required: bool,
    workspace_required: bool,
    runtime_inspect: bool,
) -> Vec<String> {
    let mut capabilities = vec!["prim:conversation.reply".to_string()];
    if runtime_action {
        capabilities.push("prim:shell.run".to_string());
        capabilities.push("command.exec".to_string());
    }
    if artifact_required {
        capabilities.push("prim:artifact.write".to_string());
        capabilities.push("prim:artifact.render".to_string());
    }
    if retrieval_required {
        capabilities.push("prim:web.search".to_string());
        capabilities.push("prim:web.read".to_string());
    }
    if workspace_required {
        capabilities.push("prim:file.search".to_string());
        capabilities.push("prim:file.read".to_string());
        capabilities.push("prim:workspace.read".to_string());
    }
    if runtime_inspect {
        capabilities.push("prim:runtime.trace.read".to_string());
    }
    capabilities
}

fn effect_contract_for(
    runtime_action: bool,
    artifact_required: bool,
    artifact_class: Option<&str>,
    retrieval_required: bool,
    workspace_required: bool,
    route_directive: &str,
) -> Value {
    if runtime_action {
        return json!({
            "applicabilityClass": "local_runtime_action",
            "effectLevel": "command_execution",
            "sandbox": "workspace_command_policy",
            "typedActionsOnly": true,
            "receiptsRequired": ["shell_run", "chat_reply"],
        });
    }
    if artifact_required {
        let diff_patch = artifact_class == Some("diff_patch");
        let mut receipts = vec![];
        if retrieval_required {
            receipts.push("retrieval_search");
            receipts.push("retrieval_read");
        }
        receipts.extend(["artifact_record", "artifact_revision", "artifact_policy"]);
        return json!({
            "applicabilityClass": "local_artifact_generation",
            "effectLevel": if diff_patch { "approval_gated_mutation" } else { "sandboxed_generation" },
            "sandbox": if diff_patch { Value::Null } else { Value::String("artifact_renderer".to_string()) },
            "typedActionsOnly": true,
            "receiptsRequired": receipts,
        });
    }
    if retrieval_required {
        return json!({
            "applicabilityClass": "remote_retrieval",
            "effectLevel": "read_only_external",
            "sandbox": Value::Null,
            "typedActionsOnly": false,
            "receiptsRequired": ["retrieval_search", "retrieval_read", "chat_reply"],
        });
    }
    if workspace_required {
        return json!({
            "applicabilityClass": "workspace_context",
            "effectLevel": "read_only_workspace",
            "sandbox": "workspace_readonly",
            "typedActionsOnly": false,
            "receiptsRequired": ["file_search", "file_read", "chat_reply"],
        });
    }
    if route_directive == "runtime_cockpit" {
        return json!({
            "applicabilityClass": "runtime_inspection",
            "effectLevel": "read_only_runtime",
            "sandbox": Value::Null,
            "typedActionsOnly": false,
            "receiptsRequired": ["runtime_trace"],
        });
    }
    json!({
        "applicabilityClass": "conversation",
        "effectLevel": "none",
        "sandbox": Value::Null,
        "typedActionsOnly": false,
        "receiptsRequired": ["chat_reply"],
    })
}

fn prompt_hash(prompt: &str) -> String {
    let digest = Sha256::digest(prompt.as_bytes());
    format!("{digest:x}").chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(prompt: &str) -> Value {
        StudioIntentFrameProjectionCore::default()
            .project(StudioIntentFrameProjectionRequest {
                prompt: Some(prompt.to_string()),
                execution_mode: Some("agent".to_string()),
                ..StudioIntentFrameProjectionRequest::default()
            })
            .unwrap()
            .frame
    }

    #[test]
    fn rust_routes_studio_intent_frames_to_artifact_retrieval_workspace_and_runtime() {
        let website = frame("Create a website that explains post-quantum computers");
        assert_eq!(website["intentId"], "artifact.create");
        assert_eq!(website["routeDirective"], "artifact");
        assert_eq!(website["artifact"]["class"], "static_html_js");
        assert_eq!(
            website["artifact"]["title"],
            "Post-quantum computers website"
        );
        assert_eq!(website["retrieval"]["required"], true);
        assert!(website["requiredCapabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("prim:web.search")));
        assert_eq!(website["effectContract"]["sandbox"], "artifact_renderer");

        let app = frame(
            "Build a small React dashboard artifact from this CSV, then make the sidebar denser.",
        );
        assert_eq!(app["artifact"]["class"], "react_vite_app");

        let document = frame("Turn this ODT into an artifact, tighten the intro, compare changes, and export a clean copy.");
        assert_eq!(document["artifact"]["class"], "imported_document");
        assert_eq!(document["retrieval"]["required"], false);

        let current = frame("Which is a better investment right now, Akash or Filecoin?");
        assert_eq!(current["intentId"], "retrieval.answer");
        assert_eq!(
            current["retrieval"]["requirements"][0],
            "current_external_state"
        );

        let workspace = frame("Where are local/native model providers registered in this repo?");
        assert_eq!(workspace["intentId"], "workspace.context");
        assert_eq!(
            workspace["workspace"]["targets"][0]["query"],
            "local native model providers registered"
        );
        assert_eq!(
            workspace["effectContract"]["effectLevel"],
            "read_only_workspace"
        );

        let path =
            frame("What does progress look like per .internal/plans/example-master-guide.md?");
        assert_eq!(path["workspace"]["targets"][0]["kind"], "path");
        assert_eq!(
            path["workspace"]["targets"][0]["path"],
            ".internal/plans/example-master-guide.md"
        );

        let runtime = frame("Show runtime cockpit policy lease and worker status for this run.");
        assert_eq!(runtime["intentId"], "runtime.inspect");
        assert_eq!(runtime["routeDirective"], "runtime_cockpit");
    }

    #[test]
    fn rust_routes_local_runtime_action_without_retained_shell_collapse() {
        let command = frame("Run `node --check scripts/lib/hypervisor-session-workbench-scenarios.mjs` and summarize the exit code.");
        assert_eq!(command["intentId"], "command.exec");
        assert_eq!(command["routeDirective"], "runtime_action");
        assert_eq!(
            command["runtimeAction"]["targetCommand"],
            "node --check scripts/lib/hypervisor-session-workbench-scenarios.mjs"
        );
        assert_eq!(command["workspace"]["required"], false);
        assert_eq!(command["retrieval"]["required"], false);

        let retained = frame(&[
            "Start a disposable retained Node.js helper that waits for stdin and echoes a status line.",
            "Check the helper status, send the input `compile-once`, terminate the helper, reset retained shell state, and then answer.",
        ].join(" "));
        assert_ne!(retained["intentId"], "command.exec");
        assert_eq!(retained["runtimeAction"], Value::Null);

        let symbol = frame("Explain how `formatOrderTotal` is used in this repo.");
        assert_ne!(symbol["intentId"], "command.exec");
        assert_eq!(symbol["runtimeAction"], Value::Null);
    }

    #[test]
    fn rust_keeps_browser_automation_governed_and_capture_as_artifact() {
        let browser = frame("Open the local browser fixture at http://127.0.0.1:45235/. Inspect the page, click the blue canvas target, and report whether the browser session stayed observable.");
        assert_eq!(browser["routeDirective"], "agent");
        assert_eq!(browser["artifact"]["required"], false);

        let capture = frame("Capture this browser session result as an artifact and let me ask a follow-up question.");
        assert_eq!(capture["intentId"], "artifact.create");
        assert_eq!(capture["artifact"]["class"], "browser_observation");
    }

    #[test]
    fn rust_studio_intent_consumes_canonical_execution_mode_only() {
        let canonical = StudioIntentFrameProjectionCore::default()
            .project(StudioIntentFrameProjectionRequest {
                prompt: Some("Can you explain the runtime policy gate?".to_string()),
                execution_mode: Some("ask".to_string()),
                ..StudioIntentFrameProjectionRequest::default()
            })
            .unwrap()
            .frame;
        assert_eq!(canonical["execution_mode"], "ask");
        assert_eq!(canonical["route_directive"], "ask");

        let retired_only = StudioIntentFrameProjectionCore::default()
            .project(StudioIntentFrameProjectionRequest {
                prompt: Some("Can you explain the runtime policy gate?".to_string()),
                ..StudioIntentFrameProjectionRequest::default()
            })
            .unwrap()
            .frame;
        assert_eq!(retired_only["execution_mode"], "agent");
        assert_eq!(retired_only["route_directive"], "agent");
    }
}
