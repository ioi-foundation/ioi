// apps/autopilot/src-tauri/src/kernel/events.rs

use crate::kernel::state::update_task_state;
use crate::kernel::{artifacts as artifact_store, thresholds};
use crate::models::{
    AgentEvent, AgentPhase, AppState, Artifact, ArtifactRef, ArtifactType, ChatMessage,
    ClarificationOption, ClarificationRequest, CredentialRequest, EventStatus, EventType, GateInfo,
    GhostInputEvent, Receipt, SwarmAgent,
};
use crate::orchestrator;
use ioi_ipc::public::chain_event::Event as ChainEventEnum;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::SubscribeEventsRequest;
use ioi_types::app::agentic::InferenceOptions;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Mutex;
use tauri::{Emitter, Manager};
use uuid::Uuid;

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

const CLARIFICATION_WAIT_STEP: &str = "Waiting for clarification on target identity.";
const LEGACY_CLARIFICATION_WAIT_STEP: &str = "Waiting for user clarification on app/package name.";
const LEGACY_INSTALL_CLARIFICATION_STEP: &str = "Waiting for install clarification";
const WAIT_FOR_CLARIFICATION_PROMPT: &str =
    "System: WAIT_FOR_CLARIFICATION. Target identity could not be resolved. Provide clarification input to continue.";

fn thread_id_from_session(app: &tauri::AppHandle, session_id: &str) -> String {
    if !session_id.is_empty() {
        return session_id.to_string();
    }
    let state = app.state::<Mutex<AppState>>();
    if let Ok(guard) = state.lock() {
        if let Some(task) = &guard.current_task {
            return task.session_id.clone().unwrap_or_else(|| task.id.clone());
        }
    }
    "unknown-thread".to_string()
}

fn snippet(text: &str) -> String {
    thresholds::trim_excerpt(text, 4, 320)
}

fn collect_urls(text: &str, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for token in text.split_whitespace() {
        let normalized = token
            .trim_matches(|c: char| ",.;:()[]{}<>\"'`".contains(c))
            .to_string();
        if normalized.starts_with("http://") || normalized.starts_with("https://") {
            if !out.iter().any(|u| u == &normalized) {
                out.push(normalized);
            }
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn event_status_from_agent_status(agent_status: &str) -> EventStatus {
    match agent_status {
        "Failed" => EventStatus::Failure,
        "Paused" => EventStatus::Partial,
        _ => EventStatus::Success,
    }
}

fn event_type_for_tool(tool_name: &str) -> EventType {
    let t = tool_name.to_lowercase();
    if t.contains("browser__navigate") || t.contains("browser::navigate") {
        EventType::BrowserNavigate
    } else if t.contains("browser__extract") || t.contains("browser::extract") {
        EventType::BrowserExtract
    } else if t.contains("search")
        || t.contains("grep")
        || t.contains("ripgrep")
        || t == "rg"
        || t.contains("find")
    {
        EventType::CodeSearch
    } else if t.contains("test") || t.contains("pytest") || t.contains("cargo test") {
        EventType::TestRun
    } else if t.contains("edit")
        || t.contains("patch")
        || t.contains("write")
        || t.contains("replace")
    {
        EventType::FileEdit
    } else if t.contains("read") || t.contains("cat") {
        EventType::FileRead
    } else {
        EventType::CommandRun
    }
}

fn is_install_package_tool(tool_name: &str) -> bool {
    let tool = tool_name.to_ascii_lowercase();
    tool == "sys__install_package"
        || tool == "sys::install_package"
        || tool.ends_with("install_package")
}

fn is_sudo_password_required_install(tool_name: &str, output: &str) -> bool {
    if !is_install_package_tool(tool_name) {
        return false;
    }
    let text = output.to_ascii_lowercase();
    let package_lookup_failure = text.contains("unable to locate package")
        || text.contains("no match for argument")
        || text.contains("has no installation candidate")
        || text.contains("cannot find a package");
    if package_lookup_failure {
        return false;
    }
    text.contains("sudo:")
        || text.contains("a password is required")
        || text.contains("not in the sudoers")
        || text.contains("incorrect password")
        || text.contains("sorry, try again")
        || (text.contains("error_class=permissionorapprovalrequired") && text.contains("sudo"))
}

fn is_install_package_lookup_failure(tool_name: &str, output: &str) -> bool {
    if !is_install_package_tool(tool_name) {
        return false;
    }
    let text = output.to_ascii_lowercase();
    text.contains("unable to locate package")
        || text.contains("no match for argument")
        || text.contains("has no installation candidate")
        || text.contains("cannot find a package")
        || text.contains("error_class=missingdependency")
}

fn is_launch_app_lookup_failure(tool_name: &str, output: &str) -> bool {
    let tool = tool_name.to_ascii_lowercase();
    if tool != "os__launch_app" && tool != "os::launch_app" && !tool.ends_with("launch_app") {
        return false;
    }
    let text = output.to_ascii_lowercase();
    let marker_launch_miss =
        text.contains("error_class=toolunavailable") && text.contains("failed to launch");
    let detailed_launch_miss = text.contains("failed to launch")
        && (text.contains("no such file")
            || text.contains("not found")
            || text.contains("unable to locate")
            || text.contains("cannot find")
            || text.contains("gtk-launch"));
    marker_launch_miss || detailed_launch_miss
}

#[derive(Clone, Copy)]
enum ClarificationPreset {
    IdentityLookup,
    InstallLookup,
    LaunchLookup,
}

fn clarification_preset_for_tool(tool_name: &str) -> Option<ClarificationPreset> {
    if is_install_package_tool(tool_name) {
        return Some(ClarificationPreset::InstallLookup);
    }
    let tool = tool_name.to_ascii_lowercase();
    if tool == "os__launch_app" || tool == "os::launch_app" || tool.ends_with("launch_app") {
        return Some(ClarificationPreset::LaunchLookup);
    }
    None
}

fn detect_clarification_preset(tool_name: &str, output: &str) -> Option<ClarificationPreset> {
    if is_install_package_lookup_failure(tool_name, output) {
        return Some(ClarificationPreset::InstallLookup);
    }
    if is_launch_app_lookup_failure(tool_name, output) {
        return Some(ClarificationPreset::LaunchLookup);
    }
    None
}

fn is_identity_resolution_kind(kind: &str) -> bool {
    kind.eq_ignore_ascii_case("identity_resolution")
        || kind.eq_ignore_ascii_case("tool_lookup")
        || kind.eq_ignore_ascii_case("install_package_lookup")
}

fn is_waiting_for_identity_clarification_step(step: &str) -> bool {
    step.eq_ignore_ascii_case(CLARIFICATION_WAIT_STEP)
        || step.eq_ignore_ascii_case(LEGACY_CLARIFICATION_WAIT_STEP)
        || step.eq_ignore_ascii_case(LEGACY_INSTALL_CLARIFICATION_STEP)
}

fn extract_missing_package_hint(output: &str) -> Option<String> {
    let lower = output.to_ascii_lowercase();
    let marker = "unable to locate package ";
    let idx = lower.find(marker)?;
    let token_start = idx + marker.len();
    let remainder = output.get(token_start..)?.trim();
    let raw = remainder.split_whitespace().next()?;
    let cleaned = raw
        .trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'));
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.to_string())
    }
}

fn extract_launch_target_hint(output: &str) -> Option<String> {
    let lower = output.to_ascii_lowercase();
    let marker = "failed to launch ";
    let idx = lower.find(marker)?;
    let token_start = idx + marker.len();
    let remainder = output.get(token_start..)?.trim();
    let raw = remainder
        .split('|')
        .next()
        .unwrap_or(remainder)
        .split(':')
        .next()
        .unwrap_or(remainder)
        .split_whitespace()
        .next()
        .unwrap_or(remainder)
        .trim();
    let cleaned = raw.trim_matches(|c: char| {
        !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/' || c == ':')
    });
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.to_string())
    }
}

fn build_clarification_request(
    preset: ClarificationPreset,
    tool_name: &str,
    output: &str,
) -> ClarificationRequest {
    let evidence = if output.trim().is_empty() {
        None
    } else {
        Some(snippet(output))
    };
    let (question, context_hint) = match preset {
        ClarificationPreset::IdentityLookup => {
            let question =
                "I could not resolve the target identity for this step. How should I proceed?"
                    .to_string();
            (question, None)
        }
        ClarificationPreset::InstallLookup => {
            let package_hint = extract_missing_package_hint(output);
            let question = if let Some(pkg) = package_hint.as_deref() {
                format!(
                    "I could not resolve software identity for install target '{}'. How should I proceed?",
                    pkg
                )
            } else {
                "I could not resolve software identity for this install attempt. How should I proceed?"
                    .to_string()
            };
            (question, package_hint)
        }
        ClarificationPreset::LaunchLookup => {
            let launch_hint = extract_launch_target_hint(output);
            let question = if let Some(target) = launch_hint.as_deref() {
                format!(
                    "I could not resolve launch identity for target '{}'. How should I proceed?",
                    target
                )
            } else {
                "I could not resolve which executable or desktop entry to launch. How should I proceed?"
                    .to_string()
            };
            (question, launch_hint)
        }
    };
    ClarificationRequest {
        kind: "identity_resolution".to_string(),
        question,
        tool_name: tool_name.to_string(),
        failure_class: Some("UserInterventionNeeded".to_string()),
        evidence_snippet: evidence,
        context_hint,
        options: Vec::new(),
        allow_other: true,
    }
}

fn clarification_option_ids_for_preset(preset: ClarificationPreset) -> [&'static str; 3] {
    match preset {
        ClarificationPreset::IdentityLookup => {
            ["discover_candidates", "provide_exact", "skip_retry"]
        }
        ClarificationPreset::InstallLookup => {
            ["discover_candidates", "launch_only", "provide_exact"]
        }
        ClarificationPreset::LaunchLookup => {
            ["discover_candidates", "provide_desktop_id", "provide_exact"]
        }
    }
}

fn clarification_option_semantics_for_preset(preset: ClarificationPreset) -> [&'static str; 3] {
    match preset {
        ClarificationPreset::IdentityLookup => [
            "Discover likely target identifiers from runtime evidence and retry once.",
            "Use an exact identifier provided by the user for a single retry.",
            "Stop retries and provide a blocker summary with concrete evidence.",
        ],
        ClarificationPreset::InstallLookup => [
            "Discover package candidates via package manager signals and retry once.",
            "Skip install retry and attempt direct launch path resolution instead.",
            "Use an exact package identifier supplied by the user for one retry.",
        ],
        ClarificationPreset::LaunchLookup => [
            "Discover executable/desktop-entry candidates and retry once.",
            "Use an explicit desktop entry identifier for the next launch retry.",
            "Use an exact executable name or absolute path for one retry.",
        ],
    }
}

#[derive(Debug, Deserialize)]
struct ClarificationOptionInference {
    id: String,
    label: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct ClarificationOptionsInferenceEnvelope {
    options: Vec<ClarificationOptionInference>,
}

fn sanitize_option_label(value: &str) -> Option<String> {
    let compact = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string();
    if compact.is_empty() {
        None
    } else {
        Some(compact.chars().take(48).collect::<String>())
    }
}

fn sanitize_option_description(value: &str) -> Option<String> {
    let compact = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string();
    if compact.is_empty() {
        None
    } else {
        Some(compact.chars().take(180).collect::<String>())
    }
}

fn extract_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    if end <= start {
        None
    } else {
        Some(raw[start..=end].to_string())
    }
}

fn parse_inferred_clarification_options(
    raw: &str,
) -> Option<ClarificationOptionsInferenceEnvelope> {
    serde_json::from_str::<ClarificationOptionsInferenceEnvelope>(raw)
        .ok()
        .or_else(|| {
            let trimmed = extract_json_object(raw)?;
            serde_json::from_str::<ClarificationOptionsInferenceEnvelope>(&trimmed).ok()
        })
}

async fn infer_clarification_option_text(
    app: &tauri::AppHandle,
    request: &ClarificationRequest,
    preset: ClarificationPreset,
    output: &str,
) -> Option<Vec<ClarificationOption>> {
    let runtime = {
        let state = app.state::<Mutex<AppState>>();
        let guard = state.lock().ok()?;
        guard.inference_runtime.clone()?
    };
    let option_ids = clarification_option_ids_for_preset(preset);
    let option_semantics = clarification_option_semantics_for_preset(preset);

    let option_id_order = option_ids.join(", ");
    let option_semantic_lines = option_ids
        .iter()
        .enumerate()
        .map(|(idx, id)| format!("{} => {}", id, option_semantics[idx]))
        .collect::<Vec<_>>()
        .join("\n");
    let evidence = request
        .evidence_snippet
        .clone()
        .unwrap_or_else(|| snippet(output));

    let prompt = format!(
        "You are generating clarification UX options for an agent failure.\n\
Return strict JSON only using this schema:\n\
{{\"options\":[{{\"id\":\"string\",\"label\":\"string\",\"description\":\"string\"}},{{\"id\":\"string\",\"label\":\"string\",\"description\":\"string\"}},{{\"id\":\"string\",\"label\":\"string\",\"description\":\"string\"}}]}}\n\
	Constraints:\n\
	- Use exactly 3 options.\n\
	- Use exactly these ids and preserve this order: [{option_id_order}].\n\
	- Option 1 must be the strongest recommended next action.\n\
	- Keep labels concise (2-5 words).\n\
	- Keep each description to one short sentence.\n\
	- No markdown, no extra fields, no prose outside JSON.\n\
	Context:\n\
	question={question}\n\
	tool_name={tool}\n\
	failure_class={failure_class}\n\
	context_hint={context_hint}\n\
	evidence={evidence}\n\
	Option semantics:\n\
	{semantics}",
        option_id_order = option_id_order,
        question = request.question,
        tool = request.tool_name,
        failure_class = request
            .failure_class
            .as_deref()
            .unwrap_or("UserInterventionNeeded"),
        context_hint = request.context_hint.as_deref().unwrap_or(""),
        evidence = evidence,
        semantics = option_semantic_lines
    );

    let infer_options = InferenceOptions {
        temperature: 0.2,
        json_mode: true,
        max_tokens: 320,
        ..Default::default()
    };

    let bytes = runtime
        .execute_inference([0u8; 32], prompt.as_bytes(), infer_options)
        .await
        .ok()?;
    let raw = match String::from_utf8(bytes.clone()) {
        Ok(s) => s,
        Err(_) => String::from_utf8_lossy(&bytes).to_string(),
    };
    let parsed = parse_inferred_clarification_options(&raw)?;
    if parsed.options.len() != 3 {
        return None;
    }

    let mut mapped = Vec::with_capacity(option_ids.len());
    for (idx, id) in option_ids.iter().enumerate() {
        let inferred = parsed
            .options
            .iter()
            .find(|opt| opt.id.eq_ignore_ascii_case(id))?;
        let label = sanitize_option_label(&inferred.label)?;
        let description = sanitize_option_description(&inferred.description)?;
        mapped.push(ClarificationOption {
            id: (*id).to_string(),
            label,
            description,
            recommended: idx == 0,
        });
    }
    Some(mapped)
}

async fn build_clarification_request_with_inference(
    app: &tauri::AppHandle,
    preset: ClarificationPreset,
    tool_name: &str,
    output: &str,
) -> ClarificationRequest {
    let mut request = build_clarification_request(preset, tool_name, output);
    if let Some(options) = infer_clarification_option_text(app, &request, preset, output).await {
        request.options = options;
    } else {
        request.options.clear();
    }
    if request.options.is_empty() {
        println!(
            "[Autopilot] Clarification options unavailable; awaiting custom clarification input (tool={}, kind={})",
            request.tool_name, request.kind
        );
    }
    request
}

fn register_event(app: &tauri::AppHandle, mut event: AgentEvent) {
    let mut scs_handle = None;

    {
        let state = app.state::<Mutex<AppState>>();
        if let Ok(mut s) = state.lock() {
            let refs = s.event_index.entry(event.thread_id.clone()).or_default();
            if event.input_refs.is_empty() {
                if let Some(prev_id) = refs.last() {
                    event.input_refs.push(prev_id.clone());
                }
            }
            refs.push(event.event_id.clone());
            scs_handle = s.studio_scs.clone();
        };
    }

    update_task_state(app, |t| {
        let thread = t.session_id.clone().unwrap_or_else(|| t.id.clone());
        if thread == event.thread_id {
            t.events.push(event.clone());
        }
    });

    if let Some(scs) = scs_handle {
        orchestrator::append_event(&scs, &event);
    }

    let _ = app.emit("agent-event", &event);
}

fn register_artifact(app: &tauri::AppHandle, artifact: Artifact) {
    let thread_id = artifact.thread_id.clone();
    let mut run_bundle_id = None;
    let mut scs_handle = None;

    {
        let state = app.state::<Mutex<AppState>>();
        if let Ok(mut s) = state.lock() {
            let refs = s.artifact_index.entry(thread_id.clone()).or_default();
            if !refs.iter().any(|id| id == &artifact.artifact_id) {
                refs.push(artifact.artifact_id.clone());
            }
            if let Some(task) = &s.current_task {
                let task_thread = task.session_id.clone().unwrap_or_else(|| task.id.clone());
                if task_thread == thread_id {
                    run_bundle_id = task.run_bundle_id.clone();
                }
            }
            scs_handle = s.studio_scs.clone();
        };
    }

    update_task_state(app, |t| {
        let task_thread = t.session_id.clone().unwrap_or_else(|| t.id.clone());
        if task_thread == thread_id
            && !t
                .artifacts
                .iter()
                .any(|existing| existing.artifact_id == artifact.artifact_id)
        {
            t.artifacts.push(artifact.clone());
        }
    });

    let _ = app.emit("artifact-created", &artifact);

    if artifact.artifact_type != ArtifactType::RunBundle {
        if let (Some(bundle_id), Some(scs)) = (run_bundle_id, scs_handle) {
            if let Some(updated_bundle) = artifact_store::append_run_bundle_ref(
                &scs,
                &thread_id,
                &bundle_id,
                &artifact.artifact_id,
            ) {
                update_task_state(app, |t| {
                    let task_thread = t.session_id.clone().unwrap_or_else(|| t.id.clone());
                    if task_thread == thread_id
                        && !t
                            .artifacts
                            .iter()
                            .any(|a| a.artifact_id == updated_bundle.artifact_id)
                    {
                        t.artifacts.push(updated_bundle.clone());
                    }
                });
                let _ = app.emit("artifact-created", &updated_bundle);
            }
        }
    }
}

fn planned_artifact_types(event_type: &EventType, output: &str) -> Vec<ArtifactType> {
    if matches!(
        event_type,
        EventType::BrowserNavigate | EventType::BrowserExtract
    ) {
        return vec![ArtifactType::Web];
    }

    let (diff_lines, diff_files) = thresholds::estimate_diff_stats(output);
    if diff_lines > 0 && thresholds::should_spill_diff(diff_lines, diff_files) {
        return vec![ArtifactType::Diff];
    }

    if thresholds::should_spill_command_output(output) {
        return vec![ArtifactType::Log];
    }

    Vec::new()
}

fn create_macro_artifacts_for_action(
    app: &tauri::AppHandle,
    thread_id: &str,
    event_type: &EventType,
    tool_name: &str,
    output: &str,
) -> Vec<ArtifactRef> {
    let scs = {
        let state = app.state::<Mutex<AppState>>();
        state.lock().ok().and_then(|s| s.studio_scs.clone())
    };
    let Some(scs) = scs else {
        return Vec::new();
    };

    let mut refs = Vec::new();

    for artifact_type in planned_artifact_types(event_type, output) {
        match artifact_type {
            ArtifactType::Web => {
                let urls = collect_urls(output, 5);
                let primary_url = urls
                    .first()
                    .cloned()
                    .unwrap_or_else(|| format!("tool://{}", tool_name));
                let artifact = artifact_store::create_web_artifact(
                    &scs,
                    thread_id,
                    &primary_url,
                    output,
                    urls,
                );
                refs.push(ArtifactRef {
                    artifact_id: artifact.artifact_id.clone(),
                    artifact_type: ArtifactType::Web,
                });
                register_artifact(app, artifact);
            }
            ArtifactType::Diff => {
                let (diff_lines, diff_files) = thresholds::estimate_diff_stats(output);
                let metadata = json!({
                    "tool_name": tool_name,
                    "line_changes": diff_lines,
                    "files_touched": diff_files,
                });
                let artifact = artifact_store::create_diff_artifact(
                    &scs,
                    thread_id,
                    "Large Diff",
                    "Diff exceeded inline thresholds",
                    output,
                    metadata,
                );
                refs.push(ArtifactRef {
                    artifact_id: artifact.artifact_id.clone(),
                    artifact_type: ArtifactType::Diff,
                });
                register_artifact(app, artifact);
            }
            ArtifactType::Log => {
                let metadata = json!({
                    "tool_name": tool_name,
                    "line_count": thresholds::line_count(output),
                });
                let artifact = artifact_store::create_log_artifact(
                    &scs,
                    thread_id,
                    &format!("{} output", tool_name),
                    "Command output spilled due to threshold",
                    output,
                    metadata,
                );
                refs.push(ArtifactRef {
                    artifact_id: artifact.artifact_id.clone(),
                    artifact_type: ArtifactType::Log,
                });
                register_artifact(app, artifact);
            }
            _ => {}
        }
    }

    refs
}

fn build_event(
    thread_id: &str,
    step_index: u32,
    event_type: EventType,
    title: String,
    digest: Value,
    details: Value,
    status: EventStatus,
    artifact_refs: Vec<ArtifactRef>,
    receipt_ref: Option<String>,
    input_refs: Vec<String>,
    duration_ms: Option<u64>,
) -> AgentEvent {
    AgentEvent {
        event_id: Uuid::new_v4().to_string(),
        timestamp: now_iso(),
        thread_id: thread_id.to_string(),
        step_index,
        event_type,
        title,
        digest,
        details,
        artifact_refs,
        receipt_ref,
        input_refs,
        status,
        duration_ms,
    }
}

pub fn emit_command_run(
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    output: &str,
    status: EventStatus,
    artifact_refs: Vec<ArtifactRef>,
    input_refs: Vec<String>,
) -> AgentEvent {
    let digest = json!({
        "tool_name": tool_name,
        "output_snippet": snippet(output),
        "line_count": thresholds::line_count(output),
    });
    let details = json!({
        "output": thresholds::trim_for_expanded_view(output),
    });

    build_event(
        thread_id,
        step_index,
        EventType::CommandRun,
        format!("Ran {}", tool_name),
        digest,
        details,
        status,
        artifact_refs,
        None,
        input_refs,
        None,
    )
}

pub fn emit_command_stream(
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    stream_id: &str,
    channel: &str,
    chunk: &str,
    seq: u64,
    is_final: bool,
    exit_code: Option<i32>,
    command_preview: &str,
) -> AgentEvent {
    let status = if is_final {
        if exit_code.unwrap_or(0) == 0 {
            EventStatus::Success
        } else {
            EventStatus::Failure
        }
    } else {
        EventStatus::Partial
    };

    let digest = json!({
        "tool_name": tool_name,
        "stream_id": stream_id,
        "channel": channel,
        "seq": seq,
        "is_final": is_final,
        "exit_code": exit_code,
        "command_preview": command_preview,
    });
    let details = json!({
        "chunk": thresholds::trim_for_expanded_view(chunk),
    });

    build_event(
        thread_id,
        step_index,
        EventType::CommandStream,
        format!("Streaming {} ({})", tool_name, channel),
        digest,
        details,
        status,
        Vec::new(),
        None,
        Vec::new(),
        None,
    )
}

pub fn emit_file_edit(
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    diff_text: &str,
    status: EventStatus,
    artifact_refs: Vec<ArtifactRef>,
    input_refs: Vec<String>,
) -> AgentEvent {
    let (line_changes, files_touched) = thresholds::estimate_diff_stats(diff_text);
    let digest = json!({
        "tool_name": tool_name,
        "line_changes": line_changes,
        "files_touched": files_touched,
        "excerpt": thresholds::trim_edit_excerpt(diff_text),
    });
    let details = json!({
        "diff_excerpt": thresholds::trim_for_expanded_view(diff_text),
    });

    build_event(
        thread_id,
        step_index,
        EventType::FileEdit,
        format!("Edited files via {}", tool_name),
        digest,
        details,
        status,
        artifact_refs,
        None,
        input_refs,
        None,
    )
}

pub fn emit_code_search(
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    output: &str,
    status: EventStatus,
    artifact_refs: Vec<ArtifactRef>,
    input_refs: Vec<String>,
) -> AgentEvent {
    let digest = json!({
        "query": tool_name,
        "result_lines": thresholds::line_count(output),
        "snippet": snippet(output),
    });
    let details = json!({
        "results": thresholds::trim_for_expanded_view(output),
    });

    build_event(
        thread_id,
        step_index,
        EventType::CodeSearch,
        format!("Searched code with {}", tool_name),
        digest,
        details,
        status,
        artifact_refs,
        None,
        input_refs,
        None,
    )
}

pub fn emit_browser_navigate(
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    output: &str,
    status: EventStatus,
    artifact_refs: Vec<ArtifactRef>,
    input_refs: Vec<String>,
) -> AgentEvent {
    let urls = collect_urls(output, 5);
    let digest = json!({
        "tool_name": tool_name,
        "url": urls.first().cloned().unwrap_or_else(|| "unknown".to_string()),
        "snippet": snippet(output),
        "citations": urls,
    });
    let details = json!({
        "output": thresholds::trim_for_expanded_view(output),
    });

    build_event(
        thread_id,
        step_index,
        EventType::BrowserNavigate,
        "Navigated browser".to_string(),
        digest,
        details,
        status,
        artifact_refs,
        None,
        input_refs,
        None,
    )
}

pub fn emit_browser_extract(
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    output: &str,
    status: EventStatus,
    artifact_refs: Vec<ArtifactRef>,
    input_refs: Vec<String>,
) -> AgentEvent {
    let urls = collect_urls(output, 5);
    let digest = json!({
        "tool_name": tool_name,
        "extract_length": output.len(),
        "top_links": urls,
        "snippet": snippet(output),
    });
    let details = json!({
        "extract": thresholds::trim_for_expanded_view(output),
    });

    build_event(
        thread_id,
        step_index,
        EventType::BrowserExtract,
        "Extracted browser content".to_string(),
        digest,
        details,
        status,
        artifact_refs,
        None,
        input_refs,
        None,
    )
}

pub fn emit_test_run(
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    output: &str,
    status: EventStatus,
    artifact_refs: Vec<ArtifactRef>,
    input_refs: Vec<String>,
) -> AgentEvent {
    let digest = json!({
        "command": tool_name,
        "summary": snippet(output),
    });
    let details = json!({
        "output": thresholds::trim_for_expanded_view(output),
    });

    build_event(
        thread_id,
        step_index,
        EventType::TestRun,
        format!("Ran tests via {}", tool_name),
        digest,
        details,
        status,
        artifact_refs,
        None,
        input_refs,
        None,
    )
}

pub fn emit_receipt_digest(
    thread_id: &str,
    step_index: u32,
    receipt_id: String,
    tool_name: &str,
    tier: &str,
    decision: &str,
    intent_class: &str,
    incident_stage: &str,
    strategy_node: &str,
    gate_state: &str,
    resolution_action: &str,
    summary: &str,
    report_ref: Option<ArtifactRef>,
    input_refs: Vec<String>,
) -> AgentEvent {
    let mut artifact_refs = Vec::new();
    if let Some(r) = report_ref {
        artifact_refs.push(r);
    }

    let digest = json!({
        "intent_class": intent_class,
        "incident_stage": incident_stage,
        "strategy_node": strategy_node,
        "gate_state": gate_state,
        "resolution_action": resolution_action,
        "tool_name": tool_name,
        "tier": tier,
        "decision": decision,
        "summary": snippet(summary),
    });
    let details = json!({
        "receipt_summary": thresholds::trim_for_expanded_view(summary),
    });

    build_event(
        thread_id,
        step_index,
        EventType::Receipt,
        format!("Receipt: {} ({})", tool_name, decision),
        digest,
        details,
        EventStatus::Success,
        artifact_refs,
        Some(receipt_id),
        input_refs,
        None,
    )
}

pub async fn monitor_kernel_events(app: tauri::AppHandle) {
    loop {
        let mut client = loop {
            match PublicApiClient::connect("http://127.0.0.1:9000").await {
                Ok(c) => {
                    println!("[Autopilot] Connected to Kernel Event Stream at :9000");
                    break c;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        };

        let request = tonic::Request::new(SubscribeEventsRequest {});

        let mut stream = match client.subscribe_events(request).await {
            Ok(s) => s.into_inner(),
            Err(e) => {
                eprintln!(
                    "[Autopilot] Failed to subscribe to events (retrying in 2s): {}",
                    e
                );
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };

        let state_handle = app.state::<Mutex<AppState>>();

        println!("[Autopilot] Event Stream Active ✅");

        while let Ok(Some(event_msg)) = stream.message().await {
            if let Some(event_enum) = event_msg.event {
                match event_enum {
                    ChainEventEnum::Thought(thought) => {
                        update_task_state(&app, |t| {
                            if let Some(agent) =
                                t.swarm_tree.iter_mut().find(|a| a.id == thought.session_id)
                            {
                                if let Some(existing) = &agent.current_thought {
                                    agent.current_thought =
                                        Some(format!("{}{}", existing, thought.content));
                                } else {
                                    agent.current_thought = Some(thought.content.clone());
                                }
                                if agent.status != "paused" && agent.status != "requisition" {
                                    agent.status = "running".to_string();
                                }
                            } else {
                                if t.current_step == "Initializing..."
                                    || t.current_step.starts_with("Executed")
                                {
                                    t.current_step = thought.content.clone();
                                } else {
                                    t.current_step.push_str(&thought.content);
                                }
                            }

                            if t.phase != AgentPhase::Complete
                                && t.phase != AgentPhase::Failed
                                && t.phase != AgentPhase::Gate
                            {
                                t.phase = AgentPhase::Running;
                            }

                            t.progress += 1;
                            if !thought.visual_hash.is_empty() {
                                t.visual_hash = Some(thought.visual_hash.clone());
                            }
                            if !thought.session_id.is_empty() {
                                t.session_id = Some(thought.session_id.clone());
                            }
                        });

                        if thought.is_final {
                            let thread_id = thread_id_from_session(&app, &thought.session_id);
                            let event = build_event(
                                &thread_id,
                                0,
                                EventType::InfoNote,
                                "Captured reasoning step".to_string(),
                                json!({
                                    "session_id": thought.session_id,
                                    "visual_hash": thought.visual_hash,
                                    "token_count": thought.content.chars().count(),
                                }),
                                json!({
                                    "content": thresholds::trim_for_expanded_view(&thought.content),
                                }),
                                EventStatus::Success,
                                Vec::new(),
                                None,
                                Vec::new(),
                                None,
                            );
                            register_event(&app, event);
                        }
                    }
                    ChainEventEnum::ActionResult(res) => {
                        let password_required =
                            is_sudo_password_required_install(&res.tool_name, &res.output);
                        let clarification_preset =
                            if res.agent_status.eq_ignore_ascii_case("paused") {
                                detect_clarification_preset(&res.tool_name, &res.output)
                            } else {
                                None
                            };
                        let clarification_required = clarification_preset.is_some();
                        let clarification_request = if clarification_required {
                            let preset =
                                clarification_preset.unwrap_or(ClarificationPreset::IdentityLookup);
                            Some(
                                build_clarification_request_with_inference(
                                    &app,
                                    preset,
                                    &res.tool_name,
                                    &res.output,
                                )
                                .await,
                            )
                        } else {
                            None
                        };
                        let dedup_key = format!("{}:{}", res.step_index, res.tool_name);
                        let already_processed = {
                            if let Ok(guard) = state_handle.lock() {
                                if let Some(task) = &guard.current_task {
                                    task.processed_steps.contains(&dedup_key)
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        };
                        if already_processed {
                            continue;
                        }

                        update_task_state(&app, |t| {
                            let dedup_key = format!("{}:{}", res.step_index, res.tool_name);

                            if t.processed_steps.contains(&dedup_key) {
                                return;
                            }
                            t.processed_steps.insert(dedup_key);

                            t.current_step = format!("Executed {}: {}", res.tool_name, res.output);
                            if !res.session_id.is_empty() {
                                t.session_id = Some(res.session_id.clone());
                            }

                            if let Some(agent) =
                                t.swarm_tree.iter_mut().find(|a| a.id == res.session_id)
                            {
                                agent.artifacts_produced += 1;
                            }

                            let waiting_for_sudo = t
                                .credential_request
                                .as_ref()
                                .map(|req| req.kind == "sudo_password")
                                .unwrap_or(false)
                                || t.current_step
                                    .eq_ignore_ascii_case("Waiting for sudo password");
                            let waiting_for_clarification = t
                                .clarification_request
                                .as_ref()
                                .map(|req| is_identity_resolution_kind(&req.kind))
                                .unwrap_or(false)
                                || is_waiting_for_identity_clarification_step(&t.current_step);

                            if password_required {
                                t.phase = AgentPhase::Complete;
                                t.current_step = "Waiting for sudo password".to_string();
                                t.gate_info = None;
                                t.pending_request_hash = None;
                                t.clarification_request = None;
                                t.credential_request = Some(CredentialRequest {
                                    kind: "sudo_password".to_string(),
                                    prompt: "A one-time sudo password is required to continue the install."
                                        .to_string(),
                                    one_time: true,
                                });
                                if !res.output.trim().is_empty() {
                                    let tool_msg =
                                        format!("Tool Output ({}): {}", res.tool_name, res.output);
                                    if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true)
                                    {
                                        t.history.push(ChatMessage {
                                            role: "tool".to_string(),
                                            text: tool_msg,
                                            timestamp: crate::kernel::state::now(),
                                        });
                                    }
                                }
                                let prompt_msg =
                                    "System: Install requires sudo password. Enter password to retry."
                                        .to_string();
                                if t.history
                                    .last()
                                    .map(|m| m.text != prompt_msg)
                                    .unwrap_or(true)
                                {
                                    t.history.push(ChatMessage {
                                        role: "system".to_string(),
                                        text: prompt_msg,
                                        timestamp: crate::kernel::state::now(),
                                    });
                                }
                                return;
                            }

                            if clarification_required {
                                t.phase = AgentPhase::Complete;
                                t.current_step = CLARIFICATION_WAIT_STEP.to_string();
                                t.gate_info = None;
                                t.pending_request_hash = None;
                                t.credential_request = None;
                                t.clarification_request = clarification_request.clone();
                                if !res.output.trim().is_empty() {
                                    let tool_msg =
                                        format!("Tool Output ({}): {}", res.tool_name, res.output);
                                    if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true)
                                    {
                                        t.history.push(ChatMessage {
                                            role: "tool".to_string(),
                                            text: tool_msg,
                                            timestamp: crate::kernel::state::now(),
                                        });
                                    }
                                }
                                let prompt_msg = WAIT_FOR_CLARIFICATION_PROMPT.to_string();
                                if t.history
                                    .last()
                                    .map(|m| m.text != prompt_msg)
                                    .unwrap_or(true)
                                {
                                    t.history.push(ChatMessage {
                                        role: "system".to_string(),
                                        text: prompt_msg,
                                        timestamp: crate::kernel::state::now(),
                                    });
                                }
                                return;
                            }

                            // Keep password prompt stable even if later receipts/actions arrive
                            // before user submits credentials.
                            let terminal_status = res.agent_status.eq_ignore_ascii_case("failed")
                                || res.agent_status.eq_ignore_ascii_case("completed");
                            let keep_waiting_for_sudo = waiting_for_sudo
                                && !terminal_status
                                && is_install_package_tool(&res.tool_name)
                                && password_required;
                            if keep_waiting_for_sudo {
                                if !res.output.trim().is_empty() {
                                    let tool_msg =
                                        format!("Tool Output ({}): {}", res.tool_name, res.output);
                                    if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true)
                                    {
                                        t.history.push(ChatMessage {
                                            role: "tool".to_string(),
                                            text: tool_msg,
                                            timestamp: crate::kernel::state::now(),
                                        });
                                    }
                                }
                                return;
                            }

                            let keep_waiting_for_clarification = waiting_for_clarification
                                && !terminal_status
                                && clarification_required;
                            if keep_waiting_for_clarification {
                                if !res.output.trim().is_empty() {
                                    let tool_msg =
                                        format!("Tool Output ({}): {}", res.tool_name, res.output);
                                    if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true)
                                    {
                                        t.history.push(ChatMessage {
                                            role: "tool".to_string(),
                                            text: tool_msg,
                                            timestamp: crate::kernel::state::now(),
                                        });
                                    }
                                }
                                return;
                            }

                            t.credential_request = None;
                            t.clarification_request = None;

                            match res.agent_status.as_str() {
                                "Completed" => {
                                    t.phase = AgentPhase::Complete;

                                    if let Some(agent) =
                                        t.swarm_tree.iter_mut().find(|a| a.id == res.session_id)
                                    {
                                        agent.status = "completed".to_string();
                                    }

                                    t.receipt = Some(Receipt {
                                        duration: "Done".to_string(),
                                        actions: t.progress,
                                        cost: Some("$0.00".to_string()),
                                    });

                                    let msg = format!("Task Completed: {}", res.output);
                                    if t.history.last().map(|m| m.text != msg).unwrap_or(true) {
                                        t.history.push(ChatMessage {
                                            role: "system".into(),
                                            text: msg,
                                            timestamp: crate::kernel::state::now(),
                                        });
                                    }
                                }
                                "Failed" => {
                                    t.phase = AgentPhase::Failed;
                                    if let Some(agent) =
                                        t.swarm_tree.iter_mut().find(|a| a.id == res.session_id)
                                    {
                                        agent.status = "failed".to_string();
                                    }

                                    t.history.push(ChatMessage {
                                        role: "system".to_string(),
                                        text: format!("Task Failed: {}", res.output),
                                        timestamp: crate::kernel::state::now(),
                                    });
                                }
                                "Paused" => {
                                    if let Some(agent) =
                                        t.swarm_tree.iter_mut().find(|a| a.id == res.session_id)
                                    {
                                        agent.status = "paused".to_string();
                                    }
                                }
                                _ => {
                                    if t.phase != AgentPhase::Gate {
                                        t.phase = AgentPhase::Running;
                                    }
                                }
                            }

                            if res.tool_name == "chat::reply" || res.tool_name == "chat__reply" {
                                if res.agent_status == "Paused" {
                                    t.phase = AgentPhase::Complete;
                                    t.current_step = "Ready for input".to_string();
                                }

                                let duplicate = t
                                    .history
                                    .last()
                                    .map(|m| m.text == res.output)
                                    .unwrap_or(false);
                                if !duplicate {
                                    t.history.push(ChatMessage {
                                        role: "agent".to_string(),
                                        text: res.output.clone(),
                                        timestamp: crate::kernel::state::now(),
                                    });
                                }
                            } else if res.tool_name == "system::refusal" {
                                t.history.push(ChatMessage {
                                    role: "system".to_string(),
                                    text: format!("⚠️ Agent Paused: {}", res.output),
                                    timestamp: crate::kernel::state::now(),
                                });
                            } else if res.agent_status == "Running"
                                && res.tool_name != "agent__complete"
                            {
                                t.history.push(ChatMessage {
                                    role: "tool".to_string(),
                                    text: format!(
                                        "Tool Output ({}): {}",
                                        res.tool_name, res.output
                                    ),
                                    timestamp: crate::kernel::state::now(),
                                });
                            }
                        });

                        let thread_id = thread_id_from_session(&app, &res.session_id);
                        let kind = event_type_for_tool(&res.tool_name);
                        let status = event_status_from_agent_status(&res.agent_status);
                        let artifact_refs = create_macro_artifacts_for_action(
                            &app,
                            &thread_id,
                            &kind,
                            &res.tool_name,
                            &res.output,
                        );

                        let event = match kind {
                            EventType::CodeSearch => emit_code_search(
                                &thread_id,
                                res.step_index,
                                &res.tool_name,
                                &res.output,
                                status,
                                artifact_refs,
                                Vec::new(),
                            ),
                            EventType::FileEdit => emit_file_edit(
                                &thread_id,
                                res.step_index,
                                &res.tool_name,
                                &res.output,
                                status,
                                artifact_refs,
                                Vec::new(),
                            ),
                            EventType::BrowserNavigate => emit_browser_navigate(
                                &thread_id,
                                res.step_index,
                                &res.tool_name,
                                &res.output,
                                status,
                                artifact_refs,
                                Vec::new(),
                            ),
                            EventType::BrowserExtract => emit_browser_extract(
                                &thread_id,
                                res.step_index,
                                &res.tool_name,
                                &res.output,
                                status,
                                artifact_refs,
                                Vec::new(),
                            ),
                            EventType::TestRun => emit_test_run(
                                &thread_id,
                                res.step_index,
                                &res.tool_name,
                                &res.output,
                                status,
                                artifact_refs,
                                Vec::new(),
                            ),
                            _ => emit_command_run(
                                &thread_id,
                                res.step_index,
                                &res.tool_name,
                                &res.output,
                                status,
                                artifact_refs,
                                Vec::new(),
                            ),
                        };
                        register_event(&app, event);
                    }
                    ChainEventEnum::ProcessActivity(activity) => {
                        let thread_id = thread_id_from_session(&app, &activity.session_id);
                        let exit_code = if activity.has_exit_code {
                            Some(activity.exit_code)
                        } else {
                            None
                        };
                        let stream_password_required = activity.is_final
                            && is_sudo_password_required_install(
                                &activity.tool_name,
                                &activity.chunk,
                            );
                        let stream_clarification_preset = if activity.is_final {
                            detect_clarification_preset(&activity.tool_name, &activity.chunk)
                        } else {
                            None
                        };
                        let stream_clarification_required = stream_clarification_preset.is_some();
                        let stream_clarification_request = if stream_clarification_required {
                            let preset = stream_clarification_preset
                                .unwrap_or(ClarificationPreset::IdentityLookup);
                            Some(
                                build_clarification_request_with_inference(
                                    &app,
                                    preset,
                                    &activity.tool_name,
                                    &activity.chunk,
                                )
                                .await,
                            )
                        } else {
                            None
                        };
                        update_task_state(&app, |t| {
                            if !activity.session_id.is_empty() {
                                t.session_id = Some(activity.session_id.clone());
                            }
                            if matches!(t.phase, AgentPhase::Idle | AgentPhase::Running) {
                                t.phase = AgentPhase::Running;
                            }
                            t.current_step =
                                format!("Streaming {} ({})", activity.tool_name, activity.channel);
                        });

                        if stream_password_required {
                            update_task_state(&app, |t| {
                                t.phase = AgentPhase::Complete;
                                t.current_step = "Waiting for sudo password".to_string();
                                t.gate_info = None;
                                t.pending_request_hash = None;
                                t.clarification_request = None;
                                t.credential_request = Some(CredentialRequest {
                                    kind: "sudo_password".to_string(),
                                    prompt:
                                        "A one-time sudo password is required to continue the install."
                                            .to_string(),
                                    one_time: true,
                                });

                                if !activity.chunk.trim().is_empty() {
                                    let tool_msg = format!(
                                        "Tool Output ({}): {}",
                                        activity.tool_name, activity.chunk
                                    );
                                    if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true)
                                    {
                                        t.history.push(ChatMessage {
                                            role: "tool".to_string(),
                                            text: tool_msg,
                                            timestamp: crate::kernel::state::now(),
                                        });
                                    }
                                }

                                let prompt_msg =
                                    "System: Install requires sudo password. Enter password to retry."
                                        .to_string();
                                if t.history
                                    .last()
                                    .map(|m| m.text != prompt_msg)
                                    .unwrap_or(true)
                                {
                                    t.history.push(ChatMessage {
                                        role: "system".to_string(),
                                        text: prompt_msg,
                                        timestamp: crate::kernel::state::now(),
                                    });
                                }
                            });
                        } else if stream_clarification_required {
                            update_task_state(&app, |t| {
                                t.phase = AgentPhase::Complete;
                                t.current_step = CLARIFICATION_WAIT_STEP.to_string();
                                t.gate_info = None;
                                t.pending_request_hash = None;
                                t.credential_request = None;
                                t.clarification_request = stream_clarification_request.clone();

                                if !activity.chunk.trim().is_empty() {
                                    let tool_msg = format!(
                                        "Tool Output ({}): {}",
                                        activity.tool_name, activity.chunk
                                    );
                                    if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true)
                                    {
                                        t.history.push(ChatMessage {
                                            role: "tool".to_string(),
                                            text: tool_msg,
                                            timestamp: crate::kernel::state::now(),
                                        });
                                    }
                                }

                                let prompt_msg = WAIT_FOR_CLARIFICATION_PROMPT.to_string();
                                if t.history
                                    .last()
                                    .map(|m| m.text != prompt_msg)
                                    .unwrap_or(true)
                                {
                                    t.history.push(ChatMessage {
                                        role: "system".to_string(),
                                        text: prompt_msg,
                                        timestamp: crate::kernel::state::now(),
                                    });
                                }
                            });
                        }

                        let event = emit_command_stream(
                            &thread_id,
                            activity.step_index,
                            &activity.tool_name,
                            &activity.stream_id,
                            &activity.channel,
                            &activity.chunk,
                            activity.seq,
                            activity.is_final,
                            exit_code,
                            &activity.command_preview,
                        );
                        register_event(&app, event);
                    }
                    ChainEventEnum::RoutingReceipt(receipt) => {
                        let receipt_is_install_tool = is_install_package_tool(&receipt.tool_name);
                        let receipt_is_identity_lookup_tool =
                            clarification_preset_for_tool(&receipt.tool_name).is_some();
                        let receipt_waiting_for_sudo = receipt
                            .post_state
                            .as_ref()
                            .map(|s| {
                                s.agent_status
                                    .to_ascii_lowercase()
                                    .contains("waiting for sudo password")
                                    || s.verification_checks.iter().any(|check| {
                                        check.eq_ignore_ascii_case("awaiting_sudo_password=true")
                                    })
                            })
                            .unwrap_or(false)
                            || (receipt_is_install_tool
                                && (receipt
                                    .resolution_action
                                    .eq_ignore_ascii_case("wait_for_sudo_password")
                                    || receipt
                                        .escalation_path
                                        .eq_ignore_ascii_case("wait_for_sudo_password")));
                        let receipt_waiting_for_clarification = receipt
                            .post_state
                            .as_ref()
                            .map(|s| {
                                s.verification_checks.iter().any(|check| {
                                    check.eq_ignore_ascii_case("awaiting_clarification=true")
                                })
                            })
                            .unwrap_or(false)
                            || (receipt_is_identity_lookup_tool
                                && (receipt
                                    .resolution_action
                                    .eq_ignore_ascii_case("wait_for_clarification")
                                    || receipt
                                        .escalation_path
                                        .eq_ignore_ascii_case("wait_for_clarification")));
                        let receipt_clarification_request = if receipt_waiting_for_clarification {
                            let preset = clarification_preset_for_tool(&receipt.tool_name)
                                .unwrap_or(ClarificationPreset::IdentityLookup);
                            Some(
                                build_clarification_request_with_inference(
                                    &app,
                                    preset,
                                    &receipt.tool_name,
                                    "",
                                )
                                .await,
                            )
                        } else {
                            None
                        };
                        let failure_class = if receipt.failure_class_name.is_empty() {
                            None
                        } else {
                            Some(receipt.failure_class_name.as_str())
                        };

                        let verification = receipt
                            .post_state
                            .as_ref()
                            .map(|s| {
                                if s.verification_checks.is_empty() {
                                    "none".to_string()
                                } else {
                                    s.verification_checks.join(", ")
                                }
                            })
                            .unwrap_or_else(|| "none".to_string());

                        let mut summary = format!(
                            "RoutingReceipt(step={}, tier={}, tool={}, decision={}, stop={}, policy_hash={})",
                            receipt.step_index,
                            receipt
                                .pre_state
                                .as_ref()
                                .map(|s| s.tier.as_str())
                                .unwrap_or("unknown"),
                            receipt.tool_name,
                            receipt.policy_decision,
                            receipt.stop_condition_hit,
                            receipt.policy_binding_hash
                        );

                        if let Some(class) = failure_class {
                            summary.push_str(&format!(", failure_class={}", class));
                        }
                        if !receipt.intent_class.is_empty() {
                            summary.push_str(&format!(", intent_class={}", receipt.intent_class));
                        }
                        if !receipt.incident_id.is_empty() {
                            summary.push_str(&format!(", incident_id={}", receipt.incident_id));
                        }
                        if !receipt.incident_stage.is_empty() {
                            summary
                                .push_str(&format!(", incident_stage={}", receipt.incident_stage));
                        }
                        if !receipt.strategy_name.is_empty() {
                            summary.push_str(&format!(", strategy_name={}", receipt.strategy_name));
                        }
                        if !receipt.strategy_node.is_empty() {
                            summary.push_str(&format!(", strategy_node={}", receipt.strategy_node));
                        }
                        if !receipt.gate_state.is_empty() {
                            summary.push_str(&format!(", gate_state={}", receipt.gate_state));
                        }
                        if !receipt.resolution_action.is_empty() {
                            summary.push_str(&format!(
                                ", resolution_action={}",
                                receipt.resolution_action
                            ));
                        }
                        if !receipt.escalation_path.is_empty() {
                            summary.push_str(&format!(", escalation={}", receipt.escalation_path));
                        }
                        if !receipt.scs_lineage_ptr.is_empty() {
                            summary.push_str(&format!(", lineage={}", receipt.scs_lineage_ptr));
                        }
                        if !receipt.mutation_receipt_ptr.is_empty() {
                            summary.push_str(&format!(
                                ", mutation_receipt={}",
                                receipt.mutation_receipt_ptr
                            ));
                        }
                        summary.push_str(&format!(", verify=[{}]", verification));

                        update_task_state(&app, |t| {
                            if !receipt.session_id.is_empty() {
                                t.session_id = Some(receipt.session_id.clone());
                            }

                            let waiting_for_sudo = t
                                .credential_request
                                .as_ref()
                                .map(|req| req.kind == "sudo_password")
                                .unwrap_or(false)
                                || t.current_step
                                    .eq_ignore_ascii_case("Waiting for sudo password");
                            let waiting_for_clarification = t
                                .clarification_request
                                .as_ref()
                                .map(|req| is_identity_resolution_kind(&req.kind))
                                .unwrap_or(false)
                                || is_waiting_for_identity_clarification_step(&t.current_step);
                            let mut effective_waiting_for_sudo = waiting_for_sudo;
                            let mut effective_waiting_for_clarification = waiting_for_clarification;

                            if waiting_for_sudo && !receipt_waiting_for_sudo {
                                t.credential_request = None;
                                effective_waiting_for_sudo = false;
                            }

                            if waiting_for_clarification && !receipt_waiting_for_clarification {
                                t.clarification_request = None;
                                effective_waiting_for_clarification = false;
                            }

                            if receipt_waiting_for_sudo {
                                t.phase = AgentPhase::Complete;
                                t.current_step = "Waiting for sudo password".to_string();
                                t.gate_info = None;
                                t.pending_request_hash = None;
                                t.clarification_request = None;
                                t.credential_request = Some(CredentialRequest {
                                    kind: "sudo_password".to_string(),
                                    prompt:
                                        "A one-time sudo password is required to continue the install."
                                            .to_string(),
                                    one_time: true,
                                });
                            }

                            if receipt_waiting_for_clarification {
                                t.phase = AgentPhase::Complete;
                                t.current_step = CLARIFICATION_WAIT_STEP.to_string();
                                t.gate_info = None;
                                t.pending_request_hash = None;
                                t.credential_request = None;
                                t.clarification_request = receipt_clarification_request.clone();
                            }

                            if receipt
                                .policy_decision
                                .eq_ignore_ascii_case("require_approval")
                                && !effective_waiting_for_sudo
                                && !receipt_waiting_for_sudo
                                && !effective_waiting_for_clarification
                                && !receipt_waiting_for_clarification
                            {
                                t.phase = AgentPhase::Gate;
                                if t.gate_info.is_none() {
                                    t.gate_info = Some(GateInfo {
                                        title: "Restricted Action Intercepted".to_string(),
                                        description: format!(
                                            "The agent is attempting to execute: {}",
                                            receipt.tool_name
                                        ),
                                        risk: "high".to_string(),
                                    });
                                }
                            }

                            if !receipt_waiting_for_sudo && !receipt_waiting_for_clarification {
                                t.current_step = format!(
                                    "Routing: {} ({})",
                                    receipt.tool_name, receipt.policy_decision
                                );
                            }
                            t.history.push(ChatMessage {
                                role: "system".to_string(),
                                text: summary.clone(),
                                timestamp: crate::kernel::state::now(),
                            });
                        });

                        let thread_id = thread_id_from_session(&app, &receipt.session_id);
                        let receipt_id =
                            format!("{}:{}:{}", thread_id, receipt.step_index, receipt.tool_name);

                        let report_ref = {
                            let scs = {
                                let state = app.state::<Mutex<AppState>>();
                                state.lock().ok().and_then(|s| s.studio_scs.clone())
                            };
                            if let Some(scs) = scs {
                                let report_payload = json!({
                                    "receipt_id": receipt_id,
                                    "session_id": receipt.session_id,
                                    "step_index": receipt.step_index,
                                    "tool_name": receipt.tool_name,
                                    "decision": receipt.policy_decision,
                                    "intent_class": receipt.intent_class,
                                    "incident_id": receipt.incident_id,
                                    "incident_stage": receipt.incident_stage,
                                    "strategy_name": receipt.strategy_name,
                                    "strategy_node": receipt.strategy_node,
                                    "gate_state": receipt.gate_state,
                                    "resolution_action": receipt.resolution_action,
                                    "failure_class_name": receipt.failure_class_name,
                                    "summary": summary,
                                    "artifacts": receipt.artifacts,
                                    "policy_binding_hash": receipt.policy_binding_hash,
                                    "verification": receipt.post_state.as_ref().map(|v| v.verification_checks.clone()).unwrap_or_default(),
                                });
                                let report = artifact_store::create_report_artifact(
                                    &scs,
                                    &thread_id,
                                    &format!("Receipt {}", receipt.step_index),
                                    "Routing policy decision receipt",
                                    &report_payload,
                                );
                                let report_ref = ArtifactRef {
                                    artifact_id: report.artifact_id.clone(),
                                    artifact_type: ArtifactType::Report,
                                };
                                register_artifact(&app, report);
                                Some(report_ref)
                            } else {
                                None
                            }
                        };

                        let event = emit_receipt_digest(
                            &thread_id,
                            receipt.step_index,
                            receipt_id,
                            &receipt.tool_name,
                            receipt
                                .pre_state
                                .as_ref()
                                .map(|s| s.tier.clone())
                                .unwrap_or_else(|| "unknown".to_string())
                                .as_str(),
                            &receipt.policy_decision,
                            &receipt.intent_class,
                            &receipt.incident_stage,
                            &receipt.strategy_node,
                            &receipt.gate_state,
                            &receipt.resolution_action,
                            &summary,
                            report_ref,
                            Vec::new(),
                        );
                        register_event(&app, event);
                    }
                    ChainEventEnum::Ghost(input) => {
                        let payload = GhostInputEvent {
                            device: input.device.clone(),
                            description: input.description.clone(),
                        };
                        let _ = app.emit("ghost-input", &payload);
                        update_task_state(&app, |t| {
                            if matches!(t.phase, AgentPhase::Running) {
                                t.current_step = format!("User Input: {}", input.description);
                                t.history.push(ChatMessage {
                                    role: "user".to_string(),
                                    text: format!("[Ghost] {}", input.description),
                                    timestamp: crate::kernel::state::now(),
                                });
                            }
                        });

                        let thread_id = thread_id_from_session(&app, "");
                        let event = build_event(
                            &thread_id,
                            0,
                            EventType::InfoNote,
                            "Captured ghost input".to_string(),
                            json!({
                                "device": input.device,
                                "description": input.description,
                            }),
                            json!({}),
                            EventStatus::Success,
                            Vec::new(),
                            None,
                            Vec::new(),
                            None,
                        );
                        register_event(&app, event);
                    }
                    ChainEventEnum::Action(action) => {
                        if action.verdict == "REQUIRE_APPROVAL" {
                            let (waiting_for_sudo, waiting_for_clarification) = {
                                if let Ok(guard) = state_handle.lock() {
                                    if let Some(task) = &guard.current_task {
                                        let waiting_for_sudo = task
                                            .credential_request
                                            .as_ref()
                                            .map(|req| req.kind == "sudo_password")
                                            .unwrap_or(false)
                                            || task
                                                .current_step
                                                .eq_ignore_ascii_case("Waiting for sudo password");
                                        let waiting_for_clarification = task
                                            .clarification_request
                                            .as_ref()
                                            .map(|req| is_identity_resolution_kind(&req.kind))
                                            .unwrap_or(false)
                                            || is_waiting_for_identity_clarification_step(
                                                &task.current_step,
                                            );
                                        (waiting_for_sudo, waiting_for_clarification)
                                    } else {
                                        (false, false)
                                    }
                                } else {
                                    (false, false)
                                }
                            };
                            let action_is_install = is_install_package_tool(&action.target);
                            let action_is_identity_lookup_tool =
                                clarification_preset_for_tool(&action.target).is_some();
                            let suppress_gate_for_wait = (waiting_for_sudo && action_is_install)
                                || (waiting_for_clarification && action_is_identity_lookup_tool);

                            let already_gating = {
                                if let Ok(guard) = state_handle.lock() {
                                    if let Some(task) = &guard.current_task {
                                        task.phase == AgentPhase::Gate
                                            && task.pending_request_hash.as_deref()
                                                == Some(action.reason.as_str())
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            };

                            if !already_gating && !suppress_gate_for_wait {
                                println!("[Autopilot] Policy Gate Triggered for {}", action.target);

                                update_task_state(&app, |t| {
                                    t.phase = AgentPhase::Gate;
                                    t.current_step = "Policy Gate: Approval Required".to_string();
                                    // Gate takes precedence over credential/clarification prompts.
                                    t.credential_request = None;
                                    t.clarification_request = None;

                                    t.gate_info = Some(GateInfo {
                                        title: "Restricted Action Intercepted".to_string(),
                                        description: format!(
                                            "The agent is attempting to execute: {}",
                                            action.target
                                        ),
                                        risk: "high".to_string(),
                                    });

                                    t.pending_request_hash = Some(action.reason.clone());

                                    if !action.session_id.is_empty() {
                                        t.session_id = Some(action.session_id.clone());
                                    }

                                    t.history.push(ChatMessage {
                                        role: "system".to_string(),
                                        text: format!(
                                            "🛑 Policy Gate triggered for action: {}",
                                            action.target
                                        ),
                                        timestamp: crate::kernel::state::now(),
                                    });

                                    if let Some(agent) =
                                        t.swarm_tree.iter_mut().find(|a| a.id == action.session_id)
                                    {
                                        agent.status = "paused".to_string();
                                    }
                                });

                                let thread_id = thread_id_from_session(&app, &action.session_id);
                                let event = build_event(
                                    &thread_id,
                                    0,
                                    EventType::Warning,
                                    "Approval required".to_string(),
                                    json!({
                                        "target": action.target,
                                        "verdict": action.verdict,
                                        "request_hash": action.reason,
                                    }),
                                    json!({
                                        "message": "Policy gate triggered",
                                    }),
                                    EventStatus::Partial,
                                    Vec::new(),
                                    None,
                                    Vec::new(),
                                    None,
                                );
                                register_event(&app, event);

                                if let Some(w) = app.get_webview_window("studio") {
                                    if w.is_visible().unwrap_or(false) {
                                        let _ = w.set_focus();
                                    }
                                }
                            }
                        } else if action.verdict == "BLOCK" {
                            update_task_state(&app, |t| {
                                t.current_step = format!("⛔ Action Blocked: {}", action.target);
                                t.phase = AgentPhase::Failed;

                                if let Some(agent) =
                                    t.swarm_tree.iter_mut().find(|a| a.id == action.session_id)
                                {
                                    agent.status = "failed".to_string();
                                }

                                t.history.push(ChatMessage {
                                    role: "system".to_string(),
                                    text: format!("⛔ Blocked action: {}", action.target),
                                    timestamp: crate::kernel::state::now(),
                                });
                            });

                            let thread_id = thread_id_from_session(&app, &action.session_id);
                            let event = build_event(
                                &thread_id,
                                0,
                                EventType::Error,
                                "Action blocked".to_string(),
                                json!({
                                    "target": action.target,
                                    "verdict": action.verdict,
                                }),
                                json!({}),
                                EventStatus::Failure,
                                Vec::new(),
                                None,
                                Vec::new(),
                                None,
                            );
                            register_event(&app, event);
                        }
                    }
                    ChainEventEnum::Spawn(spawn) => {
                        update_task_state(&app, |t| {
                            let agent = SwarmAgent {
                                id: spawn.new_session_id.clone(),
                                parent_id: if spawn.parent_session_id.is_empty() {
                                    None
                                } else {
                                    Some(spawn.parent_session_id.clone())
                                },
                                name: spawn.name.clone(),
                                role: spawn.role.clone(),
                                status: "running".to_string(),
                                budget_used: 0.0,
                                budget_cap: spawn.budget as f64,
                                current_thought: Some(format!("Initialized goal: {}", spawn.goal)),
                                artifacts_produced: 0,
                                estimated_cost: 0.0,
                                policy_hash: "".to_string(),
                            };

                            if let Some(pos) = t.swarm_tree.iter().position(|a| a.id == agent.id) {
                                t.swarm_tree[pos] = agent;
                            } else {
                                t.swarm_tree.push(agent);
                            }
                        });

                        let thread_id = thread_id_from_session(&app, &spawn.parent_session_id);
                        let event = build_event(
                            &thread_id,
                            0,
                            EventType::InfoNote,
                            format!("Spawned agent {}", spawn.name),
                            json!({
                                "agent_id": spawn.new_session_id,
                                "role": spawn.role,
                                "budget": spawn.budget,
                            }),
                            json!({
                                "goal": spawn.goal,
                            }),
                            EventStatus::Success,
                            Vec::new(),
                            None,
                            Vec::new(),
                            None,
                        );
                        register_event(&app, event);
                    }
                    ChainEventEnum::System(update) => {
                        update_task_state(&app, |t| {
                            t.history.push(ChatMessage {
                                role: "system".to_string(),
                                text: format!("⚙️ {}: {}", update.component, update.status),
                                timestamp: crate::kernel::state::now(),
                            });
                        });

                        let thread_id = thread_id_from_session(&app, "");
                        let event = build_event(
                            &thread_id,
                            0,
                            EventType::InfoNote,
                            format!("System update: {}", update.component),
                            json!({
                                "component": update.component,
                                "status": update.status,
                            }),
                            json!({}),
                            EventStatus::Success,
                            Vec::new(),
                            None,
                            Vec::new(),
                            None,
                        );
                        register_event(&app, event);
                    }
                    ChainEventEnum::Block(block) => {
                        #[cfg(debug_assertions)]
                        println!(
                            "[Autopilot] Block #{} committed (Tx: {})",
                            block.height, block.tx_count
                        );
                    }
                }
            }
        }

        eprintln!("[Autopilot] Event Stream Disconnected. Attempting reconnection...");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_output(lines: usize) -> String {
        (0..lines)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn search_flow_events_link_to_web_artifact_and_prior_step() {
        let web_ref = ArtifactRef {
            artifact_id: "web-1".to_string(),
            artifact_type: ArtifactType::Web,
        };

        let navigate = emit_browser_navigate(
            "thread-1",
            1,
            "browser__navigate",
            "https://example.com?q=rust",
            EventStatus::Success,
            vec![web_ref.clone()],
            vec![],
        );
        assert_eq!(navigate.event_type, EventType::BrowserNavigate);
        assert_eq!(navigate.artifact_refs.len(), 1);
        assert_eq!(navigate.artifact_refs[0].artifact_type, ArtifactType::Web);

        let extract = emit_browser_extract(
            "thread-1",
            2,
            "browser__extract",
            "Top links https://example.com/a https://example.com/b",
            EventStatus::Success,
            vec![web_ref],
            vec![navigate.event_id.clone()],
        );
        assert_eq!(extract.event_type, EventType::BrowserExtract);
        assert_eq!(extract.input_refs[0], navigate.event_id);

        let completion = emit_command_run(
            "thread-1",
            3,
            "agent__complete",
            "Completed web synthesis",
            EventStatus::Success,
            extract.artifact_refs.clone(),
            vec![extract.event_id.clone()],
        );
        assert_eq!(completion.input_refs[0], extract.event_id);
        assert_eq!(completion.artifact_refs[0].artifact_type, ArtifactType::Web);
    }

    #[test]
    fn large_command_output_plans_log_artifact() {
        let output = long_output(210);
        let planned = planned_artifact_types(&EventType::CommandRun, &output);
        assert_eq!(planned, vec![ArtifactType::Log]);
    }

    #[test]
    fn large_diff_plans_diff_artifact() {
        let mut diff = String::new();
        for file in 0..4 {
            diff.push_str(&format!("diff --git a/f{file}.rs b/f{file}.rs\n"));
            diff.push_str("--- a/file\n+++ b/file\n");
            diff.push_str("-old\n+new\n");
        }
        let planned = planned_artifact_types(&EventType::FileEdit, &diff);
        assert_eq!(planned, vec![ArtifactType::Diff]);
    }
}
