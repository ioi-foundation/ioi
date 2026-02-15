use super::support::{
    extract_launch_target_hint, extract_missing_package_hint, snippet, ClarificationPreset,
};
use crate::models::{AppState, ClarificationOption, ClarificationRequest};
use ioi_types::app::agentic::InferenceOptions;
use serde::Deserialize;
use std::sync::Mutex;
use tauri::Manager;

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
\tConstraints:\n\
\t- Use exactly 3 options.\n\
\t- Use exactly these ids and preserve this order: [{option_id_order}].\n\
\t- Option 1 must be the strongest recommended next action.\n\
\t- Keep labels concise (2-5 words).\n\
\t- Keep each description to one short sentence.\n\
\t- No markdown, no extra fields, no prose outside JSON.\n\
\tContext:\n\
\tquestion={question}\n\
\ttool_name={tool}\n\
\tfailure_class={failure_class}\n\
\tcontext_hint={context_hint}\n\
\tevidence={evidence}\n\
\tOption semantics:\n\
\t{semantics}",
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

pub(super) async fn build_clarification_request_with_inference(
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
