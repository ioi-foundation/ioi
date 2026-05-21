// apps/autopilot/src-tauri/src/project/workflow_model_invocation_lane.rs

use super::workflow_node_input_lane::workflow_inputs_by_kind;
use super::*;
use crate::template::interpolate_template;
use ioi_api::vm::inference::TextGenerationRequest;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::InferenceOptions;
use sha2::{Digest, Sha256};
use std::time::Instant;

#[derive(Debug, Clone)]
struct WorkflowResolvedModelBinding {
    model_id: Option<String>,
    model_hash: Option<String>,
    source: String,
    binding: Value,
}

fn workflow_model_ref_from_input(input: &Value) -> Option<String> {
    input
        .get("modelRef")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .or_else(|| {
            input.as_object().and_then(|object| {
                object.values().find_map(|value| {
                    value
                        .get("modelRef")
                        .and_then(Value::as_str)
                        .filter(|model_ref| !model_ref.trim().is_empty())
                        .map(str::to_string)
                })
            })
        })
}

fn workflow_model_call_string_any(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn workflow_model_call_binding_string_any(value: &Value, keys: &[&str]) -> Option<String> {
    workflow_model_call_string_any(value, keys)
        .or_else(|| {
            value
                .get("modelBinding")
                .and_then(|binding| workflow_model_call_string_any(binding, keys))
        })
        .or_else(|| {
            value
                .get("binding")
                .and_then(|binding| workflow_model_call_string_any(binding, keys))
        })
}

fn workflow_model_call_binding_matches(value: &Value, model_ref: &str) -> bool {
    workflow_model_call_binding_string_any(value, &["modelRef", "model_ref"])
        .map(|candidate| candidate == model_ref)
        .unwrap_or(true)
}

fn workflow_model_call_binding_candidates(
    workflow: Option<&WorkflowProject>,
    logic: &Value,
    input: &Value,
    model_ref: &str,
) -> Vec<(String, Value)> {
    let mut candidates = Vec::new();
    candidates.push(("node.logic".to_string(), logic.clone()));
    if let Some(binding) = logic.get("modelBinding") {
        candidates.push(("node.modelBinding".to_string(), binding.clone()));
    }
    if let Some(binding) = input.get("modelBinding") {
        candidates.push(("input.modelBinding".to_string(), binding.clone()));
    }
    for binding in workflow_inputs_by_kind(input, "model_binding") {
        if workflow_model_call_binding_matches(&binding, model_ref) {
            candidates.push(("input.model_binding".to_string(), binding));
        }
    }
    if let Some(binding) = workflow.and_then(|workflow| {
        workflow
            .global_config
            .get("modelBindings")
            .or_else(|| workflow.global_config.get("model_bindings"))
            .and_then(|bindings| bindings.get(model_ref))
    }) {
        candidates.push((format!("global.modelBindings.{model_ref}"), binding.clone()));
    }
    candidates
}

fn workflow_resolve_model_binding(
    workflow: Option<&WorkflowProject>,
    logic: &Value,
    input: &Value,
    model_ref: &str,
) -> WorkflowResolvedModelBinding {
    let candidates = workflow_model_call_binding_candidates(workflow, logic, input, model_ref);
    let model_id = candidates.iter().find_map(|(_, candidate)| {
        workflow_model_call_binding_string_any(candidate, &["modelId", "model_id", "model"])
    });
    let model_hash = candidates.iter().find_map(|(_, candidate)| {
        workflow_model_call_binding_string_any(candidate, &["modelHash", "model_hash"])
    });
    let source = candidates
        .iter()
        .find(|(_, candidate)| {
            workflow_model_call_binding_string_any(candidate, &["modelId", "model_id", "model"])
                .is_some()
                || workflow_model_call_binding_string_any(candidate, &["modelHash", "model_hash"])
                    .is_some()
        })
        .map(|(source, _)| source.clone())
        .unwrap_or_else(|| "unresolved".to_string());
    let binding = candidates
        .iter()
        .find(|(_, candidate)| {
            workflow_model_call_binding_string_any(candidate, &["modelId", "model_id", "model"])
                .as_deref()
                == model_id.as_deref()
        })
        .map(|(_, candidate)| candidate.clone())
        .or_else(|| candidates.last().map(|(_, candidate)| candidate.clone()))
        .unwrap_or(Value::Null);
    WorkflowResolvedModelBinding {
        model_id,
        model_hash,
        source,
        binding,
    }
}

fn workflow_model_hash_hex_from_model_id(model_id: &str) -> Result<String, String> {
    let digest = sha256(format!("model_id:{model_id}").as_bytes())
        .map_err(|error| format!("Failed to derive model hash: {}", error))?;
    Ok(hex::encode(digest.as_ref()))
}

fn workflow_model_hash_bytes(model_hash: &str) -> Result<[u8; 32], String> {
    let trimmed = model_hash
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(model_hash.trim());
    let bytes = hex::decode(trimmed)
        .map_err(|error| format!("Model hash must be 32-byte hex: {}", error))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Model hash must decode to 32 bytes, got {} bytes.",
            bytes.len()
        ));
    }
    let mut model_hash_bytes = [0_u8; 32];
    model_hash_bytes.copy_from_slice(&bytes);
    Ok(model_hash_bytes)
}

fn workflow_model_status_is_executable(status: &str) -> bool {
    !matches!(
        status,
        "failed" | "cancelled" | "queued" | "installing" | "loading" | "unloading"
    )
}

fn workflow_model_registry_status(
    runtime: &WorkflowExecutionRuntime,
    model_ref: &str,
    model_id: &str,
) -> Result<Option<Value>, String> {
    let Some(registry) = runtime.local_engine_registry.as_ref() else {
        return Ok(None);
    };
    let record = registry
        .registry_models
        .iter()
        .find(|entry| entry.model_id == model_id)
        .ok_or_else(|| {
            format!(
                "Model binding '{}' points to '{}', but Local Engine has no registered model with that id.",
                model_ref, model_id
            )
        })?;
    let status = record.status.trim().to_ascii_lowercase();
    if !workflow_model_status_is_executable(&status) {
        return Err(format!(
            "Model binding '{}' points to '{}', but Local Engine reports status '{}' instead of a runnable model.",
            model_ref, model_id, record.status
        ));
    }
    Ok(Some(json!({
        "modelId": record.model_id,
        "status": record.status,
        "residency": record.residency,
        "backendId": record.backend_id,
        "hardwareProfile": record.hardware_profile
    })))
}

fn workflow_sha256_prefixed_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn workflow_model_call_input_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => {
            let trimmed = text.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }
        Value::Array(items) => items.iter().find_map(workflow_model_call_input_text),
        Value::Object(object) => {
            for key in [
                "prompt",
                "userPrompt",
                "user_prompt",
                "question",
                "query",
                "text",
                "content",
                "message",
                "input",
                "payload",
                "response",
            ] {
                if let Some(text) = object.get(key).and_then(workflow_model_call_input_text) {
                    return Some(text);
                }
            }
            if let Some(messages) = object.get("messages").and_then(Value::as_array) {
                let joined = messages
                    .iter()
                    .filter_map(|message| {
                        message
                            .get("content")
                            .and_then(workflow_model_call_input_text)
                            .or_else(|| workflow_model_call_input_text(message))
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                if !joined.trim().is_empty() {
                    return Some(joined);
                }
            }
            object.values().find_map(workflow_model_call_input_text)
        }
        _ => None,
    }
}

fn workflow_model_call_template_context(input: &Value) -> Value {
    input
        .as_object()
        .map(|_| input.clone())
        .unwrap_or_else(|| json!({ "input": input }))
}

fn workflow_model_call_prompt(logic: &Value, input: &Value) -> Result<Value, String> {
    let system = workflow_model_call_string_any(logic, &["systemPrompt", "system_prompt"]);
    let input_text = workflow_model_call_input_text(input);
    let prompt_template = workflow_model_call_string_any(
        logic,
        &["prompt", "userPrompt", "user_prompt", "text", "query"],
    );
    let rendered = if let Some(template) = prompt_template {
        interpolate_template(&template, &workflow_model_call_template_context(input))
    } else {
        input_text
            .clone()
            .unwrap_or_else(|| "Continue the workflow.".to_string())
    };
    let user = if let Some(input_text) = input_text.as_ref() {
        if rendered.contains(input_text) {
            rendered
        } else {
            format!("{rendered}\n\nWorkflow input:\n{input_text}")
        }
    } else {
        rendered
    };
    let messages = match system.as_ref() {
        Some(system) => json!([
            { "role": "system", "content": system },
            { "role": "user", "content": user }
        ]),
        None => json!([{ "role": "user", "content": user }]),
    };
    Ok(json!({
        "system": system,
        "user": user,
        "messages": messages
    }))
}

fn workflow_model_call_inference_options(logic: &Value) -> InferenceOptions {
    InferenceOptions {
        tools: Vec::new(),
        temperature: logic
            .get("temperature")
            .and_then(Value::as_f64)
            .map(|value| value as f32)
            .unwrap_or(0.2),
        json_mode: logic
            .get("jsonMode")
            .or_else(|| logic.get("json_mode"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        max_tokens: logic
            .get("maxTokens")
            .or_else(|| logic.get("max_tokens"))
            .and_then(Value::as_u64)
            .map(|value| value.clamp(1, u32::MAX as u64) as u32)
            .unwrap_or(512),
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn workflow_model_call_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    node_name: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
    runtime: &WorkflowExecutionRuntime,
    parser_attachment: Option<Value>,
    skill_context_attachment: Option<Value>,
    memory_attachment: Option<Value>,
    tool_attachments: Vec<Value>,
    tool_calls: Vec<Value>,
    parsed_output_schema: Option<Value>,
    memory_send_options: Value,
) -> Result<Value, String> {
    let model_ref = logic
        .get("modelRef")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .or_else(|| workflow_model_ref_from_input(input))
        .ok_or_else(|| "Model binding is missing.".to_string())?;
    let resolved_binding = workflow_resolve_model_binding(workflow, logic, input, &model_ref);
    let prompt = workflow_model_call_prompt(logic, input)?;
    let prompt_payload = json!({
        "node": {
            "id": node_id,
            "name": node_name,
            "kind": evidence_kind
        },
        "modelRef": model_ref,
        "prompt": prompt,
        "workflowInput": input,
        "attachments": {
            "skillContext": skill_context_attachment,
            "parser": parser_attachment,
            "memory": memory_attachment,
            "memoryPolicy": memory_send_options.clone(),
            "tools": tool_attachments
        },
        "structuredOutputSchema": parsed_output_schema
    });
    let prompt_bytes = serde_json::to_vec(&prompt_payload)
        .map_err(|error| format!("Failed to serialize model prompt: {}", error))?;
    let prompt_hash = workflow_sha256_prefixed_bytes(&prompt_bytes);
    let mut trace = vec![
        json!({
            "phase": "input",
            "summary": "Collected upstream workflow input and typed attachments.",
            "payload": input
        }),
        json!({
            "phase": "binding",
            "summary": "Resolved the configured model binding for this Agent Step.",
            "modelRef": model_ref,
            "bindingSource": resolved_binding.source,
            "modelId": resolved_binding.model_id,
            "modelHash": resolved_binding.model_hash
        }),
        json!({
            "phase": "prompt",
            "summary": "Assembled the canonical prompt envelope for the mounted model runtime.",
            "promptHash": prompt_hash,
            "messageCount": prompt
                .get("messages")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0)
        }),
    ];

    let (mode, response, response_model_id, streamed, latency_ms, registry_status) = if runtime
        .live_model_dispatch
    {
        let inference = runtime.inference.as_ref().ok_or_else(|| {
            format!(
                "Mounted model inference runtime is unavailable for workflow model node '{}'.",
                node_name
            )
        })?;
        let model_id = resolved_binding.model_id.clone().ok_or_else(|| {
                format!(
                    "Model binding '{}' needs a mounted modelId before workflow model node '{}' can run.",
                    model_ref, node_name
                )
            })?;
        let registry_status = workflow_model_registry_status(runtime, &model_ref, &model_id)?;
        let model_hash_hex = resolved_binding
            .model_hash
            .clone()
            .map(Ok)
            .unwrap_or_else(|| workflow_model_hash_hex_from_model_id(&model_id))?;
        let model_hash = workflow_model_hash_bytes(&model_hash_hex)?;
        let request = TextGenerationRequest {
            model_hash,
            model_id: Some(model_id.clone()),
            input_context: prompt_bytes.clone(),
            options: workflow_model_call_inference_options(logic),
            stream: logic
                .get("stream")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        };
        let started = Instant::now();
        let result =
            tauri::async_runtime::block_on(inference.generate_text(request)).map_err(|error| {
                format!(
                    "Mounted model invocation failed for binding '{}': {}",
                    model_ref, error
                )
            })?;
        let latency_ms = started.elapsed().as_millis() as u64;
        let response = String::from_utf8_lossy(&result.output).into_owned();
        (
            "live_mounted_model",
            response,
            result.model_id.or(Some(model_id)),
            result.streamed,
            Some(latency_ms),
            registry_status,
        )
    } else {
        (
            "deterministic_envelope",
            format!("{} completed with bound model {}.", node_name, model_ref),
            resolved_binding.model_id.clone(),
            false,
            None,
            None,
        )
    };
    let response_hash = workflow_sha256_prefixed_bytes(response.as_bytes());
    trace.push(json!({
        "phase": "model",
        "summary": if mode == "live_mounted_model" {
            "Invoked the mounted model runtime and captured the response fingerprint."
        } else {
            "Produced the deterministic workflow envelope without invoking a model runtime."
        },
        "responseHash": response_hash,
        "latencyMs": latency_ms
    }));
    let response_model_id_for_hash = response_model_id.clone();
    let model_hash_for_trace = resolved_binding.model_hash.clone().or_else(|| {
        response_model_id_for_hash
            .as_ref()
            .and_then(|id| workflow_model_hash_hex_from_model_id(id).ok())
    });

    Ok(json!({
        "nodeId": node_id,
        "kind": evidence_kind,
        "modelRef": model_ref,
        "modelId": response_model_id,
        "message": response,
        "response": response,
        "input": input,
        "attachments": {
            "skillContext": prompt_payload["attachments"]["skillContext"].clone(),
            "parser": prompt_payload["attachments"]["parser"].clone(),
            "memory": prompt_payload["attachments"]["memory"].clone(),
            "memoryPolicy": memory_send_options.clone(),
            "tools": prompt_payload["attachments"]["tools"].clone()
        },
        "runtimeSendOptions": {
            "memory": memory_send_options
        },
        "toolCalls": tool_calls,
        "structuredOutputSchema": prompt_payload["structuredOutputSchema"].clone(),
        "modelInvocation": {
            "mode": mode,
            "modelRef": prompt_payload["modelRef"].clone(),
            "modelId": response_model_id,
            "modelHash": model_hash_for_trace,
            "bindingSource": resolved_binding.source,
            "binding": resolved_binding.binding,
            "registryStatus": registry_status,
            "promptHash": prompt_hash,
            "responseHash": response_hash,
            "streamed": streamed,
            "latencyMs": latency_ms,
            "prompt": prompt_payload["prompt"].clone(),
            "trace": trace
        },
        "streaming": {
            "eventKinds": ["node_started", "model_invocation_succeeded", "state_updated", "node_succeeded"]
        }
    }))
}
