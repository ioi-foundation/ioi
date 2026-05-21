use super::*;
use crate::template::interpolate_template;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_api::vm::inference::{
    ImageEditRequest, ImageGenerationRequest, RerankRequest, SpeechSynthesisRequest,
    TextEmbeddingRequest, TextGenerationRequest, TranscriptionRequest, VideoGenerationRequest,
    VisionReadRequest,
};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::InferenceOptions;
use ioi_types::app::{CapabilityLease, CapabilityLeaseMode, NetMode, RuntimeTarget, WorkloadSpec};
use serde_json::json;

fn parse_input_object(input: &str) -> Value {
    serde_json::from_str(input).unwrap_or(json!({}))
}

fn latency_metrics(start: std::time::Instant) -> Value {
    json!({ "latency_ms": start.elapsed().as_millis() })
}

fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn optional_string_value(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
}

fn optional_u32_value(value: &Value, key: &str) -> Option<u32> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map(|entry| entry.min(u64::from(u32::MAX)) as u32)
}

fn optional_f32_value(value: &Value, key: &str) -> Option<f32> {
    value
        .get(key)
        .and_then(Value::as_f64)
        .map(|entry| entry as f32)
}

fn optional_bool_value(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn first_non_empty_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| optional_string_value(value, key))
}

fn interpolate_config_string(config: &Value, input_obj: &Value, keys: &[&str]) -> Option<String> {
    first_non_empty_string(config, keys).map(|template| {
        if template.contains("{{") {
            interpolate_template(&template, input_obj)
        } else {
            template
        }
    })
}

fn preferred_model_id(config: &Value) -> Option<String> {
    first_non_empty_string(config, &["model_id", "modelId", "model"])
}

fn resolve_graph_model_hash(config: &Value) -> Result<[u8; 32], String> {
    if let Some(raw_hash) = first_non_empty_string(config, &["model_hash", "modelHash"]) {
        let decoded = hex::decode(raw_hash.trim())
            .map_err(|error| format!("invalid model hash: {}", error))?;
        if decoded.len() != 32 {
            return Err(format!(
                "model hash must decode to 32 bytes, got {}",
                decoded.len()
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&decoded);
        return Ok(out);
    }

    if let Some(model_id) = preferred_model_id(config) {
        let digest = sha256(format!("model_id:{model_id}").as_bytes())
            .map_err(|error| format!("failed to derive model hash: {}", error))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        return Ok(out);
    }

    Ok([0u8; 32])
}

fn graph_inference_options(config: &Value) -> InferenceOptions {
    InferenceOptions {
        temperature: optional_f32_value(config, "temperature")
            .or_else(|| optional_f32_value(config, "temp"))
            .unwrap_or(0.2),
        json_mode: optional_bool_value(config, "json_mode")
            .or_else(|| optional_bool_value(config, "jsonMode"))
            .unwrap_or(false),
        max_tokens: optional_u32_value(config, "max_tokens")
            .or_else(|| optional_u32_value(config, "maxTokens"))
            .unwrap_or(512),
        ..Default::default()
    }
}

fn candidate_string_from_value(value: &Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let object = value.as_object()?;
    [
        "content",
        "text",
        "summary",
        "output",
        "output_text",
        "response",
        "title",
        "raw",
    ]
    .iter()
    .find_map(|key| object.get(*key).and_then(Value::as_str))
    .map(str::trim)
    .filter(|entry| !entry.is_empty())
    .map(str::to_string)
}

fn infer_text_payload(input_obj: &Value) -> Option<String> {
    if let Some(text) = input_obj.as_str() {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    first_non_empty_string(
        input_obj,
        &[
            "text",
            "prompt",
            "input",
            "query",
            "output",
            "response",
            "output_text",
            "transcript",
            "content",
        ],
    )
    .or_else(|| {
        input_obj
            .get("results")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(candidate_string_from_value)
                    .collect::<Vec<_>>()
                    .join("\n\n")
            })
            .filter(|joined| !joined.trim().is_empty())
    })
    .or_else(|| {
        if input_obj.is_object() && input_obj.as_object().is_some_and(|map| map.is_empty()) {
            None
        } else {
            Some(input_obj.to_string())
        }
    })
}

fn graph_user_content_value(config: &Value, input_obj: &Value) -> Value {
    if let Some(prompt) = interpolate_config_string(
        config,
        input_obj,
        &["prompt", "user_prompt", "userPrompt", "text", "query"],
    ) {
        return Value::String(prompt);
    }

    if let Some(text) = infer_text_payload(input_obj) {
        return Value::String(text);
    }

    input_obj.clone()
}

fn graph_prompt_with_context(config: &Value, input_obj: &Value) -> Option<String> {
    let prompt = interpolate_config_string(
        config,
        input_obj,
        &["prompt", "user_prompt", "userPrompt", "text", "query"],
    )
    .or_else(|| infer_text_payload(input_obj));

    prompt.map(|mut value| {
        let rag_context = format_context_for_llm(input_obj);
        if !rag_context.is_empty()
            && !value.contains("Retrieved Context")
            && !value.contains("Additional Context")
        {
            value.push_str(&rag_context);
        }
        value
    })
}

fn serialize_graph_response_input(config: &Value, input_obj: &Value) -> Result<Vec<u8>, String> {
    let system_prompt =
        interpolate_config_string(config, input_obj, &["systemPrompt", "system_prompt"]);

    if let Some(messages) = input_obj.get("messages").and_then(Value::as_array) {
        let mut final_messages = Vec::new();
        if let Some(system_prompt) = system_prompt.filter(|entry| !entry.trim().is_empty()) {
            final_messages.push(json!({
                "role": "system",
                "content": system_prompt
            }));
        }
        final_messages.extend(messages.iter().cloned());
        return serde_json::to_vec(&final_messages)
            .map_err(|error| format!("failed to serialize message input: {}", error));
    }

    if system_prompt.is_some()
        || first_non_empty_string(
            config,
            &["prompt", "user_prompt", "userPrompt", "text", "query"],
        )
        .is_some()
    {
        let mut messages = Vec::new();
        if let Some(system_prompt) = system_prompt.filter(|entry| !entry.trim().is_empty()) {
            messages.push(json!({
                "role": "system",
                "content": system_prompt
            }));
        }
        messages.push(json!({
            "role": "user",
            "content": graph_user_content_value(config, input_obj)
        }));
        return serde_json::to_vec(&messages)
            .map_err(|error| format!("failed to serialize response input: {}", error));
    }

    if let Some(text) = infer_text_payload(input_obj) {
        return Ok(text.into_bytes());
    }

    serde_json::to_vec(input_obj).map_err(|error| format!("failed to serialize input: {}", error))
}

fn string_candidates_from_array(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .filter_map(candidate_string_from_value)
        .collect::<Vec<_>>()
}

fn resolve_rerank_candidates(config: &Value, input_obj: &Value) -> Vec<String> {
    if let Some(items) = config.get("candidates").and_then(Value::as_array) {
        let candidates = string_candidates_from_array(items);
        if !candidates.is_empty() {
            return candidates;
        }
    }

    if let Some(text) = first_non_empty_string(config, &["candidatesText", "candidates_text"]) {
        let candidates = text
            .lines()
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        if !candidates.is_empty() {
            return candidates;
        }
    }

    if let Some(items) = input_obj.get("candidates").and_then(Value::as_array) {
        let candidates = string_candidates_from_array(items);
        if !candidates.is_empty() {
            return candidates;
        }
    }

    if let Some(items) = input_obj.get("results").and_then(Value::as_array) {
        let candidates = string_candidates_from_array(items);
        if !candidates.is_empty() {
            return candidates;
        }
    }

    if let Some(items) = input_obj.as_array() {
        let candidates = string_candidates_from_array(items);
        if !candidates.is_empty() {
            return candidates;
        }
    }

    Vec::new()
}

fn read_binary_file(path: &str, label: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("failed to read {} '{}': {}", label, path, error))
}

fn byte_array_value(value: &Value, key: &str, label: &str) -> Option<Result<Vec<u8>, String>> {
    let values = value.get(key).and_then(Value::as_array)?;
    Some(
        values
            .iter()
            .map(|entry| {
                entry
                    .as_u64()
                    .and_then(|raw| u8::try_from(raw).ok())
                    .ok_or_else(|| format!("{label} '{key}' must contain byte values (0-255)"))
            })
            .collect(),
    )
}

fn base64_value(value: &Value, key: &str, label: &str) -> Option<Result<Vec<u8>, String>> {
    let raw = optional_string_value(value, key)?;
    Some(
        BASE64_STANDARD
            .decode(raw.trim())
            .map_err(|error| format!("invalid base64 {} payload: {}", label, error)),
    )
}

fn resolve_binary_input(
    config: &Value,
    input_obj: &Value,
    path_keys: &[&str],
    base64_keys: &[&str],
    byte_keys: &[&str],
    label: &str,
) -> Result<(Vec<u8>, Option<String>), String> {
    for key in path_keys {
        if let Some(path) =
            optional_string_value(config, key).or_else(|| optional_string_value(input_obj, key))
        {
            return read_binary_file(&path, label).map(|bytes| (bytes, Some(path)));
        }
    }

    for key in base64_keys {
        if let Some(result) =
            base64_value(config, key, label).or_else(|| base64_value(input_obj, key, label))
        {
            return result.map(|bytes| (bytes, None));
        }
    }

    for key in byte_keys {
        if let Some(result) =
            byte_array_value(config, key, label).or_else(|| byte_array_value(input_obj, key, label))
        {
            return result.map(|bytes| (bytes, None));
        }
    }

    Err(format!(
        "missing {label} input; provide a path, base64 payload, or byte array"
    ))
}

fn resolve_optional_binary_input(
    config: &Value,
    input_obj: &Value,
    path_keys: &[&str],
    base64_keys: &[&str],
    byte_keys: &[&str],
    label: &str,
) -> Result<Option<(Vec<u8>, Option<String>)>, String> {
    for key in path_keys {
        if let Some(path) =
            optional_string_value(config, key).or_else(|| optional_string_value(input_obj, key))
        {
            return read_binary_file(&path, label).map(|bytes| Some((bytes, Some(path))));
        }
    }

    for key in base64_keys {
        if let Some(result) =
            base64_value(config, key, label).or_else(|| base64_value(input_obj, key, label))
        {
            return result.map(|bytes| Some((bytes, None)));
        }
    }

    for key in byte_keys {
        if let Some(result) =
            byte_array_value(config, key, label).or_else(|| byte_array_value(input_obj, key, label))
        {
            return result.map(|bytes| Some((bytes, None)));
        }
    }

    Ok(None)
}

fn mime_type_from_path(path: &str, default: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".wav") {
        "audio/wav".to_string()
    } else if lower.ends_with(".mp3") {
        "audio/mpeg".to_string()
    } else if lower.ends_with(".m4a") {
        "audio/mp4".to_string()
    } else if lower.ends_with(".ogg") {
        "audio/ogg".to_string()
    } else if lower.ends_with(".flac") {
        "audio/flac".to_string()
    } else if lower.ends_with(".png") {
        "image/png".to_string()
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg".to_string()
    } else if lower.ends_with(".webp") {
        "image/webp".to_string()
    } else if lower.ends_with(".gif") {
        "image/gif".to_string()
    } else if lower.ends_with(".bmp") {
        "image/bmp".to_string()
    } else {
        default.to_string()
    }
}

fn resolve_media_mime_type(
    config: &Value,
    input_obj: &Value,
    path_hint: Option<&str>,
    default: &str,
) -> String {
    first_non_empty_string(config, &["mime_type", "mimeType"])
        .or_else(|| first_non_empty_string(input_obj, &["mime_type", "mimeType"]))
        .unwrap_or_else(|| {
            path_hint
                .map(|path| mime_type_from_path(path, default))
                .unwrap_or_else(|| default.to_string())
        })
}

fn build_result(
    status: &str,
    output: String,
    data: Option<Value>,
    metrics: Option<Value>,
    input_snapshot: Option<Value>,
    context_slice: Option<Value>,
) -> ExecutionResult {
    ExecutionResult {
        status: status.to_string(),
        output,
        data,
        metrics,
        input_snapshot,
        context_slice,
    }
}

async fn ensure_browser_ready(input_obj: &Value) -> Option<ExecutionResult> {
    if let Err(e) = BROWSER_DRIVER.launch(false).await {
        return Some(build_result(
            "error",
            format!("Failed to launch browser driver: {}", e),
            None,
            None,
            Some(input_obj.clone()),
            None,
        ));
    }
    None
}

pub(super) async fn run_mcp_tool(
    tool_name: &str,
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj = parse_input_object(input);

    let raw_args = config.get("arguments").cloned().unwrap_or(json!({}));

    fn interpolate_recursive(val: &Value, ctx: &Value) -> Value {
        match val {
            Value::String(s) => {
                if s.contains("{{") {
                    Value::String(interpolate_template(s, ctx))
                } else {
                    val.clone()
                }
            }
            Value::Array(arr) => {
                Value::Array(arr.iter().map(|v| interpolate_recursive(v, ctx)).collect())
            }
            Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (k, v) in map {
                    new_map.insert(k.clone(), interpolate_recursive(v, ctx));
                }
                Value::Object(new_map)
            }
            _ => val.clone(),
        }
    }

    let mut args = interpolate_recursive(&raw_args, &input_obj);

    if let Value::Object(ref mut map) = args {
        if let Value::Object(input_map) = &input_obj {
            for (k, v) in input_map {
                map.entry(k).or_insert(v.clone());
            }
        }
    }

    let now_ms = unix_ms_now();
    let domain_allowlist = args
        .as_object()
        .and_then(|map| map.get("url"))
        .and_then(|value| value.as_str())
        .and_then(|url| {
            url::Url::parse(url)
                .ok()
                .and_then(|parsed| parsed.host_str().map(|host| host.to_ascii_lowercase()))
        })
        .map(|host| vec![host])
        .unwrap_or_default();
    let net_mode = if domain_allowlist.is_empty() {
        NetMode::Disabled
    } else {
        NetMode::AllowListed
    };
    let lease_material = serde_json::to_vec(&json!({
        "tool_name": tool_name,
        "issued_at_ms": now_ms,
        "arguments": args,
    }))?;
    let lease_id = sha256(&lease_material)?;

    let ephemeral_spec = WorkloadSpec {
        runtime_target: RuntimeTarget::Adapter,
        net_mode,
        capability_lease: Some(CapabilityLease {
            lease_id,
            issued_at_ms: now_ms.saturating_sub(1_000),
            expires_at_ms: now_ms.saturating_add(300_000),
            mode: CapabilityLeaseMode::OneShot,
            capability_allowlist: vec![tool_name.to_string()],
            domain_allowlist,
        }),
        ui_surface: None,
    };

    match MCP_MANAGER
        .execute_tool_with_spec(tool_name, args, Some(&ephemeral_spec))
        .await
    {
        Ok(output) => Ok(build_result(
            "success",
            output.clone(),
            match serde_json::from_str(&output) {
                Ok(v) => Some(v),
                Err(_) => Some(json!({ "raw": output })),
            },
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
        Err(e) => Ok(build_result(
            "error",
            format!("MCP Error: {}", e),
            None,
            None,
            Some(input_obj),
            None,
        )),
    }
}

pub(super) async fn run_browser_execution(
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj = parse_input_object(input);

    if let Some(error) = ensure_browser_ready(&input_obj).await {
        return Ok(error);
    }

    let action = config
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("navigate");

    match action {
        "navigate" => {
            let url_template = config
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or("Missing 'url' in logic config")?;
            let url = interpolate_template(url_template, &input_obj);

            match BROWSER_DRIVER.navigate(&url).await {
                Ok(content) => Ok(build_result(
                    "success",
                    content.clone(),
                    Some(json!({
                        "url": url,
                        "title": "Page Loaded",
                        "content_length": content.len()
                    })),
                    Some(latency_metrics(start)),
                    Some(input_obj),
                    None,
                )),
                Err(e) => Ok(build_result(
                    "error",
                    format!("Navigation failed: {}", e),
                    None,
                    Some(latency_metrics(start)),
                    Some(input_obj),
                    None,
                )),
            }
        }
        "extract_dom" => match BROWSER_DRIVER.extract_dom().await {
            Ok(dom) => Ok(build_result(
                "success",
                dom.clone(),
                Some(json!({ "dom_length": dom.len() })),
                Some(latency_metrics(start)),
                Some(input_obj),
                None,
            )),
            Err(e) => Ok(build_result(
                "error",
                format!("DOM extraction failed: {}", e),
                None,
                None,
                Some(input_obj),
                None,
            )),
        },
        "click" => {
            let selector_template = config
                .get("selector")
                .and_then(|v| v.as_str())
                .ok_or("Missing 'selector'")?;

            let selector = interpolate_template(selector_template, &input_obj);

            match BROWSER_DRIVER.click_selector(&selector).await {
                Ok(_) => Ok(build_result(
                    "success",
                    format!("Clicked element: {}", selector),
                    Some(json!({ "action": "click", "selector": selector })),
                    Some(latency_metrics(start)),
                    Some(input_obj),
                    None,
                )),
                Err(e) => Ok(build_result(
                    "error",
                    format!("Click failed for '{}': {}", selector, e),
                    None,
                    None,
                    Some(input_obj),
                    None,
                )),
            }
        }
        _ => Ok(build_result(
            "error",
            format!("Unknown browser action: {}", action),
            None,
            None,
            Some(input_obj),
            None,
        )),
    }
}

pub(super) async fn run_web_search_execution(
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj = parse_input_object(input);

    if let Some(error) = ensure_browser_ready(&input_obj).await {
        return Ok(error);
    }

    let query_template = config
        .get("query")
        .and_then(|v| v.as_str())
        .unwrap_or("{{input}}");
    let query = interpolate_template(query_template, &input_obj);

    let limit = config
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(5)
        .clamp(1, 10);

    let query_contract = config
        .get("query_contract")
        .and_then(|value| value.as_str());
    let retrieval_contract =
        match ioi_services::agentic::web::derive_web_retrieval_contract(&query, query_contract) {
            Ok(contract) => contract,
            Err(err) => {
                return Ok(build_result(
                    "error",
                    format!("Could not infer web retrieval contract: {}", err),
                    None,
                    Some(latency_metrics(start)),
                    Some(input_obj),
                    None,
                ));
            }
        };

    match ioi_services::agentic::web::edge_web_search(
        &*BROWSER_DRIVER,
        &query,
        query_contract,
        &retrieval_contract,
        limit,
    )
    .await
    {
        Ok(bundle) => {
            let data = serde_json::to_value(&bundle).ok();
            let output = serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| query.clone());
            Ok(build_result(
                "success",
                output,
                data,
                Some(latency_metrics(start)),
                Some(input_obj),
                None,
            ))
        }
        Err(e) => Ok(build_result(
            "error",
            format!("Web search failed: {}", e),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
    }
}

pub(super) async fn run_web_read_execution(
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj = parse_input_object(input);

    if let Some(error) = ensure_browser_ready(&input_obj).await {
        return Ok(error);
    }

    let url_template = config
        .get("url")
        .or_else(|| config.get("endpoint"))
        .and_then(|v| v.as_str())
        .ok_or("Missing 'url' in logic config")?;
    let url = interpolate_template(url_template, &input_obj);

    let max_chars = config
        .get("max_chars")
        .or_else(|| config.get("maxChars"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .or(Some(12_000));
    let allow_browser_fallback = config
        .get("allow_browser_fallback")
        .or_else(|| config.get("allowBrowserFallback"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    match ioi_services::agentic::web::edge_web_read(
        &*BROWSER_DRIVER,
        &url,
        max_chars,
        allow_browser_fallback,
    )
    .await
    {
        Ok(bundle) => {
            let data = serde_json::to_value(&bundle).ok();
            let output = serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| url.clone());
            Ok(build_result(
                "success",
                output,
                data,
                Some(latency_metrics(start)),
                Some(input_obj),
                None,
            ))
        }
        Err(e) => Ok(build_result(
            "error",
            format!("Web read failed: {}", e),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
    }
}

pub(super) async fn run_gate_execution(
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let condition = config
        .get("conditionScript")
        .or_else(|| config.get("condition"))
        .and_then(|v| v.as_str())
        .unwrap_or("true");

    let input_obj: Value = serde_json::from_str(input).unwrap_or(serde_json::json!({}));
    let passed;
    let mut reason = "Condition met".to_string();
    let cond = condition.trim().to_string();

    if cond == "true" {
        passed = true;
    } else {
        let parts: Vec<&str> = cond.split_whitespace().collect();

        if parts.len() >= 3 {
            let key_path = parts[0];
            let op = parts[1];
            let target_val_str = parts[2];

            let json_pointer = if key_path.starts_with("input.") {
                key_path.replace("input.", "/").replace(".", "/")
            } else {
                format!("/{}", key_path.replace(".", "/"))
            };

            let actual_val_opt = input_obj.pointer(&json_pointer);

            if let Some(val) = actual_val_opt {
                if let Some(num_val) = val.as_f64() {
                    let target_num = target_val_str.parse::<f64>().unwrap_or(0.0);
                    match op {
                        ">" => passed = num_val > target_num,
                        "<" => passed = num_val < target_num,
                        ">=" => passed = num_val >= target_num,
                        "<=" => passed = num_val <= target_num,
                        "==" => passed = (num_val - target_num).abs() < f64::EPSILON,
                        _ => {
                            passed = false;
                            reason = format!("Unknown operator: {}", op);
                        }
                    }
                    if !passed {
                        reason = format!(
                            "Field '{}' ({}) is not {} {}",
                            key_path, num_val, op, target_num
                        );
                    }
                } else if let Some(str_val) = val.as_str() {
                    let target_clean = target_val_str.trim_matches('"').trim_matches('\'');
                    match op {
                        "==" => passed = str_val == target_clean,
                        "!=" => passed = str_val != target_clean,
                        "contains" => passed = str_val.contains(target_clean),
                        _ => {
                            passed = false;
                            reason = "Invalid operator for string".into();
                        }
                    }
                    if !passed {
                        reason = format!(
                            "Field '{}' ('{}') check failed vs '{}'",
                            key_path, str_val, target_clean
                        );
                    }
                } else if let Some(bool_val) = val.as_bool() {
                    let target_bool = target_val_str.parse::<bool>().unwrap_or(false);
                    match op {
                        "==" => passed = bool_val == target_bool,
                        "!=" => passed = bool_val != target_bool,
                        _ => {
                            passed = false;
                            reason = "Invalid operator for boolean".into();
                        }
                    }
                    if !passed {
                        reason =
                            format!("Field '{}' ({}) is not {}", key_path, bool_val, target_bool);
                    }
                } else {
                    passed = false;
                    reason = format!("Field '{}' is not a comparable primitive", key_path);
                }
            } else {
                passed = false;
                reason = format!("Field '{}' not found in input data", key_path);
            }
        } else {
            reason = "Complex script syntax not supported in Local Mode. Use 'input.field > value'"
                .to_string();
            passed = false;
        }
    }

    Ok(ExecutionResult {
        status: if passed {
            "success".to_string()
        } else {
            "blocked".to_string()
        },
        output: if passed {
            input.to_string()
        } else {
            format!("Gate Blocked: {}", reason)
        },
        data: Some(serde_json::json!({
            "condition": condition,
            "passed": passed,
            "reason": reason
        })),
        metrics: Some(serde_json::json!({ "latency_ms": start.elapsed().as_millis() })),
        input_snapshot: Some(input_obj),
        context_slice: None,
    })
}

// Helper to format retrieval results into LLM-friendly text
fn format_context_for_llm(input_obj: &Value) -> String {
    let mut context_str = String::new();

    // Check for "results" array (output from retrieval node)
    if let Some(results) = input_obj.get("results").and_then(|v| v.as_array()) {
        context_str.push_str("\n\n### Retrieved Context:\n");
        for (i, doc) in results.iter().enumerate() {
            let content = doc["content"].as_str().unwrap_or("").trim();
            let score = doc["score"].as_f64().unwrap_or(0.0);
            if !content.is_empty() {
                context_str.push_str(&format!(
                    "--- Doc {} (Score: {:.2}) ---\n{}\n",
                    i + 1,
                    score,
                    content
                ));
            }
        }
    }

    // Check for direct "context" field
    if let Some(ctx) = input_obj.get("context").and_then(|v| v.as_str()) {
        context_str.push_str(&format!("\n\n### Additional Context:\n{}\n", ctx));
    }

    context_str
}

pub(super) async fn run_responses_execution(
    config: &Value,
    input_json: &str,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj = parse_input_object(input_json);
    let model_id = preferred_model_id(config);
    let model_hash = match resolve_graph_model_hash(config) {
        Ok(value) => value,
        Err(error) => {
            return Ok(build_result(
                "error",
                error,
                None,
                Some(latency_metrics(start)),
                Some(input_obj),
                None,
            ));
        }
    };

    let input_context = match serialize_graph_response_input(config, &input_obj) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok(build_result(
                "error",
                error,
                None,
                Some(latency_metrics(start)),
                Some(input_obj),
                None,
            ));
        }
    };

    let request = TextGenerationRequest {
        model_hash,
        model_id: model_id.clone(),
        input_context,
        options: graph_inference_options(config),
        stream: optional_bool_value(config, "stream").unwrap_or(false),
    };

    match inference.generate_text(request).await {
        Ok(result) => {
            let response = String::from_utf8_lossy(&result.output).into_owned();
            let final_prompt_snapshot = graph_prompt_with_context(config, &input_obj);
            Ok(build_result(
                "success",
                response.clone(),
                Some(json!({
                    "response": response,
                    "model_id": result.model_id,
                    "streamed": result.streamed,
                })),
                Some(json!({
                    "latency_ms": start.elapsed().as_millis(),
                    "final_prompt_snapshot": final_prompt_snapshot,
                })),
                Some(input_obj),
                None,
            ))
        }
        Err(error) => Ok(build_result(
            "error",
            format!("Responses execution failed: {}", error),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
    }
}

pub(super) async fn run_embeddings_execution(
    config: &Value,
    input_json: &str,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj = parse_input_object(input_json);
    let text = graph_prompt_with_context(config, &input_obj)
        .or_else(|| infer_text_payload(&input_obj))
        .filter(|value| !value.trim().is_empty());

    let Some(text) = text else {
        return Ok(build_result(
            "error",
            "Embeddings node needs text, query, or input content".to_string(),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        ));
    };

    let request = TextEmbeddingRequest {
        text: text.clone(),
        model_id: preferred_model_id(config),
    };

    match inference.embed_text_typed(request).await {
        Ok(result) => Ok(build_result(
            "success",
            format!("Embedded text into {} dimensions", result.dimensions),
            Some(json!({
                "values": result.values,
                "dimensions": result.dimensions,
                "model_id": result.model_id,
                "text": text,
            })),
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
        Err(error) => Ok(build_result(
            "error",
            format!("Embedding execution failed: {}", error),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
    }
}

pub(super) async fn run_rerank_execution(
    config: &Value,
    input_json: &str,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj = parse_input_object(input_json);
    let query = interpolate_config_string(config, &input_obj, &["query", "prompt", "text"])
        .or_else(|| first_non_empty_string(&input_obj, &["query", "prompt", "text", "input"]))
        .or_else(|| infer_text_payload(&input_obj))
        .filter(|value| !value.trim().is_empty());

    let Some(query) = query else {
        return Ok(build_result(
            "error",
            "Rerank node needs a query or prompt".to_string(),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        ));
    };

    let candidates = resolve_rerank_candidates(config, &input_obj);
    if candidates.is_empty() {
        return Ok(build_result(
            "error",
            "Rerank node needs candidates or upstream results".to_string(),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        ));
    }

    let request = RerankRequest {
        query: query.clone(),
        candidates,
        top_k: optional_u32_value(config, "top_k").or_else(|| optional_u32_value(config, "topK")),
        model_id: preferred_model_id(config),
    };

    match inference.rerank(request).await {
        Ok(result) => {
            let top_candidate = result
                .items
                .first()
                .map(|item| item.candidate.clone())
                .unwrap_or_else(|| "No reranked candidates returned".to_string());
            Ok(build_result(
                "success",
                top_candidate,
                Some(json!({
                    "items": result.items,
                    "model_id": result.model_id,
                    "query": query,
                })),
                Some(latency_metrics(start)),
                Some(input_obj),
                None,
            ))
        }
        Err(error) => Ok(build_result(
            "error",
            format!("Rerank execution failed: {}", error),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
    }
}

pub(super) async fn run_transcribe_audio_execution(
    config: &Value,
    input_json: &str,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj = parse_input_object(input_json);
    let (audio_bytes, path_hint) = match resolve_binary_input(
        config,
        &input_obj,
        &["audioPath", "audio_path", "path"],
        &["audioBase64", "audio_base64", "base64"],
        &["audioBytes", "audio_bytes", "bytes"],
        "audio",
    ) {
        Ok(value) => value,
        Err(error) => {
            return Ok(build_result(
                "error",
                error,
                None,
                Some(latency_metrics(start)),
                Some(input_obj),
                None,
            ));
        }
    };

    let mime_type = resolve_media_mime_type(config, &input_obj, path_hint.as_deref(), "audio/wav");
    let request = TranscriptionRequest {
        audio_bytes,
        mime_type: mime_type.clone(),
        language: first_non_empty_string(config, &["language", "audioLanguage", "audio_language"])
            .or_else(|| {
                first_non_empty_string(&input_obj, &["language", "audioLanguage", "audio_language"])
            }),
        model_id: preferred_model_id(config),
    };

    match inference.transcribe_audio(request).await {
        Ok(result) => Ok(build_result(
            "success",
            result.text.clone(),
            Some(json!({
                "text": result.text,
                "language": result.language,
                "model_id": result.model_id,
                "mime_type": mime_type,
            })),
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
        Err(error) => Ok(build_result(
            "error",
            format!("Audio transcription failed: {}", error),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
    }
}

pub(super) async fn run_synthesize_speech_execution(
    config: &Value,
    input_json: &str,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj = parse_input_object(input_json);
    let text = graph_prompt_with_context(config, &input_obj)
        .or_else(|| infer_text_payload(&input_obj))
        .filter(|value| !value.trim().is_empty());

    let Some(text) = text else {
        return Ok(build_result(
            "error",
            "Speech synthesis node needs prompt, text, or input content".to_string(),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        ));
    };

    let request = SpeechSynthesisRequest {
        text: text.clone(),
        voice: first_non_empty_string(config, &["voice"])
            .or_else(|| first_non_empty_string(&input_obj, &["voice"])),
        mime_type: first_non_empty_string(config, &["mime_type", "mimeType"])
            .or_else(|| first_non_empty_string(&input_obj, &["mime_type", "mimeType"])),
        model_id: preferred_model_id(config),
    };

    match inference.synthesize_speech(request).await {
        Ok(result) => {
            let mime_type = result.mime_type.clone();
            let model_id = result.model_id.clone();
            let byte_length = result.audio_bytes.len();
            let audio_base64 = BASE64_STANDARD.encode(&result.audio_bytes);
            Ok(build_result(
                "success",
                format!("Synthesized audio artifact ({mime_type}, {byte_length} bytes)"),
                Some(json!({
                    "artifact_kind": "audio",
                    "audio_base64": audio_base64,
                    "mime_type": mime_type,
                    "model_id": model_id,
                    "text": text,
                    "byte_length": byte_length,
                })),
                Some(latency_metrics(start)),
                Some(input_obj),
                Some(json!({
                    "artifact_kind": "audio",
                    "mime_type": mime_type,
                    "model_id": model_id,
                    "byte_length": byte_length,
                })),
            ))
        }
        Err(error) => Ok(build_result(
            "error",
            format!("Speech synthesis failed: {}", error),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
    }
}

pub(super) async fn run_vision_read_execution(
    config: &Value,
    input_json: &str,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj = parse_input_object(input_json);
    let (image_bytes, path_hint) = match resolve_binary_input(
        config,
        &input_obj,
        &["imagePath", "image_path", "path"],
        &["imageBase64", "image_base64", "base64"],
        &["imageBytes", "image_bytes", "bytes"],
        "image",
    ) {
        Ok(value) => value,
        Err(error) => {
            return Ok(build_result(
                "error",
                error,
                None,
                Some(latency_metrics(start)),
                Some(input_obj),
                None,
            ));
        }
    };

    let mime_type = resolve_media_mime_type(config, &input_obj, path_hint.as_deref(), "image/png");
    let request = VisionReadRequest {
        image_bytes,
        mime_type: mime_type.clone(),
        prompt: interpolate_config_string(config, &input_obj, &["prompt", "query", "text"])
            .or_else(|| first_non_empty_string(&input_obj, &["prompt", "query", "text"])),
        model_id: preferred_model_id(config),
    };

    match inference.vision_read(request).await {
        Ok(result) => Ok(build_result(
            "success",
            result.output_text.clone(),
            Some(json!({
                "output_text": result.output_text,
                "model_id": result.model_id,
                "mime_type": mime_type,
            })),
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
        Err(error) => Ok(build_result(
            "error",
            format!("Vision read failed: {}", error),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
    }
}

pub(super) async fn run_generate_image_execution(
    config: &Value,
    input_json: &str,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj = parse_input_object(input_json);
    let prompt = graph_prompt_with_context(config, &input_obj)
        .or_else(|| infer_text_payload(&input_obj))
        .filter(|value| !value.trim().is_empty());

    let Some(prompt) = prompt else {
        return Ok(build_result(
            "error",
            "Image generation node needs a prompt or text input".to_string(),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        ));
    };

    let request = ImageGenerationRequest {
        prompt: prompt.clone(),
        mime_type: first_non_empty_string(config, &["mime_type", "mimeType"])
            .or_else(|| first_non_empty_string(&input_obj, &["mime_type", "mimeType"])),
        model_id: preferred_model_id(config),
    };

    match inference.generate_image(request).await {
        Ok(result) => {
            let mime_type = result.mime_type.clone();
            let model_id = result.model_id.clone();
            let byte_length = result.image_bytes.len();
            let image_base64 = BASE64_STANDARD.encode(&result.image_bytes);
            Ok(build_result(
                "success",
                format!("Generated image artifact ({mime_type}, {byte_length} bytes)"),
                Some(json!({
                    "artifact_kind": "image",
                    "image_base64": image_base64,
                    "mime_type": mime_type,
                    "model_id": model_id,
                    "prompt": prompt,
                    "byte_length": byte_length,
                })),
                Some(latency_metrics(start)),
                Some(input_obj),
                Some(json!({
                    "artifact_kind": "image",
                    "mime_type": mime_type,
                    "model_id": model_id,
                    "byte_length": byte_length,
                })),
            ))
        }
        Err(error) => Ok(build_result(
            "error",
            format!("Image generation failed: {}", error),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
    }
}

pub(super) async fn run_edit_image_execution(
    config: &Value,
    input_json: &str,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj = parse_input_object(input_json);
    let (source_image_bytes, source_path_hint) = match resolve_binary_input(
        config,
        &input_obj,
        &["imagePath", "image_path", "path"],
        &["imageBase64", "image_base64", "base64"],
        &["imageBytes", "image_bytes", "bytes"],
        "image",
    ) {
        Ok(value) => value,
        Err(error) => {
            return Ok(build_result(
                "error",
                error,
                None,
                Some(latency_metrics(start)),
                Some(input_obj),
                None,
            ));
        }
    };

    let source_mime_type =
        resolve_media_mime_type(config, &input_obj, source_path_hint.as_deref(), "image/png");
    let prompt = interpolate_config_string(config, &input_obj, &["prompt", "query", "text"])
        .or_else(|| first_non_empty_string(&input_obj, &["prompt", "query", "text"]));
    let mask = match resolve_optional_binary_input(
        config,
        &input_obj,
        &["maskImagePath", "mask_image_path", "maskPath", "mask_path"],
        &[
            "maskImageBase64",
            "mask_image_base64",
            "maskBase64",
            "mask_base64",
        ],
        &[
            "maskImageBytes",
            "mask_image_bytes",
            "maskBytes",
            "mask_bytes",
        ],
        "mask image",
    ) {
        Ok(value) => value,
        Err(error) => {
            return Ok(build_result(
                "error",
                error,
                None,
                Some(latency_metrics(start)),
                Some(input_obj),
                None,
            ));
        }
    };

    let used_mask = mask.is_some();
    let request = ImageEditRequest {
        source_image_bytes,
        source_mime_type: source_mime_type.clone(),
        prompt: prompt.clone(),
        mask_image_bytes: mask.map(|(bytes, _)| bytes),
        model_id: preferred_model_id(config),
    };

    match inference.edit_image(request).await {
        Ok(result) => {
            let mime_type = result.mime_type.clone();
            let model_id = result.model_id.clone();
            let byte_length = result.image_bytes.len();
            let image_base64 = BASE64_STANDARD.encode(&result.image_bytes);
            Ok(build_result(
                "success",
                format!("Edited image artifact ({mime_type}, {byte_length} bytes)"),
                Some(json!({
                    "artifact_kind": "image",
                    "image_base64": image_base64,
                    "mime_type": mime_type,
                    "model_id": model_id,
                    "prompt": prompt,
                    "source_mime_type": source_mime_type,
                    "used_mask": used_mask,
                    "byte_length": byte_length,
                })),
                Some(latency_metrics(start)),
                Some(input_obj),
                Some(json!({
                    "artifact_kind": "image",
                    "mime_type": mime_type,
                    "model_id": model_id,
                    "used_mask": used_mask,
                    "byte_length": byte_length,
                })),
            ))
        }
        Err(error) => Ok(build_result(
            "error",
            format!("Image edit failed: {}", error),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
    }
}

pub(super) async fn run_generate_video_execution(
    config: &Value,
    input_json: &str,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj = parse_input_object(input_json);
    let prompt = graph_prompt_with_context(config, &input_obj)
        .or_else(|| infer_text_payload(&input_obj))
        .filter(|value| !value.trim().is_empty());

    let Some(prompt) = prompt else {
        return Ok(build_result(
            "error",
            "Video generation node needs a prompt or text input".to_string(),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        ));
    };

    let duration_ms = config
        .get("durationMs")
        .and_then(Value::as_u64)
        .or_else(|| input_obj.get("durationMs").and_then(Value::as_u64));
    let request = VideoGenerationRequest {
        prompt: prompt.clone(),
        mime_type: first_non_empty_string(config, &["mime_type", "mimeType"])
            .or_else(|| first_non_empty_string(&input_obj, &["mime_type", "mimeType"])),
        duration_ms,
        model_id: preferred_model_id(config),
    };

    match inference.generate_video(request).await {
        Ok(result) => {
            let mime_type = result.mime_type.clone();
            let model_id = result.model_id.clone();
            let byte_length = result.video_bytes.len();
            let video_base64 = BASE64_STANDARD.encode(&result.video_bytes);
            Ok(build_result(
                "success",
                format!("Generated video artifact ({mime_type}, {byte_length} bytes)"),
                Some(json!({
                    "artifact_kind": "video",
                    "video_base64": video_base64,
                    "mime_type": mime_type,
                    "model_id": model_id,
                    "prompt": prompt,
                    "duration_ms": duration_ms,
                    "byte_length": byte_length,
                })),
                Some(latency_metrics(start)),
                Some(input_obj),
                Some(json!({
                    "artifact_kind": "video",
                    "mime_type": mime_type,
                    "model_id": model_id,
                    "duration_ms": duration_ms,
                    "byte_length": byte_length,
                })),
            ))
        }
        Err(error) => Ok(build_result(
            "error",
            format!("Video generation failed: {}", error),
            None,
            Some(latency_metrics(start)),
            Some(input_obj),
            None,
        )),
    }
}

pub(super) async fn run_tool_execution(
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let url = config
        .get("endpoint")
        .or_else(|| config.get("url"))
        .and_then(|v| v.as_str())
        .ok_or("Tool configuration missing 'endpoint'")?;

    let method = config
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_uppercase();
    let body_template = config
        .get("bodyTemplate")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let client = reqwest::Client::new();
    let start = std::time::Instant::now();

    let input_obj: Value = serde_json::from_str(input).unwrap_or(serde_json::json!({}));

    let mut builder = match method.as_str() {
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        _ => client.get(url),
    };

    if !body_template.is_empty() && (method == "POST" || method == "PUT") {
        let final_body = interpolate_template(body_template, &input_obj);

        if let Ok(json_body) = serde_json::from_str::<Value>(&final_body) {
            builder = builder.json(&json_body);
        } else {
            builder = builder.body(final_body);
        }
    }

    let res = builder.send().await;
    let duration = start.elapsed();

    match res {
        Ok(response) => {
            let status = response.status();
            let text = response.text().await?;

            Ok(ExecutionResult {
                status: if status.is_success() {
                    "success".to_string()
                } else {
                    "failed".to_string()
                },
                output: text.clone(),
                data: Some(serde_json::json!({
                    "status_code": status.as_u16(),
                    "body_preview": text.chars().take(500).collect::<String>()
                })),
                metrics: Some(serde_json::json!({ "latency_ms": duration.as_millis() })),
                input_snapshot: Some(input_obj),
                context_slice: None,
            })
        }
        Err(e) => Ok(ExecutionResult {
            status: "error".to_string(),
            output: format!("Network Request Failed: {}", e),
            data: None,
            metrics: Some(serde_json::json!({ "latency_ms": duration.as_millis() })),
            input_snapshot: Some(input_obj),
            context_slice: None,
        }),
    }
}

pub(super) async fn run_code_execution(
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let language = config
        .get("language")
        .and_then(|s| s.as_str())
        .unwrap_or("python");
    let _code = config.get("code").and_then(|s| s.as_str()).unwrap_or("");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let input_obj = parse_input_object(input);

    Ok(build_result(
        "success",
        format!("Executed {} code (Simulated)", language),
        Some(json!({ "processed": true, "result": "simulated_data" })),
        None,
        Some(input_obj),
        None,
    ))
}

pub(super) async fn run_router_execution(
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let routes = config
        .get("routes")
        .and_then(|v| v.as_array())
        .ok_or("No routes defined")?;

    let input_lower = input.to_lowercase();
    let mut selected_route = routes[0].as_str().unwrap_or("default").to_string();

    for r in routes {
        if let Some(route_str) = r.as_str() {
            if input_lower.contains(&route_str.to_lowercase()) {
                selected_route = route_str.to_string();
                break;
            }
        }
    }

    Ok(build_result(
        "success",
        selected_route.clone(),
        Some(json!({ "route": selected_route })),
        None,
        Some(parse_input_object(input)),
        None,
    ))
}

pub(super) async fn run_wait_execution(config: &Value) -> Result<ExecutionResult, Box<dyn Error>> {
    let duration = config
        .get("durationMs")
        .and_then(|v| v.as_u64())
        .unwrap_or(1000);
    tokio::time::sleep(std::time::Duration::from_millis(duration)).await;

    Ok(build_result(
        "success",
        format!("Waited {}ms", duration),
        None,
        None,
        None,
        None,
    ))
}

pub(super) async fn run_context_execution(
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let vars = config.get("variables").cloned().unwrap_or(json!({}));

    Ok(build_result(
        "success",
        "Context Updated".into(),
        Some(vars),
        None,
        Some(parse_input_object(input)),
        None,
    ))
}

// Semantic Retrieval Implementation
pub(super) async fn run_retrieval_execution(
    config: &Value,
    input: &str,
    memory_runtime: Arc<MemoryRuntime>,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();

    // 1. Resolve Query
    // Either from config "query" template or raw input
    let input_obj = parse_input_object(input);
    let query_template = config
        .get("query")
        .and_then(|s| s.as_str())
        .unwrap_or("{{input}}");
    let query = interpolate_template(query_template, &input_obj);

    if query.trim().is_empty() {
        return Ok(ExecutionResult {
            status: "error".into(),
            output: "Empty query".into(),
            data: None,
            metrics: None,
            input_snapshot: Some(input_obj),
            context_slice: None,
        });
    }

    // 2. Generate Embedding
    let embedding = match inference.embed_text(&query).await {
        Ok(vec) => vec,
        Err(e) => {
            return Ok(ExecutionResult {
                status: "error".into(),
                output: format!("Embedding failed: {}", e),
                data: None,
                metrics: None,
                input_snapshot: Some(input_obj),
                context_slice: None,
            })
        }
    };

    // 3. Search archival memory
    let limit = config.get("limit").and_then(|v| v.as_u64()).unwrap_or(3) as usize;
    let candidate_limit = config
        .get("candidate_limit")
        .and_then(|v| v.as_u64())
        .unwrap_or((limit as u64).saturating_mul(8).max(32))
        .max(limit as u64) as usize;
    let scope = config
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("autopilot.retrieval")
        .to_string();
    let lexical_filter = config
        .get("text_filter")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            let trimmed = query.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });

    let hits = memory_runtime
        .hybrid_search_archival_memory(&ioi_memory::HybridArchivalMemoryQuery {
            scopes: vec![scope.clone()],
            thread_id: None,
            text: lexical_filter.unwrap_or_else(|| query.clone()),
            embedding: Some(embedding),
            limit: limit.max(1),
            candidate_limit,
            allowed_trust_levels: vec![
                "runtime_observed".to_string(),
                "runtime_derived".to_string(),
                "standard".to_string(),
            ],
        })
        .map_err(|error| format!("Archival search failed: {}", error))?;

    let total_hits = hits.len();
    let query_hash = sha256(query.as_bytes())
        .map(hex::encode)
        .unwrap_or_else(|_| String::new());
    let results = hits
        .into_iter()
        .take(limit.max(1))
        .map(|hit| {
            let metadata = serde_json::from_str::<Value>(&hit.record.metadata_json)
                .unwrap_or_else(|_| json!({}));
            json!({
                "content": hit.record.content,
                "score": hit.score,
                "lexical_score": hit.lexical_score,
                "semantic_score": hit.semantic_score,
                "trust_level": hit.trust_level,
                "record_id": hit.record.id,
                "scope": hit.record.scope,
                "kind": hit.record.kind,
                "metadata": metadata
            })
        })
        .collect::<Vec<_>>();
    let retrieval_receipt = Some(json!({
        "tool_name": "retrieval",
        "backend": "ioi-memory:hybrid-archival",
        "query_hash": query_hash,
        "scope": scope,
        "k": limit.max(1),
        "candidate_limit": candidate_limit,
        "candidate_count_total": total_hits,
        "candidate_count_reranked": total_hits,
        "candidate_truncated": (total_hits as usize) > limit.max(1),
        "distance_metric": "hybrid_lexical_semantic",
        "embedding_normalized": false,
        "certificate_mode": "none"
    }));

    // 4. Format Output
    let context_str = results
        .iter()
        .map(|d| d["content"].as_str().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n\n---\n\n");

    Ok(ExecutionResult {
        status: "success".into(),
        output: context_str,
        data: Some(json!({ "results": results, "retrieval_receipt": retrieval_receipt })),
        metrics: Some(json!({
            "latency_ms": start.elapsed().as_millis(),
            "hits": results.len(),
            "k": limit.max(1),
            "candidate_limit": candidate_limit
        })),
        input_snapshot: Some(input_obj),
        context_slice: Some(json!(results)),
    })
}

#[cfg(test)]
mod tests;
