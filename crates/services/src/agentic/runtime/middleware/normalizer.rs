use anyhow::{anyhow, Result};
use ioi_types::app::agentic::AgentTool;
use serde_json::{json, Value};

use super::builtins::{canonical_deterministic_tool_name, is_deterministic_tool_name};
use super::coercion::{
    lower_edit_line_to_fs_write, normalize_browser_click_element_arguments,
    normalize_browser_key_arguments, normalize_browser_synthetic_click_arguments,
    normalize_browser_wait_arguments, normalize_file_search_arguments,
    normalize_install_package_arguments, normalize_net_fetch_arguments,
    normalize_ui_click_arguments, normalize_ui_click_component_arguments,
    normalize_ui_scroll_arguments, normalize_ui_type_arguments,
};
use super::envelope::{sanitize_json, unwrap_tool_envelope};
use super::{ToolNormalizationObservation, ToolNormalizationResult, ToolNormalizer};

fn normalized_tool_name(tool_call: &AgentTool) -> Option<String> {
    serde_json::to_value(tool_call).ok().and_then(|value| {
        value
            .get("name")
            .and_then(|name| name.as_str())
            .map(|name| name.to_string())
    })
}

fn looks_like_single_key_tool_wrapper(candidate: &str, value: &Value) -> bool {
    if !value.is_object() {
        return false;
    }

    let normalized = candidate.trim();
    if normalized.is_empty() {
        return false;
    }

    canonical_deterministic_tool_name(normalized).is_some()
        || normalized.contains("__")
        || normalized.contains("::")
        || normalized.contains(':')
        || normalized.contains('.')
}

fn single_key_tool_wrapper_records_raw_name(wrapped_name: &str) -> bool {
    matches!(wrapped_name, "file__search")
}

fn bare_tool_token_rewrite(raw: &str) -> Option<(String, Value, Vec<&'static str>)> {
    let normalized = canonical_deterministic_tool_name(raw.trim())?;
    match normalized.as_str() {
        "file__list" => Some((
            normalized,
            json!({ "path": "." }),
            vec![
                "bare_tool_token_wrapped",
                "bare_tool_token_default_root_path",
            ],
        )),
        _ => None,
    }
}

fn tool_name_with_argument_block_rewrite(raw: &str) -> Option<(String, Value, Vec<&'static str>)> {
    let trimmed = raw.trim();
    let first_line = trimmed.lines().next()?.trim();
    if first_line.is_empty() {
        return None;
    }

    let normalized = canonical_deterministic_tool_name(first_line)?;
    let remainder = trimmed[first_line.len()..].trim();
    if remainder.is_empty() {
        return None;
    }

    let sanitized_arguments = sanitize_json(remainder);
    let parsed_arguments: Value = serde_json::from_str(&sanitized_arguments).ok()?;
    if !parsed_arguments.is_object() {
        return None;
    }

    let mut labels = vec!["tool_name_line_wrapped"];
    if sanitized_arguments.trim() != remainder.trim() {
        labels.push("tool_name_line_markdown_arguments_unwrapped");
    }

    Some((
        normalized.clone(),
        json!({
            "name": normalized,
            "arguments": parsed_arguments,
        }),
        labels,
    ))
}

fn is_tool_metadata_key(key: &str) -> bool {
    matches!(
        key,
        "name"
            | "tool"
            | "recipient_name"
            | "arguments"
            | "args"
            | "parameters"
            | "input"
            | "description"
            | "comment"
            | "comments"
            | "rationale"
            | "reasoning"
            | "thought"
            | "explanation"
    )
}

impl ToolNormalizer {
    /// The boundary function.
    /// Input: Raw, potentially hallucinated JSON from LLM.
    /// Output: Strict Rust Type or Error.
    pub fn normalize(raw_llm_output: &str) -> Result<AgentTool> {
        Ok(Self::normalize_with_observation(raw_llm_output)?.tool)
    }

    pub fn normalize_with_observation(raw_llm_output: &str) -> Result<ToolNormalizationResult> {
        // [FIX] Fast fail on empty input
        if raw_llm_output.trim().is_empty() {
            return Err(anyhow!(
                "LLM returned empty output (Possible Refusal/Filter)"
            ));
        }

        let mut observation = ToolNormalizationObservation::default();
        if let Some((name, raw_val, labels)) = tool_name_with_argument_block_rewrite(raw_llm_output)
        {
            observation.raw_name = Some(name.clone());
            for label in labels {
                observation.push_label(label);
            }
            let mut raw_val = raw_val;
            raw_val = unwrap_tool_envelope(raw_val)?;
            observation.raw_name = raw_val
                .get("name")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string());
            return Self::normalize_value_with_observation(raw_val, observation);
        }

        // 1. Sanitize (Remove markdown blocks, fix trailing commas)
        let json_str = sanitize_json(raw_llm_output);
        if let Some((name, arguments, labels)) = bare_tool_token_rewrite(&json_str) {
            observation.raw_name = Some(name.clone());
            for label in labels {
                observation.push_label(label);
            }
            let raw_val = json!({
                "name": name,
                "arguments": arguments,
            });
            let tool_call: AgentTool = serde_json::from_value(raw_val)
                .map_err(|e| anyhow!("Schema Validation Error: {}", e))?;
            observation.normalized_name = normalized_tool_name(&tool_call);
            return Ok(ToolNormalizationResult {
                tool: tool_call,
                observation,
            });
        }

        // 2. Parse Generic JSON
        let raw_val: Value =
            serde_json::from_str(&json_str).map_err(|e| anyhow!("JSON Syntax Error: {}", e))?;

        // 2b. Unwrap provider envelopes (OpenAI tool_calls/function wrappers, Anthropic input).
        let raw_val = unwrap_tool_envelope(raw_val)?;
        observation.raw_name = raw_val
            .get("name")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
            .or_else(|| {
                raw_val
                    .get("recipient_name")
                    .and_then(|value| value.as_str())
                    .map(|value| value.to_string())
            })
            .or_else(|| {
                raw_val
                    .get("tool")
                    .and_then(|value| value.as_str())
                    .map(|value| value.to_string())
            });

        Self::normalize_value_with_observation(raw_val, observation)
    }

    fn normalize_value_with_observation(
        mut raw_val: Value,
        mut observation: ToolNormalizationObservation,
    ) -> Result<ToolNormalizationResult> {
        // 3. Heuristic Normalization (Fix "parameters" vs "arguments", Infer missing names)
        // Use flags to avoid borrowing raw_val immutably and mutably at the same time
        let mut needs_wrap_sys = false;
        let mut needs_wrap_chat = false;
        let mut needs_wrap_nav = false;
        let mut needs_wrap_complete = false;
        let mut completion_result: Option<String> = None;
        let mut single_key_tool_wrapper: Option<(String, Value, bool)> = None;
        let mut browser_synthetic_click_present = false;
        let mut browser_synthetic_click_args: Option<Value> = None;

        if let Some(map) = raw_val.as_object_mut() {
            if let Some(tool_name) = map.get("tool").and_then(|value| value.as_str()) {
                let tool_canonical = canonical_deterministic_tool_name(tool_name)
                    .unwrap_or_else(|| tool_name.trim().to_string());
                let current_name = map
                    .get("name")
                    .and_then(|value| value.as_str())
                    .map(str::trim)
                    .unwrap_or_default();
                let current_is_known = canonical_deterministic_tool_name(current_name).is_some();
                if !tool_canonical.is_empty() {
                    if !map.contains_key("name") {
                        observation.push_label("tool_to_name");
                        map.insert("name".to_string(), json!(tool_canonical));
                    } else if !current_is_known && current_name != tool_canonical {
                        observation.push_label("tool_field_preferred_over_name");
                        map.insert("name".to_string(), json!(tool_canonical));
                    }
                }
            }

            // [FIX] Handle "recipient_name" hallucination (common in some fine-tunes)
            // Some models output {"recipient_name": "functions.computer", ...} instead of {"name": ...}
            if !map.contains_key("name") {
                if let Some(rn) = map.remove("recipient_name") {
                    observation.push_label("recipient_name_alias");
                    map.insert("name".to_string(), rn);
                }
            }

            if !map.contains_key("name") {
                if let Some(tool_name) = map.remove("tool") {
                    observation.push_label("tool_to_name");
                    map.insert("name".to_string(), tool_name);
                }
            }

            if !map.contains_key("name") && map.len() == 1 {
                if let Some((tool_key, tool_args)) = map.iter().next() {
                    if looks_like_single_key_tool_wrapper(tool_key, tool_args) {
                        let wrapped_name = canonical_deterministic_tool_name(tool_key)
                            .unwrap_or_else(|| tool_key.trim().to_string());
                        let wrapped_args = tool_args.clone();
                        let canonicalized = wrapped_name != tool_key.trim();
                        single_key_tool_wrapper = Some((wrapped_name, wrapped_args, canonicalized));
                    }
                }
            }

            // [FIX] Handle "functions." prefix hallucination (e.g. "functions.chat__reply")
            if let Some(name_val) = map.get("name") {
                if let Some(name_str) = name_val.as_str() {
                    if name_str.starts_with("functions.") {
                        let fixed_name = name_str.strip_prefix("functions.").unwrap();
                        observation.push_label("functions_prefix_stripped");
                        map.insert("name".to_string(), json!(fixed_name));
                    }
                }
            }

            // Canonicalize deterministic tool aliases (for example sys_exec -> shell__run)
            // before schema deserialization so built-ins stay on typed execution paths.
            if let Some(name_val) = map.get("name") {
                if let Some(name_str) = name_val.as_str() {
                    if let Some(canonical_name) = canonical_deterministic_tool_name(name_str) {
                        if canonical_name != name_str {
                            observation.push_label("deterministic_alias_canonicalized");
                        }
                        map.insert("name".to_string(), json!(canonical_name));
                    }
                }
            }

            if map
                .get("name")
                .and_then(|value| value.as_str())
                .is_some_and(|name| name.eq_ignore_ascii_case("file__list"))
            {
                let promote_to_search = map
                    .get("arguments")
                    .or_else(|| map.get("args"))
                    .and_then(|value| value.as_object())
                    .is_some_and(|arguments| {
                        arguments.contains_key("pattern")
                            || arguments.contains_key("query")
                            || arguments.contains_key("regex")
                            || arguments.contains_key("glob")
                            || arguments.contains_key("filter")
                            || arguments.contains_key("filename_pattern")
                            || arguments.contains_key("file_pattern")
                    });
                if promote_to_search {
                    observation.push_label("file_list_promoted_to_search");
                    map.insert("name".to_string(), json!("file__search"));
                }
            }

            if !map.contains_key("name") {
                if map.contains_key("command") {
                    needs_wrap_sys = true;
                } else if map.contains_key("message") && map.len() == 1 {
                    needs_wrap_chat = true;
                } else if map.contains_key("url") && map.len() == 1 {
                    needs_wrap_nav = true;
                } else if let Some(result) = map.get("result").and_then(|v| v.as_str()) {
                    let trimmed = result.trim();
                    if !trimmed.is_empty() {
                        needs_wrap_complete = true;
                        completion_result = Some(trimmed.to_string());
                    }
                }
            }
        }

        if needs_wrap_sys {
            observation.push_label("flat_payload_wrapped_shell_run");
            // It's likely a shell__run call provided flat
            // Wrap it: { "name": "shell__run", "arguments": { "command": ..., ... } }
            let args = raw_val;
            let mut new_map = serde_json::Map::new();
            new_map.insert("name".to_string(), json!("shell__run"));
            new_map.insert("arguments".to_string(), args);
            raw_val = Value::Object(new_map);
        } else if needs_wrap_chat {
            observation.push_label("flat_payload_wrapped_chat_reply");
            let args = raw_val;
            let mut new_map = serde_json::Map::new();
            new_map.insert("name".to_string(), json!("chat__reply"));
            new_map.insert("arguments".to_string(), args);
            raw_val = Value::Object(new_map);
        } else if needs_wrap_nav {
            observation.push_label("flat_payload_wrapped_browser_navigate");
            let args = raw_val;
            let mut new_map = serde_json::Map::new();
            new_map.insert("name".to_string(), json!("browser__navigate"));
            new_map.insert("arguments".to_string(), args);
            raw_val = Value::Object(new_map);
        } else if needs_wrap_complete {
            observation.push_label("flat_payload_wrapped_agent_complete");
            let result = completion_result.unwrap_or_else(|| "Completed.".to_string());
            let mut new_map = serde_json::Map::new();
            new_map.insert("name".to_string(), json!("agent__complete"));
            new_map.insert("arguments".to_string(), json!({ "result": result }));
            raw_val = Value::Object(new_map);
        } else if let Some((wrapped_name, wrapped_args, canonicalized)) = single_key_tool_wrapper {
            observation.push_label("single_key_tool_wrapper_unwrapped");
            if canonicalized {
                observation.push_label("deterministic_alias_canonicalized");
            }
            if single_key_tool_wrapper_records_raw_name(&wrapped_name) {
                observation.raw_name = Some(wrapped_name.clone());
            }
            let mut new_map = serde_json::Map::new();
            new_map.insert("name".to_string(), json!(wrapped_name));
            new_map.insert("arguments".to_string(), wrapped_args);
            raw_val = Value::Object(new_map);
        }

        // Alias check (safe to do in-place if we get mut ref now)
        let mut install_package_args: Option<Value> = None;
        let mut edit_line_args: Option<Value> = None;

        let mut ui_click_component_args: Option<Value> = None;
        let mut ui_click_component_present = false;

        let mut ui_click_args: Option<Value> = None;
        let mut ui_click_present = false;

        let mut ui_click_element_args: Option<Value> = None;
        let mut ui_click_element_present = false;

        let mut ui_type_args: Option<Value> = None;
        let mut ui_type_present = false;

        let mut ui_scroll_args: Option<Value> = None;
        let mut ui_scroll_present = false;

        let mut net_fetch_args: Option<Value> = None;
        let mut net_fetch_present = false;
        let mut file_search_args: Option<Value> = None;
        let mut file_search_present = false;
        let mut browser_click_element_args: Option<Value> = None;
        let mut browser_click_element_present = false;
        let mut browser_key_args: Option<Value> = None;
        let mut browser_key_present = false;
        let mut browser_wait_args: Option<Value> = None;
        let mut browser_wait_present = false;
        if let Some(map_mut) = raw_val.as_object_mut() {
            if let Some(params) = map_mut.get("parameters").cloned() {
                observation.push_label("parameters_to_arguments");
                map_mut.insert("arguments".to_string(), params);
            }

            if !map_mut.contains_key("arguments") {
                if let Some(args) = map_mut.remove("args") {
                    observation.push_label("args_to_arguments");
                    map_mut.insert("arguments".to_string(), args);
                }
            }

            // Anthropic-style alias: {"name":"...", "input": {...}}
            if !map_mut.contains_key("arguments") {
                if let Some(input) = map_mut.remove("input") {
                    observation.push_label("input_to_arguments");
                    map_mut.insert("arguments".to_string(), input);
                }
            }

            if !map_mut.contains_key("arguments") {
                let deterministic_name = map_mut
                    .get("name")
                    .and_then(|value| value.as_str())
                    .filter(|name| is_deterministic_tool_name(name))
                    .map(str::to_string);
                if deterministic_name.is_some() {
                    let argument_keys: Vec<String> = map_mut
                        .keys()
                        .filter(|key| !is_tool_metadata_key(key))
                        .cloned()
                        .collect();
                    if !argument_keys.is_empty() {
                        let mut arguments = serde_json::Map::new();
                        for key in argument_keys {
                            if let Some(value) = map_mut.remove(&key) {
                                arguments.insert(key, value);
                            }
                        }
                        observation.push_label("top_level_fields_to_arguments");
                        map_mut.insert("arguments".to_string(), Value::Object(arguments));
                    }
                }
            }

            // OpenAI-style: arguments may arrive as a JSON string.
            let args_string = map_mut
                .get("arguments")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            if let Some(raw_args) = args_string {
                observation.push_label("arguments_string_decoded");
                let trimmed = raw_args.trim();
                let parsed: Value = if trimmed.is_empty() {
                    json!({})
                } else {
                    serde_json::from_str(trimmed).map_err(|e| {
                        anyhow!(
                            "Schema Validation Error: arguments string must be valid JSON: {}",
                            e
                        )
                    })?
                };
                if !parsed.is_object() {
                    return Err(anyhow!(
                        "Schema Validation Error: arguments must decode to a JSON object."
                    ));
                }
                map_mut.insert("arguments".to_string(), parsed);
            }

            if let Some(name) = map_mut.get("name").and_then(|n| n.as_str()) {
                if name == "package__install" {
                    install_package_args = Some(
                        map_mut
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                    );
                }
                if name == "file__replace_line" {
                    edit_line_args = Some(
                        map_mut
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                    );
                }
                if name == "screen__click" {
                    ui_click_component_present = true;
                    ui_click_component_args = Some(
                        map_mut
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                    );
                }
                if name == "ui__click" {
                    ui_click_present = true;
                    ui_click_args = Some(
                        map_mut
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                    );
                }
                if name == "screen__click" {
                    ui_click_element_present = true;
                    ui_click_element_args = Some(
                        map_mut
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                    );
                }
                if name == "ui__type" {
                    ui_type_present = true;
                    ui_type_args = Some(
                        map_mut
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                    );
                }
                if name == "ui__scroll" {
                    ui_scroll_present = true;
                    ui_scroll_args = Some(
                        map_mut
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                    );
                }
                if name == "http__fetch" {
                    net_fetch_present = true;
                    net_fetch_args = Some(
                        map_mut
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                    );
                }
                if name == "file__search" {
                    file_search_present = true;
                    file_search_args = Some(
                        map_mut
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                    );
                }
                if name == "browser__click" {
                    browser_click_element_present = true;
                    browser_click_element_args = Some(
                        map_mut
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                    );
                }
                if name == "browser__press_key" {
                    browser_key_present = true;
                    browser_key_args = Some(
                        map_mut
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                    );
                }
                if name == "browser__wait" {
                    browser_wait_present = true;
                    browser_wait_args = Some(
                        map_mut
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                    );
                }
                if name == "browser__click_at" {
                    browser_synthetic_click_present = true;
                    browser_synthetic_click_args = Some(
                        map_mut
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                    );
                }
            }

            // [NEW] Handle synthetic click aliases if LLM gets lazy
            if let Some(name) = map_mut.get("name").and_then(|n| n.as_str()) {
                if name == "browser__move_pointer" {
                    let mut normalized = false;
                    if let Some(args) = map_mut.get_mut("arguments") {
                        if let Some(x) = args.get("x").and_then(|v| v.as_f64()) {
                            let normalized_x = json!(x);
                            if args.get("x") != Some(&normalized_x) {
                                normalized = true;
                            }
                            args["x"] = normalized_x;
                        }
                        if let Some(y) = args.get("y").and_then(|v| v.as_f64()) {
                            let normalized_y = json!(y);
                            if args.get("y") != Some(&normalized_y) {
                                normalized = true;
                            }
                            args["y"] = normalized_y;
                        }
                    }
                    if normalized {
                        observation.push_label("browser_move_pointer_coordinates_normalized");
                    }
                } else if name == "browser__scroll" {
                    // Ensure deltas are integers when model returns float JSON numbers.
                    let mut normalized = false;
                    if let Some(args) = map_mut.get_mut("arguments") {
                        if let Some(delta_x) = args.get("delta_x").and_then(|v| v.as_f64()) {
                            let normalized_delta_x = json!(delta_x as i32);
                            if args.get("delta_x") != Some(&normalized_delta_x) {
                                normalized = true;
                            }
                            args["delta_x"] = normalized_delta_x;
                        }
                        if let Some(delta_y) = args.get("delta_y").and_then(|v| v.as_f64()) {
                            let normalized_delta_y = json!(delta_y as i32);
                            if args.get("delta_y") != Some(&normalized_delta_y) {
                                normalized = true;
                            }
                            args["delta_y"] = normalized_delta_y;
                        }
                    }
                    if normalized {
                        observation.push_label("browser_scroll_deltas_normalized");
                    }
                }
            }
        }

        if let Some(install_args) = install_package_args {
            let normalized = normalize_install_package_arguments(&install_args)?;
            if normalized != install_args {
                observation.push_label("package_install_arguments_normalized");
            }
            raw_val = json!({
                "name": "package__install",
                "arguments": normalized,
            });
        } else if let Some(edit_args) = edit_line_args {
            observation.push_label("file_replace_line_lowered_to_file_write");
            raw_val = lower_edit_line_to_fs_write(&edit_args)?;
        } else if ui_click_component_present {
            let args = ui_click_component_args.unwrap_or_else(|| json!({}));
            let normalized = normalize_ui_click_component_arguments(&args)?;
            if normalized != args {
                observation.push_label("screen_click_arguments_normalized");
            }
            raw_val = json!({
                "name": "screen__click",
                "arguments": normalized,
            });
        } else if ui_click_present {
            let args = ui_click_args.unwrap_or_else(|| json!({}));
            observation.push_label(
                if args.get("coordinate").is_some()
                    || (args.get("x").is_some() && args.get("y").is_some())
                {
                    "ui_click_to_screen_click_at"
                } else {
                    "ui_click_to_screen_click"
                },
            );
            raw_val = normalize_ui_click_arguments(&args)?;
        } else if ui_click_element_present {
            let args = ui_click_element_args.unwrap_or_else(|| json!({}));
            let normalized = normalize_ui_click_component_arguments(&args)?;
            if normalized != args {
                observation.push_label("screen_click_arguments_normalized");
            }
            raw_val = json!({
                "name": "screen__click",
                "arguments": normalized,
            });
        } else if ui_type_present {
            let args = ui_type_args.unwrap_or_else(|| json!({}));
            let normalized = normalize_ui_type_arguments(&args)?;
            observation.push_label("ui_type_to_screen_type");
            raw_val = json!({
                "name": "screen__type",
                "arguments": normalized,
            });
        } else if ui_scroll_present {
            let args = ui_scroll_args.unwrap_or_else(|| json!({}));
            let normalized = normalize_ui_scroll_arguments(&args)?;
            observation.push_label("ui_scroll_to_screen_scroll");
            raw_val = json!({
                "name": "screen__scroll",
                "arguments": normalized,
            });
        } else if net_fetch_present {
            let args = net_fetch_args.unwrap_or_else(|| json!({}));
            let normalized = normalize_net_fetch_arguments(&args)?;
            if normalized != args {
                observation.push_label("http_fetch_arguments_normalized");
            }
            raw_val = json!({
                "name": "http__fetch",
                "arguments": normalized,
            });
        } else if file_search_present {
            let args = file_search_args.unwrap_or_else(|| json!({}));
            if args.get("path").is_none()
                && args.get("root").is_none()
                && args.get("directory").is_none()
            {
                observation.push_label("file_search_default_root_path");
            }
            let normalized = normalize_file_search_arguments(&args)?;
            if normalized != args {
                observation.push_label("file_search_arguments_normalized");
            }
            raw_val = json!({
                "name": "file__search",
                "arguments": normalized,
            });
        } else if browser_click_element_present {
            let args = browser_click_element_args.unwrap_or_else(|| json!({}));
            let normalized = normalize_browser_click_element_arguments(&args)?;
            if normalized != args {
                observation.push_label("browser_click_arguments_normalized");
            }
            raw_val = json!({
                "name": "browser__click",
                "arguments": normalized,
            });
        } else if browser_key_present {
            let args = browser_key_args.unwrap_or_else(|| json!({}));
            let normalized = normalize_browser_key_arguments(&args)?;
            if normalized != args {
                observation.push_label("browser_press_key_arguments_normalized");
            }
            raw_val = json!({
                "name": "browser__press_key",
                "arguments": normalized,
            });
        } else if browser_wait_present {
            let args = browser_wait_args.unwrap_or_else(|| json!({}));
            let normalized = normalize_browser_wait_arguments(&args)?;
            if normalized != args {
                observation.push_label("browser_wait_arguments_normalized");
            }
            raw_val = json!({
                "name": "browser__wait",
                "arguments": normalized,
            });
        } else if browser_synthetic_click_present {
            let args = browser_synthetic_click_args.unwrap_or_else(|| json!({}));
            let normalized = normalize_browser_synthetic_click_arguments(&args)?;
            if normalized != args {
                observation.push_label("browser_click_at_arguments_normalized");
            }
            raw_val = json!({
                "name": "browser__click_at",
                "arguments": normalized,
            });
        }

        // 4. Strict Typed Deserialization
        // This validates the structure matches AgentTool definitions exactly.
        let tool_call: AgentTool = serde_json::from_value(raw_val)
            .map_err(|e| anyhow!("Schema Validation Error: {}", e))?;

        // Guardrail: `AgentTool` has an untagged `Dynamic` catch-all, so serde will happily
        // deserialize malformed built-in tool calls into `Dynamic`. That is dangerous because
        // it routes deterministic tools through the MCP executor path (tool-not-found loops)
        // instead of surfacing a schema error the model can correct.
        if let AgentTool::Dynamic(val) = &tool_call {
            let name = val
                .get("name")
                .and_then(|n| n.as_str())
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    anyhow!(
                        "Schema Validation Error: dynamic tool calls require a non-empty string 'name'."
                    )
                })?;

            let normalized = name
                .trim_matches(|ch: char| ch == '"' || ch == '\'')
                .trim()
                .to_ascii_lowercase();
            if normalized.is_empty()
                || normalized == "unknown"
                || normalized == "custom(unknown)"
                || normalized == "custom(\"unknown\")"
                || normalized == "custom('unknown')"
            {
                return Err(anyhow!(
                    "Schema Validation Error: dynamic tool name '{}' is invalid.",
                    name
                ));
            }

            if is_deterministic_tool_name(name) {
                return Err(anyhow!(
                    "Schema Validation Error: '{}' is a built-in tool but arguments did not match its typed schema.",
                    name
                ));
            }
        }

        observation.normalized_name = normalized_tool_name(&tool_call);

        Ok(ToolNormalizationResult {
            tool: tool_call,
            observation,
        })
    }
}
