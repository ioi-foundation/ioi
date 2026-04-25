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

fn rejected_legacy_tool_name(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    normalized.starts_with("functions.")
        || normalized.contains("::")
        || matches!(
            normalized.as_str(),
            "computer" | "sys_exec" | "filesystem__list_dir"
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
        // 1. Sanitize provider output without inferring an executable tool.
        let json_str = sanitize_json(raw_llm_output);
        let raw_val: Value =
            serde_json::from_str(&json_str).map_err(|e| anyhow!("JSON Syntax Error: {}", e))?;

        // 2. Unwrap bounded provider envelopes. This may decode OpenAI function
        // arguments, but it must still yield the canonical { name, arguments } shape.
        let raw_val = unwrap_tool_envelope(raw_val)?;
        observation.raw_name = raw_val
            .get("name")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());

        Self::normalize_value_with_observation(raw_val, observation)
    }

    fn normalize_value_with_observation(
        mut raw_val: Value,
        mut observation: ToolNormalizationObservation,
    ) -> Result<ToolNormalizationResult> {
        let mut browser_synthetic_click_present = false;
        let mut browser_synthetic_click_args: Option<Value> = None;

        if let Some(map) = raw_val.as_object_mut() {
            // Canonicalize exact built-in names only. Legacy aliases and inferred
            // wrappers are intentionally rejected at the executable boundary.
            if let Some(name_val) = map.get("name") {
                if let Some(name_str) = name_val.as_str() {
                    let original_name = name_str.to_string();
                    if let Some(canonical_name) = canonical_deterministic_tool_name(&original_name)
                    {
                        if canonical_name != original_name {
                            observation.push_label("deterministic_alias_canonicalized");
                        }
                        map.insert("name".to_string(), json!(canonical_name));
                    }
                    if rejected_legacy_tool_name(&original_name) {
                        return Err(anyhow!(
                            "Schema Validation Error: legacy tool alias '{}' is not executable; use canonical invocation envelopes with exact tool names.",
                            original_name
                        ));
                    }
                }
            }
        }

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

            if rejected_legacy_tool_name(name) {
                return Err(anyhow!(
                    "Schema Validation Error: legacy tool alias '{}' is not executable; use canonical invocation envelopes with exact tool names.",
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
