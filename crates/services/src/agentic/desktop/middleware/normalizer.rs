use anyhow::{anyhow, Result};
use ioi_types::app::agentic::AgentTool;
use serde_json::{json, Value};

use super::builtins::is_deterministic_tool_name;
use super::coercion::{
    lower_edit_line_to_fs_write, normalize_install_package_arguments,
    normalize_net_fetch_arguments, normalize_ui_click_arguments,
    normalize_ui_click_component_arguments, normalize_ui_scroll_arguments,
    normalize_ui_type_arguments,
};
use super::envelope::{sanitize_json, unwrap_tool_envelope};
use super::ToolNormalizer;

impl ToolNormalizer {
    /// The boundary function.
    /// Input: Raw, potentially hallucinated JSON from LLM.
    /// Output: Strict Rust Type or Error.
    pub fn normalize(raw_llm_output: &str) -> Result<AgentTool> {
        // [FIX] Fast fail on empty input
        if raw_llm_output.trim().is_empty() {
            return Err(anyhow!(
                "LLM returned empty output (Possible Refusal/Filter)"
            ));
        }

        // 1. Sanitize (Remove markdown blocks, fix trailing commas)
        let json_str = sanitize_json(raw_llm_output);

        // 2. Parse Generic JSON
        let mut raw_val: Value =
            serde_json::from_str(&json_str).map_err(|e| anyhow!("JSON Syntax Error: {}", e))?;

        // 2b. Unwrap provider envelopes (OpenAI tool_calls/function wrappers, Anthropic input).
        raw_val = unwrap_tool_envelope(raw_val)?;

        // 3. Heuristic Normalization (Fix "parameters" vs "arguments", Infer missing names)
        // Use flags to avoid borrowing raw_val immutably and mutably at the same time
        let mut needs_wrap_sys = false;
        let mut needs_wrap_chat = false;
        let mut needs_wrap_nav = false;

        if let Some(map) = raw_val.as_object_mut() {
            // [FIX] Handle "recipient_name" hallucination (common in some fine-tunes)
            // Some models output {"recipient_name": "functions.computer", ...} instead of {"name": ...}
            if !map.contains_key("name") {
                if let Some(rn) = map.remove("recipient_name") {
                    map.insert("name".to_string(), rn);
                }
            }

            // [FIX] Handle "functions." prefix hallucination (e.g. "functions.chat__reply")
            if let Some(name_val) = map.get("name") {
                if let Some(name_str) = name_val.as_str() {
                    if name_str.starts_with("functions.") {
                        let fixed_name = name_str.strip_prefix("functions.").unwrap();
                        map.insert("name".to_string(), json!(fixed_name));
                    }
                }
            }

            if !map.contains_key("name") {
                if map.contains_key("command") {
                    needs_wrap_sys = true;
                } else if map.contains_key("message") && map.len() == 1 {
                    needs_wrap_chat = true;
                } else if map.contains_key("url") && map.len() == 1 {
                    needs_wrap_nav = true;
                }
            }
        }

        if needs_wrap_sys {
            // It's likely a sys__exec call provided flat
            // Wrap it: { "name": "sys__exec", "arguments": { "command": ..., ... } }
            let args = raw_val;
            let mut new_map = serde_json::Map::new();
            new_map.insert("name".to_string(), json!("sys__exec"));
            new_map.insert("arguments".to_string(), args);
            raw_val = Value::Object(new_map);
        } else if needs_wrap_chat {
            let args = raw_val;
            let mut new_map = serde_json::Map::new();
            new_map.insert("name".to_string(), json!("chat__reply"));
            new_map.insert("arguments".to_string(), args);
            raw_val = Value::Object(new_map);
        } else if needs_wrap_nav {
            let args = raw_val;
            let mut new_map = serde_json::Map::new();
            new_map.insert("name".to_string(), json!("browser__navigate"));
            new_map.insert("arguments".to_string(), args);
            raw_val = Value::Object(new_map);
        } else {
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
            if let Some(map_mut) = raw_val.as_object_mut() {
                if let Some(params) = map_mut.get("parameters").cloned() {
                    map_mut.insert("arguments".to_string(), params);
                }

                // Anthropic-style alias: {"name":"...", "input": {...}}
                if !map_mut.contains_key("arguments") {
                    if let Some(input) = map_mut.remove("input") {
                        map_mut.insert("arguments".to_string(), input);
                    }
                }

                // OpenAI-style: arguments may arrive as a JSON string.
                let args_string = map_mut
                    .get("arguments")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                if let Some(raw_args) = args_string {
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
                    if name == "sys__install_package" {
                        install_package_args = Some(
                            map_mut
                                .get("arguments")
                                .cloned()
                                .unwrap_or_else(|| json!({})),
                        );
                    }
                    if name == "filesystem__edit_line" {
                        edit_line_args = Some(
                            map_mut
                                .get("arguments")
                                .cloned()
                                .unwrap_or_else(|| json!({})),
                        );
                    }
                    if name == "ui__click_component" {
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
                    if name == "ui__click_element" {
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
                    if name == "net__fetch" {
                        net_fetch_present = true;
                        net_fetch_args = Some(
                            map_mut
                                .get("arguments")
                                .cloned()
                                .unwrap_or_else(|| json!({})),
                        );
                    }
                }

                // [NEW] Handle synthetic click aliases if LLM gets lazy
                if let Some(name) = map_mut.get("name").and_then(|n| n.as_str()) {
                    if name == "browser__synthetic_click" {
                        // Ensure arguments are numbers (LLM might pass strings)
                        if let Some(args) = map_mut.get_mut("arguments") {
                            if let Some(x) = args.get("x").and_then(|v| v.as_f64()) {
                                args["x"] = json!(x as u32);
                            }
                            if let Some(y) = args.get("y").and_then(|v| v.as_f64()) {
                                args["y"] = json!(y as u32);
                            }
                        }
                    } else if name == "browser__scroll" {
                        // Ensure deltas are integers when model returns float JSON numbers.
                        if let Some(args) = map_mut.get_mut("arguments") {
                            if let Some(delta_x) = args.get("delta_x").and_then(|v| v.as_f64()) {
                                args["delta_x"] = json!(delta_x as i32);
                            }
                            if let Some(delta_y) = args.get("delta_y").and_then(|v| v.as_f64()) {
                                args["delta_y"] = json!(delta_y as i32);
                            }
                        }
                    }
                }
            }

            if let Some(install_args) = install_package_args {
                let normalized = normalize_install_package_arguments(&install_args)?;
                raw_val = json!({
                    "name": "sys__install_package",
                    "arguments": normalized,
                });
            } else if let Some(edit_args) = edit_line_args {
                raw_val = lower_edit_line_to_fs_write(&edit_args)?;
            } else if ui_click_component_present {
                let args = ui_click_component_args.unwrap_or_else(|| json!({}));
                let normalized = normalize_ui_click_component_arguments(&args)?;
                raw_val = json!({
                    "name": "gui__click_element",
                    "arguments": normalized,
                });
            } else if ui_click_present {
                let args = ui_click_args.unwrap_or_else(|| json!({}));
                raw_val = normalize_ui_click_arguments(&args)?;
            } else if ui_click_element_present {
                let args = ui_click_element_args.unwrap_or_else(|| json!({}));
                let normalized = normalize_ui_click_component_arguments(&args)?;
                raw_val = json!({
                    "name": "gui__click_element",
                    "arguments": normalized,
                });
            } else if ui_type_present {
                let args = ui_type_args.unwrap_or_else(|| json!({}));
                let normalized = normalize_ui_type_arguments(&args)?;
                raw_val = json!({
                    "name": "gui__type",
                    "arguments": normalized,
                });
            } else if ui_scroll_present {
                let args = ui_scroll_args.unwrap_or_else(|| json!({}));
                let normalized = normalize_ui_scroll_arguments(&args)?;
                raw_val = json!({
                    "name": "gui__scroll",
                    "arguments": normalized,
                });
            } else if net_fetch_present {
                let args = net_fetch_args.unwrap_or_else(|| json!({}));
                let normalized = normalize_net_fetch_arguments(&args)?;
                raw_val = json!({
                    "name": "net__fetch",
                    "arguments": normalized,
                });
            }
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

        Ok(tool_call)
    }
}
