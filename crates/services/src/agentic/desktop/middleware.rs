// Path: crates/services/src/agentic/desktop/middleware.rs

use anyhow::{anyhow, Result};
use ioi_types::app::agentic::AgentTool;
use serde_json::{json, Value};

// [FIX] Renamed to match call site in step/mod.rs
pub fn normalize_tool_call(raw_llm_output: &str) -> Result<AgentTool> {
    ToolNormalizer::normalize(raw_llm_output)
}

pub struct ToolNormalizer;

fn is_deterministic_tool_name(name: &str) -> bool {
    matches!(
        name,
        "computer"
            | "filesystem__write_file"
            | "filesystem__patch"
            | "filesystem__read_file"
            | "filesystem__list_directory"
            | "filesystem__search"
            | "filesystem__move_path"
            | "filesystem__copy_path"
            | "filesystem__delete_path"
            | "filesystem__create_directory"
            | "sys__exec"
            | "sys__exec_session"
            | "sys__exec_session_reset"
            | "sys__install_package"
            | "sys__change_directory"
            | "browser__navigate"
            | "browser__snapshot"
            | "browser__click"
            | "browser__click_element"
            | "browser__synthetic_click"
            | "browser__scroll"
            | "browser__type"
            | "browser__key"
            | "web__search"
            | "web__read"
            | "memory__search"
            | "memory__inspect"
            | "gui__click"
            | "gui__type"
            | "gui__scroll"
            | "gui__click_element"
            | "ui__find"
            | "os__focus_window"
            | "os__copy"
            | "os__paste"
            | "os__launch_app"
            | "chat__reply"
            | "agent__delegate"
            | "agent__await_result"
            | "agent__pause"
            | "agent__complete"
            | "commerce__checkout"
            | "system__fail"
    )
}

fn default_install_manager() -> &'static str {
    if cfg!(target_os = "macos") {
        "brew"
    } else if cfg!(target_os = "windows") {
        "winget"
    } else {
        "apt-get"
    }
}

fn normalize_install_manager(raw: Option<&str>) -> Result<String> {
    let manager = raw
        .map(|m| m.trim().to_ascii_lowercase())
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| default_install_manager().to_string());

    match manager.as_str() {
        "apt" | "apt-get" => Ok("apt-get".to_string()),
        "brew" => Ok("brew".to_string()),
        "pip" | "pip3" => Ok("pip".to_string()),
        "npm" => Ok("npm".to_string()),
        "pnpm" => Ok("pnpm".to_string()),
        "cargo" => Ok("cargo".to_string()),
        "winget" => Ok("winget".to_string()),
        "choco" | "chocolatey" => Ok("choco".to_string()),
        "yum" => Ok("yum".to_string()),
        "dnf" => Ok("dnf".to_string()),
        other => Err(anyhow!(
            "Unsupported package manager '{}'. Supported: apt-get, brew, pip, npm, pnpm, cargo, winget, choco, yum, dnf.",
            other
        )),
    }
}

fn is_safe_package_identifier(package: &str) -> bool {
    !package.is_empty()
        && package.len() <= 128
        && package.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '@' | '/' | ':')
        })
}

fn normalize_install_package_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments
        .as_object()
        .ok_or_else(|| anyhow!("sys__install_package arguments must be an object"))?;

    let package = args_obj
        .get("package")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("sys__install_package requires a non-empty 'package' field"))?;

    if !is_safe_package_identifier(package) {
        return Err(anyhow!(
            "Invalid package identifier '{}'. Use a plain package name without spaces or shell metacharacters.",
            package
        ));
    }

    let manager = normalize_install_manager(args_obj.get("manager").and_then(|v| v.as_str()))?;

    Ok(json!({
        "package": package,
        "manager": manager
    }))
}

fn lower_edit_line_to_fs_write(arguments: &Value) -> Result<Value> {
    let args_obj = arguments
        .as_object()
        .ok_or_else(|| anyhow!("filesystem__edit_line arguments must be an object"))?;

    let path = args_obj
        .get("path")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("filesystem__edit_line requires a non-empty 'path' field"))?;

    let line_number_raw = args_obj
        .get("line_number")
        .or_else(|| args_obj.get("line"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            anyhow!("filesystem__edit_line requires integer 'line_number' (or alias 'line')")
        })?;

    if line_number_raw == 0 || line_number_raw > u32::MAX as u64 {
        return Err(anyhow!(
            "filesystem__edit_line 'line_number' must be between 1 and {}",
            u32::MAX
        ));
    }

    let content = args_obj
        .get("content")
        .or_else(|| args_obj.get("text"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow!("filesystem__edit_line requires string 'content' (or alias 'text')")
        })?;

    Ok(json!({
        "name": "filesystem__write_file",
        "arguments": {
            "path": path,
            "content": content,
            "line_number": line_number_raw as u32
        }
    }))
}

fn normalize_ui_click_component_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: ui__click_component arguments must be a JSON object.")
    })?;

    let id = args_obj
        .get("id")
        .or_else(|| args_obj.get("component_id"))
        .or_else(|| args_obj.get("componentId"))
        .or_else(|| args_obj.get("element_id"))
        .or_else(|| args_obj.get("elementId"))
        .or_else(|| args_obj.get("target_id"))
        .or_else(|| args_obj.get("targetId"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "Schema Validation Error: ui__click_component requires a non-empty 'id' field (aliases: component_id, element_id, target_id)."
            )
        })?;

    Ok(json!({ "id": id }))
}

fn parse_u32_like(value: &Value) -> Option<u32> {
    if let Some(raw) = value.as_u64() {
        return u32::try_from(raw).ok();
    }
    if let Some(raw) = value.as_i64() {
        if raw >= 0 && raw <= u32::MAX as i64 {
            return Some(raw as u32);
        }
        return None;
    }
    if let Some(raw) = value.as_f64() {
        if raw.is_finite() && raw >= 0.0 && raw <= (u32::MAX as f64) {
            return Some(raw.trunc() as u32);
        }
        return None;
    }
    if let Some(raw) = value.as_str() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        if let Ok(parsed) = trimmed.parse::<f64>() {
            if parsed.is_finite() && parsed >= 0.0 && parsed <= (u32::MAX as f64) {
                return Some(parsed.trunc() as u32);
            }
        }
    }
    None
}

fn parse_i32_like(value: &Value) -> Option<i32> {
    if let Some(raw) = value.as_i64() {
        if raw >= i32::MIN as i64 && raw <= i32::MAX as i64 {
            return Some(raw as i32);
        }
        return None;
    }
    if let Some(raw) = value.as_u64() {
        if raw <= i32::MAX as u64 {
            return Some(raw as i32);
        }
        return None;
    }
    if let Some(raw) = value.as_f64() {
        if raw.is_finite() && raw >= (i32::MIN as f64) && raw <= (i32::MAX as f64) {
            return Some(raw.trunc() as i32);
        }
        return None;
    }
    if let Some(raw) = value.as_str() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        if let Ok(parsed) = trimmed.parse::<f64>() {
            if parsed.is_finite() && parsed >= (i32::MIN as f64) && parsed <= (i32::MAX as f64) {
                return Some(parsed.trunc() as i32);
            }
        }
    }
    None
}

fn normalize_ui_type_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: ui__type arguments must be a JSON object.")
    })?;

    let text = args_obj
        .get("text")
        .or_else(|| args_obj.get("content"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("Schema Validation Error: ui__type requires non-empty 'text'."))?;

    if args_obj.contains_key("id")
        || args_obj.contains_key("element_id")
        || args_obj.contains_key("elementId")
        || args_obj.contains_key("target_id")
        || args_obj.contains_key("targetId")
        || args_obj.contains_key("component_id")
        || args_obj.contains_key("componentId")
    {
        return Err(anyhow!(
            "Schema Validation Error: ui__type does not support targeting by id. Use gui__click_element(id=...) first, then gui__type(text=...)."
        ));
    }

    Ok(json!({ "text": text }))
}

fn normalize_ui_scroll_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: ui__scroll arguments must be a JSON object.")
    })?;

    let delta_x = args_obj
        .get("delta_x")
        .or_else(|| args_obj.get("deltaX"))
        .or_else(|| args_obj.get("dx"))
        .and_then(parse_i32_like)
        .unwrap_or(0);

    let delta_y = args_obj
        .get("delta_y")
        .or_else(|| args_obj.get("deltaY"))
        .or_else(|| args_obj.get("dy"))
        .and_then(parse_i32_like)
        .unwrap_or(0);

    Ok(json!({ "delta_x": delta_x, "delta_y": delta_y }))
}

fn normalize_ui_click_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: ui__click arguments must be a JSON object.")
    })?;

    let has_any_id = args_obj.contains_key("id")
        || args_obj.contains_key("component_id")
        || args_obj.contains_key("componentId")
        || args_obj.contains_key("element_id")
        || args_obj.contains_key("elementId")
        || args_obj.contains_key("target_id")
        || args_obj.contains_key("targetId");

    if has_any_id {
        let normalized = normalize_ui_click_component_arguments(arguments)?;
        return Ok(json!({
            "name": "gui__click_element",
            "arguments": normalized,
        }));
    }

    let (x, y) = if let Some(coord) = args_obj.get("coordinate").and_then(|v| v.as_array()) {
        if coord.len() < 2 {
            return Err(anyhow!(
                "Schema Validation Error: ui__click 'coordinate' must be [x, y]."
            ));
        }
        let x = coord.get(0).and_then(parse_u32_like).ok_or_else(|| {
            anyhow!("Schema Validation Error: ui__click requires numeric x/y coordinates.")
        })?;
        let y = coord.get(1).and_then(parse_u32_like).ok_or_else(|| {
            anyhow!("Schema Validation Error: ui__click requires numeric x/y coordinates.")
        })?;
        (x, y)
    } else {
        let x = args_obj.get("x").and_then(parse_u32_like).ok_or_else(|| {
            anyhow!("Schema Validation Error: ui__click requires numeric 'x' and 'y'.")
        })?;
        let y = args_obj.get("y").and_then(parse_u32_like).ok_or_else(|| {
            anyhow!("Schema Validation Error: ui__click requires numeric 'x' and 'y'.")
        })?;
        (x, y)
    };

    let button = args_obj
        .get("button")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty());

    Ok(json!({
        "name": "gui__click",
        "arguments": if let Some(button) = button {
            json!({"x": x, "y": y, "button": button})
        } else {
            json!({"x": x, "y": y})
        }
    }))
}

fn normalize_net_fetch_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: net__fetch arguments must be a JSON object.")
    })?;

    let url = args_obj
        .get("url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow!("Schema Validation Error: net__fetch requires a non-empty 'url' field.")
        })?;

    let max_chars_u64 = args_obj
        .get("max_chars")
        .or_else(|| args_obj.get("maxChars"))
        .and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f.max(0.0) as u64)));

    Ok(if let Some(max_chars) = max_chars_u64 {
        json!({ "url": url, "max_chars": max_chars })
    } else {
        json!({ "url": url })
    })
}

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
        let json_str = Self::sanitize_json(raw_llm_output);

        // 2. Parse Generic JSON
        let mut raw_val: Value =
            serde_json::from_str(&json_str).map_err(|e| anyhow!("JSON Syntax Error: {}", e))?;

        // 2b. Unwrap provider envelopes (OpenAI tool_calls/function wrappers, Anthropic input).
        raw_val = Self::unwrap_tool_envelope(raw_val)?;

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
            let args = raw_val; // Move
            let mut new_map = serde_json::Map::new();
            new_map.insert("name".to_string(), json!("sys__exec"));
            new_map.insert("arguments".to_string(), args);
            raw_val = Value::Object(new_map);
        } else if needs_wrap_chat {
            let args = raw_val; // Move
            let mut new_map = serde_json::Map::new();
            new_map.insert("name".to_string(), json!("chat__reply"));
            new_map.insert("arguments".to_string(), args);
            raw_val = Value::Object(new_map);
        } else if needs_wrap_nav {
            let args = raw_val; // Move
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
                    .map(|s| s.to_string());
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
            if val.get("name").and_then(|n| n.as_str()) == Some("net__fetch") {
                let args = val.get("arguments").cloned().unwrap_or_else(|| json!({}));
                let _ = normalize_net_fetch_arguments(&args)?;
            } else if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                if is_deterministic_tool_name(name) {
                    return Err(anyhow!(
                        "Schema Validation Error: '{}' is a built-in tool but arguments did not match its typed schema.",
                        name
                    ));
                }
            }
        }

        Ok(tool_call)
    }

    fn unwrap_tool_envelope(raw_val: Value) -> Result<Value> {
        let mut current = raw_val;

        // Peel a small bounded set of wrappers deterministically.
        for _ in 0..4 {
            let Some(map) = current.as_object() else {
                break;
            };

            // OpenAI: {"tool_calls":[{...}]} (we only take the first tool call in this slice)
            if let Some(tool_calls) = map.get("tool_calls").and_then(|v| v.as_array()) {
                if let Some(first) = tool_calls.first() {
                    current = first.clone();
                    continue;
                }
            }

            // Generic: {"tool_call": {...}}
            if let Some(tool_call) = map.get("tool_call") {
                current = tool_call.clone();
                continue;
            }

            // OpenAI: {"type":"function","function":{"name":"...","arguments":"{...}"}} (or arguments object)
            let has_name = map.get("name").and_then(|v| v.as_str()).is_some();
            if !has_name {
                if let Some(func) = map.get("function").and_then(|v| v.as_object()) {
                    let name = func
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .ok_or_else(|| {
                            anyhow!("Schema Validation Error: missing tool function name")
                        })?
                        .to_string();

                    let args = func
                        .get("arguments")
                        .cloned()
                        .or_else(|| func.get("input").cloned())
                        .unwrap_or_else(|| json!({}));

                    let args = if let Some(arg_str) = args.as_str() {
                        let trimmed = arg_str.trim();
                        if trimmed.is_empty() {
                            json!({})
                        } else {
                            serde_json::from_str::<Value>(trimmed).map_err(|e| {
                                anyhow!(
                                    "Schema Validation Error: function.arguments string must be valid JSON: {}",
                                    e
                                )
                            })?
                        }
                    } else {
                        args
                    };

                    if !args.is_object() {
                        return Err(anyhow!(
                            "Schema Validation Error: function.arguments must be a JSON object."
                        ));
                    }

                    current = json!({
                        "name": name,
                        "arguments": args
                    });
                    continue;
                }
            }

            break;
        }

        Ok(current)
    }

    fn sanitize_json(input: &str) -> String {
        let trimmed = input.trim();
        // Check for markdown code blocks
        if trimmed.starts_with("```") {
            let lines: Vec<&str> = trimmed.lines().collect();
            // Remove first line (```json or ```) and last line (```) if valid
            if lines.len() >= 2 && lines.last().unwrap().trim().starts_with("```") {
                return lines[1..lines.len() - 1].join("\n");
            }
        }
        // Also handle raw strings that might just have the json prefix without backticks
        if let Some(json_start) = trimmed.strip_prefix("json") {
            return json_start.to_string();
        }

        input.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::agentic::{AgentTool, ComputerAction};

    #[test]
    fn test_normalize_clean_json() {
        let input = r#"{"name": "computer", "arguments": {"action": "screenshot"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::Computer(ComputerAction::Screenshot) => {}
            _ => panic!("Wrong tool type"),
        }
    }

    #[test]
    fn test_normalize_markdown() {
        let input = "```json\n{\"name\": \"sys__exec\", \"arguments\": {\"command\": \"ls\"}}\n```";
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::SysExec { command, .. } => assert_eq!(command, "ls"),
            _ => panic!("Wrong tool type"),
        }
    }

    #[test]
    fn test_normalize_openai_tool_calls_wrapper_with_string_arguments() {
        let input = r#"{
          "tool_calls": [
            {
              "id": "call_1",
              "type": "function",
              "function": {
                "name": "sys__exec",
                "arguments": "{\"command\":\"ls\",\"args\":[]}"
              }
            }
          ]
        }"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::SysExec { command, args, .. } => {
                assert_eq!(command, "ls");
                assert!(args.is_empty());
            }
            _ => panic!("Wrong tool type"),
        }
    }

    #[test]
    fn test_normalize_openai_function_wrapper_with_object_arguments() {
        let input = r#"{
          "type": "function",
          "function": {
            "name": "browser__navigate",
            "arguments": { "url": "https://example.com" }
          }
        }"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::BrowserNavigate { url } => assert_eq!(url, "https://example.com"),
            _ => panic!("Wrong tool type"),
        }
    }

    #[test]
    fn test_normalize_anthropic_input_alias() {
        let input = r#"{"name":"sys__exec","input":{"command":"echo","args":["hi"]}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::SysExec { command, args, .. } => {
                assert_eq!(command, "echo");
                assert_eq!(args, vec!["hi".to_string()]);
            }
            _ => panic!("Wrong tool type"),
        }
    }

    #[test]
    fn test_normalize_arguments_json_string() {
        let input = r#"{"name":"sys__exec","arguments":"{\"command\":\"pwd\"}"}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::SysExec { command, .. } => assert_eq!(command, "pwd"),
            _ => panic!("Wrong tool type"),
        }
    }

    #[test]
    fn test_normalize_parameters_alias() {
        // LLM often outputs "parameters" instead of "arguments"
        let input = r#"{"name": "gui__type", "parameters": {"text": "hello"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::GuiType { text } => assert_eq!(text, "hello"),
            _ => panic!("Wrong tool type"),
        }
    }

    #[test]
    fn test_normalize_functions_prefix() {
        // LLM outputs "functions.chat__reply"
        let input = r#"{"name": "functions.chat__reply", "arguments": {"message": "hello"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::ChatReply { message } => assert_eq!(message, "hello"),
            _ => panic!("Wrong tool type or failed to strip prefix"),
        }
    }

    #[test]
    fn test_normalize_recipient_name() {
        // LLM outputs "recipient_name" instead of "name"
        let input =
            r#"{"recipient_name": "functions.computer", "parameters": {"action": "screenshot"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::Computer(ComputerAction::Screenshot) => {}
            _ => panic!("Wrong tool type or failed to handle recipient_name"),
        }
    }

    #[test]
    fn test_infer_sys_exec_flat() {
        // Flat output without wrapper
        let input = r#"{"command": "gnome-calculator", "args": [], "detach": true}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::SysExec {
                command, detach, ..
            } => {
                assert_eq!(command, "gnome-calculator");
                assert_eq!(detach, true);
            }
            _ => panic!("Wrong tool type inferred"),
        }
    }

    #[test]
    fn test_schema_violation_for_builtin_tool_is_rejected() {
        // Missing required field for deterministic tool name should be a hard schema error
        // (not `Dynamic` fallback routed to MCP).
        let input = r#"{"name": "browser__navigate", "arguments": {}}"#;
        let err = ToolNormalizer::normalize(input).expect_err("expected schema error");
        assert!(err.to_string().contains("Schema Validation Error"));
        assert!(err.to_string().contains("browser__navigate"));
    }

    #[test]
    fn test_normalize_ui_click_component_lowers_to_gui_click_element() {
        let input = r#"{"name":"ui__click_component","arguments":{"id":"btn_submit"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::GuiClickElement { id } => assert_eq!(id, "btn_submit"),
            other => panic!("Expected GuiClickElement, got {:?}", other),
        }
    }

    #[test]
    fn test_normalize_ui_click_component_accepts_component_id_alias() {
        let input = r#"{"name":"ui__click_component","arguments":{"component_id":"btn_submit"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::GuiClickElement { id } => assert_eq!(id, "btn_submit"),
            other => panic!("Expected GuiClickElement, got {:?}", other),
        }
    }

    #[test]
    fn test_normalize_ui_click_component_rejects_missing_id() {
        let input = r#"{"name":"ui__click_component","arguments":{}}"#;
        let err = ToolNormalizer::normalize(input).expect_err("expected schema error");
        assert!(err.to_string().contains("Schema Validation Error"));
        assert!(err.to_string().contains("ui__click_component"));
        assert!(err.to_string().contains("id"));
    }

    #[test]
    fn test_normalize_ui_type_lowers_to_gui_type() {
        let input = r#"{"name":"ui__type","arguments":{"text":"hello"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::GuiType { text } => assert_eq!(text, "hello"),
            other => panic!("Expected GuiType, got {:?}", other),
        }
    }

    #[test]
    fn test_normalize_ui_scroll_lowers_to_gui_scroll() {
        let input = r#"{"name":"ui__scroll","arguments":{"delta_y":120}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::GuiScroll { delta_x, delta_y } => {
                assert_eq!(delta_x, 0);
                assert_eq!(delta_y, 120);
            }
            other => panic!("Expected GuiScroll, got {:?}", other),
        }
    }

    #[test]
    fn test_normalize_ui_click_with_id_lowers_to_gui_click_element() {
        let input = r#"{"name":"ui__click","arguments":{"id":"btn_submit"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::GuiClickElement { id } => assert_eq!(id, "btn_submit"),
            other => panic!("Expected GuiClickElement, got {:?}", other),
        }
    }

    #[test]
    fn test_normalize_ui_click_with_coordinate_lowers_to_gui_click() {
        let input = r#"{"name":"ui__click","arguments":{"coordinate":[100,200]}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::GuiClick { x, y, button } => {
                assert_eq!(x, 100);
                assert_eq!(y, 200);
                assert!(button.is_none());
            }
            other => panic!("Expected GuiClick, got {:?}", other),
        }
    }

    #[test]
    fn test_normalize_ui_click_element_lowers_to_gui_click_element() {
        let input = r#"{"name":"ui__click_element","arguments":{"id":"btn_submit"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::GuiClickElement { id } => assert_eq!(id, "btn_submit"),
            other => panic!("Expected GuiClickElement, got {:?}", other),
        }
    }

    #[test]
    fn test_normalize_ui_type_rejects_missing_text() {
        let input = r#"{"name":"ui__type","arguments":{}}"#;
        let err = ToolNormalizer::normalize(input).expect_err("expected schema error");
        assert!(err.to_string().contains("Schema Validation Error"));
        assert!(err.to_string().contains("ui__type"));
        assert!(err.to_string().contains("text"));
    }

    #[test]
    fn test_normalize_net_fetch_accepts_valid_args() {
        let input = r#"{"name":"net__fetch","arguments":{"url":"https://example.com","max_chars":123}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::Dynamic(val) => {
                assert_eq!(val.get("name").and_then(|v| v.as_str()), Some("net__fetch"));
                assert_eq!(
                    val.get("arguments")
                        .and_then(|a| a.get("url"))
                        .and_then(|v| v.as_str()),
                    Some("https://example.com")
                );
            }
            _ => panic!("Expected Dynamic net__fetch tool"),
        }
    }

    #[test]
    fn test_normalize_net_fetch_rejects_empty_url() {
        let input = r#"{"name":"net__fetch","arguments":{"url":"   "}}"#;
        let err = ToolNormalizer::normalize(input).expect_err("expected schema error");
        assert!(err.to_string().contains("Schema Validation Error"));
        assert!(err.to_string().contains("net__fetch"));
        assert!(err.to_string().contains("url"));
    }

    #[test]
    fn test_normalize_net_fetch_decodes_arguments_string() {
        let input = r#"{"name":"net__fetch","arguments":"{\"url\":\"https://example.com\"}"}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::Dynamic(val) => {
                assert_eq!(val.get("name").and_then(|v| v.as_str()), Some("net__fetch"));
                assert_eq!(
                    val.get("arguments")
                        .and_then(|a| a.get("url"))
                        .and_then(|v| v.as_str()),
                    Some("https://example.com")
                );
            }
            _ => panic!("Expected Dynamic net__fetch tool"),
        }
    }

    #[test]
    fn test_infer_nav_flat() {
        let input = r#"{"url":"https://news.ycombinator.com"}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::BrowserNavigate { url } => {
                assert_eq!(url, "https://news.ycombinator.com");
            }
            _ => panic!("Wrong tool type inferred"),
        }
    }

    #[test]
    fn test_empty_input_fails() {
        let input = "   ";
        assert!(ToolNormalizer::normalize(input).is_err());
    }

    #[test]
    fn test_normalize_synthetic_click() {
        let input =
            r#"{"name": "browser__synthetic_click", "arguments": {"x": 100.5, "y": 200.1}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::BrowserSyntheticClick { x, y } => {
                assert_eq!(x, 100);
                assert_eq!(y, 200);
            }
            _ => panic!("Wrong tool type"),
        }
    }

    #[test]
    fn test_normalize_browser_scroll() {
        let input = r#"{"name":"browser__scroll","arguments":{"delta_x":32.8,"delta_y":480.9}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::BrowserScroll { delta_x, delta_y } => {
                assert_eq!(delta_x, 32);
                assert_eq!(delta_y, 480);
            }
            _ => panic!("Wrong tool type"),
        }
    }

    #[test]
    fn test_normalize_install_package_preserves_typed_tool() {
        let input =
            r#"{"name":"sys__install_package","arguments":{"manager":"pip","package":"pydantic"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::SysInstallPackage { package, manager } => {
                assert_eq!(package, "pydantic");
                assert_eq!(manager.as_deref(), Some("pip"));
            }
            _ => panic!("Wrong tool type"),
        }
    }

    #[test]
    fn test_normalize_install_package_rejects_unsafe_package() {
        let input = r#"{"name":"sys__install_package","arguments":{"manager":"pip","package":"bad; rm -rf /"}}"#;
        let err = ToolNormalizer::normalize(input).expect_err("expected validation error");
        assert!(err.to_string().contains("Invalid package identifier"));
    }

    #[test]
    fn test_normalize_sys_change_directory() {
        let input = r#"{"name":"sys__change_directory","arguments":{"path":"../workspace"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::SysChangeDir { path } => assert_eq!(path, "../workspace"),
            _ => panic!("Wrong tool type"),
        }
    }

    #[test]
    fn test_normalize_filesystem_edit_line_alias() {
        let input = r#"{"name":"filesystem__edit_line","arguments":{"path":"/tmp/demo.txt","line_number":2,"content":"BETA"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "/tmp/demo.txt");
                assert_eq!(content, "BETA");
                assert_eq!(line_number, Some(2));
            }
            _ => panic!("Wrong tool type"),
        }
    }

    #[test]
    fn test_normalize_filesystem_edit_line_rejects_invalid_line_number() {
        let input = r#"{"name":"filesystem__edit_line","arguments":{"path":"/tmp/demo.txt","line_number":0,"content":"BETA"}}"#;
        let err = ToolNormalizer::normalize(input).expect_err("expected validation error");
        assert!(err.to_string().contains("line_number"));
    }
}
