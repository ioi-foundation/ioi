use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use super::builtins::canonical_deterministic_tool_name;

pub(super) fn normalize_file_search_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: file__search arguments must be a JSON object.")
    })?;

    let path = args_obj
        .get("path")
        .or_else(|| args_obj.get("root"))
        .or_else(|| args_obj.get("directory"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(".");

    let regex = args_obj
        .get("regex")
        .or_else(|| args_obj.get("pattern"))
        .or_else(|| args_obj.get("query"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "Schema Validation Error: file__search requires a non-empty 'regex' field (aliases: pattern, query)."
            )
        })?;

    let file_pattern = args_obj
        .get("file_pattern")
        .or_else(|| args_obj.get("glob"))
        .or_else(|| args_obj.get("filter"))
        .or_else(|| args_obj.get("filename_pattern"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);

    let mut normalized = serde_json::Map::from_iter([
        ("path".to_string(), json!(path)),
        ("regex".to_string(), json!(regex)),
    ]);
    if let Some(file_pattern) = file_pattern {
        normalized.insert("file_pattern".to_string(), json!(file_pattern));
    }

    Ok(Value::Object(normalized))
}

pub(super) fn lower_edit_line_to_fs_write(arguments: &Value) -> Result<Value> {
    let args_obj = arguments
        .as_object()
        .ok_or_else(|| anyhow!("file__replace_line arguments must be an object"))?;

    let path = args_obj
        .get("path")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("file__replace_line requires a non-empty 'path' field"))?;

    let line_number_raw = args_obj
        .get("line_number")
        .or_else(|| args_obj.get("line"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            anyhow!("file__replace_line requires integer 'line_number' (or alias 'line')")
        })?;

    if line_number_raw == 0 || line_number_raw > u32::MAX as u64 {
        return Err(anyhow!(
            "file__replace_line 'line_number' must be between 1 and {}",
            u32::MAX
        ));
    }

    let content = args_obj
        .get("content")
        .or_else(|| args_obj.get("text"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("file__replace_line requires string 'content' (or alias 'text')"))?;

    Ok(json!({
        "name": "file__write",
        "arguments": {
            "path": path,
            "content": content,
            "line_number": line_number_raw as u32
        }
    }))
}

pub(super) fn normalize_ui_click_component_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: screen__click arguments must be a JSON object.")
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
                "Schema Validation Error: screen__click requires a non-empty 'id' field (aliases: component_id, element_id, target_id)."
            )
        })?;

    Ok(json!({ "id": id }))
}

pub(super) fn normalize_browser_wait_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: browser__wait arguments must be a JSON object.")
    })?;
    let mut normalized = args_obj.clone();

    normalize_browser_continue_with("browser__wait", &mut normalized)?;
    Ok(Value::Object(normalized))
}

pub(super) fn normalize_browser_click_element_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: browser__click arguments must be a JSON object.")
    })?;
    let mut normalized = args_obj.clone();

    normalize_browser_continue_with("browser__click", &mut normalized)?;
    Ok(Value::Object(normalized))
}

pub(super) fn normalize_browser_key_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: browser__press_key arguments must be a JSON object.")
    })?;
    let mut normalized = args_obj.clone();

    normalize_browser_continue_with("browser__press_key", &mut normalized)?;
    Ok(Value::Object(normalized))
}

pub(super) fn normalize_browser_synthetic_click_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: browser__click_at arguments must be a JSON object.")
    })?;
    let mut normalized = args_obj.clone();

    let id = normalized
        .get("id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let parsed_x = normalized.get("x").and_then(parse_f64_like);
    let parsed_y = normalized.get("y").and_then(parse_f64_like);

    if parsed_x.is_some() ^ parsed_y.is_some() {
        return Err(anyhow!(
            "Schema Validation Error: browser__click_at requires both numeric 'x' and 'y' when either coordinate is provided."
        ));
    }

    if id.is_none() && parsed_x.is_none() {
        return Err(anyhow!(
            "Schema Validation Error: browser__click_at requires either a grounded non-empty 'id' or both numeric 'x' and 'y' fields."
        ));
    }

    if let Some(id) = id {
        normalized.insert("id".to_string(), json!(id));
    } else {
        normalized.remove("id");
    }

    if let Some(x) = parsed_x {
        let y = parsed_y
            .expect("browser__click_at coordinate normalization already validated matching `y`");
        normalized.insert("x".to_string(), json!(x));
        normalized.insert("y".to_string(), json!(y));
    } else {
        normalized.remove("x");
        normalized.remove("y");
    }

    normalize_browser_continue_with("browser__click_at", &mut normalized)?;
    Ok(Value::Object(normalized))
}

fn normalize_browser_continue_with(
    tool_name: &str,
    normalized: &mut serde_json::Map<String, Value>,
) -> Result<()> {
    let Some(raw_continue_with) = normalized.get("continue_with").cloned() else {
        return Ok(());
    };

    let continue_obj = raw_continue_with.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: {tool_name} continue_with must be a JSON object.")
    })?;
    let mut continue_map = continue_obj.clone();

    if let Some(name) = continue_map
        .get("name")
        .and_then(|v| v.as_str())
        .and_then(canonical_deterministic_tool_name)
    {
        continue_map.insert("name".to_string(), json!(name));
    }

    if tool_name == "browser__click_at"
        && continue_map
            .get("name")
            .and_then(|value| value.as_str())
            .is_some_and(|name| matches!(name, "browser__pointer_down" | "browser__pointer_up"))
    {
        return Err(anyhow!(
            "Schema Validation Error: browser__click_at continue_with does not allow pointer button state changes. Use grounded drag tools as separate steps with browser__move_pointer plus browser__pointer_down/browser__pointer_up."
        ));
    }

    if !continue_map.contains_key("arguments") {
        if let Some(parameters) = continue_map.remove("parameters") {
            continue_map.insert("arguments".to_string(), parameters);
        }
    }
    if !continue_map.contains_key("arguments") {
        if let Some(input) = continue_map.remove("input") {
            continue_map.insert("arguments".to_string(), input);
        }
    }
    if !continue_map.contains_key("arguments") {
        let nested_name = continue_map
            .remove("name")
            .and_then(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "Schema Validation Error: {tool_name} continue_with requires a non-empty 'name'."
                )
            })?;
        if continue_map.is_empty() {
            normalized.remove("continue_with");
            return Ok(());
        }
        continue_map = serde_json::Map::from_iter([
            ("name".to_string(), json!(nested_name)),
            ("arguments".to_string(), Value::Object(continue_map)),
        ]);
    }

    if let Some(raw_args) = continue_map
        .get("arguments")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let parsed: Value = serde_json::from_str(raw_args).map_err(|e| {
            anyhow!(
                "Schema Validation Error: {tool_name} continue_with.arguments must be valid JSON: {}",
                e
            )
        })?;
        if !parsed.is_object() {
            return Err(anyhow!(
                "Schema Validation Error: {tool_name} continue_with.arguments must decode to a JSON object."
            ));
        }
        continue_map.insert("arguments".to_string(), parsed);
    }

    if !continue_map
        .get("arguments")
        .is_some_and(|value| value.is_object())
    {
        return Err(anyhow!(
            "Schema Validation Error: {tool_name} continue_with.arguments must be a JSON object."
        ));
    }

    normalized.insert("continue_with".to_string(), Value::Object(continue_map));
    Ok(())
}

fn parse_f64_like(value: &Value) -> Option<f64> {
    if let Some(raw) = value.as_f64() {
        if raw.is_finite() {
            return Some(raw);
        }
        return None;
    }
    if let Some(raw) = value.as_str() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        if let Ok(parsed) = trimmed.parse::<f64>() {
            if parsed.is_finite() {
                return Some(parsed);
            }
        }
    }
    None
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

pub(super) fn normalize_ui_type_arguments(arguments: &Value) -> Result<Value> {
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
            "Schema Validation Error: ui__type does not support targeting by id. Use screen__click(id=...) first, then screen__type(text=...)."
        ));
    }

    Ok(json!({ "text": text }))
}

pub(super) fn normalize_ui_scroll_arguments(arguments: &Value) -> Result<Value> {
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

pub(super) fn normalize_ui_click_arguments(arguments: &Value) -> Result<Value> {
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
            "name": "screen__click",
            "arguments": normalized,
        }));
    }

    let (x, y) = if let Some(coord) = args_obj.get("coordinate").and_then(|v| v.as_array()) {
        if coord.len() < 2 {
            return Err(anyhow!(
                "Schema Validation Error: ui__click 'coordinate' must be [x, y]."
            ));
        }
        let x = coord.first().and_then(parse_u32_like).ok_or_else(|| {
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
        "name": "screen__click_at",
        "arguments": if let Some(button) = button {
            json!({"x": x, "y": y, "button": button})
        } else {
            json!({"x": x, "y": y})
        }
    }))
}

pub(super) fn normalize_net_fetch_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: http__fetch arguments must be a JSON object.")
    })?;

    let url = args_obj
        .get("url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow!("Schema Validation Error: http__fetch requires a non-empty 'url' field.")
        })?;

    let max_chars = args_obj
        .get("max_chars")
        .or_else(|| args_obj.get("maxChars"))
        .and_then(parse_u32_like);

    Ok(if let Some(max_chars) = max_chars {
        json!({ "url": url, "max_chars": max_chars })
    } else {
        json!({ "url": url })
    })
}
