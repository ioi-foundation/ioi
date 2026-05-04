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

pub(super) fn normalize_screen_click_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: screen__click arguments must be a JSON object.")
    })?;
    for legacy_key in [
        "component_id",
        "componentId",
        "element_id",
        "elementId",
        "target_id",
        "targetId",
    ] {
        if args_obj.contains_key(legacy_key) {
            return Err(anyhow!(
                "Schema Validation Error: screen__click no longer accepts legacy '{}' alias; use 'id'.",
                legacy_key
            ));
        }
    }

    let id = args_obj
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow!("Schema Validation Error: screen__click requires a non-empty 'id' field.")
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

pub(super) fn normalize_browser_move_pointer_arguments(arguments: &Value) -> Result<Value> {
    let args_obj = arguments.as_object().ok_or_else(|| {
        anyhow!("Schema Validation Error: browser__move_pointer arguments must be a JSON object.")
    })?;
    let mut normalized = args_obj.clone();

    let observation_ref = normalized
        .get("observation_ref")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let coordinate_space_id = normalized
        .get("coordinate_space_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let semantic_id = normalized
        .get("semantic_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let parsed_x = normalized.get("x").and_then(parse_f64_like);
    let parsed_y = normalized.get("y").and_then(parse_f64_like);

    let (Some(observation_ref), Some(coordinate_space_id), Some(semantic_id), Some(x), Some(y)) = (
        observation_ref,
        coordinate_space_id,
        semantic_id,
        parsed_x,
        parsed_y,
    ) else {
        return Err(anyhow!(
            "Schema Validation Error: browser__move_pointer requires grounded 'observation_ref', 'coordinate_space_id', 'semantic_id', 'x', and 'y' fields from a browser observation."
        ));
    };

    normalized.insert("observation_ref".to_string(), json!(observation_ref));
    normalized.insert(
        "coordinate_space_id".to_string(),
        json!(coordinate_space_id),
    );
    normalized.insert("semantic_id".to_string(), json!(semantic_id));
    normalized.insert("x".to_string(), json!(x));
    normalized.insert("y".to_string(), json!(y));

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
    let observation_ref = normalized
        .get("observation_ref")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let coordinate_space_id = normalized
        .get("coordinate_space_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let semantic_id = normalized
        .get("semantic_id")
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
    if parsed_x.is_some()
        && (id.is_none()
            || observation_ref.is_none()
            || coordinate_space_id.is_none()
            || semantic_id.is_none())
    {
        return Err(anyhow!(
            "Schema Validation Error: browser__click_at raw coordinates require grounded 'id', 'observation_ref', 'coordinate_space_id', and 'semantic_id' fields from a browser observation."
        ));
    }

    if let Some(id) = id {
        normalized.insert("id".to_string(), json!(id));
    } else {
        normalized.remove("id");
    }
    if let Some(observation_ref) = observation_ref {
        normalized.insert("observation_ref".to_string(), json!(observation_ref));
    } else {
        normalized.remove("observation_ref");
    }
    if let Some(coordinate_space_id) = coordinate_space_id {
        normalized.insert(
            "coordinate_space_id".to_string(),
            json!(coordinate_space_id),
        );
    } else {
        normalized.remove("coordinate_space_id");
    }
    if let Some(semantic_id) = semantic_id {
        normalized.insert("semantic_id".to_string(), json!(semantic_id));
    } else {
        normalized.remove("semantic_id");
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

pub(super) fn normalize_http_fetch_arguments(arguments: &Value) -> Result<Value> {
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

    let max_chars = args_obj.get("max_chars").and_then(parse_u32_like);
    if args_obj.contains_key("maxChars") {
        return Err(anyhow!(
            "Schema Validation Error: http__fetch no longer accepts legacy 'maxChars' alias; use 'max_chars'."
        ));
    }

    Ok(if let Some(max_chars) = max_chars {
        json!({ "url": url, "max_chars": max_chars })
    } else {
        json!({ "url": url })
    })
}
