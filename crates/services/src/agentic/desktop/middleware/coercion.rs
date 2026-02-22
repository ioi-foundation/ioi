use anyhow::{anyhow, Result};
use serde_json::{json, Value};

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

pub(super) fn normalize_install_package_arguments(arguments: &Value) -> Result<Value> {
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

pub(super) fn lower_edit_line_to_fs_write(arguments: &Value) -> Result<Value> {
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

pub(super) fn normalize_ui_click_component_arguments(arguments: &Value) -> Result<Value> {
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
            "Schema Validation Error: ui__type does not support targeting by id. Use gui__click_element(id=...) first, then gui__type(text=...)."
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
        "name": "gui__click",
        "arguments": if let Some(button) = button {
            json!({"x": x, "y": y, "button": button})
        } else {
            json!({"x": x, "y": y})
        }
    }))
}

pub(super) fn normalize_net_fetch_arguments(arguments: &Value) -> Result<Value> {
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
