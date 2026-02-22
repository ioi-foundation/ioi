use super::*;

pub(super) fn infer_sys_tool_name(args: &serde_json::Value) -> &'static str {
    if let Some(obj) = args.as_object() {
        if obj.get("command").is_none() && obj.get("app_name").is_some() {
            return "os__launch_app";
        }
        if obj.get("command").is_none() && obj.get("path").is_some() {
            return "sys__change_directory";
        }
    }
    "sys__exec"
}

pub(super) fn infer_fs_read_tool_name(args: &serde_json::Value) -> &'static str {
    let Some(obj) = args.as_object() else {
        return "filesystem__read_file";
    };

    // Preserve deterministic filesystem search queued via ActionTarget::FsRead.
    if obj.contains_key("regex") || obj.contains_key("file_pattern") {
        return "filesystem__search";
    }

    if let Some(path) = obj
        .get("path")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if Path::new(path).is_dir() {
            return "filesystem__list_directory";
        }
    }

    "filesystem__read_file"
}

pub(super) fn infer_fs_write_tool_name(args: &serde_json::Value) -> &'static str {
    let Some(obj) = args.as_object() else {
        return "filesystem__write_file";
    };

    // Preserve deterministic patch requests queued under ActionTarget::FsWrite.
    if obj.contains_key("search") && obj.contains_key("replace") {
        return "filesystem__patch";
    }

    // Preserve deterministic delete/create-directory requests queued under
    // ActionTarget::FsWrite for backward compatibility.
    if obj.contains_key("path")
        && !obj.contains_key("content")
        && !obj.contains_key("line")
        && !obj.contains_key("line_number")
    {
        // Delete payloads include `ignore_missing`; prefer delete whenever it is present.
        if obj.contains_key("ignore_missing") {
            return "filesystem__delete_path";
        }

        // Recursive-without-delete markers maps to create_directory to avoid destructive
        // misclassification of legacy deterministic directory creation requests.
        if obj.contains_key("recursive") {
            return "filesystem__create_directory";
        }
    }

    "filesystem__write_file"
}

pub(super) fn has_non_empty_string_field(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> bool {
    obj.get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

pub(super) fn is_ambiguous_fs_write_transfer_payload(args: &serde_json::Value) -> bool {
    let Some(obj) = args.as_object() else {
        return false;
    };
    has_non_empty_string_field(obj, "source_path")
        && has_non_empty_string_field(obj, "destination_path")
}

pub(super) fn infer_custom_tool_name(name: &str, args: &serde_json::Value) -> String {
    match name {
        "ui::find" => "ui__find".to_string(),
        "os::focus" => "os__focus_window".to_string(),
        "clipboard::write" => "os__copy".to_string(),
        "clipboard::read" => "os__paste".to_string(),
        "computer::cursor" => "computer".to_string(),
        "fs::read" => infer_fs_read_tool_name(args).to_string(),
        "fs::write" => infer_fs_write_tool_name(args).to_string(),
        "sys::exec" => infer_sys_tool_name(args).to_string(),
        "sys::exec_session" => "sys__exec_session".to_string(),
        "sys::exec_session_reset" => "sys__exec_session_reset".to_string(),
        "sys::install_package" => "sys__install_package".to_string(),
        _ => name.to_string(),
    }
}

pub(super) fn infer_web_retrieve_tool_name(
    args: &serde_json::Value,
) -> Result<&'static str, TransactionError> {
    let Some(obj) = args.as_object() else {
        return Err(TransactionError::Invalid(
            "Queued web::retrieve args must be a JSON object.".into(),
        ));
    };

    if obj.contains_key("query") {
        return Ok("web__search");
    }
    if obj.contains_key("url") {
        return Ok("web__read");
    }

    Err(TransactionError::Invalid(
        "Queued web::retrieve must include either 'query' (web__search) or 'url' (web__read)."
            .into(),
    ))
}

pub(super) fn infer_browser_interact_tool_name(
    args: &serde_json::Value,
) -> Result<&'static str, TransactionError> {
    let Some(obj) = args.as_object() else {
        return Err(TransactionError::Invalid(
            "Queued browser::interact args must be a JSON object.".into(),
        ));
    };

    if obj.contains_key("url") {
        return Ok("browser__navigate");
    }
    if obj.contains_key("text") {
        return Ok("browser__type");
    }
    if obj.contains_key("id") {
        return Ok("browser__click_element");
    }
    if obj.contains_key("selector") {
        return Ok("browser__click");
    }
    if obj.contains_key("key") {
        return Ok("browser__key");
    }
    if obj.contains_key("x") && obj.contains_key("y") {
        return Ok("browser__synthetic_click");
    }
    if obj.contains_key("delta_x") || obj.contains_key("delta_y") {
        return Ok("browser__scroll");
    }

    Err(TransactionError::Invalid(
        "Queued browser::interact args did not match any known browser__* tool signature.".into(),
    ))
}

pub(super) fn looks_like_computer_action_payload(args: &serde_json::Value) -> bool {
    args.as_object()
        .and_then(|obj| obj.get("action"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

pub(super) fn ensure_computer_action(raw_args: serde_json::Value, action: &str) -> serde_json::Value {
    match raw_args {
        serde_json::Value::Object(mut obj) => {
            obj.entry("action".to_string())
                .or_insert_with(|| json!(action));
            serde_json::Value::Object(obj)
        }
        other => other,
    }
}

#[derive(Clone, Copy)]
pub(super) enum QueueToolNameScope {
    Read,
    Write,
    GuiClick,
    SysExec,
}

pub(super) fn explicit_queue_tool_name_scope(target: &ActionTarget) -> Option<QueueToolNameScope> {
    match target {
        ActionTarget::FsRead => Some(QueueToolNameScope::Read),
        ActionTarget::FsWrite => Some(QueueToolNameScope::Write),
        ActionTarget::Custom(name) if name == "fs::read" => Some(QueueToolNameScope::Read),
        ActionTarget::Custom(name) if name == "fs::write" => Some(QueueToolNameScope::Write),
        ActionTarget::GuiClick | ActionTarget::UiClick => Some(QueueToolNameScope::GuiClick),
        ActionTarget::SysExec => Some(QueueToolNameScope::SysExec),
        _ => None,
    }
}

pub(super) fn is_explicit_tool_name_allowed_for_scope(scope: QueueToolNameScope, tool_name: &str) -> bool {
    match scope {
        QueueToolNameScope::Read => matches!(
            tool_name,
            "filesystem__read_file" | "filesystem__list_directory" | "filesystem__search"
        ),
        QueueToolNameScope::Write => matches!(
            tool_name,
            "filesystem__write_file"
                | "filesystem__patch"
                | "filesystem__delete_path"
                | "filesystem__create_directory"
                | "filesystem__copy_path"
                | "filesystem__move_path"
        ),
        QueueToolNameScope::GuiClick => {
            matches!(tool_name, "gui__click" | "gui__click_element" | "computer")
        }
        QueueToolNameScope::SysExec => {
            matches!(tool_name, "sys__exec_session" | "sys__exec_session_reset")
        }
    }
}

pub(super) fn extract_explicit_tool_name(
    target: &ActionTarget,
    raw_args: &serde_json::Value,
) -> Result<Option<String>, TransactionError> {
    // Explicit queue metadata is used for targets where ActionTarget-level replay can collapse
    // distinct tool variants into ambiguous defaults.
    let Some(scope) = explicit_queue_tool_name_scope(target) else {
        return Ok(None);
    };

    let Some(obj) = raw_args.as_object() else {
        return Ok(None);
    };

    let Some(name) = obj.get(QUEUE_TOOL_NAME_KEY) else {
        return Ok(None);
    };

    let tool_name = name.as_str().map(str::trim).ok_or_else(|| {
        TransactionError::Invalid(format!(
            "Queued {} must be a non-empty string when present.",
            QUEUE_TOOL_NAME_KEY
        ))
    })?;

    if tool_name.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "Queued {} cannot be empty.",
            QUEUE_TOOL_NAME_KEY
        )));
    }

    if !is_explicit_tool_name_allowed_for_scope(scope, tool_name) {
        return Err(TransactionError::Invalid(format!(
            "Queued {} '{}' is incompatible with target {:?}.",
            QUEUE_TOOL_NAME_KEY, tool_name, target
        )));
    }

    Ok(Some(tool_name.to_string()))
}

pub(super) fn strip_internal_queue_metadata(raw_args: serde_json::Value) -> serde_json::Value {
    match raw_args {
        serde_json::Value::Object(mut obj) => {
            obj.remove(QUEUE_TOOL_NAME_KEY);
            serde_json::Value::Object(obj)
        }
        other => other,
    }
}

pub(super) fn queue_target_to_tool_name_and_args(
    target: &ActionTarget,
    raw_args: serde_json::Value,
) -> Result<(String, serde_json::Value), TransactionError> {
    let explicit_tool_name = extract_explicit_tool_name(target, &raw_args)?;
    let raw_args = strip_internal_queue_metadata(raw_args);

    if let Some(tool_name) = explicit_tool_name {
        return Ok((tool_name, raw_args));
    }

    if matches!(
        explicit_queue_tool_name_scope(target),
        Some(QueueToolNameScope::Write)
    ) && is_ambiguous_fs_write_transfer_payload(&raw_args)
    {
        return Err(TransactionError::Invalid(format!(
            "Queued fs::write transfer payloads must include {} set to filesystem__copy_path or filesystem__move_path.",
            QUEUE_TOOL_NAME_KEY
        )));
    }

    match target {
        ActionTarget::Custom(name) => Ok((infer_custom_tool_name(name, &raw_args), raw_args)),
        ActionTarget::FsRead => Ok((infer_fs_read_tool_name(&raw_args).to_string(), raw_args)),
        ActionTarget::FsWrite => Ok((infer_fs_write_tool_name(&raw_args).to_string(), raw_args)),
        ActionTarget::WebRetrieve => Ok((
            infer_web_retrieve_tool_name(&raw_args)?.to_string(),
            raw_args,
        )),
        ActionTarget::NetFetch => Ok(("net__fetch".to_string(), raw_args)),
        ActionTarget::BrowserInteract => Ok((
            infer_browser_interact_tool_name(&raw_args)?.to_string(),
            raw_args,
        )),
        ActionTarget::BrowserInspect => Ok(("browser__snapshot".to_string(), raw_args)),
        ActionTarget::GuiType | ActionTarget::UiType => {
            if looks_like_computer_action_payload(&raw_args) {
                Ok(("computer".to_string(), raw_args))
            } else {
                Ok(("gui__type".to_string(), raw_args))
            }
        }
        ActionTarget::GuiClick | ActionTarget::UiClick => {
            if looks_like_computer_action_payload(&raw_args) {
                Ok(("computer".to_string(), raw_args))
            } else {
                Ok(("gui__click".to_string(), raw_args))
            }
        }
        ActionTarget::GuiScroll => {
            if looks_like_computer_action_payload(&raw_args) {
                Ok(("computer".to_string(), raw_args))
            } else {
                Ok(("gui__scroll".to_string(), raw_args))
            }
        }
        ActionTarget::GuiMouseMove => Ok((
            "computer".to_string(),
            ensure_computer_action(raw_args, "mouse_move"),
        )),
        ActionTarget::GuiScreenshot => Ok((
            "computer".to_string(),
            ensure_computer_action(raw_args, "screenshot"),
        )),
        ActionTarget::GuiInspect => Ok(("gui__snapshot".to_string(), raw_args)),
        ActionTarget::GuiSequence => Ok(("computer".to_string(), raw_args)),
        ActionTarget::SysExec => Ok((infer_sys_tool_name(&raw_args).to_string(), raw_args)),
        ActionTarget::SysInstallPackage => Ok(("sys__install_package".to_string(), raw_args)),
        ActionTarget::WindowFocus => Ok(("os__focus_window".to_string(), raw_args)),
        ActionTarget::ClipboardWrite => Ok(("os__copy".to_string(), raw_args)),
        ActionTarget::ClipboardRead => Ok(("os__paste".to_string(), raw_args)),
        unsupported => Err(TransactionError::Invalid(format!(
            "Queue execution for target {:?} is not yet mapped to AgentTool",
            unsupported
        ))),
    }
}

pub fn queue_action_request_to_tool(
    action_request: &ActionRequest,
) -> Result<AgentTool, TransactionError> {
    let raw_args: serde_json::Value =
        serde_json::from_slice(&action_request.params).map_err(|e| {
            TransactionError::Serialization(format!("Invalid queued action params JSON: {}", e))
        })?;

    let (tool_name, args) = queue_target_to_tool_name_and_args(&action_request.target, raw_args)?;

    let wrapper = json!({
        "name": tool_name,
        "arguments": args,
    });
    let wrapper_json = serde_json::to_string(&wrapper)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;

    middleware::normalize_tool_call(&wrapper_json)
        .map_err(|e| TransactionError::Invalid(format!("Queue tool normalization failed: {}", e)))
}
