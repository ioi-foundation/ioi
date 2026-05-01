use super::*;

pub(super) fn infer_sys_tool_name(args: &serde_json::Value) -> &'static str {
    if let Some(obj) = args.as_object() {
        if obj.get("command").is_none() && obj.get("app_name").is_some() {
            return "app__launch";
        }
        if obj.get("command").is_none() && obj.get("path").is_some() {
            return "shell__cd";
        }
    }
    "shell__run"
}

pub(super) fn infer_fs_read_tool_name(args: &serde_json::Value) -> &'static str {
    let Some(obj) = args.as_object() else {
        return "file__read";
    };

    // Preserve deterministic filesystem search queued via ActionTarget::FsRead.
    if obj.contains_key("regex") || obj.contains_key("file_pattern") {
        return "file__search";
    }

    if let Some(path) = obj
        .get("path")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if Path::new(path).is_dir() {
            return "file__list";
        }
    }

    "file__read"
}

pub(super) fn infer_fs_write_tool_name(args: &serde_json::Value) -> &'static str {
    let Some(obj) = args.as_object() else {
        return "file__write";
    };

    // Preserve deterministic patch requests queued under ActionTarget::FsWrite.
    if obj.contains_key("search") && obj.contains_key("replace") {
        return "file__edit";
    }

    // Preserve deterministic archive creation requests queued under ActionTarget::FsWrite.
    if obj.contains_key("source_path") && obj.contains_key("destination_zip_path") {
        return "file__zip";
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
            return "file__delete";
        }

        // Recursive-without-delete markers maps to create_directory to avoid destructive
        // misclassification of legacy deterministic directory creation requests.
        if obj.contains_key("recursive") {
            return "file__create_dir";
        }
    }

    "file__write"
}

pub(super) fn has_non_empty_string_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> bool {
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
        "ui::find" => "screen__find".to_string(),
        "os::focus" => "window__focus".to_string(),
        "os::launch_app" => "app__launch".to_string(),
        "clipboard::write" => "clipboard__copy".to_string(),
        "clipboard::read" => "clipboard__paste".to_string(),
        "math::eval" => "math__eval".to_string(),
        "screen::cursor" => "screen".to_string(),
        "fs::read" => infer_fs_read_tool_name(args).to_string(),
        "fs::write" => infer_fs_write_tool_name(args).to_string(),
        "sys::exec" => infer_sys_tool_name(args).to_string(),
        "sys::exec_session" => "shell__start".to_string(),
        "sys::exec_session_reset" => "shell__reset".to_string(),
        "sys::install_package" => "package__install".to_string(),
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

    if obj.contains_key("tab_id") {
        if obj.get("close").and_then(|value| value.as_bool()) == Some(true) {
            return Ok("browser__close_tab");
        }
        return Ok("browser__switch_tab");
    }
    if obj.contains_key("paths") {
        return Ok("browser__upload");
    }
    if obj.contains_key("ms") {
        return Ok("browser__wait");
    }
    if obj.contains_key("condition") {
        return Ok("browser__wait");
    }
    if obj.contains_key("query") {
        return Ok("browser__find_text");
    }
    if obj.contains_key("full_page") {
        return Ok("browser__screenshot");
    }
    if obj.contains_key("value") || obj.contains_key("label") {
        return Ok("browser__select_option");
    }
    if obj.contains_key("som_id") {
        return Ok("browser__list_options");
    }
    if obj.is_empty() {
        return Ok("browser__list_tabs");
    }
    if obj.contains_key("steps") {
        return Ok("browser__back");
    }
    if obj.contains_key("url") {
        return Ok("browser__navigate");
    }
    if obj.contains_key("text") {
        return Ok("browser__type");
    }
    if obj.contains_key("start_offset") || obj.contains_key("end_offset") {
        return Ok("browser__select");
    }
    if obj.contains_key("modifiers") {
        return Ok("browser__press_key");
    }
    if obj.contains_key("id") || obj.contains_key("ids") {
        return Ok("browser__click");
    }
    if obj.contains_key("selector") {
        return Ok("browser__click");
    }
    if obj.contains_key("key") {
        return Ok("browser__press_key");
    }
    if obj.contains_key("x") && obj.contains_key("y") {
        return Ok("browser__click_at");
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

pub(super) fn ensure_computer_action(
    raw_args: serde_json::Value,
    action: &str,
) -> serde_json::Value {
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
    WebRetrieve,
    BrowserInteract,
}

pub(super) fn explicit_queue_tool_name_scope(target: &ActionTarget) -> Option<QueueToolNameScope> {
    match target {
        ActionTarget::FsRead => Some(QueueToolNameScope::Read),
        ActionTarget::FsWrite => Some(QueueToolNameScope::Write),
        ActionTarget::Custom(name) if name == "fs::read" => Some(QueueToolNameScope::Read),
        ActionTarget::Custom(name) if name == "fs::write" => Some(QueueToolNameScope::Write),
        ActionTarget::GuiClick | ActionTarget::UiClick => Some(QueueToolNameScope::GuiClick),
        ActionTarget::SysExec => Some(QueueToolNameScope::SysExec),
        ActionTarget::WebRetrieve => Some(QueueToolNameScope::WebRetrieve),
        ActionTarget::BrowserInteract => Some(QueueToolNameScope::BrowserInteract),
        _ => None,
    }
}

pub(super) fn is_explicit_tool_name_allowed_for_scope(
    scope: QueueToolNameScope,
    tool_name: &str,
) -> bool {
    match scope {
        QueueToolNameScope::Read => matches!(
            tool_name,
            "file__read" | "file__list" | "file__search" | "file__info"
        ),
        QueueToolNameScope::Write => matches!(
            tool_name,
            "file__write"
                | "file__edit"
                | "file__delete"
                | "file__create_dir"
                | "file__zip"
                | "file__copy"
                | "file__move"
        ),
        QueueToolNameScope::GuiClick => {
            matches!(tool_name, "screen__click_at" | "screen__click" | "screen")
        }
        QueueToolNameScope::SysExec => {
            matches!(tool_name, "shell__start" | "shell__reset")
        }
        QueueToolNameScope::WebRetrieve => {
            matches!(
                tool_name,
                "web__search"
                    | "web__read"
                    | "media__extract_transcript"
                    | "media__extract_evidence"
            )
        }
        QueueToolNameScope::BrowserInteract => matches!(
            tool_name,
            "browser__navigate"
                | "browser__click"
                | "browser__hover"
                | "browser__move_pointer"
                | "browser__pointer_down"
                | "browser__pointer_up"
                | "browser__click_at"
                | "browser__scroll"
                | "browser__type"
                | "browser__select"
                | "browser__press_key"
                | "browser__copy"
                | "browser__paste"
                | "browser__find_text"
                | "browser__screenshot"
                | "browser__wait"
                | "browser__upload"
                | "browser__list_options"
                | "browser__select_option"
                | "browser__back"
                | "browser__list_tabs"
                | "browser__switch_tab"
                | "browser__close_tab"
        ),
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
            "Queued fs::write transfer payloads must include {} set to file__copy or file__move.",
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
        ActionTarget::NetFetch => Ok(("http__fetch".to_string(), raw_args)),
        ActionTarget::BrowserInteract => Ok((
            infer_browser_interact_tool_name(&raw_args)?.to_string(),
            raw_args,
        )),
        ActionTarget::BrowserInspect => Ok(("browser__inspect".to_string(), raw_args)),
        ActionTarget::GuiType | ActionTarget::UiType => {
            if looks_like_computer_action_payload(&raw_args) {
                Ok(("screen".to_string(), raw_args))
            } else {
                Ok(("screen__type".to_string(), raw_args))
            }
        }
        ActionTarget::GuiClick | ActionTarget::UiClick => {
            if looks_like_computer_action_payload(&raw_args) {
                Ok(("screen".to_string(), raw_args))
            } else {
                Ok(("screen__click_at".to_string(), raw_args))
            }
        }
        ActionTarget::GuiScroll => {
            if looks_like_computer_action_payload(&raw_args) {
                Ok(("screen".to_string(), raw_args))
            } else {
                Ok(("screen__scroll".to_string(), raw_args))
            }
        }
        ActionTarget::GuiMouseMove => Ok((
            "screen".to_string(),
            ensure_computer_action(raw_args, "mouse_move"),
        )),
        ActionTarget::GuiScreenshot => Ok((
            "screen".to_string(),
            ensure_computer_action(raw_args, "screenshot"),
        )),
        ActionTarget::GuiInspect => Ok(("screen__inspect".to_string(), raw_args)),
        ActionTarget::GuiSequence => Ok(("screen".to_string(), raw_args)),
        ActionTarget::SysExec => Ok((infer_sys_tool_name(&raw_args).to_string(), raw_args)),
        ActionTarget::SysInstallPackage => Ok(("package__install".to_string(), raw_args)),
        ActionTarget::WindowFocus => Ok(("window__focus".to_string(), raw_args)),
        ActionTarget::ClipboardWrite => Ok(("clipboard__copy".to_string(), raw_args)),
        ActionTarget::ClipboardRead => Ok(("clipboard__paste".to_string(), raw_args)),
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
