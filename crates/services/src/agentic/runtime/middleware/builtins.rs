use ioi_types::app::agentic::AgentTool;

pub(super) fn is_deterministic_tool_name(name: &str) -> bool {
    AgentTool::is_reserved_tool_name(name)
}

fn legacy_deterministic_tool_name(name: &str) -> Option<&'static str> {
    match name {
        "computer" => Some("screen"),
        "filesystem__write_file" => Some("file__write"),
        "filesystem__edit_file" => Some("file__edit"),
        "filesystem__read_file" => Some("file__read"),
        "filesystem__list_dir" => Some("file__list"),
        "filesystem__search_files" => Some("file__search"),
        "filesystem__stat_path" => Some("file__info"),
        "filesystem__move_path" => Some("file__move"),
        "filesystem__copy_path" => Some("file__copy"),
        "filesystem__delete_path" => Some("file__delete"),
        "filesystem__create_dir" => Some("file__create_dir"),
        "filesystem__zip" => Some("file__zip"),
        "sys__exec" | "sys_exec" | "sys::exec" | "sys:exec" => Some("shell__run"),
        "sys__exec_session" => Some("shell__start"),
        "sys__exec_session_reset" => Some("shell__reset"),
        "sys__change_directory" => Some("shell__cd"),
        "sys__install_package" => Some("package__install"),
        "browser__snapshot" => Some("browser__inspect"),
        "browser__click_element" => Some("browser__click"),
        "browser__move_mouse" => Some("browser__move_pointer"),
        "browser__mouse_down" => Some("browser__pointer_down"),
        "browser__mouse_up" => Some("browser__pointer_up"),
        "browser__synthetic_click" => Some("browser__click_at"),
        "browser__select_text" => Some("browser__select"),
        "browser__key" => Some("browser__press_key"),
        "browser__copy_selection" => Some("browser__copy"),
        "browser__paste_clipboard" => Some("browser__paste"),
        "browser__canvas_summary" => Some("browser__inspect_canvas"),
        "browser__upload_file" => Some("browser__upload"),
        "browser__dropdown_options" => Some("browser__list_options"),
        "browser__select_dropdown" => Some("browser__select_option"),
        "browser__go_back" => Some("browser__back"),
        "browser__tab_list" => Some("browser__list_tabs"),
        "browser__tab_switch" => Some("browser__switch_tab"),
        "browser__tab_close" => Some("browser__close_tab"),
        "gui__click" => Some("screen__click_at"),
        "gui__click_element" => Some("screen__click"),
        "gui__type" => Some("screen__type"),
        "gui__scroll" => Some("screen__scroll"),
        "gui__snapshot" => Some("screen__inspect"),
        "ui__find" => Some("screen__find"),
        "os__focus_window" => Some("window__focus"),
        "os__copy" => Some("clipboard__copy"),
        "os__paste" => Some("clipboard__paste"),
        "os__launch_app" => Some("app__launch"),
        "net__fetch" => Some("http__fetch"),
        "media__extract_multimodal_evidence" => Some("media__extract_evidence"),
        "automation__create_monitor" => Some("monitor__create"),
        "memory__inspect" => Some("memory__read"),
        "memory__replace_core" => Some("memory__replace"),
        "memory__append_core" => Some("memory__append"),
        "memory__clear_core" => Some("memory__clear"),
        "agent__await_result" => Some("agent__await"),
        "system__fail" => Some("agent__escalate"),
        _ => None,
    }
}

pub(super) fn canonical_deterministic_tool_name(name: &str) -> Option<String> {
    let normalized = name
        .trim_matches(|ch: char| ch == '"' || ch == '\'')
        .trim()
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }

    // Preserve compatibility for legacy provider/tool-wrapper names while the
    // external model ecosystem catches up to the V2 native vocabulary.
    if let Some(legacy) = legacy_deterministic_tool_name(normalized.as_str()) {
        return Some(legacy.to_string());
    }

    if is_deterministic_tool_name(&normalized) {
        return Some(normalized);
    }

    // Accept common single-separator aliases produced by some models, for example:
    // sys_exec -> shell__run, browser_click -> browser__click.
    if !normalized.contains("__") {
        if let Some((namespace, rest)) = normalized.split_once('_') {
            let candidate = format!("{}__{}", namespace, rest);
            if is_deterministic_tool_name(&candidate) {
                return Some(candidate);
            }
        }
        if let Some((namespace, rest)) = normalized.split_once("::") {
            let candidate = format!("{}__{}", namespace, rest);
            if is_deterministic_tool_name(&candidate) {
                return Some(candidate);
            }
        }
        if let Some((namespace, rest)) = normalized.split_once(':') {
            let candidate = format!("{}__{}", namespace, rest);
            if is_deterministic_tool_name(&candidate) {
                return Some(candidate);
            }
        }
        if let Some((namespace, rest)) = normalized.split_once('.') {
            let candidate = format!("{}__{}", namespace, rest);
            if is_deterministic_tool_name(&candidate) {
                return Some(candidate);
            }
        }
    }

    None
}
