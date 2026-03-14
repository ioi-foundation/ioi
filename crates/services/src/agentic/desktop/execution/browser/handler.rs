use super::super::{ToolExecutionResult, ToolExecutor};
use super::element_click::{
    find_semantic_target_by_id, handle_browser_click_element, selector_fallback_candidates,
    BrowserSemanticTarget,
};
use super::selector_click::handle_browser_click;
use super::tree::{apply_browser_auto_lens, detect_human_challenge, render_browser_tree_xml};
use ioi_types::app::agentic::AgentTool;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;
use tokio::time::{sleep, Duration};

fn semantic_candidates(semantic_blob: &str) -> Vec<String> {
    semantic_blob
        .split(',')
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
        .map(str::to_string)
        .collect()
}

fn resolve_home_directory() -> Result<PathBuf, String> {
    if let Some(home) = env::var_os("HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(home));
    }
    if let Some(user_profile) = env::var_os("USERPROFILE").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(user_profile));
    }
    if let (Some(home_drive), Some(home_path)) = (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH"))
    {
        if !home_drive.is_empty() && !home_path.is_empty() {
            let mut combined = PathBuf::from(home_drive);
            combined.push(home_path);
            return Ok(combined);
        }
    }
    Err("Home directory is not configured (HOME/USERPROFILE).".to_string())
}

fn expand_tilde_path(path: &str) -> Result<PathBuf, String> {
    if path == "~" {
        return resolve_home_directory();
    }
    if let Some(remainder) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        return Ok(resolve_home_directory()?.join(remainder));
    }
    Ok(PathBuf::from(path))
}

fn resolve_upload_scope_root(cwd: Option<&str>) -> Result<PathBuf, String> {
    let normalized = cwd.unwrap_or(".").trim();
    let candidate = if normalized.is_empty() {
        PathBuf::from(".")
    } else {
        expand_tilde_path(normalized)?
    };
    let absolute = if candidate.is_absolute() {
        candidate
    } else {
        env::current_dir()
            .map_err(|e| format!("Failed to resolve current directory: {}", e))?
            .join(candidate)
    };
    let canonical = std::fs::canonicalize(&absolute).map_err(|e| {
        format!(
            "Failed to resolve upload scope root '{}': {}",
            absolute.display(),
            e
        )
    })?;
    if !canonical.is_dir() {
        return Err(format!(
            "Upload scope root '{}' is not a directory.",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn resolve_scoped_upload_paths(paths: &[String], cwd: Option<&str>) -> Result<Vec<String>, String> {
    if paths.is_empty() {
        return Err("browser__upload_file requires at least one path".to_string());
    }

    let scope_root = resolve_upload_scope_root(cwd)?;
    let mut resolved = Vec::with_capacity(paths.len());

    for raw in paths {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("browser__upload_file paths cannot be empty".to_string());
        }

        let requested = expand_tilde_path(trimmed)?;
        let candidate = if requested.is_absolute() {
            requested
        } else {
            scope_root.join(requested)
        };

        let canonical = std::fs::canonicalize(&candidate).map_err(|e| {
            format!(
                "Failed to resolve upload path '{}' within scope '{}': {}",
                trimmed,
                scope_root.display(),
                e
            )
        })?;
        if !canonical.is_file() {
            return Err(format!(
                "Upload path is not a file: '{}'",
                canonical.display()
            ));
        }
        if !canonical.starts_with(&scope_root) {
            return Err(format!(
                "Upload path '{}' is outside allowed scope root '{}'.",
                canonical.display(),
                scope_root.display()
            ));
        }

        resolved.push(canonical.to_string_lossy().to_string());
    }

    Ok(resolved)
}

async fn resolve_semantic_target_from_som(
    exec: &ToolExecutor,
    som_id: u32,
    semantic_map: Option<&BTreeMap<u32, String>>,
) -> Result<super::element_click::BrowserSemanticTarget, String> {
    let semantic_map = semantic_map.ok_or_else(|| {
        "SoM map unavailable. Run a fresh perception step before using som_id.".to_string()
    })?;
    let semantic_blob = semantic_map
        .get(&som_id)
        .ok_or_else(|| format!("SoM id '{}' not found in current semantic map.", som_id))?;
    let candidates = semantic_candidates(semantic_blob);
    if candidates.is_empty() {
        return Err(format!(
            "SoM id '{}' has no semantic candidates in the current map.",
            som_id
        ));
    }

    let raw_tree = exec
        .browser
        .get_accessibility_tree()
        .await
        .map_err(|e| format!("Failed to fetch browser accessibility tree: {}", e))?;
    let transformed = apply_browser_auto_lens(raw_tree);

    for candidate in candidates {
        if let Some(target) = find_semantic_target_by_id(&transformed, &candidate) {
            return Ok(target);
        }
    }

    Err(format!(
        "None of the semantic IDs for SoM id '{}' are present in the current browser snapshot.",
        som_id
    ))
}

async fn resolve_browser_target_from_id(
    exec: &ToolExecutor,
    id: &str,
) -> Result<BrowserSemanticTarget, String> {
    let id = id.trim();
    if id.is_empty() {
        return Err("semantic browser id cannot be empty".to_string());
    }

    let raw_tree = exec
        .browser
        .get_accessibility_tree()
        .await
        .map_err(|e| format!("Failed to fetch browser accessibility tree: {}", e))?;
    let transformed = apply_browser_auto_lens(raw_tree);

    find_semantic_target_by_id(&transformed, id).ok_or_else(|| {
        format!(
            "Semantic browser id '{}' not found in current browser snapshot.",
            id
        )
    })
}

fn browser_type_selector_lookup_token(selector: &str) -> Option<&str> {
    let selector = selector.trim();
    if selector.is_empty() {
        return None;
    }

    let token = selector.strip_prefix('#').unwrap_or(selector);
    if token.is_empty()
        || token
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
    {
        return None;
    }

    Some(token)
}

fn browser_type_selector_fallbacks_for_target(
    requested_selector: &str,
    target: &BrowserSemanticTarget,
) -> Vec<String> {
    let requested_selector = requested_selector.trim();
    selector_fallback_candidates(target)
        .into_iter()
        .filter(|candidate| candidate.trim() != requested_selector)
        .collect()
}

async fn browser_type_selector_candidates(
    exec: &ToolExecutor,
    selector: Option<&str>,
) -> Vec<Option<String>> {
    let Some(requested_selector) = selector
        .map(str::trim)
        .filter(|selector| !selector.is_empty())
        .map(str::to_string)
    else {
        return vec![None];
    };

    let mut candidates = vec![Some(requested_selector.clone())];
    let Some(token) = browser_type_selector_lookup_token(&requested_selector) else {
        return candidates;
    };

    let Ok(target) = resolve_browser_target_from_id(exec, token).await else {
        return candidates;
    };

    for fallback in browser_type_selector_fallbacks_for_target(&requested_selector, &target) {
        if !candidates
            .iter()
            .flatten()
            .any(|candidate| candidate == &fallback)
        {
            candidates.push(Some(fallback));
        }
    }

    candidates
}

fn browser_type_error_supports_selector_retry(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("failed to focus selector")
        || message.contains("selector focus failed")
        || message.contains("target not found")
}

fn normalized_browser_button(button: Option<&str>) -> &'static str {
    match button
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("right") => "right",
        Some("middle") => "middle",
        Some("back") => "back",
        Some("forward") => "forward",
        _ => "left",
    }
}

async fn resolve_hover_target(
    exec: &ToolExecutor,
    selector: Option<&str>,
    id: Option<&str>,
) -> Result<(f64, f64, serde_json::Value), String> {
    let selector = selector
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let id = id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    if selector.is_some() == id.is_some() {
        return Err("provide exactly one of selector or id".to_string());
    }

    if let Some(selector) = selector {
        let rect = exec
            .browser
            .get_selector_rect_window_logical(&selector)
            .await
            .map_err(|e| format!("resolve hover selector '{}': {}", selector, e))?;
        let center = rect.center();
        return Ok((
            center.x,
            center.y,
            json!({
                "selector": selector,
                "target_kind": "selector",
            }),
        ));
    }

    let id = id.expect("exactly one hover locator should be present");
    let raw_tree = exec
        .browser
        .get_accessibility_tree()
        .await
        .map_err(|e| format!("resolve hover semantic id '{}': {}", id, e))?;
    let transformed = apply_browser_auto_lens(raw_tree);
    let target = find_semantic_target_by_id(&transformed, &id)
        .ok_or_else(|| format!("semantic browser target '{}' not found", id))?;
    let center = target
        .center_point
        .ok_or_else(|| format!("semantic browser target '{}' has no geometry center", id))?;
    Ok((
        center.0,
        center.1,
        json!({
            "id": id,
            "target_kind": "semantic_id",
            "focused": target.focused,
            "editable": target.editable,
            "backend_dom_node_id": target.backend_dom_node_id,
            "cdp_node_id": target.cdp_node_id,
        }),
    ))
}

async fn confirm_selector_hover(exec: &ToolExecutor, selector: &str, x: f64, y: f64) -> bool {
    for attempt in 0..3 {
        if exec
            .browser
            .is_selector_hovered(selector)
            .await
            .unwrap_or(false)
        {
            return true;
        }
        if attempt >= 2 {
            break;
        }
        sleep(Duration::from_millis(35)).await;
        if exec.browser.move_mouse(x, y).await.is_err() {
            break;
        }
    }
    false
}

pub async fn handle(
    exec: &ToolExecutor,
    tool: AgentTool,
    semantic_map: Option<&BTreeMap<u32, String>>,
) -> ToolExecutionResult {
    match tool {
        AgentTool::BrowserNavigate { url } => match exec.browser.navigate(&url).await {
            Ok(content) => {
                if let Some(reason) = detect_human_challenge(&url, &content) {
                    return ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=HumanChallengeRequired {}. Complete the challenge manually in your own browser/app, then resume: {}",
                        reason, url
                    ));
                }

                ToolExecutionResult::success(format!(
                    "Navigated to {}. Content len: {}",
                    url,
                    content.len()
                ))
            }
            Err(e) => ToolExecutionResult::failure(format!("Navigation failed: {}", e)),
        },
        AgentTool::BrowserSnapshot {} => match exec.browser.get_accessibility_tree().await {
            Ok(raw_tree) => {
                let transformed = apply_browser_auto_lens(raw_tree);
                ToolExecutionResult::success(render_browser_tree_xml(&transformed))
            }
            Err(e) => ToolExecutionResult::failure(format!("Extraction failed: {}", e)),
        },
        AgentTool::BrowserClick { selector } => handle_browser_click(exec, &selector).await,
        AgentTool::BrowserClickElement { id } => handle_browser_click_element(exec, &id).await,
        AgentTool::BrowserHover { selector, id } => {
            let selector_ref = selector.as_deref();
            let id_ref = id.as_deref();
            match resolve_hover_target(exec, selector_ref, id_ref).await {
                Ok((x, y, target)) => match exec.browser.move_mouse(x, y).await {
                    Ok(()) => {
                        let hovered = if let Some(selector) = selector_ref {
                            Some(confirm_selector_hover(exec, selector, x, y).await)
                        } else {
                            None
                        };
                        let payload = json!({
                            "pointer": {
                                "action": "hover",
                                "x": x,
                                "y": y,
                                "target": target,
                                "hovered": hovered,
                            }
                        });
                        if selector_ref.is_some() && hovered != Some(true) {
                            ToolExecutionResult::failure(format!(
                                "ERROR_CLASS=NoEffectAfterAction Browser hover target was not hovered: {}",
                                payload
                            ))
                        } else {
                            ToolExecutionResult::success(payload.to_string())
                        }
                    }
                    Err(e) => ToolExecutionResult::failure(format!("Browser hover failed: {}", e)),
                },
                Err(reason) => {
                    ToolExecutionResult::failure(format!("Browser hover failed: {}", reason))
                }
            }
        }
        AgentTool::BrowserMoveMouse { x, y } => match exec.browser.move_mouse(x as f64, y as f64).await {
            Ok(()) => {
                let state = exec.browser.pointer_state().await;
                let payload = json!({
                    "pointer": {
                        "action": "move",
                        "x": state.x,
                        "y": state.y,
                        "buttons": state.buttons,
                    }
                });
                ToolExecutionResult::success(payload.to_string())
            }
            Err(e) => ToolExecutionResult::failure(format!("Browser mouse move failed: {}", e)),
        },
        AgentTool::BrowserMouseDown { button } => {
            let button = normalized_browser_button(button.as_deref());
            let state = exec.browser.pointer_state().await;
            match exec.browser.mouse_down(state.x, state.y, button).await {
                Ok(()) => {
                    let state = exec.browser.pointer_state().await;
                    let payload = json!({
                        "pointer": {
                            "action": "mouse_down",
                            "button": button,
                            "x": state.x,
                            "y": state.y,
                            "buttons": state.buttons,
                        }
                    });
                    ToolExecutionResult::success(payload.to_string())
                }
                Err(e) => ToolExecutionResult::failure(format!("Browser mouse down failed: {}", e)),
            }
        }
        AgentTool::BrowserMouseUp { button } => {
            let button = normalized_browser_button(button.as_deref());
            let state = exec.browser.pointer_state().await;
            match exec.browser.mouse_up(state.x, state.y, button).await {
                Ok(()) => {
                    let state = exec.browser.pointer_state().await;
                    let payload = json!({
                        "pointer": {
                            "action": "mouse_up",
                            "button": button,
                            "x": state.x,
                            "y": state.y,
                            "buttons": state.buttons,
                        }
                    });
                    ToolExecutionResult::success(payload.to_string())
                }
                Err(e) => ToolExecutionResult::failure(format!("Browser mouse up failed: {}", e)),
            }
        }
        AgentTool::BrowserSyntheticClick { x, y } => {
            match exec.browser.synthetic_click(x as f64, y as f64).await {
                Ok(_) => ToolExecutionResult::success(format!("Clicked at ({}, {})", x, y)),
                Err(e) => ToolExecutionResult::failure(format!("Synthetic click failed: {}", e)),
            }
        }
        AgentTool::BrowserScroll { delta_x, delta_y } => {
            match exec.browser.scroll(delta_x, delta_y).await {
                Ok(outcome) => {
                    let payload = json!({ "scroll": outcome });
                    ToolExecutionResult::success(payload.to_string())
                }
                Err(e) => ToolExecutionResult::failure(format!("Browser scroll failed: {}", e)),
            }
        }
        AgentTool::BrowserType { text, selector } => {
            let selector_candidates = browser_type_selector_candidates(exec, selector.as_deref()).await;
            let mut last_error = None;

            for (index, candidate) in selector_candidates.iter().enumerate() {
                match exec.browser.type_text(&text, candidate.as_deref()).await {
                    Ok(outcome) => {
                    let payload = json!({
                        "typed": {
                            "requested_selector": selector,
                            "resolved_selector": candidate,
                            "selector": outcome.selector,
                            "dom_id": outcome.dom_id,
                            "tag_name": outcome.tag_name,
                            "text": text,
                            "value": outcome.value,
                            "focused": outcome.focused,
                            "scroll_top": outcome.scroll_top,
                            "scroll_height": outcome.scroll_height,
                            "client_height": outcome.client_height,
                            "can_scroll_up": outcome.can_scroll_up,
                            "can_scroll_down": outcome.can_scroll_down,
                            "already_satisfied": outcome.already_satisfied,
                            "autocomplete": outcome.autocomplete,
                        }
                    });
                        return ToolExecutionResult::success(payload.to_string());
                    }
                    Err(e) => {
                        let message = e.to_string();
                        last_error = Some(message.clone());
                        let has_more_candidates = index + 1 < selector_candidates.len();
                        if !(has_more_candidates && browser_type_error_supports_selector_retry(&message)) {
                            break;
                        }
                    }
                }
            }

            ToolExecutionResult::failure(format!(
                "Browser type failed: {}",
                last_error.unwrap_or_else(|| "unknown type error".to_string())
            ))
        }
        AgentTool::BrowserSelectText {
            selector,
            start_offset,
            end_offset,
        } => match exec
            .browser
            .select_text(selector.as_deref(), start_offset, end_offset)
            .await
        {
            Ok(result) if result.found && !result.selected_text.is_empty() => {
                let payload = json!({
                    "selection": {
                        "selector": selector,
                        "target_kind": result.target_kind,
                        "selected_text": result.selected_text,
                        "start_offset": result.start_offset,
                        "end_offset": result.end_offset,
                        "text_length": result.text_length,
                        "focused": result.focused,
                        "collapsed": result.collapsed,
                    }
                });
                ToolExecutionResult::success(payload.to_string())
            }
            Ok(result) if !result.found => {
                ToolExecutionResult::failure("Browser select text failed: target not found")
            }
            Ok(result) => ToolExecutionResult::failure(format!(
                "ERROR_CLASS=NoEffectAfterAction Browser select text produced an empty selection: {}",
                json!({ "selection": result })
            )),
            Err(e) => ToolExecutionResult::failure(format!("Browser select text failed: {}", e)),
        },
        AgentTool::BrowserKey { key, modifiers } => {
            let modifiers = modifiers.unwrap_or_default();
            match exec.browser.press_key(&key, &modifiers).await {
                Ok(outcome) => {
                    let payload = json!({
                        "key": {
                            "key": key,
                            "modifiers": modifiers,
                            "is_chord": !modifiers.is_empty(),
                            "selector": outcome.selector,
                            "dom_id": outcome.dom_id,
                            "tag_name": outcome.tag_name,
                            "value": outcome.value,
                            "focused": outcome.focused,
                            "scroll_top": outcome.scroll_top,
                            "scroll_height": outcome.scroll_height,
                            "client_height": outcome.client_height,
                            "can_scroll_up": outcome.can_scroll_up,
                            "can_scroll_down": outcome.can_scroll_down,
                            "autocomplete": outcome.autocomplete,
                        }
                    });
                    ToolExecutionResult::success(payload.to_string())
                }
                Err(e) => ToolExecutionResult::failure(format!("Browser key press failed: {}", e)),
            }
        }
        AgentTool::BrowserCopySelection {} => match exec.browser.read_selection().await {
            Ok(selection) if selection.found && !selection.selected_text.is_empty() => {
                match exec.os.set_clipboard(&selection.selected_text).await {
                    Ok(()) => {
                        let payload = json!({
                            "clipboard": {
                                "action": "copy_selection",
                                "target_kind": selection.target_kind,
                                "text": selection.selected_text,
                                "text_length": selection.selected_text.chars().count(),
                                "selection_start": selection.start_offset,
                                "selection_end": selection.end_offset,
                            }
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(err) => ToolExecutionResult::failure(format!(
                        "Browser copy selection failed: {}",
                        err
                    )),
                }
            }
            Ok(selection) => ToolExecutionResult::failure(format!(
                "ERROR_CLASS=NoEffectAfterAction Browser copy selection has no selected text: {}",
                json!({ "selection": selection })
            )),
            Err(e) => ToolExecutionResult::failure(format!("Browser copy selection failed: {}", e)),
        },
        AgentTool::BrowserPasteClipboard { selector } => match exec.os.get_clipboard().await {
            Ok(clipboard_text) if !clipboard_text.is_empty() => {
                match exec
                    .browser
                    .type_text(&clipboard_text, selector.as_deref())
                    .await
                {
                    Ok(outcome) => {
                        let payload = json!({
                            "clipboard": {
                                "action": "paste_clipboard",
                                "selector": outcome.selector,
                                "text": clipboard_text,
                                "text_length": clipboard_text.chars().count(),
                                "value": outcome.value,
                                "focused": outcome.focused,
                                "autocomplete": outcome.autocomplete,
                            }
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Browser paste clipboard failed: {}",
                        e
                    )),
                }
            }
            Ok(_) => ToolExecutionResult::failure(
                "ERROR_CLASS=NoEffectAfterAction Browser paste clipboard has no clipboard text",
            ),
            Err(err) => ToolExecutionResult::failure(format!(
                "Browser paste clipboard failed: {}",
                err
            )),
        },
        AgentTool::BrowserFindText {
            query,
            scope,
            scroll,
        } => match exec
            .browser
            .find_text(&query, scope.as_deref(), scroll)
            .await
        {
            Ok(result) => {
                let payload = json!({
                    "query": query,
                    "result": result,
                });
                ToolExecutionResult::success(payload.to_string())
            }
            Err(e) => ToolExecutionResult::failure(format!("Browser find_text failed: {}", e)),
        },
        AgentTool::BrowserCanvasSummary { selector } => {
            match exec.browser.selector_canvas_shape_summary(&selector).await {
                Ok(summary) if summary.found => {
                    let payload = json!({
                        "canvas": {
                            "selector": selector,
                            "summary": summary,
                        }
                    });
                    ToolExecutionResult::success(payload.to_string())
                }
                Ok(_) => ToolExecutionResult::failure(format!(
                    "Browser canvas summary failed: selector '{}' not found",
                    selector
                )),
                Err(e) => {
                    ToolExecutionResult::failure(format!("Browser canvas summary failed: {}", e))
                }
            }
        }
        AgentTool::BrowserScreenshot { full_page } => {
            match exec.browser.capture_tab_screenshot(full_page).await {
                Ok(image_bytes) => ToolExecutionResult::success_with_visual_observation(
                    format!(
                        "Captured browser screenshot (full_page={}, bytes={})",
                        full_page,
                        image_bytes.len()
                    ),
                    image_bytes,
                ),
                Err(e) => ToolExecutionResult::failure(format!("Browser screenshot failed: {}", e)),
            }
        }
        AgentTool::BrowserWait {
            ms,
            condition,
            selector,
            query,
            scope,
            timeout_ms,
        } => {
            let normalized_condition = condition
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if normalized_condition.is_some() && ms.is_some() {
                return ToolExecutionResult::failure(
                    "Browser wait failed: provide either 'ms' or 'condition', not both.",
                );
            }

            if let Some(condition) = normalized_condition {
                let timeout_ms = timeout_ms.unwrap_or(5_000);
                match exec
                    .browser
                    .wait_for_condition(
                        condition,
                        selector.as_deref(),
                        query.as_deref(),
                        scope.as_deref(),
                        timeout_ms,
                    )
                    .await
                {
                    Ok(result) if result.met => {
                        let payload = json!({
                            "wait": result
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Ok(result) => ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=TimeoutOrHang Browser wait condition '{}' not met within {}ms",
                        result.condition, result.elapsed_ms
                    )),
                    Err(e) => ToolExecutionResult::failure(format!("Browser wait failed: {}", e)),
                }
            } else if let Some(ms) = ms {
                match exec.browser.wait_ms(ms).await {
                    Ok(waited_ms) => {
                        let payload = json!({
                            "wait": {
                                "condition": "fixed_ms",
                                "met": true,
                                "elapsed_ms": waited_ms
                            }
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!("Browser wait failed: {}", e)),
                }
            } else {
                ToolExecutionResult::failure(
                    "Browser wait failed: provide either 'ms' or 'condition'.",
                )
            }
        }
        AgentTool::BrowserUploadFile {
            paths,
            selector,
            som_id,
        } => {
            let scoped_paths =
                match resolve_scoped_upload_paths(&paths, exec.working_directory.as_deref()) {
                    Ok(paths) => paths,
                    Err(reason) => {
                        return ToolExecutionResult::failure(format!(
                            "ERROR_CLASS=PathScopeViolation Browser upload failed: {}",
                            reason
                        ))
                    }
                };

            let selector = selector
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if selector.is_some() && som_id.is_some() {
                return ToolExecutionResult::failure(
                    "Browser upload failed: provide either selector or som_id, not both.",
                );
            }

            if let Some(som_id) = som_id {
                let target =
                    match resolve_semantic_target_from_som(exec, som_id, semantic_map).await {
                        Ok(target) => target,
                        Err(reason) => {
                            return ToolExecutionResult::failure(format!(
                                "Browser upload failed: {}",
                                reason
                            ))
                        }
                    };
                let Some(backend_dom_node_id) = target.backend_dom_node_id.as_deref() else {
                    return ToolExecutionResult::failure(format!(
                        "Browser upload failed: target for som_id={} has no backend DOM node id.",
                        som_id
                    ));
                };
                match exec
                    .browser
                    .upload_files_to_backend_node(backend_dom_node_id, &scoped_paths)
                    .await
                {
                    Ok(attached) => {
                        let payload = json!({
                            "som_id": som_id,
                            "attached_files": attached
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!("Browser upload failed: {}", e)),
                }
            } else {
                match exec.browser.upload_files(selector, &scoped_paths).await {
                    Ok(attached) => ToolExecutionResult::success(format!(
                        "Attached {} file(s) using selector {}",
                        attached,
                        selector.unwrap_or("input[type='file']")
                    )),
                    Err(e) => ToolExecutionResult::failure(format!("Browser upload failed: {}", e)),
                }
            }
        }
        AgentTool::BrowserDropdownOptions {
            id,
            selector,
            som_id,
        } => {
            let id = id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let selector = selector
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let locator_count = usize::from(id.is_some())
                + usize::from(selector.is_some())
                + usize::from(som_id.is_some());
            if locator_count != 1 {
                return ToolExecutionResult::failure(
                    "Browser dropdown options failed: provide exactly one of id, selector, or som_id.",
                );
            }

            if let Some(id) = id {
                let target = match resolve_browser_target_from_id(exec, id).await {
                    Ok(target) => target,
                    Err(reason) => {
                        return ToolExecutionResult::failure(format!(
                            "Browser dropdown options failed: {}",
                            reason
                        ))
                    }
                };
                let Some((x, y)) = target.center_point else {
                    return ToolExecutionResult::failure(format!(
                        "Browser dropdown options failed: target for id='{}' has no geometry center.",
                        id
                    ));
                };
                match exec.browser.dropdown_options_at_point(x, y).await {
                    Ok(options) => {
                        let payload = json!({
                            "id": id,
                            "options": options,
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Browser dropdown options failed: {}",
                        e
                    )),
                }
            } else if let Some(selector) = selector {
                match exec.browser.dropdown_options(selector).await {
                    Ok(options) => {
                        let payload = json!({
                            "selector": selector,
                            "options": options,
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Browser dropdown options failed: {}",
                        e
                    )),
                }
            } else if let Some(som_id) = som_id {
                let target =
                    match resolve_semantic_target_from_som(exec, som_id, semantic_map).await {
                        Ok(target) => target,
                        Err(reason) => {
                            return ToolExecutionResult::failure(format!(
                                "Browser dropdown options failed: {}",
                                reason
                            ))
                        }
                    };
                let Some((x, y)) = target.center_point else {
                    return ToolExecutionResult::failure(format!(
                        "Browser dropdown options failed: target for som_id={} has no geometry center.",
                        som_id
                    ));
                };
                match exec.browser.dropdown_options_at_point(x, y).await {
                    Ok(options) => {
                        let payload = json!({
                            "som_id": som_id,
                            "options": options,
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Browser dropdown options failed: {}",
                        e
                    )),
                }
            } else {
                ToolExecutionResult::failure(
                    "Browser dropdown options failed: provide id, selector, or som_id.",
                )
            }
        }
        AgentTool::BrowserSelectDropdown {
            id,
            selector,
            som_id,
            value,
            label,
        } => {
            let id = id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let selector = selector
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let locator_count = usize::from(id.is_some())
                + usize::from(selector.is_some())
                + usize::from(som_id.is_some());
            if locator_count != 1 {
                return ToolExecutionResult::failure(
                    "Browser dropdown select failed: provide exactly one of id, selector, or som_id.",
                );
            }

            if let Some(id) = id {
                let target = match resolve_browser_target_from_id(exec, id).await {
                    Ok(target) => target,
                    Err(reason) => {
                        return ToolExecutionResult::failure(format!(
                            "Browser dropdown select failed: {}",
                            reason
                        ))
                    }
                };
                let Some((x, y)) = target.center_point else {
                    return ToolExecutionResult::failure(format!(
                        "Browser dropdown select failed: target for id='{}' has no geometry center.",
                        id
                    ));
                };
                match exec
                    .browser
                    .select_dropdown_at_point(x, y, value.as_deref(), label.as_deref())
                    .await
                {
                    Ok(selected) => {
                        let payload = json!({
                            "id": id,
                            "selected": selected,
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Browser dropdown select failed: {}",
                        e
                    )),
                }
            } else if let Some(selector) = selector {
                match exec
                    .browser
                    .select_dropdown(selector, value.as_deref(), label.as_deref())
                    .await
                {
                    Ok(selected) => {
                        let payload = json!({
                            "selector": selector,
                            "selected": selected,
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Browser dropdown select failed: {}",
                        e
                    )),
                }
            } else if let Some(som_id) = som_id {
                let target =
                    match resolve_semantic_target_from_som(exec, som_id, semantic_map).await {
                        Ok(target) => target,
                        Err(reason) => {
                            return ToolExecutionResult::failure(format!(
                                "Browser dropdown select failed: {}",
                                reason
                            ))
                        }
                    };
                let Some((x, y)) = target.center_point else {
                    return ToolExecutionResult::failure(format!(
                        "Browser dropdown select failed: target for som_id={} has no geometry center.",
                        som_id
                    ));
                };
                match exec
                    .browser
                    .select_dropdown_at_point(x, y, value.as_deref(), label.as_deref())
                    .await
                {
                    Ok(selected) => {
                        let payload = json!({
                            "som_id": som_id,
                            "selected": selected,
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Browser dropdown select failed: {}",
                        e
                    )),
                }
            } else {
                ToolExecutionResult::failure(
                    "Browser dropdown select failed: provide id, selector, or som_id.",
                )
            }
        }
        AgentTool::BrowserGoBack { steps } => {
            let steps = steps.unwrap_or(1).max(1);
            match exec.browser.go_back(steps).await {
                Ok((moved, url)) => ToolExecutionResult::success(format!(
                    "Went back {} step(s). Active URL: {}",
                    moved, url
                )),
                Err(e) => ToolExecutionResult::failure(format!("Browser go_back failed: {}", e)),
            }
        }
        AgentTool::BrowserTabList {} => match exec.browser.list_tabs().await {
            Ok(tabs) => {
                let payload = json!({ "tabs": tabs });
                ToolExecutionResult::success(payload.to_string())
            }
            Err(e) => ToolExecutionResult::failure(format!("Browser tab listing failed: {}", e)),
        },
        AgentTool::BrowserTabSwitch { tab_id } => match exec.browser.switch_tab(&tab_id).await {
            Ok(tab) => {
                let payload = json!({
                    "active_tab": tab,
                });
                ToolExecutionResult::success(payload.to_string())
            }
            Err(e) => ToolExecutionResult::failure(format!("Browser tab switch failed: {}", e)),
        },
        AgentTool::BrowserTabClose { tab_id, .. } => match exec.browser.close_tab(&tab_id).await {
            Ok(_) => ToolExecutionResult::success(format!("Closed tab '{}'", tab_id)),
            Err(e) => ToolExecutionResult::failure(format!("Browser tab close failed: {}", e)),
        },
        _ => ToolExecutionResult::failure("Unsupported Browser action"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        browser_type_error_supports_selector_retry, browser_type_selector_fallbacks_for_target,
        browser_type_selector_lookup_token, resolve_scoped_upload_paths, BrowserSemanticTarget,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ioi_browser_handler_{}_{}_{}",
            name,
            std::process::id(),
            suffix
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn resolve_scoped_upload_paths_resolves_relative_files_within_scope() {
        let scope_root = temp_dir("scope_ok");
        let nested = scope_root.join("docs");
        fs::create_dir_all(&nested).expect("create nested dir");
        let file_path = nested.join("invoice.txt");
        fs::write(&file_path, b"ok").expect("write test file");

        let resolved = resolve_scoped_upload_paths(
            &[String::from("docs/invoice.txt")],
            Some(scope_root.to_string_lossy().as_ref()),
        )
        .expect("paths should resolve");

        let expected = fs::canonicalize(&file_path).expect("canonical file");
        assert_eq!(resolved, vec![expected.to_string_lossy().to_string()]);

        let _ = fs::remove_dir_all(&scope_root);
    }

    #[test]
    fn resolve_scoped_upload_paths_rejects_absolute_paths_outside_scope() {
        let scope_root = temp_dir("scope_root");
        let outside_root = temp_dir("outside_root");
        let outside_file = outside_root.join("secret.txt");
        fs::write(&outside_file, b"nope").expect("write outside file");
        let outside_canonical = fs::canonicalize(&outside_file).expect("canonical outside file");

        let err = resolve_scoped_upload_paths(
            &[outside_canonical.to_string_lossy().to_string()],
            Some(scope_root.to_string_lossy().as_ref()),
        )
        .expect_err("outside path must fail");

        assert!(err.contains("outside allowed scope root"));

        let _ = fs::remove_dir_all(&scope_root);
        let _ = fs::remove_dir_all(&outside_root);
    }

    #[test]
    fn browser_type_selector_lookup_token_accepts_semantic_hash_reference() {
        assert_eq!(
            browser_type_selector_lookup_token("#inp_dispatch_note"),
            Some("inp_dispatch_note")
        );
    }

    #[test]
    fn browser_type_selector_lookup_token_rejects_complex_css() {
        assert_eq!(browser_type_selector_lookup_token("#note textarea"), None);
        assert_eq!(browser_type_selector_lookup_token("[id=\"note\"]"), None);
    }

    #[test]
    fn browser_type_selector_fallbacks_prefer_grounded_dom_selector_for_semantic_ids() {
        let target = BrowserSemanticTarget {
            semantic_id: Some("inp_dispatch_note".to_string()),
            dom_id: Some("note".to_string()),
            selector: Some("[id=\"note\"]".to_string()),
            ..Default::default()
        };

        let fallbacks = browser_type_selector_fallbacks_for_target("#inp_dispatch_note", &target);

        assert_eq!(fallbacks, vec!["[id=\"note\"]".to_string()]);
    }

    #[test]
    fn browser_type_focus_errors_retry_with_alternate_selectors() {
        assert!(browser_type_error_supports_selector_retry(
            "Failed to focus selector '#inp_dispatch_note'"
        ));
        assert!(browser_type_error_supports_selector_retry(
            "Selector focus failed for '#inp_dispatch_note': hidden"
        ));
        assert!(!browser_type_error_supports_selector_retry(
            "Type failed: session crashed"
        ));
    }
}
