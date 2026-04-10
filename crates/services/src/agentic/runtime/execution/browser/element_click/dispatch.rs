fn target_has_grounded_dom_click_locator(target: &BrowserSemanticTarget) -> bool {
    target
        .selector
        .as_deref()
        .map(str::trim)
        .is_some_and(|selector| !selector.is_empty())
        || target
            .dom_id
            .as_deref()
            .map(str::trim)
            .is_some_and(|dom_id| !dom_id.is_empty())
}

fn click_selector_fallback_locator(target: &BrowserSemanticTarget) -> Option<String> {
    target
        .selector
        .as_deref()
        .map(str::trim)
        .filter(|selector| !selector.is_empty())
        .map(str::to_string)
        .or_else(|| {
            target
                .dom_id
                .as_deref()
                .map(str::trim)
                .filter(|dom_id| !dom_id.is_empty())
                .map(|dom_id| {
                    format!(
                        r#"[id="{}"]"#,
                        dom_id.replace('\\', r#"\\"#).replace('"', r#"\""#)
                    )
                })
        })
}

fn prefers_selector_click_path(target: &BrowserSemanticTarget) -> bool {
    if click_selector_fallback_locator(target).is_none() {
        return false;
    }

    if target.dom_clickable {
        return true;
    }

    let Some(tag_name) = target.tag_name.as_deref().map(str::trim) else {
        return false;
    };

    matches!(
        tag_name.to_ascii_lowercase().as_str(),
        "a" | "button" | "input" | "label" | "option" | "select" | "summary" | "textarea"
    )
}

fn uses_geometry_only_click_verification(target: &BrowserSemanticTarget) -> bool {
    target.center_point.is_some()
        && target
            .backend_dom_node_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        && target.element_hash.is_none()
        && target
            .cdp_node_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        && target
            .dom_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        && target.identity_attributes.is_empty()
        && target.stable_hash.is_none()
        && target
            .x_path
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
}

fn safe_inset_click_point(target: &BrowserSemanticTarget) -> Option<(f64, f64)> {
    let tag_name = target.tag_name.as_deref()?.trim().to_ascii_lowercase();
    if !matches!(
        tag_name.as_str(),
        "div"
            | "span"
            | "li"
            | "td"
            | "tr"
            | "section"
            | "article"
            | "main"
            | "header"
            | "footer"
            | "p"
    ) {
        return None;
    }

    let (x, y, width, height) = target.rect_bounds?;
    if width < 100 || height < 100 {
        return None;
    }

    let inset_y = (height as f64 * 0.12).clamp(12.0, 24.0);
    Some((x as f64 + (width as f64 / 2.0), y as f64 + inset_y))
}

fn snapped_dom_click_coordinate(value: f64, origin: i32, extent: i32) -> f64 {
    if extent <= 0 {
        return value;
    }

    let min = if extent > 2 {
        origin as f64 + 1.0
    } else {
        origin as f64
    };
    let max = if extent > 2 {
        origin as f64 + (extent - 2) as f64
    } else {
        origin as f64 + (extent - 1).max(0) as f64
    };
    value.round().clamp(min, max)
}

fn geometry_dispatch_point(target: &BrowserSemanticTarget, point: (f64, f64)) -> (f64, f64) {
    if !prefers_selector_click_path(target) {
        return point;
    }

    let Some((x, y, width, height)) = target.rect_bounds else {
        return point;
    };
    if width <= 0 || height <= 0 {
        return point;
    }

    (
        snapped_dom_click_coordinate(point.0, x, width),
        snapped_dom_click_coordinate(point.1, y, height),
    )
}

#[derive(Debug)]
struct CurrentClickTreeRefresh {
    transformed: Option<AccessibilityNode>,
    source: &'static str,
    elapsed_ms: u64,
    error: Option<String>,
}

fn target_prefers_live_tree_refresh_before_dispatch(
    target: &BrowserSemanticTarget,
    resolved_from: &str,
) -> bool {
    resolved_from != "current_accessibility_tree"
        && prefers_selector_click_path(target)
        && target
            .backend_dom_node_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        && target
            .cdp_node_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
}

async fn refresh_current_click_tree(
    exec: &ToolExecutor,
    id: &str,
    current_tree_refresh_timeout: Duration,
) -> CurrentClickTreeRefresh {
    let current_tree_started_at = Instant::now();
    emit_browser_click_trace("current_tree_refresh_start", format!("id={id}"));
    match timeout(
        current_tree_refresh_timeout,
        exec.browser.get_accessibility_tree(),
    )
    .await
    {
        Ok(Ok(raw_tree)) => {
            let elapsed_ms = current_tree_started_at.elapsed().as_millis() as u64;
            emit_browser_click_trace(
                "current_tree_refresh_done",
                format!("elapsed_ms={elapsed_ms}"),
            );
            CurrentClickTreeRefresh {
                transformed: Some(apply_browser_auto_lens_with_som(&raw_tree)),
                source: "current_accessibility_tree",
                elapsed_ms,
                error: None,
            }
        }
        Ok(Err(error)) => {
            let elapsed_ms = current_tree_started_at.elapsed().as_millis() as u64;
            emit_browser_click_trace(
                "current_tree_refresh_error",
                format!("elapsed_ms={elapsed_ms} error={error}"),
            );
            CurrentClickTreeRefresh {
                transformed: None,
                source: "current_accessibility_tree_error",
                elapsed_ms,
                error: Some(error.to_string()),
            }
        }
        Err(_) => {
            let elapsed_ms = current_tree_started_at.elapsed().as_millis() as u64;
            emit_browser_click_trace(
                "current_tree_refresh_timeout",
                format!(
                    "elapsed_ms={elapsed_ms} timeout_ms={}",
                    current_tree_refresh_timeout.as_millis()
                ),
            );
            CurrentClickTreeRefresh {
                transformed: None,
                source: "current_accessibility_tree_timeout",
                elapsed_ms,
                error: Some(format!(
                    "current accessibility tree refresh timed out after {}ms",
                    current_tree_refresh_timeout.as_millis()
                )),
            }
        }
    }
}

fn click_dispatch_settle_schedule(target: &BrowserSemanticTarget) -> &'static [u64] {
    if uses_geometry_only_click_verification(target) {
        &CLICK_DISPATCH_SETTLE_MS_GEOMETRY_ONLY
    } else {
        &CLICK_DISPATCH_SETTLE_MS_DOM_BACKED
    }
}

fn annotate_click_result_verify(
    mut result: ToolExecutionResult,
    annotations: &[(&str, serde_json::Value)],
) -> ToolExecutionResult {
    if annotations.is_empty() {
        return result;
    }

    let annotate_text = |text: &mut String| {
        let Some(verify_idx) = text.rfind(" verify=") else {
            return;
        };
        let prefix = text[..verify_idx].to_string();
        let verify_raw = text[verify_idx + " verify=".len()..].trim();
        let Ok(mut verify_value) = serde_json::from_str::<serde_json::Value>(verify_raw) else {
            return;
        };
        let Some(verify_obj) = verify_value.as_object_mut() else {
            return;
        };
        for (key, value) in annotations {
            verify_obj.insert((*key).to_string(), value.clone());
        }
        *text = format!("{prefix} verify={verify_value}");
    };

    if let Some(history_entry) = result.history_entry.as_mut() {
        annotate_text(history_entry);
    }
    if let Some(error) = result.error.as_mut() {
        annotate_text(error);
    }

    result
}

fn history_entry_verify_value(entry: Option<&str>) -> Option<serde_json::Value> {
    let entry = entry.map(str::trim).filter(|value| !value.is_empty())?;
    let (_, verify_raw) = entry.split_once(" verify=")?;
    serde_json::from_str(verify_raw).ok()
}

fn click_result_marks_browser_session_unstable(result: &ToolExecutionResult) -> bool {
    history_entry_verify_value(result.error.as_deref())
        .as_ref()
        .is_some_and(verify_marks_browser_session_unstable)
}

fn click_result_has_dispatch_timeout(result: &ToolExecutionResult) -> bool {
    history_entry_verify_value(result.error.as_deref())
        .and_then(|verify| {
            verify
                .get("dispatch_failures")
                .and_then(serde_json::Value::as_array)
                .cloned()
        })
        .is_some_and(|failures| {
            failures.iter().any(|failure| {
                failure
                    .get("error")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|error| error.contains("dispatch timed out"))
            })
        })
}

fn dispatch_error_is_timeout(error: &str) -> bool {
    error.contains("dispatch timed out")
}

fn should_refresh_recent_accessibility_snapshot_after_success(
    postcondition: &ClickElementPostcondition,
) -> bool {
    postcondition.material_semantic_change && !postcondition.editable_focus_transition
}

async fn refresh_recent_accessibility_snapshot_after_success(
    exec: &ToolExecutor,
    verify: &mut serde_json::Value,
    postcondition: &ClickElementPostcondition,
) {
    if !should_refresh_recent_accessibility_snapshot_after_success(postcondition) {
        return;
    }

    sleep(Duration::from_millis(
        CLICK_DISPATCH_POST_SUCCESS_REFRESH_MS,
    ))
    .await;

    let refresh_started_at = Instant::now();
    let refresh = timeout(
        CLICK_DISPATCH_POST_SUCCESS_REFRESH_TIMEOUT,
        exec.browser.get_prompt_observation_tree(),
    )
    .await;

    verify["post_success_refresh"] = match refresh {
        Ok(Ok(_)) => json!({
            "attempted": true,
            "delay_ms": CLICK_DISPATCH_POST_SUCCESS_REFRESH_MS,
            "snapshot_elapsed_ms": refresh_started_at.elapsed().as_millis() as u64,
            "prompt_observation_updated": true,
            "timed_out": false,
            "updated": true,
        }),
        Ok(Err(error)) => json!({
            "attempted": true,
            "delay_ms": CLICK_DISPATCH_POST_SUCCESS_REFRESH_MS,
            "snapshot_elapsed_ms": refresh_started_at.elapsed().as_millis() as u64,
            "prompt_observation_updated": false,
            "timed_out": false,
            "updated": false,
            "error": error.to_string(),
        }),
        Err(_) => json!({
            "attempted": true,
            "delay_ms": CLICK_DISPATCH_POST_SUCCESS_REFRESH_MS,
            "snapshot_elapsed_ms": refresh_started_at.elapsed().as_millis() as u64,
            "prompt_observation_updated": false,
            "timed_out": true,
            "timeout_ms": CLICK_DISPATCH_POST_SUCCESS_REFRESH_TIMEOUT.as_millis() as u64,
            "updated": false,
        }),
    };
}

async fn verify_click_dispatch(
    exec: &ToolExecutor,
    pre_tree_xml: &str,
    semantic_target: &BrowserSemanticTarget,
    pre_url: Option<&str>,
    method: &str,
    center_point: Option<(f64, f64)>,
    pre_focused_control: Option<&BrowserSemanticTarget>,
    dispatch_started_at_ms: u64,
    dispatch_elapsed_ms: u64,
    execution_started_at: Instant,
    execution_deadline: Instant,
) -> (bool, serde_json::Value) {
    let verify_started_at = Instant::now();
    let verify_started_at_ms = unix_timestamp_ms_now();
    let settle_schedule = click_dispatch_settle_schedule(semantic_target);
    for (attempt_idx, settle_ms) in settle_schedule.iter().copied().enumerate() {
        let is_final_attempt = attempt_idx + 1 == settle_schedule.len();
        if settle_ms > 0 {
            sleep(Duration::from_millis(settle_ms)).await;
        }

        let Some(snapshot_timeout) = remaining_click_element_budget(execution_deadline) else {
            let mut verify = json!({
                "method": method,
                "dispatch_succeeded": true,
                "pre_target": semantic_target_verification_json(Some(semantic_target)),
                "postcondition": {
                    "met": false,
                },
                "budget_exhausted": true,
                "execution_budget_ms": CLICK_ELEMENT_EXECUTION_BUDGET.as_millis() as u64,
                "execution_elapsed_ms": execution_started_at.elapsed().as_millis() as u64,
                "settle_ms": settle_ms,
                "dispatch_started_at_ms": dispatch_started_at_ms,
                "dispatch_finished_at_ms": dispatch_started_at_ms.saturating_add(dispatch_elapsed_ms),
                "dispatch_elapsed_ms": dispatch_elapsed_ms,
                "verify_started_at_ms": verify_started_at_ms,
                "verify_elapsed_ms": verify_started_at.elapsed().as_millis() as u64,
            });
            if let Some((x, y)) = center_point {
                verify["center_point"] = json!([x, y]);
            }
            return (false, verify);
        };

        let snapshot_started_at = Instant::now();
        match timeout(snapshot_timeout, exec.browser.get_accessibility_tree()).await {
            Ok(Ok(post_raw_tree)) => {
                let post_url = exec.browser.active_url().await.ok();
                let post_url_ref = post_url
                    .as_deref()
                    .map(str::trim)
                    .filter(|url| !url.is_empty());
                let pre_url_ref = pre_url.map(str::trim).filter(|url| !url.is_empty());
                let post_transformed = apply_browser_auto_lens_with_som(&post_raw_tree);
                let post_tree_xml = render_browser_tree_xml(&post_transformed);
                let post_target =
                    find_semantic_target_for_verification(&post_transformed, semantic_target);
                let focused_control = find_focused_semantic_target(&post_transformed);
                let postcondition = click_element_postcondition_met(
                    pre_tree_xml,
                    semantic_target,
                    pre_url_ref,
                    &post_tree_xml,
                    post_target.as_ref(),
                    post_url_ref,
                );
                let mut verify = json!({
                    "method": method,
                    "dispatch_succeeded": true,
                    "pre_target": semantic_target_verification_json(Some(semantic_target)),
                    "post_target": semantic_target_verification_json(post_target.as_ref()),
                    "focused_control": semantic_target_verification_json(focused_control.as_ref()),
                    "postcondition": {
                        "met": postcondition.met(),
                        "target_disappeared": postcondition.target_disappeared,
                        "editable_focus_transition": postcondition.editable_focus_transition,
                        "tree_changed": postcondition.tree_changed,
                        "url_changed": postcondition.url_changed,
                        "material_semantic_change": postcondition.material_semantic_change,
                        "semantic_change_delta": postcondition.semantic_change_delta,
                    },
                    "pre_url": pre_url_ref,
                    "post_url": post_url_ref,
                    "settle_ms": settle_ms,
                    "dispatch_started_at_ms": dispatch_started_at_ms,
                    "dispatch_finished_at_ms": dispatch_started_at_ms.saturating_add(dispatch_elapsed_ms),
                    "dispatch_elapsed_ms": dispatch_elapsed_ms,
                    "verify_started_at_ms": verify_started_at_ms,
                    "post_snapshot_elapsed_ms": snapshot_started_at.elapsed().as_millis() as u64,
                    "verify_elapsed_ms": verify_started_at.elapsed().as_millis() as u64,
                });
                let success = click_element_postcondition_counts_as_success(
                    semantic_target,
                    pre_focused_control,
                    post_target.as_ref(),
                    focused_control.as_ref(),
                    &postcondition,
                );
                verify["postcondition"]["met"] = json!(success);
                if let Some((x, y)) = center_point {
                    verify["center_point"] = json!([x, y]);
                }
                if success {
                    refresh_recent_accessibility_snapshot_after_success(
                        exec,
                        &mut verify,
                        &postcondition,
                    )
                    .await;
                    return (true, verify);
                }
                if is_final_attempt {
                    return (false, verify);
                }
            }
            Ok(Err(e)) => {
                let error_text = e.to_string();
                let browser_session_unstable = browser_session_unstable_error(&error_text);
                let post_url = verification_post_url(exec, browser_session_unstable).await;
                let post_url_ref = post_url
                    .as_deref()
                    .map(str::trim)
                    .filter(|url| !url.is_empty());
                let pre_url_ref = pre_url.map(str::trim).filter(|url| !url.is_empty());
                let url_changed = pre_url_ref
                    .zip(post_url_ref)
                    .is_some_and(|(pre, post)| pre != post);
                let mut verify = json!({
                    "method": method,
                    "dispatch_succeeded": true,
                    "postcondition": {
                        "met": url_changed,
                        "url_changed": url_changed,
                    },
                    "post_snapshot_error": error_text,
                    "browser_session_unstable": browser_session_unstable,
                    "pre_url": pre_url_ref,
                    "post_url": post_url_ref,
                    "settle_ms": settle_ms,
                    "dispatch_started_at_ms": dispatch_started_at_ms,
                    "dispatch_finished_at_ms": dispatch_started_at_ms.saturating_add(dispatch_elapsed_ms),
                    "dispatch_elapsed_ms": dispatch_elapsed_ms,
                    "verify_started_at_ms": verify_started_at_ms,
                    "post_snapshot_elapsed_ms": snapshot_started_at.elapsed().as_millis() as u64,
                    "verify_elapsed_ms": verify_started_at.elapsed().as_millis() as u64,
                });
                if let Some((x, y)) = center_point {
                    verify["center_point"] = json!([x, y]);
                }
                if browser_session_unstable || url_changed || is_final_attempt {
                    return (url_changed, verify);
                }
            }
            Err(_) => {
                let mut verify = json!({
                    "method": method,
                    "dispatch_succeeded": true,
                    "postcondition": {
                        "met": false,
                    },
                    "post_snapshot_error": format!(
                        "execution budget exhausted before post-dispatch snapshot after {} ms",
                        CLICK_ELEMENT_EXECUTION_BUDGET.as_millis()
                    ),
                    "budget_exhausted": true,
                    "execution_budget_ms": CLICK_ELEMENT_EXECUTION_BUDGET.as_millis() as u64,
                    "execution_elapsed_ms": execution_started_at.elapsed().as_millis() as u64,
                    "settle_ms": settle_ms,
                    "dispatch_started_at_ms": dispatch_started_at_ms,
                    "dispatch_finished_at_ms": dispatch_started_at_ms.saturating_add(dispatch_elapsed_ms),
                    "dispatch_elapsed_ms": dispatch_elapsed_ms,
                    "verify_started_at_ms": verify_started_at_ms,
                    "post_snapshot_elapsed_ms": snapshot_started_at.elapsed().as_millis() as u64,
                    "verify_elapsed_ms": verify_started_at.elapsed().as_millis() as u64,
                });
                if let Some((x, y)) = center_point {
                    verify["center_point"] = json!([x, y]);
                }
                return (false, verify);
            }
        }
    }
    unreachable!("verification settle loop should return on the final attempt")
}

fn dispatch_failure_verify(
    method: &str,
    dispatch_elapsed_ms: u64,
    error: &str,
    center_point: Option<(f64, f64)>,
) -> serde_json::Value {
    let mut failure = json!({
        "method": method,
        "dispatch_elapsed_ms": dispatch_elapsed_ms,
        "error": error,
    });
    if let Some((x, y)) = center_point {
        failure["center_point"] = json!([x, y]);
    }
    failure
}

