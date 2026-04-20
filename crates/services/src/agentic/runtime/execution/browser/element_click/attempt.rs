fn annotate_prior_click_attempts(
    verify: &mut serde_json::Value,
    prior_attempts: &[serde_json::Value],
    prior_dispatch_failures: &[serde_json::Value],
) {
    if !prior_attempts.is_empty() {
        verify["prior_attempts"] = json!(prior_attempts);
    }
    if !prior_dispatch_failures.is_empty() {
        verify["prior_dispatch_failures"] = json!(prior_dispatch_failures);
    }
}

async fn attempt_click_element_with_target(
    exec: &ToolExecutor,
    id: &str,
    semantic_target: &BrowserSemanticTarget,
    _target_resolution_source: &str,
    pre_tree_xml: &str,
    pre_url: Option<&str>,
    pre_focused_control: Option<&BrowserSemanticTarget>,
    execution_started_at: Instant,
    execution_deadline: Instant,
) -> ToolExecutionResult {
    let mut click_errors: Vec<String> = Vec::new();
    let mut attempt_verification: Vec<serde_json::Value> = Vec::new();
    let mut dispatch_failures: Vec<serde_json::Value> = Vec::new();
    let safe_inset_point = safe_inset_click_point(semantic_target);
    let selector_click_attempted_first = prefers_selector_click_path(semantic_target);

    let budget_exhausted_failure =
        |click_errors: Vec<String>,
         attempt_verification: Vec<serde_json::Value>,
         dispatch_failures: Vec<serde_json::Value>| {
            let verify = json!({
                "id": id,
                "pre_target": semantic_target_verification_json(Some(semantic_target)),
                "attempts": attempt_verification,
                "click_errors": click_errors,
                "dispatch_failures": dispatch_failures,
                "budget_exhausted": true,
                "execution_budget_ms": CLICK_ELEMENT_EXECUTION_BUDGET.as_millis() as u64,
                "execution_elapsed_ms": execution_started_at.elapsed().as_millis() as u64,
            });
            ToolExecutionResult::failure(format!(
            "ERROR_CLASS=NoEffectAfterAction Click element '{}' exhausted {}ms execution budget. verify={}",
            id,
            CLICK_ELEMENT_EXECUTION_BUDGET.as_millis(),
            verify
        ))
        };
    let dispatch_timeout_failure =
        |click_errors: Vec<String>,
         attempt_verification: Vec<serde_json::Value>,
         dispatch_failures: Vec<serde_json::Value>| {
            let verify = json!({
                "id": id,
                "pre_target": semantic_target_verification_json(Some(semantic_target)),
                "attempts": attempt_verification,
                "click_errors": click_errors,
                "dispatch_failures": dispatch_failures,
                "execution_elapsed_ms": execution_started_at.elapsed().as_millis() as u64,
            });
            ToolExecutionResult::failure(format!(
                "ERROR_CLASS=NoEffectAfterAction Failed to click element '{}'. verify={}",
                id, verify
            ))
        };

    if selector_click_attempted_first {
        if let Some(selector) = click_selector_fallback_locator(semantic_target) {
            let Some(dispatch_timeout) = click_element_attempt_timeout(execution_deadline) else {
                return budget_exhausted_failure(
                    click_errors,
                    attempt_verification,
                    dispatch_failures,
                );
            };
            emit_browser_click_trace(
                "selector_grounded_dispatch_start",
                format!("id={id} selector={selector}"),
            );
            let dispatch_started_at_ms = unix_timestamp_ms_now();
            let dispatch_started_at = Instant::now();
            match run_browser_dispatch_with_timeout_for(
                dispatch_timeout,
                exec.browser.click_selector_grounded(&selector),
            )
            .await
            {
                Ok(()) => {
                    emit_browser_click_trace(
                        "selector_grounded_dispatch_done",
                        format!(
                            "id={id} selector={selector} elapsed_ms={}",
                            dispatch_started_at.elapsed().as_millis()
                        ),
                    );
                    let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                    let (met, mut verify) = verify_click_dispatch(
                        exec,
                        pre_tree_xml,
                        semantic_target,
                        pre_url,
                        "selector_grounded",
                        None,
                        pre_focused_control,
                        dispatch_started_at_ms,
                        dispatch_elapsed_ms,
                        execution_started_at,
                        execution_deadline,
                    )
                    .await;
                    verify["attempt_index"] = json!((attempt_verification.len() + 1) as u64);
                    verify["selector"] = json!(selector);
                    if met {
                        annotate_prior_click_attempts(
                            &mut verify,
                            &attempt_verification,
                            &dispatch_failures,
                        );
                        return ToolExecutionResult::success(format!(
                            "Clicked element '{}' via selector path '{}'. verify={}",
                            id, selector, verify
                        ));
                    }
                    if verify_marks_browser_session_unstable(&verify) {
                        attempt_verification.push(verify);
                        return browser_session_unstable_failure(
                            id,
                            semantic_target,
                            click_errors,
                            attempt_verification,
                            dispatch_failures,
                            execution_started_at,
                        );
                    }
                    attempt_verification.push(verify);
                }
                Err(error) => {
                    emit_browser_click_trace(
                        "selector_grounded_dispatch_error",
                        format!(
                            "id={id} selector={selector} elapsed_ms={} error={error}",
                            dispatch_started_at.elapsed().as_millis()
                        ),
                    );
                    let browser_session_unstable = browser_session_unstable_error(&error);
                    let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                    click_errors.push(format!("selector_path={error}"));
                    let mut failure = dispatch_failure_verify(
                        "selector_grounded",
                        dispatch_elapsed_ms,
                        &error,
                        None,
                    );
                    failure["selector"] = json!(selector);
                    if browser_session_unstable {
                        failure["browser_session_unstable"] = json!(true);
                    }
                    dispatch_failures.push(failure);
                    if browser_session_unstable {
                        return browser_session_unstable_failure(
                            id,
                            semantic_target,
                            click_errors,
                            attempt_verification,
                            dispatch_failures,
                            execution_started_at,
                        );
                    }
                    if dispatch_error_is_timeout(&error) {
                        return dispatch_timeout_failure(
                            click_errors,
                            attempt_verification,
                            dispatch_failures,
                        );
                    }
                }
            }
        }
    }

    if let Some((x, y)) = safe_inset_point {
        let dispatch_point = geometry_dispatch_point(semantic_target, (x, y));
        let Some(dispatch_timeout) = click_element_attempt_timeout(execution_deadline) else {
            return budget_exhausted_failure(click_errors, attempt_verification, dispatch_failures);
        };
        let dispatch_started_at_ms = unix_timestamp_ms_now();
        let dispatch_started_at = Instant::now();
        match run_browser_dispatch_with_timeout_for(
            dispatch_timeout,
            exec.browser
                .synthetic_click(dispatch_point.0, dispatch_point.1),
        )
        .await
        {
            Ok(()) => {
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                let (met, mut verify) = verify_click_dispatch(
                    exec,
                    pre_tree_xml,
                    semantic_target,
                    pre_url,
                    "geometry_safe_inset",
                    Some(dispatch_point),
                    pre_focused_control,
                    dispatch_started_at_ms,
                    dispatch_elapsed_ms,
                    execution_started_at,
                    execution_deadline,
                )
                .await;
                verify["attempt_index"] = json!((attempt_verification.len() + 1) as u64);
                if met {
                    annotate_prior_click_attempts(
                        &mut verify,
                        &attempt_verification,
                        &dispatch_failures,
                    );
                    return ToolExecutionResult::success(format!(
                        "Clicked element '{}' via safe inset geometry. verify={}",
                        id, verify
                    ));
                }
                if verify_marks_browser_session_unstable(&verify) {
                    attempt_verification.push(verify);
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                attempt_verification.push(verify);
            }
            Err(error) => {
                let browser_session_unstable = browser_session_unstable_error(&error);
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                click_errors.push(format!("geometry_safe_inset=({:.2},{:.2})={}", x, y, error));
                let mut failure = dispatch_failure_verify(
                    "geometry_safe_inset",
                    dispatch_elapsed_ms,
                    &error,
                    Some(dispatch_point),
                );
                if browser_session_unstable {
                    failure["browser_session_unstable"] = json!(true);
                }
                dispatch_failures.push(failure);
                if browser_session_unstable {
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                if dispatch_error_is_timeout(&error) {
                    return dispatch_timeout_failure(
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                    );
                }
            }
        }
    }

    if let Some(backend_id) = semantic_target.backend_dom_node_id.as_deref() {
        let Some(dispatch_timeout) = click_element_attempt_timeout(execution_deadline) else {
            return budget_exhausted_failure(click_errors, attempt_verification, dispatch_failures);
        };
        let dispatch_started_at_ms = unix_timestamp_ms_now();
        let dispatch_started_at = Instant::now();
        match run_browser_dispatch_with_timeout_for(
            dispatch_timeout,
            exec.browser
                .click_backend_dom_node_in_target(backend_id, semantic_target.target_id.as_deref()),
        )
        .await
        {
            Ok(()) => {
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                let (met, mut verify) = verify_click_dispatch(
                    exec,
                    pre_tree_xml,
                    semantic_target,
                    pre_url,
                    "backend_dom_node_id",
                    None,
                    pre_focused_control,
                    dispatch_started_at_ms,
                    dispatch_elapsed_ms,
                    execution_started_at,
                    execution_deadline,
                )
                .await;
                verify["attempt_index"] = json!((attempt_verification.len() + 1) as u64);
                if met {
                    annotate_prior_click_attempts(
                        &mut verify,
                        &attempt_verification,
                        &dispatch_failures,
                    );
                    return ToolExecutionResult::success(format!(
                        "Clicked element '{}'. verify={}",
                        id, verify
                    ));
                }
                if verify_marks_browser_session_unstable(&verify) {
                    attempt_verification.push(verify);
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                attempt_verification.push(verify);
            }
            Err(error) => {
                let browser_session_unstable = browser_session_unstable_error(&error);
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                click_errors.push(format!("backend_dom_node_id={}", error));
                let mut failure = dispatch_failure_verify(
                    "backend_dom_node_id",
                    dispatch_elapsed_ms,
                    &error,
                    None,
                );
                if browser_session_unstable {
                    failure["browser_session_unstable"] = json!(true);
                }
                dispatch_failures.push(failure);
                if browser_session_unstable {
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                if dispatch_error_is_timeout(&error) {
                    return dispatch_timeout_failure(
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                    );
                }
            }
        }
    }

    if let Some(cdp_id) = semantic_target.cdp_node_id.as_deref() {
        let Some(dispatch_timeout) = click_element_attempt_timeout(execution_deadline) else {
            return budget_exhausted_failure(click_errors, attempt_verification, dispatch_failures);
        };
        let dispatch_started_at_ms = unix_timestamp_ms_now();
        let dispatch_started_at = Instant::now();
        match run_browser_dispatch_with_timeout_for(
            dispatch_timeout,
            exec.browser
                .click_ax_node_in_target(cdp_id, semantic_target.target_id.as_deref()),
        )
        .await
        {
            Ok(()) => {
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                let (met, mut verify) = verify_click_dispatch(
                    exec,
                    pre_tree_xml,
                    semantic_target,
                    pre_url,
                    "cdp_node_id",
                    None,
                    pre_focused_control,
                    dispatch_started_at_ms,
                    dispatch_elapsed_ms,
                    execution_started_at,
                    execution_deadline,
                )
                .await;
                verify["attempt_index"] = json!((attempt_verification.len() + 1) as u64);
                if met {
                    annotate_prior_click_attempts(
                        &mut verify,
                        &attempt_verification,
                        &dispatch_failures,
                    );
                    return ToolExecutionResult::success(format!(
                        "Clicked element '{}'. verify={}",
                        id, verify
                    ));
                }
                if verify_marks_browser_session_unstable(&verify) {
                    attempt_verification.push(verify);
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                attempt_verification.push(verify);
            }
            Err(error) => {
                let browser_session_unstable = browser_session_unstable_error(&error);
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                click_errors.push(format!("cdp_node_id={}", error));
                let mut failure =
                    dispatch_failure_verify("cdp_node_id", dispatch_elapsed_ms, &error, None);
                if browser_session_unstable {
                    failure["browser_session_unstable"] = json!(true);
                }
                dispatch_failures.push(failure);
                if browser_session_unstable {
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                if dispatch_error_is_timeout(&error) {
                    return dispatch_timeout_failure(
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                    );
                }
            }
        }
    }

    if let Some((x, y)) = semantic_target.center_point {
        let dispatch_point = geometry_dispatch_point(semantic_target, (x, y));
        let Some(dispatch_timeout) = click_element_attempt_timeout(execution_deadline) else {
            return budget_exhausted_failure(click_errors, attempt_verification, dispatch_failures);
        };
        let dispatch_started_at_ms = unix_timestamp_ms_now();
        let dispatch_started_at = Instant::now();
        match run_browser_dispatch_with_timeout_for(
            dispatch_timeout,
            exec.browser
                .synthetic_click(dispatch_point.0, dispatch_point.1),
        )
        .await
        {
            Ok(()) => {
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                let (met, mut verify) = verify_click_dispatch(
                    exec,
                    pre_tree_xml,
                    semantic_target,
                    pre_url,
                    "geometry_center",
                    Some(dispatch_point),
                    pre_focused_control,
                    dispatch_started_at_ms,
                    dispatch_elapsed_ms,
                    execution_started_at,
                    execution_deadline,
                )
                .await;
                verify["attempt_index"] = json!((attempt_verification.len() + 1) as u64);
                if met {
                    annotate_prior_click_attempts(
                        &mut verify,
                        &attempt_verification,
                        &dispatch_failures,
                    );
                    return ToolExecutionResult::success(format!(
                        "Clicked element '{}' via geometry fallback. verify={}",
                        id, verify
                    ));
                }
                if verify_marks_browser_session_unstable(&verify) {
                    attempt_verification.push(verify);
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                attempt_verification.push(verify);
            }
            Err(error) => {
                let browser_session_unstable = browser_session_unstable_error(&error);
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                click_errors.push(format!("geometry_center=({:.2},{:.2})={}", x, y, error));
                let mut failure = dispatch_failure_verify(
                    "geometry_center",
                    dispatch_elapsed_ms,
                    &error,
                    Some(dispatch_point),
                );
                if browser_session_unstable {
                    failure["browser_session_unstable"] = json!(true);
                }
                dispatch_failures.push(failure);
                if browser_session_unstable {
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                if dispatch_error_is_timeout(&error) {
                    return dispatch_timeout_failure(
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                    );
                }
            }
        }
    }

    let verify = json!({
        "id": id,
        "pre_target": semantic_target_verification_json(Some(semantic_target)),
        "attempts": attempt_verification,
        "click_errors": click_errors,
        "dispatch_failures": dispatch_failures,
    });
    ToolExecutionResult::failure(format!(
        "ERROR_CLASS=NoEffectAfterAction Failed to click element '{}'. verify={}",
        id, verify
    ))
}

#[cfg(test)]
#[path = "attempt/tests.rs"]
mod tests;

pub(super) async fn handle_browser_click_element(
    exec: &ToolExecutor,
    id: &str,
) -> ToolExecutionResult {
    if let Some(blocked) = ensure_browser_focus_guard(exec) {
        return blocked;
    }

    let pre_url = exec.browser.known_active_url().await;
    let execution_started_at = Instant::now();
    let execution_deadline = execution_started_at + CLICK_ELEMENT_EXECUTION_BUDGET;
    emit_browser_click_trace("start", format!("id={id}"));

    let prompt_tree_started_at = Instant::now();
    let (prompt_tree, prompt_observation_source) =
        match capture_execution_prompt_browser_tree(exec).await {
            Some((tree, source)) => (Some(tree), source),
            None => (None, "prompt_observation_unavailable"),
        };
    let prompt_observation_elapsed_ms = prompt_tree_started_at.elapsed().as_millis() as u64;
    emit_browser_click_trace(
        "prompt_tree",
        format!("source={prompt_observation_source} elapsed_ms={prompt_observation_elapsed_ms}"),
    );

    let recent_tree = exec
        .browser
        .recent_accessibility_snapshot(RECENT_BROWSER_CLICK_SNAPSHOT_MAX_AGE)
        .await
        .map(|(_, tree)| apply_browser_auto_lens_with_som(&tree));
    let mut current_tree_source = "recent_accessibility_snapshot";
    let mut current_tree_elapsed_ms = 0u64;
    let mut prompt_observation_failure: Option<ToolExecutionResult> = None;
    let mut current_tree_failure: Option<ToolExecutionResult> = None;

    let mut transformed = recent_tree;
    let mut current_tree_error: Option<String> = None;
    let mut current_target = transformed
        .as_ref()
        .and_then(|tree| find_semantic_target_by_id(tree, id));
    let mut actionable_current_target = current_target
        .as_ref()
        .filter(|target| semantic_target_is_actionable(target));
    let mut current_tree_attempted_in_initial_dispatch = false;

    if let Some((semantic_target, resolved_from)) =
        resolve_semantic_target_from_current_or_prompt_tree(
            transformed.as_ref(),
            prompt_tree.as_ref(),
            id,
        )
        .filter(|(target, _)| semantic_target_is_actionable(target))
    {
        let mut semantic_target = semantic_target;
        let mut resolved_from = resolved_from;
        emit_browser_click_trace(
            "target_resolved",
            format!(
                "source={resolved_from} selector={:?} dom_id={:?} tag={:?} dom_clickable={} backend_id={:?} cdp_id={:?} center_point={:?}",
                semantic_target.selector,
                semantic_target.dom_id,
                semantic_target.tag_name,
                semantic_target.dom_clickable,
                semantic_target.backend_dom_node_id,
                semantic_target.cdp_node_id,
                semantic_target.center_point,
            ),
        );
        if target_prefers_live_tree_refresh_before_dispatch(&semantic_target, resolved_from) {
            if let Some(current_tree_refresh_timeout) =
                remaining_click_element_budget(execution_deadline)
                    .map(|remaining| remaining.min(CLICK_ELEMENT_LIVE_TREE_REFRESH_TIMEOUT))
            {
                let refreshed_tree =
                    refresh_current_click_tree(exec, id, current_tree_refresh_timeout).await;
                current_tree_source = refreshed_tree.source;
                current_tree_elapsed_ms = refreshed_tree.elapsed_ms;
                current_tree_error = refreshed_tree.error;
                transformed = refreshed_tree.transformed;
                current_target = transformed
                    .as_ref()
                    .and_then(|tree| find_semantic_target_by_id(tree, id));
                actionable_current_target = current_target
                    .as_ref()
                    .filter(|target| semantic_target_is_actionable(target));
                if let Some(current_semantic_target) = actionable_current_target.cloned() {
                    semantic_target = current_semantic_target;
                    resolved_from = current_tree_source;
                    current_tree_attempted_in_initial_dispatch = true;
                    emit_browser_click_trace(
                        "target_rebound_from_live_tree",
                        format!(
                            "source={resolved_from} selector={:?} dom_id={:?} tag={:?}",
                            semantic_target.selector,
                            semantic_target.dom_id,
                            semantic_target.tag_name,
                        ),
                    );
                }
            }
        }
        let (pre_tree, target_resolution_source, pre_focused_control) =
            if resolved_from == "prompt_observation_tree" {
                let tree = prompt_tree
                    .as_ref()
                    .expect("prompt tree must exist when prompt target resolves");
                (
                    tree,
                    "prompt_observation_tree",
                    prompt_tree
                        .as_ref()
                        .and_then(|candidate| find_focused_semantic_target(candidate)),
                )
            } else {
                let tree = transformed
                    .as_ref()
                    .expect("recent current tree must exist when current target resolves");
                (
                    tree,
                    current_tree_source,
                    transformed
                        .as_ref()
                        .and_then(|candidate| find_focused_semantic_target(candidate)),
                )
            };
        let pre_tree_xml = render_browser_tree_xml(pre_tree);
        let initial_result = attempt_click_element_with_target(
            exec,
            id,
            &semantic_target,
            target_resolution_source,
            &pre_tree_xml,
            pre_url.as_deref(),
            pre_focused_control.as_ref(),
            execution_started_at,
            execution_deadline,
        )
        .await;
        let initial_result = annotate_click_result_verify(
            initial_result,
            &[
                ("target_resolution_source", json!(target_resolution_source)),
                (
                    "prompt_observation_source",
                    json!(prompt_observation_source),
                ),
                ("current_tree_elapsed_ms", json!(current_tree_elapsed_ms)),
                (
                    "prompt_observation_elapsed_ms",
                    json!(prompt_observation_elapsed_ms),
                ),
            ],
        );
        if initial_result.success {
            return initial_result;
        }
        if click_result_marks_browser_session_unstable(&initial_result) {
            return initial_result;
        }
        if click_result_has_dispatch_timeout(&initial_result) {
            if current_tree_attempted_in_initial_dispatch {
                emit_browser_click_trace(
                    "skip_current_tree_refresh",
                    format!("id={id} reason=dispatch_timeout_current_tree_already_attempted"),
                );
                return initial_result;
            }
            emit_browser_click_trace(
                "defer_dispatch_timeout_to_current_tree_retry",
                format!("id={id} reason=dispatch_timeout"),
            );
        }
        if resolved_from == "prompt_observation_tree" {
            prompt_observation_failure = Some(initial_result);
        } else {
            current_tree_failure = Some(initial_result);
        }
    }

    if current_tree_attempted_in_initial_dispatch {
        if let Some(current_tree_failure) = current_tree_failure {
            return current_tree_failure;
        }
    }

    if remaining_click_element_budget(execution_deadline).is_none() {
        return current_tree_failure.or(prompt_observation_failure).unwrap_or_else(|| {
            let verify = json!({
                "id": id,
                "budget_exhausted": true,
                "execution_budget_ms": CLICK_ELEMENT_EXECUTION_BUDGET.as_millis() as u64,
                "execution_elapsed_ms": execution_started_at.elapsed().as_millis() as u64,
                "prompt_observation_source": prompt_observation_source,
                "current_tree_source": current_tree_source,
            });
            ToolExecutionResult::failure(format!(
                "ERROR_CLASS=NoEffectAfterAction Click element '{}' exhausted {}ms execution budget before live tree refresh. verify={}",
                id,
                CLICK_ELEMENT_EXECUTION_BUDGET.as_millis(),
                verify
            ))
        });
    }

    let Some(current_tree_refresh_timeout) = remaining_click_element_budget(execution_deadline)
        .map(|remaining| remaining.min(CLICK_ELEMENT_LIVE_TREE_REFRESH_TIMEOUT))
    else {
        return current_tree_failure.or(prompt_observation_failure).unwrap_or_else(|| {
            let verify = json!({
                "id": id,
                "budget_exhausted": true,
                "execution_budget_ms": CLICK_ELEMENT_EXECUTION_BUDGET.as_millis() as u64,
                "execution_elapsed_ms": execution_started_at.elapsed().as_millis() as u64,
                "prompt_observation_source": prompt_observation_source,
                "current_tree_source": current_tree_source,
            });
            ToolExecutionResult::failure(format!(
                "ERROR_CLASS=NoEffectAfterAction Click element '{}' exhausted {}ms execution budget before current tree refresh. verify={}",
                id,
                CLICK_ELEMENT_EXECUTION_BUDGET.as_millis(),
                verify
            ))
        });
    };

    let refreshed_tree = refresh_current_click_tree(exec, id, current_tree_refresh_timeout).await;
    current_tree_source = refreshed_tree.source;
    current_tree_elapsed_ms = refreshed_tree.elapsed_ms;
    current_tree_error = refreshed_tree.error;
    transformed = refreshed_tree.transformed;
    current_target = transformed
        .as_ref()
        .and_then(|tree| find_semantic_target_by_id(tree, id));
    actionable_current_target = current_target
        .as_ref()
        .filter(|target| semantic_target_is_actionable(target));

    if !current_tree_attempted_in_initial_dispatch {
        if let Some(semantic_target) = actionable_current_target {
            let pre_tree_xml = render_browser_tree_xml(
                transformed
                    .as_ref()
                    .expect("current tree must exist when current target resolves"),
            );
            let pre_focused_control = transformed
                .as_ref()
                .and_then(|tree| find_focused_semantic_target(tree));
            let current_result = attempt_click_element_with_target(
                exec,
                id,
                semantic_target,
                current_tree_source,
                &pre_tree_xml,
                pre_url.as_deref(),
                pre_focused_control.as_ref(),
                execution_started_at,
                execution_deadline,
            )
            .await;
            let current_result = annotate_click_result_verify(
                current_result,
                &[
                    ("target_resolution_source", json!(current_tree_source)),
                    (
                        "prompt_observation_source",
                        json!(prompt_observation_source),
                    ),
                    ("current_tree_elapsed_ms", json!(current_tree_elapsed_ms)),
                    (
                        "prompt_observation_elapsed_ms",
                        json!(prompt_observation_elapsed_ms),
                    ),
                ],
            );
            if current_result.success {
                return current_result;
            }
            current_tree_failure = Some(current_result);
        }
    }

    if let Some(current_tree_failure) = current_tree_failure {
        return current_tree_failure;
    }

    match current_tree_error {
        Some(error) => prompt_observation_failure.unwrap_or_else(|| {
            ToolExecutionResult::failure(format!(
                "Failed to fetch browser accessibility tree: {}",
                error
            ))
        }),
        None => match current_target {
            Some(_) => prompt_observation_failure.unwrap_or_else(|| {
                ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=TargetNotFound Element '{}' is present but does not expose actionable browser node identifiers or clickable geometry.",
                    id
                ))
            }),
            None => prompt_observation_failure.unwrap_or_else(|| {
                ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=TargetNotFound Element '{}' not found in current browser view. Run `browser__inspect` again and retry with a fresh ID.",
                    id
                ))
            }),
        },
    }
}
