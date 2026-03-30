fn parse_attr_bool(raw: &str) -> Option<bool> {
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn node_attr_flag(node: &AccessibilityNode, key: &str) -> Option<bool> {
    let value = node
        .attributes
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())?;

    if value.trim().is_empty() {
        return Some(true);
    }

    parse_attr_bool(value).or(Some(true))
}

fn node_is_focused(node: &AccessibilityNode) -> bool {
    matches!(node_attr_flag(node, "focused"), Some(true))
}

fn node_is_editable(node: &AccessibilityNode) -> bool {
    let disabled = matches!(node_attr_flag(node, "disabled"), Some(true))
        || matches!(node_attr_flag(node, "aria_disabled"), Some(true));
    if disabled {
        return false;
    }

    let readonly = matches!(node_attr_flag(node, "readonly"), Some(true))
        || matches!(node_attr_flag(node, "aria_readonly"), Some(true))
        || matches!(node_attr_flag(node, "read_only"), Some(true));
    if readonly {
        return false;
    }

    if matches!(node_attr_flag(node, "editable"), Some(true))
        || matches!(node_attr_flag(node, "contenteditable"), Some(true))
    {
        return true;
    }

    matches!(
        node.role.trim().to_ascii_lowercase().as_str(),
        "textbox"
            | "text box"
            | "searchbox"
            | "search box"
            | "text"
            | "edit"
            | "entry"
            | "textarea"
            | "input"
    )
}

fn normalized_attr_lookup_key(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn attr_lookup_key_matches(candidate: &str, key: &str) -> bool {
    candidate.eq_ignore_ascii_case(key)
        || normalized_attr_lookup_key(candidate) == normalized_attr_lookup_key(key)
}

fn node_attr_value<'a>(node: &'a AccessibilityNode, key: &str) -> Option<&'a str> {
    node.attributes
        .iter()
        .find(|(k, _)| attr_lookup_key_matches(k, key))
        .map(|(_, v)| v.as_str())
        .filter(|value| !value.trim().is_empty())
}

fn node_attr_i32(node: &AccessibilityNode, key: &str) -> Option<i32> {
    node_attr_value(node, key)?.trim().parse().ok()
}

fn node_attr_f64(node: &AccessibilityNode, key: &str) -> Option<f64> {
    node_attr_value(node, key)?.trim().parse().ok()
}

fn node_attr_u64(node: &AccessibilityNode, key: &str) -> Option<u64> {
    node_attr_value(node, key)?.trim().parse().ok()
}

fn semantic_target_center_point(node: &AccessibilityNode) -> Option<(f64, f64)> {
    let precise_x =
        node_attr_f64(node, "center_x_precise").or_else(|| node_attr_f64(node, "center_x"));
    let precise_y =
        node_attr_f64(node, "center_y_precise").or_else(|| node_attr_f64(node, "center_y"));
    match (precise_x, precise_y) {
        (Some(x), Some(y)) if x.is_finite() && y.is_finite() => Some((x, y)),
        _ => rect_center(node.rect),
    }
}

fn normalize_semantic_lookup_key(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn semantic_lookup_token_matches(token: &str, raw_query: &str, normalized_query: &str) -> bool {
    let token = token.trim();
    if token.is_empty() {
        return false;
    }

    token.eq_ignore_ascii_case(raw_query)
        || (!normalized_query.is_empty()
            && normalize_semantic_lookup_key(token) == normalized_query)
}

fn semantic_lookup_alias_candidates(raw_query: &str) -> Vec<String> {
    let trimmed = raw_query.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut aliases = vec![trimmed.to_string()];
    if let Some((_, remainder)) = trimmed.split_once('_') {
        if !remainder.trim().is_empty() && !aliases.iter().any(|alias| alias == remainder.trim()) {
            aliases.push(remainder.trim().to_string());
        }
    }
    if let Some((_, suffix)) = trimmed.rsplit_once('_') {
        if !suffix.trim().is_empty() && !aliases.iter().any(|alias| alias == suffix.trim()) {
            aliases.push(suffix.trim().to_string());
        }
    }

    aliases
}

fn semantic_target_from_node(node: &AccessibilityNode) -> BrowserSemanticTarget {
    let mut identity_attributes = HashMap::new();
    for key in ["name", "id", "aria-label", "type"] {
        if let Some(value) = node_attr_value(node, key) {
            identity_attributes.insert(key.to_string(), value.to_string());
        }
    }

    BrowserSemanticTarget {
        semantic_id: Some(node.id.clone()).filter(|id| !id.trim().is_empty()),
        dom_id: node_attr_value(node, "dom_id")
            .or_else(|| node_attr_value(node, "id"))
            .map(|value| value.to_string()),
        selector: node_attr_value(node, "selector").map(|value| value.to_string()),
        x_path: node_attr_value(node, "x_path").map(|value| value.to_string()),
        tag_name: node_attr_value(node, "tag_name").map(|value| value.to_string()),
        dom_clickable: matches!(node_attr_flag(node, "dom_clickable"), Some(true)),
        value: node.value.clone(),
        identity_attributes,
        element_hash: node_attr_u64(node, "element_hash"),
        stable_hash: node_attr_u64(node, "stable_hash"),
        parent_branch_hash: node_attr_u64(node, "parent_branch_hash"),
        ax_name: node_attr_value(node, "ax_name")
            .map(|value| value.to_string())
            .or_else(|| node.name.clone()),
        cdp_node_id: node.attributes.get("cdp_node_id").cloned(),
        backend_dom_node_id: node.attributes.get("backend_dom_node_id").cloned(),
        target_id: node.attributes.get("target_id").cloned(),
        frame_id: node.attributes.get("frame_id").cloned(),
        rect_bounds: Some((node.rect.x, node.rect.y, node.rect.width, node.rect.height)),
        center_point: semantic_target_center_point(node),
        focused: node_is_focused(node),
        editable: node_is_editable(node),
        checked: node_attr_flag(node, "checked"),
        selected: node_attr_flag(node, "selected"),
        scroll_top: node_attr_i32(node, "scroll_top"),
        scroll_height: node_attr_i32(node, "scroll_height"),
        client_height: node_attr_i32(node, "client_height"),
        can_scroll_up: node_attr_flag(node, "can_scroll_up"),
        can_scroll_down: node_attr_flag(node, "can_scroll_down"),
    }
}

fn point_within_rect(bounds: (i32, i32, i32, i32), x: f64, y: f64) -> bool {
    let (left, top, width, height) = bounds;
    if width <= 0 || height <= 0 || !x.is_finite() || !y.is_finite() {
        return false;
    }

    let right = left.saturating_add(width);
    let bottom = top.saturating_add(height);
    x >= left as f64 && x <= right as f64 && y >= top as f64 && y <= bottom as f64
}

fn semantic_target_locator_strength(target: &BrowserSemanticTarget) -> u8 {
    let mut strength = 0u8;
    if target
        .backend_dom_node_id
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        strength = strength.saturating_add(4);
    }
    if target
        .cdp_node_id
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        strength = strength.saturating_add(3);
    }
    if target
        .dom_id
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        strength = strength.saturating_add(2);
    }
    if target.stable_hash.is_some() {
        strength = strength.saturating_add(2);
    }
    if target
        .x_path
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        strength = strength.saturating_add(1);
    }
    if target
        .selector
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        strength = strength.saturating_add(1);
    }
    strength
}

fn find_nearest_semantic_target_by_point_recursive(
    node: &AccessibilityNode,
    x: f64,
    y: f64,
    best: &mut Option<(bool, bool, f64, u8, i64, BrowserSemanticTarget)>,
) {
    let target = semantic_target_from_node(node);
    if let Some((center_x, center_y)) = target.center_point {
        let contains_point = target
            .rect_bounds
            .is_some_and(|bounds| point_within_rect(bounds, x, y));
        let actionable = semantic_target_is_actionable(&target);
        let distance_sq = (center_x - x).powi(2) + (center_y - y).powi(2);
        let locator_strength = semantic_target_locator_strength(&target);
        let rect_area = target
            .rect_bounds
            .map(|(_, _, width, height)| i64::from(width.max(0)) * i64::from(height.max(0)))
            .unwrap_or(i64::MAX);
        let candidate = (
            contains_point,
            actionable,
            distance_sq,
            locator_strength,
            rect_area,
            target,
        );

        let replace = match best.as_ref() {
            None => true,
            Some((best_contains, best_actionable, best_distance, best_locator, best_area, _)) => {
                (candidate.0, candidate.1) > (*best_contains, *best_actionable)
                    || ((candidate.0, candidate.1) == (*best_contains, *best_actionable)
                        && (candidate.2 < *best_distance
                            || (candidate.2 == *best_distance
                                && (candidate.3 > *best_locator
                                    || (candidate.3 == *best_locator
                                        && candidate.4 < *best_area)))))
            }
        };

        if replace {
            *best = Some(candidate);
        }
    }

    for child in &node.children {
        find_nearest_semantic_target_by_point_recursive(child, x, y, best);
    }
}

fn find_semantic_target_by_semantic_id(
    node: &AccessibilityNode,
    target_id: &str,
) -> Option<BrowserSemanticTarget> {
    if node.id == target_id {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_semantic_id(child, target_id) {
            return Some(found);
        }
    }

    None
}

pub(super) fn find_semantic_target_by_som_id(
    node: &AccessibilityNode,
    target_som_id: u32,
) -> Option<BrowserSemanticTarget> {
    if node.som_id == Some(target_som_id) {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_som_id(child, target_som_id) {
            return Some(found);
        }
    }

    None
}

fn find_semantic_target_by_dom_id_or_attr_id(
    node: &AccessibilityNode,
    raw_query: &str,
    normalized_query: &str,
) -> Option<BrowserSemanticTarget> {
    if let Some(dom_id) = node_attr_value(node, "dom_id") {
        if semantic_lookup_token_matches(dom_id, raw_query, normalized_query) {
            return Some(semantic_target_from_node(node));
        }
    }

    if let Some(attr_id) = node_attr_value(node, "id") {
        if semantic_lookup_token_matches(attr_id, raw_query, normalized_query) {
            return Some(semantic_target_from_node(node));
        }
    }

    for child in &node.children {
        if let Some(found) =
            find_semantic_target_by_dom_id_or_attr_id(child, raw_query, normalized_query)
        {
            return Some(found);
        }
    }

    None
}

fn find_semantic_target_by_semantic_alias(
    node: &AccessibilityNode,
    raw_query: &str,
    normalized_query: &str,
) -> Option<BrowserSemanticTarget> {
    if let Some(aliases) = node.attributes.get("semantic_aliases") {
        if aliases
            .split_whitespace()
            .any(|alias| semantic_lookup_token_matches(alias, raw_query, normalized_query))
        {
            return Some(semantic_target_from_node(node));
        }
    }

    for child in &node.children {
        if let Some(found) =
            find_semantic_target_by_semantic_alias(child, raw_query, normalized_query)
        {
            return Some(found);
        }
    }

    None
}

fn collect_semantic_targets_by_name_or_data_index(
    node: &AccessibilityNode,
    raw_query: &str,
    normalized_query: &str,
    matches: &mut Vec<BrowserSemanticTarget>,
) {
    let name_match = node
        .name
        .as_deref()
        .is_some_and(|name| semantic_lookup_token_matches(name, raw_query, normalized_query));
    let data_index_match = node_attr_value(node, "data_index")
        .is_some_and(|value| semantic_lookup_token_matches(value, raw_query, normalized_query));
    if name_match || data_index_match {
        matches.push(semantic_target_from_node(node));
    }

    for child in &node.children {
        collect_semantic_targets_by_name_or_data_index(child, raw_query, normalized_query, matches);
    }
}

fn find_unique_semantic_target_by_name_or_data_index(
    node: &AccessibilityNode,
    raw_query: &str,
) -> Option<BrowserSemanticTarget> {
    for alias in semantic_lookup_alias_candidates(raw_query) {
        let normalized_alias = normalize_semantic_lookup_key(&alias);
        let mut matches = Vec::new();
        collect_semantic_targets_by_name_or_data_index(
            node,
            &alias,
            &normalized_alias,
            &mut matches,
        );
        if matches.len() == 1 {
            return matches.into_iter().next();
        }
    }

    None
}

fn find_focused_semantic_target(node: &AccessibilityNode) -> Option<BrowserSemanticTarget> {
    for child in &node.children {
        if let Some(found) = find_focused_semantic_target(child) {
            return Some(found);
        }
    }

    node_is_focused(node).then(|| semantic_target_from_node(node))
}

fn semantic_lookup_candidate_is_better(
    candidate: &BrowserSemanticTarget,
    candidate_alias_index: usize,
    best: Option<(&BrowserSemanticTarget, usize)>,
) -> bool {
    let candidate_rank = (
        semantic_target_is_actionable(candidate),
        target_has_grounded_dom_click_locator(candidate),
        semantic_target_locator_strength(candidate),
    );

    match best {
        None => true,
        Some((best_target, best_alias_index)) => {
            let best_rank = (
                semantic_target_is_actionable(best_target),
                target_has_grounded_dom_click_locator(best_target),
                semantic_target_locator_strength(best_target),
            );
            candidate_rank > best_rank
                || (candidate_rank == best_rank && candidate_alias_index < best_alias_index)
        }
    }
}

pub(super) fn find_semantic_target_by_id(
    node: &AccessibilityNode,
    target_id: &str,
) -> Option<BrowserSemanticTarget> {
    let target_id = target_id.trim();
    if target_id.is_empty() {
        return None;
    }

    if let Some(target) = find_semantic_target_by_semantic_id(node, target_id) {
        return Some(target);
    }

    if let Ok(target_som_id) = target_id.parse::<u32>() {
        if let Some(target) = find_semantic_target_by_som_id(node, target_som_id) {
            return Some(target);
        }
    }

    let mut best_match: Option<(BrowserSemanticTarget, usize)> = None;
    for (alias_index, alias) in semantic_lookup_alias_candidates(target_id)
        .into_iter()
        .enumerate()
    {
        let normalized_alias = normalize_semantic_lookup_key(&alias);
        for candidate in [
            find_semantic_target_by_dom_id_or_attr_id(node, &alias, &normalized_alias),
            find_semantic_target_by_semantic_alias(node, &alias, &normalized_alias),
        ]
        .into_iter()
        .flatten()
        {
            if semantic_lookup_candidate_is_better(
                &candidate,
                alias_index,
                best_match.as_ref().map(|(target, index)| (target, *index)),
            ) {
                best_match = Some((candidate, alias_index));
            }
        }
    }
    if let Some((target, _)) = best_match {
        return Some(target);
    }

    find_unique_semantic_target_by_name_or_data_index(node, target_id)
}

pub(super) fn resolve_semantic_target_from_current_or_prompt_tree(
    current_tree: Option<&AccessibilityNode>,
    prompt_tree: Option<&AccessibilityNode>,
    target_id: &str,
) -> Option<(BrowserSemanticTarget, &'static str)> {
    let current_target = current_tree.and_then(|tree| find_semantic_target_by_id(tree, target_id));
    let prompt_target = prompt_tree.and_then(|tree| find_semantic_target_by_id(tree, target_id));

    match (current_target, prompt_target) {
        (Some(current_target), Some(prompt_target)) => {
            let current_actionable = semantic_target_is_actionable(&current_target);
            let prompt_actionable = semantic_target_is_actionable(&prompt_target);
            if prompt_actionable && !current_actionable {
                return Some((prompt_target, "prompt_observation_tree"));
            }
            if current_actionable && !prompt_actionable {
                return Some((current_target, "current_accessibility_tree"));
            }

            let prompt_enriches_current =
                prompt_target_enriches_current(&current_target, &prompt_target);
            let merged_target = merge_semantic_target_metadata(&current_target, &prompt_target);
            Some((
                merged_target,
                if prompt_enriches_current {
                    "current_accessibility_tree+prompt_metadata"
                } else {
                    "current_accessibility_tree"
                },
            ))
        }
        (Some(current_target), None) => Some((current_target, "current_accessibility_tree")),
        (None, Some(prompt_target)) => Some((prompt_target, "prompt_observation_tree")),
        (None, None) => None,
    }
}

fn prompt_target_enriches_current(
    current_target: &BrowserSemanticTarget,
    prompt_target: &BrowserSemanticTarget,
) -> bool {
    (current_target.selector.is_none() && prompt_target.selector.is_some())
        || (current_target.x_path.is_none() && prompt_target.x_path.is_some())
        || (current_target.dom_id.is_none() && prompt_target.dom_id.is_some())
        || (current_target.tag_name.is_none() && prompt_target.tag_name.is_some())
        || (current_target.identity_attributes.is_empty()
            && !prompt_target.identity_attributes.is_empty())
        || (current_target.element_hash.is_none() && prompt_target.element_hash.is_some())
        || (current_target.stable_hash.is_none() && prompt_target.stable_hash.is_some())
        || (!current_target.dom_clickable && prompt_target.dom_clickable)
}

fn merge_semantic_target_metadata(
    current_target: &BrowserSemanticTarget,
    prompt_target: &BrowserSemanticTarget,
) -> BrowserSemanticTarget {
    let mut identity_attributes = prompt_target.identity_attributes.clone();
    for (key, value) in &current_target.identity_attributes {
        identity_attributes.insert(key.clone(), value.clone());
    }

    BrowserSemanticTarget {
        semantic_id: current_target
            .semantic_id
            .clone()
            .or_else(|| prompt_target.semantic_id.clone()),
        dom_id: current_target
            .dom_id
            .clone()
            .or_else(|| prompt_target.dom_id.clone()),
        selector: current_target
            .selector
            .clone()
            .or_else(|| prompt_target.selector.clone()),
        x_path: current_target
            .x_path
            .clone()
            .or_else(|| prompt_target.x_path.clone()),
        tag_name: current_target
            .tag_name
            .clone()
            .or_else(|| prompt_target.tag_name.clone()),
        dom_clickable: current_target.dom_clickable || prompt_target.dom_clickable,
        value: current_target
            .value
            .clone()
            .or_else(|| prompt_target.value.clone()),
        identity_attributes,
        element_hash: current_target.element_hash.or(prompt_target.element_hash),
        stable_hash: current_target.stable_hash.or(prompt_target.stable_hash),
        parent_branch_hash: current_target
            .parent_branch_hash
            .or(prompt_target.parent_branch_hash),
        ax_name: current_target
            .ax_name
            .clone()
            .or_else(|| prompt_target.ax_name.clone()),
        cdp_node_id: current_target
            .cdp_node_id
            .clone()
            .or_else(|| prompt_target.cdp_node_id.clone()),
        backend_dom_node_id: current_target
            .backend_dom_node_id
            .clone()
            .or_else(|| prompt_target.backend_dom_node_id.clone()),
        target_id: current_target
            .target_id
            .clone()
            .or_else(|| prompt_target.target_id.clone()),
        frame_id: current_target
            .frame_id
            .clone()
            .or_else(|| prompt_target.frame_id.clone()),
        rect_bounds: current_target.rect_bounds.or(prompt_target.rect_bounds),
        center_point: current_target.center_point.or(prompt_target.center_point),
        focused: current_target.focused,
        editable: current_target.editable || prompt_target.editable,
        checked: current_target.checked.or(prompt_target.checked),
        selected: current_target.selected.or(prompt_target.selected),
        scroll_top: current_target.scroll_top.or(prompt_target.scroll_top),
        scroll_height: current_target.scroll_height.or(prompt_target.scroll_height),
        client_height: current_target.client_height.or(prompt_target.client_height),
        can_scroll_up: current_target.can_scroll_up.or(prompt_target.can_scroll_up),
        can_scroll_down: current_target
            .can_scroll_down
            .or(prompt_target.can_scroll_down),
    }
}

pub(super) async fn capture_execution_prompt_browser_tree(
    exec: &ToolExecutor,
) -> Option<(AccessibilityNode, &'static str)> {
    if let Some((_, tree)) = exec
        .browser
        .recent_prompt_observation_snapshot(EXECUTION_PROMPT_OBSERVATION_CACHE_MAX_AGE)
        .await
    {
        return Some((
            apply_browser_auto_lens(tree),
            "recent_prompt_observation_snapshot",
        ));
    }

    exec.browser
        .get_prompt_observation_tree()
        .await
        .ok()
        .map(apply_browser_auto_lens)
        .map(|tree| (tree, "fresh_prompt_observation_tree"))
}

pub(super) fn find_nearest_semantic_target_by_point(
    node: &AccessibilityNode,
    x: f64,
    y: f64,
) -> Option<BrowserSemanticTarget> {
    let mut best = None;
    find_nearest_semantic_target_by_point_recursive(node, x, y, &mut best);
    best.map(|(_, _, _, _, _, target)| target)
}

pub(super) fn find_semantic_target_by_browser_ids(
    node: &AccessibilityNode,
    cdp_node_id: Option<&str>,
    backend_dom_node_id: Option<&str>,
) -> Option<BrowserSemanticTarget> {
    let node_cdp = node.attributes.get("cdp_node_id").map(String::as_str);
    let node_backend = node
        .attributes
        .get("backend_dom_node_id")
        .map(String::as_str);

    let cdp_match = cdp_node_id
        .filter(|id| !id.trim().is_empty())
        .is_some_and(|id| node_cdp == Some(id));
    let backend_match = backend_dom_node_id
        .filter(|id| !id.trim().is_empty())
        .is_some_and(|id| node_backend == Some(id));

    if cdp_match || backend_match {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) =
            find_semantic_target_by_browser_ids(child, cdp_node_id, backend_dom_node_id)
        {
            return Some(found);
        }
    }

    None
}

pub(super) fn find_semantic_target_by_dom_id(
    node: &AccessibilityNode,
    dom_id: &str,
) -> Option<BrowserSemanticTarget> {
    let dom_id = dom_id.trim();
    if dom_id.is_empty() {
        return None;
    }

    let node_dom_id = node_attr_value(node, "dom_id").or_else(|| node_attr_value(node, "id"));
    if node_dom_id == Some(dom_id) {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_dom_id(child, dom_id) {
            return Some(found);
        }
    }

    None
}

fn find_semantic_target_by_stable_hash(
    node: &AccessibilityNode,
    stable_hash: u64,
) -> Option<BrowserSemanticTarget> {
    if node_attr_u64(node, "stable_hash") == Some(stable_hash) {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_stable_hash(child, stable_hash) {
            return Some(found);
        }
    }

    None
}

fn find_semantic_target_by_element_hash(
    node: &AccessibilityNode,
    element_hash: u64,
) -> Option<BrowserSemanticTarget> {
    if node_attr_u64(node, "element_hash") == Some(element_hash) {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_element_hash(child, element_hash) {
            return Some(found);
        }
    }

    None
}

fn find_semantic_target_by_xpath(
    node: &AccessibilityNode,
    x_path: &str,
) -> Option<BrowserSemanticTarget> {
    if node_attr_value(node, "x_path").is_some_and(|value| value == x_path) {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_xpath(child, x_path) {
            return Some(found);
        }
    }

    None
}

fn candidate_tag_name_matches(node: &AccessibilityNode, expected_tag_name: Option<&str>) -> bool {
    expected_tag_name.is_none_or(|expected| {
        node_attr_value(node, "tag_name")
            .or_else(|| node_attr_value(node, "role"))
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(expected))
    })
}

fn find_semantic_target_by_ax_name(
    node: &AccessibilityNode,
    tag_name: Option<&str>,
    ax_name: &str,
) -> Option<BrowserSemanticTarget> {
    let tag_matches = candidate_tag_name_matches(node, tag_name);
    let ax_name_matches = node_attr_value(node, "ax_name")
        .or(node.name.as_deref())
        .is_some_and(|candidate| candidate == ax_name);
    if tag_matches && ax_name_matches {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_ax_name(child, tag_name, ax_name) {
            return Some(found);
        }
    }

    None
}

fn attribute_identity_candidates(target: &BrowserSemanticTarget) -> Vec<(&'static str, &str)> {
    let mut candidates = Vec::new();
    for key in ["name", "id", "aria-label"] {
        if let Some(value) = target.identity_attributes.get(key) {
            let value = value.trim();
            if !value.is_empty() {
                candidates.push((key, value));
            }
        }
    }
    if !target.identity_attributes.contains_key("id") {
        if let Some(dom_id) = target
            .dom_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            candidates.push(("id", dom_id));
        }
    }
    candidates
}

fn find_semantic_target_by_attribute_identity(
    node: &AccessibilityNode,
    tag_name: Option<&str>,
    attribute_key: &str,
    attribute_value: &str,
) -> Option<BrowserSemanticTarget> {
    if candidate_tag_name_matches(node, tag_name)
        && node_attr_value(node, attribute_key)
            .is_some_and(|candidate| candidate == attribute_value)
    {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_attribute_identity(
            child,
            tag_name,
            attribute_key,
            attribute_value,
        ) {
            return Some(found);
        }
    }

    None
}

fn find_semantic_target_for_verification(
    node: &AccessibilityNode,
    target: &BrowserSemanticTarget,
) -> Option<BrowserSemanticTarget> {
    find_semantic_target_by_browser_ids(
        node,
        target.cdp_node_id.as_deref(),
        target.backend_dom_node_id.as_deref(),
    )
    .or_else(|| {
        target
            .element_hash
            .and_then(|element_hash| find_semantic_target_by_element_hash(node, element_hash))
    })
    .or_else(|| {
        target
            .stable_hash
            .and_then(|stable_hash| find_semantic_target_by_stable_hash(node, stable_hash))
    })
    .or_else(|| {
        target
            .x_path
            .as_deref()
            .and_then(|x_path| find_semantic_target_by_xpath(node, x_path))
    })
    .or_else(|| {
        target.ax_name.as_deref().and_then(|ax_name| {
            find_semantic_target_by_ax_name(node, target.tag_name.as_deref(), ax_name)
        })
    })
    .or_else(|| {
        attribute_identity_candidates(target).into_iter().find_map(
            |(attribute_key, attribute_value)| {
                find_semantic_target_by_attribute_identity(
                    node,
                    target.tag_name.as_deref(),
                    attribute_key,
                    attribute_value,
                )
            },
        )
    })
    .or_else(|| {
        target
            .dom_id
            .as_deref()
            .and_then(|dom_id| find_semantic_target_by_dom_id(node, dom_id))
    })
    .or_else(|| {
        target
            .semantic_id
            .as_deref()
            .and_then(|semantic_id| find_semantic_target_by_id(node, semantic_id))
    })
}

pub(super) fn click_element_postcondition_met(
    pre_tree_xml: &str,
    pre_target: &BrowserSemanticTarget,
    pre_url: Option<&str>,
    post_tree_xml: &str,
    post_target: Option<&BrowserSemanticTarget>,
    post_url: Option<&str>,
) -> ClickElementPostcondition {
    let has_verifiable_identity = pre_target
        .backend_dom_node_id
        .as_deref()
        .is_some_and(|id| !id.trim().is_empty())
        || pre_target.element_hash.is_some()
        || pre_target
            .cdp_node_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty())
        || pre_target
            .dom_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty())
        || pre_target.stable_hash.is_some()
        || pre_target
            .x_path
            .as_deref()
            .is_some_and(|path| !path.trim().is_empty())
        || pre_target
            .ax_name
            .as_deref()
            .is_some_and(|name| !name.trim().is_empty());
    let has_geometry_only_identity = !has_verifiable_identity
        && pre_target
            .semantic_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty());
    let target_disappeared =
        (has_verifiable_identity || has_geometry_only_identity) && post_target.is_none();
    let editable_focus_transition = pre_target.editable
        && !pre_target.focused
        && post_target.is_some_and(|target| target.focused);
    let tree_changed = pre_tree_xml != post_tree_xml;
    let semantic_change_delta = if tree_changed {
        semantic_change_delta(pre_tree_xml, post_tree_xml, pre_target)
    } else {
        0
    };
    let material_semantic_change =
        semantic_change_delta >= LINK_STABLE_TARGET_MATERIAL_TREE_CHANGE_MIN_DELTA;
    let url_changed = pre_url
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .zip(post_url.map(str::trim).filter(|url| !url.is_empty()))
        .is_some_and(|(pre, post)| pre != post);

    ClickElementPostcondition {
        target_disappeared,
        editable_focus_transition,
        tree_changed,
        url_changed,
        material_semantic_change,
        semantic_change_delta,
    }
}

pub(super) fn semantic_target_verification_json(
    target: Option<&BrowserSemanticTarget>,
) -> serde_json::Value {
    match target {
        Some(target) => json!({
            "semantic_id": target.semantic_id,
            "dom_id": target.dom_id,
            "selector": target.selector,
            "x_path": target.x_path,
            "tag_name": target.tag_name,
            "dom_clickable": target.dom_clickable,
            "value": target.value,
            "identity_attributes": target.identity_attributes,
            "element_hash": target.element_hash,
            "stable_hash": target.stable_hash,
            "parent_branch_hash": target.parent_branch_hash,
            "ax_name": target.ax_name,
            "cdp_node_id": target.cdp_node_id,
            "backend_dom_node_id": target.backend_dom_node_id,
            "target_id": target.target_id,
            "frame_id": target.frame_id,
            "focused": target.focused,
            "editable": target.editable,
            "checked": target.checked,
            "selected": target.selected,
            "scroll_top": target.scroll_top,
            "scroll_height": target.scroll_height,
            "client_height": target.client_height,
            "can_scroll_up": target.can_scroll_up,
            "can_scroll_down": target.can_scroll_down,
            "center_point": target.center_point.map(|(x, y)| vec![x, y]),
        }),
        None => serde_json::Value::Null,
    }
}

