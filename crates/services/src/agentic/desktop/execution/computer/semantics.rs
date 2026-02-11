use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub(super) struct UiFindSemanticMatch {
    pub id: Option<String>,
    pub role: Option<String>,
    pub label: Option<String>,
    pub x: i32,
    pub y: i32,
    pub source: &'static str,
    pub confidence: f32,
}

fn normalize_semantic_key(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

fn find_node_by_id<'a>(node: &'a AccessibilityNode, id: &str) -> Option<&'a AccessibilityNode> {
    if node.id == id && node.is_visible {
        return Some(node);
    }

    for child in &node.children {
        if let Some(found) = find_node_by_id(child, id) {
            return Some(found);
        }
    }

    None
}

fn node_label(node: &AccessibilityNode) -> String {
    node.name
        .clone()
        .or_else(|| node.value.clone())
        .unwrap_or_else(|| node.role.clone())
}

fn semantic_confidence_from_score(score: i32) -> f32 {
    let normalized = (score as f32 / 135.0).clamp(0.35, 0.98);
    (normalized * 100.0).round() / 100.0
}

fn score_ui_find_candidate(
    query_lc: &str,
    query_norm: &str,
    query_terms: &[String],
    id: &str,
    role: &str,
    label: &str,
    rect: Rect,
) -> i32 {
    if rect.width <= 0 || rect.height <= 0 {
        return i32::MIN;
    }

    let id_lc = id.to_ascii_lowercase();
    let role_lc = role.to_ascii_lowercase();
    let label_lc = label.to_ascii_lowercase();
    let id_norm = normalize_semantic_key(id);
    let label_norm = normalize_semantic_key(label);
    let mut score = 0i32;

    if id_lc == query_lc {
        score += 140;
    }
    if label_lc == query_lc {
        score += 115;
    }
    if !query_norm.is_empty() && id_norm == query_norm {
        score += 105;
    }
    if !query_norm.is_empty() && label_norm == query_norm {
        score += 95;
    }
    if !query_lc.is_empty() && id_lc.contains(query_lc) {
        score += 75;
    }
    if !query_lc.is_empty() && label_lc.contains(query_lc) {
        score += 55;
    }
    if is_interactive_role_like(&role_lc) {
        score += 30;
    }
    if id_lc.starts_with("btn_") {
        score += 20;
    }

    if !query_terms.is_empty() {
        let haystack = format!("{} {} {}", id_lc, label_lc, role_lc);
        for term in query_terms {
            if haystack.contains(term) {
                score += 10;
            }
        }
    }

    let area = (rect.width * rect.height).max(1);
    score -= (area / 1200).min(25);
    score
}

pub(super) fn find_semantic_ui_match(
    tree: &AccessibilityNode,
    query: &str,
) -> Option<UiFindSemanticMatch> {
    let query = query.trim();
    if query.is_empty() {
        return None;
    }

    if let Some(node) = find_node_by_id(tree, query) {
        if node.rect.width > 0 && node.rect.height > 0 {
            let cx = node.rect.x + (node.rect.width / 2);
            let cy = node.rect.y + (node.rect.height / 2);
            return Some(UiFindSemanticMatch {
                id: Some(node.id.clone()),
                role: Some(node.role.clone()),
                label: Some(node_label(node)),
                x: cx,
                y: cy,
                source: "semantic_id_exact",
                confidence: 0.99,
            });
        }
    }

    let query_lc = query.to_ascii_lowercase();
    let query_norm = normalize_semantic_key(query);
    let query_terms = tokenize_query_terms(query);
    let mut best: Option<(i32, UiFindSemanticMatch)> = None;

    for (id, role, label, rect) in tree.find_matches(query) {
        let score = score_ui_find_candidate(
            &query_lc,
            &query_norm,
            &query_terms,
            &id,
            &role,
            &label,
            rect,
        );
        if score == i32::MIN {
            continue;
        }

        let cx = rect.x + (rect.width / 2);
        let cy = rect.y + (rect.height / 2);
        let candidate = UiFindSemanticMatch {
            id: Some(id),
            role: Some(role),
            label: Some(label),
            x: cx,
            y: cy,
            source: "semantic_tree",
            confidence: semantic_confidence_from_score(score),
        };

        match &best {
            Some((best_score, _)) if *best_score >= score => {}
            _ => best = Some((score, candidate)),
        }
    }

    if let Some((score, candidate)) = best {
        if score >= 25 {
            return Some(candidate);
        }
    }

    if let Some((x, y)) = find_center_for_numeric_query(tree, query) {
        return Some(UiFindSemanticMatch {
            id: None,
            role: Some("button".to_string()),
            label: Some("numeric".to_string()),
            x,
            y,
            source: "semantic_numeric",
            confidence: 0.62,
        });
    }

    None
}

fn has_node_content(node: &AccessibilityNode) -> bool {
    node.name.as_deref().is_some_and(|s| !s.trim().is_empty())
        || node.value.as_deref().is_some_and(|s| !s.trim().is_empty())
        || node
            .attributes
            .get("aria-label")
            .is_some_and(|s| !s.trim().is_empty())
        || node
            .attributes
            .get("title")
            .is_some_and(|s| !s.trim().is_empty())
        || node
            .attributes
            .get("description")
            .is_some_and(|s| !s.trim().is_empty())
}

fn is_interactive_role_like(role: &str) -> bool {
    matches!(
        role.trim().to_ascii_lowercase().as_str(),
        "button"
            | "push button"
            | "pushbutton"
            | "toggle button"
            | "menu item"
            | "menuitem"
            | "list item"
            | "listitem"
            | "link"
            | "check box"
            | "checkbox"
            | "radio button"
            | "tab"
            | "combo box"
            | "combobox"
            | "text box"
            | "textbox"
            | "entry"
            | "edit"
            | "text"
    )
}

fn is_structural_role_like(role: &str) -> bool {
    matches!(
        role.trim().to_ascii_lowercase().as_str(),
        "root" | "window" | "dialog" | "pane" | "panel" | "group" | "application"
    )
}

fn rect_contains_point(rect: Rect, x: i32, y: i32) -> bool {
    if rect.width <= 0 || rect.height <= 0 {
        return false;
    }
    let x2 = rect.x + rect.width;
    let y2 = rect.y + rect.height;
    x >= rect.x && x <= x2 && y >= rect.y && y <= y2
}

pub(super) fn find_best_element_for_point(
    root: &AccessibilityNode,
    x: i32,
    y: i32,
) -> Option<String> {
    let mut best: Option<(i32, i32, String)> = None; // score, area, id
    let mut stack = vec![root];

    while let Some(node) = stack.pop() {
        if node.is_visible && !node.id.trim().is_empty() && rect_contains_point(node.rect, x, y) {
            let role = node.role.to_ascii_lowercase();
            let is_interactive = is_interactive_role_like(&role);
            let is_leaf = node.children.is_empty();

            // Avoid snapping to non-interactive container nodes like windows/panes.
            if !is_interactive && !is_leaf {
                for child in &node.children {
                    stack.push(child);
                }
                continue;
            }

            let mut score = 0i32;
            let area = (node.rect.width * node.rect.height).max(1);

            if is_interactive {
                score += 55;
            }
            if has_node_content(node) {
                score += 25;
            }
            if node
                .attributes
                .get("semantic_aliases")
                .is_some_and(|s| !s.trim().is_empty())
            {
                score += 10;
            }
            if is_leaf {
                score += 8;
            }
            if node.id.to_ascii_lowercase().starts_with("btn_") {
                score += 12;
            }
            if is_structural_role_like(&role) && !is_interactive {
                score -= 60;
            }
            if (20..=200).contains(&node.rect.width) && (20..=200).contains(&node.rect.height) {
                score += 15;
            }

            score -= (area / 800).min(35);

            let cx = node.rect.x + (node.rect.width / 2);
            let cy = node.rect.y + (node.rect.height / 2);
            let center_distance = (cx - x).abs() + (cy - y).abs();
            score -= (center_distance / 100).min(10);

            match &best {
                Some((best_score, best_area, _))
                    if *best_score > score || (*best_score == score && *best_area <= area) => {}
                _ => best = Some((score, area, node.id.clone())),
            }
        }

        for child in &node.children {
            stack.push(child);
        }
    }

    best.and_then(|(score, _, id)| if score >= 25 { Some(id) } else { None })
}

pub(super) fn resolve_semantic_som_id(smap: &BTreeMap<u32, String>, query: &str) -> Option<u32> {
    if let Ok(id) = query.trim().parse::<u32>() {
        if smap.contains_key(&id) {
            return Some(id);
        }
    }

    if let Some((som_id, _)) = smap.iter().find(|(_, val)| val.as_str() == query) {
        return Some(*som_id);
    }

    if let Some((som_id, _)) = smap.iter().find(|(_, val)| val.eq_ignore_ascii_case(query)) {
        return Some(*som_id);
    }

    let qn = normalize_semantic_key(query);
    if !qn.is_empty() {
        if let Some((som_id, _)) = smap
            .iter()
            .find(|(_, val)| normalize_semantic_key(val.as_str()) == qn)
        {
            return Some(*som_id);
        }
    }

    let ql = query.to_ascii_lowercase();
    if !ql.is_empty() {
        if let Some((som_id, _)) = smap.iter().find(|(_, val)| {
            let v = val.to_ascii_lowercase();
            v.ends_with(&format!("_{}", ql)) || v.contains(&format!("_{}_", ql))
        }) {
            return Some(*som_id);
        }
        if let Some((som_id, _)) = smap
            .iter()
            .find(|(_, val)| val.to_ascii_lowercase().contains(&ql))
        {
            return Some(*som_id);
        }
    }

    None
}

pub(super) fn find_center_of_element(node: &AccessibilityNode, id: &str) -> Option<(i32, i32)> {
    if node.id == id && node.is_visible {
        let cx = node.rect.x + (node.rect.width / 2);
        let cy = node.rect.y + (node.rect.height / 2);
        return Some((cx, cy));
    }
    for child in &node.children {
        if let Some(coords) = find_center_of_element(child, id) {
            return Some(coords);
        }
    }
    None
}

pub(super) fn find_center_by_query(node: &AccessibilityNode, query: &str) -> Option<(i32, i32)> {
    let matches = node.find_matches(query);
    if matches.is_empty() {
        return None;
    }

    let query_norm = normalize_semantic_key(query);
    let query_lc = query.to_ascii_lowercase();

    let mut best: Option<(i32, (i32, i32))> = None;
    for (id, role, label, rect) in matches {
        if rect.width <= 0 || rect.height <= 0 {
            continue;
        }

        let mut score = 0i32;
        let id_lc = id.to_ascii_lowercase();
        let label_lc = label.to_ascii_lowercase();

        if id_lc == query_lc {
            score += 100;
        }
        if label_lc == query_lc {
            score += 90;
        }
        if !query_norm.is_empty() && normalize_semantic_key(&id) == query_norm {
            score += 80;
        }
        if !query_norm.is_empty() && normalize_semantic_key(&label) == query_norm {
            score += 70;
        }
        if id_lc.ends_with(&format!("_{}", query_lc)) {
            score += 40;
        }
        if role.to_ascii_lowercase().contains("button") {
            score += 20;
        }

        let cx = rect.x + (rect.width / 2);
        let cy = rect.y + (rect.height / 2);
        let candidate = (score, (cx, cy));
        if best.as_ref().map(|(s, _)| candidate.0 > *s).unwrap_or(true) {
            best = Some(candidate);
        }
    }

    best.map(|(_, center)| center)
}

fn is_generic_number_query(query: &str) -> bool {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return false;
    }

    q == "number"
        || q == "digit"
        || q == "num"
        || q == "any number"
        || q == "a number"
        || q.contains("number key")
        || q.contains("digit key")
}

fn extract_single_digit_token(node: &AccessibilityNode) -> Option<char> {
    let mut candidates: Vec<String> = Vec::new();

    candidates.push(node.id.clone());
    if let Some(name) = node.name.as_deref() {
        candidates.push(name.to_string());
    }
    if let Some(value) = node.value.as_deref() {
        candidates.push(value.to_string());
    }

    for key in [
        "semantic_id",
        "semantic_aliases",
        "aria-label",
        "title",
        "description",
    ] {
        if let Some(v) = node.attributes.get(key) {
            candidates.push(v.clone());
        }
    }

    for raw in candidates {
        for token in raw
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .flat_map(|part| part.split('_'))
        {
            let trimmed = token.trim();
            if trimmed.len() == 1 {
                if let Some(ch) = trimmed.chars().next() {
                    if ch.is_ascii_digit() {
                        return Some(ch);
                    }
                }
            }
        }
    }

    None
}

pub(super) fn find_center_for_numeric_query(
    node: &AccessibilityNode,
    query: &str,
) -> Option<(i32, i32)> {
    if !is_generic_number_query(query) {
        return None;
    }

    let mut best: Option<(i32, (i32, i32))> = None;
    let mut stack = vec![node];

    while let Some(current) = stack.pop() {
        if current.is_visible
            && current.rect.width > 0
            && current.rect.height > 0
            && extract_single_digit_token(current).is_some()
        {
            let mut score = 0i32;
            let role_lc = current.role.to_ascii_lowercase();

            if role_lc.contains("button") || role_lc.contains("push button") {
                score += 50;
            } else if role_lc.contains("list item") || role_lc.contains("menu item") {
                score += 20;
            }

            if (20..=150).contains(&current.rect.width) && (20..=150).contains(&current.rect.height)
            {
                score += 35;
            } else if current.rect.width >= 12 && current.rect.height >= 12 {
                score += 10;
            }

            if current.name.as_deref().is_some_and(|n| {
                n.trim().len() == 1 && n.trim().chars().all(|c| c.is_ascii_digit())
            }) {
                score += 30;
            }
            if current.value.as_deref().is_some_and(|v| {
                v.trim().len() == 1 && v.trim().chars().all(|c| c.is_ascii_digit())
            }) {
                score += 25;
            }

            if current.id.to_ascii_lowercase().starts_with("btn_") {
                score += 15;
            }

            let cx = current.rect.x + (current.rect.width / 2);
            let cy = current.rect.y + (current.rect.height / 2);
            let candidate = (score, (cx, cy));

            if best.as_ref().map(|(s, _)| candidate.0 > *s).unwrap_or(true) {
                best = Some(candidate);
            }
        }

        for child in &current.children {
            stack.push(child);
        }
    }

    best.map(|(_, center)| center)
}

fn tokenize_query_terms(input: &str) -> Vec<String> {
    input
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| token.len() >= 2)
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

pub(super) fn find_closest_matches(node: &AccessibilityNode, query: &str) -> Vec<String> {
    let query_lc = query.trim().to_ascii_lowercase();
    if query_lc.is_empty() {
        return Vec::new();
    }

    let query_norm = normalize_semantic_key(&query_lc);
    let query_terms = tokenize_query_terms(&query_lc);
    let min_score = if query_lc.len() <= 2 { 70 } else { 35 };

    let mut best_by_id: BTreeMap<String, (i32, String)> = BTreeMap::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.is_visible {
            let id_lc = current.id.to_ascii_lowercase();
            let name = current.name.as_deref().unwrap_or("").trim();
            let value = current.value.as_deref().unwrap_or("").trim();
            let label = if !name.is_empty() { name } else { value };
            let label_lc = label.to_ascii_lowercase();
            let aliases = current
                .attributes
                .get("semantic_aliases")
                .map(String::as_str)
                .unwrap_or("");
            let aliases_lc = aliases.to_ascii_lowercase();

            let mut score = 0i32;
            if id_lc == query_lc {
                score += 120;
            }
            if !label_lc.is_empty() && label_lc == query_lc {
                score += 110;
            }
            if id_lc.contains(&query_lc) {
                score += 80;
            }
            if !label_lc.is_empty() && label_lc.contains(&query_lc) {
                score += 70;
            }
            if !aliases_lc.is_empty() && aliases_lc.contains(&query_lc) {
                score += 65;
            }

            if !query_norm.is_empty() {
                let id_norm = normalize_semantic_key(&current.id);
                if id_norm == query_norm {
                    score += 75;
                } else if id_norm.contains(&query_norm) {
                    score += 50;
                }

                if !label_lc.is_empty() {
                    let label_norm = normalize_semantic_key(label);
                    if label_norm == query_norm {
                        score += 70;
                    } else if label_norm.contains(&query_norm) {
                        score += 45;
                    }
                }
            }

            if !query_terms.is_empty() {
                let haystack = format!("{} {} {}", id_lc, label_lc, aliases_lc);
                for term in &query_terms {
                    if haystack.contains(term) {
                        score += 12;
                    }
                }
            }

            if current.role.to_ascii_lowercase().contains("button") {
                score += 5;
            }

            if score >= min_score {
                let display_label = if label.is_empty() { "-" } else { label };
                let display = format!(
                    "{} (role={}, label='{}')",
                    current.id, current.role, display_label
                );
                match best_by_id.get(&current.id) {
                    Some((existing_score, _)) if *existing_score >= score => {}
                    _ => {
                        best_by_id.insert(current.id.clone(), (score, display));
                    }
                }
            }
        }

        for child in &current.children {
            stack.push(child);
        }
    }

    let mut ranked: Vec<(i32, String)> = best_by_id.into_values().collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.len().cmp(&b.1.len())));
    ranked
        .into_iter()
        .map(|(_, display)| display)
        .take(5)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn node(
        id: &str,
        role: &str,
        rect: Rect,
        children: Vec<AccessibilityNode>,
        name: Option<&str>,
    ) -> AccessibilityNode {
        AccessibilityNode {
            id: id.to_string(),
            role: role.to_string(),
            name: name.map(|v| v.to_string()),
            value: None,
            rect,
            children,
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        }
    }

    #[test]
    fn find_best_element_for_point_skips_non_interactive_containers() {
        let child_outside = node(
            "child_outside",
            "label",
            Rect {
                x: 420,
                y: 420,
                width: 40,
                height: 30,
            },
            vec![],
            Some("outside"),
        );
        let pane = node(
            "pane_1",
            "pane",
            Rect {
                x: 0,
                y: 0,
                width: 500,
                height: 500,
            },
            vec![child_outside],
            Some("container"),
        );
        let root = node(
            "window_1",
            "window",
            Rect {
                x: 0,
                y: 0,
                width: 500,
                height: 500,
            },
            vec![pane],
            Some("Calculator"),
        );

        let result = find_best_element_for_point(&root, 100, 100);
        assert_eq!(result, None);
    }

    #[test]
    fn find_best_element_for_point_returns_interactive_target() {
        let button = node(
            "btn_7",
            "button",
            Rect {
                x: 90,
                y: 80,
                width: 50,
                height: 50,
            },
            vec![],
            Some("7"),
        );
        let pane = node(
            "pane_1",
            "pane",
            Rect {
                x: 0,
                y: 0,
                width: 500,
                height: 500,
            },
            vec![button],
            Some("container"),
        );
        let root = node(
            "window_1",
            "window",
            Rect {
                x: 0,
                y: 0,
                width: 500,
                height: 500,
            },
            vec![pane],
            Some("Calculator"),
        );

        let result = find_best_element_for_point(&root, 100, 100);
        assert_eq!(result.as_deref(), Some("btn_7"));
    }
}
