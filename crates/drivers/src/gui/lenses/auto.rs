// Path: crates/drivers/src/gui/lenses/auto.rs

use super::AppLens;
use crate::gui::accessibility::AccessibilityNode;
use ioi_crypto::algorithms::hash::sha256;
use std::collections::HashSet;

/// A generalized lens that auto-generates stable semantic IDs.
///
/// V3 Update: "Unstoppable" Mode + Deep Stability.
/// 1. Soft visibility prune (recurse even if hidden to find visible descendants).
/// 2. Deep ancestry hashing (3 levels) for stability.
/// 3. Adaptive Grid Bucketing (50px).
/// 4. Invisible Container Collapse (Reduce bloat).
pub struct AutoLens;

impl AppLens for AutoLens {
    fn name(&self) -> &str {
        "universal_heuristic_v3"
    }

    fn matches(&self, _window_title: &str) -> bool {
        true // Matches everything as a fallback
    }

    fn transform(&self, root: &AccessibilityNode) -> Option<AccessibilityNode> {
        let mut context = TransformContext::new();
        // Pass depth 0 to start
        self.transform_recursive(root, &mut context, 0, 0)
    }

    fn render(&self, node: &AccessibilityNode, depth: usize) -> String {
        crate::gui::accessibility::serialize_tree_to_xml(node, depth)
    }
}

struct TransformContext {
    used_ids: HashSet<String>,
    ancestry_stack: Vec<String>,
}

impl TransformContext {
    fn new() -> Self {
        Self {
            used_ids: HashSet::new(),
            ancestry_stack: Vec::new(),
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

impl AutoLens {
    fn transform_recursive(
        &self,
        node: &AccessibilityNode,
        ctx: &mut TransformContext,
        sibling_index: usize,
        depth: usize,
    ) -> Option<AccessibilityNode> {
        // [FIX] Removed early visibility return.
        // We traverse invisible containers because they might hold visible children (e.g. scroll panes).

        // 1. Determine Interactivity & Structure
        let is_interactive = self.is_interactive_role(&node.role);
        let has_content = node.name.as_ref().map_or(false, |s| !s.trim().is_empty())
            || node.value.as_ref().map_or(false, |s| !s.trim().is_empty())
            || self
                .first_non_empty_attr(
                    node,
                    &[
                        "placeholder",
                        "description",
                        "aria-label",
                        "title",
                        "automation_id",
                    ],
                )
                .is_some();
        let is_structural = matches!(
            node.role.as_str(),
            "window" | "dialog" | "pane" | "application" | "group"
        );

        // 2. Recurse Children First (Depth-First)
        ctx.ancestry_stack.push(node.role.clone());

        // [FIX] Capture snapshot for fingerprinting BEFORE popping.
        // This snapshot now includes the current node's role, meaning context is "ancestry + self".
        let ancestry_snapshot = ctx.ancestry_stack.clone();

        let new_children: Vec<AccessibilityNode> = node
            .children
            .iter()
            .enumerate()
            .filter_map(|(i, c)| self.transform_recursive(c, ctx, i, depth + 1))
            .collect();

        ctx.ancestry_stack.pop();

        // 3. Post-Recursion Pruning (The "Soft Prune")

        // Rule A: If node is invisible AND has no surviving visible children -> Drop.
        // We always keep the root (depth 0) to maintain tree integrity.
        if depth > 0 && !node.is_visible && new_children.is_empty() {
            return None;
        }

        // Rule B: If visible but empty, non-interactive, and not structural -> Drop.
        // This cleans up "div soup" leaf nodes that have no semantic value.
        if node.is_visible
            && new_children.is_empty()
            && !is_interactive
            && !has_content
            && !is_structural
        {
            return None;
        }

        // [FIX] Rule C: Transparent Container Collapse
        // If invisible, not interactive, no content, HAS exactly 1 child, AND NOT structural -> Return child directly.
        // We guard with !is_structural to ensure we don't collapse meaningful layout anchors like panes or windows.
        if depth > 0
            && !node.is_visible
            && !is_interactive
            && !has_content
            && !is_structural
            && new_children.len() == 1
        {
            return Some(new_children[0].clone());
        }

        let mut new_node = node.clone();
        new_node.children = new_children;

        // 4. ID Generation (LiDAR)
        // Only generate stable IDs for things we might want to click or read, or structural anchors.
        if is_interactive || has_content || is_structural {
            // [FIX] Use captured snapshot for deep fingerprinting
            let fingerprint = self.compute_fingerprint(node, &ancestry_snapshot);
            let full_hash = to_hex(sha256(fingerprint.as_bytes()).unwrap().as_ref());
            let stable_hash = &full_hash[0..6];

            let base_id = self.generate_robust_id(node, sibling_index, stable_hash);

            let mut candidate = base_id.clone();

            // Collision Resolution
            if ctx.used_ids.contains(&candidate) {
                candidate = format!("{}_{}", base_id, stable_hash);
            }

            let mut counter = 1;
            while ctx.used_ids.contains(&candidate) {
                candidate = format!("{}_{}_{}", base_id, stable_hash, counter);
                counter += 1;
            }

            ctx.used_ids.insert(candidate.clone());
            new_node.id = candidate;

            // Inject Semantic Attributes for Agent context
            new_node
                .attributes
                .insert("semantic_id".to_string(), new_node.id.clone());
            if let Some(alias_blob) = self.build_semantic_aliases(&new_node) {
                new_node
                    .attributes
                    .insert("semantic_aliases".to_string(), alias_blob);
            }
        }

        Some(new_node)
    }

    fn is_interactive_role(&self, role: &str) -> bool {
        let normalized = role.trim().to_ascii_lowercase();
        matches!(
            normalized.as_str(),
            "button"
                | "push button"
                | "link"
                | "menu item"
                | "check box"
                | "radio button"
                | "combo box"
                | "combobox"
                | "text"
                | "edit"
                | "entry"
                | "search box"
                | "searchbox"
                | "text box"
                | "textbox"
                | "slider"
                | "toggle"
                | "toggle button"
                | "tab"
                | "list item"
                | "pushbutton"
        )
    }

    fn generate_robust_id(
        &self,
        node: &AccessibilityNode,
        _index: usize,
        stable_hash: &str,
    ) -> String {
        // Strategy A: Content-derived (Best for humans/agents)
        // Priority: automation IDs and labels first, then visible text.
        let raw_name = [
            self.first_non_empty_attr(
                node,
                &[
                    "automation_id",
                    "automationid",
                    "data-testid",
                    "data-test-id",
                    "testid",
                    "id",
                ],
            ),
            node.name.as_deref().filter(|s| !s.trim().is_empty()),
            node.value.as_deref().filter(|s| !s.trim().is_empty()),
            self.first_non_empty_attr(node, &["placeholder", "aria-label", "title", "description"]),
        ]
        .into_iter()
        .flatten()
        .find(|s| !s.trim().is_empty());

        let semantic_part = if let Some(text) = raw_name {
            self.slugify(text)
        } else {
            String::new()
        };

        let normalized_role = node.role.trim().to_ascii_lowercase();
        let fallback_prefix = {
            let role_slug = self.slugify(&normalized_role);
            if role_slug.is_empty() {
                "el".to_string()
            } else {
                role_slug
            }
        };
        let prefix = match normalized_role.as_str() {
            "button" | "push button" | "pushbutton" | "toggle button" => "btn",
            "link" | "hyperlink" => "lnk",
            "text" | "edit" | "entry" | "combo box" | "combobox" | "search box" | "searchbox"
            | "text box" | "textbox" => "inp",
            "window" | "frame" | "dialog" => "win",
            "group" | "generic" | "pane" | "panel" => "grp",
            "image" | "icon" | "graphic" => "img",
            _ => fallback_prefix.as_str(),
        };

        if !semantic_part.is_empty() {
            format!("{}_{}", prefix, semantic_part)
        } else {
            // Strategy B: Structural + Hash (Unstoppable Fallback)
            // We avoid sibling index to reduce ID drift when ephemeral nodes appear/disappear.
            format!("{}_{}", prefix, stable_hash)
        }
    }

    fn slugify(&self, text: &str) -> String {
        let s = text.trim();
        if s.is_empty() {
            return String::new();
        }

        // Common symbol-only controls (calculator/toolbars).
        match s {
            "+" => return "plus".to_string(),
            "-" => return "minus".to_string(),
            "*" | "×" => return "multiply".to_string(),
            "/" | "÷" => return "divide".to_string(),
            "=" => return "equals".to_string(),
            "." => return "dot".to_string(),
            "%" => return "percent".to_string(),
            _ => {}
        }

        // If it's just numbers, keep it (e.g. Calculator buttons)
        if s.chars().all(|c| c.is_ascii_digit()) {
            return s.to_string();
        }

        // Map common math symbols to words, but keep hyphen as a separator for normal text.
        let mut expanded = String::with_capacity(s.len() + 16);
        for c in s.chars() {
            match c {
                '+' => expanded.push_str(" plus "),
                '*' | '×' => expanded.push_str(" multiply "),
                '/' | '÷' => expanded.push_str(" divide "),
                '=' => expanded.push_str(" equals "),
                '.' => expanded.push_str(" dot "),
                '%' => expanded.push_str(" percent "),
                _ => expanded.push(c),
            }
        }

        let slug: String = expanded
            .chars()
            .filter_map(|c| {
                if c.is_alphanumeric() {
                    Some(c.to_ascii_lowercase())
                } else if c.is_whitespace() || c == '-' || c == '_' {
                    Some('_')
                } else {
                    None
                }
            })
            .collect();

        let mut clean_slug = String::with_capacity(slug.len());
        let mut prev_was_underscore = false;
        for c in slug.chars() {
            if c == '_' {
                if prev_was_underscore {
                    continue;
                }
                prev_was_underscore = true;
            } else {
                prev_was_underscore = false;
            }
            clean_slug.push(c);
        }

        let clean_slug = clean_slug.trim_matches('_');
        if clean_slug.len() > 30 {
            clean_slug[..30].to_string()
        } else {
            clean_slug.to_string()
        }
    }

    fn compute_fingerprint(&self, node: &AccessibilityNode, ancestry: &[String]) -> String {
        // [FIX] Use deeper ancestry (last 3 parents) for context
        // This helps differentiate identical grids/lists better than just immediate parent.
        let depth = ancestry.len();
        // Skip the last element if we want "parents only" logic, but keeping "ancestry + self" is acceptable for uniqueness.
        // We take the last 3 elements of the stack.
        let take = 3.min(depth);
        let parent_ctx = if take > 0 {
            ancestry[depth - take..].join("/")
        } else {
            "root".to_string()
        };

        // [FIX] Tuned grid bucket to 50px.
        // 100px was too coarse for dense grids; 50px offers better separation while still handling minor shifts.
        let cx = node.rect.x / 50;
        let cy = node.rect.y / 50;

        let content_hint = [
            node.name.as_deref().filter(|s| !s.trim().is_empty()),
            node.value.as_deref().filter(|s| !s.trim().is_empty()),
            self.first_non_empty_attr(
                node,
                &["placeholder", "description", "automation_id", "aria-label"],
            ),
        ]
        .into_iter()
        .flatten()
        .next()
        .unwrap_or("");

        format!(
            "{}:{}:{}:{}x{}",
            node.role, parent_ctx, content_hint, cx, cy
        )
    }

    fn first_non_empty_attr<'a>(
        &self,
        node: &'a AccessibilityNode,
        keys: &[&str],
    ) -> Option<&'a str> {
        for key in keys {
            if let Some(value) = node.attributes.get(*key).map(String::as_str) {
                if !value.trim().is_empty() {
                    return Some(value);
                }
            }
        }
        None
    }

    fn is_input_like_role(&self, role: &str) -> bool {
        matches!(
            role.trim().to_ascii_lowercase().as_str(),
            "text"
                | "edit"
                | "entry"
                | "combo box"
                | "combobox"
                | "search box"
                | "searchbox"
                | "text box"
                | "textbox"
        )
    }

    fn is_button_like_role(&self, role: &str) -> bool {
        matches!(
            role.trim().to_ascii_lowercase().as_str(),
            "button" | "push button" | "pushbutton" | "toggle button"
        )
    }

    fn build_semantic_aliases(&self, node: &AccessibilityNode) -> Option<String> {
        let mut aliases: HashSet<String> = HashSet::new();
        let mut push_alias = |raw: &str| {
            let t = raw.trim();
            if t.is_empty() {
                return;
            }
            let lower = t.to_ascii_lowercase();
            aliases.insert(lower.clone());
            aliases.insert(lower.replace('_', ""));
            aliases.insert(lower.replace('-', ""));
            aliases.insert(
                lower
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                    .collect::<String>()
                    .trim_matches('_')
                    .to_string(),
            );
        };

        push_alias(&node.id);
        if let Some(name) = node.name.as_deref() {
            push_alias(name);
        }
        if let Some(value) = node.value.as_deref() {
            push_alias(value);
        }

        for key in ["placeholder", "aria-label", "title", "description"] {
            if let Some(v) = node.attributes.get(key).map(String::as_str) {
                push_alias(v);
            }
        }

        let role_lc = node.role.to_ascii_lowercase();
        let content_blob = format!(
            "{} {} {} {}",
            node.id,
            node.name.as_deref().unwrap_or(""),
            node.value.as_deref().unwrap_or(""),
            node.attributes
                .get("placeholder")
                .map(String::as_str)
                .unwrap_or("")
        )
        .to_ascii_lowercase();

        let is_search = content_blob.contains("search") || role_lc.contains("search");
        let is_input = self.is_input_like_role(&role_lc);
        let is_button = self.is_button_like_role(&role_lc);

        if is_input {
            for alias in [
                "input",
                "text input",
                "textbox",
                "text box",
                "entry",
                "field",
                "inputfield",
            ] {
                push_alias(alias);
            }
        }

        if is_search && is_input {
            for alias in [
                "search",
                "searchinput",
                "search_input",
                "searchbox",
                "search_box",
                "searchboxinput",
                "search bar",
                "search field",
                "query",
                "query input",
            ] {
                push_alias(alias);
            }
        }

        if is_search && is_button {
            for alias in [
                "searchbutton",
                "search_button",
                "btn_search",
                "google search",
                "submit search",
            ] {
                push_alias(alias);
            }
        }

        let mut values: Vec<String> = aliases
            .into_iter()
            .filter(|s| !s.is_empty() && s.len() <= 64)
            .collect();
        values.sort();
        values.dedup();

        if values.is_empty() {
            None
        } else {
            Some(values.join(" "))
        }
    }
}
