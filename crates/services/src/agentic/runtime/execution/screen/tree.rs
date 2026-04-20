use super::super::ToolExecutor;
use ioi_api::vm::drivers::os::WindowInfo;
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use ioi_drivers::gui::platform::fetch_tree_direct;

fn rect_overlap_ratio(a: Rect, b: Rect) -> f32 {
    if a.width <= 0 || a.height <= 0 || b.width <= 0 || b.height <= 0 {
        return 0.0;
    }

    let ax2 = a.x + a.width;
    let ay2 = a.y + a.height;
    let bx2 = b.x + b.width;
    let by2 = b.y + b.height;

    let ix1 = a.x.max(b.x);
    let iy1 = a.y.max(b.y);
    let ix2 = ax2.min(bx2);
    let iy2 = ay2.min(by2);

    let iw = (ix2 - ix1).max(0);
    let ih = (iy2 - iy1).max(0);
    if iw == 0 || ih == 0 {
        return 0.0;
    }

    let inter = (iw as f64) * (ih as f64);
    let b_area = (b.width as f64) * (b.height as f64);
    if b_area <= 0.0 {
        0.0
    } else {
        (inter / b_area) as f32
    }
}

fn window_match_score(node: &AccessibilityNode, active: &WindowInfo) -> f32 {
    let role = node.role.to_ascii_lowercase();
    let mut score = 0.0f32;

    if role.contains("window") || role.contains("application") || role.contains("frame") {
        score += 1.5;
    }

    let label = format!(
        "{} {}",
        node.name.as_deref().unwrap_or_default(),
        node.id.as_str()
    )
    .to_ascii_lowercase();

    let title_lc = active.title.to_ascii_lowercase();
    let app_lc = active.app_name.to_ascii_lowercase();

    if !title_lc.is_empty() && label.contains(&title_lc) {
        score += 4.0;
    }
    if !app_lc.is_empty() && label.contains(&app_lc) {
        score += 2.5;
    }

    let active_rect = Rect {
        x: active.x,
        y: active.y,
        width: active.width,
        height: active.height,
    };
    score += rect_overlap_ratio(node.rect, active_rect) * 4.0;

    if role == "root" {
        score -= 1.0;
    }

    score
}

fn choose_active_window_subtree(
    root: &AccessibilityNode,
    active: &WindowInfo,
) -> Option<AccessibilityNode> {
    fn walk(
        node: &AccessibilityNode,
        active: &WindowInfo,
        best: &mut Option<(f32, AccessibilityNode)>,
    ) {
        let score = window_match_score(node, active);
        let role = node.role.to_ascii_lowercase();
        let window_like_role =
            role.contains("window") || role.contains("application") || role.contains("frame");
        // Never select the synthetic root node as the "best window" candidate; this helper is
        // used to scope the tree to a meaningful active-window subtree, and returning root is
        // a no-op.
        if window_like_role && score > 2.5 && best.as_ref().map(|(s, _)| score > *s).unwrap_or(true)
        {
            *best = Some((score, node.clone()));
        }
        for child in &node.children {
            walk(child, active, best);
        }
    }

    let mut best = None;
    walk(root, active, &mut best);
    best.map(|(_, node)| node)
}

pub(in super::super) async fn fetch_lensed_tree(
    exec: &ToolExecutor,
    active_lens: Option<&str>,
) -> Result<AccessibilityNode, String> {
    let mut raw_tree = fetch_tree_direct()
        .await
        .map_err(|e| format!("Failed to fetch UI tree: {}", e))?;

    if let Some(active) = exec.active_window.as_ref() {
        if let Some(scoped) = choose_active_window_subtree(&raw_tree, active) {
            raw_tree = scoped;
        }
    }

    let tree = if let Some(lens_name) = active_lens {
        if let Some(registry) = &exec.lens_registry {
            if let Some(lens) = registry.get(lens_name) {
                lens.transform(&raw_tree).unwrap_or(raw_tree)
            } else {
                raw_tree
            }
        } else {
            raw_tree
        }
    } else {
        raw_tree
    };

    Ok(tree)
}

#[cfg(test)]
#[path = "tree/tests.rs"]
mod tests;
