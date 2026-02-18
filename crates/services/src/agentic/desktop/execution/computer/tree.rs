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
        // Never select the synthetic root node as the "best window" candidate; this helper is
        // used to scope the tree to a meaningful active-window subtree, and returning root is
        // a no-op.
        if !node.role.eq_ignore_ascii_case("root")
            && score > 2.5
            && best.as_ref().map(|(s, _)| score > *s).unwrap_or(true)
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
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn node(
        id: &str,
        role: &str,
        name: Option<&str>,
        rect: Rect,
        children: Vec<AccessibilityNode>,
    ) -> AccessibilityNode {
        AccessibilityNode {
            id: id.to_string(),
            role: role.to_string(),
            name: name.map(|s| s.to_string()),
            value: None,
            rect,
            children,
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        }
    }

    #[test]
    fn choose_active_window_subtree_prefers_title_and_overlap() {
        let active = WindowInfo {
            title: "Target Window".to_string(),
            x: 100,
            y: 200,
            width: 800,
            height: 600,
            app_name: "TargetApp".to_string(),
        };

        let good = node(
            "win-good",
            "window",
            Some("Target Window - TargetApp"),
            Rect {
                x: 100,
                y: 200,
                width: 800,
                height: 600,
            },
            vec![],
        );
        let bad = node(
            "win-bad",
            "window",
            Some("Other Window - OtherApp"),
            Rect {
                x: 0,
                y: 0,
                width: 640,
                height: 480,
            },
            vec![],
        );

        let root = node(
            "root",
            "root",
            None,
            Rect {
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
            },
            vec![bad, good.clone()],
        );

        let scoped = choose_active_window_subtree(&root, &active).expect("expected a match");
        assert_eq!(scoped.id, good.id);
    }

    #[test]
    fn choose_active_window_subtree_returns_none_when_no_match() {
        let active = WindowInfo {
            title: "Target Window".to_string(),
            x: 100,
            y: 200,
            width: 800,
            height: 600,
            app_name: "TargetApp".to_string(),
        };

        let child = node(
            "panel-1",
            "pane",
            Some("Unrelated"),
            Rect {
                x: 0,
                y: 0,
                width: 10,
                height: 10,
            },
            vec![],
        );
        let root = node(
            "root",
            "root",
            None,
            Rect {
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
            },
            vec![child],
        );

        assert!(choose_active_window_subtree(&root, &active).is_none());
    }
}
