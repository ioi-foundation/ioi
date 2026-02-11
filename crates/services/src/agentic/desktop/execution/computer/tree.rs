use super::super::ToolExecutor;
use ioi_drivers::gui::accessibility::AccessibilityNode;
use ioi_drivers::gui::platform::fetch_tree_direct;

pub(in super::super) async fn fetch_lensed_tree(
    exec: &ToolExecutor,
    active_lens: Option<&str>,
) -> Result<AccessibilityNode, String> {
    let raw_tree = fetch_tree_direct()
        .await
        .map_err(|e| format!("Failed to fetch UI tree: {}", e))?;

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
