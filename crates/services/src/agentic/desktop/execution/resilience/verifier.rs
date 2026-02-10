use crate::agentic::desktop::execution::ToolExecutor;
use image::load_from_memory;
use image_hasher::{HashAlg, HasherConfig};
use ioi_drivers::gui::accessibility::AccessibilityNode;
use ioi_drivers::gui::platform::fetch_tree_direct;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct StateSnapshot {
    pub tree_hash: u64,
    pub visual_hash: [u8; 32],
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub significant: bool,
    pub tree_changed: bool,
    pub visual_distance: u32,
}

impl VerificationResult {
    pub fn is_significant(&self) -> bool {
        self.significant
    }
}

pub struct ActionVerifier;

impl ActionVerifier {
    pub async fn capture_snapshot(
        exec: &ToolExecutor,
        active_lens: Option<&str>,
    ) -> Result<StateSnapshot, String> {
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

        let mut hasher = DefaultHasher::new();
        hash_visible_tree(&tree, &mut hasher);
        let tree_hash = hasher.finish();

        let raw_screen = exec
            .gui
            .capture_raw_screen()
            .await
            .map_err(|e| format!("Failed to capture raw screen: {}", e))?;
        let visual_hash = compute_window_phash(&raw_screen, exec.active_window.as_ref())
            .unwrap_or(compute_phash(&raw_screen)?);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Ok(StateSnapshot {
            tree_hash,
            visual_hash,
            timestamp,
        })
    }

    pub fn verify_impact(before: &StateSnapshot, after: &StateSnapshot) -> VerificationResult {
        const VISUAL_DISTANCE_THRESHOLD: u32 = 6;
        let tree_changed = before.tree_hash != after.tree_hash;
        let visual_distance = hamming_distance(&before.visual_hash, &after.visual_hash);
        let significant = tree_changed || visual_distance > VISUAL_DISTANCE_THRESHOLD;

        VerificationResult {
            significant,
            tree_changed,
            visual_distance,
        }
    }
}

fn hash_visible_tree(node: &AccessibilityNode, hasher: &mut DefaultHasher) {
    if !node.is_visible {
        return;
    }

    node.id.hash(hasher);
    node.role.hash(hasher);
    node.name.hash(hasher);
    node.value.hash(hasher);
    node.rect.x.hash(hasher);
    node.rect.y.hash(hasher);
    node.rect.width.hash(hasher);
    node.rect.height.hash(hasher);
    node.children.len().hash(hasher);

    for child in &node.children {
        hash_visible_tree(child, hasher);
    }
}

fn compute_phash(image_bytes: &[u8]) -> Result<[u8; 32], String> {
    let img = load_from_memory(image_bytes).map_err(|e| format!("Image decode failed: {}", e))?;
    let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
    let hash = hasher.hash_image(&img);
    let hash_bytes = hash.as_bytes();

    let mut out = [0u8; 32];
    let len = hash_bytes.len().min(32);
    out[..len].copy_from_slice(&hash_bytes[..len]);
    Ok(out)
}

fn compute_window_phash(
    image_bytes: &[u8],
    window: Option<&ioi_api::vm::drivers::os::WindowInfo>,
) -> Option<[u8; 32]> {
    let window = window?;
    if window.width <= 0 || window.height <= 0 {
        return None;
    }

    let img = load_from_memory(image_bytes).ok()?;
    let img_w = img.width() as i32;
    let img_h = img.height() as i32;
    if img_w <= 0 || img_h <= 0 {
        return None;
    }

    let x1 = window.x.clamp(0, img_w);
    let y1 = window.y.clamp(0, img_h);
    let x2 = (window.x + window.width).clamp(0, img_w);
    let y2 = (window.y + window.height).clamp(0, img_h);
    if x2 <= x1 || y2 <= y1 {
        return None;
    }

    let cropped = img.crop_imm(x1 as u32, y1 as u32, (x2 - x1) as u32, (y2 - y1) as u32);
    let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
    let hash = hasher.hash_image(&cropped);
    let hash_bytes = hash.as_bytes();

    let mut out = [0u8; 32];
    let len = hash_bytes.len().min(32);
    out[..len].copy_from_slice(&hash_bytes[..len]);
    Some(out)
}

fn hamming_distance(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    let mut dist = 0u32;
    for i in 0..32 {
        dist += (a[i] ^ b[i]).count_ones();
    }
    dist
}

#[cfg(test)]
mod tests {
    use super::{ActionVerifier, StateSnapshot};

    #[test]
    fn verify_impact_detects_no_change() {
        let before = StateSnapshot {
            tree_hash: 10,
            visual_hash: [0u8; 32],
            timestamp: 100,
        };
        let after = StateSnapshot {
            tree_hash: 10,
            visual_hash: [0u8; 32],
            timestamp: 200,
        };
        let result = ActionVerifier::verify_impact(&before, &after);
        assert!(!result.is_significant());
        assert!(!result.tree_changed);
        assert_eq!(result.visual_distance, 0);
    }

    #[test]
    fn verify_impact_detects_change() {
        let before = StateSnapshot {
            tree_hash: 10,
            visual_hash: [0u8; 32],
            timestamp: 100,
        };
        let mut after_hash = [0u8; 32];
        after_hash[0] = 0b1111_1111;
        let after = StateSnapshot {
            tree_hash: 11,
            visual_hash: after_hash,
            timestamp: 200,
        };
        let result = ActionVerifier::verify_impact(&before, &after);
        assert!(result.is_significant());
        assert!(result.tree_changed);
    }
}
