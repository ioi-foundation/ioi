// Path: crates/drivers/src/gui/som.rs

//! "Set-of-Marks" (SoM) Visual Grounding.
//!
//! Overlays the accessibility tree onto the raw screenshot, tagging every
//! interactive element with a unique numeric ID and bounding box.
//! This allows VLM agents to "see" the UI structure and click reliably.

use image::{Rgba, RgbaImage};
use imageproc::drawing::{draw_filled_rect_mut, draw_hollow_rect_mut, draw_text_mut};
use imageproc::rect::Rect as ImageRect;
// [FIX] Import ScaleFont trait for .ascent()
use super::accessibility::{AccessibilityNode, Rect};
use super::geometry::{CoordinateSpace, DisplayTransform, Rect as GeoRect};
use ab_glyph::{Font, FontRef, PxScale, ScaleFont};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

// Static storage for the loaded font to avoid IO on every frame.
static FONT_DATA: OnceLock<Vec<u8>> = OnceLock::new();
static TRUTH_PROBE_DRAWN: AtomicBool = AtomicBool::new(false);
const SYNTHETIC_GRID_AREA_THRESHOLD: f64 = 0.20;
const SYNTHETIC_GRID_MIN_DIMENSION: f64 = 160.0;

/// Attempts to load a standard system font for rendering labels.
fn load_system_font() -> Option<FontRef<'static>> {
    // 1. Check if already loaded
    if let Some(data) = FONT_DATA.get() {
        return FontRef::try_from_slice(data).ok();
    }

    // 2. Define search paths based on OS
    let paths = if cfg!(target_os = "macos") {
        vec![
            "/System/Library/Fonts/Helvetica.ttc",
            "/System/Library/Fonts/SFNS.ttf",
            "/Library/Fonts/Arial.ttf",
        ]
    } else if cfg!(target_os = "windows") {
        vec![
            "C:\\Windows\\Fonts\\arial.ttf",
            "C:\\Windows\\Fonts\\seguiemj.ttf",
            "C:\\Windows\\Fonts\\consola.ttf",
        ]
    } else {
        // Linux/Unix
        vec![
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            "/usr/share/fonts/TTF/DejaVuSans.ttf",
            "/usr/share/fonts/gnu-free/FreeSans.ttf",
        ]
    };

    // 3. Attempt to read one
    for p in paths {
        let path = Path::new(p);
        if path.exists() {
            if let Ok(bytes) = std::fs::read(path) {
                // Store in static OnceLock to keep 'static lifetime for FontRef
                if FONT_DATA.set(bytes).is_ok() {
                    let data_ref = FONT_DATA.get().unwrap();
                    if let Ok(font) = FontRef::try_from_slice(data_ref) {
                        log::info!("SoM: Loaded system font from {:?}", path);
                        return Some(font);
                    }
                }
            }
        }
    }

    log::warn!("SoM: No system font found. IDs will not be rendered.");
    None
}

/// Blurs specific regions in the image based on the accessibility tree.
/// This runs BEFORE the SoM overlay to ensure sensitive data is hidden from the VLM.
pub fn redact_sensitive_regions(img: &mut RgbaImage, node: &AccessibilityNode, offset: (i32, i32)) {
    // 1. Check for sensitive role
    // "password_text" is common in some accessibility APIs, "password" in others
    let is_password = node.role.contains("password");

    // 2. Check for PII keywords in value/name (Basic Heuristic)
    // In a real system, use the `LocalSafetyModel` here if performance allows.
    let text_content = format!(
        "{} {}",
        node.name.as_deref().unwrap_or(""),
        node.value.as_deref().unwrap_or("")
    );
    let lower_text = text_content.to_lowercase();
    let is_sensitive_text = lower_text.contains("api key")
        || lower_text.contains("secret")
        || lower_text.contains("cvv")
        || lower_text.contains("ssn");

    if is_password || is_sensitive_text {
        let local_x = node.rect.x - offset.0;
        let local_y = node.rect.y - offset.1;
        let w = node.rect.width;
        let h = node.rect.height;

        // Clamp to image bounds
        let img_w = img.width() as i32;
        let img_h = img.height() as i32;

        if local_x + w > 0 && local_y + h > 0 && local_x < img_w && local_y < img_h {
            let rx = local_x.max(0) as u32;
            let ry = local_y.max(0) as u32;
            let rw = (w.min(img_w - local_x)).max(1) as u32;
            let rh = (h.min(img_h - local_y)).max(1) as u32;

            // Draw filled black rect for redaction (Secure and fast)
            let redaction_rect = ImageRect::at(rx as i32, ry as i32).of_size(rw, rh);
            draw_filled_rect_mut(img, redaction_rect, Rgba([0, 0, 0, 255]));

            // Optional: Label it
            // We skip labeling to avoid leaking *what* was hidden, just black box.
        }
    }

    // Recurse
    for child in &node.children {
        redact_sensitive_regions(img, child, offset);
    }
}

/// Overlays bounding boxes and IDs for all interactive elements in the tree onto the image.
/// This modifies the `screenshot` in-place.
/// Returns the mapping of ID -> Rect for click resolution.
///
/// DEPRECATED: Use `assign_som_ids` then `draw_som_overlay` for unified pipeline.
pub fn overlay_accessibility_tree(
    screenshot: &mut RgbaImage,
    root: &AccessibilityNode,
    start_id: Option<u32>, // Allow chaining overlays with offset IDs
    offset: (i32, i32),
) -> HashMap<u32, Rect> {
    let font = load_system_font();
    // Scale for ID text (24px for readability)
    let scale = PxScale { x: 24.0, y: 24.0 };

    // We start indexing from 1 to keep IDs clean for the LLM
    let mut counter = start_id.unwrap_or(1);
    let mut map = HashMap::new();

    recurse_draw(
        screenshot,
        root,
        font.as_ref(),
        scale,
        &mut counter,
        &mut map,
        offset,
    );
    map
}

fn recurse_draw(
    img: &mut RgbaImage,
    node: &AccessibilityNode,
    font: Option<&FontRef>,
    scale: PxScale,
    counter: &mut u32,
    map: &mut HashMap<u32, Rect>,
    offset: (i32, i32),
) {
    // 1. Filtering Heuristics (Noise Reduction)

    // Skip if invisible
    if !node.is_visible {
        return;
    }

    // Dimensions in screen space
    let w = node.rect.width;
    let h = node.rect.height;

    // Filter tiny elements (e.g. tracking pixels, invisible spacers)
    // Minimum 10x10 px for interactivity
    if w < 10 || h < 10 {
        // Still recurse children, as a small container might hold valid buttons
        for child in &node.children {
            recurse_draw(img, child, font, scale, counter, map, offset);
        }
        return;
    }

    // Filter giant full-screen containers that obscure context
    // If element covers > 90% of screen, it's likely a background
    let img_w = img.width() as i32;
    let img_h = img.height() as i32;
    let area = w * h;
    let screen_area = img_w * img_h;
    if area > (screen_area * 9 / 10) && node.children.len() > 0 {
        // Just recurse, don't mark the background
        for child in &node.children {
            recurse_draw(img, child, font, scale, counter, map, offset);
        }
        return;
    }

    // Apply Offset to convert Global OS coords -> Image Local coords
    let local_x = node.rect.x - offset.0;
    let local_y = node.rect.y - offset.1;

    // Check bounds relative to the image
    let is_in_bounds = local_x + w > 0 && local_y + h > 0 && local_x < img_w && local_y < img_h;

    if !is_in_bounds {
        return;
    }

    // 2. Relevance Check
    // We only tag "Interactive" or "Content" nodes
    let is_container = node.role == "group" || node.role == "generic" || node.role == "div";
    let has_direct_content = node.name.is_some() || node.value.is_some();
    let is_interactive = node.is_interactive();

    let should_tag = is_interactive
        || (is_container && has_direct_content)
        || node.role == "heading"
        || node.role == "link";

    if should_tag {
        let id = *counter;

        // IMPORTANT: Map ID to GLOBAL rect for click injection
        map.insert(id, node.rect);

        // [NEW] Visual State Indication
        let is_disabled = node.attributes.contains_key("disabled");

        // Draw Bounding Box
        // High-contrast Neon Green for active, Grey for disabled
        let border_color = if is_disabled {
            Rgba([128, 128, 128, 255])
        } else {
            Rgba([0, 255, 0, 255])
        };

        let rect_x = local_x.max(0) as u32;
        let rect_y = local_y.max(0) as u32;
        let rect_w = (w.min(img_w - local_x)).max(1) as u32;
        let rect_h = (h.min(img_h - local_y)).max(1) as u32;

        let rect = ImageRect::at(rect_x as i32, rect_y as i32).of_size(rect_w, rect_h);
        draw_hollow_rect_mut(img, rect, border_color);

        // 3. Draw ID Label
        if let Some(f) = font {
            let label = format!("{}", id);

            // Calculate label dimensions
            let v_metrics = f.as_scaled(scale).ascent();
            let text_w = (label.len() as u32) * 14 + 8; // Approx width
            let text_h = (v_metrics + 12.0) as u32;

            // Intelligent Label Positioning:
            // Prefer Top-Left Corner. If too small, go Outside-Top-Left.
            // If at edge of screen, clamp.

            let mut tag_x = rect_x as i32;
            let mut tag_y = rect_y as i32;

            // Clamp to image
            tag_x = tag_x.clamp(0, img_w - text_w as i32);
            tag_y = tag_y.clamp(0, img_h - text_h as i32);

            // Draw Label Background (Black Box)
            // Use Dark Grey background for disabled labels
            let bg_color = if is_disabled {
                Rgba([60, 60, 60, 255])
            } else {
                Rgba([0, 0, 0, 255])
            };

            let tag_rect = ImageRect::at(tag_x, tag_y).of_size(text_w, text_h);
            draw_filled_rect_mut(img, tag_rect, bg_color);

            // Draw ID Text (White)
            let text_color = Rgba([255, 255, 255, 255]);
            // [FIX] Removed dereference `*f`
            draw_text_mut(img, text_color, tag_x + 4, tag_y + 4, scale, f, &label);
        }

        *counter += 1;
    }

    // Recurse
    for child in &node.children {
        recurse_draw(img, child, font, scale, counter, map, offset);
    }
}

fn has_meaningful_semantic_content(node: &AccessibilityNode) -> bool {
    let has_text = |v: Option<&str>| v.map(|s| !s.trim().is_empty()).unwrap_or(false);
    if has_text(node.name.as_deref()) || has_text(node.value.as_deref()) {
        return true;
    }

    for key in [
        "aria-label",
        "label",
        "title",
        "description",
        "placeholder",
        "semantic_id",
    ] {
        if node
            .attributes
            .get(key)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
        {
            return true;
        }
    }

    false
}

fn axis_partition(start: i32, len: i32, parts: i32, idx: i32) -> (i32, i32) {
    let safe_len = len.max(0);
    let safe_parts = parts.max(1);
    let base = safe_len / safe_parts;
    let rem = safe_len % safe_parts;
    let offset = (idx * base) + idx.min(rem);
    let size = base + if idx < rem { 1 } else { 0 };
    (start + offset, size.max(0))
}

fn should_inject_synthetic_grid(
    node: &AccessibilityNode,
    area_ratio: f64,
    phys_w: f64,
    phys_h: f64,
) -> bool {
    if !node.children.is_empty() || node.is_interactive() {
        return false;
    }
    if area_ratio < SYNTHETIC_GRID_AREA_THRESHOLD
        || phys_w < SYNTHETIC_GRID_MIN_DIMENSION
        || phys_h < SYNTHETIC_GRID_MIN_DIMENSION
    {
        return false;
    }
    if has_meaningful_semantic_content(node) {
        return false;
    }
    if node
        .attributes
        .get("som.synthetic")
        .map(|v| v == "grid_parent" || v == "grid_cell")
        .unwrap_or(false)
    {
        return false;
    }

    let role_lc = node.role.to_ascii_lowercase();
    matches!(
        role_lc.as_str(),
        "group"
            | "generic"
            | "div"
            | "pane"
            | "canvas"
            | "document"
            | "web_area"
            | "region"
            | "image"
            | "window"
            | "application"
    )
}

fn choose_grid_dimension(area_ratio: f64, phys_w: f64, phys_h: f64) -> i32 {
    if area_ratio >= 0.45 || phys_w >= 1200.0 || phys_h >= 900.0 {
        4
    } else {
        3
    }
}

fn inject_synthetic_grid_children(node: &mut AccessibilityNode, dimension: i32) {
    let dim = dimension.max(2);
    let parent_id = node.id.clone();
    let mut children = Vec::new();

    for row in 0..dim {
        for col in 0..dim {
            let (x, w) = axis_partition(node.rect.x, node.rect.width, dim, col);
            let (y, h) = axis_partition(node.rect.y, node.rect.height, dim, row);
            if w <= 0 || h <= 0 {
                continue;
            }

            let label = format!("{}{}", (b'A' + row as u8) as char, col + 1);
            let mut attributes = HashMap::new();
            attributes.insert("som.synthetic".to_string(), "grid_cell".to_string());
            attributes.insert("som.grid_label".to_string(), label.clone());
            attributes.insert("som.grid_dim".to_string(), format!("{}x{}", dim, dim));
            attributes.insert("som.parent".to_string(), parent_id.clone());
            attributes.insert(
                "semantic_aliases".to_string(),
                format!(
                    "grid {},{} row {} col {}",
                    label.to_ascii_lowercase(),
                    label,
                    row + 1,
                    col + 1
                ),
            );

            children.push(AccessibilityNode {
                id: format!("som_grid_{}_{}", parent_id, label.to_ascii_lowercase()),
                role: "cell".to_string(),
                name: Some(format!("Grid {}", label)),
                value: Some(label),
                rect: Rect {
                    x,
                    y,
                    width: w,
                    height: h,
                },
                children: vec![],
                is_visible: true,
                attributes,
                som_id: None,
            });
        }
    }

    if !children.is_empty() {
        node.attributes
            .insert("som.synthetic".to_string(), "grid_parent".to_string());
        node.attributes
            .insert("som.grid_dim".to_string(), format!("{}x{}", dim, dim));
        node.children = children;
    }
}

// -----------------------------------------------------------------------------
// [NEW] Unified Grounding Pipeline (Visual-Semantic ID Injection)
// -----------------------------------------------------------------------------

/// PASS 1: Traverses the tree and assigns `som_id` to interactive nodes.
/// Returns the mapping of ID -> Rect for the click handler.
pub fn assign_som_ids(
    node: &mut AccessibilityNode,
    transform: &DisplayTransform,
    counter: &mut u32,
    map: &mut HashMap<u32, Rect>,
) {
    if !node.is_visible {
        return;
    }

    let logical_rect = GeoRect::from_accessibility_rect(node.rect, CoordinateSpace::ScreenLogical);
    let physical_rect = transform.logical_rect_to_physical(logical_rect);
    let local_x = physical_rect.x;
    let local_y = physical_rect.y;
    let phys_w = physical_rect.width.max(0.0);
    let phys_h = physical_rect.height.max(0.0);

    // Filter tiny elements and full-screen backgrounds
    let is_tiny = phys_w < 10.0 || phys_h < 10.0;
    let area = (phys_w * phys_h) as u64;
    let screen_area = (transform.image_width as u64) * (transform.image_height as u64);
    let area_ratio = if screen_area == 0 {
        0.0
    } else {
        area as f64 / screen_area as f64
    };

    // [FIX] Stricter background filtering.
    // If it's > 90% of screen AND has children, it's a container/background. Don't tag it.
    let is_background = area > (screen_area * 9 / 10) && !node.children.is_empty();

    // Also ignore "root" role explicitly if it passed size check
    let is_root = node.role == "root" || node.role == "application";

    // Bounds check
    let is_in_bounds = local_x + phys_w > 0.0
        && local_y + phys_h > 0.0
        && local_x < transform.image_width as f64
        && local_y < transform.image_height as f64;

    let is_container = matches!(
        node.role.as_str(),
        "group" | "generic" | "div" | "cell" | "list"
    );
    let has_direct_content = node.name.is_some() || node.value.is_some();
    let is_interactive = node.is_interactive();
    let explicit_interesting =
        matches!(node.role.as_str(), "heading" | "link" | "tab" | "menuitem");

    let should_tag = is_in_bounds
        && !is_tiny
        && !is_background
        && !is_root
        && (is_interactive || (is_container && has_direct_content) || explicit_interesting);

    if should_tag {
        let id = *counter;
        node.som_id = Some(id);
        map.insert(id, node.rect); // Global rect for clicking
        *counter += 1;
    }

    if should_inject_synthetic_grid(node, area_ratio, phys_w, phys_h) {
        let dimension = choose_grid_dimension(area_ratio, phys_w, phys_h);
        inject_synthetic_grid_children(node, dimension);
    }

    for child in &mut node.children {
        assign_som_ids(child, transform, counter, map);
    }
}

/// PASS 2: Draws the overlay based on the IDs assigned in Pass 1.
pub fn draw_som_overlay(
    img: &mut RgbaImage,
    node: &AccessibilityNode,
    transform: &DisplayTransform,
) {
    if !node.is_visible {
        return;
    }

    // Only draw if an ID was assigned in Pass 1
    if let Some(id) = node.som_id {
        let font = load_system_font();
        let scale = PxScale { x: 24.0, y: 24.0 };

        let logical_rect =
            GeoRect::from_accessibility_rect(node.rect, CoordinateSpace::ScreenLogical);
        let physical_rect = transform.logical_rect_to_physical(logical_rect);

        let img_w = img.width() as i32;
        let img_h = img.height() as i32;

        let rect_x = physical_rect.x.floor() as i32;
        let rect_y = physical_rect.y.floor() as i32;
        let rect_w = physical_rect.width.ceil().max(1.0) as i32;
        let rect_h = physical_rect.height.ceil().max(1.0) as i32;

        let clipped_x = rect_x.clamp(0, img_w.saturating_sub(1));
        let clipped_y = rect_y.clamp(0, img_h.saturating_sub(1));
        let clipped_w = (rect_w.min(img_w - clipped_x)).max(1) as u32;
        let clipped_h = (rect_h.min(img_h - clipped_y)).max(1) as u32;

        let is_disabled = node.attributes.contains_key("disabled");
        let border_color = if is_disabled {
            Rgba([128, 128, 128, 255])
        } else {
            Rgba([0, 255, 0, 255])
        };

        let rect = ImageRect::at(clipped_x, clipped_y).of_size(clipped_w, clipped_h);
        draw_hollow_rect_mut(img, rect, border_color);

        // Truth Probe A:
        // Red box = raw OS coords interpreted directly as image coords.
        // Green box = transformed coords used for drawing/injection.
        let debug_probe = std::env::var("IOI_TRUTH_PROBE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if debug_probe && !TRUTH_PROBE_DRAWN.swap(true, Ordering::SeqCst) {
            let raw_x = node.rect.x;
            let raw_y = node.rect.y;
            let raw_w = node.rect.width.max(1) as u32;
            let raw_h = node.rect.height.max(1) as u32;
            if raw_x < img_w
                && raw_y < img_h
                && raw_x + (raw_w as i32) > 0
                && raw_y + (raw_h as i32) > 0
            {
                let probe_x = raw_x.clamp(0, img_w.saturating_sub(1));
                let probe_y = raw_y.clamp(0, img_h.saturating_sub(1));
                let probe_w = ((raw_w as i32).min(img_w - probe_x)).max(1) as u32;
                let probe_h = ((raw_h as i32).min(img_h - probe_y)).max(1) as u32;
                let probe_rect = ImageRect::at(probe_x, probe_y).of_size(probe_w, probe_h);
                draw_hollow_rect_mut(img, probe_rect, Rgba([255, 0, 0, 255]));
            }
            draw_hollow_rect_mut(img, rect, Rgba([0, 255, 0, 255]));
        }

        if let Some(f) = font.as_ref() {
            let label = format!("{}", id);
            let v_metrics = f.as_scaled(scale).ascent();
            let text_w = (label.len() as u32) * 14 + 8;
            let text_h = (v_metrics + 12.0) as u32;

            // Draw tag inside top-left, clamped to image
            let max_tag_x = (img_w - text_w as i32).max(0);
            let max_tag_y = (img_h - text_h as i32).max(0);
            let tag_x = clipped_x.clamp(0, max_tag_x);
            let tag_y = clipped_y.clamp(0, max_tag_y);

            let bg_color = if is_disabled {
                Rgba([60, 60, 60, 255])
            } else {
                Rgba([0, 0, 0, 255])
            };
            let tag_rect = ImageRect::at(tag_x, tag_y).of_size(text_w, text_h);
            draw_filled_rect_mut(img, tag_rect, bg_color);

            let text_color = Rgba([255, 255, 255, 255]);
            draw_text_mut(img, text_color, tag_x + 4, tag_y + 4, scale, f, &label);
        }
    }

    for child in &node.children {
        draw_som_overlay(img, child, transform);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui::geometry::{CoordinateSpace, Point};

    fn test_transform(w: u32, h: u32) -> DisplayTransform {
        DisplayTransform::new(
            1.0,
            Point::new(0.0, 0.0, CoordinateSpace::ScreenLogical),
            Point::new(0.0, 0.0, CoordinateSpace::ImagePhysical),
            w,
            h,
        )
    }

    fn make_leaf(rect: Rect, role: &str) -> AccessibilityNode {
        AccessibilityNode {
            id: "blind_leaf".to_string(),
            role: role.to_string(),
            name: None,
            value: None,
            rect,
            children: vec![],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        }
    }

    #[test]
    fn dynamic_grid_injected_for_large_empty_leaf() {
        let mut root = make_leaf(
            Rect {
                x: 0,
                y: 0,
                width: 1000,
                height: 800,
            },
            "web_area",
        );
        let transform = test_transform(1000, 800);
        let mut counter = 1;
        let mut map = HashMap::new();

        assign_som_ids(&mut root, &transform, &mut counter, &mut map);

        assert_eq!(
            root.attributes.get("som.synthetic"),
            Some(&"grid_parent".to_string())
        );
        assert_eq!(root.children.len(), 16);
        assert_eq!(map.len(), 16);
        assert!(root.children.iter().all(|child| child.som_id.is_some()));
    }

    #[test]
    fn dynamic_grid_not_injected_when_node_has_content() {
        let mut root = make_leaf(
            Rect {
                x: 0,
                y: 0,
                width: 900,
                height: 700,
            },
            "web_area",
        );
        root.name = Some("Page Content".to_string());

        let transform = test_transform(900, 700);
        let mut counter = 1;
        let mut map = HashMap::new();
        assign_som_ids(&mut root, &transform, &mut counter, &mut map);

        assert!(root.children.is_empty());
        assert!(map.is_empty());
    }

    #[test]
    fn dynamic_grid_not_injected_for_small_leaf() {
        let mut root = make_leaf(
            Rect {
                x: 0,
                y: 0,
                width: 220,
                height: 140,
            },
            "canvas",
        );
        let transform = test_transform(1000, 800);
        let mut counter = 1;
        let mut map = HashMap::new();
        assign_som_ids(&mut root, &transform, &mut counter, &mut map);

        assert!(root.children.is_empty());
        assert!(map.is_empty());
    }
}
