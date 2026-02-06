// Path: crates/drivers/src/gui/som.rs

//! "Set-of-Marks" (SoM) Visual Grounding.
//! 
//! Overlays the accessibility tree onto the raw screenshot, tagging every
//! interactive element with a unique numeric ID and bounding box.
//! This allows VLM agents to "see" the UI structure and click reliably.

use image::{Rgba, RgbaImage};
use imageproc::drawing::{draw_hollow_rect_mut, draw_text_mut, draw_filled_rect_mut};
use imageproc::rect::Rect as ImageRect;
use ab_glyph::{FontRef, PxScale};
use super::accessibility::{AccessibilityNode, Rect};
use std::sync::OnceLock;
use std::collections::HashMap;

// Embedded minimal font. In a real build, we'd include_bytes a .ttf.
// For this MVP, we try to load a system font or fail gracefully (boxes only).
static FONT: OnceLock<Option<FontRef<'static>>> = OnceLock::new();

fn get_font() -> Option<&'static FontRef<'static>> {
    FONT.get_or_init(|| {
        // [TODO] Embed a lightweight font like DejaVuSans.ttf
        // For now, return None. The drawing logic handles missing font by drawing only boxes.
        None 
    }).as_ref()
}

/// Overlays bounding boxes and IDs for all interactive elements in the tree onto the image.
/// This modifies the `screenshot` in-place.
/// Returns the mapping of ID -> Rect for click resolution.
pub fn overlay_accessibility_tree(
    screenshot: &mut RgbaImage, 
    root: &AccessibilityNode,
    start_id: Option<u32>, // Allow chaining overlays with offset IDs
    // [NEW] Global offset to subtract from node coordinates.
    // Use (0,0) for full-screen screenshots.
    // Use (window_x, window_y) for window-local screenshots (Level 2).
    offset: (i32, i32),
) -> HashMap<u32, Rect> {
    let font = get_font();
    // Scale for ID text (20px)
    let scale = PxScale { x: 20.0, y: 20.0 };

    // We start indexing from 1 to keep IDs clean for the LLM
    let mut counter = start_id.unwrap_or(1);
    let mut map = HashMap::new();

    recurse_draw(screenshot, root, font, scale, &mut counter, &mut map, offset);
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
    // [IMPROVED] Filtering Heuristics to reduce clutter (UI-TARS Parity)
    // 1. Skip non-interactive groups/generics unless they have direct text content
    // 2. Skip tiny elements (< 5x5 px)
    // 3. Skip extremely large elements (likely background containers covering whole screen)
    
    let is_container = node.role == "group" || node.role == "generic" || node.role == "div";
    let has_direct_content = node.name.is_some() || node.value.is_some();
    let is_meaningful = node.is_interactive() || (is_container && has_direct_content);
    
    // Apply Offset to convert Global OS coords -> Image Local coords
    let local_x = node.rect.x - offset.0;
    let local_y = node.rect.y - offset.1;
    let w = node.rect.width as u32;
    let h = node.rect.height as u32;

    // Check bounds relative to the image
    let is_in_bounds = local_x >= 0 && local_y >= 0 
        && (local_x as u32 + w) <= img.width() 
        && (local_y as u32 + h) <= img.height();

    let is_visible_size = w > 5 && h > 5 && (w * h) < (img.width() * img.height());

    if is_meaningful && node.is_visible && is_visible_size && is_in_bounds {
        let id = *counter;
        
        // IMPORTANT: We map the ID to the ORIGINAL global rect, not the local one.
        // The ToolExecutor uses global coordinates for injection via Enigo.
        map.insert(id, node.rect);

        let rect = ImageRect::at(local_x, local_y).of_size(w, h);
        
        // High-contrast Neon Green for visibility
        let border_color = Rgba([0, 255, 0, 255]);
        
        // Draw Box
        draw_hollow_rect_mut(img, rect, border_color);
        
        // Thicken border (inner stroke)
        if w > 2 && h > 2 {
             let inner_rect = ImageRect::at(local_x + 1, local_y + 1).of_size(w - 2, h - 2);
             draw_hollow_rect_mut(img, inner_rect, border_color);
        }

        // Draw Label Tag
        if let Some(f) = font {
            let label = format!("{}", id);
            let text_w = (label.len() as u32) * 12 + 4; // Approx width + padding
            let text_h = 24;
            
            // [IMPROVED] Intelligent Label Positioning
            // Prefer top-left outside the box to avoid obscuring text.
            // If top is off-screen, move inside or below.
            
            // Try Top-Left (Outside)
            let mut tag_x = local_x.max(0);
            let mut tag_y = local_y - (text_h as i32);
            
            // If clipped top, move inside
            if tag_y < 0 {
                tag_y = local_y;
            }
            
            // If box is tiny, ensure tag is visible (center overlay or side)
            if h < (text_h as u32) {
                // If box is small, draw tag to the right if space permits
                if (local_x + (w as i32) + (text_w as i32)) < (img.width() as i32) {
                    tag_x = local_x + (w as i32);
                    tag_y = local_y;
                }
            }

            let tag_bg = ImageRect::at(tag_x, tag_y).of_size(text_w, text_h);
            draw_filled_rect_mut(img, tag_bg, border_color);
            
            // Draw Text (Black on Green)
            draw_text_mut(
                img, 
                Rgba([0, 0, 0, 255]), 
                tag_x + 2, 
                tag_y + 2, 
                scale, 
                f, 
                &label
            );
        }
        
        *counter += 1;
    }

    for child in &node.children {
        recurse_draw(img, child, font, scale, counter, map, offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_som_cache_logic() {
        let mut img = RgbaImage::new(100, 100);
        // Mock node at 10,10 size 20x20
        let node = AccessibilityNode {
            rect: Rect { x: 10, y: 10, width: 20, height: 20 },
            is_visible: true,
            // ... (fill other dummy fields)
            id: "test".into(), role: "button".into(), name: None, value: None, children: vec![], attributes: HashMap::new()
        };
        
        // Test with no offset
        let map = overlay_accessibility_tree(&mut img, &node, None, (0, 0));
        assert_eq!(map.len(), 1);
        let rect = map.get(&1).unwrap();
        assert_eq!(rect.x, 10);
        
        // Test with offset (simulating tab capture)
        // If window is at 5,5, local coords should be 5,5
        let map2 = overlay_accessibility_tree(&mut img, &node, None, (5, 5));
        // The MAP should still store the GLOBAL coordinate (10,10) for clicking
        let rect2 = map2.get(&1).unwrap();
        assert_eq!(rect2.x, 10); 
    }
}