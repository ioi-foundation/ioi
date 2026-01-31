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
    root: &AccessibilityNode
) -> HashMap<u32, Rect> {
    let font = get_font();
    // Scale for ID text (20px)
    let scale = PxScale { x: 20.0, y: 20.0 };

    // We start indexing from 1 to keep IDs clean for the LLM
    let mut counter = 1;
    let mut map = HashMap::new();

    recurse_draw(screenshot, root, font, scale, &mut counter, &mut map);
    map
}

fn recurse_draw(
    img: &mut RgbaImage, 
    node: &AccessibilityNode, 
    font: Option<&FontRef>, 
    scale: PxScale,
    counter: &mut u32,
    map: &mut HashMap<u32, Rect>
) {
    // Only draw if interactive, visible, and has dimension
    if node.is_interactive() && node.is_visible && node.rect.width > 0 && node.rect.height > 0 {
        let id = *counter;
        map.insert(id, node.rect);

        let x = node.rect.x as i32;
        let y = node.rect.y as i32;
        let w = node.rect.width as u32;
        let h = node.rect.height as u32;

        let rect = ImageRect::at(x, y).of_size(w, h);
        
        // High-contrast Neon Green for visibility
        let border_color = Rgba([0, 255, 0, 255]);
        
        // Draw Box
        draw_hollow_rect_mut(img, rect, border_color);
        
        // Thicken border (inner stroke)
        if w > 2 && h > 2 {
             let inner_rect = ImageRect::at(x + 1, y + 1).of_size(w - 2, h - 2);
             draw_hollow_rect_mut(img, inner_rect, border_color);
        }

        // Draw Label Tag
        if let Some(f) = font {
            let label = format!("{}", id);
            let text_w = (label.len() as u32) * 12 + 4; // Approx width + padding
            let text_h = 24;
            
            // Position label: prefer top-left, but flip if near edge
            let tag_x = x.max(0);
            let tag_y = (y - (text_h as i32)).max(0);
            
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
        recurse_draw(img, child, font, scale, counter, map);
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
            id: "test".into(), role: "button".into(), name: None, value: None, children: vec![]
        };
        
        let map = overlay_accessibility_tree(&mut img, &node);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&1));
        
        let rect = map.get(&1).unwrap();
        assert_eq!(rect.x, 10);
    }
}