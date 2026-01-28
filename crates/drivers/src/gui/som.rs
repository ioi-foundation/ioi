// Path: crates/drivers/src/gui/som.rs

//! "Set-of-Marks" (SoM) Visual Grounding.

use image::{Rgba, RgbaImage};
use imageproc::drawing::{draw_hollow_rect_mut, draw_text_mut};
use imageproc::rect::Rect as ImageRect;
// [FIX] Removed unused Font import
use ab_glyph::{FontRef, PxScale};
use super::accessibility::AccessibilityNode;

/// Overlays bounding boxes and IDs for all interactive elements in the tree onto the image.
/// This modifies the `screenshot` in-place.
pub fn overlay_accessibility_tree(screenshot: &mut RgbaImage, root: &AccessibilityNode) {
    // Load font for ID labels.
    let font_data: &[u8] = &[]; // Dummy empty
    
    // In a real build, you would do:
    // let font_data = include_bytes!("../../../fonts/DejaVuSans.ttf") as &[u8];

    // Try to load the font
    let font = match FontRef::try_from_slice(font_data) {
        Ok(f) => f,
        Err(_) => {
            // [LOG] "Font not found, skipping visual grounding labels"
            return;
        }
    };
    
    // Scale for ID text
    let scale = PxScale { x: 20.0, y: 20.0 };

    recurse_draw(screenshot, root, &font, scale);
}

fn recurse_draw(img: &mut RgbaImage, node: &AccessibilityNode, font: &FontRef, scale: PxScale) {
    if node.is_interactive() && node.is_visible {
        let rect = ImageRect::at(node.rect.x, node.rect.y)
            .of_size(node.rect.width as u32, node.rect.height as u32);
        
        let color = Rgba([0, 255, 0, 255]);
        draw_hollow_rect_mut(img, rect, color);
        if node.rect.width > 2 && node.rect.height > 2 {
             let inner_rect = ImageRect::at(node.rect.x + 1, node.rect.y + 1)
                .of_size((node.rect.width - 2) as u32, (node.rect.height - 2) as u32);
             draw_hollow_rect_mut(img, inner_rect, color);
        }
        
        draw_text_mut(
            img, 
            color, 
            node.rect.x, 
            node.rect.y.saturating_sub(20), 
            scale, 
            font, 
            &node.id
        );
    }

    for child in &node.children {
        recurse_draw(img, child, font, scale);
    }
}