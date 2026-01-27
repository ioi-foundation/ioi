// Path: crates/drivers/src/gui/som.rs

//! "Set-of-Marks" (SoM) Visual Grounding.
//!
//! This module overlays the semantic accessibility tree onto the raw visual buffer (screenshot).
//! By drawing bounding boxes and unique IDs directly onto the pixels fed to the VLM,
//! we bridge the gap between the "Visual" and "Structural" representations of the GUI.
//! This technique is essential for high-fidelity agent control (e.g., Claude Computer Use).

use image::{Rgba, RgbaImage};
use imageproc::drawing::{draw_hollow_rect_mut, draw_text_mut};
use imageproc::rect::Rect as ImageRect;
use rusttype::{Font, Scale};
use super::accessibility::AccessibilityNode;

/// Overlays bounding boxes and IDs for all interactive elements in the tree onto the image.
/// This modifies the `screenshot` in-place.
pub fn overlay_accessibility_tree(screenshot: &mut RgbaImage, root: &AccessibilityNode) {
    // Load font for ID labels.
    // Ensure "DejaVuSans.ttf" is available in your crate's assets or embedded via include_bytes.
    // For this implementation, we assume it's bundled in the binary.
    let font_data = include_bytes!("../../../fonts/DejaVuSans.ttf") as &[u8];
    let font = Font::try_from_bytes(font_data).expect("Error loading font");
    
    // Scale for ID text
    let scale = Scale { x: 20.0, y: 20.0 };

    recurse_draw(screenshot, root, &font, scale);
}

fn recurse_draw(img: &mut RgbaImage, node: &AccessibilityNode, font: &Font, scale: Scale) {
    // Only draw marks for elements that are interactive and visible.
    // This reduces visual clutter for the VLM (improving attention).
    if node.is_interactive() && node.is_visible {
        let rect = ImageRect::at(node.rect.x, node.rect.y)
            .of_size(node.rect.width as u32, node.rect.height as u32);
        
        // 1. Draw Bounding Box (Green)
        // Green is often used in SoM datasets to denote actionable zones.
        // Line width of 2px ensures visibility after compression.
        let color = Rgba([0, 255, 0, 255]);
        draw_hollow_rect_mut(img, rect, color);
        // Draw a second rect 1px smaller for thickness simulation (imageproc hollow rect is 1px)
        if node.rect.width > 2 && node.rect.height > 2 {
             let inner_rect = ImageRect::at(node.rect.x + 1, node.rect.y + 1)
                .of_size((node.rect.width - 2) as u32, (node.rect.height - 2) as u32);
             draw_hollow_rect_mut(img, inner_rect, color);
        }
        
        // 2. Draw ID Label
        // We draw the ID in the top-left corner of the box.
        // A background for text might be needed for contrast, but raw text is usually sufficient for GPT-4o/Claude.
        draw_text_mut(
            img, 
            color, 
            node.rect.x, 
            node.rect.y.saturating_sub(20), // Draw label *above* the box if possible to avoid obscuring content
            scale, 
            font, 
            &node.id
        );
    }

    // Recursively process children
    for child in &node.children {
        recurse_draw(img, child, font, scale);
    }
}