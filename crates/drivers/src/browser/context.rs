// Path: crates/drivers/src/browser/context.rs

use crate::gui::geometry::Rect as GeoRect;

#[derive(Debug, Clone, Copy)]
pub struct BrowserContentFrame {
    pub rect: GeoRect,
    pub chrome_top: f64,
}
