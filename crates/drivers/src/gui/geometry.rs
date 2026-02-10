// Path: crates/drivers/src/gui/geometry.rs

use super::accessibility::Rect as AccessibilityRect;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoordinateSpace {
    /// Operating-system logical points (DPI-aware).
    /// Origin: top-left of primary display.
    ScreenLogical,
    /// Physical pixels in an image/screenshot buffer.
    /// Origin: top-left of the captured buffer.
    ImagePhysical,
    /// Window-local logical points.
    /// Origin: top-left of the window client area.
    WindowLogical,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub x: f64,
    pub y: f64,
    pub space: CoordinateSpace,
}

impl Point {
    pub fn new(x: f64, y: f64, space: CoordinateSpace) -> Self {
        Self { x, y, space }
    }

    /// Panics if spaces do not match.
    pub fn add(self, other: Point) -> Point {
        assert_eq!(self.space, other.space, "Coordinate space mismatch");
        Point::new(self.x + other.x, self.y + other.y, self.space)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub space: CoordinateSpace,
}

impl Rect {
    pub fn new(x: f64, y: f64, width: f64, height: f64, space: CoordinateSpace) -> Self {
        Self {
            x,
            y,
            width,
            height,
            space,
        }
    }

    pub fn top_left(self) -> Point {
        Point::new(self.x, self.y, self.space)
    }

    pub fn center(self) -> Point {
        Point::new(
            self.x + (self.width / 2.0),
            self.y + (self.height / 2.0),
            self.space,
        )
    }

    pub fn from_accessibility_rect(rect: AccessibilityRect, space: CoordinateSpace) -> Self {
        Self::new(
            rect.x as f64,
            rect.y as f64,
            rect.width as f64,
            rect.height as f64,
            space,
        )
    }
}

/// Snapshot of display state required for deterministic coordinate conversion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisplayTransform {
    /// Logical * scale_factor = physical.
    pub scale_factor: f64,
    /// Window origin in screen logical points.
    pub window_origin: Point,
    /// Capture origin relative to screen in physical pixels.
    pub capture_origin: Point,
    /// Physical dimensions of the image buffer being grounded.
    pub image_width: u32,
    pub image_height: u32,
}

impl DisplayTransform {
    pub fn new(
        scale_factor: f64,
        window_origin: Point,
        capture_origin: Point,
        image_width: u32,
        image_height: u32,
    ) -> Self {
        assert_eq!(window_origin.space, CoordinateSpace::ScreenLogical);
        assert_eq!(capture_origin.space, CoordinateSpace::ImagePhysical);
        let safe_scale = if scale_factor <= 0.0 {
            1.0
        } else {
            scale_factor
        };
        Self {
            scale_factor: safe_scale,
            window_origin,
            capture_origin,
            image_width,
            image_height,
        }
    }

    pub fn logical_to_physical(&self, pt: Point) -> Point {
        assert_eq!(pt.space, CoordinateSpace::ScreenLogical);
        Point::new(
            (pt.x * self.scale_factor) - self.capture_origin.x,
            (pt.y * self.scale_factor) - self.capture_origin.y,
            CoordinateSpace::ImagePhysical,
        )
    }

    pub fn physical_to_logical(&self, pt: Point) -> Point {
        assert_eq!(pt.space, CoordinateSpace::ImagePhysical);
        Point::new(
            (pt.x + self.capture_origin.x) / self.scale_factor,
            (pt.y + self.capture_origin.y) / self.scale_factor,
            CoordinateSpace::ScreenLogical,
        )
    }

    pub fn window_to_screen(&self, pt: Point) -> Point {
        assert_eq!(pt.space, CoordinateSpace::WindowLogical);
        Point::new(
            pt.x + self.window_origin.x,
            pt.y + self.window_origin.y,
            CoordinateSpace::ScreenLogical,
        )
    }

    pub fn screen_to_window(&self, pt: Point) -> Point {
        assert_eq!(pt.space, CoordinateSpace::ScreenLogical);
        Point::new(
            pt.x - self.window_origin.x,
            pt.y - self.window_origin.y,
            CoordinateSpace::WindowLogical,
        )
    }

    pub fn logical_rect_to_physical(&self, rect: Rect) -> Rect {
        assert_eq!(rect.space, CoordinateSpace::ScreenLogical);
        let top_left = self.logical_to_physical(rect.top_left());
        Rect::new(
            top_left.x,
            top_left.y,
            rect.width * self.scale_factor,
            rect.height * self.scale_factor,
            CoordinateSpace::ImagePhysical,
        )
    }

    /// Converts normalized [0.0, 1.0] image coordinates into screen logical points.
    pub fn normalized_to_screen(&self, nx: f64, ny: f64) -> Point {
        let max_x = self.image_width.saturating_sub(1) as f64;
        let max_y = self.image_height.saturating_sub(1) as f64;
        let px = nx.clamp(0.0, 1.0) * max_x;
        let py = ny.clamp(0.0, 1.0) * max_y;
        self.physical_to_logical(Point::new(px, py, CoordinateSpace::ImagePhysical))
    }
}
