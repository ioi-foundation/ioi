use super::BrowserDriver;
use super::{analyze_canvas_shape_image, BrowserCanvasShapeSummary};
use image::{Rgba, RgbaImage};
use imageproc::drawing::draw_line_segment_mut;
use std::f32::consts::PI;

#[test]
fn focus_first_selector_script_uses_deep_visibility_checks() {
    let script = BrowserDriver::focus_first_selector_script(&["input[name='q']"])
        .expect("selector focus script should serialize selector list");
    assert!(script.contains("deepQuerySelector(selector)"));
    assert!(script.contains("isElementVisibleCandidate(el)"));
    assert!(!script.contains("window.getComputedStyle(el)"));
}

#[test]
fn focus_first_selector_script_returns_matched_selector_when_focused() {
    let script = BrowserDriver::focus_first_selector_script(&["input[type='search']"])
        .expect("selector focus script should serialize selector list");
    assert!(script.contains("if (deepActiveElement() === el) {"));
    assert!(script.contains("return selector;"));
}

#[test]
fn deep_dom_helpers_support_selector_text_collection() {
    let helpers = BrowserDriver::deep_dom_helper_js();
    assert!(helpers.contains("enqueueFrameDocument(node, queue)"));
    assert!(helpers.contains("isElementVisibleCandidate(candidate)"));
}

#[test]
fn selector_elements_script_collects_attributes_and_top_window_centers() {
    let script = BrowserDriver::selector_elements_script("svg > *")
        .expect("selector elements script should serialize selector");
    assert!(script.contains("candidate.getAttributeNames"));
    assert!(script.contains("elementCenterInTopWindow(candidate)"));
    assert!(script.contains("attributes.value = String(candidate.value);"));
}

#[test]
fn selector_canvas_raster_script_uses_deep_selector_and_png_readback() {
    let script = BrowserDriver::selector_canvas_raster_script("#c")
        .expect("selector canvas script should serialize selector");
    assert!(script.contains("const target = deepQuerySelector(selector);"));
    assert!(script.contains("canvas.toDataURL(\"image/png\")"));
    assert!(script.contains("selector did not resolve to a readable canvas"));
}

#[test]
fn select_text_script_uses_deep_query_and_selection_range_logic() {
    let script = BrowserDriver::select_text_script(Some("#editor"), Some(0), Some(8))
        .expect("select text script should serialize");
    assert!(script
        .contains("const target = selector ? deepQuerySelector(selector) : deepActiveElement();"));
    assert!(script.contains("target.setSelectionRange(start, end, \"forward\")"));
    assert!(script.contains("selection.addRange(range)"));
}

#[test]
fn read_selection_script_checks_active_editable_and_nested_documents() {
    let script = BrowserDriver::read_selection_script();
    assert!(script.contains("snapshotEditableSelection(deepActiveElement())"));
    assert!(script.contains("enqueueFrameDocument(node, queue)"));
    assert!(script.contains("selection.toString()"));
}

#[test]
fn canvas_shape_analysis_estimates_regular_polygon_sides() {
    for sides in 3..=7 {
        for rotation_deg in [0.0_f32, 17.0, 33.0, 71.0] {
            let image = render_regular_polygon(sides, rotation_deg);
            let summary = analyze_canvas_shape_image(
                &image,
                BrowserCanvasShapeSummary {
                    found: true,
                    readable: true,
                    target_kind: "canvas".to_string(),
                    width: image.width(),
                    height: image.height(),
                    dark_pixel_count: 0,
                    component_count: 0,
                    dominant_component_pixels: 0,
                    dominant_component_ratio: 0.0,
                    bounding_box_x: 0,
                    bounding_box_y: 0,
                    bounding_box_width: 0,
                    bounding_box_height: 0,
                    convex_hull_vertices: 0,
                    estimated_sides: None,
                    analysis_error: None,
                },
            );
            assert_eq!(
                summary.estimated_sides,
                Some(sides as u32),
                "rotation {} summary {:?}",
                rotation_deg,
                summary
            );
        }
    }
}

fn render_regular_polygon(sides: usize, rotation_deg: f32) -> RgbaImage {
    let mut image = RgbaImage::from_pixel(150, 100, Rgba([0, 0, 0, 0]));
    let center_x = 75.0_f32;
    let center_y = 50.0_f32;
    let radius = 35.0_f32;
    let rotation = rotation_deg * PI / 180.0;
    let points = (0..sides)
        .map(|index| {
            let angle = rotation + (index as f32 * 2.0 * PI / sides as f32);
            (
                center_x + radius * angle.cos(),
                center_y + radius * angle.sin(),
            )
        })
        .collect::<Vec<_>>();
    for index in 0..sides {
        let start = points[index];
        let end = points[(index + 1) % sides];
        for offset_x in -1..=1 {
            for offset_y in -1..=1 {
                draw_line_segment_mut(
                    &mut image,
                    (start.0 + offset_x as f32, start.1 + offset_y as f32),
                    (end.0 + offset_x as f32, end.1 + offset_y as f32),
                    Rgba([0, 0, 0, 255]),
                );
            }
        }
    }
    image
}
