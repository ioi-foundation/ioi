use super::BrowserDriver;

#[test]
fn deep_dom_helpers_include_iframe_traversal() {
    let helpers = BrowserDriver::deep_dom_helper_js();
    assert!(helpers.contains("enqueueFrameDocument"));
    assert!(helpers.contains("contentDocument"));
    assert!(helpers.contains("frameElement"));
}

#[test]
fn selector_rect_script_accumulates_iframe_offsets() {
    let script = BrowserDriver::selector_rect_script("button.primary")
        .expect("selector rect script should serialize selector");
    assert!(script.contains("deepQuerySelector(selector)"));
    assert!(script.contains("frameOffsetX"));
    assert!(script.contains("frameElement"));
    assert!(script.contains("getBoundingClientRect"));
}

#[test]
fn selector_probe_script_uses_cross_frame_viewport_and_center() {
    let script = BrowserDriver::selector_probe_script("input.search")
        .expect("selector probe script should serialize selector");
    assert!(script.contains("const ownerWin ="));
    assert!(script.contains("ownerWin.getComputedStyle(el)"));
    assert!(script.contains("const viewportHeight = ownerWin.innerHeight || 0;"));
    assert!(script.contains("elementCenterInTopWindow(el)"));
    assert!(script.contains("deepElementFromPoint(center.x, center.y)"));
    assert!(script.contains("const editable = isElementEditable(el);"));
}

#[test]
fn deep_dom_helpers_rank_visible_topmost_matches() {
    let helpers = BrowserDriver::deep_dom_helper_js();
    assert!(helpers.contains("isElementVisibleCandidate"));
    assert!(helpers.contains("isElementTopmostCandidate"));
    assert!(helpers.contains("querySelectorAll(selector)"));
    assert!(helpers.contains("return firstVisible"));
}

#[test]
fn deep_dom_helpers_define_editable_semantics_for_form_controls() {
    let helpers = BrowserDriver::deep_dom_helper_js();
    assert!(helpers.contains("const isElementEditable"));
    assert!(helpers.contains("nonEditableTypes"));
    assert!(helpers.contains("\"submit\""));
    assert!(helpers.contains("\"checkbox\""));
    assert!(helpers.contains("aria-readonly"));
}
