use super::is_visual_query;

#[test]
fn visual_query_heuristic_detects_icon_and_color_terms() {
    assert!(is_visual_query("gear icon"));
    assert!(is_visual_query("red button"));
    assert!(is_visual_query("button looking like a triangle"));
}

#[test]
fn visual_query_heuristic_ignores_plain_semantic_queries() {
    assert!(!is_visual_query("submit button"));
    assert!(!is_visual_query("open settings"));
    assert!(!is_visual_query("search field"));
}
