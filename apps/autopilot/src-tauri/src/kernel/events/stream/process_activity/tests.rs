use super::{should_flush_stream_buffer, stream_progress_excerpt};

#[test]
fn stream_progress_excerpt_prefers_last_non_empty_line() {
    let excerpt = stream_progress_excerpt("line one\n\nline two\n")
        .expect("expected stream progress excerpt");
    assert_eq!(excerpt, "line two");
}

#[test]
fn stream_progress_excerpt_truncates_long_lines() {
    let long_line = "a".repeat(200);
    let excerpt = stream_progress_excerpt(&long_line).expect("expected stream progress excerpt");
    assert!(excerpt.ends_with("..."));
    assert!(excerpt.len() < long_line.len());
}

#[test]
fn stream_buffer_flushes_on_line_threshold() {
    let mut payload = String::new();
    for idx in 0..8 {
        payload.push_str(&format!("line-{}\n", idx));
    }
    assert!(should_flush_stream_buffer(&payload));
}
