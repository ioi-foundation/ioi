pub(crate) fn extract_balanced_json_object(payload: &str, start: usize) -> Option<&str> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut started = false;

    for (idx, ch) in payload[start..].char_indices() {
        match ch {
            '"' if !escaped => {
                in_string = !in_string;
            }
            '\\' if in_string => {
                escaped = !escaped;
                continue;
            }
            '{' if !in_string => {
                depth += 1;
                started = true;
            }
            '}' if !in_string => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if started && depth == 0 {
                    let end = start + idx;
                    return Some(&payload[start..=end]);
                }
            }
            _ => {}
        }
        escaped = false;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::extract_balanced_json_object;

    #[test]
    fn extracts_json_with_escaped_quotes() {
        let payload = r#"prefix {\"msg\":\"hello \\\"world\\\"\",\"n\":1} suffix"#;
        let start = payload.find('{').expect("json start");
        let extracted = extract_balanced_json_object(payload, start).expect("json payload");
        assert_eq!(extracted, r#"{\"msg\":\"hello \\\"world\\\"\",\"n\":1}"#);
    }
}
