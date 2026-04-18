pub(crate) fn extract_balanced_json_object(payload: &str, start: usize) -> Option<&str> {
    let bytes = payload.as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut started = false;
    let mut escaped_json_mode: Option<bool> = None;

    for (idx, ch) in payload[start..].char_indices() {
        let absolute_idx = start + idx;
        let mut preceding_backslashes = 0usize;
        let mut cursor = absolute_idx;
        while cursor > 0 && bytes[cursor - 1] == b'\\' {
            preceding_backslashes += 1;
            cursor -= 1;
        }

        if ch == '"' {
            let toggles_string = match escaped_json_mode {
                Some(true) => preceding_backslashes % 4 == 1,
                Some(false) => preceding_backslashes % 2 == 0,
                None if preceding_backslashes == 0 => {
                    escaped_json_mode = Some(false);
                    true
                }
                None if preceding_backslashes % 4 == 1 => {
                    escaped_json_mode = Some(true);
                    true
                }
                None => false,
            };
            if toggles_string {
                in_string = !in_string;
            }
        }

        match ch {
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
