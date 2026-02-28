use serde_json::Value;

/// Basic Handlebars-style interpolation: `{{key}}` -> value from context.
pub fn interpolate_template(template: &str, context: &Value) -> String {
    let mut result = template.to_string();
    let mut start_idx = 0;
    while let Some(open) = result[start_idx..].find("{{") {
        let actual_open = start_idx + open;
        if let Some(close) = result[actual_open..].find("}}") {
            let actual_close = actual_open + close;
            let key = &result[actual_open + 2..actual_close].trim();

            let replacement = if let Some(val) = context.get(key) {
                if let Some(s) = val.as_str() {
                    s.to_string()
                } else {
                    val.to_string()
                }
            } else {
                format!("<<MISSING:{}>>", key)
            };

            result.replace_range(actual_open..actual_close + 2, &replacement);
            start_idx = actual_open + replacement.len();
        } else {
            break;
        }
    }
    result
}
