pub(super) fn normalize_html_semantic_structure(html: &str) -> String {
    if chat_modal_first_html_enabled() {
        return html.to_string();
    }
    let with_main = ensure_html_main_region(html);
    ensure_minimum_html_sectioning_elements(&with_main)
}

pub(super) fn normalize_html_terminal_closure(html: &str) -> String {
    let repaired_nesting = repair_html_mismatched_nesting(html);
    let trimmed = repaired_nesting.trim_end();
    if trimmed.is_empty() {
        return repaired_nesting;
    }

    if html_has_trailing_fragment(trimmed) {
        return repaired_nesting;
    }

    let lower = trimmed.to_ascii_lowercase();
    let has_html = lower.contains("<html");
    if !has_html {
        return html.to_string();
    }

    let has_body = lower.contains("<body");
    let has_main = lower.contains("<main");
    let has_close_html = lower.contains("</html>");
    let has_close_body = lower.contains("</body>");
    let has_close_main = !has_main || lower.contains("</main>");

    let mut normalized = trimmed.to_string();
    if has_close_html {
        if has_main && has_close_main {
            let lower_normalized = normalized.to_ascii_lowercase();
            if let Some(insert_at) = lower_normalized.rfind("</main>") {
                let suffix =
                    close_unclosed_html_elements_for_truncated_suffix(&normalized[..insert_at]);
                if !suffix.is_empty() {
                    normalized.insert_str(insert_at, &suffix);
                }
            }
        }

        if has_body && has_close_body {
            let lower_normalized = normalized.to_ascii_lowercase();
            if let Some(insert_at) = lower_normalized.rfind("</body>") {
                let suffix =
                    close_unclosed_html_elements_for_truncated_suffix(&normalized[..insert_at]);
                if !suffix.is_empty() {
                    normalized.insert_str(insert_at, &suffix);
                }
            }
        }

        let lower_normalized = normalized.to_ascii_lowercase();
        let Some(insert_at) = lower_normalized.rfind("</html>") else {
            return repaired_nesting;
        };
        let mut suffix =
            close_unclosed_html_elements_for_truncated_suffix(&normalized[..insert_at]);
        if has_main && !lower_normalized.contains("</main>") {
            suffix.push_str("</main>");
        }
        if has_body && !lower_normalized.contains("</body>") {
            suffix.push_str("</body>");
        }
        if !suffix.is_empty() {
            normalized.insert_str(insert_at, &suffix);
        }
        return normalized;
    }

    normalized.push_str(&close_unclosed_html_elements_for_truncated_suffix(
        &normalized,
    ));
    if has_main && !has_close_main {
        normalized.push_str("</main>");
    }
    if has_body && !has_close_body {
        normalized.push_str("</body>");
    }
    normalized.push_str("</html>");
    normalized
}

fn repair_html_mismatched_nesting(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut output = String::with_capacity(html.len() + 128);
    let mut stack = Vec::<String>::new();
    let mut index = 0usize;
    let mut cursor = 0usize;

    while index < bytes.len() {
        let Some(relative_lt) = lower[index..].find('<') else {
            break;
        };
        let start = index + relative_lt;
        output.push_str(&html[cursor..start]);
        index = start;

        if lower[index..].starts_with("<!--") {
            let Some(comment_end) = lower[index + 4..].find("-->") else {
                output.push_str(&html[index..]);
                return output;
            };
            let end = index + 4 + comment_end + 3;
            output.push_str(&html[index..end]);
            cursor = end;
            index = end;
            continue;
        }

        if lower[index..].starts_with("<!") || lower[index..].starts_with("<?") {
            let Some(tag_end) = html_markup_tag_end_index(html, index + 2) else {
                output.push_str(&html[index..]);
                return output;
            };
            let end = tag_end + 1;
            output.push_str(&html[index..end]);
            cursor = end;
            index = end;
            continue;
        }

        let mut tag_cursor = index + 1;
        let is_closing = bytes.get(tag_cursor) == Some(&b'/');
        if is_closing {
            tag_cursor += 1;
        }
        while tag_cursor < bytes.len() && bytes[tag_cursor].is_ascii_whitespace() {
            tag_cursor += 1;
        }
        let name_start = tag_cursor;
        while tag_cursor < bytes.len() && html_markup_tag_name_char(bytes[tag_cursor]) {
            tag_cursor += 1;
        }
        if tag_cursor == name_start {
            output.push('<');
            cursor = index + 1;
            index = index + 1;
            continue;
        }

        let tag_name = &lower[name_start..tag_cursor];
        let Some(tag_end) = html_markup_tag_end_index(html, tag_cursor) else {
            output.push_str(&html[index..]);
            return output;
        };
        let end = tag_end + 1;
        let token = &html[index..end];
        let tag_fragment = lower[index..end].trim_end();
        let self_closing = tag_fragment.ends_with("/>") || tag_fragment.ends_with("?>");

        if is_closing {
            if html_void_element(tag_name) || html_has_optional_closing_behavior(tag_name) {
                output.push_str(token);
            } else if let Some(position) = stack.iter().rposition(|open| open == tag_name) {
                for open_tag in stack[position + 1..].iter().rev() {
                    output.push_str("</");
                    output.push_str(open_tag);
                    output.push('>');
                }
                stack.truncate(position);
                output.push_str(token);
            }
            cursor = end;
            index = end;
            continue;
        }

        output.push_str(token);
        if !self_closing
            && !matches!(tag_name, "html" | "body" | "main")
            && !html_void_element(tag_name)
            && !html_has_optional_closing_behavior(tag_name)
        {
            if html_is_raw_text_tag(tag_name) {
                let close_pattern = format!("</{tag_name}");
                let Some(close_relative) = lower[end..].find(&close_pattern) else {
                    output.push_str(&html[end..]);
                    return output;
                };
                let close_start = end + close_relative;
                output.push_str(&html[end..close_start]);
                let Some(close_end) =
                    html_markup_tag_end_index(html, close_start + close_pattern.len())
                else {
                    output.push_str(&html[close_start..]);
                    return output;
                };
                let close_token_end = close_end + 1;
                output.push_str(&html[close_start..close_token_end]);
                cursor = close_token_end;
                index = close_token_end;
                continue;
            }
            stack.push(tag_name.to_string());
        }

        cursor = end;
        index = end;
    }

    output.push_str(&html[cursor..]);
    if stack.is_empty() {
        return output;
    }

    for tag in stack.iter().rev() {
        output.push_str("</");
        output.push_str(tag);
        output.push('>');
    }
    output
}

fn close_unclosed_html_elements_for_truncated_suffix(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut stack = Vec::<String>::new();
    let mut index = 0usize;

    while index < bytes.len() {
        let Some(relative_lt) = lower[index..].find('<') else {
            break;
        };
        index += relative_lt;

        if lower[index..].starts_with("<!--") {
            let Some(comment_end) = lower[index + 4..].find("-->") else {
                break;
            };
            index += 4 + comment_end + 3;
            continue;
        }

        if lower[index..].starts_with("<!") || lower[index..].starts_with("<?") {
            let Some(tag_end) = html_markup_tag_end_index(html, index + 2) else {
                break;
            };
            index = tag_end + 1;
            continue;
        }

        let mut cursor = index + 1;
        let is_closing = bytes.get(cursor) == Some(&b'/');
        if is_closing {
            cursor += 1;
        }
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let name_start = cursor;
        while cursor < bytes.len() && html_markup_tag_name_char(bytes[cursor]) {
            cursor += 1;
        }
        if cursor == name_start {
            index += 1;
            continue;
        }

        let tag_name = &lower[name_start..cursor];
        let Some(tag_end) = html_markup_tag_end_index(html, cursor) else {
            break;
        };
        let tag_fragment = lower[index..=tag_end].trim_end();
        let self_closing = tag_fragment.ends_with("/>") || tag_fragment.ends_with("?>");

        if is_closing {
            if html_void_element(tag_name) || html_has_optional_closing_behavior(tag_name) {
                index = tag_end + 1;
                continue;
            }
            while let Some(open_tag) = stack.pop() {
                if open_tag == tag_name {
                    break;
                }
            }
            index = tag_end + 1;
            continue;
        }

        if !self_closing
            && !matches!(tag_name, "html" | "body" | "main")
            && !html_void_element(tag_name)
            && !html_has_optional_closing_behavior(tag_name)
        {
            stack.push(tag_name.to_string());
            if html_is_raw_text_tag(tag_name) {
                let close_pattern = format!("</{tag_name}");
                let Some(close_relative) = lower[tag_end + 1..].find(&close_pattern) else {
                    break;
                };
                index = tag_end + 1 + close_relative;
                continue;
            }
        }

        index = tag_end + 1;
    }

    if stack.is_empty() {
        return String::new();
    }

    let mut suffix = String::new();
    for tag in stack.iter().rev() {
        suffix.push_str("</");
        suffix.push_str(tag);
        suffix.push('>');
    }
    suffix
}
