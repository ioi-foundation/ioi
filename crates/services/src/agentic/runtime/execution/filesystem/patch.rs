use std::ops::Range;

fn normalize_line(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_code_block_content(block: &str) -> String {
    block.replace("\r\n", "\n").trim_matches('\n').to_string()
}

fn matches_python_function_signature(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("def ") || trimmed.starts_with("async def ")
}

fn indentation_prefix(line: &str) -> &str {
    let count = line.chars().take_while(|ch| ch.is_whitespace()).count();
    &line[..count]
}

fn leading_whitespace_count(line: &str) -> usize {
    line.chars().take_while(|ch| ch.is_whitespace()).count()
}

fn python_body_indent_base(lines: &[&str]) -> Option<usize> {
    lines
        .iter()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| leading_whitespace_count(line))
        .min()
}

fn default_python_body_indent_base(lines: &[&str]) -> Option<usize> {
    lines
        .first()
        .map(|signature| leading_whitespace_count(signature).saturating_add(4))
}

fn python_function_name_from_signature(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let rest = trimmed
        .strip_prefix("def ")
        .or_else(|| trimmed.strip_prefix("async def "))?;
    let candidate = rest.split('(').next()?.trim();
    if candidate.is_empty()
        || !candidate
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return None;
    }
    Some(candidate.to_string())
}

fn python_function_name_from_block(block: &str) -> Option<String> {
    block
        .lines()
        .find_map(|line| python_function_name_from_signature(line.trim_start()))
}

fn python_blocks_reference_same_function(left: &str, right: &str) -> bool {
    python_function_name_from_block(left)
        .zip(python_function_name_from_block(right))
        .is_some_and(|(left, right)| left == right)
}

fn extract_primary_python_function_block(file_content: &str) -> Option<String> {
    let normalized = file_content.replace("\r\n", "\n");
    let lines = normalized.lines().collect::<Vec<_>>();
    let start = lines
        .iter()
        .position(|line| matches_python_function_signature(line.trim_start()))?;
    let base_indent = lines[start]
        .chars()
        .take_while(|ch| ch.is_whitespace())
        .count();
    let mut end = lines.len();
    for (offset, line) in lines.iter().enumerate().skip(start + 1) {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.chars().take_while(|ch| ch.is_whitespace()).count();
        if indent <= base_indent && !line.trim_start().starts_with('@') {
            end = offset;
            break;
        }
    }
    let block = lines[start..end].join("\n");
    let normalized = normalize_code_block_content(&block);
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn split_inline_python_body(trailing: &str) -> Vec<String> {
    let mut remaining = trailing.trim();
    let mut lines = Vec::new();
    for quote in ["\"\"\"", "'''"] {
        if remaining.starts_with(quote) {
            if let Some(end_idx) = remaining[quote.len()..].find(quote) {
                let end = quote.len() + end_idx + quote.len();
                lines.push(remaining[..end].to_string());
                remaining = remaining[end..].trim();
            }
            break;
        }
    }
    if !remaining.is_empty() {
        lines.push(remaining.to_string());
    }
    lines
}

fn split_inline_python_signature_body(line: &str) -> Option<(String, Vec<String>)> {
    let trimmed = line.trim_start();
    if !matches_python_function_signature(trimmed) {
        return None;
    }

    let colon_idx = trimmed.rfind(':')?;
    let trailing = trimmed[colon_idx + 1..].trim();
    if trailing.is_empty() {
        return None;
    }

    Some((
        trimmed[..=colon_idx].trim_end().to_string(),
        split_inline_python_body(trailing),
    ))
}

fn expand_inline_python_function_block(block: &str) -> String {
    let normalized = normalize_code_block_content(block);
    let mut lines = normalized.lines();
    let Some(first_line) = lines.next() else {
        return normalized;
    };
    let Some((header, body_lines)) = split_inline_python_signature_body(first_line) else {
        return normalized;
    };

    let signature_indent = indentation_prefix(first_line);
    let body_indent = format!("{signature_indent}    ");
    let mut expanded = vec![format!("{signature_indent}{header}")];
    for body_line in body_lines {
        expanded.push(format!("{body_indent}{body_line}"));
    }
    expanded.extend(lines.map(str::to_string));
    expanded.join("\n")
}

fn align_python_block_to_reference(candidate_block: &str, reference_block: &str) -> Option<String> {
    let candidate = expand_inline_python_function_block(candidate_block);
    let reference = expand_inline_python_function_block(reference_block);
    let candidate_lines = candidate.lines().collect::<Vec<_>>();
    let reference_lines = reference.lines().collect::<Vec<_>>();
    let candidate_signature = candidate_lines.first()?.trim_start();
    let reference_signature = reference_lines.first()?.trim_start();
    if !matches_python_function_signature(candidate_signature)
        || !matches_python_function_signature(reference_signature)
        || !python_blocks_reference_same_function(&candidate, &reference)
    {
        return None;
    }

    let signature_prefix = indentation_prefix(reference_lines.first()?);
    let reference_body_base = python_body_indent_base(&reference_lines)
        .or_else(|| default_python_body_indent_base(&reference_lines))?;
    let candidate_body_base = python_body_indent_base(&candidate_lines)
        .or_else(|| default_python_body_indent_base(&candidate_lines))
        .unwrap_or(reference_body_base);
    let mut aligned_lines = Vec::with_capacity(candidate_lines.len());
    aligned_lines.push(format!("{signature_prefix}{candidate_signature}"));

    for line in candidate_lines.iter().skip(1) {
        if line.trim().is_empty() {
            aligned_lines.push(String::new());
            continue;
        }
        let relative_indent = leading_whitespace_count(line).saturating_sub(candidate_body_base);
        let aligned_indent = format!(
            "{}{}",
            " ".repeat(reference_body_base),
            " ".repeat(relative_indent)
        );
        aligned_lines.push(format!("{}{}", aligned_indent, line.trim_start()));
    }

    Some(aligned_lines.join("\n"))
}

fn structural_python_return_line_replacement(original: &str, replacement: &str) -> Option<String> {
    let trimmed = replacement.trim();
    if !trimmed.starts_with("return ") {
        return None;
    }

    let mut indices = original
        .lines()
        .enumerate()
        .filter_map(|(index, line)| line.trim_start().starts_with("return ").then_some(index))
        .collect::<Vec<_>>();
    if indices.len() != 1 {
        return None;
    }

    let target_index = indices.pop()?;
    let mut lines = original.lines().map(str::to_string).collect::<Vec<_>>();
    let indent = indentation_prefix(&lines[target_index]).to_string();
    lines[target_index] = format!("{indent}{trimmed}");

    let newline = if original.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut updated = lines.join(newline);
    if original.ends_with('\n') {
        updated.push_str(newline);
    }
    Some(updated)
}

fn structural_python_function_replacement(original: &str, candidate: &str) -> Option<String> {
    let reference_block = extract_primary_python_function_block(original)?;
    let candidate_block = extract_primary_python_function_block(candidate)
        .unwrap_or_else(|| normalize_code_block_content(candidate));
    let aligned_block = align_python_block_to_reference(&candidate_block, &reference_block)?;
    let updated = original.replacen(&reference_block, &aligned_block, 1);
    (updated != original).then_some(updated)
}

fn source_line_ranges(source: &str) -> Vec<Range<usize>> {
    let bytes = source.as_bytes();
    let mut ranges = Vec::new();
    let mut line_start = 0;

    for (idx, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            let mut line_end = idx;
            if line_end > line_start && bytes[line_end - 1] == b'\r' {
                line_end -= 1;
            }
            ranges.push(line_start..line_end);
            line_start = idx + 1;
        }
    }

    if line_start < source.len() {
        ranges.push(line_start..source.len());
    }

    ranges
}

pub(super) fn fuzzy_find_indices(source: &str, search: &str) -> Result<Range<usize>, String> {
    let source_ranges = source_line_ranges(source);
    let search_lines: Vec<_> = search.lines().map(normalize_line).collect();

    if search_lines.is_empty() {
        return Err("search block must contain at least one line".to_string());
    }

    if search_lines.len() > source_ranges.len() {
        return Err("search block not found in file".to_string());
    }

    let source_lines: Vec<_> = source_ranges
        .iter()
        .map(|range| normalize_line(&source[range.clone()]))
        .collect();

    let mut found_start = None;
    let window_size = search_lines.len();
    for start in 0..=source_lines.len() - window_size {
        if source_lines[start..start + window_size] == search_lines {
            if found_start.replace(start).is_some() {
                return Err(
                    "search block is ambiguous: found multiple fuzzy matches; provide more context"
                        .to_string(),
                );
            }
        }
    }

    let start = found_start.ok_or_else(|| "search block not found in file".to_string())?;
    let end = start + window_size - 1;
    Ok(source_ranges[start].start..source_ranges[end].end)
}

pub(super) fn edit_line_content(
    original: &str,
    line_number: u32,
    replacement: &str,
) -> Result<String, String> {
    if line_number == 0 {
        return Err("line_number must be >= 1".to_string());
    }

    let mut lines: Vec<&str> = original.lines().collect();
    if lines.is_empty() {
        return Err("cannot edit line in empty file".to_string());
    }

    let index = (line_number - 1) as usize;
    if index >= lines.len() {
        if let Some(updated) = structural_python_return_line_replacement(original, replacement)
            .or_else(|| structural_python_function_replacement(original, replacement))
        {
            return Ok(updated);
        }
        return Err(format!(
            "line {} is out of range (file has {} line(s))",
            line_number,
            lines.len()
        ));
    }

    lines[index] = replacement;

    let newline = if original.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut updated = lines.join(newline);
    if original.ends_with('\n') {
        updated.push_str(newline);
    }

    Ok(updated)
}

pub(super) fn apply_patch(original: &str, search: &str, replace: &str) -> Result<String, String> {
    if search.is_empty() {
        return Err("search block must be non-empty".to_string());
    }

    let mut exact_matches = original.match_indices(search);
    let range = match exact_matches.next() {
        Some((start, _)) => {
            if exact_matches.next().is_some() {
                return Err(
                    "search block is ambiguous: found multiple exact matches; provide more context"
                        .to_string(),
                );
            }
            start..start + search.len()
        }
        None => match fuzzy_find_indices(original, search) {
            Ok(range) => range,
            Err(error) => {
                if let Some(updated) = structural_python_function_replacement(original, replace) {
                    return Ok(updated);
                }
                return Err(error);
            }
        },
    };

    let mut new_content = String::with_capacity(original.len() + replace.len());
    new_content.push_str(&original[..range.start]);
    new_content.push_str(replace);
    new_content.push_str(&original[range.end..]);
    Ok(new_content)
}
