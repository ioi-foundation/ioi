use super::*;

pub(crate) fn patch_build_verify_runtime_repair_preserves_python_signature(
    current_content: &str,
    candidate_content: &str,
) -> bool {
    let Some(current_signature) = single_python_function_signature(current_content) else {
        return true;
    };
    let Some(candidate_signature) = single_python_function_signature(candidate_content) else {
        return false;
    };

    current_signature == candidate_signature
}

fn single_python_function_signature(content: &str) -> Option<String> {
    let signatures = content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            matches_python_function_signature(trimmed).then_some(trimmed.trim_end().to_string())
        })
        .collect::<Vec<_>>();
    if signatures.len() == 1 {
        signatures.into_iter().next()
    } else {
        None
    }
}

pub(crate) async fn validate_python_module_syntax(
    content: &str,
) -> Result<Option<String>, TransactionError> {
    let staged_file = tempfile::Builder::new()
        .suffix(".py")
        .tempfile()
        .map_err(|error| {
            TransactionError::Invalid(format!(
                "failed to create temporary python syntax check file: {error}"
            ))
        })?;
    fs::write(staged_file.path(), content).map_err(|error| {
        TransactionError::Invalid(format!(
            "failed to stage temporary python syntax check file: {error}"
        ))
    })?;

    let output = match Command::new("python3")
        .arg("-m")
        .arg("py_compile")
        .arg(staged_file.path())
        .output()
        .await
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(TransactionError::Invalid(format!(
                "failed to run python syntax check: {error}"
            )))
        }
    };
    if output.status.success() {
        return Ok(None);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    Ok(Some(truncate_for_prompt(&detail, 160)))
}

fn extract_fenced_code_blocks(raw_tool_output: &str) -> Vec<String> {
    let normalized = raw_tool_output.replace("\r\n", "\n");
    let parts = normalized.split("```").collect::<Vec<_>>();
    let mut code_blocks = Vec::new();
    for index in (1..parts.len()).step_by(2) {
        let segment = parts[index].trim_start_matches('\n');
        if segment.trim().is_empty() {
            continue;
        }
        let mut lines = segment.lines();
        let first_line = lines.next().unwrap_or_default();
        let code = if looks_like_code_fence_language(first_line) {
            lines.collect::<Vec<_>>().join("\n")
        } else {
            segment.to_string()
        };
        let block = code.trim_matches('\n').to_string();
        if !block.trim().is_empty() {
            code_blocks.push(block);
        }
    }
    code_blocks
}

pub(crate) fn extract_fenced_python_function_blocks(raw_tool_output: &str) -> Vec<String> {
    extract_fenced_code_blocks(raw_tool_output)
        .into_iter()
        .filter_map(|block| {
            let normalized = normalize_code_block_content(&block);
            extract_primary_python_function_block(&normalized).or_else(|| {
                let first_line = normalized.lines().find(|line| !line.trim().is_empty())?;
                if matches_python_function_signature(first_line.trim_start()) {
                    Some(normalized)
                } else {
                    None
                }
            })
        })
        .collect()
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

fn extract_inline_python_function_blocks(
    current_block: &str,
    raw_tool_output: &str,
) -> Vec<String> {
    let Some(function_name) = python_function_name_from_block(current_block) else {
        return Vec::new();
    };

    let lines = raw_tool_output
        .replace("\r\n", "\n")
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();

    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim();
            let signature_start = trimmed.find(&format!("{function_name}("))?;
            let candidate_suffix = trimmed[signature_start..].trim();
            if candidate_suffix.is_empty() {
                return None;
            }

            let mut candidate_lines = vec![if candidate_suffix.starts_with("def ")
                || candidate_suffix.starts_with("async def ")
            {
                candidate_suffix.to_string()
            } else {
                format!("def {candidate_suffix}")
            }];
            for following in lines.iter().skip(index + 1) {
                let trimmed_following = following.trim();
                if trimmed_following.is_empty()
                    || trimmed_following.starts_with("```")
                    || trimmed_following.starts_with("shell__")
                    || trimmed_following.starts_with("package__")
                    || trimmed_following.starts_with("file__")
                    || trimmed_following.starts_with("agent__")
                    || trimmed_following.starts_with('{')
                    || trimmed_following.starts_with('[')
                    || matches_python_function_signature(trimmed_following)
                {
                    break;
                }
                if !looks_like_inline_python_body_line(trimmed_following) {
                    break;
                }
                candidate_lines.push(trimmed_following.to_string());
            }

            let expanded = expand_inline_python_function_block(&candidate_lines.join("\n"));
            python_blocks_reference_same_function(current_block, &expanded).then_some(expanded)
        })
        .collect()
}

fn default_python_body_indent_base(lines: &[&str]) -> Option<usize> {
    lines
        .first()
        .map(|signature| leading_whitespace_count(signature).saturating_add(4))
}

fn looks_like_inline_python_body_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }

    trimmed.starts_with("return ")
        || trimmed.starts_with("if ")
        || trimmed.starts_with("elif ")
        || trimmed == "else:"
        || trimmed.starts_with("for ")
        || trimmed.starts_with("while ")
        || trimmed.starts_with("with ")
        || trimmed == "try:"
        || trimmed.starts_with("except ")
        || trimmed == "finally:"
        || trimmed.starts_with("raise ")
        || trimmed == "pass"
        || trimmed == "break"
        || trimmed == "continue"
        || trimmed.starts_with("assert ")
        || trimmed.starts_with("\"\"\"")
        || trimmed.starts_with("'''")
        || trimmed.ends_with(':')
        || (trimmed.contains('=') && !trimmed.contains('`'))
}

fn looks_like_code_fence_language(line: &str) -> bool {
    let trimmed = line.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 24
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '+' | '#' | '.'))
}

pub(crate) fn normalize_code_block_content(block: &str) -> String {
    block.replace("\r\n", "\n").trim_matches('\n').to_string()
}

pub(crate) fn extract_primary_python_function_block(file_content: &str) -> Option<String> {
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

fn inline_python_block_repair_candidate(
    current_block: &str,
    raw_tool_output: &str,
) -> Option<String> {
    let normalized_block = normalize_code_block_content(current_block);
    let signature_line = normalized_block.lines().next()?.trim();
    if !matches_python_function_signature(signature_line) {
        return None;
    }
    let updated_return = extract_inline_python_return_line(raw_tool_output)?;
    inline_python_block_repair_candidate_from_line(current_block, &updated_return)
}

pub(crate) fn updated_python_block_candidate_from_raw_output(
    current_block: &str,
    raw_tool_output: &str,
) -> Option<String> {
    if let Some(block) = extract_fenced_python_function_blocks(raw_tool_output)
        .into_iter()
        .rev()
        .find_map(|block| {
            if !python_blocks_reference_same_function(current_block, &block) {
                return None;
            }
            align_python_block_to_reference(&block, current_block)
        })
    {
        return Some(block);
    }

    if let Some(block) = extract_inline_python_function_blocks(current_block, raw_tool_output)
        .into_iter()
        .rev()
        .find_map(|block| align_python_block_to_reference(&block, current_block))
    {
        return Some(block);
    }

    inline_python_block_repair_candidate(current_block, raw_tool_output)
}

pub(crate) fn inline_python_block_repair_candidate_from_line(
    current_block: &str,
    updated_return: &str,
) -> Option<String> {
    let normalized_block = normalize_code_block_content(current_block);
    let mut replaced = false;
    let updated_lines = normalized_block
        .lines()
        .map(|line| {
            if !replaced && line.trim_start().starts_with("return ") {
                replaced = true;
                format!("{}{}", indentation_prefix(line), updated_return.trim())
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>();
    if !replaced {
        return None;
    }

    Some(normalize_replacement_block(
        current_block,
        &updated_lines.join("\n"),
    ))
}

fn extract_inline_python_return_line(raw_tool_output: &str) -> Option<String> {
    raw_tool_output
        .replace("\r\n", "\n")
        .lines()
        .rev()
        .find_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with("```")
                || trimmed.starts_with("shell__")
                || trimmed.starts_with("package__")
                || trimmed.starts_with('{')
                || trimmed.starts_with('[')
            {
                return None;
            }
            let start = trimmed.find("return ")?;
            let candidate = trimmed[start..].trim();
            if candidate.contains("file__") || candidate.contains("agent__") {
                return None;
            }
            Some(candidate.to_string())
        })
}

pub(crate) fn python_blocks_reference_same_function(left: &str, right: &str) -> bool {
    python_function_name_from_block(left)
        .zip(python_function_name_from_block(right))
        .is_some_and(|(left, right)| left == right)
}

fn python_function_name_from_block(block: &str) -> Option<String> {
    block
        .lines()
        .find_map(|line| python_function_name_from_signature(line.trim_start()))
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

fn python_function_primary_parameter_name(signature_line: &str) -> Option<String> {
    let trimmed = signature_line.trim();
    let rest = trimmed
        .strip_prefix("def ")
        .or_else(|| trimmed.strip_prefix("async def "))?;
    let params = rest.split_once('(')?.1.split_once(')')?.0;
    let candidate = params.split(',').next()?.split(':').next()?.trim();
    if candidate.is_empty()
        || !candidate
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return None;
    }
    Some(candidate.to_string())
}

fn is_single_line_python_docstring(line: &str) -> bool {
    let trimmed = line.trim();
    (trimmed.starts_with("\"\"\"") && trimmed.ends_with("\"\"\"") && trimmed.len() >= 6)
        || (trimmed.starts_with("'''") && trimmed.ends_with("'''") && trimmed.len() >= 6)
}

pub(crate) fn patch_build_verify_path_parity_reference_repair(
    reference_block: &str,
) -> Option<String> {
    let reference = expand_inline_python_function_block(reference_block);
    let reference_lines = reference.lines().collect::<Vec<_>>();
    let signature_line = reference_lines.first()?.trim_start();
    if !matches_python_function_signature(signature_line) {
        return None;
    }

    let path_var = python_function_primary_parameter_name(signature_line)?;
    let signature_prefix = indentation_prefix(reference_lines.first()?);
    let body_indent = python_body_indent_base(&reference_lines)
        .or_else(|| default_python_body_indent_base(&reference_lines))
        .unwrap_or(signature_prefix.len() + 4);
    let branch_indent = body_indent + 4;
    let indent = " ".repeat(body_indent);
    let nested_indent = " ".repeat(branch_indent);

    let mut repaired_lines = vec![format!("{signature_prefix}{signature_line}")];
    if let Some(docstring) = reference_lines
        .iter()
        .skip(1)
        .map(|line| line.trim())
        .find(|line| is_single_line_python_docstring(line))
    {
        repaired_lines.push(format!("{indent}{docstring}"));
    }
    repaired_lines.push(format!("{indent}prefix = \"\""));
    repaired_lines.push(format!(r#"{indent}if {path_var}.startswith("./"):"#));
    repaired_lines.push(format!(r#"{nested_indent}prefix = "./""#));
    repaired_lines.push(format!(r#"{nested_indent}{path_var} = {path_var}[2:]"#));
    repaired_lines.push(format!(r#"{indent}elif {path_var}.startswith("/"):"#));
    repaired_lines.push(format!(r#"{nested_indent}prefix = "/""#));
    repaired_lines.push(format!(r#"{nested_indent}{path_var} = {path_var}[1:]"#));
    repaired_lines.push(format!(
        r#"{indent}normalized = {path_var}.replace("\\", "/")"#
    ));
    repaired_lines.push(format!(r#"{indent}while "//" in normalized:"#));
    repaired_lines.push(format!(
        r#"{nested_indent}normalized = normalized.replace("//", "/")"#
    ));
    repaired_lines.push(format!(r#"{indent}return prefix + normalized"#));

    Some(normalize_replacement_block(
        reference_block,
        &repaired_lines.join("\n"),
    ))
}

pub(crate) fn align_python_block_to_reference(
    candidate_block: &str,
    reference_block: &str,
) -> Option<String> {
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

    Some(normalize_replacement_block(
        reference_block,
        &aligned_lines.join("\n"),
    ))
}

pub(crate) fn matches_python_function_signature(line: &str) -> bool {
    line.starts_with("def ") || line.starts_with("async def ")
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

pub(crate) fn patch_search_block(file_content: &str, current_block: &str) -> Option<String> {
    if current_block.is_empty() {
        return None;
    }
    if file_content.matches(current_block).count() == 1 {
        return Some(current_block.to_string());
    }

    let trimmed_block = current_block.trim();
    if trimmed_block.is_empty() {
        return None;
    }
    if file_content.trim() == trimmed_block {
        return Some(file_content.to_string());
    }
    if file_content.matches(trimmed_block).count() == 1 {
        return Some(trimmed_block.to_string());
    }

    None
}

pub(crate) fn normalize_block_for_match(block: &str) -> String {
    block
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}
